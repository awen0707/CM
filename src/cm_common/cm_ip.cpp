/*
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
 *
 * CM is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *          http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * -------------------------------------------------------------------------
 *
 *cm_ip.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_common/cm_ip.cpp
 *
 * -------------------------------------------------------------------------
 */
#include <cstring>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netdb.h>

#ifndef WIN32
#include <netdb.h>
#include <net/if.h>
#else
#include <ws2tcpip.h>
#endif

#include "cm_msg_common.h"
#include "cm_misc_base.h"
#include "cm_elog.h"
#include "cm_text.h"
#include "cm_ip.h"

#ifdef __cplusplus
extern "C" {
#endif

static const char *const IPV4_LOCAL_HOST_ARRAY[] = {"localhost", "127.0.0.1"};
static const char *const IPV6_LOCAL_HOST_ARRAY[] = {"::1"};

/* This is used to get the type of the ip address*/
int32 GetIpVersion(const char *ip_address)
{
    if (ip_address == NULL) {
        write_runlog(ERROR, "[%s] ip is null.\n", __FUNCTION__);
        return -1;
    }

    struct in_addr ipv4_addr;
    struct in6_addr ipv6_addr;

    if (inet_pton(AF_INET, ip_address, &ipv4_addr) == 1) {
        return AF_INET;
    }

    if (inet_pton(AF_INET6, ip_address, &ipv6_addr) == 1) {
        return AF_INET6;
    }
    write_runlog(ERROR, "[%s] invalid, get ip %s version failed.\n", __FUNCTION__, ip_address);
    return -1;
}

char *GetPingStr(int32 family)
{
    if (family == AF_INET6) {
        return "ping6";
    } else {
        return "ping";
    }
}

status_t BuildSockAddrIpV4(const char *host, int port, sock_addr_t *sockAddr)
{
    struct sockaddr_in *in4 = NULL;
    sockAddr->salen = (socklen_t)sizeof(struct sockaddr_in);
    in4 = SOCKADDR_IN4(sockAddr);

    errno_t rc = memset_s(in4, sizeof(struct sockaddr_in), 0, sizeof(struct sockaddr_in));
    securec_check_errno(rc, (void)rc);

    in4->sin_family = AF_INET;
    in4->sin_port = htons((uint16)port);
#ifndef WIN32
    in4->sin_addr.s_addr = inet_addr(host);
    if (in4->sin_addr.s_addr == (in_addr_t)(-1) || (inet_pton(AF_INET, host, &in4->
sin_addr.s_addr) != 1)) {
#else
    if (InetPton(AF_INET, host, &in4->sin_addr.s_addr) != 1) {
#endif
        write_runlog(ERROR, "[%s] ip(%s) is invalid.\n", __FUNCTION__, host);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

char *IpV6LocalLink(const char *host, char *ip, uint32 ipLen)
{
    errno_t errcode;
    size_t hostLen;
    int i = 0;

    while (host[i] && host[i] != '%') {
        i++;
    }

    if (host[i] == '\0') {
        return NULL;
    } else {
        hostLen = (uint32)strlen(host);
        errcode = strncpy_s(ip, (size_t)ipLen, host, (size_t)hostLen);
        if (SECUREC_UNLIKELY(errcode != EOK)) {
            write_runlog(ERROR, "[%s] strncpy_s failed, error code %d.\n", __FUNCTION__, errcode);
            return NULL;
        }

        ip[i] = '\0';
        return ip + i + 1;
    }
}

status_t BuildSockAddrIpV6(const char *host, int port, sock_addr_t *sockAddr)
{
    struct sockaddr_in6 *in6 = NULL;
#ifndef WIN32
    char ip[CM_IP_LENGTH];
    char *scope = NULL;
#endif

    sockAddr->salen = (socklen_t)sizeof(struct sockaddr_in6);
    in6 = SOCKADDR_IN6(sockAddr);

    errno_t rc = memset_s(in6, sizeof(struct sockaddr_in6), 0, sizeof(struct sockaddr_in6));
    securec_check_errno(rc, (void)rc);

    in6->sin6_family = AF_INET6;
    in6->sin6_port = htons((uint16)port);

#ifndef WIN32
    scope = IpV6LocalLink(host, ip, CM_IP_LENGTH);
    if (scope != NULL) {
        in6->sin6_scope_id = if_nametoindex(scope);
        if (in6->sin6_scope_id == 0) {
            write_runlog(ERROR, "[%s] invalid local link (%s).\n", __FUNCTION__, scope);
            return CM_ERROR;
        }

        host = ip;
    }
    if (inet_pton(AF_INET6, host, &in6->sin6_addr) != 1) {
#else
    if (InetPton(AF_INET6, host, &in6->sin6_addr) != 1) {
#endif
        write_runlog(ERROR, "[%s] ip(%s) invalid.\n", __FUNCTION__, host);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t BuildSockAddr(const char *host, int port, sock_addr_t *sockAddr)
{
    int family = GetIpVersion(host);
    switch (family) {
    case AF_INET:
        return BuildSockAddrIpV4(host, port, sockAddr);
    case AF_INET6:
        return BuildSockAddrIpV6(host, port, sockAddr);
    default:
        write_runlog(ERROR, "[%s] ip(%s) invalid.\n", __FUNCTION__, host);
        return CM_ERROR;
    }
}

status_t IpToSockAddr(const char *host, sock_addr_t *sockAddr)
{
#define CM_INVALID_IP_PORT 0
    return BuildSockAddr(host, CM_INVALID_IP_PORT, sockAddr);
}

bool CheckIpValid(const char *ip)
{
    if (CM_IS_EMPTY_STR(ip)) {
        return false;
    }
    char tempIp[CM_IP_LENGTH] = {0};
    if (NeedAndRemoveSquareBracketsForIpV6(ip, tempIp, CM_IP_LENGTH)) {
        write_runlog(ERROR, "[%s] ip (%s) is invalid.\n", __FUNCTION__, ip);
        return false;
    }

    if (IsLocalHostIp(tempIp)) {
        return true;
    }

    sock_addr_t sockAddr;
    if (IpToSockAddr(tempIp, &sockAddr) != CM_SUCCESS) {
        write_runlog(ERROR, "[%s] ip(%s) is invalid.\n", __FUNCTION__, ip);
        return false;
    }

    return true;
}

bool IsEqualIp(const char *clientIp, const char *localIp)
{
    if (IsLocalHostIp(clientIp) && IsLocalHostIp(localIp)) {
        return true;
    }

    sock_addr_t clientSockAddr = {0};
    sock_addr_t localSockAddr = {0};
    if (IpToSockAddr(localIp, &localSockAddr) != CM_SUCCESS ||
        IpToSockAddr(clientIp, &clientSockAddr) != CM_SUCCESS) {
        return false;
    }

    if (memcmp(&localSockAddr, &clientSockAddr, sizeof(sock_addr_t)) == 0) {
        return true;
    }
    return false;
}

bool8 IsLocalHostIp(const char *ip)
{
    if (CM_IS_EMPTY_STR(ip)) {
        return CM_FALSE;
    }

    char tempIp[CM_IP_LENGTH] = {0};
    if (NeedAndRemoveSquareBracketsForIpV6(ip, tempIp, CM_IP_LENGTH) != CM_SUCCESS) {
        return false;
    }

    uint32 len = ELEMENT_COUNT(IPV4_LOCAL_HOST_ARRAY);
    uint32 i;
    for (i = 0; i < len; ++i) {
        if (cm_str_equal(tempIp, IPV4_LOCAL_HOST_ARRAY[i])) {
            return CM_TRUE;
        }
    }
    len = ELEMENT_COUNT(IPV6_LOCAL_HOST_ARRAY);
    for (i = 0; i < len; ++i) {
        if (cm_str_equal(tempIp, IPV6_LOCAL_HOST_ARRAY[i])) {
            return CM_TRUE;
        }
    }
    return CM_FALSE;
}

bool ChangeIpV6ToOsFormat(const char *sourceIp, char *destIp, uint32 destSize)
{
    if (CM_IS_EMPTY_STR(sourceIp)) {
        return false;
    }
    if (GetIpVersion(sourceIp) != AF_INET6) {
        return false;
    }
    struct in6_addr sin6Addr;
    errno_t rc = memset_s(&sin6Addr, sizeof(sin6Addr), 0, sizeof(sin6Addr));
    securec_check_errno(rc, (void)rc);
    if (inet_pton(AF_INET6, sourceIp, &sin6Addr) != 1) {
        return false;
    }
    if (inet_ntop(AF_INET6, &sin6Addr, destIp, destSize) == NULL) {
        return false;
    }
    return true;
}

status_t NeedAndRemoveSquareBracketsForIpV6(const char *sourceIp, char *destIp, uint32 size)
{
    if (sourceIp == NULL) {
        return CM_ERROR;
    }
    text_t text;
    CmStr2Text((char *)sourceIp, &text);
    CmRemoveSquareBrackets(&text);
    return CmText2Str(&text, destIp, size);
}

ProcessStatus GetPopenCmdResult(const char *cmd, const char *str, int32 tryTimes)
{
    if (CM_IS_EMPTY_STR(cmd)) {
        write_runlog(ERROR, "%s cmd is NULL, cannot popen cmd.\n", str);
        return PROCESS_STATUS_UNKNOWN;
    }
    char buf[MAX_PATH_LEN + MAX_PATH_LEN];
    FILE *fp;
    errno_t rc;
    ProcessStatus pSt = PROCESS_STATUS_INIT;
    do {
        rc = memset_s(buf, sizeof(buf), 0, sizeof(buf));
        securec_check_intval(rc, (void)rc);
        fp = popen(cmd, "re");
        if (fp == NULL) {
            write_runlog(ERROR, "%s popen failed, cmd is %s, error is %d.\n", str, cmd, errno);
            return PROCESS_STATUS_UNKNOWN;
        }
        while (fgets(buf, sizeof(buf), fp) != NULL) {
            if (strstr(buf, "success") != NULL) {
                (void)pclose(fp);
                return PROCESS_STATUS_SUCCESS;
            } else if (strstr(buf, "unknown") != NULL) {
                pSt = PROCESS_STATUS_UNKNOWN;
            } else if (pSt == PROCESS_STATUS_INIT && strstr(buf, "fail") != NULL) {
                pSt = PROCESS_STATUS_FAIL;
            }
        }
        (void)pclose(fp);
        --tryTimes;
        if (tryTimes > 0) {
            cm_sleep(1);
        }
    } while (tryTimes > 0);
    if (pSt != PROCESS_STATUS_SUCCESS) {
        write_runlog(ERROR, "%s failed to popen: %s, cmd is %s.\n", str, buf, cmd);
    }
    return pSt;
}

ProcessStatus CheckPeerIp(const char *peerIp, const char *str, const char *localIp,
    int32 tryTimes, int32 family)
{
    if (CM_IS_EMPTY_STR(peerIp)) {
        write_runlog(ERROR, "%s failed to check peer ip, because peerIp is NULL.\n", str);
        return PROCESS_STATUS_UNKNOWN;
    }

    char tempPeerIp[CM_IP_LENGTH] = {0};
    if (NeedAndRemoveSquareBracketsForIpV6(peerIp, tempPeerIp, CM_IP_LENGTH) != CM_SUCCESS) {
        write_runlog(ERROR, "%s peer ip %s invalid.\n", __FUNCTION__, peerIp);
        return PROCESS_STATUS_UNKNOWN;
    }
    const char *pingStr = GetPingStr(family);

    char cmd[MAX_PATH_LEN + MAX_PATH_LEN] = {0};
    errno_t rc;
    if (CM_IS_EMPTY_STR(localIp)) {
        rc = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "tmp0=$(%s -c 1 -w 1 %s);", pingStr, tempPeerIp);
    } else {
        char tempLocalIp[CM_IP_LENGTH] = {0};
        if (NeedAndRemoveSquareBracketsForIpV6(localIp, tempLocalIp, CM_IP_LENGTH) != CM_SUCCESS) {
            write_runlog(ERROR, "%s local ip %s invalid.\n", __FUNCTION__, localIp);
            return PROCESS_STATUS_UNKNOWN;
        }
        rc = snprintf_s(cmd,
            sizeof(cmd),
            sizeof(cmd) - 1,
            "tmp0=$(%s -c 1 w 1 -I %s %s);",
            pingStr,
            tempLocalIp,
            tempPeerIp);
    }
    securec_check_intval(rc, (void)rc);

    uint32 len = (uint32)strlen(cmd);
    const char *temp1 = family == AF_INET ? "ping -c 1 -w 1 127.0.0.1 2>&1" : "ping6 -w 1 ::1 2>&1";
    rc = snprintf_s(cmd +len,
        sizeof(cmd) - len,
        (sizeof(cmd) - len) -1,
        "if [ $? == 0]; then echo \"%s\"; "
        "else tmp1=$(%s)"
        "if [ $? == 0 ]; then echo \"%s ${tmp0}\"|tr '\\n' '|'; "
        "else echo \"%s ${tmp0} || ${tmp1}\"|tr '\\n' '|'; fi; fi",
        PING_SUCCESS,
        temp1,
        PING_FAIL,
        PING_UNKNOWN);
    securec_check_intval(rc, (void)rc);
    write_runlog(DEBUG1, "%s ping command is %s.\n", str, cmd);

    return GetPopenCmdResult(cmd, str, tryTimes);
}

#ifdef __cplusplus
}
#endif