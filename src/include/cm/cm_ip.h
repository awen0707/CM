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
* cm_ip.h
*
*
* IDENTIFICATION
*    include/cm/cm_ip.h
*
* -------------------------------------------------------------------------
*/

#ifndef CM_IP_H
#define CM_IP_H

#include <netinet/in.h>
#include "cm_ssl_base.h"
#include "cm_msg_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef CM_IP_LENGTH
#define CM_IP_LENGTH 128
#endif

#define SOCKADDR(sa) ((struct sockaddr *)&(sa)->addr)
#define SOCKADDR_IN4(sa) ((struct sockaddr_in *)&(sa)->addr)
#define SOCKADDR_IN6(sa) ((struct sockaddr_in6 *)&(sa)->addr)
#define SOCKADDR_FAMILY(sa) (SOCKADDR(sa)->sa_family)
#define SOCKADDR_PORT(sa) (SOCKADDR_FAMILY(sa) == AF_INET ? SOCKADDR_IN4(sa)->sin_port : \
SOCKADDR_IN6(sa)->sin6_port)

#define PING_SUCCESS ((const char *)"success")
#define PING_FAIL ((const char *)"fail")
#define PING_UNKNOWN ((const char *)"unknown")

int32 GetIpVersion(const char *ipstr);
char *GetPingStr(int32 family);
bool CheckIpValid(const char *ip);
bool IsEqualIp(const char *clientIp, const char *localIp);
bool8 IsLocalHostIp(const char *ip);
bool ChangeIpV6ToOsFormat(const char *sourceIp, char *destIp, uint32 destSize);
status_t NeedAndRemoveSquareBracketsForIpV6(const char *sourceIp, char *destIp, uint32 size);
ProcessStatus CheckPeerIp(const char *peerIp, const char *str, const char *localIp, int32 tryTimes, int32 family);

#ifdef __cplusplus
}
#endif
#endif