/*
 * Copyright (c) 2022 Huawei Technologies Co.,Ltd.
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
 * cma_datanode_check.cpp
 *
 * IDENTIFICATION
 *    src/cm_agent/client_adpts/libpq/cma_datanode_check.cpp
 *
 * -------------------------------------------------------------------------
 */
#include "cm_msg.h"
#include "cm_text.h"
#include "cm_misc.h"
#include "cm_elog.h"
#include "cm_ip.h"

#include "cm_config.h"

#include "cm_misc_res.h"

#include "cma_global_params.h"
#include "cma_common.h"
#include "cm_util.h"
#include "cma_libpq_com.h"
#include "cma_network_check.h"
#include "cma_datanode_utils.h"

#ifdef ENABLE_UT
#define static
#endif

typedef struct DnResultTextT {
    uint32 cnt;  // the number of parsed SQL result sets
    uint32 maxLen;
    uint32 point; // first ip point
    char result[0];
} DnResultText;

typedef struct DnCmdT {
    uint32 maxLen;
    char cmd[0];
} DnCmd;

typedef struct DnValidateT {
    uint32 cnt;
    bool8 isReentrant[0];
} DnValidate;

typedef struct DnIpTextT {
    DnResultText *dnText;
    DnCmd *dnCmd;
    DnValidate *validate;
} DnIpText;

static DnIpText g_dnIpText[CM_MAX_DATANODE_PER_NODE] = {{0}};
static THR_LOCAL DnIpText g_curDnIpText = {0};

static const char *const LISTEN_ADDRESSES = "listen_addresses";
static const char *const MATCH_POINT = "=";
static const char MATCH_POINT_CHAR = '=';
static const char *const IPV4_ALL_LISTEN_ADDRESSES = "0.0.0.0";
static const char *const IPV4_ALL_LISTEN_ADDRESSES_ARRAY[] = {IPV4_ALL_LISTEN_ADDRESSES, "*"};
static const char *const IPV6_ALL_LISTEN_ADDRESSES = "::";
static const char *const IPV6_ALL_LISTEN_ADDRESSES_ARRAY[] = {IPV6_ALL_LISTEN_ADDRESSES, "*"};
static const char *const LOCAL_HOST = {"localhost"};
static const char INPUT_END_ARRAY[] = {'\n'};
static const char SEPARATOR_ARRAY[] = {',', '\0'};

static const uint32 INIT_DN_IP_LEN = SIZE_K(2);
static const uint32 MAX_DN_IP_LEN = SIZE_K(10);
static const uint32 INVALID_DN_IP_LEN = 0xFFFFFFFF;
static const uint32 ENLARGEMENT = 2;

static const uint32 INVALID_DN_CMD = 0xFFFFFFFF;
static const uint32 INIT_DN_CMD_LEN = INIT_DN_IP_LEN + MAX_PATH_LEN;
static const uint32 MAX_DN_CMD_LEN = MAX_DN_IP_LEN + MAX_PATH_LEN;

static uint32 GetCurDnInstId(uint32 dnIdx)
{
    return g_currentNode->datanode[dnIdx].datanodeId;
}

static const char *GetCurDnDataPath(uint32 dnIdx)
{
    return g_currentNode->datanode[dnIdx].datanodeLocalDataPath;
}

static DnIpText *GetCurDnIpText()
{
    return &g_curDnIpText;
}

static status_t CheckIpInputForSecurity(const char *ipInput)
{
    const char *dangerCharList[] = {
        "|", ";", "&", "$", "<", ">", "`", "\\", "{", "}", "(", ")", "[", "]", "~", "?", "!", "\n", NULL};

    for (int32 i = 0; dangerCharList[i] != NULL; i++) {
        if (strstr(ipInput, dangerCharList[i]) != NULL) {
            write_runlog(ERROR, "invalid token \"%s\" in input_value: (%s)\n", dangerCharList[i], ipInput);
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

static status_t CheckIpInfoDnIdx(uint32 dnIdx, const char *str)
{
    if (dnIdx >= CM_MAX_DATANODE_PER_NODE) {
        write_runlog(ERROR, "%s failed to get dnIpInfo, because dnIdx(%u) is beyond the range[0: %d).\n",
            str, dnIdx, CM_MAX_DATANODE_PER_NODE);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static void ResetDnText(DnResultText *dnText)
{
    if (dnText == NULL) {
        write_runlog(ERROR, "[ResetDnText] dnText is NULL.\n");
        return;
    }
    uint32 maxLen = dnText->maxLen;
    uint32 trueLen = (uint32)sizeof(DnResultText) + maxLen;
    errno_t rc = memset_s(dnText, trueLen, 0, trueLen);
    securec_check_errno(rc, (void)rc);
    dnText->maxLen = maxLen;
}

static status_t GetDnText(DnIpText *dnIpText, uint32 ipLen = INVALID_DN_IP_LEN)
{
    if (dnIpText == NULL) {
        write_runlog(ERROR, "[GetDnText] dnIpText is NULL, cannot Get Dn Text.\n");
        return CM_ERROR;
    }

    DnResultText *dnText = dnIpText->dnText;
    uint32 tempLen = INIT_DN_IP_LEN;

    if (ipLen != INVALID_DN_IP_LEN) {
        uint32 trueLen = CM_MAX(CM_MIN(ipLen, MAX_DN_IP_LEN), INIT_DN_IP_LEN);
        tempLen = CM_ALIGN4(trueLen);
    }

    if (dnText == NULL || (ipLen != INVALID_DN_IP_LEN && tempLen > dnText->maxLen)) {
        FREE_AND_RESET(dnIpText->dnText);
        uint32 needLen = tempLen + (uint32)sizeof(DnResultText);
        dnIpText->dnText = (DnResultText *)malloc(needLen);
        if (dnIpText->dnText == NULL) {
            write_runlog(ERROR, "failed to get GetDnText, because failed to malloc memory(%u).\n", needLen);
            return CM_ERROR;
        }
        write_runlog(LOG, "it will GetDnText, needLen=%u, ipLen=%u, maxLen=%u.\n", needLen, ipLen, tempLen);
        dnText = dnIpText->dnText;
        dnText->maxLen = tempLen;
        ResetDnText(dnText);
    }
    return CM_SUCCESS;
}

static DnIpText *GetDnIpText(uint32 dnIdx)
{
    CM_RETNULL_IFERR(CheckIpInfoDnIdx(dnIdx, "[GetDnIpText]"));
    return &(g_dnIpText[dnIdx]);
}

static void ResetDnCmd(DnCmd *dnCmd)
{
    if (dnCmd == NULL) {
        return;
    }
    uint32 maxLen = dnCmd->maxLen;
    uint32 trueLen = sizeof(DnCmd) + maxLen;
    errno_t rc = memset_s(dnCmd, trueLen, 0, trueLen);
    securec_check_errno(rc, (void)rc);
    dnCmd->maxLen = maxLen;
}

static status_t GetDnCmd(DnIpText *dnIpText, uint32 cmdLen = INVALID_DN_CMD)
{
    if (dnIpText == NULL) {
        write_runlog(ERROR, "[GetDnCmd] dnIpText is NULL, cannot get Dn Cmd.\n");
        return CM_ERROR;
    }
    DnCmd *dnCmd = dnIpText->dnCmd;

    uint32 tempLen = INIT_DN_CMD_LEN;
    if (cmdLen != INVALID_DN_CMD) {
        uint32 trueLen = CM_MAX(CM_MIN(cmdLen, MAX_DN_CMD_LEN), INIT_DN_CMD_LEN);
        tempLen = CM_ALIGN4(trueLen);
    }

    if (dnCmd == NULL || (cmdLen != INVALID_DN_CMD && tempLen > dnCmd->maxLen)) {
        FREE_AND_RESET(dnIpText->dnCmd);
        uint32 needLen = tempLen + (uint32)sizeof(DnCmd);
        dnIpText->dnCmd = (DnCmd *)malloc(needLen);
        if (dnIpText->dnCmd == NULL) {
            write_runlog(ERROR, "failed to get GetDnCmd, because failed to malloc memory(%u).\n", needLen);
            return CM_ERROR;
        }
        write_runlog(LOG, "it will GetdnCmd, needLen=%u, cmdLen=%u, maxLen=%u.\n", needLen, cmdLen, tempLen);
        dnIpText->dnCmd->maxLen = tempLen;
        ResetDnCmd(dnIpText->dnCmd);
    }
    return CM_SUCCESS;
}

static void ResetDnValidate(const DnIpText *dnIpText)
{
    if (dnIpText == NULL || dnIpText->validate == NULL) {
        return;
    }
    DnValidate *validate = dnIpText->validate;
    uint32 cnt = validate->cnt;
    uint32 trueLen = sizeof(DnValidate) + cnt * sizeof(bool8);
    errno_t rc = memset_s(validate, trueLen, 0, trueLen);
    securec_check_errno(rc, (void)rc);
    validate->cnt = cnt;
}

static status_t GetDnValidate(DnIpText *dnIpText, uint32 cnt)
{
    const char *str = "[GetDnValidate]";
    if (dnIpText == NULL || cnt == 0) {
        write_runlog(ERROR, "%s dnIpText is NULL or cnt is 0, cannot get Dn validate.\n", str);
        return CM_ERROR;
    }
    if (dnIpText->validate == NULL || dnIpText->validate->cnt < cnt) {
        FREE_AND_RESET(dnIpText->validate);
        uint32 needLen = (uint32)sizeof(DnValidate) + cnt * (uint32)sizeof(bool8);
        dnIpText->validate = (DnValidate*)malloc(needLen);
        if (dnIpText->validate == NULL) {
            write_runlog(ERROR, "%s failed ot get dn validate, because failed to malloc memory(%u).\n", str, needLen);
            return CM_ERROR;
        }
        dnIpText->validate->cnt = cnt;
        ResetDnValidate(dnIpText);
        // dnIpText init, may be need to execute dn validate
        for (uint32 i = 0; i < dnIpText->validate->cnt; ++i) {
            dnIpText->validate->isReentrant[i] = CM_TRUE;
        }
    }
    return CM_SUCCESS;
}

static void ResetFloatIpDnNetState(DnStatus *dnStatus)
{
    DnFloatIpInfo *dnFloatIp = &(dnStatus->floatIpInfo.info);
    for (uint32 i = 0; i < dnFloatIp->count; ++i) {
        dnFloatIp->dnNetState[i] = (int32)NETWORK_STATE_UNKNOWN;
    }
}

static status_t DnTextTrim(char *text, char matchPoint, uint32 beginPoint, uint32 *point)
{
    uint32 tempPoint = beginPoint;
    uint32 i = tempPoint;
    bool8 isMatched = CM_FALSE;
    for (; text[i] != '\0'; ++i) {
        if (text[i] != matchPoint) {
            tempPoint = i;
            isMatched = CM_TRUE;
            break;
        }
    }
    if (!isMatched) {
        write_runlog(
            ERROR, "failed to trim text, cannot find the matched, text=[%s], matchPoint=[%c].\n", text, matchPoint);
        return CM_ERROR;
    }
    i = (uint32)strlen(text) - 1;
    for (; i > tempPoint; --i) {
        if (text[i] == matchPoint) {
            text[i] = '\0';
        } else {
            break;
        }
    }
    *point = tempPoint;
    return CM_SUCCESS;
}

static status_t GetMatchPoint(char *text, char matchPoint, uint32 *point)
{
    uint32 tempPoint = 0;
    uint32 i = 0;
    for (; text[i] != '\0'; ++i) {
        if (text[i] == matchPoint) {
            tempPoint = i + 1;
            break;
        }
    }
    if (tempPoint >= (uint32)strlen(text)) {
        write_runlog(ERROR, "%d failed to getMatchPoint, bacause text=[%s], point=[%u: %zu].\n",
            __LINE__, text, tempPoint, strlen(text));
        return CM_ERROR;
    }

    write_runlog(DEBUG1, "%d text[%u]=[\"%c\": \"%s\"].\n", __LINE__, tempPoint, text[tempPoint], &text[tempPoint]);

    if (DnTextTrim(text, ' ', tempPoint, &tempPoint) != CM_SUCCESS) {
        return CM_ERROR;
    }

    while (CM_IS_QUOTE_CHAR(text[tempPoint])) {
        if (text[strlen(text) - 1] == text[tempPoint]) {
            /* This tells the compiler that there will be no overflow issues */
#pragma GCC diagnostic ignored "-Wstringop-overflow"
            text[strlen(text) - 1] = '\0';
#pragma GCC diagnostic pop
        }
        if ((tempPoint + 1) >= strlen(text)) {
            write_runlog(ERROR, "%d failed to getMatchPoint, bacause text=[%s], point=[%u: %zu].\n",
                __LINE__, text, tempPoint, strlen(text));
            return CM_ERROR;
        }
        ++tempPoint;
        if (DnTextTrim(text, ' ', tempPoint, &tempPoint) != CM_SUCCESS) {
            return CM_ERROR;
        }
    }
    write_runlog(DEBUG1, "%d text[%u]=[\"%c\": \"%s\"].\n", __LINE__, tempPoint, text[tempPoint], &text[tempPoint]);
    *point = tempPoint;
    return CM_SUCCESS;
}

static void PrintDnText(const DnResultText *dnText, uint32 instId, const char *str, int32 logLevel = DEBUG1)
{
    if (GetCmLogMessage() > logLevel) {
        return;
    }

    char ipInfo[INIT_DN_IP_LEN] = {0};
    uint32 curPoint = dnText->point;
    errno_t rc;
    const char *curStr;
    uint32 curLen;
    for (uint32 i = 0; i < dnText->cnt; ++i) {
        while (curPoint < dnText->maxLen && dnText->result[curPoint] == '\0') {
            ++curPoint;
        }
        if (curPoint >= dnText->maxLen) {
            write_runlog(ERROR, "%s instId(%u) cannot print dn text, when curPoint=[%u: %u].\n",
                __FUNCTION__, instId, curPoint, dnText->maxLen);
            return;
        }
        curStr = dnText->result + curPoint;
        curLen = (uint32)strlen(ipInfo);
        if (curLen >= INIT_DN_IP_LEN) {
            write_runlog(DEBUG1, "%s instId(%u) curLen(%u) is more than %u.\n", str, instId, curLen, INIT_DN_IP_LEN);
            break;
        }
        if (i == dnText->cnt - 1) {
            rc = snprintf_s(ipInfo + curLen, INIT_DN_IP_LEN - curLen, (INIT_DN_IP_LEN - curLen) - 1, "%s", curStr);
        } else {
            rc = snprintf_s(ipInfo + curLen, INIT_DN_IP_LEN - curLen, (INIT_DN_IP_LEN - curLen) - 1, "%s, ", curStr);
        }
        securec_check_intval(rc, (void)rc);
        curPoint += (uint32)strlen(curStr);
    }
    write_runlog(logLevel, "[%s] instId(%u) success to get [cnt=[%u]: ipInfo=[%s]].\n",
        str, instId, dnText->cnt, ipInfo);
}

static bool8 IsCurIpAllListenAddress(const char *ip)
{
    if (CM_IS_EMPTY_STR(ip)) {
        return CM_FALSE;
    }
    uint32 len = ELEMENT_COUNT(IPV4_ALL_LISTEN_ADDRESSES_ARRAY);
    uint32 i;
    for (i = 0; i < len; ++i) {
        if (cm_str_equal(ip, IPV4_ALL_LISTEN_ADDRESSES_ARRAY[i])) {
            return CM_TRUE;
        }
    }

    len = ELEMENT_COUNT(IPV6_ALL_LISTEN_ADDRESSES_ARRAY);
    for (i = 0; i < len; ++i) {
        if (cm_str_equal(ip, IPV6_ALL_LISTEN_ADDRESSES_ARRAY[i])) {
            return CM_TRUE;
        }
    }
    
    return CM_FALSE;
}

static bool8 IsIpSkipCheck(const char *ip)
{
    if (cm_str_equal(ip, LOCAL_HOST)) {
        return CM_TRUE;
    }
    if (IsCurIpAllListenAddress(ip)) {
        return CM_TRUE;
    }
    return CM_FALSE;
}

static bool8 CheckDnTextValid(const DnResultText *dnText, uint32 instId)
{
    uint32 curPoint = dnText->point;
    const char *curIp;
    for (uint32 i = 0; i < dnText->cnt; ++i) {
        while (curPoint < dnText->maxLen && dnText->result[curPoint] == '\0') {
            ++curPoint;
        }
        if (curPoint >= dnText->maxLen) {
            write_runlog(ERROR, "%s instId(%u) cannot check whether dn text is valid , when curPoint=[%u: %u].\n",
                __FUNCTION__, instId, curPoint, dnText->maxLen);
            return CM_FALSE;
        }
        curIp = dnText->result + curPoint;
        if (!IsIpSkipCheck(curIp) && !CheckIpValid(curIp)) {
            write_runlog(ERROR, "instId(%u) find the invalid ip(%s), cannot arbitrate.\n", instId, curIp);
            return CM_FALSE;
        }
        curPoint += (uint32)strlen(curIp);
    }
    return CM_TRUE;
}

static status_t ParseDnText(DnResultText *dnText, uint32 instId)
{
    uint32 point = 0;
    if (GetMatchPoint(dnText->result, MATCH_POINT_CHAR, &point) != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (point >= (uint32)strlen(dnText->result)) {
        write_runlog(ERROR, "instId(%u) failed to parse Dn Text, bacause dnText=[%s], point=[%u: %zu].\n",
            instId, dnText->result, point, strlen(dnText->result));
        return CM_ERROR;
    }
    dnText->point = point;
    bool8 isFirst = CM_TRUE;
    uint32 cnt = 0;
    for (uint32 i = point; dnText->result[i] != '\0'; ++i) {
        if (dnText->result[i] == SEPARATOR_ARRAY[0] || dnText->result[i] == ' ') {
            dnText->result[i] = '\0';
            isFirst = CM_TRUE;
        } else if (isFirst) {
            isFirst = CM_FALSE;
            ++cnt;
        }
    }
    dnText->cnt = cnt;
    PrintDnText(dnText, instId, "ParseDnText");
    if (!CheckDnTextValid(dnText, instId)) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static bool8 IsFindVipInDnText(const DnResultText *dnText, const char *ip, bool8 isDel, bool8 *isAllListen)
{
    if (CM_IS_EMPTY_STR(dnText->result) || CM_IS_EMPTY_STR(ip)) {
        write_runlog(ERROR, "Failed to find the vip in dnText, because DnText or ip is null.\n");
        return CM_FALSE;
    }
    uint32 curPoint = dnText->point;
    const char *curIp;
    *isAllListen = CM_FALSE;
    for (uint32 i = 0; i < dnText->cnt; ++i) {
        while (curPoint < dnText->maxLen && dnText->result[curPoint] == '\0') {
            ++curPoint;
        }
        if (curPoint >= dnText->maxLen) {
            write_runlog(ERROR, "%s cannot check whether vip is in DnText, when curPoint=[%u: %u].\n",
                __FUNCTION__, curPoint, dnText->maxLen);
            return CM_FALSE;
        }
        curIp = dnText->result + curPoint;
        if (IsEqualIp(ip, curIp)) {
            return CM_TRUE;
        }
        if (!isDel && IsCurIpAllListenAddress(curIp)) {
            *isAllListen = CM_TRUE;
            return CM_TRUE;
        }
        curPoint += (uint32)strlen(curIp);
    }
    return CM_FALSE;
}

static bool8 IsResultEnd(const char *result)
{
    uint32 arrLen = ELEMENT_COUNT(INPUT_END_ARRAY);
    for (uint32 i = 0; i < arrLen; ++i) {
        if (result[strlen(result) - 1] == INPUT_END_ARRAY[i]) {
            return CM_TRUE;
        }
    }
    return CM_FALSE;
}

static status_t GetDnListenAddressesFromFile(DnIpText *dnIpText, uint32 dnIdx)
{
    DnFloatIp *dnFloatIp = GetDnFloatIpByDnIdx(dnIdx);
    if (dnFloatIp == NULL || dnFloatIp->dnFloatIpCount == 0) {
        return CM_ERROR;
    }
    const char *str = "[GetDnListenAddressesFromFile]";

    CM_RETURN_IFERR(GetDnText(dnIpText, INIT_DN_IP_LEN + dnFloatIp->dnFloatIpCount * CM_IP_LENGTH));
    char cmd[MAX_PATH_LEN] = {0};
    errno_t rc = snprintf_s(cmd, MAX_PATH_LEN, MAX_PATH_LEN - 1, "gs_guc check -Z datanode -D %s -c \"%s\" 2>&1 "
        "| grep \"gs_guc check\" | awk -F ': ' '{print $3}'", GetCurDnDataPath(dnIdx), LISTEN_ADDRESSES);
    securec_check_intval(rc, (void)rc);
    uint32 instId = GetCurDnInstId(dnIdx);
    FILE *cmdFd = popen(cmd, "r");
    if (cmdFd == NULL) {
        write_runlog(ERROR, "%s instId(%u) popen %s failed, errno is %d.\n", str, instId, cmd, errno);
        return CM_ERROR;
    }
    write_runlog(DEBUG1, "%s instId(%u) cmd=%s.\n", str, instId, cmd);
    DnResultText *dnText = dnIpText->dnText;
    bool8 isEnd = CM_FALSE;
    while (fgets(dnText->result, (int32)dnText->maxLen, cmdFd) != NULL) {
        write_runlog(DEBUG1, "%s instId(%u) success to get dnText(%s).\n", str, instId, dnText->result);
        if (cm_str_match(dnText->result, LISTEN_ADDRESSES) && cm_str_match(dnText->result, MATCH_POINT)) {
            write_runlog(DEBUG1, "%s instId(%u) success to get dnText(%s).\n", str, instId, dnText->result);
            isEnd = IsResultEnd(dnText->result);
            break;
        }
        rc = memset_s(dnText->result, dnText->maxLen, 0, dnText->maxLen);
        securec_check_errno(rc, (void)rc);
    }
    (void)pclose(cmdFd);

    if (!isEnd) {
        write_runlog(ERROR, "%s instId(%u) cannot get %s with cmd[%s], because the dnText is not end.\n",
            str, instId, LISTEN_ADDRESSES, cmd);
        (void)GetDnText(dnIpText, ENLARGEMENT * dnText->maxLen);
        return CM_ERROR;
    }

    if (CM_IS_EMPTY_STR(dnText->result)) {
        write_runlog(ERROR, "%s instId(%u) cannot get %s with cmd[%s], because the result is empty.\n",
            str, instId, LISTEN_ADDRESSES, cmd);
        return CM_ERROR;
    }

    dnText->result[strlen(dnText->result) - 1] = '\0';
    CM_RETURN_IFERR(CheckIpInputForSecurity(dnText->result));
    return ParseDnText(dnText, instId);
}

static int32 CheckFloatIpListen(const char *ip, uint32 dnIdx)
{
    char cmd[INIT_DN_CMD_LEN] = {0};
    errno_t rc = snprintf_s(cmd, INIT_DN_CMD_LEN, INIT_DN_CMD_LEN - 1, "netstat -anopW 2>&1 |grep \""
        "$(ps -ux |grep -w \"%s/%s\"|grep -w \"%s\" |grep -v grep | awk '{print $2}')/%s\" "
        "| grep -w \"LISTEN\" | awk '{print $4}'| grep -w \"%s\"",
        g_binPath, GetDnProcessName(), GetCurDnDataPath(dnIdx), GetDnProcessName(), ip);
    securec_check_intval(rc, (void)rc);
    int32 errCode = 0;
    int32 res = ExecuteSystemCmd(cmd, DEBUG1, &errCode);
    if (res != 0) {
        write_runlog(DEBUG1, "instId(%u) failed to execute the cmd(%s), res=%d, errno is %d, errCode is %d.\n",
            GetCurDnInstId(dnIdx), cmd, res, errno, errCode);
        if (res == ERROR_EXECUTE_CMD) {
            return (int32)NETWORK_STATE_UNKNOWN;
        }
        return (int32)NETWORK_STATE_DOWN;
    }
    write_runlog(DEBUG1, "instId(%u) success to execute the cmd[%s].\n", GetCurDnInstId(dnIdx), cmd);
    return (int32)NETWORK_STATE_UP;
}

static void GetAllFloatIpNetState(DnStatus *dnStatus, const DnFloatIp *dnFloatIp, uint32 dnIdx, int32 dnRole)
{
    DnFloatIpInfo *floatIpInfo = &(dnStatus->floatIpInfo.info);
    bool8 isNeedCheckAllListen = CM_TRUE;
    int32 listenRet = 0;
    for (uint32 i = 0; i < dnFloatIp->dnFloatIpCount; ++i) {
        listenRet = CheckFloatIpListen(dnFloatIp->dnFloatIp[i], dnIdx);
        if (listenRet != (int32)NETWORK_STATE_DOWN) {
            isNeedCheckAllListen = CM_FALSE;
        }
        floatIpInfo->dnNetState[i] = listenRet;
    }
    if (!isNeedCheckAllListen) {
        return;
    }

    for (uint32 i = 0; i < dnFloatIp->dnFloatIpCount; ++i) {
        listenRet = CheckFloatIpListen(GetIpVersion(
            dnFloatIp->dnFloatIp[i]) == AF_INET6 ? IPV6_ALL_LISTEN_ADDRESSES : IPV4_ALL_LISTEN_ADDRESSES,
            dnIdx);
        if (listenRet == (int32)NETWORK_STATE_DOWN) {
            continue;
        }
        floatIpInfo->dnNetState[i] = listenRet;
        if (listenRet == (int32)NETWORK_STATE_UP) {
            floatIpInfo->dnNetState[i] =
                (int32)((dnRole == INSTANCE_ROLE_PRIMARY) ? NETWORK_STATE_UP : NETWORK_STATE_DOWN);
        }
    }
}

static status_t GetDnNetStateFromFile(
    DnIpText *dnIpText, DnFloatIpInfo *floatIpInfo, uint32 dnIdx, int32 role, bool8 isDel)
{
    DnFloatIp *dnFloatIp = GetDnFloatIpByDnIdx(dnIdx);
    if (dnFloatIp == NULL || dnFloatIp->dnFloatIpCount == 0) {
        return CM_SUCCESS;
    }
    const char *str = "[GetDnNetStateFromFile]";
    uint32 instId = GetCurDnInstId(dnIdx);
    if (GetDnListenAddressesFromFile(dnIpText, dnIdx) != CM_SUCCESS) {
        write_runlog(LOG, "%s instId(%u) cannot get DnListAddresses.\n", str, instId);
        return CM_ERROR;
    }
    if (dnIpText->dnText == NULL) {
        write_runlog(LOG, "%s instId(%u) cannot find the dnIpText.\n", str, instId);
        return CM_ERROR;
    }
    bool8 isAllListen = CM_FALSE;
    for (uint32 i = 0; i < dnFloatIp->dnFloatIpCount; ++i) {
        if (isAllListen || IsFindVipInDnText(dnIpText->dnText, dnFloatIp->dnFloatIp[i], isDel, &isAllListen)) {
            floatIpInfo->dnNetState[i] =
                (role != INSTANCE_ROLE_PRIMARY && isAllListen) ? (int32)NETWORK_STATE_DOWN : (int32)NETWORK_STATE_UP;
        } else {
            floatIpInfo->dnNetState[i] = (int32)NETWORK_STATE_DOWN;
        }
    }
    return CM_SUCCESS;
}

static void GetDnAllFloatIp(DnIpText *dnIpText, DnStatus *dnStatus, uint32 dnIdx, bool8 isRunning)
{
    DnFloatIp *dnFloatIp = GetDnFloatIpByDnIdx(dnIdx);
    if (dnFloatIp == NULL || dnFloatIp->dnFloatIpCount == 0) {
        return;
    }

    DnFloatIpInfo *floatIpInfo = &(dnStatus->floatIpInfo.info);
    floatIpInfo->count = dnFloatIp->dnFloatIpCount;
    NetworkState state[MAX_FLOAT_IP_COUNT];
    GetFloatIpNicStatus(dnFloatIp->instId, CM_INSTANCE_TYPE_DN, state, MAX_FLOAT_IP_COUNT);
    for (uint32 i = 0; i < floatIpInfo->count; ++i) {
        floatIpInfo->nicNetState[i] = (int32)state[i];
    }

    int32 dnRole = dnStatus->reportMsg.local_status.local_role;
    if (isRunning) {
        GetAllFloatIpNetState(dnStatus, dnFloatIp, dnIdx, dnRole);
        (void)GetDnListenAddressesFromFile(dnIpText, dnIdx);
        return;
    }

    if (GetDnNetStateFromFile(dnIpText, floatIpInfo, dnIdx, dnRole, CM_FALSE) == CM_SUCCESS) {
        return;
    }
    ResetFloatIpDnNetState(dnStatus);
}

static bool8 CheckExecuteCmdParam(DnIpText *dnIpText, uint32 dnIdx)
{
    DnFloatIp *dnFloatIp = GetDnFloatIpByDnIdx(dnIdx);
    if (dnFloatIp == NULL) {
        return CM_FALSE;
    }
    if (dnIpText->dnText == NULL || CM_IS_EMPTY_STR(dnIpText->dnText->result)) {
        write_runlog(ERROR, "instId (%u) dnText is NULL.\n", GetCurDnInstId(dnIdx));
        return CM_FALSE;
    }
    status_t st =
        GetDnCmd(dnIpText, (dnIpText->dnText->maxLen + CM_IP_LENGTH * dnFloatIp->dnFloatIpCount) + MAX_PATH_LEN);
    if (st != CM_SUCCESS) {
        write_runlog(ERROR, "instId (%u) dnCmd is NULL.\n", GetCurDnInstId(dnIdx));
        return CM_FALSE;
    }
    return CM_TRUE;
}

static void SetDnFloatIpCmd(DnCmd *dnCmd, const char *curIp, bool8 *isFirstIp)
{
    uint32 curLen = (uint32)strlen(dnCmd->cmd);
    if (curLen >= dnCmd->maxLen) {
        write_runlog(ERROR, "cannot set dn floatIpCmd, when curLen=%u, maxLen=%u.\n", curLen, dnCmd->maxLen);
        return;
    }
    errno_t rc;
    if (!(*isFirstIp)) {
        rc = snprintf_s(dnCmd->cmd + curLen, dnCmd->maxLen - curLen, (dnCmd->maxLen - curLen) - 1,
            "%s%s", SEPARATOR_ARRAY, curIp);
    } else {
        *isFirstIp = CM_FALSE;
        rc = snprintf_s(dnCmd->cmd + curLen, dnCmd->maxLen - curLen, (dnCmd->maxLen - curLen) - 1,
            "%s", curIp);
    }
    securec_check_intval(rc, (void)rc);
}

static void ClearCntIp(bool8 tmpFindCurIp, NetworkOper oper, char *ip, uint32 len, uint32 *clearCnt)
{
    if (tmpFindCurIp && oper == NETWORK_OPER_DOWN) {
        errno_t rc = memset_s(ip, len, 0, len);
        securec_check_errno(rc, (void)rc);
        ++(*clearCnt);
    }
}

static status_t GetDnFloatIpCmd(const char *floatIp, DnIpText *dnIpText, NetworkOper oper, uint32 instId)
{
    DnResultText *dnText = dnIpText->dnText;
    DnCmd *dnCmd = dnIpText->dnCmd;
    uint32 curPoint = dnText->point;
    char *curIp;
    bool8 isFirstIp = CM_TRUE;
    bool8 isFindCurIp = CM_FALSE;
    bool8 tmpFindCurIp;
    uint32 clearCnt = 0;
    for (uint32 i = 0; i < dnText->cnt; ++i) {
        while (curPoint < dnText->maxLen && dnText->result[curPoint] == '\0') {
            ++curPoint;
        }

        if (curPoint >= dnText->maxLen) {
            write_runlog(ERROR, "%s instId(%u) cannot get floatIp cmd, when curPoint=[%u: %u].\n",
                __FUNCTION__, instId, curPoint, dnText->maxLen);
            return CM_ERROR;
        }

        curIp = dnText->result + curPoint;
        tmpFindCurIp = CM_FALSE;
        if (IsEqualIp(floatIp, curIp)) {
            isFindCurIp = CM_TRUE;
            tmpFindCurIp = CM_TRUE;
        } else {
            SetDnFloatIpCmd(dnCmd, curIp, &isFirstIp);
        }
        curPoint += (uint32)strlen(curIp);
        ClearCntIp(tmpFindCurIp, oper, curIp, (uint32)strlen(curIp), &clearCnt);
    }

    if (oper == NETWORK_OPER_UP) {
        SetDnFloatIpCmd(dnCmd, floatIp, &isFirstIp);
        if (!isFindCurIp && (curPoint + 1 + strlen(floatIp) < dnText->maxLen)) {
            errno_t rc = snprintf_s(dnText->result + curPoint + 1, (dnText->maxLen - curPoint) - 1,
                ((dnText->maxLen - curPoint) - 1) - 1, "%s", floatIp);
            ++dnText->cnt;
            securec_check_intval(rc, (void)rc);
        }
    } else if (oper == NETWORK_OPER_DOWN) {
        dnText->cnt -= clearCnt;
        if (isFirstIp) {
            write_runlog(ERROR, "instId(%u) ip only has floatIp, cannot del it.\n", instId);
            return CM_ERROR;
        }
    }
    PrintDnText(dnText, instId, "[GetDnFloatIpCmd]");
    return CM_SUCCESS;
}

static bool8 ExecuteFloatIpCmd(const char *floatIp, DnIpText *dnIpText, bool8 isRunning,
    uint32 dnIdx, NetworkOper oper)
{
    CM_RETFALSE_IFNOT(CheckExecuteCmdParam(dnIpText, dnIdx));
    ResetDnCmd(dnIpText->dnCmd);
    const char *cmdOper = isRunning ? "reload" : "set";
    DnCmd *dnCmd = dnIpText->dnCmd;
    errno_t rc = snprintf_s(dnCmd->cmd, dnCmd->maxLen, dnCmd->maxLen - 1, "gs_guc %s "
        "-Z datanode -D %s -c \"%s = \'", cmdOper, GetCurDnDataPath(dnIdx), LISTEN_ADDRESSES);
    securec_check_intval(rc, (void)rc);

    uint32 instId = GetCurDnInstId(dnIdx);
    if (GetDnFloatIpCmd(floatIp, dnIpText, oper, instId) != CM_SUCCESS) {
        return CM_FALSE;
    }

    uint32 cmdLen = (uint32)strlen(dnCmd->cmd);
    if (cmdLen + 1 >= dnCmd->maxLen) {
        write_runlog(ERROR, "instId(%u) failed to executeFloatIpCmd, because cmd[%s] is beyond the region[0: %u].\n",
            instId, dnCmd->cmd, dnCmd->maxLen);
        return CM_FALSE;
    }
    rc = snprintf_s(dnCmd->cmd + cmdLen, dnCmd->maxLen - cmdLen, (dnCmd->maxLen - cmdLen) - 1,
        "\'\" >> \"%s\" 2>&1", system_call_log);
    securec_check_intval(rc, (void)rc);
    write_runlog(LOG, "[%s] it will execute the cmd[%s].\n", __FUNCTION__, dnCmd->cmd);
    int32 res = ExecuteSystemCmd(dnCmd->cmd);
    if (res != 0) {
        write_runlog(ERROR, "instId(%u) failed to execute the cmd(%s), res=%d, errno is %d.\n", instId, dnCmd->cmd,
            res, errno);
        return CM_FALSE;
    }
    return CM_TRUE;
}

static int32 ClearConn(
    CltResultSet set, const cltPqResult_t *nodeResult, const char *sqlCommand, const SqlCond *sqlCond)
{
    const char *str = "[ClearConn]";
    write_runlog(LOG, "[%s: %u] %s sqlCommands[%s] listen_ip validate ok.\n",
        sqlCond->str, sqlCond->instId, str, sqlCommand);
    return 0;
}

static int32 ClearDnIpConn(const char *ip, uint32 dnIdx)
{
    const char *str = "[ClearDnIpConn]";
    static cmTime_t lastTime = {0, 0};
    cmTime_t curTime = {0, 0};
    (void)clock_gettime(CLOCK_MONOTONIC, &curTime);
    const long printInterval = 30;
    // conn may be null for a long time
    if (g_dnConn[dnIdx] == NULL) {
        int32 logLevel = DEBUG1;
        if (curTime.tv_sec - lastTime.tv_sec >= printInterval) {
            (void)clock_gettime(CLOCK_MONOTONIC, &lastTime);
            logLevel = LOG;
        }
        write_runlog(logLevel, "%s instId(%u) g_dnConn[%u] is null.\n", str, GetCurDnInstId(dnIdx), dnIdx);
        return -1;
    }

    char sqlCommand[MAX_PATH_LEN] = {0};
    errno_t rc = snprintf_s(sqlCommand, MAX_PATH_LEN, MAX_PATH_LEN - 1, "select gs_validate_ext_listen_ip('normal', "
        "setting::cstring, '%s') from pg_settings where name = 'pgxc_node_name' limit 1;", ip);
    securec_check_intval(rc, (void)rc);
    SqlCond sqlCond = {.str="[ClearDnIpConn]", .instId = GetCurDnInstId(dnIdx)};
    return ExecDmlSqlCmd(ClearConn, NULL, &(g_dnConn[dnIdx]), sqlCommand, &sqlCond);
}

static void ResetValidateWithExpect(DnValidate *validate, bool8 value, uint32 index)
{
    if (validate == NULL) {
        write_runlog(LOG, "[ResetValidateWithExpect] instId(%u) validate is NULL.\n", GetCurDnInstId(index));
        return;
    }
    if (index >= validate->cnt) {
        write_runlog(ERROR, "[ResetValidateWithExpect] instId(%u) validate cnt=[%u: %u].\n",
            GetCurDnInstId(index), index, validate->cnt);
        return;
    }
    validate->isReentrant[index] = value;
}

static bool8 ExeVipCmdAndValidate(uint32 index, DnIpText *dnIpText, bool8 isRunning, uint32 dnIdx, NetworkOper oper)
{
    DnFloatIp *dnFloatIp = GetDnFloatIpByDnIdx(dnIdx);
    if (dnFloatIp == NULL) {
        return CM_TRUE;
    }
    bool8 ret = ExecuteFloatIpCmd(dnFloatIp->dnFloatIp[index], dnIpText, isRunning, dnIdx, oper);
    if (oper == NETWORK_OPER_DOWN) {
        if (ret && isRunning) {
            int32 execRet = ClearDnIpConn(dnFloatIp->dnFloatIp[index], dnIdx);
            status_t st = GetDnValidate(dnIpText, dnFloatIp->dnFloatIpCount);
            if (st != CM_SUCCESS) {
                write_runlog(ERROR, "[DoFloatIpOper] instId(%u) failed to get dn validate.\n", GetCurDnInstId(dnIdx));
                return ret;
            }
            dnIpText->validate->isReentrant[index] = (execRet == 0) ? CM_FALSE : CM_TRUE;
        } else {
            ResetValidateWithExpect(dnIpText->validate, CM_TRUE, dnIdx);
        }
    } else {
        ResetDnValidate(dnIpText);
    }
    return ret;
}

static void DoFloatIpOper(DnIpText *dnIpText, const DnStatus *dnStatus, uint32 dnIdx, bool8 isRunning)
{
    DnFloatIp *dnFloatIp = GetDnFloatIpByDnIdx(dnIdx);
    if (dnFloatIp == NULL) {
        return;
    }

    NetworkOper oper = GetFloatIpOper(dnIdx);
    if (oper != NETWORK_OPER_UP && oper != NETWORK_OPER_DOWN) {
        return;
    }
    if (oper == NETWORK_OPER_UP && dnStatus->reportMsg.local_status.local_role != INSTANCE_ROLE_PRIMARY) {
        return;
    }

    bool8 isAllFinish = CM_TRUE;
    bool8 singleFinish;
    for (uint32 i = 0; i < dnFloatIp->dnFloatIpCount; ++i) {
        if (IsLocalHostIp(dnFloatIp->dnFloatIp[i])) {
            continue;
        }

        if (oper == NETWORK_OPER_UP && dnStatus->floatIpInfo.info.nicNetState[i] != (int32)NETWORK_STATE_UP) {
            SetNicOper(dnFloatIp->instId, CM_INSTANCE_TYPE_DN, NETWORK_TYPE_FLOATIP, oper);
            isAllFinish = CM_FALSE;
            continue;
        }
        singleFinish = ExeVipCmdAndValidate(i, dnIpText, isRunning, dnIdx, oper);
        isAllFinish = (bool8)(singleFinish && isAllFinish);
        SetNicOper(dnFloatIp->instId, CM_INSTANCE_TYPE_DN, NETWORK_TYPE_FLOATIP, oper);
    }
    if (isAllFinish) {
        SetFloatIpOper(dnIdx, NETWORK_OPER_UNKNOWN, "[DoFloatIpOper]");
    }
}

static void CheckDownFloatIp(DnIpText *dnIpText, const DnStatus *dnStatus, uint32 dnIdx, bool8 isRunning)
{
    if (dnStatus->reportMsg.local_status.local_role == INSTANCE_ROLE_PRIMARY && isRunning) {
        return;
    }
    DnFloatIp *dnFloatIp = GetDnFloatIpByDnIdx(dnIdx);
    if (dnFloatIp == NULL) {
        return;
    }
    SetNicOper(dnFloatIp->instId, CM_INSTANCE_TYPE_DN, NETWORK_TYPE_FLOATIP, NETWORK_OPER_DOWN);
    const DnFloatIpInfo *dnInfo = &(dnStatus->floatIpInfo.info);
    for (uint32 i = 0; i < dnFloatIp->dnFloatIpCount; ++i) {
        if (dnInfo->dnNetState[i] != (int32)NETWORK_STATE_UP) {
            continue;
        }
        (void)ExeVipCmdAndValidate(i, dnIpText, isRunning, dnIdx, NETWORK_OPER_DOWN);
    }
}

static void ClearFloatIpConn(DnIpText *dnIpText, const DnStatus *dnStatus, bool8 isRunning, uint32 dnIdx)
{
    if (dnStatus->reportMsg.local_status.local_role == INSTANCE_ROLE_PRIMARY && isRunning) {
        ResetDnValidate(dnIpText);
        return;
    }
    DnFloatIp *dnFloatIp = GetDnFloatIpByDnIdx(dnIdx);
    status_t st = GetDnValidate(dnIpText, dnFloatIp->dnFloatIpCount);
    if (st != CM_SUCCESS) {
        write_runlog(ERROR, "[ClearFloatIpConn] failed to get dn validate.\n");
        return;
    }
    DnValidate *validate = dnIpText->validate;
    if (validate == NULL) {
        write_runlog(LOG, "[ClearFloatIpConn] validate is NULL, cannot ClearFloatIpConn.\n");
        return;
    }
    if (!isRunning) {
        return;
    }
    for (uint32 i = 0; i < validate->cnt && i < dnFloatIp->dnFloatIpCount; ++i) {
        if (!validate->isReentrant[i]) {
            continue;
        }
        validate->isReentrant[i] = (ClearDnIpConn(dnFloatIp->dnFloatIp[i], dnIdx) == 0) ? CM_FALSE : CM_TRUE;
    }
}

void ReportPingDnFloatIpFailToCms(uint32 instanceId, char failedDnFloatIp[MAX_FLOAT_IP_COUNT][CM_IP_LENGTH],
    uint32 failedCount)
{
    CmSendPingDnFloatIpFail reportMsg = {0};
    BaseInstInfo *baseInfo = &reportMsg.baseInfo;
    baseInfo->msgType = (int)MSG_CMA_PING_DN_FLOAT_IP_FAIL;
    baseInfo->node = g_currentNode->node;
    baseInfo->instId = instanceId;
    baseInfo->instType = INSTANCE_TYPE_DATANODE;
    reportMsg.failedCount = failedCount;

    if (failedCount > MAX_FLOAT_IP_COUNT) {
        write_runlog(ERROR, "[%s] failed float ip count %u more tahn max float ip count %u.\n",
            __FUNCTION__,
            failedCount,
            MAX_FLOAT_IP_COUNT);
        return;
    }
    errno_t rc;
    for (uint32 i = 0; i < failedCount; ++i) {
        rc = strcpy_s(reportMsg.failedDnFloatIp[i], CM_IP_LENGTH, failedDnFloatIp[i]);
        securec_check_errno(rc, (void)rc);
    }
    PushMsgToCmsSendQue((char *)&reportMsg, (uint32)sizeof(CmSendPingDnFloatIpFail), "ping dn float ip fail");
}

bool8 CanPingDnFloatIp()
{
    static uint64 last = 0;
    const long oneMinute = 60;
    if ((GetMonotonicTimeS() - last) > oneMinute) {
        last = GetMonotonicTimeS();
        write_runlog(LOG, "[%s] floatIp ping successful.\n", __FUNCTION__);
        return CM_TRUE;
    }
    write_runlog(ERROR, "[%s] floatIp ping failed.\n", __FUNCTION__);
    return CM_FALSE;
}

void PingDnFloatIp(const DnStatus *dnstatus, uint32 dnIdx, bool8 isRuning)
{
    if (dnstatus->reportMsg.local_status.local_role == INSTANCE_ROLE_PRIMARY || !isRuning) {
        return;
    }

    DnFloatIp *dnFloatIp = GetDnFloatIpByDnIdx(dnIdx);
    if (dnFloatIp == NULL) {
        return;
    }

    if (!CanPingDnFloatIp()) {
        return;
    }

    uint32 instanceId = g_currentNode->datanode[dnIdx].datanodeId;
    char failedDnFloatIp[MAX_FLOAT_IP_COUNT][CM_IP_LENGTH] = {0};
    uint32 failedCount = 0;
    errno_t rc;
    for (uint32 i = 0; i < dnFloatIp->dnFloatIpCount; i++) {
        if (IsLocalHostIp(dnFloatIp->dnFloatIp[i])) {
            continue;
        }
        if (GetIpVersion(dnFloatIp->dnFloatIp[i]) != AF_INET6) {
            continue;
        }

        if (CheckPeerIp(dnFloatIp->dnFloatIp[i], "[PingFloatIp]", NULL, 1, AF_INET6) != PROCESS_STATUS_SUCCESS) {
            rc = strcpy_s(failedDnFloatIp[failedCount], CM_IP_LENGTH, dnFloatIp->dnFloatIp[i]);
            securec_check_errno(rc, (void)rc);
            failedCount++;
        }
    }
    if (failedCount > 0) {
        ReportPingDnFloatIpFailToCms(instanceId, failedDnFloatIp, failedCount);
    }
}

void DnCheckFloatIp(DnStatus *dnStatus, uint32 dnIdx, bool8 isRunning)
{
    if (!IsNeedCheckFloatIp() || (agent_backup_open != CLUSTER_PRIMARY)) {
        return;
    }
    DnFloatIp *dnFloatIp = GetDnFloatIpByDnIdx(dnIdx);
    if (dnFloatIp == NULL || dnFloatIp->dnFloatIpCount == 0) {
        return;
    }
    DnIpText *dnIpText = GetDnIpText(dnIdx);
    if (dnIpText == NULL) {
        write_runlog(ERROR, "failed to get dn ip text.\n");
        return;
    }
    ResetDnText(dnIpText->dnText);
    GetDnAllFloatIp(dnIpText, dnStatus, dnIdx, isRunning);
    DoFloatIpOper(dnIpText, dnStatus, dnIdx, isRunning);
    CheckDownFloatIp(dnIpText, dnStatus, dnIdx, isRunning);
    ClearFloatIpConn(dnIpText, dnStatus, isRunning, dnIdx);
    PingDnFloatIp(dnStatus, dnIdx, isRunning);
    return;
}

uint32 DelFloatIpInDatanode(uint32 dnIdx)
{
    if (!IsNeedCheckFloatIp() || (agent_backup_open != CLUSTER_PRIMARY)) {
        return 0;
    }
    DnFloatIp *dnFloatIp = GetDnFloatIpByDnIdx(dnIdx);
    if (dnFloatIp == NULL || dnFloatIp->dnFloatIpCount == 0) {
        return 0;
    }
    DnIpText *dnIpText = GetCurDnIpText();
    ResetDnText(dnIpText->dnText);
    uint32 cnt = 0;
    DnFloatIpInfo floatIpInfo = {0};
    (void)GetDnNetStateFromFile(dnIpText, &floatIpInfo, dnIdx, INSTANCE_ROLE_UNKNOWN, CM_TRUE);
    SetNicOper(dnFloatIp->instId, CM_INSTANCE_TYPE_DN, NETWORK_TYPE_FLOATIP, NETWORK_OPER_DOWN);
    for (uint32 i = 0; i < dnFloatIp->dnFloatIpCount; ++i) {
        if (floatIpInfo.dnNetState[i] != (int32)NETWORK_STATE_UP) {
            continue;
        }
        if (!ExecuteFloatIpCmd(dnFloatIp->dnFloatIp[i], dnIpText, CM_FALSE, dnIdx, NETWORK_OPER_DOWN)) {
            ++cnt;
        }
    }
    write_runlog(LOG, "it will del floatIp In datanode, cnt=%u.\n", cnt);
    return cnt;
}
