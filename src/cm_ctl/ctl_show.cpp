/*
 * Copyright (c) 2021 Huawei Technologies Co.,Ltd.
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
 * ctl_show.cpp
 *    cm_ctl show
 *
 * IDENTIFICATION
 *    src/cm_ctl/ctl_show.cpp
 *
 * -------------------------------------------------------------------------
 */

#include "ctl_show.h"

#include <time.h>

#include "c.h"
#include "cm_text.h"
#include "cm/libpq-fe.h"
#include "cm_msg_common.h"

#include "cm_elog.h"
#include "cm_rhb.h"
#include "cm_voting_disk.h"
#include "cm_json_parse_floatIp.h"

#include "ctl_global_params.h"
#include "ctl_misc.h"
#include "ctl_common.h"
#include "ctl_process_message.h"
#include "ctl_query_base.h"
#include "cm_misc_res.h"

typedef struct CtlFloatIpInstT {
    uint32 dnIdx;
    DnFloatIp floatIp;
} CtlFloatIpInst;

typedef struct CtlFloatIpNodeT {
    uint32 nodeIdx;
    uint32 instCnt;
    CtlFloatIpInst floapIpInst[CM_MAX_DATANODE_PER_NODE];
} CtlFloatIpNode;

typedef struct CtlFloatIpMapT {
    uint32 nodeCnt;
    CtlFloatIpNode floatIpNode[0];
} CtlFloatIpMap;

typedef struct CtlFloatIpHeadSizeT {
    CmConstText nodeText;
    CmConstText instText;
    CmConstText floatIpNameText;
    CmConstText floatIpText;
    CmConstText baseIpText;
} CtlFloatIpHeadSize;

static ParseFloatIpFunc g_ctlParseFuc = {0};
static CtlFloatIpMap *g_floatIpMap = NULL;
static uint32 g_floatIpCnt = 0;

static void GetMaxFloatIpNameLen(CtlFloatIpHeadSize *floatIpLen)
{
    DnFloatIp *dnFloatIp;
    uint32 len;
    for (uint32 i = 0; i < g_floatIpMap->nodeCnt; ++i) {
        for (uint32 j = 0; j < g_floatIpMap->floatIpNode[i].instCnt; ++j) {
            for (uint32 k = 0; k < g_floatIpMap->floatIpNode[i].floapIpInst[j].floatIp.dnFloatIpCount; ++k) {
                dnFloatIp = &(g_floatIpMap->floatIpNode[i].floapIpInst[j].floatIp);
                // float_ip_name
                len = (uint32)strlen(dnFloatIp->floatIpName[k]);
                floatIpLen->floatIpNameText.len = CM_MAX(len, floatIpLen->floatIpNameText.len);

                // base_ip
                len = (uint32)strlen(dnFloatIp->baseIp[i]);
                floatIpLen->baseIpText.len = CM_MAX(len, floatIpLen->baseIpText.len);

                // float_ip
                len = (uint32)strlen(dnFloatIp->dnFloatIp[i]);
                floatIpLen->floatIpText.len = CM_MAX(len, floatIpLen->floatIpText.len);
            }
        }
    }
    floatIpLen->floatIpNameText.len += SPACE_LEN;
    floatIpLen->baseIpText.len += SPACE_LEN;
    floatIpLen->floatIpText.len += SPACE_LEN;
}

static void CalcFloatIpHeaderSize(CtlFloatIpHeadSize *floatIpLen)
{
    // node
    uint32 tmpNodeLen = (uint32)(MAX_NODE_ID_LEN + SPACE_LEN + max_node_name_len + SPACE_LEN);
    floatIpLen->nodeText.len = CM_MAX(tmpNodeLen, floatIpLen->nodeText.len);
    
    // instance
    uint32 tmpInstLen = (uint32)(INSTANCE_ID_LEN + SPACE_LEN + DEFAULT_PATH_LEN);
    floatIpLen->instText.len = CM_MAX(tmpInstLen, floatIpLen->instText.len);

    GetMaxFloatIpNameLen(floatIpLen);
}

static void PrintFloatIpHeaderLine(const CtlFloatIpHeadSize *floatIpLen)
{
    (void)fprintf(g_logFilePtr, "%-*s%-*s%-*s%-*s%-*s\n",
        floatIpLen->nodeText.len, floatIpLen->nodeText.str,
        floatIpLen->instText.len, floatIpLen->instText.str,
        floatIpLen->baseIpText.len, floatIpLen->baseIpText.str,
        floatIpLen->floatIpNameText.len, floatIpLen->floatIpNameText.str,
        floatIpLen->floatIpText.len, floatIpLen->floatIpText.str);
    uint32 totalLen = floatIpLen->nodeText.len + floatIpLen->instText.len + floatIpLen->baseIpText.len +
                      floatIpLen->floatIpNameText.len + floatIpLen->floatIpText.len;
    for (uint32 i = 0; i < totalLen; ++i) {
        (void)fprintf(g_logFilePtr, "-");
    }
    if (totalLen != 0) {
        (void)fprintf(g_logFilePtr, "\n");
    }
}

static bool8 CheckFloatIpInput(uint32 nodeIdx, uint32 instIdx, uint32 ipIdx)
{
    if (g_floatIpMap == NULL) {
        write_runlog(DEBUG1, "Failed to checkFloatIpInput, because g_floatIpMap is NULL.\n");
        return CM_FALSE;
    }
    if (nodeIdx >= g_floatIpMap->nodeCnt) {
        write_runlog(DEBUG1, "Failed to checkFloatIpInput, because nodeIdx is [%u: %u].\n",
            nodeIdx, g_floatIpMap->nodeCnt);
        return CM_FALSE;
    }
    if (instIdx >= g_floatIpMap->floatIpNode[nodeIdx].instCnt) {
        write_runlog(DEBUG1, "Failed to checkFloatIpInput, because instId is [%u: %u].\n",
            instIdx, g_floatIpMap->floatIpNode[nodeIdx].instCnt);
        return CM_FALSE;
    }
    if (ipIdx >= g_floatIpMap->floatIpNode[nodeIdx].floapIpInst[instIdx].floatIp.dnFloatIpCount) {
        return CM_FALSE;
    }
    return CM_TRUE;
}

static const char *GetBaseIp(uint32 nodeIdx, uint32 instIdx, uint32 ipIdx)
{
    if (!CheckFloatIpInput(nodeIdx, instIdx, ipIdx)) {
        return "Unknown";
    }
    return g_floatIpMap->floatIpNode[nodeIdx].floapIpInst[instIdx].floatIp.baseIp[ipIdx];
}

static const char *GetFloatIp(uint32 nodeIdx, uint32 instIdx, uint32 ipIdx)
{
    if (!CheckFloatIpInput(nodeIdx, instIdx, ipIdx)) {
        return "Unknown";
    }
    return g_floatIpMap->floatIpNode[nodeIdx].floapIpInst[instIdx].floatIp.dnFloatIp[ipIdx];
}

static const char *GetFloatIpName(uint32 nodeIdx, uint32 instIdx, uint32 ipIdx)
{
    if (!CheckFloatIpInput(nodeIdx, instIdx, ipIdx)) {
        return "Unknown";
    }
    return g_floatIpMap->floatIpNode[nodeIdx].floapIpInst[instIdx].floatIp.floatIpName[ipIdx];
}

static void PrintFloatIpContent(const CmFloatIpStatAck *ack, const CtlFloatIpHeadSize *floatIpLen)
{
    Instance inst;
    errno_t rc;
    for (uint32 i = 0; i < ack->count; ++i) {
        rc = memset_s(&inst, sizeof(Instance), 0, sizeof(Instance));
        securec_check_errno(rc, (void)rc);
        rc = FindInstanceByInstId(ack->info[i].instId, &inst);
        if (rc != 0) {
            continue;
        }
        for (uint32 j = 0; j < ack->info[i].count; ++j) {
            if (ack->info[i].nicNetState[j] != (int32)NETWORK_STATE_UP) {
                continue;
            }
            // node
            (void)fprintf(g_logFilePtr, "%-2u ", g_node[inst.baseInfo.nodeIdx].node);
            (void)fprintf(g_logFilePtr, "%-*s ", max_node_name_len, g_node[inst.baseInfo.nodeIdx].nodeName);
            
            // instance
            (void)fprintf(g_logFilePtr, "%u ", ack->info[i].instId);
            (void)fprintf(g_logFilePtr, "    ");

            // base_ip
            (void)fprintf(g_logFilePtr, "%-*s ", (floatIpLen->baseIpText.len - 1),
                GetBaseIp(inst.baseInfo.nodeIdx, inst.baseInfo.instIdx, j));

            // floatIpName
            (void)fprintf(g_logFilePtr, "%-*s ", (floatIpLen->floatIpNameText.len - 1),
                GetFloatIpName(inst.baseInfo.nodeIdx, inst.baseInfo.instIdx, j));

            // floatIp
            (void)fprintf(g_logFilePtr, "%-*s \n", (floatIpLen->floatIpText.len - 1),
                GetFloatIp(inst.baseInfo.nodeIdx, inst.baseInfo.instIdx, j));
        }
    }
}

static void InitCtlFloatIpHeadSize(CtlFloatIpHeadSize *floatIpLen)
{
    errno_t rc = memset_s(floatIpLen, sizeof(CtlFloatIpHeadSize), 0, sizeof(CtlFloatIpHeadSize));
    securec_check_errno(rc, (void)rc);

    // node
    CmConststr2Text("node", &(floatIpLen->nodeText));

    // instance
    CmConststr2Text("instance", &(floatIpLen->instText));

    // baseIp
    CmConststr2Text("base_ip", &(floatIpLen->baseIpText));

    // floatIpName
    CmConststr2Text("float_ip_name", &(floatIpLen->floatIpNameText));

    // floatIp
    CmConststr2Text("float_ip", &(floatIpLen->floatIpText));
}

status_t HandleFloatIpAck(const char *option, char *recvMsg)
{
    const CmFloatIpStatAck *ack = (const CmFloatIpStatAck *)recvMsg;
    if (!ack->canShow) {
        write_runlog(DEBUG1, "cur cluster can't show floatIp.\n");
        return CM_SUCCESS;
    }
    (void)fprintf(g_logFilePtr, "\n[  FloatIp Network State  ]\n\n");
    if (ack->count == 0) {
        return CM_ERROR;
    }
    CtlFloatIpHeadSize floatIpLen;
    InitCtlFloatIpHeadSize(&floatIpLen);
    CalcFloatIpHeaderSize(&floatIpLen);
    PrintFloatIpHeaderLine(&floatIpLen);
    PrintFloatIpContent(ack, &floatIpLen);
    return CM_SUCCESS;
}

static int32 InitFloatIpMap()
{
    size_t len = sizeof(CtlFloatIpMap) + sizeof(CtlFloatIpNode) * g_node_num;
    g_floatIpMap = (CtlFloatIpMap *)malloc(len);
    if (g_floatIpMap == NULL) {
        write_runlog(DEBUG1, "failed to malloc g_floatIpMap, and len=%zu.\n", len);
        return -1;
    }
    errno_t rc = memset_s(g_floatIpMap, len, 0, len);
    securec_check_errno(rc, (void)rc);
    g_floatIpMap->nodeCnt = g_node_num;
    for (uint32 i = 0; i < g_node_num; ++i) {
        g_floatIpMap->floatIpNode[i].nodeIdx = i;
        for (uint32 j = 0; j < g_node[i].datanodeCount && j < CM_MAX_DATANODE_PER_NODE; ++j) {
            g_floatIpMap->floatIpNode[i].floapIpInst[j].dnIdx = j;
        }
    }
    return 0;
}

static bool8 CtlFindNodeInfoByNodeIdx(uint32 instId, uint32 *nodeIdx, uint32 *dnIdx, const char *str)
{
    Instance instance;
    errno_t rc = memset_s(&instance, sizeof(Instance), 0, sizeof(Instance));
    securec_check_errno(rc, (void)rc);
    int32 ret = FindInstanceByInstId(instId, &instance);
    if (ret != 0) {
        write_runlog(DEBUG1, "[%s] cannot find the instance by instId(%u).\n", str, instId);
        return CM_FALSE;
    }
    *nodeIdx = instance.baseInfo.nodeIdx;
    *dnIdx = instance.baseInfo.instIdx;
    return CM_TRUE;
}

static DnFloatIp *CtlGetDnFloatIpByNodeInfo(uint32 nodeIdx, uint32 dnIdx)
{
    if (nodeIdx >= g_floatIpMap->nodeCnt || dnIdx >= CM_MAX_DATANODE_PER_NODE) {
        write_runlog(DEBUG1, "failed to get Dn floatIp, because nodeIdx(%u) beyond the nodeNum(%u), "
            "dnIdx(%u) beyond the dnNum(%d).\n", nodeIdx, g_floatIpMap->nodeCnt, dnIdx, CM_MAX_DATANODE_PER_NODE);
        return NULL;
    }
    return &(g_floatIpMap->floatIpNode[nodeIdx].floapIpInst[dnIdx].floatIp);
}

static void CtlIncreDnFloatIpCnt(uint32 nodeIdx)
{
    ++g_floatIpMap->floatIpNode[nodeIdx].instCnt;
    ++g_floatIpCnt;
}

static void CtlInitFloatIpFunc()
{
    g_ctlParseFuc.findNodeInfo = CtlFindNodeInfoByNodeIdx;
    g_ctlParseFuc.getFloatIp = CtlGetDnFloatIpByNodeInfo;
    g_ctlParseFuc.increaseCnt = CtlIncreDnFloatIpCnt;
    InitParseFloatIpFunc(&g_ctlParseFuc);
}

static int32 CtlParseFloatIp()
{
    CtlGetCmJsonConf();
    CM_RETURN_INT_IFERR(InitFloatIpMap());
    CtlInitFloatIpFunc();
    ParseVipConf(DEBUG1);
    return 0;
}

static void ReleaseFloatIp()
{
    FREE_AND_RESET(g_floatIpMap);
    g_floatIpCnt = 0;
}

static int32 SetQueryFloatIpMsg()
{
    CmShowStatReq req = { 0 };
    req.msgType = (int32)MSG_CTL_CM_FLOAT_IP_REQ;
    if (cm_client_send_msg(GetCmsConn(), 'C', (char*)(&req), sizeof(CmShowStatReq)) != 0) {
        FINISH_CONNECTION_WITHOUT_EXITCODE((CmServer_conn));
        write_runlog(ERROR, "ctl send show node disk msg to cms failed.\n");
        (void)printf(_("ctl send msg to cms failed.\n"));
        return 1;
    }
    return 0;
}

static int32 QueryCmsFloatIp()
{
    CM_RETURN_INT_IFERR(CtlParseFloatIp());
    if (g_floatIpCnt == 0) {
        return 0;
    }
    CM_RETURN_INT_IFERR(SetQueryFloatIpMsg());
    if (GetExecCmdResult(NULL, (int)MSG_CTL_CM_FLOAT_IP_ACK) != CM_SUCCESS) {
        return -1;
    }
    return 0;
}

static int32 QueryCmsFloatIpMain()
{
    int32 ret = QueryCmsFloatIp();
    ReleaseFloatIp();
    return ret;
}

// cm_ctl rhb print
int DoShowCommand()
{
    InitCtlShowMsgFunc();
    do_conn_cmserver(false, 0);
    if (CmServer_conn == NULL) {
        write_runlog(LOG, "show command, can't connect to cmserver.\n");
        return -1;
    }

    CmShowStatReq req = { 0 };
    req.msgType = (int)MSG_CTL_CM_RHB_STATUS_REQ;

    if (cm_client_send_msg(CmServer_conn, 'C', (char*)(&req), sizeof(CmShowStatReq)) != 0) {
        FINISH_CONNECTION_WITHOUT_EXITCODE((CmServer_conn));
        write_runlog(ERROR, "ctl send show rhb msg to cms failed.\n");
        (void)printf(_("ctl show send msg to cms failed.\n"));
        return 1;
    }

    GetExecCmdResult(NULL, (int)MSG_CTL_CM_RHB_STATUS_ACK);

    req.msgType = (int)MSG_CTL_CM_NODE_DISK_STATUS_REQ;
    if (cm_client_send_msg(CmServer_conn, 'C', (char*)(&req), sizeof(CmShowStatReq)) != 0) {
        FINISH_CONNECTION_WITHOUT_EXITCODE((CmServer_conn));
        write_runlog(ERROR, "ctl send show node disk msg to cms failed.\n");
        (void)printf(_("ctl send msg to cms failed.\n"));
        return 1;
    }

    GetExecCmdResult(NULL, (int)MSG_CTL_CM_NODE_DISK_STATUS_ACK);

    if (QueryCmsFloatIpMain() != 0) {
        FINISH_CONNECTION_WITHOUT_EXITCODE((CmServer_conn));
        write_runlog(ERROR, "Failed to show floatIp.\n");
        return -1;
    }
    FINISH_CONNECTION_WITHOUT_EXITCODE((CmServer_conn));
    return 0;
}

status_t HandleRhbAck(const char *option, char *recvMsg)
{
    CmRhbStatAck *ack = (CmRhbStatAck *)recvMsg;
    (void)printf("\n[  Network Connect State  ]\n\n");

    (void)printf("Network timeout:       %us\n", ack->timeout);

    struct tm result;
    GetLocalTime(&ack->baseTime, &result);
    const uint32 timeBufMaxLen = 128;
    char timeBuf[timeBufMaxLen] = {0};
    (void)strftime(timeBuf, timeBufMaxLen, "%Y-%m-%d %H:%M:%S", &result);
    (void)printf("Current CMServer time: %s\n", timeBuf);

    (void)printf("Network stat('Y' means connected, otherwise 'N'):\n");
    char *rs = GetRhbSimple((time_t *)ack->hbs, MAX_RHB_NUM, ack->hwl, ack->baseTime, ack->timeout);
    CM_RETERR_IF_NULL(rs);
    (void)printf("%s\n", rs);
    FREE_AND_RESET(rs);
    return CM_SUCCESS;
}

// |  Y  |  Y  |  Y  |  Y  |  Y  |
static char *GetNodeDiskSimple(time_t *ndHbs, uint32 hwl, time_t baseTime, uint32 timeout)
{
    const uint32 fixLen = 6;
    size_t bufLen = (fixLen + 1) * hwl + 2;
    char *buf = (char *)malloc(bufLen);
    if (buf == NULL) {
        write_runlog(ERROR, "can't alloc mem for node disk stats, needed:%u\n", (uint32)bufLen);
        return NULL;
    }
    error_t rc = memset_s(buf, bufLen, 0, bufLen);
    securec_check_errno(rc, (void)rc);

    buf[strlen(buf)] = '|';
    for (uint32 j = 0; j < hwl; j++) {
        const char *stat = IsRhbTimeout(ndHbs[j], baseTime, (int32)timeout) ? "  N  |" : "  Y  |";
        rc = strncat_s(buf, bufLen, stat, strlen(stat));
        securec_check_errno(rc, (void)rc);
    }
    PrintRhb(ndHbs, hwl, "NodeDisk");

    return buf;
}

status_t HandleNodeDiskAck(const char *option, char *recvMsg)
{
    CmNodeDiskStatAck *ack = (CmNodeDiskStatAck *)recvMsg;
    (void)printf("\n[  Node Disk HB State  ]\n\n");

    (void)printf("Node disk hb timeout:    %us\n", ack->timeout);

    struct tm result;
    GetLocalTime(&ack->baseTime, &result);
    const uint32 timeBufMaxLen = 128;
    char timeBuf[timeBufMaxLen] = {0};
    (void)strftime(timeBuf, timeBufMaxLen, "%Y-%m-%d %H:%M:%S", &result);
    (void)printf("Current CMServer time: %s\n", timeBuf);

    (void)printf("Node disk hb stat('Y' means connected, otherwise 'N'):\n");
    char *rs = GetNodeDiskSimple(ack->nodeDiskStats, ack->hwl, ack->baseTime, ack->timeout);
    CM_RETERR_IF_NULL(rs);
    (void)printf("%s\n", rs);
    FREE_AND_RESET(rs);
    return CM_SUCCESS;
}
