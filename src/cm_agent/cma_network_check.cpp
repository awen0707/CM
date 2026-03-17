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
 * cma_network_check.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_agent/cma_network_check.cpp
 *
 * -------------------------------------------------------------------------
 */

#include <limits.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <linux/if.h>

#include "cm_util.h"
#include "cm_text.h"
#include "cm_json_config.h"
#include "cm_json_parse_floatIp.h"
#include "cm_ip.h"

#include "cma_global_params.h"
#include "cma_common.h"
#include "cma_network_check.h"

const uint32 INVALID_PORT = 0xFFFFFFFF;

typedef enum NetworkQuestE {
    NETWORK_QUEST_UNKNOWN = 0,
    NETWORK_QUEST_CHECK,
    NETWORK_QUEST_GET,
    NETWORK_QUEST_CEIL
} NetworkQuest;

typedef struct NetWorkAddrT {
    int32 family;
    const char *ip;
    char netName[NI_MAXHOST];
    char netMask[NI_MAXHOST];
} NetWorkAddr;

typedef struct ArpingCmdResT {
    char cmd[CM_MAX_COMMAND_LONG_LEN];
} ArpingCmdRes;

typedef struct NetworkInfoT {
    bool networkRes;
    NetworkType type;
    NetworkOper oper;
    NetworkOper lasterOper;
    uint32 port;
    uint32 cnt;
    uint32 checkCnt;
    const char (*ips)[CM_IP_LENGTH];
    NetWorkAddr *netAddr;
    NetworkState *stateCheck;
    NetworkState *stateRecord;
    ArpingCmdRes *arpingCmd; // notify switch command
} NetworkInfo;

typedef struct CmNetworkInfoT {
    uint32 instId;
    NetworkInfo manaIp[NETWORK_TYPE_CEIL];
} CmNetworkInfo;

typedef struct CmNetworkByTypeT {
    uint32 count;
    CmNetworkInfo *cmNetwork;
} CmNetworkByType;

typedef struct NetworkStateOperMapT {
    NetworkState state;
    NetworkOper oper;
} NetworkStateOperMap;

typedef struct NetworkOperStringMapT {
    NetworkOper oper;
    const char *str;
} NetworkOperStringMap;

typedef struct NetworkStateStringMapT {
    NetworkState state;
    const char *str;
} NetworkStateStringMap;

#ifdef ENABLE_UT
#define static
#endif

static bool GetNicstatusByAddrs(const struct ifaddrs *ifList, NetworkInfo *netInfo, int32 logLevel = WARNING,
    NetworkQuest quest = NETWORK_QUEST_CHECK);
static void GetNicDownCmd(char *cmd, uint32 cmdLen, const NetworkInfo *netInfo, uint32 index);
static void GetNicUpCmd(char *cmd, uint32 cmdLen, const NetworkInfo *netInfo, uint32 index, uint32 instId);
bool CheckNeedResetFloatIpExist(const char *ip, const DnFloatIp *dnFloatIp);

static CmNetworkInfo *g_cmNetWorkInfo = NULL;
static uint32 g_instCnt = 0;
static CmNetworkByType g_cmNetworkByType[CM_INSTANCE_TYPE_CEIL] = {{0}};
static ParseFloatIpFunc g_cmaParseFuc = {0};

static NetworkStateOperMap g_stateOperMap[] = {{NETWORK_STATE_UNKNOWN, NETWORK_OPER_UNKNOWN},
    {NETWORK_STATE_UP, NETWORK_OPER_UP},
    {NETWORK_STATE_DOWN, NETWORK_OPER_DOWN},
    {NETWORK_STATE_CEIL, NETWORK_OPER_CEIL}};

static const char *g_ifconfigCmd = "ifconfig";
static const char *g_ipCmd = "ip";
static const char *const IFCONFIG_CMD_DEFAULT = "ifconfig";
static const char *const IFCONFIG_CMD_SUSE = "/sbin/ifconfig";
static const char *const IFCONFIG_CMD_EULER = "/usr/sbin/ifconfig";
static const char *const ARPING_CMD = "arping -w 1 -A -I";
static const char *const NDISC6_CMD = "ndisc6";
static const char *const SHOW_IPV6_CMD = "ip addr show | grep";
static const char *const IPV6_TENTATIVE_FLAG = "tentative";
static const char *const IPV6_DADFAILED_FLAG = "dadfailed";
static const char *const TIMEOUT_MECHA = "timeout -s SIGKILL";
static const uint32 DEFAULT_CMD_TIMEOUT = 2;

static const char *g_ipaddrCmd = "ip addr";
static const char *const IP_CMD_DEFAULT = "ip";
static const char *const IP_CMD_SUSE = "/sbin/ip";
static const char *const IP_CMD_EULER = "/usr/sbin/ip";

static const char *g_sudoPermCmd = "";
static const char *const SUDO_PERM_CMD = "sudo";

static DnFloatIpMapOper g_floatIpMap = {0};
static NetworkOperStringMap g_operStringMap[NETWORK_OPER_CEIL] = {
    {NETWORK_OPER_UNKNOWN, "NETWORK_OPER_UNKNOWN"},
    {NETWORK_OPER_UP, "NETWORK_OPER_UP"},
    {NETWORK_OPER_DOWN, "NETWORK_OPER_DOWN"},
};

static NetworkStateStringMap g_stateStringMap[NETWORK_STATE_CEIL] = {
    {NETWORK_STATE_UNKNOWN, "NETWORK_STATE_UNKNOWN"},
    {NETWORK_STATE_UP, "NETWORK_STATE_UP"},
    {NETWORK_STATE_DOWN, "NETWORK_STATE_DOWN"},
};

const char *GetStateMapString(NetworkState state)
{
    for (uint32 i = 0; i < (uint32)NETWORK_STATE_CEIL; ++i) {
        if (g_stateStringMap[i].state == state) {
            return g_stateStringMap[i].str;
        }
    }
    return "unkown_state";
}

const char *GetOperMapString(NetworkOper oper)
{
    for (uint32 i = 0; i < (uint32)NETWORK_OPER_CEIL; ++i) {
        if (g_operStringMap[i].oper == oper) {
            return g_operStringMap[i].str;
        }
    }
    return "unknown_oper";
}

void SetFloatIpOper(uint32 dnIdx, NetworkOper oper, const char *str)
{
    if (!IsNeedCheckFloatIp() || (agent_backup_open != CLUSTER_PRIMARY)) {
        write_runlog(DEBUG1, "%s agent_backup_open=%d, cannot set floatIp oper.\n", str, (int32)agent_backup_open);
        return;
    }
    if (dnIdx >= CM_MAX_DATANODE_PER_NODE) {
        return;
    }
    g_floatIpMap.oper[dnIdx] = oper;
    write_runlog(LOG, "%s set floatIp oper=%d.\n", str, (int32)oper);
}

NetworkOper GetFloatIpOper(uint32 dnIdx)
{
    if (dnIdx >= CM_MAX_DATANODE_PER_NODE) {
        return NETWORK_OPER_UNKNOWN;
    }
    return g_floatIpMap.oper[dnIdx];
}

DnFloatIp *GetDnFloatIpByDnIdx(uint32 dnIdx)
{
    if (dnIdx >= CM_MAX_DATANODE_PER_NODE) {
        return NULL;
    }
    return &(g_floatIpMap.floatIp[dnIdx]);
}

static bool8 CmaFindNodeInfoByNodeIdx(uint32 instId, uint32 *nodeIdx, uint32 *dnIdx, const char *str)
{
    return (bool8)FindDnIdxInCurNode(instId, dnIdx, str);
}

static DnFloatIp *CmaGetDnFloatIpByNodeInfo(uint32 nodeIdx, uint32 dnIdx)
{
    return GetDnFloatIpByDnIdx(dnIdx);
}

static void IncreaseDnFloatIpCnt(uint32 nodeIdx)
{
    ++g_floatIpMap.count;
}

static void CmaInitParseFloatIpCnt()
{
    g_cmaParseFuc.findNodeInfo = CmaFindNodeInfoByNodeIdx;
    g_cmaParseFuc.getFloatIp = CmaGetDnFloatIpByNodeInfo;
    g_cmaParseFuc.increaseCnt = IncreaseDnFloatIpCnt;
    InitParseFloatIpFunc(&g_cmaParseFuc);
}

static inline void InitFloatIpMap()
{
    errno_t rc = memset_s(&(g_floatIpMap), sizeof(DnFloatIpMapOper), 0, sizeof(DnFloatIpMapOper));
    securec_check_errno(rc, (void)rc);
    CmaInitParseFloatIpCnt();
    ParseVipConf(LOG);
    write_runlog(LOG, "success to get g_floatIpMap, and this count is %u.\n", g_floatIpMap.count);
}

NetworkOper ChangeInt2NetworkOper(int32 oper)
{
    if (oper < 0 || oper >= (int32)NETWORK_OPER_CEIL) {
        return NETWORK_OPER_UNKNOWN;
    }
    return (NetworkOper)oper;
}

NetworkState GetNetworkStateByOper(NetworkOper oper)
{
    size_t len = sizeof(g_stateOperMap) / sizeof(g_stateOperMap[0]);
    for (size_t i = 0; i < len; ++i) {
        if (g_stateOperMap[i].oper == oper) {
            return g_stateOperMap[i].state;
        }
    }
    return NETWORK_STATE_UNKNOWN;
}

NetworkOper GetNetworkOperByState(NetworkState state)
{
    size_t len = sizeof(g_stateOperMap) / sizeof(g_stateOperMap[0]);
    for (size_t i = 0; i < len; ++i) {
        if (g_stateOperMap[i].state == state) {
            return g_stateOperMap[i].oper;
        }
    }
    return NETWORK_OPER_UNKNOWN;
}

static NetworkInfo *GetNetworkInfo(uint32 instId, CmaInstType instType, NetworkType type)
{
    if (instType >= CM_INSTANCE_TYPE_CEIL || type >= NETWORK_TYPE_CEIL) {
        write_runlog(ERROR, "error instType(%d: %d) or networkType(%d: %d).",
            (int32)instType, (int32)CM_INSTANCE_TYPE_CEIL, (int32)type, (int32)NETWORK_TYPE_CEIL);
        return NULL;
    }
    CmNetworkByType *cmNetworkByType = &(g_cmNetworkByType[instType]);
    if (cmNetworkByType->cmNetwork == NULL) {
        write_runlog(ERROR, "cmNetwork is NULL, type is [%d:%d].\n", (int32)instType, (int32)type);
        return NULL;
    }
    for (uint32 i = 0; i < cmNetworkByType->count; ++i) {
        if (cmNetworkByType->cmNetwork[i].instId == instId) {
            return &(cmNetworkByType->cmNetwork[i].manaIp[type]);
        }
    }
    write_runlog(ERROR, "cmNetInfo is NULL, type is [%d:%d].\n", (int32)instType, (int32)type);
    return NULL;
}

bool GetNicStatus(uint32 instId, CmaInstType instType, NetworkType type)
{
    NetworkInfo *netInfo = GetNetworkInfo(instId, instType, type);
    if (netInfo == NULL) {
        write_runlog(ERROR, "[GetNicStatus] cannot find the NetInfo, instId(%u), instType(%d), networkType(%d).\n",
            instId, (int32)instType, (int32)type);
        return false;
    }
    return netInfo->networkRes;
}

void GetFloatIpNicStatus(uint32 instId, CmaInstType instType, NetworkState *state, uint32 count)
{
    for (uint32 i = 0; i < count; ++i) {
        state[i] = NETWORK_STATE_UNKNOWN;
    }
    NetworkInfo *netInfo = GetNetworkInfo(instId, instType, NETWORK_TYPE_FLOATIP);
    if (netInfo == NULL) {
        write_runlog(ERROR, "[GetNicStatus] cannot find the NetInfo, instId(%u), instType(%d), networkType(%d).\n",
            instId, (int32)instType, (int32)NETWORK_TYPE_FLOATIP);
        return;
    }
    for (uint32 i = 0; i < count; ++i) {
        if (i >= netInfo->cnt) {
            return;
        }
        state[i] = netInfo->stateRecord[i];
    }
}

void SetNicOper(uint32 instId, CmaInstType instType, NetworkType type, NetworkOper oper)
{
    NetworkInfo *netInfo = GetNetworkInfo(instId, instType, type);
    if (netInfo == NULL) {
        write_runlog(ERROR, "[SetNicOper] cannot find the NetInfo, instId(%u), instType(%d), networkType(%d).\n",
            instId, (int32)instType, (int32)type);
        return;
    }
    netInfo->oper = oper;
    return;
}

static void SetCmNetworkByTypeCnt(CmaInstType type, uint32 *count, uint32 instcnt)
{
    if (type >= CM_INSTANCE_TYPE_CEIL) {
        return;
    }
    g_cmNetworkByType[type].count = instcnt;
    (*count) += instcnt;
}

static uint32 GetCurrentNodeInstNum()
{
    uint32 count = 0;
    // cm_agent
    SetCmNetworkByTypeCnt(CM_INSTANCE_TYPE_CMA, &count, 1);

    // cm_server
    if (g_currentNode->cmServerLevel == 1) {
        SetCmNetworkByTypeCnt(CM_INSTANCE_TYPE_CMS, &count, 1);
    }

    // CN
    if (g_currentNode->coordinate == 1) {
        SetCmNetworkByTypeCnt(CM_INSTANCE_TYPE_CN, &count, 1);
    }

    // gtm
    if (g_currentNode->gtm == 1) {
        SetCmNetworkByTypeCnt(CM_INSTANCE_TYPE_GTM, &count, 1);
    }

    // DN
    SetCmNetworkByTypeCnt(CM_INSTANCE_TYPE_DN, &count, g_currentNode->datanodeCount);
    return count;
}

static void SetNetWorkAddr(NetWorkAddr *netAddr, uint32 cnt, const char (*ips)[CM_IP_LENGTH])
{
    if (cnt == 0 || ips == NULL || netAddr == NULL) {
        return;
    }
    for (uint32 i = 0; i < cnt; ++i) {
        netAddr[i].ip = ips[i];
    }
}

static bool8 IsCurIpInIpPool(const char **ipPool, uint32 cnt, const char *ip)
{
    if (cnt == 0 || ip == NULL) {
        return CM_FALSE;
    }
    for (uint32 i = 0; i < cnt; ++i) {
        if (ipPool[i] == NULL) {
            continue;
        }
        if (IsEqualIp(ipPool[i], ip)) {
            return CM_TRUE;
        }
    }
    return CM_FALSE;
}
 
static uint32 GetIpCheckCnt(const char (*ips)[CM_IP_LENGTH], uint32 cnt)
{
    const char *ipPool[MAX_FLOAT_IP_COUNT] = {0};
    uint32 checkCnt = 0;
    for (uint32 i = 0; i < cnt; ++i) {
        if (i >= MAX_FLOAT_IP_COUNT) {
            break;
        }
        if (IsCurIpInIpPool(ipPool, checkCnt, ips[i])) {
            continue;
        }
        if (checkCnt < MAX_FLOAT_IP_COUNT) {
            ipPool[checkCnt] = ips[i];
            ++checkCnt;
        }
    }
    return checkCnt;
}

static status_t SetNetWorkInfo(
    NetworkInfo *info, uint32 cnt, const char (*ips)[CM_IP_LENGTH], NetworkType type, uint32 port)
{
    info->networkRes = false;
    info->type = type;
    info->ips = ips;
    uint32 curCnt = cnt;
    if (cnt >= MAX_FLOAT_IP_COUNT) {
        curCnt = MAX_FLOAT_IP_COUNT;
        write_runlog(LOG, "cnt(%u) is more than MAX_FLOAT_IP_COUNT(%u), will set it to MAX_FLOAT_IP_COUNT.\n",
            cnt, MAX_FLOAT_IP_COUNT);
    }
    info->cnt = curCnt;
    info->checkCnt = GetIpCheckCnt(ips, cnt);
    info->oper = NETWORK_OPER_UNKNOWN;
    info->port = port;
    if (cnt == 0) {
        info->netAddr = NULL;
    } else {
        if (type == NETWORK_TYPE_LISTEN || type == NETWORK_TYPE_HA) {
            return CM_SUCCESS;
        }
        size_t allSize =
            (sizeof(NetWorkAddr) + sizeof(NetworkState) + sizeof(NetworkState) + sizeof(ArpingCmdRes)) * curCnt;
        char *dynamicStr = (char *)malloc(allSize);
        if (dynamicStr == NULL) {
            write_runlog(ERROR, "failed to malloc memory(%lu).\n", allSize);
            return CM_ERROR;
        }
        errno_t rc = memset_s(dynamicStr, allSize, 0, allSize);
        securec_check_errno(rc, (void)rc);
        size_t curSize = 0;
        info->netAddr = (NetWorkAddr *)GetDynamicMem(dynamicStr, &curSize, sizeof(NetWorkAddr) * curCnt);
        info->stateCheck = (NetworkState *)GetDynamicMem(dynamicStr, &curSize, sizeof(NetworkState) * curCnt);
        info->stateRecord = (NetworkState *)GetDynamicMem(dynamicStr, &curSize, sizeof(NetworkState) * curCnt);
        info->arpingCmd = (ArpingCmdRes *)GetDynamicMem(dynamicStr, &curSize, sizeof(ArpingCmdRes) * curCnt);
        if (curSize != allSize) {
            FREE_AND_RESET(dynamicStr);
            info->netAddr = NULL;
            info->stateCheck = NULL;
            info->stateRecord = NULL;
            info->arpingCmd = NULL;
            write_runlog(ERROR, "falled to alloc memory, curSize is %lu, allSize is %lu.\n", curSize, allSize);
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

static status_t SetCmNetWorkInfoDn(CmaInstType type, uint32 *index, const dataNodeInfo *datanodeInfo, uint32 dnIdx)
{
    const dataNodeInfo *dnInfo = &(datanodeInfo[dnIdx]);
    CmNetworkInfo *cmNetWorkInfo = &(g_cmNetWorkInfo[(*index)]);
    cmNetWorkInfo->instId = dnInfo->datanodeId;
    DnFloatIp *dnFloatIp = GetDnFloatIpByDnIdx(dnIdx);
    CM_RETURN_IFERR(SetNetWorkInfo(&(cmNetWorkInfo->manaIp[NETWORK_TYPE_LISTEN]), dnInfo->datanodeListenCount,
        dnInfo->datanodeListenIP, NETWORK_TYPE_LISTEN, dnInfo->datanodePort));
    CM_RETURN_IFERR(SetNetWorkInfo(&(cmNetWorkInfo->manaIp[NETWORK_TYPE_HA]), dnInfo->datanodeLocalHAListenCount,
        dnInfo->datanodeLocalHAIP, NETWORK_TYPE_HA, dnInfo->datanodeLocalHAPort));
    if (dnFloatIp != NULL) {
        NetworkInfo *netInfo = &(cmNetWorkInfo->manaIp[NETWORK_TYPE_FLOATIP]);
        CM_RETURN_IFERR(SetNetWorkInfo(netInfo, dnFloatIp->dnFloatIpCount,
            dnFloatIp->dnFloatIp, NETWORK_TYPE_FLOATIP, dnFloatIp->dnFloatIpPort));
        SetNetWorkAddr(netInfo->netAddr, netInfo->cnt, dnFloatIp->baseIp);
    }
    ++(*index);
    if (type >= CM_INSTANCE_TYPE_CEIL) {
        return CM_SUCCESS;
    }
    g_cmNetworkByType[type].cmNetwork = cmNetWorkInfo;
    return CM_SUCCESS;
}

static status_t SetCmNetWorkInfoCms(uint32 *index)
{
    CmNetworkInfo *cmNetWorkInfo = &(g_cmNetWorkInfo[(*index)]);
    cmNetWorkInfo->instId = g_currentNode->cmServerId;
    CM_RETURN_IFERR(SetNetWorkInfo(&(cmNetWorkInfo->manaIp[NETWORK_TYPE_LISTEN]), g_currentNode->cmServerListenCount,
        g_currentNode->cmServer, NETWORK_TYPE_LISTEN, g_currentNode->port));
    CM_RETURN_IFERR(SetNetWorkInfo(&(cmNetWorkInfo->manaIp[NETWORK_TYPE_HA]), g_currentNode->cmServerLocalHAListenCount,
        g_currentNode->cmServerLocalHAIP, NETWORK_TYPE_HA, g_currentNode->cmServerLocalHAPort));
    CM_RETURN_IFERR(SetNetWorkInfo(&(cmNetWorkInfo->manaIp[NETWORK_TYPE_FLOATIP]), 0,
        NULL, NETWORK_TYPE_FLOATIP, INVALID_PORT));
    ++(*index);
    g_cmNetworkByType[CM_INSTANCE_TYPE_CMS].cmNetwork = cmNetWorkInfo;
    return CM_SUCCESS;
}

static status_t SetCmNetWorkInfoCma(uint32 *index)
{
    CmNetworkInfo *cmNetWorkInfo = &(g_cmNetWorkInfo[(*index)]);
    cmNetWorkInfo->instId = g_currentNode->cmAgentId;
    CM_RETURN_IFERR(SetNetWorkInfo(&(cmNetWorkInfo->manaIp[NETWORK_TYPE_LISTEN]), g_currentNode->cmAgentListenCount,
        g_currentNode->cmAgentIP, NETWORK_TYPE_LISTEN,
        INVALID_PORT));
    CM_RETURN_IFERR(SetNetWorkInfo(&(cmNetWorkInfo->manaIp[NETWORK_TYPE_HA]), 0,
        NULL, NETWORK_TYPE_HA, INVALID_PORT));
    CM_RETURN_IFERR(SetNetWorkInfo(&(cmNetWorkInfo->manaIp[NETWORK_TYPE_FLOATIP]), 0,
        NULL, NETWORK_TYPE_FLOATIP, INVALID_PORT));
    ++(*index);
    g_cmNetworkByType[CM_INSTANCE_TYPE_CMA].cmNetwork = cmNetWorkInfo;
    return CM_SUCCESS;
}

static status_t SetCmNetWorkInfoCN(uint32 *index)
{
    CmNetworkInfo *cmNetWorkInfo = &(g_cmNetWorkInfo[(*index)]);
    cmNetWorkInfo->instId = g_currentNode->coordinateId;
    CM_RETURN_IFERR(SetNetWorkInfo(&(cmNetWorkInfo->manaIp[NETWORK_TYPE_LISTEN]), g_currentNode->coordinateListenCount,
        g_currentNode->coordinateListenIP, NETWORK_TYPE_LISTEN, g_currentNode->coordinatePort));
    CM_RETURN_IFERR(SetNetWorkInfo(&(cmNetWorkInfo->manaIp[NETWORK_TYPE_HA]), g_currentNode->coordinateListenCount,
        g_currentNode->coordinateListenIP, NETWORK_TYPE_HA, g_currentNode->coordinateHAPort));
    CM_RETURN_IFERR(SetNetWorkInfo(&(cmNetWorkInfo->manaIp[NETWORK_TYPE_FLOATIP]), 0,
        NULL, NETWORK_TYPE_FLOATIP, INVALID_PORT));
    ++(*index);
    g_cmNetworkByType[CM_INSTANCE_TYPE_CN].cmNetwork = cmNetWorkInfo;
    return CM_SUCCESS;
}

static status_t SetCmNetWorkInfoGTM(uint32 *index)
{
    CmNetworkInfo *cmNetWorkInfo = &(g_cmNetWorkInfo[(*index)]);
    cmNetWorkInfo->instId = g_currentNode->gtmId;
    CM_RETURN_IFERR(SetNetWorkInfo(&(cmNetWorkInfo->manaIp[NETWORK_TYPE_LISTEN]), g_currentNode->gtmLocalListenCount,
        g_currentNode->gtmLocalListenIP, NETWORK_TYPE_LISTEN, g_currentNode->gtmLocalport));
    CM_RETURN_IFERR(SetNetWorkInfo(&(cmNetWorkInfo->manaIp[NETWORK_TYPE_HA]), g_currentNode->gtmLocalHAListenCount,
        g_currentNode->gtmLocalHAIP, NETWORK_TYPE_HA, g_currentNode->gtmLocalHAPort));
    CM_RETURN_IFERR(SetNetWorkInfo(&(cmNetWorkInfo->manaIp[NETWORK_TYPE_FLOATIP]), 0,
        NULL, NETWORK_TYPE_FLOATIP, INVALID_PORT));
    ++(*index);
    g_cmNetworkByType[CM_INSTANCE_TYPE_GTM].cmNetwork = cmNetWorkInfo;
    return CM_SUCCESS;
}

static status_t SetCmNetworkInfo()
{
    uint32 index = 0;
    // agent
    CM_RETURN_IFERR(SetCmNetWorkInfoCma(&index));

    // cm_server
    if (g_currentNode->cmServerLevel == 1) {
        CM_RETURN_IFERR(SetCmNetWorkInfoCms(&index));
    }

    // CN
    if (g_currentNode->coordinate == 1) {
        CM_RETURN_IFERR(SetCmNetWorkInfoCN(&index));
    }

    // GTM
    if (g_currentNode->gtm == 1) {
        CM_RETURN_IFERR(SetCmNetWorkInfoGTM(&index));
    }

    // DN
    for (uint32 i = 0; i < g_currentNode->datanodeCount; ++i) {
        CmaInstType type = (i == 0) ? CM_INSTANCE_TYPE_DN : CM_INSTANCE_TYPE_CEIL;
        CM_RETURN_IFERR(SetCmNetWorkInfoDn(type, &index, g_currentNode->datanode, i));
    }

    // check index
    if (index != g_instCnt) {
        write_runlog(ERROR, "index(%u) is different from instCnt(%u).\n", index, g_instCnt);
        FREE_AND_RESET(g_cmNetWorkInfo);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static void InitIfconfigCmd()
{
    if (CmFileExist(IFCONFIG_CMD_EULER)) {
        g_ifconfigCmd = IFCONFIG_CMD_EULER;
    } else if (CmFileExist(IFCONFIG_CMD_SUSE)) {
        g_ifconfigCmd = IFCONFIG_CMD_SUSE;
    } else {
        g_ifconfigCmd = IFCONFIG_CMD_DEFAULT;
    }
}

static void InitIpCmd()
{
    if (CmFileExist(IP_CMD_EULER)) {
        g_ipaddrCmd = IP_CMD_EULER;
    } else if (CmFileExist(IP_CMD_SUSE)) {
        g_ipaddrCmd = IP_CMD_SUSE;
    } else {
        g_ipaddrCmd = IP_CMD_DEFAULT;
    }
}

static void InitSudoPermCmd()
{
    g_sudoPermCmd = "";
    if (g_clusterType != V3SingleInstCluster) {
        g_sudoPermCmd = SUDO_PERM_CMD;
    }
}

static status_t InitCmNetWorkInfo()
{
    InitFloatIpMap();
    InitIfconfigCmd();
    InitIpCmd();
    InitSudoPermCmd();
    g_instCnt = GetCurrentNodeInstNum();
    write_runlog(LOG, "current node has %u instance.\n", g_instCnt);
    size_t mallocLen = sizeof(CmNetworkInfo) * g_instCnt;
    g_cmNetWorkInfo = (CmNetworkInfo *)malloc(mallocLen);
    if (g_cmNetWorkInfo == NULL) {
        write_runlog(ERROR, "[InitCmNetWorkInfo] failed to malloc %lu memory.\n", mallocLen);
        return CM_ERROR;
    }
    errno_t rc = memset_s(g_cmNetWorkInfo, mallocLen, 0, mallocLen);
    securec_check_errno(rc, (void)rc);
    return SetCmNetworkInfo();
}

static void SetNetworkStatus(NetworkInfo *netWorkInfo, bool networkRes)
{
    if (!networkRes) {
        netWorkInfo->networkRes = false;
    }
}

static void CheckNetworkValidCnt(bool networkRes)
{
    if (networkRes) {
        return;
    }
    for (uint32 i = 0; i < g_instCnt; ++i) {
        for (uint32 j = 0; j < (uint32)NETWORK_TYPE_CEIL; ++j) {
            SetNetworkStatus(&(g_cmNetWorkInfo[i].manaIp[j]), networkRes);
            if (j != (uint32)NETWORK_TYPE_FLOATIP) {
                continue;
            }
            NetworkInfo *networkInfo = &(g_cmNetWorkInfo[i].manaIp[j]);
            for (uint32 k = 0; k < networkInfo->cnt; ++k) {
                networkInfo->stateRecord[k] = NETWORK_STATE_DOWN;
            }
        }
    }
}

static void ResetNetMask(NetWorkAddr *netAddr)
{
    errno_t rc = memset_s(netAddr->netMask, NI_MAXHOST, 0, NI_MAXHOST);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(netAddr->netName, NI_MAXHOST, 0, NI_MAXHOST);
    securec_check_errno(rc, (void)rc);
}

static void ResetAllNetMask(NetworkInfo *netInfo)
{
    for (uint32 i = 0; i < netInfo->cnt; ++i) {
        ResetNetMask(&(netInfo->netAddr[i]));
    }
}

static void GetNetworkAddrNetMask(NetWorkAddr *netAddr, const struct ifaddrs *ifa, const char *ip)
{
    if (netAddr == NULL) {
        return;
    }
    // family
    int32 family = ifa->ifa_addr->sa_family;
    netAddr->family = ifa->ifa_addr->sa_family;
    // netname
    errno_t rc = strcpy_s(netAddr->netName, NI_MAXHOST, ifa->ifa_name);
    securec_check_errno(rc, (void)rc);

    // netMask
    size_t saLen = (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
    if (getnameinfo(ifa->ifa_netmask, saLen, netAddr->netMask, NI_MAXHOST, NULL, 0, NI_NUMERICHOST) != 0) {
        write_runlog(WARNING, "failed to get netMask info, ip is %s.\n", ip);
        ResetNetMask(netAddr);
    }
    write_runlog(LOG, "ip is %s, family is %d, netName is %s, netmask is %s.\n",
        ip, family, netAddr->netName, netAddr->netMask);
}

static bool GetNetworkIp(
    NetworkInfo *netInfo, const char *host, uint32 *index, NetworkQuest quest, const struct ifaddrs *ifa)
{
    if (quest == NETWORK_QUEST_CHECK) {
        for (uint32 i = 0; i < netInfo->cnt; ++i) {
            if (strncmp(netInfo->ips[i], host, NI_MAXHOST) == 0) {
                *index = i;
                return true;
            }
        }
    } else if (quest == NETWORK_QUEST_GET) {
        uint32 i;
        for (i = 0; i < netInfo->cnt; ++i) {
            if (strncmp(netInfo->netAddr[i].ip, host, NI_MAXHOST) == 0) {
                break;
            }
        }
        if (i >= netInfo->cnt) {
            return false;
        }
        *index = i;
        GetNetworkAddrNetMask(&(netInfo->netAddr[(*index)]), ifa, host);
    }
    return false;
}

static bool IsNicAvailable(const struct ifaddrs *ifa, const char *host, int32 logLevel)
{
    if (!(ifa->ifa_flags & IFF_UP)) {
        write_runlog(logLevel, "nic %s related with %s is down, ifa_flags=%u.\n", ifa->ifa_name, host, ifa->ifa_flags);
        return false;
    }

    if (!(ifa->ifa_flags & IFF_RUNNING)) {
        write_runlog(
            logLevel, "nic %s related with %s not running, ifa_flags=%u.\n", ifa->ifa_name, host, ifa->ifa_flags);
        return false;
    }
    return true;
}

static void CheckFloatIpNic(
    NetworkInfo *netInfo, const struct ifaddrs *ifa, const char *host, int32 logLevel, uint32 index)
{
    if (index >= netInfo->cnt) {
        return;
    }
    bool res = IsNicAvailable(ifa, host, logLevel);
    if (!res) {
        netInfo->stateCheck[index] = NETWORK_STATE_DOWN;
    } else {
        netInfo->stateCheck[index] = NETWORK_STATE_UP;
    }
}

static bool GetNicstatusByAddrs(
    const struct ifaddrs *ifList, NetworkInfo *netInfo, int32 logLevel, NetworkQuest quest)
{
    if (netInfo->cnt == 0 || netInfo->ips == NULL) {
        return false;
    }
    char host[NI_MAXHOST] = {0};
    uint32 validIpCount = 0;
    uint32 index = 0;
    for (const struct ifaddrs *ifa = ifList; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }
        int32 family = ifa->ifa_addr->sa_family;
        if (family != AF_INET && family != AF_INET6) {
            continue;
        }
        size_t saLen = (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
        if (getnameinfo(ifa->ifa_addr, saLen, host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST) != 0) {
            write_runlog(WARNING, "failed to get name info.\n");
            return false;
        }
        if (!GetNetworkIp(netInfo, host, &index, quest, ifa)) {
            continue;
        }
        if (netInfo->type == NETWORK_TYPE_FLOATIP) {
            CheckFloatIpNic(netInfo, ifa, host, logLevel, index);
            continue;
        }
        if (!IsNicAvailable(ifa, host, logLevel)) {
            return false;
        }
        ++validIpCount;
        if (validIpCount == netInfo->checkCnt) {
            return true;
        }
    }
    if (quest == NETWORK_QUEST_GET || netInfo->type == NETWORK_TYPE_FLOATIP) {
        return true;
    }
    char allListenIp[CM_IP_ALL_NUM_LENGTH] = {0};
    listen_ip_merge(netInfo->cnt, netInfo->ips, allListenIp, CM_IP_ALL_NUM_LENGTH);
    write_runlog(WARNING, "can't find nic related with %s, cnt=[%u: %u].\n",
        allListenIp, netInfo->cnt, netInfo->checkCnt);
    return false;
}

static void CheckNicStatus(struct ifaddrs *ifList, NetworkInfo *netInfo)
{
    int32 logLevel = DEBUG1;
    if (netInfo->type == NETWORK_TYPE_LISTEN || netInfo->type == NETWORK_TYPE_HA) {
        logLevel = WARNING;
    }
    if (netInfo->type == NETWORK_TYPE_FLOATIP) {
        for (uint32 i = 0; i < netInfo->cnt; ++i) {
            netInfo->stateCheck[i] = NETWORK_STATE_DOWN;
        }
    }
    if (GetNicstatusByAddrs(ifList, netInfo, logLevel)) {
        netInfo->networkRes = true;
    } else {
        netInfo->networkRes = false;
    }
    if (netInfo->type != NETWORK_TYPE_FLOATIP) {
        return;
    }
    for (uint32 i = 0; i < netInfo->cnt; ++i) {
        if (!netInfo->networkRes) {
            netInfo->stateRecord[i] = NETWORK_STATE_DOWN;
        } else {
            netInfo->stateRecord[i] = netInfo->stateCheck[i];
        }
    }
}

static bool CheckNetworkStatus()
{
    struct ifaddrs *ifList = NULL;
    if (getifaddrs(&ifList) < 0) {
        write_runlog(WARNING, "failed to get iflist.\n");
        return false;
    }
    for (uint32 i = 0; i < g_instCnt; ++i) {
        for (uint32 j = 0; j < (uint32)NETWORK_TYPE_CEIL; ++j) {
            CheckNicStatus(ifList, &(g_cmNetWorkInfo[i].manaIp[j]));
        }
    }
    freeifaddrs(ifList);
    return true;
}

bool8 CheckNetworkStatusByIps(const char (*ips)[CM_IP_LENGTH], uint32 cnt)
{
    struct ifaddrs *ifList = NULL;
    if (getifaddrs(&ifList) < 0) {
        write_runlog(WARNING, "failed to get iflist.\n");
        return CM_FALSE;
    }
    NetworkInfo netInfo;
    errno_t rc = memset_s(&netInfo, sizeof(NetworkInfo), 0, sizeof(NetworkInfo));
    securec_check_errno(rc, (void)rc);
    netInfo.ips = ips;
    netInfo.cnt = cnt;
    netInfo.checkCnt = GetIpCheckCnt(ips, cnt);
    netInfo.type = NETWORK_TYPE_HA;
    CheckNicStatus(ifList, &netInfo);
    freeifaddrs(ifList);
    return (bool8)netInfo.networkRes;
}

static bool GetNetworkAddr(NetworkInfo *netInfo, const char *str)
{
    struct ifaddrs *ifList = NULL;
    if (getifaddrs(&ifList) < 0) {
        write_runlog(WARNING, "%s failed to get iflist.\n", str);
        return false;
    }
    bool ret = GetNicstatusByAddrs(ifList, netInfo, DEBUG1, NETWORK_QUEST_GET);
    freeifaddrs(ifList);
    return ret;
}

status_t SetDownIpV6Nic(const NetworkInfo *netInfo, uint32 index, uint32 instId)
{
    char cmd[CM_MAX_COMMAND_LONG_LEN] = {0};
    GetNicDownCmd(cmd, CM_MAX_COMMAND_LONG_LEN, netInfo, index);
    if (cmd[0] == '\0') {
        return CM_ERROR;
    }
    write_runlog(LOG, "%s Ip: %s oper=[%d: %s], state=[%d: %s], GetNicCmd(%s).\n",
        __FUNCTION__, netInfo->ips[index], (int32)netInfo->oper, GetOperMapString(netInfo->oper),
        (int32)netInfo->stateRecord[index], GetStateMapString(netInfo->stateRecord[index]), cmd);
    int32 res = ExecuteSystemCmd(cmd);
    if (res != 0) {
        write_runlog(ERROR, "%s failed to execute the cmd(%s), res=%d, errno is %d.\n", __FUNCTION__, cmd, res, errno);
        return CM_ERROR;
    } else {
        netInfo->stateRecord[index] = NETWORK_STATE_DOWN;
        write_runlog(LOG, "[%s] successfully to execute the cmd (%s).\n",
            __FUNCTION__, cmd);
        return CM_SUCCESS;
    }
}

status_t SetUpIpV6Nic(const NetworkInfo *netInfo, uint32 index, uint32 instId)
{
    char cmd[CM_MAX_COMMAND_LONG_LEN] = {0};
    GetNicUpCmd(cmd, CM_MAX_COMMAND_LONG_LEN, netInfo, index, instId);
    if (cmd[0] == '\0') {
        return CM_ERROR;
    }
    write_runlog(LOG,
        "%s ip=%s; oper=[%d:%s], state=[%d:%s], GetNicCmd(%s).\n",
        __FUNCTION__,
        netInfo->ips[index],
        (int32)netInfo->oper,
        GetOperMapString(netInfo->oper),
        (int32)netInfo->stateRecord[index],
        GetStateMapString(netInfo->stateRecord[index]),
        cmd);
    int32 res = ExecuteSystemCmd(cmd);
    if (res != 0) {
        write_runlog(ERROR, "[%s] failed to execute the cmd (%s), res=%d, errno is %d.\n",
            __FUNCTION__, cmd, res, errno);
        return CM_ERROR;
    } else {
        netInfo->stateRecord[index] = NETWORK_STATE_UP;
        write_runlog(LOG, "[%s] successfully to execute the cmd (%s).\n",
            __FUNCTION__, cmd);
        return CM_SUCCESS;
    }
}

bool CheckAndRemoveInvaildIpV6FloatIp(const NetworkInfo *netInfo, uint32 index,
    const char *str, int32 logLevel, uint32 instId)
{
    char osFormatIp[CM_IP_LENGTH] = {0};
    if (!(ChangeIpV6ToOsFormat(netInfo->ips[index], osFormatIp, CM_IP_LENGTH))) {
        write_runlog(ERROR, "[%s] failed to change IpV6(%s) to os format.\n",
            str, netInfo->ips[index]);
        return false;
    }
    char cmd[CM_MAX_COMMAND_LONG_LEN] = {0};
    errno_t rc = snprintf_s(cmd,
        CM_MAX_COMMAND_LONG_LEN,
        CM_MAX_COMMAND_LONG_LEN - 1,
        "%s %s | grep %s | grep %s",
        SHOW_IPV6_CMD,
        osFormatIp,
        IPV6_DADFAILED_FLAG,
        IPV6_TENTATIVE_FLAG);
    securec_check_intval(rc, (void)rc);
    write_runlog(logLevel, "%s it will check ipv6 nic, and cmd is %s.\n", str, cmd);
    int32 ret = ExecuteSystemCmd(cmd, DEBUG1);
    if (ret == 0) {
        write_runlog(logLevel, "%s IPV6(%s) nic may be faulty\n", str, osFormatIp);
        return SetDownIpV6Nic(netInfo, index, instId) == CM_SUCCESS;
    }
    return true;
}

static void GetNicUpCmd(char *cmd, uint32 cmdLen, const NetworkInfo *netInfo, uint32 index, uint32 instId)
{
    const NetWorkAddr *netAddr = &(netInfo->netAddr[index]);
    if (netInfo->netAddr[index].netMask[0] == '\0' || netInfo->netAddr[index].netName[0] == '\0') {
        return;
    }
    OneCusResConfJson *resConf = NULL;
    for (uint32 i = 0; i < g_confJson->resource.count; ++i) {
        resConf = &g_confJson->resource.conf[i];
        if (resConf->resType == CUSTOM_RESOURCE_VIP) {
            break;
        }
    }

    errno_t rc = 0;
    if (netInfo->netAddr[index].family == AF_INET) {
        if (strcmp(resConf->vipResConf.cmd, "ip") == 0) {
            rc = snprintf_s(cmd, cmdLen, cmdLen - 1, "%s %us %s %s addr add %s/%s dev %s",
                TIMEOUT_MECHA, DEFAULT_CMD_TIMEOUT, g_sudoPermCmd, g_ipaddrCmd,
                resConf->vipResConf.floatIp, resConf->vipResConf.netMask, netAddr->netName);
        } else {
            rc = snprintf_s(cmd, cmdLen, cmdLen - 1, "%s %us %s %s %s:%u %s netmask %s up",
                TIMEOUT_MECHA, DEFAULT_CMD_TIMEOUT, g_sudoPermCmd, g_ifconfigCmd,
                netAddr->netName, netInfo->port, netInfo->ips[index], netAddr->netMask);
        }
        write_runlog(LOG, "Cmd is %s \n", cmd);
    } else if (netInfo->netAddr[index].family == AF_INET6) {
        if (!CheckAndRemoveInvaildIpV6FloatIp(netInfo, index, "[GetNicUpCmd]", LOG, instId)) {
            return;
        }
        rc = snprintf_s(cmd, cmdLen, cmdLen - 1,
            "%s %us %s %s -6 addr add %s/64 dev %s preferred_lft 0 nodad",
            TIMEOUT_MECHA, DEFAULT_CMD_TIMEOUT, SUDO_PERM_CMD, g_ipCmd,
            netInfo->ips[index], netAddr->netName);
        write_runlog(LOG, "IpV6AddCmd is %s \n", cmd);
    }
    securec_check_intval(rc, (void)rc);
}

static void GetNicDownCmd(char *cmd, uint32 cmdLen, const NetworkInfo *netInfo, uint32 index)
{
    const NetWorkAddr *netAddr = &(netInfo->netAddr[index]);
    if (netInfo->netAddr[index].netMask[0] == '\0' || netInfo->netAddr[index].netName[0] == '\0') {
        return;
    }
    OneCusResConfJson *resConf = NULL;
    for (uint32 i = 0; i < g_confJson->resource.count; ++i) {
        resConf = &g_confJson->resource.conf[i];
        if (resConf->resType == CUSTOM_RESOURCE_VIP) {
            break;
        }
    }

    errno_t rc = 0;
    if (netInfo->netAddr[index].family == AF_INET) {
        if (strcmp(resConf->vipResConf.cmd, "ip") == 0) {
            rc = snprintf_s(cmd, cmdLen, cmdLen - 1, "%s %us %s %s addr del %s/%s dev %s",
                TIMEOUT_MECHA, DEFAULT_CMD_TIMEOUT, g_sudoPermCmd, g_ipaddrCmd,
                resConf->vipResConf.floatIp, resConf->vipResConf.netMask,
                netAddr->netName);
        } else {
            rc = snprintf_s(cmd, cmdLen, cmdLen - 1, "%s %us %s %s %s:%u %s netmask %s down",
                TIMEOUT_MECHA, DEFAULT_CMD_TIMEOUT, g_sudoPermCmd, g_ifconfigCmd,
                netAddr->netName, netInfo->port, netInfo->ips[index], netAddr->netMask);
        }
        write_runlog(LOG, "Cmd is %s \n", cmd);
    } else {
        rc = snprintf_s(cmd, cmdLen, cmdLen - 1, "%s %us %s %s -6 addr del %s/64 dev %s",
            TIMEOUT_MECHA, DEFAULT_CMD_TIMEOUT, SUDO_PERM_CMD, g_ipCmd,
            netInfo->ips[index], netAddr->netName);
        write_runlog(LOG, "IpV6DelCmd is %s \n", cmd);
    }
    securec_check_intval(rc, (void)rc);
}

static void ExecuteArpingCmd(ArpingCmdRes *arpingCmd, const char *str)
{
    if (arpingCmd == NULL || arpingCmd->cmd[0] == '\0') {
        return;
    }
    write_runlog(LOG, "%s it will notify switch, and cmd is %s.\n", str, arpingCmd->cmd);
    int32 res = ExecuteSystemCmd(arpingCmd->cmd);
    if (res != 0) {
        write_runlog(
            ERROR, "%s failed to execute the cmd(%s), res=%d, errno is %d.\n", str, arpingCmd->cmd, res, errno);
    } else {
        write_runlog(LOG, "%s success to execute the cmd(%s).\n", str, arpingCmd->cmd);
        errno_t rc = memset_s(arpingCmd->cmd, CM_MAX_COMMAND_LONG_LEN, 0, CM_MAX_COMMAND_LONG_LEN);
        securec_check_errno(rc, (void)rc);
    }
}

static void CheckArpingCmdRes(NetworkInfo *netInfo)
{
    for (uint32 i = 0; i < netInfo->cnt; ++i) {
        ExecuteArpingCmd(&(netInfo->arpingCmd[i]), "[CheckArpingCmdRes]");
    }
}

static bool CheckNicStatusMeetsExpect(NetworkInfo *netInfo, bool8 *isExeArping)
{
    if (netInfo->cnt == 0) {
        return true;
    }
    NetworkState state = GetNetworkStateByOper(netInfo->oper);
    if (state == NETWORK_STATE_UNKNOWN) {
        return true;
    }
    // only float ip is up, it will notify switch
    if (netInfo->oper == NETWORK_OPER_UP) {
        *isExeArping = CM_TRUE;
    }
    for (uint32 i = 0; i < netInfo->cnt; ++i) {
        if (netInfo->stateRecord[i] != state) {
            return false;
        }
    }
    return true;
}

static void GenArpingCmd(NetworkInfo *netInfo, uint32 index, bool8 *isExeArping)
{
    if (netInfo->oper != NETWORK_OPER_UP) {
        return;
    }
    if (netInfo->netAddr[index].family == AF_INET6) {
        return;
    }
    errno_t rc = memset_s(netInfo->arpingCmd[index].cmd, CM_MAX_COMMAND_LONG_LEN, 0, CM_MAX_COMMAND_LONG_LEN);
    securec_check_errno(rc, (void)rc);
    if (netInfo->netAddr[index].family == AF_INET) {
        rc = snprintf_s(netInfo->arpingCmd[index].cmd, CM_MAX_COMMAND_LONG_LEN, CM_MAX_COMMAND_LONG_LEN - 1,
            "%s %s %s", ARPING_CMD, netInfo->netAddr[index].netName, netInfo->ips[index]);
        securec_check_intval(rc, (void)rc);
    } else if (netInfo->netAddr[index].family == AF_INET6) {
        rc = snprintf_s(netInfo->arpingCmd[index].cmd, CM_MAX_COMMAND_LONG_LEN, CM_MAX_COMMAND_LONG_LEN - 1,
            "%s %s %s", NDISC6_CMD, netInfo->netAddr[index].netName, netInfo->ips[index]);
        securec_check_intval(rc, (void)rc);
    }
    *isExeArping = CM_TRUE;
}

static void DoUpOrDownNetworkOper(NetworkInfo *netInfo, bool8 *isExeArping, uint32 instId)
{
    if (CheckNicStatusMeetsExpect(netInfo, isExeArping)) {
        return;
    }
    const char *str = (netInfo->oper == NETWORK_OPER_UP) ? "[DoUpNetworkOper]" : "[DoDownNetworkOper]";
    ResetAllNetMask(netInfo);
    if (!GetNetworkAddr(netInfo, str)) {
        return;
    }
    char cmd[CM_MAX_COMMAND_LONG_LEN];
    int32 res;
    errno_t rc;
    for (uint32 i = 0; i < netInfo->cnt; ++i) {
        rc = memset_s(cmd, CM_MAX_COMMAND_LONG_LEN, 0, CM_MAX_COMMAND_LONG_LEN);
        securec_check_errno(rc, (void)rc);
        if (netInfo->oper == NETWORK_OPER_UP && netInfo->stateRecord[i] != NETWORK_STATE_UP) {
            GetNicUpCmd(cmd, CM_MAX_COMMAND_LONG_LEN, netInfo, i, instId);
        } else if (netInfo->oper == NETWORK_OPER_DOWN && netInfo->stateRecord[i] == NETWORK_STATE_UP) {
            GetNicDownCmd(cmd, CM_MAX_COMMAND_LONG_LEN, netInfo, i);
        }
        if (cmd[0] == '\0') {
            GenArpingCmd(netInfo, i, isExeArping);
            continue;
        }
        write_runlog(LOG, "%s Ip: %s oper=[%d: %s], state=[%d: %s], GetNicCmd(%s).\n", str, netInfo->ips[i],
            (int32)netInfo->oper, GetOperMapString(netInfo->oper), (int32)netInfo->stateRecord[i],
            GetStateMapString(netInfo->stateRecord[i]), cmd);

        if (g_isPauseArbitration) {
            continue;
        }

        res = ExecuteSystemCmd(cmd);
        if (res != 0) {
            write_runlog(ERROR, "%s failed to execute the cmd(%s), res=%d, errno is %d.\n", str, cmd, res, errno);
        } else {
            netInfo->stateRecord[i] = GetNetworkStateByOper(netInfo->oper);
            write_runlog(LOG, "%s successfully to execute the cmd(%s).\n", str, cmd);
            GenArpingCmd(netInfo, i, isExeArping);
        }
    }
}

static void CheckAndExecuteArpingCmd()
{
    NetworkInfo *manaIp;
    for (uint32 i = 0; i < g_instCnt; ++i) {
        manaIp = &(g_cmNetWorkInfo[i].manaIp[NETWORK_TYPE_FLOATIP]);
        CheckArpingCmdRes(manaIp);
        manaIp->lasterOper = manaIp->oper;
    }
}

bool CheckEnableIpV6AutoNotify()
{
    const char *cmd = "sysctl -n net.ipv6.conf.all.ndisc_notify";
    FILE *fp = popen(cmd, "r");
    if (fp == NULL) {
        write_runlog(ERROR,
            "[%s] popen failed, cmd=[%s], error is %d.\n", __FUNCTION__, cmd, errno);
        return false;
    }

    char buf[CM_MAX_NUMBER_LENGTH] = {0};
    if (fgets(buf, CM_MAX_NUMBER_LENGTH - 1, fp) != NULL) {
        text_t text;
        text.str = buf;
        text.len = sizeof(buf);
        CmTrimText(&text);
        uint16 value;
        if (CmText2Uint16(&text, &value) == CM_SUCCESS && value == 1) {
            return true;
        }
    }
    (void)pclose(fp);
    write_runlog(DEBUG1, "[%s] exec cmd=[%s].\n", __FUNCTION__, cmd);
    return false;
}

bool CheckIpNicStatusUp(struct ifaddrs *ifList, const char *destIp)
{
    if (CM_IS_EMPTY_STR(destIp)) {
        return false;
    }
    char host[NI_MAXHOST] = {0};
    for (const struct ifaddrs *ifa = ifList; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }

        int32 family = ifa->ifa_addr->sa_family;
        if (family != AF_INET && family != AF_INET6) {
            continue;
        }
        size_t saLen = (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
        if (getnameinfo(ifa->ifa_addr, saLen, host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST) != 0) {
            write_runlog(WARNING, "[%s] failed to get name info.\n", __FUNCTION__);
            return false;
        }
        if (IsEqualIp(destIp, host) && IsNicAvailable(ifa, host, WARNING)) {
            return true;
        }
    }
    write_runlog(WARNING, "[%s] can't find nic related with %s.\n", __FUNCTION__, destIp);
    return false;
}

bool CheckIpNicExisting(const char *destIp)
{
    struct  ifaddrs *ifList = NULL;
    if (getifaddrs(&ifList) < 0) {
        write_runlog(WARNING, "[%s] failed to get ifList.\n", __FUNCTION__);
        return false;
    }

    bool ret = CheckIpNicStatusUp(ifList, destIp);
    freeifaddrs(ifList);
    return ret;
}

void ClearOneNeedResetFloatIp(const char *ip, DnFloatIp *dnFloatIp)
{
    for (uint32 i = 0; i < dnFloatIp->needResetFloatIpCnt; i++) {
        if (IsEqualIp(ip, dnFloatIp->needResetFloatIp[i])) {
            (void)pthread_rwlock_wrlock(&dnFloatIp->rwlock);
            errno_t rc = memset_s(dnFloatIp->needResetFloatIp[i], CM_IP_LENGTH, 0, CM_IP_LENGTH);
            securec_check_errno(rc, (void)rc);
            dnFloatIp->needResetFloatIpCnt--;
            (void)pthread_rwlock_unlock(&dnFloatIp->rwlock);
            return;
        }
    }
}

void ResetFloatIpV6(NetworkInfo *netInfo, DnFloatIp *dnFloatIp, uint32 instId)
{
    /* If the interface does not support NDISC, don't try reset. */
    if (!CheckEnableIpV6AutoNotify()) {
        return;  // Exit early if IPv6 auto notify is not enabled
    }

    // Iterate through the network information
    for (uint32 i = 0; i < netInfo->cnt; i++) {
        // Skip network entries based on several conditions
        if (netInfo->stateRecord[i] != NETWORK_STATE_UP ||
            netInfo->lasterOper == NETWORK_OPER_DOWN ||
            netInfo->netAddr[i].netMask[0] == '\0' ||
            netInfo->netAddr[i].netName[0] == '\0' ||
            netInfo->netAddr[i].family != AF_INET6) {
            continue;
        }

        // Skip if NIC doesn't exist or doesn't need resetting
        if (!CheckIpNicExisting(netInfo->ips[i]) ||
            !CheckNeedResetFloatIpExist(netInfo->ips[i], dnFloatIp)) {
            continue;
        }
        
        if (SetDownIpV6Nic(netInfo, i, instId) != CM_SUCCESS) {
            write_runlog(ERROR,
                "[%s] set down float up(%s) failed, error is %d.\n",
                __FUNCTION__,
                netInfo->ips[i],
                errno);
            continue;
        }
        if (SetUpIpV6Nic(netInfo, i, instId) != CM_SUCCESS) {
            write_runlog(ERROR,
                "[%s] set up float up(%s) failed, error is %d.\n",
                __FUNCTION__,
                netInfo->ips[i],
                errno);
            continue;
        }
        ClearOneNeedResetFloatIp(netInfo->ips[i], dnFloatIp);
        write_runlog(LOG, "[%s] reset float up(%s) success.\n", __FUNCTION__, netInfo->ips[i]);
    }
}

void CheckAndResetFloatIpV6()
{
    NetworkInfo *manaIp = NULL;
    DnFloatIp *floatIp = NULL;
    uint32 dnIdx = 0;
    for (uint32 i = 0; i < g_instCnt; ++i) {
        manaIp = &(g_cmNetWorkInfo[i].manaIp[NETWORK_TYPE_FLOATIP]);
        if (manaIp->cnt == 0 ||
            !FindDnIdxInCurNode(g_cmNetWorkInfo[i].instId, &dnIdx, "[CheckAndResetFloatIpV6]") ||
            GetDnFloatIpByDnIdx(dnIdx) == NULL) {
            continue;
        }
        ResetFloatIpV6(manaIp, floatIp, g_cmNetWorkInfo[i].instId);
        manaIp->lasterOper = manaIp->oper;
    }
}

static void DoNetworkOper()
{
    if (!IsNeedCheckFloatIp() || (agent_backup_open != CLUSTER_PRIMARY)) {
        write_runlog(DEBUG1, "[DoNetworkOper] agent_backup_open=%d, cannot set floatIp oper.\n",
            (int32)agent_backup_open);
        return;
    }
    NetworkInfo *manaIp = NULL;
    bool8 isExeArping = CM_FALSE;
    for (uint32 i = 0; i < g_instCnt; ++i) {
        manaIp = &(g_cmNetWorkInfo[i].manaIp[NETWORK_TYPE_FLOATIP]);
        if (manaIp->oper == NETWORK_OPER_UNKNOWN) {
            continue;
        }
        DoUpOrDownNetworkOper(manaIp, &isExeArping, g_cmNetWorkInfo[i].instId);
    }
    CheckAndExecuteArpingCmd();
    CheckAndResetFloatIpV6();
}

static void ReleaseSource()
{
    if (g_cmNetWorkInfo == NULL) {
        return;
    }
    for (uint32 i = 0; i < g_instCnt; ++i) {
        for (uint32 j = 0; j < (uint32)NETWORK_TYPE_CEIL; ++j) {
            FREE_AND_RESET(g_cmNetWorkInfo[i].manaIp[j].netAddr);
        }
    }
    FREE_AND_RESET(g_cmNetWorkInfo);
}

status_t CreateNetworkResource()
{
    status_t st = InitCmNetWorkInfo();
    if (st != CM_SUCCESS) {
        ReleaseSource();
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static uint8 CheckSingleFloatIpDown(const NetworkInfo *manaIp)
{
    for (uint32 i = 0; i < manaIp->cnt; ++i) {
        if (manaIp->stateRecord[i] == NETWORK_STATE_UP) {
            return CM_FALSE;
        }
    }
    return CM_TRUE;
}

static uint8 IsAllFloatIpDown()
{
    NetworkInfo *manaIp = NULL;
    for (uint32 i = 0; i < g_instCnt; ++i) {
        manaIp = &(g_cmNetWorkInfo[i].manaIp[NETWORK_TYPE_FLOATIP]);
        if (manaIp->cnt == 0) {
            continue;
        }
        if (!CheckSingleFloatIpDown(manaIp)) {
            return CM_FALSE;
        }
    }
    return CM_TRUE;
}

void *CmaCheckNetWorkMain(void *arg)
{
    thread_name = "CheckNetWork";
    write_runlog(LOG, "CmaCheckNetWorkMain will start, and threadId is %llu.\n", (unsigned long long)pthread_self());
    (void)pthread_detach(pthread_self());
    uint32 sleepInterval = 1;
    bool networkRes = false;
    for (;;) {
        if ((g_exitFlag || g_shutdownRequest) && IsAllFloatIpDown()) {
            cm_sleep(sleepInterval);
            continue;
        }
        networkRes = CheckNetworkStatus();
        CheckNetworkValidCnt(networkRes);
        DoNetworkOper();
        cm_sleep(sleepInterval);
    }
    ReleaseSource();
    return NULL;
}

void ClearAllNeedResetFloatIp(DnFloatIp *dnFloatIp)
{
    errno_t rc =
        memset_s(dnFloatIp->needResetFloatIp, MAX_FLOAT_IP_COUNT * CM_IP_LENGTH, 0,
            MAX_FLOAT_IP_COUNT * CM_IP_LENGTH);
    securec_check_errno(rc, (void)rc);
    dnFloatIp->needResetFloatIpCnt = 0;
}

bool CheckFloatIpExist(const char *ip, DnFloatIp *dnFloatIp)
{
    for (uint32 i = 0; i < dnFloatIp->dnFloatIpCount; ++i) {
        if (IsEqualIp(ip, dnFloatIp->dnFloatIp[i])) {
            return true;
        }
    }
    write_runlog(LOG,
        "[%s] instId(%u) floatIp(%s) not existed.\n",
        __FUNCTION__,
        dnFloatIp->instId,
        ip);
    return false;
}

bool CheckNeedResetFloatIpExist(const char *ip, const DnFloatIp *dnFloatIp)
{
    for (uint32 i = 0; i < dnFloatIp->needResetFloatIpCnt; i++) {
        if (IsEqualIp(ip, dnFloatIp->needResetFloatIp[i])) {
            return true;
        }
    }
    write_runlog(DEBUG1,
        "[%s] instId(%u) floatIp(%s) not existed in dn need reset floatIp.\n",
        __FUNCTION__,
        dnFloatIp->instId,
        ip);
    return false;
}

void SetNeedResetFloatIp(const CmSendPingDnFloatIpFail *recvMsg, uint32 dnIdx)
{
    if (dnIdx >= CM_MAX_DATANODE_PER_NODE) {
        return;
    }
    DnFloatIp *floatIp = GetDnFloatIpByDnIdx(dnIdx);
    if (floatIp == NULL) {
        return;
    }
    if (recvMsg->failedCount == 0 || recvMsg->failedCount > floatIp->dnFloatIpCount) {
        write_runlog(WARNING,
            "[%s] need reset floatIp count %u more than dn floatIp count %u or is zero.\n",
            __FUNCTION__,
            recvMsg->failedCount,
            floatIp->dnFloatIpCount);
        return;
    }
    write_runlog(LOG,
        "[%s] instId(%u) recv failed sount %u, cur need reset count %u, total count %u.\n",
        __FUNCTION__,
        g_floatIpMap.floatIp[dnIdx].instId,
        recvMsg->failedCount,
        floatIp->needResetFloatIpCnt,
        floatIp->dnFloatIpCount);
    
    (void)pthread_rwlock_wrlock(&floatIp->rwlock);
    if (floatIp->needResetFloatIpCnt >= floatIp->dnFloatIpCount) {
        ClearAllNeedResetFloatIp(floatIp);
    }

    errno_t rc;
    for (uint32 i = 0; i < recvMsg->failedCount; i++) {
        if (floatIp->needResetFloatIpCnt >= floatIp->dnFloatIpCount) {
            break;
        }
        if (!CheckFloatIpExist(recvMsg->failedDnFloatIp[i], floatIp)) {
            continue;
        }
        if (CheckNeedResetFloatIpExist(recvMsg->failedDnFloatIp[i], floatIp)) {
            continue;
        }
        rc = strcpy_s(floatIp->needResetFloatIp[floatIp->needResetFloatIpCnt],
            CM_IP_LENGTH, recvMsg->failedDnFloatIp[i]);
        securec_check_errno(rc, (void)rc);
        write_runlog(LOG, "[%s] instIs(%u) need reset floatIp %s.\n",
            __FUNCTION__,
            g_floatIpMap.floatIp[dnIdx].instId,
            floatIp->needResetFloatIp[floatIp->needResetFloatIpCnt]);
        floatIp->needResetFloatIpCnt++;
    }
    (void)pthread_rwlock_unlock(&floatIp->rwlock);
    write_runlog(LOG,
        "[%s] instIs(%u) recv failed count %u, need resest floatIp total count %u.\n",
        __FUNCTION__,
        g_floatIpMap.floatIp[dnIdx].instId,
        recvMsg->failedCount,
        floatIp->needResetFloatIpCnt);
}

bool CheckSupportIpV6()
{
    char cmd[CM_MAX_COMMAND_LONG_LEN] = {0};
    errno_t rc = snprintf_s(cmd,
        CM_MAX_COMMAND_LONG_LEN,
        CM_MAX_COMMAND_LONG_LEN - 1,
        "%s a | grep 'int6 ::1' | wc -l",
        g_ipCmd);
    securec_check_intval(rc, (void)rc);
    FILE *fp = popen(cmd, "r");
    if (fp == NULL) {
        write_runlog(ERROR, "[%s] popen faild, cmd=[%s], errno=%d.\n", __FUNCTION__, cmd, errno);
        return false;
    }

    bool support = false;
    char buf[CM_MAX_NUMBER_LENGTH] = {0};
    if (fgets(buf, CM_MAX_NUMBER_LENGTH - 1, fp) != NULL) {
        text_t text;
        text.str = buf;
        text.len = sizeof(buf);
        CmTrimText(&text);
        uint16 value;
        if (CmText2Uint16(&text, &value) == CM_SUCCESS && value >= 1) {
            support = true;
        }
    }
    (void)pclose(fp);
    write_runlog(LOG, "[%s] exec command:%s, support:%u.\n", __FUNCTION__, cmd, support);

    return support;
}