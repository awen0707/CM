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
 * cms_disk_check.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_server/cms_arbitrate_cluster.cpp
 *
 * -------------------------------------------------------------------------
 */

#include <pthread.h>
#include "cjson/cJSON.h"
#include "cm_defs.h"
#include "cm_voting_disk.h"
#include "cms_global_params.h"
#include "cms_ddb_adapter.h"
#include "cms_process_messages.h"
#include "cms_cus_res.h"
#include "cms_common_res.h"
#include "cms_rhb.h"
#include "cms_arbitrate_cluster.h"

#ifdef ENABLE_UT
#define static
#define cm_sleep break;cm_sleep
#endif
typedef enum SetStatusE {
    SET_STATUS_UNKOWN = 0,
    SET_STATUS_BEGIN,
    SET_STATUS_RUNNING,
    SET_STATUS_CEIL // it must be end
} SetStatus;

typedef struct NodeClusterT {
    int32 maxNodeNum;
    int32 clusterNum;
    int32 *cluster;  // nodeIdx
    int32 *visNode;
    int32 *resultSet;  // resultSet[i] >= i
    int32 inLastNum;  // in last cluster node num
} NodeCluster;

typedef struct MaxNodeClusterT {
    NodeCluster nodeCluster;
    pthread_rwlock_t lock;
    uint64 version;
} MaxNodeCluster;

typedef struct CmDrvTextT {
    uint32 len;
    char data[0];
} CmDrvText;

typedef struct ClusterResMapT {
    uint32 nodeIdx;
} ClusterResMap;

typedef struct ClusterResInfoT {
    int32 count;
    ClusterResMap map[CM_MAX_RES_INST_COUNT];
} ClusterResInfo;

typedef enum MaxClusterStatEn {
    MAX_CLUSTER_INIT = 0,
    MAX_CLUSTER_UNKNOWN,
    MAX_CLUSTER_INCLUDE,
    MAX_CLUSTER_EXCLUDE,
} MaxClusterStat;

typedef struct CurCmRhbStatSt {
    uint32 hwl;
    time_t baseTime;
    time_t hbs[MAX_RHB_NUM][MAX_RHB_NUM];
} CurCmRhbStat;

static CurCmRhbStat g_curRhbStat = {0};
static const int32 CHECK_DELAY_IN_ROLE_CHANGING = 10;

static MaxNodeCluster g_curCluster = {{0}};
static MaxNodeCluster g_lastCluster = {{0}};
static int32 g_delayArbiClusterTime = 0;
static ClusterResInfo g_clusterRes = {0};

static const int32 HEARTBEAT_INIT_TIME = 0;
static volatile int32 g_resHeartBeatTimeout[CM_MAX_RES_INST_COUNT][MAX_CLUSTER_TYPE_CEIL] = {{0}};

static volatile ThreadProcessStatus g_threadProcessStatus = THREAD_PROCESS_UNKNOWN;

static void PrintMaxNodeCluster(const MaxNodeCluster *maxNodeCluster, const char *str, int32 logLevel = LOG);

static void PrintAllRhbStatus();

static void InitClusterResInfo()
{
    errno_t rc = memset_s(&g_clusterRes, sizeof(ClusterResInfo), 0, sizeof(ClusterResInfo));
    securec_check_errno(rc, (void)rc);
    for (uint32 i = 0; i < g_node_num; ++i) {
        if (g_clusterRes.count >= CM_MAX_RES_INST_COUNT) {
            write_runlog(WARNING, "clusterRes count may be more then %d.\n", CM_MAX_RES_INST_COUNT);
            return;
        }
        if (g_node[i].datanodeCount > 0) {
            g_clusterRes.map[g_clusterRes.count].nodeIdx = i;
            ++g_clusterRes.count;
        }
    }
}

static bool CheckMaxClusterInputValue(int32 resIdx, int32 type)
{
    if (resIdx >= CM_MAX_RES_INST_COUNT || resIdx < 0) {
        return false;
    }
    if (type >= (int32)MAX_CLUSTER_TYPE_CEIL || type < 0) {
        return false;
    }
    return true;
}

static void SetMaxClusterHeartbeatValue(int32 resIdx, MaxClusterResType type, int32 value)
{
    if (!CheckMaxClusterInputValue(resIdx, (int32)type)) {
        return;
    }
    g_resHeartBeatTimeout[resIdx][type] = value;
}

static int32 GetMaxClusterHeartbeatValue(int32 resIdx, MaxClusterResType type)
{
    if (!CheckMaxClusterInputValue(resIdx, (int32)type)) {
        return HEARTBEAT_INIT_TIME;
    }
    return g_resHeartBeatTimeout[resIdx][type];
}

void CheckMaxClusterHeartbeartValue()
{
    for (int32 i = 0; i < CM_MAX_RES_INST_COUNT; ++i) {
        for (int32 j = 0; j < (int32)MAX_CLUSTER_TYPE_CEIL; ++j) {
            if (g_resHeartBeatTimeout[i][j] > HEARTBEAT_INIT_TIME) {
                --g_resHeartBeatTimeout[i][j];
            }
        }
    }
}

static bool IsMaxClusterHeartbeatTimeout(int32 resIdx, MaxClusterResType type)
{
    if (GetMaxClusterHeartbeatValue(resIdx, type) == HEARTBEAT_INIT_TIME) {
        return true;
    }
    return false;
}

void SetMaxClusterHeartBeatTimeout(int32 resIdx, MaxClusterResType type)
{
    SetMaxClusterHeartbeatValue(resIdx, type, (int32)instance_heartbeat_timeout);
}

static void ResetMaxClusterHeartBeatTimeOut()
{
    for (int32 i = 0; i < CM_MAX_RES_INST_COUNT; ++i) {
        for (int32 j = 0; j < (int32)MAX_CLUSTER_TYPE_CEIL; ++j) {
            SetMaxClusterHeartBeatTimeout(i, (MaxClusterResType)j);
        }
    }
}

static void RestAllMaxClusterRes()
{
    // res status
    ResetResNodeStat();
    // rhb
    ResetNodeConnStat();
    // vote disk
    ResetVotingdiskHeartBeat();
    // heartbeat
    ResetMaxClusterHeartBeatTimeOut();
    write_runlog(LOG, "reset all max cluster stat.\n");
}

static bool IsCurResInMaxCluster(int32 resIdx, const NodeCluster *nodeCluster)
{
    for (int32 i = 0; i < nodeCluster->clusterNum; ++i) {
        if (nodeCluster->cluster[i] == resIdx) {
            return true;
        }
    }
    write_runlog(DEBUG5, "res(%d) report is not in maxcluster.\n", resIdx);
    return false;
}

bool IsCurResAvail(int32 resIdx, MaxClusterResType type, MaxClusterResStatus status)
{
    if (status != MAX_CLUSTER_STATUS_INIT && status != MAX_CLUSTER_STATUS_UNKNOWN) {
        SetMaxClusterHeartBeatTimeout(resIdx, type);
        return (status == MAX_CLUSTER_STATUS_AVAIL);
    }
    if (IsMaxClusterHeartbeatTimeout(resIdx, type)) {
        write_runlog(DEBUG5, "res(%d) report heartbeat timeout.\n", resIdx);
        return false;
    }
    if (IsCurResInMaxCluster(resIdx, &(g_lastCluster.nodeCluster))) {
        return true;
    }
    return false;
}

void SetDelayArbiClusterTime()
{
    const int32 maxDelayTime = 1500;
    if (g_delayArbiClusterTime <= maxDelayTime) {
        ++g_delayArbiClusterTime;
    }
}

static CmDrvText *GetDmsValueInDdb(bool isEnd)
{
    const uint32 maxValueLen = 2048;
    static CmDrvText *value = NULL;
    // maybe value hasn't malloc memory.
    if (isEnd && value == NULL) {
        return NULL;
    }
    uint32 allLen = (uint32)sizeof(CmDrvText) + maxValueLen;
    if (value == NULL) {
        value = (CmDrvText *)malloc(allLen);
        if (value == NULL) {
            write_runlog(ERROR, "[GetDmsValueInDdb] failed to malloc value.\n");
            return NULL;
        }
    }
    errno_t rc = memset_s(value, allLen, 0, allLen);
    securec_check_errno(rc, (void)rc);
    value->len = maxValueLen;

    return value;
}

static void FreeMaxNodeClusterMemory(NodeCluster *nodeCluster)
{
    FREE_AND_RESET(nodeCluster->cluster);
    nodeCluster->resultSet = NULL;
    nodeCluster->visNode = NULL;
}

static void FreeDmsValue()
{
    CmDrvText *cmDrvTex = GetDmsValueInDdb(true);
    FREE_AND_RESET(cmDrvTex);
}

static void ReleaseMaxNodeMemory()
{
    (void)pthread_rwlock_wrlock(&(g_curCluster.lock));
    FreeMaxNodeClusterMemory(&(g_curCluster.nodeCluster));
    (void)pthread_rwlock_unlock(&(g_curCluster.lock));

    (void)pthread_rwlock_wrlock(&(g_lastCluster.lock));
    FreeMaxNodeClusterMemory(&(g_lastCluster.nodeCluster));
    (void)pthread_rwlock_unlock(&(g_lastCluster.lock));

    FreeDmsValue();
}

static status_t AllocNodeClusterMemory(NodeCluster *nodeCluster, int32 maxNodeNum)
{
    size_t memSize = sizeof(uint32) * (uint32)(maxNodeNum);
    size_t allSize = memSize + memSize + memSize;
    char *dynamicSt =  (char *)malloc(allSize);
    const char *str = "[AllocNodeClusterMemory]";
    if (dynamicSt == NULL) {
        write_runlog(ERROR, "%s dynamicSt failed to malloc %lu memory.\n", str, allSize);
        return CM_ERROR;
    }
    errno_t rc = memset_s(dynamicSt, allSize, 0, allSize);
    securec_check_errno(rc, (void)rc);

    size_t curSize = 0;
    nodeCluster->cluster = (int32 *)GetDynamicMem(dynamicSt, &(curSize), memSize);
    nodeCluster->resultSet = (int32 *)GetDynamicMem(dynamicSt, &(curSize), memSize);
    nodeCluster->visNode = (int32 *)GetDynamicMem(dynamicSt, &(curSize), memSize);
    if (curSize != allSize) {
        FREE_AND_RESET(dynamicSt);
        write_runlog(ERROR, "%s falled to alloc memory, curSize is %lu, allSize is %lu.\n", str, curSize, allSize);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static void MemsetMaxNodeCluster(NodeCluster *nodeCluster, int32 maxNodeNum)
{
    // version cannot be init
    uint32 memLen = (uint32)sizeof(int32) * (uint32)maxNodeNum;
    uint32 allLen = memLen + memLen + memLen;
    errno_t rc = memset_s(nodeCluster->cluster, allLen, 0, allLen);
    securec_check_errno(rc, (void)rc);
    nodeCluster->clusterNum = 0;
    nodeCluster->maxNodeNum = maxNodeNum;
}

static status_t InitMaxNodeCluster(MaxNodeCluster *maxNodeCluster)
{
    (void)pthread_rwlock_wrlock(&(maxNodeCluster->lock));
    if (maxNodeCluster->nodeCluster.maxNodeNum != g_clusterRes.count) {
        write_runlog(LOG, "maxNodeNum=%d, count=%d.\n", maxNodeCluster->nodeCluster.maxNodeNum, g_clusterRes.count);
        FreeMaxNodeClusterMemory(&(maxNodeCluster->nodeCluster));
        if (AllocNodeClusterMemory(&(maxNodeCluster->nodeCluster), g_clusterRes.count) != CM_SUCCESS) {
            write_runlog(ERROR, "failed to init maxNode cluster.\n");
            FreeMaxNodeClusterMemory(&(maxNodeCluster->nodeCluster));
            (void)pthread_rwlock_unlock(&(maxNodeCluster->lock));
            return CM_ERROR;
        }
        maxNodeCluster->nodeCluster.maxNodeNum = g_clusterRes.count;
    }
    MemsetMaxNodeCluster(&(maxNodeCluster->nodeCluster), maxNodeCluster->nodeCluster.maxNodeNum);
    (void)pthread_rwlock_unlock(&(maxNodeCluster->lock));
    return CM_SUCCESS;
}

static MaxClusterResStatus GetNodesConnStatByRhb(int idx1, int idx2, int timeout)
{
    if (timeout == 0) {
        return MAX_CLUSTER_STATUS_AVAIL;
    }

    if (g_curRhbStat.hbs[idx1][idx2] == 0 || g_curRhbStat.hbs[idx2][idx1] == 0) {
        return MAX_CLUSTER_STATUS_INIT;
    }

    bool RhbTimeOutDirect = IsRhbTimeout(g_curRhbStat.hbs[idx1][idx2], g_curRhbStat.baseTime, timeout);
    bool RhbTimeOutForward = IsRhbTimeout(g_curRhbStat.hbs[idx2][idx1], g_curRhbStat.baseTime, timeout);
    write_runlog(DEBUG1, "rhb timeout check result start node: %d, end node: %d, result: %d.\n",
        idx1, idx2, RhbTimeOutDirect);
    write_runlog(DEBUG1, "rhb timeout check result start node: %d, end node: %d, result: %d.\n",
        idx2, idx1, RhbTimeOutForward);
    if (RhbTimeOutDirect && RhbTimeOutForward) {
        return MAX_CLUSTER_STATUS_UNAVAIL;
    }
    return MAX_CLUSTER_STATUS_AVAIL;
}

static bool CheckPoint2PointConn(int32 resIdx1, int32 resIdx2)
{
    MaxClusterResStatus connStatus = GetNodesConnStatByRhb(resIdx1, resIdx2, (int)g_agentNetworkTimeout);

    bool connRes1 = IsCurResAvail(resIdx1, MAX_CLUSTER_TYPE_NETWORK, connStatus);
    bool connRes2 = IsCurResAvail(resIdx2, MAX_CLUSTER_TYPE_NETWORK, connStatus);
    return (connRes1 && connRes2);
}

static MaxClusterResStatus GetDiskHeartbeatStat(uint32 nodeIndex, uint32 diskTimeout, int logLevel)
{
    VotingDiskStatus stat = GetNodeHeartbeatStat(nodeIndex, diskTimeout, logLevel);
    if (stat == VOTING_DISK_STATUS_UNAVAIL) {
        return MAX_CLUSTER_STATUS_UNAVAIL;
    } else if (stat == VOTING_DISK_STATUS_AVAIL) {
        return MAX_CLUSTER_STATUS_AVAIL;
    }
    return MAX_CLUSTER_STATUS_UNKNOWN;
}

static bool IsAllResAvailInNode(int32 resIdx)
{
    uint32 nodeIdx = g_clusterRes.map[resIdx].nodeIdx;
    MaxClusterResStatus heartbeatStatus = GetDiskHeartbeatStat(nodeIdx, g_diskTimeout, DEBUG5);
    bool heartbeatRes = IsCurResAvail(resIdx, MAX_CLUSTER_TYPE_VOTE_DISK, heartbeatStatus);
    MaxClusterResStatus nodeStatus = GetResNodeStat(g_node[nodeIdx].node, DEBUG5);
    bool nodeRes = IsCurResAvail(resIdx, MAX_CLUSTER_TYPE_RES_STATUS, nodeStatus);
    return (heartbeatRes && nodeRes);
}

static bool IsNodeRhbAlive(int32 nodeIdx)
{
    int heart_beat = 
        g_instance_group_report_status_ptr[nodeIdx].instance_status.command_member[0].heat_beat;
    if (heart_beat > (int)instance_heartbeat_timeout) {
        write_runlog(DEBUG1, "node(%d) heartbeat timeout, heartbeat:%d, threshold:%u\n",
            nodeIdx, heart_beat, instance_heartbeat_timeout);
        return false;
    }
    return true;
}

static int32 GetInMaxClusterNodeCnt(int32 maxNum, const NodeCluster *nodeCluster)
{
    int32 cnt = 0;
    for (int32 i = 0; i < maxNum; ++i) {
        if (IsCurResInMaxCluster(nodeCluster->visNode[i], &(g_lastCluster.nodeCluster))) {
            ++cnt;
        }
    }
    return cnt;
}

static bool IsBetterCluster(int32 maxNum, NodeCluster *nodeCluster)
{
    int32 cnt = GetInMaxClusterNodeCnt(maxNum, nodeCluster);
    if (cnt > nodeCluster->inLastNum) {
        nodeCluster->inLastNum = cnt;
        return true;
    }
    if (cnt < nodeCluster->inLastNum) {
        return false;
    }
    for (int32 i = 0; i < maxNum; ++i) {
        if (nodeCluster->visNode[i] < nodeCluster->cluster[i]) {
            return true;
        }
    }
    return false;
}

static inline uint32 GetNodeByPoint(int point)
{
    return g_node[g_clusterRes.map[point].nodeIdx].node;
}

static void StrcatNextNodeStr(char *clusterStr, uint32 maxStrLen, int32 resIdx)
{
    uint32 nodeIdx = g_clusterRes.map[resIdx].nodeIdx;
    const uint32 nodeLen = 64;
    char nodeStr[nodeLen] = {0};
    errno_t rc = snprintf_s(nodeStr, nodeLen, nodeLen - 1, "%u, ", g_node[nodeIdx].node);
    securec_check_intval(rc, (void)rc);
    rc = strcat_s(clusterStr, maxStrLen, nodeStr);
    securec_check_errno(rc, (void)rc);
}

static void PrintClusterNodes(int32 maxNum, int32 curNode, const int32 *node, int32 maxNodeNum)
{
    if (log_min_messages > LOG) {
        return;
    }
    char nodeStr[MAX_PATH_LEN] = {0};
    for (int32 i = 0; i < maxNum && i < maxNodeNum; ++i) {
        StrcatNextNodeStr(nodeStr, MAX_PATH_LEN, node[i]);
    }
    write_runlog(LOG, "curNode=[%d: %u], curCluster=[%s].\n", curNode, GetNodeByPoint(curNode), nodeStr);
}

static int32 FindNodeCluster(int32 startPoint, int32 maxNum, NodeCluster *nodeCluster)
{
    int32 j = 0;
    // maxNum is max node num in vis.
    for (int32 i = startPoint + 1; i < nodeCluster->maxNodeNum; ++i) {
        if (!IsAllResAvailInNode(i)) {
            continue;
        }
        if (!CheckPoint2PointConn(startPoint, i)) {
            write_runlog(DEBUG5, "Node %d and %d disconnect.\n", startPoint, i);
            continue;
        }
        write_runlog(DEBUG1, "Node %d and %d connect right.\n", startPoint, i);
        for (j = 0; j < maxNum; ++j) {
            if (!CheckPoint2PointConn(i, nodeCluster->visNode[j])) {
                write_runlog(DEBUG5, "Node %d and %d disconnect.\n", i, nodeCluster->visNode[j]);
                break;
            }
            write_runlog(DEBUG1, "Node %d and %d connect right.\n", i, nodeCluster->visNode[j]);
        }
        if (j == maxNum) {  // it can connect with all node, and insert into visNode
            nodeCluster->visNode[maxNum] = i;
            if (FindNodeCluster(i, maxNum + 1, nodeCluster) == 1) {
                return 1;
            }
        }
    }

    PrintClusterNodes(maxNum, startPoint, nodeCluster->visNode, nodeCluster->maxNodeNum);

    if ((maxNum > nodeCluster->clusterNum) ||
        (maxNum == nodeCluster->clusterNum && IsBetterCluster(maxNum, nodeCluster))) {
        nodeCluster->inLastNum = GetInMaxClusterNodeCnt(maxNum, nodeCluster);
        for (int32 i = 0; i < maxNum; ++i) {
            nodeCluster->cluster[i] = nodeCluster->visNode[i];
        }
        nodeCluster->clusterNum = maxNum;
        return 1;
    }
    return 0;
}

static void FindMaxNodeCluster(MaxNodeCluster *maxCluster)
{
    NodeCluster *nodeCluster = &(maxCluster->nodeCluster);
    nodeCluster->clusterNum = -1;
    g_curRhbStat.baseTime = time(NULL);
    GetRhbStat(g_curRhbStat.hbs, &g_curRhbStat.hwl);
    PrintAllRhbStatus();
    // assume that all meet the conditions.
    for (int32 i = nodeCluster->maxNodeNum - 1; i >= 0; --i) {
        if (!IsAllResAvailInNode(i) || !IsNodeRhbAlive(i)) {
            continue;
        }
        nodeCluster->visNode[0] = i;  // first node
        (void)FindNodeCluster(i, 1, nodeCluster);
        nodeCluster->resultSet[i] = nodeCluster->clusterNum;
    }
    PrintMaxNodeCluster(maxCluster, "[FindMaxNodeCluster]");
}

static void PrintMaxNodeCluster(const MaxNodeCluster *maxNodeCluster, const char *str, int32 logLevel)
{
    if (log_min_messages > logLevel) {
        return;
    }
    char clusterStr[MAX_PATH_LEN] = {0};
    errno_t rc = snprintf_s(clusterStr, MAX_PATH_LEN, MAX_PATH_LEN - 1, "version is %lu, total node num is %d, "
        "and node is ", maxNodeCluster->version, maxNodeCluster->nodeCluster.clusterNum);
    securec_check_intval(rc, (void)rc);
    for (int32 i = 0; i < maxNodeCluster->nodeCluster.clusterNum; ++i) {
        StrcatNextNodeStr(clusterStr, MAX_PATH_LEN, maxNodeCluster->nodeCluster.cluster[i]);
    }
    write_runlog(LOG, "%s the max node cluster: %s.\n", str, clusterStr);
}

static void GetClusterKeyInDdb(char *key, uint32 keyLen)
{
    errno_t rc = snprintf_s(key, keyLen, keyLen - 1, "/%s/CM/CMServer/Cluster", pw->pw_name);
    securec_check_intval(rc, (void)rc);
}

static void SetMaxNodeClusterWhenEmptyStr(MaxNodeCluster *maxNodeCluster)
{
    for (int32 i = 0; i < maxNodeCluster->nodeCluster.maxNodeNum; ++i) {
        maxNodeCluster->nodeCluster.cluster[i] = i;
    }
    maxNodeCluster->nodeCluster.clusterNum = maxNodeCluster->nodeCluster.maxNodeNum;
    maxNodeCluster->version = 1;
}

static status_t FindClusterResIdxByNode(uint32 node, int32 *resIdx, const char *str)
{
    uint32 nodeIdx;
    for (int32 i = 0; i < g_clusterRes.count; ++i) {
        nodeIdx = g_clusterRes.map[i].nodeIdx;
        if (g_node[nodeIdx].node == node) {
            *resIdx = i;
            return CM_SUCCESS;
        }
    }
    write_runlog(ERROR, "%s cannot find the resIdx by nodeId(%u).\n", str, node);
    return CM_ERROR;
}

static status_t ParseClusterNodeSingle(int32 *clusterSingle, int32 *idx, const cJSON *cJsonItem)
{
    // id:
    cJSON *item = cJSON_GetObjectItem(cJsonItem, "id");
    if (cJSON_IsNumber(item) == 0 || item->valueint < 0) {
        write_runlog(ERROR, "failed to parse id.\n");
        return CM_ERROR;
    }
    int32 resIdx = 0;
    // maybe the node have been deleted, so it need to return CM_SUCCESS
    status_t st = FindClusterResIdxByNode((uint32)item->valueint, &resIdx, "[ParseClusterNodeSingle]");
    if (st != CM_SUCCESS) {
        return CM_SUCCESS;
    }
    clusterSingle[*idx] = resIdx;
    ++(*idx);
    return CM_SUCCESS;
}

static status_t ParseNodeClusterSingle(MaxNodeCluster *maxNodeCluster, const cJSON *cJsonItem)
{
    // version
    cJSON *item = cJSON_GetObjectItem(cJsonItem, "version");
    if (cJSON_IsString(item) == 0) {
        write_runlog(ERROR, "failed to parse version.\n");
        return CM_ERROR;
    }
    maxNodeCluster->version = (uint64)CmAtol(cJSON_GetStringValue(item), 0);

    // nodes:
    item = cJSON_GetObjectItem(cJsonItem, "nodes");
    if (cJSON_IsArray(item) == 0) {
        write_runlog(ERROR, "failed to parse nodes.\n");
        return CM_ERROR;
    }
    cJSON *nodeItem;
    int32 idx = 0;
    cJSON_ArrayForEach(nodeItem, item) {
        if (cJSON_IsObject(nodeItem) == 0) {
            write_runlog(ERROR, "failed to parse nodes, item is not object.\n");
            return CM_ERROR;
        }
        CM_RETURN_IFERR(ParseClusterNodeSingle(maxNodeCluster->nodeCluster.cluster, &idx, nodeItem));
    }
    maxNodeCluster->nodeCluster.clusterNum = idx;
    // history in ddb maybe fault, will set all res in maxNodeCluster
    if (maxNodeCluster->nodeCluster.clusterNum == 0) {
        SetMaxNodeClusterWhenEmptyStr(maxNodeCluster);
    }
    return CM_SUCCESS;
}

static status_t ParseNodeClusterSingleInLock(MaxNodeCluster *maxNodeCluster, const cJSON *cJsonItem)
{
    (void)pthread_rwlock_wrlock(&(maxNodeCluster->lock));
    status_t ret = ParseNodeClusterSingle(maxNodeCluster, cJsonItem);
    (void)pthread_rwlock_unlock(&(maxNodeCluster->lock));
    return ret;
}

static status_t SetMaxNodeClusterByParseValue(MaxNodeCluster *maxNodeCluster, const char *value)
{
    cJSON *cJsonObj = cJSON_Parse(value);
    if (cJSON_IsArray(cJsonObj) == 0) {
        write_runlog(ERROR, "cJsonObj is not array, value is %s.\n", value);
        cJSON_Delete(cJsonObj);
        return CM_ERROR;
    }
    cJSON *cJsonItem;
    cJSON_ArrayForEach(cJsonItem, cJsonObj) {
        if (cJSON_IsObject(cJsonItem) == 0) {
            write_runlog(ERROR, "cJsonItem is not object, value is %s.\n", value);
            cJSON_Delete(cJsonItem);
            return CM_ERROR;
        }
        CM_RETURN_IFERR_EX(ParseNodeClusterSingleInLock(maxNodeCluster, cJsonItem), cJSON_Delete(cJsonObj));
    }
    cJSON_Delete(cJsonObj);
    return CM_SUCCESS;
}

static status_t GetHistoryMaxClusterFromDdb(MaxNodeCluster *maxNodeCluster)
{
    const char *str = "[GetHistoryMaxClusterFromDdb]";
    status_t st = InitMaxNodeCluster(maxNodeCluster);
    if (st != CM_SUCCESS) {
        write_runlog(ERROR, "%s failed to init maxNodeCluster.\n", str);
        return CM_ERROR;
    }
    char key[MAX_PATH_LEN] = {0};
    GetClusterKeyInDdb(key, MAX_PATH_LEN);
    CmDrvText *cmText = GetDmsValueInDdb(false);
    DDB_RESULT ddbResult = SUCCESS_GET_VALUE;
    st = GetKVFromDDb(key, MAX_PATH_LEN, cmText->data, cmText->len, &ddbResult);
    write_runlog(LOG, "%s get key(%s) value(%s) from ddb, status is %d, ddbResult is %d.\n",
        str, key, cmText->data, (int32)st, (int32)ddbResult);
    if (st != CM_SUCCESS && ddbResult != CAN_NOT_FIND_THE_KEY) {
        return CM_ERROR;
    }
    if (ddbResult == CAN_NOT_FIND_THE_KEY) {
        (void)pthread_rwlock_wrlock(&(maxNodeCluster->lock));
        SetMaxNodeClusterWhenEmptyStr(maxNodeCluster);
        (void)pthread_rwlock_unlock(&(maxNodeCluster->lock));
        PrintMaxNodeCluster(maxNodeCluster, str, FATAL);
        return CM_SUCCESS;
    }
    st = SetMaxNodeClusterByParseValue(maxNodeCluster, cmText->data);
    if (st != CM_SUCCESS) {
        write_runlog(ERROR, "failed to parse json(%s).\n", cmText->data);
        return CM_ERROR;
    }
    PrintMaxNodeCluster(maxNodeCluster, "[GetHistoryMaxClusterFromDdb]", FATAL);
    return CM_SUCCESS;
}

static void SetCurMaxNodeByLast(MaxNodeCluster *curMaxNodeCluster, const MaxNodeCluster *lastMaxNodeCluster)
{
    // curMaxNodeCluster version is 1 more than lastMaxNodeCluster
    curMaxNodeCluster->version = lastMaxNodeCluster->version + 1;
}

static void SetTimeoutWaitForNewRes()
{
    g_delayArbiClusterTime = 0;
}

static int32 GetTimeoutWaitForNewRes()
{
    return g_clusterStarting ? g_clusterArbiTime : CHECK_DELAY_IN_ROLE_CHANGING;
}

static status_t UpdateMaxCluster(MaxNodeCluster *maxNodeCluster)
{
    static int lastCmsRole = CM_SERVER_UNKNOWN;
    if (g_HA_status->local_role == lastCmsRole) {
        if (g_HA_status->local_role != CM_SERVER_PRIMARY) {
            g_threadProcessStatus = THREAD_PROCESS_INIT;
            return CM_ERROR;
        }
        if (g_threadProcessStatus == THREAD_PROCESS_SLEEP) {
            return CM_SUCCESS;
        }
    }
    lastCmsRole = g_HA_status->local_role;
    if (GetHistoryMaxClusterFromDdb(maxNodeCluster) != CM_SUCCESS) {
        return CM_ERROR;
    }
    PrintMaxNodeCluster(maxNodeCluster, "[UpdateMaxCluster]", FATAL);
    return CM_SUCCESS;
}

static status_t CheckCmNodeClusterArbitrate(bool *hasHistory, CmsArbitrateStatus *cmsSt)
{
    if ((g_clusterArbiTime == 0) || CmsCanArbitrate(cmsSt, "[MaxNodeClusterArbitrateMain]") != CM_SUCCESS) {
        *hasHistory = false;
        CM_RETURN_IFERR(UpdateMaxCluster(&g_lastCluster));
        g_threadProcessStatus = THREAD_PROCESS_SLEEP;
        return CM_ERROR;
    }
    if (!(*hasHistory)) {
        g_threadProcessStatus = THREAD_PROCESS_INIT;
        SetTimeoutWaitForNewRes();
        if (GetHistoryMaxClusterFromDdb(&g_lastCluster) != CM_SUCCESS) {
            return CM_ERROR;
        }
        g_threadProcessStatus = THREAD_PROCESS_READY;
        SetCurMaxNodeByLast(&g_curCluster, &g_lastCluster);
        RestAllMaxClusterRes();
        *hasHistory = true;
    }

    return CM_SUCCESS;
}

bool8 IsLastClusterSameWithCur(const int32 *lastCluster, int32 lastLen, const int32 *curCluster, int32 curLen)
{
    if (lastLen != curLen) {
        return CM_FALSE;
    }
    for (int32 i = 0; i < lastLen; ++i) {
        if (lastCluster[i] != curCluster[i]) {
            return CM_FALSE;
        }
    }
    return CM_TRUE;
}

static void SetDataWithString(char *data, uint32 dataLen, const char *key, uint64 value)
{
    char tmp[MAX_PATH_LEN] = {0};
    errno_t rc = snprintf_s(tmp, MAX_PATH_LEN, MAX_PATH_LEN - 1, "\"%s\":\"%lu\", ", key, value);
    securec_check_intval(rc, (void)rc);
    rc = strcat_s(data, dataLen, tmp);
    securec_check_errno(rc, (void)rc);
}

static void SetDataWithInt(char *data, uint32 dataLen, const char *key, uint32 value, SetStatus setStatus)
{
    char tmp[MAX_PATH_LEN] = {0};
    errno_t rc;
    if (setStatus == SET_STATUS_BEGIN) {
        rc = snprintf_s(tmp, MAX_PATH_LEN, MAX_PATH_LEN - 1, "{\"%s\":%u}", key, value);
        securec_check_intval(rc, (void)rc);
    } else if (setStatus == SET_STATUS_RUNNING) {
        rc = snprintf_s(tmp, MAX_PATH_LEN, MAX_PATH_LEN - 1, ", {\"%s\":%u}", key, value);
        securec_check_intval(rc, (void)rc);
    }
    rc = strcat_s(data, dataLen, tmp);
    securec_check_errno(rc, (void)rc);
}

static void SetDmsValueInJson(const MaxNodeCluster *curCluster, char *data, uint32 dataLen)
{
    errno_t rc = strcat_s(data, dataLen, "[{");
    securec_check_errno(rc, (void)rc);

    // version
    SetDataWithString(data, dataLen, "version", curCluster->version);

    // nodes:
    rc = strcat_s(data, dataLen, "\"nodes\": ");
    securec_check_errno(rc, (void)rc);
    // id:
    uint32 nodeId;
    uint32 nodeIdx;
    rc = strcat_s(data, dataLen, "[");
    securec_check_errno(rc, (void)rc);
    for (int32 i = 0; i < curCluster->nodeCluster.clusterNum; ++i) {
        nodeIdx = g_clusterRes.map[curCluster->nodeCluster.cluster[i]].nodeIdx;
        nodeId = g_node[nodeIdx].node;
        if (i == 0) {
            SetDataWithInt(data, dataLen, "id", nodeId, SET_STATUS_BEGIN);
        } else {
            SetDataWithInt(data, dataLen, "id", nodeId, SET_STATUS_RUNNING);
        }
    }

    // end
    rc = strcat_s(data, dataLen, "]}]");
    securec_check_errno(rc, (void)rc);
}

static status_t SetCurClusterToDdb(const MaxNodeCluster *curCluster)
{
    char key[MAX_PATH_LEN] = {0};
    GetClusterKeyInDdb(key, MAX_PATH_LEN);
    CmDrvText *cmText = GetDmsValueInDdb(false);
    SetDmsValueInJson(curCluster, cmText->data, cmText->len);
    write_runlog(LOG, "cms will set key(%s) value(%s) to ddb.\n", key, cmText->data);
    return SetKV2Ddb(key, MAX_PATH_LEN, cmText->data, cmText->len, NULL);
}

static MaxClusterStat IsNodeInMaxCluster(uint32 nodeId)
{
    MaxNodeCluster *cluster = &(g_lastCluster);
    (void)pthread_rwlock_rdlock(&(cluster->lock));
    uint32 nodeIdx;

    if (cluster->nodeCluster.cluster == NULL || cluster->nodeCluster.clusterNum == 0) {
        (void)pthread_rwlock_unlock(&(cluster->lock));
        return MAX_CLUSTER_UNKNOWN;
    }

    for (int32 i = 0; i < cluster->nodeCluster.clusterNum; ++i) {
        nodeIdx = g_clusterRes.map[cluster->nodeCluster.cluster[i]].nodeIdx;
        if (g_node[nodeIdx].node == nodeId) {
            (void)pthread_rwlock_unlock(&(cluster->lock));
            return MAX_CLUSTER_INCLUDE;
        }
    }
    (void)pthread_rwlock_unlock(&(cluster->lock));
    return MAX_CLUSTER_EXCLUDE;
}

void NotifyResRegOrUnreg()
{
    if ((g_threadProcessStatus == THREAD_PROCESS_UNKNOWN) || (g_threadProcessStatus == THREAD_PROCESS_STOP) ||
        (g_threadProcessStatus == THREAD_PROCESS_INIT)) {
        return;
    }

    if (!CanProcessResStatus()) {
        write_runlog(LOG, "[%s], res status list invalid, can't continue.\n", __FUNCTION__);
        return;
    }

    for (uint32 i = 0; i < g_node_num; ++i) {
        MaxClusterStat ret = IsNodeInMaxCluster(g_node[i].node);
        if (ret == MAX_CLUSTER_INCLUDE) {
            NotifyCmaDoReg(g_node[i].node);
        } else if (ret == MAX_CLUSTER_EXCLUDE) {
            NotifyCmaDoUnreg(g_node[i].node);
        } else {
            write_runlog(LOG, "node=%u, MaxClusterStat=%d, can't do notify reg or unreg.\n", g_node[i].node, (int)ret);
        }
    }
}

static void CopyCur2LastMaxNodeCluster(MaxNodeCluster *lastCluster, MaxNodeCluster *curCluster)
{
    (void)pthread_rwlock_wrlock(&(lastCluster->lock));
    if (curCluster->nodeCluster.maxNodeNum > lastCluster->nodeCluster.maxNodeNum) {
        status_t st = InitMaxNodeCluster(lastCluster);
        if (st != CM_SUCCESS) {
            write_runlog(ERROR, "failed to copy curCluster to lastCluster, because failed to init.\n");
            (void)pthread_rwlock_unlock(&(lastCluster->lock));
            return;
        }
    }
    for (int32 i = 0; i < curCluster->nodeCluster.clusterNum; ++i) {
        lastCluster->nodeCluster.cluster[i] = curCluster->nodeCluster.cluster[i];
    }
    lastCluster->nodeCluster.clusterNum = curCluster->nodeCluster.clusterNum;
    lastCluster->version = curCluster->version;
    SetCurMaxNodeByLast(curCluster, lastCluster);
    (void)pthread_rwlock_unlock(&(lastCluster->lock));
    PrintMaxNodeCluster(lastCluster, "[CompareCurLastMaxNodeCluster]", DEBUG1);
}

static void AddCurResInCurCluster(int32 resIdx, NodeCluster *curCluster)
{
    if (curCluster->clusterNum >= curCluster->maxNodeNum) {
        write_runlog(ERROR, "cannot add res In curCluster, because clusterNum=%d, maxNodeNum=%d.\n",
            curCluster->clusterNum, curCluster->maxNodeNum);
        return;
    }
    curCluster->cluster[curCluster->clusterNum] = resIdx;
    ++curCluster->clusterNum;
}

/*
 * qsort comparison function for resIdx in MaxCluster
 * sort way by increment
 */
static int ResIndexComparator(const void *arg1, const void *arg2)
{
    int32 index1 = *(const int32 *)arg1;
    int32 index2 = *(const int32 *)arg2;

    return (index1 - index2);
}

static bool8 CanArbitrateMaxCluster(const NodeCluster *lastCluster, NodeCluster *curCluster)
{
    // process in starting or cms role has changed, it need to wait for the new info of agent report.
    if (g_delayArbiClusterTime >= GetTimeoutWaitForNewRes()) {
        return CM_TRUE;
    }

    int32 resIdx;
    bool8 hasModifyCluster = CM_FALSE;
    for (int32 i = 0; i < lastCluster->clusterNum; ++i) {
        resIdx = lastCluster->cluster[i];
        if (!IsCurResInMaxCluster(resIdx, curCluster)) {
            AddCurResInCurCluster(resIdx, curCluster);
            hasModifyCluster = CM_TRUE;
        }
    }
    if (!hasModifyCluster) {
        return CM_TRUE;
    }

    if (curCluster->clusterNum > 0) {
#undef qsort
        qsort(curCluster->cluster, (size_t)curCluster->clusterNum, sizeof(int32), ResIndexComparator);
    }

    return (bool8)(curCluster->clusterNum > lastCluster->clusterNum);
}

static bool IsNodeInCluster(int32 resIdx, const MaxNodeCluster *nodeCluster)
{
    for (int32 i = 0; i < nodeCluster->nodeCluster.clusterNum; ++i) {
        if (resIdx == nodeCluster->nodeCluster.cluster[i]) {
            return true;
        }
    }
    return false;
}

static void PrintOneRhbLine(time_t *timeArr)
{
    int ret;
    errno_t rc;
    char rhbStr[MAX_PATH_LEN] = {0};
    const uint32 maxInfoLen = TIME_STR_MAX_LEN + 1;

    for (uint32 i = 0; i < g_curRhbStat.hwl; ++i) {
        char info[maxInfoLen] = {0};
        char timeBuf[TIME_STR_MAX_LEN] = {0};
        GetTimeStr(timeArr[i], timeBuf, TIME_STR_MAX_LEN);
        ret = snprintf_s(info, maxInfoLen, maxInfoLen - 1, "%s|", timeBuf);
        securec_check_intval(ret, (void)ret);
        rc = strncat_s(rhbStr, MAX_PATH_LEN, info, strlen(info));
        securec_check_errno(rc, (void)rc);
    }
    write_runlog(LOG, "[RHB] hb infos: |%s\n", rhbStr);
}

static void PrintAllRhbStatus()
{
    char timeBuf[TIME_STR_MAX_LEN] = {0};
    GetTimeStr(g_curRhbStat.baseTime, timeBuf, TIME_STR_MAX_LEN);

    write_runlog(LOG, "Network timeout:%u\n", g_agentNetworkTimeout);
    write_runlog(LOG, "Network base_time:%s\n", timeBuf);
    for (uint32 i = 0; i < g_curRhbStat.hwl; ++i) {
        PrintOneRhbLine(&g_curRhbStat.hbs[i][0]);
    }
}

static void PrintKickOutResult(int32 resIdx, const MaxNodeCluster *maxCluster)
{
    uint32 nodeIdx = g_clusterRes.map[resIdx].nodeIdx;

    MaxClusterResStatus heartbeatStatus = GetDiskHeartbeatStat(nodeIdx, g_diskTimeout, LOG);
    if (!IsCurResAvail(resIdx, MAX_CLUSTER_TYPE_VOTE_DISK, heartbeatStatus)) {
        write_runlog(LOG, "kick out result: node(%u) disk heartbeat timeout.\n", g_node[nodeIdx].node);
        return;
    }

    MaxClusterResStatus nodeStatus = GetResNodeStat(g_node[nodeIdx].node, LOG);
    if (!IsCurResAvail(resIdx, MAX_CLUSTER_TYPE_RES_STATUS, nodeStatus)) {
        write_runlog(LOG, "kick out result: node(%u) res inst manual stop or report timeout.\n", g_node[nodeIdx].node);
        return;
    }

    for (int32 i = 0; i < maxCluster->nodeCluster.clusterNum; ++i) {
        if (resIdx == maxCluster->nodeCluster.cluster[i]) {
            continue;
        }
        if (!CheckPoint2PointConn(resIdx, maxCluster->nodeCluster.cluster[i])) {
            write_runlog(LOG, "kick out result: (index=%d,nodeId=%u) disconnect with (index=%d,nodeId=%u).\n",
                resIdx, GetNodeByPoint(resIdx), i, GetNodeByPoint(i));
            continue;
        }
    }
    PrintAllRhbStatus();
}

static void PrintArbitrateResult(const MaxNodeCluster *lastCluster, const MaxNodeCluster *curCluster)
{
    // kick out
    for (int32 i = 0; i < lastCluster->nodeCluster.clusterNum; ++i) {
        if (!IsNodeInCluster(lastCluster->nodeCluster.cluster[i], curCluster)) {
            uint32 nodeIdx = g_clusterRes.map[lastCluster->nodeCluster.cluster[i]].nodeIdx;
            WriteKeyEventLog(KEY_EVENT_RES_ARBITRATE, 0, "node(%u) kick out.", g_node[nodeIdx].node);
            PrintKickOutResult(lastCluster->nodeCluster.cluster[i], lastCluster);
        }
    }

    // join in
    for (int32 i = 0; i < curCluster->nodeCluster.clusterNum; ++i) {
        if (!IsNodeInCluster(curCluster->nodeCluster.cluster[i], lastCluster)) {
            uint32 nodeIdx = g_clusterRes.map[curCluster->nodeCluster.cluster[i]].nodeIdx;
            WriteKeyEventLog(KEY_EVENT_RES_ARBITRATE, 0, "node(%u) join in cluster.", g_node[nodeIdx].node);
        }
    }
}

static void CompareCurLastMaxNodeCluster(MaxNodeCluster *lastCluster, MaxNodeCluster *curCluster)
{
    if (curCluster->nodeCluster.clusterNum <= 0) {
        PrintMaxNodeCluster(lastCluster, "[CompareCurLastMaxNodeCluster]", FATAL);
        return;
    }
    bool8 result = IsLastClusterSameWithCur(lastCluster->nodeCluster.cluster, lastCluster->nodeCluster.clusterNum,
        curCluster->nodeCluster.cluster, curCluster->nodeCluster.clusterNum);
    if (result && (curCluster->version == lastCluster->version + 1)) {
        return;
    }
    if (!CanArbitrateMaxCluster(&(lastCluster->nodeCluster), &(curCluster->nodeCluster))) {
        return;
    }
    write_runlog(LOG, "last(%lu) is different from current(%lu), result is %d.\n",
        lastCluster->version, curCluster->version, result);
    PrintArbitrateResult(lastCluster, curCluster);
    // wait for successfully setting cluster to ddb.
    status_t st = SetCurClusterToDdb(curCluster);
    if (st != CM_SUCCESS) {
        return;
    }
    CopyCur2LastMaxNodeCluster(lastCluster, curCluster);
}

static void InitMaxNodeResourceSingle(MaxNodeCluster *maxCluster)
{
    errno_t rc = memset_s(maxCluster, sizeof(MaxNodeCluster), 0, sizeof(MaxNodeCluster));
    securec_check_errno(rc, (void)rc);
    maxCluster->version = 0;
    (void)pthread_rwlock_init(&(maxCluster->lock), NULL);
    (void)InitMaxNodeCluster(maxCluster);
}

static void InitMaxNodeResource()
{
    InitMaxNodeResourceSingle(&g_lastCluster);
    InitMaxNodeResourceSingle(&g_curCluster);
}

static status_t CheckVotingDisk()
{
    const uint32 timeout = 6;
    uint32 time = timeout;
    while (time > 0) {
        if (UpdateAllNodeHeartBeat(g_node_num) == CM_SUCCESS) {
            return CM_SUCCESS;
        }
        time--;
        cm_sleep(1);
    }
    /* cms to standby */
    write_runlog(LOG, "CheckVotingDisk failed, cms switch to standby.\n");
    return CM_ERROR;
}

void *MaxNodeClusterArbitrateMain(void *arg)
{
    thread_name = "MaxClusterAb";
    write_runlog(LOG, "MaxNodeClusterArbitrateMain will start, and threadId is %lu.\n", pthread_self());
    (void)pthread_detach(pthread_self());
    uint32 sleepInterval = 1;
    bool hasHistory = false;
    CmsArbitrateStatus cmsSt = {false, CM_SERVER_UNKNOWN, MAINTENANCE_MODE_NONE};
    InitClusterResInfo();
    InitMaxNodeResource();
    if (InitVotingDisk(g_votingDiskPath) != CM_SUCCESS) {
        write_runlog(FATAL, "Init voting disk failed!\n");
        exit(-1);
    }
    if (AllocVotingDiskMem() != CM_SUCCESS) {
        write_runlog(FATAL, "Alloc voting disk memory failed!\n");
        exit(-1);
    }
    g_curRhbStat.baseTime = time(NULL);
    GetRhbStat(g_curRhbStat.hbs, &g_curRhbStat.hwl);
    for (;;) {
        if (got_stop) {
            g_threadProcessStatus = THREAD_PROCESS_STOP;
            cm_sleep(sleepInterval);
            break;
        }

        if (ctl_stop_cluster_server_halt_arbitration_timeout > 0) {
            cm_sleep(sleepInterval);
            break;
        }

        if (CheckCmNodeClusterArbitrate(&hasHistory, &cmsSt) != CM_SUCCESS) {
            cm_sleep(sleepInterval);
            continue;
        }

        if (CheckVotingDisk() != CM_SUCCESS) {
            cm_sleep(sleepInterval);
            continue;
        }

        g_threadProcessStatus = THREAD_PROCESS_RUNNING;
        CM_BREAK_IF_ERROR(InitMaxNodeCluster(&g_curCluster));
        FindMaxNodeCluster(&g_curCluster);

        CompareCurLastMaxNodeCluster(&g_lastCluster, &g_curCluster);
        cm_sleep(sleepInterval);
    }
    g_threadProcessStatus = THREAD_PROCESS_STOP;
    FreeVotingDiskMem();
    ReleaseMaxNodeMemory();
    write_runlog(LOG, "MaxNodeClusterArbitrateMain will exit, and threadId is %lu.\n", pthread_self());
    return NULL;
}
