/*
* Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
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
* cms_process_messages_agent.cpp
*
*
* IDENTIFICATION
*    src/cm_server/cms_process_messages_agent.cpp
*
* -------------------------------------------------------------------------
*/
#include "cms_conn.h"
#include "cms_cus_res.h"
#include "cms_common_res.h"
#include "cms_ddb_adapter.h"
#include "cms_global_params.h"
#include "cms_process_messages.h"
#include "cm_misc_res.h"

typedef struct ResStatReportInfoSt {
    uint32 nodeId;
    MaxClusterResStatus isAvail;  // 0:res inst unavailable, 1:res inst available
} ResStatReportInfo;

typedef struct OneResStatReportInterSt {
    uint32 nodeId;
    uint32 cmInstId;
    uint32 statReportInter;
} OneResStatReportInter;

typedef struct ResStatReportInterSt {
    char resName[CM_MAX_RES_NAME];
    uint32 instCount;
    OneResStatReportInter resReport[CM_MAX_RES_INST_COUNT];
} ResStatReportInter;

static ResStatReportInfo *g_resNodeStat = NULL;
static ResStatReportInter *g_resInstReport = NULL;

void ProcessReportResChangedMsg(bool notifyClient, const OneResStatList *status)
{
    CmsReportResStatList sendMsg = {0};
    sendMsg.msgType = notifyClient ? (int)MSG_CM_AGENT_RES_STATUS_CHANGED : (int)MSG_CM_AGENT_RES_STATUS_LIST;
    errno_t rc = memcpy_s(&sendMsg.resList, sizeof(OneResStatList), status, sizeof(OneResStatList));
    securec_check_errno(rc, (void)rc);

    (void)BroadcastMsg('S', (char *)(&sendMsg), sizeof(CmsReportResStatList));
}

uint32 ResCheckResultTransToResStat(uint32 recvStat)
{
    if (recvStat == CUS_RES_CHECK_STAT_ONLINE) {
        return (uint32)CM_RES_STAT_ONLINE;
    }
    if (recvStat == CUS_RES_CHECK_STAT_OFFLINE) {
        return (uint32)CM_RES_STAT_OFFLINE;
    }
    if (recvStat == CUS_RES_CHECK_STAT_TIMEOUT) {
        return (uint32)CM_RES_STAT_UNKNOWN;
    }
    if (recvStat == CUS_RES_CHECK_STAT_ABNORMAL) {
        return (uint32)CM_RES_STAT_ONLINE;
    }

    return (uint32)CM_RES_STAT_UNKNOWN;
}

void IncreaseResReportInterMain(const char *resName, uint32 increaseInstId)
{
    if (g_resInstReport == NULL) {
        return;
    }

    for (uint32 i = 0; i < CusResCount(); ++i) {
        if (strcmp(g_resInstReport[i].resName, resName) != 0) {
            continue;
        }
        for (uint32 j = 0; j < g_resInstReport[i].instCount; ++j) {
            if (g_resInstReport[i].resReport[j].cmInstId == increaseInstId) {
                ++(g_resInstReport[i].resReport[j].statReportInter);
                break;
            }
        }
        break;
    }
}

void IncreaseOneResInstReportInter(const char *resName, uint32 instId)
{
    IncreaseResReportInterMain(resName, instId);
}

uint32 GetResReportInterMain(const char *resName, uint32 instId)
{
    if (g_resInstReport == NULL) {
        return 0;
    }

    for (uint32 i = 0; i < CusResCount(); ++i) {
        if (strcmp(g_resInstReport[i].resName, resName) != 0) {
            continue;
        }
        for (uint32 j = 0; j < g_resInstReport[i].instCount; ++j) {
            if (g_resInstReport[i].resReport[j].cmInstId == instId) {
                return g_resInstReport[i].resReport[j].statReportInter;
            }
        }
        break;
    }
    return 0;
}

uint32 GetOneResInstReportInter(const char *resName, uint32 instId)
{
    return GetResReportInterMain(resName, instId);
}

static bool IsOneCusResStatValid(uint32 status)
{
    if (status == CUS_RES_CHECK_STAT_ONLINE ||
        status == CUS_RES_CHECK_STAT_OFFLINE ||
        status == CUS_RES_CHECK_STAT_ABNORMAL ||
        status == CUS_RES_CHECK_STAT_TIMEOUT) {
        return true;
    }

    return false;
}

static void CleanResReportInter(const CmResourceStatus *resStat)
{
    for (uint32 i = 0; i < CusResCount(); ++i) {
        if (strcmp(g_resInstReport[i].resName, resStat->resName) != 0) {
            continue;
        }
        for (uint32 j = 0; j < g_resInstReport[i].instCount; ++j) {
            if (g_resInstReport[i].resReport[j].cmInstId != resStat->cmInstanceId) {
                continue;
            }
            if (IsOneCusResStatValid(resStat->status)) {
                g_resInstReport[i].resReport[j].statReportInter = 0;
            }
            break;
        }
        break;
    }
}

void CleanAllResStatusReportInter()
{
    write_runlog(LOG, "cms will clean res status report.\n");
    for (uint32 i = 0; i < CusResCount(); ++i) {
        for (uint32 j = 0; j < g_resInstReport[i].instCount; ++j) {
            g_resInstReport[i].resReport[j].statReportInter = 0;
        }
    }
}

static bool8 IsNodeCriticalResReportTimeout(uint32 nodeId)
{
    for (uint32 i = 0; i < CusResCount(); ++i) {
        for (uint32 j = 0; j < g_resInstReport[i].instCount; ++j) {
            if (g_resInstReport[i].resReport[j].nodeId != nodeId) {
                continue;
            }
            if (g_resInstReport[i].resReport[j].statReportInter >= g_agentNetworkTimeout) {
                return CM_TRUE;
            }
        }
    }
    return CM_FALSE;
}

static void InitResInstReport()
{
    g_resInstReport = (ResStatReportInter*)CmMalloc(sizeof(ResStatReportInter) * CusResCount());

    errno_t rc;
    for (uint32 i = 0; i < CusResCount(); ++i) {
        rc = strcpy_s(g_resInstReport[i].resName, CM_MAX_RES_NAME, g_resStatus[i].status.resName);
        securec_check_errno(rc, (void)rc);
        g_resInstReport[i].instCount = g_resStatus[i].status.instanceCount;
        for (uint32 j = 0; j < g_resInstReport[i].instCount; ++j) {
            g_resInstReport[i].resReport[j].nodeId = g_resStatus[i].status.resStat[j].nodeId;
            g_resInstReport[i].resReport[j].cmInstId = g_resStatus[i].status.resStat[j].cmInstanceId;
            g_resInstReport[i].resReport[j].statReportInter = 0;
        }
    }
}

static void InitResStatReport()
{
    g_resNodeStat = (ResStatReportInfo*)CmMalloc(sizeof(ResStatReportInfo) * GetResNodeCount());
    for (uint32 i = 0; i < GetResNodeCount(); ++i) {
        g_resNodeStat[i].nodeId = GetResNodeId(i);
        g_resNodeStat[i].isAvail = MAX_CLUSTER_STATUS_INIT;
    }
}

void InitNodeReportVar()
{
    InitResInstReport();
    InitResStatReport();
}

static uint32 FindNodeReportResInterByNodeId(uint32 nodeId)
{
    for (uint32 i = 0; i < GetResNodeCount(); ++i) {
        if (g_resNodeStat[i].nodeId == nodeId) {
            return i;
        }
    }
    return GetResNodeCount();
}

static MaxClusterResStatus GetResNodeStatByReport(uint32 stat)
{
    if (stat == RES_INST_WORK_STATUS_UNAVAIL) {
        return MAX_CLUSTER_STATUS_UNAVAIL;
    } else if (stat == RES_INST_WORK_STATUS_AVAIL) {
        return MAX_CLUSTER_STATUS_AVAIL;
    } else if (stat == RES_INST_WORK_STATUS_UNKNOWN) {
        return MAX_CLUSTER_STATUS_UNKNOWN;
    } else {
        write_runlog(LOG, "recv unknown status %u.\n", stat);
    }

    return MAX_CLUSTER_STATUS_UNKNOWN;
}

static MaxClusterResStatus IsAllNodeResInstAvail(const OneNodeResourceStatus *nodeStat, MaxClusterResStatus oldStat)
{
    for (uint32 i = 0; i < nodeStat->count; ++i) {
        MaxClusterResStatus newStat = GetResNodeStatByReport(nodeStat->status[i].workStatus);
        if (newStat != oldStat) {
            write_runlog(LOG, "recv cus_res inst(%u): new work_status(%d), old work_status(%d).\n",
                nodeStat->status[i].cmInstanceId, (int)newStat, (int)oldStat);
        }
        if (newStat != MAX_CLUSTER_STATUS_AVAIL) {
            return newStat;
        }
    }

    return MAX_CLUSTER_STATUS_AVAIL;
}

static inline void WriteGetResNodeStatErrLog(uint32 nodeId)
{
    write_runlog(ERROR, "can't find nodeId(%u) in g_resNodeStat.\n", nodeId);
    for (uint32 i = 0; i < GetResNodeCount(); ++i) {
        write_runlog(ERROR, "g_resNodeStat[%u].nodeId = %u.\n", i, g_resNodeStat[i].nodeId);
    }
}

static void RecordResStatReport(const OneNodeResourceStatus *nodeStat)
{
    if (g_resNodeStat == NULL || g_resInstReport == NULL) {
        write_runlog(ERROR, "g_resNodeStat or g_resInstReport is null.\n");
        return;
    }

    uint32 ind = FindNodeReportResInterByNodeId(nodeStat->node);
    if (ind < GetResNodeCount()) {
        for (uint32 i = 0; i < nodeStat->count; ++i) {
            CleanResReportInter(&nodeStat->status[i]);
        }
        g_resNodeStat[ind].isAvail = IsAllNodeResInstAvail(nodeStat, g_resNodeStat[ind].isAvail);
    } else {
        WriteGetResNodeStatErrLog(nodeStat->node);
    }
}

static const char* GetClusterResStatStr(MaxClusterResStatus stat)
{
    switch (stat) {
        case MAX_CLUSTER_STATUS_INIT:
            return "init";
        case MAX_CLUSTER_STATUS_UNKNOWN:
            return "unknown";
        case MAX_CLUSTER_STATUS_AVAIL:
            return "avail";
        case MAX_CLUSTER_STATUS_UNAVAIL:
            return "unavail";
        case MAX_CLUSTER_STATUS_CEIL:
            break;
    }

    return "";
}

MaxClusterResStatus GetResNodeStat(uint32 nodeId, int logLevel)
{
    if (g_resNodeStat == NULL || g_resInstReport == NULL) {
        return MAX_CLUSTER_STATUS_UNKNOWN;
    }

    if (IsNodeCriticalResReportTimeout(nodeId)) {
        write_runlog(logLevel, "recv node(%u) agent report res status msg timeout.\n", nodeId);
        return MAX_CLUSTER_STATUS_UNAVAIL;
    }

    uint32 ind = FindNodeReportResInterByNodeId(nodeId);
    if (ind < GetResNodeCount()) {
        if (g_resNodeStat[ind].isAvail != MAX_CLUSTER_STATUS_AVAIL) {
            write_runlog(logLevel, "node(%u) stat (%s).\n", nodeId, GetClusterResStatStr(g_resNodeStat[ind].isAvail));
        }
        return g_resNodeStat[ind].isAvail;
    } else {
        WriteGetResNodeStatErrLog(nodeId);
    }

    return MAX_CLUSTER_STATUS_UNKNOWN;
}

static bool8 IsResInstStatChange(uint32 cmInstId, uint32 recvStat, CmResStatList *oldResStat, uint32 *changeInd)
{
    for (uint32 i = 0; i < oldResStat->status.instanceCount; ++i) {
        if (cmInstId != oldResStat->status.resStat[i].cmInstanceId) {
            continue;
        }
        if (!IsOneCusResStatValid(recvStat)) {
            if (oldResStat->status.resStat[i].status != (uint32)CM_RES_STAT_UNKNOWN) {
                write_runlog(LOG, "recv inst(%u) invalid res status(%u), exceed (%u)s, will set it unknown.\n",
                    cmInstId, recvStat, g_agentNetworkTimeout);
            }
            return CM_FALSE;
        }
        uint32 newStat = ResCheckResultTransToResStat(recvStat);
        uint32 oldStat = oldResStat->status.resStat[i].status;
        if (oldStat != newStat) {
            write_runlog(LOG, "inst(%u)'s old status(%u) change to new status(%u).\n", cmInstId, oldStat, newStat);
            (*changeInd) = i;
            return CM_TRUE;
        } else {
            return CM_FALSE;
        }
    }

    write_runlog(ERROR, "res(%s)'s inst(%u) not exist.\n", oldResStat->status.resName, cmInstId);
    return CM_FALSE;
}

static void ProcessOneResInstStatReport(CmResourceStatus *newStat)
{
    newStat->resName[CM_MAX_RES_NAME - 1] = '\0';

    uint32 index = 0;
    if (GetGlobalResStatusIndex(newStat->resName, index) != CM_SUCCESS) {
        write_runlog(ERROR, "%s, unknown the resName(%s).\n", __func__, newStat->resName);
        return;
    }

    uint32 changeInd = 0;
    bool8 isChanged = IsResInstStatChange(newStat->cmInstanceId, newStat->status, &g_resStatus[index], &changeInd);
    if (isChanged) {
        (void)pthread_rwlock_wrlock(&(g_resStatus[index].rwlock));
        g_resStatus[index].status.resStat[changeInd].status = ResCheckResultTransToResStat(newStat->status);
        ++(g_resStatus[index].status.version);
        OneResStatList resStat = g_resStatus[index].status;
        (void)pthread_rwlock_unlock(&(g_resStatus[index].rwlock));

        ProcessReportResChangedMsg(true, &resStat);
        PrintCusInfoResList(&resStat, __FUNCTION__);
    }
}

void ProcessAgent2CmResStatReportMsg(ReportResStatus *resStatusPtr)
{
    RecordResStatReport(&resStatusPtr->nodeStat);

    for (uint32 i = 0; i < resStatusPtr->nodeStat.count; ++i) {
        ProcessOneResInstStatReport(&resStatusPtr->nodeStat.status[i]);
    }
}

void ProcessRequestResStatusListMsg(MsgRecvInfo* recvMsgInfo)
{
    CmsReportResStatList sendMsg = {0};

    sendMsg.msgType = (int)MSG_CM_AGENT_RES_STATUS_LIST;

    for (uint32 i = 0; i < CusResCount(); ++i) {
        (void)pthread_rwlock_rdlock(&(g_resStatus[i].rwlock));
        errno_t rc = memcpy_s(&sendMsg.resList, sizeof(OneResStatList), &g_resStatus[i].status, sizeof(OneResStatList));
        securec_check_errno(rc, (void)rc);
        (void)pthread_rwlock_unlock(&(g_resStatus[i].rwlock));

        (void)RespondMsg(recvMsgInfo, 'S', (char*)(&sendMsg), sizeof(CmsReportResStatList));
    }
}

void ProcessRequestLatestResStatusListMsg(MsgRecvInfo *recvMsgInfo, RequestLatestStatList *recvMsg)
{
    CmsReportResStatList sendMsg = {0};
    sendMsg.msgType = (int)MSG_CM_AGENT_RES_STATUS_LIST;

    errno_t rc;
    for (uint32 i = 0; i < CusResCount(); ++i) {
        if (g_resStatus[i].status.version == recvMsg->statVersion[i]) {
            continue;
        }

        (void)pthread_rwlock_rdlock(&(g_resStatus[i].rwlock));
        rc = memcpy_s(&sendMsg.resList, sizeof(OneResStatList), &g_resStatus[i].status, sizeof(OneResStatList));
        securec_check_errno(rc, (void)rc);
        (void)pthread_rwlock_unlock(&(g_resStatus[i].rwlock));

        (void)RespondMsg(recvMsgInfo, 'S', (char*)(&sendMsg), sizeof(CmsReportResStatList));
    }
}

static inline void GetResLockDdbKey(char *key, uint32 keyLen, const char *resName, const char *lockName)
{
    int ret = snprintf_s(key, keyLen, keyLen - 1, "/%s/CM/LockOwner/%s/%s", pw->pw_name, resName, lockName);
    securec_check_intval(ret, (void)ret);
}

static status_t GetLockOwner(const char *resName, const char *lockName, uint32 &curLockOwner)
{
    char key[MAX_PATH_LEN] = {0};
    GetResLockDdbKey(key, MAX_PATH_LEN, resName, lockName);

    char lockValue[MAX_PATH_LEN] = {0};
    DDB_RESULT ddbResult = SUCCESS_GET_VALUE;
    status_t st = GetKVFromDDb(key, MAX_PATH_LEN, lockValue, MAX_PATH_LEN, &ddbResult);
    if (st != CM_SUCCESS) {
        if (ddbResult != CAN_NOT_FIND_THE_KEY) {
            write_runlog(ERROR, "[CLIENT] failed to get value of key(%s).\n", key);
            return CM_ERROR;
        }
        curLockOwner = 0;
        return CM_SUCCESS;
    }
    if (is_digit_string(lockValue) != 1) {
        write_runlog(ERROR, "[CLIENT] the value(%s) of key(%s) is not digit, delete it.\n", lockValue, key);
        if (DelKeyInDdb(key, (uint32)strlen(key)) != CM_SUCCESS) {
            write_runlog(ERROR, "[CLIENT] ddb del failed. key=%s.\n", key);
            return CM_ERROR;
        }
        curLockOwner = 0;
        return CM_SUCCESS;
    }

    int owner = CmAtoi(lockValue, 1);
    if (!IsResInstIdValid(owner)) {
        write_runlog(LOG, "[CLIENT] cur res(%s) (%s)lock owner(%d) is invalid, delete it.\n", resName, lockName, owner);
        if (DelKeyInDdb(key, (uint32)strlen(key)) != CM_SUCCESS) {
            write_runlog(ERROR, "[CLIENT] ddb del failed. key=%s.\n", key);
            return CM_ERROR;
        }
        curLockOwner = 0;
        return CM_SUCCESS;
    }
    curLockOwner = (uint32)owner;

    return CM_SUCCESS;
}

static uint32 GetOfficialId()
{
    static uint32 officialId = -1;

    for (uint32 i = 0; i < g_node_num; i++) {
        for (uint32 j = 0; j < g_node[i].datanodeCount; j++) {
            if (g_node[i].datanode[j].datanodeRole == PRIMARY_DN) {
                officialId = g_node[i].datanode[j].datanodeId;
                write_runlog(LOG, "PRIMARY_DN is %d.\n", officialId);
                return officialId;
            }
        }
    }

    return officialId;
}

static status_t SetLockOwner4FirstReform()
{
    char key[MAX_PATH_LEN] = {0};
    char resName[CM_MAX_RES_NAME] = {0};
    char lockName[CM_MAX_LOCK_NAME] = {0};
    char lockValue[MAX_PATH_LEN] = {0};
    char officialId[MAX_PATH_LEN] = {0};
    errno_t rc;

    rc = strncpy_s(resName, CM_MAX_RES_NAME, "dms_res", strlen("dms_res"));
    securec_check_errno(rc, (void)rc);
    rc = strncpy_s(lockName, CM_MAX_LOCK_NAME, "dms_reformer_lock", strlen("dms_reformer_lock"));
    securec_check_errno(rc, (void)rc);
    GetResLockDdbKey(key, MAX_PATH_LEN, resName, lockName);

    DDB_RESULT ddbResult = SUCCESS_GET_VALUE;
    status_t st = GetKVFromDDb(key, MAX_PATH_LEN, lockValue, MAX_PATH_LEN, &ddbResult);
    if (st != CM_SUCCESS) {
        if (ddbResult != CAN_NOT_FIND_THE_KEY) {
            write_runlog(ERROR, "failed to get value with key(%s) in 1st reform, error info:%d.\n", key, (int)ddbResult);
            return CM_ERROR;
        }
        write_runlog(LOG, "not exit res(%s) status, key:\"%s\" in ddb in 1st reform.\n", resName, key);
    }
    
    uint32 tempOfficialId = GetOfficialId();
    if (IsResInstIdValid(tempOfficialId)) {
        if (IsOneResInstWork(resName, tempOfficialId)) {
            snprintf(officialId, MAX_PATH_LEN, "%d", tempOfficialId);
        } else {
            write_runlog(ERROR, "res(%s) inst(%u) has been get out of cluster, can't do lock.\n",
                resName, tempOfficialId);
            return CM_ERROR;
        }
    } else {
        write_runlog(ERROR, "can not get the official id.\n");
        return CM_ERROR;
    }

    if (strlen(lockValue) == 0) {
        status_t st = SetKV2Ddb(key, MAX_PATH_LEN, officialId, MAX_PATH_LEN, NULL);
        if (st != CM_SUCCESS) {
            write_runlog(ERROR, "[CLIENT] failed to set official id for key(%s).\n", key);
            return CM_ERROR;
        }
        write_runlog(LOG, "[CLIENT] official id set for key(%s): %s\n", key, officialId);
    }
    return CM_SUCCESS;
}

static status_t SetNewLockOwner(const char *resName, const char *lockName, uint32 curLockOwner, uint32 resInstId)
{
    char key[MAX_PATH_LEN] = {0};
    GetResLockDdbKey(key, MAX_PATH_LEN, resName, lockName);

    char value[MAX_PATH_LEN] = {0};
    int ret = snprintf_s(value, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%u", resInstId);
    securec_check_intval(ret, (void)ret);

    DrvSetOption opt = {0};
    char preValue[MAX_PATH_LEN] = {0};
    if (curLockOwner != 0) {
        ret = snprintf_s(preValue, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%u", curLockOwner);
        securec_check_intval(ret, (void)ret);
        opt.preValue = preValue;
        opt.len = (uint32)strlen(preValue);
    }
    if (SetKV2Ddb(key, MAX_PATH_LEN, value, MAX_PATH_LEN, &opt) != CM_SUCCESS) {
        write_runlog(ERROR, "[CLIENT] ddb set failed. key=%s, value=%s.\n", key, value);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static status_t DeleteLockKey(const char *resName, const char *lockName)
{
    char key[MAX_PATH_LEN];
    GetResLockDdbKey(key, MAX_PATH_LEN, resName, lockName);

    if (DelKeyInDdb(key, (uint32)strlen(key)) != CM_SUCCESS) {
        write_runlog(ERROR, "[CLIENT] ddb del failed. key=%s.\n", key);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

void ReleaseResLockOwner(const char *resName, uint32 instId)
{
    // get all kv need known kv count, dynamic arrays need to be added.
    const uint32 kvCount = 10;
    DrvKeyValue kvs[kvCount];
    errno_t rc = memset_s(kvs, sizeof(DrvKeyValue) * kvCount, 0, sizeof(DrvKeyValue) * kvCount);
    securec_check_errno(rc, (void)rc);
    char key[MAX_PATH_LEN] = {0};
    int ret = snprintf_s(key, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/CM/LockOwner/%s", pw->pw_name, resName);
    securec_check_intval(ret, (void)ret);
    DDB_RESULT dbResult = SUCCESS_GET_VALUE;
    if (GetAllKVFromDDb(key, MAX_PATH_LEN, kvs, kvCount, &dbResult) != CM_SUCCESS) {
        if (dbResult != CAN_NOT_FIND_THE_KEY) {
            write_runlog(ERROR, "[CLIENT] res(%s) release lock owner failed, get kvs fail.\n", resName);
        }
        return;
    }
    PrintKeyValueMsg(key, kvs, kvCount, DEBUG5);

    for (uint32 i = 0; i < kvCount; ++i) {
        if (kvs[i].key[0] == '\0' || kvs[i].value[0] == '\0') {
            break;
        }
        if ((uint32)CmAtol(kvs[i].value, 0) != instId) {
            continue;
        }
        if (DelKeyInDdb(kvs[i].key, (uint32)strlen(kvs[i].key)) != CM_SUCCESS) {
            write_runlog(ERROR, "[CLIENT] release lock failed. key=%s, value=%s.\n", kvs[i].key, kvs[i].value);
        } else {
            write_runlog(LOG, "[CLIENT] release lock success. key=%s, value=%s.\n", kvs[i].key, kvs[i].value);
        }
    }
}

static bool RealTimeBuildIsOff(const char *resName, const char* lockName, uint32 cmInstId)
{
    if (strcmp(lockName, "dms_reformer_lock") != 0) {
        return false;
    }

    if (g_realtimeBuildStatus == 0) {
        write_runlog(LOG, "skip check as realtimebuild of all nodes is off\n");
        return false;
    }

    uint32 index = 0;
    if (GetGlobalResStatusIndex(resName, index) != CM_SUCCESS) {
        write_runlog(ERROR, "%s, unknown resName(%s).\n", __FUNCTION__, resName);
        return false;
    }

    uint32 nodeId = 0;
    bool found = false;
    CmResStatList *resStat = &g_resStatus[index];
    uint32 realtimeStatusForCmp = 0;
    for (uint32 i = 0; i < resStat->status.instanceCount; ++i) {
        if (resStat->status.resStat[i].cmInstanceId == cmInstId) {
            nodeId = resStat->status.resStat[i].nodeId;
            found = true;
        }
        if (resStat->status.resStat[i].status == 1) {
            realtimeStatusForCmp |= (1U << (resStat->status.resStat[i].nodeId - 1));
        }
    }

    if (realtimeStatusForCmp == (1U << (nodeId - 1))) {
        write_runlog(LOG, "skip check as I'm the only one live node, curStatus:%u, g_realtimeBuildStatus:%u.\n",
            realtimeStatusForCmp, g_realtimeBuildStatus);
        return false;
    }

    write_runlog(LOG, "instid:%u, nodeid:%u, curStatus:%u, g_realtimeBuildStatus:%u.\n", cmInstId, nodeId,
        realtimeStatusForCmp, g_realtimeBuildStatus);

    if (((g_realtimeBuildStatus & realtimeStatusForCmp) == realtimeStatusForCmp) ||
        ((g_realtimeBuildStatus & realtimeStatusForCmp) == 0)) {
        write_runlog(LOG, "skip check as realtimebuild of all nodes is off or on, g_realtimeBuildStatus:%u.\n",
            g_realtimeBuildStatus);
        return false;
    }

    if (!found) {
        write_runlog(ERROR, "%s, skip check as can't get nodeId by instanceId(%d).\n", __FUNCTION__, cmInstId);
        return false;
    }

    return !(g_realtimeBuildStatus & (1U << (nodeId - 1)));
}

static ClientError CmResLock(const CmaToCmsResLock *lockMsg)
{
    if (SetLockOwner4FirstReform() != CM_SUCCESS) {
        write_runlog(LOG, "[%s], can not set lockowner in first reform.\n", __FUNCTION__);
    }
    if (!IsResInstIdValid((int)lockMsg->cmInstId)) {
        write_runlog(ERROR, "[CLIENT] res(%s) (%s)lock new owner (%u) is invalid.\n",
            lockMsg->resName, lockMsg->lockName, lockMsg->cmInstId);
        return CM_RES_CLIENT_CANNOT_DO;
    }
    if (!CanProcessResStatus()) {
        write_runlog(LOG, "[%s], res status list invalid, can't continue.\n", __FUNCTION__);
        return CM_RES_CLIENT_CANNOT_DO;
    }
    if (!IsOneResInstWork(lockMsg->resName, lockMsg->cmInstId)) {
        write_runlog(ERROR, "[CLIENT] res(%s) inst(%u) has been get out of cluster, can't do lock.\n",
            lockMsg->resName, lockMsg->cmInstId);
        return CM_RES_CLIENT_CANNOT_DO;
    }
    uint32 curLockOwner;
    if (GetLockOwner(lockMsg->resName, lockMsg->lockName, curLockOwner) != CM_SUCCESS) {
        write_runlog(LOG, "[CLIENT] get (%s)lock owner failed, res(%s) inst(%u) can't lock.\n",
            lockMsg->lockName, lockMsg->resName, lockMsg->cmInstId);
        return CM_RES_CLIENT_DDB_ERR;
    }

    if (RealTimeBuildIsOff(lockMsg->resName, lockMsg->lockName, lockMsg->cmInstId)) {
        write_runlog(LOG, "[CLIENT] res(%s) (%s)lock owner is inst(%u), inst(%u) can't lock as the realtime build status is off.\n",
            lockMsg->resName, lockMsg->lockName, curLockOwner, lockMsg->cmInstId);
        return CM_RES_CLIENT_CANNOT_DO;
    }

    if (curLockOwner == lockMsg->cmInstId) {
        write_runlog(LOG, "[CLIENT] res(%s) (%s)lock owner(%u) is same with lock candidate, can't lock again.\n",
            lockMsg->resName, lockMsg->lockName, curLockOwner);
        return CM_RES_CLIENT_CANNOT_DO;
    }
    if (curLockOwner != 0) {
        write_runlog(LOG, "[CLIENT] res(%s) (%s)lock owner is inst(%u), inst(%u) can't lock.\n",
            lockMsg->resName, lockMsg->lockName, curLockOwner, lockMsg->cmInstId);
        return CM_RES_CLIENT_CANNOT_DO;
    }
    if (SetNewLockOwner(lockMsg->resName, lockMsg->lockName, curLockOwner, lockMsg->cmInstId) != CM_SUCCESS) {
        write_runlog(ERROR, "[CLIENT] res(%s) instance(%u) (%s)lock failed.\n",
            lockMsg->resName, lockMsg->cmInstId, lockMsg->lockName);
        return CM_RES_CLIENT_DDB_ERR;
    }
    write_runlog(LOG, "[CLIENT] res(%s) instance(%u) (%s)lock success.\n",
        lockMsg->resName, lockMsg->cmInstId, lockMsg->lockName);

    return CM_RES_CLIENT_SUCCESS;
}

static ClientError CmResUnlock(const CmaToCmsResLock *lockMsg)
{
    uint32 curLockOwner = 0;
    if (GetLockOwner(lockMsg->resName, lockMsg->lockName, curLockOwner) != CM_SUCCESS) {
        write_runlog(LOG, "[CLIENT] get cur lock owner failed, res(%s) lockName(%s) inst(%u) can't unlock.\n",
            lockMsg->resName, lockMsg->lockName, lockMsg->cmInstId);
        return CM_RES_CLIENT_DDB_ERR;
    }
    if (curLockOwner == 0) {
        write_runlog(LOG, "[CLIENT] cur lock owner is NULL, res(%s) lockName(%s) inst(%u) can't unlock.\n",
            lockMsg->resName, lockMsg->lockName, lockMsg->cmInstId);
        return CM_RES_CLIENT_CANNOT_DO;
    }
    if (curLockOwner != lockMsg->cmInstId) {
        write_runlog(LOG, "[CLIENT] res(%s) lockName(%s) lock owner is (%u) not inst(%u), can't unlock.\n",
            lockMsg->resName, lockMsg->lockName, curLockOwner, lockMsg->cmInstId);
        return CM_RES_CLIENT_CANNOT_DO;
    }

    if (DeleteLockKey(lockMsg->resName, lockMsg->lockName) != CM_SUCCESS) {
        write_runlog(ERROR, "[CLIENT] res(%s) inst(%u) unlock failed, because ddb del lock owner failed.\n",
            lockMsg->resName, lockMsg->cmInstId);
        return CM_RES_CLIENT_DDB_ERR;
    }
    write_runlog(LOG, "[CLIENT] res(%s) instance(%u) unlock success.\n", lockMsg->resName, lockMsg->cmInstId);

    return CM_RES_CLIENT_SUCCESS;
}

static ClientError ResGetLockOwner(const char *resName, const char *lockName, uint32 &lockOwner)
{
    if (GetLockOwner(resName, lockName, lockOwner) != CM_SUCCESS) {
        write_runlog(LOG, "[CLIENT] get res(%s) (%s)lock owner failed.\n", resName, lockName);
        return CM_RES_CLIENT_DDB_ERR;
    }
    if (lockOwner == 0) {
        write_runlog(LOG, "[CLIENT] get res(%s) (%s)lock no owner.\n", resName, lockName);
        return CM_RES_CLIENT_NO_LOCK_OWNER;
    }

    return CM_RES_CLIENT_SUCCESS;
}

static ClientError TransLockOwner(const CmaToCmsResLock *lockMsg)
{
    const char *resName = lockMsg->resName;
    const char *lockName = lockMsg->lockName;
    uint32 resInstId = lockMsg->cmInstId;
    uint32 newLockOwner = lockMsg->transInstId;
    uint32 curLockOwner = 0;
    if (GetLockOwner(resName, lockName, curLockOwner) != CM_SUCCESS) {
        write_runlog(LOG, "[CLIENT] get (%s)lock owner failed, res(%s) can't trans lock.\n", lockName, resName);
        return CM_RES_CLIENT_DDB_ERR;
    }
    if (curLockOwner != resInstId) {
        write_runlog(LOG, "[CLIENT] res(%s) (%s)lock owner is inst(%u), inst(%u) can't trans lock.\n",
            resName, lockName, curLockOwner, resInstId);
        return CM_RES_CLIENT_CANNOT_DO;
    }

    if (!CanProcessResStatus()) {
        write_runlog(LOG, "[%s], res status list invalid, can't continue.\n", __FUNCTION__);
        return CM_RES_CLIENT_CANNOT_DO;
    }
    if (!IsOneResInstWork(resName, newLockOwner)) {
        write_runlog(LOG, "[CLIENT] res(%s) inst(%u) get out of cluster, can't be lockOwner.\n", resName, newLockOwner);
        return CM_RES_CLIENT_CANNOT_DO;
    }

    if (SetNewLockOwner(resName, lockName, curLockOwner, newLockOwner) != CM_SUCCESS) {
        write_runlog(ERROR, "[CLIENT] res(%s) inst(%u) trans to inst(%u) failed, cause ddb failed.\n",
            resName, resInstId, newLockOwner);
        return CM_RES_CLIENT_DDB_ERR;
    }
    write_runlog(LOG, "[CLIENT] res(%s) inst(%u) trans to inst(%u) success.\n", resName, resInstId, newLockOwner);

    return CM_RES_CLIENT_SUCCESS;
}

void ProcessCmResLock(MsgRecvInfo* recvMsgInfo, CmaToCmsResLock *lockMsg)
{
    lockMsg->resName[CM_MAX_RES_NAME - 1] = '\0';
    lockMsg->lockName[CM_MAX_LOCK_NAME - 1] = '\0';

    CmsReportLockResult ackMsg = {0};
    ackMsg.msgType = (int)MSG_CM_RES_LOCK_ACK;
    ackMsg.conId = lockMsg->conId;
    ackMsg.lockOpt = lockMsg->lockOpt;
    ackMsg.lockOwner = 0;
    errno_t rc = strcpy_s(ackMsg.lockName, CM_MAX_LOCK_NAME, lockMsg->lockName);
    securec_check_errno(rc, (void)rc);

    switch (lockMsg->lockOpt) {
        case (uint32)CM_RES_LOCK: {
            ackMsg.error = (uint32)CmResLock(lockMsg);
            break;
        }
        case (uint32)CM_RES_UNLOCK: {
            ackMsg.error = (uint32)CmResUnlock(lockMsg);
            break;
        }
        case (uint32)CM_RES_GET_LOCK_OWNER: {
            ackMsg.error = (uint32)ResGetLockOwner(lockMsg->resName, lockMsg->lockName, ackMsg.lockOwner);
            break;
        }
        case (uint32)CM_RES_LOCK_TRANS: {
            ackMsg.error = (uint32)TransLockOwner(lockMsg);
            break;
        }
        default: {
            write_runlog(ERROR, "[CLIENT] unknown lockOpt(%u).\n", lockMsg->lockOpt);
            ackMsg.error = (uint32)CM_RES_CLIENT_CANNOT_DO;
            break;
        }
    }

    if (RespondMsg(recvMsgInfo, 'S', (char *)(&ackMsg), sizeof(CmsReportLockResult), DEBUG5) != 0) {
        write_runlog(ERROR, "[CLIENT] send lock ack msg failed.\n");
    }
}

static inline void CopyResStatusToSendMsg(OneResStatList *sendStat, CmResStatList *saveStat)
{
    (void)pthread_rwlock_rdlock(&saveStat->rwlock);
    errno_t rc = memcpy_s(sendStat, sizeof(OneResStatList), &saveStat->status, sizeof(OneResStatList));
    securec_check_errno(rc, (void)rc);
    (void)pthread_rwlock_unlock(&saveStat->rwlock);
}

void ProcessResInstanceStatusMsg(MsgRecvInfo* recvMsgInfo, const CmsToCtlGroupResStatus *queryStatusPtr)
{
    CmsToCtlGroupResStatus instStatMsg = {0};
    instStatMsg.msgType = (int)MSG_CM_QUERY_INSTANCE_STATUS;

    if (queryStatusPtr->msgStep == QUERY_RES_STATUS_STEP) {
        for (uint32 i = 0; i < CusResCount(); ++i) {
            instStatMsg.msgStep = QUERY_RES_STATUS_STEP_ACK;
            CopyResStatusToSendMsg(&instStatMsg.oneResStat, &g_resStatus[i]);
            (void)RespondMsg(recvMsgInfo, 'S', (char*)&(instStatMsg), sizeof(instStatMsg), DEBUG5);
        }

        instStatMsg.msgStep = QUERY_RES_STATUS_STEP_ACK_END;
        (void)RespondMsg(recvMsgInfo, 'S', (char*)&(instStatMsg), sizeof(instStatMsg), DEBUG5);
    }
}

void ProcessQueryOneResInst(MsgRecvInfo* recvMsgInfo, const QueryOneResInstStat *queryMsg)
{
    CmsToCtlOneResInstStat ackMsg = {0};
    ackMsg.msgType = (int)MSG_CM_CTL_QUERY_RES_INST_ACK;

    uint32 destInstId = queryMsg->instId;
    for (uint32 i = 0; i < CusResCount(); ++i) {
        for (uint32 j = 0; j < g_resStatus[i].status.instanceCount; ++j) {
            if (g_resStatus[i].status.resStat[j].cmInstanceId != destInstId) {
                continue;
            }
            (void)pthread_rwlock_rdlock(&g_resStatus[i].rwlock);
            ackMsg.instStat = g_resStatus[i].status.resStat[j];
            int instanceType = g_instance_role_group_ptr[i].instanceMember[j].instanceType;
            if (instanceType == INSTANCE_TYPE_DATANODE && ackMsg.instStat.status == CM_RES_STAT_ONLINE) {
                const cm_instance_report_status *instStatus = &g_instance_group_report_status_ptr[i].instance_status;
                int localStatus = instStatus->data_node_member[j].local_status.db_state;
                int dnLocalRole = instStatus->data_node_member[j].local_status.local_role;
                if ((dnLocalRole != INSTANCE_ROLE_PRIMARY && dnLocalRole != INSTANCE_ROLE_STANDBY &&
                    dnLocalRole != INSTANCE_ROLE_MAIN_STANDBY) || localStatus != INSTANCE_HA_STATE_NORMAL) {
                    ackMsg.instStat.status = CM_RES_STAT_UNKNOWN;
                }
            }
            (void)pthread_rwlock_unlock(&g_resStatus[i].rwlock);
            (void)RespondMsg(recvMsgInfo, 'S', (char*)&(ackMsg), sizeof(ackMsg), DEBUG5);
            return;
        }
    }
    write_runlog(ERROR, "unknown res instId(%u).\n", destInstId);
}

static bool IsregIsNotUnknown(ResInstIsreg *isregList, uint32 isregCount)
{
    for (uint32 i = 0; i < isregCount; ++i) {
        if (!IsRecvIsregStatValid(isregList[i].isreg)) {
            write_runlog(ERROR, "recv inst(%u) isreg stat(%d) invalid.\n", isregList[i].cmInstId, isregList[i].isreg);
            return false;
        }
        if (isregList[i].isreg == (int)CM_RES_ISREG_UNKNOWN) {
            write_runlog(LOG, "recv inst(%u) isreg(%s).\n", isregList[i].cmInstId, GetIsregStatus(isregList[i].isreg));
            return false;
        }
    }
    return true;
}

void ProcessResIsregMsg(MsgRecvInfo *recvMsgInfo, CmaToCmsIsregMsg *isreg)
{
    if (isreg->isregCount > CM_MAX_RES_INST_COUNT) {
        write_runlog(ERROR, "recv isreg list count(%u) invalid, max(%d).\n", isreg->isregCount, CM_MAX_RES_INST_COUNT);
        return;
    }

    bool needUpdateAgentCheckList = false;
    UpdateResIsregStatusList(isreg->nodeId, isreg->isregList, isreg->isregCount, &needUpdateAgentCheckList);

    if (needUpdateAgentCheckList) {
        write_runlog(LOG, "recv check list is not right.\n");
        CmsFlushIsregCheckList sendMsg = {0};
        sendMsg.msgType = (int)MSG_CM_AGENT_ISREG_CHECK_LIST_CHANGED;
        GetCheckListByNodeId(isreg->nodeId, sendMsg.checkList, &sendMsg.checkCount);
        (void)RespondMsg(recvMsgInfo, 'S', (char*)&(sendMsg), sizeof(sendMsg), LOG);
    } else {
        if (IsregIsNotUnknown(isreg->isregList, isreg->isregCount)) {
            CleanReportInter(isreg->nodeId);
        }
    }
}

void ResetResNodeStat()
{
    if (g_resNodeStat == NULL) {
        return;
    }
    for (uint32 i = 0; i < GetResNodeCount(); ++i) {
        g_resNodeStat[i].isAvail = MAX_CLUSTER_STATUS_INIT;
    }
}
