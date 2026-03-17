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
 * cms_arbitrate_synclist.cpp
 *    DN synclist arbitrate
 *
 * IDENTIFICATION
 *    src/cm_server/cms_arbitrate_synclist.cpp
 *
 * -------------------------------------------------------------------------
 */
#include "cm/cm_elog.h"
#include "cms_ddb.h"
#include "cms_az.h"
#include "cms_alarm.h"
#include "cms_process_messages.h"
#include "cms_common.h"

static void SyncCurrentWithExceptSyncList(uint32 groupIndex, bool isCurSameWithExpect);
static bool CompareDnOnlineWithExpectSyncList(const DatanodeDynamicStatus *statusDn, const DatanodeSyncList *syncList);
static int SetCurSyncListStatusValue(uint32 groupIndex, char *value, size_t len);
static void SetInitWaitReduceOrIncreaseTime();
static bool CompareMemberSyncWithExceptSyncList(
    const DatanodeSyncList *memberSyncList, const DatanodeSyncList *expectSyncList);
static bool GetHistoryClusterSyncListFromDdb();
static void DoReduceSyncList(uint32 groupIndex, const CurrentInstanceStatus *statusInstance, int printTime,
    cm_instance_report_status *reportStatus);
static void DoIncreaseSyncList(
    uint32 groupIndex, const CurrentInstanceStatus *statusInstance, cm_instance_report_status *reportStatus);
static bool IsDoReduceOrIncreaseSyncList(uint32 groupIndex, const DatanodeDynamicStatus *statusDnOnline,
    cm_instance_report_status *reportStatus, DatanodeDynamicStatus *historyDnOnline, bool isCurSameWithExpect);
static void PrintLogMsg(uint32 groupIndex, const CurrentInstanceStatus *statusInstance, const char *value);
static void PrintReduceOrIncreaseMsg(uint32 groupIndex, const cm_instance_report_status *reportStatus,
    const char *value, bool isReduce, const CurrentInstanceStatus *statusInstance);
static bool IsDoGsGucFlag(uint32 groupIndex);

const int DELAY_TIME_TO_INCREASE_STANDBY = 300;  // the times to wait for add standby nums
const int DELAY_TIME_TO_REDUCE_STANDBY = 12;     // the times to wait for reduce standby nums
const int ONE_PRIMARY_ONE_SLAVE = 2;
const int SYNC_LIST_TIMES = 1; // the time to wait for do write oper

void GetSyncListString(const DatanodeSyncList *syncList, char *syncListString, size_t maxLen)
{
    errno_t rc = 0;
    size_t strLen = 0;
    if (syncList->count == 0) {
        rc = strcpy_s(syncListString, maxLen, "sync list is empty");
        securec_check_errno(rc, (void)rc);
        return;
    }

    if (maxLen <= 1) {
        write_runlog(ERROR, "maxLen is 1 or 0.\n");
        return;
    }
    for (int index = 0; index < syncList->count; ++index) {
        strLen = strlen(syncListString);
        if (strLen >= (maxLen - 1)) {
            return;
        }
        if (index == syncList->count - 1) {
            rc = snprintf_s(
                syncListString + strLen, maxLen - strLen, (maxLen - strLen) - 1, "%u", syncList->dnSyncList[index]);
        } else {
            rc = snprintf_s(
                syncListString + strLen, maxLen - strLen, (maxLen - strLen) - 1, "%u, ", syncList->dnSyncList[index]);
        }
        securec_check_intval(rc, (void)rc);
    }
}

void GetDnDynamicStatus(uint32 groupIndex, CurrentInstanceStatus *statusInstance, char *value, int32 valueLen)
{
    cm_instance_role_group *dnRoleGroup = &g_instance_role_group_ptr[groupIndex];
    cm_instance_datanode_report_status *dnReport =
        g_instance_group_report_status_ptr[groupIndex].instance_status.data_node_member;
    int32 dnFailCount = 0;
    int32 dnOnlineCount = 0;
    int32 dnPrimaryCount = 0;
    int32 dnVoteAzCount = 0;
    int32 normalPriCount = 0;
    bool result = false;
    for (int32 i = 0; i < dnRoleGroup->count; i++) {
        result = IsCurInstanceInVoteAz(groupIndex, i);
        if (result) {
            if (i < valueLen) {
                value[i] = INSTANCE_DATA_IN_VOTE + '0';
            }
            statusInstance->statusDnVoteAz.dnStatus[dnVoteAzCount++] = dnRoleGroup->instanceMember[i].instanceId;
            continue;
        }
        cm_local_replconninfo *localSta = &(dnReport[i].local_status);
        if (localSta->local_role == INSTANCE_ROLE_UNKNOWN) {
            statusInstance->statusDnFail.dnStatus[dnFailCount++] = dnRoleGroup->instanceMember[i].instanceId;
            if (i < valueLen) {
                value[i] = INSTANCE_DATA_NO_REDUCED + '0';
            }
            continue;
        }
        statusInstance->statusDnOnline.dnStatus[dnOnlineCount++] = dnRoleGroup->instanceMember[i].instanceId;
        if (i < valueLen) {
            value[i] = INSTANCE_DATA_REDUCED + '0';
        }
        if (localSta->local_role == INSTANCE_ROLE_PRIMARY) {
            statusInstance->statusPrimary.dnStatus[dnPrimaryCount++] = dnRoleGroup->instanceMember[i].instanceId;
            // dn primary must be useful
            bool res = (localSta->db_state == INSTANCE_HA_STATE_NORMAL && localSta->term != InvalidTerm);
            if (res) {
                statusInstance->norPrimary.dnStatus[normalPriCount++] = dnRoleGroup->instanceMember[i].instanceId;
            }
        }
    }
    statusInstance->statusDnFail.count = dnFailCount;
    statusInstance->statusDnOnline.count = dnOnlineCount;
    statusInstance->statusPrimary.count = dnPrimaryCount;
    statusInstance->statusDnVoteAz.count = dnVoteAzCount;
    statusInstance->norPrimary.count = normalPriCount;
    write_runlog(DEBUG1, "line %d: instanceId(%u), statusDnOnline=%d, statusDnFail=%d, statusPrimary=%d, "
        "normalPrimary=%d statusDnVoteAz=%d, value=%s.\n",
        __LINE__, dnRoleGroup->instanceMember[0].instanceId, statusInstance->statusDnOnline.count,
        statusInstance->statusDnFail.count, statusInstance->statusPrimary.count, statusInstance->norPrimary.count,
        statusInstance->statusDnVoteAz.count, value);
}

void MemsetDnStatus(CurrentInstanceStatus *statusInstance, char *value, size_t len)
{
    errno_t rc = memset_s(statusInstance, sizeof(CurrentInstanceStatus), 0, sizeof(CurrentInstanceStatus));
    securec_check_errno(rc, (void)rc);
    rc = memset_s(value, len, '\0', len);
    securec_check_errno(rc, (void)rc);
}

bool CompareHistorywithCurrOnline(
    const DatanodeDynamicStatus *statusDnOnline, const DatanodeDynamicStatus *historyDnOnline)
{
    if (statusDnOnline->count != historyDnOnline->count) {
        return false;
    }
    for (int i = 0; i < statusDnOnline->count; ++i) {
        if (statusDnOnline->dnStatus[i] != historyDnOnline->dnStatus[i]) {
            return false;
        }
    }
    return true;
}

bool IsInstanceIdInSyncList(uint32 instanceId, const DatanodeSyncList *syncList)
{
    if (syncList->count == 0) {
        write_runlog(DEBUG1, "The sync list is empty.\n");
        return true;
    }
    for (int i = 0; i < syncList->count; ++i) {
        if (instanceId == syncList->dnSyncList[i]) {
            return true;
        }
    }
    return false;
}

void ReportAlarmSyncList(uint32 groupIndex, bool isIncrease)
{
    DatanodeSyncList *currentSyncList =
        &(g_instance_group_report_status_ptr[groupIndex].instance_status.currentSyncList);
    for (int i = 0; i < currentSyncList->count; ++i) {
        ReportIncreaseOrReduceAlarm(ALM_AT_Event, currentSyncList->dnSyncList[i], isIncrease);
    }
}

static void SyncCurrentWithExceptSyncList(uint32 groupIndex, bool isCurSameWithExpect)
{
    if (isCurSameWithExpect) {
        return;
    }
    errno_t rc = 0;
    char statusKey[MAX_PATH_LEN] = {0};
    char statusValue[MAX_PATH_LEN] = {0};
    bool isIncrease = false;
    uint32 instanceId = g_instance_role_group_ptr[groupIndex].instanceMember[0].instanceId;
    bool hasDoGsGucFlag = IsDoGsGucFlag(groupIndex);
    cm_instance_report_status *reportGrp = &(g_instance_group_report_status_ptr[groupIndex].instance_status);
    if (reportGrp->currentSyncList.count < reportGrp->exceptSyncList.count) {
        isIncrease = true;
    }
    if (hasDoGsGucFlag) {
        reportGrp->waitSyncTime++;
        if (reportGrp->waitSyncTime <= SYNC_LIST_TIMES) {
            write_runlog(LOG, "instd(%u) time is [%d/%d] delay to sync curSyncList.\n",
                instanceId, reportGrp->waitSyncTime, SYNC_LIST_TIMES);
            return;
        }

        // the shard has finish to reduce standby.
        int doResult = SetCurSyncListStatusValue(groupIndex, statusValue, sizeof(statusValue));
        if (doResult == -1) {
            return;
        }
        rc = snprintf_s(statusKey, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/CMServer/DnCurSyncList", pw->pw_name);
        securec_check_intval(rc, (void)rc);
        status_t st = SetKV2Ddb(statusKey, MAX_PATH_LEN, statusValue, MAX_PATH_LEN, NULL);
        if (st != CM_SUCCESS) {
            write_runlog(ERROR, "%u:ddb set failed. key=%s,value=%s.\n", instanceId, statusKey, statusValue);
            return;
        }
        write_runlog(LOG, "%u: ddb set status DnCurSyncList success, key=%s, value=%s.\n", instanceId, statusKey,
            statusValue);
        // copy the exceptsynclist to currentSyncList.
        rc = memcpy_s(&(reportGrp->currentSyncList), sizeof(DatanodeSyncList), &(reportGrp->exceptSyncList),
            sizeof(DatanodeSyncList));
        securec_check_errno(rc, (void)rc);
        current_cluster_az_status = AnyFirstNo;
        ReportAlarmSyncList(groupIndex, isIncrease);
        reportGrp->waitSyncTime = 0;
    }
}

static bool PrimaryDnSyncDone(uint32 groupIdx, int32 memIdx)
{
    cm_instance_datanode_report_status *dnReport =
        &(g_instance_group_report_status_ptr[groupIdx].instance_status.data_node_member[memIdx]);
    if (dnReport->local_status.local_role != INSTANCE_ROLE_PRIMARY) {
        return true;
    }
    uint32 instId = g_instance_role_group_ptr[groupIdx].instanceMember[memIdx].instanceId;
    if (dnReport->syncDone == SUCCESS_SYNC_DATA) {
        write_runlog(LOG, "dn primary instance %u, it has finished sync.\n", instId);
        return true;
    }
    static int32 times = 0;
    const int32 printLogTimes = 20;
    if (times >= printLogTimes || log_min_messages <= DEBUG1) {
        write_runlog(LOG, "dn primary instance %u, it has not finished sync yet.\n", instId);
        times = 0;
    }
    ++times;
    return false;
}

static bool IsDoGsGucFlag(uint32 groupIndex)
{
    char doGsGuc[MAX_PATH_LEN] = {0};
    char expectSyncListStr[MAX_PATH_LEN] = {0};
    bool hasDoGsGucFlag = true;
    for (int32 i = 0; i < g_instance_role_group_ptr[groupIndex].count; ++i) {
        if (!PrimaryDnSyncDone(groupIndex, i)) {
            return false;
        }
        if (CompareMemberSyncWithExceptSyncList(
            &(g_instance_group_report_status_ptr[groupIndex].instance_status.data_node_member[i].dnSyncList),
            &(g_instance_group_report_status_ptr[groupIndex].instance_status.exceptSyncList))) {
            doGsGuc[i] = '1';
            continue;
        }
        doGsGuc[i] = '0';
        if (!IsInstanceIdInSyncList(g_instance_role_group_ptr[groupIndex].instanceMember[i].instanceId,
            &(g_instance_group_report_status_ptr[groupIndex].instance_status.exceptSyncList))) {
            continue;
        }
        hasDoGsGucFlag = false;
        break;
    }
    GetSyncListString(&(g_instance_group_report_status_ptr[groupIndex].instance_status.exceptSyncList),
        expectSyncListStr, sizeof(expectSyncListStr));
    write_runlog(LOG, "instanceId(%u) doGsGuc is [%s], expectSyncList is [%s].\n",
        g_instance_role_group_ptr[groupIndex].instanceMember[0].instanceId, doGsGuc, expectSyncListStr);
    return hasDoGsGucFlag;
}

static bool CompareDnOnlineWithExpectSyncList(const DatanodeDynamicStatus *statusDn, const DatanodeSyncList *syncList)
{
    if (statusDn->count != syncList->count) {
        return false;
    }
    for (int i = 0; i < statusDn->count; ++i) {
        if (statusDn->dnStatus[i] != syncList->dnSyncList[i]) {
            return false;
        }
    }
    return true;
}

static int SetCurSyncListStatusValue(uint32 groupIndex, char *value, size_t len)
{
    // the first datanode instanceId
    uint32 instanceId = 6001;
    uint32 curInstanceId = g_instance_role_group_ptr[groupIndex].instanceMember[0].instanceId;
    uint32 tempInstanceId = 0;
    errno_t rc = memset_s(value, len, '0', len - 1);
    securec_check_errno(rc, (void)rc);
    value[len - 1] = '\0';
    for (uint32 i = 0; i < g_dynamic_header->relationCount; ++i) {
        if (g_instance_role_group_ptr[i].instanceMember[0].instanceType != INSTANCE_TYPE_DATANODE) {
            continue;
        }
        tempInstanceId = g_instance_role_group_ptr[i].instanceMember[0].instanceId;
        cm_instance_report_status *reportStatus = &(g_instance_group_report_status_ptr[i].instance_status);
        if (groupIndex == i) {
            if (reportStatus->exceptSyncList.count <= 0) {
                write_runlog(ERROR, "line %d: curInstanceId(%u), instanceId(%u) expectSyncList is empty, cannot set "
                    "currentSyncList.\n", __LINE__, curInstanceId, tempInstanceId);
                return -1;
            }
            // sync the except sync list to ddb.
            for (int index = 0; index < reportStatus->exceptSyncList.count; ++index) {
                value[reportStatus->exceptSyncList.dnSyncList[index] - instanceId] = INSTANCE_DATA_REDUCED + '0';
            }
            for (int j = 0; j < reportStatus->voteAzInstance.count; ++j) {
                value[reportStatus->voteAzInstance.dnStatus[j] - instanceId] = INSTANCE_DATA_IN_VOTE + '0';
            }
        } else {
            if (reportStatus->currentSyncList.count <= 0) {
                write_runlog(ERROR, "line %d: curInstanceId(%u), instanceId(%u) currentSyncList is empty, cannot set "
                    "currentSyncList.\n", __LINE__, curInstanceId, tempInstanceId);
                return -1;
            }
            for (int index = 0; index < reportStatus->currentSyncList.count; ++index) {
                value[reportStatus->currentSyncList.dnSyncList[index] - instanceId] = INSTANCE_DATA_REDUCED + '0';
            }
            for (int j = 0; j < reportStatus->voteAzInstance.count; ++j) {
                value[reportStatus->voteAzInstance.dnStatus[j] - instanceId] = INSTANCE_DATA_IN_VOTE + '0';
            }
        }
    }
    return 0;
}

static void SetInitWaitReduceOrIncreaseTime()
{
    for (uint32 i = 0; i < g_dynamic_header->relationCount; ++i) {
        if (g_instance_role_group_ptr[i].instanceMember[0].instanceType != INSTANCE_TYPE_DATANODE) {
            continue;
        }
        g_instance_group_report_status_ptr[i].instance_status.waitReduceTimes = DELAY_TIME_TO_REDUCE_STANDBY;
        g_instance_group_report_status_ptr[i].instance_status.waitIncreaseTimes = DELAY_TIME_TO_INCREASE_STANDBY;
    }
}

void ComputeTimeForArbitrate(struct timeval checkBegin, struct timeval checkEnd, int *printTime)
{
    int arbitrateTime = 2;
    // 1s = 1000000us
    uint32 sleepInterval = 1000000;
    (void)gettimeofday(&checkEnd, NULL);
    ++(*printTime);
    if (*printTime > MAX_VALUE_OF_PRINT) {
        *printTime = 0;
    }
    uint32 usedTime = (uint32)GetTimeMinus(checkEnd, checkBegin);
    if ((checkEnd.tv_sec - checkBegin.tv_sec) > arbitrateTime) {
        write_runlog(LOG, "it take %u us for group arbitrate.\n", usedTime);
    }
    if (sleepInterval > usedTime) {
        CmUsleep(sleepInterval - usedTime);
    }
}

static void UpdateSyncListStat(maintenance_mode upgradeMode)
{
    if (upgradeMode != MAINTENANCE_MODE_NONE) {
        g_isEnableUpdateSyncList = SYNCLIST_THREADS_IN_MAINTENANCE;
        return;
    }
    if (!IsDdbHealth(DDB_PRE_CONN)) {
        g_isEnableUpdateSyncList = SYNCLIST_THREADS_IN_DDB_BAD;
        return;
    }
    g_isEnableUpdateSyncList = SYNCLIST_THREADS_IN_SLEEP;
}

static bool IsSyncListNumZero()
{
    for (uint32 i = 0; i < g_dynamic_header->relationCount; ++i) {
        if (g_instance_role_group_ptr[i].instanceMember[0].instanceType != INSTANCE_TYPE_DATANODE) {
            continue;
        }
        if (g_instance_group_report_status_ptr[i].instance_status.currentSyncList.count <= 0 ||
            g_instance_group_report_status_ptr[i].instance_status.exceptSyncList.count <= 0) {
            write_runlog(LOG, "group(%u) curr sync list num is %d, except sync list num is %d.\n",
                i, g_instance_group_report_status_ptr[i].instance_status.currentSyncList.count,
                g_instance_group_report_status_ptr[i].instance_status.exceptSyncList.count);
            return true;
        }
    }
    return false;
}

static void GetHistoryClusterSyncListWhenEmptySyncList()
{
    static int32 cmsRole = CM_SERVER_UNKNOWN;
    if (cmsRole == g_HA_status->local_role) {
        if (cmsRole != CM_SERVER_PRIMARY) {
            return;
        }
    } else {
        write_runlog(LOG, "last cmsRole is %d, and current cms role is %d.\n", cmsRole, g_HA_status->local_role);
    }
    cmsRole =  g_HA_status->local_role;
    if (cmsRole != CM_SERVER_PRIMARY) {
        return;
    }
    if (IsSyncListNumZero()) {
        if (!GetHistoryClusterSyncListFromDdb()) {
            write_runlog(LOG, "cannot get history syncList, and change cmsRole to %d.\n", CM_SERVER_UNKNOWN);
            cmsRole = CM_SERVER_UNKNOWN;
        }
    }
    return;
}

static bool CheckDnPendingCmd(uint32 groupIdx)
{
    cm_instance_command_status *cmd = g_instance_group_report_status_ptr[groupIdx].instance_status.command_member;
    for (int32 i = 0; i < g_instance_role_group_ptr[groupIdx].count; ++i) {
        if (cmd[i].pengding_command == (int32)MSG_CM_AGENT_SWITCHOVER) {
            write_runlog(LOG, "instd(%u) is doing(%d: %d), cannot modify synclist.\n",
                GetInstanceIdInGroup(groupIdx, i), cmd[i].command_status, cmd[i].pengding_command);
            return false;
        }
    }
    return true;
}

static bool CheckCurDnModifySyncList(uint32 groupIdx, const CurrentInstanceStatus *statusInstance, const char *value)
{
    // every shard only has one primary dn
    const int dnPrimaryNum = 1;
    if (statusInstance->statusPrimary.count != dnPrimaryNum || (statusInstance->norPrimary.count != dnPrimaryNum) ||
        (statusInstance->statusDnOnline.count + statusInstance->statusDnFail.count !=
        (g_instance_role_group_ptr[groupIdx].count - statusInstance->statusDnVoteAz.count))) {
        write_runlog(ERROR, "instanceId(%u), primary count is (%d: %d), statusDnOnline is %d, statusDnFail is %d, "
            "value is %s, can not arbitrate.\n", GetInstanceIdInGroup(groupIdx, 0), statusInstance->statusPrimary.count,
            statusInstance->norPrimary.count,  statusInstance->statusDnOnline.count, statusInstance->statusDnFail.count,
            value);
        return false;
    }
    return CheckDnPendingCmd(groupIdx);
}

void *DnGroupStatusCheckAndArbitrateMain(void *arg)
{
    uint32 sleepInterval = 1;
    thread_name = "GpArbitrate";
    bool hasHistory = false;
    // record last status
    DatanodeDynamicStatus *historyDnOnline =
        (DatanodeDynamicStatus *)malloc(sizeof(DatanodeDynamicStatus) * MAX_INSTANCE_NUM);
    if (historyDnOnline == NULL) {
        write_runlog(FATAL, "Out of memory: historyDnOnline failed.\n");
        g_isEnableUpdateSyncList = CANNOT_START_SYNCLIST_THREADS;
        FreeNotifyMsg();
        exit(-1);
    }
    errno_t rc = memset_s(historyDnOnline, sizeof(DatanodeDynamicStatus) * MAX_INSTANCE_NUM, 0,
        sizeof(DatanodeDynamicStatus) * MAX_INSTANCE_NUM);
    securec_check_errno(rc, (void)rc);
    CurrentInstanceStatus statusInstance = {{0}};
    char value[DDB_MIN_VALUE_LEN] = {0};
    SetInitWaitReduceOrIncreaseTime();
    struct timeval checkBegin = {0, 0};
    struct timeval checkEnd = {0, 0};
    bool isResult = false;
    int printTime = 0;
    bool isCurSameWithExpect = false;
    int logLevel = 0;
    bool isNeedReduce = false;
    bool isNeedIncrease = false;
    int count = 0;
    CmsArbitrateStatus cmsSt = {false, CM_SERVER_UNKNOWN, MAINTENANCE_MODE_NONE};
    for (;;) {
        (void)gettimeofday(&checkBegin, NULL);
        if (got_stop == 1) {
            write_runlog(LOG, "receive exit request in DnGroupStatusCheckAndArbitrateMain.\n");
            cm_sleep(sleepInterval);
            continue;
        }
        if (CmsCanArbitrate(&cmsSt, "[DnGroupStatusCheckAndArbitrateMain]") != CM_SUCCESS) {
            hasHistory = false;
            logLevel = (g_HA_status->local_role != CM_SERVER_PRIMARY) ? DEBUG1 : LOG;
            write_runlog(logLevel, "cannot arbitrate reduce or increase, in the condition that ddb is health is %d "
                "or upgradeMode is %u.\n", cmsSt.isDdbHealth, (uint32)cmsSt.upgradeMode);
            UpdateSyncListStat(cmsSt.upgradeMode);
            GetHistoryClusterSyncListWhenEmptySyncList();
            cm_sleep(sleepInterval);
            continue;
        }
        g_isEnableUpdateSyncList = SYNCLIST_THREADS_IN_PROCESS;
        if (!hasHistory) {
            if (!GetHistoryClusterSyncListFromDdb()) {
                cm_sleep(sleepInterval);
                continue;
            }
            hasHistory = true;
        }
        for (uint32 groupIndex = 0; groupIndex < g_dynamic_header->relationCount; ++groupIndex) {
            if (g_instance_role_group_ptr[groupIndex].instanceMember[0].instanceType != INSTANCE_TYPE_DATANODE) {
                continue;
            }
            cm_instance_report_status *reportStatus = &g_instance_group_report_status_ptr[groupIndex].instance_status;
            // memset statusDnOnline, statusDnFail, statusPrimary, and value
            MemsetDnStatus(&statusInstance, value, DDB_MIN_VALUE_LEN);
            // get datanode report status.
            GetDnDynamicStatus(groupIndex, &statusInstance, value, DDB_MIN_VALUE_LEN);

            if (!CheckCurDnModifySyncList(groupIndex, &statusInstance, value)) {
                continue;
            }
            // compare current synclist with except sync list.
            isCurSameWithExpect = CompareCurWithExceptSyncList(groupIndex);
            SyncCurrentWithExceptSyncList(groupIndex, isCurSameWithExpect);
            PrintLogMsg(groupIndex, &statusInstance, value);
            isResult = IsDoReduceOrIncreaseSyncList(groupIndex, &(statusInstance.statusDnOnline), reportStatus,
                historyDnOnline, isCurSameWithExpect);
            if (!isResult) {
                continue;
            }

            count = (g_instance_role_group_ptr[groupIndex].count - statusInstance.statusDnVoteAz.count) / 2;
            // the process that reduce synchronized standby nodes, and only all syncList can do this.
            // only statusDnonline all are in curSyncList, and then do reduce synchronized standby nodes
            isNeedReduce = statusInstance.statusDnOnline.count <= reportStatus->currentSyncList.count &&
                statusInstance.statusDnOnline.count <= count;
            if (isNeedReduce) {
                PrintReduceOrIncreaseMsg(groupIndex, reportStatus, value, true, &statusInstance);
                DoReduceSyncList(groupIndex, &statusInstance, printTime, reportStatus);
                continue;
            }
            // the process is add synchronized standby nodes
            isNeedIncrease = statusInstance.statusDnOnline.count > reportStatus->currentSyncList.count &&
                statusInstance.statusDnOnline.count >= count;
            if (isNeedIncrease) {
                PrintReduceOrIncreaseMsg(groupIndex, reportStatus, value, false, &statusInstance);
                DoIncreaseSyncList(groupIndex, &statusInstance, reportStatus);
            }
        }
        ComputeTimeForArbitrate(checkBegin, checkEnd, &printTime);
    }
    FREE_AND_RESET(historyDnOnline);
    return NULL;
}

static void PrintReduceOrIncreaseMsg(uint32 groupIndex, const cm_instance_report_status *reportStatus,
    const char *value, bool isReduce, const CurrentInstanceStatus *statusInstance)
{
    char curSyncListStr[MAX_PATH_LEN] = {0};
    char expectSyncListStr[MAX_PATH_LEN] = {0};
    char onlineStr[MAX_PATH_LEN] = {0};
    char primaryStr[MAX_PATH_LEN] = {0};
    char failStr[MAX_PATH_LEN] = {0};
    char voteAzStr[MAX_PATH_LEN] = {0};
    // covert the sync list to String.
    GetSyncListString(&(reportStatus->currentSyncList), curSyncListStr, sizeof(curSyncListStr));
    GetSyncListString(&(reportStatus->exceptSyncList), expectSyncListStr, sizeof(expectSyncListStr));
    GetDnStatusString(&(statusInstance->statusDnOnline), onlineStr, sizeof(onlineStr));
    GetDnStatusString(&(statusInstance->statusPrimary), primaryStr, sizeof(primaryStr));
    GetDnStatusString(&(statusInstance->statusDnFail), failStr, sizeof(failStr));
    GetDnStatusString(&(statusInstance->statusDnVoteAz), voteAzStr, sizeof(voteAzStr));
    if (isReduce) {
        write_runlog(LOG,
            "instanceId(%u) begin to reduce sync list, primary is [%s], online is [%s], fail is [%s], voteAz is [%s], "
            "value is [%s], currentSyncList is [%s], exceptSyncList is [%s], time is %d.\n",
            g_instance_role_group_ptr[groupIndex].instanceMember[0].instanceId, primaryStr, onlineStr, failStr,
            voteAzStr, value, curSyncListStr, expectSyncListStr, reportStatus->waitReduceTimes);
    } else {
        write_runlog(LOG,
            "instanceId(%u) begin to increase sync list, primary is [%s], online is [%s], fail is [%s], voteAz is [%s],"
            " value is [%s], currentSyncList is [%s], exceptSyncList is [%s], time is %d.\n",
            g_instance_role_group_ptr[groupIndex].instanceMember[0].instanceId, primaryStr, onlineStr, failStr,
            voteAzStr, value, curSyncListStr, expectSyncListStr, reportStatus->waitIncreaseTimes);
    }
}

static void PrintLogMsg(uint32 groupIndex, const CurrentInstanceStatus *statusInstance, const char *value)
{
    if (log_min_messages > DEBUG1) {
        return;
    }
    cm_instance_report_status *reportStatus = &g_instance_group_report_status_ptr[groupIndex].instance_status;
    char curSyncListStr[MAX_PATH_LEN] = {0};
    char expectSyncListStr[MAX_PATH_LEN] = {0};
    char onlineStr[MAX_PATH_LEN] = {0};
    char primaryStr[MAX_PATH_LEN] = {0};
    char failStr[MAX_PATH_LEN] = {0};
    char voteAzStr[MAX_PATH_LEN] = {0};
    // covert the sync list to String.
    GetSyncListString(&(reportStatus->currentSyncList), curSyncListStr, sizeof(curSyncListStr));
    GetSyncListString(&(reportStatus->exceptSyncList), expectSyncListStr, sizeof(expectSyncListStr));
    GetDnStatusString(&(statusInstance->statusDnOnline), onlineStr, sizeof(onlineStr));
    GetDnStatusString(&(statusInstance->statusPrimary), primaryStr, sizeof(primaryStr));
    GetDnStatusString(&(statusInstance->statusDnFail), failStr, sizeof(failStr));
    GetDnStatusString(&(statusInstance->statusDnVoteAz), voteAzStr, sizeof(voteAzStr));
    write_runlog(DEBUG1,
        "line %d: instanceId(%u), primary is [%s], online is [%s], fail is [%s], voteAz is [%s], "
        "value is [%s], currentSyncList is [%s], exceptSyncList is [%s].\n",
        __LINE__, g_instance_role_group_ptr[groupIndex].instanceMember[0].instanceId,
        primaryStr, onlineStr, failStr, voteAzStr, value, curSyncListStr, expectSyncListStr);
}

bool IsDnSyncListVaild(uint32 groupIndex, uint32 *instanceId)
{
    if (g_isEnableUpdateSyncList == CANNOT_START_SYNCLIST_THREADS) {
        return true;
    }
    for (int i = 0; i < g_instance_role_group_ptr[groupIndex].count; ++i) {
        if (g_instance_group_report_status_ptr[groupIndex].instance_status.data_node_member[i].dnSyncList.count == -1) {
            if (instanceId != NULL) {
                *instanceId = g_instance_role_group_ptr[groupIndex].instanceMember[i].instanceId;
            }
            return false;
        }
    }
    return true;
}

void GetDnStatusString(const DatanodeDynamicStatus *dnDynamicStatus, char *dnStatusStr, size_t maxLen)
{
    errno_t rc = 0;
    size_t strLen = 0;
    if (maxLen < 1) {
        return;
    }
    if (dnDynamicStatus->count == 0) {
        rc = strcpy_s(dnStatusStr, maxLen, "dynamic status is empty");
        securec_check_errno(rc, (void)rc);
        return;
    }

    for (int index = 0; index < dnDynamicStatus->count; ++index) {
        strLen = strlen(dnStatusStr);
        if (strLen >= (maxLen - 1)) {
            return;
        }
        if (index == dnDynamicStatus->count - 1) {
            rc = snprintf_s(
                dnStatusStr + strLen, maxLen - strLen, (maxLen - strLen) - 1, "%u", dnDynamicStatus->dnStatus[index]);
        } else {
            rc = snprintf_s(dnStatusStr + strLen,
                maxLen - strLen, (maxLen - strLen) - 1, "%u, ", dnDynamicStatus->dnStatus[index]);
        }
        securec_check_intval(rc, (void)rc);
    }
}

static bool IsDoReduceOrIncreaseSyncList(uint32 groupIndex, const DatanodeDynamicStatus *statusDnOnline,
    cm_instance_report_status *reportStatus, DatanodeDynamicStatus *historyDnOnline, bool isCurSameWithExpect)
{
    errno_t rc = 0;
    uint32 instanceId = 0;
    // when current sync list is different from expect sync list, wait for the last oper has finished.
    if (!isCurSameWithExpect) {
        return false;
    }
    // when online dn is same with expect sync list, not need to do reduce or increase standby.
    if (CompareDnOnlineWithExpectSyncList(statusDnOnline, &(reportStatus->exceptSyncList))) {
        return false;
    }
    // if the status keeps changing, cannot to do reduce or increase standby.
    if (!CompareHistorywithCurrOnline(statusDnOnline, &(historyDnOnline[groupIndex]))) {
        char onlineStr[MAX_PATH_LEN] = {0};
        char historyStr[MAX_PATH_LEN] = {0};
        GetDnStatusString(statusDnOnline, onlineStr, sizeof(onlineStr));
        GetDnStatusString(&(historyDnOnline[groupIndex]), historyStr, sizeof(historyStr));
        write_runlog(LOG, "instanceId(%u): statusDnOnline[%s] is different from historyDnOnline[%s], "
            "and reset the time.\n", g_instance_role_group_ptr[groupIndex].instanceMember[0].instanceId,
            onlineStr, historyStr);
        rc = memcpy_s(&(historyDnOnline[groupIndex]), sizeof(DatanodeDynamicStatus),
            statusDnOnline, sizeof(DatanodeDynamicStatus));
        securec_check_errno(rc, (void)rc);
        reportStatus->waitReduceTimes = DELAY_TIME_TO_REDUCE_STANDBY;
        reportStatus->waitIncreaseTimes = DELAY_TIME_TO_INCREASE_STANDBY;
        return false;
    }
    // if the dn in this group synclist is invalid, cannot do reduce or increase
    if (!IsDnSyncListVaild(groupIndex, &instanceId)) {
        write_runlog(ERROR, "syncList in instanceId(%u) is invalid, can't do reduce or increase operf.\n", instanceId);
        return false;
    }
    return true;
}

static void DoIncreaseSyncList(
    uint32 groupIndex, const CurrentInstanceStatus *statusInstance, cm_instance_report_status *reportStatus)
{
    if ((reportStatus->waitIncreaseTimes--) > 0) {
        return;
    }
    bool doResult = SetGroupExpectSyncList(groupIndex, statusInstance);
    if (doResult) {
        reportStatus->waitIncreaseTimes = DELAY_TIME_TO_INCREASE_STANDBY;
    }
}

static void DoReduceSyncList(uint32 groupIndex, const CurrentInstanceStatus *statusInstance, int printTime,
    cm_instance_report_status *reportStatus)
{
    if (statusInstance->statusDnOnline.count < ONE_PRIMARY_ONE_SLAVE) {
        if (printTime % 10 == 0) {
            write_runlog(ERROR,
                "dn instance online count(%d) less than one primary one slave, cannot to do reduce.\n",
                statusInstance->statusDnOnline.count);
        }
        return;
    }

    if ((reportStatus->waitReduceTimes--) > 0) {
        return;
    }
    bool doResult = SetGroupExpectSyncList(groupIndex, statusInstance);
    if (doResult) {
        reportStatus->waitReduceTimes = DELAY_TIME_TO_REDUCE_STANDBY;
    }
}

static bool GetHistoryClusterSyncListFromDdb()
{
    // get history currnet synlist from ddb
    if (GetHistoryClusterCurSyncListFromDdb() == FAILED_GET_VALUE) {
        write_runlog(LOG, "can't get the value from ddb.\n");
        return false;
    }
    // get history except synlist from ddb
    if (GetHistoryClusterExceptSyncListFromDdb() == FAILED_GET_VALUE) {
        write_runlog(LOG, "can't get the value from ddb.\n");
        return false;
    }
    return true;
}

bool CompareCurWithExceptSyncList(uint32 groupIndex)
{
    cm_instance_report_status *dnReportStatus = &g_instance_group_report_status_ptr[groupIndex].instance_status;
    if (dnReportStatus->currentSyncList.count != dnReportStatus->exceptSyncList.count) {
        return false;
    }
    for (int i = 0; i < dnReportStatus->currentSyncList.count; ++i) {
        if (dnReportStatus->currentSyncList.dnSyncList[i] != dnReportStatus->exceptSyncList.dnSyncList[i]) {
            return false;
        }
    }
    return true;
}

static bool CompareMemberSyncWithExceptSyncList(const DatanodeSyncList *memberSyncList,
    const DatanodeSyncList *expectSyncList)
{
    if (memberSyncList->count != expectSyncList->count) {
        return false;
    }
    for (int i = 0; i < memberSyncList->count; ++i) {
        if (memberSyncList->dnSyncList[i] != expectSyncList->dnSyncList[i]) {
            return false;
        }
    }
    return true;
}
