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
 * cms_barrier_check.cpp
 *    barries functions
 *
 * IDENTIFICATION
 *    src/cm_server/cms_barrier_check.cpp
 *
 * -------------------------------------------------------------------------
 */
#include "cm/elog.h"
#include "cms_alarm.h"
#include "cms_global_params.h"
#include "cms_ddb_adapter.h"
#include "cms_barrier_check.h"

#define IS_MAJORITY(sum, alive) (((sum) != 0) && (2 * (alive) > (sum)))
#define HALF_COUNT(count) ((count) / 2)
static uint32 g_cnMajorityNum;
static uint32 g_cnCount;
static struct timespec g_lastTime;
static struct timespec g_curTime;

static bool IsRoleCnAlive(const cm_instance_report_status *instanceStatus)
{
    if (instanceStatus->coordinatemember.status.status != INSTANCE_ROLE_NORMAL) {
        return false;
    }
    if (instanceStatus->coordinatemember.status.db_state == INSTANCE_HA_STATE_NORMAL) {
        return true;
    } else if (instanceStatus->coordinatemember.status.db_state == INSTANCE_HA_STATE_NEED_REPAIR &&
        (instanceStatus->coordinatemember.buildReason == INSTANCE_HA_DATANODE_BUILD_REASON_DISCONNECT ||
        instanceStatus->coordinatemember.buildReason == INSTANCE_HA_DATANODE_BUILD_REASON_CONNECTING)) {
        return true;
    } else if (instanceStatus->coordinatemember.status.db_state == INSTANCE_HA_STATE_WAITING) {
        return true;
    } else {
        return false;
    }
}

static bool IsRoleDnAlive(const cm_local_replconninfo *localStatus)
{
    if (localStatus->local_role != INSTANCE_ROLE_PRIMARY &&
        localStatus->local_role != INSTANCE_ROLE_STANDBY) {
        return false;
    }
    if (localStatus->db_state == INSTANCE_HA_STATE_NORMAL || localStatus->db_state == INSTANCE_HA_STATE_CATCH_UP) {
        return true;
    } else if (localStatus->db_state == INSTANCE_HA_STATE_NEED_REPAIR &&
        (localStatus->buildReason == INSTANCE_HA_DATANODE_BUILD_REASON_DISCONNECT ||
        localStatus->buildReason == INSTANCE_HA_DATANODE_BUILD_REASON_CONNECTING)) {
        return true;
    } else {
        return false;
    }
}

static void InitCnMajorityNum(void)
{
    g_cnCount = 0;
    (void)clock_gettime(CLOCK_MONOTONIC, &g_lastTime);
    for (uint32 i = 0; i < g_dynamic_header->relationCount; i++) {
        if (g_instance_role_group_ptr[i].instanceMember[0].instanceType == INSTANCE_TYPE_COORDINATE) {
            g_cnCount++;
        }
    }
    g_cnMajorityNum = HALF_COUNT(g_cnCount) + 1;
}

static inline void IncreaseCnMajorityNum(void)
{
    /* maximum number of cnMajorityNum is (cnCount/2)+1 */
    if (g_cnMajorityNum < (HALF_COUNT(g_cnCount) + 1)) {
        g_cnMajorityNum++;
        write_runlog(LOG, "[IncreaseCnMajorityNum] cn barrier majority num = %u\n", g_cnMajorityNum);
    }
}

static void DecreaseCnMajorityNum(void)
{
    const long oneMinute = 60;
    (void)clock_gettime(CLOCK_MONOTONIC, &g_curTime);
    long cnMajFailedTime = (g_curTime.tv_sec - g_lastTime.tv_sec);
    if (cnMajFailedTime >= oneMinute) {
        /* Minimum number of cnMajorityNum is 1 */
        if (g_cnMajorityNum > 1) {
            g_cnMajorityNum--;
            write_runlog(LOG, "[DecreaseCnMajorityNum] cn barrier majority num = %u\n", g_cnMajorityNum);
        }
        (void)clock_gettime(CLOCK_MONOTONIC, &g_lastTime);
    }
}

static bool IsCnMajority(uint32 barrierExistCnCount)
{
    if (barrierExistCnCount >= g_cnMajorityNum) {
        if (barrierExistCnCount > g_cnMajorityNum) {
            IncreaseCnMajorityNum();
        }
        (void)clock_gettime(CLOCK_MONOTONIC, &g_lastTime);
        return true;
    } else {
        DecreaseCnMajorityNum();
        return false;
    }
}

static bool IsDnMajority(uint32 barrierExistDnCount)
{
    const uint32 twoReplication = 2;
    if (g_dn_replication_num == twoReplication) {
        return (barrierExistDnCount >= 1);
    }
    return (IS_MAJORITY(g_dn_replication_num, barrierExistDnCount));
}

static status_t RefreshQueryBarrierToDdb(char *minBarrier, uint32 barrierLen)
{
    char key[MAX_PATH_LEN] = {0};
    errno_t rc = snprintf_s(key, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/barrier/query_barrier", pw->pw_name);
    securec_check_intval(rc, (void)rc);
    status_t st = SetKV2Ddb(key, MAX_PATH_LEN, minBarrier, barrierLen, NULL);
    if (st != CM_SUCCESS) {
        write_runlog(ERROR, "[RefreshQueryBarrierToDdb] ddb set failed. key=%s,value=%s.\n", key, minBarrier);
    }
    return st;
}

static void GlobalQueryBarrierRefresh(char *minBarrier, uint32 barrierLen)
{
    status_t st = RefreshQueryBarrierToDdb(minBarrier, barrierLen);
    if (st != CM_SUCCESS) {
        write_runlog(ERROR, "Refresh query barrier failed, value is %s\n", minBarrier);
        return;
    }
    errno_t rc = memcpy_s(g_queryBarrier, barrierLen - 1, minBarrier, barrierLen - 1);
    securec_check_errno(rc, (void)rc);
    write_runlog(LOG, "Refresh query barrier success, value is %s\n", g_queryBarrier);
}

static inline void GlobalTargetBarrierRefresh(const char *queryBarrier, uint32 barrierLen)
{
    errno_t rc;
    /* set target value */
    rc = memcpy_s(g_targetBarrier, barrierLen - 1, queryBarrier, barrierLen - 1);
    securec_check_errno(rc, (void)rc);
    write_runlog(LOG, "set target barrier value is %s\n", g_targetBarrier);
}

static void GetMinBarrierID(char *minBarrier, const char* instanceBarrierID, uint32 barrierLen, uint32 instanceId)
{
    errno_t rc;
    if (strlen(minBarrier) == 0) {
        rc = memcpy_s(minBarrier, barrierLen - 1, instanceBarrierID, barrierLen - 1);
        securec_check_intval(rc, (void)rc);
    } else {
        if (strncmp(instanceBarrierID, minBarrier, barrierLen - 1) < 0) {
            rc = memcpy_s(minBarrier, barrierLen - 1, instanceBarrierID, barrierLen - 1);
            securec_check_intval(rc, (void)rc);
        }
    }
    write_runlog(LOG, "GetMinBarrierID instanceId:%u minBarrierID:%s, instanceBarrierID:%s\n",
        instanceId, minBarrier, instanceBarrierID);
}

static void CalcMinBarrier(char *minBarrier, uint32 barrierLen)
{
    char tmpMinBarrier[BARRIERLEN] = {0};
    for (uint32 i = 0; i < g_dynamic_header->relationCount; i++) {
        cm_instance_report_status *instanceStatus = &g_instance_group_report_status_ptr[i].instance_status;
        /* compute CN nodes */
        if (g_instance_role_group_ptr[i].instanceMember[0].instanceType == INSTANCE_TYPE_COORDINATE &&
            IsRoleCnAlive(instanceStatus)) {
            /* compute and get the min global barrier */
            GetMinBarrierID(tmpMinBarrier, instanceStatus->coordinatemember.barrierID, barrierLen,
                g_instance_role_group_ptr[i].instanceMember[0].instanceId);
        }
        /* compute DN nodes */
        if (g_instance_role_group_ptr[i].instanceMember[0].instanceType != INSTANCE_TYPE_DATANODE) {
            continue;
        }
        for (int j = 0; j < g_instance_role_group_ptr[i].count; j++) {
            if (!IsRoleDnAlive(&instanceStatus->data_node_member[j].local_status)) {
                continue;
            }
            GetMinBarrierID(tmpMinBarrier, instanceStatus->data_node_member[j].barrierID, barrierLen,
                g_instance_role_group_ptr[i].instanceMember[j].instanceId);
        }
    }
    errno_t rc = memcpy_s(minBarrier, BARRIERLEN - 1, tmpMinBarrier, BARRIERLEN - 1);
    securec_check_intval(rc, (void)rc);
}

static bool IsNeedUpdateTargetBarrier()
{
    uint32 barrierExistCnCount = 0;
    for (uint32 i = 0; i < g_dynamic_header->relationCount; i++) {
        cm_instance_report_status *instanceStatus = &g_instance_group_report_status_ptr[i].instance_status;
        /* compute CN nodes */
        if (g_instance_role_group_ptr[i].instanceMember[0].instanceType == INSTANCE_TYPE_COORDINATE &&
            IsRoleCnAlive(instanceStatus)) {
            /* all tested value is exists */
            if (g_instance_group_report_status_ptr[i].instance_status.coordinatemember.is_barrier_exist) {
                barrierExistCnCount++;
            }
        }
        /* compute DN nodes */
        if (g_instance_role_group_ptr[i].instanceMember[0].instanceType != INSTANCE_TYPE_DATANODE) {
            continue;
        }
        uint32 barrierExistDnCount = 0;
        for (int j = 0; j < g_instance_role_group_ptr[i].count; j++) {
            if (!IsRoleDnAlive(&instanceStatus->data_node_member[j].local_status)) {
                continue;
            }
            /* all tested value is exists */
            if (instanceStatus->data_node_member[j].is_barrier_exist) {
                barrierExistDnCount++;
            }
        }
        if (!IsDnMajority(barrierExistDnCount)) {
            write_runlog(LOG, "[IsNeedUpdateTargetBarrier] barrierExistDnCount=%u\n", barrierExistDnCount);
            return false;
        }
    }
    if (!IsCnMajority(barrierExistCnCount)) {
        write_runlog(LOG, "[IsNeedUpdateTargetBarrier] barrierExistCnCount=%u\n", barrierExistCnCount);
        return false;
    }
    return true;
}

static bool IsNeedUpdateQueryBarrier(const char *minBarrier, const char *queryBarrier, uint32 barrierLen)
{
    /* minBarrierID can not smaller than queryBarrierID, should keeping barrier's increasement. */
    if (strncmp(minBarrier, queryBarrier, barrierLen - 1) < 0) {
        write_runlog(LOG, "[IsNeedUpdateQueryBarrier] minBarrier is smaller than queryBarrierID\n");
        return false;
    }
    /* first update query barrier */
    if (strlen(queryBarrier) == 0) {
        write_runlog(LOG, "[IsNeedUpdateQueryBarrier] first update query barrier\n");
        return true;
    }
    int count = 0;
    for (uint32 i = 0; i < g_dynamic_header->relationCount; i++) {
        /* compute CN nodes */
        if (g_instance_role_group_ptr[i].instanceMember[0].instanceType == INSTANCE_TYPE_COORDINATE &&
            IsRoleCnAlive(&g_instance_group_report_status_ptr[i].instance_status)) {
            count++;
            if (strncmp(g_instance_group_report_status_ptr[i].instance_status.coordinatemember.query_barrierId,
                queryBarrier, barrierLen - 1) != 0) {
                return false;
            }
        }
        /* compute DN nodes */
        if (g_instance_role_group_ptr[i].instanceMember[0].instanceType != INSTANCE_TYPE_DATANODE) {
            continue;
        }
        cm_instance_report_status *instanceStatus = &g_instance_group_report_status_ptr[i].instance_status;
        for (int j = 0; j < g_instance_role_group_ptr[i].count; j++) {
            if (!IsRoleDnAlive(&instanceStatus->data_node_member[j].local_status)) {
                continue;
            }
            count++;
            /* compare to the etcd value, not same, so no need to update test value */
            if (strncmp(instanceStatus->data_node_member[j].query_barrierId, queryBarrier, barrierLen - 1) != 0) {
                return false;
            }
        }
    }
    if (count == 0) {
        write_runlog(ERROR, "[IsNeedUpdateQueryBarrier] available instance in update query barrier is 0\n");
        return false;
    }
    return true;
}

static status_t GenerateStopBarrier()
{
    if (strlen(g_targetBarrier) == 0) {
        write_runlog(ERROR, "[GenerateStopBarrier] target_barrier is null, waiting for the next round\n");
        return CM_ERROR;
    }

    char key[MAX_PATH_LEN] = {0};
    errno_t rc = snprintf_s(key, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/barrier/stop_barrier", pw->pw_name);
    securec_check_intval(rc, (void)rc);
    status_t st = SetKV2Ddb(key, MAX_PATH_LEN, g_targetBarrier, BARRIERLEN, NULL);
    if (st != CM_SUCCESS) {
        write_runlog(ERROR, "[GenerateStopBarrier] ddb set failed. key=%s,value=%s.\n", key, g_targetBarrier);
    } else {
        write_runlog(LOG, "Generate Stop Barrier success, stop_barrier is %s\n", g_targetBarrier);
    }
    return st;
}

static status_t GetQueryBarrierValueFromDDb(char *value, uint32 len)
{
    errno_t rc = memset_s(value, len, 0, len);
    securec_check_errno(rc, (void)rc);
    char queryBarrierKey[MAX_PATH_LEN] = {0};
    rc = snprintf_s(queryBarrierKey, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/barrier/query_barrier", pw->pw_name);
    securec_check_intval(rc, (void)rc);
    DDB_RESULT dbResult = SUCCESS_GET_VALUE;
    status_t st = GetKVFromDDb(queryBarrierKey, MAX_PATH_LEN, value, len, &dbResult);
    if (st != CM_SUCCESS && dbResult != CAN_NOT_FIND_THE_KEY) {
        write_runlog(ERROR, "get query_barrier info %s failed from ddb: %d\n", queryBarrierKey, (int)dbResult);
        return st;
    }
    /* Ensure that the value of querybarrier in ddb is the same as g_queryBarrier and incremental */
    if (strlen(g_queryBarrier) != 0 && strncmp(value, g_queryBarrier, len - 1) < 0) {
        write_runlog(WARNING, "query_barrier form ddb is smaller than g_queryBarrier, value from ddb is %s,"
            "g_queryBarrier is %s\n", value, g_queryBarrier);
        rc = memcpy_s(value, len, g_queryBarrier, len);
        securec_check_errno(rc, (void)rc);
        return CM_SUCCESS;
    }
    rc = memcpy_s(g_queryBarrier, sizeof(g_queryBarrier), value, len);
    securec_check_errno(rc, (void)rc);
    return CM_SUCCESS;
}

static void CheckBackupOpenStatus()
{
    char getValue[MAX_PATH_LEN] = {0};
    char backupOpenKey[MAX_PATH_LEN] = {0};
    errno_t rc = snprintf_s(backupOpenKey, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/CMServer/backup_open", pw->pw_name);
    securec_check_intval(rc, (void)rc);
    DDB_RESULT dbResult = SUCCESS_GET_VALUE;
    status_t st = GetKVFromDDb(backupOpenKey, MAX_PATH_LEN, getValue, MAX_PATH_LEN, &dbResult);
    if (st != CM_SUCCESS) {
        write_runlog(ERROR, "get backup_open info failed %s from ddb: %d\n", backupOpenKey, (int)dbResult);
        return;
    }
    int backupOpenValue = (int)strtol(getValue, NULL, 0);
    /* backup_open has changed, but cms not reload it, should stop the disaster recovery mode immediately */
    if (backup_open != (ClusterRole)backupOpenValue && g_gotParameterReload == 0) {
        write_runlog(ERROR, "backup_open value has changed to %d, exit!\n", backupOpenValue);
        exit(1);
    }
    return;
}

static bool IsStopBarrierExists()
{
    char getValue[MAX_PATH_LEN] = {0};
    char stopBarrierKey[MAX_PATH_LEN] = {0};
    errno_t rc = snprintf_s(stopBarrierKey, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/barrier/stop_barrier", pw->pw_name);
    securec_check_intval(rc, (void)rc);
    DDB_RESULT dbResult = SUCCESS_GET_VALUE;
    status_t st = GetKVAndLogLevel(stopBarrierKey, getValue, MAX_PATH_LEN, &dbResult, DEBUG1);
    if (st != CM_SUCCESS) {
        write_runlog(DEBUG1, "get stop_barrier info failed %s from ddb: %d\n", stopBarrierKey, (int)dbResult);
        return false;
    }
    write_runlog(LOG, "get stop_barrier success from ddb, stop_barrier is %s\n", getValue);
    return true;
}

void *DealGlobalBarrier(void *arg)
{
    char minBarrier[BARRIERLEN] = {0};
    char queryBarrier[BARRIERLEN] = {0};
    write_runlog(LOG, "Starting DealGlobalBarrier thread.\n");
    InitCnMajorityNum();
    for (;;) {
        if (g_HA_status->local_role != CM_SERVER_PRIMARY) {
            cm_sleep(20);
            continue;
        }
        if (IsStopBarrierExists()) {
            return NULL;
        }
        status_t st = GetQueryBarrierValueFromDDb(queryBarrier, BARRIERLEN);
        if (st != CM_SUCCESS) {
            cm_sleep(1);
            continue;
        }
        CalcMinBarrier(minBarrier, BARRIERLEN);
        bool needUpdateTargetVal = false;
        bool needUpdateQueryVal = IsNeedUpdateQueryBarrier(minBarrier, queryBarrier, BARRIERLEN);
        if (needUpdateQueryVal) {
            GlobalQueryBarrierRefresh(minBarrier, BARRIERLEN);
            needUpdateTargetVal = IsNeedUpdateTargetBarrier();
        }
        if (needUpdateTargetVal) {
            GlobalTargetBarrierRefresh(queryBarrier, BARRIERLEN);
        }
        write_runlog(LOG, "get queryBarrier is %s, minBarrier is %s, needUpdateQueryVal: %d, needUpdateTargetVal: %d\n",
            queryBarrier, minBarrier, needUpdateQueryVal, needUpdateTargetVal);

        /* Generate stop_barrier when cluster failover */
        bool isInClusterFailover = false;
        bool isExistClusterMaintenance = ExistClusterMaintenance(&isInClusterFailover);
        if (isExistClusterMaintenance && isInClusterFailover) {
            st = GenerateStopBarrier();
            if (st == CM_SUCCESS) {
                return NULL;
            }
        }
        cm_sleep(1);
    }
}

void *DealBackupOpenStatus(void *arg)
{
    write_runlog(LOG, "Starting DealBackupOpenStatus thread.\n");
    for (;;) {
        CheckBackupOpenStatus();
        cm_sleep(1);
    }
    return NULL;
}
