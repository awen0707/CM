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
 * cms_ddb.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_server/cms_ddb.cpp
 *
 * -------------------------------------------------------------------------
 */
#include "cms_ddb.h"
#include "cms_global_params.h"
#include "cms_write_dynamic_config.h"
#include "cms_common.h"

/*
 * "Minority AZ Force Starting" Support!
 *
 * Gloabl variable to indicate we change the cluster arbitraction mode from MINORITY
 * to MAJROITY, normally we use it to determine if we need sync-up current in-memory
 * term value to ddb
 */
volatile bool g_arbitrationChangedFromMinority = false;
const uint32 FIRST_DN = 6001;

uint64 GetTimeMinus(const struct timeval checkEnd, const struct timeval checkBegin)
{
    const uint64 secTomicSec = 1000000;
    return (uint64)((checkEnd.tv_sec - checkBegin.tv_sec) * secTomicSec +
        (uint64)(checkEnd.tv_usec - checkBegin.tv_usec));
}

static inline void UpdateStatusRoleByDdbValue(cm_instance_role_status *status, const char *valueOfDynConf);
static int GetTermFromDdb(uint32* term, bool& firstStart);
static int SetExceptSyncListStatusValue(
    char *value, size_t len, uint32 groupIndex, const CurrentInstanceStatus *statusInstances);
static status_t GetIdxFromKeyValue(DrvKeyValue *keyValue, uint32 len, uint32 instanceId, uint32 *idx);

static void SetSyncLock(uint32 groupIdx, bool allSuccess, int32 instanceType)
{
    if (g_HA_status->local_role == CM_SERVER_PRIMARY && allSuccess) {
        while (!g_instance_group_report_status_ptr[groupIdx].instance_status.ddbSynced) {
            __sync_lock_test_and_set(&g_instance_group_report_status_ptr[groupIdx].instance_status.ddbSynced, 1);
            write_runlog(LOG, "sync %s(%u) static role from ddb all success.\n", type_int_to_string(instanceType),
                GetInstanceIdInGroup(groupIdx, 0));
        }
    }
}

static void SetStaticRoleToDdb(uint32 groupIdx, int32 instanceType)
{
    write_runlog(
        LOG, "set %s(%u) static role to ddb.\n", type_int_to_string(instanceType), GetInstanceIdInGroup(groupIdx, 0));
    for (int32 i = 0; i < g_instance_role_group_ptr[groupIdx].count; ++i) {
        SetDynamicConfigChangeToDdb(groupIdx, i);
    }
}

static status_t GetKeyValueMemory(uint32 groupIdx, uint32 count)
{
    if (count == 0) {
        return CM_ERROR;
    }
    cm_instance_report_status *reportSt = &(g_instance_group_report_status_ptr[groupIdx].instance_status);
    if (count != reportSt->kvCount) {
        write_runlog(WARNING, "instance(%u) has changed from old(%u) to new(%u), malloc memory again.\n",
            GetInstanceIdInGroup(groupIdx, 0), reportSt->kvCount, count);
        reportSt->kvCount = count;
        FREE_AND_RESET(reportSt->keyValue);
    }
    size_t len = sizeof(DrvKeyValue) * ((size_t)count);
    if (reportSt->keyValue == NULL) {
        reportSt->keyValue = (DrvKeyValue *)malloc(len);
        if (reportSt->keyValue == NULL) {
            write_runlog(ERROR, "g_dnKeyValue is NULL.\n");
            return CM_ERROR;
        }
    }
    errno_t rc = memset_s(reportSt->keyValue, len, 0, len);
    securec_check_errno(rc, FREE_AND_RESET(reportSt->keyValue));
    return CM_SUCCESS;
}

static bool IsNeedSyncStRoleFromDdb(uint32 groupIdx)
{
    /* standby cms need sync */
    if (g_HA_status->local_role != CM_SERVER_PRIMARY) {
        return true;
    }
    if (g_instance_group_report_status_ptr[groupIdx].instance_status.ddbSynced == 0) {
        return true;
    }

    return false;
}

static bool IsUpdateStRoleWithDdbRole(uint32 groupIdx, int32 memIdx)
{
    if (g_HA_status->local_role != CM_SERVER_PRIMARY) {
        return true;
    }
    if (g_instance_group_report_status_ptr[groupIdx].instance_status.command_member[memIdx].role_changed !=
        INSTANCE_ROLE_CHANGED) {
        return true;
    }
    return false;
}

static status_t GetInstStatusKeyValueFromDdb(DrvKeyValue *keyValue, uint32 len, DDB_RESULT *dbResult, int32 instdType)
{
    char key[MAX_PATH_LEN] = {0};
    errno_t rc = 0;
    switch (instdType) {
        case INSTANCE_TYPE_DATANODE:
            rc = snprintf_s(key, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/dynamic_config/datanodes/", pw->pw_name);
            break;
        case INSTANCE_TYPE_COORDINATE:
            rc = snprintf_s(key, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/dynamic_config/coordinators/", pw->pw_name);
            break;
        case INSTANCE_TYPE_GTM:
            rc = snprintf_s(key, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/dynamic_config/GTM/", pw->pw_name);
            break;
        default:
            write_runlog(ERROR, "line %s:%d undefined instdType(%d).\n", __FUNCTION__, __LINE__, instdType);
            return CM_ERROR;
    }
    securec_check_intval(rc, FREE_AND_RESET(keyValue));
    status_t st = GetAllKVFromDDb(key, MAX_PATH_LEN, keyValue, len, dbResult);
    int32 logLevel = (g_HA_status->local_role == CM_SERVER_PRIMARY) ? LOG : DEBUG1;
    if (st != CM_SUCCESS) {
        write_runlog(logLevel, "cannot get InstanceStatusKeyValue by key(%s), error msg is %d.\n", key, *dbResult);
        return CM_ERROR;
    }
    PrintKeyValueMsg(key, keyValue, len, logLevel);
    return CM_SUCCESS;
}

static void SyncCnInstanceStatusFromDdb(uint32 groupIdx, bool *cmsSyncFromDdbFlag, DrvKeyValue *keyValue, uint32 len)
{
    uint32 idx = 0;
    cm_instance_role_status *status = &g_instance_role_group_ptr[groupIdx].instanceMember[0];
    status_t st = GetIdxFromKeyValue(keyValue, len, status->instanceId, &idx);
    if (st == CM_SUCCESS) {
        if (IsUpdateStRoleWithDdbRole(groupIdx, 0)) {
            (void)pthread_rwlock_wrlock(&(g_instance_group_report_status_ptr[groupIdx].lk_lock));
            UpdateStatusRoleByDdbValue(status, keyValue[idx].value);
            (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[groupIdx].lk_lock));
        }
    } else {
        *cmsSyncFromDdbFlag = false;
    }
    return;
}

static void GetCnDynamicConfigChangeFromDdb(DrvKeyValue *keyValue, uint32 len)
{
    if (!IsInteractWithDdb(true, true)) {
        return;
    }

    for (uint32 i = 0; i < g_dynamic_header->relationCount; i++) {
        if (g_instance_role_group_ptr[i].instanceMember[0].instanceType != INSTANCE_TYPE_COORDINATE) {
            continue;
        }
        bool cmsSyncFromDdbFlag = true;
        if (IsNeedSyncStRoleFromDdb(i)) {
            SyncCnInstanceStatusFromDdb(i, &cmsSyncFromDdbFlag, keyValue, len);
            SetSyncLock(i, cmsSyncFromDdbFlag, INSTANCE_TYPE_COORDINATE);
        }
    }
}

static status_t GetIdxFromKeyValue(DrvKeyValue *keyValue, uint32 len, uint32 instanceId, uint32 *idx)
{
    char key[MAX_PATH_LEN] = {0};
    errno_t rc = snprintf_s(key, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%u", instanceId);
    securec_check_intval(rc, (void)rc);
    for (uint32 i = 0; i < len; ++i) {
        if (strstr(keyValue[i].key, key) != NULL) {
            *idx = i;
            return CM_SUCCESS;
        }
    }
    return CM_ERROR;
}

static void SetDnStaticRole2Standby(uint32 groupIdx, int32 memberIdx)
{
    for (int k = 0; k < g_instance_role_group_ptr[groupIdx].count; ++k) {
        cm_instance_role_status *dnRole = &(g_instance_role_group_ptr[groupIdx].instanceMember[k]);
        if (dnRole->role != INSTANCE_ROLE_STANDBY && dnRole->role != INSTANCE_ROLE_PRIMARY) {
            continue;
        }
        if (k != memberIdx) {
            write_runlog(LOG, "instd(%u) will change instd(%u) static role from [%d: %s] to [%d : %s].\n",
                GetInstanceIdInGroup(groupIdx, memberIdx), dnRole->instanceId, dnRole->role,
                datanode_role_int_to_string(dnRole->role), INSTANCE_ROLE_STANDBY,
                datanode_role_int_to_string(INSTANCE_ROLE_STANDBY));
            dnRole->role = INSTANCE_ROLE_STANDBY;
        }
    }
}

static void SyncDnInstanceStatusFromDdb(uint32 groupIdx, bool *cmsSyncFromDdbFlag, DrvKeyValue *keyValue, uint32 len)
{
    uint32 idx = 0;
    status_t st = CM_SUCCESS;
    int32 logLevel = (strcmp(thread_name, "SYNC") == 0) ? DEBUG1 : LOG;
    for (int32 i = 0; i < g_instance_role_group_ptr[groupIdx].count; ++i) {
        cm_instance_role_status* status = &(g_instance_role_group_ptr[groupIdx].instanceMember[i]);
        st = GetIdxFromKeyValue(keyValue, len, status->instanceId, &idx);
        if (st != CM_SUCCESS) {
            *cmsSyncFromDdbFlag = false;
            write_runlog(LOG, "cannot find the instd(%u) static role(%d) from ddb.\n",
                status->instanceId, status->role);
            continue;
        }
        if (!IsUpdateStRoleWithDdbRole(groupIdx, i)) {
            continue;
        }
        write_runlog(logLevel, "cm server role(%d): sync dynamic config(%s) of DN(%u) from ddb.\n",
            g_HA_status->local_role, keyValue[idx].value, status->instanceId);
        if (strcmp(keyValue[idx].value, PRIMARY) == 0 && status->role == INSTANCE_ROLE_STANDBY) {
            if (status->role != INSTANCE_ROLE_PRIMARY && g_HA_status->local_role == CM_SERVER_PRIMARY) {
                cm_pending_notify_broadcast_msg(groupIdx, status->instanceId);
            }
            status->role = INSTANCE_ROLE_PRIMARY;
            SetDnStaticRole2Standby(groupIdx, i);
        } else if (strcmp(keyValue[idx].value, STANDBY) == 0 && status->role == INSTANCE_ROLE_PRIMARY) {
            write_runlog(LOG, "instd(%u) will change static role from [%d: %s] to [%d : %s].\n",
                status->instanceId, status->role, datanode_role_int_to_string(status->role), INSTANCE_ROLE_STANDBY,
                datanode_role_int_to_string(INSTANCE_ROLE_STANDBY));
            status->role = INSTANCE_ROLE_STANDBY;
        }
    }
    return;
}

static void GetDnDynamicConfigChangeFromDdb(DrvKeyValue *keyValue, uint32 len)
{
    if (!IsInteractWithDdb(true, true)) {
        return;
    }

    for (uint32 i = 0; i < g_dynamic_header->relationCount; i++) {
        if (g_instance_role_group_ptr[i].instanceMember[0].instanceType != INSTANCE_TYPE_DATANODE) {
            continue;
        }
        bool cmsSyncFromDdbFlag = true;
        if (IsNeedSyncStRoleFromDdb(i)) {
            (void)pthread_rwlock_wrlock(&(g_instance_group_report_status_ptr[i].lk_lock));
            SyncDnInstanceStatusFromDdb(i, &cmsSyncFromDdbFlag, keyValue, len);
            (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[i].lk_lock));
            (void)WriteDynamicConfigFile(false);
            SetSyncLock(i, cmsSyncFromDdbFlag, INSTANCE_TYPE_DATANODE);
        }
    }
}

static uint32 GetAllInstanceCount(int32 instType)
{
    uint32 count = 0;
    for (uint32 i = 0; i < g_dynamic_header->relationCount; ++i) {
        if (g_instance_role_group_ptr[i].instanceMember[0].instanceType != instType) {
            continue;
        }
        count += (uint32)g_instance_role_group_ptr[i].count;
    }
    if (count == 0) {
        write_runlog(ERROR, "cannot get instance count(%u), instType is %d.\n", count, instType);
    }
    return count;
}

static void GetInstanceStatusKeyValueFromDdb(int32 instdType)
{
    if (!IsInteractWithDdb(true, true)) {
        write_runlog(LOG, "g_dbType is %d, cannot get instance from ddb.\n", g_dbType);
        return;
    }
    uint32 instanceCounts = GetAllInstanceCount(instdType);
    if (instanceCounts == 0) {
        return;
    }
    size_t len = instanceCounts * sizeof(DrvKeyValue);
    DrvKeyValue *keyValue = (DrvKeyValue *)malloc(len);
    if (keyValue == NULL) {
        write_runlog(ERROR, "keyValue is null, cannot get instanceStatusKeyValue from ddb.\n");
        return;
    }
    errno_t rc = memset_s(keyValue, len, 0, len);
    securec_check_errno(rc, FREE_AND_RESET(keyValue));
    DDB_RESULT dbResult = SUCCESS_GET_VALUE;
    status_t st = GetInstStatusKeyValueFromDdb(keyValue, instanceCounts, &dbResult, instdType);
    if (st != CM_SUCCESS) {
        FREE_AND_RESET(keyValue);
        return;
    }
    switch (instdType) {
        case INSTANCE_TYPE_DATANODE:
            GetDnDynamicConfigChangeFromDdb(keyValue, instanceCounts);
            break;
        case INSTANCE_TYPE_COORDINATE:
            GetCnDynamicConfigChangeFromDdb(keyValue, instanceCounts);
            break;
        default:
            break;
    }
    FREE_AND_RESET(keyValue);
    return;
}

void ClearSyncWithDdbFlag()
{
    if (!IsNeedSyncDdb()) {
        return;
    }

    for (uint32 i = 0; i < g_dynamic_header->relationCount; ++i) {
        while (g_instance_group_report_status_ptr[i].instance_status.ddbSynced) {
            __sync_lock_release(&g_instance_group_report_status_ptr[i].instance_status.ddbSynced);
        }
    }
}

static status_t GetStatusRoleFromDdb(int32 instanceType, char *value, uint32 valueLen, DDB_RESULT *ddbResult)
{
    char key[MAX_PATH_LEN] = {0};
    errno_t rc = 0;
    switch (instanceType) {
        case INSTANCE_TYPE_DATANODE:
            rc = snprintf_s(key, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/dynamic_config/datanode_status", pw->pw_name);
            break;
        case INSTANCE_TYPE_COORDINATE:
            rc = snprintf_s(key, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/dynamic_config/coordinator_status", pw->pw_name);
            break;
        default:
            write_runlog(ERROR, "line %s:%d undefined instanceType.\n", __FUNCTION__, __LINE__);
            return CM_ERROR;
    }
    securec_check_intval(rc, (void)rc);
    status_t st = GetKVFromDDb(key, MAX_PATH_LEN, value, valueLen, ddbResult);
    int32 logLevel = (g_HA_status->local_role == CM_SERVER_PRIMARY) ? LOG : DEBUG1;
    write_runlog(logLevel, "get status(%d): key [%s] value [%s], ddbResult is %d.\n", st, key, value, *ddbResult);
    return st;
}

static bool DnUpdateStausRole2Init(const char *value, int32 memIdx, cm_instance_group_report_status *dnReport,
    cm_instance_role_status *status, cm_instance_role_group *dnRole)
{
    if (value[status->instanceId - FIRST_DN] != '0') {
        return false;
    }
    (void)pthread_rwlock_wrlock(&(dnReport->lk_lock));
    status->role = status->instanceRoleInit;
    write_runlog(LOG, "cm server primary : sync dynamic config(%d) of DN(%u) from ddb.\n",
        status->role, status->instanceId);
    for (int32 otherMemIdx = 0; otherMemIdx < dnRole->count; otherMemIdx++) {
        cm_instance_role_status *otherStatus = &dnRole->instanceMember[otherMemIdx];
        if (memIdx != otherMemIdx) {
            otherStatus->role = otherStatus->instanceRoleInit;
            write_runlog(LOG, "cm server primary : sync dynamic config(%d) of DN(%u) from ddb.\n",
                otherStatus->role, otherStatus->instanceId);
        }
    }
    (void)pthread_rwlock_unlock(&(dnReport->lk_lock));
    return true;
}

static void DnUpdateStatusRoleFromDdb(const char *value)
{
    bool res = false;
    for (uint32 i = 0; i < g_dynamic_header->relationCount; ++i) {
        if (g_instance_role_group_ptr[i].instanceMember[0].instanceType != INSTANCE_TYPE_DATANODE) {
            continue;
        }
        cm_instance_group_report_status *dnReport = &g_instance_group_report_status_ptr[i];
        dnReport->instance_status.ddbSynced = 1;
        cm_instance_role_group *dnRole = &g_instance_role_group_ptr[i];
        for (int j = 0; j < dnRole->count; ++j) {
            cm_instance_role_status *status = &dnRole->instanceMember[j];
            /* if DN's static role changed from standby to primary, need broadcast */
            if (status->role != INSTANCE_ROLE_PRIMARY &&
                GetDbStaticRoleInt(value[status->instanceId - FIRST_DN]) == INSTANCE_ROLE_PRIMARY) {
                cm_pending_notify_broadcast_msg(i, status->instanceId);
            }
            res = DnUpdateStausRole2Init(value, j, dnReport, status, dnRole);
            if (res) {
                break;
            }
            (void)pthread_rwlock_wrlock(&(dnReport->lk_lock));
            status->role = GetDbStaticRoleInt(value[status->instanceId - FIRST_DN]);
            (void)pthread_rwlock_unlock(&(dnReport->lk_lock));
            write_runlog(DEBUG1, "cm server primary : sync dynamic config(%d) of DN(%u) from ddb.\n",
                status->role, status->instanceId);
        }
    }
    (void)WriteDynamicConfigFile(false);
}

static void GetDnStatusRoleFromDdbInCmsPrimary(uint32 groupIdx)
{
    if (g_HA_status->local_role != CM_SERVER_PRIMARY) {
        return;
    }
    if (g_instance_role_group_ptr[groupIdx].instanceMember[0].instanceType != INSTANCE_TYPE_DATANODE) {
        return;
    }
    cm_instance_group_report_status *dnGroup = &g_instance_group_report_status_ptr[groupIdx];
    /* in case of ddb is already sync-ed */
    if (dnGroup->instance_status.ddbSynced == 1) {
        return;
    }
    char value[MAX_PATH_LEN] = {0};
    DDB_RESULT ddbResult = SUCCESS_GET_VALUE;
    status_t st = GetStatusRoleFromDdb(INSTANCE_TYPE_DATANODE, value, MAX_PATH_LEN, &ddbResult);
    /* concurrent variable assignment */
    if (dnGroup->instance_status.ddbSynced == 1) {
        return;
    }
    if (st == CM_SUCCESS) {
        DnUpdateStatusRoleFromDdb(value);
        return;
    }
    /* dynamic config only exists when the datanode has ever switched over. */
    /* in case of upgrade, get old struct transform to new struct */
    if (ddbResult == CAN_NOT_FIND_THE_KEY) {
        if (!g_getHistoryDnStatusFromDdb) {
            g_getHistoryDnStatusFromDdb = true;
            GetInstanceStatusKeyValueFromDdb(INSTANCE_TYPE_DATANODE);
            SetDynamicConfigChangeToDdb(groupIdx, 0);
            if (dnGroup->instance_status.ddbSynced != 1) {
                g_getHistoryDnStatusFromDdb = false;
                return;
            }
            (void)WriteDynamicConfigFile(false);
        }
    }
}

static void GetDnStatusRoleFromDdbInCmsStandby()
{
    if (g_HA_status->local_role == CM_SERVER_PRIMARY) {
        return;
    }
    char value[MAX_PATH_LEN] = {0};
    DDB_RESULT ddbResult = SUCCESS_GET_VALUE;
    status_t st = GetStatusRoleFromDdb(INSTANCE_TYPE_DATANODE, value, MAX_PATH_LEN, &ddbResult);
    if (st != CM_SUCCESS) {
        return;
    }
    for (uint32 groupIdx = 0; groupIdx < g_dynamic_header->relationCount; ++groupIdx) {
        if (g_instance_role_group_ptr[groupIdx].instanceMember[0].instanceType != INSTANCE_TYPE_DATANODE) {
            continue;
        }
        cm_instance_group_report_status *dnReport = &g_instance_group_report_status_ptr[groupIdx];
        cm_instance_role_group *dnRole = &g_instance_role_group_ptr[groupIdx];
        (void)pthread_rwlock_wrlock(&(dnReport->lk_lock));
        for (int32 memIdx = 0; memIdx < dnRole->count; ++memIdx) {
            cm_instance_role_status *status = &dnRole->instanceMember[memIdx];
            status->role = GetDbStaticRoleInt(value[status->instanceId - FIRST_DN]);
            write_runlog(DEBUG1, "cm server role(%d): sync dynamic config(%d) of DN(%u) from ddb.\n",
                g_HA_status->local_role, status->role, status->instanceId);
        }
        (void)pthread_rwlock_unlock(&(dnReport->lk_lock));
    }
    (void)WriteDynamicConfigFile(false);
}

/**
 * @brief get DN primary/standby info from Ddb.
 *
 * @param groupIdx    group index in cluster config
 */
void GetDatanodeDynamicConfigChangeFromDdbNew(uint32 groupIdx)
{
    if (!IsInteractWithDdb(true, true)) {
        return;
    }

    if (g_HA_status->local_role == CM_SERVER_PRIMARY) {
        GetDnStatusRoleFromDdbInCmsPrimary(groupIdx);
    } else {
        GetDnStatusRoleFromDdbInCmsStandby();
    }
}

static void GetDatanodeDynamicConfigChangeFromDdbInShard(uint32 groupIdx)
{
    /*
     * if there is a record of DN dynamic config in ddb, it means DN has ever switched over.
     * and then comparing dynamic config in ddb and local config, cm_server reloads dynamic
     * config from ddb.
     */
    if (!IsInteractWithDdb(true, true)) {
        return;
    }
    if (g_instance_role_group_ptr[groupIdx].instanceMember[0].instanceType != INSTANCE_TYPE_DATANODE) {
        return;
    }

    if (!IsNeedSyncStRoleFromDdb(groupIdx)) {
        return;
    }
    uint32 count = GetAllInstanceCount(INSTANCE_TYPE_DATANODE);
    status_t st = GetKeyValueMemory(groupIdx, count);
    if (st != CM_SUCCESS) {
        return;
    }
    DDB_RESULT dbResult = SUCCESS_GET_VALUE;
    cm_instance_report_status *reportSt = &(g_instance_group_report_status_ptr[groupIdx].instance_status);
    st = GetInstStatusKeyValueFromDdb(reportSt->keyValue, count, &dbResult, INSTANCE_TYPE_DATANODE);
    bool cmsSyncFromDdbFlag = true;
    uint32 instd = g_instance_role_group_ptr[groupIdx].instanceMember[0].instanceId;
    if (st == CM_SUCCESS) {
        SyncDnInstanceStatusFromDdb(groupIdx, &cmsSyncFromDdbFlag, reportSt->keyValue, count);
        (void)WriteDynamicConfigFile(false);
        if (cmsSyncFromDdbFlag) {
            SetSyncLock(groupIdx, cmsSyncFromDdbFlag, INSTANCE_TYPE_DATANODE);
            return;
        }
    }
    if (g_HA_status->local_role != CM_SERVER_PRIMARY) {
        write_runlog(ERROR, "instd(%u) failed to get ddb value of DN, error info:%d\n", instd, (int)dbResult);
        return;
    }
    if (!cmsSyncFromDdbFlag || (st != CM_SUCCESS && dbResult == CAN_NOT_FIND_THE_KEY)) {
        write_runlog(LOG, "instd(%u) cmsSyncFromDdbFlag is %d, st is %d, dbResult is %d.\n",
            instd, cmsSyncFromDdbFlag, (int)st, (int)dbResult);
        cmsSyncFromDdbFlag = true;
        SetStaticRoleToDdb(groupIdx, INSTANCE_TYPE_DATANODE);
    } else {
        cmsSyncFromDdbFlag = false;
    }
    write_runlog(ERROR, "instd(%u) failed to get ddb value of DN, cmsSyncFromDdbFlag is %d, error info:%d\n",
        instd, cmsSyncFromDdbFlag, (int)dbResult);
    SetSyncLock(groupIdx, cmsSyncFromDdbFlag, INSTANCE_TYPE_DATANODE);
}

void GetDatanodeDynamicConfigChangeFromDdb(uint32 groupIdx)
{
    (void)pthread_rwlock_wrlock(&(g_instance_group_report_status_ptr[groupIdx].lk_lock));
    GetDatanodeDynamicConfigChangeFromDdbInShard(groupIdx);
    (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[groupIdx].lk_lock));
}

static void GetCnStatusFromDdbForStandbyCm()
{
    char statusKey[MAX_PATH_LEN] = {0};
    char statusValue[MAX_PATH_LEN] = {0};
    errno_t rc = snprintf_s(statusKey, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/dynamic_config/coordinator_status",
        pw->pw_name);
    securec_check_intval(rc, (void)rc);
    DDB_RESULT dbResult = SUCCESS_GET_VALUE;
    status_t st = GetKVFromDDb(statusKey, MAX_PATH_LEN, statusValue, MAX_PATH_LEN, &dbResult);
    if (st == CM_SUCCESS) {
        for (uint32 groupIndex = 0; groupIndex < g_dynamic_header->relationCount; groupIndex++) {
            cm_instance_role_status *status = &g_instance_role_group_ptr[groupIndex].instanceMember[0];
            cm_instance_group_report_status *cnGroup = &g_instance_group_report_status_ptr[groupIndex];
            if (status->instanceType == INSTANCE_TYPE_COORDINATE) {
                /* 5001 means first cn instance number. */
                uint32 cnIndex = status->instanceId - 5001;
                (void)pthread_rwlock_wrlock(&(cnGroup->lk_lock));
                status->role = statusValue[cnIndex] - '0';
                (void)pthread_rwlock_unlock(&(cnGroup->lk_lock));
            }
        }
        (void)WriteDynamicConfigFile(false);
    } else {
        write_runlog(DEBUG1, "failed get ddb value by key: %s, error info:%d\n", statusKey, dbResult);
    }
}

static void CnUpdateStatusRoleFromDdb(const char *value)
{
    bool needRefreshCfg = false;
    const uint32 cnFirstId = 5001;
    for (uint32 i = 0; i < g_dynamic_header->relationCount; ++i) {
        cm_instance_role_status *status = &g_instance_role_group_ptr[i].instanceMember[0];
        if (status->instanceType != INSTANCE_TYPE_COORDINATE) {
            continue;
        }

        cm_instance_group_report_status *oneCnGroup = &g_instance_group_report_status_ptr[i];
        if (oneCnGroup->instance_status.ddbSynced == 1) {
            continue;
        }
        uint32 cn_index = status->instanceId - cnFirstId;
        if ((value[cn_index] - '0') != status->role) {
            int oldRole = status->role;
            needRefreshCfg = true;
            (void)pthread_rwlock_wrlock(&(oneCnGroup->lk_lock));
            status->role = value[cn_index] - '0';
            (void)pthread_rwlock_unlock(&(oneCnGroup->lk_lock));

            write_runlog(LOG, "cm server primary: sync dynamic config(%d to %d) of CN(%u) from ddb.\n",
                status->role, oldRole, status->instanceId);
        }
        oneCnGroup->instance_status.ddbSynced = 1;
    }
    if (needRefreshCfg) {
        (void)WriteDynamicConfigFile(false);
    }
}

static void GetCnStatusRoleFromDdbInCmsPrimary(uint32 groupIdx)
{
    if (g_HA_status->local_role != CM_SERVER_PRIMARY) {
        return;
    }
    if (g_instance_role_group_ptr[groupIdx].instanceMember[0].instanceType != INSTANCE_TYPE_COORDINATE) {
        return;
    }
    cm_instance_group_report_status *cnGroup = &g_instance_group_report_status_ptr[groupIdx];
    /* in case of ddb is already sync-ed */
    if (cnGroup->instance_status.ddbSynced == 1) {
        return;
    }
    char value[MAX_PATH_LEN] = {0};
    DDB_RESULT dbResult = SUCCESS_GET_VALUE;
    status_t st = GetStatusRoleFromDdb(INSTANCE_TYPE_COORDINATE, value, MAX_PATH_LEN, &dbResult);
    /* concurrent variable assignment */
    if (cnGroup->instance_status.ddbSynced == 1) {
        return;
    }
    if (st == CM_SUCCESS) {
        CnUpdateStatusRoleFromDdb(value);
        return;
    }
        /* in case of upgrade, get old struct transform to new struct. */
    if (dbResult == CAN_NOT_FIND_THE_KEY) {
        if (!g_getHistoryCnStatusFromDdb) {
            g_getHistoryCnStatusFromDdb = true;
            GetInstanceStatusKeyValueFromDdb(INSTANCE_TYPE_COORDINATE);
            SetDynamicConfigChangeToDdb(groupIdx, 0);
            if (cnGroup->instance_status.ddbSynced != 1) {
                g_getHistoryCnStatusFromDdb = false;
                return;
            }
            (void)WriteDynamicConfigFile(false);
        }
    }
}

/**
 * @brief get CN status info from ddb.
 *
 * @param groupIndex    group index in cluster config
 */
void GetCoordinatorDynamicConfigChangeFromDdbNew(uint32 groupIdx)
{
    if (!IsInteractWithDdb(true, true)) {
        return;
    }
    if (g_HA_status->local_role == CM_SERVER_PRIMARY) {
        GetCnStatusRoleFromDdbInCmsPrimary(groupIdx);
    } else if (g_HA_status->local_role != CM_SERVER_PRIMARY) {
        GetCnStatusFromDdbForStandbyCm();
    }
}

DDB_RESULT GetValueFromDdbByKey(char *key, char *value, size_t len)
{
    DDB_RESULT dbResult = SUCCESS_GET_VALUE;
    status_t st = GetKVFromDDb(key, MAX_PATH_LEN, value, (uint32)len, &dbResult);
    if (st != CM_SUCCESS) {
        write_runlog(ERROR, "failed get ddb value by key: %s, error info:%d\n", key, dbResult);
        /* in case of upgrade, get old struct transform to new struct */
        if (dbResult == CAN_NOT_FIND_THE_KEY) {
            write_runlog(ERROR, "can't find the key from ddb.\n");
            return CAN_NOT_FIND_THE_KEY;
        }
        return FAILED_GET_VALUE;
    }
    write_runlog(LOG, "success to get ddb value by key: %s, value:%s.\n", key, value);
    return SUCCESS_GET_VALUE;
}

void SetSyncList(uint32 groupIndex, int memberIndex, DatanodeSyncList *syncList, int *index)
{
    bool isVoteAz = IsCurInstanceInVoteAz(groupIndex, memberIndex);
    if (!isVoteAz) {
        syncList->dnSyncList[(*index)++] = g_instance_role_group_ptr[groupIndex].instanceMember[memberIndex].instanceId;
    }
}

DDB_RESULT GetHistoryClusterCurSyncListFromDdb()
{
    char key[MAX_PATH_LEN] = {0};
    char value[MAX_PATH_LEN] = {0};
    errno_t rc;
    DDB_RESULT res;
    // the first datanode instanceId
    const uint32 instanceId = 6001;
    rc = snprintf_s(key, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/CMServer/DnCurSyncList", pw->pw_name);
    securec_check_intval(rc, (void)rc);
    res = GetValueFromDdbByKey(key, value, sizeof(value));
    if (res == FAILED_GET_VALUE) {
        return res;
    }
    for (uint32 groupIndex = 0; groupIndex < g_dynamic_header->relationCount; ++groupIndex) {
        // check whether the group is datanode.
        if (g_instance_role_group_ptr[groupIndex].instanceMember[0].instanceType != INSTANCE_TYPE_DATANODE) {
            continue;
        }
        cm_instance_report_status *reportGrp = &g_instance_group_report_status_ptr[groupIndex].instance_status;
        cm_instance_role_group *dnRoleGroup = &g_instance_role_group_ptr[groupIndex];
        rc = memset_s(&(reportGrp->currentSyncList), sizeof(DatanodeSyncList), 0, sizeof(DatanodeSyncList));
        securec_check_errno(rc, (void)rc);
        int32 index = 0;
        for (int32 i = 0; i < dnRoleGroup->count; ++i) {
            // initial ddb doesn't have this key, and all will be recode in currentSyncList.
            if (res == CAN_NOT_FIND_THE_KEY) {
                SetSyncList(groupIndex, i, &(reportGrp->currentSyncList), &index);
                continue;
            }
            // index in the ddb.
            // the instanceId has reduce, and will be recode in currentSyncList.
            if ((value[dnRoleGroup->instanceMember[i].instanceId - instanceId] - '0') == INSTANCE_DATA_REDUCED) {
                write_runlog(LOG, "line %d: instance(%u) has modified synchronous_standby_names.\n",
                    __LINE__, dnRoleGroup->instanceMember[i].instanceId);
                SetSyncList(groupIndex, i, &(reportGrp->currentSyncList), &index);
            }
        }
        /* When DN capacity expansion, the SyncList in etcd is 0, need initialize */
        if (index == 0) {
            for (int i = 0; i < dnRoleGroup->count; ++i) {
                SetSyncList(groupIndex, i, &(reportGrp->currentSyncList), &index);
            }
            write_runlog(LOG, "The currentSyncList in etcd is all 0 need init, groupindex=%u, dn_replication_num=%d.\n",
                groupIndex, index);
        }
        reportGrp->currentSyncList.count = index;
    }
    return SUCCESS_GET_VALUE;
}

DDB_RESULT GetHistoryClusterExceptSyncListFromDdb()
{
    char key[MAX_PATH_LEN] = {0};
    char value[MAX_PATH_LEN] = {0};
    errno_t rc;
    DDB_RESULT res;
    // the first datanode instanceId
    rc = snprintf_s(key, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/CMServer/DnExpectSyncList", pw->pw_name);
    securec_check_intval(rc, (void)rc);
    res = GetValueFromDdbByKey(key, value, sizeof(value));
    if (res == FAILED_GET_VALUE) {
        return res;
    }
    for (uint32 groupIndex = 0; groupIndex < g_dynamic_header->relationCount; ++groupIndex) {
        if (g_instance_role_group_ptr[groupIndex].instanceMember[0].instanceType != INSTANCE_TYPE_DATANODE) {
            continue;
        }
        cm_instance_group_report_status *dnReportGroup = &g_instance_group_report_status_ptr[groupIndex];
        cm_instance_role_group *dnRoleGroup = &g_instance_role_group_ptr[groupIndex];
        rc = memset_s(
            &(dnReportGroup->instance_status.exceptSyncList), sizeof(DatanodeSyncList), 0, sizeof(DatanodeSyncList));
        securec_check_errno(rc, (void)rc);
        // maybe shrink or expand
        int index = 0;
        for (int i = 0; i < dnRoleGroup->count; ++i) {
            // initial ddb doesn't have the key, and all will be recored in the exceptSyncList.
            if (res == CAN_NOT_FIND_THE_KEY) {
                SetSyncList(groupIndex, i, &(dnReportGroup->instance_status.exceptSyncList), &index);
                continue;
            }
            // get the index in the Ddb.
            if ((value[dnRoleGroup->instanceMember[i].instanceId - FIRST_DN] - '0') == INSTANCE_DATA_REDUCED) {
                write_runlog(LOG, "line %d: instance(%u) expects to modify synchronous_standby_names.\n",
                    __LINE__, dnRoleGroup->instanceMember[i].instanceId);
                SetSyncList(groupIndex, i, &(dnReportGroup->instance_status.exceptSyncList), &index);
            }
        }
        /* When DN capacity expansion, the SyncList in etcd is 0, need initialize */
        if (index == 0) {
            for (int i = 0; i < dnRoleGroup->count; ++i) {
                SetSyncList(groupIndex, i, &(dnReportGroup->instance_status.exceptSyncList), &index);
            }
            write_runlog(LOG, "The exceptSyncList in etcd is all 0 need init, groupindex=%u, dn_replication_num=%d.\n",
                groupIndex, index);
        }
        dnReportGroup->instance_status.exceptSyncList.count = index;
    }
    return SUCCESS_GET_VALUE;
}

static void ResetSyncDoneFlag(uint32 groupIdx)
{
    write_runlog(LOG, "instd(%u) will reset sync data to failed(%d).\n",
        GetInstanceIdInGroup(groupIdx, 0), FAILED_SYNC_DATA);
    for (int32 i = 0; i < g_instance_role_group_ptr[groupIdx].count; ++i) {
        g_instance_group_report_status_ptr[groupIdx].instance_status.data_node_member[i].syncDone = FAILED_SYNC_DATA;
    }
}

bool SetGroupExpectSyncList(uint32 groupIndex, const CurrentInstanceStatus *statusInstance)
{
    char statusKey[MAX_PATH_LEN] = {0};
    char statusValue[MAX_PATH_LEN] = {0};
    uint32 instanceId = g_instance_role_group_ptr[groupIndex].instanceMember[0].instanceId;
    cm_instance_report_status *dnReportStautus = &g_instance_group_report_status_ptr[groupIndex].instance_status;
    errno_t rc = snprintf_s(statusKey, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/CMServer/DnExpectSyncList", pw->pw_name);
    securec_check_intval(rc, (void)rc);
    int doResult = SetExceptSyncListStatusValue(statusValue, sizeof(statusValue), groupIndex, statusInstance);
    if (doResult == -1) {
        return false;
    }
    ResetSyncDoneFlag(groupIndex);
    status_t st = SetKV2Ddb(statusKey, MAX_PATH_LEN, statusValue, MAX_PATH_LEN, NULL);
    if (st != CM_SUCCESS) {
        write_runlog(ERROR, "%u: ddb set failed. key=%s, value=%s.\n", instanceId, statusKey, statusValue);
        return false;
    }
    write_runlog(LOG, "%u: ddb set status DnExpectSyncList success, key=%s, value=%s.\n", instanceId, statusKey,
        statusValue);
    rc = memset_s(&(dnReportStautus->exceptSyncList), sizeof(DatanodeSyncList), 0, sizeof(DatanodeSyncList));
    securec_check_errno(rc, (void)rc);
    for (int i = 0; i < statusInstance->statusDnOnline.count; ++i) {
        dnReportStautus->exceptSyncList.dnSyncList[i] = statusInstance->statusDnOnline.dnStatus[i];
    }
    dnReportStautus->exceptSyncList.count = statusInstance->statusDnOnline.count;
    return true;
}

static int32 SetExceptSyncListStatusValue(char* value, size_t len, uint32 groupIndex,
    const CurrentInstanceStatus *statusInstances)
{
    errno_t rc = memset_s(value, len, '0', len - 1);
    securec_check_errno(rc, (void)rc);
    value[len - 1] = '\0';
    const uint32 instanceId = 6001;
    uint32 curInstanceId = g_instance_role_group_ptr[groupIndex].instanceMember[0].instanceId;
    uint32 tempInstanceId = 0;
    const DatanodeDynamicStatus *online = &(statusInstances->statusDnOnline);
    for (uint32 i = 0; i < g_dynamic_header->relationCount; ++i) {
        if (g_instance_role_group_ptr[i].instanceMember[0].instanceType != INSTANCE_TYPE_DATANODE) {
            continue;
        }
        tempInstanceId = g_instance_role_group_ptr[i].instanceMember[0].instanceId;
        if (groupIndex == i) {
            if (online->count <= 0) {
                write_runlog(ERROR, "line %d, curInstanceId(%u) instanceId is %u, online is empty, "
                    "cannot set expectSyncList.\n", __LINE__, curInstanceId, tempInstanceId);
                return -1;
            }
            for (int32 j = 0; j < online->count; ++j) {
                value[online->dnStatus[j] - instanceId] = INSTANCE_DATA_REDUCED + '0';
            }
            cm_instance_report_status *reportStatus = &(g_instance_group_report_status_ptr[i].instance_status);
            for (int32 k = 0; k < reportStatus->voteAzInstance.count; ++k) {
                value[reportStatus->voteAzInstance.dnStatus[k] - instanceId] = INSTANCE_DATA_IN_VOTE + '0';
            }
        } else {
            cm_instance_report_status *reportStatus = &(g_instance_group_report_status_ptr[i].instance_status);
            if (reportStatus->exceptSyncList.count <= 0) {
                write_runlog(ERROR, "line %d, curInstanceId(%u) instanceId is %u, expectSyncList is empty, "
                    "cannot set expectSyncList.\n", __LINE__, curInstanceId, tempInstanceId);
                return -1;
            }
            for (int32 j = 0; j < reportStatus->exceptSyncList.count; ++j) {
                value[reportStatus->exceptSyncList.dnSyncList[j] - instanceId] = INSTANCE_DATA_REDUCED + '0';
            }
            for (int32 k = 0; k < reportStatus->voteAzInstance.count; ++k) {
                value[reportStatus->voteAzInstance.dnStatus[k] - instanceId] = INSTANCE_DATA_IN_VOTE + '0';
            }
        }
    }
    return 0;
}

static inline void UpdateStatusRoleByDdbValue(cm_instance_role_status *status, const char *valueOfDynConf)
{
    if (strcmp(valueOfDynConf, DELETED) == 0 && status->role != INSTANCE_ROLE_DELETED) {
        status->role = INSTANCE_ROLE_DELETED;
    }
    if (strcmp(valueOfDynConf, DELETING) == 0 && status->role != INSTANCE_ROLE_DELETING) {
        status->role = INSTANCE_ROLE_DELETING;
    }
    if (strcmp(valueOfDynConf, NORMAL) == 0 && status->role != INSTANCE_ROLE_NORMAL) {
        status->role = INSTANCE_ROLE_NORMAL;
    }
    /* other case will be added here */
}

void GetCoordinatorDynamicConfigChangeFromDdb(uint32 groupIdx)
{
    /*
     * if there is a record of CN dynamic config in ddb, it means CN has been deleted.
     * and then comparing dynamic config in ddb and local config, cm_server reloads dynamic
     * config from ddb.
     */
    if (!IsInteractWithDdb(true, true)) {
        return;
    }
    if (g_instance_role_group_ptr[groupIdx].instanceMember[0].instanceType != INSTANCE_TYPE_COORDINATE) {
        return;
    }

    if (!IsNeedSyncStRoleFromDdb(groupIdx)) {
        return;
    }
    uint32 count = GetAllInstanceCount(INSTANCE_TYPE_COORDINATE);
    status_t st = GetKeyValueMemory(groupIdx, count);
    if (st != CM_SUCCESS) {
        return;
    }
    cm_instance_report_status *reportSt = &(g_instance_group_report_status_ptr[groupIdx].instance_status);
    DDB_RESULT dbResult = SUCCESS_GET_VALUE;
    st = GetInstStatusKeyValueFromDdb(reportSt->keyValue, count, &dbResult, INSTANCE_TYPE_COORDINATE);
    bool cmsSyncFromDdbFlag = true;
    if (st == CM_SUCCESS) {
        SyncCnInstanceStatusFromDdb(groupIdx, &cmsSyncFromDdbFlag, reportSt->keyValue, count);
        (void)WriteDynamicConfigFile(false);
        if (cmsSyncFromDdbFlag) {
            SetSyncLock(groupIdx, cmsSyncFromDdbFlag, INSTANCE_TYPE_COORDINATE);
            return;
        }
    }
    if (g_HA_status->local_role != CM_SERVER_PRIMARY) {
        write_runlog(ERROR, "failed to get ddb value of CN, error info:%d\n", dbResult);
        return;
    }
    if (!cmsSyncFromDdbFlag || (st != CM_SUCCESS && dbResult == CAN_NOT_FIND_THE_KEY)) {
        SetStaticRoleToDdb(groupIdx, INSTANCE_TYPE_COORDINATE);
        cmsSyncFromDdbFlag = true;
    } else {
        cmsSyncFromDdbFlag = false;
        write_runlog(ERROR, "failed to get ddb value of CN, error info:%d\n", dbResult);
    }
    SetSyncLock(groupIdx, cmsSyncFromDdbFlag, INSTANCE_TYPE_COORDINATE);
}

static bool CheckTotalTermValid()
{
    uint32 term = g_dynamic_header->term;
    if (term >= FirstTerm) {
        return true;
    }
    for (uint32 i = 0; i < g_dynamic_header->relationCount; i++) {
        if (g_instance_role_group_ptr[i].instanceMember[0].instanceType != INSTANCE_TYPE_DATANODE) {
            continue;
        }
        for (int j = 0; j < g_instance_role_group_ptr[i].count; j++) {
            if (g_instance_group_report_status_ptr[i].instance_status.data_node_member[j].local_status.term >
                FirstTerm) {
                write_runlog(FATAL, "We are in danger of a term-rollback. Abort this arbitration!\n");
                return false;
            }
        }
    }
    return true;
}

static bool CheckCurrentTermValid(uint32 groupIndex)
{
    uint32 term = g_dynamic_header->term;
    if (!CheckTotalTermValid()) {
        return false;
    }

    if (term == CM_UINT32_MAX) {
        write_runlog(FATAL, "Term value is the max. Abort this arbitration!\n");
        return false;
    }

    term++;
    if (term < g_instance_group_report_status_ptr[groupIndex].instance_status.term) {
        write_runlog(ERROR, "line %d: memory term(%u) is smaller than group term(%u)!.\n",
            __LINE__, term, g_instance_group_report_status_ptr[groupIndex].instance_status.term);
        return false;
    }

    return true;
}

static uint32 ReadTermByMinority()
{
    (void)pthread_rwlock_wrlock(&term_update_rwlock);
    write_runlog(LOG,
        "Minority AZ Force Starting. In ReadTermFromDdb() read term in minority mode. current_term:%u/%u\n",
        g_dynamic_header->term,
        g_termCache);
    /* increase term value in case of minority mode */
    if (g_dynamic_header->term >= (g_termCache - 1)) {
        if (!IncrementTermToFile()) {
            (void)pthread_rwlock_unlock(&term_update_rwlock);
            write_runlog(ERROR, "Minority AZ Force Starting. IncrementTermToFile Failed\n");
            return InvalidTerm;
        }
    }
    g_dynamic_header->term++;
    uint32 term = g_dynamic_header->term;
    (void)pthread_rwlock_unlock(&term_update_rwlock);
    /* update term value into dynamic config file */
    return term;
}

/* This function serves as a helper function for each place that needs only to read term from DDB (with read lock) */
uint32 ReadTermFromDdb(uint32 groupIdx)
{
    uint32 term = InvalidTerm;
    /* In in miniority mode we assume DDB is not available */
    if (cm_arbitration_mode == MINORITY_ARBITRATION) {
        return ReadTermByMinority();
    }

    /* In primary-standby-dummystandby mode, term is set to FirstTerm which is 1. */
    if (!g_multi_az_cluster || !IsNeedSyncDdb() || IsBoolCmParamTrue(g_enableDcf)) {
        return FirstTerm;
    }

    (void)pthread_rwlock_wrlock(&term_update_rwlock);
    if (g_arbitrationChangedFromMinority && (SetTermIfArbitrationChanged(&term) != 0)) {
        (void)pthread_rwlock_unlock(&term_update_rwlock);
        return InvalidTerm;
    }

    if (g_needIncTermToDdbAgain) {
        if (IncrementTermToDdb() != 0) {
            (void)pthread_rwlock_unlock(&term_update_rwlock);
            return InvalidTerm;
        }
    }

    if (!CheckCurrentTermValid(groupIdx)) {
        (void)pthread_rwlock_unlock(&term_update_rwlock);
        return InvalidTerm;
    }

    term = g_dynamic_header->term;
    term++;
    if (term % CM_INCREMENT_TERM_VALUE == 0) {
        if (SetTermToDdb(term) != 0) {
            (void)pthread_rwlock_unlock(&term_update_rwlock);
            return InvalidTerm;
        }
    }

    write_runlog(DEBUG1, "memory current term is %u.\n", term);
    g_dynamic_header->term = term;
    (void)pthread_rwlock_unlock(&term_update_rwlock);

    return term;
}

static int GetTermFromDdb(uint32 *term, bool &firstStart)
{
    char statusKey[MAX_PATH_LEN] = {0};
    char getValue[DDB_MIN_VALUE_LEN] = {0};
    firstStart = false;

    errno_t rc = snprintf_s(statusKey, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/CMServer/status_key/term", pw->pw_name);
    securec_check_intval(rc, (void)rc);
    DDB_RESULT dbResult = SUCCESS_GET_VALUE;
    status_t st = GetKVAndLogLevel(statusKey, getValue, DDB_MIN_VALUE_LEN, &dbResult, LOG);
    if (st != CM_SUCCESS) {
        *term = InvalidTerm;
        write_runlog(ERROR, "get ddb key %s error %d\n", statusKey, dbResult);
        firstStart = (dbResult == CAN_NOT_FIND_THE_KEY);
        return -1;
    }

    *term = (uint32)strtoul(getValue, NULL, 0);
    return 0;
}

static uint32 GetMaxGroupTerm()
{
    uint32 maxGrpTerm = InvalidTerm;
    for (uint32 i = 0; i < g_dynamic_header->relationCount; i++) {
        if (g_instance_role_group_ptr[i].instanceMember[0].instanceType != INSTANCE_TYPE_DATANODE) {
            continue;
        }
        if (g_instance_group_report_status_ptr[i].instance_status.term > maxGrpTerm) {
            maxGrpTerm = g_instance_group_report_status_ptr[i].instance_status.term;
        }
    }
    return maxGrpTerm;
}

int SetTermIfArbitrationChanged(uint32* term)
{
    /*
     * If we get here, we must be in MAJORITY scenario so DDB is available and the term
     * value we fetched here need further
     */
    uint32 ddbTerm = InvalidTerm;
    bool firstStart = false;
    int res = GetTermFromDdb(&ddbTerm, firstStart);
    if (res != 0) {
        write_runlog(ERROR, "Cannot term information from ddb while arbitration changed to majorrity.\n");
        return -1;
    }

    uint32 currentTerm = g_dynamic_header->term;

    write_runlog(LOG, "Minority AZ Force Starting. "
        "Go back to majority mode to check term sync-up to ddb current_term:%u ddbTerm:%u\n",
        currentTerm, ddbTerm);

    /*
     * Check if current term is greater than that read from in DDB, if yes it
     * indicates there is DN primary & standby exchange after switch to MINORITY,
     * so we have to sync its newest term value into DDB
     *
     * Note: g_dynamic_header->term is always up-to-date, we set it in caller
     * function ReadTermFromDdb()
     */
    if (currentTerm > ddbTerm) {
        if (currentTerm == CM_UINT32_MAX) {
            write_runlog(FATAL, "line %d:Term value is the max. Abort this arbitration!\n", __LINE__);
            return -1;
        }
        ddbTerm = currentTerm + 1;
    } else {
        write_runlog(ERROR, "line %d:ddbTerm %u is greater than memory currnent term %u, It should not happen.\n",
            __LINE__, ddbTerm, currentTerm);
        if (ddbTerm >= CM_UINT32_MAX - CM_INCREMENT_TERM_VALUE) {
            write_runlog(FATAL, "line %d:get term from ddb value %u is too big "
                    "while processing arbitration changing.\n", __LINE__, ddbTerm);
            return -1;
        }
        ddbTerm += CM_INCREMENT_TERM_VALUE;
    }

    uint32 maxGrpTerm = GetMaxGroupTerm();
    if (ddbTerm < maxGrpTerm) {
        write_runlog(ERROR, "line %d: DDB term(%u) is smaller than group term(%u).\n", __LINE__, ddbTerm, maxGrpTerm);
        return -1;
    }

    if (SetTermToDdb(ddbTerm) != 0) {
        return -1;
    }

    g_dynamic_header->term = ddbTerm;
    /*
     * Mark minority2majority flag to false, from now we go regular DDB-term
     * fetching processing code path
     */
    g_arbitrationChangedFromMinority = false;
    /* Remove the for start info file after we use it */
    (void)unlink(cm_force_start_file_path);
    *term = ddbTerm;

    return 0;
}

int SetTermToDdb(uint32 term)
{
    char statusKey[MAX_PATH_LEN] = {0};
    char termValue[MAX_PATH_LEN] = {0};
    errno_t rc;

    rc = snprintf_s(statusKey, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/CMServer/status_key/term", pw->pw_name);
    securec_check_intval(rc, (void)rc);
    rc = snprintf_s(termValue, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%u", term);
    securec_check_intval(rc, (void)rc);

    status_t st = SetKV2Ddb(statusKey, MAX_PATH_LEN, termValue, MAX_PATH_LEN, NULL);
    if (st != CM_SUCCESS) {
        write_runlog(ERROR, "%d: set ddb term failed. key = %s, term = %u.\n", __LINE__, statusKey, term);
        return -1;
    }

    write_runlog(DEBUG1, "%d: set ddb term Success. key = %s, term = %u.\n", __LINE__, statusKey, term);
    return 0;
}

int SetFirstTermToDdb()
{
    uint32 term = FirstTerm;
    if (SetTermToDdb(term) != 0) {
        write_runlog(ERROR, "%d: Failed to set first term to ddb when first start ", __LINE__);
        return -1;
    }
    g_dynamic_header->term = term;
    write_runlog(LOG, "%d: set first term to ddb success. term = %u.\n", __LINE__, term);

    return 0;
}

int IncrementTermToDdb(uint32 incTerm)
{
    uint32 term = 0;
    bool firstStart = false;
    int ret = GetTermFromDdb(&term, firstStart);
    if (ret != 0) {
        if (firstStart && SetFirstTermToDdb() == 0) {
            g_needIncTermToDdbAgain = false;
            return 0;
        }
        g_needIncTermToDdbAgain = true;
        return -1;
    } else if (term == InvalidTerm || term >= CM_UINT32_MAX - CM_INCREMENT_TERM_VALUE) {
        write_runlog(ERROR, "Cannot get valid term information %u from ddb while trying to increment term.\n", term);
        g_needIncTermToDdbAgain = true;
        return -1;
    }

    term += incTerm;
    if (SetTermToDdb(term) != 0) {
        g_needIncTermToDdbAgain = true;
        return -1;
    }

    g_dynamic_header->term = term;
    g_needIncTermToDdbAgain = false;
    write_runlog(
        LOG, "Success set term to ddb, ddb term is %u, current term is %u\n", term, g_dynamic_header->term);

    return 0;
}

/* set static primary role and set other gtm static standby role, keep atomicity */
void SetStaticPrimaryRole(const uint32 groupIndex, const int staticPrimaryIndex)
{
    int count = g_instance_role_group_ptr[groupIndex].count;
    for (int i = 0; i < count; i++) {
        g_instance_role_group_ptr[groupIndex].instanceMember[i].role = INSTANCE_ROLE_STANDBY;
        if (i == staticPrimaryIndex) {
            g_instance_role_group_ptr[groupIndex].instanceMember[i].role = INSTANCE_ROLE_PRIMARY;
        }
    }
    return;
}

bool IsGetGtmKVFromDdb(uint32 groupIndex)
{
    /* if there is a record of GTM dynamic config in ddb, it means GTM has ever switched over.
     * and then comparing dynamic config in ddb and local config, cm_server reloads dynamic
     * config from ddb.
     */
    bool isSetKV = !IsInteractWithDdb(true, true) ||
                   (g_instance_role_group_ptr[groupIndex].instanceMember[0].instanceType != INSTANCE_TYPE_GTM);
    if (isSetKV) {
        return true;
    }

    if (g_HA_status->local_role == CM_SERVER_PRIMARY &&
        g_instance_group_report_status_ptr[groupIndex].instance_status.ddbSynced == 1) {
        return true;
    }
    return false;
}

static void SyncGtmStaticRole(uint32 groupIdx, DrvKeyValue *keyValue, uint32 len)
{
    uint32 idx = 0;
    bool allSuccess = true;
    int32 logLevel = (g_HA_status->local_role == CM_SERVER_PRIMARY) ? LOG : DEBUG1;
    for (int i = 0; i < g_instance_role_group_ptr[groupIdx].count; i++) {
        cm_instance_role_status* status = &g_instance_role_group_ptr[groupIdx].instanceMember[i];
        status_t st = GetIdxFromKeyValue(keyValue, len, status->instanceId, &idx);
        if (st == CM_SUCCESS) {
            if (!IsUpdateStRoleWithDdbRole(groupIdx, i)) {
                continue;
            }
            write_runlog(logLevel, "cm server role(%d): sync dynamic config(%s) of GTM(%u) from ddb.\n",
                g_HA_status->local_role, keyValue[idx].value, status->instanceId);
            if (strcmp(keyValue[idx].value, PRIMARY) == 0 && status->role == INSTANCE_ROLE_STANDBY) {
                SetStaticPrimaryRole(groupIdx, i);
            } else if (strcmp(keyValue[idx].value, STANDBY) == 0 && status->role == INSTANCE_ROLE_PRIMARY) {
                status->role = INSTANCE_ROLE_STANDBY;
            }
            (void)WriteDynamicConfigFile(false);
        } else {
            /* dynamic config only exists when the GTM has ever switched over. */
            write_runlog(DEBUG1, "sync dynamic config from ddb of GTM failed.\n");
        }
    }
    SetSyncLock(groupIdx, allSuccess, INSTANCE_TYPE_GTM);
}

static void GetGtmStaticRoleFromDdb(uint32 groupIdx)
{
    // double check
    if (!IsNeedSyncStRoleFromDdb(groupIdx)) {
        return;
    }
    int32 count = g_instance_role_group_ptr[groupIdx].count;
    status_t st = GetKeyValueMemory(groupIdx, (uint32)count);
    if (st != CM_SUCCESS) {
        return;
    }
    DDB_RESULT dbResult = SUCCESS_GET_VALUE;
    cm_instance_report_status *reportSt = &(g_instance_group_report_status_ptr[groupIdx].instance_status);
    st = GetInstStatusKeyValueFromDdb(reportSt->keyValue, (uint32)count, &dbResult, INSTANCE_TYPE_GTM);
    if (st != CM_SUCCESS) {
        /* only cms primary can set init gtm static role to ddb */
        if (dbResult == CAN_NOT_FIND_THE_KEY && (g_HA_status->local_role == CM_SERVER_PRIMARY)) {
            SetStaticRoleToDdb(groupIdx, INSTANCE_TYPE_GTM);
            SetSyncLock(groupIdx, true, INSTANCE_TYPE_GTM);
        }
        write_runlog(ERROR, "cannot find the ddb value of GTM, error info is %d.\n", dbResult);
        return;
    }
    SyncGtmStaticRole(groupIdx, reportSt->keyValue, (uint32)count);
    return;
}

void GetGtmDynamicConfigChangeFromDdb(uint32 groupIdx)
{
    if (IsGetGtmKVFromDdb(groupIdx)) {
        return;
    }

    (void)pthread_rwlock_wrlock(&(g_instance_group_report_status_ptr[groupIdx].lk_lock));
    GetGtmStaticRoleFromDdb(groupIdx);
    (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[groupIdx].lk_lock));
}

bool IsSetKV2Ddb(uint32 groupIndex, int memberIndex)
{
    if (!IsNeedSyncDdb()) {
        g_instance_group_report_status_ptr[groupIndex].instance_status.command_member[memberIndex].role_changed =
            INSTANCE_ROLE_NO_CHANGE;
        return false;
    }
    bool isDdbHealth = IsDdbHealth(DDB_PRE_CONN);
    if (!isDdbHealth) {
        write_runlog(ERROR, "the ddb cluster is not health, isDdbHealth is: %d, %d.\n",  isDdbHealth, g_dbType);
        return false;
    }
    return true;
}

static void GetDnDdbKey(char *key, uint32 len, const cm_instance_role_status *status)
{
    errno_t rc = 0;
    if ((undocumentedVersion == 0 || undocumentedVersion >= 92214) && g_multi_az_cluster) {
        rc = snprintf_s(key, len, len - 1, "/%s/dynamic_config/datanode_status", pw->pw_name);
        securec_check_intval(rc, (void)rc);
    } else {
        rc = snprintf_s(key, len, len - 1, "/%s/dynamic_config/datanodes/%u", pw->pw_name, status->instanceId);
        securec_check_intval(rc, (void)rc);
    }
}

static void GetCnDdbKey(char *key, uint32 len, const cm_instance_role_status *status)
{
    errno_t rc = 0;
    if (undocumentedVersion == 0 || undocumentedVersion >= 92214) {
        rc = snprintf_s(key, len, len - 1, "/%s/dynamic_config/coordinator_status", pw->pw_name);
        securec_check_intval(rc, (void)rc);
    } else {
        rc = snprintf_s(key, len, len - 1, "/%s/dynamic_config/coordinators/%u", pw->pw_name, status->instanceId);
        securec_check_intval(rc, (void)rc);
    }
}

static status_t GetKeyOfDynamicConfig(char *key, uint32 len, const cm_instance_role_status *status)
{
    if (key == NULL) {
        write_runlog(ERROR, "cannot get Key Of Dynamic Config, because key is NULL.\n");
        return CM_ERROR;
    }
    switch (status->instanceType) {
        case INSTANCE_TYPE_GTM: {
            errno_t rc = snprintf_s(key, len, len - 1, "/%s/dynamic_config/GTM/%u", pw->pw_name, status->instanceId);
            securec_check_intval(rc, (void)rc);
            break;
        }
        case INSTANCE_TYPE_DATANODE:
            GetDnDdbKey(key, len, status);
            break;
        case INSTANCE_TYPE_COORDINATE:
            GetCnDdbKey(key, len, status);
            break;
        default:
            write_runlog(ERROR, "line %s:%d, undefined instdType(%d).\n", __FUNCTION__, __LINE__, status->instanceType);
            return CM_ERROR;
    }
    if (strlen(key) == 0) {
        write_runlog(ERROR, "cannot get Key Of Dynamic Config, because key(%s) length is 0.\n", key);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t GetValueInSegment(char *value, uint32 len, const cm_instance_role_status *status)
{
    errno_t rc = 0;
    switch (status->role) {
        case INSTANCE_ROLE_DELETED:
            rc = strcpy_s(value, len, DELETED);
            break;
        case INSTANCE_ROLE_DELETING:
            rc = strcpy_s(value, len, DELETING);
            break;
        case INSTANCE_ROLE_NORMAL:
            rc = strcpy_s(value, len, NORMAL);
            break;
        case INSTANCE_ROLE_PRIMARY:
            rc = strcpy_s(value, len, PRIMARY);
            break;
        case INSTANCE_ROLE_STANDBY:
            rc = strcpy_s(value, len, STANDBY);
            break;
        case INSTANCE_ROLE_DUMMY_STANDBY:
            rc = strcpy_s(value, len, "SECONDARY");
            break;
        case INSTANCE_ROLE_UNKNOWN:
            rc = strcpy_s(value, len, UNKNOWN);
            break;
        default:
            write_runlog(ERROR, "line %s:%d, wrong instance role: %d.\n", __FUNCTION__, __LINE__, status->role);
            return CM_ERROR;
    }
    securec_check_errno(rc, (void)rc);
    return CM_SUCCESS;
}

static void GetDnValueofDyConfNew(char *value, uint32 len)
{
    /* initialize value, '0' means null. eg. INSTANCE_ROLE_PRIMARY means '1' */
    errno_t rc = memset_s(value, len, '0', len - 1);
    securec_check_errno(rc, (void)rc);
    for (uint32 groupIdx = 0; groupIdx < g_dynamic_header->relationCount; groupIdx++) {
        cm_instance_role_group *dnRoleGroup = &g_instance_role_group_ptr[groupIdx];
        if (dnRoleGroup->instanceMember[0].instanceType != INSTANCE_TYPE_DATANODE) {
            continue;
        }
        for (int32 memIdx = 0; memIdx < dnRoleGroup->count; memIdx++) {
            uint32 dnIdx = dnRoleGroup->instanceMember[memIdx].instanceId - FIRST_DN;
            if (dnIdx >= len) {
                continue;
            }
            value[dnIdx] = GetDbStaticRoleStr(dnRoleGroup->instanceMember[memIdx].role);
            write_runlog(DEBUG1, "line : %d DN index : %u  value is %c.\n", __LINE__, dnIdx, value[dnIdx]);
        }
    }
}

static status_t GetDnValueofDyConf(uint32 groupIdx, int32 memIdx, char *value, uint32 len)
{
    if ((undocumentedVersion == 0 || undocumentedVersion >= 92214) && g_one_master_multi_slave) {
        GetDnValueofDyConfNew(value, len);
        return CM_SUCCESS;
    }
    cm_instance_role_status *status = &g_instance_role_group_ptr[groupIdx].instanceMember[memIdx];
    return GetValueInSegment(value, len, status);
}

static status_t GetCnValueOfDyConf(uint32 groupIdx, int32 memIdx, char *value, uint32 len)
{
    const uint32 firstCn = 5001;
    if (undocumentedVersion == 0 || undocumentedVersion >= 92214) {
        /* initialize value, '0' means null */
        errno_t rc = memset_s(value, len, '0', len - 1);
        securec_check_errno(rc, (void)rc);

        for (uint32 groupIndex = 0; groupIndex < g_dynamic_header->relationCount; groupIndex++) {
            /*
             * set coordinator status on ddb value, cn_index means the position of values.
             * eg. INSTANCE_ROLE_DELETED means '7'
             */
            cm_instance_role_status *cnStatus = &g_instance_role_group_ptr[groupIndex].instanceMember[0];
            if (cnStatus->instanceType != INSTANCE_TYPE_COORDINATE) {
                continue;
            }
            uint32 cn_index = cnStatus->instanceId - firstCn;
            if (cn_index >= len) {
                continue;
            }
            value[cn_index] = '0' + cnStatus->role;
        }
        return CM_SUCCESS;
    }
    cm_instance_role_status *status = &g_instance_role_group_ptr[groupIdx].instanceMember[memIdx];
    return GetValueInSegment(value, len, status);
}

static status_t GetValueofDynamicConfig(uint32 groupIdx, int32 memIdx, char *value, uint32 len)
{
    /* if GTM or DN switched over, set the new role to ddb. */
    cm_instance_role_status *status = &g_instance_role_group_ptr[groupIdx].instanceMember[memIdx];
    status_t st = CM_SUCCESS;
    switch (status->instanceType) {
        case INSTANCE_TYPE_GTM:
            st = GetValueInSegment(value, len, status);
            break;
        case INSTANCE_TYPE_DATANODE:
            st = GetDnValueofDyConf(groupIdx, memIdx, value, len);
            break;
        case INSTANCE_TYPE_COORDINATE:
            st = GetCnValueOfDyConf(groupIdx, memIdx, value, len);
            break;
        default:
            write_runlog(ERROR, "line %s:%d, wrong instance type: %d.\n", __FUNCTION__, __LINE__, status->instanceType);
            return CM_ERROR;
    }
    if (value == NULL || strlen(value) == 0) {
        write_runlog(ERROR, "cannot Get Value of Dynamic Config, because value(%s) is NULL.\n", value);
    }
    return st;
}

void SetDynamicConfigChangeToDdb(uint32 groupIdx, int32 memIdx)
{
    if (!IsSetKV2Ddb(groupIdx, memIdx)) {
        return;
    }

    /* if GTM or DN switched over, set the new role to ddb. */
    cm_instance_role_status *status = &g_instance_role_group_ptr[groupIdx].instanceMember[memIdx];
    char key[MAX_PATH_LEN] = {0};
    char value[MAX_PATH_LEN] = {0};

    status_t st = GetKeyOfDynamicConfig(key, MAX_PATH_LEN, status);
    if (st != CM_SUCCESS) {
        write_runlog(ERROR, "cannot get key of dynamic config.\n");
        return;
    }
    st = GetValueofDynamicConfig(groupIdx, memIdx, value, MAX_PATH_LEN);
    if (st != CM_SUCCESS) {
        write_runlog(ERROR, "cannot get value of dynamic config.\n");
        return;
    }
    write_runlog(LOG, "instd(%u) success to set key(%s) and Value(%s).\n", status->instanceId, key, value);
    st = SetKV2Ddb(key, MAX_PATH_LEN, value, MAX_PATH_LEN, NULL);
    write_runlog(LOG, "instd(%u) set key(%s), value(%s) to ddb, and get the result is %d.\n", status->instanceId, key,
        value, st);

    if (st != CM_SUCCESS) {
        write_runlog(ERROR, "%d: ddb set failed. key = %s, value = %s.\n", __LINE__, key, value);
    } else {
        SetSyncLock(groupIdx, true, status->instanceType);
        g_instance_group_report_status_ptr[groupIdx].instance_status.command_member[memIdx].role_changed =
            INSTANCE_ROLE_NO_CHANGE;
    }
}

int SetReplaceCnStatusToDdb()
{
    errno_t rc;
    uint32 cnFisrtId = 5001;

    if (!IsNeedSyncDdb()) {
        return 0;
    }
    bool isDdbHealth = IsDdbHealth(DDB_PRE_CONN);
    if (!isDdbHealth) {
        write_runlog(ERROR, "set replace cn status: ddb cluster is not health.\n");
        return -1;
    }

    char keyOfDynamicConfig[MAX_PATH_LEN] = {0};
    char valueOfDynamicConfig[MAX_PATH_LEN] = {0};
	/* initialize value, '0' means null */
    rc = memset_s(valueOfDynamicConfig, sizeof(valueOfDynamicConfig), '0',
                  sizeof(valueOfDynamicConfig) - 1);
    securec_check_errno(rc, (void)rc);
    rc = snprintf_s(keyOfDynamicConfig, MAX_PATH_LEN, MAX_PATH_LEN - 1,
                    "/%s/dynamic_config/coordinator_status", pw->pw_name);
    securec_check_intval(rc, (void)rc);
    for (uint32 groupIndex = 0; groupIndex < g_dynamic_header->relationCount; groupIndex++) {
        /*
         * set coordinator status on ddb value, cn_index means the position of values.
         * eg. INSTANCE_ROLE_DELETED means '7'
         */
        cm_instance_role_status *cnStatus = &g_instance_role_group_ptr[groupIndex].instanceMember[0];
        if (cnStatus->instanceType == INSTANCE_TYPE_COORDINATE) {
            uint32 cn_index = cnStatus->instanceId - cnFisrtId;
            valueOfDynamicConfig[cn_index] = '0' + cnStatus->role;
        }
    }

    status_t st = SetKV2Ddb(keyOfDynamicConfig, MAX_PATH_LEN, valueOfDynamicConfig, MAX_PATH_LEN, NULL);
    if (st != CM_SUCCESS) {
        write_runlog(ERROR, "line:%d set ddb failed. key=%s, value=%s.\n",
            __LINE__, keyOfDynamicConfig, valueOfDynamicConfig);
        return -1;
    }

    write_runlog(LOG, "line:%d set ddb success, key=%s, value=%s.\n",
        __LINE__, keyOfDynamicConfig, valueOfDynamicConfig);
    return 0;
}

void GetReadOnlyDdbValue(const char *cnValue, const char *dnValue)
{
    int cnIndex = 0;
    int dnIndex = 0;
    for (uint32 i = 0; i < g_node_num; i++) {
        DynamicNodeReadOnlyInfo *curNodeInfo = &g_dynamicNodeReadOnlyInfo[i];
        /* CN */
        if (g_node[i].coordinate == 1) {
            if (cnValue[cnIndex] != '\0') {
                curNodeInfo->coordinateNode.ddbValue =(ReadOnlyDdbValue)(cnValue[cnIndex] - '0');
                cnIndex++;
            } else {
                curNodeInfo->coordinateNode.ddbValue = READ_ONLY_DDB_INIT;
            }
        }

        /* DN */
        for (uint32 j = 0; j < curNodeInfo->dataNodeCount; j++) {
            DataNodeReadOnlyInfo *curDn = &curNodeInfo->dataNode[j];
            if (dnValue[dnIndex] != '\0') {
                curDn->ddbValue = (ReadOnlyDdbValue)(dnValue[dnIndex] - '0');
                dnIndex++;
            } else {
                curDn->ddbValue = READ_ONLY_DDB_INIT;
            }
        }
    }
}

status_t GetNodeReadOnlyStatusFromDdb()
{
    char cnValue[MAX_PATH_LEN] = {0};
    char dnValue[MAX_PATH_LEN] = {0};
    DDB_RESULT dbResult = SUCCESS_GET_VALUE;

    char dnKey[MAX_PATH_LEN] = {0};
    errno_t rc = snprintf_s(dnKey, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/CMServer/DnReadOnlyStatus", pw->pw_name);
    securec_check_intval(rc, (void)rc);
    status_t st = GetKVFromDDb(dnKey, MAX_PATH_LEN, dnValue, MAX_PATH_LEN, &dbResult);
    if (st != CM_SUCCESS && dbResult == FAILED_GET_VALUE) {
        write_runlog(LOG, "[%s] key:[%s] error:[%d]\n", __FUNCTION__, dnKey, (int)dbResult);
        return CM_ERROR;
    }
#ifdef ENABLE_MULTIPLE_NODES
    char cnKey[MAX_PATH_LEN] = {0};
    rc = snprintf_s(cnKey, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/CMServer/CnReadOnlyStatus", pw->pw_name);
    securec_check_intval(rc, (void)rc);
    st = GetKVFromDDb(cnKey, MAX_PATH_LEN, cnValue, MAX_PATH_LEN, &dbResult);
    if (st != CM_SUCCESS && dbResult == FAILED_GET_VALUE) {
        write_runlog(LOG, "[%s] key:[%s] error:[%d]\n", __FUNCTION__, cnKey, (int)dbResult);
        return CM_ERROR;
    }
#endif
    GetReadOnlyDdbValue(cnValue, dnValue);
    return CM_SUCCESS;
}

static status_t GetKerberosValueFromDDb(char *value, uint32 len, int32 idx)
{
    errno_t rc = memset_s(value, len, 0, len);
    securec_check_errno(rc, (void)rc);
    char kerberosKey[MAX_PATH_LEN] = {0};
    rc = snprintf_s(kerberosKey, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/kerberosKey%d", pw->pw_name, idx);
    securec_check_intval(rc, (void)rc);
    DDB_RESULT dbResult = SUCCESS_GET_VALUE;
    status_t st = GetKVFromDDb(kerberosKey, MAX_PATH_LEN, value, len, &dbResult);
    if (st != CM_SUCCESS) {
        int logLevel = (dbResult == CAN_NOT_FIND_THE_KEY) ? ERROR : LOG;
        write_runlog(logLevel, "get kerberos info %s from ddb: %d\n", kerberosKey, dbResult);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

void CmsGetKerberosInfoFromDdb()
{
    char kerberosValue[MAX_PATH_LEN] = {0};
    char *tempPtr = NULL;
    char *outPtr = NULL;
    char delims[] = ",";
    errno_t rc;
    status_t st = CM_SUCCESS;
    for (int i = 0; i < KERBEROS_NUM; i++) {
        st = GetKerberosValueFromDDb(kerberosValue, MAX_PATH_LEN, i);
        if (st != CM_SUCCESS) {
            continue;
        }
        if (strcmp(kerberosValue, "0") == 0) {
            return;
        }
        /* get kerberos node */
        tempPtr = strtok_r(kerberosValue, delims, &outPtr);
        if (tempPtr == NULL) {
            write_runlog(ERROR, "/%s/kerberosKey%d get ddb node.\n", pw->pw_name, i);
            return;
        }
        g_kerberos_group_report_status.kerberos_status.node[i] = (uint32)strtol(tempPtr, NULL, 10);
        /* get kerberos nodeName */
        tempPtr = strtok_r(NULL, delims, &outPtr);
        if (tempPtr == NULL || strlen(tempPtr) > CM_NODE_NAME) {
            write_runlog(ERROR, "/%s/kerberosKey%d get ddb nodename(%s).\n", pw->pw_name, i, tempPtr);
            return;
        }
        rc = strncpy_s(g_kerberos_group_report_status.kerberos_status.nodeName[i],
            CM_NODE_NAME, tempPtr, strlen(tempPtr));
        securec_check_errno(rc, (void)rc);
        /* get kerberos kerberos_ip */
        tempPtr = strtok_r(NULL, delims, &outPtr);
        if (tempPtr == NULL || strlen(tempPtr) > CM_IP_LENGTH) {
            write_runlog(ERROR, "/%s/kerberosKey%d get ddb ip(%s).\n", pw->pw_name, i, tempPtr);
            return;
        }
        rc = strncpy_s(g_kerberos_group_report_status.kerberos_status.kerberos_ip[i],
            CM_IP_LENGTH, tempPtr, strlen(tempPtr));
        securec_check_errno(rc, (void)rc);
        /* get kerberos port */
        tempPtr = strtok_r(NULL, delims, &outPtr);
        if (tempPtr == NULL) {
            write_runlog(ERROR, "/%s/kerberosKey%d get ddb port.\n", pw->pw_name, i);
            return;
        }
        g_kerberos_group_report_status.kerberos_status.port[i] = (uint32)strtol(tempPtr, NULL, 10);
    }
    return;
}
bool GetFinishRedoFlagFromDdb(uint32 groupIdx)
{
    if (!IsNeedSyncDdb() ||
        g_instance_role_group_ptr[groupIdx].instanceMember[0].instanceType != INSTANCE_TYPE_DATANODE) {
        return false;
    }
    char statusKey[MAX_PATH_LEN] = {0};
    char statusVaule[DDB_MIN_VALUE_LEN] = {0};

    errno_t rc = snprintf_s(statusKey, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/finish_redo/%u", pw->pw_name,
        groupIdx);
    securec_check_intval(rc, (void)rc);
    DDB_RESULT dbResult = SUCCESS_GET_VALUE;
    (void)pthread_rwlock_rdlock(&g_finish_redo_rwlock);
    status_t st = GetKVFromDDb(statusKey, MAX_PATH_LEN, statusVaule, DDB_MIN_VALUE_LEN, &dbResult);

    (void)pthread_rwlock_unlock(&g_finish_redo_rwlock);
    if (st == CM_SUCCESS) {
        (void)pthread_rwlock_wrlock(&(g_instance_group_report_status_ptr[groupIdx].lk_lock));
        if (strcmp(statusVaule, "true") == 0) {
            g_instance_group_report_status_ptr[groupIdx].instance_status.finish_redo = true;
            write_runlog(LOG, "cm server role(%d): finish redo flag set to true from ddb.\n",
                g_HA_status->local_role);
        } else if (strcmp(statusVaule, "false") == 0) {
            g_instance_group_report_status_ptr[groupIdx].instance_status.finish_redo = false;
            write_runlog(LOG, "cm server role(%d): finish redo flag set to false from ddb.\n",
                g_HA_status->local_role);
        }
        (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[groupIdx].lk_lock));
        return true;
    } else {
        /* finish redo flag only exists when force promote function is in use. */
        write_runlog(DEBUG1, "failed get ddb value by key: %s, error info:%d\n", statusKey, dbResult);
        return false;
    }
}

bool GetFinishRedoFlagFromDdbNew()
{
    if (!IsDdbHealth(DDB_PRE_CONN)) {
        return false;
    }
    char statusKey[MAX_PATH_LEN] = {0};
    char statusValue[MAX_PATH_LEN] = {0};
    /* generate key path in ddb. */
    errno_t rc = snprintf_s(statusKey, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/finish_redo_status", pw->pw_name);
    securec_check_intval(rc, (void)rc);

    DDB_RESULT dbResult = SUCCESS_GET_VALUE;
    (void)pthread_rwlock_rdlock(&g_finish_redo_rwlock);
    status_t st = GetKVFromDDb(statusKey, MAX_PATH_LEN, statusValue, MAX_PATH_LEN, &dbResult);
    (void)pthread_rwlock_unlock(&g_finish_redo_rwlock);
    if (st != CM_SUCCESS) {
        /* finish redo flag only exists when force promote function is in use. */
        write_runlog(DEBUG1, "failed get ddb value by key: %s, error info:%d.\n", statusKey, dbResult);
        return false;
    }
    const uint32 firstDnInstd = 6001;
    for (uint32 groupIdx = 0; groupIdx < g_dynamic_header->relationCount; groupIdx++) {
        write_runlog(LOG, "cm server role(%d): instd(%u) finish redo flag set to %c from ddb.\n",
            g_HA_status->local_role, g_instance_role_group_ptr[groupIdx].instanceMember[0].instanceId,
            statusValue[groupIdx]);
        if (g_instance_role_group_ptr[groupIdx].instanceMember[0].instanceType != INSTANCE_TYPE_DATANODE) {
            continue;
        }
        /* eg. position of dn_6001: 6001-6001 = 0. */
        uint32 dn_index = g_instance_role_group_ptr[groupIdx].instanceMember[0].instanceId - firstDnInstd;
        (void)pthread_rwlock_wrlock(&(g_instance_group_report_status_ptr[groupIdx].lk_lock));
        if (statusValue[dn_index] == '1') {
            g_instance_group_report_status_ptr[groupIdx].instance_status.finish_redo = true;
        } else if (statusValue[dn_index] == '0') {
            g_instance_group_report_status_ptr[groupIdx].instance_status.finish_redo = false;
        }
        (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[groupIdx].lk_lock));
    }
    return true;
}

void SetReadOnlyDdbValue(char *cnValue, int cnValueLen, char *dnValue, int dnValueLen)
{
    int cnIndex = 0;
    int dnIndex = 0;
    for (uint32 i = 0; i < g_node_num; i++) {
        DynamicNodeReadOnlyInfo *curNodeInfo = &g_dynamicNodeReadOnlyInfo[i];
        /* CN */
        if (g_node[i].coordinate == 1) {
            if (cnIndex < cnValueLen - 1) {
                cnValue[cnIndex] = (int)curNodeInfo->coordinateNode.ddbValue + '0';
                cnIndex++;
            }
        }

        /* DN */
        for (uint32 j = 0; j < curNodeInfo->dataNodeCount; j++) {
            DataNodeReadOnlyInfo *curDn = &curNodeInfo->dataNode[j];
            if (dnIndex < dnValueLen - 1) {
                dnValue[dnIndex] = (int)curDn->ddbValue + '0';
                dnIndex++;
            }
        }
    }
    cnValue[cnIndex] = '\0';
    dnValue[dnIndex] = '\0';
}

void SetNodeReadOnlyStatusToDdb()
{
    char dnValue[MAX_PATH_LEN] = {0};
    char cnValue[MAX_PATH_LEN] = {0};

    char dnKey[MAX_PATH_LEN] = {0};
    errno_t rc = snprintf_s(dnKey, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/CMServer/DnReadOnlyStatus", pw->pw_name);
    securec_check_intval(rc, (void)rc);

    SetReadOnlyDdbValue(cnValue, MAX_PATH_LEN, dnValue, MAX_PATH_LEN);
    status_t st = SetKV2Ddb(dnKey, MAX_PATH_LEN, dnValue, MAX_PATH_LEN, NULL);
    if (st != CM_SUCCESS) {
        write_runlog(ERROR, "[%s] ddb set failed. key = %s, dn_read_only = %s.\n", __FUNCTION__, dnKey, dnValue);
    }
#ifdef ENABLE_MULTIPLE_NODES
    char cnKey[MAX_PATH_LEN] = {0};
    rc = snprintf_s(cnKey, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/CMServer/CnReadOnlyStatus", pw->pw_name);
    securec_check_intval(rc, (void)rc);
    st = SetKV2Ddb(cnKey, MAX_PATH_LEN, cnValue, MAX_PATH_LEN, NULL);
    if (st != CM_SUCCESS) {
        write_runlog(ERROR, "[%s] ddb set failed. key = %s, cn_read_only = %s.\n", __FUNCTION__, cnKey, cnValue);
    }
#endif
    return;
}

status_t TryDdbGet(const char *key, char *value, int32 maxSize, int32 tryTimes, int32 logLevel)
{
    DDB_RESULT ddbResult = SUCCESS_GET_VALUE;
    status_t st = CM_SUCCESS;
    for (int32 i = 0; i < tryTimes; i++) {
        st = GetKVAndLogLevel(key, value, (uint32)maxSize, &ddbResult, logLevel);
        if (st != CM_SUCCESS && (i != (tryTimes - 1))) {
            (void)sleep(1);
        } else {
            break;
        }
    }
    return st;
}
