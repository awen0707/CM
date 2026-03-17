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
 * cms_alarm.cpp
 *    cms alarm functions
 *
 * IDENTIFICATION
 *    src/cm_server/cms_alarm.cpp
 *
 * -------------------------------------------------------------------------
 */

#include "alarm/alarm.h"
#include "common/config/cm_config.h"
#include "cm/cm_elog.h"
#include "cm/cm_msg.h"
#include "cms_global_params.h"
#include "cms_ddb_adapter.h"
#include "cms_common.h"
#include "cms_alarm.h"

static Alarm *g_logStorageAlarm;
static InstanceAlarm* g_readOnlyPreAlarm = NULL;
static InstanceAlarm* g_readOnlyAlarm = NULL;
static InstancePhonyDeadAlarm* g_phony_dead_alarm = NULL;
static InstanceAlarm* g_reduceSyncListAlarm = NULL;
static InstanceAlarm* g_increaseSyncListAlarm = NULL;

static int g_instance_count = 0;
static int g_dnCount = 0;

void ReportCMSAlarmNormalCluster(Alarm* alarmItem, AlarmType type, AlarmAdditionalParam* additionalParam)
{
    bool isMaintanceOrInstanceCluster = MaintanceOrInstallCluster();
    bool isUpgrade = IsUpgradeCluster();
    if (!isMaintanceOrInstanceCluster && !isUpgrade) {
        AlarmReporter(alarmItem, type, additionalParam);
    } else {
        write_runlog(ERROR,
            "Line %d:Maintaining cluster:no event alarm is generated, maintanceflag: %d, upgradeflag: %d.\n",
            __LINE__,
            isMaintanceOrInstanceCluster,
            isUpgrade);
    }
}

void ReadOnlyAlarmItemInitialize(void)
{
    uint32 readOnlyCount = MAX_DN_NUM;
    g_readOnlyAlarm = (InstanceAlarm*)malloc(sizeof(InstanceAlarm) * readOnlyCount);
    g_readOnlyPreAlarm = (InstanceAlarm*)malloc(sizeof(InstanceAlarm) * readOnlyCount);
    g_logStorageAlarm = (Alarm*)malloc(sizeof(Alarm) * CM_NODE_MAXNUM);
    if (g_readOnlyAlarm == NULL || g_readOnlyPreAlarm == NULL || g_logStorageAlarm == NULL) {
        AlarmLog(ALM_LOG, "Out of memory: ReadOnlyAlarmItemInitialize failed.\n");
        exit(1);
    }
    write_runlog(LOG, "[%s][line:%d] ReadOnlyAlarm malloc success.\n", __FUNCTION__, __LINE__);
    for (uint32 i = 0; i < CM_NODE_MAXNUM; i++) {
        AlarmItemInitialize(&(g_logStorageAlarm[i]), ALM_AI_StorageThresholdPreAlarm, ALM_AS_Normal, NULL);
    }
    for (uint32 i = 0; i < readOnlyCount; i++) {
        AlarmItemInitialize(&(g_readOnlyAlarm[i].instanceAlarmItem),
            ALM_AI_TransactionReadOnly, ALM_AS_Normal, NULL);
        AlarmItemInitialize(&(g_readOnlyPreAlarm[i].instanceAlarmItem),
            ALM_AI_StorageThresholdPreAlarm, ALM_AS_Normal, NULL);
    }
    uint32 alarmIndex = 0;
    for (uint32 i = 0; i < g_dynamic_header->relationCount; i++) {
        for (int32 j = 0; j < g_instance_role_group_ptr[i].count; j++) {
            uint32 instanceid = g_instance_role_group_ptr[i].instanceMember[j].instanceId;
            if (alarmIndex > readOnlyCount) {
                write_runlog(ERROR, "[%s] out of range %u.\n", __FUNCTION__, readOnlyCount);
                return;
            }
            if (instanceid == 0) {
                continue;
            }
            if ((g_instance_role_group_ptr[i].instanceMember[j].instanceType == INSTANCE_TYPE_DATANODE) ||
                (g_instance_role_group_ptr[i].instanceMember[j].instanceType == INSTANCE_TYPE_COORDINATE)) {
                g_readOnlyAlarm[alarmIndex].instanceId = instanceid;
                g_readOnlyPreAlarm[alarmIndex].instanceId = instanceid;
                alarmIndex++;
            }
        }
    }
}

void ReportReadOnlyAlarm(AlarmType alarmType, const char* instanceName, uint32 instanceid)
{
    uint32 readOnlyCount = MAX_DN_NUM;
    uint32 alarmIndex = 0;
    for (; alarmIndex < readOnlyCount; alarmIndex++) {
        if (instanceid == g_readOnlyAlarm[alarmIndex].instanceId) {
            break;
        }
    }
    if (alarmIndex >= readOnlyCount) {
        AlarmLog(ALM_LOG, "%s is not in g_readOnlyAlarm.\n", instanceName);
        return;
    }
    write_runlog(DEBUG1, "[%s][line:%d] instanceName:%s, instanceid:%u, alarmIndex:%u, \n",
        __FUNCTION__, __LINE__, instanceName, instanceid, alarmIndex);

    AlarmAdditionalParam tempAdditionalParam;
    /* fill the alarm message */
    WriteAlarmAdditionalInfo(&tempAdditionalParam, instanceName, "", "", "",
        &(g_readOnlyAlarm[alarmIndex].instanceAlarmItem), alarmType, instanceName);
    /* report the alarm */
    AlarmReporter(&(g_readOnlyAlarm[alarmIndex].instanceAlarmItem), alarmType, &tempAdditionalParam);
}

void ReportReadOnlyPreAlarm(AlarmType alarmType, const char* instanceName, uint32 instanceid)
{
    uint32 readOnlyCount = MAX_DN_NUM;
    uint32 alarmIndex = 0;
    for (; alarmIndex < readOnlyCount; alarmIndex++) {
        if (instanceid == g_readOnlyPreAlarm[alarmIndex].instanceId) {
            break;
        }
    }
    if (alarmIndex >= readOnlyCount) {
        AlarmLog(ALM_LOG, "%s is not in g_readOnlyPreAlarm.\n", instanceName);
        return;
    }
    write_runlog(DEBUG1, "[%s][line:%d] instanceName:%s, instanceid:%u, alarmIndex:%u, \n",
        __FUNCTION__, __LINE__, instanceName, instanceid, alarmIndex);

    AlarmAdditionalParam tempAdditionalParam;
    /* fill the alarm message */
    WriteAlarmAdditionalInfo(&tempAdditionalParam, instanceName, "", "", "",
        &(g_readOnlyPreAlarm[alarmIndex].instanceAlarmItem), alarmType, instanceName);
    /* report the alarm */
    AlarmReporter(&(g_readOnlyPreAlarm[alarmIndex].instanceAlarmItem), alarmType, &tempAdditionalParam);
}

void ReportLogStorageAlarm(AlarmType alarmType, const char* instanceName, uint32 alarmIndex)
{
    AlarmAdditionalParam tempAdditionalParam;
    /* fill the alarm message */
    WriteAlarmAdditionalInfo(&tempAdditionalParam, instanceName, "", "", "",
        &(g_logStorageAlarm[alarmIndex]), alarmType, instanceName);
    /* report the alarm */
    AlarmReporter(&(g_logStorageAlarm[alarmIndex]), alarmType, &tempAdditionalParam);
}

int GetDnCount()
{
    int dnCount = 0;
    for (uint32 i = 0; i < g_dynamic_header->relationCount; ++i) {
        if (g_instance_role_group_ptr[i].instanceMember[0].instanceType != INSTANCE_TYPE_DATANODE) {
            continue;
        }
        dnCount += g_instance_role_group_ptr[i].count;
    }
    return dnCount;
}

void AlarmInitReduceOrIncreaseSyncList()
{
    if (g_dynamic_header->relationCount == 0 || g_instance_role_group_ptr == NULL) {
        write_runlog(ALM_LOG, "g_dynamic_header init failed.\n");
        exit(1);
    }
    int dnCount = GetDnCount();
    g_dnCount = dnCount;
    errno_t rc;
    size_t alarmLen = sizeof(InstanceAlarm) * (size_t)dnCount;
    g_increaseSyncListAlarm = (InstanceAlarm *)malloc(alarmLen);
    if (g_increaseSyncListAlarm == NULL) {
        AlarmLog(ALM_LOG, "Out of memory: IncreaseSyncListAlarmItemInitialize failed.\n");
        exit(1);
    }
    g_reduceSyncListAlarm = (InstanceAlarm *)malloc(alarmLen);
    if (g_reduceSyncListAlarm == NULL) {
        AlarmLog(ALM_LOG, "Out of memory: reduceSyncListAlarmItemInitialize failed.\n");
        exit(1);
    }
    rc = memset_s(g_increaseSyncListAlarm, alarmLen, 0, alarmLen);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(g_reduceSyncListAlarm, alarmLen, 0, alarmLen);
    securec_check_errno(rc, (void)rc);
    for (int i = 0; i < dnCount; ++i) {
        AlarmItemInitialize(
            &(g_reduceSyncListAlarm[i].instanceAlarmItem), ALM_AI_DNReduceSyncList, ALM_AS_Normal, NULL);
        AlarmItemInitialize(
            &(g_increaseSyncListAlarm[i].instanceAlarmItem), ALM_AI_DNIncreaseSyncList, ALM_AS_Normal, NULL);
    }
    int alarmIndex = 0;
    for (uint32 i = 0; i < g_dynamic_header->relationCount; ++i) {
        if (g_instance_role_group_ptr[i].instanceMember[0].instanceType != INSTANCE_TYPE_DATANODE) {
            continue;
        }

        for (int j = 0; j < g_instance_role_group_ptr[i].count; ++j) {
            uint32 instanceId = g_instance_role_group_ptr[i].instanceMember[j].instanceId;
            g_increaseSyncListAlarm[alarmIndex].instanceId = instanceId;
            g_reduceSyncListAlarm[alarmIndex].instanceId = instanceId;
            alarmIndex++;
        }
    }
}

void InstanceAlarmItemInitialize(void)
{
    Assert(g_node != NULL);
    uint32 dn_count = 0;
    for (uint32 i = 0; i < g_node_num; i++) {
        dn_count += g_node[i].datanodeCount;
    }
    if (dn_count == 0) {
        write_runlog(WARNING, "this cluster has no dn, no need to init alarm item.\n");
        return;
    }
    g_instance_count = (int)(g_coordinator_num + g_gtm_num + dn_count);
    if (g_instance_count > MAX_INSTANCE_NUM) {
        write_runlog(ERROR, "total instance count %d is greater than max(%d).\n", g_instance_count, MAX_INSTANCE_NUM);
        return;
    }
    g_phony_dead_alarm = (InstancePhonyDeadAlarm *)malloc(sizeof(InstancePhonyDeadAlarm) * MAX_INSTANCE_NUM);
    if (g_phony_dead_alarm == NULL) {
        AlarmLog(ALM_LOG, "Out of memory: PhonyDeadAlarmItemInitialize failed.\n");
        exit(1);
    }

    for (int i = 0; i < MAX_INSTANCE_NUM; i++) {
        AlarmItemInitialize(
            &(g_phony_dead_alarm[i].PhonyDeadAlarmItem[0]), ALM_AI_AbnormalPhonyDead, ALM_AS_Normal, NULL);
    }

    int alarmIndex = 0;
    Assert(g_dynamic_header->relationCount > 0);
    Assert(g_instance_role_group_ptr != NULL);
    for (uint32 i = 0; i < g_dynamic_header->relationCount; i++) {
        for (int32 j = 0; j < g_instance_role_group_ptr[i].count; j++) {
            uint32 instanceid = g_instance_role_group_ptr[i].instanceMember[j].instanceId;
            if (alarmIndex >= MAX_INSTANCE_NUM) {
                write_runlog(ERROR, "out of range %d.\n", MAX_INSTANCE_NUM);
                return;
            }

            if (instanceid == 0) {
                continue;
            }
            if ((g_instance_role_group_ptr[i].instanceMember[j].instanceType == INSTANCE_TYPE_DATANODE) ||
                (g_instance_role_group_ptr[i].instanceMember[j].instanceType == INSTANCE_TYPE_GTM) ||
                (g_instance_role_group_ptr[i].instanceMember[j].instanceType == INSTANCE_TYPE_COORDINATE)) {
                g_phony_dead_alarm[alarmIndex].instanceId = instanceid;
                alarmIndex++;
            }
        }
    }

    AlarmInitReduceOrIncreaseSyncList();
}

void report_phony_dead_alarm(AlarmType alarmType, const char* instanceName, uint32 instanceid)
{
    if (g_instance_count == 0) {
        AlarmLog(ALM_LOG, "Phony dead alarm item is not initialized.\n");
        return;
    }

    int alarmIndex = 0;
    for (; alarmIndex < g_instance_count; alarmIndex++) {
        if (instanceid == g_phony_dead_alarm[alarmIndex].instanceId) {
            break;
        }
    }
    if (alarmIndex >= g_instance_count) {
        AlarmLog(ALM_LOG, "%s is not in g_phony_dead_alarm.\n", instanceName);
        return;
    }

    AlarmAdditionalParam tempAdditionalParam;
    /* fill the alarm message */
    WriteAlarmAdditionalInfo(&tempAdditionalParam,
        instanceName,
        "",
        "",
        "",
        g_phony_dead_alarm[alarmIndex].PhonyDeadAlarmItem,
        alarmType,
        instanceName);
    /* report the alarm */
    AlarmReporter(g_phony_dead_alarm[alarmIndex].PhonyDeadAlarmItem, alarmType, &tempAdditionalParam);
}

void UnbalanceAlarmItemInitialize()
{
    AlarmItemInitialize(UnbalanceAlarmItem, ALM_AI_UnbalancedCluster, ALM_AS_Normal, NULL);
}

void report_unbalanced_alarm(AlarmType alarmType)
{
    AlarmAdditionalParam tempAdditionalParam;
    /* fill the alarm message */
    WriteAlarmAdditionalInfo(&tempAdditionalParam, "", "", "", "", UnbalanceAlarmItem, alarmType);
    /* report the alarm */
    AlarmReporter(UnbalanceAlarmItem, alarmType, &tempAdditionalParam);
}

void ReportClusterDoublePrimaryAlarm(
    AlarmType alarmType, AlarmId alarmId, uint32 instanceId, const char* serviceType)
{
    AlarmItemInitialize(DoublePrimaryAlarmItem, alarmId, ALM_AS_Normal, NULL);

    char instanceInfo[RESERVE_LEN] = {0};
    int32 ret = -1;
    ret = sprintf_s(instanceInfo, RESERVE_LEN, "%s_%d", serviceType, instanceId);
    securec_check_intval(ret, (void)ret);

    AlarmAdditionalParam tempAdditionalParam;

    /* fill the alarm message */
    WriteAlarmAdditionalInfo(&tempAdditionalParam, instanceInfo, "", "", "",
        DoublePrimaryAlarmItem, alarmType, instanceInfo);
    /* report the alarm */
    AlarmReporter(DoublePrimaryAlarmItem, alarmType, &tempAdditionalParam);
}

void report_ddb_fail_alarm(AlarmType alarmType, const char* instanceName, int alarmIndex)
{
    Alarm* alarm = GetDdbAlarm(alarmIndex);
    if (alarm == NULL) {
        return;
    }

    AlarmAdditionalParam tempAdditionalParam;

    /* fill the alarm message */
    WriteAlarmAdditionalInfo(&tempAdditionalParam, instanceName, "", "", "", alarm, alarmType, instanceName);
    /* report the alarm */
    AlarmReporter(alarm, alarmType, &tempAdditionalParam);
}

void ServerSwitchAlarmItemInitialize(void)
{
    AlarmItemInitialize(ServerSwitchAlarmItem, ALM_AI_ServerSwitchOver, ALM_AS_Normal, NULL);
}

void report_server_switch_alarm(AlarmType alarmType, const char *instanceName)
{
    AlarmAdditionalParam tempAdditionalParam;
    /* fill the alarm message */
    WriteAlarmAdditionalInfo(&tempAdditionalParam, instanceName, "", "", "", ServerSwitchAlarmItem, alarmType,
        instanceName);
    /* report the alarm */
    ReportCMSAlarmNormalCluster(ServerSwitchAlarmItem, alarmType, &tempAdditionalParam);
}

void ReportIncreaseOrReduceAlarm(AlarmType alarmType, uint32 instanceId, bool isIncrease)
{
    if (g_dnCount == 0) {
        AlarmLog(ALM_LOG, "alarm item is not initialized.\n");
        return;
    }
    InstanceAlarm *instanceAlarm = (isIncrease) ? g_increaseSyncListAlarm : g_reduceSyncListAlarm;
    int alarmIndex = 0;
    for (; alarmIndex < g_dnCount; alarmIndex++) {
        if (instanceId == instanceAlarm[alarmIndex].instanceId) {
            break;
        }
    }
    if (alarmIndex >= g_dnCount) {
        AlarmLog(ALM_LOG, "%u is not in g_increaseOrReducealarm.\n", instanceId);
        return;
    }
    char instanceName[CM_NODE_NAME] = {0};
    errno_t rc = snprintf_s(instanceName, sizeof(instanceName), sizeof(instanceName) - 1, "dn_%u", instanceId);
    securec_check_intval(rc, (void)rc);
    AlarmAdditionalParam tempAdditionalParam;
    /* fill the alarm message */
    WriteAlarmAdditionalInfo(&tempAdditionalParam,
        instanceName,
        "",
        "",
        "",
        &(instanceAlarm[alarmIndex].instanceAlarmItem),
        alarmType,
        instanceName);
    /* report the alarm */
    ReportCMSAlarmNormalCluster(&(instanceAlarm[alarmIndex].instanceAlarmItem), alarmType, &tempAdditionalParam);
}

void UpdatePhonyDeadAlarm()
{
    uint32 dnCount = 0;
    uint32 i;
    int32 j;
    int alarmIndex = 0;
    uint32 instanceId;
    for (i = 0; i < g_node_num; i++) {
        dnCount += g_node[i].datanodeCount;
    }
    g_instance_count = (int)(g_coordinator_num + g_gtm_num + dnCount);
    for (i = 0; i < g_dynamic_header->relationCount; i++) {
        for (j = 0; j < g_instance_role_group_ptr[i].count; j++) {
            instanceId = g_instance_role_group_ptr[i].instanceMember[j].instanceId;
            g_phony_dead_alarm[alarmIndex].instanceId = instanceId;
            alarmIndex++;
        }
    }
    return;
}