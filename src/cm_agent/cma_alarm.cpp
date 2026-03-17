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
 * cma_alarm.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_agent/cma_alarm.cpp
 *
 * -------------------------------------------------------------------------
 */
#include "securec.h"
#include "alarm/alarm.h"
#include "cm/cm_elog.h"
#include "cm_ddb_adapter.h"
#include "cma_main.h"
#include "cma_global_params.h"
#include "cma_common.h"
#include "cma_alarm.h"

Alarm* g_startupAlarmList = NULL;
int g_startupAlarmListSize = 0;

Alarm* g_abnormalAlarmList = NULL;
int g_abnormalAlarmListSize = 0;

Alarm* g_abnormalCmaConnAlarmList = NULL;
int g_abnormalCmaConnAlarmListSize;

Alarm* g_abnormalBuildAlarmList = NULL;
Alarm* g_abnormalDataInstDiskAlarmList = NULL;
int g_datanodeAbnormalAlarmListSize;

Alarm* g_pgxcNodeMismatchAlarm = NULL;
Alarm* g_streamingDRAlarmList = NULL;

static THR_LOCAL Alarm* StorageScalingAlarmList = NULL;

/* init alarm info  for coordinate, datanode, gtm, cmserver */
void StartupAlarmItemInitialize(const staticNodeConfig* currentNode)
{
    g_startupAlarmListSize =
        (int)(currentNode->datanodeCount + currentNode->gtm + currentNode->coordinate + currentNode->cmServerLevel);

    if (g_startupAlarmListSize <= 0) {
        return;
    }

    g_startupAlarmList = (Alarm*)malloc(sizeof(Alarm) * (size_t)g_startupAlarmListSize);
    if (g_startupAlarmList == NULL) {
        AlarmLog(ALM_LOG, "Out of memory: StartupAlarmItemInitialize failed.\n");
        exit(1);
    }

    int alarmIndex = g_startupAlarmListSize - 1;
    if (currentNode->gtm == 1) {
        /* ALM_AI_AbnormalGTMProcess */
        AlarmItemInitialize(&(g_startupAlarmList[alarmIndex]), ALM_AI_AbnormalGTMProcess, ALM_AS_Normal, NULL);

        --alarmIndex;
    }
    if (currentNode->coordinate == 1) {
        /* ALM_AI_AbnormalCoordinatorProcess */
        AlarmItemInitialize(&(g_startupAlarmList[alarmIndex]), ALM_AI_AbnormalCoordinatorProcess, ALM_AS_Normal, NULL);

        --alarmIndex;
    }
    if (currentNode->cmServerLevel == 1) {
        /* ALM_AI_AbnormalCMSProcess */
        AlarmItemInitialize(&(g_startupAlarmList[alarmIndex]), ALM_AI_AbnormalCMSProcess, ALM_AS_Normal, NULL);

        --alarmIndex;
    }
    for (; alarmIndex >= 0; --alarmIndex) {
        /* ALM_AI_AbnormalDatanodeProcess */
        AlarmItemInitialize(&(g_startupAlarmList[alarmIndex]), ALM_AI_AbnormalDatanodeProcess, ALM_AS_Normal, NULL);
    }
}

/* init alarm info for datanode and gtm */
void AbnormalAlarmItemInitialize(const staticNodeConfig* currentNode)
{
    int alarmIndex;
    g_abnormalAlarmListSize = (int)(currentNode->datanodeCount + currentNode->gtm);

    if (g_abnormalAlarmListSize <= 0) {
        return;
    }

    if (g_single_node_cluster) {
        return;
    }

    g_abnormalAlarmList = (Alarm*)malloc(sizeof(Alarm) * (size_t)g_abnormalAlarmListSize);
    if (g_abnormalAlarmList == NULL) {
        AlarmLog(ALM_LOG, "Out of memory: AbnormalAlarmItemInitialize failed.\n");
        exit(1);
    }

    alarmIndex = g_abnormalAlarmListSize - 1;
    if (currentNode->gtm == 1) {
        /* ALM_AI_AbnormalGTMInst */
        AlarmItemInitialize(&(g_abnormalAlarmList[alarmIndex]), ALM_AI_AbnormalGTMInst, ALM_AS_Normal, NULL);
        --alarmIndex;
    }
    for (; alarmIndex >= 0; --alarmIndex) {
        /* ALM_AI_AbnormalDatanodeInst */
        AlarmItemInitialize(&(g_abnormalAlarmList[alarmIndex]), ALM_AI_AbnormalDatanodeInst, ALM_AS_Normal, NULL);
    }
}

/* init alarm info  for datanode */
void DatanodeAbnormalAlarmItemInitialize(const staticNodeConfig* currentNode)
{
    int alarmIndex;
    g_datanodeAbnormalAlarmListSize = (int)currentNode->datanodeCount;
    if (g_datanodeAbnormalAlarmListSize == 0) {
        return;
    }

    g_abnormalBuildAlarmList = (Alarm*)malloc(sizeof(Alarm) * (size_t)g_datanodeAbnormalAlarmListSize);
    g_abnormalDataInstDiskAlarmList = (Alarm*)malloc(sizeof(Alarm) * (size_t)g_datanodeAbnormalAlarmListSize);
    if (g_abnormalDataInstDiskAlarmList == NULL || g_abnormalBuildAlarmList == NULL) {
        AlarmLog(ALM_LOG, "Out of memory: DatanodeAbnormalAlarmItemInitialize failed.\n");
        exit(1);
    }

    alarmIndex = g_datanodeAbnormalAlarmListSize - 1;

    for (; alarmIndex >= 0; --alarmIndex) {
        AlarmItemInitialize(&(g_abnormalBuildAlarmList[alarmIndex]), ALM_AI_AbnormalBuild, ALM_AS_Normal, NULL);
        AlarmItemInitialize(
            &(g_abnormalDataInstDiskAlarmList[alarmIndex]), ALM_AI_AbnormalDataInstDisk, ALM_AS_Normal, NULL);
    }
}

/* init alarm info  for datanode, coordinate, gtm */
void AbnormalCmaConnAlarmItemInitialize(const staticNodeConfig* currentNode)
{
    g_abnormalCmaConnAlarmListSize = (int)(currentNode->datanodeCount + currentNode->gtm + currentNode->coordinate);

    if (g_abnormalCmaConnAlarmListSize <= 0) {
        return;
    }

    g_abnormalCmaConnAlarmList = (Alarm*)malloc(sizeof(Alarm) * (size_t)g_abnormalCmaConnAlarmListSize);
    if (g_abnormalCmaConnAlarmList == NULL) {
        AlarmLog(ALM_LOG, "Out of memory: AbnormalCmaConnAlarmItemInitialize failed.\n");
        exit(1);
    }

    int alarmIndex = g_abnormalCmaConnAlarmListSize - 1;

    for (unsigned int i = 0; i < currentNode->gtm; i++) {
        /* ALM_AI_AbnormalGTMProcess */
        AlarmItemInitialize(&(g_abnormalCmaConnAlarmList[alarmIndex]), ALM_AI_AbnormalCmaConnFail, ALM_AS_Normal, NULL);

        --alarmIndex;
    }

    for (unsigned int i = 0; i < currentNode->coordinate; i++) {
        /* ALM_AI_AbnormalCoordinatorProcess */
        AlarmItemInitialize(&(g_abnormalCmaConnAlarmList[alarmIndex]), ALM_AI_AbnormalCmaConnFail, ALM_AS_Normal, NULL);

        --alarmIndex;
    }

    for (; alarmIndex >= 0; --alarmIndex) {
        AlarmItemInitialize(&(g_abnormalCmaConnAlarmList[alarmIndex]), ALM_AI_AbnormalCmaConnFail, ALM_AS_Normal, NULL);
    }
}

void report_build_fail_alarm(AlarmType alarmType, const char *instanceName, int alarmIndex)
{
    if (alarmIndex >= g_datanodeAbnormalAlarmListSize) {
        return;
    }
    AlarmAdditionalParam tempAdditionalParam;
    /* fill the alarm message */
    WriteAlarmAdditionalInfo(&tempAdditionalParam, instanceName, "", "", "", &(g_abnormalBuildAlarmList[alarmIndex]),
        alarmType, instanceName);
    /* report the alarm */
    AlarmReporter(&(g_abnormalBuildAlarmList[alarmIndex]), alarmType, &tempAdditionalParam);
}

void report_dn_disk_alarm(AlarmType alarmType, const char *instanceName, int alarmIndex, const char *data_path)
{
    if (alarmIndex >= g_datanodeAbnormalAlarmListSize) {
        return;
    }
    AlarmAdditionalParam tempAdditionalParam;
    /* fill the alarm message */
    WriteAlarmAdditionalInfo(&tempAdditionalParam,
        instanceName,
        "",
        "",
        "",
        &(g_abnormalDataInstDiskAlarmList[alarmIndex]),
        alarmType,
        instanceName,
        data_path);
    /* report the alarm */
    AlarmReporter(&(g_abnormalDataInstDiskAlarmList[alarmIndex]), alarmType, &tempAdditionalParam);
}

Alarm *GetDdbAlarm(int index, DDB_TYPE dbType)
{
    DdbInitConfig config;
    errno_t rc = memset_s(&config, sizeof(DdbInitConfig), 0, sizeof(config));
    securec_check_errno(rc, (void)rc);
    config.type = dbType;

    DdbDriver* drv = InitDdbDrv(&config);
    if (drv == NULL) {
        write_runlog(ERROR, "InitDdbDrv failed");
        return NULL;
    }

    return DdbGetAlarm(drv, index);
}

void report_ddb_fail_alarm(AlarmType alarmType, const char *instanceName, int alarmIndex, DDB_TYPE dbType)
{
    Alarm* alarm = GetDdbAlarm(alarmIndex, dbType);
    if (alarm == NULL) {
        return;
    }

    AlarmAdditionalParam tempAdditionalParam;
    /* fill the alarm message */
    WriteAlarmAdditionalInfo(
        &tempAdditionalParam, instanceName, "", "", "", alarm, alarmType, instanceName);
    /* report the alarm */
    AlarmReporter(alarm, alarmType, &tempAdditionalParam);
}

void InitializeAlarmItem(const staticNodeConfig* currentNode)
{
    /* init alarm check, check ALM_AS_Reported state of ALM_AI_AbnormalGTMInst, ALM_AI_AbnormalDatanodeInst */
    AbnormalAlarmItemInitialize(currentNode);
    /* init alarm check, check ALM_AS_Reported state of ALM_AI_AbnormalCmaConnFail */
    AbnormalCmaConnAlarmItemInitialize(currentNode);
    /* init alarm check, check ALM_AS_Reported state of ALM_AI_AbnormalGTMInst */
    /* ALM_AI_AbnormalBuild ALM_AI_AbnormalDataInstDisk */
    DatanodeAbnormalAlarmItemInitialize(currentNode);
    /* init alarm check, check ALM_AI_PgxcNodeMismatch */
    PgxcNodeMismatchAlarmItemInitialize();
    /* init alarm check, check ALM_AI_StreamingDRCnDisconnected, ALM_AI_StreamingDRDnDisconnected */
    StreamingDRAlarmItemInitialize();
}

void StorageScalingAlarmItemInitialize(void)
{
    static const int StorageScalingAlarmListSize = 2;
    StorageScalingAlarmList = (Alarm*)malloc(sizeof(Alarm) * StorageScalingAlarmListSize);
    if (StorageScalingAlarmList == NULL) {
        AlarmLog(ALM_LOG, "Out of memort: StorageScalingAlarmList failed.\n");
        exit(1);
    }

    AlarmItemInitialize(&(StorageScalingAlarmList[0]), ALM_AI_StorageDilatationAlarmNotice, ALM_AS_Normal, NULL);
    AlarmItemInitialize(&(StorageScalingAlarmList[1]), ALM_AI_StorageDilatationAlarmMajor, ALM_AS_Normal, NULL);
}

void ReportStorageScalingAlarm(AlarmType alarmType, const char* instanceName, int alarmIndex, const char *info)
{
    AlarmAdditionalParam tempAdditionalParam;
    /* fill the alarm message. */
    WriteAlarmAdditionalInfo(
        &tempAdditionalParam, instanceName, "", "", "", &(StorageScalingAlarmList[alarmIndex]), alarmType, info);
    /* report the alarm. */
    AlarmReporter(&(StorageScalingAlarmList[alarmIndex]), alarmType, &tempAdditionalParam);
}

void ReportPgxcNodeMismatchAlarm(AlarmType alarmType, const char* instanceName)
{
    AlarmAdditionalParam tempAdditionalParam;
    /* fill the alarm message */
    WriteAlarmAdditionalInfo(
        &tempAdditionalParam, instanceName, "", "", "", g_pgxcNodeMismatchAlarm, alarmType, instanceName);
    /* report the alarm */
    AlarmReporter(g_pgxcNodeMismatchAlarm, alarmType, &tempAdditionalParam);
}

void PgxcNodeMismatchAlarmItemInitialize()
{
    g_pgxcNodeMismatchAlarm = (Alarm*)malloc(sizeof(Alarm));
    if (g_pgxcNodeMismatchAlarm == NULL) {
        AlarmLog(ALM_LOG, "Out of memory: PgxcNodeMismatchAlarmItemInitialize failed.\n");
        exit(1);
    }

    AlarmItemInitialize(g_pgxcNodeMismatchAlarm, ALM_AI_PgxcNodeMismatch, ALM_AS_Normal, NULL);
}

void ReportStreamingDRAlarm(AlarmType alarmType, const char *instanceName, int alarmIndex, const char *info)
{
    AlarmAdditionalParam tempAdditionalParam;
    /* fill the alarm message */
    WriteAlarmAdditionalInfo(
        &tempAdditionalParam, instanceName, "", "", "", &(g_streamingDRAlarmList[alarmIndex]), alarmType, info);
    /* report the alarm */
    AlarmReporter(&(g_streamingDRAlarmList[alarmIndex]), alarmType, &tempAdditionalParam);
}

void StreamingDRAlarmItemInitialize(void)
{
    int32 alarmIndex;
    uint32 streamingDRAlarmListSize = g_currentNode->datanodeCount + g_currentNode->coordinate;
    if (streamingDRAlarmListSize == 0) {
        return;
    }
    g_streamingDRAlarmList = (Alarm*)malloc(sizeof(Alarm) * streamingDRAlarmListSize);
    if (g_streamingDRAlarmList == NULL) {
        AlarmLog(ALM_LOG, "Out of memory: AbnormalAlarmItemInitialize failed.\n");
        exit(1);
    }
    alarmIndex = (int32)(streamingDRAlarmListSize - 1);
    if (g_currentNode->coordinate == 1) {
        /* ALM_AI_AbnormalGTMInst */
        AlarmItemInitialize(&(g_streamingDRAlarmList[alarmIndex]), ALM_AI_StreamingDisasterRecoveryCnDisconnected,
            ALM_AS_Normal, NULL);
        --alarmIndex;
    }
    for (; alarmIndex >= 0; --alarmIndex) {
        /* ALM_AI_AbnormalDatanodeInst */
        AlarmItemInitialize(&(g_streamingDRAlarmList[alarmIndex]), ALM_AI_StreamingDisasterRecoveryDnDisconnected,
            ALM_AS_Normal, NULL);
    }
}
