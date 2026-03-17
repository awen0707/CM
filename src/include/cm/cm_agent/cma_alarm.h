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
 * cma_alarm.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_agent/cma_alarm.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CMA_ALARM_H
#define CMA_ALARM_H

#include "cm_ddb_adapter.h"

extern Alarm* g_startupAlarmList;
extern int g_startupAlarmListSize;

extern Alarm* g_abnormalAlarmList;
extern int g_abnormalAlarmListSize;

extern Alarm* g_abnormalCmaConnAlarmList;
extern int g_abnormalCmaConnAlarmListSize;

extern Alarm* g_abnormalBuildAlarmList;
extern Alarm* g_abnormalDataInstDiskAlarmList;
extern int g_datanodeAbnormalAlarmListSize;

extern void StorageScalingAlarmItemInitialize(void);
extern void ReportStorageScalingAlarm(AlarmType alarmType, const char* instanceName, int alarmIndex, const char *info);
extern void StartupAlarmItemInitialize(const staticNodeConfig* currentNode);
extern void AbnormalAlarmItemInitialize(const staticNodeConfig* currentNode);
extern void AbnormalCmaConnAlarmItemInitialize(const staticNodeConfig* currentNode);
extern void DatanodeAbnormalAlarmItemInitialize(const staticNodeConfig* currentNode);
extern void PgxcNodeMismatchAlarmItemInitialize(void);
extern void StreamingDRAlarmItemInitialize(void);

extern void report_build_fail_alarm(AlarmType alarmType, const char *instanceName, int alarmIndex);
extern void report_dn_disk_alarm(AlarmType alarmType, const char *instanceName, int alarmIndex, const char *data_path);
extern void report_ddb_fail_alarm(AlarmType alarmType, const char* instanceName, int alarmIndex, DDB_TYPE dbType);
extern void InitializeAlarmItem(const staticNodeConfig* currentNode);
extern void ReportPgxcNodeMismatchAlarm(AlarmType alarmType, const char* instanceName);
extern void ReportStreamingDRAlarm(AlarmType alarmType, const char *instanceName, int alarmIndex, const char *info);

#endif