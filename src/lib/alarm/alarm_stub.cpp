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
 * alarm_stub.cpp
 *
 *
 * IDENTIFICATION
 *    src/lib/alarm/alarm_stub.cpp
 *
 * -------------------------------------------------------------------------
 */

#include "alarm/alarm_log.h"

char system_alarm_log[MAXPGPATH] = {0};

void AlarmLog(int level, const char *fmt, ...)
{
    return;
}

void AlarmReporter(Alarm *alarmItem, AlarmType type, AlarmAdditionalParam *additionalParam)
{
    return;
}

void WriteAlarmAdditionalInfo(AlarmAdditionalParam *additionalParam, const char *instanceName,
    const char *databaseName, const char *dbUserName, const char *logicClusterName, Alarm *alarmItem, AlarmType type,
    ...)
{
    return;
}

void AlarmItemInitialize(
    Alarm* alarmItem, AlarmId alarmId, AlarmStat alarmStat, CheckerFunc checkerFunc, time_t reportTime, int reportCount)
{
    return;
}

void AlarmEnvInitialize(void)
{
    return;
}

void clean_system_alarm_log(const char *fileName, const char *sysLogPath)
{
    return;
}

void create_system_alarm_log(const char *sysLogPath)
{
    return;
}
