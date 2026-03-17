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
 * cm_elog.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_elog.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CM_ELOG_API_H
#define CM_ELOG_API_H
#include "cm_defs.h"
#include "cm/elog.h"

#define MAX_LOG_BUFF_LEN 2048

typedef enum KeyEventTypeEn {
    KEY_EVENT_FAILOVER = 0,
    KEY_EVENT_SWITCHOVER = 1,
    KEY_EVENT_RESTART = 2,
    KEY_EVENT_BUILD = 3,
    KEY_EVENT_NOTIFY = 4,
    KEY_EVENT_NOTIFY_CN = 5,
    KEY_EVENT_NOTIFY_STANDBY = 6,
    KEY_EVENT_NOTIFY_PRIMARY = 7,
    KEY_EVENT_FINISH_REDO = 8,
    KEY_EVENT_DELETE_XLOG = 9,
    KEY_EVENT_REP_SYNC = 10,
    KEY_EVENT_REP_MOST_AVAILABLE = 11,
    KEY_EVENT_RELOAD_GS_GUC = 12,
    KEY_EVENT_DELETE_CN = 13,
    KEY_EVENT_REPAIR_CN_ACK = 14,
    KEY_EVENT_OBS_BACKUP = 15,
    KEY_EVENT_RECOVER = 16,
    KEY_EVENT_REFRESH_OBS_DELETE_TEXT = 17,
    KEY_EVENT_DROP_CN_OBS_XLOG = 18,
    KEY_EVENT_RES_ARBITRATE = 19,
    KEY_EVENT_TYPE_CEIL, // new event types should be added before this.
} KeyEventType;

typedef struct log_level_string_st {
    const char* level_string;
    int level_val;
} log_level_string;

static inline int32 GetCmLogMessage()
{
    if (log_min_messages == WARNING) {
        return LOG;
    }

    if (log_min_messages == LOG) {
        return WARNING;
    }
    return log_min_messages;
}

typedef status_t (*SetParam)(const char *key, const char *value);
void LoadParamterFromConfigWithPrefixKey(const char *configFile, const char *prefixKey, SetParam setParam);

void CreateKeyEventLogFile(const char *sysLogPath);
void AddTimeLogPrefix(char *str, unsigned int strlen);
void CheckAndSwitchLogFile(const char *sysLogPath, const char *prefixLogName, char *logFilePath, char *logFileName);
void RenameLogFile(const char *sysLogPath, const char *logFilePath, const char *logFileName);
bool CheckLogFileStat(const char *fileName);
void WriteRunLogv(int elevel, const char* fmt, va_list ap) __attribute__((format(printf, 2, 0)));
void write_runlog(int elevel, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void write_stderr(const char *fmt, ...) __attribute__((format(PG_PRINTF_ATTRIBUTE, 1, 2)));
void WriteKeyEventLog(KeyEventType keyEventType, uint32 instanceId, const char *fmt, ...);

#endif
