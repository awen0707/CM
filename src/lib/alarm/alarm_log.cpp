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
 * alarm_log.cpp
 *
 *
 * IDENTIFICATION
 *    src/lib/alarm/alarm_log.cpp
 *
 * -------------------------------------------------------------------------
 */
#include <fcntl.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/stat.h>
#include "cm/cm_c.h"
#include "alarm/alarm_log.h"

#undef _
#define _(x) x


#define SYSTEM_ALARM_LOG "system_alarm"
#define MAX_SYSTEM_ALARM_LOG_SIZE (128 * 1024 * 1024) /* 128MB */
#define CURLOGFILEMARK "-current.log"

const int LOG_MAX_TIMELEN = 80;
const int COMMAND_SIZE = 4196;
const int REPORT_MSG_SIZE = 4096;

char g_alarm_scope[MAX_BUF_SIZE] = {0};
char system_alarm_log[MAXPGPATH] = {0};
static char system_alarm_log_name[MAXPGPATH];
pthread_rwlock_t alarm_log_write_lock;
FILE* alarmLogFile = NULL;
typedef int64 pg_time_t;
char sys_alarm_log_path[MAX_PATH_LEN] = {0};

/*
 * Open a new logfile with proper permissions and buffering options.
 *
 */
static FILE* logfile_open(const char* filename, const char* mode)
{
    mode_t oumask;

    // Note we do not let Log_file_mode disable IWUSR, since we certainly want to be able to write the files ourselves.
    oumask = umask((mode_t)((~(mode_t)(S_IRUSR | S_IWUSR | S_IXUSR)) & (S_IRWXU | S_IRWXG | S_IRWXO)));
    FILE *fh = fopen(filename, mode);
    (void)umask(oumask);
    if (fh != NULL) {
        (void)setvbuf(fh, NULL, LBF_MODE, 0);

#ifdef WIN32
        /* use CRLF line endings on Windows */
        _setmode(_fileno(fh), _O_TEXT);
#endif
    } else {
        AlarmLog(ALM_LOG, "could not open log file \"%s\"\n", filename);
    }
    return fh;
}

static void create_new_alarm_log_file(const char* sys_log_path)
{
    pg_time_t current_time;
    struct tm systm;
    char log_create_time[LOG_MAX_TIMELEN] = {0};
    char log_temp_name[MAXPGPATH] = {0};
    errno_t rc;

    rc = memset_s(&systm, sizeof(systm), 0, sizeof(systm));
    securec_check_c(rc, "", "");
    /* create new log file */
    rc = memset_s(system_alarm_log, MAXPGPATH, 0, MAXPGPATH);
    securec_check_c(rc, "", "");

    current_time = time(NULL);
    if (localtime_r(&current_time, &systm) != NULL) {
        (void)strftime(log_create_time, LOG_MAX_TIMELEN, "-%Y-%m-%d_%H%M%S", &systm);
    } else {
        AlarmLog(ALM_LOG, "get localtime_r failed\n");
    }

    rc = snprintf_s(
        log_temp_name, MAXPGPATH, MAXPGPATH - 1, "%s%s%s", SYSTEM_ALARM_LOG, log_create_time, CURLOGFILEMARK);
    securec_check_ss_c(rc, "", "");
    rc = snprintf_s(system_alarm_log, MAXPGPATH, MAXPGPATH - 1, "%s/%s", sys_log_path, log_temp_name);
    securec_check_ss_c(rc, "", "");
    rc = memset_s(system_alarm_log_name, MAXPGPATH, 0, MAXPGPATH);
    securec_check_c(rc, "", "");
    rc = strncpy_s(system_alarm_log_name, MAXPGPATH, log_temp_name, strlen(log_temp_name));
    securec_check_c(rc, "", "");
    canonicalize_path(system_alarm_log);
    alarmLogFile = logfile_open(system_alarm_log, "a");
}

static bool rename_alarm_log_file(const char* sys_log_path)
{
    char logFileBuff[MAXPGPATH] = {0};
    char log_new_name[MAXPGPATH] = {0};
    errno_t rc;
    int ret;

    /* renamed the current file without  Mark */
    size_t len_log_old_name = strlen(system_alarm_log_name);
    size_t len_suffix_name = strlen(CURLOGFILEMARK);
    if (len_log_old_name < len_suffix_name) {
        AlarmLog(ALM_LOG, "ERROR: len_log_old_name is %lu, len_suffix_name is %lu \n",
            len_log_old_name, len_suffix_name);
        return false;
    }
    size_t len_log_new_name = len_log_old_name - len_suffix_name;

    rc = strncpy_s(logFileBuff, MAXPGPATH, system_alarm_log_name, len_log_new_name);
    securec_check_c(rc, "", "");
    rc = strncat_s(logFileBuff, MAXPGPATH, ".log", strlen(".log"));
    securec_check_c(rc, "", "");

    rc = snprintf_s(log_new_name, MAXPGPATH, MAXPGPATH - 1, "%s/%s", sys_log_path, logFileBuff);
    securec_check_ss_c(rc, "", "");

    /* close the current  file  */
    if (alarmLogFile != NULL) {
        (void)fclose(alarmLogFile);
        alarmLogFile = NULL;
    }

    ret = rename(system_alarm_log, log_new_name);
    if (ret != 0) {
        AlarmLog(ALM_LOG, "ERROR: %s: rename log file %s failed! \n", system_alarm_log, system_alarm_log);
        return false;
    }
    return true;
}

/* write alarm info to alarm log file */
static void write_log_file(const char* buffer)
{
    (void)pthread_rwlock_wrlock(&alarm_log_write_lock);

    if (alarmLogFile == NULL) {
        if (strncmp(system_alarm_log, "/dev/null", strlen("/dev/null")) == 0) {
            create_system_alarm_log(sys_alarm_log_path);
        }
        canonicalize_path(system_alarm_log);
        alarmLogFile = logfile_open(system_alarm_log, "a");
    }

    if (alarmLogFile != NULL) {
        size_t count = strlen(buffer);

        size_t rc = fwrite(buffer, 1, count, alarmLogFile);
        if (rc != count) {
            AlarmLog(ALM_LOG, "could not write to log file: %s\n", system_alarm_log);
        }
        (void)fflush(alarmLogFile);
        (void)fclose(alarmLogFile);
        alarmLogFile = NULL;
    } else {
        AlarmLog(ALM_LOG, "write_log_file, log file is null now: %s\n", buffer);
    }

    (void)pthread_rwlock_unlock(&alarm_log_write_lock);
}

/* unify log style */
void create_system_alarm_log(const char* sys_log_path)
{
    struct dirent* de = NULL;
    bool is_exist = false;

    /* check validity of current log file name */
    char* name_ptr = NULL;
    errno_t rc;

    if (strlen(sys_alarm_log_path) == 0) {
        rc = strncpy_s(sys_alarm_log_path, MAX_PATH_LEN, sys_log_path, strlen(sys_log_path));
        securec_check_c(rc, "", "");
    }

    DIR *dir = opendir(sys_log_path);
    if (dir == NULL) {
        AlarmLog(ALM_LOG, "opendir %s failed! \n", sys_log_path);
        rc = strncpy_s(system_alarm_log, MAXPGPATH, "/dev/null", strlen("/dev/null"));
        securec_check_ss_c(rc, "", "");
        return;
    }

    while ((de = readdir(dir)) != NULL) {
        /* exist current log file */
        if (strstr(de->d_name, SYSTEM_ALARM_LOG) != NULL) {
            name_ptr = strstr(de->d_name, CURLOGFILEMARK);
            if (name_ptr != NULL) {
                name_ptr += strlen(CURLOGFILEMARK);
                if ((*name_ptr) == '\0') {
                    is_exist = true;
                    break;
                }
            }
        }
    }
    if (is_exist) {
        rc = memset_s(system_alarm_log_name, MAXPGPATH, 0, MAXPGPATH);
        securec_check_c(rc, "", "");
        rc = memset_s(system_alarm_log, MAXPGPATH, 0, MAXPGPATH);
        securec_check_c(rc, "", "");
        rc = snprintf_s(system_alarm_log, MAXPGPATH, MAXPGPATH - 1, "%s/%s", sys_log_path, de->d_name);
        securec_check_ss_c(rc, "", "");
        rc = strncpy_s(system_alarm_log_name, MAXPGPATH, de->d_name, strlen(de->d_name));
        securec_check_c(rc, "", "");
    } else {
        /* create current log file name */
        create_new_alarm_log_file(sys_log_path);
    }
    (void)closedir(dir);
}

void clean_system_alarm_log(const char* file_name, const char* sys_log_path)
{
    Assert(file_name != NULL);

    struct stat statbuff;

    errno_t rc = memset_s(&statbuff, sizeof(statbuff), 0, sizeof(statbuff));
    securec_check_c(rc, "", "");

    int ret = stat(file_name, &statbuff);
    if (ret != 0 || (strncmp(file_name, "/dev/null", strlen("/dev/null")) == 0)) {
        AlarmLog(ALM_LOG, "ERROR: stat system alarm log %s error.ret=%d\n", file_name, ret);
        return;
    }

    long filesize = statbuff.st_size;
    if (filesize > MAX_SYSTEM_ALARM_LOG_SIZE) {
        (void)pthread_rwlock_wrlock(&alarm_log_write_lock);
        /* renamed the current file without  Mark */
        if (rename_alarm_log_file(sys_log_path)) {
            /* create new log file */
            create_new_alarm_log_file(sys_log_path);
        }
        (void)pthread_rwlock_unlock(&alarm_log_write_lock);
    }
    return;
}

void write_alarm(const Alarm* alarmItem, const char* alarmName, const char* alarmLevel, AlarmType type,
    AlarmAdditionalParam* additionalParam)
{
    char command[COMMAND_SIZE];
    char reportInfo[REPORT_MSG_SIZE];
    errno_t rcs = 0;

    if (strlen(system_alarm_log) == 0) {
        return;
    }

    errno_t rc = memset_s(command, COMMAND_SIZE, 0, COMMAND_SIZE);
    securec_check_c(rc, "", "");
    rc = memset_s(reportInfo, REPORT_MSG_SIZE, 0, REPORT_MSG_SIZE);
    securec_check_c(rc, "", "");
    if (type == ALM_AT_Fault || type == ALM_AT_Event) {
        rcs = snprintf_s(reportInfo,
            REPORT_MSG_SIZE,
            REPORT_MSG_SIZE - 1,
            "{" SYSQUOTE "id" SYSQUOTE SYSCOLON SYSQUOTE "%016ld" SYSQUOTE SYSCOMMA SYSQUOTE
            "name" SYSQUOTE SYSCOLON SYSQUOTE "%s" SYSQUOTE SYSCOMMA SYSQUOTE "level" SYSQUOTE SYSCOLON SYSQUOTE
            "%s" SYSQUOTE SYSCOMMA SYSQUOTE "scope" SYSQUOTE SYSCOLON "%s" SYSCOMMA SYSQUOTE
            "source_tag" SYSQUOTE SYSCOLON SYSQUOTE "%s-%s" SYSQUOTE SYSCOMMA SYSQUOTE
            "op_type" SYSQUOTE SYSCOLON SYSQUOTE "%s" SYSQUOTE SYSCOMMA SYSQUOTE "details" SYSQUOTE SYSCOLON SYSQUOTE
            "%s" SYSQUOTE SYSCOMMA SYSQUOTE "clear_type" SYSQUOTE SYSCOLON SYSQUOTE "%s" SYSQUOTE SYSCOMMA SYSQUOTE
            "start_timestamp" SYSQUOTE SYSCOLON "%ld" SYSCOMMA SYSQUOTE "end_timestamp" SYSQUOTE SYSCOLON "%d"
            "}\n",
            (long)alarmItem->id,
            alarmName,
            alarmLevel,
            g_alarm_scope,
            additionalParam->hostName,
            (strlen(additionalParam->instanceName) != 0) ? additionalParam->instanceName : additionalParam->clusterName,
            "firing",
            additionalParam->additionInfo,
            type == ALM_AT_Event ? "ADMC" : "ADAC",
            alarmItem->startTimeStamp,
            0);
    } else if (type == ALM_AT_Resume) {
        rcs = snprintf_s(reportInfo,
            REPORT_MSG_SIZE,
            REPORT_MSG_SIZE - 1,
            "{" SYSQUOTE "id" SYSQUOTE SYSCOLON SYSQUOTE "%016ld" SYSQUOTE SYSCOMMA SYSQUOTE
            "name" SYSQUOTE SYSCOLON SYSQUOTE "%s" SYSQUOTE SYSCOMMA SYSQUOTE "level" SYSQUOTE SYSCOLON SYSQUOTE
            "%s" SYSQUOTE SYSCOMMA SYSQUOTE "scope" SYSQUOTE SYSCOLON "%s" SYSCOMMA SYSQUOTE
            "source_tag" SYSQUOTE SYSCOLON SYSQUOTE "%s-%s" SYSQUOTE SYSCOMMA SYSQUOTE
            "op_type" SYSQUOTE SYSCOLON SYSQUOTE "%s" SYSQUOTE SYSCOMMA SYSQUOTE "start_timestamp" SYSQUOTE SYSCOLON
            "%d" SYSCOMMA SYSQUOTE "end_timestamp" SYSQUOTE SYSCOLON "%ld"
            "}\n",
            (long)alarmItem->id,
            alarmName,
            alarmLevel,
            g_alarm_scope,
            additionalParam->hostName,
            (strlen(additionalParam->instanceName) != 0) ? additionalParam->instanceName : additionalParam->clusterName,
            "resolved",
            0,
            alarmItem->endTimeStamp);
    }
    securec_check_ss_c(rcs, "", "");
    write_log_file(reportInfo);
}
