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
 * cm_elog.cpp
 *     cm log functions
 *
 * IDENTIFICATION
 *    src/cm_common/cm_elog.cpp
 *
 * -------------------------------------------------------------------------
 */
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <ctype.h>
#include <syslog.h>

#include "alarm/alarm.h"
#include "cm/cm_elog.h"

#include <sys/time.h>
#if !defined(WIN32)
#include <sys/syscall.h>
#define gettid() syscall(__NR_gettid)
#else
/* windows. */
#endif
#include <sys/stat.h>

#undef _
#define _(x) x

#define KEY_EVENT_PRE "key_event"

pthread_rwlock_t g_operationLogWriteLock;
char g_operationLogPath[MAXPGPATH] = {0};
char g_operationLogName[MAXPGPATH] = {0};

int log_destion_choice = LOG_DESTION_FILE;

/* declare the global variable of alarm module. */
int g_alarmReportInterval;
char g_alarmComponentPath[MAXPGPATH];
int g_alarmReportMaxCount;

char sys_log_path[MAX_PATH_LEN] = {0};  /* defalut cmData/cm_server  or cmData/cm_agent. */
char cm_krb_server_keyfile[MAX_PATH_LEN] = {0};
int Log_RotationSize = 16 * 1024 * 1024L;
pthread_rwlock_t syslog_write_lock;
pthread_rwlock_t dotCount_lock;
static bool dotCountNotZero = false;

FILE* syslogFile = NULL;
const char* prefix_name = NULL;

char g_curLogFileName[MAXPGPATH] = {0};
volatile int log_min_messages = WARNING;
volatile bool incremental_build = true;
volatile bool security_mode = false;
volatile int maxLogFileSize = 16 * 1024 * 1024;
volatile bool logInitFlag = false;
/* undocumentedVersion:
 * It's for inplace upgrading. This variable means which version we are
 * upgrading from. Zero means we are not upgrading.
 */
volatile uint32 undocumentedVersion = 0;
bool g_logFileSet = false;
/* unify log style */
THR_LOCAL const char* thread_name = NULL;

FILE* logfile_open(const char* fileName, const char* mode);
static void get_alarm_report_interval(const char* conf);
static void TrimPathDoubleEndQuotes(char* path);

#define BUF_LEN 1024
#define COUNTSTR_LEN 128
#define MSBUF_LENGTH 8
#define FORMATTED_TS_LEN 128

typedef struct ErrBufCtx_ {
    char errdetail[EREPORT_BUF_LEN];
    char errcode[EREPORT_BUF_LEN];
    char errmodule[EREPORT_BUF_LEN];
    char errmsg[EREPORT_BUF_LEN];
    char errcause[EREPORT_BUF_LEN];
    char erraction[EREPORT_BUF_LEN];
    char fmtLogTime[FORMATTED_TS_LEN];
} ErrBufCtx;

static pthread_key_t g_cm_log_key = PTHREAD_KEYS_MAX;
static ErrBufCtx *GetErrBufCtx()
{
    if (g_cm_log_key == PTHREAD_KEYS_MAX) {
        (void)pthread_key_create(&g_cm_log_key, free);
    }

    void *errCtx = pthread_getspecific(g_cm_log_key);
    if (errCtx == NULL) {
        errCtx = malloc(sizeof(ErrBufCtx));
        if (errCtx == NULL) {
            (void)printf("FATAL: out of memory! g_errCtx requested size: %lu.\n", sizeof(ErrBufCtx));
            exit(1);
        }
        (void)pthread_setspecific(g_cm_log_key, errCtx);
    }

    return (ErrBufCtx *)errCtx;
}

static const char* g_cmKeyEventType[KEY_EVENT_TYPE_CEIL] = {0};

/**
 * @brief When a parent process opens a file, the child processes will inherit the
 * file handle of the parent process. If the file is deleted and the child processes
 * are still running, the file handle will not be freed and take up disk space.
 * We set the FD_CLOEXEC flag to the file, so that the child processes don't inherit
 * the file handle of the parent process, and do not cause handle leak.
 *
 * @param fp open file object
 * @return int 0 means successfully set the flag.
 */

log_level_string log_level_map_string2[] = {

        {"DEBUG5", DEBUG5},
        {"DEBUG1", DEBUG1},
        {"WARNING", WARNING},
        {"LOG", LOG},
        {"ERROR", ERROR},
        {"FATAL", FATAL},
        {NULL, 0}
};

const char* log_level_int_to_string2(int log_level)
{
    int i;
    for (i = 0; log_level_map_string2[i].level_string != NULL; i++) {
        if (log_level_map_string2[i].level_val == log_level) {
            return log_level_map_string2[i].level_string;
        }
    }
    return "Unknown";
}

int SetFdCloseExecFlag(FILE* fp)
{
    int fd = fileno(fp);
    int flags = fcntl(fd, F_GETFD);
    if (flags < 0) {
        (void)printf("fcntl get flags failed.\n");
        return flags;
    }
    flags |= FD_CLOEXEC;
    int ret = fcntl(fd, F_SETFD, flags);
    if (ret == -1) {
        (void)printf("fcntl set flags failed.\n");
    }

    return ret;
}

void AlarmLogImplementation(int level, const char* prefix, const char* logtext)
{
    switch (level) {
        case ALM_DEBUG:
            write_runlog(LOG, "%s%s\n", prefix, logtext);
            break;
        case ALM_LOG:
            write_runlog(LOG, "%s%s\n", prefix, logtext);
            break;
        default:
            break;
    }
}

/*
 * setup formatted_log_time, for consistent times between CSV and regular logs
 */
static void setup_formatted_log_time(void)
{
    struct timeval tv = {0};
    time_t stamp_time;
    char msbuf[MSBUF_LENGTH];
    struct tm timeinfo = {0};
    int rc;
    errno_t rcs;

    (void)gettimeofday(&tv, NULL);
    stamp_time = (time_t)tv.tv_sec;
    (void)localtime_r(&stamp_time, &timeinfo);

    ErrBufCtx *errCtx = GetErrBufCtx();
    (void)strftime(errCtx->fmtLogTime,
        FORMATTED_TS_LEN,
        /* leave room for milliseconds... */
        "%Y-%m-%d %H:%M:%S     %Z",
        &timeinfo);

    /* 'paste' milliseconds into place... */
    rc = sprintf_s(msbuf, MSBUF_LENGTH, ".%03d", (int)(tv.tv_usec / 1000));
    securec_check_intval(rc, (void)rc);
    rcs = strncpy_s(errCtx->fmtLogTime + 19, FORMATTED_TS_LEN - 19, msbuf, 4);
    securec_check_errno(rcs, (void)rcs);
}

void add_log_prefix(int elevel, char* str)
{
    char errbuf_tmp[BUF_LEN * 3] = {0};
    errno_t rc;
    int rcs;

    setup_formatted_log_time();

    /* unify log style */
    if (thread_name == NULL) {
        thread_name = "";
    }
    ErrBufCtx *errCtx = GetErrBufCtx();
    rcs = snprintf_s(errbuf_tmp,
        sizeof(errbuf_tmp),
        sizeof(errbuf_tmp) - 1,
        "%s tid=%ld %s %s: ",
        errCtx->fmtLogTime,
        gettid(),
        thread_name,
        log_level_int_to_string2(elevel));
    securec_check_intval(rcs, (void)rcs);
    /* max message length less than 2048. */
    rc = strncat_s(errbuf_tmp, BUF_LEN * 3, str, BUF_LEN * 3 - strlen(errbuf_tmp));
    securec_check_errno(rc, (void)rc);
    rc = memcpy_s(str, BUF_LEN * 2, errbuf_tmp, BUF_LEN * 2 - 1);
    securec_check_errno(rc, (void)rc);
    str[BUF_LEN * 2 - 1] = '\0';
}

/*
 * is_log_level_output -- is elevel logically >= log_min_level?
 *
 * We use this for tests that should consider LOG to sort out-of-order,
 * between ERROR and FATAL.  Generally this is the right thing for testing
 * whether a message should go to the postmaster log, whereas a simple >=
 * test is correct for testing whether the message should go to the client.
 */
static bool is_log_level_output(int elevel, int log_min_level)
{
    if (elevel == LOG) {
        if (log_min_level == LOG || log_min_level <= ERROR) {
            return true;
        }
    } else if (log_min_level == LOG) {
        /* elevel not equal to LOG */
        if (elevel >= FATAL) {
            return true;
        }
    } else if (elevel >= log_min_level) {
        /* Neither is LOG */
        return true;
    }

    return false;
}

void WriteRunLogv(int elevel, const char* fmt, va_list ap)
{
    /* Get whether the record will be logged into the file. */
    if (!is_log_level_output(elevel, log_min_messages)) {
        return;
    }

    /* Obtaining international texts. */
    fmt = _(fmt);

    if (prefix_name != NULL && strcmp(prefix_name, "cm_ctl") == 0) {
        /* Skip the wait dot log and the line break log. */
        if (strcmp(fmt, ".") == 0) {
            (void)pthread_rwlock_wrlock(&dotCount_lock);
            dotCountNotZero = true;
            (void)pthread_rwlock_unlock(&dotCount_lock);
            (void)vfprintf(stdout, fmt, ap);
            (void)fflush(stdout);
            return;
        }

        /**
         * Log the record to std error.
         * 1. The log level is greater than the level "LOG", and the process name is "cm_ctl".
         * 2. The log file path was not initialized.
         */
        if (elevel >= LOG || sys_log_path[0] == '\0') {
            if (dotCountNotZero) {
                (void)fprintf(stdout, "\n");
                (void)pthread_rwlock_wrlock(&dotCount_lock);
                dotCountNotZero = false;
                (void)pthread_rwlock_unlock(&dotCount_lock);
            }

            /* Get the print out format. */
            char fmtBuffer[MAX_LOG_BUFF_LEN] = {0};
            int ret = snprintf_s(fmtBuffer, sizeof(fmtBuffer), sizeof(fmtBuffer) - 1, "%s: %s", prefix_name, fmt);
            securec_check_intval(ret, (void)ret);
            va_list bp;
            va_copy(bp, ap);
            (void)vfprintf(stdout, fmtBuffer, bp);
            (void)fflush(stdout);
            va_end(bp);
        }
    }

    /* Format the log record, if more than size of buf, and will truncated it. */
    char errbuf[MAX_LOG_BUFF_LEN] = {0};
    int count = vsnprintf_truncated_s(errbuf, sizeof(errbuf), fmt, ap);
    if (count == -1) {
        write_runlog(ERROR, "cannot print message, because count is -1.\n");
        return;
    }

    if (log_destion_choice == LOG_DESTION_FILE) {
        add_log_prefix(elevel, errbuf);
        write_log_file(errbuf, count);
    }
}

/*
 * Write errors to stderr (or by equal means when stderr is
 * not available).
 */
void write_runlog(int elevel, const char* fmt, ...)
{
    /* Get whether the record will be logged into the file. */
    if (!is_log_level_output(elevel, log_min_messages)) {
        return;
    }

    /* Obtaining international texts. */
    fmt = _(fmt);

    va_list ap;
    va_start(ap, fmt);
    WriteRunLogv(elevel, fmt, ap);
    va_end(ap);
}

int add_message_string(char* errmsg_tmp, char* errdetail_tmp, char* errmodule_tmp, char* errcode_tmp, const char* fmt)
{
    char errbuf_tmp[EREPORT_BUF_LEN] = {0};

    int rcs = snprintf_s(errbuf_tmp, sizeof(errbuf_tmp), sizeof(errbuf_tmp) - 1, "%s", fmt);
    securec_check_intval(rcs, (void)rcs);
    char *p = strstr(errbuf_tmp, "[ERRMSG]:");
    if (p != NULL) {
        rcs = snprintf_s(errmsg_tmp, EREPORT_BUF_LEN, EREPORT_BUF_LEN - 1, "%s", fmt + strlen("[ERRMSG]:"));
    } else if ((p = strstr(errbuf_tmp, "[ERRDETAIL]:")) != NULL) {
        rcs = snprintf_s(errdetail_tmp, EREPORT_BUF_LEN, EREPORT_BUF_LEN - 1, "%s", fmt);
    } else if ((p = strstr(errbuf_tmp, "[ERRMODULE]:")) != NULL) {
        rcs = snprintf_s(errmodule_tmp, EREPORT_BUF_LEN, EREPORT_BUF_LEN - 1, "%s", fmt + strlen("[ERRMODULE]:"));
    } else if ((p = strstr(errbuf_tmp, "[ERRCODE]:")) != NULL) {
        rcs = snprintf_s(errcode_tmp, EREPORT_BUF_LEN, EREPORT_BUF_LEN - 1, "%s", fmt + strlen("[ERRCODE]:"));
    }
    securec_check_intval(rcs, (void)rcs);
    return 0;
}

int add_message_string(char* errmsg_tmp, char* errdetail_tmp, char* errmodule_tmp, char* errcode_tmp,
    char* errcause_tmp, char* erraction_tmp, const char* fmt)
{
    char *p = NULL;
    char errbuf_tmp[EREPORT_BUF_LEN] = {0};

    int rcs = snprintf_s(errbuf_tmp, sizeof(errbuf_tmp), sizeof(errbuf_tmp) - 1, "%s", fmt);
    securec_check_intval(rcs, (void)rcs);
    if ((p = strstr(errbuf_tmp, "[ERRMSG]:")) != NULL) {
        rcs = snprintf_s(errmsg_tmp, EREPORT_BUF_LEN, EREPORT_BUF_LEN - 1, "%s", fmt + strlen("[ERRMSG]:"));
    } else if ((p = strstr(errbuf_tmp, "[ERRDETAIL]:")) != NULL) {
        rcs = snprintf_s(errdetail_tmp, EREPORT_BUF_LEN, EREPORT_BUF_LEN - 1, "%s", fmt);
    } else if ((p = strstr(errbuf_tmp, "[ERRMODULE]:")) != NULL) {
        rcs = snprintf_s(errmodule_tmp, EREPORT_BUF_LEN, EREPORT_BUF_LEN - 1, "%s", fmt + strlen("[ERRMODULE]:"));
    } else if ((p = strstr(errbuf_tmp, "[ERRCODE]:")) != NULL) {
        rcs = snprintf_s(errcode_tmp, EREPORT_BUF_LEN, EREPORT_BUF_LEN - 1, "%s", fmt + strlen("[ERRCODE]:"));
    } else if ((p = strstr(errbuf_tmp, "[ERRCAUSE]:")) != NULL) {
        rcs = snprintf_s(errcause_tmp, EREPORT_BUF_LEN, EREPORT_BUF_LEN - 1, "%s", fmt);
    } else if ((p = strstr(errbuf_tmp, "[ERRACTION]:")) != NULL) {
        rcs = snprintf_s(erraction_tmp, EREPORT_BUF_LEN, EREPORT_BUF_LEN - 1, "%s", fmt);
    }
    securec_check_intval(rcs, (void)rcs);
    return 0;
}


void add_log_prefix2(int elevel, const char* errmodule_tmp, const char* errcode_tmp, char* str)
{
    char errbuf_tmp[BUF_LEN * 3] = {0};
    errno_t rc;
    int rcs;

    setup_formatted_log_time();

    /* unify log style */
    if (thread_name == NULL) {
        thread_name = "";
    }
    ErrBufCtx *errCtx = GetErrBufCtx();
    if (errmodule_tmp[0] && errcode_tmp[0]) {
        rcs = snprintf_s(errbuf_tmp,
            sizeof(errbuf_tmp),
            sizeof(errbuf_tmp) - 1,
            "%s tid=%ld %s [%s] %s %s: ",
            errCtx->fmtLogTime,
            gettid(),
            thread_name,
            errmodule_tmp,
            errcode_tmp,
            log_level_int_to_string2(elevel));
    } else {
        rcs = snprintf_s(errbuf_tmp,
            sizeof(errbuf_tmp),
            sizeof(errbuf_tmp) - 1,
            "%s tid=%ld %s %s: ",
            errCtx->fmtLogTime,
            gettid(),
            thread_name,
            log_level_int_to_string2(elevel));
    }
    securec_check_intval(rcs, (void)rcs);

    /* max message length less than 2048. */
    rc = strncat_s(errbuf_tmp, BUF_LEN * 3, str, BUF_LEN * 3 - strlen(errbuf_tmp));
    securec_check_errno(rc, (void)rc);

    rc = memcpy_s(str, BUF_LEN * 2, errbuf_tmp, BUF_LEN * 2 - 1);
    securec_check_errno(rc, (void)rc);
    str[BUF_LEN * 2 - 1] = '\0';
}

/*
 * Write errors to stderr (or by equal means when stderr is
 * not available).
 */
void write_runlog3(int elevel, const char* errmodule_tmp, const char* errcode_tmp, const char* fmt, ...)
{
    va_list ap;
    va_list bp;
    char errbuf[2048] = {0};
    char fmtBuffer[2048] = {0};
    int ret = 0;

    /* Get whether the record will be logged into the file. */
    bool output_to_server = is_log_level_output(elevel, log_min_messages);
    if (!output_to_server) {
        return;
    }

    /* Obtaining international texts. */
    fmt = _(fmt);

    va_start(ap, fmt);

    if (prefix_name != NULL && strcmp(prefix_name, "cm_ctl") == 0) {
        /* Skip the wait dot log and the line break log. */
        if (strcmp(fmt, ".") == 0) {
            (void)pthread_rwlock_wrlock(&dotCount_lock);
            dotCountNotZero = true;
            (void)pthread_rwlock_unlock(&dotCount_lock);
            (void)vfprintf(stdout, fmt, ap);
            (void)fflush(stdout);
            va_end(ap);
            return;
        }

        /**
         * Log the record to std error.
         * 1. The log level is greater than the level "LOG", and the process name is "cm_ctl".
         * 2. The log file path was not initialized.
         */
        if (elevel >= LOG || sys_log_path[0] == '\0') {
            if (dotCountNotZero) {
                (void)fprintf(stdout, "\n");
                (void)pthread_rwlock_wrlock(&dotCount_lock);
                dotCountNotZero = false;
                (void)pthread_rwlock_unlock(&dotCount_lock);
            }

            /* Get the print out format. */
            ret = snprintf_s(fmtBuffer, sizeof(fmtBuffer), sizeof(fmtBuffer) - 1, "%s: %s", prefix_name, fmt);
            securec_check_intval(ret, (void)ret);
            va_copy(bp, ap);
            (void)vfprintf(stdout, fmtBuffer, bp);
            (void)fflush(stdout);
            va_end(bp);
        }
    }

    /* Format the log record. */
    ret = vsnprintf_s(errbuf, sizeof(errbuf), sizeof(errbuf) - 1, fmt, ap);
    securec_check_intval(ret, (void)ret);
    va_end(ap);

    switch (log_destion_choice) {
        case LOG_DESTION_FILE:
            add_log_prefix2(elevel, errmodule_tmp, errcode_tmp, errbuf);
            write_log_file(errbuf, ret);
            break;

        default:
            break;
    }
}

/*
 * Open a new logfile with proper permissions and buffering options.
 *
 * If allow_errors is true, we just log any open failure and return NULL
 * (with errno still correct for the fopen failure).
 * Otherwise, errors are treated as fatal.
 */
FILE* logfile_open(const char* fileName, const char* mode)
{
    mode_t oumask;
    char log_file_name[MAXPGPATH] = {0};
    char log_temp_name[MAXPGPATH] = {0};
    char log_create_time[LOG_MAX_TIMELEN] = {0};
    struct dirent* de = NULL;
    bool is_exist = false;
    pg_time_t current_time;
    struct tm* systm = NULL;
    /* check validity of current log file name */
    char* name_ptr = NULL;
    errno_t rc;
    int ret;

    if (fileName == NULL) {
        (void)printf("logfile_open,log file path is null.\n");
        return NULL;
    }

    /*
     * Note we do not let Log_file_mode disable IWUSR,
     * since we certainly want to be able to write the files ourselves.
     */
    oumask = umask((mode_t)((~(mode_t)(S_IRUSR | S_IWUSR | S_IXUSR)) & (S_IRWXU | S_IRWXG | S_IRWXO)));

    /* find current log file. */
    DIR *dir = opendir(fileName);
    if (dir == NULL) {
        (void)printf(_("%s: opendir %s failed! \n"), prefix_name, fileName);
        return NULL;
    }
    while ((de = readdir(dir)) != NULL) {
        /* exist current log file. */
        if (strstr(de->d_name, prefix_name) != NULL) {
            name_ptr = strstr(de->d_name, "-current.log");
            if (name_ptr != NULL) {
                name_ptr += strlen("-current.log");
                if ((*name_ptr) == '\0') {
                    is_exist = true;
                    break;
                }
            }
        }
    }

    rc = memset_s(log_file_name, MAXPGPATH, 0, MAXPGPATH);
    securec_check_errno(rc, (void)rc);
    if (!is_exist) {
        /* create current log file name. */
        current_time = time(NULL);
        systm = localtime(&current_time);
        if (systm != NULL) {
            (void)strftime(log_create_time, LOG_MAX_TIMELEN, "-%Y-%m-%d_%H%M%S", systm);
        }
        ret =
            snprintf_s(log_temp_name, MAXPGPATH, MAXPGPATH - 1, "%s%s%s", prefix_name, log_create_time, curLogFileMark);
        securec_check_intval(ret, (void)ret);
        ret = snprintf_s(log_file_name, MAXPGPATH, MAXPGPATH - 1, "%s/%s", fileName, log_temp_name);
        securec_check_intval(ret, (void)ret);
    } else {
        /* if log file exist, get its file name. */
        ret = snprintf_s(log_file_name, MAXPGPATH, MAXPGPATH - 1, "%s/%s", fileName, de->d_name);
        securec_check_intval(ret, (void)ret);
    }
    (void)closedir(dir);
    FILE *fh = fopen(log_file_name, mode);

    (void)umask(oumask);

    if (fh != NULL) {
        (void)setvbuf(fh, NULL, LBF_MODE, 0);

#ifdef WIN32
        /* use CRLF line endings on Windows */
        _setmode(_fileno(fh), _O_TEXT);
#endif
        /*
         * when parent process(cm_agent) open the cm_agent_xxx.log, the child processes(cn\dn\gtm\cm_server)
         * inherit the file handle of the parent process. If the file is deleted and the child processes
         * are still running, the file handle will not be freed, it will take up disk space, so we set
         * the FD_CLOEXEC flag to the file, so that the child processes don't inherit the file handle of the
         * parent process.
         */
        if (SetFdCloseExecFlag(fh) == -1) {
            (void)printf("set file flag failed, filename:%s, errmsg: %s.\n", log_file_name, strerror(errno));
        }
    } else {
        int save_errno = errno;

        (void)printf("logfile_open could not open log file:%s %s.\n", log_file_name, strerror(errno));
        errno = save_errno;
    }

    /* store current log file name */
    rc = memset_s(g_curLogFileName, MAXPGPATH, 0, MAXPGPATH);
    securec_check_errno(rc, (void)rc);
    rc = strncpy_s(g_curLogFileName, MAXPGPATH, log_file_name, strlen(log_file_name));
    securec_check_errno(rc, (void)rc);

    return fh;
}

int logfile_init()
{
    int rc;
    errno_t rcs;

    rc = pthread_rwlock_init(&syslog_write_lock, NULL);
    if (rc != 0) {
        (void)fprintf(stderr, "FATAL logfile_init lock failed.exit\n");
        exit(1);
    }
    rc = pthread_rwlock_init(&dotCount_lock, NULL);
    if (rc != 0) {
        (void)fprintf(stderr, "FATAL logfile_init dot_count_lock failed.exit\n");
        exit(1);
    }
    rcs = memset_s(sys_log_path, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rcs, (void)rcs);

    return 0;
}

int is_comment_line(const char* str)
{
    size_t ii = 0;

    if (str == NULL) {
        (void)printf("FATAL bad config file line\n");
        exit(1);
    }

    /* skip blank */
    for (;;) {
        if (*(str + ii) == ' ') {
            ii++;  /* skip blank */
        } else {
            break;
        }
    }

    if (*(str + ii) == '#') {
        return 1;  /* comment line */
    }

    return 0;  /* not comment line */
}

/* trim successive characters on both ends */
static char* TrimToken(char* src, const char& delim)
{
    char* s = 0;
    char* e = 0;

    for (char *c = src; (c != NULL) && *c; ++c) {
        if (*c == delim) {
            if (e == NULL) {
                e = c;
            }
        } else {
            if (s == NULL) {
                s = c;
            }
            e = NULL;
        }
    }

    if (s == NULL) {
        s = src;
    }

    if (e != NULL) {
        *e = 0;
    }

    return s;
}

static void TrimPathDoubleEndQuotes(char* path)
{
    size_t pathLen = strlen(path);
    /* make sure buf[MAXPGPATH] can copy the whole path, last '\0' included */
    if (pathLen > MAXPGPATH - 1) {
        return;
    }
    char *pathTrimed = TrimToken(path, '\'');
    pathTrimed = TrimToken(pathTrimed, '\"');
    char buf[MAXPGPATH] = {0};

    errno_t rc = strncpy_s(buf, MAXPGPATH, pathTrimed, strlen(pathTrimed));
    securec_check_errno(rc, (void)rc);

    rc = strncpy_s(path, pathLen + 1, buf, strlen(buf));
    securec_check_errno(rc, (void)rc);
}

void get_krb_server_keyfile(const char* config_file)
{
    char buf[MAXPGPATH];

    int ii = 0;

    char* subStr = NULL;
    char* subStr1 = NULL;
    char* subStr2 = NULL;
    char* subStr3 = NULL;

    char* saveptr1 = NULL;
    char* saveptr2 = NULL;
    char* saveptr3 = NULL;
    errno_t rc = 0;

    if (config_file == NULL) {
        return;
    } else {
        logInitFlag = true;
    }

    FILE *fd = fopen(config_file, "r");
    if (fd == NULL) {
        (void)printf("FATAL get_krb_server_keyfile confDir error\n");
        exit(1);
    }

    while (!feof(fd)) {
        rc = memset_s(buf, MAXPGPATH, 0, MAXPGPATH);
        securec_check_errno(rc, (void)rc);

        (void)fgets(buf, MAXPGPATH, fd);
        buf[MAXPGPATH - 1] = 0;

        if (is_comment_line(buf) == 1) {
            continue;  /* skip  # comment */
        }

        subStr = strstr(buf, "cm_krb_server_keyfile");
        if (subStr == NULL) {
            continue;
        }

        subStr = strstr(subStr + 7, "=");
        if (subStr == NULL) {
            continue;
        }

        /* = is last char */
        if (subStr + 1 == 0) {
            continue;
        }

        /* skip blank */
        ii = 1;
        for (;;) {
            if (*(subStr + ii) == ' ') {
                ii++;  /* skip blank */
            } else {
                break;
            }
        }
        subStr = subStr + ii;

        /* beging check blank */
        subStr1 = strtok_r(subStr, " ", &saveptr1);
        if (subStr1 == NULL) {
            continue;
        }

        subStr2 = strtok_r(subStr1, "\n", &saveptr2);
        if (subStr2 == NULL) {
            continue;
        }

        subStr3 = strtok_r(subStr2, "\r", &saveptr3);
        if (subStr3 == NULL) {
            continue;
        }
        if (subStr3[0] == '\'') {
            subStr3 = subStr3 + 1;
        }
        if (subStr3[strlen(subStr3) - 1] == '\'') {
            subStr3[strlen(subStr3) - 1] = '\0';
        }
        if (strlen(subStr3) > 0) {
            rc = memcpy_s(cm_krb_server_keyfile, sizeof(sys_log_path), subStr3, strlen(subStr3) + 1);
            securec_check_errno(rc, (void)rc);
        }
    }

    (void)fclose(fd);

    TrimPathDoubleEndQuotes(cm_krb_server_keyfile);

    return;  /* default value warning */
}

void GetStringFromConf(const char* configFile, char* itemValue, size_t itemValueLenth, const char* itemName)
{
    char buf[MAXPGPATH];

    int ii = 0;

    char* subStr = NULL;
    char* subStr1 = NULL;
    char* subStr2 = NULL;
    char* subStr3 = NULL;

    char* saveptr1 = NULL;
    char* saveptr2 = NULL;
    char* saveptr3 = NULL;
    errno_t rc = 0;

    if (configFile == NULL) {
        return;
    } else {
        logInitFlag = true;
    }

    FILE *fd = fopen(configFile, "r");
    if (fd == NULL) {
        (void)printf("FATAL %s confDir error\n", itemName);
        exit(1);
    }

    while (!feof(fd)) {
        rc = memset_s(buf, MAXPGPATH, 0, MAXPGPATH);
        securec_check_errno(rc, (void)rc);

        (void)fgets(buf, MAXPGPATH, fd);
        buf[MAXPGPATH - 1] = 0;

        if (is_comment_line(buf) == 1) {
            continue;  /* skip  # comment */
        }

        subStr = strstr(buf, itemName);
        if (subStr == NULL) {
            continue;
        }

        subStr = strstr(subStr + strlen(itemName), "=");
        if (subStr == NULL) {
            continue;
        }

        if (subStr + 1 == 0) {
            continue;  /* = is last char */
        }

        /* skip blank */
        ii = 1;
        for (;;) {
            if (*(subStr + ii) == ' ') {
                ii++;  /* skip blank */
            } else {
                break;
            }
        }
        subStr = subStr + ii;

        /* beging check blank */
        subStr1 = strtok_r(subStr, " ", &saveptr1);
        if (subStr1 == NULL) {
            continue;
        }

        subStr2 = strtok_r(subStr1, "\n", &saveptr2);
        if (subStr2 == NULL) {
            continue;
        }

        subStr3 = strtok_r(subStr2, "\r", &saveptr3);
        if (subStr3 == NULL) {
            continue;
        }
        if (subStr3[0] == '\'') {
            subStr3 = subStr3 + 1;
        }
        if (subStr3[strlen(subStr3) - 1] == '\'') {
            subStr3[strlen(subStr3) - 1] = '\0';
        }
        if (strlen(subStr3) > 0) {
            rc = memcpy_s(itemValue, itemValueLenth, subStr3, strlen(subStr3) + 1);
            securec_check_errno(rc, (void)rc);
        } else {
            write_runlog(ERROR, "invalid value for parameter \" %s \" in %s.\n", itemName, configFile);
        }
    }

    (void)fclose(fd);

    return;  /* default value warning */
}

/* used for cm_agent and cm_server */
/* g_currentNode->cmDataPath  -->  confDir */
void get_log_level(const char* config_file)
{
    char buf[BUF_LEN];

    if (config_file == NULL) {
        return;
    } else {
        logInitFlag = true;
    }

    FILE *fd = fopen(config_file, "r");
    if (fd == NULL) {
        (void)printf("FATAL can not open config file: %s errno:%s\n", config_file, strerror(errno));
        exit(1);
    }

    while (!feof(fd)) {
        errno_t rc = memset_s(buf, BUF_LEN, 0, BUF_LEN);
        securec_check_errno(rc, (void)rc);
        (void)fgets(buf, BUF_LEN, fd);

        if (is_comment_line(buf) == 1) {
            continue;  /* skip  # comment */
        }

        if (strstr(buf, "log_min_messages") != NULL) {
            /* check all lines */
            if (strcasestr(buf, "DEBUG5") != NULL) {
                log_min_messages = DEBUG5;
                break;
            }

            if (strcasestr(buf, "DEBUG1") != NULL) {
                log_min_messages = DEBUG1;
                break;
            }

            if (strcasestr(buf, "WARNING") != NULL) {
                log_min_messages = WARNING;
                break;
            }

            if (strcasestr(buf, "ERROR") != NULL) {
                log_min_messages = ERROR;
                break;
            }

            if (strcasestr(buf, "FATAL") != NULL) {
                log_min_messages = FATAL;
                break;
            }

            if (strcasestr(buf, "LOG") != NULL) {
                log_min_messages = LOG;
                break;
            }
        }
    }

    (void)fclose(fd);
    return;  /* default value warning */
}

/* used for cm_agent */
void get_build_mode(const char* config_file)
{
    char buf[BUF_LEN];

    if (config_file == NULL) {
        return;
    }

    FILE *fd = fopen(config_file, "r");
    if (fd == NULL) {
        (void)printf("FATAL can not open config file: %s errno:%s\n", config_file, strerror(errno));
        exit(1);
    }

    while (!feof(fd)) {
        errno_t rc = memset_s(buf, BUF_LEN, 0, BUF_LEN);
        securec_check_errno(rc, (void)rc);
        (void)fgets(buf, BUF_LEN, fd);

        /* skip # comment */
        if (is_comment_line(buf) == 1) {
            continue;
        }

        /* check all lines */
        if (strstr(buf, "incremental_build") != NULL) {
            if ((strstr(buf, "on") != NULL) || (strstr(buf, "true") != NULL) || (strstr(buf, "yes") != NULL) ||
                (strstr(buf, "1") != NULL)) {
                incremental_build = true;
            } else if ((strstr(buf, "off") != NULL) || (strstr(buf, "false") != NULL) || (strstr(buf, "no") != NULL) ||
                (strstr(buf, "0") != NULL)) {
                incremental_build = false;
            } else {
                incremental_build = true;
                write_runlog(FATAL, "invalid value for parameter \"incremental_build\" in %s.\n", config_file);
            }
        }
    }

    (void)fclose(fd);
    return;
}

/* used for cm_agent and cm_server */
void get_log_file_size(const char* config_file)
{
    char buf[BUF_LEN];
    const int minLogFileSize = 1 * 1024 * 1024;
    const char *logFileSizeStr = "log_file_size";

    if (config_file == NULL) {
        return;  /* default size */
    } else {
        logInitFlag = true;
    }

    FILE *fd = fopen(config_file, "r");
    if (fd == NULL) {
        (void)printf("FATAL get_log_file_size error\n");
        exit(1);
    }

    while (!feof(fd)) {
        errno_t rc = memset_s(buf, BUF_LEN, 0, BUF_LEN);
        securec_check_errno(rc, (void)rc);
        (void)fgets(buf, BUF_LEN, fd);

        if (is_comment_line(buf) == 1 || strlen(buf) == 0) {
            continue;  /* skip  # comment */
        }

        char *subBuf = trim(buf);
        if (strncmp(subBuf, logFileSizeStr, strlen(logFileSizeStr)) == 0) {
            /* only check the first line */
            char countStr[COUNTSTR_LEN] = {0};
            int ii = 0;
            int jj = 0;

            char *subStr = strchr(buf, '=');
            if (subStr != NULL) {
                /* find = */
                ii = 1;  /* 1 is = */

                /* skip blank */
                for (;;) {
                    if (*(subStr + ii) == ' ') {
                        ii++;  /* skip blank */
                    } else if (*(subStr + ii) >= '0' && *(subStr + ii) <= '9') {
                        break;  /* number find.break */
                    } else {
                        /* invalid character. */
                        goto out;
                    }
                }

                while (*(subStr + ii) >= '0' && *(subStr + ii) <= '9') {
                    /* end when no more number. */
                    if (jj > (int)sizeof(countStr) - 2) {
                        (void)printf("FATAL too large log file size.\n");
                        exit(1);
                    } else {
                        countStr[jj] = *(subStr + ii);
                    }

                    ii++;
                    jj++;
                }
                countStr[jj] = 0;  /* jj maybe have added itself.terminate string. */

                if (countStr[0] != 0) {
                    maxLogFileSize = atoi(countStr) * 1024 * 1024;  /* byte */
                } else {
                    write_runlog(ERROR, "invalid value for parameter \"log_file_size\" in %s.\n", config_file);
                }

                if (maxLogFileSize == 0) {
                    maxLogFileSize = minLogFileSize;    /*  Min log value: 1  */
                }
            }
        }
    }

out:
    (void)fclose(fd);
    return;  /* default value is warning */
}

int get_cm_thread_count(const char* config_file)
{
#define DEFAULT_THREAD_NUM 5

    char buf[BUF_LEN];
    int thread_count = DEFAULT_THREAD_NUM;
    errno_t rc = 0;

    if (config_file == NULL) {
        (void)printf("FATAL no cmserver config file! exit.\n");
        exit(1);
    }

    FILE *fd = fopen(config_file, "r");
    if (fd == NULL) {
        (void)printf("FATAL open cmserver config file :%s ,error:%d\n", config_file, errno);
        exit(1);
    }

    while (!feof(fd)) {
        rc = memset_s(buf, sizeof(buf), 0, sizeof(buf));
        securec_check_errno(rc, (void)rc);
        (void)fgets(buf, BUF_LEN, fd);

        if (is_comment_line(buf) == 1) {
            continue;  /* skip  # comment */
        }

        if (strstr(buf, "thread_count") != NULL) {
            /* only check the first line */
            char countStr[COUNTSTR_LEN] = {0};
            int ii = 0;
            int jj = 0;

            char *subStr = strchr(buf, '=');
            /* find = */
            if (subStr != NULL) {
                ii = 1;

                /* skip blank */
                for (;;) {
                    if (*(subStr + ii) == ' ') {
                        ii++;  /* skip blank */
                    } else if (*(subStr + ii) >= '0' && *(subStr + ii) <= '9') {
                        /* number find.break */
                        break;
                    } else {
                        /* invalid character. */
                        goto out;
                    }
                }

                /* end when no number */
                while (*(subStr + ii) >= '0' && *(subStr + ii) <= '9') {
                    if (jj > (int)sizeof(countStr) - 2) {
                        (void)printf("FATAL too large thread count.\n");
                        exit(1);
                    } else {
                        countStr[jj] = *(subStr + ii);
                    }

                    ii++;
                    jj++;
                }
                countStr[jj] = 0;  /* jj maybe have added itself.terminate string. */

                if (countStr[0] != 0) {
                    thread_count = atoi(countStr);
                    if (thread_count < 2 || thread_count > 1000) {
                        (void)printf("FATAL invalid thread count %d, range [2 - 1000].\n", thread_count);
                        exit(1);
                    }
                } else {
                    thread_count = DEFAULT_THREAD_NUM;
                }
            }
        }
    }

out:
    (void)fclose(fd);
    return thread_count;
}

/*
 * @Description:  get value of paramater from configuration file
 *
 * @in config_file: configuration file path
 * @in key: name of paramater
 * @in defaultValue: default value of parameter
 *
 * @out: value of parameter
 */
int get_int_value_from_config(const char* config_file, const char* key, int defaultValue)
{
    int64 i64 = get_int64_value_from_config(config_file, key, defaultValue);
    if (i64 > INT_MAX) {
        return defaultValue;
    } else if (i64 < INT_MIN) {
        return defaultValue;
    }

    return (int)i64;
}

/*
 * @Description:  get value of paramater from configuration file
 *
 * @in config_file: configuration file path
 * @in key: name of paramater
 * @in defaultValue: default value of parameter
 *
 * @out: value of parameter
 */
uint32 get_uint32_value_from_config(const char* config_file, const char* key, uint32 defaultValue)
{
    int64 i64 = get_int64_value_from_config(config_file, key, defaultValue);
    if (i64 > UINT_MAX) {
        return defaultValue;
    } else if (i64 < 0) {
        return defaultValue;
    }

    return (uint32)i64;
}

/*
 * @Description:  get value of paramater from configuration file
 *
 * @in config_file: configuration file path
 * @in key: name of paramater
 * @in defaultValue: default value of parameter
 *
 * @out: value of parameter
 */
int64 get_int64_value_from_config(const char* config_file, const char* key, int64 defaultValue)
{
    char buf[BUF_LEN];
    int64 int64Value = defaultValue;
    errno_t rc = 0;

    if (config_file == NULL) {
        (void)printf("FATAL no config file! exit.\n");
        exit(1);
    }

    FILE *fd = fopen(config_file, "r");
    if (fd == NULL) {
        (void)printf("FATAL open config file failed:%s ,errno:%s\n", config_file, strerror(errno));
        exit(1);
    }

    while (!feof(fd)) {
        rc = memset_s(buf, sizeof(buf), 0, sizeof(buf));
        securec_check_errno(rc, (void)rc);
        (void)fgets(buf, BUF_LEN, fd);

        if (is_comment_line(buf) == 1) {
            continue;  /* skip  # comment */
        }

        if (strstr(buf, key) != NULL) {
            /* only check the first line */
            char countStr[COUNTSTR_LEN] = {0};
            int ii = 0;
            int jj = 0;

            char *subStr = strchr(buf, '=');
            if (subStr != NULL) {
                /* find = */
                ii = 1;

                /* skip blank */
                while (1) {
                    if (*(subStr + ii) == ' ') {
                        ii++;  /* skip blank */
                    } else if (isdigit(*(subStr + ii))) {
                        /* number find.break */
                        break;
                    } else {
                        /* invalid character. */
                        goto out;
                    }
                }

                while (isdigit(*(subStr + ii))) {
                    /* end when no number */
                    if (jj >= COUNTSTR_LEN - 1) {
                        write_runlog(ERROR, "length is not enough for constr\n");
                        goto out;
                    }
                    countStr[jj] = *(subStr + ii);

                    ii++;
                    jj++;
                }
                countStr[jj] = 0; /* jj maybe have added itself.terminate string. */

                if (countStr[0] != 0) {
                    int64Value = strtoll(countStr, NULL, 10);
                }
                break;
            }
        }
    }

out:
    (void)fclose(fd);
    return int64Value;
}

#define ALARM_REPORT_INTERVAL "alarm_report_interval"
#define ALARM_REPORT_INTERVAL_DEFAULT 10

#define ALARM_REPORT_MAX_COUNT "alarm_report_max_count"
#define ALARM_REPORT_MAX_COUNT_DEFAULT 5

/* trim blank characters on both ends */
char* trim(char* src)
{
    char* s = 0;
    char* e = 0;

    for (char *c = src; (c != NULL) && *c; ++c) {
        if (isspace(*c)) {
            if (e == NULL) {
                e = c;
            }
        } else {
            if (s == NULL) {
                s = c;
            }
            e = 0;
        }
    }
    if (s == NULL) {
        s = src;
    }
    if (e != NULL) {
        *e = 0;
    }

    return s;
}

/* Check this line is comment line or not, which is in cm_server.conf file */
static bool is_comment_entity(char* strLine, uint32 lineLen)
{
    if (strLine == NULL || strlen(strLine) == 0 || lineLen == 0) {
        return true;
    }
    char *src = strLine;
    src = trim(src);
    if (src == NULL || strlen(src) < 1) {
        return true;
    }
    if (*src == '#') {
        return true;
    }

    return false;
}

int is_digit_string(char* str)
{
#define isDigital(_ch) (((_ch) >= '0') && ((_ch) <= '9'))

    if (str == NULL) {
        return 0;
    }
    size_t len = strlen(str);
    if (len == 0) {
        return 0;
    }
    char *p = str;
    for (size_t i = 0; i < len; i++) {
        if (!isDigital(p[i])) {
            return 0;
        }
    }
    return 1;
}
static void get_alarm_parameters(const char* config_file)
{
    char buf[BUF_LEN] = {0};
    char* index1 = NULL;
    char* index2 = NULL;
    char* src = NULL;
    char* key = NULL;
    char* value = NULL;
    errno_t rc = 0;

    if (config_file == NULL) {
        return;
    }

    FILE *fd = fopen(config_file, "r");
    if (fd == NULL) {
        return;
    }

    while (!feof(fd)) {
        rc = memset_s(buf, BUF_LEN, 0, BUF_LEN);
        securec_check_errno(rc, (void)rc);
        (void)fgets(buf, BUF_LEN, fd);

        if (is_comment_entity(buf, BUF_LEN)) {
            continue;
        }
        index1 = strchr(buf, '#');
        if (index1 != NULL) {
            *index1 = '\0';
        }
        index2 = strchr(buf, '=');
        if (index2 == NULL) {
            continue;
        }
        src = buf;
        src = trim(src);
        index2 = strchr(src, '=');
        key = src;
        /* jump to the beginning of recorded values */
        value = index2 + 1;

        key = trim(key);
        value = trim(value);
        if (strncmp(key, ALARM_REPORT_INTERVAL, strlen(ALARM_REPORT_INTERVAL)) == 0) {
            if (is_digit_string(value)) {
                g_alarmReportInterval = atoi(value);
                if (g_alarmReportInterval == -1) {
                    g_alarmReportInterval = ALARM_REPORT_INTERVAL_DEFAULT;
                }
            }
            break;
        }
    }
    (void)fclose(fd);
}

static void get_alarm_report_max_count(const char* config_file)
{
    char buf[BUF_LEN] = {0};
    char* index1 = NULL;
    char* index2 = NULL;
    char* src = NULL;
    char* key = NULL;
    char* value = NULL;
    errno_t rc = 0;

    if (config_file == NULL) {
        return;
    }

    FILE *fd = fopen(config_file, "r");
    if (fd == NULL) {
        return;
    }

    while (!feof(fd)) {
        rc = memset_s(buf, BUF_LEN, 0, BUF_LEN);
        securec_check_errno(rc, (void)fclose(fd));
        (void)fgets(buf, BUF_LEN, fd);

        if (is_comment_entity(buf, BUF_LEN)) {
            continue;
        }
        index1 = strchr(buf, '#');
        if (index1 != NULL) {
            *index1 = '\0';
        }
        index2 = strchr(buf, '=');
        if (index2 == NULL) {
            continue;
        }
        src = buf;
        src = trim(src);
        index2 = strchr(src, '=');
        key = src;
        /* jump to the beginning of recorded values */
        value = index2 + 1;

        key = trim(key);
        value = trim(value);
        if (strncmp(key, ALARM_REPORT_MAX_COUNT, strlen(ALARM_REPORT_MAX_COUNT)) == 0) {
            if (is_digit_string(value)) {
                g_alarmReportMaxCount = atoi(value);
                if (g_alarmReportMaxCount == -1) {
                    g_alarmReportMaxCount = ALARM_REPORT_MAX_COUNT_DEFAULT;
                }
            }
            break;
        }
    }
    (void)fclose(fd);
}

/*
 * This function is for reading cm_server.conf parameters, which have been applied at server side.
 * In cm_server this function is ugly, it should be rewritten at new version.
 */
static void get_alarm_report_interval(const char* conf)
{
    get_alarm_parameters(conf);
}

static void GetAlarmReportInterval(const char *conf)
{
    g_alarmReportInterval = get_int_value_from_config(conf, "alarm_report_interval", g_alarmReportInterval);
}
static void GetAlarmReportMaxCount(const char *conf)
{
    g_alarmReportMaxCount = get_int_value_from_config(conf, "alarm_report_max_count", g_alarmReportMaxCount);
}

void get_log_paramter(const char* confDir)
{
    get_log_level(confDir);
    get_log_file_size(confDir);
    GetStringFromConf(confDir, g_alarmComponentPath, sizeof(g_alarmComponentPath), "alarm_component");
    get_alarm_report_interval(confDir);
    get_alarm_report_max_count(confDir);
}

void GetAlarmConfig(const char *confDir)
{
    GetStringFromConf(confDir, g_alarmComponentPath, sizeof(g_alarmComponentPath), "alarm_component");
    GetAlarmReportInterval(confDir);
    GetAlarmReportMaxCount(confDir);
}

/*
 * @GaussDB@
 * Brief			:  close the current  file, and open the next   file
 */
void switchLogFile(void)
{
    char log_new_name[MAXPGPATH] = {0};
    char current_localtime[LOG_MAX_TIMELEN] = {0};
    struct tm* systm;

    pg_time_t current_time = time(NULL);

    systm = localtime(&current_time);
    if (systm != NULL) {
        (void)strftime(current_localtime, LOG_MAX_TIMELEN, "-%Y-%m-%d_%H%M%S", systm);
    }

    /* close the current  file */
    if (syslogFile != NULL) {
        (void)fclose(syslogFile);
        syslogFile = NULL;
    }

    /* renamed the current file without  Mark */
    int len_log_cur_name = (int)strlen(g_curLogFileName);
    int len_suffix_name = (int)strlen(curLogFileMark);
    int len_log_new_name = len_log_cur_name - len_suffix_name;

    errno_t rc = strncpy_s(log_new_name, MAXPGPATH, g_curLogFileName, (size_t)len_log_new_name);
    securec_check_errno(rc, (void)rc);
    rc = strncat_s(log_new_name, MAXPGPATH, ".log", strlen(".log"));
    securec_check_errno(rc, (void)rc);
    int ret = rename(g_curLogFileName, log_new_name);
    if (ret != 0) {
        (void)printf(_("%s: rename log file %s failed! \n"), prefix_name, g_curLogFileName);
        return;
    }

    /* new current file name */
    rc = memset_s(g_curLogFileName, MAXPGPATH, 0, MAXPGPATH);
    securec_check_errno(rc, (void)rc);
    ret = snprintf_s(g_curLogFileName,
        MAXPGPATH,
        MAXPGPATH - 1,
        "%s/%s%s%s",
        sys_log_path,
        prefix_name,
        current_localtime,
        curLogFileMark);
    securec_check_intval(ret, (void)ret);

    mode_t oumask = umask((mode_t)((~(mode_t)(S_IRUSR | S_IWUSR | S_IXUSR)) & (S_IRWXU | S_IRWXG | S_IRWXO)));

    syslogFile = fopen(g_curLogFileName, "a");

    (void)umask(oumask);

    if (syslogFile == NULL) {
        (void)printf("switchLogFile,switch new log file failed %s\n", strerror(errno));
    } else {
        (void)setvbuf(syslogFile, NULL, LBF_MODE, 0);

#ifdef WIN32
        /* use CRLF line endings on Windows */
        _setmode(_fileno(syslogFile), _O_TEXT);
#endif
        if (SetFdCloseExecFlag(syslogFile) == -1) {
            (void)printf("set file flag failed, filename:%s, errmsg: %s.\n", g_curLogFileName, strerror(errno));
        }
    }
}

bool CheckLogFileExist()
{
    struct stat st;
    if (stat(g_curLogFileName, &st) != 0) {
        return false;
    }
    return true;
}

/*
 * @GaussDB@
 * Description: write info to the files
 * Notes: if the current  file size is full, switch to the next
 */
void write_log_file(const char* buffer, int count)
{
    (void)pthread_rwlock_wrlock(&syslog_write_lock);

    if (syslogFile == NULL) {
        /* maybe syslogFile no init. */
        syslogFile = logfile_open(sys_log_path, "a");
    }
    if (syslogFile != NULL) {
        count = (int)strlen(buffer);
        /* switch to the next file when current file full */
        if ((ftell(syslogFile) + count) > (maxLogFileSize)) {
            switchLogFile();
        }

        if (!CheckLogFileExist()) {
            if (syslogFile != NULL) {
                (void)fclose(syslogFile);
                syslogFile = NULL;
            }
            syslogFile = logfile_open(sys_log_path, "a");
        }

        if (syslogFile != NULL) {
            if (fwrite(buffer, 1, (size_t)count, syslogFile) != (size_t)count) {
                (void)printf("could not write to log file: %s, erron:%d\n", g_curLogFileName, errno);
            }
        } else {
            (void)printf("write_log_file could not open log file  %s : erron:%d\n", g_curLogFileName, errno);
        }
    } else {
        (void)printf("write_log_file,log file is null now:%s\n", buffer);
    }

    (void)pthread_rwlock_unlock(&syslog_write_lock);
}

char *errmsg(const char *fmt, ...)
{
    va_list ap;
    char errbuf[BUF_LEN] = {0};
    fmt = _(fmt);
    va_start(ap, fmt);
    ErrBufCtx *errCtx = GetErrBufCtx();
    errno_t rc = memset_s(errCtx->errmsg, EREPORT_BUF_LEN, 0, EREPORT_BUF_LEN);
    securec_check_errno(rc, (void)rc);
    int ret = vsnprintf_s(errbuf, sizeof(errbuf), sizeof(errbuf) - 1, fmt, ap);
    securec_check_intval(ret, (void)ret);
    va_end(ap);
    rc = snprintf_s(errCtx->errmsg, EREPORT_BUF_LEN, EREPORT_BUF_LEN - 1, "[ERRMSG]:%s", errbuf);
    securec_check_intval(rc, (void)rc);
    return errCtx->errmsg;
}

char *errdetail(const char *fmt, ...)
{
    va_list ap;
    char errbuf[BUF_LEN] = {0};
    fmt = _(fmt);
    va_start(ap, fmt);
    ErrBufCtx *errCtx = GetErrBufCtx();
    errno_t rc = memset_s(errCtx->errdetail, EREPORT_BUF_LEN, 0, EREPORT_BUF_LEN);
    securec_check_errno(rc, (void)rc);
    int ret = vsnprintf_s(errbuf, sizeof(errbuf), sizeof(errbuf) - 1, fmt, ap);
    securec_check_intval(ret, (void)ret);
    va_end(ap);
    rc = snprintf_s(errCtx->errdetail, EREPORT_BUF_LEN, EREPORT_BUF_LEN - 1, "[ERRDETAIL]:%s", errbuf);
    securec_check_intval(rc, (void)rc);
    return errCtx->errdetail;
}

char* errcode(int sql_state)
{
    int i;
    errno_t rc;
    char buf[6] = {0};
    ErrBufCtx *errCtx = GetErrBufCtx();
    rc = memset_s(errCtx->errcode, EREPORT_BUF_LEN, 0, EREPORT_BUF_LEN);
    securec_check_errno(rc, (void)rc);
    /* the length of sql code is 5 */
    for (i = 0; i < 5; i++) {
        buf[i] = PGUNSIXBIT(sql_state);
        sql_state >>= 6;
    }
    buf[i] = '\0';
    int ret = snprintf_s(errCtx->errcode, EREPORT_BUF_LEN, EREPORT_BUF_LEN - 1, "%s%s", "[ERRCODE]:", buf);
    securec_check_intval(ret, (void)ret);
    return errCtx->errcode;
}

char *errcause(const char *fmt, ...)
{
    va_list ap;
    char errbuf[BUF_LEN] = {0};
    fmt = _(fmt);
    va_start(ap, fmt);
    ErrBufCtx *errCtx = GetErrBufCtx();
    errno_t rc = memset_s(errCtx->errcause, EREPORT_BUF_LEN, 0, EREPORT_BUF_LEN);
    securec_check_errno(rc, (void)rc);
    int ret = vsnprintf_s(errbuf, sizeof(errbuf), sizeof(errbuf) - 1, fmt, ap);
    securec_check_intval(ret, (void)ret);
    va_end(ap);
    rc = snprintf_s(errCtx->errcause, EREPORT_BUF_LEN, EREPORT_BUF_LEN - 1, "[ERRCAUSE]:%s", errbuf);
    securec_check_intval(rc, (void)rc);
    return errCtx->errcause;
}

char *erraction(const char *fmt, ...)
{
    va_list ap;
    char errbuf[BUF_LEN] = {0};
    fmt = _(fmt);
    va_start(ap, fmt);
    ErrBufCtx *errCtx = GetErrBufCtx();
    errno_t rc = memset_s(errCtx->erraction, EREPORT_BUF_LEN, 0, EREPORT_BUF_LEN);
    securec_check_errno(rc, (void)rc);
    int ret = vsnprintf_s(errbuf, sizeof(errbuf), sizeof(errbuf) - 1, fmt, ap);
    securec_check_intval(ret, (void)ret);
    va_end(ap);
    rc = snprintf_s(errCtx->erraction, EREPORT_BUF_LEN, EREPORT_BUF_LEN - 1, "[ERRACTION]:%s", errbuf);
    securec_check_intval(rc, (void)rc);
    return errCtx->erraction;
}

char* errmodule(ModuleId id)
{
    ErrBufCtx *errCtx = GetErrBufCtx();
    errno_t rc = memset_s(errCtx->errmodule, EREPORT_BUF_LEN, 0, EREPORT_BUF_LEN);
    securec_check_errno(rc, (void)rc);
    rc = snprintf_s(errCtx->errmodule, EREPORT_BUF_LEN, EREPORT_BUF_LEN - 1, "[ERRMODULE]:%s",
        get_valid_module_name(id));
    securec_check_intval(rc, (void)rc);
    return errCtx->errmodule;
}

int SetLogFilePath(const char *logPath)
{
    errno_t rc = strcpy_s(sys_log_path, MAX_PATH_LEN, logPath);
    securec_check_errno(rc, (void)rc);
    syslogFile = logfile_open(logPath, "a");
    if (syslogFile == NULL) {
        (void)printf(_("open log file failed\n"));
        return -1;
    }
    return 0;
}

static char *RemoveQuotation(char *buf, uint32 len)
{
    if (len == 0) {
        return NULL;
    }
    char *subStr = trim(buf);
    if (subStr[0] == '\'' || subStr[0] == '\"') {
        subStr = subStr + 1;
    }
    if (subStr[strlen(subStr) - 1] == '\'' || subStr[strlen(subStr) - 1] == '\"') {
        subStr[strlen(subStr) - 1] = '\0';
    }
    return trim(subStr);
}

static bool GetKeyFromBuf(char *buf, const char *prefixKey, char *key, uint32 len, char **curStr)
{
    char *subStr = strstr(buf, prefixKey);
    if (subStr == NULL) {
        return false;
    }
    char *savePtr = NULL;
    subStr = strtok_r(buf, "=", &savePtr);
    if (subStr == NULL) {
        return false;
    }
    subStr = RemoveQuotation(subStr, (uint32)strlen(subStr));
    if (subStr == NULL) {
        return false;
    }
    if (strncmp(subStr, prefixKey, strlen(prefixKey)) != 0) {
        return false;
    }
    errno_t rc = strcpy_s(key, len - 1, subStr);
    securec_check_errno(rc, (void)rc);
    *curStr = savePtr;
    return true;
}

static bool GetValueFromBuf(char *buf, char *value, uint32 len)
{
    if (buf == NULL) {
        return false;
    }
    char *savePtr = NULL;
    char *subStr = trim(buf);
    if (subStr != NULL) {
        subStr = strtok_r(subStr, "#", &savePtr);
    }
    if (subStr != NULL) {
        subStr = strtok_r(subStr, "\n", &savePtr);
    }
    if (subStr != NULL) {
        subStr = strtok_r(subStr, "\r", &savePtr);
    }
    if (subStr == NULL) {
        return false;
    }
    subStr = RemoveQuotation(subStr, (uint32)strlen(subStr));
    if (subStr == NULL) {
        return false;
    }
    if (strlen(subStr) + 1 > (size_t)len) {
        write_runlog(ERROR, "The value of paramter %s is invalid.\n", subStr);
        return false;
    }
    errno_t rc = strcpy_s(value, len - 1, subStr);
    securec_check_errno(rc, (void)rc);
    return true;
}

void LoadParamterFromConfigWithPrefixKey(const char *configFile, const char *prefixKey, SetParam setParam)
{
    if (configFile == NULL || prefixKey == NULL || setParam == NULL) {
        write_runlog(ERROR, "configfile or prefixKey, set param is NULL.\n");
        return;
    }
    FILE *fd = fopen(configFile, "r");
    if (fd == NULL) {
        write_runlog(ERROR, "cannot open configDir %s.\n", configFile);
        return;
    }
    char buf[MAX_PATH_LEN];
    errno_t rc = 0;
    char key[MAX_PATH_LEN];
    char value[MAX_PATH_LEN];
    char *keyStr = NULL;
    status_t st = CM_SUCCESS;
    while (!feof(fd)) {
        rc = memset_s(buf, MAX_PATH_LEN, 0, MAX_PATH_LEN);
        securec_check_errno(rc, (void)rc);
        rc = memset_s(key, MAX_PATH_LEN, 0, MAX_PATH_LEN);
        securec_check_errno(rc, (void)rc);
        rc = memset_s(value, MAX_PATH_LEN, 0, MAX_PATH_LEN);
        securec_check_errno(rc, (void)rc);
        (void)fgets(buf, MAX_PATH_LEN, fd);
        buf[MAX_PATH_LEN - 1] = 0;
        if (is_comment_line(buf) == 1) {
            continue;
        }
        if (!GetKeyFromBuf(buf, prefixKey, key, MAX_PATH_LEN, &keyStr)) {
            continue;
        }
        if (!GetValueFromBuf(keyStr, value, MAX_PATH_LEN)) {
            continue;
        }
        st = setParam(key, value);
        if (st != CM_SUCCESS) {
            write_runlog(ERROR, "failed to set key_value(%s: %s) to ddb.\n", key, value);
        }
    }
    (void)fclose(fd);
}

status_t CreateNewLogFile(const char *sysLogPath, const char *prefixLogName, char *logFilePath, char *logFileName)
{
    pg_time_t currentTime;
    struct tm systm;
    char logCreateTime[LOG_MAX_TIMELEN] = {0};
    char logTempName[MAXPGPATH] = {0};
    errno_t rc = memset_s(&systm, sizeof(systm), 0, sizeof(systm));
    securec_check_errno(rc, (void)rc);
    currentTime = time(NULL);
    if (localtime_r(&currentTime, &systm) != NULL) {
        (void)strftime(logCreateTime, LOG_MAX_TIMELEN, "-%Y-%m-%d_%H%M%S", &systm);
    } else {
        write_runlog(LOG, "get localtime_r failed for log(%s)\n", logFilePath);
        return CM_ERROR;
    }
    /* create new log file */
    rc = memset_s(logFilePath, MAXPGPATH, 0, MAXPGPATH);
    securec_check_errno(rc, (void)rc);
    rc = snprintf_s(logTempName, MAXPGPATH, MAXPGPATH - 1, "%s%s%s", prefixLogName, logCreateTime, curLogFileMark);
    securec_check_intval(rc, (void)rc);
    rc = snprintf_s(logFilePath, MAXPGPATH, MAXPGPATH - 1, "%s/%s", sysLogPath, logTempName);
    securec_check_intval(rc, (void)rc);
    rc = memset_s(logFileName, MAXPGPATH, 0, MAXPGPATH);
    securec_check_errno(rc, (void)rc);
    rc = strncpy_s(logFileName, MAXPGPATH, logTempName, strlen(logTempName));
    securec_check_errno(rc, (void)rc);
    int fd = open(logFilePath, O_RDWR | O_CREAT | O_CLOEXEC, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        write_runlog(ERROR, "create file(%s) failed.\n", logFilePath);
        return CM_ERROR;
    }
    write_runlog(LOG, "create file(%s) success.\n", logFilePath);
    (void)close(fd);
    return CM_SUCCESS;
}

void CmKeyEventInit(void)
{
    g_cmKeyEventType[KEY_EVENT_FAILOVER]                    = "KEY_EVENT_FAILOVER";
    g_cmKeyEventType[KEY_EVENT_SWITCHOVER]                  = "KEY_EVENT_SWITCHOVER";
    g_cmKeyEventType[KEY_EVENT_RESTART]                     = "KEY_EVENT_RESTART";
    g_cmKeyEventType[KEY_EVENT_BUILD]                       = "KEY_EVENT_BUILD";
    g_cmKeyEventType[KEY_EVENT_NOTIFY]                      = "KEY_EVENT_NOTIFY";
    g_cmKeyEventType[KEY_EVENT_NOTIFY_CN]                   = "KEY_EVENT_NOTIFY_CN";
    g_cmKeyEventType[KEY_EVENT_NOTIFY_STANDBY]              = "KEY_EVENT_NOTIFY_STANDBY";
    g_cmKeyEventType[KEY_EVENT_NOTIFY_PRIMARY]              = "KEY_EVENT_NOTIFY_PRIMARY";
    g_cmKeyEventType[KEY_EVENT_FINISH_REDO]                 = "KEY_EVENT_FINISH_REDO";
    g_cmKeyEventType[KEY_EVENT_DELETE_XLOG]                 = "KEY_EVENT_DELETE_XLOG";
    g_cmKeyEventType[KEY_EVENT_REP_SYNC]                    = "KEY_EVENT_REP_SYNC";
    g_cmKeyEventType[KEY_EVENT_REP_MOST_AVAILABLE]          = "KEY_EVENT_REP_MOST_AVAILABLE";
    g_cmKeyEventType[KEY_EVENT_RELOAD_GS_GUC]               = "KEY_EVENT_RELOAD_GS_GUC";
    g_cmKeyEventType[KEY_EVENT_DELETE_CN]                   = "KEY_EVENT_DELETE_CN";
    g_cmKeyEventType[KEY_EVENT_REPAIR_CN_ACK]               = "KEY_EVENT_REPAIR_CN_ACK";
    g_cmKeyEventType[KEY_EVENT_OBS_BACKUP]                  = "KEY_EVENT_OBS_BACKUP";
    g_cmKeyEventType[KEY_EVENT_RECOVER]                     = "KEY_EVENT_RECOVER";
    g_cmKeyEventType[KEY_EVENT_REFRESH_OBS_DELETE_TEXT]     = "KEY_EVENT_REFRESH_OBS_DELETE_TEXT";
    g_cmKeyEventType[KEY_EVENT_DROP_CN_OBS_XLOG]            = "KEY_EVENT_DROP_CN_OBS_XLOG";
    g_cmKeyEventType[KEY_EVENT_RES_ARBITRATE]               = "KEY_EVENT_RES_ARBITRATE";
}

void CreateKeyEventLogFile(const char *sysLogPath)
{
    bool isExist = false;
    char *namePtr;
    errno_t rc;

    CmKeyEventInit();
    if (sysLogPath == NULL) {
        rc = strncpy_s(g_operationLogPath, MAXPGPATH, "/dev/null", strlen("/dev/null"));
        securec_check_errno(rc, (void)rc);
        return;
    }
    DIR *dir = opendir(sysLogPath);
    if (dir == NULL) {
        write_runlog(ERROR, "opendir %s failed! \n", sysLogPath);
        rc = strncpy_s(g_operationLogPath, MAXPGPATH, "/dev/null", strlen("/dev/null"));
        securec_check_errno(rc, (void)rc);
        return;
    }
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
        /* exist current log file */
        if (strstr(de->d_name, KEY_EVENT_PRE) == NULL) {
            continue;
        }
        namePtr = strstr(de->d_name, curLogFileMark);
        if (namePtr == NULL) {
            continue;
        }
        namePtr += strlen(curLogFileMark);
        if ((*namePtr) == '\0') {
            isExist = true;
            break;
        }
    }
    if (isExist) {
        rc = memset_s(g_operationLogPath, MAXPGPATH, 0, MAXPGPATH);
        securec_check_errno(rc, (void)rc);
        rc = memset_s(g_operationLogName, MAXPGPATH, 0, MAXPGPATH);
        securec_check_errno(rc, (void)rc);
        rc = snprintf_s(g_operationLogPath, MAXPGPATH, MAXPGPATH - 1, "%s/%s", sysLogPath, de->d_name);
        securec_check_intval(rc, (void)rc);
        rc = strncpy_s(g_operationLogName, MAXPGPATH, de->d_name, strlen(de->d_name));
        securec_check_errno(rc, (void)rc);
    } else {
        /* create current log file name */
        if (CreateNewLogFile(sysLogPath, KEY_EVENT_PRE, g_operationLogPath, g_operationLogName) == CM_ERROR) {
            rc = strncpy_s(g_operationLogPath, MAXPGPATH, "/dev/null", strlen("/dev/null"));
            securec_check_errno(rc, (void)rc);
        }
    }
    (void)closedir(dir);
}

bool CheckLogFileStat(const char *fileName)
{
    struct stat statbuff;
    int ret;
    errno_t rc = memset_s(&statbuff, sizeof(statbuff), 0, sizeof(statbuff));
    securec_check_errno(rc, (void)rc);
    ret = stat(fileName, &statbuff);
    if (ret != 0 || (strncmp(fileName, "/dev/null", strlen("/dev/null")) == 0)) {
        write_runlog(ERROR, "stat log %s error, ret=%d.\n", fileName, ret);
        return false;
    }
    long filesize = statbuff.st_size;
    /* Check Log File Permissions */
    if (!S_ISREG(statbuff.st_mode) || (statbuff.st_mode & (S_IRWXG | S_IRWXO | S_IXUSR))) {
        write_runlog(ERROR, "[CheckLogFileStat] %s has execute, group or world access permission.\n", fileName);
        return true;
    }
    /* Check Log File size */
    if (filesize > maxLogFileSize) {
        return true;
    }
    return false;
}

void RenameLogFile(const char *sysLogPath, const char *logFilePath, const char *logFileName)
{
    size_t oldNameLen, suffixNameLen;
    char logFileBuff[MAXPGPATH] = {0};
    char newName[MAXPGPATH] = {0};
    errno_t rc;
    int ret;
    /* renamed the current file without  Mark */
    oldNameLen = strlen(logFileName);
    suffixNameLen = strlen(curLogFileMark);
    size_t newNameLen = oldNameLen - suffixNameLen;
    rc = strncpy_s(logFileBuff, MAXPGPATH, logFileName, newNameLen);
    securec_check_errno(rc, (void)rc);
    rc = strncat_s(logFileBuff, MAXPGPATH, ".log", strlen(".log"));
    securec_check_errno(rc, (void)rc);
    rc = snprintf_s(newName, MAXPGPATH, MAXPGPATH - 1, "%s/%s", sysLogPath, logFileBuff);
    securec_check_intval(rc, (void)rc);
    ret = rename(logFilePath, newName);
    if (ret != 0) {
        write_runlog(ERROR, "ERROR: %s: rename log file %s failed! \n", logFilePath, logFilePath);
    }
    return;
}

void CheckAndSwitchLogFile(const char *sysLogPath, const char *prefixLogName, char *logFilePath, char *logFileName)
{
    status_t ret;
    if (CheckLogFileStat(logFilePath)) {
        RenameLogFile(sysLogPath, logFilePath, logFileName);
        ret = CreateNewLogFile(sysLogPath, prefixLogName, logFilePath, logFileName);
        if (ret == CM_SUCCESS) {
            write_runlog(LOG, "Create new log file(%s) successfully! \n", logFileName);
        }
    }
}

void AddTimeLogPrefix(char *str, unsigned int strlen)
{
    int rcs;
    setup_formatted_log_time();

    if (thread_name == NULL) {
        thread_name = "";
    }
    ErrBufCtx *errCtx = GetErrBufCtx();
    rcs = snprintf_s(str, strlen, strlen - 1, "%s tid=%ld %s: ", errCtx->fmtLogTime, gettid(), thread_name);
    securec_check_intval(rcs, (void)rcs);
}

void write_stderr(const char* fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    (void)vfprintf(stdout, fmt, ap);
    (void)fflush(stdout);
    va_end(ap);
}

void WriteKeyEventLog(KeyEventType keyEventType, uint32 instanceId, const char *fmt, ...)
{
    const unsigned int logLen = 2048;
    va_list ap;
    int rcs;
    char logBuf[logLen] = {0};
    char format[logLen] = {0};
    char details[logLen] = {0};

    AddTimeLogPrefix(logBuf, logLen);
    fmt = _(fmt);
    va_start(ap, fmt);
    rcs = vsnprintf_s(details, sizeof(details), sizeof(details) - 1, fmt, ap);
    securec_check_intval(rcs, (void)rcs);
    va_end(ap);

    rcs = snprintf_s(format, sizeof(format), sizeof(format) - 1, "[KeyEvent: %s] [Instance: %u] [Details: %s]\n",
        g_cmKeyEventType[keyEventType], instanceId, details);
    securec_check_intval(rcs, (void)rcs);
    rcs = strcat_s(logBuf, sizeof(logBuf), format);
    securec_check_errno(rcs, (void)rcs);

    (void)pthread_rwlock_wrlock(&g_operationLogWriteLock);
    CheckAndSwitchLogFile(sys_log_path, "key_event", g_operationLogPath, g_operationLogName);
    canonicalize_path(g_operationLogPath);
    FILE *logFile = fopen(g_operationLogPath, "a");
    size_t actualLogLen = strlen(logBuf);
    if (logFile != NULL) {
        if (fwrite(logBuf, 1, actualLogLen, logFile) != actualLogLen) {
            write_runlog(ERROR, "could not write to log file: %s.\n", g_operationLogName);
        }
        (void)fflush(logFile);
        (void)fclose(logFile);
    } else {
        write_runlog(ERROR, "write_log_file could not open log file  %s.\n", g_operationLogName);
    }
    (void)pthread_rwlock_unlock(&g_operationLogWriteLock);
    write_runlog(LOG, "%s", format);
}
