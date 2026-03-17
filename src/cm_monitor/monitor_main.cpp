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
 * monitor_main.cpp
 *    om_moniter check cm_agent and etcd.
 *
 * IDENTIFICATION
 *    src/cm_monitor/monitor_main.cpp
 *
 * -------------------------------------------------------------------------
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/procfs.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/file.h>

#include "cm/pqsignal.h"
#include "cm/stringinfo.h"
#include "cm/cm_elog.h"
#include "cm/cm_cgroup.h"
#include "cm/cm_misc.h"
#include "common/config/cm_config.h"
#include "getopt_long.h"
#include "alarm/alarm.h"

#include <sys/mman.h>
#include <mntent.h>
#include "utils/syscall_lock.h"
#include "alarm/alarm_log.h"
#include "config.h"
#include "cm/cm_c.h"

pid_t g_cmAgentPid = 0;

#define LOGIC_CLUSTER_LIST "logic_cluster_name.txt"

#define MAX_PORT_LEN (8)
#define TRY_COUNT_FOR_KILL_ETCD_REPLACE (5)

/* year(4) + -(1) + month(2) -(1) + day (2) +(1) + hour(2) + minute(2) + second(2) + \0 */
#define LEN_TIMESTAMP (18)

#define CM_AGENT_PID_FILE   "cm_agent.pid"
#define CM_AGENT_CONFIG     "cm_agent.conf"
/* sleep time between two om_monitor detections */
#define MONITOR_CHECK_INTERVAL (1)

/* how many times T status in detection to treat it as HANG */
#define HANG_T_DETECT_MAX_TIMES (3)

#ifdef ENABLE_MULTIPLE_NODES
typedef enum { PROCKIND_ETCD, PROCKIND_CMAGENT, PROCKIND_MONITOR, PROCKIND_MAX } ProcessKind;
#else
typedef enum { PROCKIND_ETCD, PROCKIND_CMAGENT, PROCKIND_MONITOR, PROCKIND_ITRAN, PROCKIND_MAX } ProcessKind;
#endif

static char g_cmAgentBinPath[MAX_PATH_LEN];
static char g_etcdBinPath[MAX_PATH_LEN];
char g_cmManualStartPath[MAX_PATH_LEN];
static char g_etcdManualStartPath[MAX_PATH_LEN];
#ifndef ENABLE_MULTIPLE_NODES
char g_ltranManualStartPath[MAX_PATH_LEN];
char g_libnetManualStartFile[MAX_PATH_LEN];
#endif
static char g_etcdReplacedPath[MAX_PATH_LEN]; /* etcd_replaced file path. */
static char g_cmUpgradeManualStartPath[MAX_PATH_LEN];
static char g_cmRollbackManualStartPath[MAX_PATH_LEN];
static char g_cmStaticConfigChangeFlagFilePath[MAX_PATH_LEN];
char g_cmStaticConfigurePath[MAX_PATH_LEN];
char g_logicClusterListPath[MAX_PATH_LEN];
static char g_noCgroupFlag[MAX_PATH_LEN];
static char g_agentConfigPath[MAXPGPATH];

static char g_alarmConfigPath[MAX_PATH_LEN];
Alarm *g_startupAlarmList = NULL;
int g_startupAlarmListSize = 0;
bool g_isStart = false;
static bool g_isAttachToCgroup = false;

static int g_myProcPid = 0;
int g_tcpKeepalivesIdle = 0;
int g_tcpKeepalivesInterval = 0;
int g_tcpKeepalivesCount = 0;
static uid_t g_myUid = 0;

static int g_previousStatus = 0;
static int g_agentFaultCount = 0;
static char g_monitorLockfile[MAX_PATH_LEN] = {0};
FILE *g_lockfile = NULL;

const char *g_progname;

extern char g_curLogFileName[MAXPGPATH];
extern char sys_log_path[MAX_PATH_LEN];
extern FILE *syslogFile;

extern volatile int maxLogFileSize;
extern bool g_logFileSet;
extern char system_alarm_log[MAXPGPATH];
char *g_logFile;

EtcdTlsAuthPath g_tlsPath = {0};
static char g_curEtcdLogFile[MAXPGPATH] = {0};
static char g_etcdLogPath[MAX_PATH_LEN] = {0};

static int g_startEtcdCount = 0;
static int g_replaceEtcdCount = 0;

static void check_ETCD_process_status(AlarmAdditionalParam *additionalParam, const char *userName);
int check_process_status(ProcessKind type, pid_t parentPid, bool *isKillProcess = NULL);
static int MonitorLock(bool isKillProcess);
static int MonitorUnlock(void);

/**
 * @brief
 *  Check whether the CM Agent meets the startup conditions.
 *
 * @return
 *  Return whether the CM Agent meets the startup conditions.
 */
static bool check_start_request();

int cmmonitor_getenv(const char *env_var, char *output_env_value, uint32 env_value_len)
{
    if (env_var == NULL) {
        (void)fprintf(stderr, "cmmonitor_getenv: invalid env_var !\n");
        return -1;
    }

    (void)syscalllockAcquire(&g_cmEnvLock);
    char *env_value = getenv(env_var);
    if (env_value == NULL || env_value[0] == '\0') {
        (void)fprintf(stderr,
            "cmmonitor_getenv: failed to get environment variable:%s. Please check and make sure it is configured!\n",
            env_var);
        (void)syscalllockRelease(&g_cmEnvLock);
        return -1;
    }
    CheckEnvValue(env_value);

    int rc = strcpy_s(output_env_value, env_value_len, env_value);
    if (rc != EOK) {
        (void)fprintf(stderr,
            "cmmonitor_getenv: failed to get environment variable:%s, variable length:%lu.\n",
            env_var,
            strlen(env_value));
        (void)syscalllockRelease(&g_cmEnvLock);
        return -1;
    }

    (void)syscalllockRelease(&g_cmEnvLock);

    return EOK;
}

void StartupAlarmItemInitialize(const staticNodeConfig *currentNode)
{
    g_startupAlarmListSize = 1;

    if (currentNode->etcd) {
        g_startupAlarmListSize += 1;
    }

    g_startupAlarmList = (Alarm *)malloc(sizeof(Alarm) * (size_t)g_startupAlarmListSize);
    if (g_startupAlarmList == NULL) {
        AlarmLog(ALM_LOG, "Out of memory: StartupAlarmItemInitialize failed.\n");
        exit(1);
    }

    int alarmIndex = g_startupAlarmListSize - 1;

    /* ALM_AI_AbnormalCMAProcess. */
    AlarmItemInitialize(&(g_startupAlarmList[alarmIndex]), ALM_AI_AbnormalCMAProcess, ALM_AS_Normal, NULL);

    --alarmIndex;

    for (; alarmIndex >= 0; --alarmIndex) {
        /* ALM_AI_AbnormalETCDProcess. */
        AlarmItemInitialize(&(g_startupAlarmList[alarmIndex]), ALM_AI_AbnormalETCDProcess, ALM_AS_Normal, NULL);
    }
}

void GetCmdlineOpt(int argc, char *const argv[])
{
    long logChoice = 0;
    const int base = 10;

    /* Default value shall be log file. */
    Assert(log_destion_choice == LOG_DESTION_FILE);

    if (argc > 1) {
        logChoice = strtol(argv[1], NULL, base);

        switch (logChoice) {
            case LOG_DESTION_STDERR:
                log_destion_choice = LOG_DESTION_FILE;
                break;

            case LOG_DESTION_SYSLOG:
                log_destion_choice = LOG_DESTION_SYSLOG;
                break;

            case LOG_DESTION_FILE:
                log_destion_choice = LOG_DESTION_FILE;
                break;

            case LOG_DESTION_DEV_NULL:
                log_destion_choice = LOG_DESTION_DEV_NULL;
                break;

            default:
                log_destion_choice = LOG_DESTION_FILE;
                break;
        }
    }
}

static const char *GetProcessName(ProcessKind type)
{
    switch (type) {
        case PROCKIND_ETCD:
            return "etcd";
        case PROCKIND_CMAGENT:
            return "cm_agent";
        case PROCKIND_MONITOR:
            return "om_monitor";
#ifndef ENABLE_MULTIPLE_NODES
        case PROCKIND_ITRAN:
            return "ltran";
#endif
        default:
            return "UNKOWN";
    }
}

static bool IsNeedKillProcess(const char *processName, int pid, int ppid)
{
    if (strcmp(processName, "cm_agent") != 0) {
        return true;
    }

    /* some sub process of cm_agent, whose ppid is cm_agent, not om_monitor, should not be killed.
    eg: check_cmd in etcd_disk_quota_check(), commandstr in IsMyPostmasterPid(), called by cmagent by popen() */
    if (ppid == g_cmAgentPid) {
        return false;
    }

    char cmdPath[MAX_PATH_LEN] = {0};
    char getBuff[MAX_PATH_LEN] = {0};
    const char *parameter[] = {"-h", "--help", "-?", "-V", "--version", NULL};

    int rcs = snprintf_s(cmdPath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/proc/%d/cmdline", pid);
    securec_check_intval(rcs, (void)rcs);

    FILE *fp = fopen(cmdPath, "r");
    if (fp == NULL) {
        return true;
    }

    bool isNeedKillProcess = true;
    if (fgets(getBuff, MAX_PATH_LEN - 1, fp) != NULL) {
        char *temp = getBuff + strlen(getBuff) + 1;
        for (int i = 0; parameter[i] != NULL; i++) {
            if (strcmp(temp, parameter[i]) == 0) {
                isNeedKillProcess = false;
                break;
            }
        }
    }
    (void)fclose(fp);
    return isNeedKillProcess;
}

static void SetKillProcessValue(bool *isKillProcess)
{
    if (isKillProcess != NULL) {
        *isKillProcess = true;
    }
}

int check_process_status(ProcessKind type, pid_t parentPid, bool *isKillProcess)
{
    struct dirent *de;
    char pid_path[MAX_PATH_LEN];
    FILE *fp = NULL;
    char getBuff[MAX_PATH_LEN];
    char paraName[MAX_PATH_LEN];
    char paraValue[MAX_PATH_LEN];
    int tgid = 0;
    int spid = 0;
    int pid = 0;
    int ppid = 0;
    char state = '0';
    uid_t uid = 0;
    uid_t uid1 = 0;
    uid_t uid2 = 0;
    uid_t uid3 = 0;
    bool nameFound = false;
    bool nameGet = false;
    bool tgidGet = false;
    bool spidGet = false;
    bool ppidGet = false;
    bool stateGet = false;
    bool haveFound = false;
    bool uidGet = false;
    errno_t rc;
    int rcs;
    const char *processName = GetProcessName(type);
    bool isProcessFile = false;

    DIR *dir = opendir("/proc");
    if (dir == NULL) {
        write_runlog(ERROR, "opendir(/proc) failed! \n ");
        return -1;
    }

    while ((de = readdir(dir)) != NULL) {
        /*
         * judging whether the directory name is composed by digitals, if so, we will
         * check whether there are files under the directory , these files includes
         * all detailed information about the process.
         */
        if (CM_is_str_all_digit(de->d_name) != 0) {
            continue;
        }
        isProcessFile = true;

    MONITOR_RETRIES:
        rc = memset_s(pid_path, MAX_PATH_LEN, 0, MAX_PATH_LEN);
        securec_check_errno(rc, (void)rc);
        pid = (int)strtol(de->d_name, NULL, 10);
        {
            rcs = snprintf_s(pid_path, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/proc/%d/status", pid);
            securec_check_intval(rcs, (void)rcs);
        }

        /* maybe fail because of privilege */
        fp = fopen(pid_path, "r");
        if (fp == NULL) {
            continue;
        }

        nameGet = false;
        tgidGet = false;
        spidGet = false;
        ppidGet = false;
        stateGet = false;
        uidGet = false;
        rc = memset_s(paraValue, MAX_PATH_LEN, 0, MAX_PATH_LEN);
        securec_check_errno(rc, (void)rc);
        tgid = 0;
        spid = 0;
        ppid = 0;
        state = '0';
        uid = 0;
        rc = memset_s(getBuff, MAX_PATH_LEN, 0, MAX_PATH_LEN);
        securec_check_errno(rc, (void)rc);
        nameFound = false;

        /* parse process's status file */
        while (fgets(getBuff, MAX_PATH_LEN - 1, fp) != NULL) {
            rc = memset_s(paraName, MAX_PATH_LEN, 0, MAX_PATH_LEN);
            securec_check_errno(rc, (void)rc);

            if (!nameGet && (strstr(getBuff, "Name:") != NULL)) {
                nameGet = true;
                rcs = sscanf_s(getBuff, "%s %s", paraName, MAX_PATH_LEN, paraValue, MAX_PATH_LEN);
                check_sscanf_s_result(rcs, 2);
                securec_check_intval(rcs, (void)rcs);

                if (strcmp(processName, paraValue) == 0) {
                    nameFound = true;
                } else {
                    break;
                }
            }

            if (!tgidGet && (strstr(getBuff, "Tgid:") != NULL)) {
                tgidGet = true;
                rcs = sscanf_s(getBuff, "%s	%d", paraName, MAX_PATH_LEN, &tgid);
                check_sscanf_s_result(rcs, 2);
                securec_check_intval(rcs, (void)rcs);
            }

            if (!spidGet && (strstr(getBuff, "Pid:") != NULL)) {
                spidGet = true;
                rcs = sscanf_s(getBuff, "%s	%d", paraName, MAX_PATH_LEN, &spid);
                check_sscanf_s_result(rcs, 2);
                securec_check_intval(rcs, (void)rcs);
            }

            if (!ppidGet && (strstr(getBuff, "PPid:") != NULL)) {
                ppidGet = true;
                rcs = sscanf_s(getBuff, "%s	%d", paraName, MAX_PATH_LEN, &ppid);
                check_sscanf_s_result(rcs, 2);
                securec_check_intval(rcs, (void)rcs);
            }

            if (!stateGet && (strstr(getBuff, "State:") != NULL)) {
                stateGet = true;
                rcs = sscanf_s(getBuff, "%s	%c", paraName, MAX_PATH_LEN, &state, 1);
                check_sscanf_s_result(rcs, 2);
                securec_check_intval(rcs, (void)rcs);
            }

            if (!uidGet && (strstr(getBuff, "Uid:") != NULL)) {
                uidGet = true;
                rcs =
                    sscanf_s(getBuff, "%s    %u    %u    %u    %u", paraName, MAX_PATH_LEN, &uid, &uid1, &uid2, &uid3);
                check_sscanf_s_result(rcs, 5);
                securec_check_intval(rcs, (void)rcs);
            }

            /* Once all used attributes are analysis out, stop doing more. */
            if (nameGet && tgidGet && spidGet && ppidGet && stateGet && uidGet) {
                break;
            }
        }
        (void)fclose(fp);

        /*
         * Skip following four kinds of process:
         * (1) matched process with specified name;
         * (2) this is not om_monitor itself;
         * (3) this is the child process of some one;
         * (4) this is not current user's process.
         */
        if (nameFound && g_myProcPid != spid && tgid == spid && g_myUid == uid) {
            if ((parentPid != 0) && (ppid != parentPid) && IsNeedKillProcess(processName, pid, ppid)) {
                write_runlog(LOG,
                    "kill process %s, tgid is %d, pid is %d, ppid:%d is not equal to parentPid:%d \n",
                    processName,
                    tgid,
                    spid,
                    ppid,
                    parentPid);
                if (kill(spid, SIGKILL) < 0) {
                    write_runlog(LOG, "failed to kill process (%s:%d)\n", processName, spid);
                }
                continue;
            } else if (stateGet) {
                /* how many times process has persisted in T status */
                static int persistTTimes[PROCKIND_MAX] = {0};

                if (state == 'T' || state == 't') {
                    /* one more HANG is detected. */
                    persistTTimes[type]++;

                    /* Up to HANG_T_DETECT_MAX_TIMES times, kill this HANG process. */
                    if (persistTTimes[type] >= HANG_T_DETECT_MAX_TIMES) {
                        write_runlog(LOG,
                            "kill process (%s:%d)"
                            " due to STOPPED status!\n",
                            processName,
                            spid);
                        if (kill(spid, SIGKILL) < 0) {
                            write_runlog(LOG, "failed to kill process (%s:%d)\n", processName, spid);
                        } else {
                            SetKillProcessValue(isKillProcess);
                        }
                    } else if (type == PROCKIND_MONITOR) {
                        /* kill monitor if it is in T status during 3 seconds */
                        cm_sleep(1);
                        goto MONITOR_RETRIES;
                    } else {
                        write_runlog(LOG,
                            "Process (%s:%d)'s state is T (TASK_STOPPED"
                            " or TASK_TRACED), times=%d\n",
                            processName,
                            spid,
                            persistTTimes[type]);
                        haveFound = true;
                    }
                    continue;
                } else if (state == 'D' || state == 'd') {
                    /* can't be killed, just show some hint. */
                    write_runlog(LOG, "Process (%s:%d)'s state is D (TASK_UNINTERRUPTIBLE)\n", processName, spid);
                } else if (state == 'Z' || state == 'z') {
                    /* can't be killed, just show some hint. */
                    write_runlog(LOG, "Process (%s:%d)'s state is Z (TASK_DEAD)\n", processName, spid);
                }

                /* reset its 'T' times. */
                persistTTimes[type] = 0;
            }
            haveFound = true;
        }
    }
    (void)closedir(dir);

    if (!isProcessFile) {
        write_runlog(LOG, "the process files may not exist in /proc.\n");
        return PROCESS_UNKNOWN;
    }

    return haveFound ? PROCESS_RUNNING : PROCESS_NOT_EXIST;
}

int get_prog_path()
{
    char execPath[MAX_PATH_LEN] = {0};

    errno_t rc = memset_s(g_cmManualStartPath, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(g_etcdManualStartPath, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
#ifndef ENABLE_MULTIPLE_NODES
    rc = memset_s(g_ltranManualStartPath, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(g_libnetManualStartFile, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
#endif
    rc = memset_s(g_etcdReplacedPath, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(g_cmAgentBinPath, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(g_etcdBinPath, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(g_cmStaticConfigChangeFlagFilePath, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(g_cmStaticConfigurePath, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(g_alarmConfigPath, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(g_tlsPath.etcd_ca_path, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(g_tlsPath.client_crt_path, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(g_tlsPath.client_key_path, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(g_cmUpgradeManualStartPath, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(g_cmRollbackManualStartPath, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(g_logicClusterListPath, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(g_monitorLockfile, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);

    int rcs = GetHomePath(execPath, sizeof(execPath));
    if (rcs != EOK) {
        (void)fprintf(stderr, "Get GAUSSHOME failed, please check.\n");
        return -1;
    } else {
        canonicalize_path(execPath);
        rcs = snprintf_s(g_cmManualStartPath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/cluster_manual_start", execPath);
        securec_check_intval(rcs, (void)rcs);
        rcs = snprintf_s(g_etcdManualStartPath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/etcd_manual_start", execPath);
        securec_check_intval(rcs, (void)rcs);
#ifndef ENABLE_MULTIPLE_NODES
        rcs = snprintf_s(g_ltranManualStartPath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/ltran_manual_start", execPath);
        securec_check_intval(rcs, (void)rcs);
        rcs =
            snprintf_s(g_libnetManualStartFile, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/libnet_manual_start", execPath);
        securec_check_intval(rcs, (void)rcs);
#endif
        rcs = snprintf_s(g_etcdReplacedPath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/etcd_replaced", execPath);
        securec_check_intval(rcs, (void)rcs);
        rcs = snprintf_s(g_cmAgentBinPath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/cm_agent", execPath);
        securec_check_intval(rcs, (void)rcs);
        rcs = snprintf_s(g_etcdBinPath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/etcd", execPath);
        securec_check_intval(rcs, (void)rcs);
        rcs = snprintf_s(g_cmStaticConfigChangeFlagFilePath,
            MAX_PATH_LEN,
            MAX_PATH_LEN - 1,
            "%s/bin/cluster_dilatation_status",
            execPath);
        securec_check_intval(rcs, (void)rcs);
        rcs = snprintf_s(
            g_cmStaticConfigurePath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/cluster_static_config", execPath);
        securec_check_intval(rcs, (void)rcs);
        rcs = snprintf_s(g_alarmConfigPath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/alarmConfig.conf", execPath);
        securec_check_intval(rcs, (void)rcs);
        rcs = snprintf_s(
            g_tlsPath.etcd_ca_path, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/share/sslcert/etcd/etcdca.crt", execPath);
        securec_check_intval(rcs, (void)rcs);
        rcs = snprintf_s(
            g_tlsPath.client_crt_path, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/share/sslcert/etcd/client.crt", execPath);
        securec_check_intval(rcs, (void)rcs);
        rcs = snprintf_s(
            g_tlsPath.client_key_path, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/share/sslcert/etcd/client.key", execPath);
        securec_check_intval(rcs, (void)rcs);
        rcs = snprintf_s(g_cmUpgradeManualStartPath,
            MAX_PATH_LEN,
            MAX_PATH_LEN - 1,
            "%s/bin/cluster_upgrade_manual_start",
            execPath);
        securec_check_intval(rcs, (void)rcs);
        rcs = snprintf_s(g_cmRollbackManualStartPath,
            MAX_PATH_LEN,
            MAX_PATH_LEN - 1,
            "%s/bin/cluster_rollback_manual_start",
            execPath);
        securec_check_intval(rcs, (void)rcs);
        rcs = snprintf_s(g_noCgroupFlag, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/no_cm_cgroup", execPath);
        securec_check_intval(rcs, (void)rcs);
        rcs = snprintf_s(
            g_logicClusterListPath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/%s", execPath, LOGIC_CLUSTER_LIST);
        securec_check_intval(rcs, (void)rcs);
        rc = snprintf_s(g_monitorLockfile, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/om_monitor.lock", execPath);
        securec_check_intval(rc, (void)rcs);
        check_input_for_security(g_monitorLockfile);
        canonicalize_path(g_monitorLockfile);
    }

    return 0;
}

bool CheckOfflineNode()
{
    char env[MAX_PATH_LEN] = {0};

    if (cmmonitor_getenv("DORADO_REARRANGE", env, sizeof(env)) != EOK) {
        write_runlog(LOG, "Line:%d Get DORADO_REARRANGE failed, please check.\n", __LINE__);
        return false;
    }
    if (strcmp(env, "offline") == 0) {
        write_runlog(LOG, "Line:%d DORADO_REARRANGE is offline.\n", __LINE__);
        return true;
    }

    return false;
}

void CreateEtcdLogPath()
{
    char gausslog[MAXPGPATH] = {0};

    errno_t rc = memset_s(gausslog, sizeof(gausslog), 0, MAXPGPATH);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(g_etcdLogPath, MAXPGPATH, 0, MAXPGPATH);
    securec_check_errno(rc, (void)rc);

    int rcs = cmmonitor_getenv("GAUSSLOG", gausslog, sizeof(gausslog));
    if (rcs != EOK) {
        (void)fprintf(stderr, "FATAL The environment variable 'GAUSSLOG' was not specified.\n");
        exit(-1);
    }
    CheckEnvValue(gausslog);

    if (CheckOfflineNode()) {
        uint32 nodeIndex = 0;
        int ret = find_node_index_by_nodeid(g_nodeHeader.node, &nodeIndex);
        if (ret != 0) {
            write_runlog(ERROR, "create etcd directory get node index failed!\n");
            return;
        }
        rcs = snprintf_s(g_etcdLogPath,
            sizeof(g_etcdLogPath),
            MAX_PATH_LEN - 1,
            "%s/etcdlog/",
            g_node[nodeIndex].etcdDataPath);
        securec_check_intval(rcs, (void)rcs);
        if (mkdir(g_etcdLogPath, S_IRWXU) != 0) {
            write_runlog(ERROR, "create directory(%s) failed, errno: %d.\n", g_etcdLogPath, errno);
        } else {
            write_runlog(LOG, "create etcd directory(%s) successfully.\n", g_etcdLogPath);
        }
        rcs = strncat_s(g_etcdLogPath, sizeof(g_etcdLogPath), "etcd", strlen("etcd"));
        securec_check_errno(rcs, (void)rcs);
    } else {
        rcs = snprintf_s(g_etcdLogPath, sizeof(g_etcdLogPath), MAX_PATH_LEN - 1, "%s/cm/etcd", gausslog);
        securec_check_intval(rcs, (void)rcs);
    }

    rcs = snprintf_s(g_curEtcdLogFile, MAXPGPATH, MAXPGPATH - 1, "%s/%s%s", g_etcdLogPath, "etcd", curLogFileMark);
    securec_check_intval(rcs, (void)rcs);
    check_input_for_security(g_curEtcdLogFile);
    canonicalize_path(g_curEtcdLogFile);

    if (mkdir(g_etcdLogPath, S_IRWXU) != 0) {
        write_runlog(ERROR, "create etcd directory(%s) failed, errno: %d.\n", g_etcdLogPath, errno);
    } else {
        write_runlog(LOG, "create etcd directory(%s) successfully.\n", g_etcdLogPath);
    }
}

int start_cm_agent(void)
{
    pid_t pid;
    int status;
    bool inUpgrade = false;
    bool inRollback = false;
    struct stat stat_buf = {0};

    pid = fork();
    /* If current process is child process. */
    if (pid == 0) {
        int fd = open(g_curLogFileName, O_RDWR | O_APPEND | O_CREAT, 0600);
        if (fd == -1) {
            char errBuffer[ERROR_LIMIT_LEN];
            write_runlog(ERROR,
                "can not open execl call log file: %s %s\n",
                g_curLogFileName,
                strerror_r(errno, errBuffer, ERROR_LIMIT_LEN));
        } else {
            (void)dup2(fd, STDOUT_FILENO);
            (void)dup2(fd, STDERR_FILENO);
            (void)close(fd);
        }

        /* check cluster_upgrade_manual_start file. */
        if (stat(g_cmUpgradeManualStartPath, &stat_buf) == 0) {
            /* if the cluster_upgrade_manual_start exists. */
            inUpgrade = true;
        }

        /* check cluster_rollback_manual_start file. */
        if (stat(g_cmRollbackManualStartPath, &stat_buf) == 0) {
            /* if the cluster_rollback_manual_start exists. */
            inRollback = true;
        }

        if (g_isStart || inUpgrade || inRollback) {
            /* the cm_agent is started normally. */
            status = execl(g_cmAgentBinPath, g_cmAgentBinPath, "normal", (char *)0);
        } else {
            /* the cm_agent is started by killed. */
            status = execl(g_cmAgentBinPath, g_cmAgentBinPath, "abnormal", (char *)0);
        }

        if (status < 0) {
            write_runlog(FATAL, "execl cm_agent faild! path is %s\n", g_cmAgentBinPath);
            _exit(1);
        }

        _exit(1);
    }

    return (int)pid;
}

#ifdef ENABLE_LLT
extern "C" {
extern void HLLT_Coverage_SaveCoverageData();
}
#endif

static int get_current_timestamp(char *timestamp, size_t len)
{
    pg_time_t currentTime = time(NULL);
    struct tm *t = localtime(&currentTime);
    if (t != NULL) {
        (void)strftime(timestamp, len, "%Y-%m-%d_%H%M%S", t);
        return 0;
    }

    return -1;
}

static void CreateEtcdLog()
{
    if (access(g_curEtcdLogFile, F_OK) != -1) {
        return;
    }

    char createTime[LEN_TIMESTAMP] = {0};
    char buff[LOG_MAX_TIMELEN];
    size_t counter;
    int rcs;
    mode_t oumask;

    if (get_current_timestamp(createTime, LEN_TIMESTAMP) != 0) {
        write_runlog(ERROR, "create etcd log get timestamp error\n");
        return;
    }

    rcs = snprintf_s(buff, LOG_MAX_TIMELEN, LOG_MAX_TIMELEN - 1, "log_file_create_time=%s\n", createTime);
    securec_check_intval(rcs, (void)rcs);
    oumask = umask((mode_t)((~(mode_t)(S_IRUSR | S_IWUSR | S_IXUSR)) & (S_IRWXU | S_IRWXG | S_IRWXO)));
    FILE *etcdLogFile = fopen(g_curEtcdLogFile, "w+");
    (void)umask(oumask);
    if (etcdLogFile == NULL) {
        write_runlog(ERROR, "create etcd log file failed! errno is %s\n", strerror(errno));
        return;
    }
    counter = fwrite(buff, sizeof(char), LOG_MAX_TIMELEN, etcdLogFile);
    write_runlog(LOG, "counter is %lu\n", counter);
    (void)fclose(etcdLogFile);
}

static void switch_ETCD_logfile()
{
    struct stat statBuf = {0};

    if (stat(g_curEtcdLogFile, &statBuf) == 0 && statBuf.st_size > maxLogFileSize) {
        char command[MAXPGPATH * 4] = {0};
        char hstEtcdLogFile[MAXPGPATH] = {0};
        int rcs;

        char createTime[LEN_TIMESTAMP] = {0};
        if (get_current_timestamp(createTime, LEN_TIMESTAMP) != 0) {
            write_runlog(ERROR, "get timestamp error\n");
            return;
        }

        rcs = snprintf_s(hstEtcdLogFile, MAXPGPATH, MAXPGPATH - 1, "%s/%s-%s.log", g_etcdLogPath, "etcd", createTime);
        securec_check_intval(rcs, (void)rcs);

        /* copy current to history and clean current file. (sed -c -i not supported on some systems) */
        rcs = snprintf_s(command,
            4 * MAXPGPATH,
            (4 * MAXPGPATH) - 1,
            "cp %s %s;echo \"log_file_create_time=%s\" > %s;",
            g_curEtcdLogFile, hstEtcdLogFile, createTime, g_curEtcdLogFile);
        securec_check_intval(rcs, (void)rcs);

        rcs = system(command);
        if (rcs != 0) {
            write_runlog(ERROR,
                "failed to switch ETCD logfile. cmd:%s. return:(%d,%d), errno=%d.\n",
                command,
                rcs,
                WEXITSTATUS(rcs),
                errno);
        } else {
            write_runlog(LOG, "switch ETCD logfile successfully. cmd:%s.\n", command);
        }
    }
}

#ifndef ENABLE_MULTIPLE_NODES
static void KillLtranProcess()
{
    char command[MAXPGPATH] = {0};
    int ret = snprintf_s(command,
        2 * MAXPGPATH,
        2 * MAXPGPATH - 1,
        SYSTEMQUOTE "killall ltran >> \"%s\" 2>&1 &" SYSTEMQUOTE,
        g_curLogFileName);
    securec_check_ss_c(ret, "", "");
    write_runlog(LOG, "kill ltran! command=%s \n", command);
    ret = system(command);
    if (ret != 0) {
        write_runlog(ERROR, "run system command failed %d! %s, errno=%d.\n", ret, command, errno);
    }
}

static void CheckLtranProcessStatus()
{
    char command[MAXPGPATH] = {0};
    char ltranConfDir[MAX_PATH_LEN] = {0};
    int rcs = strcpy_s(ltranConfDir, MAX_PATH_LEN, "/usr/share/libnet/ltran.conf");
    securec_check_errno(rcs, (void)rcs);
    if (access(g_ltranManualStartPath, 0) != 0) {
        if (check_process_status(PROCKIND_ITRAN, 0) == PROCESS_NOT_EXIST) {
            write_runlog(DEBUG1, "The result for checking libnet nic is sucessfully\n");
            int rc = snprintf_s(command,
                MAXPGPATH,
                MAXPGPATH - 1,
                "ltran --config-file %s  >> \"%s\" 2>&1 &",
                ltranConfDir,
                g_curLogFileName);
            securec_check_intval(rc, (void)rc);
            write_runlog(LOG, "ltran START system(command:%s)\n", command);
            rc = system(command);
            if (rc != 0) {
                write_runlog(ERROR, "run system command failed %d! %s, errno=%d.\n", rcs, command, errno);
            }
        }
    } else {
        if (check_process_status(PROCKIND_ITRAN, 0) == PROCESS_RUNNING) {
            KillLtranProcess();
        }
    }
}
#endif

int server_loop(void)
{
    int status;
    int pid; /* process id of dead child process */
    struct stat stat_buf = {0};
    char agentPidFile[MAXPGPATH] = {0};
    int startCMACount = 0;
    int startRetryTimes = 3;
    AlarmAdditionalParam tempAdditionalParam;

    struct passwd *pw = getpwuid(getuid());

    errno_t rc = snprintf_s(agentPidFile, MAXPGPATH, MAXPGPATH - 1, "%s/%s", g_agentConfigPath, CM_AGENT_PID_FILE);
    securec_check_intval(rc, (void)rc);
    check_input_for_security(agentPidFile);
    canonicalize_path(agentPidFile);

    if (pw == NULL || pw->pw_name == NULL) {
        write_runlog(FATAL, "can not get current user name.\n");
        return -1;
    }

    for (;;) {
        pid = waitpid(-1, &status, WNOHANG);
        if (pid > 0) {
            write_runlog(LOG, "child process cm_agent have die! pid is %d, exit status is %d\n ", pid, status);
            /* If the exit code is not 0, we will record the last exit code of the CM Agent. */
            if (WIFEXITED(status)) {
                write_runlog(LOG, "cm_agent exited, status=%d\n", WEXITSTATUS(status));
            } else if (WIFSIGNALED(status)) {
                write_runlog(LOG, "cm_agent killed by signal %d\n", WTERMSIG(status));
            }
            if (pid == g_cmAgentPid) {
                if (status != 0) {
                    g_agentFaultCount++;
                    g_previousStatus = status;
                } else {
                    g_agentFaultCount = 0;
                    g_previousStatus = 0;
                }
            }

            delete_lock_file(agentPidFile);
        }

        if (stat(g_monitorLockfile, &stat_buf) != 0) {
            write_runlog(LOG, "The monitor lock file doesn't exist, process exit.\n");
            return 1;
        }

        /* check cluster_manual_start file. */
        if (stat(g_cmManualStartPath, &stat_buf) == 0) {
            /* if the cluster_manual_start exists. */
            g_isStart = true;
        }

        status = check_process_status(PROCKIND_CMAGENT, g_myProcPid);
        if (status == PROCESS_NOT_EXIST) {
            write_runlog(DEBUG5, "child process(%d) cm_agent have exit\n ", g_cmAgentPid);
            if (access(g_cmManualStartPath, 0) != 0) {
                ++startCMACount;
            }

            /* If start cm_agent more than 3 times, then report the cm_agent process abnormal alarm. */
            if (startCMACount >= startRetryTimes) {
                /* Report the alarm. */
                if (g_startupAlarmList != NULL) {
                    /* Fill the alarm message. */
                    WriteAlarmAdditionalInfo(&tempAdditionalParam,
                        "cma",
                        "",
                        "",
                        "",
                        &(g_startupAlarmList[g_startupAlarmListSize - 1]),
                        ALM_AT_Fault);
                    /* Report the alarm. */
                    AlarmReporter(
                        &(g_startupAlarmList[g_startupAlarmListSize - 1]), ALM_AT_Fault, &tempAdditionalParam);
                }
            }

            if (check_start_request()) {
                g_cmAgentPid = start_cm_agent();
                write_runlog(LOG, "cm_agent start, pid is %d\n ", g_cmAgentPid);

                if (create_lock_file(agentPidFile, g_agentConfigPath, g_cmAgentPid) != 0) {
                    write_runlog(WARNING, "failed to create the cm agent pid file.\n");
                }

                if (startCMACount % 20 == 0) {
                    status = get_prog_path();
                    if (status < 0) {
                        (void)fprintf(stderr, "FATAL get_prog_path failed!\n");
                        exit(status);
                    } else {
                        write_runlog(LOG, "Reload env, agent path is %s.\n", g_cmAgentBinPath);
                    }
                }
                if (startCMACount == 100) {
                    write_runlog(LOG, "Monitor has started agent for 5 minutes, agent path is %s.\n", g_cmAgentBinPath);
                    char execPath[MAX_PATH_LEN] = {0};
                    int rcs = GetHomePath(execPath, sizeof(execPath));
                    if (rcs != EOK) {
                        (void)fprintf(stderr, "FATAL The environment variable 'GAUSSHOME' was not specified.\n");
                        exit(-1);
                    }
                    write_runlog(LOG, "env is %s.\n", execPath);
                }
#ifdef ENABLE_LLT
                HLLT_Coverage_SaveCoverageData();
#endif
            }
        } else if (status == PROCESS_RUNNING) {
            /* If the cm_agent process is running, then report the cm_agent process abnormal resume. */
            startCMACount = 0;
            if (g_startupAlarmList != NULL) {
                /* fill the alarm message */
                WriteAlarmAdditionalInfo(&tempAdditionalParam,
                    "cma",
                    "",
                    "",
                    "",
                    &(g_startupAlarmList[g_startupAlarmListSize - 1]),
                    ALM_AT_Resume);
                /* report the alarm */
                AlarmReporter(&(g_startupAlarmList[g_startupAlarmListSize - 1]), ALM_AT_Resume, &tempAdditionalParam);
            }
        }

        /* check etcd process */
        check_ETCD_process_status(&tempAdditionalParam, pw->pw_name);

        switch_ETCD_logfile();
#ifndef ENABLE_MULTIPLE_NODES
        if (stat(g_libnetManualStartFile, &stat_buf) == 0 && g_currentNode->datanodeCount > 0) {
            CheckLtranProcessStatus();
        }
#endif
        if (stat(g_cmManualStartPath, &stat_buf) != 0) {
            /* if the cluster_manual_start file does not exist */
            g_isStart = false;
        }
        clean_system_alarm_log(system_alarm_log, sys_log_path);

        /* Sleep for MONITOR_CHECK_INTERVAL seconds for next loop */
        cm_sleep(MONITOR_CHECK_INTERVAL);
    }
}

/*
 * etcd 3.3.23 support "--log-output", but It has been changed to "--log-outputs" in etcd 3.5.0.
 * monitor must all support etcd 3.3.23 and etcd 3.5.0 command when upgrade cluster.
 */
int GetEtcdLogOutputCmd(char *logOutPutCmd, uint32 len)
{
    char command[MAXPGPATH * 2] = {0};
    int rcs;
    int ret;
    rcs = snprintf_s(
        command, sizeof(command), sizeof(command) - 1, "%s --help | grep \"\\-\\-log-outputs\"", g_etcdBinPath);
    securec_check_intval(rcs, (void)rcs);
    ret = system(command);
    if (ret == 0) {
        write_runlog(LOG, "run check etcd log-outputs command: %s success\n", command);
        rcs = strcpy_s(logOutPutCmd, len, "--log-outputs");
        securec_check_intval(rcs, (void)rcs);
        return 0;
    }
    write_runlog(LOG, "run check etcd log-outputs command %s failed,try to check log-output command!\n", command);
    rcs = snprintf_s(
        command, sizeof(command), sizeof(command) - 1, "%s --help | grep \"\\-\\-log-output\"", g_etcdBinPath);
    securec_check_intval(rcs, (void)rcs);
    ret = system(command);
    if (ret == 0) {
        write_runlog(LOG, "run check etcd log-output command: %s success\n", command);
        rcs = strcpy_s(logOutPutCmd, len, "--log-output");
        securec_check_intval(rcs, (void)rcs);
        return 0;
    }
    write_runlog(WARNING, "run check etcd log-output command %s failed %d!\n", command, ret);
    return -1;
}
void CheckStartEtcdCount(AlarmAdditionalParam *additionalParam)
{
    int status = 0;
    int rcs;
    if (g_startEtcdCount >= 3) {
        if (g_startupAlarmList != NULL) {
            WriteAlarmAdditionalInfo(additionalParam, "etcd", "", "", "", &(g_startupAlarmList[0]), ALM_AT_Fault);
            AlarmReporter(&(g_startupAlarmList[0]), ALM_AT_Fault, additionalParam);
        }
    }
    if (g_startEtcdCount % 20 == 0) {
        status = get_prog_path();
        if (status < 0) {
            (void)fprintf(stderr, "FATAL get_prog_path failed!\n");
            exit(status);
        } else {
            write_runlog(LOG, "Reload env, ETCD path is %s.\n", g_etcdBinPath);
        }
    }
    if (g_startEtcdCount == 100) {
        write_runlog(LOG, "Monitor has started ETCD for 5 minutes, ETCD path is %s.\n", g_etcdBinPath);
        char execPath[MAX_PATH_LEN] = {0};
        rcs = GetHomePath(execPath, sizeof(execPath));
        if (rcs != EOK) {
            (void)fprintf(stderr, "FATAL The environment variable 'GAUSSHOME' was not specified.\n");
            exit(-1);
        }
        write_runlog(LOG, "env is %s.\n", execPath);
    }
}
static void check_ETCD_process_status(AlarmAdditionalParam *additionalParam, const char *userName)
{
    int status = 0;

    if (g_currentNode->etcd) {
        char command[MAXPGPATH * 2] = {0};
        int rcs;
        int ret;
        /*
         * Remember how many times we have killed etcd. Once MONITOR_CHECK_INTERVAL*90
         * seconds have passed, try to kill etcd forcely while it is still alive.
         */
        static int haveKillEtcdCount = 0;
        static const int forceKillEtcd = 90;

        if (access(g_etcdManualStartPath, 0) != 0) {
            status = check_process_status(PROCKIND_ETCD, 0);
            if (status == PROCESS_NOT_EXIST) {
                uint32 currNodeIndex = 0;
                ret = find_node_index_by_nodeid(g_nodeHeader.node, &currNodeIndex);
                if (ret != 0) {
                    write_runlog(ERROR, "check ETCD process get node index failed!\n");
                    return;
                }
                char logOutPutCmd[MAXPGPATH] = {0};
                if (GetEtcdLogOutputCmd(logOutPutCmd, MAXPGPATH) != 0) {
                    write_runlog(
                        ERROR, "get etcd log-output command failed, please check etcd bin file %s!\n", g_etcdBinPath);
                    ++g_startEtcdCount;
                    CheckStartEtcdCount(additionalParam);
                    return;
                }
                char clientUrls[CM_IP_LENGTH * CM_IP_NUM] = {0};
                for (uint32 ipnum = 0; ipnum < CM_IP_NUM; ipnum++) {
                    if (strlen(g_node[currNodeIndex].etcdClientListenIPs[ipnum]) == 0) {
                        break;
                    }

                    char single_url[CM_IP_LENGTH] = {0};
                    rcs = snprintf_s(single_url, CM_IP_LENGTH, CM_IP_LENGTH - 1,
                        SYSTEMQUOTE "https://%s:%u" SYSTEMQUOTE,
                        g_node[currNodeIndex].etcdClientListenIPs[ipnum], g_node[currNodeIndex].etcdClientListenPort);
                    securec_check_intval(rcs, (void)rcs);

                    if ((ipnum + 1) < g_node[currNodeIndex].etcdClientListenIPCount) {
                        rcs = strncat_s(single_url, CM_IP_LENGTH, ",", strlen(","));
                        securec_check_errno(rcs, (void)rcs);
                    }

                    rcs = strncat_s(clientUrls, CM_IP_LENGTH * CM_IP_NUM, single_url, strlen(single_url));
                    securec_check_errno(rcs, (void)rcs);
                }

                rcs = snprintf_s(command,
                    2 * MAXPGPATH,
                    (2 * MAXPGPATH) - 1,
                    SYSTEMQUOTE "umask=`umask`;umask 0077;%s  -name %s --data-dir %s "
                    "--client-cert-auth --trusted-ca-file %s --cert-file %s/etcd.crt --key-file %s/etcd.key  "
                    "--peer-client-cert-auth --peer-trusted-ca-file %s --peer-cert-file %s/etcd.crt --peer-key-file "
                    "%s/etcd.key "
                    "-initial-advertise-peer-urls https://%s:%u  -listen-peer-urls https://%s:%u  "
                    "-listen-client-urls %s  -advertise-client-urls %s --election-timeout 5000 "
                    "--heartbeat-interval 1000 %s 'stdout' --quota-backend-bytes $((8*1024*1024*1024)) "
                    "--auto-compaction-mode 'periodic' --auto-compaction-retention '1h' "
                    "-initial-cluster-token etcd-cluster-%s --enable-v2=false -initial-cluster " SYSTEMQUOTE,
                    g_etcdBinPath,
                    g_node[currNodeIndex].etcdName,
                    g_node[currNodeIndex].etcdDataPath,
                    g_tlsPath.etcd_ca_path,
                    g_node[currNodeIndex].etcdDataPath,
                    g_node[currNodeIndex].etcdDataPath,
                    g_tlsPath.etcd_ca_path,
                    g_node[currNodeIndex].etcdDataPath,
                    g_node[currNodeIndex].etcdDataPath,
                    g_node[currNodeIndex].etcdHAListenIPs[0],
                    g_node[currNodeIndex].etcdHAListenPort,
                    g_node[currNodeIndex].etcdHAListenIPs[0],
                    g_node[currNodeIndex].etcdHAListenPort,
                    clientUrls,
                    clientUrls,
                    logOutPutCmd,
                    userName);
                securec_check_intval(rcs, (void)rcs);

                uint32 j = 0;
                for (uint32 i = 0; i < g_node_num; i++) {
                    if (g_node[i].etcd) {
                        char port[MAX_PORT_LEN];
                        if (j++ > 0) {
                            rcs = strncat_s(command, 2 * MAXPGPATH, ",", strlen(","));
                            securec_check_errno(rcs, (void)rcs);
                        }
                        rcs = strncat_s(command, 2 * MAXPGPATH, g_node[i].etcdName, strlen(g_node[i].etcdName));
                        securec_check_errno(rcs, (void)rcs);
                        rcs = strncat_s(command, 2 * MAXPGPATH, "=https://", strlen("=https://"));
                        securec_check_errno(rcs, (void)rcs);
                        rcs = strncat_s(
                            command, 2 * MAXPGPATH, g_node[i].etcdHAListenIPs[0], strlen(g_node[i].etcdHAListenIPs[0]));
                        securec_check_errno(rcs, (void)rcs);
                        rcs = strncat_s(command, 2 * MAXPGPATH, ":", strlen(":"));
                        securec_check_errno(rcs, (void)rcs);
                        rcs = snprintf_s(port, MAX_PORT_LEN, MAX_PORT_LEN - 1, "%u", g_node[i].etcdHAListenPort);
                        securec_check_intval(rcs, (void)rcs);
                        rcs = strncat_s(command, 2 * MAXPGPATH, port, strlen(port));
                        securec_check_errno(rcs, (void)rcs);
                    }
                }
                /*
                 * the replaced ETCD node must be started with flag "-initial-cluster-state existing" so that
                 * new node can sync data from other members.
                 */
                if (access(g_etcdReplacedPath, 0) != 0) {
                    rcs = strncat_s(command,
                        2 * MAXPGPATH,
                        " -initial-cluster-state new >> \"",
                        strlen(" -initial-cluster-state new >> \""));
                    securec_check_errno(rcs, (void)rcs);
                } else {
                    rcs = strncat_s(command,
                        2 * MAXPGPATH,
                        " -initial-cluster-state existing >> \"",
                        strlen(" -initial-cluster-state existing >> \""));

                    securec_check_errno(rcs, (void)rcs);

                    ret = unlink(g_etcdReplacedPath);
                    if (ret != 0) {
                        write_runlog(ERROR, "could not remove etcd_replaced file: %d.\n", errno);
                    }
                }
                rcs = strncat_s(command, 2 * MAXPGPATH, g_curEtcdLogFile, strlen(g_curEtcdLogFile));
                securec_check_errno(rcs, (void)rcs);
                rcs = strncat_s(command, 2 * MAXPGPATH, "\" 2>&1 & umask $umask", strlen("\" 2>&1 & umask $umask"));
                securec_check_errno(rcs, (void)rcs);
                ret = system(command);
                write_runlog(LOG, "run etcd command: %s \n", command);
                if (ret != 0) {
                    write_runlog(ERROR, "run system command failed %d! %s, errno=%d.\n", ret, command, errno);
                }

                /* reset cgroup attach and kill counter at resetart */
                g_isAttachToCgroup = false;
                haveKillEtcdCount = 0;

                /* if start etcd more than 3 times, then report the etcd process abnormal alarm. */
                ++g_startEtcdCount;
                CheckStartEtcdCount(additionalParam);
            } else if (status == PROCESS_RUNNING) {
                /* if the etcd process is running, then report the etcd process abnormal resume. */
                g_startEtcdCount = 0;
                if (g_startupAlarmList != NULL) {
                    /* fill the alarm message. */
                    WriteAlarmAdditionalInfo(additionalParam, "etcd", "", "", "", &(g_startupAlarmList[0]),
                        ALM_AT_Resume);
                    /* report the alarm. */
                    AlarmReporter(&(g_startupAlarmList[0]), ALM_AT_Resume, additionalParam);
                }

#ifdef ENABLE_MULTIPLE_NODES
                /* g_noCgroupFlag is temporarily used for debug, delete it when commit to main branch */
                struct stat stat_buf1 = {0};
                int retStat = stat(g_noCgroupFlag, &stat_buf1);
                if (!g_isAttachToCgroup && retStat != 0) {
                    char buf[64] = {0};
                    int etcd_pid = 0;

                    rcs = snprintf_s(command,
                        2 * MAXPGPATH,
                        2 * MAXPGPATH - 1,
                        "status=`ps x|grep '%s' |grep -v 'grep' | awk '{print $1}'`;echo \"$status\"",
                        g_etcdBinPath);
                    securec_check_intval(rcs, (void)rcs);

                    write_runlog(LOG, "get etcd processid.  command=%s.\n", command);

                    FILE *fp = popen(command, "r");
                    if (fp == NULL) {
                        write_runlog(ERROR, "get etcd processid failed. command=%s.\n", command);
                        return;
                    } else {
                        if (fgets(buf, sizeof(buf), fp) != NULL) {
                            write_runlog(LOG, "etcd processid is %s.\n", buf);
                            etcd_pid = (int)strtol(buf, NULL, 10);
                            /* initialize cm cgroup and attach it if the relative path is not NULL. */
                            char *cmcgroup_relpath = gscgroup_cm_init();
                            if (cmcgroup_relpath != NULL) {
                                gscgroup_cm_attach_task_pid(cmcgroup_relpath, etcd_pid);
                                free(cmcgroup_relpath);
                            }
                            g_isAttachToCgroup = true;
                        }
                        (void)pclose(fp);
                    }
                }
#endif
            }
        } else {
            if (check_process_status(PROCKIND_ETCD, 0) == PROCESS_RUNNING) {
                if (access(g_etcdReplacedPath, 0) == 0) {
                    g_replaceEtcdCount++;
                } else {
                    g_replaceEtcdCount = 0;
                }
                haveKillEtcdCount++;
                if (g_replaceEtcdCount > TRY_COUNT_FOR_KILL_ETCD_REPLACE || g_replaceEtcdCount == 0) {
                    g_replaceEtcdCount = 0;
                    rcs = snprintf_s(command,
                        2 * MAXPGPATH,
                        2 * MAXPGPATH - 1,
                        SYSTEMQUOTE "killall %s etcd" SYSTEMQUOTE,
                        (haveKillEtcdCount >= forceKillEtcd) ? "-s 9" : "");
                    securec_check_intval(rcs, (void)rcs);

                    struct stat statBuf = {0};
                    if (stat(g_curLogFileName, &statBuf) == 0) {
                        rcs = strncat_s(command, 2 * MAXPGPATH, " >> ", strlen(" >> "));
                        securec_check_errno(rcs, (void)rcs);
                        rcs = strncat_s(command, 2 * MAXPGPATH, g_curLogFileName, strlen(g_curLogFileName));
                        securec_check_errno(rcs, (void)rcs);
                        rcs = strncat_s(command, 2 * MAXPGPATH, " 2>&1", strlen(" 2>&1"));
                        securec_check_errno(rcs, (void)rcs);
                    }

                    write_runlog(LOG, "kill etcd! command=%s \n", command);
                    ret = system(command);
                    if (ret != 0) {
                        write_runlog(ERROR, "run system command failed %d! %s, errno=%d.\n", ret, command, errno);
                    }
                }
            }
        }
    }
}

/*
 * @Description: get all cgroup sub system's mount points.
 * @IN void
 * @Return:  0: normal -1: abnormal
 * @See also:
 */
#define MOUNT_SUBSYS_KINDS (2)
#define MOUNT_CPU_NAME "cpu"
#define MOUNT_CPUSET_NAME "cpuset"

#define GSCGROUP_TOP_DATABASE "Gaussdb"
#define GSCGROUP_TOP_CLASS "Class"

static char g_mpoints[MOUNT_SUBSYS_KINDS][MAXPGPATH]; /* subsys mount points */

int OmGetMountPoints(void)
{
    struct mntent *ent;
    char mntentBuffer[2 * FILENAME_MAX];

    struct mntent tempEnt;
    int i;
    const char *subsysTable[] = {MOUNT_CPU_NAME, MOUNT_CPUSET_NAME};

    errno_t rc;

    /* reset mount points */
    rc = memset_s(g_mpoints, MOUNT_SUBSYS_KINDS * MAXPGPATH, 0, MOUNT_SUBSYS_KINDS * MAXPGPATH);
    securec_check_errno(rc, (void)rc);

    /* open '/proc/mounts' to load mount points */
    FILE *procMount = fopen("/proc/mounts", "re");

    if (procMount == NULL) {
        return -1;
    }

    while ((ent = getmntent_r(procMount, &tempEnt, mntentBuffer, sizeof(mntentBuffer))) != NULL) {
        /* not cgroup, pass */
        if (strcmp(ent->mnt_type, "cgroup") != 0) {
            continue;
        }

        for (i = 0; i < MOUNT_SUBSYS_KINDS; ++i) {
            if (hasmntopt(ent, subsysTable[i]) == NULL) {
                continue;
            }

            /* get mount point */
            rc = snprintf_s(g_mpoints[i], MAXPGPATH, MAXPGPATH - 1, "%s", ent->mnt_dir);
            securec_check_intval(rc, (void)fclose(procMount));
        }
    }

    (void)fclose(procMount);

    return 0;
}

/* Check if Cgroup has been mounted correctly */
void CheckCgroupInstallation(void)
{
    /* Get the cgroup mount points */
    int ret = 0;

    /* variable to indicate the user of Cgroup configuration file */
    errno_t rc;

    /* save current user info */
    struct passwd *passwdUser = getpwuid(geteuid());
    if (passwdUser == NULL) {
        write_runlog(ERROR,
            "can't get the passwdUser. "
            "HINT: please check the running user!\n");
        return;
    }

    /* reset mount points */
    rc = memset_s(g_mpoints, MOUNT_SUBSYS_KINDS * MAXPGPATH, 0, MOUNT_SUBSYS_KINDS * MAXPGPATH);
    securec_check_errno(rc, (void)rc);

    /* if the mount point doesn't exist, retrieve them */
    if (*g_mpoints[0] == '\0' || *g_mpoints[1] == '\0') {
        ret = OmGetMountPoints();
        if (ret == -1 || *g_mpoints[0] == '\0' || *g_mpoints[1] == '\0') {
            write_runlog(ERROR,
                "can't get the mount points\n"
                "Please check if cgroup has been mounted and user's cgroup data has been created!\n");
            return;
        }
    }

    if (*g_mpoints[0] && *g_mpoints[1]) {
        struct stat buf = {0};
        char cgpath[MAXPGPATH];

        ret = 0;

        for (int i = 0; i < MOUNT_SUBSYS_KINDS && ret == 0; ++i) {
            /* begin to check if Gaussdb:user has been created */
            rc = snprintf_s(
                cgpath, MAXPGPATH, MAXPGPATH - 1, "%s/%s:%s", g_mpoints[i], GSCGROUP_TOP_DATABASE, passwdUser->pw_name);
            securec_check_intval(rc, (void)rc);

            ret = stat(cgpath, &buf);
            if (ret == 0) {
                /* begin to check if Gaussdb:user/Class has been created */
                rc = snprintf_s(cgpath,
                    MAXPGPATH,
                    MAXPGPATH - 1,
                    "%s/%s:%s/%s",
                    g_mpoints[i],
                    GSCGROUP_TOP_DATABASE,
                    passwdUser->pw_name,
                    GSCGROUP_TOP_CLASS);
                securec_check_intval(rc, (void)rc);

                ret = stat(cgpath, &buf);
                if (ret != 0) {
                    write_runlog(ERROR,
                        "can't get the %s,\n"
                        "Please check if cgroup has been mounted and user's cgroup data has been created!\n",
                        cgpath);
                }
            } else {
                write_runlog(ERROR,
                    "can't get the %s,\n"
                    "Please check if cgroup has been mounted and user's cgroup data has been created!\n",
                    cgpath);
            }
        }
    }
}

static void DoAdvice(void)
{
    (void)fprintf(stderr, "Try \"%s --help\" for more information.\n", g_progname);
}

static void DoHelp(void)
{
    (void)printf(_("%s is a utility to start an agent or a WMP.\n\n"), g_progname);

    (void)printf(_("Usage:\n"));
    (void)printf(_("  %s 0  -L FILENAME\n"), g_progname);
    (void)printf(_("  %s 1\n"), g_progname);
    (void)printf(_("  %s 2  -L FILENAME\n"), g_progname);
    (void)printf(_("  %s 3\n"), g_progname);
    (void)printf(_("  %s -L FILENAME\n"), g_progname);

    (void)printf(_("\nCommon options:\n"));
    (void)printf(_("  -?, --help             show this help, then exit\n"));
    (void)printf(_("  -V, --version          output version information, then exit\n"));
}

void InitLogFiles()
{
    int rcs = 0;

    errno_t rc = memset_s(g_curLogFileName, MAXPGPATH, 0, MAXPGPATH);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(sys_log_path, MAXPGPATH, 0, MAXPGPATH);
    securec_check_errno(rc, (void)rc);
    canonicalize_path(g_alarmConfigPath);
    GetAlarmConfig(g_alarmConfigPath);
    /* user specify log path. */
    if (g_logFileSet) {
        (void)logfile_init();

        rcs = snprintf_s(
            g_curLogFileName, MAXPGPATH, MAXPGPATH - 1, "%s/%s%s.log", g_logFile, g_progname, curLogFileMark);
        securec_check_intval(rcs, (void)rcs);
        rc = strncpy_s(sys_log_path, MAX_PATH_LEN, g_logFile, strlen(g_logFile));
        securec_check_errno(rc, (void)rc);
    } else {
        char exec_path[MAX_PATH_LEN] = {0};
        rcs = GetHomePath(exec_path, sizeof(exec_path));
        if (rcs != EOK) {
            (void)fprintf(stderr, "FATAL Get GAUSSHOME failed, please check.\n");
            exit(-1);
        } else {
            rcs = snprintf_s(sys_log_path, sizeof(sys_log_path), MAX_PATH_LEN - 1, "%s/bin", exec_path);
            securec_check_intval(rcs, (void)rcs);

            rcs = snprintf_s(
                g_curLogFileName, MAXPGPATH, MAXPGPATH - 1, "%s/%s-%s.log", sys_log_path, g_progname, curLogFileMark);
            securec_check_intval(rcs, (void)rcs);
        }
    }
    check_input_for_security(g_curLogFileName);
    canonicalize_path(g_curLogFileName);

    (void)mkdir(sys_log_path, S_IRWXU);
    syslogFile = logfile_open(sys_log_path, "a");
    if (syslogFile == NULL) {
        (void)printf("monitor_main,open log file failed\n");
    }
}

static void CheckDirExist()
{
    char gausslog[MAXPGPATH] = {0};
    char cmlog[MAXPGPATH] = {0};
    char monitorlog[MAXPGPATH] = {0};
    char serverlog[MAXPGPATH] = {0};
    char agentlog[MAXPGPATH] = {0};
    int rcs = cmmonitor_getenv("GAUSSLOG", gausslog, sizeof(gausslog));
    if (rcs != EOK) {
        (void)fprintf(stderr, "FATAL The environment variable 'GAUSSLOG' was not specified.\n");
        exit(-1);
    }
    if (access(gausslog, F_OK) != 0) {
        write_runlog(ERROR, "FATAL access %s return error %d \n", gausslog, errno);
        exit(-1);
    }
    rcs = snprintf_s(cmlog, MAXPGPATH, MAXPGPATH - 1, "%s/cm", gausslog);
    securec_check_intval(rcs, (void)rcs);
    if (access(cmlog, F_OK) != 0) {
        rcs = mkdir(cmlog, S_IRWXU);
        if (rcs != 0) {
            write_runlog(ERROR, "FATAL mkdir %s return error %d \n", cmlog, errno);
            exit(-1);
        }
        rcs = snprintf_s(monitorlog, MAXPGPATH, MAXPGPATH - 1, "%s/om_monitor", cmlog);
        securec_check_intval(rcs, (void)rcs);
        rcs = mkdir(monitorlog, S_IRWXU);
        if (rcs != 0) {
            write_runlog(ERROR, "FATAL mkdir %s return error %d \n", monitorlog, errno);
            exit(-1);
        }
        rcs = snprintf_s(serverlog, MAXPGPATH, MAXPGPATH - 1, "%s/cm_server", cmlog);

        securec_check_intval(rcs, (void)rcs);
        rcs = mkdir(serverlog, S_IRWXU);
        if (rcs != 0) {
            write_runlog(ERROR, "FATAL mkdir %s return error %d \n", serverlog, errno);
            exit(-1);
        }
        rcs = snprintf_s(agentlog, MAXPGPATH, MAXPGPATH - 1, "%s/cm_agent", cmlog);
        securec_check_intval(rcs, (void)rcs);
        rcs = mkdir(agentlog, S_IRWXU);
        if (rcs != 0) {
            write_runlog(ERROR, "FATAL mkdir %s return error %d \n", agentlog, errno);
            exit(-1);
        }
    }
    return;
}

int main(int argc, char **argv)
{
#define LIMIT_OPEN_FILE 640000
    static struct option longOptions[] = {{"location", required_argument, NULL, 'L'}, {NULL, 0, NULL, 0}};
    int option_index;
    int c;
    int status;
    int err_no = 0;
    errno_t rc = 0;
    struct rlimit r = {0};

    g_myProcPid = getpid();
    g_myUid = getuid();
    g_progname = "om_monitor";
    /* unify log style. */
    prefix_name = g_progname;

    if (g_myUid == 0) {
        (void)printf("current user is the root user (uid = 0), exit.\n");
        return 1;
    }

    (void)syscalllockInit(&g_cmEnvLock);

    GetCmdlineOpt(argc, argv);

    if (argc > 1) {
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-?") == 0) {
            DoHelp();
            _exit(0);
        } else if (strcmp(argv[1], "-V") == 0 || strcmp(argv[1], "--version") == 0) {
            (void)puts("om_monitor " DEF_CM_VERSION);
            _exit(0);
        }
    }

    optind = 1;
    while (optind < argc) {
        while ((c = getopt_long(argc, argv, "L:", longOptions, &option_index)) != -1) {
            if (c == 'L') {
                g_logFileSet = true;
                FREE_AND_RESET(g_logFile);
                g_logFile = strdup(optarg);
                if (g_logFile == NULL) {
                    (void)fprintf(stderr, "%s: -L file is needed.\n", g_progname);
                    DoAdvice();
                    _exit(1);
                }
                check_input_for_security(g_logFile);
                break;
            } else {
                DoAdvice();
                _exit(1);
            }
        }
        optind++;
    }

    if (g_logFileSet && (log_destion_choice == LOG_DESTION_SYSLOG || log_destion_choice == LOG_DESTION_DEV_NULL)) {
        (void)fprintf(stderr, "%s: -L option is not needed.\n", g_progname);
        DoAdvice();
        _exit(1);
    }

    status = get_prog_path();
    if (status < 0) {
        (void)fprintf(stderr, "get_prog_path failed!\n");
        _exit(status);
    }

    InitLogFiles();
    bool isKillProcess = false;
    status = check_process_status(PROCKIND_MONITOR, 0, &isKillProcess);
    if (status == PROCESS_RUNNING) {
        write_runlog(DEBUG5, "monitor exit\n");
        _exit(0);
    }

    if (MonitorLock(isKillProcess) == -1) {
        write_runlog(DEBUG1, "Another om_monitor command is still running, start failed !\n");
        _exit(-1);
    }
    CheckDirExist();
    print_environ();

    /* Check max open files */
    if (getrlimit(RLIMIT_NOFILE, &r) == 0) {
        if (r.rlim_cur < LIMIT_OPEN_FILE) {
            write_runlog(FATAL,
                "max number of open files limit %lu less than %d, monitor start failed.\n",
                r.rlim_cur,
                LIMIT_OPEN_FILE);
            _exit(1);
        }
    } else {
        write_runlog(FATAL, "failed to getrlimit number of files\n");
        _exit(1);
    }

    /* init the sigset and register the signal handle */
    init_signal_mask();
    (void)sigprocmask(SIG_SETMASK, &block_sig, NULL);

    /* effect Contraction? */
    status = read_config_file(g_cmStaticConfigurePath, &err_no);
    char errBuffer[ERROR_LIMIT_LEN] = {0};
    switch (status) {
        case OPEN_FILE_ERROR: {
            write_runlog(FATAL,
                "%s: could not open the static config file \"%s\": %s\n",
                g_progname,
                g_cmStaticConfigurePath,
                strerror_r(err_no, errBuffer, ERROR_LIMIT_LEN));
            _exit(1);
        }
        case READ_FILE_ERROR: {
            write_runlog(FATAL,
                "%s: could not read static config file \"%s\": %s\n",
                g_progname,
                g_cmStaticConfigurePath,
                strerror_r(err_no, errBuffer, ERROR_LIMIT_LEN));
            _exit(1);
        }
        case OUT_OF_MEMORY:
            write_runlog(FATAL, "%s: out of memory\n", g_progname);
            _exit(1);
        default:
            break;
    }

    if (access(g_logicClusterListPath, F_OK) == 0) {
        status = read_logic_cluster_config_files(g_logicClusterListPath, &err_no);
        char errBuf[ERROR_LIMIT_LEN] = {0};
        switch (status) {
            case OPEN_FILE_ERROR: {
                write_runlog(FATAL,
                    "%s: could not open logic cluster static config files: %s\n",
                    g_progname,
                    strerror_r(err_no, errBuf, ERROR_LIMIT_LEN));
                _exit(1);
            }
            case READ_FILE_ERROR: {
                char errBuff[ERROR_LIMIT_LEN];
                write_runlog(FATAL,
                    "%s: could not read logic cluster static config files: %s\n",
                    g_progname,
                    strerror_r(err_no, errBuff, ERROR_LIMIT_LEN));
                _exit(1);
            }
            case OUT_OF_MEMORY:
                write_runlog(FATAL, "%s: out of memory\n", g_progname);
                _exit(1);
            default:
                break;
        }
    }

    max_logic_cluster_name_len = (max_logic_cluster_name_len < strlen("logiccluster_name"))
                                     ? (uint32)strlen("logiccluster_name")
                                     : max_logic_cluster_name_len;

    int ret = find_current_node_by_nodeid();
    if (ret != 0) {
        write_runlog(FATAL, "find_current_node_by_nodeid failed, nodeId=%u.\n", g_nodeHeader.node);
        _exit(1);
    }

    rc = memset_s(g_agentConfigPath, MAXPGPATH, 0, MAXPGPATH);
    securec_check_errno(rc, (void)rc);
    rc = snprintf_s(g_agentConfigPath, MAXPGPATH, MAXPGPATH - 1, "%s/%s", g_currentNode->cmDataPath, CM_AGENT_BIN_NAME);
    securec_check_intval(rc, (void)rc);
#ifdef ENABLE_MULTIPLE_NODES
    /* check Cgroup installation */
    CheckCgroupInstallation();
#endif
    AlarmEnvInitialize();
    StartupAlarmItemInitialize(g_currentNode);

#ifdef ENABLE_MULTIPLE_NODES
    /* g_noCgroupFlag is temporarily used for debug, delete it when commit to main branch */
    struct stat stat_buf = {0};
    int retStat = stat(g_noCgroupFlag, &stat_buf);
    if (retStat != 0) {
        write_runlog(LOG, "om_monitor gscgroup_cm_attach_task.\n");
        /* initialize cm cgroup and attach it if the relative path is not NULL. */
        char *cmcgroup_relpath = gscgroup_cm_init();
        if (cmcgroup_relpath != NULL) {
            gscgroup_cm_attach_task(cmcgroup_relpath);
            free(cmcgroup_relpath);
        }
    }
#endif

    create_system_alarm_log(sys_log_path);
    /* get separate path for etcd */
    if (g_currentNode->etcd) {
        CreateEtcdLogPath();
        CreateEtcdLog();
    }
    status = server_loop();
    (void)MonitorUnlock();

    _exit(status);
}

/**
 * @brief
 *  Check whether the CM Agent meets the startup conditions.
 *
 *  1. Normal Scenario:
 *      The cluster manual start file does not exist.
 *      The CM Agent config file can be read by current user.
 *      The binary file can be execute by current user.
 *      The config change file "cluster_dilatation_status" does not exist.
 *
 *  1. Abnormal Exit Scenario:
 *      The cluster manual start file exists.
 *      The CM Agent config file can be read by current user.
 *      The binary file can be execute by current user.
 *      The config change file "cluster_dilatation_status" does not exist.
 *      The CM Agent instance exits abnormally at last time.
 *
 * @return
 *  Return whether the CM Agent meets the startup conditions.
 */
static bool check_start_request()
{
    bool startRequest = false;
    static int agentRestartCount = 0;
    char agentConfigFile[MAXPGPATH] = {0};
    int retryTimes = 3;

    int rc = snprintf_s(agentConfigFile, MAXPGPATH, MAXPGPATH - 1, "%s/%s", g_agentConfigPath, CM_AGENT_CONFIG);
    securec_check_intval(rc, (void)rc);

    /* If the cluster manual start file exist, the CM Agent will not be started. */
    const bool disableManualStart = (access(g_cmManualStartPath, F_OK) == 0);
    /* If the config file can not be read, the CM Agent will not be started. */
    const bool isConfigExist = (access(agentConfigFile, R_OK) == 0);
    /* If the binary file can not be execute, the CM Agent will not be started. */
    const bool isBinaryExist = (access(g_cmAgentBinPath, X_OK) == 0);
    /* If the config change file exist, the CM Agent will not be started. */
    const bool isConfigChange = (access(g_cmStaticConfigChangeFlagFilePath, F_OK) == 0);
    /* Normal Scenario. */
    if (!disableManualStart && isBinaryExist && isConfigExist && !isConfigChange) {
        startRequest = true;
        agentRestartCount = 0;
    }
    /**
     * Need to restart the CM Agent even if the cluster manual start file exists.
     */
    if (disableManualStart && isBinaryExist && isConfigExist && !isConfigChange && g_previousStatus != 0 &&
        agentRestartCount < retryTimes) {
        write_runlog(LOG,
            "The CM Agent did not exit correctly last time. Restart the CM Agent"
            " to complete the unfinished stop operation: start_times=%d.\n",
            g_agentFaultCount);
        startRequest = true;
        agentRestartCount++;
    }

    write_runlog(LOG,
        "The CM Agent startup check is complete: cluster_manual_start=%d,"
        " agent_config_file_r=%d, agent_binary_file_x=%d, config_change_flag=%d, previous_status=%d,"
        " start_count=%d.\n",
        disableManualStart,
        isConfigExist,
        isBinaryExist,
        isConfigChange,
        g_previousStatus,
        g_agentFaultCount);

    return startRequest;
}

static int MonitorLock(bool isKillProcess)
{
    struct stat statbuf = {0};

    /* If gtm_ctl.lock dose not exist,create it */
    if (stat(g_monitorLockfile, &statbuf) != 0) {
        char content[MAX_PATH_LEN] = {0};
        g_lockfile = fopen(g_monitorLockfile, PG_BINARY_W);
        if (g_lockfile == NULL) {
            write_runlog(
                DEBUG1, "%s: can't open lock file \"%s\" : %s\n", g_progname, g_monitorLockfile, strerror(errno));
            exit(1);
        } else {
            if (fwrite(content, MAX_PATH_LEN, 1, g_lockfile) != 1) {
                (void)fclose(g_lockfile);
                g_lockfile = NULL;
                write_runlog(
                    DEBUG1, "%s: can't write lock file \"%s\" : %s\n", g_progname, g_monitorLockfile, strerror(errno));
                exit(1);
            }
            (void)fclose(g_lockfile);
            (void)chmod(g_monitorLockfile, 0600);
            g_lockfile = NULL;
        }
    }
    if ((g_lockfile = fopen(g_monitorLockfile, PG_BINARY_W)) == NULL) {
        write_runlog(
            DEBUG1, "%s: could not open lock file \"%s\" : %s\n", g_progname, g_monitorLockfile, strerror(errno));
        exit(1);
    }

    if (SetFdCloseExecFlag(g_lockfile) < 0) {
        write_runlog(DEBUG1, "%s: can't set file flag\"%s\" : %s\n", g_progname, g_monitorLockfile, strerror(errno));
    }

    // in order to avoid restarting monitor as soon as prossible
    const int32 tryTotalTime = 10;
    int32 tryTime = tryTotalTime;
    int32 ret;
    do {
        ret = flock(fileno(g_lockfile), LOCK_EX | LOCK_NB);
        if (ret == 0 || !isKillProcess) {
            break;
        }
        --tryTime;
        cm_sleep(1);
    } while (tryTime > 0);

    return ret;
}

static int MonitorUnlock(void)
{
    int ret = flock(fileno(g_lockfile), LOCK_UN);
    if (g_lockfile != NULL) {
        (void)fclose(g_lockfile);
        g_lockfile = NULL;
    }
    return ret;
}
