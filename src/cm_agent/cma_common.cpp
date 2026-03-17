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
 * cma_common.cpp
 *    cma common functions
 *
 * IDENTIFICATION
 *    src/cm_agent/cma_common.cpp
 *
 * -------------------------------------------------------------------------
 */
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <string>
#include <algorithm>
#include "cm/cm_c.h"
#include "cm/cm_elog.h"
#include "cm/pqsignal.h"
#include "cm/libpq-fe.h"
#include "cm/libpq-int.h"
#include "cma_global_params.h"
#include "cma_connect.h"
#include "cma_network_check.h"
#include "cma_instance_management.h"
#include "cma_instance_management_res.h"
#include "cma_common.h"

void save_thread_id(pthread_t thrId)
{
    int length = (int)(sizeof(g_threadId) / sizeof(g_threadId[0]));
    int32 i;
    for (i = 0; i < length; i++) {
        if (g_threadId[i] == 0) {
            g_threadId[i] = thrId;
            break;
        }
    }
    if (i == length) {
        write_runlog(WARNING, "the num(%d) of array for thread state is not enough.\n", length);
    }
}

void set_thread_state(pthread_t thrId)
{
    if (thrId == 0) {
        return;
    }
    int length = (int)(sizeof(g_threadId) / sizeof(g_threadId[0]));
    for (int32 i = 0; i < length; i++) {
        if (g_threadId[i] == thrId) {
            struct timespec now = {0};
            (void)clock_gettime(CLOCK_MONOTONIC, &now);
            g_thread_state[i] = now.tv_sec;
            g_threadName[i] = thread_name;
            break;
        }
    }
}
int cmagent_getenv(const char *env_var, char *output_env_value, uint32 env_value_len)
{
    return cm_getenv(env_var, output_env_value, env_value_len);
}

const char *type_int_to_str_name(InstanceTypes ins_type)
{
    switch (ins_type) {
        case INSTANCE_CN:
            return "coordinator";
        case INSTANCE_DN:
            return "datanode";
        case INSTANCE_GTM:
            return "gtm";
        case INSTANCE_CM:
            return "cm_server";
        case INSTANCE_FENCED:
            return "fenced";
        case INSTANCE_KERBEROS:
            return "krb5kdc";
        default:
            return "unknown";
    }
}

const char *GetDnProcessName(void)
{
    return g_clusterType == V3SingleInstCluster ? ZENGINE_BIN_NAME : DATANODE_BIN_NAME;
}

const char *type_int_to_str_binname(InstanceTypes ins_type)
{
    switch (ins_type) {
        case INSTANCE_CN:
        case INSTANCE_FENCED:
            return COORDINATE_BIN_NAME;
        case INSTANCE_DN:
            return GetDnProcessName();
        case INSTANCE_GTM:
            return GTM_BIN_NAME;
        case INSTANCE_CM:
            return CM_SERVER_BIN_NAME;
        case INSTANCE_KERBEROS:
            return KERBEROS_BIN_NAME;
        default:
            return "unknown";
    }
}

static void SigAlarmHandler(int arg)
{
    ;
}
static int GetChildCmdResult(int status)
{
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    } else if (WIFSIGNALED(status) && WTERMSIG(status)) {
        return CM_EXECUTE_CMD_TIME_OUT;
    } else {
        return -1;
    }
}

int ExecuteCmd(const char *command, struct timeval timeout)
{
#ifndef WIN32
    pid_t pid;
    pid_t child = 0;
    struct sigaction ign = {};
    struct sigaction intact = {};
    struct sigaction quitact = {};
    sigset_t newsigblock, oldsigblock;
    struct itimerval write_timeout;
    errno_t rc;
    int childStatus = 0;

    rc = memset_s(&ign, sizeof(struct sigaction), 0, sizeof(struct sigaction));
    securec_check_errno(rc, (void)rc);
    if (command == NULL) {
        write_runlog(ERROR, "ExecuteCmd invalid command.\n");
        return 1;
    }
    /*
     * Ignore SIGINT and SIGQUIT, block SIGCHLD. Remember to save existing
     * signal dispositions.
     */
    ign.sa_handler = SIG_IGN;
    (void)sigemptyset(&ign.sa_mask);
    ign.sa_flags = 0;
    (void)sigaction(SIGINT, &ign, &intact);
    (void)sigaction(SIGQUIT, &ign, &quitact);
    (void)sigemptyset(&newsigblock);
    (void)sigaddset(&newsigblock, SIGCHLD);
    (void)sigprocmask(SIG_BLOCK, &newsigblock, &oldsigblock);
    switch (pid = fork()) {
        case -1: /* error */
            break;
        case 0: /* child */
            write_timeout.it_value.tv_sec = timeout.tv_sec;
            write_timeout.it_value.tv_usec = timeout.tv_usec;
            write_timeout.it_interval.tv_sec = 0;
            write_timeout.it_interval.tv_usec = 0;
            (void)setitimer(ITIMER_REAL, &write_timeout, NULL);
            (void)signal(SIGALRM, SigAlarmHandler);
            /*
             * Restore original signal dispositions and exec the command.
             */
            (void)sigaction(SIGINT, &intact, NULL);
            (void)sigaction(SIGQUIT, &quitact, NULL);
            (void)sigprocmask(SIG_SETMASK, &oldsigblock, NULL);
            (void)execl("/bin/sh", "sh", "-c", command, (char *)0);
            (void)signal(SIGALRM, SIG_IGN);
            _exit(127);
        default:
            child = pid;
            /* wait the child process end ,if timeout then kill the child process force */
            write_runlog(DEBUG1, "ExecuteCmd: %s, pid:%d. start!\n", command, pid);
            if (pid != waitpid(pid, &childStatus, 0)) {
                /* kill child process */
                (void)kill(child, SIGKILL);
                pid = -1;
                /* avoid the zombie process */
                (void)wait(NULL);
                write_runlog(ERROR, "ExecuteCmd: %s, child:%d will reset. end!\n", command, child);
            }
            write_runlog(DEBUG1, "ExecuteCmd: %s, pid:%d, childStatus %d end!\n", command, pid, childStatus);
            (void)signal(SIGALRM, SIG_IGN);
            break;
    }
    (void)sigaction(SIGINT, &intact, NULL);
    (void)sigaction(SIGQUIT, &quitact, NULL);
    (void)sigprocmask(SIG_SETMASK, &oldsigblock, NULL);
    if (pid == -1) {
        write_runlog(ERROR, "ExecuteCmd: %s, failed errno:%d.\n", command, errno);
    }

    return ((pid == -1) ? -1 : GetChildCmdResult(childStatus));
#else
    return -1;
#endif
}

/*
 * Read parameter from cm_agent.conf by accurate parameter name.
 */
int get_config_param(const char *config_file, const char *srcParam, char *destParam, int destLen)
{
    char buf[MAXPGPATH] = {'\0'};
    char *subStr = NULL;
    char *saveptr1 = NULL;
    errno_t rc;

    if (config_file == NULL || srcParam == NULL || destParam == NULL) {
        write_runlog(
            ERROR, "Get parameter failed,confDir=%s,srcParam = %s, destParam=%s.\n", config_file, srcParam, destParam);
        return -1;
    }

    FILE *fd = fopen(config_file, "re");
    if (fd == NULL) {
        write_runlog(FATAL, "Open configure file failed \n");
        exit(1);
    }
    while (!feof(fd)) {
        (void)fgets(buf, MAXPGPATH, fd);
        buf[MAXPGPATH - 1] = 0;
        /* skip # comment of agent configure file */
        if (is_comment_line(buf) == 1) {
            continue;
        }
        /* Process parameter one by one line */
        subStr = strstr(buf, srcParam);
        if (subStr == NULL) {
            continue;
        }
        subStr = strtok_r(buf, "=", &saveptr1);
        if (subStr == NULL) {
            continue;
        }
        /* Find same name then skip loop */
        if (strcmp(trim(subStr), srcParam) == 0) {
            break;
        }
    }
    /* process each row to find parameter */
    if (saveptr1 != NULL) {
        subStr = trim(saveptr1);
        subStr = strtok_r(subStr, "#", &saveptr1);
        subStr = strtok_r(subStr, "\n", &saveptr1);
        subStr = strtok_r(subStr, "\r", &saveptr1);

        char *trimStr = trim(subStr);
        if (strcmp(trimStr, "''") == 0) {
            trimStr = "";
        }
        if (trimStr == NULL || strlen(trimStr) + 1 > (size_t)destLen) {
#ifdef ENABLE_UT
            (void)fclose(fd);
            return -1;
#endif
            write_runlog(FATAL, "The value of parameter %s is invalid.\n", srcParam);
            exit(1);
        }
        rc = memcpy_s(destParam, strlen(trimStr) + 1, trimStr, strlen(trimStr) + 1);
        securec_check_errno(rc, (void)rc);
    }

    (void)fclose(fd);
    return 0;
}

/* used for connection mode or option between cm_agent and cn/dn */
void get_connection_mode(char *config_file)
{
    const char *srcStr = "enable_xc_maintenance_mode";
    char dstStr[10] = {'\0'};

    /* read parameter from cm_agent.conf by accurate parameter name */
    if (get_config_param(config_file, srcStr, dstStr, sizeof(dstStr)) < 0) {
        write_runlog(ERROR, "get_config_param() get enable_xc_maintenance_mode fail.\n");
        return;
    }
    if (strlen(dstStr) != 0) {
        if (strcasecmp(dstStr, "on") == 0 || strcasecmp(dstStr, "yes") == 0 || strcasecmp(dstStr, "true") == 0 ||
            strcasecmp(dstStr, "1") == 0) {
            enable_xc_maintenance_mode = true;
        } else if (strcasecmp(dstStr, "off") == 0 || strcasecmp(dstStr, "no") == 0 ||
                   strcasecmp(dstStr, "false") == 0 || strcasecmp(dstStr, "0") == 0) {
            enable_xc_maintenance_mode = false;
        } else {
            enable_xc_maintenance_mode = true;
            write_runlog(ERROR, "invalid value for parameter \"enable_xc_maintenance_mode\" in %s.\n", config_file);
        }
    } else {
        enable_xc_maintenance_mode = true;
        write_runlog(ERROR, "Get config parameter \"enable_xc_maintenance_mode\" value failed!\n");
    }

    return;
}
/* used for cm_agent */
void get_start_mode(char *config_file)
{
    const char *srcStr = "security_mode";
    char dstStr[10] = {'\0'};

    /* read parameter from cm_agent.conf by accurate parameter name */
    if (get_config_param(config_file, srcStr, dstStr, sizeof(dstStr)) < 0) {
        write_runlog(ERROR, "get_config_param() get security_mode fail.\n");
        return;
    }
    if (strlen(dstStr) != 0) {
        if (strcasecmp(dstStr, "on") == 0 || strcasecmp(dstStr, "yes") == 0 || strcasecmp(dstStr, "true") == 0 ||
            strcasecmp(dstStr, "1") == 0) {
            security_mode = true;
        } else if (strcasecmp(dstStr, "off") == 0 || strcasecmp(dstStr, "no") == 0 ||
            strcasecmp(dstStr, "false") == 0 || strcasecmp(dstStr, "0") == 0) {
            security_mode = false;
        } else {
            security_mode = true;
            write_runlog(FATAL, "invalid value for parameter \"security_mode\" in %s.\n", config_file);
        }
    } else {
        security_mode = true;
        write_runlog(FATAL, "Get config parameter \"security_mode\" value failed!\n");
    }

    return;
}
void ReloadParametersFromConfig()
{
    write_runlog(LOG, "reload cm_agent parameters from config file.\n");
    GetAlarmConfig(g_alarmConfigDir);
    get_log_paramter(configDir);
    get_build_mode(configDir);
    get_start_mode(configDir);
    GetStringFromConf(configDir, g_environmentThreshold, sizeof(g_environmentThreshold), "environment_threshold");
    agent_report_interval = (uint32)(get_int_value_from_config(configDir, "agent_report_interval", 1));
    agent_heartbeat_timeout = (uint32)(get_int_value_from_config(configDir, "agent_heartbeat_timeout", 8));
    agent_connect_timeout = (uint32)(get_int_value_from_config(configDir, "agent_connect_timeout", 1));
    agent_connect_retries = (uint32)(get_int_value_from_config(configDir, "agent_connect_retries", 15));
    agent_check_interval = (uint32)(get_int_value_from_config(configDir, "agent_check_interval", 2));
    agent_kill_instance_timeout = (uint32)get_int_value_from_config(configDir, "agent_kill_instance_timeout", 0);
    agent_phony_dead_check_interval =
        (uint32)get_int_value_from_config(configDir, "agent_phony_dead_check_interval", 10);
    enable_gtm_phony_dead_check = (uint32)get_int_value_from_config(configDir, "enable_gtm_phony_dead_check", 1);
    g_disasterRecoveryType =
        (DisasterRecoveryType)get_uint32_value_from_config(configDir, "disaster_recovery_type", DISASTER_RECOVERY_NULL);
    g_enableE2ERto = (uint32)get_int_value_from_config(configDir, "enable_e2e_rto", 0);
    if (g_enableE2ERto == 1) {
        agent_phony_dead_check_interval = 1;
    }
    g_ssDoubleClusterMode =
        (SSDoubleClusterMode)get_uint32_value_from_config(configDir, "ss_double_cluster_mode", SS_DOUBLE_NULL);
    if (agent_backup_open == CLUSTER_OBS_STANDBY) {
        agent_backup_open = (ClusterRole)get_uint32_value_from_config(configDir, "agent_backup_open", CLUSTER_PRIMARY);
    }
    log_threshold_check_interval =
        get_uint32_value_from_config(configDir, "log_threshold_check_interval", log_threshold_check_interval);
    undocumentedVersion = get_uint32_value_from_config(configDir, "upgrade_from", 0);
    dilatation_shard_count_for_disk_capacity_alarm = get_uint32_value_from_config(
        configDir, "dilatation_shard_count_for_disk_capacity_alarm", dilatation_shard_count_for_disk_capacity_alarm);
    g_diskTimeout = get_uint32_value_from_config(configDir, "disk_timeout", 200);
    GetEventTrigger();
}

void ReloadParametersFromConfigfile()
{
    ReloadParametersFromConfig();
    if (get_config_param(configDir, "enable_cn_auto_repair", g_enableCnAutoRepair, sizeof(g_enableCnAutoRepair)) < 0) {
        write_runlog(ERROR, "get_config_param() get enable_cn_auto_repair fail.\n");
    }
    if (get_config_param(configDir, "enable_log_compress", g_enableLogCompress, sizeof(g_enableLogCompress)) < 0) {
        write_runlog(ERROR, "get_config_param() get enable_log_compress fail.\n");
    }
    if (get_config_param(configDir, "security_mode", g_enableOnlineOrOffline, sizeof(g_enableOnlineOrOffline)) < 0) {
        write_runlog(ERROR, "get_config_param() get security_mode fail.\n");
    }

    if (get_config_param(configDir, "unix_socket_directory", g_unixSocketDirectory, sizeof(g_unixSocketDirectory)) <
        0) {
        write_runlog(ERROR, "get_config_param() get unix_socket_directory fail.\n");
    } else {
        check_input_for_security(g_unixSocketDirectory);
    }

    if (get_config_param(configDir, "db_service_vip", g_dbServiceVip, sizeof(g_dbServiceVip)) < 0) {
        write_runlog(ERROR, "get_config_param() get db_service_vip fail.\n");
    }

    log_max_size = get_int_value_from_config(configDir, "log_max_size", 10240);
    log_saved_days = (uint32)get_int_value_from_config(configDir, "log_saved_days", 90);
    log_max_count = (uint32)get_int_value_from_config(configDir, "log_max_count", 10000);

#ifndef ENABLE_MULTIPLE_NODES
    if (get_config_param(configDir, "enable_fence_dn", g_enableFenceDn, sizeof(g_enableFenceDn)) < 0)
        write_runlog(ERROR, "get_config_param() get enable_fence_dn fail.\n");
#endif

    write_runlog(LOG,
        "reload cm_agent parameters:\n"
        "  log_min_messages=%d, maxLogFileSize=%d, sys_log_path=%s, \n  alarm_component=%s, "
        "alarm_report_interval=%d, dilatation_shard_count_for_disk_capacity_alarm:%u, \n"
        "  agent_heartbeat_timeout=%u, agent_report_interval=%u, agent_connect_timeout=%u, \n"
        "  agent_connect_retries=%u, agent_check_interval=%u, agent_kill_instance_timeout=%u, \n"
        "  agent_phony_dead_check_interval=%u, enable_gtm_phony_dead_check=%u, disk_timeout=%u, \n"
        "  log_threshold_check_interval=%u, log_max_size=%ld, log_max_count=%u, log_saved_days=%u, "
        "upgrade_from=%u,\n  enable_cn_auto_repair=%s, enable_log_compress=%s, security_mode=%s,\n"
        "  incremental_build=%d, unix_socket_directory=%s, "
#ifndef ENABLE_MULTIPLE_NODES
        "enable_e2e_rto=%u, disaster_recovery_type=%d, environment_threshold=%s,\n"
        "  db_service_vip=%s, enable_fence_dn=%s, ss_double_cluster_mode=%d, agent_backup_open=%d\n",
#else
        "enable_e2e_rto=%u, disaster_recovery_type=%d, environment_threshold=%s\n",
#endif
        log_min_messages,
        maxLogFileSize,
        sys_log_path,
        g_alarmComponentPath,
        g_alarmReportInterval,
        dilatation_shard_count_for_disk_capacity_alarm,
        agent_heartbeat_timeout,
        agent_report_interval,
        agent_connect_timeout,
        agent_connect_retries,
        agent_check_interval,
        agent_kill_instance_timeout,
        agent_phony_dead_check_interval,
        enable_gtm_phony_dead_check,
        g_diskTimeout,
        log_threshold_check_interval,
        log_max_size,
        log_max_count,
        log_saved_days,
        undocumentedVersion,
        g_enableCnAutoRepair,
        g_enableLogCompress,
        g_enableOnlineOrOffline,
        incremental_build,
        g_unixSocketDirectory,
        g_enableE2ERto,
        g_disasterRecoveryType,
#ifndef ENABLE_MULTIPLE_NODES
        g_environmentThreshold,
        g_dbServiceVip,
        g_enableFenceDn,
        g_ssDoubleClusterMode,
        agent_backup_open);
#else
        g_environmentThreshold);
#endif
}

int ReadDBStateFile(GaussState *state, const char *statePath)
{
    if (state == NULL) {
        write_runlog(LOG, "Could not get information from gaussdb.state\n");
        return -1;
    }

    FILE *statef = fopen(statePath, "re");
    if (statef == NULL) {
        if (errno == ENOENT) {
            char errBuffer[ERROR_LIMIT_LEN];
            write_runlog(LOG,
                "gaussdb state file \"%s\" is not exist, could not get the build infomation: %s\n",
                statePath,
                strerror_r(errno, errBuffer, ERROR_LIMIT_LEN));
        } else {
            char errBuffer[ERROR_LIMIT_LEN];
            write_runlog(LOG,
                "open gaussdb state file \"%s\" failed, could not get the build infomation: %s\n",
                statePath,
                strerror_r(errno, errBuffer, ERROR_LIMIT_LEN));
        }
        return -1;
    }
    if ((fread(state, 1, sizeof(GaussState), statef)) == 0) {
        write_runlog(LOG, "get gaussdb state infomation from the file \"%s\" failed\n", statePath);
        (void)fclose(statef);
        return -1;
    }
    write_runlog(DEBUG1, "gaussdb state file: state:%d, mode:%d.\n", state->state, state->mode);
    (void)fclose(statef);
    return 0;
}

void UpdateDBStateFile(const char *path, const GaussState *state)
{
    int ret;
    char tempPath[CM_PATH_LENGTH] = {0};

    if (state == NULL || path == NULL) {
        return;
    }

    ret = snprintf_s(tempPath, CM_PATH_LENGTH, CM_PATH_LENGTH - 1, "%s.temp", path);
    securec_check_intval(ret, (void)ret);

    FILE *fp = fopen(tempPath, "w");
    if (fp == NULL) {
        write_runlog(ERROR, "open file \"%s\" failed.\n", tempPath);
        return;
    }
    if (chmod(tempPath, S_IRUSR | S_IWUSR) == -1) {
        /* Close file and Nullify the pointer for retry */
        write_runlog(ERROR, "chmod file \"%s\" failed.\n", tempPath);
        (void)fclose(fp);
        return;
    }
    if (fwrite(state, 1, sizeof(GaussState), fp) == 0) {
        write_runlog(ERROR, "write file \"%s\" failed.\n", tempPath);
        (void)fclose(fp);
        return;
    }
    (void)fclose(fp);

    (void)rename(tempPath, path);

    return;
}

pgpid_t get_pgpid(char *pid_path, uint32 len)
{
    if (len == 0) {
        write_runlog(ERROR, "pidPath(%s) len is 0.\n", pid_path);
        return 0;
    }
    long pid;

    canonicalize_path(pid_path);
    FILE *pidf = fopen(pid_path, "re");
    if (pidf == NULL) {
        write_runlog(DEBUG5, "could not open PID file \"%s\"\n", pid_path);
        return 0;
    }
    if (fscanf_s(pidf, "%ld", &pid) != 1) {
        write_runlog(ERROR, "invalid data in PID file \"%s\"\n", pid_path);
        (void)fclose(pidf);
        return -1;
    }
    (void)fclose(pidf);
    return (pgpid_t)pid;
}

bool is_process_alive(pgpid_t pid)
{
    if (pid == getpid() || pid == getppid()) {
        return false;
    }
    if (kill((int)pid, 0) == 0) {
        return true;
    }
    return false;
}

int check_disc_state(uint32 instanceId)
{
    struct timespec now = {0};
    (void)clock_gettime(CLOCK_MONOTONIC, &now);

    if ((now.tv_sec - g_check_disc_state > (long)g_threadDeadEffectiveTime) && g_check_disc_state != 0 &&
        instanceId == g_checkDiscInstanceNow) {
        write_runlog(LOG, "check disc phony dead for instance(%u) is invalid.\n", g_checkDiscInstanceNow);
        return -1;
    }

    if ((now.tv_sec - g_check_disc_state > 120) && g_check_disc_state != 0) {
        write_runlog(LOG,
            "the instance check disc take %ld second, instance is %u.\n",
            now.tv_sec - g_check_disc_state,
            g_checkDiscInstanceNow);
    }

    return 0;
}

void set_disc_check_state(uint32 instanceId)
{
    g_checkDiscInstanceNow = instanceId;
    struct timeval now = {0};
    (void)gettimeofday(&now, NULL);
    if (instanceId == 0) {
        if (now.tv_sec - g_check_disc_state > 120) {
            write_runlog(LOG, "the instance check disc take %ld second.\n", now.tv_sec - g_check_disc_state);
        }
        g_check_disc_state = 0;
    } else {
        g_check_disc_state = now.tv_sec;
    }
}

bool agentCheckDisc(const char *path)
{
    char write_test_file[MAXPGPATH] = {0};
    int rc;
    char buf[2] = {0};

    Assert(path != NULL);
    rc = snprintf_s(
        write_test_file, sizeof(write_test_file), sizeof(write_test_file) - 1, "%s/disc_readonly_test", path);
    securec_check_intval(rc, (void)rc);
    check_input_for_security(write_test_file);
    canonicalize_path(write_test_file);
    errno = 0;
    FILE *fd = fopen(write_test_file, "we");
    if (fd != NULL) {
        errno = 0;
        if (fwrite("1", sizeof("1"), 1, fd) != 1) {
            if (errno == EROFS || errno == EIO) {
                (void)fclose(fd);
                write_runlog(LOG, "could not write disc test file, ERRNO : %d\n", errno);
                (void)remove(write_test_file);
                return false;
            }
        }
        (void)fclose(fd);
        fd = fopen(write_test_file, "re");
        if (fd != NULL) {
            if (fread(buf, sizeof("1"), 1, fd) != 1) {
                if (errno == ENOSPC) {
                    (void)fclose(fd);
                    write_runlog(LOG, "could not read disc test file, ERRNO : %d\n", errno);
                    (void)remove(write_test_file);
                    return false;
                }
            }
            (void)fclose(fd);
        }
        (void)remove(write_test_file);
        return true;
    } else {
        int save_errno = errno;
        write_runlog(LOG, "could not open disc test file, ERRNO : %d\n", save_errno);

        if (save_errno == EROFS || save_errno == EACCES || save_errno == ENOENT || save_errno == EIO ||
            save_errno == ENOSPC) {
            return false;
        }

        return true;
    }
}

void set_instance_not_exist_alarm_value(int *val, int state)
{
    if (*val != UNKNOWN_BAD_REASON) {
        return;
    }
    *val = state;
}

/*
 * @Description: when cn start, record datanode pid
 *
 */
void record_pid(const char *DataPath)
{
    int rcs;
    int ret;
    char command[MAXPGPATH];
    const char *dnName = GetDnProcessName();
    rcs = snprintf_s(command,
        MAXPGPATH,
        MAXPGPATH - 1,
        "ps -ux | grep  %s | grep %s| awk '{print \"start instance pid: \"$2"
        ", \"data path: \"$14}' >> \"%s\" 2>&1 &",
        DataPath,
        dnName,
        system_call_log);
    securec_check_intval(rcs, (void)rcs);

    ret = system(command);
    if (ret != 0) {
        write_runlog(ERROR, "run system command failed %d! %s, errno=%d.\n", ret, command, errno);
    } else {
        write_runlog(DEBUG1, "run system command success %s \n", command);
    }
}

uint32 GetDatanodeNumSort(const staticNodeConfig *p_node_config, uint32 sort)
{
    uint32 j;
    uint32 cur_dn_num = 0;

    for (j = 0; j < p_node_config->datanodeCount; j++) {
        if (sort == p_node_config->datanode[j].datanodeRole) {
            cur_dn_num++;
        }
    }

    return cur_dn_num;
}

int search_HA_node(uint32 localPort, uint32 LocalHAListenCount, char LocalHAIP[][CM_IP_LENGTH], uint32 peerPort,
    uint32 PeerHAListenCount, char PeerHAIP[][CM_IP_LENGTH], uint32 *node_index, uint32 *instance_index,
    uint32 loal_role)
{
    uint32 i;
    uint32 max_node_count;
    char input_local_listen_ip[CM_IP_ALL_NUM_LENGTH];
    char input_peer_listen_ip[CM_IP_ALL_NUM_LENGTH];
    char local_listen_ip[CM_IP_ALL_NUM_LENGTH];
    char peer_listen_ip[CM_IP_ALL_NUM_LENGTH];
    uint32 j;
    errno_t rc;

    *node_index = 0;
    *instance_index = 0;

    max_node_count = g_node_num;
    rc = memset_s(input_local_listen_ip, CM_IP_ALL_NUM_LENGTH, 0, CM_IP_ALL_NUM_LENGTH);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(input_peer_listen_ip, CM_IP_ALL_NUM_LENGTH, 0, CM_IP_ALL_NUM_LENGTH);
    securec_check_errno(rc, (void)rc);
    listen_ip_merge(LocalHAListenCount, LocalHAIP, input_local_listen_ip, CM_IP_ALL_NUM_LENGTH);
    listen_ip_merge(PeerHAListenCount, PeerHAIP, input_peer_listen_ip, CM_IP_ALL_NUM_LENGTH);

    for (i = 0; i < max_node_count; i++) {
        for (j = 0; j < g_node[i].datanodeCount; j++) {
            if (g_multi_az_cluster) {
                bool be_continue = true;
                uint32 primary_dn_idx = 0;
                for (uint32 dnId = 0; dnId < g_dn_replication_num - 1; dnId++) {
                    be_continue = true;
                    if (g_node[i].datanode[j].peerDatanodes[dnId].datanodePeerRole == PRIMARY_DN) {
                        be_continue = false;
                        primary_dn_idx = dnId;
                        if ((g_node[i].datanode[j].datanodeLocalHAPort != peerPort) ||
                            (g_node[i].datanode[j].peerDatanodes[dnId].datanodePeerHAPort != localPort)) {
                            be_continue = true;
                        }
                        break; /* break if get one primary dn */
                    }
                }
                if (be_continue) {
                    continue;
                }

                rc = memset_s(local_listen_ip, CM_IP_ALL_NUM_LENGTH, 0, CM_IP_ALL_NUM_LENGTH);
                securec_check_errno(rc, (void)rc);
                rc = memset_s(peer_listen_ip, CM_IP_ALL_NUM_LENGTH, 0, CM_IP_ALL_NUM_LENGTH);
                securec_check_errno(rc, (void)rc);
                listen_ip_merge(g_node[i].datanode[j].datanodeLocalHAListenCount,
                    g_node[i].datanode[j].datanodeLocalHAIP,
                    local_listen_ip,
                    CM_IP_ALL_NUM_LENGTH);

                if (g_node[i].datanode[j].peerDatanodes[primary_dn_idx].datanodePeerRole == PRIMARY_DN) {
                    listen_ip_merge(g_node[i].datanode[j].peerDatanodes[primary_dn_idx].datanodePeerHAListenCount,
                        g_node[i].datanode[j].peerDatanodes[primary_dn_idx].datanodePeerHAIP,
                        peer_listen_ip,
                        CM_IP_ALL_NUM_LENGTH);
                }
                if ((strncmp(local_listen_ip, input_peer_listen_ip, CM_IP_ALL_NUM_LENGTH) == 0) &&
                    (strncmp(peer_listen_ip, input_local_listen_ip, CM_IP_ALL_NUM_LENGTH) == 0)) {
                    *node_index = i;
                    *instance_index = j;
                    return 0;
                }
            } else {
                if (loal_role == g_node[i].datanode[j].datanodePeerRole) {
                    if ((g_node[i].datanode[j].datanodeLocalHAPort != peerPort) ||
                        (g_node[i].datanode[j].datanodePeerHAPort != localPort)) {
                        continue;
                    }
                } else if (loal_role == g_node[i].datanode[j].datanodePeer2Role) {
                    if ((g_node[i].datanode[j].datanodeLocalHAPort != peerPort) ||
                        (g_node[i].datanode[j].datanodePeer2HAPort != localPort)) {
                        continue;
                    }
                } else {
                    continue;
                }

                rc = memset_s(local_listen_ip, CM_IP_ALL_NUM_LENGTH, 0, CM_IP_ALL_NUM_LENGTH);
                securec_check_errno(rc, (void)rc);
                rc = memset_s(peer_listen_ip, CM_IP_ALL_NUM_LENGTH, 0, CM_IP_ALL_NUM_LENGTH);
                securec_check_errno(rc, (void)rc);
                listen_ip_merge(g_node[i].datanode[j].datanodeLocalHAListenCount,
                    g_node[i].datanode[j].datanodeLocalHAIP,
                    local_listen_ip,
                    CM_IP_ALL_NUM_LENGTH);
                if (loal_role == g_node[i].datanode[j].datanodePeerRole) {
                    listen_ip_merge(g_node[i].datanode[j].datanodePeerHAListenCount,
                        g_node[i].datanode[j].datanodePeerHAIP,
                        peer_listen_ip,
                        CM_IP_ALL_NUM_LENGTH);
                } else if (loal_role == g_node[i].datanode[j].datanodePeer2Role) {
                    listen_ip_merge(g_node[i].datanode[j].datanodePeer2HAListenCount,
                        g_node[i].datanode[j].datanodePeer2HAIP,
                        peer_listen_ip,
                        CM_IP_ALL_NUM_LENGTH);
                }

                if ((strncmp(local_listen_ip, input_peer_listen_ip, CM_IP_ALL_NUM_LENGTH) == 0) &&
                    (strncmp(peer_listen_ip, input_local_listen_ip, CM_IP_ALL_NUM_LENGTH) == 0)) {
                    *node_index = i;
                    *instance_index = j;
                    return 0;
                }
            }
        }
    }

    return -1;
}

int agentCheckPort(uint32 port)
{
    char buf[MAXPGPATH] = {0};
    char localip[MAXPGPATH] = {0};
    char peerip[MAXPGPATH] = {0};
    char other[MAXPGPATH] = {0};

    uint32 ls = 0;
    uint32 localport = 0;
    uint32 peerport = 0;
    uint32 status = 0;
    int rc = 0;

    FILE *fp = fopen(PROC_NET_TCP, "re");
    if (fp == NULL) {
        write_runlog(ERROR, "can not open file \"%s\"\n", PROC_NET_TCP);
        return -1;
    }

    if (fgets(buf, MAXPGPATH - 1, fp) == NULL) {
        write_runlog(ERROR, "can not read file \"%s\"\n", PROC_NET_TCP);
        (void)fclose(fp);
        return -1;
    }

    while (fgets(buf, MAXPGPATH - 1, fp) != NULL) {
        localport = 0;
        status = 0;

        rc = sscanf_s(buf,
            "%u: %[0-9A-Fa-f]:%X %[0-9A-Fa-f]:%X %X %s",
            &ls,
            localip,
            MAXPGPATH,
            &localport,
            peerip,
            MAXPGPATH,
            &peerport,
            &status,
            other,
            MAXPGPATH);
        if (rc != 7) {
            write_runlog(ERROR, "get value by sscanf_s return error:%d, %s:%d \n", rc, __FUNCTION__, __LINE__);
            continue;
        }

        securec_check_intval(rc, (void)rc);
        if (localport == port && status == LISTEN) {
            (void)fclose(fp);
            write_runlog(WARNING,
                "port:%u already in use. /proc/net/tcp:\n%s \n%s",
                localport,
                "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ",
                buf);

            char command[MAXPGPATH] = {0};
            rc = snprintf_s(command,
                MAXPGPATH,
                MAXPGPATH - 1,
                SYSTEMQUOTE "lsof -i:%u | grep -E \'COMMAND|LISTEN\' >> \"%s\" 2>&1 " SYSTEMQUOTE,
                localport,
                system_call_log);
            securec_check_intval(rc, (void)rc);

            rc = system(command);
            if (rc != 0) {
                write_runlog(ERROR, "run system command failed %d! %s, errno=%d.\n", rc, command, errno);
            }

            write_runlog(LOG, "CheckPort: system(command:%s).\n", command);
            return 1;
        }
    }

    (void)fclose(fp);
    return 0;
}

/**
 * @brief Get the disk usage of a specified directory like the df command.
 *
 * @param  pathName         The directory path of the disk usage.
 * @return uint32           Get the Data path disk usage.
 */
uint32 GetDiskUsageForPath(const char *pathName)
{
    int ret;
    uint32 percent = 0;
    struct statfs diskInfo = {0};

    if (pathName == NULL) {
        return percent;
    }

    ret = statfs(pathName, &diskInfo);
    if (ret < 0) {
        write_runlog(ERROR, "[%s][line:%d] GetDiskUsageForPath %s disk usage failed! errno:%d err:%s.\n",
            __FUNCTION__, __LINE__, pathName, errno, strerror(errno));
        return percent;
    }

    if (diskInfo.f_blocks == 0 || (diskInfo.f_blocks - diskInfo.f_bfree + diskInfo.f_bavail) == 0) {
        return percent;
    }
    /*
     * The df command is used to obtain an integer percentage without decimals.
     * The forward method is used here, not the rounding method.
     * Therefore, the system rounds the value by 1 in the program.
     */
    percent = (uint32)((diskInfo.f_blocks - diskInfo.f_bfree) * 100 /
        (diskInfo.f_blocks - diskInfo.f_bfree + diskInfo.f_bavail));

    return (percent <= 100) ? percent : 100;
}

uint32 CheckDiskForLogPath(void)
{
    uint32 percent = 0;
    char currentLogPath[MAX_PATH_LEN] = {0};
    int isLogPath = cmagent_getenv("GAUSSLOG", currentLogPath, sizeof(currentLogPath));
    if (isLogPath != EOK) {
        write_runlog(DEBUG1, "[%s][line:%d] CheckDiskForLogPath: GAUSSLOG get fail!\n", __FUNCTION__, __LINE__);
        return percent;
    }

    check_input_for_security(currentLogPath);
    percent = GetDiskUsageForPath(currentLogPath);
    return percent;
}

int ExecuteSystemCmd(const char *cmd, int32 logLevel, int32 *errCode)
{
    int ret = system(cmd);
    if (ret == -1) {
        // shield error codes 10 (no child processes), it may be much
        const int32 noChildProcessesErrCode = 10;
        int32 tmpLevel = (errno == noChildProcessesErrCode) ? logLevel : ERROR;
        write_runlog(tmpLevel, "Fail to execute command %s, and errno=%d.\n", cmd, errno);
        return ERROR_EXECUTE_CMD;
    }

    if (WIFEXITED(ret)) {
        if (WEXITSTATUS(ret) == 0) {
            return SUCCESS_EXECUTE_CMD;
        }
        // arping cmd return 1 is not error
        if (strstr(cmd, "arping") != NULL && WEXITSTATUS(ret) == 1) {
            return SUCCESS_EXECUTE_CMD;
        }
    }

    write_runlog(logLevel, "Fail to execute command %s, script exit code %d.\n", cmd, WEXITSTATUS(ret));
    if (errCode != NULL) {
        *errCode = WEXITSTATUS(ret);
    }
    return FAILED_EXECUTE_CMD;
}

void CheckDnNicDown(uint32 index)
{
    dataNodeInfo *dnInfo = &(g_currentNode->datanode[index]);
    g_nicDown[index] = ((!GetNicStatus(dnInfo->datanodeId, CM_INSTANCE_TYPE_DN)) ||
        (!GetNicStatus(dnInfo->datanodeId, CM_INSTANCE_TYPE_DN, NETWORK_TYPE_HA)) ||
        (!GetNicStatus(g_currentNode->cmAgentId, CM_INSTANCE_TYPE_CMA)));
    if (g_nicDown[index]) {
        write_runlog(WARNING, "nic related with datanode(%s) not up.\n", dnInfo->datanodeLocalDataPath);
    }
}

bool DnManualStop(uint32 index)
{
    struct stat instanceStatBuf = {0};
    struct stat clusterStatBuf = {0};
    int rcs;
    char instanceManualStartPath[MAX_PATH_LEN] = {0};
    rcs = snprintf_s(instanceManualStartPath,
        MAX_PATH_LEN,
        MAX_PATH_LEN - 1,
        "%s_%u",
        g_cmInstanceManualStartPath,
        g_currentNode->datanode[index].datanodeId);
    securec_check_intval(rcs, (void)rcs);
    if (stat(instanceManualStartPath, &instanceStatBuf) == 0 || stat(g_cmManualStartPath, &clusterStatBuf) == 0) {
        return true;
    }

    return false;
}

bool DirectoryIsDestroyed(const char *path)
{
    struct dirent *xlde;
    bool ret = true;

    DIR *xldir = opendir(path);
    if (xldir == NULL) {
        /* missing dir is not considerred here */
        return false;
    }

    while ((xlde = readdir(xldir)) != NULL) {
        if (strcmp(xlde->d_name, ".") == 0 || strcmp(xlde->d_name, "..") == 0) {
            continue;
        }

        ret = false;
        break;
    }

    (void)closedir(xldir);

    return ret;
}

bool IsDirectoryDestroyed(const char *path)
{
    struct dirent *xlde;
    bool ret = true;

    DIR *xldir = opendir(path);
    if (xldir == NULL) {
        /* missing dir is not considerred here */
        return false;
    }

    while ((xlde = readdir(xldir)) != NULL) {
        if (strcmp(xlde->d_name, ".") == 0 || strcmp(xlde->d_name, "..") == 0) {
            continue;
        }

        ret = false;
        break;
    }

    (void)closedir(xldir);

    return ret;
}

void CheckDnDiskDamage(uint32 index)
{
    bool dnManualStop = DnManualStop(index);
    if (!dnManualStop) {
        set_disc_check_state(g_currentNode->datanode[index].datanodeId);
        bool cdt = (IsDirectoryDestroyed(g_currentNode->datanode[index].datanodeLocalDataPath) ||
            !agentCheckDisc(g_currentNode->datanode[index].datanodeLocalDataPath) || !agentCheckDisc(g_logBasePath));
        if (cdt) {
            write_runlog(ERROR,
                "data path disc writable test failed, %s.\n",
                g_currentNode->datanode[index].datanodeLocalDataPath);
            g_dnDiskDamage[index] = true;
        } else {
            g_dnDiskDamage[index] = false;
        }
        set_disc_check_state(0);
    } else {
        g_dnDiskDamage[index] = false;
        g_dnBuild[index] = false;
        write_runlog(DEBUG1,
            "%d, dn(%u) the g_dnBuild[%u] is set to false.\n",
            __LINE__,
            g_currentNode->datanode[index].datanodeId,
            index);
    }
}

bool CheckMaintanceCluster()
{
    char execPath[MAX_PATH_LEN] = {0};
    char maintanceClusterFlagPath[MAX_PATH_LEN] = {0};
    char maintanceInstanceFlagPath[MAX_PATH_LEN] = {0};
    char upgradeFlagPath[MAX_PATH_LEN] = {0};
    int rc = cmagent_getenv("GAUSSHOME", execPath, sizeof(execPath));
    if (rc != EOK) {
        write_runlog(ERROR, "Line:%d Get GAUSSHOME failed, please check.\n", __LINE__);
        return false;
    }
    rc = snprintf_s(
        maintanceClusterFlagPath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/%s", execPath, "mainstance_cluster_status");
    securec_check_intval(rc, (void)rc);
    if (access(maintanceClusterFlagPath, F_OK) == 0) {
        write_runlog(LOG, "Line:%d Get maintance cluster flag success.\n", __LINE__);
        return true;
    }
    rc = snprintf_s(
        maintanceInstanceFlagPath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/%s", execPath, "mainstance_instance");
    securec_check_intval(rc, (void)rc);
    if (access(maintanceInstanceFlagPath, F_OK) == 0) {
        write_runlog(LOG, "Line:%d Get maintance instance flag success.\n", __LINE__);
        return true;
    }
    rc = cmagent_getenv("PGHOST", execPath, sizeof(execPath));
    if (rc != EOK) {
        write_runlog(ERROR, "Line:%d Get PGHOST failed, please check.\n", __LINE__);
        return false;
    }
    rc = snprintf_s(upgradeFlagPath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/binary_upgrade", execPath);
    securec_check_intval(rc, (void)rc);
    if (access(upgradeFlagPath, F_OK) == 0) {
        write_runlog(LOG, "Line:%d Get upgrade flag success.\n", __LINE__);
        return true;
    }
    return false;
}

void ReportCMAEventAlarm(Alarm* alarmItem, AlarmAdditionalParam* additionalParam)
{
    bool isMaintainCluster = CheckMaintanceCluster();
    if (!isMaintainCluster) {
        AlarmReporter(alarmItem, ALM_AT_Event, additionalParam);
    } else {
        write_runlog(ERROR, "Line %d:Maintaining cluster:no event alarm is generated, maintancefalg: %d\n",
            __LINE__, isMaintainCluster);
    }
}

bool CheckStartDN()
{
    if (!GetIsSharedStorageMode()) {
        return true;
    }
    if (undocumentedVersion != 0 && undocumentedVersion < DORADO_UPGRADE_VERSION) {
        return !IsNodeOfflineFromEtcd(g_nodeId, CM_AGENT);
    }
    if (g_doradoIp[0] == '\0') {
        write_runlog(LOG, "get dorado ip is NULL.\n");
        return true;
    }
    if (strcmp(g_doradoIp, "unknown") == 0) {
        write_runlog(ERROR, "get dorado ip failed.\n");
        return true;
    }
    if (strcmp(g_doradoIp, g_currentNode->sshChannel[0]) == 0) {
        write_runlog(DEBUG1, "Line:%d Get ignore node(%s) successfully.\n", __LINE__, g_currentNode->sshChannel[0]);
        return false;
    }

    return true;
}

static void RefreshQueryBarrier(const cm_to_agent_barrier_info *barrierRespMsg)
{
    errno_t rc = 0;
    /* Just at first, queryBarrier and targetBarrier can be null, whick is ok. */
    if (barrierRespMsg->queryBarrier[0] == '\0') {
        write_runlog(LOG, "[RefreshQueryBarrier] queryBarrier is null.\n");
        return;
    }
    write_runlog(LOG, "[RefreshQueryBarrier] queryBarrier is %s.\n", barrierRespMsg->queryBarrier);
    /* updata queryBarrier */
    if (g_agentQueryBarrier[0] == '\0' ||
        strncmp(g_agentQueryBarrier, barrierRespMsg->queryBarrier, BARRIERLEN - 1) < 0) {
        rc = memcpy_s(g_agentQueryBarrier, BARRIERLEN - 1, barrierRespMsg->queryBarrier, BARRIERLEN - 1);
        securec_check_errno(rc, (void)rc);
        write_runlog(LOG, "[RefreshQueryBarrier]querybarrier info refresh, querybarrier: %s.\n", g_agentQueryBarrier);
    } else {
        write_runlog(LOG, "[RefreshQueryBarrier] the new barrier(%s) is not bigger than the old(%s).\n",
            barrierRespMsg->queryBarrier, g_agentQueryBarrier);
        return;
    }
}

static void RefreshTargetBarrier(const cm_to_agent_barrier_info *barrierRespMsg)
{
    errno_t rc = 0;
    /* targetBarrier can not be bigger than queryBarrier because of barrier's increasement. */
    if (barrierRespMsg->targetBarrier[0] == '\0' ||
        strncmp(barrierRespMsg->targetBarrier, barrierRespMsg->queryBarrier, BARRIERLEN - 1) > 0) {
        write_runlog(LOG, "[RefreshTargetBarrier] targetBarrier is invalid, targetBarrier is %s.\n",
            barrierRespMsg->targetBarrier);
        return;
    }
    /* update targetBarrier */
    if (g_agentTargetBarrier[0] == '\0' ||
        strncmp(g_agentTargetBarrier, barrierRespMsg->targetBarrier, BARRIERLEN - 1) < 0) {
        rc = memcpy_s(g_agentTargetBarrier, BARRIERLEN - 1, barrierRespMsg->targetBarrier, BARRIERLEN - 1);
        securec_check_errno(rc, (void)rc);
        write_runlog(LOG, "[RefreshTargetBarrier]targetbarrier info refresh, targetbarrier: %s.\n",
            g_agentTargetBarrier);
    } else {
        write_runlog(LOG, "[RefreshTargetBarrier] the new barrier(%s) is not bigger than the old(%s).\n",
            barrierRespMsg->targetBarrier, g_agentTargetBarrier);
        return;
    }
}

int ProcessDnBarrierInfoResp(const cm_to_agent_barrier_info *barrierRespMsg)
{
    RefreshQueryBarrier(barrierRespMsg);
    RefreshTargetBarrier(barrierRespMsg);
    return 0;
}

#if ((defined(ENABLE_MULTIPLE_NODES)) || (defined(ENABLE_PRIVATEGAUSS)))
static int GetDnInstanceIdStr(const CmToAgentGsGucSyncList *msgTypeDoGsGuc, char *ids, size_t idsLen)
{
    errno_t rc = 0;
    uint32 instanceId = msgTypeDoGsGuc->instanceId;
    const DatanodeSyncList *expectSyncList = &(msgTypeDoGsGuc->dnSyncList);
    bool flag = false;
    int index = 0;
    size_t len = 0;
    for (; index < expectSyncList->count; ++index) {
        if (expectSyncList->dnSyncList[index] == instanceId) {
            continue;
        }
        if (!flag) {
            rc = snprintf_s(ids, idsLen, idsLen - 1, "dn_%u", expectSyncList->dnSyncList[index]);
            securec_check_intval(rc, (void)rc);
            flag = true;
        } else {
            len = strlen(ids);
            if (len >= (idsLen - 1)) {
                return index;
            }
            rc = snprintf_s(ids + len, (idsLen - len), ((idsLen - len) - 1),
                ", dn_%u", expectSyncList->dnSyncList[index]);
            securec_check_intval(rc, (void)rc);
        }
    }
    return index;
}

static void GetSyncListString(const DatanodeSyncList *syncList, char *syncListString, size_t maxLen)
{
    errno_t rc = 0;
    size_t strLen = 0;
    if (syncList->count <= 0) {
        rc = strcpy_s(syncListString, maxLen, "sync list is empty");
        securec_check_errno(rc, (void)rc);
        return;
    }

    if (maxLen <= 1) {
        write_runlog(ERROR, "maxLen is 1 or 0.\n");
        return;
    }
    for (int index = 0; index < syncList->count; ++index) {
        strLen = strlen(syncListString);
        if (strLen >= (maxLen - 1)) {
            return;
        }
        if (index == syncList->count - 1) {
            rc = snprintf_s(
                syncListString + strLen, maxLen - strLen, (maxLen - strLen) - 1, "%u", syncList->dnSyncList[index]);
        } else {
            rc = snprintf_s(
                syncListString + strLen, maxLen - strLen, (maxLen - strLen) - 1, "%u, ", syncList->dnSyncList[index]);
        }
        securec_check_intval(rc, (void)rc);
    }
}

static void SetCmDoWrite(uint32 idx)
{
    (void)pthread_rwlock_wrlock(&(g_cmDoWriteOper[idx].lock));
    g_cmDoWriteOper[idx].doWrite = true;
    (void)pthread_rwlock_unlock(&(g_cmDoWriteOper[idx].lock));
    write_runlog(LOG, "receive modifing syncList from cms, and need to do write oper.\n");
}

int ProcessGsGucDnCommand(const CmToAgentGsGucSyncList *msgTypeDoGsGuc)
{
    char gsGucCommand[MAXPGPATH] = {0};
    char dnInstanceIds[MAXPGPATH] = {0};
    char syncListStr[MAXPGPATH] = {0};
    int syncStandbyNum = GetDnInstanceIdStr(msgTypeDoGsGuc, dnInstanceIds, sizeof(dnInstanceIds));
    if (syncStandbyNum == 0) {
        write_runlog(ERROR, "syncStandbyNum is 0.\n");
        return -1;
    }
    GetSyncListString(&(msgTypeDoGsGuc->dnSyncList), syncListStr, sizeof(syncListStr));
    write_runlog(LOG, "dnSyncList is [%s], syncStandbyNum is %d, dnInstanceIds is %s.\n",
        syncListStr, syncStandbyNum, dnInstanceIds);
    syncStandbyNum = syncStandbyNum / 2;
    uint32 dnIndex;
    bool result = true;
    for (dnIndex = 0; dnIndex < g_currentNode->datanodeCount; dnIndex++) {
        if (g_currentNode->datanode[dnIndex].datanodeId == msgTypeDoGsGuc->instanceId) {
            break;
        }
    }
    const char *dnSyncMode = "ANY";
    errno_t rc = snprintf_s(gsGucCommand, MAXPGPATH, MAXPGPATH - 1,
        "gs_guc reload  -Z datanode -D %s  -c \"synchronous_standby_names = '%s NODE %d(%s)'\" >> %s 2>&1 ",
        g_currentNode->datanode[dnIndex].datanodeLocalDataPath, dnSyncMode, syncStandbyNum, dnInstanceIds,
        system_call_log);
    securec_check_intval(rc, (void)rc);
    write_runlog(LOG, "gsGucCommand is %s.\n", gsGucCommand);
    rc = system(gsGucCommand);
    if (rc != 0) {
        write_runlog(ERROR, "Execute %s failed: , errno=%d.\n", gsGucCommand, errno);
        result = false;
    } else {
        write_runlog(LOG, "Execute %s success: \n", gsGucCommand);
        result = true;
    }
    if (result) {
        SetCmDoWrite(dnIndex);
    }
    return 0;
}
#endif

void PrintInstanceStack(const char* dataPath, bool isPrintedOnce)
{
    if (isPrintedOnce) {
        return;
    }

    char command[CM_MAX_COMMAND_LEN];
    errno_t rc = snprintf_s(command, CM_MAX_COMMAND_LEN, CM_MAX_COMMAND_LEN - 1,
        "gs_ctl stack -D %s >> \"%s\" 2>&1 &",
        dataPath, system_call_log);
    securec_check_intval(rc, (void)rc);

    int ret = system(command);
    if (ret != 0) {
        write_runlog(ERROR, "[%s] command:%s failed %d! errno=%d.\n", __FUNCTION__, command, ret, errno);
    } else {
        write_runlog(LOG, "[%s] command:%s success\n", __FUNCTION__, command);
    }
}

uint32 GetMaxLenOfPartition(void)
{
    FILE *fp;
    char line[1024];
    char partitionName[1024];
    uint32 maxPartitionLen = 0;

    char command[CM_MAX_COMMAND_LEN];
    errno_t rc = snprintf_s(command, CM_MAX_COMMAND_LEN, CM_MAX_COMMAND_LEN - 1,
                            "df |awk '{print $NF}' |grep ^/");
    securec_check_intval(rc, (void)rc);

    fp = popen(command, "r");
    if (fp == NULL) {
        write_runlog(ERROR, "[%s] command: %s failed! errno=%d.\n", __FUNCTION__, command, errno);
        return MAX_PATH_LEN;
    }
    while (fgets(line, sizeof(line)-1, fp)!= NULL) {
        sscanf(line, "%s", partitionName);
        maxPartitionLen = maxPartitionLen > strlen(partitionName)? maxPartitionLen: strlen(partitionName);
    }
    (void)pclose(fp);
    return maxPartitionLen;
}

uint32 GetMaxPercentFromDirList(const vector<string> v_linkPathInfo)
{
    uint32 maxDiskUsage = 0;
    uint32 diskUsage = 0;
    for (unsigned i = 0; i < v_linkPathInfo.size(); i++) {
        diskUsage = GetDiskUsageForPath(v_linkPathInfo[i].c_str());
        maxDiskUsage = maxDiskUsage > diskUsage ? maxDiskUsage : diskUsage;
    }
    return maxDiskUsage;
}

uint32 GetDiskUsageForLinkPath(const char *pathName)
{
    vector<string> v_linkPathInfo;
    uint32 maxPartitionLen = GetMaxLenOfPartition();
    const char *pgDirList[] = {"base", "global", "pg_xlog", "pg_tblspc"};
    char entryObsolutePath[MAX_PATH_LEN];
    char entryObsoluteRealPath[MAX_PATH_LEN];
    char pgTblspcObsolutePath[MAX_PATH_LEN];
    int rc = 0;

    for (unsigned i = 0; i < sizeof(pgDirList) / sizeof(pgDirList[0]); i++) {
        rc = memset_s(entryObsolutePath, MAX_PATH_LEN, 0, MAX_PATH_LEN);
        securec_check_errno(rc, (void) rc);
        rc = memset_s(entryObsoluteRealPath, MAX_PATH_LEN, 0, MAX_PATH_LEN);
        securec_check_errno(rc, (void) rc);
        snprintf_s(entryObsolutePath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/%s", pathName, pgDirList[i]);
        int size = readlink(entryObsolutePath, entryObsoluteRealPath, MAX_PATH_LEN - 1);
        if (size > 0) {
            for (unsigned ii = maxPartitionLen -1; ii < strlen(entryObsoluteRealPath); ii++) {
                if (entryObsoluteRealPath[ii] == '/') {
                    entryObsoluteRealPath[ii] = '\0';
                }
            }
            v_linkPathInfo.push_back(entryObsoluteRealPath);
        }
    }

    rc = memset_s(pgTblspcObsolutePath, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void) rc);
    snprintf_s(pgTblspcObsolutePath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/%s", pathName, "pg_tblspc");
    DIR *dir;
    struct dirent *entry;

    if ((dir = opendir(pgTblspcObsolutePath)) == nullptr) {
        return GetMaxPercentFromDirList(v_linkPathInfo);
    }

    while ((entry = readdir(dir)) != nullptr) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        rc = memset_s(entryObsolutePath, MAX_PATH_LEN, 0, MAX_PATH_LEN);
        securec_check_errno(rc, (void) rc);
        rc = memset_s(entryObsoluteRealPath, MAX_PATH_LEN, 0, MAX_PATH_LEN);
        securec_check_errno(rc, (void) rc);
        if (entry->d_type == DT_LNK) {
            snprintf_s(entryObsolutePath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/%s", pgTblspcObsolutePath,
                       entry->d_name);
            int size = readlink(entryObsolutePath, entryObsoluteRealPath, MAX_PATH_LEN - 1);
            if (size > 0) {
                for (unsigned i = maxPartitionLen -1; i < strlen(entryObsoluteRealPath); i++) {
                    if (entryObsoluteRealPath[i] == '/'){
                        entryObsoluteRealPath[i] = '\0';
                    }
                }
                v_linkPathInfo.push_back(entryObsoluteRealPath);
            }
        }
    }

    (void)closedir(dir);

    v_linkPathInfo.erase(unique(v_linkPathInfo.begin(), v_linkPathInfo.end()), v_linkPathInfo.end());
    return GetMaxPercentFromDirList(v_linkPathInfo);
}

bool IsLinkPathDestroyedOrDamaged(const char *pathName)
{
    const char *pgDirList[] = {"base", "global", "pg_xlog"};
    char entryAbsolutePath[MAX_PATH_LEN];
    char pgTblspcAbsolutePath[MAX_PATH_LEN];
    errno_t rc = 0;
    bool cdt;

    for (unsigned i = 0; i < sizeof(pgDirList) / sizeof(pgDirList[0]); i++) {
        rc = memset_s(entryAbsolutePath, MAX_PATH_LEN, 0, MAX_PATH_LEN);
        securec_check_errno(rc, (void) rc);
        rc = snprintf_s(entryAbsolutePath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/%s", pathName, pgDirList[i]);
        securec_check_intval(rc, (void)rc);
        cdt = IsDirectoryDestroyed(entryAbsolutePath) || !agentCheckDisc(entryAbsolutePath);
        if (cdt) {
            write_runlog(ERROR, "disc writable test failed, %s.\n", entryAbsolutePath);
            return true;
        }
    }

    rc = memset_s(pgTblspcAbsolutePath, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void) rc);
    rc = snprintf_s(pgTblspcAbsolutePath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/%s", pathName, "pg_tblspc");
    securec_check_intval(rc, (void)rc);
    DIR *dir;
    struct dirent *entry;

    if ((dir = opendir(pgTblspcAbsolutePath)) == nullptr) {
        write_runlog(ERROR, "disc writable test failed, %s.\n", pgTblspcAbsolutePath);
        return true;
    }
    while ((entry = readdir(dir)) != nullptr) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        rc = memset_s(entryAbsolutePath, MAX_PATH_LEN, 0, MAX_PATH_LEN);
        securec_check_errno(rc, (void) rc);

        if (entry->d_type == DT_LNK) {
            rc = snprintf_s(entryAbsolutePath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/%s",
                pgTblspcAbsolutePath, entry->d_name);
            securec_check_intval(rc, (void)rc);
            cdt = IsDirectoryDestroyed(entryAbsolutePath) || !agentCheckDisc(entryAbsolutePath);
            if (cdt) {
                write_runlog(ERROR, "disc writable test failed, %s.\n", entryAbsolutePath);
                (void)closedir(dir);
                return true;
            }
        }
    }
    (void)closedir(dir);
    return false;
}

void *DiskUsageCheckMain(void *arg)
{
    thread_name = "DiskUsageCheck";
    pthread_t threadId = pthread_self();
    write_runlog(LOG, "Disk usage check thread start, threadid %lu.\n", threadId);

    for (;;) {
        if (g_shutdownRequest) {
            cm_sleep(5);
            continue;
        }
#ifdef ENABLE_MULTIPLE_NODES
        CheckDiskForCNDataPath();
#endif
        CheckDiskForDNDataPath();
        cm_sleep(1);
    }
    return NULL;
}

void *PGControlDataCheckMain(void *arg)
{
    thread_name = "PGDataControlCheck";
    pthread_t threadId = pthread_self();
    write_runlog(LOG, "PG Control Data check thread start, threadid %lu.\n", threadId);

    for (;;) {
        if (g_shutdownRequest || !g_isStorageWithDMSorDSS) {
            cm_sleep(5);
            continue;
        }
        PGDataControlCheck();
        cm_sleep(1);
    }
    return NULL;
}

bool FindDnIdxInCurNode(uint32 instId, uint32 *dnIdx, const char *str)
{
    for (uint32 i = 0; i < g_currentNode->datanodeCount; ++i) {
        if (g_currentNode->datanode[i].datanodeId == instId) {
            *dnIdx = i;
            return true;
        }
    }
    write_runlog(ERROR, "%s cannot find the instId(%u) in current node.\n", str, instId);
    return false;
}

CmResConfList *CmaGetResConfByResName(const char *resName)
{
    for (uint32 i = 0; i < GetLocalResConfCount(); ++i) {
        if (strcmp(g_resConf[i].resName, resName) == 0) {
            return &g_resConf[i];
        }
    }
    write_runlog(ERROR, "in local res conf, can't find res(%s).\n", resName);
    return NULL;
}

static void GetParameterValueFromConfigFile(const char* file_path, const char* paraName)
{
    char get_cmd[MAXPGPATH * 2];
    char result[NAMEDATALEN] = {0};
    int retry_cnt = 0;

    int ret = snprintf_s(get_cmd,
        sizeof(get_cmd),
        MAXPGPATH * 2 - 1,
        "grep \"^%s\" %s/postgresql.conf|awk -F= \'{print $2}\'|tail -1|grep -o \"[[:alnum:]]*\"",
        paraName,
        file_path);
    securec_check_intval(ret, (void)ret);

    while (retry_cnt < MAX_RETRY_TIME) {
        if (!ExecuteCmdWithResult(get_cmd, result, NAMEDATALEN)) {
            retry_cnt++;
            continue;
        }
        result[strlen(result) - 1] = '\0';
        write_runlog(LOG, "Get value of %s: %s\n", paraName, result);
        if (strcmp(result, "on") == 0 || strcmp(result, "true") == 0 || strcmp(result, "1") == 0 ||
            strcmp(result, "ON") == 0 || strcmp(result, "TRUE") == 0) {
            /*
             * The bit of g_onDemandRealTimeBuildStatus means:
             *|Get By SQL | Get By File | Value|
             *|0x    0    |      0      |  0   |
             */
            g_onDemandRealTimeBuildStatus |= 0x3;
            return;
        } else {
            g_onDemandRealTimeBuildStatus |= 0x2;
            return;
        }
    }

    write_runlog(LOG, "The parameter %s is not found, use the default\n", paraName);
    return;
}

void check_datanode_realtime_build_status_by_file(agent_to_cm_datanode_status_report *reportMsg, const char *dataPath)
{
    if (g_onDemandRealTimeBuildStatus & 0x2) {
        return;
    }

    const char* paraName = "ss_enable_ondemand_realtime_build";
    GetParameterValueFromConfigFile(dataPath, paraName);
    write_runlog(LOG, "ondemand_realtime_build_status by file is %d\n", g_onDemandRealTimeBuildStatus);
    reportMsg->local_status.realtime_build_status = (g_onDemandRealTimeBuildStatus & 0x1);
}