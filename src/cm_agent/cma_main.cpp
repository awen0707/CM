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
 * cma_main.cpp
 *    cma main file
 *
 * IDENTIFICATION
 *    src/cm_agent/cma_main.cpp
 *
 * -------------------------------------------------------------------------
 */
#include <sys/wait.h>
#include <sys/procfs.h>
#include <sys/file.h>
#ifdef __aarch64__
#include <sys/sysinfo.h>
#endif
#include "cm_cipher.h"
#include "alarm/alarm_log.h"
#include "cm/pqsignal.h"
#include "cm_json_config.h"
#include "cm_ip.h"
#include "cma_global_params.h"
#include "cma_common.h"
#include "cma_threads.h"
#include "cma_client.h"
#include "cma_datanode_scaling.h"
#include "cma_log_management.h"
#include "cma_instance_management.h"
#include "cma_instance_management_res.h"
#include "config.h"
#include "cma_process_messages.h"
#include "cm_util.h"
#include "cma_connect.h"
#include "cma_status_check.h"
#include "cma_mes.h"
#ifdef ENABLE_MULTIPLE_NODES
#include "cma_gtm.h"
#include "cma_coordinator.h"
#include "cma_cn_gtm_work_threads_mgr.h"
#include "cma_instance_check.h"
#endif

#ifndef ENABLE_MULTIPLE_NODES
const char *g_libnetManualStart = "libnet_manual_start";
#endif

cm_instance_central_node_msg g_ccnNotify;

char g_agentDataDir[CM_PATH_LENGTH] = {0};

static volatile sig_atomic_t g_gotParameterReload = 0;

int g_tcpKeepalivesIdle = 30;
int g_tcpKeepalivesInterval = 30;
int g_tcpKeepalivesCount = 3;

bool g_poolerPingEnd = false;
bool *g_coordinatorsDrop;
datanode_failover *g_datanodesFailover = NULL;
gtm_failover *g_gtmsFailover = NULL;

uint32 *g_droppedCoordinatorId = NULL;
coordinator_status *g_cnStatus = NULL;
uint32 g_cancelCoordinatorId = 0;
bool g_coordinatorsCancel;
pthread_rwlock_t g_datanodesFailoverLock;
pthread_rwlock_t g_gtmsFailoverLock;
pthread_rwlock_t g_cnDropLock;
pthread_rwlock_t g_coordinatorsCancelLock;

bool g_poolerPingEndRequest = false;

int g_gtmConnFailTimes = 0;
int g_cnConnFailTimes = 0;
int g_dnConnFailTimes[CM_MAX_DATANODE_PER_NODE] = {0};
char *g_eventTriggers[EVENT_COUNT] = {NULL};

static const uint32 MAX_MSG_BUF_POOL_SIZE = 102400;
static const uint32 MAX_MSG_BUF_POOL_COUNT = 200;
static const int32 INVALID_ID = -1;
/* unify log style */
void create_system_call_log(void);
int check_one_instance_status(const char *processName, const char *cmdLine, int *isPhonyDead);
int get_agent_global_params_from_configfile();

void stop_flag(void)
{
    g_exitFlag = true;
    cm_sleep(6);
}

void report_conn_fail_alarm(AlarmType alarmType, InstanceTypes instance_type, uint32 instanceId)
{
    int rc = 0;
    uint32 alarmIndex = 0;
    char instanceName[CM_NODE_NAME] = {0};
    if (instance_type == INSTANCE_CN) {
        if (alarmType == ALM_AT_Fault) {
            g_cnConnFailTimes++;
            if (g_cnConnFailTimes < CONN_FAIL_TIMES) {
                return;
            }
        } else {
            g_cnConnFailTimes = 0;
        }
        rc = check_one_instance_status(type_int_to_str_binname(instance_type), g_currentNode->DataPath, NULL);
        if (rc != PROCESS_RUNNING) {
            return;
        }
        alarmIndex = g_currentNode->datanodeCount;
        rc = snprintf_s(instanceName, sizeof(instanceName), sizeof(instanceName) - 1, "cn_%u", instanceId);
    } else if (instance_type == INSTANCE_DN) {
        for (uint32 ii = 0; ii < g_currentNode->datanodeCount; ii++) {
            if (g_currentNode->datanode[ii].datanodeId == instanceId) {
                if (alarmType == ALM_AT_Fault) {
                    g_dnConnFailTimes[ii]++;
                    if (g_dnConnFailTimes[ii] < CONN_FAIL_TIMES) {
                        return;
                    }
                } else {
                    g_dnConnFailTimes[ii] = 0;
                }
                rc = check_one_instance_status(
                    type_int_to_str_binname(instance_type), g_currentNode->datanode[ii].datanodeLocalDataPath, NULL);
                alarmIndex = ii;
                break;
            }
        }
        if (rc != PROCESS_RUNNING) {
            return;
        }
        rc = snprintf_s(instanceName, sizeof(instanceName), sizeof(instanceName) - 1, "dn_%u", instanceId);
    } else if (instance_type == INSTANCE_GTM) {
        if (alarmType == ALM_AT_Fault) {
            g_gtmConnFailTimes++;
            if (g_gtmConnFailTimes < CONN_FAIL_TIMES) {
                return;
            }
        } else {
            g_gtmConnFailTimes = 0;
        }
        rc = check_one_instance_status(type_int_to_str_binname(instance_type), g_currentNode->gtmLocalDataPath, NULL);
        if (rc != PROCESS_RUNNING) {
            return;
        }
        rc = snprintf_s(instanceName, sizeof(instanceName), sizeof(instanceName) - 1, "gtm_%u", instanceId);
        alarmIndex = g_currentNode->datanodeCount + g_currentNode->coordinate;
    } else {
        /* do nothing. */
    }
    securec_check_intval(rc, (void)rc);

    AlarmAdditionalParam tempAdditionalParam;
    /* fill the alarm message. */
    WriteAlarmAdditionalInfo(&tempAdditionalParam, instanceName, "", "", "", &(g_abnormalCmaConnAlarmList[alarmIndex]),
        alarmType, instanceName);
    /* report the alarm. */
    AlarmReporter(&(g_abnormalCmaConnAlarmList[alarmIndex]), alarmType, &tempAdditionalParam);
}

uint32 GetThreadDeadEffectiveTime(size_t threadIdx)
{
    const int specialEffectiveTime = 10;
    if (g_threadName[threadIdx] != NULL && strcmp(g_threadName[threadIdx], "SendCmsMsg") == 0) {
        return specialEffectiveTime;
    }
    return g_threadDeadEffectiveTime;
}

void check_thread_state()
{
    size_t length = sizeof(g_threadId) / sizeof(g_threadId[0]);
    struct timespec now = {0};

    (void)clock_gettime(CLOCK_MONOTONIC, &now);
    for (size_t i = 0; i < length; i++) {
        if (g_threadId[i] == 0) {
            continue;
        }
        uint32 threadDeadEffectiveTime = GetThreadDeadEffectiveTime(i);
        if ((now.tv_sec - g_thread_state[i] < 0) || (now.tv_sec - g_thread_state[i] > 4 * threadDeadEffectiveTime)) {
            g_thread_state[i] = now.tv_sec;
            continue;
        }
        if ((now.tv_sec - g_thread_state[i] > threadDeadEffectiveTime) && g_thread_state[i] != 0) {
            write_runlog(FATAL, "the thread(%lu) is not execing for a long time(%ld).\n",
                g_threadId[i], now.tv_sec - g_thread_state[i]);
            /* progress abort */
            exit(-1);
        }
    }
}

void reload_cmagent_parameters(int arg)
{
    g_gotParameterReload = 1;
}

void RecvSigusrSingle(int arg)
{
    return;
}

#ifdef ENABLE_MULTIPLE_NODES
void SetFlagToUpdatePortForCnDn(int arg)
{
    cm_agent_need_check_libcomm_port = true;
}
#endif
void GetCmdlineOpt(int argc, char *argv[])
{
    long logChoice = 0;
    const int base = 10;

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

/* unify log style */
void create_system_call_log(void)
{
    DIR *dir;
    struct dirent *de;
    bool is_exist = false;

    /* check validity of current log file name */
    char *name_ptr = NULL;
    errno_t rc;
    int rcs;
    if ((dir = opendir(sys_log_path)) == NULL) {
        write_runlog(ERROR, "%s: opendir %s failed! \n", prefix_name, sys_log_path);
        rcs = snprintf_s(system_call_log, MAXPGPATH, MAXPGPATH - 1, "%s", "/dev/null");
        securec_check_intval(rcs, (void)rcs);
        return;
    }
    while ((de = readdir(dir)) != NULL) {
        /* exist current log file */
        if (strstr(de->d_name, SYSTEM_CALL_LOG) == NULL) {
            continue;
        }
        name_ptr = strstr(de->d_name, "-current.log");
        if (name_ptr == NULL) {
            continue;
        }
        name_ptr += strlen("-current.log");
        if ((*name_ptr) == '\0') {
            is_exist = true;
            break;
        }
    }

    rc = memset_s(g_systemCallLogName, MAXPGPATH, 0, MAXPGPATH);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(system_call_log, MAXPGPATH, 0, MAXPGPATH);
    securec_check_errno(rc, (void)rc);
    rcs = snprintf_s(g_systemCallLogName, MAXPGPATH, MAXPGPATH - 1, "%s%s", SYSTEM_CALL_LOG, curLogFileMark);
    securec_check_intval(rcs, (void)rcs);
    rcs = snprintf_s(system_call_log, MAXPGPATH, MAXPGPATH - 1, "%s/%s", sys_log_path, g_systemCallLogName);
    securec_check_intval(rcs, (void)rcs);
    /* current system_call_log name must be system_call-current.log */
    if (is_exist && strstr(de->d_name, "system_call-current") == NULL) {
        char oldSystemCallLog[MAXPGPATH] = {0};
        rcs = snprintf_s(oldSystemCallLog, MAXPGPATH, MAXPGPATH - 1, "%s/%s", sys_log_path, de->d_name);
        securec_check_intval(rcs, (void)rcs);
        rcs = rename(oldSystemCallLog, system_call_log);
        if (rcs != 0) {
            write_runlog(ERROR, "%s: rename log file %s failed! \n", prefix_name, oldSystemCallLog);
        }
    }
    (void)closedir(dir);
    (void)chmod(system_call_log, S_IRUSR | S_IWUSR);
}

status_t CreateSysLogFile(void)
{
    if (syslogFile != NULL) {
        (void)fclose(syslogFile);
        syslogFile = NULL;
    }
    syslogFile = logfile_open(sys_log_path, "a");
    if (syslogFile == NULL) {
        (void)fprintf(stderr, "cma_main, open log file failed\n");
    }

    int fd = open("/dev/null", O_RDWR);
    if (fd < 0) {
        (void)fprintf(stderr, "FATAL cma_main, open /dev/null failed, cma will exit.\n");
        return CM_ERROR;
    }
    /* Redirect the handle to /dev/null, which is inherited from the om_monitor. */
    (void)dup2(fd, STDOUT_FILENO);
    (void)dup2(fd, STDERR_FILENO);
    if (fd > STDERR_FILENO) {
        (void)close(fd);
    }
    return CM_SUCCESS;
}

static void InitClientCrt(const char *appPath)
{
    errno_t rcs =
        snprintf_s(g_tlsPath.caFile, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/share/sslcert/etcd/etcdca.crt", appPath);
    securec_check_intval(rcs, (void)rcs);
    rcs = snprintf_s(
        g_tlsPath.crtFile, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/share/sslcert/etcd/client.crt", appPath);
    securec_check_intval(rcs, (void)rcs);
    rcs = snprintf_s(
        g_tlsPath.keyFile, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/share/sslcert/etcd/client.key", appPath);
    securec_check_intval(rcs, (void)rcs);
}

int get_prog_path()
{
    char exec_path[MAX_PATH_LEN] = {0};
    errno_t rc;
    int rcs;

    rc = memset_s(g_cmAgentLogPath, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(g_cmStaticConfigurePath, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(g_cmManualStartPath, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(g_cmInstanceManualStartPath, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(g_cmEtcdManualStartPath, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(g_cmResumingCnStopPath, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(g_tlsPath.caFile, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(g_tlsPath.crtFile, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(g_tlsPath.keyFile, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(g_cmClusterResizePath, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(g_cmClusterReplacePath, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(instance_maintance_path, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
#ifndef ENABLE_MULTIPLE_NODES
    rc = memset_s(g_cmLibnetManualStartPath, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
#endif
    rc = memset_s(g_autoRepairPath, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(g_cmManualPausePath, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(g_cmManualStartingPath, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    if (GetHomePath(exec_path, sizeof(exec_path)) != 0) {
        (void)fprintf(stderr, "Get GAUSSHOME failed, please check.\n");
        return -1;
    } else {
        check_input_for_security(exec_path);
        /* g_logicClusterListPath */
        rcs = snprintf_s(
            g_logicClusterListPath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/%s", exec_path, LOGIC_CLUSTER_LIST);
        securec_check_intval(rcs, (void)rcs);
        rcs = snprintf_s(result_path, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/%s", exec_path, STOP_PRIMARY_RESULT);
        securec_check_intval(rcs, (void)rcs);
        canonicalize_path(result_path);
        rcs = snprintf_s(
            g_cmStaticConfigurePath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/%s", exec_path, CM_STATIC_CONFIG_FILE);
        securec_check_intval(rcs, (void)rcs);
        rcs = snprintf_s(
            g_cmManualStartPath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/%s", exec_path, CM_CLUSTER_MANUAL_START);
        securec_check_intval(rcs, (void)rcs);
        rcs = snprintf_s(
            g_cmResumingCnStopPath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/%s", exec_path, CM_RESUMING_CN_STOP);
        securec_check_intval(rcs, (void)rcs);
        rcs = snprintf_s(g_cmInstanceManualStartPath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/%s",
            exec_path, CM_INSTANCE_MANUAL_START);
        securec_check_intval(rcs, (void)rcs);
        rcs = snprintf_s(
            g_cmEtcdManualStartPath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/%s", exec_path, CM_ETCD_MANUAL_START);
        securec_check_intval(rcs, (void)rcs);
        rcs = snprintf_s(g_binPath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin", exec_path);
        securec_check_intval(rcs, (void)rcs);
        rcs = snprintf_s(
            g_cmClusterResizePath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/%s", exec_path, CM_CLUSTER_RESIZE);
        securec_check_intval(rcs, (void)rcs);
        rcs = snprintf_s(
            g_cmClusterReplacePath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/%s", exec_path, CM_CLUSTER_REPLACE);
        securec_check_intval(rcs, (void)rcs);
        rc = snprintf_s(g_cmagentLockfile, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/cm_agent.lock", exec_path);
        securec_check_intval(rc, (void)rc);
        canonicalize_path(g_cmagentLockfile);
        rcs = snprintf_s(
            instance_maintance_path, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/%s", exec_path, INSTANCE_MAINTANCE);
        securec_check_intval(rcs, (void)rcs);
        canonicalize_path(instance_maintance_path);
#ifndef ENABLE_MULTIPLE_NODES
        rcs = snprintf_s(
            g_cmLibnetManualStartPath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/%s", exec_path, g_libnetManualStart);
        securec_check_intval(rcs, (void)rcs);
#endif
        rcs = snprintf_s(g_autoRepairPath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/stop_auto_repair", exec_path);
        securec_check_intval(rcs, (void)rcs);
        rcs = snprintf_s(
            g_cmManualPausePath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/%s", exec_path, CM_CLUSTER_MANUAL_PAUSE);
        securec_check_intval(rcs, (void)rcs);
        rcs = snprintf_s(
            g_cmManualStartingPath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/%s", exec_path, CM_CLUSTER_MANUAL_STARTING);
        securec_check_intval(rcs, (void)rcs);
        InitClientCrt(exec_path);
    }

    return 0;
}

static void SetCmsIndexStr(char *cmServerIdxStr, uint32 strLen, uint32 cmServerIdx, uint32 nodeIdx)
{
    char cmServerStr[MAX_PATH_LEN];
    errno_t rc = snprintf_s(cmServerStr, MAX_PATH_LEN, MAX_PATH_LEN - 1,
        "[%u node:%u, cmserverId:%u, cmServerIndex:%u], ",
        cmServerIdx, g_node[nodeIdx].node, g_node[nodeIdx].cmServerId, nodeIdx);
    securec_check_intval(rc, (void)rc);
    rc = strcat_s(cmServerIdxStr, strLen, cmServerStr);
    securec_check_errno(rc, (void)rc);
}

static void initialize_cm_server_node_index(void)
{
    uint32 i = 0;
    uint32 j = 0;
    char cmServerIdxStr[MAX_PATH_LEN] = {0};
    uint32 cm_instance_id[CM_PRIMARY_STANDBY_NUM] = {0};
    uint32 cmServerNum = 0;
    /* get cmserver instance id */
    for (i = 0; i < g_node_num; i++) {
        if (g_node[i].cmServerLevel == 1) {
            cm_instance_id[j] = g_node[i].cmServerId;
            j++;
            cmServerNum++;
        }
    }
#undef qsort
    qsort(cm_instance_id, cmServerNum, sizeof(uint32), node_index_Comparator);

    j = 0;
    for (uint32 k = 0; k < cmServerNum; k++) {
        for (i = 0; i < g_node_num; i++) {
            if (cm_instance_id[k] != g_node[i].cmServerId) {
                continue;
            }
            g_nodeIndexForCmServer[j] = i;
            SetCmsIndexStr(cmServerIdxStr, MAX_PATH_LEN, j, i);
            j++;
            break;
        }
    }
    (void)fprintf(stderr, "[%s]: cmserverNum is %u, and cmserver info is %s.\n",
        g_progname, cmServerNum, cmServerIdxStr);
}

int countCnAndDn()
{
    uint32 j = 0;
    uint32 cn = 0;
    uint32 dnPairs = 0;

    for (uint32 i = 0; i < g_node_num; i++) {
        if (g_node[i].coordinate == 1) {
            cn++;
        }
        if (g_multi_az_cluster) {
            dnPairs = dnPairs + g_node[i].datanodeCount;
        } else {
            for (j = 0; j < g_node[i].datanodeCount; j++) {
                if (g_node[i].datanode[j].datanodeRole == PRIMARY_DN) {
                    dnPairs++;
                }
            }
        }
    }

    return (int)(cn + dnPairs);
}

int read_config_file_check(void)
{
    int status;
    int err_no = 0;
    int rc;

    if (!g_cmAgentFirstStart && (g_node != NULL)) {
        return 0;
    }

    status = read_config_file(g_cmStaticConfigurePath, &err_no);
    if (status == 0) {
        if (g_nodeHeader.node == 0) {
            (void)fprintf(stderr, "current node self is invalid  node =%u\n", g_nodeHeader.node);
            return -1;
        }

        g_cmAgentFirstStart = false;

        rc = find_node_index_by_nodeid(g_nodeHeader.node, &g_nodeId);
        if (rc != 0) {
            (void)fprintf(stderr, "find_node_index_by_nodeid failed, nodeId=%u.\n", g_nodeHeader.node);
            return -1;
        }

        rc = find_current_node_by_nodeid();
        if (rc != 0) {
            (void)fprintf(stderr, "find_current_node_by_nodeid failed, nodeId=%u.\n", g_nodeHeader.node);
            return -1;
        }

        g_cmStaticConfigNeedVerifyToCn = true;

        g_cnDnPairsCount = countCnAndDn();

        initialize_cm_server_node_index();
        int family = GetIpVersion(g_currentNode->sshChannel[0]);
        if (family != AF_INET && family != AF_INET6) {
            (void)fprintf(stderr, "ip(%s) is invalid, nodeId=%u.\n", g_currentNode->sshChannel[0], g_nodeHeader.node);
            return -1;
        }
        rc = snprintf_s(g_cmAgentLogPath,
            MAX_PATH_LEN,
            MAX_PATH_LEN - 1,
            "%s/%s/%s",
            g_currentNode->cmDataPath,
            CM_AGENT_DATA_DIR,
            CM_AGENT_LOG_FILE);
        securec_check_intval(rc, (void)rc);

        g_datanodesFailover = (datanode_failover *)malloc(sizeof(datanode_failover) * g_node_num);
        if (g_datanodesFailover == NULL) {
            (void)fprintf(stderr, "g_datanodesFailover: out of memory\n");
            return -1;
        }

        rc = memset_s(
            g_datanodesFailover, sizeof(datanode_failover) * g_node_num, 0, sizeof(datanode_failover) * g_node_num);
        securec_check_errno(rc, FREE_AND_RESET(g_datanodesFailover));

        g_gtmsFailover = (gtm_failover *)malloc(sizeof(gtm_failover) * g_node_num);
        if (g_gtmsFailover == NULL) {
            (void)fprintf(stderr, "g_gtmsFailover: out of memory\n");
            return -1;
        }

        rc = memset_s(g_gtmsFailover, sizeof(gtm_failover) * g_node_num, 0, sizeof(gtm_failover) * g_node_num);
        securec_check_errno(rc, FREE_AND_RESET(g_gtmsFailover));

        g_coordinatorsDrop = (bool *)malloc(sizeof(bool) * g_node_num);
        if (g_coordinatorsDrop == NULL) {
            (void)fprintf(stderr, "g_coordinatorsDrop: out of memory\n");
            return -1;
        }

        rc = memset_s(g_coordinatorsDrop, sizeof(bool) * g_node_num, 0, sizeof(bool) * g_node_num);
        securec_check_errno(rc, FREE_AND_RESET(g_coordinatorsDrop));

        g_droppedCoordinatorId = (uint32 *)malloc(sizeof(uint32) * g_node_num);
        if (g_droppedCoordinatorId == NULL) {
            (void)fprintf(stderr, "g_droppedCoordinatorId: out of memory\n");
            return -1;
        }

        rc = memset_s(g_droppedCoordinatorId, sizeof(uint32) * g_node_num, 0, sizeof(uint32) * g_node_num);
        securec_check_errno(rc, FREE_AND_RESET(g_droppedCoordinatorId));

        g_cnStatus = (coordinator_status *)malloc(sizeof(coordinator_status) * g_node_num);
        if (g_cnStatus == NULL) {
            (void)fprintf(stderr, "g_droppedCoordinatorId: out of memory\n");
            return -1;
        }
        rc = memset_s(g_cnStatus, sizeof(coordinator_status) * g_node_num, 0, sizeof(coordinator_status) * g_node_num);
        securec_check_errno(rc, FREE_AND_RESET(g_cnStatus));

        (void)pthread_rwlock_init(&g_datanodesFailoverLock, NULL);
        (void)pthread_rwlock_init(&g_cnDropLock, NULL);
        (void)pthread_rwlock_init(&g_coordinatorsCancelLock, NULL);
        (void)pthread_rwlock_init(&g_gtmsFailoverLock, NULL);
    } else if (status == OUT_OF_MEMORY) {
        (void)fprintf(stderr, "read staticNodeConfig failed! out of memory\n");
        return -1;
    } else {
        (void)fprintf(stderr, "read staticNodeConfig failed! errno = %d\n", err_no);
        return -1;
    }

    if (access(g_logicClusterListPath, F_OK) == 0) {
        status = read_logic_cluster_config_files(g_logicClusterListPath, &err_no);
        char errBuffer[ERROR_LIMIT_LEN] = {0};
        switch (status) {
            case OPEN_FILE_ERROR: {
                write_runlog(FATAL,
                    "%s: could not open the logic cluster static config file: %s\n",
                    g_progname,
                    strerror_r(err_no, errBuffer, ERROR_LIMIT_LEN));
                exit(1);
            }
            case READ_FILE_ERROR: {
                char errBuff[ERROR_LIMIT_LEN];
                write_runlog(FATAL,
                    "%s: could not read logic cluster static config files: %s\n",
                    g_progname,
                    strerror_r(err_no, errBuff, ERROR_LIMIT_LEN));
                exit(1);
            }
            case OUT_OF_MEMORY:
                write_runlog(FATAL, "%s: out of memory\n", g_progname);
                exit(1);
            default:
                break;
        }
    }

    return 0;
}

int node_match_find(const char *node_type, const char *node_port, const char *node_host, const char *node_port1,
    const char *node_host1, int *node_index, int *instance_index, int *inode_type)
{
    uint32 i;
    uint32 j = 0;

    *node_index = 0;
    *instance_index = 0;

    if (*node_type == 'C') {
        for (i = 0; i < g_node_num; i++) {
            if (g_node[i].coordinate == 1) {
                if ((g_node[i].coordinatePort == (uint32)strtol(node_port, NULL, 10)) &&
                    (strncmp(g_node[i].coordinateListenIP[0], node_host, CM_IP_ALL_NUM_LENGTH) == 0)) {
                    *inode_type = CM_COORDINATENODE;
                    *node_index = (int)i;
                    *instance_index = (int)j;
                    return 0;
                }
            }
        }
    } else if (*node_type == 'D' || *node_type == 'S') {
        for (i = 0; i < g_node_num; i++) {
            for (j = 0; j < g_node[i].datanodeCount; j++) {
                if ((g_node[i].datanode[j].datanodePort == (uint32)strtol(node_port, NULL, 10)) &&
                    (strncmp(g_node[i].datanode[j].datanodeListenIP[0], node_host, CM_IP_ALL_NUM_LENGTH) == 0)) {
                    *inode_type = CM_DATANODE;
                    *node_index = (int)i;
                    *instance_index = (int)j;
                    return 0;
                }
            }
        }
    } else {
        write_runlog(ERROR, "node_type is invalid node_type =%s, node1 is %s:%s, node_host1\n",
            node_type, node_host1, node_port1);
    }
    return -1;
}

static bool ModifyDatanodePort(const char *Keywords, uint32 value, const char *file_path)
{
    char modify_cmd[MAXPGPATH * 2];
    char fsync_cmd[MAXPGPATH * 2];
    char check_cmd[MAXPGPATH * 2];
    char result[NAMEDATALEN];
    int ret;
    int retry = 0;

    struct timeval timeOut = {0};
    timeOut.tv_sec = 10;
    timeOut.tv_usec = 0;

    ret = snprintf_s(modify_cmd,
        sizeof(modify_cmd),
        MAXPGPATH * 2 - 1,
        "sed -i \"/^#%s =/c\\%s = %u\"   %s/postgresql.conf",
        Keywords,
        Keywords,
        value,
        file_path);
    securec_check_intval(ret, (void)ret);

    ret = snprintf_s(fsync_cmd, sizeof(fsync_cmd), MAXPGPATH * 2 - 1, "fsync %s/postgresql.conf", file_path);
    securec_check_intval(ret, (void)ret);

    ret = snprintf_s(check_cmd,
        sizeof(check_cmd),
        MAXPGPATH * 2 - 1,
        "grep \"^%s = %u\" %s/postgresql.conf|wc -l",
        Keywords,
        value,
        file_path);
    securec_check_intval(ret, (void)ret);

    while (retry < MAX_RETRY_TIME) {
        ret = ExecuteCmd(modify_cmd, timeOut);
        write_runlog(LOG, "update %s/postgresql.conf command:%s\n", file_path, modify_cmd);
        if (ret != 0) {
            write_runlog(WARNING, "update %s/postgresql.conf failed!%d! %s \n", file_path, ret, modify_cmd);
            retry++;
            continue;
        }

        ret = ExecuteCmd(fsync_cmd, timeOut);
        write_runlog(LOG, "fsync %s/postgresql.conf command:%s\n", file_path, fsync_cmd);
        if (ret != 0) {
            write_runlog(WARNING, "fsync %s/postgresql.conf failed!%d! %s \n", file_path, ret, fsync_cmd);
            retry++;
            continue;
        }

        /* check modify is really effective */
        if (!ExecuteCmdWithResult(check_cmd, result, NAMEDATALEN)) {
            write_runlog(ERROR, "check %s failed, command:%s, errno[%d].\n", Keywords, check_cmd, errno);
            retry++;
            continue;
        }
        write_runlog(LOG, "check %s, command:%s\n", Keywords, check_cmd);

        if (strtol(result, NULL, 10) != 1) {
            write_runlog(WARNING, "update %s failed, retry it:%s\n", Keywords, modify_cmd);
            retry++;
            continue;
        }

        write_runlog(LOG, "update %s succeed:%s\n", Keywords, modify_cmd);
        return true;
    }
    write_runlog(ERROR, "update %s failed final:%s\n", Keywords, modify_cmd);
    return false;
}

static bool UpdateLibcommPort(const char *file_path, const char *port_name, uint32 port)
{
    int ret;
    char cmd_buf[MAXPGPATH * 2];
    char result[NAMEDATALEN] = {0};
    long need_update;

    ret = snprintf_s(cmd_buf, sizeof(cmd_buf), MAXPGPATH * 2 - 1, "%s/postgresql.conf", file_path);
    securec_check_intval(ret, (void)ret);

    /*
     * if file not found, that means dn/cn was moved/lost,
     * we must return true, otherwise, cm_agent will try to visit the file again and again.
     */
    if (access(cmd_buf, F_OK) != 0) {
        write_runlog(ERROR, "file not found, instance maybe lost, command: %s, errno[%d].\n", cmd_buf, errno);
        return true;
    }

    /* printf old port */
    ret =
        snprintf_s(cmd_buf, sizeof(cmd_buf), MAXPGPATH * 2 - 1, "grep \"%s\" %s/postgresql.conf", port_name, file_path);
    securec_check_intval(ret, (void)ret);
    if (!ExecuteCmdWithResult(cmd_buf, result, NAMEDATALEN)) {
        write_runlog(ERROR, "update failed, command: %s, errno[%d].\n", cmd_buf, errno);
        return false;
    }
    write_runlog(LOG, "command: %s, result: %s\n", cmd_buf, result);

    /* check this need update */
    ret = snprintf_s(
        cmd_buf, sizeof(cmd_buf), MAXPGPATH * 2 - 1, "grep \"#%s\" %s/postgresql.conf|wc -l", port_name, file_path);
    securec_check_intval(ret, (void)ret);
    if (!ExecuteCmdWithResult(cmd_buf, result, NAMEDATALEN)) {
        write_runlog(ERROR, "update failed, command: %s, errno[%d].\n", cmd_buf, errno);
        return false;
    }
    write_runlog(LOG, "command: %s, result: %s\n", cmd_buf, result);

    need_update = strtol(result, NULL, 10);
    if (need_update == 1) {
        g_cmAgentNeedAlterPgxcNode = true;
        return ModifyDatanodePort(port_name, port, file_path);
    }

    return true;
}

bool UpdateLibcommConfig(void)
{
    uint32 j;
    uint32 libcomm_sctp_port = 0;
    uint32 libcomm_ctrl_port = 0;
    bool re = false;
    bool result = true;

    if (g_currentNode->coordinate == 1) {
        libcomm_sctp_port = GetLibcommPort(g_currentNode->DataPath, g_currentNode->coordinatePort, COMM_PORT_TYPE_DATA);
        re = UpdateLibcommPort(g_currentNode->DataPath, "comm_sctp_port", libcomm_sctp_port);
        if (!re) {
            result = false;
        }
        libcomm_ctrl_port = GetLibcommPort(g_currentNode->DataPath, g_currentNode->coordinatePort, COMM_PORT_TYPE_CTRL);
        re = UpdateLibcommPort(g_currentNode->DataPath, "comm_control_port", libcomm_ctrl_port);
        if (!re) {
            result = false;
        }
    }

    for (j = 0; j < g_currentNode->datanodeCount; j++) {
        if (g_multi_az_cluster) {
            /*
             * In primary multiple standby cluster,
             * the DN port comm_sctp_port and comm_comtrol_port
             * settings are the same as CN.
             */
            libcomm_sctp_port = (g_currentNode->datanode[j].datanodePort + 2);
            libcomm_ctrl_port = (g_currentNode->datanode[j].datanodePort + 3);
        } else {
            libcomm_sctp_port = (g_currentNode->datanode[j].datanodePort +
                                 GetDatanodeNumSort(g_currentNode, g_currentNode->datanode[j].datanodeRole) * 2);
            libcomm_ctrl_port = (g_currentNode->datanode[j].datanodePort +
                                 GetDatanodeNumSort(g_currentNode, g_currentNode->datanode[j].datanodeRole) * 2 + 1);
        }

        re = UpdateLibcommPort(g_currentNode->datanode[j].datanodeLocalDataPath, "comm_sctp_port", libcomm_sctp_port);
        if (!re) {
            result = false;
        }
        re =
            UpdateLibcommPort(g_currentNode->datanode[j].datanodeLocalDataPath, "comm_control_port", libcomm_ctrl_port);
        if (!re) {
            result = false;
        }
    }

    return result;
}

bool Is_cn_replacing()
{
    struct stat stat_buf = {0};
    char instance_replace[MAX_PATH_LEN] = {0};

    int rc = snprintf_s(instance_replace,
        MAX_PATH_LEN,
        MAX_PATH_LEN - 1,
        "%s/%s_%u",
        g_binPath,
        CM_INSTANCE_REPLACE,
        g_currentNode->coordinateId);
    securec_check_intval(rc, (void)rc);

    int state_cn_replace = stat(instance_replace, &stat_buf);
    return (state_cn_replace == 0) ? true : false;
}

uint32 cm_get_first_cn_node()
{
    /* get update SQL */
    for (int32 nodeidx = 0; nodeidx < (int)g_node_num; nodeidx++) {
        if (g_node[nodeidx].coordinate == 1) {
            return g_node[nodeidx].node;
        }
    }
    return 0;
}

#ifdef __aarch64__
/*
 * @Description: process bind cpu
 * @IN: instance_index, primary_dn_index, pid
 * @Return: void
 */
void process_bind_cpu(uint32 instance_index, uint32 primary_dn_index, pgpid_t pid)
{
    int ret;
    int rcs;
    bool dn_need_bind = true;
    bool datanode_is_primary = false;
    uint8 physical_cpu_num = (uint8)PHYSICAL_CPU_NUM;
    uint32 bind_start_cpu = 0;
    uint32 bind_end_cpu = 0;
    uint32 dn_res = g_datanode_primary_num % physical_cpu_num;
    char command[MAX_PATH_LEN] = {0};

    /* For those process_cpu_affinity is zero, do not taskset process */
    if (agent_process_cpu_affinity == 0) {
        return;
    }

    /* Calculate if current primary dn needs to be set */
    if (dn_res) {
        dn_need_bind = (primary_dn_index < (g_datanode_primary_num - dn_res));
    }

    datanode_is_primary =
        g_dn_report_msg_ok
            ? g_dnReportMsg[instance_index].dnStatus.reportMsg.local_status.local_role == INSTANCE_ROLE_PRIMARY
            : PRIMARY_DN == g_currentNode->datanode[instance_index].datanodeRole;

    /* For those belongs to primary dn, do taskset process */
    if (datanode_is_primary && dn_need_bind) {
        /*
         * 1. calculate start_core and end_core,
         * total_cpu_core_num / physical_cpu_num gets the cpu core num of a single physical cpu
         * primary_dn_index % physical_cpu_num gets the index of "socket_group"
         */
        bind_start_cpu = (primary_dn_index % physical_cpu_num) * (total_cpu_core_num / physical_cpu_num);
        bind_end_cpu = (primary_dn_index % physical_cpu_num + 1) * (total_cpu_core_num / physical_cpu_num) - 1;

        /* 2. build taskset cammand */
        rcs = snprintf_s(command, sizeof(command), sizeof(command) - 1,
            "taskset -pac %u-%u %ld 1>/dev/null",
            bind_start_cpu,
            bind_end_cpu,
            pid);
    } else {
        /*
         * For those not belongs to primary dn, do reset affinity process
         * 2. build taskset cammand to reset affinity
         */
        bind_start_cpu = 0;
        bind_end_cpu = total_cpu_core_num - 1;
        rcs = snprintf_s(command,
            sizeof(command),
            sizeof(command) - 1,
            "taskset -pac %u-%u %ld 1>/dev/null",
            bind_start_cpu,
            bind_end_cpu,
            pid);
    }

    securec_check_intval(rcs, (void)rcs);

    /* 3. exec taskset command */
    ret = system(command);
    if (ret != 0) {
        write_runlog(ERROR, "run system command failed %d! %s, errno=%d.\n", ret, command, errno);
    }
}
#endif

void switch_system_call_log(const char *file_name)
{
#define MAX_SYSTEM_CALL_LOG_SIZE (16 * 1024 * 1024) /* 16MB. */

    pg_time_t current_time;
    struct tm *systm = NULL;
    char currentTime[LOG_MAX_TIMELEN] = {0};
    char command[MAXPGPATH] = {0};
    char logFileBuff[MAXPGPATH] = {0};
    char historyLogName[MAXPGPATH] = {0};

    Assert(file_name != NULL);

    long filesize;
    struct stat statbuff;

    int ret = stat(file_name, &statbuff);
    if (ret == -1) {
        write_runlog(WARNING, "stat system call log error, ret=%d, errno=%d.\n", ret, errno);
        return;
    } else {
        filesize = statbuff.st_size;
    }

    if (filesize > MAX_SYSTEM_CALL_LOG_SIZE) {
        current_time = time(NULL);
        systm = localtime(&current_time);
        if (systm != NULL) {
            (void)strftime(currentTime, LOG_MAX_TIMELEN, "-%Y-%m-%d_%H%M%S", systm);
        } else {
            write_runlog(WARNING, "switch_system_call_log get localtime failed.");
        }
        int rcs = snprintf_s(logFileBuff, MAXPGPATH, MAXPGPATH - 1, "%s%s.log", SYSTEM_CALL_LOG, currentTime);
        securec_check_intval(rcs, (void)rcs);

        rcs = snprintf_s(historyLogName, MAXPGPATH, MAXPGPATH - 1, "%s/%s", sys_log_path, logFileBuff);
        securec_check_intval(rcs, (void)rcs);

        /* copy current to history and clean current file. (sed -c -i not supported on some systems) */
        rcs = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1,
            "cp %s %s;> %s", system_call_log, historyLogName, system_call_log);
        securec_check_intval(rcs, (void)rcs);

        rcs = system(command);
        if (rcs != 0) {
            write_runlog(ERROR, "failed to switch system_call logfile. cmd:%s. return:(%d,%d), erron=%d.\n",
                command, rcs, WEXITSTATUS(rcs), errno);
        } else {
            write_runlog(LOG, "switch system_call logfile successfully. cmd:%s.\n", command);
        }
    }
    (void)chmod(file_name, S_IRUSR | S_IWUSR);
    return;
}

void server_loop(void)
{
    int pid;
    int pstat;
    int rc;
    uint32 recv_count = 0;
    uint32 msgPoolCount = 0;
    timespec startTime = {0, 0};
    timespec endTime = {0, 0};
    struct stat statbuf = {0};
    const int msgPoolInfoPrintTime = 60 * 1000 * 1000;

    /* unify log style */
    thread_name = "main";
    (void)clock_gettime(CLOCK_MONOTONIC, &startTime);
    (void)clock_gettime(CLOCK_MONOTONIC, &g_disconnectTime);

    const int pauseLogInterval = 5;
    int pauseLogTimes = 0;
    for (;;) {
        if (g_shutdownRequest) {
            cm_sleep(5);
            continue;
        }

        if (access(g_cmManualPausePath, F_OK) == 0) {
            g_isPauseArbitration = true;
            // avoid log swiping
            if (pauseLogTimes == 0) {
                write_runlog(LOG, "The cluster has been paused.\n");
            }
            ++pauseLogTimes;
            pauseLogTimes = pauseLogTimes % pauseLogInterval;
        } else {
            g_isPauseArbitration = false;
            pauseLogTimes = 0;
        }

        if (access(g_cmManualStartingPath, F_OK) == 0) {
            g_isStarting = true;
        } else {
            g_isStarting = false;
        }

        (void)clock_gettime(CLOCK_MONOTONIC, &endTime);
        if (g_isStart) {
            g_suppressAlarm = true;
            if (endTime.tv_sec - startTime.tv_sec >= 300) {
                g_suppressAlarm = false;
                g_isStart = false;
            }
        }

        /* report instances status every agent_report_interval sec */
        if (recv_count >= (agent_report_interval * 1000 * 1000) / AGENT_RECV_CYCLE) {
            pid = waitpid(-1, &pstat, WNOHANG);
            if (pid > 0) {
                write_runlog(LOG, "child process have die! pid is %d exit status is %d\n ", pid, pstat);
            }

            /* if system_call-current.log > 16MB switch */
            switch_system_call_log(system_call_log);
            clean_system_alarm_log(system_alarm_log, sys_log_path);

            /* undocumentedVersion > 0 means the cluster is upgrading, upgrade will change
            the directory $GAUSSHOME/bin, the g_cmagentLockfile will lost, agent should not exit */
            if ((stat(g_cmagentLockfile, &statbuf) != 0) && (undocumentedVersion == 0)) {
                write_runlog(FATAL, "lock file doesn't exist.\n");
                exit(1);
            }

            rc = read_config_file_check();
            if (rc < 0) {
                write_runlog(ERROR, "read_config_file_check failed when start in server_loop!\n");
            }
            if (g_node == NULL) {
                cm_sleep(5);
                continue;
            }

            recv_count = 0;
        }

        if (msgPoolCount > (msgPoolInfoPrintTime / AGENT_RECV_CYCLE)) {
            PrintMsgBufPoolUsage(LOG);
            msgPoolCount = 0;
        }

        check_thread_state();

        if (g_gotParameterReload == 1) {
            ReloadParametersFromConfigfile();
            g_gotParameterReload = 0;
        }
        CmUsleep(AGENT_RECV_CYCLE);
        recv_count++;
        msgPoolCount++;
    }
}
