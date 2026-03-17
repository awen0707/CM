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

static void DoHelp(void)
{
    (void)printf(_("%s is a utility to monitor an instance.\n\n"), g_progname);

    (void)printf(_("Usage:\n"));
    (void)printf(_("  %s\n"), g_progname);
    (void)printf(_("  %s 0\n"), g_progname);
    (void)printf(_("  %s 1\n"), g_progname);
    (void)printf(_("  %s 2\n"), g_progname);
    (void)printf(_("  %s 3\n"), g_progname);
    (void)printf(_("  %s normal\n"), g_progname);
    (void)printf(_("  %s abnormal\n"), g_progname);

    (void)printf(_("\nCommon options:\n"));
    (void)printf(_("  -?, -h, --help         show this help, then exit\n"));
    (void)printf(_("  -V, --version          output version information, then exit\n"));

    (void)printf(_("\nlocation of the log information options:\n"));
    (void)printf(_("  0                      LOG_DESTION_FILE\n"));
    (void)printf(_("  1                      LOG_DESTION_SYSLOG\n"));
    (void)printf(_("  2                      LOG_DESTION_FILE\n"));
    (void)printf(_("  3                      LOG_DESTION_DEV_NULL\n"));

    (void)printf(_("\nstarted mode options:\n"));
    (void)printf(_("  normal                 cm_agent is started normally\n"));
    (void)printf(_("  abnormal               cm_agent is started by killed\n"));
}

/*
 * Replace character to another.
 */
int replaceStr(char *sSrc, const char *sMatchStr, const char *sReplaceStr)
{
    char caNewString[MAX_PATH_LEN];
    errno_t rc;
    if (sMatchStr == NULL) {
        return -1;
    }
    char *FindPos = strstr(sSrc, sMatchStr);
    if (FindPos == NULL) {
        return 0; /* if sSrc does not contain sMatchStr, we think it relpaces successfully */
    }

    while (FindPos != NULL) {
        rc = memset_s(caNewString, MAX_PATH_LEN, 0, MAX_PATH_LEN);
        securec_check_errno(rc, (void)rc);
        long StringLen = FindPos - sSrc;
        rc = strncpy_s(caNewString, MAX_PATH_LEN, sSrc, (size_t)StringLen);
        securec_check_errno(rc, (void)rc);
        rc = strcat_s(caNewString, MAX_PATH_LEN, sReplaceStr);
        securec_check_errno(rc, (void)rc);
        rc = strcat_s(caNewString, MAX_PATH_LEN, FindPos + strlen(sMatchStr));
        securec_check_errno(rc, (void)rc);
        rc = strcpy_s(sSrc, MAX_PATH_LEN, caNewString);
        securec_check_errno(rc, (void)rc);

        FindPos = strstr(sSrc, sMatchStr);
    }

    return 0;
}

/*
 * Cut time from trace name.
 * This time will be used to sort traces.
 */
void cutTimeFromFileLog(const char *fileName, char *pattern, uint32 patternLen, char *strTime)
{
    errno_t rc;
    char subStr2[MAX_PATH_LEN] = {'\0'};
    char subStr5[MAX_PATH_LEN] = {'\0'};
    char *saveStr = NULL;
    char *saveStr2 = NULL;
    char subStr3[MAX_PATH_LEN] = {'\0'};
    char tempTimeStamp[MAX_TIME_LEN] = {'\0'};
    /* Copy file name avoid modifying the value */
    rc = memcpy_s(subStr2, MAX_PATH_LEN, fileName, strlen(fileName) + 1);
    securec_check_errno(rc, (void)rc);
    rc = memcpy_s(subStr5, MAX_PATH_LEN, fileName, strlen(fileName) + 1);
    securec_check_errno(rc, (void)rc);
    char *subStr4 = strstr(subStr5, "-");
    char *subStr = strtok_r(subStr2, "-", &saveStr);
    if (subStr == NULL) {
        write_runlog(ERROR, "file path name get failed.\n");
        return;
    }
    rc = snprintf_s(subStr3, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s%s", subStr, "-");
    securec_check_intval(rc, (void)rc);
    rc = memcpy_s(pattern, patternLen, subStr3, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);

    // assin a biggest data to current log in order to avoid compressing current log file when time changed
    // also for etcd and system_call current log filename doesn't contain timestamp. So, we assign a date to it
    if (strstr(fileName, "-current.log") != NULL) {
        rc = snprintf_s(tempTimeStamp, MAX_TIME_LEN, MAX_TIME_LEN - 1, "%s", MAX_LOGFILE_TIMESTAMP);
        securec_check_intval(rc, (void)rc);
        rc = memcpy_s(strTime, MAX_TIME_LEN, tempTimeStamp, MAX_TIME_LEN);
        securec_check_errno(rc, (void)rc);
        return;
    }

    /* Replace invalid character of strTime */
    if (subStr4 != NULL) {
        subStr = strtok_r(subStr4, ".", &saveStr2);
        if (subStr != NULL) {
            (void)replaceStr(subStr, "-current", "");
            if (subStr != NULL) {
                (void)replaceStr(subStr, "-", "");
                if (subStr != NULL) {
                    (void)replaceStr(subStr, "_", "");
                    if (is_digit_string(subStr)) {
                        rc = memcpy_s(strTime, MAX_TIME_LEN, subStr, strlen(subStr) + 1);
                        securec_check_errno(rc, (void)rc);
                    }
                }
            }
        }
    }
}

/*
 * Read all traces by log pattern,including zip file and non zip file.
 * Trace information are file time,file size,file path.These traces are
 * saved in the global variable.
 */
int readFileList(const char *basePath, LogFile *logFile, uint32 *count, int64 *totalSize, uint32 maxCount)
{
    errno_t rc;
    DIR *dir;
    struct dirent *ptr = NULL;
    char base[MAX_PATH_LEN] = {'\0'};
    char path[MAX_PATH_LEN] = {'\0'};
    char strTime[MAX_TIME_LEN] = {'\0'};
    char pattern[MAX_PATH_LEN] = {'\0'};

    if ((dir = opendir(basePath)) == NULL) {
        write_runlog(ERROR, "could not open file %s", basePath);
        return -1;
    }

    while (*count < maxCount && (ptr = readdir(dir)) != NULL) {
        struct stat stat_buf;
        /* Filter current directory and parent directory */
        if (strcmp(ptr->d_name, ".") == 0 || strcmp(ptr->d_name, "..") == 0) {
            continue;
        }

        rc = snprintf_s(path, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/%s", basePath, ptr->d_name);
        securec_check_intval(rc, (void)rc);
        if (unlikely(stat(path, &stat_buf) < 0)) {
            write_runlog(LOG, "could not stat file %s\n", path);
            continue;
        }
        /* Process file */
        if (S_ISREG(stat_buf.st_mode) && isLogFile(ptr->d_name)) {
            cutTimeFromFileLog(ptr->d_name, pattern, sizeof(pattern), strTime);
            /* Filter traces by pattern,trace name should contains date */
            if (strTime[0] != 0) {
                if (logFile != NULL) {
                    *totalSize += stat_buf.st_size;
                    rc = memcpy_s(logFile[*count].fileName, MAX_PATH_LEN, path, MAX_PATH_LEN);
                    securec_check_errno(rc, (void)rc);
                    rc = memcpy_s(logFile[*count].basePath, MAX_PATH_LEN, basePath, MAX_PATH_LEN);
                    securec_check_errno(rc, (void)rc);
                    rc = memcpy_s(logFile[*count].timestamp, MAX_TIME_LEN, strTime, MAX_TIME_LEN);
                    securec_check_errno(rc, (void)rc);
                    rc = memcpy_s(logFile[*count].pattern, MAX_PATH_LEN, pattern, MAX_PATH_LEN);
                    securec_check_errno(rc, (void)rc);
                    rc = memcpy_s(&logFile[*count].fileSize, sizeof(int64), &stat_buf.st_size, sizeof(int64));
                    securec_check_errno(rc, (void)rc);
                }
                *count += 1;
            }
        } else if (S_ISDIR(stat_buf.st_mode)) { /* Process directory */
            rc = memset_s(base, sizeof(base), '\0', sizeof(base));
            securec_check_errno(rc, (void)rc);
            rc = strcpy_s(base, MAX_PATH_LEN, basePath);
            securec_check_errno(rc, (void)rc);
            rc = strcat_s(base, MAX_PATH_LEN, "/");
            securec_check_errno(rc, (void)rc);
            rc = strcat_s(base, MAX_PATH_LEN, ptr->d_name);
            securec_check_errno(rc, (void)rc);
            if (readFileList(base, logFile, count, totalSize, maxCount) < 0) {
                write_runlog(ERROR, "readFileList() fail.");
            }
        }
    }
    (void)closedir(dir);
    return 0;
}

static int cmagent_unlock(void)
{
    int ret = flock(fileno(g_lockfile), LOCK_UN);
    if (g_lockfile != NULL) {
        (void)fclose(g_lockfile);
        g_lockfile = NULL;
    }
    return ret;
}

static int cmagent_lock(void)
{
    int ret;
    struct stat statbuf = {0};

    /* If gtm_ctl.lock dose not exist,create it */
    if (stat(g_cmagentLockfile, &statbuf) != 0) {
        char content[MAX_PATH_LEN] = {0};
        g_lockfile = fopen(g_cmagentLockfile, PG_BINARY_W);
        if (g_lockfile == NULL) {
            (void)fprintf(stderr, "FATAL %s: can't open lock file \"%s\" : %s\n",
                g_progname, g_cmagentLockfile, strerror(errno));
            exit(1);
        }
        (void)chmod(g_cmagentLockfile, S_IRUSR | S_IWUSR);
        if (fwrite(content, MAX_PATH_LEN, 1, g_lockfile) != 1) {
            (void)fclose(g_lockfile);
            g_lockfile = NULL;
            (void)fprintf(stderr,
                "FATAL %s: can't write lock file \"%s\" : %s\n",
                g_progname, g_cmagentLockfile, strerror(errno));
            exit(1);
        }
        (void)fclose(g_lockfile);
        g_lockfile = NULL;
        (void)chmod(g_cmagentLockfile, S_IRUSR | S_IWUSR);
    }
    if ((g_lockfile = fopen(g_cmagentLockfile, PG_BINARY_W)) == NULL) {
        (void)fprintf(stderr, "FATAL %s: could not open lock file \"%s\" : %s\n",
            g_progname, g_cmagentLockfile, strerror(errno));
        exit(1);
    }

    if (SetFdCloseExecFlag(g_lockfile) < 0) {
        (void)fprintf(stderr, "%s: can't set file flag\"%s\" : %s\n", g_progname, g_cmagentLockfile, strerror(errno));
    }

    ret = flock(fileno(g_lockfile), LOCK_EX | LOCK_NB);

    return ret;
}

void GetAgentConfigEx()
{
    /* Create thread of compressed and remove task. */
    if (get_config_param(configDir, "enable_cn_auto_repair", g_enableCnAutoRepair, sizeof(g_enableCnAutoRepair)) < 0) {
        (void)fprintf(stderr, "get_config_param() get enable_cn_auto_repair fail.\n");
    }

    if (get_config_param(configDir, "enable_log_compress", g_enableLogCompress, sizeof(g_enableLogCompress)) < 0) {
        (void)fprintf(stderr, "get_config_param() get enable_log_compress fail.\n");
    }

    if (get_config_param(configDir, "enable_ssl", g_enableMesSsl, sizeof(g_enableMesSsl)) < 0) {
        (void)fprintf(stderr, "get_config_param() get enable_ssl fail.\n");
    }

    if (get_config_param(configDir, "security_mode", g_enableOnlineOrOffline, sizeof(g_enableOnlineOrOffline)) < 0) {
        (void)fprintf(stderr, "get_config_param() get security_mode fail.\n");
    }

    if (get_config_param(configDir, "unix_socket_directory", g_unixSocketDirectory, sizeof(g_unixSocketDirectory)) <
        0) {
        (void)fprintf(stderr, "get_config_param() get unix_socket_directory fail.\n");
    } else {
        check_input_for_security(g_unixSocketDirectory);
    }
    if (get_config_param(configDir, "voting_disk_path", g_votingDiskPath, sizeof(g_votingDiskPath)) < 0) {
        (void)fprintf(stderr, "get_config_param() get voting_disk_path fail.\n");
    }
    canonicalize_path(g_votingDiskPath);
    g_diskTimeout = get_uint32_value_from_config(configDir, "disk_timeout", 200);
    log_max_size = get_int_value_from_config(configDir, "log_max_size", 10240);
    log_saved_days = get_uint32_value_from_config(configDir, "log_saved_days", 90);
    log_max_count = get_uint32_value_from_config(configDir, "log_max_count", 10000);

    g_cmaRhbItvl = get_uint32_value_from_config(configDir, "agent_rhb_interval", 1000);

    g_sslOption.expire_time = get_uint32_value_from_config(configDir, "ssl_cert_expire_alert_threshold",
        CM_DEFAULT_SSL_EXPIRE_THRESHOLD);
    g_sslCertExpireCheckInterval = get_uint32_value_from_config(configDir, "ssl_cert_expire_check_interval",
        SECONDS_PER_DAY);
    if (g_sslOption.expire_time < CM_MIN_SSL_EXPIRE_THRESHOLD ||
        g_sslOption.expire_time > CM_MAX_SSL_EXPIRE_THRESHOLD) {
        write_runlog(ERROR, "invalid ssl expire alert threshold %u, must between %u and %u\n",
            g_sslOption.expire_time, CM_MIN_SSL_EXPIRE_THRESHOLD, CM_MAX_SSL_EXPIRE_THRESHOLD);
    }
}

static void GetAlarmConf()
{
    char alarmPath[MAX_PATH_LEN] = {0};
    int rcs = GetHomePath(alarmPath, sizeof(alarmPath));
    if (rcs != EOK) {
        write_runlog(ERROR, "Get GAUSSHOME failed, please check.\n");
        return;
    }
    canonicalize_path(alarmPath);
    int rc =
        snprintf_s(g_alarmConfigDir, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/alarmConfig.conf", alarmPath);
    securec_check_intval(rc, (void)rc);
    GetAlarmConfig(g_alarmConfigDir);
}

int get_agent_global_params_from_configfile()
{
    int rc =
    snprintf_s(configDir, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/cm_agent/cm_agent.conf", g_currentNode->cmDataPath);
    securec_check_intval(rc, (void)rc);
    check_input_for_security(configDir);
    canonicalize_path(configDir);
    if (cmagent_lock() == -1) {
        return -1;
    }
    GetAlarmConf();
    get_log_paramter(configDir);
    GetStringFromConf(configDir, sys_log_path, sizeof(sys_log_path), "log_dir");
    check_input_for_security(sys_log_path);
    get_build_mode(configDir);
    get_start_mode(configDir);
    get_connection_mode(configDir);
    GetStringFromConf(configDir, g_environmentThreshold, sizeof(g_environmentThreshold), "environment_threshold");
    
    GetStringFromConf(configDir, g_dbServiceVip, sizeof(g_dbServiceVip), "db_service_vip");
    if (g_dbServiceVip[0] == '\0') {
        write_runlog(LOG, "parameter \"db_service_vip\" is not provided, please check!\n");
    } else if (!IsIPAddrValid(g_dbServiceVip)) {
        write_runlog(ERROR, "value of parameter \"db_service_vip\" is invalid, please check!\n");
        return -1;
    }
    agent_report_interval = get_uint32_value_from_config(configDir, "agent_report_interval", 1);
    agent_heartbeat_timeout = get_uint32_value_from_config(configDir, "agent_heartbeat_timeout", 8);
    agent_connect_timeout = get_uint32_value_from_config(configDir, "agent_connect_timeout", 1);
    agent_backup_open = (ClusterRole)get_uint32_value_from_config(configDir, "agent_backup_open", CLUSTER_PRIMARY);
    agent_connect_retries = get_uint32_value_from_config(configDir, "agent_connect_retries", 15);
    agent_check_interval = get_uint32_value_from_config(configDir, "agent_check_interval", 2);
    agent_kill_instance_timeout = get_uint32_value_from_config(configDir, "agent_kill_instance_timeout", 0);
    agent_phony_dead_check_interval = get_uint32_value_from_config(configDir, "agent_phony_dead_check_interval", 10);
    enable_gtm_phony_dead_check = get_uint32_value_from_config(configDir, "enable_gtm_phony_dead_check", 1);
    g_enableE2ERto = (uint32)get_int_value_from_config(configDir, "enable_e2e_rto", 0);
    g_disasterRecoveryType =
        (DisasterRecoveryType)get_uint32_value_from_config(configDir, "disaster_recovery_type", DISASTER_RECOVERY_NULL);
    agent_phony_dead_check_interval = g_enableE2ERto == 1 ? 1 : agent_phony_dead_check_interval;
    g_ssDoubleClusterMode =
        (SSDoubleClusterMode)get_uint32_value_from_config(configDir, "ss_double_cluster_mode", SS_DOUBLE_NULL);

    log_threshold_check_interval =
        get_uint32_value_from_config(configDir, "log_threshold_check_interval", log_threshold_check_interval);
    undocumentedVersion = get_uint32_value_from_config(configDir, "upgrade_from", 0);
    dilatation_shard_count_for_disk_capacity_alarm = get_uint32_value_from_config(
        configDir, "dilatation_shard_count_for_disk_capacity_alarm", dilatation_shard_count_for_disk_capacity_alarm);
    if (get_config_param(configDir, "enable_dcf", g_agentEnableDcf, sizeof(g_agentEnableDcf)) < 0) {
        write_runlog(ERROR, "get_config_param() get enable_dcf fail.\n");
    }

#ifndef ENABLE_MULTIPLE_NODES
    if (get_config_param(configDir, "enable_fence_dn", g_enableFenceDn, sizeof(g_enableFenceDn)) < 0)
        write_runlog(ERROR, "get_config_param() get enable_fence_dn fail.\n");
#endif
    GetEventTrigger();

#ifdef __aarch64__
    agent_process_cpu_affinity = get_uint32_value_from_config(configDir, "process_cpu_affinity", 0);
    if (agent_process_cpu_affinity > CPU_AFFINITY_MAX) {
        (void)fprintf(stderr, "CM parameter 'process_cpu_affinity':%d is bigger than limit:%d\n",
            agent_process_cpu_affinity, CPU_AFFINITY_MAX);
        agent_process_cpu_affinity = 0;
    }

    total_cpu_core_num = get_nprocs();
    (void)fprintf(stdout, "total_cpu_core_num is %d, agent_process_cpu_affinity is %d\n",
        total_cpu_core_num, agent_process_cpu_affinity);
#endif
    GetAgentConfigEx();
    return 0;
}

static status_t InitSendDdbOperRes()
{
    if (g_currentNode->coordinate == 0) {
        return CM_SUCCESS;
    }
    (void)pthread_rwlock_init(&(g_gtmSendDdbOper.lock), NULL);
    (void)pthread_rwlock_init(&(g_gtmCmDdbOperRes.lock), NULL);
    size_t sendLen = sizeof(CltSendDdbOper);
    CltSendDdbOper *sendOper = (CltSendDdbOper *)malloc(sendLen);
    if (sendOper == NULL) {
        write_runlog(ERROR, "sendOper is NULL, cma will exit.\n");
        return CM_ERROR;
    }
    errno_t rc = memset_s(sendOper, sendLen, 0, sendLen);
    securec_check_errno(rc, FREE_AND_RESET(sendOper));
    g_gtmSendDdbOper.sendOper = sendOper;
    size_t operResLen = sizeof(CmSendDdbOperRes);
    CmSendDdbOperRes *ddbOperRes = (CmSendDdbOperRes *)malloc(operResLen);
    if (ddbOperRes == NULL) {
        free(sendOper);
        sendOper = NULL;
        write_runlog(ERROR, "ddbOperRes is NULL, cma will exit.\n");
        return CM_ERROR;
    }
    rc = memset_s(ddbOperRes, operResLen, 0, operResLen);
    securec_check_errno(rc, FREE_AND_RESET(ddbOperRes));
    g_gtmCmDdbOperRes.ddbOperRes = ddbOperRes;
    return CM_SUCCESS;
}

static void InitNeedInfoRes()
{
    size_t syncListLen = sizeof(DnSyncListInfo) * CM_MAX_DATANODE_PER_NODE;
    errno_t rc = memset_s(g_dnSyncListInfo, syncListLen, 0, syncListLen);
    securec_check_errno(rc, (void)rc);
    size_t doWriteLen = sizeof(CmDoWriteOper) * CM_MAX_DATANODE_PER_NODE;
    rc = memset_s(g_cmDoWriteOper, doWriteLen, 0, doWriteLen);
    securec_check_errno(rc, (void)rc);
}

static inline void InitResReportMsg()
{
    errno_t rc = memset_s(&g_resReportMsg, sizeof(OneNodeResStatusInfo), 0, sizeof(OneNodeResStatusInfo));
    securec_check_errno(rc, (void)rc);
    InitResStatCommInfo(&g_resReportMsg.resStat);
    (void)pthread_rwlock_init(&(g_resReportMsg.rwlock), NULL);
}

static void CreateCusResThread()
{
    if (IsCusResExistLocal()) {
        CreateRecvClientMessageThread();
        CreateSendMessageToClientThread();
        CreateProcessMessageThread();
        InitResReportMsg();
        CreateDefResStatusCheckThread();
        CreateCusResIsregCheckThread();
    } else {
        write_runlog(LOG, "[CLIENT] no resource, start client thread is unnecessary.\n");
    }
}

static status_t CmaReadCusResConf()
{
    int ret = ReadCmConfJson((void*)write_runlog);
    if (!IsReadConfJsonSuccess(ret)) {
        write_runlog(FATAL, "read cm conf json failed, ret=%d, reason=\"%s\".\n", ret, ReadConfJsonFailStr(ret));
        return CM_ERROR;
    }
    if (InitAllResStat() != CM_SUCCESS) {
        write_runlog(FATAL, "init res status failed.\n");
        return CM_ERROR;
    }
    if (InitLocalResConf() != CM_SUCCESS) {
        write_runlog(FATAL, "init local res conf failed.\n");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static void InitAgentGlobalVariable()
{
    //Init is openGauss with dms or dss mode
    for (uint32 i = 0; i < GetLocalResConfCount(); ++i) {
        if (strcmp(g_resConf[i].resName, "dss") == 0 || strcmp(g_resConf[i].resName, "dms_res") == 0) {
            g_isStorageWithDMSorDSS = true;
            write_runlog(LOG, "This node has dms or dss enabled.\n");
            return;
        }
    }
}

int main(int argc, char** argv)
{
    uid_t uid = getuid();
    if (uid == 0) {
        (void)printf("current user is the root user (uid = 0), exit.\n");
        return 1;
    }

    int status;
    uint32 i;
    size_t lenth = 0;
    int *thread_index = NULL;
    errno_t rc;
    const int maxArgcNum = 2;
    bool &isSharedStorageMode = GetIsSharedStorageMode();

    if (argc > maxArgcNum) {
        (void)printf(_("the argv is error, try cm_agent -h for more information!\n"));
        return -1;
    }

    GetCmdlineOpt(argc, argv);

    g_progname = "cm_agent";
    prefix_name = g_progname;
    if (argc > 1) {
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-?") == 0) {
            DoHelp();
            exit(0);
        } else if (strcmp(argv[1], "-V") == 0 || strcmp(argv[1], "--version") == 0) {
            (void)puts("cm_agent " DEF_CM_VERSION);
            exit(0);
        } else if (strcmp("normal", argv[1]) == 0) {
            g_isStart = true;
            lenth = strlen(argv[1]);
            rc = memset_s(argv[1], lenth, 0, lenth);
            securec_check_errno(rc, (void)rc);
        } else if (strcmp("abnormal", argv[1]) == 0) {
            g_isStart = false;
            lenth = strlen(argv[1]);
            rc = memset_s(argv[1], lenth, 0, lenth);
            securec_check_errno(rc, (void)rc);
        }
    }
    (void)syscalllockInit(&g_cmEnvLock);

    /* init the sigset and register the signal handle */
    init_signal_mask();
    (void)sigprocmask(SIG_SETMASK, &block_sig, NULL);
    setup_signal_handle(SIGHUP, reload_cmagent_parameters);
    setup_signal_handle(SIGUSR1, RecvSigusrSingle);
#ifdef ENABLE_MULTIPLE_NODES
    setup_signal_handle(SIGUSR2, SetFlagToUpdatePortForCnDn);
#endif
    status = get_prog_path();
    if (status < 0) {
        (void)fprintf(stderr, "get_prog_path  failed!\n");
        return -1;
    }

    pw = getpwuid(getuid());
    if (pw == NULL || pw->pw_name == NULL) {
        (void)fprintf(stderr, "can not get current user name.\n");
        return -1;
    }
    SetEnvSupportIpV6(CheckSupportIpV6());

    /* Initialize OPENSSL, and register a signal handler to clean up when use exit() */
    if (RegistOpensslExitSignal(g_progname)) {
        return -1;
    }

    status = CmSSlConfigInit(true);
    if (status < 0) {
        (void)fprintf(stderr, "read ssl cerfication files when start!\n");
        return -1;
    }

    status = read_config_file_check();
    if (status < 0) {
        (void)fprintf(stderr, "read_config_file_check failed when start!\n");
        return -1;
    }

    max_logic_cluster_name_len = (max_logic_cluster_name_len < strlen("logiccluster_name"))
                                     ? (uint32)strlen("logiccluster_name")
                                     : max_logic_cluster_name_len;

    (void)logfile_init();
    if (get_agent_global_params_from_configfile() == -1) {
        (void)fprintf(stderr, "Another cm_agent command is still running, start failed !\n");
        return -1;
    }
    /* deal sys_log_path is null.save log to cmData dir. */
    if (sys_log_path[0] == '\0') {
        rc = strncpy_s(sys_log_path, sizeof(sys_log_path), g_currentNode->cmDataPath, MAXPGPATH - 1);
        securec_check_errno(rc, (void)rc);

        rc = strncat_s(sys_log_path, sizeof(sys_log_path), "/cm_agent/log", strlen("/cm_agent/log"));
        securec_check_errno(rc, (void)rc);
        (void)mkdir(sys_log_path, S_IRWXU);
    } else {
        if (sys_log_path[0] == '/') {
            (void)CmMkdirP(sys_log_path, S_IRWXU);
        } else {
            char buf[MAXPGPATH] = {0};

            rc = memset_s(buf, sizeof(buf), 0, MAXPGPATH);
            securec_check_errno(rc, (void)rc);

            rc = strncpy_s(buf, sizeof(buf), g_currentNode->cmDataPath, MAXPGPATH - 1);
            securec_check_errno(rc, (void)rc);

            rc = strncat_s(buf, sizeof(buf), "/cm_agent/", strlen("/cm_agent/"));
            securec_check_errno(rc, (void)rc);
            rc = strncat_s(buf, sizeof(buf), sys_log_path, strlen(sys_log_path));
            securec_check_errno(rc, (void)rc);

            rc = memcpy_s(sys_log_path, sizeof(sys_log_path), buf, MAXPGPATH);
            securec_check_errno(rc, (void)rc);
            (void)mkdir(sys_log_path, S_IRWXU);
        }
    }
    status_t st = CreateSysLogFile();
    if (st != CM_SUCCESS) {
        exit(-1);
    }

    rc = memset_s(system_call_log, MAXPGPATH, 0, MAXPGPATH);
    securec_check_errno(rc, (void)rc);

    create_system_call_log();

    create_system_alarm_log(sys_log_path);

    print_environ();

    if (g_currentNode->datanodeCount > CM_MAX_DATANODE_PER_NODE) {
        write_runlog(FATAL,
            "%u datanodes deployed on this node more than limit(%d)\n",
            g_currentNode->datanodeCount,
            CM_MAX_DATANODE_PER_NODE);
        exit(1);
    }

    AlarmEnvInitialize();
    InitializeAlarmItem(g_currentNode);
    rc = snprintf_s(g_agentDataDir, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/cm_agent/", g_currentNode->cmDataPath);
    securec_check_intval(rc, (void)rc);

    (void)atexit(stop_flag);

    if (CmaReadCusResConf() != CM_SUCCESS) {
        exit(-1);
    }

    InitAgentGlobalVariable();

    CmServerCmdProcessorInit();
    status = CreateCheckNetworkThread();
    if (status != 0) {
        exit(status);
    }
#ifdef ENABLE_MULTIPLE_NODES
    if (g_currentNode->gtm == 1) {
        (void)pthread_rwlock_init(&(g_gtmReportMsg.lk_lock), NULL);
        CreateGTMStatusCheckThread();
    }

    if (g_currentNode->coordinate == 1) {
        (void)pthread_rwlock_init(&(g_cnReportMsg.lk_lock), NULL);
        CreateCNStatusCheckThread();
        /* start ccn status checker */
        CreateCCNStatusCheckThread();
        CreateCNBackupStatusCheckThread();
    }
#endif
    InitNeedInfoRes();
    if (g_currentNode->datanodeCount > 0) {
        thread_index = (int *)malloc(sizeof(int) * g_currentNode->datanodeCount);
        if (thread_index == NULL) {
            write_runlog(FATAL, "out of memory\n");
            exit(1);
        }

        for (i = 0; i < g_currentNode->datanodeCount; i++) {
            thread_index[i] = (int)i;
#ifdef __aarch64__
            /* Get the initial primary datanode number */
            g_datanode_primary_num += (PRIMARY_DN == g_currentNode->datanode[i].datanodeRole) ? 1 : 0;
            g_datanode_primary_and_standby_num += (DUMMY_STANDBY_DN != g_currentNode->datanode[i].datanodeRole) ? 1 : 0;
#endif
        }

        for (i = 0; i < g_currentNode->datanodeCount; i++) {
            (void)pthread_rwlock_init(&(g_dnReportMsg[i].lk_lock), NULL);
            (void)pthread_rwlock_init(&(g_dnSyncListInfo[i].lk_lock), NULL);
            (void)pthread_rwlock_init(&(g_cmDoWriteOper[i].lock), NULL);
            int *ind = thread_index + i;
            CreateDNStatusCheckThread(ind);
            CreateDNConnectionStatusCheckThread(ind);
            CreateDNCheckSyncListThread(ind);
            CreateDNCheckAvailableSyncThread(ind);
#ifdef ENABLE_MULTIPLE_NODES
            CreateDNBackupStatusCheckThread(ind);
            CreateDNStorageScalingAlarmThread(ind);
#endif
        }
    }

    /* Get log path that is used in start&stop thread and log compress&remove thread. */
    status = cmagent_getenv("GAUSSLOG", g_logBasePath, sizeof(g_logBasePath));
    if (status != EOK) {
        write_runlog(FATAL, "get env GAUSSLOG fail.\n");
        exit(status);
    }
    isSharedStorageMode = IsSharedStorageMode();

    AllocCmaMsgQueueMemory();
    AllQueueInit();
    MsgPoolInit(MAX_MSG_BUF_POOL_SIZE, MAX_MSG_BUF_POOL_COUNT);
    st = InitSendDdbOperRes();
    if (st != CM_SUCCESS) {
        write_runlog(FATAL, "failed to InitSendDdbOperRes.\n");
        exit(-1);
    }
    check_input_for_security(g_logBasePath);
    CreatePhonyDeadCheckThread();
    CreateStartAndStopThread();
    CreateFaultDetectThread();
    CreateConnCmsPThread();
    CreateCheckUpgradeModeThread();
    CreateRhbCheckThreads();
    CreateVotingDiskThread();
    CreateCusResThread();
    int err = CreateSendAndRecvCmsMsgThread();
    if (err != 0) {
        write_runlog(FATAL, "Failed to create send and recv thread: error %d\n", err);
        exit(err);
    }
    err = CreateProcessSendCmsMsgThread();  // inst status report thread
    if (err != 0) {
        write_runlog(FATAL, "Failed to create send msg thread: error %d\n", err);
        exit(err);
    }
    err = CreateProcessRecvCmsMsgThread();
    if (err != 0) {
        write_runlog(FATAL, "Failed to create process recv msg thread: error %d\n", err);
        exit(err);
    }
    CreateKerberosStatusCheckThread();
    CreateDiskUsageCheckThread();
    CreateOnDemandRedoCheckThread();

#ifdef ENABLE_MULTIPLE_NODES
    err = CreateCheckNodeStatusThread();
    if (err != 0) {
        write_runlog(FATAL, "Failed to create check node status thread: error %d\n", err);
        exit(err);
    }
    if (g_currentNode->coordinate > 0) {
        err = CreateCnDnConnectCheckThread();
        if (err != 0) {
            write_runlog(FATAL, "Failed to create check conn status thread: error %d\n", err);
            exit(err);
        }
        CreatePgxcNodeCheckThread();
    }

    /* if g_etcd_num = 0, cms change to dcc arbitrate, so can check gtm mode */
    if (g_currentNode->coordinate > 0) {
        CreateGtmModeThread();
    }
#endif

    if (g_currentNode->etcd) {
        (void)pthread_rwlock_init(&(g_etcdReportMsg.lk_lock), NULL);
        CreateETCDStatusCheckThread();
        CreateETCDConnectionStatusCheckThread();
    }

    /* Parameter is on then start compress thread */
    if (CreateLogFileCompressAndRemoveThread() != 0) {
        write_runlog(FATAL, "CreateLogFileCompressAndRemoveThread failed!\n");
        exit(-1);
    }

    server_loop();
    (void)cmagent_unlock();

    write_runlog(LOG, "cm_agent exit\n");
    if (thread_index != NULL) {
        FREE_AND_RESET(thread_index);
    }

    exit(status);
}

uint32 GetLibcommDefaultPort(uint32 base_port, int port_type)
{
    /* DWS: default port, other: cn_port +2 */
    if (port_type == COMM_PORT_TYPE_DATA) {
        if (security_mode) {
            return COMM_DATA_DFLT_PORT;
        } else {
            return (base_port + 2);
        }
    } else {
        /* DWS: default port, other: cn_port +3 */
        if (security_mode) {
            return COMM_CTRL_DFLT_PORT;
        } else {
            return (base_port + 3);
        }
    }
}

bool ExecuteCmdWithResult(char *cmd, char *result, int resultLen)
{
    FILE *cmd_fd = popen(cmd, "r");
    if (cmd_fd == NULL) {
        write_runlog(ERROR, "popen %s failed, errno[%d].\n", cmd, errno);
        return false;
    }

    if (fgets(result, resultLen - 1, cmd_fd) == NULL) {
        (void)pclose(cmd_fd);
        /* has error or result is really null */
        write_runlog(LOG, "fgets result for %s failed, errno[%d].\n", cmd, errno);
        return false;
    }
    (void)pclose(cmd_fd);

    return true;
}

uint32 GetLibcommPort(const char *file_path, uint32 base_port, int port_type)
{
    char get_cmd[MAXPGPATH * 2];
    char result[NAMEDATALEN] = {0};
    int retry_cnt = 0;
    uint32 port = 0;
    const char *Keywords = NULL;

    if (port_type == COMM_PORT_TYPE_DATA) {
        Keywords = "comm_sctp_port";
    } else {
        Keywords = "comm_control_port";
    }

    /* read port from postgres.conf */
    int ret = snprintf_s(get_cmd,
        sizeof(get_cmd),
        MAXPGPATH * 2 - 1,
        "grep \"^%s\" %s/postgresql.conf|awk \'{print $3}\'|tail -1",
        Keywords,
        file_path);
    securec_check_intval(ret, (void)ret);

    while (retry_cnt < MAX_RETRY_TIME) {
        if (!ExecuteCmdWithResult(get_cmd, result, NAMEDATALEN)) {
            retry_cnt++;
            continue;
        }

        port = (uint32)strtol(result, NULL, 10);
        /* guc param is out of range */
        if (port == 0 || port > 65535) {
            port = GetLibcommDefaultPort(base_port, port_type);
            write_runlog(
                WARNING, "Custom %s: %ld is invalid, use the default:%u.\n", Keywords, strtol(result, NULL, 10), port);
            return port;
        } else {
            write_runlog(LOG, "Custom %s: %u has found.\n", Keywords, port);
            return port;
        }
    }

    port = GetLibcommDefaultPort(base_port, port_type);
    write_runlog(LOG, "No custom %s found, use the default:%u.\n", Keywords, port);
    return port;
}

static EventTriggerType GetTriggerTypeFromStr(const char *typeStr)
{
    for (int i = EVENT_START; i < EVENT_COUNT; ++i) {
        if (strcmp(typeStr, triggerTypeStringMap[i].typeStr) == 0) {
            return triggerTypeStringMap[i].type;
        }
    }
    write_runlog(ERROR, "Event trigger type %s is not supported.\n", typeStr);
    return EVENT_UNKNOWN;
}

/*
 * check trigger item, key and value can't be empty and must be string,
 * value must be shell script file, current user has right permission.
 */
static status_t CheckEventTriggersItem(const cJSON *item)
{
    if (!cJSON_IsString(item)) {
        write_runlog(ERROR, "The trigger value must be string.\n");
        return CM_ERROR;
    }

    char *valuePtr = item->valuestring;
    if (valuePtr == NULL || strlen(valuePtr) == 0) {
        write_runlog(ERROR, "The trigger value can't be empty.\n");
        return CM_ERROR;
    }

    if (valuePtr[0] != '/') {
        write_runlog(ERROR, "The trigger script path must be absolute path.\n");
        return CM_ERROR;
    }

    const char *extention = ".sh";
    const size_t shExtLen = strlen(extention);
    size_t pathLen = strlen(valuePtr);
    if (pathLen < shExtLen ||
        strncmp((valuePtr + (pathLen - shExtLen)), extention, shExtLen) != 0) {
        write_runlog(ERROR, "The trigger value %s is not shell script.\n", valuePtr);
        return CM_ERROR;
    }

    if (access(valuePtr, F_OK) != 0) {
        write_runlog(ERROR, "The trigger script %s is not a file or does not exist.\n", valuePtr);
        return CM_ERROR;
    }
    if (access(valuePtr, R_OK | X_OK) != 0) {
        write_runlog(ERROR, "Current user has no permission to access the "
            "trigger script %s.\n", valuePtr);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

/*
 * event_triggers sample:
 * {
 *     "on_start": "/dir/on_start.sh",
 *     "on_stop": "/dir/on_stop.sh",
 *     "on_failover": "/dir/on_failover.sh",
 *     "on_switchover": "/dir/on_switchover.sh"
 * }
 */
static void ParseEventTriggers(const char *value)
{
    if (value == NULL || value[0] == 0) {
        write_runlog(WARNING, "The value of event_triggers is empty.\n");
        return;
    }
    if (strlen(value) > MAX_PATH_LEN) {
        write_runlog(ERROR, "The string value \"%s\" is longer than 1024.\n", value);
        return;
    }

    cJSON *root = NULL;
    root = cJSON_Parse(value);
    if (!root) {
        write_runlog(ERROR, "The value of event_triggers is not a json.\n");
        return;
    }
    if (cJSON_IsArray(root)) {
        write_runlog(ERROR, "The value of event_triggers can't be a json item array.\n");
        cJSON_Delete(root);
        return;
    }

    int triggerNums[EVENT_COUNT] = {0};
    cJSON *item = root->child;
    /* when the new value is invalid, the old value should not be modify at all,
     * so a temporary backup is needed, to avoid partial modifications
     */
    char *eventTriggers[EVENT_COUNT] = {NULL};
    bool isValueInvalid = false;
    while (item != NULL) {
        if (CheckEventTriggersItem(item) == CM_ERROR) {
            isValueInvalid = true;
            break;
        }

        char *typeStr = item->string;
        EventTriggerType type = GetTriggerTypeFromStr(typeStr);
        if (type == EVENT_UNKNOWN) {
            write_runlog(ERROR, "The trigger type %s does support.\n", typeStr);
            isValueInvalid = true;
            break;
        }

        char *valuePtr = item->valuestring;
        ++triggerNums[type];
        if (triggerNums[type] > 1) {
            write_runlog(ERROR, "Duplicated trigger %s are supported.\n", typeStr);
            isValueInvalid = true;
            break;
        }

        eventTriggers[type] = (char*)CmMalloc(strlen(valuePtr));
        int ret = snprintf_s(eventTriggers[type], MAX_PATH_LEN,
            MAX_PATH_LEN - 1, "%s", valuePtr);
        securec_check_intval(ret, (void)ret);
        item = item->next;
    }

    if (isValueInvalid) {
        for (int i = 0; i < EVENT_COUNT; ++i) {
            if (eventTriggers[i] != NULL) {
                FREE_AND_RESET(eventTriggers[i]);
            }
        }
        cJSON_Delete(root);
        return;
    }

    // copy the temporary backup to the global variable and clean up the temporary backup
    for (int i = 0; i < EVENT_COUNT; ++i) {
        if (eventTriggers[i] == NULL) {
            if (g_eventTriggers[i] != NULL) {
                FREE_AND_RESET(g_eventTriggers[i]);
            }
        } else {
            if (g_eventTriggers[i] == NULL) {
                g_eventTriggers[i] = (char*)CmMalloc(strlen(eventTriggers[i]));
            }
            int ret = snprintf_s(g_eventTriggers[i], MAX_PATH_LEN,
                MAX_PATH_LEN - 1, "%s", eventTriggers[i]);
            securec_check_intval(ret, (void)ret);
            FREE_AND_RESET(eventTriggers[i]);
            write_runlog(LOG, "Event trigger %s was added, script path = %s.\n",
                triggerTypeStringMap[i].typeStr, g_eventTriggers[i]);
        }
    }
    cJSON_Delete(root);
}

void GetEventTrigger()
{
    char eventTriggerString[MAX_PATH_LEN] = {0};
    if (get_config_param(configDir, "event_triggers", eventTriggerString, MAX_PATH_LEN) < 0) {
        write_runlog(ERROR, "get_config_param() get event_triggers fail.\n");
        return;
    }
    ParseEventTriggers(eventTriggerString);
}

void ExecuteEventTrigger(const EventTriggerType triggerType, int32 staPrimId)
{
    if (g_eventTriggers[triggerType] == NULL) {
        return;
    }
    write_runlog(LOG, "Event trigger %s was triggered.\n", triggerTypeStringMap[triggerType].typeStr);
    char execTriggerCmd[MAX_COMMAND_LEN] = {0};
    int rc;
    if (staPrimId != INVALID_ID && triggerType == EVENT_FAILOVER) {
        rc = snprintf_s(execTriggerCmd, MAX_COMMAND_LEN, MAX_COMMAND_LEN - 1,
        SYSTEMQUOTE "%s %d >> %s 2>&1 &" SYSTEMQUOTE, g_eventTriggers[triggerType], staPrimId, system_call_log);
    } else {
        rc = snprintf_s(execTriggerCmd, MAX_COMMAND_LEN, MAX_COMMAND_LEN - 1,
        SYSTEMQUOTE "%s >> %s 2>&1 &" SYSTEMQUOTE, g_eventTriggers[triggerType], system_call_log);
    }
    securec_check_intval(rc, (void)rc);
    write_runlog(LOG, "event trigger command: \"%s\".\n", execTriggerCmd);
    RunCmd(execTriggerCmd);
}
