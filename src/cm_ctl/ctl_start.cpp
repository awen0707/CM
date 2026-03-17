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
 * ctl_start.cpp
 *    cm_ctl start [-z AVAILABILITY_ZONE [--cm_arbitration_mode=ARBITRATION_MODE]]
 *                    [-n NODEID] [-D DATADIR] [-m resume] [-t SECS] [-R]
 *
 * IDENTIFICATION
 *    src/cm_ctl/ctl_start.cpp
 *
 * -------------------------------------------------------------------------
 */
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include "common/config/cm_config.h"
#include "cm/libpq-fe.h"
#include "cm/cm_misc.h"
#include "ctl_common.h"
#include "cm_msg_version_convert.h"
#include "cm/libpq-int.h"
#include "cm_ddb_adapter.h"
#include "ctl_common_res.h"
#include "cm_ip.h"

#define EXPECTED_CLUSTER_START_TIME 120
#define ETCD_START_WAIT 90
#define INSTANCE_START_CONFIRM_TIME 3
#define START_AZ_TRY_HEARTBEAT 20
#define CLUSTER_STATE_CHECK_INTERVAL 10
#define LTRAN_CHECK_INTERVAL 2
#define LTRAN_CHECK_TIMES 30

static void start_and_check_etcd_cluster();
static void start_cluster(void);
static void start_etcd_cluster(void);
static uint32 get_alive_etcd_node_count();
static void start_and_check_etcd_az(const char* azName);
static void start_etcd_node(uint32 nodeid);
static void check_etcd_cluster_status();
static void start_az(char* azName);
static void start_and_check_etcd_node(uint32 nodeId);
static void start_node(uint32 nodeid);
static void start_datanode_instance_relation(uint32 node, const char *dataPath);
static void start_az_try_more_one(const char* azName);
static void* check_cluster_start_status(void* arg);
static void StartFailQueryAndReport();
static void* start_check(void* arg);
static int start_check_cluster();
static int start_check_az(const char* azName);
static int start_check_node(uint32 node_id_check);
static int start_check_dn_relation(uint32  node, const char *dataPath);
static int start_check_instance(uint32 node_id_check, const char* datapath);
static void ExecuteGsGuc(const char* allAzLists, bool isSingleRep, uint32 repNum, uint32 nodeIndex);
#ifndef ENABLE_MULTIPLE_NODES
static void StartLtranProcess();
static bool CheckLibosKniIsOk();
static int StartLtranProcessByNode(uint32 nodeid);
extern char g_ltranManualStartFile[MAXPGPATH];
extern char g_libnetManualStartFile[MAXPGPATH];
#else
#include "ctl_distribute.h"
extern bool cn_resumes_restart;
#endif
void RunCmdInStartAz(const char* command, uint32 nodeIndex);

static uint32 GetEtcdNumOfAz(const char* azName);
static uint32 GetAliveEtcdNumOfAz(const char* azName);

static int g_cluster_start_status = CM_STATUS_UNKNOWN;
static int g_az_start_status = CM_STATUS_UNKNOWN;
static int g_instance_start_status = CM_STATUS_UNKNOWN;
static int g_node_start_status = CM_STATUS_UNKNOWN;
static int g_dn_relation_start_status = CM_STATUS_UNKNOWN;
static int g_resStartStatus = CM_STATUS_UNKNOWN;
static int g_dn_status = INSTANCE_HA_STATE_UNKONWN;
static StartExitCode g_startExitCode = CM_START_EXIT_INIT;

static int startaz_try_heartbeat = START_AZ_TRY_HEARTBEAT;
static struct timespec g_startTime;
static struct timespec g_endTime;

extern char g_cmData[CM_PATH_LENGTH];
extern char manual_start_file[MAXPGPATH];
extern char instance_manual_start_file[MAXPGPATH];
extern char cluster_manual_starting_file[MAXPGPATH];
extern char etcd_manual_start_file[MAXPGPATH];
extern char minority_az_start_file[MAX_PATH_LEN];
extern char g_minorityAzArbitrateFile[MAX_PATH_LEN];
extern char mpp_env_separate_file[MAXPGPATH];
extern char hosts_path[MAXPGPATH];
extern char g_appPath[MAXPGPATH];
extern char pssh_out_path[MAXPGPATH];
extern char result_path[MAXPGPATH];
extern char sys_log_path[MAXPGPATH];
extern const char* prefix_name;
extern bool got_stop;
extern bool wait_seconds_set;
extern int g_waitSeconds;
extern passwd* pw;
extern bool g_commandRelationship;
extern char* g_command_operation_azName;
extern uint32 g_commandOperationNodeId;
extern uint32 g_nodeId;
extern char* cm_arbitration_mode_set;
extern const char* g_progname;
extern CM_Conn* CmServer_conn;
extern uint32 g_commandOperationInstanceId;
extern char manual_pause_file[MAXPGPATH];

static int StartResInstCheck(uint32 instId)
{
    if (GetResInstStatus(instId) == CM_RES_STAT_ONLINE) {
        return CM_STATUS_NORMAL;
    }
    return CM_STATUS_UNKNOWN;
}

static void StartResInst(uint32 nodeId, uint32 instId)
{
    char instStartFile[MAX_PATH_LEN] = {0};
    int ret = snprintf_s(instStartFile, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/instance_manual_start_%u",
        g_appPath, instId);
    securec_check_intval(ret, (void)ret);

    char command[MAX_PATH_LEN] = {0};
    if (g_isPauseArbitration) {
        ret = snprintf_s(command, MAX_PATH_LEN, MAX_PATH_LEN - 1,
            SYSTEMQUOTE "rm -f %s; touch %s < \"%s\" 2>&1" SYSTEMQUOTE,
            instStartFile, cluster_manual_starting_file, DEVNULL);
    } else {
        ret = snprintf_s(command, MAX_PATH_LEN, MAX_PATH_LEN - 1, SYSTEMQUOTE "rm -f %s < \"%s\" 2>&1" SYSTEMQUOTE,
            instStartFile, DEVNULL);
    }
    securec_check_intval(ret, (void)ret);

    ret = runCmdByNodeId(command, nodeId);
    if (ret != 0) {
        write_runlog(DEBUG1, "Failed to start the resource instance with executing the command: command=\"%s\", "
            "nodeId=%u, instId=%u, systemReturn=%d, shellReturn=%d, errno=%d.\n",
            command, nodeId, instId, ret, SHELL_RETURN_CODE(ret), errno);
    }
}

static void StartAllResInstByNode(uint32 nodeId)
{
    for (uint32 i = 0; i < CusResCount(); ++i) {
        for (uint32 k = 0; k < g_resStatus[i].status.instanceCount; ++k) {
            if (g_resStatus[i].status.resStat[k].nodeId != nodeId) {
                continue;
            }
            StartResInst(nodeId, g_resStatus[i].status.resStat[k].cmInstanceId);
        }
    }
}

status_t StartWholeCluster()
{
    int ret;
#ifndef ENABLE_MULTIPLE_NODES
    struct stat libnetManualStat = {0};
    if (stat(g_libnetManualStartFile, &libnetManualStat) == 0) {
        StartLtranProcess();
        if (!CheckLibosKniIsOk()) {
            write_runlog(ERROR, "start the ltran cluster failed. \n");
            return CM_ERROR;
        }
        write_runlog(LOG, "start the ltran cluster successfully.\n");
    }
#endif
    if (g_etcd_num > 0) {
        write_runlog(LOG, "starting the ETCD cluster.\n");
        start_and_check_etcd_cluster();
    }

    write_runlog(LOG, "checking cluster status.\n");

    ret = g_single_node_cluster ? CheckSingleClusterRunningStatus() : CheckClusterRunningStatus();
    if (ret != 0) {
        return CM_ERROR;
    }

    write_runlog(LOG, "start cluster. \n");
    start_cluster();
    return CM_SUCCESS;
}

static status_t WaitCmsPrimaryNormal(CM_Conn **pCmsConn)
{
    int times = 0;

    while (*pCmsConn == NULL) {
        if (times++ > SHARED_STORAGE_MODE_TIMEOUT) {
            write_runlog(ERROR, "connect primary timeout.\n");
            return CM_ERROR;
        }
        do_conn_cmserver(false, 0, false, pCmsConn);
        cm_sleep(1);
    }

    return CM_SUCCESS;
}

static bool CheckOfflineInstance(uint32 node)
{
    uint32 nodeid = 0;
    CM_Conn *pCmsCon = NULL;

    if (!IsCmSharedStorageMode()) {
        return false;
    }

    if ((node < 1) || (get_node_index(node) >= g_node_num)) {
        write_runlog(ERROR, "node(%u) is invalid, max node num(%u)  \n", node, g_node_num);
        return false;
    }
    for (uint32 j = 0; j < g_node_num; j++) {
        if (g_node[j].node != node) {
            continue;
        }
        nodeid = j;
        break;
    }
    if (WaitCmsPrimaryNormal(&pCmsCon) != CM_SUCCESS) {
        return false;
    }

    bool result = SetOfflineNode(nodeid, pCmsCon);
    ReleaseConn(pCmsCon);

    return result;
}

status_t do_start(void)
{
    CtlGetCmJsonConf();
    int ret;
    pthread_t checkStatusThrId;
    pthread_t startCheckThrId;
    g_startExitCode = CM_START_EXIT_INIT;
#ifndef ENABLE_MULTIPLE_NODES
    int nodeNumsInAz = 0;
    struct stat libnetManualStat = {0};
    int ltranCheckTimes = 0;
    (void)atexit(RemoveStartingFile);
#endif
    if (g_commandOperationNodeId > 0 && get_node_index(g_commandOperationNodeId) >= g_node_num) {
        write_runlog(FATAL, "node_id specified is illegal. \n");
        return CM_ERROR;
    }

    (void)clock_gettime(CLOCK_MONOTONIC, &g_startTime);
    (void)getPauseStatus();
    /* start the whole cluster */
    if (g_commandOperationInstanceId == 0 && g_command_operation_azName == NULL && g_commandOperationNodeId == 0) {
#ifdef ENABLE_MULTIPLE_NODES
        if (cn_resumes_restart) {
            write_stderr(_("%s: enable resuming the fault CN.\n"), g_progname);
            remove_stop_resuming_cn_file();
            return CM_SUCCESS;
        }
#endif
        CM_RETURN_IFERR(StartWholeCluster());
    } else if (g_command_operation_azName != NULL) {
        if (cm_arbitration_mode_set != NULL) {
            if (isMinority(cm_arbitration_mode_set)) {
                if (g_currentNode->cmServerLevel != 1) {
                    write_runlog(
                        FATAL, "The minority AZ starting command can only be executed on nodes with CM Server. \n");
                    return CM_ERROR;
                }

                write_runlog(LOG, "Minority cluster! The cluster data may be lost: RPO !=0.\n");
            } else if (isMajority(cm_arbitration_mode_set)) {
                write_runlog(LOG, "Majority cluster! The minority cluster settings will be clear if they exist.\n");
            } else {
                write_runlog(FATAL, "invalid cm server arbitration mode.\n");
                DoAdvice();
                return CM_ERROR;
            }
        }
#ifndef ENABLE_MULTIPLE_NODES
        if (stat(g_libnetManualStartFile, &libnetManualStat) == 0) {
            write_runlog(LOG, "start ltran processes. \n");
            for (uint32 ii = 0; ii < g_node_num; ii++) {
                if (strcmp(g_node[ii].azName, g_command_operation_azName) == 0) {
                    if (g_node[ii].datanodeCount == 0) {
                        continue;
                    }
                    nodeNumsInAz++;
                    if (StartLtranProcessByNode(g_node[ii].node) != 0) {
                        write_runlog(ERROR, "start the ltran processes failed. \n");
                        return CM_ERROR;
                    }
                }
            }
            int aliveLtranNum = 0;
            ltranCheckTimes = 0;
            while (aliveLtranNum < nodeNumsInAz && ltranCheckTimes < LTRAN_CHECK_TIMES) {
                aliveLtranNum = 0;
                ltranCheckTimes++;
                for (uint32 ii = 0; ii < g_node_num; ii++) {
                    if (strcmp(g_node[ii].azName, g_command_operation_azName) == 0 && g_node[ii].datanodeCount > 0) {
                        if (CM_STATUS_NORMAL == start_check_instance(ii, "ltran")) {
                            aliveLtranNum++;
                        }
                    }
                }
                write_runlog(DEBUG1, "ltran processes check %d times\n", ltranCheckTimes);
                cm_sleep(LTRAN_CHECK_INTERVAL);
            }
            if (!CheckLibosKniIsOk()) {
                write_runlog(ERROR, "start the ltran processes failed. \n");
                return CM_ERROR;
            }
            write_runlog(LOG, "start the ltran processes successfully. \n");
        }
#endif
        if (g_etcd_num > 0) {
            /* start etcd firstly. */
            start_and_check_etcd_az(g_command_operation_azName);

            write_runlog(LOG, "checking the ETCD cluster status.\n");
            check_etcd_cluster_status();
        }

        /* start a az with availability zone name */
        write_runlog(LOG, "start the availability zone: %s. \n", g_command_operation_azName);
        start_az(g_command_operation_azName);
    } else if (g_commandOperationInstanceId > 0) {
        if (CheckResInstInfo(&g_commandOperationNodeId, g_commandOperationInstanceId) != CM_SUCCESS) {
            write_runlog(ERROR, "can't do start resource instance, instId:%u.\n", g_commandOperationInstanceId);
            return CM_ERROR;
        }
        write_runlog(LOG, "start resource instance, instId:%u.\n", g_commandOperationInstanceId);
        StartAllResInstByNode(g_commandOperationNodeId);
    } else if (g_cmData[0] == '\0') {
        // start all instance of one node
#ifndef ENABLE_MULTIPLE_NODES
        if (stat(g_libnetManualStartFile, &libnetManualStat) == 0) {
            write_runlog(LOG, "start ltran process. \n");
            uint32 ii = 0;
            for (ii = 0; ii < g_node_num; ii++) {
                if (g_node[ii].node == g_commandOperationNodeId) {
                    break;
                }
            }
            if (ii >= g_node_num) {
                write_runlog(FATAL, "can't find the nodeid: %u\n", g_commandOperationNodeId);
                return CM_ERROR;
            }

            if (g_node[ii].datanodeCount > 0 && StartLtranProcessByNode(g_commandOperationNodeId) != 0) {
                write_runlog(ERROR, "start the ltran process failed. \n");
                return CM_ERROR;
            }
            ltranCheckTimes = 0;
            while (CM_STATUS_NORMAL != start_check_instance(ii, "ltran") && ltranCheckTimes < LTRAN_CHECK_TIMES) {
                ltranCheckTimes++;
                cm_sleep(LTRAN_CHECK_INTERVAL);
                write_runlog(DEBUG1, "ltran process checks %d times\n", ltranCheckTimes);
            }
            if (!CheckLibosKniIsOk()) {
                write_runlog(ERROR, "start the ltran process failed. \n");
                return CM_ERROR;
            }
            write_runlog(LOG, "start the ltran process successfully. \n");
        }
#endif
        /* start etcd firstly. */
        start_and_check_etcd_node(g_commandOperationNodeId);

        /*  if etcd cluster is not available, cm_ctl can not start the node. */
        if (g_etcd_num > 0) {
            write_runlog(LOG, "checking the ETCD cluster status\n");
            check_etcd_cluster_status();
        }

        /* start a node with node_id */
        write_runlog(LOG, "start the node:%u. \n", g_commandOperationNodeId);
        start_node(g_commandOperationNodeId);
    } else if (g_commandRelationship) {
        if (g_commandOperationNodeId == 0) {
            write_runlog(FATAL, "node_id specified is illegal. \n");
            return CM_ERROR;
        }
        if (g_cmData[0] == '\0') {
            write_runlog(FATAL, "data path specified is illegal. \n");
            return CM_ERROR;
        }
        write_runlog(LOG, "start relation datanode.\n");
        start_datanode_instance_relation(g_commandOperationNodeId, g_cmData);
    } else {
        if (CheckOfflineInstance(g_commandOperationNodeId)) {
            write_runlog(LOG, "the instance(node:%u) is Offline, no need to start.\n", g_commandOperationNodeId);
            exit(0);
        }
        write_runlog(LOG, "start the node:%u,datapath:%s. \n", g_commandOperationNodeId, g_cmData);
        start_instance(g_commandOperationNodeId, g_cmData);
    }

    /* create a thread to check cluster's status */
    ret = pthread_create(&checkStatusThrId, NULL, &check_cluster_start_status, NULL);
    if (ret != 0) {
        write_runlog(FATAL, "failed to create thread to check if cluster started.\n");
        return CM_ERROR;
    }

    /* check node's status */
    ret = pthread_create(&startCheckThrId, NULL, &start_check, NULL);
    if (ret != 0) {
        write_runlog(FATAL, "failed to create start check thread.\n");
        return CM_ERROR;
    }

    (void)pthread_join(startCheckThrId, NULL);
    exit((int)g_startExitCode);
}

/*
 * @Description: start ETCD cluster.
 * if failed in 30 sec, ETCD cluster should stopped forcely and MPPDB cluster can not be started.
 */
static void start_and_check_etcd_cluster()
{
    if (g_etcd_num == 0) {
        return;
    }
    uint32 ii = 0;

    start_etcd_cluster();
    while (ii < ETCD_START_WAIT) {
        (void)sleep(1);
        write_runlog(LOG, ".");
        if (get_alive_etcd_node_count() > g_etcd_num / 2 && CheckDdbHealth()) {
            write_runlog(LOG, "the ETCD cluster starts successfully.\n");

            if (g_multi_az_cluster && isMinority(cm_arbitration_mode_set)) {
                write_runlog(
                    FATAL, "The minority AZ starting command can only be executed while ETCD cluster is unhealthy. \n");
                exit(1);
            }
            break;
        }
        ii++;
    }
    if (ii == ETCD_START_WAIT) {
        write_runlog(ERROR, "failed to start the ETCD cluster.\n");
        if (g_multi_az_cluster && isMinority(cm_arbitration_mode_set)) {
        /* for one-primary-multi-standby, do minority start (az1 and az2 are fault, force to start az3,
        az3 has only one etcd/dn/cn/gtm/cms/cma), when etcd start failed, continue to start other instance */
        } else {
            stop_etcd_cluster();
            exit(1);
        }
    }
}

static void start_cluster(void)
{
    if (got_stop) {
        return;
    }
    char command[MAXPGPATH] = {0};
    int ret = 0;

    init_hosts();

    for (uint32 ii = 0; ii < g_node_num; ii++) {
        write_runlog(LOG, "start nodeid: %u\n", g_node[ii].node);
    }

    /*
     * in case that cm_ctl can't set start command to etcd or om_monitor can't get start command from etcd, cm_ctl
     * need also start cluster by removing cluster_manual_start file through pssh, which has better performance than
     * ssh.
     */
    if (g_single_node_cluster) {
        if (mpp_env_separate_file[0] == '\0') {
            ret = snprintf_s(command,
                MAXPGPATH,
                MAXPGPATH - 1,
                SYSTEMQUOTE "source /etc/profile; rm -f %s %s_*" SYSTEMQUOTE,
                manual_start_file,
                instance_manual_start_file);
        } else {
            ret = snprintf_s(command,
                MAXPGPATH,
                MAXPGPATH - 1,
                SYSTEMQUOTE "source /etc/profile; source %s; rm -f %s %s_*" SYSTEMQUOTE,
                mpp_env_separate_file,
                manual_start_file,
                instance_manual_start_file);
        }
    } else {
        if (mpp_env_separate_file[0] == '\0') {
            ret = snprintf_s(command,
                MAXPGPATH,
                MAXPGPATH - 1,
                SYSTEMQUOTE "source /etc/profile; "
                        "pssh -i %s -h %s \"rm -f %s %s_*; if [ -f %s ]; then touch %s; fi\" > %s; "
                        "if [ $? -ne 0 ]; then cat %s; fi; rm -f %s" SYSTEMQUOTE,
                PSSH_TIMEOUT_OPTION,
                hosts_path,
                manual_start_file,
                instance_manual_start_file,
                manual_pause_file,
		        cluster_manual_starting_file,
                pssh_out_path,
                pssh_out_path,
                pssh_out_path);
        } else {
            ret = snprintf_s(command,
                MAXPGPATH,
                MAXPGPATH - 1,
                SYSTEMQUOTE "source /etc/profile;"
                        "pssh -i %s -h %s \"source %s; rm -f %s %s_*; if [ -f %s ]; then touch %s; fi\" > %s; "
                        "if [ $? -ne 0 ]; then cat %s; fi; rm -f %s" SYSTEMQUOTE,
                PSSH_TIMEOUT_OPTION,
                hosts_path,
                mpp_env_separate_file,
                manual_start_file,
                instance_manual_start_file,
                manual_pause_file,
                cluster_manual_starting_file,
                pssh_out_path,
                pssh_out_path,
                pssh_out_path);
        }
    }
    securec_check_intval(ret, (void)ret);

    ret = system(command);
    if (ret != 0) {
        write_runlog(DEBUG1,
            "Failed to start the cluster with executing the command: command=\"%s\","
            " nodeId=%u, systemReturn=%d, shellReturn=%d, errno=%d.\n",
            command,
            g_currentNode->node,
            ret,
            SHELL_RETURN_CODE(ret),
            errno);
    }

    (void)unlink(hosts_path);
}

static void start_etcd_cluster(void)
{
    char command[MAXPGPATH];
    int ret = 0;

    for (uint32 ii = 0; ii < g_node_num; ii++) {
        if (!g_node[ii].etcd) {
            continue;
        }
        ret = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1, SYSTEMQUOTE "rm -f %s < \"%s\" 2>&1" SYSTEMQUOTE,
            etcd_manual_start_file, DEVNULL);
        securec_check_intval(ret, (void)ret);
        ret = RunEtcdCmd(command, ii);
        if (ret != 0) {
            write_runlog(DEBUG1, "Failed to start the etcd node with executing the command: command=\"%s\","
                " nodeId=%u, systemReturn=%d, shellReturn=%d, errno=%d.\n",
                command, g_node[ii].node, ret, SHELL_RETURN_CODE(ret), errno);
        }
    }
}

/*
 * @Description: get the count of etcd which is running.
 *
 * @out: count of etcd which is running
 */
static uint32 get_alive_etcd_node_count()
{
    uint32 alive_count = 0;

    for (uint32 i = 0; i < g_node_num; i++) {
        if (g_node[i].etcd && start_check_instance(i, "etcd") == CM_STATUS_NORMAL) {
            alive_count++;
        }
    }
    return alive_count;
}
#ifndef ENABLE_MULTIPLE_NODES
static void StartLtranProcess()
{
    char command[MAXPGPATH];
    int ret = 0;
    uint32 ltranAliveNum = 0;
    uint32 dnNodeNums = 0;
    int ltranCheckTimes = 0;
    write_runlog(LOG, "start the ltran cluster.\n");
    for (uint32 ii = 0; ii < g_node_num; ii++) {
        if (g_node[ii].datanodeCount > 0) {
            dnNodeNums++;
            ret = snprintf_s(command,
                MAXPGPATH,
                MAXPGPATH - 1,
                SYSTEMQUOTE "rm -f %s < \"%s\" 2>&1" SYSTEMQUOTE,
                g_ltranManualStartFile,
                DEVNULL);
            securec_check_intval(ret, (void)ret);
            if (g_node[ii].node == g_currentNode->node) {
                ret = system(command);
            } else {
                ret = ssh_exec(&g_node[ii], command);
            }
            if (ret != 0) {
                write_runlog(DEBUG1,
                    "Failed to start the ltran process with executing the command: command=\"%s\","
                    " nodeId=%u, systemReturn=%d, shellReturn=%d, errno=%d.\n",
                    command,
                    g_node[ii].node,
                    ret,
                    SHELL_RETURN_CODE(ret),
                    errno);
            }
        }
    }
    while (ltranAliveNum < dnNodeNums && ltranCheckTimes < LTRAN_CHECK_TIMES) {
        ltranCheckTimes++;
        ltranAliveNum = 0;
        for (uint32 ii = 0; ii < g_node_num; ii++) {
            if (g_node[ii].datanodeCount > 0 && CM_STATUS_NORMAL == start_check_instance(ii, "ltran")) {
                ltranAliveNum++;
            }
        }
        cm_sleep(LTRAN_CHECK_INTERVAL);
        write_runlog(LOG, ".");
        write_runlog(DEBUG1, "ltran cluster checks %d times\n", ltranCheckTimes);
    }
}

static int StartLtranProcessByNode(uint32 nodeid)
{
    char command[MAXPGPATH];
    int ret;

    ret = snprintf_s(command,
        MAXPGPATH,
        MAXPGPATH - 1,
        SYSTEMQUOTE "rm -f %s < \"%s\" 2>&1 &" SYSTEMQUOTE,
        g_ltranManualStartFile,
        DEVNULL);
    securec_check_intval(ret, (void)ret);

    ret = runCmdByNodeId(command, nodeid);
    if (ret != 0) {
        write_runlog(DEBUG1,
            "Failed to start the ltran process with executing the command: command=\"%s\","
            " nodeId=%u, systemReturn=%d, shellReturn=%d, errno=%d.\n",
            command,
            nodeid,
            ret,
            SHELL_RETURN_CODE(ret),
            errno);
    }
    return ret;
}

static bool ExecCheckCmd(const char* printStr, const char* cmd, const uint32 cmdCount)
{
    char checkCmd[MAXPGPATH] = {0};
    char buf[MAXPGPATH];
    if (cmd != NULL) {
        int rcs = memcpy_s(checkCmd, MAXPGPATH, cmd, cmdCount);
        securec_check_c(rcs, "", "");
        write_runlog(DEBUG1, "cheak_libnet %s command is %s.\n", printStr, checkCmd);
    }

    FILE* fp = popen(checkCmd, "r");
    if (fp == NULL) {
        write_runlog(ERROR, "popen failed\n");
        return false;
    }
    if (fgets(buf, sizeof(buf), fp) != NULL) {
        if (strstr(buf, "success") != NULL) {
            (void)pclose(fp);
        } else {
            (void)pclose(fp);
            write_runlog(DEBUG1, "%s cheack failed.\n", printStr);
            return false;
        }
    }

    write_runlog(DEBUG1, "%s cheack OK by exec command:%s.\n", printStr, cmd);
    return true;
}

static bool CheckLibosKniIsOk()
{
    char checkKniCmd[MAXPGPATH] = {0};
    char checkIpCmd[MAXPGPATH] = {0};
    char checPingCmd[MAXPGPATH] = {0};
    const int items = 3;
    char* checkItem[items] = {"libnet_kni", "libnet_ip", "libnet_ping"};
    uint32 cmdCount = 0;
    int idx = 0;
    bool checkRes = true;

    int rc = strcpy_s(checkKniCmd, MAXPGPATH,
        "ifconfig | grep libos_kni  > /dev/null;if [ $? == 0 ];then echo success;else echo fail;fi;");
    securec_check_errno(rc, (void)rc);
    write_runlog(DEBUG1, "cheak_libnet kni command is %s.\n", checkKniCmd);
    cmdCount = strlen(checkKniCmd);
    checkRes = ExecCheckCmd(checkItem[idx++], checkKniCmd, cmdCount);
    if (checkRes == false) {
        write_runlog(DEBUG1, "%s cheack failed by exec command:%s.\n", checkItem[idx++], checkKniCmd);
        return false;
    }

    rc = snprintf_s(checkIpCmd,
        MAXPGPATH,
        MAXPGPATH - 1,
        "ifconfig | grep %s  > /dev/null;if [ $? == 0 ];then echo success;else echo fail;fi;",
        g_currentNode->cmAgentIP);
    securec_check_intval(rc, (void)rc);
    write_runlog(DEBUG1, "cheak_libnet ip command is %s.\n", checkIpCmd);
    cmdCount = strlen(checkIpCmd);
    checkRes = ExecCheckCmd(checkItem[idx++], checkIpCmd, cmdCount);
    if (checkRes == false) {
        write_runlog(DEBUG1, "%s cheack failed by exec command:%s.\n", checkItem[idx++], checkIpCmd);
        return false;
    }
    const char *ping_ip = *g_currentNode->cmAgentIP;
    const char *pingStr = GetPingStr(GetIpVersion(ping_ip));
    rc = snprintf_s(checPingCmd,
        MAXPGPATH,
        MAXPGPATH - 1,
        "%s -c 1 -w 1 %s  > /dev/null;if [ $? == 0 ];then echo success;else echo fail;fi;",
        pingStr, ping_ip);
    securec_check_intval(rc, (void)rc);
    write_runlog(DEBUG1, "cheak_libnet ping command is %s.\n", checPingCmd);
    cmdCount = strlen(checPingCmd);
    checkRes = ExecCheckCmd(checkItem[idx], checPingCmd, cmdCount);
    if (checkRes == false) {
        write_runlog(DEBUG1, "%s cheack failed by exec command:%s.\n", checkItem[idx], checPingCmd);
        return false;
    }

    write_runlog(DEBUG1, "libos_kni and libos_ip cheack OK.\n");
    return true;
}
#endif

/*
 * @Description: start ETCD node in AZ.
 * if failed in 30 sec, ETCD node should stopped forcely.
 */
static void start_and_check_etcd_az(const char* azName)
{
    uint32 ii;
    uint32 etcd_count = 0;
    uint32 etcd_alive_count;
    uint32 wait_count = 0;
    write_runlog(LOG, "start ETCD in availability zone, availability zone name: %s.\n", azName);

    for (ii = 0; ii < g_node_num; ii++) {
        if (strcmp(g_node[ii].azName, azName) == 0) {
            if (g_node[ii].etcd) {
                start_etcd_node(g_node[ii].node);
                etcd_count++;
            }
        }
    }

    while (wait_count < ETCD_START_WAIT) {
        (void)sleep(1);
        write_runlog(LOG, ".");
        etcd_alive_count = 0;

        for (ii = 0; ii < g_node_num; ii++) {
            if (strcmp(g_node[ii].azName, azName) == 0) {
                if (g_node[ii].etcd) {
                    if (start_check_instance(ii, "etcd") == CM_STATUS_NORMAL) {
                        etcd_alive_count++;
                    }
                }
            }
        }

        if (etcd_alive_count == etcd_count) {
            write_runlog(LOG, "the ETCD instances in this availability zone start successfully.\n");
            break;
        }

        wait_count++;
    }

    if (wait_count == ETCD_START_WAIT) {
        write_runlog(LOG, "failed to start all ETCD in this availability zone.\n");
        for (ii = 0; ii < g_node_num; ii++) {
            if (strcmp(g_node[ii].azName, azName) == 0) {
                if (g_node[ii].etcd) {
                    stop_etcd_node(g_node[ii].node);
                }
            }
        }
    }
}

/*
 * start etcd of specified node
 */
static void start_etcd_node(uint32 nodeid)
{
    char command[MAXPGPATH] = {0};
    int ret;

    write_runlog(LOG, "start ETCD in node, nodeid: %u\n", nodeid);

    ret = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1, SYSTEMQUOTE "rm -f %s < \"%s\" 2>&1 &" SYSTEMQUOTE,
        etcd_manual_start_file, DEVNULL);
    securec_check_intval(ret, (void)ret);

    ret = runCmdByNodeId(command, nodeid);
    if (ret != 0) {
        write_runlog(DEBUG1, "Failed to start the etcd node with executing the command: command=\"%s\","
            " nodeId=%u, systemReturn=%d, shellReturn=%d, errno=%d.\n", command, nodeid, ret, SHELL_RETURN_CODE(ret),
            errno);
    }
}

#ifndef ENABLE_MULTIPLE_NODES
static int StartCheckLtranProcess(uint32 nodeIdCheck, const char* datapath)
{
    int ret;
    int result = -1;
    char resultPath[MAXPGPATH] = {0};
    int fd;
    bool flag = false;
    char checkLtranProcessResultPath[MAX_PATH_LEN] = {0};
    if (strcmp(datapath, "ltran") == 0) {
        ret = GetHomePath(resultPath, sizeof(resultPath));
        if (ret != EOK) {
            return CM_STATUS_UNKNOWN;
        }
        ret = snprintf_s(checkLtranProcessResultPath, MAX_PATH_LEN, MAX_PATH_LEN - 1,
            "%s/bin/checkLtranProcessResult-XXXXXX", resultPath);
        securec_check_intval(ret, (void)ret);

        fd = mkstemp(checkLtranProcessResultPath);
        if (fd <= 0) {
            write_runlog(ERROR, "failed to create the ltran process check result file: errno=%d.\n", errno);
            flag = true;
        }
        char command[MAXPGPATH] = {0};
        if (nodeIdCheck == g_nodeId && strstr(g_appPath, "/var/chroot") == NULL) {
            ret = snprintf_s(command,
                MAXPGPATH,
                MAXPGPATH - 1,
                "cm_ctl check -B ltran -T ltran  \n echo  -e  $? > %s",
                flag ? result_path : checkLtranProcessResultPath);
            securec_check_intval(ret, (void)ret);
            exec_system(command, &result, flag ? result_path : checkLtranProcessResultPath);
        } else {
            ret = snprintf_s(command,
                MAXPGPATH,
                MAXPGPATH - 1,
                "cm_ctl check -B ltran -T ltran\" > /dev/null 2>&1; echo  -e $? > %s",
                flag ? result_path : checkLtranProcessResultPath);
            securec_check_intval(ret, (void)ret);
            exec_system_ssh(
                nodeIdCheck, command, &result, flag ? result_path : checkLtranProcessResultPath, mpp_env_separate_file);
        }
        if (fd > 0) {
            (void)close(fd);
        }
        (void)unlink(flag ? result_path : checkLtranProcessResultPath);
        return (result == PROCESS_RUNNING) ? CM_STATUS_NORMAL : CM_STATUS_UNKNOWN;
    }
    return CM_STATUS_UNKNOWN;
}
#endif

static int start_check_instance(uint32 node_id_check, const char* datapath)
{
    int result = -1;
    CM_Conn *pCmsCon = NULL;

    if (checkStaticConfigExist(node_id_check) != 0) {
        write_runlog(
            ERROR, "the cluster static config file does not exist on the node: %u.\n", g_node[node_id_check].node);
        write_runlog(FATAL, "failed to check the instance running status: %s.\n", datapath);
        return CM_STATUS_UNKNOWN;
    }

    /* coordinator */
    if (g_node[node_id_check].coordinate == 1 && strncmp(datapath, g_node[node_id_check].DataPath, MAX_PATH_LEN) == 0) {
        CheckCnNodeStatusById(node_id_check, &result);
        return (result == PROCESS_RUNNING) ? CM_STATUS_NORMAL : CM_STATUS_UNKNOWN;
    }

    /* datanode */
    for (uint32 ii = 0; ii < g_node[node_id_check].datanodeCount; ii++) {
        char* local_data_path = g_node[node_id_check].datanode[ii].datanodeLocalDataPath;
        if (strncmp(datapath, local_data_path, MAX_PATH_LEN) != 0) {
            continue;
        }
        if (IsCmSharedStorageMode()) {
            if (WaitCmsPrimaryNormal(&pCmsCon) != CM_SUCCESS) {
                return CM_STATUS_UNKNOWN;
            }
            if (SetOfflineNode(node_id_check, pCmsCon)) {
                ReleaseConn(pCmsCon);
                return CM_STATUS_NORMAL;
            }
            ReleaseConn(pCmsCon);
        }
        CheckDnNodeStatusById(node_id_check, &result, ii);
        return (result == PROCESS_RUNNING) ? CM_STATUS_NORMAL : CM_STATUS_UNKNOWN;
    }

    /* gtm */
    if (g_node[node_id_check].gtm == 1 &&
        strncmp(datapath, g_node[node_id_check].gtmLocalDataPath, MAX_PATH_LEN) == 0) {
        CheckGtmNodeStatusById(node_id_check, &result);
        return (result == PROCESS_RUNNING) ? CM_STATUS_NORMAL : CM_STATUS_UNKNOWN;
    }

    if (strcmp(datapath, "etcd") == 0) {
        int ret;
        char resultPath[MAXPGPATH] = {0};
        char checkEtcdProcessResultPath[MAX_PATH_LEN] = {0};
        int fd;
        bool flag = false;

        ret = GetHomePath(resultPath, sizeof(resultPath));
        if (ret != EOK) {
            return CM_STATUS_UNKNOWN;
        }
        ret = snprintf_s(checkEtcdProcessResultPath, MAX_PATH_LEN, MAX_PATH_LEN - 1,
            "%s/bin/checkEtcdProcessResult-XXXXXX", resultPath);
        securec_check_intval(ret, (void)ret);

        fd = mkstemp(checkEtcdProcessResultPath);
        if (fd <= 0) {
            write_runlog(ERROR, "failed to create the etcd process check result file: errno=%d.\n", errno);
            flag = true;
        }

        /* etcd */
        if (g_node[node_id_check].etcd == 1) {
            char command[MAXPGPATH] = {0};

            if (node_id_check == g_nodeId && strstr(g_appPath, "/var/chroot") == NULL) {
                ret = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1,
                    "cm_ctl check -B etcd -T %s/bin/etcd  \n echo  -e  $? > %s",
                    g_appPath, flag ? result_path : checkEtcdProcessResultPath);
                securec_check_intval(ret, (void)ret);
                exec_system(command, &result, flag ? result_path : checkEtcdProcessResultPath);
            } else {
                ret = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1,
                    "cm_ctl check -B etcd -T %s/bin/etcd\" > /dev/null 2>&1; echo  -e $? > %s",
                    g_appPath, flag ? result_path : checkEtcdProcessResultPath);
                securec_check_intval(ret, (void)ret);
                exec_system_ssh(node_id_check, command, &result, flag ? result_path : checkEtcdProcessResultPath,
                    mpp_env_separate_file);
            }
            if (fd > 0) {
                (void)close(fd);
            }
            (void)unlink(flag ? result_path : checkEtcdProcessResultPath);
            return (result == PROCESS_RUNNING) ? CM_STATUS_NORMAL : CM_STATUS_UNKNOWN;
        }
        if (fd > 0) {
            (void)close(fd);
        }
        (void)unlink(flag ? result_path : checkEtcdProcessResultPath);
    }

#ifndef ENABLE_MULTIPLE_NODES
    return StartCheckLtranProcess(node_id_check, datapath);
#endif

    return CM_STATUS_UNKNOWN;
}

/*
 * @Description: check ETCD cluster status.
 * if failed in 30 sec, MPPDB node can not be started.
 */
static void check_etcd_cluster_status()
{
    if (g_etcd_num == 0) {
        return;
    }
    uint32 ii;

    /*
     * etcd node just started up and etcd cluster can't be healthy right now.
     * so cm_ctl check  etcd cluster status 30 times.
     */
    for (ii = 0; ii < ETCD_START_WAIT; ii++) {
        (void)sleep(1);
        write_runlog(LOG, ".");

        /* isMinority Az start */
        if (isMinority(cm_arbitration_mode_set) &&
            GetAliveEtcdNumOfAz(g_command_operation_azName) == GetEtcdNumOfAz(g_command_operation_azName)) {
            write_runlog(DEBUG1, "The minority AZ starting check ETCD cluster finished.\n");
            break;
        }

        if (CheckDdbHealth()) {
            write_runlog(LOG, "check ETCD cluster finished.\n");

            if (g_multi_az_cluster && isMinority(cm_arbitration_mode_set)) {
                write_runlog(
                    FATAL, "The minority AZ starting command can only be executed while ETCD cluster is unhealthy. \n");
                exit(1);
            }

            break;
        }
    }
    if (ii == ETCD_START_WAIT) {
        write_runlog(ERROR, "ETCD cluster is unhealthy. \n");
        if (g_multi_az_cluster && !isMinority(cm_arbitration_mode_set)) {
            exit(1);
        }
    }
}

static void MinorityStartPreSetGTM(uint32 nodeIdx)
{
    char command[MAXPGPATH];
    char command_opts[MAXPGPATH];
    int ret;

    // set local gtm and the other gtm sync mode
    for (unsigned int i = 0; i < g_node_num; i++) {
        if (strcmp(g_node[i].azName, g_node[nodeIdx].azName) != 0 || i == nodeIdx) {
            continue;
        }

        if (g_node[i].gtm == 1) {
            if (g_currentNode->node == g_node[nodeIdx].node) {
                ret = snprintf_s(command_opts,
                    MAXPGPATH,
                    MAXPGPATH - 1,
                    "gs_guc reload -Z gtm -D %s -c \"active_host = '%s'\" -c \"active_port = '%u'\"",
                    g_node[nodeIdx].gtmLocalDataPath,
                    g_node[i].gtmLocalHAIP,
                    g_node[i].gtmLocalHAPort);
            } else {
                ret = snprintf_s(command_opts,
                    MAXPGPATH,
                    MAXPGPATH - 1,
                    "gs_guc reload -Z gtm -D %s -c \\\"active_host = '%s'\\\" -c \\\"active_port = '%u'\\\"",
                    g_node[nodeIdx].gtmLocalDataPath,
                    g_node[i].gtmLocalHAIP,
                    g_node[i].gtmLocalHAPort);
            }
            securec_check_intval(ret, (void)ret);

            ret = snprintf_s(command,
                MAXPGPATH,
                MAXPGPATH - 1,
                SYSTEMQUOTE "%s > %s 2>&1 &" SYSTEMQUOTE,
                command_opts,
                DEVNULL);
            securec_check_intval(ret, (void)ret);
            RunCmdInStartAz(command, nodeIdx);
            break;
        }
    }

    if (g_currentNode->node == g_node[nodeIdx].node) {
        ret = snprintf_s(command_opts, MAXPGPATH, MAXPGPATH - 1, "gs_guc reload -Z gtm -D %s -c \"standby_only = 1\"",
            g_node[nodeIdx].gtmLocalDataPath);
    } else {
        ret = snprintf_s(command_opts, MAXPGPATH, MAXPGPATH - 1,
            "gs_guc reload -Z gtm -D %s -c \\\"standby_only = 1\\\"", g_node[nodeIdx].gtmLocalDataPath);
    }
    securec_check_intval(ret, (void)ret);

    ret = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1, SYSTEMQUOTE "%s > %s 2>&1 &" SYSTEMQUOTE,
        command_opts, DEVNULL);
    securec_check_intval(ret, (void)ret);
    RunCmdInStartAz(command, nodeIdx);
}

static void MinorityStartPreSetServer(uint32 nodeIdx)
{
    char command[MAXPGPATH];
    char command_opts[MAXPGPATH];
    cm_start_mode mode;
    int ret;

    mode = (g_currentNode->node == g_node[nodeIdx].node) ? MINORITY_START : OTHER_MINORITY_START;

    // make minority start file at all cm_server nodes in pointed az
    ret = snprintf_s(command_opts, MAXPGPATH, MAXPGPATH - 1, "echo -e \'%d\' >  %s; chmod 600 %s",
        mode, minority_az_start_file, minority_az_start_file);
    securec_check_intval(ret, (void)ret);

    ret = snprintf_s(
        command, MAXPGPATH, MAXPGPATH - 1, SYSTEMQUOTE "%s > %s 2>&1 &" SYSTEMQUOTE, command_opts, DEVNULL);
    securec_check_intval(ret, (void)ret);
    RunCmdInStartAz(command, nodeIdx);

    // make minority arbitrate history file in primary cm_server
    if (mode == MINORITY_START) {
        ret = snprintf_s(command_opts, MAXPGPATH, MAXPGPATH - 1, "touch %s; chmod 600 %s",
            g_minorityAzArbitrateFile, g_minorityAzArbitrateFile);
        securec_check_intval(ret, (void)ret);

        ret = snprintf_s(
            command, MAXPGPATH, MAXPGPATH - 1, SYSTEMQUOTE "%s > %s 2>&1 &" SYSTEMQUOTE, command_opts, DEVNULL);
        securec_check_intval(ret, (void)ret);
        RunCmdInStartAz(command, nodeIdx);
    }
}

static void MinorityStartPreSet(uint32 nodeIdx, uint32 repNumInAZ)
{
    // modify cm_server for minority start
    if (g_node[nodeIdx].cmServerLevel == 1) {
        MinorityStartPreSetServer(nodeIdx);
    }

    if (g_node[nodeIdx].gtm == 1) {
        MinorityStartPreSetGTM(nodeIdx);
    }

    ExecuteGsGuc(NULL, (repNumInAZ == 1), repNumInAZ, nodeIdx);
}

static void MajorityStartPreSetServer(uint32 nodeIdx)
{
    char command[MAXPGPATH];
    char command_opts[MAXPGPATH];
    int ret;

    // remove minority file
    ret = snprintf_s(command_opts, MAXPGPATH, MAXPGPATH - 1, "rm -f %s;", minority_az_start_file);
    securec_check_intval(ret, (void)ret);

    ret = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1, SYSTEMQUOTE "%s > %s 2>&1 &" SYSTEMQUOTE,
        command_opts, DEVNULL);
    securec_check_intval(ret, (void)ret);
    RunCmdInStartAz(command, nodeIdx);
}

static void MajorityStartPreSetGTM(uint32 nodeIdx)
{
    char command[MAXPGPATH];
    char command_opts[MAXPGPATH];
    int ret;

    if (g_currentNode->node == g_node[nodeIdx].node) {
        ret = snprintf_s(command_opts,
            MAXPGPATH,
            MAXPGPATH - 1,
            "gs_guc reload -Z gtm -D %s -c \"standby_only = 0\" -c \"active_host = ''\" "
            "-c \"active_port = '1'\"",
            g_node[nodeIdx].gtmLocalDataPath);
    } else {
        ret = snprintf_s(command_opts,
            MAXPGPATH,
            MAXPGPATH - 1,
            "gs_guc reload -Z gtm -D %s -c \\\"standby_only = 0\\\" -c \\\"active_host = ''\\\" "
            "-c \\\"active_port = '1'\\\"",
            g_node[nodeIdx].gtmLocalDataPath);
    }
    securec_check_intval(ret, (void)ret);

    ret = snprintf_s(
        command, MAXPGPATH, MAXPGPATH - 1, SYSTEMQUOTE "%s > %s 2>&1 &" SYSTEMQUOTE, command_opts, DEVNULL);
    securec_check_intval(ret, (void)ret);
    RunCmdInStartAz(command, nodeIdx);
}

static void MajorityStartPreSet(uint32 nodeIdx, uint32 repNumInAZ, const char *azAllStr)
{
    // modify cm_server for majority start
    if (g_node[nodeIdx].cmServerLevel == 1) {
        MajorityStartPreSetServer(nodeIdx);
    }

    if (g_node[nodeIdx].gtm == 1) {
        MajorityStartPreSetGTM(nodeIdx);
    }

    // dn
    ExecuteGsGuc(azAllStr, (repNumInAZ == 1), g_dn_replication_num, nodeIdx);
}

static void StartAz4Force(const char* azName)
{
    const uint32 maxAzNum = 5;
    char *azLists[maxAzNum];
    int rc = memset_s(azLists, sizeof(char *) * maxAzNum, 0, sizeof(char *) * maxAzNum);
    securec_check_errno(rc, (void)rc);
    // find repNum in pointed az
    uint32 mirrorId, repNumInAZ = 0;
    for (uint32 i = 0; i < g_node_num; i++) {
        if (g_node[i].datanodeCount == 0) {
            continue;
        }
        for (uint32 j = 0; j < maxAzNum; j++) {
            if (azLists[j] == NULL) {
                azLists[j] = g_node[i].azName;
                break;
            } else if (strcmp(g_node[i].azName, azLists[j]) == 0) {
                break;
            }
        }

        if (strcmp(g_node[i].azName, azName) == 0) {
            for (uint32 j = 0; j < g_node[i].datanodeCount; j++) {
                if (repNumInAZ == 0) {
                    mirrorId = g_node[i].datanode[j].datanodeMirrorId;
                    repNumInAZ++;
                } else if (mirrorId == g_node[i].datanode[j].datanodeMirrorId) {
                    repNumInAZ++;
                }
            }
        }
    }

    char azAllStr[maxAzNum * CM_AZ_NAME] = {0};
    for (uint32 i = 0; azLists[i] != NULL; i++) {
        if (i > 0) {
            rc = strncat_s(azAllStr, (maxAzNum * CM_AZ_NAME), ", ", strlen(", "));
            securec_check_errno(rc, (void)rc);
        }
        rc = strncat_s(azAllStr, (maxAzNum * CM_AZ_NAME), azLists[i], strlen(azLists[i]));
        securec_check_errno(rc, (void)rc);
    }

    for (uint32 ii = 0; ii < g_node_num; ii++) {
        // find pointed az
        if (strcmp(g_node[ii].azName, azName) == 0) {
            // minority start
            if (isMinority(cm_arbitration_mode_set)) {
                MinorityStartPreSet(ii, repNumInAZ);
            } else if (isMajority(cm_arbitration_mode_set)) {
                MajorityStartPreSet(ii, repNumInAZ, azAllStr);
            }

            write_runlog(LOG, "start node, nodeid: %u\n", g_node[ii].node);
            start_node(g_node[ii].node);
        }
    }
}

/*
 * find the node info according to availability zone name
 */
static void start_az(char *azName)
{
    int rc = 0;
    write_runlog(LOG, "start instances excepts ETCD in availability zone, availability zone name: %s.\n", azName);

    if (!isMinority(cm_arbitration_mode_set)) {
        /* clear the value of the key /az_stop_nodes and /az_stop_nodes_num to 0 */
        char etcdStopNodesKey[MAXPGPATH] = {0};
        char etcdStopNodesValue[MAXPGPATH] = {0};
        status_t res;

        rc = snprintf_s(etcdStopNodesKey, MAXPGPATH, MAXPGPATH - 1, "/%s/command/%d/az_stop_nodes", pw->pw_name, 0);
        securec_check_intval(rc, (void)rc);
        rc = snprintf_s(etcdStopNodesValue, MAXPGPATH, MAXPGPATH - 1, "%d", 0);
        securec_check_intval(rc, (void)rc);
        res = SendKVToCms(etcdStopNodesKey, etcdStopNodesValue, "startAz");
        if (res != CM_SUCCESS) {
            write_runlog(DEBUG1, "etcd clear stop_nodes failed, ETCD set error.\n\n");
        } else {
            write_runlog(DEBUG1, "etcd clear stop_nodes successfully.\n");
        }

        rc = snprintf_s(etcdStopNodesKey, MAXPGPATH, MAXPGPATH - 1, "/%s/command/az_stop_nodes_num", pw->pw_name);
        securec_check_intval(rc, (void)rc);
        rc = snprintf_s(etcdStopNodesValue, MAXPGPATH, MAXPGPATH - 1, "%d", 0);
        securec_check_intval(rc, (void)rc);
        res = SendKVToCms(etcdStopNodesKey, etcdStopNodesValue, "startAz");
        if (res != CM_SUCCESS) {
            write_runlog(DEBUG1, "etcd clear stop_nodes_num failed, ETCD set error.\n");
        } else {
            write_runlog(DEBUG1, "etcd clear stop_nodes_num successfully.\n");
        }
    }

    StartAz4Force(azName);
}

/*
 * @Description: start ETCD node.
 * if failed in 30 sec, ETCD node should stopped forcely.
 */
static void start_and_check_etcd_node(uint32 nodeId)
{
    uint32 ii;

    for (ii = 0; ii < g_node_num; ii++) {
        if (g_node[ii].node == nodeId) {
            break;
        }
    }
    if (ii >= g_node_num) {
        write_runlog(FATAL, "can't find the nodeid: %u\n", nodeId);
        exit(1);
    }

    if (g_node[ii].etcd) {
        start_etcd_node(nodeId);

        time_t startTime = time(NULL);
        while (time(NULL) - startTime < static_cast<time_t>(ETCD_START_WAIT)) {
            (void)sleep(1);
            write_runlog(LOG, ".");

            if (start_check_instance(ii, "etcd") == CM_STATUS_NORMAL) {
                write_runlog(LOG, "the ETCD instance in this node starts successfully done.\n");
                return;
            }
        }

        write_runlog(LOG, "failed to start the ETCD node.\n");
        stop_etcd_node(nodeId);
    }
}

/*
 * find the node info according to nodeid
 */
static void start_node(uint32 nodeid)
{
    if (got_stop) {
        return;
    }
    char command[MAXPGPATH];
    uint32 ii;
    errno_t rc;
    if (g_isPauseArbitration) {
        rc = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1,
            SYSTEMQUOTE "rm -f %s %s %s_*; touch %s < \"%s\" 2>&1 &" SYSTEMQUOTE,
            manual_start_file, etcd_manual_start_file,
            instance_manual_start_file, cluster_manual_starting_file, DEVNULL);
    } else {
        rc = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1,
            SYSTEMQUOTE "rm -f %s %s %s_* < \"%s\" 2>&1 &" SYSTEMQUOTE,
            manual_start_file, etcd_manual_start_file,
            instance_manual_start_file, DEVNULL);
    }
    securec_check_intval(rc, (void)rc);

    if (nodeid == g_currentNode->node) {
        rc = system(command);
    } else {
        for (ii = 0; ii < g_node_num; ii++) {
            if (g_node[ii].node == nodeid) {
                break;
            }
        }
        if (ii < g_node_num) {
            rc = ssh_exec(&g_node[ii], command);
        } else {
            write_runlog(ERROR, "Could not find the node in the cluster by the node id %u.\n", nodeid);
            exit(1);
        }
    }

    if (rc != 0) {
        write_runlog(DEBUG1,
            "Failed to start the node with executing the command: command=\"%s\","
            " nodeId=%u, systemReturn=%d, shellReturn=%d, errno=%d.\n",
            command,
            nodeid,
            rc,
            SHELL_RETURN_CODE(rc),
            errno);
    }
}

static void StartInstanceByInstanceid(uint32 instanceId)
{
    for (uint32 i = 0; i < g_node_num; i++) {
        for (uint32 j = 0; j < g_node[i].datanodeCount; j++) {
            if (instanceId == g_node[i].datanode[j].datanodeId) {
                start_instance(g_node[i].node, g_node[i].datanode[j].datanodeLocalDataPath);
                write_runlog(LOG,
                    "start the node:%u,datapath:%s. \n",
                    g_node[i].node,
                    g_node[i].datanode[j].datanodeLocalDataPath);
                return;
            }
        }
    }
}

static void start_datanode_instance_relation(uint32 node, const char* dataPath)
{
    int ret;
    uint32 instanceId;
    cm_to_ctl_get_datanode_relation_ack getInstanceMsg = {0};
    ret = GetDatanodeRelationInfo(node, dataPath, &getInstanceMsg);
    if (ret == -1) {
        write_runlog(ERROR, "can not get datanode information.\n");
        exit(1);
    }
    for (int i = 0; i < CM_PRIMARY_STANDBY_MAX_NUM; i++) {
        instanceId = getInstanceMsg.instanceMember[i].instanceId;
        if (instanceId != 0) {
            StartInstanceByInstanceid(instanceId);
        }
    }
}

void start_instance(uint32 nodeid, const char* datapath)
{
    int instance_type;
    uint32 instanceId;
    char command[MAXPGPATH];
    int nRet;

    nRet = FindInstanceIdAndType(nodeid, datapath, &instanceId, &instance_type);
    if (nRet != 0) {
        write_runlog(FATAL, "can't find the node_id:%u, data_path:%s.\n", nodeid, datapath);
        exit(1);
    }
    if (instance_type == INSTANCE_TYPE_DATANODE && CheckOfflineInstance(nodeid)) {
        write_runlog(DEBUG1, "the instance(node:%u) is Offline, no need to start.\n", nodeid);
        return;
    }

    if (g_isPauseArbitration) {
        nRet = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1,
            SYSTEMQUOTE "rm -f %s_%u; touch %s < \"%s\" 2>&1 &" SYSTEMQUOTE,
            instance_manual_start_file, instanceId, cluster_manual_starting_file, DEVNULL);
    } else {
        nRet = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1, SYSTEMQUOTE "rm -f %s_%u < \"%s\" 2>&1 &" SYSTEMQUOTE,
            instance_manual_start_file, instanceId, DEVNULL);
    }
    securec_check_intval(nRet, (void)nRet);

    nRet = runCmdByNodeId(command, nodeid);
    if (nRet != 0) {
        write_runlog(DEBUG1, "Failed to start the instance with executing the command: command=\"%s\","
            " nodeId=%u, dataPath=\"%s\", systemReturn=%d, shellReturn=%d, errno=%d.\n",
            command, nodeid, datapath, nRet, SHELL_RETURN_CODE(nRet), errno);
    }
}

void RemoveStartingFile()
{
    int ret;
    char command[MAX_COMMAND_LEN] = {0};

    if (!g_isPauseArbitration) {
        exit(0);
    }

    init_hosts();
    if (mpp_env_separate_file[0] == '\0') {
        ret = snprintf_s(command,
            MAX_COMMAND_LEN,
            MAX_COMMAND_LEN - 1,
            SYSTEMQUOTE "source /etc/profile;pssh -i %s -h %s \"rm -f %s\" > %s; "
                        "if [ $? -ne 0 ]; then cat %s; fi; rm -f %s" SYSTEMQUOTE,
            PSSH_TIMEOUT_OPTION,
            hosts_path,
            cluster_manual_starting_file,
            pssh_out_path,
            pssh_out_path,
            pssh_out_path);
    } else {
        ret = snprintf_s(command,
            MAX_COMMAND_LEN,
            MAX_COMMAND_LEN - 1,
            SYSTEMQUOTE "source /etc/profile;pssh -i %s -h %s \"source %s;rm -f %s\" > %s; "
                        "if [ $? -ne 0 ]; then cat %s; fi; rm -f %s" SYSTEMQUOTE,
            PSSH_TIMEOUT_OPTION,
            hosts_path,
            mpp_env_separate_file,
            cluster_manual_starting_file,
            pssh_out_path,
            pssh_out_path,
            pssh_out_path);
    }
    securec_check_intval(ret, (void)ret);
    ret = system(command);
    if (ret != 0) {
        write_runlog(DEBUG1,
            "Failed to delete the startingFile with executing the command: command=\"%s\","
            " nodeId=%u, systemReturn=%d, shellReturn=%d, errno=%d.\n",
            command,
            g_currentNode->node,
            ret,
            SHELL_RETURN_CODE(ret),
            errno);
    }
    exit(0);
}

static void ContinueCheckClsStatus(long *startingTime)
{
    (void)sleep(1);

    (void)clock_gettime(CLOCK_MONOTONIC, &g_endTime);
    *startingTime = (g_endTime.tv_sec - g_startTime.tv_sec);
    if (*startingTime > EXPECTED_CLUSTER_START_TIME && *startingTime % CLUSTER_STATE_CHECK_INTERVAL == 0) {
        write_runlog(DEBUG1, "starting exceeds 2 mins, instance status:g_cluster_start_status=%d,"
            "g_az_start_status=%d, g_node_start_status=%d, g_instance_start_status=%d\n",
            g_cluster_start_status, g_az_start_status, g_node_start_status, g_instance_start_status);
    }
}

static void* check_cluster_start_status(void* arg)
{
    int count = 0;
    long startingTime = 0;

    if (!wait_seconds_set) {
        /* caculate timeout based on the number of nodes */
        g_waitSeconds = caculate_default_timeout(START_COMMAND);
    }

    while (startingTime < g_waitSeconds) {
        if (g_startExitCode != CM_START_EXIT_INIT) {
            // wait start_check thread exit until g_waitSeconds
            ContinueCheckClsStatus(&startingTime);
            continue;
        }
        if (g_cluster_start_status == CM_STATUS_NORMAL) {
            write_runlog(LOG, "start cluster successfully.\n");
            g_startExitCode = CM_START_EXIT_SUCCESS;
            continue;
        } else if (g_cluster_start_status == CM_STATUS_NORMAL_WITH_CN_DELETED) {
            write_runlog(LOG, "start cluster successfully. There is a coordinator that has been deleted. \n");
            g_startExitCode = CM_START_EXIT_SUCCESS;
            continue;
        } else if (g_az_start_status == CM_STATUS_NORMAL) {
            for (uint32 ii = 0; ii < g_node_num; ii++) {
                if (g_command_operation_azName != NULL && strcmp(g_node[ii].azName, g_command_operation_azName) == 0) {
                    write_runlog(LOG, "start node successfully, nodeid: %u. \n", g_node[ii].node);
                }
            }

            write_runlog(LOG, "start availability zone successfully.\n");
            g_startExitCode = CM_START_EXIT_SUCCESS;
            continue;
        } else if (g_az_start_status == CM_STATUS_NORMAL_WITH_CN_DELETED) {
            for (uint32 ii = 0; ii < g_node_num; ii++) {
                if (g_command_operation_azName != NULL && strcmp(g_node[ii].azName, g_command_operation_azName) == 0) {
                    write_runlog(LOG, "start node successfully, nodeid: %u. \n", g_node[ii].node);
                }
            }

            write_runlog(LOG, "start availability zone successfully. There is a coordinator that has been deleted. \n");
            g_startExitCode = CM_START_EXIT_SUCCESS;
            continue;
        } else if (g_node_start_status == CM_STATUS_NORMAL) {
            write_runlog(LOG, "start node successfully.\n");
            g_startExitCode = CM_START_EXIT_SUCCESS;
            continue;
        } else if (g_node_start_status == CM_STATUS_NORMAL_WITH_CN_DELETED) {
            write_runlog(LOG, "start node successfully. There is a coordinator that has been deleted. \n");
            g_startExitCode = CM_START_EXIT_SUCCESS;
            continue;
        } else if (g_instance_start_status == CM_STATUS_NORMAL) {
            /*
             * CM Client found the instance running, but maybe it quit immediately after startup.
             * so only if CM Client found the instance running for 3 times, instance has started.
             */
            count++;
            if (count > INSTANCE_START_CONFIRM_TIME) {
                write_runlog(LOG, "start instance successfully.\n");
                g_startExitCode = CM_START_EXIT_SUCCESS;
                continue;
            }
        } else if (g_dn_relation_start_status == CM_STATUS_NORMAL) {
            /* check whether the relation datanodes have been started successfully */
            write_runlog(LOG, "start relation datanodes successfully(node:%u, path:%s).\n",
                         g_commandOperationNodeId, g_cmData);
            g_startExitCode = CM_START_EXIT_SUCCESS;
            continue;
        } else if (g_resStartStatus == CM_STATUS_NORMAL) {
            write_runlog(LOG, "start resource instance successfully(nodeId:%u, instId:%u).\n",
                g_commandOperationNodeId, g_commandOperationInstanceId);
            g_startExitCode = CM_START_EXIT_SUCCESS;
            continue;
        } else if (g_dn_status == INSTANCE_HA_STATE_READ_ONLY) {
            write_runlog(ERROR,
                "start cluster failed!\n\n"
                "HINT: Some nodes are in ReadOnly mode.\n"
                "To identify which nodes are ReadOnly, use the following command:\n"
                "\'cm_ctl query -Cvipdw\'\n");
            g_startExitCode = CM_START_EXIT_SUCCESS;
            continue;
        } else {
            count = 0;
        }

        ContinueCheckClsStatus(&startingTime);
        write_runlog(LOG, ".");
    }

    /* query cluster and report when start failed */
    StartFailQueryAndReport();

    if ((g_command_operation_azName == NULL) && !g_commandOperationNodeId && (g_cmData[0] == '\0') &&
        g_cluster_start_status != CM_STATUS_NORMAL && g_cluster_start_status != CM_STATUS_NORMAL_WITH_CN_DELETED) {
        write_runlog(ERROR,
            "start cluster failed in (%d)s!\n\n"
            "HINT: Maybe the cluster is continually being started in the background.\n"
            "You can wait for a while and check whether the cluster starts, or increase the value of parameter \"-t\", "
            "e.g -t 600.\n",
            g_waitSeconds);
    } else if (!g_commandOperationNodeId && (g_cmData[0] == '\0') && g_az_start_status != CM_STATUS_NORMAL &&
        g_az_start_status != CM_STATUS_NORMAL_WITH_CN_DELETED) {
        write_runlog(ERROR,
            "start availability zone failed in (%d)s!\n\n"
            "HINT: Maybe the availability zone is continually being started in the background.\n"
            "You can wait for a while and check whether the availability zone starts, or increase the value of "
            "parameter \"-t\", e.g -t 600.\n",
            g_waitSeconds);
    } else if ((g_commandOperationNodeId > 0) && (g_commandOperationInstanceId > 0) &&
        (g_resStartStatus != CM_STATUS_NORMAL)) {
        write_runlog(ERROR,
            "start resource instance failed in (%d)s!\n\n"
            "HINT: Maybe the node is continually being started in the background.\n"
            "You can wait for a while and check whether the node starts, or increase the value of parameter \"-t\", "
            "e.g -t 600.\n",
            g_waitSeconds);
    } else if ((g_cmData[0] == '\0') && g_node_start_status != CM_STATUS_NORMAL &&
        g_node_start_status != CM_STATUS_NORMAL_WITH_CN_DELETED) {
        write_runlog(ERROR,
            "start node failed in (%d)s!\n\n"
            "HINT: Maybe the node is continually being started in the background.\n"
            "You can wait for a while and check whether the node starts, or increase the value of parameter \"-t\", "
            "e.g -t 600.\n",
            g_waitSeconds);
    } else if (g_instance_start_status != CM_STATUS_NORMAL) {
        write_runlog(ERROR,
            "start instance failed in (%d)s!\n\n"
            "HINT: Maybe the instance is continually being started in the background.\n"
            "You can wait for a while and check whether the instance starts, or increase the value of parameter "
            "\"-t\", e.g -t 600.\n",
            g_waitSeconds);
    }

    g_startExitCode = CM_START_EXIT_FAILED;
    // wait start_check thread exit
    // cm_ctl maybe core if start_check thread not exit conn cm_server with openssl
    (void)sleep(6);
    exit(-1);
}

/* exce command: cm_ctl query -Cv to report cluster starting status, and print cluster status info to log */
static void StartFailQueryAndReport()
{
    char queryCommand[MAXPGPATH] = {0};
    char log_file_name[MAXPGPATH] = {0};
    char* name_ptr = NULL;
    bool is_exist = false;
    DIR *dir = opendir(sys_log_path);
    if (dir == NULL) {
        write_runlog(DEBUG1, "start_query_and_report: log dir open failed!\n");
        return;
    }
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
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
    if (is_exist) {
        int ret = snprintf_s(log_file_name, MAXPGPATH, MAXPGPATH - 1, "%s/%s", sys_log_path, de->d_name);
        securec_check_intval(ret, (void)ret);
        int rc = snprintf_s(queryCommand, MAXPGPATH, MAXPGPATH - 1,
            "cm_ctl query -Cvdip >> %s 2>&1 &", log_file_name);
        securec_check_intval(rc, (void)rc);
        ret = system(queryCommand);
        if (ret != 0) {
            write_runlog(DEBUG1, "check_cluster_start_status: command cm_ctl query -Cv failed, errno=%d.\n", errno);
            (void)closedir(dir);
            return;
        }
    } else {
        write_runlog(DEBUG1, "check_cluster_start_status: cm_ctl log file not exist.\n");
    }
    (void)closedir(dir);
    return;
}

static void* start_check(void* arg)
{
    uint32 ii;

    for (;;) {
        if (g_startExitCode != CM_START_EXIT_INIT) {
            write_runlog(DEBUG1, "start_check thread exit:%d\n", (int)g_startExitCode);
            break;
        }
        if (g_command_operation_azName == NULL && g_commandOperationNodeId == 0) {
            g_cluster_start_status = start_check_cluster();
        } else if (g_command_operation_azName != NULL) {
            g_az_start_status = start_check_az(g_command_operation_azName);
            startaz_try_heartbeat--;
        } else if (g_commandOperationNodeId > 0 && g_commandOperationInstanceId > 0) {
            g_resStartStatus = StartResInstCheck(g_commandOperationInstanceId);
        } else if (g_cmData[0] == '\0' || (g_commandOperationNodeId > 0 && g_commandOperationInstanceId == 0)) {
            for (ii = 0; ii < g_node_num; ii++) {
                if (g_node[ii].node == g_commandOperationNodeId) {
                    break;
                }
            }

            if (ii >= g_node_num) {
                write_runlog(ERROR, "can't find the nodeid: %u\n", g_commandOperationNodeId);
                g_startExitCode = CM_START_EXIT_FAILED;
                break;
            }
            g_node_start_status = start_check_node(ii);
        } else if (g_commandRelationship) {
            g_dn_relation_start_status = start_check_dn_relation(g_commandOperationNodeId, g_cmData);
        } else {
            for (ii = 0; ii < g_node_num; ii++) {
                if (g_node[ii].node == g_commandOperationNodeId) {
                    break;
                }
            }

            if (ii >= g_node_num) {
                write_runlog(ERROR, "can't find the nodeid: %u\n", g_commandOperationNodeId);
                g_startExitCode = CM_START_EXIT_FAILED;
                break;
            }

            g_instance_start_status = start_check_instance(ii, g_cmData);
        }

        (void)sleep(1);
    }
    return NULL;
}

static void NotifyCMSClusterStarting()
{
    int ret;
    ctl_to_cm_notify ctlToCmNotifyContent;
    ctlToCmNotifyContent.msg_type = MSG_CTL_CM_NOTIFY;
    ctlToCmNotifyContent.detail = CLUSTER_STARTING;

    ret = cm_client_send_msg(CmServer_conn, 'C', (char*)&ctlToCmNotifyContent, sizeof(ctlToCmNotifyContent));
    if (ret != 0) {
        write_runlog(WARNING, "Notify Cluster Starting failed.\n");
    }
    return;
}

static int start_check_cluster()
{
    ctl_to_cm_query cm_ctl_cm_query_content;
    char* receive_msg = NULL;
    cm_msg_type* cm_msg_type_ptr = NULL;

    cm_to_ctl_cluster_status* cm_to_ctl_cluster_status_ptr = NULL;
    int cnt_deleted = 0;
    int cnt_abnormal = 0;

    int ret;
    int cluster_status = CM_STATUS_UNKNOWN;
    cmTime_t tv;
    (void)clock_gettime(CLOCK_MONOTONIC, &tv);
    if (CmServer_conn != NULL) {
        CMPQfinish(CmServer_conn);
        CmServer_conn = NULL;
    }
    /* return conn to cm_server */
    do_conn_cmserver(false, 0);

    if (CmServer_conn == NULL) {
        write_runlog(DEBUG1, "CmServer_conn is null.\n");
        return -1;
    } else {
        if (CMPQstatus(CmServer_conn) != CONNECTION_OK) {
            CMPQfinish(CmServer_conn);
            CmServer_conn = NULL;
            return -1;
        }
    }
    NotifyCMSClusterStarting();

    cm_ctl_cm_query_content.msg_type = (int)MSG_CTL_CM_QUERY;
    cm_ctl_cm_query_content.node = INVALID_NODE_NUM;
    cm_ctl_cm_query_content.instanceId = INVALID_INSTACNE_NUM;
    cm_ctl_cm_query_content.wait_seconds = DEFAULT_WAIT;
    cm_ctl_cm_query_content.detail = CLUSTER_DETAIL_STATUS_QUERY;
    cm_ctl_cm_query_content.relation = 0;

    ret = cm_client_send_msg(CmServer_conn, 'C', (char*)&cm_ctl_cm_query_content, sizeof(cm_ctl_cm_query_content));
    if (ret != 0) {
        CMPQfinish(CmServer_conn);
        CmServer_conn = NULL;
        return -1;
    }

    bool rec_data_end = false;
    for (;;) {
        ret = cm_client_flush_msg(CmServer_conn);
        if (ret == TCP_SOCKET_ERROR_EPIPE) {
            CMPQfinish(CmServer_conn);
            CmServer_conn = NULL;
            return -1;
        }
        CM_BREAK_IF_TRUE(IsTimeOut(&tv, "[start_check_cluster]"));
        receive_msg = recv_cm_server_cmd(CmServer_conn);
        while (receive_msg != NULL) {
            cm_msg_type_ptr = (cm_msg_type*)receive_msg;
            switch (cm_msg_type_ptr->msg_type) {
                case MSG_CM_CTL_DATA_BEGIN:
                    cm_to_ctl_cluster_status_ptr = (cm_to_ctl_cluster_status*)receive_msg;
                    cluster_status = cm_to_ctl_cluster_status_ptr->cluster_status;
                    if (cluster_status == CM_STATUS_NORMAL) {
                        rec_data_end = true;
                    }
                    break;
                case MSG_CM_CTL_DATA:
                    // The cluster status is degrade, not normal, whether a cn is deleted and all other instances are
                    // normal.
                    if (cluster_status == CM_STATUS_DEGRADE) {
                        cm_to_ctl_instance_status cm_to_ctl_instance_status_ptr = {0};
                        cm_to_ctl_instance_status_ipv4 *cm_to_ctl_instance_status_ptr_ipv4 = NULL;
                        if (undocumentedVersion != 0 && undocumentedVersion < SUPPORT_IPV6_VERSION) {
                            cm_to_ctl_instance_status_ptr_ipv4 = (cm_to_ctl_instance_status_ipv4 *)receive_msg;
                            CmToCtlInstanceStatusV1ToV2(
                                cm_to_ctl_instance_status_ptr_ipv4,
                                &cm_to_ctl_instance_status_ptr);
                        } else {
                            errno_t rc = memcpy_s(
                                &cm_to_ctl_instance_status_ptr,
                                sizeof(cm_to_ctl_instance_status_ptr),
                                receive_msg,
                                sizeof(cm_to_ctl_instance_status_ptr));
                            securec_check_errno(rc, (void)rc);
                        }

                        if (cm_to_ctl_instance_status_ptr.instance_type == INSTANCE_TYPE_COORDINATE) {
                            int status = cm_to_ctl_instance_status_ptr.coordinatemember.status;

                            if (status == INSTANCE_ROLE_DELETED) {
                                cnt_deleted++;
                            }

                            if (status != INSTANCE_ROLE_NORMAL && status != INSTANCE_ROLE_DELETED) {
                                cnt_abnormal++;
                            }
                        } else if (cm_to_ctl_instance_status_ptr.instance_type == INSTANCE_TYPE_GTM) {
                            int local_role = cm_to_ctl_instance_status_ptr.gtm_member.local_status.local_role;

                            if (local_role != INSTANCE_ROLE_PRIMARY && local_role != INSTANCE_ROLE_STANDBY) {
                                cnt_abnormal++;
                            }
                        } else if (cm_to_ctl_instance_status_ptr.instance_type == INSTANCE_TYPE_DATANODE) {
                            int local_role = cm_to_ctl_instance_status_ptr.data_node_member.local_status.local_role;
                            if (local_role != INSTANCE_ROLE_PRIMARY && local_role != INSTANCE_ROLE_STANDBY &&
                                local_role != INSTANCE_ROLE_DUMMY_STANDBY) {
                                cnt_abnormal++;
                            }
                        }
                    }
                    break;
                case MSG_CM_CTL_NODE_END:
                    break;
                case MSG_CM_CTL_DATA_END:
                    rec_data_end = true;
                    break;
                default:
                    write_runlog(ERROR, "unknown the msg type is %d.\n", cm_msg_type_ptr->msg_type);
                    break;
            }
            receive_msg = recv_cm_server_cmd(CmServer_conn);
        }
        if (rec_data_end) {
            break;
        }
    }

    CMPQfinish(CmServer_conn);
    CmServer_conn = NULL;

    if (cluster_status == CM_STATUS_DEGRADE && cnt_abnormal == 0 && cnt_deleted >= 1) {
        cluster_status = CM_STATUS_NORMAL_WITH_CN_DELETED;
    }

    return cluster_status;
}

static bool IsAllResInstStarted(uint32 nodeId)
{
    for (uint32 i = 0; i < CusResCount(); ++i) {
        for (uint32 j = 0; j < g_resStatus[i].status.instanceCount; ++j) {
            if (g_resStatus[i].status.resStat[j].nodeId != nodeId) {
                continue;
            }
            if (GetResInstStatus(g_resStatus[i].status.resStat[j].cmInstanceId) != CM_RES_STAT_ONLINE) {
                return false;
            }
        }
    }
    return true;
}

static int start_check_node(uint32 node_id_check)
{
    uint32 ii;
    int cnt = 0;
    int cnt_base = 0;
    int cnt_deleted = 0;
    int result = -1;
    int ret;
    errno_t tnRet = 0;
    CM_Conn *pCmsCon = NULL;

    char command[MAXPGPATH] = {0};
    char cmBinPath[MAXPGPATH] = {0};

    if (checkStaticConfigExist(node_id_check) != 0) {
        write_runlog(
            ERROR, "the cluster static config file does not exist on the node: %u.\n", g_node[node_id_check].node);
        write_runlog(FATAL, "failed to check the node instances start status.\n");
        exit(-1);
    }

    /* coordinator */
    if (g_node[node_id_check].coordinate == 1) {
        cnt_base++;

        CheckCnNodeStatusById(node_id_check, &result);
        if (result == PROCESS_RUNNING) {
            cnt++;
        } else {
            ctl_to_cm_query cm_ctl_cm_query_content;
            char* receive_msg = NULL;
            cm_msg_type* cm_msg_type_ptr = NULL;
            bool rec_data_end = false;

            if (CmServer_conn != NULL) {
                CMPQfinish(CmServer_conn);
                CmServer_conn = NULL;
            }
            /* return conn to cm_server */
            do_conn_cmserver(false, 0);
            if (CmServer_conn == NULL) {
                return CM_STATUS_UNKNOWN;
            } else {
                if (CMPQstatus(CmServer_conn) != CONNECTION_OK) {
                    CMPQfinish(CmServer_conn);
                    CmServer_conn = NULL;
                    return CM_STATUS_UNKNOWN;
                }
            }

            cm_ctl_cm_query_content.msg_type = (int)MSG_CTL_CM_QUERY;
            cm_ctl_cm_query_content.node = g_node[node_id_check].node;
            cm_ctl_cm_query_content.instanceId = g_node[node_id_check].coordinateId;
            cm_ctl_cm_query_content.instance_type = INSTANCE_TYPE_COORDINATE;
            cm_ctl_cm_query_content.wait_seconds = DEFAULT_WAIT;
            cm_ctl_cm_query_content.detail = CLUSTER_DETAIL_STATUS_QUERY;
            cm_ctl_cm_query_content.relation = 0;

            ret = cm_client_send_msg(
                CmServer_conn, 'C', (char*)&cm_ctl_cm_query_content, sizeof(cm_ctl_cm_query_content));
            if (ret != 0) {
                CMPQfinish(CmServer_conn);
                CmServer_conn = NULL;
                return CM_STATUS_UNKNOWN;
            }
            struct timespec timeBegin = {0, 0};
            (void)clock_gettime(CLOCK_MONOTONIC, &timeBegin);
            for (;;) {
                ret = cm_client_flush_msg(CmServer_conn);
                if (ret == TCP_SOCKET_ERROR_EPIPE) {
                    CMPQfinish(CmServer_conn);
                    CmServer_conn = NULL;
                    return CM_STATUS_UNKNOWN;
                }

                if (IsTimeOut(&timeBegin, "[start_check_node]")) {
                    CMPQfinish(CmServer_conn);
                    CmServer_conn = NULL;
                    return CM_STATUS_UNKNOWN;
                }

                receive_msg = recv_cm_server_cmd(CmServer_conn);
                while (receive_msg != NULL) {
                    cm_msg_type_ptr = (cm_msg_type *)receive_msg;
                    switch (cm_msg_type_ptr->msg_type) {
                        case MSG_CM_CTL_DATA_BEGIN:
                            break;
                        case MSG_CM_CTL_DATA: {
                            cm_to_ctl_instance_status cm_to_ctl_instance_status_ptr = {0};
                            cm_to_ctl_instance_status_ipv4 *cm_to_ctl_instance_status_ptr_ipv4 = NULL;
                            if (undocumentedVersion != 0 && undocumentedVersion < SUPPORT_IPV6_VERSION) {
                                cm_to_ctl_instance_status_ptr_ipv4 = (cm_to_ctl_instance_status_ipv4 *)receive_msg;
                                CmToCtlInstanceStatusV1ToV2(
                                    cm_to_ctl_instance_status_ptr_ipv4,
                                    &cm_to_ctl_instance_status_ptr);
                            } else {
                                errno_t rc = memcpy_s(
                                    &cm_to_ctl_instance_status_ptr,
                                    sizeof(cm_to_ctl_instance_status_ptr),
                                    receive_msg,
                                    sizeof(cm_to_ctl_instance_status_ptr));
                                securec_check_errno(rc, (void)rc);
                            }
                            if (cm_to_ctl_instance_status_ptr.instance_type == INSTANCE_TYPE_COORDINATE &&
                                g_node[node_id_check].node == cm_to_ctl_instance_status_ptr.node &&
                                cm_to_ctl_instance_status_ptr.coordinatemember.status == INSTANCE_ROLE_DELETED) {
                                cnt_deleted++;
                            }
                            rec_data_end = true;
                            break;
                        }
                        case MSG_CM_CTL_NODE_END:
                            break;
                        case MSG_CM_CTL_DATA_END:
                            break;
                        case MSG_CM_BUILD_DOING:
                        case MSG_CM_BUILD_DOWN:
                            rec_data_end = true;
                            break;
                        default:
                            write_runlog(ERROR, "unknown the msg type is %d.\n", cm_msg_type_ptr->msg_type);
                    }
                    receive_msg = recv_cm_server_cmd(CmServer_conn);
                }
                if (rec_data_end) {
                    break;
                }
            }

            CMPQfinish(CmServer_conn);
            CmServer_conn = NULL;
        }
    }

    /* datanode */
    if (IsCmSharedStorageMode()) {
        if (WaitCmsPrimaryNormal(&pCmsCon) != CM_SUCCESS) {
            return CM_STATUS_UNKNOWN;
        }
    }
    for (ii = 0; ii < g_node[node_id_check].datanodeCount; ii++) {
        if (IsCmSharedStorageMode() && SetOfflineNode(node_id_check, pCmsCon)) {
            continue;
        }
        cnt_base++;
        CheckDnNodeStatusById(node_id_check, &result, ii);
        if (result == PROCESS_RUNNING) {
            cnt++;
        }
    }
    ReleaseConn(pCmsCon);

    char resultPath[MAXPGPATH] = {0};
    char checkCmserverProcessResultPath[MAX_PATH_LEN] = {0};
    int fd;
    bool flag = false;
    ret = GetHomePath(resultPath, sizeof(resultPath));
    if (ret != EOK) {
        return CM_STATUS_UNKNOWN;
    }
    ret = snprintf_s(checkCmserverProcessResultPath, MAX_PATH_LEN, MAX_PATH_LEN - 1,
        "%s/bin/checkCmserverProcessResult-XXXXXX", resultPath);
    securec_check_intval(ret, (void)ret);

    fd = mkstemp(checkCmserverProcessResultPath);
    if (fd <= 0) {
        write_runlog(ERROR, "failed to create the cmserver process check result file: errno=%d.\n", errno);
        flag = true;
    }

    /* cm_server */
    if (g_node[node_id_check].cmServerLevel == 1) {
        cnt_base++;
        tnRet = memset_s(command, MAXPGPATH, 0, MAXPGPATH);
        securec_check_errno(tnRet, (void)tnRet);
        tnRet = memset_s(cmBinPath, MAXPGPATH, 0, MAXPGPATH);
        securec_check_errno(tnRet, (void)tnRet);
        ret = snprintf_s(cmBinPath, MAXPGPATH, MAXPGPATH - 1, "%s/bin/%s", g_appPath, CM_SERVER_BIN_NAME);
        securec_check_intval(ret, (void)ret);
        if (node_id_check == g_nodeId && strstr(g_appPath, "/var/chroot") == NULL) {
            ret = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1, "cm_ctl check -B %s -T %s  \n echo  -e  $? > %s",
                CM_SERVER_BIN_NAME, cmBinPath, flag ? result_path : checkCmserverProcessResultPath);
            securec_check_intval(ret, (void)ret);
            exec_system(command, &result,  flag ? result_path : checkCmserverProcessResultPath);
        } else {
            ret = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1,
                "cm_ctl check -B %s -T %s\" > /dev/null 2>&1; echo  -e $? > %s",
                CM_SERVER_BIN_NAME, cmBinPath, flag ? result_path : checkCmserverProcessResultPath);
            securec_check_intval(ret, (void)ret);
            exec_system_ssh(node_id_check, command, &result,
                flag ? result_path : checkCmserverProcessResultPath, mpp_env_separate_file);
        }

        if (result == PROCESS_RUNNING) {
            cnt++;
        }
    }

    if (fd > 0) {
        (void)close(fd);
    }
    (void)unlink(flag ? result_path : checkCmserverProcessResultPath);

    /* gtm */
    if (g_node[node_id_check].gtm == 1) {
        cnt_base++;
        CheckGtmNodeStatusById(node_id_check, &result);
        if (result == PROCESS_RUNNING) {
            cnt++;
        }
    }

    /* resource */
    ++cnt_base;
    if (IsAllResInstStarted(g_node[node_id_check].node)) {
        ++cnt;
    }

    if (cnt < cnt_base) {
        if (cnt_base == cnt + cnt_deleted && cnt_deleted >= 1) {
            return CM_STATUS_NORMAL_WITH_CN_DELETED;
        } else {
            return CM_STATUS_UNKNOWN;
        }
    }
    return CM_STATUS_NORMAL;
}

static int start_check_dn_relation(uint32 node, const char *dataPath)
{
    int ret;
    uint32 instanceId;
    int dbState;
    cm_to_ctl_get_datanode_relation_ack getInstanceMsg = {0};
    ret = GetDatanodeRelationInfo(node, dataPath, &getInstanceMsg);
    if (ret == -1) {
        write_runlog(ERROR, "can not get datanode information.\n");
        exit(1);
    }
    for (int i = 0; i < CM_PRIMARY_STANDBY_MAX_NUM; i++) {
        instanceId = getInstanceMsg.instanceMember[i].instanceId;
        if (instanceId != 0) {
            dbState = getInstanceMsg.data_node_member[i].local_status.db_state;
            if (dbState != INSTANCE_HA_STATE_NORMAL) {
                return CM_STATUS_UNKNOWN;
            }
        }
    }
    return CM_STATUS_NORMAL;
}

/**
 * @param allAzLists    str of all az names like "AZ1,AZ2,AZ3". NULL means it's in minority
 *
 * @param repNum    rep number in pointe az, 1 means we should change 'most_available_sync'
 *
 * @param nodeIndex     which node.
 *
 */
static void ExecuteGsGuc(const char *allAzLists, bool isSingleRep, uint32 repNum, uint32 nodeIndex)
{
    char command[MAXPGPATH];
    int ret;
    const char* switchFlag = (allAzLists != NULL) ? "off" : "on";
    const char* az = (allAzLists != NULL) ? allAzLists : g_node[nodeIndex].azName;
    const uint32 half = 2;
    
    for (uint32 kk = 0; kk < g_node[nodeIndex].datanodeCount; kk++) {
        // minority : NULL-> curNodeAz
        if (g_currentNode->node == g_node[nodeIndex].node) {
            if (isSingleRep) {
                    ret = snprintf_s(command,
                        MAXPGPATH, MAXPGPATH - 1,
                        "gs_guc reload -Z datanode -D %s -c \"most_available_sync = '%s'\" > %s 2>&1 &",
                        g_node[nodeIndex].datanode[kk].datanodeLocalDataPath, switchFlag, DEVNULL);
            } else {
                ret = snprintf_s(command,
                    MAXPGPATH, MAXPGPATH - 1,
                    "gs_guc reload -Z datanode -D %s -c \"synchronous_standby_names = 'ANY %u(%s)'\" > %s 2>&1 &",
                    g_node[nodeIndex].datanode[kk].datanodeLocalDataPath,
                    repNum / half, az, DEVNULL);
            }
        } else {
            if (isSingleRep) {
                ret = snprintf_s(command,
                    MAXPGPATH,  MAXPGPATH - 1,
                    "gs_guc reload -Z datanode -D %s -c \\\"most_available_sync = '%s'\\\" > %s 2>&1 &",
                    g_node[nodeIndex].datanode[kk].datanodeLocalDataPath, switchFlag, DEVNULL);
            } else {
                ret = snprintf_s(command,
                    MAXPGPATH, MAXPGPATH - 1,
                    "gs_guc reload -Z datanode -D %s -c \\\"synchronous_standby_names = 'ANY %u(%s)'\\\" > %s 2>&1 &",
                    g_node[nodeIndex].datanode[kk].datanodeLocalDataPath,
                    repNum / half, az, DEVNULL);
            }
        }
        securec_check_intval(ret, (void)ret);
        write_runlog(DEBUG1, "The node %s begins to execute the command: %s.\n", g_node[nodeIndex].nodeName, command);

        if (g_currentNode->node == g_node[nodeIndex].node) {
            ret = system(command);
        } else {
            ret = ssh_exec(&g_node[nodeIndex], command);
        }

        if (ret == 0) {
            write_runlog(DEBUG1, "Successful exexution of the above command.\n");
        } else {
            write_runlog(DEBUG1, "Failed exexution of the above command, ignore it, errno=%d.\n", errno);
        }
    }
}

void RunCmdInStartAz(const char* command, uint32 nodeIndex)
{
    int ret;
    write_runlog(DEBUG1, "The node %s begins to execute the command: %s.\n", g_node[nodeIndex].nodeName, command);
    if (g_currentNode->node == g_node[nodeIndex].node) {
        ret = system(command);
    } else {
        ret = ssh_exec(&g_node[nodeIndex], command);
    }

    if (ret == 0) {
        write_runlog(DEBUG1, "Successful exexution of the above command.\n");
    } else {
        write_runlog(DEBUG1, "Failed exexution of the above command, ignore it, errno=%d.\n", errno);
    }
}

/* GetEtcdNumOfAz: Count the etcd num of AZ */
static uint32 GetEtcdNumOfAz(const char* azName)
{
    uint32 etcdNumOfAz = 0;
    for (uint32 ii = 0; ii < g_node_num; ii++) {
        if (strcmp(g_node[ii].azName, azName) == 0) {
            if (g_node[ii].etcd) {
                etcdNumOfAz++;
            }
        }
    }
    write_runlog(DEBUG1, "The etcd num = %u of %s.\n", etcdNumOfAz, azName);
    return etcdNumOfAz;
}

/* GetAliveEtcdNumOfAz: Count the alive etcd num of AZ */
static uint32 GetAliveEtcdNumOfAz(const char* azName)
{
    uint32 aliveEtcdNumOfAz = 0;
    for (uint32 ii = 0; ii < g_node_num; ii++) {
        if (strcmp(g_node[ii].azName, azName) == 0) {
            if (g_node[ii].etcd) {
                if (start_check_instance(ii, "etcd") == CM_STATUS_NORMAL) {
                    aliveEtcdNumOfAz++;
                }
            }
        }
    }
    write_runlog(DEBUG1, "The alive etcd num = %u of %s.\n", aliveEtcdNumOfAz, azName);
    return aliveEtcdNumOfAz;
}

static void start_az_try_more_one(const char* azName)
{
    for (uint32 ii = 0; ii < g_node_num; ii++) {
        if (strcmp(g_node[ii].azName, azName) == 0) {
            start_node(g_node[ii].node);
        }
    }
}

static int start_check_az(const char* azName)
{
    int ret = CM_STATUS_UNKNOWN;

    for (uint32 ii = 0; ii < g_node_num; ii++) {
        if (strcmp(g_node[ii].azName, azName) == 0) {
            int node_status;

            node_status = start_check_node(ii);
            if (node_status == CM_STATUS_UNKNOWN) {
                ret = CM_STATUS_UNKNOWN;
                break;
            } else if (node_status == CM_STATUS_NORMAL_WITH_CN_DELETED) {
                ret = CM_STATUS_NORMAL_WITH_CN_DELETED;
            } else if (node_status == CM_STATUS_NORMAL && ret != CM_STATUS_NORMAL_WITH_CN_DELETED) {
                ret = CM_STATUS_NORMAL;
            }
        }
    }
    // start remote maybe failed, by try to let success
    if (startaz_try_heartbeat <= 0) {
        start_az_try_more_one(g_command_operation_azName);
        startaz_try_heartbeat = START_AZ_TRY_HEARTBEAT;
    }

    return ret;
}

void getPauseStatus()
{
    struct stat statBuf = { 0 };
    if (stat(manual_pause_file, &statBuf) == 0) {
        g_isPauseArbitration = true;
    } else {
        g_isPauseArbitration = false;
    }
}