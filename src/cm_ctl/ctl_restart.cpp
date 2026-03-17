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
 * ctl_restart.cpp
 *    cm_ctl restart [-L LCNAME]
 *
 * IDENTIFICATION
 *    src/cm_ctl/ctl_restart.cpp
 *
 * -------------------------------------------------------------------------
 */
#include <signal.h>
#include "common/config/cm_config.h"
#include "cm/libpq-fe.h"
#include "cm/cm_misc.h"
#include "ctl_common.h"
#include "cm/cm_msg.h"
#include "cm/cm_agent/cma_main.h"

#define START_DEFAULT_WAIT 600
#define CM_STOP_STATUS_UNKNOWN (-1)
#define SINGLE_INSTANCE 0
#define CM_STOP_STATUS_STOP 2
#define INSTANCE_START_CONFIRM_TIME 3

#ifdef ENABLE_MULTIPLE_NODES
static int g_all_instance_start_status = CM_STATUS_UNKNOWN;
static int g_all_instance_stop_status_lc = CM_STOP_STATUS_UNKNOWN;
#endif

extern int do_force;
extern int shutdown_level;
extern ShutdownMode shutdown_mode_num;
extern bool wait_seconds_set;
extern int g_waitSeconds;
extern time_t CHECK_BUILDING_DN_TIMEOUT;
extern bool is_check_building_dn;
extern char mpp_env_separate_file[MAXPGPATH];
extern char result_path[MAXPGPATH];
extern char* g_command_operation_lcName;
extern uint32 g_nodeId;
extern char instance_manual_start_file[MAXPGPATH];
extern char cluster_manual_starting_file[MAXPGPATH];
extern bool switchover_all_quick;

#ifdef ENABLE_MULTIPLE_NODES
static void do_stop_lc(void);
static void do_start_lc(void);
static void stop_instance_lc(uint32 nodeid, uint32 instanceId);
static void stop_instance_check_lc(void);
static int stop_check_one_instance_lc(uint32 node_id_check, const char* datapath);
static void* check_instance_stop_status_lc(void* arg);
static void start_instance_lc(uint32 nodeid, uint32 instanceId);
static int start_instance_check_lc(void);
static int start_check_one_instance_lc(uint32 node_id_check, const char* datapath);
static void* check_instance_start_status(void* arg);
static int get_nodeIndex_from_nodeId(uint32 node_id);

void do_logic_cluster_restart(void)
{
    char Command_set[] = {"cm_ctl set --cm_failover_delay_time=180 > /dev/null 2>&1 &"};
    char Command_set_bak[] = {"cm_ctl set --cm_failover_delay_time=2 > /dev/null 2>&1 &"};
    int ret = system(Command_set);
    if (ret != 0) {
        write_runlog(ERROR,
            "Failed to set the failover delay time with executing the command: command=\"%s\","
            " nodeId=%u, systemReturn=%d, shellReturn=%d, errno=%d.\n",
            Command_set,
            g_currentNode->node,
            ret,
            SHELL_RETURN_CODE(ret),
            errno);
    }

    do_stop_lc();
    do_start_lc();

    ret = system(Command_set_bak);
    if (ret != 0) {
        write_runlog(ERROR,
            "Failed to set the failover delay time with executing the command: command=\"%s\","
            " nodeId=%u, systemReturn=%d, shellReturn=%d, errno=%d.\n",
            Command_set_bak,
            g_currentNode->node,
            ret,
            SHELL_RETURN_CODE(ret),
            errno);
    }
}

static void do_stop_lc(void)
{
    for (uint32 ii = 0; ii < g_logic_cluster_count; ii++) {
        if (strcmp(g_command_operation_lcName, g_logicClusterStaticConfig[ii].LogicClusterName) != 0) {
            continue;
        }
        for (uint32 jj = 0; jj < g_logicClusterStaticConfig[ii].logicClusterNodeHeader.nodeCount; jj++) {
            for (uint32 kk = 0; kk < g_logicClusterStaticConfig[ii].logicClusterNode[jj].datanodeCount; kk++) {
                stop_instance_lc(g_logicClusterStaticConfig[ii].logicClusterNode[jj].node,
                    g_logicClusterStaticConfig[ii].logicClusterNode[jj].datanodeId[kk]);
            }
        }
        break;
    }

    /* creat a thread to check instances' status     */
    pthread_t thr_id;
    int ret = pthread_create(&thr_id, NULL, &check_instance_stop_status_lc, NULL);
    if (ret != 0) {
        write_runlog(FATAL, "failed to create thread to check if cluster stopped.\n");
        exit(-1);
    }

    stop_instance_check_lc();
}

static void do_start_lc(void)
{
    for (uint32 ii = 0; ii < g_logic_cluster_count; ii++) {
        if (strcmp(g_command_operation_lcName, g_logicClusterStaticConfig[ii].LogicClusterName) != 0) {
            continue;
        }
        for (uint32 jj = 0; jj < g_logicClusterStaticConfig[ii].logicClusterNodeHeader.nodeCount; jj++) {
            for (uint32 kk = 0; kk < g_logicClusterStaticConfig[ii].logicClusterNode[jj].datanodeCount; kk++) {
                start_instance_lc(g_logicClusterStaticConfig[ii].logicClusterNode[jj].node,
                    g_logicClusterStaticConfig[ii].logicClusterNode[jj].datanodeId[kk]);
            }
        }
    }

    /* creaet a thread to check instances' status */
    pthread_t thr_id;
    int ret = pthread_create(&thr_id, NULL, &check_instance_start_status, NULL);
    if (ret != 0) {
        write_runlog(FATAL, "failed to create thread to check if cluster started.\n");
        exit(-1);
    }

    /* check node' s status */
    if (start_instance_check_lc() != 0) {
        exit(-1);
    }
    return;
}

static void stop_instance_lc(uint32 nodeid, uint32 instanceId)
{
    char command[MAXPGPATH];
    char command_opts[MAXPGPATH];
    uint32 ii = 0;
    int nRet;

    shutdown_level = SINGLE_INSTANCE;

    nRet = snprintf_s(command_opts,
        MAXPGPATH,
        MAXPGPATH - 1,
        "echo -e \'%d\\n%d\\n%d\' >  %s_%u;chmod 600 %s_%u",
        do_force,
        (int)shutdown_mode_num,
        shutdown_level,
        instance_manual_start_file,
        instanceId,
        instance_manual_start_file,
        instanceId);
    securec_check_intval(nRet, (void)nRet);
    nRet = snprintf_s(
        command, MAXPGPATH, MAXPGPATH - 1, SYSTEMQUOTE "%s < \"%s\" 2>&1 &" SYSTEMQUOTE, command_opts, DEVNULL);
    securec_check_intval(nRet, (void)nRet);

    if (nodeid == g_currentNode->node) {
        nRet = system(command);
    } else {
        for (ii = 0; ii < g_node_num; ii++) {
            if (g_node[ii].node == nodeid) {
                break;
            }
        }
        if (ii < g_node_num) {
            nRet = ssh_exec(&g_node[ii], command);
        } else {
            write_runlog(ERROR, "can't find the nodeid: %u\n", nodeid);
        }
    }

    if (nRet != 0) {
        write_runlog(ERROR,
            "Failed to stop the logical cluster instance with executing the command: command=\"%s\","
            " nodeId=%u, instanceId=%u, systemReturn=%d, shellReturn=%d, errno=%d.\n",
            command,
            g_node[ii].node,
            instanceId,
            nRet,
            SHELL_RETURN_CODE(nRet),
            errno);
    }
}


static int stop_check_one_instance_lc(uint32 node_id_check, const char* datapath)
{
    int result = -1;

    if (checkStaticConfigExist(node_id_check) != 0) {
        write_runlog(
            ERROR, "the cluster static config file does not exist on the node: %u.\n", g_node[node_id_check].node);
        write_runlog(FATAL, "failed to check the logical cluster instance stop status: %s.\n", datapath);
        exit(-1);
    }

    /* datanode */
    for (uint32 ii = 0; ii < g_node[node_id_check].datanodeCount; ii++) {
        char* local_data_path = g_node[node_id_check].datanode[ii].datanodeLocalDataPath;

        if (strncmp(datapath, local_data_path, MAX_PATH_LEN) == 0) {
            CheckDnNodeStatusById(node_id_check, &result, ii);
            if (result == PROCESS_NOT_EXIST && (shutdown_mode_num == IMMEDIATE_MODE ||
                (shutdown_mode_num == FAST_MODE && is_check_building_dn))) {
                char command[MAXPGPATH] = {0};
                int ret;
                char gausshomePath[MAXPGPATH] = {0};
                ret = GetHomePath(gausshomePath, sizeof(gausshomePath));
                if (ret != EOK) {
                    return -1;
                }
                if (node_id_check == g_nodeId && strstr(gausshomePath, "/var/chroot") == NULL) {
                    ret = snprintf_s(command,
                        MAXPGPATH,
                        MAXPGPATH - 1,
                        "cm_ctl check -B gs_ctl -T %s  \n echo  -e  $? > %s",
                        local_data_path,
                        result_path);
                    securec_check_intval(ret, (void)ret);
                    exec_system(command, &result, result_path);
                } else {
                    ret = snprintf_s(command,
                        MAXPGPATH,
                        MAXPGPATH - 1,
                        "cm_ctl check -B gs_ctl -T %s\" > /dev/null 2>&1; echo  -e $? > %s",
                        local_data_path,
                        result_path);
                    securec_check_intval(ret, (void)ret);
                    exec_system_ssh(node_id_check, command, &result, result_path, mpp_env_separate_file);
                }
            }

            return (result == PROCESS_NOT_EXIST) ? 0 : -1;
        }
    }

    return -1;
}

static void stop_instance_check_lc(void)
{
    uint32 ii;
    uint32 jj;
    uint32 kk;
    int rcs;

    for (ii = 0; ii < g_logic_cluster_count; ii++) {
        if (strcmp(g_command_operation_lcName, g_logicClusterStaticConfig[ii].LogicClusterName) != 0) {
            continue;
        }
        for (;;) {
            uint32 stop_instance_count = 0;
            uint32 all_lc_datenode_count = 0;
            int node_index = 0;
            for (jj = 0; jj < g_logicClusterStaticConfig[ii].logicClusterNodeHeader.nodeCount; jj++) {
                for (kk = 0; kk < g_logicClusterStaticConfig[ii].logicClusterNode[jj].datanodeCount; kk++) {
                    all_lc_datenode_count++;
                    node_index = get_nodeIndex_from_nodeId(g_logicClusterStaticConfig[ii].logicClusterNode[jj].node);
                    if (node_index == -1) {
                        write_runlog(FATAL,
                            "failed to find the node %u.\n",
                            g_logicClusterStaticConfig[ii].logicClusterNode[jj].node);
                        exit(-1);
                    }

                    rcs = stop_check_one_instance_lc(
                        (uint32)node_index, g_node[node_index].datanode[kk].datanodeLocalDataPath);
                    if (rcs == 0) {
                        stop_instance_count++;
                    }
                }
            }
            if (stop_instance_count == all_lc_datenode_count && (stop_instance_count != 0)) {
                g_all_instance_stop_status_lc = CM_STOP_STATUS_STOP;
                break;
            }
            (void)sleep(1);
        }
        break;
    }
    return;
}

static void* check_instance_stop_status_lc(void* arg)
{
#define STOP_WAIT_SECONDS_LC 3
    int i;
    const time_t    start_time = get_start_time();

    if (!wait_seconds_set) {
        /* wait 3mins */
        g_waitSeconds = DEFAULT_WAIT * STOP_WAIT_SECONDS_LC;
    }
    for (i = 0; i < g_waitSeconds; i++) {
        if (check_with_end_time(start_time) > CHECK_BUILDING_DN_TIMEOUT) {
            is_check_building_dn = false;
            write_runlog(DEBUG1, "Set is_check_building_dn to false.\n");
        }

        (void)sleep(1);
        write_runlog(LOG, ".");

        if (g_all_instance_stop_status_lc == CM_STOP_STATUS_STOP) {
            write_runlog(LOG, "stop instance successfully! \n");
            break;
        }
    }

    /* delete result */
    (void)unlink(result_path);

    if (g_all_instance_stop_status_lc == CM_STOP_STATUS_UNKNOWN) {
        write_runlog(ERROR, "stop instance failed in (%d)s!", g_waitSeconds);
        write_runlog(ERROR, "restart the %s failed.\n", g_command_operation_lcName);
        exit(-1);
    }

    return NULL;
}

static void start_instance_lc(uint32 nodeid, uint32 instanceId)
{
    char command[MAXPGPATH] = {0};
    int nRet;
    nRet = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1,
        SYSTEMQUOTE "rm -f %s_%u < \"%s\" 2>&1 &" SYSTEMQUOTE,
        instance_manual_start_file, instanceId, DEVNULL);
    securec_check_intval(nRet, (void)nRet);

    nRet = runCmdByNodeId(command, nodeid);
    if (nRet != 0) {
        write_runlog(ERROR,
            "Failed to start the logical cluster instance with executing the command: command=\"%s\","
            " nodeId=%u, instanceId=%u, systemReturn=%d, shellReturn=%d, errno=%d.\n",
            command, nodeid, instanceId, nRet, SHELL_RETURN_CODE(nRet), errno);
    }
}

static int start_instance_check_lc(void)
{
    uint32 ii;
    uint32 jj;
    uint32 kk;
    int logic_cluster_start_status = CM_STATUS_UNKNOWN;

    for (ii = 0; ii < g_logic_cluster_count; ii++) {
        if (strcmp(g_command_operation_lcName, g_logicClusterStaticConfig[ii].LogicClusterName) != 0) {
            continue;
        }
        for (;;) {
            uint32 start_instance_count = 0;
            uint32 all_lc_datenode_count = 0;
            int node_index = 0;
            for (jj = 0; jj < g_logicClusterStaticConfig[ii].logicClusterNodeHeader.nodeCount; jj++) {
                for (kk = 0; kk < g_logicClusterStaticConfig[ii].logicClusterNode[jj].datanodeCount; kk++) {
                    all_lc_datenode_count++;
                    node_index = get_nodeIndex_from_nodeId(g_logicClusterStaticConfig[ii].logicClusterNode[jj].node);
                    if (node_index == -1) {
                        write_runlog(ERROR,
                            "failed to find the node %u.\n",
                            g_logicClusterStaticConfig[ii].logicClusterNode[jj].node);
                        return -1;
                    }
                    logic_cluster_start_status = start_check_one_instance_lc(
                        (uint32)node_index, g_node[node_index].datanode[kk].datanodeLocalDataPath);
                    if (logic_cluster_start_status == CM_STATUS_NORMAL) {
                        start_instance_count++;
                    }
                }
            }
            if (start_instance_count == all_lc_datenode_count && (start_instance_count != 0)) {
                g_all_instance_start_status = CM_STATUS_NORMAL;
            } else {
                g_all_instance_start_status = CM_STATUS_UNKNOWN;
            }
            (void)sleep(1);
        }
    }
    return 0;
}

static int start_check_one_instance_lc(uint32 node_id_check, const char* datapath)
{
    if (checkStaticConfigExist(node_id_check) != 0) {
        write_runlog(
            ERROR, "the cluster static config file does not exist on the node: %u.\n", g_node[node_id_check].node);
        write_runlog(FATAL, "failed to check the logical cluster instance start status: %s.\n", datapath);
        exit(-1);
    }

    /* datanode */
    for (uint32 ii = 0; ii < g_node[node_id_check].datanodeCount; ii++) {
        int result = -1;
        char* local_data_path = g_node[node_id_check].datanode[ii].datanodeLocalDataPath;

        if (strncmp(datapath, local_data_path, MAX_PATH_LEN) == 0) {
            CheckDnNodeStatusById(node_id_check, &result, ii);
            return (result == PROCESS_RUNNING) ? CM_STATUS_NORMAL : CM_STATUS_UNKNOWN;
        }
    }

    return CM_STATUS_UNKNOWN;
}

static void* check_instance_start_status(void* arg)
{
    int count = 0;

    if (!wait_seconds_set) {
        g_waitSeconds = START_DEFAULT_WAIT;
    }

    for (int i = 0; i < g_waitSeconds; i++) {
        if (g_all_instance_start_status == CM_STATUS_NORMAL) {
            /*
             * CM Client found the instance running, but maybe it quit immediately after startup.
             * so only if CM Client found the instance running for 3 times, instance has started.
             */
            count++;
            if (count > INSTANCE_START_CONFIRM_TIME) {
                if (!switchover_all_quick) {
                    write_runlog(LOG, "start instance successfully.\n");
                    write_runlog(LOG, "restart the %s successful.\n", g_command_operation_lcName);
                }
                exit(0);
            }
        } else {
            count = 0;
        }
        (void)sleep(1);
        write_runlog(LOG, ".");
    }

    if (g_all_instance_start_status != CM_STATUS_NORMAL) {
        if (!switchover_all_quick) {
            write_runlog(ERROR, "start instance failed in (%d)s.\n", g_waitSeconds);
            write_runlog(ERROR, "restart the %s failed.\n", g_command_operation_lcName);
        }
    }
    exit(-1);
}

static int get_nodeIndex_from_nodeId(uint32 node_id)
{
    int node_index;
    uint32 ii;
    for (ii = 0; ii < g_node_num; ii++) {
        if (g_node[ii].node == node_id) {
            node_index = (int)ii;
            return node_index;
        }
    }
    return -1;
}
#endif