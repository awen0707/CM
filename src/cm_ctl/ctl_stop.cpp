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
 * ctl_stop.cpp
 *    cm_ctl stop [-z AVAILABILITY_ZONE] [-n NODEID] [-D DATADIR] [-m SHUTDOWN-MODE] [-t SECS] [-R]
 *
 * IDENTIFICATION
 *    src/cm_ctl/ctl_stop.cpp
 *
 * -------------------------------------------------------------------------
 */
#include <signal.h>
#include "common/config/cm_config.h"
#include "cm/libpq-fe.h"
#include "cm/cm_misc.h"
#include "ctl_common.h"
#include "ctl_common_res.h"
#include "cm/cm_msg.h"
#include "cm/cm_agent/cma_main.h"
#include "cm/libpq-int.h"

#define CM_STOP_STATUS_UNKNOWN (-1)
#define CM_STOP_STATUS_INIT 1
#define CM_STOP_STATUS_STOP 2

#define SINGLE_INSTANCE 0
#define SINGLE_NODE 1
#define ALL_NODES 2

#define ETCD_STOP_WAIT 300

#ifndef ENABLE_MULTIPLE_NODES
#define ITRAN_STOP_WAIT 30
void StopLtranProcess(uint32 nodeid);
extern char g_ltranManualStartFile[MAXPGPATH];
extern char g_libnetManualStartFile[MAXPGPATH];
#else
#include "ctl_distribute.h"
#endif
const int CHECKED_FINISH_STATUS = 0;
const int CHECKED_OTHER_STATUS = -1;

static void stop_cluster(void);
static void stop_az(const char* azName);
static int stop_node(uint32 nodeid);
static void stop_datanode_instance_relation(uint32 node, const char* dataPath);

static void* check_cluster_stop_status(void* arg);
static void stop_and_check_etcd_cluster();
static int stop_check_etcd_cluster();
static void stop_and_check_etcd_node(uint32 nodeid);
static int stop_check_etcd_node(uint32 nodeid);

static void stop_check();
static int stop_check_az(const char* azName);
static int stop_check_dn_relation(uint32  node, const char *dataPath);
static int stop_check_instance(uint32 node_id_check, const char* datapath);
static int stop_cm_server_arbitration();
static int calDigitNum(uint32 num);

static int g_cluster_stop_status = CM_STOP_STATUS_UNKNOWN;
static int g_az_stop_status = CM_STOP_STATUS_UNKNOWN;
static int g_node_stop_status = CM_STOP_STATUS_UNKNOWN;
static int g_instance_stop_status = CM_STOP_STATUS_UNKNOWN;
static int g_dn_relation_stop_status = CM_STOP_STATUS_UNKNOWN;
static int g_resStopStatus = CM_STOP_STATUS_UNKNOWN;
static int shutdown_level = 0;

extern bool got_stop;
extern int do_force;
extern int shutdown_level;
extern ShutdownMode shutdown_mode_num;
extern bool wait_seconds_set;
extern int g_waitSeconds;
extern time_t CHECK_BUILDING_DN_TIMEOUT;
extern bool is_check_building_dn;
extern char mpp_env_separate_file[MAXPGPATH];
extern passwd* pw;
extern bool g_commandRelationship;
extern char g_cmData[CM_PATH_LENGTH];
extern char pssh_out_path[MAXPGPATH];
extern char hosts_path[MAXPGPATH];
extern char result_path[MAXPGPATH];
extern char* g_command_operation_azName;
extern uint32 g_commandOperationNodeId;
extern uint32 g_commandOperationInstanceId;
extern uint32 g_nodeId;
extern char manual_start_file[MAXPGPATH];
extern char instance_manual_start_file[MAXPGPATH];
extern char etcd_manual_start_file[MAXPGPATH];
extern char g_appPath[MAXPGPATH];
extern CM_Conn* CmServer_conn;
extern bool g_stopAbnormal;

static int StopResInstCheck(uint32 instId)
{
    if (GetResInstStatus(instId) == CM_RES_STAT_OFFLINE) {
        return 0;
    }
    return -1;
}

static void StopResInst(uint32 nodeId, uint32 instId)
{
    char instanceStartFile[MAX_PATH_LEN] = {0};
    int ret = snprintf_s(instanceStartFile, MAX_PATH_LEN, MAX_PATH_LEN - 1,
        "%s/bin/instance_manual_start_%u", g_appPath, instId);
    securec_check_intval(ret, (void)ret);

    char command[MAX_PATH_LEN] = {0};
    ret = snprintf_s(command, MAX_PATH_LEN, MAX_PATH_LEN - 1, SYSTEMQUOTE "touch %s;chmod 600 %s < \"%s\" 2>&1"
        SYSTEMQUOTE, instanceStartFile, instanceStartFile, DEVNULL);
    securec_check_intval(ret, (void)ret);

    ret = runCmdByNodeId(command, nodeId);
    if (ret != 0) {
        write_runlog(DEBUG1, "Failed to stop the resource instance executing the command: command=\"%s\","
            " nodeId=%u, instId=%u, systemReturn=%d, shellReturn=%d, errno=%d.\n",
            command, nodeId, instId, ret, SHELL_RETURN_CODE(ret), errno);
    }
}

int DoStop(void)
{
    CtlGetCmJsonConf();
    if (g_commandOperationNodeId > 0 && get_node_index(g_commandOperationNodeId) >= g_node_num) {
        write_runlog(FATAL, "node_id specified is illegal. \n");
        return 1;
    }
#ifdef ENABLE_MULTIPLE_NODES
    if (g_command_operation_azName == NULL && g_commandOperationNodeId == 0 && shutdown_mode_num == RESUME_MODE) {
        write_runlog(LOG, "disable resuming fault CN which is deleted. \n");
        stop_resuming_cn();
        return 0;
    }
#endif

    if (g_commandOperationInstanceId == 0 && g_command_operation_azName == NULL && g_commandOperationNodeId == 0) {
        write_runlog(LOG, "stop cluster. \n");
        stop_cluster();
    } else if (g_command_operation_azName != NULL) {
        write_runlog(LOG, "stop the availability zone: %s. \n", g_command_operation_azName);
        stop_az(g_command_operation_azName);
    } else if (g_commandOperationInstanceId > 0) {
        if (CheckResInstInfo(&g_commandOperationNodeId, g_commandOperationInstanceId) != CM_SUCCESS) {
            write_runlog(ERROR, "can't do stop resource instance, instId:%u.\n", g_commandOperationInstanceId);
            return 1;
        }
        write_runlog(LOG, "stop resource instance.\n");
        StopResInst(g_commandOperationNodeId, g_commandOperationInstanceId);
    } else if (g_cmData[0] == '\0') {
        write_runlog(LOG, "stop the node: %u. \n", g_commandOperationNodeId);

        (void)stop_node(g_commandOperationNodeId);
    } else if (g_commandRelationship) {
        if (g_commandOperationNodeId == 0) {
            write_runlog(FATAL, "node_id specified is illegal.\n");
            return 1;
        }
        if (g_cmData[0] == '\0') {
            write_runlog(FATAL, "data path specified is illegal.\n");
            return 1;
        }

        write_runlog(LOG, "stop relation datanode.\n");
        stop_datanode_instance_relation(g_commandOperationNodeId, g_cmData);
    } else {
        write_runlog(LOG, "stop the node: %u, datapath: %s. \n", g_commandOperationNodeId, g_cmData);

        stop_instance(g_commandOperationNodeId, g_cmData);
    }

    /* create a thread to check cluster' status */
    pthread_t thr_id;
    if (pthread_create(&thr_id, NULL, &check_cluster_stop_status, NULL) != 0) {
        write_runlog(FATAL, "failed to create thread to check if cluster stopped.\n");
        return -1;
    }

    stop_check();

    return 0;
}

static void stop_cluster(void)
{
    if (got_stop) {
        return;
    }
    char command[MAXPGPATH];
    int ret;

    init_hosts();

    shutdown_level = ALL_NODES;

    if ((ret = stop_cm_server_arbitration()) == -1) {
        return;
    }

    for (uint32 ii = 0; ii < g_node_num; ii++) {
        if (!g_isRestop) {
            write_runlog(LOG, "stop nodeid: %u\n", g_node[ii].node);
        }
    }

    if (g_single_node_cluster) {
        if (mpp_env_separate_file[0] == '\0') {
            ret = snprintf_s(command,
                MAXPGPATH,
                MAXPGPATH - 1,
                SYSTEMQUOTE "source /etc/profile; echo -e \'%d\\n%d\\n%d\' >  %s;chmod 600 %s" SYSTEMQUOTE,
                do_force,
                shutdown_mode_num,
                shutdown_level,
                manual_start_file,
                manual_start_file);
        } else {
            ret = snprintf_s(command,
                MAXPGPATH,
                MAXPGPATH - 1,
                SYSTEMQUOTE "source /etc/profile; source %s; echo -e \'%d\\n%d\\n%d\' >  %s;chmod 600 %s" SYSTEMQUOTE,
                mpp_env_separate_file,
                do_force,
                shutdown_mode_num,
                shutdown_level,
                manual_start_file,
                manual_start_file);
        }
    } else {
        /*
         * in case that cm_ctl can't set stop command to etcd or cm_agent can't get stop command from etcd, cm_ctl
         * need also stop cluster by touching cluster_manual_start file through pssh, which has better performance than
         * ssh.
         */
        if (mpp_env_separate_file[0] == '\0') {
            ret = snprintf_s(command,
                MAXPGPATH,
                MAXPGPATH - 1,
                SYSTEMQUOTE "source /etc/profile;pssh -i %s -h %s \"echo -e \'%d\\n%d\\n%d\' >  %s;chmod 600 %s\" > "
                            "%s; if [ $? -ne 0 ]; then cat %s; fi; rm -f %s" SYSTEMQUOTE,
                PSSH_TIMEOUT_OPTION,
                hosts_path,
                do_force,
                shutdown_mode_num,
                shutdown_level,
                manual_start_file,
                manual_start_file,
                pssh_out_path,
                pssh_out_path,
                pssh_out_path);
        } else {
            ret = snprintf_s(command,
                MAXPGPATH,
                MAXPGPATH - 1,
                SYSTEMQUOTE "source /etc/profile;pssh -i %s -h %s \"source %s;echo -e \'%d\\n%d\\n%d\' >  %s;chmod 600 "
                            "%s\" > %s; if [ $? -ne 0 ]; then cat %s; fi; rm -f %s" SYSTEMQUOTE,
                PSSH_TIMEOUT_OPTION,
                hosts_path,
                mpp_env_separate_file,
                do_force,
                shutdown_mode_num,
                shutdown_level,
                manual_start_file,
                manual_start_file,
                pssh_out_path,
                pssh_out_path,
                pssh_out_path);
        }
    }
    securec_check_intval(ret, (void)ret);

    ret = system(command);
    if (ret != 0) {
        write_runlog(DEBUG1,
            "Failed to stop the cluster with executing the command: command=\"%s\", nodeId=%u,"
            " systemReturn=%d, shellReturn=%d, errno=%d.\n",
            command,
            g_currentNode->node,
            ret,
            SHELL_RETURN_CODE(ret),
            errno);
    }

    (void)unlink(hosts_path);
}

/*
 * find the node info according to availability zone
 */
static void stop_az(const char* azName)
{
    uint32 stopNodes[g_node_num];
    int num = 0;
    int nodeId;

    write_runlog(LOG, "stop availability zone, availability zone name: %s.\n", azName);
    for (uint32 ii = 0; ii < g_node_num; ii++) {
        if (strcmp(g_node[ii].azName, azName) == 0) {
            nodeId = stop_node(g_node[ii].node);
            if (nodeId != -1) {
                stopNodes[num] = (uint32)nodeId;
                num++;
            }
        }
    }

    if (num == 0) {
        write_runlog(WARNING, "neither node has been stopped.\n");
        return;
    }

    int etcdValueNum = 0;
    char etcdStopNodesKey[MAXPGPATH];
    char etcdStopNodesValue[MAXPGPATH];
    char stopNodesStr[MAXPGPATH];
    int rc;
    status_t res;

    rc = memset_s(etcdStopNodesKey, MAXPGPATH, 0, MAXPGPATH);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(etcdStopNodesValue, MAXPGPATH, 0, MAXPGPATH);
    securec_check_errno(rc, (void)rc);

    for (int ii = 0; ii < num; ii++) {
        int nextLength = (int)strlen(etcdStopNodesValue) + 1 + calDigitNum(stopNodes[ii]);
        if (nextLength < MAXPGPATH) {
            if (strlen(etcdStopNodesValue) == 0) {
                rc = snprintf_s(etcdStopNodesValue, MAXPGPATH, MAXPGPATH - 1, "%u", stopNodes[ii]);
                securec_check_intval(rc, (void)rc);
            } else {
                rc = snprintf_s(stopNodesStr, MAXPGPATH, MAXPGPATH - 1, "%u", stopNodes[ii]);
                securec_check_intval(rc, (void)rc);
                errno_t rno = strcat_s(etcdStopNodesValue, MAXPGPATH, ",");
                securec_check_errno(rno, (void)rno);
                rno = strcat_s(etcdStopNodesValue, MAXPGPATH, stopNodesStr);
                securec_check_errno(rno, (void)rno);
            }
        }

        if ((nextLength < MAXPGPATH && ii == num - 1) || nextLength >= MAXPGPATH) {
            rc = snprintf_s(
                etcdStopNodesKey, MAXPGPATH, MAXPGPATH - 1, "/%s/command/%d/az_stop_nodes", pw->pw_name, etcdValueNum);
            securec_check_intval(rc, (void)rc);

            res = SendKVToCms(etcdStopNodesKey, etcdStopNodesValue, "stopAz");
            if (res != CM_SUCCESS) {
                write_runlog(DEBUG1, "etcd set stop_nodes failed, nodes are: (%s). ETCD set error.\n",
                    etcdStopNodesValue);
            } else {
                write_runlog(DEBUG1, "etcd set stop_nodes successfully, nodes are: (%s).\n", etcdStopNodesValue);
            }

            etcdValueNum++;
            rc = memset_s(etcdStopNodesKey, MAXPGPATH, 0, MAXPGPATH);
            securec_check_errno(rc, (void)rc);
            rc = memset_s(etcdStopNodesValue, MAXPGPATH, 0, MAXPGPATH);
            securec_check_errno(rc, (void)rc);
        }
    }

    rc = snprintf_s(etcdStopNodesKey, MAXPGPATH, MAXPGPATH - 1, "/%s/command/az_stop_nodes_num", pw->pw_name);
    securec_check_intval(rc, (void)rc);
    rc = snprintf_s(etcdStopNodesValue, MAXPGPATH, MAXPGPATH - 1, "%d", etcdValueNum);
    securec_check_intval(rc, (void)rc);

    res = SendKVToCms(etcdStopNodesKey, etcdStopNodesValue, "stopAz");
    if (res != CM_SUCCESS) {
        write_runlog(DEBUG1, "etcd set stop_nodes_num failed, nodes num is: (%d). ETCD set error.\n", etcdValueNum);
    } else {
        write_runlog(DEBUG1, "etcd set stop_nodes_num successfully, nodes num is: (%d).\n", etcdValueNum);
    }
}

/*
 * find the node info according to nodeid
 */
static int stop_node(uint32 nodeid)
{
    if (got_stop) {
        return -1;
    }
    char command[MAXPGPATH] = {0};
    char command_opts[MAXPGPATH] = {0};
    uint32 ii;
    int ret;
    
    shutdown_level = SINGLE_NODE;
    if (g_etcd_num > 0 && nodeid != g_currentNode->node && CheckDdbHealth()) {
        write_runlog(DEBUG1, "stop node, etcd healthy.\n");
    } else {
        do_force = 1;
    }

    write_runlog(LOG, "stop node, nodeid: %u\n", nodeid);
    if (nodeid == g_currentNode->node) {
        ret = snprintf_s(command_opts, MAXPGPATH, MAXPGPATH - 1, "echo -e \'%d\\n%d\\n%d\' >  %s; chmod 600 %s",
            do_force, shutdown_mode_num, shutdown_level, manual_start_file, manual_start_file);
        securec_check_intval(ret, (void)ret);

        ret = snprintf_s(
            command, MAXPGPATH, MAXPGPATH - 1, SYSTEMQUOTE "%s < \"%s\" 2>&1 &" SYSTEMQUOTE, command_opts, DEVNULL);
        securec_check_intval(ret, (void)ret);
        ret = system(command);
    } else {
        for (ii = 0; ii < g_node_num; ii++) {
            if (g_node[ii].node == nodeid) {
                break;
            }
        }
        if (ii < g_node_num) {
            ret = snprintf_s(command_opts, MAXPGPATH, MAXPGPATH - 1, "echo -e \'%d\\n%d\\n%d\' >  %s; chmod 600 %s",
                do_force, shutdown_mode_num, shutdown_level, manual_start_file, manual_start_file);
            securec_check_intval(ret, (void)ret);

            ret = snprintf_s(
                command, MAXPGPATH, MAXPGPATH - 1, SYSTEMQUOTE "%s < \"%s\" 2>&1 &" SYSTEMQUOTE, command_opts, DEVNULL);
            securec_check_intval(ret, (void)ret);
            ret = ssh_exec(&g_node[ii], command);
        } else {
            write_runlog(ERROR, "can't find the nodeid: %u\n", nodeid);
            exit(1);
        }
    }

    if (ret != 0) {
        write_runlog(DEBUG1, "Failed to stop the node with executing the command: command=\"%s\","
            " nodeId=%u, systemReturn=%d, shellReturn=%d, errno=%d.\n",
            command, nodeid, ret, SHELL_RETURN_CODE(ret), errno);
        return -1;
    } else {
        return (int)nodeid;
    }
}

static void StopInstanceByInstanceId(uint32 instanceId)
{
    for (uint32 i = 0; i < g_node_num; i++) {
        for (uint32 j = 0; j < g_node[i].datanodeCount; j++) {
            if (instanceId == g_node[i].datanode[j].datanodeId) {
                stop_instance(g_node[i].node, g_node[i].datanode[j].datanodeLocalDataPath);
                write_runlog(LOG, "stop the node:%u,datapath:%s. \n",
                    g_node[i].node, g_node[i].datanode[j].datanodeLocalDataPath);
                return;
            }
        }
    }
}

static void stop_datanode_instance_relation(uint32 node, const char* dataPath)
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
            StopInstanceByInstanceId(instanceId);
        }
    }
}

void stop_instance(uint32 nodeid, const char *datapath)
{
    int ret;
    uint32 instanceId;
    int instance_type;
    char command[MAXPGPATH];
    char command_opts[MAXPGPATH];

    shutdown_level = SINGLE_INSTANCE;

    ret = FindInstanceIdAndType(nodeid, datapath, &instanceId, &instance_type);
    if (ret != 0) {
        write_runlog(ERROR, "can't find the node_id:%u, data_path:%s.\n", nodeid, datapath);
        exit(1);
    }
    ret = snprintf_s(command_opts,
        MAXPGPATH,
        MAXPGPATH - 1,
        "echo -e \'%d\\n%d\\n%d\' >  %s_%u;chmod 600 %s_%u",
        do_force,
        shutdown_mode_num,
        shutdown_level,
        instance_manual_start_file,
        instanceId,
        instance_manual_start_file,
        instanceId);
    securec_check_intval(ret, (void)ret);
    ret = snprintf_s(
        command, MAXPGPATH, MAXPGPATH - 1, SYSTEMQUOTE "%s < \"%s\" 2>&1 &" SYSTEMQUOTE, command_opts, DEVNULL);
    securec_check_intval(ret, (void)ret);

    ret = runCmdByNodeId(command, nodeid);
    if (ret != 0) {
        write_runlog(DEBUG1,
            "Failed to stop the instance with executing the command: command=\"%s\","
            " nodeId=%u, dataPath=\"%s\", systemReturn=%d, shellReturn=%d, errno=%d.\n",
            command,
            nodeid,
            datapath,
            ret,
            SHELL_RETURN_CODE(ret),
            errno);
    }
}

int CheckClusterStopFileStatus()
{
    int ret;
    char command[MAXPGPATH];

    if (g_single_node_cluster) {
        if (mpp_env_separate_file[0] == '\0') {
            ret = snprintf_s(command,
                MAXPGPATH,
                MAXPGPATH - 1,
                SYSTEMQUOTE "source /etc/profile; if [ -f %s ]; then exit 0;"
                            "else exit 1; fi" SYSTEMQUOTE,
                manual_start_file);
        } else {
            ret = snprintf_s(command,
                MAXPGPATH,
                MAXPGPATH - 1,
                SYSTEMQUOTE "source /etc/profile; source %s; if [ -f %s ];"
                            "then exit 0; else exit 1; fi" SYSTEMQUOTE,
                mpp_env_separate_file,
                manual_start_file);
        }
    } else {
        if (mpp_env_separate_file[0] == '\0') {
            ret = snprintf_s(command,
                MAXPGPATH,
                MAXPGPATH - 1,
                SYSTEMQUOTE "source /etc/profile; pssh -i %s -h %s if [ -f %s ];"
                            "then exit 0; else exit 1; fi" SYSTEMQUOTE,
                PSSH_TIMEOUT_OPTION,
                hosts_path,
                manual_start_file);
        } else {
            ret = snprintf_s(command,
                MAXPGPATH,
                MAXPGPATH - 1,
                SYSTEMQUOTE "source /etc/profile; pssh -i %s -h %s \"source %s;"
                            "if [ -f %s ]; then exit 0; else exit 1; fi" SYSTEMQUOTE,
                PSSH_TIMEOUT_OPTION,
                hosts_path,
                mpp_env_separate_file,
                manual_start_file);
        }
    }
    securec_check_intval(ret, (void)ret);

    ret = system(command);
    if (ret != 0) {
        write_runlog(DEBUG1,
            "Failed to check the stop_flag_file with executing the command: command=\"%s\", nodeId=%u.\n",
            command,
            g_currentNode->node);
        return ret;
    }

    (void)unlink(hosts_path);
    return CM_SUCCESS;
}

static void* check_cluster_stop_status(void* arg)
{
    int i;
    uint32 ii;
    const time_t startTime = get_start_time();

#ifndef ENABLE_MULTIPLE_NODES
    struct stat libnetManualStat = {0};
#endif
    if (!wait_seconds_set) {
        /* caculate timeout based on the number of nodes */
        g_waitSeconds = caculate_default_timeout(STOP_COMMAND);
    }
restop:
    for (i = 0; i < g_waitSeconds; i++) {
        if (check_with_end_time(startTime) > CHECK_BUILDING_DN_TIMEOUT) {
            is_check_building_dn = false;
            write_runlog(DEBUG1, "Set is_check_building_dn to false.\n");
        }
        (void)sleep(1);
        write_runlog(LOG, ".");

        if (g_cluster_stop_status == CM_STOP_STATUS_STOP) {
            if (g_stopAbnormal) {
                write_runlog(LOG, "stop cluster partly successfully.\n");
            } else {
                write_runlog(LOG, "stop cluster successfully.\n");
            }
            (void)unlink(result_path);
            if (g_etcd_num > 0) {
                write_runlog(LOG, "stopping the ETCD cluster.\n");
                stop_and_check_etcd_cluster();
            }
#ifndef ENABLE_MULTIPLE_NODES
            for (ii = 0; ii < g_node_num; ii++) {
                if (stat(g_libnetManualStartFile, &libnetManualStat) == 0) {
                    StopLtranProcess(g_node[ii].node);
                }
            }
#endif
            exit(0);
        } else if (g_az_stop_status == CM_STOP_STATUS_STOP) {
            for (ii = 0; ii < g_node_num; ii++) {
                if (strcmp(g_node[ii].azName, g_command_operation_azName) == 0) {
                    write_runlog(LOG, "stop node successfully, nodeid: %u. \n", g_node[ii].node);

                    if (g_node[ii].etcd) {
                        write_runlog(LOG, "stopping the ETCD instance in node: %u. \n", g_node[ii].node);
                        stop_and_check_etcd_node(g_node[ii].node);
                    }
#ifndef ENABLE_MULTIPLE_NODES
                    if (stat(g_libnetManualStartFile, &libnetManualStat) == 0) {
                        StopLtranProcess(g_node[ii].node);
                    }
#endif
                }
            }
            write_runlog(LOG, "stop availability zone successfully. \n");
            (void)unlink(result_path);
            exit(0);
        } else if (g_node_stop_status == CM_STOP_STATUS_STOP) {
            write_runlog(LOG, "stop node successfully. \n");
            for (ii = 0; ii < g_node_num; ii++) {
                if (g_node[ii].node == g_commandOperationNodeId && g_node[ii].etcd) {
                    write_runlog(LOG, "stopping the ETCD instance. \n");
                    stop_and_check_etcd_node(g_node[ii].node);
                }
#ifndef ENABLE_MULTIPLE_NODES
                if (g_node[ii].node == g_commandOperationNodeId) {
                    if (stat(g_libnetManualStartFile, &libnetManualStat) == 0) {
                        StopLtranProcess(g_node[ii].node);
                    }
                }
#endif
            }
            (void)unlink(result_path);
            exit(0);
        } else if (g_instance_stop_status == CM_STOP_STATUS_STOP) {
            write_runlog(LOG, "stop instance successfully. \n");
            (void)unlink(result_path);
            exit(0);
        } else if (g_dn_relation_stop_status == CM_STOP_STATUS_STOP) {
            write_runlog(LOG, "stop relation instance successfully. \n");
            (void)unlink(result_path);
            exit(0);
        } else if (g_resStopStatus == CM_STOP_STATUS_STOP) {
            write_runlog(LOG, "stop resource instance successfully(nodeId:%u, instId:%u).\n",
                g_commandOperationNodeId, g_commandOperationInstanceId);
            exit(0);
        }
    }

    /* delete result */
    (void)unlink(result_path);

    if (g_cluster_stop_status == CM_STOP_STATUS_INIT) {
        if (shutdown_mode_num == FAST_MODE && g_waitSeconds >= caculate_default_timeout(STOP_COMMAND)) {
            shutdown_mode_num = IMMEDIATE_MODE;
            if (CheckClusterStopFileStatus() != 0) {
                write_runlog(ERROR,
                    "stop cluster failed in (%d)s!\n\n"
                    "HINT: cluster_manual_start is not exist, Maybe \"cm_ctl start\" was executed after stop.\n",
                    g_waitSeconds);
            } else {
                g_isRestop = true;
                write_runlog(ERROR,
                    "stop cluster failed in (%d)s!\n\n"
                    "HINT: The cluster will be stopped again.\n",
                    g_waitSeconds);
                stop_cluster();
                g_isRestop = false;
                goto restop;
            }
        } else {
            write_runlog(ERROR,
                "stop cluster failed in (%d)s!\n\n"
                "HINT: Maybe the cluster is continually being stopped in the background.\n"
                "You can wait for a while and check whether the cluster stops, or immediately stop the cluster using "
                "\"cm_ctl stop -m i\".\n",
                g_waitSeconds);
        }
    } else if (g_az_stop_status == CM_STOP_STATUS_INIT) {
        write_runlog(ERROR,
            "stop availability zone failed in (%d)s!\n\n"
            "HINT: Maybe the availability zone is continually being stopped in the background.\n"
            "You can wait for a while and check whether the availability zone stops, or immediately stop the cluster "
            "using "
            "\"cm_ctl stop -z <azid> -m i\".\n",
            g_waitSeconds);
    } else if (g_node_stop_status == CM_STOP_STATUS_INIT) {
        write_runlog(ERROR,
            "stop node failed in (%d)s!\n\n"
            "HINT: Maybe the node is continually being stopped in the background.\n"
            "You can wait for a while and check whether the node stops, or immediately stop the node using "
            "\"cm_ctl stop -n <nodeid> -m i\".\n",
            g_waitSeconds);
    } else if (g_instance_stop_status == CM_STOP_STATUS_INIT) {
        write_runlog(ERROR,
            "stop instance failed in (%d)s!\n\n"
            "HINT: Maybe the instance is continually being stopped in the background.\n"
            "You can wait for a while and check whether the instance stops, or immediately stop the instance using "
            "\"cm_ctl stop -D <datapath> -m i\".\n",
            g_waitSeconds);
    } else if (g_resStopStatus == CM_STOP_STATUS_INIT) {
        write_runlog(ERROR,
            "stop resource instance failed in (%d)s!\n\n"
            "HINT: Maybe the instance is continually being stopped in the background.\n"
            "You can wait for a while and check whether the instance stops, or immediately stop the instance using "
            "\"cm_ctl stop -D <datapath> -m i\".\n",
            g_waitSeconds);
    }

    exit(-1);
}

/*
 * @Description: stop ETCD cluster.
 */
static void stop_and_check_etcd_cluster()
{
    int j = 0;

    stop_etcd_cluster();
    while (j < ETCD_STOP_WAIT) {
        (void)sleep(1);
        write_runlog(LOG, ".");
        if (stop_check_etcd_cluster() == 0) {
            write_runlog(LOG, "The ETCD cluster stops successfully.\n");
            break;
        }
        j++;
    }
    if (j == ETCD_STOP_WAIT) {
        write_runlog(ERROR, "failed to stop the ETCD cluster.\n");
        exit(-1);
    }
}

static int StopExecEtcdCluser(uint32 num, char *command, uint32 cmdLen)
{
    int ret;
    int result = -1;
    
    if (num == g_nodeId && strstr(g_appPath, "/var/chroot") == NULL) {
        ret = snprintf_s(command, cmdLen, cmdLen - 1, "cm_ctl check -B etcd -T %s/bin/etcd \n echo  -e  $? > %s",
            g_appPath, result_path);
        securec_check_intval(ret, (void)ret);
        exec_system(command, &result, result_path);
    } else {
        ret = snprintf_s(command, cmdLen, cmdLen - 1,
            "cm_ctl check -B etcd -T %s/bin/etcd\" > /dev/null 2>&1; echo  -e $? > %s",
            g_appPath, result_path);
        securec_check_intval(ret, (void)ret);
        exec_system_ssh(num, command, &result, result_path, mpp_env_separate_file);
    }

    return result;
}

static int stop_check_etcd_cluster()
{
    int result;

    for (uint32 i = 0; i < g_node_num; i++) {
        if (g_node[i].etcd) {
            char command[MAX_PATH_LEN] = {0};
            if (checkStaticConfigExist(i) != 0) {
                write_runlog(ERROR, "the cluster static config file does not exist on the node: %u.\n", g_node[i].node);
                write_runlog(FATAL, "failed to check the etcd cluster stop status.\n");
                exit(-1);
            }
            result = StopExecEtcdCluser(i, command, MAX_PATH_LEN);
            if (result == PROCESS_WAIT_START) {
                write_runlog(LOG, "When check instance, process is working in WAIT_START.\n");
            }
            if (result != PROCESS_NOT_EXIST && result != PROCESS_WAIT_START) {
                return CHECKED_OTHER_STATUS;
            }
        }
    }

    return CHECKED_FINISH_STATUS;
}

static void stop_check()
{
    uint32 ii;
    int ret;
    bool finished = false;
    bool firstStopCheck = true;

    for (;;) {
        if (finished) {
            (void)sleep(1);
            continue;
        }

        /* firstStopCheck: The first time to stop check.
         * In order to prevent stop-check before all instances exit,
         * we need to wait for a period of time to stop check at the first stop-check
         * The first waiting time is g_node_num / 2 seconds, and then 1 second.
         */
        if (firstStopCheck) {
            (void)sleep(g_node_num / 2);
            firstStopCheck = false;
        } else {
            (void)sleep(1);
        }

        if (g_command_operation_azName == NULL && g_commandOperationNodeId == 0) {
            g_cluster_stop_status = CM_STOP_STATUS_INIT;

            ret = g_single_node_cluster ? CheckSingleClusterRunningStatus() : CheckClusterRunningStatus();
            if (ret == 0) {
                g_cluster_stop_status = CM_STOP_STATUS_STOP;
                finished = true;
            }
        } else if (g_command_operation_azName != NULL) {
            g_az_stop_status = CM_STOP_STATUS_INIT;

            ret = stop_check_az(g_command_operation_azName);
            if (ret == 0) {
                g_az_stop_status = CM_STOP_STATUS_STOP;
                finished = true;
            }
        } else if ((g_commandOperationNodeId > 0) && (g_commandOperationInstanceId > 0)) {
            g_resStopStatus = CM_STOP_STATUS_INIT;
            if (StopResInstCheck(g_commandOperationInstanceId) == 0) {
                g_resStopStatus = CM_STOP_STATUS_STOP;
                finished = true;
            }
        } else if (g_cmData[0] == '\0') {
            g_node_stop_status = CM_STOP_STATUS_INIT;

            for (ii = 0; ii < g_node_num; ii++) {
                if (g_node[ii].node == g_commandOperationNodeId) {
                    break;
                }
            }

            if (ii >= g_node_num) {
                write_runlog(FATAL, "can't find the nodeid: %u\n", g_commandOperationNodeId);
                exit(1);
            }

            ret = stop_check_node(ii);
            if (ret == 0) {
                g_node_stop_status = CM_STOP_STATUS_STOP;
                finished = true;
            }
        } else if (g_commandRelationship) {
            g_dn_relation_stop_status = stop_check_dn_relation(g_commandOperationNodeId, g_cmData);
        } else {
            g_instance_stop_status = CM_STOP_STATUS_INIT;

            for (ii = 0; ii < g_node_num; ii++) {
                if (g_node[ii].node == g_commandOperationNodeId) {
                    break;
                }
            }

            if (ii >= g_node_num) {
                write_runlog(FATAL, "can't find the nodeid: %u\n", g_commandOperationNodeId);
                exit(1);
            }

            ret = stop_check_instance(ii, g_cmData);
            if (ret == 0) {
                g_instance_stop_status = CM_STOP_STATUS_STOP;
                finished = true;
            }
        }
    }
}

static int stop_check_az(const char* azName)
{
    uint32 node_count = 0;
    uint32 stopped_node_count = 0;

    for (uint32 ii = 0; ii < g_node_num; ii++) {
        if (strcmp(g_node[ii].azName, azName) == 0) {
            node_count++;
            if (stop_check_node(ii) == 0) {
                stopped_node_count++;
            }
        }
    }

    return (node_count == stopped_node_count) ? 0 : -1;
}

static int StopExecNode(uint32 nodeId, char *command, uint32 cmdLen, const char *cmBinPath)
{
    int ret;
    int result = -1;
    
    if (nodeId == g_nodeId && strstr(g_appPath, "/var/chroot") == NULL) {
        ret = snprintf_s(command, cmdLen, cmdLen - 1, "cm_ctl check -B %s -T %s  \n echo  -e  $? > %s",
            CM_AGENT_BIN_NAME, cmBinPath, result_path);
        securec_check_intval(ret, (void)ret);
        exec_system(command, &result, result_path);
    } else {
        ret = snprintf_s(command, cmdLen, cmdLen - 1,
            "cm_ctl check -B %s -T %s\" > /dev/null 2>&1; echo  -e $? > %s",
            CM_AGENT_BIN_NAME, cmBinPath, result_path);
        securec_check_intval(ret, (void)ret);
        exec_system_ssh(nodeId, command, &result, result_path, mpp_env_separate_file);
    }

    return result;
}


int stop_check_node(uint32 node_id_check)
{
    char command[MAX_PATH_LEN] = {0};
    char cmBinPath[MAX_PATH_LEN] = {0};

    if (checkStaticConfigExist(node_id_check) != 0) {
        write_runlog(
            ERROR, "the cluster static config file does not exist on the node: %u.\n", g_node[node_id_check].node);
        write_runlog(FATAL, "failed to check the node stop status.\n");
        exit(-1);
    }

    errno_t ret = snprintf_s(cmBinPath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/%s", g_appPath, CM_AGENT_BIN_NAME);
    securec_check_intval(ret, (void)ret);

    int result = StopExecNode(node_id_check, command, MAX_PATH_LEN, cmBinPath);
    if (result == PROCESS_WAIT_START) {
        write_runlog(LOG, "When check instance, process is working in WAIT_START.\n");
    }
    return (result == PROCESS_NOT_EXIST || result == PROCESS_WAIT_START) ?
        CHECKED_FINISH_STATUS : CHECKED_OTHER_STATUS;
}

static int CheckInstanceByInstanceid(uint32 instanceId)
{
    bool find = false;
    int relationStartStatus = CM_STATUS_UNKNOWN;
    for (uint32 i = 0; i < g_node_num; i++) {
        for (uint32 j = 0; j < g_node[i].datanodeCount; j++) {
            if (instanceId == g_node[i].datanode[j].datanodeId) {
                find = true;
                relationStartStatus = stop_check_instance(i, g_node[i].datanode[j].datanodeLocalDataPath);
                if (relationStartStatus != 0) {
                    return relationStartStatus;
                } else {
                    relationStartStatus = CM_STOP_STATUS_STOP;
                }
                break;
            }
        }
        if (find) {
            break;
        }
    }
    if (!find) {
        write_runlog(ERROR, "can't find node:path.\n");
        exit(1);
    }
    return relationStartStatus;
}

static int stop_check_dn_relation(uint32 node, const char* dataPath)
{
    int ret;
    uint32 instanceId;
    int relationStatus = CM_STATUS_UNKNOWN;
    cm_to_ctl_get_datanode_relation_ack getInstanceMsg = {0};
    ret = GetDatanodeRelationInfo(node, dataPath, &getInstanceMsg);
    if (ret == -1) {
        write_runlog(ERROR, "can not get datanode information.\n");
        exit(1);
    }
    for (int i = 0; i < CM_PRIMARY_STANDBY_MAX_NUM; i++) {
        instanceId = getInstanceMsg.instanceMember[i].instanceId;
        if (instanceId != 0) {
            relationStatus = CheckInstanceByInstanceid(instanceId);
            if (relationStatus != CM_STOP_STATUS_STOP) {
                return relationStatus;
            }
        }
    }
    return relationStatus;
}

static void stop_and_check_etcd_node(uint32 nodeid)
{
    int j = 0;

    stop_etcd_node(nodeid);
    while (j < ETCD_STOP_WAIT) {
        (void)sleep(1);
        write_runlog(LOG, ".");
        if (stop_check_etcd_node(nodeid) == 0) {
            write_runlog(LOG, "The ETCD instance stopped successfully in node: %u.\n", nodeid);
            break;
        }
        j++;
    }
    if (j == ETCD_STOP_WAIT) {
        write_runlog(ERROR, "failed to stop the ETCD instance in node: %u.\n", nodeid);
        exit(-1);
    }
}

static int stop_check_etcd_node(uint32 nodeid)
{
    int result;

    for (uint32 i = 0; i < g_node_num; i++) {
        if (g_node[i].node == nodeid && g_node[i].etcd) {
            char command[MAX_PATH_LEN] = {0};

            if (checkStaticConfigExist(i) != 0) {
                write_runlog(ERROR, "the cluster static config file does not exist on the node: %u.\n", g_node[i].node);
                write_runlog(FATAL, "failed to check the etcd instance stop status.\n");
                exit(-1);
            }

            result = StopExecEtcdCluser(i, command, MAX_PATH_LEN);
            if (result == PROCESS_WAIT_START) {
                write_runlog(LOG, "When check instance, process is working in WAIT_START.\n");
            }
            if (result != PROCESS_NOT_EXIST && (result != PROCESS_WAIT_START)) {
                return CHECKED_OTHER_STATUS;
            }
        }
    }

    return CHECKED_FINISH_STATUS;
}

/*
 * stop etcd of specified node
 */
void stop_etcd_node(uint32 nodeid)
{
    char command[MAXPGPATH];
    char command_opts[MAXPGPATH];
    int ret;

    ret = snprintf_s(command_opts, MAXPGPATH, MAXPGPATH - 1, "touch %s;chmod 600 %s",
        etcd_manual_start_file, etcd_manual_start_file);
    securec_check_intval(ret, (void)ret);

    ret = snprintf_s(
        command, MAXPGPATH, MAXPGPATH - 1, SYSTEMQUOTE "%s < \"%s\" 2>&1 &" SYSTEMQUOTE, command_opts, DEVNULL);
    securec_check_intval(ret, (void)ret);

    write_runlog(LOG, "stop the ETCD instance in this node, nodeid: %u.\n", nodeid);

    ret = runCmdByNodeId(command, nodeid);
    if (ret != 0) {
        write_runlog(DEBUG1,
            "Failed to stop the etcd node with executing the command: command=\"%s\","
            " nodeId=%u, systemReturn=%d, shellReturn=%d, errno=%d.\n",
            command,
            nodeid,
            ret,
            SHELL_RETURN_CODE(ret),
            errno);
    }
}

void stop_etcd_cluster(void)
{
    for (uint32 ii = 0; ii < g_node_num; ii++) {
        if (g_node[ii].etcd) {
            char command[MAXPGPATH];
            int ret;

            ret = snprintf_s(command,
                MAXPGPATH,
                MAXPGPATH - 1,
                SYSTEMQUOTE "touch %s;chmod 600 %s < \"%s\" 2>&1" SYSTEMQUOTE,
                etcd_manual_start_file,
                etcd_manual_start_file,
                DEVNULL);
            securec_check_intval(ret, (void)ret);

            ret = RunEtcdCmd(command, ii);
            if (ret != 0) {
                write_runlog(DEBUG1,
                    "Failed to stop the etcd node with executing the command: command=\"%s\","
                    " nodeId=%u, systemReturn=%d, shellReturn=%d, errno=%d.\n",
                    command,
                    g_node[ii].node,
                    ret,
                    SHELL_RETURN_CODE(ret),
                    errno);
            }
        }
    }
}

/* a simple func to calculate int digit, for node num can not be unlimited */
static int calDigitNum(uint32 num)
{
    if (num < 10) {
        return 1;
    } else if (num < 100) {
        return 2;
    } else if (num < 1000) {
        return 3;
    } else if (num < 10000) {
        return 4;
    } else {
        // a cluster can not have so many nodes;
        return 0;
    }
}

static int stop_cm_server_arbitration()
{
    ctl_to_cm_stop_arbitration ctl_to_cm_stop_arbitration_content;
    int ret;

    /* Get the connection to CM_Server */
    do_conn_cmserver(false, 0);
    if (CmServer_conn == NULL) {
        write_runlog(DEBUG1,
            "Halt arbitration to cm_server sent, yet connect failed. "
            "Stopping without notifying cm_server.\n");
        /* We will need to allow cluster stopping without CM server alive or when CM server does not have a primary */
        return 0;
    }

    write_runlog(DEBUG1, "First sending msg to cm_server to stop the arbitration process.\n");

    ctl_to_cm_stop_arbitration_content.msg_type = (int)MSG_CTL_CM_STOP_ARBITRATION;
    ret = cm_client_send_msg(
        CmServer_conn, 'C', (char*)&ctl_to_cm_stop_arbitration_content, sizeof(ctl_to_cm_stop_arbitration_content));
    if (ret != 0) {
        FINISH_CONNECTION((CmServer_conn), -1);
        write_runlog(DEBUG1,
            "Halt arbitration to cm_server sent, msg delivery failed. "
            "Stopping without notifying cm_server.\n");
        /*
         * Same here. We will need to allow cluster stopping
         * without CM server alive or when CM server does not have a primary
         */
        return 0;
    }

    write_runlog(DEBUG1, "Successfully halted the arbitration process.\n");
    return 0;
}

static int StopExecGsCtlInstance(uint32 nodeId, char *command, uint32 cmdLen, const char *dataPath)
{
    int ret;
    int result = -1;

    if (nodeId == g_nodeId && strstr(g_appPath, "/var/chroot") == NULL) {
        ret = snprintf_s(command, cmdLen, cmdLen - 1, "cm_ctl check -B gs_ctl -T %s  \n echo  -e  $? > %s",
            dataPath, result_path);
        securec_check_intval(ret, (void)ret);
        exec_system(command, &result, result_path);
    } else {
        ret = snprintf_s(command, cmdLen, cmdLen - 1,
            "cm_ctl check -B gs_ctl -T %s\" > /dev/null 2>&1; echo  -e $? > %s",
            dataPath, result_path);
        securec_check_intval(ret, (void)ret);
        exec_system_ssh(nodeId, command, &result, result_path, mpp_env_separate_file);
    }

    return result;
}


static int stop_check_instance(uint32 node_id_check, const char* datapath)
{
    int result = -1;

    if (checkStaticConfigExist(node_id_check) != 0) {
        write_runlog(
            ERROR, "the cluster static config file does not exist on the node: %u.\n", g_node[node_id_check].node);
        write_runlog(FATAL, "failed to check the instance stop status: %s.\n", datapath);
        exit(-1);
    }

    /* coordinator */
    if (g_node[node_id_check].coordinate == 1 && strncmp(datapath, g_node[node_id_check].DataPath, MAX_PATH_LEN) == 0) {
        CheckCnNodeStatusById(node_id_check, &result);
        if (result == PROCESS_WAIT_START) {
            write_runlog(LOG, "When check instance, process is working in WAIT_START.\n");
        }
        return (result == PROCESS_NOT_EXIST || result == PROCESS_WAIT_START) ?
            CHECKED_FINISH_STATUS : CHECKED_OTHER_STATUS;
    }

    /* datanode */
    for (uint32 ii = 0; ii < g_node[node_id_check].datanodeCount; ii++) {
        char* local_data_path = g_node[node_id_check].datanode[ii].datanodeLocalDataPath;

        if (strncmp(datapath, local_data_path, MAX_PATH_LEN) == 0) {
            CheckDnNodeStatusById(node_id_check, &result, ii);
            if (result == PROCESS_NOT_EXIST && (shutdown_mode_num == IMMEDIATE_MODE || 
                (shutdown_mode_num == FAST_MODE && is_check_building_dn))) {
                char command[MAX_PATH_LEN] = {0};
                result = StopExecGsCtlInstance(node_id_check, command, MAX_PATH_LEN, local_data_path);
            }

            if (result == PROCESS_WAIT_START) {
                write_runlog(LOG, "When check instance, process is working in WAIT_START.\n");
            }
            return (result == PROCESS_NOT_EXIST || result == PROCESS_WAIT_START) ?
                CHECKED_FINISH_STATUS : CHECKED_OTHER_STATUS;
        }
    }

    /* gtm */
    if (g_node[node_id_check].gtm == 1 &&
        strncmp(datapath, g_node[node_id_check].gtmLocalDataPath, MAX_PATH_LEN) == 0) {
        CheckGtmNodeStatusById(node_id_check, &result);
        if (result == PROCESS_WAIT_START) {
            write_runlog(LOG, "When check instance, process is working in WAIT_START.\n");
        }
        return (result == PROCESS_NOT_EXIST || result == PROCESS_WAIT_START) ?
            CHECKED_FINISH_STATUS : CHECKED_OTHER_STATUS;
    }

    return CHECKED_OTHER_STATUS;
}

#ifndef ENABLE_MULTIPLE_NODES
static int StopCheckLtran(uint32 num, char* command, uint32 cmdLen)
{
    int ret;
    int result = -1;

    if (num == g_nodeId && strstr(g_appPath, "/var/chroot") == NULL) {
        ret = snprintf_s(command, cmdLen, cmdLen - 1, "cm_ctl check -B ltran -T ltran \n echo  -e  $? > %s",
            result_path);
        securec_check_intval(ret, (void)ret);
        exec_system(command, &result, result_path);
    } else {
        ret = snprintf_s(command, cmdLen, cmdLen - 1,
            "cm_ctl check -B ltran -T ltran\" > /dev/null 2>&1; echo  -e $? > %s",
            result_path);
        securec_check_intval(ret, (void)ret);
        exec_system_ssh(num, command, &result, result_path, mpp_env_separate_file);
    }
    return result;
}
static int StopCheckLtranNode(uint32 nodeid)
{
    int result = -1;

    for (uint32 i = 0; i < g_node_num; i++) {
        if (g_node[i].node == nodeid) {
            char command[MAX_PATH_LEN] = {0};
            result = StopCheckLtran(i, command, MAX_PATH_LEN);
            if (result == PROCESS_WAIT_START) {
                write_runlog(LOG, "When check instance, process is working in WAIT_START.\n");
            }
            if (result != PROCESS_NOT_EXIST && (result != PROCESS_WAIT_START)) {
                return CHECKED_OTHER_STATUS;
            }
        }
    }

    return CHECKED_FINISH_STATUS;
}

void StopLtranProcess(uint32 nodeid)
{
    char command[MAXPGPATH];
    char command_opts[MAXPGPATH];
    int ret;
    int time = 0;
    uint32 ii = 0;

    for (ii = 0; ii < g_node_num; ii++) {
        if (g_node[ii].node == nodeid) {
            break;
        }
    }
    if (ii >= g_node_num) {
        write_runlog(FATAL, "can't find the nodeid: %u\n", nodeid);
        exit(1);
    }

    if (g_node[ii].datanodeCount > 0) {
        ret = snprintf_s(command_opts, MAXPGPATH, MAXPGPATH - 1, "touch %s;chmod 600 %s",
            g_ltranManualStartFile, g_ltranManualStartFile);
        securec_check_intval(ret, (void)ret);

        ret = snprintf_s(
            command, MAXPGPATH, MAXPGPATH - 1, SYSTEMQUOTE "%s < \"%s\" 2>&1 &" SYSTEMQUOTE, command_opts, DEVNULL);
        securec_check_intval(ret, (void)ret);

        ret = runCmdByNodeId(command, nodeid);
        if (ret != 0) {
            write_runlog(DEBUG1, "Failed to stop the ltran process with executing the command: command=\"%s\","
                " nodeId=%u, systemReturn=%d, shellReturn=%d, errno=%d.\n", command, nodeid, ret,
                SHELL_RETURN_CODE(ret), errno);
        }
        while (time < ITRAN_STOP_WAIT) {
            (void)sleep(1);
            if (StopCheckLtranNode(nodeid) == 0) {
                write_runlog(LOG, "The ltran instance stops successfully in node: %d.\n", nodeid);
                break;
            }
            time++;
        }
        if (time == ITRAN_STOP_WAIT) {
            write_runlog(ERROR, "failed to stop the ltran instance in node: %d.\n", nodeid);
            exit(-1);
        }
    }
}
#endif
