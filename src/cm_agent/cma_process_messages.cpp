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
 * cma_process_messages.cpp
 *    cma process cms messages functions
 *
 * IDENTIFICATION
 *    src/cm_agent/cma_process_messages.cpp
 *
 * -------------------------------------------------------------------------
 */
#include "securec.h"
#include "cm/cm_elog.h"
#include "cm_msg_version_convert.h"
#include "cm_ip.h"
#include "cm/cm_util.h"
#include "cma_common.h"
#include "cma_global_params.h"
#include "cma_client.h"
#include "cma_status_check.h"
#include "cma_connect.h"
#include "cma_process_messages_client.h"
#include "cma_instance_management.h"
#include "cma_instance_management_res.h"
#include "cma_instance_check.h"
#include "cma_mes.h"
#include "cma_instance_management_res.h"
#include "cma_process_messages.h"
#ifdef ENABLE_MULTIPLE_NODES
#include "cma_coordinator.h"
#include "cma_cn_process_message.h"
#include "cma_cn_gtm_instance_management.h"
#endif

#ifdef ENABLE_UT
#define static
#endif

static void InstancesStatusCheckAndReport(void)
{
    if (g_shutdownRequest) {
        return;
    }

#ifdef ENABLE_MULTIPLE_NODES
    gtm_status_check_and_report();
    coordinator_status_check_and_report();
#endif

    DatanodeStatusReport();
    fenced_UDF_status_check_and_report();
    etcd_status_check_and_report();
    kerberos_status_check_and_report();
    if (IsCusResExistLocal()) {
        SendResStatReportMsg();
        SendResIsregReportMsg();
    }
}

static void WillSetFloatIpOper(uint32 instId, NetworkOper oper, const char *str)
{
    if (!IsNeedCheckFloatIp() || (agent_backup_open != CLUSTER_PRIMARY)) {
        write_runlog(LOG, "%s agent_backup_open=%d, cannot set floatIp oper.\n", str, (int32)agent_backup_open);
        return;
    }
    uint32 dnIdx = 0;
    bool ret = FindDnIdxInCurNode(instId, &dnIdx, str);
    if (!ret) {
        write_runlog(ERROR, "%s cannot do the network oper in instId(%u), because it cannot be found in "
            "current node.\n", str, instId);
        return;
    }
    SetNicOper(instId, CM_INSTANCE_TYPE_DN, NETWORK_TYPE_FLOATIP, oper);
    SetFloatIpOper(dnIdx, oper, str);
}

static void AgentSendHeartbeat()
{
    agent_to_cm_heartbeat hbMsg = {0};
    hbMsg.msg_type = (int)MSG_AGENT_CM_HEARTBEAT;
    hbMsg.node = g_currentNode->node;
    hbMsg.instanceType = CM_AGENT;
    /*
     * After pg_pool_validate execute successfully, we will request the cluster
     * status until it is normal.
     */
    hbMsg.cluster_status_request = g_poolerPingEndRequest ? 1 : 0;

    PushMsgToCmsSendQue((char *)&hbMsg, (uint32)sizeof(agent_to_cm_heartbeat), "cma heartbeat");
}

bool FindIndexByLocalPath(const char* data_path, uint32* node_index)
{
    uint32 i = 0;
    uint32 data_node_num;
    if (data_path == NULL) {
        write_runlog(ERROR, "invalid data path.\n");
        return false;
    }
    if (g_currentNode == NULL) {
        write_runlog(ERROR, "invalid g_currentNode.\n");
        return false;
    }
    data_node_num = g_currentNode->datanodeCount;
    for (i = 0; i < data_node_num; i++) {
        if (strcmp(data_path, g_currentNode->datanode[i].datanodeLocalDataPath) == 0) {
            *node_index = i;
            return true;
        }
    }
    write_runlog(ERROR, "could not find datanode instance by path %s.\n", data_path);
    return false;
}

void ResetPhonyDeadCount(const char* data_path, InstanceTypes ins_type)
{
    uint32 node_index = 0;
    int phonyDead = PROCESS_UNKNOWN;
    switch (ins_type) {
#ifdef ENABLE_MULTIPLE_NODES
        case INSTANCE_CN:
            g_cnPhonyDeadTimes = 0;
            break;
        case INSTANCE_GTM:
            g_gtmPhonyDeadTimes = 0;
            break;
#endif
        case INSTANCE_DN:
            (void)check_one_instance_status(GetDnProcessName(), data_path, &phonyDead);
            if (phonyDead != PROCESS_PHONY_DEAD_D && FindIndexByLocalPath(data_path, &node_index)) {
                g_dnPhonyDeadTimes[node_index] = 0;
            }
            break;
        case INSTANCE_CM:
            break;
        case INSTANCE_FENCED:
            break;
        default:
            write_runlog(ERROR, "unknown instance type: %d.\n", ins_type);
            break;
    }
    return;
}

void kill_instance_force(const char* data_path, InstanceTypes ins_type)
{
    struct timeval timeOut = {0};
    char Lrealpath[PATH_MAX] = {0};
    char cmd[CM_PATH_LENGTH];
    char system_cmd[CM_PATH_LENGTH];
    int ret;
    char system_cmdexten[] = {"\" | grep -v grep | awk '{print $1}'  | xargs kill -9 "};
    char cmdexten[] = {"\")  print $(NF-2)}' | awk -F/ '{print $3 }' | xargs kill -9 "};
    errno_t rc;
    int rcs;

    rcs = snprintf_s(system_cmd, CM_PATH_LENGTH, CM_PATH_LENGTH - 1,
        "ps  -eo pid,euid,cmd | grep `id -u` | grep -i %s | grep -i -w \"", type_int_to_str_binname(ins_type));
    securec_check_intval(rcs, (void)rcs);
    rcs = snprintf_s(cmd, CM_PATH_LENGTH, CM_PATH_LENGTH - 1,
        "ps -eo pid,euid,cmd | grep -i %s | grep -v grep | awk '{if($2 == curuid && $1!=\"-n\") print "
        "\"/proc/\"$1\"/cwd\"}' curuid=`id -u`| xargs ls -l | awk '{if ($NF==\"", type_int_to_str_binname(ins_type));
    securec_check_intval(rcs, (void)rcs);
    write_runlog(LOG, "killing %s by force ...\n", type_int_to_str_name(ins_type));

    if (strcmp(data_path, "fenced") == 0) {
        rcs = strcpy_s(Lrealpath, PATH_MAX, "fenced");
        securec_check_errno(rcs, (void)rcs);
    } else if (strcmp(data_path, "krb5kdc") == 0) {
        rcs = strcpy_s(Lrealpath, PATH_MAX, "krb5kdc");
        securec_check_errno(rcs, (void)rcs);
    } else {
        (void)realpath(data_path, Lrealpath);
    }

    rc = strncat_s(cmd, CM_PATH_LENGTH, Lrealpath, strlen(Lrealpath));
    securec_check_errno(rc, (void)rc);

    if (ins_type != INSTANCE_CM) {
        rc = strncat_s(system_cmd, CM_PATH_LENGTH, Lrealpath, strlen(Lrealpath));
        securec_check_errno(rc, (void)rc);
    }

    rc = strncat_s(cmd, CM_PATH_LENGTH, cmdexten, strlen(cmdexten));
    securec_check_errno(rc, (void)rc);

    rc = strncat_s(system_cmd, CM_PATH_LENGTH, system_cmdexten, strlen(system_cmdexten));
    securec_check_errno(rc, (void)rc);

    if (access(system_call_log, W_OK) == 0) {
        /* redirect to system_call.log */
        rc = strncat_s(cmd, CM_PATH_LENGTH, ">> ", strlen(">> "));
        securec_check_errno(rc, (void)rc);
        rc = strncat_s(cmd, CM_PATH_LENGTH, system_call_log, strlen(system_call_log));
        securec_check_errno(rc, (void)rc);
        rc = strncat_s(cmd, CM_PATH_LENGTH, " 2>&1", strlen(" 2>&1"));
        securec_check_errno(rc, (void)rc);

        rc = strncat_s(system_cmd, CM_PATH_LENGTH, ">> ", strlen(">> "));
        securec_check_errno(rc, (void)rc);
        rc = strncat_s(system_cmd, CM_PATH_LENGTH, system_call_log, strlen(system_call_log));
        securec_check_errno(rc, (void)rc);
        rc = strncat_s(system_cmd, CM_PATH_LENGTH, " 2>&1", strlen(" 2>&1"));
        securec_check_errno(rc, (void)rc);
    }

    timeOut.tv_sec = 10;
    timeOut.tv_usec = 0;

    ret = system(system_cmd);
    if (ret != 0) {
        write_runlog(ERROR, "kill_instance_force: run system command failed! %s, errno=%d.\n", system_cmd, errno);

        ret = killInstanceByPid(type_int_to_str_binname(ins_type), data_path);
        if (ret != 0) {
            ret = ExecuteCmd(cmd, timeOut);
            if (ret != 0) {
                write_runlog(LOG, "kill_instance_force: execute command failed. %s, errno=%d.\n", cmd, errno);
                return;
            }
        }
    }
    /* if kill cn/dn/gtm success by syscmd, clear some obsoleted paramter. */
    ResetPhonyDeadCount(data_path, ins_type);

    if (ins_type == INSTANCE_DN) {
        ExecuteEventTrigger(EVENT_STOP);
    }

    write_runlog(LOG, "%s stopped.\n", type_int_to_str_name(ins_type));
    return;
}

void immediate_stop_one_instance(const char* instance_data_path, InstanceTypes instance_type)
{
    kill_instance_force(instance_data_path, instance_type);
    return;
}

void process_restart_command(const char *data_dir, int instance_type)
{
    write_runlog(LOG, "restart msg from cm_server, data_dir :%s  instance type is %d\n", data_dir, instance_type);

    switch (instance_type) {
#ifdef ENABLE_MULTIPLE_NODES
        case INSTANCE_TYPE_GTM:
            write_runlog(LOG, "gtm restart !\n");
            immediate_stop_one_instance(data_dir, INSTANCE_GTM);
            break;
        case INSTANCE_TYPE_COORDINATE:
            if (g_repairCn) {
                write_runlog(LOG, "cn is being repaired, do not restart!\n");
            } else if (g_restoreCn) {
                write_runlog(LOG, "cn is being restore, do not restart!\n");
            } else {
                write_runlog(LOG, "cn restart !\n");
                immediate_stop_one_instance(data_dir, INSTANCE_CN);
            }
            break;
#endif
        case INSTANCE_TYPE_DATANODE:
            write_runlog(LOG, "datanode restart !\n");
            immediate_stop_one_instance(data_dir, INSTANCE_DN);
            break;
        default:
            write_runlog(LOG, "node_type is unknown !\n");
            return;
    }
    return;
}

char* get_logicClusterName_by_dnInstanceId(uint32 dnInstanceId)
{
    uint32 ii;
    uint32 jj;

    for (ii = 0; ii < g_nodeHeader.nodeCount; ii++) {
        for (jj = 0; jj < g_node[ii].datanodeCount; jj++) {
            if (g_node[ii].datanode[jj].datanodeId == dnInstanceId) {
                return g_node[ii].datanode[jj].LogicClusterName;
            }
        }
    }
    return NULL;
}

void RunCmd(const char* command)
{
    int ret = system(command);
    if (ret != 0) {
        write_runlog(LOG, "exec command failed !  command is %s, errno=%d.\n", command, errno);
    }
}

static void ExeSwitchoverZengineCmd(const char *dataDir)
{
    int ret;
    char cmd[CM_PATH_LENGTH] = {0};
    uint32 port = 0;

    for (uint32 i = 0; i < g_currentNode->datanodeCount; ++i) {
        if (strcmp(g_currentNode->datanode[i].datanodeLocalDataPath, dataDir) == 0) {
            port = g_currentNode->datanode[i].datanodePort;
            break;
        }
    }
    if (IsBoolCmParamTrue(g_agentEnableDcf)) {
        for (uint32 i = 0; i < g_currentNode->sshCount; ++i) {
            ret = snprintf_s(cmd,
                CM_PATH_LENGTH,
                CM_PATH_LENGTH - 1,
                SYSTEMQUOTE "sh %s/cm_script/dn_zenith_zpaxos/switchoverdb.sh %s %s %u >> \"%s\" 2>&1 &" SYSTEMQUOTE,
                g_binPath,
                dataDir,
                g_currentNode->sshChannel[i],
                port,
                system_call_log);
            securec_check_intval(ret, (void)ret);
            ret = system(cmd);
            if (ret == 0) {
                write_runlog(LOG, "run success switchover cmd(%s).\n", cmd);
                break;
            }
            write_runlog(LOG, "exec command failed! command is %s, errno=%d.\n", cmd, errno);
        }
    } else {
        ret = snprintf_s(cmd,
            CM_PATH_LENGTH,
            CM_PATH_LENGTH - 1,
            SYSTEMQUOTE "sh %s/cm_script/dn_zenith_ha/switchoverdb.sh %s %u >> \"%s\" 2>&1 &" SYSTEMQUOTE,
            g_binPath,
            dataDir,
            port,
            system_call_log);
        securec_check_intval(ret, (void)ret);
        RunCmd(cmd);
    }

    return;
}

static void ProcessSwitchoverCommand(const char *dataDir, int instanceType, uint32 instanceId, uint32 term, bool doFast)
{
    char command[MAXPGPATH];
    errno_t rc;
    char instanceName[CM_NODE_NAME] = {0};
    char *lcName = NULL;
    Alarm alarm[1];
    AlarmAdditionalParam alarmParam;

    write_runlog(LOG, "switchover msg from cm_server, data_dir :%s  nodeType is %d\n", dataDir, instanceType);

    switch (instanceType) {
#ifdef ENABLE_MULTIPLE_NODES
        case INSTANCE_TYPE_GTM:
            rc = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1,
                SYSTEMQUOTE "%s switchover -D %s >> \"%s\" 2>&1 &" SYSTEMQUOTE, GTM_CTL_NAME, dataDir, system_call_log);
            securec_check_intval(rc, (void)rc);

            /* Initialize the instance name */
            rc = snprintf_s(instanceName, sizeof(instanceName), sizeof(instanceName) - 1, "%s_%u", "gtm", instanceId);
            securec_check_intval(rc, (void)rc);
            /* Initialize the alarm item structure(typedef struct Alarm) */
            AlarmItemInitialize(&(alarm[0]), ALM_AI_GTMSwitchOver, ALM_AS_Normal, NULL);
            /* fill the alarm message */
            WriteAlarmAdditionalInfo(&alarmParam, instanceName, "", "", "", alarm, ALM_AT_Event, instanceName);
            /* report the alarm */
            ReportCMAEventAlarm(alarm, &alarmParam);
            break;
#endif
        case INSTANCE_TYPE_DATANODE:
            if (g_clusterType == V3SingleInstCluster) {
                ExeSwitchoverZengineCmd(dataDir);
                return;
            }
            lcName = get_logicClusterName_by_dnInstanceId(instanceId);
            if (doFast) {
                rc = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1,
                    SYSTEMQUOTE "%s switchover -D  %s  -T %u -f>> \"%s\" 2>&1 &" SYSTEMQUOTE,
                    PG_CTL_NAME, dataDir, term, system_call_log);
            } else {
                rc = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1,
                    SYSTEMQUOTE "%s switchover -D  %s  -T %u >> \"%s\" 2>&1 &" SYSTEMQUOTE,
                    PG_CTL_NAME, dataDir, term, system_call_log);
            }
            securec_check_intval(rc, (void)rc);

            rc = snprintf_s(instanceName, sizeof(instanceName), sizeof(instanceName) - 1, "%s_%u", "dn", instanceId);
            securec_check_intval(rc, (void)rc);
            /* Initialize the alarm item structure(typedef struct Alarm) */
            AlarmItemInitialize(&(alarm[0]), ALM_AI_DatanodeSwitchOver, ALM_AS_Normal, NULL);
            /* fill the alarm message */
            WriteAlarmAdditionalInfo(&alarmParam, instanceName, "", "", lcName, alarm, ALM_AT_Event, instanceName);
            /* report the alarm */
            ReportCMAEventAlarm(alarm, &alarmParam);
            break;
        default:
            write_runlog(LOG, "node_type is unknown !\n");
            return;
    }
    RunCmd(command);

    if (instanceType == INSTANCE_TYPE_DATANODE) {
        ExecuteEventTrigger(EVENT_SWITCHOVER);
    }

    return;
}

void GetDnFailoverCommand(char *command, uint32 cmdLen, const char *dataDir, uint32 term)
{
    errno_t rc;
    if (g_clusterType == V3SingleInstCluster) {
        rc = snprintf_s(command,
            cmdLen,
            cmdLen - 1,
            SYSTEMQUOTE "sh %s/cm_script/dn_zenith_ha/failoverdb.sh %s %u >> \"%s\" 2>&1 &" SYSTEMQUOTE,
            g_binPath,
            dataDir,
            term,
            system_call_log);
    } else {
        rc = snprintf_s(command,
            cmdLen,
            cmdLen - 1,
            SYSTEMQUOTE "%s failover -D  %s -T %u >> \"%s\" 2>&1 &" SYSTEMQUOTE,
            PG_CTL_NAME,
            dataDir,
            term,
            system_call_log);
    }
    securec_check_intval(rc, (void)rc);
}

static void process_failover_command(const char* dataDir, int instanceType,
    uint32 instance_id, uint32 term, int32 staPrimId)
{
    char command[MAXPGPATH];
    errno_t rc;
    char instanceName[CM_NODE_NAME] = {0};
    char* logicClusterName = NULL;
    Alarm AlarmFailOver[1];
    AlarmAdditionalParam tempAdditionalParam;

    write_runlog(LOG, "failover msg from cm_server, data_dir :%s  nodetype is %d\n", dataDir, instanceType);

    switch (instanceType) {
#ifdef ENABLE_MULTIPLE_NODES
        case INSTANCE_TYPE_GTM:
            rc = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1,
                SYSTEMQUOTE "%s failover -D  %s >> \"%s\" 2>&1 &" SYSTEMQUOTE,
                GTM_CTL_NAME, dataDir, system_call_log);
            securec_check_intval(rc, (void)rc);

            /* Initialize the instance name */
            rc = snprintf_s(instanceName, sizeof(instanceName), sizeof(instanceName) - 1, "%s_%u", "gtm", instance_id);
            securec_check_intval(rc, (void)rc);
            /* Initialize the alarm item structure(typedef struct Alarm) */
            AlarmItemInitialize(&(AlarmFailOver[0]), ALM_AI_GTMFailOver, ALM_AS_Normal, NULL);
            /* fill the alarm message */
            WriteAlarmAdditionalInfo(
                &tempAdditionalParam, instanceName, "", "", "", AlarmFailOver, ALM_AT_Event, instanceName);
            /* report the alarm */
            ReportCMAEventAlarm(AlarmFailOver, &tempAdditionalParam);
            break;
#endif
        case INSTANCE_TYPE_DATANODE:
            GetDnFailoverCommand(command, MAXPGPATH, dataDir, term);
            logicClusterName = get_logicClusterName_by_dnInstanceId(instance_id);
            rc = snprintf_s(instanceName, sizeof(instanceName), sizeof(instanceName) - 1, "%s_%u", "dn", instance_id);
            securec_check_intval(rc, (void)rc);
            /* Initialize the alarm item structure(typedef struct Alarm) */
            AlarmItemInitialize(&(AlarmFailOver[0]), ALM_AI_DatanodeFailOver, ALM_AS_Normal, NULL);
            /* fill the alarm message */
            WriteAlarmAdditionalInfo(&tempAdditionalParam,
                instanceName,
                "",
                "",
                logicClusterName,
                AlarmFailOver,
                ALM_AT_Event,
                instanceName);
            /* report the alarm */
            ReportCMAEventAlarm(AlarmFailOver, &tempAdditionalParam);
            WillSetFloatIpOper(instance_id, NETWORK_OPER_UP, "[process_failover_command]");
            break;
        default:
            write_runlog(LOG, "node_type is unknown !\n");
            return;
    }
    RunCmd(command);

    if (instanceType == INSTANCE_TYPE_DATANODE) {
        ExecuteEventTrigger(EVENT_FAILOVER, staPrimId);
    }

    return;
}

static void process_failover_cascade_command(const char* dataDir, uint32 instance_id)
{
    char command[MAXPGPATH];
    errno_t rc;
    write_runlog(LOG, "failover cascade msg from cm_server, data_dir :%s \n", dataDir);
    rc = snprintf_s(command,
            MAXPGPATH,
            MAXPGPATH - 1,
            SYSTEMQUOTE "%s failover -D  %s -M standby >> \"%s\" 2>&1 &" SYSTEMQUOTE,
            PG_CTL_NAME,
            dataDir,
            system_call_log);
    securec_check_intval(rc, (void)rc);
    RunCmd(command);
    return;
}

static void process_finish_redo_command(const char* dataDir, uint32 instd, bool isFinishRedoCmdSent)
{
    char command[MAXPGPATH];
    errno_t rc;

    write_runlog(LOG, "Finish redo msg from cm_server, data_dir :%s\n", dataDir);

    rc = snprintf_s(command,
        MAXPGPATH,
        MAXPGPATH - 1,
        SYSTEMQUOTE "%s finishredo -D  %s >> \"%s\" 2>&1 &" SYSTEMQUOTE,
        PG_CTL_NAME,
        dataDir,
        system_call_log);
    securec_check_intval(rc, (void)rc);

    if (!isFinishRedoCmdSent) {
        char instanceName[CM_NODE_NAME] = {0};
        char* logicClusterName = get_logicClusterName_by_dnInstanceId(instd);
        Alarm AlarmFinishRedo[1];
        AlarmAdditionalParam tempAdditionalParam;

        rc = snprintf_s(instanceName, sizeof(instanceName), sizeof(instanceName) - 1, "%s_%u", "dn", instd);
        securec_check_intval(rc, (void)rc);
        /* Initialize the alarm item structure(typedef struct Alarm) */
        AlarmItemInitialize(&(AlarmFinishRedo[0]), ALM_AI_ForceFinishRedo, ALM_AS_Reported, NULL);
        /* fill the alarm message */
        WriteAlarmAdditionalInfo(&tempAdditionalParam, instanceName, "", "", logicClusterName,
            AlarmFinishRedo, ALM_AT_Event, instanceName);
        /* report the alarm */
        ReportCMAEventAlarm(AlarmFinishRedo, &tempAdditionalParam);
    }
    RunCmd(command);
    return;
}

static status_t FindDatanodeIndex(uint32 &index, const char *dataDir)
{
    for (index = 0; index < g_currentNode->datanodeCount; ++index) {
        if (strncmp(g_currentNode->datanode[index].datanodeLocalDataPath, dataDir, MAXPGPATH) == 0) {
            g_dnBuild[index] = true;
            g_isCmaBuildingDn[index] = true;
            write_runlog(LOG, "CMA is processing build command of %u, set is_cma_building_dn to true.\n",
                g_currentNode->datanode[index].datanodeId);
            return CM_SUCCESS;
        }
    }
    write_runlog(LOG, "can't find the DataNode instance id from the current node, dataDir:\"%s\"\n", dataDir);

    return CM_ERROR;
}

static status_t DeleteInstanceManualStartFile(uint32 datanodeId)
{
    int ret;
    struct stat instanceStatBuf = {0};
    char instanceManualStartFile[MAX_PATH_LEN] = {'\0'};

    ret = snprintf_s(instanceManualStartFile,
        MAX_PATH_LEN,
        MAX_PATH_LEN - 1,
        "%s_%u",
        g_cmInstanceManualStartPath,
        datanodeId);
    securec_check_intval(ret, (void)ret);

    if (stat(instanceManualStartFile, &instanceStatBuf) == 0) {
        char command[MAXPGPATH] = {0};
        ret = snprintf_s(command,
            MAXPGPATH,
            MAXPGPATH - 1,
            "rm -f %s_%u >> \"%s\" 2>&1 &",
            g_cmInstanceManualStartPath,
            datanodeId,
            system_call_log);
        securec_check_intval(ret, (void)ret);
        if (system(command) != 0) {
            write_runlog(ERROR, "failed to execute the command-line: %s, errno=%d.\n", command, errno);
            return CM_ERROR;
        }
    }

    return CM_SUCCESS;
}

static status_t ExecuteCommand(const char *cmd)
{
    int ret;

    ret = system(cmd);
    if (ret == -1) {
        write_runlog(ERROR, "Failed to call the system function: func_name=\"%s\", command=\"%s\","
                            " error=\"[%d]\".\n", "system", cmd, errno);
    } else if (WIFSIGNALED(ret)) {
        write_runlog(ERROR, "Failed to execute the shell command: the shell command was killed by"
                            " signal %d.\n", WTERMSIG(ret));
    } else if (ret != 0) {
        write_runlog(ERROR, "Failed to execute the shell command: the shell command ended abnormally:"
                            " shell_return=%d, command=\"%s\", errno=%d.\n", WEXITSTATUS(ret), cmd, errno);
    } else {
        return CM_SUCCESS;
    }

    return CM_ERROR;
}

static void ExecuteBuildDatanodeCommand(bool is_single_node, BuildMode build_mode, const char *data_dir,
    const cm_to_agent_build *buildMsg)
{
    char command[MAXPGPATH] = {0};
    char build_mode_str[MAXPGPATH];
    char termStr[MAX_TIME_LEN] = {0};
    int rc = 0;
    const char *buildOptr = "";
    if (buildMsg->role == INSTANCE_ROLE_CASCADE_STANDBY) {
        buildOptr = " -M cascade_standby ";
    }

    if (IsBoolCmParamTrue(g_agentEnableDcf)) {
        build_mode = FULL_BUILD;
    }

    if (build_mode == FULL_BUILD) {
        rc = strncpy_s(build_mode_str, MAXPGPATH, "-b full", strlen("-b full"));
    } else if (build_mode == INC_BUILD) {
        rc = strncpy_s(build_mode_str, MAXPGPATH, "-b incremental", strlen("-b incremental"));
    } else {
        rc = strncpy_s(build_mode_str, MAXPGPATH, "", strlen(""));
    }
    securec_check_errno(rc, (void)rc);

    rc = snprintf_s(termStr, MAX_TIME_LEN, MAX_TIME_LEN - 1, "-T %u", buildMsg->term);
    securec_check_intval(rc, (void)rc);

#ifdef ENABLE_MULTIPLE_NODES
    rc = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1,
        SYSTEMQUOTE "%s build -Z %s %s %s %s -D %s %s -r %d >> \"%s\" 2>&1 &" SYSTEMQUOTE,
        PG_CTL_NAME, is_single_node ? "single_node" : "datanode",
        build_mode_str, security_mode ? "-o \"--securitymode\"" : "", buildOptr, data_dir,
        termStr, buildMsg->wait_seconds, system_call_log);
#else
    rc = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1,
        SYSTEMQUOTE "%s build %s %s %s -D %s %s -r %d >> \"%s\" 2>&1 &" SYSTEMQUOTE,
        PG_CTL_NAME,
        build_mode_str, security_mode ? "-o \"--securitymode\"" : "", buildOptr, data_dir,
        termStr, buildMsg->wait_seconds, system_call_log);
#endif
    securec_check_intval(rc, (void)rc);

    write_runlog(LOG, "start build operation: command=\"%s\".\n", command);

    (void)ExecuteCommand(command);

    return;
}

static int GetPrimaryIndex(uint32 nodeId)
{
    for (uint32 i = 0; i < g_cm_server_num; ++i) {
        if (g_node[g_nodeIndexForCmServer[i]].node == nodeId) {
            return static_cast<int>(g_nodeIndexForCmServer[i]);
        }
    }

    return -1;
}

static void ExecuteZengineBuildScriptPaxos(const char *dataDir, uint32 primaryNodeId)
{
    int ret;
    char buildCmd[MAXPGPATH] = { 0 };

    int primaryIndex = GetPrimaryIndex(primaryNodeId);
    if (primaryIndex == -1) {
        write_runlog(ERROR, "cms has no primary, can't do build.\n");
        return;
    }

    for (uint32 j = 0; j < g_node[primaryIndex].sshCount; ++j) {
        ret = snprintf_s(buildCmd,
            MAXPGPATH,
            MAXPGPATH - 1,
            SYSTEMQUOTE "sh %s/cm_script/dn_zenith_zpaxos/builddb.sh %s %s %u" SYSTEMQUOTE,
            g_binPath,
            dataDir,
            g_node[primaryIndex].sshChannel[j],
            g_node[primaryIndex].port);
        securec_check_intval(ret, (void)ret);

        write_runlog(LOG, "start to execute zpaxos buildCmd(%s)\n", buildCmd);

        if (ExecuteCommand(buildCmd) == CM_SUCCESS) {
            write_runlog(LOG, "Execute build zengine cmd %s success.\n", buildCmd);
            return;
        }
    }

    return;
}

static void ExecuteZengineBuildScript(uint32 index, bool isSingle, const char *dataDir, const BuildMode &mode,
    const cm_to_agent_build *buildMsg)
{
    int ret;
    errno_t rc;
    char buildCmd[MAXPGPATH] = { 0 };
    char buildModeStr[NAMEDATALEN] = { 0 };

    int primaryIndex = GetPrimaryIndex(buildMsg->primaryNodeId);
    if (primaryIndex == -1) {
        write_runlog(ERROR, "cms has no primary, can't do build.\n");
        return;
    }

    if (mode == FULL_BUILD) {
        rc = strncpy_s(buildModeStr, NAMEDATALEN, "full", strlen("full"));
    } else {
        rc = strncpy_s(buildModeStr, NAMEDATALEN, "auto", strlen("auto"));
    }
    securec_check_errno(rc, (void)rc);

    for (uint32 j = 0; j < g_node[primaryIndex].sshCount; ++j) {
        ret = snprintf_s(buildCmd,
            MAXPGPATH,
            MAXPGPATH - 1,
            SYSTEMQUOTE "sh %s/cm_script/dn_zenith_ha/builddb.sh %s %s %u %s %s %s %s %d %s" SYSTEMQUOTE,
            g_binPath,
            dataDir,
            "standby",
            g_currentNode->datanode[index].datanodePort,
            g_node[primaryIndex].sshChannel[j],
            isSingle ? "SINGLE_NODE" : "DN_ZENITH_HA",
            "ipv4",
            "300",
            buildMsg->parallel,
            buildModeStr);
        securec_check_intval(ret, (void)ret);

        write_runlog(LOG, "start to execute buildCmd(%s)\n", buildCmd);

        if (ExecuteCommand(buildCmd) == CM_SUCCESS) {
            write_runlog(LOG, "Execute build zengine cmd %s success.\n", buildCmd);
            return;
        }
    }

    return;
}

static void BuildDatanode(const char *dataDir, const cm_to_agent_build *buildMsg)
{
    BuildMode buildMode;

    if (g_only_dn_cluster) {
        if (buildMsg->full_build == 1) {
            buildMode = FULL_BUILD;
        } else if (incremental_build) {
            buildMode = AUTO_BUILD;
        } else {
            buildMode = FULL_BUILD;
        }
        ExecuteBuildDatanodeCommand(true, buildMode, dataDir, buildMsg);
    } else if (g_multi_az_cluster) {
        if (buildMsg->full_build == 1) {
            buildMode = FULL_BUILD;
        } else if (incremental_build) {
            buildMode = AUTO_BUILD;
        } else {
            buildMode = FULL_BUILD;
        }
        ExecuteBuildDatanodeCommand(false, buildMode, dataDir, buildMsg);
    }  else {
        if (buildMsg->full_build == 1) {
            buildMode = FULL_BUILD;
        } else if (incremental_build) {
            buildMode = INC_BUILD;
        } else {
            buildMode = AUTO_BUILD;
        }
        ExecuteBuildDatanodeCommand(false, buildMode, dataDir, buildMsg);
    }

    return;
}

static void BuildZengine(uint32 dnIndex, const char *dataDir, const cm_to_agent_build *buildMsg)
{
    errno_t rc;
    BuildMode buildMode;
    GaussState state;
    int ret;
    char gaussdbStatePath[CM_PATH_LENGTH];

    if (buildMsg->full_build == 1) {
        buildMode = FULL_BUILD;
    } else {
        buildMode = AUTO_BUILD;
    }

    ret = snprintf_s(gaussdbStatePath,
        CM_PATH_LENGTH,
        CM_PATH_LENGTH - 1,
        "%s/gaussdb.state",
        dataDir);
    securec_check_intval(ret, (void)ret);
    canonicalize_path(gaussdbStatePath);

    rc = memset_s(&state, sizeof(GaussState), 0, sizeof(GaussState));
    securec_check_errno(rc, (void)rc);

    // build zengine need primary dn ip, so use conn_num replace primary index
    state.conn_num = GetPrimaryIndex(buildMsg->primaryNodeId);
    state.mode = STANDBY_MODE;
    state.state = BUILDING_STATE;
    state.sync_stat = false;
    UpdateDBStateFile(gaussdbStatePath, &state);

    if (IsBoolCmParamTrue(g_agentEnableDcf)) {
        ExecuteZengineBuildScriptPaxos(dataDir, buildMsg->primaryNodeId);
        g_isCmaBuildingDn[dnIndex] = false;
        return;
    }

    if (g_only_dn_cluster) {
        ExecuteZengineBuildScript(dnIndex, true, dataDir, buildMode, buildMsg);
    } else {
        ExecuteZengineBuildScript(dnIndex, false, dataDir, buildMode, buildMsg);
    }

    return;
}


/**
 * @brief  If cm_agent receive the build command from cm_server, the agent will perform the build operation.
 *         Currently, all shell commands in this function are executed in the background. Therefore,
 *         this function cannot obtain the actual return value of the shell command.
 *         An alarm is reported before the build operation is performed.
 * @param  dataDir          The instance data path.
 * @param  instanceType     The instance type.
 * @param  buildMsg         The build msg from cm server.
 */
static void ProcessBuildCommand(const char *dataDir, int instanceType, const cm_to_agent_build *buildMsg)
{
    int ret;
    uint32 dnIndex;

    write_runlog(LOG, "build msg from cm_server, dataDir :%s  instance type is %d waitSeconds is %d\n",
        dataDir, instanceType, buildMsg->wait_seconds);

    write_runlog(LOG, "%s\n", g_cmInstanceManualStartPath);
    if (agent_backup_open == CLUSTER_STREAMING_STANDBY) {
        ProcessStreamingStandbyClusterBuildCommand(instanceType, dataDir, buildMsg);
        return;
    }
    if (FindDatanodeIndex(dnIndex, dataDir) != CM_SUCCESS) {
        write_runlog(LOG, "find the dn(%s) instanceId filed, can't do build.\n", dataDir);
        return;
    }

    if (DeleteInstanceManualStartFile(g_currentNode->datanode[dnIndex].datanodeId) != CM_SUCCESS) {
        write_runlog(LOG, "delete dn instance manual start file failed, can't do build.\n");
        return;
    }

    char instanceName[CM_NODE_NAME] = {0};
    Alarm AlarmBuild[1];
    AlarmAdditionalParam tempAdditionalParam;

    ret = snprintf_s(instanceName, sizeof(instanceName), (sizeof(instanceName) - 1), "%s_%u",
        "dn", g_currentNode->datanode[dnIndex].datanodeId);
    securec_check_intval(ret, (void)ret);
    /* Initialize the alarm item structure(typedef struct Alarm). */
    AlarmItemInitialize(&(AlarmBuild[0]), ALM_AI_Build, ALM_AS_Normal, NULL);
    /* fill the alarm message. */
    WriteAlarmAdditionalInfo(&tempAdditionalParam, instanceName, "", "", "", AlarmBuild, ALM_AT_Event, instanceName);
    /* report the alarm. */
    ReportCMAEventAlarm(AlarmBuild, &tempAdditionalParam);

    switch (instanceType) {
        case INSTANCE_TYPE_DATANODE:
            if (g_clusterType == V3SingleInstCluster) {
                BuildZengine(dnIndex, dataDir, buildMsg);
            } else {
                BuildDatanode(dataDir, buildMsg);
            }
            break;
        case INSTANCE_TYPE_GTM:
            write_runlog(LOG, "GTM no need to handle build command.\n");
            break;
        default:
            write_runlog(LOG, "node_type is unknown !\n");
            break;
    }
    return;
}

/*
 * @Description: process notify to cmagent
 * @IN notify: cancle user session notify from cm server
 * @Return: void
 */
static void process_cancle_session_command(const cm_to_agent_cancel_session* cancel_msg)
{
    write_runlog(LOG, "process_cancle_session_command()\n");

    if (g_currentNode->coordinate == 0) {
        return;
    }

    write_runlog(LOG, "cm_agent notify cn %u to cancel session.\n", cancel_msg->instanceId);

    (void)pthread_rwlock_wrlock(&g_coordinatorsCancelLock);
    g_coordinatorsCancel = true;
    (void)pthread_rwlock_unlock(&g_coordinatorsCancelLock);

    return;
}

static void process_rep_sync_command(const char* dataDir, int instType)
{
    char command[MAXPGPATH];
    errno_t rc;

    write_runlog(LOG, "rep sync msg from cm_server, data_dir :%s  nodetype is %d\n", dataDir, instType);
    switch (instType) {
        case INSTANCE_TYPE_GTM:
            rc = snprintf_s(command,
                MAXPGPATH,
                MAXPGPATH - 1,
                SYSTEMQUOTE "%s setsyncmode -Z gtm -A %s -D %s >> \"%s\" 2>&1 &" SYSTEMQUOTE,
                GTM_CTL_NAME,
                "on",
                dataDir,
                system_call_log);
            securec_check_intval(rc, (void)rc);
            break;
        default:
            write_runlog(LOG, "node_type is unknown !\n");
            return;
    }
    RunCmd(command);

    return;
}

static void process_rep_most_available_command(const char *dataDir, int instance_type)
{
    char command[MAXPGPATH];
    errno_t rc;

    write_runlog(LOG, "rep most available msg from cm_server, data_dir :%s  nodetype is %d\n", dataDir, instance_type);
    switch (instance_type) {
        case INSTANCE_TYPE_GTM:
            rc = snprintf_s(command,
                MAXPGPATH,
                MAXPGPATH - 1,
                SYSTEMQUOTE "%s setsyncmode -Z gtm -A %s -D %s >> \"%s\" 2>&1 &" SYSTEMQUOTE,
                GTM_CTL_NAME,
                "auto",
                dataDir,
                system_call_log);
            securec_check_intval(rc, (void)rc);
            break;
        default:
            write_runlog(LOG, "node_type is unknown !\n");
            return;
    }
    RunCmd(command);

    return;
}

static void process_modify_most_available_command(const char* data_dir, int instance_type, uint32 oper)
{
    char command[MAXPGPATH] = {0};
    int ret;
    errno_t rc;

    write_runlog(LOG, "receive modify most available msg from cm_server, data_dir :%s  nodetype is %d, oper is %d.\n",
        data_dir, instance_type, oper);

    switch (instance_type) {
        case INSTANCE_TYPE_DATANODE:
            rc = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1,
            "gs_guc reload  -Z datanode -D %s  -c \"most_available_sync = '%s'\"  >> %s 2>&1 ",
            data_dir, oper ? "on" : "off",
            system_call_log);
            securec_check_intval(rc, (void)rc);
            break;
        default:
            write_runlog(LOG, "node_type is unknown !\n");
            return;
    }
    ret = system(command);
    write_runlog(LOG, "exec modify most available command:%s\n", command);
    if (ret != 0) {
        write_runlog(LOG, "exec modify most available command failed ret=%d ! command is %s, errno=%d.\n",
            ret, command, errno);
    }
    return;
}

static void process_notify_command(const char* data_dir, int instance_type, int role, uint32 term)
{
    char command[MAXPGPATH] = {0};
    int ret;
    errno_t rc;

    write_runlog(LOG, "notify msg from cm_server, data_dir :%s  nodetype is %d, role is %d.\n",
        data_dir, instance_type, role);

    switch (instance_type) {
        case INSTANCE_TYPE_DATANODE:
            if (role == INSTANCE_ROLE_PRIMARY) {
                rc = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1,
                    SYSTEMQUOTE "%s notify -M %s -D %s -T %u -w -t 1 >> \"%s\" 2>&1 &" SYSTEMQUOTE,
                    PG_CTL_NAME, "primary", data_dir, term, system_call_log);
                securec_check_intval(rc, (void)rc);
            } else if (role == INSTANCE_ROLE_STANDBY) {
                rc = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1,
                    SYSTEMQUOTE "%s notify -M %s -D %s -w -t 1 >> \"%s\" 2>&1 &" SYSTEMQUOTE,
                    PG_CTL_NAME, "standby", data_dir, system_call_log);
                securec_check_intval(rc, (void)rc);
            } else if (role == INSTANCE_ROLE_CASCADE_STANDBY) {
                rc = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1,
                    SYSTEMQUOTE "%s notify -M %s -D %s -w -t 1 >> \"%s\" 2>&1 &" SYSTEMQUOTE,
                    PG_CTL_NAME, "cascade_standby", data_dir, system_call_log);
                securec_check_intval(rc, (void)rc);
            } else {
                write_runlog(
                    LOG, "the instance datadir(%s) instance type(%d) role is unknown role\n", data_dir, instance_type);
                return;
            }
            break;
        case INSTANCE_TYPE_GTM:
            if (role == INSTANCE_ROLE_PRIMARY) {
                rc = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1,
                    SYSTEMQUOTE "%s notify -M %s -D %s -w -t 3 >> \"%s\" 2>&1 &" SYSTEMQUOTE,
                    GTM_CTL_NAME, "primary", data_dir, system_call_log);
                securec_check_intval(rc, (void)rc);
            } else if (role == INSTANCE_ROLE_STANDBY) {
                if (!g_single_node_cluster) {
                    rc = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1,
                        SYSTEMQUOTE "%s notify -M %s -D %s -w -t 3 >> \"%s\" 2>&1 &" SYSTEMQUOTE,
                        GTM_CTL_NAME, "standby", data_dir, system_call_log);
                    securec_check_intval(rc, (void)rc);
                }
            } else {
                write_runlog(
                    LOG, "the instance datadir(%s) instance type(%d) role is unknown role\n", data_dir, instance_type);
                return;
            }
            break;
        default:
            write_runlog(LOG, "node_type is unknown !\n");
            return;
    }
    ret = system(command);
    write_runlog(LOG, "exec notify command:%s\n", command);
    if (ret != 0) {
        write_runlog(LOG, "exec notify command failed ret=%d !  command is %s, errno=%d.\n", ret, command, errno);
    }

    return;
}

int datanode_status_check_before_restart(const char *dataDir, int *local_role)
{
    int ret = check_one_instance_status(GetDnProcessName(), dataDir, NULL);
    if (ret == PROCESS_RUNNING) {
        return CheckDatanodeStatus(dataDir, local_role);
    }

    return -1;
}


static void process_restart_by_mode_command(char* data_dir, int instance_type, int role_old, int role_new)
{
    char command[MAXPGPATH];
    int local_role = INSTANCE_ROLE_UNKNOWN;
    errno_t rc;

    int ret = datanode_status_check_before_restart(data_dir, &local_role);
    if (ret == 0 && (role_old == local_role)) {
        if (role_new == INSTANCE_ROLE_STANDBY) {
            if (g_single_node_cluster) {
                return;
            }
#ifdef ENABLE_MULTIPLE_NODES
            rc = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1,
                SYSTEMQUOTE "%s restart -M %s -D %s -Z datanode -m i -w -t 2 >> \"%s\" 2>&1 &" SYSTEMQUOTE,
                PG_CTL_NAME,
                "standby",
                data_dir,
                system_call_log);
#else
            rc = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1,
                SYSTEMQUOTE "%s restart -M %s -D %s -m i -w -t 2 >> \"%s\" 2>&1 &" SYSTEMQUOTE,
                PG_CTL_NAME,
                "standby",
                data_dir,
                system_call_log);
#endif
            securec_check_intval(rc, (void)rc);
        } else if (role_new == INSTANCE_ROLE_PRIMARY) {
            if (g_single_node_cluster) {
#ifdef ENABLE_MULTIPLE_NODES
                rc = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1,
                    SYSTEMQUOTE "%s restart  -D %s -Z datanode -m i -w -t 2 >> \"%s\" 2>&1 &" SYSTEMQUOTE,
                    PG_CTL_NAME,
                    data_dir,
                    system_call_log);
#else
                rc = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1,
                    SYSTEMQUOTE "%s restart  -D %s -m i -w -t 2 >> \"%s\" 2>&1 &" SYSTEMQUOTE,
                    PG_CTL_NAME,
                    data_dir,
                    system_call_log);
#endif
            } else {
#ifdef ENABLE_MULTIPLE_NODES
                rc = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1,
                    SYSTEMQUOTE "%s restart -M %s -D %s -Z datanode -m i -w -t 2 >> \"%s\" 2>&1 &" SYSTEMQUOTE,
                    PG_CTL_NAME,
                    "primary",
                    data_dir,
                    system_call_log);
#else
                rc = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1,
                    SYSTEMQUOTE "%s restart -M %s -D %s -m i -w -t 2 >> \"%s\" 2>&1 &" SYSTEMQUOTE,
                    PG_CTL_NAME,
                    "primary",
                    data_dir,
                    system_call_log);
#endif
            }
            securec_check_intval(rc, (void)rc);
        } else {
            write_runlog(
                LOG, "the instance datadir(%s) instance type(%d) role is unknown role\n", data_dir, instance_type);
            return;
        }

        write_runlog(LOG, "restart datanode by mode , data_dir :%s  nodetype is %d\n", data_dir, instance_type);

        write_runlog(LOG, "exec restart datanode command:%s\n", command);

        RunCmd(command);
    }
    return;
}

/* Process the heartbeat from server to agent */
static void process_heartbeat_command(int cluster_status)
{
    /*
     * After the cluster is normal, agent will not continue to request, and
     * CN STATUS thread will close the pooler ping.
     */
    if (g_poolerPingEndRequest && (cluster_status == CM_STATUS_NORMAL || cluster_status == CM_STATUS_DEGRADE)) {
        g_poolerPingEndRequest = false;
        g_poolerPingEnd = true;
    }

    /* update cm_server heartbeat */
    (void)clock_gettime(CLOCK_MONOTONIC, &g_serverHeartbeatTime);
}

#if ((defined(ENABLE_MULTIPLE_NODES)) || (defined(ENABLE_PRIVATEGAUSS)))
static void process_gs_guc_command(const cm_to_agent_gs_guc* gsGucPtr)
{
    char gsGucCommand[MAXPGPATH] = {0};
    int rc = 0;
    bool result = true;
    uint32 dnIndex;
    synchronous_standby_mode syncMode = gsGucPtr->type;
    bool azName_Valid = true;
    char* az1 = getAZNamebyPriority(g_az_master);
    char* az2 = getAZNamebyPriority(g_az_slave);

    for (dnIndex = 0; dnIndex < g_currentNode->datanodeCount; dnIndex++) {
        if (g_currentNode->datanode[dnIndex].datanodeId == gsGucPtr->instanceId) {
            break;
        }
    }

    switch (syncMode) {
        case AnyAz1:
            azName_Valid = (az1 != NULL);
            rc = snprintf_s(gsGucCommand,
                MAXPGPATH,
                MAXPGPATH - 1,
                "gs_guc reload  -Z datanode -D %s  -c \"synchronous_standby_names = 'ANY 1(%s)'\"",
                g_currentNode->datanode[dnIndex].datanodeLocalDataPath,
                az1);
            break;
        case FirstAz1:
            azName_Valid = (az1 != NULL);
            rc = snprintf_s(gsGucCommand,
                MAXPGPATH,
                MAXPGPATH - 1,
                "gs_guc reload  -Z datanode -D %s  -c \"synchronous_standby_names = 'FIRST 1(%s)'\"",
                g_currentNode->datanode[dnIndex].datanodeLocalDataPath,
                az1);
            break;
        case AnyAz2:
            azName_Valid = (az2 != NULL);
            rc = snprintf_s(gsGucCommand,
                MAXPGPATH,
                MAXPGPATH - 1,
                "gs_guc reload  -Z datanode -D %s  -c \"synchronous_standby_names = 'ANY 1(%s)'\"",
                g_currentNode->datanode[dnIndex].datanodeLocalDataPath,
                az2);
            break;
        case FirstAz2:
            azName_Valid = (az2 != NULL);
            rc = snprintf_s(gsGucCommand,
                MAXPGPATH,
                MAXPGPATH - 1,
                "gs_guc reload  -Z datanode -D %s  -c \"synchronous_standby_names = 'FIRST 1(%s)'\"",
                g_currentNode->datanode[dnIndex].datanodeLocalDataPath,
                az2);
            break;
        case Any2Az1Az2:
            azName_Valid = (az1 != NULL) && (az2 != NULL);
            rc = snprintf_s(gsGucCommand,
                MAXPGPATH,
                MAXPGPATH - 1,
                "gs_guc reload  -Z datanode -D %s -c \"synchronous_standby_names = 'ANY 2(%s,%s)'\"",
                g_currentNode->datanode[dnIndex].datanodeLocalDataPath,
                az1,
                az2);
            break;
        case First2Az1Az2:
            azName_Valid = (az1 != NULL) && (az2 != NULL);
            rc = snprintf_s(gsGucCommand,
                MAXPGPATH,
                MAXPGPATH - 1,
                "gs_guc reload  -Z datanode -D %s  -c \"synchronous_standby_names = 'FIRST 2(%s,%s)'\"",
                g_currentNode->datanode[dnIndex].datanodeLocalDataPath,
                az1,
                az2);
            break;
        case Any3Az1Az2:
            azName_Valid = (az1 != NULL) && (az2 != NULL);
            rc = snprintf_s(gsGucCommand,
                MAXPGPATH,
                MAXPGPATH - 1,
                "gs_guc reload  -Z datanode -D %s  -c \"synchronous_standby_names = 'ANY 3(%s,%s)'\"",
                g_currentNode->datanode[dnIndex].datanodeLocalDataPath,
                az1,
                az2);
            break;
        case First3Az1Az2:
            azName_Valid = (az1 != NULL) && (az2 != NULL);
            rc = snprintf_s(gsGucCommand,
                MAXPGPATH,
                MAXPGPATH - 1,
                "gs_guc reload  -Z datanode -D %s  -c \"synchronous_standby_names = 'FIRST 3(%s,%s)'\"",
                g_currentNode->datanode[dnIndex].datanodeLocalDataPath,
                az1,
                az2);
            break;
        default:
            break;
    }

    securec_check_intval(rc, (void)rc);

    if (azName_Valid) {
        rc = system(gsGucCommand);
        if (rc != 0) {
            write_runlog(ERROR, "Execute %s failed: , errno=%d.\n", gsGucCommand, errno);
            result = false;
        } else {
            write_runlog(LOG, "Execute %s success: \n", gsGucCommand);
            result = true;
        }
    } else {
        result = false;
    }

    agent_to_cm_gs_guc_feedback gsGucFeedback = {0};
    gsGucFeedback.msg_type = (int)MSG_AGENT_CM_GS_GUC_ACK;
    gsGucFeedback.node = g_currentNode->node;
    gsGucFeedback.instanceId = gsGucPtr->instanceId;
    gsGucFeedback.type = syncMode;
    gsGucFeedback.status = result;

    PushMsgToCmsSendQue((char *)&gsGucFeedback, (uint32)sizeof(agent_to_cm_gs_guc_feedback), "cma feedback");
}
#endif

static int FindInstancePathAndType(uint32 node, uint32 instanceId, char *dataPath, int *instanceType)
{
    uint32 i;
    uint32 j;
    errno_t rc;

    for (i = 0; i < g_node_num; i++) {
        if (g_node[i].gtm == 1) {
            if ((g_node[i].gtmId == instanceId) && (g_node[i].node == node)) {
                rc = memcpy_s(dataPath, MAXPGPATH, g_node[i].gtmLocalDataPath, CM_PATH_LENGTH - 1);
                securec_check_errno(rc, (void)rc);
                *instanceType = INSTANCE_TYPE_GTM;
                return 0;
            }
        }

        if (g_node[i].coordinate == 1) {
            if ((g_node[i].coordinateId == instanceId) && (g_node[i].node == node)) {
                rc = memcpy_s(dataPath, MAXPGPATH, g_node[i].DataPath, CM_PATH_LENGTH - 1);
                securec_check_errno(rc, (void)rc);
                *instanceType = INSTANCE_TYPE_COORDINATE;
                return 0;
            }
        }

        for (j = 0; j < g_node[i].datanodeCount; j++) {
            if ((g_node[i].datanode[j].datanodeId == instanceId) && (g_node[i].node == node)) {
                rc = memcpy_s(dataPath, MAXPGPATH, g_node[i].datanode[j].datanodeLocalDataPath, CM_PATH_LENGTH - 1);
                securec_check_errno(rc, (void)rc);
                *instanceType = INSTANCE_TYPE_DATANODE;
                return 0;
            }
        }
    }

    return -1;
}

static void ProcessDdbOperFromCms(const CmSendDdbOperRes *msgDdbOper)
{
    write_runlog(LOG, "receive ddbOper(%d) from cms.\n", msgDdbOper->dbOper);
    (void)pthread_rwlock_wrlock(&(g_gtmCmDdbOperRes.lock));
    if (g_gtmCmDdbOperRes.ddbOperRes == NULL) {
        (void)pthread_rwlock_unlock(&(g_gtmCmDdbOperRes.lock));
        return;
    }
    errno_t rc = memcpy_s(g_gtmCmDdbOperRes.ddbOperRes, sizeof(CmSendDdbOperRes),
        msgDdbOper, sizeof(CmSendDdbOperRes));
    securec_check_errno(rc, (void)rc);
    (void)pthread_rwlock_unlock(&(g_gtmCmDdbOperRes.lock));
}

static void ProcessSharedStorageModeFromCms(const CmsSharedStorageInfo *recvMsg)
{
    if (strcmp(g_doradoIp, recvMsg->doradoIp) != 0) {
        write_runlog(LOG, "cma recv g_doradoIp has change from \"%s\" to \"%s\"\n", g_doradoIp, recvMsg->doradoIp);
        errno_t rc = strcpy_s(g_doradoIp, CM_IP_LENGTH, recvMsg->doradoIp);
        securec_check_errno(rc, (void)rc);
    } else {
        write_runlog(DEBUG5, "cma recv g_doradoIp = %s\n", recvMsg->doradoIp);
    }
    return;
}

static const char *CmGetMsgBytesPtr(const AgentMsgPkg *msg, uint32 dataLen)
{
    if (dataLen > msg->msgLen) {
        write_runlog(ERROR,
            "CmGetMsgBytesPtr: insufficient data left in message, dataLen=%u, msg->msgLen=%u.\n", dataLen, msg->msgLen);
        return NULL;
    }
    return (const char*)(msg->msgPtr);
}

static void MsgCmAgentRestart(const AgentMsgPkg *msg, char *dataPath, const cm_msg_type* msgTypePtr)
{
    int instanceType;
    int ret;

    const cm_to_agent_restart *cmToAgentRestartPtr =
        (const cm_to_agent_restart *)CmGetMsgBytesPtr(msg, sizeof(cm_to_agent_restart));
    if (cmToAgentRestartPtr == NULL) {
        return;
    }
    if (cmToAgentRestartPtr->node == 0 && cmToAgentRestartPtr->instanceId == 0) {
        write_runlog(FATAL, "receive cmagent exit request.\n\n");
        exit(-1);
    }
    ret = FindInstancePathAndType(
        cmToAgentRestartPtr->node, cmToAgentRestartPtr->instanceId, dataPath, &instanceType);
    if (ret != 0) {
        write_runlog(ERROR,
            "can't find the instance  node is %u, instance is %u\n",
            cmToAgentRestartPtr->node,
            cmToAgentRestartPtr->instanceId);
        return;
    }
    process_restart_command(dataPath, instanceType);
}

static void MsgCmAgentSwitchoverOrFast(const AgentMsgPkg *msg, char *dataPath, const cm_msg_type* msgTypePtr)
{
    int instanceType;
    int ret;

    const cm_to_agent_switchover *msgTypeSwithoverPtr =
        (const cm_to_agent_switchover *)CmGetMsgBytesPtr(msg, sizeof(cm_to_agent_switchover));
    if (msgTypeSwithoverPtr == NULL) {
        return;
    }
    uint32 term = msgTypeSwithoverPtr->term;
    ret = FindInstancePathAndType(
        msgTypeSwithoverPtr->node, msgTypeSwithoverPtr->instanceId, dataPath, &instanceType);
    if (ret != 0) {
        write_runlog(ERROR,
            "can't find the instance  node is %u, instance is %u\n",
            msgTypeSwithoverPtr->node,
            msgTypeSwithoverPtr->instanceId);
        return;
    }
    if (msgTypePtr->msg_type == MSG_CM_AGENT_SWITCHOVER) {
        ProcessSwitchoverCommand(dataPath, instanceType, msgTypeSwithoverPtr->instanceId, term, false);
    } else {
        ProcessSwitchoverCommand(dataPath, instanceType, msgTypeSwithoverPtr->instanceId, term, true);
    }
}

static void MsgCmAgentFailover(const AgentMsgPkg* msg, char *dataPath, const cm_msg_type* msgTypePtr)
{
    int instanceType;
    int ret;
    uint32 node, term, instanceId;
    int32 staPrimId = -1;
    bool8 isCascade = CM_FALSE;

    if (msg->msgLen == sizeof(cm_to_agent_failover_cascade)) {
        const cm_to_agent_failover_cascade *failoverMsg =
            (const cm_to_agent_failover_cascade *)(const char*)(msg->msgPtr);
        if (failoverMsg == NULL) {
            return;
        }
        node = failoverMsg->node;
        instanceId = failoverMsg->instanceId;
        isCascade = CM_TRUE;
    } else {
        if (undocumentedVersion != 0 && undocumentedVersion < FAILOVER_STAPRI_VERSION) {
            const cm_to_agent_failover *failoverMsg =
                (const cm_to_agent_failover *)CmGetMsgBytesPtr(msg, sizeof(cm_to_agent_failover));
            if (failoverMsg == NULL) {
                return;
            }
            term = failoverMsg->term;
            node = failoverMsg->node;
            instanceId = failoverMsg->instanceId;
        } else {
            const cm_to_agent_failover_sta *failoverMsg =
                (const cm_to_agent_failover_sta *)CmGetMsgBytesPtr(msg, sizeof(cm_to_agent_failover_sta));
            if (failoverMsg == NULL) {
                return;
            }
            term = failoverMsg->term;
            node = failoverMsg->node;
            instanceId = failoverMsg->instanceId;
            staPrimId = failoverMsg->staPrimId;
        }
    }

    ret = FindInstancePathAndType(
        node, instanceId, dataPath, &instanceType);
    if (ret != 0) {
        write_runlog(ERROR,
            "can't find the instance  node is %u, instance is %u\n",
            node, instanceId);
        return;
    }
    if (isCascade) {
        process_failover_cascade_command(dataPath, instanceId);
    } else {
        process_failover_command(dataPath, instanceType, instanceId, term, staPrimId);
    }
}

static void MsgCmAgentBuild(const AgentMsgPkg* msg, char *dataPath, const cm_msg_type* msgTypePtr)
{
    if (g_enableSharedStorage) {
        write_runlog(LOG, "don't need do build, in shared storage mode.\n");
        return;
    }

    const cm_to_agent_build *msgTypeBuildPtr =
        (const cm_to_agent_build *)CmGetMsgBytesPtr(msg, sizeof(cm_to_agent_build));
    if (msgTypeBuildPtr == NULL) {
        return;
    }
    int instanceType;
    int ret = FindInstancePathAndType(
        msgTypeBuildPtr->node, msgTypeBuildPtr->instanceId, dataPath, &instanceType);
    if (ret != 0) {
        write_runlog(ERROR,
            "can't find the instance  node is %u, instance is %u\n",
            msgTypeBuildPtr->node,
            msgTypeBuildPtr->instanceId);
        return;
    }
    ProcessBuildCommand(dataPath, instanceType, msgTypeBuildPtr);
}

static void MsgCmAgentCancelSession(const AgentMsgPkg* msg, char *dataPath, const cm_msg_type* msgTypePtr)
{
    int instanceType;
    int ret;

    write_runlog(LOG, "message type is MSG_CM_AGENT_CANCLE_SESSION.\n");
    const cm_to_agent_cancel_session *msgTypeCancelSeesionPtr =
        (const cm_to_agent_cancel_session *)CmGetMsgBytesPtr(msg, sizeof(cm_to_agent_cancel_session));
    if (msgTypeCancelSeesionPtr == NULL) {
        return;
    }
    ret = FindInstancePathAndType(
        msgTypeCancelSeesionPtr->node, msgTypeCancelSeesionPtr->instanceId, dataPath, &instanceType);
    if (ret != 0) {
        write_runlog(ERROR,
            "can't find the instance node is %u, instance is %u\n",
            msgTypeCancelSeesionPtr->node,
            msgTypeCancelSeesionPtr->instanceId);
        return;
    }
    Assert(instanceType == INSTANCE_TYPE_COORDINATE);

    /*
     * Send a feedback to server if we handle the notify cn msg
     * successfully, let the server clean up the notify cn msg map.
     */
    process_cancle_session_command(msgTypeCancelSeesionPtr);
}

static void MsgCmAgentSync(const AgentMsgPkg* msg, char *dataPath, const cm_msg_type* msgTypePtr)
{
    write_runlog(DEBUG1, "receive sync msg.\n");
}

static void MsgCmAgentRepSync(const AgentMsgPkg* msg, char *dataPath, const cm_msg_type* msgTypePtr)
{
    int instanceType;
    int ret;
    const cm_to_agent_rep_sync *msgTypeRepSyncPtr =
        (const cm_to_agent_rep_sync *)CmGetMsgBytesPtr(msg, sizeof(cm_to_agent_rep_sync));
    if (msgTypeRepSyncPtr == NULL) {
        return;
    }
    ret = FindInstancePathAndType(
        msgTypeRepSyncPtr->node, msgTypeRepSyncPtr->instanceId, dataPath, &instanceType);
    if (ret != 0) {
        write_runlog(ERROR,
            "can't find the instance  node is %u, instance is %u\n",
            msgTypeRepSyncPtr->node,
            msgTypeRepSyncPtr->instanceId);
        return;
    }
    process_rep_sync_command(dataPath, instanceType);
}

static void MsgCmAgentRepMostAvailable(const AgentMsgPkg* msg, char *dataPath, const cm_msg_type* msgTypePtr)
{
    int instanceType;
    int ret;

    const cm_to_agent_rep_most_available *msgTypeRepMostAvailablePtr =
        (const cm_to_agent_rep_most_available *)CmGetMsgBytesPtr(msg, sizeof(cm_to_agent_rep_most_available));
    if (msgTypeRepMostAvailablePtr == NULL) {
        return;
    }
    ret = FindInstancePathAndType(msgTypeRepMostAvailablePtr->node,
        msgTypeRepMostAvailablePtr->instanceId,
        dataPath,
        &instanceType);
    if (ret != 0) {
        write_runlog(ERROR,
            "can't find the instance  node is %u, instance is %u\n",
            msgTypeRepMostAvailablePtr->node,
            msgTypeRepMostAvailablePtr->instanceId);
        return;
    }
    process_rep_most_available_command(dataPath, instanceType);
}

static void MsgCmAgentModifyMostAvailable(const AgentMsgPkg* msg, char *dataPath, const cm_msg_type* msgTypePtr)
{
    int instanceType;
    int ret;

    const cm_to_agent_modify_most_available *modifyMsg =
        (const cm_to_agent_modify_most_available *)CmGetMsgBytesPtr(msg, sizeof(cm_to_agent_modify_most_available));
    if (modifyMsg == NULL) {
        return;
    }
    ret = FindInstancePathAndType(modifyMsg->node,
        modifyMsg->instanceId,
        dataPath,
        &instanceType);
    if (ret != 0) {
        write_runlog(ERROR,
            "can't find the instance  node is %u, instance is %u\n",
            modifyMsg->node,
            modifyMsg->instanceId);
        return;
    }
    process_modify_most_available_command(dataPath, instanceType, modifyMsg->oper);
}

static void MsgCmAgentNotify(const AgentMsgPkg* msg, char *dataPath, const cm_msg_type* msgTypePtr)
{
    int instanceType;
    int ret;
    const cm_to_agent_notify *msgTypeNotifyPtr =
        (const cm_to_agent_notify *)CmGetMsgBytesPtr(msg, sizeof(cm_to_agent_notify));
    if (msgTypeNotifyPtr == NULL || g_clusterType == V3SingleInstCluster) {
        return;
    }
    uint32 term = msgTypeNotifyPtr->term;
    ret = FindInstancePathAndType(
        msgTypeNotifyPtr->node, msgTypeNotifyPtr->instanceId, dataPath, &instanceType);
    if (ret != 0) {
        write_runlog(ERROR,
            "can't find the instance  node is %u, instance is %u\n",
            msgTypeNotifyPtr->node,
            msgTypeNotifyPtr->instanceId);
        return;
    }
    process_notify_command(dataPath, instanceType, msgTypeNotifyPtr->role, term);
}

static void MsgCmAgentRestartByMode(const AgentMsgPkg* msg, char *dataPath, const cm_msg_type* msgTypePtr)
{
    int instanceType;
    int ret;

    const cm_to_agent_restart_by_mode *msgTypeRestartByModePtr =
        (const cm_to_agent_restart_by_mode *)CmGetMsgBytesPtr(msg, sizeof(cm_to_agent_restart_by_mode));
    if (msgTypeRestartByModePtr == NULL) {
        return;
    }
    ret = FindInstancePathAndType(
        msgTypeRestartByModePtr->node, msgTypeRestartByModePtr->instanceId, dataPath, &instanceType);
    if (ret != 0) {
        write_runlog(ERROR,
            "can't find the instance  node is %u, instance is %u\n",
            msgTypeRestartByModePtr->node,
            msgTypeRestartByModePtr->instanceId);
        return;
    }
    process_restart_by_mode_command(dataPath,
        instanceType,
        msgTypeRestartByModePtr->role_old,
        msgTypeRestartByModePtr->role_new);
}

static void MsgCmAgentHeartbeat(const AgentMsgPkg* msg, char *dataPath, const cm_msg_type* msgTypePtr)
{
    const cm_to_agent_heartbeat* msgTypeHeartbeatPtr =
        (const cm_to_agent_heartbeat *)CmGetMsgBytesPtr(msg, sizeof(cm_to_agent_heartbeat));
    if (msgTypeHeartbeatPtr == NULL) {
        return;
    }
    process_heartbeat_command(msgTypeHeartbeatPtr->cluster_status);
    if (msgTypeHeartbeatPtr->healthInstanceId != 0) {
        g_healthInstance = msgTypeHeartbeatPtr->healthInstanceId;
    }
}

static void MsgCmAgentGsGuc(const AgentMsgPkg* msg, char *dataPath, const cm_msg_type* msgTypePtr)
{
#if ((defined(ENABLE_MULTIPLE_NODES)) || (defined(ENABLE_PRIVATEGAUSS)))
    const cm_to_agent_gs_guc* msgTypeGsGucPtr =
        (const cm_to_agent_gs_guc *)CmGetMsgBytesPtr(msg, sizeof(cm_to_agent_gs_guc));
    if (msgTypeGsGucPtr == NULL) {
        return;
    }
    process_gs_guc_command(msgTypeGsGucPtr);
#endif
}

static void MsgCmCtlCmserver(const AgentMsgPkg* msg, char *dataPath, const cm_msg_type* msgTypePtr)
{
    const cm_to_ctl_cmserver_status* cmToCtlCmserverStatusPtr =
        (const cm_to_ctl_cmserver_status *)CmGetMsgBytesPtr(msg, sizeof(cm_to_ctl_cmserver_status));
    if (cmToCtlCmserverStatusPtr == NULL) {
        return;
    }
    g_cmServerInstanceStatus = cmToCtlCmserverStatusPtr->local_role;
}

static void MsgCmServerRepairCnAck(const AgentMsgPkg* msg, char *dataPath, const cm_msg_type* msgTypePtr)
{
    g_cleanDropCnFlag = false;
    write_runlog(LOG, "receive repair cn ack msg.\n");
}

static void MsgCmAgentLockNoPrimary(const AgentMsgPkg *msg, char *dataPath, const cm_msg_type *msgTypePtr)
{
    int ret;
    const cm_to_agent_lock1 *msgTypeLock1Ptr =
        (const cm_to_agent_lock1 *)CmGetMsgBytesPtr(msg, sizeof(cm_to_agent_lock1));
    if (msgTypeLock1Ptr == NULL) {
        return;
    }
    ret = ProcessLockNoPrimaryCmd(msgTypeLock1Ptr->instanceId);
    if (ret != 0) {
        write_runlog(ERROR, "set lock1 to instance %u failed.\n", msgTypeLock1Ptr->instanceId);
    }
}

static void MsgCmAgentLockChosenPrimary(const AgentMsgPkg *msg, char *dataPath, const cm_msg_type *msgTypePtr)
{
    int ret;
    errno_t rc;
    cm_to_agent_lock2 msgTypeLock = {0};
    if (undocumentedVersion != 0 && undocumentedVersion < SUPPORT_IPV6_VERSION) {
        const cm_to_agent_lock2_ipv4 *msgTypeLock2PtrIpv4 =
            (const cm_to_agent_lock2_ipv4 *)CmGetMsgBytesPtr(msg, sizeof(cm_to_agent_lock2_ipv4));
        if (msgTypeLock2PtrIpv4 == NULL) {
            return;
        }
        CmToAgentLock2V1ToV2(msgTypeLock2PtrIpv4, &msgTypeLock);
    } else {
        const cm_to_agent_lock2 *msgTypeLock2Ptr =
            (const cm_to_agent_lock2 *)CmGetMsgBytesPtr(msg, sizeof(cm_to_agent_lock2));
        if (msgTypeLock2Ptr == NULL) {
            return;
        }
        rc = memcpy_s(&msgTypeLock, sizeof(cm_to_agent_lock2), msgTypeLock2Ptr, sizeof(cm_to_agent_lock2));
        securec_check_errno(rc, (void)rc);
    }
    
    ret = ProcessLockChosenPrimaryCmd(&msgTypeLock);
    if (ret != 0) {
        write_runlog(ERROR, "set lock2 to instance %u failed.\n", msgTypeLock.instanceId);
    }
}

static void MsgCmAgentUnlock(const AgentMsgPkg *msg, char *dataPath, const cm_msg_type *msgTypePtr)
{
    int ret;
    const cm_to_agent_unlock *msgTypeUnlockPtr =
        (const cm_to_agent_unlock *)CmGetMsgBytesPtr(msg, sizeof(cm_to_agent_unlock));
    if (msgTypeUnlockPtr == NULL) {
        return;
    }
    ret = ProcessUnlockCmd(msgTypeUnlockPtr);
    if (ret != 0) {
        write_runlog(ERROR, "set unlock to instance %u failed.\n", msgTypeUnlockPtr->instanceId);
    }
}

static void MsgCmAgentFinishRedo(const AgentMsgPkg* msg, char *dataPath, const cm_msg_type* msgTypePtr)
{
    int ret;
    int instanceType;
    const cm_to_agent_finish_redo* msgTypeFinishRedoPtr =
        (const cm_to_agent_finish_redo *)CmGetMsgBytesPtr(msg, sizeof(cm_to_agent_finish_redo));
    if (msgTypeFinishRedoPtr == NULL) {
        return;
    }
    ret = FindInstancePathAndType(
        msgTypeFinishRedoPtr->node, msgTypeFinishRedoPtr->instanceId, dataPath, &instanceType);
    process_finish_redo_command(
        dataPath, msgTypeFinishRedoPtr->instanceId, msgTypeFinishRedoPtr->is_finish_redo_cmd_sent);
    if (ret != 0) {
        write_runlog(ERROR, "set finish redo to instance %u failed.\n", msgTypeFinishRedoPtr->instanceId);
    }
}

static void MsgCmAgentDnSyncList(const AgentMsgPkg* msg, char *dataPath, const cm_msg_type* msgTypePtr)
{
#if ((defined(ENABLE_MULTIPLE_NODES)) || (defined(ENABLE_PRIVATEGAUSS)))
    int ret;
    const CmToAgentGsGucSyncList *msgTypeDoGsGuc =
        (const CmToAgentGsGucSyncList *)CmGetMsgBytesPtr(msg, sizeof(CmToAgentGsGucSyncList));
    if (msgTypeDoGsGuc == NULL) {
        return;
    }
    write_runlog(LOG, "receive gs guc dn msg from cm_server.\n");
    ret = ProcessGsGucDnCommand(msgTypeDoGsGuc);
    if (ret != 0) {
        write_runlog(ERROR, "instance(%u) do gs guc dn Failed\n", msgTypeDoGsGuc->instanceId);
    }
#endif
}

static void MsgCmAgentResStatusChanged(const AgentMsgPkg* msg, char *dataPath, const cm_msg_type* msgTypePtr)
{
    const CmsReportResStatList *msgResStatusList =
        (const CmsReportResStatList *)CmGetMsgBytesPtr(msg, sizeof(CmsReportResStatList));
    if (msgResStatusList == NULL) {
        return;
    }
    ProcessResStatusChanged(msgResStatusList);
}

static void MsgCmAgentResStatusList(const AgentMsgPkg* msg, char *dataPath, const cm_msg_type* msgTypePtr)
{
    const CmsReportResStatList *msgResStatusList =
        (const CmsReportResStatList *)CmGetMsgBytesPtr(msg, sizeof(CmsReportResStatList));
    if (msgResStatusList == NULL) {
        return;
    }
    ProcessResStatusList(msgResStatusList);
}

static void MsgCmAgentClientDdbOperAck(const AgentMsgPkg* msg, char *dataPath, const cm_msg_type* msgTypePtr)
{
    const CmSendDdbOperRes *msgDdbOper =
        (const CmSendDdbOperRes *)CmGetMsgBytesPtr(msg, sizeof(CmSendDdbOperRes));
    if (msgDdbOper == NULL) {
        return;
    }
    ProcessDdbOperFromCms(msgDdbOper);
}

static void MsgCmAgentDnInstanceBarrier(const AgentMsgPkg* msg, char *dataPath, const cm_msg_type* msgTypePtr)
{
    int ret;
    if (agent_backup_open == CLUSTER_STREAMING_STANDBY) {
        const cm_to_agent_barrier_info *barrierRespMsg =
            (const cm_to_agent_barrier_info *)CmGetMsgBytesPtr(msg, sizeof(cm_to_agent_barrier_info));
        if (barrierRespMsg == NULL) {
            return;
        }
        ret = ProcessDnBarrierInfoResp(barrierRespMsg);
        if (ret != 0) {
            write_runlog(ERROR, "cn instance(%u) barrier info failed to refresh.\n", barrierRespMsg->instanceId);
        }
    } else {
        write_runlog(ERROR, "MSG_CM_AGENT_COORDINATE_INSTANCE_BARRIER do not support in this backup mode, "
            "agent_backup_open: %d.\n", agent_backup_open);
    }
}

static void MsgCmAgentGetSharedStorageModeAck(const AgentMsgPkg *msg, char *dataPath, const cm_msg_type *msgTypePtr)
{
    const CmsSharedStorageInfo *recvMsg =
        (const CmsSharedStorageInfo*)CmGetMsgBytesPtr(msg, sizeof(CmsSharedStorageInfo));
    if (recvMsg == NULL) {
        return;
    }
    ProcessSharedStorageModeFromCms(recvMsg);
}

static void MsgCmAgentResLockAck(const AgentMsgPkg *msg, char *dataPath, const cm_msg_type *msgTypePtr)
{
    CmsReportLockResult *recvMsg = (CmsReportLockResult*)CmGetMsgBytesPtr(msg, sizeof(CmsReportLockResult));
    if (recvMsg == NULL) {
        return;
    }
    ProcessResLockAckFromCms(recvMsg);
}

static void MsgCmAgentResArbitrate(const AgentMsgPkg *msg, char *dataPath, const cm_msg_type *msgTypePtr)
{
    const CmsNotifyAgentRegMsg *recvMsg =
        (const CmsNotifyAgentRegMsg *)CmGetMsgBytesPtr(msg, sizeof(CmsNotifyAgentRegMsg));
    if (recvMsg == NULL) {
        return;
    }

    static uint64 processTime = 0;
    static const uint64 processInterval = 1000;
    uint64 curTime = GetMonotonicTimeMs();
    if ((curTime - processTime) > processInterval) {
        ProcessResRegFromCms(recvMsg);
        processTime = curTime;
    }
}

static void ProcessFloatIpFromCms(const CmsDnFloatIpAck *recvMsg)
{
    NetworkOper oper = ChangeInt2NetworkOper(recvMsg->oper);
    if (oper == NETWORK_OPER_UNKNOWN) {
        return;
    }
    write_runlog(LOG, "receive floatIp oper msg(%d=%s) from cms.\n", (int32)oper, GetOperMapString(oper));
    WillSetFloatIpOper(recvMsg->baseInfo.instId, oper, "[ProcessFloatIpFromCms]");
}

static void MsgCmAgentFloatIpAck(const AgentMsgPkg *msg, char *dataPath, const cm_msg_type *msgTypePtr)
{
    const CmsDnFloatIpAck *recvMsg = (const CmsDnFloatIpAck *)CmGetMsgBytesPtr(msg, sizeof(CmsDnFloatIpAck));
    if (recvMsg == NULL) {
        return;
    }
    if (!IsNeedCheckFloatIp() || (agent_backup_open != CLUSTER_PRIMARY)) {
        write_runlog(DEBUG1, "[MsgCmAgentFloatIpAck] agent_backup_open=%d, cannot set floatIp oper.\n",
            (int32)agent_backup_open);
        return;
    }
    ProcessFloatIpFromCms(recvMsg);
}

static void MsgCmAgentIsregCheckListChanged(const AgentMsgPkg *msg, char *dataPath, const cm_msg_type *msgTypePtr)
{
    const CmsFlushIsregCheckList *recvMsg =
        (const CmsFlushIsregCheckList*)CmGetMsgBytesPtr(msg, sizeof(CmsFlushIsregCheckList));
    CM_RETURN_IF_NULL(recvMsg);
    ProcessIsregCheckListChanged(recvMsg);
}

void ProcessResetFloatIpFromCms(const CmSendPingDnFloatIpFail *recvMsg)
{
    write_runlog(LOG,
        "[%s] nodeId(%u) instId(%u) receive floatIp from cms, count %u.\n",
        __FUNCTION__,
        recvMsg->baseInfo.node,
        recvMsg->baseInfo.instId,
        recvMsg->failedCount);
    
    uint32 dnIdx = 0;
    bool ret = FindDnIdxInCurNode(recvMsg->baseInfo.instId, &dnIdx, "[ProcessResetFloatIpFromCms]");
    if (!ret) {
        write_runlog(ERROR,
            "[%s] cannot do the network oper in instId(%u), because it cannot be found in current node.\n",
            __FUNCTION__,
            recvMsg->baseInfo.instId);
        return;
    }
    SetNeedResetFloatIp(recvMsg, dnIdx);
}

void MsgCmAgentResetFloatIpAck(const AgentMsgPkg *msg, char *dataPath, const cm_msg_type *msgTypePtr)
{
    const CmSendPingDnFloatIpFail *recvMsg =
        (const CmSendPingDnFloatIpFail *)CmGetMsgBytesPtr(msg, sizeof(CmSendPingDnFloatIpFail));
    if (recvMsg == NULL) {
        return;
    }
    if (!IsNeedCheckFloatIp() || (agent_backup_open != CLUSTER_PRIMARY)) {
        write_runlog(DEBUG1,
            "[%s] agent_backup_open=%d, cannot reset floatIp oper.\n",
            __FUNCTION__,
            (int32)agent_backup_open);
        return;
    }
    ProcessResetFloatIpFromCms(recvMsg);
}

#ifdef ENABLE_MULTIPLE_NODES
static void MsgCmAgentNotifyCn(const AgentMsgPkg* msg, char *dataPath, const cm_msg_type* msgTypePtr)
{
    int instanceType;
    int ret;
    bool status = false;
    const cm_to_agent_notify_cn *msgTypeNotifyCnPtr =
        (const cm_to_agent_notify_cn *)CmGetMsgBytesPtr(msg, sizeof(cm_to_agent_notify_cn));
    if (msgTypeNotifyCnPtr == NULL) {
        return;
    }
    ret = FindInstancePathAndType(
        msgTypeNotifyCnPtr->node, msgTypeNotifyCnPtr->instanceId, dataPath, &instanceType);
    if (ret != 0) {
        write_runlog(ERROR,
            "can't find the instance node is %u, instance is %u\n",
            msgTypeNotifyCnPtr->node,
            msgTypeNotifyCnPtr->instanceId);
        return;
    }
    Assert(instanceType == INSTANCE_TYPE_COORDINATE);

    if (agent_backup_open == CLUSTER_PRIMARY) {
        /*
         * Send a feedback to server if we handle the notify cn msg
         * successfully, let the server clean up the notify cn msg map.
         */
        if (!g_pgxcNodeConsist) {
            write_runlog(ERROR, "notify cn find error, pgxc_node is not match.\n");
            return;
        }
        status = process_notify_cn_command(msgTypeNotifyCnPtr, (int)msg->msgLen);
    } else {
        write_runlog(LOG,
            "agent_backup_open is true, we should ignore notify cn, instance is %u\n",
            msgTypeNotifyCnPtr->instanceId);
        status = true;
    }
    send_notify_cn_feedback_msg(
        msgTypeNotifyCnPtr->instanceId, msgTypeNotifyCnPtr->notifyCount, status);
}

static void MsgCmAgentNotifyCnCentralNode(const AgentMsgPkg* msg, char *dataPath, const cm_msg_type* msgTypePtr)
{
    if (agent_backup_open == CLUSTER_PRIMARY) {
        const cm_to_agent_notify_cn_central_node *msgTypeNotifyCnCentralPtr =
            (const cm_to_agent_notify_cn_central_node *)CmGetMsgBytesPtr(
                msg, sizeof(cm_to_agent_notify_cn_central_node));
        if (msgTypeNotifyCnCentralPtr == NULL) {
            return;
        }
        process_notify_ccn_command(msgTypeNotifyCnCentralPtr);
    }
}

static void MsgCmAgentDropCn(const AgentMsgPkg* msg, char *dataPath, const cm_msg_type* msgTypePtr)
{
    int ret;
    int instanceType;
    const cm_to_agent_drop_cn *msgTypeDropCnPtr =
        (const cm_to_agent_drop_cn *)CmGetMsgBytesPtr(msg, sizeof(cm_to_agent_drop_cn));
    if (msgTypeDropCnPtr == NULL) {
        return;
    }
    ret = FindInstancePathAndType(
        msgTypeDropCnPtr->node, msgTypeDropCnPtr->instanceId, dataPath, &instanceType);
    if (ret != 0) {
        write_runlog(ERROR,
            "can't find the instance node is %u, instance is %u\n",
            msgTypeDropCnPtr->node,
            msgTypeDropCnPtr->instanceId);
        return;
    }
    Assert(instanceType == INSTANCE_TYPE_COORDINATE);
    /*
     * Send a feedback to server if we handle the notify cn msg
     * successfully, let the server clean up the notify cn msg map.
     */
    process_drop_cn_command(msgTypeDropCnPtr, true);
}

static void MsgCmAgentDroppedCn(const AgentMsgPkg* msg, char *dataPath, const cm_msg_type* msgTypePtr)
{
    const cm_to_agent_drop_cn *msgTypeDropCnPtr =
        (const cm_to_agent_drop_cn *)CmGetMsgBytesPtr(msg, sizeof(cm_to_agent_drop_cn));
    if (msgTypeDropCnPtr == NULL) {
        return;
    }
    if (!g_syncDroppedCoordinator) {
        write_runlog(LOG, "MSG_CM_AGENT_DROPPED_CN: sync_dropped_coordinator change to true.\n");
    }
    g_syncDroppedCoordinator = true;
    process_drop_cn_command(msgTypeDropCnPtr, false);
}

static void MsgCmAgentCnInstanceBarrier(const AgentMsgPkg* msg, char *dataPath, const cm_msg_type* msgTypePtr)
{
    int ret;
    if (agent_backup_open == CLUSTER_STREAMING_STANDBY) {
        const cm_to_agent_barrier_info *barrierRespMsg =
            (const cm_to_agent_barrier_info *)CmGetMsgBytesPtr(msg, sizeof(cm_to_agent_barrier_info));
        if (barrierRespMsg == NULL) {
            return;
        }
        ret = ProcessCnBarrierInfoResp(barrierRespMsg);
        if (ret != 0) {
            write_runlog(ERROR, "dn instance(%u) barrier info failed to refresh.\n", barrierRespMsg->instanceId);
        }
    } else {
        write_runlog(ERROR, "MSG_CM_AGENT_DATANODE_INSTANCE_BARRIER do not support in this backup mode, "
            "agent_backup_open: %d.\n", agent_backup_open);
    }
}
#endif

typedef void (*cms_cmd_proc_t)(const AgentMsgPkg *msg, char *dataPath, const cm_msg_type *msgTypePtr);

static cms_cmd_proc_t g_cmsCmdProcessor[MSG_CM_TYPE_CEIL] = {0};

void CmServerCmdProcessorInit(void)
{
    g_cmsCmdProcessor[MSG_CM_AGENT_RESTART]                     = MsgCmAgentRestart;
    g_cmsCmdProcessor[MSG_CM_AGENT_SWITCHOVER]                  = MsgCmAgentSwitchoverOrFast;
    g_cmsCmdProcessor[MSG_CM_AGENT_SWITCHOVER_FAST]             = MsgCmAgentSwitchoverOrFast;
    g_cmsCmdProcessor[MSG_CM_AGENT_FAILOVER]                    = MsgCmAgentFailover;
    g_cmsCmdProcessor[MSG_CM_AGENT_BUILD]                       = MsgCmAgentBuild;
    g_cmsCmdProcessor[MSG_CM_AGENT_CANCEL_SESSION]              = MsgCmAgentCancelSession;
    g_cmsCmdProcessor[MSG_CM_AGENT_SYNC]                        = MsgCmAgentSync;
    g_cmsCmdProcessor[MSG_CM_AGENT_REP_SYNC]                    = MsgCmAgentRepSync;
    g_cmsCmdProcessor[MSG_CM_AGENT_REP_MOST_AVAILABLE]          = MsgCmAgentRepMostAvailable;
    g_cmsCmdProcessor[MSG_CM_AGENT_MODIFY_MOST_AVAILABLE]       = MsgCmAgentModifyMostAvailable;
    g_cmsCmdProcessor[MSG_CM_AGENT_NOTIFY]                      = MsgCmAgentNotify;
    g_cmsCmdProcessor[MSG_CM_AGENT_RESTART_BY_MODE]             = MsgCmAgentRestartByMode;
    g_cmsCmdProcessor[MSG_CM_AGENT_HEARTBEAT]                   = MsgCmAgentHeartbeat;
    g_cmsCmdProcessor[MSG_CM_AGENT_GS_GUC]                      = MsgCmAgentGsGuc;
    g_cmsCmdProcessor[MSG_CM_CTL_CMSERVER]                      = MsgCmCtlCmserver;
    g_cmsCmdProcessor[MSG_CM_SERVER_REPAIR_CN_ACK]              = MsgCmServerRepairCnAck;
    g_cmsCmdProcessor[MSG_CM_AGENT_LOCK_NO_PRIMARY]             = MsgCmAgentLockNoPrimary;
    g_cmsCmdProcessor[MSG_CM_AGENT_LOCK_CHOSEN_PRIMARY]         = MsgCmAgentLockChosenPrimary;
    g_cmsCmdProcessor[MSG_CM_AGENT_UNLOCK]                      = MsgCmAgentUnlock;
    g_cmsCmdProcessor[MSG_CM_AGENT_FINISH_REDO]                 = MsgCmAgentFinishRedo;
    g_cmsCmdProcessor[MSG_CM_AGENT_OBS_DELETE_XLOG]             = NULL;
    g_cmsCmdProcessor[MSG_CM_AGENT_DN_SYNC_LIST]                = MsgCmAgentDnSyncList;
    g_cmsCmdProcessor[MSG_CM_AGENT_RES_STATUS_CHANGED]          = MsgCmAgentResStatusChanged;
    g_cmsCmdProcessor[MSG_CM_AGENT_RES_STATUS_LIST]             = MsgCmAgentResStatusList;
    g_cmsCmdProcessor[MSG_CM_CLIENT_DDB_OPER_ACK]               = MsgCmAgentClientDdbOperAck;
    g_cmsCmdProcessor[MSG_CM_AGENT_DATANODE_INSTANCE_BARRIER]   = MsgCmAgentDnInstanceBarrier;
    g_cmsCmdProcessor[MSG_GET_SHARED_STORAGE_INFO_ACK]          = MsgCmAgentGetSharedStorageModeAck;
    g_cmsCmdProcessor[MSG_CM_RES_LOCK_ACK]                      = MsgCmAgentResLockAck;
    g_cmsCmdProcessor[MSG_CM_RES_REG]                           = MsgCmAgentResArbitrate;
    g_cmsCmdProcessor[MSG_CM_AGENT_FLOAT_IP_ACK]                = MsgCmAgentFloatIpAck;
    g_cmsCmdProcessor[MSG_CM_AGENT_ISREG_CHECK_LIST_CHANGED]    = MsgCmAgentIsregCheckListChanged;
    g_cmsCmdProcessor[MSG_CMS_NOTIFY_PRIMARY_DN_RESET_FLOAT_IP] = MsgCmAgentResetFloatIpAck;
#ifdef ENABLE_MULTIPLE_NODES
    g_cmsCmdProcessor[MSG_CM_AGENT_NOTIFY_CN]                   = MsgCmAgentNotifyCn;
    g_cmsCmdProcessor[MSG_CM_AGENT_NOTIFY_CN_CENTRAL_NODE]      = MsgCmAgentNotifyCnCentralNode;
    g_cmsCmdProcessor[MSG_CM_AGENT_DROP_CN]                     = MsgCmAgentDropCn;
    g_cmsCmdProcessor[MSG_CM_AGENT_DROP_CN_OBS_XLOG]            = NULL;
    g_cmsCmdProcessor[MSG_CM_AGENT_DROPPED_CN]                  = MsgCmAgentDroppedCn;
    g_cmsCmdProcessor[MSG_CM_AGENT_NOTIFY_CN_RECOVER]           = NULL;
    g_cmsCmdProcessor[MSG_CM_AGENT_FULL_BACKUP_CN_OBS]          = NULL;
    g_cmsCmdProcessor[MSG_CM_AGENT_REFRESH_OBS_DEL_TEXT]        = NULL;
    g_cmsCmdProcessor[MSG_CM_AGENT_COORDINATE_INSTANCE_BARRIER] = MsgCmAgentCnInstanceBarrier;
#endif
}

static void EtcdCurrentTimeReport(void)
{
    if (agent_cm_server_connect == NULL || g_currentNode->etcd != 1) {
        return;
    }

    agent_to_cm_current_time_report reportMsg = {0};
    reportMsg.msg_type = (int)MSG_AGENT_CM_ETCD_CURRENT_TIME;
    reportMsg.nodeid = g_nodeId;
    reportMsg.etcd_time = (pg_time_t)time(NULL);

    write_runlog(DEBUG5, "current etcd time = (%ld).\n", reportMsg.etcd_time);
    PushMsgToCmsSendQue((char *)&reportMsg, (uint32)sizeof(agent_to_cm_current_time_report), "etcd time");
}

static bool IsServerHeartbeatTimeout()
{
    struct timespec now = {0};
    (void)clock_gettime(CLOCK_MONOTONIC, &now);

    return (now.tv_sec - g_serverHeartbeatTime.tv_sec) >= (time_t)agent_heartbeat_timeout;
}

static void SendCmDdbOper()
{
    if (agent_cm_server_connect == NULL) {
        return;
    }
    if (g_currentNode->coordinate == 0) {
        return;
    }
    (void)pthread_rwlock_wrlock(&(g_gtmSendDdbOper.lock));
    if (g_gtmSendDdbOper.sendOper == NULL) {
        (void)pthread_rwlock_unlock(&(g_gtmSendDdbOper.lock));
        return;
    }
    if (g_gtmSendDdbOper.sendOper->dbOper == DDB_INIT_OPER) {
        (void)pthread_rwlock_unlock(&(g_gtmSendDdbOper.lock));
        return;
    }
    CltSendDdbOper sendOper = {0};
    errno_t rc = memcpy_s(&sendOper, sizeof(CltSendDdbOper), g_gtmSendDdbOper.sendOper, sizeof(CltSendDdbOper));
    securec_check_errno(rc, (void)rc);
    (void)pthread_rwlock_unlock(&(g_gtmSendDdbOper.lock));

    write_runlog(LOG, "ddb oper(%d), msgType(%d).\n", (int)sendOper.dbOper, sendOper.msgType);
    PushMsgToCmsSendQue((char *)&sendOper, (uint32)sizeof(CltSendDdbOper), "ddb cmd");
}

static void GetDoradoIpFromCms()
{
    GetSharedStorageInfo sendMsg = {0};
    sendMsg.msg_type = (int)MSG_GET_SHARED_STORAGE_INFO;

    PushMsgToCmsSendQue((char *)&sendMsg, (uint32)sizeof(GetSharedStorageInfo), "dorado");
}

static void SendHbs()
{
    if (agent_cm_server_connect == NULL || g_currentNode->datanodeCount == 0) {
        return;
    }

    CmRhbMsg hbMsg = {0};
    GetHbs(hbMsg.hbs, &hbMsg.hwl);
    hbMsg.msg_type = (int)MSG_CM_RHB;
    hbMsg.nodeId = g_nodeHeader.node;

    PushMsgToCmsSendQue((const char *)&hbMsg, (uint32)sizeof(CmRhbMsg), "SendHbs");
    write_runlog(DEBUG5, "push cms msg to send queue, hbs msg.\n");
}

static void GetCusResStatListFromCms()
{
    RequestLatestStatList sendMsg = {0};
    sendMsg.msgType = (int)MSG_AGENT_CM_GET_LATEST_STATUS_LIST;

    for (uint32 i = 0; i < CusResCount(); ++i) {
        sendMsg.statVersion[i] = g_resStatus[i].status.version;
    }

    PushMsgToCmsSendQue((char *)&sendMsg, (uint32)sizeof(RequestLatestStatList), "get res status");
}

static void ReportInstanceStatus()
{
    InstancesStatusCheckAndReport();
    AgentSendHeartbeat();
    SendCmDdbOper();
    if (GetIsSharedStorageMode()) {
        GetDoradoIpFromCms();
    }
    SendHbs();
    if (IsCusResExist()) {
        GetCusResStatListFromCms();
    }
}

void *ProcessSendCmsMsgMain(void *arg)
{
    uint32 etcdTimeReportInterval = 0;
    struct timespec lastReportTime = {0, 0};
    struct timespec currentTime = {0, 0};
    long expiredTime = 0;
    const uint32 overLongTime = 1000;
    (void)clock_gettime(CLOCK_MONOTONIC, &lastReportTime);
    pthread_t threadId = pthread_self();
    thread_name = "SendCmsMsg";
    write_runlog(LOG, "SendCmsMsgMain will start, and threadId is %lu.\n", (unsigned long)threadId);
    for (;;) {
        set_thread_state(threadId);
        if (g_shutdownRequest) {
            cm_sleep(SHUTDOWN_SLEEP_TIME);
            continue;
        }
        (void)clock_gettime(CLOCK_MONOTONIC, &currentTime);
        expiredTime = (currentTime.tv_sec - lastReportTime.tv_sec);
        write_runlog(DEBUG5, "send cms msg expiredTime=%ld,currentTime=%ld,lastReportTime=%ld\n", expiredTime,
            currentTime.tv_sec, lastReportTime.tv_sec);
        if (expiredTime >= 1) {
            if ((agent_cm_server_connect != NULL) && IsServerHeartbeatTimeout()) {
                write_runlog(LOG, "connection to cm_server %u seconds timeout expired .\n", agent_heartbeat_timeout);
                g_cmServerNeedReconnect = true;
            }
            uint64 t1 = GetMonotonicTimeMs();

            ReportInstanceStatus();
            uint64 t2 = GetMonotonicTimeMs();

            if (etcdTimeReportInterval >= AGENT_REPORT_ETCD_CYCLE || etcdTimeReportInterval == 0) {
                EtcdCurrentTimeReport();
                etcdTimeReportInterval = 0;
            }
            etcdTimeReportInterval++;
            (void)clock_gettime(CLOCK_MONOTONIC, &lastReportTime);
            uint64 t3 = GetMonotonicTimeMs();
            if ((t3 - t1) > overLongTime) {
                write_runlog(LOG, "[%s] ReportInstanceStatus=%lu, EtcdCurrentTimeReport=%lu.\n",
                    __FUNCTION__, (t2 - t1), (t3 - t2));
            }
        }
        CmUsleep(AGENT_RECV_CYCLE);
    }
    return NULL;
}

static void ProcessCmServerCmd(const AgentMsgPkg *msg)
{
    char dataPath[MAXPGPATH] = {0};

    const cm_msg_type *msgTypePtr = (const cm_msg_type *)CmGetMsgBytesPtr(msg, sizeof(cm_msg_type));
    CM_RETURN_IF_NULL(msgTypePtr);
    if (msgTypePtr->msg_type >= MSG_CM_TYPE_CEIL || msgTypePtr->msg_type < 0) {
        write_runlog(ERROR, "recv cms msg, msg_type=%d invalid.\n", msgTypePtr->msg_type);
        return;
    }
    write_runlog(DEBUG5, "receive cms msg: %s \n", cluster_msg_int_to_string(msgTypePtr->msg_type));

    cms_cmd_proc_t procFunc = g_cmsCmdProcessor[msgTypePtr->msg_type];
    if (procFunc) {
        procFunc(msg, dataPath, msgTypePtr);
        return;
    }

    write_runlog(LOG, "received command type %d is unknown \n", msgTypePtr->msg_type);
}

void *ProcessRecvCmsMsgMain(void *arg)
{
    thread_name = "ProcessCmsMsg";
    write_runlog(LOG, "process cms msg thread begin, threadId:%lu.\n", (unsigned long)pthread_self());

    int32 msgType;
    const uint32 overLongTime = 3000;
    for (;;) {
        if (g_shutdownRequest) {
            cm_sleep(5);
            continue;
        }
        msgType = -1;
        MsgQueue &recvQueue = GetCmsRecvQueue();
        uint64 t1 = GetMonotonicTimeMs();

        (void)pthread_mutex_lock(&recvQueue.lock);
        uint64 t2 = GetMonotonicTimeMs();

        while (recvQueue.msg.empty()) {
            (void)pthread_cond_wait(&recvQueue.cond, &recvQueue.lock);
        }
        uint64 t3 = GetMonotonicTimeMs();

        AgentMsgPkg msgPkg = recvQueue.msg.front();
        recvQueue.msg.pop();
        uint64 t4 = GetMonotonicTimeMs();

        (void)pthread_mutex_unlock(&recvQueue.lock);
        uint64 t5 = GetMonotonicTimeMs();

        ProcessCmServerCmd(&msgPkg);
        if (msgPkg.msgLen >= (sizeof(int32))) {
            msgType = *(int *)(msgPkg.msgPtr);
        }
        uint64 t6 = GetMonotonicTimeMs();

        FreeBufFromMsgPool(msgPkg.msgPtr);
        uint64 t7 = GetMonotonicTimeMs();
        if ((t7 - t1) > overLongTime) {
            write_runlog(LOG, "[%s] lock=%lu, wait=%lu, pop=%lu, unlock=%lu, process=%lu, free=%lu, msgType=%d.\n",
                __FUNCTION__, (t2 - t1), (t3 - t2), (t4 - t3), (t5 - t4), (t6 - t5), (t7 - t6), msgType);
        }
    }

    return NULL;
}
