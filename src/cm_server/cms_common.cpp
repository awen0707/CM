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
 * cms_common.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_server/cms_common.cpp
 *
 * -------------------------------------------------------------------------
 */
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "cms_global_params.h"
#include "sys/epoll.h"
#include "cms_ddb_adapter.h"
#include "cm_ddb_sharedisk_disklock.h"
#include "cms_common.h"
static const int CMS_NETWORK_ISOLATION_TIMES = 20;
static const int BOOL_STR_MAX_LEN = 10;

void ExecSystemSsh(uint32 remoteNodeid, const char *cmd, int *result, const char *resultPath)
{
    int rc;
    char command[MAXPGPATH] = {0};
    const uint32 maxBufLen = 10;
    char resultStr[maxBufLen + 1] = {0};
    char mppEnvSeparateFile[MAXPGPATH] = {0};
    uint32 ii;
    rc = cmserver_getenv("MPPDB_ENV_SEPARATE_PATH", mppEnvSeparateFile, sizeof(mppEnvSeparateFile), LOG);
    if (rc == EOK) {
        check_input_for_security(mppEnvSeparateFile);
    } else {
        write_runlog(DEBUG1, "Get MPPDB_ENV_SEPARATE_PATH failed, please check if the env exists.\n");
    }

    for (ii = 0; ii < g_node[remoteNodeid].sshCount; ii++) {
        /*
         * if MPPDB_ENV_SEPARATE_PATH env not exists, env is in .bashrc file.
         * so it is no need to source the env before execute the commend.
         */
        if (mppEnvSeparateFile[0] == '\0') {
            rc = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1, "pssh %s -s -H %s \"%s", PSSH_TIMEOUT_OPTION,
                g_node[remoteNodeid].sshChannel[ii], cmd);
            securec_check_intval(rc, (void)rc);
        } else {
            rc = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1, "pssh %s -s -H %s \"source %s;%s", PSSH_TIMEOUT_OPTION,
                g_node[remoteNodeid].sshChannel[ii], mppEnvSeparateFile, cmd);
            securec_check_intval(rc, (void)rc);
        }
        write_runlog(LOG, "exec_system_ssh cmd is %s.\n", command);

        rc = system(command);
        if (rc == 0) {
            break;
        } else {
            write_runlog(ERROR,
                "failed to execute the ssh command: nodeId=%u, command=\"%s\", systemReturn=%d,"
                " commandReturn=%d, errno=%d.\n",
                g_node[remoteNodeid].node, command, rc, SHELL_RETURN_CODE(rc), errno);
            *result = -1;
            return;
        }
    }

    FILE *fd = fopen(resultPath, "r");
    if (fd == NULL) {
        write_runlog(ERROR, "failed to open the result file: errno=%d.\n", errno);
        *result = -1;
        return;
    }
    /* read result */
    uint32 bytesread = (uint32)fread(resultStr, 1, maxBufLen, fd);
    if (bytesread > maxBufLen) {
        write_runlog(ERROR, "exec_system_ssh fread failed! file=%s, bytesread=%u.\n", resultPath, bytesread);
        (void)fclose(fd);
        *result = -1;
        return;
    }
    *result = CmAtoi(resultStr, 0);
    if (*result != 0) {
        write_runlog(DEBUG1,
            "execute the ssh command: nodeId=%u, command=\"%s\", commandReturn=%d.\n",
            g_node[remoteNodeid].node, cmd, *result);
    }
    (void)fclose(fd);
}

int StopCheckNode(uint32 nodeIdCheck)
{
    int result = -1;
    int ret;

    char command[MAX_PATH_LEN] = {0};
    char cmBinPath[MAX_PATH_LEN] = {0};
    char execPath[MAX_PATH_LEN] = {0};
    char resultPath[MAX_PATH_LEN] = {0};
    if (GetHomePath(execPath, sizeof(execPath)) != 0) {
        return -1;
    }

    ret = snprintf_s(cmBinPath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/cm_agent", execPath);
    securec_check_intval(ret, (void)ret);
    ret = snprintf_s(resultPath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/cms_check_result-%u", execPath, nodeIdCheck);
    securec_check_intval(ret, (void)ret);
    check_input_for_security(resultPath);
    canonicalize_path(resultPath);
    ret = snprintf_s(command, MAX_PATH_LEN, MAX_PATH_LEN - 1,
        "cm_ctl check -B cm_agent -T %s\" > /dev/null 2>&1; echo  -e $? > %s",
        cmBinPath, resultPath);
    securec_check_intval(ret, (void)ret);
    ExecSystemSsh(nodeIdCheck, command, &result, resultPath);

    return (result == PROCESS_NOT_EXIST) ? 0 : -1;
}

NotifyCn_t setNotifyCnFlagByNodeId(uint32 nodeId)
{
    uint32 nodeIndex = 0;
    bool findTheNode = false;
    uint32 notify_index = 0;
    cm_notify_msg_status *notify_msg = NULL;

    for (uint32 i = 0; i < g_dynamic_header->relationCount; i++) {
        if (g_instance_role_group_ptr[i].instanceMember[0].instanceType == INSTANCE_TYPE_COORDINATE &&
            g_instance_role_group_ptr[i].instanceMember[0].node == nodeId) {
            findTheNode = true;
            nodeIndex = i;
            notify_msg = &g_instance_group_report_status_ptr[i].instance_status.coordinatemember.notify_msg;
            break;
        }
    }
    if (!findTheNode) {
        return NOT_NEED_TO_NOTITY_CN;
    }
    if ((notify_msg == NULL) || (notify_msg->datanode_index == NULL)) {
        return NOT_NEED_TO_NOTITY_CN;
    }
    for (uint32 i = 0; i < g_dynamic_header->relationCount; i++) {
        if (g_instance_role_group_ptr[i].instanceMember[0].instanceType != INSTANCE_TYPE_DATANODE) {
            continue;
        }
        for (uint32 j = 0; j < (uint32)g_instance_role_group_ptr[i].count; j++) {
            if (g_instance_role_group_ptr[i].instanceMember[j].role == INSTANCE_ROLE_PRIMARY) {
                (void)pthread_rwlock_wrlock(&(g_instance_group_report_status_ptr[i].lk_lock));
                cm_instance_group_report_status *dnGroup = &g_instance_group_report_status_ptr[i];
                bool res = (IsSyncDdbWithArbiMode() && dnGroup->instance_status.ddbSynced != 1);
                if (res) {
                    write_runlog(LOG, "wait for (%u) sync from ddb, and then notify cn(%u).\n",
                        GetInstanceIdInGroup(i, j), GetInstanceIdInGroup(nodeIndex, 0));
                    (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[i].lk_lock));
                    return WAIT_TO_NOTFY_CN;
                }
                (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[i].lk_lock));
                for (uint32 m = 0; m < g_datanode_instance_count; m++) {
                    if (notify_msg->datanode_index[m] == i) {
                        notify_index = m;
                        break;
                    }
                }
                (void)pthread_rwlock_wrlock(&(g_instance_group_report_status_ptr[nodeIndex].lk_lock));
                write_runlog(LOG, "pending datanode %u to coordinator %u notify map index %u\n",
                    g_instance_role_group_ptr[i].instanceMember[j].instanceId,
                    g_instance_role_group_ptr[nodeIndex].instanceMember[0].instanceId, notify_index);
                if (notify_msg->datanode_instance != NULL) {
                    notify_msg->datanode_instance[notify_index] =
                        g_instance_role_group_ptr[i].instanceMember[j].instanceId;
                }
                if (notify_msg->notify_status != NULL) {
                    notify_msg->notify_status[notify_index] = true;
                }
                g_instance_group_report_status_ptr[nodeIndex].instance_status.command_member[0].command_status =
                    (int)INSTANCE_COMMAND_WAIT_EXEC;
                g_instance_group_report_status_ptr[nodeIndex].instance_status.command_member[0].pengding_command =
                    (int)MSG_CM_AGENT_NOTIFY_CN;
                if (g_instance_group_report_status_ptr[nodeIndex].instance_status.command_member[0].notifyCnCount >=
                    0 &&
                    g_instance_group_report_status_ptr[nodeIndex].instance_status.command_member[0].notifyCnCount <
                    MAX_COUNT_OF_NOTIFY_CN) {
                    g_instance_group_report_status_ptr[nodeIndex].instance_status.command_member[0].notifyCnCount++;
                } else {
                    g_instance_group_report_status_ptr[nodeIndex].instance_status.command_member[0].notifyCnCount = 0;
                }
                (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[nodeIndex].lk_lock));
            }
        }
    }
    return NEED_TO_NOTITY_CN;
}

uint32 findMinCmServerInstanceIdIndex()
{
    uint32 i;
    uint32 minIndex = 0;
    for (i = 0; i < g_node_num; i++) {
        if (g_node[i].cmServerLevel == 1) {
            minIndex = i;
            break;
        }
    }

    i = i + 1;
    for (; i < g_node_num; i++) {
        if (g_node[i].cmServerLevel == 1) {
            if (g_node[minIndex].cmServerId > g_node[i].cmServerId) {
                minIndex = i;
            }
        }
    }
    return minIndex;
}

bool is_valid_host(const CM_Connection* con, int remote_type)
{
    uint32 i;
    uint32 j;

    if (con == NULL) {
        return false;
    }

    if (con->port == NULL) {
        return false;
    }

    struct sockaddr_storage peerAddr;
    socklen_t sockLen = sizeof(peerAddr);
    int ret = getpeername(con->port->sock, (struct sockaddr*)&peerAddr, &sockLen);
    if (ret < 0) {
        write_runlog(ERROR, "getpeername failed, sockfd=%d, remote_type=%d.\n", con->port->sock, remote_type);
        return false;
    }

    char peerIP[INET6_ADDRSTRLEN]; // INET6_ADDRSTRLEN is sufficient for both IPv4 and IPv6
    if (peerAddr.ss_family == AF_INET) {
        struct sockaddr_in *ipv4 = (struct sockaddr_in*)&peerAddr;
        inet_ntop(AF_INET, &(ipv4->sin_addr), peerIP, INET_ADDRSTRLEN);
    } else if (peerAddr.ss_family == AF_INET6) {
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6*)&peerAddr;
        inet_ntop(AF_INET6, &(ipv6->sin6_addr), peerIP, INET6_ADDRSTRLEN);
    } else {
        write_runlog(ERROR, "Unknown address family for peer, sockfd=%d, remote_type=%d.\n",
            con->port->sock, remote_type);
        return false;
    }

    switch (remote_type) {
        case CM_AGENT:
            for (i = 0; i < g_node_num; i++) {
                for (j = 0; j < g_node[i].cmAgentListenCount; j++) {
                    if (strcmp(g_node[i].cmAgentIP[j], peerIP) == 0) {
                        return true;
                    }
                }
            }
            break;

        case CM_CTL:
            for (i = 0; i < g_node_num; i++) {
                for (j = 0; j < g_node[i].cmAgentListenCount; j++) {
                    if (strcmp(g_node[i].cmAgentIP[j], peerIP) == 0) {
                        return true;
                    }
                }
            }
            break;

        case CM_SERVER:
            for (i = 0; i < g_currentNode->cmServerPeerHAListenCount; i++) {
                if (strcmp(g_currentNode->cmServerPeerHAIP[i], peerIP) == 0) {
                    return true;
                }
            }
            break;
        default:
            break;
    }

    write_runlog(ERROR, "invalid host(%s), sockfd=%d, remote_type=%d.\n", peerIP, con->port->sock, remote_type);
    return false;
}

#ifdef ENABLE_MULTIPLE_NODES
/*
 * When network is disconnected, cn status change to down after instance_heartbeat_timeout,
 * we delete cn after it's status become down. If cn auto delete is enabled(coordinator_heartbeat_timeout !=0),
 * we set coordinator_heartbeat_timeout no less than instance_heartbeat_timeout
 */
void get_paramter_coordinator_heartbeat_timeout()
{
    coordinator_heartbeat_timeout =
        (uint32)get_int_value_from_config(configDir, "coordinator_heartbeat_timeout", (int)cn_delete_default_time);
    if (coordinator_heartbeat_timeout != 0 && coordinator_heartbeat_timeout < instance_heartbeat_timeout) {
        coordinator_heartbeat_timeout = instance_heartbeat_timeout;
    }
}
#endif


void GetDdbTypeParam(void)
{
    int32 ddbType = get_int_value_from_config(configDir, "ddb_type", 0);
    const int32 dbEtcd = 0;
    const int32 dbDcc = 1;
    const int32 dbShareDisk = 2;
    switch (ddbType) {
        case dbEtcd:
            g_dbType = DB_ETCD;
            break;
        case dbDcc:
            g_dbType = DB_DCC;
            break;
        case dbShareDisk:
            g_dbType = DB_SHAREDISK;
            break;
        default:
            write_runlog(WARNING, "unkown ddbType(%d).\n", ddbType);
            break;
    }
    write_runlog(LOG, "ddbType is %d.\n", g_dbType);
}
/* Obtain arbitrate params from cm_server.conf in two nodes arch */
void GetTwoNodesArbitrateParams(void) {
    get_config_param(configDir, "third_party_gateway_ip", g_paramsOn2Nodes.thirdPartyGatewayIp,
        sizeof(g_paramsOn2Nodes.thirdPartyGatewayIp));
    
    char szEnableFailover[BOOL_STR_MAX_LEN]  = {0};
    get_config_param(configDir, "cms_enable_failover_on2nodes", szEnableFailover, sizeof(szEnableFailover));
    if (szEnableFailover[0] == '\0') {
        write_runlog(WARNING, "parameter \"cms_enable_failover_on2nodes\" not provided, will use defaule value [%d].\n",
            g_paramsOn2Nodes.cmsEnableFailoverOn2Nodes);
    } else {
        if (!CheckBoolConfigParam(szEnableFailover)) {
            write_runlog(WARNING, "invalid value for parameter \" cms_enable_failover_on2nodes \" in %s, "
                "will use default value [%d].\n", configDir, g_paramsOn2Nodes.cmsEnableFailoverOn2Nodes);
        } else {
            g_paramsOn2Nodes.cmsEnableFailoverOn2Nodes = IsBoolCmParamTrue(szEnableFailover) ? true : false;
        }
    }

    if (g_paramsOn2Nodes.cmsEnableFailoverOn2Nodes == true && !IsIPAddrValid(g_paramsOn2Nodes.thirdPartyGatewayIp)) {
        write_runlog(ERROR, "parameter \"cms_enable_failover_on2nodes\" is true, "
            "but parameter \"third_party_gateway_ip\" is invalid, please check!\n");
        exit(1);
    }

    g_paramsOn2Nodes.cmsNetworkIsolationTimeout = (uint32)get_int_value_from_config(configDir,
        "cms_network_isolation_timeout", CMS_NETWORK_ISOLATION_TIMES);
    
    char szCrashRecovery[BOOL_STR_MAX_LEN] = {0};
    get_config_param(configDir, "cms_enable_db_crash_recovery", szCrashRecovery, sizeof(szCrashRecovery));
    if (szCrashRecovery[0] == '\0') {
        write_runlog(WARNING,
            "parameter \"cms_enable_db_crash_recovery\" not provided, will use defaule value [%d].\n",
            g_paramsOn2Nodes.cmsEnableDbCrashRecovery);
    } else {
        if (!CheckBoolConfigParam(szCrashRecovery)) {
            write_runlog(FATAL, "invalid value for parameter \" cms_enable_db_crash_recovery \" in %s, "
                "will use default value [%d].\n", configDir, g_paramsOn2Nodes.cmsEnableDbCrashRecovery);
        } else {
            g_paramsOn2Nodes.cmsEnableDbCrashRecovery = IsBoolCmParamTrue(szCrashRecovery) ? true : false;
        }
    }
}

void GetCmsParaFromConfig()
{
    errno_t rcs = 0;
    /* parameter called after log initialized */
    get_config_param(configDir, "enable_transaction_read_only", g_enableSetReadOnly, sizeof(g_enableSetReadOnly));
    if (!CheckBoolConfigParam(g_enableSetReadOnly)) {
        rcs = strcpy_s(g_enableSetReadOnly, sizeof(g_enableSetReadOnly), "on");
        securec_check_errno(rcs, (void)rcs);
        write_runlog(FATAL, "invalid value for parameter \" enable_transaction_read_only \" in %s.\n", configDir);
    }

    get_config_param(configDir, "enable_dcf", g_enableDcf, sizeof(g_enableDcf));

    char szEnableSetMostAvailableSync[MAX_PATH_LEN] = {0};
    get_config_param(configDir, "enable_set_most_available_sync",
        szEnableSetMostAvailableSync, sizeof(szEnableSetMostAvailableSync));
    if (szEnableSetMostAvailableSync[0] == '\0') {
        write_runlog(WARNING,
            "parameter \"enable_set_most_available_sync\" not provided, will use defaule value [%d].\n",
                g_enableSetMostAvailableSync);
    } else {
        if (!CheckBoolConfigParam(szEnableSetMostAvailableSync)) {
            write_runlog(FATAL, "invalid value for parameter \"enable_set_most_available_sync\" in %s, "
                "will use default value [%d].\n", configDir, g_enableSetMostAvailableSync);
        } else {
            g_enableSetMostAvailableSync = IsBoolCmParamTrue(szEnableSetMostAvailableSync) ? true : false;
        }
    }
    char enableSsl[10] = {0};
    get_config_param(configDir, "enable_ssl", enableSsl, sizeof(enableSsl));
    get_config_param(configDir, "voting_disk_path", g_votingDiskPath, sizeof(g_votingDiskPath));
    canonicalize_path(g_votingDiskPath);
    if (IsBoolCmParamTrue(enableSsl)) {
        g_sslOption.enable_ssl = CM_TRUE;
    } else {
        g_sslOption.enable_ssl = CM_FALSE;
    }

    g_sslOption.verify_peer = 1;

    GetDdbTypeParam();
    GetDelayArbitTimeFromConf();
    GetDelayArbitClusterTimeFromConf();

    if (g_cm_server_num == CMS_ONE_PRIMARY_ONE_STANDBY) {
        GetTwoNodesArbitrateParams();
    }

    char cmsEnableFailoverCascade[10] = {0};
    get_config_param(configDir, "cms_enable_failover_cascade", cmsEnableFailoverCascade,
                     sizeof(cmsEnableFailoverCascade));
    if (!CheckBoolConfigParam(cmsEnableFailoverCascade)) {
        rcs = strcpy_s(cmsEnableFailoverCascade, sizeof(cmsEnableFailoverCascade), "false");
        securec_check_errno(rcs, (void)rcs);
        write_runlog(FATAL, "invalid value for parameter \" cms_enable_failover_cascade \" in %s.\n", configDir);
    } else {
        g_cms_enable_failover_cascade = IsBoolCmParamTrue(cmsEnableFailoverCascade) ? true : false;
    }
}

void GetDdbArbiCfg(int32 loadWay)
{
    (void)pthread_rwlock_wrlock(&(g_ddbArbicfg.lock));
    g_ddbArbicfg.haStatusInterval = (uint32)get_int_value_from_config(configDir, "cmserver_ha_status_interval", 1);
    g_ddbArbicfg.haHeartBeatTimeOut = (uint32)get_int_value_from_config(configDir, "cmserver_ha_heartbeat_timeout", 6);
    if (g_ddbArbicfg.haHeartBeatTimeOut == 0) {
        g_ddbArbicfg.haHeartBeatTimeOut = 6;
        write_runlog(FATAL, "invalid value for parameter \'cmserver_ha_heartbeat_timeout\' in %s.\n", configDir);
    }
    g_ddbArbicfg.arbiDelayBaseTimeOut =
        (uint32)get_int_value_from_config(configDir, "cm_server_arbitrate_delay_base_time_out", 10);
    g_ddbArbicfg.arbiDelayIncrementalTimeOut = (uint32)get_int_value_from_config(
        configDir, "cm_server_arbitrate_delay_incrememtal_time_out", CM_SERVER_ARBITRATE_DELAY_CYCLE_MAX_COUNT);
    (void)pthread_rwlock_unlock(&(g_ddbArbicfg.lock));
    if (loadWay == RELOAD_PARAMTER) {
        LoadDdbParamterFromConfig();
    }
}

void GetDelayArbitTimeFromConf()
{
    int32 delayArbiTime = get_int_value_from_config(configDir, "delay_arbitrate_timeout", 0);
    if (delayArbiTime <= 0) {
        write_runlog(WARNING, "delay_arbitrate_timeout is %d.\n", delayArbiTime);
        g_delayArbiTime = 0;
    } else {
        g_delayArbiTime = (uint32)delayArbiTime;
    }
}

void GetDelayArbitClusterTimeFromConf()
{
    int32 clusterArbiTime = get_int_value_from_config(configDir, "delay_arbitrate_max_cluster_timeout", 300);
    const int32 maxClusterArbiTime = 1000;
    const int32 initClusterArbiTime = 300;
    if (clusterArbiTime < 0 || clusterArbiTime > maxClusterArbiTime) {
        write_runlog(WARNING, "delay_arbitrate_max_cluster_timeout is %d.\n", clusterArbiTime);
        g_clusterArbiTime = initClusterArbiTime;
    } else {
        g_clusterArbiTime = clusterArbiTime;
    }
}

void GetBackupOpenConfig()
{
    errno_t rc =
        snprintf_s(configDir, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/cm_server/cm_server.conf", g_currentNode->cmDataPath);
    securec_check_intval(rc, (void)rc);
    canonicalize_path(configDir);
    /* first obtain backup_open from etcd to ensure global consistency */
    int backupOpenValue = -1;
    char valueKey[MAX_PATH_LEN] = {0};
    char getValue[MAX_PATH_LEN] = {0};
    /* update the test query value */
    rc = snprintf_s(valueKey, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/CMServer/backup_open", pw->pw_name);
    securec_check_intval(rc, (void)rc);
    DDB_RESULT dbResult = SUCCESS_GET_VALUE;
    status_t st = GetKVAndLogLevel(valueKey, getValue, MAX_PATH_LEN, &dbResult, LOG);
    if (st == CM_SUCCESS) {
        backupOpenValue = (int)strtol(getValue, NULL, 0);
        write_runlog(LOG, "get backup_open success form ddb. key=%s, value=%d.\n", valueKey, backupOpenValue);
    } else {
        backupOpenValue = get_int_value_from_config(configDir, "backup_open", 0);
        write_runlog(LOG, "get backup_open filed from ddb, use conf file. key=%s, dbResult=%d, backupOpenValue=%d\n",
            valueKey, (int)dbResult, backupOpenValue);
    }

    switch (backupOpenValue) {
        case 0:
            backup_open = CLUSTER_PRIMARY;
            break;
        case 1:
            backup_open = CLUSTER_OBS_STANDBY;
            break;
        case 2:
            backup_open = CLUSTER_STREAMING_STANDBY;
            break;
        default:
            write_runlog(ERROR, "Invalid backup_open value %d.\n", backupOpenValue);
            backup_open = CLUSTER_PRIMARY;
    }
    return;
}

void GetDnArbitrateMode()
{
    char dnArbitrateMode[MAX_PATH_LEN] = {0};
    get_config_param(configDir, "dn_arbitrate_mode", dnArbitrateMode, sizeof(dnArbitrateMode));
    if (strcmp(dnArbitrateMode, "paxos") == 0) {
        g_dnArbitrateMode = PAXOS;
        return;
    }
    if (strcmp(dnArbitrateMode, "share_disk") == 0) {
        g_dnArbitrateMode = SHARE_DISK;
        return;
    }
    g_dnArbitrateMode = QUORUM;
    return;
}

/*
 * reload cm_server parameters from cm_server.conf without kill and restart the cm_server process
 * the parameters include:
 * log_min_messages , log_file_size, log_dir,
 * alarm_component, alarm_report_interval
 * instance_heartbeat_timeout
 * coordinator_heartbeat_timeout
 * cmserver_ha_heartbeat_timeout
 * cmserver_self_vote_timeout
 * cmserver_ha_status_interval
 * cmserver_ha_connect_timeout
 * instance_failover_delay_timeout
 * datastorage_threshold_check_interval
 * max_datastorage_threshold_check
 * g_enableSetReadOnly
 * g_readOnlyThreshold
 * g_storageReadOnlyCheckCmd
 * not include: thread_count
 */
void get_parameters_from_configfile()
{
    const int min_switch_rto = 60;
    const uint32 default_value = 6;
    char alarmPath[MAX_PATH_LEN] = {0};
    int rcs;
    int rc = GetHomePath(alarmPath, sizeof(alarmPath));
    if (rc != EOK) {
        write_runlog(ERROR, "Get GAUSSHOME failed, please check.\n");
        return;
    }
    canonicalize_path(alarmPath);
    rcs =
        snprintf_s(configDir, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/cm_server/cm_server.conf", g_currentNode->cmDataPath);
    securec_check_intval(rcs, (void)rcs);
    check_input_for_security(configDir);
    canonicalize_path(configDir);
    rcs = snprintf_s(g_alarmConfigDir, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/alarmConfig.conf", alarmPath);
    securec_check_intval(rcs, (void)rcs);
    GetAlarmConfig(g_alarmConfigDir);
    get_log_paramter(configDir);
    GetStringFromConf(configDir, sys_log_path, sizeof(sys_log_path), "log_dir");
    undocumentedVersion = get_uint32_value_from_config(configDir, "upgrade_from", 0);
#ifdef ENABLE_MULTIPLE_NODES
    get_paramter_coordinator_heartbeat_timeout();
#endif
    instance_heartbeat_timeout = (uint32)get_int_value_from_config(configDir, "instance_heartbeat_timeout", 6);
    if (instance_heartbeat_timeout == 0) {
        instance_heartbeat_timeout = 6;
        write_runlog(FATAL, "invalid value for parameter \'instance_heartbeat_timeout\' in %s.\n", configDir);
    }
    instance_keep_heartbeat_timeout =
        (uint32)get_int_value_from_config(configDir, "instance_keep_heartbeat_timeout", 40);
    cmserver_self_vote_timeout = (uint32)get_int_value_from_config(configDir, "cmserver_self_vote_timeout", 8);
    cmserver_ha_connect_timeout = (uint32)get_int_value_from_config(configDir, "cmserver_ha_connect_timeout", 2);
    instance_failover_delay_timeout =
        (uint32)get_int_value_from_config(configDir, "instance_failover_delay_timeout", 0);
    datastorage_threshold_check_interval =
        get_uint32_value_from_config(configDir, "datastorage_threshold_check_interval", 10);
    max_datastorage_threshold_check = get_int_value_from_config(configDir, "max_datastorage_threshold_check", 1800);
    az_switchover_threshold = get_int_value_from_config(configDir, "az_switchover_threshold", 100);
    az_check_and_arbitrate_interval = get_int_value_from_config(configDir, "az_check_and_arbitrate_interval", 2);
    az1_and_az2_connect_check_interval = get_int_value_from_config(configDir, "az_connect_check_interval", 60);
    az1_and_az2_connect_check_delay_time = get_int_value_from_config(configDir, "az_connect_check_delay_time", 150);
    phony_dead_effective_time = get_int_value_from_config(configDir, "phony_dead_effective_time", 5);
    if (phony_dead_effective_time <= 0) {
        phony_dead_effective_time = DEFAULT_PHONY_DEAD_EFFECTIVE_TIME;
    }
    instance_phony_dead_restart_interval =
        get_int_value_from_config(configDir, "instance_phony_dead_restart_interval", 21600);
    enable_az_auto_switchover = get_int_value_from_config(configDir, "enable_az_auto_switchover", 1);

    cmserver_demote_delay_on_etcd_fault =
        get_int_value_from_config(configDir, "cmserver_demote_delay_on_etcd_fault", 8);

    cm_thread_count = get_cm_thread_count(configDir);
    cm_auth_method = get_authentication_type(configDir);
    get_krb_server_keyfile(configDir);
    switch_rto = get_int_value_from_config(configDir, "switch_rto", 600);
    if (switch_rto < min_switch_rto) {
        switch_rto = min_switch_rto;
    }

    g_clusterInstallType = (ClusterInstallType)get_int_value_from_config(configDir, "install_type",
        (int)INSTALL_TYPE_DEFAULT);
    g_clusterStartingArbitDelay = get_uint32_value_from_config(
        configDir, "cluster_starting_aribt_delay", CLUSTER_STARTING_ARBIT_DELAY);

    force_promote = get_int_value_from_config(configDir, "force_promote", 0);
    g_enableE2ERto = get_uint32_value_from_config(configDir, "enable_e2e_rto", 0);
    if (g_enableE2ERto == 1) {
        instance_heartbeat_timeout = INSTANCE_HEARTBEAT_TIMEOUT_FOR_E2E_RTO;
    }
    g_cm_agent_kill_instance_time = get_uint32_value_from_config(configDir, "agent_fault_timeout", 60);
    g_cm_agent_set_most_available_sync_delay_time =
        get_uint32_value_from_config(configDir, "cmserver_set_most_available_sync_delay_times", default_value);
    GetCmsParaFromConfig();
    get_config_param(configDir, "share_disk_path", g_shareDiskPath, sizeof(g_shareDiskPath));
    canonicalize_path(g_shareDiskPath);
    GetDdbArbiCfg(INIT_GET_PARAMTER);
    g_readOnlyThreshold = get_uint32_value_from_config(configDir, "datastorage_threshold_value_check", 85);
    g_ss_enable_check_sys_disk_usage = get_uint32_value_from_config(configDir, "ss_enable_check_sys_disk_usage", 0);
    g_sslOption.expire_time = get_uint32_value_from_config(configDir, "ssl_cert_expire_alert_threshold",
        CM_DEFAULT_SSL_EXPIRE_THRESHOLD);
    g_sslCertExpireCheckInterval = get_uint32_value_from_config(configDir, "ssl_cert_expire_check_interval",
        SECONDS_PER_DAY);
    g_diskTimeout = get_uint32_value_from_config(configDir, "disk_timeout", 200);
    g_agentNetworkTimeout = get_uint32_value_from_config(configDir, "agent_network_timeout", 6);
    g_ssDoubleClusterMode =
        (SSDoubleClusterMode)get_uint32_value_from_config(configDir, "ss_double_cluster_mode", SS_DOUBLE_NULL);
    g_shareDiskLockType =
        (SharediskLockType)get_uint32_value_from_config(configDir, "share_disk_lock_type", DISK_LOCK_MGR_NORMAL);
    GetDnArbitrateMode();
#ifndef ENABLE_PRIVATEGAUSS
    g_waitStaticPrimaryTimes = get_uint32_value_from_config(configDir, "wait_static_primary_times", 6);
    if (g_waitStaticPrimaryTimes < 5) {
        g_waitStaticPrimaryTimes = 5;
    }
#endif
}

void clean_init_cluster_state()
{
    if (g_init_cluster_mode) {
        instance_heartbeat_timeout = (uint32)get_int_value_from_config(configDir, "instance_heartbeat_timeout", 6);
        if (instance_heartbeat_timeout == 0) {
            instance_heartbeat_timeout = 6;
            write_runlog(FATAL, "invalid value for parameter \'instance_heartbeat_timeout\' in %s.\n", configDir);
        }
        if (g_enableE2ERto == 1) {
            instance_heartbeat_timeout = INSTANCE_HEARTBEAT_TIMEOUT_FOR_E2E_RTO;
        }
        write_runlog(
            LOG, "cluster is on init mode, clean instance timeout to %d.\n", INIT_CLUSTER_MODE_INSTANCE_DEAL_TIME);
    }
    g_init_cluster_mode = false;
}

void SendSignalToAgentThreads()
{
    if (pthread_kill(gIOThreads.threads[0].tid, SIGUSR1) != 0) {
        write_runlog(ERROR, "send SIGUSR1 to thread %lu failed.\n", gIOThreads.threads[0].tid);
    } else {
        write_runlog(LOG, "send SIGUSR1 to thread %lu.\n", gIOThreads.threads[0].tid);
    }
}

void FreeNotifyMsg()
{
    for (uint32 i = 0; i < g_dynamic_header->relationCount; i++) {
        if (g_instance_role_group_ptr[i].instanceMember[0].instanceType == INSTANCE_TYPE_COORDINATE) {
            (void)pthread_rwlock_wrlock(&(g_instance_group_report_status_ptr[i].lk_lock));

            FREE_AND_RESET(g_instance_group_report_status_ptr[i].instance_status
                    .coordinatemember.notify_msg.datanode_instance);
            FREE_AND_RESET(g_instance_group_report_status_ptr[i].instance_status
                    .coordinatemember.notify_msg.datanode_index);
            FREE_AND_RESET(g_instance_group_report_status_ptr[i].instance_status
                    .coordinatemember.notify_msg.notify_status);
            FREE_AND_RESET(g_instance_group_report_status_ptr[i].instance_status
                    .coordinatemember.notify_msg.have_notified);
            FREE_AND_RESET(g_instance_group_report_status_ptr[i].instance_status
                    .coordinatemember.notify_msg.have_dropped);

            (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[i].lk_lock));
        }
    }

    return;
}

int UpdateDynamicConfig()
{
    bool dynamicModified = false;
    ssize_t returnCode;
    errno_t rc;
    (void)BuildDynamicConfigFile(&dynamicModified);
    size_t headerAglinmentSize =
        (sizeof(dynamicConfigHeader) / AGLINMENT_SIZE + ((sizeof(dynamicConfigHeader) % AGLINMENT_SIZE == 0) ? 0 : 1)) *
        AGLINMENT_SIZE;
    size_t cmsStateTimelineSize = sizeof(dynamic_cms_timeline);
    int fd = open(cm_dynamic_configure_path, O_RDWR | O_CLOEXEC, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        write_runlog(ERROR, "[reload] OPEN dynamic config file error.\n");
        return -1;
    } else {
        returnCode = write(fd,
            g_dynamic_header,
            headerAglinmentSize + cmsStateTimelineSize +
                (g_dynamic_header->relationCount) * sizeof(cm_instance_role_group));
        if (returnCode != (ssize_t)(headerAglinmentSize + cmsStateTimelineSize +
            (g_dynamic_header->relationCount) * sizeof(cm_instance_role_group))) {
            write_runlog(ERROR, "[reload] write instance configure faile!\n");
            (void)close(fd);
            return -1;
        }
        rc = fsync(fd);
        if (rc != 0) {
            char errBuffer[ERROR_LIMIT_LEN];
            write_runlog(ERROR,
                "[reload] write_dynamic_config_file fsync file failed, errno=%d, errmsg=%s\n",
                errno,
                strerror_r(errno, errBuffer, ERROR_LIMIT_LEN));
            (void)close(fd);
            return -1;
        }
    }
    (void)close(fd);
    return 0;
}

void UpdateAzNodeInfo()
{
    uint32 azNodeIndex = 0;
    uint32 ii;
    uint32 jj;
    for (ii = 0; ii < g_azNum; ii++) {
        azNodeIndex = 0;
        for (jj = 0; jj < g_node_num; jj++) {
            if (strcmp(g_azArray[ii].azName, g_node[jj].azName) == 0) {
                g_azArray[ii].nodes[azNodeIndex] = g_node[jj].node;
                azNodeIndex++;
            }
        }
    }
    return;
}

status_t GetMaintainPath(char *maintainFile, uint32 fileLen)
{
    errno_t rc;
    char gausshomePath[CM_PATH_LENGTH] = {0};

    if (GetHomePath(gausshomePath, sizeof(gausshomePath)) != EOK) {
        write_runlog(ERROR, "get GAUSSHOME env fail, errno(%d).\n", errno);
        return CM_ERROR;
    }
    rc = snprintf_s(maintainFile, fileLen, fileLen - 1, "%s/bin/cms_maintain", gausshomePath);
    securec_check_intval(rc, (void)rc);

    return CM_SUCCESS;
}

status_t GetDdbKVFilePath(char *kvFile, uint32 fileLen)
{
    int ret;
    char gausshome[CM_PATH_LENGTH] = {0};

    if (GetHomePath(gausshome, sizeof(gausshome)) != 0) {
        write_runlog(ERROR, "get GAUSSHOME env fail, errno(%d).\n", errno);
        return CM_ERROR;
    }

    ret = snprintf_s(kvFile, fileLen, fileLen - 1, "%s/bin/cms_ddb_kv", gausshome);
    securec_check_intval(ret, (void)ret);

    return CM_SUCCESS;
}

bool IsUpgradeCluster()
{
    char upgradeCheck[MAX_PATH_LEN] = {0};
    char pgHostPath[MAX_PATH_LEN] = {0};
    int rcs = cmserver_getenv("PGHOST", pgHostPath, sizeof(pgHostPath), ERROR);
    if (rcs == EOK) {
        rcs = snprintf_s(upgradeCheck, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/binary_upgrade", pgHostPath);
        securec_check_intval(rcs, (void)rcs);
        if (access(upgradeCheck, F_OK) == 0) {
            write_runlog(LOG, "Line:%d Get upgrade file success.\n", __LINE__);
            return true;
        }
    } else {
        write_runlog(ERROR, "get PGHOST failed!\n");
    }
    return false;
}
bool MaintanceOrInstallCluster()
{
    char execPath[MAX_PATH_LEN] = {0};
    char installFlagPath[MAX_PATH_LEN] = {0};
    int rc = cmserver_getenv("GAUSSHOME", execPath, sizeof(execPath), ERROR);
    if (rc != EOK) {
        write_runlog(ERROR, "Line:%d Get GAUSSHOME failed, please check.\n", __LINE__);
        return false;
    }
    check_input_for_security(execPath);
    rc =
        snprintf_s(installFlagPath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/%s", execPath, "mainstance_cluster_status");
    securec_check_intval(rc, (void)rc);
    if (access(installFlagPath, F_OK) == 0) {
        write_runlog(LOG, "Line:%d Get mainstance_cluster_status success.\n", __LINE__);
        return true;
    }
    if (access(instance_maintance_path, F_OK) == 0) {
        write_runlog(LOG, "Line:%d Get mainstance_instance success.\n", __LINE__);
        return true;
    }
    return false;
}

void GetDoradoOfflineIp(char *ip, uint32 ipLen)
{
    int ret;
    char key[MAX_PATH_LEN] = {0};
    DDB_RESULT ddbResult = SUCCESS_GET_VALUE;

    ret = snprintf_s(key, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/dorado_offline_node", pw->pw_name);
    securec_check_intval(ret, (void)ret);
    if (GetKVFromDDb(key, MAX_PATH_LEN, ip, ipLen, &ddbResult) != CM_SUCCESS) {
        if (ddbResult == CAN_NOT_FIND_THE_KEY) {
            write_runlog(ERROR, "failed to get value with key(%s), error info:%d.\n", key, (int)ddbResult);
            errno_t rc = strcpy_s(ip, ipLen, "unknown");
            securec_check_errno(rc, (void)rc);
            return;
        }
        write_runlog(ERROR, "failed to get value with key(%s), error info:%d.\n", key, (int)ddbResult);
        return;
    }

    return;
}

bool SetOfflineNode()
{
    if (!GetIsSharedStorageMode()) {
        return false;
    }

    if (g_doradoIp[0] == '\0') {
        write_runlog(ERROR, "failed to get offline ip.\n");
        return false;
    }

    for (uint32 i = 0; i < g_node_num; i++) {
        if (strcmp(g_doradoIp, g_node[i].sshChannel[0]) == 0) {
            write_runlog(DEBUG5, "node(%u) is offline, ip is %s.\n", g_node[i].node, g_node[i].sshChannel[0]);
            return true;
        }
    }

    return false;
}

void CmsSyncStandbyMode()
{
    if (!g_needReloadSyncStandbyMode) {
        return;
    }
    char key[MAX_PATH_LEN] = {0};
    char value[MAX_PATH_LEN] = {0};
    errno_t rc =
        snprintf_s(key, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/CMServer/status_key/sync_standby_mode", pw->pw_name);
    securec_check_intval(rc, (void)rc);

    DDB_RESULT ddbResult = SUCCESS_GET_VALUE;
    status_t st = GetKVFromDDb(key, MAX_PATH_LEN, value, MAX_PATH_LEN, &ddbResult);
    if (st != CM_SUCCESS) {
        g_needReloadSyncStandbyMode = false;
        int logLevel = (ddbResult == CAN_NOT_FIND_THE_KEY) ? ERROR : LOG;
        write_runlog(logLevel, "failed to get value with key(%s).\n", key);
        return;
    }
    current_cluster_az_status = (synchronous_standby_mode)strtol(value, NULL, 10);
    g_needReloadSyncStandbyMode = false;
    write_runlog(LOG, "setting current cluster az status to %d.\n", (int)current_cluster_az_status);
    return;
}

bool EnableShareDisk()
{
    return (g_dnArbitrateMode == SHARE_DISK);
}
