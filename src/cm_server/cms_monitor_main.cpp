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
 * cms_monitor_main.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_server/cms_monitor_main.cpp
 *
 * -------------------------------------------------------------------------
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include "cm/cm_elog.h"
#include "cms_alarm.h"
#include "cms_ddb.h"
#include "cms_common.h"
#include "cms_common_res.h"
#include "cms_cus_res.h"
#include "cms_global_params.h"
#include "cms_process_messages.h"
#include "cms_write_dynamic_config.h"
#include "cms_arbitrate_cluster.h"
#include "cjson/cJSON.h"
#include "cms_monitor_main.h"

/* cluster unbalance check interval */
const int cluster_unbalance_check_interval = 10;
static int g_cluster_unbalance_check_interval = cluster_unbalance_check_interval;
static const uint32 CHECK_SLEEP_INTERVAL = 5;
static const uint32 MAX_VOTE_NUM = 2;
static const uint32 DDB_STATUS_CHECK_INTERVAL = 2;
static const uint32 CMS_ID_INDEX_ONE = 1;
static const uint32 CMS_ID_INDEX_TWO = 2;
static void RmAllBlackFile(const char *blackFile);

using MonitorContext = struct StMonitorContext {
    long takeTime;
};

#ifdef ENABLE_MULTIPLE_NODES
static void coordinator_status_reset(int group_index, int member_index)
{
    write_runlog(LOG,
        "coordinator_status_reset: InstanceId[%d][%d]=%u.\n",
        group_index,
        member_index,
        g_instance_role_group_ptr[group_index].instanceMember[member_index].instanceId);

    g_instance_group_report_status_ptr[group_index].instance_status.coordinatemember.status.status =
        INSTANCE_ROLE_UNKNOWN;
    g_instance_group_report_status_ptr[group_index].instance_status.coordinatemember.status.db_state =
        INSTANCE_HA_STATE_HEARTBEAT_TIMEOUT;

    /*
     * The CCN crashed, resetting the central node information
     * and reselecting the next time the agent sent the message
     */
    (void)pthread_mutex_lock(&g_centralNode.mt_lock);
    if (g_centralNode.instanceId == g_instance_role_group_ptr[group_index].instanceMember[member_index].instanceId) {
        errno_t rc =
            memset_s(g_centralNode.cnodename, sizeof(g_centralNode.cnodename), 0, sizeof(g_centralNode.cnodename));
        securec_check_errno(rc, (void)pthread_mutex_unlock(&g_centralNode.mt_lock));

        g_centralNode.instanceId = 0;
        g_centralNode.node = 0;
        g_centralNode.recover = 1;
        write_runlog(LOG,
            "clear ccn info, %u.\n",
            g_instance_role_group_ptr[group_index].instanceMember[member_index].instanceId);
    }
    (void)pthread_mutex_unlock(&g_centralNode.mt_lock);
}

static void gtm_status_reset(uint32 group_index, int member_index, bool isNodeStop)
{
    cm_gtm_replconninfo *local_status =
        &g_instance_group_report_status_ptr[group_index].instance_status.gtm_member[member_index].local_status;
    if (g_instance_role_group_ptr[group_index].instanceMember[member_index].instanceType != INSTANCE_TYPE_GTM) {
        return;
    }
    if (local_status->local_role != INSTANCE_ROLE_UNKNOWN) {
        write_runlog(LOG,
            "gtm_status_reset: InstanceId[%u][%d]=%u.\n",
            group_index, member_index,
            g_instance_role_group_ptr[group_index].instanceMember[member_index].instanceId);
        local_status->local_role = INSTANCE_ROLE_UNKNOWN;
    }

    local_status->xid = 0;
    local_status->send_msg_count = 0;
    local_status->receive_msg_count = 0;

    if (isNodeStop) {
        local_status->connect_status = CON_MANUAL_STOPPED;
    } else {
        local_status->connect_status = CON_UNKNOWN;
    }
}
#endif

static bool CheckRaiseArbitrateInterval(uint32 groupIdx)
{
    /* when dn is doing failover, or the group has primary dn, not need to raise arbitrate interval */
    cm_instance_datanode_report_status *dnReport =
        g_instance_group_report_status_ptr[groupIdx].instance_status.data_node_member;
    for (int32 i = 0; i < g_instance_role_group_ptr[groupIdx].count; ++i) {
        if (dnReport[i].arbitrateFlag) {
            write_runlog(LOG, "instId(%u) is doing failover, cannot raise arbitrate interval.\n",
                GetInstanceIdInGroup(groupIdx, i));
            return false;
        }
        if (dnReport[i].local_status.db_state == INSTANCE_HA_STATE_PROMOTING) {
            write_runlog(LOG, "instId(%u) is promoting, cannot raise arbitrate interval.\n",
                GetInstanceIdInGroup(groupIdx, i));
            return false;
        }
        if (dnReport[i].local_status.local_role == INSTANCE_ROLE_PRIMARY &&
            dnReport[i].local_status.db_state == INSTANCE_HA_STATE_NORMAL) {
            write_runlog(
                DEBUG1, "instId(%u) is primary, cannot raise arbitrate interval.\n", GetInstanceIdInGroup(groupIdx, i));
            return false;
        }
    }
    return true;
}

static void datanode_status_reset(uint32 group_index, int member_index, bool isNodeStop)
{
    if (g_instance_role_group_ptr[group_index].instanceMember[member_index].instanceType != INSTANCE_TYPE_DATANODE) {
        return;
    }
    errno_t rc;
    const uint32 max_arbitrate_interval = 100;
    cm_instance_datanode_report_status *dnReportStatus =
        g_instance_group_report_status_ptr[group_index].instance_status.data_node_member;
    dnReportStatus[member_index].local_status.local_role = INSTANCE_ROLE_UNKNOWN;
    if (!g_clusterStarting && CheckRaiseArbitrateInterval(group_index)) {
        g_instance_group_report_status_ptr[group_index].instance_status.time += max_arbitrate_interval;
        for (int32 i = 0; i < g_instance_role_group_ptr[group_index].count; ++i) {
            dnReportStatus[i].arbiTime += max_arbitrate_interval;
        }
    }
    write_runlog(LOG,
        "datanode_status_reset, arbitrate time is : %u, InstanceId[%u][%d]=%u, local_arbitrate_time=%u.\n",
        g_instance_group_report_status_ptr[group_index].instance_status.time, group_index, member_index,
        g_instance_role_group_ptr[group_index].instanceMember[member_index].instanceId,
        dnReportStatus[member_index].arbiTime);

    g_instance_group_report_status_ptr[group_index]
        .instance_status.data_node_member[member_index]
        .local_status.static_connections = 0;
    g_instance_group_report_status_ptr[group_index]
        .instance_status.data_node_member[member_index]
        .local_status.buildReason = INSTANCE_HA_DATANODE_BUILD_REASON_UNKNOWN;

    g_instance_group_report_status_ptr[group_index].instance_status.data_node_member[member_index].floatIp.count = 0;

    rc = memset_s(&g_instance_group_report_status_ptr[group_index]
        .instance_status.data_node_member[member_index] .sender_status[0].sender_sent_location,
        8 * sizeof(XLogRecPtr), 0, 8 * sizeof(XLogRecPtr));
    securec_check_errno(rc, (void)rc);
    rc = memset_s(&g_instance_group_report_status_ptr[group_index]
        .instance_status.data_node_member[member_index].receive_status.sender_sent_location,
        8 * sizeof(XLogRecPtr), 0, 8 * sizeof(XLogRecPtr));
    securec_check_errno(rc, (void)rc);

    if (isNodeStop) {
        g_instance_group_report_status_ptr[group_index]
            .instance_status.data_node_member[member_index]
            .local_status.db_state = INSTANCE_HA_STATE_MANUAL_STOPPED;
    } else {
        g_instance_group_report_status_ptr[group_index]
            .instance_status.data_node_member[member_index]
            .local_status.db_state = INSTANCE_HA_STATE_UNKONWN;
    }
}

static void check_cluster_balance_status()
{
    if (!g_isStart && g_HA_status->local_role == CM_SERVER_PRIMARY) {
        int switchedCount = isNodeBalanced(NULL);
        if (switchedCount > 0) {
            report_unbalanced_alarm(ALM_AT_Fault);
        } else if (switchedCount == 0) {
            report_unbalanced_alarm(ALM_AT_Resume);
        }
    }
}

static void FindParam(FILE *fd, char* buf, size_t maxLen, const char *srcParam, char*& subStr, char*& saveptr1)
{
    errno_t rc;
    while (!feof(fd)) {
        rc = memset_s(buf, maxLen, 0, maxLen);
        securec_check_errno(rc, (void)rc);
        (void)fgets(buf, (int)maxLen, fd);
        buf[maxLen - 1] = 0;

        /* skip # comment of agent configure file */
        if (is_comment_line(buf) == 1) {
            continue;
        }

        subStr = strstr(buf, srcParam);
        if (subStr == NULL) {
            continue;
        }
        subStr = strtok_r(buf, "=", &saveptr1);
        if (subStr == NULL) {
            continue;
        }

        if (strcmp(trim(subStr), srcParam) == 0) {
            return;
        }
    }
}

void get_config_param(const char *config_file, const char *srcParam, char *destParam, int destLen)
{
    errno_t rc;
    char buf[MAXPGPATH];
    char *subStr = NULL;
    char *saveptr1 = NULL;

    if (config_file == NULL || srcParam == NULL || destParam == NULL) {
        (void)printf(
            "FATAL Get parameter failed,confDir=%s,srcParam = %s, destParam=%s\n", config_file, srcParam, destParam);
        exit(1);
    }

    FILE *fd = fopen(config_file, "r");
    if (fd == NULL) {
        (void)printf("FATAL Open configure file failed \n");
        exit(1);
    }

    FindParam(fd, buf, sizeof(buf), srcParam, subStr, saveptr1);
    /* process each row to filter character */
    if (subStr != NULL) {
        subStr = trim(saveptr1);
        if (subStr != NULL) {
            subStr = strtok_r(subStr, "#", &saveptr1);
        }
        if (subStr != NULL) {
            subStr = strtok_r(subStr, "\n", &saveptr1);
        }
        if (subStr != NULL) {
            subStr = strtok_r(subStr, "\r", &saveptr1);
        }
        if (subStr != NULL) {
            if (strlen(trim(subStr)) + 1 > (size_t)destLen) {
                write_runlog(FATAL, "The value of parameter %s is invalid, subStr is %s.\n", srcParam, subStr);
                (void)fclose(fd);
                exit(1);
            }
            rc = memcpy_s(destParam, strlen(trim(subStr)) + 1, trim(subStr), strlen(trim(subStr)) + 1);
            securec_check_errno(rc, (void)fclose(fd));
        }
    }

    (void)fclose(fd);
}
/**
 * @brief reload cm_server parameters from cm_server.conf without kill and restart the cm_server process
 *
 */
static void ReloadParametersFromConfigfile()
{
    const int min_switch_rto = 60;
    const uint32 default_value = 6;
    write_runlog(LOG, "reload cm_server parameters from config file.\n");
    int rcs;
    canonicalize_path(configDir);
    GetAlarmConfig(g_alarmConfigDir);
    get_log_paramter(configDir);
    instance_heartbeat_timeout = (uint32)get_int_value_from_config(configDir, "instance_heartbeat_timeout", 6);
    if (instance_heartbeat_timeout == 0) {
        instance_heartbeat_timeout = 6;
        write_runlog(FATAL, "invalid value for parameter \'instance_heartbeat_timeout\' in %s.\n", configDir);
    }
#ifdef ENABLE_MULTIPLE_NODES
    get_paramter_coordinator_heartbeat_timeout();
#endif
    instance_keep_heartbeat_timeout =
        (uint32)get_int_value_from_config(configDir, "instance_keep_heartbeat_timeout", 40);
    cmserver_self_vote_timeout = (uint32)get_int_value_from_config(configDir, "cmserver_self_vote_timeout", 8);
    cmserver_ha_connect_timeout = (uint32)get_int_value_from_config(configDir, "cmserver_ha_connect_timeout", 2);
    instance_failover_delay_timeout =
        (uint32)get_int_value_from_config(configDir, "instance_failover_delay_timeout", 0);
    datastorage_threshold_check_interval =
        get_uint32_value_from_config(configDir, "datastorage_threshold_check_interval", 10);
    g_readOnlyThreshold = get_uint32_value_from_config(configDir, "datastorage_threshold_value_check", 85);
    g_ss_enable_check_sys_disk_usage = get_uint32_value_from_config(configDir, "ss_enable_check_sys_disk_usage", 0);
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
    cm_auth_method = get_authentication_type(configDir);
    get_krb_server_keyfile(configDir);
    switch_rto = get_int_value_from_config(configDir, "switch_rto", 600);
    if (switch_rto < min_switch_rto) {
        switch_rto = min_switch_rto;
    }

    g_clusterStartingArbitDelay =
        (uint32)get_int_value_from_config(configDir, "cluster_starting_aribt_delay", CLUSTER_STARTING_ARBIT_DELAY);

    force_promote = get_int_value_from_config(configDir, "force_promote", 0);
    g_enableE2ERto = (uint32)get_int_value_from_config(configDir, "enable_e2e_rto", 0);
    if (g_enableE2ERto == 1) {
        instance_heartbeat_timeout = INSTANCE_HEARTBEAT_TIMEOUT_FOR_E2E_RTO;
    }
    g_cm_agent_kill_instance_time = get_uint32_value_from_config(configDir, "agent_fault_timeout", 60);
    g_cm_agent_set_most_available_sync_delay_time =
        get_uint32_value_from_config(configDir, "cmserver_set_most_available_sync_delay_times", default_value);
    get_config_param(configDir, "enable_transaction_read_only", g_enableSetReadOnly, sizeof(g_enableSetReadOnly));
    if (!CheckBoolConfigParam(g_enableSetReadOnly)) {
        rcs = strcpy_s(g_enableSetReadOnly, sizeof(g_enableSetReadOnly), "on");
        securec_check_errno(rcs, (void)rcs);
        write_runlog(FATAL, "invalid value for parameter \" enable_transaction_read_only \" in %s.\n", configDir);
    }
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
    GetDdbArbiCfg(RELOAD_PARAMTER);
    GetDelayArbitTimeFromConf();
    GetDelayArbitClusterTimeFromConf();
    g_diskTimeout = get_uint32_value_from_config(configDir, "disk_timeout", 200);
    g_agentNetworkTimeout = get_uint32_value_from_config(configDir, "agent_network_timeout", 6);
    g_ssDoubleClusterMode =
        (SSDoubleClusterMode)get_uint32_value_from_config(configDir, "ss_double_cluster_mode", SS_DOUBLE_NULL);
    GetDnArbitrateMode();
#ifndef ENABLE_PRIVATEGAUSS
    g_waitStaticPrimaryTimes = get_uint32_value_from_config(configDir, "wait_static_primary_times", 6);
    if (g_waitStaticPrimaryTimes < 5) {
        g_waitStaticPrimaryTimes = 5;
    }
#endif

    if (g_cm_server_num == CMS_ONE_PRIMARY_ONE_STANDBY) {
        GetTwoNodesArbitrateParams();
    }

    if (backup_open == CLUSTER_OBS_STANDBY) {
        backup_open = (ClusterRole)get_int_value_from_config(configDir, "backup_open", 0);
    }
    undocumentedVersion = get_uint32_value_from_config(configDir, "upgrade_from", 0);

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

#ifdef ENABLE_MULTIPLE_NODES
    write_runlog(LOG,
        "reload cm_server parameters:\n"
        "  log_min_messages=%d, maxLogFileSize=%d, sys_log_path=%s, \n  alarm_component=%s, "
        "alarm_report_interval=%d, instance_heartbeat_timeout=%u,\n  instance_keep_heartbeat_timeout=%u, "
        "coordinator_heartbeat_timeout=%u, cmserver_ha_heartbeat_timeout=%u, cmserver_self_vote_timeout=%u,\n"
        "  cmserver_ha_status_interval=%u, cmserver_ha_connect_timeout=%u, "
        "instance_failover_delay_timeout=%u, datastorage_threshold_check_interval=%u,\n"
        "  max_datastorage_threshold_check=%d, enableSetReadOnly=%s, enable_set_most_available_sync=%s, "
        "disk_timeout=%u, agent_network_timeout=%u, ss_double_cluster_mode=%u, enableSetReadOnlyThreshold=%u, "
        "ss_enable_check_sys_disk_usage=%u,\n  az_switchover_threshold=%d, az_check_and_arbitrate_interval=%d, "
        "az_connect_check_interval=%d, az_connect_check_delay_time=%d,\n  phony_dead_effective_time=%d, "
        "instance_phony_dead_restart_interval=%d, enable_az_auto_switchover=%d,\n"
        "  cmserver_demote_delay_on_etcd_fault=%d, switch_rto=%d, force_promote=%d, "
        "cluster_starting_aribt_delay=%u, enable_e2e_rto=%u,\n  agent_fault_timeout=%u, "
        "cmserver_set_most_available_sync_delay_times=%u, g_delayArbiTime=%u, g_clusterArbiTime=%d, "
        "wait_static_primary_times=%u, backup_open=%d.\n",
        log_min_messages, maxLogFileSize, sys_log_path, g_alarmComponentPath, g_alarmReportInterval,
        instance_heartbeat_timeout, instance_keep_heartbeat_timeout, coordinator_heartbeat_timeout,
        g_ddbArbicfg.haHeartBeatTimeOut, cmserver_self_vote_timeout, g_ddbArbicfg.haStatusInterval,
        cmserver_ha_connect_timeout, instance_failover_delay_timeout, datastorage_threshold_check_interval,
        max_datastorage_threshold_check, g_enableSetReadOnly, szEnableSetMostAvailableSync, g_diskTimeout,
        g_agentNetworkTimeout, g_ssDoubleClusterMode, g_readOnlyThreshold, g_ss_enable_check_sys_disk_usage,
        az_switchover_threshold, az_check_and_arbitrate_interval, az1_and_az2_connect_check_interval,
        az1_and_az2_connect_check_delay_time, phony_dead_effective_time, instance_phony_dead_restart_interval,
        enable_az_auto_switchover, cmserver_demote_delay_on_etcd_fault, switch_rto, force_promote,
        g_clusterStartingArbitDelay, g_enableE2ERto, g_cm_agent_kill_instance_time,
        g_cm_agent_set_most_available_sync_delay_time, g_delayArbiTime, g_clusterArbiTime,
        g_waitStaticPrimaryTimes, backup_open);
#else
    write_runlog(LOG,
        "reload cm_server parameters:\n"
        "  log_min_messages=%d, maxLogFileSize=%d, sys_log_path=%s, \n  alarm_component=%s, "
        "alarm_report_interval=%d, instance_heartbeat_timeout=%u,\n  instance_keep_heartbeat_timeout=%u, "
        "cmserver_ha_heartbeat_timeout=%u, cmserver_self_vote_timeout=%u,\n  cmserver_ha_status_interval=%u, "
        "cmserver_ha_connect_timeout=%u, instance_failover_delay_timeout=%u,\n"
        "  datastorage_threshold_check_interval=%u, max_datastorage_threshold_check=%d, "
        "enableSetReadOnly=%s,\n  enable_set_most_available_sync=%s, disk_timeout=%u, "
        "agent_network_timeout=%u,\n  ss_double_cluster_mode=%u, enableSetReadOnlyThreshold=%u, "
        "g_ss_enable_check_sys_disk_usage=%u,\n  az_switchover_threshold=%d, az_check_and_arbitrate_interval=%d, "
        "az_connect_check_interval=%d,\n  az_connect_check_delay_time=%d, phony_dead_effective_time=%d, "
        "instance_phony_dead_restart_interval=%d,\n  enable_az_auto_switchover=%d,"
        "cmserver_demote_delay_on_etcd_fault=%d, switch_rto=%d,\n  force_promote=%d, "
        "cluster_starting_aribt_delay=%u, enable_e2e_rto=%u,\n  agent_fault_timeout=%u, "
        "cmserver_set_most_available_sync_delay_times=%u, g_delayArbiTime=%u,\n"
        "g_clusterArbiTime=%d, wait_static_primary_times=%u, backup_open=%d, upgrade_from=%d, "
        "cms_enable_failover_cascade=%u.\n",
        log_min_messages, maxLogFileSize, sys_log_path, g_alarmComponentPath, g_alarmReportInterval,
        instance_heartbeat_timeout, instance_keep_heartbeat_timeout, g_ddbArbicfg.haHeartBeatTimeOut,
        cmserver_self_vote_timeout, g_ddbArbicfg.haStatusInterval, cmserver_ha_connect_timeout,
        instance_failover_delay_timeout, datastorage_threshold_check_interval, max_datastorage_threshold_check,
        g_enableSetReadOnly, szEnableSetMostAvailableSync, g_diskTimeout, g_agentNetworkTimeout,
        g_ssDoubleClusterMode, g_readOnlyThreshold, g_ss_enable_check_sys_disk_usage, az_switchover_threshold,
        az_check_and_arbitrate_interval, az1_and_az2_connect_check_interval, az1_and_az2_connect_check_delay_time,
        phony_dead_effective_time, instance_phony_dead_restart_interval, enable_az_auto_switchover,
        cmserver_demote_delay_on_etcd_fault, switch_rto, force_promote, g_clusterStartingArbitDelay,
        g_enableE2ERto, g_cm_agent_kill_instance_time, g_cm_agent_set_most_available_sync_delay_time,
        g_delayArbiTime, g_clusterArbiTime,
        g_waitStaticPrimaryTimes, backup_open, undocumentedVersion, g_cms_enable_failover_cascade);
#endif
}

static void CheckKerberosHB()
{
    uint32 kerberosHeartBeatTimeOut = 20;

    /* monitor kerberos status heartbeat */
    for (uint kk = 0; kk < KERBEROS_NUM; kk++) {
        g_kerberos_group_report_status.kerberos_status.heartbeat[kk]++;
        if (g_kerberos_group_report_status.kerberos_status.heartbeat[kk] > kerberosHeartBeatTimeOut) {
            g_kerberos_group_report_status.kerberos_status.status[kk] = 0;
        }
    }
}

static void CheckMajorityReElect()
{
    if (arbitration_majority_reelection_timeout > 0) {
        arbitration_majority_reelection_timeout--;
        if (arbitration_majority_reelection_timeout == 0) {
            write_runlog(LOG,
                "arbitration_majority_reelection_timeout elapsed "
                "into 0. Majority re-election enabled now.\n");
        }
    }
}

static void CheckCmctlStop()
{
    if (ctl_stop_cluster_server_halt_arbitration_timeout > 0) {
        ctl_stop_cluster_server_halt_arbitration_timeout--;
        if (ctl_stop_cluster_server_halt_arbitration_timeout == 0) {
            write_runlog(LOG,
                "ctl_stop_cluster_server_halt_arbitration_timeout elapsed into 0, and for some "
                "reason cm_ctl stop-cluster did not succeed. Resume arbitration now.\n");
        }
    }
}

#ifdef ENABLE_MULTIPLE_NODES
static void CheckCnDelDelayTime()
{
    if (g_cnDeleteDelayTimeForClusterStarting > 0) {
        g_cnDeleteDelayTimeForClusterStarting--;
        if (g_cnDeleteDelayTimeForClusterStarting == 0) {
            write_runlog(LOG,
                "cn delete delay time for cm_server_start_mode or big_cluster elapsed "
                "into 0. Coordinator deletion enabled now.\n");
        }
    }

    if (g_cnDeleteDelayTimeForDnWithoutPrimary > 0) {
        g_cnDeleteDelayTimeForDnWithoutPrimary--;
        if (g_cnDeleteDelayTimeForDnWithoutPrimary == 0) {
            write_runlog(LOG,
                "cn delete delay time for dn without primary elapsed "
                "into 0. Coordinator deletion enabled now.\n");
        }
    }
}
#endif

static void CheckRoleChange()
{
    static int historyCMSRole = g_HA_status->local_role;

    if (historyCMSRole != g_HA_status->local_role) {
        write_runlog(LOG,
            "the instance state will reset, history role is %d, current role is %d.\n",
            historyCMSRole,
            g_HA_status->local_role);
        historyCMSRole = g_HA_status->local_role;
        for (uint32 i = 0; i < g_dynamic_header->relationCount; i++) {
            (void)pthread_rwlock_wrlock(&(g_instance_group_report_status_ptr[i].lk_lock));
            for (int j = 0; j < g_instance_role_group_ptr[i].count; j++) {
                /* when cms change primary, the heart beat will ++ at the time of last role */
                g_instance_group_report_status_ptr[i].instance_status.command_member[j].heat_beat = 0;
            }
            (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[i].lk_lock));
        }
    }
}

static void CheckETCD()
{
    (void)pthread_rwlock_wrlock(&instance_status_rwlock);

    for (uint32 ii = 0; ii < g_etcd_num; ii++) {
        if (g_instance_status_for_etcd_timeout[ii] > 0) {
            g_instance_status_for_etcd_timeout[ii]--;
        } else {
            write_runlog(LOG, "the %u etcd heartbeat timeout.\n", ii);
            g_instance_status_for_etcd[ii] = CM_ETCD_DOWN;
        }
    }

    (void)pthread_rwlock_unlock(&instance_status_rwlock);
}

static void CheckHB()
{
    if (cmserver_switchover_timeout > 0) {
        cmserver_switchover_timeout--;
    }

    if (g_instance_failover_delay_time_from_set > 0) {
        g_instance_failover_delay_time_from_set--;
    }

    if (g_init_cluster_delay_time > 0) {
        g_init_cluster_delay_time--;
    } else {
        g_init_cluster_delay_time = 0;
        clean_init_cluster_state();
    }

    if (g_clusterStartingTimeout > 0) {
        g_clusterStartingTimeout--;
    } else {
        g_clusterStartingTimeout = 0;
        g_clusterStarting = false;
    }
}

static inline void CheckDdbClusterStatusOn2Nodes()
{
    if (g_ddbNetworkIsolationTimeout > 0) {
        g_ddbNetworkIsolationTimeout--;
    } else {
        g_ddbNetworkIsolationTimeout = 0;
    }
}

#ifdef ENABLE_MULTIPLE_NODES
static void DoCNTimeout(uint32 groupIdx, int memIdx)
{
    cm_instance_report_status *instanceReportStatus = &g_instance_group_report_status_ptr[groupIdx].instance_status;
    cm_instance_command_status *instanceCommandStatus = &instanceReportStatus->command_member[memIdx];
    cm_instance_role_status *instanceRoleStatus = &g_instance_role_group_ptr[groupIdx].instanceMember[memIdx];

    if (instanceReportStatus->coordinatemember.status.status != INSTANCE_ROLE_UNKNOWN) {
        coordinator_status_reset((int)groupIdx, memIdx);
    }

    if (((coordinator_heartbeat_timeout == 0 && g_cmd_disable_coordinatorId == instanceRoleStatus->instanceId) ||
            (coordinator_heartbeat_timeout > 0 &&
                instanceCommandStatus->heat_beat > (int)coordinator_heartbeat_timeout)) &&
        (instanceReportStatus->coordinatemember.status.status == INSTANCE_ROLE_UNKNOWN) &&
        (instanceReportStatus->coordinatemember.status.db_state == INSTANCE_HA_STATE_STARTING)) {
        write_runlog(LOG,
            "CN heartbeat timeout, reset CN. InstanceId[%u][%d]=%u, heat_beat=%d, "
            "coordinator_heartbeat_timeout=%u, status=%d, db_state=%d\n",
            groupIdx, memIdx, instanceRoleStatus->instanceId, instanceCommandStatus->heat_beat,
            coordinator_heartbeat_timeout, instanceReportStatus->coordinatemember.status.status,
            instanceReportStatus->coordinatemember.status.db_state);

        coordinator_status_reset((int)groupIdx, memIdx);
    }
}
#endif

static void DoCommandTimeout(uint32 i, int j)
{
    cm_instance_report_status *instanceReportStatus = &g_instance_group_report_status_ptr[i].instance_status;
    cm_instance_command_status *instanceCommandStatus = &instanceReportStatus->command_member[j];
    cm_instance_role_status *instanceRoleStatus = &g_instance_role_group_ptr[i].instanceMember[j];

    if ((instanceCommandStatus->heat_beat - (int)instance_heartbeat_timeout) % 5 == 0) {
        write_runlog(LOG,
            "instance(%u) heartbeat timeout, heartbeat:%d, threshold:%u\n",
            instanceRoleStatus->instanceId,
            instanceCommandStatus->heat_beat,
            instance_heartbeat_timeout);
    }

    uint32 checkNode = instanceRoleStatus->node;
    g_stopNodeIter = g_stopNodes.find(checkNode);
    if (g_stopNodeIter != g_stopNodes.end()) {
        write_runlog(LOG, "node(%u) is stopped.\n", checkNode);
        datanode_status_reset(i, j, true);
#ifdef ENABLE_MULTIPLE_NODES
        gtm_status_reset(i, j, true);
#endif
    } else {
        datanode_status_reset(i, j, false);
#ifdef ENABLE_MULTIPLE_NODES
        gtm_status_reset(i, j, false);
#endif
    }
#ifdef ENABLE_MULTIPLE_NODES
    DoCNTimeout(i, j);
#endif
}

static void DoInstancePromote(uint32 i, int j)
{
    cm_instance_report_status *instanceReportStatus = &g_instance_group_report_status_ptr[i].instance_status;
    cm_instance_command_status *instanceCommandStatus = &instanceReportStatus->command_member[j];
    cm_instance_role_status *instanceRoleStatus = &g_instance_role_group_ptr[i].instanceMember[j];
    cm_instance_arbitrate_status *instanceArbitrateAtatus = &instanceReportStatus->arbitrate_status_member[j];
    cm_instance_datanode_report_status *dataNodeMember = &instanceReportStatus->data_node_member[j];
    int other_member_index;

    if (j == 0) {
        other_member_index = 1;
    } else {
        other_member_index = 0;
    }

    if (instanceArbitrateAtatus->promoting_timeout > 0) {
        if (dataNodeMember->local_status.local_role == INSTANCE_ROLE_PRIMARY &&
            dataNodeMember->local_status.db_state == INSTANCE_HA_STATE_NORMAL) {
            instanceArbitrateAtatus->promoting_timeout = 0;
            write_runlog(LOG, "instance %u failover successful.\n", instanceRoleStatus->instanceId);
        } else if (instanceArbitrateAtatus->promoting_timeout == 1) {
            if (dataNodeMember->local_status.db_state == INSTANCE_HA_STATE_NEED_REPAIR) {
                instanceArbitrateAtatus->promoting_timeout = 0;
                instanceRoleStatus->role = INSTANCE_ROLE_STANDBY;
                g_instance_role_group_ptr[i].instanceMember[other_member_index].role = INSTANCE_ROLE_PRIMARY;
                instanceCommandStatus->role_changed = INSTANCE_ROLE_CHANGED;
                (void)WriteDynamicConfigFile(false);
                write_runlog(LOG,
                    "instance role is changed, instance %u is standby, instance %u is primary.\n",
                    instanceRoleStatus->instanceId,
                    g_instance_role_group_ptr[i].instanceMember[other_member_index].instanceId);
            } else if (dataNodeMember->local_status.db_state != INSTANCE_HA_STATE_PROMOTING) {
                instanceArbitrateAtatus->promoting_timeout--;
            }
        } else {
            instanceArbitrateAtatus->promoting_timeout--;
        }
    }
}

static void UpdateCommandStatus(uint32 i, int j)
{
    cm_instance_report_status *instanceReportStatus = &g_instance_group_report_status_ptr[i].instance_status;
    cm_instance_command_status *instanceCommandStatus = &instanceReportStatus->command_member[j];
    cm_instance_role_status *instanceRoleStatus = &g_instance_role_group_ptr[i].instanceMember[j];

    instanceCommandStatus->heat_beat++;
    write_runlog(DEBUG5, "instance(%u) heartbeat is %d monitor count is %u!\n",
        instanceRoleStatus->instanceId,
        instanceCommandStatus->heat_beat,
        instance_heartbeat_timeout);

    if (instanceCommandStatus->keep_heartbeat_timeout >= 0) {
        instanceCommandStatus->keep_heartbeat_timeout++;
    } else {
        instanceCommandStatus->keep_heartbeat_timeout = 0;
    }
}

static void UpdateCommandStatus1(uint32 i, int j)
{
    cm_instance_report_status *instanceReportStatus = &g_instance_group_report_status_ptr[i].instance_status;
    cm_instance_command_status *instanceCommandStatus = &instanceReportStatus->command_member[j];

    if (instanceCommandStatus->pengding_command == MSG_CM_AGENT_SWITCHOVER) {
        instanceCommandStatus->command_send_times++;
    }

    if (instanceCommandStatus->pengding_command == MSG_CM_AGENT_BUTT) {
        instanceCommandStatus->command_send_times = 0;
        instanceCommandStatus->command_send_num = 0;
    }

    if (instanceCommandStatus->arbitrate_delay_time_out > 0) {
        instanceCommandStatus->arbitrate_delay_time_out--;
    }

    if (instanceCommandStatus->time_out > 0) {
        instanceCommandStatus->time_out--;
    }
}

static void CheckOneMember(uint32 i, int j)
{
    cm_instance_report_status *instanceReportStatus = &g_instance_group_report_status_ptr[i].instance_status;
    cm_instance_command_status *instanceCommandStatus = &instanceReportStatus->command_member[j];
    cm_instance_datanode_report_status *dataNodeMember = &instanceReportStatus->data_node_member[j];
    int instanceType = g_instance_role_group_ptr[i].instanceMember[j].instanceType;
    uint32 instanceId = g_instance_role_group_ptr[i].instanceMember[j].instanceId;

    UpdateCommandStatus(i, j);

    const int dnNormalTimeout = 3;
    if (instanceCommandStatus->heat_beat > dnNormalTimeout && instanceType == INSTANCE_TYPE_DATANODE) {
        dataNodeMember->local_status.local_role = INSTANCE_ROLE_UNKNOWN;
        write_runlog(LOG, "instance(%u) heartbeat abnormal, set dn INSTANCE_ROLE_UNKNOWN\n", instanceId);
    }

    if (instanceCommandStatus->heat_beat > (int)instance_heartbeat_timeout) {
        DoCommandTimeout(i, j);
    }

    if (instanceCommandStatus->delaySwitchoverTime > 0) {
        --instanceCommandStatus->delaySwitchoverTime;
    }

    if (!g_multi_az_cluster) {
        DoInstancePromote(i, j);
    }

    if (dataNodeMember->phony_dead_interval > 0) {
        dataNodeMember->phony_dead_interval--;
    } else if (dataNodeMember->phony_dead_interval < 0) {
        dataNodeMember->phony_dead_interval = 0;
    }
    if (instanceReportStatus->gtm_member[j].phony_dead_interval > 0) {
        instanceReportStatus->gtm_member[j].phony_dead_interval--;
    } else if (instanceReportStatus->gtm_member[j].phony_dead_interval < 0) {
        instanceReportStatus->gtm_member[j].phony_dead_interval = 0;
    }

    if (instanceCommandStatus->buildFailedTimeout > 1) {
        --instanceCommandStatus->buildFailedTimeout;
    }

    UpdateCommandStatus1(i, j);

    if (dataNodeMember->send_gs_guc_time < CM_GS_GUC_SEND_INTERVAL) {
        dataNodeMember->send_gs_guc_time++;
    }

#ifdef ENABLE_MULTIPLE_NODES
    if (instanceCommandStatus->time_out <= 0) {
        if (instanceCommandStatus->pengding_command != (int)MSG_CM_AGENT_NOTIFY_CN) {
            CleanCommand(i, j);
        }
    }
#else
    if (instanceCommandStatus->time_out <= 0) {
        CleanCommand(i, j);
    }
#endif
}

static void CheckOneInstanceGroup(uint32 i)
{
    cm_instance_report_status *instanceReportStatus = &g_instance_group_report_status_ptr[i].instance_status;
    if (instanceReportStatus->cma_kill_instance_timeout > 1) {
        instanceReportStatus->cma_kill_instance_timeout--;
    }
    if (instanceReportStatus->coordinatemember.phony_dead_interval > 0) {
        instanceReportStatus->coordinatemember.phony_dead_interval--;
    } else if (instanceReportStatus->coordinatemember.phony_dead_interval < 0) {
        instanceReportStatus->coordinatemember.phony_dead_interval = 0;
    }

    if (g_instance_role_group_ptr[i].instanceMember[0].instanceType == INSTANCE_TYPE_COORDINATE) {
        instanceReportStatus->coordinatemember.auto_delete_delay_time++;
        instanceReportStatus->coordinatemember.cma_fault_timeout_to_killcn++;

        if (instanceReportStatus->coordinatemember.disable_time_out > 0) {
            instanceReportStatus->coordinatemember.disable_time_out--;
        }
    }

    for (int j = 0; j < g_instance_role_group_ptr[i].count; j++) {
        CheckOneMember(i, j);
    }
}

static void CheckAllInstanceGroup()
{
    for (uint32 i = 0; i < g_dynamic_header->relationCount; i++) {
        (void)pthread_rwlock_wrlock(&(g_instance_group_report_status_ptr[i].lk_lock));
        CheckOneInstanceGroup(i);
        (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[i].lk_lock));
    }
}

static void CheckAllUDF()
{
    for (uint32 i = 0; i < g_node_num; i++) {
        (void)pthread_rwlock_wrlock(&(g_fenced_UDF_report_status_ptr[i].lk_lock));
        g_fenced_UDF_report_status_ptr[i].heart_beat++;
        write_runlog(DEBUG5,
            "fenced UDF(%u) heartbeat is %d monitor count is %u!\n",
            i,
            g_fenced_UDF_report_status_ptr[i].heart_beat,
            instance_heartbeat_timeout);

        if (g_fenced_UDF_report_status_ptr[i].heart_beat > (int)instance_heartbeat_timeout) {
            write_runlog(DEBUG1,
                "fenced UDF(%u) heartbeat timeout, heartbeat:%d, threshold:%u.\n",
                i,
                g_fenced_UDF_report_status_ptr[i].heart_beat,
                instance_heartbeat_timeout);
            g_fenced_UDF_report_status_ptr[i].status = INSTANCE_ROLE_UNKNOWN;
        }
        (void)pthread_rwlock_unlock(&(g_fenced_UDF_report_status_ptr[i].lk_lock));
    }
}

static void ResetInstanceStatus()
{
    for (uint32 i = 0; i < g_dynamic_header->relationCount; i++) {
        g_instance_group_report_status_ptr[i].instance_status.cma_kill_instance_timeout = 0;
        g_instance_group_report_status_ptr[i].instance_status.coordinatemember.phony_dead_interval = 0;
        for (int j = 0; j < g_instance_role_group_ptr[i].count; j++) {
            g_instance_group_report_status_ptr[i].instance_status.data_node_member[j].phony_dead_interval = 0;
            g_instance_group_report_status_ptr[i].instance_status.gtm_member[j].phony_dead_interval = 0;
        }
    }
}

static void UpdateCheckInterval(MonitorContext *ctx)
{
    struct timespec checkEnd = {0, 0};

    (void)clock_gettime(CLOCK_MONOTONIC, &checkEnd);
    if (ctx->takeTime == 0) {
        g_monitor_thread_check_invalid_times = 0;
    } else {
        if ((checkEnd.tv_sec - ctx->takeTime) > 2) {
            g_monitor_thread_check_invalid_times++;
            write_runlog(LOG,
                "has find %d invalid check times, take %ld seconds.\n",
                g_monitor_thread_check_invalid_times,
                (checkEnd.tv_sec - ctx->takeTime));
        } else {
            if (g_monitor_thread_check_invalid_times > 0) {
                write_runlog(LOG, "reset invalid check times to zeros.\n");
            }
            g_monitor_thread_check_invalid_times = 0;
        }
    }
    ctx->takeTime = checkEnd.tv_sec;
}

static void SetResStatUnknown(CmResStatList *resStat, uint32 instIndex)
{
    if (!CanProcessResStatus()) {
        write_runlog(LOG, "[%s], res status list invalid, can't continue.\n", __FUNCTION__);
        return;
    }

    if (resStat->status.resStat[instIndex].status != (uint32)CM_RES_STAT_UNKNOWN) {
        (void)pthread_rwlock_wrlock(&resStat->rwlock);
        resStat->status.resStat[instIndex].status = (uint32)CM_RES_STAT_UNKNOWN;
        ++resStat->status.version;
        OneResStatList tmpStat = resStat->status;
        (void)pthread_rwlock_unlock(&resStat->rwlock);

        write_runlog(LOG, "res inst(%u) report invalid status timeout, set its status unknown.\n", instIndex);
        PrintCusInfoResList(&tmpStat, __FUNCTION__);
        ProcessReportResChangedMsg(false, &resStat->status);
    }
}

static void CheckAllResReportByNode()
{
    for (uint32 i = 0; i < CusResCount(); ++i) {
        for (uint32 j = 0; j < g_resStatus[i].status.instanceCount; ++j) {
            uint32 cmInstId = g_resStatus[i].status.resStat[j].cmInstanceId;
            uint32 inter = GetOneResInstReportInter(g_resStatus[i].status.resName, cmInstId);
            if (inter >= g_agentNetworkTimeout) {
                SetResStatUnknown(&g_resStatus[i], j);
            } else {
                IncreaseOneResInstReportInter(g_resStatus[i].status.resName, cmInstId);
            }
        }
    }
}

static void CheckAllIsregByNode()
{
    UpdateCheckListAfterTimeout();
    UpdateReportInter();
}

static void CheckMaxCluster()
{
    SetDelayArbiClusterTime();
    CheckMaxClusterHeartbeartValue();
}

static status_t IsPeerCmsReachableOn2Nodes()
{
    if (!ENABLED_AUTO_FAILOVER_ON2NODES(g_cm_server_num, g_paramsOn2Nodes.cmsEnableFailoverOn2Nodes)) {
        write_runlog(ERROR, "should be called by two node cluster with enabling auto failover only.\n");
        return CM_ERROR;
    }

    int socketFd = -1;
    struct addrinfo hints;
    struct addrinfo *result;
    struct addrinfo *rp;
    struct timeval tv = { 0, 0 };
    status_t ret = CM_ERROR;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    // Allow IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;

    for (uint32 i = 0; i < g_cm_server_num; i++) {
        if (g_node[i].cmServerId == g_currentNode->cmServerId) {
            continue;
        }

        // Resolve peer cms hostname to IP addresses
        char port[CM_IP_LENGTH];
        errno_t rc = snprintf_s(port, CM_IP_LENGTH, CM_IP_LENGTH - 1, "%u", g_node[i].cmServerLocalHAPort);
        securec_check_intval(rc, (void)rc);
        int addrStatus = getaddrinfo(g_node[i].cmServerLocalHAIP[0], port, &hints, &result);
        if (addrStatus != 0) {
            write_runlog(ERROR, "getaddrinfo: %s\n", gai_strerror(addrStatus));
            continue;
        }

        for (rp = result; rp != NULL; rp = rp->ai_next) {
            socketFd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (socketFd == -1) {
                write_runlog(ERROR, "could not create socket.\n");
                continue;
            }

            tv.tv_sec = CM_TCP_TIMEOUT;
            setsockopt(socketFd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            setsockopt(socketFd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

            char addrStr[INET6_ADDRSTRLEN];
            void *addr;
            if (rp->ai_family == AF_INET) {
                struct sockaddr_in *ipv4 = (struct sockaddr_in *)rp->ai_addr;
                addr = &(ipv4->sin_addr);
            } else { // AF_INET6
                struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)rp->ai_addr;
                addr = &(ipv6->sin6_addr);
            }
            inet_ntop(rp->ai_family, addr, addrStr, sizeof(addrStr));

            if (connect(socketFd, rp->ai_addr, rp->ai_addrlen) == -1) {
                write_runlog(LOG, "could not connect to peer cms %s, errno=%d.\n", addrStr, errno);
                close(socketFd);
                freeaddrinfo(result);
                return CM_ERROR;
            }
            write_runlog(DEBUG1, "connect to peer cms %s successfuly.\n", addrStr);
            ret = CM_SUCCESS;
            close(socketFd);
            break; // Connected successfully, break out of loop
        }

        freeaddrinfo(result);
        if (ret == CM_SUCCESS) {
            break; // Connected successfully, break out of loop
        }
    }

    return ret;
}

static status_t GetClusterInfoFromDDb(char *info, int outLen)
{
    if (g_inMaintainMode) {
        write_runlog(LOG, "in maintain mode, can't do ddb cmd.\n");
        return CM_SUCCESS;
    }

    char cmd[DCC_CMD_MAX_LEN] = {0};
    char errMsg[ERR_MSG_LENGTH] = {0};
    status_t ret = CM_SUCCESS;

    errno_t rc = snprintf_s(cmd, DCC_CMD_MAX_LEN, DCC_CMD_MAX_LEN - 1, " %s", CM_DDB_CLUSTER_INFO_CMD);
    securec_check_intval(rc, (void)rc);
    ret = DoDdbExecCmd(cmd, info, &outLen, errMsg, DCC_CMD_MAX_OUTPUT_LEN);
    if (ret != CM_SUCCESS) {
        write_runlog(ERROR, "get ddb cluster info failed. error: %s\n", errMsg);
    }

    return ret;
}

static status_t IsPeerApplyIndexChanged(cJSON *nodes)
{
    static int peerApplyIndex = 0;
    int prevPeerApplyIndex = peerApplyIndex;
    cJSON *applyIndex = NULL;

    if (g_currentNode->cmServerId == CMS_ID_INDEX_ONE) {
        applyIndex = cJSON_GetObjectItem(cJSON_GetArrayItem(nodes, 1), "apply_index");
    } else if (g_currentNode->cmServerId == CMS_ID_INDEX_TWO) {
        applyIndex = cJSON_GetObjectItem(cJSON_GetArrayItem(nodes, 0), "apply_index");
    } else {
        write_runlog(ERROR, "wrong cm server id: %d\n", g_currentNode->cmServerId);
        exit(1);
    }

    if (applyIndex == NULL) {
        write_runlog(ERROR, "cannot parse ddb cluster info {apply_index}.\n");
        return CM_ERROR;
    }
    peerApplyIndex = applyIndex->valueint;
    write_runlog(DEBUG5, "prevPeerApplyIndex: %d peerApplyIndex: %d g_ddbNetworkIsolationTimeout: %d\n",
        prevPeerApplyIndex, peerApplyIndex, g_ddbNetworkIsolationTimeout);

    if (peerApplyIndex == prevPeerApplyIndex) {
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static status_t IsPeerCmsRolePrimary(cJSON *nodes)
{
    int peerCmserverRole = -1;
    cJSON *role = NULL;

    if (g_currentNode->cmServerId == CMS_ID_INDEX_ONE) {
        role = cJSON_GetObjectItem(cJSON_GetArrayItem(nodes, 1), "role");
    } else if (g_currentNode->cmServerId == CMS_ID_INDEX_TWO) {
        role = cJSON_GetObjectItem(cJSON_GetArrayItem(nodes, 0), "role");
    }

    if (role == NULL) {
        write_runlog(ERROR, "cannot parse ddb cluster info {role}.\n");
        return CM_ERROR;
    }
    peerCmserverRole = strcmp(cJSON_GetStringValue(role), "LEADER") == 0 ? CM_SERVER_PRIMARY : CM_SERVER_STANDBY;
    write_runlog(DEBUG5, "peerCmserverRole: %s g_ddbNetworkIsolationTimeout: %d\n",
        peerCmserverRole == CM_SERVER_PRIMARY ? "Primary" : "Standby", g_ddbNetworkIsolationTimeout);

    if (peerCmserverRole != CM_SERVER_PRIMARY) {
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static status_t IsDdbLogSyncOn2Nodes(char * info)
{
    if (info == NULL) {
        return CM_ERROR;
    }

    write_runlog(DEBUG5, "ddb cluster info: %s\n", info);
    cJSON *root = cJSON_Parse(info);
    if (root == NULL) {
        write_runlog(ERROR, "cannot parse ddb cluster info {root}.\n");
        return CM_ERROR;
    }

    cJSON *stream = cJSON_GetArrayItem(cJSON_GetObjectItem(root, "stream_list"), 0);
    if (stream == NULL) {
        write_runlog(ERROR, "cannot parse ddb cluster info {stream_list}.\n");
	cJSON_Delete(root);
        return CM_ERROR;
    }

    cJSON *nodes = cJSON_GetObjectItem(stream, "nodes");
    if (nodes == NULL) {
        write_runlog(ERROR, "cannot parse ddb cluster info {nodes}.\n");
	cJSON_Delete(root);
        return CM_ERROR;
    }

    switch (g_HA_status->local_role) {
        case CM_SERVER_PRIMARY:
            return IsPeerApplyIndexChanged(nodes);
        case CM_SERVER_STANDBY:
            return IsPeerCmsRolePrimary(nodes);
        default:
            write_runlog(ERROR, "unexpected local_role: %d\n", g_HA_status->local_role);
            return CM_ERROR;
    }
    
    cJSON_Delete(root);
    return CM_SUCCESS;
}

static inline void DdbSetDdbWorkMode(ddb_work_mode workMode, unsigned int voteNum, uint32 isBigVoteNum)
{
    if (SetDdbWorkMode(workMode, voteNum) != CM_SUCCESS) {
        write_runlog(ERROR, "setting work mode: %d failed with minVoteNum: %d isBigVoteNum: %d\n",
            workMode, voteNum, isBigVoteNum);
        return;
    }
    g_ddbWorkMode = workMode;
    if (workMode == DDB_WORK_MODE_MINORITY) {
        g_bigVoteNumInMinorityMode = isBigVoteNum;
    }
}

/*
 * if reachale is true:
 * all ip is reachable, return CM_SUCCESS
 * else return CM_ERROR
 * if reachale is false:
 * all ip is not reachable, return CM_SUCCESS
 * else return CM_ERROR
 */
static status_t CheckAllIpStatus(char *ip, bool reachable)
{
    if (ip == nullptr) {
        return CM_ERROR;
    }

    char tmpIp[CM_IP_LENGTH];
    errno_t rc = strcpy_s(tmpIp, CM_IP_LENGTH, ip);
    securec_check_errno(rc, (void)rc);
    char *saveptr = NULL;
    char *token = strtok_r(tmpIp, ",", &saveptr);
    status_t ret = CM_SUCCESS;
    bool flag = false;
    while (token != NULL) {
        if (reachable && IsReachableIP(token) != CM_SUCCESS) {
            ret = CM_ERROR;
            break;
        } else if (!reachable && IsReachableIP(token) == CM_SUCCESS) {
            ret = CM_ERROR;
            break;
        }
        flag = true;
        token = strtok_r(NULL, ",", &saveptr);
    }

    return flag ? ret : CM_ERROR;
}

static void DdbMinorityWorkModeSetInMajority()
{
    uint32 minVoteNum = 1;
    if (CheckAllIpStatus(g_paramsOn2Nodes.thirdPartyGatewayIp, true) == CM_SUCCESS) {
        // all third party gateway is reachable, setting a small vote num to make sure current node works as primary.
        write_runlog(LOG, "promote node to primary\n");
        DdbSetDdbWorkMode(DDB_WORK_MODE_MINORITY, minVoteNum, 0);
    } else {
        // not all third party gateway is reachable, setting a big vote num to make sure current node works as standby.
        minVoteNum += MAX_VOTE_NUM;
        DdbSetDdbWorkMode(DDB_WORK_MODE_MINORITY, minVoteNum, 1);

        if (g_HA_status->local_role == CM_SERVER_PRIMARY) {
            // primary node need to demote to standby
            write_runlog(LOG, "demote node to standby\n");
            if (DemoteDdbRole2Standby() != CM_SUCCESS) {
                write_runlog(ERROR, "demote node to standby failed\n");
                return;
            }
        }
    }

    write_runlog(LOG, "go into minority work mode with minVoteNum: %d g_bigVoteNumInMinorityMode: %d.\n",
        minVoteNum, g_bigVoteNumInMinorityMode);
    (void)pthread_rwlock_wrlock(&term_update_rwlock);
    IncrementTermToDdb(CM_INCREMENT_BIG_TERM_VALUE);
    (void)pthread_rwlock_unlock(&term_update_rwlock);
}

static void DdbMinorityWorkModeSetInMinority()
{
    uint32 minVoteNum = 1;
    if (CheckAllIpStatus(g_paramsOn2Nodes.thirdPartyGatewayIp, true) == CM_SUCCESS && g_bigVoteNumInMinorityMode == 1) {
        write_runlog(LOG, "reset minority work mode and become primary.\n");
        DdbSetDdbWorkMode(DDB_WORK_MODE_MINORITY, minVoteNum, 0);
    } else if (CheckAllIpStatus(g_paramsOn2Nodes.thirdPartyGatewayIp, false) == CM_SUCCESS
        && g_bigVoteNumInMinorityMode == 0) {
        /*
         * every third party gateway is not reachable,
         * setting a big vote num to make sure current node works as standby.
         */
        minVoteNum += MAX_VOTE_NUM;
        write_runlog(LOG, "reset minority work mode and become standby.\n");
        DdbSetDdbWorkMode(DDB_WORK_MODE_MINORITY, minVoteNum, 1);

        if (g_HA_status->local_role == CM_SERVER_PRIMARY) {
            write_runlog(LOG, "demote node to standby\n");
            if (DemoteDdbRole2Standby() != CM_SUCCESS) {
                write_runlog(ERROR, "demote node to standby failed\n");
            }
        }
    }
}

static void DdbMinorityWorkModeSetInStartup()
{
    uint32 minVoteNum = 1;
    if (CheckAllIpStatus(g_paramsOn2Nodes.thirdPartyGatewayIp, true) == CM_SUCCESS) {
        write_runlog(LOG, "start up with minority work mode and minVoteNum: %d.\n", minVoteNum);
        DdbSetDdbWorkMode(DDB_WORK_MODE_MINORITY, minVoteNum, 0);
    } else {
        minVoteNum += MAX_VOTE_NUM;
        write_runlog(LOG, "start up with minority work mode and minVoteNum: %d.\n", minVoteNum);
        DdbSetDdbWorkMode(DDB_WORK_MODE_MINORITY, minVoteNum, 1);
        DemoteDdbRole2Standby();
    }

}

static int DdbStatusCheck() {
    /*
    * start to do dcc cluster status check.
    */
    char info[DCC_CMD_MAX_OUTPUT_LEN] = {0};
    if (IsPeerCmsReachableOn2Nodes() == CM_SUCCESS ||
        (GetClusterInfoFromDDb(info, DCC_CMD_MAX_OUTPUT_LEN) == CM_SUCCESS
        && IsDdbLogSyncOn2Nodes(info) == CM_SUCCESS)) {
        /*
        * network are good between two nodes. reset g_ddbNetworkIsolationTimeout.
        */
        g_ddbNetworkIsolationTimeout = g_paramsOn2Nodes.cmsNetworkIsolationTimeout;
        return CM_SUCCESS;
    }

    return CM_ERROR;
}

static void DoDdbStatusCheckAndSet()
{
    /*
     * if the cluster are not two nodes cluster, or don't enable auto failover, skip check.
     */
    if (!ENABLED_AUTO_FAILOVER_ON2NODES(g_cm_server_num, g_paramsOn2Nodes.cmsEnableFailoverOn2Nodes)) {
        cm_sleep(DDB_STATUS_CHECK_INTERVAL);
        return;
    }

    if (DdbStatusCheck() == CM_SUCCESS) {
        if (g_ddbWorkMode != DDB_WORK_MODE_MAJORITY) {
            write_runlog(LOG, "go into majority work mode.\n");
            DdbSetDdbWorkMode(DDB_WORK_MODE_MAJORITY, 0, 0);
        }
        cm_sleep(DDB_STATUS_CHECK_INTERVAL);
        return;
    }

    if (g_ddbNetworkIsolationTimeout != 0) {
        cm_sleep(DDB_STATUS_CHECK_INTERVAL);
        return;
    }

    /*
    * go into minority work mode, because:
    * 1. we cannot get ddb cluster info sync within g_cms_ddb_log_sync_timeout
    * 2. we cannot reach peer node dcc ip:port
    */
    switch (g_ddbWorkMode) {
        case DDB_WORK_MODE_MAJORITY:
            DdbMinorityWorkModeSetInMajority();
            break;
        case DDB_WORK_MODE_MINORITY:
            DdbMinorityWorkModeSetInMinority();
            break;
        default:
            DdbMinorityWorkModeSetInStartup();
    }
    cm_sleep(DDB_STATUS_CHECK_INTERVAL);
    return;
}

static void DoMonitor(MonitorContext *ctx)
{
    CheckKerberosHB();

    CheckMajorityReElect();

    CheckCmctlStop();

#ifdef ENABLE_MULTIPLE_NODES
    CheckCnDelDelayTime();
#endif

    CheckHB();

    if (g_dbType == DB_DCC &&
        ENABLED_AUTO_FAILOVER_ON2NODES(g_cm_server_num, g_paramsOn2Nodes.cmsEnableFailoverOn2Nodes)) {
        /*
         * two nodes cluster and enable auto failover.
         * when network isolation happened, cms choice a node as new primary if
         * the node can reach the third party gateway.
         */
        CheckDdbClusterStatusOn2Nodes();
    }

    CheckMaxCluster();

    CheckRoleChange();

    if (g_HA_status->local_role == CM_SERVER_PRIMARY) {
        CheckETCD();

        if (g_cmserverDemoteDelayOnDdbFault > 0) {
            g_cmserverDemoteDelayOnDdbFault--;
        }

        CheckAllInstanceGroup();

        CheckAllUDF();
    } else {
        ResetInstanceStatus();
    }

    if (g_gotParameterReload == 1) {
        ReloadParametersFromConfigfile();
        g_gotParameterReload = 0;
    }

    if (cmserver_switchover_timeout == 0) {
        switchOverInstances.clear();
        write_runlog(DEBUG1, "switchover timeout clear, no switchover in progress.\n");
        (void)pthread_rwlock_wrlock(&(switchover_az_rwlock));
        switchoverAZInProgress = false;
        (void)pthread_rwlock_unlock(&(switchover_az_rwlock));
    }

    if (g_instance_failover_delay_time_from_set == 1) {
        instance_failover_delay_timeout =
            (uint32)get_int_value_from_config(configDir, "instance_failover_delay_timeout", 0);
    }

    g_cluster_unbalance_check_interval--;
    if (g_cluster_unbalance_check_interval <= 0) {
        g_cluster_unbalance_check_interval = cluster_unbalance_check_interval;
        check_cluster_balance_status();
    }

    if (IsCusResExist() && (g_HA_status->local_role == CM_SERVER_PRIMARY)) {
        CheckAllResReportByNode();
        CheckAllIsregByNode();
    }

    cm_sleep(1);

    if (g_HA_status->local_role == CM_SERVER_PRIMARY) {
        UpdateCheckInterval(ctx);
    }
}

void *CM_ThreadMonitorMain(void *argp)
{
    CM_MonitorThread *monitor = (CM_MonitorThread *)argp;
    /* unify log style */
    thread_name = "Monitor";

    write_runlog(LOG, "Starting Monitor thread\n");

    monitor->thread.type = THREAD_TYPE_MONITOR;

    MonitorContext ctx;
    ctx.takeTime = 0;

    for (;;) {
        DoMonitor(&ctx);
    }
    return NULL;
}

void *CM_ThreadDdbStatusCheckAndSetMain(void *argp)
{
    CM_DdbStatusCheckAndSetThread *pCheckThread = (CM_DdbStatusCheckAndSetThread *)argp;
    /* unify log style */
    thread_name = "DdbStatusCheck";

    write_runlog(LOG, "Starting Ddb Status Check thread\n");

    pCheckThread->thread.type = THREAD_TYPE_DDB_STATUS_CHECKER;

    for (;;) {
        DoDdbStatusCheckAndSet();
    }
    return NULL;
}

static void GetStopNodes(char *stopAzNodes, size_t len)
{
    if (stopAzNodes == NULL || len == 0) {
        write_runlog(WARNING, "az_stop_nodes is null, or len is zero.\n");
        return;
    }

    write_runlog(LOG, "az_stop_nodes is: (%s).\n", stopAzNodes);

    char *saveptr = NULL;
    char *subStr = strtok_r(stopAzNodes, ",", &saveptr);
    while (subStr) {
        (void)g_stopNodes.insert(strtol(subStr, NULL, 10));
        subStr = strtok_r(NULL, ",", &saveptr);
    }
}

/*
 * thread to check whether node is manually stopped
 * check node status must not be too often since ddb query cost some seconds
 */
void *CM_ThreadMonitorNodeStopMain(void *argp)
{
    CM_MonitorNodeStopThread *monitor = (CM_MonitorNodeStopThread *)argp;
    thread_name = "MonitorNodeStop";
    monitor->thread.type = THREAD_TYPE_MONITOR;
    write_runlog(LOG, "Starting MonitorNodeStop thread.\n");

    const int checkInterval = 3;
    int checkTrigger = 0;
    int stopNodesKeyNum = 0;
    char ddbValue[DDB_MIN_VALUE_LEN] = {0};
    char ddbKey[MAX_PATH_LEN] = {0};
    int tryTimes = TRY_TIME_GET_STATUSONLINE_FROM_DDB;
    errno_t rc = 0;
    status_t ret = CM_SUCCESS;

    for (;;) {
        if (checkTrigger != checkInterval) {
            checkTrigger++;
            cm_sleep(1);
            continue;
        }

        checkTrigger = 0;

        rc = snprintf_s(ddbKey, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/command/az_stop_nodes_num", pw->pw_name);
        securec_check_intval(rc, (void)rc);

        ret = TryDdbGet(ddbKey, ddbValue, DDB_MIN_VALUE_LEN, tryTimes, DEBUG1);
        if (ret != CM_SUCCESS) {
            write_runlog(DEBUG1, "get az_stop_nodes_num failed, key is %s\n", ddbKey);
            cm_sleep(1);
            continue;
        } else {
            stopNodesKeyNum = (int)strtol(ddbValue, NULL, 10);
            rc = memset_s(ddbValue, DDB_MIN_VALUE_LEN, 0, DDB_MIN_VALUE_LEN);
            securec_check_errno(rc, (void)rc);
        }

        g_stopNodes.clear();

        for (int ii = 0; ii < stopNodesKeyNum; ii++) {
            rc = snprintf_s(ddbKey, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/command/%d/az_stop_nodes", pw->pw_name, ii);
            securec_check_intval(rc, (void)rc);
            ret = TryDdbGet(ddbKey, ddbValue, DDB_MIN_VALUE_LEN, tryTimes);
            if (ret != CM_SUCCESS) {
                write_runlog(ERROR, "get az_stop_nodes failed, key is %s.\n", ddbKey);
            } else {
                GetStopNodes(ddbValue, DDB_MIN_VALUE_LEN);
                rc = memset_s(ddbValue, DDB_MIN_VALUE_LEN, 0, DDB_MIN_VALUE_LEN);
                securec_check_errno(rc, (void)rc);
            }
        }
    }
}

static void DeleteIgnoreNodeToDdb(char *key, uint32 keyLen)
{
    status_t st = DelKeyInDdb(key, keyLen);
    if (st != CM_SUCCESS) {
        write_runlog(ERROR, "%d: ddb delete falied. Key=%s\n", __LINE__, key);
    }
}

static void SetIgnoreNodeToDdb(char *key, uint32 keyLen, char *value, uint32 valueLen)
{
    status_t st = SetKV2Ddb(key, keyLen, value, valueLen, NULL);
    if (st != CM_SUCCESS) {
        write_runlog(ERROR, "%d: ddb set failed. Key=%s, value=%s\n", __LINE__, key, value);
    }
}

static void FindAndSetIgnoreNodeToDdb(const char *blackFile)
{
    char ignoreNodeKey[MAX_PATH_LEN] = {0};
    char ignoreNodeNumKey[MAX_PATH_LEN] = {0};
    char nodeName[CM_NODE_NAME];
    uint32 nodeNamenums = 1;
    char nodeNamenumValue[MAX_PATH_LEN] = {0};

    FILE *fp = fopen(blackFile, "r");
    if (fp == NULL) {
        write_runlog(ERROR, "%d: failed to open file %s\n", __LINE__, blackFile);
        return;
    }
    int rc = memset_s(nodeName, CM_NODE_NAME, 0, CM_NODE_NAME);
    securec_check_errno(rc, (void)fclose(fp));
    while (!feof(fp)) {
        if (fgets(nodeName, CM_NODE_NAME, fp) == NULL) {
            write_runlog(ERROR, "%d: failed to get nodename\n", __LINE__);
            continue;
        }
        (void)trim(nodeName);
        rc = snprintf_s(ignoreNodeKey, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/ignorenode/%u", pw->pw_name, nodeNamenums);
        securec_check_intval(rc, (void)fclose(fp));
        SetIgnoreNodeToDdb(ignoreNodeKey, MAX_PATH_LEN, nodeName, CM_NODE_NAME);
        nodeNamenums++;
    }
    (void)fclose(fp);
    fp = NULL;
    nodeNamenums--;
    rc = snprintf_s(ignoreNodeNumKey, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/ignoreNodeNumKey", pw->pw_name);
    securec_check_intval(rc, (void)rc);
    rc = snprintf_s(nodeNamenumValue, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%u", nodeNamenums);
    securec_check_intval(rc, (void)rc);
    SetIgnoreNodeToDdb(ignoreNodeNumKey, MAX_PATH_LEN, nodeNamenumValue, MAX_PATH_LEN);
}

static void DdbGetIgnoreNode(const char *key, char *value, uint32 valueLen)
{
    DDB_RESULT dbResult = SUCCESS_GET_VALUE;
    status_t st = GetKVAndLogLevel(key, value, valueLen, &dbResult, DEBUG1);
    if (st != CM_SUCCESS) {
        write_runlog(DEBUG1, "get ddb key %s error %d\n", key, dbResult);
    }
}

static bool CheckIgnoreNode()
{
    char ignoreNodeKey[MAX_PATH_LEN] = {0};
    char getIgnoreNodeValue[MAX_PATH_LEN] = {0};
    char ignoreNodeNumKey[MAX_PATH_LEN] = {0};
    char getignoreNodeNumValue[MAX_PATH_LEN] = {0};

    errno_t rc = snprintf_s(ignoreNodeNumKey, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/ignoreNodeNumKey", pw->pw_name);
    securec_check_intval(rc, (void)rc);
    DdbGetIgnoreNode(ignoreNodeNumKey, getignoreNodeNumValue, MAX_PATH_LEN);
    uint32 ignoreNum = (uint32)strtoul(getignoreNodeNumValue, NULL, 0);
    if (ignoreNum == 0) {
        return false;
    }
    for (uint32 i = 0; i < ignoreNum; i++) {
        rc = snprintf_s(ignoreNodeKey, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/ignorenode/%u", pw->pw_name, i + 1);
        securec_check_intval(rc, (void)rc);
        getIgnoreNodeValue[0] = 0;
        DdbGetIgnoreNode(ignoreNodeKey, getIgnoreNodeValue, MAX_PATH_LEN);
        if (strncmp(g_currentNode->nodeName, getIgnoreNodeValue, MAX_PATH_LEN) == 0) {
            return true;
        }
    }
    return false;
}

static void StopIgnoreNode()
{
    int rcs;
    char stopCmd[MAXPGPATH] = {0};

    if (!CheckIgnoreNode()) {
        return;
    }
    write_runlog(LOG, "stop hostname is %s.\n", g_currentNode->nodeName);
    rcs =
        snprintf_s(stopCmd, MAXPGPATH, MAXPGPATH - 1, "cm_ctl stop -n %u -m i > /dev/null 2>&1 &", g_currentNode->node);
    securec_check_intval(rcs, (void)rcs);
    rcs = system(stopCmd);
    if (rcs != 0) {
        write_runlog(ERROR, "cmd execute failed : %s, errno=%d.\n", stopCmd, errno);
    }
    write_runlog(FATAL, "The current node(%u) has been ignored.\n", g_currentNode->node);
    FreeNotifyMsg();
    exit(1);
}

static void RmAllBlackFile(const char *blackFile)
{
    int ret;
    char rmCmd[MAXPGPATH] = {0};
    for (uint32 i = 0; i < g_node_num; i++) {
        /* cmServerLevel used to check if the node has cm_server */
        if (g_node[i].cmServerLevel != 1 || g_node[i].sshCount == 0) {
            continue;
        }

        ret = snprintf_s(rmCmd,
            MAXPGPATH,
            MAXPGPATH - 1,
            "pssh %s -s -H %s \"if [ -f %s ];then rm -f %s;fi\"",
            PSSH_TIMEOUT_OPTION,
            g_node[i].sshChannel[0],
            blackFile,
            blackFile);
        securec_check_intval(ret, (void)ret);
        ret = system(rmCmd);
        if (ret != 0) {
            write_runlog(ERROR, "Remove blackfile fail cmd is: %s, errno=%d.\n", rmCmd, errno);
        }
    }
}

static void DeleteIgnoreNodeFromDdb()
{
    char ignoreNodeNumKey1[MAX_PATH_LEN] = {0};
    char ignoreNodeKey[MAX_PATH_LEN] = {0};
    char getIgnoreNodeValue[MAX_PATH_LEN] = {0};
    char getignoreNodeNumValue[MAX_PATH_LEN] = {0};

    errno_t rc = snprintf_s(ignoreNodeNumKey1, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/ignoreNodeNumKey", pw->pw_name);
    securec_check_intval(rc, (void)rc);
    DdbGetIgnoreNode(ignoreNodeNumKey1, getignoreNodeNumValue, MAX_PATH_LEN);
    uint32 ignoreNum = (uint32)strtoul(getignoreNodeNumValue, NULL, 0);
    if (ignoreNum == 0) {
        return;
    }
    for (uint32 i = 0; i < ignoreNum; i++) {
        rc = snprintf_s(ignoreNodeKey, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/ignorenode/%u", pw->pw_name, i + 1);
        securec_check_intval(rc, (void)rc);
        getIgnoreNodeValue[0] = 0;
        DdbGetIgnoreNode(ignoreNodeKey, getIgnoreNodeValue, MAX_PATH_LEN);
        if (strncmp(g_currentNode->nodeName, getIgnoreNodeValue, MAX_PATH_LEN) == 0) {
            return;
        }
    }
    for (uint32 i = 0; i < ignoreNum; i++) {
        rc = snprintf_s(ignoreNodeKey, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/ignorenode/%u", pw->pw_name, i + 1);
        securec_check_intval(rc, (void)rc);
        DeleteIgnoreNodeToDdb(ignoreNodeKey, MAX_PATH_LEN);
    }
    DeleteIgnoreNodeToDdb(ignoreNodeNumKey1, MAX_PATH_LEN);
}

static void CheckIgnoreFile(struct stat *beforeStat, const char *blackFile, bool *firstGetFile)
{
    struct stat afterStat = {0};
    if (stat(blackFile, &afterStat) != 0) {
        DeleteIgnoreNodeFromDdb();
        return;
    }
    if ((*firstGetFile) && stat(blackFile, beforeStat) == 0) {
        FindAndSetIgnoreNodeToDdb(blackFile);
        *firstGetFile = false;
    } else if (stat(blackFile, &afterStat) == 0 && (beforeStat->st_mtim.tv_sec != afterStat.st_mtim.tv_sec ||
                                                       beforeStat->st_mtim.tv_nsec != afterStat.st_mtim.tv_nsec)) {
        int ret;
        FindAndSetIgnoreNodeToDdb(blackFile);
        ret = memcpy_s(beforeStat, sizeof(afterStat), &afterStat, sizeof(afterStat));
        securec_check_errno(ret, (void)ret);
    }
}

static void CheckOneIP(char *ip, uint32 ipLen, bool *isIncluster)
{
    int ret;
    char stopCmd[MAXPGPATH] = {0};

    for (uint32 i = 0; i < g_node_num; i++) {
        if (strncmp(ip, g_node[i].nodeName, CM_IP_LENGTH) == 0) {
            *isIncluster = true;

            if (StopCheckNode(i) == -1) {
                write_runlog(LOG, "stop hostname is %s.\n", g_node[i].nodeName);
                ret = snprintf_s(
                    stopCmd, MAXPGPATH, MAXPGPATH - 1, "cm_ctl stop -n %u -m i > /dev/null 2>&1 &", g_node[i].node);
                securec_check_intval(ret, (void)ret);
                ret = system(stopCmd);
                if (ret != 0) {
                    write_runlog(ERROR, "cmd execute failed : %s, errno=%d.\n", stopCmd, errno);
                }
                ret = memset_s(ip, ipLen, 0, ipLen);
                securec_check_errno(ret, (void)ret);
            }
            break;
        }
    }
}

static void CheckBlackFile(const char* blackFile)
{
    char ip[CM_IP_LENGTH];
    int ret = memset_s(ip, CM_IP_LENGTH, 0, CM_IP_LENGTH);
    securec_check_errno(ret, (void)ret);

    FILE *fp = fopen(blackFile, "r");
    if (fp != NULL) {
        bool isIncluster = false;
        while (!feof(fp)) {
            if (fgets(ip, CM_NODE_NAME, fp) != NULL) {
                (void)trim(ip);
                CheckOneIP(ip, CM_IP_LENGTH, &isIncluster);
            }
        }
        (void)fclose(fp);
        if (!isIncluster) {
            RmAllBlackFile(blackFile);
        }
    }
}

static void CheckAgentFile(const char* execPath)
{
    int ret;
    char upgradeStopFile[MAX_PATH_LEN] = {0};
    char stopCmd[MAXPGPATH] = {0};
    struct stat stopStatBuf = {0};

    // check agent version file
    for (uint32 i = 0; i < g_node_num; i++) {
        ret = snprintf_s(
            upgradeStopFile, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/check_version_result-%u", execPath, i);
        securec_check_intval(ret, (void)ret);
        if (stat(upgradeStopFile, &stopStatBuf) == 0) {
            ret = snprintf_s(stopCmd,
                MAXPGPATH,
                MAXPGPATH - 1,
                "cm_ctl stop -n %u -m i > /dev/null 2>&1 & rm %s;",
                i,
                upgradeStopFile);
            securec_check_intval(ret, (void)ret);
            ret = system(stopCmd);
            if (ret != 0) {
                write_runlog(ERROR, "cmd execute failed : %s, errno=%d.\n", stopCmd, errno);
            } else {
                write_runlog(LOG, "cmd execute successed : %s.\n", stopCmd);
            }
            char rmCmd[MAXPGPATH] = {0};
            ret = snprintf_s(rmCmd, MAXPGPATH, MAXPGPATH - 1, "rm %s &", upgradeStopFile);
            securec_check_intval(ret, (void)ret);
            ret = system(rmCmd);
            if (ret != 0) {
                write_runlog(ERROR, "cmd execute failed : %s, errno=%d.\n", rmCmd, errno);
            } else {
                write_runlog(LOG, "cmd execute successed : %s.\n", stopCmd);
            }
        }
    }
}

static void DoCheckBlackList(const char* execPath, const char* blackFile)
{
    StopIgnoreNode();
    CheckBlackFile(blackFile);
    CheckAgentFile(execPath);
}

void *CheckBlackList(void *arg)
{
    int ret;
    char pghostPath[MAXPGPATH] = {0};
    char execPath[MAXPGPATH] = {0};
    char blackFile[MAX_PATH_LEN] = {0};
    bool firstGetIgnore = true;
    struct stat beforeStat = {0};

    ret = cmserver_getenv("PGHOST", pghostPath, sizeof(pghostPath), ERROR);
    if (ret != EOK) {
        write_runlog(ERROR, "Get PGHOST failed, please check.\n");
        return NULL;
    }
    check_input_for_security(pghostPath);
    if (GetHomePath(execPath, sizeof(execPath)) != 0) {
        return NULL;
    }

    ret = snprintf_s(blackFile, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/ignore_node_record", pghostPath);
    securec_check_intval(ret, (void)ret);
    check_input_for_security(blackFile);
    canonicalize_path(blackFile);
    for (;;) {
        if (got_stop == 1) {
            write_runlog(LOG, "receive exit request in CheckBlackList.\n");
            break;
        }
        CheckIgnoreFile(&beforeStat, blackFile, &firstGetIgnore);
        if (g_HA_status->local_role == CM_SERVER_PRIMARY) {
            DoCheckBlackList(execPath, blackFile);
        }
        cm_sleep(CHECK_SLEEP_INTERVAL);
    }
    return NULL;
}

#ifdef ENABLE_MULTIPLE_NODES
static int GetGtmMode()
{
    if (!IsNeedSyncDdb()) {
        return -1;
    }
    char ddbKey[MAX_PATH_LEN] = {0};
    char ddbValue[MAX_PATH_LEN] = {0};
    int tryTimes = TRY_TIME_GET_STATUSONLINE_FROM_DDB;

    int erc = snprintf_s(ddbKey, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/command/gtm_mode", pw->pw_name);
    securec_check_intval(erc, (void)erc);
    status_t getResult = TryDdbGet(ddbKey, ddbValue, MAX_PATH_LEN, tryTimes);
    if (getResult != CM_SUCCESS) {
        write_runlog(WARNING, "get gtm_mode failed, key is %s.\n", ddbKey);
        return -1;
    } else {
        write_runlog(LOG, "get gtm_mode successfully, values is %s.\n", ddbValue);
        g_gtm_free_mode = (strcmp(ddbValue, "on") == 0);
    }
    return 0;
}

void *CheckGtmModMain(void *arg)
{
    uint32 sleepInterval = 1;
    thread_name = "CheckGtmMod";
    write_runlog(LOG, "Starting check gtm mod thread.\n");
    for (;;) {
        if (got_stop == 1) {
            write_runlog(LOG, "receive exit request in CheckGtmModMain.\n");
            cm_sleep(sleepInterval);
            continue;
        }
        /* gtm_mode can not change after cluster install in actual situation, this guc param will set in install guc */
        if (GetGtmMode() == 0) {
            write_runlog(LOG, "success get gtm mod (%d), and CheckGtmModMain will exit.\n", (int)g_gtm_free_mode);
            break;
        }
        cm_sleep(sleepInterval);
    }
    return NULL;
}
#endif

