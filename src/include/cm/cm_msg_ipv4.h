/*
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
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
 * cm_msg_ipv4.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_msg_ipv4.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CM_MSG_IPV4_H
#define CM_MSG_IPV4_H

#include "cm_msg.h"

typedef struct cm_to_agent_lock2_ipv4_st {
    int msg_type;
    uint32 node;
    uint32 instanceId;
    char disconn_host[HOST_LENGTH];
    uint32 disconn_port;
} cm_to_agent_lock2_ipv4;

typedef struct cm_local_replconninfo_ipv4_st {
    int local_role;
    int static_connections;
    int db_state;
    XLogRecPtr last_flush_lsn;
    int buildReason;
    uint32 term;
    uint32 disconn_mode;
    char disconn_host[HOST_LENGTH];
    uint32 disconn_port;
    char local_host[HOST_LENGTH];
    uint32 local_port;
    bool redo_finished;
} cm_local_replconninfo_ipv4;

typedef struct agent_to_cm_datanode_status_report_ipv4_st {
    int msg_type;
    uint32 node;
    uint32 instanceId;
    int instanceType;
    int connectStatus;
    int processStatus;
    cm_local_replconninfo_ipv4 local_status;
    BuildState build_info;
    cm_sender_replconninfo sender_status[CM_MAX_SENDER_NUM];
    cm_receiver_replconninfo receive_status;
    RedoStatsData parallel_redo_status;
    cm_redo_stats local_redo_stats;
    int dn_restart_counts;
    int phony_dead_times;
    int dn_restart_counts_in_hour;
    int dnVipStatus;
} agent_to_cm_datanode_status_report_ipv4;

typedef struct DnStatus_ipv4_t {
    CM_MessageType barrierMsgType;
    agent_to_cm_datanode_status_report_ipv4 reportMsg;
    union {
        AgentToCmBarrierStatusReport barrierMsg;
        Agent2CmBarrierStatusReport barrierMsgNew;
    };
    AgentCmDnLocalPeer lpInfo;
    AgentToCmDiskUsageStatusReport diskUsageMsg;
    CmaDnFloatIpInfo floatIpInfo;
} DnStatus_ipv4;

typedef struct datanode_status_info_ipv4_st {
    pthread_rwlock_t lk_lock;
    DnStatus_ipv4 dnStatus;
} datanode_status_info_ipv4;

typedef struct CmDnReportStatusMsgT_ipv4 {
    cm_local_replconninfo_ipv4 local_status;
    int sender_count;
    BuildState build_info;
    cm_sender_replconninfo sender_status[CM_MAX_SENDER_NUM];
    cm_receiver_replconninfo receive_status;
    RedoStatsData parallel_redo_status;
    cm_redo_stats local_redo_stats;
    synchronous_standby_mode sync_standby_mode;
    int send_gs_guc_time;
    int dn_restart_counts;
    bool arbitrateFlag;
    int failoverStep;
    int failoverTimeout;
    int phony_dead_times;
    int phony_dead_interval;
    int dn_restart_counts_in_hour;
    bool is_finish_redo_cmd_sent;
    uint64 ckpt_redo_point;
    char barrierID[BARRIERLEN];
    char query_barrierId[BARRIERLEN];
    uint64 barrierLSN;
    uint64 archive_LSN;
    uint64 flush_LSN;
    DatanodeSyncList dnSyncList;
    int32 syncDone;
    uint32 arbiTime;
    uint32 sendFailoverTimes;
    bool is_barrier_exist;
    cmTime_t printBegin; // print synclist time
    DatanodelocalPeer dnLp;
} CmDnReportStatusMsg_ipv4;

// need to keep consist with cm_to_ctl_instance_datanode_status
typedef struct cm_instance_datanode_report_status_ipv4_st {
    cm_local_replconninfo_ipv4 local_status;
    int sender_count;
    BuildState build_info;
    cm_sender_replconninfo sender_status[CM_MAX_SENDER_NUM];
    cm_receiver_replconninfo receive_status;
    RedoStatsData parallel_redo_status;
    cm_redo_stats local_redo_stats;
    synchronous_standby_mode sync_standby_mode;
    int send_gs_guc_time;
    int dn_restart_counts;
    bool arbitrateFlag;
    int failoverStep;
    int failoverTimeout;
    int phony_dead_times;
    int phony_dead_interval;
    int dn_restart_counts_in_hour;
    int dnVipStatus;
    bool is_finish_redo_cmd_sent;
    uint64 ckpt_redo_point;
    char barrierID[BARRIERLEN];
    char query_barrierId[BARRIERLEN];
    uint64 barrierLSN;
    uint64 archive_LSN;
    uint64 flush_LSN;
    DatanodeSyncList dnSyncList;
    int32 syncDone;
    uint32 arbiTime;
    uint32 sendFailoverTimes;
    bool is_barrier_exist;
    cmTime_t printBegin; // print synclist time
    DatanodelocalPeer dnLp;
    DnFloatIpInfo floatIp;
} cm_instance_datanode_report_status_ipv4;

typedef struct cm_to_cm_report_sync_ipv4_st {
    int msg_type;
    uint32 node[CM_PRIMARY_STANDBY_NUM];
    uint32 instanceId[CM_PRIMARY_STANDBY_NUM];
    int instance_type[CM_PRIMARY_STANDBY_NUM];
    cm_instance_command_status command_member[CM_PRIMARY_STANDBY_NUM];
    cm_instance_datanode_report_status_ipv4 data_node_member[CM_PRIMARY_STANDBY_NUM];
    cm_instance_gtm_report_status gtm_member[CM_PRIMARY_STANDBY_NUM];
    cm_instance_coordinate_report_status coordinatemember;
    cm_instance_arbitrate_status arbitrate_status_member[CM_PRIMARY_STANDBY_NUM];
} cm_to_cm_report_sync_ipv4;

typedef struct cm_to_ctl_get_datanode_relation_ack_ipv4_st {
    int command_result;
    int member_index;
    cm_instance_role_status instanceMember[CM_PRIMARY_STANDBY_MAX_NUM];
    cm_instance_gtm_report_status gtm_member[CM_PRIMARY_STANDBY_NUM];
    CmDnReportStatusMsg_ipv4 data_node_member[CM_PRIMARY_STANDBY_MAX_NUM];
} cm_to_ctl_get_datanode_relation_ack_ipv4;

// need to keep consist with the struct cm_instance_datanode_report_status
typedef struct cm_to_ctl_instance_datanode_status_ipv4_st {
    cm_local_replconninfo_ipv4 local_status;
    int sender_count;
    BuildState build_info;
    cm_sender_replconninfo sender_status[CM_MAX_SENDER_NUM];
    cm_receiver_replconninfo receive_status;
    RedoStatsData parallel_redo_status;
    cm_redo_stats local_redo_stats;
    synchronous_standby_mode sync_standby_mode;
    int send_gs_guc_time;
} cm_to_ctl_instance_datanode_status_ipv4;

typedef struct cm_to_ctl_instance_status_ipv4_st {
    int msg_type;
    uint32 node;
    uint32 instanceId;
    int instance_type;
    int member_index;
    int is_central;
    int fenced_UDF_status;
    cm_to_ctl_instance_datanode_status_ipv4 data_node_member;
    cm_to_ctl_instance_gtm_status gtm_member;
    cm_to_ctl_instance_coordinate_status coordinatemember;
} cm_to_ctl_instance_status_ipv4;

#endif
