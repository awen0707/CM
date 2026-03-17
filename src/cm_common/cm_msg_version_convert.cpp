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
 *cm_msg_version_convert.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_common/cm_msg_version_convert.cpp
 *
 * -------------------------------------------------------------------------
 */

#include "cm_msg_version_convert.h"

#ifdef __cplusplus
extern "C" {
#endif

void CmToAgentLock2V1ToV2(const cm_to_agent_lock2_ipv4 *v1, cm_to_agent_lock2 *v2)
{
    v2->instanceId = v1->instanceId;
    v2->msg_type = v1->msg_type;
    v2->node = v1->node;
    errno_t rc = snprintf_s(v2->disconn_host,
        CM_IP_LENGTH, (int)strlen(v1->disconn_host),
        "%s",
        v1->disconn_host);
    securec_check_intval(rc, (void)rc);
    v2->disconn_port = v1->disconn_port;
}

void CmToAgentLock2V2ToV1(const cm_to_agent_lock2 *v2, cm_to_agent_lock2_ipv4 *v1)
{
    v1->instanceId = v2->instanceId;
    v1->msg_type = v2->msg_type;
    v1->node = v2->node;
    errno_t rc = strncpy_s(v1->disconn_host, HOST_LENGTH, v2->disconn_host, HOST_LENGTH - 1);
    securec_check_errno(rc, (void)rc);
    v1->disconn_port = v2->disconn_port;
}

void CmLocalReplconninfoV1ToV2(const cm_local_replconninfo_ipv4 *v1, cm_local_replconninfo *v2)
{
    v2->buildReason = v1->buildReason;
    v2->db_state = v1->db_state;
    errno_t rc = snprintf_s(v2->disconn_host, CM_IP_LENGTH, (int)strlen(v1->disconn_host), "%s", v1->disconn_host);
    securec_check_intval(rc, (void)rc);
    v2->disconn_mode = v1->disconn_mode;
    v2->disconn_port = v1->disconn_port;
    v2->last_flush_lsn = v1->last_flush_lsn;
    rc = snprintf_s(v2->local_host, CM_IP_LENGTH, (int)strlen(v1->local_host), "%s", v1->local_host);
    securec_check_intval(rc, (void)rc);
    v2->local_port = v1->local_port;
    v2->local_role = v1->local_role;
    v2->redo_finished = v1->redo_finished;
    v2->static_connections = v1->static_connections;
    v2->term = v1->term;
}

void CmLocalReplconninfoV2ToV1(const cm_local_replconninfo *v2, cm_local_replconninfo_ipv4 *v1)
{
    v1->buildReason = v2->buildReason;
    v1->db_state = v2->db_state;
    errno_t rc = strncpy_s(v1->disconn_host, HOST_LENGTH, v2->disconn_host, HOST_LENGTH - 1);
    securec_check_errno(rc, (void)rc);
    v1->disconn_mode = v2->disconn_mode;
    v1->disconn_port = v2->disconn_port;
    v1->last_flush_lsn = v2->last_flush_lsn;
    rc = strncpy_s(v1->local_host, HOST_LENGTH, v2->local_host, HOST_LENGTH - 1);
    securec_check_errno(rc, (void)rc);
    v1->local_port = v2->local_port;
    v1->local_role = v2->local_role;
    v1->redo_finished = v2->redo_finished;
    v1->static_connections = v2->static_connections;
    v1->term = v2->term;
}

void AgentToCmDatanodeStatusReportV1ToV2(const agent_to_cm_datanode_status_report_ipv4 *v1,
    agent_to_cm_datanode_status_report *v2)
{
    errno_t rc = memcpy_s((void *)&(v2->build_info),
        sizeof(BuildState),
        (void *const)&(v1->build_info),
        sizeof(BuildState));
    securec_check_intval(rc, (void)rc);
    v2->connectStatus = v1->connectStatus;
    v2->dn_restart_counts = v1->dn_restart_counts;
    v2->dn_restart_counts_in_hour = v1->dn_restart_counts_in_hour;
    v2->dnVipStatus = v1->dnVipStatus;
    v2->instanceId = v1->instanceId;
    v2->instanceType = v1->instanceType;
    rc = memcpy_s((void *)&(v2->local_redo_stats),
        sizeof(cm_redo_stats),
        (void *const)&(v1->local_redo_stats),
        sizeof(cm_redo_stats));
    securec_check_intval(rc, (void)rc);
    CmLocalReplconninfoV1ToV2(&v1->local_status, &v2->local_status);
    v2->msg_type = v1->msg_type;
    v2->node = v1->node;
    rc = memcpy_s((void *)&(v2->parallel_redo_status),
        sizeof(RedoStatsData),
        (void *const)&(v1->parallel_redo_status),
        sizeof(RedoStatsData));
    securec_check_intval(rc, (void)rc);
    v2->phony_dead_times = v1->phony_dead_times;
    v2->processStatus = v1->processStatus;
    rc = memcpy_s((void *)&(v2->receive_status),
        sizeof(cm_receiver_replconninfo),
        (void *const)&(v1->receive_status),
        sizeof(cm_receiver_replconninfo));
    securec_check_intval(rc, (void)rc);
    rc = memcpy_s((void *)&(v2->sender_status[0]),
        CM_MAX_SENDER_NUM * sizeof(cm_sender_replconninfo),
        (void *const)v1->sender_status,
        CM_MAX_SENDER_NUM * sizeof(cm_sender_replconninfo));
    securec_check_intval(rc, (void)rc);
}

void AgentToCmDatanodeStatusReportV2ToV1(const agent_to_cm_datanode_status_report *v2,
    agent_to_cm_datanode_status_report_ipv4 *v1)
{
    errno_t rc = memcpy_s((void *)&(v1->build_info),
        sizeof(BuildState),
        (void *const)&(v2->build_info),
        sizeof(BuildState));
    securec_check_intval(rc, (void)rc);
    v1->connectStatus = v2->connectStatus;
    v1->dn_restart_counts = v2->dn_restart_counts;
    v1->dn_restart_counts_in_hour = v2->dn_restart_counts_in_hour;
    v1->dnVipStatus = v2->dnVipStatus;
    v1->instanceId = v2->instanceId;
    v1->instanceType = v2->instanceType;
    rc = memcpy_s((void *)&(v1->local_redo_stats),
        sizeof(cm_redo_stats),
        (void *const)&(v2->local_redo_stats),
        sizeof(cm_redo_stats));
    securec_check_intval(rc, (void)rc);
    CmLocalReplconninfoV2ToV1(&v2->local_status, &v1->local_status);
    v1->msg_type = v2->msg_type;
    v1->node = v2->node;
    rc = memcpy_s((void *)&(v1->parallel_redo_status),
        sizeof(RedoStatsData),
        (void *const)&(v2->parallel_redo_status),
        sizeof(RedoStatsData));
    securec_check_intval(rc, (void)rc);
    v1->phony_dead_times = v2->phony_dead_times;
    v1->processStatus = v2->processStatus;
    rc = memcpy_s((void *)&(v1->receive_status),
        sizeof(cm_receiver_replconninfo),
        (void *const)&(v2->receive_status),
        sizeof(cm_receiver_replconninfo));
    securec_check_intval(rc, (void)rc);
    rc = memcpy_s((void *)&(v1->sender_status[0]),
        CM_MAX_SENDER_NUM * sizeof(cm_sender_replconninfo),
        (void *const)v2->sender_status,
        CM_MAX_SENDER_NUM * sizeof(cm_sender_replconninfo));
    securec_check_intval(rc, (void)rc);
}

void CmDnReportStatusMsgV1ToV2(const CmDnReportStatusMsg_ipv4 *v1, CmDnReportStatusMsg *v2)
{
    v2->arbiTime = v1->arbiTime;
    v2->arbitrateFlag = v1->arbitrateFlag;
    v2->archive_LSN = v1->archive_LSN;
    errno_t rc = snprintf_s(v2->barrierID, BARRIERLEN, BARRIERLEN-1, "%s", v1->barrierID);
    securec_check_intval(rc, (void)rc);
    v2->barrierLSN = v1->barrierLSN;
    rc = memcpy_s((void *)&(v2->build_info), sizeof(BuildState), (void *const)&(v1->build_info), sizeof(BuildState));
    securec_check_intval(rc, (void)rc);
    v2->ckpt_redo_point = v1->ckpt_redo_point;
    v2->dn_restart_counts = v1->dn_restart_counts;
    v2->dn_restart_counts_in_hour = v1->dn_restart_counts_in_hour;
    rc = memcpy_s((void *)&(v2->dnLp), sizeof(DatanodelocalPeer), (void *const)&(v1->dnLp), sizeof(DatanodelocalPeer));
    securec_check_intval(rc, (void)rc);
    rc = memcpy_s((void *)&(v2->dnSyncList), sizeof(DatanodeSyncList), (void *const)&(v1->dnSyncList),
        sizeof(DatanodeSyncList));
    securec_check_intval(rc, (void)rc);
    v2->failoverStep = v1->failoverStep;
    v2->failoverTimeout = v1->failoverTimeout;
    v2->flush_LSN = v1->flush_LSN;
    v2->is_barrier_exist = v1->is_barrier_exist;
    v2->is_finish_redo_cmd_sent = v1->is_finish_redo_cmd_sent;
    rc = memcpy_s((void *)&(v2->local_redo_stats), sizeof(cm_redo_stats), (void *const)&(v1->local_redo_stats),
        sizeof(cm_redo_stats));
    securec_check_intval(rc, (void)rc);
    CmLocalReplconninfoV1ToV2(&v1->local_status, &v2->local_status);
    rc = memcpy_s((void *)&(v2->parallel_redo_status), sizeof(RedoStatsData), (void *const)&(v1->parallel_redo_status),
        sizeof(RedoStatsData));
    securec_check_intval(rc, (void)rc);
    v2->phony_dead_interval = v1->phony_dead_interval;
    v2->phony_dead_times = v1->phony_dead_times;
    v2->printBegin = v1->printBegin;
    rc = memcpy_s((void *)&(v2->printBegin), sizeof(cmTime_t), (void *const)&(v1->printBegin), sizeof(cmTime_t));
    securec_check_intval(rc, (void)rc);
    rc = snprintf_s(v2->query_barrierId, BARRIERLEN, BARRIERLEN-1, "%s", v1->query_barrierId);
    securec_check_intval(rc, (void)rc);
    rc = memcpy_s((void *)&(v2->receive_status), sizeof(cm_receiver_replconninfo), (void *const)&(v1->receive_status),
        sizeof(cm_receiver_replconninfo));
    securec_check_intval(rc, (void)rc);
    v2->send_gs_guc_time = v1->send_gs_guc_time;
    v2->sender_count = v1->sender_count;
    rc = memcpy_s((void *)&(v2->sender_status[0]), CM_MAX_SENDER_NUM * sizeof(cm_sender_replconninfo),
        (void *const)v1->sender_status, CM_MAX_SENDER_NUM * sizeof(cm_sender_replconninfo));
    securec_check_intval(rc, (void)rc);
    v2->sendFailoverTimes = v1->sendFailoverTimes;
    v2->sync_standby_mode = v1->sync_standby_mode;
    v2->syncDone = v1->syncDone;
}

void CmDnReportStatusMsgV2ToV1(const CmDnReportStatusMsg *v2, CmDnReportStatusMsg_ipv4 *v1)
{
    v1->arbiTime = v2->arbiTime;
    v1->arbitrateFlag = v2->arbitrateFlag;
    v1->archive_LSN = v2->archive_LSN;
    errno_t rc = snprintf_s(v1->barrierID, BARRIERLEN, BARRIERLEN-1, "%s", v2->barrierID);
    securec_check_intval(rc, (void)rc);
    v1->barrierLSN = v2->barrierLSN;
    rc = memcpy_s((void *)&(v1->build_info), sizeof(BuildState), (void *const)&(v2->build_info), sizeof(BuildState));
    securec_check_intval(rc, (void)rc);
    v1->ckpt_redo_point = v2->ckpt_redo_point;
    v1->dn_restart_counts = v2->dn_restart_counts;
    v1->dn_restart_counts_in_hour = v2->dn_restart_counts_in_hour;
    rc = memcpy_s((void *)&(v1->dnLp), sizeof(DatanodelocalPeer), (void *const)&(v2->dnLp), sizeof(DatanodelocalPeer));
    securec_check_intval(rc, (void)rc);
    rc = memcpy_s((void *)&(v1->dnSyncList), sizeof(DatanodeSyncList), (void *const)&(v2->dnSyncList),
        sizeof(DatanodeSyncList));
    securec_check_intval(rc, (void)rc);
    v1->failoverStep = v2->failoverStep;
    v1->failoverTimeout = v2->failoverTimeout;
    v1->flush_LSN = v2->flush_LSN;
    v1->is_barrier_exist = v2->is_barrier_exist;
    v1->is_finish_redo_cmd_sent = v2->is_finish_redo_cmd_sent;
    rc = memcpy_s((void *)&(v1->local_redo_stats), sizeof(cm_redo_stats), (void *const)&(v2->local_redo_stats),
        sizeof(cm_redo_stats));
    securec_check_intval(rc, (void)rc);
    CmLocalReplconninfoV2ToV1(&v2->local_status, &v1->local_status);
    rc = memcpy_s((void *)&(v1->parallel_redo_status), sizeof(RedoStatsData), (void *const)&(v2->parallel_redo_status),
        sizeof(RedoStatsData));
    securec_check_intval(rc, (void)rc);
    v1->phony_dead_interval = v2->phony_dead_interval;
    v1->phony_dead_times = v2->phony_dead_times;
    v1->printBegin = v2->printBegin;
    rc = memcpy_s((void *)&(v1->printBegin), sizeof(cmTime_t), (void *const)&(v2->printBegin), sizeof(cmTime_t));
    securec_check_intval(rc, (void)rc);
    rc = snprintf_s(v1->query_barrierId, BARRIERLEN, BARRIERLEN-1, "%s", v2->query_barrierId);
    securec_check_intval(rc, (void)rc);
    rc = memcpy_s((void *)&(v1->receive_status), sizeof(cm_receiver_replconninfo), (void *const)&(v2->receive_status),
        sizeof(cm_receiver_replconninfo));
    securec_check_intval(rc, (void)rc);
    v1->send_gs_guc_time = v2->send_gs_guc_time;
    v1->sender_count = v2->sender_count;
    rc = memcpy_s((void *)&(v1->sender_status[0]), CM_MAX_SENDER_NUM * sizeof(cm_sender_replconninfo),
        (void *const)v2->sender_status, CM_MAX_SENDER_NUM * sizeof(cm_sender_replconninfo));
    securec_check_intval(rc, (void)rc);
    v1->sendFailoverTimes = v2->sendFailoverTimes;
    v1->sync_standby_mode = v2->sync_standby_mode;
    v1->syncDone = v2->syncDone;
}

void CmToCtlGetDatanodeRelationAckV1ToV2(const cm_to_ctl_get_datanode_relation_ack_ipv4 *v1,
    cm_to_ctl_get_datanode_relation_ack *v2)
{
    v2->command_result = v1->command_result;
    for (uint32 i = 0; i < CM_PRIMARY_STANDBY_MAX_NUM; ++i) {
        CmDnReportStatusMsgV1ToV2(&v1->data_node_member[i], &v2->data_node_member[i]);
    }
    errno_t rc = memcpy_s((void *)&(v2->gtm_member[0]),
        CM_PRIMARY_STANDBY_NUM * sizeof(cm_instance_gtm_report_status),
        (void *const)v1->gtm_member,
        CM_PRIMARY_STANDBY_NUM * sizeof(cm_instance_gtm_report_status));
    securec_check_intval(rc, (void)rc);
    rc = memcpy_s((void *)&(v2->instanceMember[0]),
        CM_PRIMARY_STANDBY_MAX_NUM * sizeof(CM_PRIMARY_STANDBY_MAX_NUM),
        (void *const)v1->instanceMember,
        CM_PRIMARY_STANDBY_MAX_NUM * sizeof(cm_instance_role_status));
    securec_check_intval(rc, (void)rc);
    v2->member_index = v1->member_index;
}

void CmToCtlGetDatanodeRelationAckV2ToV1(const cm_to_ctl_get_datanode_relation_ack *v2,
    cm_to_ctl_get_datanode_relation_ack_ipv4 *v1)
{
    v1->command_result = v2->command_result;
    for (uint32 i = 0; i < CM_PRIMARY_STANDBY_MAX_NUM; ++i) {
        CmDnReportStatusMsgV2ToV1(&v2->data_node_member[i], &v1->data_node_member[i]);
    }
    errno_t rc = memcpy_s((void *)&(v1->gtm_member[0]),
        CM_PRIMARY_STANDBY_NUM * sizeof(cm_instance_gtm_report_status),
        (void *const)v2->gtm_member,
        CM_PRIMARY_STANDBY_NUM * sizeof(cm_instance_gtm_report_status));
    securec_check_intval(rc, (void)rc);
    rc = memcpy_s((void *)&(v1->instanceMember[0]),
        CM_PRIMARY_STANDBY_MAX_NUM * sizeof(CM_PRIMARY_STANDBY_MAX_NUM),
        (void *const)v2->instanceMember,
        CM_PRIMARY_STANDBY_MAX_NUM * sizeof(cm_instance_role_status));
    securec_check_intval(rc, (void)rc);
    v1->member_index = v2->member_index;
}

void CmToCtlInstanceDatanodeStatusV1ToV2(const cm_to_ctl_instance_datanode_status_ipv4 *v1,
    cm_to_ctl_instance_datanode_status *v2)
{
    errno_t rc = memcpy_s((void *)&(v2->build_info),
        sizeof(BuildState),
        (void *const)&(v1->build_info),
        sizeof(BuildState));
    securec_check_intval(rc, (void)rc);
    rc = memcpy_s((void *)&(v2->local_redo_stats),
        sizeof(cm_redo_stats),
        (void *const)&(v1->local_redo_stats),
        sizeof(cm_redo_stats));
    securec_check_intval(rc, (void)rc);
    CmLocalReplconninfoV1ToV2(&v1->local_status, &v2->local_status);
    rc = memcpy_s((void *)&(v2->parallel_redo_status),
        sizeof(RedoStatsData),
        (void *const)&(v1->parallel_redo_status),
        sizeof(RedoStatsData));
    securec_check_intval(rc, (void)rc);
    rc = memcpy_s((void *)&(v2->receive_status),
        sizeof(cm_receiver_replconninfo),
        (void *const)&(v1->receive_status),
        sizeof(cm_receiver_replconninfo));
    securec_check_intval(rc, (void)rc);
    v2->send_gs_guc_time = v1->send_gs_guc_time;
    v2->sender_count = v1->sender_count;
    rc = memcpy_s((void *)&(v2->sender_status[0]),
        CM_MAX_SENDER_NUM * sizeof(cm_sender_replconninfo),
        (void *const)v1->sender_status,
        CM_MAX_SENDER_NUM * sizeof(cm_sender_replconninfo));
    securec_check_intval(rc, (void)rc);
    v2->sync_standby_mode = v1->sync_standby_mode;
}

void CmToCtlInstanceDatanodeStatusV2ToV1(const cm_to_ctl_instance_datanode_status *v2,
    cm_to_ctl_instance_datanode_status_ipv4 *v1)
{
    errno_t rc = memcpy_s((void *)&(v1->build_info),
        sizeof(BuildState),
        (void *const)&(v2->build_info),
        sizeof(BuildState));
    securec_check_intval(rc, (void)rc);
    rc = memcpy_s((void *)&(v1->local_redo_stats),
        sizeof(cm_redo_stats),
        (void *const)&(v2->local_redo_stats),
        sizeof(cm_redo_stats));
    securec_check_intval(rc, (void)rc);
    CmLocalReplconninfoV2ToV1(&v2->local_status, &v1->local_status);
    rc = memcpy_s((void *)&(v1->parallel_redo_status),
        sizeof(RedoStatsData),
        (void *const)&(v2->parallel_redo_status),
        sizeof(RedoStatsData));
    securec_check_intval(rc, (void)rc);
    rc = memcpy_s((void *)&(v1->receive_status),
        sizeof(cm_receiver_replconninfo),
        (void *const)&(v2->receive_status),
        sizeof(cm_receiver_replconninfo));
    securec_check_intval(rc, (void)rc);
    v1->send_gs_guc_time = v2->send_gs_guc_time;
    v1->sender_count = v2->sender_count;
    rc = memcpy_s((void *)&(v1->sender_status[0]),
        CM_MAX_SENDER_NUM * sizeof(cm_sender_replconninfo),
        (void *const)v2->sender_status,
        CM_MAX_SENDER_NUM * sizeof(cm_sender_replconninfo));
    securec_check_intval(rc, (void)rc);
    v1->sync_standby_mode = v2->sync_standby_mode;
}

void CmToCtlInstanceStatusV1ToV2(const cm_to_ctl_instance_status_ipv4 *v1, cm_to_ctl_instance_status *v2)
{
    v2->coordinatemember = v1->coordinatemember;
    errno_t rc = memcpy_s((void *)&(v2->coordinatemember),
        sizeof(cm_to_ctl_instance_coordinate_status),
        (void *const)&(v1->coordinatemember),
        sizeof(cm_to_ctl_instance_coordinate_status));
    securec_check_intval(rc, (void)rc);
    CmToCtlInstanceDatanodeStatusV1ToV2(&v1->data_node_member, &v2->data_node_member);
    v2->fenced_UDF_status = v1->fenced_UDF_status;
    rc = memcpy_s((void *)&(v2->gtm_member),
        sizeof(cm_to_ctl_instance_gtm_status),
        (void *const)&(v1->gtm_member),
        sizeof(cm_to_ctl_instance_gtm_status));
    securec_check_intval(rc, (void)rc);
    v2->instance_type = v1->instance_type;
    v2->instanceId = v1->instanceId;
    v2->is_central = v1->is_central;
    v2->member_index = v1->member_index;
    v2->msg_type = v1->msg_type;
    v2->node = v1->node;
}

void CmToCtlInstanceStatusV2ToV1(const cm_to_ctl_instance_status *v2, cm_to_ctl_instance_status_ipv4 *v1)
{
    v1->coordinatemember = v2->coordinatemember;
    errno_t rc = memcpy_s((void *)&(v1->coordinatemember),
        sizeof(cm_to_ctl_instance_coordinate_status),
        (void *const)&(v2->coordinatemember),
        sizeof(cm_to_ctl_instance_coordinate_status));
    securec_check_intval(rc, (void)rc);
    CmToCtlInstanceDatanodeStatusV2ToV1(&v2->data_node_member, &v1->data_node_member);
    v1->fenced_UDF_status = v2->fenced_UDF_status;
    rc = memcpy_s((void *)&(v1->gtm_member),
        sizeof(cm_to_ctl_instance_gtm_status),
        (void *const)&(v2->gtm_member),
        sizeof(cm_to_ctl_instance_gtm_status));
    securec_check_intval(rc, (void)rc);
    v1->instance_type = v2->instance_type;
    v1->instanceId = v2->instanceId;
    v1->is_central = v2->is_central;
    v1->member_index = v2->member_index;
    v1->msg_type = v2->msg_type;
    v1->node = v2->node;
}

void GetCtlInstanceStatusFromRecvMsg(char *receiveMsg, cm_to_ctl_instance_status *ctlInstanceStatusPtr)
{
    if (undocumentedVersion != 0 && undocumentedVersion < SUPPORT_IPV6_VERSION) {
        cm_to_ctl_instance_status_ipv4 *statusPtrIpv4 = (cm_to_ctl_instance_status_ipv4 *)receiveMsg;
        CmToCtlInstanceStatusV1ToV2(statusPtrIpv4, ctlInstanceStatusPtr);
    } else {
        errno_t rc = memcpy_s(ctlInstanceStatusPtr,
        sizeof(cm_to_ctl_instance_status),
        receiveMsg,
        sizeof(cm_to_ctl_instance_status));
    securec_check_intval(rc, (void)rc);
    }
}

#ifdef __cplusplus
}
#endif