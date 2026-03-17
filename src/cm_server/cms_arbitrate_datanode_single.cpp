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
 * cms_arbitrate_datanode_single.cpp
 *    only one DN arbitration in cms
 *
 * IDENTIFICATION
 *    src/cm_server/cms_arbitrate_datanode_single.cpp
 *
 * -------------------------------------------------------------------------
 */
#include "cms_conn.h"
#include "cms_global_params.h"
#include "cms_arbitrate_datanode.h"
#include "cms_write_dynamic_config.h"
#include "cms_common.h"

uint32 find_primary_term(uint32 group_index)
{
    uint32 primary_term = InvalidTerm;
    uint32 max_term = InvalidTerm;
    cm_instance_datanode_report_status* dnReportStatus =
        g_instance_group_report_status_ptr[group_index].instance_status.data_node_member;
    for (int ii = 0; ii < g_instance_role_group_ptr[group_index].count; ii++) {
        max_term = Max(max_term, dnReportStatus[ii].local_status.term);
        if (dnReportStatus[ii].local_status.local_role == INSTANCE_ROLE_PRIMARY &&
            g_instance_role_group_ptr[group_index].instanceMember[ii].role == INSTANCE_ROLE_PRIMARY) {
            primary_term = dnReportStatus[ii].local_status.term;
        }
    }
    if (max_term > primary_term) {
        return InvalidTerm;
    }
    return primary_term;
}

void datanode_instance_arbitrate_single(
    MsgRecvInfo* recvMsgInfo, const agent_to_cm_datanode_status_report* agent_to_cm_datanode_status_ptr)
{
    uint32 group_index = 0;
    int member_index = 0;
    int ret;
    XLogRecPtr local_last_xlog_location;

    int local_static_role;
    int local_dynamic_role;
    int local_db_state;
    int local_sync_state;
    int build_reason;
    int double_restarting;

    cm_to_agent_restart restart_msg;
    cm_to_agent_notify notify_msg;

    uint32 node = agent_to_cm_datanode_status_ptr->node;
    uint32 instanceId = agent_to_cm_datanode_status_ptr->instanceId;
    int instanceType = agent_to_cm_datanode_status_ptr->instanceType;
    errno_t rc;

    ret = find_node_in_dynamic_configure(node, instanceId, &group_index, &member_index);
    if (ret != 0) {
        write_runlog(LOG, "can't find the instance(node =%u  instanceid =%u)\n", node, instanceId);
        return;
    }

    (void)pthread_rwlock_wrlock(&(g_instance_group_report_status_ptr[group_index].lk_lock));

    if (g_HA_status->local_role == CM_SERVER_STANDBY) {
        write_runlog(LOG, "cm_server is in standby state\n");
        AsyncProcMsg(recvMsgInfo, PM_REMOVE_CONN, NULL, 0);
        goto process_finish;
    }

    g_instance_group_report_status_ptr[group_index].instance_status.command_member[member_index].heat_beat = 0;

    if (agent_to_cm_datanode_status_ptr->local_redo_stats.is_by_query) {
        XLogRecPtr standby_replay_location =
            agent_to_cm_datanode_status_ptr->parallel_redo_status.last_replayed_read_ptr;

        XLogRecPtr standby_last_replayed_read_Ptr =
            g_instance_group_report_status_ptr[group_index].instance_status.data_node_member[member_index]
                .local_redo_stats.standby_last_replayed_read_Ptr;

        if (standby_last_replayed_read_Ptr > 0) {
            g_instance_group_report_status_ptr[group_index].instance_status.data_node_member[member_index]
                .local_redo_stats.redo_replayed_speed = (standby_replay_location - standby_last_replayed_read_Ptr);
        }

        rc = memcpy_s((void*)&(g_instance_group_report_status_ptr[group_index]
            .instance_status.data_node_member[member_index].local_redo_stats.standby_last_replayed_read_Ptr),
            sizeof(XLogRecPtr),
            (void*)&standby_replay_location,
            sizeof(XLogRecPtr));
        securec_check_errno(rc, (void)rc);
    }
    rc = memcpy_s((void*)&(g_instance_group_report_status_ptr[group_index]
        .instance_status.data_node_member[member_index].local_status),
        sizeof(cm_local_replconninfo),
        (void*)&(agent_to_cm_datanode_status_ptr->local_status),
        sizeof(cm_local_replconninfo));
    securec_check_errno(rc, (void)rc);
    rc = memcpy_s(
        (void*)&(
            g_instance_group_report_status_ptr[group_index].instance_status.data_node_member[member_index].build_info),
        sizeof(BuildState),
        (void*)&(agent_to_cm_datanode_status_ptr->build_info),
        sizeof(BuildState));
    securec_check_errno(rc, (void)rc);
    rc = memcpy_s((void*)g_instance_group_report_status_ptr[group_index]
        .instance_status.data_node_member[member_index].sender_status,
        CM_MAX_SENDER_NUM * sizeof(cm_sender_replconninfo),
        (void*)agent_to_cm_datanode_status_ptr->sender_status,
        CM_MAX_SENDER_NUM * sizeof(cm_sender_replconninfo));
    securec_check_errno(rc, (void)rc);
    rc = memcpy_s((void*)&(g_instance_group_report_status_ptr[group_index]
        .instance_status.data_node_member[member_index].receive_status),
        sizeof(cm_receiver_replconninfo),
        (void*)&(agent_to_cm_datanode_status_ptr->receive_status),
        sizeof(cm_receiver_replconninfo));
    securec_check_errno(rc, (void)rc);
    rc = memcpy_s((void*)&(g_instance_group_report_status_ptr[group_index]
        .instance_status.data_node_member[member_index].parallel_redo_status),
        sizeof(RedoStatsData),
        (void*)&(agent_to_cm_datanode_status_ptr->parallel_redo_status),
        sizeof(RedoStatsData));
    securec_check_errno(rc, (void)rc);
    if (agent_to_cm_datanode_status_ptr->local_redo_stats.is_by_query) {
        g_instance_group_report_status_ptr[group_index]
            .instance_status.data_node_member[member_index]
            .parallel_redo_status.speed_according_seg = (uint32)g_instance_group_report_status_ptr[group_index]
                                                            .instance_status.data_node_member[member_index]
                                                            .local_redo_stats.redo_replayed_speed;
    }
    g_instance_group_report_status_ptr[group_index]
        .instance_status.data_node_member[member_index]
        .local_redo_stats.is_by_query = agent_to_cm_datanode_status_ptr->local_redo_stats.is_by_query;
    local_static_role = g_instance_role_group_ptr[group_index].instanceMember[member_index].role;
    local_dynamic_role = g_instance_group_report_status_ptr[group_index]
        .instance_status.data_node_member[member_index].local_status.local_role;
    local_last_xlog_location = g_instance_group_report_status_ptr[group_index]
        .instance_status.data_node_member[member_index].local_status.last_flush_lsn;
    local_db_state = g_instance_group_report_status_ptr[group_index]
        .instance_status.data_node_member[member_index].local_status.db_state;
    local_sync_state = g_instance_group_report_status_ptr[group_index]
        .instance_status.data_node_member[member_index].sender_status[0].sync_state;
    build_reason = g_instance_group_report_status_ptr[group_index]
        .instance_status.data_node_member[member_index].local_status.buildReason;
    double_restarting = (int)g_instance_group_report_status_ptr[group_index]
        .instance_status.arbitrate_status_member[member_index].restarting;

    if ((local_dynamic_role != INSTANCE_ROLE_PRIMARY && local_dynamic_role != INSTANCE_ROLE_NORMAL) ||
        local_db_state != INSTANCE_HA_STATE_NORMAL) {
        write_runlog(LOG,
            "node %u "
            ", instanceId %u, local_static_role %d=%s, local_dynamic_role %d=%s, "
            ", local_last_xlog_location=%X/%X, local_db_state %d=%s, local_sync_state=%d, build_reason %d=%s, "
            "double_restarting=%d \n",
            node,
            instanceId,
            local_static_role,
            datanode_role_int_to_string(local_static_role),
            local_dynamic_role,
            datanode_role_int_to_string(local_dynamic_role),
            (uint32)(local_last_xlog_location >> 32),
            (uint32)local_last_xlog_location,
            local_db_state,
            datanode_dbstate_int_to_string(local_db_state),
            local_sync_state,
            build_reason,
            datanode_rebuild_reason_int_to_string(build_reason),
            double_restarting);
    }

    instance_delay_arbitrate_time_out_clean(local_dynamic_role,
        INSTANCE_ROLE_INIT,
        group_index,
        member_index,
        MONITOR_INSTANCE_ARBITRATE_DELAY_CYCLE_MAX_COUNT);

    if (local_static_role == INSTANCE_ROLE_PRIMARY) {
        if (g_instance_group_report_status_ptr[group_index]
                .instance_status.arbitrate_status_member[member_index].restarting) {
            g_HA_status->status = CM_STATUS_NEED_REPAIR;
            if (local_dynamic_role == INSTANCE_ROLE_PRIMARY || local_dynamic_role == INSTANCE_ROLE_STANDBY) {
                restart_msg.msg_type = (int)MSG_CM_AGENT_RESTART;
                restart_msg.node = node;
                restart_msg.instanceId = instanceId;
                WriteKeyEventLog(KEY_EVENT_RESTART, instanceId, "send restart message to instance(%u)", instanceId);
                (void)RespondMsg(recvMsgInfo, 'S', (char*)&restart_msg, sizeof(cm_to_agent_restart));
                goto process_finish;
            }

            if (local_dynamic_role == INSTANCE_ROLE_PENDING) {
                g_instance_group_report_status_ptr[group_index]
                    .instance_status.arbitrate_status_member[member_index].restarting = false;
                write_runlog(LOG, "instance %u restart done.\n", instanceId);
            }

            if (g_instance_group_report_status_ptr[group_index]
                    .instance_status.arbitrate_status_member[member_index].restarting) {
                goto process_finish;
            }
        }

        if (local_dynamic_role == INSTANCE_ROLE_STANDBY) {
            g_HA_status->status = CM_STATUS_NEED_REPAIR;
            restart_msg.msg_type = (int)MSG_CM_AGENT_RESTART;
            restart_msg.node = node;
            restart_msg.instanceId = instanceId;
            WriteKeyEventLog(KEY_EVENT_RESTART, instanceId, "send restart message to instance(%u)", instanceId);
            (void)RespondMsg(recvMsgInfo, 'S', (char*)&restart_msg, sizeof(cm_to_agent_restart));
            g_instance_group_report_status_ptr[group_index]
                .instance_status.arbitrate_status_member[member_index].restarting = true;
            write_runlog(LOG, "standby datanode instance, restart to pending.\n");

            goto process_finish;
        }

        if (local_dynamic_role == INSTANCE_ROLE_PENDING) {
            g_HA_status->status = CM_STATUS_NEED_REPAIR;
            notify_msg.msg_type = (int)MSG_CM_AGENT_NOTIFY;
            notify_msg.node = node;
            notify_msg.instanceId = instanceId;
            notify_msg.term = FirstTerm;
            notify_msg.role = INSTANCE_ROLE_PRIMARY;
            WriteKeyEventLog(KEY_EVENT_NOTIFY, instanceId, "send notify message to instance(%u)", instanceId);
            (void)RespondMsg(recvMsgInfo, 'S', (char*)&notify_msg, sizeof(cm_to_agent_notify));
            write_runlog(LOG, "notify datanode to primary.\n");
            goto process_finish;
        }

        if (local_dynamic_role == INSTANCE_ROLE_UNKNOWN) {
            g_HA_status->status = CM_STATUS_NEED_REPAIR;
            goto process_finish;
        }
    } else if (local_static_role == INSTANCE_ROLE_STANDBY) {
        g_HA_status->status = CM_STATUS_NEED_REPAIR;
        /* nerver to do, if done, need to check the code. */
        write_runlog(LOG, "change local role to primary for datanode.\n");
        g_instance_role_group_ptr[group_index].instanceMember[member_index].role = INSTANCE_ROLE_PRIMARY;
        (void)WriteDynamicConfigFile(false);
        goto process_finish;
    } else {
        g_HA_status->status = CM_STATUS_NEED_REPAIR;
        g_instance_role_group_ptr[group_index].instanceMember[member_index].role = INSTANCE_ROLE_PRIMARY;
        write_runlog(ERROR,
            "local_static_role unknown localrole=%d instancetype =%d(node =%u  instanceid =%u)\n",
            local_static_role,
            instanceType,
            node,
            instanceId);
    }
process_finish:
    (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[group_index].lk_lock));
    return;
}
