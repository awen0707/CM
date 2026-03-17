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
 * cms_arbitrate_datanode_pms.cpp
 *    DN one primary multi standby mode arbitration in cms
 *
 * IDENTIFICATION
 *    src/cm_server/cms_arbitrate_datanode_pms.cpp
 *
 * -------------------------------------------------------------------------
 */
#include "cms_global_params.h"
#include "cms_ddb.h"
#include "cms_arbitrate_datanode.h"
#include "cms_write_dynamic_config.h"
#include "cms_arbitrate_datanode_pms_utils.h"
#include "cms_common.h"
#include "cms_disk_check.h"
#include "cms_alarm.h"
#include "cm_ip.h"
#include "cm_msg_version_convert.h"
#ifdef ENABLE_MULTIPLE_NODES
#include "cms_arbitrate_gtm.h"
#endif

void SendUnlockMessage(const DnArbCtx *ctx, uint32 term)
{
    cm_to_agent_unlock unlockMsgPtr;
    unlockMsgPtr.msg_type = (int)MSG_CM_AGENT_UNLOCK;
    if (g_clusterType == V3SingleInstCluster) {
        if (TermIsInvalid(term)) {
            write_runlog(LOG, "Can't send unlock message to instance(%u) because term is invalid.\n", ctx->instId);
            return;
        }
        unlockMsgPtr.node = term;
    } else {
        unlockMsgPtr.node = ctx->node;
    }
    unlockMsgPtr.instanceId = ctx->instId;
    write_runlog(LOG, "send unlock message to instance(%u).\n", ctx->instId);
    (void)RespondMsg(ctx->recvMsgInfo, 'S', (char *)(&unlockMsgPtr), sizeof(cm_to_agent_unlock));
}

static void SendNotifyMessage2Cma(const DnArbCtx *ctx, int32 roleType)
{
    cm_to_agent_notify notifyMsgPtr;
    notifyMsgPtr.msg_type = (int)MSG_CM_AGENT_NOTIFY;
    notifyMsgPtr.node = ctx->node;
    notifyMsgPtr.instanceId = ctx->instId;
    notifyMsgPtr.role = roleType;
    notifyMsgPtr.term = FirstTerm;
    const char *roleStr = (roleType == INSTANCE_ROLE_STANDBY) ? "standby" : "cascade standby";
    WriteKeyEventLog(KEY_EVENT_NOTIFY_STANDBY, ctx->instId, "send notify %s to instance(%u)", roleStr, ctx->instId);
    (void)RespondMsg(ctx->recvMsgInfo, 'S', (char *)(&notifyMsgPtr), sizeof(cm_to_agent_notify));
}

static void SendFinishRedoMessage(const DnArbCtx *ctx)
{
    cm_to_agent_finish_redo finishRedoMsgPtr;
    finishRedoMsgPtr.msg_type = (int)MSG_CM_AGENT_FINISH_REDO;
    finishRedoMsgPtr.node = ctx->node;
    finishRedoMsgPtr.instanceId = ctx->instId;
    finishRedoMsgPtr.is_finish_redo_cmd_sent = ctx->localRep->is_finish_redo_cmd_sent;
    WriteKeyEventLog(KEY_EVENT_FINISH_REDO, ctx->instId, "send finish redo message to instance(%u)", ctx->instId);
    (void)RespondMsg(ctx->recvMsgInfo, 'S', (char*)(&finishRedoMsgPtr), sizeof(cm_to_agent_finish_redo));
}

static void SetDynamicRole(DnArbCtx *ctx, int32 role, const char *str1, const char *str2)
{
    write_runlog(LOG, "%s, %s reset dynamic role from %d to %d.\n", str1, str2, ctx->info.dyRole, role);
    ctx->localRep->local_status.local_role = role;
    ctx->info.dyRole = role;
}

static void SendRestartMsg(DnArbCtx *ctx, const char *str)
{
    cm_to_agent_restart restartMsg;
    restartMsg.msg_type = (int)MSG_CM_AGENT_RESTART;
    restartMsg.node = ctx->node;
    restartMsg.instanceId = ctx->instId;
    WriteKeyEventLog(KEY_EVENT_RESTART, ctx->instId, "%s, send restart message to instance(%u)", str, ctx->instId);
    (void)RespondMsg(ctx->recvMsgInfo, 'S', (char *)&restartMsg, sizeof(cm_to_agent_restart));
    SetDynamicRole(ctx, INSTANCE_ROLE_UNKNOWN, str, "[SendRestartMsg]");
}

static void SendLock1Message(const DnArbCtx *ctx)
{
    cm_to_agent_lock1 lock1MsgPtr;
    lock1MsgPtr.msg_type = (int)MSG_CM_AGENT_LOCK_NO_PRIMARY;
    lock1MsgPtr.node = ctx->node;
    lock1MsgPtr.instanceId = ctx->instId;
    write_runlog(LOG, "send lock1 message to instance(%u).\n", ctx->instId);
    (void)RespondMsg(ctx->recvMsgInfo, 'S', (char *)&lock1MsgPtr, sizeof(cm_to_agent_lock1));
}

static void SendLock2Messange(const DnArbCtx *ctx, const char *dhost, int dlen, uint32 dport,
    uint32 primaryTerm)
{
    cm_to_agent_lock2 lock2MsgPtr = {0};
    lock2MsgPtr.msg_type = (int)MSG_CM_AGENT_LOCK_CHOSEN_PRIMARY;
    if (g_clusterType == V3SingleInstCluster) {
        lock2MsgPtr.node = primaryTerm;
    } else {
        lock2MsgPtr.node = ctx->node;
    }
    lock2MsgPtr.instanceId = ctx->instId;
    errno_t rc = snprintf_s(lock2MsgPtr.disconn_host, (size_t)CM_IP_LENGTH, dlen, "%s", dhost);
    securec_check_intval(rc, (void)rc);
    lock2MsgPtr.disconn_port = dport;
    write_runlog(LOG, "send lock2 message to instance(%u: %u), dhost=%s, dport=%u.\n",
        ctx->instId, GetInstanceIdInGroup(ctx->groupIdx, ctx->cond.vaildPrimIdx), dhost, dport);
    if (undocumentedVersion != 0 && undocumentedVersion < SUPPORT_IPV6_VERSION) {
        cm_to_agent_lock2_ipv4 lock2MsgPtrIpv4;
        CmToAgentLock2V2ToV1(&lock2MsgPtr, &lock2MsgPtrIpv4);
        (void)RespondMsg(ctx->recvMsgInfo, 'S', (char *)&lock2MsgPtrIpv4, sizeof(cm_to_agent_lock2_ipv4));
    } else {
        (void)RespondMsg(ctx->recvMsgInfo, 'S', (char *)&lock2MsgPtr, sizeof(cm_to_agent_lock2));
    }
}

static void copy_cm_to_agent_failover_msg(cm_to_agent_failover* failover_msg_ptr,
    cm_to_agent_failover_sta* staMsg, int32 staId)
{
    staMsg->msg_type = failover_msg_ptr->msg_type;
    staMsg->node = failover_msg_ptr->node;
    staMsg->instanceId = failover_msg_ptr->instanceId;
    staMsg->term = failover_msg_ptr->term;
    staMsg->staPrimId = staId;
}

static void send_failover_message(MsgRecvInfo* recvMsgInfo, uint32 node, uint32 instanceId, uint32 group_index,
    int member_index, cm_to_agent_failover* failover_msg_ptr, int32 staPrimId)
{
    cm_instance_role_group* role_group = &g_instance_role_group_ptr[group_index];
    int count = role_group->count;
    cm_instance_role_status* roleMember = role_group->instanceMember;
    cm_instance_datanode_report_status* dnReportStatus =
        g_instance_group_report_status_ptr[group_index].instance_status.data_node_member;

    ChangeDnPrimaryMemberIndex(group_index, member_index);

    failover_msg_ptr->msg_type = (int)MSG_CM_AGENT_FAILOVER;
    failover_msg_ptr->node = node;
    failover_msg_ptr->instanceId = instanceId;
    uint32 pass_term = ReadTermFromDdb(group_index);
    if (pass_term == InvalidTerm) {
        write_runlog(ERROR, "line %d: Term on DDB has not been set yet, which should not happen.\n", __LINE__);
        (void)WriteDynamicConfigFile(false);
        return;
    }

    (void)WriteDynamicConfigFile(false);

    if (pass_term < g_instance_group_report_status_ptr[group_index].instance_status.term) {
        write_runlog(ERROR, "line %d: DDB term(%u) is smaller than group term(%u)!.\n",
            __LINE__, pass_term, g_instance_group_report_status_ptr[group_index].instance_status.term);
        return;
    }

    g_instance_group_report_status_ptr[group_index].instance_status.term = pass_term;
    failover_msg_ptr->term = pass_term;
    WriteKeyEventLog(KEY_EVENT_FAILOVER, instanceId, "Failover message has sent to instance %u, term %u, "
        "sendFailoverTimes is %u.", instanceId, pass_term, dnReportStatus[member_index].sendFailoverTimes);
    for (int i = 0; i < count; i++) {
        int node_static_role = roleMember[i].role;
        int node_dynamic_role = dnReportStatus[i].local_status.local_role;
        XLogRecPtr node_last_xlog_location = dnReportStatus[i].local_status.last_flush_lsn;
        uint32 node_term = dnReportStatus[i].local_status.term;
        int node_db_state = dnReportStatus[i].local_status.db_state;
        int node_sync_state = dnReportStatus[i].sender_status[0].sync_state;
        bool node_redo_finished = dnReportStatus[i].local_status.redo_finished;
        int node_build_reason = dnReportStatus[i].local_status.buildReason;
        int node_restarting =
            (int)g_instance_group_report_status_ptr[group_index].instance_status.arbitrate_status_member[i].restarting;
        write_runlog(LOG, "line %d: new arbitra node %d"
            ", instanceId %u, static_role %d=%s, local_dynamic_role %d=%s, local_term=%u, local_redo_finished = %d"
            ", local_last_xlog_location=%X/%X, local_db_state %d=%s, local_sync_state=%d, build_reason %d=%s, "
            "double_restarting=%d, group_term=%u, sendFailoverTimes=%u\n",
            __LINE__, i, roleMember[i].instanceId, node_static_role, datanode_role_int_to_string(node_static_role),
            node_dynamic_role, datanode_role_int_to_string(node_dynamic_role),
            node_term, node_redo_finished, (uint32)(node_last_xlog_location >> 32),
            (uint32)node_last_xlog_location, node_db_state, datanode_dbstate_int_to_string(node_db_state),
            node_sync_state, node_build_reason, datanode_rebuild_reason_int_to_string(node_build_reason),
            node_restarting, pass_term, dnReportStatus[i].sendFailoverTimes);
    }

    if (undocumentedVersion != 0 && undocumentedVersion < FAILOVER_STAPRI_VERSION) {
        (void)RespondMsg(recvMsgInfo, 'S', (char*)failover_msg_ptr, sizeof(cm_to_agent_failover));
    } else {
        cm_to_agent_failover_sta staMsg;
        copy_cm_to_agent_failover_msg(failover_msg_ptr, &staMsg, staPrimId);
        (void)RespondMsg(recvMsgInfo, 'S', (char*)(&staMsg), sizeof(cm_to_agent_failover_sta));
    }

    dnReportStatus[member_index].arbitrateFlag = true;
    dnReportStatus[member_index].sendFailoverTimes++;
    cm_pending_notify_broadcast_msg(group_index, instanceId);
}

static bool CanFailoverDn(bool isMajority)
{
    if (isMajority) {
        return true;
    }
#ifndef ENABLE_MULTIPLE_NODES
    if (g_clusterInstallType == INSTALL_TYPE_SHARE_STORAGE && backup_open == CLUSTER_PRIMARY) {
        return true;
    }
#endif
    return false;
}

static void CleanBuildCmdWhenBuildFailed(uint32 groupIdx, int32 memIdx)
{
    /*
     * cm_agent found both gs_build.pid and gaussdb.state do not exist during building and regard building
     * failed. but may this is just betweenness and cm_server delay to arbitrate.
     */
    cm_instance_command_status *cmd =
        &(g_instance_group_report_status_ptr[groupIdx].instance_status.command_member[memIdx]);
    if (cmd->pengding_command == (int32)MSG_CM_AGENT_BUILD) {
        uint32 instId = GetInstanceIdInGroup(groupIdx, memIdx);
        if (cmd->buildFailedTimeout <= 0) {
            cmd->buildFailedTimeout = MONITOR_INSTANCE_ARBITRATE_DELAY_CYCLE_MAX_COUNT;
            write_runlog(LOG, "instId(%u) build failed and set cleaning command time(%d).\n",
                instId, cmd->buildFailedTimeout);
            return;
        }
        write_runlog(LOG, "instId(%u) build failed and will clean command after %d.\n",
            instId, cmd->buildFailedTimeout);
        if (cmd->buildFailedTimeout == 1) {
            write_runlog(LOG, "CleanCommand: instance(%u) build failed.\n", instId);
            CleanCommand(groupIdx, memIdx);
        }
    }
}

static void CleanBuildCommand(uint32 groupIdx, int32 memIdx, int32 dbState, bool *needBuild)
{
    bool isneedBuild = true;
    const int32 thresHold = 7200;
    const int32 delayTime = 20;
    cm_instance_report_status *instRep = &(g_instance_group_report_status_ptr[groupIdx].instance_status);
    cm_instance_command_status *cmd = &(instRep->command_member[memIdx]);
    int32 timeOut = cmd->time_out;
    if (dbState == INSTANCE_HA_STATE_NORMAL && (timeOut > thresHold || timeOut < (thresHold - delayTime))) {
        if (cmd->pengding_command == (int)MSG_CM_AGENT_BUILD) {
            write_runlog(LOG, "CleanCommand: instance(%u) is building.\n", GetInstanceIdInGroup(groupIdx, memIdx));
            CleanCommand(groupIdx, memIdx);
        }
        isneedBuild = false;
    }
    cm_local_replconninfo *dnSt = &(instRep->data_node_member[memIdx].local_status);
    if (dnSt->local_role == INSTANCE_ROLE_UNKNOWN && dnSt->db_state == INSTANCE_HA_STATE_BUILD_FAILED) {
        CleanBuildCmdWhenBuildFailed(groupIdx, memIdx);
        isneedBuild = false;
    }
    if (needBuild != NULL) {
        *needBuild = isneedBuild;
    }
}

void CleanBuildCommandInfo(uint32 groupIndex, int memberIndex, int dbState)
{
    CleanBuildCommand(groupIndex, memberIndex, dbState, NULL);
    DnBuildStatus buildStatus = {0};
    CheckDnBuildStatus(groupIndex, -1, &buildStatus);
    if (buildStatus.buildCount > 0) {
        return;
    }
    DealDbstateNormalPrimaryDown(groupIndex, INSTANCE_TYPE_DATANODE);
}

bool CheckBuildCond(int dbState, uint32 groupIndex, int memberIndex, int buildReason, bool dcfMode)
{
    bool isNeedBuild = false;

    bool needBuild = dbState == INSTANCE_HA_STATE_NEED_REPAIR &&
        (buildReason == INSTANCE_HA_DATANODE_BUILD_REASON_SYSTEMID_NOT_MATCHED ||
        buildReason == INSTANCE_HA_DATANODE_BUILD_REASON_VERSION_NOT_MATCHED ||
        buildReason == INSTANCE_HA_DATANODE_BUILD_REASON_TIMELINE_NOT_MATCHED ||
        buildReason == INSTANCE_HA_DATANODE_BUILD_REASON_WALSEGMENT_REMOVED ||
        buildReason == INSTANCE_HA_DATANODE_BUILD_REASON_DCF_LOG_LOSS);
    const char *str = "[sendBuild]";
    CleanBuildCommand(groupIndex, memberIndex, dbState, &isNeedBuild);
    if (!isNeedBuild) {
        return false;
    }

    if (needBuild) {
        uint32 instanceId = GetInstanceIdInGroup(groupIndex, memberIndex);
        if (g_instance_group_report_status_ptr[groupIndex].instance_status.command_member[memberIndex]
            .pengding_command == MSG_CM_AGENT_BUILD) {
            write_runlog(LOG, "%s, instance(%u) need to send build msg again.\n", str, instanceId);
            return true;
        }
        int32 count = GetInstanceCountsInGroup(groupIndex);
        DnBuildStatus buildStatus = {0};
        CheckDnBuildStatus(groupIndex, memberIndex, &buildStatus);
        int32 twoStandby = 2;
        if (dcfMode) {
            if (buildStatus.buildCount > 0) {
                write_runlog(LOG, "%s, [dcf]: instanceId %u, count is %d, buildCount is %d, standby is %d, can not "
                    "send build msg.\n", str, instanceId, count, buildStatus.buildCount, buildStatus.standbyCount);
                return false;
            }
            return true;
        }
        /*
         * if this instance isn't in synclist, it is asynchronous standby node,
         * so can send build as soon as possible.
         */
        if (buildStatus.inSyncList == -1) {
            write_runlog(LOG, "%s, lines %d: instanceId %u, count is %d, buildCount is %d, standby is %d, "
                "asynch standby can send build msg.\n", str, __LINE__, instanceId, count, buildStatus.buildCount,
                buildStatus.standbyCount);
            return true;
        }
        /*
         * one primary and one standby can send build.
         * this time only one standby need to build, other instance may be not upto standby.
         * if standby count small than 2, only send build one by one.
         */
        if (buildStatus.standbyCount <= twoStandby) {
            if (buildStatus.buildCount > 0) {
                write_runlog(LOG, "%s, instanceId %u, count is %d, buildCount is %d, standby is %d, can not send "
                    "build msg.\n", str, instanceId, count, buildStatus.buildCount, buildStatus.standbyCount);
                return false;
            }
            return true;
        }
        /* online instance can not include primary, if it needs to satisfy the minority */
        if (buildStatus.buildCount > ((buildStatus.standbyCount - 1) / 2 - 1)) {
            write_runlog(LOG, "%s, lines %d: instanceId %u, count is %d, buildCount is %d, standby is %d, cannot send "
                "build msg.\n", str, __LINE__, instanceId, count, buildStatus.buildCount, buildStatus.standbyCount);
            return false;
        }
    }

    return needBuild;
}

void DatanodeBuildExec(MsgRecvInfo* recvMsgInfo, const db_state_role &role, maintenance_mode mode)
{
    int timeOut = 86400;
    cm_to_agent_build build_msg;
    const char *str = "[sendBuild]";
    write_runlog(LOG, "%s, line %d: before send MSG_CM_AGENT_BUILD local_dynamic_role =%d "
        "instanceId=%u timeout_set=%d delay_time =%d \n", str, __LINE__, role.local_dynamic_role,
        GetInstanceIdInGroup((uint32)role.group_index, role.member_index),
        g_instance_group_report_status_ptr[role.group_index].instance_status.command_member[role.member_index]
        .arbitrate_delay_set,
        g_instance_group_report_status_ptr[role.group_index].instance_status.command_member[role.member_index]
        .arbitrate_delay_time_out);

    if (IsMaintenanceModeDisableOperation(CMS_BUILD_DN, mode)) {
        write_runlog(LOG, "%s, %d Maintaining cluster: cm server cannot build dn.\n", str, __LINE__);
        return;
    }

    build_msg.msg_type = (int)MSG_CM_AGENT_BUILD;
    build_msg.node = role.node;
    build_msg.instanceId = (uint32)role.instance_id;
    build_msg.wait_seconds = BUILD_TIMER_OUT;
    build_msg.full_build = 0;
    build_msg.term = find_primary_term((uint32)role.group_index);
    build_msg.role = role.local_dynamic_role;
    if (build_msg.term == InvalidTerm && backup_open == CLUSTER_PRIMARY) {
        write_runlog(DEBUG1, "%s, line %d: No legal primary for building instance %d", str, __LINE__, role.instance_id);
    }
    WriteKeyEventLog(KEY_EVENT_BUILD, (uint32)role.instance_id, "send build message to instance(%d)",
        role.instance_id);
    (void)RespondMsg(recvMsgInfo, 'S', (char*)&build_msg, sizeof(cm_to_agent_build));
    g_instance_group_report_status_ptr[role.group_index].instance_status.command_member[role.member_index]
        .pengding_command = (int)MSG_CM_AGENT_BUILD;
    g_instance_group_report_status_ptr[role.group_index].instance_status.command_member[role.member_index]
        .time_out = timeOut;

    write_runlog(LOG, "%s, DatanodeBuildExec: instance(%d) start building.\n", str, role.instance_id);
    return;
}

static status_t InitDnArbiStatusEx(DnArbCtx *ctx)
{
    ctx->localRole = GetRoleStatus(ctx->groupIdx, ctx->memIdx);
    ctx->repGroup = GetReportStatus(ctx->groupIdx);
    ctx->localRep = GetLocalReportStatus(ctx->groupIdx, ctx->memIdx);
    ctx->localCom = GetCommand(ctx->groupIdx, ctx->memIdx);
    ctx->maintaMode = getMaintenanceMode(ctx->groupIdx);
    ctx->lock = &(g_instance_group_report_status_ptr[ctx->groupIdx].lk_lock);
    ctx->dbStatePre = GetDataNodeMember(ctx->groupIdx, ctx->memIdx).local_status.db_state;
    ctx->dnReport = GetDnReportStatus(ctx->groupIdx);
    ctx->roleGroup = &(g_instance_role_group_ptr[ctx->groupIdx]);
    ctx->curAzIndex = 0;
    return CM_SUCCESS;
}

static status_t InitDnArbCtx(
    MsgRecvInfo* recvMsgInfo, const agent_to_cm_datanode_status_report *agentRep, DnArbCtx *ctx)
{
    ctx->recvMsgInfo = recvMsgInfo;
    ctx->node = agentRep->node;
    ctx->instId = agentRep->instanceId;
    int32 ret = find_node_in_dynamic_configure(ctx->node, ctx->instId, &ctx->groupIdx, &ctx->memIdx);
    if (ret != 0) {
        write_runlog(LOG, "can't find the instance(node =%u  instanceid =%u)\n", ctx->node, ctx->instId);
        return CM_ERROR;
    }
    status_t resStatus = InitDnArbiStatusEx(ctx);
    CM_RETURN_IFERR(resStatus);
    return CM_SUCCESS;
}

static void GetDnStaticRoleFromDdb(const DnArbCtx *ctx)
{
    if (undocumentedVersion == 0 || undocumentedVersion >= 92214) {
        GetDatanodeDynamicConfigChangeFromDdbNew(ctx->groupIdx);
    } else {
        GetDatanodeDynamicConfigChangeFromDdb(ctx->groupIdx);
    }
    if (g_needIncTermToDdbAgain) {
        (void)pthread_rwlock_wrlock(&term_update_rwlock);
        /* Prevent multiple worker threads from increasing term at the same time. */
        if (g_needIncTermToDdbAgain) {
            (void)IncrementTermToDdb();
        }
        (void)pthread_rwlock_unlock(&term_update_rwlock);
    }
}

static void ResetHeartbeat(const DnArbCtx *ctx)
{
    ctx->localCom->keep_heartbeat_timeout = 0;
    ctx->localCom->heat_beat = 0;
}

static void SaveDnStatusFromReport(const agent_to_cm_datanode_status_report *agentRep, const DnArbCtx *ctx)
{
    errno_t rc = 0;
    ctx->localRep->local_redo_stats.is_by_query = agentRep->local_redo_stats.is_by_query;
    if (ctx->localRep->local_redo_stats.is_by_query) {
        XLogRecPtr repLoc = agentRep->parallel_redo_status.last_replayed_read_ptr;
        XLogRecPtr lastRepLoc = ctx->localRep->local_redo_stats.standby_last_replayed_read_Ptr;
        if (lastRepLoc > 0) {
            ctx->localRep->local_redo_stats.redo_replayed_speed = repLoc - lastRepLoc;
        }
        rc = memcpy_s((void *)&(ctx->localRep->local_redo_stats.standby_last_replayed_read_Ptr),
            sizeof(XLogRecPtr), (void *)&repLoc, sizeof(XLogRecPtr));
        securec_check_errno(rc, (void)rc);
    }

    rc = memcpy_s((void*)&(ctx->localRep->local_status), sizeof(cm_local_replconninfo),
        (void * const)&(agentRep->local_status), sizeof(cm_local_replconninfo));
    securec_check_errno(rc, (void)rc);
    rc = memcpy_s((void *)&(ctx->localRep->build_info), sizeof(BuildState),
        (void * const)&(agentRep->build_info), sizeof(BuildState));
    securec_check_errno(rc, (void)rc);
    rc = memcpy_s((void *)&(ctx->localRep->sender_status[0]), CM_MAX_SENDER_NUM * sizeof(cm_sender_replconninfo),
        (void * const)agentRep->sender_status, CM_MAX_SENDER_NUM * sizeof(cm_sender_replconninfo));
    securec_check_errno(rc, (void)rc);
    rc = memcpy_s((void *)&(ctx->localRep->receive_status), sizeof(cm_receiver_replconninfo),
        (void * const)&(agentRep->receive_status), sizeof(cm_receiver_replconninfo));
    securec_check_errno(rc, (void)rc);
    rc = memcpy_s((void *)&(ctx->localRep->parallel_redo_status), sizeof(RedoStatsData),
        (void * const)&(agentRep->parallel_redo_status), sizeof(RedoStatsData));
    securec_check_errno(rc, (void)rc);
    if (agentRep->local_redo_stats.is_by_query) {
        ctx->localRep->parallel_redo_status.speed_according_seg =
            (uint32)ctx->localRep->local_redo_stats.redo_replayed_speed;
    }
    ctx->localRep->dn_restart_counts = agentRep->dn_restart_counts;
    ctx->localRep->dn_restart_counts_in_hour = agentRep->dn_restart_counts_in_hour;
    if (ctx->localRep->phony_dead_times >= phony_dead_effective_time && agentRep->phony_dead_times == 0) {
        ctx->localRep->phony_dead_interval = instance_phony_dead_restart_interval;
        write_runlog(LOG, "line %d: set phony dead interval to %d for instance %u.\n",
            __LINE__, ctx->localRep->phony_dead_interval, ctx->instId);
    }
    ctx->localRep->phony_dead_times = agentRep->phony_dead_times;
    if (undocumentedVersion == 0) {
        ctx->localRep->dnVipStatus = agentRep->dnVipStatus;
    } else {
        ctx->localRep->dnVipStatus = CM_ERROR;
    }
    /* cluster streaming standby ignore term */
    if (backup_open == CLUSTER_STREAMING_STANDBY) {
        ctx->localRep->local_status.term = FirstTerm;
    }

    if (g_instance_group_report_status_ptr[ctx->groupIdx]
            .instance_status.data_node_member[ctx->memIdx]
            .local_status.realtime_build_status) {
        g_realtimeBuildStatus |= (1U << (ctx->node - 1));
    } else {
        g_realtimeBuildStatus &= ~(1U << (ctx->node - 1));
    }
}

static void InitStateRole(db_state_role *role, const DnArbCtx *ctx)
{
    role->node = ctx->node;
    role->instance_id = (int)ctx->instId;
    role->local_dynamic_role = ctx->localRep->local_status.local_role;
    role->local_db_state = ctx->localRep->local_status.db_state;
    role->group_index = (int)ctx->groupIdx;
    role->member_index = ctx->memIdx;
}

static void DealDnInSelfArbitrate(const DnArbCtx *ctx)
{
    write_runlog(DEBUG1, "Self-Arbitration mode is on, %u\n", ctx->instId);
    db_state_role role;
    InitStateRole(&role, ctx);
    int32 buildReason = ctx->info.buildReason;
    if (CheckBuildCond(role.local_db_state, ctx->groupIdx, ctx->memIdx, buildReason, true)) {
        DatanodeBuildExec(ctx->recvMsgInfo, role, ctx->maintaMode);
    }
    int32 peerIdx = GetMemIdxByInstanceId(ctx->groupIdx, ctx->localCom->peerInstId);
    (void)CheckSwitchOverDone(ctx, peerIdx);
    ChangeStaticPrimaryByDynamicPrimary(ctx);
}

static void DealDnArbitrateInBackup(const DnArbCtx *ctx)
{
    if (ctx->localRep->local_status.local_role == INSTANCE_ROLE_PENDING) {
        SendNotifyMessage2Cma(ctx, INSTANCE_ROLE_STANDBY);
        write_runlog(LOG, "line %d: notify local datanode to standby.\n", __LINE__);
    }

    int32 buildReason = ctx->info.buildReason;
    if (CheckBuildCond(ctx->localRep->local_status.db_state, ctx->groupIdx, ctx->memIdx, buildReason, false)) {
        db_state_role role;
        InitStateRole(&role, ctx);
        DatanodeBuildExec(ctx->recvMsgInfo, role, ctx->maintaMode);
    }
}

static void DynamicPrimaryInCoreDump(DnArbCtx *ctx)
{
    bool res = (ctx->localRep->local_status.local_role == INSTANCE_ROLE_PRIMARY &&
                ctx->localRep->local_status.db_state == INSTANCE_HA_STATE_COREDUMP);
    if (res) {
        write_runlog(LOG, "The primary datanode (%u) may be coredump.\n", ctx->instId);
        ctx->localRep->local_status.local_role = INSTANCE_ROLE_UNKNOWN;
        ctx->info.dyRole = INSTANCE_ROLE_UNKNOWN;
    }
}

uint32 GetPrimaryDnCount(uint32 groupIdx)
{
    int32 count = GetInstanceCountsInGroup(groupIdx);
    uint32 primaryCount = 0;
    cm_instance_datanode_report_status *dnReport = GetDnReportStatus(groupIdx);
    for (int32 i = 0; i < count; ++i) {
        if (dnReport[i].local_status.local_role == INSTANCE_ROLE_PRIMARY) {
            primaryCount++;
        }
    }
    return primaryCount;
}

static status_t RestartSmallerTermDynamicPrimary(DnArbCtx *ctx)
{
    DnArbitInfo info;
    InitDnArbitInfo(&info);
    GetDnArbitInfo(ctx->groupIdx, &info);
    ctx->maxTerm = info.maxTerm;
    if (info.switchoverIdx != -1) {
        if (ctx->repGroup->command_member[info.switchoverIdx].peerInstId == ctx->instId) {
            write_runlog(DEBUG1, "instId(%u) may be doing switchover, switchoverInstId is %u.\n", ctx->instId,
                GetInstanceIdInGroup(ctx->groupIdx, info.switchoverIdx));
            return CM_SUCCESS;
        }
    }
    uint32 localTerm = ctx->localRep->local_status.term;
    if (localTerm < info.maxTerm && ctx->localRep->local_status.local_role == INSTANCE_ROLE_PRIMARY &&
        ctx->localRep->local_status.db_state == INSTANCE_HA_STATE_NORMAL && localTerm != InvalidTerm) {
         /*
          * stop instance only when
          * enable CM cluster auto failover and unable DB cluster auto crash recovery in two node deployment arch
          */
        if (ENABLED_AUTO_FAILOVER_ON2NODES(g_cm_server_num, g_paramsOn2Nodes.cmsEnableFailoverOn2Nodes) &&
            !g_paramsOn2Nodes.cmsEnableDbCrashRecovery) {
            write_runlog(ERROR,
                "line %d: split brain failure in db service, instance %u local term(%u) is not max term(%u). "
                "Due to auto crash recovery is disabled, will not restart current instance, "
                "waiting for manual intervention.\n",
                __LINE__, ctx->instId, localTerm, ctx->maxTerm);
            ReportClusterDoublePrimaryAlarm(
                ALM_AT_Event,
                ALM_AI_DbInstanceDoublePrimary,
                ctx->instId,
                SERVICE_TYPE_DB);

            // try to stop fake primary db instance from cms
            StopFakePrimaryResourceInstance(ctx);
        } else {
            SendRestartMsg(ctx, "[SmallerTerm]");
            write_runlog(LOG, "line %d: instance %u local term(%u) is not max term(%u), "
                "restart to pending.\n", __LINE__, ctx->instId, localTerm, ctx->maxTerm);
        }
        return CM_ERROR;
    }
    /* The connection between the CMA and the DN may be abnormal. Need to restart this Primary. */
    if (ctx->localRep->local_status.local_role == INSTANCE_ROLE_PRIMARY &&
        ctx->localRep->local_status.db_state == INSTANCE_HA_STATE_UNKONWN && localTerm == InvalidTerm) {
        if (GetPrimaryDnCount(ctx->groupIdx) > 1) {
            SendRestartMsg(ctx, "[SmallerTerm]");
            write_runlog(LOG, "line %d: instance %u local term is 0, restart to pending.\n", __LINE__, ctx->instId);
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

static void PrintLogIfInstanceIsUnheal(const DnArbCtx *ctx)
{
    int32 dyRole = ctx->localRep->local_status.local_role;
    int32 dyDbState = ctx->localRep->local_status.db_state;
    int32 staticRole = ctx->localRole->role;
    bool isUnhealth = (dyRole != INSTANCE_ROLE_PRIMARY && dyRole != INSTANCE_ROLE_STANDBY &&
                      dyRole != INSTANCE_ROLE_CASCADE_STANDBY) ||
                      (dyDbState != INSTANCE_HA_STATE_NORMAL) ||
                      (dyRole == INSTANCE_ROLE_PRIMARY && staticRole != INSTANCE_ROLE_PRIMARY) ||
                      (log_min_messages <= DEBUG1);
    if (isUnhealth) {
        PrintCurAndPeerDnInfo(ctx, "[InstanceIsUnheal]");
    }
}

static void DnArbitrateInTwoRepAndSingleInst(const DnArbCtx *ctx)
{
    if (!((g_dn_replication_num == 2 || SetOfflineNode()) && g_only_dn_cluster)) {
        return;
    }
    int32 localRole = ctx->localRep->local_status.local_role;
    int32 localDbState = ctx->localRep->local_status.db_state;

    /* one primary one standby */
    int32 peerIndex = (ctx->memIdx != 0) ? 0 : 1;
    int32 peerRole = ctx->dnReport[peerIndex].local_status.local_role;
    int32 peerDbState = ctx->dnReport[peerIndex].local_status.db_state;

    bool cond = (((localRole == INSTANCE_ROLE_PRIMARY && peerRole == INSTANCE_ROLE_STANDBY) ||
        (localRole == INSTANCE_ROLE_STANDBY && peerRole == INSTANCE_ROLE_PRIMARY)) &&
        (localDbState == INSTANCE_HA_STATE_NORMAL && peerDbState == INSTANCE_HA_STATE_NORMAL)) ||
        (cm_arbitration_mode == MINORITY_ARBITRATION);
    if (cond) {
        if (ctx->localCom->sync_mode == 0) {
            write_runlog(LOG, "the sync mode of instance %u become to 1.\n", ctx->instId);
        }
        ctx->localCom->sync_mode = 1;
    }
    cond = (localRole == INSTANCE_ROLE_PRIMARY && peerRole == INSTANCE_ROLE_UNKNOWN &&
        cm_arbitration_mode == MINORITY_ARBITRATION);
    if (cond) {
        if (ctx->repGroup->command_member[peerIndex].sync_mode == 1) {
            write_runlog(LOG, "sync mode of instance %u become to 0\n", GetInstanceIdInGroup(ctx->groupIdx, peerIndex));
        }
        ctx->repGroup->command_member[peerIndex].sync_mode = 0;
    }
}

static void InstanceInfoValues(uint32 groupIdx, int32 memIdx, StatusInstances *insInfo)
{
    insInfo->itStatus[insInfo->count].instId = GetInstanceIdInGroup(groupIdx, memIdx);
    insInfo->itStatus[insInfo->count].term = GetInstanceTerm(groupIdx, memIdx);
    insInfo->itStatus[insInfo->count].memIdx = memIdx;
    ++insInfo->count;
}

static bool CheckPrimInfo(
    const StatusInstances *dyPri, const StatusInstances *dyNorPri, const StatusInstances *staPri)
{
    if (dyPri->count == 0 || staPri->count == 0 || dyNorPri->count == 0) {
        return false;
    }
    if ((dyPri->count != staPri->count) || (dyNorPri->count != dyPri->count)) {
        return false;
    }
    for (int32 i = 0; i < dyPri->count; ++i) {
        if (dyPri->itStatus[i].instId != staPri->itStatus[i].instId) {
            return false;
        }
    }
    return true;
}

static void InitStatusInstance(DnArbCtx *ctx)
{
    errno_t rc = memset_s(&(ctx->dyNorPrim), sizeof(StatusInstances), 0, sizeof(StatusInstances));
    securec_check_errno(rc, (void)rc);
    rc = memset_s(&(ctx->dyPrim), sizeof(StatusInstances), 0, sizeof(StatusInstances));
    securec_check_errno(rc, (void)rc);
    rc = memset_s(&(ctx->staPrim), sizeof(StatusInstances), 0, sizeof(StatusInstances));
    securec_check_errno(rc, (void)rc);
    rc = memset_s(&(ctx->pendStatus), sizeof(StatusInstances), 0, sizeof(StatusInstances));
    securec_check_errno(rc, (void)rc);
    rc = memset_s(&(ctx->staCasCade), sizeof(StatusInstances), 0, sizeof(StatusInstances));
    securec_check_errno(rc, (void)rc);
    rc = memset_s(&(ctx->dyCascade), sizeof(StatusInstances), 0, sizeof(StatusInstances));
    securec_check_errno(rc, (void)rc);
}

static bool IsInstdInstances(uint32 instd, const StatusInstances *stInst2)
{
    for (int32 i = 0; i < stInst2->count; ++i) {
        if (instd == stInst2->itStatus[i].instId) {
            return true;
        }
    }
    return false;
}

static bool IsSameStanceStatus(const StatusInstances *stInst1, const StatusInstances *stInst2)
{
    if (stInst1->count > stInst2->count) {
        return false;
    }

    for (int32 i = 0; i < stInst1->count; ++i) {
        if (!IsInstdInstances(stInst1->itStatus[i].instId, stInst2)) {
            return false;
        }
    }
    return true;
}

static void PrintStanceInfo(const DnArbCtx *ctx, const GetInstType *instType)
{
    if (log_min_messages > DEBUG1) {
        if (instType->instMode == DN_ARBI_PMS) {
            return;
        }
        if (CheckPrimInfo(&(ctx->dyPrim), &(ctx->dyNorPrim), &(ctx->staPrim))) {
            return;
        }
        if (IsSameStanceStatus(&(ctx->staCasCade), &(ctx->dyCascade))) {
            return;
        }
    }

    char dyPriStr[MAX_PATH_LEN] = {0};
    GetInstanceInfoStr(&(ctx->dyPrim), dyPriStr, MAX_PATH_LEN);
    char dyNorPriStr[MAX_PATH_LEN] = {0};
    GetInstanceInfoStr(&(ctx->dyNorPrim), dyNorPriStr, MAX_PATH_LEN);
    char staticPriStr[MAX_PATH_LEN] = {0};
    GetInstanceInfoStr(&(ctx->staPrim), staticPriStr, MAX_PATH_LEN);
    char pendingStaStr[MAX_PATH_LEN] = {0};
    GetInstanceInfoStr(&(ctx->pendStatus), pendingStaStr, MAX_PATH_LEN);
    char staNorStandbyStr[MAX_PATH_LEN] = {0};
    GetInstanceInfoStr(&(ctx->staNorStandby), staNorStandbyStr, MAX_PATH_LEN);
    char dyCascadeStr[MAX_PATH_LEN] = {0};
    GetInstanceInfoStr(&(ctx->dyCascade), dyCascadeStr, MAX_PATH_LEN);
    char staCascadeStr[MAX_PATH_LEN] = {0};
    GetInstanceInfoStr(&(ctx->staCasCade), staCascadeStr, MAX_PATH_LEN);
    write_runlog(LOG, "%s: instd(%u) staPrimary: [%s], dyPrimary: [%s], dyNorPrim: [%s], notPendCmd: [%s], "
                      "staNorStandby: [%s], cascade: [sta: (%s);  dy: (%s)].\n", instType->instTpStr, ctx->instId,
                 staticPriStr, dyPriStr, dyNorPriStr, pendingStaStr, staNorStandbyStr, staCascadeStr, dyCascadeStr);
}

static void GetInstanceInfo(DnArbCtx *ctx, const GetInstType *instType)
{
    int32 count = GetInstanceCountsInGroup(ctx->groupIdx);
    cm_instance_command_status *commd = ctx->repGroup->command_member;
    InitStatusInstance(ctx);
    for (int32 i = 0; i < count; ++i) {
        if (ctx->dnReport[i].local_status.local_role == INSTANCE_ROLE_PRIMARY) {
            InstanceInfoValues(ctx->groupIdx, i, &(ctx->dyPrim));
            if (ctx->dnReport[i].local_status.db_state == INSTANCE_HA_STATE_NORMAL) {
                InstanceInfoValues(ctx->groupIdx, i, &(ctx->dyNorPrim));
            }
        }
        if (g_instance_role_group_ptr[ctx->groupIdx].instanceMember[i].role == INSTANCE_ROLE_PRIMARY) {
            InstanceInfoValues(ctx->groupIdx, i, &(ctx->staPrim));
        }
        if (commd[i].command_status != INSTANCE_NONE_COMMAND || commd[i].pengding_command != MSG_CM_AGENT_BUTT) {
            InstanceInfoValues(ctx->groupIdx, i, &(ctx->pendStatus));
        }
        if (ctx->dnReport[i].local_status.local_role == INSTANCE_ROLE_STANDBY
            && ctx->dnReport[i].local_status.db_state == INSTANCE_HA_STATE_NORMAL) {
            InstanceInfoValues(ctx->groupIdx, i, &(ctx->staNorStandby));
        }
        if (ctx->dnReport[i].local_status.local_role == INSTANCE_ROLE_CASCADE_STANDBY) {
            InstanceInfoValues(ctx->groupIdx, i, &(ctx->dyCascade));
        }
        if (ctx->roleGroup->instanceMember[i].role == INSTANCE_ROLE_CASCADE_STANDBY) {
            InstanceInfoValues(ctx->groupIdx, i, &(ctx->staCasCade));
        }
    }
    PrintStanceInfo(ctx, instType);
}

static void CleanFailoverFlag(const DnArbCtx *ctx)
{
    if (ctx->dyNorPrim.count == 0) {
        return;
    }
    int32 count = GetInstanceCountsInGroup(ctx->groupIdx);
    for (int32 i = 0; i < count; ++i) {
        if (ctx->dnReport[i].arbitrateFlag) {
            write_runlog(LOG, "[clean arbitrateFlag], instance %u.\n", GetInstanceIdInGroup(ctx->groupIdx, i));
            ctx->dnReport[i].arbitrateFlag = false;
            ctx->repGroup->cma_kill_instance_timeout = 0;
        }
    }
}

static int32 GetAzIndex(DnArbCtx *ctx)
{
    int32 azIndex = 0;
    int32 az1Index = 1;
    int32 az2Index = 2;
    uint32 priority = ctx->localRole->azPriority;
    if (priority < g_az_master) {
        write_runlog(ERROR, "az name is %s, priority=%u is invalid.\n", ctx->localRole->azName, priority);
        return -1;
    } else if (priority >= g_az_master && priority < g_az_slave) {
        azIndex = az1Index;
    } else if (priority >= g_az_slave && priority < g_az_arbiter) {
        azIndex = az2Index;
    }
    if (current_cluster_az_status >= AnyAz1 && current_cluster_az_status <= FirstAz1) {
        ctx->curAzIndex = az1Index;
    } else if (current_cluster_az_status >= AnyAz2 && current_cluster_az_status <= FirstAz2) {
        ctx->curAzIndex = az2Index;
    }
    return azIndex;
}

uint32 GetPrimaryTerm(const DnArbCtx *ctx)
{
    int32 count = GetInstanceCountsInGroup(ctx->groupIdx);
    uint32 maxTerm = 0;
    for (int32 i = 0; i < count; ++i) {
        if (ctx->dnReport[i].local_status.local_role == INSTANCE_ROLE_PRIMARY) {
            if (maxTerm < GetInstanceTerm(ctx->groupIdx, i)) {
                maxTerm = GetInstanceTerm(ctx->groupIdx, i);
            }
        }
    }
    return maxTerm;
}

static bool DnArbitrateInAsync(DnArbCtx *ctx)
{
    if (g_needReloadSyncStandbyMode) {
        write_runlog(LOG, "line %d: wait to reload sync standby mode ddb value.\n", __LINE__);
        return true;
    }
    int azIndex = GetAzIndex(ctx);
    if (azIndex == -1) {
        return true;
    }
    bool isInSync = IsInSyncList(ctx->groupIdx, ctx->memIdx, INVALID_INDEX);
    bool isInVoteAz = (IsCurInstanceInVoteAz(ctx->groupIdx, ctx->memIdx) &&
        (cm_arbitration_mode == MAJORITY_ARBITRATION));
    if ((ctx->curAzIndex != 0 && ctx->curAzIndex != azIndex) || !isInSync || isInVoteAz) {
        int logLevel = isInVoteAz ? DEBUG1 : LOG;
        write_runlog(logLevel,
            "line %d: instanceId %u is in AZ%d, while current AZ is AZ%d, isInsync is %d, isInVoteAz is %d, "
            "do not arbitrate.\n", __LINE__, ctx->instId, azIndex, ctx->curAzIndex, isInSync, isInVoteAz);
        if (ctx->info.lockmode == PROHIBIT_CONNECTION || ctx->info.lockmode == SPECIFY_CONNECTION) {
            SendUnlockMessage(ctx, GetPrimaryTerm(ctx));
            write_runlog(LOG, "line %d: Unlock message has sent to instance %u.\n", __LINE__, ctx->instId);
        }
        if (ctx->info.dyRole == INSTANCE_ROLE_PENDING && IsTermLsnValid(ctx->info.term, ctx->info.lsn)) {
            SendNotifyMessage2Cma(ctx, INSTANCE_ROLE_STANDBY);
            write_runlog(LOG, "line %d: notify local datanode to standby in dedgraded AZ.\n", __LINE__);
        } else if (ctx->info.dyRole == INSTANCE_ROLE_PRIMARY) {
            if (ctx->info.dbState != INSTANCE_HA_STATE_DEMOTING) {
                SendRestartMsg(ctx, "[Async]");
                write_runlog(LOG, "line %d: dynamic primary in degraded AZ restart to pending.\n", __LINE__);
            }
        }
        return true;
    }
    return false;
}

static bool BuildPreCheck(const DnArbCtx *ctx)
{
    if (backup_open == CLUSTER_STREAMING_STANDBY) {
        return true;
    }

    if ((ctx->info.dyRole != INSTANCE_ROLE_STANDBY && ctx->info.dyRole != INSTANCE_ROLE_CASCADE_STANDBY) ||
        ctx->info.dbState != INSTANCE_HA_STATE_NEED_REPAIR) {
        return false;
    }

    if (ctx->dyNorPrim.count == 0) {
        if (ctx->dyPrim.count != 0 || log_min_messages <= DEBUG1) {
            write_runlog(WARNING, "Inst(%u): cannot send build msg, because primary[sta: %d, dy: %d, dyNor: %d].\n",
                ctx->instId, ctx->staPrim.count, ctx->dyPrim.count, ctx->dyNorPrim.count);
        }
        return false;
    }
    return true;
}

static void SendBuildMsg(const DnArbCtx *ctx)
{
    if (!BuildPreCheck(ctx)) {
        return;
    }
    const char *str = "[SendBuildMsg]";
    int32 buildReason = ctx->info.buildReason;
    if (CheckBuildCond(ctx->info.dbState, ctx->groupIdx, ctx->memIdx, buildReason, false)) {
        GroupStatusShow(str, ctx->groupIdx, ctx->instId, -1, false);
        db_state_role role;
        InitStateRole(&role, ctx);
        DatanodeBuildExec(ctx->recvMsgInfo, role, ctx->maintaMode);
    }
    return;
}

static bool InstanceIsCandicate(const DnArbCtx *ctx, int32 memIdx, bool isDynamicPrimary)
{
    /* instance in current az */
    int32 az1Index = 1;
    int32 az2Index = 2;
    int32 logLevel = (ctx->memIdx == memIdx) ? LOG : DEBUG1;
    // for more dn to choose to primary
    if (ctx->roleGroup->instanceMember[memIdx].role == INSTANCE_ROLE_CASCADE_STANDBY) {
        write_runlog(logLevel, "instd(%u) static role  is cascade standby.\n",
            GetInstanceIdInGroup(ctx->groupIdx, memIdx));
        return false;
    }
    if (!IsInstanceInCurrentAz(ctx->groupIdx, (uint32)memIdx, ctx->curAzIndex, az1Index, az2Index)) {
        write_runlog(logLevel, "instd(%u) isn't in current az.\n", GetInstanceIdInGroup(ctx->groupIdx, memIdx));
        return false;
    }

    /* instance in synclist */
    if (!IsInSyncList(ctx->groupIdx, memIdx, ctx->memIdx)) {
        write_runlog(logLevel, "instd(%u) isn't in syncList.\n", GetInstanceIdInGroup(ctx->groupIdx, memIdx));
        return false;
    }

    /* instance in vote az */
    if (isDynamicPrimary && IsCurInstanceInVoteAz(ctx->groupIdx, memIdx) &&
        (cm_arbitration_mode == MAJORITY_ARBITRATION)) {
        write_runlog(logLevel, "instd(%u) is in voteAZ.\n", GetInstanceIdInGroup(ctx->groupIdx, memIdx));
        return false;
    }

    /* node in minority az */
    if ((g_minorityAzName != NULL) && (!IsNodeInMinorityAz(ctx->groupIdx, memIdx))) {
        write_runlog(logLevel, "instd(%u, %s) is in minorityAZ(%s).\n", GetInstanceIdInGroup(ctx->groupIdx, memIdx),
            ctx->roleGroup->instanceMember[memIdx].azName, g_minorityAzName);
        return false;
    }

    return true;
}

static void ComputeSameAzDnCount(const DnArbCtx *ctx, int32 localMemIdx, int32 *dnCount)
{
    if (ctx->staPrim.count != 1 || ctx->staPrim.itStatus[0].memIdx < 0 || localMemIdx < 0) {
        return;
    }
    // only compute dn online
    if (ctx->dnReport[localMemIdx].local_status.local_role == INSTANCE_ROLE_UNKNOWN) {
        return;
    }
    // count = staticPrimary + sameAz
    int32 memIdx = ctx->staPrim.itStatus[0].memIdx;
    cm_instance_role_status *dnRole = ctx->roleGroup->instanceMember;
    if (strcmp(dnRole[memIdx].azName, dnRole[localMemIdx].azName) == 0) {
        ++(*dnCount);
    }
}

static void GetCandiCondInfo(DnArbCtx *ctx, int32 memIdx)
{
    ctx->cond.vaildCount++;
    ComputeSameAzDnCount(ctx, memIdx, &(ctx->cond.snameAzDnCount));
    if (ctx->cond.maxMemArbiTime < ctx->dnReport[memIdx].arbiTime) {
        ctx->cond.maxMemArbiTime = ctx->dnReport[memIdx].arbiTime;
    }
    if (ctx->dnReport[memIdx].local_status.local_role != INSTANCE_ROLE_UNKNOWN) {
        ctx->cond.onlineCount++;
    }
    if (ctx->repGroup->command_member[memIdx].pengding_command == MSG_CM_AGENT_SWITCHOVER) {
        ctx->cond.switchoverIdx = memIdx;
    }
}

static void GetCandiDyPrimaryInfo(DnArbCtx *ctx, int32 memIdx)
{
    if (ctx->dnReport[memIdx].local_status.local_role == INSTANCE_ROLE_PRIMARY) {
        ctx->cond.hasDynamicPrimary = true;
        ctx->cond.dyPrimIdx = memIdx;
        if (ctx->dnReport[memIdx].local_status.db_state == INSTANCE_HA_STATE_NORMAL) {
            ctx->cond.dyPrimNormalIdx = memIdx;
        }
        if (ctx->roleGroup->instanceMember[memIdx].role == INSTANCE_ROLE_PRIMARY) {
            ctx->cond.isPrimaryValid = true;
            ctx->cond.vaildPrimIdx = memIdx;
            if (ctx->dnReport[memIdx].local_status.db_state == INSTANCE_HA_STATE_DEMOTING) {
                ctx->cond.isPrimDemoting = true;
            }
        } else {
            ctx->cond.igPrimaryCount++;
            ctx->cond.igPrimaryIdx = memIdx;
        }
        (void)clock_gettime(CLOCK_MONOTONIC, &ctx->repGroup->finishredo_time);
    }
    if (ctx->roleGroup->instanceMember[memIdx].role == INSTANCE_ROLE_PRIMARY) {
        ctx->cond.staticPriIdx = memIdx;
    }
}

static void GetCandiCateLockMsg(DnArbCtx *ctx, int32 memIdx)
{
    if (ctx->dnReport[memIdx].local_status.disconn_mode == PROHIBIT_CONNECTION ||
        ctx->dnReport[memIdx].local_status.disconn_mode == PRE_PROHIBIT_CONNECTION) {
        ctx->cond.lock1Count++;
        if (ctx->dnReport[memIdx].local_status.local_role == INSTANCE_ROLE_STANDBY) {
            ComputeSameAzDnCount(ctx, memIdx, &(ctx->cond.snameAzRedoDoneCount));
            if (ctx->dnReport[memIdx].sendFailoverTimes < MAX_SEND_FAILOVER_TIMES) {
                ctx->cond.vaildCandiCount++;
            }
        }
    }

    if (ctx->dnReport[memIdx].local_status.disconn_mode == SPECIFY_CONNECTION) {
        ctx->cond.lock2Count++;
    }
}

static void GetCandiCateOtherMsg(DnArbCtx *ctx, int32 memIdx)
{
    if (ctx->dnReport[memIdx].local_status.db_state == INSTANCE_HA_STATE_BUILD_FAILED) {
        ctx->cond.buildCount++;
    }
    if (ctx->dnReport[memIdx].local_status.redo_finished) {
        ctx->cond.redoDone++;
    }
    if (ctx->dnReport[memIdx].sendFailoverTimes >= MAX_SEND_FAILOVER_TIMES) {
        ctx->cond.failoverNum++;
    }
}

static void GetCandiCateTermLsn(DnArbCtx *ctx, int32 memIdx)
{
    cm_local_replconninfo *localRepl = &(ctx->dnReport[memIdx].local_status);
    if (ctx->dyPrim.count == 0 && ctx->dnReport[memIdx].sendFailoverTimes >= MAX_SEND_FAILOVER_TIMES) {
        return;
    }

    if (XLByteWE_W_TERM(localRepl->term, localRepl->last_flush_lsn, ctx->cond.maxTerm, ctx->cond.maxLsn)) {
        ctx->cond.maxTerm = ctx->dnReport[memIdx].local_status.term;
        ctx->cond.maxLsn = ctx->dnReport[memIdx].local_status.last_flush_lsn;
    }

    if (ctx->dyPrim.count == 0 && localRepl->disconn_mode != PROHIBIT_CONNECTION &&
        localRepl->disconn_mode != PRE_PROHIBIT_CONNECTION) {
        return;
    }

    if (localRepl->local_role == INSTANCE_ROLE_STANDBY) {
        if (XLByteWE_W_TERM(localRepl->term, localRepl->last_flush_lsn,
            ctx->cond.standbyMaxTerm, ctx->cond.standbyMaxLsn)) {
            ctx->cond.standbyMaxTerm = localRepl->term;
            ctx->cond.standbyMaxLsn = localRepl->last_flush_lsn;
        }
    }
}

static void DnInstanceIsDegrade(DnArbCtx *ctx)
{
    if (ctx->cond.vaildCount + ctx->cond.voteAzCount + ctx->staCasCade.count < ctx->roleGroup->count) {
        ctx->cond.isDegrade = true;
    }
    if (ctx->cond.staticPriIdx != INVALID_INDEX) {
        ctx->cond.staticPrimaryDbstate = ctx->dnReport[ctx->cond.staticPriIdx].local_status.db_state;
    } else {
        write_runlog(LOG, "instance(%u) can not find static primary.\n", ctx->instId);
    }
}

static bool CanbeCandicate(const DnArbCtx *ctx, int32 memIdx, const CandicateCond *cadiCond)
{
    /* memIdx index is valid */
    if (memIdx == INVALID_INDEX) {
        return false;
    }
    /* Failover condition */
    if (cadiCond->mode == COS4FAILOVER) {
        /* memIdx failover times archive the most */
        if (ctx->dnReport[memIdx].sendFailoverTimes >= MAX_SEND_FAILOVER_TIMES) {
            return false;
        }
        /* memIdx is standby and has redo done */
        if (ctx->dnReport[memIdx].local_status.local_role != INSTANCE_ROLE_STANDBY ||
            ctx->dnReport[memIdx].local_status.disconn_mode != PROHIBIT_CONNECTION) {
            return false;
        }
    } else if (cadiCond->mode == COS4SWITCHOVER) {
        /* switchover condition */
        if (ctx->dnReport[memIdx].local_status.db_state != INSTANCE_HA_STATE_NORMAL) {
            return false;
        }
        if (!IsReadOnlyFinalState(ctx->groupIdx, memIdx, READ_ONLY_OFF)) {
            return false;
        }
    }
    uint32 localTerm = ctx->dnReport[memIdx].local_status.term;
    XLogRecPtr localLsn = ctx->dnReport[memIdx].local_status.last_flush_lsn;

    /* term and lsn is the most */
    if (!XLByteEQ_W_TERM(ctx->cond.standbyMaxTerm, ctx->cond.standbyMaxLsn, localTerm, localLsn)) {
        return false;
    }
    return true;
}

uint32 GetAvaiSyncDdbInstId()
{
    static char key[MAX_PATH_LEN] = "/most_available_sync";
    char value[MAX_PATH_LEN] = {0};
    DDB_RESULT ddbResult = SUCCESS_GET_VALUE;
    if (GetKVFromDDb(key, MAX_PATH_LEN, value, MAX_PATH_LEN, &ddbResult) != CM_SUCCESS) {
        write_runlog(ERROR, "[GetAvaiSyncDdbInstId] get key %s from ddb failed: %d.\n", key, (int)ddbResult);
        return 0;
    }
    uint32 instID = (uint32)atoi(value);
    return instID;
}

void ChooseMostAvailableSyncOnTobaCandicate(DnArbCtx *ctx, const CandicateCond *cadiCond)
{
    if (g_enableSetMostAvailableSync && g_cm_server_num > CMS_ONE_PRIMARY_ONE_STANDBY) {
        uint32 instId = GetAvaiSyncDdbInstId();
        if (instId != 0) {
            write_runlog(WARNING, "[ChooseMostAvailableSyncOnTobaCandicate] instanceId(%u)"
                "most_available_sync is on.\n", instId);
            for (int32 i = 0; i < ctx->roleGroup->count; ++i) {
                if (ctx->roleGroup->instanceMember[i].instanceId == instId) {
                    write_runlog(WARNING, "[ChooseMostAvailableSyncOnTobaCandicate] instanceId(%u)"
                        " most_available_sync is on, choose to be candidate.\n", instId);
                    ctx->cond.candiIdx = i;
                    return;
                }
            }
        }
    }
}

static void ChooseStaticPrimaryTobeCandicate(DnArbCtx *ctx, const CandicateCond *cadiCond)
{
    if (ctx->cond.candiIdx != INVALID_INDEX) {
        return;
    }
    int32 staticPriIdx = ctx->cond.staticPriIdx;
    /* no static primary */
    if (CanbeCandicate(ctx, staticPriIdx, cadiCond)) {
        ctx->cond.candiIdx = staticPriIdx;
    }
}

static void ChooseCandicateIdxFromOther(DnArbCtx *ctx, const CandicateCond *cadiCond)
{
    /* the static primary may be the best choice */
    if (ctx->cond.candiIdx != INVALID_INDEX) {
        return;
    }
    int32 candiIdx = INVALID_INDEX;
    cm_instance_role_status *roleMember = ctx->roleGroup->instanceMember;
    for (int32 i = 0; i < ctx->roleGroup->count; ++i) {
        if (!InstanceIsCandicate(ctx, i, true)) {
            continue;
        }
        if (!CanbeCandicate(ctx, i, cadiCond)) {
            continue;
        }
        /* the smaller instanceId is the prefer choice */
        if (candiIdx == INVALID_INDEX) {
            candiIdx = i;
        }
        /* the smaller azPriority is the perfer choice */
        if (roleMember[candiIdx].azPriority > roleMember[i].azPriority) {
            candiIdx = i;
        }
        /* if the azName of instance is same with static primary, it is the perfer choice */
        if (ctx->cond.staticPriIdx == INVALID_INDEX) {
            continue;
        }
        if (strcmp(roleMember[i].azName, roleMember[ctx->cond.staticPriIdx].azName) == 0) {
            candiIdx = i;
            break;
        }
    }
    ctx->cond.candiIdx = candiIdx;
}

static void GetCandicateIdx(DnArbCtx *ctx, const CandicateCond *cadiCond)
{
    ctx->cond.candiIdx = -1;
    const char *str = "[GetCandicate]";
    if (cadiCond->mode == COS4FAILOVER && ctx->cond.dyPrimNormalIdx != INVALID_INDEX &&
        ctx->cond.vaildPrimIdx != INVALID_INDEX) {
        write_runlog(DEBUG1, "%s, instanceId(%u), this group has dynamic primary(%d), validPrimIdx is %d, "
            "not need to choose candicate.\n", str, ctx->instId, ctx->cond.dyPrimNormalIdx, ctx->cond.vaildPrimIdx);
        return;
    }
    /* max term and lsn is valid */
    if (!IsTermLsnValid(ctx->cond.standbyMaxTerm, ctx->cond.standbyMaxLsn)) {
        write_runlog(LOG, "%s, instanceId(%u) standbyMaxTerm or standbyMaxLsn is invalid.\n", str, ctx->instId);
        return;
    }
    /* if dcc most_available_sync is on, choose that dn*/
    ChooseMostAvailableSyncOnTobaCandicate(ctx, cadiCond);
    /* choose static primary  */
    ChooseStaticPrimaryTobeCandicate(ctx, cadiCond);
    /* static primary cannot be candicate */
    ChooseCandicateIdxFromOther(ctx, cadiCond);
}

static void PrintCandiMsg(DnArbCtx *ctx, const char *str, const CandicateCond *cadiCond)
{
    const uint32 arbit_static_interval = 5;
    /* if in switchover condition, it needs to print msg. */
    if (ctx->cond.maxMemArbiTime < arbit_static_interval && log_min_messages > DEBUG1 &&
        cadiCond->mode == COS4FAILOVER) {
        return;
    }
    uint32 localTerm = ctx->info.term;
    XLogRecPtr localLsn = ctx->info.lsn;
    uint32 groupTerm = ctx->repGroup->term;
    DnInstInfo instInfo = {{0}};
    GetDnIntanceInfo(ctx, &instInfo);
    ArbiCond *cond = &(ctx->cond);
    write_runlog(LOG, "%s, instanceId(%d: %u), mode is %d, find the best candicate is %d, "
        " primary Idx is [static: %d:%d, dynamic: %d:%d, dynormal: %d:%d, vaildPrim: %d, demoting: %d], "
        "isReduced is [isReduced: %d, vaildCandiCount: %d, vaildCount: %d, onlineCount:%d], sameAz is [%d: %d], "
        "lock msg is [lock1: %d, lock2: %d, redoFinish: [local: %d, group: %d]], "
        "arbitrateTime is [local: %u, max: %u, delay is %u], "
        "termAndLsn is [InCond:[max: (%u, %X/%X), local: (%u, %X/%X)], noCond:[term: %u], group: %u], "
        "listStr is [curSync: [%s], expSync: [%s], voteAz: [%s]], cascade is [sta: [%s], dy: [%s]]"
        "localMsg is [dbState: %d=%s, maxSendTime: %u, dbRestart: %d, buildReason: %d=%s, disconn is "
        "[mode: %u=%s, host: %s, port: %u]], "
        "azIndex is [cur: %d, master: %u, slave: %u, arbiter: %u] "
        "azName is %s, minorityAzName is %s.\n",
        str, ctx->memIdx, ctx->instId, cadiCond->mode, cond->candiIdx,
        cond->staticPriIdx, ctx->staPrim.count, cond->dyPrimIdx, ctx->dyPrim.count, cond->dyPrimNormalIdx,
        ctx->dyNorPrim.count, cond->vaildPrimIdx, cond->isPrimDemoting,
        cond->isDegrade, cond->vaildCandiCount, cond->vaildCount, cond->onlineCount,
        cond->snameAzDnCount, cond->snameAzRedoDoneCount,
        cond->lock1Count, cond->lock2Count, ctx->localRep->local_status.redo_finished, ctx->repGroup->finish_redo,
        cond->localArbiTime, cond->maxMemArbiTime, g_delayArbiTime,
        cond->maxTerm, (uint32)(cond->maxLsn >> 32), (uint32)cond->maxLsn, localTerm, (uint32)(localLsn >> 32),
        (uint32)localLsn, ctx->maxTerm, groupTerm,
        instInfo.curSl, instInfo.expSl, instInfo.voteL, instInfo.stCasL, instInfo.dyCasL,
        ctx->info.dbState, datanode_dbstate_int_to_string(ctx->info.dbState), ctx->info.sendFailoverTimes,
        ctx->info.dbRestart, ctx->info.buildReason, datanode_rebuild_reason_int_to_string(ctx->info.buildReason),
        ctx->info.lockmode, DatanodeLockmodeIntToString(ctx->info.lockmode), ctx->localRep->local_status.disconn_host,
        ctx->localRep->local_status.disconn_port,
        ctx->curAzIndex, g_az_master, g_az_slave, g_az_arbiter,
        ctx->localRole->azName, g_minorityAzName);
}

static void CleanArbiTime(DnArbCtx *ctx)
{
    ArbiCond *cond = &(ctx->cond);
    if (backup_open == CLUSTER_PRIMARY) {
        if (!cond->hasDynamicPrimary && (cond->vaildCandiCount < HALF_COUNT(cond->vaildCount + 1) ||
            cond->instMainta)) {
            ClearDnArbiCond(ctx->groupIdx, CLEAR_SEND_FAILOVER_TIMES);
        }
    } else {
        if (cond->failoverNum == cond->vaildCount || cond->instMainta) {
            ClearDnArbiCond(ctx->groupIdx, CLEAR_SEND_FAILOVER_TIMES);
        }
    }

    if (cond->isPrimaryValid && cond->igPrimaryCount == 0) {
        ctx->repGroup->time = 0;
        ClearDnArbiCond(ctx->groupIdx, CLEAR_ALL);
        cond->maxMemArbiTime = 0;
    }
}

static void GetCandiMsgAndIdx(DnArbCtx *ctx)
{
    for (int32 i = 0; i < ctx->roleGroup->count; ++i) {
        bool isDynamicPri = ctx->dnReport[i].local_status.local_role != INSTANCE_ROLE_PRIMARY;
        if (!InstanceIsCandicate(ctx, i, isDynamicPri)) {
            continue;
        }
        GetCandiCondInfo(ctx, i);
        GetCandiDyPrimaryInfo(ctx, i);
        GetCandiCateLockMsg(ctx, i);
        GetCandiCateOtherMsg(ctx, i);
        GetCandiCateTermLsn(ctx, i);
    }
    /* dn is reduce synclist */
    DnInstanceIsDegrade(ctx);
    CleanArbiTime(ctx);
    CandicateCond cadiCond = {COS4FAILOVER};
    GetCandicateIdx(ctx, &cadiCond);
    PrintCandiMsg(ctx, "[PrintCandiMsg]", &cadiCond);
}

static void GetCandiMsgAndIdxBackup(DnArbCtx *ctx)
{
    for (int32 i = 0; i < ctx->roleGroup->count; ++i) {
        GetCandiInfoBackup(ctx, i);
    }

    if (ctx->cond.staticPriIdx != INVALID_INDEX) {
        ctx->cond.staticPrimaryDbstate = ctx->dnReport[ctx->cond.staticPriIdx].local_status.db_state;
    } else {
        write_runlog(LOG, "instance(%u) can not find static primary.\n", ctx->instId);
    }

    if (ctx->cond.isPrimaryValid && ctx->cond.igPrimaryCount == 0) {
        ctx->repGroup->time = 0;
        ClearDnArbiCond(ctx->groupIdx, CLEAR_ALL);
        ctx->cond.maxMemArbiTime = 0;
    }
    CandicateCond cadiCond = {COS4FAILOVER};
    GetCandicateIdxBackup(ctx, &cadiCond);
    PrintCandiMsg(ctx, "[PrintCandiMsg]", &cadiCond);
}

static void SendFinishRedoMsg(const DnArbCtx *ctx, const char* str)
{
    SendFinishRedoMessage(ctx);
    if (!ctx->localRep->is_finish_redo_cmd_sent) {
        ctx->localRep->is_finish_redo_cmd_sent = true;
    }
    write_runlog(LOG, "%s, send finish redo msg to instance(%u).\n", str, ctx->instId);
}

static bool CanSendFinishRedoMsg(DnArbCtx *ctx)
{
    if (ctx->cond.hasDynamicPrimary || ctx->localRep->local_status.redo_finished) {
        return false;
    }
    struct timespec previous_time = ctx->repGroup->finishredo_time;
    ArbiCond *cond = &(ctx->cond);
    const char *str = "[SendFinishRedo]";
    if (force_promote == 1 && cond->onlineCount > HALF_COUNT(cond->vaildCount) && previous_time.tv_sec > 0) {
        struct timespec current_time = {0, 0};
        (void)clock_gettime(CLOCK_MONOTONIC, &current_time);
        if (current_time.tv_sec - previous_time.tv_sec > (long)switch_rto) {
            SendFinishRedoMsg(ctx, str);
            write_runlog(LOG, "%s, line %d: Finish redo message sent to instance %u, switch_rto (%d) timeout.\n",
                str, __LINE__, ctx->instId, switch_rto);
            return true;
        }
    }
    if (ctx->repGroup->finish_redo) {
        SendFinishRedoMsg(ctx, str);
        write_runlog(LOG, " %s, line %d: Finish redo message sent to instance %u, requested by cm_ctl.\n",
            str, __LINE__, ctx->instId);
        return true;
    }
    return false;
}

static bool SyncFinishRedoNew(const DnArbCtx *ctx, const char* str)
{
    /* generate key path in ddb */
    char statusKey[MAX_PATH_LEN] = {0};
    char value[MAX_DN_NUM] = {0};
    errno_t rc = snprintf_s(statusKey, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/finish_redo_status", pw->pw_name);
    securec_check_intval(rc, (void)rc);
    rc = memset_s(value, sizeof(value), '2', sizeof(value) - 1);
    securec_check_errno(rc, (void)rc);

    ctx->repGroup->finish_redo = false;
    write_runlog(LOG, "%s, line %d: Group %u has been recovered, finish_redo flag has been reset.\n",
        str, __LINE__, ctx->groupIdx);

    /* '0' means false, '1' means true, '2' means null */
    for (uint32 i = 0; i < g_dynamic_header->relationCount; i++) {
        if (g_instance_role_group_ptr[i].instanceMember[0].instanceType != INSTANCE_TYPE_DATANODE) {
            continue;
        }
        uint32 index = g_instance_role_group_ptr[i].instanceMember[0].instanceId - 6001;
        if (i == ctx->groupIdx) {
            value[index] = '0';
            continue;
        }
        if (g_instance_group_report_status_ptr[i].instance_status.finish_redo) {
            value[index] = '1';
        } else {
            value[index] = '0';
        }
    }
    write_runlog(LOG, "%s, %d: %u, Ddb set finish_redos flag. key = %s, value = %s.\n", str, __LINE__,
        ctx->instId, statusKey, value);

    (void)pthread_rwlock_wrlock(&g_finish_redo_rwlock);
    status_t st = SetKV2Ddb(statusKey, MAX_PATH_LEN, value, MAX_PATH_LEN, NULL);
    if (st != CM_SUCCESS) {
        (void)pthread_rwlock_unlock(&g_finish_redo_rwlock);
        write_runlog(ERROR, "%s, %d: %u, Ddb set finish_redos flag failed. key = %s, value = %s.\n",
            str, __LINE__, ctx->instId, statusKey, value);
        return true;
    }
    (void)pthread_rwlock_unlock(&g_finish_redo_rwlock);
    return false;
}

static bool SyncFinishRedoOld(const DnArbCtx *ctx, const char *str)
{
    char statKey[MAX_PATH_LEN] = {0};
    errno_t rc = snprintf_s(statKey, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/finish_redo/%u", pw->pw_name, ctx->groupIdx);
    securec_check_intval(rc, (void)rc);

    (void)pthread_rwlock_wrlock(&g_finish_redo_rwlock);
    status_t st = SetKV2Ddb(statKey, MAX_PATH_LEN, "false", (uint32)strlen("false"), NULL);
    if (st != CM_SUCCESS) {
        write_runlog(ERROR, "%s, Ddb set finish_redo flag failed. key = %s, value = false.\n", str, statKey);
        (void)pthread_rwlock_unlock(&g_finish_redo_rwlock);
        return true;
    }
    (void)pthread_rwlock_unlock(&g_finish_redo_rwlock);

    ctx->repGroup->finish_redo = false;
    write_runlog(LOG, "%s, line %d: instanceId %u groupIdx is %u has been recovered, finish_redo flag "
        "has been reset.\n", str, __LINE__, ctx->instId, ctx->groupIdx);
    return false;
}

static bool SyncFinishRedoWithDdb(const DnArbCtx *ctx)
{
    if (!ctx->repGroup->finish_redo || !ctx->cond.isPrimaryValid) {
        return false;
    }
    const char *str = "[SyncFinishRedo]";
    bool res = false;
    if (undocumentedVersion == 0 || undocumentedVersion >= 92214) {
        res = SyncFinishRedoNew(ctx, str);
    } else {
        res = SyncFinishRedoOld(ctx, str);
    }
    return res;
}

static bool InstanceForceFinishRedo(DnArbCtx *ctx)
{
    /* force finish redo, the data may be lost, this action is very dangerous. */
    bool res = CanSendFinishRedoMsg(ctx);
    if (res) {
        return true;
    }
    res = SyncFinishRedoWithDdb(ctx);
    if (res) {
        return true;
    }
    /* find the valid primary, set instance finish redo cmd sent false */
    if (ctx->cond.isPrimaryValid && ctx->localRep->is_finish_redo_cmd_sent) {
        ctx->localRep->is_finish_redo_cmd_sent = false;
    }
    return false;
}

static int32 GetFailoverMsgStaPriID(DnArbCtx *ctx)
{
    ArbiCond *cond = &(ctx->cond);
    if (cond->staticPriIdx != INVALID_INDEX) {
        cm_instance_role_status *role = ctx->roleGroup->instanceMember;
        return role[cond->staticPriIdx].instanceId;
    }
    return INVALID_INDEX;
}

static bool CheckAvailSyncDdb(DnArbCtx *ctx)
{
    if (g_enableSetMostAvailableSync && g_cm_server_num > CMS_ONE_PRIMARY_ONE_STANDBY) {
        uint32 instId = GetAvaiSyncDdbInstId();
        if (instId != 0 && instId != ctx->instId) {
            write_runlog(WARNING, "[CheckAvailSyncDdb], line %d: instance %u most_available_sync is on, "
                "can not send failover message to %u\n", __LINE__, instId, ctx->instId);
            return false;
        }
    }
    return true;
}

/*
 * check whether most_available_sync is on
 * if on:
 * do not need to restart this dn, just restart another fake primary dn.
 */
static bool CheckRestart2AvaiSyncDdb(DnArbCtx *ctx)
{
    if (g_enableSetMostAvailableSync && g_cm_server_num > CMS_ONE_PRIMARY_ONE_STANDBY) {
        uint32 instId = GetAvaiSyncDdbInstId();
        if (instId != 0 && instId == ctx->instId) {
            return true;
        }
    }
    return false;
}

static bool InstanceForceFailover(DnArbCtx *ctx)
{
    bool res = InstanceForceFinishRedo(ctx);
    if (res) {
        return true;
    }

    /* force to send failover */
    ArbiCond *cond = &(ctx->cond);
    /* redo_finish flag */
    if (!cond->hasDynamicPrimary && ctx->repGroup->finish_redo && ctx->localRep->local_status.redo_finished) {
        if (!CheckAvailSyncDdb(ctx)) {
            return false;
        }
        /* candicate neets quarm */
        bool isMajority = cond->onlineCount > HALF_COUNT(cond->vaildCount) ? true : false;
        if (cond->candiIdx == ctx->memIdx && CanFailoverDn(isMajority) &&
            cond->redoDone > HALF_COUNT(cond->vaildCount)) {
            cm_to_agent_failover failoverMsg;
            int32 staPrimId = GetFailoverMsgStaPriID(ctx);
            send_failover_message(ctx->recvMsgInfo, ctx->node, ctx->instId, ctx->groupIdx,
                ctx->memIdx, &failoverMsg, staPrimId);
            write_runlog(LOG, "[ForceFailover], line %d: Redo done, non force failover message sent to instance %u, "
                "requested by cm_ctl, arbitrate_time=%u\n", __LINE__, ctx->instId, cond->maxMemArbiTime);
            return true;
        }
    }
    return false;
}

bool IsCurrentNodeDorado(uint32 node)
{
    if (!GetIsSharedStorageMode() || strcmp(g_doradoIp, "unknown") == 0 || g_doradoIp[0] == '\0') {
        return false;
    }

    for (uint32 i = 0; i < g_node_num; ++i) {
        if (g_node[i].node != node) {
            continue;
        }
        if (strcmp(g_node[i].sshChannel[0], g_doradoIp) == 0) {
            return true;
        }
        return false;
    }

    return false;
}

static void ArbitrateUnkownInstance(const DnArbCtx *ctx, const char *typeName)
{
    if (IsCurrentNodeDorado(ctx->node)) {
        write_runlog(DEBUG5, "node %u is dorado, not need print unknown instance.\n", ctx->node);
        return;
    }
    write_runlog(ERROR, "%s,line %d: localrole=[%d=%s: %d=%s] (node:%u  instanceid:%d/%u), termlsn is [%u, %X/%X], "
        "dbState is %d=%s, buildReason: %d=%s, lockmode: %u=%s.\n",
        typeName, __LINE__, ctx->localRole->role, datanode_role_int_to_string(ctx->localRole->role),
        ctx->info.dyRole, datanode_role_int_to_string(ctx->info.dyRole),
        ctx->node, ctx->memIdx, ctx->instId, ctx->info.term, (uint32)(ctx->info.lsn >> 32), (uint32)ctx->info.lsn,
        ctx->info.dbState, datanode_dbstate_int_to_string(ctx->info.dbState),
        ctx->info.buildReason, datanode_rebuild_reason_int_to_string(ctx->info.buildReason),
        ctx->info.lockmode, DatanodeLockmodeIntToString(ctx->info.lockmode));
}

static void ArbitratePendingInstance(const DnArbCtx *ctx, const char *typeName)
{
    if (IsTermLsnValid(ctx->info.term, ctx->info.lsn)) {
        GroupStatusShow(typeName, ctx->groupIdx, ctx->instId, -1, false);
        SendNotifyMessage2Cma(ctx, INSTANCE_ROLE_STANDBY);
        write_runlog(LOG, "%s, line %d: notify local datanode(%u) to standby.\n", typeName, __LINE__, ctx->instId);
    } else {
        ArbitrateUnkownInstance(ctx, typeName);
    }
}

static bool MoreDyPrimary(DnArbCtx *ctx, const char *typeName)
{
    if (backup_open == CLUSTER_STREAMING_STANDBY) {
        if (ctx->cond.igPrimaryCount >= 1 && ctx->instId != ctx->repGroup->lastFailoverDn) {
            SendRestartMsg(ctx, typeName);
            write_runlog(LOG, "Dynamic primary %u is not last failover dn, restart to cascade_standby.\n", ctx->instId);
            return true;
        }
        return false;
    }

    /* restart dn instance */
    if (ctx->info.dbRestart) {
        GroupStatusShow(typeName, ctx->groupIdx, ctx->instId, ctx->cond.vaildCount, ctx->cond.finishRedo);
         /*
          * stop instance only when
          * enable CM cluster auto failover and unable DB cluster auto crash recovery in two node deployment arch
          */
        if (ENABLED_AUTO_FAILOVER_ON2NODES(g_cm_server_num, g_paramsOn2Nodes.cmsEnableFailoverOn2Nodes) &&
            !g_paramsOn2Nodes.cmsEnableDbCrashRecovery) {
            write_runlog(ERROR,
                "%s, line %d: split brain failure in db service, more dynamic primary and their term(%u) "
                "are the most(%u). Due to auto crash recovery is disabled, no need send restart msg to instance(%u) "
                "that had been restarted, waiting for manual intervention.\n",
                typeName, __LINE__, ctx->info.term, ctx->maxTerm, ctx->instId);

            /* compare local term, local lsn, noidid */
            if (XLByteWE_W_TERM(ctx->maxTerm, ctx->cond.maxLsn,
                ctx->dnReport[ctx->memIdx].local_status.term, ctx->dnReport[ctx->memIdx].local_status.last_flush_lsn) ||
                IsInstanceIdMax(ctx)) {
                ReportClusterDoublePrimaryAlarm(
                    ALM_AT_Event,
                    ALM_AI_DbInstanceDoublePrimary,
                    ctx->instId,
                    SERVICE_TYPE_DB);

                /* try to stop fake primary db instance from cms */
                StopFakePrimaryResourceInstance(ctx);
            }
        } else {
            /* dn most_available_sync is on, do not need to restart */
            if (CheckRestart2AvaiSyncDdb(ctx)) {
                write_runlog(LOG, "%s, line %d: instance %u most_available_sync is on, "
                    "not need to restart.\n",
                    typeName, __LINE__, ctx->instId);
                ctx->repGroup->arbitrate_status_member[ctx->memIdx].restarting = false;
                return true;
            }
            SendRestartMsg(ctx, typeName);
            write_runlog(LOG, "%s, line %d: more dynamic primary and their term(%u) are the most(%u), "
                "send restart msg to instance(%u) that had been restarted.\n",
                typeName, __LINE__, ctx->info.term, ctx->maxTerm, ctx->instId);
            ctx->repGroup->arbitrate_status_member[ctx->memIdx].restarting = false;
        }
        return true;
    }

    if (ctx->dyNorPrim.count == 1 || TermIsInvalid(ctx->maxTerm)) {
        return false;
    }

    int32 count = 0;
    int32 memIdx = -1;
    for (int32 i = 0; i < ctx->dyNorPrim.count; ++i) {
        /* dn instance is not in synclist, cannot be restart here */
        if (!InstanceIsCandicate(ctx, ctx->dyNorPrim.itStatus[i].memIdx, true)) {
            continue;
        }
        if (ctx->dyNorPrim.itStatus[i].term == ctx->maxTerm) {
            ctx->repGroup->arbitrate_status_member[ctx->dyNorPrim.itStatus[i].memIdx].restarting = true;
            memIdx = ctx->dyNorPrim.itStatus[i].memIdx;
            count++;
        }
    }
    
    /* only one dynamic primary term is the most, so cannot be restart here, and clear the mark */
    if (count == 1 && memIdx != -1) {
        ctx->repGroup->arbitrate_status_member[memIdx].restarting = false;
    }

    /* restart dn instance */
    if (ctx->repGroup->arbitrate_status_member[ctx->memIdx].restarting) {
        GroupStatusShow(typeName, ctx->groupIdx, ctx->instId, ctx->cond.vaildCount, ctx->cond.finishRedo);
         /*
          * stop instance only when
          * enable CM cluster auto failover and unable DB cluster auto crash recovery in two node deployment arch
          */
        if (ENABLED_AUTO_FAILOVER_ON2NODES(g_cm_server_num, g_paramsOn2Nodes.cmsEnableFailoverOn2Nodes) &&
            !g_paramsOn2Nodes.cmsEnableDbCrashRecovery) {
            write_runlog(ERROR,
                "%s, line %d: split brain failure in db service, more dynamic primary and their term(%u) "
                "are the most(%u). Due to auto crash recovery is disabled, no need send restart msg to instance(%u),  "
                "waiting for manual intervention.\n", typeName, __LINE__, ctx->info.term, ctx->maxTerm, ctx->instId);

            /* compare local term, local lsn, noidid */
            if (XLByteWE_W_TERM(ctx->maxTerm, ctx->cond.maxLsn,
                ctx->dnReport[memIdx].local_status.term, ctx->dnReport[memIdx].local_status.last_flush_lsn) ||
                IsInstanceIdMax(ctx)) {
                ReportClusterDoublePrimaryAlarm(
                    ALM_AT_Event,
                    ALM_AI_DbInstanceDoublePrimary,
                    ctx->instId,
                    SERVICE_TYPE_DB);

                /* try to stop fake primary db instance from cms */
                StopFakePrimaryResourceInstance(ctx);
            }
        } else {
            /* dn most_available_sync is on, do not need to restart */
            if (CheckRestart2AvaiSyncDdb(ctx)) {
                write_runlog(LOG, "%s, line %d: instance %u most_available_sync is on, "
                    "not need to restart.\n",
                    typeName, __LINE__, ctx->instId);
                ctx->repGroup->arbitrate_status_member[ctx->memIdx].restarting = false;
                return true;
            }
            SendRestartMsg(ctx, typeName);
            write_runlog(LOG, "%s, line %d: more dynamic primary and their term(%u) are the most(%u), "
                "send restart msg to instance(%u).\n", typeName, __LINE__, ctx->info.term, ctx->maxTerm, ctx->instId);
            ctx->repGroup->arbitrate_status_member[ctx->memIdx].restarting = false;
        }

        return true;
    }
    return false;
}

static void PrintPrimMsg(DnArbCtx *ctx, const char *typeName, const char *logMsg)
{
    ArbiCond *cond = &(ctx->cond);
    /* no primary dn don't need to print msg. */
    if (log_min_messages > DEBUG1 && cond->dyPrimIdx == INVALID_INDEX) {
        return;
    }
    write_runlog(LOG, "%s, instance:[%d: %u], %s, "
        "primary Idx is [static: %d:%d, dynamic: %d:%d, dyNormal: %d:%d, vaildPrim: %d, demoting: %d], "
        "term is [inCond: [local: %u, max: %u], noCond: %u, group: %u], "
        "local msg is [dbState: %d=%s, send_failover_times: %u].\n",
        typeName, ctx->memIdx, ctx->instId, logMsg,
        cond->staticPriIdx, ctx->staPrim.count, cond->dyPrimIdx, ctx->dyPrim.count, cond->dyPrimNormalIdx,
        ctx->dyNorPrim.count, cond->vaildPrimIdx, cond->isPrimDemoting,
        ctx->info.term, cond->maxTerm, ctx->maxTerm, ctx->repGroup->term,
        ctx->info.dbState, datanode_dbstate_int_to_string(ctx->info.dbState), ctx->info.sendFailoverTimes);
}

static void ChangeStaticPrimary(DnArbCtx *ctx, const char *typeName)
{
    ArbiCond *cond = &(ctx->cond);
    if (cond->staticPriIdx == ctx->memIdx && ctx->info.term == cond->maxTerm && ctx->staPrim.count == 1) {
        return;
    }

    PrintPrimMsg(ctx, typeName, "will change static primary");

    if (ctx->info.term < cond->maxTerm || (!cond->isPrimDemoting && ctx->info.term < ctx->repGroup->term)) {
        if (ctx->info.dbState == INSTANCE_HA_STATE_NORMAL && !TermIsInvalid(ctx->info.term)) {
            GroupStatusShow(typeName, ctx->groupIdx, ctx->instId, cond->vaildCount, cond->finishRedo);
            SendRestartMsg(ctx, typeName);
            write_runlog(LOG,
                "%s line %d: dynamic primary is not static primary datanode instance, "
                "restart to pending.\n",
                typeName, __LINE__);
            return;
        }
    }

    /* change dn static primary with dynamic primary */
    if ((ctx->info.term == cond->maxTerm) ||
        (ctx->info.term > ctx->cond.maxTerm && ctx->info.sendFailoverTimes >= MAX_SEND_FAILOVER_TIMES)) {
        GroupStatusShow(typeName, ctx->groupIdx, ctx->instId, cond->vaildCount, cond->finishRedo);
        ChangeDnPrimaryMemberIndex(ctx->groupIdx, ctx->memIdx);
        cm_pending_notify_broadcast_msg(ctx->groupIdx, ctx->instId);
        write_runlog(LOG, "%s, line %d: set instance %u to be static primary.\n", typeName, __LINE__, ctx->instId);
    }
}

static bool IsInstanceNoCmd(const DnArbCtx *ctx, const char *str)
{
    if (ctx->pendStatus.count == 0) {
        return true;
    }
    int32 memIdx = ctx->pendStatus.itStatus[0].memIdx;
    uint32 instId = ctx->pendStatus.itStatus[0].instId;
    cm_instance_command_status *commd = ctx->repGroup->command_member;
    write_runlog(WARNING, "%s, %u: another instance (%u) is doing[%d/%d], pendStatus count is %d, "
        "cannot to do arbitrate.\n", str, ctx->instId, instId, commd[memIdx].command_status,
        commd[memIdx].pengding_command, ctx->pendStatus.count);
    return false;
}

static void SendSwitchoverMessage(const DnArbCtx *ctx, int32 memIdx, const char *str)
{
    if (IsMaintenanceModeDisableOperation(CMS_SWITCHOVER_DN, ctx->maintaMode) || backup_open != CLUSTER_PRIMARY) {
        write_runlog(LOG, "%s, %u Maintaining cluster: cm server cannot switchover dn.\n", str, ctx->instId);
        return;
    }
    ctx->repGroup->command_member[memIdx].command_status = INSTANCE_COMMAND_WAIT_EXEC;
    ctx->repGroup->command_member[memIdx].pengding_command = (int)MSG_CM_AGENT_SWITCHOVER;
    ctx->repGroup->command_member[memIdx].time_out = SWITCHOVER_DEFAULT_WAIT;
    ctx->repGroup->command_member[memIdx].cmdPur = INSTANCE_ROLE_PRIMARY;
    ctx->repGroup->command_member[memIdx].cmdSour = INSTANCE_ROLE_STANDBY;
    ctx->repGroup->command_member[memIdx].peerInstId = ctx->instId;
    SetSendTimes(ctx->groupIdx, memIdx, SWITCHOVER_DEFAULT_WAIT);
    GroupStatusShow(str, ctx->groupIdx, ctx->instId, ctx->cond.vaildCount, ctx->cond.finishRedo);
    write_runlog(LOG, "%s, DN(%u) will automatically switchover.\n", str, GetInstanceIdInGroup(ctx->groupIdx, memIdx));
}

static bool DyPrimaryNeedToSwitchover(DnArbCtx *ctx, const char *str)
{
    int32 dnRestartCounts = ctx->localRep->dn_restart_counts;
    int32 dnRestartCountsInHour = ctx->localRep->dn_restart_counts_in_hour;
    bool readOnly = IsReadOnlyFinalState(ctx->groupIdx, ctx->memIdx, READ_ONLY_ON);
    if (dnRestartCounts <= DN_RESTART_COUNTS && dnRestartCountsInHour <= DN_RESTART_COUNTS_IN_HOUR && !readOnly) {
        return false;
    }
    CandicateCond cadiCond = {COS4SWITCHOVER};
    GetCandicateIdx(ctx, &cadiCond);
    PrintCandiMsg(ctx, str, &cadiCond);
    if (ctx->cond.candiIdx == -1) {
        write_runlog(LOG, "%s, %u: cannot find candicate to be primary by switchover.\n", str, ctx->instId);
        return false;
    }
    write_runlog(LOG, "%s: the primary dn(%u) restarts count: %d in 10 min, %d in hour, has delay timeout(%u).\n", str,
        ctx->instId, dnRestartCounts, dnRestartCountsInHour, instance_failover_delay_timeout);
    SendSwitchoverMessage(ctx, ctx->cond.candiIdx, str);
    return true;
}

static bool DyPrimaryIsUnheal(DnArbCtx *ctx, const char *str)
{
    /* dynamic primary term or lsn is invalid */
    if (!IsTermLsnValid(ctx->info.term, ctx->info.lsn)) {
        ArbitrateUnkownInstance(ctx, str);
        return true;
    }
    /* instance is doing other command, cannot restart the dynamic primary */
    bool res = IsInstanceNoCmd(ctx, str);
    if (!res) {
        return false;
    }
    res = MoreDyPrimary(ctx, str);
    if (res) {
        return true;
    }
    res = DyPrimaryNeedToSwitchover(ctx, str);
    if (res) {
        return true;
    }
    return false;
}

static status_t SendStartWalrcvMsg(DnArbCtx *ctx)
{
    if (ctx->cond.vaildPrimIdx == INVALID_INDEX) {
        return CM_SUCCESS;
    }
    if (ctx->info.lockmode == POLLING_CONNECTION && ctx->info.dbState == INSTANCE_HA_STATE_NEED_REPAIR &&
        (ctx->info.buildReason == INSTANCE_HA_DATANODE_BUILD_REASON_CONNECTING ||
        ctx->info.buildReason == INSTANCE_HA_DATANODE_BUILD_REASON_DISCONNECT)) {
        char* chosenHost = ctx->dnReport[ctx->cond.vaildPrimIdx].local_status.local_host;
        uint32 chosenPort = ctx->dnReport[ctx->cond.vaildPrimIdx].local_status.local_port;
        if (chosenHost != NULL && strlen(chosenHost) != 0) {
            uint32 primaryTerm = GetInstanceTerm(ctx->groupIdx, ctx->cond.vaildPrimIdx);
            SendLock2Messange(ctx, chosenHost, (int)strlen(chosenHost), chosenPort, primaryTerm);
            write_runlog(LOG, "%s, Lock2 message has sent to instance (%u: %u), disconn(%s:%u).\n",
                "[SendUnLock]", ctx->instId, GetInstanceIdInGroup(ctx->groupIdx, ctx->cond.vaildPrimIdx), chosenHost, chosenPort);
            return CM_TIMEDOUT;
        }
    }
    return CM_SUCCESS;
}

static void ArbitratePrimaryInstance(DnArbCtx *ctx, const char *typeName)
{
    /* clean primary instance lock msg */
    if (ctx->info.lockmode == PROHIBIT_CONNECTION || ctx->info.lockmode == SPECIFY_CONNECTION) {
        SendUnlockMessage(ctx, ctx->info.term);
        write_runlog(LOG, "%s, line %d: Unlock message has sent to instance %u.\n", typeName, __LINE__, ctx->instId);
    }
    
    (void)SendStartWalrcvMsg(ctx);

    bool res = DyPrimaryIsUnheal(ctx, typeName);
    if (res) {
        return;
    }
    ChangeStaticPrimary(ctx, typeName);
}

static bool CheckCanSendFailoverMsg(const DnArbCtx *ctx)
{
    const ArbiCond *cond = &ctx->cond;
    //  more than delary time , not need wait for same az dn, or static primary is no one can send failover msg
    if ((cond->maxMemArbiTime > g_delayArbiTime) || (cond->snameAzDnCount == cond->snameAzRedoDoneCount) ||
        (ctx->staPrim.count != 1)) {
        return true;
    }
    int32 memIdx = ctx->staPrim.itStatus[0].memIdx;
    // static primary is invalid
    if (memIdx < 0) {
        return true;
    }
    // the dn whose azname same with static primary, can be promote primary.
    if (strcmp(ctx->localRole->azName, ctx->roleGroup->instanceMember[memIdx].azName) == 0) {
        return true;
    }
    return false;
}

static void SendFailoverMsg(DnArbCtx *ctx, uint32 arbitInterval, bool isStaPrim, const SendMsg_t *sfMsg)
{
    ArbiCond *cond = &ctx->cond;
    if (cond->maxMemArbiTime < arbitInterval) {
        write_runlog(LOG, "%s, Cannot failover (isDegrade=%d) instance %u, because time(%u) is smaller than %u.\n",
            sfMsg->tyName, cond->isDegrade, ctx->instId, cond->maxMemArbiTime, arbitInterval);
        return;
    }
    if (!isStaPrim && !CheckCanSendFailoverMsg(ctx)) {
        write_runlog(LOG, "%s, Cannot failover (isDegrade=%d) instance %u, because time(%u) is smaller than %u.\n",
            sfMsg->tyName, cond->isDegrade, ctx->instId, cond->maxMemArbiTime, g_delayArbiTime);
        return;
    }
    write_runlog(LOG, "%s, line %d: instId(%u) isStaPrim=%d, "
        "arbitime[inst(max: %u, local: %u, wait: %u), cond(sta: %u, noSta: %u, delay: %u)], "
        "count[build: %d, online: %d, validCanditate: %d, valid: %d], "
        "same_az[%d: %d].\n",
        sfMsg->tyName, __LINE__, ctx->instId, isStaPrim,
        cond->maxMemArbiTime, cond->localArbiTime, arbitInterval,
        cond->arbitStaticInterval, cond->arbitInterval, g_delayArbiTime,
        cond->buildCount, cond->onlineCount, cond->vaildCandiCount, cond->vaildCount,
        cond->snameAzRedoDoneCount, cond->snameAzDnCount);
    if (!CheckAvailSyncDdb(ctx)) {
        write_runlog(LOG, "%s, Cannot failover (isDegrade=%d) instance %u, because most_available_sync is on.\n",
            sfMsg->tyName, cond->isDegrade, ctx->instId);
        return;
    }
    if (ctx->cond.vaildCount <= 0) {
        write_runlog(LOG, "%s, line %d instd(%u) has invaildcount(%d).\n",
            sfMsg->tyName, __LINE__, ctx->instId, ctx->cond.vaildCount);
        return;
    }
    ctx->repGroup->time = 0;
    ClearDnArbiCond(ctx->groupIdx, CLEAR_ARBI_TIME);
    cm_to_agent_failover failoverMsg;
    int32 staPrimId = GetFailoverMsgStaPriID(ctx);
    if ((!cond->instMainta && !IsSyncListEmpty(ctx->groupIdx, ctx->instId, ctx->maintaMode)) || isStaPrim) {
        GroupStatusShow(sfMsg->tyName, ctx->groupIdx, ctx->instId, cond->vaildCount, cond->finishRedo);
        send_failover_message(ctx->recvMsgInfo, ctx->node, ctx->instId, ctx->groupIdx,
            ctx->memIdx, &failoverMsg, staPrimId);
        write_runlog(LOG, "%s, line %d: Failover message has sent to instance %u in reduce standy condition(%d), %s.\n",
            sfMsg->tyName, __LINE__, ctx->instId, cond->isDegrade, sfMsg->sendMsg);
    } else {
        write_runlog(LOG, "%s, line %d: (%u) Failover is forbidden by maintance, or syncList is empty "
            "in reduce standy condition(%d)!\n", sfMsg->tyName, __LINE__, ctx->instId, cond->isDegrade);
    }
}

static status_t SendFailoverByBuild(DnArbCtx *ctx)
{
    if (ctx->localRole->role != INSTANCE_ROLE_PRIMARY || ctx->info.dbState != INSTANCE_HA_STATE_NEED_REPAIR) {
        return CM_SUCCESS;
    }

    ArbiCond *cond = &(ctx->cond);
    if (!XLByteEQ_W_TERM(cond->maxTerm, cond->maxLsn, ctx->info.term, ctx->info.lsn)) {
        return CM_SUCCESS;
    }

    if (cond->isDegrade) {
        if (cond->buildCount == (cond->vaildCount - 1)) {
            SendMsg_t sfMsg = {"[FailoverByBuild]", "a majority of others are building"};
            SendFailoverMsg(ctx, cond->arbitInterval, false, &sfMsg);
            return CM_TIMEDOUT;
        }
    } else if (cond->buildCount > HALF_COUNT(cond->vaildCount)) {
        SendMsg_t sfMsg = {"[FailoverByBuild]", "all others are building"};
        SendFailoverMsg(ctx, cond->arbitInterval, false, &sfMsg);
        return CM_TIMEDOUT;
    }
    return CM_SUCCESS;
}

static status_t SendUnlockToInstance(DnArbCtx *ctx)
{
    ArbiCond *cond = &(ctx->cond);
    const char *str = "[SendUnlock]";
    if (!cond->isPrimaryValid || cond->isPrimDemoting || cond->vaildPrimIdx == INVALID_INDEX) {
        PrintPrimMsg(ctx, str, "cannot send unlock msg");
        return CM_SUCCESS;
    }

    /* term commit notes that whether the term of the primary has been commited and interface fulfillment needed */
    if (ctx->info.term == ctx->dnReport[cond->vaildPrimIdx].local_status.term) {
        if (ctx->info.lockmode == PROHIBIT_CONNECTION || ctx->info.lockmode == SPECIFY_CONNECTION) {
            uint32 primaryTerm = ctx->dnReport[ctx->cond.vaildPrimIdx].local_status.term;
            SendUnlockMessage(ctx, primaryTerm);
            write_runlog(LOG, "%s, line %d: Unlock message has sent to instance %u.\n", str, __LINE__, ctx->instId);
            return CM_TIMEDOUT;
        }
    } else {
        char* chosenHost = ctx->localRep->local_status.disconn_host;
        uint32 chosenPort = ctx->localRep->local_status.disconn_port;
        if (strcmp(chosenHost, ctx->dnReport[cond->vaildPrimIdx].local_status.local_host) != 0 ||
            chosenPort != ctx->dnReport[cond->vaildPrimIdx].local_status.local_port ||
            ctx->info.lockmode != SPECIFY_CONNECTION) {
            chosenHost = ctx->dnReport[cond->vaildPrimIdx].local_status.local_host;
            chosenPort = ctx->dnReport[cond->vaildPrimIdx].local_status.local_port;
            if (chosenHost != NULL && strlen(chosenHost) != 0) {
                uint32 primaryTerm = ctx->dnReport[cond->vaildPrimIdx].local_status.term;
                SendLock2Messange(ctx, chosenHost, (int)strlen(chosenHost), chosenPort, primaryTerm);
                write_runlog(LOG, "%s, Lock2 message has sent to instance (%u: %u), disconn(%s:%u).\n",
                    str, ctx->instId, GetInstanceIdInGroup(ctx->groupIdx, cond->vaildPrimIdx), chosenHost, chosenPort);
            } else {
                write_runlog(LOG, "%s, %u, Lock2 message error, invalid primary port.\n", str, ctx->instId);
            }
        }
        return CM_TIMEDOUT;
    }
    if (SendStartWalrcvMsg(ctx) != CM_SUCCESS) {
        return CM_TIMEDOUT;
    }
    return CM_SUCCESS;
}

static bool CheckIfPromoteStaticPrimary(const DnArbCtx *ctx, const char *str)
{
    if (ctx->localRole->role == INSTANCE_ROLE_PRIMARY) {
        return true;
    }
    if (!IsSameStanceStatus(&(ctx->dyCascade), &(ctx->staCasCade))) {
        char staCascadeStr[MAX_PATH_LEN] = {0};
        char dyCascadeStr[MAX_PATH_LEN] = {0};
        GetInstanceInfoStr(&(ctx->staCasCade), staCascadeStr, MAX_PATH_LEN);
        GetInstanceInfoStr(&(ctx->dyCascade), dyCascadeStr, MAX_PATH_LEN);
        write_runlog(LOG, "%s: line %d:instance(%u) changes cascade standby[sta: [%s], dy: [%s]], cannot be primary.\n",
            str, __LINE__, ctx->instId, staCascadeStr, dyCascadeStr);
        return false;
    }
    if (!ctx->cond.isDegrade) {
        return true;
    }
    if (!IsFinishReduceSyncList(ctx->groupIdx, ctx->memIdx, str)) {
        write_runlog(LOG, "%s: instance(%u) is doing reduce syncList, cannot be primary.\n", str, ctx->instId);
        return false;
    }
    return true;
}

static void SendFailoverInQuarm(DnArbCtx *ctx)
{
    ArbiCond *cond = &(ctx->cond);
    const char *str = "[SendFailoverQuarm]";
    bool isMajority = cond->vaildCandiCount >= HALF_COUNT(cond->vaildCount + 1) ? true : false;
    if (ctx->info.lockmode != PROHIBIT_CONNECTION) {
        SendLock1Message(ctx);
        write_runlog(LOG, "%s, line %d: Lock1 message has sent to instance %u, isDegrade=%d.\n",
            str, __LINE__, ctx->instId, cond->isDegrade);
    } else if (CanFailoverDn(isMajority) || ctx->cond.setOffline) {
        if (cond->candiIdx == ctx->memIdx) {
            if (!CheckIfPromoteStaticPrimary(ctx, str)) {
                return;
            }
            bool isStaticPimary = (cond->staticPriIdx == ctx->memIdx) ? true : false;
            uint32 dnArbitInterval = isStaticPimary ? cond->arbitStaticInterval : GetDnArbitateDelayTime(ctx);
            SendMsg_t sfMsg = {str, "local promoting"};
            SendFailoverMsg(ctx, dnArbitInterval, ctx->localRole->role == INSTANCE_ROLE_PRIMARY, &sfMsg);
        }
    } else {
        write_runlog(LOG, "%s, line %d: Could not arbitrate instance %u for not a majority of Lock1(%d/%d).\n",
            str, __LINE__, ctx->instId, cond->vaildCandiCount, HALF_COUNT(cond->vaildCount + 1));
    }
}

static void SendFailoverInQuarmBackup(DnArbCtx *ctx)
{
    ArbiCond *cond = &(ctx->cond);
    const char *str = "[SendFailoverQuarm]";
    if (cond->candiIdx != ctx->memIdx) {
        return;
    }
    bool isStaticPimary = (cond->staticPriIdx == ctx->memIdx) ? true : false;
    uint32 dnArbitInterval = isStaticPimary ? cond->arbitStaticInterval : cond->arbitInterval;
    SendMsg_t sfMsg = {str, "local promoting"};

    if (cond->maxMemArbiTime <= dnArbitInterval) {
        write_runlog(LOG, "%s, line %d:Cannot failover instance %u, because time(%u) is smaller than %u.\n",
            sfMsg.tyName, __LINE__, ctx->instId, cond->maxMemArbiTime, cond->arbitInterval);
        return;
    }
    if (!CheckAvailSyncDdb(ctx)) {
        write_runlog(LOG, "%s, line %d:Cannot failover instance %u, because most_available_sync is on.\n",
            sfMsg.tyName, __LINE__, ctx->instId);
        return;
    }
    for (int32 i = 0; i < GetInstanceCountsInGroup(ctx->groupIdx); ++i) {
        if (ctx->repGroup->command_member[i].pengding_command == (int)MSG_CM_AGENT_BUILD &&
            g_instance_role_group_ptr[ctx->groupIdx].instanceMember[i].role == INSTANCE_ROLE_PRIMARY) {
            write_runlog(LOG, "Cannot failover instance %u, because instance(%u) is building.\n",
                ctx->instId, GetInstanceIdInGroup(ctx->groupIdx, i));
            return;
        }
    }
    write_runlog(LOG, "%s, line %d: instanceId(%u) arbitrate_time=%u, local_arbitrate_time=%u, other_arbit_interval=%u,"
        " arbit_static_interval=%u, buildCount=%d, onlineCount=%d, arbit_interval=%u valid_count=%d.\n",
        sfMsg.tyName, __LINE__, ctx->instId, cond->maxMemArbiTime, cond->localArbiTime, cond->arbitInterval,
        cond->arbitStaticInterval, cond->buildCount, cond->onlineCount, dnArbitInterval, cond->vaildCount);

    ctx->repGroup->time = 0;
    ClearDnArbiCond(ctx->groupIdx, CLEAR_ARBI_TIME);
    cm_to_agent_failover failoverMsg;
    if (!cond->instMainta || ctx->localRole->role == INSTANCE_ROLE_PRIMARY) {
        GroupStatusShow(sfMsg.tyName, ctx->groupIdx, ctx->instId, cond->vaildCount, cond->finishRedo);
        int32 staPrimId = GetFailoverMsgStaPriID(ctx);
        send_failover_message(ctx->recvMsgInfo, ctx->node, ctx->instId, ctx->groupIdx,
            ctx->memIdx, &failoverMsg, staPrimId);
        ctx->repGroup->lastFailoverDn = ctx->instId;
        write_runlog(LOG, "%s, line %d: Failover message has sent to instance %u, %s.\n",
            sfMsg.tyName, __LINE__, ctx->instId, sfMsg.sendMsg);
    } else {
        write_runlog(LOG, "%s, line %d: (%u) Failover is forbidden by maintance\n",
            sfMsg.tyName, __LINE__, ctx->instId);
    }
}

bool ChangeStaticPrimaryRoleInStandby(DnArbCtx *ctx, const char *str)
{
    if (!ctx->cond.hasDynamicPrimary || ctx->cond.dyPrimIdx == INVALID_INDEX) {
        return false;
    }
    ArbiCond *cond = &(ctx->cond);
    const uint32 changeStaticRoleInterval = 3;
    if (ctx->info.dbState == INSTANCE_HA_STATE_NORMAL || ctx->info.dbState == INSTANCE_HA_STATE_CATCH_UP) {
        if (ctx->repGroup->time < ((uint32)(ctx->roleGroup->count) * changeStaticRoleInterval)) {
            write_runlog(LOG,
                "%s, line %d:do not change static primary, dynamic primary instanceid is %u, time is %u, "
                "all time is %u.\n",
                str, __LINE__, GetInstanceIdInGroup(ctx->groupIdx, ctx->cond.dyPrimIdx), ctx->repGroup->time,
                (uint32)(ctx->roleGroup->count) * changeStaticRoleInterval);
            return true;
        }
        if (ctx->repGroup->data_node_member[ctx->cond.dyPrimIdx].local_status.term == ctx->cond.maxTerm) {
            write_runlog(LOG, "line %d: manual do the instance switchover or failover node is %u, instanceId is %u.\n",
                __LINE__, ctx->node, ctx->instId);
            GroupStatusShow(str, ctx->groupIdx, ctx->instId, cond->vaildCount, cond->finishRedo);
            ChangeDnPrimaryMemberIndex(ctx->groupIdx, ctx->cond.dyPrimIdx);
            cm_pending_notify_broadcast_msg(ctx->groupIdx, GetInstanceIdInGroup(ctx->groupIdx, ctx->cond.dyPrimIdx));
            write_runlog(LOG, "%s, line %d: set instance %u to be static primary.\n", str, __LINE__,
                GetInstanceIdInGroup(ctx->groupIdx, ctx->cond.dyPrimIdx));
            ctx->repGroup->time = 0;
        }
        return true;
    }
    return false;
}

static void ArbitrateStandbyInQuarm(DnArbCtx *ctx, const char *str)
{
    if (ctx->cond.isPrimaryValid) {
        write_runlog(DEBUG1,
            "%s, instanceId %u isPrimaryValid is %d, dyPrimNormalIdx is %d, vaildPrimIdx is %d, "
            "not need to arbitrate.\n",
            str, ctx->instId, ctx->cond.isPrimaryValid, ctx->cond.dyPrimNormalIdx, ctx->cond.vaildPrimIdx);
        return;
    }

    if (ctx->localRep->dnVipStatus == CM_SUCCESS) {
        write_runlog(DEBUG1, "%s, instanceId %u dnVipStatus is %s, dyPrimNormalIdx is %d, vaildPrimIdx is %d, "
            "not need to arbitrate.\n",
            str, ctx->instId, ctx->localRep->dnVipStatus == CM_SUCCESS ? "good" : "bad",
            ctx->cond.dyPrimNormalIdx, ctx->cond.vaildPrimIdx);
        return;
    }
    
    if (ChangeStaticPrimaryRoleInStandby(ctx, str)) {
        return;
    }
    if (ctx->cond.dyPrimNormalIdx != INVALID_INDEX) {
        write_runlog(DEBUG1, "%s, instanceId %u  dyPrimNormalIdx is %d, not need to arbitrate.\n", str, ctx->instId,
            ctx->cond.dyPrimNormalIdx);
        return;
    }
    ArbiCond *cond = &(ctx->cond);
    if (cond->switchoverIdx != INVALID_INDEX) {
        write_runlog(LOG, "%s, can't arbitrate instance %u, doSwitchoverIndex is %d, send swithover num is [%d/%d].\n",
            str, ctx->instId, cond->switchoverIdx, GetSendTimes(ctx->groupIdx, cond->switchoverIdx, false),
            GetSendTimes(ctx->groupIdx, cond->switchoverIdx, true));
        return;
    }
    if (backup_open == CLUSTER_STREAMING_STANDBY) {
        SendFailoverInQuarmBackup(ctx);
        return;
    }
    SendFailoverInQuarm(ctx);
}

static bool StandbyDatanodeIsUnheal(const DnArbCtx *ctx, const char *typeName)
{
    /* dn instance term and lsn is invalid, cannot arbitrate. */
    if (!IsTermLsnValid(ctx->info.term, ctx->info.lsn)) {
        ArbitrateUnkownInstance(ctx, typeName);
        return true;
    }
    return false;
}

static void ArbitrateStandByInstance(DnArbCtx *ctx, const char *typeName)
{
    /* dn instance term and lsn is invalid, cannot arbitrate. */
    if (StandbyDatanodeIsUnheal(ctx, typeName)) {
        return;
    }
    status_t resStatus = SendFailoverByBuild(ctx);
    if (resStatus != CM_SUCCESS) {
        return;
    }
    resStatus = SendUnlockToInstance(ctx);
    if (resStatus != CM_SUCCESS) {
        return;
    }
    ArbitrateStandbyInQuarm(ctx, typeName);
}

static void DnArbitrateNormal(DnArbCtx *ctx)
{
    if (backup_open == CLUSTER_PRIMARY) {
        GetCandiMsgAndIdx(ctx);
    } else {
        GetCandiMsgAndIdxBackup(ctx);
    }
    bool res = InstanceForceFailover(ctx);
    if (res) {
        return;
    }
    /* After cleaning instance mark, get instance info again. */
    GetInstType instTp = {"[DnArbitrateNormal]", DN_ARBI_NORMAL};
    GetInstanceInfo(ctx, &instTp);
    int32 dyRole = ctx->info.dyRole;
    switch (dyRole) {
        case INSTANCE_ROLE_PRIMARY:
            ArbitratePrimaryInstance(ctx, "[Primary]");
            break;
        case INSTANCE_ROLE_STANDBY:
            ArbitrateStandByInstance(ctx, "[Standby]");
            break;
        case INSTANCE_ROLE_PENDING:
            ArbitratePendingInstance(ctx, "[Pending]");
            break;
        case INSTANCE_ROLE_UNKNOWN:
            ArbitrateUnkownInstance(ctx, "[Unkown]");
            break;
        default:
            write_runlog(ERROR, "instance(%u) dynamic role is %d, may be error, please check it.\n", ctx->instId,
                dyRole);
            break;
    }
}

static void CleanDoubleRestartMsg(DnArbCtx *ctx)
{
    if (ctx->info.dyRole == INSTANCE_ROLE_PRIMARY) {
        return;
    }
    if (ctx->info.dbRestart) {
        ctx->info.dbRestart = false;
        ctx->repGroup->arbitrate_status_member[ctx->memIdx].restarting = false;
        write_runlog(LOG, "instanceId(%u) will clean dbRestart, because it status is [%d %d:%d].\n",
            ctx->instId, ctx->localRole->role, ctx->info.dyRole, ctx->info.dbState);
    }
}

static void CleanArbitInfo(DnArbCtx *ctx)
{
    /* clean failover flag */
    CleanFailoverFlag(ctx);
    /* dn switchover */
    CleanSwitchoverInfo(ctx);
    /* send build msg */
    SendBuildMsg(ctx);
    /* dn build */
    CleanBuildCommandInfo(ctx->groupIdx, ctx->memIdx, ctx->info.dbState);
    /* double restart msg */
    CleanDoubleRestartMsg(ctx);
    /* After cleaning instance mark, get instance info again. */
    GetInstType instTp = {"[CleanArbitInfo]", DN_ARBI_PMS};
    GetInstanceInfo(ctx, &instTp);
}

static int32 GetDnSwitchoverIndex(const DnArbCtx *ctx)
{
    for (int32 i = 0; i < ctx->roleGroup->count; ++i) {
        if (ctx->repGroup->command_member[i].pengding_command == (int)MSG_CM_AGENT_SWITCHOVER) {
            return i;
        }
    }
    return -1;
}

static int32 GetDnFailoveroverIndex(const DnArbCtx *ctx)
{
    for (int32 i = 0; i < ctx->roleGroup->count; ++i) {
        if (ctx->repGroup->command_member[i].pengding_command == (int)MSG_CM_AGENT_FAILOVER) {
            return i;
        }
    }
    return -1;
}

static void ChangeRole2CasCade(DnArbCtx *ctx, const char *str)
{
    // static role
    if (ctx->localRole->role != INSTANCE_ROLE_CASCADE_STANDBY) {
        ArbitrateUnkownInstance(ctx, str);
        int32 switchIdx = GetDnSwitchoverIndex(ctx);
        if (switchIdx != -1) {
            write_runlog(LOG, "%s line %d: instd(%u) cannot send restart msg, bacause instd(%u) is doing switchover.\n",
                str, __LINE__, ctx->instId, GetInstanceIdInGroup(ctx->groupIdx, switchIdx));
            return;
        }
        int32 failoverIdx = GetDnFailoveroverIndex(ctx);
        if (failoverIdx != -1) {
            write_runlog(LOG, "%s line %d: instd(%u) cannot send restart msg, bacause instd(%u) is doing failover.\n",
                str, __LINE__, ctx->instId, GetInstanceIdInGroup(ctx->groupIdx, failoverIdx));
            return;
        }
        SendRestartMsg(ctx, str);
    } else if (ctx->info.dyRole != INSTANCE_ROLE_CASCADE_STANDBY && IsTermLsnValid(ctx->info.term, ctx->info.lsn)) {
        // dynamic role
        if (ctx->info.dyRole != INSTANCE_ROLE_PENDING) {
            ArbitrateUnkownInstance(ctx, str);
            int32 switchIdx = GetDnSwitchoverIndex(ctx);
            if (switchIdx != -1) {
                write_runlog(LOG, "%s line %d: instd(%u) cannot send restart msg, bacause instd(%u) is doing "
                    "switchover.\n", str, __LINE__, ctx->instId, GetInstanceIdInGroup(ctx->groupIdx, switchIdx));
                return;
            }
            int32 failoverIdx = GetDnFailoveroverIndex(ctx);
            if (failoverIdx != -1) {
                write_runlog(LOG, "%s line %d: instd(%u) cannot send restart msg, bacause instd(%u) is doing "
                    "failover.\n",
                    str, __LINE__, ctx->instId, GetInstanceIdInGroup(ctx->groupIdx, failoverIdx));
                return;
            }
            SendRestartMsg(ctx, str);
        } else {
            ArbitrateUnkownInstance(ctx, str);
            SendNotifyMessage2Cma(ctx, INSTANCE_ROLE_CASCADE_STANDBY);
        }
    }
}

static void send_cascade_failover_message(DnArbCtx *ctx, cm_to_agent_failover_cascade* failover_msg_ptr)
{
    uint32 group_index = ctx->groupIdx;
    int member_index = ctx->memIdx;
    uint32 instanceId = ctx->instId;
    for (int i = 0; i <= ctx->roleGroup->count; ++i) {
        cm_instance_role_status instanceReport = ctx->roleGroup->instanceMember[i];
        if (instanceReport.role == INSTANCE_ROLE_STANDBY) {
            ChangeCascadeMemberIndex("[ChangeDnStandbyMemberIndex]", group_index, member_index, i);
            break;
        }
    }
    failover_msg_ptr->msg_type = (int)MSG_CM_AGENT_FAILOVER;
    failover_msg_ptr->node = ctx->node;
    failover_msg_ptr->instanceId = instanceId;
    uint32 pass_term = ReadTermFromDdb(group_index);
    if (pass_term == InvalidTerm) {
        write_runlog(ERROR, "line %d: Term on DDB has not been set yet, which should not happen.\n", __LINE__);
        (void)WriteDynamicConfigFile(false);
        return;
    }

    (void)WriteDynamicConfigFile(false);

    if (pass_term < g_instance_group_report_status_ptr[group_index].instance_status.term) {
        write_runlog(ERROR, "line %d: DDB term(%u) is smaller than group term(%u)!.\n",
            __LINE__, pass_term, g_instance_group_report_status_ptr[group_index].instance_status.term);
        return;
    }

    g_instance_group_report_status_ptr[group_index].instance_status.term = pass_term;
    WriteKeyEventLog(KEY_EVENT_FAILOVER, instanceId, "Failover to standby message has sent to instance %u.",
                     instanceId);
    (void)RespondMsg(ctx->recvMsgInfo, 'S', (char*)failover_msg_ptr, sizeof(cm_to_agent_failover_cascade));
    ctx->repGroup->command_member[member_index].pengding_command = (int)MSG_CM_AGENT_FAILOVER;
    cm_pending_notify_broadcast_msg(group_index, instanceId);
}

static void SendFailoverCascadeMsg(DnArbCtx *ctx, const SendMsg_t *sfMsg)
{
    ArbiCond *cond = &ctx->cond;
    GroupStatusShow(sfMsg->tyName, ctx->groupIdx, ctx->instId, cond->vaildCount, cond->finishRedo);
    cm_to_agent_failover_cascade failover_msg_ptr;
    send_cascade_failover_message(ctx, &failover_msg_ptr);
    write_runlog(LOG, "%s, line %d: Failover message has sent to instance %u in reduce standy condition(%d), %s.\n",
                 sfMsg->tyName, __LINE__, ctx->instId, cond->isDegrade, sfMsg->sendMsg);
}

static void arbitrateStandby(DnArbCtx *ctx, const char *str)
{
    if (g_cms_enable_failover_cascade && ctx->staNorStandby.count == 0) {
        g_cascade_failover_count++;
        if (g_cascade_failover_count < ctx->cond.arbitInterval) {
            write_runlog(LOG, "%s, line %d: Cannot failover instance %u, because time(%u) is smaller than %u.\n",
                str, __LINE__, ctx->instId, g_cascade_failover_count, ctx->cond.arbitInterval);
            return;
        }
        int32 staCascadeCount = ctx->staCasCade.count;
        for (int32 i = 0; i < staCascadeCount; i++) {
            int32 memIdx = ctx->staCasCade.itStatus[i].memIdx;
            if (ctx->dnReport[memIdx].local_status.db_state == INSTANCE_HA_STATE_NEED_REPAIR) {
                ctx->cond.candiIdx = memIdx;
                break;
            }
        }
        ArbiCond *cond = &(ctx->cond);
        const char *str = "[SendFailoverCascade]";
        if (cond->candiIdx == ctx->memIdx) {
            SendMsg_t sfMsg = {str, "local promoting"};
            SendFailoverCascadeMsg(ctx, &sfMsg);
            g_cascade_failover_count = 0;
        } else {
            write_runlog(LOG, "%s, line %d: No valid candidate found for failover (candiIdx=%d, memIdx=%d), "
                            "g_cascade_failover_count = %d.\n",
                str, __LINE__, cond->candiIdx, ctx->memIdx, g_cascade_failover_count);
        }
    }
}

static bool CheckCurNodeIsCascade(DnArbCtx *ctx)
{
    if (ctx->info.dyRole != INSTANCE_ROLE_CASCADE_STANDBY && ctx->localRole->role != INSTANCE_ROLE_CASCADE_STANDBY) {
        return false;
    }
    const char *str = "[CascadeStandby]";

    if (log_min_messages <= DEBUG1) {
        ArbitrateUnkownInstance(ctx, str);
    }
    arbitrateStandby(ctx, str);
    ChangeRole2CasCade(ctx, str);
    if (ctx->info.lockmode == PROHIBIT_CONNECTION || ctx->info.lockmode == SPECIFY_CONNECTION) {
        SendUnlockMessage(ctx, GetPrimaryTerm(ctx));
        write_runlog(LOG, "line %d: Unlock message has sent to instance %u.\n", __LINE__, ctx->instId);
    }

    return true;
}

static void DnArbitrateInpms(DnArbCtx *ctx)
{
    /* get instance info first, for clean arbitInfo. */
    GetInstType instTp = {"[DnArbitrateInpms]", DN_ARBI_PMS};
    GetInstanceInfo(ctx, &instTp);
    CleanArbitInfo(ctx);
    /* deal instance in asynchronous */
    bool result = DnArbitrateInAsync(ctx);
    if (result) {
        return;
    }
    if (CheckCurNodeIsCascade(ctx)) {
        return;
    }
    DnArbitrateNormal(ctx);
}

static status_t ArbitrateUnhealDyPrim(DnArbCtx *ctx)
{
    /* dynamic primary may be coredump, and reset it unknown */
    DynamicPrimaryInCoreDump(ctx);
    /* the term of dynamic primary instance may be not the most, restart it, and wait for arbitrate */
    status_t resStatus = RestartSmallerTermDynamicPrimary(ctx);
    CM_RETURN_IFERR(resStatus);
    return CM_SUCCESS;
}

static void AddArbitrateTime(DnArbCtx *ctx)
{
    ctx->localRep->arbiTime++;
    ctx->repGroup->time++;
    ctx->cond.localArbiTime = ctx->localRep->arbiTime;
}

static void DnArbitrateInner(DnArbCtx *ctx)
{
    DealPhonyDeadStatus(ctx->recvMsgInfo, INSTANCE_TYPE_DATANODE, ctx->groupIdx, ctx->memIdx, ctx->maintaMode);
    DealDataNodeDBStateChange(ctx->groupIdx, ctx->memIdx, ctx->dbStatePre);
    if (IsBoolCmParamTrue(g_enableDcf) || g_enableSharedStorage) {
        DealDnInSelfArbitrate(ctx);
        return;
    }
    if (backup_open == CLUSTER_OBS_STANDBY) {
        DealDnArbitrateInBackup(ctx);
        return;
    }
    AddArbitrateTime(ctx);
    status_t resStatus = ArbitrateUnhealDyPrim(ctx);
    if (resStatus != CM_SUCCESS) {
        return;
    }
    PrintLogIfInstanceIsUnheal(ctx);
    /* one primary one standby in single-inst */
    DnArbitrateInTwoRepAndSingleInst(ctx);
    DnArbitrateInpms(ctx);
}

static bool IsMaintance(maintenance_mode mode)
{
    return mode != MAINTENANCE_MODE_NONE;
}

static void InitDnArbCond(DnArbCtx *ctx)
{
    ctx->cond.maxTerm = InvalidTerm;
    ctx->cond.maxLsn = InvalidXLogRecPtr;
    ctx->cond.voteAzCount = ctx->repGroup->voteAzInstance.count;
    ctx->cond.igPrimaryCount = 0;
    ctx->cond.igPrimaryIdx = INVALID_INDEX;
    ctx->cond.isPrimaryValid = false;
    ctx->cond.vaildPrimIdx = INVALID_INDEX;
    ctx->cond.lock1Count = 0;
    ctx->cond.lock2Count = 0;
    ctx->cond.buildCount = 0;
    ctx->cond.vaildCandiCount = 0;
    ctx->cond.vaildCount = 0;
    ctx->cond.staticPriIdx = INVALID_INDEX;
    ctx->cond.staticPrimaryDbstate = INSTANCE_HA_STATE_UNKONWN;
    ctx->cond.isDegrade = false;
    ctx->cond.candiIdx = INVALID_INDEX;
    ctx->cond.isPrimDemoting = false;
    ctx->cond.redoDone = 0;
    ctx->cond.failoverNum = 0;
    ctx->cond.standbyMaxTerm = InvalidTerm;
    ctx->cond.standbyMaxLsn = InvalidXLogRecPtr;
    ctx->cond.dyPrimIdx = INVALID_INDEX;
    ctx->cond.dyPrimNormalIdx = INVALID_INDEX;
    ctx->cond.maxMemArbiTime = 0;
    ctx->cond.instMainta = IsMaintance(ctx->maintaMode);
    ctx->cond.switchoverIdx = INVALID_INDEX;
    ctx->cond.arbitInterval = g_clusterStarting ? g_clusterStartingArbitDelay : g_waitStaticPrimaryTimes;
    ctx->cond.arbitStaticInterval = 5;
    ctx->cond.setOffline = SetOfflineNode();
    ctx->cond.snameAzDnCount = 0;
    ctx->cond.snameAzRedoDoneCount = 0;
}

static void InitDnInfo(DnArbCtx *ctx)
{
    ctx->info.term = ctx->localRep->local_status.term;
    ctx->info.dyRole = ctx->localRep->local_status.local_role;
    ctx->info.lockmode = ctx->localRep->local_status.disconn_mode;
    ctx->info.lsn = ctx->localRep->local_status.last_flush_lsn;
    ctx->info.dbState = ctx->localRep->local_status.db_state;
    ctx->info.dbRestart = ctx->repGroup->arbitrate_status_member[ctx->memIdx].restarting;
    ctx->info.sendFailoverTimes = ctx->localRep->sendFailoverTimes;
    ctx->info.buildReason = ctx->localRep->local_status.buildReason;
    InitDnArbCond(ctx);
}

void DatanodeInstanceArbitrate(MsgRecvInfo* recvMsgInfo, const agent_to_cm_datanode_status_report *agentRep)
{
    DnArbCtx ctx = {0};
    status_t resStatus;
    /* Get groupIndex, memberIndex */
    resStatus = InitDnArbCtx(recvMsgInfo, agentRep, &ctx);
    if (resStatus != CM_SUCCESS) {
        return;
    }
    /* we should reset heartbeat as soon as possiable */
    if (!CanArbitrate(recvMsgInfo, "dn_arbitrate")) {
        return;
    }

    /* sync static status from ddb */
    GetDnStaticRoleFromDdb(&ctx);
    (void)pthread_rwlock_wrlock(ctx.lock);
    ResetHeartbeat(&ctx);
    SaveDnStatusFromReport(agentRep, &ctx);
    InitDnInfo(&ctx);

    /* skip arbitration when the cluster is pausing,
     * but cm_ctl operation is allowed, it's necessary to clean some falgs.
     */
    if (g_isPauseArbitration) {
        write_runlog(LOG, "The cluster has been paused.\n");
        CleanArbitInfo(&ctx);
        (void)pthread_rwlock_unlock(ctx.lock);
        return;
    }

    DnArbitrateInner(&ctx);
    (void)pthread_rwlock_unlock(ctx.lock);
}

void StopFakePrimaryResourceInstance(const DnArbCtx *ctx)
{
    int ret = -1;
    uint32 ii = 0;
    uint32 jj = 0;
    bool isFound = false;
    char command[MAX_PATH_LEN] = {0};

    // find fake primary instance's local data path
    for (ii = 0; ii < g_node_num; ii++) {
        for (jj = 0; jj < g_node[ii].datanodeCount; jj++) {
	    if (g_node[ii].datanode[jj].datanodeId == ctx->instId) {
                isFound = true;
		break;
	    }
        }
	if (isFound) {
	    break;
	}
    }

    if (ii >= g_node_num) {
        write_runlog(ERROR, "cannot find dn instance: nodeid=%u.\n", g_node[ii].node);
        return;
    }

    // stop fake primary instance
    ret = snprintf_s(command, sizeof(command), sizeof(command) - 1,
        SYSTEMQUOTE "cm_ctl stop -n %u -D %s" SYSTEMQUOTE, ctx->node, g_node[ii].datanode[jj].datanodeLocalDataPath);
    securec_check_intval(ret, (void)ret);

    ret = system(command);
    if (ret != 0) {
        write_runlog(ERROR, "failed to stop db instance with command: \"%s\","
            "nodeId=%u, systemReturn=%d, shellReturn=%d, errno=%d.\n",
            command, ctx->node, ret, SHELL_RETURN_CODE(ret), errno);
        return;
    }

    write_runlog(LOG, "stop db instance successfully, nodeid: %u, instanceid %u.\n", ctx->node, ctx->instId);
}

// judge whether current instance's id is the max
bool IsInstanceIdMax(const DnArbCtx *ctx)
{
    uint32 maxId = ctx->instId;
    for (int32 i = 0; i < ctx->dyNorPrim.count; ++i) {
        if (!InstanceIsCandicate(ctx, ctx->dyNorPrim.itStatus[i].memIdx, true)) {
            continue;
        }

        maxId = ctx->dyNorPrim.itStatus[i].instId > maxId ? ctx->dyNorPrim.itStatus[i].instId : maxId;
    }

    return ((maxId == ctx->instId) ? true : false);
}
