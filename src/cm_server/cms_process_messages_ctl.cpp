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
 * cms_process_messages_ctl.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_server/cms_process_messages_ctl.cpp
 *
 * -------------------------------------------------------------------------
 */
#include "cms_global_params.h"
#include "cms_process_messages.h"
#include "cms_disk_check.h"
#include "cms_ddb_adapter.h"
#include "cms_common.h"
#include "cm_ip.h"
#include "cm_msg_version_convert.h"

/**
 * @brief
 *
 * @param  con              My Param doc
 * @param  switchoverMsg    My Param doc
 */
void ProcessCtlToCmSwitchoverMsg(MsgRecvInfo* recvMsgInfo, const ctl_to_cm_switchover *switchoverMsg)
{
    int ret;
    int memberIndex = 0;
    uint32 groupIndex = 0;
    cm_to_ctl_command_ack ackMsg;

    ret = find_node_in_dynamic_configure(switchoverMsg->node, switchoverMsg->instanceId, &groupIndex, &memberIndex);
    if (ret != 0) {
        write_runlog(
            LOG, "can't find the instance(node =%u  instanceid =%u)\n", switchoverMsg->node, switchoverMsg->instanceId);
        return;
    }

    const cm_instance_role_status *instInfo = &g_instance_role_group_ptr[groupIndex].instanceMember[memberIndex];
    cm_instance_report_status *instStatus = &g_instance_group_report_status_ptr[groupIndex].instance_status;

    ackMsg.msg_type = MSG_CM_CTL_COMMAND_ACK;
    ackMsg.node = groupIndex;
    ackMsg.instanceId = instInfo->instanceId;
    ackMsg.instance_type = instInfo->instanceType;

    int32 localRole = -1;
    const char *str = "[ProcessCtlToCmSwitchoverMsg]";
    bool isInVoteAz = IsCurInstanceInVoteAz(groupIndex, memberIndex);
    if (instInfo->instanceType == INSTANCE_TYPE_GTM) {
        localRole = instStatus->gtm_member[memberIndex].local_status.local_role;
        if (localRole == INSTANCE_ROLE_STANDBY && !isInVoteAz) {
            ackMsg.command_result = CM_CAN_PRCESS_COMMAND;
        } else {
            ackMsg.command_result = CM_INVALID_COMMAND;
            write_runlog(LOG, "switchover the gtm instance(node =%u instanceid =%u) is not standby \n",
                switchoverMsg->node, switchoverMsg->instanceId);
        }
    } else if (instInfo->instanceType == INSTANCE_TYPE_DATANODE) {
        cm_instance_datanode_report_status *dnReport = &(instStatus->data_node_member[memberIndex]);
        localRole = dnReport->local_status.local_role;
        EnCheckSynclist echeck = CheckInstInSyncList(groupIndex, memberIndex, str);
        if (localRole == INSTANCE_ROLE_STANDBY && !isInVoteAz && (echeck == SYNCLIST_IS_FINISTH)) {
            ackMsg.command_result = CM_CAN_PRCESS_COMMAND;
        } else if (localRole == INSTANCE_ROLE_CASCADE_STANDBY && dnReport->dnLp.peerInst != 0) {
            ackMsg.command_result = CM_CAN_PRCESS_COMMAND;
        } else {
            ackMsg.command_result = CM_INVALID_COMMAND;
            write_runlog(LOG, "switchover the datanode instance(node =%u  instanceid =%u) is not standby, but is %s, "
                "echeck is %d, peerInst is %u.\n", switchoverMsg->node, switchoverMsg->instanceId,
                datanode_role_int_to_string(localRole), (int)echeck, dnReport->dnLp.peerInst);
        }
        if (IsBoolCmParamTrue(g_enableDcf) && dnReport->receive_status.local_role != (int)DCF_ROLE_FOLLOWER) {
            ackMsg.command_result = CM_INVALID_COMMAND;
            write_runlog(LOG, "switchover the datanode instance(node =%u instanceid =%u) is not Follower, but is %s\n",
                switchoverMsg->node, switchoverMsg->instanceId, DcfRoleToString(dnReport->receive_status.local_role));
        }
    } else {
        ackMsg.command_result = CM_INVALID_COMMAND;
        write_runlog(LOG, "switchover can't find the instance(node =%u  instanceid =%u) type is %d\n",
            switchoverMsg->node, switchoverMsg->instanceId, instInfo->instanceType);
    }

    ackMsg.command_status = instStatus->command_member[memberIndex].command_status;
    ackMsg.pengding_command = instStatus->command_member[memberIndex].pengding_command;

    if (!CheckCanDoSwitchover(groupIndex, memberIndex, &(ackMsg.pengding_command), str)) {
        ackMsg.command_result = CM_ANOTHER_COMMAND_RUNNING;
        (void)RespondMsg(recvMsgInfo, 'S', (char *)(&ackMsg), sizeof(ackMsg));
        return;
    }
    /* If the cluester is in OnDemand Recovery. */
    if (isInOnDemandStatus()) {
        ackMsg.command_result = CM_DN_IN_ONDEMAND_STATUE;
        (void)RespondMsg(recvMsgInfo, 'S', (char *)(&ackMsg), sizeof(ackMsg));
        return;
    }
    // tell cm_ctl will switchover to primary or standby
    ackMsg.pengding_command = localRole;
    write_runlog(LOG, "ackMsg.pengding_command: %d\n", localRole);
    (void)RespondMsg(recvMsgInfo, 'S', (char *)(&ackMsg), sizeof(ackMsg));
    if (ackMsg.command_result == CM_INVALID_COMMAND) {
        return;
    }

    // XXX: above check is out of lock, may has concurrency issues
    (void)pthread_rwlock_wrlock(&(g_instance_group_report_status_ptr[groupIndex].lk_lock));
    SetSwitchoverCmd(&(instStatus->command_member[memberIndex]), localRole, instInfo->instanceId,
        GetPeerInstId(groupIndex, memberIndex));
    instStatus->command_member[memberIndex].time_out = switchoverMsg->wait_seconds;
    instStatus->command_member[memberIndex].msgProcFlag = recvMsgInfo->msgProcFlag;
    SetSendTimes(groupIndex, memberIndex, switchoverMsg->wait_seconds);
    (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[groupIndex].lk_lock));

    return;
}

static bool ExistAnotherCommandRunning(uint32 groupIndex, cm_to_ctl_command_ack ackMsg, MsgRecvInfo* recvMsgInfo,
    const ctl_to_cm_build *buildMsg)
{
    /* if cluster is multi az, the cluster will have more standby than one */
    bool isAnotherCommandRunning = false;
    for (int i = 0; i < g_instance_role_group_ptr[groupIndex].count; i++) {
        if (!g_multi_az_cluster) {
            if (g_instance_group_report_status_ptr[groupIndex].instance_status.command_member[i].command_status !=
                INSTANCE_NONE_COMMAND) {
                isAnotherCommandRunning = true;
            }
        } else {
            if (g_instance_group_report_status_ptr[groupIndex].instance_status.command_member[i].pengding_command ==
                (int32)MSG_CM_AGENT_SWITCHOVER ||
                g_instance_group_report_status_ptr[groupIndex].instance_status.command_member[i].pengding_command ==
                (int32)MSG_CM_AGENT_FAILOVER) {
                isAnotherCommandRunning = true;
            }
        }
        /* if one instance is building in dcf, can not send build msg */
        if (IsBoolCmParamTrue(g_enableDcf) &&
            g_instance_group_report_status_ptr[groupIndex].instance_status.command_member[i].pengding_command ==
            (int)MSG_CM_AGENT_BUILD) {
            isAnotherCommandRunning = true;
            ackMsg.pengding_command = MSG_CM_AGENT_BUILD;
        }
        if (isAnotherCommandRunning) {
            write_runlog(LOG, "instance(node =%u instanceId =%u) is executing another command (%d)\n", buildMsg->node,
                buildMsg->instanceId,
                g_instance_group_report_status_ptr[groupIndex].instance_status.command_member[i].pengding_command);
            ackMsg.command_result = CM_ANOTHER_COMMAND_RUNNING;
            (void)RespondMsg(recvMsgInfo, 'S', (char *)(&ackMsg), sizeof(ackMsg));
            return isAnotherCommandRunning;
        }
    }

    return isAnotherCommandRunning;
}

static bool IsSendBuild(int32 localRole)
{
    return (localRole == INSTANCE_ROLE_STANDBY || localRole == INSTANCE_ROLE_CASCADE_STANDBY);
}

static void ProcessDatanodeCommandResult(const ctl_to_cm_build *buildMsg, cm_to_ctl_command_ack *ackMsg,
    const cm_local_replconninfo *dnStatus)
{
    if (((buildMsg->force_build == CM_CTL_FORCE_BUILD) || (dnStatus->db_state == INSTANCE_HA_STATE_NEED_REPAIR)) &&
        (IsSendBuild(dnStatus->local_role)) &&
        (dnStatus->buildReason != INSTANCE_HA_DATANODE_BUILD_REASON_DISCONNECT) &&
        (dnStatus->buildReason != INSTANCE_HA_DATANODE_BUILD_REASON_CONNECTING)) {
        ackMsg->command_result = CM_CAN_PRCESS_COMMAND;
    } else if ((IsSendBuild(dnStatus->local_role)) && (dnStatus->db_state == INSTANCE_HA_STATE_NORMAL)) {
        ackMsg->command_result = CM_CAN_PRCESS_COMMAND;
    } else if (dnStatus->local_role == INSTANCE_ROLE_UNKNOWN) {
        ackMsg->command_result = CM_CAN_PRCESS_COMMAND;
    } else {
        ackMsg->command_result = CM_INVALID_COMMAND;
    }

    return;
}

static void ProcessZengineCommandResult(const ctl_to_cm_build *buildMsg, cm_to_ctl_command_ack *ackMsg,
    const cm_local_replconninfo *dnStatus)
{
    write_runlog(LOG, "(build) role = %d, state = %d, build reason = %d.\n", dnStatus->local_role, dnStatus->db_state,
        dnStatus->buildReason);
    if (dnStatus->local_role == INSTANCE_ROLE_STANDBY && (dnStatus->db_state == INSTANCE_HA_STATE_NORMAL ||
        dnStatus->db_state == INSTANCE_HA_STATE_NEED_REPAIR || buildMsg->force_build == CM_CTL_FORCE_BUILD)) {
        ackMsg->command_result = CM_CAN_PRCESS_COMMAND;
    }  else if (dnStatus->local_role == INSTANCE_ROLE_UNKNOWN) {
        ackMsg->command_result = CM_CAN_PRCESS_COMMAND;
    } else {
        ackMsg->command_result = CM_INVALID_COMMAND;
    }

    return;
}

static status_t ExeScpCommand(uint32 index)
{
    int ret;
    errno_t rc;
    char command[MAX_PATH_LEN] = { 0 };
    for (uint32 i = 0; i < g_node[index].sshCount; ++i) {
        if (GetIpVersion(g_node[index].sshChannel[i]) == AF_INET6) {
            rc = snprintf_s(command,
                MAX_PATH_LEN,
                MAX_PATH_LEN - 1,
                "scp -r %s/gstor/data %s@[%s]:%s/gstor",
                g_currentNode->cmDataPath,
                pw->pw_name,
                g_node[index].sshChannel[i],
                g_node[index].cmDataPath);
            securec_check_intval(rc, (void)rc);
        } else {
            rc = snprintf_s(command,
                MAX_PATH_LEN,
                MAX_PATH_LEN - 1,
                "scp -r %s/gstor/data %s@%s:%s/gstor",
                g_currentNode->cmDataPath,
                pw->pw_name,
                g_node[index].sshChannel[i],
                g_node[index].cmDataPath);
            securec_check_intval(rc, (void)rc);
        }
        ret = system(command);
        if (ret != -1 && WEXITSTATUS(ret) == 0) {
            write_runlog(LOG, "exec cmd(%s) success\n", command);
            return CM_SUCCESS;
        } else {
            write_runlog(ERROR, "exec cmd(%s) failed, ret = %d, errno = %d.\n", command, WEXITSTATUS(ret), errno);
            continue;
        }
    }

    return CM_ERROR;
}

static status_t CopyDccDataToRemote(uint32 nodeId)
{
    for (uint32 i = 0; i < g_node_num; ++i) {
        if (g_node[i].node == nodeId) {
            return ExeScpCommand(i);
        }
    }
    write_runlog(LOG, "node(%u) not exist, can't do build cms.\n", nodeId);

    return CM_ERROR;
}

static void ProcessCmsBuild(
    MsgRecvInfo* recvMsgInfo, uint32 nodeId, CmsBuildStep step, cm_to_ctl_command_ack *ackMsg)
{
    ackMsg->msg_type = (int)MSG_CM_CTL_COMMAND_ACK;
    ackMsg->isCmsBuildStepSuccess = false;

    switch (step) {
        case CMS_BUILD_LOCK:
            if (DoDdbSetBlocked(DDB_LOCK, DDB_SET_BLOCKED_TIMEOUT) == CM_SUCCESS) {
                write_runlog(LOG, "[build cms] dcc lock success.\n");
                ackMsg->isCmsBuildStepSuccess = true;
            } else {
                write_runlog(LOG, "[build cms] dcc lock failed.\n");
            }
            break;
        case CMS_BUILD_DOING:
            if (CopyDccDataToRemote(nodeId) == CM_SUCCESS) {
                write_runlog(LOG, "[build cms] copy data folder success.\n");
                ackMsg->isCmsBuildStepSuccess = true;
            } else {
                write_runlog(LOG, "[build cms] copy data folder failed.\n");
            }
            break;
        case CMS_BUILD_UNLOCK:
            if (DoDdbSetBlocked(DDB_UNLOCK, DDB_SET_BLOCKED_TIMEOUT) == CM_SUCCESS) {
                write_runlog(LOG, "[build cms] dcc unlock success\n");
                ackMsg->isCmsBuildStepSuccess = true;
            } else {
                write_runlog(LOG, "[build cms] dcc unlock failed.\n");
            }
            break;
        default:
            write_runlog(LOG, "[build cms] cms can't do unknown step.\n");
            break;
    }
    (void)RespondMsg(recvMsgInfo, 'S', (char *)ackMsg, sizeof(cm_to_ctl_command_ack));

    return;
}

/**
 * @brief  process build msg from cm_ctl
 *
 * @param  con         My Param doc
 * @param  buildMsg    My Param doc
 */
void ProcessCtlToCmBuildMsg(MsgRecvInfo* recvMsgInfo, ctl_to_cm_build *buildMsg)
{
    int memberIndex = 0;
    uint32 groupIndex = 0;
    cm_to_ctl_command_ack ackMsg = { 0 };

    if (g_enableSharedStorage) {
        write_runlog(LOG, "can't do build, in shared storage mode.\n");
        return;
    }

    if (backup_open != CLUSTER_PRIMARY) {
        ackMsg.msg_type = MSG_CM_CTL_BACKUP_OPEN;
        (void)RespondMsg(recvMsgInfo, 'S', (char *)(&ackMsg), sizeof(cm_to_ctl_command_ack));
        return;
    }

    if (buildMsg->cmsBuildStep != CMS_BUILD_NONE) {
        ProcessCmsBuild(recvMsgInfo, buildMsg->node, buildMsg->cmsBuildStep, &ackMsg);
        return;
    }

    if (IsBoolCmParamTrue(g_enableDcf) && g_clusterType != V3SingleInstCluster) {
        buildMsg->full_build = 1;
    }

    if (find_node_in_dynamic_configure(buildMsg->node, buildMsg->instanceId, &groupIndex, &memberIndex) != 0) {
        write_runlog(LOG, "can't find the instance(node=%u, instanceId=%u)\n", buildMsg->node, buildMsg->instanceId);
        return;
    }

    const cm_instance_role_status *instInfo = &g_instance_role_group_ptr[groupIndex].instanceMember[memberIndex];
    cm_instance_report_status *instStatus = &g_instance_group_report_status_ptr[groupIndex].instance_status;

    ackMsg.msg_type = MSG_CM_CTL_COMMAND_ACK;
    ackMsg.node = buildMsg->node;
    ackMsg.instanceId = instInfo->instanceId;
    ackMsg.instance_type = instInfo->instanceType;

    if (ackMsg.instance_type == INSTANCE_TYPE_DATANODE) {
        if (g_clusterType == V3SingleInstCluster) {
            ProcessZengineCommandResult(buildMsg, &ackMsg, &instStatus->data_node_member[memberIndex].local_status);
        } else {
            ProcessDatanodeCommandResult(buildMsg, &ackMsg, &instStatus->data_node_member[memberIndex].local_status);
        }
    } else {
        ackMsg.command_result = CM_INVALID_COMMAND;
    }

    ackMsg.command_status = instStatus->command_member[memberIndex].command_status;
    ackMsg.pengding_command = instStatus->command_member[memberIndex].pengding_command;

    /* if cluster is multi az, the cluster will have more standby than one */
    if (ExistAnotherCommandRunning(groupIndex, ackMsg, recvMsgInfo, buildMsg)) {
        write_runlog(DEBUG1, "exist another command running.\n");
        return;
    }

    if (ackMsg.command_result == CM_INVALID_COMMAND) {
        (void)RespondMsg(recvMsgInfo, 'S', (char *)(&ackMsg), sizeof(ackMsg));
        return;
    }

    if ((IsSendBuild(instStatus->data_node_member[memberIndex].local_status.local_role)) &&
        (instStatus->data_node_member[memberIndex].local_status.db_state == INSTANCE_HA_STATE_NORMAL) &&
        (buildMsg->force_build != CM_CTL_FORCE_BUILD)) {
        ackMsg.command_result = CM_DN_NORMAL_STATE;
        (void)RespondMsg(recvMsgInfo, 'S', (char*)(&ackMsg), sizeof(ackMsg));
        write_runlog(LOG, "instance %u is normal standby, will do nothing for build request without -f from cm_ctl.\n",
            instInfo->instanceId);
        return;
    }

    (void)RespondMsg(recvMsgInfo, 'S', (char *)(&ackMsg), sizeof(ackMsg));
    write_runlog(LOG, "set the instance %u to do build by cm_ctl.\n", instInfo->instanceId);

    (void)pthread_rwlock_wrlock(&(g_instance_group_report_status_ptr[groupIndex].lk_lock));
    instStatus->command_member[memberIndex].command_status = INSTANCE_COMMAND_WAIT_EXEC;
    instStatus->command_member[memberIndex].pengding_command = MSG_CM_AGENT_BUILD;
    instStatus->command_member[memberIndex].time_out = buildMsg->wait_seconds;
    instStatus->command_member[memberIndex].full_build = buildMsg->full_build;
    instStatus->command_member[memberIndex].parallel = buildMsg->parallel;
    (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[groupIndex].lk_lock));

    return;
}

/**
 * @brief
 *
 * @param  con              My Param doc
 * @param  noNeedDoGtmNum   My Param doc
 * @param  needDoGtmNum     My Param doc
 * @param  noNeedDoDnNum    My Param doc
 * @param  needDoDnNum      My Param doc
 * @return true
 * @return false
 */
static bool process_ctl_to_cm_switchover_incomplete_msg(
    MsgRecvInfo* recvMsgInfo, int noNeedDoGtmNum, int needDoGtmNum, int noNeedDoDnNum, int needDoDnNum)
{
    bool hasWarning = false;
    cm_switchover_incomplete_msg switchover_incomplete_msg = {0};
    const int one = 1;

    if ((noNeedDoGtmNum + needDoGtmNum) != one && !g_only_dn_cluster) {
        int rcs = snprintf_s(switchover_incomplete_msg.errMsg, CM_MSG_ERR_INFORMATION_LENGTH,
            CM_MSG_ERR_INFORMATION_LENGTH - 1, "need do 1 gtm and %u dn for switchover, but only find %d gtm",
            g_datanode_instance_count, (noNeedDoGtmNum + needDoGtmNum));
        securec_check_intval(rcs, (void)rcs);
        hasWarning = true;
    }
    if ((noNeedDoDnNum + needDoDnNum) != (int)g_datanode_instance_count) {
        if ((noNeedDoGtmNum + needDoGtmNum) != one) {
            size_t len = strlen(switchover_incomplete_msg.errMsg);
            if (len < (CM_MSG_ERR_INFORMATION_LENGTH - 1)) {
                int rcs = snprintf_s(switchover_incomplete_msg.errMsg + len,
                    CM_MSG_ERR_INFORMATION_LENGTH - len, (CM_MSG_ERR_INFORMATION_LENGTH - 1) - len,
                    "need do %d dn for switchover, but only find %d dn", g_datanode_instance_count,
                    (noNeedDoDnNum + needDoDnNum));
                securec_check_intval(rcs, (void)rcs);
            }
        } else {
            int rcs = snprintf_s(switchover_incomplete_msg.errMsg, CM_MSG_ERR_INFORMATION_LENGTH,
                CM_MSG_ERR_INFORMATION_LENGTH - 1, "need do 1 gtm and %u dn for switchover, but only find %d dn",
                g_datanode_instance_count, (noNeedDoDnNum + needDoDnNum));
            securec_check_intval(rcs, (void)rcs);
        }
        hasWarning = true;
    }
    if (hasWarning) {
        switchover_incomplete_msg.msg_type = MSG_CM_CTL_SWITCHOVER_INCOMPLETE_ACK;
        (void)RespondMsg(recvMsgInfo, 'S', (char *)(&switchover_incomplete_msg), sizeof(switchover_incomplete_msg));
    }

    return hasWarning;
}

static void process_single_instance_switchover_info(switchover_instance *instance, int instanceType,
    uint32 i, int j, const ctl_to_cm_switchover* ctl_to_cm_swithover_ptr)
{
    /* do switchover */
    cm_instance_report_status *instReport = &(g_instance_group_report_status_ptr[i].instance_status);
    cm_instance_command_status *cmd = &(instReport->command_member[j]);
    cmd->command_status = INSTANCE_COMMAND_WAIT_EXEC;
    cmd->pengding_command = (int)MSG_CM_AGENT_SWITCHOVER;
    if (g_ssDoubleClusterMode == SS_DOUBLE_STANDBY) {
        cmd->cmdPur = INSTANCE_ROLE_MAIN_STANDBY;
    } else {
        cmd->cmdPur = INSTANCE_ROLE_PRIMARY;
    }
    cmd->cmdSour = INSTANCE_ROLE_STANDBY;
    cmd->peerInstId = GetPeerInstId(i, j);
    cmd->time_out = ctl_to_cm_swithover_ptr->wait_seconds;
    write_runlog(LOG, "full switchover instanceid %u\n", g_instance_role_group_ptr[i].instanceMember[j].instanceId);
    int32 localRole = instReport->data_node_member[j].local_status.local_role;
    write_runlog(LOG, "instd(%u) localRole is (%d: %s), cmd[cmdPur(%d: %s), cmdSour(%d: %s), peerInstId: %u].\n",
        GetInstanceIdInGroup(i, j), localRole, datanode_role_int_to_string(localRole), cmd->cmdPur,
        datanode_role_int_to_string(cmd->cmdPur), cmd->cmdSour, datanode_role_int_to_string(cmd->cmdSour),
        cmd->peerInstId);
    /* clear peer comand status */
    for (int k = 0; k < g_instance_role_group_ptr[i].count; k++) {
        if (j != k) {
            CleanCommand(i, k);
        }
    }

    /* save instance  info */
    instance->node = g_instance_role_group_ptr[i].instanceMember[j].node;
    instance->instanceId = g_instance_role_group_ptr[i].instanceMember[j].instanceId;
    instance->instanceType = instanceType;
    switchOverInstances.push_back(*instance);
}

bool IsInCatchUpState(uint32 ptrIndex, int memberIndex)
{
    /* Single file: 16 MB, if the file gap exceeds 240, the switchover is not allowed */
    const XLogRecPtr fileSize = 0x1000000;
    const uint32 maxFileGap = 240;
    const uint32 high = 32;

    if (g_instance_group_report_status_ptr[ptrIndex].instance_status.data_node_member[memberIndex].
        local_status.local_role != INSTANCE_ROLE_STANDBY) {
        return false;
    }

    XLogRecPtr primaryFlushLocation = g_instance_group_report_status_ptr[ptrIndex].instance_status.
        data_node_member[memberIndex].receive_status.sender_flush_location;
    XLogRecPtr standbyReplayLocation = g_instance_group_report_status_ptr[ptrIndex].instance_status.
        data_node_member[memberIndex].receive_status.receiver_replay_location;
    XLogRecPtr gap = primaryFlushLocation - standbyReplayLocation;

    if (gap > maxFileGap * fileSize) {
        write_runlog(LOG, "dn instanceid=%u, xlog location gap between the primary and standby is too large, "
            "primaryFlushLocation=%08X/%08X, standbyReplayLocation=%08X/%08X, gap=%08X/%08X.\n",
            g_instance_role_group_ptr[ptrIndex].instanceMember[memberIndex].instanceId,
            (uint32)(primaryFlushLocation >> high), (uint32)primaryFlushLocation,
            (uint32)(standbyReplayLocation >> high), (uint32)standbyReplayLocation,
            (uint32)(gap >> high), (uint32)gap);
        return true;
    }
    write_runlog(LOG,
        "dn instanceid=%u, primaryFlushLocation=%08X/%08X, standbyReplayLocation=%08X/%08X, gap=%08X/%08X.\n",
        g_instance_role_group_ptr[ptrIndex].instanceMember[memberIndex].instanceId,
        (uint32)(primaryFlushLocation >> high), (uint32)primaryFlushLocation,
        (uint32)(standbyReplayLocation >> high), (uint32)standbyReplayLocation,
        (uint32)(gap >> high), (uint32)gap);
    return false;
}

static bool CanDoSwitchoverInAllShard(MsgRecvInfo* recvMsgInfo, cm_to_ctl_command_ack *msg,
    const ctl_to_cm_switchover *swithoverPtr, const char *str)
{
    if (isInOnDemandStatus()) {
        msg->command_result = CM_DN_IN_ONDEMAND_STATUE;
        msg->pengding_command = (int)MSG_CM_AGENT_SWITCHOVER;
        (void)RespondMsg(recvMsgInfo, 'S', (const char *)(msg), sizeof(cm_to_ctl_command_ack));
        return false;
    }
    int32 instType = 0;
    for (uint32 i = 0; i < g_dynamic_header->relationCount; i++) {
        instType = g_instance_role_group_ptr[i].instanceMember[0].instanceType;
        if ((instType != INSTANCE_TYPE_GTM) && (instType != INSTANCE_TYPE_DATANODE)) {
            continue;
        }
        for (int j = 0; j < g_instance_role_group_ptr[i].count; j++) {
            cm_instance_command_status *cmd =
                &(g_instance_group_report_status_ptr[i].instance_status.command_member[j]);
            if (cmd->command_status != INSTANCE_NONE_COMMAND) {
                msg->command_result = CM_ANOTHER_COMMAND_RUNNING;
                msg->pengding_command = cmd->pengding_command;
                write_runlog(LOG, "do %s instance(node =%u  instanceid =%u) is executing another command (%d)\n",
                    str, swithoverPtr->node, swithoverPtr->instanceId, msg->pengding_command);
                (void)RespondMsg(recvMsgInfo, 'S', (const char *)(msg), sizeof(cm_to_ctl_command_ack));
                return false;
            }
        }
        if (CheckInstInSyncList(i, 0, str) == SYNCLIST_IS_NOT_SAME) {
            msg->command_result = CM_ANOTHER_COMMAND_RUNNING;
            msg->pengding_command = (int)MSG_CM_AGENT_DN_SYNC_LIST;
            write_runlog(LOG, "do %s instance(node =%u  instanceid =%u) is executing another command (%d)\n",
                str, swithoverPtr->node, swithoverPtr->instanceId, (int)MSG_CM_AGENT_DN_SYNC_LIST);
            (void)RespondMsg(recvMsgInfo, 'S', (const char *)(msg), sizeof(cm_to_ctl_command_ack));
            return false;
        }
    }
    return true;
}

static void CheckSwitchoverInstance(const ctl_to_cm_switchover* swithoverPtr, const char *str)
{
    uint32 count = (uint32)switchOverInstances.size();
    if (count > 0) {
        cmserver_switchover_timeout = (uint32)(swithoverPtr->wait_seconds);
        write_runlog(LOG, "%s, switchoversize is %u, timeout is %u.\n", str, count, cmserver_switchover_timeout);
    }
}

/**
 * @brief cm server process the msg from cm_ctl to do a full switchover
 *
 * @param  con              My Param doc
 * @param  ctl_to_cm_swithover_ptrMy Param doc
 */
void process_ctl_to_cm_switchover_full_msg(
    MsgRecvInfo* recvMsgInfo, const ctl_to_cm_switchover *ctl_to_cm_swithover_ptr)
{
    int instanceType = 0;
    switchover_instance instance;
    cm_to_ctl_command_ack msgSwitchoverFullAck = {0};
    msgSwitchoverFullAck.msg_type = MSG_CM_CTL_SWITCHOVER_FULL_ACK;

    if (!CanDoSwitchoverInAllShard(
        recvMsgInfo, &msgSwitchoverFullAck, ctl_to_cm_swithover_ptr, "switchover_full_msg")) {
        return;
    }

    const int noNeedDoGtmNum = 0;
    int noNeedDoDnNum = 0;
    int needDoGtmNum = 0;
    int needDoDnNum = 0;
    bool isInVoteAz = false;
    bool doResult = false;
    bool isCatchUp = false;
    for (uint32 i = 0; i < g_dynamic_header->relationCount; i++) {
        (void)pthread_rwlock_wrlock(&(g_instance_group_report_status_ptr[i].lk_lock));
        for (int j = 0; j < g_instance_role_group_ptr[i].count; j++) {
            bool notNeedFindSwitchover = false;
            instanceType = g_instance_role_group_ptr[i].instanceMember[j].instanceType;
            isInVoteAz = IsCurInstanceInVoteAz(i, j);
            switch (instanceType) {
                case INSTANCE_TYPE_GTM:
                    doResult = (g_instance_group_report_status_ptr[i].instance_status.gtm_member[j]
                                .local_status.local_role == INSTANCE_ROLE_STANDBY &&
                                g_instance_group_report_status_ptr[i].instance_status.gtm_member[j]
                                .local_status.connect_status == CON_OK && !isInVoteAz);
                    if (doResult) {
                        process_single_instance_switchover_info(&instance, instanceType,
                            i, j, ctl_to_cm_swithover_ptr);
                        needDoGtmNum++;
                        notNeedFindSwitchover = true;
                    }
                    break;
                case INSTANCE_TYPE_DATANODE: {
                    isCatchUp = IsInCatchUpState(i, j);
                    doResult = (g_instance_group_report_status_ptr[i].instance_status.data_node_member[j]
                                .local_status.local_role == INSTANCE_ROLE_STANDBY &&
                                g_instance_group_report_status_ptr[i].instance_status.data_node_member[j]
                                .local_status.db_state == INSTANCE_HA_STATE_NORMAL && !isInVoteAz && !isCatchUp);
                    EnCheckSynclist eCheck = CheckInstInSyncList(i, j, "[process_ctl_to_cm_switchover_full_msg]");
                    if (doResult) {
                        if (eCheck == SYNCLIST_IS_FINISTH) {
                            process_single_instance_switchover_info(&instance, instanceType,
                                i, j, ctl_to_cm_swithover_ptr);
                            needDoDnNum++;
                            notNeedFindSwitchover = true;
                        } else if (eCheck == SYNCLIST_IS_NOT_SAME) {
                            noNeedDoDnNum++;
                            notNeedFindSwitchover = true;
                        }
                    }
                    break;
                }
                default:
                    break;
            }
            if (notNeedFindSwitchover) {
                break;
            }
        }
        (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[i].lk_lock));
    }

    (void)process_ctl_to_cm_switchover_incomplete_msg(
        recvMsgInfo, noNeedDoGtmNum, needDoGtmNum, noNeedDoDnNum, needDoDnNum);
    CheckSwitchoverInstance(ctl_to_cm_swithover_ptr, "[process_ctl_to_cm_switchover_full_msg]");

    (void)RespondMsg(recvMsgInfo, 'S', (char*)(&msgSwitchoverFullAck), sizeof(msgSwitchoverFullAck));
}

/**
 * @brief cm server process the msg from cm_ctl to do a az switchover
 *
 * @param  con              My Param doc
 * @param  ctl_to_cm_swithover_ptrMy Param doc
 */
void ProcessCtlToCmSwitchoverAzMsg(MsgRecvInfo* recvMsgInfo, ctl_to_cm_switchover* ctl_to_cm_swithover_ptr)
{
    ctl_to_cm_swithover_ptr->azName[CM_AZ_NAME - 1] = '\0';
    int instanceType = 0;
    cm_msg_type msgSwitchoverAZAck;

    char *azName = ctl_to_cm_swithover_ptr->azName;
    bool isVoteAz = false;
    for (int i = 0; i < AZ_MEMBER_MAX_COUNT; ++i) {
        if (g_cmAzInfo[i].isVoteAz == IS_NOT_VOTE_AZ) {
            continue;
        }
        if (strncmp(azName, g_cmAzInfo[i].azName, strlen(azName)) == 0) {
            isVoteAz = true;
            write_runlog(ERROR, "this az(%s) is vote az, cannot promote primary.\n", azName);
        }
    }

    /* check if another cm_ctl switchover -z is running */
    (void)pthread_rwlock_wrlock(&(switchover_az_rwlock));
    if (switchoverAZInProgress) {
        msgSwitchoverAZAck.msg_type = (int)MSG_CM_CTL_SWITCHOVER_AZ_DENIED;
        (void)RespondMsg(recvMsgInfo, 'S', (char*)(&msgSwitchoverAZAck), sizeof(msgSwitchoverAZAck));
        (void)pthread_rwlock_unlock(&(switchover_az_rwlock));
        return;
    } else if (isVoteAz) {
        msgSwitchoverAZAck.msg_type = (int)MSG_CM_CTL_INVALID_COMMAND_ACK;
        (void)RespondMsg(recvMsgInfo, 'S', (char*)(&msgSwitchoverAZAck), sizeof(msgSwitchoverAZAck));
        (void)pthread_rwlock_unlock(&(switchover_az_rwlock));
        return;
    } else if (!CheckAllDnShardSynclist("[ProcessCtlToCmSwitchoverAzMsg]")) {
        msgSwitchoverAZAck.msg_type = (int)MSG_CM_AGENT_DN_SYNC_LIST;
        (void)RespondMsg(recvMsgInfo, 'S', (char *)(&msgSwitchoverAZAck), sizeof(msgSwitchoverAZAck));
        (void)pthread_rwlock_unlock(&(switchover_az_rwlock));
        return;
    } else {
        switchoverAZInProgress = true;
        (void)pthread_rwlock_unlock(&(switchover_az_rwlock));
    }

    int needDoGtmNum = 0;
    int needDoDnNum = 0;
    int noNeedDoGtmNum = 0;
    int noNeedDoDnNum = 0;

    for (uint32 i = 0; i < g_dynamic_header->relationCount; i++) {
        bool primaryInstanceInTargetAZ = false;
        bool switchedInstanceInTargetAZ = false;
        bool checkSwitchoverInstance = false;
        bool isCatchUp = false;
        (void)pthread_rwlock_wrlock(&(g_instance_group_report_status_ptr[i].lk_lock));

        /* if there is a primary instance in the target AZ, no more switchover will be needed. */
        for (int j = 0; j < g_instance_role_group_ptr[i].count; j++) {
            bool sameAz =
                (strcmp(ctl_to_cm_swithover_ptr->azName, g_instance_role_group_ptr[i].instanceMember[j].azName) == 0);
            if (g_instance_role_group_ptr[i].instanceMember[j].instanceType == INSTANCE_TYPE_GTM &&
                g_instance_group_report_status_ptr[i].instance_status.gtm_member[j].local_status.local_role ==
                INSTANCE_ROLE_PRIMARY && sameAz) {
                primaryInstanceInTargetAZ = true;
                noNeedDoGtmNum++;
                checkSwitchoverInstance = true;
                break;
            } else if (g_instance_role_group_ptr[i].instanceMember[j].instanceType == INSTANCE_TYPE_DATANODE &&
                ((g_instance_group_report_status_ptr[i].instance_status.data_node_member[j]
                .local_status.local_role == INSTANCE_ROLE_PRIMARY ||
                g_instance_group_report_status_ptr[i].instance_status.data_node_member[j]
                .local_status.local_role == INSTANCE_ROLE_MAIN_STANDBY) && sameAz)) {
                primaryInstanceInTargetAZ = true;
                noNeedDoDnNum++;
                checkSwitchoverInstance = true;
                break;
            }
        }

        if (primaryInstanceInTargetAZ) {
            (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[i].lk_lock));
            continue;
        }

        for (int j = 0; j < g_instance_role_group_ptr[i].count && !switchedInstanceInTargetAZ; j++) {
            if (strcmp(ctl_to_cm_swithover_ptr->azName, g_instance_role_group_ptr[i].instanceMember[j].azName) == 0) {
                instanceType = g_instance_role_group_ptr[i].instanceMember[j].instanceType;
                switch (instanceType) {
                    case INSTANCE_TYPE_GTM:
                        if (g_instance_group_report_status_ptr[i].instance_status.gtm_member[j]
                            .local_status.local_role == INSTANCE_ROLE_STANDBY &&
                            g_instance_group_report_status_ptr[i].instance_status.gtm_member[j]
                            .local_status.connect_status == CON_OK) {
                            SwitchOverSetting(ctl_to_cm_swithover_ptr->wait_seconds, instanceType, i, j);
                            switchedInstanceInTargetAZ = true;
                            checkSwitchoverInstance = true;
                            needDoGtmNum++;
                        }

                        break;
                    case INSTANCE_TYPE_DATANODE: {
                        isCatchUp = IsInCatchUpState(i, j);
                        bool res = (g_instance_group_report_status_ptr[i].instance_status.data_node_member[j]
                                .local_status.local_role == INSTANCE_ROLE_STANDBY &&
                            g_instance_group_report_status_ptr[i].instance_status.data_node_member[j]
                                .local_status.db_state == INSTANCE_HA_STATE_NORMAL && !isCatchUp &&
                                (CheckInstInSyncList(i, j, "[ProcessCtlToCmSwitchoverAzMsg]") == SYNCLIST_IS_FINISTH));
                        if (res) {
                            SwitchOverSetting(ctl_to_cm_swithover_ptr->wait_seconds, instanceType, i, j);
                            switchedInstanceInTargetAZ = true;
                            checkSwitchoverInstance = true;
                            needDoDnNum++;
                        }
                        break;
                    }

                    default:
                        break;
                }
            }
        }
        if (!checkSwitchoverInstance && g_instance_role_group_ptr[i].count > 0) {
            if (g_instance_role_group_ptr[i].instanceMember[0].instanceType == INSTANCE_TYPE_GTM) {
                write_runlog(LOG, "cannot find legal switchover goal in gtm group %u, switchover incomplete.\n", i);
            } else if (g_instance_role_group_ptr[i].instanceMember[0].instanceType == INSTANCE_TYPE_DATANODE) {
                write_runlog(LOG, "cannot find legal switchover goal in dn group %u, switchover incomplete.\n", i);
            }
        }
        (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[i].lk_lock));
    }

    (void)process_ctl_to_cm_switchover_incomplete_msg(
        recvMsgInfo, noNeedDoGtmNum, needDoGtmNum, noNeedDoDnNum, needDoDnNum);
    CheckSwitchoverInstance(ctl_to_cm_swithover_ptr, "[ProcessCtlToCmSwitchoverAzMsg]");

    msgSwitchoverAZAck.msg_type = MSG_CM_CTL_SWITCHOVER_AZ_ACK;
    (void)RespondMsg(recvMsgInfo, 'S', (char *)(&msgSwitchoverAZAck), sizeof(msgSwitchoverAZAck));
}

/**
 * @brief Set the Switchover In Switchover Done object
 *
 * @param  ptrIndex         My Param doc
 * @param  memberIndex      My Param doc
 */
static void SetSwitchoverInSwitchoverDone(uint32 groupIdx, int memIdx, bool isNeedDelay)
{
    write_runlog(LOG, "add switchover instanceid=%u.\n",
        g_instance_role_group_ptr[groupIdx].instanceMember[memIdx].instanceId);
    SetSwitchoverPendingCmd(groupIdx, memIdx, SWITCHOVER_DEFAULT_WAIT, "[SetSwitchoverInSwitchoverDone]", isNeedDelay);
    (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[groupIdx].lk_lock));
}

/* 
 * This function is only used under on-demand recovery.
 */
static bool CanDoSwitchoverUnderOnDemandStatus()
{
    if (isInOnDemandStatus()) {
        write_runlog(LOG, "We can not process switchover because cluster in on-demand redo status.\n");
        return false;
    }
    return true;
}


/* *
 * @brief check cm_ctl switchover -a done
 *        if switchover DONE return true
 *            1. no MSG_CM_AGENT_SWITCHOVER pending command
 *            2. standby instance have Promoting to Primary
 *
 * @return int
 */
static int SwitchoverDone(void)
{
    bool partlySwitchover = false;
    bool allInitPrimaryNormal = true;
    bool anyInitPrimarySwitchover = false;
    int voteAZ = GetVoteAzIndex();
    uint32 gtmCount = 0;
    uint32 dnCount = 0;
    bool partlySwitchoverWithVoteAZ = false;
    uint32 instanceId = 0;
    const char *str = "[SwitchoverDone]";

    if (!CanDoSwitchoverUnderOnDemandStatus()) {
        return SWITCHOVER_CANNOT_RESPONSE;
    }
    for (uint32 i = 0; i < g_dynamic_header->relationCount; i++) {
        (void)pthread_rwlock_wrlock(&(g_instance_group_report_status_ptr[i].lk_lock));
        for (int j = 0; j < g_instance_role_group_ptr[i].count; j++) {
            int instanceType = g_instance_role_group_ptr[i].instanceMember[j].instanceType;
            int initRole = g_instance_role_group_ptr[i].instanceMember[j].instanceRoleInit;
            int* command = &g_instance_group_report_status_ptr[i].instance_status.command_member[j].pengding_command;
            instanceId = g_instance_role_group_ptr[i].instanceMember[j].instanceId;
            switch (instanceType) {
                case INSTANCE_TYPE_GTM: {
                    const cm_gtm_replconninfo *gtmLocalStat =
                        &g_instance_group_report_status_ptr[i].instance_status.gtm_member[j].local_status;
                    int gtmLocalRole = gtmLocalStat->local_role;
                    if (initRole == INSTANCE_ROLE_PRIMARY && gtmLocalRole != INSTANCE_ROLE_PRIMARY &&
                        *command != (int32)MSG_CM_AGENT_SWITCHOVER && gtmLocalStat->connect_status == CON_OK) {
                        SetSwitchoverInSwitchoverDone(i, j, false);
                        return SWITCHOVER_EXECING;
                    }

                    if ((*command == MSG_CM_AGENT_SWITCHOVER) &&
                        (gtmLocalRole != INSTANCE_ROLE_PRIMARY && initRole == INSTANCE_ROLE_PRIMARY)) {
                        (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[i].lk_lock));
                        write_runlog(LOG, "%s: inst(%u) is doing switchover.\n", str, instanceId);
                        return SWITCHOVER_EXECING;
                    }
                    if (*command != MSG_CM_AGENT_SWITCHOVER && gtmLocalRole != INSTANCE_ROLE_PRIMARY &&
                        initRole == INSTANCE_ROLE_PRIMARY) {
                        write_runlog(LOG, "line %s: %d: instanceId(%u) has not do switchover.\n",
                            str, __LINE__, instanceId);
                        partlySwitchover = true;
                        gtmCount++;
                    }

                    if (initRole == INSTANCE_ROLE_PRIMARY && gtmLocalRole != INSTANCE_ROLE_PRIMARY &&
                        gtmLocalRole != INSTANCE_ROLE_STANDBY) {
                        (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[i].lk_lock));
                        write_runlog(LOG, "%s: inst(%u) canot do switchover, because gtm role is %d.\n",
                            str, instanceId, gtmLocalRole);
                        return SWITCHOVER_ABNORMAL;
                    }
                    break;
                }
                case INSTANCE_TYPE_DATANODE: {
                    int localStatus =
                        g_instance_group_report_status_ptr[i].instance_status.data_node_member[j].local_status.db_state;
                    int dnLocalRole = g_instance_group_report_status_ptr[i].instance_status.data_node_member[j]
                        .local_status.local_role;
                    bool enCheck = (CheckInstInSyncList(i, j, str) == SYNCLIST_IS_FINISTH);
                    if ((initRole == INSTANCE_ROLE_PRIMARY || initRole == INSTANCE_ROLE_MAIN_STANDBY) &&
                        (dnLocalRole != INSTANCE_ROLE_PRIMARY && dnLocalRole != INSTANCE_ROLE_MAIN_STANDBY) &&
                        *command != (int)MSG_CM_AGENT_SWITCHOVER && enCheck) {
                        if (localStatus == INSTANCE_HA_STATE_NORMAL) {
                            set_pending_command(i, j, MSG_CM_AGENT_SWITCHOVER, SWITCHOVER_DEFAULT_WAIT);
                            write_runlog(LOG, "%s: add switchover instanceid %u.\n", str,
                                g_instance_role_group_ptr[i].instanceMember[j].instanceId);
                            SetSwitchoverInSwitchoverDone(i, j, true);
                            return SWITCHOVER_EXECING;
                        } else {
                            allInitPrimaryNormal = false;
                            write_runlog(LOG, "%s: The db state of init primary datanode (instance_id %u) is "
                                "abnormal.\n", str, g_instance_role_group_ptr[i].instanceMember[j].instanceId);
                        }
                    }

                    if ((initRole == INSTANCE_ROLE_PRIMARY || initRole == INSTANCE_ROLE_MAIN_STANDBY) && dnLocalRole == INSTANCE_ROLE_STANDBY &&
                        localStatus == INSTANCE_HA_STATE_PROMOTING && *command == MSG_CM_AGENT_SWITCHOVER) {
                        anyInitPrimarySwitchover = true;
                    }

                    /* must keep three or in this if condition, otherwise will result to some problem. */
                    if (*command == MSG_CM_AGENT_SWITCHOVER &&
                        (((dnLocalRole != INSTANCE_ROLE_PRIMARY && dnLocalRole != INSTANCE_ROLE_MAIN_STANDBY) &&
                            (initRole == INSTANCE_ROLE_PRIMARY || initRole == INSTANCE_ROLE_MAIN_STANDBY)) ||
                            ((g_instance_role_group_ptr[i].instanceMember[j].role == INSTANCE_ROLE_PRIMARY ||
                            g_instance_role_group_ptr[i].instanceMember[j].role == INSTANCE_ROLE_MAIN_STANDBY) &&
                            localStatus != INSTANCE_HA_STATE_NORMAL))) {
                        (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[i].lk_lock));
                        write_runlog(LOG, "%s: inst(%u) is doing switchover.\n", str, instanceId);
                        return SWITCHOVER_EXECING;
                    }

                    if (*command != MSG_CM_AGENT_SWITCHOVER &&
                        (dnLocalRole != INSTANCE_ROLE_PRIMARY && dnLocalRole != INSTANCE_ROLE_MAIN_STANDBY) &&
                        (initRole == INSTANCE_ROLE_PRIMARY || initRole == INSTANCE_ROLE_MAIN_STANDBY)) {
                        write_runlog(LOG, "line %d: instanceId(%u) has not do switchover.\n", __LINE__, instanceId);
                        dnCount++;
                        partlySwitchover = true;
                    }
                    break;
                }
                default:
                    break;
            }
        }
        (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[i].lk_lock));
    }

    if (voteAZ != AZ_ALL_INDEX) {
        write_runlog(LOG, "%s voteAZ is %d, gtmCount is [%u/%u], dnCount is [%u/%u].\n",
            str, voteAZ, gtmCount, g_cmAzInfo[voteAZ].gtmDuplicate, dnCount, g_cmAzInfo[voteAZ].dnDuplicate);
        if ((gtmCount + dnCount) == (g_cmAzInfo[voteAZ].gtmDuplicate + g_cmAzInfo[voteAZ].dnDuplicate)) {
            partlySwitchoverWithVoteAZ = true;
        }
    }
    write_runlog(LOG, "[SwitchoverDone] partlySwitchover is %d, partlySwitchoverWithVoteAZ is %d, "
        "allInitPrimaryNormal is %d, anyInitPrimarySwitchover is %d.\n",
        partlySwitchover, partlySwitchoverWithVoteAZ, allInitPrimaryNormal, anyInitPrimarySwitchover);
    if (partlySwitchover && !partlySwitchoverWithVoteAZ) {
        return SWITCHOVER_PARTLY_SUCCESS;
    }
    if ((!allInitPrimaryNormal && !anyInitPrimarySwitchover) || partlySwitchoverWithVoteAZ) {
        return SWITCHOVER_ABNORMAL;
    }

    return SWITCHOVER_SUCCESS;
}

/**
 * @brief
 *
 * @param  con              My Param doc
 */
void ProcessCtlToCmSwitchoverFullCheckMsg(MsgRecvInfo* recvMsgInfo)
{
    cm_to_ctl_switchover_full_check_ack msgSwitchoverFullCheckAck;
    msgSwitchoverFullCheckAck.msg_type = MSG_CM_CTL_SWITCHOVER_FULL_CHECK_ACK;

    int32 switchoverDone = GetSwitchoverDone("[ProcessCtlToCmSwitchoverFullCheckMsg]");
    msgSwitchoverFullCheckAck.switchoverDone = switchoverDone;

    (void)RespondMsg(recvMsgInfo, 'S', (char *)(&msgSwitchoverFullCheckAck), sizeof(msgSwitchoverFullCheckAck));

    /* delete the data and clear the flag. */
    if ((switchoverDone == SWITCHOVER_SUCCESS) || (switchoverDone == SWITCHOVER_PARTLY_SUCCESS)) {
        write_runlog(LOG, "Switchover -A has been completed.\n");
        switchOverInstances.clear();
        (void)pthread_rwlock_wrlock(&(switchover_full_rwlock));
        switchoverFullInProgress = false;
        (void)pthread_rwlock_unlock(&(switchover_full_rwlock));
    }
}

/**
 * @brief
 *
 * @param  con              My Param doc
 */
void ProcessCtlToCmSwitchoverAzCheckMsg(MsgRecvInfo* recvMsgInfo)
{
    cm_to_ctl_switchover_az_check_ack msgSwitchoverAZCheckAck;
    msgSwitchoverAZCheckAck.msg_type = MSG_CM_CTL_SWITCHOVER_AZ_CHECK_ACK;

    int32 switchoverDone = GetSwitchoverDone("[ProcessCtlToCmSwitchoverAzCheckMsg]");
    msgSwitchoverAZCheckAck.switchoverDone = switchoverDone;

    (void)RespondMsg(recvMsgInfo, 'S', (char *)(&msgSwitchoverAZCheckAck), sizeof(msgSwitchoverAZCheckAck));

    /* delete the data and clear the flag. */
    if ((switchoverDone == SWITCHOVER_SUCCESS) || (switchoverDone == SWITCHOVER_PARTLY_SUCCESS)) {
        write_runlog(LOG, "Switchover -z has been completed.\n");
        switchOverInstances.clear();
        (void)pthread_rwlock_wrlock(&(switchover_az_rwlock));
        switchoverAZInProgress = false;
        (void)pthread_rwlock_unlock(&(switchover_az_rwlock));
    }
}

/**
 * @brief
 *
 * @param  con              My Param doc
 */
void ProcessCtlToCmSwitchoverFullTimeoutMsg(MsgRecvInfo* recvMsgInfo)
{
    cm_msg_type msgSwitchoverFullTimeoutAck;
    msgSwitchoverFullTimeoutAck.msg_type = MSG_CM_CTL_SWITCHOVER_FULL_TIMEOUT_ACK;

    (void)RespondMsg(recvMsgInfo, 'S', (char *)(&msgSwitchoverFullTimeoutAck), sizeof(msgSwitchoverFullTimeoutAck));

    /* delete the data and clear the flag. */
    switchOverInstances.clear();
    (void)pthread_rwlock_wrlock(&(switchover_full_rwlock));
    switchoverFullInProgress = false;
    (void)pthread_rwlock_unlock(&(switchover_full_rwlock));
}
/**
 * @brief
 *
 * @param  con              My Param doc
 */
void process_ctl_to_cm_switchover_az_timeout_msg(MsgRecvInfo* recvMsgInfo)
{
    cm_msg_type msgSwitchoverAZTimeoutAck;

    msgSwitchoverAZTimeoutAck.msg_type = MSG_CM_CTL_SWITCHOVER_AZ_TIMEOUT_ACK;
    (void)RespondMsg(recvMsgInfo, 'S', (char *)(&msgSwitchoverAZTimeoutAck), sizeof(msgSwitchoverAZTimeoutAck));

    /* delete the data and clear the flag. */
    switchOverInstances.clear();
    (void)pthread_rwlock_wrlock(&(switchover_az_rwlock));
    switchoverAZInProgress = false;
    (void)pthread_rwlock_unlock(&(switchover_az_rwlock));
}

/**
 * @brief
 *
 * @param  con              My Param doc
 */
void process_ctl_to_cm_balance_check_msg(MsgRecvInfo* recvMsgInfo)
{
    cm_to_ctl_balance_check_ack msgBalanceCheckAck;

    msgBalanceCheckAck.msg_type = MSG_CM_CTL_BALANCE_CHECK_ACK;
    msgBalanceCheckAck.switchoverDone = SwitchoverDone();

    write_runlog(LOG, "the balance state is %d by DN.\n", msgBalanceCheckAck.switchoverDone);

#ifdef ENABLE_MULTIPLE_NODES
    if (msgBalanceCheckAck.switchoverDone == SWITCHOVER_SUCCESS) {
        msgBalanceCheckAck.switchoverDone = CheckNotifyCnStatus();
        write_runlog(LOG, "the balance state is %d by CN.\n", msgBalanceCheckAck.switchoverDone);
    }
#endif

    (void)RespondMsg(recvMsgInfo, 'S', (char *)(&msgBalanceCheckAck), sizeof(msgBalanceCheckAck));
}

/**
 * @brief
 *
 * @param  con              My Param doc
 * @param  ctl_to_cm_set_ptrMy Param doc
 */
void ProcessCtlToCmSetMsg(MsgRecvInfo* recvMsgInfo, const ctl_to_cm_set* ctl_to_cm_set_ptr)
{
    cm_msg_type msgSetAck;

    if (ctl_to_cm_set_ptr->log_level > 0) {
        write_runlog(LOG, "log_min_messages changed from %d to %d\n", log_min_messages, ctl_to_cm_set_ptr->log_level);
        log_min_messages = ctl_to_cm_set_ptr->log_level;
    } else {
        write_runlog(ERROR, "invalid log level %d\n", ctl_to_cm_set_ptr->log_level);
    }

    if (ctl_to_cm_set_ptr->cm_arbitration_mode != UNKNOWN_ARBITRATION) {
        write_runlog(LOG, "cm_arbitration_mode has changed from %d to %d. MAJORITY = 1; MINORITY = 2.\n",
            cm_arbitration_mode, ctl_to_cm_set_ptr->cm_arbitration_mode);
        cm_arbitration_mode = ctl_to_cm_set_ptr->cm_arbitration_mode;
    }

    if (ctl_to_cm_set_ptr->cm_switchover_az_mode != UNKNOWN_SWITCHOVER_AZ) {
        write_runlog(LOG, "cm_switchover_az_mode has changed from %d to %d. NON_AUTO = 1; AUTO = 2.\n",
            cm_switchover_az_mode, ctl_to_cm_set_ptr->cm_switchover_az_mode);
        cm_switchover_az_mode = ctl_to_cm_set_ptr->cm_switchover_az_mode;
    }

    if (ctl_to_cm_set_ptr->cm_logic_cluster_restart_mode != UNKNOWN_LOGIC_CLUSTER_RESTART) {
        write_runlog(LOG, "cm_logic_cluster_restart_mode has changed from %d to %d, failover delay time to %u. "
            "INITIAL_LOGIC_CLUSTER_RESTART = 1; MODIFY_LOGIC_CLUSTER_RESTART = 2.\n",
            cm_logic_cluster_restart_mode, ctl_to_cm_set_ptr->cm_logic_cluster_restart_mode,
            ctl_to_cm_set_ptr->logic_cluster_delay);
        cm_logic_cluster_restart_mode = ctl_to_cm_set_ptr->cm_logic_cluster_restart_mode;
        instance_failover_delay_timeout = ctl_to_cm_set_ptr->logic_cluster_delay;
        g_instance_failover_delay_time_from_set = instance_failover_delay_timeout;
    }

    msgSetAck.msg_type = MSG_CM_CTL_SET_ACK;
    (void)RespondMsg(recvMsgInfo, 'S', (char *)(&msgSetAck), sizeof(msgSetAck));
}

static void HdlGtmBlanceAndAbnormal(const ctl_to_cm_query *ctlToCmQry, uint32 ii, bool *isSkip)
{
    bool gtmBlance = false;
    bool gtmAbnormal = false;
    for (uint32 i = 0; i < g_gtm_num; i++) {
        if ((ctlToCmQry->detail == CLUSTER_BALANCE_COUPLE_DETAIL_STATUS_QUERY ||
            ctlToCmQry->detail == CLUSTER_ABNORMAL_BALANCE_COUPLE_DETAIL_STATUS_QUERY) &&
            g_instance_role_group_ptr[ii].instanceMember[i].instanceRoleInit == INSTANCE_ROLE_PRIMARY &&
            g_instance_group_report_status_ptr[ii].instance_status.gtm_member[i]
            .local_status.local_role == INSTANCE_ROLE_PRIMARY) {
            gtmBlance = true;
        }
        if ((ctlToCmQry->detail == CLUSTER_ABNORMAL_COUPLE_DETAIL_STATUS_QUERY ||
            ctlToCmQry->detail == CLUSTER_ABNORMAL_BALANCE_COUPLE_DETAIL_STATUS_QUERY) &&
            g_instance_group_report_status_ptr[ii].instance_status.gtm_member[i].local_status.connect_status !=
            CON_OK) {
            gtmAbnormal = true;
        }
    }
    if ((ctlToCmQry->detail == CLUSTER_BALANCE_COUPLE_DETAIL_STATUS_QUERY && gtmBlance) ||
        (ctlToCmQry->detail == CLUSTER_ABNORMAL_COUPLE_DETAIL_STATUS_QUERY && !gtmAbnormal) ||
        (ctlToCmQry->detail == CLUSTER_ABNORMAL_BALANCE_COUPLE_DETAIL_STATUS_QUERY &&
        (gtmBlance && !gtmAbnormal))) {
        *isSkip = true;
    }
}

static void HdlDnBlanceAndAbnormal(const ctl_to_cm_query *ctlToCmQry, uint32 ii, bool *isSkip)
{
    bool dnBalance = false;
    bool dnAbnormal = false;
    if ((ctlToCmQry->detail == CLUSTER_BALANCE_COUPLE_DETAIL_STATUS_QUERY ||
        ctlToCmQry->detail == CLUSTER_ABNORMAL_BALANCE_COUPLE_DETAIL_STATUS_QUERY) &&
        g_instance_group_report_status_ptr[ii].instance_status.data_node_member[0].local_status.local_role ==
        INSTANCE_ROLE_PRIMARY) {
        dnBalance = true;
    }
    for (int i = 0; i < g_instance_role_group_ptr[ii].count; i++) {
        if ((ctlToCmQry->detail == CLUSTER_ABNORMAL_COUPLE_DETAIL_STATUS_QUERY ||
            ctlToCmQry->detail == CLUSTER_ABNORMAL_BALANCE_COUPLE_DETAIL_STATUS_QUERY) &&
            g_instance_group_report_status_ptr[ii].instance_status.data_node_member[i].local_status.db_state !=
            INSTANCE_HA_STATE_NORMAL) {
            dnAbnormal = true;
            break;
        }
    }
    if ((ctlToCmQry->detail == CLUSTER_BALANCE_COUPLE_DETAIL_STATUS_QUERY && dnBalance) ||
        (ctlToCmQry->detail == CLUSTER_ABNORMAL_COUPLE_DETAIL_STATUS_QUERY && !dnAbnormal) ||
        (ctlToCmQry->detail == CLUSTER_ABNORMAL_BALANCE_COUPLE_DETAIL_STATUS_QUERY && (dnBalance && !dnAbnormal))) {
        *isSkip = true;
    }
}

static void HdlInstBlanceAndAbnormal4MultiAz(const ctl_to_cm_query *ctlToCmQry, uint32 ii, bool *isSkip)
{
    if (g_instance_role_group_ptr[ii].instanceMember[0].instanceType == INSTANCE_TYPE_GTM) {
        HdlGtmBlanceAndAbnormal(ctlToCmQry, ii, isSkip);
    } else if (g_instance_role_group_ptr[ii].instanceMember[0].instanceType == INSTANCE_TYPE_DATANODE) {
        HdlDnBlanceAndAbnormal(ctlToCmQry, ii, isSkip);
    }
}

static void HdlCtl2CmQryMsg4SingleAz(const ctl_to_cm_query *ctlToCmQry, uint32 ii, bool *isSkip)
{
    int instType = g_instance_role_group_ptr[ii].instanceMember[0].instanceType;
    cm_local_replconninfo *dnMbr0Stat =
        &(g_instance_group_report_status_ptr[ii].instance_status.data_node_member[0].local_status);
    cm_local_replconninfo *dnMbr1Stat =
        &(g_instance_group_report_status_ptr[ii].instance_status.data_node_member[1].local_status);
    cm_local_replconninfo *dnMbr2Stat =
        &(g_instance_group_report_status_ptr[ii].instance_status.data_node_member[2].local_status);
    cm_gtm_replconninfo *gtmMbr0Stat =
        &(g_instance_group_report_status_ptr[ii].instance_status.gtm_member[0].local_status);
    cm_gtm_replconninfo *gtmMbr1Stat =
        &(g_instance_group_report_status_ptr[ii].instance_status.gtm_member[1].local_status);

    if (ctlToCmQry->detail == CLUSTER_BALANCE_COUPLE_DETAIL_STATUS_QUERY && instType == INSTANCE_TYPE_DATANODE &&
        dnMbr0Stat->local_role == INSTANCE_ROLE_PRIMARY && dnMbr1Stat->local_role != INSTANCE_ROLE_PRIMARY) {
        *isSkip = true;
        return;
    }
    if (ctlToCmQry->detail == CLUSTER_ABNORMAL_COUPLE_DETAIL_STATUS_QUERY && instType == INSTANCE_TYPE_DATANODE &&
        dnMbr0Stat->db_state == INSTANCE_HA_STATE_NORMAL && dnMbr1Stat->db_state == INSTANCE_HA_STATE_NORMAL &&
        dnMbr2Stat->db_state == INSTANCE_HA_STATE_NORMAL) {
        *isSkip = true;
        return;
    }
    if (ctlToCmQry->detail == CLUSTER_ABNORMAL_BALANCE_COUPLE_DETAIL_STATUS_QUERY &&
        instType == INSTANCE_TYPE_DATANODE && dnMbr0Stat->local_role == INSTANCE_ROLE_PRIMARY &&
        dnMbr1Stat->local_role != INSTANCE_ROLE_PRIMARY && dnMbr0Stat->db_state == INSTANCE_HA_STATE_NORMAL &&
        dnMbr1Stat->db_state == INSTANCE_HA_STATE_NORMAL && dnMbr2Stat->db_state == INSTANCE_HA_STATE_NORMAL) {
        *isSkip = true;
        return;
    }
    if (ctlToCmQry->detail == CLUSTER_BALANCE_COUPLE_DETAIL_STATUS_QUERY && instType == INSTANCE_TYPE_GTM &&
        gtmMbr0Stat->local_role == INSTANCE_ROLE_PRIMARY && gtmMbr1Stat->local_role != INSTANCE_ROLE_PRIMARY) {
        *isSkip = true;
        return;
    }
    if (ctlToCmQry->detail == CLUSTER_ABNORMAL_COUPLE_DETAIL_STATUS_QUERY && instType == INSTANCE_TYPE_GTM &&
        gtmMbr0Stat->connect_status == CON_OK && gtmMbr1Stat->connect_status == CON_OK) {
        *isSkip = true;
        return;
    }
    if (ctlToCmQry->detail == CLUSTER_ABNORMAL_BALANCE_COUPLE_DETAIL_STATUS_QUERY && instType == INSTANCE_TYPE_GTM &&
        gtmMbr0Stat->local_role == INSTANCE_ROLE_PRIMARY && gtmMbr1Stat->local_role != INSTANCE_ROLE_PRIMARY &&
        gtmMbr0Stat->connect_status == CON_OK && gtmMbr1Stat->connect_status == CON_OK) {
        *isSkip = true;
        return;
    }
}

static void FillCm2CtlRsp4GtmGroup(uint32 ii, uint32 jj, cm_to_ctl_instance_status *cmToCtlStatusContent)
{
    cmToCtlStatusContent->instance_type = INSTANCE_TYPE_GTM;
    errno_t rc = memcpy_s(&(cmToCtlStatusContent->gtm_member), sizeof(cm_gtm_replconninfo),
        &(g_instance_group_report_status_ptr[ii].instance_status.gtm_member[jj].local_status),
        sizeof(cm_gtm_replconninfo));
    securec_check_errno(rc, (void)rc);
}

static void FillCm2CtlRsp4CnGroup(uint32 ii, cm_to_ctl_instance_status *cmToCtlStatusContent)
{
    /* skip notify map in cm query */
    cmToCtlStatusContent->instance_type = INSTANCE_TYPE_COORDINATE;
    if (g_instance_role_group_ptr[ii].instanceMember[0].role == INSTANCE_ROLE_DELETED) {
        cmToCtlStatusContent->coordinatemember.status = INSTANCE_ROLE_DELETED;
    } else if (g_instance_role_group_ptr[ii].instanceMember[0].role == INSTANCE_ROLE_DELETING) {
        cmToCtlStatusContent->coordinatemember.status = INSTANCE_ROLE_UNKNOWN;
    } else {
        if (g_instance_group_report_status_ptr[ii].instance_status.coordinatemember.status.status ==
            INSTANCE_ROLE_NORMAL &&
            g_instance_group_report_status_ptr[ii].instance_status.coordinatemember.status.db_state ==
            INSTANCE_HA_STATE_STARTING) {
            cmToCtlStatusContent->coordinatemember.status = INSTANCE_ROLE_INIT;
        } else if (g_instance_group_report_status_ptr[ii].instance_status.coordinatemember.status.status ==
            INSTANCE_ROLE_NORMAL &&
            CheckReadOnlyStatus(ii, 0)) {
            cmToCtlStatusContent->coordinatemember.status = INSTANCE_ROLE_READONLY;
        } else {
            cmToCtlStatusContent->coordinatemember.status =
                g_instance_group_report_status_ptr[ii].instance_status.coordinatemember.status.status;
        }
    }
    cmToCtlStatusContent->data_node_member.local_status.db_state = INSTANCE_HA_STATE_NORMAL;
    if (backup_open == CLUSTER_STREAMING_STANDBY) {
        cmToCtlStatusContent->data_node_member.local_status.db_state =
            g_instance_group_report_status_ptr[ii].instance_status.coordinatemember.status.db_state;
        cmToCtlStatusContent->data_node_member.local_status.buildReason =
            g_instance_group_report_status_ptr[ii].instance_status.coordinatemember.buildReason;
    }
    cmToCtlStatusContent->coordinatemember.group_mode =
        g_instance_group_report_status_ptr[ii].instance_status.coordinatemember.group_mode;
    (void)pthread_mutex_lock(&g_centralNode.mt_lock);
    if (g_centralNode.instanceId != 0 && g_centralNode.instanceId == cmToCtlStatusContent->instanceId) {
        cmToCtlStatusContent->is_central = 1;
    }
    (void)pthread_mutex_unlock(&g_centralNode.mt_lock);
}

static void ChangeLocalRoleInBackup(cm_local_replconninfo* status)
{
    if (status->local_role == INSTANCE_ROLE_PRIMARY) {
        status->local_role = INSTANCE_ROLE_MAIN_STANDBY;
    } else if (status->local_role == INSTANCE_ROLE_STANDBY) {
        status->local_role = INSTANCE_ROLE_CASCADE_STANDBY;
    }
}

static void ChangeLocalRoleToOffline(cm_local_replconninfo *status, uint32 nodeId)
{
    for (uint32 i = 0; i < g_node_num; ++i) {
        if (g_node[i].node != nodeId) {
            continue;
        }
        if (strcmp(g_doradoIp, g_node[i].sshChannel[0]) == 0) {
            status->local_role = INSTANCE_ROLE_OFFLINE;
        }
        break;
    }

    return;
}

static void FillCm2CtlRsp4DnGroup(uint32 ii, uint32 jj, cm_to_ctl_instance_status *cmToCtlStatusContent)
{
    cmToCtlStatusContent->instance_type = INSTANCE_TYPE_DATANODE;
    errno_t rc = memcpy_s(&(cmToCtlStatusContent->data_node_member),
        sizeof(cm_to_ctl_instance_datanode_status),
        &(g_instance_group_report_status_ptr[ii].instance_status.data_node_member[jj]),
        sizeof(cm_to_ctl_instance_datanode_status));
    securec_check_errno(rc, (void)rc);
    if (cmToCtlStatusContent->data_node_member.local_status.db_state == INSTANCE_HA_STATE_NORMAL &&
        CheckReadOnlyStatus(ii, (int)jj)) {
        cmToCtlStatusContent->data_node_member.local_status.db_state = INSTANCE_HA_STATE_READ_ONLY;
    }
    if (GetIsSharedStorageMode()) {
        uint32 nodeId = g_instance_role_group_ptr[ii].instanceMember[jj].node;
        ChangeLocalRoleToOffline(&(cmToCtlStatusContent->data_node_member.local_status), nodeId);
    }
    if (backup_open == CLUSTER_STREAMING_STANDBY) {
        ChangeLocalRoleInBackup(&(cmToCtlStatusContent->data_node_member.local_status));
    }
}

static status_t FillCm2CtlRsp4InstGroup(MsgRecvInfo* recvMsgInfo, const ctl_to_cm_query *ctlToCmQry,
    uint32 ii, int type, uint32 group_index, cm_to_ctl_instance_status *cmToCtlStatusContent)
{
    cm_to_ctl_instance_status_ipv4 cmToCtlStatusContentIpv4 = {0};
    for (int jj = 0; jj < g_instance_role_group_ptr[ii].count; jj++) {
        if (g_instance_role_group_ptr[ii].instanceMember[jj].instanceType != type) {
            break;
        }
        cmToCtlStatusContent->msg_type = MSG_CM_CTL_DATA;
        cmToCtlStatusContent->node = g_instance_role_group_ptr[ii].instanceMember[jj].node;
        cmToCtlStatusContent->instanceId = g_instance_role_group_ptr[ii].instanceMember[jj].instanceId;
        cmToCtlStatusContent->instance_type = g_instance_role_group_ptr[ii].instanceMember[jj].instanceType;
        cmToCtlStatusContent->member_index = jj;
        cmToCtlStatusContent->is_central = 0;
        if (g_instance_role_group_ptr[ii].instanceMember[jj].instanceType == INSTANCE_TYPE_GTM) {
            FillCm2CtlRsp4GtmGroup(ii, (uint32)jj, cmToCtlStatusContent);
        } else if (g_instance_role_group_ptr[ii].instanceMember[jj].instanceType == INSTANCE_TYPE_COORDINATE) {
            FillCm2CtlRsp4CnGroup(ii, cmToCtlStatusContent);
        } else if (g_instance_role_group_ptr[ii].instanceMember[jj].instanceType == INSTANCE_TYPE_DATANODE) {
            if (ctlToCmQry->relation == 1 && group_index != ii) {
                continue;
            }
            FillCm2CtlRsp4DnGroup(ii, (uint32)jj, cmToCtlStatusContent);
        } else {
            write_runlog(ERROR, "can't find the instance(nodeId=%u, instanceId=%u) type(%d) is unknown\n",
                g_instance_role_group_ptr[ii].instanceMember[jj].node,
                g_instance_role_group_ptr[ii].instanceMember[jj].instanceId,
                g_instance_role_group_ptr[ii].instanceMember[jj].instanceType);
            return CM_ERROR;
        }
        write_runlog(DEBUG5, "send the instance query result (node =%u  instanceid =%u)\n",
            g_instance_role_group_ptr[ii].instanceMember[jj].node,
            g_instance_role_group_ptr[ii].instanceMember[jj].instanceId);
        if (undocumentedVersion != 0 && undocumentedVersion < SUPPORT_IPV6_VERSION) {
            CmToCtlInstanceStatusV2ToV1(cmToCtlStatusContent, &cmToCtlStatusContentIpv4);
            (void)RespondMsg(
                recvMsgInfo, 'S', (char *)&(cmToCtlStatusContentIpv4), sizeof(cm_to_ctl_instance_status_ipv4));
        } else {
            (void)RespondMsg(
                recvMsgInfo, 'S', (char *)cmToCtlStatusContent, sizeof(cm_to_ctl_instance_status));
        }
    }
    return CM_SUCCESS;
}

static void ProcessCtlToCmOneTypeQryMsg(MsgRecvInfo* recvMsgInfo, const ctl_to_cm_query *ctlToCmQry, int type)
{
    cm_to_ctl_instance_status cmToCtlStatusContent = {0};
    cm_to_ctl_instance_status_ipv4 cmToCtlStatusContentIpv4 = {0};
    uint32 ii;
    int jj;
    uint32 group_index = 0;
    int member_index = 0;
    bool isSkip;

    if (ctlToCmQry->relation == 1) {
        if (find_node_in_dynamic_configure(ctlToCmQry->node, ctlToCmQry->instanceId, &group_index, &member_index) !=
            0) {
            write_runlog(LOG, "can't find instance(nodeId=%u, instId=%u)\n", ctlToCmQry->node, ctlToCmQry->instanceId);
            return;
        }
    }

    for (ii = 0; ii < g_dynamic_header->relationCount; ii++) {
        for (jj = 0; jj < g_instance_role_group_ptr[ii].count; jj++) {
            if (g_instance_role_group_ptr[ii].instanceMember[jj].node == ctlToCmQry->node) {
                break;
            }
        }

        if ((ctlToCmQry->node != 0) && (ctlToCmQry->node != INVALID_NODE_NUM) &&
            (g_instance_role_group_ptr[ii].count == jj)) {
            continue;
        }

        if ((ctlToCmQry->detail == CLUSTER_BALANCE_COUPLE_DETAIL_STATUS_QUERY ||
            ctlToCmQry->detail == CLUSTER_ABNORMAL_BALANCE_COUPLE_DETAIL_STATUS_QUERY) &&
            g_instance_role_group_ptr[ii].instanceMember[0].instanceType == INSTANCE_TYPE_DATANODE &&
            g_instance_group_report_status_ptr[ii].instance_status.data_node_member[0].local_status.local_role ==
            INSTANCE_ROLE_NORMAL &&
            g_single_node_cluster) {
            continue;
        }

        isSkip = false;
        if (g_multi_az_cluster) {
            HdlInstBlanceAndAbnormal4MultiAz(ctlToCmQry, ii, &isSkip);
        } else {
            HdlCtl2CmQryMsg4SingleAz(ctlToCmQry, ii, &isSkip);
        }
        if (isSkip) {
            continue;
        }
        status_t ret = FillCm2CtlRsp4InstGroup(recvMsgInfo, ctlToCmQry, ii, type, group_index, &cmToCtlStatusContent);
        if (ret != CM_SUCCESS) {
            return;
        }
    }
    cmToCtlStatusContent.msg_type = MSG_CM_CTL_NODE_END;
    cmToCtlStatusContent.instance_type = type;

    if (undocumentedVersion != 0 && undocumentedVersion < SUPPORT_IPV6_VERSION) {
        CmToCtlInstanceStatusV2ToV1(&cmToCtlStatusContent, &cmToCtlStatusContentIpv4);
        (void)RespondMsg(
            recvMsgInfo, 'S', (char *)&(cmToCtlStatusContentIpv4), sizeof(cm_to_ctl_instance_status_ipv4), DEBUG5);
        return;
    }
    (void)RespondMsg(recvMsgInfo, 'S', (char *)&(cmToCtlStatusContent), sizeof(cm_to_ctl_instance_status), DEBUG5);
}

/* *
 * @brief
 *
 * @param  con              My Param doc
 * @param  node             My Param doc
 * @param  instanceId       My Param doc
 * @param  instanceType     My Param doc
 */
static void ProcessCtlToCmOneInstanceQueryMsg(
    MsgRecvInfo* recvMsgInfo, uint32 node, uint32 instanceId, int instanceType)
{
    uint32 groupIndex = 0;
    int memberIndex = 0;
    cm_to_ctl_instance_status statusMsg = {0};
    errno_t rc;

    if (find_node_in_dynamic_configure(node, instanceId, &groupIndex, &memberIndex) != 0) {
        write_runlog(LOG, "can't find the instance(node =%u  instanceid =%u)\n", node, instanceId);
        return;
    }

    statusMsg.msg_type = MSG_CM_CTL_DATA;
    statusMsg.node = node;
    statusMsg.instanceId = instanceId;
    statusMsg.instance_type = instanceType;
    statusMsg.is_central = 0;

    int instType = g_instance_role_group_ptr[groupIndex].instanceMember[memberIndex].instanceType;
    const cm_instance_report_status *instStatus = &g_instance_group_report_status_ptr[groupIndex].instance_status;

    if (instType == INSTANCE_TYPE_GTM) {
        statusMsg.instance_type = INSTANCE_TYPE_GTM;
        rc = memcpy_s(&(statusMsg.gtm_member), sizeof(cm_gtm_replconninfo),
            &(instStatus->gtm_member[memberIndex].local_status), sizeof(cm_gtm_replconninfo));
        securec_check_errno(rc, (void)rc);
        write_runlog(DEBUG5, "send the instance query result (gtm id = %d, gtm status = %d)\n",
            memberIndex, statusMsg.gtm_member.local_status.local_role);
    } else if (instType == INSTANCE_TYPE_COORDINATE) {
        /* skip notify map in cm query */
        statusMsg.instance_type = INSTANCE_TYPE_COORDINATE;
        if (g_instance_role_group_ptr[groupIndex].instanceMember[0].role == INSTANCE_ROLE_DELETED) {
            statusMsg.coordinatemember.status = INSTANCE_ROLE_DELETED;
        } else if (g_instance_role_group_ptr[groupIndex].instanceMember[0].role == INSTANCE_ROLE_DELETING) {
            statusMsg.coordinatemember.status = INSTANCE_ROLE_UNKNOWN;
        } else {
            if (instStatus->coordinatemember.status.status == INSTANCE_ROLE_NORMAL &&
                instStatus->coordinatemember.status.db_state == INSTANCE_HA_STATE_STARTING) {
                statusMsg.coordinatemember.status = INSTANCE_ROLE_INIT;
            } else if (instStatus->coordinatemember.status.status == INSTANCE_ROLE_NORMAL &&
                CheckReadOnlyStatus(groupIndex, 0)) {
                statusMsg.coordinatemember.status = INSTANCE_ROLE_READONLY;
            } else {
                statusMsg.coordinatemember.status = instStatus->coordinatemember.status.status;
            }
        }
        statusMsg.data_node_member.local_status.db_state = INSTANCE_HA_STATE_NORMAL;
        if (backup_open == CLUSTER_STREAMING_STANDBY) {
            statusMsg.data_node_member.local_status.db_state =
                g_instance_group_report_status_ptr[groupIndex].instance_status.coordinatemember.status.db_state;
            statusMsg.data_node_member.local_status.buildReason =
                g_instance_group_report_status_ptr[groupIndex].instance_status.coordinatemember.buildReason;
        }
        statusMsg.coordinatemember.group_mode = instStatus->coordinatemember.group_mode;

        (void)pthread_mutex_lock(&g_centralNode.mt_lock);
        if (g_centralNode.instanceId != 0 && g_centralNode.instanceId == statusMsg.instanceId) {
            statusMsg.is_central = 1;
        }
        (void)pthread_mutex_unlock(&g_centralNode.mt_lock);
    } else if (instType == INSTANCE_TYPE_DATANODE) {
        statusMsg.instance_type = INSTANCE_TYPE_DATANODE;
        rc = memcpy_s(&(statusMsg.data_node_member), sizeof(cm_to_ctl_instance_datanode_status),
            &(instStatus->data_node_member[memberIndex]), sizeof(cm_to_ctl_instance_datanode_status));
        securec_check_errno(rc, (void)rc);
        HashCascadeStandby(&(statusMsg.data_node_member), groupIndex, memberIndex);
        if (g_clusterType == V3SingleInstCluster) {
            statusMsg.data_node_member.sender_status[0].peer_role = INSTANCE_ROLE_STANDBY;
            for (uint32 i = 0; i < g_dynamic_header->relationCount; i++) {
                if (i == groupIndex) {
                    continue;
                }
                // need to be optimized
                if (g_instance_group_report_status_ptr[i].instance_status.data_node_member[memberIndex].local_status.
                    local_role == INSTANCE_ROLE_PRIMARY) {
                    statusMsg.data_node_member.sender_status[0].peer_role = INSTANCE_ROLE_PRIMARY;
                }
            }
        } else {
            if (statusMsg.data_node_member.local_status.db_state == INSTANCE_HA_STATE_NORMAL &&
                CheckReadOnlyStatus(groupIndex, memberIndex)) {
                statusMsg.data_node_member.local_status.db_state = INSTANCE_HA_STATE_READ_ONLY;
            }
            if (GetIsSharedStorageMode()) {
                ChangeLocalRoleToOffline(&(statusMsg.data_node_member.local_status), node);
            }
            if (backup_open == CLUSTER_STREAMING_STANDBY) {
                ChangeLocalRoleInBackup(&(statusMsg.data_node_member.local_status));
            }
        }
    } else {
        write_runlog(ERROR, "can't find instance=%u node=%u, type(%d) is unknown\n", instanceId, node, instType);
        return;
    }
    write_runlog(DEBUG5, "send the instance query result (node=%u, instanceId=%u)\n", node, instanceId);

    if (undocumentedVersion != 0 && undocumentedVersion < SUPPORT_IPV6_VERSION) {
        cm_to_ctl_instance_status_ipv4 statusIpv4 = {0};
        CmToCtlInstanceStatusV2ToV1(&statusMsg, &statusIpv4);
        (void)RespondMsg(recvMsgInfo, 'S', (char *)(&statusIpv4), sizeof(statusIpv4)); // XXXX:DEBUG5
    } else {
        (void)RespondMsg(recvMsgInfo, 'S', (char *)(&statusMsg), sizeof(statusMsg));  // XXXX:DEBUG5
    }
    return;
}

static void check_logic_cluster_status()
{
    uint32 i;
    uint32 j;
    int logicClusterId = -1;

    for (i = 0; i < LOGIC_CLUSTER_NUMBER; i++) {
        g_logicClusterStaticConfig[i].LogicClusterStatus = CM_STATUS_NORMAL;
        g_logicClusterStaticConfig[i].isRedistribution = false;
    }

    for (i = 0; i < g_dynamic_header->relationCount; i++) {
        if (g_instance_role_group_ptr[i].instanceMember[0].instanceType == INSTANCE_TYPE_DATANODE) {
            if (g_instance_role_group_ptr[i].count >= 3) {
                logicClusterId =
                    get_logicClusterId_by_dynamic_dataNodeId(g_instance_role_group_ptr[i].instanceMember[0].instanceId);
                if (logicClusterId < 0 || logicClusterId >= LOGIC_CLUSTER_NUMBER) {
                    continue;
                }

                if ((g_instance_group_report_status_ptr[i].instance_status.data_node_member[0]
                    .local_status.local_role == INSTANCE_ROLE_PRIMARY) &&
                    (g_instance_group_report_status_ptr[i].instance_status.data_node_member[1]
                    .local_status.local_role == INSTANCE_ROLE_STANDBY) &&
                    (g_instance_group_report_status_ptr[i].instance_status.data_node_member[1]
                    .local_status.db_state == INSTANCE_HA_STATE_NORMAL ||
                    g_instance_group_report_status_ptr[i].instance_status.data_node_member[1]
                    .local_status.db_state == INSTANCE_HA_STATE_CATCH_UP) &&
                    (g_instance_group_report_status_ptr[i].instance_status.data_node_member[2]
                    .local_status.local_role == INSTANCE_ROLE_DUMMY_STANDBY)) {
                } else if ((g_instance_group_report_status_ptr[i].instance_status.data_node_member[1]
                            .local_status.local_role == INSTANCE_ROLE_PRIMARY) &&
                           (g_instance_group_report_status_ptr[i].instance_status.data_node_member[0]
                            .local_status.local_role == INSTANCE_ROLE_STANDBY) &&
                           (g_instance_group_report_status_ptr[i].instance_status.data_node_member[0]
                            .local_status.db_state == INSTANCE_HA_STATE_NORMAL ||
                            g_instance_group_report_status_ptr[i].instance_status.data_node_member[0]
                            .local_status.db_state == INSTANCE_HA_STATE_CATCH_UP) &&
                           (g_instance_group_report_status_ptr[i].instance_status.data_node_member[2]
                            .local_status.local_role == INSTANCE_ROLE_DUMMY_STANDBY)) {
                } else if ((g_instance_group_report_status_ptr[i].instance_status.data_node_member[0]
                            .local_status.local_role == INSTANCE_ROLE_PRIMARY) &&
                           (g_instance_group_report_status_ptr[i].instance_status.data_node_member[1]
                            .local_status.local_role == INSTANCE_ROLE_STANDBY) &&
                           (g_instance_group_report_status_ptr[i].instance_status.data_node_member[1]
                            .local_status.db_state == INSTANCE_HA_STATE_NORMAL) &&
                           (g_instance_group_report_status_ptr[i].instance_status.data_node_member[2]
                            .local_status.local_role == INSTANCE_ROLE_UNKNOWN)) {
                    g_logicClusterStaticConfig[logicClusterId].LogicClusterStatus = CM_STATUS_DEGRADE;
                } else if ((g_instance_group_report_status_ptr[i].instance_status.data_node_member[1]
                            .local_status.local_role == INSTANCE_ROLE_PRIMARY) &&
                           (g_instance_group_report_status_ptr[i].instance_status.data_node_member[0]
                            .local_status.local_role == INSTANCE_ROLE_STANDBY) &&
                           (g_instance_group_report_status_ptr[i].instance_status.data_node_member[0]
                                .local_status.db_state == INSTANCE_HA_STATE_NORMAL) &&
                           (g_instance_group_report_status_ptr[i].instance_status.data_node_member[2]
                            .local_status.local_role == INSTANCE_ROLE_UNKNOWN)) {
                    g_logicClusterStaticConfig[logicClusterId].LogicClusterStatus = CM_STATUS_DEGRADE;
                } else if ((g_instance_group_report_status_ptr[i].instance_status.data_node_member[0]
                            .local_status.local_role == INSTANCE_ROLE_PRIMARY) &&
                           (g_instance_group_report_status_ptr[i].instance_status.data_node_member[0]
                            .local_status.db_state == INSTANCE_HA_STATE_NORMAL) &&
                           (g_instance_group_report_status_ptr[i].instance_status.data_node_member[1]
                            .local_status.local_role != INSTANCE_ROLE_PRIMARY) &&
                           (g_instance_group_report_status_ptr[i].instance_status.data_node_member[2]
                            .local_status.local_role == INSTANCE_ROLE_DUMMY_STANDBY)) {
                    g_logicClusterStaticConfig[logicClusterId].LogicClusterStatus = CM_STATUS_DEGRADE;
                } else if ((g_instance_group_report_status_ptr[i].instance_status.data_node_member[1]
                            .local_status.local_role == INSTANCE_ROLE_PRIMARY) &&
                           (g_instance_group_report_status_ptr[i].instance_status.data_node_member[1]
                            .local_status.db_state == INSTANCE_HA_STATE_NORMAL) &&
                           (g_instance_group_report_status_ptr[i].instance_status.data_node_member[0]
                            .local_status.local_role != INSTANCE_ROLE_PRIMARY) &&
                           (g_instance_group_report_status_ptr[i].instance_status.data_node_member[2]
                            .local_status.local_role == INSTANCE_ROLE_DUMMY_STANDBY)) {
                    g_logicClusterStaticConfig[logicClusterId].LogicClusterStatus = CM_STATUS_DEGRADE;
                } else {
                    write_runlog(LOG,
                        "CheckClusterStatus: DN[%u][0]: local_role=%d, db_state=%d;  DN[%u][1]: local_role=%d, "
                        "db_state=%d;  DN[%u][2]: local_role=%d\n",
                        i, g_instance_group_report_status_ptr[i].instance_status.data_node_member[0]
                            .local_status.local_role,
                        g_instance_group_report_status_ptr[i].instance_status.data_node_member[0].local_status.db_state,
                        i, g_instance_group_report_status_ptr[i].instance_status.data_node_member[1]
                        .local_status.local_role,
                        g_instance_group_report_status_ptr[i].instance_status.data_node_member[1].local_status.db_state,
                        i, g_instance_group_report_status_ptr[i]
                        .instance_status.data_node_member[2].local_status.local_role);
                    g_logicClusterStaticConfig[logicClusterId].LogicClusterStatus = CM_STATUS_NEED_REPAIR;
                    return;
                }
            }
        } else if (g_instance_role_group_ptr[i].instanceMember[0].instanceType == INSTANCE_TYPE_COORDINATE) {
            for (j = 0; j < g_logic_cluster_count; j++) {
                if (strcmp(g_instance_group_report_status_ptr[i].instance_status.coordinatemember.logicClusterName,
                    g_logicClusterStaticConfig[j].LogicClusterName) == 0) {
                    g_logicClusterStaticConfig[j].isRedistribution = true;
                }
            }
            if (strcmp(g_instance_group_report_status_ptr[i].instance_status.coordinatemember.logicClusterName,
                ELASTICGROUP) == 0) {
                g_logicClusterStaticConfig[LOGIC_CLUSTER_NUMBER - 1].isRedistribution = true;
            }
        } else {
            /* do nothing */
        }
    }
}

static void getDnRelationState(uint32 instanceId)
{
    uint32 i;
    int j;
    bool find = false;
    g_HA_status->status = CM_STATUS_NORMAL;
    g_HA_status->is_all_group_mode_pending = false;
    for (i = 0; i < g_dynamic_header->relationCount; i++) {
        for (j = 0; j < g_instance_role_group_ptr[i].count; j++) {
            if (instanceId == g_instance_role_group_ptr[i].instanceMember[j].instanceId) {
                find = true;
                break;
            }
        }
        if (find) {
            break;
        }
    }

    if (!find) {
        write_runlog(LOG, "unexpected instanceId %u.\n", instanceId);
        return;
    }

    int normalPrimaryDatanodeCount = 0;
    int normalStandbyDatanodeCount = 0;
    int demotingPrimaryDatanodeCount = 0;

    for (j = 0; j < g_instance_role_group_ptr[i].count; j++) {
        if (g_instance_group_report_status_ptr[i].instance_status.data_node_member[j].local_status.local_role ==
            INSTANCE_ROLE_PRIMARY) {
            if (g_instance_group_report_status_ptr[i].instance_status.data_node_member[j].local_status.db_state ==
                INSTANCE_HA_STATE_NORMAL) {
                normalPrimaryDatanodeCount++;
            }
            if (g_instance_group_report_status_ptr[i].instance_status.data_node_member[j].local_status.db_state ==
                INSTANCE_HA_STATE_DEMOTING) {
                demotingPrimaryDatanodeCount++;
            }
        } else if (g_instance_group_report_status_ptr[i].instance_status.data_node_member[j].local_status.local_role ==
            INSTANCE_ROLE_STANDBY &&
            (g_instance_group_report_status_ptr[i].instance_status.data_node_member[j].local_status.db_state ==
            INSTANCE_HA_STATE_NORMAL ||
            g_instance_group_report_status_ptr[i].instance_status.data_node_member[j].local_status.db_state ==
            INSTANCE_HA_STATE_CATCH_UP)) {
            normalStandbyDatanodeCount++;
        }
    }

    if (normalPrimaryDatanodeCount == 1 &&
        normalStandbyDatanodeCount == g_instance_role_group_ptr[i].count - (1 + demotingPrimaryDatanodeCount)) {
        if (demotingPrimaryDatanodeCount == 0) {
            g_HA_status->status = CM_STATUS_NORMAL;
        } else {
            g_HA_status->status = CM_STATUS_DEGRADE;
        }
    } else if (normalPrimaryDatanodeCount == 1 && normalStandbyDatanodeCount < g_instance_role_group_ptr[i].count - 1 &&
        ((normalStandbyDatanodeCount >= 0 && g_instance_role_group_ptr[i].count == 2) ||
        (normalStandbyDatanodeCount > 0 && g_instance_role_group_ptr[i].count == 3) ||
        (normalStandbyDatanodeCount > 1 && g_instance_role_group_ptr[i].count == 4))) {
        g_HA_status->status = CM_STATUS_DEGRADE;
    } else {
        write_runlog(LOG,
            "check_datanode_status: DN[%u][0]: local_role=%d, db_state=%d; DN[%u][1]: local_role=%d, "
            "db_state=%d; DN[%u][2]: local_role=%d\n",
            i, g_instance_group_report_status_ptr[i].instance_status.data_node_member[0].local_status.local_role,
            g_instance_group_report_status_ptr[i].instance_status.data_node_member[0].local_status.db_state, i,
            g_instance_group_report_status_ptr[i].instance_status.data_node_member[1].local_status.local_role,
            g_instance_group_report_status_ptr[i].instance_status.data_node_member[1].local_status.db_state, i,
            g_instance_group_report_status_ptr[i].instance_status.data_node_member[2].local_status.local_role);

        g_HA_status->status = CM_STATUS_NEED_REPAIR;
        return;
    }
}
/* *
 * @brief
 *
 * @param  instanceId       My Param doc
 * @return int
 */
static int isDnRelationBalanced(uint32 instanceId)
{
    uint32 i;
    int j;
    bool find = false;
    for (i = 0; i < g_dynamic_header->relationCount; i++) {
        for (j = 0; j < g_instance_role_group_ptr[i].count; j++) {
            if (instanceId == g_instance_role_group_ptr[i].instanceMember[j].instanceId) {
                find = true;
                break;
            }
        }
        if (find) {
            break;
        }
    }

    if (!find) {
        write_runlog(LOG, "unexpected instanceId %u.\n", instanceId);
        return 1;
    }
    int switchoverCount = 0;
    for (j = 0; j < g_instance_role_group_ptr[i].count; j++) {
        const int dynamic_role =
            g_instance_group_report_status_ptr[i].instance_status.data_node_member[j].local_status.local_role;
        const int init_role = g_instance_role_group_ptr[i].instanceMember[j].instanceRoleInit;

        if ((dynamic_role == INSTANCE_ROLE_PRIMARY && init_role == INSTANCE_ROLE_STANDBY) ||
            (dynamic_role != INSTANCE_ROLE_PRIMARY && init_role == INSTANCE_ROLE_PRIMARY)) {
            switchoverCount++;
        }
    }

    return switchoverCount;
}

static void HdlCtlToCmOneInstanceQryMsg(MsgRecvInfo* recvMsgInfo, const ctl_to_cm_query *ctlToCmQry)
{
    uint32 groupIndex = 0;
    int memberIndex = 0;
    int ret;
    struct stat statBuf = {0};
    char instanceManualStartFile[MAX_PATH_LEN] = {0};

    errno_t rc = snprintf_s(instanceManualStartFile, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s_%u",
        g_cmInstanceManualStartPath, ctlToCmQry->instanceId);
    securec_check_intval(rc, (void)rc);

    ret = find_node_in_dynamic_configure(ctlToCmQry->node, ctlToCmQry->instanceId, &groupIndex, &memberIndex);
    if (ret != 0) {
        write_runlog(LOG, "can't find the instance=%u node=%u\n", ctlToCmQry->instanceId, ctlToCmQry->node);
        return;
    }
    const cm_instance_report_status *instStatus = &g_instance_group_report_status_ptr[groupIndex].instance_status;
    if (instStatus->command_member[memberIndex].pengding_command == MSG_CM_AGENT_SWITCHOVER &&
        (instStatus->data_node_member[memberIndex].local_status.db_state == INSTANCE_HA_STATE_WAITING ||
        instStatus->data_node_member[memberIndex].local_status.db_state == INSTANCE_HA_STATE_PROMOTING ||
        instStatus->data_node_member[memberIndex].local_status.local_role == INSTANCE_ROLE_PRIMARY)) {
        return;
    }

    if (instStatus->command_member[memberIndex].pengding_command == MSG_CM_AGENT_BUILD) {
        if ((stat(instanceManualStartFile, &statBuf) == 0)) {
            ++g_instance_manual_start_file_exist;
        }
        cm_msg_type sendMsg;
        if (g_instance_manual_start_file_exist < MAX_QUERY_DOWN_COUNTS) {
            sendMsg.msg_type = MSG_CM_BUILD_DOING;
            (void)RespondMsg(recvMsgInfo, 'S', (char *)(&sendMsg), sizeof(cm_msg_type));
        } else {
            g_instance_manual_start_file_exist = 0;
            (void)pthread_rwlock_wrlock(&g_instance_group_report_status_ptr[groupIndex].lk_lock);
            CleanCommand(groupIndex, memberIndex);
            (void)pthread_rwlock_unlock(&g_instance_group_report_status_ptr[groupIndex].lk_lock);
            sendMsg.msg_type = MSG_CM_BUILD_DOWN;
            (void)RespondMsg(recvMsgInfo, 'S', (char *)(&sendMsg), sizeof(cm_msg_type));
        }
        return;
    }

    if (g_instance_role_group_ptr[groupIndex].instanceMember[memberIndex].instanceType == INSTANCE_TYPE_DATANODE &&
        CheckNotifyCnStatus() == SWITCHOVER_EXECING) {
        return;
    }

    ProcessCtlToCmOneInstanceQueryMsg(recvMsgInfo, ctlToCmQry->node, ctlToCmQry->instanceId, ctlToCmQry->instance_type);
}

static void HdlCtlToCmStartStatQry(MsgRecvInfo* recvMsgInfo, const ctl_to_cm_query *ctlToCmQry,
    cm_to_ctl_instance_status *instStat, cm_to_ctl_cluster_status *clusterStat)
{
    set_cluster_status();
    /* Send cluster status information in begin message. */
    clusterStat->msg_type = MSG_CM_CTL_DATA_BEGIN;
    clusterStat->inReloading = g_inReload;
    if (clusterStat->inReloading) {
        clusterStat->cluster_status = CM_STATUS_UNKNOWN;
    } else if (backup_open != CLUSTER_PRIMARY) {
        clusterStat->cluster_status = g_HA_status->status;
    } else {
        clusterStat->cluster_status = (g_HA_status->status == CM_STATUS_NORMAL && CheckReadOnlyStatusAll()) ?
            CM_STATUS_DEGRADE : g_HA_status->status;
    }
    if (clusterStat->inReloading) {
        clusterStat->is_all_group_mode_pending = false;
    } else {
        clusterStat->is_all_group_mode_pending = g_HA_status->is_all_group_mode_pending;
    }
    (void)RespondMsg(recvMsgInfo, 'S', (char *)clusterStat, sizeof(cm_to_ctl_cluster_status));
    if (ctlToCmQry->relation == 0) {
        for (uint32 i = 0; i < g_node_num; i++) {
            if ((ctlToCmQry->node != 0) && (ctlToCmQry->node != INVALID_NODE_NUM) &&
                (ctlToCmQry->node != (i + 1))) {
                continue;
            }
            if (g_node[i].coordinate == 1) {
                ProcessCtlToCmOneInstanceQueryMsg(
                    recvMsgInfo, g_node[i].node, g_node[i].coordinateId, INSTANCE_TYPE_COORDINATE);
            }
        }
    }
    /* Send CN status information in end message. */
    instStat->msg_type = MSG_CM_CTL_DATA_END;
    if (undocumentedVersion != 0 && undocumentedVersion < SUPPORT_IPV6_VERSION) {
        cm_to_ctl_instance_status_ipv4 instStatIpv4 = {0};
        CmToCtlInstanceStatusV2ToV1(instStat, &instStatIpv4);
        (void)RespondMsg(recvMsgInfo, 'S', (char *)(&instStatIpv4), sizeof(cm_to_ctl_instance_status_ipv4));
    } else {
        (void)RespondMsg(recvMsgInfo, 'S', (char *)instStat, sizeof(cm_to_ctl_instance_status));
    }
}

static void HdlCtlToCmLogicCpleDetStatQry(MsgRecvInfo* recvMsgInfo, cm_to_ctl_instance_status *instStat,
    cm_to_ctl_cluster_status *clusterStat, bool *isQryDone)
{
    cm_to_ctl_logic_cluster_status logicClusterStat;
    g_elastic_exist_node = false;
    set_cluster_status();
    check_logic_cluster_status();
    logicClusterStat.msg_type = MSG_CM_CTL_DATA_BEGIN;
    logicClusterStat.inReloading = g_inReload;
    if (backup_open != CLUSTER_PRIMARY) {
        clusterStat->cluster_status = g_HA_status->status;
    } else {
        logicClusterStat.cluster_status =
            (g_HA_status->status == CM_STATUS_NORMAL && CheckReadOnlyStatusAll()) ?
            CM_STATUS_DEGRADE : g_HA_status->status;
    }
    logicClusterStat.is_all_group_mode_pending = g_HA_status->is_all_group_mode_pending;
    logicClusterStat.switchedCount = isNodeBalanced(NULL);

    for (uint32 ii = 0; ii < g_logic_cluster_count; ii++) {
        logicClusterStat.logic_cluster_status[ii] = (int)g_logicClusterStaticConfig[ii].LogicClusterStatus;
        /* "redistributing" is relation to the status of CN, so we con't consider now */
        logicClusterStat.logic_is_all_group_mode_pending[ii] = g_logicClusterStaticConfig[ii].isRedistribution;
        logicClusterStat.logic_switchedCount[ii] = (int)g_logicClusterStaticConfig[ii].isLogicClusterBalanced;
    }
    /* check if exist elastic group, if not set switchover -1 */
    if (g_elastic_exist_node) {
        logicClusterStat.logic_switchedCount[LOGIC_CLUSTER_NUMBER - 1] =
            (int)g_logicClusterStaticConfig[LOGIC_CLUSTER_NUMBER - 1].isLogicClusterBalanced;
        logicClusterStat.logic_cluster_status[LOGIC_CLUSTER_NUMBER - 1] =
            (int)g_logicClusterStaticConfig[LOGIC_CLUSTER_NUMBER - 1].LogicClusterStatus;
        logicClusterStat.logic_is_all_group_mode_pending[LOGIC_CLUSTER_NUMBER - 1] =
            g_logicClusterStaticConfig[LOGIC_CLUSTER_NUMBER - 1].isRedistribution;
    } else {
        logicClusterStat.logic_switchedCount[LOGIC_CLUSTER_NUMBER - 1] = -1;
    }
    (void)RespondMsg(recvMsgInfo, 'S', (char *)&(logicClusterStat), sizeof(cm_to_ctl_logic_cluster_status));
    if (logicClusterStat.inReloading) {
        instStat->msg_type = MSG_CM_CTL_DATA_END;
        (void)RespondMsg(recvMsgInfo, 'S', (char *)instStat, sizeof(cm_to_ctl_instance_status));
        *isQryDone = true;
        return;
    }
}

static void UpdateAzNodeIdxOfClusterStat(cm_to_ctl_cluster_status *clusterStat)
{
    int cur_az = AZ_ALL_INDEX;
    if (current_cluster_az_status >= AnyAz1 && current_cluster_az_status <= FirstAz1) {
        cur_az = AZ1_INDEX;
    } else if (current_cluster_az_status >= AnyAz2 && current_cluster_az_status <= FirstAz2) {
        cur_az = AZ2_INDEX;
    }
    /* if curSyncList has more than one az, cur_az is AZ_ALL
       if curSyncList has only az1, cur_az is AZ1
       if curSyncList has only az2, cur_az is AZ2
     */
    if (g_isEnableUpdateSyncList != CANNOT_START_SYNCLIST_THREADS && current_cluster_az_status == AnyFirstNo) {
        cur_az = GetCurAz();
    }
    int azNodeIndex = -1;
    if (cur_az == AZ1_INDEX) {
        for (uint32 i = 0; i < g_node_num; i++) {
            uint32 priority = g_node[i].azPriority;
            if (g_node[i].datanodeCount == 0) {
                continue;
            } else {
                if (priority >= g_az_master && priority < g_az_slave) {
                    azNodeIndex = (int)i;
                    break;
                }
            }
        }
    } else if (cur_az == AZ2_INDEX) {
        for (uint32 i = 0; i < g_node_num; i++) {
            uint32 priority = g_node[i].azPriority;
            if (g_node[i].datanodeCount == 0) {
                continue;
            } else {
                if (priority >= g_az_slave && priority < g_az_arbiter) {
                    azNodeIndex = (int)i;
                    break;
                }
            }
        }
    }

    clusterStat->node_id = azNodeIndex;
}

static void HdlCtlToCmNonBalOrLgcCpleDetStatQry(MsgRecvInfo* recvMsgInfo, const ctl_to_cm_query *ctlToCmQry,
    cm_to_ctl_instance_status *instStat, cm_to_ctl_cluster_status *clusterStat, bool *isQryDone)
{
    set_cluster_status();

    UpdateAzNodeIdxOfClusterStat(clusterStat);

    if (ctlToCmQry->relation == 1) {
        getDnRelationState(ctlToCmQry->instanceId);
        clusterStat->msg_type = MSG_CM_CTL_DATA_BEGIN;
        clusterStat->inReloading = g_inReload;
        if (backup_open != CLUSTER_PRIMARY) {
            clusterStat->cluster_status = g_HA_status->status;
        } else {
            clusterStat->cluster_status =
                (g_HA_status->status == CM_STATUS_NORMAL && CheckReadOnlyStatusAll()) ?
                CM_STATUS_DEGRADE : g_HA_status->status;
        }
        clusterStat->switchedCount = isDnRelationBalanced(ctlToCmQry->instanceId);
    } else {
        set_cluster_status();
        clusterStat->msg_type = MSG_CM_CTL_DATA_BEGIN;
        clusterStat->inReloading = g_inReload;
        if (backup_open != CLUSTER_PRIMARY) {
            clusterStat->cluster_status = g_HA_status->status;
        } else {
            clusterStat->cluster_status =
                (g_HA_status->status == CM_STATUS_NORMAL && CheckReadOnlyStatusAll()) ?
                CM_STATUS_DEGRADE : g_HA_status->status;
        }
        clusterStat->is_all_group_mode_pending = g_HA_status->is_all_group_mode_pending;
        clusterStat->switchedCount = isNodeBalanced(NULL);
    }
    (void)RespondMsg(recvMsgInfo, 'S', (char *)clusterStat, sizeof(cm_to_ctl_cluster_status));
    if (clusterStat->inReloading) {
        instStat->msg_type = MSG_CM_CTL_DATA_END;
        if (undocumentedVersion != 0 && undocumentedVersion < SUPPORT_IPV6_VERSION) {
            cm_to_ctl_instance_status_ipv4 instStatIpv4 = {0};
            CmToCtlInstanceStatusV2ToV1(instStat, &instStatIpv4);
            (void)RespondMsg(recvMsgInfo, 'S', (char *)(&instStatIpv4), sizeof(cm_to_ctl_instance_status_ipv4));
        } else {
            (void)RespondMsg(recvMsgInfo, 'S', (char *)instStat, sizeof(cm_to_ctl_instance_status));
        }
        *isQryDone = true;
        return;
    }
}

status_t HdlCtlToCmClusDetstatQryForRelation(MsgRecvInfo* recvMsgInfo, const ctl_to_cm_query *ctlToCmQry,
    cm_to_ctl_instance_status *instStat, cm_to_ctl_instance_status_ipv4 *instStatIpv4)
{
    uint32 group_index_in = 0;
    uint32 group_index = 0;
    int member_index = 0;
    int ret = find_node_in_dynamic_configure(
        ctlToCmQry->node,
        ctlToCmQry->instanceId,
        &group_index_in,
        &member_index);
    if (ret != 0) {
        write_runlog(LOG, "can't find the instance(nodeId=%u, instanceId=%u)\n", ctlToCmQry->node,
            ctlToCmQry->instanceId);
        return CM_ERROR;
    }
    for (uint32 i = 0; i < g_node_num; i++) {
        bool find = false;
        ret = find_node_in_dynamic_configure(ctlToCmQry->node,
            ctlToCmQry->instanceId,
            &group_index,
            &member_index);
        if (ret != 0) {
            write_runlog(LOG, "can't find the instance(nodeId=%u, instanceId=%u)\n", ctlToCmQry->node,
                ctlToCmQry->instanceId);
            return CM_ERROR;
        }
        uint32 node_id = g_node[i].node;
        for (uint32 j = 0; j < g_node[i].datanodeCount; j++) {
            uint32 datanode_id = g_node[i].datanode[j].datanodeId;
            ret = find_node_in_dynamic_configure(node_id, datanode_id, &group_index, &member_index);
            if (ret != 0) {
                write_runlog(LOG, "can't find the instance(nodeId=%u, instanceId=%u)\n", node_id, datanode_id);
                return CM_ERROR;
            }
            if (group_index == group_index_in) {
                ProcessCtlToCmOneInstanceQueryMsg(recvMsgInfo, node_id, datanode_id, INSTANCE_TYPE_DATANODE);
                find = true;
                break;
            }
        }
        if (!find) {
            continue;
        }
        instStat->msg_type = MSG_CM_CTL_DATA;
        instStat->node = node_id;
        instStat->instanceId = 0;
        instStat->instance_type = INSTANCE_TYPE_FENCED_UDF;
        instStat->member_index = 0;
        instStat->is_central = 0;
        instStat->fenced_UDF_status = g_fenced_UDF_report_status_ptr[i].status;
        if (undocumentedVersion != 0 && undocumentedVersion < SUPPORT_IPV6_VERSION) {
            CmToCtlInstanceStatusV2ToV1(instStat, instStatIpv4);
            (void)RespondMsg(recvMsgInfo, 'S', (char *)instStatIpv4, sizeof(cm_to_ctl_instance_status_ipv4));

            instStatIpv4->msg_type = MSG_CM_CTL_NODE_END;
            (void)RespondMsg(recvMsgInfo, 'S', (char *)instStatIpv4, sizeof(cm_to_ctl_instance_status_ipv4));
        } else {
            (void)RespondMsg(recvMsgInfo, 'S', (char *)instStat, sizeof(cm_to_ctl_instance_status));  // XXXX:DEBUG5

            instStat->msg_type = MSG_CM_CTL_NODE_END;
            (void)RespondMsg(recvMsgInfo, 'S', (char *)instStat, sizeof(cm_to_ctl_instance_status));  // XXXX:DEBUG5
        }
    }
    return CM_SUCCESS;
}

status_t HdlCtlToCmClusDetStatQry(MsgRecvInfo* recvMsgInfo, const ctl_to_cm_query *ctlToCmQry,
    cm_to_ctl_instance_status *instStat)
{
    cm_to_ctl_instance_status_ipv4 instStatIpv4 = {0};
    for (uint32 i = 0; i < g_node_num && ctlToCmQry->relation == 0; i++) {
        if ((ctlToCmQry->node != 0) && (ctlToCmQry->node != INVALID_NODE_NUM) && (ctlToCmQry->node != (i + 1))) {
            continue;
        }

        if (g_node[i].coordinate == 1) {
            ProcessCtlToCmOneInstanceQueryMsg(
                recvMsgInfo, g_node[i].node, g_node[i].coordinateId, INSTANCE_TYPE_COORDINATE);
        }

        if (g_node[i].gtm == 1) {
            ProcessCtlToCmOneInstanceQueryMsg(recvMsgInfo, g_node[i].node, g_node[i].gtmId, INSTANCE_TYPE_GTM);
        }

        for (uint32 j = 0; j < g_node[i].datanodeCount; j++) {
            ProcessCtlToCmOneInstanceQueryMsg(
                recvMsgInfo, g_node[i].node, g_node[i].datanode[j].datanodeId, INSTANCE_TYPE_DATANODE);
        }

        if (g_clusterType != V3SingleInstCluster) {
            instStat->msg_type = MSG_CM_CTL_DATA;
            instStat->node = g_node[i].node;
            instStat->instanceId = 0;
            instStat->instance_type = INSTANCE_TYPE_FENCED_UDF;
            instStat->member_index = 0;
            instStat->is_central = 0;
            instStat->fenced_UDF_status = g_fenced_UDF_report_status_ptr[i].status;

            if (undocumentedVersion != 0 && undocumentedVersion < SUPPORT_IPV6_VERSION) {
                CmToCtlInstanceStatusV2ToV1(instStat, &instStatIpv4);
                (void)RespondMsg(recvMsgInfo, 'S', (char *)(&instStatIpv4), sizeof(cm_to_ctl_instance_status_ipv4));
            } else {
                (void)RespondMsg(recvMsgInfo, 'S', (char *)instStat, sizeof(cm_to_ctl_instance_status));  // XXXX:DEBUG5
            }
        }

        if (undocumentedVersion != 0 && undocumentedVersion < SUPPORT_IPV6_VERSION) {
            instStatIpv4.msg_type = MSG_CM_CTL_NODE_END;
            (void)RespondMsg(recvMsgInfo, 'S', (char *)(&instStatIpv4), sizeof(cm_to_ctl_instance_status_ipv4));
        } else {
            instStat->msg_type = MSG_CM_CTL_NODE_END;
            (void)RespondMsg(recvMsgInfo, 'S', (char *)instStat, sizeof(cm_to_ctl_instance_status));  // XXXX:DEBUG5
        }
    }
    if (ctlToCmQry->relation == 1) {
        return HdlCtlToCmClusDetstatQryForRelation(recvMsgInfo, ctlToCmQry, instStat, &instStatIpv4);
    }
    return CM_SUCCESS;
}

static void HdlCtlToCmClusRestStatQry(MsgRecvInfo* recvMsgInfo, const ctl_to_cm_query *ctlToCmQry,
    cm_to_ctl_instance_status *instStat)
{
    ProcessCtlToCmOneTypeQryMsg(recvMsgInfo, ctlToCmQry, INSTANCE_TYPE_COORDINATE);
    ProcessCtlToCmOneTypeQryMsg(recvMsgInfo, ctlToCmQry, INSTANCE_TYPE_GTM);
    ProcessCtlToCmOneTypeQryMsg(recvMsgInfo, ctlToCmQry, INSTANCE_TYPE_DATANODE);
    for (uint32 i = 0; i < g_node_num; i++) {
        instStat->msg_type = MSG_CM_CTL_DATA;
        instStat->node = g_node[i].node;
        instStat->instanceId = 0;
        instStat->instance_type = INSTANCE_TYPE_FENCED_UDF;
        instStat->member_index = 0;
        instStat->is_central = 0;
        instStat->fenced_UDF_status = g_fenced_UDF_report_status_ptr[i].status;
        if (undocumentedVersion != 0 && undocumentedVersion < SUPPORT_IPV6_VERSION) {
            cm_to_ctl_instance_status_ipv4 instStatIpv4 = {0};
            CmToCtlInstanceStatusV2ToV1(instStat, &instStatIpv4);
            (void)RespondMsg(recvMsgInfo, 'S', (char *)(&instStatIpv4), sizeof(cm_to_ctl_instance_status_ipv4));
        } else {
            (void)RespondMsg(recvMsgInfo, 'S', (char *)instStat, sizeof(cm_to_ctl_instance_status));
        }
    }
}

/**
 * @brief
 *
 * @param  con              My Param doc
 * @param  ctlToCmQry       My Param doc
 */
void ProcessCtlToCmQueryMsg(MsgRecvInfo* recvMsgInfo, const ctl_to_cm_query *ctlToCmQry)
{
    cm_to_ctl_instance_status instStat = {0};
    cm_to_ctl_cluster_status clusterStat;
    bool isQryDone = false;

    ctl_to_cm_query ctlToCmQryTmp;
    errno_t rc = memcpy_s(&ctlToCmQryTmp, sizeof(ctl_to_cm_query), ctlToCmQry, sizeof(ctl_to_cm_query));
    securec_check_errno(rc, (void)rc);
    /* If this query is from switchover process, we will do process alone. */
    if (ctlToCmQryTmp.detail == CLUSTER_QUERY_IN_SWITCHOVER && g_isInRedoStateUnderSwitchover) {
        write_runlog(LOG, "getg_isInRedoStateUnderSwitchover true \n");
        instStat.msg_type = MSG_CM_CTL_DATA;
        instStat.node = 0;
        instStat.instanceId = 0;
        instStat.instance_type = INSTANCE_TYPE_PENDING;
        instStat.member_index = 0;
        instStat.is_central = 0;
        instStat.fenced_UDF_status = INSTANCE_TYPE_PENDING;
        if (undocumentedVersion != 0 && undocumentedVersion < SUPPORT_IPV6_VERSION) {
            cm_to_ctl_instance_status_ipv4 instStatIpv4 = {0};
            CmToCtlInstanceStatusV2ToV1(&instStat, &instStatIpv4);
            (void)RespondMsg(recvMsgInfo, 'S', (char *)(&instStatIpv4), sizeof(cm_to_ctl_instance_status_ipv4));
        } else {
            (void)RespondMsg(recvMsgInfo, 'S', (char *)&(instStat), sizeof(cm_to_ctl_instance_status));
        }
        instStat.msg_type = MSG_CM_CTL_DATA_END;
        if (undocumentedVersion != 0 && undocumentedVersion < SUPPORT_IPV6_VERSION) {
            cm_to_ctl_instance_status_ipv4 instStatIpv4 = {0};
            CmToCtlInstanceStatusV2ToV1(&instStat, &instStatIpv4);
            (void)RespondMsg(recvMsgInfo, 'S', (char *)(&instStatIpv4), sizeof(cm_to_ctl_instance_status_ipv4));
        } else {
            (void)RespondMsg(recvMsgInfo, 'S', (char *)&(instStat), sizeof(cm_to_ctl_instance_status));
        }
        return;
    }

    if ((ctlToCmQryTmp.node != 0) && (ctlToCmQryTmp.node != INVALID_NODE_NUM) &&
        (ctlToCmQryTmp.instanceId != INVALID_INSTACNE_NUM) && ctlToCmQryTmp.relation == 0) {
        HdlCtlToCmOneInstanceQryMsg(recvMsgInfo, &ctlToCmQryTmp);
        return;
    }

    if (ctlToCmQryTmp.detail == CLUSTER_START_STATUS_QUERY) {
        HdlCtlToCmStartStatQry(recvMsgInfo, &ctlToCmQryTmp, &instStat, &clusterStat);
        return;
    }

    if (ctlToCmQryTmp.detail == CLUSTER_LOGIC_COUPLE_DETAIL_STATUS_QUERY) {
        HdlCtlToCmLogicCpleDetStatQry(recvMsgInfo, &instStat, &clusterStat, &isQryDone);
        if (isQryDone) {
            return;
        }
    } else if (ctlToCmQryTmp.detail != CLUSTER_BALANCE_COUPLE_DETAIL_STATUS_QUERY) {
        HdlCtlToCmNonBalOrLgcCpleDetStatQry(recvMsgInfo, &ctlToCmQryTmp, &instStat, &clusterStat, &isQryDone);
        if (isQryDone) {
            return;
        }
    }

    if (ctlToCmQryTmp.detail == CLUSTER_STATUS_QUERY ||
        ctlToCmQryTmp.detail == CLUSTER_COUPLE_STATUS_QUERY ||
        ctlToCmQryTmp.detail == CLUSTER_PARALLEL_REDO_REPLAY_STATUS_QUERY) {
        return;
    }

    if (ctlToCmQryTmp.detail == CLUSTER_DETAIL_STATUS_QUERY) {
        status_t ret = HdlCtlToCmClusDetStatQry(recvMsgInfo, &ctlToCmQryTmp, &instStat);
        if (ret != CM_SUCCESS) {
            return;
        }
    } else {
        HdlCtlToCmClusRestStatQry(recvMsgInfo, &ctlToCmQryTmp, &instStat);
    }

    instStat.msg_type = MSG_CM_CTL_DATA_END;
    if (undocumentedVersion != 0 && undocumentedVersion < SUPPORT_IPV6_VERSION) {
        cm_to_ctl_instance_status_ipv4 instStatIpv4 = {0};
        CmToCtlInstanceStatusV2ToV1(&instStat, &instStatIpv4);
        (void)RespondMsg(recvMsgInfo, 'S', (char *)(&instStatIpv4), sizeof(cm_to_ctl_instance_status_ipv4));
    } else {
        (void)RespondMsg(recvMsgInfo, 'S', (char *)&(instStat), sizeof(cm_to_ctl_instance_status));
    }
    return;
}

/**
 * @brief
 *
 * @param  con              My Param doc
 */
void process_ctl_to_cm_setmode(MsgRecvInfo* recvMsgInfo)
{
    int instanceType = 0;

    for (uint32 i = 0; i < g_dynamic_header->relationCount; i++) {
        (void)pthread_rwlock_wrlock(&(g_instance_group_report_status_ptr[i].lk_lock));
        for (int j = 0; j < g_instance_role_group_ptr[i].count; j++) {
            instanceType = g_instance_role_group_ptr[i].instanceMember[j].instanceType;
            switch (instanceType) {
                case INSTANCE_TYPE_DATANODE:
                case INSTANCE_TYPE_COORDINATE:
                    SetProcessingMode(PostUpgradeProcessing);
                    break;
                default:
                    break;
            }
        }
        (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[i].lk_lock));
    }

    cm_msg_type msgSetmodeAck;
    msgSetmodeAck.msg_type = MSG_CM_CTL_SETMODE_ACK;
    (void)RespondMsg(recvMsgInfo, 'S', (char *)(&msgSetmodeAck), sizeof(msgSetmodeAck));
}

/**
 * @brief Set the Switchover In Switchover Process object
 *
 * @param  ptrIndex         My Param doc
 * @param  memberIndex      My Param doc
 * @param  waitSecond       My Param doc
 */
static void SetSwitchoverInSwitchoverProcess(uint32 ptrIndex, int memIdx, int waitSecond)
{
    write_runlog(LOG, "auto switchover instanceid=%u, wait_seconds=%d.\n",
        GetInstanceIdInGroup(ptrIndex, memIdx), waitSecond);
    SetSwitchoverPendingCmd(ptrIndex, memIdx, waitSecond, "[SetSwitchoverInSwitchoverProcess]");
}

void ProcessCtlToCmSwitchoverAllMsg(MsgRecvInfo* recvMsgInfo, const ctl_to_cm_switchover *switchoverMsg)
{
    cm_to_ctl_command_ack msgSwitchoverAllAck = { 0 };

    msgSwitchoverAllAck.msg_type = MSG_CM_CTL_SWITCHOVER_ALL_ACK;
    if (!CanDoSwitchoverInAllShard(recvMsgInfo, &msgSwitchoverAllAck, switchoverMsg, "switchover_all_msg")) {
        return;
    }
    const char *str = "[ProcessCtlToCmSwitchoverAllMsg]";
    int noNeedDoGtmNum = 0;
    int noNeedDoDnNum = 0;
    int needDoGtmNum = 0;
    int needDoDnNum = 0;
    int imbalanceIndex = 0;
    cm_to_ctl_balance_result msgBalanceResult;
    msgBalanceResult.msg_type = MSG_CM_CTL_BALANCE_RESULT_ACK;
    int voteAZIndex = GetVoteAzIndex();
    bool isInVoteAz = false;
    for (uint32 i = 0; i < g_dynamic_header->relationCount; i++) {
        (void)pthread_rwlock_wrlock(&(g_instance_group_report_status_ptr[i].lk_lock));
        const cm_instance_report_status *instStatus = &g_instance_group_report_status_ptr[i].instance_status;
        for (int j = 0; j < g_instance_role_group_ptr[i].count; j++) {
            int instanceType = g_instance_role_group_ptr[i].instanceMember[j].instanceType;
            int initRole = g_instance_role_group_ptr[i].instanceMember[j].instanceRoleInit;
            uint32 instanceId = g_instance_role_group_ptr[i].instanceMember[j].instanceId;
            isInVoteAz = IsCurInstanceInVoteAz(i, j);
            switch (instanceType) {
                case INSTANCE_TYPE_GTM: {
                    int conStatus = instStatus->gtm_member[j].local_status.connect_status;
                    int gtmLocalRole = instStatus->gtm_member[j].local_status.local_role;
                    if (gtmLocalRole == INSTANCE_ROLE_STANDBY && initRole == INSTANCE_ROLE_PRIMARY &&
                        conStatus == CON_OK && !isInVoteAz) {
                        SetSwitchoverInSwitchoverProcess(i, j, switchoverMsg->wait_seconds);
                        needDoGtmNum++;
                    } else if (initRole == INSTANCE_ROLE_PRIMARY && conStatus != CON_OK) {
                        write_runlog(LOG,
                            "gtm instance=%u connection status=%d, will not switchover for status is unNormal.\n",
                            instanceId, conStatus);
                        msgBalanceResult.instances[imbalanceIndex++] = instanceId;
                        noNeedDoGtmNum++;
                    } else if (initRole == INSTANCE_ROLE_PRIMARY && gtmLocalRole == INSTANCE_ROLE_PRIMARY) {
                        write_runlog(LOG,
                            "gtm instance=%u status=%s, will not switchover for status is already primary.\n",
                            instanceId, datanode_dbstate_int_to_string(INSTANCE_ROLE_PRIMARY));
                        noNeedDoGtmNum++;
                    } else if (initRole == INSTANCE_ROLE_PRIMARY && isInVoteAz) {
                        write_runlog(LOG, "gtm instance=%u status=%s, will not switchover in vote AZ.\n", instanceId,
                            datanode_dbstate_int_to_string(INSTANCE_ROLE_PRIMARY));
                        noNeedDoGtmNum++;
                    }
                    break;
                }
                case INSTANCE_TYPE_DATANODE: {
                    int localStatus = instStatus->data_node_member[j].local_status.db_state;
                    int dnLocalRole = instStatus->data_node_member[j].local_status.local_role;
                    bool isCatchUp = IsInCatchUpState(i, j);
                    bool isCheckSyncList = (CheckInstInSyncList(i, j, str) == SYNCLIST_IS_FINISTH);
                    if ((dnLocalRole == INSTANCE_ROLE_STANDBY || dnLocalRole == INSTANCE_ROLE_CASCADE_STANDBY) &&
                        (initRole == INSTANCE_ROLE_PRIMARY || initRole == INSTANCE_ROLE_MAIN_STANDBY) &&
                        localStatus == INSTANCE_HA_STATE_NORMAL && !isInVoteAz &&
                        !isCatchUp && isCheckSyncList) {
                        SetSwitchoverInSwitchoverProcess(i, j, switchoverMsg->wait_seconds);
                        needDoDnNum++;
                    } else if ((initRole == INSTANCE_ROLE_PRIMARY || initRole == INSTANCE_ROLE_MAIN_STANDBY) &&
                        localStatus != INSTANCE_HA_STATE_NORMAL) {
                        write_runlog(LOG, "dn instance=%u status=%s, will not switchover for status is unNormal.\n",
                            instanceId, datanode_dbstate_int_to_string(localStatus));
                        msgBalanceResult.instances[imbalanceIndex++] = instanceId;
                        noNeedDoDnNum++;
                    } else if ((initRole == INSTANCE_ROLE_PRIMARY || initRole == INSTANCE_ROLE_MAIN_STANDBY) &&
                        (dnLocalRole == INSTANCE_ROLE_PRIMARY || dnLocalRole == INSTANCE_ROLE_MAIN_STANDBY)) {
                        write_runlog(LOG,
                            "dn instance=%u status=%s, will not switchover for status is already primary.\n",
                            instanceId, datanode_dbstate_int_to_string(localStatus));
                        noNeedDoDnNum++;
                    } else if ((initRole == INSTANCE_ROLE_PRIMARY || initRole == INSTANCE_ROLE_MAIN_STANDBY) &&
                        isInVoteAz && isCheckSyncList) {
                        write_runlog(LOG, "dn instance=%u status=%s, will not switchover in vote AZ.\n", instanceId,
                            datanode_dbstate_int_to_string(localStatus));
                        noNeedDoDnNum++;
                    } else if ((initRole == INSTANCE_ROLE_PRIMARY || initRole == INSTANCE_ROLE_MAIN_STANDBY) && isCatchUp) {
                        write_runlog(LOG,
                            "dn instance=%u status=%s, will not switchover for the xlog location gap"
                            "between the primary and standby is too large.\n",
                            instanceId, datanode_dbstate_int_to_string(localStatus));
                        if (dnLocalRole == INSTANCE_ROLE_STANDBY &&
                            (initRole == INSTANCE_ROLE_PRIMARY || initRole == INSTANCE_ROLE_MAIN_STANDBY)) {
                            msgBalanceResult.instances[imbalanceIndex++] = instanceId;
                        }
                        noNeedDoDnNum++;
                    } else if ((initRole == INSTANCE_ROLE_PRIMARY || initRole == INSTANCE_ROLE_MAIN_STANDBY) && isCheckSyncList) {
                        write_runlog(LOG,
                            "dn instance=%u status=%s, will not switchover for the inst not in synclist.\n", instanceId,
                            datanode_dbstate_int_to_string(localStatus));
                        if (dnLocalRole == INSTANCE_ROLE_STANDBY &&
                            (initRole == INSTANCE_ROLE_PRIMARY || initRole == INSTANCE_ROLE_MAIN_STANDBY)) {
                            msgBalanceResult.instances[imbalanceIndex++] = instanceId;
                        }
                        noNeedDoDnNum++;
                    }
                    break;
                }
                default:
                    break;
            }
        }
        (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[i].lk_lock));
    }

    bool incomplete = process_ctl_to_cm_switchover_incomplete_msg(
        recvMsgInfo, noNeedDoGtmNum, needDoGtmNum, noNeedDoDnNum, needDoDnNum);
    if (!incomplete && needDoDnNum == 0 && needDoGtmNum == 0 && voteAZIndex == AZ_ALL_INDEX) {
        write_runlog(LOG, "no need to do switchover, the broken gtm and dn num is: %d.\n", imbalanceIndex);
        msgBalanceResult.imbalanceCount = imbalanceIndex;
        (void)RespondMsg(recvMsgInfo, 'S', (char *)(&msgBalanceResult), sizeof(msgBalanceResult));
    } else {
        (void)RespondMsg(recvMsgInfo, 'S', (char *)(&msgSwitchoverAllAck), sizeof(msgSwitchoverAllAck));
    }
}

/* *
 * @brief
 *
 * @param  con              My Param doc
 * @param  ctl_to_cm_datanode_relation_info_ptrMy Param doc
 */
void process_ctl_to_cm_get_datanode_relation_msg(
    MsgRecvInfo* recvMsgInfo, const ctl_to_cm_datanode_relation_info *info_ptr)
{
    uint32 group_index = 0;
    int member_index = 0;
    int instanceType;
    int ret;
    cm_to_ctl_get_datanode_relation_ack ack = {0};

    ret = find_node_in_dynamic_configure(info_ptr->node,
        info_ptr->instanceId, &group_index, &member_index);
    if (ret != 0) {
        write_runlog(LOG, "can't find the instance(nodeId=%u, instanceId=%u)\n",
            info_ptr->node, info_ptr->instanceId);
        return;
    }

    instanceType = g_instance_role_group_ptr[group_index].instanceMember[member_index].instanceType;

    if (instanceType == INSTANCE_TYPE_DATANODE) {
        if (g_instance_group_report_status_ptr[group_index]
            .instance_status.data_node_member[member_index]
            .local_status.local_role == INSTANCE_ROLE_STANDBY) {
            ack.command_result = CM_CAN_PRCESS_COMMAND;
        } else {
            ack.command_result = CM_INVALID_COMMAND;
            write_runlog(LOG,
                "quick switchover the datanode instance(node =%u  instanceid =%u) is not standby \n",
                info_ptr->node,
                info_ptr->instanceId);
        }
    } else if (instanceType == INSTANCE_TYPE_GTM) {
        if (g_instance_group_report_status_ptr[group_index].instance_status.gtm_member[member_index]
                .local_status.local_role == INSTANCE_ROLE_STANDBY) {
            ack.command_result = CM_CAN_PRCESS_COMMAND;
        } else {
            ack.command_result = CM_INVALID_COMMAND;
            write_runlog(LOG,
                "quick switchover the datanode instance(node =%u  instanceid =%u) is not standby \n",
                info_ptr->node,
                info_ptr->instanceId);
        }
    } else {
        ack.command_result = CM_INVALID_COMMAND;
        write_runlog(LOG,
            "switchover can't find the instance(nodeId=%u, instanceId=%u) type is %d\n",
            info_ptr->node,
            info_ptr->instanceId,
            g_instance_role_group_ptr[group_index].instanceMember[member_index].instanceType);
    }

    ack.member_index = member_index;

    for (int i = 0; i < CM_PRIMARY_STANDBY_MAX_NUM; i++) {
        ack.instanceMember[i] =
            g_instance_role_group_ptr[group_index].instanceMember[i];
        errno_t rc = memcpy_s(&(ack.data_node_member[i]), sizeof(CmDnReportStatusMsg),
            &(g_instance_group_report_status_ptr[group_index].instance_status.data_node_member[i]),
            sizeof(CmDnReportStatusMsg));
        securec_check_errno(rc, (void)rc);
        ack.gtm_member[i] =
            g_instance_group_report_status_ptr[group_index].instance_status.gtm_member[i];
    }

    if (undocumentedVersion != 0 && undocumentedVersion < SUPPORT_IPV6_VERSION) {
        cm_to_ctl_get_datanode_relation_ack_ipv4 ackIpv4;
        CmToCtlGetDatanodeRelationAckV2ToV1(&ack, &ackIpv4);
        (void)RespondMsg(recvMsgInfo, 'S', (char *)(&ackIpv4), sizeof(ackIpv4));
    } else {
        (void)RespondMsg(recvMsgInfo, 'S', (char *)(&ack), sizeof(ack));
    }

    return;
}
