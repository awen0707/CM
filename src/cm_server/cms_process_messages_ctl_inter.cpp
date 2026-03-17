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
 * cms_process_messages_ctl_inter.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_server/cms_process_messages_ctl_inter.cpp
 *
 * -------------------------------------------------------------------------
 */
#include "cms_global_params.h"
#include "cms_process_messages.h"
#include "cms_disk_check.h"
#include "cms_az.h"

void ProcessCtlToCmQueryCmserverMsg(MsgRecvInfo* recvMsgInfo)
{
    cm_to_ctl_cmserver_status cmToCtlCmserverStatusContent = {0};

    cmToCtlCmserverStatusContent.msg_type = (int32)MSG_CM_CTL_CMSERVER;
    cmToCtlCmserverStatusContent.local_role = g_HA_status->local_role;
    (void)RespondMsg(recvMsgInfo, 'S', (char*)&(cmToCtlCmserverStatusContent), sizeof(cmToCtlCmserverStatusContent));
    return;
}

void ProcessCtlToCmGetMsg(MsgRecvInfo* recvMsgInfo)
{
    cm_to_ctl_get msgGetAck;

    msgGetAck.cm_switchover_az_mode = cm_switchover_az_mode;
    msgGetAck.cm_arbitration_mode = cm_arbitration_mode;
    msgGetAck.log_level = log_min_messages;
    msgGetAck.msg_type = (int32)MSG_CM_CTL_GET_ACK;

    (void)RespondMsg(recvMsgInfo, 'S', (char*)(&msgGetAck), sizeof(msgGetAck));
}

void ProcessCtlToCmQueryKerberosStatusMsg(MsgRecvInfo* recvMsgInfo)
{
    g_kerberos_group_report_status.kerberos_status.msg_type = (int32)MSG_CTL_CM_QUERY_KERBEROS_ACK;

    if (g_kerberos_group_report_status.kerberos_status.port[0] != 0) {
        (void)RespondMsg(recvMsgInfo, 'S', (char*)&(g_kerberos_group_report_status.kerberos_status),
            sizeof(cm_to_ctl_kerberos_status_query));
        return;
    }
}

void ProcessCtlToCmBalanceResultMsg(MsgRecvInfo* recvMsgInfo)
{
    cm_to_ctl_balance_result msgBalanceResult;

    msgBalanceResult.msg_type = (int32)MSG_CM_CTL_BALANCE_RESULT_ACK;
    msgBalanceResult.imbalanceCount = isNodeBalanced(msgBalanceResult.instances);

    (void)RespondMsg(recvMsgInfo, 'S', (char*)(&msgBalanceResult), sizeof(msgBalanceResult));
}

int GetCurAz()
{
    if (!g_multi_az_cluster) {
        return AZ_ALL_INDEX;
    }
    bool isVoteAz = (GetVoteAzIndex() != AZ_ALL_INDEX);
    if (GetAzDeploymentType(isVoteAz) != TWO_AZ_DEPLOYMENT) {
        write_runlog(LOG, "this is simple AZ cluster.\n");
        return AZ_ALL_INDEX;
    }
    int azDnCount[AZ_MEMBER_MAX_COUNT] = {0};
    int ret = GetDnCountOfAZ(azDnCount, AZ_MEMBER_MAX_COUNT, true, false);
    if (ret == -1) {
        return AZ_ALL_INDEX;
    }
    int azCount = 0;
    int azIndex = 0;
    int simpleAZ = 1;
    write_runlog(DEBUG1, "azDnCount[AZ1]=%d, azDnCount[AZ2]=%d, azDnCount[AZ3]=%d.\n", azDnCount[AZ1_INDEX],
        azDnCount[AZ2_INDEX], azDnCount[AZ3_INDEX]);
    for (int i = 0; i < AZ_MEMBER_MAX_COUNT; ++i) {
        if (azDnCount[i] != 0) {
            ++azCount;
            azIndex = i;
        }
    }
    if (azCount != simpleAZ) {
        return AZ_ALL_INDEX;
    }
    return azIndex;
}

uint32 GetPrimaryDnIndex()
{
    int instIndex = 0;
    uint32 groupIndex = 0;

    for (uint32 i = 0; i < g_node_num; ++i) {
        (void)find_node_in_dynamic_configure(g_node[i].node, g_node[i].datanode[0].datanodeId, &groupIndex, &instIndex);
        if (g_instance_group_report_status_ptr[groupIndex].instance_status.data_node_member[instIndex].local_status.
            local_role == INSTANCE_ROLE_PRIMARY) {
            write_runlog(LOG, "primary DN node is %u.\n", g_node[i].node);
            return g_node[i].node;
        }
    }
    write_runlog(LOG, "can't find primary DN.\n");

    return 0;
}


void SetSwitchoverPendingCmd(uint32 groupIdx, int32 memIdx, int32 waitSecond, const char *str, bool isNeedDelay)
{
    /* do switchover */
    cm_instance_report_status *instReport = &(g_instance_group_report_status_ptr[groupIdx].instance_status);
    cm_instance_command_status *cmd = &(instReport->command_member[memIdx]);
    cmd->time_out = waitSecond;
    cmd->command_status = INSTANCE_COMMAND_WAIT_EXEC;
    cmd->pengding_command = (int32)MSG_CM_AGENT_SWITCHOVER;
    SetSendTimes(groupIdx, memIdx, waitSecond);
    cmd->peerInstId = GetPeerInstId(groupIdx, memIdx);
    int32 localRole = 0;
    int32 instType = g_instance_role_group_ptr[groupIdx].instanceMember[memIdx].instanceType;
    if (instType == INSTANCE_TYPE_GTM) {
        localRole = instReport->gtm_member[memIdx].local_status.local_role;
        cmd->cmdPur = INSTANCE_ROLE_PRIMARY;
        cmd->cmdSour = INSTANCE_ROLE_STANDBY;
    } else if (instType == INSTANCE_TYPE_DATANODE) {
        localRole = instReport->data_node_member[memIdx].local_status.local_role;
        if (localRole == INSTANCE_ROLE_CASCADE_STANDBY) {
            cmd->cmdPur = INSTANCE_ROLE_STANDBY;
            cmd->cmdSour = INSTANCE_ROLE_CASCADE_STANDBY;
            cmd->cmdRealPur = INSTANCE_ROLE_PRIMARY;
        } else {
            if (g_ssDoubleClusterMode == SS_DOUBLE_STANDBY) {
                cmd->cmdPur = INSTANCE_ROLE_MAIN_STANDBY;
            } else {
                cmd->cmdPur = INSTANCE_ROLE_PRIMARY;
            }
            cmd->cmdSour = INSTANCE_ROLE_STANDBY;
            cmd->cmdRealPur = INSTANCE_ROLE_INIT;
            if (isNeedDelay) {
                const int32 delayTime = 8;
                cmd->delaySwitchoverTime = delayTime;
            }
        }
    }
    write_runlog(LOG, "%s, instd(%u) localRole is (%d: %s), cmd[cmdPur(%d: %s), cmdSour(%d: %s), cmdPur(%d: %s), "
        "peerIdx: %u] timeout is %d, delayTime is %d.\n", str, GetInstanceIdInGroup(groupIdx, memIdx), localRole,
        datanode_role_int_to_string(localRole), cmd->cmdPur, datanode_role_int_to_string(cmd->cmdPur), cmd->cmdSour,
        datanode_role_int_to_string(cmd->cmdSour), cmd->cmdRealPur, datanode_role_int_to_string(cmd->cmdRealPur),
        cmd->peerInstId, waitSecond, cmd->delaySwitchoverTime);
    for (int jj = 0; jj < g_instance_role_group_ptr[groupIdx].count; jj++) {
        if (memIdx != jj) {
            CleanCommand(groupIdx, jj);
        }
    }
}

int CheckNotifyCnStatus()
{
    for (uint32 i = 0; i < g_dynamic_header->relationCount; i++) {
        if (g_instance_role_group_ptr[i].instanceMember[0].instanceType != INSTANCE_TYPE_COORDINATE) {
            continue;
        }
        cm_instance_report_status *rep = &(g_instance_group_report_status_ptr[i].instance_status);
        cm_instance_command_status *cmd = &(rep->command_member[0]);
        bool res = ((cmd->command_status == INSTANCE_COMMAND_WAIT_EXEC ||
            cmd->command_status == INSTANCE_COMMAND_SEND_STATUS_FAIL) &&
            cmd->pengding_command == (int32)MSG_CM_AGENT_NOTIFY_CN &&
            rep->coordinatemember.status.status == INSTANCE_ROLE_NORMAL);
        if (res) {
            write_runlog(LOG, "waiting the DN(%u:%d) master-slave mapping info to flush into the system table.\n",
                g_instance_role_group_ptr[i].instanceMember[0].instanceId, cmd->command_status);
            return SWITCHOVER_EXECING;
        }
    }
    return SWITCHOVER_SUCCESS;
}

int32 GetSwitchoverDone(const char *str)
{
    int32 switchoverDone = switchoverFullDone();
    if (switchoverDone == SWITCHOVER_SUCCESS) {
        switchoverDone = CheckNotifyCnStatus();
    }
    // get the total number of segments of the DN and GTM
    uint32 total = g_cmAzInfo[0].gtmDuplicate + g_cmAzInfo[0].dnDuplicate;
    uint32 switchoverSize = (uint32)switchOverInstances.size();
    write_runlog(LOG, "%s: %d,  switchover size is %u, duplication is [%u: %u: %u], "
        "switchoverDone is %d.\n", str, __LINE__, switchoverSize,
        g_cmAzInfo[0].gtmDuplicate, g_cmAzInfo[0].dnDuplicate, total, switchoverDone);

    write_runlog(LOG, "%s: %d, switchover size is %u, duplication is [%u: %u: %u], "
        "switchoverDone is %d.\n", str, __LINE__, switchoverSize,
        g_cmAzInfo[0].gtmDuplicate, g_cmAzInfo[0].dnDuplicate, total, switchoverDone);
    return switchoverDone;
}
