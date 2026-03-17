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
 * cms_process_messages_clt.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_server/cms_process_messages_clt.cpp
 *
 * -------------------------------------------------------------------------
 */
#include "cms_ddb.h"
#include "hotpatch/hotpatch.h"
#include "cms_common.h"
#include "cm_msg.h"
#include "cms_process_messages.h"
#include "cms_arbitrate_datanode.h"
#include "cms_arbitrate_datanode_pms.h"
#include "cms_az.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include "cm_ip.h"
#include "cm_msg_version_convert.h"

const int KV_POS = 2;

#if ((defined(ENABLE_MULTIPLE_NODES)) || (defined(ENABLE_PRIVATEGAUSS)))
const int SYNC_FINISH_PERCENT = 99;
static int NeedDoGsGuc(uint32 groupIndex, int memberIndex);
static bool CompareMemberWithExpectSyncList(uint32 groupIdx, int memIdx);
static bool IsExpectSyncListInstanceNormal(uint32 groupIndex, uint32 instanceId, int *primaryCount);
#endif
static bool SwitchoverStatusCheck(uint32 group_index, int member_index);
void process_to_query_instance_status_msg(MsgRecvInfo* recvMsgInfo, const cm_query_instance_status *query_status_ptr);

int FinishRedoCheck(void)
{
    int finish_redo_group = 0;
    for (uint32 i = 0; i < g_dynamic_header->relationCount; i++) {
        (void)pthread_rwlock_rdlock(&(g_instance_group_report_status_ptr[i].lk_lock));
        if (g_instance_role_group_ptr[i].count > 0 &&
            g_instance_role_group_ptr[i].instanceMember[0].instanceType == INSTANCE_TYPE_DATANODE &&
            g_instance_group_report_status_ptr[i].instance_status.finish_redo) {
                finish_redo_group++;
        }
        (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[i].lk_lock));
    }
    return finish_redo_group;
}

static bool CmsDoCltDdbOper(CltSendDdbOper *ddbOper, char *value, uint32 valueLen, DDB_RESULT *ddbResult, status_t *st)
{
    switch (ddbOper->dbOper) {
        case DDB_GET_OPER:
            *st = GetKVFromDDb(ddbOper->key, ddbOper->keyLen, value, valueLen, ddbResult);
            break;
        case DDB_SET_OPER:
            *st = SetKV2Ddb(ddbOper->key, ddbOper->keyLen, ddbOper->value, ddbOper->valueLen, NULL);
            break;
        case DDB_DEL_OPER:
            *st = DelKeyInDdb(ddbOper->key, ddbOper->keyLen);
            break;
        default:
            write_runlog(ERROR, "unkown ddbOper(%d).\n", ddbOper->dbOper);
            return false;
    }
    return true;
}

static void GetSendCltDdbMsg(
    CmSendDdbOperRes *sendDdbRes, const CltSendDdbOper *ddbOper, const char *value, status_t st)
{
    sendDdbRes->msgType = (int32)MSG_CM_CLIENT_DDB_OPER_ACK;
    sendDdbRes->dbOper = ddbOper->dbOper;
    sendDdbRes->node = ddbOper->node;
    errno_t rc = strcpy_s(sendDdbRes->threadName, THREAD_NAME_LEN, ddbOper->threadName);
    securec_check_errno(rc, (void)rc);
    sendDdbRes->keyLen = ddbOper->keyLen;
    rc = strcpy_s(sendDdbRes->key, MAX_PATH_LEN, ddbOper->key);
    securec_check_errno(rc, (void)rc);
    if (ddbOper->dbOper == DDB_GET_OPER) {
        sendDdbRes->valueLen = (uint32)strlen(value);
        rc = strcpy_s(sendDdbRes->value, MAX_PATH_LEN, value);
        securec_check_errno(rc, (void)rc);
    } else {
        sendDdbRes->valueLen = ddbOper->valueLen;
        rc = strcpy_s(sendDdbRes->value, MAX_PATH_LEN, ddbOper->value);
        securec_check_errno(rc, (void)rc);
    }
    if (st != CM_SUCCESS) {
        sendDdbRes->exeStatus = false;
    } else {
        sendDdbRes->exeStatus = true;
    }
}

void ProcessCltSendOper(MsgRecvInfo* recvMsgInfo, CltSendDdbOper *ddbOper)
{
    if (ddbOper == NULL || ddbOper->dbOper == DDB_INIT_OPER) {
        write_runlog(ERROR, "ddbOper is NULL, or dbOper is DDB_INIT_OPER.\n");
        return;
    }
    ddbOper->key[MAX_PATH_LEN - 1] = '\0';
    ddbOper->value[MAX_PATH_LEN - 1] = '\0';
    ddbOper->reserved[RESERVE_LEN - 1] = '\0';
    ddbOper->threadName[THREAD_NAME_LEN - 1] = '\0';
    status_t st = CM_SUCCESS;
    DDB_RESULT ddbResult = SUCCESS_GET_VALUE;
    char value[MAX_PATH_LEN] = {0};
    bool res = CmsDoCltDdbOper(ddbOper, value, MAX_PATH_LEN, &ddbResult, &st);
    if (!res) {
        return;
    }

    CmSendDdbOperRes sendDdbRes = {0};
    GetSendCltDdbMsg(&sendDdbRes, ddbOper, value, st);
    write_runlog(LOG,
        "send ddbRes to client(%u), threadName is %s, oper is %d, key(%s), value(%s), exeStatus is %d.\n",
        ddbOper->node,
        ddbOper->threadName,
        ddbOper->dbOper,
        ddbOper->key,
        sendDdbRes.value,
        sendDdbRes.exeStatus);
        (void)RespondMsg(recvMsgInfo, 'S', (const char *)(&sendDdbRes), sizeof(CmSendDdbOperRes));
}
#if ((defined(ENABLE_MULTIPLE_NODES)) || (defined(ENABLE_PRIVATEGAUSS)))
void FindInstanceInSyncList(uint32 groupIdx, int memIdx, bool *hasFound)
{
    DatanodeSyncList *exceptSyncList = &(g_instance_group_report_status_ptr[groupIdx].instance_status.exceptSyncList);
    uint32 instanceId = g_instance_role_group_ptr[groupIdx].instanceMember[memIdx].instanceId;
    for (int i = 0; i < exceptSyncList->count; ++i) {
        if (exceptSyncList->dnSyncList[i] == instanceId) {
            *hasFound = true;
            break;
        }
    }
}

static bool CompareMemberWithExpectSyncList(uint32 groupIdx, int memIdx)
{
    DatanodeSyncList *expectSyncList = &(g_instance_group_report_status_ptr[groupIdx].instance_status.exceptSyncList);
    cm_instance_datanode_report_status *dnReport =
        &(g_instance_group_report_status_ptr[groupIdx].instance_status.data_node_member[memIdx]);
    DatanodeSyncList *memberSyncList = &(dnReport->dnSyncList);
    if (log_min_messages <= DEBUG1) {
        char expectSyncListStr[MAX_PATH_LEN] = {0};
        char memberSyncListStr[MAX_PATH_LEN] = {0};
        GetSyncListString(expectSyncList, expectSyncListStr, sizeof(expectSyncListStr));
        GetSyncListString(memberSyncList, memberSyncListStr, sizeof(memberSyncListStr));
        write_runlog(DEBUG1,
            "instanceId(%u), expectSyncList is [%s], memberSyncList is [%s], dbstate is %d, "
            "syncDone is %d.\n", g_instance_role_group_ptr[groupIdx].instanceMember[memIdx].instanceId,
            expectSyncListStr, memberSyncListStr, dnReport->local_status.db_state, dnReport->syncDone);
    }
    if (expectSyncList->count != memberSyncList->count) {
        return false;
    }
    for (int i = 0; i < expectSyncList->count; ++i) {
        if (expectSyncList->dnSyncList[i] != memberSyncList->dnSyncList[i]) {
            return false;
        }
    }
    return true;
}

static int NeedDoGsGuc(uint32 groupIndex, int memberIndex)
{
    if (g_isEnableUpdateSyncList == CANNOT_START_SYNCLIST_THREADS) {
        return SEND_AZ_SYNC_LIST;
    }
    if (g_isEnableUpdateSyncList == SYNCLIST_THREADS_IN_MAINTENANCE) {
        return CAN_NOT_SEND_SYNC_lIST;
    }
    bool hasFound = false;
    int primaryCount = 0;
    DatanodeSyncList exceptSyncList = g_instance_group_report_status_ptr[groupIndex].instance_status.exceptSyncList;
    cm_instance_datanode_report_status *dnReport =
        &(g_instance_group_report_status_ptr[groupIndex].instance_status.data_node_member[memberIndex]);
    FindInstanceInSyncList(groupIndex, memberIndex, &hasFound);
    if (!hasFound) {
        return NOT_NEED_TO_SEND_SYNC_LIST;
    }
    if (dnReport->local_status.local_role == INSTANCE_ROLE_PRIMARY && !CompareCurWithExceptSyncList(groupIndex)) {
        write_runlog(DEBUG1, "instd %u: dn primary cur is different from expect, need to send sync list.\n",
            GetInstanceIdInGroup(groupIndex, memberIndex));
        return NEED_TO_SEND_SYNC_LIST;
    }
    if (CompareMemberWithExpectSyncList(groupIndex, memberIndex)) {
        return NOT_NEED_TO_SEND_SYNC_LIST;
    }
    for (int i = 0; i < exceptSyncList.count; ++i) {
        if (!IsExpectSyncListInstanceNormal(groupIndex, exceptSyncList.dnSyncList[i], &primaryCount)) {
            return CAN_NOT_SEND_SYNC_lIST;
        }
    }
    if (primaryCount != 1) {
        return CAN_NOT_SEND_SYNC_lIST;
    }
    return NEED_TO_SEND_SYNC_LIST;
}

bool isDnGroupAvailable(uint32 groupId, int dnId)
{
    synchronous_standby_mode currentMode =
        g_instance_group_report_status_ptr[groupId].instance_status.data_node_member[dnId].sync_standby_mode;

    if (currentMode <= FirstAz2) {
        return true;
    }

    const int ONE_HUNDRED = 100;
    const int percent_of_auto_gsguc = 50;
    int availableNum = 0;

    for (int j = 0; j < g_instance_role_group_ptr[groupId].count; j++) {
        if (g_instance_group_report_status_ptr[groupId].instance_status.data_node_member[j].local_status.db_state ==
            INSTANCE_HA_STATE_NORMAL) {
            availableNum++;
        }
    }

    return (availableNum * ONE_HUNDRED / g_instance_role_group_ptr[groupId].count) > percent_of_auto_gsguc;
}

static bool IsExpectSyncListInstanceNormal(uint32 groupIndex, uint32 instanceId, int *primaryCount)
{
    for (int i = 0; i < g_instance_role_group_ptr[groupIndex].count; ++i) {
        if (instanceId != g_instance_role_group_ptr[groupIndex].instanceMember[i].instanceId) {
            continue;
        }
        if (g_instance_group_report_status_ptr[groupIndex].instance_status.data_node_member[i].local_status.db_state !=
            INSTANCE_HA_STATE_NORMAL ||
            g_instance_group_report_status_ptr[groupIndex].instance_status.data_node_member[i].local_status.term ==
            InvalidTerm) {
            return false;
        }
        if (g_instance_group_report_status_ptr[groupIndex]
            .instance_status.data_node_member[i].local_status.local_role == INSTANCE_ROLE_PRIMARY) {
            ++(*primaryCount);
        }
        break;
    }
    return true;
}
#endif

status_t GetSwitchOverMsg(uint32 i, int j, bool doSwitchoverFast, cm_to_agent_switchover *switchoverMsg)
{
    uint32 term = InvalidTerm;
    cm_instance_report_status *instStatus = &g_instance_group_report_status_ptr[i].instance_status;
    const cm_instance_role_status *instInfo = &g_instance_role_group_ptr[i].instanceMember[j];

    if (doSwitchoverFast) {
        switchoverMsg->msg_type = MSG_CM_AGENT_SWITCHOVER_FAST;
    } else {
        switchoverMsg->msg_type = MSG_CM_AGENT_SWITCHOVER;
    }
    switchoverMsg->node = instInfo->node;
    switchoverMsg->instanceId = instInfo->instanceId;
    switchoverMsg->instance_type = instInfo->instanceType;
    switchoverMsg->wait_seconds = instStatus->command_member[j].time_out;

    EnCheckSynclist echeck = CheckInstInSyncList(i, j, "[Send switchover]");
    if (echeck != SYNCLIST_IS_FINISTH && (g_clusterType != V3SingleInstCluster)) {
        write_runlog(LOG, "instId(%u) may be doing modify sync(%d), cannot do switchover.\n",
            GetInstanceIdInGroup(i, j), (int32)echeck);
        CleanCommand(i, j);
        return CM_ERROR;
    }

    cm_instance_command_status *cmd = &(instStatus->command_member[j]);
    if (cmd->cmdPur == INSTANCE_ROLE_STANDBY && cmd->cmdSour == INSTANCE_ROLE_CASCADE_STANDBY) {
        switchoverMsg->term = InvalidTerm;
        return CM_SUCCESS;
    }

    if ((g_clusterType != V3SingleInstCluster) && ((term = ReadTermFromDdb(i)) == InvalidTerm)) {
        write_runlog(ERROR, "Term on Ddb has not been set yet, which should not happen.\n");
        return CM_ERROR;
    }
    switchoverMsg->term = term;
    return CM_SUCCESS;
}

void ProcessSwitchOverMsg(MsgRecvInfo* recvMsgInfo, uint32 i, int j, const cm_to_agent_switchover *switchoverMsg)
{
    cm_instance_report_status *instStatus = &g_instance_group_report_status_ptr[i].instance_status;
    const cm_instance_role_status *instInfo = &g_instance_role_group_ptr[i].instanceMember[j];
    instStatus->command_member[j].command_send_status = INSTANCE_COMMAND_SEND_STATUS_SENDING;
    instStatus->command_member[j].command_send_times = 0;
    uint32 syncInstid = GetAvaiSyncDdbInstId();
    if (syncInstid != 0) {
        write_runlog(ERROR,
            "primary dn(%u) most_available_sync is on, can not do switchover.\n", syncInstid);
        return;
    }
    if (instStatus->command_member[j].delaySwitchoverTime > 0) {
        write_runlog(LOG, "instId(%u) delayTime is %d, cannot do switchover.\n", instInfo->instanceId,
            instStatus->command_member[j].delaySwitchoverTime);
        return;
    }
    if (instStatus->command_member[j].command_status == INSTANCE_COMMAND_WAIT_EXEC) {
        instStatus->command_member[j].command_send_num = 0;
    }
    instStatus->command_member[j].command_send_num++;
    write_runlog(LOG,
        "send switchover to instance(%u) for [%d/%d] times.\n",
        instInfo->instanceId,
        GetSendTimes(i, j, false),
        GetSendTimes(i, j, true));
    if (g_multi_az_cluster && (instStatus->command_member[j].command_send_num > 1)) {
        return;
    }
    if (!IsArchiveMaxSendTimes(i, j)) {
        return;
    }

    WriteKeyEventLog(KEY_EVENT_SWITCHOVER, g_instance_role_group_ptr[i].instanceMember[j].instanceId,
        "send switchover message, node=%u, instance=%u",
        g_instance_role_group_ptr[i].instanceMember[j].node,
        g_instance_role_group_ptr[i].instanceMember[j].instanceId);
    if (RespondMsg(recvMsgInfo, 'S', (const char *)(switchoverMsg), sizeof(cm_to_agent_switchover)) == 0) {
        instStatus->command_member[j].command_status = INSTANCE_COMMAND_WAIT_EXEC_ACK;
    } else {
        instStatus->command_member[j].command_send_status = INSTANCE_COMMAND_SEND_STATUS_FAIL;
    }
    return;
}

void ProcessBuildMsg(MsgRecvInfo* recvMsgInfo, uint32 i, int j)
{
    cm_instance_report_status *instStatus = &g_instance_group_report_status_ptr[i].instance_status;
    const cm_instance_role_status *instInfo = &g_instance_role_group_ptr[i].instanceMember[j];
    cm_to_agent_build buildMsg;
    buildMsg.msg_type = MSG_CM_AGENT_BUILD;
    buildMsg.full_build = instStatus->command_member[j].full_build;
    buildMsg.node = instInfo->node;
    buildMsg.instanceId = instInfo->instanceId;
    buildMsg.instance_type = instInfo->instanceType;
    buildMsg.wait_seconds = instStatus->command_member[j].time_out;
    buildMsg.term = instStatus->term;
    buildMsg.parallel = instStatus->command_member[j].parallel;
    buildMsg.role = instInfo->role;
    if (buildMsg.instance_type == INSTANCE_TYPE_DATANODE) {
        if (g_clusterType == V3SingleInstCluster) {
            buildMsg.primaryNodeId = GetPrimaryDnIndex();
        } else {
            uint32 primaryTerm = find_primary_term(i);
            if (primaryTerm > InvalidTerm || IsBoolCmParamTrue(g_enableDcf)) {
                buildMsg.term = primaryTerm;
            } else {
                write_runlog(ERROR,
                    "line %d: No legal primary for building instance %u.",
                    __LINE__,
                    instInfo->instanceId);
                return;
            }
        }
    }
    instStatus->command_member[j].command_send_status = INSTANCE_COMMAND_SEND_STATUS_SENDING;
    instStatus->command_member[j].command_send_times = 0;
    if (RespondMsg(recvMsgInfo, 'S', (char *)(&buildMsg), sizeof(buildMsg)) == 0) {
        instStatus->command_member[j].command_status = INSTANCE_COMMAND_WAIT_EXEC_ACK;
    } else {
        instStatus->command_member[j].command_send_status = INSTANCE_COMMAND_SEND_STATUS_FAIL;
    }
    return;
}

void SaveNotifyMsg(uint32 i, int j, cm_to_agent_notify_cn *p_cm_to_agent_notify_cn)
{
    int count = 0;
    cm_instance_report_status *instStatus = &g_instance_group_report_status_ptr[i].instance_status;
    cm_notify_msg_status *notify_msg = &instStatus->coordinatemember.notify_msg;
    for (uint32 k = 0; k < g_datanode_instance_count; k++) {
        if (notify_msg->notify_status != NULL && notify_msg->notify_status[k] &&
            notify_msg->datanode_instance != NULL) {
            p_cm_to_agent_notify_cn->datanodeId[count++] = notify_msg->datanode_instance[k];
        }
    }
    if (notify_msg->gtmIdBroadCast != 0) {
        p_cm_to_agent_notify_cn->datanodeId[count] = notify_msg->gtmIdBroadCast;
    }
    p_cm_to_agent_notify_cn->coordinatorId = 0;
    instStatus->command_member[j].command_send_status = INSTANCE_COMMAND_SEND_STATUS_SENDING;
    instStatus->command_member[j].command_send_times = 0;
    return;
}

int GetNotifyCnCount(cm_instance_report_status *instStatus, const cm_instance_role_status *instInfo)
{
    int count = 0;
    int gtmCount = 0;
    cm_notify_msg_status *notify_msg;
    /*
     * Scan the notify status array, allocate the datanode array memory due to the
     * actual scan result, put all the needed datanode instanceId into notify msg.
     */
    notify_msg = &instStatus->coordinatemember.notify_msg;
    for (uint32 k = 0; k < g_datanode_instance_count; k++) {
        if (notify_msg->notify_status != NULL && notify_msg->notify_status[k]) {
            Assert(notify_msg->datanode_instance[k] != 0);
            count++;
        }
    }
    if (notify_msg->gtmIdBroadCast != 0) {
        gtmCount++;
    }
    write_runlog(LOG,
        "coordinator %u notify map datanode count %d, gtm count %d, notifyCount %d\n",
        instInfo->instanceId,
        count,
        gtmCount,
        instStatus->command_member[0].notifyCnCount);
    count += gtmCount;
    return count;
}

status_t ProcessNotifyMsg(MsgRecvInfo* recvMsgInfo, uint32 i, int j, int count)
{
    cm_instance_report_status *instStatus = &g_instance_group_report_status_ptr[i].instance_status;
    const cm_instance_role_status *instInfo = &g_instance_role_group_ptr[i].instanceMember[j];

    /* notify message init */
    size_t msg_len = offsetof(cm_to_agent_notify_cn, datanodeId) + (uint32)(count) * sizeof(uint32);
    if (msg_len == 0) {
        return CM_ERROR;
    }
    cm_to_agent_notify_cn *p_cm_to_agent_notify_cn = (cm_to_agent_notify_cn *)malloc(msg_len);
    if (p_cm_to_agent_notify_cn == NULL) {
        write_runlog(ERROR, "out of memory! requested size: %lu.\n", msg_len);
        return CM_ERROR;
    }

    p_cm_to_agent_notify_cn->msg_type = MSG_CM_AGENT_NOTIFY_CN;
    p_cm_to_agent_notify_cn->node = instInfo->node;
    p_cm_to_agent_notify_cn->instanceId = instInfo->instanceId;
    p_cm_to_agent_notify_cn->datanodeCount = count; /* gtm : 1 */
    p_cm_to_agent_notify_cn->notifyCount = instStatus->command_member[0].notifyCnCount;

    /* store the instanceId list into message */
    SaveNotifyMsg(i, j, p_cm_to_agent_notify_cn);
    if (RespondMsg(recvMsgInfo, 'S', (char *)p_cm_to_agent_notify_cn, msg_len) == 0) {
        /* set the command status to wait ack, clean up the status until feedback */
        instStatus->command_member[j].command_status = INSTANCE_COMMAND_WAIT_EXEC_ACK;
    } else {
        instStatus->command_member[j].command_send_status = INSTANCE_COMMAND_SEND_STATUS_FAIL;
    }
    FREE_AND_RESET(p_cm_to_agent_notify_cn);
    return CM_SUCCESS;
}

#if ((defined(ENABLE_MULTIPLE_NODES)) || (defined(ENABLE_PRIVATEGAUSS)))
status_t CheckDnSendRecv(uint32 i, int j, int needDoGsGuc, const cm_instance_role_status *dnRole)
{
    const long printInterval = 60;
    cm_instance_datanode_report_status *dnReport =
        &(g_instance_group_report_status_ptr[i].instance_status.data_node_member[j]);
    int senderPercent = dnReport->sender_status[0].sync_percent;
    int receiverPercent = dnReport->receive_status.sync_percent;
    if ((senderPercent < SYNC_FINISH_PERCENT && receiverPercent < SYNC_FINISH_PERCENT &&
        dnReport->local_status.local_role != INSTANCE_ROLE_UNKNOWN) || needDoGsGuc == CAN_NOT_SEND_SYNC_lIST) {
        int32 logLevel = LOG;
        cmTime_t checkEnd;
        (void)clock_gettime(CLOCK_MONOTONIC, &checkEnd);
        bool res = ((needDoGsGuc == CAN_NOT_SEND_SYNC_lIST) || (dnRole->role == INSTANCE_ROLE_DUMMY_STANDBY) ||
                    (needDoGsGuc == NOT_NEED_TO_SEND_SYNC_LIST) ||
                    (checkEnd.tv_sec - dnReport->printBegin.tv_sec < printInterval));
        if (res) {
            logLevel = DEBUG1;
        } else {
            (void)clock_gettime(CLOCK_MONOTONIC, &(dnReport->printBegin));
        }
        write_runlog(logLevel,
            "instance %u, sender percent %d, receive percent %d, needDoGsGuc is %d, will do nothing.\n",
            dnRole->instanceId, senderPercent, receiverPercent, needDoGsGuc);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

void SendSyncListMsg(MsgRecvInfo* recvMsgInfo, uint32 nodeId, uint32 i, const cm_instance_role_status *dnRole,
    const DatanodeSyncList *exceptSyncList)
{
    CmToAgentGsGucSyncList cmToAgentSyncListContent = {0};
    cmToAgentSyncListContent.msgType = (int)MSG_CM_AGENT_DN_SYNC_LIST;
    cmToAgentSyncListContent.node = nodeId;
    cmToAgentSyncListContent.instanceId = dnRole->instanceId;
    cmToAgentSyncListContent.instanceNum = g_instance_role_group_ptr[i].count;
    cmToAgentSyncListContent.groupIndex = i;
    error_t rc = memcpy_s(
        &(cmToAgentSyncListContent.dnSyncList), sizeof(DatanodeSyncList), exceptSyncList, sizeof(DatanodeSyncList));
    securec_check_errno(rc, (void)rc);
    char dnSyncListStr[MAX_PATH_LEN] = {0};
    GetSyncListString(&(cmToAgentSyncListContent.dnSyncList), dnSyncListStr, sizeof(dnSyncListStr));
    WriteKeyEventLog(KEY_EVENT_RELOAD_GS_GUC, dnRole->instanceId,
        "send reload gs guc msg, instanceId is %u, msgtype is %d, SyncList is [%s]",
        dnRole->instanceId, cmToAgentSyncListContent.msgType, dnSyncListStr);
    (void)RespondMsg(recvMsgInfo, 'S', (char *)(&cmToAgentSyncListContent), sizeof(CmToAgentGsGucSyncList));
    return;
}

void PutGsGucContent(MsgRecvInfo* recvMsgInfo, synchronous_standby_mode standbyMode, uint32 nodeId,
    const cm_instance_role_status *dnRole)
{
    cm_to_agent_gs_guc cm_to_agent_gs_guc_content;
    cm_to_agent_gs_guc_content.msg_type = MSG_CM_AGENT_GS_GUC;
    cm_to_agent_gs_guc_content.type = standbyMode;
    cm_to_agent_gs_guc_content.node = nodeId;
    cm_to_agent_gs_guc_content.instanceId = dnRole->instanceId;
    WriteKeyEventLog(KEY_EVENT_RELOAD_GS_GUC, dnRole->instanceId,
        "send reload gs guc msg, instanceId is %u, type is %d", dnRole->instanceId,
        (int)cm_to_agent_gs_guc_content.type);
    (void)RespondMsg(recvMsgInfo,
        'S', (char *)(&cm_to_agent_gs_guc_content), sizeof(cm_to_agent_gs_guc_content));
    return;
}
#endif

void CmToAgentMsg(MsgRecvInfo* recvMsgInfo, int msgType)
{
    uint32 i;
    int j;
    status_t ret = CM_SUCCESS;
    bool doSwitchoverFast = false;

    if (recvMsgInfo->connID.remoteType != CM_AGENT) {
        return;
    }

    for (i = 0; i < g_dynamic_header->relationCount; i++) {
        cm_instance_report_status *instStatus = &g_instance_group_report_status_ptr[i].instance_status;
        for (j = 0; j < g_instance_role_group_ptr[i].count; j++) {
            const cm_instance_role_status *instInfo = &g_instance_role_group_ptr[i].instanceMember[j];
            if ((instInfo->node == recvMsgInfo->connID.agentNodeId) &&
                ((instStatus->command_member[j].command_status == INSTANCE_COMMAND_WAIT_EXEC) ||
                    !SwitchoverStatusCheck(i, j))) {
                (void)pthread_rwlock_wrlock(&(g_instance_group_report_status_ptr[i].lk_lock));
                switch (instStatus->command_member[j].pengding_command) {
                    case MSG_CM_AGENT_SWITCHOVER:
                        cm_to_agent_switchover switchoverMsg;
                        doSwitchoverFast = instStatus->command_member[j].msgProcFlag & MPF_DO_SWITCHOVER;
                        ret = GetSwitchOverMsg(i, j, doSwitchoverFast, &switchoverMsg);
                        if (ret != CM_SUCCESS) {
                            break;
                        }
                        ProcessSwitchOverMsg(recvMsgInfo, i, j, &switchoverMsg);
                        break;
                    case MSG_CM_AGENT_BUILD:
                        ProcessBuildMsg(recvMsgInfo, i, j);
                        break;
                    case MSG_CM_AGENT_NOTIFY_CN:
                        if (msgType == MSG_AGENT_CM_COORDINATE_INSTANCE_STATUS) {
                            int count = GetNotifyCnCount(instStatus, instInfo);
                            ret = ProcessNotifyMsg(recvMsgInfo, i, j, count);
                            if (ret != CM_SUCCESS) {
                                (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[i].lk_lock));
                                return;
                            }
                            break;
                        } else {
                            /* ignore other message type, only handle the pending command in coordinator report message
                             */
                            break;
                        }
                    default:
                        write_runlog(LOG, "unknown command is %d \n", instStatus->command_member[j].pengding_command);
                        (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[i].lk_lock));
                        return;
                }
                (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[i].lk_lock));
            }
        }
#if ((defined(ENABLE_MULTIPLE_NODES)) || (defined(ENABLE_PRIVATEGAUSS)))
        if (msgType == MSG_AGENT_CM_DATA_INSTANCE_REPORT_STATUS &&
            enable_az_auto_switchover != 0) {
            if (IsBoolCmParamTrue(g_enableDcf)) {
                write_runlog(DEBUG1, "working in dcf mode, return.\n");
                continue;
            }
            for (j = 0; j < g_instance_role_group_ptr[i].count; j++) {
                cm_instance_role_status *dnRole = &(g_instance_role_group_ptr[i].instanceMember[j]);
                uint32 nodeId = dnRole->node;
                if (nodeId != recvMsgInfo->connID.agentNodeId) {
                    continue;
                }
                if (g_instance_role_group_ptr[i].instanceMember[0].instanceType != INSTANCE_TYPE_DATANODE) {
                    break;
                }
                if (!IsDnSyncListVaild(i, NULL)) {
                    break;
                }
                synchronous_standby_mode standbyMode = instStatus->data_node_member[j].sync_standby_mode;
                int needDoGsGuc = NeedDoGsGuc(i, j);
                write_runlog(DEBUG1, "instanceId is %u, needDoGsGuc is %d.\n", dnRole->instanceId, needDoGsGuc);
                if ((standbyMode == AnyFirstNo && needDoGsGuc == SEND_AZ_SYNC_LIST) ||
                    (needDoGsGuc != NEED_TO_SEND_SYNC_LIST && needDoGsGuc != SEND_AZ_SYNC_LIST)) {
                    continue;
                }

                ret = CheckDnSendRecv(i, j, needDoGsGuc, dnRole);
                if (ret != CM_SUCCESS) {
                    break;
                }
                DatanodeSyncList exceptSyncList = instStatus->exceptSyncList;
                if (needDoGsGuc == NEED_TO_SEND_SYNC_LIST) {
                    if (instStatus->data_node_member[j].send_gs_guc_time < CM_GS_GUC_SEND_INTERVAL) {
                        continue;
                    }
                    if (instStatus->data_node_member[j].local_status.local_role == INSTANCE_ROLE_UNKNOWN) {
                        continue;
                    }
                    instStatus->data_node_member[j].send_gs_guc_time = 0;
                    SendSyncListMsg(recvMsgInfo, nodeId, i, dnRole, &exceptSyncList);
                    continue;
                }

                if (standbyMode != AnyFirstNo && (nodeId == recvMsgInfo->connID.agentNodeId)) {
                    bool dnGroupAvailable = isDnGroupAvailable(i, j);
                    if (!dnGroupAvailable) {
                        write_runlog(LOG,
                            "instance %u: dnAvailable: %d, will do nothing.\n",
                            dnRole->instanceId,
                            dnGroupAvailable);
                        break;
                    }
                    if (instStatus->data_node_member[j].send_gs_guc_time < CM_GS_GUC_SEND_INTERVAL) {
                        continue;
                    }
                    instStatus->data_node_member[j].send_gs_guc_time = 0;
                    PutGsGucContent(recvMsgInfo, standbyMode, nodeId, dnRole);
                }
            }
        }
#endif
    }
}

static bool SwitchoverStatusCheck(uint32 group_index, int member_index)
{
    if (g_instance_group_report_status_ptr[group_index]
        .instance_status.command_member[member_index].command_send_times < 0) {
        g_instance_group_report_status_ptr[group_index].instance_status.command_member[member_index]
        .command_send_times = 0;
    }
    if (g_instance_group_report_status_ptr[group_index].instance_status.command_member[member_index].pengding_command !=
        MSG_CM_AGENT_SWITCHOVER) {
        return true;
    }
    if (g_instance_group_report_status_ptr[group_index]
        .instance_status.command_member[member_index]
        .command_send_times >= SWITCHOVER_SEND_CHECK_RATE &&
        g_instance_group_report_status_ptr[group_index]
        .instance_status.data_node_member[member_index]
        .local_status.db_state != INSTANCE_HA_STATE_WAITING &&
        g_instance_group_report_status_ptr[group_index]
        .instance_status.data_node_member[member_index]
        .local_status.db_state != INSTANCE_HA_STATE_PROMOTING &&
        IsArchiveMaxSendTimes(group_index, member_index) &&
        g_instance_role_group_ptr[group_index].instanceMember[member_index].instanceType == INSTANCE_TYPE_DATANODE) {
        g_instance_group_report_status_ptr[group_index]
        .instance_status.command_member[member_index]
        .command_send_times = 0;
        return false;
    }
    return true;
}

uint32 find_nodeindex_by_nodeid(uint32 nodeId, int instanceType)
{
    uint32 index = 0;
    bool findIndex = false;
    for (uint32 i = 0; i < g_node_num; i++) {
        if (instanceType == PROCESS_ETCD) {
            if (g_node[i].etcd && g_node[i].node == nodeId) {
                findIndex = true;
                break;
            }
            if (g_node[i].etcd) {
                ++index;
            }
        } else if (instanceType == PROCESS_CMSERVER) {
            if (g_node[i].cmServerLevel == 1 && g_node[i].node == nodeId) {
                findIndex = true;
                break;
            }
            if (g_node[i].cmServerLevel == 1) {
                ++index;
            }
        } else {
            write_runlog(ERROR, "unexpected replicat number %u.\n", index);
            continue;
        }
    }
    if (index > CM_PRIMARY_STANDBY_NUM || !findIndex) {
        write_runlog(ERROR, "unexpected replicat number %u.\n", index);
    }
    return index;
}

void process_to_query_instance_status_msg(
    MsgRecvInfo* recvMsgInfo, const cm_query_instance_status *query_status_ptr)
{
    cm_query_instance_status cm_query_instance_status_content;
    if (query_status_ptr->msg_step == QUERY_STATUS_CMSERVER_STEP) {
        cm_query_instance_status_content.msg_type = MSG_CM_QUERY_INSTANCE_STATUS;
        cm_query_instance_status_content.nodeId = query_status_ptr->nodeId;
        cm_query_instance_status_content.instanceType = query_status_ptr->instanceType;
        cm_query_instance_status_content.msg_step = QUERY_STATUS_CMSERVER_STEP;
        if (cm_query_instance_status_content.instanceType == PROCESS_ETCD) {
            uint32 index = find_nodeindex_by_nodeid(cm_query_instance_status_content.nodeId, PROCESS_ETCD);
            cm_query_instance_status_content.status = g_instance_status_for_etcd[index];
        } else if (cm_query_instance_status_content.instanceType == PROCESS_CMSERVER) {
            uint32 index = find_nodeindex_by_nodeid(cm_query_instance_status_content.nodeId, PROCESS_CMSERVER);
            cm_query_instance_status_content.status = g_instance_status_for_cm_server[index];
            cm_query_instance_status_content.pending = g_instance_status_for_cm_server_pending[index];
        } else {
            write_runlog(ERROR, "unknown instance type %u for query instance status.\n",
                cm_query_instance_status_content.instanceType);
        }
        (void)RespondMsg(recvMsgInfo,
            'S',
            (char *)&(cm_query_instance_status_content),
            sizeof(cm_query_instance_status_content),
            DEBUG5);
    } else if (query_status_ptr->msg_step == QUERY_STATUS_CMAGENT_STEP) {
        (void)pthread_rwlock_wrlock(&instance_status_rwlock);
        if (query_status_ptr->instanceType == PROCESS_ETCD) {
            uint32 index = find_nodeindex_by_nodeid(query_status_ptr->nodeId, PROCESS_ETCD);
            if (query_status_ptr->status == CM_ETCD_LEADER) {
                for (uint32 i = 0; i < g_etcd_num; i++) {
                    if (i != index && g_instance_status_for_etcd[i] == CM_ETCD_LEADER) {
                        g_instance_status_for_etcd[i] = CM_ETCD_FOLLOWER;
                        g_instance_status_for_etcd[index] = CM_ETCD_LEADER;
                    }
                }
            }
            g_instance_status_for_etcd[index] = query_status_ptr->status;
            g_instance_status_for_etcd_timeout[index] = cmserver_and_etcd_instance_status_for_timeout;
        } else if (query_status_ptr->instanceType == PROCESS_CMSERVER) {
            uint32 index = find_nodeindex_by_nodeid(query_status_ptr->nodeId, PROCESS_CMSERVER);
            if (g_HA_status->local_role == CM_SERVER_PRIMARY && g_currentNode->node == query_status_ptr->nodeId) {
                g_instance_status_for_cm_server[index] = CM_SERVER_PRIMARY;
            } else {
                g_instance_status_for_cm_server[index] = query_status_ptr->status;
            }
            g_instance_status_for_cm_server_pending[index] = query_status_ptr->pending;
            g_instance_status_for_cm_server_timeout[index] = cmserver_and_etcd_instance_status_for_timeout;
        } else {
            write_runlog(
                ERROR, "unknown instance type %u for query instance status.\n", query_status_ptr->instanceType);
        }
        (void)pthread_rwlock_unlock(&instance_status_rwlock);
    }
}

void HotpatchInfoStateToString(unsigned int state, char *state_string, size_t length_state_string)
{
    int ret;

    const char *string_state[] = {
        "UNKNOWN",
        "UNLOAD",
        "DEACTIVE",
        "ACTIVE",
    };

    switch (state) {
        case HP_STATE_ACTIVED:
        case HP_STATE_DEACTIVE:
        case HP_STATE_UNLOAD:
            ret = snprintf_s(state_string, length_state_string, length_state_string - 1, "%s", string_state[state]);
            securec_check_intval(ret, (void)ret);
            break;

        default:
            ret = snprintf_s(state_string, length_state_string, length_state_string - 1, "%s", string_state[0]);
            securec_check_intval(ret, (void)ret);
            break;
    }

    return;
}

/* patch_info_all should free by caller */
int HotpatchGetPatchInfo(const char *file_path, int *patch_number, PATCH_INFO_T **patch_info_all)
{
    int max_patch_number;
    char real_path[PATH_MAX] = {0};
    PATCH_INFO_HEADER_T hp_header = {0};

    if (file_path == NULL) {
        return HP_ERROR_FILE_PATH_ERROR;
    }

    if (realpath(file_path, real_path) == NULL) {
        return HP_ERROR_FILE_PATH_ERROR;
    }

    FILE *fp = fopen(real_path, "r");
    if (fp == NULL) {
        return HP_ERROR_FILE_OPEN_ERROR;
    }

    size_t ret = fread(&hp_header, sizeof(PATCH_INFO_HEADER_T), 1, fp);
    if (ret != 1) {
        (void)fclose(fp);
        fp = NULL;
        return HP_ERROR_FILE_READ_ERROR;
    }

    max_patch_number = hp_header.max_patch_number;
    if ((max_patch_number <= 0) || (max_patch_number > g_max_number_patch)) {
        (void)fclose(fp);
        fp = NULL;
        return HP_ERROR_PATCH_NUMBER_ERROR;
    }

    *patch_info_all = (PATCH_INFO_T *)malloc((size_t)max_patch_number * sizeof(PATCH_INFO_T));
    if (*patch_info_all == NULL) {
        (void)fclose(fp);
        fp = NULL;
        return HP_ERROR_SYSTEM_ERROR;
    }

    ret = fread(*patch_info_all, sizeof(PATCH_INFO_T), (size_t)max_patch_number, fp);
    if ((int)ret != max_patch_number) {
        free(*patch_info_all);
        *patch_info_all = NULL;
        (void)fclose(fp);
        fp = NULL;
        return HP_ERROR_PATCH_INFO_ERROR;
    }
    *patch_number = max_patch_number;
    (void)fclose(fp);
    fp = NULL;

    return HP_OK;
}

#if defined (ENABLE_MULTIPLE_NODES) || defined (ENABLE_PRIVATEGAUSS)
void HotpatchReturnError(MsgRecvInfo* recvMsgInfo, int err_code)
{
    char return_string[MAX_LENGTH_RETURN_STRING] = {0};

    patch_err_info_handler(err_code, return_string, MAX_LENGTH_RETURN_STRING);
    (void)RespondMsg(recvMsgInfo, 'S', return_string, strlen(return_string), DEBUG5);
}

void SendHotPatchMsg(MsgRecvInfo* recvMsgInfo, int patch_number, const PATCH_INFO_T *patch_info_all)
{
    int ret;
    char *patch_name = NULL;
    char patch_state_string[g_length_statstr] = {0};
    int str_start = 0;
    int list_strlen;

    list_strlen = patch_number * g_max_length_line;
    char *return_string_list = (char *)malloc(list_strlen);
    if (return_string_list == NULL) {
        HotpatchReturnError(recvMsgInfo, (int32)HP_ERROR_SYSTEM_ERROR);
        return;
    }
    for (int i = 0; i < patch_number; i++) {
        HotpatchInfoStateToString(patch_info_all[i].patch_state, patch_state_string,
            sizeof(patch_state_string));
        patch_name = strip_path_from_pathname(patch_info_all[i].patch_name);
        if (patch_name == NULL) {
            ret = snprintf_s(return_string_list + str_start,
                list_strlen - str_start,
                (list_strlen - str_start) - 1,
                "PATCH: UNKNOW STATE: %s\n",
                patch_state_string);
        } else {
            ret = snprintf_s(return_string_list + str_start,
                list_strlen - str_start,
                (list_strlen - str_start) - 1,
                "PATCH: %s STATE: %s\n",
                patch_name,
                patch_state_string);
        }
        securec_check_intval(ret, (void)ret);
        str_start = str_start + ret;
    }
    ret = strcat_s(return_string_list, list_strlen, "[PATCH-SUCCESS] : LIST PATCH\n");
    securec_check_errno(ret, (void)ret);

    (void)RespondMsg(recvMsgInfo, 'S', return_string_list, strlen(return_string_list), DEBUG5);
    free(return_string_list);
    return;
}

void HotpatchReturnList(MsgRecvInfo* recvMsgInfo)
{
    int ret;
    int patch_number;
    char patch_dir[MAX_PATH_LEN] = {0};
    PATCH_INFO_T *patch_info_all = NULL;

    if (cm_server_dataDir == NULL) {
        HotpatchReturnError(recvMsgInfo, (int32)HP_ERROR_CM_DATADIR_NULL);
        return;
    }

    ret = snprintf_s(patch_dir, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/hotpatch/patch.info", cm_server_dataDir);
    securec_check_intval(ret, (void)ret);

    ret = HotpatchGetPatchInfo(patch_dir, &patch_number, &patch_info_all);
    if (ret != HP_OK) {
        HotpatchReturnError(recvMsgInfo, ret);
        return;
    }

    SendHotPatchMsg(recvMsgInfo, patch_number, patch_info_all);
    free(patch_info_all);
    patch_info_all = NULL;
    return;
}
#endif

void ProcessHotpatchMessage(MsgRecvInfo* recvMsgInfo, cm_hotpatch_msg *hotpatch_msg)
{
#if defined (ENABLE_MULTIPLE_NODES) || defined (ENABLE_PRIVATEGAUSS)
    int ret;
    bool is_list = false;
    char return_string[MAX_LENGTH_RETURN_STRING] = {0};

    hotpatch_msg->command[MAX_LENGTH_HP_CMD - 1] = '\0';
    if (strncmp(hotpatch_msg->command, "list", g_length_list) == 0) {
        is_list = true;
        ret = exec_hotpatch_command(hotpatch_msg->path, "check", return_string, MAX_LENGTH_RETURN_STRING);
    } else {
        ret = exec_hotpatch_command(hotpatch_msg->path, hotpatch_msg->command, return_string, MAX_LENGTH_RETURN_STRING);
    }

    if (ret != HP_OK) {
        write_runlog(LOG, "hotpatch exec error. ret is %d\n", ret);
    }

    if (is_list && (strncmp(return_string, "[PATCH-SUCCESS]", g_length_okstr) == 0)) {
        HotpatchReturnList(recvMsgInfo);
    } else if (is_list && (strstr(return_string, "No patch loaded now") != NULL)) {
        ret = strcpy_s(return_string, sizeof(return_string), "[PATCH-SUCCESS] LIST PATCH , NO PATCH LOAD!\n");
        securec_check_errno(ret, (void)ret);
        (void)RespondMsg(recvMsgInfo, 'S', return_string, strlen(return_string), DEBUG5);
    } else {
        (void)RespondMsg(recvMsgInfo, 'S', return_string, strlen(return_string), DEBUG5);
    }
#endif
    return;
}

void ProcessStopArbitrationMessage(void)
{
    ctl_stop_cluster_server_halt_arbitration_timeout = (uint32)ctl_stop_cluster_server_halt_arbitration_timeout_init;
    write_runlog(WARNING,
        "Received stop arbitration from cm_ctl, meaning that cm_ctl is about to running "
        "a full stop-cluster. stopping arbitration for %u\n",
        ctl_stop_cluster_server_halt_arbitration_timeout);
}

void process_finish_redo_check_message(MsgRecvInfo* recvMsgInfo)
{
    cm_to_ctl_finish_redo_check_ack msg_finish_redo_check_ack;
    msg_finish_redo_check_ack.msg_type = MSG_CM_CTL_FINISH_REDO_CHECK_ACK;
    msg_finish_redo_check_ack.finish_redo_count = FinishRedoCheck();
    (void)RespondMsg(recvMsgInfo, 'S', (char *)(&msg_finish_redo_check_ack), sizeof(msg_finish_redo_check_ack));
}

void process_finish_redo_message(MsgRecvInfo* recvMsgInfo)
{
    cm_msg_type msgFinishRedoAck;
    if (backup_open != CLUSTER_PRIMARY) {
        msgFinishRedoAck.msg_type = MSG_CM_CTL_BACKUP_OPEN;
        (void)RespondMsg(recvMsgInfo, 'S', (char *)(&msgFinishRedoAck), sizeof(cm_msg_type));
        return;
    }

    do_finish_redo = true;

    if (undocumentedVersion == 0 || undocumentedVersion >= 92214) {
        char status_key[MAX_PATH_LEN] = {0};
        char value[MAX_PATH_LEN] = {0};
        // initialize value, '2' means null
        errno_t rc = memset_s(value, sizeof(value), '2', sizeof(value) - 1);
        securec_check_errno(rc, (void)rc);

        // generate key path in ddb
        rc = snprintf_s(status_key, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/finish_redo_status", pw->pw_name);
        securec_check_intval(rc, (void)rc);

        for (uint32 group_index = 0; group_index < g_dynamic_header->relationCount; group_index++) {
            if (g_instance_role_group_ptr[group_index].instanceMember[0].instanceType == INSTANCE_TYPE_DATANODE) {
                (void)pthread_rwlock_wrlock(&(g_instance_group_report_status_ptr[group_index].lk_lock));
                g_instance_group_report_status_ptr[group_index].instance_status.finish_redo = true;
                (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[group_index].lk_lock));
                uint32 dn_index = g_instance_role_group_ptr[group_index].instanceMember[0].instanceId - 6001;
                value[dn_index] = '1';
            }
        }
        (void)pthread_rwlock_wrlock(&g_finish_redo_rwlock);
        status_t st = SetKV2Ddb(status_key, MAX_PATH_LEN, value, MAX_PATH_LEN, NULL);
        if (st != CM_SUCCESS) {
            write_runlog(
                ERROR, "%d: Ddb set finish_redos flag failed. key = %s,value = %s.\n", __LINE__, status_key, value);
            (void)pthread_rwlock_unlock(&g_finish_redo_rwlock);
            return;
        }
        (void)pthread_rwlock_unlock(&g_finish_redo_rwlock);
        write_runlog(LOG, "%d: Ddb set finish_redos flag success. key = %s,value = %s.\n", __LINE__, status_key, value);
    } else {
        char statusValue[MAX_PATH_LEN] = {0};
        errno_t rc = strcpy_s(statusValue, MAX_PATH_LEN, "true");
        securec_check_errno(rc, (void)rc);
        for (uint32 i = 0; i < g_dynamic_header->relationCount; i++) {
            (void)pthread_rwlock_wrlock(&(g_instance_group_report_status_ptr[i].lk_lock));
            if (g_instance_role_group_ptr[i].count > 0 &&
                g_instance_role_group_ptr[i].instanceMember[0].instanceType == INSTANCE_TYPE_DATANODE) {
                g_instance_group_report_status_ptr[i].instance_status.finish_redo = true;
            }
            (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[i].lk_lock));

            char status_key[MAX_PATH_LEN] = {0};
            rc = snprintf_s(status_key, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/finish_redo/%u", pw->pw_name, i);
            securec_check_intval(rc, (void)rc);

            (void)pthread_rwlock_wrlock(&g_finish_redo_rwlock);
            status_t st = SetKV2Ddb(status_key, MAX_PATH_LEN, statusValue, (uint32)MAX_PATH_LEN, NULL);
            if (st != CM_SUCCESS) {
                write_runlog(
                    ERROR, "%d: Ddb set finish redo flag failed, key = %s, value = true.\n", __LINE__, status_key);
                (void)pthread_rwlock_unlock(&g_finish_redo_rwlock);
                continue;
            }
            (void)pthread_rwlock_unlock(&g_finish_redo_rwlock);
            write_runlog(LOG, "line %d: Finish redo flag has been set to ddb in group %u.\n", __LINE__, i);
        }
    }

    write_runlog(LOG, "Finish redo flag has been set to true.\n");

    msgFinishRedoAck.msg_type = MSG_CM_CTL_FINISH_REDO_ACK;
    (void)RespondMsg(recvMsgInfo, 'S', (char *)(&msgFinishRedoAck), sizeof(msgFinishRedoAck));
}

void FlushCmToAgentMsg(MsgRecvInfo* recvMsgInfo, int msgType)
{
    CmToAgentMsg(recvMsgInfo, msgType);
}

status_t GetAgentDataReportMsg(CM_StringInfo inBuffer, agent_to_cm_datanode_status_report *agentToCmDatanodeStatusPtr)
{
    if (undocumentedVersion != 0 && undocumentedVersion < SUPPORT_IPV6_VERSION) {
        const agent_to_cm_datanode_status_report_ipv4 *agent_to_cm_datanode_status_ptr_ipv4 =
            (const agent_to_cm_datanode_status_report_ipv4 *)CmGetmsgbytes(inBuffer,
                sizeof(agent_to_cm_datanode_status_report_ipv4));
        if (agent_to_cm_datanode_status_ptr_ipv4 == NULL) {
            write_runlog(ERROR, "MSG_AGENT_CM_DATA_INSTANCE_REPORT_STATUS is null. inBuffer->qtype: %d \n",
                inBuffer->qtype);
            return CM_ERROR;
        }
        AgentToCmDatanodeStatusReportV1ToV2(agent_to_cm_datanode_status_ptr_ipv4, agentToCmDatanodeStatusPtr);
    } else {
        const agent_to_cm_datanode_status_report *agent_to_cm_datanode_status_ptr =
            (const agent_to_cm_datanode_status_report *)CmGetmsgbytes(inBuffer,
                sizeof(agent_to_cm_datanode_status_report));
        if (agent_to_cm_datanode_status_ptr == NULL) {
            write_runlog(ERROR,
                "MSG_AGENT_CM_DATA_INSTANCE_REPORT_STATUS is null. inBuffer->qtype: %d \n", inBuffer->qtype);
            return CM_ERROR;
        }
        errno_t rc = memcpy_s(agentToCmDatanodeStatusPtr,
            sizeof(agent_to_cm_datanode_status_report),
            agent_to_cm_datanode_status_ptr,
            sizeof(agent_to_cm_datanode_status_report));
        securec_check_errno(rc, (void)rc);
    }
    return CM_SUCCESS;
}

void SetAgentDataReportMsg(MsgRecvInfo* recvMsgInfo, CM_StringInfo inBuffer)
{
    agent_to_cm_datanode_status_report agent_to_cm_datanode_status_ptr = {0};
    if (GetAgentDataReportMsg(inBuffer, &agent_to_cm_datanode_status_ptr) != CM_SUCCESS) {
            return;
    }

    agent_to_cm_datanode_status_ptr.local_status.disconn_host[CM_IP_LENGTH - 1] = '\0';
    agent_to_cm_datanode_status_ptr.local_status.local_host[CM_IP_LENGTH - 1] = '\0';

    if (!g_inReload) {
        if (agent_to_cm_datanode_status_ptr.instanceType != INSTANCE_TYPE_DATANODE) {
            write_runlog(ERROR,
                "Instance type %d not equal INSTANCE_TYPE_DATANODE(%d) ! Maybe the msg_type send by remote "
                "cm_agent not match with local cm_server."
                "Check whether the version of cm_agent and cm_server on node %u is the same as localhost. "
                "msg_type=%d, node=%u, instanceId=%u, instanceType=%d, connectStatus=%d, processStatus=%d \n",
                agent_to_cm_datanode_status_ptr.instanceType,
                INSTANCE_TYPE_DATANODE, agent_to_cm_datanode_status_ptr.node,
                agent_to_cm_datanode_status_ptr.msg_type, agent_to_cm_datanode_status_ptr.node,
                agent_to_cm_datanode_status_ptr.instanceId, agent_to_cm_datanode_status_ptr.instanceType,
                agent_to_cm_datanode_status_ptr.connectStatus, agent_to_cm_datanode_status_ptr.processStatus);
            return;
        }
        g_loopState.execStatus[0] = 0;
        struct timeval checkBegin = {0, 0};
        struct timeval checkEnd = {0, 0};
        (void)gettimeofday(&checkBegin, NULL);
        if (g_single_node_cluster) {
            datanode_instance_arbitrate_single(recvMsgInfo, &agent_to_cm_datanode_status_ptr);
        } else if (g_multi_az_cluster) {
            DatanodeInstanceArbitrate(recvMsgInfo, &agent_to_cm_datanode_status_ptr);
        } else {
            /* datanode instances arbitrate for primary-standby-dummy cluster */
            datanode_instance_arbitrate_for_psd(recvMsgInfo, &agent_to_cm_datanode_status_ptr);
        }

        (void)gettimeofday(&checkEnd, NULL);
        if ((checkEnd.tv_sec - checkBegin.tv_sec) >= 2) {
            write_runlog(LOG,
                "it take %llu seconds for DN arbitrate.\n",
                (unsigned long long)GetTimeMinus(checkEnd, checkBegin));
        }
        g_loopState.execStatus[0] = 1;
    }
    return;
}

static void DnBarrierReportRespToCm(cm_to_agent_barrier_info *barrierRespMsg)
{
    errno_t rc = memset_s(barrierRespMsg, sizeof(cm_to_agent_barrier_info), 0, sizeof(cm_to_agent_barrier_info));
    securec_check_errno(rc, (void)rc);
    if (pw == NULL || pw->pw_name == NULL) {
        write_runlog(ERROR, "failed to get user name to make etcd key\n");
        return;
    }
    /* get query barrier from etcd */
    if (g_queryBarrier[0] != '\0') {
        rc = memcpy_s(barrierRespMsg->queryBarrier, BARRIERLEN - 1, g_queryBarrier, BARRIERLEN - 1);
        securec_check_errno(rc, (void)rc);
    }
    /* get target barrier from etcd */
    rc = memcpy_s(barrierRespMsg->targetBarrier, BARRIERLEN - 1, g_targetBarrier, BARRIERLEN - 1);
    securec_check_errno(rc, (void)rc);
}

static void SetDatanodeBarrierInfo(const AgentToCmBarrierStatusReport* barrierInfo)
{
    uint32 node = barrierInfo->node;
    uint32 instanceId = barrierInfo->instanceId;
    uint32 groupIdx = 0;
    int memIdx = 0;
    int ret;
    int rc;
    ret = find_node_in_dynamic_configure(node, instanceId, &groupIdx, &memIdx);
    if (ret != 0) {
        write_runlog(LOG, "can't find the instance(node =%u  instanceid =%u)\n", node, instanceId);
        return;
    }
    (void)pthread_rwlock_wrlock(&(g_instance_group_report_status_ptr[groupIdx].lk_lock));
    cm_instance_datanode_report_status *localRep =
        &(g_instance_group_report_status_ptr[groupIdx].instance_status.data_node_member[memIdx]);
    rc = memcpy_s(localRep->barrierID, BARRIERLEN, barrierInfo->barrierID, BARRIERLEN);
    securec_check_errno(rc, (void)rc);
    rc = memcpy_s(localRep->query_barrierId, BARRIERLEN, barrierInfo->query_barrierId, BARRIERLEN);
    securec_check_errno(rc, (void)rc);
    localRep->is_barrier_exist = barrierInfo->is_barrier_exist;
    (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[groupIdx].lk_lock));
}

void ProcessDnBarrierinfo(MsgRecvInfo* recvMsgInfo, CM_StringInfo inBuffer)
{
    AgentToCmBarrierStatusReport *barrierInfo =
        (AgentToCmBarrierStatusReport *)CmGetmsgbytes(inBuffer, sizeof(AgentToCmBarrierStatusReport));
    if (barrierInfo == NULL) {
        write_runlog(ERROR, "MSG_AGENT_CM_DATA_INSTANCE_BARRIER is null. inBuffer->qtype: %d \n", inBuffer->qtype);
        return;
    }
    barrierInfo->global_achive_barrierId[BARRIERLEN - 1] = '\0';
    barrierInfo->global_barrierId[BARRIERLEN - 1] = '\0';
    barrierInfo->query_barrierId[BARRIERLEN - 1] = '\0';
    barrierInfo->barrierID[BARRIERLEN - 1] = '\0';
    SetDatanodeBarrierInfo(barrierInfo);
    /* response to cm agent. */
    cm_to_agent_barrier_info barrierRespMsg;
    DnBarrierReportRespToCm(&barrierRespMsg);
    barrierRespMsg.msg_type = (int)MSG_CM_AGENT_DATANODE_INSTANCE_BARRIER;
    barrierRespMsg.instanceId = barrierInfo->instanceId;
    barrierRespMsg.node = barrierInfo->node;
    (void)RespondMsg(recvMsgInfo, 'S', (char *)(&barrierRespMsg), sizeof(cm_to_agent_barrier_info), DEBUG5);

    return;
}

static status_t CheckDdbType(DDB_TYPE toDdbType)
{
    if (g_dbType == DB_UNKOWN) {
        write_runlog(LOG, "[switch] ddb type is unknown.\n");
        return CM_ERROR;
    }
    bool isEtcdToDcc = (g_dbType == DB_ETCD) && (toDdbType == DB_DCC);
    bool isDccToEtcd = (g_dbType == DB_DCC) && (toDdbType == DB_ETCD);
    if (isEtcdToDcc || isDccToEtcd) {
        write_runlog(LOG, "[switch] can do switch ddb to %d.\n", (int)toDdbType);
        return CM_SUCCESS;
    }
    write_runlog(ERROR, "[switch] current ddb is %s, can't switch to %d.\n", GetDdbToString(g_dbType), (int)toDdbType);

    return CM_ERROR;
}

static status_t CreateMaintainPath(const char *maintainFile)
{
    std::string ddbStr = to_string(static_cast<int>(g_dbType));
    FILE *fp = fopen(maintainFile, "w+");
    if (fp == NULL) {
        write_runlog(ERROR, "[switch] can't open file \"%s\", errno(%d).\n", maintainFile, errno);
        return CM_ERROR;
    }
    (void)chmod(maintainFile, S_IRUSR | S_IWUSR);

    if (fwrite(ddbStr.c_str(), ddbStr.size(), 1, fp) != 1) {
        write_runlog(ERROR, "[switch] could not write file \"%s\", errno(%d)\n", maintainFile, errno);
        (void)fclose(fp);
        return CM_ERROR;
    }
    (void)fclose(fp);

    return CM_SUCCESS;
}

static status_t SendMaintainFileToAllCms(const char *maintainFile)
{
    int ret;
    char cmd[CM_PATH_LENGTH] = {0};

    for (uint32 i = 0; i < g_cm_server_num; ++i) {
        if (g_node[g_nodeIndexForCmServer[i]].node == g_currentNode->node) {
            continue;
        }
        if (GetIpVersion(g_node[g_nodeIndexForCmServer[i]].sshChannel[0]) == AF_INET6) {
            ret = snprintf_s(cmd, CM_PATH_LENGTH, CM_PATH_LENGTH - 1, "scp %s %s@[%s]:%s", maintainFile, pw->pw_name,
                g_node[g_nodeIndexForCmServer[i]].sshChannel[0], maintainFile);
                securec_check_intval(ret, (void)ret);
        } else {
            ret = snprintf_s(cmd, CM_PATH_LENGTH, CM_PATH_LENGTH - 1, "scp %s %s@%s:%s", maintainFile, pw->pw_name,
                g_node[g_nodeIndexForCmServer[i]].sshChannel[0], maintainFile);
            securec_check_intval(ret, (void)ret);
        }
        ret = system(cmd);
        if (ret != -1 && WEXITSTATUS(ret) == 0) {
            write_runlog(LOG, "[switch] exec cmd(%s) success\n", cmd);
            continue;
        } else {
            write_runlog(ERROR, "[switch] exec cmd(%s) failed, ret = %d, errno = %d.\n", cmd, WEXITSTATUS(ret), errno);
            return CM_ERROR;
        }
    }

    return CM_SUCCESS;
}

static status_t CreateMaintainFileInAllCms()
{
    char maintainFile[CM_PATH_LENGTH] = {0};

    if (GetMaintainPath(maintainFile, CM_PATH_LENGTH) != CM_SUCCESS) {
        write_runlog(ERROR, "[switch] get maintain file path fail.\n");
        return CM_ERROR;
    }

    if (CreateMaintainPath(maintainFile) != CM_SUCCESS) {
        write_runlog(ERROR, "[switch] can't into maintain mode.\n");
        return CM_ERROR;
    }
    if (SendMaintainFileToAllCms(maintainFile) != CM_SUCCESS) {
        write_runlog(ERROR, "[switch] send maintain file fail.\n");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static status_t CreateCommitFlagFile()
{
    FILE *fp;
    errno_t rc;
    char gausshomePath[CM_PATH_LENGTH] = {0};
    char commitFlagFile[CM_PATH_LENGTH] = {0};

    if (GetHomePath(gausshomePath, sizeof(gausshomePath)) != EOK) {
        write_runlog(ERROR, "get GAUSSHOME env fail, errno(%d).\n", errno);
        return CM_ERROR;
    }
    rc = snprintf_s(commitFlagFile, CM_PATH_LENGTH, CM_PATH_LENGTH - 1, "%s/bin/switch_commit_flag", gausshomePath);
    securec_check_intval(rc, (void)rc);

    canonicalize_path(commitFlagFile);
    if ((fp = fopen(commitFlagFile, "w+")) == NULL) {
        write_runlog(ERROR, "[switch] can't open file \"%s\", errno(%d).\n", commitFlagFile, errno);
        return CM_ERROR;
    }
    (void)chmod(commitFlagFile, S_IRUSR | S_IWUSR);
    (void)fclose(fp);

    return CM_SUCCESS;
}

static status_t DeleteCommitFlag()
{
    int ret;
    char gausshome[CM_PATH_LENGTH] = {0};
    char commitFlag[CM_PATH_LENGTH] = {0};

    if (GetHomePath(gausshome, sizeof(gausshome)) != 0) {
        write_runlog(ERROR, "get GAUSSHOME env fail, errno(%d).\n", errno);
        return CM_ERROR;
    }
    ret = snprintf_s(commitFlag, CM_PATH_LENGTH, CM_PATH_LENGTH - 1, "%s/bin/switch_commit_flag", gausshome);
    securec_check_intval(ret, (void)ret);
    (void)unlink(commitFlag);

    return CM_SUCCESS;
}

static status_t SetCmsConfParam(const DDB_TYPE ddb)
{
    int ret;
    char setCmd[CM_PATH_LENGTH] = {0};

    if (ddb == DB_UNKOWN) {
        write_runlog(ERROR, "[switch] set ddb is unknown.\n");
        return CM_ERROR;
    }
    if (CreateCommitFlagFile() != CM_SUCCESS) {
        write_runlog(ERROR, "[switch] create commit flag file fail.\n");
        return CM_ERROR;
    }

    ret = snprintf_s(
        setCmd,
        CM_PATH_LENGTH,
        CM_PATH_LENGTH - 1,
        "nohup cm_ctl set --param --server -k \"ddb_type\"=\"%d\"",
        (int)(ddb));
    securec_check_intval(ret, (void)ret);
    if (system(setCmd) != 0) {
        write_runlog(ERROR, "[switch] exec set cmd(%s) fail.\n", setCmd);
        return CM_ERROR;
    }
    if (DeleteCommitFlag() != CM_SUCCESS) {
        write_runlog(ERROR, "[switch] delete commit file fail.\n");
        return CM_ERROR;
    }
    write_runlog(LOG, "[switch] exec set cmd(%s) success.\n", setCmd);

    return CM_SUCCESS;
}

static void ProcessEnterMaintainMode(const CtlToCmsSwitch *switchMsg, CmsToCtlSwitchAck *ackMsg)
{
    errno_t rc;
    DDB_TYPE toDdbType = GetStringToDdb(switchMsg->ddbType);
    if (toDdbType == DB_ETCD && g_etcd_num == 0) {
        ackMsg->isSuccess = false;
        rc = strcpy_s(ackMsg->errMsg, CM_PATH_LENGTH,
            "can't switch to ETCD, cause no etcd is configured in the cluster.");
        securec_check_errno(rc, (void)rc);
        return;
    }
    if (CheckDdbType(toDdbType) != CM_SUCCESS) {
        ackMsg->isSuccess = false;
        rc = snprintf_s(ackMsg->errMsg, CM_PATH_LENGTH, CM_PATH_LENGTH - 1,
            "current ddb is %s, can't switch to %s, you can switch to DCC or ETCD.",
            GetDdbToString(g_dbType), switchMsg->ddbType);
        securec_check_intval(rc, (void)rc);
        return;
    }
    if (CreateMaintainFileInAllCms() != CM_SUCCESS) {
        ackMsg->isSuccess = false;
        rc = strcpy_s(ackMsg->errMsg, CM_PATH_LENGTH, "create maintain files fail.");
        securec_check_errno(rc, (void)rc);
        return;
    }
    ackMsg->isSuccess = true;

    return;
}

static status_t SwitchSaveAllKVS()
{
    char kvFile[MAX_PATH_LEN] = {0};
    DDB_RESULT dbResult = SUCCESS_GET_VALUE;
    DrvSaveOption option = {0};

    if (GetDdbKVFilePath(kvFile, MAX_PATH_LEN) != CM_SUCCESS) {
        write_runlog(ERROR, "[switch] can't get kv file path.\n");
        return CM_ERROR;
    }

    option.kvFile = kvFile;
    if (SaveAllKVFromDDb(&dbResult, &option) != CM_SUCCESS) {
        write_runlog(ERROR, "[switch] can't save all KV, error msg is %d.\n", (int)dbResult);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static void ProcessSaveAllKVS(const char *ddbType, CmsToCtlSwitchAck *ackMsg)
{
    errno_t rc;

    if (SwitchSaveAllKVS() != CM_SUCCESS) {
        ackMsg->isSuccess = false;
        rc = strcpy_s(ackMsg->errMsg, CM_PATH_LENGTH, "save all kvs from ddb fail.");
        securec_check_errno(rc, (void)rc);
        return;
    }
    if (SetCmsConfParam(GetStringToDdb(ddbType)) != CM_SUCCESS) {
        ackMsg->isSuccess = false;
        rc = strcpy_s(ackMsg->errMsg, CM_PATH_LENGTH, "set cm_server.conf ddb_type param fail.");
        securec_check_errno(rc, (void)rc);
        return;
    }
    ackMsg->isSuccess = true;

    return;
}

static status_t GetMaintainFromOtherCms(const char *kvFile)
{
    int ret;
    int index = -1;
    char cmd[CM_PATH_LENGTH] = {0};

    for (uint32 i = 0; i < g_cm_server_num; ++i) {
        if (g_node[i].node == g_currentNode->node) {
            continue;
        }
        ret = snprintf_s(cmd,
            CM_PATH_LENGTH,
            CM_PATH_LENGTH - 1,
            "pssh %s -H %s \" stat %s \" > /dev/null 2>&1",
            PSSH_TIMEOUT_OPTION,
            g_node[i].sshChannel[0],
            kvFile);
        securec_check_intval(ret, (void)ret);
        ret = system(cmd);
        if (ret != -1 && WEXITSTATUS(ret) == 0) {
            write_runlog(LOG, "[switch] node(%u) exist maintain, exec cmd(%s).\n", i, cmd);
            index = (int)i;
            break;
        }
        write_runlog(LOG, "[switch] node(%u) exist no maintain, exec cmd(%s).\n", i, cmd);
    }
    if (index == -1) {
        write_runlog(ERROR, "no cms has maintain file.\n");
        return CM_ERROR;
    }
    ret = memset_s(cmd, sizeof(cmd), 0, sizeof(cmd));
    securec_check_errno(ret, (void)ret);
    if (GetIpVersion(g_node[index].sshChannel[0]) == AF_INET6) {
        ret = snprintf_s(cmd, CM_PATH_LENGTH, CM_PATH_LENGTH - 1, "scp %s@[%s]:%s %s > /dev/null 2>&1",
            pw->pw_name, g_node[index].sshChannel[0], kvFile, kvFile);
        securec_check_intval(ret, (void)ret);
    } else {
        ret = snprintf_s(cmd, CM_PATH_LENGTH, CM_PATH_LENGTH - 1, "scp %s@%s:%s %s > /dev/null 2>&1",
            pw->pw_name, g_node[index].sshChannel[0], kvFile, kvFile);
        securec_check_intval(ret, (void)ret);
    }
    ret = system(cmd);
    if (ret != -1 && WEXITSTATUS(ret) == 0) {
        write_runlog(LOG, "[switch] exec cmd(%s) success.\n", cmd);
        return CM_SUCCESS;
    }
    write_runlog(ERROR, "[switch] exec cmd(%s) fail, ret = %d, errno = %d.\n", cmd, WEXITSTATUS(ret), errno);

    return CM_ERROR;
}

static status_t GetKVFile(char *kvFile, uint32 len)
{
    struct stat buf = {0};

    if (GetDdbKVFilePath(kvFile, len) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (stat(kvFile, &buf) != 0) {
        if (GetMaintainFromOtherCms(kvFile) != CM_SUCCESS) {
            write_runlog(ERROR, "[switch] no kv file, can't do switch ddb.\n");
            return CM_ERROR;
        }
    }

    return CM_SUCCESS;
}

static inline void ModifierLine(char *line)
{
    char *find = strchr(line, '\n');
    if (find != NULL) {
        *find = '\0';
    }
    return;
}

static void ProcessSwitchDdb(CmsToCtlSwitchAck *ackMsg)
{
    errno_t rc;
    DrvSetOption opt = {0};
    char kvFile[CM_PATH_LENGTH] = {0};

    if (GetKVFile(kvFile, CM_PATH_LENGTH) != CM_SUCCESS) {
        ackMsg->isSuccess = false;
        rc = strcpy_s(ackMsg->errMsg, CM_PATH_LENGTH, "no kv file exist.");
        securec_check_errno(rc, (void)rc);
        return;
    }
    char **lines = CmReadfile(kvFile);
    if (lines == NULL) {
        write_runlog(ERROR, "read kv file failed, errno(%d).\n", errno);
        rc = strcpy_s(ackMsg->errMsg, CM_PATH_LENGTH, "read kv file failed.");
        securec_check_errno(rc, (void)rc);
        return;
    }
    int i = 0;
    opt.maintainCanSet = true;
    opt.isSetBinary = false;
    while (lines[i] != NULL && lines[i + 1] != NULL) {
        ModifierLine(lines[i]);
        ModifierLine(lines[i + 1]);
        if (SetKV2Ddb(lines[i], DDB_KEY_LEN, lines[i + 1], DDB_VALUE_LEN, &opt) != CM_SUCCESS) {
            ackMsg->isSuccess = false;
            rc = strcpy_s(ackMsg->errMsg, CM_PATH_LENGTH, "put all kv to new ddb fail.");
            securec_check_errno(rc, (void)rc);
            freefile(lines);
            return;
        }
        i += KV_POS;
    }
    ackMsg->isSuccess = true;
    freefile(lines);

    return;
}

void ProcessCtlToCmsSwitchMsg(MsgRecvInfo* recvMsgInfo, CtlToCmsSwitch *switchMsg)
{
    CmsToCtlSwitchAck ackMsg;

    switchMsg->ddbType[CM_PATH_LENGTH - 1] = '\0';
    switch (switchMsg->step) {
        case SWITCH_DDB_ENTER_MAINTAIN:
            ProcessEnterMaintainMode(switchMsg, &ackMsg);
            break;
        case SWITCH_DDB_SAVE_ALL_KVS:
            ProcessSaveAllKVS(switchMsg->ddbType, &ackMsg);
            break;
        case SWITCH_DDB:
            ProcessSwitchDdb(&ackMsg);
            break;
        case UNKNOWN_STEP:
        default:
            break;
    }
    ackMsg.msgType = (int)MSG_CMS_CTL_SWITCH_ACK;
    (void)RespondMsg(recvMsgInfo, 'S', (char *)(&ackMsg), sizeof(ackMsg));

    return;
}
