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
 * cma_process_messages_client.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_agent/cma_process_messages_client.cpp
 *
 * -------------------------------------------------------------------------
 */
#include "cm/cm_elog.h"
#include "cma_connect.h"
#include "cma_connect_client.h"
#include "cma_common.h"
#include "cma_global_params.h"
#include "cma_instance_check.h"
#include "cma_status_check.h"
#include "cma_instance_management_res.h"
#include "cma_process_messages_client.h"

void NotifyClientConnectClose()
{
    AgentToClientNotify cmaMsg = {{0}};
    cmaMsg.head.msgType = (uint32)MSG_AGENT_CLIENT_NOTIFY_CONN_CLOSE;
    cmaMsg.notify.isCmaConnClose = CM_TRUE;

    PushMsgToAllClientSendQue((char*)&cmaMsg, sizeof(cmaMsg));
}

static void SendHeartbeatAckToClient(uint32 conId)
{
    MsgHead hbAck = {0};
    hbAck.msgType = MSG_AGENT_CLIENT_HEARTBEAT_ACK;

    PushMsgToClientSendQue((char*)&hbAck, sizeof(MsgHead), conId);
}

static void SendStatusListToClient(CmResStatList &statList, uint32 conId, bool isNotifyChange)
{
    AgentToClientResList sendList;
    errno_t rc = memset_s(&sendList, sizeof(AgentToClientResList), 0, sizeof(AgentToClientResList));
    securec_check_errno(rc, (void)rc);

    if (isNotifyChange) {
        sendList.head.msgType = (uint32)MSG_AGENT_CLIENT_RES_STATUS_CHANGE;
    } else {
        sendList.head.msgType = (uint32)MSG_AGENT_CLIENT_RES_STATUS_LIST;
    }

    (void)pthread_rwlock_rdlock(&(statList.rwlock));
    rc = memcpy_s(&sendList.resStatusList, sizeof(OneResStatList), &statList.status, sizeof(OneResStatList));
    securec_check_errno(rc, (void)rc);
    (void)pthread_rwlock_unlock(&(statList.rwlock));

    PrintCusInfoResList(&sendList.resStatusList, __FUNCTION__);

    PushMsgToClientSendQue((char*)&sendList, sizeof(AgentToClientResList), conId);
}

static void SendLockFailAckToClient(uint32 conId)
{
    AgentToClientResLockResult clientAck;
    errno_t rc = memset_s(&clientAck, sizeof(AgentToClientResLockResult), 0, sizeof(AgentToClientResLockResult));
    securec_check_errno(rc, (void)rc);
    clientAck.head.msgType = MSG_CM_RES_LOCK_ACK;
    clientAck.head.conId = conId;
    clientAck.result.error = (uint32)CM_RES_CLIENT_CANNOT_DO;

    PushMsgToClientSendQue((char*)&clientAck, sizeof(AgentToClientResLockResult), conId);
}

static void ProcessClientHeartbeat(const ClientHbMsg &hbMsg)
{
    uint32 index = 0;
    ClientConn *clientCon = GetClientConnect();
    if (GetGlobalResStatusIndex(clientCon[hbMsg.head.conId].resName, index) != CM_SUCCESS) {
        write_runlog(ERROR, "[CLIENT] ProcessClientHeartbeat, unknown the resName(%s) of client.\n",
            clientCon[hbMsg.head.conId].resName);
        return;
    }

    (void)pthread_rwlock_rdlock(&(g_resStatus[index].rwlock));
    bool isResStatChanged = (hbMsg.version != g_resStatus[index].status.version);
    (void)pthread_rwlock_unlock(&(g_resStatus[index].rwlock));

    if (isResStatChanged) {
        SendStatusListToClient(g_resStatus[index], hbMsg.head.conId, false);
    } else {
        SendHeartbeatAckToClient(hbMsg.head.conId);
    }
}

static void ProcessInitMsg(const ClientInitMsg &initData)
{
    AgentToClientInitResult sendMsg;
    errno_t rc = memset_s(&sendMsg, sizeof(AgentToClientInitResult), 0, sizeof(AgentToClientInitResult));
    securec_check_errno(rc, (void)rc);

    sendMsg.head.msgType = (uint32)MSG_AGENT_CLIENT_INIT_ACK;
    sendMsg.head.conId = initData.head.conId;
    sendMsg.result.isSuccess = false;

    ClientConn *clientCon = GetClientConnect();
    for (const CmResConfList &resInfo : g_resConf) {
        if ((strcmp(initData.resInfo.resName, resInfo.resName) == 0) && (g_currentNode->node == resInfo.nodeId) &&
            initData.resInfo.resInstanceId == resInfo.resInstanceId) {
            clientCon[initData.head.conId].cmInstanceId = resInfo.cmInstanceId;
            clientCon[initData.head.conId].resInstanceId = resInfo.resInstanceId;
            rc = strcpy_s(clientCon[initData.head.conId].resName, CM_MAX_RES_NAME, initData.resInfo.resName);
            securec_check_errno(rc, (void)rc);
            sendMsg.result.isSuccess = true;
            break;
        }
    }

    if (sendMsg.result.isSuccess) {
        write_runlog(LOG, "[CLIENT] res(%s) init success.\n", initData.resInfo.resName);
    } else {
        write_runlog(LOG, "[CLIENT] res(%s) init failed, init cfg: nodeId(%u), resInstId(%u).\n",
            initData.resInfo.resName, g_currentNode->node, initData.resInfo.resInstanceId);
    }

    PushMsgToClientSendQue((char*)&sendMsg, sizeof(AgentToClientInitResult), initData.head.conId);
}

static void GetResLockSendMsg(CmaToCmsResLock *sendMsg, const ClientCmLockMsg *lockMsg)
{
    sendMsg->msgType = (int)MSG_CM_RES_LOCK;
    sendMsg->lockOpt = lockMsg->info.lockOpt;
    sendMsg->conId = lockMsg->head.conId;
    const ClientConn *clientCon = GetClientConnect();
    sendMsg->cmInstId = clientCon[sendMsg->conId].cmInstanceId;
    errno_t rc = strcpy_s(sendMsg->resName, CM_MAX_RES_NAME, clientCon[sendMsg->conId].resName);
    securec_check_errno(rc, (void)rc);
    rc = strcpy_s(sendMsg->lockName, CM_MAX_LOCK_NAME, lockMsg->info.lockName);
    securec_check_errno(rc, (void)rc);
}

static uint32 ResInstIdToCmInstId(const char *resName, uint32 resInstId)
{
    uint32 index = 0;
    if (GetGlobalResStatusIndex(resName, index) != CM_SUCCESS) {
        write_runlog(ERROR, "[CLIENT] ProcessResStatusList, unknown the res(%s) of client.\n", resName);
        return 0;
    }
    for (uint32 i = 0; i < g_resStatus[index].status.instanceCount; ++i) {
        if (g_resStatus[index].status.resStat[i].resInstanceId == resInstId) {
            return g_resStatus[index].status.resStat[i].cmInstanceId;
        }
    }
    return 0;
}

static void ProcessCmResLock(ClientCmLockMsg *lockMsg)
{
    CmaToCmsResLock sendMsg = {0};
    GetResLockSendMsg(&sendMsg, lockMsg);

    if (lockMsg->info.lockOpt == (uint32)CM_RES_LOCK_TRANS) {
        sendMsg.transInstId = ResInstIdToCmInstId(sendMsg.resName, lockMsg->info.transInstId);
        if (!IsResInstIdValid((int)sendMsg.transInstId)) {
            write_runlog(ERROR, "[CLIENT] res instId(%u) is invalid, ack client!\n", sendMsg.transInstId);
            SendLockFailAckToClient(lockMsg->head.conId);
            return;
        }
    }

    PushMsgToCmsSendQue((char*)&sendMsg, sizeof(CmaToCmsResLock), "res lock");
}

static void ProcessClientMsg(char *recvMsg)
{
    const MsgHead *head = (MsgHead *)recvMsg;

    switch (head->msgType) {
        case MSG_CLIENT_AGENT_INIT_DATA: {
            ClientInitMsg *initMsg = (ClientInitMsg *)recvMsg;
            ProcessInitMsg(*initMsg);
            break;
        }
        case MSG_CLIENT_AGENT_HEARTBEAT: {
            ClientHbMsg *hbMsg = (ClientHbMsg *)recvMsg;
            ProcessClientHeartbeat(*hbMsg);
            break;
            }
        case MSG_CM_RES_LOCK: {
            ClientCmLockMsg *lockMsg = (ClientCmLockMsg *)recvMsg;
            ProcessCmResLock(lockMsg);
            break;
        }
        default:
            write_runlog(LOG, "[CLIENT] agent get unknown msg from client\n");
            break;
    }
}

void* ProcessMessageMain(void * const arg)
{
    thread_name = "ProcessClientMsg";
    write_runlog(LOG, "process client recv msg thread begin.\n");

    for (;;) {
        if (g_shutdownRequest || g_exitFlag) {
            cm_sleep(SHUTDOWN_SLEEP_TIME);
            continue;
        }
        MsgQueue &recvQueue = GetClientRecvQueue();
        (void)pthread_mutex_lock(&recvQueue.lock);
        while (recvQueue.msg.empty()) {
            (void)pthread_cond_wait(&recvQueue.cond, &recvQueue.lock);
        }
        char *msg = recvQueue.msg.front().msgPtr;
        recvQueue.msg.pop();
        (void)pthread_mutex_unlock(&recvQueue.lock);
        ProcessClientMsg(msg);
        FreeBufFromMsgPool(msg);
    }
    return NULL;
}

static inline void UpdateResStatusList(CmResStatList *resStat, const OneResStatList *newStat)
{
    (void)pthread_rwlock_wrlock(&(resStat->rwlock));
    errno_t rc = memcpy_s(&resStat->status, sizeof(OneResStatList), newStat, sizeof(OneResStatList));
    securec_check_errno(rc, (void)rc);
    (void)pthread_rwlock_unlock(&(resStat->rwlock));
}

void ProcessResStatusList(const CmsReportResStatList *msg)
{
    if (msg->resList.instanceCount > CM_MAX_RES_INST_COUNT) {
        write_runlog(ERROR, "cms send to cma, custom resource instance count (%u) is unavail, range[0, %d].\n",
            msg->resList.instanceCount, CM_MAX_RES_INST_COUNT);
        return;
    }

    uint32 index = 0;
    if (GetGlobalResStatusIndex(msg->resList.resName, index) != CM_SUCCESS) {
        write_runlog(ERROR, "[CLIENT] ProcessResStatusList, unknown the res(%s) of client.\n", msg->resList.resName);
        return;
    }

    UpdateResStatusList(&g_resStatus[index], &msg->resList);
    PrintCusInfoResList(&msg->resList, __FUNCTION__);
}

void ProcessResStatusChanged(const CmsReportResStatList *msg)
{
    ProcessResStatusList(msg);
    uint32 index = 0;
    if (GetGlobalResStatusIndex(msg->resList.resName, index) != CM_SUCCESS) {
        write_runlog(ERROR, "[CLIENT] ProcessResStatusChanged, unknown the res(%s) of client.\n", msg->resList.resName);
        return;
    }
    ClientConn *clientCon = GetClientConnect();
    for (uint32 i = 0; i < CM_MAX_RES_COUNT; ++i) {
        if (clientCon[i].isClosed || strcmp(clientCon[i].resName, msg->resList.resName) != 0) {
            continue;
        }
        SendStatusListToClient(g_resStatus[index], i, true);
    }
}

void ProcessResLockAckFromCms(const CmsReportLockResult *recvMsg)
{
    AgentToClientResLockResult sendMsg;
    errno_t rc = memset_s(&sendMsg, sizeof(AgentToClientResLockResult), 0, sizeof(AgentToClientResLockResult));
    securec_check_errno(rc, (void)rc);

    sendMsg.head.msgType = MSG_CM_RES_LOCK_ACK;
    sendMsg.head.conId = recvMsg->conId;
    sendMsg.result.error = recvMsg->error;
    rc = strcpy_s(sendMsg.result.lockName, CM_MAX_LOCK_NAME, recvMsg->lockName);
    securec_check_errno(rc, (void)rc);

    ClientConn *clientCon = GetClientConnect();
    if (recvMsg->lockOpt == (uint32)CM_RES_GET_LOCK_OWNER && recvMsg->error == 0) {
        uint32 index = 0;
        if (GetGlobalResStatusIndex(clientCon[sendMsg.head.conId].resName, index) != CM_SUCCESS) {
            write_runlog(ERROR, "[CLIENT] ProcessResLockAckFromCms, unknown the res(%s) of client.\n",
                clientCon[sendMsg.head.conId].resName);
            return;
        }
        bool getFlag = false;
        for (uint32 i = 0; i < g_resStatus[index].status.instanceCount; ++i) {
            if (g_resStatus[index].status.resStat[i].cmInstanceId == recvMsg->lockOwner) {
                sendMsg.result.lockOwner = g_resStatus[index].status.resStat[i].resInstanceId;
                getFlag = true;
                break;
            }
        }
        if (!getFlag) {
            sendMsg.result.lockOwner = 0;
            sendMsg.result.error = (uint32)CM_RES_CLIENT_CANNOT_DO;
            write_runlog(ERROR, "[CLIENT] unknown cmInstId %u.\n", recvMsg->lockOwner);
        }
    }

    PushMsgToClientSendQue((char*)&sendMsg, sizeof(AgentToClientResLockResult), recvMsg->conId);
}

static void ProcessUnregResInst(const CmsNotifyAgentRegMsg *recvMsg)
{
    CmResConfList *local = CmaGetResConfByResName(recvMsg->resName);
    if (local == NULL) {
        write_runlog(ERROR, "%s, get local res list failed.\n", __FUNCTION__);
        return;
    }

    ResIsregStatus isreg = IsregOneResInst(local, recvMsg->resInstId);
    if (isreg == CM_RES_ISREG_UNREG) {
        write_runlog(LOG, "local res inst[%s:%u] has been unreg.\n", recvMsg->resName, recvMsg->resInstId);
    } else if ((isreg == CM_RES_ISREG_REG) || (isreg == CM_RES_ISREG_PENDING) ||
        (recvMsg->resStat == CM_RES_ISREG_REG) || (recvMsg->resStat == CM_RES_ISREG_PENDING)) {
        (void)UnregOneResInst(local, recvMsg->resInstId);
    } else if (isreg == CM_RES_ISREG_NOT_SUPPORT) {
        write_runlog(LOG, "res inst[%s:%u] don't support reg, not need unreg.\n", recvMsg->resName, recvMsg->resInstId);
    } else {
        write_runlog(ERROR, "res inst[%s:%u] isreg:%s, can't do unreg.\n", recvMsg->resName, recvMsg->resInstId,
            GetIsregStatus((int)isreg));
    }
}

static void ProcessRegResInst(const CmsNotifyAgentRegMsg *recvMsg)
{
    if (g_currentNode->node != recvMsg->nodeId) {
        return;
    }

    CmResConfList *local = CmaGetResConfByResName(recvMsg->resName);
    if (local == NULL) {
        write_runlog(ERROR, "%s, get local res list failed.\n", __FUNCTION__);
        return;
    }

    ResIsregStatus isreg = IsregOneResInst(local, recvMsg->resInstId);
    if (isreg == CM_RES_ISREG_PENDING || recvMsg->resStat == CM_RES_ISREG_PENDING) {
        write_runlog(LOG, "res inst[%s:%u] is pending, local check isreg:%s, cms check isreg:%s.\n", recvMsg->resName, recvMsg->resInstId,
            GetIsregStatus((int)isreg), GetIsregStatus((int)recvMsg->resStat));
        (void)RegOneResInst(local, recvMsg->resInstId, CM_TRUE);
    } else if (isreg == CM_RES_ISREG_REG) {
        write_runlog(LOG, "local res inst[%s:%u] has been reg.\n", recvMsg->resName, recvMsg->resInstId);
    } else if (isreg == CM_RES_ISREG_UNREG) {
        /* when CM Server get abnormal status in DSS, we should clean at first, register all vg later. */
        write_runlog(LOG, "This res is abnormaly, before reg res inst, need clean res inst first.\n");
        if ((CheckOneResInst(local) == CUS_RES_CHECK_STAT_OFFLINE) || (CleanOneResInst(local) == CM_SUCCESS)) {
            (void)RegOneResInst(local, recvMsg->resInstId, CM_TRUE);
        }
    } else if (isreg == CM_RES_ISREG_UNKNOWN) {
        bool isCleanRes = false;
        /* We may get UNKNOWN status under adding VG process. */
        (void)pthread_rwlock_wrlock(&(pending_status_rwlock));
        if (g_isInVGAddProcess) {
            /* If ResourceIsregCheck thread has dected the PENDING status. */
            g_isRegUnderVGAddProcess= true;
        } else {
            isCleanRes = true;
        }
        (void)pthread_rwlock_unlock(&(pending_status_rwlock));
        if (isCleanRes && (CheckOneResInst(local) == CUS_RES_CHECK_STAT_OFFLINE ||
            CleanOneResInst(local) == CM_SUCCESS)) {
            write_runlog(LOG, "This res is abnormaly, before reg res inst, need clean res inst first.\n");
        }
        /* We should reg whether dss is online or offline. */
        (void)RegOneResInst(local, recvMsg->resInstId, CM_TRUE);
    } else if (isreg == CM_RES_ISREG_PENDING) {
        /* when CM Server get PENDING status in DSS, we should reg again to register all vg. */
        write_runlog(LOG, "partially register, will let reg again.\n");
        (void)pthread_rwlock_wrlock(&(pending_status_rwlock));
        g_isRegUnderVGAddProcess= true;
        (void)pthread_rwlock_unlock(&(pending_status_rwlock));
        (void)RegOneResInst(local, recvMsg->resInstId, CM_TRUE);
    } else if (isreg == CM_RES_ISREG_NOT_SUPPORT) {
        write_runlog(LOG, "res inst[%s:%u] don't support reg, not need reg.\n", recvMsg->resName, recvMsg->resInstId);
    } else {
        write_runlog(ERROR, "res inst[%s:%u] isreg:%s, can't do reg.\n", recvMsg->resName, recvMsg->resInstId,
            GetIsregStatus((int)isreg));
    }
}

void ProcessResRegFromCms(const CmsNotifyAgentRegMsg *recvMsg)
{
    switch (recvMsg->resMode) {
        case 0:
            ProcessUnregResInst(recvMsg);
            break;
        case 1:
            ProcessRegResInst(recvMsg);
            break;
        default:
            write_runlog(ERROR, "ProcessResRegFromCms, unknown res mode.\n");
            break;
    }
}

void ProcessIsregCheckListChanged(const CmsFlushIsregCheckList *recvMsg)
{
    write_runlog(LOG, "node(%u) report isreg list is wrong, need update.\n", g_currentNode->node);
    UpdateIsregCheckList(recvMsg->checkList, recvMsg->checkCount);
}
