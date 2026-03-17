/*
 * Copyright (c) 2022 Huawei Technologies Co.,Ltd.
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
 * cma_msg_queue.cpp
 *
 * IDENTIFICATION
 *    src/cm_agent/cma_msg_queue.cpp
 *
 * -------------------------------------------------------------------------
 */
#include <csignal>
#include "cm_elog.h"
#include "cm_msg_buf_pool.h"
#include "cma_connect.h"
#include "cma_connect_client.h"
#include "cma_msg_queue.h"

typedef struct AgentMsgQueueSt {
    MsgQueue cms;
    MsgQueue client;
} AgentMsgQueue;

AgentMsgQueue *g_sendQueue = NULL;
AgentMsgQueue *g_recvQueue = NULL;
pthread_t g_recvSendThreadId = 0;

void AllocCmaMsgQueueMemory()
{
    g_sendQueue = new AgentMsgQueue();
    g_recvQueue = new AgentMsgQueue();
}

void FreeMsgQueueMemory()
{
    delete g_sendQueue;
    g_sendQueue = NULL;
    delete g_recvQueue;
    g_recvQueue = NULL;
}

static char *GetMsgBufAndFillBuf(const char *msgPtr, uint32 msgLen)
{
    char *ptr = (char*)AllocBufFromMsgPool(msgLen);
    if (ptr == NULL) {
        write_runlog(ERROR, "AllocBufFromMsgPool failed.\n");
        return NULL;
    }
    errno_t rc = memcpy_s(ptr, msgLen, msgPtr, msgLen);
    securec_check_errno(rc, (void)rc);
    return ptr;
}

static inline void WakeCmaSendThread()
{
    if (g_recvSendThreadId == 0) {
        write_runlog(LOG, "recvSendThread not ready, can't wakeup.\n");
        return;
    }
    if (pthread_kill(g_recvSendThreadId, SIGUSR1) != 0) {
        write_runlog(ERROR, "send SIGUSR1 sig to recv and send thread fail.\n");
    }
}

void PushMsgToCmsSendQue(const char *msgPtr, uint32 msgLen, const char *msgInfo)
{
    if (msgPtr != NULL && msgLen >= sizeof(int32) && *(int32*)msgPtr == 0) {
        write_runlog(LOG, "%s msgPtr is 0. it may be error.\n", msgInfo);
    }

    AgentMsgPkg msgPkg = {0};
    msgPkg.msgLen = msgLen;
    msgPkg.msgPtr = GetMsgBufAndFillBuf(msgPtr, msgLen);
    CM_RETURN_IF_NULL(msgPkg.msgPtr);

    write_runlog(DEBUG5, "push [%s] msg to send que:msgLen=%u.\n", msgInfo, msgPkg.msgLen);

    (void)pthread_mutex_lock(&g_sendQueue->cms.lock);
    g_sendQueue->cms.msg.push(msgPkg);
    WakeCmaSendThread();
    (void)pthread_mutex_unlock(&g_sendQueue->cms.lock);
}

static inline void PushToAgentMsgQue(const AgentMsgPkg *msgPkg, MsgQueue *msgQue)
{
    (void)pthread_mutex_lock(&msgQue->lock);
    msgQue->msg.push(*msgPkg);
    (void)pthread_mutex_unlock(&msgQue->lock);
    (void)pthread_cond_signal(&msgQue->cond);
}

void PushMsgToAllClientSendQue(const char *msgPtr, uint32 msgLen)
{
    ClientConn *clientConn = GetClientConnect();
    for (uint32 i = 0; i < CM_MAX_RES_COUNT; ++i) {
        if (!clientConn[i].isClosed) {
            write_runlog(LOG, "notify inst(%u), CMA disconnect with CMS.\n", clientConn[i].cmInstanceId);
            PushMsgToClientSendQue(msgPtr, msgLen, i);
        }
    }
}

void PushMsgToClientSendQue(const char *msgPtr, uint32 msgLen, uint32 conId)
{
    AgentMsgPkg msgPkg = {0};
    msgPkg.msgLen = msgLen;
    msgPkg.conId = conId;
    msgPkg.msgPtr = GetMsgBufAndFillBuf(msgPtr, msgLen);
    CM_RETURN_IF_NULL(msgPkg.msgPtr);

    const char *resName = GetClientConnect()[conId].resName;
    write_runlog(DEBUG5, "push msg to res(%s) client send que:msgLen=%u.\n", resName, msgPkg.msgLen);

    PushToAgentMsgQue(&msgPkg, &g_sendQueue->client);
}

void PushMsgToCmsRecvQue(const char *msgPtr, uint32 msgLen)
{
    AgentMsgPkg msgPkg = {0};
    msgPkg.msgLen = msgLen;
    msgPkg.msgPtr = GetMsgBufAndFillBuf(msgPtr, msgLen);
    CM_RETURN_IF_NULL(msgPkg.msgPtr);

    write_runlog(DEBUG5, "push msg to recv que:msgLen=%u.\n", msgPkg.msgLen);

    PushToAgentMsgQue(&msgPkg, &g_recvQueue->cms);
}

void PushMsgToClientRecvQue(const char *msgPtr, uint32 msgLen, uint32 conId)
{
    AgentMsgPkg msgPkg = {0};
    msgPkg.msgLen = msgLen;
    msgPkg.msgPtr = GetMsgBufAndFillBuf(msgPtr, msgLen);
    CM_RETURN_IF_NULL(msgPkg.msgPtr);

    const char *resName = GetClientConnect()[conId].resName;
    write_runlog(DEBUG5, "push msg to res(%s) client recv que:msgLen=%u.\n", resName, msgPkg.msgLen);

    PushToAgentMsgQue(&msgPkg, &g_recvQueue->client);
}

void CleanCmsMsgQueueCore(AgentMsgQueue *msgQueue)
{
    (void)pthread_mutex_lock(&msgQueue->cms.lock);
    while (!msgQueue->cms.msg.empty()) {
        FreeBufFromMsgPool(msgQueue->cms.msg.front().msgPtr);
        msgQueue->cms.msg.pop();
    }
    (void)pthread_mutex_unlock(&msgQueue->cms.lock);
}

void CleanClientMsgQueueCore(AgentMsgQueue *msgQueue, uint32 conId)
{
    (void)pthread_mutex_lock(&msgQueue->client.lock);
    queue<AgentMsgPkg> newQue;
    while (!msgQueue->client.msg.empty()) {
        if (msgQueue->client.msg.front().conId == conId) {
            FreeBufFromMsgPool(msgQueue->client.msg.front().msgPtr);
            msgQueue->client.msg.pop();
            continue;
        }
        newQue.push(msgQueue->client.msg.front());
        msgQueue->client.msg.pop();
    }
    swap(msgQueue->client.msg, newQue);
    (void)pthread_mutex_unlock(&msgQueue->client.lock);
}

void CleanCmsMsgQueue()
{
    CleanCmsMsgQueueCore(g_sendQueue);
    CleanCmsMsgQueueCore(g_recvQueue);
}

void CleanClientMsgQueue(uint32 conId = 0)
{
    CleanClientMsgQueueCore(g_sendQueue, conId);
    CleanClientMsgQueueCore(g_recvQueue, conId);
}

static void CleanAllClientMsgQueueCore(MsgQueue *clientQueue)
{
    (void)pthread_mutex_lock(&clientQueue->lock);
    while (!clientQueue->msg.empty()) {
        FreeBufFromMsgPool(clientQueue->msg.front().msgPtr);
        clientQueue->msg.pop();
    }
    (void)pthread_mutex_unlock(&clientQueue->lock);
}

void CleanAllClientRecvMsgQueue()
{
    CleanAllClientMsgQueueCore(&g_recvQueue->client);
}

void CleanAllClientSendMsgQueue()
{
    CleanAllClientMsgQueueCore(&g_sendQueue->client);
}

MsgQueue &GetCmsSendQueue()
{
    return g_sendQueue->cms;
}

MsgQueue &GetCmsRecvQueue()
{
    return g_recvQueue->cms;
}

MsgQueue &GetClientSendQueue()
{
    return g_sendQueue->client;
}

MsgQueue &GetClientRecvQueue()
{
    return g_recvQueue->client;
}

pthread_t &GetSendRecvThreadId()
{
    return g_recvSendThreadId;
}

bool IsCmsSendQueueEmpty()
{
    return g_sendQueue->cms.msg.empty();
}

void AllQueueInit()
{
    (void)pthread_mutex_init(&g_sendQueue->cms.lock, NULL);
    (void)pthread_cond_init(&g_sendQueue->cms.cond, NULL);
    (void)pthread_mutex_init(&g_sendQueue->client.lock, NULL);
    (void)pthread_cond_init(&g_sendQueue->client.cond, NULL);
    (void)pthread_mutex_init(&g_recvQueue->cms.lock, NULL);
    (void)pthread_cond_init(&g_recvQueue->cms.cond, NULL);
    (void)pthread_mutex_init(&g_recvQueue->client.lock, NULL);
    (void)pthread_cond_init(&g_recvQueue->client.cond, NULL);
}
