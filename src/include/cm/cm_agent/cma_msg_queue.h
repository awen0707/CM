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
 * cma_msg_queue.h
 *
 * IDENTIFICATION
 *    include/cm/cm_agent/cma_msg_queue.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CM_CMA_MSG_QUEUE_H
#define CM_CMA_MSG_QUEUE_H

#include <queue>
#include "cm_c.h"

using namespace std;

typedef struct AgentMsgPkgSt {
    char *msgPtr;
    uint32 msgLen;
    uint32 conId;
} AgentMsgPkg;

typedef struct MsgQueueSt {
    queue<AgentMsgPkg> msg;
    pthread_mutex_t lock;
    pthread_cond_t cond;
} MsgQueue;

void AllocCmaMsgQueueMemory();
void FreeMsgQueueMemory();

void PushMsgToCmsSendQue(const char *msgPtr, uint32 msgLen, const char *msgInfo);
void PushMsgToCmsRecvQue(const char *msgPtr, uint32 msgLen);
void PushMsgToClientSendQue(const char *msgPtr, uint32 msgLen, uint32 conId);
void PushMsgToClientRecvQue(const char *msgPtr, uint32 msgLen, uint32 conId);
void PushMsgToAllClientSendQue(const char *msgPtr, uint32 msgLen);

void CleanCmsMsgQueue();
void CleanClientMsgQueue(uint32 conId);
void CleanAllClientRecvMsgQueue();
void CleanAllClientSendMsgQueue();

void AllQueueInit();

MsgQueue &GetCmsSendQueue();
MsgQueue &GetCmsRecvQueue();
MsgQueue &GetClientSendQueue();
MsgQueue &GetClientRecvQueue();
pthread_t &GetSendRecvThreadId();

bool IsCmsSendQueueEmpty();

#endif  // CM_CMA_MSG_QUEUE_H
