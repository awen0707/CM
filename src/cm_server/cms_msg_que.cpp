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
 * cms_msg_que.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_server/cms_msg_que.cpp
 *
 * -------------------------------------------------------------------------
 */

#include "cm_c.h"
#include "cm_util.h"
#include "cm_misc_base.h"
#include "cm_msg_buf_pool.h"

#include "cms_msg_que.h"


static wakeSenderFuncType wakeSenderFunc = NULL;
static CanProcThisMsgFunType CanProcThisMsgFun = NULL;

void InitMsgQue(PriMsgQues &que)
{
    for (int i = 0; i < (int)MSG_SRC_COUNT; i++) {
        CMFairMutexInit(que.ques[i].fairLock);
    }

    (void)pthread_mutex_init(&que.msgLock, NULL);
    InitPthreadCondMonotonic(&que.msgCond);
}

void setWakeSenderFunc(wakeSenderFuncType func)
{
    wakeSenderFunc = func;
}

void SetCanProcThisMsgFun(CanProcThisMsgFunType func)
{
    CanProcThisMsgFun = func;
}

size_t getMsgCount(PriMsgQues *priQue)
{
    size_t count = 0;

    for (int i = 0; i < (int)MSG_SRC_COUNT; i++) {
        MsgQuePtr que = &priQue->ques[i].que;
        count += que->size();
    }

    return count;
}

bool existMsg(const PriMsgQues *priQue)
{
    for (int i = 0; i < (int)MSG_SRC_COUNT; i++) {
        ConstMsgQuePtr que = &priQue->ques[i].que;
        if (!que->empty()) {
            return true;
        }
    }

    return false;
}

void pushRecvMsg(PriMsgQues *priQue, MsgRecvInfo *msg, MsgSourceType src)
{
    Assert(src >= 0 && src < MSG_SRC_COUNT);

    (void)CMFairMutexLock(priQue->ques[src].fairLock, CMFairMutexType::CM_MUTEX_WRITE);
    msg->connID.t2 = GetMonotonicTimeMs();
    priQue->ques[src].que.push_back((const char *)msg);
    CMFairMutexUnLock(priQue->ques[src].fairLock);

    (void)pthread_cond_broadcast(&priQue->msgCond);
}

static const MsgRecvInfo *getRecvMsgInner(PriMsgQues *priQue, MsgSourceType src, void *threadInfo)
{
    Assert(src >= 0 && src < MSG_SRC_COUNT);
    MsgRecvInfo *msg = NULL;
    uint64 t3 = GetMonotonicTimeMs();

    if (!existMsg(priQue)) {
        return NULL;
    }

    for (int i = 0; i < (int)MSG_SRC_COUNT; i++) {
        MsgQuePtr que = &priQue->ques[src].que;
        (void)CMFairMutexLock(priQue->ques[src].fairLock, CMFairMutexType::CM_MUTEX_READ);
        MsgQueType::iterator it = que->begin();
        for (; it != que->end(); ++it) {
            if (CanProcThisMsgFun == NULL || CanProcThisMsgFun(threadInfo, *it)) {
                msg = (MsgRecvInfo *)*it;
                (void)que->erase(it);
                msg->connID.t3 = t3;
                msg->connID.t4 = GetMonotonicTimeMs();
                break;
            }
        }
        CMFairMutexUnLock(priQue->ques[src].fairLock);

        if (msg != NULL) {
            break;
        }
        src = (src == MsgSrcAgent) ? MsgSrcCtl : MsgSrcAgent;  // switch src type;
    }

    return msg;
}

const MsgRecvInfo *getRecvMsg(PriMsgQues *priQue, MsgSourceType src, uint32 waitTime, void *threadInfo)
{
    struct timespec tv;
    if (priQue == NULL) {
        return NULL;
    }

    const MsgRecvInfo* msg = getRecvMsgInner(priQue, src, threadInfo);

    if (msg == NULL && waitTime > 0) {
        (void)clock_gettime(CLOCK_MONOTONIC, &tv);
        tv.tv_sec = tv.tv_sec + (long long)waitTime;
        (void)pthread_mutex_lock(&priQue->msgLock);
        (void)pthread_cond_timedwait(&priQue->msgCond, &priQue->msgLock, &tv);
        (void)pthread_mutex_unlock(&priQue->msgLock);
    }

    return msg;
}

void pushSendMsg(PriMsgQues *priQue, MsgSendInfo *msg, MsgSourceType src)
{
    Assert(src >= 0 && src < MSG_SRC_COUNT);
    ConnID connID = msg->connID;
    (void)CMFairMutexLock(priQue->ques[src].fairLock, CMFairMutexType::CM_MUTEX_WRITE);
    priQue->ques[src].que.push_back((const char*)msg);
    msg->connID.t6 = GetMonotonicTimeMs();
    CMFairMutexUnLock(priQue->ques[src].fairLock);

    if (wakeSenderFunc != NULL) {
        wakeSenderFunc(connID);
    }
}

const MsgSendInfo *getSendMsg(PriMsgQues *priQue, MsgSourceType src)
{
    const MsgSendInfo *msg = NULL;

    if (!existMsg(priQue)) {
        return NULL;
    }

    uint64 now = GetMonotonicTimeMs();
    for (int i = 0; i < (int)MSG_SRC_COUNT; i++) {
        MsgQuePtr que = &priQue->ques[src].que;
        (void)CMFairMutexLock(priQue->ques[src].fairLock, CMFairMutexType::CM_MUTEX_READ);
        MsgQueType::iterator it = que->begin();
        for (; it != que->end(); ++it) {
            MsgSendInfo *sendMsg = (MsgSendInfo *)(*it);
            if (sendMsg->procTime == 0 || sendMsg->procTime <= now) {
                msg = sendMsg;
                (void)que->erase(it);
                sendMsg->connID.t7 = now;
                sendMsg->connID.t8 = GetMonotonicTimeMs();
                break;
            }
        }
        CMFairMutexUnLock(priQue->ques[src].fairLock);

        if (msg != NULL) {
            break;
        }
        src = (src == MsgSrcAgent) ? MsgSrcCtl : MsgSrcAgent;
    }

    return msg;
}

bool existSendMsg(const PriMsgQues *priQue)
{
    return existMsg(priQue);
}

