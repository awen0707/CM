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
 * cms_msg_que.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_server/cms_msg_que.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CMS_MSG_QUE_H
#define CMS_MSG_QUE_H

#include <queue>
#include <pthread.h>
#include "c.h"
#include "stringinfo.h"
#include "cm_util.h"

enum MsgSourceType {
    MsgSrcAgent = 0,
    MsgSrcCtl,
    MSG_SRC_COUNT
};

struct ConnID {
    int32 remoteType; // CM_AGENT,CM_CTL
    uint64 connSeq;
    uint32 agentNodeId;
    uint64 t1;
    uint64 t2;
    uint64 t3;
    uint64 t4;
    uint64 t5;
    uint64 t6;
    uint64 t7;
    uint64 t8;
    uint64 t9;
    uint64 t10;
};

struct MsgSendInfo {
    ConnID connID;
    int32 log_level;
    uint64 procTime;
    uint8 msgProcFlag;
    char msgType;
    char procMethod;
    char reserved;  // for alignment
    uint32 dataSize;
    uint64 data[0];
};

struct MsgRecvInfo {
    ConnID connID;
    uint8 msgProcFlag;
    uint8 reserved1;
    uint8 reserved2;
    uint8 reserved3;
    CM_StringInfoData msg;
    uint64 data[0];
};

using MsgQueType = std::deque<const char *>;
using MsgQuePtr = MsgQueType*;
using ConstMsgQuePtr = const MsgQueType*;

struct MsgQue {
    MsgQueType que;
    CMFairMutex fairLock;
};

struct PriMsgQues {
    MsgQue ques[MSG_SRC_COUNT];
    pthread_mutex_t msgLock;
    pthread_cond_t msgCond;
};

typedef void (*wakeSenderFuncType)(const ConnID connID);
typedef bool (*CanProcThisMsgFunType)(void *threadInfo, const char *msgData);
void InitMsgQue(PriMsgQues &que);
size_t getMsgCount(PriMsgQues *priQue);

void pushRecvMsg(PriMsgQues* priQue, MsgRecvInfo* msg, MsgSourceType src);
const MsgRecvInfo *getRecvMsg(PriMsgQues *priQue, MsgSourceType src, uint32 waitTime, void *threadInfo);
bool existRecvMsg();

void pushSendMsg(PriMsgQues *priQue, MsgSendInfo *msg, MsgSourceType src);
const MsgSendInfo *getSendMsg(PriMsgQues *priQue, MsgSourceType src);

bool existSendMsg(const PriMsgQues *priQue);
void setWakeSenderFunc(wakeSenderFuncType func);
void SetCanProcThisMsgFun(CanProcThisMsgFunType func);

#endif