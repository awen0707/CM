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
 * cm_client.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_client/cm_client.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CM_CLIENT_H
#define CM_CLIENT_H

#include <list>
#include <sys/un.h>
#include "cm/cm_msg.h"
#include "cm/cm_misc_base.h"
#include "cm_client_api.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CM_CLIENT_MSG_VER 1

#define NO_STAT_CHANGED 0
#define STAT_CHANGED    1

#define CLIENT_USEC_TO_NSEC     (1000)
#define CLIENT_INVALID_SOCKET   (-1)
#define CLIENT_RES_DATA_TIMEOUT (5)
#define CLIENT_SEND_CHECK_INTERVAL (300 * 1000)
#define CLIENT_RECV_CHECK_INTERVAL (300 * 1000)
#define CLIENT_CHECK_CONN_INTERVAL (200 * 1000)

typedef struct MsgPackageSt {
    char *msgPtr;
    size_t msgLen;
} MsgPackage;

typedef struct SockAddrSt {
    struct sockaddr_un addr;
    socklen_t addrLen;
} SockAddr;

typedef struct ConnAgentSt {
    int sock;
    volatile bool isClosed;
    uint32 resInstanceId;
    CmNotifyFunc callback;
    timespec recvTime;
    pthread_rwlock_t rwlock;
} ConnAgent;

typedef struct SendMsgQueueSt {
    std::list<MsgPackage> sendQueue;
    pthread_mutex_t lock;
    pthread_cond_t cond;
} SendMsgQueue;

typedef struct InitFlagSt {
    bool initSuccess;
    pthread_mutex_t lock;
    pthread_cond_t cond;
} InitFlag;

typedef struct LockFlagSt {
    uint32 error;
    uint32 ownerId;
    pthread_mutex_t condLock;
    pthread_mutex_t optLock;
    pthread_cond_t cond;
} LockFlag;

typedef struct ClientLockResultSt {
    uint32 error;
    uint32 ownerId;
} ClientLockResult;

typedef struct {
    LockFlag lockFlag;
    InitFlag initFlag;
    ConnAgent agentConnect;
    SendMsgQueue sendMsg;
    OneResStatList clientStatusList;
    pthread_t conThreadId;
    pthread_t sendThreadId;
    pthread_t recvThreadId;
} ClientCtx;

status_t CreateConnectAgentThread(void);
status_t CreateSendMsgThread(void);
status_t CreateRecvMsgThread(void);

#ifdef __cplusplus
}

status_t PreInit(uint32 instanceId, const char *resName, CmNotifyFunc func, bool *isFirstInit);
void ShutdownClient();
void AllocClientMemory();
void FreeClientMemory();
void SendMsgApi(char *msgPtr, size_t msgLen);
bool &GetIsClientInit();
LockFlag *GetLockFlag();
InitFlag *GetInitFlag();
OneResStatList *GetClientStatusList();
status_t SendInitMsg(uint32 instanceId, const char *resName);
bool SendInitMsgAndGetResult(const char *resName, uint32 instId);
ClientLockResult SendLockMsgAndWaitResult(char *msgPtr, uint32 msgLen);
void get_pause_path();

extern char g_manualPausePath[MAX_PATH_LEN];

#endif
#endif // CM_CLIENT_H
