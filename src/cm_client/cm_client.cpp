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
 * cm_client.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_client/cm_client.cpp
 *
 * -------------------------------------------------------------------------
 */
#include <pthread.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/unistd.h>
#include "securec.h"
#include "c.h"
#include "cm/cm_elog.h"
#include "cm_client.h"

ClientCtx *g_clientCtx = NULL;
LockFlag *g_lockFlag = NULL;
InitFlag *g_initFlag = NULL;
bool g_isClientInit = false;

static char g_resName[CM_MAX_RES_NAME] = {0};
static ConnAgent *g_agentConnect = NULL;
static bool g_shutdownClient = false;
static SendMsgQueue *g_sendMsg = NULL;
static OneResStatList *g_clientStatusList = NULL;
static volatile bool g_needReconnect = false;
#define CLUSTER_MANUAL_PAUSE "cluster_manual_pause"
char g_manualPausePath[MAX_PATH_LEN];

static pthread_t *g_conThreadId = NULL;
static pthread_t *g_sendThreadId = NULL;
static pthread_t *g_recvThreadId = NULL;

bool &GetIsClientInit()
{
    return g_isClientInit;
}

LockFlag *GetLockFlag()
{
    return g_lockFlag;
}

InitFlag *GetInitFlag()
{
    return g_initFlag;
}

OneResStatList *GetClientStatusList()
{
    return g_clientStatusList;
}

static timespec GetMutexTimeout(time_t timeout)
{
    struct timespec releaseTime = { 0, 0 };
    (void)clock_gettime(CLOCK_MONOTONIC, &releaseTime);
    releaseTime.tv_sec = releaseTime.tv_sec + timeout;

    return releaseTime;
}

static inline status_t CmClientSendMsg(char *buf, size_t remainSize)
{
    (void)pthread_rwlock_rdlock(&g_agentConnect->rwlock);
    status_t st = TcpSendMsg(g_agentConnect->sock, buf, remainSize);
    (void)pthread_rwlock_unlock(&g_agentConnect->rwlock);

    return st;
}

static inline status_t CmClientRecvMsg(char *buf, size_t remainSize)
{
    (void)pthread_rwlock_rdlock(&g_agentConnect->rwlock);
    status_t st = TcpRecvMsg(g_agentConnect->sock, buf, remainSize);
    (void)pthread_rwlock_unlock(&g_agentConnect->rwlock);

    return st;
}

static inline void CmClientCloseSocket()
{
    (void)pthread_rwlock_wrlock(&g_agentConnect->rwlock);
    if (g_agentConnect->sock != CLIENT_INVALID_SOCKET) {
        (void)close(g_agentConnect->sock);
        g_agentConnect->sock = CLIENT_INVALID_SOCKET;
    }
    (void)pthread_rwlock_unlock(&g_agentConnect->rwlock);
}

void SendMsgApi(char *msgPtr, size_t msgLen)
{
    MsgPackage msg = {msgPtr, msgLen};
    (void)pthread_mutex_lock(&g_sendMsg->lock);
    g_sendMsg->sendQueue.push_back(msg);
    (void)pthread_mutex_unlock(&g_sendMsg->lock);
    (void)pthread_cond_signal(&g_sendMsg->cond);
}

status_t SendInitMsg(uint32 instanceId, const char *resName)
{
    ClientInitMsg *initMsg = (ClientInitMsg*) malloc(sizeof(ClientInitMsg));
    if (initMsg == NULL) {
        write_runlog(ERROR, "Out of memory, client create init msg!\n");
        return CM_ERROR;
    }
    errno_t rc = memset_s(initMsg, sizeof(ClientInitMsg), 0, sizeof(ClientInitMsg));
    securec_check_errno(rc, (void)rc);
    initMsg->head.msgVer = CM_CLIENT_MSG_VER;
    initMsg->head.msgType = MSG_CLIENT_AGENT_INIT_DATA;
    initMsg->resInfo.resInstanceId = instanceId;
    rc = strcpy_s(initMsg->resInfo.resName, CM_MAX_RES_NAME, resName);
    securec_check_errno(rc, (void)rc);

    SendMsgApi((char*)initMsg, sizeof(ClientInitMsg));

    return CM_SUCCESS;
}

void SendHeartBeatMsg()
{
    ClientHbMsg *hbMsg = (ClientHbMsg*)malloc(sizeof(ClientHbMsg));
    if (hbMsg == NULL) {
        write_runlog(ERROR, "out of memory, SendHeartBeatMsg.\n");
        return;
    }
    errno_t rc = memset_s(hbMsg, sizeof(ClientHbMsg), 0, sizeof(ClientHbMsg));
    securec_check_errno(rc, (void)rc);
    hbMsg->head.msgVer = CM_CLIENT_MSG_VER;
    hbMsg->head.msgType = MSG_CLIENT_AGENT_HEARTBEAT;
    hbMsg->version = g_clientStatusList->version;

    SendMsgApi((char*)hbMsg, sizeof(ClientHbMsg));
}

static inline void ConnectSetTimeout(const ConnAgent *con)
{
    struct timeval tv = { 0, 0 };

    tv.tv_sec = CM_TCP_TIMEOUT;
    (void)setsockopt(con->sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(tv));
    (void)setsockopt(con->sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv));
}

static void ConnectClose()
{
    if (g_agentConnect->isClosed) {
        return;
    }

    CmClientCloseSocket();
    g_agentConnect->isClosed = true;

    (void)pthread_mutex_lock(&g_sendMsg->lock);
    while (!g_sendMsg->sendQueue.empty()) {
        free(g_sendMsg->sendQueue.front().msgPtr);
        g_sendMsg->sendQueue.pop_front();
    }
    (void)pthread_mutex_unlock(&g_sendMsg->lock);

    (void)pthread_mutex_lock(&g_initFlag->lock);
    g_initFlag->initSuccess = false;
    (void)pthread_mutex_unlock(&g_initFlag->lock);

    write_runlog(LOG, "client close connect with cm agent.\n");
}

static void ConnectCreate(ConnAgent *con)
{
    char homePath[MAX_PATH_LEN] = {0};
    char serverPath[MAX_PATH_LEN] = {0};
    SockAddr remoteSock{};

    if (!con->isClosed) {
        write_runlog(LOG, "Create connect failed, because connect has been created.\n");
        return;
    }
    if (GetHomePath(homePath, sizeof(homePath)) != 0) {
        return;
    }
    errno_t rc = snprintf_s(serverPath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/%s", homePath, CM_DOMAIN_SOCKET);
    securec_check_intval(rc, (void)rc);

    con->sock = (int)socket(AF_UNIX, SOCK_STREAM, 0);
    if (con->sock == CLIENT_INVALID_SOCKET) {
        write_runlog(ERROR, "Creat connect socket failed.\n");
        return;
    }

    ConnectSetTimeout(con);

    remoteSock.addrLen = sizeof(remoteSock.addr);
    rc = memset_s(&remoteSock.addr, remoteSock.addrLen, 0, remoteSock.addrLen);
    securec_check_errno(rc, (void)rc);

    remoteSock.addr.sun_family = AF_UNIX;
    rc = strcpy_s(remoteSock.addr.sun_path, sizeof(remoteSock.addr.sun_path), serverPath);
    securec_check_errno(rc, (void)rc);

    int ret = connect(con->sock, (struct sockaddr *)&remoteSock.addr, remoteSock.addrLen);
    if (ret < 0) {
        write_runlog(ERROR, "Client connect to agent error, ret=%d, errno=%d.\n", ret, errno);
        (void)close(con->sock);
        con->sock = CLIENT_INVALID_SOCKET;
        return;
    }
    // create connect success
    (void)clock_gettime(CLOCK_MONOTONIC, &con->recvTime);
    con->isClosed = false;
}

void *ConnectAgentMain(void *arg)
{
    thread_name = "CONN_AGENT";
    write_runlog(LOG, "connect agent thread start.\n");

    struct timespec currentTime = { 0, 0 };
    struct timespec lastReportTime = { 0, 0 };
    for (;;) {
        if (g_shutdownClient) {
            write_runlog(LOG, "exit conn agent thread.\n");
            ConnectClose();
            break;
        }
        if (g_agentConnect->isClosed) {
            write_runlog(LOG, "cm_client connect to cm_agent start.\n");
            ConnectCreate(g_agentConnect);
            if (g_agentConnect->isClosed) {
                write_runlog(ERROR, "cm_client connect to cm_agent failed, retry.\n");
                (void)usleep(CLIENT_CHECK_CONN_INTERVAL);
                continue;
            }
            g_needReconnect = false;
            (void)clock_gettime(CLOCK_MONOTONIC, &lastReportTime);
            if (!g_isClientInit) {
                write_runlog(LOG, "cm_client connect to cm_agent success.\n");
                continue;
            }
            bool isSuccess = SendInitMsgAndGetResult(g_resName, g_agentConnect->resInstanceId);
            if (!isSuccess) {
                write_runlog(ERROR, "cm_client init failed, close the new connect.\n");
                ConnectClose();
            }
        } else {
            if (g_needReconnect) {
                write_runlog(LOG, "need reconnect, close connect.\n");
                ConnectClose();
                continue;
            }
            (void)clock_gettime(CLOCK_MONOTONIC, &currentTime);
            if ((currentTime.tv_sec - lastReportTime.tv_sec) >= 1 && g_initFlag->initSuccess) {
                SendHeartBeatMsg();
                (void)clock_gettime(CLOCK_MONOTONIC, &lastReportTime);
            }
            if ((currentTime.tv_sec - g_agentConnect->recvTime.tv_sec) >= HEARTBEAT_TIMEOUT) {
                write_runlog(ERROR, "recv agent heartbeat timeout(%ds), close connect.\n", HEARTBEAT_TIMEOUT);
                ConnectClose();
                continue;
            }
        }
        (void)usleep(CLIENT_CHECK_CONN_INTERVAL);
    }

    return NULL;
}

status_t CreateConnectAgentThread()
{
    int err;
    if ((err = pthread_create(g_conThreadId, NULL, ConnectAgentMain, NULL)) != 0) {
        write_runlog(ERROR, "fail to create connect agent thread, err=%d.\n", err);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static bool NeedSendMsgToAgent()
{
    (void)pthread_mutex_lock(&g_sendMsg->lock);
    if (g_sendMsg->sendQueue.empty()) {
        const struct timespec releaseTime = GetMutexTimeout(CLIENT_RES_DATA_TIMEOUT);
        (void)pthread_cond_timedwait(&g_sendMsg->cond, &g_sendMsg->lock, &releaseTime);
    }
    if (g_sendMsg->sendQueue.empty()) {
        write_runlog(LOG, "no msg need send more than %d s.\n", CLIENT_RES_DATA_TIMEOUT);
        (void)pthread_mutex_unlock(&g_sendMsg->lock);
        return false;
    }

    (void)pthread_mutex_unlock(&g_sendMsg->lock);
    return true;
}

void SendOneMsgToAgent()
{
    (void)pthread_mutex_lock(&g_sendMsg->lock);
    if (g_sendMsg->sendQueue.empty()) {
        (void)pthread_mutex_unlock(&g_sendMsg->lock);
        return;
    }
    MsgPackage msgPkg = g_sendMsg->sendQueue.front();
    g_sendMsg->sendQueue.pop_front();
    (void)pthread_mutex_unlock(&g_sendMsg->lock);

    if (msgPkg.msgPtr == NULL) {
        write_runlog(LOG, "msg in sendQueue is null, msgLen=%zu.\n", msgPkg.msgLen);
        return;
    }

    if (CmClientSendMsg(msgPkg.msgPtr, msgPkg.msgLen) != CM_SUCCESS) {
        write_runlog(ERROR, "client send msg to agent failed!\n");
        g_needReconnect = true;
        (void)usleep(CLIENT_CHECK_CONN_INTERVAL);
    }
    free(msgPkg.msgPtr);
}

void *SendMsgToAgentMain(void *arg)
{
    thread_name = "SEND_MSG";
    write_runlog(LOG, "send msg to agent thread start.\n");

    for (;;) {
        if (g_shutdownClient) {
            write_runlog(LOG, "exit send msg thread.\n");
            break;
        }
        if (g_agentConnect->isClosed) {
            (void)usleep(CLIENT_SEND_CHECK_INTERVAL);
            continue;
        }

        if (NeedSendMsgToAgent()) {
            SendOneMsgToAgent();
        }
    }

    return NULL;
}

status_t CreateSendMsgThread()
{
    int err;
    if ((err = pthread_create(g_sendThreadId, NULL, SendMsgToAgentMain, NULL)) != 0) {
        write_runlog(ERROR, "failed to create send msg thread, err=%d\n", err);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t RecvInitAckProcess()
{
    InitResult result = {0};

    if (CmClientRecvMsg((char*)&result, sizeof(InitResult)) != CM_SUCCESS) {
        write_runlog(ERROR, "cm_client recv init ack from agent fail or timeout.\n");
        return CM_ERROR;
    }

    if (g_initFlag->initSuccess) {
        write_runlog(LOG, "client has init, can't process init ack again.\n");
        return CM_SUCCESS;
    }

    if (result.isSuccess) {
        write_runlog(LOG, "client init success.\n");
    } else {
        write_runlog(ERROR, "client init fail.\n");
    }
    (void)pthread_mutex_lock(&g_initFlag->lock);
    g_initFlag->initSuccess = result.isSuccess;
    (void)pthread_mutex_unlock(&g_initFlag->lock);
    (void)pthread_cond_signal(&g_initFlag->cond);

    return CM_SUCCESS;
}

static status_t RecvResStatusListProcess(int isNotifyChange)
{
    OneResStatList tmpStatList = {0};

    if (CmClientRecvMsg((char*)&tmpStatList, sizeof(OneResStatList)) != CM_SUCCESS) {
        write_runlog(ERROR, "recv status list from agent fail.\n");
        return CM_ERROR;
    }

    if (!g_initFlag->initSuccess) {
        write_runlog(LOG, "client has not init, can't refresh status list.\n");
        return CM_SUCCESS;
    }

    if (g_clientStatusList->version == tmpStatList.version) {
        write_runlog(DEBUG1, "same version(%llu).\n", g_clientStatusList->version);
        return CM_SUCCESS;
    }

    errno_t rc = memcpy_s(g_clientStatusList, sizeof(OneResStatList), &tmpStatList, sizeof(OneResStatList));
    securec_check_errno(rc, (void)rc);
    if (isNotifyChange == STAT_CHANGED) {
        g_agentConnect->callback();
    }
    write_runlog(LOG, "resName(%s) version=%llu\n", g_clientStatusList->resName, g_clientStatusList->version);
    for (uint32 i = 0; i < g_clientStatusList->instanceCount; ++i) {
        write_runlog(LOG, "nodeId(%u),cmInstId=%u,resInstId=%u,isWork=%u,status=%u\n",
            g_clientStatusList->resStat[i].nodeId,
            g_clientStatusList->resStat[i].cmInstanceId,
            g_clientStatusList->resStat[i].resInstanceId,
            g_clientStatusList->resStat[i].isWorkMember,
            g_clientStatusList->resStat[i].status);
    }

    return CM_SUCCESS;
}

static status_t RecvResLockAckProcess()
{
    LockResult result = {0};

    if (CmClientRecvMsg((char*)&result, sizeof(LockResult)) != CM_SUCCESS) {
        write_runlog(ERROR, "client recv res data from agent fail or timeout.\n");
        return CM_ERROR;
    }

    (void)pthread_mutex_lock(&g_lockFlag->condLock);
    g_lockFlag->ownerId = result.lockOwner;
    g_lockFlag->error = result.error;
    (void)pthread_mutex_unlock(&g_lockFlag->condLock);
    (void)pthread_cond_signal(&g_lockFlag->cond);

    return CM_SUCCESS;
}

static void SetLockApiFailed()
{
    (void)pthread_mutex_lock(&g_lockFlag->condLock);
    g_lockFlag->error = (uint32)CM_RES_CLIENT_CONNECT_ERR;
    (void)pthread_mutex_unlock(&g_lockFlag->condLock);
    (void)pthread_cond_signal(&g_lockFlag->cond);
}

static status_t RecvCmaConnClose()
{
    CmaNotifyClient cmaMsg = {0};

    if (CmClientRecvMsg((char*)&cmaMsg, sizeof(CmaNotifyClient)) != CM_SUCCESS) {
        write_runlog(ERROR, "[%s] client recv msg agent fail or timeout.\n", __FUNCTION__);
        return CM_ERROR;
    }

    if (cmaMsg.isCmaConnClose) {
        write_runlog(LOG, "the CMA and CMS are disconnected.\n");
        SetLockApiFailed();
    }

    return CM_SUCCESS;
}

static status_t RecvMsgFromAgent()
{
    MsgHead msgHead = {0};
    if (CmClientRecvMsg((char*)&msgHead, sizeof(MsgHead)) != CM_SUCCESS) {
        write_runlog(ERROR, "client recv msg from agent fail or timeout.\n");
        return CM_ERROR;
    }

    switch (msgHead.msgType) {
        case MSG_AGENT_CLIENT_INIT_ACK:
            CM_RETURN_IFERR(RecvInitAckProcess());
            break;
        case MSG_AGENT_CLIENT_HEARTBEAT_ACK:
            break;
        case MSG_AGENT_CLIENT_RES_STATUS_LIST:
            CM_RETURN_IFERR(RecvResStatusListProcess(NO_STAT_CHANGED));
            break;
        case MSG_AGENT_CLIENT_RES_STATUS_CHANGE:
            CM_RETURN_IFERR(RecvResStatusListProcess(STAT_CHANGED));
            break;
        case MSG_CM_RES_LOCK_ACK:
            CM_RETURN_IFERR(RecvResLockAckProcess());
            break;
        case MSG_AGENT_CLIENT_NOTIFY_CONN_CLOSE:
            CM_RETURN_IFERR(RecvCmaConnClose());
            break;
        default:
            write_runlog(ERROR, "recv unknown msg, msgType(%u).\n", msgHead.msgType);
            return CM_ERROR;
    }

    // update heartbeat
    (void)clock_gettime(CLOCK_MONOTONIC, &g_agentConnect->recvTime);
    return CM_SUCCESS;
}

void *RecvMsgFromAgentMain(void *arg)
{
    thread_name = "RECV_MSG";
    write_runlog(LOG, "recv msg thread start.\n");

    for (;;) {
        if (g_shutdownClient) {
            write_runlog(LOG, "exit recv msg thread.\n");
            break;
        }
        if (g_agentConnect->isClosed) {
            (void)usleep(CLIENT_CHECK_CONN_INTERVAL);
            continue;
        }
        if (RecvMsgFromAgent() != CM_SUCCESS) {
            g_needReconnect = true;
            (void)usleep(CLIENT_CHECK_CONN_INTERVAL);
        }
    }

    return NULL;
}

status_t CreateRecvMsgThread()
{
    int err;
    if ((err = pthread_create(g_recvThreadId, NULL, RecvMsgFromAgentMain, NULL)) != 0) {
        write_runlog(ERROR, "failed to create recv msg thread, error=%d.\n", err);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t InitLogFile()
{
    char logPath[MAX_PATH_LEN] = {0};
    char clientLogPath[MAX_PATH_LEN] = {0};

    prefix_name = g_resName;

    (void)syscalllockInit(&g_cmEnvLock);
    if (cm_getenv("GAUSSLOG", logPath, sizeof(logPath)) != EOK) {
        (void)printf(_("cm_client get GAUSSLOG dir failed\n"));
        return CM_ERROR;
    }
    check_input_for_security(logPath);
    int ret = snprintf_s(clientLogPath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/cm/cm_client", logPath);
    securec_check_intval(ret, (void)ret);
    if (access(clientLogPath, F_OK) != 0) {
        (void)mkdir(clientLogPath, S_IRWXU);
    }

    if (SetLogFilePath(clientLogPath) == -1) {
        return CM_ERROR;
    }

    write_runlog(LOG, "init cm_client log file (%s) success.\n", clientLogPath);

    return CM_SUCCESS;
}

inline void EmptyCallback()
{
    write_runlog(LOG, "client init null call back func.\n");
}

static inline void InitAgentConnect(uint32 instanceId, CmNotifyFunc func)
{
    errno_t rc = memset_s(g_agentConnect, sizeof(ConnAgent), 0, sizeof(ConnAgent));
    securec_check_errno(rc, (void)rc);
    g_agentConnect->sock = CLIENT_INVALID_SOCKET;
    g_agentConnect->isClosed = true;
    g_agentConnect->resInstanceId = instanceId;
    g_agentConnect->callback = (func == NULL) ? EmptyCallback : func;
    (void)pthread_rwlock_init(&g_agentConnect->rwlock, NULL);
}

static void InitGlobalVariable(const char *resName)
{
    AllocClientMemory();

    errno_t rc = strcpy_s(g_resName, CM_MAX_RES_NAME, resName);
    securec_check_errno(rc, (void)rc);

    rc = memset_s(g_clientStatusList, sizeof(OneResStatList), 0, sizeof(OneResStatList));
    securec_check_errno(rc, (void)rc);

    g_initFlag->initSuccess = false;
    (void)pthread_mutex_init(&g_initFlag->lock, NULL);
    InitPthreadCondMonotonic(&g_initFlag->cond);

    g_sendMsg->sendQueue.clear();
    (void)pthread_mutex_init(&g_sendMsg->lock, NULL);
    InitPthreadCondMonotonic(&g_sendMsg->cond);

    (void)pthread_mutex_init(&g_lockFlag->condLock, NULL);
    (void)pthread_mutex_init(&g_lockFlag->optLock, NULL);
    InitPthreadCondMonotonic(&g_lockFlag->cond);
}

status_t PreInit(uint32 instanceId, const char *resName, CmNotifyFunc func, bool *isFirstInit)
{
    get_pause_path();
    if (isFirstInit) {
        InitGlobalVariable(resName);
        CM_RETURN_IFERR(InitLogFile());
        *isFirstInit = false;
    }
    InitAgentConnect(instanceId, func);
    g_shutdownClient = false;

    return CM_SUCCESS;
}

static void WaitClientThreadClose(pthread_t *tid)
{
    if (*tid == 0) {
        write_runlog(LOG, "Thread not exist, can't close.\n");
        return;
    }

    (void)pthread_join(*tid, NULL);
    *tid = 0;
}

void ShutdownClient()
{
    g_shutdownClient = true;
    // weak up send msg thread
    (void)pthread_cond_signal(&g_sendMsg->cond);

    WaitClientThreadClose(g_conThreadId);
    WaitClientThreadClose(g_sendThreadId);
    WaitClientThreadClose(g_recvThreadId);

    write_runlog(LOG, "shutdown client over.\n");
}

void AllocClientMemory()
{
    g_clientCtx = new ClientCtx();
    g_lockFlag = &g_clientCtx->lockFlag;
    g_initFlag = &g_clientCtx->initFlag;
    g_agentConnect = &g_clientCtx->agentConnect;
    g_clientStatusList = &g_clientCtx->clientStatusList;
    g_conThreadId = &g_clientCtx->conThreadId;
    g_sendThreadId = &g_clientCtx->sendThreadId;
    g_recvThreadId = &g_clientCtx->recvThreadId;
    g_sendMsg = &g_clientCtx->sendMsg;
}

void FreeClientMemory()
{
    delete g_clientCtx;
    g_clientCtx = NULL;
}

bool SendInitMsgAndGetResult(const char *resName, uint32 instId)
{
    (void)pthread_mutex_lock(&g_initFlag->lock);
    g_initFlag->initSuccess = false;
    if (SendInitMsg(instId, resName) != CM_SUCCESS) {
        (void)pthread_mutex_unlock(&g_initFlag->lock);
        return false;
    }

    struct timespec releaseTime = GetMutexTimeout(CLIENT_RES_DATA_TIMEOUT);
    (void)pthread_cond_timedwait(&g_initFlag->cond, &g_initFlag->lock, &releaseTime);
    bool result = g_initFlag->initSuccess;
    (void)pthread_mutex_unlock(&g_initFlag->lock);

    return result;
}

ClientLockResult SendLockMsgAndWaitResult(char *msgPtr, uint32 msgLen)
{
    (void)pthread_mutex_lock(&g_lockFlag->optLock);

    (void)pthread_mutex_lock(&g_lockFlag->condLock);
    g_lockFlag->error = (uint32)CM_RES_CLIENT_TIMEOUT;
    SendMsgApi(msgPtr, msgLen);
    struct timespec releaseTime = GetMutexTimeout(CLIENT_RES_DATA_TIMEOUT);
    (void)pthread_cond_timedwait(&g_lockFlag->cond, &g_lockFlag->condLock, &releaseTime);
    ClientLockResult result = {g_lockFlag->error, g_lockFlag->ownerId};
    (void)pthread_mutex_unlock(&g_lockFlag->condLock);

    (void)pthread_mutex_unlock(&g_lockFlag->optLock);

    return result;
}

void get_pause_path()
{
    char exec_path[MAX_PATH_LEN] = {0};
    errno_t rc;
    int rcs;

    rc = memset_s(g_manualPausePath, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    if (GetHomePath(exec_path, sizeof(exec_path)) != 0) {
        (void)fprintf(stderr, "Get GAUSSHOME failed, please check.\n");
        return;
    } else {
        check_input_for_security(exec_path);
        rcs = snprintf_s(
            g_manualPausePath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/%s", exec_path, CLUSTER_MANUAL_PAUSE);
        securec_check_intval(rcs, (void)rcs);
    }
}