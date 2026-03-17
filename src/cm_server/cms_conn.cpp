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
 * cms_conn.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_server/cms_conn.cpp
 *
 * -------------------------------------------------------------------------
 */
#include <map>
#include <sys/eventfd.h>
#include <sys/prctl.h>
#include <sys/epoll.h>
#include "cm/cm_elog.h"
#include "cm_debug.h"
#include "cms_common.h"
#include "cms_global_params.h"
#include "cms_conn.h"
#ifdef KRB5
#include "gssapi/gssapi_krb5.h"
#endif
#include "cms_ddb_adapter.h"
#include "cm_msg_buf_pool.h"
#include "cm_error.h"
#include "cms_process_messages.h"
#include "cm_util.h"

static const int EPOLL_TIMEOUT = 1000;
static const uint32 ALL_AGENT_NODE_ID = 0xffffffff;
static const uint32 MAX_MSG_BUF_POOL_SIZE = 102400;
static const uint32 MAX_MSG_BUF_POOL_COUNT = 200;
static const uint32 MAX_MSG_IN_QUE = 100;

struct DdbPreAgentCon {
    uint32 connCount;
    char conFlag[DDB_MAX_CONNECTIONS];
};

using MapConns = std::map<uint64, CM_Connection*>;

struct TempConns {
    MapConns tempConns;
    pthread_mutex_t lock;
};

using CM_Connections = struct CM_Connections_t {
    uint32 count;
    uint32 max_node_id;
    CM_Connection* connections[CM_MAX_CONNECTIONS + MAXLISTEN];
    pthread_rwlock_t lock;
} ;

TempConns g_tempConns;
CM_Connections gConns;
DdbPreAgentCon g_preAgentCon = {0};
uint8 g_msgProcFlag[MSG_CM_TYPE_CEIL];
int32 InitConn()
{
    MsgPoolInit(MAX_MSG_BUF_POOL_SIZE, MAX_MSG_BUF_POOL_COUNT);

    int ret = pthread_rwlock_init(&(gConns.lock), NULL);
    if (ret != 0) {
        write_runlog(LOG, "init CM Connections lock failed !\n");
        return -1;
    }
    errno_t rc = memset_s(&g_preAgentCon, sizeof(DdbPreAgentCon), 0, sizeof(DdbPreAgentCon));
    securec_check_errno(rc, (void)rc);

    rc = memset_s(g_msgProcFlag, sizeof(g_msgProcFlag), 0, sizeof(g_msgProcFlag));
    securec_check_errno(rc, (void)rc);

    g_msgProcFlag[MSG_CTL_CM_SWITCHOVER_FAST] |= MPF_DO_SWITCHOVER;
    g_msgProcFlag[MSG_AGENT_CM_COORDINATE_INSTANCE_STATUS] |= MPF_IS_CN_REPORT;

    return 0;
}

/*
 * ConnCreate -- create a local connection data structure
 */
Port* ConnCreate(int serverFd)
{
    Port *port = (Port*)calloc(1, sizeof(Port));
    if (port == NULL) {
        write_runlog(FATAL, "out of memory\n");
        FreeNotifyMsg();
        exit(1);
    }

    errno_t rc = memset_s(port, sizeof(Port), 0, sizeof(Port));
    securec_check_errno(rc, (void)rc);

    port->pipe.link.tcp.closed = CM_TRUE;
    port->pipe.link.tcp.sock = CS_INVALID_SOCKET;
    port->pipe.link.ssl.tcp.closed = CM_TRUE;
    port->pipe.link.ssl.tcp.sock = CS_INVALID_SOCKET;
    port->pipe.link.ssl.ssl_ctx = NULL;
    port->pipe.link.ssl.ssl_sock = NULL;

    if (StreamConnection(serverFd, port) != STATUS_OK) {
        if (port->sock >= 0) {
            StreamClose(port->sock);
        }
        ConnFree(port);
        port = NULL;
    }

    return port;
}

void set_socket_timeout(const Port* my_port, int timeout)
{
    struct timeval t = {timeout, 0};
    socklen_t len = sizeof(struct timeval);
    if (setsockopt(my_port->sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&t, len) < 0) {
        write_runlog(LOG, "setsockopt set SO_RCVTIMEO=%d failed.", timeout);
    }
}

void ConnCloseAndFree(CM_Connection* con)
{
    if (con == NULL) {
        write_runlog(DEBUG1, "The input connection pointer is NULL: Function:%s.\n", "ConnCloseAndFree");
        return;
    } else if (con->port == NULL) {
        write_runlog(DEBUG1, "The input connection port pointer is NULL: Function:%s.\n", "ConnCloseAndFree");
    } else {
        if (con->port->remote_type == CM_CTL || g_node_num < con->port->node_id) {
            write_runlog(DEBUG1,
                "close connection sock [fd=%d], type is %d, nodeid %u.\n",
                con->port->sock,
                con->port->remote_type,
                con->port->node_id);
        } else {
            write_runlog(LOG,
                "close connection sock [fd=%d], type is %d, nodeid %u.\n",
                con->port->sock,
                con->port->remote_type,
                con->port->node_id);
        }

        // prevent the sock will be closed again
        CsDisconnect(&(con->port->pipe), con->port->remote_type, &(con->port->sock));
        if (con->port->sock >= 0) {
            StreamClose(con->port->sock);
        }
        FREE_AND_RESET(con->port->user_name);

        FREE_AND_RESET(con->port->node_name);

        FREE_AND_RESET(con->port->remote_host);

        FREE_AND_RESET(con->port);
    }

    con->fd = INVALIDFD;

    if (con->inBuffer != NULL) {
        CM_freeStringInfo(con->inBuffer);
        FREE_AND_RESET(con->inBuffer);
    }
}

void RemoveTempConnection(CM_Connection *con);

void RemoveConnection(CM_Connection* con)
{
    if (con == NULL) {
        return;
    }

    /* for check cma and cms conn */
    if (con->port == NULL || con->port->node_id == CM_MAX_CONNECTIONS * 2) {
        ConnCloseAndFree(con);
        return;
    }

    if (con->port->remote_type == CM_AGENT) {
        (void)pthread_rwlock_wrlock(&gConns.lock);

        Assert(con->port->node_id < CM_MAX_CONNECTIONS);

        if (con == gConns.connections[con->port->node_id]) {
            gConns.connections[con->port->node_id] = NULL;
            gConns.count--;
            if (g_preAgentCon.conFlag[con->port->node_id] == 1) {
                --g_preAgentCon.connCount;
                g_preAgentCon.conFlag[con->port->node_id] = 0;
            }
        }

        if (con->connSeq != 0) {
            RemoveTempConnection(con);
        }
        (void)pthread_rwlock_unlock(&gConns.lock);
    } else if (con->port->remote_type == CM_CTL) {
        RemoveTempConnection(con);
    }

    ConnCloseAndFree(con);
}

void DisableRemoveConn(CM_Connection* con)
{
    EventDel(con->epHandle, con);
    RemoveConnection(con);
}

void RemoveConnAfterSendMsgFailed(CM_Connection* con)
{
    if (con->port->remote_type != CM_SERVER) {
        DisableRemoveConn(con);
    }
}

void AddCMAgentConnection(CM_Connection *con)
{
    Assert(con != NULL);
    (void)pthread_rwlock_wrlock(&gConns.lock);
    if (gConns.connections[con->port->node_id] != NULL) {
        write_runlog(ERROR, "A same cm_agent connected from nodeId %u.\n", con->port->node_id);
        // if free old cm_agent conn will core for other thread maybe use this conn now.
        // old cm_agent conn will be free by other thread when read or send msg from this conn failed.
        gConns.count--;
    }

    gConns.connections[con->port->node_id] = con;
    gConns.count++;

    if (gConns.max_node_id < con->port->node_id) {
        gConns.max_node_id = con->port->node_id;
    }

    write_runlog(LOG, "cm_agent connected from nodeId %u, conn count=%u.\n", con->port->node_id, gConns.count);
    if (gConns.count == 1) {
        write_runlog(LOG, "pre conn count reset when add conn.\n");
        g_preAgentCon.connCount = 0;
        errno_t rc = memset_s(g_preAgentCon.conFlag, sizeof(g_preAgentCon.conFlag), 0, sizeof(g_preAgentCon.conFlag));
        securec_check_errno(rc, (void)pthread_rwlock_unlock(&gConns.lock));
    }
    (void)pthread_rwlock_unlock(&gConns.lock);
    con->notifyCn = setNotifyCnFlagByNodeId(con->port->node_id);
}

void AddTempConnection(CM_Connection *con)
{
    (void)pthread_mutex_lock(&g_tempConns.lock);
    (void)g_tempConns.tempConns.insert(make_pair(con->connSeq, con));
    (void)pthread_mutex_unlock(&g_tempConns.lock);
    write_runlog(DEBUG5, "AddTempConnection:connSeq=%lu.\n", con->connSeq);
}

void RemoveTempConnection(CM_Connection *con)
{
    (void)pthread_mutex_lock(&g_tempConns.lock);
    (void)g_tempConns.tempConns.erase(con->connSeq);
    (void)pthread_mutex_unlock(&g_tempConns.lock);
    write_runlog(DEBUG5, "RemoveTempConnection:connSeq=%lu.\n", con->connSeq);
}

CM_Connection* GetTempConnection(uint64 connSeq)
{
    CM_Connection *con = NULL;
    (void)pthread_mutex_lock(&g_tempConns.lock);
    MapConns::iterator it = g_tempConns.tempConns.find(connSeq);
    if (it != g_tempConns.tempConns.end()) {
        con = it->second;
    }
    (void)pthread_mutex_unlock(&g_tempConns.lock);

    write_runlog(DEBUG5, "GetTempConnection:connSeq=%lu\n", connSeq);

    return con;
}

int cm_server_flush_msg(CM_Connection* con)
{
    int ret = 0;
    if (con != NULL && con->fd >= 0) {
        ret = pq_flush(con->port);
        if (ret != 0) {
            write_runlog(ERROR, "pq_flush failed, return ret=%d\n", ret);
        }
    }
    return ret;
}

int CMHandleCheckAuth(CM_Connection* con)
{
    int cmAuth;
#ifdef KRB5
    if (con->gss_check) {
        return 0;
    }
#endif // KRB5
    char envPath[MAX_PATH_LEN] = {0};
    if (con->port == NULL) {
        write_runlog(ERROR, "port is null.\n");
        return -1;
    }

    /* 2. Prepare gss environment. */
    if (cmserver_getenv("KRB5_KTNAME", envPath, (uint32)sizeof(envPath), DEBUG5) != EOK) {
        /* check whether set guc parameter gtm_krb_server_keyfile or not */
        if (cm_krb_server_keyfile == NULL || strlen(cm_krb_server_keyfile) == 0) {
            write_runlog(ERROR, "out of memory, failed to malloc memory.\n");
            return -1;
        }
        int rc = memset_s(envPath, MAX_PATH_LEN, 0, MAX_PATH_LEN);
        securec_check_errno(rc, (void)rc);
        rc = snprintf_s(envPath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "KRB5_KTNAME=%s", cm_krb_server_keyfile);
        securec_check_intval(rc, (void)rc);
        rc = putenv(envPath);
        if (rc != 0) {
            write_runlog(ERROR, "failed to putenv 'KRB5_KTNAME', return value: %d.\n", rc);
            return -1;
        }
        write_runlog(DEBUG1, "Set KRB5_KTNAME to %s.\n", envPath);
    }

#ifdef KRB5
    /* 3. Handle client GSS authentication message. */
    con->gss_ctx = GSS_C_NO_CONTEXT;
    con->gss_cred = GSS_C_NO_CREDENTIAL;
    OM_uint32 maj_stat = 0;
    OM_uint32 min_stat = 0;
    OM_uint32 lmin_s = 0;
    OM_uint32 gflags = 0;
    gss_buffer_desc gss_buf;
    char* krbconfig = NULL;

    do {
        /* Get the actual GSS token */
        if (pq_getmessage(con->port, con->inBuffer, CM_MAX_AUTH_TOKEN_LENGTH, false)) {
            return -1;
        }
        /* Map to GSSAPI style buffer */
        gss_buf.length = con->inBuffer->len;
        gss_buf.value = con->inBuffer->data;
        /* Clean the config cache and ticket cache set by hadoop remote read. */
        krb5_clean_cache_profile_path();
        /* Krb5 config file priority : setpath > env(MPPDB_KRB5_FILE_PATH) > default(/etc/krb5.conf). */
        krbconfig = gs_getenv_r("MPPDB_KRB5_FILE_PATH");
        if (krbconfig != NULL) {
            krb5_set_profile_path(krbconfig);
        }
        maj_stat = gss_accept_sec_context(&min_stat,
            &con->gss_ctx,
            con->gss_cred,
            &gss_buf,
            GSS_C_NO_CHANNEL_BINDINGS,
            &con->gss_name,
            NULL,
            &con->gss_outbuf,
            &gflags,
            NULL,
            NULL);

        /* Negotiation generated data to be sent to the client. */
        if (con->gss_outbuf.length > 0) {
            int ret = CmsSendAndFlushMsg(con, 'P', (char*)con->gss_outbuf.value, con->gss_outbuf.length);
            if (ret != 0) {
                RemoveConnAfterSendMsgFailed(con);
                write_runlog(ERROR, "[%s][line:%d] CmsSendAndFlushMsg fail.\n", __FUNCTION__, __LINE__);
            }
            if (ret != 0) {
                (void)gss_release_cred(&min_stat, &con->gss_cred);
                (void)gss_delete_sec_context(&lmin_s, &con->gss_ctx, GSS_C_NO_BUFFER);
                (void)gss_release_name(&lmin_s, &con->gss_name);
                if (con->gss_outbuf.value != NULL) {
                    FREE_AND_RESET(con->gss_outbuf.value);
                }
                write_runlog(ERROR, "line %d: accepting GSS security context failed.\n", __LINE__);
                return -1;
            }
        }

        /* Wrong status, report error here */
        if (maj_stat != GSS_S_COMPLETE && maj_stat != GSS_S_CONTINUE_NEEDED) {
            (void)gss_release_cred(&lmin_s, &con->gss_cred);
            (void)gss_delete_sec_context(&lmin_s, &con->gss_ctx, GSS_C_NO_BUFFER);
            (void)gss_release_name(&lmin_s, &con->gss_name);
            if (con->gss_outbuf.value != NULL) {
                FREE_AND_RESET(con->gss_outbuf.value);
            }
            write_runlog(ERROR, "line %d: accepting GSS security context failed.\n", __LINE__);
            return -1;
        }
    } while (maj_stat == GSS_S_CONTINUE_NEEDED); /* GSS_S_COMPLETE now */

    /* Release gss security credential */
    (void)gss_release_cred(&min_stat, &con->gss_cred);
    /* Release gss security context and name after server authentication finished */
    (void)gss_delete_sec_context(&min_stat, &con->gss_ctx, GSS_C_NO_BUFFER);
    /* Release gss_name and gss_buf */
    (void)gss_release_name(&min_stat, &con->gss_name);
    (void)gss_release_buffer(&lmin_s, &con->gss_outbuf);
#endif // KRB5
    /* Authentication succeed, send GTM_AUTH_REQ_OK */
    cmAuth = (int)htonl(CM_AUTH_REQ_OK);
    if (CmsSendAndFlushMsg(con, 'R', (char*)&cmAuth, sizeof(cmAuth)) != 0) {
        RemoveConnAfterSendMsgFailed(con);
        write_runlog(ERROR, "[%s][line:%d] CmsSendAndFlushMsg fail.\n", __FUNCTION__, __LINE__);
    }

    return 0;
}

/*
 * Initialise the masks for select() for the ports we are listening on.
 * Return the number of sockets to listen on.
 */
int initMasks(const int* listenSocket, fd_set* rmask)
{
    int maxSock = -1;
    int i;
    int fd;

    FD_ZERO(rmask);

    for (i = 0; i < MAXLISTEN; i++) {
        fd = listenSocket[i];
        if (fd == -1) {
            break;
        }
        FD_SET(fd, rmask);
        if (fd > maxSock) {
            maxSock = fd;
        }
    }

    return maxSock + 1;
}

/*
 * ConnFree -- free a local connection data structure
 */
void ConnFree(Port* conn)
{
    free(conn);
}

static void CloseAllConnections(CM_IOThread *thrinfo)
{
    CM_Connection* con = NULL;

    if (thrinfo->gotConnClose == 1) {
        /* left some time, other thread maybe use the mem of conn. */
        cm_sleep(1);
        bool findepollHandle = false;
        (void)pthread_rwlock_wrlock(&gConns.lock);
        write_runlog(LOG, "receive signal to close all the agent connections now, conn count is %u.\n", gConns.count);
        for (uint32 i = 0; i < gConns.max_node_id + 1; i++) {
            if (i % gIOThreads.count != thrinfo->id) {
                continue;
            }

            con = gConns.connections[i];
            if (con != NULL && thrinfo->epHandle == con->epHandle) {
                Assert(con->port->remote_type == CM_AGENT);

                EventDel(con->epHandle, con);
                Assert(con->port->node_id < CM_MAX_CONNECTIONS);
                gConns.connections[con->port->node_id] = NULL;
                gConns.count--;

                ConnCloseAndFree(con);
                FREE_AND_RESET(con);
                findepollHandle = true;
            }
        }
        if (gConns.count == 0 || g_HA_status->local_role == CM_SERVER_PRIMARY) {
            thrinfo->gotConnClose = 0;
            write_runlog(LOG, "reset close conn flag.\n");
        }
        (void)pthread_rwlock_unlock(&gConns.lock);
        if (!findepollHandle) {
            write_runlog(LOG, "can't get epollHandle %d.\n", thrinfo->epHandle);
        }
    }
}

void setBlockSigMask(sigset_t* block_signal)
{
    (void)sigfillset(block_signal);

#ifdef SIGTRAP
    (void)sigdelset(block_signal, SIGTRAP);
#endif
#ifdef SIGABRT
    (void)sigdelset(block_signal, SIGABRT);
#endif
#ifdef SIGILL
    (void)sigdelset(block_signal, SIGILL);
#endif
#ifdef SIGFPE
    (void)sigdelset(block_signal, SIGFPE);
#endif
#ifdef SIGSEGV
    (void)sigdelset(block_signal, SIGSEGV);
#endif
#ifdef SIGBUS
    (void)sigdelset(block_signal, SIGBUS);
#endif
#ifdef SIGSYS
    (void)sigdelset(block_signal, SIGSYS);
#endif
}

bool CanProcThisMsg(void *threadInfo, const char *msgData)
{
    const MsgRecvInfo *msg = (const MsgRecvInfo *)msgData;
    CM_WorkThread *thrinfo = (CM_WorkThread *)threadInfo;
    for (uint32 i = 0; i < gWorkThreads.count; i++) {
        if (gWorkThreads.threads[i].ProcConnID.remoteType == msg->connID.remoteType &&
            gWorkThreads.threads[i].ProcConnID.connSeq == msg->connID.connSeq &&
            gWorkThreads.threads[i].ProcConnID.agentNodeId == msg->connID.agentNodeId) {
            return false;
        }
    }

    thrinfo->ProcConnID = msg->connID;
    return true;
}

void* CM_WorkThreadMain(void* argp)
{
    sigset_t block_sig_set;

    CM_WorkThread* thrinfo = (CM_WorkThread*)argp;

    thread_name = (thrinfo->type == CM_AGENT) ? "AGENT_WORKER" : "CTL_WORKER";
    MsgSourceType src = (thrinfo->type == CM_AGENT) ? MsgSrcAgent : MsgSrcCtl;
    (void)prctl(PR_SET_NAME, thread_name);

    (void)pthread_detach(pthread_self());

    setBlockSigMask(&block_sig_set);

    write_runlog(LOG, "cmserver pool thread %lu starting, \n", thrinfo->tid);
    SetCanProcThisMsgFun(CanProcThisMsg);

    uint32 preMsgCount = 0;
    uint64 totalWaitTime = 0;
    uint64 totalProcTime = 0;
    MsgRecvInfo *msg = NULL;
    uint64 t0 = GetMonotonicTimeMs();

    uint32 ioThreadIdx = thrinfo->id % gIOThreads.count;
    CM_IOThread* ioThrInfo = &gIOThreads.threads[ioThreadIdx];

    for (;;) {
        if (got_stop == true) {
            write_runlog(LOG, "receive exit request in cm arbitrate.\n");
            cm_sleep(1);
            continue;
        }

        uint64 t1 = GetMonotonicTimeMs();
        thrinfo->isBusy = false;
        do {
            msg = (MsgRecvInfo*)(getRecvMsg((PriMsgQues*)ioThrInfo->recvMsgQue, src, 1, argp));
        } while (msg == NULL);
        uint64 t2 = GetMonotonicTimeMs();

        thrinfo->isBusy = true;
        write_runlog(DEBUG5,
            "get message from recv que:remote_type:%s,connSeq=%lu,agentNodeId=%u,qtype=%c,len=%d.\n",
            msg->connID.remoteType == CM_CTL ? "CM_CTL" : "CM_AGENT",
            msg->connID.connSeq,
            msg->connID.agentNodeId,
            msg->msg.qtype,
            msg->msg.len);

        cm_server_process_msg(msg);
        uint64 t3 = GetMonotonicTimeMs();
        thrinfo->ProcConnID.remoteType = 0;
        thrinfo->ProcConnID.connSeq = 0;
        thrinfo->ProcConnID.agentNodeId = 0;
        FreeBufFromMsgPool((void *)msg);
        msg = NULL;
        thrinfo->procMsgCount++;

        totalWaitTime += t2 - t1;
        totalProcTime += t3 - t2;

        if (t3 - t0 > MSG_TIME_FOR_LOG * CM_MS_COUNT_PER_SEC) {
            write_runlog(DEBUG5,
                "the thread process message:total count:%u,this time:%u,wait time=%lums,proc time=%lums\n",
                thrinfo->procMsgCount,
                thrinfo->procMsgCount - preMsgCount,
                totalWaitTime,
                totalProcTime);
            totalWaitTime = 0;
            totalProcTime = 0;
            t0 = t3;
            preMsgCount = thrinfo->procMsgCount;
        }
    }

    return thrinfo;
}

void pushMsgToQue(CM_IOThread *thrinfo, CM_Connection* con)
{
    uint32 totalFreeCount, totalAllocCount, freeCount, allocCount, typeCount;

    if (con->inBuffer->len < 0) {
        write_runlog(ERROR, "invalid message buffer length:%d\n", con->inBuffer->len);
        return;
    }

    uint32 allocLen = sizeof(MsgRecvInfo) + (uint32)con->inBuffer->len;
    MsgRecvInfo* msgInfo = (MsgRecvInfo*)AllocBufFromMsgPool(allocLen);
    if (msgInfo == NULL) {
        GetTotalBufInfo(&totalFreeCount, &totalAllocCount, &typeCount);
        GetTypeBufInfo(allocLen, &freeCount, &allocCount);

        write_runlog(LOG,
            "alloc memory for msg failed,totalFreeCount(%u), totalAllocCount(%u). this type(%u) "
            "freeCount(%u), allocCount(%u).\n",
            totalFreeCount, totalAllocCount, allocLen, freeCount, allocCount);
        return;
    }
    errno_t rc = memset_s(msgInfo, (size_t)allocLen, 0, (size_t)allocLen);
    securec_check_errno(rc, (void)rc);
    msgInfo->connID.remoteType = con->port->remote_type;
    msgInfo->msgProcFlag = 0;
    msgInfo->msg = *con->inBuffer;
    msgInfo->msg.data = (char*)&msgInfo->data[0];
    if (con->inBuffer->len > 0) {
        rc = memcpy_s(msgInfo->msg.data, (size_t)con->inBuffer->len, con->inBuffer->data, (size_t)con->inBuffer->len);
        securec_check_errno(rc, (void)rc);
    }
    msgInfo->connID.connSeq = con->connSeq;
    msgInfo->connID.agentNodeId = con->port->node_id;

    if (con->notifyCn == WAIT_TO_NOTFY_CN) {
        con->notifyCn = setNotifyCnFlagByNodeId(con->port->node_id);
    }

    write_runlog(DEBUG5,
        "push message to recv que:remote_type:%s,connSeq=%lu,agentNodeId=%u,qtype=%c,len=%d.\n",
        msgInfo->connID.remoteType == CM_CTL ? "CM_CTL" : "CM_AGENT",
        msgInfo->connID.connSeq,
        msgInfo->connID.agentNodeId,
        msgInfo->msg.qtype,
        msgInfo->msg.len);

    // push the message to the queue
    uint64 t1 = GetMonotonicTimeMs();
    msgInfo->connID.t1 = t1;
    if (con->port->remote_type == CM_CTL) {
        pushRecvMsg((PriMsgQues*)thrinfo->recvMsgQue, msgInfo, MsgSrcCtl);
    } else {
        pushRecvMsg((PriMsgQues*)thrinfo->recvMsgQue, msgInfo, MsgSrcAgent);
    }
    uint64 t2 = GetMonotonicTimeMs();
    thrinfo->pushRecvQueWaitTime += (uint32)(t2 - t1);
}

static bool checkMsg(CM_Connection* con)
{
    const cm_msg_type *msgTypePtr = (const cm_msg_type *)(CmGetmsgtype(con->inBuffer, (int)sizeof(cm_msg_type)));
    if (msgTypePtr == NULL) {
        return false;
    }

    int msgType = msgTypePtr->msg_type;
    if (msgType >= (int)MSG_CM_TYPE_CEIL || msgType < 0) {
        write_runlog(ERROR, "Invalid cms msg type=[%d], node=[%s: %u], socket=%d.\n",
            msgType, con->port->node_name, con->port->node_id, con->port->sock);
        CM_resetStringInfo(con->inBuffer);
        return false;
    }

    if (!con->port->is_postmaster && g_HA_status->local_role != CM_SERVER_PRIMARY &&
        con->port->remote_type != CM_SERVER) {
        write_runlog(LOG,
            "local cmserver role(%d) is not primary, the msg is %s.\n",
            g_HA_status->local_role,
            cluster_msg_int_to_string(msgType));
        DisableRemoveConn(con);
        return false;
    }

    if (msgType != (int)MSG_CM_SSL_CONN_REQUEST && g_sslOption.enable_ssl == CM_TRUE &&
        con->port->pipe.type != CS_TYPE_SSL) {
        write_runlog(ERROR, "It will disconnect the connection for msg type %d is invalid,the msg is %s.\n",
            (int)con->port->pipe.type, cluster_msg_int_to_string(msgType));
        DisableRemoveConn(con);
        return false;
    }

    return true;
}

static void PrintReadNoMessage(const CM_Connection* con)
{
    int32 logLevel = DEBUG5;
    if (con == NULL) {
        write_runlog(logLevel, "read no messge");
        return;
    }
    if (con->port != NULL && con->inBuffer != NULL) {
        write_runlog(logLevel, "read no messge, node=[%s: %u], socket=%d, qtype=%d, msgLen=%d, len=%d, maxLen=%d.\n",
            con->port->node_name, con->port->node_id, con->port->sock, con->inBuffer->qtype, con->inBuffer->msglen,
            con->inBuffer->len, con->inBuffer->maxlen);
    } else if (con->inBuffer != NULL) {
        write_runlog(logLevel, "read no messge, qtype=%d, msgLen=%d, len=%d, maxLen=%d.\n",
            con->inBuffer->qtype, con->inBuffer->msglen, con->inBuffer->len, con->inBuffer->maxlen);
    } else if (con->port != NULL) {
        write_runlog(logLevel, "read no messge, node=[%s: %u], socket=%d.\n",
            con->port->node_name, con->port->node_id, con->port->sock);
    } else {
        write_runlog(logLevel, "read no messge");
    }
}

static void CleanConBuffer(CM_Connection *con)
{
    if (con == NULL) {
        return;
    }
    PrintReadNoMessage(con);

    // wait for 60s, and then close socket
    if (con->msgFirstPartRecvTime != 0 && time(NULL) >= con->msgFirstPartRecvTime + AUTHENTICATION_TIMEOUT) {
        if (con->port != NULL) {
            write_runlog(LOG, "recv message timeout, nodeId[%s: %u], socket is %d.\n",
                con->port->node_name, con->port->node_id, con->port->sock);
        } else {
            write_runlog(LOG, "recv message timeout.\n");
        }
        DisableRemoveConn(con);
    }
}

/**
 * @brief
 *
 * @param  epollFd          My Param doc
 * @param  events           My Param doc
 * @param  arg              My Param doc
 */
static void cm_server_recv_msg(CM_IOThread *thrinfo, void* arg)
{
    CM_Connection* con = (CM_Connection*)arg;
    int qtype = 0;

    while (con != NULL && con->fd >= 0) {
        qtype = ReadCommand(con, "cm_server_recv_msg");
        write_runlog(
            DEBUG5, "read qtype is %d, msglen =%d len =%d\n", qtype, con->inBuffer->msglen, con->inBuffer->len);

        switch (qtype) {
            case 'C':
                con->last_active = time(NULL);
                con->msgFirstPartRecvTime = 0;
#ifdef KRB5
                if (!con->gss_check && cm_auth_method == CM_AUTH_GSS) {
                    write_runlog(
                        LOG, "will igrone the msg(nodeid:%u), the gss check has not pass.\n", con->port->node_id);
                    DisableRemoveConn(con);
                } else {
#endif  // KRB5
                if (!checkMsg(con)) {
                    break;
                }
                pushMsgToQue(thrinfo, con);
#ifdef KRB5
                }
#endif // KRB5
                CM_resetStringInfo(con->inBuffer);
                break;
            case 'p':
                con->msgFirstPartRecvTime = 0;
#ifdef KRB5
                if (cm_auth_method == CM_AUTH_GSS) {
                    con->last_active = time(NULL);
                    if (CMHandleCheckAuth(con) == 0) {
                        con->gss_check = true;
                    }
                } else {
#endif // KRB5
                    write_runlog(LOG, "trust conn type, don't need send gss msg.\n");
                    DisableRemoveConn(con);
#ifdef KRB5
                }
#endif // KRB5
                CM_resetStringInfo(con->inBuffer);
                break;
            case 'X':
            case EOF:
                con->msgFirstPartRecvTime = 0;
                if (con->port != NULL) {
                    if (con->port->remote_type == CM_CTL) {
                        write_runlog(DEBUG1, "connection closed by client, nodeid is %u.\n", con->port->node_id);
                    } else {
                        write_runlog(LOG, "connection closed by client, nodeid is %u.\n", con->port->node_id);
                    }
                }
                DisableRemoveConn(con);
                break;
            case TCP_SOCKET_ERROR_NO_MESSAGE:
            case 0:
                CleanConBuffer(con);
                return;
            case TCP_SOCKET_ERROR_EPIPE:
                write_runlog(ERROR, "connection was broken, nodeid is %u.\n", con->port->node_id);
                DisableRemoveConn(con);
                break;
            default:
                write_runlog(ERROR, "invalid frontend message type %d", qtype);
                DisableRemoveConn(con);
                break;
        }

        /* some communication error occurred, free con here */
        Assert(con != NULL);
        if (con->fd == INVALIDFD) {
            FREE_AND_RESET(con);
        }
    }
}

static void recvMsg(int fds, struct epoll_event *events, CM_IOThread *thrinfo)
{
    eventfd_t value = 0;

    for (int i = 0; i < fds; i++) {
        if (thrinfo->gotConnClose) {
            return;
        }

        if (events[i].data.fd == thrinfo->wakefd) {
            int ret = eventfd_read(thrinfo->wakefd, &value);
            write_runlog(DEBUG5, "eventfd_read ret = %d,value=%lu.\n", ret, value);
            continue;
        }

        CM_Connection* con = (CM_Connection*)events[i].data.ptr;
        write_runlog(DEBUG5, "epoll event type %u.\n", events[i].events);
        /* read event */
        if (events[i].events & EPOLLIN) {
            if ((con != NULL) && (con->port != NULL)) {
                cm_server_recv_msg(thrinfo, con->arg);
                thrinfo->recvMsgCount++;
            }
        }
    }
}

static CM_Connection *getConnect(const MsgSendInfo* msg)
{
    CM_Connection *con = NULL;
    int32 msgType = -1;
    if (msg->dataSize > sizeof(int)) {
        msgType = *((const int *)msg->data);
    }
    if (msg->connID.remoteType == CM_CTL) {
        con = GetTempConnection(msg->connID.connSeq);
    } else if (msg->connID.remoteType == CM_AGENT) {
        if (g_sslOption.enable_ssl && msgType == (int)MSG_CM_SSL_CONN_ACK) {
            con = GetTempConnection(msg->connID.connSeq);
            if (con != NULL && con->port->node_id != msg->connID.agentNodeId) {
                write_runlog(ERROR,
                    "getConnect is invalid,connect's node_id=%u,msg'node_id=%u.\n",
                    con->port->node_id,
                    msg->connID.agentNodeId);
                con = NULL;
            }
        } else {
            con = GetTempConnection(msg->connID.connSeq);
            if (con == NULL || con->port->node_id != msg->connID.agentNodeId) {
                con = gConns.connections[msg->connID.agentNodeId];
            }
        }
    }

    write_runlog(DEBUG5, "getConnect:remote_type=%d,connSeq=%lu,agentNodeId=%u,msg_type=%d.\n",
        msg->connID.remoteType, msg->connID.connSeq, msg->connID.agentNodeId, msgType);

    return con;
}

static inline uint64 GetIOThreadID(const ConnID connID)
{
    if (connID.remoteType == CM_AGENT) {
        return connID.agentNodeId % gIOThreads.count;
    } else if (connID.remoteType == CM_CTL) {
        return connID.connSeq % gIOThreads.count;
    }

    CM_ASSERT(0);
    return 0;
}

static void pushMsgToSendQue(MsgSendInfo *msg, MsgSourceType src)
{
    if (msg->connID.remoteType == CM_AGENT && msg->connID.agentNodeId == ALL_AGENT_NODE_ID) {
        for (uint32 i = 1; i < gIOThreads.count; i++) {
            uint32 len = sizeof(MsgSendInfo) + msg->dataSize;
            MsgSendInfo *msg_cpy = (MsgSendInfo *)AllocBufFromMsgPool(len);
            if (msg_cpy == NULL) {
                write_runlog(ERROR, "pushMsgToSendQue:AllocBufFromMsgPool failed,size=%u\n", len);
                return;
            }
            errno_t rc = memcpy_s(msg_cpy, len, msg, len);
            securec_check_errno(rc, (void)rc);
            CM_IOThread *thrinfo = &gIOThreads.threads[i];
            pushSendMsg((PriMsgQues *)thrinfo->sendMsgQue, msg_cpy, src);            
        }

        CM_IOThread *thrinfo = &gIOThreads.threads[0];
        pushSendMsg((PriMsgQues *)thrinfo->sendMsgQue, msg, src);
    } else {
        uint64 id = GetIOThreadID(msg->connID);
        CM_IOThread *thrinfo = &gIOThreads.threads[id];
        pushSendMsg((PriMsgQues *)thrinfo->sendMsgQue, msg, src);
    }
}

static void InnerProcSSLAccept(const MsgSendInfo *msg, CM_Connection *con)
{
    status_t status = CM_SUCCESS;
    CmsSSLConnMsg *connMsg = (CmsSSLConnMsg *)msg->data;
    uint64 now = GetMonotonicTimeMs();
    bool retryProc = false;
    static const int retrySSLAcceptDetayMs = 10;
    write_runlog(DEBUG5, "[InnerProcSSLAccept] now=%lu,procTime=%lu,startTime=%lu,connSeq=%lu.\n",
        now, msg->procTime, connMsg->startConnTime, con->connSeq);

    status = cm_cs_ssl_accept(g_ssl_acceptor_fd, &con->port->pipe);
    if (status == CM_TIMEDOUT) {
        if (now < connMsg->startConnTime + CM_SSL_IO_TIMEOUT) {
            retryProc = true;
            status = CM_SUCCESS;
            write_runlog(DEBUG5, "[ProcessSslConnRequest]retry ssl connect,connSeq=%lu.\n", con->connSeq);
        } else {
            write_runlog(ERROR, "[ProcessSslConnRequest]ssl connect timeout,connSeq=%lu.\n", con->connSeq);
        }
    }

    if (status == CM_SUCCESS && retryProc) {
        uint32 msgSize = sizeof(MsgSendInfo) + msg->dataSize;
        MsgSendInfo *nextConnMsg = (MsgSendInfo *)AllocBufFromMsgPool(msgSize);
        if (nextConnMsg == NULL) {
            write_runlog(ERROR, "[%s] AllocBufFromMsgPool failed.\n", __FUNCTION__);
            DisableRemoveConn(con);
            return;
        }
        errno_t rc = memcpy_s(nextConnMsg, msgSize, msg, msgSize);
        securec_check_errno(rc, (void)rc);
        nextConnMsg->procTime = now + retrySSLAcceptDetayMs;
        pushMsgToSendQue(nextConnMsg, msg->connID.remoteType == CM_AGENT ? MsgSrcAgent : MsgSrcCtl);
        write_runlog(DEBUG5,
            "[ProcessSslConnRequest]retry ssl connect later,procTime=%lu,connSeq=%lu.\n",
            nextConnMsg->procTime,
            con->connSeq);
        return;
    }

    (void)EventAdd(con->epHandle, (int)EPOLLIN, con);

    if (status != CM_SUCCESS) {
        write_runlog(ERROR, "[ProcessSslConnRequest]srv ssl accept failed,connSeq=%lu.\n", con->connSeq);
        DisableRemoveConn(con);
        return;
    }

    if (con->fd >= 0 && con->port->remote_type == CM_AGENT && con->port->node_id < CM_MAX_CONNECTIONS &&
        !con->port->is_postmaster) {
        AddCMAgentConnection(con);
        RemoveTempConnection(con);
    }
    write_runlog(DEBUG5, "[ProcessSslConnRequest]srv ssl connect success,connSeq=%lu.\n", con->connSeq);
}

/**
 * @brief
 *
 * @param  con              My Param doc
 * @param  thread           My Param doc
 * @return int
 */
static int CMAssignConnToThread(CM_Connection* con, const CM_IOThread* thread)
{
    Assert(con);
    Assert(con->port);
    Assert(thread);

    int epollfd;

    epollfd = thread->epHandle;
    if (epollfd < 0) {
        write_runlog(ERROR, "invalid epoll fd %d, thread %lu", epollfd, thread->tid);
        return -1;
    }

    con->callback = NULL;  // cm_server_recv_msg;
    con->arg = con;
    CM_resetStringInfo(con->inBuffer);
    con->port->startpack_have_processed = true;
    con->epHandle = epollfd;

    if (con->port->remote_type == CM_CTL) {
        write_runlog(DEBUG1, "Add con socket [fd=%d] to thread %lu [epollfd=%d].\n", con->fd, thread->tid, epollfd);
    } else {
        write_runlog(LOG, "Add con socket [fd=%d node=[%s: %u], socket=%d] to thread %lu [epollfd=%d].\n",
            con->fd, con->port->node_name, con->port->node_id, con->port->sock, thread->tid, epollfd);
    }

    set_socket_timeout(con->port, 0);
    if (EventAdd(epollfd, (int)EPOLLIN, con)) {
        write_runlog(ERROR, "Add con socket [fd=%d] to thread %lu failed!\n", con->fd, thread->tid);
        return -1;
    }

    return 0;
}

static int32 AssignCmaConnToThread(CM_Connection *con)
{
    if (con->fd < 0) {
        return -1;
    }
    if (!con->port->is_postmaster && g_sslOption.enable_ssl != CM_TRUE) {
        AddCMAgentConnection(con);
    } else {
        AddTempConnection(con);
    }

    /* assign new connection to a work thread by round robin */
    uint32 threadID = con->port->node_id % gIOThreads.count;
    CM_IOThread *ioThread = &gIOThreads.threads[threadID];
    if (CMAssignConnToThread(con, ioThread) != STATUS_OK) {
        write_runlog(LOG, "Assign new CM_AGENT connection to worker thread failed, confd is %d.\n", con->fd);
        return -1;
    }
    return 0;
}

static int32 AssignCmctlConnToThread(CM_Connection *con)
{
    if (con->fd < 0) {
        return -1;
    }
    uint64 threadID = con->connSeq % gIOThreads.count;
    CM_IOThread *ioThread = &gIOThreads.threads[threadID];
    AddTempConnection(con);
    if (CMAssignConnToThread(con, ioThread) != STATUS_OK) {
        write_runlog(
            LOG, "Assign new connection %d to worker thread failed, confd is %d.\n", con->port->remote_type, con->fd);
        return -1;
    }
    return 0;
}

static void AssignConnToThread(CM_Connection *con)
{
    Assert(con != NULL);
    Assert(con->port != NULL);
    int32 ret = -1; // remote_type is not cm_agent or cm_ctl, it will be disableAndRemove
    switch (con->port->remote_type) {
        case CM_AGENT:
            ret = AssignCmaConnToThread(con);
            break;
        case CM_CTL:
            ret = AssignCmctlConnToThread(con);
            break;
        default:
            write_runlog(ERROR, "remote_type(%d) is unkown, will disable conn.\n", con->port->remote_type);
            break;
    }
    if (ret != 0) {
        RemoveConnection(con);
    }
}

static inline CM_Connection *GetCmConnect(const MsgSendInfo* msg)
{
    CM_Connection *con = getConnect(msg);
    if (con == NULL) {
        write_runlog(ERROR,
            "[sendMsgs]get connection failed:remote_type=%s,connSeq=%lu,agentNodeId=%u.\n",
            msg->connID.remoteType == CM_CTL ? "CM_CTL" : "CM_AGENT",
            msg->connID.connSeq,
            msg->connID.agentNodeId);
        return NULL;
    }
    return con;
}

static void CheckDisableRemoveConn(const MsgSendInfo* msg)
{
    CM_Connection *con = GetCmConnect(msg);
    if (con == NULL) {
        return;
    }
    DisableRemoveConn(con);
}

static void CheckInnerProcSSLAccept(const MsgSendInfo *msg)
{
    CM_Connection *con = GetCmConnect(msg);
    if (con == NULL) {
        return;
    }
    InnerProcSSLAccept(msg, con);
}

static void ConnCheckDelEvent(const MsgSendInfo *msg)
{
    CM_Connection *con = GetCmConnect(msg);
    if (con == NULL) {
        return;
    }
    EventDel(con->epHandle, con);
}

static void CheckConnectAssignThread(const MsgSendInfo* msg)
{
    if (msg->dataSize < sizeof(CM_Connection *)) {
        return;
    }
    AssignConnToThread(*(CM_Connection **)msg->data);
}

void InnerProc(MsgSendInfo* msg)
{
    switch (msg->procMethod) {
        case PM_REMOVE_CONN:
            CheckDisableRemoveConn(msg);
            break;
        case PM_SSL_ACCEPT:
            CheckInnerProcSSLAccept(msg);
            break;
        case PM_REMOVE_EPOLL:
            // don't receive message while the ssl connection is not ready.
            ConnCheckDelEvent(msg);
            break;
        case PM_ASSIGN_CONN:
            CheckConnectAssignThread(msg);
            break;
        default:
            write_runlog(ERROR, "unknown procMethod:%d.\n", (int)msg->procMethod);
    }
    msg->connID.t9 = GetMonotonicTimeMs();
}

static int sendMsg(MsgSendInfo *msg, CM_Connection *con)
{
    int ret = CmsSendAndFlushMsg(con, msg->msgType, (const char *)&msg->data[0], msg->dataSize, msg->log_level);
    msg->connID.t9 = GetMonotonicTimeMs();
    if (ret != 0) {
        write_runlog(ERROR, "CmsSendAndFlushMsg error.\n");
    } else {
        write_runlog(DEBUG5, "CmsSendAndFlushMsg success.\n");
    }
#ifdef ENABLE_MULTIPLE_NODES
    if (msg->msgProcFlag & MPF_IS_CN_REPORT) {
        SetCmdStautus(ret);
    }
#endif
    return ret;
}

static void sendMsg(uint32 id, MsgSendInfo *msg)
{
    if (msg->connID.remoteType == CM_AGENT && msg->connID.agentNodeId == ALL_AGENT_NODE_ID) {
        (void)pthread_rwlock_wrlock(&gConns.lock);
        for (uint32 i = 0; i < gConns.max_node_id + 1; i++) {
            if (i % gIOThreads.count != id) {
                continue;
            }

            CM_Connection *con = gConns.connections[i];
            if (con == NULL) {
                continue;
            }
            if (sendMsg(msg, con) != 0) {
                (void)pthread_rwlock_unlock(&gConns.lock);
                RemoveConnAfterSendMsgFailed(con);
                (void)pthread_rwlock_wrlock(&gConns.lock);
            }
        }
        (void)pthread_rwlock_unlock(&gConns.lock);
    } else {
        CM_Connection *con = getConnect(msg);
        if (con == NULL) {
            write_runlog(ERROR,
                "[sendMsgs]get connection failed:remote_type=%s,connSeq=%lu,agentNodeId=%u.\n",
                msg->connID.remoteType == CM_CTL ? "CM_CTL" : "CM_AGENT",
                msg->connID.connSeq,
                msg->connID.agentNodeId);
            return;
        }

        if (sendMsg(msg, con) != 0) {
            RemoveConnAfterSendMsgFailed(con);
        }
    }
}

static void procSendMsg(CM_IOThread &thrinfo, MsgSendInfo *msg)
{
    static const int log_interval = 5;
    static const int expire_time = 7000;
    if (msg->procMethod == (int)PM_NONE) {
        thrinfo.sendMsgCount++;
        sendMsg(thrinfo.id, msg);
    } else {
        write_runlog(DEBUG5, "innerProc,method=%d.\n", msg->procMethod);
        thrinfo.innerProcCount++;
        InnerProc(msg);
    }

    if (msg->connID.t1 != 0 && msg->connID.t9 != 0 && msg->connID.t9 - msg->connID.t1 > expire_time) {
        static volatile time_t pre = 0;
        static volatile uint32 discard = 0;
        time_t now = time(NULL);
        if (now > pre + log_interval) {
            write_runlog(WARNING,
                "msg_delay:type=%c,procMethod=%d,msgProcFlag=%d,msgType=%d,remoteType=%d,pushRecvQue=%lu,inRecvQue=%lu,"
                "getRecvQue=%lu,proc=%lu,pushSendQue=%lu,inSendQue=%lu,getSendQue=%lu,send=%lu,discard=%u\n",
                msg->msgType,
                (int)msg->procMethod,
                (int)msg->msgProcFlag,
                msg->dataSize > sizeof(int) ? *((int *)msg->data) : -1,
                msg->connID.remoteType,
                msg->connID.t2 - msg->connID.t1,
                msg->connID.t3 - msg->connID.t2,
                msg->connID.t4 - msg->connID.t3,
                msg->connID.t5 - msg->connID.t4,
                msg->connID.t6 - msg->connID.t5,
                msg->connID.t7 - msg->connID.t6,
                msg->connID.t8 - msg->connID.t7,
                msg->connID.t9 - msg->connID.t8,
                discard);
            pre = now;
            discard = 0;
        } else {
            ++discard;
        }
    }
}

static void sendMsgs(CM_IOThread &thrinfo)
{
    PriMsgQues *sendQue = (PriMsgQues*)thrinfo.sendMsgQue;
    size_t total = getMsgCount(sendQue);
    size_t procCount = 0;

    if (total == 0) {
        return;
    }

    for (;;) {
        uint64 t1 = GetMonotonicTimeMs();
        MsgSendInfo *msg = (MsgSendInfo *)(getSendMsg(sendQue, MsgSrcAgent));
        if (msg == NULL) {
            uint64 t2 = GetMonotonicTimeMs();
            thrinfo.getSendQueWaitTime += (uint32)(t2 - t1);
            break;
        }

        uint64 t2 = GetMonotonicTimeMs();
        thrinfo.getSendQueWaitTime += (uint32)(t2 - t1);

        write_runlog(DEBUG5,
            "get message from send que:remote_type:%s,connSeq=%lu,agentNodeId=%u,msgType=%c:%d,len=%u.\n",
            msg->connID.remoteType == CM_CTL ? "CM_CTL" : "CM_AGENT",
            msg->connID.connSeq,
            msg->connID.agentNodeId,
            msg->msgType,
            msg->dataSize > sizeof(int) ? *((int *)msg->data) : 0,  // internal process message's datasize maybe 0
            msg->dataSize);

        procSendMsg(thrinfo, msg);
        FreeBufFromMsgPool(msg);
        msg = NULL;

        procCount++;
        if (procCount >= total) {
            break;
        }
    }
}

static void WakeSenderFunc(const ConnID connID)
{
    uint64 id = GetIOThreadID(connID);
    CM_IOThread *thrinfo = &gIOThreads.threads[id];
    int wakefd = thrinfo->wakefd;
    eventfd_t value = pthread_self();
    if (wakefd >= 0) {
        int ret = eventfd_write(wakefd, value);
        if (ret != 0) {
            write_runlog(ERROR, "eventfd_write failed.ret = %d,errno=%d,value=%lu.\n", ret, errno, value);
        }
    } else {
        write_runlog(DEBUG5, "io thread is not ready.\n");
    }
}

static int CreateWakeupEvent(int epollHandle, int &wakefd)
{
    wakefd = eventfd(0, 0);
    if (wakefd < 0) {
        write_runlog(ERROR, "eventfd error :%d.\n", errno);
        return CM_ERROR;
    }

    write_runlog(LOG, "eventfd :%d.\n", wakefd);

    struct epoll_event ev = {.events = (uint32)EPOLLIN, {.fd = wakefd}};
    if (epoll_ctl(epollHandle, EPOLL_CTL_ADD, wakefd, &ev) != 0) {
        write_runlog(ERROR, "epoll_ctl error :%d.\n", errno);
        (void)close(wakefd);
        wakefd = -1;
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

void *CM_IOThreadMain(void *argp)
{
    int epollHandle;
    struct epoll_event events[MAX_EVENTS];
    sigset_t block_sig_set;
    CM_IOThread *thrinfo = (CM_IOThread *)argp;
    time_t time1 = time(NULL);

    thread_name = "IO_WORKER";
    (void)prctl(PR_SET_NAME, thread_name);
    epollHandle = thrinfo->epHandle;
    if (CreateWakeupEvent(epollHandle, thrinfo->wakefd) != CM_SUCCESS) {
        return NULL;
    }

    uint64 epollWait = 0, recvMsgTime = 0, sendMsgTime = 0, count = 0;

    (void)pthread_detach(pthread_self());
    setBlockSigMask(&block_sig_set);
    setWakeSenderFunc(WakeSenderFunc);
    int waitTime = EPOLL_TIMEOUT;
    write_runlog(LOG, "cmserver pool thread %lu starting, epollfd is %d.\n", thrinfo->tid, epollHandle);
    for (;;) {
        if (got_stop == 1) {
            write_runlog(LOG, "receive exit request in cm arbitrate.\n");
            cm_sleep(1);
            continue;
        }

        CloseAllConnections(thrinfo);

        thrinfo->isBusy = false;
        /* wait for events to happen, 5s timeout */
        if (existSendMsg((PriMsgQues*)thrinfo->sendMsgQue)) {
            waitTime = 1;
        } else {
            waitTime = EPOLL_TIMEOUT;
        }
        uint64 t2 = GetMonotonicTimeMs();
        int fds = epoll_pwait(epollHandle, events, MAX_EVENTS, waitTime, &block_sig_set);
        if (fds < 0) {
            if (errno != EINTR && errno != EWOULDBLOCK) {
                write_runlog(ERROR, "epoll_wait fd %d error :%d, agent thread exit.\n", epollHandle, errno);
                break;
            }
        }
        thrinfo->isBusy = true;
        uint64 t3 = GetMonotonicTimeMs();
        if (fds > 0) {
            recvMsg(fds, events, thrinfo);
        }
        uint64 t4 = GetMonotonicTimeMs();
        sendMsgs(*thrinfo);
        uint64 t5 = GetMonotonicTimeMs();

        epollWait += t3 - t2;
        recvMsgTime += t4 - t3;
        sendMsgTime += t5 - t4;
        count++;
        time_t time2 = time(NULL);
        if (time2 - time1 >= MSG_TIME_FOR_LOG) {
            size_t totalRecvMsg = getMsgCount((PriMsgQues *)thrinfo->recvMsgQue);
            size_t totalSendMsg = getMsgCount((PriMsgQues *)thrinfo->sendMsgQue);
            if (totalRecvMsg >= MAX_MSG_IN_QUE || totalSendMsg >= MAX_MSG_IN_QUE) {
                write_runlog(LOG,
                    "total receive count:%u,send count:%u,innerProc count:%u;recv que size:%lu,send que size:%lu,"
                    "push send msg wait:%u,get send msg wait:%u,epoll wait=%lu,recv msg=%lu,send msg=%lu,count=%lu\n",
                    thrinfo->recvMsgCount, thrinfo->sendMsgCount, thrinfo->innerProcCount, totalRecvMsg, totalSendMsg,
                    thrinfo->pushRecvQueWaitTime / CM_MS_COUNT_PER_SEC,
                    thrinfo->getSendQueWaitTime / CM_MS_COUNT_PER_SEC,
                    epollWait, recvMsgTime, sendMsgTime, count);
            }
            epollWait = recvMsgTime = sendMsgTime = 0;
            count = 0;
            time1 = time2;
        }
    }

    (void)close(epollHandle);
    thrinfo->epHandle = -1;
    (void)close(thrinfo->wakefd);
    thrinfo->wakefd = -1;
    delete (PriMsgQues*)thrinfo->recvMsgQue;
    thrinfo->recvMsgQue = NULL;
    delete (PriMsgQues*)thrinfo->sendMsgQue;
    thrinfo->sendMsgQue = NULL;

    return thrinfo;
}

/**
 * @brief add/mod an event to epoll
 *
 * @param  epoll_handle     My Param doc
 * @param  events           My Param doc
 * @param  con              My Param doc
 * @return int
 */
int EventAdd(int epoll_handle, int events, CM_Connection* con)
{
    struct epoll_event epv;
    errno_t rc = memset_s(&epv, sizeof(epoll_event), 0, sizeof(epoll_event));
    securec_check_errno(rc, (void)rc);
    epv.data.ptr = con;
    con->events = events;
    epv.events = (uint32)events;

    if (epoll_ctl(epoll_handle, EPOLL_CTL_ADD, con->fd, &epv) < 0) {
        write_runlog(LOG, "Event Add failed [fd=%d], evnets[%04X]: %d\n", con->fd, (uint32)events, errno);
        return -1;
    }

    return 0;
}

/**
 * @brief delete an event from epoll
 *
 * @param  epollFd          My Param doc
 * @param  con              My Param doc
 */
void EventDel(int epollFd, CM_Connection* con)
{
    struct epoll_event epv;
    errno_t rc = memset_s(&epv, sizeof(epoll_event), 0, sizeof(epoll_event));
    securec_check_errno(rc, (void)rc);
    epv.data.ptr = con;

    if (epoll_ctl(epollFd, EPOLL_CTL_DEL, con->fd, &epv) < 0) {
        write_runlog(LOG, "EPOLL_CTL_DEL failed [fd=%d]: %d\n", con->fd, errno);
    }
}

/**
 * @brief ReadCommand reads a command from either the frontend or
 * standard input, places it in inBuf, and returns the
 * message type code (first byte of the message).
 * EOF is returned if end of file.
 *
 * @param  myport           My Param doc
 * @param  inBuf            My Param doc
 * @return int
 */
int ReadCommand(CM_Connection *con, const char *str)
{
    int qtype;
    int ret;

    if (con == NULL || con->port == NULL || con->inBuffer == NULL) {
        write_runlog(ERROR, "input param is null.\n");
        return -1;
    }
    Port *myport = con->port;
    CM_StringInfo inBuf = con->inBuffer;
    if ((inBuf->msglen != 0) && (inBuf->msglen == inBuf->len)) {
        return inBuf->qtype;
    }
    /*
     * Get message type code from the frontend.
     */
    if (inBuf->qtype == 0) {
        qtype = pq_getbyte(myport);
        /* frontend disconnected */
        if (qtype < 0) {
            return qtype;
        }

        switch (qtype) {
            case 'A':
            case 'C':
            case 'X':
            case 'p':
                break;
            default:
                write_runlog(ERROR, "[%s] invalid frontend message type %d, nodeId=[%s: %u], socket=%d,"
                    " in ReadCommand\n", str, qtype, myport->node_name, myport->node_id, myport->sock);
                return EOF;
        }
        inBuf->qtype = qtype;
        con->msgFirstPartRecvTime = time(NULL);
    }
    /*
     * In protocol version 3, all frontend messages have a length word next
     * after the type code; we can read the message contents independently of
     * the type.
     */
    ret = pq_getmessage(myport, inBuf, 0, true);
    if (ret != 0) {
        return ret; /* suitable message already logged */
    }

    if ((inBuf->msglen != 0) && (inBuf->msglen == inBuf->len)) {
        return inBuf->qtype;
    } else {
        return 0;
    }
}

/*
 * GtmHandleTrustAuth
 * handles trust authentication between gtm client and gtm server.
 *
 * @param (in) thrinfo: CreateRlsPolicyStmt describes the policy to create.
 * @return: void
 */
static void CMHandleTrustAuth(CM_Connection* con)
{
    /*
     * Send a dummy authentication request message 'R' as the client
     * expects that in the current protocol
     */
    int cmAuth = (int)htonl(CM_AUTH_REQ_OK);
    if (CmsSendAndFlushMsg(con, 'R', (char*)&cmAuth, sizeof(cmAuth)) != 0) {
        RemoveConnAfterSendMsgFailed(con);
        write_runlog(ERROR, "[%s][line:%d] CmsSendAndFlushMsg fail.\n", __FUNCTION__, __LINE__);
    }
    CM_resetStringInfo(con->inBuffer);
}

#ifdef KRB5
static void CMHandleGssAuth(CM_Connection* con)
{
    /* 1. Send authentication request message GTM_AUTH_REQ_GSS to client */
    int cmAuth = (int)htonl(CM_AUTH_REQ_GSS);
    if (CmsSendAndFlushMsg(con, 'R', (char*)&cmAuth, sizeof(cmAuth)) != 0) {
        RemoveConnAfterSendMsgFailed(con);
        write_runlog(ERROR, "[%s][line:%d] CmsSendAndFlushMsg fail.\n", __FUNCTION__, __LINE__);
    }
    CM_resetStringInfo(con->inBuffer);
}
#endif // KRB5

/*
 * GtmPerformAuthentication -- gtm server authenticate a remote client
 *
 * returns: nothing.  Will not return at all if there's any failure.
 */
void CMPerformAuthentication(CM_Connection *con)
{
    if (cm_auth_method == CM_AUTH_TRUST) {
        CMHandleTrustAuth(con);
        return;
    }
#ifdef KRB5
    if (cm_auth_method == CM_AUTH_GSS) {
        CMHandleGssAuth(con);
        return;
    }
#endif  // KRB5
    if (cm_auth_method == CM_AUTH_REJECT) {
        write_runlog(ERROR, "CM server reject any client connection.\n");
        return;
    }

    write_runlog(ERROR, "Invalid authentication method for CM server.\n");
    return;
}

#define BUF_LEN 1024
int get_authentication_type(const char* config_file)
{
    char buf[BUF_LEN];
    int type = CM_AUTH_TRUST;

    if (config_file == NULL) {
        return CM_AUTH_TRUST;  /* default level */
    }

    FILE *fd = fopen(config_file, "r");
    if (fd == NULL) {
        (void)printf("FATAL can not open config file: %s errno:%s\n", config_file, strerror(errno));
        exit(1);
    }

    while (!feof(fd)) {
        errno_t rc = memset_s(buf, BUF_LEN, 0, BUF_LEN);
        securec_check_errno(rc, (void)rc);
        (void)fgets(buf, BUF_LEN, fd);

        if (is_comment_line(buf) == 1) {
            continue;  /* skip  # comment */
        }

        if (strstr(buf, "cm_auth_method") != NULL) {
            /* check all lines */
            if (strstr(buf, "trust") != NULL) {
                type = CM_AUTH_TRUST;
            }

#ifdef KRB5
            if (strstr(buf, "gss") != NULL) {
                type = CM_AUTH_GSS;
            }
#endif // KRB5
        }
    }

    (void)fclose(fd);
    return type;
}

uint32 GetCmsConnCmaCount(void)
{
    (void)pthread_rwlock_rdlock(&gConns.lock);
    uint32 count = gConns.count;
    (void)pthread_rwlock_unlock(&gConns.lock);
    return count;
}

bool CheckAgentConnIsCurrent(uint32 nodeid)
{
    (void)pthread_rwlock_rdlock(&gConns.lock);
    bool res = (gConns.connections[nodeid] == NULL);
    (void)pthread_rwlock_unlock(&gConns.lock);
    return res;
}

bool isLoneNode(int timeout)
{
    uint32 count = 0;
    long currentTime = time(NULL);
    long delayTime;
    const int div_count = 2;
    CM_Connection* conn;

    (void)pthread_rwlock_wrlock(&gConns.lock);
    for (uint32 i = 0; i < gConns.max_node_id + 1; i++) {
        conn = gConns.connections[i];
        if ((conn != NULL) && (conn->fd >= 0)) {
            delayTime = currentTime - conn->last_active;
            if (delayTime < timeout) {
                count++;
            }
        }
    }

    for (uint32 i = 0; i < MAXLISTEN; i++) {
        conn = gConns.connections[CM_MAX_CONNECTIONS + i];
        if ((conn != NULL) && (conn->fd >= 0)) {
            delayTime = currentTime - conn->last_active;
            if (delayTime < timeout) {
                count++;
            }
        }
    }
    (void)pthread_rwlock_unlock(&gConns.lock);

    write_runlog(LOG, "active agent connections count = %u\n", count);

    return g_single_node_cluster ? false : (count <= g_node_num / div_count);
}

static void ProcessNodeConn(uint32 nodeId)
{
    write_runlog(LOG, "add pre conn for node %u.\n", nodeId);
    ++g_preAgentCon.connCount;
    g_preAgentCon.conFlag[nodeId] = 1;
}

void ProcPreNodeConn(uint32 nodeId)
{
    (void)pthread_rwlock_wrlock(&gConns.lock);
    if (nodeId >= CM_MAX_CONNECTIONS || g_preAgentCon.conFlag[nodeId] != 0) {
        (void)pthread_rwlock_unlock(&gConns.lock);
        return;
    }

    if (g_multi_az_cluster) {
        if (g_etcd_num > 0) {
            if (nodeId != g_currentNode->node) {
                ProcessNodeConn(nodeId);
            }
        } else {
            ProcessNodeConn(nodeId);
        }
    } else {
        if (IsDdbHealth(DDB_PRE_CONN)) {
            if (nodeId != g_currentNode->node) {
                ProcessNodeConn(nodeId);
            }
        } else {
            ProcessNodeConn(nodeId);
        }
    }

    (void)pthread_rwlock_unlock(&gConns.lock);
}

void addListenConn(int i, CM_Connection *listenCon)
{
    gConns.connections[CM_MAX_CONNECTIONS + i] = listenCon;
}

void getConnInfo(uint32& connCount, uint32& preConnCount)
{
    (void)pthread_rwlock_rdlock(&gConns.lock);

    connCount = gConns.count;
    preConnCount = g_preAgentCon.connCount;

    (void)pthread_rwlock_unlock(&gConns.lock);
}

uint32 getPreConnCount(void)
{
    (void)pthread_rwlock_rdlock(&gConns.lock);
    uint32 count =  g_preAgentCon.connCount;
    (void)pthread_rwlock_unlock(&gConns.lock);

    return count;
}

void resetPreConn(void)
{
    (void)pthread_rwlock_wrlock(&gConns.lock);
    write_runlog(LOG, "pre conn reset when choose cms primary.\n");
    g_preAgentCon.connCount = 0;
    errno_t rc = memset_s(g_preAgentCon.conFlag, sizeof(g_preAgentCon.conFlag), 0, sizeof(g_preAgentCon.conFlag));
    securec_check_errno(rc, (void)rc);
    (void)pthread_rwlock_unlock(&gConns.lock);
}

static int asyncSendMsgInner(const ConnID& connID, uint8 msgProcFlag, char msgtype,
    const char *s, size_t len, int log_level)
{
    MsgSendInfo *msg = (MsgSendInfo *)AllocBufFromMsgPool((uint32)(sizeof(MsgSendInfo) + len));
    if (msg == NULL) {
        write_runlog(ERROR, "RespondMsg:AllocBufFromMsgPool failed,size=%u\n", (uint32)(sizeof(MsgSendInfo) + len));
        return (int)ERR_ALLOC_MEMORY;
    }
    msg->connID = connID;
    msg->procTime = 0;
    msg->log_level = log_level;
    msg->dataSize = (uint32)len;
    msg->msgType = msgtype;
    msg->procMethod = 0;
    msg->msgProcFlag = msgProcFlag;
    if (s != NULL && len > 0) {
        errno_t rc = memcpy_s(msg->data, len, s, len);
        securec_check_errno(rc, (void)rc);
    }

    write_runlog(DEBUG1,
        "push message to send que:remote_type:%s,connSeq=%lu,agentNodeId=%u,msgType=%c,len=%u.\n",
        msg->connID.remoteType == CM_CTL ? "CM_CTL" : "CM_AGENT",
        msg->connID.connSeq,
        msg->connID.agentNodeId,
        msg->msgType,
        msg->dataSize);

    pushMsgToSendQue(msg, msg->connID.remoteType == CM_CTL ? MsgSrcCtl : MsgSrcAgent);

    return 0;
}

int RespondMsg(MsgRecvInfo* recvMsg, char msgtype, const char *s, size_t len, int log_level)
{
    recvMsg->connID.t5 = GetMonotonicTimeMs();
    return asyncSendMsgInner(recvMsg->connID, recvMsg->msgProcFlag, msgtype, s, len, log_level);
}

int SendToAgentMsg(uint agentNodeId, char msgtype, const char *s, size_t len, int log_level)
{
    ConnID connID;
    connID.remoteType = CM_AGENT;
    connID.connSeq = 0;
    connID.agentNodeId = agentNodeId;
    return asyncSendMsgInner(connID, 0, msgtype, s, len, log_level);
}

int BroadcastMsg(char msgtype, const char *s, size_t len, int log_level)
{
    ConnID connID;
    connID.remoteType = CM_AGENT;
    connID.connSeq = 0;
    connID.agentNodeId = ALL_AGENT_NODE_ID;
    return asyncSendMsgInner(connID, 0, msgtype, s, len, log_level);
}

void AsyncProcMsg(const MsgRecvInfo *recvMsg, IOProcMethond procMethod, const char *s, uint32 len)
{
    MsgSendInfo *msg = (MsgSendInfo *)AllocBufFromMsgPool(sizeof(MsgSendInfo) + len);
    if (msg == NULL) {
        write_runlog(ERROR, "[%s] AllocBufFromMsgPool failed.\n", __FUNCTION__);
        return;
    }
    msg->connID = recvMsg->connID;
    msg->procTime = 0;
    msg->dataSize = len;
    msg->msgType = 0;
    msg->procMethod = (char)procMethod;
    if (s != NULL && len > 0) {
        errno_t rc = memcpy_s(msg->data, len, s, len);
        securec_check_errno(rc, (void)rc);
    }
    int32 logLevel = LOG;
    if (msg->connID.remoteType == CM_CTL) {
        logLevel = DEBUG1;
    }

    write_runlog(logLevel,
        "push message to send que:remote_type:%s,connSeq=%lu,agentNodeId=%u,procMethod=%d,len=%u.\n",
        msg->connID.remoteType == CM_CTL ? "CM_CTL" : "CM_AGENT",
        msg->connID.connSeq,
        msg->connID.agentNodeId,
        (int)msg->procMethod,
        msg->dataSize);

    pushMsgToSendQue(msg, msg->connID.remoteType == CM_CTL ? MsgSrcCtl : MsgSrcAgent);
}
