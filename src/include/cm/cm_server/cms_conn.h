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
 * cms_conn.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_server/cms_conn.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CMS_CONN_H
#define CMS_CONN_H

#include "cm/libpq-fe.h"
#include "cm_server.h"

#define CM_AUTH_REJECT (0)
#define CM_AUTH_TRUST (1)
#ifdef KRB5
#define CM_AUTH_GSS (2)
#endif // KRB5

#define CM_SERVER_PACKET_ERROR_MSG 128
#define MSG_TIME_FOR_LOG  5
#include "cms_msg_que.h"

enum IOProcMethond {
    PM_NONE = 0,
    PM_REMOVE_CONN = 1,
    PM_SSL_ACCEPT = 2,
    PM_REMOVE_EPOLL = 3,
    PM_ASSIGN_CONN = 4,
};

#define MPF_DO_SWITCHOVER 0x1
#define MPF_IS_CN_REPORT 0x2

extern uint8 g_msgProcFlag[MSG_CM_TYPE_CEIL];

void *CM_WorkThreadMain(void* argp);
void* CM_IOThreadMain(void* argp);
int32 InitConn();
void RemoveConnection(CM_Connection* con);
void RemoveConnAfterSendMsgFailed(CM_Connection *con);
void AddCMAgentConnection(CM_Connection* con);
void AddTempConnection(CM_Connection *con);
void ConnCloseAndFree(CM_Connection* con);
void set_socket_timeout(const Port* my_port, int timeout);

Port* ConnCreate(int serverFd);
void ConnFree(Port* conn);
int initMasks(const int* listenSocket, fd_set* rmask);
int CMHandleCheckAuth(CM_Connection* con);
int cm_server_flush_msg(CM_Connection* con);

int EventAdd(int epoll_handle, int events, CM_Connection* con);
void EventDel(int epollFd, CM_Connection* con);
void CMPerformAuthentication(CM_Connection* con);
int ReadCommand(CM_Connection *con, const char *str);
int get_authentication_type(const char* config_file);
int RespondMsg(MsgRecvInfo* recvMsg, char msgtype, const char *s, size_t len, int log_level = LOG);
int SendToAgentMsg(uint agentNodeId, char msgtype, const char *s, size_t len, int log_level = LOG);
int BroadcastMsg(char msgtype, const char *s, size_t len, int log_level = LOG);
void AsyncProcMsg(const MsgRecvInfo* recvMsg, IOProcMethond procMethod, const char *s, uint32 len);
uint32 GetCmsConnCmaCount(void);
bool CheckAgentConnIsCurrent(uint32 nodeid);
bool isLoneNode(int timeout);
void ProcPreNodeConn(uint32 nodeId);
void addListenConn(int i, CM_Connection* listenCon);
void getConnInfo(uint32 &connCount, uint32 &preConnCount);
uint32 getPreConnCount(void);
void resetPreConn(void);
#endif
