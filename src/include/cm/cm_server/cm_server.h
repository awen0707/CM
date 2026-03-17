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
 * cm_server.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_server/cm_server.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef SERVER_MAIN_H
#define SERVER_MAIN_H

#include "common/config/cm_config.h"
#include "cm/stringinfo.h"
#include "cm/libpq-be.h"
#include "cm/cm_msg.h"
#include "cm/pqsignal.h"
#include "cm/cm_misc.h"
#include "cm_ddb_adapter.h"
#include "cms_msg_que.h"

#define CM_MAX_RES_SLOT_COUNT 16

#define CM_MAX_CONNECTIONS 1024
#define CM_MAX_THREADS 1024

#define CM_MONITOR_THREAD_NUM 1
#define CM_HA_THREAD_NUM 1

#define MAXLISTEN 64

#define MAX_EVENTS 512

#define DEFAULT_THREAD_NUM 5

#define INVALIDFD (-1)

#define CM_INCREMENT_TERM_VALUE 100

#define CM_INCREMENT_BIG_TERM_VALUE 10000

#define CM_UINT32_MAX 0xFFFFFFFFU

#define CM_MIN_CONN_TO_DDB (2)

#define CM_MAX_CONN_TO_DDB (100)

#define CM_TEN_DIVISOR 10

#define INVALID_CN_ID (0)

typedef void (*PCallback)(int fd, void* arg);

typedef enum NotifyCnE { NOT_NEED_TO_NOTITY_CN = 0, WAIT_TO_NOTFY_CN, NEED_TO_NOTITY_CN } NotifyCn_t;

typedef struct CM_Connection_t {
    int fd;
    int epHandle;
    int events;
    PCallback callback;
    void* arg;
    Port* port;
    CM_StringInfo inBuffer;
    long last_active;
    long msgFirstPartRecvTime;
#ifdef KRB5
    bool gss_check;
    gss_ctx_id_t gss_ctx;           /* GSS context */
    gss_cred_id_t gss_cred;         /* GSS credential */
    gss_name_t gss_name;            /* GSS target name */
    gss_buffer_desc gss_outbuf;     /* GSS output token */
#endif // KRB5
    NotifyCn_t notifyCn;
    uint64 connSeq;
} CM_Connection;

typedef struct CM_WorkThread_t {
    pthread_t tid;
    uint32 id;
    int type;
    uint32 procMsgCount;
    ConnID ProcConnID; // which connection is processing now;
    volatile bool isBusy;
} CM_WorkThread;

typedef struct CM_WorkThreads_t {
    uint32 count;
    CM_WorkThread threads[CM_MAX_THREADS];
} CM_WorkThreads;

typedef struct CM_HAThread_t {
    CM_WorkThread thread;
} CM_HAThread;

typedef struct CM_HAThreads_t {
    uint32 count;
    CM_HAThread threads[CM_HA_THREAD_NUM];
} CM_HAThreads;

typedef struct CM_MonitorThread_t {
    CM_WorkThread thread;
} CM_MonitorThread;

typedef struct CM_DdbStatusCheckAndSetThread_t {
    CM_WorkThread thread;
} CM_DdbStatusCheckAndSetThread;

typedef struct CM_MonitorNodeStopThread_t {
    CM_WorkThread thread;
} CM_MonitorNodeStopThread;

typedef struct {
    pthread_t tid;
    uint32 id;
    int epHandle;
    int wakefd;
    volatile bool isBusy;
    volatile int gotConnClose;
    void* recvMsgQue;
    void* sendMsgQue;
    uint32 pushRecvQueWaitTime;
    uint32 getSendQueWaitTime;
    uint32 recvMsgCount;
    uint32 sendMsgCount;
    uint32 innerProcCount;
} CM_IOThread;

typedef struct CM_IOThreads_t {
    uint32 count;
    CM_IOThread threads[CM_MAX_THREADS];
} CM_IOThreads;

typedef enum CM_ThreadStatus_e {
    CM_THREAD_STARTING,
    CM_THREAD_RUNNING,
    CM_THREAD_EXITING,
    CM_THREAD_INVALID
} CM_ThreadStatus;

typedef struct CM_Server_HA_Status_t {
    int local_role;
    int peer_role;
    int status;
    bool is_all_group_mode_pending;
    pthread_rwlock_t ha_lock;
} CM_Server_HA_Status;

typedef struct ObsDeleteItem_t {
    uint instId;
    char taskIdStr[CN_BUILD_TASK_ID_MAX_LEN];  // cnId(4) + cmsId(2) + time(14->yyyyMMddHH24mmss) + '\0'
    int buildStatus;
} ObsDeleteItem;

typedef struct BackupHeader_t {
    int32 version;
    int32 delCount;
} BackupHeader;

typedef struct GlobalBackUpInfo_t {
    uint32 obsKeyCnInstId;  // CN that backup cluster's CN used(report).
    char slotName[MAX_SLOT_NAME_LEN];
    BackupHeader header;
    ObsDeleteItem deleteItems[MAX_OBS_CN_COUNT];
    char *originDeleteData;
    uint32 newKeyCnInstId;  // we choose cn when cn can't use
} GlobalBackUpInfo;

typedef struct global_barrier_t {
    uint32 slotCount;
    GlobalBackUpInfo globalBackUpInfo[MAX_BARRIER_SLOT_COUNT];
    GlobalBarrierStatus globalBarrierInfo;
    char globalRecoveryBarrierId[BARRIERLEN];
    pthread_rwlock_t barrier_lock;
} global_barrier;

typedef struct CM_ConnectionInfo_t {
    /* Port contains all the vital information about this connection */
    Port *con_port;
} CM_ConnectionInfo;

typedef struct CM_ConnDdbInfo_t {
    uint32 count;
    uint32 curIdx;
    DdbConn ddbConn[CM_MAX_CONN_TO_DDB];
} CM_ConnDdbInfo;


#define THREAD_TYPE_HA 1
#define THREAD_TYPE_MONITOR 2
#define THREAD_TYPE_CTL_SERVER 3
#define THREAD_TYPE_AGENT_SERVER 4
#define THREAD_TYPE_INIT 5
#define THREAD_TYPE_ALARM_CHECKER 6
#define THREAD_TYPE_DDB_STATUS_CHECKER 7

#define MONITOR_CYCLE_TIMER 1000000
#define MONITOR_CYCLE_TIMER_OUT 6000000
#define MONITOR_CYCLE_MAX_COUNT (MONITOR_CYCLE_TIMER_OUT / MONITOR_CYCLE_TIMER)

// ARBITRATE_DELAY_CYCLE 10s
#define MONITOR_INSTANCE_ARBITRATE_DELAY_CYCLE_MAX_COUNT (10)

#define MONITOR_INSTANCE_ARBITRATE_DELAY_CYCLE_MAX_COUNT2 (MONITOR_INSTANCE_ARBITRATE_DELAY_CYCLE_MAX_COUNT * 2)
#define BUILD_TIMER_OUT (60 * 60 * 2)
#define PROMOTING_TIME_OUT   (30)

#define CM_INSTANCE_GROUP_SIZE 128

#define INSTANCE_NONE_COMMAND 0
#define INSTANCE_COMMAND_WAIT_SEND_SERVER 1
#define INSTANCE_COMMAND_WAIT_SERVER_ACK 2
#define INSTANCE_COMMAND_WAIT_EXEC 3
#define INSTANCE_COMMAND_WAIT_EXEC_ACK 4

#define INSTANCE_COMMAND_SEND_STATUS_NONE 0
#define INSTANCE_COMMAND_SEND_STATUS_SENDING 1
#define INSTANCE_COMMAND_SEND_STATUS_OK 2
#define INSTANCE_COMMAND_SEND_STATUS_FAIL 3

#define INSTANCE_ROLE_NO_CHANGE 0
#define INSTANCE_ROLE_CHANGED 1

#define INSTANCE_ARBITRATE_DELAY_NO_SET 0
#define INSTANCE_ARBITRATE_DELAY_HAVE_SET 1

constexpr int NO_NEED_TO_SET_PARAM = -1;

typedef struct DatanodeDynamicStatusT {
    int count;
    uint32 dnStatus[CM_PRIMARY_STANDBY_NUM];
} DatanodeDynamicStatus;

typedef struct cm_instance_report_status_t {
    cm_instance_command_status command_member[CM_PRIMARY_STANDBY_NUM];
    cm_instance_datanode_report_status data_node_member[CM_PRIMARY_STANDBY_NUM];
    cm_instance_gtm_report_status gtm_member[CM_PRIMARY_STANDBY_NUM];
    cm_instance_coordinate_report_status coordinatemember;
    cm_instance_arbitrate_status arbitrate_status_member[CM_PRIMARY_STANDBY_NUM];
    uint32 time;
    uint32 term;
    int ddbSynced;
    int cma_kill_instance_timeout;
    uint32 obs_delete_xlog_time;
    struct timespec finishredo_time;
    bool finish_redo;
    DatanodeSyncList currentSyncList;
    DatanodeSyncList exceptSyncList;
    DatanodeDynamicStatus voteAzInstance;
    int waitReduceTimes;
    int waitIncreaseTimes;
    int waitSyncTime;
    DrvKeyValue *keyValue;
    uint32 kvCount;
    uint32 lastFailoverDn;
} cm_instance_report_status;

typedef struct cm_instance_group_report_status_t {
    pthread_rwlock_t lk_lock;
    cm_instance_report_status instance_status;
} cm_instance_group_report_status;

typedef struct cm_fenced_UDF_report_status_t {
    pthread_rwlock_t lk_lock;
    int heart_beat;
    int status;
} cm_fenced_UDF_report_status;

typedef enum ProcessingModeE {
    BootstrapProcessing,  /* bootstrap creation of template database */
    InitProcessing,       /* initializing system */
    NormalProcessing,     /* normal processing */
    PostUpgradeProcessing /* Post upgrade to run script */
} ProcessingMode;

typedef enum VoteAZE {
    IS_NOT_VOTE_AZ = 0,
    IS_VOTE_AZ
} VoteAZ;

typedef struct CmAzInfoT {
    char azName[CM_AZ_NAME];
    uint32 azPriority;
    uint32 cnCount;
    uint32 dnCount;
    uint32 gtmCount;
    uint32 unkownCount;
    uint32 udfCount;
    int32 azIndex;
    int32 isVoteAz;
    uint32 gtmDuplicate;
    uint32 dnDuplicate;
    uint32 cnDuplicate;
} CmAzInfo;

typedef struct ThreadExecStatusT {
    uint32 count;
    uint32 execStatus[CM_MAX_THREADS];
} ThreadExecStatus;

#define IsBootstrapProcessingMode() (Mode == BootstrapProcessing)
#define IsInitProcessingMode() (Mode == InitProcessing)
#define IsNormalProcessingMode() (Mode == NormalProcessing)
#define IsPostUpgradeProcessingMode() (Mode == PostUpgradeProcessing)

#define GetProcessingMode() Mode

#define SetProcessingMode(mode)                                                                        \
    do {                                                                                               \
        if ((mode) == BootstrapProcessing || (mode) == InitProcessing || (mode) == NormalProcessing || \
            (mode) == PostUpgradeProcessing)                                                           \
            Mode = (mode);                                                                             \
    } while (0)

extern volatile sig_atomic_t got_stop;
extern volatile sig_atomic_t g_gotParameterReload;
extern volatile sig_atomic_t g_SetReplaceCnStatus;
extern volatile sig_atomic_t ha_connection_closed;
extern char g_replaceCnStatusFile[MAX_PATH_LEN];

void ProcessStartupPacket(int epollFd, void* arg);
extern int cm_server_send_msg(CM_Connection* con, char msgtype, const char* s, size_t len, int log_level = LOG);
int CmsSendAndFlushMsg(CM_Connection *con, char msgType, const char *s, size_t len, int logLevel = LOG);
void set_pending_command(
    const uint32 &group_index,
    const int &member_index,
    const CM_MessageType &pending_command,
    const int &time_out = NO_NEED_TO_SET_PARAM,
    const int &full_build = NO_NEED_TO_SET_PARAM);
extern int BuildDynamicConfigFile(bool* dynamicModified);

#endif
