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
 * cm_msg.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_msg.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CM_MSG_H
#define CM_MSG_H

#include <pthread.h>
#include <sys/time.h>
#include "cm_misc_res.h"
#include "common/config/cm_config.h"
#include "replication/replicainternal.h"
#include "access/xlogdefs.h"
#include "access/redo_statistic_msg.h"
#include "cm_rhb.h"
#include "cm_voting_disk.h"
#include "cm/cm_msg_common.h"

#define CM_MAX_SENDER_NUM 2
#define CM_MSG_ERR_INFORMATION_LENGTH 1024
#ifndef MAX_INT32
#define MAX_INT32 (2147483600)
#endif
#define CN_INFO_NUM 8
#define RESERVE_NUM 160
#define RESERVE_NUM_USED 4
#define MAX_SYNC_STANDBY_LIST 1024
#define REMAIN_LEN 20

typedef struct timespec cmTime_t;

const uint32 g_barrierSlotVersion = 92380;
const uint32 g_hadrKeyCn = 92381;

const uint32 RESERVE_LEN = 256;
const uint32 THREAD_NAME_LEN = 256;

const int32 FAILED_SYNC_DATA = 0;
const int32 SUCCESS_SYNC_DATA = 1;

/*
 * Symbols in the following enum are usd in cluster_msg_map_string defined in cm_misc.cpp.
 * Modifictaion to the following enum should be reflected to cluster_msg_map_string as well.
 */
typedef enum CM_MessageType_st {
    MSG_CTL_CM_SWITCHOVER = 0,
    MSG_CTL_CM_BUILD = 1,
    MSG_CTL_CM_SYNC = 2,
    MSG_CTL_CM_QUERY = 3,
    MSG_CTL_CM_NOTIFY = 4,
    MSG_CTL_CM_BUTT = 5,
    MSG_CM_CTL_DATA_BEGIN = 6,
    MSG_CM_CTL_DATA = 7,
    MSG_CM_CTL_NODE_END = 8,
    MSG_CM_CTL_DATA_END = 9,
    MSG_CM_CTL_COMMAND_ACK = 10,

    MSG_CM_AGENT_SWITCHOVER = 11,
    MSG_CM_AGENT_FAILOVER = 12,
    MSG_CM_AGENT_BUILD = 13,
    MSG_CM_AGENT_SYNC = 14,
    MSG_CM_AGENT_NOTIFY = 15,
    MSG_CM_AGENT_NOTIFY_CN = 16,
    MSG_AGENT_CM_NOTIFY_CN_FEEDBACK = 17,
    MSG_CM_AGENT_CANCEL_SESSION = 18,
    MSG_CM_AGENT_RESTART = 19,
    MSG_CM_AGENT_RESTART_BY_MODE = 20,
    MSG_CM_AGENT_REP_SYNC = 21,
    MSG_CM_AGENT_REP_ASYNC = 22,
    MSG_CM_AGENT_REP_MOST_AVAILABLE = 23,
    MSG_CM_AGENT_BUTT = 24,

    MSG_AGENT_CM_DATA_INSTANCE_REPORT_STATUS = 25,
    MSG_AGENT_CM_COORDINATE_INSTANCE_STATUS = 26,
    MSG_AGENT_CM_GTM_INSTANCE_STATUS = 27,
    MSG_AGENT_CM_BUTT = 28,

    /****************  =====CAUTION=====  ****************:
    If you want to add a new MessageType, you should add at the end ,
    It's forbidden to insert new MessageType at middle,  it will change the other MessageType value.
    The MessageType is transfered between cm_agent and cm_server on different host,
    You should ensure the type value be identical and compatible between old and new versions */

    MSG_CM_CM_VOTE = 29,
    MSG_CM_CM_BROADCAST = 30,
    MSG_CM_CM_NOTIFY = 31,
    MSG_CM_CM_SWITCHOVER = 32,
    MSG_CM_CM_FAILOVER = 33,
    MSG_CM_CM_SYNC = 34,
    MSG_CM_CM_SWITCHOVER_ACK = 35,
    MSG_CM_CM_FAILOVER_ACK = 36,
    MSG_CM_CM_ROLE_CHANGE_NOTIFY = 37,
    MSG_CM_CM_REPORT_SYNC = 38,

    MSG_AGENT_CM_HEARTBEAT = 39,
    MSG_CM_AGENT_HEARTBEAT = 40,
    MSG_CTL_CM_SET = 41,
    MSG_CTL_CM_SWITCHOVER_ALL = 42,
    MSG_CM_CTL_SWITCHOVER_ALL_ACK = 43,
    MSG_CTL_CM_BALANCE_CHECK = 44,
    MSG_CM_CTL_BALANCE_CHECK_ACK = 45,
    MSG_CTL_CM_BALANCE_RESULT = 46,
    MSG_CM_CTL_BALANCE_RESULT_ACK = 47,
    MSG_CTL_CM_QUERY_CMSERVER = 48,
    MSG_CM_CTL_CMSERVER = 49,

    MSG_TYPE_BUTT = 50,
    MSG_CM_AGENT_NOTIFY_CN_CENTRAL_NODE = 51,
    MSG_CM_AGENT_DROP_CN = 52,
    MSG_CM_AGENT_DROPPED_CN = 53,
    MSG_AGENT_CM_FENCED_UDF_INSTANCE_STATUS = 54,
    MSG_CTL_CM_SWITCHOVER_FULL = 55,             /* inform cm agent to do switchover -A */
    MSG_CM_CTL_SWITCHOVER_FULL_ACK = 56,         /* inform cm ctl that cm server is doing swtichover -A */
    MSG_CM_CTL_SWITCHOVER_FULL_DENIED = 57,      /* inform cm ctl that switchover -A is denied by cm server */
    MSG_CTL_CM_SWITCHOVER_FULL_CHECK = 58,       /* cm ctl inform cm server to check if swtichover -A is done */
    MSG_CM_CTL_SWITCHOVER_FULL_CHECK_ACK = 59,   /* inform cm ctl that swtichover -A is done */
    MSG_CTL_CM_SWITCHOVER_FULL_TIMEOUT = 60,     /* cm ctl inform cm server to swtichover -A timed out */
    MSG_CM_CTL_SWITCHOVER_FULL_TIMEOUT_ACK = 61, /* inform cm ctl that swtichover -A stopped */

    MSG_CTL_CM_SETMODE = 62, /* new mode */
    MSG_CM_CTL_SETMODE_ACK = 63,

    MSG_CTL_CM_SWITCHOVER_AZ = 64,             /* inform cm agent to do switchover -zazName */
    MSG_CM_CTL_SWITCHOVER_AZ_ACK = 65,         /* inform cm ctl that cm server is doing swtichover -zazName */
    MSG_CM_CTL_SWITCHOVER_AZ_DENIED = 66,      /* inform cm ctl that switchover -zazName is denied by cm server */
    MSG_CTL_CM_SWITCHOVER_AZ_CHECK = 67,       /* cm ctl inform cm server to check if swtichover -zazName is done */
    MSG_CM_CTL_SWITCHOVER_AZ_CHECK_ACK = 68,   /* inform cm ctl that swtichover -zazName is done */
    MSG_CTL_CM_SWITCHOVER_AZ_TIMEOUT = 69,     /* cm ctl inform cm server to swtichover -zazName timed out */
    MSG_CM_CTL_SWITCHOVER_AZ_TIMEOUT_ACK = 70, /* inform cm ctl that swtichover -zazName stopped */

    MSG_CM_CTL_SET_ACK = 71,
    MSG_CTL_CM_GET = 72,
    MSG_CM_CTL_GET_ACK = 73,
    MSG_CM_AGENT_GS_GUC = 74,
    MSG_AGENT_CM_GS_GUC_ACK = 75,
    MSG_CM_CTL_SWITCHOVER_INCOMPLETE_ACK = 76,
    MSG_CM_CM_TIMELINE = 77, /* when restart cluster , cmserver primary and standy timeline */
    MSG_CM_BUILD_DOING = 78,
    MSG_AGENT_CM_ETCD_CURRENT_TIME = 79, /* etcd clock monitoring message */
    MSG_CM_QUERY_INSTANCE_STATUS = 80,
    MSG_CM_SERVER_TO_AGENT_CONN_CHECK = 81,
    MSG_CTL_CM_GET_DATANODE_RELATION = 82, /* depracated for the removal of quick switchover */
    MSG_CM_BUILD_DOWN = 83,
    MSG_CTL_CM_HOTPATCH = 84,
    MSG_CM_SERVER_REPAIR_CN_ACK = 85,
    MSG_CTL_CM_DISABLE_CN = 86,
    MSG_CTL_CM_DISABLE_CN_ACK = 87,
    MSG_CM_AGENT_LOCK_NO_PRIMARY = 88,
    MSG_CM_AGENT_LOCK_CHOSEN_PRIMARY = 89,
    MSG_CM_AGENT_UNLOCK = 90,
    MSG_CTL_CM_STOP_ARBITRATION = 91,
    MSG_CTL_CM_FINISH_REDO = 92,
    MSG_CM_CTL_FINISH_REDO_ACK = 93,
    MSG_CM_AGENT_FINISH_REDO = 94,
    MSG_CTL_CM_FINISH_REDO_CHECK = 95,
    MSG_CM_CTL_FINISH_REDO_CHECK_ACK = 96,
    MSG_AGENT_CM_KERBEROS_STATUS = 97,
    MSG_CTL_CM_QUERY_KERBEROS = 98,
    MSG_CTL_CM_QUERY_KERBEROS_ACK = 99,
    MSG_AGENT_CM_DISKUSAGE_STATUS = 100,
    MSG_CM_AGENT_OBS_DELETE_XLOG = 101,
    MSG_CM_AGENT_DROP_CN_OBS_XLOG = 102,
    MSG_AGENT_CM_DATANODE_INSTANCE_BARRIER = 103,
    MSG_AGENT_CM_COORDINATE_INSTANCE_BARRIER = 104,
    MSG_CTL_CM_GLOBAL_BARRIER_QUERY = 105,
    MSG_CM_CTL_GLOBAL_BARRIER_DATA = 106,
    MSG_CM_CTL_GLOBAL_BARRIER_DATA_BEGIN = 107,
    MSG_CM_CTL_BARRIER_DATA_END = 108,
    MSG_CM_CTL_BACKUP_OPEN = 109,
    MSG_CM_AGENT_DN_SYNC_LIST = 110,
    MSG_AGENT_CM_DN_SYNC_LIST = 111,
    MSG_CTL_CM_SWITCHOVER_FAST = 112,
    MSG_CM_AGENT_SWITCHOVER_FAST = 113,
    MSG_CTL_CM_RELOAD = 114,
    MSG_CM_CTL_RELOAD_ACK = 115,
    MSG_CM_CTL_INVALID_COMMAND_ACK = 116,
    MSG_AGENT_CM_CN_OBS_STATUS = 117,
    MSG_CM_AGENT_NOTIFY_CN_RECOVER = 118,
    MSG_CM_AGENT_FULL_BACKUP_CN_OBS = 119,
    MSG_AGENT_CM_BACKUP_STATUS_ACK = 120,
    MSG_CM_AGENT_REFRESH_OBS_DEL_TEXT = 121,
    MSG_AGENT_CM_INSTANCE_BARRIER_NEW = 122,
    MSG_CTL_CM_GLOBAL_BARRIER_QUERY_NEW = 123,
    MSG_CM_CTL_GLOBAL_BARRIER_DATA_BEGIN_NEW = 124,
    MSG_AGENT_CM_RESOURCE_STATUS = 125,
    MSG_CTL_CM_RESOURCE_STATUS = 126,

    MSG_CM_AGENT_RES_STATUS_LIST = 127,
    MSG_CM_AGENT_RES_STATUS_CHANGED = 128,
    MSG_CM_AGENT_SET_INSTANCE_DATA_STATUS = 129,
    MSG_CM_AGENT_REPORT_SET_STATUS = 130,
    MSG_CM_AGENT_REPORT_RES_DATA = 131,

    MSG_AGENT_CM_REQUEST_RES_STATUS_LIST = 132,
    MSG_AGENT_CM_GET_LATEST_STATUS_LIST = 133,
    MSG_AGENT_CM_SET_RES_DATA = 134,
    MSG_AGENT_CM_GET_RES_DATA = 135,

    MSG_CLIENT_AGENT_HEARTBEAT = 136,
    MSG_CLIENT_AGENT_INIT_DATA = 137,
    MSG_CLIENT_AGENT_SET_DATA = 138,
    MSG_CLIENT_AGENT_SET_RES_DATA = 139,
    MSG_CLIENT_AGENT_GET_RES_DATA = 140,

    MSG_AGENT_CLIENT_HEARTBEAT_ACK = 141,
    MSG_AGENT_CLIENT_RES_STATUS_LIST = 142,
    MSG_AGENT_CLIENT_RES_STATUS_CHANGE = 143,
    MSG_AGENT_CLIENT_NOTIFY_CONN_CLOSE = 144,
    MSG_AGENT_CLIENT_REPORT_RES_DATA = 145,

    MSG_EXEC_DDB_COMMAND = 146,
    EXEC_DDB_COMMAND_ACK = 147,
    MSG_CLIENT_CM_DDB_OPER = 148,
    MSG_CM_CLIENT_DDB_OPER_ACK = 149,
    MSG_CM_SSL_CONN_REQUEST = 150,
    MSG_CM_SSL_CONN_ACK = 151,

    MSG_CTL_CMS_SWITCH = 152,
    MSG_CMS_CTL_SWITCH_ACK = 153,
    MSG_CM_AGENT_DATANODE_INSTANCE_BARRIER = 154,
    MSG_CM_AGENT_COORDINATE_INSTANCE_BARRIER = 155,
    MSG_AGENT_CM_DATANODE_LOCAL_PEER = 156,
    MSG_GET_SHARED_STORAGE_INFO = 157,
    MSG_GET_SHARED_STORAGE_INFO_ACK = 158,

    MSG_AGENT_CLIENT_INIT_ACK = 159,
    MSG_CM_RES_LOCK = 160,
    MSG_CM_RES_LOCK_ACK = 161,
    MSG_CM_RES_REG = 162,
    MSG_CM_RES_REG_ACK = 163,
    MSG_CTL_CM_QUERY_RES_INST = 164,
    MSG_CM_CTL_QUERY_RES_INST_ACK = 165,

    MSG_CM_RHB = 166,
    MSG_CTL_CM_RHB_STATUS_REQ = 167,
    MSG_CTL_CM_RHB_STATUS_ACK = 168,
    MSG_CTL_CM_NODE_DISK_STATUS_REQ = 169,
    MSG_CTL_CM_NODE_DISK_STATUS_ACK = 170,
    MSG_AGENT_CM_FLOAT_IP = 171,
    MSG_CM_AGENT_FLOAT_IP_ACK = 172,
    MSG_FINISHREDO_RETRIVE = 173,
    MSG_AGENT_CM_ISREG_REPORT = 174,
    MSG_CM_AGENT_ISREG_CHECK_LIST_CHANGED = 175,
    MSG_CM_AGENT_DISKUSAGE_STATUS_ACK = 176,
    MSG_AGENT_CM_EXT_IP_STATUS = 177,
    MSG_CTL_CM_EXT_IP_STATUS_REQ = 178,
    MSG_CM_CTL_EXT_IP_DATA = 179,
    MSG_CM_CTL_EXT_IP_DATA_END = 180,
    MSG_CTL_CM_FLOAT_IP_REQ = 181,
    MSG_CTL_CM_FLOAT_IP_ACK = 182,
    MSG_CM_AGENT_MODIFY_MOST_AVAILABLE = 183,
    MSG_AGENT_CM_DN_MOST_AVAILABLE = 184,
    MSG_CMA_PING_DN_FLOAT_IP_FAIL = 185,
    MSG_CMS_NOTIFY_PRIMARY_DN_RESET_FLOAT_IP = 186,
    MSG_AGENT_ONDEMAND_STATUES_REPORT = 187,

    MSG_CM_TYPE_CEIL,  // new message types should be added before this.
} CM_MessageType;

#define UNDEFINED_LOCKMODE 0
#define POLLING_CONNECTION 1
#define SPECIFY_CONNECTION 2
#define PROHIBIT_CONNECTION 3
#define PRE_PROHIBIT_CONNECTION 4

#define INSTANCE_ROLE_INIT 0
#define INSTANCE_ROLE_PRIMARY 1
#define INSTANCE_ROLE_STANDBY 2
#define INSTANCE_ROLE_PENDING 3
#define INSTANCE_ROLE_NORMAL 4
#define INSTANCE_ROLE_UNKNOWN 5
#define INSTANCE_ROLE_DUMMY_STANDBY 6
#define INSTANCE_ROLE_DELETED 7
#define INSTANCE_ROLE_DELETING 8
#define INSTANCE_ROLE_READONLY 9
#define INSTANCE_ROLE_OFFLINE 10
#define INSTANCE_ROLE_MAIN_STANDBY 11
#define INSTANCE_ROLE_CASCADE_STANDBY 12
#define INSTANCE_ROLE_END 13 // must be the end

#define INSTANCE_ROLE_FIRST_INIT 1
#define INSTANCE_ROLE_HAVE_INIT 2

#define INSTANCE_DATA_REPLICATION_SYNC 1
#define INSTANCE_DATA_REPLICATION_ASYNC 2
#define INSTANCE_DATA_REPLICATION_MOST_AVAILABLE 3
#define INSTANCE_DATA_REPLICATION_POTENTIAL_SYNC 4
#define INSTANCE_DATA_REPLICATION_QUORUM 5
#define INSTANCE_DATA_REPLICATION_UNKONWN 6

#define INSTANCE_TYPE_GTM 1
#define INSTANCE_TYPE_DATANODE 2
#define INSTANCE_TYPE_COORDINATE 3
#define INSTANCE_TYPE_FENCED_UDF 4
#define INSTANCE_TYPE_UNKNOWN 5
#define INSTANCE_TYPE_RESOURCE 6
#define INSTANCE_TYPE_PENDING 7


#define INSTANCE_WALSNDSTATE_STARTUP 0
#define INSTANCE_WALSNDSTATE_BACKUP 1
#define INSTANCE_WALSNDSTATE_CATCHUP 2
#define INSTANCE_WALSNDSTATE_STREAMING 3
#define INSTANCE_WALSNDSTATE_DUMPLOG 4
const int INSTANCE_WALSNDSTATE_NORMAL = 5;
const int INSTANCE_WALSNDSTATE_UNKNOWN = 6;

#define GS_SSL_IO_TIMEOUT          (uint32)30000 /* mill-seconds */

#define CON_OK 0
#define CON_BAD 1
#define CON_STARTED 2
#define CON_MADE 3
#define CON_AWAITING_RESPONSE 4
#define CON_AUTH_OK 5
#define CON_SETEN 6
#define CON_SSL_STARTUP 7
#define CON_NEEDED 8
#define CON_UNKNOWN 9
#define CON_MANUAL_STOPPED 10
#define CON_DISK_DEMAGED 11
#define CON_PORT_USED 12
#define CON_NIC_DOWN 13
#define CON_GTM_STARTING 14

#define CM_SERVER_UNKNOWN 0
#define CM_SERVER_PRIMARY 1
#define CM_SERVER_STANDBY 2
#define CM_SERVER_INIT 3
#define CM_SERVER_DOWN 4

#define CM_ETCD_UNKNOWN 0
#define CM_ETCD_FOLLOWER 1
#define CM_ETCD_LEADER 2
#define CM_ETCD_DOWN 3

#define SWITCHOVER_UNKNOWN 0
#define SWITCHOVER_FAIL 1
#define SWITCHOVER_SUCCESS 2
#define SWITCHOVER_EXECING 3
#define SWITCHOVER_PARTLY_SUCCESS 4
#define SWITCHOVER_ABNORMAL 5
#define INVALID_COMMAND 6
#define SWITCHOVER_CANNOT_RESPONSE 7


#define UNKNOWN_BAD_REASON 0
#define PORT_BAD_REASON 1
#define NIC_BAD_REASON 2
#define DISC_BAD_REASON 3
#define STOPPED_REASON 4
#define CN_DELETED_REASON 5

#define KERBEROS_STATUS_UNKNOWN 0
#define KERBEROS_STATUS_NORMAL 1
#define KERBEROS_STATUS_ABNORMAL 2
#define KERBEROS_STATUS_DOWN 3

#define HOST_LENGTH 32
#define BARRIERLEN 40
#define MAX_SLOT_NAME_LEN 64
#define MAX_BARRIER_SLOT_COUNT 5

#define CM_MSG_MAX_LENGTH (70 * 1024)

#define CMAGENT_NO_CCN "NoCentralNode"

#define OBS_DEL_VERSION_V1 (1)
#define DEL_TEXT_HEADER_LEN_V1 (10)  // version(4->V%3d) + delCount(4->C%3d) + '\n' + '\0'
#define CN_BUILD_TASK_ID_MAX_LEN   (21)      // cnId(4) + cmsId(4) + time(12->yyMMddHH24mmss) + 1
#define MAX_OBS_CN_COUNT   (64)
#define MAX_OBS_DEL_TEXT_LEN  (CN_BUILD_TASK_ID_MAX_LEN * MAX_OBS_CN_COUNT + DEL_TEXT_HEADER_LEN_V1)

#define SSL_ENABLE (1)
#define SSL_DISABLE (2)

#define CM_DDB_CLUSTER_INFO_CMD "--cluster_info"

/* The ondemand recovery status. */
#define IN_ONDEMAND_RECOVERY 0
#define NOT_IN_ONDEMAND_RECOVERY 1
/* Unexpect status of pg_controldata, such as DSS down. */
#define UNEXPECT_ONDEMAND_RECOVERY 2


extern int g_gtmPhonyDeadTimes;
extern int g_dnPhonyDeadTimes[CM_MAX_DATANODE_PER_NODE];
extern int g_cnPhonyDeadTimes;

const int ERR_MSG_LENGTH = 2048;
const int DCC_CMD_MAX_LEN = 2057;
const int DCC_CMD_MAX_OUTPUT_LEN = (2048 - 64);

typedef enum DDB_OPER_t {
    DDB_INIT_OPER = 0,
    DDB_SET_OPER,
    DDB_GET_OPER,
    DDB_DEL_OPER,
} DDB_OPER;

typedef struct DatanodeSyncListSt {
    int count;
    uint32 dnSyncList[CM_PRIMARY_STANDBY_NUM];
    int syncStandbyNum;
    // remain
    int remain;
    char remainStr[DN_SYNC_LEN];
} DatanodeSyncList;

typedef struct cm_msg_type_st {
    int msg_type;
} cm_msg_type;

typedef struct cm_switchover_incomplete_msg_st {
    int msg_type;
    char errMsg[CM_MSG_ERR_INFORMATION_LENGTH];
} cm_switchover_incomplete_msg;

typedef struct cm_redo_stats_st {
    int is_by_query;
    uint64 redo_replayed_speed;
    XLogRecPtr standby_last_replayed_read_Ptr;
} cm_redo_stats;

typedef struct ctl_to_cm_stop_arbitration_st {
    int msg_type;
} ctl_to_cm_stop_arbitration;

typedef struct ctl_to_cm_switchover_st {
    int msg_type;
    char azName[CM_AZ_NAME];
    uint32 node;
    uint32 instanceId;
    int instance_type;
    int wait_seconds;
} ctl_to_cm_switchover;

typedef struct ctl_to_cm_failover_st {
    int msg_type;
    uint32 node;
    uint32 instanceId;
    int instance_type;
    int wait_seconds;
} ctl_to_cm_failover;

typedef struct cm_to_ctl_finish_redo_check_ack_st {
    int msg_type;
    int finish_redo_count;
} cm_to_ctl_finish_redo_check_ack;

typedef struct ctl_to_cm_finish_redo_st {
    int msg_type;
} ctl_to_cm_finish_redo;

typedef enum SwitchStepEn {
    UNKNOWN_STEP = 0,
    SWITCH_DDB_ENTER_MAINTAIN,
    SWITCH_DDB_SAVE_ALL_KVS,
    SWITCH_DDB,
} SwitchStep;

typedef struct CtlToCmsSwitchSt {
    int msgType;
    char ddbType[CM_PATH_LENGTH];
    SwitchStep step;
} CtlToCmsSwitch;

typedef struct CmsToCtlSwitchAckSt {
    int msgType;
    bool isSuccess;
    char errMsg[CM_PATH_LENGTH];
} CmsToCtlSwitchAck;

#define CM_CTL_UNFORCE_BUILD 0
#define CM_CTL_FORCE_BUILD 1

typedef enum CmsBuildStepEn {
    CMS_BUILD_NONE = 0,
    CMS_BUILD_LOCK = 1,
    CMS_BUILD_DOING = 2,
    CMS_BUILD_UNLOCK = 3
} CmsBuildStep;

typedef struct ctl_to_cm_build_st {
    int msg_type;
    uint32 node;
    uint32 instanceId;
    int instance_type;
    int wait_seconds;
    int force_build;
    int full_build;
    int parallel;
    CmsBuildStep cmsBuildStep;
} ctl_to_cm_build;

typedef struct ctl_to_cm_global_barrier_query_st {
    int msg_type;
}ctl_to_cm_global_barrier_query;

typedef struct ctl_to_cm_query_st {
    int msg_type;
    uint32 node;
    uint32 instanceId;
    int instance_type;
    int wait_seconds;
    int detail;
    int relation;
} ctl_to_cm_query;

typedef struct Cm2AgentNotifyCnRecoverByObs_t {
    int msg_type;
    uint32 instanceId;
    bool changeKeyCn;
    uint32 syncCnId;
    char slotName[MAX_SLOT_NAME_LEN];
} Cm2AgentNotifyCnRecoverByObs;

typedef struct Cm2AgentBackupCn2Obs_t {
    int msg_type;
    uint32 instanceId;
    char slotName[MAX_SLOT_NAME_LEN];
    char taskIdStr[CN_BUILD_TASK_ID_MAX_LEN];
} Cm2AgentBackupCn2Obs;

typedef struct Agent2CMBackupStatusAck_t {
    int msg_type;
    uint32 node;
    uint32 instanceId;
    char slotName[MAX_SLOT_NAME_LEN];
    char taskIdStr[CN_BUILD_TASK_ID_MAX_LEN];
    int32 status;
} Agent2CMBackupStatusAck;

typedef struct Cm2AgentRefreshObsDelText_t {
    int msg_type;
    uint32 instanceId;
    char slotName[MAX_SLOT_NAME_LEN];
    char obsDelCnText[MAX_OBS_DEL_TEXT_LEN];
} Cm2AgentRefreshObsDelText;

typedef struct ctl_to_cm_notify_st {
    CM_MessageType msg_type;
    ctlToCmNotifyDetail detail;
} ctl_to_cm_notify;

typedef struct ctl_to_cm_disable_cn_st {
    int msg_type;
    uint32 instanceId;
    int wait_seconds;
} ctl_to_cm_disable_cn;

typedef struct ctl_to_cm_disable_cn_ack_st {
    int msg_type;
    bool disable_ok;
    char errMsg[CM_MSG_ERR_INFORMATION_LENGTH];
} ctl_to_cm_disable_cn_ack;

typedef enum arbitration_mode_en {
    UNKNOWN_ARBITRATION = 0,
    MAJORITY_ARBITRATION = 1,
    MINORITY_ARBITRATION = 2
} arbitration_mode;

typedef enum cm_start_mode_en {
    UNKNOWN_START = 0,
    MAJORITY_START = 1,
    MINORITY_START = 2,
    OTHER_MINORITY_START = 3
} cm_start_mode;

typedef enum PromoteMode_t {
    PMODE_AUTO = 0,              // promote primary by vote, etcd, dcc, disk lock...
    PMODE_FORCE_PRIMAYR = 1,     // force primary at any time
    PMODE_FORCE_STANDBY = 2,     // force standby at any time
} PromoteMode;

typedef enum switchover_az_mode_en {
    UNKNOWN_SWITCHOVER_AZ = 0,
    NON_AUTOSWITCHOVER_AZ = 1,
    AUTOSWITCHOVER_AZ = 2
} switchover_az_mode;

typedef enum logic_cluster_restart_mode_en {
    UNKNOWN_LOGIC_CLUSTER_RESTART = 0,
    INITIAL_LOGIC_CLUSTER_RESTART = 1,
    MODIFY_LOGIC_CLUSTER_RESTART = 2
} logic_cluster_restart_mode;

typedef enum cluster_mode_en {
    INVALID_CLUSTER_MODE = 0,
    ONE_MASTER_1_SLAVE,
    ONE_MASTER_2_SLAVE,
    ONE_MASTER_3_SLAVE,
    ONE_MASTER_4_SLAVE,
    ONE_MASTER_5_SLAVE
} cluster_mode;

typedef enum synchronous_standby_mode_en {
    AnyFirstNo = 0, /* don't have */
    AnyAz1,         /* ANY 1(az1) */
    FirstAz1,       /* FIRST 1(az1) */
    AnyAz2,         /* ANY 1(az2) */
    FirstAz2,       /* FIRST 1(az2) */
    Any2Az1Az2,     /* ANY 2(az1,az2) */
    First2Az1Az2,   /* FIRST 2(az1,az2) */
    Any3Az1Az2,     /* ANY 3(az1, az2) */
    First3Az1Az2    /* FIRST 3(az1, az2) */
} synchronous_standby_mode;

typedef enum {
    CLUSTER_PRIMARY = 0,
    CLUSTER_OBS_STANDBY = 1,
    CLUSTER_STREAMING_STANDBY = 2
} ClusterRole;

typedef enum {
    DISASTER_RECOVERY_NULL = 0,
    DISASTER_RECOVERY_OBS = 1,
    DISASTER_RECOVERY_STREAMING = 2
} DisasterRecoveryType;

typedef enum {
    QUORUM = 0,
    PAXOS = 1,
    SHARE_DISK = 2
} DnArbitrateMode;

typedef enum {
    INSTALL_TYPE_DEFAULT = 0,
    INSTALL_TYPE_SHARE_STORAGE = 1,
    INSTALL_TYPE_STREAMING = 2
} ClusterInstallType;

typedef enum {
    SS_DOUBLE_NULL = 0,
    SS_DOUBLE_PRIMARY = 1,
    SS_DOUBLE_STANDBY = 2
} SSDoubleClusterMode;

typedef struct ctl_to_cm_set_st {
    int msg_type;
    int log_level;
    uint32 logic_cluster_delay;
    arbitration_mode cm_arbitration_mode;
    switchover_az_mode cm_switchover_az_mode;
    logic_cluster_restart_mode cm_logic_cluster_restart_mode;
} ctl_to_cm_set, cm_to_ctl_get;

typedef struct cm_to_agent_switchover_st {
    int msg_type;
    uint32 node;
    uint32 instanceId;
    int instance_type;
    int wait_seconds;
    int role;
    uint32 term;
} cm_to_agent_switchover;

typedef struct cm_to_agent_failover_st {
    int msg_type;
    uint32 node;
    uint32 instanceId;
    int instance_type;
    int wait_seconds;
    uint32 term;
} cm_to_agent_failover;

typedef struct cm_to_agent_failover_sta_st {
    int msg_type;
    uint32 node;
    uint32 instanceId;
    int instance_type;
    int wait_seconds;
    int32 staPrimId;
    uint32 term;
} cm_to_agent_failover_sta;

typedef struct cm_to_agent_failover_cascade_st {
    int msg_type;
    uint32 node;
    uint32 instanceId;
    int wait_seconds;
} cm_to_agent_failover_cascade;

typedef struct cm_to_agent_build_st {
    int msg_type;
    uint32 node;
    uint32 instanceId;
    int instance_type;
    int wait_seconds;
    int role;
    int full_build;
    uint32 term;
    int parallel;
    uint32 primaryNodeId;
} cm_to_agent_build;

typedef struct cm_to_agent_lock1_st {
    int msg_type;
    uint32 node;
    uint32 instanceId;
} cm_to_agent_lock1;

typedef struct cm_to_agent_obs_delete_xlog_st {
    int msg_type;
    uint32 node;
    uint32 instanceId;
    uint64 lsn;
} cm_to_agent_obs_delete_xlog;

typedef struct cm_to_agent_lock2_st {
    int msg_type;
    uint32 node;
    uint32 instanceId;
    char disconn_host[CM_IP_LENGTH];
    uint32 disconn_port;
} cm_to_agent_lock2;

typedef struct cm_to_agent_unlock_st {
    int msg_type;
    uint32 node;
    uint32 instanceId;
} cm_to_agent_unlock;

typedef struct cm_to_agent_finish_redo_st {
    int msg_type;
    uint32 node;
    uint32 instanceId;
    bool is_finish_redo_cmd_sent;
} cm_to_agent_finish_redo;

typedef struct cm_to_agent_gs_guc_st {
    int msg_type;
    uint32 node;
    uint32 instanceId;
    synchronous_standby_mode type;
} cm_to_agent_gs_guc;

typedef struct agent_to_cm_gs_guc_feedback_st {
    int msg_type;
    uint32 node;
    uint32 instanceId; /* node of this agent */
    synchronous_standby_mode type;
    bool status; /* gs guc command exec status */
} agent_to_cm_gs_guc_feedback;

typedef struct CmToAgentGsGucSyncList_st {
    int msgType;
    uint32 node;
    uint32 instanceId;
    uint32 groupIndex;
    DatanodeSyncList dnSyncList;
    int instanceNum;
    // remain
    int remain[REMAIN_LEN];
} CmToAgentGsGucSyncList;

typedef struct cm_to_agent_notify_st {
    int msg_type;
    uint32 node;
    uint32 instanceId;
    int role;
    uint32 term;
} cm_to_agent_notify;

typedef struct CltSendDdbOper_t {
    int msgType;
    uint32 node;
    char threadName[THREAD_NAME_LEN];
    DDB_OPER dbOper;
    uint32 keyLen;
    char key[MAX_PATH_LEN];
    uint32 valueLen;
    char value[MAX_PATH_LEN];
    char reserved[RESERVE_LEN];
} CltSendDdbOper;

typedef struct CmSendDdbOperRes_t {
    int msgType;
    uint32 node;
    char threadName[THREAD_NAME_LEN];
    DDB_OPER dbOper;
    bool exeStatus;
    uint32 keyLen;
    char key[MAX_PATH_LEN];
    uint32 valueLen;
    char value[MAX_PATH_LEN];
    uint32 errLen;
    char errMsg[MAX_PATH_LEN];
    char reserved[RESERVE_LEN];
} CmSendDdbOperRes;


/*
 * msg struct using for cmserver to cmagent
 * including primaryed datanode count and datanode instanceId list.
 */
typedef struct cm_to_agent_notify_cn_st {
    int msg_type;
    uint32 node;       /* node of this coordinator */
    uint32 instanceId; /* coordinator instance id */
    int datanodeCount; /* current count of datanode got primaryed */
    uint32 coordinatorId;
    int notifyCount;
    /* datanode instance id array */
    uint32 datanodeId[FLEXIBLE_ARRAY_MEMBER]; /* VARIABLE LENGTH ARRAY */
} cm_to_agent_notify_cn;

/*
 * msg struct using for cmserver to cmagent
 * including primaryed datanode count and datanode instanceId list.
 */
typedef struct cm_to_agent_drop_cn_st {
    int msg_type;
    uint32 node;       /* node of this coordinator */
    uint32 instanceId; /* coordinator instance id */
    uint32 coordinatorId;
    int role;
    bool delay_repair;
} cm_to_agent_drop_cn;

typedef struct cm_to_agent_notify_cn_central_node_st {
    int msg_type;
    uint32 node;                 /* node of this coordinator */
    uint32 instanceId;           /* coordinator instance id */
    char cnodename[NAMEDATALEN]; /* central node id */
    char nodename[NAMEDATALEN];
} cm_to_agent_notify_cn_central_node;

/*
 * msg struct using for cmserver to cmagent
 * including primaryed datanode count and datanode instanceId list.
 */
typedef struct cm_to_agent_cancel_session_st {
    int msg_type;
    uint32 node;       /* node of this coordinator */
    uint32 instanceId; /* coordinator instance id */
} cm_to_agent_cancel_session;

/*
 * msg struct using for cmagent to cmserver
 * feedback msg for notify cn.
 */
typedef struct agent_to_cm_notify_cn_feedback_st {
    int msg_type;
    uint32 node;       /* node of this coordinator */
    uint32 instanceId; /* coordinator instance id */
    bool status;       /* notify command exec status */
    int notifyCount;
} agent_to_cm_notify_cn_feedback;

typedef struct BackupInfo_t {
    uint32 localKeyCnId;
    uint32 obsKeyCnId;
    char slotName[MAX_SLOT_NAME_LEN];
    char obsDelCnText[MAX_OBS_DEL_TEXT_LEN];
} BackupInfo;

typedef struct Agent2CmBackupInfoRep_t {
    int msg_type;
    uint32 instanceId; /* coordinator instance id */
    uint32 slotCount;
    BackupInfo backupInfos[MAX_BARRIER_SLOT_COUNT];
} Agent2CmBackupInfoRep;

typedef struct cm_to_agent_restart_st {
    int msg_type;
    uint32 node;
    uint32 instanceId;
} cm_to_agent_restart;

typedef struct cm_to_agent_restart_by_mode_st {
    int msg_type;
    uint32 node;
    uint32 instanceId;
    int role_old;
    int role_new;
} cm_to_agent_restart_by_mode;

typedef struct cm_to_agent_rep_sync_st {
    int msg_type;
    uint32 node;
    uint32 instanceId;
    int instance_type;
    int sync_mode;
} cm_to_agent_rep_sync;

typedef struct cm_to_agent_rep_async_st {
    int msg_type;
    uint32 node;
    uint32 instanceId;
    int instance_type;
    int sync_mode;
} cm_to_agent_rep_async;

typedef struct cm_to_agent_rep_most_available_st {
    int msg_type;
    uint32 node;
    uint32 instanceId;
    int instance_type;
    int sync_mode;
} cm_to_agent_rep_most_available;

typedef struct cm_to_agent_modify_most_available_st {
    int msg_type;
    uint32 node;
    uint32 instanceId;
    int instance_type;
    uint32 oper; /*0： turn off; 1: trun on*/
} cm_to_agent_modify_most_available;

typedef struct cm_instance_central_node_st {
    pthread_rwlock_t rw_lock;
    pthread_mutex_t mt_lock;
    uint32 instanceId;
    uint32 node;
    uint32 recover;
    uint32 isCentral;
    uint32 nodecount;
    char nodename[NAMEDATALEN];
    char cnodename[NAMEDATALEN];
    char* failnodes;
    cm_to_agent_notify_cn_central_node notify;
} cm_instance_central_node;

typedef struct cm_instance_central_node_msg_st {
    pthread_rwlock_t rw_lock;
    cm_to_agent_notify_cn_central_node notify;
} cm_instance_central_node_msg;

#define MAX_LENGTH_HP_CMD (9)
#define MAX_LENGTH_HP_PATH (256)
#define MAX_LENGTH_HP_RETURN_MSG (1024)

typedef struct cm_hotpatch_msg_st {
    int msg_type;
    char command[MAX_LENGTH_HP_CMD];
    char path[MAX_LENGTH_HP_PATH];
} cm_hotpatch_msg;

typedef struct cm_hotpatch_ret_msg_st {
    char msg[MAX_LENGTH_HP_RETURN_MSG];
} cm_hotpatch_ret_msg;

typedef struct cm_to_agent_barrier_info_st {
    int msg_type;
    uint32 node;
    uint32 instanceId;
    char queryBarrier[BARRIERLEN];
    char targetBarrier[BARRIERLEN];
    char reserved[RESERVE_NUM];
} cm_to_agent_barrier_info;

#ifndef IP_LEN
#define IP_LEN 64
#endif
#define MAX_REPL_CONNINFO_LEN 256
#define MAX_REBUILD_REASON_LEN 256

const int cn_active_unknown = 0;
const int cn_active = 1;
const int cn_inactive = 2;

#define INSTANCE_HA_STATE_UNKONWN 0
#define INSTANCE_HA_STATE_NORMAL 1
#define INSTANCE_HA_STATE_NEED_REPAIR 2
#define INSTANCE_HA_STATE_STARTING 3
#define INSTANCE_HA_STATE_WAITING 4
#define INSTANCE_HA_STATE_DEMOTING 5
#define INSTANCE_HA_STATE_PROMOTING 6
#define INSTANCE_HA_STATE_BUILDING 7
#define INSTANCE_HA_STATE_CATCH_UP 8
#define INSTANCE_HA_STATE_COREDUMP 9
#define INSTANCE_HA_STATE_MANUAL_STOPPED 10
#define INSTANCE_HA_STATE_DISK_DAMAGED 11
#define INSTANCE_HA_STATE_PORT_USED 12
#define INSTANCE_HA_STATE_BUILD_FAILED 13
#define INSTANCE_HA_STATE_HEARTBEAT_TIMEOUT 14
#define INSTANCE_HA_STATE_NIC_DOWN 15
#define INSTANCE_HA_STATE_READ_ONLY 16
#define INSTANCE_HA_STATE_DISCONNECTED 17

#define INSTANCE_HA_DATANODE_BUILD_REASON_NORMAL 0
#define INSTANCE_HA_DATANODE_BUILD_REASON_WALSEGMENT_REMOVED 1
#define INSTANCE_HA_DATANODE_BUILD_REASON_DISCONNECT 2
#define INSTANCE_HA_DATANODE_BUILD_REASON_VERSION_NOT_MATCHED 3
#define INSTANCE_HA_DATANODE_BUILD_REASON_MODE_NOT_MATCHED 4
#define INSTANCE_HA_DATANODE_BUILD_REASON_SYSTEMID_NOT_MATCHED 5
#define INSTANCE_HA_DATANODE_BUILD_REASON_TIMELINE_NOT_MATCHED 6
#define INSTANCE_HA_DATANODE_BUILD_REASON_UNKNOWN 7
#define INSTANCE_HA_DATANODE_BUILD_REASON_USER_PASSWD_INVALID 8
#define INSTANCE_HA_DATANODE_BUILD_REASON_CONNECTING 9
#define INSTANCE_HA_DATANODE_BUILD_REASON_DCF_LOG_LOSS 10

#define UNKNOWN_LEVEL 0

typedef enum CM_DCF_ROLE {
    DCF_ROLE_UNKNOWN = 0,
    DCF_ROLE_LEADER,
    DCF_ROLE_FOLLOWER,
    DCF_ROLE_PASSIVE,
    DCF_ROLE_LOGGER,
    DCF_ROLE_PRE_CANDIDATE,
    DCF_ROLE_CANDIDATE,
    DCF_ROLE_CEIL,
} DCF_ROLE;

typedef struct AgentToCmBarrierStatusReportSt {
    int msg_type;
    uint32 node;
    uint32 instanceId;
    int instanceType;
    uint64 ckpt_redo_point;
    char global_barrierId[BARRIERLEN];
    char global_achive_barrierId[BARRIERLEN];
    char barrierID [BARRIERLEN];
    char query_barrierId[BARRIERLEN];
    uint64 barrierLSN;
    uint64 archive_LSN;
    uint64 flush_LSN;
    bool is_barrier_exist;
} AgentToCmBarrierStatusReport;

typedef struct GlobalBarrierItem_t {
    char slotname[MAX_SLOT_NAME_LEN];
    char globalBarrierId[BARRIERLEN];
    char globalAchiveBarrierId[BARRIERLEN];
} GlobalBarrierItem;

typedef struct GlobalBarrierStatus_t {
    int slotCount;
    GlobalBarrierItem globalBarriers[MAX_BARRIER_SLOT_COUNT];
} GlobalBarrierStatus;

typedef struct LocalBarrierStatus_t {
    uint64 ckptRedoPoint;
    uint64 barrierLSN;
    uint64 archiveLSN;
    uint64 flushLSN;
    char barrierID[BARRIERLEN];
} LocalBarrierStatus;

typedef struct Agent2CmBarrierStatusReport_t {
    int msg_type;
    uint32 node;
    uint32 instanceId;
    int instanceType;
    LocalBarrierStatus localStatus;
    GlobalBarrierStatus globalStatus;
} Agent2CmBarrierStatusReport;

typedef struct cm_local_replconninfo_st {
    int local_role;
    int static_connections;
    int db_state;
    XLogRecPtr last_flush_lsn;
    int buildReason;
    uint32 term;
    uint32 disconn_mode;
    char disconn_host[CM_IP_LENGTH];
    uint32 disconn_port;
    char local_host[CM_IP_LENGTH];
    uint32 local_port;
    bool redo_finished;
    bool realtime_build_status;
} cm_local_replconninfo;

typedef struct cm_sender_replconninfo_st {
    pid_t sender_pid;
    int local_role;
    int peer_role;
    int peer_state;
    int state;
    XLogRecPtr sender_sent_location;
    XLogRecPtr sender_write_location;
    XLogRecPtr sender_flush_location;
    XLogRecPtr sender_replay_location;
    XLogRecPtr receiver_received_location;
    XLogRecPtr receiver_write_location;
    XLogRecPtr receiver_flush_location;
    XLogRecPtr receiver_replay_location;
    int sync_percent;
    int sync_state;
    int sync_priority;
} cm_sender_replconninfo;

typedef struct cm_receiver_replconninfo_st {
    pid_t receiver_pid;
    int local_role;
    int peer_role;
    int peer_state;
    int state;
    XLogRecPtr sender_sent_location;
    XLogRecPtr sender_write_location;
    XLogRecPtr sender_flush_location;
    XLogRecPtr sender_replay_location;
    XLogRecPtr receiver_received_location;
    XLogRecPtr receiver_write_location;
    XLogRecPtr receiver_flush_location;
    XLogRecPtr receiver_replay_location;
    int sync_percent;
} cm_receiver_replconninfo;

typedef struct cm_gtm_replconninfo_st {
    int local_role;
    int connect_status;
    TransactionId xid;
    uint64 send_msg_count;
    uint64 receive_msg_count;
    int sync_mode;
} cm_gtm_replconninfo;

typedef struct cm_coordinate_replconninfo_st {
    int status;
    int db_state;
} cm_coordinate_replconninfo;

typedef enum cm_coordinate_group_mode_en {
    GROUP_MODE_INIT,
    GROUP_MODE_NORMAL,
    GROUP_MODE_PENDING,
    GROUP_MODE_BUTT
} cm_coordinate_group_mode;

#define AGENT_TO_INSTANCE_CONNECTION_BAD 0
#define AGENT_TO_INSTANCE_CONNECTION_OK 1

#define INSTANCE_PROCESS_DIED 0
#define INSTANCE_PROCESS_RUNNING 1

const int max_cn_node_num_for_old_version = 16;

typedef struct cluster_cn_info_st {
    uint32 cn_Id;
    uint32 cn_active;
    bool cn_connect;
    bool drop_success;
} cluster_cn_info;

typedef struct agent_to_cm_coordinate_status_report_old_st {
    int msg_type;
    uint32 node;
    uint32 instanceId;
    int instanceType;
    int connectStatus;
    int processStatus;
    int isCentral;
    char nodename[NAMEDATALEN];
    char logicClusterName[CM_LOGIC_CLUSTER_NAME_LEN];
    char cnodename[NAMEDATALEN];
    cm_coordinate_replconninfo status;
    cm_coordinate_group_mode group_mode;
    bool cleanDropCnFlag;
    bool isCnDnDisconnected;
    cluster_cn_info cn_active_info[max_cn_node_num_for_old_version];
    int cn_restart_counts;
    int phony_dead_times;
} agent_to_cm_coordinate_status_report_old;

typedef struct agent_to_cm_coordinate_status_report_st {
    int msg_type;
    uint32 node;
    uint32 instanceId;
    int instanceType;
    int connectStatus;
    int processStatus;
    int isCentral;
    char nodename[NAMEDATALEN];
    char logicClusterName[CM_LOGIC_CLUSTER_NAME_LEN];
    char cnodename[NAMEDATALEN];
    cm_coordinate_replconninfo status;
    cm_coordinate_group_mode group_mode;
    bool cleanDropCnFlag;
    bool isCnDnDisconnected;
    uint32 cn_active_info[CN_INFO_NUM];
    int buildReason;
    char resevered[RESERVE_NUM - 4];
    int cn_restart_counts;
    int phony_dead_times;
} agent_to_cm_coordinate_status_report;

typedef struct agent_to_cm_coordinate_status_report_v1_st {
    int msg_type;
    uint32 node;
    uint32 instanceId;
    int instanceType;
    int connectStatus;
    int processStatus;
    int isCentral;
    char nodename[NAMEDATALEN];
    char logicClusterName[CM_LOGIC_CLUSTER_NAME_LEN];
    char cnodename[NAMEDATALEN];
    cm_coordinate_replconninfo status;
    cm_coordinate_group_mode group_mode;
    bool cleanDropCnFlag;
    bool isCnDnDisconnected;
    uint32 cn_active_info[CN_INFO_NUM];
    int buildReason;
    int cn_dn_disconnect_times;
    char resevered[RESERVE_NUM - (2 * RESERVE_NUM_USED)];
    int cn_restart_counts;
    int phony_dead_times;
} agent_to_cm_coordinate_status_report_v1;

typedef struct agent_to_cm_fenced_UDF_status_report_st {
    int msg_type;
    uint32 nodeid;
    int status;
} agent_to_cm_fenced_UDF_status_report;

typedef struct agent_to_cm_ondemand_status_report {
    int msg_type;
    uint32 nodeId;
    int onDemandStatus;
    time_t reportTime;
} agent_to_cm_ondemand_status_report;

typedef struct agent_to_cm_datanode_status_report_st {
    int msg_type;
    uint32 node;
    uint32 instanceId;
    int instanceType;
    int connectStatus;
    int processStatus;
    cm_local_replconninfo local_status;
    BuildState build_info;
    cm_sender_replconninfo sender_status[CM_MAX_SENDER_NUM];
    cm_receiver_replconninfo receive_status;
    RedoStatsData parallel_redo_status;
    cm_redo_stats local_redo_stats;
    int dn_restart_counts;
    int phony_dead_times;
    int dn_restart_counts_in_hour;
    int dnVipStatus;
} agent_to_cm_datanode_status_report;

typedef struct AgentToCmserverDnSyncListSt {
    int msg_type;
    uint32 node;
    uint32 instanceId;
    int instanceType;
    char dnSynLists[DN_SYNC_LEN];
    // remain
    int syncDone; // remain[0]
    int remain[REMAIN_LEN - 1];
    char remainStr[DN_SYNC_LEN];
} AgentToCmserverDnSyncList;

typedef struct AgentToCmserverDnSyncAvailableSt {
    int msg_type;
    uint32 node;
    uint32 instanceId;
    int instanceType;
    char dnSynLists[DN_SYNC_LEN];
    char syncStandbyNames[DN_SYNC_LEN];
    char syncCommit[REMAIN_LEN-1];
    bool dnAvailableSyncStatus;
} AgentToCmserverDnSyncAvailable;

typedef struct agent_to_cm_gtm_status_report_st {
    int msg_type;
    uint32 node;
    uint32 instanceId;
    int instanceType;
    int connectStatus;
    int processStatus;
    cm_gtm_replconninfo status;
    int phony_dead_times;
} agent_to_cm_gtm_status_report;

typedef struct agent_to_cm_current_time_report_st {
    int msg_type;
    uint32 nodeid;
    long int etcd_time;
} agent_to_cm_current_time_report;

typedef enum {
    READ_ONLY_DDB_INIT = 0,
    READ_ONLY_EXPECT = 1,
    READ_ONLY_ALREADY = 2,
    READ_ONLY_NOT_EXPECT = 3,
    READ_ONLY_DDB_MAX
} ReadOnlyDdbValue;

typedef enum {
    READ_ONLY_INIT,
    READ_ONLY_ON,
    READ_ONLY_OFF
} ReadOnlyState;

typedef struct {
    int msgType;
    uint32 instanceId;
    uint32 dataPathUsage;
    uint32 logPathUsage;
    uint32 vgdataPathUsage;
    uint32 vglogPathUsage;
    int instanceType;
    ReadOnlyState readOnly;
    char reserved[16];
} AgentToCmDiskUsageStatusReport;

typedef struct agent_to_cm_heartbeat_st {
    int msg_type;
    uint32 node;
    uint32 instanceId;
    int instanceType;
    int cluster_status_request;
} agent_to_cm_heartbeat;

typedef struct AgentToCmConnectRequestSt {
    int msg_type;
    uint32 nodeid;
} AgentToCmConnectRequest;

typedef struct CmToAgentConnectAckSt {
    int msg_type;
    uint32 status;
} CmToAgentConnectAck;

typedef struct DnLocalPeer_t {
    char localIp[CM_IP_LENGTH];
    char peerIp[CM_IP_LENGTH];
    uint32 localPort;
    uint32 peerPort;
    char reserver[DN_SYNC_LEN];
} DnLocalPeer;

typedef struct AgentCmDnLocalPeer_t {
    int32 msgType;
    uint32 node;
    uint32 instanceId;
    int32 instanceType;
    DnLocalPeer dnLpInfo;
} AgentCmDnLocalPeer;

const uint32 MAX_FLOAT_IP_COUNT = 6;

const uint32 BASE_INST_RES = 16;
typedef struct BaseInstInfoT {
    int msgType;
    uint32 node;
    uint32 instId;  // instanceId
    int instType;   // instanceType
    char remain[BASE_INST_RES];
} BaseInstInfo;

const uint32 FLOAT_IP_MSG_RES = 512;

typedef struct DnFloatIpInfoT {
    uint32 count;
    int32 dnNetState[MAX_FLOAT_IP_COUNT];
    int32 nicNetState[MAX_FLOAT_IP_COUNT];
} DnFloatIpInfo;

typedef struct CmaDnFloatIpInfoT {
    BaseInstInfo baseInfo;
    DnFloatIpInfo info;
    char remain[FLOAT_IP_MSG_RES];
} CmaDnFloatIpInfo;

typedef struct CmsDnFloatIpAckT {
    BaseInstInfo baseInfo;
    int32 oper;
    char remain[FLOAT_IP_MSG_RES];
} CmsDnFloatIpAck;

typedef struct DnStatus_t {
    CM_MessageType barrierMsgType;
    agent_to_cm_datanode_status_report reportMsg;
    union {
        AgentToCmBarrierStatusReport barrierMsg;
        Agent2CmBarrierStatusReport barrierMsgNew;
    };
    AgentCmDnLocalPeer lpInfo;
    AgentToCmDiskUsageStatusReport diskUsageMsg;
    CmaDnFloatIpInfo floatIpInfo;
} DnStatus;

typedef struct DnSyncListInfo_t {
    pthread_rwlock_t lk_lock;
    AgentToCmserverDnSyncList dnSyncListMsg;
} DnSyncListInfo;

typedef struct CnStatus_t {
    CM_MessageType barrierMsgType;
    agent_to_cm_coordinate_status_report reportMsg;
    Agent2CmBackupInfoRep backupMsg;
    union {
        AgentToCmBarrierStatusReport barrierMsg;
        Agent2CmBarrierStatusReport barrierMsgNew;
    };
    AgentToCmDiskUsageStatusReport diskUsageMsg;
} CnStatus;

typedef struct coordinate_status_info_st {
    pthread_rwlock_t lk_lock;
    CnStatus cnStatus;
} coordinate_status_info;

typedef struct datanode_status_info_st {
    pthread_rwlock_t lk_lock;
    DnStatus dnStatus;
} datanode_status_info;

typedef struct gtm_status_info_st {
    pthread_rwlock_t lk_lock;
    agent_to_cm_gtm_status_report report_msg;
} gtm_status_info;

typedef struct cm_to_agent_heartbeat_st {
    int msg_type;
    uint32 node;
    int type;
    int cluster_status;
    uint32 healthInstanceId;
} cm_to_agent_heartbeat;

typedef struct cm_to_cm_vote_st {
    int msg_type;
    uint32 node;
    uint32 instanceId;
    int role;
} cm_to_cm_vote;

typedef struct cm_to_cm_timeline_st {
    int msg_type;
    uint32 node;
    uint32 instanceId;
    long timeline;
} cm_to_cm_timeline;

typedef struct cm_to_cm_broadcast_st {
    int msg_type;
    uint32 node;
    uint32 instanceId;
    int role;
} cm_to_cm_broadcast;

typedef struct cm_to_cm_notify_st {
    int msg_type;
    int role;
} cm_to_cm_notify;

typedef struct cm_to_cm_switchover_st {
    int msg_type;
    uint32 node;
    uint32 instanceId;
    int instance_type;
    int wait_seconds;
} cm_to_cm_switchover;

typedef struct cm_to_cm_switchover_ack_st {
    int msg_type;
    uint32 node;
    uint32 instanceId;
    int instance_type;
    int wait_seconds;
} cm_to_cm_switchover_ack;

typedef struct cm_to_cm_failover_st {
    int msg_type;
    uint32 node;
    uint32 instanceId;
    int instance_type;
    int wait_seconds;
} cm_to_cm_failover;

typedef struct cm_to_cm_failover_ack_st {
    int msg_type;
    uint32 node;
    uint32 instanceId;
    int instance_type;
    int wait_seconds;
} cm_to_cm_failover_ack;

typedef struct cm_to_cm_sync_st {
    int msg_type;
    int role;
} cm_to_cm_sync;

typedef struct cm_instance_command_status_st {
    int command_status;
    int command_send_status;
    int command_send_times;
    int command_send_num;
    int pengding_command;
    int cmdPur; // purpose
    int cmdSour; // source
    int cmdRealPur; // real purpose
    uint32 peerInstId;
    int time_out;
    int delaySwitchoverTime;
    int role_changed;
    volatile int heat_beat;
    int arbitrate_delay_time_out;
    int arbitrate_delay_set;
    int local_arbitrate_delay_role;
    int peerl_arbitrate_delay_role;
    int full_build;
    int notifyCnCount;
    volatile int keep_heartbeat_timeout;
    int sync_mode;
    int maxSendTimes;
    int parallel;
    int32 buildFailedTimeout;
    cmTime_t cmTime; // use to record time
    uint8 msgProcFlag;
} cm_instance_command_status;

typedef struct DatanodelocalPeer_t {
    uint32 ipCount;
    char localIp[CM_IP_NUM][CM_IP_LENGTH];
    uint32 localPort;
    uint32 peerInst;
} DatanodelocalPeer;

typedef struct CmDnReportStatusMsgT {
    cm_local_replconninfo local_status;
    int sender_count;
    BuildState build_info;
    cm_sender_replconninfo sender_status[CM_MAX_SENDER_NUM];
    cm_receiver_replconninfo receive_status;
    RedoStatsData parallel_redo_status;
    cm_redo_stats local_redo_stats;
    synchronous_standby_mode sync_standby_mode;
    int send_gs_guc_time;
    int dn_restart_counts;
    bool arbitrateFlag;
    int failoverStep;
    int failoverTimeout;
    int phony_dead_times;
    int phony_dead_interval;
    int dn_restart_counts_in_hour;
    bool is_finish_redo_cmd_sent;
    uint64 ckpt_redo_point;
    char barrierID[BARRIERLEN];
    char query_barrierId[BARRIERLEN];
    uint64 barrierLSN;
    uint64 archive_LSN;
    uint64 flush_LSN;
    DatanodeSyncList dnSyncList;
    int32 syncDone;
    uint32 arbiTime;
    uint32 sendFailoverTimes;
    bool is_barrier_exist;
    cmTime_t printBegin; // print synclist time
    DatanodelocalPeer dnLp;
} CmDnReportStatusMsg;

typedef struct DataNodeReadOnlyInfoT DataNodeReadOnlyInfo;

// need to keep consist with cm_to_ctl_instance_datanode_status
typedef struct cm_instance_datanode_report_status_st {
    cm_local_replconninfo local_status;
    int sender_count;
    BuildState build_info;
    cm_sender_replconninfo sender_status[CM_MAX_SENDER_NUM];
    cm_receiver_replconninfo receive_status;
    RedoStatsData parallel_redo_status;
    cm_redo_stats local_redo_stats;
    synchronous_standby_mode sync_standby_mode;
    int send_gs_guc_time;
    int dn_restart_counts;
    bool arbitrateFlag;
    int failoverStep;
    int failoverTimeout;
    int phony_dead_times;
    int phony_dead_interval;
    int dn_restart_counts_in_hour;
    int dnVipStatus;
    bool is_finish_redo_cmd_sent;
    uint64 ckpt_redo_point;
    char barrierID[BARRIERLEN];
    char query_barrierId[BARRIERLEN];
    uint64 barrierLSN;
    uint64 archive_LSN;
    uint64 flush_LSN;
    DatanodeSyncList dnSyncList;
    int32 syncDone;
    uint32 arbiTime;
    uint32 sendFailoverTimes;
    bool is_barrier_exist;
    cmTime_t printBegin; // print synclist time
    DatanodelocalPeer dnLp;
    DnFloatIpInfo floatIp;
    DataNodeReadOnlyInfo *readOnly;
} cm_instance_datanode_report_status;

typedef struct cm_instance_gtm_report_status_st {
    cm_gtm_replconninfo local_status;
    int phony_dead_times;
    int phony_dead_interval;
} cm_instance_gtm_report_status;

/*
 * each coordinator manage a list of datanode notify status
 */
typedef struct cm_notify_msg_status_st {
    uint32* datanode_instance;
    uint32* datanode_index;
    bool* notify_status;
    bool* have_notified;
    bool* have_dropped;
    bool have_canceled;
    uint32 gtmIdBroadCast;
} cm_notify_msg_status;

#define OBS_BACKUP_INIT         (0)    // not start
#define OBS_BACKUP_PROCESSING   (1)
#define OBS_BACKUP_COMPLETED    (2)
#define OBS_BACKUP_FAILED       (3)
#define OBS_BACKUP_UNKNOWN      (4)    // conn failed, can't get status, will do nothing until it change to other

typedef struct cm_instance_coordinate_report_status_st {
    cm_coordinate_replconninfo status;
    int isdown;
    int clean;
    uint32 exec_drop_instanceId;
    cm_coordinate_group_mode group_mode;
    cm_notify_msg_status notify_msg;
    char logicClusterName[CM_LOGIC_CLUSTER_NAME_LEN];
    uint32 cn_restart_counts;
    int phony_dead_times;
    int phony_dead_interval;
    bool delay_repair;
    bool isCnDnDisconnected;
    int auto_delete_delay_time;
    int disable_time_out;
    int cma_fault_timeout_to_killcn;

    char barrierID [BARRIERLEN];
    char query_barrierId[BARRIERLEN];
    uint64 barrierLSN;
    uint64 archive_LSN;
    uint64 flush_LSN;
    uint64 ckpt_redo_point;
    bool is_barrier_exist;
    int buildReason;
    DataNodeReadOnlyInfo *readOnly;
} cm_instance_coordinate_report_status;

typedef struct cm_instance_arbitrate_status_st {
    int sync_mode;
    bool restarting;
    int promoting_timeout;
} cm_instance_arbitrate_status;

#define MAX_CM_TO_CM_REPORT_SYNC_COUNT_PER_CYCLE 5
typedef struct cm_to_cm_report_sync_st {
    int msg_type;
    uint32 node[CM_PRIMARY_STANDBY_NUM];
    uint32 instanceId[CM_PRIMARY_STANDBY_NUM];
    int instance_type[CM_PRIMARY_STANDBY_NUM];
    cm_instance_command_status command_member[CM_PRIMARY_STANDBY_NUM];
    cm_instance_datanode_report_status data_node_member[CM_PRIMARY_STANDBY_NUM];
    cm_instance_gtm_report_status gtm_member[CM_PRIMARY_STANDBY_NUM];
    cm_instance_coordinate_report_status coordinatemember;
    cm_instance_arbitrate_status arbitrate_status_member[CM_PRIMARY_STANDBY_NUM];
} cm_to_cm_report_sync;

typedef struct cm_instance_role_status_st {
    // available zone information
    char azName[CM_AZ_NAME];
    uint32 azPriority;

    uint32 node;
    uint32 instanceId;
    int instanceType;
    int role;
    int dataReplicationMode;
    int instanceRoleInit;
} cm_instance_role_status;

typedef struct cm_instance_role_status_0_st {
    uint32 node;
    uint32 instanceId;
    int instanceType;
    int role;
    int dataReplicationMode;
    int instanceRoleInit;
} cm_instance_role_status_0;

#define CM_PRIMARY_STANDBY_MAX_NUM_0 3  // support master standby dummy

#if ((defined(ENABLE_MULTIPLE_NODES)) || (defined(ENABLE_PRIVATEGAUSS)))
#define CM_PRIMARY_STANDBY_MAX_NUM 8    // supprot 1 primary and [1, 7] standby
#else
#define CM_PRIMARY_STANDBY_MAX_NUM 9    // supprot 1 primary and [1, 7] standby
#endif

typedef struct cm_instance_role_group_0_st {
    int count;
    cm_instance_role_status_0 instanceMember[CM_PRIMARY_STANDBY_MAX_NUM_0];
} cm_instance_role_group_0;

typedef struct cm_instance_role_group_st {
    int count;
    cm_instance_role_status instanceMember[CM_PRIMARY_STANDBY_MAX_NUM];
} cm_instance_role_group;

typedef struct cm_to_cm_role_change_notify_st {
    int msg_type;
    cm_instance_role_group role_change;
} cm_to_cm_role_change_notify;

typedef struct ctl_to_cm_datanode_relation_info_st {
    int msg_type;
    uint32 node;
    uint32 instanceId;
    int instance_type;
    int wait_seconds;
} ctl_to_cm_datanode_relation_info;

typedef struct cm_to_ctl_get_datanode_relation_ack_st {
    int command_result;
    int member_index;
    cm_instance_role_status instanceMember[CM_PRIMARY_STANDBY_MAX_NUM];
    cm_instance_gtm_report_status gtm_member[CM_PRIMARY_STANDBY_NUM];
    CmDnReportStatusMsg data_node_member[CM_PRIMARY_STANDBY_MAX_NUM];
} cm_to_ctl_get_datanode_relation_ack;

// need to keep consist with the struct cm_instance_datanode_report_status
typedef struct cm_to_ctl_instance_datanode_status_st {
    cm_local_replconninfo local_status;
    int sender_count;
    BuildState build_info;
    cm_sender_replconninfo sender_status[CM_MAX_SENDER_NUM];
    cm_receiver_replconninfo receive_status;
    RedoStatsData parallel_redo_status;
    cm_redo_stats local_redo_stats;
    synchronous_standby_mode sync_standby_mode;
    int send_gs_guc_time;
} cm_to_ctl_instance_datanode_status;

typedef struct cm_to_ctl_instance_gtm_status_st {
    cm_gtm_replconninfo local_status;
} cm_to_ctl_instance_gtm_status;

typedef struct cm_to_ctl_instance_coordinate_status_st {
    int status;
    cm_coordinate_group_mode group_mode;
    /* no notify map in ctl */
} cm_to_ctl_instance_coordinate_status;

typedef struct CmResourceStatusSt {
    char resName[CM_MAX_RES_NAME];
    uint32 nodeId;
    uint32 cmInstanceId;
    uint32 resInstanceId;
    uint32 status; // process status.
    uint32 workStatus;
} CmResourceStatus;

typedef struct OneNodeResourceStatusSt {
    uint32 node;
    uint32 count;
    CmResourceStatus status[CM_MAX_RES_COUNT];
} OneNodeResourceStatus;

typedef struct ResourceStatusReportSt {
    pthread_rwlock_t rwlock;
    OneNodeResourceStatus resStat;
} OneNodeResStatusInfo;

typedef struct cm_to_ctl_instance_status_st {
    int msg_type;
    uint32 node;
    uint32 instanceId;
    int instance_type;
    int member_index;
    int is_central;
    int fenced_UDF_status;
    cm_to_ctl_instance_datanode_status data_node_member;
    cm_to_ctl_instance_gtm_status gtm_member;
    cm_to_ctl_instance_coordinate_status coordinatemember;
} cm_to_ctl_instance_status;

typedef struct cm_to_ctl_instance_barrier_info_st {
    int msg_type;
    uint32 node;
    uint32 instanceId;
    int instance_type;
    int member_index;
    uint64 ckpt_redo_point;
    char barrierID [BARRIERLEN];
    uint64 barrierLSN;
    uint64 archive_LSN;
    uint64 flush_LSN;
} cm_to_ctl_instance_barrier_info;

typedef struct cm_to_ctl_central_node_status_st {
    uint32 instanceId;
    int node_index;
    int status;
} cm_to_ctl_central_node_status;

#define CM_CAN_PRCESS_COMMAND 0
#define CM_ANOTHER_COMMAND_RUNNING 1
#define CM_INVALID_COMMAND 2
#define CM_DN_NORMAL_STATE 3
#define CM_DN_IN_ONDEMAND_STATUE 4

typedef struct cm_to_ctl_command_ack_st {
    int msg_type;
    int command_result;
    uint32 node;
    uint32 instanceId;
    int instance_type;
    int command_status;
    int pengding_command;
    int time_out;
    bool isCmsBuildStepSuccess;
} cm_to_ctl_command_ack;

typedef struct cm_to_ctl_balance_check_ack_st {
    int msg_type;
    int switchoverDone;
} cm_to_ctl_balance_check_ack;

typedef struct cm_to_ctl_switchover_full_check_ack_st {
    int msg_type;
    int switchoverDone;
} cm_to_ctl_switchover_full_check_ack, cm_to_ctl_switchover_az_check_ack;

#define MAX_INSTANCES_LEN 512
typedef struct cm_to_ctl_balance_result_st {
    int msg_type;
    int imbalanceCount;
    uint32 instances[MAX_INSTANCES_LEN];
} cm_to_ctl_balance_result;

#define CM_STATUS_STARTING 0
#define CM_STATUS_PENDING 1
#define CM_STATUS_NORMAL 2
#define CM_STATUS_NEED_REPAIR 3
#define CM_STATUS_DEGRADE 4
#define CM_STATUS_UNKNOWN 5
#define CM_STATUS_NORMAL_WITH_CN_DELETED 6

typedef struct cm_to_ctl_cluster_status_st {
    int msg_type;
    int cluster_status;
    bool is_all_group_mode_pending;
    int switchedCount;
    int node_id;
    bool inReloading;
} cm_to_ctl_cluster_status;

typedef struct cm_to_ctl_cluster_global_barrier_info_st {
    int msg_type;
    char global_barrierId[BARRIERLEN];
    char global_achive_barrierId[BARRIERLEN];
    char globalRecoveryBarrierId[BARRIERLEN];
} cm_to_ctl_cluster_global_barrier_info;

typedef struct cm2CtlGlobalBarrierNew_t {
    int msg_type;
    char globalRecoveryBarrierId[BARRIERLEN];
    GlobalBarrierStatus globalStatus;
} cm2CtlGlobalBarrierNew;

typedef struct CmsSharedStorageInfoSt {
    int msg_type;
    char doradoIp[CM_IP_LENGTH];
} CmsSharedStorageInfo;

typedef struct GetSharedStorageInfoSt {
    int msg_type;
} GetSharedStorageInfo;

typedef struct cm_to_ctl_logic_cluster_status_st {
    int msg_type;
    int cluster_status;
    bool is_all_group_mode_pending;
    int switchedCount;
    bool inReloading;

    int logic_cluster_status[LOGIC_CLUSTER_NUMBER];
    bool logic_is_all_group_mode_pending[LOGIC_CLUSTER_NUMBER];
    int logic_switchedCount[LOGIC_CLUSTER_NUMBER];
} cm_to_ctl_logic_cluster_status;

typedef struct cm_to_ctl_cmserver_status_st {
    int msg_type;
    int local_role;
    bool is_pending;
} cm_to_ctl_cmserver_status;

typedef struct cm_query_instance_status_st {
    int msg_type;
    uint32 nodeId;
    uint32 instanceType;  // only for etcd and cmserver
    uint32 msg_step;
    uint32 status;
    bool pending;
} cm_query_instance_status;

typedef struct CmRhbMsg_ {
    int msg_type;
    uint32 nodeId;
    uint32 hwl;
    time_t hbs[MAX_RHB_NUM];
} CmRhbMsg;

typedef struct CmShowStatReq_ {
    int msgType;
} CmShowStatReq;

typedef struct CmRhbStatAck_ {
    int msg_type;
    time_t baseTime;
    uint32 timeout;
    uint32 hwl;
    time_t hbs[MAX_RHB_NUM][MAX_RHB_NUM];
} CmRhbStatAck;

typedef struct CmNodeDiskStatAck_ {
    int msg_type;
    time_t baseTime;
    uint32 timeout;
    uint32 hwl;
    time_t nodeDiskStats[VOTING_DISK_MAX_NODE_NUM];
} CmNodeDiskStatAck;

typedef struct etcd_status_info_st {
    pthread_rwlock_t lk_lock;
    cm_query_instance_status report_msg;
} etcd_status_info;

/* kerberos information */
#define ENV_MAX 100
#define ENVLUE_NUM 3
#define MAX_BUFF 1024
#define MAXLEN 20
#define KERBEROS_NUM 2

typedef struct agent_to_cm_kerberos_status_report_st {
    int msg_type;
    uint32 node;
    char kerberos_ip[CM_IP_LENGTH];
    uint32 port;
    uint32 status;
    char role[MAXLEN];
    char nodeName[CM_NODE_NAME];
} agent_to_cm_kerberos_status_report;

typedef struct kerberos_status_info_st {
    pthread_rwlock_t lk_lock;
    agent_to_cm_kerberos_status_report report_msg;
} kerberos_status_info;

typedef struct cm_to_ctl_kerberos_status_query_st {
    int msg_type;
    uint32 heartbeat[KERBEROS_NUM];
    uint32 node[KERBEROS_NUM];
    char kerberos_ip[KERBEROS_NUM][CM_IP_LENGTH];
    uint32 port[KERBEROS_NUM];
    uint32 status[KERBEROS_NUM];
    char role[KERBEROS_NUM][MAXLEN];
    char nodeName[KERBEROS_NUM][CM_NODE_NAME];
} cm_to_ctl_kerberos_status_query;

typedef struct kerberos_group_report_status_st {
    pthread_rwlock_t lk_lock;
    cm_to_ctl_kerberos_status_query kerberos_status;
} kerberos_group_report_status;


/* ----------------
 *        Special transaction ID values
 *
 * BootstrapTransactionId is the XID for "bootstrap" operations, and
 * FrozenTransactionId is used for very old tuples.  Both should
 * always be considered valid.
 *
 * FirstNormalTransactionId is the first "normal" transaction id.
 * Note: if you need to change it, you must change pg_class.h as well.
 * ----------------
 */
#define InvalidTransactionId ((TransactionId)0)
#define BootstrapTransactionId ((TransactionId)1)
#define FrozenTransactionId ((TransactionId)2)
#define FirstNormalTransactionId ((TransactionId)3)
#define MaxTransactionId ((TransactionId)0xFFFFFFFF)

/* ----------------
 *        transaction ID manipulation macros
 * ----------------
 */
#define TransactionIdIsValid(xid) ((xid) != InvalidTransactionId)
#define TransactionIdIsNormal(xid) ((xid) >= FirstNormalTransactionId)
#define TransactionIdEquals(id1, id2) ((id1) == (id2))
#define TransactionIdStore(xid, dest) (*(dest) = (xid))
#define StoreInvalidTransactionId(dest) (*(dest) = InvalidTransactionId)

/*
 * Macros for comparing XLogRecPtrs
 *
 * Beware of passing expressions with side-effects to these macros,
 * since the arguments may be evaluated multiple times.
 */
#ifndef XLByteLT
#define XLByteLT(a, b) ((a) < (b))
#endif
#ifndef XLByteLE
#define XLByteLE(a, b) ((a) <= (b))
#endif
#ifndef XLByteEQ
#define XLByteEQ(a, b) ((a) == (b))
#endif

#define InvalidTerm (0)
#define FirstTerm (2)
#define TermIsInvalid(term) ((term) == InvalidTerm)

#define XLByteLT_W_TERM(a_term, a_logptr, b_term, b_logptr) \
    (((a_term) < (b_term)) || (((a_term) == (b_term)) && ((a_logptr) < (b_logptr))))
#define XLByteLE_W_TERM(a_term, a_logptr, b_term, b_logptr) \
    (((a_term) < (b_term)) || (((a_term) == (b_term)) && ((a_logptr) <= (b_logptr))))
#define XLByteEQ_W_TERM(a_term, a_logptr, b_term, b_logptr) (((a_term) == (b_term)) && ((a_logptr) == (b_logptr)))
#define XLByteWE_W_TERM(a_term, a_logptr, b_term, b_logptr) \
    (((a_term) > (b_term)) || (((a_term) == (b_term)) && ((a_logptr) > (b_logptr))))


#define CM_RESULT_COMM_ERROR (-2) /* Communication error */
#define CM_RESULT_ERROR (-1)
#define CM_RESULT_OK (0)
/*
 * This error is used ion the case where allocated buffer is not large
 * enough to store the errors. It may happen of an allocation failed
 * so it's status is considered as unknown.
 */
#define CM_RESULT_UNKNOWN (1)

typedef struct ResultDataPackedSt {
    char pad[CM_MSG_MAX_LENGTH];
} ResultDataPacked;

typedef union CM_ResultData_st {
    ResultDataPacked packed;
} CM_ResultData;

typedef struct CM_Result_st {
    int gr_msglen;
    int gr_status;
    int gr_type;
    CM_ResultData gr_resdata;
} CM_Result;

extern int query_gtm_status_wrapper(const char pid_path[MAXPGPATH], agent_to_cm_gtm_status_report& agent_to_cm_gtm);
extern int query_gtm_status_for_phony_dead(const char pid_path[MAXPGPATH]);

typedef struct CtlToCMReloadSt {
    int msgType;
} CtlToCMReload;

typedef struct CMToCtlReloadAckSt {
    int msgType;
    bool reloadOk;
} CMToCtlReloadAck;

typedef struct ExecDdbCmdMsgSt {
    int msgType;
    char cmdLine[DCC_CMD_MAX_LEN];
} ExecDdbCmdMsg;

typedef struct ExecDdbCmdAckMsgSt {
    int msgType;
    bool isSuccess;
    char output[DCC_CMD_MAX_OUTPUT_LEN];
    int outputLen;
    char errMsg[ERR_MSG_LENGTH];
} ExecDdbCmdAckMsg;

typedef struct ResInfoSt {
    uint32 resInstanceId;
    char reserve[4];
    char resName[CM_MAX_RES_NAME];
} ResInfo;

typedef struct LockInfoSt {
    uint32 lockOpt;
    uint32 transInstId;
    char lockName[CM_MAX_LOCK_NAME];
} LockInfo;

typedef enum LockOptionEn {
    CM_RES_LOCK = 0,
    CM_RES_UNLOCK,
    CM_RES_GET_LOCK_OWNER,
    CM_RES_LOCK_TRANS,
} LockOption;

typedef struct InitResultSt {
    bool isSuccess;
    char reserve[7];
} InitResult;

typedef struct LockResultSt {
    uint32 lockOwner;
    uint32 error;
    char lockName[CM_MAX_LOCK_NAME];
} LockResult;

typedef struct CmaNotifyClientSt {
    bool8 isCmaConnClose;
    char reserve[7];
} CmaNotifyClient;

// cms to cma
typedef struct CmsReportResStatListSt {
    int msgType;
    OneResStatList resList;
} CmsReportResStatList;

typedef struct CmsReportLockResultSt {
    int msgType;
    uint32 lockOwner;
    uint32 conId;
    uint32 lockOpt;
    uint32 error;
    char lockName[CM_MAX_LOCK_NAME];
} CmsReportLockResult;

typedef struct CmsNotifyAgentRegMsgSt {
    int msgType;
    int resMode;  // 1:need do reg 0:need do unreg
    uint32 nodeId;  // reg node or unreg node
    uint32 resInstId;  // reg node or unreg res inst
    char resName[CM_MAX_RES_NAME];
    ResIsregStatus resStat;
} CmsNotifyAgentRegMsg;

typedef struct CmsFlushIsregCheckListSt {
    int msgType;
    uint32 checkCount;
    uint32 checkList[CM_MAX_RES_INST_COUNT];
} CmsFlushIsregCheckList;

// cma to cms
typedef struct ReportResStatusSt {
    int msgType;
    OneNodeResourceStatus nodeStat;
} ReportResStatus;

typedef struct RequestResStatListSt {
    int msgType;
} RequestResStatList;

typedef struct RequestLatestStatListSt {
    int msgType;
    unsigned long long statVersion[CM_MAX_RES_COUNT];
} RequestLatestStatList;

typedef struct ResInstIsregSt {
    uint32 cmInstId;
    int isreg;
} ResInstIsreg;

typedef struct CmaToCmsIsregMsgSt {
    int msgType;
    uint32 nodeId;
    uint32 isregCount;
    ResInstIsreg isregList[CM_MAX_RES_INST_COUNT];
} CmaToCmsIsregMsg;

typedef struct CmaToCmsResLockSt {
    int msgType;
    uint32 conId;
    uint32 lockOpt;
    uint32 cmInstId;
    uint32 transInstId;
    char resName[CM_MAX_RES_NAME];
    char lockName[CM_MAX_LOCK_NAME];
} CmaToCmsResLock;

typedef struct MsgHeadSt {
    uint32 msgType;
    uint32 conId;
    uint64 msgVer;
} MsgHead;

// cma to client
typedef struct AgentToClientResListSt {
    MsgHead head;
    OneResStatList resStatusList;
} AgentToClientResList;

typedef struct AgentToClientInitResultSt {
    MsgHead head;
    InitResult result;
} AgentToClientInitResult;

typedef struct AgentToClientResLockResultSt {
    MsgHead head;
    LockResult result;
} AgentToClientResLockResult;

typedef struct AgentToClientNotifySt {
    MsgHead head;
    CmaNotifyClient notify;
} AgentToClientNotify;

// client to cma
typedef struct ClientHbMsgSt {
    MsgHead head;
    uint64 version;
} ClientHbMsg;

typedef struct ClientInitMsgSt {
    MsgHead head;
    ResInfo resInfo;
} ClientInitMsg;

typedef struct ClientCmLockMsgSt {
    MsgHead head;
    LockInfo info;
} ClientCmLockMsg;

// cms to ctl
typedef struct CmsToCtlOneResInstStatSt {
    int msgType;
    CmResStatInfo instStat;
} CmsToCtlOneResInstStat;


typedef struct CmsToCtlGroupResStatusSt {
    int msgType;
    int msgStep;
    OneResStatList oneResStat;
} CmsToCtlGroupResStatus;

// ctl to cms
typedef struct QueryOneResInstStatSt {
    int msgType;
    uint32 instId;
} QueryOneResInstStat;

typedef struct CmsSSLConnSt {
    uint64 startConnTime;
} CmsSSLConnMsg;

typedef struct CmFloatIpStatInfoT {
    uint32 nodeId;
    uint32 instId;
    uint32 count;
    int32 nicNetState[MAX_FLOAT_IP_COUNT];
} CmFloatIpStatInfo;

typedef struct CmSendPingDnFloatIpFailSt {
    BaseInstInfo baseInfo;
    uint32 failedCount;
    char failedDnFloatIp[MAX_FLOAT_IP_COUNT][CM_IP_LENGTH];
} CmSendPingDnFloatIpFail;

typedef struct CmFloatIpStatAckT {
    int32 msgType;
    bool8 canShow;
    char reserved1[3];   // for alignment
    char reserved2[52];  // the reserved
    uint32 count;
    CmFloatIpStatInfo info[0];
} CmFloatIpStatAck;  // the totol size is 64

#endif
