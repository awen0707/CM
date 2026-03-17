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
 * cms_global_params.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_server/cms_global_params.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CMS_GLOBAL_PARAMS_H
#define CMS_GLOBAL_PARAMS_H

#include <vector>
#include <string>
#include <set>
#include "common/config/cm_config.h"
#include "alarm/alarm.h"
#include "cm_server.h"
#include "cm/cm_c.h"
#include "cm/cm_misc.h"
#include "cm_server.h"
#include "cms_conn.h"

using std::set;
using std::string;
using std::vector;


typedef struct azInfoT {
    char azName[CM_AZ_NAME];
    uint32 nodes[CM_NODE_MAXNUM];
} azInfo;

typedef enum CMS_OPERATION_ {
    CMS_SWITCHOVER_DN = 0,
    CMS_FAILOVER_DN,
    CMS_BUILD_DN,
    CMS_DROP_CN,
    CMS_PHONY_DEAD_CHECK,
    CMS_FAILOVER_DN_NEW,
    CMS_BUILD_CN,
} cms_operation;

typedef enum MAINTENANCE_MODE_ {
    MAINTENANCE_MODE_NONE = 0,
    MAINTENANCE_MODE_UPGRADE,
    MAINTENANCE_MODE_UPGRADE_OBSERVATION,
    MAINTENANCE_MODE_DILATATION,
    MAINTENANCE_NODE_UPGRADED_GRAYSCALE,
    MAINTENANCE_NODE_DISASTER_RECOVERY
} maintenance_mode;

typedef enum REDUCE_INCREASE_SYNCLIST_ {
    CANNOT_START_SYNCLIST_THREADS = 0,
    SYNCLIST_THREADS_IN_SLEEP,
    SYNCLIST_THREADS_IN_PROCESS,
    SYNCLIST_THREADS_IN_MAINTENANCE,
    SYNCLIST_THREADS_IN_DDB_BAD
} reduceOrIncreaseSyncLists;

typedef enum CHECK_SYNCLIST_EN {
    SYNCLIST_IS_FINISTH = 0,
    SYNCLIST_IS_NOT_SAME,
    INST_IS_NOT_IN_SYNCLIST
} EnCheckSynclist;

typedef enum GET_HEART_BEAT_FROM_ETCD {
    CANNOT_GET_HEARTBEAT = 0,
    CAN_GET_HEARTBEART
} getHeartBeatFromEtcd;

typedef enum DDB_WORK_MODE_ {
    DDB_WORK_MODE_MAJORITY = 0,
    DDB_WORK_MODE_MINORITY,
    DDB_WORK_MODE_NONE,
} ddb_work_mode;

/* data structures to record instances that are in switchover procedure */
typedef struct switchover_instance_t {
    uint32 node;
    uint32 instanceId;
    int instanceType;
} switchover_instance;
typedef struct DataNodeReadOnlyInfoT {
    uint32 node;
    uint32 instanceId;
    uint32 groupIndex;
    int memberIndex;
    uint32 vgdataDiskUsage;
    uint32 vglogDiskUsage;
    int dataDiskUsage;
    int instanceType;
    char ddbValue;
    ReadOnlyState readOnly;
    bool finalState;
    char dataNodePath[CM_PATH_LENGTH];
    char instanceName[CM_NODE_NAME];
    char nodeName[CM_NODE_NAME];
} DataNodeReadOnlyInfo;

typedef struct InstanceStatusKeyValueT {
    char key[ETCD_KEY_LENGTH];
    char value[ETCD_VLAUE_LENGTH];
} InstanceStatusKeyValue;

typedef struct DynamicNodeReadOnlyInfoT {
    char instanceName[CM_NODE_NAME];
    uint32 dataNodeCount;
    uint32 logDiskUsage;
    DataNodeReadOnlyInfo dataNode[CM_MAX_DATANODE_PER_NODE];
    DataNodeReadOnlyInfo coordinateNode;
} DynamicNodeReadOnlyInfo;

typedef struct CurrentInstanceStatusT {
        // recode online dns
    DatanodeDynamicStatus statusDnOnline;
    // recode fail dns
    DatanodeDynamicStatus statusDnFail;
    // recode primary dns
    DatanodeDynamicStatus statusPrimary;
    // recode primary normal dns
    DatanodeDynamicStatus norPrimary;
    // recode vote az dns
    DatanodeDynamicStatus statusDnVoteAz;
} CurrentInstanceStatus;

typedef struct CmsArbitrateStatusT {
    bool isDdbHealth;
    int32 cmsRole;
    maintenance_mode upgradeMode;
} CmsArbitrateStatus;

typedef enum ThreadProcessStatusE {
    THREAD_PROCESS_INIT = 0,
    THREAD_PROCESS_READY,
    THREAD_PROCESS_UNKNOWN,
    THREAD_PROCESS_RUNNING,
    THREAD_PROCESS_STOP,
    THREAD_PROCESS_SLEEP,
    THREAD_PROCESS_CEIL,  // it must be end
} ThreadProcessStatus;

#define ELASTICGROUP "elastic_group"

#define CMS_CURRENT_VERSION 1
#define LOGIC_CLUSTER_LIST "logic_cluster_name.txt"
#define CM_STATIC_CONFIG_FILE "cluster_static_config"
#define CM_CLUSTER_MANUAL_START "cluster_manual_start"
#define CM_INSTANCE_MANUAL_START "instance_manual_start"
#define MINORITY_AZ_START "minority_az_start"
#define CMS_PMODE_FILE_NAME "promote_mode_cms"
#define MINORITY_AZ_ARBITRATE "minority_az_arbitrate_hist"
#define INSTANCE_MAINTANCE "instance_maintance"
#define CM_PID_FILE "cm_server.pid"
#define CLUSTER_MAINTANCE "cluster_maintance"
#define CM_CLUSTER_MANUAL_PAUSE "cluster_manual_pause"

#define PRIMARY "PRIMARY"
#define STANDBY "STANDBY"
#define DELETED "DELETED"
#define DELETING "DELETING"
#define UNKNOWN "UNKNOWN"
#define NORMAL "NORMAL"
#define DATANODE_ALL 0
#define READONLY_OFF 0
#define READONLY_ON 1
#define DN_RESTART_COUNTS 3         /* DN restarts frequently due to core down */
#define DN_RESTART_COUNTS_IN_HOUR 8 /* DN restarts in hour */
#define TRY_TIME_GET_STATUSONLINE_FROM_DDB 1
#define CMA_KILL_INSTANCE_BALANCE_TIME 10
/*
 * the sum of cm_server heartbeat timeout and arbitrate delay time must be less than
 * cm_agent disconnected timeout. or else, cm_agent may self-kill before cm_server
 * standby failover.
 */
#define AZ_MEMBER_MAX_COUNT (3)
#define INIT_CLUSTER_MODE_INSTANCE_DEAL_TIME 180
#define CM_SERVER_ARBITRATE_DELAY_CYCLE_MAX_COUNT 3
#define THREAHOLD_LEN 10
#define BYTENUM 4
#define SWITCHOVER_SEND_CHECK_NUM 3
#define MAX_VALUE_OF_CM_PRIMARY_HEARTBEAT 86400
#define MAX_COUNT_OF_NOTIFY_CN 86400
#define MAX_VALUE_OF_PRINT 86400
#define CM_MAX_AUTH_TOKEN_LENGTH 65535
#define INSTANCE_ID_LEN 5
#define CM_GS_GUC_SEND_INTERVAL 3
#define ClUSTER_STARTINT_STATUS_TIME_OUT 5
#define CLUSTER_STARTING_ARBIT_DELAY 180
#define INSTANCE_HEARTBEAT_TIMEOUT_FOR_E2E_RTO 4

#define CN_DELETE_DELAY_SECONDS 10
#define MAX_QUERY_DOWN_COUNTS 30

#define INSTANCE_DATA_NO_REDUCED 0 //  no reduce shard instanceId
#define INSTANCE_DATA_REDUCED 1   // reduce shard instanceId
#define INSTANCE_DATA_IN_VOTE 2

#define AZ1_INDEX 0                              // for the index flag, az1
#define AZ2_INDEX 1                              // for the index flag, az2
#define AZ3_INDEX 2                              // for the index flag, az3
#define AZ_ALL_INDEX (-1)                        // for the index flag, az1 and az2,az3

#define GS_GUC_SYNCHRONOUS_STANDBY_MODE 1
/*
 * ssh connect does not exit automatically when the network is fault,
 * this will cause cm_ctl hang for several hours,
 * so we should add the following timeout options for ssh.
 */
#define SSH_CONNECT_TIMEOUT "5"
#define SSH_CONNECT_ATTEMPTS "3"
#define SSH_SERVER_ALIVE_INTERVAL "15"
#define SSH_SERVER_ALIVE_COUNT_MAX "3"
#define PSSH_TIMEOUT_OPTION                                                                        \
    " -t 60 -O ConnectTimeout=" SSH_CONNECT_TIMEOUT " -O ConnectionAttempts=" SSH_CONNECT_ATTEMPTS \
    " -O ServerAliveInterval=" SSH_SERVER_ALIVE_INTERVAL " -O ServerAliveCountMax=" SSH_SERVER_ALIVE_COUNT_MAX " "
#define PSSH_TIMEOUT " -t 30 "
#define SERVICE_TYPE_DB "dn"

#define SWITCHOVER_DEFAULT_WAIT 120  /* It needs an integer multiple of 3, because of sleep(3) */

#define AUTHENTICATION_TIMEOUT 60
#define RELOADWAIT_TIMEOUT 60
#define MAX_DN_NUM 9
#define MAX_INSTANCE_NUM 9

/* ondemand status check timeout */
#define ONDEMADN_STATUS_CHECK_TIMEOUT 6

#define CAN_NOT_SEND_SYNC_lIST 1
#define NOT_NEED_TO_SEND_SYNC_LIST 2
#define NEED_TO_SEND_SYNC_LIST 3
#define SEND_AZ_SYNC_LIST 4
const int DEFAULT_PHONY_DEAD_EFFECTIVE_TIME = 5;

#define MAX_SEND_FAILOVER_TIMES (10)
#define MAX_ONDEMAND_NODE_STATUS 9

#define WITHOUT_CN_CLUSTER(str)                                                                \
    do {                                                                                       \
        if (g_only_dn_cluster || g_coordinator_num == 0) {                                     \
            write_runlog(WARNING, "this cluster has no coordinator, no need to %s.\n", (str)); \
            return;                                                                            \
        }                                                                                      \
    } while (0)

#define WITHOUT_CN_CLUSTER_WITH_VALUE(str)                                                                \
    do {                                                                                       \
        if (g_only_dn_cluster || g_coordinator_num == 0) {                                     \
            write_runlog(WARNING, "this cluster has no coordinator, no need to %s.\n", (str)); \
            return 0;                                                                            \
        }                                                                                      \
    } while (0)

#define ENABLED_AUTO_FAILOVER_ON2NODES(nodeNum, autoFailover)                                  \
    ((nodeNum) == CMS_ONE_PRIMARY_ONE_STANDBY && (autoFailover) == true)

bool &GetIsSharedStorageMode();

extern set<int> g_stopNodes;
extern set<int>::iterator g_stopNodeIter;
extern vector<switchover_instance> switchOverInstances;
extern vector<uint32> vecSortCmId;

extern const int HALF_HOUR;
extern const int MINUS_ONE;
extern ClusterRole backup_open;
extern ClusterInstallType g_clusterInstallType;
extern global_barrier g_global_barrier_data;
extern global_barrier* g_global_barrier;

extern volatile arbitration_mode cm_arbitration_mode;
extern volatile PromoteMode g_cmsPromoteMode;
extern char *g_minorityAzName;
extern uint32 ctl_stop_cluster_server_halt_arbitration_timeout;
extern struct passwd* pw;
extern CM_Server_HA_Status* g_HA_status;
extern dynamicConfigHeader* g_dynamic_header;
extern uint32 g_termCache;
extern cm_instance_role_group* g_instance_role_group_ptr;
extern CM_ConnDdbInfo *g_sess;
extern DDB_TYPE g_dbType;
extern DdbConn g_gtm2Etcd;
extern TlsAuthPath g_tlsPath;
extern dynamicConfigHeader* g_dynamic_header;
extern cm_instance_group_report_status* g_instance_group_report_status_ptr;
extern cm_instance_central_node g_centralNode;
extern pthread_rwlock_t switchover_az_rwlock;
extern pthread_rwlock_t gsguc_feedback_rwlock;
extern pthread_rwlock_t g_finish_redo_rwlock;
extern pthread_rwlock_t g_sendQueueRwlock;
extern pthread_rwlock_t g_recvQueueRwlock;
extern synchronous_standby_mode current_cluster_az_status;
extern CM_WorkThreads gWorkThreads;
extern CM_IOThreads gIOThreads;
extern CM_HAThreads gHAThreads;
extern CM_MonitorThread gMonitorThread;
extern CM_DdbStatusCheckAndSetThread gDdbCheckThread;
extern CM_MonitorNodeStopThread gMonitorNodeStopThread;
extern cm_fenced_UDF_report_status* g_fenced_UDF_report_status_ptr;
extern pthread_rwlock_t instance_status_rwlock;
extern pthread_rwlock_t dynamic_file_rwlock;
extern pthread_rwlock_t term_update_rwlock;
extern pthread_rwlock_t g_minorityArbitrateFileRwlock;
extern pthread_rwlock_t switchover_full_rwlock;
extern kerberos_group_report_status g_kerberos_group_report_status;

extern dynamic_cms_timeline* g_timeline;
extern DynamicNodeReadOnlyInfo *g_dynamicNodeReadOnlyInfo;
extern Alarm UnbalanceAlarmItem[1];
extern Alarm ServerSwitchAlarmItem[1];
extern Alarm DoublePrimaryAlarmItem[1];
extern Alarm* AbnormalDdbAlarmList;
extern volatile logic_cluster_restart_mode cm_logic_cluster_restart_mode;
extern volatile cm_start_mode cm_server_start_mode;
extern volatile switchover_az_mode cm_switchover_az_mode;

extern THR_LOCAL ProcessingMode Mode;

extern const uint32 majority_reelection_timeout_init;
#ifdef ENABLE_MULTIPLE_NODES
extern const int coordinator_deletion_timeout_init;
#endif
extern const int ctl_stop_cluster_server_halt_arbitration_timeout_init;
extern const int cn_dn_disconnect_to_delete_time;
extern int switch_rto;
extern int force_promote;
extern int cm_auth_method;
extern int g_cms_ha_heartbeat;
extern int cm_server_arbitrate_delay_set;
extern int g_init_cluster_delay_time;
extern int max_datastorage_threshold_check;
extern int az_switchover_threshold;
extern int az_check_and_arbitrate_interval;
extern int az1_and_az2_connect_check_interval;
extern int az1_and_az2_connect_check_delay_time;
extern int phony_dead_effective_time;
extern int instance_phony_dead_restart_interval;
extern int enable_az_auto_switchover;
extern int cmserver_demote_delay_on_etcd_fault;
extern int cmserver_demote_delay_on_conn_less;
extern int cmserver_promote_delay_count;
extern int g_cmserver_promote_delay_count;
extern int g_cmserverDemoteDelayOnDdbFault;
extern int g_monitor_thread_check_invalid_times;
extern int cm_server_current_role;
extern int ccn_change_delay_time;
extern int* cn_dn_disconnect_times;
extern int* g_lastCnDnDisconnectTimes;
extern char g_enableDcf[10];
extern char g_shareDiskPath[MAX_PATH_LEN];

extern uint32 datastorage_threshold_check_interval;
extern const uint32 min_normal_cn_number;
extern uint32 g_instance_manual_start_file_exist;
extern uint32 g_gaussdb_restart_counts;
extern uint32 g_cm_to_cm_report_sync_cycle_count;
extern uint32 g_current_node_index;
extern uint32 arbitration_majority_reelection_timeout;
#ifdef ENABLE_MULTIPLE_NODES
extern uint32 g_cnDeleteDelayTimeForClusterStarting;
extern uint32 g_cnDeleteDelayTimeForDnWithoutPrimary;
extern uint32 g_cmd_disable_coordinatorId;
#endif
extern uint32 g_instance_failover_delay_time_from_set;
extern bool g_cms_enable_failover_cascade;
extern uint32 g_cascade_failover_count;
extern uint32 cmserver_gs_guc_reload_timeout;
extern uint32 serverHATimeout;
extern uint32 cmserver_switchover_timeout;
extern uint32 g_datanode_instance_count;
extern uint32 cn_delete_default_time;
extern uint32 instance_heartbeat_timeout;
extern uint32 instance_failover_delay_timeout;
extern uint32 cmserver_ha_connect_timeout;
extern DdbArbiCfg g_ddbArbicfg;
extern uint32 cmserver_self_vote_timeout;
extern uint32 instance_keep_heartbeat_timeout;
extern uint32 g_clusterStartingTimeout;
extern uint32 g_clusterStartingArbitDelay;
extern uint32 g_ddbNetworkIsolationTimeout;
extern ddb_work_mode g_ddbWorkMode;
extern uint32 g_bigVoteNumInMinorityMode;
#ifdef ENABLE_MULTIPLE_NODES
extern uint32 coordinator_heartbeat_timeout;
extern int32 g_cmAgentDeleteCn;
#endif
extern uint32 g_cm_agent_kill_instance_time;
extern uint32 g_cm_agent_set_most_available_sync_delay_time;
extern uint32 cmserver_switchover_timeout;
extern uint32 cmserver_and_etcd_instance_status_for_timeout;
extern uint32 g_dropped_cn[MAX_CN_NUM];
extern uint32 g_instance_status_for_etcd[CM_PRIMARY_STANDBY_NUM];
extern uint32 g_instance_status_for_etcd_timeout[CM_PRIMARY_STANDBY_NUM];
extern uint32 g_nodeIndexForCmServer[CM_PRIMARY_STANDBY_NUM];
extern InstInfo g_cmsInstInfo[CM_PRIMARY_STANDBY_NUM];
extern uint32 g_instance_status_for_cm_server_timeout[CM_PRIMARY_STANDBY_NUM];
extern uint32 g_instance_status_for_cm_server[CM_PRIMARY_STANDBY_NUM];

extern azInfo g_azArray[CM_NODE_MAXNUM];
extern uint32 g_azNum;
extern uint32 g_enableE2ERto;
extern uint32 g_sslCertExpireCheckInterval;
extern uint32 g_diskTimeout;
extern uint32 g_agentNetworkTimeout;
extern DnArbitrateMode g_dnArbitrateMode;
extern uint32 g_readOnlyThreshold;
extern uint32 g_ss_enable_check_sys_disk_usage;
extern bool do_finish_redo;
extern bool isNeedCancel;
extern bool g_init_cluster_mode;
extern bool g_gtm_free_mode;
extern volatile DDB_ROLE g_ddbRole;
extern bool g_open_new_logical;
extern bool g_isStart;
extern bool switchoverAZInProgress;
extern bool g_dnWithoutPrimaryFlag;
extern bool switchoverFullInProgress;
extern bool g_elastic_exist_node;
extern bool g_kerberos_check_cms_primary_standby;
extern bool g_syncDnFinishRedoFlagFromDdb;
extern bool g_getHistoryDnStatusFromDdb;
extern bool g_getHistoryCnStatusFromDdb;
extern volatile uint32 g_refreshDynamicCfgNum;
extern bool g_needIncTermToDdbAgain;
extern volatile bool g_needReloadSyncStandbyMode;
extern bool g_instance_status_for_cm_server_pending[CM_PRIMARY_STANDBY_NUM];
extern bool g_clusterStarting;
extern bool g_enableSetMostAvailableSync;
/* thread count of thread pool */
extern int cm_thread_count;

extern volatile bool g_isInRedoStateUnderSwitchover;

extern FILE* syslogFile;
extern char* cm_server_dataDir;
extern char sys_log_path[MAX_PATH_LEN];
extern char g_curLogFileName[MAXPGPATH];
extern char system_alarm_log[MAXPGPATH];
extern char cm_krb_server_keyfile[MAX_PATH_LEN];
extern char configDir[MAX_PATH_LEN];
extern char g_alarmConfigDir[MAX_PATH_LEN];
extern char minority_az_start_file[MAX_PATH_LEN];
extern char g_minorityAzArbitrateFile[MAX_PATH_LEN];
extern char g_cmsPModeFilePath[MAX_PATH_LEN];
extern char g_cmInstanceManualStartPath[MAX_PATH_LEN];

extern char g_enableSetReadOnly[10];
extern char g_storageReadOnlyCheckCmd[MAX_PATH_LEN];
extern char g_cmStaticConfigurePath[MAX_PATH_LEN];
extern char cm_dynamic_configure_path[MAX_PATH_LEN];
extern char g_logicClusterListPath[MAX_PATH_LEN];
extern char instance_maintance_path[MAX_PATH_LEN];
extern char cluster_maintance_path[MAX_PATH_LEN];
extern char g_cmManualStartPath[MAX_PATH_LEN];
extern char cm_force_start_file_path[MAX_PATH_LEN];
extern CmAzInfo g_cmAzInfo[AZ_MEMBER_MAX_COUNT];
extern char g_queryBarrier[BARRIERLEN];
extern char g_targetBarrier[BARRIERLEN];
extern char g_doradoIp[CM_IP_LENGTH];
extern char g_votingDiskPath[MAX_PATH_LEN];

extern volatile int log_min_messages;
extern volatile int maxLogFileSize;
extern volatile int curLogFileNum;
extern volatile bool logInitFlag;
extern volatile bool cm_server_pending;
extern volatile reduceOrIncreaseSyncLists g_isEnableUpdateSyncList;
extern bool g_inReload;
extern volatile bool g_inMaintainMode;
extern ThreadExecStatus g_loopState;
extern DdbArbiCon g_ddbArbiCon;
extern ssl_ctx_t *g_ssl_acceptor_fd;
extern uint32 g_delayArbiTime;
extern int32 g_clusterArbiTime;
extern bool g_isPauseArbitration;
extern char g_cmManualPausePath[MAX_PATH_LEN];
extern uint32 g_waitStaticPrimaryTimes;
extern SSDoubleClusterMode g_ssDoubleClusterMode;
extern uint32 g_realtimeBuildStatus;

/* The global time structure of ondemand redo check. */
extern int g_onDemandStatus[MAX_ONDEMAND_NODE_STATUS];
extern time_t g_onDemandStatusTime[MAX_ONDEMAND_NODE_STATUS];

/* The rwlock of ondemand redo check. */
extern pthread_rwlock_t g_ondemandStatusCheckRwlock;


extern void clean_init_cluster_state();
extern void instance_delay_arbitrate_time_out_direct_clean(uint32 group_index, int member_index,
    uint32 delay_max_count);
extern void instance_delay_arbitrate_time_out_clean(
    int local_dynamic_role, int peerl_dynamic_role, uint32 group_index, int member_index, int delay_max_count);

extern int find_node_in_dynamic_configure(
    uint32 node, uint32 instanceId, uint32* group_index, int* member_index);

extern void change_primary_member_index(uint32 group_index, int primary_member_index);
extern void ChangeDnPrimaryMemberIndex(uint32 group_index, int primary_member_index);
extern void DealDbstateNormalPrimaryDown(uint32 groupIdx, int32 instType);
extern int find_other_member_index(uint32 groupIdx, int memIdx, int role);
extern int instance_delay_arbitrate_time_out(
    int localDynamicRole, int peerlDynamicRole, uint32 groupIdx, int memIdx, int delayMaxCount);
extern void CleanCommand(uint32 groupIndex, int memberIndex);
extern bool isLoneNode(int timeout);
extern int SetNotifyPrimaryInfoToEtcd(uint32 groupIndex, int memberIndex);
void DealPhonyDeadStatus(
    MsgRecvInfo* recvMsgInfo, int32 instRole, uint32 groupIdx, int32 memIdx, maintenance_mode mode);
extern void DealDNPhonyDeadStatusE2E(uint32 groupIndex, int memberIndex);
extern void DealCNPhonyDeadStatusE2E(uint32 groupIndex, int memberIndex);
extern void DealGTMPhonyDeadStatusE2E(uint32 groupIndex, int memberIndex);
extern void kill_instance_for_agent_fault(uint32 node, uint32 instanceId, int insType);
extern int find_other_member_index_for_DN_psd(uint32 group_index, int member_index);
extern int cmserver_getenv(const char* env_var, char* output_env_value, uint32 env_value_len, int elevel);
extern bool IsMaintenanceModeDisableOperation(const cms_operation &op, maintenance_mode mode);
extern void cm_pending_notify_broadcast_msg(uint32 group_index, uint32 instanceId);
extern inline bool isDisableSwitchoverDN(const maintenance_mode &mode);
extern inline bool isDisableFailoverDN(const maintenance_mode &mode);
extern inline bool isDisableDropCN(const maintenance_mode &mode);
extern inline bool isDisablePhonyDeadCheck(const maintenance_mode &mode);
extern inline bool isDisableBuildDN(const maintenance_mode &mode);
extern maintenance_mode getMaintenanceMode(const uint32 &group_index);
extern uint32 GetTermForMinorityStart(void);
extern cm_start_mode get_cm_start_mode(const char* path);
extern int GetSendTimes(uint32 groupIndex, int memberIndex, bool isTotal);
extern void SetSendTimes(uint32 groupIndex, int memberIndex, int timeOut);
extern bool IsArchiveMaxSendTimes(uint32 groupIndex, int memberIndex);
extern bool IsCurInstanceInVoteAz(uint32 groupIndex, int memberIndex);
extern int GetVoteAzIndex(void);

extern void initazArray(char azArray[][CM_AZ_NAME]);
bool isLargerNode();
void setStorageCheckCmd();
bool IsNodeInMinorityAz(uint32 groupIdx, int32 memIdx);
extern uint32 GetInstanceIdInGroup(uint32 groupIndex, int memberIndex);
extern int32 GetInstanceCountsInGroup(uint32 groupIndex);
extern bool CurAzIsNeedToStop(const char *azName);
void InitClientCrt(const char *appPath);
bool CanArbitrate(MsgRecvInfo* recvMsgInfo, const char *arbitrateType);
void ChangeDnMemberIndex(const char *str, uint32 groupIdx, int32 memIdx, int32 instTypePur, int32 instTypeSor);
void ChangeCascadeMemberIndex(const char *str, uint32 groupIdx, int32 memIdx, int32 peerId);
void SetSwitchoverCmd(cm_instance_command_status *cmd, int32 localRole, uint32 instId, uint32 peerInstId);
void HashCascadeStandby(cm_to_ctl_instance_datanode_status *dnReport, uint32 groupIdx, int32 memIdx);
bool IncrementTermToFile(void);
bool ExistClusterMaintenance(bool *isInFailover);
bool CheckCanDoSwitchover(uint32 groupIdx, int32 memIdx, int32 *pendCmd, const char *str);
EnCheckSynclist CheckInstInSyncList(uint32 groupIdx, int32 memIdx, const char *str);
void PrintSyncListMsg(uint32 groupIdx, int32 memIdx, const char *str);
bool CheckAllDnShardSynclist(const char *str);
uint32 GetPeerInstId(uint32 groupIdx, int32 memIdx);
bool CheckGroupAndMemIndex(uint32 groupIdx, int32 memIdx, const char *str);
status_t CmsCanArbitrate(CmsArbitrateStatus *cmsSt, const char *str);
status_t GetNodeIdxByNodeId(uint32 nodeId, uint32 *nodeIdx, const char *str);
bool8 IsCurInstIdCascadeStandby(uint32 groupIdx, int memberIdx);
#endif
