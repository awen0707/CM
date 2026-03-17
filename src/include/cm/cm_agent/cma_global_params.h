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
 * cma_global_params.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_agent/cma_global_params.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CMA_GLOBAL_PARAMS_H
#define CMA_GLOBAL_PARAMS_H

#include "cm/cm_c.h"
#include "cm/cm_misc.h"
#include "cm_ddb_adapter.h"
#include "cma_network_check.h"
#include "cma_main.h"

typedef enum MAINTENANCE_MODE_ {
    MAINTENANCE_MODE_NONE = 0,
    MAINTENANCE_MODE_UPGRADE,
    MAINTENANCE_MODE_UPGRADE_OBSERVATION,
    MAINTENANCE_MODE_DILATATION,
} maintenance_mode;

typedef struct AgentSendCmDdbOper_t {
    pthread_rwlock_t lock;
    CltSendDdbOper_t *sendOper;
} AgentSendCmDdbOper;

typedef struct CmDdbOperRes_t {
    pthread_rwlock_t lock;
    CmSendDdbOperRes *ddbOperRes;
} CmDdbOperRes;

typedef struct CmDoWriteOper_t {
    pthread_rwlock_t lock;
    bool doWrite;
} CmDoWriteOper;

#define CM_SERVER_DATA_DIR "cm_server"
#define CM_INSTANCE_REPLACE "instance_replace"
#define PROC_NET_TCP "/proc/net/tcp"

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

/* UDF_DEFAULT_MEMORY is 200*1024 kB */
/* Must be same as UDF_DEFAULT_MEMORY in memprot.h and udf_memory_limit in cluster_guc.conf */
#define UDF_DEFAULT_MEMORY (200 * 1024)
#define AGENT_RECV_CYCLE (200 * 1000)
#define AGENT_START_AND_STOP_CYCLE (200 * 1000)
#define AGENT_REPORT_ETCD_CYCLE 600
#define INSTANCE_ID_LEN 8
#define SINGLE_INSTANCE 0
#define SINGLE_NODE 1
#define ALL_NODES 2
#define COMM_PORT_TYPE_DATA 1
#define COMM_PORT_TYPE_CTRL 2
#define MAX_RETRY_TIME 10
#define MAX_INSTANCE_BUILD 3
#define COMM_DATA_DFLT_PORT 7000
#define COMM_CTRL_DFLT_PORT 7001

#define INSTANCE_START_CYCLE 20
#define INSTANCE_BUILD_CYCLE 10

#define STARTUP_DN_CHECK_TIMES 3
#define STARTUP_CN_CHECK_TIMES 3
#define STARTUP_GTM_CHECK_TIMES 3
#define STARTUP_CMS_CHECK_TIMES 3

#define PHONY_DEAD_THRESHOLD 300

#define LISTEN 10
#define AGENT_CONN_DN_TIMEOUT (2)

#define BOOL_STR_MAX_LEN 10

extern struct passwd* pw;
extern FILE* g_lockfile;
extern DdbConn g_sess;
extern DDB_TYPE g_dbType;
extern cm_instance_central_node g_centralNode;
extern gtm_status_info g_gtmReportMsg;
extern coordinate_status_info g_cnReportMsg;
extern datanode_status_info g_dnReportMsg[CM_MAX_DATANODE_PER_NODE];
extern DnSyncListInfo g_dnSyncListInfo[CM_MAX_DATANODE_PER_NODE];
extern CmDoWriteOper g_cmDoWriteOper[CM_MAX_DATANODE_PER_NODE];
extern etcd_status_info g_etcdReportMsg;
extern kerberos_status_info g_kerberosReportMsg;
extern OneNodeResStatusInfo g_resReportMsg;

/* Enable the datanode incremental build mode */
extern volatile bool incremental_build;
extern volatile bool security_mode;
extern bool enable_xc_maintenance_mode;
extern char sys_log_path[MAX_PATH_LEN];
extern FILE* syslogFile;
extern pthread_t g_repairCnThread;
extern struct timespec g_serverHeartbeatTime;
extern struct timespec g_disconnectTime;

extern TlsAuthPath g_tlsPath;
extern pthread_t g_threadId[CM_MAX_THREAD_NUM];

extern const char* g_progname;
extern char configDir[MAX_PATH_LEN];
extern char g_alarmConfigDir[MAX_PATH_LEN];
extern char g_binPath[MAX_PATH_LEN];
extern char g_cmagentLockfile[MAX_PATH_LEN];
extern char g_runLongCommand[MAX_LOGIC_DATANODE * CM_NODE_NAME + 64];
extern char g_cnNameBuf[MAXPGPATH];
extern char g_logicClusterListPath[MAXPGPATH];
extern char g_systemCallLogName[MAXPGPATH];
extern char result_path[MAX_PATH_LEN];
extern char g_cmAgentLogPath[MAX_PATH_LEN];
extern char g_cmStaticConfigurePath[MAX_PATH_LEN];
extern char g_cmManualStartPath[MAX_PATH_LEN];
extern char g_cmInstanceManualStartPath[MAX_PATH_LEN];
extern char g_cmEtcdManualStartPath[MAX_PATH_LEN];
#ifndef ENABLE_MULTIPLE_NODES
extern char g_cmLibnetManualStartPath[MAX_PATH_LEN];
#endif
extern char g_cmResumingCnStopPath[MAX_PATH_LEN];
extern int g_datanodeNum;
extern char g_datanodeNames[MAX_LOGIC_DATANODE][CM_NODE_NAME];
extern char g_datanodeNameOids[MAX_LOGIC_DATANODE][CM_NODE_NAME];
extern char system_alarm_log[MAXPGPATH];
extern char g_dnNameBuf[MAX_LOGIC_DATANODE * CM_NODE_NAME];
extern char node_group_members1[MAX_NODE_GROUP_MEMBERS_LEN];
extern char node_group_members2[MAX_NODE_GROUP_MEMBERS_LEN];
extern char g_cmClusterResizePath[MAX_PATH_LEN];
extern char g_cmClusterReplacePath[MAX_PATH_LEN];
extern char system_call_log[MAXPGPATH];
extern char g_unixSocketDirectory[MAXPGPATH];
extern char g_votingDiskPath[MAX_PATH_LEN];
extern char g_logBasePath[MAXPGPATH];
extern char g_enableCnAutoRepair[BOOL_STR_MAX_LEN];
extern char g_enableOnlineOrOffline[BOOL_STR_MAX_LEN];
extern char g_enableLogCompress[BOOL_STR_MAX_LEN];
extern char instance_maintance_path[MAX_PATH_LEN];

extern volatile bool g_repairCn;
extern bool g_shutdownRequest;
extern bool g_syncDroppedCoordinator;
extern bool g_exitFlag;
extern bool g_cmDoForce;          /*  stop by force */
extern bool g_pgxcNodeConsist;
extern bool g_cmAgentFirstStart;
extern bool g_cmStaticConfigNeedVerifyToCn;
extern bool g_cmServerNeedReconnect;
extern bool g_cmAgentNeedAlterPgxcNode;
#ifdef ENABLE_MULTIPLE_NODES
extern bool cm_agent_need_check_libcomm_port;
#endif
extern bool g_isCmaBuildingDn[CM_MAX_DATANODE_PER_NODE];
extern bool g_gtmDiskDamage;
extern bool g_cnDiskDamage;
extern bool g_cmsDiskDamage;
extern bool g_fencedUdfStopped;
extern bool g_cnNicDown;
extern bool g_cmsNicDown;
extern bool g_gtmNicDown;
extern bool g_agentNicDown;
extern bool g_dnDiskDamage[CM_MAX_DATANODE_PER_NODE];
extern bool g_dnBuild[CM_MAX_DATANODE_PER_NODE];
extern bool g_nicDown[CM_MAX_DATANODE_PER_NODE];
extern bool g_dnPingFault[CM_MAX_DATANODE_PER_NODE];
extern bool g_mostAvailableSync[CM_MAX_DATANODE_PER_NODE];
extern ReadOnlyState g_dnReadOnly[CM_MAX_DATANODE_PER_NODE];
extern ReadOnlyState g_cnReadOnly;
#ifndef ENABLE_MULTIPLE_NODES
extern bool g_ltranDown[CM_MAX_DATANODE_PER_NODE];
#endif
extern bool g_cmAgentFirstStart;
extern bool g_isStart;
extern bool g_suppressAlarm;
extern bool g_needReloadActive;
extern bool g_cnPhonyDeadD;

extern const uint32 AGENT_WATCH_DOG_THRESHOLD;
/* cm_agent config parameters */
extern uint32 agent_report_interval;
extern uint32 agent_heartbeat_timeout;
extern uint32 agent_connect_timeout;
extern ClusterRole agent_backup_open;
extern uint32 agent_connect_retries;
extern uint32 agent_check_interval;
extern uint32 agent_kill_instance_timeout;
extern uint32 g_agentKerberosStatusCheckInterval;
extern uint32 g_cnAutoRepairDelay;
extern uint32 dilatation_shard_count_for_disk_capacity_alarm;
extern uint32 g_checkDiscInstanceNow;
extern uint32 g_nodeId;
extern uint32 g_healthInstance;
extern uint32 agent_phony_dead_check_interval;
extern uint32 g_agentCheckTStatusInterval;
extern uint32 g_threadDeadEffectiveTime;
extern uint32 enable_gtm_phony_dead_check;
extern uint32 g_cmaConnectCmsInOtherNodeCount;
extern uint32 g_cmaConnectCmsPrimaryInLocalNodeCount;
extern uint32 g_cmaConnectCmsInOtherAzCount;
extern uint32 g_cmaConnectCmsPrimaryInLocalAzCount;
extern uint32 g_dnBuildCheckTimes[CM_MAX_DATANODE_PER_NODE];
extern uint32 g_nodeIndexForCmServer[CM_PRIMARY_STANDBY_NUM];
extern uint32 g_enableE2ERto;
extern DisasterRecoveryType g_disasterRecoveryType;
extern SSDoubleClusterMode g_ssDoubleClusterMode;

extern int g_cmShutdownLevel; /* cm_ctl stop single instance, single node or all nodes */
extern ShutdownMode g_cmShutdownMode;  /* fast shutdown */
extern int g_cnFrequentRestartCounts;
extern int g_cnDnPairsCount;
extern int g_currenPgxcNodeNum;
extern int g_normalStopTryTimes;
extern int g_gtmStartCounts;
extern int g_coStartCounts;
extern int g_dnStartCounts[CM_MAX_DATANODE_PER_NODE];
extern int g_primaryDnRestartCounts[CM_MAX_DATANODE_PER_NODE];
extern int g_primaryDnRestartCountsInHour[CM_MAX_DATANODE_PER_NODE];
extern bool g_dnPhonyDeadD[CM_MAX_DATANODE_PER_NODE];
extern bool g_dnCore[CM_MAX_DATANODE_PER_NODE];
extern bool g_dnNoFreeProc[CM_MAX_DATANODE_PER_NODE];
extern bool g_isCatalogChanged;
extern bool g_gtmPhonyDeadD;
extern bool g_cnNoFreeProc;
extern bool g_cnWaiting;
extern bool g_cleanDropCnFlag;

extern int g_startCmsCount;
extern int g_startCnCount;
extern int g_startDnCount[CM_MAX_DATANODE_PER_NODE];
extern int g_startGtmCount;
extern int g_cmServerInstanceStatus;
extern int g_dnRoleForPhonyDead[CM_MAX_DATANODE_PER_NODE];
extern int g_gtmRoleForPhonyDead;
extern int g_localCnStatus;
extern int g_dnPhonyDeadTimes[CM_MAX_DATANODE_PER_NODE];
extern int g_gtmPhonyDeadTimes;
extern int g_cnPhonyDeadTimes;
extern volatile uint32 g_cnDnDisconnectTimes;

extern int64 log_max_size;
extern uint32 log_max_count;
extern uint32 log_saved_days;
extern uint32 log_threshold_check_interval;
extern char g_agentEnableDcf[BOOL_STR_MAX_LEN];
extern long g_check_disc_state;
extern long g_thread_state[CM_MAX_THREAD_NUM];
extern const char *g_threadName[CM_MAX_THREAD_NUM];
extern uint32 g_serverNodeId;
extern bool g_pgxcPoolReload;
extern uint32 g_autoRepairCnt;
extern char g_autoRepairPath[MAX_PATH_LEN];
extern AgentSendCmDdbOper g_gtmSendDdbOper;
extern CmDdbOperRes g_gtmCmDdbOperRes;
extern conn_option_t g_sslOption;
extern char g_agentQueryBarrier[BARRIERLEN];
extern char g_agentTargetBarrier[BARRIERLEN];
extern char g_environmentThreshold[CM_PATH_LENGTH];
extern char g_doradoIp[CM_IP_LENGTH];
#ifndef ENABLE_MULTIPLE_NODES
extern char g_dbServiceVip[CM_IP_LENGTH];
extern char g_enableFenceDn[10];
extern bool g_isStorageWithDMSorDSS;
extern char g_onDemandRealTimeBuildStatus;
#endif
extern uint32 g_diskTimeout;
extern char g_enableMesSsl[BOOL_STR_MAX_LEN];
extern uint32 g_sslCertExpireCheckInterval;
extern uint32 g_cmaRhbItvl;
extern CmResConfList g_resConf[CM_MAX_RES_INST_COUNT];
extern IpType g_ipType;

/* Whether we are in add avg process. */
extern bool g_isInVGAddProcess;
extern bool g_isRegUnderVGAddProcess;

/* Lock for pending status update, we dont wonder modify status under racing. */
extern pthread_rwlock_t pending_status_rwlock;

bool &GetIsSharedStorageMode();

#define FENCE_TIMEOUT (agent_connect_retries * (agent_connect_timeout + agent_report_interval))

bool GetEnvSupportIpV6();
void SetEnvSupportIpV6(bool val);

#ifdef __aarch64__
extern uint32 agent_process_cpu_affinity;
extern uint32 g_datanode_primary_and_standby_num;
extern uint32 g_datanode_primary_num;
extern uint32 total_cpu_core_num;
extern bool g_dn_report_msg_ok;
/* cm_agent start_command parameters */
#define PHYSICAL_CPU_NUM (1 << agent_process_cpu_affinity)
#define CPU_AFFINITY_MAX 2
#endif

extern bool g_isPauseArbitration;
extern char g_cmManualPausePath[MAX_PATH_LEN];
extern bool g_isStarting;
extern char g_cmManualStartingPath[MAX_PATH_LEN];


#endif
