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
 * cma_global_params.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_agent/cma_global_params.cpp
 *
 * -------------------------------------------------------------------------
 */
#include "cma_global_params.h"

struct passwd* pw = NULL;
/* last time receive heartbeat from cmserver */
struct timespec g_serverHeartbeatTime;
/* time of disconnect witch cmserver */
struct timespec g_disconnectTime;
TlsAuthPath g_tlsPath = {0};
etcd_status_info g_etcdReportMsg;
cm_instance_central_node g_centralNode;
gtm_status_info g_gtmReportMsg;
coordinate_status_info g_cnReportMsg;
datanode_status_info g_dnReportMsg[CM_MAX_DATANODE_PER_NODE];
DnSyncListInfo g_dnSyncListInfo[CM_MAX_DATANODE_PER_NODE];
CmDoWriteOper g_cmDoWriteOper[CM_MAX_DATANODE_PER_NODE];
kerberos_status_info g_kerberosReportMsg;
OneNodeResStatusInfo g_resReportMsg;

pthread_t g_repairCnThread;
pthread_t g_threadId[CM_MAX_THREAD_NUM] = {0};
FILE* g_lockfile = NULL;

bool enable_xc_maintenance_mode = true;
/* unify log style */
char g_logicClusterListPath[MAXPGPATH] = {0};
char g_systemCallLogName[MAXPGPATH] = {0};
char result_path[MAX_PATH_LEN] = {0};
char g_cmAgentLogPath[MAX_PATH_LEN] = {0};
char g_cmStaticConfigurePath[MAX_PATH_LEN] = {0};
char g_cmManualStartPath[MAX_PATH_LEN] = {0};
char g_cmInstanceManualStartPath[MAX_PATH_LEN] = {0};
char g_cmEtcdManualStartPath[MAX_PATH_LEN] = {0};
#ifndef ENABLE_MULTIPLE_NODES
char g_cmLibnetManualStartPath[MAX_PATH_LEN] = {0};
#endif
char g_cmResumingCnStopPath[MAX_PATH_LEN] = {0};
/* on is online off is offline */
char g_enableOnlineOrOffline[BOOL_STR_MAX_LEN] = {0};
char g_unixSocketDirectory[MAXPGPATH] = {'\0'};
char g_votingDiskPath[MAX_PATH_LEN] = {0};
char g_enableCnAutoRepair[BOOL_STR_MAX_LEN] = {0};
/* root directory of trace */
char g_logBasePath[MAXPGPATH];
/* gateway to control log compress */
char g_enableLogCompress[BOOL_STR_MAX_LEN] = {0};
char configDir[MAX_PATH_LEN] = {0};
char g_alarmConfigDir[MAX_PATH_LEN] = {0};
char g_cmagentLockfile[MAX_PATH_LEN] = {0};
char g_binPath[MAX_PATH_LEN] = {0};
char g_runLongCommand[MAX_LOGIC_DATANODE * CM_NODE_NAME + 64] = {0};
char g_cnNameBuf[MAXPGPATH] = {0};
char system_call_log[MAXPGPATH] = {0};
char g_datanodeNames[MAX_LOGIC_DATANODE][CM_NODE_NAME];
char g_datanodeNameOids[MAX_LOGIC_DATANODE][CM_NODE_NAME];
char instance_maintance_path[MAX_PATH_LEN] = {0};
char g_dnNameBuf[MAX_LOGIC_DATANODE * CM_NODE_NAME] = {0};
char node_group_members1[MAX_NODE_GROUP_MEMBERS_LEN] = {0};
char node_group_members2[MAX_NODE_GROUP_MEMBERS_LEN] = {0};
char g_cmClusterResizePath[MAX_PATH_LEN] = {0};
char g_cmClusterReplacePath[MAX_PATH_LEN] = {0};
const char* g_progname;

volatile bool g_repairCn = false;
volatile uint g_restoreCn = 0;
bool g_syncDroppedCoordinator = false;
bool g_pgxcNodeConsist = false;
bool g_cmDoForce = false;          /*  stop by force */
bool g_cmAgentFirstStart = true;
bool g_cmStaticConfigNeedVerifyToCn = false;
bool g_cmServerNeedReconnect = false;
bool g_cmAgentNeedAlterPgxcNode = false;
#ifdef ENABLE_MULTIPLE_NODES
bool cm_agent_need_check_libcomm_port = true;
#endif
bool g_cnNicDown = false;
bool g_cmsNicDown = false;
bool g_gtmNicDown = false;
bool g_agentNicDown = false;
bool g_suppressAlarm = false;
bool g_isStart = false;
bool g_dnDiskDamage[CM_MAX_DATANODE_PER_NODE];
bool g_dnBuild[CM_MAX_DATANODE_PER_NODE];
bool g_nicDown[CM_MAX_DATANODE_PER_NODE];
bool g_dnPingFault[CM_MAX_DATANODE_PER_NODE];
bool g_mostAvailableSync[CM_MAX_DATANODE_PER_NODE];
bool g_dnNoFreeProc[CM_MAX_DATANODE_PER_NODE];
ReadOnlyState g_dnReadOnly[CM_MAX_DATANODE_PER_NODE];
ReadOnlyState g_cnReadOnly;
bool g_cnPhonyDeadD = false;
bool g_cnNoFreeProc = false;
bool g_cnWaiting = false;
bool g_isCatalogChanged = false;
bool g_cleanDropCnFlag = false;
#ifndef ENABLE_MULTIPLE_NODES
bool g_ltranDown[CM_MAX_DATANODE_PER_NODE];
#endif

int g_datanodeNum = 0;
int g_cnFrequentRestartCounts = 0;
int g_cnDnPairsCount = 0;
/* cm_ctl stop single instance, single node or all nodes */
int g_cmShutdownLevel = ALL_NODES;
/* fast shutdown */
ShutdownMode g_cmShutdownMode = FAST_MODE;
/* Indicates pgxc_node or pgxc_group is changed. if not, we do not need to execute pgxc_pool_reload. */
int g_currenPgxcNodeNum = 0;
int g_normalStopTryTimes = 0;
int g_startCmsCount = -1;
int g_startCnCount = 0;
int g_startDnCount[CM_MAX_DATANODE_PER_NODE] = {0};
int g_startGtmCount = 0;
int g_cmServerInstanceStatus = CM_SERVER_DOWN;
int g_dnRoleForPhonyDead[CM_MAX_DATANODE_PER_NODE] = {0};
int g_gtmRoleForPhonyDead = 0;
int g_localCnStatus = 0;
int g_dnPhonyDeadTimes[CM_MAX_DATANODE_PER_NODE] = {0};
int g_gtmPhonyDeadTimes = 0;
int g_cnPhonyDeadTimes = 0;
volatile uint32 g_cnDnDisconnectTimes = 0;
int g_dnStartCounts[CM_MAX_DATANODE_PER_NODE] = {0};
int g_gtmStartCounts = 0;
int g_coStartCounts = 0;
int g_primaryDnRestartCounts[CM_MAX_DATANODE_PER_NODE] = {0};
int g_primaryDnRestartCountsInHour[CM_MAX_DATANODE_PER_NODE] = {0};
/* Added the number of disk shard expand nodes */
uint32 dilatation_shard_count_for_disk_capacity_alarm = 1;
uint32 g_cnAutoRepairDelay = 0;
uint32 agent_phony_dead_check_interval = 10;
DisasterRecoveryType g_disasterRecoveryType = DISASTER_RECOVERY_NULL;
SSDoubleClusterMode g_ssDoubleClusterMode = SS_DOUBLE_NULL;
/* T status agent check phony dead inteval */
uint32 g_agentCheckTStatusInterval = 36;
uint32 enable_gtm_phony_dead_check = 1;
uint32 g_enableE2ERto = 0;
/* disk capacity,the unit is MB,the highest priority */
int64 log_max_size = 1024;
/* the maximum trace count save on disk,the lowest priority */
uint32 log_max_count = 10000;

char g_agentEnableDcf[BOOL_STR_MAX_LEN] = {0};
/* guard trace saved days,the priority,the medium priority */
uint32 log_saved_days = 90;
/* interval of next check disk capacity,the unit is second */
uint32 log_threshold_check_interval = 1800;
uint32 g_checkDiscInstanceNow = 0;
uint32 g_nodeId = 0;
uint32 g_healthInstance = 0;
uint32 g_threadDeadEffectiveTime = 600;
/* cm_agent config parameters */
uint32 agent_report_interval = 1;
uint32 agent_heartbeat_timeout = 8;
uint32 agent_connect_timeout = 1;
ClusterRole agent_backup_open = CLUSTER_PRIMARY;
uint32 agent_connect_retries = 15;
uint32 agent_check_interval = 2;
uint32 agent_kill_instance_timeout = 0;
uint32 g_agentKerberosStatusCheckInterval = 5;
const uint32 AGENT_WATCH_DOG_THRESHOLD = 200;
uint32 g_cmaConnectCmsInOtherNodeCount = 0;
uint32 g_cmaConnectCmsPrimaryInLocalNodeCount = 0;
uint32 g_cmaConnectCmsInOtherAzCount = 0;
uint32 g_cmaConnectCmsPrimaryInLocalAzCount = 0;
uint32 g_diskTimeout = 200;
uint32 g_dnBuildCheckTimes[CM_MAX_DATANODE_PER_NODE] = {0};
uint32 g_nodeIndexForCmServer[CM_PRIMARY_STANDBY_NUM] = {INVALID_NODE_NUM,
    INVALID_NODE_NUM,
    INVALID_NODE_NUM,
    INVALID_NODE_NUM,
    INVALID_NODE_NUM,
    INVALID_NODE_NUM,
    INVALID_NODE_NUM,
    INVALID_NODE_NUM};

/* Update secbox.conf when CN/DN starting */
bool g_exitFlag = false;
bool g_shutdownRequest = false;
bool g_gtmDiskDamage = false;
bool g_cnDiskDamage = false;
bool g_cmsDiskDamage = false;

bool g_fencedUdfStopped = false;
bool g_needReloadActive = false;
bool g_isCmaBuildingDn[CM_MAX_DATANODE_PER_NODE] = {0};

long g_check_disc_state = 0;
long g_thread_state[CM_MAX_THREAD_NUM] = {0};
const char *g_threadName[CM_MAX_THREAD_NUM] = {0};
uint32 g_serverNodeId;
bool g_pgxcPoolReload = false;
uint32 g_autoRepairCnt = 0;
char g_autoRepairPath[MAX_PATH_LEN] = {0};
bool g_dnPhonyDeadD[CM_MAX_DATANODE_PER_NODE] = {0};
bool g_dnCore[CM_MAX_DATANODE_PER_NODE] = {0};
bool g_gtmPhonyDeadD = false;
char g_agentQueryBarrier[BARRIERLEN] = {0};
char g_agentTargetBarrier[BARRIERLEN] = {0};
AgentSendCmDdbOper g_gtmSendDdbOper;
CmDdbOperRes g_gtmCmDdbOperRes;
char g_environmentThreshold[CM_PATH_LENGTH] = {0};
bool g_isSharedStorageMode = false;
char g_doradoIp[CM_IP_LENGTH] = {0};
char g_enableMesSsl[BOOL_STR_MAX_LEN] = {0};
uint32 g_sslCertExpireCheckInterval = SECONDS_PER_DAY;
uint32 g_cmaRhbItvl = 1000;
CmResConfList g_resConf[CM_MAX_RES_INST_COUNT] = {{{0}}};
IpType g_ipType = IP_TYPE_INIT;
bool g_supportIpV6 = false;
#ifndef ENABLE_MULTIPLE_NODES
char g_dbServiceVip[CM_IP_LENGTH] = {0};
char g_enableFenceDn[10] = {0};
bool g_isStorageWithDMSorDSS = false;
char g_onDemandRealTimeBuildStatus = 0;
#endif
bool g_isPauseArbitration = false;
char g_cmManualPausePath[MAX_PATH_LEN] = {0};
bool g_isStarting = false;
char g_cmManualStartingPath[MAX_PATH_LEN] = {0};

/* Whether we are in add avg process */
bool g_isInVGAddProcess = false;
bool g_isRegUnderVGAddProcess = false;

/* Lock for pending status update, we dont wonder modify status under racing. */
pthread_rwlock_t pending_status_rwlock = PTHREAD_RWLOCK_INITIALIZER;;

bool &GetIsSharedStorageMode()
{
    return g_isSharedStorageMode;
}

bool GetEnvSupportIpV6()
{
    return g_supportIpV6;
}

void SetEnvSupportIpV6(bool val)
{
    g_supportIpV6 = val;
}

#ifdef __aarch64__
/*
 * 0 indicates we do NOT bind cpu,
 * 1 indicates 2^1 (physical cpu number is 2),
 * 2 indicates 2^2 (physical cpu number is 4).
 */
uint32 agent_process_cpu_affinity = 0;
uint32 total_cpu_core_num = 0;
uint32 g_datanode_primary_num = 0;
uint32 g_datanode_primary_and_standby_num = 0;
/*
 * g_dn_report_msg_ok is true indicates we get dynamic role of datanodes (primary or standby).
 * In this case, we bind cpu cores using DN dynamic roles;
 * Otherwise, we bind cpu cores using DN static roles.
 */
bool g_dn_report_msg_ok = false;

#endif
