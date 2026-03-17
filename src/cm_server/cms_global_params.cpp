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
 * cms_global_params.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_server/cms_global_params.cpp
 *
 * -------------------------------------------------------------------------
 */

#include <sys/epoll.h>
#include "cm/cm_elog.h"
#include "cms_ddb.h"
#include "cms_common.h"
#include "cms_process_messages.h"
#include "cms_alarm.h"
#include "cms_write_dynamic_config.h"
#include "cms_conn.h"
#include "cms_global_params.h"

const int HALF_HOUR = 1800;
const int MINUS_ONE = -1;

set<int> g_stopNodes;
set<int>::iterator g_stopNodeIter;
vector<switchover_instance> switchOverInstances;
vector<uint32> vecSortCmId;

azInfo g_azArray[CM_NODE_MAXNUM] = {{{0}}};
uint32 g_azNum = 0;

CM_Server_HA_Status g_HA_status_data = {0};
CM_Server_HA_Status *g_HA_status = &g_HA_status_data;
CM_Server_HA_Status g_logic_HA_status[LOGIC_CLUSTER_NUMBER] = {{0}};
cm_instance_role_group *g_instance_role_group_ptr = NULL;
uint32 g_termCache = 0;
dynamicConfigHeader *g_dynamic_header = NULL;
cm_instance_group_report_status *g_instance_group_report_status_ptr = NULL;
volatile arbitration_mode cm_arbitration_mode = MAJORITY_ARBITRATION;
volatile PromoteMode g_cmsPromoteMode = PMODE_AUTO;
char *g_minorityAzName = NULL;
cm_instance_central_node g_centralNode = {0};
kerberos_group_report_status g_kerberos_group_report_status = {0};

pthread_rwlock_t dynamic_file_rwlock = PTHREAD_RWLOCK_INITIALIZER;
pthread_rwlock_t term_update_rwlock = PTHREAD_RWLOCK_INITIALIZER;
pthread_rwlock_t g_minorityArbitrateFileRwlock = PTHREAD_RWLOCK_INITIALIZER;
CM_ConnDdbInfo *g_sess = NULL;
DDB_TYPE g_dbType = DB_ETCD;
DdbConn g_gtm2Etcd = {0};
TlsAuthPath g_tlsPath = {{0}};
struct passwd *pw = NULL;
DynamicNodeReadOnlyInfo *g_dynamicNodeReadOnlyInfo = NULL;
global_barrier g_global_barrier_data = {0};
global_barrier *g_global_barrier = &g_global_barrier_data;
ClusterRole backup_open = CLUSTER_PRIMARY;
ClusterInstallType g_clusterInstallType = INSTALL_TYPE_DEFAULT;
Alarm UnbalanceAlarmItem[1];
Alarm ServerSwitchAlarmItem[1];
Alarm DoublePrimaryAlarmItem[1];
synchronous_standby_mode current_cluster_az_status = AnyFirstNo;
volatile cm_start_mode cm_server_start_mode = MAJORITY_START; /* cm_arbitration_mode needs to be deleted. */

THR_LOCAL ProcessingMode Mode = NormalProcessing;

int switch_rto = 600;
int force_promote = 0;
int cm_auth_method = CM_AUTH_TRUST;
/* modify from read only to read write for recovery disk usage */
int max_datastorage_threshold_check = 1800;
/* the percent when bigger than it, will not do auto switchover az */
int az_switchover_threshold = 100;
/* the sleep interval of az check */
int az_check_and_arbitrate_interval = 2;
/* the sleep interval of az1 and az2 connect check */
int az1_and_az2_connect_check_interval = 60;
/* the sleep delay time of az1 and az2 connect check */
int az1_and_az2_connect_check_delay_time = 150;
/* the times for phony dead to effective */
int phony_dead_effective_time = 5;
/* the interval for phony dead effective */
int instance_phony_dead_restart_interval = 21600;
/* the switch of cross az auto arbitration */
int enable_az_auto_switchover = 1;
/* delay time fro etcd unhealth */
int cmserver_demote_delay_on_etcd_fault = 8;
int cmserver_demote_delay_on_conn_less = 10;
int cmserver_promote_delay_count = 3;
int g_cmserver_promote_delay_count = 0;
int g_cmserverDemoteDelayOnDdbFault = cmserver_demote_delay_on_etcd_fault;
char g_enableDcf[10] = {0};
char g_shareDiskPath[MAX_PATH_LEN] = {0};
const uint32 majority_reelection_timeout_init = 10;
#ifdef ENABLE_MULTIPLE_NODES
const int coordinator_deletion_timeout_init = 45;
#endif
/* thread count of thread pool */
int cm_thread_count = DEFAULT_THREAD_NUM;
/* ccn change delay */
int ccn_change_delay_time = 10;

char *cm_server_dataDir = NULL;
/* Check support read only */
char g_enableSetReadOnly[10] = {'\0'};
/* Threshold of checking disk storage usage ratio for pre-alarm */
char g_enableSetPreAlarmThreshold[THREAHOLD_LEN] = {'\0'};
/* Check data disk storage usage ratio to set read-write mode */
char g_storageReadOnlyCheckCmd[MAX_PATH_LEN] = {'\0'};
char configDir[MAX_PATH_LEN] = {0};
char g_alarmConfigDir[MAX_PATH_LEN] = {0};
char cm_dynamic_configure_path[MAX_PATH_LEN] = {0};
char g_logicClusterListPath[MAX_PATH_LEN] = {0};
char instance_maintance_path[MAX_PATH_LEN] = {0};
char cluster_maintance_path[MAX_PATH_LEN] = {0};
char g_cmManualStartPath[MAX_PATH_LEN] = {0};
char minority_az_start_file[MAX_PATH_LEN] = {0};
char g_minorityAzArbitrateFile[MAX_PATH_LEN] = {0};
char g_cmsPModeFilePath[MAX_PATH_LEN] = {0};
char g_cmInstanceManualStartPath[MAX_PATH_LEN] = {0};
char cm_force_start_file_path[MAX_PATH_LEN] = {0};
CmAzInfo g_cmAzInfo[AZ_MEMBER_MAX_COUNT] = {{{0}}};
char g_queryBarrier[BARRIERLEN] = {0};
char g_targetBarrier[BARRIERLEN] = {0};
char g_doradoIp[CM_IP_LENGTH] = {0};
char g_votingDiskPath[MAX_PATH_LEN] = {0};

uint32 g_readOnlyThreshold = 85;
uint32 g_ss_enable_check_sys_disk_usage = 0;
uint32 datastorage_threshold_check_interval = 10;
uint32 ctl_stop_cluster_server_halt_arbitration_timeout = 0;
uint32 arbitration_majority_reelection_timeout = majority_reelection_timeout_init;
uint32 cn_delete_default_time = 25;
uint32 instance_heartbeat_timeout = 6;
uint32 instance_failover_delay_timeout = 0;
uint32 cmserver_ha_connect_timeout = 2;
DdbArbiCfg g_ddbArbicfg;
uint32 cmserver_self_vote_timeout = 6;
uint32 instance_keep_heartbeat_timeout = 40;
uint32 g_clusterStartingTimeout = 0;
uint32 g_clusterStartingArbitDelay = CLUSTER_STARTING_ARBIT_DELAY;
uint32 g_enableE2ERto = 0;
uint32 g_sslCertExpireCheckInterval = SECONDS_PER_DAY;
uint32 g_diskTimeout = 200;
uint32 g_agentNetworkTimeout = 6;
DnArbitrateMode g_dnArbitrateMode = QUORUM;
uint32 g_ddbNetworkIsolationTimeout = 20;
ddb_work_mode g_ddbWorkMode = DDB_WORK_MODE_NONE;
uint32 g_bigVoteNumInMinorityMode = 0;
#ifdef ENABLE_MULTIPLE_NODES
uint32 coordinator_heartbeat_timeout = cn_delete_default_time;
int32 g_cmAgentDeleteCn = 30;
#endif
uint32 g_cm_to_cm_report_sync_cycle_count = 0;
uint32 g_datanode_instance_count = 0;
uint32 g_gaussdb_restart_counts = 50; /* DN or CN restarts frequently due to core down */
uint32 g_cm_agent_kill_instance_time = 0;
uint32 g_cm_agent_set_most_available_sync_delay_time = 0;
uint32 g_instance_manual_start_file_exist = 0;
uint32 g_instance_status_for_cm_server[CM_PRIMARY_STANDBY_NUM] = {0};
uint32 g_instance_status_for_etcd[CM_PRIMARY_STANDBY_NUM] = {
    CM_ETCD_DOWN, CM_ETCD_DOWN, CM_ETCD_DOWN, CM_ETCD_DOWN, CM_ETCD_DOWN, CM_ETCD_DOWN, CM_ETCD_DOWN, CM_ETCD_DOWN};
uint32 g_instance_status_for_etcd_timeout[CM_PRIMARY_STANDBY_NUM] = {cmserver_and_etcd_instance_status_for_timeout,
    cmserver_and_etcd_instance_status_for_timeout,
    cmserver_and_etcd_instance_status_for_timeout,
    cmserver_and_etcd_instance_status_for_timeout,
    cmserver_and_etcd_instance_status_for_timeout,
    cmserver_and_etcd_instance_status_for_timeout,
    cmserver_and_etcd_instance_status_for_timeout,
    cmserver_and_etcd_instance_status_for_timeout};

uint32 g_nodeIndexForCmServer[CM_PRIMARY_STANDBY_NUM] = {INVALID_NODE_NUM,
    INVALID_NODE_NUM,
    INVALID_NODE_NUM,
    INVALID_NODE_NUM,
    INVALID_NODE_NUM,
    INVALID_NODE_NUM,
    INVALID_NODE_NUM,
    INVALID_NODE_NUM};

InstInfo g_cmsInstInfo[CM_PRIMARY_STANDBY_NUM] = {{0}};

uint32 g_instance_status_for_cm_server_timeout[CM_PRIMARY_STANDBY_NUM] = {cmserver_and_etcd_instance_status_for_timeout,
    cmserver_and_etcd_instance_status_for_timeout,
    cmserver_and_etcd_instance_status_for_timeout,
    cmserver_and_etcd_instance_status_for_timeout,
    cmserver_and_etcd_instance_status_for_timeout,
    cmserver_and_etcd_instance_status_for_timeout,
    cmserver_and_etcd_instance_status_for_timeout,
    cmserver_and_etcd_instance_status_for_timeout};
bool g_instance_status_for_cm_server_pending[CM_PRIMARY_STANDBY_NUM] = {
    false, false, false, false, false, false, false, false};
bool isNeedCancel = false;
bool g_init_cluster_mode = false;
bool g_open_new_logical = true;
bool g_getHistoryDnStatusFromDdb = false;
bool g_getHistoryCnStatusFromDdb = false;
bool g_needIncTermToDdbAgain = false;
bool g_clusterStarting = false;
bool g_isSharedStorageMode = false;
bool g_enableSetMostAvailableSync = false;
volatile bool g_isInRedoStateUnderSwitchover = false;
volatile bool g_needReloadSyncStandbyMode = false;

volatile uint32 g_refreshDynamicCfgNum = 0;

bool g_elastic_exist_node = false;

/* is true when gtm-free */
bool g_gtm_free_mode = false;

ssl_ctx_t *g_ssl_acceptor_fd = NULL;

volatile DDB_ROLE g_ddbRole = DDB_ROLE_UNKNOWN;

pthread_rwlock_t instance_status_rwlock = PTHREAD_RWLOCK_INITIALIZER;

uint32 g_current_node_index = 0;
uint32 g_dropped_cn[MAX_CN_NUM] = {0};

int g_init_cluster_delay_time = 0;
/* Record current time at the CMS instance is upgraded to the primary instance.
 * It is used to determine the status of the CM instance when the cluster is restarted or undo exception.
 * The detailed scheme is described as follows:
 * 1.The small node sends timeline message to the large node.
 * 2.The large node according to the timeline to determine whether it is the primary, or the standby.
 * 3.After the large node arbitrate successfully, the large node sends the broadcast msg to the small node.
 * 4.The small node judge whether it is standby or primary by the role of the peer.
 */
dynamic_cms_timeline *g_timeline = NULL;

int g_tcpKeepalivesIdle = 5;
int g_tcpKeepalivesInterval = 2;
int g_tcpKeepalivesCount = 3;

bool g_isStart = false;
bool g_kerberos_check_cms_primary_standby = false;
bool g_syncDnFinishRedoFlagFromDdb = false;

char g_cmStaticConfigurePath[MAX_PATH_LEN] = {0};

cm_fenced_UDF_report_status *g_fenced_UDF_report_status_ptr = NULL;
int *cn_dn_disconnect_times = NULL;
int *g_lastCnDnDisconnectTimes = NULL;
SSDoubleClusterMode g_ssDoubleClusterMode = SS_DOUBLE_NULL;

volatile switchover_az_mode cm_switchover_az_mode = AUTOSWITCHOVER_AZ;
volatile logic_cluster_restart_mode cm_logic_cluster_restart_mode = INITIAL_LOGIC_CLUSTER_RESTART;

CM_IOThreads gIOThreads;
CM_WorkThreads gWorkThreads;
CM_HAThreads gHAThreads;
CM_MonitorThread gMonitorThread;
CM_DdbStatusCheckAndSetThread gDdbCheckThread;
CM_MonitorNodeStopThread gMonitorNodeStopThread;

/*
 * if one of cm_servers crashes or cm_servers disconnect with each other, both of them
 * turn to pending after ha heartbeat timeout expired and close all cm_agent connect to
 * let them reconnect.
 * the one which got more than a half of cm_agent connection in specified seconds
 * promotes to primary and the other turns to standby.
 * after cm_server itself recovered from fault, cm_server arbitrates gtm and datanodes.
 * if gtm or datanodes crashes, cm_server detects the fault after instance heartbeat
 * timeout expired. and if the ha connection also lost, cm_server sends FAILOVER
 * command to cm_agent after a delayment.
 *
 * Time To Repair if both cm_server and gtm fault:
 *
 * cmserver_ha_heartbeat_timeout + max(cmserver_self_vote_timeout,3instance_heartbeat_timeout,
 * gtm ha heartbeat timeout) + instance_failover_delay_timeout
 *
 * Time To Repair if both cm_server and datanode fault:
 *
 * cmserver_ha_heartbeat_timeout + max(cmserver_self_vote_timeout, instance_heartbeat_timeout,
 * datanode ha heartbeat timeout) + instance_failover_delay_timeout
 */
uint32 g_instance_failover_delay_time_from_set = 0;
/* If all standby nodes in a cluster with cascaded standbys are abnormal
 * whether the cms will failover a cascaded standby node
 */
bool g_cms_enable_failover_cascade = false;
/* If all standby nodes in a cluster with cascaded standbys are abnormal and the threshold is reached,
 *then failover the cascaded standby.
 */
uint32 g_cascade_failover_count = 0;
uint32 cmserver_gs_guc_reload_timeout = 300;
uint32 serverHATimeout = 6;
uint32 cmserver_switchover_timeout = SWITCHOVER_DEFAULT_WAIT;
#ifdef ENABLE_MULTIPLE_NODES
uint32 g_cmd_disable_coordinatorId = 0;
#endif
int cm_server_current_role = CM_SERVER_UNKNOWN;
/* fault cn can be deleted only if normal cn number >= min_normal_cn_number */
const uint32 min_normal_cn_number = 1;
/* fault cn can be deleted if cn dn disconnect times >= cn_dn_disconnect_to_delete_time */
const int cn_dn_disconnect_to_delete_time = 4;

int cm_server_arbitrate_delay_set = 0;

const int ctl_stop_cluster_server_halt_arbitration_timeout_init = 30;
#ifdef ENABLE_MULTIPLE_NODES
uint32 g_cnDeleteDelayTimeForClusterStarting = 0;
uint32 g_cnDeleteDelayTimeForDnWithoutPrimary = 0;
#endif
bool g_dnWithoutPrimaryFlag = false;
bool do_finish_redo = false;
int g_monitor_thread_check_invalid_times = 0;
/* lock for switchover -A, we do not allow more than one switchover -A running at the same time. */
pthread_rwlock_t switchover_full_rwlock = PTHREAD_RWLOCK_INITIALIZER;
bool switchoverFullInProgress = false;

/* lock for switchover -A, we do not allow more than one switchover -A running at the same time. */
pthread_rwlock_t switchover_az_rwlock = PTHREAD_RWLOCK_INITIALIZER;
bool switchoverAZInProgress = false;

pthread_rwlock_t gsguc_feedback_rwlock = PTHREAD_RWLOCK_INITIALIZER;
pthread_rwlock_t g_finish_redo_rwlock = PTHREAD_RWLOCK_INITIALIZER;
int g_cms_ha_heartbeat = 1;
uint32 cmserver_and_etcd_instance_status_for_timeout = 20;
/* the thread that add or increase standby nums is started. */
volatile reduceOrIncreaseSyncLists g_isEnableUpdateSyncList = CANNOT_START_SYNCLIST_THREADS;
bool g_inReload = false;
volatile bool g_inMaintainMode = false;
ThreadExecStatus g_loopState = {0};
DdbArbiCon g_ddbArbiCon = {0};
uint32 g_delayArbiTime = 0;
int32 g_clusterArbiTime = 300;
bool g_isPauseArbitration = false;
char g_cmManualPausePath[MAX_PATH_LEN] = {0};
uint32 g_waitStaticPrimaryTimes = 6;
uint32 g_realtimeBuildStatus = 0;

/* The global time structure of ondemand redo check. */
int g_onDemandStatus[MAX_ONDEMAND_NODE_STATUS] = {0};
time_t g_onDemandStatusTime[MAX_ONDEMAND_NODE_STATUS] = {0};

pthread_rwlock_t g_ondemandStatusCheckRwlock = PTHREAD_RWLOCK_INITIALIZER;


bool isLargerNode()
{
    if (IsInteractWithDdb(false, true)) {
        return false;
    }

    return (!g_single_node_cluster && (g_current_node_index != g_nodeIndexForCmServer[0]));
}

void initazArray(char azArray[][CM_AZ_NAME])
{
    const uint32 numTwo = 2;
    uint32 azIndex = 0;
    for (uint32 i = 0; i < g_node_num; i++) {
        if (strlen(g_node[i].azName) == 0) {
            write_runlog(WARNING, "current azName is invalid: %s.\n", g_node[i].azName);
            continue;
        }

        bool findAz = false;
        for (uint32 j = 0; j < AZ_MEMBER_MAX_COUNT; j++) {
            if (strcmp(g_node[i].azName, *(azArray + j)) == 0) {
                findAz = true;
                break;
            }
        }

        if (findAz) {
            continue;
        }

        uint32 priority = g_node[i].azPriority;
        if (priority < g_az_master) {
            write_runlog(FATAL, "az name is:%s, invalid priority=%u.\n", g_node[i].azName, g_node[i].azPriority);
            FreeNotifyMsg();
            exit(1);
        } else if (priority >= g_az_master && priority < g_az_slave) {
            azIndex = 0;
        } else if (priority >= g_az_slave && priority < g_az_arbiter) {
            azIndex = 1;
        } else {
            azIndex = numTwo;
        }

        int rc = memcpy_s(*(azArray + azIndex), CM_AZ_NAME, g_node[i].azName, CM_AZ_NAME);
        securec_check_errno(rc, (void)rc);
        write_runlog(DEBUG1, "after init, the valid azName is: %s, index is: %u.\n", *(azArray + azIndex), azIndex);
    }
}

maintenance_mode getMaintenanceMode(const uint32 &group_index)
{
    maintenance_mode mode = MAINTENANCE_MODE_NONE;
    uint32 upgradeMode = GetClusterUpgradeMode();
    /* MAINTENANCE_MODE_NONE */
    if (upgradeMode == 0) {
        if (existMaintenanceInstanceInGroup(group_index, NULL)) {
            mode = MAINTENANCE_MODE_DILATATION;
        } else if (ExistClusterMaintenance(NULL)) {
            mode = MAINTENANCE_NODE_DISASTER_RECOVERY;
        }
    } else if (upgradeMode == 1) {
        mode = MAINTENANCE_MODE_UPGRADE_OBSERVATION;
    } else if (upgradeMode == MAINTENANCE_NODE_UPGRADED_GRAYSCALE) {
        mode = MAINTENANCE_NODE_UPGRADED_GRAYSCALE;
    } else {
        mode = MAINTENANCE_MODE_UPGRADE;
    }
    return mode;
}
inline bool isDisableSwitchoverDN(const maintenance_mode &mode)
{
    return (mode == MAINTENANCE_MODE_UPGRADE || mode == MAINTENANCE_MODE_DILATATION);
}

inline bool isDisableFailoverDN(const maintenance_mode &mode)
{
    return (mode == MAINTENANCE_MODE_UPGRADE || mode == MAINTENANCE_MODE_DILATATION);
}
inline bool isDisableBuildDN(const maintenance_mode &mode)
{
    bool isDisable = false;
    if (mode == MAINTENANCE_MODE_UPGRADE) {
        isDisable = true;
    } else if (mode == MAINTENANCE_MODE_DILATATION) {
        isDisable = g_multi_az_cluster ? false : true;
    } else if (mode == MAINTENANCE_NODE_DISASTER_RECOVERY) {
        isDisable = true;
    }
    return isDisable;
}
inline bool isDisableDropCN(const maintenance_mode &mode)
{
    return (mode == MAINTENANCE_MODE_UPGRADE || mode == MAINTENANCE_MODE_UPGRADE_OBSERVATION ||
            mode == MAINTENANCE_MODE_DILATATION);
}

inline bool isDisablePhonyDeadCheck(const maintenance_mode &mode)
{
    return (mode == MAINTENANCE_MODE_UPGRADE || mode == MAINTENANCE_MODE_UPGRADE_OBSERVATION ||
            mode == MAINTENANCE_MODE_DILATATION);
}

static bool RestCmaKillTimeOut(int32 *timeout, int32 staticRole, int32 dynamicRole)
{
    /* report role has primary */
    if (dynamicRole == INSTANCE_ROLE_PRIMARY) {
        *timeout = 0;
        return true;
    }
    /* static primary is not offline */
    if (staticRole == INSTANCE_ROLE_PRIMARY && dynamicRole != INSTANCE_ROLE_UNKNOWN) {
        *timeout = 0;
        return true;
    }
    return false;
}

static void DealGtmPrimaryDown(uint32 groupIdx)
{
    int32 count = g_instance_role_group_ptr[groupIdx].count;
    cm_instance_report_status *instRep = &(g_instance_group_report_status_ptr[groupIdx].instance_status);
    cm_instance_gtm_report_status *gtmRep = instRep->gtm_member;
    cm_instance_role_status *instRole = g_instance_role_group_ptr[groupIdx].instanceMember;
    bool res = false;
    for (int32 i = 0; i < count; ++i) {
        res = RestCmaKillTimeOut(
            &instRep->cma_kill_instance_timeout, instRole[i].role, gtmRep[i].local_status.local_role);
        if (res) {
            return;
        }
    }
    for (int32 i = 0; i < count; ++i) {
        if (gtmRep[i].local_status.connect_status == CON_OK && instRep->cma_kill_instance_timeout < 1 &&
            gtmRep[i].local_status.local_role == INSTANCE_ROLE_STANDBY) {
            instRep->cma_kill_instance_timeout = (int)g_cm_agent_kill_instance_time;
            write_runlog(LOG,
                "instance %u, dbstate is normal, will set kill instance timeout %u.\n",
                instRole[i].instanceId,
                g_cm_agent_kill_instance_time);
            return;
        }
        if (instRep->cma_kill_instance_timeout == 1 && instRole[i].role == INSTANCE_ROLE_PRIMARY &&
            gtmRep[i].local_status.local_role == INSTANCE_ROLE_PRIMARY) {
            kill_instance_for_agent_fault(instRole[i].node, instRole[i].instanceId, INSTANCE_TYPE_GTM);
            instRep->cma_kill_instance_timeout = 0;
        }
    }
}

static void SendKillForAgentFault(uint32 groupIdx)
{
    int32 count = g_instance_role_group_ptr[groupIdx].count;
    cm_instance_report_status *instRep = &(g_instance_group_report_status_ptr[groupIdx].instance_status);
    cm_instance_datanode_report_status *dnRep = instRep->data_node_member;
    cm_instance_role_status *instRole = g_instance_role_group_ptr[groupIdx].instanceMember;
    for (int32 i = 0; i < count; ++i) {
        if (dnRep[i].local_status.local_role == INSTANCE_ROLE_STANDBY &&
            dnRep[i].local_status.db_state == INSTANCE_HA_STATE_NORMAL && instRep->cma_kill_instance_timeout < 1) {
            instRep->cma_kill_instance_timeout = (int)g_cm_agent_kill_instance_time;
            write_runlog(LOG,
                "instance %u, dbstate is normal, will set kill instance timeout %d.\n",
                instRole[i].instanceId,
                (int)g_cm_agent_kill_instance_time);
        }
        if (instRep->cma_kill_instance_timeout == 1 && instRole[i].role == INSTANCE_ROLE_PRIMARY &&
            dnRep[i].local_status.local_role == INSTANCE_ROLE_UNKNOWN) {
            kill_instance_for_agent_fault(instRole[i].node, instRole[i].instanceId, INSTANCE_TYPE_DATANODE);
            instRep->cma_kill_instance_timeout = 0;
        }
    }
}

static void DealDnPrimaryDown(uint32 groupIdx)
{
    int32 count = g_instance_role_group_ptr[groupIdx].count;
    cm_instance_report_status *instRep = &(g_instance_group_report_status_ptr[groupIdx].instance_status);
    cm_instance_datanode_report_status *dnRep = instRep->data_node_member;
    cm_instance_role_status *instRole = g_instance_role_group_ptr[groupIdx].instanceMember;
    bool res = false;
    for (int32 i = 0; i < count; ++i) {
        res =
            RestCmaKillTimeOut(&instRep->cma_kill_instance_timeout, instRole[i].role, dnRep[i].local_status.local_role);
        if (res) {
            return;
        }
        cm_local_replconninfo *dnState = &(dnRep[i].local_status);
        if (dnState->local_role == INSTANCE_ROLE_STANDBY && dnState->db_state != INSTANCE_HA_STATE_NEED_REPAIR &&
            dnState->db_state != INSTANCE_HA_STATE_NORMAL) {
            instRep->cma_kill_instance_timeout = 0;
            return;
        }
    }
    SendKillForAgentFault(groupIdx);
}

void DealDbstateNormalPrimaryDown(uint32 groupIdx, int32 instType)
{
    switch (instType) {
        case INSTANCE_TYPE_GTM:
            DealGtmPrimaryDown(groupIdx);
            return;
        case INSTANCE_TYPE_DATANODE:
            DealDnPrimaryDown(groupIdx);
            return;
        default:
            write_runlog(WARNING, "undefined instType(%d), cannot deal normal primary down.\n", instType);
            return;
    }
}

bool isMaintenanceInstance(const char *file_path, uint32 notify_instance_id)
{
    char current[INSTANCE_ID_LEN] = {0};
    bool instanceMaintenance = false;

    FILE *fd = fopen(file_path, "r");
    if (fd == NULL) {
        write_runlog(DEBUG1, "can't open the  MaintenanceInstance file\n");
        return instanceMaintenance;
    }

    while (!feof(fd)) {
        if (fscanf_s(fd, "%s\n", current, INSTANCE_ID_LEN) < 0) {
            (void)fclose(fd);
            write_runlog(LOG, "get MaintenanceInstance content failed \n");
            return instanceMaintenance;
        }
        if ((strlen(current) != 0) && ((uint32)strtol(current, NULL, 10) == notify_instance_id)) {
            write_runlog(
                LOG, "get MaintenanceInstance successfully, the current datanodeId is %u\n", notify_instance_id);
            instanceMaintenance = true;
            break;
        }
    }
    (void)fclose(fd);
    return instanceMaintenance;
}
int cmserver_getenv(const char *env_var, char *output_env_value, uint32 env_value_len, int elevel)
{
    return cm_getenv(env_var, output_env_value, env_value_len, elevel);
}

bool IsNodeInMinorityAz(uint32 groupIdx, int32 memIdx)
{
    return (g_minorityAzName != NULL &&
            strcmp(g_instance_role_group_ptr[groupIdx].instanceMember[memIdx].azName, g_minorityAzName) == 0);
}

bool existMaintenanceInstanceInGroup(uint32 group_index, int *init_primary_member_index)
{
    bool instanceMaintenance = false;
    for (int member_index = 0; member_index < g_instance_role_group_ptr[group_index].count; member_index++) {
        int instanceRoleInit = g_instance_role_group_ptr[group_index].instanceMember[member_index].instanceRoleInit;
        if (instanceRoleInit == INSTANCE_ROLE_PRIMARY) {
            instanceMaintenance = isMaintenanceInstance(instance_maintance_path,
                g_instance_role_group_ptr[group_index].instanceMember[member_index].instanceId);
            if (init_primary_member_index != NULL) {
                *init_primary_member_index = member_index;
            }
            break;
        }
    }
    return instanceMaintenance;
}

int check_if_candidate_is_in_faulty_az(uint32 group_index, int candidate_member_index)
{
    if (candidate_member_index == MINUS_ONE) {
        return MINUS_ONE;
    }
    cm_instance_role_group *role_group = &g_instance_role_group_ptr[group_index];
    cm_instance_role_status *instanceMember = role_group->instanceMember;
    char azArray[AZ_MEMBER_MAX_COUNT][CM_AZ_NAME] = {{0}};
    initazArray(azArray);
    int faultyAZ;

    if ((current_cluster_az_status == AnyAz1) || (current_cluster_az_status == FirstAz1)) {
        faultyAZ = AZ2_INDEX;
    } else if ((current_cluster_az_status == AnyAz2) || (current_cluster_az_status == FirstAz2)) {
        faultyAZ = AZ1_INDEX;
    } else {
        /* If the cluster AZ status is normal, then we don't bother go any further */
        return candidate_member_index;
    }

    if (strcmp(azArray[faultyAZ], instanceMember[candidate_member_index].azName) == 0) {
        write_runlog(WARNING,
            "Selected candidate dn %u is in a faulty AZ (%s). Current AZ status is %d."
            "Invalid candidate primary.\n",
            instanceMember[candidate_member_index].instanceId,
            azArray[faultyAZ],
            (int)current_cluster_az_status);
        return -1;
    }

    return candidate_member_index;
}
/*
 * pending the notify broadcast msg to each coordinator map.
 */
void cm_pending_notify_broadcast_msg(uint32 group_index, uint32 instanceId)
{
    WITHOUT_CN_CLUSTER("notify cn");

    cm_notify_msg_status *notify_msg = NULL;
    uint32 i;
    uint32 notify_index = 0;

    write_runlog(LOG, "cm pending notify broadcast msg group %u, instanceId %u.\n", group_index, instanceId);

    /* find the datanode index in the coordinator notify msg map. */
    for (i = 0; i < g_dynamic_header->relationCount; i++) {
        if (g_instance_role_group_ptr[i].instanceMember[0].instanceType == INSTANCE_TYPE_COORDINATE) {
            notify_msg = &g_instance_group_report_status_ptr[i].instance_status.coordinatemember.notify_msg;
            /* datanode_index may be null, and it could lead to coredump */
            if (notify_msg->datanode_index == NULL) {
                notify_msg = NULL;
                continue;
            }
            break;
        }
    }

    if (notify_msg == NULL) {
        write_runlog(FATAL, "cm_pending_notify_broadcast_msg:no coordinator configed in cluster.\n");
        FreeNotifyMsg();
        exit(1);
    }

    for (i = 0; i < g_datanode_instance_count; i++) {
        if (notify_msg->datanode_index != NULL && notify_msg->datanode_index[i] == group_index) {
            notify_index = i;
            break;
        }
    }

    if (i == g_datanode_instance_count) {
        write_runlog(ERROR, "could not locate group index %u in datanode index.\n", group_index);
        for (i = 0; i < g_datanode_instance_count; i++) {
            write_runlog(ERROR, "g_datanode index is %u, group index is %u.\n", i, notify_msg->datanode_index[i]);
        }
        return;
    }

    /* update the notify instance status */
    for (i = 0; i < g_dynamic_header->relationCount; i++) {
        if (g_instance_role_group_ptr[i].instanceMember[0].instanceType == INSTANCE_TYPE_COORDINATE) {
            (void)pthread_rwlock_wrlock(&(g_instance_group_report_status_ptr[i].lk_lock));
            notify_msg = &g_instance_group_report_status_ptr[i].instance_status.coordinatemember.notify_msg;
            write_runlog(DEBUG1,
                "pending datanode %u to coordinator %u notify map index %u\n",
                instanceId,
                g_instance_role_group_ptr[i].instanceMember[0].instanceId,
                notify_index);
            if (notify_msg->datanode_instance != NULL) {
                notify_msg->datanode_instance[notify_index] = instanceId;
                notify_msg->notify_status[notify_index] = true;
            }
            g_instance_group_report_status_ptr[i].instance_status.command_member[0].command_status =
                INSTANCE_COMMAND_WAIT_EXEC;
            g_instance_group_report_status_ptr[i].instance_status.command_member[0].pengding_command =
                MSG_CM_AGENT_NOTIFY_CN;
            if (g_instance_group_report_status_ptr[i].instance_status.command_member[0].notifyCnCount >= 0 &&
                g_instance_group_report_status_ptr[i].instance_status.command_member[0].notifyCnCount <
                MAX_COUNT_OF_NOTIFY_CN) {
                g_instance_group_report_status_ptr[i].instance_status.command_member[0].notifyCnCount++;
            } else {
                g_instance_group_report_status_ptr[i].instance_status.command_member[0].notifyCnCount = 0;
            }
            (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[i].lk_lock));
        }
    }
}

bool IsMaintenanceModeDisableOperation(const cms_operation &op, maintenance_mode mode)
{
    bool isDisable = false;
    switch (op) {
        case CMS_SWITCHOVER_DN:
            isDisable = isDisableSwitchoverDN(mode);
            break;
        case CMS_FAILOVER_DN:
            isDisable = isDisableFailoverDN(mode);
            break;
        case CMS_BUILD_DN:
            isDisable = isDisableBuildDN(mode);
            break;
        case CMS_DROP_CN:
            isDisable = isDisableDropCN(mode);
            break;
        case CMS_PHONY_DEAD_CHECK:
            isDisable = isDisablePhonyDeadCheck(mode);
            break;
        default:
            break;
    }
    return isDisable;
}

int find_other_member_index_for_DN_psd(uint32 group_index, int member_index)
{
    int candiateMemberIndex = -1;
    int staticPrimaryIndex = -1;
    cm_instance_role_group *role_group = &g_instance_role_group_ptr[group_index];
    int count = role_group->count;
    cm_instance_role_status *instanceMember = role_group->instanceMember;
    cm_instance_datanode_report_status *dnReportStatus =
        g_instance_group_report_status_ptr[group_index].instance_status.data_node_member;

    for (int i = 0; i < count; i++) {
        if (instanceMember[i].role == INSTANCE_ROLE_PRIMARY) {
            staticPrimaryIndex = i;
            break;
        }
    }

    if (staticPrimaryIndex == -1) {
        XLogRecPtr last_lsn = 0;
        write_runlog(LOG,
            "There is no static primary when finding the peer member of instance %u.\n",
            instanceMember[member_index].instanceId);
        int onlineCount = 0;
        for (int i = 0; i < count; i++) {
            if (dnReportStatus[i].local_status.local_role == INSTANCE_ROLE_STANDBY ||
                dnReportStatus[i].local_status.local_role == INSTANCE_ROLE_PENDING) {
                if (XLogRecPtrIsInvalid(dnReportStatus[i].local_status.last_flush_lsn)) {
                    continue;
                }
                onlineCount++;
                if (XLByteLT(last_lsn, dnReportStatus[i].local_status.last_flush_lsn)) {
                    last_lsn = dnReportStatus[i].local_status.last_flush_lsn;
                    staticPrimaryIndex = i;
                }
            }
        }

        if (onlineCount >= (count + 1) / 2 && staticPrimaryIndex != -1) {
            change_primary_member_index(group_index, staticPrimaryIndex);
            (void)WriteDynamicConfigFile(false);
        }
    }

    if (arbitration_majority_reelection_timeout > 0) {
        write_runlog(DEBUG1,
            "[arbitrator] The required condition for majority re-election is not met for primary/standby mode.\n");
    } else {
        if (g_instance_role_group_ptr[group_index].count >= 2) {
            if (member_index == 0) {
                candiateMemberIndex = 1;
            } else {
                candiateMemberIndex = 0;
            }
        }
    }
    return candiateMemberIndex;
}

/* When notify primary, cm set gtm ip and port to etcd */
int SetNotifyPrimaryInfoToEtcd(uint32 groupIndex, int memberIndex)
{
    errno_t rcs;
    uint32 i;
    char gtmPrimaryInfo[MAX_PATH_LEN] = {0};
    char gtmIpPort[GTM_IP_PORT] = {0};
    char primaryIp[CM_IP_NUM][CM_IP_LENGTH] = {{0}};
    uint32 primaryPort = 0;

    if (g_multi_az_cluster) {
        cm_server_start_mode = get_cm_start_mode(minority_az_start_file);
    }

    /* if GTM is been notify, failover or switchover to primary, set the ip and port to etcd. */
    uint32 primaryInstanceId = g_instance_role_group_ptr[groupIndex].instanceMember[memberIndex].instanceId;

    if ((cm_arbitration_mode == MINORITY_ARBITRATION || cm_server_start_mode == MINORITY_START)) {
        write_runlog(LOG,
            "%s: %d, instance(%u) MINORITY_ARBITRATION or MINORITY_START, do nothing.\n",
            __FUNCTION__,
            __LINE__,
            primaryInstanceId);
        return 0;
    }

    /*
     * if no etcd deployment, nothing to do. if etcd deployment but unhealthy,
     * return -1 and wait next gtm arbiration
     */
    if (g_etcd_num == 0) {
        write_runlog(LOG, "%s: %d, no etcd deployment.\n", __FUNCTION__, __LINE__);
        return 0;
    } else if (!IsDdbHealth(DDB_PRE_CONN)) {
        write_runlog(ERROR, "%s: %d, ddb is unhealthy.\n", __FUNCTION__, __LINE__);
        return -1;
    }

    for (i = 0; i < g_node_num; i++) {
        if (g_node[i].gtmId == primaryInstanceId) {
            rcs = memcpy_s(primaryIp, CM_IP_NUM * CM_IP_LENGTH, g_node[i].gtmLocalHAIP, CM_IP_NUM * CM_IP_LENGTH);
            securec_check_errno(rcs, (void)rcs);
            primaryPort = g_node[i].gtmLocalHAPort;
            break;
        }
    }

    if (i == g_node_num) {
        write_runlog(ERROR, "Can't find the gtm node.");
        return -1;
    }

    rcs =
        snprintf_s(gtmPrimaryInfo, sizeof(gtmPrimaryInfo), sizeof(gtmPrimaryInfo) - 1, "/%s/primary_info", pw->pw_name);
    securec_check_intval(rcs, (void)rcs);
    rcs = snprintf_s(gtmIpPort, sizeof(gtmIpPort), sizeof(gtmIpPort) - 1, "host=%s port=%u", primaryIp, primaryPort);
    securec_check_intval(rcs, (void)rcs);

    /* set gtm ip and port to etcd */
    status_t st = SetKVWithConn(GetDdbConnFromGtm(), gtmPrimaryInfo, MAX_PATH_LEN, gtmIpPort, GTM_IP_PORT);
    if (st != CM_SUCCESS) {
        write_runlog(ERROR,
            "%d: SetNotifyPrimaryInfoToEtcd, etcd set failed."
            "gtm_primary_info = %s, gtm_ip_port = %s.\n",
            __LINE__,
            gtmPrimaryInfo,
            gtmIpPort);
        return -1;
    } else {
        write_runlog(LOG,
            "%d: SetNotifyPrimaryInfoToEtcd, set ip and port to etcd successful."
            "gtm_primary_info = %s, gtm_ip_port = %s.\n",
            __LINE__,
            gtmPrimaryInfo,
            gtmIpPort);
    }
    return 0;
}

static bool IsInstanceCoreDump(uint32 groupIndex, int32 memberIndex)
{
    return g_instance_group_report_status_ptr[groupIndex]
            .instance_status.data_node_member[memberIndex]
            .local_status.db_state == INSTANCE_HA_STATE_COREDUMP;
}

static bool CheckInstPhonyDeadInterval(int32 phonyDealInterval, int32 phonyDeadTimes, uint32 instd)
{
    if (phonyDealInterval <= 0) {
        return true;
    }
    const int32 printLogInterval = 5;
    if (phonyDeadTimes >= phony_dead_effective_time && (phonyDealInterval % printLogInterval == 0)) {
        write_runlog(LOG,
            "the check for phony dead can't effective, instance is %u, check interval is %d.\n",
            instd,
            phonyDealInterval);
    }
    return false;
}

static void GetOtherMemIdxInDnPhonyDead(int32 *otherMemIdx, uint32 groupIdx, int32 memIdx)
{
    int32 count = g_instance_role_group_ptr[groupIdx].count;
    if (count <= 1) {
        return;
    }
    const int32 onePrimaryOneStandby = 2;
    if (count == onePrimaryOneStandby) {
        *otherMemIdx = (memIdx == 0) ? 1 : 0;
        return;
    }
    cm_instance_datanode_report_status *dnReport =
        g_instance_group_report_status_ptr[groupIdx].instance_status.data_node_member;
    cm_instance_datanode_report_status *curRep = &(dnReport[memIdx]);
    if (curRep->local_status.local_role != INSTANCE_ROLE_PRIMARY ||
        curRep->phony_dead_times < phony_dead_effective_time) {
        return;
    }
    for (int32 i = 0; i < count; ++i) {
        if (i == memIdx) {
            continue;
        }
        if ((XLByteLT_W_TERM(curRep->local_status.term, curRep->local_status.last_flush_lsn,
            dnReport[i].local_status.term, dnReport[i].local_status.last_flush_lsn)) &&
            dnReport[i].phony_dead_times == 0) {
            *otherMemIdx = i;
            break;
        }
    }
    if ((*otherMemIdx) == -1) {
        return;
    }
    cm_instance_role_status *dnRole = g_instance_role_group_ptr[groupIdx].instanceMember;
    write_runlog(LOG, "can't find a suiable instance to promot primary when %u is phony dead.\n",
        dnRole[memIdx].instanceId);
    for (int32 i = 0; i < count; ++i) {
        write_runlog(LOG, "instanceid: %u, static role: %s, dynamic role: %s, db state: %s, term %u, xlog: %X/%X, "
            "phony dead time: %d.\n", dnRole[i].instanceId, datanode_role_int_to_string(dnRole[i].role),
            datanode_role_int_to_string(dnReport[i].local_status.local_role),
            datanode_dbstate_int_to_string(dnReport[i].local_status.db_state), dnReport[i].local_status.term,
            (uint32)(dnReport[i].local_status.last_flush_lsn >> 32), (uint32)(dnReport[i].local_status.last_flush_lsn),
            dnReport[i].phony_dead_times);
    }
}

static void ReportInstPhonyDeadAlarm(uint32 instd, const char *typeName)
{
    char instanceName[CM_NODE_NAME] = {0};
    errno_t rc = snprintf_s(instanceName, CM_NODE_NAME, CM_NODE_NAME - 1, "%s%u", typeName, instd);
    securec_check_intval(rc, (void)rc);
    report_phony_dead_alarm(ALM_AT_Fault, instanceName, instd);
}

static void ReportAlarmAndSendRestart(
    MsgRecvInfo* recvMsgInfo, uint32 groupIdx, int32 memIdx, int32 oMemIdx, int32 instType)
{
    uint32 curInstd = g_instance_role_group_ptr[groupIdx].instanceMember[memIdx].instanceId;
    int32 curPhonyDeadTimes = -1;
    int32 oPhonyDeadTimes = -1;
    switch (instType) {
        case INSTANCE_TYPE_DATANODE: {
            ReportInstPhonyDeadAlarm(curInstd, "dn_");
            cm_instance_datanode_report_status *dnReport =
                g_instance_group_report_status_ptr[groupIdx].instance_status.data_node_member;
            curPhonyDeadTimes = dnReport[memIdx].phony_dead_times;
            if (oMemIdx >= 0) {
                oPhonyDeadTimes = dnReport[oMemIdx].phony_dead_times;
            }
            break;
        }
        case INSTANCE_TYPE_GTM: {
            ReportInstPhonyDeadAlarm(curInstd, "gtm_");
            cm_instance_gtm_report_status *gtmReport =
                g_instance_group_report_status_ptr[groupIdx].instance_status.gtm_member;
            curPhonyDeadTimes = gtmReport[memIdx].phony_dead_times;
            if (oMemIdx >= 0) {
                oPhonyDeadTimes = gtmReport[oMemIdx].phony_dead_times;
            }
            break;
        }
        case INSTANCE_TYPE_COORDINATE: {
            ReportInstPhonyDeadAlarm(curInstd, "cn_");
            cm_instance_coordinate_report_status *cnReport =
                &(g_instance_group_report_status_ptr[groupIdx].instance_status.coordinatemember);
            curPhonyDeadTimes = cnReport->phony_dead_times;
            break;
        }
        default:
            write_runlog(WARNING, "undefined instType(%d), cannot report phony dead alarm.\n", instType);
            break;
    }
    write_runlog(LOG,
        "phony dead times(%d:%d) already exceeded, will restart(%u)\n",
        curPhonyDeadTimes,
        oPhonyDeadTimes,
        curInstd);
    cm_to_agent_restart restartMsg = {0};
    restartMsg.msg_type = MSG_CM_AGENT_RESTART;
    restartMsg.node = g_instance_role_group_ptr[groupIdx].instanceMember[memIdx].node;
    restartMsg.instanceId = curInstd;
    WriteKeyEventLog(KEY_EVENT_RESTART,
        restartMsg.instanceId,
        "send restart message, node=%u, instanceId=%u",
        restartMsg.node,
        restartMsg.instanceId);
    (void)RespondMsg(recvMsgInfo, 'S', (const char *)&restartMsg, sizeof(cm_to_agent_restart));
}

static void CheckLocalDnIsPrimaryAndChangePrimaryIdx(uint32 groupIdx, int32 memIdx, int32 oMemIdx)
{
    if (oMemIdx == -1) {
        return;
    }
    cm_instance_datanode_report_status *dnReport =
        g_instance_group_report_status_ptr[groupIdx].instance_status.data_node_member;
    cm_instance_datanode_report_status *curRep = &(dnReport[memIdx]);
    if (curRep->local_status.local_role == INSTANCE_ROLE_PRIMARY &&
        g_instance_role_group_ptr[groupIdx].instanceMember[memIdx].role == INSTANCE_ROLE_PRIMARY &&
        dnReport[oMemIdx].phony_dead_times == 0) {
        if (!g_multi_az_cluster || (g_instance_group_report_status_ptr[groupIdx].instance_status.term <=
                                       dnReport[oMemIdx].local_status.term)) {
            ChangeDnPrimaryMemberIndex(groupIdx, oMemIdx);
        }
    }
}

static void RestInstDynamicRoleToUnkown(int32 *localRole, int32 phonyDeadTimes, uint32 instd, int32 instType)
{
    if (phonyDeadTimes >= phony_dead_effective_time && (*localRole == INSTANCE_ROLE_PRIMARY)) {
        write_runlog(LOG, "set %s(%u) role to unknown, it's phony dead is %d beyound to %d.\n",
            type_int_to_string(instType), instd, phonyDeadTimes, phony_dead_effective_time);
        *localRole = INSTANCE_ROLE_UNKNOWN;
    }
}

static status_t FindDoSwitchoverMemIdx(uint32 groupIdx, int32 *curMemIdx)
{
    cm_instance_command_status *cmd = g_instance_group_report_status_ptr[groupIdx].instance_status.command_member;
    for (int32 i = 0; i < g_instance_role_group_ptr[groupIdx].count; ++i) {
        if (cmd[i].pengding_command == (int32)MSG_CM_AGENT_SWITCHOVER) {
            *curMemIdx = i;
            return CM_SUCCESS;
        }
    }
    return CM_ERROR;
}

static void PrintNoRestartLog(uint32 groupIdx, int32 memIdx, uint32 instId)
{
    cm_instance_command_status *cmd = g_instance_group_report_status_ptr[groupIdx].instance_status.command_member;
    cmTime_t curTime = {0};
    (void)clock_gettime(CLOCK_MONOTONIC, &curTime);
    int32 logLevel = DEBUG1;
    const uint32 logInterval = 10;
    if (curTime.tv_sec - cmd[memIdx].cmTime.tv_sec > logInterval) {
        (void)clock_gettime(CLOCK_MONOTONIC, &(cmd[memIdx].cmTime));
        logLevel = LOG;
    }
    write_runlog(logLevel, "instId(%u) cannot send restart, because instId(%u) is doing switchover.\n",
        GetInstanceIdInGroup(groupIdx, memIdx), instId);
}

static bool8 CanSendRestart(uint32 groupIdx, int32 memIdx)
{
    cm_instance_command_status *cmd = g_instance_group_report_status_ptr[groupIdx].instance_status.command_member;
    if (cmd[memIdx].pengding_command == (int32)MSG_CM_AGENT_SWITCHOVER) {
        PrintNoRestartLog(groupIdx, memIdx, GetInstanceIdInGroup(groupIdx, memIdx));
        return CM_FALSE;
    }
    int32 switchoverMemIdx = 0;
    status_t st = FindDoSwitchoverMemIdx(groupIdx, &switchoverMemIdx);
    if (st != CM_SUCCESS) {
        return CM_TRUE;
    }
    if (cmd[switchoverMemIdx].peerInstId == GetInstanceIdInGroup(groupIdx, memIdx)) {
        PrintNoRestartLog(groupIdx, memIdx, GetInstanceIdInGroup(groupIdx, switchoverMemIdx));
        return CM_FALSE;
    }
    return CM_TRUE;
}

static void DealDnPhonyDead(MsgRecvInfo* recvMsgInfo, uint32 groupIdx, int32 memIdx)
{
    if (g_enableE2ERto) {
        DealDNPhonyDeadStatusE2E(groupIdx, memIdx);
        return;
    }
    uint32 curInstd = g_instance_role_group_ptr[groupIdx].instanceMember[memIdx].instanceId;
    if (IsInstanceCoreDump(groupIdx, memIdx)) {
        write_runlog(LOG, "instance(%u) may be core dump, cm server cannot deal phony dead status.\n", curInstd);
        return;
    }
    cm_instance_datanode_report_status *dnReport =
        g_instance_group_report_status_ptr[groupIdx].instance_status.data_node_member;
    cm_instance_datanode_report_status *curRep = &(dnReport[memIdx]);
    RestInstDynamicRoleToUnkown(
        &(curRep->local_status.local_role), curRep->phony_dead_times, curInstd, INSTANCE_TYPE_DATANODE);
    bool res = CheckInstPhonyDeadInterval(curRep->phony_dead_interval, curRep->phony_dead_times, curInstd);
    if (!res) {
        return;
    }
    int32 otherMemIdx = -1;
    GetOtherMemIdxInDnPhonyDead(&otherMemIdx, groupIdx, memIdx);
    if (curRep->phony_dead_times >= phony_dead_effective_time) {
        if (!CanSendRestart(groupIdx, memIdx)) {
            return;
        }
        ReportAlarmAndSendRestart(recvMsgInfo, groupIdx, memIdx, otherMemIdx, INSTANCE_TYPE_DATANODE);
        CheckLocalDnIsPrimaryAndChangePrimaryIdx(groupIdx, memIdx, otherMemIdx);
    }
}

void GetOtherMemIdxInGtmPhonyDead(int32 *oMemIdx, uint32 groupIdx, int32 memIdx)
{
    *oMemIdx = -1;
    int32 count = g_instance_role_group_ptr[groupIdx].count;
    if (count <= 1) {
        return;
    }
    const int32 onePrimaryOneStandby = 2;
    if (count == onePrimaryOneStandby) {
        *oMemIdx = (memIdx == 0) ? 1 : 0;
        return;
    }
    uint32 curInstd = g_instance_role_group_ptr[groupIdx].instanceMember[memIdx].instanceId;
    cm_instance_gtm_report_status *gtmReport = g_instance_group_report_status_ptr[groupIdx].instance_status.gtm_member;
    cm_instance_gtm_report_status *curRep = &(gtmReport[memIdx]);
    if (curRep->local_status.local_role != INSTANCE_ROLE_PRIMARY ||
        curRep->phony_dead_times < phony_dead_effective_time) {
        return;
    }
    for (int32 i = 0; i < count; ++i) {
        if (i == memIdx) {
            continue;
        }
        if (TransactionIdPrecedesOrEquals(curRep->local_status.xid, gtmReport[i].local_status.xid) &&
            gtmReport[i].phony_dead_times == 0) {
            *oMemIdx = i;
            break;
        }
    }
    if (*oMemIdx == -1) {
        write_runlog(LOG, "can't find a suiable instance to promot primary when %u is phony dead.\n", curInstd);
    }
}

static void CheckLocalGtmIsPrimaryAndChangePrimaryIdx(uint32 groupIdx, int32 memIdx, int32 oMemIdx)
{
    if (oMemIdx == -1) {
        return;
    }
    cm_instance_gtm_report_status *gtmReport = g_instance_group_report_status_ptr[groupIdx].instance_status.gtm_member;
    if (gtmReport[memIdx].local_status.local_role == INSTANCE_ROLE_PRIMARY &&
        g_instance_role_group_ptr[groupIdx].instanceMember[memIdx].role == INSTANCE_ROLE_PRIMARY &&
        gtmReport[oMemIdx].phony_dead_times == 0) {
        int32 res = SetNotifyPrimaryInfoToEtcd(groupIdx, oMemIdx);
        if (res == -1) {
            return;
        }
        change_primary_member_index(groupIdx, oMemIdx);
    }
}

static void DealGtmPhonyDead(MsgRecvInfo* recvMsgInfo, uint32 groupIdx, int32 memIdx)
{
    if (g_enableE2ERto) {
        DealGTMPhonyDeadStatusE2E(groupIdx, memIdx);
        return;
    }
    uint32 curInstd = g_instance_role_group_ptr[groupIdx].instanceMember[memIdx].instanceId;
    cm_instance_gtm_report_status *gtmReport = g_instance_group_report_status_ptr[groupIdx].instance_status.gtm_member;
    cm_instance_gtm_report_status *curRep = &(gtmReport[memIdx]);
    bool res = CheckInstPhonyDeadInterval(curRep->phony_dead_interval, curRep->phony_dead_times, curInstd);
    if (!res) {
        return;
    }
    int32 otherMemIdx;
    GetOtherMemIdxInGtmPhonyDead(&otherMemIdx, groupIdx, memIdx);
    if (curRep->phony_dead_times >= phony_dead_effective_time) {
        ReportAlarmAndSendRestart(recvMsgInfo, groupIdx, memIdx, otherMemIdx, INSTANCE_TYPE_GTM);
        CheckLocalGtmIsPrimaryAndChangePrimaryIdx(groupIdx, memIdx, otherMemIdx);
    }
    RestInstDynamicRoleToUnkown(
        &(curRep->local_status.local_role), curRep->phony_dead_times, curInstd, INSTANCE_TYPE_GTM);
}

static void ResetCnCentral(uint32 groupIdx, uint32 instd)
{
    cm_instance_coordinate_report_status *cnReport = NULL;
    for (uint32 i = 0; i < g_dynamic_header->relationCount; ++i) {
        if (i == groupIdx) {
            continue;
        }
        if (g_instance_role_group_ptr[i].instanceMember[0].instanceType != INSTANCE_TYPE_COORDINATE) {
            continue;
        }
        cnReport = &(g_instance_group_report_status_ptr[i].instance_status.coordinatemember);
        if (cnReport->phony_dead_times != 0 || cnReport->status.status != INSTANCE_ROLE_NORMAL) {
            continue;
        }
        if (g_centralNode.instanceId == instd) {
            errno_t rc = snprintf_s(g_centralNode.cnodename,
                NAMEDATALEN,
                NAMEDATALEN - 1,
                "cn_%u",
                g_instance_role_group_ptr[i].instanceMember[0].instanceId);
            securec_check_intval(rc, (void)rc);
            g_centralNode.instanceId = g_instance_role_group_ptr[i].instanceMember[0].instanceId;
            g_centralNode.node = g_instance_role_group_ptr[i].instanceMember[0].node;
            g_centralNode.recover = 0;
            break;
        }
    }
}

static void DealCnPhonyDead(MsgRecvInfo* recvMsgInfo, uint32 groupIdx, int32 memIdx)
{
    if (g_enableE2ERto) {
        DealCNPhonyDeadStatusE2E(groupIdx, memIdx);
        return;
    }
    uint32 curInstd = g_instance_role_group_ptr[groupIdx].instanceMember[memIdx].instanceId;
    cm_instance_coordinate_report_status *cnReport =
        &(g_instance_group_report_status_ptr[groupIdx].instance_status.coordinatemember);
    bool res = CheckInstPhonyDeadInterval(cnReport->phony_dead_interval, cnReport->phony_dead_times, curInstd);
    if (!res) {
        return;
    }
    if (cnReport->phony_dead_times >= phony_dead_effective_time && cnReport->status.status == INSTANCE_ROLE_NORMAL) {
        ReportAlarmAndSendRestart(recvMsgInfo, groupIdx, memIdx, -1, INSTANCE_TYPE_COORDINATE);
        ResetCnCentral(groupIdx, curInstd);
    }
    RestInstDynamicRoleToUnkown(
        &(cnReport->status.status), cnReport->phony_dead_times, curInstd, INSTANCE_TYPE_COORDINATE);
}

void DealPhonyDeadStatus(
    MsgRecvInfo* recvMsgInfo, int32 instRole, uint32 groupIdx, int32 memIdx, maintenance_mode mode)
{
    if (IsMaintenanceModeDisableOperation(CMS_PHONY_DEAD_CHECK, mode)) {
        write_runlog(LOG, "%d Maintaining cluster: cm server cannot deal phony dead status.\n", __LINE__);
        return;
    }
    switch (instRole) {
        case INSTANCE_TYPE_DATANODE:
            DealDnPhonyDead(recvMsgInfo, groupIdx, memIdx);
            return;
        case INSTANCE_TYPE_COORDINATE:
            DealCnPhonyDead(recvMsgInfo, groupIdx, memIdx);
            return;
        case INSTANCE_TYPE_GTM:
            DealGtmPhonyDead(recvMsgInfo, groupIdx, memIdx);
            return;
        default:
            write_runlog(ERROR, "undefined instRole(%d).\n", instRole);
            return;
    }
}

void CleanCommand(uint32 groupIndex, int memberIndex)
{
    cm_instance_command_status *curCmd =
        &g_instance_group_report_status_ptr[groupIndex].instance_status.command_member[memberIndex];
    if (curCmd->command_status != INSTANCE_NONE_COMMAND || curCmd->pengding_command != MSG_CM_AGENT_BUTT) {
        write_runlog(LOG,
            "instance %u will clean pending command, command_status=%d, pengding_command=%d, time_out=%d, "
            "command_send_times=%d, command_send_num=[%d/%d], full_build=%d. cmd[%d: %d: %d :%u].\n",
            g_instance_role_group_ptr[groupIndex].instanceMember[memberIndex].instanceId,
            curCmd->command_status,
            curCmd->pengding_command,
            curCmd->time_out,
            curCmd->command_send_times,
            curCmd->maxSendTimes,
            curCmd->command_send_num,
            curCmd->full_build,
            curCmd->cmdPur,
            curCmd->cmdSour,
            curCmd->cmdRealPur,
            curCmd->peerInstId);
    }

    curCmd->command_status = INSTANCE_NONE_COMMAND;
    curCmd->pengding_command = MSG_CM_AGENT_BUTT;
    curCmd->cmdPur = INSTANCE_ROLE_INIT;
    curCmd->cmdSour = INSTANCE_ROLE_INIT;
    curCmd->cmdRealPur = INSTANCE_ROLE_INIT;
    curCmd->peerInstId = 0;
    curCmd->time_out = 0;
    curCmd->delaySwitchoverTime = 0;
    curCmd->command_send_times = 0;
    curCmd->command_send_num = 0;
    curCmd->full_build = 0;
    curCmd->maxSendTimes = 0;
    curCmd->buildFailedTimeout = 0;
}

int find_other_member_index(uint32 groupIdx, int memIdx, int role)
{
    if (role == INSTANCE_TYPE_DATANODE) {
        return find_other_member_index_for_DN_psd(groupIdx, memIdx);
    }

    return -1;
}

void kill_instance_for_agent_fault(uint32 node, uint32 instanceId, int insType)
{
    char pid_path[MAXPGPATH] = {0};
    int rcs = 0;
    char data_dir[MAXPGPATH] = {0};
    char sshIp[CM_IP_LENGTH] = {0};
    bool findNode = false;
    for (uint32 i = 0; i < g_node_num; i++) {
        if (insType == INSTANCE_TYPE_DATANODE) {
            if (node != g_node[i].node) {
                continue;
            }
            for (uint32 j = 0; j < g_node[i].datanodeCount; j++) {
                if (g_node[i].datanode[j].datanodeId == instanceId) {
                    rcs = memcpy_s(data_dir, MAXPGPATH, g_node[i].datanode[j].datanodeLocalDataPath, MAXPGPATH - 1);
                    securec_check_errno(rcs, (void)rcs);
                    rcs = memcpy_s(sshIp, CM_IP_LENGTH, g_node[i].sshChannel[0], CM_IP_LENGTH - 1);
                    securec_check_errno(rcs, (void)rcs);
                    findNode = true;
                    break;
                }
            }
        } else if (insType == INSTANCE_TYPE_GTM) {
            if ((g_node[i].gtmId == instanceId) && (g_node[i].node == node)) {
                rcs = memcpy_s(data_dir, MAXPGPATH, g_node[i].gtmLocalDataPath, MAXPGPATH - 1);
                securec_check_errno(rcs, (void)rcs);
                rcs = memcpy_s(sshIp, CM_IP_LENGTH, g_node[i].sshChannel[0], CM_IP_LENGTH - 1);
                securec_check_errno(rcs, (void)rcs);
                findNode = true;
            }
        } else if (insType == INSTANCE_TYPE_COORDINATE) {
            if ((g_node[i].coordinateId == instanceId) && (g_node[i].node == node)) {
                rcs = memcpy_s(data_dir, MAXPGPATH, g_node[i].DataPath, MAXPGPATH - 1);
                securec_check_errno(rcs, (void)rcs);
                rcs = memcpy_s(sshIp, CM_IP_LENGTH, g_node[i].sshChannel[0], CM_IP_LENGTH - 1);
                securec_check_errno(rcs, (void)rcs);
                findNode = true;
            }
        } else {
            return;
        }

        if (findNode) {
            break;
        }
    }

    if (insType == INSTANCE_TYPE_DATANODE || insType == INSTANCE_TYPE_COORDINATE) {
        rcs = snprintf_s(pid_path, MAXPGPATH, MAXPGPATH - 1, "%s/%s", data_dir, "postmaster.pid");
    } else if (insType == INSTANCE_TYPE_GTM) {
        rcs = snprintf_s(pid_path, MAXPGPATH, MAXPGPATH - 1, "%s/%s", data_dir, "gtm.pid");
    } else {
        return;
    }
    securec_check_intval(rcs, (void)rcs);

    char command[MAXPGPATH] = {0};
    rcs = snprintf_s(command,
        MAXPGPATH,
        MAXPGPATH - 1,
        "pssh %s -s -H %s \"cat %s| head -n1 | xargs kill -9\" > /dev/null 2>&1 &",
        PSSH_TIMEOUT_OPTION,
        sshIp,
        pid_path);
    securec_check_intval(rcs, (void)rcs);

    uint32 tryTimes = 2;
    while (tryTimes > 0) {
        rcs = system(command);
        write_runlog(DEBUG1, "Call system command(%s) for killing disconnected instances.\n", command);
        if (rcs != 0) {
            /* If system command failed, we need try again. */
            write_runlog(ERROR, "Execute the command %s failed, errnum:%d, errno=%d.\n", command, rcs, errno);
            tryTimes--;
            cm_sleep(1);
            continue;
        }
        write_runlog(LOG, "Execute the command %s successfully.\n", command);
        break;
    }
}

int instance_delay_arbitrate_time_out(
    int localDynamicRole, int peerlDynamicRole, uint32 groupIdx, int memIdx, int delayMaxCount)
{
    cm_instance_command_status *localCmd =
        &(g_instance_group_report_status_ptr[groupIdx].instance_status.command_member[memIdx]);
    if (localCmd->arbitrate_delay_set == INSTANCE_ARBITRATE_DELAY_NO_SET) {
        if (delayMaxCount > 0) {
            localCmd->arbitrate_delay_set = INSTANCE_ARBITRATE_DELAY_HAVE_SET;
            localCmd->arbitrate_delay_time_out = delayMaxCount;
            localCmd->local_arbitrate_delay_role = localDynamicRole;
            localCmd->peerl_arbitrate_delay_role = peerlDynamicRole;

            write_runlog(LOG,
                "instance_delay_arbitrate_time_out start (node=%u instanceid=%u) local_delay_role=%d "
                "peerl_delay_role=%d "
                "local_dynamic_role=%d peerl_dynamic_role=%d delayMaxCount=%d arbitrate_delay_time_out=%d\n",
                g_instance_role_group_ptr[groupIdx].instanceMember[memIdx].node,
                g_instance_role_group_ptr[groupIdx].instanceMember[memIdx].instanceId,
                localCmd->local_arbitrate_delay_role,
                localCmd->peerl_arbitrate_delay_role,
                localDynamicRole,
                peerlDynamicRole,
                delayMaxCount,
                localCmd->arbitrate_delay_time_out);
        } else {
            return 1;
        }
    } else {
        if (localCmd->arbitrate_delay_time_out > delayMaxCount) {
            write_runlog(LOG, "instance_delay_arbitrate_time_out middle, change delay time to %d.\n", delayMaxCount);
            localCmd->arbitrate_delay_time_out = delayMaxCount;
        }

        if (localCmd->arbitrate_delay_time_out <= 0) {
            localCmd->arbitrate_delay_set = INSTANCE_ARBITRATE_DELAY_NO_SET;
            localCmd->arbitrate_delay_time_out = delayMaxCount;
            localCmd->local_arbitrate_delay_role = INSTANCE_ROLE_UNKNOWN;
            localCmd->peerl_arbitrate_delay_role = INSTANCE_ROLE_UNKNOWN;

            write_runlog(LOG,
                "instance_delay_arbitrate_time_out end (node=%u  instanceid=%u) local_delay_role=%d "
                "peerl_delay_role=%d "
                "local_dynamic_role=%d peerl_dynamic_role=%d delayMaxCount=%d arbitrate_delay_time_out=%d \n",
                g_instance_role_group_ptr[groupIdx].instanceMember[memIdx].node,
                g_instance_role_group_ptr[groupIdx].instanceMember[memIdx].instanceId,
                localCmd->local_arbitrate_delay_role,
                localCmd->peerl_arbitrate_delay_role,
                localDynamicRole,
                peerlDynamicRole,
                delayMaxCount,
                localCmd->arbitrate_delay_time_out);

            return 1;
        } else {
            write_runlog(DEBUG1,
                "instance_delay_arbitrate_time_out running (node=%u  instanceid=%u) "
                "local_delay_role=%d peerl_delay_role=%d"
                "local_dynamic_role=%d peerl_dynamic_role =%d delayMaxCount=%d arbitrate_delay_time_out=%d\n",
                g_instance_role_group_ptr[groupIdx].instanceMember[memIdx].node,
                g_instance_role_group_ptr[groupIdx].instanceMember[memIdx].instanceId,
                localCmd->local_arbitrate_delay_role,
                localCmd->peerl_arbitrate_delay_role,
                localDynamicRole,
                peerlDynamicRole,
                delayMaxCount,
                localCmd->arbitrate_delay_time_out);
        }
    }
    return 0;
}

void instance_delay_arbitrate_time_out_clean(
    int local_dynamic_role, int peerl_dynamic_role, uint32 group_index, int member_index, int delay_max_count)
{
    bool findDynaicPrimary = false;
    bool findStaticPrimary = false;
    bool isDNType = false;
    int staticPrimary = 0;
    bool needCleanSwitchover = false;
    for (int i = 0; i < g_instance_role_group_ptr[group_index].count; i++) {
        if (g_instance_role_group_ptr[group_index].instanceMember[member_index].instanceType == INSTANCE_TYPE_GTM) {
            if (g_instance_group_report_status_ptr[group_index].instance_status.gtm_member[i].local_status.local_role ==
                INSTANCE_ROLE_PRIMARY) {
                findDynaicPrimary = true;
                break;
            }
        } else {
            isDNType = true;
            if (g_instance_group_report_status_ptr[group_index]
                .instance_status.data_node_member[i]
                .local_status.local_role == INSTANCE_ROLE_PRIMARY) {
                findDynaicPrimary = true;
                break;
            }
        }
    }
    if (isDNType && findDynaicPrimary) {
        for (int i = 0; i < g_instance_role_group_ptr[group_index].count; i++) {
            if (g_instance_group_report_status_ptr[group_index].instance_status.data_node_member[i].arbitrateFlag) {
                write_runlog(LOG,
                    "clean arbitrateFlag, instance %u.\n",
                    g_instance_role_group_ptr[group_index].instanceMember[i].instanceId);
                g_instance_group_report_status_ptr[group_index].instance_status.data_node_member[i].arbitrateFlag =
                    false;
                g_instance_group_report_status_ptr[group_index].instance_status.cma_kill_instance_timeout = 0;
            }
        }
    }
    for (int i = 0; i < g_instance_role_group_ptr[group_index].count; i++) {
        if (g_instance_role_group_ptr[group_index].instanceMember[i].role == INSTANCE_ROLE_PRIMARY) {
            findStaticPrimary = true;
            staticPrimary = i;
            break;
        }
    }
    for (int i = 0; i < g_instance_role_group_ptr[group_index].count; i++) {
        if (g_instance_role_group_ptr[group_index].instanceMember[i].role == INSTANCE_ROLE_PRIMARY &&
            g_instance_group_report_status_ptr[group_index].instance_status.data_node_member[i]
            .local_status.local_role == INSTANCE_ROLE_PENDING) {
            needCleanSwitchover = true;
            break;
        }
        if (g_instance_group_report_status_ptr[group_index].instance_status.command_member[i].pengding_command ==
            (int32)MSG_CM_AGENT_SWITCHOVER &&
            g_instance_group_report_status_ptr[group_index].instance_status.data_node_member[i]
            .local_status.local_role == INSTANCE_ROLE_PENDING) {
            needCleanSwitchover = true;
            break;
        }
        if (g_instance_group_report_status_ptr[group_index].instance_status.command_member[i].pengding_command ==
                MSG_CM_AGENT_SWITCHOVER &&
            !IsArchiveMaxSendTimes(group_index, i)) {
            needCleanSwitchover = true;
            break;
        }
    }
    if (needCleanSwitchover) {
        for (int i = 0; i < g_instance_role_group_ptr[group_index].count; i++) {
            if (g_instance_group_report_status_ptr[group_index].instance_status.command_member[i].pengding_command ==
                MSG_CM_AGENT_SWITCHOVER) {
                write_runlog(LOG,
                    "clean switchover(%u) command, command send num(%d/%d).\n",
                    g_instance_role_group_ptr[group_index].instanceMember[i].instanceId,
                    GetSendTimes(group_index, i, false),
                    GetSendTimes(group_index, i, true));
                if (findStaticPrimary) {
                    write_runlog(LOG,
                        "clean switchover(%u), static primary(%d), switchover(%d), command_send_num(%d).\n",
                        g_instance_role_group_ptr[group_index].instanceMember[i].instanceId,
                        g_instance_group_report_status_ptr[group_index]
                            .instance_status.data_node_member[staticPrimary]
                            .local_status.local_role,
                        g_instance_group_report_status_ptr[group_index]
                            .instance_status.data_node_member[i]
                            .local_status.local_role,
                        g_instance_group_report_status_ptr[group_index]
                            .instance_status.command_member[i]
                            .command_send_num);
                }

                CleanCommand(group_index, i);
            }
        }
    }
    if (findDynaicPrimary &&
        (g_instance_group_report_status_ptr[group_index].instance_status.command_member[member_index]
        .local_arbitrate_delay_role != local_dynamic_role ||
        g_instance_group_report_status_ptr[group_index].instance_status.command_member[member_index]
        .peerl_arbitrate_delay_role != peerl_dynamic_role)) {
        g_instance_group_report_status_ptr[group_index].instance_status.command_member[member_index]
            .arbitrate_delay_set = INSTANCE_ARBITRATE_DELAY_NO_SET;
        g_instance_group_report_status_ptr[group_index].instance_status.command_member[member_index]
            .arbitrate_delay_time_out = delay_max_count;
        g_instance_group_report_status_ptr[group_index].instance_status.command_member[member_index]
            .local_arbitrate_delay_role = INSTANCE_ROLE_UNKNOWN;
        g_instance_group_report_status_ptr[group_index].instance_status.command_member[member_index]
            .peerl_arbitrate_delay_role = INSTANCE_ROLE_UNKNOWN;

        write_runlog(DEBUG1,
            "instance_delay_arbitrate_time_out_clean (node=%u instanceid=%u) local_delay_role=%d peerl_delay_role=%d "
            "local_dynamic_role=%d peerl_dynamic_role=%d delay_max_count=%d arbitrate_delay_time_out=%d\n",
            g_instance_role_group_ptr[group_index].instanceMember[member_index].node,
            g_instance_role_group_ptr[group_index].instanceMember[member_index].instanceId,
            g_instance_group_report_status_ptr[group_index]
                .instance_status.command_member[member_index]
                .local_arbitrate_delay_role,
            g_instance_group_report_status_ptr[group_index]
                .instance_status.command_member[member_index]
                .peerl_arbitrate_delay_role,
            local_dynamic_role,
            peerl_dynamic_role,
            delay_max_count,
            g_instance_group_report_status_ptr[group_index]
                .instance_status.command_member[member_index]
                .arbitrate_delay_time_out);
    }
}

bool &GetIsSharedStorageMode()
{
    return g_isSharedStorageMode;
}
