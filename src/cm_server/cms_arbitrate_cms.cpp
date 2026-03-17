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
 * cms_arbitrate_cms.cpp
 *    cms self arbitrate
 *
 * IDENTIFICATION
 *    src/cm_server/cms_arbitrate_cms.cpp
 *
 * -------------------------------------------------------------------------
 */
#include "cm/libpq-fe.h"
#include "cm/libpq-int.h"
#include "cms_alarm.h"
#include "cms_ddb.h"
#include "cms_conn.h"
#include "cms_global_params.h"
#include "cms_common.h"
#include "cms_arbitrate_cms.h"

static void CMServerRecord()
{
    write_runlog(LOG, "%d: node(%u) cm_server role is %s, to standby\n",
        __LINE__, g_currentNode->node, server_role_to_string(g_HA_status->local_role));

    g_HA_status->local_role = CM_SERVER_STANDBY;
    SendSignalToAgentThreads();
}

/*
 * @Description: init all instances' status. if ddb configured, primary doesn't
 * sync instances' status to standby. so standby must init instances' status
 * before failover in case of any expired status recorded in memory.
 */
static void coordinator_notify_msg_reset(void)
{
    WITHOUT_CN_CLUSTER("reset cn notify msg");
    uint32 i;
    uint32 j = 0;
    uint32 k = 0;
    errno_t rc = EOK;
    cm_notify_msg_status* notify_msg = NULL;
    cm_notify_msg_status* last_notify_msg = NULL;

    /* free memory of notify msg for each coordinator instance */
    for (i = 0; i < g_dynamic_header->relationCount; i++) {
        if (g_instance_role_group_ptr[i].instanceMember[0].instanceType != INSTANCE_TYPE_COORDINATE) {
            continue;
        }
        k = i;
        last_notify_msg = &g_instance_group_report_status_ptr[i].instance_status.coordinatemember.notify_msg;
        (void)pthread_rwlock_wrlock(&(g_instance_group_report_status_ptr[i].lk_lock));
        if (last_notify_msg->datanode_instance != NULL) {
            rc = memset_s(last_notify_msg->datanode_instance, sizeof(uint32) * g_datanode_instance_count,
                0, sizeof(uint32) * g_datanode_instance_count);
            securec_check_errno(rc, (void)rc);
        }

        if (last_notify_msg->datanode_index != NULL) {
            rc = memset_s(last_notify_msg->datanode_index, sizeof(uint32) * g_datanode_instance_count,
                0, sizeof(uint32) * g_datanode_instance_count);
            securec_check_errno(rc, (void)rc);
        }

        if (last_notify_msg->notify_status != NULL) {
            rc = memset_s(last_notify_msg->notify_status, sizeof(bool) * g_datanode_instance_count,
                0, sizeof(bool) * g_datanode_instance_count);
            securec_check_errno(rc, (void)rc);
        }

        if (last_notify_msg->have_notified != NULL) {
            rc = memset_s(last_notify_msg->have_notified, g_dynamic_header->relationCount,
                0, sizeof(bool) * g_dynamic_header->relationCount);
            securec_check_errno(rc, (void)rc);
        }

        if (last_notify_msg->have_dropped != NULL) {
            rc = memset_s(last_notify_msg->have_dropped, g_dynamic_header->relationCount,
                0, sizeof(bool) * g_dynamic_header->relationCount);
            securec_check_errno(rc, (void)rc);
        }
        (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[i].lk_lock));
    }

    if (last_notify_msg == NULL) {
        write_runlog(FATAL, "coordinator_notify_msg_reset:no coordinator configed in cluster.\n");
        FreeNotifyMsg();
        exit(1);
    }

    (void)pthread_rwlock_wrlock(&(g_instance_group_report_status_ptr[k].lk_lock));
    for (i = 0; i < g_dynamic_header->relationCount; i++) {
        if (g_instance_role_group_ptr[i].instanceMember[0].instanceType != INSTANCE_TYPE_DATANODE) {
            continue;
        }
        if (last_notify_msg->datanode_index != NULL) {
            last_notify_msg->datanode_index[j++] = i;
        }
    }
    (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[k].lk_lock));
    Assert(j == g_datanode_instance_count);

    for (i = 0; i < g_dynamic_header->relationCount; i++) {
        if (g_instance_role_group_ptr[i].instanceMember[0].instanceType != INSTANCE_TYPE_COORDINATE) {
            continue;
        }
        notify_msg = &g_instance_group_report_status_ptr[i].instance_status.coordinatemember.notify_msg;
        (void)pthread_rwlock_wrlock(&(g_instance_group_report_status_ptr[i].lk_lock));
        for (j = 0; j < g_datanode_instance_count; j++) {
            if (notify_msg->datanode_index != NULL && last_notify_msg->datanode_index != NULL) {
                notify_msg->datanode_index[j] = last_notify_msg->datanode_index[j];
            }
        }
        (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[i].lk_lock));
    }
}

static void clean_cn_heart_beat(int cmServerCurrentRole, int cm_server_last_role)
{
    if ((cmServerCurrentRole != CM_SERVER_PRIMARY) && (cm_server_last_role == CM_SERVER_PRIMARY)) {
        for (uint32 i = 0; i < g_dynamic_header->relationCount; i++) {
            if (g_instance_role_group_ptr[i].instanceMember[0].instanceType != INSTANCE_TYPE_COORDINATE) {
                continue;
            }
            (void)pthread_rwlock_wrlock(&(g_instance_group_report_status_ptr[i].lk_lock));
            g_instance_group_report_status_ptr[i].instance_status.command_member[0].heat_beat = 0;
            g_instance_group_report_status_ptr[i].instance_status.command_member[0].keep_heartbeat_timeout = 0;
            g_instance_group_report_status_ptr[i].instance_status.coordinatemember.auto_delete_delay_time = 0;
            (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[i].lk_lock));
            write_runlog(LOG, "cm_server change to Standby. clean instanceId: %u  heatbeat.\n",
                g_instance_role_group_ptr[i].instanceMember[0].instanceId);
        }
    }
}

static void CleanSwitchoverCommand()
{
    write_runlog(LOG, "cms change to primary, will clean switchover command.\n");
    for (uint32 i = 0; i < g_dynamic_header->relationCount; ++i) {
        if (g_instance_role_group_ptr[i].instanceMember[0].instanceType != INSTANCE_TYPE_DATANODE &&
            g_instance_role_group_ptr[i].instanceMember[0].instanceType != INSTANCE_TYPE_GTM) {
            continue;
        }
        for (int j = 0; j < g_instance_role_group_ptr[i].count; ++j) {
            if (g_instance_group_report_status_ptr[i].instance_status.command_member[j].pengding_command ==
                MSG_CM_AGENT_SWITCHOVER) {
                (void)pthread_rwlock_wrlock(&(g_instance_group_report_status_ptr[i].lk_lock));
                CleanCommand(i, j);
                (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[i].lk_lock));
            }
        }
    }
}

static void check_server_role_changed(int cm_server_role)
{
    bool need_to_reload = false;
    int cm_server_last_role = CM_SERVER_UNKNOWN;
    uint32 instanceId = g_currentNode->cmServerId;
    char instanceName[CM_NODE_NAME] = {0};
    errno_t rc;
#ifdef ENABLE_MULTIPLE_NODES
    const int bigClusterNodeCount = 32;
#endif

    if (!IsNeedSyncDdb()) {
        return;
    }

    if (cm_server_current_role != cm_server_role) {
        cm_server_last_role = cm_server_current_role;
        cm_server_current_role = cm_server_role;

        if ((cm_server_current_role == CM_SERVER_PRIMARY) && (cm_server_last_role != CM_SERVER_PRIMARY)) {
            need_to_reload = true;
            g_syncDnFinishRedoFlagFromDdb = true;
            g_kerberos_check_cms_primary_standby = true;

            write_runlog(LOG, "current node is %u, change it's role to primary.\n", g_currentNode->node);
        }

        clean_cn_heart_beat(cm_server_current_role, cm_server_last_role);

        if ((cm_server_current_role == CM_SERVER_PRIMARY) && (cm_server_last_role == CM_SERVER_STANDBY)) {
            rc = snprintf_s(instanceName, sizeof(instanceName), sizeof(instanceName) - 1, "server_%u", instanceId);
            securec_check_intval(rc, (void)rc);
            ServerSwitchAlarmItemInitialize();
            report_server_switch_alarm(ALM_AT_Event, instanceName);
        }
    }

    /* We need to actively do variable reload if we are promoted from standby to primary */
    if (need_to_reload) {
        write_runlog(LOG, "cm_server_current_role is %d. cm_server_last_role is %d.\n", cm_server_current_role,
            cm_server_last_role);
        write_runlog(LOG, "Promoted to PRIMARY. Do variable reset and reload.\n");
        CleanSwitchoverCommand();
        arbitration_majority_reelection_timeout = majority_reelection_timeout_init;
        write_runlog(LOG, "Setting arbitration_majority_reelection_timeout to %u.\n", majority_reelection_timeout_init);
#ifdef ENABLE_MULTIPLE_NODES
        if (cm_server_start_mode == MINORITY_START || g_node_num >= bigClusterNodeCount) {
            g_cnDeleteDelayTimeForClusterStarting = (uint32)coordinator_deletion_timeout_init;
            write_runlog(LOG,
                "Setting cn delete delay time to %d, cm_server_start_mode is %d, and g_node_num "
                "is %u.\n",
                coordinator_deletion_timeout_init, (int)cm_server_start_mode, g_node_num);
        } else {
            write_runlog(LOG,
                "not need to set cn delete delay time, cm_server_start_mode is %d, and "
                "g_node_num is %u\n",
                (int)cm_server_start_mode, g_node_num);
        }
#endif
    }
}

uint32 GetTermForMinorityStart(void)
{
    uint32 term = InvalidTerm;

    write_runlog(LOG,
        "Minority AZ Force Starting. Try to read term value from \"%s\"\n",
        cm_force_start_file_path);
    FILE *force_start_file = fopen(cm_force_start_file_path, "r");
    if (force_start_file == NULL) {
        return InvalidTerm;
    }

    if (fscanf_s(force_start_file, "%u", &term) != 1) {
        write_runlog(ERROR,
            "Minority AZ Force Starting. invalid data in term file: \"%s\"\n",
            cm_force_start_file_path);
        (void)fclose(force_start_file);
        return InvalidTerm;
    }

    write_runlog(LOG,
        "Minority AZ Force Starting. Succeed read term value from \"%s\" with term value:%u\n",
        cm_force_start_file_path, term);

    (void)fclose(force_start_file);
    return term;
}

static void HandleStartMode(cm_start_mode startMode)
{
    if ((cm_server_start_mode == MINORITY_START) && startMode == MAJORITY_START) {
        /* Make sure we are in case of arbitration mode changed from MINORITY to MAJORITY */
        uint32 term;
        (void)pthread_rwlock_wrlock(&term_update_rwlock);
        if (SetTermIfArbitrationChanged(&term) != 0) {
            g_arbitrationChangedFromMinority = true;
            write_runlog(ERROR, "need reset term to etcd!");
        }
        (void)pthread_rwlock_unlock(&term_update_rwlock);
        write_runlog(LOG, "CM start mode changed from MINORITY to MAJORITY. start mode:%d\n", cm_server_start_mode);
    } else if ((cm_server_start_mode == MAJORITY_START || cm_server_start_mode == OTHER_MINORITY_START) &&
               startMode == MINORITY_START) {
        /* Make sure we are not in case of arbitration mode changed from MINORITY to MAJORITY */
        g_arbitrationChangedFromMinority = false;

        /* Read term value from "force_start.info" file if exists  */
        if (g_dynamic_header->term == InvalidTerm) {
            g_dynamic_header->term = GetTermForMinorityStart();
            (void)IncrementTermToFile();
        }

        write_runlog(LOG,
            "CM start mode changed from MAJORITY/OTHER_MINORITY to MINORITY. start mode:%d\n",
            cm_server_start_mode);
    } else if (cm_server_start_mode == MAJORITY_START && startMode == OTHER_MINORITY_START) {
        /* Make sure we are not in case of arbitration mode changed from MINORITY to MAJORITY */
        g_arbitrationChangedFromMinority = false;
        write_runlog(LOG, "CM start mode changed from MAJORITY to OTHER_MINORITY. \n");
    }
}

cm_start_mode get_cm_start_mode(const char* path)
{
    cm_start_mode start_mode = MAJORITY_START;
    FILE* infile = NULL;

    arbitration_mode oldArbMode = cm_arbitration_mode;

    /* Check if minority flag file exits, we get cm_arbitration from its content */
    struct stat stat_buf = {0};
    if (stat(path, &stat_buf) == 0) {
        if ((infile = fopen(path, "r")) == NULL) {
            /* When read flag file fail we set cm_arbitration as it s default */
            g_minorityAzName = NULL;
            cm_arbitration_mode = MAJORITY_ARBITRATION;
            return start_mode;
        }

        if (fscanf_s(infile, "%u", &start_mode) != 1) {
            write_runlog(ERROR, "invalid data in az_start_mode file: \"%s\"\n", path);
            (void)fclose(infile);

            /* in case of error we set majority as default return mode */
            g_minorityAzName = NULL;
            cm_arbitration_mode = MAJORITY_ARBITRATION;
            return start_mode;
        }
        if (start_mode == static_cast<int32>(MINORITY_ARBITRATION)) {
            g_minorityAzName = g_currentNode->azName;
        } else {
            g_minorityAzName = NULL;
        }

        (void)fclose(infile);
        /* set cm_arbitration_mode by its start mode */
        switch (start_mode) {
            case MAJORITY_START:            /* in case of regular start */
            case OTHER_MINORITY_START:      /* in case of minority start but on other CMS node */
                cm_arbitration_mode = MAJORITY_ARBITRATION;
                break;
            case MINORITY_START:
                cm_arbitration_mode = MINORITY_ARBITRATION;
                break;
            default:
                cm_arbitration_mode = UNKNOWN_ARBITRATION;
                break;
        }
    } else {
        /* If flag file does not exists, use MAJOORITY as default */
        g_minorityAzName = NULL;
        cm_arbitration_mode = MAJORITY_ARBITRATION;
    }

    int logLevel = (oldArbMode == cm_arbitration_mode && cm_server_start_mode == start_mode) ? DEBUG1 : LOG;
    write_runlog(logLevel, "Start AZ with \"-z %s\" succeed, with start mode %d with arbitration mode %d\n",
        g_minorityAzName, start_mode, cm_arbitration_mode);

    HandleStartMode(start_mode);

    return start_mode;
}

static PromoteMode GetCmsPromoteMode()
{
    PromoteMode curPMode = PMODE_AUTO;

    FILE *pModeFile = NULL;
    struct stat statBuf = {0};
    if (stat(g_cmsPModeFilePath, &statBuf) == 0) {
        do {
            if ((pModeFile = fopen(g_cmsPModeFilePath, "r")) == NULL) {
                /* When read flag file fail we set cm_arbitration as it s default */
                write_runlog(ERROR, "cms pMode file(%s) can't be open, errno=%d.\n", g_cmsPModeFilePath, errno);
                curPMode = PMODE_AUTO;
                break;
            }

            if (fscanf_s(pModeFile, "%u", &curPMode) != 1) {
                write_runlog(ERROR, "invalid data in cms pMode file: \"%s\"\n", g_cmsPModeFilePath);
                /* in case of error we set auto as default cms arbitrate mode */
                curPMode = PMODE_AUTO;
            }
            (void)fclose(pModeFile);
        } while (0);
    }

    int logLevel = (curPMode != g_cmsPromoteMode) ? LOG : DEBUG1;
    write_runlog(logLevel, "Cms promote mode[%d] change to %d.\n", (int)g_cmsPromoteMode, (int)curPMode);
    g_cmsPromoteMode = curPMode;

    return g_cmsPromoteMode;
}

static void CmsChange2Primary(int32 *cmsDemoteDelayOnConnLess)
{
    if (g_HA_status->local_role == CM_SERVER_PRIMARY) {
        return;
    }
    if (IsNeedSyncDdb()) {
        (void)pthread_rwlock_wrlock(&term_update_rwlock);
        g_needIncTermToDdbAgain = true;
        (void)pthread_rwlock_unlock(&term_update_rwlock);
        g_needReloadSyncStandbyMode = true;
    }

    write_runlog(LOG, "node(%u) cms role is %s, change to primary by ddb, and g_ddbRole is %d.\n",
        g_currentNode->node, server_role_to_string(g_HA_status->local_role), (int)g_ddbRole);
    g_HA_status->local_role = CM_SERVER_PRIMARY;
    *cmsDemoteDelayOnConnLess = cmserver_demote_delay_on_conn_less;
    ClearSyncWithDdbFlag();
    if (g_dbType != DB_SHAREDISK) {
        NotifyDdb(DDB_ROLE_LEADER);
    }
}

static void PromoteCmsDirect(int32 *cmsDemoteDelayOnConnLess)
{
    write_runlog(DEBUG5, "local role is %s\n", server_role_to_string(g_HA_status->local_role));
    if ((g_HA_status->local_role != CM_SERVER_PRIMARY) || (g_ddbRole != DDB_ROLE_LEADER)) {
        write_runlog(LOG, "%d: node(%u) cm_server role is %s, direct to primary\n", __LINE__,
            g_currentNode->node, server_role_to_string(g_HA_status->local_role));
        CmsChange2Primary(cmsDemoteDelayOnConnLess);
        NotifyDdb(DDB_ROLE_LEADER);
    }
}

static void CmsChange2Standby()
{
    if (g_HA_status->local_role == CM_SERVER_STANDBY) {
        return;
    }
    if (g_HA_status->local_role == CM_SERVER_PRIMARY) {
        coordinator_notify_msg_reset();
    }
    write_runlog(LOG, "node(%u) cms role is %s, cms change to standby by ddb, and g_ddbRole is %d.\n",
        g_currentNode->node, server_role_to_string(g_HA_status->local_role), (int)g_ddbRole);
    g_HA_status->local_role = CM_SERVER_STANDBY;
    CMServerRecord();
    NotifyDdb(DDB_ROLE_FOLLOWER);
}

static uint32 g_resumeDelay = 0;
static uint32 g_reportDelay = 0;

static void CmsResumeDdbAlarm()
{
    const uint32 delayTimeout = 20;
    g_resumeDelay++;
    g_reportDelay = 0;
    if (g_resumeDelay >= delayTimeout) {
        report_ddb_fail_alarm(ALM_AT_Resume, "", 0);
    }
}

static void CmsReportDdbAlarm()
{
    const uint32 delayTimeout = 3;
    g_reportDelay++;
    g_resumeDelay = 0;
    if (g_reportDelay >= delayTimeout) {
        report_ddb_fail_alarm(ALM_AT_Fault, "", 0);
    }
}

static status_t CmsRoleChangeWithDdb(int32 *cmsDemoteDelayOnConnLess)
{
    if (!IsDdbHealth(DDB_PRE_CONN)) {
        write_runlog(LOG, "ddb is unhealth.\n");
        CmsReportDdbAlarm();
        return CM_ERROR;
    }
    /* keep cms primary stable */
    g_cmserverDemoteDelayOnDdbFault = cmserver_demote_delay_on_etcd_fault;
    CmsResumeDdbAlarm();
    if (g_ddbRole == DDB_ROLE_LEADER) {
        if (g_HA_status->local_role == CM_SERVER_PRIMARY) {
            return CM_SUCCESS;
        }
        CmsChange2Primary(cmsDemoteDelayOnConnLess);
    } else {
        if (g_HA_status->local_role == CM_SERVER_STANDBY) {
            return CM_SUCCESS;
        }
        CmsChange2Standby();
    }
    return CM_SUCCESS;
}

static void CheckCmsPrimaryAgentConn(int32 *cmsDemoteDelayOnConnLess)
{
    if (g_HA_status->local_role != CM_SERVER_PRIMARY) {
        return;
    }
    static int32 logLevel = LOG;
    /* only two cms node, no need check agent conn */
    const uint32 onePrimaryOneStandby = 2;
    if ((g_dbType == DB_DCC || g_dbType == DB_SHAREDISK) && g_cm_server_num <= onePrimaryOneStandby) {
        write_runlog(DEBUG1, "cur cluster only has two cms(%u) and dbtype is %d, not need to check agent conn.\n",
            g_cm_server_num, g_dbType);
        return;
    }
    uint32 count = GetCmsConnCmaCount();
    write_runlog(DEBUG1, "cmserver accept agent connection count = %u\n", count);
    /* in addition to the current node, there must be another agent connection */
    if (count <= 1) {
        if (count == 1 && CheckAgentConnIsCurrent(g_currentNode->node)) {
            *cmsDemoteDelayOnConnLess = cmserver_demote_delay_on_conn_less;
            write_runlog(logLevel, "current agent conn is not current node(%u), count is 1.\n", g_currentNode->node);
            logLevel = DEBUG1;
            return;
        }
        if (*cmsDemoteDelayOnConnLess == 0) {
            write_runlog(LOG,
                "turn to standy cms_demote_delay_on_conn_less later,"
                "because of the connection with cma is less than 1, count = %u.\n",
                count);
            CmsChange2Standby();
            NotifyDdb(DDB_ROLE_FOLLOWER);
            *cmsDemoteDelayOnConnLess = cmserver_demote_delay_on_conn_less;
        } else {
            --(*cmsDemoteDelayOnConnLess);
        }
    } else {
        *cmsDemoteDelayOnConnLess = cmserver_demote_delay_on_conn_less;
    }
    logLevel = LOG;
}

static bool CheckCmsInMonrityStart()
{
    if (!g_multi_az_cluster) {
        return false;
    }
    cm_server_start_mode = get_cm_start_mode(minority_az_start_file);
    if (cm_arbitration_mode != MINORITY_ARBITRATION && cm_server_start_mode != MINORITY_START) {
        return false;
    }
    write_runlog(DEBUG5, "local role is %s.\n", server_role_to_string(g_HA_status->local_role));
    if (g_HA_status->local_role != CM_SERVER_PRIMARY) {
        write_runlog(LOG, "%d: node(%u) cm_server role is %s, to primary\n", __LINE__, g_currentNode->node,
            server_role_to_string(g_HA_status->local_role));
        g_HA_status->local_role = CM_SERVER_PRIMARY;
        ClearSyncWithDdbFlag();
    }
    return true;
}

static void ComputArbTime(const struct timeval *checkBegin, struct timeval *checkEnd)
{
    const uint32 twoSec = 2;
    (void)gettimeofday(checkEnd, NULL);
    if ((checkEnd->tv_sec - checkBegin->tv_sec) > twoSec) {
        write_runlog(LOG, "line %d: it takes %llu to self-arbitrate.\n",
            __LINE__, (unsigned long long)GetTimeMinus(*checkEnd, *checkBegin));
        return;
    }
    cm_sleep(g_ddbArbicfg.haStatusInterval);
}

static void CheckCmsNeed2Standby()
{
    write_runlog(DEBUG5, "local role is %s\n", server_role_to_string(g_HA_status->local_role));
    uint32 count = GetCmsConnCmaCount();
    if (g_cmserverDemoteDelayOnDdbFault > 0 && g_HA_status->local_role == CM_SERVER_PRIMARY && count > g_node_num / 2) {
        if ((!g_multi_az_cluster) || cm_server_start_mode != OTHER_MINORITY_START) {
            write_runlog(LOG, "ddb is unhealth, and delay time is %d.\n", g_cmserverDemoteDelayOnDdbFault);
            return;
        }
    }
    write_runlog(LOG, "%d: ddb is unhealth, node(%u) cm_server role is %s, to standby, is unhealth.\n", __LINE__,
        g_currentNode->node, server_role_to_string(g_HA_status->local_role));
    CmsChange2Standby();
}

static void PromotePrimaryInSingleNode()
{
    if (g_HA_status->local_role == CM_SERVER_PRIMARY) {
        return;
    }
    write_runlog(LOG, "cm_server will change to primary from %d.\n", g_HA_status->local_role);
    g_HA_status->local_role = CM_SERVER_PRIMARY;
    ClearSyncWithDdbFlag();
    return;
}

static void ArbitratePromote(int32 *cmsDemoteDelayOnConnLess)
{
    bool isMonitoryStart = CheckCmsInMonrityStart();
    if (isMonitoryStart) {
        SetDdbMinority(true);
        return;
    }
    SetDdbMinority(false);

    if (g_dbType == DB_DCC &&
        ENABLED_AUTO_FAILOVER_ON2NODES(g_cm_server_num, g_paramsOn2Nodes.cmsEnableFailoverOn2Nodes) &&
        g_ddbWorkMode == DDB_WORK_MODE_NONE) {
        return;
    }

    status_t st = CmsRoleChangeWithDdb(cmsDemoteDelayOnConnLess);
    if (st == CM_SUCCESS) {
        CheckCmsPrimaryAgentConn(cmsDemoteDelayOnConnLess);
    } else {
        CheckCmsNeed2Standby();
    }
}

void *CM_ThreadHAMain(void *argp)
{
    struct timeval checkBeginFunction = {0, 0};
    struct timeval checkEndFunction = {0, 0};
    CM_HAThread* pHAThread = (CM_HAThread*)argp;

    pHAThread->thread.type = THREAD_TYPE_HA;
    /* unify log style */
    thread_name = "HA";

    write_runlog(LOG, "Starting HA thread\n");

    int32 cmsDemoteDelayOnConnLess = cmserver_demote_delay_on_conn_less;
    for (;;) {
        /* close the connection in case of memory leak. */
        (void)gettimeofday(&checkBeginFunction, NULL);
        if (got_stop == 1) {
            write_runlog(LOG, "close connection to peer cmserver.\n");
            ha_connection_closed = 1;
            cm_sleep(g_ddbArbicfg.haStatusInterval);
            continue;
        }

        check_server_role_changed(g_HA_status->local_role);

        if (GetCmsPromoteMode() == PMODE_FORCE_PRIMAYR) {
            PromoteCmsDirect(&cmsDemoteDelayOnConnLess);
        } else if (IsNeedSyncDdb()) {
            ArbitratePromote(&cmsDemoteDelayOnConnLess);
        } else {
            PromotePrimaryInSingleNode();
        }
        ComputArbTime(&checkBeginFunction, &checkEndFunction);
    }
    return NULL;
}
