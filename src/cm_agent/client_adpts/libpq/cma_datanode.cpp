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
 * cma_datanode.cpp
 *    cma client use libpq to check database
 *
 * IDENTIFICATION
 *    src/cm_agent/client_adpts/libpq/cma_datanode.cpp
 *
 * -------------------------------------------------------------------------
 */

#include <signal.h>
#include <math.h>
#include "cma_global_params.h"
#include "cma_datanode_utils.h"
#include "cma_common.h"
#include "cma_client.h"
#include "cma_instance_management.h"
#include "cma_process_messages.h"
#include "cma_network_check.h"

static cltPqConn_t* g_dnConnSend[CM_MAX_DATANODE_PER_NODE] = {NULL};

#define MAX_SQLCOMMAND_LENGTH 1024

static int g_lastBuildRole = INSTANCE_ROLE_INIT;
extern bool g_isDnFirstStart;

static int ProcessStatusFromStateFile(agent_to_cm_datanode_status_report *reportMsg, const GaussState *state)
{
    switch (state->mode) {
        case UNKNOWN_MODE:
            reportMsg->connectStatus = AGENT_TO_INSTANCE_CONNECTION_BAD;
            write_runlog(ERROR, "get local_role from DB state file: UNKNOWN_MODE.\n");
            return -1;
        case NORMAL_MODE:
            reportMsg->connectStatus = AGENT_TO_INSTANCE_CONNECTION_BAD;
            write_runlog(ERROR, "get local_role from DB state file: NORMAL_MODE.\n");
            return -1;
        case PRIMARY_MODE:
            reportMsg->local_status.local_role = INSTANCE_ROLE_PRIMARY;
            write_runlog(LOG, "get local_role from DB state file: PRIMARY_MODE.\n");
            break;
        case STANDBY_MODE:
            reportMsg->local_status.local_role = INSTANCE_ROLE_STANDBY;
            write_runlog(LOG, "get local_role from DB state file: STANDBY_MODE.\n");
            break;
        case PENDING_MODE:
            reportMsg->local_status.local_role = INSTANCE_ROLE_PENDING;
            write_runlog(LOG, "get local_role from DB state file: PENDING_MODE.\n");
            break;
        case CASCADE_STANDBY_MODE:
            reportMsg->local_status.local_role = INSTANCE_ROLE_CASCADE_STANDBY;
            write_runlog(LOG, "get local_role from DB state file: CASCADE_STANDBY_MODE.\n");
            return -1;
        default:
            reportMsg->connectStatus = AGENT_TO_INSTANCE_CONNECTION_BAD;
            write_runlog(ERROR, "invalid local_role from DB state file: %d.\n", state->mode);
            return -1;
    }
    return 0;
}

static int getDNStatusFromStateFile(agent_to_cm_datanode_status_report* report_msg, const char* gaussdb_state_path)
{
    GaussState state;

    int rcs = memset_s(&state, sizeof(state), 0, sizeof(state));
    securec_check_errno(rcs, (void)rcs);
    rcs = ReadDBStateFile(&state, gaussdb_state_path);
    if (rcs == 0) {
        report_msg->connectStatus = AGENT_TO_INSTANCE_CONNECTION_OK;
        report_msg->local_status.static_connections = state.conn_num;
        report_msg->local_status.buildReason = datanode_rebuild_reason_enum_to_int(state.ha_rebuild_reason);
        report_msg->local_status.last_flush_lsn = state.lsn;
        /*
         * When the DN is disconnected, term should not be obtained from the drop file.
         * Because this value may be backward, causing cm error arbitration.
         */
        report_msg->local_status.term = InvalidTerm;
        if (state.state == INSTANCE_HA_STATE_NORMAL) {
            write_runlog(WARNING, "got wrong DB state from the state file, dn is disconnected but state is NORMAL.\n");
            report_msg->local_status.db_state = INSTANCE_HA_STATE_UNKONWN;
        } else {
            report_msg->local_status.db_state = state.state;
        }

        rcs = ProcessStatusFromStateFile(report_msg, (const GaussState *)&state);
        if (rcs != 0) {
            return rcs;
        }
        return 0;
    }

    write_runlog(ERROR, "failed to read db state file:%s .\n", gaussdb_state_path);
    return -1;
}

static void GetRebuildCmd(char *cmd, size_t maxLen, const char *dataPath)
{
    BuildMode buildMode;
    char buildModeStr[MAXPGPATH] = {0};
    int rc = 0;
    const int32 waitSec = 7200;

    if (agent_backup_open != CLUSTER_PRIMARY) {
        buildMode = STANDBY_FULL_BUILD;
    } else if (IsBoolCmParamTrue(g_agentEnableDcf)) {
        buildMode = FULL_BUILD;
    } else {
        if (g_only_dn_cluster) {
            buildMode = incremental_build ? AUTO_BUILD : FULL_BUILD;
        } else if (g_multi_az_cluster) {
            buildMode = incremental_build ? AUTO_BUILD : FULL_BUILD;
        } else {
            buildMode = incremental_build ? INC_BUILD : AUTO_BUILD;
        }
    }

    switch (buildMode) {
        case FULL_BUILD:
            rc = strncpy_s(buildModeStr, MAXPGPATH, "-b full", strlen("-b full"));
            break;
        case INC_BUILD:
            rc = strncpy_s(buildModeStr, MAXPGPATH, "-b incremental", strlen("-b incremental"));
            break;
        case STANDBY_FULL_BUILD:
            rc = strncpy_s(buildModeStr, MAXPGPATH, "-b standby_full", strlen("-b standby_full"));
            break;
        default:
            rc = strncpy_s(buildModeStr, MAXPGPATH, "", strlen(""));
            break;
    }
    securec_check_errno(rc, (void)rc);

#ifdef ENABLE_MULTIPLE_NODES
    rc = snprintf_s(cmd,
        maxLen, maxLen - 1, SYSTEMQUOTE "%s build -Z %s %s %s -D %s -r %d >> \"%s\" 2>&1 &" SYSTEMQUOTE,
        PG_CTL_NAME, g_only_dn_cluster ? "single_node" : "datanode",
        buildModeStr, security_mode ? "-o \"--securitymode\"" : "", dataPath, waitSec, system_call_log);
#else
    rc = snprintf_s(cmd,
        maxLen, maxLen - 1, SYSTEMQUOTE "%s build %s %s -D %s -r %d >> \"%s\" 2>&1 &" SYSTEMQUOTE, PG_CTL_NAME,
        buildModeStr, security_mode ? "-o \"--securitymode\"" : "", dataPath, waitSec, system_call_log);
#endif
    securec_check_intval(rc, (void)rc);
}

static void GetPgThreadWaitStatusBuffer(const cltPqResult_t *nodeResult, char *buffer, size_t bufLen)
{
    int maxRows = Ntuples(nodeResult);
    int maxColums = Nfields(nodeResult);
    const char *field = "\nwait_status | wait_event | tid | sessionid | query\n";
    errno_t rc = strcat_s(buffer, bufLen, field);
    securec_check_errno(rc, (void)rc);
    for (int numRows = 0; numRows < maxRows; numRows++) {
        for (int numCols = 0; numCols < maxColums; numCols++) {
            securec_check_intval(rc, (void)rc);
            rc = strcat_s(buffer, bufLen, Getvalue(nodeResult, numRows, numCols));
            securec_check_errno(rc, (void)rc);
            rc = strcat_s(buffer, bufLen, " |");
            securec_check_errno(rc, (void)rc);
        }
        rc = strcat_s(buffer, bufLen, "\n");
        securec_check_errno(rc, (void)rc);
    }
}
 
void ShowPgThreadWaitStatus(cltPqConn_t* Conn, uint32 index, int instanceType)
{
    uint32 instanceId;
    if (instanceType == INSTANCE_TYPE_DATANODE) {
        instanceId = g_currentNode->datanode[index].datanodeId;
    } else {
        instanceId = g_currentNode->coordinateId;
    }
    if (Conn == NULL) {
        write_runlog(ERROR, "No long connection can be used to get pg thread wait status, intanceId=%u\n", instanceId);
        return;
    }
    const char *sqlCommands = "select A.wait_status,A.wait_event,A.tid,B.sessionid,B.query from"
        " pg_thread_wait_status as A, pg_stat_activity as B where A.tid = B.pid and B.application_name = 'cm_agent';";
    cltPqResult_t *nodeResult = Exec(Conn, sqlCommands);
    if (nodeResult == NULL) {
        write_runlog(ERROR, "ShowPgThreadWaitStatus fail return NULL!\n");
    }
    if ((ResultStatus(nodeResult) == CLTPQRES_CMD_OK) || (ResultStatus(nodeResult) == CLTPQRES_TUPLES_OK)) {
        int maxRows = Ntuples(nodeResult);
        if (maxRows == 0) {
            write_runlog(LOG, "ShowPgThreadWaitStatus rows is 0\n");
        } else {
            const int maxBufLen = 4096;
            char buffer[maxBufLen] = {0};
            GetPgThreadWaitStatusBuffer(nodeResult, buffer, sizeof(buffer));
            write_runlog(LOG, "Instance %u ShowPgThreadWaitStatus:%s\n", instanceId, buffer);
        }
    } else {
        write_runlog(ERROR, "ShowPgThreadWaitStatus fail FAIL! Status=%d\n", (int)ResultStatus(nodeResult));
    }
    Clear(nodeResult);
    return;
}

int DatanodeStatusCheck(DnStatus *dnStatus, uint32 dataNodeIndex, int32 dnProcess)
{
    static uint32 checkDnSql5Timer = g_check_dn_sql5_interval;
    checkDnSql5Timer++;

    int rcs = 0;
    char pid_path[MAXPGPATH] = {0};
    char gaussdbStatePath[MAXPGPATH] = {0};
    char redo_state_path[MAXPGPATH] = {0};

    char *dataPath = g_currentNode->datanode[dataNodeIndex].datanodeLocalDataPath;
    bool doBuild = g_dnBuild[dataNodeIndex];

    agent_to_cm_datanode_status_report *reportMsg = &dnStatus->reportMsg;
    /* in case we return 0 without set the db_state. */
    reportMsg->local_status.db_state = INSTANCE_HA_STATE_UNKONWN;

    if (strcmp(g_dbServiceVip, "") != 0) {
        reportMsg->dnVipStatus = IsReachableIP(g_dbServiceVip);
    } else {
        reportMsg->dnVipStatus = CM_ERROR;
    }

    if (g_dnConn[dataNodeIndex] == NULL) {
        rcs = snprintf_s(gaussdbStatePath, MAXPGPATH, MAXPGPATH - 1, "%s/gaussdb.state", dataPath);
        securec_check_intval(rcs, (void)rcs);
        rcs = snprintf_s(redo_state_path, MAXPGPATH, MAXPGPATH - 1, "%s/redo.state", dataPath);
        securec_check_intval(rcs, (void)rcs);
        check_input_for_security(redo_state_path);
        canonicalize_path(redo_state_path);
        rcs = snprintf_s(pid_path, MAXPGPATH, MAXPGPATH - 1, "%s/postmaster.pid", dataPath);
        securec_check_intval(rcs, (void)rcs);

        if (g_isStorageWithDMSorDSS) {
            g_onDemandRealTimeBuildStatus = 0;
        }
        g_dnConn[dataNodeIndex] = get_connection(pid_path, false, AGENT_CONN_DN_TIMEOUT);
        if (g_dnConn[dataNodeIndex] == NULL || (!IsConnOk(g_dnConn[dataNodeIndex]))) {
            char build_pid_path[MAXPGPATH];
            GaussState state;

            reportMsg->connectStatus = AGENT_TO_INSTANCE_CONNECTION_BAD;
            write_runlog(ERROR, "failed to connect to datanode:%s\n", dataPath);
            if (g_dnConn[dataNodeIndex] != NULL) {
                write_runlog(ERROR, "connection return errmsg : %s\n", ErrorMessage(g_dnConn[dataNodeIndex]));
                close_and_reset_connection(g_dnConn[dataNodeIndex]);
            }

            rcs = snprintf_s(build_pid_path, MAXPGPATH, MAXPGPATH - 1, "%s/gs_build.pid", dataPath);
            securec_check_intval(rcs, (void)rcs);
            pgpid_t pid = get_pgpid(build_pid_path, MAXPGPATH);
            if (pid > 0 && is_process_alive(pid)) {
                rcs = memset_s(&state, sizeof(state), 0, sizeof(state));
                securec_check_errno(rcs, (void)rcs);
                check_parallel_redo_status_by_file(reportMsg, redo_state_path);
                if (g_isStorageWithDMSorDSS) {
                    check_datanode_realtime_build_status_by_file(reportMsg, dataPath);
                }
                rcs = ReadDBStateFile(&state, gaussdbStatePath);
                if (rcs == 0) {
                    reportMsg->connectStatus = AGENT_TO_INSTANCE_CONNECTION_OK;
                    reportMsg->local_status.local_role = INSTANCE_ROLE_STANDBY;
                    reportMsg->local_status.static_connections = state.conn_num;
                    reportMsg->local_status.db_state = INSTANCE_HA_STATE_BUILDING;
                    reportMsg->build_info.build_mode = state.build_info.build_mode;
                    reportMsg->build_info.total_done = state.build_info.total_done;
                    reportMsg->build_info.total_size = state.build_info.total_size;
                    reportMsg->build_info.process_schedule =
                        (state.build_info.build_mode != NONE_BUILD) ? state.build_info.process_schedule : 100;
                    reportMsg->build_info.estimated_time = state.build_info.estimated_time;
                    return 0;
                }
                report_conn_fail_alarm(ALM_AT_Fault, INSTANCE_DN, reportMsg->instanceId);
                write_runlog(ERROR, "failed to read db state file.\n");
                return -1;
            }

            if (dnProcess == PROCESS_RUNNING) {
                check_parallel_redo_status_by_file(reportMsg, redo_state_path);
                if (g_isStorageWithDMSorDSS) {
                    check_datanode_realtime_build_status_by_file(reportMsg, dataPath);
                }
                rcs = getDNStatusFromStateFile(reportMsg, gaussdbStatePath);
                if (rcs != 0) {
                    report_conn_fail_alarm(ALM_AT_Fault, INSTANCE_DN, reportMsg->instanceId);
                }
                return rcs;
            }

            /*
             * gs_ctl gets datanode running mode before building and may exit if gaussdb.state does not exist.
             */
            if (doBuild && ReadDBStateFile(&state, gaussdbStatePath)) {
                reportMsg->connectStatus = AGENT_TO_INSTANCE_CONNECTION_OK;
                reportMsg->local_status.local_role = INSTANCE_ROLE_UNKNOWN;
                reportMsg->local_status.db_state = INSTANCE_HA_STATE_BUILD_FAILED;
                return 0;
            }
            report_conn_fail_alarm(ALM_AT_Fault, INSTANCE_DN, reportMsg->instanceId);
            return -1;
        }

        if (g_isStorageWithDMSorDSS) {
            check_datanode_realtime_build_status_by_file(reportMsg, dataPath);
        }
    }

    report_conn_fail_alarm(ALM_AT_Resume, INSTANCE_DN, reportMsg->instanceId);
    reportMsg->connectStatus = AGENT_TO_INSTANCE_CONNECTION_OK;
    if (dnProcess == PROCESS_NOT_EXIST) {
        write_runlog(WARNING, "datanode(%u) process is not running!\n", reportMsg->instanceId);
        CLOSE_CONNECTION(g_dnConn[dataNodeIndex]);
    }

    report_conn_fail_alarm(ALM_AT_Resume, INSTANCE_DN, reportMsg->instanceId);
    /* set command time out. */
    cltPqResult_t *node_result = Exec(g_dnConn[dataNodeIndex], "SET statement_timeout = 10000000;");
    if (node_result == NULL) {
        write_runlog(ERROR, " datanode check set command time out return NULL!\n");
        CLOSE_CONNECTION(g_dnConn[dataNodeIndex]);
    }
    if ((ResultStatus(node_result) != CLTPQRES_CMD_OK) && (ResultStatus(node_result) != CLTPQRES_TUPLES_OK)) {
        write_runlog(ERROR,
            " datanode(%u) check set command time out return FAIL! errmsg is %s\n",
            dataNodeIndex, ErrorMessage(g_dnConn[dataNodeIndex]));
        CLEAR_AND_CLOSE_CONNECTION(node_result, g_dnConn[dataNodeIndex]);
    }
    Clear(node_result);

    /* SQL0 check */
    if (check_datanode_status_by_SQL0(reportMsg, dataNodeIndex) != 0) {
        return -1;
    }

    /* SQL6 check */
    if (check_datanode_status_by_SQL6(reportMsg, dataNodeIndex, dataPath) != 0) {
        return -1;
    }
    /* SQL1 check The dn term can be checked only after the dn disconn mode has been checked. */
    if (check_datanode_status_by_SQL1(reportMsg, dataNodeIndex) != 0) {
        return -1;
    }
    if (check_flush_lsn_by_preparse(reportMsg, dataNodeIndex) != 0) {
        return -1;
    }
if (!IsBoolCmParamTrue(g_agentEnableDcf)) {
        /* SQL2 check */
        if (check_datanode_status_by_SQL2(reportMsg, dataNodeIndex) != 0) {
            return -1;
        }
        /* SQL3 check */
        if (check_datanode_status_by_SQL3(reportMsg, dataNodeIndex) != 0) {
            return -1;
        }
        /* SQL4 check */
        if (check_datanode_status_by_SQL4(reportMsg, &(dnStatus->lpInfo.dnLpInfo), dataNodeIndex) != 0) {
            return -1;
        }
    } else {
        if (CheckDatanodeStatusBySqL10(reportMsg, dataNodeIndex) != 0) {
            return -1;
        }
    }
    /* SQL5 check */
    if (checkDnSql5Timer > g_check_dn_sql5_interval) {
        check_datanode_status_by_SQL5(reportMsg->instanceId, dataNodeIndex, dataPath);
        checkDnSql5Timer = 0;
    }

    /* check dn most_available_sync */
    if (CheckMostAvailableSync(dataNodeIndex)) {
        return -1;
    }
    CheckTransactionReadOnly(g_dnConn[dataNodeIndex], dataNodeIndex, INSTANCE_TYPE_DATANODE);

    if (g_dnNoFreeProc[dataNodeIndex]) {
        ShowPgThreadWaitStatus(g_dnConn[dataNodeIndex], dataNodeIndex, INSTANCE_TYPE_DATANODE);
    }
    g_dnPhonyDeadTimes[dataNodeIndex] = 0;

    /* check datanode realtime build status by sending sql */
    if (g_isStorageWithDMSorDSS) {
        check_datanode_realtime_build_status_by_sql(reportMsg, dataNodeIndex);
        reportMsg->local_status.realtime_build_status = (g_onDemandRealTimeBuildStatus & 0x1);
    }

    return 0;
}

int ProcessLockNoPrimaryCmd(uint32 instId)
{
    int rcs = 0;

    char pid_path[MAXPGPATH] = {0};
    int ii = -1;
    /* If in lock1 status, do nothing */
    for (uint32 i = 0; i < g_currentNode->datanodeCount; i++) {
        /* Get the datanode id */
        if (g_currentNode->datanode[i].datanodeId == instId) {
            ii = (int)i;
            break;
        }
    }
    if (ii == -1) {
        write_runlog(ERROR, "instance(%u) not found for lock1! \n", instId);
        return -1;
    }
    char* data_path = g_currentNode->datanode[ii].datanodeLocalDataPath;

    if (g_dnConnSend[ii] == NULL) {
        rcs = snprintf_s(pid_path, MAXPGPATH, MAXPGPATH - 1, "%s/postmaster.pid", data_path);
        securec_check_intval(rcs, (void)rcs);
        g_dnConnSend[ii] = get_connection(pid_path, false, AGENT_CONN_DN_TIMEOUT);
        if (g_dnConnSend[ii] == NULL || (!IsConnOk(g_dnConnSend[ii]))) {
            write_runlog(ERROR, "instId(%u) failed to connect to datanode:%s\n", instId, data_path);
            if (g_dnConnSend[ii] != NULL) {
                write_runlog(ERROR, "%u connection return errmsg : %s\n", instId, ErrorMessage(g_dnConnSend[ii]));
                close_and_reset_connection(g_dnConnSend[ii]);
            }

            return -1;
        }
        write_runlog(LOG, "instId(%d: %u) successfully connect to datanode: %s.\n", ii, instId, data_path);
    }

    /* set DN instance status */
    const char* sqlCommands = "select * from pg_catalog.disable_conn(\'prohibit_connection\', \'\', 0);";

    cltPqResult_t *node_result = Exec(g_dnConnSend[ii], sqlCommands);
    if (node_result == NULL) {
        write_runlog(ERROR, "instId(%u) process_lock_no_primary_command(%s) fail return NULL!\n", instId, sqlCommands);
        CLOSE_CONNECTION(g_dnConnSend[ii]);
    }
    if ((ResultStatus(node_result) != CLTPQRES_CMD_OK) && (ResultStatus(node_result) != CLTPQRES_TUPLES_OK)) {
        write_runlog(ERROR, "instId(%u) process_lock_no_primary_command(%s) fail return FAIL!\n", instId, sqlCommands);
        CLEAR_AND_CLOSE_CONNECTION(node_result, g_dnConnSend[ii]);
    }
    write_runlog(LOG, "instId(%u) process_lock_no_primary_command(%s) succeed!\n", instId, sqlCommands);
    Clear(node_result);
    return 0;
}

int ProcessLockChosenPrimaryCmd(const cm_to_agent_lock2* msgTypeLock2Ptr)
{
    int rcs = 0;
    char pid_path[MAXPGPATH] = {0};
    const char* tmp_host = msgTypeLock2Ptr->disconn_host;
    uint32 tmp_port = msgTypeLock2Ptr->disconn_port;
    /* set DN instance status */
    char sqlCommands[MAX_SQLCOMMAND_LENGTH] = {0};

    errno_t rc = snprintf_s(sqlCommands,
        MAX_SQLCOMMAND_LENGTH,
        MAX_SQLCOMMAND_LENGTH - 1,
        "select * from pg_catalog.disable_conn(\'specify_connection\', \'%s\', %u);",
        tmp_host,
        tmp_port);
    securec_check_intval(rc, (void)rc);
    check_input_for_security(tmp_host);
    int ii = -1;
    /* If in lock2 status, do nothing */
    for (uint32 i = 0; i < g_currentNode->datanodeCount; i++) {
        /* Get the datanode id */
        if (g_currentNode->datanode[i].datanodeId == msgTypeLock2Ptr->instanceId) {
            ii = (int)i;
            break;
        }
    }
    if (ii == -1) {
        write_runlog(ERROR, "instance(%u) not found for lock2! \n", msgTypeLock2Ptr->instanceId);
        return -1;
    }
    uint32 instId = msgTypeLock2Ptr->instanceId;
    char* data_path = g_currentNode->datanode[ii].datanodeLocalDataPath;

    if (g_dnConnSend[ii] == NULL) {
        rcs = snprintf_s(pid_path, MAXPGPATH, MAXPGPATH - 1, "%s/postmaster.pid", data_path);
        securec_check_intval(rcs, (void)rcs);
        g_dnConnSend[ii] = get_connection(pid_path, false, AGENT_CONN_DN_TIMEOUT);
        if (g_dnConnSend[ii] == NULL || (!IsConnOk(g_dnConnSend[ii]))) {
            write_runlog(ERROR, "instId(%u) failed to connect to datanode:%s\n", instId, data_path);
            if (g_dnConnSend[ii] != NULL) {
                write_runlog(ERROR, "%u connection return errmsg : %s\n", instId, ErrorMessage(g_dnConnSend[ii]));
                close_and_reset_connection(g_dnConnSend[ii]);
            }
            return -1;
        }
        write_runlog(LOG, "instId(%d: %u) successfully connect to datanode: %s.\n", ii, instId, data_path);
    }
    cltPqResult_t *node_result = Exec(g_dnConnSend[ii], sqlCommands);
    if (node_result == NULL) {
        write_runlog(ERROR, "instId(%u) process_lock_chosen_primary_command(%s) fail return NULL!\n",
            instId, sqlCommands);
        CLOSE_CONNECTION(g_dnConnSend[ii]);
    }
    if ((ResultStatus(node_result) != CLTPQRES_CMD_OK) && (ResultStatus(node_result) != CLTPQRES_TUPLES_OK)) {
        write_runlog(ERROR, "instId(%u) process_lock_chosen_primary_command(%s) fail return FAIL!\n",
            instId, sqlCommands);
        CLEAR_AND_CLOSE_CONNECTION(node_result, g_dnConnSend[ii]);
    }
    write_runlog(LOG, "instId(%u) process_lock_chosen_primary_command succeed! command: %s\n", instId, sqlCommands);
    Clear(node_result);
    return 0;
}

int ProcessUnlockCmd(const cm_to_agent_unlock *unlockMsg)
{
    int rcs = 0;
    char pid_path[MAXPGPATH] = {0};
    /* set DN instance status */
    const char* sqlCommands = "select * from pg_catalog.disable_conn(\'polling_connection\', \'\', 0);";
    int ii = -1;

    for (uint32 i = 0; i < g_currentNode->datanodeCount; i++) {
        /* Get the datanode id */
        if (g_currentNode->datanode[i].datanodeId == unlockMsg->instanceId) {
            ii = (int)i;
            break;
        }
    }
    if (ii == -1) {
        write_runlog(ERROR, "instance not found for unlock1! \n");
        return -1;
    }
    uint32 instId = unlockMsg->instanceId;
    char* data_path = g_currentNode->datanode[ii].datanodeLocalDataPath;

    if (g_dnConnSend[ii] == NULL) {
        rcs = snprintf_s(pid_path, MAXPGPATH, MAXPGPATH - 1, "%s/postmaster.pid", data_path);
        securec_check_intval(rcs, (void)rcs);
        g_dnConnSend[ii] = get_connection(pid_path, false, AGENT_CONN_DN_TIMEOUT);
        if (g_dnConnSend[ii] == NULL || (!IsConnOk(g_dnConnSend[ii]))) {
            write_runlog(ERROR, "instId(%u) failed to connect to datanode:%s\n", instId, data_path);
            if (g_dnConnSend[ii] != NULL) {
                write_runlog(ERROR, "%u connection return errmsg : %s\n", instId, ErrorMessage(g_dnConnSend[ii]));
                close_and_reset_connection(g_dnConnSend[ii]);
            }
            return -1;
        }
        write_runlog(LOG, "instId(%d: %u) successfully connect to datanode: %s.\n", ii, instId, data_path);
    }
    cltPqResult_t *node_result = Exec(g_dnConnSend[ii], sqlCommands);
    if (node_result == NULL) {
        write_runlog(ERROR, "instId(%u) process_unlock_no_primary_command(%s) fail return NULL!\n",
            instId, sqlCommands);
        CLOSE_CONNECTION(g_dnConnSend[ii]);
    }
    if ((ResultStatus(node_result) != CLTPQRES_CMD_OK) && (ResultStatus(node_result) != CLTPQRES_TUPLES_OK)) {
        write_runlog(ERROR, "instId(%u) process_unlock_no_primary_command fail(%s) return FAIL!\n",
            instId, sqlCommands);
        CLEAR_AND_CLOSE_CONNECTION(node_result, g_dnConnSend[ii]);
    }
    write_runlog(LOG, "instId(%u) process_unlock_no_primary_command succeed! command: %s\n", instId, sqlCommands);
    Clear(node_result);
    return 0;
}

int CheckDatanodeStatus(const char *dataDir, int *role)
{
    int maxRows = 0;
    int maxColums = 0;
    const char* sqlCommands = "select local_role from pg_stat_get_stream_replications();";

    char postmaster_pid_path[MAXPGPATH] = {0};
    int rc = snprintf_s(postmaster_pid_path, MAXPGPATH, MAXPGPATH - 1, "%s/postmaster.pid", dataDir);
    securec_check_intval(rc, (void)rc);

    cltPqConn_t *Conn = get_connection(postmaster_pid_path);
    if (Conn == NULL) {
        write_runlog(ERROR, "get connect failed!\n");
        return -1;
    } else {
        if (!IsConnOk(Conn)) {
            write_runlog(ERROR, "get connect failed! PQstatus IS NOT OK,errmsg is %s\n", ErrorMessage(Conn));
            CLOSE_CONNECTION(Conn);
        }
    }

    /* set command time out. */
    cltPqResult_t *node_result = Exec(Conn, "SET statement_timeout = 10000000 ;");
    if (node_result == NULL) {
        write_runlog(ERROR, " CheckDatanodeStatus: datanode set command time out fail return NULL!\n");
        CLOSE_CONNECTION(Conn);
    }
    if ((ResultStatus(node_result) != CLTPQRES_CMD_OK) && (ResultStatus(node_result) != CLTPQRES_TUPLES_OK)) {
        write_runlog(ERROR, " CheckDatanodeStatus: datanode set command time out fail return FAIL!\n");
        CLEAR_AND_CLOSE_CONNECTION(node_result, Conn);
    }
    Clear(node_result);

    node_result = Exec(Conn, sqlCommands);
    if (node_result == NULL) {
        write_runlog(ERROR, "CheckDatanodeStatus: sqlCommands fail return NULL!\n");
        CLOSE_CONNECTION(Conn);
    }
    if ((ResultStatus(node_result) == CLTPQRES_CMD_OK) || (ResultStatus(node_result) == CLTPQRES_TUPLES_OK)) {
        maxRows = Ntuples(node_result);
        if (maxRows == 0) {
            write_runlog(LOG, "CheckDatanodeStatus: sqlCommands result is 0\n");
            CLEAR_AND_CLOSE_CONNECTION(node_result, Conn);
        } else {
            maxColums = Nfields(node_result);
            if (maxColums != 1) {
                write_runlog(ERROR, "CheckDatanodeStatus: sqlCommands FAIL! col is %d\n", maxColums);
                CLEAR_AND_CLOSE_CONNECTION(node_result, Conn);
            }
            *role = datanode_role_string_to_int(Getvalue(node_result, 0, 0));
        }
    } else {
        write_runlog(ERROR, "CheckDatanodeStatus: sqlCommands FAIL! Status=%d\n", ResultStatus(node_result));
        CLEAR_AND_CLOSE_CONNECTION(node_result, Conn);
    }

    Clear(node_result);
    close_and_reset_connection(Conn);
    return 0;
}

static bool IsConnBadButNotPhonyDead(const char *errMsg, int conResult)
{
    if (strstr(errMsg, "too many clients already")) {
        write_runlog(LOG, "need to change conn pool number, conn result is %d.\n", conResult);
        return true;
    }
    if (strstr(errMsg, "failed to request snapshot")) {
        write_runlog(LOG, "failed to request snapshot, not phony dead, conn result is %d.\n", conResult);
        return true;
    }

    return false;
}

int CheckDnStausPhonyDead(int dnId, int agentCheckTimeInterval)
{
    int agentConnectDb = 5;
    char pidPath[MAXPGPATH] = {0};
    errno_t rc = snprintf_s(
        pidPath, MAXPGPATH, MAXPGPATH - 1, "%s/postmaster.pid", g_currentNode->datanode[dnId].datanodeLocalDataPath);
    securec_check_intval(rc, (void)rc);
    if (!g_isStorageWithDMSorDSS) {
         /* According the origin logic when we are not in shared storage mode. */
        if (agentCheckTimeInterval < agentConnectDb) {
            agentConnectDb = agentCheckTimeInterval;
        }
    } else {
#define CONNECT_TIMEOUT_UNDER_SHEARD_STORAGE 1000
        /* Due to the performance of DSS, we should wait for connection for more. */
        agentConnectDb = CONNECT_TIMEOUT_UNDER_SHEARD_STORAGE;
    }
    const char sqlCommands[] = {
        "select local_role,static_connections,db_state,detail_information from pg_stat_get_stream_replications();"};

    cltPqConn_t *tmpDNConn = get_connection(pidPath, false, agentConnectDb);
    if (tmpDNConn == NULL) {
        write_runlog(ERROR, "get connect failed for dn(%s) phony dead check, conn is null.\n", pidPath);
        return -1;
    }

    if (!IsConnOk(tmpDNConn)) {
        write_runlog(ERROR, "get connect failed for dn(%s) phony dead check, errmsg is %s\n",
            pidPath, ErrorMessage(tmpDNConn));
        if (IsConnBadButNotPhonyDead(ErrorMessage(tmpDNConn), Status(tmpDNConn))) {
            close_and_reset_connection(tmpDNConn);
            return 0;
        }
        if (strstr(ErrorMessage(tmpDNConn), "No free proc")) {
            PrintInstanceStack(g_currentNode->datanode[dnId].datanodeLocalDataPath, g_dnNoFreeProc[dnId]);
            g_dnNoFreeProc[dnId] = true;
        }
        CLOSE_CONNECTION(tmpDNConn);
    }
    g_dnNoFreeProc[dnId] = false;
    /* set command time out. */
    cltPqResult_t *node_result = Exec(tmpDNConn, sqlCommands);
    if (node_result == NULL) {
        write_runlog(ERROR,
            "select pg_stat_get_stream_replications fail return NULL, when check dn(%s) phony dead.\n",
            pidPath);
        CLOSE_CONNECTION(tmpDNConn);
    }
    if ((ResultStatus(node_result) != CLTPQRES_CMD_OK) && (ResultStatus(node_result) != CLTPQRES_TUPLES_OK)) {
        write_runlog(ERROR,
            "select pg_stat_get_stream_replications fail, dn is %s, errmsg is %s\n",
            pidPath, ErrorMessage(tmpDNConn));
        CLEAR_AND_CLOSE_CONNECTION(node_result, tmpDNConn);
    }

    Clear(node_result);
    close_and_reset_connection(tmpDNConn);

    return 0;
}

#ifndef ENABLE_MULTIPLE_NODES
static void LtranStopCheck()
{
    struct stat instanceStatBuf = {0};
    for (uint32 ii = 0; ii < g_currentNode->datanodeCount; ii++) {
        if (stat(g_cmLibnetManualStartPath, &instanceStatBuf) != 0) {
            g_ltranDown[ii] = false;
        } else {
            if (check_one_instance_status("ltran", "ltran", NULL) != PROCESS_RUNNING) {
                g_ltranDown[ii] = true;
            } else {
                g_ltranDown[ii] = false;
            }
        }
    }
}
#endif

static int GsctlBuildCheck(const char *dataPath)
{
    char command[MAXPGPATH] = {0};
    char resultStr[MAX_BUF_LEN + 1] = {0};
    int bytesread;
    char mpprvFile[MAXPGPATH] = {0};
    int rc;

    int ret = cmagent_getenv("MPPDB_ENV_SEPARATE_PATH", mpprvFile, sizeof(mpprvFile));
    if (ret != EOK) {
        rc = snprintf_s(command,
            MAXPGPATH, MAXPGPATH - 1,
            "cm_ctl check -B %s -T %s > /dev/null 2>&1; echo  -e $? > %s",
            PG_CTL_NAME, dataPath, result_path);
    } else {
        check_input_for_security(mpprvFile);
        rc = snprintf_s(command,
            MAXPGPATH, MAXPGPATH - 1,
            "source %s;cm_ctl check -B %s -T %s > /dev/null 2>&1; echo  -e $? > %s",
            mpprvFile, PG_CTL_NAME, dataPath, result_path);
    }
    securec_check_intval(rc, (void)rc);

    ret = system(command);
    if (ret != 0) {
        write_runlog(LOG, "exec command failed !  command is %s, errno=%d.\n", command, errno);
        (void)unlink(result_path);
        return -1;
    }

    FILE *fd = fopen(result_path, "re");
    if (fd == NULL) {
        write_runlog(LOG, "fopen failed, errno[%d] !\n", errno);
        (void)unlink(result_path);
        return -1;
    }

    bytesread = (int)fread(resultStr, 1, MAX_BUF_LEN, fd);
    if ((bytesread < 0) || (bytesread > MAX_BUF_LEN)) {
        write_runlog(LOG, "gs_ctl build check  fread file failed! file=%s, bytesread=%d\n", result_path, bytesread);
        (void)fclose(fd);
        (void)unlink(result_path);
        return -1;
    }

    (void)fclose(fd);
    (void)unlink(result_path);
    return (int)strtol(resultStr, NULL, 10);
}

/*
 * @Description: build command to start datanode
 *
 * @in: instanceIndex    the datanode index of current node
 *        command            command to start datanode
 */
static void BuildStartCommand(uint32 instanceIndex, char *command, size_t maxLen)
{
    int rcs;
    const char *startModeArg = "-M pending";
    char undocumentedVersionArg[128] = "";

    write_runlog(LOG, "BuildStartCommand %s\n", g_agentEnableDcf);

    if (IsBoolCmParamTrue(g_agentEnableDcf)) {
        startModeArg = "-M standby";
    }

    if (g_currentNode->datanode[instanceIndex].datanodeRole == DUMMY_STANDBY_DN) {
        startModeArg = "-M standby -R";
    }

    if (agent_backup_open == CLUSTER_OBS_STANDBY) {
        startModeArg = "-M standby";
    } else if (agent_backup_open == CLUSTER_STREAMING_STANDBY) {
        startModeArg = "-M cascade_standby";
    }

    if (g_clusterType == SingleInstClusterCent) {
        startModeArg = "-M primary";
    }

    if (undocumentedVersion) {
        rcs = sprintf_s(undocumentedVersionArg, sizeof(undocumentedVersionArg), "-u %u", undocumentedVersion);
        securec_check_intval(rcs, (void)rcs);
    }

    rcs = snprintf_s(command,
        maxLen,
        maxLen - 1,
        SYSTEMQUOTE "%s/%s %s %s %s -D %s %s >> \"%s\" 2>&1 &" SYSTEMQUOTE,
        g_binPath,
        DATANODE_BIN_NAME,
        undocumentedVersionArg,
        g_only_dn_cluster ? "" : "--datanode",
        security_mode ? "--securitymode" : "",
        g_currentNode->datanode[instanceIndex].datanodeLocalDataPath,
        startModeArg,
        system_call_log);
    securec_check_intval(rcs, (void)rcs);
}

static void CheckDnDiskStatus(char *instanceManualStartPath, uint32 ii, int *alarmReason)
{
    int rcs;
    struct stat instanceStatBuf = {0};
    struct stat clusterStatBuf = {0};
    bool cdt;

    rcs = snprintf_s(instanceManualStartPath,
        MAX_PATH_LEN,
        MAX_PATH_LEN - 1,
        "%s_%u",
        g_cmInstanceManualStartPath,
        g_currentNode->datanode[ii].datanodeId);
    securec_check_intval(rcs, (void)rcs);

    cdt = (stat(instanceManualStartPath, &instanceStatBuf) != 0 &&
        stat(g_cmManualStartPath, &clusterStatBuf) != 0);
    if (cdt) {
        set_disc_check_state(g_currentNode->datanode[ii].datanodeId);
        cdt = (IsDirectoryDestroyed(g_currentNode->datanode[ii].datanodeLocalDataPath) ||
            !agentCheckDisc(g_currentNode->datanode[ii].datanodeLocalDataPath) || !agentCheckDisc(g_logBasePath));
        if (cdt) {
            write_runlog(ERROR,
                "data path disc writable test failed, %s.\n",
                g_currentNode->datanode[ii].datanodeLocalDataPath);
            g_dnDiskDamage[ii] = true;
            set_instance_not_exist_alarm_value(alarmReason, DISC_BAD_REASON);
        } else {
            cdt = IsLinkPathDestroyedOrDamaged(g_currentNode->datanode[ii].datanodeLocalDataPath);
            if (cdt) {
                write_runlog(ERROR,
                             "link path disc writable test failed, %s.\n",
                             g_currentNode->datanode[ii].datanodeLocalDataPath);
                g_dnDiskDamage[ii] = true;
                set_instance_not_exist_alarm_value(alarmReason, DISC_BAD_REASON);
            } else {
                g_dnDiskDamage[ii] = false;
            }
        }
        set_disc_check_state(0);
    } else {
        g_dnDiskDamage[ii] = false;
        g_dnBuild[ii] = false;
        write_runlog(DEBUG1,
            "%d, dn(%u) the g_dnBuild[%u] is set to false.\n",
            __LINE__,
            g_currentNode->datanode[ii].datanodeId,
            ii);
    }
}

static void CheckDnNicStatus(uint32 ii, int *alarmReason)
{
    bool cdt = ((!GetNicStatus(g_currentNode->datanode[ii].datanodeId, CM_INSTANCE_TYPE_DN)) ||
        (!GetNicStatus(g_currentNode->datanode[ii].datanodeId, CM_INSTANCE_TYPE_DN, NETWORK_TYPE_HA)) ||
        (!GetNicStatus(g_currentNode->cmAgentId, CM_INSTANCE_TYPE_CMA)));
    if (cdt) {
        write_runlog(
            WARNING, "nic related with datanode(%s) not up.\n", g_currentNode->datanode[ii].datanodeLocalDataPath);
        g_nicDown[ii] = true;
        set_instance_not_exist_alarm_value(alarmReason, NIC_BAD_REASON);
    } else {
        g_nicDown[ii] = false;
    }
}

static void CheckifSigleNodeCluster(uint32 ii)
{
    if (g_single_node_cluster) {
        bool cdt = ((g_currentNode->datanode[ii].datanodeRole == STANDBY_DN) ||
            (g_currentNode->datanode[ii].datanodeRole == DUMMY_STANDBY_DN));
        if (cdt) {
            g_dnDiskDamage[ii] = true;
        }
    } /* end of if (g_single_node_cluster) */
}
