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

static int CheckifGaussdbRunning(
    char *gaussdbStatePath, size_t statePathMaxLen, char *gaussdbPidPath, size_t pidPathMaxLen, uint32 ii)
{
    int rcs = snprintf_s(gaussdbStatePath,
        statePathMaxLen,
        statePathMaxLen - 1,
        "%s/gaussdb.state",
        g_currentNode->datanode[ii].datanodeLocalDataPath);
    securec_check_intval(rcs, (void)rcs);

    rcs = snprintf_s(gaussdbPidPath,
        pidPathMaxLen,
        pidPathMaxLen - 1,
        "%s/postmaster.pid",
        g_currentNode->datanode[ii].datanodeLocalDataPath);
    securec_check_intval(rcs, (void)rcs);

    /* check if datanode is running. */
    return check_one_instance_status(DATANODE_BIN_NAME, g_currentNode->datanode[ii].datanodeLocalDataPath, NULL);
}

static void GaussdbRunningProcessCheckAlarm(AlarmAdditionalParam* tempAdditionalParam, const char* instanceName,
    const char* logicClusterName, uint32 ii)
{
    g_startDnCount[ii] = 0;
    if (g_startupAlarmList != NULL) {
        /* fill the alarm message */
        WriteAlarmAdditionalInfo(tempAdditionalParam,
            instanceName,
            "",
            "",
            logicClusterName,
            &(g_startupAlarmList[ii]),
            ALM_AT_Resume);
        /* report the alarm */
        AlarmReporter(&(g_startupAlarmList[ii]), ALM_AT_Resume, tempAdditionalParam);
    }
}

#ifdef __aarch64__
static void GaussdbRunningProcessForAarch64(uint32 ii, uint32 &datanodeConnectCount, bool &datanodeIsPrimary,
    uint32 &gaussdbPrimaryIndex, int gaussdbPid)
{
    /* to set datanode dn_report_msg_ok flag, calculate datanode primary and standby instance number */
    bool cdt = (AGENT_TO_INSTANCE_CONNECTION_OK == g_dnReportMsg[ii].dnStatus.reportMsg.connectStatus &&
        DUMMY_STANDBY_DN != g_currentNode->datanode[ii].datanodeRole);
    if (cdt) {
        datanodeConnectCount++;
    }

    /* do process cpubind by using taskset */
    if (agent_process_cpu_affinity) {
        datanodeIsPrimary =
            g_dn_report_msg_ok
                ? g_dnReportMsg[ii].dnStatus.reportMsg.local_status.local_role == INSTANCE_ROLE_PRIMARY
                : PRIMARY_DN == g_currentNode->datanode[ii].datanodeRole;
        process_bind_cpu(ii, gaussdbPrimaryIndex, gaussdbPid);
        gaussdbPrimaryIndex += datanodeIsPrimary ? 1 : 0;
    }
}
#endif

static void GaussdbRunningProcessRest(uint32 ii, GaussState *state, const char *statePath)
{
    bool cdt;
    g_dnStartCounts[ii] = 0;
    /* secondary standby doesn't have gaussdb.state file and skip it. */
    cdt = (g_currentNode->datanode[ii].datanodeRole != DUMMY_STANDBY_DN &&
        ReadDBStateFile(state, statePath) == 0);
    if (cdt) {
        g_dnBuild[ii] = false;
        write_runlog(DEBUG1,
            "%d, dn(%u) the g_dnBuild[%u] is set to false.\n",
            __LINE__,
            g_currentNode->datanode[ii].datanodeId,
            ii);
    }
#ifdef ENABLE_MULTIPLE_NODES
    cdt = (g_dnDiskDamage[ii] || g_nicDown[ii]);
#else
    cdt = (g_dnDiskDamage[ii] || g_nicDown[ii] || g_ltranDown[ii]);
#endif
    if (cdt) {
        immediate_stop_one_instance(g_currentNode->datanode[ii].datanodeLocalDataPath, INSTANCE_DN);
    }
    if (g_isCmaBuildingDn[ii]) {
        g_isCmaBuildingDn[ii] = false;
        write_runlog(LOG,
            "Datanode %u is running, set g_isCmaBuildingDn to false.\n",
            g_currentNode->datanode[ii].datanodeId);
    }
}

static void GaussdbNotExistProcessCheckPort(uint32 ii, int *alarmReason, bool *portConflict,
    const char *instanceManualStartPath, bool *dnManualStop)
{
    bool cdt;
    struct stat instanceStatBuf = {0};
    struct stat clusterStatBuf = {0};

    cdt = (agentCheckPort(g_currentNode->datanode[ii].datanodePort) > 0 ||
        agentCheckPort(g_currentNode->datanode[ii].datanodeLocalHAPort) > 0);
    if (cdt) {
        set_instance_not_exist_alarm_value(alarmReason, PORT_BAD_REASON);
        *portConflict = true;
    }

    cdt = (stat(instanceManualStartPath, &instanceStatBuf) == 0 ||
        stat(g_cmManualStartPath, &clusterStatBuf) == 0);
    if (cdt) {
        *dnManualStop = true;
        set_instance_not_exist_alarm_value(alarmReason, STOPPED_REASON);
    }
}

static void GaussdbNotExistProcessCheckAlarm(AlarmAdditionalParam* tempAdditionalParam, const char* instanceName,
    const char* logicClusterName, uint32 ii, bool dnManualStop, int alarmReason)
{
    if (g_startDnCount[ii] < STARTUP_DN_CHECK_TIMES) {
        ++(g_startDnCount[ii]);
    } else {
        bool cdt = (g_startupAlarmList != NULL && !dnManualStop);
        if (cdt) {
            /* fill the alarm message. */
            WriteAlarmAdditionalInfo(tempAdditionalParam,
                instanceName,
                "",
                "",
                logicClusterName,
                &(g_startupAlarmList[ii]),
                ALM_AT_Fault,
                instanceName,
                instance_not_exist_reason_to_string(alarmReason));
            /* report the alarm. */
            AlarmReporter(&(g_startupAlarmList[ii]), ALM_AT_Fault, tempAdditionalParam);
        }
    }
}

static void GaussdbNotExistProcessBuildCheck(uint32 ii)
{
    if (GsctlBuildCheck(g_currentNode->datanode[ii].datanodeLocalDataPath) == PROCESS_RUNNING) {
        write_runlog(LOG, "gs_ctl build is running, sleep 2s and make sure the gs_build.pid is been create.\n");
        cm_sleep(2);
    }
}

static void GaussdbNotExistProcessBuilding(uint32 ii)
{
    write_runlog(LOG, "building data_dir: %s\n", g_currentNode->datanode[ii].datanodeLocalDataPath);
    g_dnBuild[ii] = false;
    g_dnStartCounts[ii] = 0;
}

static void GaussdbNotExistProcessBuildFailed(uint32 ii, GaussState *state, const char *statePath, pgpid_t pid,
    char *command, size_t maxLen)
{
    int ret;
    errno_t rc;

    rc = memset_s(state, sizeof(GaussState), 0, sizeof(GaussState));
    securec_check_errno(rc, (void)rc);
    ret = ReadDBStateFile(state, statePath);
    if (ret == -1) {
        write_runlog(LOG,
            "build failed(please refer to the log of gs_ctl for detailed reasons), data_dir: %s, process_schedule "
            "(N/A), build_pid: %ld; try to build again.\n",
            g_currentNode->datanode[ii].datanodeLocalDataPath,
            pid);
    } else {
        write_runlog(LOG,
            "build failed(please refer to the log of gs_ctl for detailed reasons), data_dir: %s, process_schedule: %d, "
            "build_pid: %ld; try to build again.\n",
            g_currentNode->datanode[ii].datanodeLocalDataPath,
            state->build_info.process_schedule,
            pid);
    }
    g_dnBuild[ii] = true;
    g_dnStartCounts[ii]++;
    if (g_dnStartCounts[ii] >= INSTANCE_BUILD_CYCLE) {
        g_dnStartCounts[ii] = 0;
    }
    if (agent_backup_open == CLUSTER_STREAMING_STANDBY) {
        if (g_lastBuildRole == INSTANCE_ROLE_INIT) {
            write_runlog(WARNING, "cm_agent lost last build role, rebuild failed\n");
            return;
        }
        if (g_lastBuildRole == INSTANCE_ROLE_CASCADE_STANDBY) {
            ExecuteCascadeStandbyDnBuildCommand(g_currentNode->datanode[ii].datanodeLocalDataPath);
        } else {
            ProcessCrossClusterBuildCommand(INSTANCE_TYPE_DATANODE, g_currentNode->datanode[ii].datanodeLocalDataPath);
        }
        return;
    }
    GetRebuildCmd(command, maxLen, g_currentNode->datanode[ii].datanodeLocalDataPath);

    ret = system(command);
    if (ret != 0) {
        write_runlog(LOG, "exec command failed %d! command is %s, errno=%d.\n", ret, command, errno);
    } else {
        if (!g_isCmaBuildingDn[ii]) {
            g_isCmaBuildingDn[ii] = true;
            write_runlog(LOG,
                "CMA is building %u, set g_isCmaBuildingDn to true.\n",
                g_currentNode->datanode[ii].datanodeId);
        }
    }
}

static void GaussdbNotExistProcessUpdateBuildCheckTimes(uint32 ii)
{
    g_dnBuildCheckTimes[ii]++;
    if (g_dnBuildCheckTimes[ii] > CHECK_DN_BUILD_TIME / agent_check_interval) {
        g_dnBuildCheckTimes[ii] = 0;
        g_dnBuild[ii] = false;
        write_runlog(DEBUG1,
            "line %d, dn(%u) the g_dnBuild[%u] is set to false, g_dnBuildCheckTimes is %u.\n",
            __LINE__,
            g_currentNode->datanode[ii].datanodeId,
            ii,
            g_dnBuildCheckTimes[ii]);
    }
}

static void GaussdbNotExistProcessShowNodeInfo(uint32 ii, bool portConflict, bool dnManualStop)
{
#ifdef ENABLE_MULTIPLE_NODES
    write_runlog(LOG,
        "datanodeId=%u, dn_manual_stop=%d, g_dnDiskDamage=%d, g_nicDown=%d, port_conflict=%d, g_dnBuild=%d, "
        "g_dnStartCounts=%d.\n",
        g_currentNode->datanode[ii].datanodeId,
        dnManualStop,
        g_dnDiskDamage[ii],
        g_nicDown[ii],
        portConflict,
        g_dnBuild[ii],
        g_dnStartCounts[ii]);
#else
    write_runlog(LOG,
        "datanodeId=%u, dn_manual_stop=%d, g_dnDiskDamage=%d, g_nicDown=%d, port_conflict=%d, g_dnBuild=%d, "
        "g_ltranDown=%d, g_dnStartCounts=%d.\n",
        g_currentNode->datanode[ii].datanodeId,
        dnManualStop,
        g_dnDiskDamage[ii],
        g_nicDown[ii],
        portConflict,
        g_dnBuild[ii],
        g_ltranDown[ii],
        g_dnStartCounts[ii]);
#endif
}

static void GaussdbNotExistProcessCheckdnStartCounts(uint32 ii, const char *gaussdbPidPath)
{
    int ret;
    struct stat instanceStatBuf = {0};

    if (g_dnStartCounts[ii] < INSTANCE_START_CYCLE) {
        return;
    }

    if (stat(gaussdbPidPath, &instanceStatBuf) == 0) {
        /* wait for gaussdb process is running. */
        const int waitGaussdbProcessInterval = 5;
        cm_sleep(waitGaussdbProcessInterval);
        immediate_stop_one_instance(g_currentNode->datanode[ii].datanodeLocalDataPath, INSTANCE_DN);
        ret = check_one_instance_status(
            DATANODE_BIN_NAME, g_currentNode->datanode[ii].datanodeLocalDataPath, NULL);
        if (ret == PROCESS_NOT_EXIST) {
            if (unlink(gaussdbPidPath) != 0) {
                write_runlog(ERROR, "unlink DN pid file(%s) failed, errno[%d].\n", gaussdbPidPath, errno);
            } else {
                write_runlog(LOG, "unlink DN pid file(%s) successfully.\n", gaussdbPidPath);
            }
        }
    }
    g_dnStartCounts[ii] = 0;
}

static void GaussdbNotExistProcessRestartCmdSuccess(uint32 ii)
{
    g_primaryDnRestartCounts[ii]++;
    g_primaryDnRestartCountsInHour[ii]++;
    write_runlog(LOG,
        "the dn(id:%u) instance restarts counts: %d in 10 min, %d in hour.\n",
        g_currentNode->datanode[ii].datanodeId,
        g_primaryDnRestartCounts[ii],
        g_primaryDnRestartCountsInHour[ii]);
    record_pid(g_currentNode->datanode[ii].datanodeLocalDataPath);
    if (g_isCmaBuildingDn[ii]) {
        g_isCmaBuildingDn[ii] = false;
        write_runlog(LOG,
            "CMA is starting %u, set g_isCmaBuildingDn to false.\n",
            g_currentNode->datanode[ii].datanodeId);
    }
}

void StartDatanodeCheck(void)
{
    int ret;
    uint32 ii;
    char gaussdbStatePath[MAXPGPATH];
    char buildPidPath[MAXPGPATH];
    char gaussdbPidPath[MAXPGPATH];
    struct stat instanceStatBuf = {0};
    struct stat clusterStatBuf = {0};
    char instanceManualStartPath[MAX_PATH_LEN] = {0};
    int rcs;
    GaussState state;
    bool cdt;
#ifdef __aarch64__
    uint32 gaussdb_primary_index = 0;
    uint32 datanode_connect_count = 0;
#endif

    for (ii = 0; ii < g_currentNode->datanodeCount; ii++) {
        char instanceName[CM_NODE_NAME] = {0};
        int alarmReason = UNKNOWN_BAD_REASON;
        AlarmAdditionalParam tempAdditionalParam;
#ifdef __aarch64__
        bool datanode_is_primary = false;
#endif

        /*
         * g_abnormalAlarmList store items as follow:
         * first:	datanode
         * second:	cm_server
         * third:	coordinator
         * fourth:	gtm
         */
        rcs = snprintf_s(instanceName,
            sizeof(instanceName),
            sizeof(instanceName) - 1,
            "%s_%u",
            "dn",
            g_currentNode->datanode[ii].datanodeId);
        securec_check_intval(rcs, (void)rcs);

        /*
         * It is not necessary to check a disk failure after manually stopping the instance. In the scenario where the
         * disk IO is slow, this check is quite time consuming, delays the entire start process, and even causes the
         * start timeout to fail.
         */
        CheckDnDiskStatus(instanceManualStartPath, ii, &alarmReason);
#ifndef ENABLE_MULTIPLE_NODES
        LtranStopCheck();
#endif
        CheckDnNicStatus(ii, &alarmReason);
        CheckifSigleNodeCluster(ii);
        ret = CheckifGaussdbRunning(
            gaussdbStatePath, sizeof(gaussdbStatePath), gaussdbPidPath, sizeof(gaussdbPidPath), ii);

        char *logicClusterName = get_logicClusterName_by_dnInstanceId(g_currentNode->datanode[ii].datanodeId);

        if (ret == PROCESS_RUNNING) {
            GaussdbRunningProcessCheckAlarm(&tempAdditionalParam, instanceName, logicClusterName, ii);
#ifdef __aarch64__
            int gaussdbPid = get_pgpid(gaussdbPidPath, sizeof(gaussdbPidPath));
            GaussdbRunningProcessForAarch64(ii, datanode_connect_count, datanode_is_primary,
                gaussdb_primary_index, gaussdbPid);
#endif
            GaussdbRunningProcessRest(ii, &state, gaussdbStatePath);
        } else if (ret == PROCESS_NOT_EXIST) {
            char command[MAXPGPATH];

            bool port_conflict = false;
            bool dn_manual_stop = false;

            GaussdbNotExistProcessCheckPort(
                ii, &alarmReason, &port_conflict, instanceManualStartPath, &dn_manual_stop);
            GaussdbNotExistProcessCheckAlarm(&tempAdditionalParam, instanceName, logicClusterName, ii,
                dn_manual_stop, alarmReason);
            GaussdbNotExistProcessBuildCheck(ii);

            rcs = snprintf_s(buildPidPath,
                MAXPGPATH,
                MAXPGPATH - 1,
                "%s/gs_build.pid",
                g_currentNode->datanode[ii].datanodeLocalDataPath);
            securec_check_intval(rcs, (void)rcs);
            pgpid_t pid = get_pgpid(buildPidPath, MAXPGPATH);

            rcs = snprintf_s(instanceManualStartPath,
                MAX_PATH_LEN,
                MAX_PATH_LEN - 1,
                "%s_%u",
                g_cmInstanceManualStartPath,
                g_currentNode->datanode[ii].datanodeId);
            securec_check_intval(rcs, (void)rcs);

            write_runlog(DEBUG1, "gs_build pid is %ld, is_process_alive is %d.\n", pid, is_process_alive(pid));
            cdt = (pid > 0 && is_process_alive(pid));
            if (cdt) {
                /*
                 * The g_dnBuild only shows us that we should not start the datanode
                 * while the build process has not setup the build pid file. Since
                 * we recognize that the build is running, we should reset it.
                 * Otherwise, the CM agent would not start the datanode when the
                 * build process ends up in start failure.
                 */
                GaussdbNotExistProcessBuilding(ii);
                continue;
            } else if (((pid > 0 && !is_process_alive(pid)) || pid < 0) && g_dnStartCounts[ii] < MAX_INSTANCE_BUILD &&
                       stat(instanceManualStartPath, &instanceStatBuf) != 0 &&
                       stat(g_cmManualStartPath, &clusterStatBuf) != 0) {
                if (g_single_node_cluster) {
                    continue;
                }

                /* Before we reset the build, get more information from state file. */
                GaussdbNotExistProcessBuildFailed(ii, &state, gaussdbStatePath, pid, command, sizeof(command));
                continue;
            } else if (pid == 0 && g_dnBuild[ii]) {
                GaussdbNotExistProcessUpdateBuildCheckTimes(ii);
                continue;
            }
            GaussdbNotExistProcessShowNodeInfo(ii, port_conflict, dn_manual_stop);
            GaussdbNotExistProcessCheckdnStartCounts(ii, gaussdbPidPath);

            /* start dns */
#ifdef ENABLE_MULTIPLE_NODES
            cdt = (!dn_manual_stop && !g_dnDiskDamage[ii] && !g_nicDown[ii] && !port_conflict && !g_dnBuild[ii]);
#else
            cdt = (!dn_manual_stop && !g_dnDiskDamage[ii] && !g_nicDown[ii] && !port_conflict && !g_dnBuild[ii] &&
                !g_ltranDown[ii]);
#endif
            if (cdt) {
                if (stat(gaussdbStatePath, &instanceStatBuf) == 0) {
                    if (unlink(gaussdbStatePath) != 0) {
                        write_runlog(ERROR, "unlink DN state file(%s) failed.\n", gaussdbStatePath);
                        continue;
                    }
                    write_runlog(LOG, "unlink DN state file(%s) succeeded.\n", gaussdbStatePath);
                }

                BuildStartCommand(ii, command, sizeof(command));

                write_runlog(LOG, "DN START system(command:%s), try %d\n", command, g_dnStartCounts[ii]);

                ret = system(command);
                if (ret != 0) {
                    write_runlog(ERROR, "run system command failed %d! %s, errno=%d.\n", ret, command, errno);
                } else {
                    GaussdbNotExistProcessRestartCmdSuccess(ii);
                    ExecuteEventTrigger(EVENT_START);
                    // set the g_isDnFirstStart to false, only when the first startup is successful
                    if (g_isDnFirstStart) {
                        g_isDnFirstStart = false;
                    }
                }
            }

            /* see DNStatusCheckMain(), the if condition is corresponding to that in DNStatusCheckMain() */
            cdt = (dn_manual_stop || g_dnDiskDamage[ii] || port_conflict);
            if (cdt) {
                g_dnStartCounts[ii] = 0;
            } else {
                g_dnStartCounts[ii]++;
            }
        } else {
            write_runlog(ERROR, "error.dn is %u ret=%d\n", g_currentNode->datanode[ii].datanodeId, ret);
        }
    }
#ifdef __aarch64__
    /* Update g_datanode_primary_count */
    if (g_dn_report_msg_ok) {
        g_datanode_primary_num = gaussdb_primary_index;
    }

    /* cm_agent has connected all primary datanode ad standby datanode */
    if (datanode_connect_count == g_datanode_primary_and_standby_num) {
        g_dn_report_msg_ok = true;
    }
#endif
    return;
}

#if ((defined(ENABLE_MULTIPLE_NODES)) || (defined(ENABLE_PRIVATEGAUSS)))
static void InitDnSyncListMsg(AgentToCmserverDnSyncList *syncListMsg, uint32 index)
{
    errno_t rc = memset_s(syncListMsg, sizeof(AgentToCmserverDnSyncList), 0, sizeof(AgentToCmserverDnSyncList));
    securec_check_errno(rc, (void)rc);
    syncListMsg->node = g_currentNode->node;
    syncListMsg->instanceId = g_currentNode->datanode[index].datanodeId;
    syncListMsg->instanceType = INSTANCE_TYPE_DATANODE;
    syncListMsg->msg_type = (int32)MSG_AGENT_CM_DN_SYNC_LIST;
    syncListMsg->syncDone = FAILED_SYNC_DATA;
}

static void CopyDnSyncListToReportMsg(const AgentToCmserverDnSyncList *syncListMsg, uint32 idx)
{
    (void)pthread_rwlock_wrlock(&(g_dnSyncListInfo[idx].lk_lock));
    errno_t rc = memcpy_s(&(g_dnSyncListInfo[idx].dnSyncListMsg), sizeof(AgentToCmserverDnSyncList),
        syncListMsg, sizeof(AgentToCmserverDnSyncList));
    securec_check_errno(rc, (void)rc);
    (void)pthread_rwlock_unlock(&(g_dnSyncListInfo[idx].lk_lock));
}

static void ResetCmaDoWrite(uint32 idx, bool isDoWrite)
{
    (void)pthread_rwlock_wrlock(&(g_cmDoWriteOper[idx].lock));
    g_cmDoWriteOper[idx].doWrite = isDoWrite;
    (void)pthread_rwlock_unlock(&(g_cmDoWriteOper[idx].lock));
}

static bool CheckundocumentedVersion(uint32 instd)
{
    static int32 count = 0;
    const int32 needPrintLog = 10;
    const uint32 doWriteVersion = 92497;

    if (undocumentedVersion != 0 && undocumentedVersion < doWriteVersion) {
        int32 logLevel = DEBUG1;
        if (count >= needPrintLog) {
            logLevel = LOG;
            count = 0;
        }
        ++count;
        write_runlog(logLevel, "undocumentedVersion is (%u, %u), instd(%u) cannot do write check.\n",
            undocumentedVersion, doWriteVersion, instd);
        return true;
    }
    return false;
}

static void GetSyncListFromDn(AgentToCmserverDnSyncList *syncListMsg, uint32 idx, cltPqConn_t **curDnConn)
{
    const int32 rwTimeout = 3600;
    uint32 instd = g_currentNode->datanode[idx].datanodeId;
    if ((*curDnConn) == NULL) {
        char pidPath[MAX_PATH_LEN] = {0};
        errno_t rc = snprintf_s(pidPath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/postmaster.pid",
            g_currentNode->datanode[idx].datanodeLocalDataPath);
        securec_check_intval(rc, (void)rc);
        (*curDnConn) = get_connection(pidPath, false, AGENT_CONN_DN_TIMEOUT, rwTimeout);
        if ((*curDnConn) == NULL || (!IsConnOk(*curDnConn))) {
            write_runlog(ERROR, "curDnConn is NULL, instd is %u, pidPath is %s.\n", instd, pidPath);
            return;
        }
    }

    if (CheckDatanodeSyncList(instd, syncListMsg, curDnConn) != 0) {
        write_runlog(ERROR, "instd is %u, falied to check datanode syncList.\n", instd);
        return;
    }

    (void)pthread_rwlock_wrlock(&(g_cmDoWriteOper[idx].lock));
    if (!g_cmDoWriteOper[idx].doWrite) {
        (void)pthread_rwlock_unlock(&(g_cmDoWriteOper[idx].lock));
        return;
    }
    (void)pthread_rwlock_unlock(&(g_cmDoWriteOper[idx].lock));

    if (CheckundocumentedVersion(instd)) {
        return;
    }

    (void)pthread_rwlock_wrlock(&(g_dnReportMsg[idx].lk_lock));
    if (g_dnReportMsg[idx].dnStatus.reportMsg.local_status.local_role != INSTANCE_ROLE_PRIMARY) {
        (void)pthread_rwlock_unlock(&(g_dnReportMsg[idx].lk_lock));
        ResetCmaDoWrite(idx, false);
        return;
    }
    (void)pthread_rwlock_unlock(&(g_dnReportMsg[idx].lk_lock));

    if (CheckDnSyncDone(instd, syncListMsg, curDnConn) != 0) {
        write_runlog(ERROR, "instd is %u, falied to check datanode sync done.\n", instd);
    } else {
        write_runlog(LOG, "success do write oper(%d) in dn(%u), and synclist is %s.\n", syncListMsg->syncDone,
            instd, syncListMsg->dnSynLists);
        ResetCmaDoWrite(idx, false);
    }
}

void *DNSyncCheckMain(void *arg)
{
    AgentToCmserverDnSyncList dnSyncListMsg;
    uint32 idx = *(uint32 *)arg;
    pthread_t threadId = pthread_self();
    write_runlog(LOG, "dn(%u) status check thread start, threadid %lu.\n", idx, threadId);
    int32 processStatus = 0;
    uint32 shutdownSleepInterval = 5;
    cltPqConn_t *curDnConn = NULL;
    for (;;) {
        if (g_shutdownRequest) {
            cm_sleep(shutdownSleepInterval);
            continue;
        }
        InitDnSyncListMsg(&dnSyncListMsg, idx);
        processStatus =
            check_one_instance_status(DATANODE_BIN_NAME, g_currentNode->datanode[idx].datanodeLocalDataPath, NULL);
        if (processStatus != PROCESS_RUNNING) {
            CopyDnSyncListToReportMsg(&dnSyncListMsg, idx);
        } else {
            GetSyncListFromDn(&dnSyncListMsg, idx, &curDnConn);
            CopyDnSyncListToReportMsg(&dnSyncListMsg, idx);
        }
        cm_sleep(agent_report_interval);
    }

    return NULL;
}
#endif

static void InitDnSyncAvailabletMsg(AgentToCmserverDnSyncAvailable *dnAvailableSyncMsg, uint32 index)
{
    errno_t rc = 0;
    rc = memset_s(dnAvailableSyncMsg, sizeof(AgentToCmserverDnSyncAvailable),
        0, sizeof(AgentToCmserverDnSyncAvailable));
    securec_check_errno(rc, (void)rc);
    dnAvailableSyncMsg->node = g_currentNode->node;
    dnAvailableSyncMsg->instanceId = g_currentNode->datanode[index].datanodeId;
    dnAvailableSyncMsg->instanceType = INSTANCE_TYPE_DATANODE;
    dnAvailableSyncMsg->msg_type = (int32)MSG_AGENT_CM_DN_MOST_AVAILABLE;
    dnAvailableSyncMsg->dnAvailableSyncStatus = false;
    dnAvailableSyncMsg->dnSynLists[0] = '\0';
    dnAvailableSyncMsg->syncStandbyNames[0] = '\0';
    dnAvailableSyncMsg->syncCommit[0] = '\0';
}

static void GetSyncAvailableFromDn(AgentToCmserverDnSyncAvailable *dnAvailableSyncMsg,
    uint32 idx, cltPqConn_t **curDnConn)
{
    const int32 rwTimeout = 3600;
    const int report_sleep_times = 5;
    int rc;
    uint32 instd = g_currentNode->datanode[idx].datanodeId;
    if ((*curDnConn) == NULL) {
        char pidPath[MAX_PATH_LEN] = {0};
        errno_t rc = snprintf_s(pidPath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/postmaster.pid",
            g_currentNode->datanode[idx].datanodeLocalDataPath);
        securec_check_intval(rc, (void)rc);
        (*curDnConn) = get_connection(pidPath, false, AGENT_CONN_DN_TIMEOUT, rwTimeout);
        if ((*curDnConn) == NULL || (!IsConnOk(*curDnConn))) {
            write_runlog(ERROR, "curDnConn is NULL, instd is %u, pidPath is %s.\n", instd, pidPath);
            return;
        }
    }
    bool isDnPrimary = g_dnReportMsg[idx].dnStatus.reportMsg.local_status.local_role == INSTANCE_ROLE_PRIMARY;
    AgentToCmserverDnSyncList syncListMsg;
    if (isDnPrimary && CheckDatanodeSyncList(instd, &syncListMsg, curDnConn) != 0) {
        write_runlog(ERROR, "instd is %u, falied to get datanode synchronous_standby_names.\n", instd);
        return;
    }
    rc = strcpy_s(dnAvailableSyncMsg->syncStandbyNames, DN_SYNC_LEN, syncListMsg.dnSynLists);
    securec_check_errno(rc, (void)rc);

    if (CheckDatanodeSyncCommit(instd, dnAvailableSyncMsg, curDnConn) != 0) {
        write_runlog(ERROR, "instd is %u, falied to get datanode synchronous_commit.\n", instd);
        return;
    }

    if (isDnPrimary && CheckDatanodeCurSyncLists(instd, dnAvailableSyncMsg, curDnConn) != 0) {
        write_runlog(ERROR, "instd is %u, falied to get datanode current SyncLists.\n", instd);
        return;
    }

    if (g_mostAvailableSync[idx]) {
        dnAvailableSyncMsg->dnAvailableSyncStatus = true;
    } else {
        dnAvailableSyncMsg->dnAvailableSyncStatus = false;
    }

    write_runlog(DEBUG5, "dn(%u) will send syncAvailable msg to cms.\n", instd);
    PushMsgToCmsSendQue((char *)dnAvailableSyncMsg,
        (uint32)sizeof(AgentToCmserverDnSyncAvailable), "dn syncavailableMsg");

    /* dn is not primary, sleep agent_report_interval*5 second */
    if (!isDnPrimary) {
        cm_sleep(agent_report_interval * report_sleep_times);
    }
}

void *DNMostAvailableCheckMain(void *arg)
{
    AgentToCmserverDnSyncAvailable dnAvailableSyncMsg;
    uint32 idx = *(uint32 *)arg;
    pthread_t threadId = pthread_self();
    write_runlog(LOG, "dn(%u) most available sync check thread start, threadid %lu.\n", idx, threadId);
    int32 processStatus = 0;
    uint32 shutdownSleepInterval = 5;
    cltPqConn_t *curDnConn = NULL;
    for (;;) {
        if (g_shutdownRequest) {
            cm_sleep(shutdownSleepInterval);
            continue;
        }
        InitDnSyncAvailabletMsg(&dnAvailableSyncMsg, idx);
        processStatus =
            check_one_instance_status(DATANODE_BIN_NAME, g_currentNode->datanode[idx].datanodeLocalDataPath, NULL);
        if (processStatus != PROCESS_RUNNING) {
            write_runlog(DEBUG5, "%s :%d, dn(%u) is not running.\n",
                __FUNCTION__, __LINE__, idx);
        } else {
            write_runlog(DEBUG5, "dn(%u) is running, will update sync available Msg from dn instance.\n", idx);
            GetSyncAvailableFromDn(&dnAvailableSyncMsg, idx, &curDnConn);
        }
        cm_sleep(agent_report_interval);
    }
    return NULL;
}

static int GetHadrUserInfoCiphertext(cltPqConn_t* &healthConn, char *cipherText, uint32 cipherTextLen)
{
    const char *sqlCommands = "select value from gs_global_config where name='hadr_user_info';";
    cltPqResult_t *nodeResult = Exec(healthConn, sqlCommands);
    if (nodeResult == NULL) {
        write_runlog(ERROR, "[%s] sqlCommands fail return NULL!\n", __FUNCTION__);
        CLOSE_CONNECTION(healthConn);
    }
    if ((ResultStatus(nodeResult) == CLTPQRES_CMD_OK) || (ResultStatus(nodeResult) == CLTPQRES_TUPLES_OK)) {
        int maxRows = Ntuples(nodeResult);
        if (maxRows == 0) {
            write_runlog(LOG, "[%s] sqlCommands fail is 0\n", __FUNCTION__);
            CLEAR_AND_CLOSE_CONNECTION(nodeResult, healthConn);
        } else {
            int maxColums = Nfields(nodeResult);
            if (maxColums != 1) {
                write_runlog(ERROR, "[%s] sqlCommands fail FAIL! col is %d\n", __FUNCTION__, maxColums);
                CLEAR_AND_CLOSE_CONNECTION(nodeResult, healthConn);
            }
            char *cipherTextTmp = Getvalue(nodeResult, 0, 0);
            errno_t rc = strncpy_s(cipherText, cipherTextLen, cipherTextTmp, strlen(cipherTextTmp));
            securec_check_errno(rc, (void)rc);
            /* Clear sensitive information */
            rc = memset_s(cipherTextTmp, strlen(cipherTextTmp), 0, strlen(cipherTextTmp));
            securec_check_errno(rc, (void)rc);
        }
    } else {
        write_runlog(ERROR, "[%s] sqlCommands fail FAIL! Status=%d\n", __FUNCTION__, ResultStatus(nodeResult));
        CLEAR_AND_CLOSE_CONNECTION(nodeResult, healthConn);
    }
    Clear(nodeResult);
    return 0;
}

static int GetHadrUserInfo(cltPqConn_t* &healthConn, const char *cipherText, const char *plain, char *userInfo)
{
    char sqlCommands[CM_MAX_COMMAND_LEN];
    errno_t rc = snprintf_s(sqlCommands, CM_MAX_COMMAND_LEN, CM_MAX_COMMAND_LEN - 1,
        "select pg_catalog.gs_decrypt_aes128('%s','%s');", cipherText, plain);
    securec_check_intval(rc, (void)rc);
    cltPqResult_t *nodeResult = Exec(healthConn, sqlCommands);
    rc = memset_s(sqlCommands, CM_MAX_COMMAND_LEN, 0, CM_MAX_COMMAND_LEN);
    securec_check_errno(rc, (void)rc);
    if (nodeResult == NULL) {
        write_runlog(ERROR, "sqlCommands fail return NULL!\n");
        CLOSE_CONNECTION(healthConn);
    }
    if ((ResultStatus(nodeResult) == CLTPQRES_CMD_OK) || (ResultStatus(nodeResult) == CLTPQRES_TUPLES_OK)) {
        int maxRows = Ntuples(nodeResult);
        if (maxRows == 0) {
            write_runlog(LOG, "sqlCommands fail is 0\n");
            CLEAR_AND_CLOSE_CONNECTION(nodeResult, healthConn);
        } else {
            int maxColums = Nfields(nodeResult);
            if (maxColums != 1) {
                write_runlog(ERROR, "sqlCommands fail FAIL! col is %d\n", maxColums);
                CLEAR_AND_CLOSE_CONNECTION(nodeResult, healthConn);
            }
            char *userInfoTmp = Getvalue(nodeResult, 0, 0);
            rc = strncpy_s(userInfo, CM_MAX_COMMAND_LEN, userInfoTmp, strlen(userInfoTmp));
            securec_check_errno(rc, (void)rc);
            /* Clear sensitive information */
            rc = memset_s(userInfoTmp, strlen(userInfoTmp), 0, strlen(userInfoTmp));
            securec_check_errno(rc, (void)rc);
        }
    } else {
        write_runlog(ERROR, "sqlCommands fail FAIL! Status=%d\n", ResultStatus(nodeResult));
        CLEAR_AND_CLOSE_CONNECTION(nodeResult, healthConn);
    }
    Clear(nodeResult);
    return 0;
}

static void ExecuteCrossClusterDnBuildCommand(const char *dataDir, char *userInfo)
{
    char *userPassword = NULL;
    /* userInfo format is <userName>|<userPassword> */
    char *userName = strtok_r(userInfo, "|", &userPassword);
    if (userName == NULL) {
        write_runlog(ERROR, "[ExecuteCrossClusterDnBuildCommand] unexpect userInfo.\n");
        return;
    }
    char command[MAXPGPATH] = {0};

#ifdef ENABLE_MULTIPLE_NODES
    errno_t rc = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1, SYSTEMQUOTE
        "%s build -Z datanode -D %s -M hadr_main_standby -U %s -P \'%s\' >> %s 2>&1 &" SYSTEMQUOTE,
        PG_CTL_NAME, dataDir, userName, userPassword, system_call_log);
#else
    errno_t rc = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1, SYSTEMQUOTE
        "%s build -D %s -M hadr_main_standby -U %s -P \'%s\' >> %s 2>&1 &" SYSTEMQUOTE,
        PG_CTL_NAME, dataDir, userName, userPassword, system_call_log);
#endif
    securec_check_intval(rc, (void)rc);

    write_runlog(LOG, "[ExecuteCrossClusterDnBuildCommand] start build operation.\n");
    int ret = system(command);
    if (ret != 0) {
        write_runlog(ERROR, "ExecuteCrossClusterDnBuildCommand: exec command failed %d! errno=%d.\n", ret, errno);
        return;
    }
    g_lastBuildRole = INSTANCE_ROLE_MAIN_STANDBY;
    /* Clear sensitive information */
    rc = memset_s(command, MAXPGPATH, 0, MAXPGPATH);
    securec_check_errno(rc, (void)rc);
    return;
}

void ExecuteCascadeStandbyDnBuildCommand(const char *dataDir)
{
    char command[MAXPGPATH] = {0};

#ifdef ENABLE_MULTIPLE_NODES
    errno_t rc = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1, SYSTEMQUOTE
        "%s build -Z datanode -D %s -M cascade_standby -b standby_full >> %s 2>&1 &" SYSTEMQUOTE,
        PG_CTL_NAME, dataDir, system_call_log);
#else
    errno_t rc = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1, SYSTEMQUOTE
        "%s build -D %s -M cascade_standby -b standby_full >> %s 2>&1 &" SYSTEMQUOTE,
        PG_CTL_NAME, dataDir, system_call_log);
#endif
    securec_check_intval(rc, (void)rc);

    int ret = system(command);
    if (ret != 0) {
        write_runlog(ERROR, "ExecuteCascadeStandbyDnBuildCommand: exec command failed %d! command is %s, errno=%d.\n",
            ret, command, errno);
        return;
    }
    g_lastBuildRole = INSTANCE_ROLE_CASCADE_STANDBY;
    write_runlog(LOG, "ExecuteCascadeStandbyDnBuildCommand: exec command success! command is %s\n", command);
}

static status_t GetRemoteHealthConnInfo(uint32 healthInstanceId, uint32 &remotePort, char* &remoteListenIP)
{
    for (uint32 i = 0; i < g_node_num; i++) {
        if (g_node[i].coordinate == 1 && g_node[i].coordinateId == healthInstanceId) {
            remotePort = g_node[i].coordinatePort + 1;
            remoteListenIP = g_node[i].coordinateListenIP[0];
            return CM_SUCCESS;
        }
        for (uint32 j = 0; j < g_node[i].datanodeCount; j++) {
            if (g_node[i].datanode[j].datanodeId == healthInstanceId) {
                remotePort = g_node[i].datanode[j].datanodePort + 1;
                remoteListenIP = g_node[i].datanode[j].datanodeListenIP[0];
                return CM_SUCCESS;
            }
        }
    }
    write_runlog(ERROR, "[GetRemoteHealthConnInfo] can't find instance_%u.\n", healthInstanceId);
    return CM_ERROR;
}

static cltPqConn_t *GetHealthConnection(uint32 healthInstanceId)
{
    char connStr[MAXCONNINFO] = {0};

    write_runlog(LOG, "[GetHealthConnection] healthInstance is dn_%u\n", healthInstanceId);
    uint32 remotePort = 0;
    char *remoteListenIP = NULL;
    if (GetRemoteHealthConnInfo(healthInstanceId, remotePort, remoteListenIP) != CM_SUCCESS) {
        return NULL;
    }

    errno_t rc = snprintf_s(connStr, sizeof(connStr), sizeof(connStr) - 1,
        "dbname=postgres port=%u host='%s' connect_timeout=10 rw_timeout=1260 application_name=%s "
        "options='-c xc_maintenance_mode=on'",
        remotePort, remoteListenIP, g_progname);
    securec_check_intval(rc, (void)rc);

    cltPqConn_t *healthConn = Connect(connStr);
    if (healthConn == NULL) {
        write_runlog(ERROR, "[GetHealthConnection] connect to %u failed, connStr: %s.\n", healthInstanceId, connStr);
        return NULL;
    }
    if (!IsConnOk(healthConn)) {
        write_runlog(ERROR, "[GetHealthConnection] connect to %u failed, PQstatus not ok, connStr: %s, errmsg is %s.\n",
            healthInstanceId, connStr, ErrorMessage(healthConn));
        close_and_reset_connection(healthConn);
    }
    return healthConn;
}

void ProcessCrossClusterBuildCommand(int instanceType, const char *dataDir)
{
    uint32 healthInstance = g_healthInstance;
    /* use healthConn to get UserInfo, prevent local instances is unavailable. */
    cltPqConn_t *healthConn = GetHealthConnection(healthInstance);
    if (healthConn == NULL) {
        write_runlog(ERROR, "[ProcessCrossClusterBuildCommand] Get health connection fail.\n");
        return;
    }

    char keyPassword[CM_PASSWD_MAX_LEN + 1];
    char cipherText[CM_MAX_COMMAND_LEN];
    char userInfo[CM_MAX_COMMAND_LEN];

    int ret = GetHadrUserInfoCiphertext(healthConn, cipherText, CM_MAX_COMMAND_LEN);
    if (ret != 0) {
        write_runlog(ERROR, "[ProcessCrossClusterBuildCommand] Get hadr userInfo ciphertext failed.\n");
        return;
    }

    if (cm_verify_ssl_key_pwd(keyPassword, sizeof(keyPassword) - 1, HADR_CIPHER) != CM_SUCCESS) {
        write_runlog(ERROR, "[ProcessCrossClusterBuildCommand] srv verify ssl keypwd failed.\n");
        return;
    }

    ret = GetHadrUserInfo(healthConn, cipherText, keyPassword, userInfo);
    if (ret != 0) {
        write_runlog(ERROR, "[ProcessCrossClusterBuildCommand] Get hadr userinfo failed.\n");
        return;
    }

    /* Clear sensitive information */
    errno_t rc = memset_s(keyPassword, CM_PASSWD_MAX_LEN, 0, CM_PASSWD_MAX_LEN);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(cipherText, CM_MAX_COMMAND_LEN, 0, CM_MAX_COMMAND_LEN);
    securec_check_errno(rc, (void)rc);

    switch (instanceType) {
        case INSTANCE_TYPE_DATANODE:
            ExecuteCrossClusterDnBuildCommand(dataDir, userInfo);
            break;
#ifdef ENABLE_MULTIPLE_NODES
        case INSTANCE_TYPE_COORDINATE:
            ExecuteCrossClusterCnBuildCommand(dataDir, userInfo);
            break;
#endif
        default:
            write_runlog(LOG, "[ProcessCrossClusterBuildCommand] node_type is unknown !\n");
            break;
    }
    /* Clear sensitive information */
    rc = memset_s(userInfo, CM_MAX_COMMAND_LEN, 0, CM_MAX_COMMAND_LEN);
    securec_check_errno(rc, (void)rc);
    close_and_reset_connection(healthConn);
}

void ProcessStreamingStandbyClusterBuildCommand(
    int instanceType, const char *dataDir, const cm_to_agent_build *buildMsg)
{
    if (instanceType == INSTANCE_TYPE_DATANODE && buildMsg->role == INSTANCE_ROLE_STANDBY) {
        ExecuteCascadeStandbyDnBuildCommand(dataDir);
        return;
    }
    ProcessCrossClusterBuildCommand(instanceType, dataDir);
}
