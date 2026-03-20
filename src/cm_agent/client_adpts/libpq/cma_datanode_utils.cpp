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
 * cma_datanode_utils.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_agent/client_adpts/libpq/cma_datanode_utils.cpp
 *
 * -------------------------------------------------------------------------
 */
#include "cma_global_params.h"
#include "cma_common.h"
#include "cjson/cJSON.h"
#include "cma_datanode_utils.h"

#define MAX_ROLE_LEN 16
#define MAX_JSONSTR_LEN 2048

cltPqConn_t* g_dnConn[CM_MAX_DATANODE_PER_NODE] = {NULL};
THR_LOCAL cltPqConn_t* g_Conn = NULL;
extern const char* g_progname;
#ifdef ENABLE_MULTIPLE_NODES
static cltPqConn_t* GetDnConnect(int index, const char *dbname);
static int GetDnDatabaseResult(cltPqConn_t* dnConn, const char* runCommand, char* databaseName);
int GetDBTableFromSQL(int index, uint32 databaseId, uint32 tableId, uint32 tableIdSize,
                      DNDatabaseInfo *dnDatabaseInfo, int dnDatabaseCount, char* databaseName, char* tableName);
#endif

#ifdef ENABLE_UT
#define static
#endif

const char *RoleLeader = "LEADER";
const char *RoleFollower = "FOLLOWER";
const char *RolePassive = "PASSIVE";
const char *RoleLogger = "LOGGER";
const char *RolePrecandicate = "PRE_CANDIDATE";
const char *RoleCandicate = "CANDIDATE";

static int g_errCountPgStatBadBlock[CM_MAX_DATANODE_PER_NODE] = {0};

static void fill_sql6_report_msg1(agent_to_cm_datanode_status_report* report_msg, const cltPqResult_t* node_result)
{
    int rc = sscanf_s(Getvalue(node_result, 0, 0), "%lu", &(report_msg->parallel_redo_status.redo_start_ptr));
    check_sscanf_s_result(rc, 1);

    securec_check_intval(rc, (void)rc);
    rc = sscanf_s(Getvalue(node_result, 0, 1), "%ld", &(report_msg->parallel_redo_status.redo_start_time));
    check_sscanf_s_result(rc, 1);
    securec_check_intval(rc, (void)rc);

    rc = sscanf_s(Getvalue(node_result, 0, 2), "%ld", &(report_msg->parallel_redo_status.redo_done_time));
    check_sscanf_s_result(rc, 1);
    securec_check_intval(rc, (void)rc);

    rc = sscanf_s(Getvalue(node_result, 0, 3), "%ld", &(report_msg->parallel_redo_status.curr_time));
    check_sscanf_s_result(rc, 1);
    securec_check_intval(rc, (void)rc);

    rc = sscanf_s(Getvalue(node_result, 0, 4), "%lu", &(report_msg->parallel_redo_status.min_recovery_point));
    check_sscanf_s_result(rc, 1);
    securec_check_intval(rc, (void)rc);

    rc = sscanf_s(Getvalue(node_result, 0, 5), "%lu", &(report_msg->parallel_redo_status.read_ptr));
    check_sscanf_s_result(rc, 1);
    securec_check_intval(rc, (void)rc);

    rc = sscanf_s(Getvalue(node_result, 0, 6), "%lu", &(report_msg->parallel_redo_status.last_replayed_read_ptr));
    check_sscanf_s_result(rc, 1);
    securec_check_intval(rc, (void)rc);

    rc = sscanf_s(Getvalue(node_result, 0, 7), "%lu", &(report_msg->parallel_redo_status.recovery_done_ptr));
    check_sscanf_s_result(rc, 1);
    securec_check_intval(rc, (void)rc);
}

static void fill_sql6_report_msg2(agent_to_cm_datanode_status_report* report_msg,
    const cltPqResult_t* node_result)
{
    int rc = sscanf_s(Getvalue(node_result, 0, 8), "%ld", &(report_msg->parallel_redo_status.wait_info[0].counter));
    check_sscanf_s_result(rc, 1);
    securec_check_intval(rc, (void)rc);
    rc =
        sscanf_s(Getvalue(node_result, 0, 9), "%ld", &(report_msg->parallel_redo_status.wait_info[0].total_duration));
    check_sscanf_s_result(rc, 1);
    securec_check_intval(rc, (void)rc);
    rc = sscanf_s(Getvalue(node_result, 0, 10), "%ld", &(report_msg->parallel_redo_status.wait_info[1].counter));
    check_sscanf_s_result(rc, 1);
    securec_check_intval(rc, (void)rc);
    rc = sscanf_s(
        Getvalue(node_result, 0, 11), "%ld", &(report_msg->parallel_redo_status.wait_info[1].total_duration));
    check_sscanf_s_result(rc, 1);
    securec_check_intval(rc, (void)rc);
    rc = sscanf_s(Getvalue(node_result, 0, 12), "%ld", &(report_msg->parallel_redo_status.wait_info[2].counter));
    check_sscanf_s_result(rc, 1);
    securec_check_intval(rc, (void)rc);
    rc = sscanf_s(
        Getvalue(node_result, 0, 13), "%ld", &(report_msg->parallel_redo_status.wait_info[2].total_duration));
    check_sscanf_s_result(rc, 1);
    securec_check_intval(rc, (void)rc);
    rc = sscanf_s(Getvalue(node_result, 0, 14), "%ld", &(report_msg->parallel_redo_status.wait_info[3].counter));
    check_sscanf_s_result(rc, 1);
    securec_check_intval(rc, (void)rc);
    rc = sscanf_s(
        Getvalue(node_result, 0, 15), "%ld", &(report_msg->parallel_redo_status.wait_info[3].total_duration));
    check_sscanf_s_result(rc, 1);
    securec_check_intval(rc, (void)rc);
    rc = sscanf_s(Getvalue(node_result, 0, 16), "%ld", &(report_msg->parallel_redo_status.wait_info[4].counter));
    check_sscanf_s_result(rc, 1);
    securec_check_intval(rc, (void)rc);
    rc = sscanf_s(
        Getvalue(node_result, 0, 17), "%ld", &(report_msg->parallel_redo_status.wait_info[4].total_duration));
    check_sscanf_s_result(rc, 1);
    securec_check_intval(rc, (void)rc);
}

int ReadRedoStateFile(RedoStatsData* redo_state, const char* redo_state_path)
{
    if (redo_state == NULL) {
        write_runlog(LOG, "Could not get information from redo.state\n");
        return -1;
    }
    FILE *statef = fopen(redo_state_path, "re");
    if (statef == NULL) {
        if (errno == ENOENT) {
            char errBuffer[ERROR_LIMIT_LEN];
            write_runlog(LOG,
                "redo state file \"%s\" is not exist, could not get the build infomation: %s\n",
                redo_state_path,
                strerror_r(errno, errBuffer, ERROR_LIMIT_LEN));
        } else {
            char errBuffer[ERROR_LIMIT_LEN];
            write_runlog(LOG,
                "open redo state file \"%s\" failed, could not get the build infomation: %s\n",
                redo_state_path,
                strerror_r(errno, errBuffer, ERROR_LIMIT_LEN));
        }
        return -1;
    }
    if ((fread(redo_state, 1, sizeof(RedoStatsData), statef)) == 0) {
        write_runlog(LOG, "get redo state infomation from the file \"%s\" failed\n", redo_state_path);
        (void)fclose(statef);
        return -1;
    }
    (void)fclose(statef);
    return 0;
}

void check_parallel_redo_status_by_file(agent_to_cm_datanode_status_report *reportMsg, const char *redoStatePath)
{
    RedoStatsData parallel_redo_state;

    int rcs = memset_s(&parallel_redo_state, sizeof(parallel_redo_state), 0, sizeof(parallel_redo_state));
    securec_check_errno(rcs, (void)rcs);

    rcs = ReadRedoStateFile(&parallel_redo_state, redoStatePath);
    if (rcs == 0) {
        reportMsg->local_redo_stats.is_by_query = 0;
        reportMsg->parallel_redo_status.redo_start_ptr = parallel_redo_state.redo_start_ptr;

        reportMsg->parallel_redo_status.redo_start_time = parallel_redo_state.redo_start_time;

        reportMsg->parallel_redo_status.redo_done_time = parallel_redo_state.redo_done_time;

        reportMsg->parallel_redo_status.curr_time = parallel_redo_state.curr_time;

        reportMsg->parallel_redo_status.min_recovery_point = parallel_redo_state.min_recovery_point;

        reportMsg->parallel_redo_status.read_ptr = parallel_redo_state.read_ptr;

        reportMsg->parallel_redo_status.last_replayed_read_ptr = parallel_redo_state.last_replayed_read_ptr;

        reportMsg->parallel_redo_status.local_max_lsn = parallel_redo_state.local_max_lsn;

        reportMsg->parallel_redo_status.recovery_done_ptr = parallel_redo_state.recovery_done_ptr;

        reportMsg->parallel_redo_status.worker_info_len = parallel_redo_state.worker_info_len;

        reportMsg->parallel_redo_status.speed_according_seg = parallel_redo_state.speed_according_seg;

        rcs = memcpy_s(reportMsg->parallel_redo_status.worker_info,
            REDO_WORKER_INFO_BUFFER_SIZE,
            parallel_redo_state.worker_info,
            parallel_redo_state.worker_info_len);
        securec_check_errno(rcs, (void)rcs);
        rcs = memcpy_s(reportMsg->parallel_redo_status.wait_info,
            WAIT_REDO_NUM * sizeof(RedoWaitInfo),
            parallel_redo_state.wait_info,
            WAIT_REDO_NUM * sizeof(RedoWaitInfo));
        securec_check_errno(rcs, (void)rcs);
    }
}

int check_datanode_status_by_SQL0(agent_to_cm_datanode_status_report* report_msg, uint32 ii)
{
    int maxRows = 0;
    int maxColums = 0;

    /* in case we return 0 without set the db_state. */
    const char* sqlCommands =
        "select local_role,static_connections,db_state,detail_information from pg_stat_get_stream_replications();";
    cltPqResult_t *node_result = Exec(g_dnConn[ii], sqlCommands);
    if (node_result == NULL) {
        write_runlog(ERROR, "sqlCommands[0] fail return NULL!\n");
        CLOSE_CONNECTION(g_dnConn[ii]);
    }
    if ((ResultStatus(node_result) == CLTPQRES_CMD_OK) || (ResultStatus(node_result) == CLTPQRES_TUPLES_OK)) {
        maxRows = Ntuples(node_result);
        if (maxRows == 0) {
            write_runlog(LOG, "sqlCommands[0] fail  is 0\n");
            CLEAR_AND_CLOSE_CONNECTION(node_result, g_dnConn[ii]);
        } else {
            int rc;

            maxColums = Nfields(node_result);
            if (maxColums != 4) {
                write_runlog(ERROR, "sqlCommands[0] fail  FAIL! col is %d\n", maxColums);
                CLEAR_AND_CLOSE_CONNECTION(node_result, g_dnConn[ii]);
            }

            report_msg->local_status.local_role = datanode_role_string_to_int(Getvalue(node_result, 0, 0));
            if (report_msg->local_status.local_role == INSTANCE_ROLE_UNKNOWN) {
                write_runlog(LOG, "sqlCommands[0] get local_status.local_role is: INSTANCE_ROLE_UNKNOWN\n");
            }
            rc = sscanf_s(Getvalue(node_result, 0, 1), "%d", &(report_msg->local_status.static_connections));
            check_sscanf_s_result(rc, 1);
            securec_check_intval(rc, (void)rc);
            report_msg->local_status.db_state = datanode_dbstate_string_to_int(Getvalue(node_result, 0, 2));
            report_msg->local_status.buildReason = datanode_rebuild_reason_string_to_int(Getvalue(node_result, 0, 3));
            if (report_msg->local_status.buildReason == INSTANCE_HA_DATANODE_BUILD_REASON_UNKNOWN) {
                write_runlog(LOG,
                    "build reason is %s, buildReason = %d\n",
                    Getvalue(node_result, 0, 3),
                    report_msg->local_status.buildReason);
            }
        }
    } else {
        write_runlog(ERROR, "sqlCommands[0] fail  FAIL! Status=%d\n", ResultStatus(node_result));
        CLEAR_AND_CLOSE_CONNECTION(node_result, g_dnConn[ii]);
    }
    Clear(node_result);
    return 0;
}

static bool get_datanode_realtime_build(const char* realtime_build_status)
{
    if (strcmp(realtime_build_status, "on") == 0) {
        return true;
    }

    return false;
}

constexpr int SQL_QUERY_REALTIME_BUILD_SUCCESS = 0;
constexpr int SQL_QUERY_REALTIME_BUILD_FAILURE = -1;

void check_datanode_realtime_build_status_by_sql(agent_to_cm_datanode_status_report* report_msg, uint32 ii)
{
    if (undocumentedVersion != 0 || (g_onDemandRealTimeBuildStatus & 0x4)) {
        return;
    }

    int max_rows = 0;
    int max_colums = 0;

    const char* sql_command = "show ss_enable_ondemand_realtime_build;";
    if (g_dnConn[ii] == NULL) {
        return;
    }
    cltPqResult_t* node_result = Exec(g_dnConn[ii], sql_command);
    if (node_result == NULL) {
        write_runlog(ERROR, "query sql fail: %s\n", sql_command);
        Clear(node_result);
        close_and_reset_connection(g_dnConn[ii]);
        return;
    }
    if ((ResultStatus(node_result) == CLTPQRES_CMD_OK) || (ResultStatus(node_result) == CLTPQRES_TUPLES_OK)) {
        max_rows = Ntuples(node_result);
        if (max_rows == 0) {
            write_runlog(ERROR, "query sql fail: %s\n", sql_command);
            Clear(node_result);
            close_and_reset_connection(g_dnConn[ii]);
            return;
        } else {
            max_colums = Nfields(node_result);
            if (max_colums != 1) {
                write_runlog(ERROR, "query sql fail: %s! col is %d\n", sql_command, max_colums);
                Clear(node_result);
                close_and_reset_connection(g_dnConn[ii]);
                return;
            }

            if (get_datanode_realtime_build(Getvalue(node_result, 0, 0))) {
                g_onDemandRealTimeBuildStatus |= 0x5;
            } else {
                g_onDemandRealTimeBuildStatus |= 0x4;
                g_onDemandRealTimeBuildStatus = ((g_onDemandRealTimeBuildStatus >> 1) << 1);
            }
            write_runlog(LOG, "ondemand_realtime_build_status by sql is %d\n", g_onDemandRealTimeBuildStatus);
        }
    } else {
        write_runlog(ERROR, "query sql fail: %s! Status=%d\n", sql_command, ResultStatus(node_result));
        Clear(node_result);
        close_and_reset_connection(g_dnConn[ii]);
        return;
    }
    Clear(node_result);
    return;
}

/* DN instance status check SQL 1 */
int check_datanode_status_by_SQL1(agent_to_cm_datanode_status_report* report_msg, uint32 ii)
{
    int maxRows = 0;
    int maxColums = 0;
    uint32 hi = 0;
    uint32 lo = 0;

    const char* sqlCommands = "select term, lsn from pg_last_xlog_replay_location();";

    cltPqResult_t *node_result = Exec(g_dnConn[ii], sqlCommands);
    if (node_result == NULL) {
        write_runlog(ERROR, "sqlCommands[1] fail return NULL!\n");
        CLOSE_CONNECTION(g_dnConn[ii]);
    }
    if ((ResultStatus(node_result) == CLTPQRES_CMD_OK) || (ResultStatus(node_result) == CLTPQRES_TUPLES_OK)) {
        maxRows = Ntuples(node_result);
        if (maxRows == 0) {
            write_runlog(LOG, "sqlCommands[1] is 0\n");
            CLEAR_AND_CLOSE_CONNECTION(node_result, g_dnConn[ii]);
        } else {
            int rc;

            maxColums = Nfields(node_result);
            if (maxColums != 2) {
                write_runlog(ERROR, "sqlCommands[1] fail ! col is %d\n", maxColums);
                CLEAR_AND_CLOSE_CONNECTION(node_result, g_dnConn[ii]);
            }

            char *term = Getvalue(node_result, 0, 0);
            if (term == NULL || strcmp(term, "") == 0) {
                write_runlog(ERROR, "term is invalid.\n");
                CLEAR_AND_CLOSE_CONNECTION(node_result, g_dnConn[ii]);
            } else {
                report_msg->local_status.term = (uint32)strtoul(term, NULL, 0);
            }

            char *xlog_location = Getvalue(node_result, 0, 1);
            if (xlog_location == NULL || strcmp(xlog_location, "") == 0) {
                write_runlog(ERROR, "pg_last_xlog_replay_location is empty.\n");
                CLEAR_AND_CLOSE_CONNECTION(node_result, g_dnConn[ii]);
            } else {
                /* Shielding %x format read Warning. */
                rc = sscanf_s(xlog_location, "%X/%X", &hi, &lo);
                check_sscanf_s_result(rc, 2);
                securec_check_intval(rc, (void)rc);
                report_msg->local_status.last_flush_lsn = (((uint64)hi) << 32) | lo;
            }
        }
    } else {
        write_runlog(ERROR, "sqlCommands[1] fail ResultStatus=%d!\n", ResultStatus(node_result));
        CLEAR_AND_CLOSE_CONNECTION(node_result, g_dnConn[ii]);
    }
    Clear(node_result);
    return 0;
}

int check_datanode_status_by_SQL2(agent_to_cm_datanode_status_report* report_msg, uint32 ii)
{
    uint32 hi = 0;
    uint32 lo = 0;
    int dn_sync_state = 0;
    char* most_available = NULL;

    char sqlCommands[CM_MAX_COMMAND_LEN];
    errno_t rc = snprintf_s(sqlCommands, CM_MAX_COMMAND_LEN, CM_MAX_COMMAND_LEN - 1,
        "select sender_pid,local_role,peer_role,peer_state,state,sender_sent_location,sender_write_location,"
        "sender_flush_location,sender_replay_location,receiver_received_location,receiver_write_location,"
        "receiver_flush_location,receiver_replay_location,sync_percent,sync_state,sync_priority,"
        "sync_most_available,channel from pg_stat_get_wal_senders() where peer_role='%s';",
        agent_backup_open == CLUSTER_STREAMING_STANDBY ? "Cascade Standby" : "Standby");
    securec_check_intval(rc, (void)rc);

    cltPqResult_t *node_result = Exec(g_dnConn[ii], sqlCommands);
    if (node_result == NULL) {
        write_runlog(ERROR, "sqlCommands[2] fail return NULL!\n");
        CLOSE_CONNECTION(g_dnConn[ii]);
    }
    if ((ResultStatus(node_result) == CLTPQRES_CMD_OK) || (ResultStatus(node_result) == CLTPQRES_TUPLES_OK)) {
        int maxRows = Ntuples(node_result);
        if (maxRows == 0) {
            write_runlog(DEBUG5, "walsender information is empty.\n");
        } else {
            int maxColums = Nfields(node_result);
            if (maxColums != 18) {
                write_runlog(ERROR, "sqlCommands[2] fail! col is %d\n", maxColums);
                CLEAR_AND_CLOSE_CONNECTION(node_result, g_dnConn[ii]);
            }
            rc = sscanf_s(Getvalue(node_result, 0, 0), "%d", &(report_msg->sender_status[0].sender_pid));
            check_sscanf_s_result(rc, 1);
            securec_check_intval(rc, (void)rc);
            report_msg->sender_status[0].local_role = datanode_role_string_to_int(Getvalue(node_result, 0, 1));
            if (report_msg->sender_status[0].local_role == INSTANCE_ROLE_UNKNOWN) {
                write_runlog(LOG, "sqlCommands[2] get sender_status.local_role is: INSTANCE_ROLE_UNKNOWN\n");
            }
            report_msg->sender_status[0].peer_role = datanode_role_string_to_int(Getvalue(node_result, 0, 2));
            if (report_msg->sender_status[0].peer_role == INSTANCE_ROLE_UNKNOWN) {
                write_runlog(LOG, "sqlCommands[2] get sender_status.peer_role is: INSTANCE_ROLE_UNKNOWN\n");
            }
            report_msg->sender_status[0].peer_state = datanode_dbstate_string_to_int(Getvalue(node_result, 0, 3));
            report_msg->sender_status[0].state = datanode_wal_send_state_string_to_int(Getvalue(node_result, 0, 4));
            /* Shielding %x format read Warning. */
            rc = sscanf_s(Getvalue(node_result, 0, 5), "%X/%X", &hi, &lo);
            check_sscanf_s_result(rc, 2);
            securec_check_intval(rc, (void)rc);
            report_msg->sender_status[0].sender_sent_location = (((uint64)hi) << 32) | lo;
            rc = sscanf_s(Getvalue(node_result, 0, 6), "%X/%X", &hi, &lo);
            check_sscanf_s_result(rc, 2);
            securec_check_intval(rc, (void)rc);
            report_msg->sender_status[0].sender_write_location = (((uint64)hi) << 32) | lo;
            rc = sscanf_s(Getvalue(node_result, 0, 7), "%X/%X", &hi, &lo);
            check_sscanf_s_result(rc, 2);
            securec_check_intval(rc, (void)rc);
            report_msg->sender_status[0].sender_flush_location = (((uint64)hi) << 32) | lo;
            rc = sscanf_s(Getvalue(node_result, 0, 8), "%X/%X", &hi, &lo);
            check_sscanf_s_result(rc, 2);
            securec_check_intval(rc, (void)rc);
            report_msg->sender_status[0].sender_replay_location = (((uint64)hi) << 32) | lo;
            rc = sscanf_s(Getvalue(node_result, 0, 9), "%X/%X", &hi, &lo);
            check_sscanf_s_result(rc, 2);
            securec_check_intval(rc, (void)rc);
            report_msg->sender_status[0].receiver_received_location = (((uint64)hi) << 32) | lo;
            rc = sscanf_s(Getvalue(node_result, 0, 10), "%X/%X", &hi, &lo);
            check_sscanf_s_result(rc, 2);
            securec_check_intval(rc, (void)rc);
            report_msg->sender_status[0].receiver_write_location = (((uint64)hi) << 32) | lo;
            rc = sscanf_s(Getvalue(node_result, 0, 11), "%X/%X", &hi, &lo);
            check_sscanf_s_result(rc, 2);
            securec_check_intval(rc, (void)rc);
            report_msg->sender_status[0].receiver_flush_location = (((uint64)hi) << 32) | lo;
            rc = sscanf_s(Getvalue(node_result, 0, 12), "%X/%X", &hi, &lo);
            check_sscanf_s_result(rc, 2);
            securec_check_intval(rc, (void)rc);
            report_msg->sender_status[0].receiver_replay_location = (((uint64)hi) << 32) | lo;
            rc = sscanf_s(Getvalue(node_result, 0, 13), "%d", &(report_msg->sender_status[0].sync_percent));
            check_sscanf_s_result(rc, 1);
            securec_check_intval(rc, (void)rc);
            dn_sync_state = datanode_wal_sync_state_string_to_int(Getvalue(node_result, 0, 14));
            if (!g_multi_az_cluster) {
                most_available = Getvalue(node_result, 0, 16);
                if (dn_sync_state == INSTANCE_DATA_REPLICATION_ASYNC) {
                    report_msg->sender_status[0].sync_state = INSTANCE_DATA_REPLICATION_ASYNC;
                } else if (dn_sync_state == INSTANCE_DATA_REPLICATION_SYNC && (strcmp(most_available, "Off") == 0)) {
                    report_msg->sender_status[0].sync_state = INSTANCE_DATA_REPLICATION_SYNC;
                } else if (dn_sync_state == INSTANCE_DATA_REPLICATION_SYNC && (strcmp(most_available, "On") == 0)) {
                    report_msg->sender_status[0].sync_state = INSTANCE_DATA_REPLICATION_MOST_AVAILABLE;
                } else {
                    report_msg->sender_status[0].sync_state = INSTANCE_DATA_REPLICATION_UNKONWN;
                    write_runlog(ERROR,
                        "datanode status report get wrong sync mode:%d, most available:%s\n",
                        dn_sync_state,
                        most_available);
                }
            } else {
                report_msg->sender_status[0].sync_state = dn_sync_state;
            }
            rc = sscanf_s(Getvalue(node_result, 0, 15), "%d", &(report_msg->sender_status[0].sync_priority));
            check_sscanf_s_result(rc, 1);
            securec_check_intval(rc, (void)rc);
        }
    } else {
        write_runlog(ERROR, "sqlCommands[2] fail ResultStatus=%d!\n", ResultStatus(node_result));
        CLEAR_AND_CLOSE_CONNECTION(node_result, g_dnConn[ii]);
    }
    Clear(node_result);
    return 0;
}

int check_datanode_status_by_SQL3(agent_to_cm_datanode_status_report* report_msg, uint32 ii)
{
    int maxRows = 0;
    int maxColums = 0;
    uint32 hi = 0;
    uint32 lo = 0;
    int dn_sync_state = 0;
    char* most_available = NULL;

    /* DN instance status check SQL 3 */
    const char* sqlCommands =
        "select sender_pid,local_role,peer_role,peer_state,state,sender_sent_location,sender_write_location,"
        "sender_flush_location,sender_replay_location,receiver_received_location,receiver_write_location,"
        "receiver_flush_location,receiver_replay_location,sync_percent,sync_state,sync_priority,"
        "sync_most_available,channel from pg_stat_get_wal_senders() where peer_role='Secondary';";
    cltPqResult_t *node_result = Exec(g_dnConn[ii], sqlCommands);
    if (node_result == NULL) {
        write_runlog(ERROR, "sqlCommands[3] fail return NULL!\n");
        CLOSE_CONNECTION(g_dnConn[ii]);
    }
    if ((ResultStatus(node_result) == CLTPQRES_CMD_OK) || (ResultStatus(node_result) == CLTPQRES_TUPLES_OK)) {
        maxRows = Ntuples(node_result);
        if (maxRows == 0) {
            write_runlog(DEBUG5, "walsender information is empty.\n");
        } else {
            int rc;

            maxColums = Nfields(node_result);
            if (maxColums != 18) {
                write_runlog(ERROR, "sqlCommands[3] fail! col is %d\n", maxColums);
                CLEAR_AND_CLOSE_CONNECTION(node_result, g_dnConn[ii]);
            }

            rc = sscanf_s(Getvalue(node_result, 0, 0), "%d", &(report_msg->sender_status[1].sender_pid));
            check_sscanf_s_result(rc, 1);
            securec_check_intval(rc, (void)rc);
            report_msg->sender_status[1].local_role = datanode_role_string_to_int(Getvalue(node_result, 0, 1));
            if (report_msg->sender_status[1].local_role == INSTANCE_ROLE_UNKNOWN) {
                write_runlog(LOG, "sqlCommands[3] get sender_status.local_role is: INSTANCE_ROLE_UNKNOWN\n");
            }
            report_msg->sender_status[1].peer_role = datanode_role_string_to_int(Getvalue(node_result, 0, 2));
            if (report_msg->sender_status[1].peer_role == INSTANCE_ROLE_UNKNOWN) {
                write_runlog(LOG, "sqlCommands[3] get sender_status.peer_role is: INSTANCE_ROLE_UNKNOWN\n");
            }
            report_msg->sender_status[1].peer_state = datanode_dbstate_string_to_int(Getvalue(node_result, 0, 3));
            report_msg->sender_status[1].state = datanode_wal_send_state_string_to_int(Getvalue(node_result, 0, 4));
            /* Shielding %x format read Warning. */
            rc = sscanf_s(Getvalue(node_result, 0, 5), "%X/%X", &hi, &lo);
            check_sscanf_s_result(rc, 2);
            securec_check_intval(rc, (void)rc);
            report_msg->sender_status[1].sender_sent_location = (((uint64)hi) << 32) | lo;
            rc = sscanf_s(Getvalue(node_result, 0, 6), "%X/%X", &hi, &lo);
            check_sscanf_s_result(rc, 2);
            securec_check_intval(rc, (void)rc);
            report_msg->sender_status[1].sender_write_location = (((uint64)hi) << 32) | lo;
            rc = sscanf_s(Getvalue(node_result, 0, 7), "%X/%X", &hi, &lo);
            check_sscanf_s_result(rc, 2);
            securec_check_intval(rc, (void)rc);
            report_msg->sender_status[1].sender_flush_location = (((uint64)hi) << 32) | lo;
            rc = sscanf_s(Getvalue(node_result, 0, 8), "%X/%X", &hi, &lo);
            check_sscanf_s_result(rc, 2);
            securec_check_intval(rc, (void)rc);
            report_msg->sender_status[1].sender_replay_location = (((uint64)hi) << 32) | lo;
            rc = sscanf_s(Getvalue(node_result, 0, 9), "%X/%X", &hi, &lo);
            check_sscanf_s_result(rc, 2);
            securec_check_intval(rc, (void)rc);
            report_msg->sender_status[1].receiver_received_location = (((uint64)hi) << 32) | lo;
            rc = sscanf_s(Getvalue(node_result, 0, 10), "%X/%X", &hi, &lo);
            check_sscanf_s_result(rc, 2);
            securec_check_intval(rc, (void)rc);
            report_msg->sender_status[1].receiver_write_location = (((uint64)hi) << 32) | lo;
            rc = sscanf_s(Getvalue(node_result, 0, 11), "%X/%X", &hi, &lo);
            check_sscanf_s_result(rc, 2);
            securec_check_intval(rc, (void)rc);
            report_msg->sender_status[1].receiver_flush_location = (((uint64)hi) << 32) | lo;
            rc = sscanf_s(Getvalue(node_result, 0, 12), "%X/%X", &hi, &lo);
            check_sscanf_s_result(rc, 2);
            securec_check_intval(rc, (void)rc);
            report_msg->sender_status[1].receiver_replay_location = (((uint64)hi) << 32) | lo;
            rc = sscanf_s(Getvalue(node_result, 0, 13), "%d", &(report_msg->sender_status[1].sync_percent));
            check_sscanf_s_result(rc, 1);
            securec_check_intval(rc, (void)rc);
            dn_sync_state = datanode_wal_sync_state_string_to_int(Getvalue(node_result, 0, 14));
            if (!g_multi_az_cluster) {
                most_available = Getvalue(node_result, 0, 16);
                if (dn_sync_state == INSTANCE_DATA_REPLICATION_ASYNC) {
                    report_msg->sender_status[1].sync_state = INSTANCE_DATA_REPLICATION_ASYNC;
                } else if (dn_sync_state == INSTANCE_DATA_REPLICATION_SYNC && (strcmp(most_available, "Off") == 0)) {
                    report_msg->sender_status[1].sync_state = INSTANCE_DATA_REPLICATION_SYNC;
                } else if (dn_sync_state == INSTANCE_DATA_REPLICATION_SYNC && (strcmp(most_available, "On") == 0)) {
                    report_msg->sender_status[1].sync_state = INSTANCE_DATA_REPLICATION_MOST_AVAILABLE;
                } else {
                    report_msg->sender_status[1].sync_state = INSTANCE_DATA_REPLICATION_UNKONWN;
                    write_runlog(ERROR,
                        "datanode status report get wrong sync mode:%d, most available:%s\n",
                        dn_sync_state,
                        most_available);
                }
            } else {
                report_msg->sender_status[1].sync_state = dn_sync_state;
            }
            rc = sscanf_s(Getvalue(node_result, 0, 15), "%d", &(report_msg->sender_status[1].sync_priority));
            check_sscanf_s_result(rc, 1);
            securec_check_intval(rc, (void)rc);
        }
    } else {
        write_runlog(ERROR, "sqlCommands[3] fail ResultStatus=%d!\n", ResultStatus(node_result));
        CLEAR_AND_CLOSE_CONNECTION(node_result, g_dnConn[ii]);
    }
    Clear(node_result);
    return 0;
}

static int ParseIpAndPort(char *addrStr, char *ipStr, uint32 *port)
{
    char *lastColon = strrchr(addrStr, ':');
    if (lastColon != NULL) {
        // Calculate the position of the colon
        size_t colonPos = lastColon - addrStr;
        
        // Copy the IP portion
        errno_t rc = strncpy_s(ipStr, CM_IP_LENGTH, addrStr, colonPos);
        securec_check_errno(rc, (void)rc);
        ipStr[colonPos] = '\0';  // Ensure the string terminator

        // Copy the port portion
        *port = (uint32)atoi(lastColon + 1);
        return 0; // Success
    } else {
        return -1;
    }
}

static void GetLpInfoByStr(char *channel, DnLocalPeer *lpInfo, uint32 instId)
{
    char localIpStr[CM_IP_LENGTH];
    char peerIpStr[CM_IP_LENGTH];
    char *peerStr = NULL;
    char *localStr = strtok_r(channel, "<--", &peerStr);
    errno_t rc;
    if (localStr == NULL) {
        write_runlog(ERROR, "[GetLpInfoByStr] line: %d, instance ID is %u, channel is %s.\n",
            __LINE__, instId, channel);
        return;
    }

    if (ParseIpAndPort(localStr, localIpStr, &lpInfo->localPort) == 0) {
        rc = strcpy_s(lpInfo->localIp, CM_IP_LENGTH, localIpStr);
        securec_check_errno(rc, (void)rc);
    } else {
        write_runlog(ERROR, "[GetLpInfoByStr] line: %d, instance ID is %u, channel is %s.\n",
            __LINE__, instId, channel);
        return;
    }

    // Parse peer IP and port
    if (ParseIpAndPort(peerStr, peerIpStr, &lpInfo->peerPort) == 0) {
        rc = strcpy_s(lpInfo->peerIp, CM_IP_LENGTH, peerIpStr);
        securec_check_errno(rc, (void)rc);
    } else {
        write_runlog(ERROR, "[GetLpInfoByStr] line: %d, instance ID is %u, channel is %s.\n",
            __LINE__, instId, channel);
        return;
    }

    write_runlog(DEBUG1, "%u, channel is %s:%u<--%s:%u.\n", instId,
        lpInfo->localIp, lpInfo->localPort, lpInfo->peerIp, lpInfo->peerPort);
}

int check_datanode_status_by_SQL4(agent_to_cm_datanode_status_report *report_msg, DnLocalPeer *lpInfo, uint32 ii)
{
    int maxRows = 0;
    int maxColums = 0;
    uint32 hi = 0;
    uint32 lo = 0;

    /* DN instance status check SQL 4 */
    const char* sqlCommands =
        "select receiver_pid,local_role,peer_role,peer_state,state,sender_sent_location,sender_write_location,"
        "sender_flush_location,sender_replay_location,receiver_received_location,receiver_write_location,"
        "receiver_flush_location,receiver_replay_location,sync_percent,channel from pg_stat_get_wal_receiver();";
    cltPqResult_t *node_result = Exec(g_dnConn[ii], sqlCommands);
    if (node_result == NULL) {
        write_runlog(ERROR, "sqlCommands[4] fail return NULL!\n");
        CLOSE_CONNECTION(g_dnConn[ii]);
    }
    if ((ResultStatus(node_result) == CLTPQRES_CMD_OK) || (ResultStatus(node_result) == CLTPQRES_TUPLES_OK)) {
        maxRows = Ntuples(node_result);
        if (maxRows == 0) {
            write_runlog(DEBUG5, "walreceviver information is empty.\n");
        } else {
            int rc;

            maxColums = Nfields(node_result);
            if (maxColums != 15) {
                write_runlog(ERROR, "sqlCommands[4] fail  FAIL! col is %d\n", maxColums);
                CLEAR_AND_CLOSE_CONNECTION(node_result, g_dnConn[ii]);
            }

            rc = sscanf_s(Getvalue(node_result, 0, 0), "%d", &(report_msg->receive_status.receiver_pid));
            check_sscanf_s_result(rc, 1);
            securec_check_intval(rc, (void)rc);
            report_msg->receive_status.local_role = datanode_role_string_to_int(Getvalue(node_result, 0, 1));
            if (report_msg->receive_status.local_role == INSTANCE_ROLE_UNKNOWN) {
                write_runlog(LOG, "sqlCommands[4] get receive_status.local_role is: INSTANCE_ROLE_UNKNOWN\n");
            }
            report_msg->receive_status.peer_role = datanode_role_string_to_int(Getvalue(node_result, 0, 2));
            if (report_msg->receive_status.peer_role == INSTANCE_ROLE_UNKNOWN) {
                write_runlog(LOG, "sqlCommands[4] get receive_status.peer_role is: INSTANCE_ROLE_UNKNOWN\n");
            }
            report_msg->receive_status.peer_state = datanode_dbstate_string_to_int(Getvalue(node_result, 0, 3));
            report_msg->receive_status.state = datanode_wal_send_state_string_to_int(Getvalue(node_result, 0, 4));
            /* Shielding %x format read Warning. */
            rc = sscanf_s(Getvalue(node_result, 0, 5), "%X/%X", &hi, &lo);
            check_sscanf_s_result(rc, 2);
            securec_check_intval(rc, (void)rc);
            report_msg->receive_status.sender_sent_location = (((uint64)hi) << 32) | lo;
            rc = sscanf_s(Getvalue(node_result, 0, 6), "%X/%X", &hi, &lo);
            check_sscanf_s_result(rc, 2);
            securec_check_intval(rc, (void)rc);
            report_msg->receive_status.sender_write_location = (((uint64)hi) << 32) | lo;
            rc = sscanf_s(Getvalue(node_result, 0, 7), "%X/%X", &hi, &lo);
            check_sscanf_s_result(rc, 2);
            securec_check_intval(rc, (void)rc);
            report_msg->receive_status.sender_flush_location = (((uint64)hi) << 32) | lo;
            rc = sscanf_s(Getvalue(node_result, 0, 8), "%X/%X", &hi, &lo);
            check_sscanf_s_result(rc, 2);
            securec_check_intval(rc, (void)rc);
            report_msg->receive_status.sender_replay_location = (((uint64)hi) << 32) | lo;
            rc = sscanf_s(Getvalue(node_result, 0, 9), "%X/%X", &hi, &lo);
            check_sscanf_s_result(rc, 2);
            securec_check_intval(rc, (void)rc);
            report_msg->receive_status.receiver_received_location = (((uint64)hi) << 32) | lo;
            rc = sscanf_s(Getvalue(node_result, 0, 10), "%X/%X", &hi, &lo);
            check_sscanf_s_result(rc, 2);
            securec_check_intval(rc, (void)rc);
            report_msg->receive_status.receiver_write_location = (((uint64)hi) << 32) | lo;
            rc = sscanf_s(Getvalue(node_result, 0, 11), "%X/%X", &hi, &lo);
            check_sscanf_s_result(rc, 2);
            securec_check_intval(rc, (void)rc);
            report_msg->receive_status.receiver_flush_location = (((uint64)hi) << 32) | lo;
            rc = sscanf_s(Getvalue(node_result, 0, 12), "%X/%X", &hi, &lo);
            check_sscanf_s_result(rc, 2);
            securec_check_intval(rc, (void)rc);
            report_msg->receive_status.receiver_replay_location = (((uint64)hi) << 32) | lo;
            rc = sscanf_s(Getvalue(node_result, 0, 13), "%d", &(report_msg->receive_status.sync_percent));
            check_sscanf_s_result(rc, 1);
            securec_check_intval(rc, (void)rc);
            if (report_msg->receive_status.local_role == INSTANCE_ROLE_CASCADE_STANDBY) {
                GetLpInfoByStr(Getvalue(node_result, 0, 14), lpInfo, g_currentNode->datanode[ii].datanodeId);
            }
        }
    } else {
        write_runlog(ERROR, "sqlCommands[4] fail ResultStatus=%d!\n", ResultStatus(node_result));
        CLEAR_AND_CLOSE_CONNECTION(node_result, g_dnConn[ii]);
    }
    Clear(node_result);
    return 0;
}


