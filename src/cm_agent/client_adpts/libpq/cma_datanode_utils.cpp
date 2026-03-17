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

void check_datanode_status_by_SQL5(uint32 instanceId, uint32 ii, const char *data_path)
{
    int maxRows = 0;
    int maxColums = 0;
    bool needClearResult = true;
    /* we neednot check the bad block during upgrading. */
    if (undocumentedVersion != 0) {
        return;
    }
    /* DN instance status check SQL 5 */
    const char* sqlCommands = "select pg_catalog.sum(error_count) from pg_stat_bad_block;";
    cltPqResult_t *node_result = Exec(g_dnConn[ii], sqlCommands);

    if (node_result == NULL) {
        write_runlog(ERROR, "sqlCommands[5] fail return NULL!\n");
        needClearResult = false;
    }
    if ((ResultStatus(node_result) == CLTPQRES_CMD_OK) || (ResultStatus(node_result) == CLTPQRES_TUPLES_OK)) {
        maxRows = Ntuples(node_result);
        if (maxRows == 0) {
            write_runlog(LOG, "sqlCommands[5] is 0\n");
        } else {
            int rc;
            maxColums = Nfields(node_result);
            if (maxColums != 1) {
                write_runlog(ERROR, "sqlCommands[5] fail  FAIL! col is %d\n", maxColums);
            }

            int tmpErrCount = 0;
            char* tmpErrCountValue = Getvalue(node_result, 0, 0);
            if (tmpErrCountValue != NULL) {
                tmpErrCount = CmAtoi(tmpErrCountValue, 0);
            }
            tmpErrCount = (tmpErrCount < 0) ? 0 : tmpErrCount;

            char instanceName[CM_NODE_NAME] = {0};
            rc = snprintf_s(
                instanceName, sizeof(instanceName), sizeof(instanceName) - 1, "%s_%u", "dn", instanceId);
            securec_check_intval(rc, (void)rc);

            /*
             * 1. tmpErrCount > g_errCountPgStatBadBlock[ii], have new bad block, make a alarm.
             * 2. tmpErrCount < g_errCountPgStatBadBlock[ii], the gaussdb may killed, restart or execute.
             * when this happen, check tmpErrCount !=0 (it means have new bad block after reset ), make a alarm.
             */
            if (((tmpErrCount - g_errCountPgStatBadBlock[ii]) >= 1) ||
                (((tmpErrCount - g_errCountPgStatBadBlock[ii]) < 0) && (tmpErrCount != 0))) {
                /* report the alarm. */
                report_dn_disk_alarm(ALM_AT_Fault, instanceName, (int)ii, data_path);
                write_runlog(WARNING, "pg_stat_bad_block error count is %d\n", tmpErrCount);
            } else {
                if (tmpErrCount == 0) {
                    report_dn_disk_alarm(ALM_AT_Resume, instanceName, (int)ii, data_path);
                }
            }

            g_errCountPgStatBadBlock[ii] = tmpErrCount;
        }
    } else {
        write_runlog(ERROR, "sqlCommands[5] fail  FAIL! Status=%d\n", ResultStatus(node_result));
    }
    if (needClearResult) {
        Clear(node_result);
    }
}

int check_datanode_status_by_SQL6(agent_to_cm_datanode_status_report* report_msg, uint32 ii, const char* data_path)
{
    int maxRows = 0;
    int maxColums = 0;
    /* DN instance status check SQL 6 */
    const char* sqlCommands =
        "SELECT redo_start_ptr, redo_start_time, redo_done_time, curr_time,"
        "min_recovery_point, read_ptr, last_replayed_read_ptr, recovery_done_ptr,"
        "read_xlog_io_counter, read_xlog_io_total_dur, read_data_io_counter, read_data_io_total_dur,"
        "write_data_io_counter, write_data_io_total_dur, process_pending_counter, process_pending_total_dur,"
        "apply_counter, apply_total_dur,speed, local_max_ptr, worker_info FROM local_redo_stat();";
    cltPqResult_t *node_result = Exec(g_dnConn[ii], sqlCommands);
    if (node_result == NULL) {
        write_runlog(ERROR, "sqlCommands[6] fail return NULL!\n");
        CLOSE_CONNECTION(g_dnConn[ii]);
    }
    if ((ResultStatus(node_result) == CLTPQRES_CMD_OK) || (ResultStatus(node_result) == CLTPQRES_TUPLES_OK)) {
        maxRows = Ntuples(node_result);
        if (maxRows == 0) {
            write_runlog(DEBUG5, "parallel redo status information is empty.\n");
        } else {
            int rc;

            maxColums = Nfields(node_result);
            report_msg->local_redo_stats.is_by_query = 1;
            fill_sql6_report_msg1(report_msg, node_result);
            fill_sql6_report_msg2(report_msg, node_result);
            report_msg->parallel_redo_status.speed_according_seg = 0xFFFFFFFF;

            rc = sscanf_s(Getvalue(node_result, 0, 19), "%lu", &(report_msg->parallel_redo_status.local_max_lsn));
            check_sscanf_s_result(rc, 1);
            securec_check_intval(rc, (void)rc);

            char* info = Getvalue(node_result, 0, 20);
            report_msg->parallel_redo_status.worker_info_len = (uint32)strlen(info);
            rc = memcpy_s(
                report_msg->parallel_redo_status.worker_info, REDO_WORKER_INFO_BUFFER_SIZE, info, strlen(info));
            securec_check_errno(rc, (void)rc);
        }
    } else {
        char redo_state_path[MAXPGPATH] = {0};
        int rcs = snprintf_s(redo_state_path, MAXPGPATH, MAXPGPATH - 1, "%s/redo.state", data_path);
        securec_check_intval(rcs, (void)rcs);
        check_input_for_security(redo_state_path);
        canonicalize_path(redo_state_path);
        check_parallel_redo_status_by_file(report_msg, redo_state_path);
        write_runlog(ERROR, "sqlCommands[6] fail  FAIL! Status=%d\n", ResultStatus(node_result));
        write_runlog(LOG, "read parallel redo status from redo.state file\n");
    }
    Clear(node_result);
    /* single node cluster does not need to continue executing. */
    if (g_single_node_cluster) {
        return 0;
    }
    /* DN instance status check SQL 6 */
    sqlCommands = "select disconn_mode, disconn_host, disconn_port, local_host, local_port, redo_finished from "
                  "read_disable_conn_file();";
    char* is_redo_finished = NULL;
    bool needClearResult = true;
    node_result = Exec(g_dnConn[ii], sqlCommands);
    if (node_result == NULL) {
        write_runlog(ERROR, "sqlCommands[6] fail return NULL!\n");
        needClearResult = false;
    }

    if ((ResultStatus(node_result) == CLTPQRES_CMD_OK) || (ResultStatus(node_result) == CLTPQRES_TUPLES_OK)) {
        maxRows = Nfields(node_result);
        if (maxRows == 0) {
            write_runlog(LOG, "sqlCommands[6] is 0\n");
            CLEAR_AND_CLOSE_CONNECTION(node_result, g_dnConn[ii]);
        } else {
            maxColums = Nfields(node_result);
            if (maxColums != 6) {
                write_runlog(ERROR, "sqlCommands[6] fail FAIL! col is %d\n", maxColums);
            }

            report_msg->local_status.disconn_mode = datanode_lockmode_string_to_int(Getvalue(node_result, 0, 0));
            errno_t rc = memset_s(report_msg->local_status.disconn_host, CM_IP_LENGTH, 0, CM_IP_LENGTH);
            securec_check_errno(rc, (void)rc);
            char *tmp_result = Getvalue(node_result, 0, 1);
            if (tmp_result != NULL && (strlen(tmp_result) > 0)) {
                rc = snprintf_s(report_msg->local_status.disconn_host,
                    CM_IP_LENGTH, CM_IP_LENGTH - 1, "%s", tmp_result);
                securec_check_intval(rc, (void)rc);
            }
            rc = sscanf_s(Getvalue(node_result, 0, 2), "%u", &(report_msg->local_status.disconn_port));
            check_sscanf_s_result(rc, 1);
            securec_check_intval(rc, (void)rc);
            rc = memset_s(report_msg->local_status.local_host, CM_IP_LENGTH, 0, CM_IP_LENGTH);
            securec_check_errno(rc, (void)rc);
            tmp_result = Getvalue(node_result, 0, 3);
            if (tmp_result != NULL && (strlen(tmp_result) > 0)) {
                rc = snprintf_s(report_msg->local_status.local_host,
                    CM_IP_LENGTH, CM_IP_LENGTH - 1, "%s", tmp_result);
                securec_check_intval(rc, (void)rc);
            }
            rc = sscanf_s(Getvalue(node_result, 0, 4), "%u", &(report_msg->local_status.local_port));
            check_sscanf_s_result(rc, 1);
            securec_check_intval(rc, (void)rc);
            is_redo_finished = Getvalue(node_result, 0, 5);
            if (strcmp(is_redo_finished, "true") == 0) {
                report_msg->local_status.redo_finished = true;
            } else {
                report_msg->local_status.redo_finished = false;
            }
        }
    } else {
        write_runlog(ERROR, "sqlCommands[6] fail  FAIL! Status=%d\n", ResultStatus(node_result));
    }
    if (needClearResult) {
        Clear(node_result);
    }
    return 0;
}

int check_flush_lsn_by_preparse(agent_to_cm_datanode_status_report* report_msg, uint32 dataNodeIndex)
{
    if (report_msg->local_status.local_role != INSTANCE_ROLE_STANDBY ||
        report_msg->local_status.disconn_mode == PROHIBIT_CONNECTION) {
        return 0;
    }

    cltPqResult_t *node_result = Exec(g_dnConn[dataNodeIndex],  "select preparse_end_location from gs_get_preparse_location();");

    if (node_result == NULL) {
        write_runlog(ERROR, "sqlCommands query preparse flush lsn fail return NULL!\n");
        CLOSE_CONNECTION(g_dnConn[dataNodeIndex]);
    }

    if ((ResultStatus(node_result) != CLTPQRES_CMD_OK) && (ResultStatus(node_result) != CLTPQRES_TUPLES_OK)) {
        write_runlog(ERROR, "sqlCommands query preparse flush lsn fail ResultStatus=%d!\n", ResultStatus(node_result));
        CLEAR_AND_CLOSE_CONNECTION(node_result, g_dnConn[dataNodeIndex]);
    }

    if (Ntuples(node_result) == 0) {
        write_runlog(DEBUG5, "No preparse flush lsn information available.\n");
        Clear(node_result);
        return 0;
    }  

    int maxColums = Nfields(node_result);
    if (maxColums != 1) {
        write_runlog(ERROR, "sqlCommands query preparse flush lsn fail! col is %d\n", maxColums);
        CLEAR_AND_CLOSE_CONNECTION(node_result, g_dnConn[dataNodeIndex]);
    }

    uint32 hi = 0;
    uint32 lo = 0;
    int rc = sscanf_s(Getvalue(node_result, 0, 0), "%X/%X", &hi, &lo);
    check_sscanf_s_result(rc, 2);
    securec_check_intval(rc, (void)rc);
    XLogRecPtr preparseLsn = (((uint64)hi) << 32) | lo;
    if (preparseLsn != InvalidXLogRecPtr) {
        report_msg->local_status.last_flush_lsn = preparseLsn;
        report_msg->local_status.disconn_mode = PRE_PROHIBIT_CONNECTION;
    }
    Clear(node_result);
    return 0;
}

int CheckDatanodeSyncList(uint32 instd, AgentToCmserverDnSyncList *syncListMsg, cltPqConn_t **curDnConn)
{
    int maxRows = 0;
    int maxColums = 0;
    const char *sqlCommands = "show synchronous_standby_names;";
    cltPqResult_t *nodeResult = Exec((*curDnConn), sqlCommands);
    if (nodeResult == NULL) {
        write_runlog(ERROR, "instd is %u, CheckDatanodeSyncList fail return NULL!\n", instd);
        CLOSE_CONNECTION((*curDnConn));
    }
    if ((ResultStatus(nodeResult) == CLTPQRES_CMD_OK) || (ResultStatus(nodeResult) == CLTPQRES_TUPLES_OK)) {
        maxRows = Ntuples(nodeResult);
        if (maxRows == 0) {
            write_runlog(ERROR, "instd is %u, synchronous_standby_names information is empty.\n", instd);
        } else {
            int rc;
            maxColums = Nfields(nodeResult);
            if (maxColums != 1) {
                write_runlog(ERROR, "instd is %u, CheckDatanodeSyncList fail! col is %d.\n", instd, maxColums);
                CLEAR_AND_CLOSE_CONNECTION(nodeResult, (*curDnConn));
            }
            char *result = Getvalue(nodeResult, 0, 0);
            if (result == NULL || strcmp(result, "") == 0) {
                write_runlog(ERROR, "instd is %u, synchronous_standby_names is empty.\n", instd);
                CLEAR_AND_CLOSE_CONNECTION(nodeResult, (*curDnConn));
            }
            rc = strcpy_s(syncListMsg->dnSynLists, DN_SYNC_LEN, result);
            securec_check_errno(rc, (void)rc);
            write_runlog(DEBUG1, "instd is %u, result=%s, len is %lu, report_msg->dnSynLists=%s.\n", instd, result,
                strlen(result), syncListMsg->dnSynLists);
        }
    } else {
        write_runlog(ERROR, "instd is %u, CheckDatanodeSyncList fail Status=%d!\n",
            instd, ResultStatus(nodeResult));
    }
    Clear(nodeResult);
    return 0;
}

int CheckDatanodeSyncCommit(uint32 instd, AgentToCmserverDnSyncAvailable *syncMsg, cltPqConn_t **curDnConn)
{
    int maxRows = 0;
    int maxColums = 0;
    const char *sqlCommands = "show synchronous_commit;";
    cltPqResult_t *nodeResult = Exec((*curDnConn), sqlCommands);
    if (nodeResult == NULL) {
        write_runlog(ERROR, "instd is %u, CheckDatanodeSyncCommit fail return NULL!\n", instd);
        CLOSE_CONNECTION((*curDnConn));
    }
    if ((ResultStatus(nodeResult) == CLTPQRES_CMD_OK) || (ResultStatus(nodeResult) == CLTPQRES_TUPLES_OK)) {
        maxRows = Ntuples(nodeResult);
        if (maxRows == 0) {
            write_runlog(ERROR, "instd is %u, synchronous_commit information is empty.\n", instd);
        } else {
            int rc;
            maxColums = Nfields(nodeResult);
            if (maxColums != 1) {
                write_runlog(ERROR, "instd is %u, CheckDatanodeSyncCommit fail! col is %d.\n", instd, maxColums);
                CLEAR_AND_CLOSE_CONNECTION(nodeResult, (*curDnConn));
            }
            char *result = Getvalue(nodeResult, 0, 0);
            if (result == NULL) {
                write_runlog(ERROR, "instd is %u, synchronous_commit is NULL.\n", instd);
                CLEAR_AND_CLOSE_CONNECTION(nodeResult, (*curDnConn));
            }
            rc = strcpy_s(syncMsg->syncCommit, DN_SYNC_LEN, result);
            securec_check_errno(rc, (void)rc);
            write_runlog(DEBUG1, "instd is %u, result=%s, len is %lu, report_msg->syncCommit=%s.\n", instd, result,
                strlen(result), syncMsg->syncCommit);
        }
    } else {
        write_runlog(ERROR, "instd is %u, CheckDatanodeSyncCommit fail Status=%d!\n",
            instd, ResultStatus(nodeResult));
    }
    Clear(nodeResult);
    return 0;
}

int CheckDatanodeCurSyncLists(uint32 instd, AgentToCmserverDnSyncAvailable *syncMsg, cltPqConn_t **curDnConn)
{
    int maxRows = 0;
    int maxColums = 0;
    const char *sqlCommands = "SELECT string_agg(substring(application_name FROM '\\[(.*?)\\]') , ',') "
        " FROM pg_stat_replication "
        " WHERE  state = 'Streaming' AND sync_state IN ('Sync', 'Quorum') ;";
    cltPqResult_t *nodeResult = Exec((*curDnConn), sqlCommands);
    if (nodeResult == NULL) {
        write_runlog(ERROR, "instd is %u, CheckDatanodeCurSyncLists fail return NULL!\n", instd);
        CLOSE_CONNECTION((*curDnConn));
    }
    if ((ResultStatus(nodeResult) == CLTPQRES_CMD_OK) || (ResultStatus(nodeResult) == CLTPQRES_TUPLES_OK)) {
        maxRows = Ntuples(nodeResult);
        if (maxRows == 0) {
            write_runlog(ERROR, "instd is %u, curSyncLists information is empty.\n", instd);
        } else {
            int rc;
            maxColums = Nfields(nodeResult);
            if (maxColums != 1) {
                write_runlog(ERROR, "instd is %u, CheckDatanodeCurSyncLists fail! col is %d.\n", instd, maxColums);
                CLEAR_AND_CLOSE_CONNECTION(nodeResult, (*curDnConn));
            }
            char *result = Getvalue(nodeResult, 0, 0);
            if (result == NULL) {
                write_runlog(ERROR, "instd is %u, curSyncLists is NULL.\n", instd);
                CLEAR_AND_CLOSE_CONNECTION(nodeResult, (*curDnConn));
            }
            rc = strcpy_s(syncMsg->dnSynLists, DN_SYNC_LEN, result);
            securec_check_errno(rc, (void)rc);
            write_runlog(DEBUG1, "instd is %u, result=%s, len is %lu, report_msg->dnSynLists=%s.\n", instd, result,
                strlen(result), syncMsg->dnSynLists);
        }
    } else {
        write_runlog(ERROR, "instd is %u, CheckDatanodeCurSyncLists fail Status=%d!\n",
            instd, ResultStatus(nodeResult));
    }
    Clear(nodeResult);
    return 0;
}

/* check whether query barrier id exists or not */
int StandbyClusterCheckQueryBarrierID(cltPqConn_t* &conn, AgentToCmBarrierStatusReport *barrierInfo)
{
    char *tmpResult = NULL;
    char queryBarrier[BARRIERLEN] = {0};
    char sqlCommand[MAX_PATH_LEN] = {0};

    errno_t rc = memcpy_s(queryBarrier, BARRIERLEN - 1, g_agentQueryBarrier, BARRIERLEN - 1);
    securec_check_errno(rc, (void)rc);
    if (queryBarrier[0] == '\0') {
        write_runlog(LOG, "query barrier is NULL when checking it's existance.\n");
        return 0;
    }
    if (strcmp(queryBarrier, g_agentTargetBarrier) == 0) {
        write_runlog(LOG, "The query barrier:%s  has been checked\n", g_agentQueryBarrier);
        rc = snprintf_s(barrierInfo->query_barrierId, BARRIERLEN, BARRIERLEN - 1, "%s", queryBarrier);
        securec_check_intval(rc, (void)rc);
        barrierInfo->is_barrier_exist = true;
        return 0;
    }
    rc = snprintf_s(sqlCommand, MAX_PATH_LEN, MAX_PATH_LEN - 1,
        "select pg_catalog.gs_query_standby_cluster_barrier_id_exist('%s');", queryBarrier);
    securec_check_intval(rc, (void)rc);
    cltPqResult_t *nodeResult = Exec(conn, sqlCommand);
    if (nodeResult == NULL) {
        write_runlog(ERROR, "sqlCommands query barrier: sqlCommands:%s, return NULL!\n", sqlCommand);
        CLOSE_CONNECTION(conn);
    }
    if ((ResultStatus(nodeResult) == CLTPQRES_CMD_OK) || (ResultStatus(nodeResult) == CLTPQRES_TUPLES_OK)) {
        int maxRows = Ntuples(nodeResult);
        if (maxRows == 0) {
            write_runlog(ERROR, "sqlCommands[8]: sqlCommands:%s, return 0!\n", sqlCommand);
            CLEAR_AND_CLOSE_CONNECTION(nodeResult, conn);
        } else {
            tmpResult = Getvalue(nodeResult, 0, 0);
            if (strcmp(tmpResult, "t") == 0) {
                barrierInfo->is_barrier_exist = true;
            }
            // query success, so we need update the query_barrierId
            rc = snprintf_s(barrierInfo->query_barrierId, BARRIERLEN, BARRIERLEN - 1, "%s", queryBarrier);
            securec_check_intval(rc, (void)rc);
        }
    } else {
        write_runlog(ERROR, "sqlCommands: sqlCommands:%s ResultStatus=%d!\n",
            sqlCommand, ResultStatus(nodeResult));
        CLEAR_AND_CLOSE_CONNECTION(nodeResult, conn);
    }
    write_runlog(LOG, "check_query_barrierID, val is %s, query barrier ID is %s, result is %s\n",
        queryBarrier, barrierInfo->query_barrierId, tmpResult);
    Clear(nodeResult);
    return 0;
}

int StandbyClusterSetTargetBarrierID(cltPqConn_t* &conn)
{
    int maxRows = 0;
    char *tmpResult = NULL;
    char targetBarrier[BARRIERLEN] = {0};
    char sqlCommand[MAX_PATH_LEN] = {0};
    int rc;
    // need locked
    rc = memcpy_s(targetBarrier, BARRIERLEN - 1, g_agentTargetBarrier, BARRIERLEN - 1);
    securec_check_errno(rc, (void)rc);
    if (targetBarrier[0] == '\0') {
        write_runlog(LOG, "target barrier is NULL when setting it.\n");
        return 0;
    }
    rc = snprintf_s(sqlCommand, MAX_PATH_LEN, MAX_PATH_LEN - 1,
        "select pg_catalog.gs_set_standby_cluster_target_barrier_id('%s');", targetBarrier);
    securec_check_intval(rc, (void)rc);
    cltPqResult_t *nodeResult = Exec(conn, sqlCommand);
    if (nodeResult == NULL) {
        write_runlog(ERROR, "sqlCommands set barrier: sqlCommands:%s, return NULL!\n", sqlCommand);
        CLOSE_CONNECTION(conn);
    }
    if ((ResultStatus(nodeResult) == CLTPQRES_CMD_OK) || (ResultStatus(nodeResult) == CLTPQRES_TUPLES_OK)) {
        maxRows = Ntuples(nodeResult);
        if (maxRows == 0) {
            write_runlog(ERROR, "sqlCommands set barrier: sqlCommands:%s, return 0!\n", sqlCommand);
            CLEAR_AND_CLOSE_CONNECTION(nodeResult, conn);
        } else {
            tmpResult = Getvalue(nodeResult, 0, 0);
            if (strncmp(tmpResult, targetBarrier, BARRIERLEN) != 0) {
                write_runlog(WARNING, "the return target barrier value %s is not euqal to set value %s\n",
                    tmpResult, targetBarrier);
            }
        }
    } else {
        write_runlog(ERROR, "sqlCommands set barrier: sqlCommands:%s ResultStatus=%d!\n",
            sqlCommand, ResultStatus(nodeResult));
        CLEAR_AND_CLOSE_CONNECTION(nodeResult, conn);
    }
    write_runlog(LOG, "set_tatget_barrierID, val is %s, set result is %s\n", targetBarrier, tmpResult);
    Clear(nodeResult);
    return 0;
}

int StandbyClusterGetBarrierInfo(cltPqConn_t* &conn, AgentToCmBarrierStatusReport *barrierInfo)
{
    int maxRows = 0;
    char* tmpResult = NULL;
    const char* sqlCommand = "select barrier_id from gs_get_standby_cluster_barrier_status();";
    cltPqResult_t *nodeResult = Exec(conn, sqlCommand);
    if (nodeResult == NULL) {
        write_runlog(ERROR, "StandbyClusterGetBarrierInfo sqlCommands: sqlCommands:%s, return NULL!\n", sqlCommand);
        CLOSE_CONNECTION(conn);
    }
    if ((ResultStatus(nodeResult) == CLTPQRES_CMD_OK) || (ResultStatus(nodeResult) == CLTPQRES_TUPLES_OK)) {
        maxRows = Ntuples(nodeResult);
        if (maxRows == 0) {
            write_runlog(ERROR, "StandbyClusterGetBarrierInfo sqlCommands: sqlCommands:%s, return 0!\n", sqlCommand);
            CLEAR_AND_CLOSE_CONNECTION(nodeResult, conn);
        } else {
            tmpResult = Getvalue(nodeResult, 0, 0);
            if (tmpResult != NULL && (strlen(tmpResult) > 0)) {
                int rc = snprintf_s(barrierInfo->barrierID, BARRIERLEN, BARRIERLEN - 1, "%s", tmpResult);
                securec_check_intval(rc, (void)rc);
            }
        }
    } else {
        write_runlog(ERROR, "StandbyClusterGetBarrierInfo sqlCommands: sqlCommands:%s ResultStatus=%d!\n",
            sqlCommand, ResultStatus(nodeResult));
        CLEAR_AND_CLOSE_CONNECTION(nodeResult, conn);
    }
    write_runlog(LOG, "StandbyClusterGetBarrierInfo, get barrier ID is %s\n", barrierInfo->barrierID);
    Clear(nodeResult);
    return 0;
}

int StandbyClusterCheckCnWaiting(cltPqConn_t* &conn)
{
    int maxRows = 0;
    char* tmpResult = NULL;
    char localBarrier[BARRIERLEN] = {0};
    const char* sqlCommand = "select barrier_id from gs_get_local_barrier_status();";
    cltPqResult_t *nodeResult = Exec(conn, sqlCommand);
    if (nodeResult == NULL) {
        write_runlog(ERROR, "StandbyClusterCheckCnWaiting sqlCommands: sqlCommands:%s, return NULL!\n", sqlCommand);
        CLOSE_CONNECTION(conn);
    }
    if ((ResultStatus(nodeResult) == CLTPQRES_CMD_OK) || (ResultStatus(nodeResult) == CLTPQRES_TUPLES_OK)) {
        maxRows = Ntuples(nodeResult);
        if (maxRows == 0) {
            write_runlog(ERROR, "StandbyClusterCheckCnWaiting sqlCommands: sqlCommands:%s, return 0!\n", sqlCommand);
            CLEAR_AND_CLOSE_CONNECTION(nodeResult, conn);
        } else {
            tmpResult = Getvalue(nodeResult, 0, 0);
            if (tmpResult != NULL && (strlen(tmpResult) > 0)) {
                int rc = snprintf_s(localBarrier, BARRIERLEN, BARRIERLEN - 1, "%s", tmpResult);
                securec_check_intval(rc, (void)rc);
            }
        }
    } else {
        write_runlog(ERROR, "StandbyClusterCheckCnWaiting sqlCommands: sqlCommands:%s ResultStatus=%d!\n",
            sqlCommand, ResultStatus(nodeResult));
        CLEAR_AND_CLOSE_CONNECTION(nodeResult, conn);
    }
    if (strlen(g_agentTargetBarrier) != 0 && strncmp(localBarrier, g_agentTargetBarrier, BARRIERLEN - 1) > 0) {
        write_runlog(LOG, "localBarrier %s is bigger than targetbarrier %s\n", localBarrier, g_agentTargetBarrier);
        g_cnWaiting = true;
    } else {
        g_cnWaiting = false;
    }
    write_runlog(LOG, "StandbyClusterCheckCnWaiting, get localbarrier is %s\n", localBarrier);
    Clear(nodeResult);
    return 0;
}

static status_t GetValueStrFromCJson(char *str, uint32 strLen, const cJSON *object, const char *infoKey)
{
    cJSON *objValue = cJSON_GetObjectItem(object, infoKey);
    if (!cJSON_IsString(objValue)) {
        write_runlog(ERROR, "(%s) object is not string.\n", infoKey);
        return CM_ERROR;
    }
    if (CM_IS_EMPTY_STR(objValue->valuestring)) {
        write_runlog(ERROR, "(%s) object is empty.\n", infoKey);
        return CM_ERROR;
    }

    if (str != NULL) {
        if (strlen(objValue->valuestring) >= strLen) {
            write_runlog(ERROR, "(%s):str(%s) is longer than max(%u).\n", infoKey, objValue->valuestring, strLen - 1);
            return CM_ERROR;
        }
        errno_t rc = strcpy_s(str, strLen, objValue->valuestring);
        securec_check_errno(rc, (void)rc);
        check_input_for_security(str);
    }

    return CM_SUCCESS;
}

static int ParseDcfConfigInfo(const char *tmpResult, char *role, uint32 roleLen)
{
    int ret = 0;
    int rc = 0;

    char jsonString[MAX_JSONSTR_LEN] = {0};
    rc = strncpy_s(jsonString, MAX_JSONSTR_LEN, tmpResult, MAX_JSONSTR_LEN - 1);
    securec_check_errno(rc, (void)rc);
    cJSON *object = cJSON_Parse(jsonString);

    status_t res = GetValueStrFromCJson(role, roleLen, object, "role");
    if (res !=  CM_SUCCESS) {
        ret = -1;
    }
    if (object != NULL) {
        cJSON_Delete(object);
    }
    return ret;
}

int SetDnRoleOnDcfMode(const cltPqResult_t *nodeResult)
{
    char dcfRole[MAX_ROLE_LEN] = {0};
    int role = DCF_ROLE_UNKNOWN;

    char *tmpResult = Getvalue(nodeResult, 0, 0);
    int res = ParseDcfConfigInfo((const char *)tmpResult, dcfRole, MAX_ROLE_LEN);
    if (res == -1) {
        role = DCF_ROLE_UNKNOWN;
        return role;
    }

    if (dcfRole != NULL && (strlen(dcfRole) > 0)) {
        if (strstr(dcfRole, RoleLeader) != NULL) {
            role = DCF_ROLE_LEADER;
        } else if (strstr(dcfRole, RoleFollower) != NULL) {
            role = DCF_ROLE_FOLLOWER;
        } else if (strstr(dcfRole, RolePassive) != NULL) {
            role = DCF_ROLE_PASSIVE;
        } else if (strstr(dcfRole, RoleLogger) != NULL) {
            role = DCF_ROLE_LOGGER;
        } else if (strstr(dcfRole, RolePrecandicate) != NULL) {
            role = DCF_ROLE_PRE_CANDIDATE;
        } else if (strstr(dcfRole, RoleCandicate) != NULL) {
            role = DCF_ROLE_CANDIDATE;
        } else {
            role = DCF_ROLE_UNKNOWN;
        }
    }

    return role;
}

int CheckDatanodeStatusBySqL10(agent_to_cm_datanode_status_report *reportMsg, uint32 ii)
{
    const char* sqlCommand = "SELECT dcf_replication_info from get_paxos_replication_info();";
    cltPqResult_t *nodeResult = Exec(g_dnConn[ii], sqlCommand);
    if (nodeResult == NULL) {
        write_runlog(ERROR, "sqlCommands[10]: sqlCommands:%s, return NULL!\n", sqlCommand);
        CLOSE_CONNECTION(g_dnConn[ii]);
    }

    if ((ResultStatus(nodeResult) == CLTPQRES_CMD_OK) || (ResultStatus(nodeResult) == CLTPQRES_TUPLES_OK)) {
        int maxRows = Ntuples(nodeResult);
        if (maxRows == 0) {
            write_runlog(ERROR, "dn_report_wrapper_1: sqlCommands:%s, return 0!\n", sqlCommand);
            CLEAR_AND_CLOSE_CONNECTION(nodeResult, g_dnConn[ii]);
        } else {
            reportMsg->receive_status.local_role = SetDnRoleOnDcfMode(nodeResult);
        }
    } else {
        write_runlog(ERROR, "cn_report_wrapper_1: sqlCommands:%s ResultStatus=%d!\n",
            sqlCommand, ResultStatus(nodeResult));
        CLEAR_AND_CLOSE_CONNECTION(nodeResult, g_dnConn[ii]);
    }

    Clear(nodeResult);
    return 0;
}

int cmagent_execute_query(cltPqConn_t* db_connection, const char* run_command)
{
    if (db_connection == NULL) {
        write_runlog(ERROR, "error, the connection to coordinator is NULL!\n");
        return -1;
    }

    cltPqResult_t *node_result = Exec(db_connection, run_command);
    if (node_result == NULL) {
        write_runlog(ERROR, "execute command(%s) return NULL!\n", run_command);
        return -1;
    }
    if ((ResultStatus(node_result) != CLTPQRES_CMD_OK) && (ResultStatus(node_result) != CLTPQRES_TUPLES_OK)) {
        if (ResHasError(node_result)) {
            write_runlog(ERROR, "execute command(%s) failed, errMsg is: %s!\n", run_command, GetResErrMsg(node_result));
        } else {
            write_runlog(ERROR, "execute command(%s) failed!\n", run_command);
        }

        Clear(node_result);
        return -1;
    }

    Clear(node_result);
    return 0;
}

int cmagent_execute_query_and_check_result(cltPqConn_t* db_connection, const char* run_command)
{
    if (db_connection == NULL) {
        write_runlog(ERROR, "error, the connection to coordinator is NULL!\n");
        return -1;
    }

    cltPqResult_t *node_result = Exec(db_connection, run_command);
    if (node_result == NULL) {
        write_runlog(ERROR, "execute command(%s) return NULL!\n", run_command);
        return -1;
    }
    if ((ResultStatus(node_result) != CLTPQRES_CMD_OK) && (ResultStatus(node_result) != CLTPQRES_TUPLES_OK)) {
        if (ResHasError(node_result)) {
            write_runlog(ERROR, "execute command(%s) failed, errMsg is: %s!\n", run_command, GetResErrMsg(node_result));
        } else {
            write_runlog(ERROR, "execute command(%s) failed!\n", run_command);
        }

        Clear(node_result);
        return -1;
    }
    char *res_s = Getvalue(node_result, 0, 0);
    write_runlog(LOG, "execute command(%s) result %s!\n", run_command, res_s);
    if (strcmp(res_s, "t") == 0) {
        Clear(node_result);
        return 0;
    } else if (strcmp(res_s, "f") == 0) {
        Clear(node_result);
        return -1;
    }
    Clear(node_result);
    return 0;
}

/*
 * get connection to coordinator and set statement timeout.
 */
int cmagent_to_coordinator_connect(const char* pid_path)
{
    if (pid_path == NULL) {
        return -1;
    }

    g_Conn = get_connection(pid_path, true, AGENT_CONN_DN_TIMEOUT);
    if (g_Conn == NULL) {
        write_runlog(ERROR, "get coordinate connect failed!\n");
        return -1;
    }

    if (!IsConnOk(g_Conn)) {
        write_runlog(ERROR, "connect is not ok, errmsg is %s!\n", ErrorMessage(g_Conn));
        CLOSE_CONNECTION(g_Conn);
    }

    cltPqResult_t *res = Exec(g_Conn, "SET statement_timeout = 10000000;");
    if (res == NULL) {
        write_runlog(ERROR, "cmagent_to_coordinator_connect: set command time out fail return NULL!\n");
        CLOSE_CONNECTION(g_Conn);
    }
    if ((ResultStatus(res) != CLTPQRES_CMD_OK) && (ResultStatus(res) != CLTPQRES_TUPLES_OK)) {
        write_runlog(ERROR, "cmagent_to_coordinator_connect: set command time out fail return FAIL!\n");
        CLEAR_AND_CLOSE_CONNECTION(res, g_Conn);
    }
    Clear(res);

    return 0;
}

uint32 find_cn_active_info_index(const agent_to_cm_coordinate_status_report_old* report_msg, uint32 coordinatorId)
{
    uint32 index;
    for (index = 0; index < max_cn_node_num_for_old_version; index++) {
        if (coordinatorId == report_msg->cn_active_info[index].cn_Id) {
            return index;
        }
    }
    write_runlog(ERROR, "find_cn_active_info_index: can not find cn %u\n", coordinatorId);
    return index;
}

/* before drop cn_xxx, we test wheather cn_xxx can be connected, if cn_xxx can be connected, do not drop it.
in the scene: cm_agent is down but cn_xxx is normal, cm_server can not receive status of cn_xxx from cm_agent,
so cm_server think cn_xxx is fault and drop it, but cn_xxx is running and status is normal, we should not drop it.
 */
int is_cn_connect_ok(uint32 coordinatorId)
{
    int test_result = 0;
    errno_t rc = 0;
    char connStr[MAXCONNINFO] = {0};

    for (uint32 i = 0; i < g_node_num; i++) {
        if (g_node[i].coordinateId == coordinatorId) {
            /* use HA port(coordinatePort+1) to connect CN */
            rc = snprintf_s(connStr,
                sizeof(connStr),
                sizeof(connStr) - 1,
                "dbname=postgres port=%u host='%s' connect_timeout=2 rw_timeout=3 application_name=%s "
                "options='-c xc_maintenance_mode=on'",
                g_node[i].coordinatePort + 1,
                g_node[i].coordinateListenIP[0],
                g_progname);
            securec_check_intval(rc, (void)rc);
            break;
        }
    }

    cltPqConn_t *test_cn_conn = Connect(connStr);
    if (test_cn_conn == NULL) {
        write_runlog(LOG, "[autodeletecn] connect to cn_%u failed, connStr: %s.\n", coordinatorId, connStr);
        test_result = -1;
    }
    if (!IsConnOk(test_cn_conn)) {
        write_runlog(LOG,
            "[autodeletecn] connect to cn_%u failed, PQstatus is not ok, connStr: %s, errmsg is %s.\n",
            coordinatorId,
            connStr,
            ErrorMessage(test_cn_conn));
        test_result = -1;
    }

    close_and_reset_connection(test_cn_conn);
    return test_result;
}

/* Covert the enum of Ha rebuild reason to int */
int datanode_rebuild_reason_enum_to_int(HaRebuildReason reason)
{
    switch (reason) {
        case NONE_REBUILD:
            return INSTANCE_HA_DATANODE_BUILD_REASON_NORMAL;
        case WALSEGMENT_REBUILD:
            return INSTANCE_HA_DATANODE_BUILD_REASON_WALSEGMENT_REMOVED;
        case CONNECT_REBUILD:
            return INSTANCE_HA_DATANODE_BUILD_REASON_DISCONNECT;
        case VERSION_REBUILD:
            return INSTANCE_HA_DATANODE_BUILD_REASON_VERSION_NOT_MATCHED;
        case MODE_REBUILD:
            return INSTANCE_HA_DATANODE_BUILD_REASON_MODE_NOT_MATCHED;
        case SYSTEMID_REBUILD:
            return INSTANCE_HA_DATANODE_BUILD_REASON_SYSTEMID_NOT_MATCHED;
        case TIMELINE_REBUILD:
            return INSTANCE_HA_DATANODE_BUILD_REASON_TIMELINE_NOT_MATCHED;
        default:
            break;
    }
    return INSTANCE_HA_DATANODE_BUILD_REASON_UNKNOWN;
}

cltPqConn_t* get_connection(const char* pid_path, bool isCoordinater, int connectTimeOut, const int32 rwTimeout)
{
    char** optlines;
    long pmpid;
    cltPqConn_t* dbConn = NULL;

    /* Try to read the postmaster.pid file */
    if ((optlines = CmReadfile(pid_path)) == NULL) {
        write_runlog(ERROR, "[%s: %d]: fail to read pid file (%s).\n", __FUNCTION__, __LINE__, pid_path);
        return NULL;
    }

    if (optlines[0] == NULL || /* optlines[0] means pid of datapath */
        optlines[1] == NULL || /* optlines[1] means datapath */
        optlines[2] == NULL || /* optlines[2] means start time */
        optlines[3] == NULL || /* optlines[3] means port */
        optlines[4] == NULL || /* optlines[4] means socket dir */
        optlines[5] == NULL) { /* optlines[5] means listen addr */
        /* File is exactly three lines, must be pre-9.1 */
        write_runlog(ERROR, " -w option is not supported when starting a pre-9.1 server\n");

        freefile(optlines);
        optlines = NULL;
        return NULL;
    }

    /* File is complete enough for us, parse it */
    pmpid = CmAtol(optlines[LOCK_FILE_LINE_PID - 1], 0);
    if (pmpid > 0) {
        /*
         * OK, seems to be a valid pidfile from our child.
         */
        int portnum;
        char host_str[MAXPGPATH] = {0};
        char local_conninfo[MAXCONNINFO] = {0};
        int rc;

        /*
         * Extract port number and host string to use.
         * We used to prefer unix domain socket.
         * With thread pool, we prefer tcp port and connect to cn/dn ha port
         * so that we do not need to be queued by thread pool controller.
         */
        portnum = CmAtoi(optlines[LOCK_FILE_LINE_PORT - 1], 0);
        char *sockdir = optlines[LOCK_FILE_LINE_SOCKET_DIR - 1];
        char *hostaddr = optlines[LOCK_FILE_LINE_LISTEN_ADDR - 1];
        if (hostaddr != NULL && hostaddr[0] != '\0' && hostaddr[0] != '\n') {
            rc = strncpy_s(host_str, sizeof(host_str), hostaddr, sizeof(host_str) - 1);
            securec_check_errno(rc, (void)rc);
        } else if (sockdir[0] == '/') {
            rc = strncpy_s(host_str, sizeof(host_str), sockdir, sizeof(host_str) - 1);
            securec_check_errno(rc, (void)rc);
        }

        /* remove trailing newline */
        char *cptr = strchr(host_str, '\n');
        if (cptr != NULL) {
            *cptr = '\0';
        }

        /* Fail if couldn't get either sockdir or host addr */
        if (host_str[0] == '\0') {
            write_runlog(ERROR, "option cannot use a relative socket directory specification\n");
            freefile(optlines);
            optlines = NULL;
            return NULL;
        }

        /* If postmaster is listening on "*", use localhost */
        if (strcmp(host_str, "*") == 0) {
            rc = strncpy_s(host_str, sizeof(host_str), "localhost", sizeof("localhost"));
            securec_check_errno(rc, (void)rc);
        }
        /* ha port equals normal port plus 1, required by om */
        if (isCoordinater) {
            rc = snprintf_s(local_conninfo,
                sizeof(local_conninfo),
                sizeof(local_conninfo) - 1,
                "dbname=postgres port=%d host='127.0.0.1' connect_timeout=%d rw_timeout=5 application_name=%s "
                "options='%s %s'",
                portnum + 1,
                connectTimeOut,
                g_progname,
                enable_xc_maintenance_mode ? "-c xc_maintenance_mode=on" : "",
                "-c remotetype=internaltool");
                securec_check_intval(rc, freefile(optlines));
        } else {
            rc = snprintf_s(local_conninfo,
                sizeof(local_conninfo),
                sizeof(local_conninfo) - 1,
                "dbname=postgres port=%d host='%s' connect_timeout=%d rw_timeout=%d application_name=%s "
                "options='%s %s'",
                portnum + 1,
                host_str,
                connectTimeOut,
                rwTimeout,
                g_progname,
                enable_xc_maintenance_mode ? "-c xc_maintenance_mode=on" : "",
                "-c remotetype=internaltool");
            securec_check_intval(rc, freefile(optlines));
        }

        write_runlog(DEBUG1, "cm agent connect cn/dn instance local_conninfo: %s\n", local_conninfo);

        dbConn = Connect(local_conninfo);
    }

    freefile(optlines);
    optlines = NULL;
    return dbConn;
}

#ifdef ENABLE_MULTIPLE_NODES
static cltPqConn_t* GetDnConnect(int index, const char *dbname)
{
    char** optlines;
    long pmpid;
    cltPqConn_t* dbConn = NULL;
    char pidPath[MAXPGPATH] = {0};
    int rcs = snprintf_s(pidPath, MAXPGPATH, MAXPGPATH - 1, "%s/postmaster.pid",
        g_currentNode->datanode[index].datanodeLocalDataPath);
    securec_check_intval(rcs, (void)rcs);

    /* Try to read the postmaster.pid file */
    if ((optlines = CmReadfile(pidPath)) == NULL) {
        write_runlog(ERROR, "[%s: %d]: fail to read pid file (%s).\n", __FUNCTION__, __LINE__, pidPath);
        return NULL;
    }

    if (optlines[0] == NULL || /* optlines[0] means pid of datapath */
        optlines[1] == NULL || /* optlines[1] means datapath */
        optlines[2] == NULL || /* optlines[2] means start time */
        optlines[3] == NULL || /* optlines[3] means port */
        optlines[4] == NULL || /* optlines[4] means socket dir */
        optlines[5] == NULL) { /* optlines[5] means listen addr */
        /* File is exactly three lines, must be pre-9.1 */
        write_runlog(ERROR, " -w option is not supported when starting a pre-9.1 server\n");

        freefile(optlines);
        optlines = NULL;
        return NULL;
    }

    /* File is complete enough for us, parse it */
    pmpid = CmAtol(optlines[LOCK_FILE_LINE_PID - 1], 0);
    if (pmpid > 0) {
        /*
         * OK, seems to be a valid pidfile from our child.
         */
        int portnum;
        char host_str[MAXPGPATH] = {0};
        char local_conninfo[MAXCONNINFO] = {0};
        int rc = 0;

        /*
         * Extract port number and host string to use.
         * We used to prefer unix domain socket.
         * With thread pool, we prefer tcp port and connect to cn/dn ha port
         * so that we do not need to be queued by thread pool controller.
         */
        portnum = CmAtoi(optlines[LOCK_FILE_LINE_PORT - 1], 0);
        char *sockdir = optlines[LOCK_FILE_LINE_SOCKET_DIR - 1];
        char *hostaddr = optlines[LOCK_FILE_LINE_LISTEN_ADDR - 1];

        if (hostaddr != NULL && hostaddr[0] != '\0' && hostaddr[0] != '\n') {
            rc = strncpy_s(host_str, sizeof(host_str), hostaddr, sizeof(host_str) - 1);
            securec_check_errno(rc, (void)rc);
        } else if (sockdir[0] == '/') {
            rc = strncpy_s(host_str, sizeof(host_str), sockdir, sizeof(host_str) - 1);
            securec_check_errno(rc, (void)rc);
        }

        /* remove trailing newline */
        char *cptr = strchr(host_str, '\n');
        if (cptr != NULL) {
            *cptr = '\0';
        }

        /* Fail if couldn't get either sockdir or host addr */
        if (host_str[0] == '\0') {
            write_runlog(ERROR, "[%s()][line:%d] option cannot use a relative socket directory specification\n",
                __FUNCTION__, __LINE__);
            freefile(optlines);
            optlines = NULL;
            return NULL;
        }

        /* If postmaster is listening on "*", use localhost */
        if (strcmp(host_str, "*") == 0) {
            rc = strncpy_s(host_str, sizeof(host_str), "localhost", sizeof("localhost"));
            securec_check_errno(rc, (void)rc);
        }
        rc = snprintf_s(local_conninfo,
            sizeof(local_conninfo),
            sizeof(local_conninfo) - 1,
            "dbname=%s port=%d host='%s' connect_timeout=5 rw_timeout=10 application_name=%s "
            "options='%s %s'",
            dbname,
            portnum + 1,
            host_str,
            g_progname,
            enable_xc_maintenance_mode ? "-c xc_maintenance_mode=on" : "",
            "-c remotetype=internaltool");
        securec_check_intval(rc, freefile(optlines));

        write_runlog(DEBUG1, "[%s()][line:%d] cm agent connect cn/dn instance local_conninfo: %s\n",
            __FUNCTION__, __LINE__, local_conninfo);

        dbConn = Connect(local_conninfo);
    }

    freefile(optlines);
    optlines = NULL;
    return dbConn;
}

static int GetDnDatabaseResult(cltPqConn_t* dnConn, const char* runCommand, char* databaseName)
{
    errno_t rcs = 0;

    write_runlog(DEBUG1, "[%s()][line:%d] runCommand = %s\n", __FUNCTION__, __LINE__, runCommand);

    cltPqResult_t *node_result = Exec(dnConn, runCommand);
    if (node_result == NULL) {
        write_runlog(ERROR, "[%s()][line:%d]  datanode check set command time out fail return NULL!\n",
            __FUNCTION__, __LINE__);
        return -1;
    }

    if ((ResultStatus(node_result) != CLTPQRES_CMD_OK) && (ResultStatus(node_result) != CLTPQRES_TUPLES_OK)) {
        if (ResHasError(node_result)) {
            write_runlog(ERROR, "[%s()][line:%d]  execute command(%s) is failed, errMsg is: %s!\n",
                __FUNCTION__, __LINE__, runCommand, GetResErrMsg(node_result));
        }
        Clear(node_result);
        return -1;
    }

    const int tuplesNum = Ntuples(static_cast<const cltPqResult_t*>(node_result));
    if (tuplesNum == 1) {
        rcs = strncpy_s(databaseName, NAMEDATALEN,
            Getvalue(static_cast<const cltPqResult_t*>(node_result), 0, 0), NAMEDATALEN - 1);
        securec_check_errno(rcs, (void)rcs);
        write_runlog(LOG, "[%s()][line:%d] databaseName:[%s]\n", __FUNCTION__, __LINE__, databaseName);
    } else {
        write_runlog(LOG, "[%s()][line:%d] check_datanode_status: sqlCommands result is %d\n",
            __FUNCTION__, __LINE__, tuplesNum);
    }
    Clear(node_result);
    return 0;
}

int GetDBTableFromSQL(int index, uint32 databaseId, uint32 tableId, uint32 tableIdSize,
                      DNDatabaseInfo *dnDatabaseInfo, int dnDatabaseCount, char* databaseName, char* tableName)
{
    char runCommand[CM_MAX_COMMAND_LONG_LEN] = {0};
    errno_t rc;
    int rcs = 0;

    if (dnDatabaseInfo == NULL) {
        write_runlog(ERROR, "[%s()][line:%d] dnDatabaseInfo is NULL!\n", __FUNCTION__, __LINE__);
        return -1;
    }

    if (dnDatabaseCount == 0) {
        write_runlog(ERROR, "[%s()][line:%d] dnDatabaseCount is 0!\n", __FUNCTION__, __LINE__);
        return -1;
    }
    write_runlog(DEBUG1, "[%s()][line:%d] database databaseId:%u\n", __FUNCTION__, __LINE__, databaseId);
    rc = memset_s(databaseName, NAMEDATALEN, 0, NAMEDATALEN);
    securec_check_errno(rc, (void)rc);
    for (int i = 0; i < dnDatabaseCount; i++) {
        write_runlog(DEBUG1, "[%s()][line:%d] oid:[%u] dbname:[%s]\n",
            __FUNCTION__, __LINE__, dnDatabaseInfo[i].oid, dnDatabaseInfo[i].dbname);
        if (databaseId == dnDatabaseInfo[i].oid) {
            rcs = strncpy_s(databaseName, NAMEDATALEN, dnDatabaseInfo[i].dbname, NAMEDATALEN - 1);
            securec_check_errno(rcs, (void)rcs);
            write_runlog(LOG, "[%s()][line:%d] databaseName:[%s]\n", __FUNCTION__, __LINE__, databaseName);
            break;
        }
    }
    write_runlog(LOG, "[%s()][line:%d] databaseName:%s tableId:%u tableIdSize:%u\n",
        __FUNCTION__, __LINE__, databaseName, tableId, tableIdSize);
    /* Get tablename from relfilenode */
    if (databaseName != NULL) {
        rc = memset_s(runCommand, CM_MAX_COMMAND_LONG_LEN, 0, CM_MAX_COMMAND_LONG_LEN);
        securec_check_errno(rc, (void)rc);
        rcs = snprintf_s(
            runCommand,
            CM_MAX_COMMAND_LONG_LEN,
            CM_MAX_COMMAND_LONG_LEN - 1,
            "select pg_catalog.get_large_table_name('%u', %u);",
            tableId,
            tableIdSize);
        securec_check_intval(rcs, (void)rcs);
        write_runlog(DEBUG1, "[%s()][line:%d] tablename runCommand:%s\n", __FUNCTION__, __LINE__, runCommand);
        
        cltPqConn_t* dnConn = GetDnConnect(index, databaseName);
        
        if (dnConn == NULL) {
            write_runlog(ERROR, "[%s()][line:%d]get coordinate connect failed!\n", __FUNCTION__, __LINE__);
            return -1;
        }

        if (!IsConnOk(dnConn)) {
            write_runlog(ERROR, "[%s()][line:%d]connect is not ok, errmsg is %s!\n",
                __FUNCTION__, __LINE__, ErrorMessage(dnConn));
            close_and_reset_connection(dnConn);
            return -1;
        }
        rcs = GetDnDatabaseResult(dnConn, runCommand, tableName);
        if (rcs < 0) {
            write_runlog(ERROR, "[%s()][line:%d] get dn tableName failed \n", __FUNCTION__, __LINE__);
        }
        close_and_reset_connection(dnConn);
    }
    return 0;
}
#endif

int GetAllDatabaseInfo(int index, DNDatabaseInfo **dnDatabaseInfo, int *dnDatabaseCount)
{
    char *dbname = NULL;
    int database_count;
    errno_t rc = 0;
    char postmaster_pid_path[MAXPGPATH] = {0};
    const char *STMT_GET_DATABASE_LIST = "SELECT DATNAME,OID FROM PG_DATABASE;";
    errno_t rcs = snprintf_s(postmaster_pid_path,
        MAXPGPATH, MAXPGPATH - 1, "%s/postmaster.pid", g_currentNode->datanode[index].datanodeLocalDataPath);
    securec_check_intval(rcs, (void)rcs);

    cltPqConn_t *dnConn = get_connection(postmaster_pid_path);
    if (dnConn == NULL) {
        write_runlog(ERROR, "[%s()][line:%d] get connect failed!\n", __FUNCTION__, __LINE__);
        return -1;
    }

    if (!IsConnOk(dnConn)) {
        write_runlog(ERROR, "[%s()][line:%d] get connect failed! PQstatus IS NOT OK, errmsg is %s\n",
            __FUNCTION__, __LINE__, ErrorMessage(dnConn));
        close_and_reset_connection(dnConn);
        return -1;
    }

    cltPqResult_t *node_result = Exec(dnConn, STMT_GET_DATABASE_LIST);
    if (node_result == NULL) {
        write_runlog(ERROR, "[%s()][line:%d] sqlCommands[0] fail return NULL!\n", __FUNCTION__, __LINE__);
        close_and_reset_connection(dnConn);
        return -1;
    }

    if ((ResultStatus(node_result) != CLTPQRES_CMD_OK) && (ResultStatus(node_result) != CLTPQRES_TUPLES_OK)) {
        if (ResHasError(node_result)) {
            write_runlog(ERROR, "[%s()][line:%d] execute command(%s) failed, errMsg is: %s!\n",
                __FUNCTION__, __LINE__, STMT_GET_DATABASE_LIST, GetResErrMsg(node_result));
        } else {
            write_runlog(ERROR, "[%s()][line:%d] execute command(%s) failed!\n",
                __FUNCTION__, __LINE__, STMT_GET_DATABASE_LIST);
        }
        Clear(node_result);
        close_and_reset_connection(dnConn);
        return -1;
    }

    database_count = Ntuples(node_result);
    if (!(database_count > 0)) {
        write_runlog(ERROR, "[%s()][line:%d] sqlCommands[1] is 0\n", __FUNCTION__, __LINE__);
        Clear(node_result);
        close_and_reset_connection(dnConn);
        return -1;
    }

    if (dnDatabaseCount == NULL) {
        write_runlog(ERROR, "[%s()][line:%d] dnDatabaseCount is NULL!\n", __FUNCTION__, __LINE__);
        Clear(node_result);
        close_and_reset_connection(dnConn);
        return -1;
    }
    *dnDatabaseCount = database_count;

    DNDatabaseInfo *localDnDBInfo = (DNDatabaseInfo *)malloc(sizeof(DNDatabaseInfo) * (size_t)database_count);
    if (localDnDBInfo == NULL) {
        write_runlog(ERROR, "[%s()][line:%d] g_dnDatabaseList malloc failed!\n", __FUNCTION__, __LINE__);
        Clear(node_result);
        close_and_reset_connection(dnConn);
        return -1;
    }
    rcs = memset_s(localDnDBInfo, sizeof(DNDatabaseInfo) * (size_t)database_count, 0,
                   sizeof(DNDatabaseInfo) * (size_t)database_count);
    securec_check_errno(rcs, FREE_AND_RESET(localDnDBInfo));

    for (int i = 0; i < database_count; i++) {
        dbname = Getvalue(node_result, i, 0);
        rc = strncpy_s(localDnDBInfo[i].dbname, NAMEDATALEN, dbname, NAMEDATALEN - 1);
        securec_check_errno(rc, (void)rc);
        rc = sscanf_s(Getvalue(node_result, i, 1), "%u", &(localDnDBInfo[i].oid));
        check_sscanf_s_result(rc, 1);
        securec_check_intval(rc, (void)rc);
    }

    *dnDatabaseInfo = localDnDBInfo;
    Clear(node_result);
    close_and_reset_connection(dnConn);
    return 0;
}

int CheckMostAvailableSync(uint32 index)
{
    int maxRows = 0;
    int maxColums = 0;
    const char *sqlCommands = "show most_available_sync;";
    cltPqResult_t *nodeResult = Exec(g_dnConn[index], sqlCommands);
    if (nodeResult == NULL) {
        write_runlog(ERROR, "CheckMostAvailableSync fail return NULL!\n");
        CLOSE_CONNECTION(g_dnConn[index]);
    }
    if ((ResultStatus(nodeResult) == CLTPQRES_CMD_OK) || (ResultStatus(nodeResult) == CLTPQRES_TUPLES_OK)) {
        maxRows = Ntuples(nodeResult);
        if (maxRows == 0) {
            write_runlog(ERROR, "most_available_sync information is empty.\n");
        } else {
            maxColums = Nfields(nodeResult);
            if (maxColums != 1) {
                write_runlog(ERROR, "CheckMostAvailableSync fail! col is %d.\n", maxColums);
                CLEAR_AND_CLOSE_CONNECTION(nodeResult, g_dnConn[index]);
            }
            char *result = Getvalue(nodeResult, 0, 0);
            write_runlog(DEBUG1, "CheckMostAvailableSync most_available_sync is %s.\n", result);
            if (strcmp(result, "on") == 0) {
                g_mostAvailableSync[index] = true;
            } else {
                g_mostAvailableSync[index] = false;
            }
        }
    } else {
        write_runlog(ERROR, "CheckMostAvailableSync fail Status=%d!\n", ResultStatus(nodeResult));
    }
    Clear(nodeResult);
    return 0;
}

void CheckTransactionReadOnly(cltPqConn_t* Conn, uint32 index, int instanceType)
{
    ReadOnlyState *readOnly;
    if (instanceType == INSTANCE_TYPE_DATANODE) {
        readOnly = &g_dnReadOnly[index];
    } else {
        readOnly = &g_cnReadOnly;
    }
    const char *sqlCommands = "show default_transaction_read_only;";
    cltPqResult_t *nodeResult = Exec(Conn, sqlCommands);
    if (nodeResult == NULL) {
        write_runlog(ERROR, "[%s] fail return NULL!\n", __FUNCTION__);
        return;
    }
    if ((ResultStatus(nodeResult) == CLTPQRES_CMD_OK) || (ResultStatus(nodeResult) == CLTPQRES_TUPLES_OK)) {
        int maxRows = Ntuples(nodeResult);
        if (maxRows == 0) {
            write_runlog(ERROR, "default_transaction_read_only information is empty.\n");
        } else {
            int maxColums = Nfields(nodeResult);
            if (maxColums != 1) {
                write_runlog(ERROR, "[%s] fail! col is %d.\n", __FUNCTION__, maxColums);
                Clear(nodeResult);
                return;
            }
            char *result = Getvalue(nodeResult, 0, 0);
            *readOnly = strcmp(result, "on") == 0 ? READ_ONLY_ON : READ_ONLY_OFF;
            if (*readOnly == READ_ONLY_ON) {
                write_runlog(LOG, "[%s] default_transaction_read_only is %s.\n", __FUNCTION__, result);
            }
            if (undocumentedVersion != 0) {
                *readOnly = READ_ONLY_OFF;
            }
        }
    } else {
        write_runlog(ERROR, "[%s] fail Status=%d!\n", __FUNCTION__, (int)ResultStatus(nodeResult));
    }
    Clear(nodeResult);
    return;
}

int32 CheckDnSyncDone(uint32 instd, AgentToCmserverDnSyncList *syncListMsg, cltPqConn_t **curDnConn)
{
    const char *sqlCommands = "select * from gs_write_term_log();";
    cltPqResult_t *nodeResult = Exec((*curDnConn), sqlCommands);
    if (nodeResult == NULL) {
        write_runlog(ERROR, "instd is %u, CheckDnSyncDone fail return NULL!\n", instd);
        CLOSE_CONNECTION((*curDnConn));
    }
    int32 st = 0;
    if ((ResultStatus(nodeResult) == CLTPQRES_CMD_OK) || (ResultStatus(nodeResult) == CLTPQRES_TUPLES_OK)) {
        int32 maxRows = Ntuples(nodeResult);
        if (maxRows == 0) {
            write_runlog(ERROR, "instd is %u, CheckDnSyncDone information is empty.\n", instd);
            st = -1;
        } else {
            int32 maxColums = Nfields(nodeResult);
            if (maxColums != 1) {
                write_runlog(ERROR, "instd is %u, CheckDnSyncDone fail! col is %d.\n", instd, maxColums);
                CLEAR_AND_CLOSE_CONNECTION(nodeResult, (*curDnConn));
            }
            char *result = Getvalue(nodeResult, 0, 0);
            write_runlog(DEBUG1, "instd is %u, CheckDnSyncDone result is %s.\n", instd, result);
            if (strcmp(result, "t") == 0) {
                syncListMsg->syncDone = SUCCESS_SYNC_DATA;
            } else {
                syncListMsg->syncDone = FAILED_SYNC_DATA;
                st = -1;
            }
        }
    } else {
        write_runlog(ERROR, "instd is %u, CheckDnSyncDone fail Status=%d!\n", instd, ResultStatus(nodeResult));
        syncListMsg->syncDone = FAILED_SYNC_DATA;
        st = -1;
    }
    Clear(nodeResult);
    return st;
}

int GetDnBackUpStatus(cltPqConn_t* &conn, AgentToCmBarrierStatusReport *barrierMsg)
{
    if (StandbyClusterGetBarrierInfo(conn, barrierMsg) != 0) {
        return -1;
    }
    if (StandbyClusterCheckQueryBarrierID(conn, barrierMsg) != 0) {
        return -1;
    }
    if (StandbyClusterSetTargetBarrierID(conn) != 0) {
        return -1;
    }
    return 0;
}

status_t GetDnBarrierConn(cltPqConn_t* &dnBarrierConn, int dnIdx)
{
    if (dnBarrierConn == NULL) {
        char *dataPath = g_currentNode->datanode[dnIdx].datanodeLocalDataPath;
        char pid_path[MAXPGPATH] = {0};
        errno_t rc = snprintf_s(pid_path, MAXPGPATH, MAXPGPATH - 1, "%s/postmaster.pid", dataPath);
        securec_check_intval(rc, (void)rc);
        dnBarrierConn = get_connection(pid_path, false, AGENT_CONN_DN_TIMEOUT);
        if (dnBarrierConn == NULL || (!IsConnOk(dnBarrierConn))) {
            write_runlog(ERROR, "instId(%u) failed to connect\n", g_currentNode->datanode[dnIdx].datanodeId);
            if (dnBarrierConn != NULL) {
                write_runlog(ERROR, "%u connection return errmsg : %s\n",
                    g_currentNode->datanode[dnIdx].datanodeId, ErrorMessage(dnBarrierConn));
                close_and_reset_connection(dnBarrierConn);
            }
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

// we use cn reportMsg when in single-node cluster
void InitDNBarrierMsg(AgentToCmBarrierStatusReport &barrierMsg, int dnIdx, CM_MessageType &barrierMsgType)
{
    barrierMsgType = MSG_AGENT_CM_DATANODE_INSTANCE_BARRIER;
    write_runlog(LOG, "Init barrier info, instanceId=%u\n", g_currentNode->datanode[dnIdx].datanodeId);
    barrierMsg.barrierID[0] = '\0';
    barrierMsg.msg_type = (int)MSG_AGENT_CM_DATANODE_INSTANCE_BARRIER;
    barrierMsg.node = g_currentNode->node;
    barrierMsg.instanceId = g_currentNode->datanode[dnIdx].datanodeId;
    barrierMsg.instanceType = INSTANCE_TYPE_DATANODE;
    barrierMsg.query_barrierId[0] = '\0';
    barrierMsg.is_barrier_exist = false;
}

void* DNBackupStatusCheckMain(void * arg)
{
    int i = *(int*)arg;
    pthread_t threadId = pthread_self();
    cltPqConn_t* dnBarrierConn = NULL;
    write_runlog(LOG, "dn(%d) backup status check thread start, threadid %lu.\n", i, threadId);

    for (;;) {
        if (g_shutdownRequest) {
            cm_sleep(5);
            continue;
        }
        AgentToCmBarrierStatusReport barrierMsg;
        CM_MessageType barrierMsgType;
        InitDNBarrierMsg(barrierMsg, i, barrierMsgType);

        status_t st = GetDnBarrierConn(dnBarrierConn, i);
        if (st != CM_SUCCESS) {
            cm_sleep(1);
            continue;
        }

        if (GetDnBackUpStatus(dnBarrierConn, &barrierMsg) != 0) {
            write_runlog(ERROR, "get backup barrier info failed, datanode:%u\n", g_currentNode->datanode[i].datanodeId);
            close_and_reset_connection(dnBarrierConn);
            cm_sleep(1);
            continue;
        }

        (void)pthread_rwlock_wrlock(&(g_dnReportMsg[i].lk_lock));
        errno_t rc = memcpy_s((void *)&(g_dnReportMsg[i].dnStatus.barrierMsg), sizeof(AgentToCmBarrierStatusReport),
            (void *)&barrierMsg, sizeof(AgentToCmBarrierStatusReport));
        securec_check_errno(rc, (void)rc);
        g_dnReportMsg[i].dnStatus.barrierMsgType = barrierMsgType;
        (void)pthread_rwlock_unlock(&(g_dnReportMsg[i].lk_lock));

        cm_sleep(1);
    }
}
