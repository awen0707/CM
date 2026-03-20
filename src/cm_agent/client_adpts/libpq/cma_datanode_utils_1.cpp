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
