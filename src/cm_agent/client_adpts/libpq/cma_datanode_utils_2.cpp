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
