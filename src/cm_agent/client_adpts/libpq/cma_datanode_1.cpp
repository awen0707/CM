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