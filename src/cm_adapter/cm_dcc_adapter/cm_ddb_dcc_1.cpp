
static void DrvDccFreeNodeInfo(void)
{
    return;
}

static void DrvNotifyDcc(DDB_ROLE dbRole)
{
    const char *str = "[DrvNotifyDcc]";
    write_runlog(LOG, "%s %d: receive notify msg, it will set prority, dbRole is [%d: %d], g_expectPriority is %u, "
        "g_cmServerNum is %u.\n", str, __LINE__, (int32)dbRole, (int32)g_dbRole, g_expectPriority, g_cmServerNum);
    if (g_dbRole != dbRole && g_cmServerNum > ONE_PRIMARY_ONE_STANDBY) {
        if (dbRole == DDB_ROLE_FOLLOWER) {
            g_expectPriority = DCC_MIN_PRIORITY;
            g_waitForChangeTime = g_waitForTime;
        } else if (dbRole == DDB_ROLE_LEADER) {
            g_expectPriority = DCC_MAX_PRIORITY;
            g_waitForChangeTime = g_waitForTime;
        }
        write_runlog(LOG, "%s receive notify msg, it has setted prority, dbRole is [%d: %d], g_expectPriority is %u, "
            "g_waitForChangeTime is %ld, g_waitForTime is %ld.\n", str, (int32)dbRole, (int32)g_dbRole,
            g_expectPriority, (long int)g_waitForChangeTime, (long int)g_waitForTime);
    }
    return;
}

static void DrvDccSetMinority(bool isMinority)
{
    return;
}

Alarm *DrvDccGetAlarm(int alarmIndex)
{
    return NULL;
}

static status_t DrvDccLeaderNodeId(NodeIdInfo *idInfo, const char *azName)
{
    uint32 instd = 0;
    int32 ret = srv_dcc_query_leader_info(&instd);
    if (ret != 0) {
        return CM_ERROR;
    }
    for (uint32 i = 0; i < g_cmServerNum; ++i) {
        if (g_dccInfo[i].nodeIdInfo.azName == NULL) {
            write_runlog(ERROR, "[DrvDccLeaderNodeId]: i=%u, azName is NULL.\n", i);
            return CM_ERROR;
        }
        if ((azName != NULL) && (strcmp(g_dccInfo[i].nodeIdInfo.azName, azName) != 0)) {
            continue;
        }
        if (g_dccInfo[i].nodeIdInfo.instd == instd) {
            idInfo->azName = g_dccInfo[i].nodeIdInfo.azName;
            idInfo->nodeId = g_dccInfo[i].nodeIdInfo.nodeId;
            return CM_SUCCESS;
        }
    }
    return CM_ERROR;
}

static status_t DrvDccRestConn(DrvCon_t sess, int32 timeOut)
{
    return CM_SUCCESS;
}

status_t DrvExecDccCmd(DrvCon_t session, char *cmdLine, char *output, int *outputLen, uint32 maxBufLen)
{
    int ret;
    errno_t rc;
    dcc_text_t cmdText = {0};
    dcc_text_t getText = {0};

    SetDccText(&cmdText, cmdLine, strlen(cmdLine));

    ret = srv_dcc_exec_cmd(session, &cmdText, &getText);
    if (ret != 0) {
        write_runlog(ERROR, "Failed to exec dcc cmd(%s), ret is %d.\n", cmdLine, ret);
        GetErrorMsg(NULL);
        return CM_ERROR;
    }

    if (output != NULL && getText.len != 0) {
        uint32 copyLen = getText.len;
        if (maxBufLen <= getText.len) {
            copyLen = maxBufLen - 1;
        }
        rc = memcpy_s(output, copyLen, getText.value, copyLen);
        securec_check_errno(rc, (void)rc);
        output[copyLen] = '\0';
    }

    if (outputLen != NULL) {
        *outputLen = static_cast<int>(getText.len);
    }

    if (g_cmServerNum != ONE_PRIMARY_ONE_STANDBY) {
        write_runlog(LOG, "Success to exec dcc cmd(%s).\n", cmdLine);
    } else {
        write_runlog(DEBUG5, "Success to exec dcc cmd(%s).\n", cmdLine);
    }

    return CM_SUCCESS;
}

static status_t DrvDccSetBlocked(unsigned int setBlock, unsigned int waitTimeoutMs)
{
    int ret;

    ret = srv_dcc_set_blocked(setBlock, waitTimeoutMs);
    if (ret != 0) {
        write_runlog(ERROR, "Failed to set blocked.\n");
        GetErrorMsg("Failed to set blocked");
        return CM_ERROR;
    }
    write_runlog(LOG, "Success to set blocked.\n");
    return CM_SUCCESS;
}

static bool IsFilterParameter(const char *key)
{
    if (g_invalidParmeter == NULL || key == NULL) {
        write_runlog(ERROR, "g_invalidParmeter is NULL, or key is NULL.\n");
        return false;
    }
    for (int32 i = 0; g_invalidParmeter[i] != NULL; ++i) {
        if (strncmp(key, g_invalidParmeter[i], strlen(g_invalidParmeter[i])) == 0) {
            return true;
        }
    }
    return false;
}

static status_t DrvDccSetParam(const char *key, const char *value)
{
    if (key == NULL || value == NULL) {
        write_runlog(ERROR, "failed to set dcc param, because key(%s) or value(%s) is null.\n", key, value);
        return CM_ERROR;
    }
    if (strlen(key) <= strlen("ddb_")) {
        write_runlog(ERROR, "this is not ddb parameter(key %s: value %s).\n", key, value);
        return CM_ERROR;
    }
    if (IsFilterParameter(key)) {
        write_runlog(WARNING, "key_value is [%s, %s], not need set param.\n", key, value);
        return CM_SUCCESS;
    }
    const char *dccKey = key + strlen("ddb_");
    int32 ret = srv_dcc_set_param(dccKey, value);
    if (ret != 0) {
        write_runlog(
            ERROR, "failed to set dcc param(key %s: value %s), error msg is %s.\n", dccKey, value, DrvDccLastError());
        return CM_ERROR;
    }
    write_runlog(LOG, "sucess to set param(key %s: value %s) to dcc.\n", dccKey, value);
    return CM_SUCCESS;
}

static void PrintDccInfo()
{
    char dccStr[DDB_MAX_KEY_VALUE_LEN] = {0};
    size_t dccSize = 0;
    errno_t rc = 0;
    for (uint32 ii = 0; ii < g_cmServerNum; ++ii) {
        dccSize = strlen(dccStr);
        if (dccSize >= (DDB_MAX_KEY_VALUE_LEN - 1)) {
            break;
        }
        rc = snprintf_s(dccStr + dccSize, (DDB_MAX_KEY_VALUE_LEN - dccSize), ((DDB_MAX_KEY_VALUE_LEN - 1) - dccSize),
            "%s:%u:%s:%u:%u:%s; ", g_dccInfo[ii].host, g_dccInfo[ii].port, g_dccInfo[ii].nodeInfo.nodeName,
            g_dccInfo[ii].nodeIdInfo.nodeId, g_dccInfo[ii].nodeIdInfo.instd, g_dccInfo[ii].nodeIdInfo.azName);
        securec_check_intval(rc, (void)rc);
    }
    write_runlog(LOG, "dccStr is %s.\n", dccStr);
}

static status_t InitDccInfo(const DrvApiInfo *apiInfo)
{
    g_cmServerNum = apiInfo->nodeNum;
    if (g_cmServerNum == 0) {
        write_runlog(ERROR, "g_cmServerNum is zero, failed to init dcc info.\n");
        return CM_ERROR;
    }
    size_t len = g_cmServerNum * sizeof(ServerSocket);
    g_dccInfo = (ServerSocket *)malloc(len);
    if (g_dccInfo == NULL) {
        write_runlog(ERROR, "g_dccInof is NULL.\n");
        return CM_ERROR;
    }
    errno_t rc = memset_s(g_dccInfo, len, 0, len);
    securec_check_errno(rc, FREE_AND_RESET(g_dccInfo));
    uint32 jj = 0;
    ServerSocket *srNode = NULL;
    for (uint32 ii = 0; ii < apiInfo->serverLen; ++ii) {
        if (jj >= g_cmServerNum) {
            break;
        }
        srNode = &apiInfo->serverList[ii];
        if (srNode->host == NULL || srNode->port == 0 || srNode->nodeInfo.nodeName == NULL ||
            srNode->nodeInfo.len == 0) {
            continue;
        }
        g_dccInfo[jj] = *srNode;
        ++jj;
    }
    if (jj == 0 || jj != g_cmServerNum) {
        write_runlog(ERROR, "%s :%d, failed to init dcc info, jj: %u, g_dccNum is %u.\n",
            __FUNCTION__, __LINE__, jj, g_cmServerNum);
        return CM_ERROR;
    }
    PrintDccInfo();
    return CM_SUCCESS;
}

static int32 SetPriority(uint32 priority)
{
    int32 ret = srv_dcc_set_election_priority((unsigned long long)priority);
    write_runlog(LOG, "will set ELECTION_PRIORITY, and value is %u, ret is %d.\n", priority, ret);
    if (ret != 0) {
        write_runlog(ERROR, "set PRIORITY failed, error msg is %s.\n", DrvDccLastError());
    }
    return ret;
}

static int32 CheckDccLeader()
{
    uint32 instd = 0;
    int32 ret = srv_dcc_query_leader_info(&instd);
    write_runlog(
        LOG, "get dcc leader (%u), curNode is %u, ret is %d.\n", instd, g_dccInfo[g_curIdx].nodeIdInfo.instd, ret);
    if (ret != 0) {
        return CANNOT_FIND_DCC_LEAD;
    }
    if (instd == g_dccInfo[g_curIdx].nodeIdInfo.instd) {
        return LEAD_IS_CURRENT_INSTANCE;
    }
    return CAN_FIND_DCC_LEAD;
}

static bool CheckDccDemote()
{
    if (g_expectPriority != DCC_MIN_PRIORITY) {
        return false;
    }
    int32 ret = 0;
    if (g_dbRole == DDB_ROLE_LEADER) {
        ret = SetPriority(g_expectPriority);
        ret = srv_dcc_demote_follower();
        (void)DccRoleToDdbRole(DCC_ROLE_FOLLOWER);
        write_runlog(LOG, "[CheckDccDemote] dcc will demote follower, ret is %d.\n", ret);
        if (ret != 0) {
            write_runlog(ERROR, "[CheckDccDemote] dcc failed to demote follower, error msg is %s.\n",
                DrvDccLastError());
        }
        return true;
    }
    if (CheckDccLeader() != CAN_FIND_DCC_LEAD) {
        return true;
    }
    // wait for all cms can be promoted, in order to prevent two-cms turn.
    if (g_waitForChangeTime > 0) {
        write_runlog(DEBUG1, "[CheckDccDemote] g_waitForChangeTime is %ld, cannot reset g_expectPriority.\n",
            (long int)g_waitForChangeTime);
        return true;
    }
    write_runlog(LOG, "[CheckDccDemote] line %s:%d, will reset g_expectPriority from %u to %u.\n",
        __FUNCTION__, __LINE__, g_expectPriority, DCC_AVG_PRIORITY);
    g_expectPriority = DCC_AVG_PRIORITY;
    return false;
}

static bool CheckDccPromote()
{
    if (g_expectPriority != DCC_MAX_PRIORITY) {
        return false;
    }
    if (g_dbRole != DDB_ROLE_LEADER) {
        if (CheckDccLeader() == CANNOT_FIND_DCC_LEAD) {
            return true;
        }
        int32 ret = SetPriority(g_expectPriority);
        write_runlog(LOG, "[CheckDccPromote] line %s:%d set priority(%u), ret is %d.\n", __FUNCTION__, __LINE__,
            g_expectPriority, ret);
        ret = srv_dcc_promote_leader(g_dccInfo[g_curIdx].nodeIdInfo.instd, PROMOTE_LEADER_TIME);
        if (ret != 0) {
            write_runlog(ERROR, "[CheckDccPromote] failed to set dcc promote leader, error msg is %s.\n",
                DrvDccLastError());
        }
        return true;
    }
    if (g_waitForChangeTime > 0) {
        write_runlog(DEBUG1, "[CheckDccDemote] g_waitForChangeTime is %ld, cannot reset g_expectPriority.\n",
            (long int)g_waitForChangeTime);
        return true;
    }
    write_runlog(LOG, "[CheckDccPromote] line %s:%d, will reset g_expectPriority from %u to %u.\n",
        __FUNCTION__, __LINE__, g_expectPriority, DCC_AVG_PRIORITY);
    g_expectPriority = DCC_AVG_PRIORITY;
    return false;
}

static uint32 GetCurPriority()
{
    bool res = false;
    if (g_expectPriority != DCC_AVG_PRIORITY) {
        write_runlog(LOG, "g_expectPriority is %u, g_dbRole is %d.\n", g_expectPriority, g_dbRole);
        res = CheckDccDemote();
        if (res) {
            return DCC_MIN_PRIORITY;
        }
        res = CheckDccPromote();
        if (res) {
            return DCC_MAX_PRIORITY;
        }
    }
    return DCC_AVG_PRIORITY;
}

bool CheckSetPriority(uint32 *lastPrio, uint32 *curPriority, int32 ret)
{
    if (ret != 0) {
        return true;
    }
    (*curPriority) = GetCurPriority();
    if ((*curPriority) == (*lastPrio)) {
        return false;
    }
    *lastPrio = (*curPriority);
    return true;
}

void *SetPriorityMain(void *arg)
{
    thread_name = "DCC_SET";
    write_runlog(LOG, "Starting DCC SET priority thread.\n");
    int32 ret = 0;
    uint32 curPriority = 0;
    uint32 lastPrority = 0;
    bool isNeedSet = false;
    for (;;) {
        isNeedSet = CheckSetPriority(&lastPrority, &curPriority, ret);
        if (isNeedSet) {
            ret = SetPriority(curPriority);
        }
        write_runlog(DEBUG1, "prority is [%u/%u], isNeedSet is %d, g_dbRole is %d.\n", lastPrority, g_expectPriority,
            isNeedSet, g_dbRole);
        (void)sleep(1);
    }
    return NULL;
}

static status_t CreateSetPriorityThread()
{
    pthread_t thrId;
    int32 res = pthread_create(&thrId, NULL, SetPriorityMain, NULL);
    if (res != 0) {
        write_runlog(ERROR, "Failed to create SetPriorityMain.\n");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

void *DccMonitorMain(void *argp)
{
    thread_name = "DCC_MONITOR";
    write_runlog(LOG, "Starting DCC monitor thread.\n");
    for (;;) {
        if (g_waitForChangeTime > 0) {
            --g_waitForChangeTime;
        }
        (void)sleep(1);
    }
    return NULL;
}

static status_t CreateMonitorThread()
{
    pthread_t thrId;
    int32 res = pthread_create(&thrId, NULL, DccMonitorMain, NULL);
    if (res != 0) {
        write_runlog(ERROR, "Failed to create DccMonitorMain.\n");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t CreateDccThread(const DrvApiInfo *apiInfo)
{
    if (g_cmServerNum <= ONE_PRIMARY_ONE_STANDBY) {
        write_runlog(LOG, "this cmServer is %u, cannot CreateSetPriorityThread.\n", g_cmServerNum);
        return CM_SUCCESS;
    }
    status_t st = CreateMonitorThread();
    if (st != CM_SUCCESS) {
        return CM_ERROR;
    }
    st = CreateSetPriorityThread();
    return st;
}

static status_t GetCurNodeIdx(const DrvApiInfo *apiInfo)
{
    for (uint32 i = 0; i < g_cmServerNum; ++i) {
        if (g_dccInfo[i].nodeIdInfo.nodeId == apiInfo->nodeId) {
            g_curIdx = (int32)i;
            break;
        }
    }
    write_runlog(LOG, "get curidx(%d) from server.\n", g_curIdx);
    if (g_curIdx == -1) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t InitDccInfoAndCreateThread(const DrvApiInfo *apiInfo)
{
    status_t st = InitDccInfo(apiInfo);
    CM_RETURN_IFERR(st);
    if (apiInfo->timeOut < 0) {
        write_runlog(ERROR, "timeout(%d) is invalid.\n", apiInfo->timeOut);
        return CM_ERROR;
    }
    const int32 toSec = 1000;
    if (apiInfo->timeOut < toSec) {
        g_timeOut = 1;
    } else {
        g_timeOut = (uint32)(apiInfo->timeOut / toSec);
    }
    st = GetCurNodeIdx(apiInfo);
    CM_RETURN_IFERR(st);
    g_waitForTime = apiInfo->server_t.waitTime;
    st = CreateDccThread(apiInfo);
    return st;
}

static status_t DrvDccStop(bool *ddbStop)
{
    int32 ret = srv_dcc_stop();
    write_runlog(LOG, "dcc has stopped, and ret is %d.\n", ret);
    if (ret == 0) {
        *ddbStop = true;
        return CM_SUCCESS;
    }
    return CM_ERROR;
}

status_t DrvDccSetWorkMode(DrvCon_t session, unsigned int workMode, unsigned int voteNum)
{
    int32 res = 0;
    res = srv_dcc_set_work_mode((dcc_work_mode_t)workMode, voteNum);
    if (res != CM_SUCCESS) {
        write_runlog(ERROR, "set work mode failed. %d \n", res);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t DrvDccDemoteDdbRole(DrvCon_t session)
{
    int32 res = 0;
    res = srv_dcc_demote_follower();
    if (res != CM_SUCCESS) {
        write_runlog(ERROR, "dcc demote follower failed. %d \n", res);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t DccLoadApi(const DrvApiInfo *apiInfo)
{
    DdbDriver *drv = DrvDccGet();
    drv->allocConn = DrvDccAllocConn;
    drv->freeConn = DrvDccFreeConn;
    drv->getValue = DrvDccGetValue;
    drv->getAllKV = DrvDccGetAllKV;
    drv->saveAllKV = DrvDccSaveAllKV;
    drv->setKV = DrvDccSetKV;
    drv->delKV = DrvDccDelKV;
    drv->drvNodeState = DrvDccNodeState;
    drv->lastError = DrvDccLastError;

    drv->isHealth = IsDrvDccHeal;
    drv->freeNodeInfo = DrvDccFreeNodeInfo;
    drv->notifyDdb = DrvNotifyDcc;
    drv->setMinority = DrvDccSetMinority;
    drv->getAlarm = DrvDccGetAlarm;
    drv->leaderNodeId = DrvDccLeaderNodeId;
    drv->restConn = DrvDccRestConn;
    drv->execCmd = DrvExecDccCmd;
    drv->setBlocked = DrvDccSetBlocked;
    drv->setParam = DrvDccSetParam;
    drv->stop = DrvDccStop;
    drv->setWorkMode = DrvDccSetWorkMode;
    drv->demoteDdbRole = DrvDccDemoteDdbRole;
    g_cmServerNum = apiInfo->nodeNum;
    status_t st = StartDccProcess(apiInfo);
    if (st != CM_SUCCESS) {
        return CM_ERROR;
    }
    st = InitDccInfoAndCreateThread(apiInfo);
    return st;
}

DdbDriver *DrvDccGet(void)
{
    return &g_drvDcc;
}