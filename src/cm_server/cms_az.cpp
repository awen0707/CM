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
 * cms_az.cpp
 *    cms az functions
 *
 * IDENTIFICATION
 *    src/cm_server/cms_az.cpp
 *
 * -------------------------------------------------------------------------
 */
#include "cm/cm_elog.h"
#include "cms_global_params.h"
#include "cms_ddb.h"
#include "cms_process_messages.h"
#include "cms_common.h"
#include "cms_az.h"
#include "cm_ip.h"

static uint32 GetCurrentAZnodeNum(const char *azName);
static void StartOrStopInstanceByCommand(OperateType operateType, uint32 node, const char *instanceDataPath,
    int32 timeOut = 0);
static bool IsCnDeleted(uint32 nodeId);
static void DoMultiAzStartDecision(
    bool isLeaf1AZConnectOK, const char *leaf1AzName, bool isLeaf2AZConnectOK, const char *leaf2AzName);
static void DoMultiAzStopDecision(bool isLeaf1AZConnectOK, const char *leaf1AzName, bool isLeaf2AZConnectOK,
    const char *leaf2AzName, bool isCmsConnectOK);
static bool SetIsolatedAzToDdb(const char *disconAzName, const char *conAzName);
static void DdbKeyOfAzConnectStatus(
    const char *azName, char *azConnectStatusKey, uint32 keyLen, const char *peerAzName);
static bool SetOrGetDdbKeyValueOfAzConnectStatus(
    DdbOperateType ddbOperateType, const char *key, int value, bool *operResult);
static void StartCmsNodeInstances(bool isLeaf1AZConnectOK, bool isLeaf2AZConnectOK);
static void CleanMultiConnState(const char *azName1, const char *azName2);

DdbConn g_dbConn = {0};
const int32 TRY_TIMES = 3;
const int DELAY_TIME_TO_AUTO_SWITCHOVER = 3;

az_role_string az_role_map_string[] = {{"AZ1", AZMaster}, {"AZ2", AZSlave}, {"AZ3", AZArbiter}};

/**
 * @brief Set the Stop Az Flag To Ddb object
 *
 * @param  azRole           My Param doc
 * @param  stopFlag         My Param doc
 * @return true
 * @return false
 */
bool SetStopAzFlagToDdb(AZRole azRole, bool stopFlag)
{
    char status_key[MAX_PATH_LEN] = {0};
    char value[DDB_MIN_VALUE_LEN] = {0};

    int rc = snprintf_s(status_key,
        MAX_PATH_LEN,
        MAX_PATH_LEN - 1,
        "/%s/CMServer/StopAz/%s",
        pw->pw_name,
        az_role_map_string[azRole].role_string);
    securec_check_intval(rc, (void)rc);

    rc = snprintf_s(value, DDB_MIN_VALUE_LEN, DDB_MIN_VALUE_LEN - 1, "%d", (int)stopFlag);
    securec_check_intval(rc, (void)rc);

    int tryTimes = 3;
    DdbConn ddbConn = g_dbConn;
    status_t st = CM_SUCCESS;
    do {
        st = SetKVWithConn(&ddbConn, status_key, MAX_PATH_LEN, value, DDB_MIN_VALUE_LEN);
        if (st != CM_SUCCESS) {
            write_runlog(ERROR, "Ddb set failed. key=%s, value=%s.\n", status_key, value);
            cm_sleep(1);
        }
        tryTimes--;
    } while (st != CM_SUCCESS && tryTimes > 0);

    write_runlog(LOG, "Ddb set key=%s, value=%s, result=%d.\n", status_key, value, st);
    return (st == CM_SUCCESS);
}

/**
 * @brief Get the Stop Az Flag From Ddb object
 *
 * @param  azRole           My Param doc
 * @return true
 * @return false
 */
bool GetStopAzFlagFromDdb(AZRole azRole)
{
    int rc;
    char status_key[MAX_PATH_LEN] = {0};
    char value[DDB_MIN_VALUE_LEN] = {0};

    rc = snprintf_s(status_key, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/CMServer/StopAz/%s",
        pw->pw_name, az_role_map_string[azRole].role_string);
    securec_check_intval(rc, (void)rc);
    DdbOption option = {SUCCESS_GET_VALUE, DEBUG1};
    int32 tryTimes = TRY_TIMES;
    status_t st = CM_SUCCESS;
    static DDB_RESULT lastDdbResult = SUCCESS_GET_VALUE;
    int32 logLevel = DEBUG1;
    do {
        st = GetKVConAndLog(&g_dbConn, status_key, value, DDB_MIN_VALUE_LEN, &option);
        if (option.ddbResult != lastDdbResult) {
            lastDdbResult = option.ddbResult;
            logLevel = LOG;
        }
        if (option.ddbResult == CAN_NOT_FIND_THE_KEY) {
            write_runlog(logLevel, "get stop az(%s) flag from Ddb, message is: %d\n",
                status_key, (int)option.ddbResult);
            break;
        }
        if (st != CM_SUCCESS) {
            cm_sleep(1);
            --tryTimes;
        }
    } while (st != CM_SUCCESS && tryTimes > 0);
    if (st != CM_SUCCESS) {
        logLevel = (option.ddbResult == CAN_NOT_FIND_THE_KEY) ? DEBUG1 : LOG;
        write_runlog(logLevel, "get stop az(%s) flag from Ddb: %d\n", status_key, (int)option.ddbResult);
        return false;
    }

    if (strtol(value, NULL, 10) == 1) {
        return true;
    }
    return false;
}

/**
 * @brief
 *
 * @param  azPriority       My Param doc
 * @param  azRole           My Param doc
 * @return true
 * @return false
 */
bool isAZPrioritySatisfyAZRole(uint32 azPriority, AZRole azRole)
{
    bool result = false;
    switch (azRole) {
        case AZMaster:
            result = (azPriority >= g_az_master && azPriority < g_az_slave);
            break;
        case AZSlave:
            result = (azPriority >= g_az_slave && azPriority < g_az_arbiter);
            break;
        case AZArbiter:
            result = (azPriority >= g_az_arbiter);
            break;
        default:
            break;
    }

    return result;
}

/**
 * @brief Get the Node Index By Az Role object
 *
 * @param  azRole           My Param doc
 * @return int
 */
int GetNodeIndexByAzRole(AZRole azRole)
{
    uint32 node_index;
    for (node_index = 0; node_index < g_node_num; node_index++) {
        if (isAZPrioritySatisfyAZRole(g_node[node_index].azPriority, azRole)) {
            break;
        }
    }
    if (node_index == g_node_num) {
        write_runlog(ERROR, "can not get node for az%d.\n", (azRole + 1));
        return -1;
    }
    return (int)node_index;
}

/**
 * @brief
 *
 * @param  azRole           My Param doc
 */
void StartAZ(AZRole azRole)
{
    char startAzCmd[MAX_PATH_LEN] = {0};
    int node_index = GetNodeIndexByAzRole(azRole);
    if (node_index == -1) {
        write_runlog(ERROR, "StartAZ: can not get node for az%d.\n", (azRole + 1));
        return;
    }

    int rc = snprintf_s(startAzCmd, MAX_PATH_LEN, MAX_PATH_LEN - 1,
        "nohup cm_ctl start -z %s > /dev/null 2>&1 &",
        g_node[node_index].azName);
    securec_check_intval(rc, (void)rc);

    rc = system(startAzCmd);
    if (rc != 0) {
        write_runlog(ERROR, "StartAZ failed: %s, errnum=%d, errno=%d.\n", startAzCmd, rc, errno);
    } else {
        write_runlog(LOG, "StartAZ success: %s.\n", startAzCmd);
    }
}

/**
 * @brief
 *
 * @param  ArbiterAZIp      My Param doc
 * @param  azRole           My Param doc
 */
void StopAZ(const char *ArbiterAZIp, AZRole azRole)
{
    char stopAzCmd[MAX_PATH_LEN] = {0};
    int node_index = GetNodeIndexByAzRole(azRole);
    if (node_index == -1) {
        write_runlog(ERROR, "StopAZ: can not get node for az%d.\n", (azRole + 1));
        return;
    }

    int rc = snprintf_s(stopAzCmd, MAX_PATH_LEN, MAX_PATH_LEN - 1,
        "pssh %s -s -H %s \"nohup cm_ctl stop -z %s > /dev/null 2>&1 &\" ",
        PSSH_TIMEOUT, ArbiterAZIp, g_node[node_index].azName);
    securec_check_intval(rc, (void)rc);

    rc = system(stopAzCmd);
    if (rc != 0) {
        write_runlog(ERROR, "StopAZ failed: %s, errnum=%d, errno=%d.\n", stopAzCmd, rc, errno);
    } else {
        write_runlog(LOG, "StopAZ success: %s.\n", stopAzCmd);
    }
}

/**
 * @brief
 *
 * @param  sshIp            My Param doc
 * @param  azRole           My Param doc
 * @return true
 * @return false
 */
bool doPingAzNodes(const char *sshIp, AZRole azRole)
{
    uint32 i = 0;
    char pingCommand[CM_MAX_COMMAND_LEN] = {0};
    int rc = 0;
    int tryTimes = AZ1_AZ2_CONNECT_PING_TRY_TIMES;
    do {
        for (i = 0; i < g_node_num; i++) {
            if (isAZPrioritySatisfyAZRole(g_node[i].azPriority, azRole)) {
                const char *pingStr = GetPingStr(GetIpVersion(g_node[i].cmAgentIP[0]));
                if (sshIp != NULL) {
                    rc = snprintf_s(pingCommand, CM_MAX_COMMAND_LEN, CM_MAX_COMMAND_LEN - 1,
                        "pssh %s -s -H %s \"%s %s %s\" ",
                        PSSH_TIMEOUT, sshIp, pingStr, g_node[i].cmAgentIP[0], PING_TIMEOUT_OPTION);
                } else {
                    rc = snprintf_s(pingCommand, CM_MAX_COMMAND_LEN, CM_MAX_COMMAND_LEN - 1,
                        "%s %s %s", pingStr, g_node[i].cmAgentIP[0], PING_TIMEOUT_OPTION);
                }
                securec_check_intval(rc, (void)rc);
                rc = system(pingCommand);
                if (rc != 0) {
                    write_runlog(ERROR,
                        "Execute %s failed: system result is %d, shell result is %d, errno=%d.\n",
                        pingCommand, rc, WEXITSTATUS(rc), errno);
                } else {
                    return true;
                }
            }
        }
        cm_sleep(2);
        tryTimes--;
    } while (tryTimes > 0);
    return false;
}

/**
 * @brief do ssh az3 ssh az1 to check start file
 *
 * @param  sshIp            My Param doc
 * @param  azRole           My Param doc
 * @return true
 * @return false
 */
bool doCheckAzStatus(const char *sshIp, AZRole azRole)
{
    int rc = 0;
    int count = 0;
    int totalCount = 0;
    char checkStartFile[CM_MAX_COMMAND_LONG_LEN] = {0};

    for (uint32 i = 0; i < g_node_num; i++) {
        const char *ping_ip = g_node[i].cmAgentIP[0];
        const char *pingStr = GetPingStr(GetIpVersion(ping_ip));
        if (isAZPrioritySatisfyAZRole(g_node[i].azPriority, azRole)) {
            if (sshIp == NULL) {
                rc = snprintf_s(checkStartFile,
                    CM_MAX_COMMAND_LONG_LEN,
                    CM_MAX_COMMAND_LONG_LEN - 1,
                    "%s %s %s;if [ $? == 0 ];then pssh %s -s -H %s \"ls %s \";fi;",
                    pingStr,
                    ping_ip,
                    PING_TIMEOUT_OPTION,
                    PSSH_TIMEOUT,
                    g_node[i].sshChannel[0],
                    g_cmManualStartPath);
            } else {
                rc = snprintf_s(checkStartFile,
                    CM_MAX_COMMAND_LONG_LEN,
                    CM_MAX_COMMAND_LONG_LEN - 1,
                    "%s %s %s;"
                    "if [ $? == 0 ];then pssh %s -s -H [%s] \" "
                    " echo '%s %s %s;if [ $\"\"? -eq 0 ];then touch %s/azIpcheck.flag;fi;' > %s/azIpcheck.sh;"
                    " sh %s/azIpcheck.sh;rm -f %s/azIpcheck.sh;"
                    " if test -e %s/azIpcheck.flag;then rm -f %s/azIpcheck.flag;pssh %s -s -H %s \"ls %s \";fi;"
                    "\";fi;",
                    pingStr,
                    sshIp,
                    PING_TIMEOUT_OPTION,
                    PSSH_TIMEOUT,
                    sshIp,
                    pingStr,
                    ping_ip,
                    PING_TIMEOUT_OPTION,
                    sys_log_path,
                    sys_log_path,
                    sys_log_path,
                    sys_log_path,
                    sys_log_path,
                    sys_log_path,
                    PSSH_TIMEOUT,
                    g_node[i].sshChannel[0],
                    g_cmManualStartPath);
            }
            securec_check_intval(rc, (void)rc);

            rc = system(checkStartFile);
            if (rc != -1 && WEXITSTATUS(rc) == 0) {
                write_runlog(LOG, "Execute %s may success, start file exist.\n", checkStartFile);
            } else if (rc != -1 && WEXITSTATUS(rc) != 0) {
                write_runlog(DEBUG1,
                    "Execute %s may failed, start file don't exist, system result is %d, shell result is %d,"
                    " errno=%d.\n",
                    checkStartFile,
                    rc,
                    WEXITSTATUS(rc),
                    errno);
                count++;
            } else {
                write_runlog(LOG, "Execute %s failed, system result is %d.\n", checkStartFile, rc);
            }
            if (count > AZ1_AND_AZ2_CHECK_SUCCESS_NODE_LIMIT) {
                break;
            }
            totalCount++;
        }
    }

    if (count > totalCount / 2 || count > AZ1_AND_AZ2_CHECK_SUCCESS_NODE_LIMIT) {
        return true;
    }
    return false;
}

static int32 UpdateAzDnCount(int *azDnCount, int32 len, int32 azIndex)
{
    if (azIndex >= len || azIndex < 0) {
        return -1;
    }
    ++(*(azDnCount + azIndex));
    return 0;
}

bool GetAzIndexByGroupAndMemberIdx(int32 *azIndex, bool inCurSyncList, bool isVoteAz, uint32 groupIdx, int32 memIdx)
{
    cm_instance_role_status *dnRole = &(g_instance_role_group_ptr[groupIdx].instanceMember[memIdx]);
    if (g_only_dn_cluster && strlen(dnRole->azName) == 0) {
        *azIndex = AZ1_INDEX;
        return true;
    }
    /* isVoteAz is true, and instanceId in Vote az */
    bool doResult = (isVoteAz && IsCurInstanceInVoteAz(groupIdx, memIdx));
    if (doResult) {
        return false;
    }
    doResult = IsInstanceIdInSyncList(
        dnRole->instanceId, &(g_instance_group_report_status_ptr[groupIdx].instance_status.currentSyncList));
    if (inCurSyncList && !doResult) {
        return false;
    }
    uint32 priority = dnRole->azPriority;

    if (priority < g_az_master) {
        write_runlog(ERROR, "Invalid priority: az name is %s, priority=%u.\n", dnRole->azName, priority);
        *azIndex = -1;
    } else if (priority >= g_az_master && priority < g_az_slave) {
        *azIndex = AZ1_INDEX;
    } else if (priority >= g_az_slave && priority < g_az_arbiter) {
        *azIndex = AZ2_INDEX;
    } else {
        *azIndex = AZ3_INDEX;
    }
    return true;
}

/**
 * @brief Get the Dn Count Of A Z object
 *
 * @param  azDnCount        My Param doc
 * @return int
 */
int GetDnCountOfAZ(int *azDnCount, int32 len, bool inCurSyncList, bool isVoteAz)
{
    if (!g_multi_az_cluster) {
        return -1;
    }
    bool doResult = false;
    for (uint32 i = 0; i < g_dynamic_header->relationCount; i++) {
        if (g_instance_role_group_ptr[i].instanceMember[0].instanceType != INSTANCE_TYPE_DATANODE) {
            continue;
        }
        for (int32 j = 0; j < g_instance_role_group_ptr[i].count; ++j) {
            int32 azIndex = 0;
            doResult = GetAzIndexByGroupAndMemberIdx(&azIndex, inCurSyncList, isVoteAz, i, j);
            if (!doResult) {
                continue;
            }
            if (UpdateAzDnCount(azDnCount, len, azIndex) != 0) {
                return -1;
            }
        }
    }
    return 0;
}

/**
 * @brief
 *
 * @return true
 * @return false
 */
int GetAzDeploymentType(bool isVoteAz)
{
    if (!g_multi_az_cluster) {
        return (int)UNKNOWN_AZ_DEPLOYMENT;
    }

    int azDnCount[AZ_MEMBER_MAX_COUNT] = {0, 0, 0};
    int ret = GetDnCountOfAZ(azDnCount, AZ_MEMBER_MAX_COUNT, false, isVoteAz);
    write_runlog(DEBUG1,
        "GetDnCountOfAZ: ret=%d, Az1DnCount=%d, Az2DnCount=%d, Az3DnCount=%d.\n",
        ret,
        azDnCount[AZ1_INDEX],
        azDnCount[AZ2_INDEX],
        azDnCount[AZ3_INDEX]);
    if (ret == -1) {
        return (int)UNKNOWN_AZ_DEPLOYMENT;
    }
    /* AZ3 is arbitrable AZ, which does not deploy dn and only deloys Ddb */
    if (azDnCount[AZ1_INDEX] > 0 && azDnCount[AZ2_INDEX] > 0 && azDnCount[AZ3_INDEX] == 0) {
        return (int)TWO_AZ_DEPLOYMENT;
    } else if (azDnCount[AZ1_INDEX] > 0 && azDnCount[AZ2_INDEX] > 0 && azDnCount[AZ3_INDEX] > 0) {
        return (int)THREE_AZ_DEPLOYMENT;
    }
    return (int)UNKNOWN_AZ_DEPLOYMENT;
}

/**
 * @brief PingIpThrdFuncMain: thread main function which is used to ping other AZ
 *
 * @param arg: thread parameter
 *
 * @return void*
 */
static void *PingIpThrdFuncMain(void *arg)
{
    char command[MAXPGPATH] = {0};
    char buf[MAXPGPATH];
    PingCheckThreadParmInfo *info = (PingCheckThreadParmInfo *)arg;

    if (info == NULL) {
        write_runlog(ERROR, "PingIpThrdFuncMain: invalid argument (info is NULL)\n");
        return NULL;
    }

    uint32 threadIndex = info->threadIdx;
    uint32 nodeIndex = 0;
    int ret = find_node_index_by_nodeid(info->azNode, &nodeIndex);
    int rc;
    if (ret != 0) {
        write_runlog(ERROR, "PingIpThrdFuncMain: get node index failed!\n");
        return NULL;
    }
     
    const char *pingStr = GetPingStr(GetIpVersion(g_node[nodeIndex].cmAgentIP[0]));
    rc = snprintf_s(command,
        MAXPGPATH,
        MAXPGPATH - 1,
        "%s -c 1 -w 1 %s > /dev/null;if [ $? == 0 ];then echo success;else echo fail;fi;",
        pingStr, g_node[nodeIndex].cmAgentIP[0]);
    securec_check_intval(rc, (void)rc);
    write_runlog(DEBUG1, "ping command is %s.\n", command);

    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        write_runlog(ERROR, "popen failed\n.");
        return NULL;
    }
    if (fgets(buf, sizeof(buf), fp) != NULL) {
        if (strstr(buf, "success") != NULL) {
            info->pingResultArrayRef[threadIndex] = 1;
        } else {
            info->pingResultArrayRef[threadIndex] = 0;
        }
    }
    (void)pclose(fp);
    return NULL;
}

/**
 * @brief CheckPingReulst: Check the ping results
 *
 * @param pingResultArray: a array for storing the ping results of each thread
 * @param pthreadNum: the num of thread
 *
 * @return bool
 */
static bool CheckPingReulst(const uint32 *pingResultArray, uint32 pthreadNum)
{
    bool checkResult = false;
    for (uint32 i = 0; i < pthreadNum; i++) {
        if (pingResultArray[i] > 0) {
            checkResult = true;
            break;
        }
    }
    return checkResult;
}

/**
 * @brief MulAzThread: Create multiple thread according to the pthreadNum
 *
 * @param pthreadNum: the num of thread
 * @param azNodes: nodes array of the az
 *
 * @return bool
 */
bool MulAzThread(const uint32 pthreadNum, const uint32* azNodes)
{
    int err = 0;
    pthread_t thr_id[MAX_PING_NODE_NUM];
    uint32 threadIndex;

    uint32 pingCheckResult[MAX_PING_NODE_NUM];
    for (uint32 ii = 0; ii < MAX_PING_NODE_NUM; ii++) {
        pingCheckResult[ii] = 0;
    }

    /* pthreadInfo: save the thread info including node〝threadIdx〝pingCheckResult */
    PingCheckThreadParmInfo pthreadInfo[MAX_PING_NODE_NUM];
    for (uint32 j = 0; j < pthreadNum; j++) {
        pthreadInfo[j].azNode = azNodes[j];
        pthreadInfo[j].threadIdx = j;
        pthreadInfo[j].pingResultArrayRef = pingCheckResult;
    }

    for (threadIndex = 0; threadIndex < pthreadNum; threadIndex++) {
        err = pthread_create(&thr_id[threadIndex], NULL, PingIpThrdFuncMain, &pthreadInfo[threadIndex]);
        if (err != 0) {
            write_runlog(ERROR, "create thread failed.\n");
            return true;
        } else {
            write_runlog(DEBUG1, "create thread successfully.\n");
        }
    }

    for (threadIndex = 0; threadIndex < pthreadNum; threadIndex++) {
        (void)pthread_join(thr_id[threadIndex], NULL);
    }

    if (CheckPingReulst(pingCheckResult, pthreadNum)) {
        return true;
    } else {
        return false;
    }
}

/*
 * Get nodes(tempNodesArray) in AZ(azName)
 * @azName: AZ
 * @tempNodesArray : nodes in AZ
 *
 */
static void GetAzNodes(const char *azName, uint32 *tempNodesArray, uint32 arrLen)
{
    uint32 azNodesArrray[arrLen];
    size_t len = sizeof(uint32) * arrLen;
    errno_t ret = memset_s(azNodesArrray, len, 0, len);
    securec_check_errno(ret, (void)ret);

    for (uint32 azIndex = 0; azIndex < g_azNum; azIndex++) {
        if (strcmp(azName, g_azArray[azIndex].azName) != 0) {
            continue;
        }
        uint32 azNodeIndex = 0;
        uint32 nodeIdx = 0;
        while (g_azArray[azIndex].nodes[azNodeIndex] != 0) {
            if (g_azArray[azIndex].nodes[azNodeIndex] == g_currentNode->node) {
                azNodeIndex++;
                continue;
            }
            azNodesArrray[nodeIdx] = g_azArray[azIndex].nodes[azNodeIndex];
            azNodeIndex++;
            nodeIdx++;
            /* When the azNodeIndex exceeds the maximum CM_NODE_MAXNUM of aznodes-arry, we need break the loop. */
            if (azNodeIndex >= CM_NODE_MAXNUM) {
                break;
            }
        }
        break;
    }

    if (arrLen > MAX_PING_NODE_NUM) {
        srand((unsigned int)time(0));
        for (uint32 nodeIndex = 0; nodeIndex < MAX_PING_NODE_NUM; nodeIndex++) {
            tempNodesArray[nodeIndex] = azNodesArrray[rand() % MAX_PING_NODE_NUM];
        }
    } else {
        ret = memcpy_s(tempNodesArray, sizeof(azNodesArrray), azNodesArrray, sizeof(azNodesArrray));
        securec_check_errno(ret, (void)ret);
    }
}

/*
 * Get the number of nodes in current AZ
 * @azName: AZ
 * @currentAzNodeNum : the num of nodes in current AZ
 *
 */
static uint32 GetCurrentAZnodeNum(const char *azName)
{
    uint32 currentAzNodeNum = 0;
    azInfo *targetAz = NULL;
    uint32 nodeIdx = 0;
    for (uint32 ii = 0; ii < g_azNum; ii++) {
        if (strcmp(azName, g_azArray[ii].azName) == 0) {
            targetAz = &g_azArray[ii];
            break;
        }
    }
    if (targetAz == NULL) {
        write_runlog(ERROR, "We cannot find the target AZ(%s).\n", azName);
        return 0;
    }
    while (targetAz->nodes[nodeIdx] != 0) {
        currentAzNodeNum++;
        nodeIdx++;
        /* When the nodeIdx exceeds the maximum CM_NODE_MAXNUM of aznodes-arry, we need break the loop. */
        if (nodeIdx >= CM_NODE_MAXNUM) {
            break;
        }
    }
    return currentAzNodeNum;
}

/*
 * Get CMS node in Az
 */
static void GetCmsNode(const char *azName, uint32 *cmsNodeArray, uint32 arrLen)
{
    uint32 ii;
    uint32 jj;
    uint32 kk;
    uint32 currentAzNodeNum = GetCurrentAZnodeNum(azName);
    uint32 nodeIndex;
    for (kk = 0; kk < g_azNum; kk++) {
        if (strcmp(azName, g_azArray[kk].azName) == 0) {
            break;
        }
    }

    uint32 cmsNodeIdx = 0;
    for (ii = 0; ii < currentAzNodeNum; ii++) {
        int ret = find_node_index_by_nodeid(g_azArray[kk].nodes[ii], &nodeIndex);
        if (ret != 0) {
            write_runlog(ERROR, "GetCmsNode: get node index failed!\n");
            return;
        }
        for (jj = 0; jj < CM_IP_NUM; jj++) {
            if (strcmp(g_node[nodeIndex].cmAgentIP[0], g_node[nodeIndex].cmServer[jj]) != 0 ||
                strcmp(g_node[nodeIndex].azName, azName) != 0) {
                continue;
            }
            write_runlog(DEBUG1, "The cms node is %u in %s.\n", nodeIndex + 1, azName);
            if (cmsNodeIdx >= arrLen) {
                write_runlog(ERROR, "cmsNodeIdx(%u) is more than arrlen(%u).\n", cmsNodeIdx, arrLen);
                break;
            }
            cmsNodeArray[cmsNodeIdx] = nodeIndex + 1;
            cmsNodeIdx++;
        }
    }
    return;
}

static uint32 GetCmsPrimaryAZ(char *azName)
{
    uint32 cmsPrimaryNodeId;
    char value[DDB_MIN_VALUE_LEN] = {0};
    errno_t rc;
    char primary_key[MAX_PATH_LEN] = {0};
    uint32 ii;
    uint32 tryTimes = 2;
    uint32 currentAzNodeNum;
    uint32 nodeIndex;

    rc = snprintf_s(primary_key, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/CMServer/primary_node_id", pw->pw_name);
    securec_check_intval(rc, (void)rc);

    DdbConn dbConn = g_dbConn;
    DDB_RESULT dbResult = SUCCESS_GET_VALUE;
    status_t st = CM_SUCCESS;
    while (tryTimes > 0) {
        st = GetKVWithCon(&dbConn, primary_key, value, DDB_MIN_VALUE_LEN, &dbResult);
        if (st != CM_SUCCESS) {
            write_runlog(ERROR, "/%s/CMServer/primary_node_id get Ddb error: %d\n", pw->pw_name, dbResult);
        } else {
            break;
        }
        tryTimes--;
    }

    if (st != CM_SUCCESS) {
        return 0;
    }

    cmsPrimaryNodeId = (uint32)strtol(value, NULL, 10);
    for (ii = 0; ii < g_azNum; ii++) {
        currentAzNodeNum = GetCurrentAZnodeNum(g_azArray[ii].azName);
        uint32 cmsNodeArray[CM_NODE_MAXNUM] = {0};
        GetCmsNode(g_azArray[ii].azName, cmsNodeArray, CM_NODE_MAXNUM);
        nodeIndex = 0;
        while (cmsNodeArray[nodeIndex] != 0) {
            if (cmsNodeArray[nodeIndex] == cmsPrimaryNodeId) {
                rc = memcpy_s(azName, CM_AZ_NAME, g_azArray[ii].azName, CM_AZ_NAME);
                write_runlog(LOG, "The cms(%u) primay az is %s.\n", cmsNodeArray[nodeIndex], azName);
                securec_check_errno(rc, (void)rc);
                return 1;
            }
            nodeIndex++;
            /* When the nodeIndex exceeds the currentAzNodeNum, we need break the loop. */
            if (nodeIndex >= currentAzNodeNum) {
                break;
            }
        }
    }
    return 0;
}

/*
 * Do the operation of ping AZ
 * @azName: AZ
 *
 */
bool DoPingAz(const char *azName)
{
    uint32 currenAzNodeNum;
    int rc;
    currenAzNodeNum = GetCurrentAZnodeNum(azName);
    if (currenAzNodeNum == 0) {
        return true;
    }
    /*
     * If the num of AZ-nodes more than 10, we create 10 pthreads to do the ping opereation.
     * Otherwise we we create multiple pthreads to do the ping opereation according to the actual number of nodes.
     */
    uint32 tempAzNodeNum;
    if (currenAzNodeNum < MAX_PING_NODE_NUM) {
        tempAzNodeNum = currenAzNodeNum;
    } else {
        tempAzNodeNum = MAX_PING_NODE_NUM;
    }

    /* When doing ping dection for current node AZ,
     * considering the result of ping self is always ok, we have not to ping self.
     */
    if (strcmp(azName, g_currentNode->azName) == 0) {
        currenAzNodeNum--;
        tempAzNodeNum--;

        if (tempAzNodeNum == 0) {
            return true;
        }
    }

    uint32 azNodes[tempAzNodeNum];
    rc = memset_s(azNodes, sizeof(azNodes), 0, sizeof(azNodes));
    securec_check_errno(rc, (void)rc);
    GetAzNodes(azName, azNodes, currenAzNodeNum);
    return MulAzThread(tempAzNodeNum, azNodes);
}

/*
 * Set the name of ddb-key about az connection status
 * @azName: AZ
 * @azConnectStatusKey: the ddb key of az connection status
 * @peerAzName : peer az
 */
static void DdbKeyOfAzConnectStatus(const char *azName, char *azConnectStatusKey, uint32 keyLen, const char *peerAzName)
{
    errno_t rcs;
    char tempAzName[CM_AZ_NAME] = {0};
    if (peerAzName == NULL) {
        rcs = memcpy_s(tempAzName, CM_AZ_NAME, g_currentNode->azName, CM_AZ_NAME);
        securec_check_errno(rcs, (void)rcs);
    } else {
        rcs = memcpy_s(tempAzName, CM_AZ_NAME, peerAzName, CM_AZ_NAME);
        securec_check_errno(rcs, (void)rcs);
    }

    if (strcmp(tempAzName, azName) < 0) {
        rcs = snprintf_s(azConnectStatusKey, keyLen, keyLen - 1, "%sAnd%s", tempAzName, azName);
        securec_check_intval(rcs, (void)rcs);
    } else if (strcmp(tempAzName, azName) > 0) {
        rcs = snprintf_s(azConnectStatusKey, keyLen, keyLen - 1, "%sAnd%s", azName, tempAzName);
        securec_check_intval(rcs, (void)rcs);
    }
    return;
}

static bool SetDdbKeyValueOfAzConnectStatus(const char *key, int value)
{
    errno_t rc;
    char azConnectStatusKey[MAX_PATH_LEN] = {0};
    char azConnectStatusValue[DDB_MIN_VALUE_LEN] = {0};
    rc = snprintf_s(azConnectStatusKey, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/%s", pw->pw_name, key);
    securec_check_intval(rc, (void)rc);
    rc = snprintf_s(azConnectStatusValue, DDB_MIN_VALUE_LEN, DDB_MIN_VALUE_LEN - 1, "%d", value);
    securec_check_intval(rc, (void)rc);
    int32 tryTimes = TRY_TIMES;
    status_t st = CM_SUCCESS;
    do {
        st = SetKVWithConn(&g_dbConn, azConnectStatusKey, MAX_PATH_LEN, azConnectStatusValue, DDB_MIN_VALUE_LEN);
        if (st != CM_SUCCESS) {
            cm_sleep(1);
            --tryTimes;
        }
    } while (st != CM_SUCCESS && tryTimes > 0);
    if (st != CM_SUCCESS) {
        write_runlog(ERROR,
            "ddb set(SetOnlineStatusToDdb) failed. key=%s, value=%s.\n",
            azConnectStatusKey,
            azConnectStatusValue);
    } else {
        write_runlog(DEBUG1,
            "ddb set(SetOnlineStatusToDdb) successfully. key=%s, value=%s.\n",
            azConnectStatusKey,
            azConnectStatusValue);
        return true;
    }
    return false;
}

static bool GetDdbKeyValueOfAzConnectStatus(const char *key, int32 value, bool *operResult)
{
    DDB_RESULT dbResult = SUCCESS_GET_VALUE;
    char azConnectStatusKey[MAX_PATH_LEN] = {0};
    char azConnectStatusValue[DDB_MIN_VALUE_LEN] = {0};
    errno_t rc = snprintf_s(azConnectStatusKey, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/%s", pw->pw_name, key);
    securec_check_intval(rc, (void)rc);
    status_t st = CM_SUCCESS;
    int32 tryTimes = TRY_TIMES;
    do {
        st = GetKVWithCon(&g_dbConn, azConnectStatusKey, azConnectStatusValue, DDB_MIN_VALUE_LEN, &dbResult);
        if (dbResult == CAN_NOT_FIND_THE_KEY) {
            break;
        }
        if (st != CM_SUCCESS) {
            cm_sleep(1);
            --tryTimes;
        }
    } while (st != CM_SUCCESS && tryTimes > 0);
    if (st != CM_SUCCESS) {
        write_runlog(ERROR,
            "ddb get(SetOnlineStatusToDdb) failed. key=%s, value=%s, %d.\n",
            azConnectStatusKey,
            azConnectStatusValue,
            dbResult);
        *operResult = false;
        return false;
    } else {
        write_runlog(DEBUG1,
            "ddb get(SetOnlineStatusToDdb) successfully. key=%s, value=%s.\n",
            azConnectStatusKey,
            azConnectStatusValue);
        *operResult = true;
    }
    int32 tempValue = (int32)strtol(azConnectStatusValue, NULL, 10);
    if (tempValue == value) {
        write_runlog(LOG, "The azConnectStatusValue is %d\n", tempValue);
        return true;
    } else {
        write_runlog(LOG, "The azConnectStatusValue is %d\n", tempValue);
        return false;
    }
}

/*
 * Set or Get the key of AzConnectStatus to ddb
 * @ddbOperateType: Set or Get
 * @Key: the ddb key of az connection status
 * @value : the ddb value of az connection status
 */
static bool SetOrGetDdbKeyValueOfAzConnectStatus(
    DdbOperateType ddbOperateType, const char *key, int value, bool *operResult)
{
    if (ddbOperateType == SET_DDB_AZ) {
        return SetDdbKeyValueOfAzConnectStatus(key, value);
    } else if (ddbOperateType == GET_DDB_AZ) {
        return GetDdbKeyValueOfAzConnectStatus(key, value, operResult);
    }
    write_runlog(ERROR, "We do not know the specific optrate.\n");
    return false;
}

/*
 * Set isolated az connect status to ddb
 * @ddbOperateType: Set or Get
 * @Key: the ddb key of az connection status
 * @value : the ddb value of az connection status
 */
static bool SetIsolatedAzToDdb(const char *disconAzName, const char *conAzName)
{
    /*
     * If the AZ is isolated, we cannot write key-value to ddb.
     * We use other normal AZ to record its connection status.
     */
    int rc;
    char keyOfMulAzConnectStatus[MAX_PATH_LEN] = {0};
    bool isSetOk;
    bool isGetOk1 = false;
    bool isGetOk2 = false;
    int value;
    static uint32 consistentTimes = 0;
    static bool lastLeaf1AzSetted = false;
    static bool lastLeaf2AzSetted = false;
    const uint32 maxConsistentTimes = 5;

    cm_sleep(AZ_START_STOP_INTERVEL);
    DdbKeyOfAzConnectStatus(disconAzName, keyOfMulAzConnectStatus, MAX_PATH_LEN, NULL);
    bool isLeaf1AzSetted = SetOrGetDdbKeyValueOfAzConnectStatus(GET_DDB_AZ, keyOfMulAzConnectStatus, 1, &isGetOk1);
    rc = memset_s(keyOfMulAzConnectStatus, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    DdbKeyOfAzConnectStatus(disconAzName, keyOfMulAzConnectStatus, MAX_PATH_LEN, conAzName);
    bool isLeaf2AzSetted = SetOrGetDdbKeyValueOfAzConnectStatus(GET_DDB_AZ, keyOfMulAzConnectStatus, 1, &isGetOk2);
    if (isLeaf1AzSetted == lastLeaf1AzSetted && isLeaf2AzSetted == lastLeaf2AzSetted) {
        consistentTimes++;
    } else {
        write_runlog(LOG, "[%s] Leaf1AzSetted[%d:%d] Leaf2AzSetted[%d:%d], ConsistentTimes is %u.\n", __FUNCTION__,
            isLeaf1AzSetted, lastLeaf1AzSetted, isLeaf2AzSetted, lastLeaf2AzSetted, consistentTimes);
        lastLeaf1AzSetted = isLeaf1AzSetted;
        lastLeaf2AzSetted = isLeaf2AzSetted;
        consistentTimes = 0;
    }

    if (consistentTimes < maxConsistentTimes) {
        return false;
    }

    write_runlog(LOG, "[%s] Leaf1AzSetted[%d] Leaf2AzSetted[%d].\n", __FUNCTION__, isLeaf1AzSetted, isLeaf2AzSetted);
    if (isLeaf1AzSetted && isLeaf2AzSetted) {
        value = 1;
    } else if (isGetOk1 && isGetOk2) {
        value = 0;
    } else {
        write_runlog(ERROR, "Can't get edge status value from ddb.\n");
        return false;
    }

    isSetOk = SetOrGetDdbKeyValueOfAzConnectStatus(SET_DDB_AZ, disconAzName, value, NULL);
    if (!isSetOk) {
        write_runlog(ERROR, "Set the isolated AZ status failed, value %d.\n", value);
        return false;
    }
    write_runlog(LOG, "Set the isolated AZ status successfully, value %d.\n", value);
    return true;
}

/*
 * Create stop node flag file when CMS node is stoppped
 */
int CreateStopNodeInstancesFlagFile(int type)
{
    int rc;
    int ret;
    char exec_path[MAX_PATH_LEN] = {0};
    char stopFlagFile[MAX_PATH_LEN] = {0};
    char cmd[MAX_PATH_LEN] = {0};

    if (GetHomePath(exec_path, sizeof(exec_path)) != 0) {
        return -1;
    }
    if (type == SINGLENODE_TYPE) {
        rc = snprintf_s(stopFlagFile, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/%s", exec_path, "node_instances_stop");
    } else {
        rc = snprintf_s(stopFlagFile, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/%s", exec_path, "az_node_instances_stop");
    }

    securec_check_intval(rc, (void)rc);
    ret = snprintf_s(cmd, MAX_PATH_LEN, MAX_PATH_LEN - 1, "touch %s;chmod 600 %s", stopFlagFile, stopFlagFile);
    securec_check_intval(ret, (void)ret);

    ret = system(cmd);
    if (ret != 0) {
        write_runlog(ERROR, "CreateStopNodeInstancesFlagFile failed:%s, errnum=%d, errno=%d..\n", cmd, ret, errno);
        return -1;
    }
    write_runlog(LOG, "CreateStopNodeInstancesFlagFile success: %s.\n", cmd);
    return 0;
}

bool CheckStopFileExist(int type)
{
    int rc = 0;
    char exec_path[MAX_PATH_LEN] = {0};
    char stopFlagFile[MAX_PATH_LEN] = {0};

    if (GetHomePath(exec_path, sizeof(exec_path)) != 0) {
        return false;
    }
    if (type == SINGLENODE_TYPE) {
        rc = snprintf_s(stopFlagFile, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/%s", exec_path, "node_instances_stop");
    } else if (type == SINGLEAZ_TYPE) {
        rc = snprintf_s(stopFlagFile, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/%s", exec_path, "az_node_instances_stop");
    }
    securec_check_intval(rc, (void)rc);

    struct stat stat_buf = {0};
    if (stat(stopFlagFile, &stat_buf) == 0) {
        return true;
    }

    return false;
}

static void CheckAndDoAzStop(const char *azName)
{
    bool isGetOk = false;

    cm_sleep(AZ_STOP_DELAY);
    bool isAzStopped = SetOrGetDdbKeyValueOfAzConnectStatus(GET_DDB_AZ, azName, MULTIAZ_STOPPING_STATUS, &isGetOk);
    if (!isGetOk) {
        return;
    }
    if (isAzStopped) {
        write_runlog(LOG, "AZ(%s) have been stopped, and we need not to stop the current AZ.\n", azName);
        return;
    }
    StartOrStopAZ(STOP_AZ, g_currentNode->azName);
    bool isSetOk =
        SetOrGetDdbKeyValueOfAzConnectStatus(SET_DDB_AZ, g_currentNode->azName, MULTIAZ_STOPPING_STATUS, NULL);
    if (!isSetOk) {
        write_runlog(ERROR, "set ddb value failed.\n");
    }
    if (CreateStopNodeInstancesFlagFile(SINGLEAZ_TYPE) == -1) {
        write_runlog(ERROR, "Create stop cms node FlagFile failed.\n");
    }
    write_runlog(LOG, "The current az(%s) has been stopped.\n", g_currentNode->azName);

    return;
}

static void CheckNumAndDoAzStop(const char *leaf1AzName)
{
    bool isGetOk = false;
    bool isSetOk = false;
    cm_sleep(AZ_STOP_DELAY);
    bool isAzStopped = SetOrGetDdbKeyValueOfAzConnectStatus(GET_DDB_AZ, leaf1AzName, MULTIAZ_STOPPING_STATUS, &isGetOk);
    if (!isGetOk) {
        return;
    }
    if (isAzStopped) {
        write_runlog(LOG, "AZ(%s) have been stopped, and we need not to stop the current AZ.\n", leaf1AzName);
        return;
    }

    /* the az having the most azPriority need to be stopped */
    if (CurAzIsNeedToStop(leaf1AzName)) {
        StartOrStopAZ(STOP_AZ, g_currentNode->azName);
        isSetOk =
            SetOrGetDdbKeyValueOfAzConnectStatus(SET_DDB_AZ, g_currentNode->azName, MULTIAZ_STOPPING_STATUS, NULL);
        if (!isSetOk) {
            write_runlog(ERROR, "set ddb value failed.\n");
        }
    } else {
        write_runlog(LOG, "After check peer AZ status, Do not decide to stop the AZ(%s).\n", g_currentNode->azName);
        return;
    }

    if (CreateStopNodeInstancesFlagFile(SINGLEAZ_TYPE) == -1) {
        write_runlog(ERROR, "Create stop cms node FlagFile failed.\n");
    }
    write_runlog(LOG, "The current az(%s) has been stopped.\n", g_currentNode->azName);

    return;
}

/*
 * Start Az instances when the az network connection restored
 */
static void DoMultiAzStopSingleEdge(
    bool isLeaf1AZConnectOK, const char *leaf1AzName, bool isLeaf2AZConnectOK, const char *leaf2AzName)
{
    uint32 ret;
    char cmsPrimayAz[CM_AZ_NAME] = {0};
    ret = GetCmsPrimaryAZ(cmsPrimayAz);
    if (ret == 0) {
        write_runlog(ERROR, "Cannot get cms-primary Az.\n");
        return;
    }

    /*
     * In 3*AZ deployment (current_az, leaf1Az, leaf2Az)
     *
     * If leaf1Az or leaf2Az(disconnected) has been stopped, we do not have to further stop current_az,
     * as there is no enough information to indicate current_az is "fully-isolated" fromother nodes.
     */
    cm_sleep(AZ_START_STOP_INTERVEL);
    bool cond1 = !isLeaf1AZConnectOK && isLeaf2AZConnectOK && (strcmp(cmsPrimayAz, leaf1AzName) == 0);
    bool cond2 = isLeaf1AZConnectOK && !isLeaf2AZConnectOK && (strcmp(cmsPrimayAz, leaf2AzName) == 0);
    bool cond3 = !isLeaf1AZConnectOK && isLeaf2AZConnectOK && (strcmp(cmsPrimayAz, leaf2AzName) == 0);
    bool cond4 = isLeaf1AZConnectOK && !isLeaf2AZConnectOK && (strcmp(cmsPrimayAz, leaf1AzName) == 0);

    if (cond1) {
        CheckAndDoAzStop(leaf1AzName);
        return;
    } else if (cond2) {
        CheckAndDoAzStop(leaf2AzName);
        return;
    } else if (cond3) {
        CheckNumAndDoAzStop(leaf1AzName);
        return;
    } else if (cond4) {
        CheckNumAndDoAzStop(leaf2AzName);
        return;
    } else {
        write_runlog(LOG, "Do not need to stop any AZ.\n");
    }

    return;
}

/*
 * Start Az instances when the az network connection restored
 */
static void DoMultiAzStopDecision(bool isLeaf1AZConnectOK, const char *leaf1AzName, bool isLeaf2AZConnectOK,
    const char *leaf2AzName, bool isCmsConnectOK)
{
    /* Only the CMS is disconnected, we stop the CMS node.
     * The AZ where the CMS is located is disconnected, we stop the current AZ.
     *
     * Perform ping detection on the current AZ where the current CMS node is located.
     * If the current AZ has only one node (the node where the CMS is located),
     * then the disconnection of the CMS is the disconnection of the current AZ, and we have not to ping self.
     * Otherwise, we need to ping current AZ to check and deal with whether CMS-Node is disconnected
     * or the current AZ is disconnected.
     */

    if (CheckStopFileExist(SINGLEAZ_TYPE)) {
        write_runlog(LOG, "az stop file exist, return.\n");
        return;
    }

    if (!isLeaf1AZConnectOK && !isLeaf2AZConnectOK && !isCmsConnectOK) {
        if (CheckStopFileExist(SINGLENODE_TYPE)) {
            write_runlog(LOG, "node stop file exist, return.\n");
            return;
        }
        StartOrStopNodeInstanceByCommand(STOP_AZ, g_currentNode->node);
        if (CreateStopNodeInstancesFlagFile(SINGLENODE_TYPE) == -1) {
            write_runlog(ERROR, "Create stop cms node FlagFile failed.\n");
        }
        write_runlog(
            LOG, "The %s CMS is disconnected, and the ping result is %d.\n", g_currentNode->azName, isCmsConnectOK);
        return;
    } else if (!isLeaf1AZConnectOK && !isLeaf2AZConnectOK) {
        StartOrStopAZ(STOP_AZ, g_currentNode->azName);
        if (CreateStopNodeInstancesFlagFile(SINGLEAZ_TYPE) == -1) {
            write_runlog(ERROR, "Create stop cms node FlagFile failed.\n");
        }
        write_runlog(LOG, "The current az(%s) is isolated and it is stopped.\n", g_currentNode->azName);
        return;
    }

    DoMultiAzStopSingleEdge(isLeaf1AZConnectOK, leaf1AzName, isLeaf2AZConnectOK, leaf2AzName);
    return;
}

/*
 * Reset the key-value of stopped Az to 0
 */
static void ResetStoppedAz()
{
    int rc;
    char exec_path[MAX_PATH_LEN] = {0};
    char stopFlagFile[MAX_PATH_LEN] = {0};
    struct stat stat_buf = {0};
    if (GetHomePath(exec_path, sizeof(exec_path)) != 0) {
        return;
    }
    rc = snprintf_s(stopFlagFile, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/%s", exec_path, "az_node_instances_stop");
    securec_check_intval(rc, (void)rc);
    if (stat(stopFlagFile, &stat_buf) == 0) {
        if (unlink(stopFlagFile) != 0) {
            write_runlog(ERROR, "delete cms-node stop instances flag file: %s failed.\n", stopFlagFile);
        }
    }

    bool isSetOk = SetOrGetDdbKeyValueOfAzConnectStatus(SET_DDB_AZ, g_currentNode->azName, AZ_STATUS_RUNNING, NULL);
    if (!isSetOk) {
        write_runlog(ERROR, "Set the started AZ(%s) failed.\n", g_currentNode->azName);
    } else {
        write_runlog(DEBUG1, "Set the started AZ(%s) successfully.\n", g_currentNode->azName);
    }

    return;
}

static void CheckAzStoppedStatus(const char *azName, bool *isAzStopped)
{
    bool isGetOk = false;

    *isAzStopped = SetOrGetDdbKeyValueOfAzConnectStatus(GET_DDB_AZ, azName, AZ_STAUTS_STOPPED, &isGetOk);
    if (isGetOk && !*isAzStopped) {
        write_runlog(LOG, "AZ(%s) no stopped flag in ddb.\n", azName);
    } else {
        write_runlog(LOG, "Get AZ(%s) stopped flag in ddb.\n", azName);
    }
    return;
}

/*
 * Stop Az instances when the az network is disconnected
 */
static void DoMultiAzStartDecision(
    bool isLeaf1AZConnectOK, const char *leaf1AzName, bool isLeaf2AZConnectOK, const char *leaf2AzName)
{
    bool doStart = false;
    bool isCurAzStopped = false;
    bool isLeft1AzStopped = false;
    bool isLeft2AzStopped = false;

    bool isExist = CheckStopFileExist(SINGLEAZ_TYPE);
    if (!isExist) {
        write_runlog(LOG, "No stop file exist, There is no any AZ to start.\n");
        return;
    } else {
        write_runlog(LOG, "Stop file exist, try to start Az(%s).\n", g_currentNode->azName);
    }

    CheckAzStoppedStatus(g_currentNode->azName, &isCurAzStopped);
    CheckAzStoppedStatus(leaf1AzName, &isLeft1AzStopped);
    CheckAzStoppedStatus(leaf2AzName, &isLeft2AzStopped);

    /*
     * In 3*AZ deployment (current_az, leaf1Az, leaf2Az)
     *
     * If the connection of current Az with Leaf1Az and Leaf2Az is OK, we have to restart the current Az.
     * Or, if the leaf1Az or leaf2Az(disconnected) has been stopped, we have to restart currentAz
     * to ensure that only the isolated Az is stopped.
     */
    char cmsPrimayAz[CM_AZ_NAME] = {0};
    uint32 ret = GetCmsPrimaryAZ(cmsPrimayAz);
    if (ret == 0) {
        write_runlog(ERROR, "Cannot get cms-primary Az.\n");
        return;
    }
    if (isLeaf1AZConnectOK && isLeaf2AZConnectOK) {
        StartOrStopAZ(START_AZ, g_currentNode->azName);
        ResetStoppedAz();
        CleanMultiConnState(g_currentNode->azName, NULL);
        doStart = true;
    } else if ((!isLeaf1AZConnectOK && isLeaf2AZConnectOK) ||
        (isLeaf1AZConnectOK && !isLeaf2AZConnectOK)) {
        if ((strcmp(cmsPrimayAz, g_currentNode->azName) == 0) || isLeft1AzStopped || isLeft2AzStopped) {
            StartOrStopAZ(START_AZ, g_currentNode->azName);
            ResetStoppedAz();
            CleanMultiConnState(g_currentNode->azName, NULL);
            doStart = true;
        } else {
            write_runlog(ERROR,
                "cmsPrimayAz is %s, leaf1AZ is (%d: %d), leaf2AZ is (%d: %d), "
                "so the current Az(%s) cannot be restarted.\n",
                cmsPrimayAz,
                isLeaf1AZConnectOK,
                isLeft1AzStopped,
                isLeaf2AZConnectOK,
                isLeft2AzStopped,
                g_currentNode->azName);
            return;
        }
    }

    if (doStart) {
        write_runlog(LOG, "The current Az(%s) is started.\n", g_currentNode->azName);
    } else {
        write_runlog(LOG, "waitting Az(%s) network recovery.\n", g_currentNode->azName);
    }

    return;
}

bool AzPingCheck(bool *preConnStatusAZ, const char *azName1)
{
    bool isAZConnectOK = (cm_server_start_mode != MAJORITY_START) || DoPingAz(azName1);
    if (!isAZConnectOK) {
        write_runlog(LOG, "The %s is disconnected, and the ping result is %d.\n", azName1, isAZConnectOK);
    } else if (cm_server_start_mode != MAJORITY_START) {
        write_runlog(
            DEBUG1, "The %s connected OK, cause start mode(%d) is not majority.\n", azName1, cm_server_start_mode);
    } else {
        write_runlog(DEBUG1, "The %s connected OK, and the ping result is %d.\n", azName1, isAZConnectOK);
    }

    if (*preConnStatusAZ != isAZConnectOK) {
        *preConnStatusAZ = isAZConnectOK;
        return false;
    }

    return true;
}

static int SetMultiAzConnectStatus(const char *leaf1Az, int value)
{
    char keyOfMulAzConnectStatus[MAX_PATH_LEN] = {0};

    DdbKeyOfAzConnectStatus(leaf1Az, keyOfMulAzConnectStatus, MAX_PATH_LEN, NULL);
    bool isSetKeyValueOK = SetOrGetDdbKeyValueOfAzConnectStatus(SET_DDB_AZ, keyOfMulAzConnectStatus, value, NULL);
    if (!isSetKeyValueOK) {
        write_runlog(ERROR, "Set the ddb key %s failed.\n", keyOfMulAzConnectStatus);
        return -1;
    }
    return 0;
}

void StopCurrentAz()
{
    StartOrStopAZ(STOP_AZ, g_currentNode->azName);
    if (CreateStopNodeInstancesFlagFile(SINGLEAZ_TYPE) == -1) {
        write_runlog(ERROR, "Create stop cms node FlagFile failed.\n");
    }
    write_runlog(LOG, "The current az(%s) is isolated and it is stopped.\n", g_currentNode->azName);
    return;
}

static void CleanMultiConnState(const char *azName1, const char *azName2)
{
    char azConnectStatusKey[MAX_PATH_LEN] = {0};
    char keyOfMulAzConnectStatus[MAX_PATH_LEN] = {0};
    errno_t rc = 0;
    if (azName2 == NULL) {
        rc = memcpy_s(keyOfMulAzConnectStatus, MAX_PATH_LEN, azName1, CM_AZ_NAME);
        securec_check_errno(rc, (void)rc);
    } else {
        DdbKeyOfAzConnectStatus(azName1, keyOfMulAzConnectStatus, MAX_PATH_LEN, azName2);
    }
    DdbConn *dbCon = &g_dbConn;
    if (dbCon->modId == MOD_ALL) {
        dbCon = GetNextDdbConn();
    }
    rc = snprintf_s(azConnectStatusKey, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/%s", pw->pw_name, keyOfMulAzConnectStatus);
    securec_check_intval(rc, (void)rc);
    status_t st = CM_SUCCESS;
    int32 tryTimes = TRY_TIMES;
    do {
        st = DelKeyWithConn(dbCon, azConnectStatusKey, MAX_PATH_LEN);
        if (st != CM_SUCCESS) {
            --tryTimes;
            cm_sleep(1);
        }
    } while (st != CM_SUCCESS && tryTimes > 0);
    if (st != CM_SUCCESS) {
        write_runlog(ERROR, "ddb delete (SetOnlineStatusToDdb) failed. key=%s.\n", azConnectStatusKey);
    } else {
        write_runlog(LOG, "ddb delete (SetOnlineStatusToDdb) successfully. key=%s.\n", azConnectStatusKey);
    }

    return;
}

status_t GetDdbSessionInAz(DdbConn *dbConn, int32 timeOut, const char *azNames)
{
    DdbInitConfig config;
    errno_t rc = memset_s(&config, sizeof(DdbInitConfig), 0, sizeof(DdbInitConfig));
    securec_check_errno(rc, (void)rc);
    config.type = g_dbType;
    status_t st = InitDdbCfgApi(config.type, &(config.drvApiInfo), timeOut, azNames);
    CM_RETURN_IFERR(st);

    st = InitDdbConn(dbConn, &config);
    ClearDdbCfgApi(&config.drvApiInfo, g_dbType);
    return st;
}

void CreateDdbConnSession(bool lastLeft1Conn, bool lastLeft2Conn, bool lastCurAzConn)
{
    if (!IsNeedSyncDdb()) {
        return;
    }
    if (g_dbConn.modId != MOD_ALL) {
        RestDdbConn(&g_dbConn, CM_ERROR, NULL);
        return;
    }
    char *azNames = NULL;
    bool lastRes = lastLeft1Conn && lastLeft2Conn && lastCurAzConn;
    if (!lastRes) {
        azNames = g_currentNode->azName;
    }
    const int32 timeOut = 6000;
    status_t res = GetDdbSessionInAz(&g_dbConn, timeOut, azNames);
    if (res != CM_SUCCESS) {
        errno_t rc = memset_s(&g_dbConn, sizeof(DdbConn), 0, sizeof(DdbConn));
        securec_check_errno(rc, (void)rc);
    }
}

static bool IsNeedAzConnectStateCheck()
{
    if (!g_multi_az_cluster) {
        write_runlog(LOG, "The current cluster is not multi-az cluster.\n");
        return false;
    }

    if (GetAzDeploymentType(false) != THREE_AZ_DEPLOYMENT) {
        write_runlog(LOG, "The current deployment is not a CBG 3AZ scenario.\n");
        return false;
    }

    if (g_azNum == 1) {
        write_runlog(LOG, "We cannot stop single AZ.\n");
        return false;
    }

    return true;
}

static void InitAZName(char *leaf1Az, uint32 len1, char *leaf2Az, uint32 len2)
{
    int rc;
    for (uint32 ii = 0; ii < g_azNum; ii++) {
        if (strcmp(g_azArray[ii].azName, g_currentNode->azName) != 0 && leaf1Az[0] == '\0') {
            rc = memcpy_s(leaf1Az, len1, g_azArray[ii].azName, len1);
            write_runlog(DEBUG1, "The leaf1 AZ name is %s.\n", leaf1Az);
            securec_check_errno(rc, (void)rc);
        } else if (strcmp(g_azArray[ii].azName, g_currentNode->azName) != 0 && leaf2Az[0] == '\0') {
            rc = memcpy_s(leaf2Az, len2, g_azArray[ii].azName, len2);
            write_runlog(DEBUG1, "The leaf2 AZ name is %s.\n", leaf2Az);
            securec_check_errno(rc, (void)rc);
        }
    }
}

/**
 * @brief MultiAzConnectStateCheckMain: The Thread main function of multiple AZ network connection status detection
 *
 * @param arg：thread parameters
 *
 * @return void
 */
void *MultiAzConnectStateCheckMain(void *arg)
{
    if (!IsNeedAzConnectStateCheck()) {
        return NULL;
    }

    uint32 cnt = g_loopState.count;
    g_loopState.count++;
    g_loopState.execStatus[cnt] = 1;
    write_runlog(LOG, "[reload] MultiAzConnectStateCheckMain thread loop-index:%u.\n", cnt);
    bool isLeaf1AZConnectOK = true;
    bool isLeaf2AZConnectOK = true;
    bool currConnStatus = true;
    bool checkLeft1AZConnectOK = true;
    bool checkLeft2AZConnectOK = true;
    bool checkCurrAZConnectOK = true;
    bool lastLeft1Conn = false;
    bool lastLeft2Conn = false;
    bool lastCurAzConn = false;
    uint32 checkConnTimes = 0;
    uint32 checkConnMax = 5;
    char keyOfMulAzConnectStatus[MAX_PATH_LEN];
    struct timeval beginPing = {0, 0};
    struct timeval endPing = {0, 0};
    long totalTime = 21;
    long intervalTime = 0;
    int rc;
    int isSetKeyValueOK;
    uint32 failedWriteTimes = 0;
    uint32 maxRetryTime = 15;
    thread_name = "MultiAzCheck";
    char Leaf1Az[CM_AZ_NAME] = {0};
    char Leaf2Az[CM_AZ_NAME] = {0};

    InitAZName(Leaf1Az, CM_AZ_NAME, Leaf2Az, CM_AZ_NAME);
    CleanMultiConnState(g_currentNode->azName, NULL);

    for (;;) {
        if (g_inReload) {
            cm_sleep(AZ_START_STOP_INTERVEL);
            continue;
        }
        checkConnTimes++;
        g_loopState.execStatus[cnt] = 0;
        rc = memset_s(keyOfMulAzConnectStatus, MAX_PATH_LEN, 0, MAX_PATH_LEN);
        securec_check_errno(rc, (void)rc);
        (void)gettimeofday(&beginPing, NULL);
        /* ping Leaf1 Az */
        checkLeft1AZConnectOK = AzPingCheck(&isLeaf1AZConnectOK, Leaf1Az);
        checkLeft2AZConnectOK = AzPingCheck(&isLeaf2AZConnectOK, Leaf2Az);
        checkCurrAZConnectOK = AzPingCheck(&currConnStatus, g_currentNode->azName);

        if ((!isLeaf1AZConnectOK) || (!isLeaf2AZConnectOK) || (!currConnStatus)) {
            write_runlog(LOG, "The AZ Conn Status %s:%d, %s:%d, %s:%d Changed this time %u, try next time.\n", Leaf1Az,
                isLeaf1AZConnectOK, Leaf2Az, isLeaf2AZConnectOK, g_currentNode->azName, currConnStatus, checkConnTimes);
        }

        bool needContinue = false;
        if ((!checkLeft1AZConnectOK) || (!checkLeft2AZConnectOK) || (!checkCurrAZConnectOK)) {
            checkConnTimes = 0;
            cm_sleep(AZ_START_STOP_INTERVEL);
            g_loopState.execStatus[cnt] = 1;
            needContinue = true;
        } else {
            if (checkConnTimes < checkConnMax) {
                cm_sleep(AZ_START_STOP_INTERVEL);
                g_loopState.execStatus[cnt] = 1;
                needContinue = true;
            } else {
                checkConnTimes = 0;
            }
        }

        if (isLeaf1AZConnectOK != lastLeft1Conn || isLeaf2AZConnectOK != lastLeft2Conn ||
            currConnStatus != lastCurAzConn || g_dbConn.modId == MOD_ALL) {
            write_runlog(LOG,
                "left1(%s %d: %d), left2(%s %d: %d), cur(%s %d: %d), will open "
                "new ddb Connect.\n",
                Leaf1Az, lastLeft1Conn, isLeaf1AZConnectOK, Leaf2Az, lastLeft2Conn, isLeaf2AZConnectOK,
                g_currentNode->azName, lastCurAzConn, currConnStatus);
            lastLeft1Conn = isLeaf1AZConnectOK;
            lastLeft2Conn = isLeaf2AZConnectOK;
            lastCurAzConn = currConnStatus;
            CreateDdbConnSession(lastLeft1Conn, lastLeft2Conn, lastCurAzConn);
        }

        /* set multi az connect status */
        if (!isLeaf1AZConnectOK && !isLeaf2AZConnectOK) {
            /*
             * If both the isLeaf1AZConnectOK and isLeaf1AZConnectOK are false, the current az is network isolatedd.
             * So, we cannot set this az connection status to ddb.
             */
        } else if (!isLeaf1AZConnectOK && isLeaf2AZConnectOK) {
            isSetKeyValueOK = SetMultiAzConnectStatus(Leaf1Az, MULTIAZ_STOPPING_STATUS);
            if (isSetKeyValueOK == 0) {
                failedWriteTimes = 0;
            } else {
                failedWriteTimes++;
                write_runlog(ERROR, "Set the IsolatedAz %s failed.\n", Leaf1Az);
                g_loopState.execStatus[cnt] = 1;
                continue;
            }
        } else if (isLeaf1AZConnectOK && !isLeaf2AZConnectOK) {
            isSetKeyValueOK = SetMultiAzConnectStatus(Leaf2Az, MULTIAZ_STOPPING_STATUS);
            if (isSetKeyValueOK == 0) {
                failedWriteTimes = 0;
            } else {
                failedWriteTimes++;
                write_runlog(ERROR, "Set the IsolatedAz %s failed.\n", Leaf2Az);
                g_loopState.execStatus[cnt] = 1;
                continue;
            }
        } else if (isLeaf1AZConnectOK && isLeaf2AZConnectOK) {
            failedWriteTimes = 0;
            isSetKeyValueOK = SetMultiAzConnectStatus(Leaf1Az, MULTIAZ_RUNNING_STATUS);
            if (isSetKeyValueOK != 0) {
                write_runlog(ERROR, "Set the IsolatedAz %s failed.\n", Leaf1Az);
                g_loopState.execStatus[cnt] = 1;
                continue;
            }
            isSetKeyValueOK = SetMultiAzConnectStatus(Leaf2Az, MULTIAZ_RUNNING_STATUS);
            if (isSetKeyValueOK != 0) {
                write_runlog(ERROR, "Set the IsolatedAz %s failed.\n", Leaf2Az);
                g_loopState.execStatus[cnt] = 1;
                continue;
            }
        }

        /* set isolated az */
        bool isSetIsolatedAzOk = true;
        if (!isLeaf1AZConnectOK && isLeaf2AZConnectOK) {
            isSetIsolatedAzOk = SetIsolatedAzToDdb(Leaf1Az, Leaf2Az);
            if (!isSetIsolatedAzOk) {
                write_runlog(LOG, "Try to merge the IsolatedAz %s failed.\n", Leaf1Az);
                g_loopState.execStatus[cnt] = 1;
                continue;
            }
        } else if (isLeaf1AZConnectOK && !isLeaf2AZConnectOK) {
            isSetIsolatedAzOk = SetIsolatedAzToDdb(Leaf2Az, Leaf1Az);
            if (!isSetIsolatedAzOk) {
                write_runlog(LOG, "Try to merge the IsolatedAz %s failed.\n", Leaf2Az);
                g_loopState.execStatus[cnt] = 1;
                continue;
            }
        }

        if (needContinue) {
            continue;
        }

        if (!isLeaf1AZConnectOK || !isLeaf2AZConnectOK) {
            write_runlog(LOG, "failedWriteTimes = %u, local_role = %d \n", failedWriteTimes, g_HA_status->local_role);
            if (failedWriteTimes >= maxRetryTime && (g_HA_status->local_role != CM_SERVER_PRIMARY)) {
                if (!CheckStopFileExist(SINGLEAZ_TYPE) && !CheckStopFileExist(SINGLENODE_TYPE)) {
                    write_runlog(ERROR, "ddb write failed reach max times, restart current az.\n");
                    StopCurrentAz();
                }
                cm_sleep(AZ_START_STOP_INTERVEL);
                g_loopState.execStatus[cnt] = 1;
                continue;
            }
        } else {
            failedWriteTimes = 0;
        }

        if (isLeaf1AZConnectOK && isLeaf2AZConnectOK && currConnStatus) {
            if (!CheckStopFileExist(SINGLEAZ_TYPE) && !CheckStopFileExist(SINGLENODE_TYPE)) {
                cm_sleep(AZ_START_STOP_INTERVEL);
                g_loopState.execStatus[cnt] = 1;
                continue;
            }
        }

        /* start or stop */
        DoMultiAzStopDecision(isLeaf1AZConnectOK, Leaf1Az, isLeaf2AZConnectOK, Leaf2Az, currConnStatus);
        cm_sleep(AZ_START_STOP_INTERVEL);
        DoMultiAzStartDecision(isLeaf1AZConnectOK, Leaf1Az, isLeaf2AZConnectOK, Leaf2Az);
        StartCmsNodeInstances(isLeaf1AZConnectOK, isLeaf2AZConnectOK);

        if (isLeaf1AZConnectOK && isLeaf2AZConnectOK && currConnStatus) {
            cm_sleep(AZ_START_STOP_INTERVEL);
            CleanMultiConnState(Leaf1Az, g_currentNode->azName);
            CleanMultiConnState(Leaf2Az, g_currentNode->azName);
            CleanMultiConnState(g_currentNode->azName, NULL);
        }

        (void)gettimeofday(&endPing, NULL);
        intervalTime = endPing.tv_sec - beginPing.tv_sec;
        if (intervalTime < totalTime) {
            write_runlog(DEBUG1, "The ping opretation takes time %ld seconds.\n", intervalTime);
            cm_sleep((unsigned int)(totalTime - intervalTime));
        } else {
            write_runlog(DEBUG1, "The ping opretation takes time %ld seconds.\n", intervalTime);
            cm_sleep(5);
        }
        g_loopState.execStatus[cnt] = 1;
    }
    return NULL;
}

/**
 * @brief  Start Cms node when this node network connection restored
 *
 * @param isLeaf1AZConnectOK: Leaf1AZ connection status with current AZ
 * @param isLeaf2AZConnectOK: Leaf2AZ connection status with current AZ
 *
 * @return void
 */
static void StartCmsNodeInstances(bool isLeaf1AZConnectOK, bool isLeaf2AZConnectOK)
{
    int rc;
    char exec_path[MAX_PATH_LEN] = {0};
    char stopFlagFile[MAX_PATH_LEN] = {0};

    if (GetHomePath(exec_path, sizeof(exec_path)) != 0) {
        return;
    }
    rc = snprintf_s(stopFlagFile, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/%s", exec_path, "node_instances_stop");
    securec_check_intval(rc, (void)rc);

    struct stat stat_buf = {0};
    if (isLeaf1AZConnectOK && isLeaf2AZConnectOK) {
        if (stat(stopFlagFile, &stat_buf) == 0) {
            write_runlog(LOG, "We only need start current node(%u).\n", g_currentNode->node);
            StartOrStopNodeInstanceByCommand(START_AZ, g_currentNode->node);
            if (unlink(stopFlagFile) != 0) {
                write_runlog(ERROR, "delete cms-node stop instances flag file: %s failed.\n", stopFlagFile);
            } else {
                write_runlog(LOG, "delete cms-node stop instances flag file: %s successfully.\n", stopFlagFile);
            }
        }
    }
    return;
}

/* start or stop AZ */
void StartOrStopAZ(OperateType operateType, const char *azName)
{
    for (uint32 ii = 0; ii < g_azNum; ii++) {
        if (strcmp(azName, g_azArray[ii].azName) != 0) {
            continue;
        }
        uint32 jj = 0;
        while (g_azArray[ii].nodes[jj] != 0) {
            StartOrStopNodeInstanceByCommand(operateType, g_azArray[ii].nodes[jj]);
            jj++;
            /* When the node index jj exceeds the maximum CM_NODE_MAXNUM of aznodes-arry, we need break the loop. */
            if (jj >= CM_NODE_MAXNUM) {
                break;
            }
        }
        break;
    }
    return;
}

/* start or stop node in the AZ */
void StartOrStopNodeInstanceByCommand(OperateType operateType, uint32 nodeId)
{
    uint32 nodeIndex;
    int ret = find_node_index_by_nodeid(nodeId, &nodeIndex);
    if (ret != 0) {
        write_runlog(ERROR, "[%s] get node index failed!\n", __FUNCTION__);
        return;
    }
    if (g_node[nodeIndex].coordinate == 1) {
        if (operateType == START_AZ && IsCnDeleted(nodeId)) {
            const int32 timeOut = 30;
            StartOrStopInstanceByCommand(operateType, nodeId, g_node[nodeIndex].DataPath, timeOut);
        } else {
            StartOrStopInstanceByCommand(operateType, nodeId, g_node[nodeIndex].DataPath);
        }
    }

    if (g_node[nodeIndex].gtm == 1) {
        StartOrStopInstanceByCommand(operateType, nodeId, g_node[nodeIndex].gtmLocalDataPath);
    }

    for (uint32 ii = 0; ii < g_node[nodeIndex].datanodeCount; ii++) {
        StartOrStopInstanceByCommand(
            operateType, nodeId, g_node[nodeIndex].datanode[ii].datanodeLocalDataPath);
    }
    return;
}

/* start or stop instacnes in the node by command */
static void StartOrStopInstanceByCommand(OperateType operateType, uint32 node, const char *instanceDataPath,
    int32 timeOut)
{
    int ret;
    errno_t rc;
    char cmd[MAXPGPATH] = {0};
    uint32 tryTimes = 2;

    if (operateType == START_AZ) {
        if (timeOut == 0) {
            rc = snprintf_s(cmd, MAXPGPATH, MAXPGPATH - 1, "cm_ctl start -n %u -D %s > /dev/null 2>&1 &", node,
                instanceDataPath);
        } else {
            rc = snprintf_s(cmd, MAXPGPATH, MAXPGPATH - 1, "cm_ctl start -n %u -D %s -t %d > /dev/null 2>&1 &", node,
                instanceDataPath, timeOut);
        }
    } else if (operateType == STOP_AZ) {
        rc = snprintf_s(cmd, MAXPGPATH, MAXPGPATH - 1, "cm_ctl stop -n %u -D %s -m i > /dev/null 2>&1 &", node,
            instanceDataPath);
    } else {
        write_runlog(ERROR, "Invalid start-stop command, please recheck it.\n");
        return;
    }
    securec_check_intval(rc, (void)rc);

    while (tryTimes > 0) {
        ret = system(cmd);
        write_runlog(DEBUG1, "Call system command(%s) to execute node start and stop.\n", cmd);
        if (ret != 0) {
            /* If system command failed, we need try again. */
            write_runlog(ERROR, "StartOrStopInstanceByCommand failed:%s, errnum:%d, errno=%d.\n", cmd, ret, errno);
            tryTimes--;
            cm_sleep(1);
        } else {
            write_runlog(LOG, "StartOrStopInstanceByCommand successfully: %s.\n", cmd);
            break;
        }
    }
    return;
}

/* *
 * @brief IsCnDeleted: Judge whether the CN of the node has been deleted
 *
 * @param  nodeId: node
 *
 * @return bool
 */
static bool IsCnDeleted(uint32 nodeId)
{
    cm_instance_role_status *member = NULL;
    for (uint32 i = 0; i < g_dynamic_header->relationCount; i++) {
        if (g_instance_role_group_ptr[i].instanceMember[0].node == nodeId &&
            g_instance_role_group_ptr[i].instanceMember[0].instanceType == INSTANCE_TYPE_COORDINATE) {
            member = &g_instance_role_group_ptr[i].instanceMember[0];
            break;
        }
    }
    if (member == NULL) {
        write_runlog(ERROR, "can't find cn in node %u.\n", nodeId);
        return false;
    }
    if (member->role == INSTANCE_ROLE_DELETED || member->role == INSTANCE_ROLE_DELETING) {
        write_runlog(LOG, "The CN of node %u have been deleted.\n", nodeId);
        return true;
    }
    write_runlog(LOG, "The CN of node %u have not been deleted.\n", nodeId);
    return false;
}
