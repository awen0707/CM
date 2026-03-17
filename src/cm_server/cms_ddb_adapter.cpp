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
 * cms_ddb_adapter.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_server/cms_ddb_adapter.cpp
 *
 * -------------------------------------------------------------------------
 */
#include "cm/cm_elog.h"
#include "cm/cs_ssl.h"
#include "cms_common.h"
#include "cms_ddb.h"
#include "cms_conn.h"

static CM_ConnDdbInfo g_ddbSession = {0};

static DDB_RESULT GetKVInDDb(DdbConn *ddbConn, DrvText *drvKey, DrvText *drvValue, int32 logLevel = -1);
static status_t SetDdbWorkModeInDDb(DdbConn *ddbConn, unsigned int workMode, unsigned int voteNum);
static status_t DemoteDdbRole2StandbyInDDb(DdbConn *ddbConn);

void RestDdbConn(DdbConn *ddbConn, status_t st, const DDB_RESULT *ddbResult)
{
    if (ddbConn == NULL) {
        return;
    }
    if (st == CM_SUCCESS) {
        return;
    }
    if (ddbResult != NULL && (*ddbResult != FAILED_GET_VALUE)) {
        return;
    }
    (void)DdbRestConn(ddbConn);
}

void StopDdbByDrv()
{
    if (g_sess == NULL) {
        return;
    }
    DdbConn *ddbConn = GetNextDdbConn();
    if (ddbConn == NULL) {
        (void)DdbStop(&(g_sess->ddbConn[0]));
        return;
    }
    (void)DdbStop(ddbConn);
}

status_t GetKVFromDDb(char *key, uint32 keyLen, char *value, uint32 valueLen, DDB_RESULT *ddbResult)
{
    DdbConn *ddbConn = GetNextDdbConn();
    CM_RETERR_IF_NULL(ddbConn);
    DrvText drvKey = {key, keyLen};
    DrvText drvValue = {value, valueLen};
    DDB_RESULT dbState = GetKVInDDb(ddbConn, &drvKey, &drvValue);
    if (ddbResult != NULL) {
        *ddbResult = dbState;
    }
    RestDdbConn(ddbConn, CM_SUCCESS, &dbState);
    if (dbState != SUCCESS_GET_VALUE) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t GetKVAndLogLevel(const char *key, char *value, uint32 valueLen, DDB_RESULT *ddbResult, int32 logLevel)
{
    DdbConn *ddbConn = GetNextDdbConn();
    CM_RETERR_IF_NULL(ddbConn);
    char tmpKey[MAX_PATH_LEN] = {0};
    errno_t rc = snprintf_s(tmpKey, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s", key);
    securec_check_intval(rc, (void)rc);
    DrvText drvKey = {tmpKey, MAX_PATH_LEN};
    DrvText drvValue = {value, valueLen};
    DDB_RESULT dbState = GetKVInDDb(ddbConn, &drvKey, &drvValue, logLevel);
    if (ddbResult != NULL) {
        *ddbResult = dbState;
    }
    RestDdbConn(ddbConn, CM_SUCCESS, &dbState);
    if (dbState != SUCCESS_GET_VALUE) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t SetKV2Ddb(char *key, uint32 keyLen, char *value, uint32 valueLen, DrvSetOption *option)
{
    if (g_inMaintainMode) {
        write_runlog(DEBUG1, "in maintain mode.\n");
        if (option == NULL) {
            write_runlog(DEBUG1, "line=%d, can't set kv.\n", __LINE__);
            return CM_ERROR;
        }
        if (!option->maintainCanSet) {
            write_runlog(DEBUG1, "line=%d, can't set kv.\n", __LINE__);
            return CM_ERROR;
        }
        write_runlog(DEBUG1, "can set kv.\n");
    }
    DdbConn *ddbConn = GetNextDdbConn();
    CM_RETERR_IF_NULL(ddbConn);
    DrvText drvKey = {key, keyLen};
    DrvText drvValue = {value, valueLen};
    status_t setStatus = DdbSetValue(ddbConn, &drvKey, &drvValue, option);
    RestDdbConn(ddbConn, setStatus, NULL);
    if (setStatus != CM_SUCCESS) {
        const char *errMsg = DdbGetLastError(ddbConn);
        write_runlog(ERROR, "Failed to set key (%s) value (%s) to ddb, error msg is %s.\n", key, value, errMsg);
    }
    return setStatus;
}

status_t DelKeyInDdb(char *key, uint32 keyLen)
{
    DdbConn *ddbConn = GetNextDdbConn();
    CM_RETERR_IF_NULL(ddbConn);
    DrvText drvKey = {key, keyLen};
    status_t delStatus = DdbDelKey(ddbConn, &drvKey);
    RestDdbConn(ddbConn, delStatus, NULL);
    if (delStatus != CM_SUCCESS) {
        const char *errMsg = DdbGetLastError(ddbConn);
        write_runlog(ERROR, "Failed to del key (%s) in ddb, error msg is %s.\n", key, errMsg);
    }
    return delStatus;
}

status_t GetKVWithCon(DdbConn *ddbConn, const char *key, char *value, uint32 valueLen, DDB_RESULT *ddbResult)
{
    CM_RETERR_IF_NULL(ddbConn);
    char tmpKey[MAX_PATH_LEN] = {0};
    errno_t rc = snprintf_s(tmpKey, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s", key);
    securec_check_intval(rc, (void)rc);
    DrvText drvKey = {tmpKey, MAX_PATH_LEN};
    DrvText drvValue = {value, valueLen};
    DDB_RESULT dbState = GetKVInDDb(ddbConn, &drvKey, &drvValue);
    if (ddbResult != NULL) {
        *ddbResult = dbState;
    }
    RestDdbConn(ddbConn, CM_SUCCESS, &dbState);
    if (dbState != SUCCESS_GET_VALUE) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t GetKVConAndLog(DdbConn *ddbConn, const char *key, char *value, uint32 valueLen, DdbOption *option)
{
    CM_RETERR_IF_NULL(ddbConn);
    char tmpKey[MAX_PATH_LEN] = {0};
    errno_t rc = snprintf_s(tmpKey, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s", key);
    securec_check_intval(rc, (void)rc);
    DrvText drvKey = {tmpKey, MAX_PATH_LEN};
    DrvText drvValue = {value, valueLen};
    DDB_RESULT dbState = SUCCESS_GET_VALUE;
    if (option != NULL) {
        dbState = GetKVInDDb(ddbConn, &drvKey, &drvValue, option->logLevel);
    } else {
        dbState = GetKVInDDb(ddbConn, &drvKey, &drvValue);
    }
    RestDdbConn(ddbConn, CM_SUCCESS, &dbState);
    if (option != NULL) {
        option->ddbResult = dbState;
    }
    if (dbState != SUCCESS_GET_VALUE) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t SetKVWithConn(DdbConn *ddbConn, char *key, uint32 keyLen, char *value, uint32 valueLen)
{
    if (g_inMaintainMode) {
        write_runlog(DEBUG1, "in maintain mode, can't set kv.\n");
        return CM_ERROR;
    }
    CM_RETERR_IF_NULL(ddbConn);
    DrvText drvKey = {key, keyLen};
    DrvText drvValue = {value, valueLen};
    status_t setStatus = DdbSetValue(ddbConn, &drvKey, &drvValue, NULL);
    RestDdbConn(ddbConn, setStatus, NULL);
    if (setStatus != CM_SUCCESS) {
        const char *errMsg = DdbGetLastError(ddbConn);
        write_runlog(ERROR, "Failed to set key (%s) value (%s) to ddb, error msg is %s.\n", key, value, errMsg);
    }
    RestDdbConn(ddbConn, setStatus, NULL);
    return setStatus;
}

status_t DelKeyWithConn(DdbConn *ddbConn, char *key, uint32 keyLen)
{
    CM_RETERR_IF_NULL(ddbConn);
    DrvText drvKey = {key, keyLen};
    status_t delStatus = DdbDelKey(ddbConn, &drvKey);
    if (delStatus != CM_SUCCESS) {
        const char *errMsg = DdbGetLastError(ddbConn);
        write_runlog(ERROR, "Failed to del key (%s) in ddb, error msg is %s.\n", key, errMsg);
    }
    RestDdbConn(ddbConn, delStatus, NULL);
    return delStatus;
}

void PrintKeyValueMsg(const char *initKey, const DrvKeyValue *keyValue, size_t length, int32 logLevel)
{
    if (logLevel > log_min_messages) {
        return;
    }
    if (keyValue == NULL) {
        return;
    }
    errno_t rc = 0;
    char allKeyValue[DDB_MAX_KEY_VALUE_LEN] = {0};
    size_t sizeLen = 0;
    for (uint32 i = 0; i < length; ++i) {
        sizeLen = strlen(allKeyValue);
        if (sizeLen >= DDB_MAX_KEY_VALUE_LEN) {
            break;
        }
        rc = snprintf_s(allKeyValue + sizeLen, DDB_MAX_KEY_VALUE_LEN - sizeLen,
            DDB_MAX_KEY_VALUE_LEN - 1 - sizeLen, "%s: %s; ", keyValue[i].key, keyValue[i].value);
        securec_check_intval(rc, (void)rc);
    }
    write_runlog(logLevel, "get value from ddb by key[%s], and result_key_value is [%s].\n", initKey, allKeyValue);
}

status_t GetAllKVFromDDb(char *key, uint32 keyLen, DrvKeyValue *keyValue, uint32 len, DDB_RESULT *ddbResult)
{
    DdbConn *ddbConn = GetNextDdbConn();
    CM_RETERR_IF_NULL(ddbConn);
    DrvText drvKey = {key, keyLen};
    status_t getStatus = DdbGetAllKV(ddbConn, &drvKey, keyValue, len, NULL);
    int32 logLevel = (g_HA_status->local_role == CM_SERVER_PRIMARY) ? ERROR : DEBUG1;
    if (getStatus != CM_SUCCESS) {
        const char *errMsg = DdbGetLastError(ddbConn);
        if (strstr(errMsg, "can't find the key") != NULL) {
            write_runlog(DEBUG1, "can not find the key(%s), error msg is %s.\n", key, errMsg);
            if (ddbResult != NULL) {
                *ddbResult = CAN_NOT_FIND_THE_KEY;
            }
        } else {
            write_runlog(logLevel, "Failed to get all value from DDb with key(%s), error msg is %s.\n", key, errMsg);
            if (ddbResult != NULL) {
                *ddbResult = FAILED_GET_VALUE;
            }
        }
    } else {
        if (ddbResult != NULL) {
            *ddbResult = SUCCESS_GET_VALUE;
        }
    }
    RestDdbConn(ddbConn, getStatus, ddbResult);
    return getStatus;
}

status_t SaveAllKVFromDDb(DDB_RESULT *ddbResult, DrvSaveOption *option)
{
    DdbConn *ddbConn = GetNextDdbConn();
    CM_RETERR_IF_NULL(ddbConn);
    DrvText drvKey = {const_cast<char*>(""), 0};
    status_t getStatus = DdbSaveAllKV(ddbConn, &drvKey, option);
    int32 logLevel = (g_HA_status->local_role == CM_SERVER_PRIMARY) ? ERROR : DEBUG1;
    if (getStatus != CM_SUCCESS) {
        const char *errMsg = DdbGetLastError(ddbConn);
        write_runlog(logLevel, "Failed to save all value from DDb, error msg is %s.\n", errMsg);
        if (strstr(errMsg, "can't find the key") != NULL) {
            write_runlog(logLevel, "can not find the key, error msg is %s.\n", errMsg);
            if (ddbResult != NULL) {
                *ddbResult = CAN_NOT_FIND_THE_KEY;
            }
        } else {
            if (ddbResult != NULL) {
                *ddbResult = FAILED_GET_VALUE;
            }
        }
    } else {
        if (ddbResult != NULL) {
            *ddbResult = SUCCESS_GET_VALUE;
        }
    }
    RestDdbConn(ddbConn, getStatus, ddbResult);
    return getStatus;
}

static DDB_RESULT GetKVInDDb(DdbConn *ddbConn, DrvText *drvKey, DrvText *drvValue, int32 logLevel)
{
    status_t getStatus = DdbGetValue(ddbConn, drvKey, drvValue, NULL);
    if (getStatus != CM_SUCCESS) {
        const char *errMsg = DdbGetLastError(ddbConn);
        if (logLevel == -1) {
            logLevel = (g_HA_status->local_role == CM_SERVER_PRIMARY) ? ERROR : DEBUG1;
        }
        if (strstr(errMsg, "can't find the key") != NULL) {
            write_runlog(logLevel, "can not find the key(%s), error msg is %s.\n", drvKey->data, errMsg);
            return CAN_NOT_FIND_THE_KEY;
        } else {
            write_runlog(
                logLevel, "Failed to get value from DDb with key(%s), error msg is %s.\n", drvKey->data, errMsg);
            return FAILED_GET_VALUE;
        }
    } else {
        if (logLevel == -1) {
            logLevel = DEBUG1;
        }
        if (logLevel == ERROR) {
            logLevel = LOG;
        }
        write_runlog(logLevel, "sucessfully get key_value(%s: %s) from DDb .\n", drvKey->data, drvValue->data);
        return SUCCESS_GET_VALUE;
    }
}

bool IsDdbHealth(DDB_CHECK_MOD checkMod)
{
    DdbConn *ddbConn = GetNextDdbConn();
    if (ddbConn == NULL) {
        write_runlog(ERROR, "%s:%d ddbConn is NULL.\n", __FUNCTION__, __LINE__);
        return false;
    }
    return DdbIsValid(ddbConn, checkMod);
}

void ClearDdbNodeInfo(const DdbConn *ddbConn)
{
    DdbFreeNodeInfo(ddbConn);
}

static int32 CmpForCmInstInfo(const void *a, const void *b)
{
    return ((int32)(((const InstInfo *)a)->instd) - (int32)(((const InstInfo *)b)->instd));
}

status_t CreateCmsInstInfo(void)
{
    if (g_cm_server_num > CM_PRIMARY_STANDBY_NUM) {
        write_runlog(ERROR, "cannot create cmsInstInfo, because cm_server_num is %u, but max cms num is %d.\n",
            g_cm_server_num, CM_PRIMARY_STANDBY_NUM);
        return CM_ERROR;
    }
    uint32 nodeIdx = 0;
    for (uint32 i = 0; i < g_cm_server_num; ++i) {
        nodeIdx = g_nodeIndexForCmServer[i];
        g_cmsInstInfo[i].nodeIdx = nodeIdx;
        g_cmsInstInfo[i].instd = g_node[nodeIdx].cmServerId;
        g_cmsInstInfo[i].nodeId = g_node[nodeIdx].node;
    }

    /* sort for g_cmsInstInfo by instd */
#undef qsort
    qsort(g_cmsInstInfo, g_cm_server_num, sizeof(InstInfo), CmpForCmInstInfo);
    char str[MAX_PATH_LEN] = {0};
    size_t len = 0;
    errno_t rc = 0;
    for (uint32 i = 0; i < g_cm_server_num; ++i) {
        len = strlen(str);
        if (len >= MAX_PATH_LEN) {
            break;
        }
        rc = snprintf_s(str + len, MAX_PATH_LEN - len, MAX_PATH_LEN - 1 - len, "%u:%u:%u, ", g_cmsInstInfo[i].instd,
            g_cmsInstInfo[i].nodeId, g_cmsInstInfo[i].nodeIdx);
        securec_check_intval(rc, (void)rc);
    }
    write_runlog(LOG, "g_cmsInstInfo is %s.\n", str);
    return CM_SUCCESS;
}

static bool IsCurrentNodeInVoteAZ()
{
    uint32 azPriority = g_currentNode->azPriority;
    for (int i = 0; i < AZ_MEMBER_MAX_COUNT; ++i) {
        if (azPriority == g_cmAzInfo[i].azPriority && g_cmAzInfo[i].isVoteAz == IS_VOTE_AZ) {
            write_runlog(LOG, "this current cms in vote AZ, cannot promote primary.\n");
            return true;
        }
    }
    return false;
}

status_t InitDdbArbitrate(DrvApiInfo *drvApiInfo)
{
    if (g_dbType != DB_ETCD && g_dbType != DB_SHAREDISK) {
        return CM_SUCCESS;
    }

    g_ddbArbiCon.getPreConnCount = getPreConnCount;
    g_ddbArbiCon.resetPreConn = resetPreConn;
    g_ddbArbiCon.arbiCfg = &(g_ddbArbicfg);
    g_ddbArbiCon.instInfo = g_cmsInstInfo;
    g_ddbArbiCon.instNum = g_cm_server_num;
    g_ddbArbiCon.userName = pw->pw_name;
    g_ddbArbiCon.curInfo.instd = g_currentNode->cmServerId;
    g_ddbArbiCon.curInfo.nodeId = g_currentNode->node;
    uint32 i;
    for (i = 0; i < g_cm_server_num; ++i) {
        if (g_cmsInstInfo[i].instd == g_ddbArbiCon.curInfo.instd) {
            g_ddbArbiCon.curInfo.nodeIdx = g_cmsInstInfo[i].nodeIdx;
            g_ddbArbiCon.curInfo.instIdx = i;
            g_ddbArbiCon.curInfo.isVoteAz = IsCurrentNodeInVoteAZ();
        }
    }
    if (i != g_cm_server_num) {
        write_runlog(ERROR, "cannot find current node(%u:%u) idx.\n", g_currentNode->cmServerId, g_currentNode->node);
        return CM_ERROR;
    }
    drvApiInfo->cmsArbiCon = &g_ddbArbiCon;
    return CM_SUCCESS;
}

void NotifyDdb(DDB_ROLE dbRole)
{
    DdbConn *ddbConn = GetNextDdbConn();
    if (ddbConn == NULL) {
        write_runlog(ERROR, "%s:%d ddbConn is NULL.\n", __FUNCTION__, __LINE__);
        return;
    }
    DdbNotify(ddbConn, dbRole);
}

void SetDdbMinority(bool isMinority)
{
    DdbConn *ddbConn = GetNextDdbConn();
    if (ddbConn == NULL) {
        write_runlog(ERROR, "%s:%d ddbConn is NULL.\n", __FUNCTION__, __LINE__);
        return;
    }
    DdbSetMinority(ddbConn, isMinority);
}

Alarm* GetDdbAlarm(int index)
{
    DdbConn *ddbConn = GetNextDdbConn();
    if (ddbConn == NULL) {
        write_runlog(ERROR, "%s:%d ddbConn is NULL.\n", __FUNCTION__, __LINE__);
        return NULL;
    }
    return DdbGetAlarm(ddbConn, index);
}


bool IsNeedSyncDdb(void)
{
    if (g_dbType == DB_ETCD) {
        if (g_etcd_num == 0) {
            return false;
        }
    }
    return g_dbType != DB_DCC || g_cm_server_num > 1;
}

bool DdbLeaderInAz(const char *azName, uint32 *nodeId)
{
    DdbConn *ddbConn = GetNextDdbConn();
    if (ddbConn == NULL) {
        write_runlog(ERROR, "%s:%d ddbConn is NULL.\n", __FUNCTION__, __LINE__);
        return false;
    }
    NodeIdInfo idInfo = {0};
    status_t st = DdbLeaderNodeId(ddbConn, &idInfo, azName);
    if (st != CM_SUCCESS) {
        if (azName != NULL) {
            write_runlog(LOG, "cannot find ddb leader in az(%s).\n", azName);
        } else {
            write_runlog(LOG, "cannot find ddb leader.\n");
        }
        return false;
    }
    *nodeId = idInfo.nodeId;
    return true;
}

bool IsInteractWithDdb(bool checkMinority, bool checkEtcd)
{
    if (g_dbType == DB_ETCD) {
        if (checkEtcd && g_etcd_num == 0) {
            return false;
        }
        if (!checkMinority) {
            return true;
        }
        if (cm_server_start_mode == MINORITY_START || cm_server_start_mode == OTHER_MINORITY_START) {
            return false;
        }
    }
    return true;
}

bool IsSyncDdbWithArbiMode()
{
    if (g_dbType == DB_ETCD) {
        if (g_etcd_num > 0 && cm_arbitration_mode == MAJORITY_ARBITRATION) {
            return true;
        }
        return false;
    }
    return true;
}

bool IsAzInUsefulAz(const char *azNames, const char *curAzName)
{
    if (azNames == NULL || curAzName == NULL) {
        return true;
    }
    if (strcmp(curAzName, azNames) == 0) {
        return true;
    }
    return false;
}

void SetServerSocketWithEtcdInfo(ServerSocket *server, staticNodeConfig *curNode)
{
    server->nodeIdInfo.azName = curNode->azName;
    server->nodeIdInfo.nodeId = curNode->node;
    server->nodeIdInfo.instd = curNode->etcdId;
    server->nodeInfo.nodeName = curNode->etcdName;
    server->nodeInfo.len = CM_NODE_NAME;
    server->host = curNode->etcdClientListenIPs[0];
    server->port = curNode->etcdClientListenPort;
}

/**
 * @brief To balance the load of etcd on the first node, setting IPs and listen port based on node id.
 *        If the id is odd, setting info from the start to the end, vice versa.
 *
 * @param  server           My Param doc
 */
void EtcdIpPortInfoBalance(ServerSocket *server, const char *azNames)
{
    uint32 j = 0;
    if (g_currentNode->cmServerId % 2 == 1) {
        for (uint32 i = 0; i < g_node_num; i++) {
            if (!g_node[i].etcd) {
                continue;
            }
            if (!IsAzInUsefulAz(azNames, g_node[i].azName)) {
                continue;
            }
            SetServerSocketWithEtcdInfo(&server[j], &g_node[i]);
            ++j;
        }
    } else {
        for (int32 ii = (int32)(g_node_num - 1); ii >= 0; ii--) {
            if (!g_node[ii].etcd) {
                continue;
            }
            if (!IsAzInUsefulAz(azNames, g_node[ii].azName)) {
                continue;
            }
            SetServerSocketWithEtcdInfo(&server[j], &g_node[ii]);
            ++j;
        }
    }
}

status_t SetDdbWorkMode(unsigned int workMode, unsigned int voteNum)
{
    DdbConn *ddbConn = GetNextDdbConn();
    if (ddbConn == NULL) {
        write_runlog(ERROR, "%s:%d ddbConn is NULL.\n", __FUNCTION__, __LINE__);
        return CM_ERROR;
    }
    return SetDdbWorkModeInDDb(ddbConn, workMode, voteNum);
}

status_t DemoteDdbRole2Standby()
{
    DdbConn *ddbConn = GetNextDdbConn();
    if (ddbConn == NULL) {
        write_runlog(ERROR, "%s:%d ddbConn is NULL.\n", __FUNCTION__, __LINE__);
        return CM_ERROR;
    }
    return DemoteDdbRole2StandbyInDDb(ddbConn);
}

static status_t InitEtcdServerList(DrvApiInfo *drvApiInfo, const char *azNames)
{
    size_t len = (g_etcd_num + 1) * sizeof(ServerSocket);
    ServerSocket *server = (ServerSocket *)malloc(len);
    if (server == NULL) {
        write_runlog(FATAL, "out of memory!\n");
        return CM_ERROR;
    }
    errno_t rc = memset_s(server, len, 0, len);
    securec_check_errno(rc, FREE_AND_RESET(server));

    EtcdIpPortInfoBalance(server, azNames);
    server[g_etcd_num].host = NULL;

    drvApiInfo->serverList = server;
    drvApiInfo->serverLen = g_etcd_num + 1;
    drvApiInfo->nodeNum = g_etcd_num;
    return CM_SUCCESS;
}

static void SetServerSocketWithDccInfo(ServerSocket *server, staticNodeConfig *curNode)
{
    server->nodeIdInfo.nodeId = curNode->node;
    server->nodeIdInfo.azName = curNode->azName;
    server->nodeIdInfo.instd = curNode->cmServerId;
    server->nodeInfo.nodeName = curNode->nodeName;
    server->nodeInfo.len = CM_NODE_NAME;
    server->host = curNode->cmServerLocalHAIP[0];
    server->port = curNode->cmServerLocalHAPort;
}

void CmsIpPortInfoBalance(ServerSocket *server)
{
    uint32 idx = 0;
    for (uint32 i = 0; i < g_node_num; ++i) {
        if (g_node[i].cmServerLevel != 1) {
            continue;
        }
        SetServerSocketWithDccInfo(&server[idx], &(g_node[i]));
        ++idx;
    }
}

static status_t InitDccServerList(DrvApiInfo *drvApiInfo)
{
    size_t len = (g_cm_server_num + 1) * sizeof(ServerSocket);
    ServerSocket *server = (ServerSocket *)malloc(len);
    if (server == NULL) {
        write_runlog(FATAL, "out of memory!\n");
        return CM_ERROR;
    }
    errno_t rc = memset_s(server, len, 0, len);
    securec_check_errno(rc, FREE_AND_RESET(server));
    CmsIpPortInfoBalance(server);
    server[g_cm_server_num].host = NULL;
    drvApiInfo->serverList = server;
    drvApiInfo->serverLen = g_cm_server_num + 1;
    drvApiInfo->nodeNum = g_cm_server_num;
    return CM_SUCCESS;
}

static status_t InitShareDisk(DrvApiInfo *drvApiInfo)
{
    int ret = strcpy_s(drvApiInfo->sdConfig.devPath, DDB_MAX_PATH_LEN, g_shareDiskPath);
    if (ret != 0) {
        write_runlog(ERROR, "Get share disk path failed!\n");
        return CM_ERROR;
    }
    write_runlog(LOG, "InitShareDisk: get config share disk path %s!\n", g_shareDiskPath);
    drvApiInfo->serverList = NULL;
    drvApiInfo->sdConfig.offset = DDB_DISK_ORIGINAL_OFFSET;
    drvApiInfo->sdConfig.instanceId = g_currentNode->cmServerId;
    drvApiInfo->nodeNum = g_cm_server_num;
    drvApiInfo->sdConfig.waitTime = (int64)((int32)g_cm_server_num * cmserver_demote_delay_on_conn_less);
    return CM_SUCCESS;
}

static void InitDdbClientCfg(DDB_TYPE dbType, DrvApiInfo *drvApiInfo)
{
    if (dbType != DB_ETCD) {
        return;
    }
    drvApiInfo->client_t.tlsPath = &g_tlsPath;
    drvApiInfo->client_t.waitTime = (int64)((int32)g_cm_server_num * cmserver_demote_delay_on_conn_less);
}

int32 CmsNotifyStatus(DDB_ROLE roleType)
{
    g_ddbRole = roleType;
    return 0;
}

static void GetServerLogPath(DrvApiInfo *drvApiInfo)
{
    uint32 i = 0;
    uint32 idx = 0;
    errno_t rc = 0;
    char logPath[MAX_PATH_LEN] = {0};
    int32 rcs = cmserver_getenv("GAUSSLOG", logPath, MAX_PATH_LEN, ERROR);
    if (rcs == EOK) {
        check_input_for_security(logPath);
        write_runlog(LOG, "successfully to get GAUSSLOG(%s) from env.\n", logPath);
        rc = snprintf_s(drvApiInfo->server_t.logPath, DDB_MAX_PATH_LEN, DDB_MAX_PATH_LEN - 1, "%s/cm", logPath);
        securec_check_intval(rc, (void)rc);
        return;
    }
    write_runlog(ERROR, "cannot get GAUSSLOG(%s) from env.\n", logPath);
    while (i < MAX_PATH_LEN && sys_log_path[i] != '\0' && (i + 1) < MAX_PATH_LEN) {
        if (sys_log_path[i] == '/' && sys_log_path[i + 1] != '\0') {
            idx = i;
        }
        ++i;
    }
    rc = memcpy_s(drvApiInfo->server_t.logPath, DDB_MAX_PATH_LEN - 1, sys_log_path, (size_t)idx);
    securec_check_errno(rc, (void)rc);
}

static status_t GetSslFilePath(SslConfig *sslcfg)
{
    char homePath[MAX_PATH_LEN] = {0};
    if (GetHomePath(homePath, MAX_PATH_LEN) != 0) {
        return CM_ERROR;
    }

    char certFilePath[MAX_PATH_LEN] = {0};
    errno_t rc = snprintf_s(certFilePath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/share/sslcert/cm", homePath);
    securec_check_intval(rc, (void)rc);

    TlsAuthPath *sslPath = &(sslcfg->sslPath);
    rc = snprintf_s(sslPath->caFile, DDB_MAX_PATH_LEN, DDB_MAX_PATH_LEN - 1, "%s/cacert.pem", certFilePath);
    securec_check_intval(rc, (void)rc);

    rc = snprintf_s(sslPath->crtFile, DDB_MAX_PATH_LEN, DDB_MAX_PATH_LEN - 1, "%s/server.crt", certFilePath);
    securec_check_intval(rc, (void)rc);

    rc = snprintf_s(sslPath->keyFile, DDB_MAX_PATH_LEN, DDB_MAX_PATH_LEN - 1, "%s/server.key", certFilePath);
    securec_check_intval(rc, (void)rc);
    return CM_SUCCESS;
}

static status_t CheckSslFileExit(const SslConfig *sslcfg)
{
    if (!CmFileExist(sslcfg->sslPath.caFile)) {
        write_runlog(DEBUG5, "cms_init_ssl ca_file is not exist.\n");
        return CM_ERROR;
    }

    if (!CmFileExist(sslcfg->sslPath.keyFile)) {
        write_runlog(DEBUG5, "cms_init_ssl key_file is not exist.\n");
        return CM_ERROR;
    }

    if (!CmFileExist(sslcfg->sslPath.crtFile)) {
        write_runlog(DEBUG5, "cms_init_ssl Crt_File is not exist.\n");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t GetSslConfig(DrvApiInfo *drvApiInfo)
{
    if (g_sslOption.enable_ssl == CM_FALSE) {
        write_runlog(LOG, "enable ssl is off.\n");
        drvApiInfo->server_t.sslcfg.enableSsl = false;
        return CM_SUCCESS;
    }
    SslConfig *sslCfg = &(drvApiInfo->server_t.sslcfg);
    status_t st = GetSslFilePath(sslCfg);
    if (st != CM_SUCCESS) {
        write_runlog(ERROR, "Failed to get ssl file path.\n");
        return CM_ERROR;
    }
    st = CheckSslFileExit(sslCfg);
    if (st != CM_SUCCESS) {
        write_runlog(LOG, "ssl file does not exist.\n");
        drvApiInfo->server_t.sslcfg.enableSsl = false;
        return CM_ERROR;
    }

    sslCfg->expireTime = g_sslOption.expire_time;
    sslCfg->enableSsl = true;
    return CM_SUCCESS;
}

static status_t InitDdbServerCfg(DDB_TYPE dbType, DrvApiInfo *drvApiInfo)
{
    if (dbType != DB_DCC) {
        return CM_SUCCESS;
    }
    drvApiInfo->server_t.curServer.nodeIdInfo.instd = g_currentNode->cmServerId;
    drvApiInfo->server_t.curServer.host = g_currentNode->cmServerLocalHAIP[0];
    drvApiInfo->server_t.curServer.port = g_currentNode->cmServerLocalHAPort;
    drvApiInfo->server_t.dataPath = g_currentNode->cmDataPath;
    drvApiInfo->server_t.waitTime = (int64)((int32)g_cm_server_num * cmserver_demote_delay_on_conn_less);
    GetServerLogPath(drvApiInfo);
    return GetSslConfig(drvApiInfo);
}

void ClearDdbCfgApi(DrvApiInfo *drvApiInfo, DDB_TYPE dbType)
{
    FREE_AND_RESET(drvApiInfo->serverList);
    if (dbType != DB_DCC) {
        return;
    }
    errno_t rc = memset_s(&(drvApiInfo->server_t.sslcfg), sizeof(SslConfig), 0, sizeof(SslConfig));
    securec_check_errno(rc, (void)rc);
}

status_t InitDdbCfgApi(DDB_TYPE dbType, DrvApiInfo *drvApiInfo, int32 timeOut, const char *azNames)
{
    status_t st;
    switch (dbType) {
        case DB_ETCD:
            st = InitEtcdServerList(drvApiInfo, azNames);
            break;
        case DB_DCC:
            st = InitDccServerList(drvApiInfo);
            break;
        case DB_SHAREDISK:
            st = InitShareDisk(drvApiInfo);
            break;
        case DB_UNKOWN:
        default:
            write_runlog(ERROR, "undefined ddbtype(%d).\n", dbType);
            return CM_ERROR;
    }
    if (st != CM_SUCCESS) {
        ClearDdbCfgApi(drvApiInfo, dbType);
        return CM_ERROR;
    }
    drvApiInfo->modId = MOD_CMS;
    drvApiInfo->nodeId = g_currentNode->node;
    drvApiInfo->timeOut = timeOut;

    InitDdbClientCfg(dbType, drvApiInfo);
    st = InitDdbServerCfg(dbType, drvApiInfo);
    if (st != CM_SUCCESS) {
        write_runlog(ERROR, "failed to init ddb server, cms will exit.\n");
        ClearDdbCfgApi(drvApiInfo, dbType);
        return CM_ERROR;
    }
    st = InitDdbArbitrate(drvApiInfo);
    if (st != CM_SUCCESS) {
        ClearDdbCfgApi(drvApiInfo, dbType);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static void InitDdbConfig(DdbInitConfig *config)
{
    errno_t rc = memset_s(config, sizeof(DdbInitConfig), 0, sizeof(DdbInitConfig));
    securec_check_errno(rc, (void)rc);
    config->type = g_dbType;
}

status_t GetDdbSession(CM_ConnDdbInfo *session, int32 timeOut, const char *azNames)
{
    DdbInitConfig config;
    InitDdbConfig(&config);
    status_t st = InitDdbCfgApi(config.type, &(config.drvApiInfo), timeOut, azNames);
    if (st != CM_SUCCESS) {
        ClearDdbCfgApi(&(config.drvApiInfo), g_dbType);
        return CM_ERROR;
    }

    for (uint32 i = 0; i < session->count; ++i) {
        st = InitDdbConn(&(session->ddbConn[i]), &config);
        if (st != CM_SUCCESS) {
            for (uint j = 0; j < i; j++) {
                CloseDdbSession(&(session->ddbConn[j]));
            }
            ClearDdbCfgApi(&(config.drvApiInfo), g_dbType);
            StopDdbByDrv();
            return CM_ERROR;
        }
    }
    ClearDdbCfgApi(&(config.drvApiInfo), g_dbType);
    return CM_SUCCESS;
}

static status_t CreateGtm2etcdSession()
{
    if (g_gtm_num == 0 || g_etcd_num == 0 || g_dbType == DB_ETCD) {
        return CM_SUCCESS;
    }
    DdbInitConfig config;
    errno_t rc = memset_s(&config, sizeof(DdbInitConfig), 0, sizeof(DdbInitConfig));
    securec_check_errno(rc, (void)rc);
    config.type = DB_ETCD;
    status_t st = InitDdbCfgApi(config.type, &(config.drvApiInfo), DDB_DEFAULT_TIMEOUT, NULL);
    CM_RETURN_IFERR(st);
    st = InitDdbConn(&g_gtm2Etcd, &config);
    ClearDdbCfgApi(&(config.drvApiInfo), DB_ETCD);
    if (st != CM_SUCCESS) {
        write_runlog(ERROR, "can not create ddb(etcd) conn for gtm, error is %s.\n", DdbGetLastError(&g_gtm2Etcd));
    }
    return st;
}

status_t ServerDdbInit()
{
    if (g_dbType == DB_ETCD && g_etcd_num == 0 && g_cm_server_num > 1) {
        write_runlog(LOG, "dbType is etcd, but etcd_num is 0, will change to dcc.\n");
        g_dbType = DB_DCC;
    }
    if (!IsInteractWithDdb(false, true)) {
        return CM_SUCCESS;
    }
    g_sess = &g_ddbSession;

    // divide 10 just to avoid creating too many conn to ddb if cmserver node number is too large
    uint32 connNum = g_node_num / CM_TEN_DIVISOR + CM_MIN_CONN_TO_DDB;
    if (connNum > CM_MAX_CONN_TO_DDB) {
        connNum = CM_MAX_CONN_TO_DDB;
    }

    g_sess->count = connNum;
    errno_t rc = memset_s(g_sess->ddbConn, sizeof(g_sess->ddbConn), 0, sizeof(g_sess->ddbConn));
    securec_check_errno(rc, (void)rc);
    if (GetDdbSession(g_sess, DDB_DEFAULT_TIMEOUT, NULL) != CM_SUCCESS) {
        ClearDdbNodeInfo(&(g_sess->ddbConn[0]));
        return CM_ERROR;
    }
    write_runlog(LOG, "Init ddb connection success, connect to ddb num is %u.\n", g_sess->count);
    if (CreateGtm2etcdSession() != CM_SUCCESS) {
        CloseAllDdbSession();
        return CM_ERROR;
    }
    LoadDdbParamterFromConfig();
    return CM_SUCCESS;
}

DdbConn *GetNextDdbConn()
{
    if (g_sess == NULL || g_sess->count == 0) {
        return NULL;
    }
    if (g_sess->curIdx > g_sess->count) {
        g_sess->curIdx %= g_sess->count;
    }
    uint32 idx = 0;
    for (uint32 i = 0; i < g_sess->count; ++i) {
        idx = (g_sess->curIdx + i) % g_sess->count;
        if (g_sess->ddbConn[idx].state != PROCESS_IN_RUNNING) {
            break;
        }
    }
    g_sess->curIdx = (idx + 1) % g_sess->count;
    return &(g_sess->ddbConn[idx]);
}

static void PrintDdbLog(DdbConn *ddbConn, status_t st, const char *str, const char *msg)
{
    if (ddbConn == NULL || ddbConn->drv == NULL) {
        write_runlog(LOG, "%s: %s execute the result is %d.\n", str, msg, (int32)st);
        return;
    }

    if (st != CM_SUCCESS) {
        /* Only print error info */
        const char *err = DdbGetLastError(ddbConn);
        write_runlog(
            WARNING, "%s: %s(%d: %s) failed, error is %s.\n", str, msg, ddbConn->drv->type, ddbConn->drv->msg, err);
    } else {
        write_runlog(LOG, "%s: %s(%d: %s) successfully.\n", str, msg, ddbConn->drv->type, ddbConn->drv->msg);
    }
}

void CloseDdbSession(DdbConn *ddbConn)
{
    if (DdbFreeConn(ddbConn) != CM_SUCCESS) {
        PrintDdbLog(ddbConn, CM_ERROR, "[CloseDdbSession]", "ddb close conn");
        return;
    }
    PrintDdbLog(ddbConn, CM_SUCCESS, "[CloseDdbSession]", "ddb close conn");
}

void CloseAllDdbSession()
{
    if (g_etcd_num == 0 && g_dbType == DB_ETCD) {
        return;
    }
    if (g_sess != NULL) {
        for (uint i = 0; i < g_sess->count; i++) {
            CloseDdbSession(&(g_sess->ddbConn[i]));
        }
        StopDdbByDrv();
    }
}

DdbConn *GetDdbConnFromGtm()
{
    if (g_gtm2Etcd.drv != NULL) {
        return &g_gtm2Etcd;
    }
    return GetNextDdbConn();
}

status_t DoDdbExecCmd(const char *cmd, char *output, int *outputLen, char *errMsg, uint32 maxBufLen)
{
    errno_t rc;
    if (g_dbType != DB_DCC && g_dbType != DB_SHAREDISK) {
        const char *dbStr = GetDdbToString(g_dbType);
        rc = snprintf_s(errMsg, ERR_MSG_LENGTH, ERR_MSG_LENGTH - 1,
            "current ddbType is %s, don't support this operation", dbStr);
        securec_check_intval(rc, (void)rc);
        write_runlog(ERROR, "current ddbType is %s, don't support this operation", dbStr);
        return CM_ERROR;
    }
    int cmdLen = (int)strlen(cmd);
    if (cmdLen > DCC_CMD_MAX_LEN) {
        write_runlog(ERROR, "ddb cmd is too long, len:%d.\n", cmdLen);
        return CM_ERROR;
    }
    DdbConn *ddbConn = GetNextDdbConn();

    if (ddbConn == NULL) {
        write_runlog(ERROR, "%s:%d ddbConn is NULL.\n", __FUNCTION__, __LINE__);
        return CM_ERROR;
    }

    if (DdbExecCmd(ddbConn, const_cast<char*>(cmd), output, outputLen, maxBufLen) != CM_SUCCESS) {
        /* Only print error info */
        const char *err = DdbGetLastError(ddbConn);
        rc = strcpy_s(errMsg, maxBufLen, err);
        securec_check_errno(rc, (void)rc);
        write_runlog(WARNING, "ddb exec cmd(%d: %s) failed, error: %s\n", ddbConn->drv->type, ddbConn->drv->msg, err);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t DoDdbSetBlocked(unsigned int setBlock, unsigned int waitTimeoutMs)
{
    DdbConn *ddbConn = GetNextDdbConn();
    if (ddbConn == NULL) {
        write_runlog(ERROR, "%s:%d ddbConn is NULL.\n", __FUNCTION__, __LINE__);
        return CM_ERROR;
    }
    status_t st = DdbSetBlocked(ddbConn, setBlock, waitTimeoutMs);
    if (st != CM_SUCCESS) {
        write_runlog(LOG, "cannot set ddb block mode.\n");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t SetDdbParam(const char *key, const char *value)
{
    DdbConn *ddbConn = GetNextDdbConn();
    if (ddbConn == NULL) {
        write_runlog(ERROR, "%s:%d ddbConn is NULL.\n", __FUNCTION__, __LINE__);
        return CM_ERROR;
    }
    return DDbSetParam(ddbConn, key, value);
}

void LoadDdbParamterFromConfig()
{
    if (g_dbType != DB_DCC) {
        return;
    }
    LoadParamterFromConfigWithPrefixKey(configDir, "ddb_", SetDdbParam);
}

static status_t SetDdbWorkModeInDDb(DdbConn *ddbConn, unsigned int workMode, unsigned int voteNum)
{
    if (g_dbType != DB_DCC) {
        const char *dbStr = GetDdbToString(g_dbType);
        write_runlog(ERROR, "current ddbType is %s, don't support this operation", dbStr);
        return CM_ERROR;
    }
    return DdbSetWorkMode(ddbConn, workMode, voteNum);
}

static status_t DemoteDdbRole2StandbyInDDb(DdbConn *ddbConn)
{
    if (g_dbType != DB_DCC) {
        const char *dbStr = GetDdbToString(g_dbType);
        write_runlog(ERROR, "current ddbType is %s, don't support this operation", dbStr);
        return CM_ERROR;
    }
    return DdbDemoteRole2Standby(ddbConn);
}
