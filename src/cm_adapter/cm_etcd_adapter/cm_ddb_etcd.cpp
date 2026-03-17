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
 * cm_ddb_etcd.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_adapter/cm_etcd_adapter/cm_ddb_etcd.cpp
 *
 * -------------------------------------------------------------------------
 */

#include "cm_ddb_etcd.h"
#include "alarm.h"
#include "cm/cm_elog.h"
#include "cm/cm_c.h"

uint32 g_etcdNum = 0;

static uint32 g_healthEtcdIndex[MAX_ETCD_NODE_NUM] = {0};
static bool g_healthEtcdFlag = false;
static uint32 g_healthEtcdCount = 0;
EtcdTlsAuthPath g_etcdTlsPath = {{0}};
int32 g_timeOut = 0;
static pthread_rwlock_t g_healthEtcdRwlock = PTHREAD_RWLOCK_INITIALIZER;
static ModuleId g_modId = MOD_ALL;
ServerSocket *g_etcdInfo = NULL;

static status_t EtcdLoadApi(const DrvApiInfo *apiInfo);

static DdbDriver g_drvEtcd = {PTHREAD_RWLOCK_INITIALIZER, false, DB_ETCD, "etcd conn", EtcdLoadApi};

static const int ABNORMAL_ETCD_ALARM_LIST_SIZE = 3;
static Alarm g_etcdAlarmList[ABNORMAL_ETCD_ALARM_LIST_SIZE];

enum AbnormalEtcdAlarmItem { ETCD_UNHEALTH = 0, ETCD_DOWN = 1, ETCD_NEAR_QUOTA = 2 };

/* init alarm info  for etcd */
void CmsEtcdAbnormalAlarmItemInitialize(void)
{
    errno_t rc = memset_s(g_etcdAlarmList, sizeof(g_etcdAlarmList), 0, sizeof(g_etcdAlarmList));
    securec_check_errno(rc, (void)rc);
    AlarmItemInitialize(&(g_etcdAlarmList[ETCD_UNHEALTH]), ALM_AI_AbnormalEtcdUnhealth, ALM_AS_Normal, NULL, 0, 0);
    AlarmItemInitialize(&(g_etcdAlarmList[ETCD_DOWN]), ALM_AI_AbnormalEtcdDown, ALM_AS_Normal, NULL, 0, 0);
    AlarmItemInitialize(&(g_etcdAlarmList[ETCD_NEAR_QUOTA]), ALM_AI_AbnormalEtcdNearQuota, ALM_AS_Normal, NULL);
}

static void PrintEtcdServerList(const EtcdServerSocket *etcdServerList, uint32 len, int32 logLevel)
{
    char serverStr[DDB_MAX_KEY_VALUE_LEN] = {0};
    size_t serverSize = 0;
    errno_t rc = 0;
    for (uint32 i = 0; i < len; ++i) {
        serverSize = strlen(serverStr);
        if (serverSize >= (DDB_MAX_KEY_VALUE_LEN - 1)) {
            break;
        }
        rc = snprintf_s(serverStr + serverSize, DDB_MAX_KEY_VALUE_LEN - serverSize,
            DDB_MAX_KEY_VALUE_LEN - 1 - serverSize, "%s:%u; ", etcdServerList[i].host, etcdServerList[i].port);
        securec_check_intval(rc, (void)rc);
    }
    write_runlog(logLevel, "etcdServerList is %s.\n", serverStr);
}

static status_t InitEtcdServerList(EtcdServerSocket **etcdServerList, const DrvApiInfo *apiInfo, uint32 len)
{
    if (len == 0) {
        write_runlog(ERROR, "InitEtcdServerList len is 0.\n");
        return CM_ERROR;
    }
    int32 logLevel = (apiInfo->modId == MOD_CMCTL) ? DEBUG5 : ((apiInfo->modId == MOD_CMS) ? LOG : DEBUG1);
    uint32 idx = 0;
    for (uint32 i = 0; i < apiInfo->serverLen; ++i) {
        if (apiInfo->serverList[i].host == NULL || apiInfo->serverList[i].port == 0) {
            break;
        }
        (*etcdServerList)[idx].host = apiInfo->serverList[i].host;
        (*etcdServerList)[idx].port = (unsigned short)apiInfo->serverList[i].port;
        ++idx;
    }
    if (idx == 0) {
        write_runlog(logLevel, "etcdServerList is empty.\n");
        FREE_AND_RESET((*etcdServerList));
        return CM_ERROR;
    }
    if (idx < len - 1) {
        (*etcdServerList)[idx + 1].host = NULL;
    }
    logLevel = (apiInfo->modId == MOD_CMCTL) ? DEBUG5 : DEBUG1;
    PrintEtcdServerList((*etcdServerList), idx, logLevel);
    return CM_SUCCESS;
}

status_t InitEtcdServerSocket(EtcdServerSocket **etcdServerList, const DrvApiInfo *apiInfo)
{
    int32 logLevel = (apiInfo->modId == MOD_CMCTL) ? DEBUG1 : LOG;
    size_t len = apiInfo->serverLen * sizeof(EtcdServerSocket);
    *etcdServerList = (EtcdServerSocket *)malloc(len);
    if (*etcdServerList == NULL) {
        write_runlog(logLevel, "etcdSeverList is null.\n");
        return CM_ERROR;
    }
    errno_t rc = memset_s(*etcdServerList, len, 0, len);
    securec_check_errno(rc, FREE_AND_RESET(*etcdServerList));
    status_t st = InitEtcdServerList(etcdServerList, apiInfo, apiInfo->serverLen);
    return st;
}

status_t CreateEtcdSession(EtcdSession *session, const DrvApiInfo *apiInfo)
{
    int32 logLevel = (apiInfo->modId == MOD_CMCTL) ? DEBUG5 : ((apiInfo->modId == MOD_CMS) ? LOG : DEBUG1);
    EtcdServerSocket *etcdServerList = NULL;
    status_t st = InitEtcdServerSocket(&etcdServerList, apiInfo);
    if (st != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (etcdServerList == NULL) {
        write_runlog(logLevel, "line %s:%d, etcdServerList is NULL.\n", __FUNCTION__, __LINE__);
        return CM_ERROR;
    }
    int32 res = etcd_open(session, etcdServerList, &g_etcdTlsPath, apiInfo->timeOut);
    FREE_AND_RESET(etcdServerList);
    if (res != (int32)ETCD_OK) {
        write_runlog(logLevel, "cannot open etcd conn, error is %s.\n", get_last_error());
        return CM_ERROR;
    }
    write_runlog(logLevel, "etcdSession is %d\n", *session);
    return CM_SUCCESS;
}

status_t DrvEtcdAllocConn(DrvCon_t *session, const DrvApiInfo *apiInfo)
{
    EtcdSession **etcdSession = (EtcdSession **)session;
    int32 logLevel = (apiInfo->modId == MOD_CMCTL) ? DEBUG1 : LOG;
    *etcdSession = (EtcdSession *)malloc(sizeof(EtcdSession));
    if (*etcdSession == NULL) {
        write_runlog(logLevel, "%s:%d Failed to malloc etcdSession.\n", __FUNCTION__, __LINE__);
        return CM_ERROR;
    }
    errno_t rc = memset_s(*etcdSession, sizeof(EtcdSession), 0, sizeof(EtcdSession));
    securec_check_errno(rc, (void)rc);
    status_t st = CreateEtcdSession(*etcdSession, apiInfo);
    if (st != CM_SUCCESS) {
        FREE_AND_RESET(*session);
    }
    return st;
}

static status_t DrvEtcdFreeConn(DrvCon_t *session)
{
    EtcdSession **etcdSession = (EtcdSession **)session;
    int32 res = etcd_close(**etcdSession);
    FREE_AND_RESET(*session);
    if (res != (int32)ETCD_OK) {
        write_runlog(ERROR, "Failed to close etcd, error is %s.\n", get_last_error());
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t DrvEtcdGetValue(const DrvCon_t session, DrvText *key, DrvText *value, const DrvGetOption *option)
{
    const EtcdSession *etcdSession = (const EtcdSession *)session;
    GetEtcdOption getOption = {false, false, true};
    if (option != NULL) {
        getOption.quorum = option->quorum;
    }
    int32 res = etcd_get(*etcdSession, key->data, value->data, (int32)value->len, &getOption);
    if (res != (int32)ETCD_OK) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t DrvEtcdGetAllKV(
    const DrvCon_t session, DrvText *key, DrvKeyValue *keyValue, uint32 length, const DrvGetOption *option)
{
    const EtcdSession *etcdSession = (const EtcdSession *)session;
    GetEtcdOption getOption = {false, false, true};
    if (option != NULL) {
        getOption.quorum = option->quorum;
    }
    char etcdKeyValue[DDB_MAX_KEY_VALUE_LEN] = {0};
    int32 res = EtcdGetAllValues(*etcdSession, key->data, etcdKeyValue, &getOption, DDB_MAX_KEY_VALUE_LEN);
    if (res != (int32)ETCD_OK) {
        return CM_ERROR;
    }
    write_runlog(
        DEBUG1, "get all values by cgo, and key is [%s], result_key_value is [%s].\n", key->data, etcdKeyValue);
    errno_t rc = 0;
    char *pLeft = NULL;
    char *pKey = strtok_r(etcdKeyValue, ",", &pLeft);
    char *pValue = strtok_r(NULL, ",", &pLeft);
    uint32 i = 0;
    while (pKey && pValue) {
        rc = snprintf_s(keyValue[i].key, DDB_KEY_LEN, DDB_KEY_LEN - 1, "%s", pKey);
        securec_check_intval(rc, (void)rc);
        rc = snprintf_s(keyValue[i].value, DDB_VALUE_LEN, DDB_VALUE_LEN - 1, "%s", pValue);
        securec_check_intval(rc, (void)rc);
        if (++i >= length) {
            break;
        }
        pKey = strtok_r(NULL, ",", &pLeft);
        pValue = strtok_r(NULL, ",", &pLeft);
    }
    if (i == 0) {
        write_runlog(
            ERROR, "get all values by cgo, and key is [%s], result_key_value is [%s].\n", key->data, etcdKeyValue);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t SaveAllKV(const char *key, size_t keyLen, const char *value, size_t valueLen, FILE *fp)
{
    if (fp == NULL) {
        write_runlog(ERROR, "line:%d, fp is NULL.\n", __LINE__);
        return CM_ERROR;
    }
    if (fwrite(key, keyLen, 1, fp) == 0) {
        write_runlog(ERROR, "line:%d, write kv file failed, key(%s).\n", __LINE__, key);
        return CM_ERROR;
    }
    if (fputc('\n', fp) == EOF) {
        write_runlog(ERROR, "line:%d, write kv file failed.\n", __LINE__);
        return CM_ERROR;
    }
    if (fwrite(value, valueLen, 1, fp) == 0) {
        write_runlog(ERROR, "line:%d, write kv file failed, key(%s).\n", __LINE__, value);
        return CM_ERROR;
    }
    if (fputc('\n', fp) == EOF) {
        write_runlog(ERROR, "line:%d, write kv file failed.\n", __LINE__);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t DrvEtcdSaveAllKV(const DrvCon_t session, const DrvText *key, DrvSaveOption *option)
{
    char *pLeft = NULL;
    char etcdKeyValue[DDB_MAX_KEY_VALUE_LEN] = {0};
    const EtcdSession *etcdSession = (const EtcdSession *)session;
    GetEtcdOption getOption = {false, false, true};

    if (EtcdGetAllValues(*etcdSession, key->data, etcdKeyValue, &getOption, DDB_MAX_KEY_VALUE_LEN) != (int32)ETCD_OK) {
        return CM_ERROR;
    }
    write_runlog(DEBUG1, "get all values by cgo, and key is \"\", result_key_value is [%s].\n", etcdKeyValue);
    char *pKey = strtok_r(etcdKeyValue, ",", &pLeft);
    char *pValue = strtok_r(NULL, ",", &pLeft);

    if (option->kvFile == NULL) {
        write_runlog(ERROR, "open kvs file is null.\n");
        return CM_ERROR;
    }

    canonicalize_path(option->kvFile);
    FILE *fp = fopen(option->kvFile, "w+");
    if (fp == NULL) {
        write_runlog(ERROR, "open kvs file \"%s\" failed.\n", option->kvFile);
        return CM_ERROR;
    }

    while (pKey && pValue) {
        if (SaveAllKV(pKey, strlen(pKey), pValue, strlen(pValue), fp) != CM_SUCCESS) {
            (void)fclose(fp);
            return CM_ERROR;
        }
        pKey = strtok_r(NULL, ",", &pLeft);
        pValue = strtok_r(NULL, ",", &pLeft);
    }
    (void)fclose(fp);

    return CM_SUCCESS;
}

status_t DrvEtcdSetKV(const DrvCon_t session, DrvText *key, DrvText *value, DrvSetOption *option)
{
    const EtcdSession *etcdSession = (const EtcdSession *)session;
    int32 res = 0;
    if (option == NULL) {
        res = etcd_set(*etcdSession, key->data, value->data, NULL);
    } else {
        SetEtcdOption setOption = {0};
        setOption.prevValue = option->preValue;
        res = etcd_set(*etcdSession, key->data, value->data, &setOption);
    }
    if (res != (int32)ETCD_OK) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t DrvEtcdDelKV(const DrvCon_t session, DrvText *key)
{
    const EtcdSession *etcdSession = (const EtcdSession *)session;
    int32 res = etcd_delete(*etcdSession, key->data, NULL);
    if (res != (int32)ETCD_OK) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t DrvEtcdNodeHealth(DrvCon_t session, char *memberName, DdbNodeState *nodeState)
{
    EtcdSession *etcdSession = (EtcdSession *)session;
    char health[ETCD_STATE_LEN] = {0};
    int32 res = etcd_cluster_health(*etcdSession, memberName, health, ETCD_STATE_LEN);
    if (res != (int)ETCD_OK) {
        nodeState->health = DDB_STATE_DOWN;
        return CM_ERROR;
    }
    if (strcmp(health, "healthy") != 0) {
        nodeState->health = DDB_STATE_DOWN;
        return CM_ERROR;
    }
    nodeState->health = DDB_STATE_HEALTH;
    return CM_SUCCESS;
}

status_t DrvEtcdNodeState(DrvCon_t session, char *memberName, DdbNodeState *nodeState)
{
    EtcdSession *etcdSession = (EtcdSession *)session;
    char health[ETCD_STATE_LEN] = {0};
    int32 res = etcd_cluster_health(*etcdSession, memberName, health, ETCD_STATE_LEN);
    if (res != (int32)ETCD_OK) {
        nodeState->health = DDB_STATE_DOWN;
        nodeState->role = DDB_ROLE_UNKNOWN;
        return CM_ERROR;
    }
    if (strcmp(health, "healthy") != 0) {
        nodeState->health = DDB_STATE_DOWN;
        nodeState->role = DDB_ROLE_UNKNOWN;
        return CM_ERROR;
    }
    nodeState->health = DDB_STATE_HEALTH;
    bool isLeader = false;
    res = etcd_cluster_state(*etcdSession, memberName, &isLeader);
    if (res != (int32)ETCD_OK) {
        nodeState->role = DDB_ROLE_UNKNOWN;
        return CM_ERROR;
    }
    if (isLeader) {
        nodeState->role = DDB_ROLE_LEADER;
    } else {
        nodeState->role = DDB_ROLE_FOLLOWER;
    }
    return CM_SUCCESS;
}

static status_t GetEtcdNodeHealth(uint32 idx, DdbNodeState *nodeState, int timeOut)
{
    int logLevel = (g_modId == MOD_CMCTL) ? DEBUG1 : ERROR;
    const uint32 serverLen = 2;
    EtcdServerSocket server[serverLen] = {{0}};
    server[0].host = g_etcdInfo[idx].host;
    server[0].port = (unsigned short)g_etcdInfo[idx].port;
    server[1].host = NULL;
    EtcdSession sess = 0;
    if (etcd_open(&sess, server, &g_etcdTlsPath, timeOut) != 0) {
        write_runlog(logLevel, "open etcd server %s failed: %s.\n", server[0].host, get_last_error());
        return CM_TIMEDOUT;
    }
    status_t st = DrvEtcdNodeHealth((DrvCon_t)(&sess), g_etcdInfo[idx].nodeInfo.nodeName, nodeState);
    if (etcd_close(sess) != 0) {
        write_runlog(logLevel, "line %s %d: cannot free conn, error is %s.\n", __FUNCTION__, __LINE__,
            get_last_error());
    }
    if (st == CM_ERROR) {
        write_runlog(logLevel, "line %s %d: cannot get ddbInstance, error is %s.\n", __FUNCTION__, __LINE__,
            get_last_error());
        return CM_ERROR;
    }
    return st;
}

static status_t GetEtcdNodeState(uint32 idx, DdbNodeState *nodeState)
{
    int logLevel = (g_modId == MOD_CMCTL) ? DEBUG1 : ERROR;
    const uint32 serverLen = 2;
    EtcdServerSocket server[serverLen] = {{0}};
    server[0].host = g_etcdInfo[idx].host;
    server[0].port = (unsigned short)g_etcdInfo[idx].port;
    server[1].host = NULL;
    EtcdSession sess = 0;
    if (etcd_open(&sess, server, &g_etcdTlsPath, g_timeOut) != 0) {
        write_runlog(logLevel, "open etcd server %s failed: %s.\n", server[0].host, get_last_error());
        return CM_TIMEDOUT;
    }
    status_t st = DrvEtcdNodeState((DrvCon_t)(&sess), g_etcdInfo[idx].nodeInfo.nodeName, nodeState);
    if (etcd_close(sess) != 0) {
        write_runlog(logLevel, "line %s %d: cannot free conn, error is %s.\n",
            __FUNCTION__, __LINE__, get_last_error());
    }
    if (st == CM_ERROR) {
        write_runlog(logLevel, "line %s %d: cannot get ddbInstance, error is %s.\n",
            __FUNCTION__, __LINE__, get_last_error());
        return CM_ERROR;
    }
    return st;
}

static status_t EtcdNodeIsHealth(uint32 idx, int timeOut)
{
    int logLevel = (g_modId == MOD_CMCTL) ? DEBUG1 : ERROR;
    DdbNodeState nodeState;
    errno_t rc = memset_s(&nodeState, sizeof(DdbNodeState), 0, sizeof(DdbNodeState));
    securec_check_errno(rc, (void)rc);
    status_t st = GetEtcdNodeHealth(idx, &nodeState, timeOut);
    if (st != CM_SUCCESS) {
        return st;
    }
    write_runlog(DEBUG5, "line %s %d: nodeState heal is %d, role is %d.\n",
        __FUNCTION__, __LINE__, (int32)nodeState.health, (int32)nodeState.role);
    if (nodeState.health != DDB_STATE_HEALTH) {
        write_runlog(logLevel, "line %s %d: node (%s)is unhealth.\n", __FUNCTION__, __LINE__,
            g_etcdInfo[idx].nodeInfo.nodeName);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static uint32 GetHealthEtcdFromAllEtcd(int timeOut)
{
    uint32 healthCount = 0;
    uint32 unhealthCount = 0;
    bool findUnhealth = true;
    status_t st = CM_SUCCESS;
    uint32 healthEtcdIndex[MAX_ETCD_NODE_NUM] = {0};
    for (uint32 i = 0; i < g_etcdNum; i++) {
        st = EtcdNodeIsHealth(i, timeOut);
        if (st == CM_TIMEDOUT) {
            continue;
        }
        if (st == CM_ERROR) {
            ++unhealthCount;
        } else if (st == CM_SUCCESS) {
            healthEtcdIndex[healthCount] = i;
            ++healthCount;
        }
        if (healthCount > g_etcdNum / 2) {
            findUnhealth = false;
            break;
        }

        if (unhealthCount > g_etcdNum / 2) {
            break;
        }
    }
    (void)pthread_rwlock_wrlock(&g_healthEtcdRwlock);
    g_healthEtcdCount = 0;
    for (uint32 i = 0; i < healthCount; ++i) {
        g_healthEtcdIndex[i] = healthEtcdIndex[i];
    }
    if (findUnhealth) {
        g_healthEtcdFlag = false;
    } else {
        g_healthEtcdFlag = true;
        g_healthEtcdCount = healthCount;
    }
    (void)pthread_rwlock_unlock(&g_healthEtcdRwlock);

    return healthCount;
}

static uint32 GetHealthEtcdNodeCount(int timeOut)
{
    uint32 i;
    uint32 healthCount = 0;
    status_t st = CM_SUCCESS;
    if (g_healthEtcdFlag) {
        for (i = 0; i < g_healthEtcdCount; i++) {
            uint32 etcdIndex = g_healthEtcdIndex[i];
            if (etcdIndex >= g_etcdNum) {
                break;
            }
            st = EtcdNodeIsHealth(etcdIndex, timeOut);
            if (st != CM_SUCCESS) {
                break;
            }
            ++healthCount;
            if (healthCount > g_etcdNum / 2) {
                return healthCount;
            }
        }
    }
    return GetHealthEtcdFromAllEtcd(timeOut);
}

bool IsEtcdHealth(DDB_CHECK_MOD checkMod, int timeOut)
{
    if (g_etcdNum == 0) {
        return true;
    }
    if (checkMod == DDB_HEAL_COUNT) {
        uint32 healCount = GetHealthEtcdNodeCount(timeOut);
        if (healCount <= g_etcdNum / 2) {
            return false;
        }
    } else if (checkMod == DDB_PRE_CONN) {
        if (g_healthEtcdCountForPreConn <= g_etcdNum / 2) {
            return false;
        }
    }
    return true;
}

static void DrvEtcdFreeInfo(void)
{
    if (g_modId != MOD_CMCTL) {
        return;
    }
    FREE_AND_RESET(g_etcdInfo);
}

static status_t InitEtcdTlsPath(const TlsAuthPath *tlsPath)
{
    int32 logLevel = (g_modId == MOD_CMCTL) ? DEBUG5 : DEBUG1;
    if (tlsPath == NULL) {
        logLevel = (g_modId == MOD_CMCTL) ? DEBUG1 : ERROR;
        write_runlog(logLevel, "line %s: %d tlsPath is null.\n", __FUNCTION__, __LINE__);
        return CM_ERROR;
    }
    write_runlog(logLevel, "init: ca: %s, crt: %s, key: %s.\n", tlsPath->caFile, tlsPath->crtFile, tlsPath->keyFile);
    errno_t rc = memcpy_s(g_etcdTlsPath.etcd_ca_path, ETCD_MAX_PATH_LEN - 1, tlsPath->caFile, DDB_MAX_PATH_LEN - 1);
    securec_check_errno(rc, (void)rc);
    rc = memcpy_s(g_etcdTlsPath.client_crt_path, ETCD_MAX_PATH_LEN - 1, tlsPath->crtFile, DDB_MAX_PATH_LEN - 1);
    securec_check_errno(rc, (void)rc);
    rc = memcpy_s(g_etcdTlsPath.client_key_path, ETCD_MAX_PATH_LEN - 1, tlsPath->keyFile, DDB_MAX_PATH_LEN - 1);
    securec_check_errno(rc, (void)rc);
    write_runlog(logLevel, "end: ca: %s, crt: %s, key: %s.\n", g_etcdTlsPath.etcd_ca_path,
        g_etcdTlsPath.client_crt_path, g_etcdTlsPath.client_key_path);
    return CM_SUCCESS;
}

static void PrintEtcdInfo()
{
    int32 logLevel = (g_modId == MOD_CMCTL) ? DEBUG1 : LOG;
    char etcdStr[DDB_MAX_KEY_VALUE_LEN] = {0};
    size_t etcdSize = 0;
    errno_t rc = 0;
    for (uint32 i = 0; i < g_etcdNum; ++i) {
        etcdSize = strlen(etcdStr);
        if (etcdSize >= DDB_MAX_KEY_VALUE_LEN) {
            break;
        }
        rc = snprintf_s(etcdStr + etcdSize, DDB_MAX_KEY_VALUE_LEN - etcdSize, DDB_MAX_KEY_VALUE_LEN - 1 - etcdSize,
            "%s:%u:%s:%u:%u:%s; ", g_etcdInfo[i].host, g_etcdInfo[i].port, g_etcdInfo[i].nodeInfo.nodeName,
            g_etcdInfo[i].nodeIdInfo.nodeId, g_etcdInfo[i].nodeIdInfo.instd, g_etcdInfo[i].nodeIdInfo.azName);
        securec_check_intval(rc, (void)rc);
    }
    write_runlog(logLevel, "etcdStr is %s.\n", etcdStr);
}

static status_t InitEtcdInfoEx(const DrvApiInfo *apiInfo)
{
    int32 logLevel = (apiInfo->modId == MOD_CMCTL) ? DEBUG1 : LOG;
    g_etcdNum = apiInfo->nodeNum;
    if (g_etcdNum == 0) {
        write_runlog(ERROR, "g_etcdNum is 0.\n");
        return CM_ERROR;
    }
    size_t len = g_etcdNum * sizeof(ServerSocket);
    g_etcdInfo = (ServerSocket *)malloc(len);
    if (g_etcdInfo == NULL) {
        write_runlog(logLevel, "g_etcdInfo malloc failed.\n");
        return CM_ERROR;
    }
    errno_t rc = memset_s(g_etcdInfo, len, 0, len);
    securec_check_errno(rc, FREE_AND_RESET(g_etcdInfo));
    uint32 idx = 0;
    for (uint32 i = 0; i < apiInfo->serverLen; ++i) {
        if (idx >= g_etcdNum) {
            break;
        }
        ServerSocket *server = &apiInfo->serverList[i];
        if (server->host == NULL || server->port == 0 || server->nodeInfo.nodeName == NULL ||
            server->nodeInfo.len == 0) {
            continue;
        }
        g_etcdInfo[idx] = *server;
        ++idx;
    }
    if (idx == 0 || idx != g_etcdNum) {
        write_runlog(logLevel, "%s: %d, failed to init etcd info, idx: %u, g_etcdNum is %u.\n",
            __FUNCTION__, __LINE__, idx, g_etcdNum);
        FREE_AND_RESET(g_etcdInfo);
        return CM_ERROR;
    }
    PrintEtcdInfo();
    return CM_SUCCESS;
}

static status_t DrvEtcdLeaderNodeId(NodeIdInfo *idInfo, const char *azName)
{
    DdbNodeState nodeState = {DDB_STATE_HEALTH};
    status_t st = CM_SUCCESS;
    for (uint32 i = 0; i < g_etcdNum; ++i) {
        if (g_etcdInfo[i].nodeIdInfo.azName == NULL) {
            write_runlog(ERROR, "[DrvEtcdLeaderNodeId]: i=%u, azName is NULL.\n", i);
            return CM_ERROR;
        }
        if ((azName != NULL) && (strcmp(g_etcdInfo[i].nodeIdInfo.azName, azName) != 0)) {
            continue;
        }
        st = GetEtcdNodeState(i, &nodeState);
        if (st != CM_SUCCESS) {
            continue;
        }
        if (nodeState.role == DDB_ROLE_LEADER) {
            idInfo->azName = g_etcdInfo[i].nodeIdInfo.azName;
            idInfo->nodeId = g_etcdInfo[i].nodeIdInfo.nodeId;
            return CM_SUCCESS;
        }
    }
    return CM_ERROR;
}

status_t InitEtcdInfo(const DrvApiInfo *apiInfo)
{
    g_modId = apiInfo->modId;
    g_timeOut = apiInfo->timeOut;
    status_t st = InitEtcdTlsPath(apiInfo->client_t.tlsPath);
    CM_RETURN_IFERR(st);
    st = InitEtcdInfoEx(apiInfo);
    return st;
}

Alarm *DrvEtcdGetAlarm(int alarmIndex)
{
    if (alarmIndex < 0 || alarmIndex >= ABNORMAL_ETCD_ALARM_LIST_SIZE) {
        return NULL;
    }

    return &g_etcdAlarmList[alarmIndex];
}

static status_t DrvEtcdSetParam(const char *key, const char *value)
{
    if (key == NULL || value == NULL) {
        write_runlog(ERROR, "failed to set dcc param, because key(%s) or value(%s) is null.\n", key, value);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t DrvEtcdStop(bool *ddbStop)
{
    *ddbStop = true;
    return CM_SUCCESS;
}

static status_t EtcdLoadApi(const DrvApiInfo *apiInfo)
{
    CmsEtcdAbnormalAlarmItemInitialize();

    DdbDriver *drv = DrvEtcdGet();
    drv->allocConn = DrvEtcdAllocConn;
    drv->freeConn = DrvEtcdFreeConn;
    drv->getValue = DrvEtcdGetValue;
    drv->getAllKV = DrvEtcdGetAllKV;
    drv->saveAllKV = DrvEtcdSaveAllKV;
    drv->setKV = DrvEtcdSetKV;
    drv->delKV = DrvEtcdDelKV;
    drv->drvNodeState = DrvEtcdNodeState;
    drv->lastError = get_last_error;

    drv->isHealth = IsEtcdHealth;
    drv->freeNodeInfo = DrvEtcdFreeInfo;
    drv->notifyDdb = DrvNotifyEtcd;
    drv->setMinority = DrvEtcdSetMinority;
    drv->getAlarm = DrvEtcdGetAlarm;
    drv->leaderNodeId = DrvEtcdLeaderNodeId;
    drv->restConn = DrvEtcdRestConn;
    drv->setParam = DrvEtcdSetParam;
    drv->stop = DrvEtcdStop;
    status_t st = InitEtcdInfo(apiInfo);
    if (st != CM_SUCCESS) {
        return CM_ERROR;
    }
    st = CreateEtcdThread(apiInfo);
    return st;
}

DdbDriver *DrvEtcdGet(void)
{
    return &g_drvEtcd;
}
