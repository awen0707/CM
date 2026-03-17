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
 * cm_ddb_adapter.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_adapter/cm_ddb_adapter/cm_ddb_adapter.cpp
 *
 * -------------------------------------------------------------------------
 */

#include "cm_ddb_dcc.h"
#include "cm_ddb_etcd.h"
#include "cm/cm_elog.h"
#include "cm_ddb_sharedisk.h"

#define CHECK_DB_SESSION_AND_STOPPED(ddbConn, returnValue)                                                            \
    do {                                                                                                              \
        if ((((ddbConn)->drv) == NULL) || (((ddbConn)->session) == NULL && ((ddbConn)->drv->type) != DB_SHAREDISK) || \
            ((ddbConn)->drv->ddbStopped)) {                                                                           \
            DdbSetIdle(ddbConn);                                                                                      \
            return (returnValue);                                                                                     \
        }                                                                                                             \
    } while (0)

static const uint32 MAX_LOG_LEN = 2048;

static DdbNotifyStatusFunc g_ddbNotify = NULL;

static DdbTypeString g_dbType2String[] = {
    {"ETCD", DB_ETCD}, {"DCC", DB_DCC}, {"SHAREDISK", DB_SHAREDISK}, {NULL, DB_UNKOWN}};

const char *GetDdbToString(DDB_TYPE dbType)
{
    for (int32 i = 0; g_dbType2String[i].dbString != NULL; ++i) {
        if (dbType == g_dbType2String[i].dbType) {
            return g_dbType2String[i].dbString;
        }
    }
    return "unkown dbType";
}

const DDB_TYPE GetStringToDdb(const char *str)
{
    for (int32 i = 0; g_dbType2String[i].dbType != DB_UNKOWN; ++i) {
        if (strcmp(str, g_dbType2String[i].dbString) == 0) {
            return g_dbType2String[i].dbType;
        }
    }
    return DB_UNKOWN;
}

uint64 GetTimeMinus(const struct timespec *checkEnd, const struct timespec *checkBegin)
{
    return (uint64)(checkEnd->tv_sec - checkBegin->tv_sec);
}

void ComputTimeInDdb(const struct timespec *checkBegin, const char *msg, ModuleId modId)
{
    const long ddbTime = 2;
    struct timespec checkEnd = {0, 0};
    (void)clock_gettime(CLOCK_MONOTONIC, &checkEnd);
    if (checkEnd.tv_sec - checkBegin->tv_sec > ddbTime) {
        int32 logLevel = (modId == MOD_CMCTL) ? DEBUG1 : LOG;
        write_runlog(logLevel, "%s, it take %llu s.\n", msg, (unsigned long long)GetTimeMinus(&checkEnd, checkBegin));
    }
}

DdbDriver *DrvGetInstance(DDB_TYPE type)
{
    switch (type) {
        case DB_ETCD:
            return DrvEtcdGet();
        case DB_DCC:
            return DrvDccGet();
        case DB_SHAREDISK:
            return DrvSdGet();
        default:
            write_runlog(WARNING, "undefined ddb type(%d)\n", (int32)type);
            break;
    }
    return NULL;
}

status_t DrvLazyLoad(DdbDriver *drv, const DrvApiInfo *apiInfo)
{
    status_t loadingStatus = CM_SUCCESS;
    if (SECUREC_LIKELY(drv->initialized)) {
        return CM_SUCCESS;
    }
    (void)pthread_rwlock_wrlock(&(drv->lock));
    if (!drv->initialized) {
        loadingStatus = drv->loadingApi(apiInfo);
        if (loadingStatus == CM_SUCCESS) {
            drv->initialized = true;
        }
    }
    (void)pthread_rwlock_unlock(&(drv->lock));
    return loadingStatus;
}

static void DrvFreeNodeInfo(const DdbDriver *drv)
{
    if (drv == NULL || drv->freeNodeInfo == NULL) {
        return;
    }
    drv->freeNodeInfo();
}

DdbDriver *InitDdbDrv(const DdbInitConfig *config)
{
    DdbDriver *drv = DrvGetInstance(config->type);
    if (drv == NULL) {
        write_runlog(ERROR, "invalid type(%d), cannot init ddbConn.\n", (int32)config->type);
        return NULL;
    }
    if (SECUREC_UNLIKELY(DrvLazyLoad(drv, &(config->drvApiInfo)) != CM_SUCCESS)) {
        write_runlog(ERROR, "load driver(%s) library failed, type = [%d].\n", drv->msg, (int32)drv->type);
        DrvFreeNodeInfo(drv);
        return NULL;
    }

    return drv;
}

static const char *DrvGetLastError(const DdbDriver *drv)
{
    if (drv == NULL || drv->lastError == NULL) {
        return "unkown error";
    }
    return drv->lastError();
}

status_t InitDdbConn(DdbConn *ddbConn, const DdbInitConfig *config)
{
    DdbDriver *drv = InitDdbDrv(config);
    if (drv == NULL) {
        write_runlog(ERROR, "InitDdbDrv failed.\n");
        return CM_ERROR;
    }

    if (drv->allocConn(&ddbConn->session, &(config->drvApiInfo)) != CM_SUCCESS) {
        write_runlog(ERROR, "failed alloc conn, driver is (%s), type is %d, error is %s.\n",
            drv->msg, (int32)drv->type, DrvGetLastError(drv));
        DrvFreeNodeInfo(drv);
        return CM_ERROR;
    }
    ddbConn->drv = drv;
    ddbConn->modId = config->drvApiInfo.modId;
    ddbConn->nodeId = config->drvApiInfo.nodeId;
    ddbConn->timeOut = config->drvApiInfo.timeOut;
    (void)pthread_rwlock_init(&(ddbConn->lock), NULL);

    return CM_SUCCESS;
}

void DdbSetRunning(DdbConn *ddbConn)
{
    (void)pthread_rwlock_wrlock(&(ddbConn->lock));
    ddbConn->state = PROCESS_IN_RUNNING;
}

void DdbSetIdle(DdbConn *ddbConn)
{
    ddbConn->state = PROCESS_IN_IDLE;
    (void)pthread_rwlock_unlock(&(ddbConn->lock));
}

static status_t CheckDdbConn(const DdbConn *ddbConn, const char *str)
{
    if (ddbConn == NULL) {
        return CM_ERROR;
    }
    int32 logLevel = (ddbConn->modId == MOD_CMCTL) ? DEBUG1 : ERROR;
    if (ddbConn->drv == NULL) {
        write_runlog(logLevel, "[%s] ddbConn drv is NULL.\n", str);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t CheckDdbSession(const DdbConn *ddbConn, const char *str)
{
    if (CheckDdbConn(ddbConn, str) != CM_SUCCESS) {
        return CM_ERROR;
    }
    int32 logLevel = (ddbConn->modId == MOD_CMCTL) ? DEBUG1 : ERROR;
    if (ddbConn->session == NULL && ddbConn->drv->type != DB_SHAREDISK) {
        write_runlog(logLevel, "[%d: %s] [%s] ddbConn session is NULL.\n",
            (int32)ddbConn->drv->type, ddbConn->drv->msg, str);
        return CM_ERROR;
    }
    if (ddbConn->drv->ddbStopped) {
        write_runlog(logLevel, "[%d: %s] [%s] ddb has stopped.\n", (int32)ddbConn->drv->type, ddbConn->drv->msg, str);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t DdbGetValue(DdbConn *ddbConn, DrvText *key, DrvText *value, const DrvGetOption *option)
{
    CM_RETURN_IFERR(CheckDdbSession(ddbConn, __FUNCTION__));
    if (ddbConn->drv->getValue == NULL) {
        int32 logLevel = (ddbConn->modId == MOD_CMCTL) ? DEBUG1 : ERROR;
        write_runlog(logLevel, "[%d: %s] [DdbGetValue] ddbConn getValue is NULL.\n",
            (int32)ddbConn->drv->type, ddbConn->drv->msg);
        return CM_ERROR;
    }
    struct timespec checkBegin = {0, 0};
    (void)clock_gettime(CLOCK_MONOTONIC, &checkBegin);
    DdbSetRunning(ddbConn);
    CHECK_DB_SESSION_AND_STOPPED(ddbConn, CM_ERROR);
    status_t st = ddbConn->drv->getValue(ddbConn->session, key, value, option);
    DdbSetIdle(ddbConn);
    char msg[MAX_LOG_LEN] = {0};
    errno_t rc = snprintf_s(msg, MAX_LOG_LEN, MAX_LOG_LEN - 1,
        "[%d: %s] [DdbGetValue], get value(%u: %s) by key(%u: %s)",
        (int32)ddbConn->drv->type, ddbConn->drv->msg, key->len, key->data, value->len, value->data);
    securec_check_intval(rc, (void)rc);
    ComputTimeInDdb(&checkBegin, msg, ddbConn->modId);
    return st;
}

status_t DdbGetAllKV(DdbConn *ddbConn, DrvText *key, DrvKeyValue *keyValue, uint32 length, const DrvGetOption *option)
{
    CM_RETURN_IFERR(CheckDdbSession(ddbConn, __FUNCTION__));
    if (ddbConn->drv->getAllKV == NULL) {
        int32 logLevel = (ddbConn->modId == MOD_CMCTL) ? DEBUG1 : ERROR;
        write_runlog(logLevel, "[%d: %s] [getAllKV] ddbConn getAllKV is NULL.\n",
            (int32)ddbConn->drv->type, ddbConn->drv->msg);
        return CM_ERROR;
    }
    struct timespec checkBegin = {0, 0};
    (void)clock_gettime(CLOCK_MONOTONIC, &checkBegin);
    DdbSetRunning(ddbConn);
    CHECK_DB_SESSION_AND_STOPPED(ddbConn, CM_ERROR);
    status_t st = ddbConn->drv->getAllKV(ddbConn->session, key, keyValue, length, option);
    DdbSetIdle(ddbConn);
    char msg[MAX_LOG_LEN] = {0};
    errno_t rc = snprintf_s(msg, MAX_LOG_LEN, MAX_LOG_LEN - 1, "[%d: %s] [DdbGetAllKV], get all values by key(%u: %s).",
        (int32)ddbConn->drv->type, ddbConn->drv->msg, key->len, key->data);
    securec_check_intval(rc, (void)rc);
    ComputTimeInDdb(&checkBegin, msg, ddbConn->modId);
    return st;
}

status_t DdbSaveAllKV(DdbConn *ddbConn, DrvText *key, DrvSaveOption *option)
{
    CM_RETURN_IFERR(CheckDdbSession(ddbConn, __FUNCTION__));
    if (ddbConn->drv->saveAllKV == NULL) {
        int32 logLevel = (ddbConn->modId == MOD_CMCTL) ? DEBUG1 : ERROR;
        write_runlog(logLevel, "[%d: %s] [DdbSaveAllKV] ddbConn getAllKV is NULL.\n",
            (int32)ddbConn->drv->type, ddbConn->drv->msg);
        return CM_ERROR;
    }
    struct timespec checkBegin = {0, 0};
    (void)clock_gettime(CLOCK_MONOTONIC, &checkBegin);
    DdbSetRunning(ddbConn);
    CHECK_DB_SESSION_AND_STOPPED(ddbConn, CM_ERROR);
    status_t st = ddbConn->drv->saveAllKV(ddbConn->session, key, option);
    DdbSetIdle(ddbConn);
    char msg[MAX_LOG_LEN] = {0};
    errno_t rc = snprintf_s(msg, MAX_LOG_LEN, MAX_LOG_LEN - 1, "[%d: %s] [DdbGetAllKV], get all values by key(%u: %s).",
        (int32)ddbConn->drv->type, ddbConn->drv->msg, key->len, key->data);
    securec_check_intval(rc, (void)rc);
    ComputTimeInDdb(&checkBegin, msg, ddbConn->modId);
    return st;
}

status_t DdbSetValue(DdbConn *ddbConn, DrvText *key, DrvText *value, DrvSetOption *option)
{
    CM_RETURN_IFERR(CheckDdbSession(ddbConn, __FUNCTION__));
    if (ddbConn->drv->setKV == NULL) {
        int32 logLevel = (ddbConn->modId == MOD_CMCTL) ? DEBUG1 : ERROR;
        write_runlog(logLevel, "[%d: %s] [setKV] ddbConn setKV is NULL.\n",
            (int32)ddbConn->drv->type, ddbConn->drv->msg);
        return CM_ERROR;
    }
    struct timespec checkBegin = {0, 0};
    (void)clock_gettime(CLOCK_MONOTONIC, &checkBegin);
    DdbSetRunning(ddbConn);
    CHECK_DB_SESSION_AND_STOPPED(ddbConn, CM_ERROR);
    status_t st = ddbConn->drv->setKV(ddbConn->session, key, value, option);
    DdbSetIdle(ddbConn);
    char msg[MAX_LOG_LEN] = {0};
    errno_t rc = snprintf_s(msg, MAX_LOG_LEN, MAX_LOG_LEN - 1,
        "[%d: %s] [DdbSetValue], set key_value[%u: %s,  %u: %s].", (int32)ddbConn->drv->type, ddbConn->drv->msg,
        key->len, key->data, value->len, value->data);
    securec_check_intval(rc, (void)rc);
    ComputTimeInDdb(&checkBegin, msg, ddbConn->modId);
    return st;
}

status_t DdbDelKey(DdbConn *ddbConn, DrvText *key)
{
    CM_RETURN_IFERR(CheckDdbSession(ddbConn, __FUNCTION__));
    if (ddbConn->drv->delKV == NULL) {
        int32 logLevel = (ddbConn->modId == MOD_CMCTL) ? DEBUG1 : ERROR;
        write_runlog(logLevel, "[%d: %s] [DdbDelKey] ddbConn delKV is NULL.\n",
            (int32)ddbConn->drv->type, ddbConn->drv->msg);
        return CM_ERROR;
    }
    struct timespec checkBegin = {0, 0};
    (void)clock_gettime(CLOCK_MONOTONIC, &checkBegin);
    DdbSetRunning(ddbConn);
    CHECK_DB_SESSION_AND_STOPPED(ddbConn, CM_ERROR);
    status_t st = ddbConn->drv->delKV(ddbConn->session, key);
    DdbSetIdle(ddbConn);
    char msg[MAX_LOG_LEN] = {0};
    errno_t rc = snprintf_s(msg, MAX_LOG_LEN, MAX_LOG_LEN - 1, "[%d: %s] [DdbDelKey], del key[%u: %s].",
        (int32)ddbConn->drv->type, ddbConn->drv->msg, key->len, key->data);
    securec_check_intval(rc, (void)rc);
    ComputTimeInDdb(&checkBegin, msg, ddbConn->modId);
    return st;
}

status_t DdbInstanceState(DdbConn *ddbConn, char *memberName, DdbNodeState *drvState)
{
    CM_RETURN_IFERR(CheckDdbSession(ddbConn, __FUNCTION__));
    if (ddbConn->drv->drvNodeState == NULL) {
        int32 logLevel = (ddbConn->modId == MOD_CMCTL) ? DEBUG1 : ERROR;
        write_runlog(logLevel, "[%d: %s] [DdbInstanceState] ddbConn drvNodeState is NULL.\n",
            (int32)ddbConn->drv->type, ddbConn->drv->msg);
        return CM_ERROR;
    }
    struct timespec checkBegin = {0, 0};
    (void)clock_gettime(CLOCK_MONOTONIC, &checkBegin);
    DdbSetRunning(ddbConn);
    CHECK_DB_SESSION_AND_STOPPED(ddbConn, CM_ERROR);
    status_t st = ddbConn->drv->drvNodeState(ddbConn->session, memberName, drvState);
    DdbSetIdle(ddbConn);
    char msg[MAX_LOG_LEN] = {0};
    errno_t rc = snprintf_s(msg, MAX_LOG_LEN, MAX_LOG_LEN - 1, "[%d: %s] [DdbHealth], memberName[%s].",
        (int32)ddbConn->drv->type, ddbConn->drv->msg, memberName);
    securec_check_intval(rc, (void)rc);
    ComputTimeInDdb(&checkBegin, msg, ddbConn->modId);
    return st;
}

status_t DdbFreeConn(DdbConn *ddbConn)
{
    if (CheckDdbConn(ddbConn, "[DdbFreeConn]") != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (ddbConn->session == NULL) {
        return CM_SUCCESS;
    }
    if (ddbConn->drv->freeConn == NULL) {
        int32 logLevel = (ddbConn->modId == MOD_CMCTL) ? DEBUG1 : ERROR;
        write_runlog(logLevel, "[%d: %s] [DdbFreeConn] ddbConn freeConn is NULL.\n",
            (int32)ddbConn->drv->type, ddbConn->drv->msg);
        return CM_ERROR;
    }
    struct timespec checkBegin = {0, 0};
    (void)clock_gettime(CLOCK_MONOTONIC, &checkBegin);
    DdbSetRunning(ddbConn);
    CHECK_DB_SESSION_AND_STOPPED(ddbConn, CM_SUCCESS);
    status_t st = ddbConn->drv->freeConn(&ddbConn->session);
    DdbSetIdle(ddbConn);
    char msg[MAX_LOG_LEN] = {0};
    errno_t rc = snprintf_s(msg, MAX_LOG_LEN, MAX_LOG_LEN - 1, "[%d: %s] [DdbFreeConn]",
        (int32)ddbConn->drv->type, ddbConn->drv->msg);
    securec_check_intval(rc, (void)rc);
    ComputTimeInDdb(&checkBegin, msg, ddbConn->modId);
    return st;
}

const char *DdbGetLastError(const DdbConn *ddbConn)
{
    if (ddbConn == NULL) {
        return "unknown reason";
    }
    return DrvGetLastError(ddbConn->drv);
}

int32 DdbRegisterStatusNotify(DdbNotifyStatusFunc ddbNotify)
{
    g_ddbNotify = ddbNotify;
    return 0;
}

DdbNotifyStatusFunc GetDdbStatusFunc(void)
{
    return g_ddbNotify;
}

void DdbFreeNodeInfo(const DdbConn *ddbConn)
{
    if (ddbConn == NULL) {
        return;
    }
    DrvFreeNodeInfo(ddbConn->drv);
}

bool DdbIsValid(const DdbConn *ddbConn, DDB_CHECK_MOD checkMod, int timeOut)
{
    if (ddbConn->drv == NULL) {
        return false;
    }
    return ddbConn->drv->isHealth(checkMod, timeOut);
}

void DdbNotify(const DdbConn *ddbConn, DDB_ROLE dbRole)
{
    if (ddbConn->drv == NULL) {
        return;
    }
    ddbConn->drv->notifyDdb(dbRole);
}

void DdbSetMinority(const DdbConn *ddbConn, bool isMinority)
{
    if (ddbConn->drv == NULL) {
        return;
    }
    ddbConn->drv->setMinority(isMinority);
}

Alarm *DdbGetAlarm(const DdbConn *ddbConn, int index)
{
    if (ddbConn->drv == NULL) {
        return NULL;
    }

    return ddbConn->drv->getAlarm(index);
}

Alarm *DdbGetAlarm(const DdbDriver *drv, int index)
{
    if (drv == NULL) {
        return NULL;
    }

    return drv->getAlarm(index);
}


status_t DdbLeaderNodeId(const DdbConn *ddbConn, NodeIdInfo *idInfo, const char *azName)
{
    if (ddbConn->drv == NULL) {
        return CM_ERROR;
    }
    return ddbConn->drv->leaderNodeId(idInfo, azName);
}

status_t DdbRestConn(DdbConn *ddbConn)
{
    CM_RETURN_IFERR(CheckDdbSession(ddbConn, __FUNCTION__));
    if (ddbConn->drv->restConn == NULL) {
        int32 logLevel = (ddbConn->modId == MOD_CMCTL) ? DEBUG1 : ERROR;
        write_runlog(logLevel, "[%d: %s] [DdbRestConn] ddbConn restConn is NULL.\n",
            (int32)ddbConn->drv->type, ddbConn->drv->msg);
        return CM_ERROR;
    }
    struct timespec checkBegin = {0, 0};
    (void)clock_gettime(CLOCK_MONOTONIC, &checkBegin);
    DdbSetRunning(ddbConn);
    CHECK_DB_SESSION_AND_STOPPED(ddbConn, CM_ERROR);
    status_t st = ddbConn->drv->restConn(ddbConn->session, ddbConn->timeOut);
    DdbSetIdle(ddbConn);
    char msg[MAX_LOG_LEN] = {0};
    errno_t rc = snprintf_s(msg, MAX_LOG_LEN, MAX_LOG_LEN - 1, "[%d: %s] DdbRestConn.",
        (int32)ddbConn->drv->type, ddbConn->drv->msg);
    securec_check_intval(rc, (void)rc);
    ComputTimeInDdb(&checkBegin, msg, ddbConn->modId);
    return st;
}

status_t DdbExecCmd(DdbConn *ddbConn, char *cmdLine, char *output, int *outputLen, uint32 maxBufLen)
{
    CM_RETURN_IFERR(CheckDdbSession(ddbConn, __FUNCTION__));
    if (ddbConn->drv->execCmd == NULL) {
        int32 logLevel = (ddbConn->modId == MOD_CMCTL) ? DEBUG1 : ERROR;
        write_runlog(logLevel, "[%d: %s] [DdbExecCmd] ddbConn restConn is NULL.\n",
            (int32)ddbConn->drv->type, ddbConn->drv->msg);
        return CM_ERROR;
    }
    struct timespec checkBegin = { 0, 0 };
    (void)clock_gettime(CLOCK_MONOTONIC, &checkBegin);
    DdbSetRunning(ddbConn);
    CHECK_DB_SESSION_AND_STOPPED(ddbConn, CM_ERROR);
    status_t st = ddbConn->drv->execCmd(ddbConn->session, cmdLine, output, outputLen, maxBufLen);
    DdbSetIdle(ddbConn);
    char msg[MAX_LOG_LEN] = { 0 };
    errno_t rc = snprintf_s(msg, MAX_LOG_LEN, MAX_LOG_LEN - 1, "[%d: %s] [DdbExecCmd].",
        (int32)ddbConn->drv->type, ddbConn->drv->msg);
    securec_check_intval(rc, (void)rc);
    ComputTimeInDdb(&checkBegin, msg, ddbConn->modId);
    return st;
}

status_t DdbSetBlocked(const DdbConn *ddbConn, unsigned int setBlock, unsigned waitTimeoutMs)
{
    if (ddbConn->drv == NULL) {
        return CM_ERROR;
    }
    return ddbConn->drv->setBlocked(setBlock, waitTimeoutMs);
}

status_t DDbSetParam(const DdbConn *ddbConn, const char *key, const char *value)
{
    CM_RETERR_IF_NULL(ddbConn->drv);
    return ddbConn->drv->setParam(key, value);
}

status_t DdbStop(DdbConn *ddbConn)
{
    if (CheckDdbConn(ddbConn, "[DdbStop]") != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (ddbConn->drv->stop == NULL) {
        int32 logLevel = (ddbConn->modId == MOD_CMCTL) ? DEBUG1 : ERROR;
        write_runlog(logLevel, "[%d: %s] [DdbStop] stop is NULL.\n", (int32)ddbConn->drv->type, ddbConn->drv->msg);
        return CM_ERROR;
    }
    if (ddbConn->drv->ddbStopped) {
        return CM_SUCCESS;
    }
    struct timespec checkBegin = { 0, 0 };
    (void)clock_gettime(CLOCK_MONOTONIC, &checkBegin);
    DdbSetRunning(ddbConn);
    if (ddbConn->drv->ddbStopped) {
        return CM_SUCCESS;
    }
    status_t st = ddbConn->drv->stop(&ddbConn->drv->ddbStopped);
    DdbSetIdle(ddbConn);
    char msg[MAX_LOG_LEN] = { 0 };
    errno_t rc = snprintf_s(msg, MAX_LOG_LEN, MAX_LOG_LEN - 1, "[%d: %s] [DdbStop].",
        (int32)ddbConn->drv->type, ddbConn->drv->msg);
    securec_check_intval(rc, (void)rc);
    ComputTimeInDdb(&checkBegin, msg, ddbConn->modId);
    return st;
}

status_t DdbSetWorkMode(DdbConn *ddbConn, unsigned int workMode, unsigned int voteNum)
{
    status_t ret = CM_ERROR;
    CM_RETURN_IFERR(CheckDdbSession(ddbConn, __FUNCTION__));
    DdbSetRunning(ddbConn);
    CHECK_DB_SESSION_AND_STOPPED(ddbConn, CM_ERROR);
    ret = ddbConn->drv->setWorkMode(ddbConn->session, workMode, voteNum);
    DdbSetIdle(ddbConn);
    return ret;
}

status_t DdbDemoteRole2Standby(DdbConn *ddbConn)
{
    status_t ret = CM_ERROR;
    CM_RETURN_IFERR(CheckDdbSession(ddbConn, __FUNCTION__));
    DdbSetRunning(ddbConn);
    CHECK_DB_SESSION_AND_STOPPED(ddbConn, CM_ERROR);
    ret = ddbConn->drv->demoteDdbRole(ddbConn->session);
    DdbSetIdle(ddbConn);
    return ret;
}
