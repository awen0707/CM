/*
 * Copyright (c) 2022 Huawei Technologies Co.,Ltd.
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
 * cm_ddb_sharedisk.cpp
 *
 * IDENTIFICATION
 *    src/cm_adapter/cm_sharedisk_adapter/cm_ddb_sharedisk.cpp
 *
 * -------------------------------------------------------------------------
 */
#include <limits.h>
#include "cm/cm_c.h"
#include "cm/cm_elog.h"
#include "cm_disk_rw.h"
#include "cm_ddb_sharedisk_cmd.h"
#include "cm_ddb_sharedisk_disklock.h"
#include "cm_ddb_sharedisk.h"

uint32 g_cmSdServerNum = 0;
static diskLrwHandler g_cmsArbitrateDiskHandler;
static pthread_rwlock_t g_notifySdLock;
static DDB_ROLE g_notifySd = DDB_ROLE_UNKNOWN;
static DDB_ROLE g_dbRole = DDB_ROLE_FOLLOWER;
static uint32 g_cmServerNum = 0;
static int64 g_waitForTime = 0;
static volatile int64 g_notifyBeginSec = 0;
const uint32 ONE_PRIMARY_ONE_STANDBY = 2;
static DdbArbiCon *g_arbiCon = NULL;
static const time_t MAX_VALID_LOCK_TIME = 125;
static const time_t BASE_VALID_LOCK_TIME = 1;
#ifdef ENABLE_MEMCHECK
static const uint32 DEFAULT_CMD_TIME_OUT = 120;
#else
static const uint32 DEFAULT_CMD_TIME_OUT = 2;
#endif

typedef enum en_persist_cmd_type {
    CMD_LOCK = 0,
    CMD_FORCE_LOCK = 1,
} PERSIST_CMD_TYPE;

typedef struct SdArbitrateDataSt {
    uint32 lockNotRefreshTimes;
    time_t lockFailBeginTime;
    time_t lockTime;
    DDB_ROLE lastDdbRole;
} SdArbitrateData;

static status_t SdLoadApi(const DrvApiInfo *apiInfo);

static DdbDriver g_drvSd = {PTHREAD_RWLOCK_INITIALIZER, false, DB_SHAREDISK, "sharedisk conn", SdLoadApi};

status_t DrvSdGetValue(const DrvCon_t session, DrvText *key, DrvText *value, const DrvGetOption *option)
{
    status_t res = DiskCacheRead(key->data, value->data, value->len);
    if (res != CM_SUCCESS) {
        write_runlog(DEBUG1, "DrvSdGetValue: failed to get value of key %s.\n", key->data);
        return CM_ERROR;
    }

    write_runlog(DEBUG1,
        "DrvSdGetValue: success to get keyValue[%s:%u, %s:%u].\n",
        key->data,
        key->len,
        value->data,
        value->len);
    return CM_SUCCESS;
}

status_t DrvSdGetAllKV(
    const DrvCon_t session, DrvText *key, DrvKeyValue *keyValue, uint32 length, const DrvGetOption *option)
{
    char kvBuff[DDB_MAX_KEY_VALUE_LEN] = {0};
    status_t res = DiskCacheRead(key->data, kvBuff, DDB_MAX_KEY_VALUE_LEN, true);
    if (res != CM_SUCCESS) {
        write_runlog(DEBUG1, "DrvSdGetValue: failed to get all value of key %s.\n", key->data);
        return CM_ERROR;
    }
    write_runlog(DEBUG1, "DrvSdGetAllKV: get all values, key is %s, result_key_value is %s.\n", key->data, kvBuff);

    errno_t rc;
    char *pLeft = NULL;
    char *pKey = strtok_r(kvBuff, ",", &pLeft);
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
            ERROR, "DrvSdGetAllKV: get all values is empty, key is %s result_key_value is %s.\n", key->data, kvBuff);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t DrvSdSetKV(const DrvCon_t session, DrvText *key, DrvText *value, DrvSetOption *option)
{
    // key->len % 512 and value->len % 512 must equal to 0
    write_runlog(DEBUG1, "DrvSdSetKV: set key %s to value %s.\n", key->data, value->data);
    status_t res;
    if (option != NULL) {
        update_option updateOption;
        updateOption.preValue = option->preValue;
        updateOption.len = option->len;
        res = DiskCacheWrite(key->data, key->len, value->data, value->len, &updateOption);
    } else {
        res = DiskCacheWrite(key->data, key->len, value->data, value->len, NULL);
    }
    if (res != CM_SUCCESS) {
        write_runlog(ERROR, "DrvSdSetKV: set key %s to value %s failed.\n", key->data, value->data);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t DrvSdDelKV(const DrvCon_t session, DrvText *key)
{
    write_runlog(DEBUG1, "DrvSdDelKV: begin to del key %s.\n", key->data);
    status_t res = DiskCacheDelete(key->data);
    if (res != CM_SUCCESS) {
        write_runlog(ERROR, "DrvSdDelKV: del key %s failed.\n", key->data);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t GetNotifyRole(DrvCon_t session, char *memberName, DdbNodeState *nodeState)
{
    return CM_SUCCESS;
}

status_t InitShareDiskManager(const DrvApiInfo *apiInfo)
{
    g_cmServerNum = apiInfo->nodeNum;
    g_waitForTime = apiInfo->sdConfig.waitTime;
    int64 instId = apiInfo->sdConfig.instanceId;
    uint32 offset = apiInfo->sdConfig.offset + DISK_ARBITRATE_LOCK_SPACE + DISK_RESERVED_LEN_AFTER_CMSLOCK;
    CM_RETURN_IFERR(InitDiskData(apiInfo->sdConfig.devPath, offset, instId));
    return CM_SUCCESS;
}

status_t InitSdManagerLock(const DrvApiInfo *apiInfo)
{
    CM_RETURN_IFERR(InitShareDiskManager(apiInfo));

    return CM_SUCCESS;
}

const char *DrvSdLastError(void)
{
    return GetDiskRwError();
}

status_t DrvSdAllocConn(DrvCon_t *session, const DrvApiInfo *apiInfo)
{
    return CM_SUCCESS;
}

status_t DrvSdFreeConn(DrvCon_t *session)
{
    return CM_SUCCESS;
}

static uint32 DrvSdHealthCount(int timeOut)
{
    return g_cmSdServerNum;
}

static bool IsDrvSdHeal(DDB_CHECK_MOD checkMod, int timeOut)
{
    return true;
}

static void DrvSdFreeNodeInfo(void)
{
    return;
}

static void DrvNotifySd(DDB_ROLE dbRole)
{
    DdbNotifyStatusFunc ddbNotiStatusFun = GetDdbStatusFunc();
    if (ddbNotiStatusFun == NULL) {
        write_runlog(ERROR,
            "DrvNotifySd: ddb callback statuc func is null.\n");
        return;
    }

    if (g_dbRole != dbRole) {
        struct timespec checkBegin = {0, 0};
        (void)clock_gettime(CLOCK_MONOTONIC, &checkBegin);

        (void)pthread_rwlock_wrlock(&g_notifySdLock);
        g_notifyBeginSec = checkBegin.tv_sec;
        g_notifySd = dbRole;
        ddbNotiStatusFun(dbRole);
        (void)pthread_rwlock_unlock(&g_notifySdLock);
        write_runlog(LOG, "receive notify msg, it has set ddb role, dbRole is [%d: %d], g_waitForTime is %ld, "
            "g_cmServerNum is %u.\n", (int32)dbRole, (int32)g_dbRole, g_waitForTime, g_cmServerNum);
    }
}

static void DrvSdSetMinority(bool isMinority)
{
    return;
}
static status_t DrvSdSaveAllKV(const DrvCon_t session, const DrvText *key, DrvSaveOption *option)
{
    return CM_SUCCESS;
}

Alarm *DrvSdGetAlarm(int alarmIndex)
{
    return NULL;
}
status_t DrvSdLeaderNodeId(NodeIdInfo *idInfo, const char *azName)
{
    return CM_SUCCESS;
}
status_t DrvSdSetParam(const char *key, const char *value)
{
    if (key == NULL || value == NULL) {
        write_runlog(ERROR, "failed to set dcc param, because key or value is null.\n");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}
status_t DrvSdRestConn(DrvCon_t sess, int32 timeOut)
{
    return CM_SUCCESS;
}

static void NotifyDdbRole(DDB_ROLE *lastDdbRole)
{
    DdbNotifyStatusFunc ddbNotiSta = GetDdbStatusFunc();
    if (ddbNotiSta == NULL) {
        write_runlog(ERROR,
            "NotifyDdbRole: ddb callback statuc func is null.\n");
        return ;
    }

    if (g_dbRole != (*lastDdbRole)) {
        write_runlog(LOG,
            "NotifyDdbRole: current ddbRole is %d, last ddbRole is %d.\n",
            (int)g_dbRole,
            (int)(*lastDdbRole));
        ddbNotiSta(g_dbRole);
    }

    write_runlog(DEBUG1, "NotifyDdbRole: current ddbRole is %d.\n", (int)g_dbRole);
    *lastDdbRole = g_dbRole;
}

static uint32 GetForceLockTimeOutCfg()
{
    uint32 curForceLockTimeOut = g_arbiCon->arbiCfg->haHeartBeatTimeOut;
    if (curForceLockTimeOut < DEFAULT_CMD_TIME_OUT) {
        curForceLockTimeOut = DEFAULT_CMD_TIME_OUT;
    }
    return curForceLockTimeOut;
}

static bool CheckDemoteDdbRole(SdArbitrateData *sdArbitrateData)
{
    if (sdArbitrateData->lastDdbRole != DDB_ROLE_LEADER) {
        sdArbitrateData->lockFailBeginTime = 0;
        return true;
    }

    uint32 forceLockTimeOut = GetForceLockTimeOutCfg();
    uint32 exeCmdTwiceTimeOut = DEFAULT_CMD_TIME_OUT + DEFAULT_CMD_TIME_OUT;
    if (exeCmdTwiceTimeOut >= forceLockTimeOut) {
        sdArbitrateData->lockFailBeginTime = 0;
        return true;
    }

    // try to avoid execute cmd timeout, so use diff time to demote cms primary
    uint32 diffTimeOut = forceLockTimeOut - exeCmdTwiceTimeOut;
    struct timespec time = {0, 0};
    (void)clock_gettime(CLOCK_MONOTONIC, &time);
    time_t minusTime = time.tv_sec - sdArbitrateData->lockFailBeginTime;
    if (minusTime >= diffTimeOut) {
        write_runlog(LOG,
            "CheckDemoteDdbRole: CMS primary will demote for current time %ld, lockFailBeginTime %ld, diffTimeOut "
            "%u.\n",
            time.tv_sec,
            sdArbitrateData->lockFailBeginTime,
            diffTimeOut);
        return true;
    }
    write_runlog(LOG,
        "CheckDemoteDdbRole: CMS primary demote will wait %u seconds for current time %ld, lockFailBeginTime %ld, "
        "diffTimeOut %u.\n",
        (uint32)(diffTimeOut - minusTime),
        time.tv_sec,
        sdArbitrateData->lockFailBeginTime,
        diffTimeOut);

    return false;
}

static void CmNormalArbitrate(SdArbitrateData *sdArbitrateData)
{
    disk_lock_info_t lockInfo = cm_lock_disklock();
    write_runlog(DEBUG1,
        "CmNormalArbitrate: cm_lock_disklock result %d. lockTime %ld, "
        "lockNotRefreshTimes %u, lockFailBeginTime %ld\n",
        lockInfo.lock_result, sdArbitrateData->lockTime,
        sdArbitrateData->lockNotRefreshTimes, sdArbitrateData->lockFailBeginTime);
    if (lockInfo.lock_result == 0) {
        // get lock success, notify cmserver to primary
        sdArbitrateData->lockTime = 0;
        sdArbitrateData->lockNotRefreshTimes = 0;
        sdArbitrateData->lockFailBeginTime = 0;
        g_dbRole = DDB_ROLE_LEADER;
        NotifyDdbRole(&sdArbitrateData->lastDdbRole);
        return;
    }

    if (lockInfo.lock_time >= BASE_VALID_LOCK_TIME && lockInfo.lock_time <= MAX_VALID_LOCK_TIME) {
        g_dbRole = DDB_ROLE_FOLLOWER;
        sdArbitrateData->lockFailBeginTime = 0;
        // get lock failed, check lock time if refreshed by other process
        if (sdArbitrateData->lockTime != lockInfo.lock_time) {
            sdArbitrateData->lockTime = lockInfo.lock_time;
            sdArbitrateData->lockNotRefreshTimes = 0;
        } else {
            const uint32 defaultNotRefreshTimes = 2;
            uint32 curForceLockTimeOut = GetForceLockTimeOutCfg();
            int logLevel = sdArbitrateData->lockNotRefreshTimes >= defaultNotRefreshTimes ? LOG : DEBUG1;
            write_runlog(logLevel,
                "CmNormalArbitrate: other cmserver maybe lost lock for %u times, current lock time %ld\n",
                sdArbitrateData->lockNotRefreshTimes, sdArbitrateData->lockTime);
            if (sdArbitrateData->lockNotRefreshTimes < curForceLockTimeOut) {
                ++sdArbitrateData->lockNotRefreshTimes;
            } else {
                sdArbitrateData->lockNotRefreshTimes = 0;
                int32 lockRst = cm_lockf_disklock();
                g_dbRole = ((lockRst == 0) ? DDB_ROLE_LEADER : DDB_ROLE_FOLLOWER);
                write_runlog(LOG, "CmNormalArbitrate: cm_disk_lockf_s result %d, curForceLockTime %u.\n",
                    lockRst, curForceLockTimeOut);
            }
        }
        NotifyDdbRole(&sdArbitrateData->lastDdbRole);
        return;
    }

    // get lock time failed
    sdArbitrateData->lockTime = 0;
    sdArbitrateData->lockNotRefreshTimes = 0;
    g_dbRole = CheckDemoteDdbRole(sdArbitrateData) ? DDB_ROLE_FOLLOWER : DDB_ROLE_LEADER;
    NotifyDdbRole(&sdArbitrateData->lastDdbRole);
}

static bool CheckResetTime()
{
    struct timespec checkEnd = {0, 0};
    (void)clock_gettime(CLOCK_MONOTONIC, &checkEnd);
    int64 diffSeconds = checkEnd.tv_sec - g_notifyBeginSec;
    if (diffSeconds <= g_waitForTime) {
        write_runlog(DEBUG1,
            "CheckResetTime: current time %ld, g_notifyBeginSec %ld, g_waitTime %ld, cannot reset g_notifySd.\n",
            (long int)checkEnd.tv_sec, g_notifyBeginSec, g_waitForTime);
        return false;
    }

    return true;
}

static bool CheckSdDemote(SdArbitrateData *sdArbitrateData)
{
    if (g_notifySd != DDB_ROLE_FOLLOWER) {
        return false;
    }

    if (g_dbRole == DDB_ROLE_LEADER) {
        g_dbRole = DDB_ROLE_FOLLOWER;
        NotifyDdbRole(&sdArbitrateData->lastDdbRole);
        return true;
    }
    
    if (!CheckResetTime()) {
        return true;
    }

    write_runlog(LOG,
        "CheckSdDemote: will reset g_notifySd from %u to %u after wait %ld time.\n",
        (uint32)g_notifySd,
        (uint32)DDB_ROLE_UNKNOWN,
        g_waitForTime);
    g_notifySd = DDB_ROLE_UNKNOWN;
    return false;
}

static status_t ExePromoteCmd(SdArbitrateData *sdArbitrateData)
{
    disk_lock_info_t lockInfo = cm_lock_disklock();
    if (lockInfo.lock_result != 0) {
        write_runlog(WARNING, "ExePromoteCmd: Execute get lock failed, lockResult %d!\n", lockInfo.lock_result);
        if (lockInfo.lock_time >= BASE_VALID_LOCK_TIME && lockInfo.lock_time <= MAX_VALID_LOCK_TIME) {
            int32 lockRst = cm_lockf_disklock();
            if (lockRst != 0) {
                write_runlog(WARNING, "ExePromoteCmd: Execute cm_lockf_disklock failed, result %d!\n", lockRst);
                return CM_ERROR;
            }
            return CM_SUCCESS;
        }
        return CM_ERROR;
    }

    sdArbitrateData->lockTime = 0;
    sdArbitrateData->lockNotRefreshTimes = 0;
    sdArbitrateData->lockFailBeginTime = 0;
    write_runlog(DEBUG1, "ExePromoteCmd: Execute get lock cmd success!\n");
    return CM_SUCCESS;
}

static bool CheckSdPromote(SdArbitrateData *sdArbitrateData)
{
    if (g_notifySd != DDB_ROLE_LEADER) {
        return false;
    }

    if (g_dbRole != DDB_ROLE_LEADER) {
        (void)ExePromoteCmd(sdArbitrateData);
        g_dbRole = DDB_ROLE_LEADER;
        NotifyDdbRole(&sdArbitrateData->lastDdbRole);
        return true;
    }

    (void)ExePromoteCmd(sdArbitrateData);

    if (!CheckResetTime()) {
        return true;
    }

    write_runlog(LOG,
        "CheckSdPromote: will reset g_notifySd from %u to %u after wait %ld seconds.\n",
        (uint32)g_notifySd,
        (uint32)DDB_ROLE_UNKNOWN,
        g_waitForTime);
    g_notifySd = DDB_ROLE_UNKNOWN;
    return false;
}

static bool HaveNotifySd(SdArbitrateData *sdArbitrateData)
{
    bool res = false;
    (void)pthread_rwlock_wrlock(&g_notifySdLock);
    if (g_notifySd == DDB_ROLE_FOLLOWER) {
        res = CheckSdDemote(sdArbitrateData);
    } else if (g_notifySd == DDB_ROLE_LEADER) {
        res = CheckSdPromote(sdArbitrateData);
    }
    (void)pthread_rwlock_unlock(&g_notifySdLock);
    return res;
}

static void *GetShareDiskLockMain(void *arg)
{
    thread_name = "GetShareDiskLockMain";
    write_runlog(LOG, "Starting get share disk lock thread.\n");
    initializeDiskLockManager();

    uint64 lockAddr = g_cmsArbitrateDiskHandler.offset;
    int64 instId = g_cmsArbitrateDiskHandler.instId;

    int32 lockRst = cm_init_disklock(g_cmsArbitrateDiskHandler.scsiDev, lockAddr, instId);
    if (lockRst != 0) {
        write_runlog(LOG, "Failed to initialize disk lock, lockRst is %d, instId is %ld, offset is %ld\n",
            lockRst, instId, lockAddr);
        return NULL;
    }

    SdArbitrateData sdArbitrateData;
    errno_t rc = memset_s(&sdArbitrateData, sizeof(SdArbitrateData), 0, sizeof(SdArbitrateData));
    securec_check_errno(rc, (void)rc);
    struct timespec checkBegin = {0, 0};
    struct timespec checkEnd = {0, 0};
    uint32 twoSec = 2;

    for (;;) {
        (void)clock_gettime(CLOCK_MONOTONIC, &checkBegin);
        if (!HaveNotifySd(&sdArbitrateData)) {
            if (sdArbitrateData.lockFailBeginTime == 0) {
                sdArbitrateData.lockFailBeginTime = checkBegin.tv_sec;
            }
            CmNormalArbitrate(&sdArbitrateData);
        }
        (void)clock_gettime(CLOCK_MONOTONIC, &checkEnd);
        uint32 second = (uint32)(checkEnd.tv_sec - checkBegin.tv_sec);
        int64 nanosecond = checkEnd.tv_nsec - checkBegin.tv_nsec;
        if (second > twoSec) {
            write_runlog(
                LOG, "it takes %u seconds %ld nanoseconds to cmserver share disk arbitrate.\n", second, nanosecond);
        } else {
            (void)sleep(1);
        }
    }
    return NULL;
}

status_t InitDiskLockHandle(diskLrwHandler *sdLrwHandler, const DrvApiInfo *apiInfo)
{
    int32 ret = strcpy_s(sdLrwHandler->scsiDev, MAX_PATH_LENGTH, apiInfo->sdConfig.devPath);
    if (ret != 0) {
        write_runlog(ERROR, "InitDiskLockHandle: copy string %s failed\n", apiInfo->sdConfig.devPath);
        return CM_ERROR;
    }
    sdLrwHandler->instId = apiInfo->sdConfig.instanceId;
    sdLrwHandler->offset = apiInfo->sdConfig.offset;
    return CM_SUCCESS;
}

static status_t CreateShareDiskThread(const DrvApiInfo *apiInfo)
{
    if (InitDiskLockHandle(&g_cmsArbitrateDiskHandler, apiInfo) != CM_SUCCESS) {
        write_runlog(ERROR, "Failed to start get share disk lock thread.\n");
        return CM_ERROR;
    }
    g_arbiCon = apiInfo->cmsArbiCon;
    pthread_t thrId;
    int32 res = pthread_create(&thrId, NULL, GetShareDiskLockMain, NULL);
    if (res != 0) {
        write_runlog(ERROR, "Failed to create share disk lock thread.\n");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}
static status_t DrvSdExecCmd(DrvCon_t session, char *cmdLine, char *output, int *outputLen, uint32 maxBufLen)
{
    return ExecuteDdbCmd(cmdLine, output, outputLen, maxBufLen);
}

static status_t SdLoadApi(const DrvApiInfo *apiInfo)
{
    DdbDriver *drv = DrvSdGet();
    drv->allocConn = DrvSdAllocConn;
    drv->freeConn = DrvSdFreeConn;
    drv->getValue = DrvSdGetValue;
    drv->getAllKV = DrvSdGetAllKV;
    drv->saveAllKV = DrvSdSaveAllKV;
    drv->setKV = DrvSdSetKV;
    drv->delKV = DrvSdDelKV;
    drv->execCmd = DrvSdExecCmd;
    drv->drvNodeState = GetNotifyRole;
    drv->lastError = DrvSdLastError;
    drv->isHealth = IsDrvSdHeal;
    drv->healCount = DrvSdHealthCount;
    drv->freeNodeInfo = DrvSdFreeNodeInfo;
    drv->notifyDdb = DrvNotifySd;
    drv->setMinority = DrvSdSetMinority;
    drv->getAlarm = DrvSdGetAlarm;
    drv->leaderNodeId = DrvSdLeaderNodeId;
    drv->restConn = DrvSdRestConn;
    drv->setParam = DrvSdSetParam;
    g_cmSdServerNum = apiInfo->nodeNum;
    status_t st = InitSdManagerLock(apiInfo);
    if (st != CM_SUCCESS) {
        return st;
    }

    return CreateShareDiskThread(apiInfo);
}

DdbDriver *DrvSdGet(void)
{
    return &g_drvSd;
}
