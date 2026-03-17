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
 * cm_client_api.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_client/cm_client_api.cpp
 *
 * -------------------------------------------------------------------------
 */
#include <stdlib.h>
#include "cm/cm_elog.h"
#include "cm/cm_msg.h"
#include "cm_client.h"
#include "cm_client_api.h"

static char *g_jsonStrPtr = NULL;

static bool IsStrOverLength(const char *str, uint32 maxLen)
{
    uint32 len = 0;
    while (len < maxLen) {
        if (str[len++] == '\0') {
            return true;
        }
    }
    return false;
}

static bool CanDoCmInit(const char *resName)
{
    if (GetIsClientInit()) {
        write_runlog(LOG, "cm_client has init, can't do init again.\n");
        return false;
    }
    if (resName == NULL) {
        (void)printf(_("resName length is NULL.\n"));
        return false;
    }
    if (!IsStrOverLength(resName, CM_MAX_RES_NAME)) {
        (void)printf(_("resName length >= %d.\n"), CM_MAX_RES_NAME);
        return false;
    }
    return true;
}

ClientCmLockMsg *GetLockSendMsg(const char *lockName, LockOption opt)
{
    ClientCmLockMsg *sendMsg = (ClientCmLockMsg*) malloc(sizeof(ClientCmLockMsg));
    if (sendMsg == NULL) {
        write_runlog(ERROR, "out of memory, lock option = %u.\n", (uint32)opt);
        return NULL;
    }
    sendMsg->head.msgType = (uint32)MSG_CM_RES_LOCK;
    sendMsg->info.lockOpt = (uint32)opt;
    errno_t rc = strcpy_s(sendMsg->info.lockName, CM_MAX_LOCK_NAME, lockName);
    securec_check_errno(rc, (void)rc);
    return sendMsg;
}

int ResLockCore(const char *lockName)
{
    if (access(g_manualPausePath, F_OK) == 0 && strcmp(lockName, "dms_reformer_lock") == 0) {
        write_runlog(LOG, "cm is pause, don't lock(%s).\n", lockName);
        return 1;
    }
    ClientCmLockMsg *sendMsg = GetLockSendMsg(lockName, CM_RES_LOCK);
    if (sendMsg == NULL) {
        write_runlog(ERROR, "generate (%s)lock msg failed.\n", lockName);
        return 1;
    }

    ClientLockResult lockResult = SendLockMsgAndWaitResult((char*)sendMsg, sizeof(ClientCmLockMsg));
    if (lockResult.error != 0) {
        write_runlog(ERROR, "(%s)lock fail, error=%u.\n", lockName, lockResult.error);
    } else {
        write_runlog(LOG, "(%s)lock success.\n", lockName);
    }

    return (int)lockResult.error;
}

int ResUnlockCore(const char *lockName)
{
    ClientCmLockMsg *sendMsg = GetLockSendMsg(lockName, CM_RES_UNLOCK);
    if (sendMsg == NULL) {
        write_runlog(ERROR, "generate (%s) unlock msg failed.\n", lockName);
        return 1;
    }

    ClientLockResult lockResult = SendLockMsgAndWaitResult((char*)sendMsg, sizeof(ClientCmLockMsg));
    if (lockResult.error != 0) {
        write_runlog(ERROR, "unlock fail, error=%u.\n", lockResult.error);
    } else {
        write_runlog(LOG, "unlock success.\n");
    }

    return (int)lockResult.error;
}

int ResGetLockOwnerCore(const char *lockName, unsigned int *instId)
{
    ClientCmLockMsg *sendMsg = GetLockSendMsg(lockName, CM_RES_GET_LOCK_OWNER);
    if (sendMsg == NULL) {
        write_runlog(ERROR, "generate (%s) get lock owner msg failed.\n", lockName);
        return 1;
    }

    ClientLockResult lockResult = SendLockMsgAndWaitResult((char*)sendMsg, sizeof(ClientCmLockMsg));
    if (lockResult.error != 0) {
        write_runlog(ERROR, "get lock owner fail, error=%u.\n", lockResult.error);
    } else {
        *instId = lockResult.ownerId;
    }

    return (int)lockResult.error;
}

int ResTransLockCore(const char *lockName, unsigned int instId)
{
    ClientCmLockMsg *sendMsg = GetLockSendMsg(lockName, CM_RES_LOCK_TRANS);
    if (sendMsg == NULL) {
        write_runlog(ERROR, "generate (%s) get lock owner msg failed.\n", lockName);
        return 1;
    }
    sendMsg->info.transInstId = instId;

    ClientLockResult lockResult = SendLockMsgAndWaitResult((char*)sendMsg, sizeof(ClientCmLockMsg));
    if (lockResult.error != 0) {
        write_runlog(ERROR, "trans lock owner failed, error=%u.\n", lockResult.error);
    } else {
        write_runlog(LOG, "trans lock owner to %u success.\n", instId);
    }

    return (int)lockResult.error;
}

bool CanDoLockOperate(const char *lockName)
{
    if (!GetIsClientInit()) {
        (void)printf(_("cm_client is not alive, please init cm_client first.\n"));
        return false;
    }
    if (lockName == NULL) {
        write_runlog(ERROR, "lock name is NULL.\n");
        return false;
    }
    if (!IsStrOverLength(lockName, CM_MAX_LOCK_NAME)) {
        write_runlog(ERROR, "lock name is too long, max len is %d.\n", CM_MAX_LOCK_NAME);
        return false;
    }
    return true;
}

bool CanDoGetLockOwner(const char *lockName, const unsigned int *instId)
{
    if (!CanDoLockOperate(lockName)) {
        return false;
    }
    if (instId == NULL) {
        write_runlog(ERROR, "input parameter is NULL, can't get lock owner.\n");
        return false;
    }
    return true;
}

#ifdef __cplusplus
extern "C" {
#endif

int CmInit(unsigned int instId, const char *resName, CmNotifyFunc func)
{
    static bool isFirstInit = true;
    if (!CanDoCmInit(resName)) {
        return -1;
    }
    if (PreInit(instId, resName, func, &isFirstInit) != CM_SUCCESS) {
        (void)printf(_("resName(%s) instanceId(%u) init cm_client failed.\n"), resName, instId);
        return -1;
    }
    bool &isClientInit = GetIsClientInit();
    isClientInit = false;
    if (CreateConnectAgentThread() != CM_SUCCESS || CreateSendMsgThread() != CM_SUCCESS ||
        CreateRecvMsgThread() != CM_SUCCESS) {
        write_runlog(LOG, "cm_client create thread failed.\n");
        ShutdownClient();
        return -1;
    }
    bool isSuccess = SendInitMsgAndGetResult(resName, instId);
    if (!isSuccess) {
        write_runlog(ERROR, "resName(%s) instanceId(%u) init client failed, can check agent.\n", resName, instId);
        ShutdownClient();
        return -1;
    }
    write_runlog(LOG, "resName(%s) instanceId(%u) init cm_client success.\n", resName, instId);
    isClientInit = true;
    return 0;
}

void CmClientFini()
{
    ShutdownClient();
    FreeClientMemory();
}

static void GetResStatJsonHead(char *jsonStr, uint32 strLen, const OneResStatList *statList)
{
    int ret = snprintf_s(jsonStr,
        strLen,
        strLen - 1,
        "{\"version\":%llu,\"res_name\":\"%s\",\"inst_count\":%u,\"inst_status\":[",
        statList->version,
        statList->resName,
        statList->instanceCount);
    securec_check_intval(ret, (void)ret);
}

static void GetResStatJsonInst(char *instInfo, uint32 strLen, const CmResStatInfo *instStat, bool isEnd)
{
    int ret = snprintf_s(instInfo,
        strLen,
        strLen - 1,
        "{\"node_id\":%u,\"cm_instance_id\":%u,\"res_instance_id\":%u,\"is_work_member\":%u,\"status\":%u}",
        instStat->nodeId,
        instStat->cmInstanceId,
        instStat->resInstanceId,
        instStat->isWorkMember,
        instStat->status);
    securec_check_intval(ret, (void)ret);
    if (!isEnd) {
        errno_t rc = strcat_s(instInfo, MAX_PATH_LEN, ",");
        securec_check_errno(rc, (void)rc);
    }
}

static void ResStatusToJsonStr(const OneResStatList *statList)
{
    const int maxJsonStrLen = 10240;
    char jsonStr[maxJsonStrLen] = {0};

    GetResStatJsonHead(jsonStr, maxJsonStrLen, statList);

    errno_t rc;
    for (uint32 i = 0; i < statList->instanceCount; ++i) {
        char instInfo[MAX_PATH_LEN] = {0};
        GetResStatJsonInst(instInfo, MAX_PATH_LEN, &statList->resStat[i], (i == (statList->instanceCount - 1)));
        rc = strcat_s(jsonStr, maxJsonStrLen, instInfo);
        securec_check_errno(rc, (void)rc);
    }
    rc = strcat_s(jsonStr, maxJsonStrLen, "]}");
    securec_check_errno(rc, (void)rc);

    g_jsonStrPtr = strdup(jsonStr);
}

char *CmGetResStats()
{
    OneResStatList *statusList = GetClientStatusList();
    if (statusList->version == 0) {
        write_runlog(LOG, "version is 0, statList is invalid.\n");
        return NULL;
    }
    ResStatusToJsonStr(statusList);
    return g_jsonStrPtr;
}

int CmFreeResStats(char *resStats)
{
    if (resStats == NULL) {
        write_runlog(ERROR, "res stat ptr is NULL, can't free.\n");
        return 1;
    }
    if (resStats != g_jsonStrPtr) {
        write_runlog(ERROR, "res stat ptr is not stat list ptr, can't free.\n");
        return 1;
    }
    FREE_AND_RESET(g_jsonStrPtr);
    return 0;
}

int CmResLock(const char *lockName)
{
    if (!CanDoLockOperate(lockName)) {
        return 1;
    }
    return ResLockCore(lockName);
}

int CmResUnlock(const char *lockName)
{
    if (!CanDoLockOperate(lockName)) {
        return 1;
    }
    return ResUnlockCore(lockName);
}

int CmResGetLockOwner(const char *lockName, unsigned int *instId)
{
    if (!CanDoGetLockOwner(lockName, instId)) {
        return 1;
    }
    return ResGetLockOwnerCore(lockName, instId);
}

int CmResTransLock(const char *lockName, unsigned int instId)
{
    if (!CanDoLockOperate(lockName)) {
        return 1;
    }
    return ResTransLockCore(lockName, instId);
}

#ifdef __cplusplus
}
#endif
