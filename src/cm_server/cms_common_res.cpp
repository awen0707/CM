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
* cms_common.cpp
*
*
* IDENTIFICATION
*    src/cm_server/cms_common_res.cpp
*
* -------------------------------------------------------------------------
 */
#include "cjson/cJSON.h"
#include "cms_ddb_adapter.h"
#include "cms_global_params.h"
#include "cms_process_messages.h"
#include "cms_common_res.h"

typedef struct NodeIsregCheckListSt {
    uint32 nodeId;
    volatile uint32 reportInter;
    bool isValid;
    uint32 defCheckCount;
    uint32 defCheckList[CM_MAX_RES_INST_COUNT];
    uint32 checkCount;
    uint32 checkList[CM_MAX_RES_INST_COUNT];
} NodeIsregCheckList;

typedef struct AgentIsregCheckListSt {
    uint32 nodeCount;
    NodeIsregCheckList nodeCheck[CM_MAX_RES_NODE_COUNT];
} AgentIsregCheckList;

typedef struct OneResInstIsregSt {
    uint32 cmInstId;
    ResIsregStatus isreg;
} OneResInstIsreg;

typedef struct OneResIsregSt {
    char resName[CM_MAX_RES_NAME];
    uint32 instCount;
    OneResInstIsreg resStat[CM_MAX_RES_INST_COUNT];
} OneResIsreg;

typedef struct AllResIsregSt {
    uint64 version;
    uint32 resCount;
    OneResIsreg res[CM_MAX_RES_COUNT];
} AllResIsreg;

static AllResIsreg g_isregStatus = {0};
static AgentIsregCheckList g_isregCheckList = {0};

static void InitCheckList(uint32 nodeId, NodeIsregCheckList *isregCheck)
{
    isregCheck->checkCount = 0;
    isregCheck->defCheckCount = 0;
    for (uint32 i = 0; i < CusResCount(); ++i) {
        for (uint32 j = 0; j < g_resStatus[i].status.instanceCount; ++j) {
            if (g_resStatus[i].status.resStat[j].nodeId == nodeId) {
                isregCheck->checkList[isregCheck->checkCount++] = g_resStatus[i].status.resStat[j].cmInstanceId;
                isregCheck->defCheckList[isregCheck->defCheckCount++] = g_resStatus[i].status.resStat[j].cmInstanceId;
            }
        }
    }
}

void InitIsregVariable()
{
    g_isregStatus.version = 0;
    g_isregStatus.resCount = CusResCount();
    for (uint32 i = 0; i < g_isregStatus.resCount; ++i) {
        errno_t rc = strcpy_s(g_isregStatus.res[i].resName, CM_MAX_RES_NAME, g_resStatus[i].status.resName);
        securec_check_errno(rc, (void)rc);
        g_isregStatus.res[i].instCount = g_resStatus[i].status.instanceCount;
        for (uint32 j = 0; j < g_isregStatus.res[i].instCount; ++j) {
            g_isregStatus.res[i].resStat[j].isreg = CM_RES_ISREG_INIT;
            g_isregStatus.res[i].resStat[j].cmInstId = g_resStatus[i].status.resStat[j].cmInstanceId;
        }
    }

    g_isregCheckList.nodeCount = GetResNodeCount();
    for (uint32 i = 0; i < g_isregCheckList.nodeCount; ++i) {
        g_isregCheckList.nodeCheck[i].nodeId = GetResNodeId(i);
        g_isregCheckList.nodeCheck[i].reportInter = 0;
        g_isregCheckList.nodeCheck[i].isValid = true;
        InitCheckList(g_isregCheckList.nodeCheck[i].nodeId, &g_isregCheckList.nodeCheck[i]);
    }
}

static void PrintOneNodeCheckList(const uint32 *checkList, uint32 Len, int logLevel)
{
    char checkListStr[MAX_PATH_LEN] = {0};
    for (uint32 i = 0; i < Len; ++i) {
        const uint32 itemLen = 16;
        char itemStr[itemLen] = {0};
        int ret = snprintf_s(itemStr, itemLen, itemLen - 1, "%u, ", checkList[i]);
        securec_check_intval(ret, (void)ret);
        errno_t rc = strcat_s(checkListStr, MAX_PATH_LEN, itemStr);
        securec_check_errno(rc, (void)rc);
    }

    write_runlog(logLevel, "check list: %s.\n", checkListStr);
}

static void PrintAllCheckList(int logLevel)
{
    for (uint32 i = 0; i < g_isregCheckList.nodeCount; ++i) {
        const NodeIsregCheckList *oneNodeCheckList = &g_isregCheckList.nodeCheck[i];
        write_runlog(logLevel, "node(%u) check list, is_valid(%d), report_inter(%u).\n",
            oneNodeCheckList->nodeId, oneNodeCheckList->isValid, oneNodeCheckList->reportInter);
        PrintOneNodeCheckList(oneNodeCheckList->checkList, oneNodeCheckList->checkCount, logLevel);
    }
}

void UpdateReportInter()
{
    for (uint32 i = 0; i < g_isregCheckList.nodeCount; ++i) {
        ++g_isregCheckList.nodeCheck[i].reportInter;
    }
}

static void DelInstCheckList(uint32 instId, NodeIsregCheckList *nodeCheckList)
{
    uint32 destIndex = nodeCheckList->checkCount;
    for (uint32 i = 0; i < nodeCheckList->checkCount; ++i) {
        if (nodeCheckList->checkList[i] == instId) {
            destIndex = i;
            break;
        }
    }
    if (destIndex == nodeCheckList->checkCount) {
        return;
    }

    for (uint32 i = destIndex; i < nodeCheckList->checkCount - 1; ++i) {
        nodeCheckList->checkList[i] = nodeCheckList->checkList[i + 1];
    }
    nodeCheckList->checkList[nodeCheckList->checkCount - 1] = 0;
    --nodeCheckList->checkCount;
    PrintAllCheckList(LOG);
}

static void RestoreCheckList(uint32 index)
{
    uint32 *defCheckList = g_isregCheckList.nodeCheck[index].defCheckList;
    uint32 defCheckCount = g_isregCheckList.nodeCheck[index].defCheckCount;

    for (uint32 i = 0; i < defCheckCount; ++i) {
        uint32 instId = defCheckList[i];
        for (uint32 k = 0; k < g_isregCheckList.nodeCount; ++k) {
            if (k == index) {
                continue;
            }
            DelInstCheckList(instId, &g_isregCheckList.nodeCheck[k]);
        }
    }
}

void CleanReportInter(uint32 nodeId)
{
    for (uint32 i = 0; i < g_isregCheckList.nodeCount; ++i) {
        if (g_isregCheckList.nodeCheck[i].nodeId == nodeId) {
            g_isregCheckList.nodeCheck[i].reportInter = 0;
            g_isregCheckList.nodeCheck[i].isValid = true;
            RestoreCheckList(i);
        }
    }
}

static void AddCheckList(uint32 newIndex, uint32 errIndex)
{
    NodeIsregCheckList *newCheckList = &g_isregCheckList.nodeCheck[newIndex];
    const NodeIsregCheckList *errCheckList = &g_isregCheckList.nodeCheck[errIndex];

    for (uint32 i = 0; i < errCheckList->checkCount; ++i) {
        newCheckList->checkList[newCheckList->checkCount + i] = errCheckList->checkList[i];
    }
    newCheckList->checkCount += errCheckList->checkCount;
}

static uint32 GetFirstValidIndex(uint32 errIndex)
{
    for (uint32 i = 0; i < g_isregCheckList.nodeCount; ++i) {
        if (i == errIndex) {
            continue;
        }
        if (g_isregCheckList.nodeCheck[i].isValid) {
            return i;
        }
    }
    return g_isregCheckList.nodeCount;
}

static void ChangeCheckList(uint32 errIndex)
{
    uint32 newIndex = GetFirstValidIndex(errIndex);
    if (newIndex == g_isregCheckList.nodeCount) {
        write_runlog(ERROR, "no node is valid to report isreg status.\n");
        return;
    }

    for (uint32 i = (newIndex + 1); i < g_isregCheckList.nodeCount; ++i) {
        if ((i == errIndex) || !g_isregCheckList.nodeCheck[i].isValid) {
            continue;
        }
        if (g_isregCheckList.nodeCheck[i].checkCount < g_isregCheckList.nodeCheck[newIndex].checkCount) {
            newIndex = i;
        }
    }

    AddCheckList(newIndex, errIndex);

    g_isregCheckList.nodeCheck[errIndex].checkCount = g_isregCheckList.nodeCheck[errIndex].defCheckCount;
    errno_t rc = memcpy_s(g_isregCheckList.nodeCheck[errIndex].checkList, (sizeof(uint32) * CM_MAX_RES_INST_COUNT),
        g_isregCheckList.nodeCheck[errIndex].defCheckList, (sizeof(uint32) * CM_MAX_RES_INST_COUNT));
    securec_check_errno(rc, (void)rc);

    write_runlog(LOG, "transfer node(%u) check list to node(%u).\n", g_isregCheckList.nodeCheck[errIndex].nodeId,
        g_isregCheckList.nodeCheck[newIndex].nodeId);
    PrintAllCheckList(LOG);
}

void UpdateCheckListAfterTimeout()
{
    const uint32 isregTimeout = g_agentNetworkTimeout;
    for (uint32 i = 0; i < g_isregCheckList.nodeCount; ++i) {
        if ((g_isregCheckList.nodeCheck[i].reportInter > isregTimeout) && g_isregCheckList.nodeCheck[i].isValid) {
            g_isregCheckList.nodeCheck[i].isValid = false;
            ChangeCheckList(i);
        }
    }
}

ResIsregStatus GetIsregStatusByCmInstId(uint32 cmInstId)
{
    for (uint32 i = 0; i < g_isregStatus.resCount; ++i) {
        for (uint32 j = 0; j < g_isregStatus.res[i].instCount; ++j) {
            if (g_isregStatus.res[i].resStat[j].cmInstId == cmInstId) {
                return g_isregStatus.res[i].resStat[j].isreg;
            }
        }
    }
    write_runlog(ERROR, "%s, unknown instId:%u.\n", __FUNCTION__, cmInstId);
    return CM_RES_ISREG_UNKNOWN;
}

void GetCheckListByNodeId(uint32 nodeId, uint32 *checkList, uint32 *checkCount)
{
    for (uint32 i = 0; i < g_isregCheckList.nodeCount; ++i) {
        if (g_isregCheckList.nodeCheck[i].nodeId != nodeId) {
            continue;
        }
        (*checkCount) = g_isregCheckList.nodeCheck[i].checkCount;
        for (uint32 j = 0; j < (*checkCount); ++j) {
            checkList[j] = g_isregCheckList.nodeCheck[i].checkList[j];
        }
        return;
    }
}

void UpdateIsworkList(uint32 cmInstId, int newIswork)
{
    for (uint32 i = 0; i < CusResCount(); ++i) {
        for (uint32 j = 0; j < g_resStatus[i].status.instanceCount; ++j) {
            if (g_resStatus[i].status.resStat[j].cmInstanceId != cmInstId) {
                continue;
            }
            if (newIswork == RES_INST_WORK_STATUS_UNAVAIL) {
                ReleaseResLockOwner(g_resStatus[i].status.resName, g_resStatus[i].status.resStat[j].cmInstanceId);
            }
            if (g_resStatus[i].status.resStat[j].isWorkMember != (uint32)newIswork) {
                (void)pthread_rwlock_wrlock(&g_resStatus[i].rwlock);
                g_resStatus[i].status.resStat[j].isWorkMember = (uint32)newIswork;
                ++(g_resStatus[i].status.version);
                OneResStatList resStat = g_resStatus[i].status;
                (void)pthread_rwlock_unlock(&g_resStatus[i].rwlock);

                ProcessReportResChangedMsg(false, &resStat);
                PrintCusInfoResList(&resStat, __FUNCTION__);
            }
            return;
        }
    }
}

void PrintCurrentIsregStatusList()
{
    write_runlog(LOG, "isreg status list, version:%lu.\n", g_isregStatus.version);
    for (uint32 i = 0; i < g_isregStatus.resCount; ++i) {
        char resIsreg[MAX_PATH_LEN] = {0};
        for (uint32 j = 0; j < g_isregStatus.res[i].instCount; ++j) {
            const uint32 instIsregLen = 32;
            char instStr[instIsregLen] = {0};
            int ret = snprintf_s(instStr, instIsregLen, instIsregLen - 1, "%u:%s, ",
                g_isregStatus.res[i].resStat[j].cmInstId, GetIsregStatus((int)g_isregStatus.res[i].resStat[j].isreg));
            securec_check_intval(ret, (void)ret);
            errno_t rc = strcat_s(resIsreg, MAX_PATH_LEN, instStr);
            securec_check_errno(rc, (void)rc);
        }
        write_runlog(LOG, "res(%s) isreg list: %s\n", g_isregStatus.res[i].resName, resIsreg);
    }
}

void UpdateIsregStatusList(uint32 cmInstId, ResIsregStatus newIsreg)
{
    for (uint32 i = 0; i < g_isregStatus.resCount; ++i) {
        for (uint32 j = 0; j < g_isregStatus.res[i].instCount; ++j) {
            if (g_isregStatus.res[i].resStat[j].cmInstId != cmInstId) {
                continue;
            }
            if (g_isregStatus.res[i].resStat[j].isreg != newIsreg) {
                g_isregStatus.res[i].resStat[j].isreg = newIsreg;
                ++g_isregStatus.version;
                PrintCurrentIsregStatusList();
            }
            return;
        }
    }
    write_runlog(ERROR, "%s, unknown instId:%u.\n", __FUNCTION__, cmInstId);
}

bool IsRecvIsregStatValid(int stat)
{
    return (stat >= (int)CM_RES_ISREG_INIT && stat < (int)CM_RES_ISREG_CEIL);
}

static ResIsregStatus GetNewIsregStatus(uint32 instId, ResInstIsreg *isregList, uint32 isregCount)
{
    for (uint32 i = 0; i < isregCount; ++i) {
        if (isregList[i].cmInstId != instId) {
            continue;
        }
        if (!IsRecvIsregStatValid(isregList[i].isreg)) {
            write_runlog(ERROR, "recv inst(%u) isreg status(%d) invalid.\n", isregList[i].cmInstId, isregList[i].isreg);
            return CM_RES_ISREG_UNKNOWN;
        }
        return (ResIsregStatus)isregList[i].isreg;
    }
    return CM_RES_ISREG_INIT;
}

void UpdateResIsregStatusList(uint32 nodeId, ResInstIsreg *isregList, uint32 isregCount, bool *needChangCheckList)
{
    (*needChangCheckList) = false;

    for (uint32 i = 0; i < g_isregCheckList.nodeCount; ++i) {
        if (g_isregCheckList.nodeCheck[i].nodeId != nodeId) {
            continue;
        }
        for (uint32 k = 0; k < g_isregCheckList.nodeCheck[i].checkCount; ++k) {
            ResIsregStatus stat = GetNewIsregStatus(g_isregCheckList.nodeCheck[i].checkList[k], isregList, isregCount);
            if (stat == CM_RES_ISREG_INIT) {
                (*needChangCheckList) = true;
                continue;
            }
            UpdateIsregStatusList(g_isregCheckList.nodeCheck[i].checkList[k], stat);
        }
        if (g_isregCheckList.nodeCheck[i].checkCount != isregCount) {
            (*needChangCheckList) = true;
        }
        return;
    }
}

static inline void GetResStatusDdbKey(char *key, size_t keyLen, const char *resName)
{
    errno_t rc = snprintf_s(key, keyLen, keyLen - 1, "/%s/CM/CMServer/ResStatus/%s", pw->pw_name, resName);
    securec_check_intval(rc, (void)rc);
}

static cJSON *CreateOneInstStatusObj(const CmResStatInfo *status)
{
    cJSON *instStat = cJSON_CreateObject();
    (void)cJSON_AddNumberToObject(instStat, "cmInstId", (const double)status->cmInstanceId);
    (void)cJSON_AddNumberToObject(instStat, "isWorkMember", (const double)status->isWorkMember);
    (void)cJSON_AddNumberToObject(instStat, "status", (const double)status->status);
    if (!cJSON_IsObject(instStat)) {
        cJSON_Delete(instStat);
        return NULL;
    }
    return instStat;
}

static status_t AddAllResInstStatToJson(cJSON *root, const OneResStatList *oneResStat)
{
    char versionStr[MAX_PATH_LEN];
    int ret = sprintf_s(versionStr, MAX_PATH_LEN, "%llu", oneResStat->version);
    securec_check_intval(ret, (void)ret);
    (void)cJSON_AddStringToObject(root, "version", versionStr);
    cJSON *instArray = cJSON_AddArrayToObject(root, "instStatus");
    if (!cJSON_IsArray(instArray)) {
        write_runlog(ERROR, "get res(%s)'s all inst status array failed.\n", oneResStat->resName);
        return CM_ERROR;
    }
    for (uint32 i = 0; i < oneResStat->instanceCount; ++i) {
        cJSON *instStat = CreateOneInstStatusObj(&oneResStat->resStat[i]);
        if (instStat == NULL) {
            write_runlog(ERROR, "get res(%s)'s one inst status obj failed.\n", oneResStat->resName);
            return CM_ERROR;
        }
        if (!cJSON_AddItemToArray(instArray, instStat)) {
            write_runlog(ERROR, "add res(%s)'s one inst to instArray failed.\n", oneResStat->resName);
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

static status_t SetResStatJsonToDdb(const cJSON *root, const char *resName)
{
    char *resStatJson = cJSON_PrintUnformatted(root);
    CM_RETERR_IF_NULL(resStatJson);
    char key[MAX_PATH_LEN] = {0};
    GetResStatusDdbKey(key, MAX_PATH_LEN, resName);
    if (SetKV2Ddb(key, MAX_PATH_LEN, resStatJson, (uint32)strlen(resStatJson), NULL) != CM_SUCCESS) {
        cJSON_free(resStatJson);
        return CM_ERROR;
    }
    cJSON_free(resStatJson);
    return CM_SUCCESS;
}

status_t SaveOneResStatusToDdb(const OneResStatList *oneResStat)
{
    const char *resName = oneResStat->resName;
    cJSON *root = cJSON_CreateObject();
    if (!cJSON_IsObject(root)) {
        write_runlog(ERROR, "create res status json obj failed, save res(%s) status failed.\n", resName);
        cJSON_Delete(root);
        return CM_ERROR;
    }

    if (AddAllResInstStatToJson(root, oneResStat) != CM_SUCCESS) {
        write_runlog(ERROR, "fill res status json obj failed, save res(%s) status failed.\n", resName);
        cJSON_Delete(root);
        return CM_ERROR;
    }

    if (SetResStatJsonToDdb(root, resName) != CM_SUCCESS) {
        write_runlog(ERROR, "set res status json obj to ddb failed, save res(%s) status failed.\n", resName);
        cJSON_Delete(root);
        return CM_ERROR;
    }

    write_runlog(LOG, "save res(%s) version(%llu) status json to ddb success.\n", resName, oneResStat->version);
    cJSON_Delete(root);
    return CM_SUCCESS;
}

static status_t ParseAndProcessOneResInst(cJSON *instItem, OneResStatList *resStat)
{
    cJSON *tmpObj = cJSON_GetObjectItem(instItem, "cmInstId");
    if (!cJSON_IsNumber(tmpObj)) {
        write_runlog(ERROR, "get cmInstId from res(%s) status json failed.\n", resStat->resName);
        return CM_ERROR;
    }
    uint32 cmInstId = (uint32)tmpObj->valueint;
    for (uint32 i = 0; i < resStat->instanceCount; ++i) {
        if (resStat->resStat[i].cmInstanceId != cmInstId) {
            continue;
        }
        tmpObj = cJSON_GetObjectItem(instItem, "isWorkMember");
        if (!cJSON_IsNumber(tmpObj)) {
            write_runlog(ERROR, "get isWorkMember from res(%s) status json failed.\n", resStat->resName);
            return CM_ERROR;
        }
        resStat->resStat[i].isWorkMember = (uint32)tmpObj->valueint;
        tmpObj = cJSON_GetObjectItem(instItem, "status");
        if (!cJSON_IsNumber(tmpObj)) {
            write_runlog(ERROR, "get status from res(%s) status json failed.\n", resStat->resName);
            return CM_ERROR;
        }
        resStat->resStat[i].status = (uint32)tmpObj->valueint;
    }

    return CM_SUCCESS;
}

static status_t UpdateResStatus(OneResStatList *resStat, const cJSON * const resObj)
{
    cJSON *versionObj = cJSON_GetObjectItem(resObj, "version");
    if (!cJSON_IsString(versionObj)) {
        write_runlog(ERROR, "get version from res(%s) status json failed.\n", resStat->resName);
        return CM_ERROR;
    }
    resStat->version = (unsigned long long)CmAtol(versionObj->valuestring, 0);
    cJSON *instStatArray = cJSON_GetObjectItem(resObj, "instStatus");
    if (!cJSON_IsArray(instStatArray)) {
        write_runlog(ERROR, "get instStatus array from res(%s) status json failed.\n", resStat->resName);
        return CM_ERROR;
    }

    cJSON *instItem;
    cJSON_ArrayForEach(instItem, instStatArray) {
        CM_RETURN_IFERR(ParseAndProcessOneResInst(instItem, resStat));
    }

    return CM_SUCCESS;
}

status_t GetOneResStatusFromDdb(OneResStatList *resStat)
{
    char key[MAX_PATH_LEN] = {0};
    char value[MAX_PATH_LEN] = {0};
    GetResStatusDdbKey(key, MAX_PATH_LEN, resStat->resName);
    DDB_RESULT ddbResult = SUCCESS_GET_VALUE;
    if (GetKVFromDDb(key, MAX_PATH_LEN, value, MAX_PATH_LEN, &ddbResult) != CM_SUCCESS) {
        if (ddbResult == CAN_NOT_FIND_THE_KEY) {
            write_runlog(LOG, "not exit res(%s) status, key:\"%s\" in ddb.\n", resStat->resName, key);
            return CM_SUCCESS;
        } else {
            write_runlog(ERROR, "get res(%s) status %s from ddb failed: %d.\n", resStat->resName, key, (int)ddbResult);
            return CM_ERROR;
        }
    }

    write_runlog(LOG, "get res(%s) status json str success, str:\"%s\".\n", resStat->resName, value);
    cJSON *root = cJSON_Parse(value);
    if (cJSON_IsObject(root)) {
        OneResStatList tmpResStat = (*resStat);
        if (UpdateResStatus(&tmpResStat, root) == CM_SUCCESS) {
            errno_t rc = memcpy_s(resStat, sizeof(OneResStatList), &tmpResStat, sizeof(OneResStatList));
            securec_check_errno(rc, (void)rc);
        }
    } else {
        write_runlog(ERROR, "res(%s) status json str in ddb is irregular.\n", resStat->resName);
    }

    cJSON_Delete(root);
    return CM_SUCCESS;
}

status_t GetAllResStatusFromDdb()
{
    write_runlog(LOG, "get latest res status from ddb.\n");
    for (uint32 i = 0; i < CusResCount(); ++i) {
        OneResStatList tmpResStat = g_resStatus[i].status;
        CM_RETURN_IFERR(GetOneResStatusFromDdb(&tmpResStat));
        PrintCusInfoResList(&tmpResStat, __FUNCTION__);

        (void)pthread_rwlock_wrlock(&g_resStatus[i].rwlock);
        errno_t rc = memcpy_s(&g_resStatus[i].status, sizeof(OneResStatList), &tmpResStat, sizeof(OneResStatList));
        securec_check_errno(rc, (void)rc);
        (void)pthread_rwlock_unlock(&g_resStatus[i].rwlock);
    }

    return CM_SUCCESS;
}

void SendRegMsgToCma(uint32 destNodeId, int resMode, uint32 resInstId, const char *resName, ResIsregStatus resStat)
{
    CmsNotifyAgentRegMsg sendMsg = {0};
    sendMsg.msgType = (int32)MSG_CM_RES_REG;
    sendMsg.resMode = resMode;
    sendMsg.nodeId = destNodeId;
    sendMsg.resInstId = resInstId;
    sendMsg.resStat = resStat;
    errno_t rc = strcpy_s(sendMsg.resName, CM_MAX_RES_NAME, resName);
    securec_check_errno(rc, (void)rc);

    if (resMode == 0) {
        (void)BroadcastMsg('S', (char *)(&sendMsg), sizeof(CmsNotifyAgentRegMsg), LOG);
    } else if (resMode == 1) {
        (void)SendToAgentMsg(destNodeId, 'S', (char *)(&sendMsg), sizeof(CmsNotifyAgentRegMsg), LOG);
    } else {
        write_runlog(ERROR, "%s, unknown resMode(%d).\n", __FUNCTION__, resMode);
    }
}

void NotifyCmaDoReg(uint32 destNodeId)
{
    for (uint32 i = 0; i < CusResCount(); ++i) {
        const OneResStatList *resInfo = &g_resStatus[i].status;
        for (uint32 j = 0; j < resInfo->instanceCount; ++j) {
            if (resInfo->resStat[j].nodeId != destNodeId) {
                continue;
            }
            ResIsregStatus isreg = GetIsregStatusByCmInstId(resInfo->resStat[j].cmInstanceId);
            if (isreg == CM_RES_ISREG_REG) {
                UpdateIsworkList(resInfo->resStat[j].cmInstanceId, RES_INST_WORK_STATUS_AVAIL);
            } else if (isreg == CM_RES_ISREG_UNREG || isreg == CM_RES_ISREG_PENDING || isreg == CM_RES_ISREG_INIT) {
                SendRegMsgToCma(destNodeId, 1, resInfo->resStat[j].resInstanceId, resInfo->resName, isreg);
            } else if (isreg == CM_RES_ISREG_NOT_SUPPORT && resInfo->resStat[j].status == (uint32)CM_RES_STAT_OFFLINE) {
                UpdateIsworkList(resInfo->resStat[j].cmInstanceId, RES_INST_WORK_STATUS_AVAIL);
            }
        }
    }
}

void NotifyCmaDoUnreg(uint32 destNodeId)
{
    for (uint32 i = 0; i < CusResCount(); ++i) {
        const OneResStatList *resInfo = &g_resStatus[i].status;
        for (uint32 j = 0; j < g_resStatus[i].status.instanceCount; ++j) {
            if (g_resStatus[i].status.resStat[j].nodeId != destNodeId) {
                continue;
            }
            ResIsregStatus isreg = GetIsregStatusByCmInstId(g_resStatus[i].status.resStat[j].cmInstanceId);
            if (isreg == CM_RES_ISREG_REG || isreg == CM_RES_ISREG_PENDING || isreg == CM_RES_ISREG_INIT) {
                SendRegMsgToCma(destNodeId, 0, resInfo->resStat[j].resInstanceId, resInfo->resName, isreg);
                ReleaseResLockOwner(g_resStatus[i].status.resName, g_resStatus[i].status.resStat[j].cmInstanceId);
            } else if (isreg == CM_RES_ISREG_UNREG || isreg == CM_RES_ISREG_NOT_SUPPORT) {
                UpdateIsworkList(g_resStatus[i].status.resStat[j].cmInstanceId, RES_INST_WORK_STATUS_UNAVAIL);
            }
        }
    }
}
