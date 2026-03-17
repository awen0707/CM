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
* cma_status_check_res.cpp
*    cma send res isreg and status check msg
*
* IDENTIFICATION
*    src/cm_agent/cma_status_check_res.cpp
*
* -------------------------------------------------------------------------
*/
#include <cjson/cJSON.h>
#include "cma_common.h"
#include "cma_global_params.h"
#include "cma_instance_management_res.h"

typedef struct ResIsregCheckListSt {
    uint32 checkList[CM_MAX_RES_INST_COUNT];  // cmInstId
    uint32 checkCount;
} ResIsregCheckList;

typedef struct OneNodeResIsregInfoSt {
    pthread_rwlock_t rwlock;
    CmaToCmsIsregMsg isreg;
} OneNodeResIsregInfo;

static ResIsregCheckList g_isregCheckList;
static OneNodeResIsregInfo g_isregStatus;

void InitIsregCheckVar()
{
    errno_t rc = memset_s(&g_isregStatus, sizeof(OneNodeResIsregInfo), 0, sizeof(OneNodeResIsregInfo));
    securec_check_errno(rc, (void)rc);
    rc = memset_s(&g_isregCheckList, sizeof(ResIsregCheckList), 0, sizeof(ResIsregCheckList));
    securec_check_errno(rc, (void)rc);
    g_isregCheckList.checkCount = GetLocalResConfCount();
    for (uint32 i = 0; i < GetLocalResConfCount(); ++i) {
        g_isregCheckList.checkList[i] = g_resConf[i].cmInstanceId;
    }
    (void)pthread_rwlock_init(&g_isregStatus.rwlock, NULL);
    g_isregStatus.isreg.msgType = (int)MSG_AGENT_CM_ISREG_REPORT;
    g_isregStatus.isreg.nodeId = g_currentNode->node;
}

static int GetResInstId(const char *resName, uint32 cmInstId)
{
    for (uint32 i = 0; i < CusResCount(); ++i) {
        if (strcmp(resName, g_resStatus[i].status.resName) != 0) {
            continue;
        }
        for (uint32 j = 0; j < g_resStatus[i].status.instanceCount; ++j) {
            if (g_resStatus[i].status.resStat[j].cmInstanceId == cmInstId) {
                return (int)g_resStatus[i].status.resStat[j].resInstanceId;
            }
        }
        write_runlog(ERROR, "can't get res_inst_id, by cm_inst_id(%u).\n", cmInstId);
        break;
    }
    write_runlog(ERROR, "can't get res_inst_id, by res(%s) cm_inst_id(%u).\n", resName, cmInstId);
    return -1;
}

static void CheckIsregList(ResInstIsreg *newIsregList, uint32 listLen, uint32 *newIsregCount)
{
    (*newIsregCount) = 0;
    for (uint32 i = 0; i < g_isregCheckList.checkCount; ++i) {
        if (i >= listLen) {
            write_runlog(ERROR, "check list check count(%u) is invalid.\n", g_isregCheckList.checkCount);
            return;
        }
        char resName[CM_MAX_RES_NAME] = {0};
        if (GetResNameByCmInstId(g_isregCheckList.checkList[i], resName, CM_MAX_RES_NAME) != CM_SUCCESS) {
            continue;
        }
        CmResConfList *resConf = CmaGetResConfByResName(resName);
        if (resConf == NULL) {
            continue;
        }
        int destInstId = GetResInstId(resName, g_isregCheckList.checkList[i]);
        if (destInstId < 0) {
            continue;
        }
        newIsregList[(*newIsregCount)].cmInstId = g_isregCheckList.checkList[i];
        int regStatus = (int)IsregOneResInst(resConf, (uint32)destInstId);
        /* If we dectected PENGDING (only happened under DSS). */
        if (regStatus == CM_RES_ISREG_PENDING) {
            (void)pthread_rwlock_wrlock(&(pending_status_rwlock));
            /* If we get CM_RES_ISREG_PENDING, we must had add VG in process, we should mark it. */
            if (g_isRegUnderVGAddProcess) {
                /* 
                * If CMA had already process the reg message, 
                * we should not mark this value again, ignore this check. 
                */
                write_runlog(LOG, "Recent partial register has done, so ingnore this epoch.\n");
                g_isRegUnderVGAddProcess = false;
                g_isInVGAddProcess = false;
            } else {
                /* If CMA had not already process the reg message, we shound mark and wait process. */
                write_runlog(LOG, "Detected the PENDING status, it should be done by Reg operation.\n");
                g_isInVGAddProcess = true;
            }
            (void)pthread_rwlock_unlock(&(pending_status_rwlock));
        }
        newIsregList[(*newIsregCount)].isreg = (int)IsregOneResInst(resConf, (uint32)destInstId);
        ++(*newIsregCount);
    }
}

static void StrcatIsregListStr(char *isregStr, uint32 isregStrLen, uint32 cmInstId, int isreg)
{
    const uint32 instIsregLen = 64;
    char instStr[instIsregLen] = {0};
    int ret = snprintf_s(instStr, instIsregLen, instIsregLen - 1, "%u:%s, ", cmInstId, GetIsregStatus(isreg));
    securec_check_intval(ret, (void)ret);
    errno_t rc = strcat_s(isregStr, isregStrLen, instStr);
    securec_check_errno(rc, (void)rc);
}

static void PrintIsregList(const ResInstIsreg *newIsregList, uint32 listLen, int logLevel)
{
    if (log_min_messages > logLevel) {
        return;
    }
    char isregList[MAX_PATH_LEN] = {0};
    for (uint32 i = 0; i < listLen; ++i) {
        StrcatIsregListStr(isregList, MAX_PATH_LEN, newIsregList[i].cmInstId, newIsregList[i].isreg);
    }
    write_runlog(logLevel, "node(%u) isreg list: %s.\n", g_currentNode->node, isregList);
}

static void CopyNewIsregStatus(const ResInstIsreg *newIsregList, uint32 newListLen, uint32 newIsregCount)
{
    (void)pthread_rwlock_wrlock(&g_isregStatus.rwlock);
    g_isregStatus.isreg.isregCount = newIsregCount;
    errno_t rc = memcpy_s(g_isregStatus.isreg.isregList, (sizeof(ResInstIsreg) * CM_MAX_RES_INST_COUNT),
        newIsregList, (sizeof(ResInstIsreg) * newListLen));
    (void)pthread_rwlock_unlock(&g_isregStatus.rwlock);
    securec_check_errno(rc, (void)rc);
}

void *ResourceIsregCheckMain(void *arg)
{
    thread_name = "ResIsregCheck";
    write_runlog(LOG, "resource isreg check thread start.\n");

    ResInstIsreg newIsregList[CM_MAX_RES_INST_COUNT] = {{0}};

    for (;;) {
        if (g_shutdownRequest) {
            cm_sleep(5);
            continue;
        }

        uint32 newIsregCount = 0;
        errno_t rc = memset_s(newIsregList, (sizeof(ResInstIsreg) * CM_MAX_RES_INST_COUNT),
            0, (sizeof(ResInstIsreg) * CM_MAX_RES_INST_COUNT));
        securec_check_errno(rc, (void)rc);

        CheckIsregList(newIsregList, CM_MAX_RES_INST_COUNT, &newIsregCount);

        PrintIsregList(newIsregList, newIsregCount, DEBUG5);

        CopyNewIsregStatus(newIsregList, CM_MAX_RES_INST_COUNT, newIsregCount);

        cm_sleep(agent_report_interval);
    }

    return NULL;
}

static void PrintItemCheckList(char *checkListStr, uint32 listLen, uint32 cmInstId)
{
    const uint32 itemLen = 32;
    char itemStr[itemLen] = {0};
    int ret = snprintf_s(itemStr, itemLen, itemLen - 1, "%u, ", cmInstId);
    securec_check_intval(ret, (void)ret);
    errno_t rc = strcat_s(checkListStr, listLen, itemStr);
    securec_check_errno(rc, (void)rc);
}

static void PrintCheckList(const uint32 *checkList, uint32 Len, int logLevel)
{
    char checkListStr[MAX_PATH_LEN] = {0};
    for (uint32 i = 0; i < Len; ++i) {
        PrintItemCheckList(checkListStr, MAX_PATH_LEN, checkList[i]);
    }

    write_runlog(logLevel, "check list: %s.\n", checkListStr);
}

void UpdateIsregCheckList(const uint32 *newCheckList, uint32 newCheckCount)
{
    if (newCheckCount > CM_MAX_RES_INST_COUNT) {
        write_runlog(ERROR, "new check list count(%u) is invalid.\n", newCheckCount);
        return;
    }

    write_runlog(LOG, "print old isreg check list.\n");
    PrintCheckList(g_isregCheckList.checkList, g_isregCheckList.checkCount, LOG);
    write_runlog(LOG, "print new isreg check list.\n");
    PrintCheckList(newCheckList, newCheckCount, LOG);

    size_t checkListSize = sizeof(uint32) * CM_MAX_RES_INST_COUNT;
    size_t newCheckListSize = sizeof(uint32) * newCheckCount;
    errno_t rc = memset_s(g_isregCheckList.checkList, checkListSize, 0, checkListSize);
    securec_check_errno(rc, (void)rc);
    rc = memcpy_s(g_isregCheckList.checkList, checkListSize, newCheckList, newCheckListSize);
    securec_check_errno(rc, (void)rc);

    g_isregCheckList.checkCount = newCheckCount;
}

void SendResIsregReportMsg()
{
    (void)pthread_rwlock_rdlock(&g_isregStatus.rwlock);
    PrintIsregList(g_isregStatus.isreg.isregList, g_isregStatus.isreg.isregCount, DEBUG5);
    PushMsgToCmsSendQue((char *)&g_isregStatus.isreg, (uint32)sizeof(CmaToCmsIsregMsg), "res isreg");
    (void)pthread_rwlock_unlock(&g_isregStatus.rwlock);
}

// check res status
static void DoCheckResourceStatus(CmResConfList *resConf, CmResourceStatus *resStat)
{
    long curTime = GetCurMonotonicTimeSec();
    static uint32 latestStat = (uint32)CUS_RES_CHECK_STAT_UNKNOWN;
    if (resConf->checkInfo.checkTime == 0) {
        resStat->status = (uint32)CheckOneResInst(resConf);
        resConf->checkInfo.checkTime = curTime;
        latestStat = resStat->status;
        return;
    }
    if ((curTime - resConf->checkInfo.checkTime) < resConf->checkInfo.checkInterval) {
        resStat->status = latestStat;
        return;
    }
    resStat->status = (uint32)CheckOneResInst(resConf);
    resConf->checkInfo.checkTime = curTime;
    latestStat = resStat->status;
}

void InitResStatCommInfo(OneNodeResourceStatus *nodeStat)
{
    nodeStat->node = g_currentNode->node;
    for (uint32 i = 0; i < GetLocalResConfCount(); ++i) {
        errno_t rc = strcpy_s(nodeStat->status[i].resName, CM_MAX_RES_NAME, g_resConf[i].resName);
        securec_check_errno(rc, (void)rc);
        nodeStat->status[i].nodeId = g_resConf[i].nodeId;
        nodeStat->status[i].cmInstanceId = g_resConf[i].cmInstanceId;
        nodeStat->status[i].resInstanceId = g_resConf[i].resInstanceId;
        nodeStat->status[i].status = CUS_RES_CHECK_STAT_UNKNOWN;
        nodeStat->status[i].workStatus = RES_INST_WORK_STATUS_UNKNOWN;
    }
    nodeStat->count = GetLocalResConfCount();
}

void CheckResourceState(OneNodeResourceStatus *nodeStat)
{
    for (uint32 i = 0; i < GetLocalResConfCount(); ++i) {
        DoCheckResourceStatus(&g_resConf[i], &nodeStat->status[i]);
        bool isInstStopped = IsInstManualStopped(nodeStat->status[i].cmInstanceId);
        nodeStat->status[i].workStatus = (isInstStopped ? RES_INST_WORK_STATUS_UNAVAIL : RES_INST_WORK_STATUS_AVAIL);
    }
}

void *ResourceStatusCheckMain(void *arg)
{
    errno_t rc;
    OneNodeResourceStatus nodeStat = {0};

    InitResStatCommInfo(&nodeStat);

    thread_name = "ResStatCheck";
    write_runlog(LOG, "Resource status check thread start.\n");

    for (;;) {
        if (g_shutdownRequest) {
            cm_sleep(5);
            continue;
        }

        CheckResourceState(&nodeStat);

        (void)pthread_rwlock_wrlock(&g_resReportMsg.rwlock);
        rc = memcpy_s(&g_resReportMsg.resStat, sizeof(OneNodeResourceStatus), &nodeStat, sizeof(OneNodeResourceStatus));
        securec_check_errno(rc, (void)pthread_rwlock_unlock(&g_resReportMsg.rwlock));
        (void)pthread_rwlock_unlock(&g_resReportMsg.rwlock);

        cm_sleep(agent_report_interval);
    }

    return NULL;
}

void SendResStatReportMsg()
{
    ReportResStatus reportMsg = {0};
    reportMsg.msgType = (int)MSG_AGENT_CM_RESOURCE_STATUS;

    (void)pthread_rwlock_rdlock(&g_resReportMsg.rwlock);
    errno_t rc = memcpy_s(&reportMsg.nodeStat, sizeof(OneNodeResourceStatus),
        &g_resReportMsg.resStat, sizeof(OneNodeResourceStatus));
    securec_check_errno(rc, (void)pthread_rwlock_unlock(&g_resReportMsg.rwlock));
    (void)pthread_rwlock_unlock(&g_resReportMsg.rwlock);

    PushMsgToCmsSendQue((char *)&reportMsg, (uint32)sizeof(ReportResStatus), "res status");
}
