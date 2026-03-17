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
 * cms_rhb.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_server/cms_rhb.cpp
 *
 * -------------------------------------------------------------------------
 */
#include "cm_elog.h"
#include "cm_rhb.h"
#include "cm_config.h"
#include "cms_rhb.h"
#include "cms_global_params.h"

typedef struct DbResNodeIdxInfo_t {
    uint32 hwl;
    uint32 idxLists[MAX_RHB_NUM];
} DbResNodeIdxInfo;

static time_t g_hbs[MAX_RHB_NUM][MAX_RHB_NUM] = {0};
static time_t g_hbs_bak[MAX_RHB_NUM][MAX_RHB_NUM] = {0};
static DbResNodeIdxInfo g_dbResNodeIdxInfo = { 0 };
bool g_hbsFlags = false;
time_t startWaitTime = 0;
int delayTime = 2;

void InitDbListsByStaticConfig()
{
    char buf[MAX_LOG_BUFF_LEN] = {0};
    const uint32 maxInfoLen = 64;
    char info[maxInfoLen] = {0};
    int rcs;
    for (uint32 i = 0; i < g_node_num; i++) {
        if (g_node[i].datanodeCount > 0) {
            if (g_dbResNodeIdxInfo.hwl >= MAX_RHB_NUM) {
                write_runlog(ERROR, "[InitDbListsByStaticConfig] we supported res count less than %d", MAX_RHB_NUM);
                return;
            }
            g_dbResNodeIdxInfo.idxLists[g_dbResNodeIdxInfo.hwl] = i;
            rcs = snprintf_s(info, maxInfoLen, maxInfoLen - 1, " %u:[%u-%u]",
                g_dbResNodeIdxInfo.hwl, i, g_node[i].node);
            securec_check_intval(rcs, (void)rcs);
            rcs = strncat_s(buf, MAX_LOG_BUFF_LEN, info, strlen(info));
            securec_check_errno(rcs, (void)rcs);
            g_dbResNodeIdxInfo.hwl++;
        }
    }

    write_runlog(LOG, "[InitDbListsByStaticConfig] hwl:%u, detail:%s\n", g_dbResNodeIdxInfo.hwl, buf);
}

static status_t FindResIdxByNodeId(uint32 nodeId, uint32 *resIdx)
{
    for (uint32 i = 0; i < g_dbResNodeIdxInfo.hwl; i++) {
        uint32 curNodeIdx = g_dbResNodeIdxInfo.idxLists[i];
        if (g_node[curNodeIdx].node == nodeId) {
            *resIdx = i;
            return CM_SUCCESS;
        }
    }

    write_runlog(ERROR, "[FindResIdxByNodeId] can't find nodeId(%u), hwl(%u)\n", nodeId, g_dbResNodeIdxInfo.hwl);
    return CM_ERROR;
}

void RefreshNodeRhbInfo(unsigned int nodeId, const time_t *hbs, unsigned int hwl)
{
    uint32 resIdx;
    errno_t rc;
    if (hwl != g_dbResNodeIdxInfo.hwl) {
        write_runlog(
            ERROR, "[RefreshNodeRhbInfo] node[%u] rhb hwl(%u) must equal %u\n", nodeId, hwl, g_dbResNodeIdxInfo.hwl);
        return;
    }
    CM_RETVOID_IFERR(FindResIdxByNodeId(nodeId, &resIdx));
    if (g_hbsFlags == true && difftime(time(NULL), startWaitTime) >= delayTime) {
        rc = memcpy_s(g_hbs, sizeof(time_t) * MAX_RHB_NUM * MAX_RHB_NUM,
            g_hbs_bak, sizeof(time_t) * MAX_RHB_NUM * MAX_RHB_NUM);
        securec_check_errno(rc, (void)rc);
        g_hbsFlags = false;
    }
    for (int i = 0; i < MAX_RHB_NUM; i++) {
        if (hbs[i] - g_hbs[resIdx][i] > g_agentNetworkTimeout) {
            if (g_hbsFlags == false) {
                startWaitTime = time(NULL);
                rc = memcpy_s(g_hbs_bak, sizeof(time_t) * MAX_RHB_NUM * MAX_RHB_NUM,
                    g_hbs, sizeof(time_t) * MAX_RHB_NUM * MAX_RHB_NUM);
                securec_check_errno(rc, (void)rc);
                g_hbsFlags = true;
            }
            rc = memcpy_s(g_hbs_bak[resIdx], sizeof(time_t) * MAX_RHB_NUM, hbs, sizeof(time_t) * hwl);
            securec_check_errno(rc, (void)rc);
            return;
        }
    }
    startWaitTime = 0;
    rc = memcpy_s(g_hbs[resIdx], sizeof(time_t) * MAX_RHB_NUM, hbs, sizeof(time_t) * hwl);
    securec_check_errno(rc, (void)rc);
}

// lock ?
void GetRhbStat(time_t hbs[MAX_RHB_NUM][MAX_RHB_NUM], unsigned int *hwl)
{
    *hwl = g_dbResNodeIdxInfo.hwl;
    const size_t hbsSize = sizeof(time_t) * MAX_RHB_NUM * MAX_RHB_NUM;
    errno_t rc = memcpy_s(hbs, hbsSize, g_hbs, hbsSize);
    securec_check_errno(rc, (void)rc);
}

void ResetNodeConnStat()
{
    errno_t rc = memset_s(g_hbs, sizeof(g_hbs), 0, sizeof(g_hbs));
    securec_check_errno(rc, (void)rc);
}

static void PrintOneHbInfo(int resIdx1, uint32 nodeId1, int resIdx2, uint32 nodeId2, int logLevel)
{
    struct tm result;
    GetLocalTime(&g_hbs[resIdx1][resIdx2], &result);
    const uint32 timeBufMaxLen = 128;
    char timeBuf[timeBufMaxLen] = {0};
    (void)strftime(timeBuf, timeBufMaxLen, "%Y-%m-%d %H:%M:%S", &result);
    write_runlog(logLevel, "(index=%d,nodeId=%u)->(index=%d,nodeId=%u) hb info: %s.\n",
        resIdx1, nodeId1, resIdx1, nodeId2, timeBuf);
}

void PrintHbsInfo(int resIdx1, uint32 nodeId1, int resIdx2, uint32 nodeId2, int logLevel)
{
    PrintOneHbInfo(resIdx1, nodeId1, resIdx2, nodeId2, logLevel);
    PrintOneHbInfo(resIdx2, nodeId2, resIdx1, nodeId1, logLevel);
}

void GetTimeStr(time_t baseTime, char *timeStr, uint32 strLen)
{
    struct tm result;
    GetLocalTime(&baseTime, &result);
    (void)strftime(timeStr, strLen, "%Y-%m-%d %H:%M:%S", &result);
}
