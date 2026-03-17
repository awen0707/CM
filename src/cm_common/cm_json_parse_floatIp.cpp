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
* cm_json_parse_floatIp.cpp
*
*
* IDENTIFICATION
*    src/cm_common/cm_json_parse_floatIp.cpp
*
* -------------------------------------------------------------------------
*/

#include "cm_json_parse_floatIp.h"

#include "cm_elog.h"
#include "cm_misc.h"
#include "cm_json_config.h"
#include "cm_ip.h"

static const ParseFloatIpFunc *g_parseFuc = NULL;

static DnFloatIp *CmGetDnFloatIpByDnIdx(uint32 nodeIdx, uint32 dnIdx)
{
    if (g_parseFuc == NULL || g_parseFuc->getFloatIp == NULL) {
        return NULL;
    }
    return g_parseFuc->getFloatIp(nodeIdx, dnIdx);
}

static bool IsBaseIpInDnFloatIp(const char *baseIp, const char *floatIp, uint32 nodeIdx, uint32 dnIdx)
{
    DnFloatIp *dnFloatIp = CmGetDnFloatIpByDnIdx(nodeIdx, dnIdx);
    if (dnFloatIp == NULL) {
        return true;
    }
    for (uint32 i = 0; i < dnFloatIp->dnFloatIpCount; ++i) {
        if (IsEqualIp(baseIp, dnFloatIp->baseIp[i])) {
            write_runlog(LOG, "instId(%u) baseIp(%s) may be existed in floatIp.\n", dnFloatIp->instId, baseIp);
            return true;
        }
        if (IsEqualIp(floatIp, dnFloatIp->dnFloatIp[i])) {
            write_runlog(LOG, "instId(%u) floatIp(%s) may be existed in floatIp.\n", dnFloatIp->instId, floatIp);
            return true;
        }
    }
    return false;
}

static void CmIncreaseFloatIpCnt(uint32 nodeIdx)
{
    if (g_parseFuc == NULL || g_parseFuc->increaseCnt == NULL) {
        return;
    }
    g_parseFuc->increaseCnt(nodeIdx);
}

static void GenDnFloat(uint32 nodeIdx, uint32 dnIdx, const char *baseIp, const char *floatIp, const char *floatIpName)
{
    DnFloatIp *dnFloatIp = CmGetDnFloatIpByDnIdx(nodeIdx, dnIdx);
    if (dnFloatIp == NULL) {
        return;
    }
    if (IsBaseIpInDnFloatIp(baseIp, floatIp, nodeIdx, dnIdx)) {
        return;
    }
    dnFloatIp->instId = g_currentNode->datanode[dnIdx].datanodeId;
    dnFloatIp->dataPath = g_currentNode->datanode[dnIdx].datanodeLocalDataPath;
    dnFloatIp->dnFloatIpPort = g_currentNode->datanode[dnIdx].datanodePort;
    uint32 point = dnFloatIp->dnFloatIpCount;
    if (point >= MAX_FLOAT_IP_COUNT) {
        write_runlog(
            LOG, "instId(%u) point(%u) more than maxCount(%u).\n", dnFloatIp->instId, point, MAX_FLOAT_IP_COUNT);
        return;
    }
    if (point == 0) {
        CmIncreaseFloatIpCnt(nodeIdx);
    }
    errno_t rc = strcpy_s(dnFloatIp->baseIp[point], CM_IP_LENGTH, baseIp);
    securec_check_errno(rc, (void)rc);
    rc = strcpy_s(dnFloatIp->dnFloatIp[point], CM_IP_LENGTH, floatIp);
    securec_check_errno(rc, (void)rc);
    rc = strncpy_s(dnFloatIp->floatIpName[point], CM_MAX_RES_NAME, floatIpName, CM_MAX_RES_NAME - 1);
    securec_check_errno(rc, (void)rc);
    ++dnFloatIp->dnFloatIpCount;
}

static bool8 CmFindNodeInfoByInstId(uint32 instId, uint32 *nodeIdx, uint32 *dnIdx, const char *str)
{
    if (g_parseFuc == NULL || g_parseFuc->findNodeInfo == NULL) {
        return CM_FALSE;
    }
    return g_parseFuc->findNodeInfo(instId, nodeIdx, dnIdx, str);
}

static void CheckDnInstInItem(const VipCusResConfJson *vipConf, const char *floatIp, const char *floatIpName)
{
    const char *str = "[CheckDnInstInItem]";
    int32 instId;
    uint32 nodeIdx;
    uint32 dnIdx;
    const char *baseIp;
    for (uint32 i = 0; i < vipConf->baseIpList.count; ++i) {
        instId = vipConf->baseIpList.conf[i].instId;
        if (instId < 0) {
            write_runlog(ERROR, "find the error insId(%d) in base_ip_list.\n", instId);
            continue;
        }
        if (!CmFindNodeInfoByInstId((uint32)vipConf->baseIpList.conf[i].instId, &nodeIdx, &dnIdx, str)) {
            continue;
        }
        if (CM_IS_EMPTY_STR(vipConf->baseIpList.conf[i].baseIp) ||
            !CheckIpValid(vipConf->baseIpList.conf[i].baseIp)) {
            continue;
        }
        baseIp = vipConf->baseIpList.conf[i].baseIp;
        check_input_for_security(baseIp);
        if (IsEqualIp(baseIp, floatIp)) {
            continue;
        }
        GenDnFloat(nodeIdx, dnIdx, baseIp, floatIp, floatIpName);
    }
}

void ParseVipConf(int32 logLevel)
{
    if (IsConfJsonEmpty()) {
        write_runlog(logLevel, "ParseVipConf, no resource exist.\n");
        return;
    }

    char floatIp[MAX_PATH_LEN];
    const char *floatIpName;
    errno_t rc;
    for (uint32 i = 0; i < g_confJson->resource.count; ++i) {
        if (g_confJson->resource.conf[i].resType != CUSTOM_RESOURCE_VIP) {
            continue;
        }
        if (CM_IS_EMPTY_STR(g_confJson->resource.conf[i].vipResConf.floatIp) ||
            !CheckIpValid(g_confJson->resource.conf[i].vipResConf.floatIp)) {
            continue;
        }
        rc = memset_s(floatIp, MAX_PATH_LEN, 0, MAX_PATH_LEN);
        securec_check_errno(rc, (void)rc);
        rc = strcpy_s(floatIp, MAX_PATH_LEN, g_confJson->resource.conf[i].vipResConf.floatIp);
        securec_check_errno(rc, (void)rc);
        floatIpName = g_confJson->resource.conf[i].vipResConf.resName;
        check_input_for_security(floatIpName);
        CheckDnInstInItem(&g_confJson->resource.conf[i].vipResConf, floatIp, floatIpName);
    }
}

void InitParseFloatIpFunc(const ParseFloatIpFunc *parseFuc)
{
    g_parseFuc = parseFuc;
}
