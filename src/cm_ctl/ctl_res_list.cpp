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
* ctl_res_list.cpp
*
* IDENTIFICATION
*    src/cm_ctl/ctl_res_list.cpp
*
* -------------------------------------------------------------------------
*/
#include "ctl_res_list.h"

#include "cjson/cJSON.h"

#include "cm_text.h"
#include "cm_elog.h"
#include "cm_misc_res.h"
#include "cm_misc.h"

#include "ctl_global_params.h"
#include "ctl_res.h"

typedef struct ResBaseInfoT {
    CmConstText resName;
    CmConstText resType;
} ResBaseInfo;

typedef struct PrintArrayT {
    const char **arr;
    uint32 arrLen;
} PrintArray;

typedef struct ResPrintInfoT {
    PrintArray resArr;
    PrintArray instArr;
} ResPrintInfo;

typedef struct ResValueInfoT {
    char *attrChar;
    uint32 attrValue;
    uint32 len;
    uint32 value[0];
} ResValueInfo;

// for str '\0'
static const uint32 TEXT_RESERVE_LEN = 10;

static const char *const PRINT_TABLE_SPEPARATOR = "-";
static const char *const PRINT_TABLE_SPLIT = "| ";
static const char *const PRINT_NULL = "Null";

static const uint32 LIST_RES_SPACE_LEN = 1;
static const int32 TEN_MECHAN = 10;

static const char *g_resCom[] = {RES_NAME, RESOURCE_TYPE};

static const char *g_appResArr[] = {
    RES_SCRIPT, RES_CHECK_INTERVAL, RES_TIMEOUT, RES_RESTART_DELAY, RES_PERIOD, RES_RESTART_TIMES};

static const char *g_appInstArr[] = {INST_NODE_ID, INST_RES_INST_ID, INST_REG};

// VIP
static const char *g_vipResArr[] = {RES_FLOAT_IP};
static const char *g_vipInstArr[] = {INST_NODE_ID, INST_RES_INST_ID, INST_ATTR};

static const char *g_resAttr[] = {RES_FLOAT_IP, INST_ATTR};

static const char *g_resSkipAttr[] = {RES_ATTR, INST_ATTR};

static ResPrintInfo g_printInfo[RES_TYPE_CEIL];

static KvRestrict g_resAllKv[] = {{RES_KV_TYPE_STRING, RES_NAME},
    {RES_KV_TYPE_STRING, RESOURCE_TYPE},
    {RES_KV_TYPE_STRING, RES_SCRIPT},
    {RES_KV_TYPE_INTEGER, RES_CHECK_INTERVAL},
    {RES_KV_TYPE_INTEGER, RES_TIMEOUT},
    {RES_KV_TYPE_INTEGER, RES_RESTART_DELAY},
    {RES_KV_TYPE_INTEGER, RES_PERIOD},
    {RES_KV_TYPE_INTEGER, RES_RESTART_TIMES},
    {RES_KV_TYPE_INTEGER, INST_NODE_ID},
    {RES_KV_TYPE_INTEGER, INST_RES_INST_ID},
    {RES_KV_TYPE_STRING, RES_FLOAT_IP},
    {RES_KV_TYPE_STRING, INST_REG},
    {RES_KV_TYPE_STRING, INST_ATTR},
    {RES_KV_TYPE_STRING, RES_ATTR}};

static void PrintListTitle()
{
    (void)fprintf(g_logFilePtr, "\n[  CM Resource Info  ]\n\n");
}

static bool8 IsInSkipAttr(const char *key)
{
    if (CM_IS_EMPTY_STR(key)) {
        return CM_FALSE;
    }

    uint32 len = ELEMENT_COUNT(g_resSkipAttr);
    for (uint32 i = 0; i < len; ++i) {
        if (cm_str_equal(g_resSkipAttr[i], key)) {
            return CM_TRUE;
        }
    }
    return CM_FALSE;
}

static void InitResBaseInfo(ResBaseInfo *info)
{
    errno_t rc = memset_s(info, sizeof(ResBaseInfo), 0, sizeof(ResBaseInfo));
    securec_check_errno(rc, (void)rc);

    info->resName.str = RES_NAME;
    info->resName.len = (uint32)strlen(RES_NAME);

    info->resType.str = RESOURCE_TYPE;
    info->resType.len = (uint32)strlen(RESOURCE_TYPE);
}

static status_t SetResBaseInfoInArray(ResBaseInfo *info, const cJSON *resArray, const ResOption *resCtx)
{
    const cJSON *item;
    const char *resName;
    const char *resType;
    bool8 isCanPrint = CM_FALSE;
    cJSON_ArrayForEach(item, resArray) {
        if (!cJSON_IsObject(item)) {
            continue;
        }
        resName = GetValueStrFromCJson(item, RES_NAME);
        if (resName == NULL) {
            resName = PRINT_NULL;
        } else {
            isCanPrint = CM_TRUE;
        }
        info->resName.len = CM_MAX(info->resName.len, (uint32)strlen(resName));
        resType = GetValueStrFromCJson(item, RESOURCE_TYPE);
        if (resType == NULL) {
            resType = ResConfDefValue(RESOURCE_TYPE);
        }
        info->resType.len = CM_MAX(info->resType.len, (uint32)strlen(resType));
    }
    // space
    info->resName.len += LIST_RES_SPACE_LEN;
    info->resType.len += LIST_RES_SPACE_LEN;
    if (!isCanPrint) {
        write_runlog(ERROR, "%s%s Res(%s) cannot print res info, when no res in json.\n", GetResOperStr(resCtx->mode),
            GetInstOperStr(resCtx->inst.mode), resCtx->resName);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static void PrintAllResInfoTitle(const ResBaseInfo *info)
{
    (void)fprintf(g_logFilePtr, "%-*s%s%-*s\n",
        info->resName.len, info->resName.str,
        PRINT_TABLE_SPLIT,
        info->resType.len, info->resType.str);

    // ---
    uint32 totalLen = info->resName.len + info->resType.len + (uint32)strlen(PRINT_TABLE_SPLIT);
    for (uint32 i = 0; i < totalLen; ++i) {
        (void)fprintf(g_logFilePtr, "%s", PRINT_TABLE_SPEPARATOR);
    }
    (void)fprintf(g_logFilePtr, "\n");
}

static void PrintAllResInfoBody(const ResBaseInfo *info, const cJSON *resArray)
{
    const cJSON *item;
    const char *resName;
    const char *resType;
    cJSON_ArrayForEach(item, resArray) {
        if (!cJSON_IsObject(item)) {
            continue;
        }
        resName = GetValueStrFromCJson(item, RES_NAME);
        if (resName == NULL) {
            resName = PRINT_NULL;
        }
        resType = GetValueStrFromCJson(item, RESOURCE_TYPE);
        if (resType == NULL) {
            resType = ResConfDefValue(RESOURCE_TYPE);
        }
        (void)fprintf(g_logFilePtr, "%-*s%s%-*s\n",
            info->resName.len, resName,
            PRINT_TABLE_SPLIT,
            info->resType.len, resType);
    }
}

static bool8 IsInResArr(const char *key)
{
    if (key == NULL) {
        return CM_FALSE;
    }
    uint32 len = ELEMENT_COUNT(g_resAttr);
    for (uint32 i = 0; i < len; ++i) {
        if (cm_str_equal(key, g_resAttr[i])) {
            return CM_TRUE;
        }
    }
    return CM_FALSE;
}

static uint32 GetValueLen(int32 value, int32 mechan = TEN_MECHAN)
{
    if (mechan == 0) {
        write_runlog(DEBUG1, "fail to get value len, whne mechan is 0.\n");
        return 0;
    }
    uint32 len = 0;
    int32 tmpValue = value;
    int32 tmpMechan = abs(mechan);
    if (tmpValue < 0) {
        // minus sign
        tmpValue = abs(tmpValue);
        len += 1;
    }

    while (tmpValue != 0) {
        tmpValue /= tmpMechan;
        ++len;
    }
    return len;
}

static status_t PrintAllResInfo(const cJSON *resArray, const ResOption *resCtx)
{
    PrintListTitle();
    ResBaseInfo info;
    InitResBaseInfo(&info);
    CM_RETURN_IFERR(SetResBaseInfoInArray(&info, resArray, resCtx));
    PrintAllResInfoTitle(&info);
    PrintAllResInfoBody(&info, resArray);
    return CM_SUCCESS;
}

static status_t CheckListParam(cJSON *resArray, const ResOption *resCtx)
{
    if (resArray == NULL) {
        write_runlog(ERROR, "%s%s Res(%s) cannot list res, when resArray is NULL.\n", GetResOperStr(resCtx->mode),
            GetInstOperStr(resCtx->inst.mode), resCtx->resName);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static void InitListFunc()
{
    errno_t rc = memset_s(g_printInfo, sizeof(g_printInfo), 0, sizeof(g_printInfo));
    securec_check_errno(rc, (void)rc);

    g_printInfo[RES_TYPE_APP].resArr.arr = g_appResArr;
    g_printInfo[RES_TYPE_APP].resArr.arrLen = ELEMENT_COUNT(g_appResArr);
    g_printInfo[RES_TYPE_APP].instArr.arr = g_appInstArr;
    g_printInfo[RES_TYPE_APP].instArr.arrLen = ELEMENT_COUNT(g_appInstArr);

    g_printInfo[RES_TYPE_DN].resArr.arr = g_appResArr;
    g_printInfo[RES_TYPE_DN].resArr.arrLen = ELEMENT_COUNT(g_appResArr);

    g_printInfo[RES_TYPE_VIP].resArr.arr = g_vipResArr;
    g_printInfo[RES_TYPE_VIP].resArr.arrLen = ELEMENT_COUNT(g_vipResArr);
    g_printInfo[RES_TYPE_VIP].instArr.arr = g_vipInstArr;
    g_printInfo[RES_TYPE_VIP].instArr.arrLen = ELEMENT_COUNT(g_vipInstArr);
}

static ResPrintInfo *GetPrintInfo(cJSON *objItem, const ResOption *resCtx)
{
    ResType type = GetResTypeFromCjson(objItem);
    if (type == RES_TYPE_UNKNOWN) {
        write_runlog(ERROR, "%s%s Res(%s) cannot get print Info, when type is %d.\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName, (int32)type);
        return NULL;
    }

    if (type >= RES_TYPE_CEIL) {
        write_runlog(ERROR, "%s%s Res(%s) cannot get print Info, when type is %d.\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName, (int32)type);
        return NULL;
    }
    return &(g_printInfo[type]);
}

static ResValueInfo *InitValueArr(uint32 arrLen, const ResOption *resCtx)
{
    uint32 totalLen =  arrLen + (uint32)ELEMENT_COUNT(g_resCom);
    size_t totalsize = sizeof(ResValueInfo) + sizeof(uint32) * totalLen;
    ResValueInfo *valueArr = (ResValueInfo *)malloc(totalsize);
    if (valueArr == NULL) {
        write_runlog(DEBUG1, "%s%s Res(%s) fails to print list info, when valueArr is NULL, and len=[%u: %zu].\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName, totalLen, totalsize);
        write_runlog(ERROR, "%s%s Res(%s) fails to print list info, when valueArr is NULL.\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName);
        return NULL;
    }
    errno_t rc = memset_s(valueArr, totalsize, 0, totalsize);
    securec_check_errno(rc, (void)rc);
    valueArr->len = totalLen;
    return valueArr;
}

static ResKvType GetCurKvType(const char *key)
{
    if (key == NULL) {
        return RES_KV_TYPE_UNKNOWN;
    }
    uint32 len = ELEMENT_COUNT(g_resAllKv);
    for (uint32 i = 0; i < len; ++i) {
        if (cm_str_equal(g_resAllKv[i].key, key)) {
            return g_resAllKv[i].type;
        }
    }
    return RES_KV_TYPE_UNKNOWN;
}

static int32 GetValueIntOrDefValueFromJson(const cJSON *root, const char *key)
{
    int32 value = GetValueIntFromCJson(root, key, DEBUG1);
    if (value == -1) {
        value = CmAtoi(ResConfDefValue(key), -1);
    }
    return value;
}

static uint32 GetValueLenFromJson(const cJSON *root, const char *key)
{
    int32 value = GetValueIntOrDefValueFromJson(root, key);
    return GetValueLen(value);
}

static const char *GetValueStrOrDefValueFromJson(const cJSON *root, const char *key)
{
    const char *value = GetValueStrFromCJson(root, key, DEBUG1);
    if (value == NULL) {
        value = ResConfDefValue(key);
    }
    if (value == NULL) {
        value = PRINT_NULL;
    }
    return value;
}

static uint32 GetValueStrLenFromJson(const cJSON *root, const char *key)
{
    const char *value = GetValueStrOrDefValueFromJson(root, key);
    if (value == NULL) {
        return 0;
    }
    return (uint32)strlen(value);
}

static uint32 GetCJsonItemLen(const cJSON *root, const char *key, const ResOption *resCtx)
{
    if (!cJSON_IsObject(root)) {
        write_runlog(DEBUG1, "%s%s Res(%s) fails to get cJson item len, when root is not object.\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName);
        return 0;
    }
    if (CM_IS_EMPTY_STR(key)) {
        write_runlog(DEBUG1, "%s%s Res(%s) fails to get cJson item len, when key is empty.\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName);
        return 0;
    }
    ResKvType type = GetCurKvType(key);
    if (type == RES_KV_TYPE_UNKNOWN) {
        write_runlog(DEBUG1, "%s%s Res(%s) fails to get cJson item len, when type is unknown.\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName);
        return 0;
    }
    uint32 valueLen = 0;
    switch (type) {
        case RES_KV_TYPE_INTEGER:
            valueLen = GetValueLenFromJson(root, key);
            break;
        case RES_KV_TYPE_STRING:
            valueLen = GetValueStrLenFromJson(root, key);
            break;
        default:;
    }
    if (!IsInResArr(key)) {
        return valueLen;
    }
    if (!IsInSkipAttr(key)) {
        // "="
        const uint32 splitLen = 1;
        return (uint32)strlen(key) + splitLen + valueLen;
    }
    return valueLen;
}

static void InitArrItemLen(
    ResValueInfo *valueArr, const PrintArray *printInfo, uint32 *index, const ResOption *resCtx, const char *attrName)
{
    uint32 tmpIndex = *index;
    const char *key;
    for (uint32 i = 0; i < printInfo->arrLen; ++i) {
        if (tmpIndex + i >= valueArr->len) {
            write_runlog(DEBUG1, "%s%s Res(%s) fails to init arr Item len, when tmpIndex=%u, i=%u, len=%u.\n",
                GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName, tmpIndex, i,
                valueArr->len);
            break;
        }
        key = printInfo->arr[i];
        if (!IsInResArr(key)) {
            valueArr->value[tmpIndex + i] = (uint32)strlen(key);
        } else {
            valueArr->attrValue = (uint32)strlen(attrName);
        }
    }
    *index = tmpIndex + printInfo->arrLen;
}

static void InitListArrItem(ResValueInfo *valueArr, const ResOption *resCtx, const PrintArray *printInfo)
{
    uint32 index = 0;
    // g_resComm
    PrintArray tmpArray = {.arr = g_resCom, .arrLen = ELEMENT_COUNT(g_resCom)};
    InitArrItemLen(valueArr, &tmpArray, &index, resCtx, INST_ATTR);

    // printInfo
    InitArrItemLen(valueArr, printInfo, &index, resCtx, INST_ATTR);
}

static void ComputeArrItemLen(
    const cJSON *objItem, ResValueInfo *valueArr, uint32 *index, const PrintArray *printInfo, const ResOption *resCtx)
{
    uint32 tmpIndex = *index;
    const char *key;
    for (uint32 i = 0; i < printInfo->arrLen; ++i) {
        if (tmpIndex + i >= valueArr->len) {
            write_runlog(DEBUG1, "%s%s Res(%s) fails to compute arr Item len, when tmpIndex=%u, i=%u, len=%u.\n",
                GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName, tmpIndex, i,
                valueArr->len);
            break;
        }
        key = printInfo->arr[i];
        if (!IsInResArr(key)) {
            valueArr->value[tmpIndex + i] =
                CM_MAX(GetCJsonItemLen(objItem, key, resCtx), valueArr->value[tmpIndex + i]);
        } else {
            if (valueArr->attrValue == 0) {
                valueArr->attrValue += GetCJsonItemLen(objItem, key, resCtx);
            } else {
                // ","
                valueArr->attrValue += GetCJsonItemLen(objItem, key, resCtx) + 1;
            }
        }
    }
    *index = tmpIndex + printInfo->arrLen;
}

static void AddSplit(ResValueInfo *valueArr)
{
    // add split
    for (uint32 i = 0; i < valueArr->len; ++i) {
        if (valueArr->value[i] == 0) {
            continue;
        }
        valueArr->value[i] += LIST_RES_SPACE_LEN;
    }
    if (valueArr->attrValue != 0) {
        valueArr->attrValue += LIST_RES_SPACE_LEN;
    }
}

static status_t ComputeListTableItemLen(
    const cJSON *objItem, const PrintArray *printInfo, ResValueInfo *valueArr, const ResOption *resCtx)
{
    // record attrValue
    uint32 attrValue = valueArr->attrValue;
    valueArr->attrValue = 0;

    // g_resComm
    uint32 index = 0;
    PrintArray tmpArray = {.arr = g_resCom, .arrLen = ELEMENT_COUNT(g_resCom)};
    ComputeArrItemLen(objItem, valueArr, &index, &tmpArray, resCtx);

    // printInfo
    cJSON *objArray = cJSON_GetObjectItem(objItem, INSTANCES);
    if (!cJSON_IsArray(objArray)) {
        write_runlog(DEBUG1, "%s%s Res(%s) fails to compute cur table item len.\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName);
        return CM_ERROR;
    }
    cJSON *item;
    uint32 tmpAttrValue = valueArr->attrValue;
    uint32 tmpIdx;
    cJSON_ArrayForEach(item, objArray) {
        if (!cJSON_IsObject(item)) {
            continue;
        }
        tmpIdx = index;
        attrValue = CM_MAX(valueArr->attrValue, attrValue);
        valueArr->attrValue = tmpAttrValue;
        ComputeArrItemLen(item, valueArr, &tmpIdx, printInfo, resCtx);
    }
    valueArr->attrValue = CM_MAX(valueArr->attrValue, attrValue);

    AddSplit(valueArr);
    return CM_SUCCESS;
}

static void PrintTableTileItem(
    const PrintArray *printInfo, ResValueInfo *valueArr, const ResOption *resCtx, uint32 *index, bool8 isFirst)
{
    uint32 tmpIndex = *index;
    bool8 isTmpFirst = isFirst;
    for (uint32 i = 0; i < printInfo->arrLen; ++i) {
        if (tmpIndex + i >= valueArr->len) {
            write_runlog(DEBUG1, "%s%s Res(%s) fails to print table title item, when tmpIndex=%u, i=%u, len=%u.\n",
                GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName, tmpIndex, i,
                valueArr->len);
            break;
        }
        if (valueArr->value[tmpIndex + i] == 0) {
            continue;
        }
        if (isTmpFirst) {
            isTmpFirst = CM_FALSE;
            (void)fprintf(g_logFilePtr, "%-*s", valueArr->value[tmpIndex + i], printInfo->arr[i]);
        } else {
            (void)fprintf(g_logFilePtr, "%s%-*s", PRINT_TABLE_SPLIT, valueArr->value[tmpIndex + i], printInfo->arr[i]);
        }
    }
    *index = tmpIndex + printInfo->arrLen;
}

static void PrintListTableTile(
    const PrintArray *printInfo, ResValueInfo *valueArr, const ResOption *resCtx, const char *attrName)
{
    uint32 index = 0;
    // g_resComm
    PrintArray tmpArray = {.arr = g_resCom, .arrLen = ELEMENT_COUNT(g_resCom)};
    PrintTableTileItem(&tmpArray, valueArr, resCtx, &index, CM_TRUE);

    // prinfInfo
    PrintTableTileItem(printInfo, valueArr, resCtx, &index, CM_FALSE);

    if (valueArr->attrValue != 0) {
        (void)fprintf(g_logFilePtr, "%s%-*s", PRINT_TABLE_SPLIT, valueArr->attrValue, attrName);
    }
    (void)fprintf(g_logFilePtr, "\n");
}

static void PrintListTableSperatorBar(ResValueInfo *valueArr)
{
    uint32 totalLen = valueArr->attrValue;
    uint32 trueCnt = 0;
    if (totalLen != 0) {
        ++trueCnt;
    }
    for (uint32 i = 0; i < valueArr->len; ++i) {
        if (valueArr->value[i] == 0) {
            continue;
        }
        totalLen += valueArr->value[i];
        ++trueCnt;
    }
    if (trueCnt >= 1) {
        totalLen += (trueCnt - 1) * (uint32)strlen(PRINT_TABLE_SPLIT);
    }
    for (uint32 i = 0; i < totalLen; ++i) {
        (void)fprintf(g_logFilePtr, "%s", PRINT_TABLE_SPEPARATOR);
    }
    (void)fprintf(g_logFilePtr, "\n");
}

static status_t PrintListTableInfo(
    const cJSON *objItem, const PrintArray *printInfo, ResValueInfo *valueArr, const ResOption *resCtx)
{
    InitListArrItem(valueArr, resCtx, printInfo);
    CM_RETURN_IFERR(ComputeListTableItemLen(objItem, printInfo, valueArr, resCtx));

    PrintListTableTile(printInfo, valueArr, resCtx, INST_ATTR);

    PrintListTableSperatorBar(valueArr);
    return CM_SUCCESS;
}

static void PrintNameAndResType(const char *resName, const char *resType, ResValueInfo *valueArr)
{
    (void)fprintf(g_logFilePtr, "%-*s%s%-*s", valueArr->value[0], resName, PRINT_TABLE_SPLIT, valueArr->value[1],
        resType);
}

static void SetResAttrFromJson(const cJSON *root, const char *key, ResValueInfo *valueArr, const ResOption *resCtx)
{
    ResKvType type = GetCurKvType(key);
    if (type == RES_KV_TYPE_UNKNOWN) {
        write_runlog(DEBUG1, "%s%s Res(%s) fails to set res attr from json, when type is unknown.\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName);
        return;
    }
    errno_t rc;
    uint32 curLen = (uint32)strlen(valueArr->attrChar);
    if (curLen != 0) {
        rc = strcat_s(valueArr->attrChar, valueArr->attrValue, ",");
        securec_check_errno(rc, (void)rc);
        ++curLen;
    }

    if (!IsInSkipAttr(key)) {
        rc = snprintf_s(valueArr->attrChar + curLen, valueArr->attrValue - curLen, (valueArr->attrValue - curLen) - 1,
            "%s=", key);
        securec_check_intval(rc, (void)rc);
    }

    curLen = (uint32)strlen(valueArr->attrChar);
    switch (type) {
        case RES_KV_TYPE_INTEGER:
            rc = snprintf_s(valueArr->attrChar + curLen, valueArr->attrValue - curLen,
                (valueArr->attrValue - curLen) - 1, "%d", GetValueIntOrDefValueFromJson(root, key));
            securec_check_intval(rc, (void)rc);
            break;
        case RES_KV_TYPE_STRING:
            rc = snprintf_s(valueArr->attrChar + curLen, valueArr->attrValue - curLen,
                (valueArr->attrValue - curLen) - 1, "%s", GetValueStrOrDefValueFromJson(root, key));
            securec_check_intval(rc, (void)rc);
            break;
        default:;
    }
    return;
}

static void PrintInfoFromCjson(const cJSON *root, const char *key, uint32 len, const ResOption *resCtx)
{
    ResKvType type = GetCurKvType(key);
    if (type == RES_KV_TYPE_UNKNOWN) {
        write_runlog(DEBUG1, "%s%s Res(%s) fails to set res attr from json, when type is unknown.\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName);
        return;
    }
    switch (type) {
        case RES_KV_TYPE_INTEGER:
            (void)fprintf(g_logFilePtr, "%s%-*d", PRINT_TABLE_SPLIT, len, GetValueIntOrDefValueFromJson(root, key));
            break;
        case RES_KV_TYPE_STRING:
            (void)fprintf(g_logFilePtr, "%s%-*s", PRINT_TABLE_SPLIT, len, GetValueStrOrDefValueFromJson(root, key));
            break;
        default:;
    }
    return;
}

static void PrintCJsonBody(
    const cJSON *objItem, const PrintArray *printInfo, ResValueInfo *valueArr, const ResOption *resCtx)
{
    const char *key;
    const uint32 otherIndex = 2;
    for (uint32 i = 0; i < printInfo->arrLen; ++i) {
        if (otherIndex + i >= valueArr->len) {
            write_runlog(DEBUG1, "%s%s Res(%s) fails to print cjson body, when index=%u, i=%u, len=%u.\n",
                GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName, otherIndex, i,
                valueArr->len);
            break;
        }
        key = printInfo->arr[i];
        if (IsInResArr(key)) {
            SetResAttrFromJson(objItem, key, valueArr, resCtx);
        } else {
            PrintInfoFromCjson(objItem, key, valueArr->value[otherIndex + i], resCtx);
        }
    }
    if (valueArr->attrValue != 0) {
        (void)fprintf(g_logFilePtr, "%s%-*s", PRINT_TABLE_SPLIT, valueArr->attrValue, valueArr->attrChar);
    }
    (void)fprintf(g_logFilePtr, "\n");
}

static void SetAttrChar(ResValueInfo *valueArr)
{
    if (valueArr->attrValue == 0 || valueArr->attrChar == NULL) {
        return;
    }
    errno_t rc =
        memset_s(valueArr->attrChar, valueArr->attrValue + TEXT_RESERVE_LEN, 0, valueArr->attrValue + TEXT_RESERVE_LEN);
    securec_check_errno(rc, (void)rc);
}

static status_t InitAttrChar(ResValueInfo *valueArr, const ResOption *resCtx)
{
    if (valueArr->attrValue == 0) {
        return CM_SUCCESS;
    }
    valueArr->attrChar = (char *)malloc(valueArr->attrValue + TEXT_RESERVE_LEN);
    if (valueArr->attrChar == NULL) {
        write_runlog(ERROR, "%s%s res(%s) fails to malloc attr char.\n", GetResOperStr(resCtx->mode),
            GetInstOperStr(resCtx->inst.mode), resCtx->resName);
        return CM_ERROR;
    }
    SetAttrChar(valueArr);
    return CM_SUCCESS;
}

static status_t PrintListTableBody(
    const cJSON *objItem, const PrintArray *printInfo, ResValueInfo *valueArr, const ResOption *resCtx)
{
    const uint32 minValueLen = 2;
    if (valueArr->value == NULL || valueArr->len < minValueLen) {
        write_runlog(ERROR, "%s%s Res(%s) fails to print list table body, when value is NULL, or len=[%u: %u].\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName, valueArr->len,
            minValueLen);
        return CM_ERROR;
    }
    const char *resName = GetValueStrOrDefValueFromJson(objItem, RES_NAME);
    const char *resType = GetValueStrOrDefValueFromJson(objItem, RESOURCE_TYPE);
    cJSON *objArray = cJSON_GetObjectItem(objItem, INSTANCES);
    if (!cJSON_IsArray(objArray)) {
        write_runlog(DEBUG1, "%s%s Res(%s) fails to print list table body, when objArray is not array.\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName);
        return CM_ERROR;
    }
    CM_RETURN_IFERR(InitAttrChar(valueArr, resCtx));
    cJSON *item;
    cJSON_ArrayForEach(item, objArray) {
        PrintNameAndResType(resName, resType, valueArr);
        PrintCJsonBody(item, printInfo, valueArr, resCtx);
        SetAttrChar(valueArr);
    }
    FREE_AND_RESET(valueArr->attrChar);
    return CM_SUCCESS;
}

static status_t PrintListInfo(const cJSON *objItem, const ResOption *resCtx, const PrintArray *printInfo)
{
    if (printInfo->arr == NULL || printInfo->arrLen == 0) {
        return CM_SUCCESS;
    }
    PrintListTitle();
    ResValueInfo *valueArr = InitValueArr(printInfo->arrLen, resCtx);
    CM_RETERR_IF_NULL(valueArr);
    status_t st = CM_SUCCESS;
    do {
        st = PrintListTableInfo(objItem, printInfo, valueArr, resCtx);
        CM_BREAK_IF_ERROR(st);
        st = PrintListTableBody(objItem, printInfo, valueArr, resCtx);
        CM_BREAK_IF_ERROR(st);
    } while (0);
    FREE_AND_RESET(valueArr);
    return st;
}

static void InitResArrItem(ResValueInfo *valueArr, const ResOption *resCtx, const PrintArray *printInfo)
{
    uint32 index = 0;
    // g_resComm
    PrintArray tmpArray = {.arr = g_resCom, .arrLen = ELEMENT_COUNT(g_resCom)};
    InitArrItemLen(valueArr, &tmpArray, &index, resCtx, RES_NAME);

    // printInfo
    InitArrItemLen(valueArr, printInfo, &index, resCtx, RES_NAME);
}

static void ComputeResTableItemLen(
    const cJSON *objItem, const PrintArray *printInfo, ResValueInfo *valueArr, const ResOption *resCtx)
{
    // record attrValue
    uint32 attrValue = valueArr->attrValue;
    valueArr->attrValue = 0;

    // g_resComm
    uint32 index = 0;
    PrintArray tmpArray = {.arr = g_resCom, .arrLen = ELEMENT_COUNT(g_resCom)};
    ComputeArrItemLen(objItem, valueArr, &index, &tmpArray, resCtx);

    ComputeArrItemLen(objItem, valueArr, &index, printInfo, resCtx);
    valueArr->attrValue = CM_MAX(valueArr->attrValue, attrValue);

    AddSplit(valueArr);
}

static void PrintResTableInfo(
    const cJSON *objItem, const PrintArray *printInfo, ResValueInfo *valueArr, const ResOption *resCtx)
{
    InitResArrItem(valueArr, resCtx, printInfo);
    ComputeResTableItemLen(objItem, printInfo, valueArr, resCtx);
    PrintListTableTile(printInfo, valueArr, resCtx, RES_ATTR);

    PrintListTableSperatorBar(valueArr);
}

static status_t PrintResTableBody(
    const cJSON *objItem, const PrintArray *printInfo, ResValueInfo *valueArr, const ResOption *resCtx)
{
    const uint32 minValueLen = 2;
    if (valueArr->value == NULL || valueArr->len < minValueLen) {
        write_runlog(ERROR, "%s%s Res(%s) fails to print res table body, when value is NULL, or len=[%u: %u].\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName,
            valueArr->len, minValueLen);
        return CM_ERROR;
    }
    const char *resName = GetValueStrOrDefValueFromJson(objItem, RES_NAME);
    const char *resType = GetValueStrOrDefValueFromJson(objItem, RESOURCE_TYPE);
    CM_RETURN_IFERR(InitAttrChar(valueArr, resCtx));
    PrintNameAndResType(resName, resType, valueArr);
    PrintCJsonBody(objItem, printInfo, valueArr, resCtx);
    FREE_AND_RESET(valueArr->attrChar);
    return CM_SUCCESS;
}

static status_t PrintResInfo(const cJSON *objItem, const ResOption *resCtx, const PrintArray *printInfo)
{
    if (printInfo->arr == NULL || printInfo->arrLen == 0) {
        return CM_SUCCESS;
    }
    PrintListTitle();
    ResValueInfo *valueArr = InitValueArr(printInfo->arrLen, resCtx);
    CM_RETERR_IF_NULL(valueArr);
    status_t st = CM_SUCCESS;
    do {
        PrintResTableInfo(objItem, printInfo, valueArr, resCtx);
        st = PrintResTableBody(objItem, printInfo, valueArr, resCtx);
        CM_BREAK_IF_ERROR(st);
    } while (0);
    FREE_AND_RESET(valueArr);
    return st;
}

status_t ListResInJson(cJSON *resArray, const ResOption *resCtx)
{
    InitListFunc();
    CM_RETURN_IFERR(CheckListParam(resArray, resCtx));
    if (CM_IS_EMPTY_STR(resCtx->resName)) {
        return PrintAllResInfo(resArray, resCtx);
    }
    cJSON *objItem = GetCurResInArray(resArray, resCtx->resName, resCtx);
    if (objItem == NULL) {
        write_runlog(ERROR, "%s%s cannot list Res, because can't find the res(%s) in json.\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName);
        return CM_ERROR;
    }
    ResPrintInfo *printInfo = GetPrintInfo(objItem, resCtx);
    if (printInfo == NULL) {
        return CM_ERROR;
    }
    if (resCtx->inst.mode == RES_OP_LIST) {
        return PrintListInfo(objItem, resCtx, &(printInfo->instArr));
    }

    if (resCtx->inst.mode != RES_OP_INIT) {
        write_runlog(ERROR, "%s%s Res(%s) cannot list Res, because inst_mode(%u) may not be supported.\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName, (uint32)resCtx->inst.mode);
        return CM_ERROR;
    }
    return PrintResInfo(objItem, resCtx, &(printInfo->resArr));
}
