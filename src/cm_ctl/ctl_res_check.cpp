/*
* Copyright (c) 2023 Huawei Technologies Co.,Ltd.
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
* ctl_res.cpp
*    cm_ctl res --check
*
* IDENTIFICATION
*    src/cm_ctl/ctl_res_check.cpp
*
* -------------------------------------------------------------------------
 */

#include "cjson/cJSON.h"

#include "cm_text.h"
#include "cm_ip.h"

#include "ctl_res.h"
#include "ctl_common.h"
#include "ctl_common_res.h"

typedef struct FloatIpResInfoT {
    char ip[CM_IP_LENGTH];
    int32 instId;
} FloatIpResInfo;

static status_t CheckAppResInfo(cJSON *resItem, const char *resName);
static status_t CheckDnResInfo(cJSON *resItem, const char *resName);
static status_t CheckVipResInfo(cJSON *resItem, const char *resName);

ResTypeMap g_resTypeMap[RES_TYPE_CEIL];

const char *g_instAttrMap[] = {"base_ip"};

static void PrintCheckJsonInfo(int level, const char* fmt, ...)
{
    va_list ap;
    char infoBuf[MAX_LOG_BUFF_LEN] = {0};

    fmt = _(fmt);
    va_start(ap, fmt);
    int ret = vsnprintf_s(infoBuf, sizeof(infoBuf), sizeof(infoBuf) - 1, fmt, ap);
    securec_check_intval(ret, (void)ret);

    switch (level) {
        case WARNING:
            write_runlog(level, "warning: %s", infoBuf);
            break;
        case ERROR:
            write_runlog(level, "error: %s", infoBuf);
            break;
        default:
            write_runlog(level, "%s", infoBuf);
            break;
    }

    va_end(ap);
}

static bool8 CmCheckIsJsonNumber(const cJSON *obj, const char *resName, const char *paraName, int logLevel)
{
    const char *defValue = ResConfDefValue(paraName);
    if (obj == NULL) {
        PrintCheckJsonInfo(logLevel, "resource(%s)'s %s not configured, default(%s).\n", resName, paraName, defValue);
        return CM_FALSE;
    }
    if (!cJSON_IsNumber(obj)) {
        PrintCheckJsonInfo(logLevel, "resource(%s)'s %s is not a number, default(%s).\n", resName, paraName, defValue);
        return CM_FALSE;
    }

    return CM_TRUE;
}

static bool8 CmCheckIsJsonString(const cJSON *obj, const char *resName, const char *paraName, int logLevel)
{
    const char *defValue = ResConfDefValue(paraName);
    if (obj == NULL) {
        PrintCheckJsonInfo(logLevel, "resource(%s)'s %s not configured, default(%s).\n", resName, paraName, defValue);
        return CM_FALSE;
    }
    if (!cJSON_IsString(obj)) {
        PrintCheckJsonInfo(logLevel, "resource(%s)'s %s is not a string, default(%s).\n", resName, paraName, defValue);
        return CM_FALSE;
    }

    return CM_TRUE;
}

static bool8 CmCheckIsJsonBool(const cJSON *obj, const char *resName, const char *paraName, int logLevel)
{
    const char *defValue = ResConfDefValue(paraName);
    if (obj == NULL) {
        PrintCheckJsonInfo(logLevel, "resource(%s)'s %s not configured, default(%s).\n", resName, paraName, defValue);
        return CM_FALSE;
    }
    if (!cJSON_IsBool(obj) && (!cJSON_IsString(obj) || !CheckBoolConfigParam(obj->valuestring))) {
        PrintCheckJsonInfo(logLevel, "resource(%s)'s %s is not a bool, default(%s).\n", resName, paraName, defValue);
        return CM_FALSE;
    }

    return CM_TRUE;
}

static status_t CheckOneResInst(cJSON *instItem, const char *resName)
{
    cJSON *nodeJson = cJSON_GetObjectItem(instItem, INST_NODE_ID);
    CM_RETERR_IF_FALSE(CmCheckIsJsonNumber(nodeJson, resName, "one instance node_id", ERROR));
    if (!IsNodeIdValid(nodeJson->valueint)) {
        PrintCheckJsonInfo(ERROR, "resource(%s)'s one instance node_id(%d) is invalid.\n", resName, nodeJson->valueint);
        return CM_ERROR;
    }

    cJSON *resInstValue = cJSON_GetObjectItem(instItem, INST_RES_INST_ID);
    (void)CmCheckIsJsonNumber(resInstValue, resName, "one instance res_instance_id", WARNING);

    resInstValue = cJSON_GetObjectItem(instItem, "res_args");
    (void)CmCheckIsJsonString(resInstValue, resName, "one instance res_args", WARNING);

    return CM_SUCCESS;
}

static status_t CheckAllResInst(cJSON *instArray, const char *resName)
{
    cJSON *instItem;
    cJSON_ArrayForEach(instItem, instArray) {
        CM_RETURN_IFERR(CheckOneResInst(instItem, resName));
    }

    return CM_SUCCESS;
}

static status_t CheckResNumberOptInfo(cJSON *resItem, const char *resName, const char *checkKey)
{
    cJSON *objValue = cJSON_GetObjectItem(resItem, checkKey);
    CM_RETERR_IF_FALSE(CmCheckIsJsonNumber(objValue, resName, checkKey, WARNING));
    if (!IsResConfValid(checkKey, objValue->valueint)) {
        PrintCheckJsonInfo(WARNING, "resource(%s)'s %s=%d out of range, range[%d %d], default(%s).\n",
            resName, checkKey, objValue->valueint,
            ResConfMinValue(checkKey), ResConfMaxValue(checkKey), ResConfDefValue(checkKey));
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static bool ParseIsCritical(cJSON *objValue)
{
    if (cJSON_IsBool(objValue)) {
        return (bool)cJSON_IsTrue(objValue);
    }

    if (cJSON_IsString(objValue) && CheckBoolConfigParam(objValue->valuestring)) {
        return IsBoolCmParamTrue(objValue->valuestring);
    }

    return true;
}

static void CheckLocationAttrFormat(const char *resName, const char *attr)
{
    int paramLen = 0;
    int valueLen = 0;
    int flagCount = 0;
    for (uint32 i = 0; i < strlen(attr); ++i) {
        if (attr[i] == ':') {
            ++flagCount;
            continue;
        }

        if (flagCount == 0) {
            ++paramLen;
        }
        if (flagCount == 1) {
            ++valueLen;
        }
        if (flagCount > 1) {
            break;
        }
    }

    if (flagCount == 0) {
        PrintCheckJsonInfo(WARNING, "resource(%s)'s location_attr(%s) format wrong, have no \':\'.\n",
            resName, attr);
        return;
    }
    if (flagCount > 1) {
        PrintCheckJsonInfo(WARNING, "resource(%s)'s location_attr(%s) format wrong, more than one \':\'.\n",
            resName, attr);
        return;
    }

    if (paramLen == 0) {
        PrintCheckJsonInfo(WARNING, "resource(%s)'s location_attr(%s) format wrong, have no parameter.\n",
            resName, attr);
    }
    if (valueLen == 0) {
        PrintCheckJsonInfo(WARNING, "resource(%s)'s location_attr(%s) format wrong, have no right value.\n",
            resName, attr);
    }
}

static void CheckResLocalOptInfo(cJSON *resItem, const char *resName)
{
    char localType[NAMEDATALEN] = {0};
    cJSON *objType = cJSON_GetObjectItem(resItem, "location_type");
    if (CmCheckIsJsonString(objType, resName, "location_type", WARNING)) {
        errno_t rc = strcpy_s(localType, NAMEDATALEN, objType->valuestring);
        securec_check_errno(rc, (void)rc);
    } else {
        cJSON *objValue = cJSON_GetObjectItem(resItem, "is_critical");
        (void)CmCheckIsJsonBool(objValue, resName, "is_critical", WARNING);
        return;
    }

    if (strcasecmp(localType, "local") != 0 && strcasecmp(localType, "any_one") != 0 &&
        strcasecmp(localType, "qualified_one") != 0) {
        PrintCheckJsonInfo(WARNING, "resource(%s)'s location_type=\"%s\" not in (local/any_one/qualified_one), "
            "default(%s).\n", resName, localType, ResConfDefValue("location_type"));
    }

    cJSON *objValue = cJSON_GetObjectItem(resItem, "is_critical");
    bool isCritical = IsBoolCmParamTrue(ResConfDefValue("is_critical"));
    if (CmCheckIsJsonBool(objValue, resName, "is_critical", WARNING)) {
        isCritical = ParseIsCritical(objValue);
    }

    if (isCritical && (strcasecmp(localType, "any_one") == 0 || strcasecmp(localType, "qualified_one") == 0)) {
        PrintCheckJsonInfo(WARNING, "resource(%s)'s location_type is %s, is_critical must be false.\n",
            resName, localType);
    }

    if (strcasecmp(localType, "qualified_one") == 0) {
        cJSON *objAttr = cJSON_GetObjectItem(resItem, "location_attr");
        if (CmCheckIsJsonString(objType, resName, "location_attr", WARNING)) {
            CheckLocationAttrFormat(resName, objAttr->valuestring);
        }
    }
}

static status_t CheckAppDnCommResInfo(cJSON *resItem, const char *resName)
{
    cJSON *objValue = cJSON_GetObjectItem(resItem, "script");
    CM_RETERR_IF_FALSE(CmCheckIsJsonString(objValue, resName, "script", ERROR));

    (void)CheckResNumberOptInfo(resItem, resName, "check_interval");
    (void)CheckResNumberOptInfo(resItem, resName, "time_out");
    (void)CheckResNumberOptInfo(resItem, resName, "restart_delay");
    (void)CheckResNumberOptInfo(resItem, resName, "restart_period");
    (void)CheckResNumberOptInfo(resItem, resName, "restart_times");

    CheckResLocalOptInfo(resItem, resName);

    return CM_SUCCESS;
}

static status_t CheckAppResInfo(cJSON *resItem, const char *resName)
{
    cJSON *instArray = cJSON_GetObjectItem(resItem, INSTANCES);
    if (!cJSON_IsArray(instArray)) {
        PrintCheckJsonInfo(ERROR, "resource(%s)'s resource_type is APP, but instance array not configured.\n", resName);
        return CM_ERROR;
    }
    if (cJSON_GetArraySize(instArray) == 0) {
        PrintCheckJsonInfo(ERROR, "resource(%s)'s resource_type is APP, but instance array is empty.\n", resName);
        return CM_ERROR;
    }

    CM_RETURN_IFERR(CheckAllResInst(instArray, resName));

    return CheckAppDnCommResInfo(resItem, resName);
}

static status_t CheckDnResInfo(cJSON *resItem, const char *resName)
{
    cJSON *instArray = cJSON_GetObjectItem(resItem, INSTANCES);
    if (cJSON_IsArray(instArray)) {
        CM_RETURN_IFERR(CheckAllResInst(instArray, resName));
    }
    return CheckAppDnCommResInfo(resItem, resName);
}

static bool8 IsKeyInInstAttr(const char *key)
{
    if (CM_IS_EMPTY_STR(key)) {
        return CM_FALSE;
    }

    uint32 len = ELEMENT_COUNT(g_instAttrMap);
    for (uint32 i = 0; i < len; ++i) {
        if (cm_str_equal(key, g_instAttrMap[i])) {
            return CM_TRUE;
        }
    }
    return CM_FALSE;
}

static status_t GetExpIpFromJson(cJSON *resItem, const char *key, const char *resName, char *ip, uint32 ipLen)
{
    bool8 isInInstAttr = IsKeyInInstAttr(key);
    const char *trueKey = isInInstAttr ? INST_ATTR : key;
    cJSON *objValue = cJSON_GetObjectItem(resItem, trueKey);
    CM_RETERR_IF_FALSE(CmCheckIsJsonString(objValue, resName, trueKey, ERROR));

    if (!isInInstAttr) {
        check_input_for_security(objValue->valuestring);
        errno_t rc = strcpy_s(ip, ipLen, objValue->valuestring);
        securec_check_errno(rc, (void)rc);
        return CM_SUCCESS;
    }

    char *point = strstr(objValue->valuestring, key);
    if (point == NULL) {
        write_runlog(ERROR, "Res(%s) cannot find %s from %s.\n", resName, key, INST_ATTR);
        return CM_ERROR;
    }
    char tmpIp[MAX_PATH_LEN] = {0};
    if (FetchStrFromText(point, tmpIp, MAX_PATH_LEN, KEY_VALUE_SPLIT_CHAR) != 0) {
        write_runlog(ERROR, "Res(%s) cannot find [%s] from [%s] with the key[%s].\n",
            resName, key, objValue->valuestring, INST_ATTR);
        return CM_ERROR;
    }
    check_input_for_security(tmpIp);
    errno_t rc = strncpy_s(ip, ipLen, tmpIp, ipLen - 1);
    securec_check_errno(rc, (void)rc);
    return CM_SUCCESS;
}

static status_t CheckIpValidInJson(cJSON *resItem, const char *key, const char *resName, char *ip, uint32 ipLen)
{
    CM_RETURN_IFERR(GetExpIpFromJson(resItem, key, resName, ip, ipLen));
    if (!CheckIpValid(ip)) {
        PrintCheckJsonInfo(ERROR, "resource(%s)'s %s is an invalid ip.\n", resName, key);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t CheckAndGetNumberFromJson(cJSON *resItem, const char *resName, const char *checkKey, int32 *value)
{
    cJSON *objValue = cJSON_GetObjectItem(resItem, checkKey);
    CM_RETERR_IF_FALSE(CmCheckIsJsonNumber(objValue, resName, checkKey, ERROR));

    if (!IsResConfValid(checkKey, objValue->valueint)) {
        PrintCheckJsonInfo(ERROR, "resource(%s)'s %s=%d out of range, range[%d %d].\n", resName, checkKey,
            objValue->valueint, ResConfMinValue(checkKey), ResConfMaxValue(checkKey));
        return CM_ERROR;
    }
    if (value != NULL) {
        *value = objValue->valueint;
    }
    return CM_SUCCESS;
}

static status_t CheckFloatIPResInfo(
    const char *resName, FloatIpResInfo *info, int32 maxLen, int32 *index, const FloatIpResInfo *curInfo)
{
    int32 point = *index;
    if (point >= maxLen) {
        PrintCheckJsonInfo(ERROR, "resource(%s)'s point(%d) has more then MaxLen(%d).\n", resName, point, maxLen);
        return CM_ERROR;
    }

    // instance_id
    for (int32 i = 0; i < point; ++i) {
        if (curInfo->instId == info[i].instId) {
            PrintCheckJsonInfo(ERROR,
                "resource(%s)'s FloatIp base_ip_list instance_id(%d) may be repeated.\n", resName, curInfo->instId);
            return CM_ERROR;
        }
    }

    // base_ip
    for (int32 i = 0; i < point; ++i) {
        if (IsEqualIp(curInfo->ip, info[i].ip)) {
            PrintCheckJsonInfo(ERROR,
                "resource(%s)'s FloatIp base_ip_list base_ip(%s) may be repeated.\n", resName, curInfo->ip);
            return CM_ERROR;
        }
    }

    info[point].instId = curInfo->instId;
    errno_t rc = strcpy_s(info[point].ip, CM_IP_LENGTH, curInfo->ip);
    securec_check_errno(rc, (void)rc);
    ++(*index);
    return CM_SUCCESS;
}

static status_t CheckVipResInfo(cJSON *resItem, const char *resName)
{
    // instances
    cJSON *instArray = cJSON_GetObjectItem(resItem, INSTANCES);
    if (!cJSON_IsArray(instArray)) {
        PrintCheckJsonInfo(ERROR, "resource(%s)'s resource_type is VIP, but base_ip_list not configured.\n", resName);
        return CM_ERROR;
    }
    FloatIpResInfo info[CM_PRIMARY_STANDBY_MAX_NUM + 1] = {{{0}}};
    int32 arrSize = cJSON_GetArraySize(instArray);
    if (arrSize < 0 || arrSize > CM_PRIMARY_STANDBY_MAX_NUM) {
        PrintCheckJsonInfo(ERROR,
            "resource(%s)'s base_ip_list size(%d) must in [0: %d].\n", resName, arrSize, CM_PRIMARY_STANDBY_MAX_NUM);
        return CM_ERROR;
    }
    // float_ip
    CM_RETURN_IFERR(CheckIpValidInJson(resItem, "float_ip", resName, info[0].ip, CM_IP_LENGTH));
    FloatIpResInfo curInfo = {0};
    cJSON *instItem;
    int32 index = 1;
    cJSON_ArrayForEach(instItem, instArray) {
        // res_instance_id
        CM_RETURN_IFERR(CheckAndGetNumberFromJson(instItem, resName, INST_RES_INST_ID, &(curInfo.instId)));
        // base_ip
        CM_RETURN_IFERR(CheckIpValidInJson(instItem, g_instAttrMap[0], resName, curInfo.ip, CM_IP_LENGTH));

        CM_RETURN_IFERR(CheckFloatIPResInfo(resName, info, CM_PRIMARY_STANDBY_MAX_NUM + 1, &index, &curInfo));
    }
    return CM_SUCCESS;
}

status_t CheckResName(
    const cJSON *resItem, char (*resName)[CM_MAX_RES_NAME], uint32 maxCnt, uint32 *curCnt, const char **curResName)
{
    cJSON *objName = cJSON_GetObjectItem(resItem, RES_NAME);
    CM_RETERR_IF_FALSE(CmCheckIsJsonString(objName, "", RES_NAME, ERROR));

    if (strlen(objName->valuestring) >= CM_MAX_RES_NAME) {
        PrintCheckJsonInfo(ERROR, "resource's name(%s) length exceeds the maximum(%d).\n",
            objName->valuestring, CM_MAX_RES_NAME);
        return CM_ERROR;
    }
    uint32 resNameCount = *curCnt;
    if (resNameCount >= maxCnt) {
        PrintCheckJsonInfo(ERROR, "resource count exceeds the maximum(%u).\n", maxCnt);
        return CM_ERROR;
    }
    errno_t rc = strcpy_s(resName[resNameCount], CM_MAX_RES_NAME, objName->valuestring);
    securec_check_errno(rc, (void)rc);
    *curResName = resName[resNameCount];
    for (uint32 i = 0; i < resNameCount; i++) {
        if (strcmp(resName[resNameCount], resName[i]) == 0) {
            PrintCheckJsonInfo(ERROR, "resource(%s)'s configure repeated.\n", objName->valuestring);
            return CM_ERROR;
        }
    }
    ++(*curCnt);
    return CM_SUCCESS;
}

static void GetAllRestypeStr(char *typeStr, uint32 maxlen)
{
    errno_t rc;
    uint32 arrLen = (uint32)(sizeof(g_resTypeMap) / sizeof(g_resTypeMap[0]));
    char tmpStr[MAX_PATH_LEN] = {0};
    for (uint32 i = 0; i < arrLen; ++i) {
        if (g_resTypeMap[i].type == RES_TYPE_INIT || g_resTypeMap[i].type == RES_TYPE_UNKNOWN) {
            continue;
        }
        if (strlen(typeStr) + strlen(g_resTypeMap[i].typeStr) >= maxlen) {
            return;
        }
        if (typeStr[0] == '\0') {
            rc = snprintf_s(tmpStr, MAX_PATH_LEN, MAX_PATH_LEN - 1, "\"%s\"", g_resTypeMap[i].typeStr);
        } else {
            rc = snprintf_s(tmpStr, MAX_PATH_LEN, MAX_PATH_LEN - 1, ", \"%s\"", g_resTypeMap[i].typeStr);
        }
        securec_check_intval(rc, (void)rc);
        rc = strcat_s(typeStr, maxlen, tmpStr);
        securec_check_errno(rc, (void)rc);
    }
}

bool CompareResType(const char *value, uint32 *index)
{
    if (value == NULL) {
        write_runlog(ERROR, "value is NULL.\n");
        return false;
    }
    char resTypeStr[MAX_PATH_LEN] = {0};
    errno_t rc;
    uint32 arrLen = (uint32)(sizeof(g_resTypeMap) / sizeof(g_resTypeMap[0]));
    char tmpStr[MAX_PATH_LEN] = {0};
    for (uint32 i = 0; i < arrLen; ++i) {
        if (g_resTypeMap[i].type == RES_TYPE_INIT || g_resTypeMap[i].type == RES_TYPE_UNKNOWN) {
            continue;
        }
        if (g_resTypeMap[i].typeStr == NULL) {
            continue;
        }
        if (cm_str_equal(value, g_resTypeMap[i].typeStr)) {
            *index = i;
            return true;
        }
        if (i == 0) {
            rc = snprintf_s(
                tmpStr, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s-%s", g_resTypeMap[i].typeStr, g_resTypeMap[i].value);
        } else {
            rc = snprintf_s(
                tmpStr, MAX_PATH_LEN, MAX_PATH_LEN - 1, ", %s-%s", g_resTypeMap[i].typeStr, g_resTypeMap[i].value);
        }
        securec_check_intval(rc, (void)rc);
        rc = strcat_s(resTypeStr, MAX_PATH_LEN, tmpStr);
        securec_check_errno(rc, (void)rc);
    }
    write_runlog(DEBUG1, "cannot find resType%s in g_resTypeMap%s.\n", value, resTypeStr);
    return false;
}

static uint32 GetResTypeIndex(cJSON *resItem, const char *resName)
{
    cJSON *objValue = cJSON_GetObjectItem(resItem, RESOURCE_TYPE);
    if (!CmCheckIsJsonString(objValue, resName, RESOURCE_TYPE, WARNING)) {
        return RES_TYPE_UNKNOWN;
    }

    uint32 index = 0;
    if (CompareResType(objValue->valuestring, &index)) {
        return index;
    }
    char allResName[MAX_PATH_LEN] = {0};
    GetAllRestypeStr(allResName, MAX_PATH_LEN);
    PrintCheckJsonInfo(WARNING, "resource(%s)'s resources_type is (%s), not in range(%s), default(%s).\n",
        resName, objValue->valuestring, allResName, ResConfDefValue(RESOURCE_TYPE));
    return RES_TYPE_UNKNOWN;
}

ResType GetResTypeFromCjson(cJSON *resItem)
{
    const char *resType = GetValueStrFromCJson(resItem, RESOURCE_TYPE);
    if (resType == NULL) {
        resType = ResConfDefValue(RESOURCE_TYPE);
    }
    if (CM_IS_EMPTY_STR(resType)) {
        return RES_TYPE_UNKNOWN;
    }
    for (uint32 i = 0; i < (uint32)RES_TYPE_CEIL; ++i) {
        if (g_resTypeMap[i].typeStr == NULL) {
            continue;
        }
        if (g_resTypeMap[i].type == RES_TYPE_UNKNOWN) {
            continue;
        }
        if (cm_str_equal(g_resTypeMap[i].typeStr, resType)) {
            return g_resTypeMap[i].type;
        }
    }
    return RES_TYPE_UNKNOWN;
}

static CheckResInfo GetResCheckFunc(uint32 curIndex)
{
    if (curIndex >= (uint32)RES_TYPE_CEIL) {
        return NULL;
    }
    return g_resTypeMap[curIndex].check;
}

status_t CheckResFromArray(cJSON *resArray)
{
    cJSON *resItem;
    const uint32 maxResCnt = CM_MAX_RES_COUNT + CM_MAX_VIP_COUNT;
    char resName[maxResCnt][CM_MAX_RES_NAME];
    uint32 resNameCount = 0;

    cJSON_ArrayForEach(resItem, resArray) {
        const char *curResName;

        CM_RETURN_IFERR(CheckResName(resItem, resName, maxResCnt, &resNameCount, &curResName));

        CheckResInfo check = GetResCheckFunc(GetResTypeIndex(resItem, curResName));
        // resource may not be checked.
        if (check != NULL) {
            CM_RETURN_IFERR(check(resItem, curResName));
        }
    }
    return CM_SUCCESS;
}

static status_t GetLocalJsonMd5(const char *jsonFile, char *result, uint32 resultLen)
{
    char localMd5Cmd[MAX_PATH_LEN] = {0};
    int ret = sprintf_s(localMd5Cmd, MAX_PATH_LEN, "md5sum -t %s | awk '{print $1}'", jsonFile);
    securec_check_intval(ret, (void)ret);
    FILE *fp = popen(localMd5Cmd, "r");
    if (fp == NULL) {
        PrintCheckJsonInfo(ERROR, "execute command:\"md5sum %s\" failed.\n", jsonFile);
        return CM_ERROR;
    }
    if (fgets(result, ((int32)resultLen) - 1, fp) == NULL) {
        (void)pclose(fp);
        PrintCheckJsonInfo(ERROR, "can't get local md5sum of %s.\n", jsonFile);
        return CM_ERROR;
    }

    (void)pclose(fp);
    return CM_SUCCESS;
}

status_t CheckRemoteJson(const char *jsonFile)
{
    char localMd5[NAMEDATALEN] = {0};
    CM_RETURN_IFERR(GetLocalJsonMd5(jsonFile, localMd5, NAMEDATALEN));

    char remoteMd5Cmd[MAX_PATH_LEN];
    int ret = sprintf_s(remoteMd5Cmd, MAX_PATH_LEN, "md5sum -t %s | grep -w %s", jsonFile, localMd5);
    securec_check_intval(ret, (void)ret);

    status_t result = CM_SUCCESS;
    for (uint32 i = 0; i < g_node_num; ++i) {
        if (g_node[i].node == g_currentNode->node) {
            continue;
        }
        if (ssh_exec(&g_node[i], remoteMd5Cmd, DEBUG1) != 0) {
            PrintCheckJsonInfo(ERROR, "node(%u)'s cm_resource.json not same with local, please check ip(%s)'s json.\n",
                g_node[i].node, g_node[i].sshChannel[0]);
            result = CM_ERROR;
        }
    }

    return result;
}

void InitResTypeMap()
{
    errno_t rc = memset_s(g_resTypeMap, sizeof(g_resTypeMap), 0, sizeof(g_resTypeMap));
    securec_check_errno(rc, (void)rc);
    g_resTypeMap[RES_TYPE_UNKNOWN].type = RES_TYPE_UNKNOWN;
    g_resTypeMap[RES_TYPE_UNKNOWN].typeStr = "APP";
    g_resTypeMap[RES_TYPE_UNKNOWN].value = INSTANCES;
    g_resTypeMap[RES_TYPE_UNKNOWN].check = CheckAppResInfo;
    
    g_resTypeMap[RES_TYPE_APP].type = RES_TYPE_APP;
    g_resTypeMap[RES_TYPE_APP].typeStr = "APP";
    g_resTypeMap[RES_TYPE_APP].value = INSTANCES;
    g_resTypeMap[RES_TYPE_APP].check = CheckAppResInfo;

    g_resTypeMap[RES_TYPE_DN].type = RES_TYPE_DN;
    g_resTypeMap[RES_TYPE_DN].typeStr = "DN";
    g_resTypeMap[RES_TYPE_DN].value = NULL;
    g_resTypeMap[RES_TYPE_DN].check = CheckDnResInfo;

    g_resTypeMap[RES_TYPE_VIP].type = RES_TYPE_VIP;
    g_resTypeMap[RES_TYPE_VIP].typeStr = "VIP";
    g_resTypeMap[RES_TYPE_VIP].value = INSTANCES;
    g_resTypeMap[RES_TYPE_VIP].check = CheckVipResInfo;
}

bool8 IsResCheckInstances(ResType resType)
{
    uint32 len = ELEMENT_COUNT(g_resTypeMap);
    for (uint32 i = 0; i < len; ++i) {
        if (resType == g_resTypeMap[i].type && g_resTypeMap[i].value != NULL) {
            return CM_TRUE;
        }
    }
    return CM_FALSE;
}

bool8 IsCurNotCheckInstances(const ResOption *resCtx, const cJSON *resObj)
{
    ResType type = GetResTypeInJson(resCtx, resObj);
    uint32 len = ELEMENT_COUNT(g_resTypeMap);
    for (uint32 i = 0; i < len; ++i) {
        if (type == g_resTypeMap[i].type && g_resTypeMap[i].value == NULL) {
            return CM_TRUE;
        }
    }
    return CM_FALSE;
}

const char *GetResTypeValue(uint32 index)
{
    return g_resTypeMap[index].value;
}
