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
* cm_json_config.cpp
*
*
* IDENTIFICATION
*    src/cm_common/cm_json_config.cpp
*
* -------------------------------------------------------------------------
*/
#include "cm_defs.h"
#include "elog.h"
#include "cm_text.h"
#include "cm_json_config.h"

#define CM_SET_READ_JSON_ERR(errPtr, err)  \
    do {                                   \
        if ((errPtr) != NULL) {            \
            (*(errPtr)) = (err);           \
        }                                  \
    } while (0)

typedef void (*ParseCusRes)(const cJSON *resJson, OneCusResConfJson *resConf);

static void ParseAppResConfJson(const cJSON *resJson, OneCusResConfJson *resConf);
static void ParseDnResConfJson(const cJSON *resJson, OneCusResConfJson *resConf);
static void ParseVipResConfJson(const cJSON *resJson, OneCusResConfJson *resConf);

static void EmptyCmJsonWriteLog(int logLevel, const char *format, ...)
{
    return;
}

typedef struct ParseCusResMapSt {
    const char *resTypeName;
    CusResType resType;
    ParseCusRes parseFunc;
} ParseCusResMap;

CmConfJson *g_confJson = NULL;
static CmJsonLogOutput CmJsonWriteLog = EmptyCmJsonWriteLog;

static ParseCusResMap g_cusResMap[] = {
    {"APP", CUSTOM_RESOURCE_APP, ParseAppResConfJson},
    {"DN", CUSTOM_RESOURCE_DN, ParseDnResConfJson},
    {"VIP", CUSTOM_RESOURCE_VIP, ParseVipResConfJson},
};

static void *CmJsonMalloc(size_t size)
{
    if (size == 0) {
        CmJsonWriteLog(FATAL, "[CmJsonMalloc] malloc 0.\n");
        exit(1);
    }
    void *result = malloc(size);
    if (result == NULL) {
        CmJsonWriteLog(FATAL, "[CmJsonMalloc] malloc failed, out of memory.\n");
        exit(1);
    }
    errno_t rc = memset_s(result, size, 0, size);
    securec_check_errno(rc, (void)rc);

    return result;
}

static void CmJsonCheckForSecurity(const char *input)
{
    const char *dangerCharList[] = {"|", ";", "&", "$", "<", ">", "`", "\\", "'", "\"", "{", "}",
        "(", ")", "[", "]", "~", "*", "?", "!", "\n", NULL};

    for (int i = 0; dangerCharList[i] != NULL; i++) {
        if (strstr(input, dangerCharList[i]) != NULL) {
            CmJsonWriteLog(FATAL, "invalid token %s in input:\"%s\".\n", dangerCharList[i], input);
            exit(1);
        }
    }
}

static int GetValueIntFromJson(int *infoValue, const cJSON *object, const char *infoKey)
{
    cJSON *objValue = cJSON_GetObjectItem(object, infoKey);
    if (!cJSON_IsNumber(objValue)) {
        CmJsonWriteLog(WARNING, "[ReadConfJson] (%s) object is not number or not exit.\n", infoKey);
        return 1;
    }
    if (infoValue != NULL) {
        *infoValue = objValue->valueint;
    }
    return 0;
}

static int GetValueStrFromJson(char *valueStr, uint32 valueLen, const cJSON *object, const char *infoKey)
{
    cJSON *objValue = cJSON_GetObjectItem(object, infoKey);
    if (!cJSON_IsString(objValue)) {
        CmJsonWriteLog(WARNING, "[ReadConfJson] (%s) object is not string or not exit.\n", infoKey);
        return 1;
    }
    if (objValue->valuestring[0] == '\0') {
        CmJsonWriteLog(WARNING, "[ReadConfJson] (%s) object is an empty string.\n", infoKey);
        return 1;
    }
    if (valueStr != NULL) {
        errno_t rc = strcpy_s(valueStr, valueLen, objValue->valuestring);
        securec_check_errno(rc, (void)rc);
        CmJsonCheckForSecurity(valueStr);
    }

    return 0;
}

static void ParseOneCusResInstConfJson(const cJSON *instJson, CusResInstConf *instConf)
{
    const int defValue = -1;

    if (GetValueIntFromJson(&instConf->nodeId, instJson, "node_id") != 0) {
        instConf->nodeId = defValue;
    }
    if (GetValueIntFromJson(&instConf->resInstId, instJson, "res_instance_id") != 0) {
        instConf->resInstId = defValue;
    }
    if (GetValueStrFromJson(instConf->resArgs, CM_JSON_STR_LEN, instJson, "res_args") != 0) {
        errno_t rc = memset_s(instConf->resArgs, CM_JSON_STR_LEN, 0, CM_JSON_STR_LEN);
        securec_check_errno(rc, (void)rc);
    }
}

static void ParseAllCusResInstConfJson(const cJSON *resJson, CusResConfJson *resConf)
{
    cJSON *instArr = cJSON_GetObjectItem(resJson, "instances");
    if (!cJSON_IsArray(instArr)) {
        if (instArr != NULL) {
            CmJsonWriteLog(WARNING, "[ReadConfJson] \"instances\" obj is not an array, can't parse continue.\n");
        }
        return;
    }
    int arrLen = cJSON_GetArraySize(instArr);
    if (arrLen <= 0) {
        CmJsonWriteLog(WARNING, "[ReadConfJson] inst array len invalid, arrLen=%d, can't parse continue.\n", arrLen);
        return;
    }

    resConf->instance.count = (uint32)arrLen;
    resConf->instance.conf = (CusResInstConf*)CmJsonMalloc((uint32)arrLen * sizeof(CusResInstConf));

    for (int i = 0; i < arrLen; ++i) {
        cJSON *resItem = cJSON_GetArrayItem(instArr, i);
        if (resItem != NULL) {
            ParseOneCusResInstConfJson(resItem, &resConf->instance.conf[i]);
        }
    }
}

static void ParseAppDnResConfJson(const cJSON *resJson, CusResConfJson *resConf)
{
    errno_t rc;
    const int defValue = -1;

    if (GetValueStrFromJson(resConf->resName, CM_JSON_STR_LEN, resJson, "name") != 0) {
        rc = memset_s(resConf->resName, CM_JSON_STR_LEN, 0, CM_JSON_STR_LEN);
        securec_check_errno(rc, (void)rc);
    }
    if (GetValueStrFromJson(resConf->resScript, CM_JSON_STR_LEN, resJson, "script") != 0) {
        rc = memset_s(resConf->resScript, CM_JSON_STR_LEN, 0, CM_JSON_STR_LEN);
        securec_check_errno(rc, (void)rc);
    }
    if (GetValueIntFromJson(&resConf->checkInterval, resJson, "check_interval") != 0) {
        resConf->checkInterval = defValue;
    }
    if (GetValueIntFromJson(&resConf->timeOut, resJson, "time_out") != 0) {
        resConf->timeOut = defValue;
    }
    if (GetValueIntFromJson(&resConf->restartDelay, resJson, "restart_delay") != 0) {
        resConf->restartDelay = defValue;
    }
    if (GetValueIntFromJson(&resConf->restartPeriod, resJson, "restart_period") != 0) {
        resConf->restartPeriod = defValue;
    }
    if (GetValueIntFromJson(&resConf->restartTimes, resJson, "restart_times") != 0) {
        resConf->restartTimes = defValue;
    }
    if (GetValueIntFromJson(&resConf->abnormalTimeout, resJson, "abnormal_timeout") != 0) {
        resConf->abnormalTimeout = defValue;
    }
}

static void ParseAppResConfJson(const cJSON *resJson, OneCusResConfJson *resConf)
{
    ParseAppDnResConfJson(resJson, &resConf->appResConf);
    ParseAllCusResInstConfJson(resJson, &resConf->appResConf);
}

static void ParseDnResConfJson(const cJSON *resJson, OneCusResConfJson *resConf)
{
    ParseAppDnResConfJson(resJson, &resConf->dnResConf);
    ParseAllCusResInstConfJson(resJson, &resConf->dnResConf);
}

int FetchStrFromText(const char *textStr, char *result, uint32 len, char beginPoint)
{
    bool8 isFetch = CM_FALSE;
    uint32 point = 0;
    for (uint32 i = 0; textStr[i] != '\0'; ++i) {
        if (!isFetch) {
            if (textStr[i] == beginPoint) {
                isFetch = CM_TRUE;
            }
            continue;
        }
        if (textStr[i] == SEPARATOR_CHAR) {
            break;
        }
        if (point >= len) {
            return -1;
        }
        result[point] = textStr[i];
        ++point;
    }
    CmTrimStr(result);
    if (result[0] == '\0') {
        return -1;
    }
    return 0;
}

int GetValueStrFromText(char *result, uint32 resultLen, const char *textStr, const char *expectValue)
{
    const char *point = strstr(textStr, expectValue);
    if (point == NULL) {
        write_runlog(ERROR, "Failed to get value str from text, when textStr=[%s], expectValue=[%s].\n",
            textStr, expectValue);
        return -1;
    }
    if (FetchStrFromText(point, result, resultLen, '=') != 0) {
        write_runlog(ERROR, "Failed to fetch text from string, when textStr=[%s], expectValue=[%s].\n",
            textStr, expectValue);
        return -1;
    }
    return 0;
}

static void ParseOneBaseIp(const cJSON *ipJson, BaseIpListConf *ipConf)
{
    if (GetValueIntFromJson(&ipConf->instId, ipJson, "res_instance_id") != 0) {
        ipConf->instId = 0;
    }
    char baseIp[CM_JSON_STR_LEN] = {0};
    if (GetValueStrFromJson(baseIp, CM_JSON_STR_LEN, ipJson, "inst_attr") != 0) {
        return;
    }

    if (GetValueStrFromText(ipConf->baseIp, CM_JSON_STR_LEN, baseIp, "base_ip") != 0) {
        errno_t rc = memset_s(ipConf->baseIp, CM_JSON_STR_LEN, 0, CM_JSON_STR_LEN);
        securec_check_errno(rc, (void)rc);
    }
}

static void ParseAllBaseIp(const cJSON *resJson, VipCusResConfJson *resConf)
{
    cJSON *baseIpArray = cJSON_GetObjectItem(resJson, "instances");
    if (!cJSON_IsArray(baseIpArray)) {
        if (baseIpArray != NULL) {
            CmJsonWriteLog(WARNING, "[ReadConfJson] \"instances\" obj is not an array, can't parse continue.\n");
        }
        return;
    }
    int arrLen = cJSON_GetArraySize(baseIpArray);
    if (arrLen <= 0) {
        CmJsonWriteLog(WARNING, "[ReadConfJson] baseIp array len invalid, arrLen=%d, can't parse continue.\n", arrLen);
        return;
    }

    resConf->baseIpList.count = (uint32)arrLen;
    resConf->baseIpList.conf = (BaseIpListConf*)CmJsonMalloc((uint32)arrLen * sizeof(BaseIpListConf));

    for (int i = 0; i < arrLen; ++i) {
        cJSON *resItem = cJSON_GetArrayItem(baseIpArray, i);
        if (resItem != NULL) {
            ParseOneBaseIp(resItem, &resConf->baseIpList.conf[i]);
        }
    }
}

static void ParseVipResConfJson(const cJSON *resJson, OneCusResConfJson *resConf)
{
    errno_t rc;
    if (GetValueStrFromJson(resConf->vipResConf.resName, CM_JSON_STR_LEN, resJson, "name") != 0) {
        rc = memset_s(resConf->vipResConf.resName, CM_JSON_STR_LEN, 0, CM_JSON_STR_LEN);
        securec_check_errno(rc, (void)rc);
    }
    if (GetValueStrFromJson(resConf->vipResConf.floatIp, CM_JSON_STR_LEN, resJson, "float_ip") != 0) {
        rc = memset_s(resConf->vipResConf.floatIp, CM_JSON_STR_LEN, 0, CM_JSON_STR_LEN);
        securec_check_errno(rc, (void)rc);
    }
    if (GetValueStrFromJson(resConf->vipResConf.cmd, CM_JSON_STR_LEN, resJson, "cmd") != 0) {
        rc = memset_s(resConf->vipResConf.cmd, CM_JSON_STR_LEN, 0, CM_JSON_STR_LEN);
        securec_check_errno(rc, (void)rc);
    }
    if (GetValueStrFromJson(resConf->vipResConf.netMask, CM_JSON_STR_LEN, resJson, "netMask") != 0) {
        rc = memset_s(resConf->vipResConf.netMask, CM_JSON_STR_LEN, 0, CM_JSON_STR_LEN);
        securec_check_errno(rc, (void)rc);
    }

    ParseAllBaseIp(resJson, &resConf->vipResConf);
}

static void ParseOneCusResConfJson(const cJSON *resItem, OneCusResConfJson *resConf)
{
    char resType[CM_JSON_STR_LEN] = {0};
    if (GetValueStrFromJson(resType, CM_JSON_STR_LEN, resItem, "resources_type") != 0) {
        CmJsonWriteLog(ERROR, "[ReadConfJson] unknown resources_type, can't parse current resource continue.\n");
        return;
    }

    size_t arrLen = sizeof(g_cusResMap) / sizeof(g_cusResMap[0]);
    for (size_t i = 0; i < arrLen; ++i) {
        if (strcmp(resType, g_cusResMap[i].resTypeName) == 0) {
            resConf->resType = g_cusResMap[i].resType;
            g_cusResMap[i].parseFunc(resItem, resConf);
        }
    }
}

static void ParseAllCusResConfJson(const cJSON *resArr, CmConfJson *cmConf)
{
    int arrLen = cJSON_GetArraySize(resArr);
    if (arrLen <= 0) {
        CmJsonWriteLog(ERROR, "[ReadConfJson] resource array size(%d) is invalid, can't parse continue.\n", arrLen);
        return;
    }

    cmConf->resource.count = (uint32)arrLen;
    cmConf->resource.conf = (OneCusResConfJson*)CmJsonMalloc((uint32)arrLen * sizeof(OneCusResConfJson));

    for (int i = 0; i < arrLen; ++i) {
        cJSON *resItem = cJSON_GetArrayItem(resArr, i);
        if (!cJSON_IsObject(resItem)) {
            CmJsonWriteLog(WARNING, "[ReadConfJson] index(%d) of res array is not an object.\n", i);
            continue;
        }
        ParseOneCusResConfJson(resItem, &cmConf->resource.conf[i]);
    }
}

void ParseRootJson(const cJSON *root, CmConfJson *cmConf)
{
    if (cmConf == NULL) {
        CmJsonWriteLog(WARNING, "[ReadConfJson] cmConf is null, can't do parse.\n");
        return;
    }
    if (root == NULL) {
        CmJsonWriteLog(WARNING, "[ReadConfJson] conf json is null, can't do parse.\n");
        return;
    }

    cJSON *resObj = cJSON_GetObjectItem(root, "resources");
    if (cJSON_IsArray(resObj)) {
        ParseAllCusResConfJson(resObj, cmConf);
    } else {
        CmJsonWriteLog(WARNING, "[ReadConfJson] \"resources\" obj is not an array.\n");
    }
}

int ReadConfJsonFile(const char *jsonFile)
{
    int readJsonErr = 0;
    cJSON *root = ReadJsonFile(jsonFile, &readJsonErr);
    if (readJsonErr != 0) {
        CmJsonWriteLog(LOG, "[ReadConfJson] read conf json:\"%s\" failed, err=%d.\n", jsonFile, readJsonErr);
        return readJsonErr;
    }

    if (g_confJson == NULL) {
        g_confJson = (CmConfJson*)CmJsonMalloc(sizeof(CmConfJson));
    }

    ParseRootJson(root, g_confJson);
    cJSON_Delete(root);

    return 0;
}

void SetReadJsonConfWriteLog(CmJsonLogOutput logFunc)
{
    if (logFunc != NULL) {
        CmJsonWriteLog = logFunc;
    }
}

bool IsConfJsonEmpty()
{
    return (g_confJson == NULL);
}

cJSON *ReadJsonFile(const char *jsonPath, int *err)
{
    FILE *fd = fopen(jsonPath, "r");
    if (fd == NULL) {
        if (errno == ENOENT) {
            CM_SET_READ_JSON_ERR(err, CM_JSON_NOT_EXIST);
            return NULL;
        }
        CM_SET_READ_JSON_ERR(err, CM_JSON_OPEN_ERROR);
        return NULL;
    }

    long size = (fseek(fd, 0, SEEK_END) == 0) ? ftell(fd) : 0;
    if (size <= 0) {
        CM_SET_READ_JSON_ERR(err, CM_JSON_GET_LEN_ERROR);
        (void)fclose(fd);
        return NULL;
    }

    // date in file maybe not end with \0, need add \0
    char *jsonData = (char*)malloc((size_t)(size + 1));
    if (jsonData == NULL) {
        CM_SET_READ_JSON_ERR(err, CM_JSON_OUT_OF_MEMORY);
        (void)fclose(fd);
        return NULL;
    }
    errno_t rc = memset_s(jsonData, (size_t)(size + 1), 0, (size_t)(size + 1));
    securec_check_errno(rc, (void)rc);

    if ((fseek(fd, 0, SEEK_SET) != 0) || (fread(jsonData, 1, (size_t)size, fd) == 0)) {
        CM_SET_READ_JSON_ERR(err, CM_JSON_READ_ERROR);
        FREE_AND_RESET(jsonData);
        (void)fclose(fd);
        return NULL;
    }

    cJSON *root = cJSON_Parse(jsonData);
    CM_SET_READ_JSON_ERR(err, 0);
    FREE_AND_RESET(jsonData);
    (void)fclose(fd);

    return root;
}
