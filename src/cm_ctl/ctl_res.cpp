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
* ctl_res.cpp
*    cm_ctl res --add
*    cm_ctl res --edit
*    cm_ctl res --del
*
* IDENTIFICATION
*    src/cm_ctl/ctl_res.cpp
*
* -------------------------------------------------------------------------
*/
#include "cjson/cJSON.h"

#include "ctl_res.h"

#include "c.h"
#include "cm_defs.h"

#include "cm_text.h"
#include "cm_json_config.h"

#include "ctl_common.h"
#include "ctl_res_list.h"

static char g_jsonFile[CM_PATH_LENGTH] = {0};
static char g_resNames[CM_MAX_RES_COUNT + CM_MAX_VIP_COUNT][CM_MAX_RES_NAME];
static uint32 g_resCount = 0;

// res
static const char *g_resSkipMap[] = {RES_NAME, RESOURCE_TYPE, INSTANCES};
static KvRestrict g_resKv[] = {{RES_KV_TYPE_STRING, RES_NAME},
    {RES_KV_TYPE_STRING, RESOURCE_TYPE},
    {RES_KV_TYPE_ARRAY, INSTANCES}};

// inst
static KvRestrict g_instKv[] = {{RES_KV_TYPE_INTEGER, INST_NODE_ID}, {RES_KV_TYPE_INTEGER, INST_RES_INST_ID}};
static KvRestrict g_instUniqueKey[] = {{RES_KV_TYPE_INTEGER, INST_RES_INST_ID}};
static const char *g_instCriticalKey[] = {INST_NODE_ID, INST_RES_INST_ID};

typedef status_t (*ProcessConfJson)(
    const ResOption *resCtx, cJSON *const confObj, ResOpMode mode, const char *key, const char *value);
typedef status_t (*OperateRes)(cJSON *resArray, const ResOption *resCtx);

typedef bool8 (*CjsonTypeCheck)(const ResOption *resCtx, const cJSON *objValue, const char *key);
typedef bool8 (*CjsonUniqueCheck)(
    const ResOption *resCtx, const cJSON *objValue, const cJSON *instArray, const char *key);
typedef status_t (*EditJson)(const ResOption *resCtx, cJSON *root, const char *key, const char *value, ResOpMode mode);

typedef void (*printRet)(int32 ret, const char *resName);

static const char *g_resOperStrMap[] = {
    [RES_OP_INIT] = "",
    [RES_OP_UNKNOWN] = "[RES_UNKNOWN]",
    [RES_OP_ADD] = "[RES_ADD]",
    [RES_OP_DEL] = "[RES_DEL]",
    [RES_OP_EDIT] = "[RES_EDIT]",
    [RES_OP_CHECK] = "[RES_CHECK]",
    [RES_OP_LIST] = "[RES_LIST]"
};

static const char *g_instOperStrMap[] = {
    [RES_OP_INIT] = "",
    [RES_OP_UNKNOWN] = "[INST_UNKNOWN]",
    [RES_OP_ADD] = "[INST_ADD]",
    [RES_OP_DEL] = "[INST_DEL]",
    [RES_OP_EDIT] = "[INST_EDIT]",
    [RES_OP_CHECK] = "[INST_CHECK]",
    [RES_OP_LIST] = "[INST_LIST]"
};

static ResTypeStr g_resTypeStrMap[] = {{RES_TYPE_APP, "APP"}, {RES_TYPE_DN, "DN"}, {RES_TYPE_VIP, "VIP"}};

static CjsonTypeCheck g_typeCheck[RES_KV_TYPE_CEIL];
static CjsonUniqueCheck g_uniqueCheck[RES_KV_TYPE_CEIL];
static EditJson g_editJson[RES_KV_TYPE_CEIL];

static OperateRes g_operResMap[RES_OP_CEIL];
static OperateRes g_operInstMap[RES_OP_CEIL];
static printRet g_printRet[RES_OP_CEIL];

static const char *const *GetOperPoint(ResLevel level)
{
    switch (level) {
        case RES_LEVEL_RES:
            return g_resOperStrMap;
        case RES_LEVEL_INST:
            return g_instOperStrMap;
        default:;
    }
    return NULL;
}

static const char *GetOperStr(ResOpMode opMode, ResLevel level = RES_LEVEL_RES)
{
    const char *const *map = GetOperPoint(level);
    if (map == NULL) {
        write_runlog(DEBUG1, "cannot find the oper point.\n");
        return "unknown";
    }
    if ((int32)opMode < 0 || opMode >= RES_OP_CEIL) {
        return map[RES_OP_UNKNOWN];
    }
    return map[opMode];
}

const char *GetResOperStr(ResOpMode opMode)
{
    return GetOperStr(opMode, RES_LEVEL_RES);
}

const char *GetInstOperStr(ResOpMode opMode)
{
    return GetOperStr(opMode, RES_LEVEL_INST);
}

static bool IsValueNumber(const char *value)
{
    if (value == NULL) {
        return false;
    }
    if (value[0] == '-') {
        if (strlen(value) > 1) {
            return (CM_is_str_all_digit(value + 1) == 0);
        }
        return false;
    }

    return (CM_is_str_all_digit(value) == 0);
}

static status_t CreateEmptyJsonFile(const char *fileName)
{
    char newFileName[MAX_PATH_LEN] = {0};
    int ret = snprintf_s(newFileName, MAX_PATH_LEN, MAX_PATH_LEN, "%s", fileName);
    securec_check_intval(ret, (void)ret);
    
    FILE *fp = fopen(newFileName, "a");
    if (fp == NULL) {
        write_runlog(ERROR, "create file \"%s\" failed, errno is %s.\n", newFileName, gs_strerror(errno));
        return CM_ERROR;
    }

    (void)fclose(fp);

    if (chmod(newFileName, S_IRUSR | S_IWUSR) == -1) {
        write_runlog(ERROR, "chmod file \"%s\" failed.\n", newFileName);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static status_t WriteJsonFile(const cJSON *root, char *jsonPath)
{
    FILE *fp = fopen(jsonPath, "w+");
    if (fp == NULL) {
        CM_RETURN_IFERR(CreateEmptyJsonFile(jsonPath));
        fp = fopen(jsonPath, "w+");
        if (fp == NULL) {
            write_runlog(ERROR, "could not open file \"%s\". errno is %s \n", jsonPath, gs_strerror(errno));
            return CM_ERROR;
        }
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        (void)fclose(fp);
        return CM_ERROR;
    }
    char *jsonStr = cJSON_Print(root);
    CM_RETERR_IF_NULL_EX(jsonStr, (void)fclose(fp));
    size_t jsonStrLen = strlen(jsonStr);
    write_runlog(DEBUG1, "new res conf json str len is (%zu).\n", jsonStrLen);
    if (fwrite(jsonStr, jsonStrLen, 1, fp) != 1) {
        write_runlog(ERROR, "could not write file \"%s\": %s.\n", jsonPath, gs_strerror(errno));
        (void)fclose(fp);
        cJSON_free(jsonStr);
        return CM_ERROR;
    }
    cJSON_free(jsonStr);
    
    if (fsync(fileno(fp)) != 0) {
        write_runlog(ERROR, "could not fsync file \"%s\": %s.\n", jsonPath, gs_strerror(errno));
        (void)fclose(fp);
        return CM_ERROR;
    }
    
    (void)fclose(fp);
    return CM_SUCCESS;
}

static status_t SplitKeyAndValue(
    const ResOption *resCtx, cJSON *obj, char *str, ResOpMode opMode, ProcessConfJson processFuc)
{
    CmTrimStr(str);
    if (CM_IS_EMPTY_STR(str)) {
        write_runlog(WARNING, "%s%s Res(%s) res_attr exist null kv pair, please check.\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName);
        return CM_SUCCESS;
    }
    char *value = NULL;
    char *key = strtok_r(str, KEY_VALUE_SPLIT_ARRAY, &value);
    CmTrimStr(key);
    CmTrimStr(value);
    if (CM_IS_EMPTY_STR(key) || (opMode != RES_OP_EDIT && CM_IS_EMPTY_STR(value))) {
        write_runlog(ERROR, "%s%s Res(%s) res_attr irregular, key or value may be empty, please check.\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName);
        return CM_ERROR;
    }
    return processFuc(resCtx, obj, opMode, key, value);
}

static status_t SplitResAttr(const ResOption *resCtx, cJSON *obj, char *resAttr, ResOpMode opMode, ProcessConfJson fuc)
{
    char *left = NULL;
    char *oneAttr = strtok_r(resAttr, SEPARATOR_ARRAY, &left);
    CM_RETURN_IFERR(SplitKeyAndValue(resCtx, obj, oneAttr, opMode, fuc));
    while (!CM_IS_EMPTY_STR(left)) {
        oneAttr = strtok_r(NULL, SEPARATOR_ARRAY, &left);
        CM_RETURN_IFERR(SplitKeyAndValue(resCtx, obj, oneAttr, opMode, fuc));
    }

    return CM_SUCCESS;
}

static ResKvType GetResKvTypeByKey(ResLevel level, const char *key)
{
    KvRestrict *kv = NULL;
    uint32 len = 0;
    if (level == RES_LEVEL_RES) {
        kv = g_resKv;
        len = ELEMENT_COUNT(g_resKv);
    } else if (level == RES_LEVEL_INST) {
        kv = g_instKv;
        len = ELEMENT_COUNT(g_instKv);
    }
    if (kv == NULL || len == 0) {
        return RES_KV_TYPE_OBJECT;
    }
    for (uint32 i = 0; i < len; ++i) {
        if (cm_str_equal(kv[i].key, key)) {
            return kv[i].type;
        }
    }
    return RES_KV_TYPE_OBJECT;
}

static EditJson GetEditJson(const ResOption *resCtx, ResLevel level, const char *key, const char *value)
{
    ResKvType type = GetResKvTypeByKey(level, key);
    if (type < RES_KV_TYPE_INIT || type >= RES_KV_TYPE_CEIL) {
        write_runlog(ERROR, "%s%s Res(%s) fails to edit item to Object, when key=[%s], value=[%s].\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName, key, value);
        return NULL;
    }
    EditJson add2Json = g_editJson[type];
    if (add2Json == NULL) {
        write_runlog(ERROR, "%s%s Res(%s) fails to edit item to Object, when key=[%s], value=[%s], add2Json is NULL.\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName, key, value);
        return NULL;
    }
    return add2Json;
}

static status_t AddItemToObject(
    const ResOption *resCtx, cJSON *const confObj, const char *key, const char *value, ResLevel level)
{
    cJSON *obj = cJSON_GetObjectItem(confObj, key);
    if (obj != NULL) {
        write_runlog(ERROR, "%s%s key(%s) may has exited in Res(%s).\n", GetResOperStr(resCtx->mode),
            GetInstOperStr(resCtx->inst.mode), key, resCtx->resName);
        return CM_ERROR;
    }

    EditJson add2Json = GetEditJson(resCtx, level, key, value);
    if (add2Json == NULL) {
        return CM_ERROR;
    }
    return add2Json(resCtx, confObj, key, value, RES_OP_ADD);
}

static status_t ReplaceItemInObject(
    const ResOption *resCtx, cJSON *const confObj, const char *key, const char *value, ResLevel level)
{
    cJSON *obj = cJSON_GetObjectItem(confObj, key);
    if (obj == NULL) {
        write_runlog(DEBUG1, "%s%s key(%s) may hasn't exited in Res(%s).\n", GetResOperStr(resCtx->mode),
            GetInstOperStr(resCtx->inst.mode), key, resCtx->resName);
        return AddItemToObject(resCtx, confObj, key, value, level);
    }
    EditJson add2Json = GetEditJson(resCtx, level, key, value);
    if (add2Json == NULL) {
        return CM_ERROR;
    }
    return add2Json(resCtx, confObj, key, value, RES_OP_EDIT);
}

static status_t EditArrayToJson(
    const ResOption *resCtx, cJSON *root, const char *key, const char *value, ResOpMode mode)
{
    if (CM_IS_EMPTY_STR(key)) {
        write_runlog(ERROR, "%s%s Res(%s) fails to add array to json, when key is empty.\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName);
        return CM_ERROR;
    }
    if (mode != RES_OP_EDIT) {
        (void)cJSON_AddArrayToObject(root, key);
        return CM_SUCCESS;
    } else {
        write_runlog(ERROR, "%s%s Res(%s) fails to edit array to json, when mode is replace.\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName);
        return CM_ERROR;
    }
}

status_t ProcessResAttrConfJson(
    const ResOption *resCtx, cJSON *const confObj, ResOpMode mode, const char *key, const char *value)
{
    CM_RETURN_IFERR(AddItemToObject(resCtx, confObj, key, value, RES_LEVEL_RES));
    uint32 index;
    if (cm_str_equal(key, RESOURCE_TYPE)) {
        if (!CompareResType(value, &index)) {
            write_runlog(ERROR, "%s%s Res(%s) attr %s can not be set to %s.\n", GetResOperStr(resCtx->mode),
                GetInstOperStr(resCtx->inst.mode), resCtx->resName, RESOURCE_TYPE, value);
        return CM_ERROR;
        }
        if (GetResTypeValue(index) == NULL) {
            return CM_SUCCESS;
        }
        return EditArrayToJson(resCtx, confObj, GetResTypeValue(index), NULL, mode);
    }
    return CM_SUCCESS;
}

cJSON *ParseResAttr(const ResOption *resCtx, const char *resName, char *resAttr)
{
    cJSON *resObj = cJSON_CreateObject();
    if (!cJSON_IsObject(resObj)) {
        write_runlog(ERROR, "%s Res(%s) create new res json obj failed, add res failed.\n",
            GetResOperStr(resCtx->mode), resName);
        cJSON_Delete(resObj);
        return NULL;
    }
    if (cJSON_AddStringToObject(resObj, RES_NAME, resName) == NULL) {
        write_runlog(ERROR, "%s Res(%s) add name info to new res json obj failed, add res failed.\n",
            GetResOperStr(resCtx->mode), resName);
        cJSON_Delete(resObj);
        return NULL;
    }
    if (SplitResAttr(resCtx, resObj, resAttr, resCtx->mode, ProcessResAttrConfJson) != CM_SUCCESS) {
        write_runlog(ERROR, "%s Res(%s) parse res attr failed, add res failed.\n",
            GetResOperStr(resCtx->mode), resName);
        cJSON_Delete(resObj);
        return NULL;
    }
    return resObj;
}

static cJSON *CreateNewResJsonObj()
{
    cJSON *root = cJSON_CreateObject();
    if (!cJSON_IsObject(root)) {
        write_runlog(ERROR, "create new res json obj failed.\n");
        cJSON_Delete(root);
        return NULL;
    }
    cJSON *resArray = cJSON_AddArrayToObject(root, RESOURCES);
    if (!cJSON_IsArray(resArray)) {
        write_runlog(ERROR, "create new res json array failed.\n");
        cJSON_Delete(root);
        return NULL;
    }
    return root;
}

static status_t AddNewResToJsonObj(cJSON *const resArray, cJSON *newRes)
{
    CM_RETURN_IF_FALSE(cJSON_IsObject(newRes));
    if (!cJSON_IsArray(resArray)) {
        write_runlog(ERROR, "json obj in \"%s\" incorrect format.\n", g_jsonFile);
        return CM_ERROR;
    }

    if (!cJSON_AddItemToArray(resArray, newRes)) {
        write_runlog(ERROR, "add new res info to json failed.\n");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static cJSON *GetResJsonFromFile(const char *jsonFile, bool canCreateFile)
{
    int err = 0;
    cJSON *root = ReadJsonFile(jsonFile, &err);
    if (!cJSON_IsObject(root)) {
        if (root != NULL) {
            cJSON_Delete(root);
        }
        if (canCreateFile) {
            root = CreateNewResJsonObj();
        } else {
            write_runlog(ERROR, "read res conf json \"%s\" failed, err=%d.\n", jsonFile, err);
            root = NULL;
        }
    }
    return root;
}

int GetValueIntFromCJson(const cJSON *object, const char *infoKey, int32 logLevel)
{
    cJSON *objValue = cJSON_GetObjectItem(object, infoKey);
    if (!cJSON_IsNumber(objValue)) {
        write_runlog(logLevel, "(%s) object is not number.\n", infoKey);
        return -1;
    }
    if (objValue->valueint < 0) {
        write_runlog(logLevel, "get invalid objValue(%d) from cJson, by key(%s).\n", objValue->valueint, infoKey);
        return -1;
    }
    return objValue->valueint;
}

char *GetValueStrFromCJson(const cJSON *object, const char *infoKey, int32 logLevel)
{
    cJSON *objValue = cJSON_GetObjectItem(object, infoKey);
    if (!cJSON_IsString(objValue)) {
        write_runlog(logLevel, "(%s) object is not string.\n", infoKey);
        return NULL;
    }
    if (CM_IS_EMPTY_STR(objValue->valuestring)) {
        write_runlog(logLevel, "(%s) object is null.\n", infoKey);
        return NULL;
    }
    check_input_for_security(objValue->valuestring);
    return objValue->valuestring;
}

cJSON *GetArrayFromObj(const cJSON *obj, const char *arrName)
{
    cJSON *array = cJSON_GetObjectItem(obj, arrName);
    if (!cJSON_IsArray(array)) {
        write_runlog(ERROR, "\"%s\" not exit array: %s.\n", g_jsonFile, arrName);
        return NULL;
    }
    return array;
}

cJSON *GetResFromArray(cJSON *resArray, const char *resName)
{
    cJSON *resItem;
    cJSON_ArrayForEach(resItem, resArray) {
        char *valueStr = GetValueStrFromCJson(resItem, RES_NAME);
        if (valueStr == NULL) {
            continue;
        }
        if (cm_str_equal(valueStr, resName)) {
            break;
        }
    }
    if (resItem == NULL) {
        write_runlog(ERROR, "no res(%s) info in \"%s\".\n", resName, g_jsonFile);
    }
    
    return resItem;
}

// command: cm_ctl res --check
static status_t CheckResInJson(cJSON *resArray, const ResOption *resCtx)
{
    return CheckResFromArray(resArray);
}

static bool8 CheckParam(const ResOption *resCtx)
{
    if (CM_IS_EMPTY_STR(resCtx->resName)) {
        write_runlog(
            ERROR, "%s%s resName is NULL.\n", GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode));
        return CM_FALSE;
    }
    return CM_TRUE;
}

static bool8 CheckAddResParam(const ResOption *resCtx)
{
    CM_RETFALSE_IFNOT(CheckParam(resCtx));
    if (resCtx->resAttr != NULL && resCtx->resAttr[0] == '\0') {
        write_runlog(ERROR, "%s Res(%s)'s resAttr is empty.\n", GetResOperStr(resCtx->mode), resCtx->resName);
        return CM_FALSE;
    }
    return CM_TRUE;
}

cJSON *GetCurResInArray(cJSON *resArray, const char *resName, const ResOption *resCtx, int32 *resIdx)
{
    if (!cJSON_IsArray(resArray)) {
        write_runlog(ERROR, "%s%s Res(%s) cannot find resource from JsonFile.\n", GetResOperStr(resCtx->mode),
            GetInstOperStr(resCtx->inst.mode), resName);
        return NULL;
    }

    cJSON *resObj;
    const uint32 maxResCnt = CM_MAX_RES_COUNT + CM_MAX_VIP_COUNT;
    //char resName[maxResCnt][CM_MAX_RES_NAME];
    g_resCount = 0;
    int32 resIndex = -1;
    int32 arraySize = cJSON_GetArraySize(resArray);
    for (int32 i = 0; i < arraySize; ++i) {
        resObj = cJSON_GetArrayItem(resArray, i);
        if (!cJSON_IsObject(resObj)) {
            continue;
        }
        const char* tmpResName;
        if(CheckResName(resObj, g_resNames, maxResCnt, &g_resCount, &tmpResName) != CM_SUCCESS) {
            write_runlog(ERROR, "%s%s Res(%s) configure contains some error, check first.\n", GetResOperStr(resCtx->mode),
                GetInstOperStr(resCtx->inst.mode), resName);
            return NULL;
        }

        if (tmpResName != NULL && cm_str_equal(tmpResName, resName)) {
            resIndex = i;
            if (resIdx != NULL) {
                *resIdx = i;
            }
        }
    }

    if (resIndex != -1) {
        return cJSON_GetArrayItem(resArray, resIndex);
    }
    return NULL;
}

static bool8 ResKvTypeCheck(const ResOption *resCtx, const cJSON *resItem, const char *key, ResKvType type)
{
    if (type < RES_KV_TYPE_INIT || type >= RES_KV_TYPE_CEIL) {
        return g_typeCheck[RES_KV_TYPE_OBJECT](resCtx, resItem, key);
    }
    CjsonTypeCheck check = g_typeCheck[type];
    if (check == NULL) {
        return g_typeCheck[RES_KV_TYPE_OBJECT](resCtx, resItem, key);
    }
    return check(resCtx, resItem, key);
}

static bool8 CheckKvTypeValid(
    const ResOption *resCtx, const cJSON *resItem, const KvRestrict *kvRes, uint32 kvLen, const char *key)
{
    if (CM_IS_EMPTY_STR(key)) {
        write_runlog(ERROR, "%s%s Res(%s) cannot check kv type, when key is empty.\n", GetResOperStr(resCtx->mode),
            GetInstOperStr(resCtx->inst.mode), resCtx->resName);
        return CM_FALSE;
    }

    for (uint32 i = 0; i < kvLen; ++i) {
        if (cm_str_equal(kvRes[i].key, key)) {
            return ResKvTypeCheck(resCtx, resItem, key, kvRes[i].type);
        }
    }
    return ResKvTypeCheck(resCtx, resItem, key, RES_KV_TYPE_OBJECT);
}

ResType GetResTypeInJson(const ResOption *resCtx, const cJSON *resObj)
{
    if (!cJSON_IsObject(resObj)) {
        write_runlog(DEBUG1, "%s%s Res(%s) cannot find the resType in json, when resObj is not object.\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName);
        return RES_TYPE_UNKNOWN;
    }
    const char *value = GetValueStrFromCJson(resObj, RESOURCE_TYPE);
    if (CM_IS_EMPTY_STR(value)) {
        write_runlog(DEBUG1, "%s%s Res(%s) cannot find the resType in json, when value is empty.\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName);
        return RES_TYPE_UNKNOWN;
    }
    uint32 len = ELEMENT_COUNT(g_resTypeStrMap);
    for (uint32 i = 0; i < len; ++i) {
        if (cm_str_equal(value, g_resTypeStrMap[i].str)) {
            return g_resTypeStrMap[i].type;
        }
    }
    return RES_TYPE_UNKNOWN;
}

static bool8 IsCurResCheckInstances(const ResOption *resCtx, const cJSON *resObj)
{
    ResType type = GetResTypeInJson(resCtx, resObj);
    return IsResCheckInstances(type);
}

static status_t CheckResJsonInAdd(const ResOption *resCtx, const cJSON *resObj, const char *resName)
{
    uint32 len = ELEMENT_COUNT(g_resKv);
    const cJSON *resItem;
    bool8 isCheckInstances = IsCurResCheckInstances(resCtx, resObj);
    for (uint32 i = 0; i < len; ++i) {
        if (!isCheckInstances && cm_str_equal(g_resKv[i].key, INSTANCES)) {
            continue;
        }
        resItem = cJSON_GetObjectItem(resObj, g_resKv[i].key);
        if (!CheckKvTypeValid(resCtx, resItem, g_resKv, len, g_resKv[i].key)) {
            write_runlog(ERROR, "%s%s Res(%s) cannot find the item(%s).\n", GetResOperStr(resCtx->mode),
                GetInstOperStr(resCtx->inst.mode), resCtx->resName, g_resKv[i].key);
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

static status_t AddResToJson(cJSON *resArray, const ResOption *resCtx)
{
    if (!CheckAddResParam(resCtx)) {
        return CM_ERROR;
    }
    const char *str = GetResOperStr(resCtx->mode);
    cJSON *resObj = GetCurResInArray(resArray, resCtx->resName, resCtx);
    if (resObj != NULL) {
        write_runlog(ERROR, "%s Res(%s) may be existed in json.\n", str, resCtx->resName);
        return CM_ERROR;
    }
    cJSON *newRes = ParseResAttr(resCtx, resCtx->resName, resCtx->resAttr);
    CM_RETERR_IF_NULL(newRes);
    CM_RETURN_IFERR_EX(CheckResJsonInAdd(resCtx, newRes, resCtx->resName), cJSON_Delete(newRes));
    CM_RETURN_IFERR_EX(AddNewResToJsonObj(resArray, newRes), cJSON_Delete(newRes));
    return CM_SUCCESS;
}

static status_t DelResInJson(cJSON *resArray, const ResOption *resCtx)
{
    const char *str = GetResOperStr(resCtx->mode);
    CM_RETURN_IF_FALSE(CheckParam(resCtx));
    int32 resIdx;
    cJSON *resObj = GetCurResInArray(resArray, resCtx->resName, resCtx, &resIdx);
    if (resObj == NULL) {
        write_runlog(ERROR, "%s Res(%s) may be not existed in json.\n", str, resCtx->resName);
        return CM_ERROR;
    }
    cJSON_DeleteItemFromArray(resArray, resIdx);
    return CM_SUCCESS;
}

static void TrimAllRes(ResOption *resCtx)
{
    CmTrimStr(resCtx->resName);
    CmTrimStr(resCtx->resAttr);
    CmTrimStr(resCtx->inst.instName);
    CmTrimStr(resCtx->inst.instAttr);
}

static status_t DelItemInObjectByKey(
    const ResOption *resCtx, cJSON *const confObj, const char *key, const char **skipMap, uint32 mapLen)
{
    if (CM_IS_EMPTY_STR(key)) {
        return CM_SUCCESS;
    }
    for (uint32 i = 0; i < mapLen; ++i) {
        if (cm_str_equal(key, skipMap[i])) {
            write_runlog(ERROR, "%s%s Res(%s) cannot del the item(%s).\n", GetResOperStr(resCtx->mode),
                GetInstOperStr(resCtx->inst.mode), resCtx->resName, key);
            return CM_ERROR;
        }
    }
    cJSON_DeleteItemFromObject(confObj, key);
    return CM_SUCCESS;
}

static status_t EditResAttrConfJson(
    const ResOption *resCtx, cJSON *const confObj, ResOpMode mode, const char *key, const char *value)
{
    if (CM_IS_EMPTY_STR(value)) {
        return DelItemInObjectByKey(resCtx, confObj, key, g_resSkipMap, ELEMENT_COUNT(g_resSkipMap));
    }
    if (mode != RES_OP_EDIT) {
        return AddItemToObject(resCtx, confObj, key, value, RES_LEVEL_RES);
    } else {
        return ReplaceItemInObject(resCtx, confObj, key, value, RES_LEVEL_RES);
    }
}

static status_t EditResAddr(cJSON *resObj, const ResOption *resCtx)
{
    if (CM_IS_EMPTY_STR(resCtx->resAttr)) {
        return CM_SUCCESS;
    }
    if (SplitResAttr(resCtx, resObj, resCtx->resAttr, resCtx->mode, EditResAttrConfJson) != CM_SUCCESS) {
        write_runlog(ERROR, "%s%s Res(%s) failed to edit res addr.\n", GetOperStr(resCtx->mode),
            GetInstOperStr(resCtx->inst.mode), resCtx->resName);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static bool8 CheckEditParam(const ResOption *resCtx)
{
    CM_RETFALSE_IFNOT(CheckParam(resCtx));
    if (CM_IS_EMPTY_STR(resCtx->resAttr) && CM_IS_EMPTY_STR(resCtx->inst.instName)) {
        write_runlog(ERROR, "%s%s Res(%s) failed to edit res, when resAtrr is NULL, and inst is NULL.\n",
            GetOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName);
        return CM_FALSE;
    }
    return CM_TRUE;
}

static status_t GetInstanceArray(cJSON **instArray, const ResOption *resCtx, cJSON *resObj)
{
    if (IsCurNotCheckInstances(resCtx, resObj)) {
        return CM_SUCCESS;
    }
    cJSON *tempInstArray = cJSON_GetObjectItem(resObj, INSTANCES);
    if (tempInstArray != NULL) {
        if (!cJSON_IsArray(tempInstArray)) {
            write_runlog(ERROR, "%s%s Res(%s) cannot find the array(%s).\n", GetResOperStr(resCtx->mode),
                GetInstOperStr(resCtx->inst.mode), resCtx->resName, INSTANCES);
            return CM_ERROR;
        } else {
            *instArray = tempInstArray;
            return CM_SUCCESS;
        }
    }
    if (EditArrayToJson(resCtx, resObj, INSTANCES, NULL, RES_OP_ADD) != CM_SUCCESS) {
        return CM_ERROR;
    }
    tempInstArray = cJSON_GetObjectItem(resObj, INSTANCES);
    if (!cJSON_IsArray(tempInstArray)) {
        write_runlog(ERROR, "%s%s Res(%s) cannot get the array(%s) from json.\n", GetResOperStr(resCtx->mode),
            GetInstOperStr(resCtx->inst.mode), resCtx->resName, INSTANCES);
        return CM_ERROR;
    }
    *instArray = tempInstArray;
    return CM_SUCCESS;
}

static status_t EditResInJson(cJSON *resArray, const ResOption *resCtx)
{
    const char *editStr = GetResOperStr(resCtx->mode);
    const char *instStr = GetInstOperStr(resCtx->inst.mode);
    CM_RETURN_IF_FALSE(CheckEditParam(resCtx));
    cJSON *resObj = GetCurResInArray(resArray, resCtx->resName, resCtx, NULL);
    if (resObj == NULL) {
        write_runlog(ERROR, "%s%s Res(%s) may be not existed in json.\n", editStr, instStr, resCtx->resName);
        return CM_ERROR;
    }
    CM_RETURN_IFERR(EditResAddr(resObj, resCtx));
    if (CM_IS_EMPTY_STR(resCtx->inst.instName)) {
        write_runlog(DEBUG1, "%s%s Res(%s) inst may be empty.\n", GetResOperStr(resCtx->mode),
            GetInstOperStr(resCtx->inst.mode), resCtx->resName);
        return CM_SUCCESS;
    }
    if (resCtx->inst.mode < RES_OP_INIT || resCtx->inst.mode >= RES_OP_CEIL) {
        write_runlog(ERROR, "%s Res(%s) instMode(%d) is unknown.\n", GetResOperStr(resCtx->mode), resCtx->resName,
            (int32)resCtx->inst.mode);
        return CM_ERROR;
    }
    OperateRes operInstMap = g_operInstMap[resCtx->inst.mode];
    if (operInstMap == NULL) {
        write_runlog(ERROR, "%s Res(%s) instMode%s may not supprot.\n", GetResOperStr(resCtx->mode), resCtx->resName,
            GetInstOperStr(resCtx->inst.mode));
        return CM_ERROR;
    }
    cJSON *instArray = NULL;
    if (GetInstanceArray(&instArray, resCtx, resObj) != CM_SUCCESS) {
        write_runlog(ERROR, "%s%s Res(%s) cannot find the array(%s).\n", GetResOperStr(resCtx->mode),
            GetInstOperStr(resCtx->inst.mode), resCtx->resName, INSTANCES);
        return CM_ERROR;
    }
    return operInstMap(instArray, resCtx);
}

static bool8 CheckInstParam(const ResOption *resCtx)
{
    if (CM_IS_EMPTY_STR(resCtx->inst.instName)) {
        write_runlog(ERROR, "%s%s Res(%s) inst is empty.\n", GetResOperStr(resCtx->mode),
            GetInstOperStr(resCtx->inst.mode), resCtx->resName);
        return CM_FALSE;
    }
    return CM_TRUE;
}

static bool8 IsUniqueKey(const KvRestrict *uniqueKey, uint32 len, const char *key)
{
    for (uint32 i = 0; i < len; ++i) {
        if (cm_str_equal(uniqueKey[i].key, key)) {
            return CM_TRUE;
        }
    }
    return CM_FALSE;
}

static status_t EditInstAttrConfJson(
    const ResOption *resCtx, cJSON *const confObj, ResOpMode mode, const char *key, const char *value)
{
    if (CM_IS_EMPTY_STR(value)) {
        return DelItemInObjectByKey(resCtx, confObj, key, g_instCriticalKey, ELEMENT_COUNT(g_instCriticalKey));
    }
    if (mode != RES_OP_EDIT) {
        return AddItemToObject(resCtx, confObj, key, value, RES_LEVEL_INST);
    } else {
        if (IsUniqueKey(g_instUniqueKey, ELEMENT_COUNT(g_instUniqueKey), key)) {
            return CM_SUCCESS;
        }
        return ReplaceItemInObject(resCtx, confObj, key, value, RES_LEVEL_INST);
    }
}

static bool8 CheckUniqueInArray(
    const ResOption *resCtx, const cJSON *resArray, const cJSON *resObj, const char *key, ResKvType type)
{
    if (CM_IS_EMPTY_STR(key)) {
        write_runlog(ERROR, "%s%s Res(%s) cannot check unique, when key is empty.\n", GetResOperStr(resCtx->mode),
            GetInstOperStr(resCtx->inst.mode), resCtx->resName);
        return CM_FALSE;
    }
    if (type < RES_KV_TYPE_INIT || type >= RES_KV_TYPE_CEIL) {
        write_runlog(ERROR, "%s%s Res(%s) cannot check unique, when type is %d.\n", GetResOperStr(resCtx->mode),
            GetInstOperStr(resCtx->inst.mode), resCtx->resName, (int32)type);
        return CM_FALSE;
    }

    CjsonUniqueCheck check = g_uniqueCheck[type];
    if (check == NULL) {
        write_runlog(ERROR, "%s%s Res(%s) cannot check unique, when type=%d, and check is NULL.\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName, (int32)type);
        return CM_FALSE;
    }
    return check(resCtx, resObj, resArray, key);
}

static status_t CheckCjsonObjInAdd(const ResOption *resCtx, const cJSON *resArray, const cJSON *resObj)
{
    uint32 len = ELEMENT_COUNT(g_instCriticalKey);
    const cJSON *resItem;
    for (uint32 i = 0; i < len; ++i) {
        resItem = cJSON_GetObjectItem(resObj, g_instCriticalKey[i]);
        if (!CheckKvTypeValid(resCtx, resItem, g_instKv, ELEMENT_COUNT(g_instKv), g_instCriticalKey[i])) {
            write_runlog(ERROR, "%s%s Res(%s) cannot find the item(%s).\n", GetResOperStr(resCtx->mode),
                GetInstOperStr(resCtx->inst.mode), resCtx->resName, g_instCriticalKey[i]);
            return CM_ERROR;
        }
    }
    len = ELEMENT_COUNT(g_instUniqueKey);
    for (uint32 i = 0; i < len; ++i) {
        if (!CheckUniqueInArray(resCtx, resArray, resObj, g_instUniqueKey[i].key, g_instUniqueKey[i].type)) {
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

status_t GetIntFromText(const ResOption *resCtx, const char *str, const char *expectValue, int32 *value, int32 logLevel)
{
    const char *point = strstr(str, expectValue);
    if (point == NULL) {
        write_runlog(logLevel, "%s%s Res(%s) failed to get %s from text, when %s doesn't exist in inst.\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName, expectValue, expectValue);
        return CM_ERROR;
    }
    char valueStr[MAX_PATH_LEN] = {0};
    if (FetchStrFromText(point, valueStr, MAX_PATH_LEN, '=') != 0) {
        write_runlog(logLevel, "%s%s Res(%s) failed to get %s from text, when %s cannot be find in inst.\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName, expectValue, expectValue);
        return CM_ERROR;
    }
    if (!IsValueNumber(valueStr)) {
        write_runlog(logLevel, "%s%s Res(%s) failed to get %s from text, when %s may be not integer.\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName, expectValue, expectValue);
        return CM_ERROR;
    }
    *value = CmAtoi(valueStr, -1);
    return CM_SUCCESS;
}

static status_t FindInstIdInInstName(const ResOption *resCtx, ResInstInfo *instInfo)
{
    instInfo->instId = -1;
    instInfo->nodeId = -1;

    if (CM_IS_EMPTY_STR(resCtx->inst.instName)) {
        write_runlog(ERROR, "%s%s Res(%s) failed to get inst from array, when inst is NULL.\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName);
        return CM_ERROR;
    }

    CM_RETURN_IFERR(GetIntFromText(resCtx, resCtx->inst.instName, INST_RES_INST_ID, &instInfo->instId, ERROR));

    if (strstr(resCtx->inst.instName, INST_NODE_ID) != NULL) {
        CM_RETURN_IFERR(GetIntFromText(resCtx, resCtx->inst.instName, INST_NODE_ID, &instInfo->nodeId, DEBUG1));
        if (instInfo->instId == -1) {
            write_runlog(ERROR, "%s%s Res(%s) failed to get instId from array, when instId is invalid.\n",
                GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName);
            return CM_ERROR;
        }
    }
    write_runlog(DEBUG1, "%s%s Res(%s) success to get nodeId(%d), instId(%d).\n", GetResOperStr(resCtx->mode),
        GetInstOperStr(resCtx->inst.mode), resCtx->resName, instInfo->nodeId, instInfo->instId);
    return CM_SUCCESS;
}

static cJSON *GetInstFromArray(const ResOption *resCtx, const cJSON *resArray, int32 *index)
{
    if (CM_IS_EMPTY_STR(resCtx->inst.instName)) {
        write_runlog(ERROR, "%s%s Res(%s) failed to get inst from array, when inst is NULL.\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName);
        return NULL;
    }
    ResInstInfo instInfo;
    if (FindInstIdInInstName(resCtx, &instInfo) != CM_SUCCESS) {
        return NULL;
    }
    cJSON *resObj;
    int32 instId;
    int32 nodeId;
    int32 arraySize = cJSON_GetArraySize(resArray);
    for (int32 i = 0; i < arraySize; ++i) {
        resObj = cJSON_GetArrayItem(resArray, i);
        if (!cJSON_IsObject(resObj)) {
            continue;
        }
        instId = GetValueIntFromCJson(resObj, INST_RES_INST_ID);
        nodeId = GetValueIntFromCJson(resObj, INST_NODE_ID);
        if (instId != instInfo.instId) {
            continue;
        }
        if ((instInfo.nodeId != -1 && instInfo.nodeId == nodeId) || (instInfo.nodeId == -1)) {
            if (index != NULL) {
                *index = i;
            }
            return resObj;
        }
    }
    return NULL;
}

static bool CheckResNameForEdit(const char *value)
{
    if (strlen(value) >= CM_MAX_RES_NAME) {
        write_runlog(ERROR, "resource's new name(%s) length exceeds the maximum(%d).\n", value, CM_MAX_RES_NAME);
        return false;
    }
    for (uint32 i = 0; i < g_resCount; i++) {
        if (strcmp(value, g_resNames[i]) == 0) {
            write_runlog(ERROR, "resource's new name(%s) has already exist in configure.\n", value);
            return false;
        }
    }
    return true;
}

static status_t EditStringToJson(
    const ResOption *resCtx, cJSON *root, const char *key, const char *value, ResOpMode mode)
{
    if (CM_IS_EMPTY_STR(key) || CM_IS_EMPTY_STR(value)) {
        write_runlog(ERROR, "%s%s Res(%s) fails to edit string to json, when key or value is empty.\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName);
        return CM_ERROR;
    }
    check_input_for_security(value);
    if (mode != RES_OP_EDIT) {
        (void)cJSON_AddStringToObject(root, key, value);
    } else {
        uint32 index = 0;
        if (cm_str_equal(key, RES_NAME) && !CheckResNameForEdit(value)) {
            write_runlog(ERROR, "%s%s Res(%s) fails to edit new name to json.\n",
                GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName);
            return CM_ERROR;
        }
        if (cm_str_equal(key, RESOURCE_TYPE) && !CompareResType(value, &index)) {
            write_runlog(ERROR, "%s%s Res(%s) fails to edit new resource_type to json.\n",
                GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName);
            return CM_ERROR;
        }
        (void)cJSON_ReplaceItemInObject(root, key, cJSON_CreateString(value));
    }
    return CM_SUCCESS;
}

static status_t SetInstAttrToJson(const ResOption *resCtx, cJSON *resObj, ResOpMode mode)
{
    if (resCtx->inst.instAttr == NULL) {
        return CM_SUCCESS;
    }
    if (resCtx->inst.instAttr[0] == '\0') {
        cJSON_DeleteItemFromObject(resObj, INST_ATTR);
    } else {
        return EditStringToJson(resCtx, resObj, INST_ATTR, resCtx->inst.instAttr, mode);
    }
    return CM_SUCCESS;
}

static status_t AddInstToJson(cJSON *resArray, const ResOption *resCtx)
{
    CM_RETURN_IF_FALSE(CheckInstParam(resCtx));
    if (GetInstFromArray(resCtx, resArray, NULL) != NULL) {
        write_runlog(ERROR, "%s%s Res(%s) failed to add inst to json, when inst in json.\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName);
        return CM_ERROR;
    }

    cJSON *resObj = cJSON_CreateObject();
    if (SplitResAttr(resCtx, resObj, resCtx->inst.instName, resCtx->inst.mode, EditInstAttrConfJson) !=
        CM_SUCCESS) {
        write_runlog(ERROR, "%s%s Res(%s) failed to add inst to json.\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName);
        cJSON_Delete(resObj);
        return CM_ERROR;
    }

    if (SetInstAttrToJson(resCtx, resObj, RES_OP_ADD) != CM_SUCCESS) {
        write_runlog(ERROR, "%s%s Res(%s) failed to add %s to json.\n", GetResOperStr(resCtx->mode),
            GetInstOperStr(resCtx->inst.mode), resCtx->resName, INST_ATTR);
        cJSON_Delete(resObj);
        return CM_ERROR;
    }

    if (CheckCjsonObjInAdd(resCtx, resArray, resObj) != CM_SUCCESS) {
        cJSON_Delete(resObj);
        return CM_ERROR;
    }

    if (AddNewResToJsonObj(resArray, resObj) != CM_SUCCESS) {
        write_runlog(ERROR, "%s%s Res(%s) failed to add obj to array.\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName);
        cJSON_Delete(resObj);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t DelInstInJson(cJSON *resArray, const ResOption *resCtx)
{
    CM_RETURN_IF_FALSE(CheckInstParam(resCtx));
    int32 index;
    if (GetInstFromArray(resCtx, resArray, &index) == NULL) {
        write_runlog(ERROR, "%s%s Res(%s) cannot find the inst in json.\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName);
        return CM_ERROR;
    }
    cJSON_DeleteItemFromArray(resArray, index);
    return CM_SUCCESS;
}

static status_t EditInstInJson(cJSON *resArray, const ResOption *resCtx)
{
    CM_RETURN_IF_FALSE(CheckInstParam(resCtx));
    cJSON *resObj = GetInstFromArray(resCtx, resArray, NULL);
    if (resObj == NULL) {
        write_runlog(ERROR, "%s%s Res(%s) cannot find then inst in json.\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName);
        return CM_ERROR;
    }

    if (SplitResAttr(resCtx, resObj, resCtx->inst.instName, resCtx->inst.mode, EditInstAttrConfJson) !=
        CM_SUCCESS) {
        write_runlog(ERROR, "%s%s Res(%s) failed to edit inst to json.\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName);
        return CM_ERROR;
    }

    if (SetInstAttrToJson(resCtx, resObj, resCtx->inst.mode) != CM_SUCCESS) {
        write_runlog(ERROR, "%s%s Res(%s) failed to edit %s to json.\n", GetResOperStr(resCtx->mode),
            GetInstOperStr(resCtx->inst.mode), resCtx->resName, INST_ATTR);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static bool8 CjsonIntegerCheck(const ResOption *resCtx, const cJSON *objValue, const char *key)
{
    if (!cJSON_IsNumber(objValue)) {
        write_runlog(ERROR, "%s%s Res(%s) key(%s) value is not integer.\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName, key);
        return CM_FALSE;
    }

    if (objValue->valueint < 0) {
        write_runlog(ERROR, "%s%s Res(%s) key(%s) value is negative number.\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName, key);
        return CM_FALSE;
    }
    return CM_TRUE;
}

static bool8 CjsonStringCheck(const ResOption *resCtx, const cJSON *objValue, const char *key)
{
    if (!cJSON_IsString(objValue)) {
        write_runlog(ERROR, "%s%s Res(%s) key(%s) value is not string.\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName, key);
        return CM_FALSE;
    }

    if (CM_IS_EMPTY_STR(objValue->valuestring)) {
        write_runlog(ERROR, "%s%s Res(%s) key(%s) value is empty.\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName, key);
        return CM_FALSE;
    }
    check_input_for_security(objValue->valuestring);
    return CM_TRUE;
}

static bool8 CjsonArrayCheck(const ResOption *resCtx, const cJSON *objValue, const char *key)
{
    if (!cJSON_IsArray(objValue)) {
        write_runlog(ERROR, "%s%s Res(%s) key(%s) value is not array.\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName, key);
        return CM_FALSE;
    }

    return CM_TRUE;
}

static bool8 CjsonObjectCheck(const ResOption *resCtx, const cJSON *objValue, const char *key)
{
    if (objValue == NULL) {
        write_runlog(ERROR, "%s%s Res(%s) key(%s) value is not object.\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName, key);
        return CM_FALSE;
    }
    return CM_TRUE;
}

static bool8 IntegerUniqueCheck(const ResOption *resCtx, const cJSON *objValue, const cJSON *instArray, const char *key)
{
    int32 value = GetValueIntFromCJson(objValue, key);
    if (value < 0) {
        write_runlog(ERROR, "%s%s Res(%s) fail to check integer unique key(%s) value is invalid.\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName, key);
        return CM_FALSE;
    }
    const cJSON *objItem;
    int32 tmpValue;
    cJSON_ArrayForEach(objItem, instArray) {
        tmpValue = GetValueIntFromCJson(objItem, key);
        if (tmpValue == value) {
            write_runlog(ERROR, "%s%s Res(%s) unique_key([%s]: [%d]) may be repeat.\n", GetResOperStr(resCtx->mode),
                GetInstOperStr(resCtx->inst.mode), resCtx->resName, key, value);
            return CM_FALSE;
        }
    }
    return CM_TRUE;
}

static bool8 StringUniqueCheck(const ResOption *resCtx, const cJSON *objValue, const cJSON *instArray, const char *key)
{
    const char *value = GetValueStrFromCJson(objValue, key);
    if (CM_IS_EMPTY_STR(value)) {
        write_runlog(ERROR, "%s%s Res(%s) fail to check integer unique key(%s) value is empty.\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName, key);
        return CM_FALSE;
    }
    const cJSON *objItem;
    const char *tmpValue;
    cJSON_ArrayForEach(objItem, instArray) {
        tmpValue = GetValueStrFromCJson(objItem, key);
        if (!CM_IS_EMPTY_STR(tmpValue) && cm_str_equal(tmpValue, value)) {
            write_runlog(ERROR, "%s%s Res(%s) unique_key([%s]: [%s]) may be repeat.\n", GetResOperStr(resCtx->mode),
                GetInstOperStr(resCtx->inst.mode), resCtx->resName, key, value);
            return CM_FALSE;
        }
    }
    return CM_TRUE;
}

static status_t EditIntegerToJson(
    const ResOption *resCtx, cJSON *root, const char *key, const char *value, ResOpMode mode)
{
    if (CM_IS_EMPTY_STR(key) || CM_IS_EMPTY_STR(value)) {
        write_runlog(ERROR, "%s%s Res(%s) fails to add integer to json, when key or value is empty.\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName);
        return CM_ERROR;
    }
    if (!IsValueNumber(value)) {
        write_runlog(ERROR, "%s%s Res(%s) fails to add integer to json, when value(%s) is not number.\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName, value);
        return CM_ERROR;
    }
    if (mode != RES_OP_EDIT) {
        (void)cJSON_AddNumberToObject(root, key, (const double)CmAtol(value, -1));
    } else {
        (void)cJSON_ReplaceItemInObject(root, key, cJSON_CreateNumber((const double)CmAtol(value, -1)));
    }
    return CM_SUCCESS;
}

static status_t EditObjectToJson(
    const ResOption *resCtx, cJSON *root, const char *key, const char *value, ResOpMode mode)
{
    if (CM_IS_EMPTY_STR(key) || CM_IS_EMPTY_STR(value)) {
        write_runlog(ERROR, "%s%s Res(%s) fails to add object to json, when key or value is empty.\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName);
        return CM_ERROR;
    }

    if (mode != RES_OP_EDIT) {
        if (IsValueNumber(value)) {
            (void)cJSON_AddNumberToObject(root, key, (const double)CmAtol(value, -1));
        } else {
            check_input_for_security(value);
            (void)cJSON_AddStringToObject(root, key, value);
        }
        return CM_SUCCESS;
    }
    if(IsKeyInRestrictList(key) && (!IsValueNumber(value) || !IsResConfValid(key, (const int)CmAtol(value, -1)))) {
        write_runlog(ERROR, "%s%s Res(%s) fails to set key(%s) to new value(%s) due to wrong type or out of range.\n",
            GetResOperStr(resCtx->mode), GetInstOperStr(resCtx->inst.mode), resCtx->resName, key, value);
        return CM_ERROR;
    }
    if (IsValueNumber(value)) {
        (void)cJSON_ReplaceItemInObject(root, key, cJSON_CreateNumber((const double)CmAtol(value, -1)));
    } else {
        (void)cJSON_ReplaceItemInObject(root, key, cJSON_CreateString(value));
    }
    return CM_SUCCESS;
}

static void AddPrintRet(int32 ret, const char *resName)
{
    if (ret == 0) {
        write_runlog(LOG, "add res(%s) success.\n", resName);
    } else {
        write_runlog(ERROR, "add res(%s) fail.\n", resName);
    }
}

static void EditPrintRet(int32 ret, const char *resName)
{
    if (ret == 0) {
        write_runlog(LOG, "edit res(%s) success.\n", resName);
    } else {
        write_runlog(ERROR, "edit res(%s) fail.\n", resName);
    }
}

static void DelPrintRet(int32 ret, const char *resName)
{
    if (ret == 0) {
        write_runlog(LOG, "delete res(%s) success.\n", resName);
    } else {
        write_runlog(ERROR, "delete res(%s) fail, please check file \"%s\".\n", resName, g_jsonFile);
    }
}

static void CheckPrintRet(int32 ret, const char *resName)
{
    if (ret == 0) {
        write_runlog(LOG, "resource config is valid.\n");
    } else {
        write_runlog(ERROR, "resource config is invalid, please check file \"%s\".\n", g_jsonFile);
    }
}

static void InitOperResMap()
{
    InitResTypeMap();

    // res
    errno_t rc = memset_s(g_operResMap, sizeof(g_operResMap), 0, sizeof(g_operResMap));
    securec_check_errno(rc, (void)rc);
    g_operResMap[RES_OP_ADD] = AddResToJson;
    g_operResMap[RES_OP_DEL] = DelResInJson;
    g_operResMap[RES_OP_EDIT] = EditResInJson;
    g_operResMap[RES_OP_CHECK] = CheckResInJson;
    g_operResMap[RES_OP_LIST] = ListResInJson;

    // inst
    rc = memset_s(g_operInstMap, sizeof(g_operInstMap), 0, sizeof(g_operInstMap));
    securec_check_errno(rc, (void)rc);
    g_operInstMap[RES_OP_ADD] = AddInstToJson;
    g_operInstMap[RES_OP_DEL] = DelInstInJson;
    g_operInstMap[RES_OP_EDIT] = EditInstInJson;
    g_operInstMap[RES_OP_CHECK] = NULL;
    g_operInstMap[RES_OP_LIST] = NULL;

    // type
    rc = memset_s(g_typeCheck, sizeof(g_typeCheck), 0, sizeof(g_typeCheck));
    securec_check_errno(rc, (void)rc);
    g_typeCheck[RES_KV_TYPE_INTEGER] = CjsonIntegerCheck;
    g_typeCheck[RES_KV_TYPE_STRING] = CjsonStringCheck;
    g_typeCheck[RES_KV_TYPE_ARRAY] = CjsonArrayCheck;
    g_typeCheck[RES_KV_TYPE_OBJECT] = CjsonObjectCheck;

    // unique
    rc = memset_s(g_uniqueCheck, sizeof(g_uniqueCheck), 0, sizeof(g_uniqueCheck));
    securec_check_errno(rc, (void)rc);
    g_uniqueCheck[RES_KV_TYPE_INTEGER] = IntegerUniqueCheck;
    g_uniqueCheck[RES_KV_TYPE_STRING] = StringUniqueCheck;

    rc = memset_s(g_editJson, sizeof(g_editJson), 0, sizeof(g_editJson));
    securec_check_errno(rc, (void)rc);
    g_editJson[RES_KV_TYPE_INTEGER] = EditIntegerToJson;
    g_editJson[RES_KV_TYPE_STRING] = EditStringToJson;
    g_editJson[RES_KV_TYPE_ARRAY] = EditArrayToJson;
    g_editJson[RES_KV_TYPE_OBJECT] = EditObjectToJson;

    rc = memset_s(g_printRet, sizeof(g_printRet), 0, sizeof(g_printRet));
    securec_check_errno(rc, (void)rc);
    g_printRet[RES_OP_ADD] = AddPrintRet;
    g_printRet[RES_OP_DEL] = DelPrintRet;
    g_printRet[RES_OP_EDIT] = EditPrintRet;
    g_printRet[RES_OP_CHECK] = CheckPrintRet;
}

void CheckAndWriteJson(const cJSON *root, ResOpMode mode)
{
    if (mode == RES_OP_ADD || mode == RES_OP_DEL || mode == RES_OP_EDIT) {
        if (WriteJsonFile(root, g_jsonFile) != CM_SUCCESS) {
            write_runlog(ERROR, "failed to write json file(%s).\n", g_jsonFile);
            }
    }
}

static void PrintExecRet(int32 ret, const char *resName, ResOpMode mode)
{
    if (mode < RES_OP_INIT || mode >= RES_OP_CEIL) {
        return;
    }
    printRet printRet = g_printRet[mode];
    if (printRet != NULL) {
        printRet(ret, resName);
    }
}

int32 DoResOperCmd(ResOption *resCtx)
{
    if (resCtx->mode >= RES_OP_CEIL) {
        write_runlog(ERROR, "unknown cm_ctl res opt %u.\n", (uint32)resCtx->mode);
        return -1;
    }
    OperateRes operRes = g_operResMap[resCtx->mode];
    if (operRes == NULL) {
        write_runlog(ERROR, "not input (--add,--edit,--del,--check), please check input.\n");
        return -1;
    }

    GetCmConfJsonPath(g_jsonFile, sizeof(g_jsonFile));

    cJSON *root = GetResJsonFromFile(g_jsonFile, (resCtx->mode == RES_OP_ADD));
    if (root == NULL) {
        write_runlog(ERROR, "Failed to get res json from File(%s).\n", g_jsonFile);
        return -1;
    }
    // resources
    cJSON *resArray = cJSON_GetObjectItem(root, RESOURCES);
    if (!cJSON_IsArray(resArray)) {
        write_runlog(ERROR, "failed to get resource array from jsonFile(%s).\n", g_jsonFile);
        cJSON_Delete(root);
        return -1;
    }

    int32 ret = (int32)operRes(resArray, resCtx);
    if (ret == 0) {
        CheckAndWriteJson(root, resCtx->mode);
    }
    PrintExecRet(ret, resCtx->resName, resCtx->mode);
    cJSON_Delete(root);
    return ret;
}

int DoResCommand(ResOption *resCtx)
{
    TrimAllRes(resCtx);
    InitOperResMap();
    return DoResOperCmd(resCtx);
}
