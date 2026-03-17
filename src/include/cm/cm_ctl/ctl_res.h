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
 * ctl_res.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_ctl/ctl_res.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CTL_RES_H
#define CTL_RES_H

#include "c.h"
#include "cm_defs.h"
#include "cm_misc_res.h"

#include "cjson/cJSON.h"
#include "cm_elog.h"

typedef enum ResTypeE {
    RES_TYPE_INIT = 0,
    RES_TYPE_UNKNOWN,
    RES_TYPE_APP,
    RES_TYPE_DN,
    RES_TYPE_VIP,
    RES_TYPE_CEIL,  // it must be end
} ResType;

typedef enum ResOpModeE {
    RES_OP_INIT = 0,
    RES_OP_UNKNOWN,
    RES_OP_ADD,
    RES_OP_DEL,
    RES_OP_EDIT,
    RES_OP_CHECK,
    RES_OP_LIST,
    RES_OP_CEIL  // it must be end
} ResOpMode;

typedef struct ResInstOpT {
    ResOpMode mode;
    char reserved[4];  // for alignment
    char *instName;
    char *instAttr;
} ResInstOp;

typedef struct ResOptionT {
    ResOpMode mode;
    char reserved[4];  // for alignment
    char *resName;
    char *resAttr;
    ResInstOp inst;
} ResOption;

typedef struct ResTypeStrT {
    ResType type;
    const char *str;
} ResTypeStr;

typedef enum ResLevelE {
    RES_LEVEL_INIT = 0,
    RES_LEVEL_UNKNOWN,
    RES_LEVEL_RES,
    RES_LEVEL_INST,
    RES_LEVEL_CEIL
} ResLevel;

typedef enum ResKvTypeE {
    RES_KV_TYPE_INIT = 0,
    RES_KV_TYPE_UNKNOWN,
    RES_KV_TYPE_INTEGER,
    RES_KV_TYPE_STRING,
    RES_KV_TYPE_ARRAY,
    RES_KV_TYPE_OBJECT,
    RES_KV_TYPE_CEIL
} ResKvType;

typedef struct KvRestrictT {
    ResKvType type;
    const char *key;
} KvRestrict;

typedef struct ResInstInfoT {
    int32 instId;
    int32 nodeId;
} ResInstInfo;

// res
const char KEY_VALUE_SPLIT_CHAR = '=';
const char KEY_VALUE_SPLIT_ARRAY[] = {KEY_VALUE_SPLIT_CHAR, '\0'};
const char *const RES_NAME = "name";
const char *const RESOURCE_TYPE = "resources_type";
const char *const RESOURCES = "resources";
const char *const INSTANCES = "instances";
const char *const RES_ATTR = "res_attr";

// instances
const char *const INST_NODE_ID = "node_id";
const char *const INST_RES_INST_ID = "res_instance_id";

// APP or DN
const char *const RES_SCRIPT = "script";
const char *const RES_CHECK_INTERVAL = "check_interval";
const char *const RES_TIMEOUT = "time_out";
const char *const RES_RESTART_DELAY = "restart_delay";
const char *const RES_PERIOD = "restart_period";
const char *const RES_RESTART_TIMES = "restart_times";

const char *const INST_REG = "res_args";

// VIP
const char *const RES_FLOAT_IP = "float_ip";
const char *const INST_ATTR = "inst_attr";

typedef status_t (*CheckResInfo)(cJSON *resItem, const char *resName);

typedef struct ResTypeMapT {
    ResType type;
    const char *typeStr;
    const char *value;
    CheckResInfo check;
} ResTypeMap;

status_t GetIntFromText(
    const ResOption *resCtx, const char *str, const char *expectValue, int32 *value, int32 logLevel);
status_t CheckResFromArray(cJSON *resArray);
bool CompareResType(const char *value, uint32 *index);
status_t CheckResFromArray(cJSON *resArray);
int DoResCommand(ResOption *resCtx);
const char *GetResOperStr(ResOpMode opMode);
const char *GetInstOperStr(ResOpMode opMode);
int GetValueIntFromCJson(const cJSON *object, const char *infoKey, int32 logLevel = ERROR);
char *GetValueStrFromCJson(const cJSON *object, const char *infoKey, int32 logLevel = ERROR);
cJSON *GetCurResInArray(cJSON *resArray, const char *resName, const ResOption *resCtx, int32 *resIdx = NULL);
ResType GetResTypeFromCjson(cJSON *resItem);
bool CompareResType(const char *value, uint32 *index);
void InitResTypeMap();
bool8 IsResCheckInstances(ResType resType);
bool8 IsCurNotCheckInstances(const ResOption *resCtx, const cJSON *resObj);
const char *GetResTypeValue(uint32 index);
ResType GetResTypeInJson(const ResOption *resCtx, const cJSON *resObj);
status_t CheckResName(
    const cJSON *resItem, char (*resName)[CM_MAX_RES_NAME], uint32 maxCnt, uint32 *curCnt, const char **curResName);

#endif
