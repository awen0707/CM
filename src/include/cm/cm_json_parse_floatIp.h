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
* cm_json_parse_floatIp.h
*
*
* IDENTIFICATION
*    include/cm/cm_json_parse_floatIp.h
*
* -------------------------------------------------------------------------
*/
#ifndef CM_JSON_PARSE_FLOATIP_H
#define CM_JSON_PARSE_FLOATIP_H
#include "c.h"
#include "cm_defs.h"
#include "cm_msg.h"
#include "cm_misc_res.h"

typedef struct DnFloatIpT {
    pthread_rwlock_t rwlock;
    uint32 instId;
    const char *dataPath;
    // float ip and manage ip
    uint32 dnFloatIpCount;
    char baseIp[MAX_FLOAT_IP_COUNT][CM_IP_LENGTH];
    char dnFloatIp[MAX_FLOAT_IP_COUNT][CM_IP_LENGTH];
    char floatIpName[MAX_FLOAT_IP_COUNT][CM_MAX_RES_NAME];
    uint32 dnFloatIpPort;
    uint32 needResetFloatIpCnt;
    char needResetFloatIp[MAX_FLOAT_IP_COUNT][CM_IP_LENGTH];
} DnFloatIp;

typedef bool8 (*findNodeInfoByNodeIdx)(uint32 instId, uint32 *nodeIdx, uint32 *dnIdx, const char *str);
typedef DnFloatIp *(*getDnFloatIpByNodeInfo)(uint32 nodeIdx, uint32 dnIdx);
typedef void (*increDnFloatIpCnt)(uint32 nodeIdx);

typedef struct ParseFloatIpFuncT {
    findNodeInfoByNodeIdx findNodeInfo;
    getDnFloatIpByNodeInfo getFloatIp;
    increDnFloatIpCnt increaseCnt;
} ParseFloatIpFunc;

void ParseVipConf(int32 logLevel);
void InitParseFloatIpFunc(const ParseFloatIpFunc *parseFuc);

#endif
