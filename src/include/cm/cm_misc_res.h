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
* cm_misc_res.h
*
*
* IDENTIFICATION
*    include/cm/cm_misc_res.h
*
* -------------------------------------------------------------------------
 */

#ifndef CM_CM_MISC_RES_H
#define CM_CM_MISC_RES_H

#include "cm_misc_base.h"

#define HEARTBEAT_TIMEOUT 5
#define CM_MAX_RES_NAME 32
#define CM_MAX_LOCK_NAME 32
#define CM_MAX_RES_INST_COUNT 64
#define CM_MAX_RES_COUNT 16
#define CM_MAX_RES_NODE_COUNT 16
const uint32 CM_MAX_VIP_COUNT = 16;

#define RES_INST_WORK_STATUS_UNAVAIL 0
#define RES_INST_WORK_STATUS_AVAIL 1
#define RES_INST_WORK_STATUS_UNKNOWN 2

#define RES_INST_ISREG_UNKNOWN 255  // -1
#define RES_INST_ISREG_UNREG 0
#define RES_INST_ISREG_PENDING 1
#define RES_INST_ISREG_REG 2
#define RES_INST_ISREG_NOT_SUPPORT 11

#define CUS_RES_CHECK_STAT_ONLINE   0
#define CUS_RES_CHECK_STAT_OFFLINE  1
#define CUS_RES_CHECK_STAT_UNKNOWN  2
#define CUS_RES_CHECK_STAT_ABNORMAL 3
#define CUS_RES_CHECK_STAT_TIMEOUT  137
#define CUS_RES_CHECK_STAT_FAILED   255  // -1

#define CUS_RES_START_FAIL_DEPEND_NOT_ALIVE 6

#define RES_INSTANCE_ID_MIN 20000
#define RES_INSTANCE_ID_MAX 30000

#define MIN_DN_INST_ID 6000
#define MAX_DN_INST_ID 7000

#define QUERY_RES_STATUS_STEP 0
#define QUERY_RES_STATUS_STEP_ACK 1
#define QUERY_RES_STATUS_STEP_ACK_END 2

#define CM_DOMAIN_SOCKET "agent.socket"

typedef enum IpTypeEn {
    IP_TYPE_INIT = 0,
    IP_TYPE_UNKNOWN = 1,
    IP_TYPE_IPV4,
    IP_TYPE_IPV6,
    IP_TYPE_NEITHER,
    IP_TYPE_CEIL,
} IpType;

typedef enum {
    CM_RES_ISREG_INIT = 0,
    CM_RES_ISREG_REG  = 1,
    CM_RES_ISREG_UNREG = 2,
    CM_RES_ISREG_PENDING = 3,
    CM_RES_ISREG_UNKNOWN = 4,
    CM_RES_ISREG_NOT_SUPPORT = 5,
    CM_RES_ISREG_CEIL = 6,
} ResIsregStatus;

typedef struct CmResStatInfoSt {
    uint32 nodeId;
    uint32 cmInstanceId;
    uint32 resInstanceId;
    uint32 isWorkMember;
    uint32 status;
} CmResStatInfo;

typedef struct OneResStatListSt {
    unsigned long long version;
    uint32 instanceCount;
    char resName[CM_MAX_RES_NAME];
    CmResStatInfo resStat[CM_MAX_RES_INST_COUNT];
} OneResStatList;

typedef struct CmResStatListSt {
    pthread_rwlock_t rwlock;
    OneResStatList status;
} CmResStatList;

extern bool g_enableSharedStorage;
extern CmResStatList g_resStatus[CM_MAX_RES_COUNT];

int ResConfMaxValue(const char *param);
int ResConfMinValue(const char *param);
const char* ResConfDefValue(const char *param);

bool IsResConfValid(const char *param, int value);
bool IsKeyInRestrictList(const char *key);
void GetCmConfJsonPath(char *path, uint32 pathLen);
int ReadCmConfJson(void *logFunc);
status_t InitAllResStat(int logLevel = LOG);
status_t GetGlobalResStatusIndex(const char *resName, uint32 &index);
bool IsResInstIdValid(int instId);
bool IsOneResInstWork(const char *resName, uint32 cmInstId);
bool IsReadConfJsonSuccess(int ret);
const char *ReadConfJsonFailStr(int ret);
status_t GetResNameByCmInstId(uint32 instId, char *resName, uint32 nameLen);
uint32 CusResCount();
bool IsCusResExist();
const char *GetIsregStatus(int isreg);
void PrintCusInfoResList(const OneResStatList *status, const char *info);
bool8 IsDatanodeSSMode();
uint32 GetResNodeCount();
uint32 GetResNodeId(uint32 index);

#endif  // CM_CM_MISC_RES_H
