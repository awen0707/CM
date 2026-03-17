/*
 * Copyright (c) 2021 Huawei Technologies Co.,Ltd.
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
 * cms_ddb_adapter.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_server/cms_ddb_adapter.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CMS_DDB_ADAPTER_H
#define CMS_DDB_ADAPTER_H

#include "cm_ddb_adapter.h"
#include "c.h"
#include "cm_server.h"

const int DDB_UNLOCK = 0;
const int DDB_LOCK = 1;

const int DDB_SET_BLOCKED_TIMEOUT = 3000;

const int32 INIT_GET_PARAMTER = 1;
const int32 RELOAD_PARAMTER = 2;

#define DDB_MIN_VALUE_LEN (128)
typedef enum DDB_RESULT_E {
    FAILED_GET_VALUE = -1,
    SUCCESS_GET_VALUE = 0,
    CAN_NOT_FIND_THE_KEY = 1,
} DDB_RESULT;

typedef struct DdbOptionT {
    DDB_RESULT ddbResult;
    int32 logLevel;
} DdbOption;

status_t GetKVFromDDb(char *key, uint32 keyLen, char *value, uint32 valueLen, DDB_RESULT *ddbResult);
status_t SetKV2Ddb(char *key, uint32 keyLen, char *value, uint32 valueLen, DrvSetOption *option);
status_t DelKeyInDdb(char *key, uint32 keyLen);
status_t GetKVWithCon(DdbConn *ddbConn, const char *key, char *value, uint32 valueLen, DDB_RESULT *ddbResult);
status_t SetKVWithConn(DdbConn *ddbConn, char *key, uint32 keyLen, char *value, uint32 valueLen);
status_t DelKeyWithConn(DdbConn *ddbConn, char *key, uint32 keyLen);
status_t GetAllKVFromDDb(char *key, uint32 keyLen, DrvKeyValue *keyValue, uint32 len, DDB_RESULT *ddbResult);
status_t SaveAllKVFromDDb(DDB_RESULT *ddbResult, DrvSaveOption *option);
status_t GetKVAndLogLevel(const char *key, char *value, uint32 valueLen,
    DDB_RESULT *ddbResult, int32 logLevel = DEBUG1);
status_t GetKVConAndLog(DdbConn *ddbConn, const char *key, char *value, uint32 valueLen, DdbOption *option);
bool IsDdbHealth(DDB_CHECK_MOD checkMod);
void ClearDdbNodeInfo(const DdbConn *ddbConn);
status_t InitDdbArbitrate(DrvApiInfo *drvApiInfo);
status_t CreateCmsInstInfo(void);
void NotifyDdb(DDB_ROLE dbRole);
void SetDdbMinority(bool isMinority);
Alarm *GetDdbAlarm(int index);
bool IsNeedSyncDdb(void);
bool IsSyncDdbWithArbiMode(void);
void PrintKeyValueMsg(const char *initKey, const DrvKeyValue *keyValue, size_t length, int32 logLevel);
bool DdbLeaderInAz(const char *azName, uint32 *nodeId);
bool IsInteractWithDdb(bool checkMinority, bool checkEtcd);
void ClearDdbCfgApi(DrvApiInfo *drvApiInfo, DDB_TYPE dbType);
status_t GetDdbSession(CM_ConnDdbInfo *session, int32 timeOut, const char *azNames);
status_t InitDdbCfgApi(DDB_TYPE dbType, DrvApiInfo *drvApiInfo, int32 timeOut, const char *azNames);
int32 CmsNotifyStatus(DDB_ROLE roleType);
void CloseAllDdbSession(void);
DdbConn *GetNextDdbConn(void);
status_t ServerDdbInit(void);
void EtcdIpPortInfoBalance(ServerSocket *server, const char *azNames = NULL);
void CloseDdbSession(DdbConn *ddbConn);
DdbConn *GetDdbConnFromGtm(void);
void RestDdbConn(DdbConn *ddbConn, status_t st, const DDB_RESULT *ddbResult);
status_t DoDdbExecCmd(const char *cmd, char *output, int *outputLen, char *errMsg, uint32 maxBufLen);
status_t DoDdbSetBlocked(unsigned int setBlock, unsigned int waitTimeoutMs);
void LoadDdbParamterFromConfig(void);
status_t SetDdbWorkMode(unsigned int workMode, unsigned int voteNum);
status_t DemoteDdbRole2Standby();

#endif
