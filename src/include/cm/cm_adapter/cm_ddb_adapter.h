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
 * cm_ddb_adapter.h
 *    API for ddb adapter
 *
 * IDENTIFICATION
 *    include/cm/cm_adapter/cm_ddb_adapter.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CM_DDB_ADAPTER_API_H
#define CM_DDB_ADAPTER_API_H

#include <pthread.h>
#include "c.h"
#include "cm/cm_defs.h"
#include "cm/be_module.h"
#include "utils/syscall_lock.h"

#define DDB_MAX_PATH_LEN (1024)
#define DDB_KEY_LEN (1024)
#define DDB_VALUE_LEN (1024)
#define DDB_MAX_KEY_VALUE_LEN (10240)

#define DDB_IP_PORT_NUM (256)

#define DDB_DEFAULT_TIMEOUT (2000)
#define DDB_MAX_CONNECTIONS (1024)
// reserverd 8K space from disk head before writing data
#define DDB_DISK_ORIGINAL_OFFSET (8 * 1024)

typedef enum DDB_TYPE_EN { DB_ETCD = 0, DB_DCC, DB_SHAREDISK, DB_UNKOWN } DDB_TYPE;

typedef struct DdbTypeString_t {
    const char *dbString;
    DDB_TYPE dbType;
} DdbTypeString;

typedef enum DDB_ROLE {
    DDB_ROLE_UNKNOWN = 0,
    DDB_ROLE_LEADER,
    DDB_ROLE_FOLLOWER,
    DDB_ROLE_LOGGER,
    DDB_ROLE_PASSIVE,
    DDB_ROLE_PRE_CANDIDATE,
    DDB_ROLE_CANDIDATE,
    DDB_ROLE_CEIL,
} DDB_ROLE;

typedef enum { PROCESS_IN_INIT = 0, PROCESS_IN_RUNNING, PROCESS_IN_IDLE } PROCESS_STATE;

typedef enum { DDB_PRE_CONN = 0, DDB_HEAL_COUNT } DDB_CHECK_MOD;

typedef enum DDB_STATE {
    DDB_STATE_UNKOWN = 0,
    DDB_STATE_HEALTH,
    DDB_STATE_DOWN,
} DDB_STATE;

typedef struct NodeInfoSt {
    char *nodeName;
    uint32 len;
} NodeInfo;

typedef struct NodeIdInfo_t {
    const char *azName;
    uint32 nodeId;
    uint32 instd;
} NodeIdInfo;

typedef struct ServerSocketSt {
    char *host;
    uint32 port;
    NodeIdInfo nodeIdInfo;
    NodeInfo nodeInfo;
} ServerSocket;

typedef struct TlsAuthPathSt {
    char caFile[DDB_MAX_PATH_LEN];
    char crtFile[DDB_MAX_PATH_LEN];
    char keyFile[DDB_MAX_PATH_LEN];
} TlsAuthPath;

typedef struct SslConfig_t {
    bool enableSsl;
    uint32 expireTime;
    TlsAuthPath sslPath;
} SslConfig;

typedef struct InstInfoSt {
    bool isVoteAz;
    uint32 instd;
    uint32 nodeId;
    uint32 nodeIdx;
    uint32 instIdx;
} InstInfo;

typedef struct DdbArbiCfgSt {
    uint32 haStatusInterval;
    uint32 arbiDelayBaseTimeOut;
    uint32 arbiDelayIncrementalTimeOut;
    uint32 haHeartBeatTimeOut;
    pthread_rwlock_t lock;
} DdbArbiCfg;

typedef uint32 (*funcGetPreConnCount)(void);
typedef void (*funcResetPreConn)(void);

typedef struct DdbArbiConSt {
    char *userName;

    InstInfo *instInfo;
    uint32 instNum;

    DdbArbiCfg *arbiCfg;

    InstInfo curInfo;

    funcGetPreConnCount getPreConnCount;
    funcResetPreConn resetPreConn;
} DdbArbiCon;

typedef struct DrvApiInfoSt {
    uint32 nodeId;
    ModuleId modId;

    uint32 serverLen;
    ServerSocket *serverList;

    uint32 nodeNum;
    int32 timeOut;
    union {
        struct {
            TlsAuthPath *tlsPath;
            int64 waitTime; // the time is used to wait to change expectations
        } client_t;
        struct {
            char *dataPath;
            char logPath[DDB_MAX_PATH_LEN];
            int64 waitTime; // the time is used to wait to change expectations
            ServerSocket curServer;
            SslConfig sslcfg;
        } server_t;
        struct {
            char devPath[DDB_MAX_PATH_LEN];
            int64 instanceId;
            int64 waitTime;
            uint32 offset;
        } sdConfig;
    };
    DdbArbiCon *cmsArbiCon;
} DrvApiInfo;

typedef struct DdbInitConfigSt {
    DDB_TYPE type;
    DrvApiInfo drvApiInfo;
} DdbInitConfig;

typedef struct DrvTextSt {
    char *data;
    uint32 len;
} DrvText;

typedef struct DrvGetOptionSt {
    bool quorum;
} DrvGetOption;

typedef struct DrvSaveOptionSt {
    char *kvFile;
} DrvSaveOption;

typedef struct DrvSetOptionSt {
    char *preValue;
    uint32 len;
    bool maintainCanSet;
    bool isSetBinary;
} DrvSetOption;

typedef struct DrvDelOptionSt {
    char *prevValue;
    uint32 len;
} DrvDelOption;

typedef struct DrvHealStateSt {
    char *state;
    uint32 stateSize;
} DrvHealState;

typedef struct DrvKeyValueSt {
    char key[DDB_KEY_LEN];
    char value[DDB_VALUE_LEN];
} DrvKeyValue;

typedef struct DdbNodeStateSt {
    DDB_STATE health;
    DDB_ROLE role;
} DdbNodeState;

struct Alarm;

#define DrvCon_t void*
typedef status_t (*DrvApiLoad)(const DrvApiInfo *apiInfo);
typedef status_t (*DrvAllocConn)(DrvCon_t *session, const DrvApiInfo *apiInfo);
typedef status_t (*DrvFreeConn)(DrvCon_t *session);
typedef status_t (*DrvGetValue)(const DrvCon_t session, DrvText *key, DrvText *value, const DrvGetOption *option);
typedef status_t (*DrvGetAllKV)(
    const DrvCon_t session, DrvText *key, DrvKeyValue *keyValue, uint32 length, const DrvGetOption *option);
typedef status_t (*DrvSet)(const DrvCon_t session, DrvText *key, DrvText *value, DrvSetOption *option);
typedef status_t (*DrvDelete)(const DrvCon_t session, DrvText *key);
typedef status_t (*DrvSaveAllKV)(const DrvCon_t session, const DrvText *key, DrvSaveOption *option);
typedef status_t (*DrvNodeState)(DrvCon_t session, char *memberName, DdbNodeState *nodeState);
typedef const char *(*DrvLastError)(void);
typedef int32 (*DdbNotifyStatusFunc)(DDB_ROLE ddbRole);
typedef uint32 (*DrvDDbHealCount)(int timeOut);
typedef bool (*IsDrvDdbHealth)(DDB_CHECK_MOD checkMod, int timeOut);
typedef void (*DrvDdbFreeNodeInfo)(void);
typedef void (*DrvDdbNotify)(DDB_ROLE dbRole);
typedef void (*DrvDdbSetMinority)(bool isMinority);
typedef Alarm *(*DrvDdbGetAlarm)(int alarmIndex);
typedef status_t (*DrvDdbLeaderNodeId)(NodeIdInfo *idInfo, const char *azName);
typedef status_t (*DrvDdbRestConn)(DrvCon_t sess, int32 timeOut);
typedef status_t (*DrvDdbExecCmd)(DrvCon_t session, char *cmdLine, char *value, int *valueLen, uint32 maxBufLen);
typedef status_t (*DrvDdbSetBlocked)(unsigned int setBlock, unsigned int waitTimeoutMs);
typedef status_t (*DrvSetParam)(const char *key, const char *value);
typedef status_t (*DrvStop)(bool *ddbStop);
typedef status_t (*DrvSetWorkMode)(DrvCon_t session, unsigned int workMode, unsigned int voteNum);
typedef status_t (*DrvDemoteDdbRole)(DrvCon_t session);

typedef struct DdbDriverSt {
    pthread_rwlock_t lock;
    bool initialized; // whether ddb has been inited
    DDB_TYPE type;
    char msg[DDB_MAX_PATH_LEN];

    // interface:
    DrvApiLoad loadingApi; // laoding api drv
    DrvAllocConn allocConn; // alloc conn
    DrvFreeConn freeConn; // free conn
    DrvGetValue getValue; // get value by key
    DrvGetAllKV getAllKV; // get all key-value by prefix key
    DrvSaveAllKV saveAllKV; // save all key-value by prefix key
    DrvSet setKV; // set key-value
    DrvDelete delKV; // delete key-value
    DrvNodeState drvNodeState; // get ddb instance state status
    DrvLastError lastError; // get last error msg

    DrvDDbHealCount healCount; // health node count
    IsDrvDdbHealth isHealth; // whether is ddb health
    DrvDdbFreeNodeInfo freeNodeInfo; // free node info
    DrvDdbNotify notifyDdb; // upper notify ddb to be standby or primary
    DrvDdbSetMinority setMinority; // upper notify it is in minority, cannot do arbitrate
    DrvDdbGetAlarm getAlarm; // get ddb alarm
    DrvDdbLeaderNodeId leaderNodeId; // get ddb leader nodeId.
    DrvDdbRestConn restConn; // rest ddb conn
    DrvDdbExecCmd execCmd; // exec ddb cmd
    DrvDdbSetBlocked setBlocked;  // set ddb block
    DrvSetParam setParam;         // set ddb param
    DrvStop stop;
    DrvSetWorkMode setWorkMode; // set ddb work mode
    DrvDemoteDdbRole demoteDdbRole;

    bool ddbStopped;
} DdbDriver;

typedef struct DdbConnSt {
    DdbDriver *drv;
    DrvCon_t session;
    int32 timeOut;
    ModuleId modId;
    uint32 nodeId;
    PROCESS_STATE state;
    pthread_rwlock_t lock;
} DdbConn;

const char *GetDdbToString(DDB_TYPE dbType);
const DDB_TYPE GetStringToDdb(const char *str);
DdbDriver *InitDdbDrv(const DdbInitConfig *config);
status_t InitDdbConn(DdbConn *ddbConn, const DdbInitConfig *config);
status_t DdbGetValue(DdbConn *ddbConn, DrvText *key, DrvText *value, const DrvGetOption *option);
status_t DdbGetAllKV(DdbConn *ddbConn, DrvText *key, DrvKeyValue *keyValue, uint32 length, const DrvGetOption *option);
status_t DdbSaveAllKV(DdbConn *ddbConn, DrvText *key, DrvSaveOption *option);
status_t DdbSetValue(DdbConn *ddbConn, DrvText *key, DrvText *value, DrvSetOption *option);
status_t DdbDelKey(DdbConn *ddbConn, DrvText *key);
status_t DdbInstanceState(DdbConn *ddbConn, char *memberName, DdbNodeState *drvState);
status_t DdbFreeConn(DdbConn *ddbConn);
const char *DdbGetLastError(const DdbConn *ddbConn);

/* register the function: notify the upper to be primary or standby */
int32 DdbRegisterStatusNotify(DdbNotifyStatusFunc ddbNotify);
/* callback function */
DdbNotifyStatusFunc GetDdbStatusFunc(void);

void DdbFreeNodeInfo(const DdbConn *ddbConn);
bool DdbIsValid(const DdbConn *ddbConn, DDB_CHECK_MOD checkMod, int timeOut = 2000);
void DdbNotify(const DdbConn *ddbConn, DDB_ROLE dbRole);
void DdbSetMinority(const DdbConn *ddbConn, bool isMinority);
Alarm *DdbGetAlarm(const DdbConn *ddbConn, int index);
Alarm *DdbGetAlarm(const DdbDriver *drv, int index);
status_t DdbLeaderNodeId(const DdbConn *ddbConn, NodeIdInfo *idInfo, const char *azName);
status_t DdbRestConn(DdbConn *ddbConn);
status_t DdbExecCmd(DdbConn *ddbConn, char *cmdLine, char *output, int *outputLen, uint32 maxBufLen);
status_t DdbSetBlocked(const DdbConn *ddbConn, unsigned int setBlock, unsigned waitTimeoutMs);
status_t DDbSetParam(const DdbConn *ddbConn, const char *key, const char *value);
status_t DdbStop(DdbConn *ddbConn);
status_t DdbSetWorkMode(DdbConn *ddbConn, unsigned int workMode, unsigned int voteNum);
status_t DdbDemoteRole2Standby(DdbConn *ddbConn);

#endif
