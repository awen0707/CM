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
 * cms_az.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_server/cms_az.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CMS_AZ_CHECK_H
#define CMS_AZ_CHECK_H

#define AZ_STATUS_RUNNING 0
#define AZ_STAUTS_STOPPED 1

#define PING_TIMEOUT_OPTION " -c 2 -W 2"
/* for the limit of check node of success, when check az1 is success */
#define AZ1_AND_AZ2_CHECK_SUCCESS_NODE_LIMIT 10
#define AZ1_AZ2_CONNECT_PING_TRY_TIMES 3

#define SINGLENODE_TYPE (1)
#define SINGLEAZ_TYPE (2)
#define MULTIAZ_RUNNING_STATUS (0)
#define MULTIAZ_STOPPING_STATUS (1)

const int MAX_PING_NODE_NUM = 10;

extern DdbConn g_dbConn;

/* data structure to store input/output of ping-check thread function */
typedef struct PingCheckThreadParmInfoT {
    /* the node to ping */
    uint32 azNode;
    /* ping thread idnex */
    uint32 threadIdx;
    /* the array of ping result */
    uint32 *pingResultArrayRef;
} PingCheckThreadParmInfo;

typedef struct ConnCheckT {
    bool lastConn;
    bool curConn;
    AZRole azRole;
    uint32 azPriority;
    char azName[CM_AZ_NAME];
} ConnCheck;

typedef enum AzPingCheckResE { CONTINUE_EXECTING = 0, WAIT_NEXT_TIME } AzPingCheckRes;

typedef enum OperateTypeE { START_AZ, STOP_AZ } OperateType;
typedef enum DdbOperateTypeE { SET_DDB_AZ, GET_DDB_AZ } DdbOperateType;
typedef enum AZDeploymentTypeE { UNKNOWN_AZ_DEPLOYMENT, TWO_AZ_DEPLOYMENT, THREE_AZ_DEPLOYMENT } AZDeploymentType;

extern int GetNodeIndexByAzRole(AZRole azRole);
extern bool AzPingCheck(bool *preConnStatusAZ, const char *azName1);
extern void CreateDdbConnSession(bool lastLeft1Conn, bool lastLeft2Conn, bool lastCurAzConn);
extern bool CheckStopFileExist(int type);
extern void StartOrStopAZ(OperateType operateType, const char *azName);
extern void StartOrStopNodeInstanceByCommand(OperateType operateType, uint32 nodeId);
extern bool GetStopAzFlagFromDdb(AZRole azRole);
extern bool SetStopAzFlagToDdb(AZRole azRole, bool stopFlag);
extern bool doCheckAzStatus(const char *sshIp, AZRole azRole);
extern void StopAZ(const char* ArbiterAZIp, AZRole azRole);
extern void StartAZ(AZRole azRole);
extern int CreateStopNodeInstancesFlagFile(int type);
extern void *BothAzConnectStateCheckMain(void *arg);
extern void* MultiAzConnectStateCheckMain(void* arg);
extern void getAZDyanmicStatus(int azCount, int* statusOnline,
    int* statusPrimary, int* statusFail, int* statusDnFail, const char azArray[][CM_AZ_NAME]);

extern void *DnGroupStatusCheckAndArbitrateMain(void *arg);
bool CompareCurWithExceptSyncList(uint32 groupIndex);
extern void GetSyncListString(const DatanodeSyncList *syncList, char *syncListString, size_t maxLen);
extern bool IsInstanceIdInSyncList(uint32 instanceId, const DatanodeSyncList *syncList);
extern int GetDnCountOfAZ(int* azDnCount, int32 len, bool inCurSyncList, bool isVoteAz);
extern int GetAzDeploymentType(bool isVoteAz);
extern bool IsDnSyncListVaild(uint32 groupIndex, uint32 *instanceId);
extern void GetDnStatusString(const DatanodeDynamicStatus *dnDynamicStatus, char *dnStatusStr, size_t maxLen);
#endif