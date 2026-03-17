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
 * cms_arbitrate_datanode_pms.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_server/cms_arbitrate_datanode_pms.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CMS_ARBITRATE_DATANODE_PMS_H
#define CMS_ARBITRATE_DATANODE_PMS_H

#include "cm/cm_msg.h"
#include "cm_server.h"
#include "cms_global_params.h"

#define HALF_COUNT(numCount) ((numCount) / 2)

#define INVALID_INDEX (-1)

typedef struct InstanceStatus_t {
    int32 memIdx;
    uint32 instId;
    uint32 term;
} InstanceStatus;

typedef struct StatusInstances_t {
    int32 count;
    InstanceStatus itStatus[CM_PRIMARY_STANDBY_NUM];
} StatusInstances;

typedef struct InstanceInfo_t {
    bool dbRestart;
    int32 dbState;
    int32 dyRole;  // dynamic role
    int32 buildReason;
    uint32 term;
    uint32 lockmode;
    uint32 sendFailoverTimes;
    XLogRecPtr lsn;
} InstanceInfo;

typedef struct ArbiCond_t {
    bool isPrimaryValid;
    bool isDegrade;
    bool isPrimDemoting;
    bool hasDynamicPrimary;
    bool finishRedo;
    bool instMainta;
    bool setOffline;
    int32 voteAzCount;
    int32 igPrimaryCount;
    int32 igPrimaryIdx;
    int32 vaildPrimIdx;
    int32 dyPrimNormalIdx;
    int32 dyPrimIdx;
    int32 switchoverIdx;
    int32 lock1Count;
    int32 lock2Count;
    int32 buildCount;
    int32 vaildCandiCount;
    int32 vaildCount;
    int32 staticPriIdx;
    int32 staticPrimaryDbstate;
    int32 candiIdx;
    int32 onlineCount;
    int32 redoDone;
    int32 failoverNum;
    int32 invalidMemIdx;
    int32 cascadeCount;
    int32 snameAzDnCount;
    int32 snameAzRedoDoneCount;
    uint32 maxTerm;
    uint32 standbyMaxTerm;
    uint32 maxMemArbiTime;
    uint32 localArbiTime;
    uint32 arbitInterval;
    uint32 arbitStaticInterval;
    XLogRecPtr maxLsn;
    XLogRecPtr standbyMaxLsn;
} ArbiCond;

typedef struct DnArbCtx_t {
    pthread_rwlock_t *lock;
    MsgRecvInfo* recvMsgInfo;
    uint32 node;
    int32 memIdx;
    uint32 groupIdx;
    uint32 instId;
    uint32 maxTerm;
    int32 dbStatePre;
    int32 curAzIndex;
    maintenance_mode maintaMode;
    cm_instance_role_group *roleGroup;
    cm_instance_role_status *localRole;
    cm_instance_report_status *repGroup;
    cm_instance_datanode_report_status *dnReport;
    cm_instance_command_status *localCom;
    cm_instance_datanode_report_status *localRep;
    InstanceInfo info;
    StatusInstances staPrim;
    StatusInstances dyPrim;
    StatusInstances dyNorPrim;
    StatusInstances staNorStandby;
    StatusInstances pendStatus;
    StatusInstances staCasCade;
    StatusInstances dyCascade;
    ArbiCond cond;
} DnArbCtx;

typedef enum CAND_MODE_E {
    COS4FAILOVER = 0,
    COS4SWITCHOVER,
} CAND_MODE;

typedef struct CandicateCond_t {
    CAND_MODE mode;
} CandicateCond;

typedef enum INST_MODE_E {
    DN_ARBI_PMS = 0,
    DN_ARBI_NORMAL,
} INST_MODE;

typedef struct GetInstType_t {
    const char *instTpStr;
    INST_MODE instMode;
} GetInstType;

typedef struct SendMsgT {
    const char *tyName;
    const char *sendMsg;
} SendMsg_t;

typedef struct DnInstInfo_t {
    char curSl[MAX_PATH_LEN]; // curruent syncList
    char expSl[MAX_PATH_LEN]; // expect syncList
    char voteL[MAX_PATH_LEN]; // vote az list
    char dyCasL[MAX_PATH_LEN]; // dynamic cascade standby list
    char stCasL[MAX_PATH_LEN]; // static cascade standby list
} DnInstInfo;

void DatanodeInstanceArbitrate(MsgRecvInfo* recvMsgInfo, const agent_to_cm_datanode_status_report *agentRep);
bool IsCurrentNodeDorado(uint32 node);
void StopFakePrimaryResourceInstance(const DnArbCtx *ctx);
bool IsInstanceIdMax(const DnArbCtx *ctx);
uint32 GetAvaiSyncDdbInstId();
#endif