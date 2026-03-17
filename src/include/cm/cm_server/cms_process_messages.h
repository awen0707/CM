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
 * cms_process_messages.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_server/cms_process_messages.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CMS_PROCESS_MESSAGES_H
#define CMS_PROCESS_MESSAGES_H

#include "cms_arbitrate_cluster.h"

#ifndef CM_AZ_NAME
#define CM_AZ_NAME 65
#endif

// ETCD TIME THRESHOLD
#define ETCD_CLOCK_THRESHOLD 3
#define SWITCHOVER_SEND_CHECK_RATE 30

#define PROCESS_MSG_BY_TYPE(struct_name, strunct_ptr, function_name, recvMsgInfo, msgType) \
    do { \
        (strunct_ptr) = reinterpret_cast<struct_name *>( \
            reinterpret_cast<void *>(const_cast<char *>(CmGetmsgbytes(&recvMsgInfo->msg, sizeof(struct_name))))); \
        if ((strunct_ptr) != NULL) { \
            (function_name)(recvMsgInfo, (strunct_ptr)); \
        } else { \
            write_runlog(ERROR, "CmGetmsgbytes failed, msg_type=%d.\n", msgType); \
        } \
    } while (0)

typedef struct CmdMsgProc_t {
    bool doSwitchover;
    bool isCnReport;
} CmdMsgProc;

struct MsgRecvInfo;

typedef void (*CltCmdProc)(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc);

extern CltCmdProc g_cmdProc[MSG_CM_TYPE_CEIL];

extern int cmserver_getenv(const char* env_var, char* output_env_value, uint32 env_value_len, int elevel);
extern int check_if_candidate_is_in_faulty_az(uint32 group_index, int candidate_member_index);
extern int findAzIndex(const char azArray[][CM_AZ_NAME], const char* azName);
extern int ReadCommand(CM_Connection *con, const char *str);
extern int isNodeBalanced(uint32* switchedInstance);
int get_logicClusterId_by_dynamic_dataNodeId(uint32 dataNodeId);

extern bool process_auto_switchover_full_check();
extern bool existMaintenanceInstanceInGroup(uint32 group_index, int *init_primary_member_index);
extern bool isMaintenanceInstance(const char *file_path, uint32 notify_instance_id);

extern uint32 GetClusterUpgradeMode();

extern void cm_server_process_msg(MsgRecvInfo* recvMsgInfo);
extern void SwitchOverSetting(int time_out, int instanceType, uint32 ptrIndex, int memberIndex);

extern void getAZDyanmicStatus(int azCount,
    int* statusOnline, int* statusPrimary, int* statusFail, int* statusDnFail, const char azArray[][CM_AZ_NAME]);
extern void CheckClusterStatus();
int switchoverFullDone(void);
void set_cluster_status(void);

void ProcessCtlToCmBalanceResultMsg(MsgRecvInfo* recvMsgInfo);
void ProcessCtlToCmGetMsg(MsgRecvInfo* recvMsgInfo);
void ProcessCtlToCmBuildMsg(MsgRecvInfo* recvMsgInfo, ctl_to_cm_build* buildMsg);
void ProcessCtlToCmQueryMsg(MsgRecvInfo* recvMsgInfo, const ctl_to_cm_query *ctlToCmQry);
void ProcessCtlToCmQueryKerberosStatusMsg(MsgRecvInfo* recvMsgInfo);
void ProcessCtlToCmQueryCmserverMsg(MsgRecvInfo* recvMsgInfo);
void ProcessCtlToCmSwitchoverMsg(MsgRecvInfo* recvMsgInfo, const ctl_to_cm_switchover *switchoverMsg);
void ProcessCtlToCmSwitchoverAllMsg(MsgRecvInfo* recvMsgInfo, const ctl_to_cm_switchover *switchoverMsg);
void process_ctl_to_cm_switchover_full_msg(
    MsgRecvInfo* recvMsgInfo, const ctl_to_cm_switchover* ctl_to_cm_swithover_ptr);
void ProcessCtlToCmSwitchoverFullCheckMsg(MsgRecvInfo* recvMsgInfo);
void ProcessCtlToCmSwitchoverFullTimeoutMsg(MsgRecvInfo* recvMsgInfo);
void ProcessCtlToCmSwitchoverAzMsg(MsgRecvInfo* recvMsgInfo, ctl_to_cm_switchover* ctl_to_cm_swithover_ptr);
void ProcessCtlToCmSwitchoverAzCheckMsg(MsgRecvInfo* recvMsgInfo);
void process_ctl_to_cm_switchover_az_timeout_msg(MsgRecvInfo* recvMsgInfo);
void process_ctl_to_cm_setmode(MsgRecvInfo* recvMsgInfo);
void ProcessCtlToCmSetMsg(MsgRecvInfo* recvMsgInfo, const ctl_to_cm_set* ctl_to_cm_set_ptr);
void process_ctl_to_cm_balance_check_msg(MsgRecvInfo* recvMsgInfo);
void ProcessCtlToCmsSwitchMsg(MsgRecvInfo* recvMsgInfo, CtlToCmsSwitch *switchMsg);

void process_ctl_to_cm_get_datanode_relation_msg(
    MsgRecvInfo* recvMsgInfo, const ctl_to_cm_datanode_relation_info *info_ptr);

void process_gs_guc_feedback_msg(const agent_to_cm_gs_guc_feedback* feedback_ptr);
void process_notify_cn_feedback_msg(MsgRecvInfo* recvMsgInfo, const agent_to_cm_notify_cn_feedback* feedback_ptr);
uint32 AssignCnForAutoRepair(uint32 nodeId);
void process_agent_to_cm_heartbeat_msg(
    MsgRecvInfo* recvMsgInfo, const agent_to_cm_heartbeat* agent_to_cm_heartbeat_ptr);
void process_agent_to_cm_disk_usage_msg(const AgentToCmDiskUsageStatusReport *diskUsage);
void process_agent_to_cm_current_time_msg(const agent_to_cm_current_time_report* etcd_time_ptr);
void process_agent_to_cm_kerberos_status_report_msg(
    agent_to_cm_kerberos_status_report *agent_to_cm_kerberos_status_ptr);
void process_agent_to_cm_fenced_UDF_status_report_msg(
    const agent_to_cm_fenced_UDF_status_report* agent_to_cm_fenced_UDF_status_ptr);
void ProcessCtlToCmQueryGlobalBarrierMsg(MsgRecvInfo* recvMsgInfo);
void ProcessCtlToCmQueryBarrierMsg(MsgRecvInfo* recvMsgInfo);
void ProcessCtl2CmOneInstanceBarrierQueryMsg(
    MsgRecvInfo* recvMsgInfo, uint32 node, uint32 instanceId, int instanceType);
#if ((defined(ENABLE_MULTIPLE_NODES)) || (defined(ENABLE_PRIVATEGAUSS)))
void ProcessGetDnSyncListMsg(AgentToCmserverDnSyncList *agentDnSyncList);
#endif
void ProcessAgent2CmResStatReportMsg(ReportResStatus *resStatusPtr);
void ProcessReportResChangedMsg(bool notifyClient, const OneResStatList *status);
void IncreaseOneResInstReportInter(const char *resName, uint32 instId);
uint32 GetOneResInstReportInter(const char *resName, uint32 instId);
int GetCurAz();
uint32 GetPrimaryDnIndex(void);
void InitNodeReportVar();
MaxClusterResStatus GetResNodeStat(uint32 nodeId, int logLevel);

void ProcessCtlToCmReloadMsg(MsgRecvInfo* recvMsgInfo);
void ProcessCtlToCmExecDccCmdMsg(MsgRecvInfo* recvMsgInfo, ExecDdbCmdMsg *msg);
void ProcessRequestResStatusListMsg(MsgRecvInfo* recvMsgInfo);
void ProcessRequestLatestResStatusListMsg(MsgRecvInfo *recvMsgInfo, RequestLatestStatList *recvMsg);
void ProcessCltSendOper(MsgRecvInfo* recvMsgInfo, CltSendDdbOper *ddbOper);
void ProcessSslConnRequest(MsgRecvInfo* recvMsgInfo, const AgentToCmConnectRequest *requestMsg);
void ProcessSharedStorageMsg(MsgRecvInfo* recvMsgInfo);

void GetSyncListString(const DatanodeSyncList *syncList, char *syncListString, size_t maxLen);

void ProcessHotpatchMessage(MsgRecvInfo* recvMsgInfo, cm_hotpatch_msg *hotpatch_msg);
void process_to_query_instance_status_msg(MsgRecvInfo* recvMsgInfo, const cm_query_instance_status *query_status_ptr);
void SetAgentDataReportMsg(MsgRecvInfo* recvMsgInfo, CM_StringInfo inBuffer);
void ProcessStopArbitrationMessage(void);
void process_finish_redo_message(MsgRecvInfo* recvMsgInfo);
void process_finish_redo_check_message(MsgRecvInfo* recvMsgInfo);
void ProcessDnBarrierinfo(MsgRecvInfo* recvMsgInfo, CM_StringInfo inBuffer);
void ProcessCnBarrierinfo(MsgRecvInfo* recvMsgInfo, CM_StringInfo inBuffer);
void FlushCmToAgentMsg(MsgRecvInfo* recvMsgInfo, int msgType);
void InitCltCmdProc(void);
void SetSwitchoverPendingCmd(
    uint32 groupIdx, int32 memIdx, int32 waitSecond, const char *str, bool isNeedDelay = false);
int CheckNotifyCnStatus();
int32 GetSwitchoverDone(const char *str);
void ProcessDnLocalPeerMsg(MsgRecvInfo* recvMsgInfo, AgentCmDnLocalPeer *dnLpInfo);
void ProcessDnMostAvailableMsg(MsgRecvInfo* recvMsgInfo, AgentToCmserverDnSyncAvailable *dnAvailInfo);
void ProcessResInstanceStatusMsg(MsgRecvInfo* recvMsgInfo, const CmsToCtlGroupResStatus *queryStatusPtr);
void ProcessCmResLock(MsgRecvInfo* recvMsgInfo, CmaToCmsResLock *lockMsg);
void ProcessQueryOneResInst(MsgRecvInfo* recvMsgInfo, const QueryOneResInstStat *queryMsg);
void ProcessCmRhbMsg(MsgRecvInfo* recvMsgInfo, const CmRhbMsg *rhbMsg);
void ProcessResIsregMsg(MsgRecvInfo *recvMsgInfo, CmaToCmsIsregMsg *isreg);
void ReleaseResLockOwner(const char *resName, uint32 instId);
void ResetResNodeStat();
void ProcessDnFloatIpMsg(MsgRecvInfo *recvMsgInfo, CmaDnFloatIpInfo *floatIp);
void GetFloatIpSet(CmFloatIpStatAck *ack, size_t maxMsgLen, size_t *curMsgLen);
void ProcessPingDnFloatIpFailedMsg(MsgRecvInfo *recvMsgInfo, CmSendPingDnFloatIpFail *failedFloatIpInfo);
void ProcessOndemandStatusMsg(MsgRecvInfo *recvMsgInfo, agent_to_cm_ondemand_status_report* ondemandStatusReport);
bool isInOnDemandStatus();
#ifdef ENABLE_MULTIPLE_NODES
void SetCmdStautus(int32 ret);
#endif

#endif
