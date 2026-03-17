/*
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
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
 * cm_msg_version_convert.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_msg_version_convert.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CM_MSG_VERSION_CONVERT
#define CM_MSG_VERSION_CONVERT

#include "cm_msg_ipv4.h"

#ifdef __cplusplus
extern "C" {
#endif

void CmToAgentLock2V1ToV2(const cm_to_agent_lock2_ipv4 *v1, cm_to_agent_lock2 *v2);
void CmToAgentLock2V2ToV1(const cm_to_agent_lock2 *v2, cm_to_agent_lock2_ipv4 *v1);
void CmLocalReplconninfoV1ToV2(const cm_local_replconninfo_ipv4 *v1, cm_local_replconninfo *v2);
void CmLocalReplconninfoV2ToV1(const cm_local_replconninfo *v2, cm_local_replconninfo_ipv4 *v1);
void AgentToCmDatanodeStatusReportV1ToV2(const agent_to_cm_datanode_status_report_ipv4 *v1,
    agent_to_cm_datanode_status_report *v2);
void AgentToCmDatanodeStatusReportV2ToV1(const agent_to_cm_datanode_status_report *v2,
    agent_to_cm_datanode_status_report_ipv4 *v1);
void CmDnReportStatusMsgV1ToV2(const CmDnReportStatusMsg_ipv4 *v1, CmDnReportStatusMsg *v2);
void CmDnReportStatusMsgV2ToV1(const CmDnReportStatusMsg *v2, CmDnReportStatusMsg_ipv4 *v1);
void CmToCtlGetDatanodeRelationAckV1ToV2(const cm_to_ctl_get_datanode_relation_ack_ipv4 *v1,
    cm_to_ctl_get_datanode_relation_ack *v2);
void CmToCtlGetDatanodeRelationAckV2ToV1(const cm_to_ctl_get_datanode_relation_ack *v2,
    cm_to_ctl_get_datanode_relation_ack_ipv4 *v1);
void CmToCtlInstanceDatanodeStatusV1ToV2(const cm_to_ctl_instance_datanode_status_ipv4 *v1,
    cm_to_ctl_instance_datanode_status *v2);
void CmToCtlInstanceDatanodeStatusV2ToV1(const cm_to_ctl_instance_datanode_status *v2,
    cm_to_ctl_instance_datanode_status_ipv4 *v1);
void CmToCtlInstanceStatusV1ToV2(const cm_to_ctl_instance_status_ipv4 *v1, cm_to_ctl_instance_status *v2);
void CmToCtlInstanceStatusV2ToV1(const cm_to_ctl_instance_status *v2, cm_to_ctl_instance_status_ipv4 *v1);
void GetCtlInstanceStatusFromRecvMsg(char *receiveMsg, cm_to_ctl_instance_status *ctlInstanceStatusPtr);

#ifdef __cplusplus
}
#endif
#endif