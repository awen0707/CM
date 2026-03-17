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
 * cms_arbitrate_datanode.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_server/cms_arbitrate_datanode.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CMS_ARBITRATE_DATANODE_H
#define CMS_ARBITRATE_DATANODE_H

#include "cm/cm_msg.h"
#include "cm_server.h"
#include "cms_global_params.h"

typedef struct _db_state {
    uint32 node;
    int instance_id;
    int local_dynamic_role;
    int local_db_state;
    int group_index;
    int member_index;
} db_state_role;

extern uint32 find_primary_term(uint32 group_index);
extern uint32 ReadTermFromDdb(uint32 groupIdx);
bool check_datanode_arbitrate_status(uint32 group_index, int member_index);

cm_instance_datanode_report_status &GetDataNodeMember(const uint32 &group, const int &member);

int find_candiate_primary_node_in_instance_role_group(uint32 group_index, int member_index);
int find_auto_switchover_primary_node(uint32 group_index, int member_index);

void datanode_instance_arbitrate_for_psd(
    MsgRecvInfo* recvMsgInfo, const agent_to_cm_datanode_status_report *status_ptr);
void datanode_instance_arbitrate_new(
    MsgRecvInfo* recvMsgInfo, agent_to_cm_datanode_status_report* agent_to_cm_datanode_status_ptr,
    uint32 group_index, int member_index, maintenance_mode mode);
void datanode_instance_arbitrate_single(
    MsgRecvInfo* recvMsgInfo, const agent_to_cm_datanode_status_report* agent_to_cm_datanode_status_ptr);

void DealDataNodeDBStateChange(const uint32 &group, const int &member, const int &dbStatePrev);
void NotifyDatanodeDynamicPrimary(
    MsgRecvInfo* recvMsgInfo, const uint32 &node, const uint32 &instanceId, const uint32 &group, const int &member);

#endif
