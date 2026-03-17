/*
 * Copyright (c) 2021 Huawei Technologies Co.,Ltd.
 *
 * CM is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 * http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * -------------------------------------------------------------------------
 *
 * cms_main.h
 *
 *
 * IDENTIFICATION
 * include/cm/cm_server/cms_main.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CMS_MAIN_H
#define CMS_MAIN_H

#define MAX_UNAUTH_CONN 10000

#ifdef ENABLE_MULTIPLE_NODES
#include "cm_msg.h"
typedef struct _exec_msg_ {
    uint32 localPort;
    uint32 peerPort;
    char *local_listen_ip;
    char *peer_listen_ip;
    char *input_local_listen_ip;
    char *input_peer_listen_ip;
    int *node_index;
    int *instance_index;
} execParam;

int CmNotifyCnMsgInit(cm_notify_msg_status **notifyMsg);
int SearchHaGtmNode(const execParam *para);
void BuildDynamicCoordConfig(cm_instance_role_group *instance_group, bool *dynamicModified, int i);
void BuildDynamicGtmMazConfig(cm_instance_role_group *instance_group, bool *dynamicModified, int i);
void BuildDynamicGtmSazConfig(cm_instance_role_group *instGrp, bool *dynamicModified, int32 i);
void BuildDynamicDnMazConfig(cm_instance_role_group *instance_group, bool *dynamicModified, int i, int j);
void BuildDynamicDnSazConfigIfSucc(
    cm_instance_role_group *instGrp, int32 i, int32 j, int32 curNodeIdx, int32 curInstIdx);
void BuildDynamicDnSazConfig(cm_instance_role_group *instance_group, bool *dynamicModified, int i, int j);
int BuildDynamicConfigFile(bool *dynamicModified);
int AddNodeInDynamicConfigure(const cm_instance_role_group *instance_role_group_ptr);
int search_HA_node(int node_type, uint32 localPort, uint32 LocalHAListenCount, const char (*LocalHAIP)[CM_IP_LENGTH],
    uint32 peerPort, uint32 PeerHAListenCount, const char (*PeerHAIP)[CM_IP_LENGTH], int *node_index,
    int *instance_index);
#endif

#endif
