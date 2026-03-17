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
 * cms_process_messages_hadr.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_server/cms_process_messages_hadr.cpp
 *
 * -------------------------------------------------------------------------
 */
#include "cms_common.h"
#include "cms_global_params.h"
#include "cms_process_messages.h"

void ProcessCtl2CmOneInstanceBarrierQueryMsg(
    MsgRecvInfo* recvMsgInfo, uint32 node, uint32 instanceId, int instanceType)
{
    uint32 groupIndex = 0;
    int memberIndex = 0;
    int ret;
    cm_to_ctl_instance_barrier_info cm2CtlBarrierContent = {0};
    errno_t rc;

    ret = find_node_in_dynamic_configure(node, instanceId, &groupIndex, &memberIndex);
    if (ret != 0) {
        write_runlog2(
            LOG, errmsg("can't find the instance(node =%u  instanceid =%u)\n", node, instanceId), errmodule(MOD_CMS));
        return;
    }

    cm2CtlBarrierContent.msg_type = (int)MSG_CM_CTL_GLOBAL_BARRIER_DATA;
    cm2CtlBarrierContent.node = node;
    cm2CtlBarrierContent.instanceId = instanceId;
    cm2CtlBarrierContent.instance_type = instanceType;
    if (instanceType == INSTANCE_TYPE_COORDINATE) {
        rc = memcpy_s(cm2CtlBarrierContent.barrierID, BARRIERLEN,
            g_instance_group_report_status_ptr[groupIndex].instance_status.coordinatemember.barrierID, BARRIERLEN);
        securec_check_errno(rc, (void)rc);
    } else if (instanceType == INSTANCE_TYPE_DATANODE) {
        cm_instance_datanode_report_status *curDn =
            &g_instance_group_report_status_ptr[groupIndex].instance_status.data_node_member[memberIndex];
        rc = memcpy_s(cm2CtlBarrierContent.barrierID, BARRIERLEN, curDn->barrierID, BARRIERLEN);
        securec_check_errno(rc, (void)rc);
    }

    (void)RespondMsg(recvMsgInfo, 'S', (char *)(&cm2CtlBarrierContent), sizeof(cm_to_ctl_instance_barrier_info));
}

void ProcessCtlToCmQueryGlobalBarrierMsg(MsgRecvInfo* recvMsgInfo)
{
    cm_to_ctl_cluster_global_barrier_info globalBarrierInfo = {0};
    globalBarrierInfo.msg_type = (int)MSG_CM_CTL_GLOBAL_BARRIER_DATA_BEGIN;

    /* Get the global_barrierId from the etcd key `queryvalue` */
    errno_t rc = strncpy_s(globalBarrierInfo.global_barrierId, BARRIERLEN, g_queryBarrier, BARRIERLEN - 1);
    securec_check_errno(rc, (void)rc);
    /* Get the global_recovery_barrierId from the etcd key `targetvalue` */
    rc = strncpy_s(globalBarrierInfo.globalRecoveryBarrierId, BARRIERLEN, g_targetBarrier, BARRIERLEN - 1);
    securec_check_errno(rc, (void)rc);

    (void)RespondMsg(recvMsgInfo, 'S', (char *)(&globalBarrierInfo), sizeof(cm_to_ctl_cluster_global_barrier_info));
}

void ProcessCtlToCmQueryBarrierMsg(MsgRecvInfo* recvMsgInfo)
{
    ProcessCtlToCmQueryGlobalBarrierMsg(recvMsgInfo);
    uint32 i;
    cm_to_ctl_cluster_global_barrier_info globalBarrierInfo;

    for (i = 0; i < g_node_num; i++) {
        if (g_node[i].coordinate == 1) {
            ProcessCtl2CmOneInstanceBarrierQueryMsg(
                recvMsgInfo, g_node[i].node, g_node[i].coordinateId, INSTANCE_TYPE_COORDINATE);
        }

        for (uint32 j = 0; j < g_node[i].datanodeCount; j++) {
            ProcessCtl2CmOneInstanceBarrierQueryMsg(
                recvMsgInfo, g_node[i].node, g_node[i].datanode[j].datanodeId, INSTANCE_TYPE_DATANODE);
        }
    }
    globalBarrierInfo.msg_type = (int)MSG_CM_CTL_BARRIER_DATA_END;
    (void)RespondMsg(recvMsgInfo, 'S', (char *)(&globalBarrierInfo), sizeof(cm_to_ctl_cluster_global_barrier_info));
}

void ProcessSharedStorageMsg(MsgRecvInfo* recvMsgInfo)
{
    errno_t rc;
    CmsSharedStorageInfo sendMsg = {0};

    sendMsg.msg_type = (int)MSG_GET_SHARED_STORAGE_INFO_ACK;

    if (g_doradoIp[0] == '\0') {
        rc = strcpy_s(sendMsg.doradoIp, CM_IP_LENGTH, "unknown");
        securec_check_errno(rc, (void)rc);
    } else {
        rc = strcpy_s(sendMsg.doradoIp, CM_IP_LENGTH, g_doradoIp);
        securec_check_errno(rc, (void)rc);
    }
    (void)RespondMsg(recvMsgInfo, 'S', (char *)(&sendMsg), sizeof(sendMsg), DEBUG5);

    return;
}
