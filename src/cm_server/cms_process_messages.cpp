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
 * cms_process_messages.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_server/cms_process_messages.cpp
 *
 * -------------------------------------------------------------------------
 */
#include <vector>
#include "cms_global_params.h"
#include "cms_arbitrate_datanode.h"
#include "cms_ddb.h"
#include "cms_az.h"
#include "cms_common.h"
#include "cms_common_res.h"
#include "cms_cus_res.h"
#include "cms_arbitrate_datanode_pms.h"
#include "cms_rhb.h"
#ifdef ENABLE_MULTIPLE_NODES
#include "cms_cn.h"
#include "cms_arbitrate_gtm.h"
#endif
#include "cms_arbitrate_cluster.h"
#include "cms_process_messages.h"

const int DOUBLE_REPLICATION = 2;

#define PROCESS_MSG_BY_TYPE_WITHOUT_CONN(struct_name, strunct_ptr, function_name) \
    do {                                                                             \
        (strunct_ptr) = (struct_name *)CmGetmsgbytes((CM_StringInfo)&recvMsgInfo->msg, sizeof(struct_name)); \
        if ((strunct_ptr) != NULL) {                                                 \
            (function_name)((strunct_ptr));                                          \
        } else {                                                                     \
            write_runlog(ERROR, "CmGetmsgbytes failed, msg_type=%d.\n", msgType);    \
        }                                                                            \
    } while (0)

typedef struct _init_node_ {
    int dnNum[AZ_MEMBER_MAX_COUNT];
    int primaryDn;
    int normalPrimaryDn;
    int normalStandbyDn[AZ_MEMBER_MAX_COUNT];
    int norPrimInCurSL;
    int normStdbInCurSL;
    int normalVoteAzStandby;
    int normalVoteAzPrimary;
    uint32 primaryId;
    uint32 primInVA;
    int32 casStandby;
    int32 casNorStandby;
    int32 curStatus;
    char primaryStr[MAX_PATH_LEN];
    char standbyStr[MAX_PATH_LEN];
    char casStr[MAX_PATH_LEN];
    char casNorStr[MAX_PATH_LEN];
    char methodStr[MAX_PATH_LEN];
} InitNodeMsg;

typedef struct {
    int index;
    time_t time;
} onDemandStatusItem;

CltCmdProc g_cmdProc[MSG_CM_TYPE_CEIL] = {0};

static bool judgeHAStatus(const int* normalStandbyDn, const int* dnNum, int azIndex, uint32 groupIndex)
{
    bool haNeedRepair = false;
    const int one_hundred = 100;
    const int aliveDnRate = 50;
    const int primaryNum = 1;

    switch (azIndex) {
        case AZ1_INDEX:
            if (normalStandbyDn[AZ1_INDEX] * one_hundred < (dnNum[AZ1_INDEX] - primaryNum) * aliveDnRate &&
                g_dn_replication_num > DOUBLE_REPLICATION) {
                write_runlog(WARNING,
                    "cluster is unavailable, synchronous_standby_mode is %d, normalStandbyDn in az1 is: %d, "
                    "one of member in this group is dn_%u.\n.",
                    (int32)current_cluster_az_status,
                    normalStandbyDn[AZ1_INDEX],
                    g_instance_role_group_ptr[groupIndex].instanceMember[0].instanceId);
                haNeedRepair = true;
            }
            break;
        case AZ2_INDEX:
            if (normalStandbyDn[AZ2_INDEX] * one_hundred < (dnNum[AZ2_INDEX] - primaryNum) * aliveDnRate &&
                g_dn_replication_num > DOUBLE_REPLICATION) {
                write_runlog(WARNING,
                    "cluster is unavailable, synchronous_standby_mode is %d, normalStandbyDn in az2 is: %d, "
                    "one of member in this group is dn_%u.\n.",
                    (int32)current_cluster_az_status,
                    normalStandbyDn[AZ2_INDEX],
                    g_instance_role_group_ptr[groupIndex].instanceMember[0].instanceId);
                haNeedRepair = true;
            }
            break;
        case AZ_ALL_INDEX:
            if ((normalStandbyDn[AZ1_INDEX] + normalStandbyDn[AZ2_INDEX]) * one_hundred <
                    (dnNum[AZ1_INDEX] + dnNum[AZ2_INDEX] - primaryNum) * aliveDnRate &&
                g_dn_replication_num > DOUBLE_REPLICATION) {
                write_runlog(WARNING,
                    "cluster is unavailable, synchronous_standby_mode is %d, normalStandbyDn in az1 is: %d, "
                    "normalStandbyDn in az2 is: %d, one of member in this group is dn_%u.\n.",
                    (int32)current_cluster_az_status,
                    normalStandbyDn[AZ1_INDEX],
                    normalStandbyDn[AZ2_INDEX],
                    g_instance_role_group_ptr[groupIndex].instanceMember[0].instanceId);
                haNeedRepair = true;
            }
            break;
        default:
            break;
    }

    return haNeedRepair;
}

int findAzIndex(const char azArray[][CM_AZ_NAME], const char* azName)
{
    for (int j = 0; j < AZ_MEMBER_MAX_COUNT; j++) {
        if (strcmp(azName, *(azArray + j)) == 0) {
            return j;
        }
    }
    return -1;
}
void getAZDyanmicStatus(int azCount, int* statusOnline, int* statusPrimary, int* statusFail,
    int* statusDnFail, const char azArray[][CM_AZ_NAME])
{
    for (uint32 i = 0; i < g_dynamic_header->relationCount; i++) {
        int tmpStatusDnOnline[AZ_MEMBER_MAX_COUNT] = {0};
        bool findDN = false;
        int count = g_instance_role_group_ptr[i].count;

        for (int32 j = 0; j < count; j++) {
            int azIndex = findAzIndex(azArray, g_instance_role_group_ptr[i].instanceMember[j].azName);
            if (azIndex < 0 || azIndex >= azCount) {
                write_runlog(FATAL,
                    "a unexpected az name %s when find azindex.\n",
                    g_instance_role_group_ptr[i].instanceMember[j].azName);
                FreeNotifyMsg();
                exit(1);
            }

            if ((g_instance_role_group_ptr[i].instanceMember[j].instanceType == INSTANCE_TYPE_DATANODE) &&
                (g_instance_group_report_status_ptr[i].instance_status.data_node_member[j].local_status.local_role !=
                    INSTANCE_ROLE_UNKNOWN)) {
                (*(statusOnline + azIndex))++;
                tmpStatusDnOnline[azIndex]++;
                findDN = true;
            }
            if ((g_instance_role_group_ptr[i].instanceMember[j].instanceType == INSTANCE_TYPE_DATANODE) &&
                (g_instance_group_report_status_ptr[i].instance_status.data_node_member[j].local_status.local_role ==
                    INSTANCE_ROLE_PRIMARY)) {
                (*(statusPrimary + azIndex))++;
                findDN = true;
            }
            if ((g_instance_role_group_ptr[i].instanceMember[j].instanceType == INSTANCE_TYPE_DATANODE) &&
                (g_instance_group_report_status_ptr[i].instance_status.data_node_member[j].local_status.local_role ==
                    INSTANCE_ROLE_UNKNOWN)) {
                (*(statusFail + azIndex))++;
                findDN = true;
            }
        }
        if (findDN && tmpStatusDnOnline[AZ1_INDEX] <= 0) {
            (*(statusDnFail + AZ1_INDEX))++;
        } else if (findDN && tmpStatusDnOnline[AZ2_INDEX] <= 0) {
            (*(statusDnFail + AZ2_INDEX))++;
        } else {
            /* don't have failed DN */
        }
    }
}

void CheckCoordinateStatus(uint32 *abnormal_cn_count, uint32 i)
{
    if (g_instance_role_group_ptr[i].instanceMember[0].role == INSTANCE_ROLE_DELETED ||
        g_instance_role_group_ptr[i].instanceMember[0].role == INSTANCE_ROLE_DELETING ||
        g_instance_group_report_status_ptr[i].instance_status.coordinatemember.status.status != INSTANCE_ROLE_NORMAL ||
        (g_instance_group_report_status_ptr[i].instance_status.coordinatemember.status.status == INSTANCE_ROLE_NORMAL &&
        g_instance_group_report_status_ptr[i].instance_status.coordinatemember.status.db_state ==
        INSTANCE_HA_STATE_STARTING)) {
        (*abnormal_cn_count)++;
    }

    return;
}

status_t CheckGtmStatusOnSingleNode(uint32 i)
{
    if (g_instance_group_report_status_ptr[i].instance_status.gtm_member[0].local_status.local_role ==
        INSTANCE_ROLE_PRIMARY) {
        return CM_SUCCESS;
    }
    write_runlog(LOG,
        "CheckClusterStatus: gtm[%u][0]: local_role=%d \n", i,
        g_instance_group_report_status_ptr[i].instance_status.gtm_member[0].local_status.local_role);
    g_HA_status->status = CM_STATUS_NEED_REPAIR;
    return CM_ERROR;
}

void CheckGtmStatusCond1(bool *cond1, bool *cond2, bool *cond3, bool *cond4, uint32 i)
{
    *cond1 = ((g_instance_group_report_status_ptr[i].instance_status.gtm_member[0].local_status.local_role ==
                  INSTANCE_ROLE_PRIMARY) &&
              (g_instance_group_report_status_ptr[i].instance_status.gtm_member[1].local_status.local_role ==
                  INSTANCE_ROLE_STANDBY) &&
              (g_instance_group_report_status_ptr[i].instance_status.gtm_member[0].local_status.connect_status ==
                  CON_OK) &&
              (g_instance_group_report_status_ptr[i].instance_status.gtm_member[1].local_status.connect_status ==
                  CON_OK) &&
              (g_instance_group_report_status_ptr[i].instance_status.gtm_member[0].local_status.sync_mode ==
                  INSTANCE_DATA_REPLICATION_SYNC));
    *cond2 = ((g_instance_group_report_status_ptr[i].instance_status.gtm_member[1].local_status.local_role ==
                  INSTANCE_ROLE_PRIMARY) &&
              (g_instance_group_report_status_ptr[i].instance_status.gtm_member[0].local_status.local_role ==
                  INSTANCE_ROLE_STANDBY) &&
              (g_instance_group_report_status_ptr[i].instance_status.gtm_member[0].local_status.connect_status ==
                  CON_OK) &&
              (g_instance_group_report_status_ptr[i].instance_status.gtm_member[1].local_status.connect_status ==
                  CON_OK) &&
              (g_instance_group_report_status_ptr[i].instance_status.gtm_member[1].local_status.sync_mode ==
                  INSTANCE_DATA_REPLICATION_SYNC));
    *cond3 = ((g_instance_group_report_status_ptr[i].instance_status.gtm_member[0].local_status.local_role ==
                  INSTANCE_ROLE_PRIMARY) &&
              (g_instance_group_report_status_ptr[i].instance_status.gtm_member[1].local_status.local_role !=
                  INSTANCE_ROLE_PRIMARY) &&
              ((g_instance_group_report_status_ptr[i].instance_status.gtm_member[0].local_status.sync_mode ==
                   INSTANCE_DATA_REPLICATION_MOST_AVAILABLE) ||
                  (g_etcd_num > 0)));
    *cond4 = ((g_instance_group_report_status_ptr[i].instance_status.gtm_member[1].local_status.local_role ==
                  INSTANCE_ROLE_PRIMARY) &&
              (g_instance_group_report_status_ptr[i].instance_status.gtm_member[0].local_status.local_role !=
                  INSTANCE_ROLE_PRIMARY) &&
              ((g_instance_group_report_status_ptr[i].instance_status.gtm_member[1].local_status.sync_mode ==
                   INSTANCE_DATA_REPLICATION_MOST_AVAILABLE) ||
                  (g_etcd_num > 0)));
    return;
}

int CheckGtmSingleAzStatus(uint32 i)
{
    bool cond1, cond2, cond3, cond4;
    CheckGtmStatusCond1(&cond1, &cond2, &cond3, &cond4, i);
    if (cond1) {
    } else if (cond2) {
    } else if (cond3) {
        g_HA_status->status = CM_STATUS_DEGRADE;
        write_runlog(LOG, "Line:%d, gtm primary is most available\n", __LINE__);
    } else if (cond4) {
        g_HA_status->status = CM_STATUS_DEGRADE;
        write_runlog(LOG, "Line:%d, gtm primary is most available\n", __LINE__);
    } else {
        write_runlog(LOG,
            "CheckClusterStatus: gtm[%u][0]: local_role=%d, connect_status=%d, sync_mode=%d;   "
            "gtm[%u][1]: local_role=%d, connect_status=%d, sync_mode=%d, etcd_num=%u\n",
            i,
            g_instance_group_report_status_ptr[i].instance_status.gtm_member[0].local_status.local_role,
            g_instance_group_report_status_ptr[i].instance_status.gtm_member[0].local_status.connect_status,
            g_instance_group_report_status_ptr[i].instance_status.gtm_member[0].local_status.sync_mode,
            i,
            g_instance_group_report_status_ptr[i].instance_status.gtm_member[1].local_status.local_role,
            g_instance_group_report_status_ptr[i].instance_status.gtm_member[1].local_status.connect_status,
            g_instance_group_report_status_ptr[i].instance_status.gtm_member[1].local_status.sync_mode,
            g_etcd_num);

        g_HA_status->status = CM_STATUS_NEED_REPAIR;
        return -1;
    }
    return 0;
}

int CheckGtmMultiAzStatus(uint32 i)
{
    bool findPrimary = false;
    bool findDown = false;
    bool findPending = false;

    for (uint32 gtmId = 0; gtmId < g_gtm_num; gtmId++) {
        if (g_instance_group_report_status_ptr[i].instance_status.gtm_member[gtmId].local_status.local_role ==
            INSTANCE_ROLE_PRIMARY) {
            findPrimary = true;
        } else if (g_instance_group_report_status_ptr[i].instance_status.gtm_member[gtmId].local_status.local_role !=
                    INSTANCE_ROLE_PRIMARY &&
                   g_instance_group_report_status_ptr[i].instance_status.gtm_member[gtmId].local_status.local_role !=
                    INSTANCE_ROLE_STANDBY &&
                   g_instance_group_report_status_ptr[i].instance_status.gtm_member[gtmId].local_status.local_role !=
                    INSTANCE_ROLE_PENDING) {
            findDown = true;
        } else if (g_instance_group_report_status_ptr[i].instance_status.gtm_member[gtmId].local_status.local_role ==
                   INSTANCE_ROLE_PENDING) {
            findPending = true;
        }
    }
    if (!findPrimary) {
        write_runlog(LOG, "there is no gtm primary.\n");
        g_HA_status->status = CM_STATUS_NEED_REPAIR;
        return -1;
    } else if ((findDown && findPrimary) || (findPending && findPrimary)) {
        g_HA_status->status = CM_STATUS_DEGRADE;
    } else {
    }

    return 0;
}

int  CheckGtmStatus(uint32 i)
{
    int ret = 0;
    if (g_single_node_cluster) {
        if (CheckGtmStatusOnSingleNode(i) != CM_SUCCESS) {
            return CM_ERROR;
        }
    }

    if (g_instance_role_group_ptr[i].count >= 2) {
        if (g_multi_az_cluster) {
            ret = CheckGtmMultiAzStatus(i);
        } else {
            ret = CheckGtmSingleAzStatus(i);
        }
    }
    return ret;
}

status_t CheckSingleDataNodeStatus(uint32 i)
{
    if ((g_instance_group_report_status_ptr[i].instance_status.data_node_member[0].local_status.local_role ==
        INSTANCE_ROLE_PRIMARY ||
        g_instance_group_report_status_ptr[i].instance_status.data_node_member[0].local_status.local_role ==
        INSTANCE_ROLE_NORMAL) &&
        g_instance_group_report_status_ptr[i].instance_status.data_node_member[0].local_status.db_state ==
        INSTANCE_HA_STATE_NORMAL) {
        return CM_SUCCESS;
    }
    write_runlog(LOG, "CheckClusterStatus: DN[%u][0]: local_role=%d, db_state=%d\n", i,
        g_instance_group_report_status_ptr[i].instance_status.data_node_member[0].local_status.local_role,
        g_instance_group_report_status_ptr[i].instance_status.data_node_member[0].local_status.db_state);

    g_HA_status->status = CM_STATUS_NEED_REPAIR;
    return CM_ERROR;
}

status_t GetDataNodeAzIndex(uint32 priority, uint32 i, int j, int *azIndex)
{
    if (priority < g_az_master) {
        write_runlog(ERROR,
            "az name is %s, priority=%u is invalid.\n",
            g_instance_role_group_ptr[i].instanceMember[j].azName,
            priority);
        g_HA_status->status = CM_STATUS_NEED_REPAIR;
        return CM_ERROR;
    } else if (priority >= g_az_master && priority < g_az_slave) {
        *azIndex = AZ1_INDEX;
    } else if (priority >= g_az_slave && priority < g_az_arbiter) {
        *azIndex = AZ2_INDEX;
    } else {
        *azIndex = AZ3_INDEX;
    }
    return CM_SUCCESS;
}

void GetInstanceStrInfo(uint32 instId, char *instInfo, uint32 len)
{
    char instStr[MAX_PATH_LEN] = {0};
    errno_t rc = snprintf_s(instStr, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%u, ", instId);
    securec_check_intval(rc, (void)rc);
    rc = strcat_s(instInfo, len, instStr);
    securec_check_errno(rc, (void)rc);
}

static void InitMultiAzDataNodePrimaryStatus(uint32 groupIdx, int memberIdx, InitNodeMsg *nodeMsg)
{
    cm_instance_role_status *dnRole = &(g_instance_role_group_ptr[groupIdx].instanceMember[memberIdx]);
    cm_instance_report_status *instRep = &(g_instance_group_report_status_ptr[groupIdx].instance_status);
    int status = instRep->data_node_member[memberIdx].local_status.db_state;
    nodeMsg->primaryDn++;
    if (status == INSTANCE_HA_STATE_NORMAL) {
        nodeMsg->normalPrimaryDn++;
        if (IsInstanceIdInSyncList(dnRole->instanceId, &(instRep->currentSyncList))) {
            ++nodeMsg->norPrimInCurSL;
            nodeMsg->primaryId = dnRole->instanceId;
        } else if (IsCurInstanceInVoteAz(groupIdx, memberIdx)) {
            ++nodeMsg->normalVoteAzPrimary;
            nodeMsg->primInVA = dnRole->instanceId;
        }
        GetInstanceStrInfo(dnRole->instanceId, nodeMsg->primaryStr, MAX_PATH_LEN);
    }
}

static bool InitCascadeStandbyMsg(
    const cm_instance_role_status *dnRole, InitNodeMsg *nodeMsg, int32 localRole, bool statusNormal)
{
    if (dnRole->role != INSTANCE_ROLE_CASCADE_STANDBY) {
        return false;
    }
    ++nodeMsg->casStandby;
    GetInstanceStrInfo(dnRole->instanceId, nodeMsg->casStr, MAX_PATH_LEN);
    if (localRole == INSTANCE_ROLE_CASCADE_STANDBY && statusNormal) {
        ++nodeMsg->casNorStandby;
        GetInstanceStrInfo(dnRole->instanceId, nodeMsg->casNorStr, MAX_PATH_LEN);
    }
    return true;
}

static bool SatisfyNormalConditions(int dbState, int buildReason)
{
    if (dbState == INSTANCE_HA_STATE_NORMAL || dbState == INSTANCE_HA_STATE_CATCH_UP) {
        return true;
    }
    if (backup_open == CLUSTER_OBS_STANDBY && g_clusterInstallType == INSTALL_TYPE_SHARE_STORAGE &&
        dbState == INSTANCE_HA_STATE_NEED_REPAIR &&
        (buildReason == INSTANCE_HA_DATANODE_BUILD_REASON_DISCONNECT ||
        buildReason == INSTANCE_HA_DATANODE_BUILD_REASON_CONNECTING)) {
        return true;
    }
    return false;
}

status_t InitMultiAzDataNodeStatus(uint32 i, int *minorityAz, InitNodeMsg *nodeMsg)
{
    int groupDnNum = g_instance_role_group_ptr[i].count;
    status_t ret = CM_SUCCESS;

    /* step1: init dn information */
    cm_instance_role_status *dnRole = NULL;
    cm_instance_report_status *instRep = &(g_instance_group_report_status_ptr[i].instance_status);
    for (int j = 0; j < groupDnNum; j++) {
        int localRole = instRep->data_node_member[j].local_status.local_role;
        int status = instRep->data_node_member[j].local_status.db_state;
        int buildReason = instRep->data_node_member[j].local_status.buildReason;
        bool statusNormal = (status == INSTANCE_HA_STATE_NORMAL || status == INSTANCE_HA_STATE_CATCH_UP);
        int azIndex = 0;
        dnRole = &(g_instance_role_group_ptr[i].instanceMember[j]);
        if (g_only_dn_cluster && strlen(dnRole->azName) == 0) {
            azIndex = AZ1_INDEX;
        } else {
            ret = GetDataNodeAzIndex(dnRole->azPriority, i, j, &azIndex);
            if (ret != CM_SUCCESS) {
                return CM_ERROR;
            }
        }
        nodeMsg->dnNum[azIndex]++;
        if (IsNodeInMinorityAz(i, j)) {
            *minorityAz = azIndex;
        }

        // if the dn is cascade standby, cannot calculate it's dynamic role.
        if (InitCascadeStandbyMsg(dnRole, nodeMsg, localRole, statusNormal)) {
            continue;
        }
        if (localRole == INSTANCE_ROLE_PRIMARY) {
            InitMultiAzDataNodePrimaryStatus(i, j, nodeMsg);
        } else if (localRole == INSTANCE_ROLE_STANDBY && SatisfyNormalConditions(status, buildReason)) {
            nodeMsg->normalStandbyDn[azIndex]++;
            if (IsInstanceIdInSyncList(dnRole->instanceId, &(instRep->currentSyncList))) {
                ++nodeMsg->normStdbInCurSL;
            } else if (IsCurInstanceInVoteAz(i, j)) {
                ++nodeMsg->normalVoteAzStandby;
            }
            GetInstanceStrInfo(dnRole->instanceId, nodeMsg->standbyStr, MAX_PATH_LEN);
        }
    }
    return CM_SUCCESS;
}

int ProcessDataNodeStatusObsStandby(int normalStandbyDnSum, int groupDnNum)
{
    if ((normalStandbyDnSum < groupDnNum && normalStandbyDnSum > groupDnNum / 2) ||
        (g_dn_replication_num == DOUBLE_REPLICATION && normalStandbyDnSum == 1)) {
        g_HA_status->status = CM_STATUS_DEGRADE;
    } else if (normalStandbyDnSum <= groupDnNum / 2) {
        g_HA_status->status = CM_STATUS_NEED_REPAIR;
        return -1;
    }
    return 0;
}

int ProcessDataNodeStatusStreamingStandby(int normalStandbyDnSum, int groupDnNum, const InitNodeMsg *nodeMsg)
{
    const int majority = 2;
    write_runlog(LOG, "streaming standby cluster, groupDnNum=%d, primaryDn=%d, normalPrimaryDn=%d,"
        "normalStandbyDnSum=%d\n", groupDnNum, nodeMsg->primaryDn, nodeMsg->normalPrimaryDn, normalStandbyDnSum);
    if (nodeMsg->primaryDn != 1 || (normalStandbyDnSum < groupDnNum / majority && groupDnNum > DOUBLE_REPLICATION)) {
        g_HA_status->status = CM_STATUS_NEED_REPAIR;
        write_runlog(WARNING, "streaming standby cluster unavailable\n");
        return -1;
    }
    if (nodeMsg->normalPrimaryDn + normalStandbyDnSum < groupDnNum) {
        g_HA_status->status = CM_STATUS_DEGRADE;
        write_runlog(WARNING, "streaming standby cluster degrade\n");
    }
    return 0;
}

int ProcessHaStatusWhenCmsMinority(
    int normalStandbyDnSum, const int *dnNum, int minorityAz, int normalPrimaryDn)
{
    const int32 half = 2;
    if (normalPrimaryDn != 1 ||
        (dnNum[minorityAz] > DOUBLE_REPLICATION && normalStandbyDnSum <= (dnNum[minorityAz] / half))) {
        write_runlog(WARNING,
            "cluster is unavailable in minority(%s) when normalPrimaryDn=%d, "
            "normalStandbyDnSum=%d.\n"
            "azDnNum=%d.\n",
            g_minorityAzName,
            normalPrimaryDn,
            normalStandbyDnSum,
            dnNum[minorityAz]);
        g_HA_status->status = CM_STATUS_NEED_REPAIR;
        return -1;
    }
    g_HA_status->status = CM_STATUS_DEGRADE;
    return 1;
}

status_t ProcessHaStatusWhenException(int normalStandbyDnSum, int groupDnNum, int normalPrimaryDn)
{
    if (normalPrimaryDn != 1 || normalStandbyDnSum >= groupDnNum || normalStandbyDnSum < 0 ||
        (normalStandbyDnSum == 0 && g_dn_replication_num > 2)) {
        write_runlog(WARNING,
            "cluster is unavailable when normalPrimaryDn=%d, normalStandbyDnSum=%d.\n",
            normalPrimaryDn,
            normalStandbyDnSum);
        g_HA_status->status = CM_STATUS_NEED_REPAIR;
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

int ProcessHaStatusWhenNoBackup(int normalStandbyDnSum, int groupDnNum, int minorityAz, const InitNodeMsg *nodeMsg)
{
    int normalPrimaryDn = nodeMsg->normalPrimaryDn;
    if ((cm_arbitration_mode == MINORITY_ARBITRATION || cm_server_start_mode == MINORITY_START) && minorityAz != -1) {
        return ProcessHaStatusWhenCmsMinority(normalStandbyDnSum, nodeMsg->dnNum, minorityAz, normalPrimaryDn);
    }
    if (g_clusterInstallType == INSTALL_TYPE_SHARE_STORAGE) {
        if (normalPrimaryDn + normalStandbyDnSum < groupDnNum && normalPrimaryDn == 1) {
            g_HA_status->status = CM_STATUS_DEGRADE;
            write_runlog(WARNING, "cluster is unavailable when normalPrimaryDn=%d, normalStandbyDnSum=%d.\n",
                normalPrimaryDn, normalStandbyDnSum);
            return 0;
        }
    }
    status_t ret = ProcessHaStatusWhenException(normalStandbyDnSum, groupDnNum, normalPrimaryDn);
    if (ret != CM_SUCCESS) {
        return (int)ret;
    }

    if (normalPrimaryDn == 1 && normalStandbyDnSum > 0 && normalStandbyDnSum < (groupDnNum - 1) && !g_only_dn_cluster) {
        g_HA_status->status = CM_STATUS_DEGRADE;
    } else if (normalPrimaryDn == 1 && normalStandbyDnSum < ((groupDnNum - 1) - nodeMsg->casStandby) &&
               (((normalPrimaryDn + normalStandbyDnSum) * 2 > ((int)g_dn_replication_num) - nodeMsg->casStandby) ||
                   (g_dn_replication_num == DOUBLE_REPLICATION))) {
        /* g_dn_replication_num == 2 means one primary + one standby, when standby is down,
        the cluster is degrade, the primary will continue to run without standby */
        g_HA_status->status = CM_STATUS_DEGRADE;
        write_runlog(LOG, "Line:%d, standby is not normal, normalStandbyDnSum=%d\n", __LINE__, normalStandbyDnSum);
    }
    return 0;
}

static void PrintClusterStatus(uint32 groupIdx, int32 groupDnNum, int normalStandbyDnSum, const InitNodeMsg *nodeMsg)
{
    if (nodeMsg->curStatus == 0 && log_min_messages > LOG) {
        return;
    }
    uint32 instId = g_instance_role_group_ptr[groupIdx].instanceMember[0].instanceId;
    cm_instance_report_status *report = &(g_instance_group_report_status_ptr[groupIdx].instance_status);
    int count = (report->currentSyncList.count == 0) ? groupDnNum : report->currentSyncList.count;
    char syncList[MAX_PATH_LEN] = {0};
    char voteAzList[MAX_PATH_LEN] = {0};
    GetSyncListString(&(report->currentSyncList), syncList, MAX_PATH_LEN);
    GetDnStatusString(&(report->voteAzInstance), voteAzList, MAX_PATH_LEN);
    write_runlog(LOG, "%s: instanceId(%u) count: %d, groupDnNum: %d, normalStandbyDnSum: %d ,"
        "dn status:[primary: [%s], standby:[%s], cascade:[(%s): (%s)]], "
        "syncList: [cur: [%s], norPrim: [%d], norSdb: [%d]], "
        "voteAZ: [prim: (%u), list: [%s]], cluster_state=%d, current_cluster_az_status is %d.\n",
        nodeMsg->methodStr, instId, count, groupDnNum, normalStandbyDnSum,
        nodeMsg->primaryStr, nodeMsg->standbyStr, nodeMsg->casNorStr, nodeMsg->casStr,
        syncList, nodeMsg->norPrimInCurSL, nodeMsg->normStdbInCurSL,
        nodeMsg->primInVA, voteAzList, nodeMsg->curStatus, (int)current_cluster_az_status);
}

static void swap(onDemandStatusItem *a, onDemandStatusItem *b)
{
    onDemandStatusItem temp = *a;
    *a = *b;
    *b = temp;
}

static void sort_by_time(onDemandStatusItem sortedIndices[], int size)
{
    for (int i = 0; i < size - 1; i++) {
        for (int j = 0; j < size - 1 - i; j++) {
            if (sortedIndices[j].time < sortedIndices[j + 1].time) {
                swap(&sortedIndices[j], &sortedIndices[j + 1]);
            }
        }
    }
}

/* When cm Server recive a switchover request, should determind by the report status. */
bool isInOnDemandStatus()
{
    time_t nowTime = time(NULL);
    onDemandStatusItem sortedIndices[MAX_ONDEMAND_NODE_STATUS];
    (void)pthread_rwlock_wrlock(&(g_ondemandStatusCheckRwlock));
    for (int i = 0; i < MAX_ONDEMAND_NODE_STATUS; i++) {
        sortedIndices[i].index = i;
        sortedIndices[i].time = g_onDemandStatusTime[i];
    }
    sort_by_time(sortedIndices, MAX_ONDEMAND_NODE_STATUS);
    for (int i = 0; i < MAX_ONDEMAND_NODE_STATUS; i++) {
        write_runlog(DEBUG1,
            "Sorted Redo Status:Index: %d, Status: %d, Time: %ld\n", sortedIndices[i].index, 
                g_onDemandStatus[sortedIndices[i].index], sortedIndices[i].time);
    }
    /*
     * Because of the sort of current status, we can sure that the list of indices must 
     * contain the all seq of status. So if we get this first NOT_IN_ONDEMAND_RECOVERY
     * or IN_ONDEMAND_RECOVERY status, we can confer the clust status. If we get 
     * UNKNOW_ONDEMAND_RECOVERY, maybe the node had something wrong, it should be handled
     * by other judgement strategy.
     */
    for (int i = 0; i < MAX_ONDEMAND_NODE_STATUS; i++) {
        /* If we find timeout message, no need to judge. */
        if (difftime(nowTime, sortedIndices[i].time) >= ONDEMADN_STATUS_CHECK_TIMEOUT) {
            break;
        }
        int status = g_onDemandStatus[sortedIndices[i].index];
        if (status == IN_ONDEMAND_RECOVERY || status == NOT_IN_ONDEMAND_RECOVERY) {
            (void)pthread_rwlock_unlock(&(g_ondemandStatusCheckRwlock));
            write_runlog(DEBUG1,
                "Final Pick up Redo Status:Index: %d, Status: %d, Time: %s.\n", 
                    sortedIndices[i].index, g_onDemandStatus[sortedIndices[i].index], 
                        ctime(&sortedIndices[i].time));
            return status == IN_ONDEMAND_RECOVERY;
        }
    }
    (void)pthread_rwlock_unlock(&(g_ondemandStatusCheckRwlock));
    return false;
}

static void SetNodeMsgMethodStr(InitNodeMsg *nodeMsg, const char *str)
{
    errno_t rc = strcpy_s(nodeMsg->methodStr, MAX_PATH_LEN, str);
    securec_check_errno(rc, (void)rc);
}

static void SetNodeMsgCurState(InitNodeMsg *nodeMsg, int32 status)
{
    g_HA_status->status = status;
    nodeMsg->curStatus = status;
}

static int ProcessHaStatus2AzStartSyncThr(int count, int groupDnNum, InitNodeMsg *nodeMsg)
{
    SetNodeMsgMethodStr(nodeMsg, "[ProcessHaStatus2AzStartSyncThr]");
    // note that, number of normal standby in sync list should >= groupDnNum/2, and groupDnNum should >= 3
    if ((nodeMsg->norPrimInCurSL + nodeMsg->normalVoteAzPrimary) != 1 ||
        (g_cm_server_num > CMS_ONE_PRIMARY_ONE_STANDBY && nodeMsg->normStdbInCurSL < count / 2)) {
        SetNodeMsgCurState(nodeMsg, CM_STATUS_NEED_REPAIR);
        return -1;
    }
    if ((count + nodeMsg->normalVoteAzPrimary + nodeMsg->normalVoteAzStandby + nodeMsg->casNorStandby) != groupDnNum) {
        SetNodeMsgCurState(nodeMsg, CM_STATUS_DEGRADE);
    } else if (nodeMsg->norPrimInCurSL + nodeMsg->normStdbInCurSL < count) {
        SetNodeMsgCurState(nodeMsg, CM_STATUS_DEGRADE);
    }
    write_runlog(DEBUG1, "process ha status end, status = %d\n", g_HA_status->status);

    return 1;
}

int JudgeAz3DeployMent(const int *statusDnFail, uint32 i, InitNodeMsg *nodeMsg)
{
    SetNodeMsgMethodStr(nodeMsg, "[JudgeAz3DeployMent]");
    const int one_hundred = 100;
    /* step3: complex situation judgement, can not decide base on
    synchronous_standby_names since time delay */
    if ((statusDnFail[AZ1_INDEX] * one_hundred) / ((int)g_datanode_instance_count) < az_switchover_threshold &&
        (statusDnFail[AZ2_INDEX] * one_hundred) / ((int)g_datanode_instance_count) < az_switchover_threshold &&
        judgeHAStatus(nodeMsg->normalStandbyDn, nodeMsg->dnNum, AZ_ALL_INDEX, i)) {
        if (current_cluster_az_status < AnyAz1 || current_cluster_az_status > FirstAz2 ||
            (current_cluster_az_status >= AnyAz1 && current_cluster_az_status <= FirstAz1 &&
                judgeHAStatus(nodeMsg->normalStandbyDn, nodeMsg->dnNum, AZ1_INDEX, i)) ||
            (current_cluster_az_status >= AnyAz2 && current_cluster_az_status <= FirstAz2 &&
                judgeHAStatus(nodeMsg->normalStandbyDn, nodeMsg->dnNum, AZ2_INDEX, i))) {
            SetNodeMsgCurState(nodeMsg, CM_STATUS_NEED_REPAIR);
            write_runlog(LOG,
                "Line:%d, statusDnFail[AZ1_INDEX] = %d, statusDnFail[AZ2_INDEX] = %d\n",
                __LINE__,
                statusDnFail[AZ1_INDEX],
                statusDnFail[AZ2_INDEX]);
        }
        return -1;
    } else if ((statusDnFail[AZ1_INDEX] * one_hundred) / ((int)g_datanode_instance_count) >= az_switchover_threshold &&
               judgeHAStatus(nodeMsg->normalStandbyDn, nodeMsg->dnNum, AZ2_INDEX, i)) {
        SetNodeMsgCurState(nodeMsg, CM_STATUS_NEED_REPAIR);
        write_runlog(LOG, "Line:%d, statusDnFail[AZ2_INDEX] = %d\n", __LINE__, statusDnFail[AZ2_INDEX]);
        return -1;
    } else if ((statusDnFail[AZ2_INDEX] * one_hundred) / ((int)g_datanode_instance_count) >= az_switchover_threshold &&
               judgeHAStatus(nodeMsg->normalStandbyDn, nodeMsg->dnNum, AZ1_INDEX, i)) {
        SetNodeMsgCurState(nodeMsg, CM_STATUS_NEED_REPAIR);
        write_runlog(LOG, "Line:%d, statusDnFail[AZ1_INDEX] = %d\n", __LINE__, statusDnFail[AZ1_INDEX]);
        return -1;
    }
    if (nodeMsg->normalStandbyDn[AZ1_INDEX] != 0 && nodeMsg->normalStandbyDn[AZ2_INDEX] != 0 &&
        judgeHAStatus(nodeMsg->normalStandbyDn, nodeMsg->dnNum, AZ_ALL_INDEX, i)) {
        SetNodeMsgCurState(nodeMsg, CM_STATUS_NEED_REPAIR);
        write_runlog(LOG,
            "Line:%d, normalStandbyDn[AZ1_INDEX] = %d, normalStandbyDn[AZ2_INDEX] = %d\n",
            __LINE__,
            nodeMsg->normalStandbyDn[AZ1_INDEX],
            nodeMsg->normalStandbyDn[AZ2_INDEX]);
        return -1;
    }
    return 0;
}

static int32 CheckStatusInCascade(int32 normalStandbyDnSum, int32 groupDnNum, InitNodeMsg *nodeMsg)
{
    if (nodeMsg->casStandby == 0 || (g_isEnableUpdateSyncList != CANNOT_START_SYNCLIST_THREADS)) {
        return 0;
    }
    SetNodeMsgMethodStr(nodeMsg, "[CheckStatusInCascade]");
    if (normalStandbyDnSum < (groupDnNum - nodeMsg->casStandby) / 2 || nodeMsg->normalPrimaryDn != 1) {
        SetNodeMsgCurState(nodeMsg, CM_STATUS_NEED_REPAIR);
        return -1;
    }
    if ((normalStandbyDnSum + nodeMsg->casNorStandby) < (groupDnNum - 1)) {
        SetNodeMsgCurState(nodeMsg, CM_STATUS_DEGRADE);
    }
    return 1;
}

int ProcessHaStatus2Az(
    const int *statusDnFail, uint32 i, int normalStandbyDnSum, int groupDnNum, InitNodeMsg *nodeMsg)
{
    if (g_dn_replication_num <= DOUBLE_REPLICATION) {
        return 0;
    }
    int32 ret = CheckStatusInCascade(normalStandbyDnSum, groupDnNum, nodeMsg);
    if (ret != 0) {
        return ret;
    }
    /* if it is doing modify synclist, cluster can be degrade at most */
    if (!CompareCurWithExceptSyncList(i)) {
        SetNodeMsgMethodStr(nodeMsg, "[ProcessHaStatus2Az, CompareCurWithExceptSyncList]");
        SetNodeMsgCurState(nodeMsg, CM_STATUS_DEGRADE);
    }
    /* If AZ3 does not deploy DN, when DN fault occurs, cluster may switchover to AZ1 or AZ2,
    we need judge the Ha status specially */
    int count = (g_instance_group_report_status_ptr[i].instance_status.currentSyncList.count == 0) ?
        groupDnNum : g_instance_group_report_status_ptr[i].instance_status.currentSyncList.count;
    if ((count != 0) && (current_cluster_az_status == AnyFirstNo)) {
        return ProcessHaStatus2AzStartSyncThr(count, groupDnNum, nodeMsg);
    }
    if (nodeMsg->dnNum[AZ3_INDEX] == 0) {
        ret = JudgeAz3DeployMent(statusDnFail, i, nodeMsg);
        if (ret != 0) {
            return ret;
        }
    } else if ((nodeMsg->normalPrimaryDn + normalStandbyDnSum) * 2 <= groupDnNum &&
        g_dn_replication_num > DOUBLE_REPLICATION) {
        SetNodeMsgMethodStr(nodeMsg, "[ProcessHaStatus2Az]");
        SetNodeMsgCurState(nodeMsg, CM_STATUS_NEED_REPAIR);
        write_runlog(LOG, "Line:%d, normalPrimaryDn = %d, normalStandbyDnSum = %d\n",
            __LINE__, nodeMsg->normalPrimaryDn, normalStandbyDnSum);
        return -1;
    }

    return 0;
}

int CheckMultiAzDataNodeStatus(uint32 i, const int *statusDnFail)
{
    int groupDnNum = g_instance_role_group_ptr[i].count;
    int minorityAz = -1;

    InitNodeMsg nodeMsg;
    errno_t rc = memset_s(&nodeMsg, sizeof(InitNodeMsg), 0, sizeof(InitNodeMsg));
    securec_check_errno(rc, (void)rc);

    if (InitMultiAzDataNodeStatus(i, &minorityAz, &nodeMsg) != CM_SUCCESS) {
        return -1;
    }
    /* step2: simple situation judgment */
    int normalStandbyDnSum =
        nodeMsg.normalStandbyDn[AZ1_INDEX] + nodeMsg.normalStandbyDn[AZ2_INDEX] + nodeMsg.normalStandbyDn[AZ3_INDEX];
    /* The offline node is considered as a normal standby node when determining the cluster status */
    if (SetOfflineNode()) {
        normalStandbyDnSum++;
        nodeMsg.normStdbInCurSL++;
    }
    int ret;
    if (backup_open == CLUSTER_OBS_STANDBY) {
        ret = ProcessDataNodeStatusObsStandby(normalStandbyDnSum, groupDnNum);
        if (ret != 0) {
            return ret;
        }
    } else if (backup_open == CLUSTER_STREAMING_STANDBY) {
        ret = ProcessDataNodeStatusStreamingStandby(normalStandbyDnSum, groupDnNum, &nodeMsg);
        if (ret != 0) {
            return ret;
        }
    } else {
        ret = ProcessHaStatusWhenNoBackup(normalStandbyDnSum, groupDnNum, minorityAz, &nodeMsg);
        if (ret != 0) {
            return ret;
        }
        ret = ProcessHaStatus2Az(statusDnFail, i, normalStandbyDnSum, groupDnNum, &nodeMsg);
        PrintClusterStatus(i, groupDnNum, normalStandbyDnSum, &nodeMsg);
        if (ret != 0) {
            return ret;
        }
    }

    return 0;
}

void CheckDnRoleCond1(bool *cond1, bool *cond2, bool *cond3, uint32 i)
{
    *cond1 = ((g_instance_group_report_status_ptr[i].instance_status.data_node_member[0].local_status.local_role ==
                  INSTANCE_ROLE_PRIMARY) &&
              (g_instance_group_report_status_ptr[i].instance_status.data_node_member[1].local_status.local_role ==
                  INSTANCE_ROLE_STANDBY) &&
              (g_instance_group_report_status_ptr[i].instance_status.data_node_member[1].local_status.db_state ==
                      INSTANCE_HA_STATE_NORMAL ||
                  g_instance_group_report_status_ptr[i].instance_status.data_node_member[1].local_status.db_state ==
                      INSTANCE_HA_STATE_CATCH_UP) &&
              (g_instance_group_report_status_ptr[i].instance_status.data_node_member[2].local_status.local_role ==
                  INSTANCE_ROLE_DUMMY_STANDBY));

    *cond2 = ((g_instance_group_report_status_ptr[i].instance_status.data_node_member[1].local_status.local_role ==
                  INSTANCE_ROLE_PRIMARY) &&
              (g_instance_group_report_status_ptr[i].instance_status.data_node_member[0].local_status.local_role ==
                  INSTANCE_ROLE_STANDBY) &&
              (g_instance_group_report_status_ptr[i].instance_status.data_node_member[0].local_status.db_state ==
                      INSTANCE_HA_STATE_NORMAL ||
                  g_instance_group_report_status_ptr[i].instance_status.data_node_member[0].local_status.db_state ==
                      INSTANCE_HA_STATE_CATCH_UP) &&
              (g_instance_group_report_status_ptr[i].instance_status.data_node_member[2].local_status.local_role ==
                  INSTANCE_ROLE_DUMMY_STANDBY));

    *cond3 = ((g_instance_group_report_status_ptr[i].instance_status.data_node_member[0].local_status.local_role ==
                  INSTANCE_ROLE_PRIMARY) &&
              (g_instance_group_report_status_ptr[i].instance_status.data_node_member[1].local_status.local_role ==
                  INSTANCE_ROLE_STANDBY) &&
              (g_instance_group_report_status_ptr[i].instance_status.data_node_member[1].local_status.db_state ==
                  INSTANCE_HA_STATE_NORMAL) &&
              (g_instance_group_report_status_ptr[i].instance_status.data_node_member[2].local_status.local_role ==
                  INSTANCE_ROLE_UNKNOWN));
    return;
}

void CheckDnRoleCond2(bool *cond4, bool *cond5, bool *cond6, uint32 i)
{
    *cond4 = ((g_instance_group_report_status_ptr[i].instance_status.data_node_member[1].local_status.local_role ==
                  INSTANCE_ROLE_PRIMARY) &&
              (g_instance_group_report_status_ptr[i].instance_status.data_node_member[0].local_status.local_role ==
                  INSTANCE_ROLE_STANDBY) &&
              (g_instance_group_report_status_ptr[i].instance_status.data_node_member[0].local_status.db_state ==
                  INSTANCE_HA_STATE_NORMAL) &&
              (g_instance_group_report_status_ptr[i].instance_status.data_node_member[2].local_status.local_role ==
                  INSTANCE_ROLE_UNKNOWN));

    *cond5 = ((g_instance_group_report_status_ptr[i].instance_status.data_node_member[0].local_status.local_role ==
                  INSTANCE_ROLE_PRIMARY) &&
              (g_instance_group_report_status_ptr[i].instance_status.data_node_member[0].local_status.db_state ==
                  INSTANCE_HA_STATE_NORMAL) &&
              (g_instance_group_report_status_ptr[i].instance_status.data_node_member[1].local_status.local_role !=
                  INSTANCE_ROLE_PRIMARY) &&
              (g_instance_group_report_status_ptr[i].instance_status.data_node_member[2].local_status.local_role ==
                  INSTANCE_ROLE_DUMMY_STANDBY));

    *cond6 = ((g_instance_group_report_status_ptr[i].instance_status.data_node_member[1].local_status.local_role ==
                  INSTANCE_ROLE_PRIMARY) &&
              (g_instance_group_report_status_ptr[i].instance_status.data_node_member[1].local_status.db_state ==
                  INSTANCE_HA_STATE_NORMAL) &&
              (g_instance_group_report_status_ptr[i].instance_status.data_node_member[0].local_status.local_role !=
                  INSTANCE_ROLE_PRIMARY) &&
              (g_instance_group_report_status_ptr[i].instance_status.data_node_member[2].local_status.local_role ==
                  INSTANCE_ROLE_DUMMY_STANDBY));
    return;
}

int CheckShareDiskDataNodeStatus(uint32 groupIndex)
{
    int32 normalPriCnt = 0;
    int32 priCnt = 0;
    int32 dnFaultCnt = 0;
    int32 unknownCnt = 0;
    cm_instance_datanode_report_status *dnReport =
        g_instance_group_report_status_ptr[groupIndex].instance_status.data_node_member;
    for (int32 i = 0; i < g_instance_role_group_ptr->count; ++i) {
        if (dnReport[i].local_status.local_role == INSTANCE_ROLE_PRIMARY ||
            dnReport[i].local_status.local_role == INSTANCE_ROLE_MAIN_STANDBY)  {
            ++priCnt;
            if (dnReport[i].local_status.db_state == INSTANCE_HA_STATE_NORMAL) {
                ++normalPriCnt;
            }
        }
        if (dnReport[i].local_status.db_state != INSTANCE_HA_STATE_NORMAL) {
            ++dnFaultCnt;
        }
        if (dnReport[i].local_status.local_role == INSTANCE_HA_STATE_UNKONWN) {
            ++unknownCnt;
        }
    }
    if (normalPriCnt != 1) {
        g_HA_status->status = CM_STATUS_NEED_REPAIR;
        write_runlog(LOG,
            "cluster status is unavail, instanceId(%u), normalPriCnt=%d, priCnt=%d, dnFaultCnt=%d, unknownCnt=%d.\n",
            GetInstanceIdInGroup(groupIndex, 0), normalPriCnt, priCnt, dnFaultCnt, unknownCnt);
        return -1;
    }
    if (dnFaultCnt != 0 || unknownCnt != 0) {
        g_HA_status->status = CM_STATUS_DEGRADE;
        write_runlog(LOG,
            "cluster status is degrade, instanceId(%u), normalPriCnt=%d, priCnt=%d, dnFaultCnt=%d, unknownCnt=%d.\n",
            GetInstanceIdInGroup(groupIndex, 0), normalPriCnt, priCnt, dnFaultCnt, unknownCnt);
        return 1;
    }

    return 0;
}

int CheckDataNodeStatus(uint32 i, const int *statusDnFail)
{
    int ret = 0;
    bool cond1, cond2, cond3, cond4, cond5, cond6;

    if (EnableShareDisk()) {
        return CheckShareDiskDataNodeStatus(i);
    }

    if (g_single_node_cluster) {
        if (CheckSingleDataNodeStatus(i) != CM_SUCCESS) {
            return -1;
        }
    } else if (g_multi_az_cluster) {
        ret = CheckMultiAzDataNodeStatus(i, statusDnFail);
        if (ret != 0) {
            return ret;
        }
    } else {
        if (g_instance_role_group_ptr[i].count >= 3) {
            CheckDnRoleCond1(&cond1, &cond2, &cond3, i);
            CheckDnRoleCond2(&cond4, &cond5, &cond6, i);
            if (cond1) {
            } else if (cond2) {
            } else if (cond3) {
                g_HA_status->status = CM_STATUS_DEGRADE;
            } else if (cond4) {
                g_HA_status->status = CM_STATUS_DEGRADE;
            } else if (cond5) {
                g_HA_status->status = CM_STATUS_DEGRADE;
            } else if (cond6) {
                g_HA_status->status = CM_STATUS_DEGRADE;
            } else {
                g_HA_status->status = CM_STATUS_NEED_REPAIR;
                return -1;
            }
        }
    }
    return ret;
}

void CheckClusterStatus()
{
    uint32 cn_count = 0;
    uint32 abnormal_cn_count = 0;
    int statusOnline[AZ_MEMBER_MAX_COUNT] = {0};
    int statusPrimary[AZ_MEMBER_MAX_COUNT] = {0};
    int statusFail[AZ_MEMBER_MAX_COUNT] = {0};
    int statusDnFail[AZ_MEMBER_MAX_COUNT] = {0};
    int ret = 0;
    if (g_multi_az_cluster) {
        char azArray[AZ_MEMBER_MAX_COUNT][CM_AZ_NAME] = {0};
        initazArray(azArray);
        getAZDyanmicStatus(AZ_MEMBER_MAX_COUNT, statusOnline, statusPrimary, statusFail, statusDnFail, azArray);
    }

    for (uint32 i = 0; i < g_dynamic_header->relationCount; i++) {
        if (g_instance_role_group_ptr[i].instanceMember[0].instanceType == INSTANCE_TYPE_COORDINATE) {
            cn_count++;
            CheckCoordinateStatus(&abnormal_cn_count, i);
        } else if (!g_gtm_free_mode &&
            g_instance_role_group_ptr[i].instanceMember[0].instanceType == INSTANCE_TYPE_GTM) {
            ret = CheckGtmStatus(i);
            if (ret == -1) {
                return;
            }
        } else if (g_instance_role_group_ptr[i].instanceMember[0].instanceType == INSTANCE_TYPE_DATANODE) {
            ret = CheckDataNodeStatus(i, statusDnFail);
            if (ret == -1) {
                return;
            } else if (ret == 1) {
                continue;
            }
        } else {
            /* do nothing */
        }
    }

    if (!g_only_dn_cluster) {
        if (cn_count == abnormal_cn_count) {
            g_HA_status->status = CM_STATUS_NEED_REPAIR;
        } else if (abnormal_cn_count > 0) {
            g_HA_status->status = CM_STATUS_DEGRADE;
        } else {
            /* do nothing */
        }
    }

    clean_init_cluster_state();
    /*
     * In master standby cluster, if the count of normal etcd instance is less than a half of total, cluster status is
     * degrade.
     */
    if (g_etcd_num > 0 && !IsDdbHealth(DDB_PRE_CONN) && !g_multi_az_cluster && !g_single_node_cluster) {
        write_runlog(WARNING, "CheckClusterStatus, ddb is unhealth.\n");
    }
}

void set_cluster_status(void)
{
    uint32 i;

    g_HA_status->status = CM_STATUS_NORMAL;
    g_HA_status->is_all_group_mode_pending = false;

    CheckClusterStatus();
    /*
     * Check the cluster is in dilatation status or not.
     * If one or serveral coordinator report GROUP_MODE_PENDING status,
     * then the cluster status shoud be set to dilatation status. Otherwise not.
     */
    for (i = 0; i < g_dynamic_header->relationCount; i++) {
        if (g_instance_role_group_ptr[i].instanceMember[0].instanceType == INSTANCE_TYPE_COORDINATE) {
            if (g_instance_group_report_status_ptr[i].instance_status.coordinatemember.group_mode ==
                GROUP_MODE_PENDING) {
                g_HA_status->is_all_group_mode_pending = true;
                return;
            }
        }
    }
}

/**
 * @brief Get the logicClusterId by dynamic dataNodeId object
 *
 * @param  dataNodeId       My Param doc
 * @return int
 */
int get_logicClusterId_by_dynamic_dataNodeId(uint32 dataNodeId)
{
    uint32 ii;
    uint32 jj;
    uint32 kk;
    int logicClusterId = -1;
    for (ii = 0; ii < g_logic_cluster_count; ii++) {
        for (jj = 0; jj < g_logicClusterStaticConfig[ii].logicClusterNodeHeader.nodeCount; jj++) {
            for (kk = 0; kk < g_logicClusterStaticConfig[ii].logicClusterNode[jj].datanodeCount; kk++) {
                if (g_logicClusterStaticConfig[ii].logicClusterNode[jj].datanodeId[kk] == dataNodeId) {
                    logicClusterId = (int)ii;
                }
            }
        }
    }
    if (g_logic_cluster_count > 0 && logicClusterId == -1) {
        logicClusterId = LOGIC_CLUSTER_NUMBER - 1;
        g_elastic_exist_node = true;
    }

    return logicClusterId;
}

int isNodeBalanced(uint32 *switchedInstance)
{
    int instanceType = 0;
    int switchedCount = 0;
    int logicClusterId = -1;

    for (uint32 i = 0; i < LOGIC_CLUSTER_NUMBER; i++) {
        g_logicClusterStaticConfig[i].isLogicClusterBalanced = 0;
    }

    for (uint32 i = 0; i < g_dynamic_header->relationCount && switchedCount < MAX_INSTANCES_LEN; i++) {
        (void)pthread_rwlock_wrlock(&(g_instance_group_report_status_ptr[i].lk_lock));
        for (int j = 0; j < g_instance_role_group_ptr[i].count; j++) {
            instanceType = g_instance_role_group_ptr[i].instanceMember[j].instanceType;
            switch (instanceType) {
                case INSTANCE_TYPE_GTM:
                    if ((g_instance_group_report_status_ptr[i].instance_status.gtm_member[j].local_status.local_role ==
                        INSTANCE_ROLE_PRIMARY &&
                        g_instance_role_group_ptr[i].instanceMember[j].instanceRoleInit == INSTANCE_ROLE_STANDBY) ||
                        (g_instance_group_report_status_ptr[i].instance_status.gtm_member[j].local_status.local_role !=
                        INSTANCE_ROLE_PRIMARY &&
                        g_instance_role_group_ptr[i].instanceMember[j].instanceRoleInit == INSTANCE_ROLE_PRIMARY)) {
                        if (switchedInstance != NULL) {
                            switchedInstance[switchedCount] = g_instance_role_group_ptr[i].instanceMember[j].instanceId;
                        }
                        switchedCount++;
                    }

                    break;
                case INSTANCE_TYPE_DATANODE: {
                    const cm_local_replconninfo *dnStat =
                        &g_instance_group_report_status_ptr[i].instance_status.data_node_member[j].local_status;
                    logicClusterId = get_logicClusterId_by_dynamic_dataNodeId(
                        g_instance_role_group_ptr[i].instanceMember[0].instanceId);
                    if (g_single_node_cluster && dnStat->local_role == INSTANCE_ROLE_NORMAL &&
                        (g_instance_role_group_ptr[i].instanceMember[j].instanceRoleInit == INSTANCE_ROLE_PRIMARY ||
                        g_instance_role_group_ptr[i].instanceMember[j].instanceRoleInit == INSTANCE_ROLE_MAIN_STANDBY)) {
                        break;
                    }

                    if (((dnStat->local_role == INSTANCE_ROLE_PRIMARY || dnStat->local_role == INSTANCE_ROLE_MAIN_STANDBY) &&
                        g_instance_role_group_ptr[i].instanceMember[j].instanceRoleInit == INSTANCE_ROLE_STANDBY) ||
                        ((dnStat->local_role != INSTANCE_ROLE_PRIMARY && dnStat->local_role != INSTANCE_ROLE_MAIN_STANDBY) &&
                        (g_instance_role_group_ptr[i].instanceMember[j].instanceRoleInit == INSTANCE_ROLE_PRIMARY ||
                        g_instance_role_group_ptr[i].instanceMember[j].instanceRoleInit == INSTANCE_ROLE_MAIN_STANDBY))) {
                        if (switchedInstance != NULL) {
                            switchedInstance[switchedCount] = g_instance_role_group_ptr[i].instanceMember[j].instanceId;
                        }
                        switchedCount++;

                        if (logicClusterId >= 0 && logicClusterId < LOGIC_CLUSTER_NUMBER) {
                            g_logicClusterStaticConfig[logicClusterId].isLogicClusterBalanced++;
                        }
                    }

                    break;
                }
                default:
                    break;
            }
        }
        (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[i].lk_lock));
    }

    return switchedCount;
}

/* *
 * @brief check if cm_ctl switchover -A/-z done
 * Switchover full/AZ DONE return true if:
 * 1. no MSG_CM_AGENT_SWITCHOVER pending command
 * 2. standby instance have been promoted to Primary
 *
 * @return int
 */
int switchoverFullDone(void)
{
    uint32 group_index = 0;
    int ret = 0;
    int member_index = 0;
    int instanceType = 0;

    for (uint32 i = 0; i < (uint32)switchOverInstances.size(); i++) {
        ret = find_node_in_dynamic_configure(switchOverInstances[i].node, switchOverInstances[i].instanceId,
            &group_index, &member_index);
        if (ret != 0) {
            write_runlog(LOG, "can't find the instance(node =%u  instanceid =%u)\n", switchOverInstances[i].node,
                switchOverInstances[i].instanceId);
            return SWITCHOVER_FAIL;
        }

        (void)pthread_rwlock_wrlock(&(g_instance_group_report_status_ptr[group_index].lk_lock));
        instanceType = g_instance_role_group_ptr[group_index].instanceMember[member_index].instanceType;
        switch (instanceType) {
            case INSTANCE_TYPE_GTM:
                if (g_instance_group_report_status_ptr[group_index].instance_status.command_member[member_index]
                        .pengding_command != MSG_CM_AGENT_SWITCHOVER &&
                    g_instance_group_report_status_ptr[group_index].instance_status.gtm_member[member_index]
                        .local_status.local_role != INSTANCE_ROLE_PRIMARY) {
                    (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[group_index].lk_lock));
                    write_runlog(LOG, "the instance(node = %u  instanceid = %u) switchover fail\n",
                        switchOverInstances[i].node, switchOverInstances[i].instanceId);
                    return SWITCHOVER_FAIL;
                }
                if ((g_instance_group_report_status_ptr[group_index].instance_status.command_member[member_index]
                        .pengding_command == MSG_CM_AGENT_SWITCHOVER) ||
                    !((g_instance_group_report_status_ptr[group_index].instance_status.gtm_member[member_index]
                        .local_status.local_role == INSTANCE_ROLE_PRIMARY) &&
                    (g_instance_group_report_status_ptr[group_index].instance_status.gtm_member[member_index]
                        .local_status.connect_status == CON_OK))) {
                    (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[group_index].lk_lock));
                    write_runlog(LOG, "the instance(node = %u  instanceid = %u) is executing switchover.\n",
                        switchOverInstances[i].node, switchOverInstances[i].instanceId);
                    return SWITCHOVER_EXECING;
                } else {
                    write_runlog(LOG,
                        "the instance(node = %u  instanceid = %u) switchover success, pending command :%d, role:%d.\n",
                        switchOverInstances[i].node, switchOverInstances[i].instanceId,
                        g_instance_group_report_status_ptr[group_index]
                            .instance_status.command_member[member_index]
                            .pengding_command,
                        g_instance_group_report_status_ptr[group_index]
                            .instance_status.gtm_member[member_index]
                            .local_status.local_role);
                }
                break;
            case INSTANCE_TYPE_DATANODE:
                if (g_instance_group_report_status_ptr[group_index].instance_status.command_member[member_index]
                        .pengding_command != (int32)MSG_CM_AGENT_SWITCHOVER &&
                    (g_instance_group_report_status_ptr[group_index].instance_status.data_node_member[member_index]
                        .local_status.local_role != INSTANCE_ROLE_PRIMARY &&
                    g_instance_group_report_status_ptr[group_index].instance_status.data_node_member[member_index]
                        .local_status.local_role != INSTANCE_ROLE_MAIN_STANDBY)) {
                    (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[group_index].lk_lock));
                    write_runlog(LOG, "the instance(node = %u  instanceid = %u) switchover fail\n",
                        switchOverInstances[i].node, switchOverInstances[i].instanceId);
                    return SWITCHOVER_FAIL;
                }
                if (g_instance_group_report_status_ptr[group_index].instance_status.command_member[member_index]
                    .pengding_command == (int32)MSG_CM_AGENT_SWITCHOVER) {
                    for (int ii = 0; ii < g_instance_role_group_ptr[group_index].count; ii++) {
                        if ((g_instance_role_group_ptr[group_index].instanceMember[ii].role == INSTANCE_ROLE_PRIMARY ||
                            g_instance_role_group_ptr[group_index].instanceMember[ii].role == INSTANCE_ROLE_MAIN_STANDBY) &&
                            g_instance_group_report_status_ptr[group_index].instance_status.data_node_member[ii]
                            .local_status.db_state != INSTANCE_HA_STATE_NORMAL) {
                            (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[group_index].lk_lock));
                            write_runlog(LOG,
                                "the instance(node = %u  instanceid = %u), static primary dbstate is not normal\n",
                                switchOverInstances[i].node, switchOverInstances[i].instanceId);
                            return SWITCHOVER_EXECING;
                        }
                    }
                }
                if ((g_instance_group_report_status_ptr[group_index].instance_status.command_member[member_index]
                        .pengding_command == MSG_CM_AGENT_SWITCHOVER) ||
                    (g_instance_group_report_status_ptr[group_index].instance_status.data_node_member[member_index]
                        .local_status.local_role != INSTANCE_ROLE_PRIMARY &&
                    g_instance_group_report_status_ptr[group_index].instance_status.data_node_member[member_index]
                        .local_status.local_role != INSTANCE_ROLE_MAIN_STANDBY)) {
                    (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[group_index].lk_lock));
                    write_runlog(LOG, "the instance(node = %u  instanceid = %u) is executing switchover.\n",
                        switchOverInstances[i].node, switchOverInstances[i].instanceId);
                    return SWITCHOVER_EXECING;
                } else {
                    write_runlog(LOG,
                        "the instance(node = %u  instanceid = %u) switchover success, pending command :%d, role:%d.\n",
                        switchOverInstances[i].node,
                        switchOverInstances[i].instanceId,
                        g_instance_group_report_status_ptr[group_index]
                            .instance_status.command_member[member_index]
                            .pengding_command,
                        g_instance_group_report_status_ptr[group_index]
                            .instance_status.gtm_member[member_index]
                            .local_status.local_role);
                }
                break;
            default:
                break;
        }
        (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[group_index].lk_lock));
    }

    return SWITCHOVER_SUCCESS;
}

/* *
 * @brief
 *
 * @param  time_out         My Param doc
 * @param  instanceType     My Param doc
 * @param  ptrIndex         My Param doc
 * @param  memberIndex      My Param doc
 */
void SwitchOverSetting(int time_out, int instanceType, uint32 ptrIndex, int memberIndex)
{
    switchover_instance instance;

    /* do switchover */
    cm_instance_command_status *cmd =
        &(g_instance_group_report_status_ptr[ptrIndex].instance_status.command_member[memberIndex]);
    cmd->command_status = INSTANCE_COMMAND_WAIT_EXEC;
    cmd->pengding_command = (int)MSG_CM_AGENT_SWITCHOVER;
    if (g_ssDoubleClusterMode == SS_DOUBLE_STANDBY) {
        cmd->cmdPur = INSTANCE_ROLE_MAIN_STANDBY;
    } else {
        cmd->cmdPur = INSTANCE_ROLE_PRIMARY;
    }
    cmd->cmdSour = INSTANCE_ROLE_STANDBY;
    cmd->time_out = time_out;
    cmd->peerInstId = GetPeerInstId(ptrIndex, memberIndex);
    SetSendTimes(ptrIndex, memberIndex, time_out);
    write_runlog(LOG,
        "az switchover instanceid %u\n",
        g_instance_role_group_ptr[ptrIndex].instanceMember[memberIndex].instanceId);

    /* clear peer comand status */
    for (int k = 0; k < g_instance_role_group_ptr[ptrIndex].count; k++) {
        if (k != memberIndex) {
            CleanCommand(ptrIndex, k);
        }
    }

    /* save instance info */
    instance.node = g_instance_role_group_ptr[ptrIndex].instanceMember[memberIndex].node;
    instance.instanceId = g_instance_role_group_ptr[ptrIndex].instanceMember[memberIndex].instanceId;
    instance.instanceType = instanceType;
    switchOverInstances.push_back(instance);
}

static void MsgRelationDatanode(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    ctl_to_cm_datanode_relation_info *ctlToCmDatanodeRelationInfoPtr;
    PROCESS_MSG_BY_TYPE(
        ctl_to_cm_datanode_relation_info, ctlToCmDatanodeRelationInfoPtr, process_ctl_to_cm_get_datanode_relation_msg,
        recvMsgInfo, msgType);
}

static void MsgSwitchover(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    ctl_to_cm_switchover *ctlToCmSwithoverPtr;
    PROCESS_MSG_BY_TYPE(ctl_to_cm_switchover, ctlToCmSwithoverPtr, ProcessCtlToCmSwitchoverMsg,
        recvMsgInfo, msgType);
}

static void MsgSwitchoverFast(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    ctl_to_cm_switchover *ctlToCmSwithoverPtr;
    msgProc->doSwitchover = true;
    PROCESS_MSG_BY_TYPE(ctl_to_cm_switchover, ctlToCmSwithoverPtr, ProcessCtlToCmSwitchoverMsg,
        recvMsgInfo, msgType);
}

static void MsgSwitchoverAll(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    ctl_to_cm_switchover *ctlToCmSwithoverPtr;
    PROCESS_MSG_BY_TYPE(ctl_to_cm_switchover, ctlToCmSwithoverPtr, ProcessCtlToCmSwitchoverAllMsg,
        recvMsgInfo, msgType);
}

static void MsgSwitchoverFull(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    ctl_to_cm_switchover *ctlToCmSwithoverPtr;
    PROCESS_MSG_BY_TYPE(ctl_to_cm_switchover, ctlToCmSwithoverPtr, process_ctl_to_cm_switchover_full_msg,
        recvMsgInfo, msgType);
}

static void MsgSwitchoverFullCheck(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    ProcessCtlToCmSwitchoverFullCheckMsg(recvMsgInfo);
}

static void MsgSwitchoverFullTimeout(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    ProcessCtlToCmSwitchoverFullTimeoutMsg(recvMsgInfo);
}

static void MsgSwitchoverAz(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    ctl_to_cm_switchover *ctlToCmSwithoverPtr;
    PROCESS_MSG_BY_TYPE(ctl_to_cm_switchover, ctlToCmSwithoverPtr, ProcessCtlToCmSwitchoverAzMsg,
        recvMsgInfo, msgType);
}

static void MsgSwitchoverAzTimeout(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    process_ctl_to_cm_switchover_az_timeout_msg(recvMsgInfo);
}

static void MsgSwitchoverAzCheck(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    ProcessCtlToCmSwitchoverAzCheckMsg(recvMsgInfo);
}

static void MsgBalanceCheck(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    process_ctl_to_cm_balance_check_msg(recvMsgInfo);
}

static void MsgBalanceResult(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    ProcessCtlToCmBalanceResultMsg(recvMsgInfo);
}

static void MsgSetMode(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    process_ctl_to_cm_setmode(recvMsgInfo);
}

static void MsgBuild(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    ctl_to_cm_build* ctlToCmBuildPtr;
    PROCESS_MSG_BY_TYPE(ctl_to_cm_build, ctlToCmBuildPtr, ProcessCtlToCmBuildMsg,
        recvMsgInfo, msgType);
}

static void MsgSync(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    return;
}

static void ProcessCtlToCmNotifyMsg(const ctl_to_cm_notify* ctlToCmNotifyPtr)
{
    ctlToCmNotifyDetail notifyDetail = ctlToCmNotifyPtr->detail;
    switch (notifyDetail) {
        case CLUSTER_STARTING:
            g_clusterStarting = true;
            g_clusterStartingTimeout = ClUSTER_STARTINT_STATUS_TIME_OUT;
            break;
        default:
            break;
    }
    return;
}

static void MsgNotify(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    const ctl_to_cm_notify *ctlToCmNotifyPtr =
        (const ctl_to_cm_notify *)CmGetmsgbytes((CM_StringInfo)&recvMsgInfo->msg, sizeof(ctl_to_cm_notify));
    if (ctlToCmNotifyPtr != NULL) {
        ProcessCtlToCmNotifyMsg(ctlToCmNotifyPtr);
    } else {
        write_runlog(ERROR, "CmGetmsgbytes failed, msg_type=%d.\n", msgType);
    }
}

static void MsgQuery(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    ctl_to_cm_query *ctlToCmQueryPtr;
    PROCESS_MSG_BY_TYPE(ctl_to_cm_query, ctlToCmQueryPtr, ProcessCtlToCmQueryMsg,
        recvMsgInfo, msgType);
}

static void MsgCtlResourceStatus(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    CmsToCtlGroupResStatus *queryStatusPtr;
    PROCESS_MSG_BY_TYPE(CmsToCtlGroupResStatus, queryStatusPtr, ProcessResInstanceStatusMsg,
        recvMsgInfo, msgType);
}

static void MsgQueryCmserver(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    ProcessCtlToCmQueryCmserverMsg(recvMsgInfo);
}

static void MsgSet(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    ctl_to_cm_set *ctl_to_cm_set_ptr;
    PROCESS_MSG_BY_TYPE(ctl_to_cm_set, ctl_to_cm_set_ptr, ProcessCtlToCmSetMsg,
        recvMsgInfo, msgType);
}

static void MsgGet(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    ProcessCtlToCmGetMsg(recvMsgInfo);
}

static void MsgDataInstanceReport(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    SetAgentDataReportMsg(recvMsgInfo, (CM_StringInfo)&recvMsgInfo->msg);
}

static void MsgFencedUdf(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    agent_to_cm_fenced_UDF_status_report *agentToCmFencedUdfStatusPtr;
    PROCESS_MSG_BY_TYPE_WITHOUT_CONN(agent_to_cm_fenced_UDF_status_report, agentToCmFencedUdfStatusPtr,
        process_agent_to_cm_fenced_UDF_status_report_msg);
}

static void MsgHeatbeat(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    agent_to_cm_heartbeat *agentToCmHeartbeatPtr;
    PROCESS_MSG_BY_TYPE(agent_to_cm_heartbeat, agentToCmHeartbeatPtr, process_agent_to_cm_heartbeat_msg,
        recvMsgInfo, msgType);
}

static void MsgGsGucAck(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    agent_to_cm_gs_guc_feedback *cmToCmGsGucPtr;
    PROCESS_MSG_BY_TYPE_WITHOUT_CONN(agent_to_cm_gs_guc_feedback, cmToCmGsGucPtr, process_gs_guc_feedback_msg);
}

static void MsgEtcdCurrentTime(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    agent_to_cm_current_time_report *agentToCmCurrentTimePtr;
    PROCESS_MSG_BY_TYPE_WITHOUT_CONN(
        agent_to_cm_current_time_report, agentToCmCurrentTimePtr, process_agent_to_cm_current_time_msg);
}

static void MsgQueryInstanceStatus(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    cm_query_instance_status *cmQueryInstanceStatusPtr;
    PROCESS_MSG_BY_TYPE(cm_query_instance_status, cmQueryInstanceStatusPtr, process_to_query_instance_status_msg,
        recvMsgInfo, msgType);
}

static void MsgHotpatch(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    cm_hotpatch_msg *cmHotpatchMsgPtr;
    PROCESS_MSG_BY_TYPE(cm_hotpatch_msg, cmHotpatchMsgPtr, ProcessHotpatchMessage, recvMsgInfo, msgType);
}

static void MsgStopArbitration(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    ProcessStopArbitrationMessage();
}

static void MsgQueryKerberos(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    ProcessCtlToCmQueryKerberosStatusMsg(recvMsgInfo);
}

static void MsgKerberosStatus(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    agent_to_cm_kerberos_status_report *agentToCmKerberosStatusPtr;
    PROCESS_MSG_BY_TYPE_WITHOUT_CONN(
        agent_to_cm_kerberos_status_report, agentToCmKerberosStatusPtr, process_agent_to_cm_kerberos_status_report_msg);
}

static void MsgAgentResourceStatus(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    if (!IsCusResExist()) {
        return;
    }
    if (!CanProcessResStatus()) {
        write_runlog(LOG, "[%s], res status list invalid, can't continue.\n", __FUNCTION__);
        return;
    }
    ReportResStatus *cmaToCmsResStatusPtr;
    PROCESS_MSG_BY_TYPE_WITHOUT_CONN(ReportResStatus, cmaToCmsResStatusPtr, ProcessAgent2CmResStatReportMsg);
}

static void MsgFinishRedo(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    process_finish_redo_message(recvMsgInfo);
}

static void MsgFinishRedoCheck(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    process_finish_redo_check_message(recvMsgInfo);
}

static void MsgDiskUsageStatus(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    AgentToCmDiskUsageStatusReport *agentToCmDiskUsagePtr;
    PROCESS_MSG_BY_TYPE_WITHOUT_CONN(
        AgentToCmDiskUsageStatusReport, agentToCmDiskUsagePtr, process_agent_to_cm_disk_usage_msg);
}

static void MsgDatanodeInstanceBarrier(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    ProcessDnBarrierinfo(recvMsgInfo, (CM_StringInfo)&recvMsgInfo->msg);
}

static void MsgGlobalBarrierQuery(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    ProcessCtlToCmQueryBarrierMsg(recvMsgInfo);
}

static void MsgDnSyncList(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
#if ((defined(ENABLE_MULTIPLE_NODES)) || (defined(ENABLE_PRIVATEGAUSS)))
    AgentToCmserverDnSyncList *syncListMsg;
    PROCESS_MSG_BY_TYPE_WITHOUT_CONN(AgentToCmserverDnSyncList, syncListMsg, ProcessGetDnSyncListMsg);
#endif
}

static void MsgDnMostAvailable(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    AgentToCmserverDnSyncAvailable *availableMsg;
    PROCESS_MSG_BY_TYPE(AgentToCmserverDnSyncAvailable, availableMsg, ProcessDnMostAvailableMsg, recvMsgInfo, msgType);
}

static void MsgDnLocalPeer(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    AgentCmDnLocalPeer *dnLocalPeer;
    PROCESS_MSG_BY_TYPE(AgentCmDnLocalPeer, dnLocalPeer, ProcessDnLocalPeerMsg, recvMsgInfo, msgType);
}

static void MsgReload(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    ProcessCtlToCmReloadMsg(recvMsgInfo);
}

static void MsgDdbCmd(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    ExecDdbCmdMsg *execDccCmdMsg;
    PROCESS_MSG_BY_TYPE(ExecDdbCmdMsg, execDccCmdMsg, ProcessCtlToCmExecDccCmdMsg,
        recvMsgInfo, msgType);
}

static void MsgSwitchCmd(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    CtlToCmsSwitch *switchMsg;
    PROCESS_MSG_BY_TYPE(CtlToCmsSwitch, switchMsg, ProcessCtlToCmsSwitchMsg,
        recvMsgInfo, msgType);
}

static void MsgRequestResStatusList(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    if (!IsCusResExist()) {
        return;
    }
    if (!CanProcessResStatus()) {
        write_runlog(LOG, "[%s], res status list invalid, can't continue.\n", __FUNCTION__);
        return;
    }
    ProcessRequestResStatusListMsg(recvMsgInfo);
}

static void MsgLatestResStatusList(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    if (!IsCusResExist()) {
        return;
    }
    if (!CanProcessResStatus()) {
        write_runlog(LOG, "[%s], res status list invalid, can't continue.\n", __FUNCTION__);
        return;
    }
    RequestLatestStatList *recvMsg;
    PROCESS_MSG_BY_TYPE(RequestLatestStatList, recvMsg, ProcessRequestLatestResStatusListMsg,
        recvMsgInfo, msgType);
}

static void MsgGetSharedStorageInfo(MsgRecvInfo *recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    ProcessSharedStorageMsg(recvMsgInfo);
}

static void MsgDdbOper(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    CltSendDdbOper *cltSendOper;
    PROCESS_MSG_BY_TYPE(CltSendDdbOper, cltSendOper, ProcessCltSendOper,
        recvMsgInfo, msgType);
}

static void MsgSslConnRequest(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    AgentToCmConnectRequest *connMsgReq;
    PROCESS_MSG_BY_TYPE(AgentToCmConnectRequest, connMsgReq, ProcessSslConnRequest,
        recvMsgInfo, msgType);
}

static void MsgCmResLock(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    if (!IsCusResExist()) {
        return;
    }
    CmaToCmsResLock *lockMsg = NULL;
    PROCESS_MSG_BY_TYPE(CmaToCmsResLock, lockMsg, ProcessCmResLock,
        recvMsgInfo, msgType);
}

static void MsgCmQueryOneResInst(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    QueryOneResInstStat *queryMsg = NULL;
    PROCESS_MSG_BY_TYPE(QueryOneResInstStat, queryMsg, ProcessQueryOneResInst,
        recvMsgInfo, msgType);
}

void ProcessCmRhbMsg(MsgRecvInfo *recvMsgInfo, const CmRhbMsg *rhbMsg)
{
    write_runlog(DEBUG1, "[ProcessCmRhbMsg] receive rhb msg from nodeid: %u\n", rhbMsg->nodeId);
    RefreshNodeRhbInfo(rhbMsg->nodeId, rhbMsg->hbs, rhbMsg->hwl);
}

static void MsgCmRhb(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    CmRhbMsg *hbMsg = NULL;
    PROCESS_MSG_BY_TYPE(CmRhbMsg, hbMsg, ProcessCmRhbMsg, recvMsgInfo, msgType);
}

void ProcessRhbStatReq(MsgRecvInfo *recvMsgInfo, const CmShowStatReq *req)
{
    write_runlog(DEBUG1, "[ProcessRhbStatReq] receive rhb query msg\n");
    CmRhbStatAck ack = {0};
    ack.msg_type = (int)MSG_CTL_CM_RHB_STATUS_ACK;
    GetRhbStat(ack.hbs, &ack.hwl);
    ack.baseTime = time(NULL);
    ack.timeout = g_agentNetworkTimeout;

    (void)RespondMsg(recvMsgInfo, 'S', (char *)(&ack), sizeof(CmRhbStatAck));
}

void ProcessNodeDiskStatReq(MsgRecvInfo *recvMsgInfo, const CmShowStatReq *req)
{
    write_runlog(DEBUG1, "[ProcessNodeDiskStatReq] receive node disk query msg\n");
    CmNodeDiskStatAck ack = {0};
    ack.msg_type = (int)MSG_CTL_CM_NODE_DISK_STATUS_ACK;
    GetNodeDiskStat(ack.nodeDiskStats, &ack.hwl);
    ack.baseTime = time(NULL);
    ack.timeout = g_diskTimeout;

    (void)RespondMsg(recvMsgInfo, 'S', (char *)(&ack), sizeof(CmNodeDiskStatAck));
}

void ProcessFloatIpReq(MsgRecvInfo *recvMsgInfo, const CmShowStatReq *req)
{
    write_runlog(DEBUG1, "[ProcessFloatIpReq] receive float ip query msg.\n");
    char sendMsg[DDB_MAX_KEY_VALUE_LEN] = {0};
    size_t msgLen = sizeof(CmFloatIpStatAck);
    GetFloatIpSet((CmFloatIpStatAck*)sendMsg, DDB_MAX_KEY_VALUE_LEN, &msgLen);
    (void)RespondMsg(recvMsgInfo, 'S', sendMsg, msgLen);
}

static void MsgShowStatus(MsgRecvInfo* recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    CmShowStatReq *req = NULL;
    switch (msgType) {
        case MSG_CTL_CM_RHB_STATUS_REQ:
            PROCESS_MSG_BY_TYPE(CmShowStatReq, req, ProcessRhbStatReq, recvMsgInfo, msgType);
            break;
        case MSG_CTL_CM_NODE_DISK_STATUS_REQ:
            PROCESS_MSG_BY_TYPE(CmShowStatReq, req, ProcessNodeDiskStatReq, recvMsgInfo, msgType);
            break;
        case MSG_CTL_CM_FLOAT_IP_REQ:
            PROCESS_MSG_BY_TYPE(CmShowStatReq, req, ProcessFloatIpReq, recvMsgInfo, msgType);
            break;
        default:
            write_runlog(ERROR, "[MsgShowStatus] unknown request(%d)\n", msgType);
            break;
    }
}

static void MsgGetFloatIpInfo(MsgRecvInfo *recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    if (!IsNeedCheckFloatIp() || (backup_open != CLUSTER_PRIMARY)) {
        return;
    }
    CmaDnFloatIpInfo *floatIpInfo;
    PROCESS_MSG_BY_TYPE(CmaDnFloatIpInfo, floatIpInfo, ProcessDnFloatIpMsg, recvMsgInfo, msgType);
}

static void MsgResIsreg(MsgRecvInfo *recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    if (!IsCusResExist()) {
        return;
    }
    CmaToCmsIsregMsg *isregMsg;
    PROCESS_MSG_BY_TYPE(CmaToCmsIsregMsg, isregMsg, ProcessResIsregMsg, recvMsgInfo, msgType);
}

void MsgGetPingDnFloatIpFailedInfo(MsgRecvInfo *recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    if (!IsNeedCheckFloatIp() || (backup_open != CLUSTER_PRIMARY)) {
        return;
    }
    CmSendPingDnFloatIpFail *failedFloatIpInfo;
    PROCESS_MSG_BY_TYPE(
        CmSendPingDnFloatIpFail, failedFloatIpInfo, ProcessPingDnFloatIpFailedMsg, recvMsgInfo, msgType);
}

void MsgInOnDemandStatus(MsgRecvInfo *recvMsgInfo, int msgType, CmdMsgProc *msgProc)
{
    agent_to_cm_ondemand_status_report* ondemandStatusReport = NULL;
    PROCESS_MSG_BY_TYPE(
        agent_to_cm_ondemand_status_report, ondemandStatusReport, ProcessOndemandStatusMsg, recvMsgInfo, msgType);   
}

static void InitCmCtlCmdProc()
{
    // 32
    g_cmdProc[MSG_CTL_CM_GET_DATANODE_RELATION] = MsgRelationDatanode;
    g_cmdProc[MSG_CTL_CM_SWITCHOVER] = MsgSwitchover;
    g_cmdProc[MSG_CTL_CM_SWITCHOVER_FAST] = MsgSwitchoverFast;
    g_cmdProc[MSG_CTL_CM_SWITCHOVER_ALL] = MsgSwitchoverAll;
    g_cmdProc[MSG_CTL_CM_SWITCHOVER_FULL] = MsgSwitchoverFull;
    g_cmdProc[MSG_CTL_CM_SWITCHOVER_FULL_CHECK] = MsgSwitchoverFullCheck;
    g_cmdProc[MSG_CTL_CM_SWITCHOVER_FULL_TIMEOUT] = MsgSwitchoverFullTimeout;
    g_cmdProc[MSG_CTL_CM_SWITCHOVER_AZ] = MsgSwitchoverAz;
    g_cmdProc[MSG_CTL_CM_SWITCHOVER_AZ_CHECK] = MsgSwitchoverAzCheck;
    g_cmdProc[MSG_CTL_CM_SWITCHOVER_AZ_TIMEOUT] = MsgSwitchoverAzTimeout;
    g_cmdProc[MSG_CTL_CM_BALANCE_CHECK] = MsgBalanceCheck;
    g_cmdProc[MSG_CTL_CM_BALANCE_RESULT] = MsgBalanceResult;
    g_cmdProc[MSG_CTL_CM_SETMODE] = MsgSetMode;
    g_cmdProc[MSG_CTL_CM_BUILD] = MsgBuild;
    g_cmdProc[MSG_CTL_CM_SYNC] = MsgSync;
    g_cmdProc[MSG_CTL_CM_NOTIFY] = MsgNotify;
    g_cmdProc[MSG_CTL_CM_QUERY] = MsgQuery;
    g_cmdProc[MSG_CTL_CM_RESOURCE_STATUS] = MsgCtlResourceStatus;
    g_cmdProc[MSG_CTL_CM_QUERY_CMSERVER] = MsgQueryCmserver;
    g_cmdProc[MSG_CTL_CM_SET] = MsgSet;
    g_cmdProc[MSG_CTL_CM_GET] = MsgGet;
    g_cmdProc[MSG_CTL_CM_HOTPATCH] = MsgHotpatch;
    g_cmdProc[MSG_CTL_CM_STOP_ARBITRATION] = MsgStopArbitration;
    g_cmdProc[MSG_CTL_CM_QUERY_KERBEROS] = MsgQueryKerberos;
    g_cmdProc[MSG_CTL_CM_FINISH_REDO] = MsgFinishRedo;
    g_cmdProc[MSG_CTL_CM_FINISH_REDO_CHECK] = MsgFinishRedoCheck;
    g_cmdProc[MSG_CTL_CM_GLOBAL_BARRIER_QUERY] = MsgGlobalBarrierQuery;
    g_cmdProc[MSG_CTL_CM_GLOBAL_BARRIER_QUERY_NEW] = NULL;
    g_cmdProc[MSG_CTL_CM_RELOAD] = MsgReload;
    g_cmdProc[MSG_EXEC_DDB_COMMAND] = MsgDdbCmd;
    g_cmdProc[MSG_CTL_CMS_SWITCH] = MsgSwitchCmd;
    g_cmdProc[MSG_CTL_CM_QUERY_RES_INST] = MsgCmQueryOneResInst;
    g_cmdProc[MSG_CTL_CM_RHB_STATUS_REQ] = MsgShowStatus;
    g_cmdProc[MSG_CTL_CM_NODE_DISK_STATUS_REQ] = MsgShowStatus;
    g_cmdProc[MSG_CTL_CM_FLOAT_IP_REQ] = MsgShowStatus;
}

static void InitCmAgentCmdProc()
{
    // 19
    g_cmdProc[MSG_AGENT_CM_DATA_INSTANCE_REPORT_STATUS] = MsgDataInstanceReport;
    g_cmdProc[MSG_AGENT_CM_FENCED_UDF_INSTANCE_STATUS] = MsgFencedUdf;
    g_cmdProc[MSG_AGENT_CM_HEARTBEAT] = MsgHeatbeat;
    g_cmdProc[MSG_AGENT_CM_GS_GUC_ACK] = MsgGsGucAck;
    g_cmdProc[MSG_AGENT_CM_ETCD_CURRENT_TIME] = MsgEtcdCurrentTime;
    g_cmdProc[MSG_CM_QUERY_INSTANCE_STATUS] = MsgQueryInstanceStatus;
    g_cmdProc[MSG_AGENT_CM_KERBEROS_STATUS] = MsgKerberosStatus;
    g_cmdProc[MSG_AGENT_CM_DISKUSAGE_STATUS] = MsgDiskUsageStatus;
    g_cmdProc[MSG_AGENT_CM_DATANODE_INSTANCE_BARRIER] = MsgDatanodeInstanceBarrier;
    g_cmdProc[MSG_AGENT_CM_DN_SYNC_LIST] = MsgDnSyncList;
    g_cmdProc[MSG_AGENT_CM_DN_MOST_AVAILABLE] = MsgDnMostAvailable;
    g_cmdProc[MSG_AGENT_CM_DATANODE_LOCAL_PEER] = MsgDnLocalPeer;
    g_cmdProc[MSG_GET_SHARED_STORAGE_INFO] = MsgGetSharedStorageInfo;
    g_cmdProc[MSG_CM_RHB] = MsgCmRhb;
    g_cmdProc[MSG_AGENT_CM_FLOAT_IP] = MsgGetFloatIpInfo;

    g_cmdProc[MSG_CM_RES_LOCK] = MsgCmResLock;
    g_cmdProc[MSG_AGENT_CM_ISREG_REPORT] = MsgResIsreg;
    g_cmdProc[MSG_AGENT_CM_RESOURCE_STATUS] = MsgAgentResourceStatus;
    g_cmdProc[MSG_AGENT_CM_GET_LATEST_STATUS_LIST] = MsgLatestResStatusList;
    g_cmdProc[MSG_AGENT_CM_REQUEST_RES_STATUS_LIST] = MsgRequestResStatusList;

    g_cmdProc[MSG_CMA_PING_DN_FLOAT_IP_FAIL] = MsgGetPingDnFloatIpFailedInfo;
    g_cmdProc[MSG_AGENT_ONDEMAND_STATUES_REPORT] = MsgInOnDemandStatus;
}

static void InitCmClientCmdProc()
{
    // 2
    g_cmdProc[MSG_CLIENT_CM_DDB_OPER] = MsgDdbOper;
    g_cmdProc[MSG_CM_SSL_CONN_REQUEST] = MsgSslConnRequest;
}

void InitCltCmdProc()
{
    // cm_ctl
    InitCmCtlCmdProc();

    // cm_agent
    InitCmAgentCmdProc();

    // client
    InitCmClientCmdProc();

#ifdef ENABLE_MULTIPLE_NODES
    InitMultipleCmdProc();
#endif
}

void DefaultProcessMsg(int msgType)
{
    write_runlog(LOG, "receive the command type is %d is unknown \n", msgType);
}

void cm_server_process_msg(MsgRecvInfo* recvMsgInfo)
{
    CM_StringInfo  inBuffer = (CM_StringInfo)&recvMsgInfo->msg;
    const cm_msg_type *msgTypePtr = (const cm_msg_type *)CmGetmsgtype(inBuffer, sizeof(cm_msg_type));
    if (msgTypePtr == NULL) {
        write_runlog(ERROR, "get msg type failed,cms msg is Invalid. \n");
        return;
    }
    int msgType = msgTypePtr->msg_type;
    if (msgType >= MSG_CM_TYPE_CEIL || msgType < 0) {
        write_runlog(ERROR, "cms msg type is %d is Invalid. \n", msgType);
        return;
    }

    write_runlog(DEBUG5, "receive command type %d:%s \n", msgType,
        cluster_msg_int_to_string(msgType));

    recvMsgInfo->msgProcFlag = g_msgProcFlag[msgType];

    CltCmdProc cmdProc = g_cmdProc[msgType];
    CmdMsgProc msgProc = {false, false};
    if (cmdProc != NULL) {
        cmdProc(recvMsgInfo, msgType, &msgProc);
    } else {
        DefaultProcessMsg(msgType);
    }
    FlushCmToAgentMsg(recvMsgInfo, msgType);
}
