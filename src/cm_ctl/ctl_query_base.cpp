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
 * ctl_query_base.cpp
 *    cm_ctl query [-z ALL] [-n NODEID [-D DATADIR -R]] [-l FILENAME][-v [-C [-s] [-S] [-d] [-i] [-F]
 *                      [-L ALL] [-x] [-p]] | [-r]] [-t SECS] [--minorityAz=AZ_NAME]
 *
 * IDENTIFICATION
 *    src/cm_ctl/ctl_query_base.cpp
 *
 * -------------------------------------------------------------------------
 */
#include "cm/libpq-fe.h"
#include "cm/cm_misc.h"
#include "ctl_common.h"
#include "cm_msg_ipv4.h"
#include "ctl_query_base.h"

extern bool g_detailQuery;
extern bool g_coupleQuery;
extern bool g_formatQuery;
extern bool g_balanceQuery;
extern bool g_startStatusQuery;
extern bool g_portQuery;
extern bool g_paralleRedoState;
extern bool g_abnormalQuery;
extern bool g_dataPathQuery;
extern bool g_availabilityZoneCommand;
extern bool g_ipQuery;
extern int g_fencedUdfQuery;
extern bool g_nodeIdSet;
extern int g_waitSeconds;
extern bool g_commandRelationship;
extern char g_cmData[CM_PATH_LENGTH];
extern uint32 g_commandOperationNodeId;
extern bool g_gtmBalance;
extern bool g_datanodesBalance;
extern cm_to_ctl_central_node_status g_centralNode;
extern FILE* g_logFilePtr;

static void PrintClusterStatus(int clusterStatus = CM_STATUS_UNKNOWN, bool redistributing = false,
    int switchedCount = -1, int nodeID = -1);

static void PrintLogicResult(uint32 nameLen, uint32 stateLen, const cm_to_ctl_logic_cluster_status *clusterStatusPtr)
{
    for (uint32 ii = 0; ii < g_logic_cluster_count; ii++) {
        (void)fprintf(g_logFilePtr, "%-*s ", nameLen - SPACE_LEN,
            g_logicClusterStaticConfig[ii].LogicClusterName);
        (void)fprintf(g_logFilePtr, "%-*s ", stateLen - SPACE_LEN,
            cluster_state_int_to_string(clusterStatusPtr->logic_cluster_status[ii]));
        (void)fprintf(g_logFilePtr, "%-*s ", stateLen - SPACE_LEN,
            clusterStatusPtr->logic_is_all_group_mode_pending[ii] ? "Yes" : "No");
        (void)fprintf(g_logFilePtr, "%-*s\n", stateLen - SPACE_LEN,
            (clusterStatusPtr->logic_switchedCount[ii] == 0) ? "Yes" : "No");
    }
    /* if elastic exist node get its status,else set default status */
    if (clusterStatusPtr->logic_switchedCount[LOGIC_CLUSTER_NUMBER - 1] >= 0) {
        (void)fprintf(g_logFilePtr, "%-*s ", nameLen - SPACE_LEN, ELASTICGROUP);
        (void)fprintf(g_logFilePtr, "%-*s ", stateLen - SPACE_LEN,
            cluster_state_int_to_string(clusterStatusPtr->logic_cluster_status[LOGIC_CLUSTER_NUMBER - 1]));
        (void)fprintf(g_logFilePtr, "%-*s ", stateLen - SPACE_LEN,
            clusterStatusPtr->logic_is_all_group_mode_pending[LOGIC_CLUSTER_NUMBER - 1]
                ? "Yes" : "No");
        (void)fprintf(g_logFilePtr, "%-*s\n", stateLen - SPACE_LEN,
            (clusterStatusPtr->logic_switchedCount[LOGIC_CLUSTER_NUMBER - 1] == 0) ? "Yes" : "No");
    } else {
        (void)fprintf(g_logFilePtr, "%-*s ", nameLen - SPACE_LEN, ELASTICGROUP);
        (void)fprintf(g_logFilePtr, "%-*s ", stateLen - SPACE_LEN, "Normal");
        (void)fprintf(g_logFilePtr, "%-*s ", stateLen - SPACE_LEN, "No");
        (void)fprintf(g_logFilePtr, "%-*s\n", stateLen - SPACE_LEN, "Yes");
    }
}

static void PrintClusterStatus(int clusterStatus, bool redistributing, int switchedCount, int nodeID)
{
    (void)fprintf(g_logFilePtr, "[   Cluster State   ]\n\n");
    (void)fprintf(g_logFilePtr, "cluster_state   : %s\n", cluster_state_int_to_string(clusterStatus));
    (void)fprintf(g_logFilePtr, "redistributing  : %s\n", redistributing ? "Yes" : "No");
    if (!g_startStatusQuery || (logic_cluster_query && g_logic_cluster_count)) {
        (void)fprintf(g_logFilePtr, "balanced        : %s\n", (switchedCount == 0) ? "Yes" : "No");
        if (nodeID == -1) {
            (void)fprintf(g_logFilePtr, "current_az      : %s\n", "AZ_ALL");
        } else if (nodeID >= 0 && nodeID < (int)g_node_num) {
            (void)fprintf(g_logFilePtr, "current_az      : %s\n", g_node[nodeID].azName);
        } else {
            (void)fprintf(g_logFilePtr, "current_az      : %s\n", "AZ_DOWN");
        }
    }

    if (g_isPauseArbitration) {
        (void)fprintf(g_logFilePtr, "pausing         : Yes\n");
    }
}

int PrintLogicClusterStatus(const char *receiveMsg, int nodeId)
{
    cm_to_ctl_logic_cluster_status *clusterStatusPtr = (cm_to_ctl_logic_cluster_status*)receiveMsg;
    uint32 nameLen = max_logic_cluster_name_len + SPACE_NUM * SPACE_LEN;
    uint32 stateLen = max_logic_cluster_state_len;

    if (clusterStatusPtr->inReloading) {
        PrintClusterStatus();
        return CYCLE_BREAK;
    }
    PrintClusterStatus(clusterStatusPtr->cluster_status,
        clusterStatusPtr->is_all_group_mode_pending,
        clusterStatusPtr->switchedCount,
        nodeId);

    (void)fprintf(g_logFilePtr, "[   logicCluster State   ]\n\n");
    (void)fprintf(g_logFilePtr,
        "%-*s%-*s%-*s%s\n", nameLen,
        "logiccluster_name", stateLen,
        "logiccluster_state", stateLen,
        "redistributing", "balanced");

    for (uint32 i = 0;
        i < (nameLen - SPACE_LEN + STATE_NUM * (stateLen - SPACE_LEN));
        i++) {
        (void)fprintf(g_logFilePtr, "-");
    }
    (void)fprintf(g_logFilePtr, "\n");

    PrintLogicResult(nameLen, stateLen, clusterStatusPtr);
    return 0;
}

void SetCmQueryContentDetail(ctl_to_cm_query *cmQueryContent)
{
    if (g_coupleQuery) {
        cmQueryContent->detail = CLUSTER_COUPLE_STATUS_QUERY;
        if (g_detailQuery) {
            cmQueryContent->detail = CLUSTER_COUPLE_DETAIL_STATUS_QUERY;
            if (g_balanceQuery && !g_abnormalQuery) {
                cmQueryContent->detail = CLUSTER_BALANCE_COUPLE_DETAIL_STATUS_QUERY;
            }
            if (logic_cluster_query) {
                cmQueryContent->detail = CLUSTER_LOGIC_COUPLE_DETAIL_STATUS_QUERY;
            }
            if (g_abnormalQuery && !g_balanceQuery) {
                cmQueryContent->detail = CLUSTER_ABNORMAL_COUPLE_DETAIL_STATUS_QUERY;
            }
            if (g_abnormalQuery && g_balanceQuery) {
                cmQueryContent->detail = CLUSTER_ABNORMAL_BALANCE_COUPLE_DETAIL_STATUS_QUERY;
            }
            if (g_startStatusQuery) {
                cmQueryContent->detail = CLUSTER_START_STATUS_QUERY;
            }
        }
    } else if (g_paralleRedoState) {
        cmQueryContent->detail = CLUSTER_PARALLEL_REDO_REPLAY_STATUS_QUERY;
        if (g_detailQuery) {
            cmQueryContent->detail = CLUSTER_PARALLEL_REDO_REPLAY_DETAIL_STATUS_QUERY;
        }
    } else if (g_detailQuery) {
        cmQueryContent->detail = CLUSTER_DETAIL_STATUS_QUERY;
    } else {
        cmQueryContent->detail = CLUSTER_STATUS_QUERY;
    }
}

status_t SetCmQueryContent(ctl_to_cm_query *cmQueryContent)
{
    cmQueryContent->msg_type = (int)MSG_CTL_CM_QUERY;
    if (g_nodeIdSet) {
        cmQueryContent->node = g_commandOperationNodeId;
    } else {
        cmQueryContent->node = INVALID_NODE_NUM;
    }
    cmQueryContent->relation = 0;
    if (g_nodeIdSet && g_cmData[0] != '\0' && g_only_dn_cluster && g_commandRelationship) {
        int ret;
        int instanceType;
        uint32 instanceId;
        ret = FindInstanceIdAndType(g_commandOperationNodeId, g_cmData, &instanceId, &instanceType);
        if (ret != 0) {
            write_runlog(FATAL, "can't find the node_id:%u, data_path:%s.\n", g_commandOperationNodeId, g_cmData);
            return CM_ERROR;
        }
        if (instanceType != INSTANCE_TYPE_DATANODE) {
            write_runlog(FATAL, "data path %s is not dn.\n", g_cmData);
            return CM_ERROR;
        }
        cmQueryContent->instanceId = instanceId;
        cmQueryContent->relation = 1;
    } else {
        cmQueryContent->instanceId = INVALID_INSTACNE_NUM;
    }
    cmQueryContent->wait_seconds = g_waitSeconds;
    SetCmQueryContentDetail(cmQueryContent);
    return CM_SUCCESS;
}

void PrintCnHeaderLine(uint32 nodeLen, uint32 instanceLen, uint32 ipLen)
{
    (void)fprintf(g_logFilePtr, "\n[ Coordinator State ]\n\n");
    uint32 tmpInstanceLen = instanceLen;
    if (g_portQuery) {
        tmpInstanceLen = tmpInstanceLen + INSTANCE_LEN;
    }
    if (g_ipQuery) {
        (void)fprintf(g_logFilePtr,
            "%-*s%-*s%-*s%s\n",
            nodeLen,
            "node",
            ipLen,
            "node_ip",
            tmpInstanceLen,
            "instance",
            "state");
    } else {
        (void)fprintf(
            g_logFilePtr,
            "%-*s%-*s%s\n", nodeLen,
            "node",
            tmpInstanceLen,
            "instance",
            "state");
    }
    uint32 maxLen = nodeLen + instanceLen + INSTANCE_DYNAMIC_ROLE_LEN + (g_ipQuery ? ipLen : 0);
    for (uint32 i = 0; i < maxLen; i++) {
        (void)fprintf(g_logFilePtr, "-");
    }
    (void)fprintf(g_logFilePtr, "\n");
}

uint32 GetCnIpMaxLen()
{
    uint32 maxLen = MAX_IPV4_LEN;
    uint32 curIpLen;
    for (uint32 i = 0; i < g_node_num; ++i) {
        curIpLen = (uint32)strlen(g_node[i].coordinateListenIP[0]);
        maxLen = (maxLen > curIpLen) ? maxLen : curIpLen;
    }
    return (maxLen + SPACE_LEN);
}

int ProcessCoupleDetailQuery(const char *receiveMsg)
{
    int ret;
    const cm_to_ctl_cluster_status* clusterStatusPtr = (const cm_to_ctl_cluster_status*)receiveMsg;
    uint32 nodeLen = MAX_NODE_ID_LEN + SPACE_LEN + max_node_name_len + SPACE_LEN;
    const uint32 instanceLen =
        INSTANCE_ID_LEN + SPACE_LEN + (g_dataPathQuery ? (max_cnpath_len + 1) : DEFAULT_PATH_LEN);
    if (g_availabilityZoneCommand) {
        nodeLen += max_az_name_len + SPACE_LEN;
    }
    if (logic_cluster_query && g_logic_cluster_count) {
        ret = PrintLogicClusterStatus(receiveMsg, clusterStatusPtr->node_id);
        if (ret != 0) {
            return ret;
        }
    } else {
        if (clusterStatusPtr->inReloading && !g_startStatusQuery) {
            PrintClusterStatus();
            return CYCLE_BREAK;
        }
        PrintClusterStatus(clusterStatusPtr->cluster_status,
            clusterStatusPtr->is_all_group_mode_pending,
            clusterStatusPtr->switchedCount,
            clusterStatusPtr->node_id);
    }

    if (g_only_dn_cluster) {
        return 0;
    }
    uint32 ipLen = GetCnIpMaxLen();
    PrintCnHeaderLine(nodeLen, instanceLen, ipLen);
    return 0;
}

int ProcessDataBeginMsg(const char *receiveMsg, bool *recDataEnd)
{
    int ret;
    if (g_coupleQuery && g_detailQuery) {
        ret = ProcessCoupleDetailQuery(receiveMsg);
        if (ret != 0) {
            return ret;
        }
    } else {
        cm_to_ctl_cluster_status *clusterStatusPtr = (cm_to_ctl_cluster_status*)receiveMsg;
        (void)fprintf(g_logFilePtr,
            "-----------------------------------------------------------------------\n\n");
        (void)fprintf(g_logFilePtr,
            "cluster_state             : %s\n",
            cluster_state_int_to_string(clusterStatusPtr->cluster_status));
        (void)fprintf(g_logFilePtr,
            "redistributing            : %s\n",
            clusterStatusPtr->is_all_group_mode_pending ? "Yes" : "No");
        (void)fprintf(g_logFilePtr,
            "balanced                  : %s\n",
            (clusterStatusPtr->switchedCount == 0) ? "Yes" : "No");
        if (g_isPauseArbitration) {
            (void)fprintf(g_logFilePtr, "pausing                   : Yes\n");
        }
        (void)fprintf(g_logFilePtr, "\n");
        (void)fprintf(g_logFilePtr,
            "-----------------------------------------------------------------------\n\n");
    }
    if (!g_detailQuery) {
        *recDataEnd = true;
    }

    return CM_SUCCESS;
}

void CalcGtmHeaderSize(uint32 *nodeLen, uint32 *instanceLen, uint32 *stateLen)
{
    *nodeLen = MAX_NODE_ID_LEN + SPACE_LEN + max_node_name_len + SPACE_LEN;
    *instanceLen = INSTANCE_ID_LEN + SPACE_LEN + (g_dataPathQuery ? (max_gtmpath_len + 1) : DEFAULT_PATH_LEN);
    if (g_availabilityZoneCommand) {
        *nodeLen += max_az_name_len + SPACE_LEN;
    }
    if (g_single_node_cluster) {
        *stateLen =
            INSTANCE_STATIC_ROLE_LEN + SPACE_LEN + INSTANCE_DYNAMIC_ROLE_LEN + SPACE_LEN;
    } else {
        *stateLen = INSTANCE_STATIC_ROLE_LEN + SPACE_LEN + INSTANCE_DYNAMIC_ROLE_LEN +
                    SPACE_LEN + MAX_GTM_CONNECTION_STATE_LEN + SPACE_LEN;
    }
}
/*
 * @Description: print central node detail info
 * @IN file: file pointer
 * @Return: void
 */
static void PrintCentralNodeDetail(FILE* file)
{
    if (g_centralNode.instanceId == 0) {
        return;
    }

    /* query cm_server */
    uint32 nodeLen = MAX_NODE_ID_LEN + SPACE_LEN + max_node_name_len + SPACE_LEN;
    const uint32 instanceLen = INSTANCE_ID_LEN + SPACE_LEN +
        (g_dataPathQuery ? (max_cnpath_len + 1) : DEFAULT_PATH_LEN);
    uint32 ipLen = GetCnIpMaxLen();

    if (g_availabilityZoneCommand) {
        nodeLen += max_az_name_len + SPACE_LEN;
    }

    /* information head */
    (void)fprintf(file, "[ Central Coordinator State ]\n\n");

    /* show ip */
    if (g_ipQuery) {
        (void)fprintf(file, "%-*s%-*s%-*s%s\n", nodeLen, "node", ipLen, "node_ip", instanceLen, "instance", "state");
    } else {
        (void)fprintf(file, "%-*s%-*s%s\n", nodeLen, "node", instanceLen, "instance", "state");
    }

    for (uint32 i = 0; i < nodeLen + instanceLen + INSTANCE_DYNAMIC_ROLE_LEN + (g_ipQuery ? ipLen : 0);
         ++i) {
        (void)fprintf(file, "-");
    }

    (void)fprintf(file, "\n");

    int nodeIndex = g_centralNode.node_index;

    /* it's couple query */
    if (g_coupleQuery) {
        if (g_abnormalQuery && (strcmp(datanode_role_int_to_string(g_centralNode.status), "Normal") == 0)) {
            return;
        }
        if (g_availabilityZoneCommand) {
            (void)fprintf(g_logFilePtr, "%-*s ", max_az_name_len, g_node[nodeIndex].azName);
        }
        (void)fprintf(file, "%-2u ", g_node[nodeIndex].node);
        (void)fprintf(file, "%-*s ", max_node_name_len, g_node[nodeIndex].nodeName);

        if (g_ipQuery) {
            (void)fprintf(file, "%-*s ", ipLen, g_node[nodeIndex].coordinateListenIP[0]);
        }

        (void)fprintf(file, "%u ", g_centralNode.instanceId);

        if (g_dataPathQuery) {
            (void)fprintf(file, "%-*s ", max_cnpath_len, g_node[nodeIndex].DataPath);
        } else {
            (void)fprintf(file, "    ");
        }

        (void)fprintf(file, "%s\n", datanode_role_int_to_string(g_centralNode.status));
    } else {
        (void)fprintf(file, "node                      : %u\n", g_node[nodeIndex].node);
        (void)fprintf(file, "instance_id               : %u\n", g_centralNode.instanceId);
        (void)fprintf(file, "node_ip                   : %s\n", g_node[nodeIndex].coordinateListenIP[0]);
        (void)fprintf(file, "data_path                 : %s\n", g_node[nodeIndex].DataPath);
        (void)fprintf(file, "type                      : %s\n", type_int_to_string(INSTANCE_TYPE_COORDINATE));
        (void)fprintf(file, "state                     : %s\n\n", datanode_role_int_to_string(g_centralNode.status));
    }
}

uint32 GetGtmIpMaxLen()
{
    uint32 maxLen = MAX_IPV4_LEN;
    uint32 curIpLen;
    for (uint32 i = 0; i < g_node_num; ++i) {
        curIpLen = (uint32)strlen(g_node[i].gtmLocalListenIP[0]);
        maxLen = (maxLen > curIpLen) ? maxLen : curIpLen;
    }
    return (maxLen + SPACE_LEN);
}

void PrintGtmHeaderLine()
{
    uint32 nodeLen;
    uint32 instanceLen;
    uint32 stateLen;

    CalcGtmHeaderSize(&nodeLen, &instanceLen, &stateLen);
    uint32 ipLen = GetGtmIpMaxLen();

    if (g_only_dn_cluster) {
        return;
    }

    if (!g_balanceQuery || g_abnormalQuery) {
        (void)fprintf(g_logFilePtr, "\n");
        PrintCentralNodeDetail(g_logFilePtr);
    }

    if (!g_balanceQuery) {
        (void)fprintf(g_logFilePtr, "\n");
    }
    (void)fprintf(g_logFilePtr, "[     GTM State     ]\n\n");

    if (g_ipQuery) {
        if (g_single_node_cluster) {
            (void)fprintf(g_logFilePtr, "%-*s%-*s%-*s%-*s\n", nodeLen, "node", ipLen, "node_ip",
                instanceLen, "instance", stateLen, "state");
        } else {
            (void)fprintf(g_logFilePtr, "%-*s%-*s%-*s%-*s%s\n", nodeLen, "node", ipLen, "node_ip",
                instanceLen, "instance", stateLen, "state", "sync_state");
        }
    } else {
        if (g_single_node_cluster) {
            (void)fprintf(g_logFilePtr, "%-*s%-*s%-*s\n", nodeLen, "node", instanceLen, "instance", stateLen, "state");
        } else {
            (void)fprintf(g_logFilePtr, "%-*s%-*s%-*s%s\n",
                nodeLen, "node", instanceLen, "instance", stateLen, "state", "sync_state");
        }
    }
    for (uint32 i = 0; i < nodeLen + instanceLen + stateLen +
                        (g_single_node_cluster ? 0 : MAX_GTM_SYNC_STATE_LEN) +
                        (g_ipQuery ? ipLen : 0);
        i++) {
        (void)fprintf(g_logFilePtr, "-");
    }
    (void)fprintf(g_logFilePtr, "\n");
}

uint32 GetDnIpMaxLen()
{
    uint32 maxLen = MAX_IPV4_LEN;
    for (uint32 i = 0; i < g_node_num; ++i) {
        for (uint32 j = 0; j < g_node[i].datanodeCount; ++j) {
            uint32 curIpLen = (uint32)strlen(g_node[i].datanode[j].datanodeListenIP[0]);
            maxLen = (maxLen > curIpLen) ? maxLen : curIpLen;
        }
    }
    return (maxLen + SPACE_LEN);
}

void CalcDnHeaderSize(uint32 *nodeLen, uint32 *ipLen, uint32 *instanceLen, uint32 *stateLen)
{
    uint32 nameLen;
    uint32 nodeLength;

    nodeLength = MAX_NODE_ID_LEN + SPACE_LEN + max_node_name_len + SPACE_LEN;
    *instanceLen =
        INSTANCE_ID_LEN + SPACE_LEN + (g_dataPathQuery ? (max_datapath_len + 1) : DEFAULT_PATH_LEN);
    *stateLen = INSTANCE_STATIC_ROLE_LEN + SPACE_LEN + INSTANCE_DYNAMIC_ROLE_LEN +
                             SPACE_LEN + INSTANCE_DB_STATE_LEN + SPACE_LEN;
    nameLen = max_logic_cluster_name_len + SPACE_NUM * SPACE_LEN;
    if (g_availabilityZoneCommand) {
        nodeLength += max_az_name_len + SPACE_LEN;
    }
    if (g_balanceQuery && g_gtmBalance && !g_only_dn_cluster) {
        (void)fprintf(g_logFilePtr, "(no need to switchover gtm)\n");
    }
    if (logic_cluster_query) {
        (void)fprintf(g_logFilePtr, "%-*s| ", nameLen, "logiccluster_name");
    }
    *nodeLen = nodeLength;
    *ipLen = GetDnIpMaxLen();
}

void PrintDnHeaderLine(uint32 nodeLen, uint32 ipLen, uint32 instanceLen, uint32 tmpInstanceLen, uint32 stateLen)
{
    if (g_formatQuery) {
        if (g_ipQuery) {
            (void)fprintf(g_logFilePtr,
                "%-*s%-*s%-*s%s\n",
                nodeLen,
                "node",
                ipLen,
                "node_ip",
                tmpInstanceLen,
                "instance",
                "state");
        } else {
            (void)fprintf(g_logFilePtr, "%-*s%-*s%s\n", nodeLen, "node",
                g_single_node_cluster ? tmpInstanceLen : instanceLen, "instance", "state");
        }
    } else {
        if (g_ipQuery) {
            if (g_multi_az_cluster) {
                for (uint32 jj = 0; jj < g_dn_replication_num - 1; jj++) {
                    (void)fprintf(g_logFilePtr, "%-*s%-*s%-*s%-*s| ", nodeLen, "node", ipLen, "node_ip",
                        tmpInstanceLen, "instance", stateLen, "state");
                }
            } else if (!g_single_node_cluster) {
                (void)fprintf(g_logFilePtr, "%-*s%-*s%-*s%-*s| ", nodeLen, "node", ipLen, "node_ip",
                    tmpInstanceLen, "instance", stateLen, "state");
                (void)fprintf(g_logFilePtr, "%-*s%-*s%-*s%-*s| ", nodeLen, "node", ipLen, "node_ip",
                    tmpInstanceLen, "instance", stateLen, "state");
            }
            (void)fprintf(g_logFilePtr,
                "%-*s%-*s%-*s%s\n",
                nodeLen,
                "node",
                ipLen,
                "node_ip",
                tmpInstanceLen,
                "instance",
                "state");
        } else {
            if (g_multi_az_cluster) {
                for (uint32 jj = 0; jj < g_dn_replication_num - 1; jj++) {
                    (void)fprintf(g_logFilePtr, "%-*s%-*s%-*s| ", nodeLen, "node",
                        tmpInstanceLen, "instance", stateLen, "state");
                }
            } else if (!g_single_node_cluster) {
                (void)fprintf(g_logFilePtr, "%-*s%-*s%-*s| ", nodeLen, "node",
                    tmpInstanceLen, "instance", stateLen, "state");
                (void)fprintf(g_logFilePtr, "%-*s%-*s%-*s| ",
                    nodeLen, "node", tmpInstanceLen, "instance", stateLen, "state");
            }
            (void)fprintf(g_logFilePtr, "%-*s%-*s%s\n", nodeLen, "node",
                g_single_node_cluster ? tmpInstanceLen : instanceLen, "instance", "state");
        }
    }
}

void PrintDnStatusLine()
{
    uint32 nodeLen;
    uint32 ipLen;
    uint32 instanceLen;
    uint32 stateLen;

    CalcDnHeaderSize(&nodeLen, &ipLen, &instanceLen, &stateLen);
    uint32 tmpInstanceLen = instanceLen;
    if (g_portQuery) {
        tmpInstanceLen = tmpInstanceLen + INSTANCE_LEN;
    }

    (void)fprintf(g_logFilePtr, "\n[  Datanode State   ]\n\n");

    PrintDnHeaderLine(nodeLen, ipLen, instanceLen, tmpInstanceLen, stateLen);

    uint32 maxLen;
    uint32 secondryStateLen = INSTANCE_STATIC_ROLE_LEN + SPACE_LEN +
        SECONDARY_DYNAMIC_ROLE_LEN + SPACE_LEN + INSTANCE_DB_STATE_LEN;
    if (g_multi_az_cluster || g_single_node_cluster) {
        if (g_formatQuery) {
            maxLen = (nodeLen + tmpInstanceLen + (g_ipQuery ? ipLen : 0)) +
                (stateLen + SEPERATOR_LEN + SPACE_LEN);
        } else {
            maxLen = g_dn_replication_num *
                (nodeLen + tmpInstanceLen + (g_ipQuery ? ipLen : 0)) +
                    g_dn_replication_num * (stateLen + SEPERATOR_LEN + SPACE_LEN);
        }
    } else {
        if (g_formatQuery) {
            maxLen = (nodeLen + tmpInstanceLen + (g_ipQuery ? ipLen : 0)) +
                (stateLen + SEPERATOR_LEN + SPACE_LEN) + secondryStateLen;
        } else {
            maxLen = NODE_NUM * (nodeLen + tmpInstanceLen + (g_ipQuery ? ipLen : 0)) +
                SPACE_NUM * (stateLen + SEPERATOR_LEN + SPACE_LEN) + secondryStateLen;
        }
    }
    for (uint32 i = 0; i < maxLen; i++) {
        (void)fprintf(g_logFilePtr, "-");
    }
    (void)fprintf(g_logFilePtr, "\n");
}

void PrintFenceHeaderLine()
{
    const uint32 nodeLen = MAX_NODE_ID_LEN + SPACE_LEN + max_node_name_len + SPACE_LEN;
    uint32 ipLen = GetDnIpMaxLen();
    if (g_balanceQuery && g_datanodesBalance) {
        (void)fprintf(g_logFilePtr, "(no need to switchover datanodes)\n");
    }
    if (g_fencedUdfQuery && !g_balanceQuery) {
        (void)fprintf(g_logFilePtr, "\n[  Fenced UDF State   ]\n\n");
        if (g_ipQuery) {
            (void)fprintf(g_logFilePtr, "%-*s%-*s%s\n", nodeLen, "node", ipLen, "node_ip", "state");
        } else {
            (void)fprintf(g_logFilePtr, "%-*s%s\n", nodeLen, "node", "state");
        }
        for (uint32 i = 0; i < nodeLen + INSTANCE_DYNAMIC_ROLE_LEN + (g_ipQuery ? ipLen : 0); i++) {
            (void)fprintf(g_logFilePtr, "-");
        }
        (void)fprintf(g_logFilePtr, "\n");
    }
}

void DoProcessNodeEndMsg(const char *receiveMsg)
{
    int instanceType;
    if (undocumentedVersion != 0 && undocumentedVersion < SUPPORT_IPV6_VERSION) {
        cm_to_ctl_instance_status_ipv4 *instanceStatusPtrIpv4 = (cm_to_ctl_instance_status_ipv4 *)receiveMsg;
        instanceType = instanceStatusPtrIpv4->instance_type;
    } else {
        cm_to_ctl_instance_status *instanceStatusPtr = (cm_to_ctl_instance_status *)receiveMsg;
        instanceType = instanceStatusPtr->instance_type;
    }
    if (g_coupleQuery && !g_startStatusQuery) {
        if (instanceType == INSTANCE_TYPE_COORDINATE) {
            PrintGtmHeaderLine();
        }
        if (instanceType == INSTANCE_TYPE_GTM) {
            PrintDnStatusLine();
        }
        if (instanceType == INSTANCE_TYPE_DATANODE) {
            PrintFenceHeaderLine();
        }
    } else {
        (void)fprintf(g_logFilePtr,
            "-----------------------------------------------------------------------\n\n");
    }
}
