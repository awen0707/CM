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
 * cms_arbitrate_datanode_psd.cpp
 *    DN primary+standby+dummyStandby arbitration in cms
 *
 * IDENTIFICATION
 *    src/cm_server/cms_arbitrate_datanode_psd.cpp
 *
 * -------------------------------------------------------------------------
 */

#include "cms_arbitrate_datanode.h"
#include "cms_global_params.h"
#include "cms_process_messages.h"
#include "cms_ddb.h"
#include "cms_write_dynamic_config.h"
#include "cms_common.h"

/**
 * @brief
 * Sends arbitration-related command to the CM Agent instance.
 *
 * @note
 * 1. If the message was sent failed, the connection would be closed.
 * 2. The following message types are supported:
 * MSG_CM_AGENT_RESTART
 * MSG_CM_AGENT_NOTIFY
 * MSG_CM_AGENT_FAILOVER
 * MSG_CM_AGENT_BUILD
 * MSG_CM_AGENT_REP_SYNC
 * MSG_CM_AGENT_REP_MOST_AVAILABLE
 * 3. The parameter "instance_role", "time_out" and "full_build" are optional.
 *
 * @param  con              Connection object between the CM Server and CM Agent.
 * @param  msg_type         Type of the message.
 * @param  node             The node id.
 * @param  instance_id      The instance id.
 * @param  instance_role    The instance role.
 * @param  time_out         The operation timeout interval.
 * @param  full_build       The full build flag
 */
void send_arbitration_command(MsgRecvInfo* recvMsgInfo, const CM_MessageType &msg_type, const uint32 &node,
    const uint32 &instance_id, const int &instance_role = NO_NEED_TO_SET_PARAM,
    const int &time_out = NO_NEED_TO_SET_PARAM, const int &full_build = NO_NEED_TO_SET_PARAM)
{
    switch (msg_type) {
        case MSG_CM_AGENT_RESTART: {
            cm_to_agent_restart msg;
            msg.msg_type = (int)MSG_CM_AGENT_RESTART;
            msg.node = node;
            msg.instanceId = instance_id;
            WriteKeyEventLog(KEY_EVENT_RESTART, instance_id, "send restart message to instance(%u)", instance_id);
            (void)RespondMsg(recvMsgInfo, 'S', (char *)(&msg), sizeof(cm_to_agent_restart));
            break;
        }
        case MSG_CM_AGENT_NOTIFY: {
            cm_to_agent_notify msg;
            msg.term = FirstTerm;
            msg.msg_type = (int)MSG_CM_AGENT_NOTIFY;
            msg.node = node;
            msg.instanceId = instance_id;
            msg.role = instance_role;
            WriteKeyEventLog(KEY_EVENT_NOTIFY, instance_id, "send notify message to instance(%u)", instance_id);
            (void)RespondMsg(recvMsgInfo, 'S', (char *)(&msg), sizeof(cm_to_agent_notify));
            break;
        }
        case MSG_CM_AGENT_FAILOVER: {
            cm_to_agent_failover msg;
            msg.term = FirstTerm;
            msg.msg_type = (int)MSG_CM_AGENT_FAILOVER;
            msg.node = node;
            msg.instanceId = instance_id;
            WriteKeyEventLog(KEY_EVENT_FAILOVER, instance_id, "send failover message to instance(%u)", instance_id);
            (void)RespondMsg(recvMsgInfo, 'S', (char *)(&msg), sizeof(cm_to_agent_failover));
            break;
        }
        case MSG_CM_AGENT_BUILD: {
            cm_to_agent_build msg;
            msg.term = FirstTerm;
            msg.msg_type = (int)MSG_CM_AGENT_BUILD;
            msg.node = node;
            msg.instanceId = instance_id;
            msg.wait_seconds = time_out;
            msg.full_build = full_build;
            WriteKeyEventLog(KEY_EVENT_BUILD, instance_id, "send build message to instance(%u)", instance_id);
            (void)RespondMsg(recvMsgInfo, 'S', (char *)(&msg), sizeof(cm_to_agent_build));
            break;
        }
        case MSG_CM_AGENT_REP_SYNC: {
            cm_to_agent_rep_sync msg;
            msg.msg_type = (int)MSG_CM_AGENT_REP_SYNC;
            msg.node = node;
            msg.instanceId = instance_id;
            msg.sync_mode = INSTANCE_DATA_REPLICATION_SYNC;
            WriteKeyEventLog(KEY_EVENT_REP_SYNC, instance_id, "send rep sync message to instance(%u)", instance_id);
            (void)RespondMsg(recvMsgInfo, 'S', (char *)(&msg), sizeof(cm_to_agent_rep_sync));
            break;
        }
        case MSG_CM_AGENT_REP_MOST_AVAILABLE: {
            cm_to_agent_rep_most_available msg;
            msg.msg_type = (int)MSG_CM_AGENT_REP_MOST_AVAILABLE;
            msg.node = node;
            msg.instanceId = instance_id;
            msg.sync_mode = INSTANCE_DATA_REPLICATION_MOST_AVAILABLE;
            WriteKeyEventLog(KEY_EVENT_REP_MOST_AVAILABLE, instance_id,
                "send rep most available message to instance(%u)", instance_id);
            (void)RespondMsg(recvMsgInfo, 'S', (char *)(&msg), sizeof(cm_to_agent_rep_most_available));
            break;
        }
        default:
            break;
    }
}

void NotifyDatanodeDynamicPrimary(MsgRecvInfo* recvMsgInfo, const uint32 &node, const uint32 &instanceId,
    const uint32 &group, const int &member)
{
    send_arbitration_command(recvMsgInfo, MSG_CM_AGENT_NOTIFY, node, instanceId, INSTANCE_ROLE_PRIMARY);
    g_instance_group_report_status_ptr[group].instance_status.data_node_member[member].arbitrateFlag = true;
    cm_pending_notify_broadcast_msg(group, instanceId);
}

static int GetDatanodeStaticPrimaryIndex(const uint32 &group_index)
{
    int staticPrimaryIndex = -1;
    for (int member_index = 0; member_index < g_instance_role_group_ptr[group_index].count; member_index++) {
        int staticRole = g_instance_role_group_ptr[group_index].instanceMember[member_index].role;
        if (staticRole == INSTANCE_ROLE_PRIMARY) {
            staticPrimaryIndex = member_index;
            break;
        }
    }
    return staticPrimaryIndex;
}

static int GetDatanodeInitPrimaryIndex(const uint32 &group_index)
{
    int initPrimaryIndex = -1;

    /* Find the init primary member index. */
    for (int member_index = 0; member_index < g_instance_role_group_ptr[group_index].count; member_index++) {
        const int initRole = g_instance_role_group_ptr[group_index].instanceMember[member_index].instanceRoleInit;
        if (initRole == INSTANCE_ROLE_PRIMARY) {
            initPrimaryIndex = member_index;
            break;
        }
    }

    /* If can not find the init primary member index, use the first instance instead. */
    if (initPrimaryIndex == -1) {
        initPrimaryIndex = 0;
        write_runlog(ERROR, "Failed to find the init primary instance, use the first instance instead:"
            " node_id=%u, instance_id=%u.\n",
            g_instance_role_group_ptr[group_index].instanceMember[0].node,
            g_instance_role_group_ptr[group_index].instanceMember[0].instanceId);
    }

    return initPrimaryIndex;
}

/**
 * @brief
 * Obtains the instance status structure reference based on the instance group index.
 *
 * @note
 * Generally, the instance group index is obtained from the dynamic configuration information
 * based on the node ID and instance ID.
 *
 * @param  group_index      The instance group index.
 * @return Return the instance status structure reference.
 */
inline cm_instance_report_status &get_instance_status(const uint32& group_index)
{
    return g_instance_group_report_status_ptr[group_index].instance_status;
}
static inline cm_instance_command_status &get_command_status(const uint32& group_index, const int &member_index)
{
    return get_instance_status(group_index).command_member[member_index];
}

int get_pending_command(const uint32 &group_index, const int &member_index)
{
    return get_command_status(group_index, member_index).pengding_command;
}

bool is_pending_command(const uint32 &group_index, const int &member_index, const CM_MessageType &pending_command)
{
    return (get_pending_command(group_index, member_index) == pending_command);
}


/**
 * @brief
 * Sets the pending command of the build type.
 *
 * @note
 * 1. Generally, the instance group index and the instance member index is obtained from the
 * dynamic configuration information based on the node ID and instance ID.
 * 2. Search for the instance command status structure by the group index and the member index.
 * 3. The parameter "full_build" can be 1 (full build) or 0(not specified) or NO_NEED_TO_SET_PARAM.
 *
 * @param group_index       The instance group index.
 * @param member_index      The instance member index.
 * @param pending_command   The pending command type.
 * @param time_out          The timeout interval of the build command.
 * @param group_index       The full build flag.
 */
void set_pending_command(
    const uint32 &group_index,
    const int &member_index,
    const CM_MessageType &pending_command,
    const int &time_out,
    const int &full_build)
{
    cm_instance_command_status& instance_command_status = get_command_status(group_index, member_index);
    switch (pending_command) {
        case MSG_CM_AGENT_SWITCHOVER:
            instance_command_status.command_status = (int)INSTANCE_COMMAND_WAIT_EXEC;
            instance_command_status.pengding_command = (int)MSG_CM_AGENT_SWITCHOVER;
            instance_command_status.command_send_num = 0;
            if (time_out != NO_NEED_TO_SET_PARAM) {
                instance_command_status.time_out = time_out;
            }
            SetSendTimes(group_index, member_index, time_out);
            break;

        case MSG_CM_AGENT_BUILD:
            instance_command_status.command_status = (int)INSTANCE_COMMAND_WAIT_EXEC;
            instance_command_status.pengding_command = (int)MSG_CM_AGENT_BUILD;
            if (time_out != NO_NEED_TO_SET_PARAM) {
                instance_command_status.time_out = time_out;
            }
            if (full_build != NO_NEED_TO_SET_PARAM) {
                instance_command_status.full_build = full_build;
            }
            break;

        case MSG_CM_AGENT_NOTIFY_CN:
            instance_command_status.command_status = (int)INSTANCE_COMMAND_WAIT_EXEC;
            instance_command_status.pengding_command = (int)MSG_CM_AGENT_NOTIFY_CN;
            break;

        case MSG_CM_AGENT_BUTT:
            instance_command_status.command_status = (int)INSTANCE_NONE_COMMAND;
            instance_command_status.pengding_command = (int)MSG_CM_AGENT_BUTT;
            instance_command_status.time_out = 0;
            instance_command_status.full_build = 0;
            instance_command_status.command_send_num = 0;
            instance_command_status.command_send_times = 0;
            break;

        default:
            write_runlog(ERROR, "The specified command type does not support pending command setting:"
                " pending_command=%d(%s).", (int)pending_command, cluster_msg_int_to_string((int)pending_command));
            break;
    }
}

/**
 * @brief Get the Data Node Member object
 *
 * @param  group            My Param doc
 * @param  member           My Param doc
 * @return cm_instance_datanode_report_status&
 */
cm_instance_datanode_report_status &GetDataNodeMember(const uint32 &group, const int &member)
{
    return g_instance_group_report_status_ptr[group].instance_status.data_node_member[member];
}

static inline int GetInstanceType(const uint32 &group, const int &member)
{
    return g_instance_role_group_ptr[group].instanceMember[member].instanceType;
}

static inline uint32 GetInstanceId(const uint32 &group, const int &member)
{
    return g_instance_role_group_ptr[group].instanceMember[member].instanceId;
}

void DealDataNodeDBStateChange(const uint32 &group, const int &member, const int &dbStatePrev)
{
    if (GetInstanceType(group, member) != INSTANCE_TYPE_DATANODE) {
        write_runlog(ERROR, "Instance %u is not a datanode.\n", GetInstanceId(group, member));
        return;
    }

    int dbStateCurr = GetDataNodeMember(group, member).local_status.db_state;
    bool cdt = (dbStatePrev != INSTANCE_HA_STATE_MANUAL_STOPPED && dbStateCurr == INSTANCE_HA_STATE_MANUAL_STOPPED);
    if (cdt) {
        write_runlog(LOG,
            "The db_state of instance %u is changed from %d (%s) to %d (%s). "
            "Clean the corresponding pending command.\n",
            GetInstanceId(group, member), dbStatePrev, datanode_dbstate_int_to_string(dbStatePrev), dbStateCurr,
            datanode_dbstate_int_to_string(dbStateCurr));
        set_pending_command(group, member, MSG_CM_AGENT_BUTT);
    }
}

bool check_datanode_arbitrate_status(uint32 group_index, int member_index)
{
    bool findPrimary = false;
    bool arbitrateFlag = false;
    for (int i = 0; i < g_instance_role_group_ptr[group_index].count; i++) {
        if (g_instance_group_report_status_ptr[group_index]
            .instance_status.data_node_member[i]
            .local_status.local_role == INSTANCE_ROLE_PRIMARY) {
            findPrimary = true;
        }

        if (g_instance_group_report_status_ptr[group_index].instance_status.data_node_member[i].arbitrateFlag) {
            if (g_instance_group_report_status_ptr[group_index].instance_status.data_node_member[i]
                .local_status.local_role != INSTANCE_ROLE_STANDBY &&
                g_instance_group_report_status_ptr[group_index].instance_status.data_node_member[i]
                .local_status.local_role != INSTANCE_ROLE_PRIMARY) {
                g_instance_group_report_status_ptr[group_index].instance_status.data_node_member[i].arbitrateFlag =
                    false;
                if (i == member_index) {
                    write_runlog(LOG, "reset arbitrateFlag for instance %u.\n",
                        g_instance_role_group_ptr[group_index].instanceMember[i].instanceId);
                    return true;
                }
                continue;
            }
            write_runlog(LOG, "find instanceId %u is arbitrating now.\n",
                g_instance_role_group_ptr[group_index].instanceMember[i].instanceId);
            if (arbitrateFlag) {
                write_runlog(LOG, "find double arbitrate for %u.\n", group_index);
            }
            if (i == member_index) {
                arbitrateFlag = false;
                write_runlog(LOG, "instance %d is promoting to primary now.\n",
                    g_instance_role_group_ptr[group_index].instanceMember[i].role);
            } else {
                arbitrateFlag = true;
                bool cdt = (g_instance_role_group_ptr[group_index].instanceMember[i].role != INSTANCE_ROLE_PRIMARY &&
                    g_instance_group_report_status_ptr[group_index]
                                    .instance_status.data_node_member[i]
                                    .local_status.db_state != INSTANCE_HA_STATE_PROMOTING);
                if (cdt) {
                    g_instance_group_report_status_ptr[group_index].instance_status.data_node_member[i].arbitrateFlag =
                        false;
                    write_runlog(LOG, "reset arbitrateFlag for instance %u, it't static role is standby.\n",
                        g_instance_role_group_ptr[group_index].instanceMember[i].instanceId);
                }
            }
        }
    }
    if (findPrimary) {
        g_instance_group_report_status_ptr[group_index].instance_status.cma_kill_instance_timeout = 0;
        for (int i = 0; i < g_instance_role_group_ptr[group_index].count; i++) {
            g_instance_group_report_status_ptr[group_index].instance_status.data_node_member[i].arbitrateFlag = false;
        }
    }

    if (findPrimary) {
        return true;
    } else {
        return arbitrateFlag;
    }
}

int find_candiate_primary_node_in_instance_role_group(uint32 group_index, int member_index)
{
    int candiate_primary_member_index = -1;
    cm_instance_role_group *role_group = &g_instance_role_group_ptr[group_index];
    int count = role_group->count;
    cm_instance_role_status *instanceMember = role_group->instanceMember;
    cm_instance_datanode_report_status *dnReportStatus =
        g_instance_group_report_status_ptr[group_index].instance_status.data_node_member;
    uint32 unknownNum = 0;
    int staticPrimaryIndex = 0;
    bool isStaticPrimaryIndexSet = false;
    XLogRecPtr last_lsn = 0;
    uint32 term = InvalidTerm;
    bool findSameAzForStaticPrimary = false;
    uint32 azPriority = g_az_invalid;
    bool findSameAz = false;
    bool cdt;

    DealDbstateNormalPrimaryDown(group_index, INSTANCE_TYPE_DATANODE);

    for (int i = 0; i < count; i++) {
        if (instanceMember[i].role == INSTANCE_ROLE_PRIMARY) {
            staticPrimaryIndex = i;
            isStaticPrimaryIndexSet = true;
            break;
        }
    }

    if (!g_multi_az_cluster) {
        int other_member_index = ((member_index == 0) ? 1 : 0);
        cdt = (dnReportStatus[member_index].local_status.db_state == INSTANCE_HA_STATE_NEED_REPAIR ||
            (dnReportStatus[member_index].local_status.db_state == INSTANCE_HA_STATE_NORMAL &&
            g_instance_group_report_status_ptr[group_index].instance_status.cma_kill_instance_timeout == 1) ||
            (g_instance_group_report_status_ptr[group_index].instance_status.data_node_member[other_member_index]
                .phony_dead_times > 2 * phony_dead_effective_time &&
            dnReportStatus[other_member_index].local_status.local_role == INSTANCE_ROLE_UNKNOWN));
        if (cdt) {
            return member_index;
        } else {
            return -1;
        }
    }

    for (int i = 0; i < count; i++) {
        int dynamic_role;
        int db_state;

        dynamic_role = dnReportStatus[i].local_status.local_role;
        if (dynamic_role == INSTANCE_ROLE_PRIMARY) {
            candiate_primary_member_index = -1;
            break;
        } else if (dynamic_role == INSTANCE_ROLE_STANDBY || dynamic_role == INSTANCE_ROLE_PENDING) {
            db_state = dnReportStatus[i].local_status.db_state;

            cdt = (db_state == INSTANCE_HA_STATE_NEED_REPAIR ||
                ((db_state == INSTANCE_HA_STATE_NORMAL) &&
                (g_instance_group_report_status_ptr[group_index].instance_status.cma_kill_instance_timeout == 1)) ||
                (isStaticPrimaryIndexSet && g_instance_group_report_status_ptr[group_index]
                                                    .instance_status.data_node_member[staticPrimaryIndex]
                                                    .phony_dead_times > 2 * phony_dead_effective_time));
            if (cdt) {
                /* get highest xlog instance */
                cdt = (XLByteLT_W_TERM(term, last_lsn, dnReportStatus[i].local_status.term,
                    dnReportStatus[i].local_status.last_flush_lsn) &&
                    isStaticPrimaryIndexSet);
                if (cdt) {
                    term = dnReportStatus[i].local_status.term;
                    last_lsn = dnReportStatus[i].local_status.last_flush_lsn;
                    candiate_primary_member_index = i;
                    azPriority = instanceMember[i].azPriority;
                    if (i == staticPrimaryIndex) {
                        findSameAzForStaticPrimary = true;
                        findSameAz = true;
                    } else if (strcmp(instanceMember[i].azName, instanceMember[staticPrimaryIndex].azName) == 0) {
                        findSameAz = true;
                    }
                } else if (XLByteEQ_W_TERM(term, last_lsn, dnReportStatus[i].local_status.term,
                    dnReportStatus[i].local_status.last_flush_lsn) &&
                    !XLogRecPtrIsInvalid(dnReportStatus[i].local_status.last_flush_lsn) && isStaticPrimaryIndexSet &&
                    (strcmp(instanceMember[i].azName, instanceMember[staticPrimaryIndex].azName) == 0)) {
                    if (findSameAzForStaticPrimary) {
                        continue;
                    }
                    if (i == staticPrimaryIndex) {
                        findSameAzForStaticPrimary = true;
                    }
                    findSameAz = true;
                    last_lsn = dnReportStatus[i].local_status.last_flush_lsn;
                    term = dnReportStatus[i].local_status.term;
                    candiate_primary_member_index = i;
                    azPriority = instanceMember[i].azPriority;
                } else if (XLByteEQ_W_TERM(term, last_lsn, dnReportStatus[i].local_status.term,
                    dnReportStatus[i].local_status.last_flush_lsn) &&
                    !XLogRecPtrIsInvalid(dnReportStatus[i].local_status.last_flush_lsn) &&
                    (!isStaticPrimaryIndexSet ||
                    (strcmp(instanceMember[i].azName, instanceMember[staticPrimaryIndex].azName) != 0))) {
                    if (findSameAz) {
                        continue;
                    }
                    cdt = (azPriority > instanceMember[i].azPriority || azPriority == g_az_invalid);
                    if (cdt) {
                        last_lsn = dnReportStatus[i].local_status.last_flush_lsn;
                        term = dnReportStatus[i].local_status.term;
                        candiate_primary_member_index = i;
                        azPriority = instanceMember[i].azPriority;
                    }
                }
            } else {
                write_runlog(LOG, "db state is not need repair(%u,%d).\n",
                    g_instance_role_group_ptr[group_index].instanceMember[i].instanceId, db_state);
                candiate_primary_member_index = -1;
                break;
            }
        } else if (dynamic_role == INSTANCE_ROLE_UNKNOWN) {
            unknownNum++;
        }
    }
    cdt = ((cm_arbitration_mode == MAJORITY_ARBITRATION) && (unknownNum > (g_dn_replication_num / 2)));
    if (cdt) {
        return -1;
    }

    if (member_index == candiate_primary_member_index) {
        write_runlog(LOG, "find prep dn %u that to be primary.\n",
            g_instance_role_group_ptr[group_index].instanceMember[member_index].instanceId);
        for (int32 j = 0; j < g_instance_role_group_ptr[group_index].count; j++) {
            write_runlog(LOG,
                " instanceid: %u, static role: %s, dynamic role: %s, "
                "db state: %s, term: %u, xlog: %X/%X.\n",
                g_instance_role_group_ptr[group_index].instanceMember[j].instanceId,
                datanode_role_int_to_string(g_instance_role_group_ptr[group_index].instanceMember[j].role),
                datanode_role_int_to_string(g_instance_group_report_status_ptr[group_index]
                    .instance_status.data_node_member[j].local_status.local_role),
                datanode_dbstate_int_to_string(g_instance_group_report_status_ptr[group_index]
                    .instance_status.data_node_member[j].local_status.db_state),
                g_instance_group_report_status_ptr[group_index].instance_status.data_node_member[j].local_status.term,
                (uint32)(g_instance_group_report_status_ptr[group_index]
                    .instance_status.data_node_member[j].local_status.last_flush_lsn >> 32),
                (uint32)g_instance_group_report_status_ptr[group_index]
                    .instance_status.data_node_member[j].local_status.last_flush_lsn);
        }
    }

    /* Check if the candidate is located in the faulty AZ */
    candiate_primary_member_index = check_if_candidate_is_in_faulty_az(group_index, candiate_primary_member_index);

    return candiate_primary_member_index;
}


int find_auto_switchover_primary_node(uint32 group_index, int member_index)
{
    /*
     * When cluster is normal, the DN restarted frequently due to a disk failure.
     * here , to find candinate primary node.
     */
    int candiate_primary = -1;
    cm_instance_role_group* role_group = &g_instance_role_group_ptr[group_index];
    int count = role_group->count;
    cm_instance_role_status* instanceMember = role_group->instanceMember;
    cm_instance_datanode_report_status* dnReportStatus =
        g_instance_group_report_status_ptr[group_index].instance_status.data_node_member;
    cm_instance_command_status* dnCommandStatus =
        g_instance_group_report_status_ptr[group_index].instance_status.command_member;
    int staticPrimaryIndex = -1;
    uint32 azPriority = g_az_invalid;

    for (int i = 0; i < count; i++) {
        if (dnCommandStatus[i].pengding_command == (int)MSG_CM_AGENT_SWITCHOVER) {
            return -1;
        }
    }
    for (int i = 0; i < count; i++) {
        if (instanceMember[i].role == INSTANCE_ROLE_PRIMARY) {
            staticPrimaryIndex = i;
            break;
        }
    }

    for (int i = 0; i < count; i++) {
        int dynamic_role;
        int db_state;

        dynamic_role = dnReportStatus[i].local_status.local_role;
        if (dynamic_role == INSTANCE_ROLE_PRIMARY) {
            continue;
        } else if (dynamic_role == INSTANCE_ROLE_STANDBY) {
            db_state = dnReportStatus[i].local_status.db_state;

            if (db_state == INSTANCE_HA_STATE_NORMAL) {
                if (i == staticPrimaryIndex ||
                    strcmp(instanceMember[i].azName, instanceMember[staticPrimaryIndex].azName) == 0) {
                    candiate_primary = i;
                    break;
                } else if (strcmp(instanceMember[i].azName, instanceMember[staticPrimaryIndex].azName) != 0) {
                    if ((azPriority < instanceMember[i].azPriority && azPriority > g_az_invalid) ||
                        azPriority == g_az_invalid) {
                        candiate_primary = i;
                        azPriority = instanceMember[i].azPriority;
                    }
                }
            }
        } else {
            return -1;
        }
    }

    if (member_index == candiate_primary && member_index >= 0) {
        write_runlog(LOG,
            "find prep dn %u that to be primary.\n",
            g_instance_role_group_ptr[group_index].instanceMember[member_index].instanceId);
    }

    return candiate_primary;
}

static void ResetInstanceStatusHeartbeat(uint32 groupIndex, int memberIndex)
{
    g_instance_group_report_status_ptr[groupIndex].instance_status.command_member[memberIndex].heat_beat = 0;
    g_instance_group_report_status_ptr[groupIndex]
        .instance_status.command_member[memberIndex].keep_heartbeat_timeout = 0;
}

static void UpdateDataNodeMemberStatus(const agent_to_cm_datanode_status_report *agentToCmDatanodeStatusPtr,
    uint32 groupIndex, int memberIndex)
{
    errno_t rc = memcpy_s((void *)&(
        g_instance_group_report_status_ptr[groupIndex].instance_status.data_node_member[memberIndex].local_status),
        sizeof(cm_local_replconninfo), (void *)&(agentToCmDatanodeStatusPtr->local_status),
        sizeof(cm_local_replconninfo));
    securec_check_errno(rc, (void)rc);
    rc = memcpy_s((void *)&(
        g_instance_group_report_status_ptr[groupIndex].instance_status.data_node_member[memberIndex].build_info),
        sizeof(BuildState), (void *)&(agentToCmDatanodeStatusPtr->build_info), sizeof(BuildState));
    securec_check_errno(rc, (void)rc);
    rc = memcpy_s((void *)&(g_instance_group_report_status_ptr[groupIndex].instance_status
        .data_node_member[memberIndex].sender_status[0]),
        CM_MAX_SENDER_NUM * sizeof(cm_sender_replconninfo), (void *)agentToCmDatanodeStatusPtr->sender_status,
        CM_MAX_SENDER_NUM * sizeof(cm_sender_replconninfo));
    securec_check_errno(rc, (void)rc);
    rc = memcpy_s((void *)&(
        g_instance_group_report_status_ptr[groupIndex].instance_status.data_node_member[memberIndex].receive_status),
        sizeof(cm_receiver_replconninfo), (void *)&(agentToCmDatanodeStatusPtr->receive_status),
        sizeof(cm_receiver_replconninfo));
    securec_check_errno(rc, (void)rc);
}

static void UpdateDataNodeMemberDnRestartCount(
    const agent_to_cm_datanode_status_report *agentToCmDatanodeStatusPtr,
    uint32 groupIndex, int memberIndex)
{
    g_instance_group_report_status_ptr[groupIndex].instance_status.data_node_member[memberIndex].dn_restart_counts =
        agentToCmDatanodeStatusPtr->dn_restart_counts;
    g_instance_group_report_status_ptr[groupIndex].instance_status.data_node_member[memberIndex]
        .dn_restart_counts_in_hour = agentToCmDatanodeStatusPtr->dn_restart_counts_in_hour;
}

static void CheckAndUpdatePhonyDeadInfo(const agent_to_cm_datanode_status_report *agentToCmDatanodeStatusPtr,
    uint32 groupIndex, int memberIndex)
{
    uint32 instanceId = agentToCmDatanodeStatusPtr->instanceId;
    bool cdt = (g_instance_group_report_status_ptr[groupIndex]
            .instance_status.data_node_member[memberIndex].phony_dead_times >= phony_dead_effective_time &&
        agentToCmDatanodeStatusPtr->phony_dead_times == 0);
    if (cdt) {
        g_instance_group_report_status_ptr[groupIndex]
            .instance_status.data_node_member[memberIndex].phony_dead_interval = instance_phony_dead_restart_interval;
        write_runlog(LOG, "set phony dead interval to %d for instance %u.\n",
            g_instance_group_report_status_ptr[groupIndex]
                .instance_status.data_node_member[memberIndex].phony_dead_interval,
            instanceId);
    }
    g_instance_group_report_status_ptr[groupIndex].instance_status.data_node_member[memberIndex].phony_dead_times =
        agentToCmDatanodeStatusPtr->phony_dead_times;
}

static void CheckIfNeedSetSyncMode(uint32 instanceId, uint32 groupIndex, int memberIndex, int otherMemberIndex)
{
    bool cdt = ((((g_instance_group_report_status_ptr[groupIndex].instance_status.data_node_member[memberIndex]
            .local_status.local_role == INSTANCE_ROLE_PRIMARY &&
        g_instance_group_report_status_ptr[groupIndex].instance_status.data_node_member[otherMemberIndex]
            .local_status.local_role == INSTANCE_ROLE_STANDBY) ||
        (g_instance_group_report_status_ptr[groupIndex].instance_status.data_node_member[memberIndex]
            .local_status.local_role == INSTANCE_ROLE_STANDBY &&
        g_instance_group_report_status_ptr[groupIndex].instance_status.data_node_member[otherMemberIndex]
            .local_status.local_role == INSTANCE_ROLE_PRIMARY)) &&
        g_instance_group_report_status_ptr[groupIndex].instance_status.data_node_member[memberIndex]
            .local_status.db_state == INSTANCE_HA_STATE_NORMAL &&
        g_instance_group_report_status_ptr[groupIndex].instance_status.data_node_member[otherMemberIndex]
            .local_status.db_state == INSTANCE_HA_STATE_NORMAL) ||
        (cm_arbitration_mode == MINORITY_ARBITRATION));
    if (cdt) {
        cdt = (g_instance_group_report_status_ptr[groupIndex].instance_status.
                command_member[memberIndex].sync_mode == 0);
        if (cdt) {
            write_runlog(LOG, "the sync mode of instance %u become to 1.\n", instanceId);
        }
        g_instance_group_report_status_ptr[groupIndex].instance_status.command_member[memberIndex].sync_mode = 1;
    }
}

static void CheckIfNeedClearSyncMode(uint32 groupIndex, int memberIndex, int otherMemberIndex)
{
    bool cdt = (g_instance_group_report_status_ptr[groupIndex].instance_status.data_node_member[memberIndex]
            .local_status.local_role == INSTANCE_ROLE_PRIMARY &&
        g_instance_group_report_status_ptr[groupIndex].instance_status.data_node_member[otherMemberIndex]
            .local_status.local_role == INSTANCE_ROLE_UNKNOWN &&
        (cm_arbitration_mode == MAJORITY_ARBITRATION));
    if (cdt) {
        if (g_instance_group_report_status_ptr[groupIndex]
                .instance_status.command_member[otherMemberIndex].sync_mode == 1) {
            write_runlog(LOG, "the sync mode of instance %u become to 0.\n",
                g_instance_role_group_ptr[groupIndex].instanceMember[otherMemberIndex].instanceId);
        }
        g_instance_group_report_status_ptr[groupIndex]
            .instance_status.command_member[otherMemberIndex].sync_mode = 0;
    }
}

static void CheckDnRoleAndDbState(uint32 groupIndex, int memberIndex, int otherMemberIndex, uint32 node,
    uint32 instanceId)
{
    XLogRecPtr localLastXlogLocation;
    XLogRecPtr PeerLastXlogLocation;

    int localStaticRole;
    int peerStaticRole;
    int localDynamicRole;
    int peerDynamicRole;
    int localDbState;
    int peerDbState;
    int localSyncState;
    int buildReason;
    int doubleRestarting;
    uint32 peerInstanceId;

    localStaticRole = g_instance_role_group_ptr[groupIndex].instanceMember[memberIndex].role;
    localDynamicRole = g_instance_group_report_status_ptr[groupIndex]
        .instance_status.data_node_member[memberIndex].local_status.local_role;
    peerStaticRole = g_instance_role_group_ptr[groupIndex].instanceMember[otherMemberIndex].role;
    peerDynamicRole = g_instance_group_report_status_ptr[groupIndex]
        .instance_status.data_node_member[otherMemberIndex].local_status.local_role;
    localLastXlogLocation = g_instance_group_report_status_ptr[groupIndex]
        .instance_status.data_node_member[memberIndex].local_status.last_flush_lsn;
    PeerLastXlogLocation = g_instance_group_report_status_ptr[groupIndex]
        .instance_status.data_node_member[otherMemberIndex].local_status.last_flush_lsn;
    localDbState = g_instance_group_report_status_ptr[groupIndex]
        .instance_status.data_node_member[memberIndex].local_status.db_state;
    peerDbState = g_instance_group_report_status_ptr[groupIndex]
        .instance_status.data_node_member[otherMemberIndex].local_status.db_state;
    localSyncState = g_instance_group_report_status_ptr[groupIndex]
        .instance_status.data_node_member[memberIndex].sender_status[0].sync_state;
    buildReason = g_instance_group_report_status_ptr[groupIndex]
        .instance_status.data_node_member[memberIndex].local_status.buildReason;
    doubleRestarting = (int)g_instance_group_report_status_ptr[groupIndex]
        .instance_status.arbitrate_status_member[memberIndex].restarting;
    peerInstanceId = g_instance_role_group_ptr[groupIndex].instanceMember[otherMemberIndex].instanceId;

    bool cdt = ((localDynamicRole != INSTANCE_ROLE_PRIMARY && localDynamicRole != INSTANCE_ROLE_STANDBY) ||
        (localDbState != INSTANCE_HA_STATE_NORMAL) ||
        (localDynamicRole == INSTANCE_ROLE_PRIMARY && localStaticRole != INSTANCE_ROLE_PRIMARY));
    if (cdt) {
        write_runlog(LOG, "node %u, instanceId %u, localStaticRole %d=%s, localDynamicRole %d=%s, "
            "peer_instanceId %u, peerStaticRole %d=%s, peerDynamicRole %d=%s "
            ", localLastXlogLocation=%X/%X, PeerLastXlogLocation=%X/%X, localDbState %d=%s, peerDbState "
            "%d=%s, localSyncState=%d, buildReason %d=%s, doubleRestarting=%d \n",
            node, instanceId, localStaticRole, datanode_role_int_to_string(localStaticRole), localDynamicRole,
            datanode_role_int_to_string(localDynamicRole), peerInstanceId, peerStaticRole,
            datanode_role_int_to_string(peerStaticRole), peerDynamicRole,
            datanode_role_int_to_string(peerDynamicRole), (uint32)(localLastXlogLocation >> 32),
            (uint32)localLastXlogLocation, (uint32)(PeerLastXlogLocation >> 32), (uint32)PeerLastXlogLocation,
            localDbState, datanode_dbstate_int_to_string(localDbState), peerDbState,
            datanode_dbstate_int_to_string(peerDbState), localSyncState, buildReason,
            datanode_rebuild_reason_int_to_string(buildReason), doubleRestarting);
    }
}

static void ArbitrationSetRestarting(uint32 groupIndex, int memberIndex, int otherMemberIndex)
{
    g_instance_group_report_status_ptr[groupIndex]
        .instance_status.arbitrate_status_member[memberIndex].restarting = true;
    g_instance_group_report_status_ptr[groupIndex]
        .instance_status.arbitrate_status_member[otherMemberIndex].restarting = true;
}

static void PeerStaticRoleCheckStandbyProcess(uint32 groupIndex, int memberIndex, int otherMemberIndex,
    MsgRecvInfo* recvMsgInfo, const agent_to_cm_datanode_status_report *agentToCmDatanodeStatusPtr)
{
    uint32 node = agentToCmDatanodeStatusPtr->node;
    uint32 instanceId = agentToCmDatanodeStatusPtr->instanceId;
    int peerStaticRole = g_instance_role_group_ptr[groupIndex].instanceMember[otherMemberIndex].role;
    if (peerStaticRole != INSTANCE_ROLE_STANDBY) {
        send_arbitration_command(recvMsgInfo, MSG_CM_AGENT_RESTART, node, instanceId);
        g_instance_group_report_status_ptr[groupIndex]
            .instance_status.arbitrate_status_member[memberIndex].restarting = true;
        write_runlog(LOG, "double primary datanode instance, restart to pending.\n");
    } else {
        cm_pending_notify_broadcast_msg(groupIndex, instanceId);
        write_runlog(LOG,
            "double primary datanode instance, peerStaticRole %u is standby, need to restart peer.\n",
            g_instance_role_group_ptr[groupIndex].instanceMember[otherMemberIndex].instanceId);
    }
    g_instance_group_report_status_ptr[groupIndex]
        .instance_status.arbitrate_status_member[otherMemberIndex].restarting = true;
}

static void InstanceIsBuildingProcess(uint32 groupIndex, int memberIndex, uint32 instanceId)
{
    int localDynamicRole = g_instance_group_report_status_ptr[groupIndex]
        .instance_status.data_node_member[memberIndex].local_status.local_role;
    int localDbState = g_instance_group_report_status_ptr[groupIndex]
        .instance_status.data_node_member[memberIndex].local_status.db_state;

    bool cdt = (localDynamicRole == INSTANCE_ROLE_STANDBY && localDbState == INSTANCE_HA_STATE_BUILDING);
    if (cdt) {
        g_instance_group_report_status_ptr[groupIndex]
            .instance_status.arbitrate_status_member[memberIndex].restarting = false;
        write_runlog(LOG, "primary logic, instance %u is building, set it's restarting flag to false.\n",
            instanceId);
    }
}

static void MultiAzOrOnlyDnProcess(uint32 groupIndex, int memberIndex, int otherMemberIndex, uint32 instanceId)
{
    int localDynamicRole = g_instance_group_report_status_ptr[groupIndex]
        .instance_status.data_node_member[memberIndex].local_status.local_role;
    int peerDynamicRole = g_instance_group_report_status_ptr[groupIndex]
        .instance_status.data_node_member[otherMemberIndex].local_status.local_role;

    if (localDynamicRole == INSTANCE_ROLE_PENDING) {
        g_instance_group_report_status_ptr[groupIndex]
            .instance_status.arbitrate_status_member[memberIndex].restarting = false;
        write_runlog(LOG, "instance %u restart done.\n", instanceId);
    }
    bool cdt = (peerDynamicRole == INSTANCE_ROLE_PENDING &&
        g_instance_group_report_status_ptr[groupIndex]
            .instance_status.arbitrate_status_member[otherMemberIndex].restarting);
    if (cdt) {
        g_instance_group_report_status_ptr[groupIndex]
            .instance_status.arbitrate_status_member[otherMemberIndex].restarting = false;
        write_runlog(LOG, "instance %u restart done.\n",
            g_instance_role_group_ptr[groupIndex].instanceMember[otherMemberIndex].instanceId);
    }
}

static void NotMultiAzOrOnlyDnProcess(uint32 groupIndex, int memberIndex, maintenance_mode mode,
    MsgRecvInfo *recvMsgInfo, const agent_to_cm_datanode_status_report *agentToCmDatanodeStatusPtr)
{
    uint32 node = agentToCmDatanodeStatusPtr->node;
    uint32 instanceId = agentToCmDatanodeStatusPtr->instanceId;
    int localDynamicRole = g_instance_group_report_status_ptr[groupIndex]
        .instance_status.data_node_member[memberIndex].local_status.local_role;

    if (localDynamicRole == INSTANCE_ROLE_PENDING) {
        bool cdt = (mode == MAINTENANCE_MODE_UPGRADE || mode == MAINTENANCE_MODE_DILATATION);
        if (cdt) {
            g_instance_group_report_status_ptr[groupIndex]
                .instance_status.arbitrate_status_member[memberIndex].restarting = false;
            write_runlog(LOG, "%d Maintaining cluster: instance %u restart done.\n", __LINE__, instanceId);
        } else {
            /*
             * If restarting flag is set, forced to notify to standby and waiting for failover if necessary
             */
            send_arbitration_command(recvMsgInfo, MSG_CM_AGENT_NOTIFY, node, instanceId, INSTANCE_ROLE_STANDBY);
            g_instance_group_report_status_ptr[groupIndex]
                .instance_status.arbitrate_status_member[memberIndex].restarting = false;
            write_runlog(LOG, "Notify instance %u to standby after restarted.\n", instanceId);
        }
    }
}

static void PerformPeerInstancePostSwitchoverWork(uint32 groupIndex, int otherMemberIndex)
{
    /* update the static configure state */
    write_runlog(LOG,
        "Perform the post-switchover work, clean the pending command"
        " and change the static role from standby to primary for peer instance %u.\n",
        g_instance_role_group_ptr[groupIndex].instanceMember[otherMemberIndex].instanceId);
    set_pending_command(groupIndex, otherMemberIndex, MSG_CM_AGENT_BUTT);
    change_primary_member_index(groupIndex, otherMemberIndex);
    /* to deal switchover fail, but notify cn success */
    cm_pending_notify_broadcast_msg(groupIndex,
        g_instance_role_group_ptr[groupIndex].instanceMember[otherMemberIndex].instanceId);
}

#ifndef ENABLE_LLT
static void ArbitrationSendCmdAndSetRestarting(uint32 groupIndex, int memberIndex, int otherMemberIndex,
    MsgRecvInfo* recvMsgInfo, const agent_to_cm_datanode_status_report *agentToCmDatanodeStatusPtr)
{
    uint32 node = agentToCmDatanodeStatusPtr->node;
    uint32 instanceId = agentToCmDatanodeStatusPtr->instanceId;

    send_arbitration_command(recvMsgInfo, MSG_CM_AGENT_RESTART, node, instanceId);
    g_instance_group_report_status_ptr[groupIndex]
        .instance_status.arbitrate_status_member[memberIndex].restarting = true;
    g_instance_group_report_status_ptr[groupIndex]
        .instance_status.arbitrate_status_member[otherMemberIndex].restarting = true;
}

static void InstanceUpdateMemberRole(uint32 groupIndex, int memberIndex, int otherMemberIndex)
{
    g_instance_role_group_ptr[groupIndex].instanceMember[memberIndex].role =
        INSTANCE_ROLE_PRIMARY;
    g_instance_role_group_ptr[groupIndex].instanceMember[otherMemberIndex].role =
        INSTANCE_ROLE_STANDBY;
    g_instance_group_report_status_ptr[groupIndex]
        .instance_status.command_member[memberIndex].role_changed = INSTANCE_ROLE_CHANGED;
    (void)WriteDynamicConfigFile(false);
}
#endif

static void CheckIfSetRestartFlag(uint32 groupIndex, int memberIndex, int bestPrimaryIndex, uint32 instanceId)
{
    bool cdt = (bestPrimaryIndex != memberIndex && bestPrimaryIndex != -1);
    if (cdt) {
        g_instance_group_report_status_ptr[groupIndex]
            .instance_status.arbitrate_status_member[memberIndex].restarting = true;
        write_runlog(LOG, "set %u restart flag to true.\n", instanceId);
    }
}

static void SetMemberArbitrateFlag(uint32 groupIndex, int memberIndex)
{
    g_instance_group_report_status_ptr[groupIndex]
            .instance_status.data_node_member[memberIndex].arbitrateFlag = true;
}

static void ArbitratesNodeToDynamicPrimary(uint32 groupIndex, int memberIndex, int otherMemberIndex,
    MsgRecvInfo* recvMsgInfo, const agent_to_cm_datanode_status_report *agentToCmDatanodeStatusPtr)
{
    int peerStaticRole = g_instance_role_group_ptr[groupIndex].instanceMember[otherMemberIndex].role;
    uint32 node = agentToCmDatanodeStatusPtr->node;
    uint32 instanceId = agentToCmDatanodeStatusPtr->instanceId;

    if (peerStaticRole == INSTANCE_ROLE_PRIMARY) {
        int initPrimaryIndex = GetDatanodeInitPrimaryIndex(groupIndex);
        uint32 initNode = g_instance_role_group_ptr[groupIndex].instanceMember[initPrimaryIndex].node;
        uint32 initId = g_instance_role_group_ptr[groupIndex].instanceMember[initPrimaryIndex].instanceId;
        NotifyDatanodeDynamicPrimary(recvMsgInfo, initNode, initId, groupIndex, initPrimaryIndex);
        write_runlog(LOG,
            "%d Maintaining cluster with double static primary: "
            "cm server arbitrate init primary (%u) to dynamic primary.\n",
            __LINE__, initId);
    } else {
        NotifyDatanodeDynamicPrimary(recvMsgInfo, node, instanceId, groupIndex, memberIndex);
        write_runlog(LOG,
            "%d Maintaining cluster: cm server arbitrates static primary (%u) to dynamic primary.\n",
            __LINE__, instanceId);
    }
}

static void CheckIfNotifyDataNodeToStandby(uint32 groupIndex, int memberIndex, int otherMemberIndex,
    MsgRecvInfo* recvMsgInfo, const agent_to_cm_datanode_status_report *agentToCmDatanodeStatusPtr)
{
    uint32 node = agentToCmDatanodeStatusPtr->node;
    uint32 instanceId = agentToCmDatanodeStatusPtr->instanceId;
    int localDynamicRole = g_instance_group_report_status_ptr[groupIndex]
        .instance_status.data_node_member[memberIndex].local_status.local_role;
    int peerDynamicRole = g_instance_group_report_status_ptr[groupIndex]
        .instance_status.data_node_member[otherMemberIndex].local_status.local_role;
    int ret;

    /*
     * when dn is pending and unknown, it need make pending to standby, then let standby to failover primary
     * because of the logic of failover, it will check some thing, and notify primary will check nothing
     */
    int bestPrimaryIndex = find_candiate_primary_node_in_instance_role_group(groupIndex, memberIndex);

    bool cdt = (g_multi_az_cluster ||
        (g_instance_group_report_status_ptr[groupIndex].instance_status.data_node_member[(g_dn_replication_num - 1)]
        .local_status.db_state == INSTANCE_HA_STATE_NORMAL));
    if (cdt) {
        ret = instance_delay_arbitrate_time_out(localDynamicRole, peerDynamicRole, groupIndex,
            memberIndex, static_cast<int>(instance_heartbeat_timeout));
    } else {
        /* when dummy down, failover will not success */
        write_runlog(LOG, "dummy is down, state is %d.\n",
            g_instance_group_report_status_ptr[groupIndex]
                .instance_status.data_node_member[(g_dn_replication_num - 1)].local_status.db_state);
        ret = -1;
    }
    cdt = (bestPrimaryIndex == memberIndex && ret == 1);
    if (cdt) {
        /* *
         * operation and maintenance status, arbitrate the static primary is primary;
         * operating status arbitrate the static is standby
         */
        send_arbitration_command(recvMsgInfo, MSG_CM_AGENT_NOTIFY, node, instanceId, INSTANCE_ROLE_STANDBY);
        write_runlog(LOG, "notify datanode to %s.\n", datanode_role_int_to_string(INSTANCE_ROLE_STANDBY));
    }
}

static void PeerStaticRoleCheckPrimaryProcess(uint32 groupIndex, int memberIndex, int otherMemberIndex,
    const agent_to_cm_datanode_status_report *agentToCmDatanodeStatusPtr)
{
    uint32 instanceId = agentToCmDatanodeStatusPtr->instanceId;
    int peerStaticRole = g_instance_role_group_ptr[groupIndex].instanceMember[otherMemberIndex].role;

    g_instance_group_report_status_ptr[groupIndex]
        .instance_status.arbitrate_status_member[memberIndex].restarting = true;
    if (peerStaticRole != INSTANCE_ROLE_PRIMARY) {
        g_instance_group_report_status_ptr[groupIndex]
            .instance_status.arbitrate_status_member[otherMemberIndex].restarting = true;
        write_runlog(LOG, "double primary datanode instance, restart to pending.\n");
    } else {
        cm_pending_notify_broadcast_msg(groupIndex,
            g_instance_role_group_ptr[groupIndex].instanceMember[otherMemberIndex].instanceId);
        write_runlog(LOG,
            "double primary datanode instance, peerStaticRole is primary, restart to pending only for local "
            "%u.\n",
            instanceId);
    }
}

static void LocalStandbyBuildingProcess(uint32 groupIndex, int memberIndex, uint32 instanceId)
{
    int localDynamicRole = g_instance_group_report_status_ptr[groupIndex]
        .instance_status.data_node_member[memberIndex].local_status.local_role;
    int localDbState = g_instance_group_report_status_ptr[groupIndex]
        .instance_status.data_node_member[memberIndex].local_status.db_state;

    bool cdt = (localDynamicRole == INSTANCE_ROLE_STANDBY && localDbState == INSTANCE_HA_STATE_BUILDING);
    if (cdt) {
        g_instance_group_report_status_ptr[groupIndex]
            .instance_status.arbitrate_status_member[memberIndex].restarting = false;
        write_runlog(LOG, "standby logic, instance %u is building, set it's restarting flag to false.\n",
            instanceId);
    }
}

static void CheckIfPendingOnlyDnOrNot(uint32 groupIndex, int memberIndex, int otherMemberIndex,
    MsgRecvInfo* recvMsgInfo, const agent_to_cm_datanode_status_report *agentToCmDatanodeStatusPtr)
{
    uint32 node = agentToCmDatanodeStatusPtr->node;
    uint32 instanceId = agentToCmDatanodeStatusPtr->instanceId;
    int localDynamicRole = g_instance_group_report_status_ptr[groupIndex]
        .instance_status.data_node_member[memberIndex].local_status.local_role;
    int peerDynamicRole = g_instance_group_report_status_ptr[groupIndex]
        .instance_status.data_node_member[otherMemberIndex].local_status.local_role;

    if (g_only_dn_cluster) {
        if (localDynamicRole == INSTANCE_ROLE_PENDING) {
            g_instance_group_report_status_ptr[groupIndex]
                .instance_status.arbitrate_status_member[memberIndex].restarting = false;
            write_runlog(LOG, "instance %u restart done.\n", instanceId);
        }
        bool cdt = (peerDynamicRole == INSTANCE_ROLE_PENDING &&
            g_instance_group_report_status_ptr[groupIndex]
                .instance_status.arbitrate_status_member[otherMemberIndex].restarting);
        if (cdt) {
            g_instance_group_report_status_ptr[groupIndex]
                .instance_status.arbitrate_status_member[otherMemberIndex].restarting = false;
            write_runlog(LOG, "instance %u restart done.\n",
                g_instance_role_group_ptr[groupIndex].instanceMember[otherMemberIndex].instanceId);
        }
    } else {
        if (localDynamicRole == INSTANCE_ROLE_PENDING) {
            /* If restarting flag is set, forced to notify to standby and waiting for failover if necessary */
            send_arbitration_command(recvMsgInfo, MSG_CM_AGENT_NOTIFY, node, instanceId, INSTANCE_ROLE_STANDBY);
            g_instance_group_report_status_ptr[groupIndex]
                .instance_status.arbitrate_status_member[memberIndex].restarting = false;
            write_runlog(LOG, "instance %u restart done, notify to standby.\n", instanceId);
        }
    }
}

void datanode_instance_arbitrate_for_psd(MsgRecvInfo* recvMsgInfo, const agent_to_cm_datanode_status_report *status_ptr)
{
    uint32 group_index = 0;
    int member_index = 0;
    int other_member_index = 0;
    int ret;
    XLogRecPtr local_last_xlog_location;
    XLogRecPtr peer_last_xlog_location;

    int local_static_role;
    int local_dynamic_role;
    int peer_dynamic_role;
    int local_db_state;
    int peer_db_state;
    int build_reason;
    int peer_pre_restart_counts = 0;
    int peer_restart_counts = 0;
    int peer_restart_counts_in_hour = 0;
    uint32 peerInstanceId = 0;

    int localDBStatePrev;
    maintenance_mode mode = MAINTENANCE_MODE_NONE;
    uint32 node = status_ptr->node;
    uint32 instanceId = status_ptr->instanceId;
    int instanceType = status_ptr->instanceType;
    bool cdt;

    ret = find_node_in_dynamic_configure(node, instanceId, &group_index, &member_index);
    if (ret != 0) {
        write_runlog(LOG, "can't find the instance(node =%u  instanceid =%u)\n", node, instanceId);
        return;
    }

    if (g_needReloadSyncStandbyMode) {
        write_runlog(LOG,
            "instance(node=%u instanceid=%u) arbitrate will wait to reload sync standby mode ddb value.\n",
            node,
            instanceId);
        return;
    }

    GetDatanodeDynamicConfigChangeFromDdb(group_index);
    (void)pthread_rwlock_wrlock(&(g_instance_group_report_status_ptr[group_index].lk_lock));

    if (g_HA_status->local_role == CM_SERVER_STANDBY) {
        write_runlog(LOG, "datanode_arbitrate: cm_server is in standby state\n");
        AsyncProcMsg(recvMsgInfo, PM_REMOVE_CONN, NULL, 0);
        goto process_finish;
    }

    localDBStatePrev = GetDataNodeMember(group_index, member_index).local_status.db_state;

    ResetInstanceStatusHeartbeat(group_index, member_index);
    UpdateDataNodeMemberStatus(status_ptr, group_index, member_index);
    UpdateDataNodeMemberDnRestartCount(status_ptr, group_index, member_index);
    CheckAndUpdatePhonyDeadInfo(status_ptr, group_index, member_index);

    mode = getMaintenanceMode(group_index);
    DealPhonyDeadStatus(recvMsgInfo, INSTANCE_TYPE_DATANODE, group_index, member_index, mode);

    DealDataNodeDBStateChange(group_index, member_index, localDBStatePrev);

    other_member_index = find_other_member_index(group_index, member_index, INSTANCE_TYPE_DATANODE);
    if (other_member_index == -1) {
        goto process_finish;
    }

    cdt = ((g_dn_replication_num == 2) && g_only_dn_cluster);
    if (cdt) {
        CheckIfNeedSetSyncMode(instanceId, group_index, member_index, other_member_index);
        CheckIfNeedClearSyncMode(group_index, member_index, other_member_index);
    }

    local_static_role = g_instance_role_group_ptr[group_index].instanceMember[member_index].role;
    local_dynamic_role = g_instance_group_report_status_ptr[group_index]
        .instance_status.data_node_member[member_index].local_status.local_role;
    peer_dynamic_role = g_instance_group_report_status_ptr[group_index]
        .instance_status.data_node_member[other_member_index].local_status.local_role;
    local_last_xlog_location = g_instance_group_report_status_ptr[group_index]
        .instance_status.data_node_member[member_index].local_status.last_flush_lsn;
    peer_last_xlog_location = g_instance_group_report_status_ptr[group_index]
        .instance_status.data_node_member[other_member_index].local_status.last_flush_lsn;
    local_db_state = g_instance_group_report_status_ptr[group_index]
        .instance_status.data_node_member[member_index].local_status.db_state;
    peer_db_state = g_instance_group_report_status_ptr[group_index]
        .instance_status.data_node_member[other_member_index].local_status.db_state;
    build_reason = g_instance_group_report_status_ptr[group_index]
        .instance_status.data_node_member[member_index].local_status.buildReason;
    peer_pre_restart_counts = g_instance_group_report_status_ptr[group_index]
        .instance_status.data_node_member[other_member_index].dn_restart_counts;
    peer_restart_counts = g_instance_group_report_status_ptr[group_index]
        .instance_status.data_node_member[other_member_index].dn_restart_counts;
    peer_restart_counts_in_hour = g_instance_group_report_status_ptr[group_index]
        .instance_status.data_node_member[other_member_index].dn_restart_counts_in_hour;
    peerInstanceId = g_instance_role_group_ptr[group_index].instanceMember[other_member_index].instanceId;

    CheckDnRoleAndDbState(group_index, member_index, other_member_index, node, instanceId);

    instance_delay_arbitrate_time_out_clean(local_dynamic_role, peer_dynamic_role, group_index, member_index,
        MONITOR_INSTANCE_ARBITRATE_DELAY_CYCLE_MAX_COUNT);

    /* primary datanode instance's state is abnormal, primamry is disconnected with standby and secondary, double
     * restart to pending
     */
    cdt = (local_dynamic_role == INSTANCE_ROLE_PRIMARY && !g_multi_az_cluster && !g_only_dn_cluster);
    if (cdt) {
        int sender_standby_state = g_instance_group_report_status_ptr[group_index]
            .instance_status.data_node_member[member_index].sender_status[0].state;
        int sender_secondary_state = g_instance_group_report_status_ptr[group_index]
            .instance_status.data_node_member[member_index].sender_status[1].state;
        int standby_build_reason = g_instance_group_report_status_ptr[group_index]
            .instance_status.data_node_member[other_member_index].local_status.buildReason;
        cdt = ((sender_standby_state != INSTANCE_WALSNDSTATE_STREAMING &&
            sender_secondary_state != INSTANCE_WALSNDSTATE_STREAMING) &&
            (peer_dynamic_role == INSTANCE_ROLE_STANDBY && peer_db_state == INSTANCE_HA_STATE_NEED_REPAIR &&
            standby_build_reason == INSTANCE_HA_DATANODE_BUILD_REASON_WALSEGMENT_REMOVED));
        if (cdt) {
            ret = instance_delay_arbitrate_time_out(local_dynamic_role, peer_dynamic_role, group_index, member_index,
                MONITOR_INSTANCE_ARBITRATE_DELAY_CYCLE_MAX_COUNT);
            if (ret == 1) {
                send_arbitration_command(recvMsgInfo, MSG_CM_AGENT_RESTART, node, instanceId);
                ArbitrationSetRestarting(group_index, member_index, other_member_index);
                write_runlog(LOG,
                    "Connection states of primary(%u)-standby(%u) and primary-secondary are %d (%s) and %d (%s), "
                    "respectively."
                    "Double restart primary and standby to pending.\n",
                    instanceId, g_instance_role_group_ptr[group_index].instanceMember[other_member_index].instanceId,
                    sender_standby_state, datanode_wal_send_state_int_to_string(sender_standby_state),
                    sender_secondary_state, datanode_wal_send_state_int_to_string(sender_secondary_state));
            }

            goto process_finish;
        }
    }

    if (local_static_role == INSTANCE_ROLE_PRIMARY) {
        /* local is primary process */
        cdt = ((local_dynamic_role == INSTANCE_ROLE_PRIMARY) && (peer_dynamic_role == INSTANCE_ROLE_PRIMARY) &&
            (local_db_state != INSTANCE_HA_STATE_DEMOTING && peer_db_state != INSTANCE_HA_STATE_DEMOTING) &&
            !is_pending_command(group_index, other_member_index, MSG_CM_AGENT_SWITCHOVER));
        if (cdt) {
            PeerStaticRoleCheckStandbyProcess(group_index, member_index, other_member_index, recvMsgInfo, status_ptr);
            goto process_finish;
        }

        if (g_instance_group_report_status_ptr[group_index]
                .instance_status.arbitrate_status_member[member_index].restarting) {
            cdt = (local_dynamic_role == INSTANCE_ROLE_PRIMARY ||
                (local_dynamic_role == INSTANCE_ROLE_STANDBY && local_db_state != INSTANCE_HA_STATE_BUILDING));
            if (cdt) {
                send_arbitration_command(recvMsgInfo, MSG_CM_AGENT_RESTART, node, instanceId);
                goto process_finish;
            }

            InstanceIsBuildingProcess(group_index, member_index, instanceId);

            cdt = (g_multi_az_cluster || g_only_dn_cluster);
            if (cdt) {
                MultiAzOrOnlyDnProcess(group_index, member_index, other_member_index, instanceId);
            } else {
                NotMultiAzOrOnlyDnProcess(group_index, member_index, mode, recvMsgInfo, status_ptr);
            }
            cdt = (g_instance_group_report_status_ptr[group_index]
                    .instance_status.arbitrate_status_member[member_index].restarting ||
                g_instance_group_report_status_ptr[group_index]
                    .instance_status.arbitrate_status_member[other_member_index].restarting);
            if (cdt) {
                goto process_finish;
            }
        }

        /* local is standby process */
        cdt = ((local_dynamic_role == INSTANCE_ROLE_STANDBY) && (peer_dynamic_role == INSTANCE_ROLE_PRIMARY));
        if (cdt) {
            cdt = ((g_instance_group_report_status_ptr[group_index].instance_status.command_member[other_member_index]
                    .command_status == INSTANCE_COMMAND_WAIT_EXEC_ACK) &&
                (is_pending_command(group_index, other_member_index, MSG_CM_AGENT_SWITCHOVER) ||
                is_pending_command(group_index, other_member_index, MSG_CM_AGENT_FAILOVER)));
            if (cdt) {
                cdt = (local_db_state == INSTANCE_HA_STATE_NORMAL || local_db_state == INSTANCE_HA_STATE_CATCH_UP);
                if (cdt) {
                    PerformPeerInstancePostSwitchoverWork(group_index, other_member_index);
                    goto process_finish;
                }
            } else if ((g_instance_group_report_status_ptr[group_index].instance_status.command_member[member_index]
                            .command_status == INSTANCE_COMMAND_WAIT_EXEC_ACK) &&
                (is_pending_command(group_index, member_index, MSG_CM_AGENT_BUILD))) {
                cdt = (local_db_state == INSTANCE_HA_STATE_NORMAL || local_db_state == INSTANCE_HA_STATE_CATCH_UP);
                if (cdt) {
                    write_runlog(LOG,
                        "instanceid %u build down, and clean the command_status to instance_none_command, "
                        "pending_command to msg_cm_agent_butt, time_out to 0, full_build to 0.\n",
                        g_instance_role_group_ptr[group_index].instanceMember[member_index].instanceId);
                    set_pending_command(group_index, member_index, MSG_CM_AGENT_BUTT);

                    goto process_finish;
                }
            } else if (g_instance_group_report_status_ptr[group_index].instance_status
                        .command_member[member_index].command_status == INSTANCE_NONE_COMMAND &&
                is_pending_command(group_index, member_index, MSG_CM_AGENT_BUTT) &&
                (peer_restart_counts > DN_RESTART_COUNTS || peer_restart_counts_in_hour > DN_RESTART_COUNTS_IN_HOUR) &&
                local_db_state == INSTANCE_HA_STATE_NORMAL) {
                int bestPrimaryIndex =
                    g_multi_az_cluster ? find_auto_switchover_primary_node(group_index, member_index) : member_index;
                ret = instance_delay_arbitrate_time_out(local_dynamic_role, peer_dynamic_role, group_index,
                    member_index, (int)instance_failover_delay_timeout);
                cdt = (ret == 1 && bestPrimaryIndex == member_index);
                if (cdt) {
                    write_runlog(LOG, "the primary dn restarts count: %d in 10 min, %d in hour.\n", peer_restart_counts,
                        peer_restart_counts_in_hour);
                    if (IsMaintenanceModeDisableOperation(CMS_SWITCHOVER_DN, mode)) {
                        write_runlog(LOG, "%d Maintaining cluster: cm server cannot switchover dn.\n", __LINE__);
                        goto process_finish;
                    }

                    set_pending_command(group_index, member_index, MSG_CM_AGENT_SWITCHOVER, SWITCHOVER_DEFAULT_WAIT);
                    write_runlog(LOG, "DN(instanceId:%u) will automatically switchover.\n", instanceId);
                }
                goto process_finish;
            } else {
#ifndef ENABLE_LLT
                write_runlog(LOG, "manual does the instance switchover or failover node is %u, instanceId is %u\n",
                    node, instanceId);
                cdt = ((local_db_state == INSTANCE_HA_STATE_NORMAL || local_db_state == INSTANCE_HA_STATE_CATCH_UP) &&
                    g_instance_group_report_status_ptr[group_index].instance_status
                        .data_node_member[other_member_index].phony_dead_times < phony_dead_effective_time);
                if (cdt) {
                    change_primary_member_index(group_index, other_member_index);
                    /* to deal switchover fail, but notify cn success */
                    cm_pending_notify_broadcast_msg(group_index,
                        g_instance_role_group_ptr[group_index].instanceMember[other_member_index].instanceId);
                    goto process_finish;
                } else if (local_db_state == INSTANCE_HA_STATE_NEED_REPAIR) {
                    g_HA_status->status = CM_STATUS_NEED_REPAIR;
                    goto process_finish;
                } else {
                    write_runlog(LOG, "unknown status =%d  node is %u, instanceId is %u\n", local_db_state, node,
                        instanceId);
                }
#endif
            }
            goto process_finish;
        }
#ifndef ENABLE_LLT
        if (g_only_dn_cluster) {
            cdt = ((local_dynamic_role == INSTANCE_ROLE_STANDBY) && (peer_dynamic_role == INSTANCE_ROLE_STANDBY) &&
                !(local_db_state == INSTANCE_HA_STATE_PROMOTING && peer_db_state == INSTANCE_HA_STATE_BUILDING) &&
                (local_db_state != INSTANCE_HA_STATE_PROMOTING && peer_db_state != INSTANCE_HA_STATE_PROMOTING) &&
                !is_pending_command(group_index, other_member_index, MSG_CM_AGENT_SWITCHOVER));
            if (cdt) {
                /*
                 * when switchover, if switchover has timeout, there is a scenes, the primary become standby, but the
                 * standby  promte to primary after 10+ second.
                 */
                ret = instance_delay_arbitrate_time_out(local_dynamic_role, peer_dynamic_role, group_index,
                    member_index, MONITOR_INSTANCE_ARBITRATE_DELAY_CYCLE_MAX_COUNT * 2);
                if (ret == 1) {
                    ArbitrationSendCmdAndSetRestarting(group_index, member_index, other_member_index, recvMsgInfo,
                        status_ptr);
                    write_runlog(LOG, "double standby datanode instance, restart to pending.\n");
                }
                goto process_finish;
            }
        } else {
            cdt = ((local_dynamic_role == INSTANCE_ROLE_STANDBY) && (peer_dynamic_role == INSTANCE_ROLE_STANDBY) &&
                !(local_db_state == INSTANCE_HA_STATE_PROMOTING && peer_db_state == INSTANCE_HA_STATE_BUILDING) &&
                (local_db_state != INSTANCE_HA_STATE_PROMOTING && peer_db_state != INSTANCE_HA_STATE_PROMOTING) &&
                !is_pending_command(group_index, other_member_index, MSG_CM_AGENT_SWITCHOVER));
            if (cdt) {
                cdt = (mode == MAINTENANCE_MODE_UPGRADE || mode == MAINTENANCE_MODE_DILATATION);
                if (cdt) {
                    ret = instance_delay_arbitrate_time_out(local_dynamic_role, peer_dynamic_role, group_index,
                        member_index, MONITOR_INSTANCE_ARBITRATE_DELAY_CYCLE_MAX_COUNT * 2);
                    if (ret == 1) {
                        ArbitrationSendCmdAndSetRestarting(group_index, member_index, other_member_index, recvMsgInfo,
                            status_ptr);
                        write_runlog(LOG, "%d Maintaining cluster with double standby: restart to pending.\n",
                            __LINE__);
                    }
                    goto process_finish;
                }

                if (local_db_state == INSTANCE_HA_STATE_BUILDING) {
                    ret = instance_delay_arbitrate_time_out(local_dynamic_role, peer_dynamic_role, group_index,
                        member_index, MONITOR_INSTANCE_ARBITRATE_DELAY_CYCLE_MAX_COUNT);
                    if (ret == 1) {
                        change_primary_member_index(group_index, other_member_index);
                        write_runlog(LOG, "Change static primary %u, which is building, to %u.\n", instanceId,
                            peerInstanceId);
                    }
                    goto process_finish;
                }

                cdt = ((local_db_state == INSTANCE_HA_STATE_NEED_REPAIR) &&
                    ((peer_db_state == INSTANCE_HA_STATE_NEED_REPAIR &&
                    g_instance_group_report_status_ptr[group_index]
                        .instance_status.arbitrate_status_member[member_index].promoting_timeout == 0 &&
                    g_instance_group_report_status_ptr[group_index]
                        .instance_status.arbitrate_status_member[other_member_index].promoting_timeout == 0) ||
                    (peer_db_state == INSTANCE_HA_STATE_BUILDING)));
                if (cdt) {
                    ret = instance_delay_arbitrate_time_out(local_dynamic_role, peer_dynamic_role, group_index,
                        member_index, MONITOR_INSTANCE_ARBITRATE_DELAY_CYCLE_MAX_COUNT);
                    if (ret == 1) {
                        if (IsMaintenanceModeDisableOperation(CMS_FAILOVER_DN, mode)) {
                            write_runlog(LOG, "%d Maintaining cluster: cm server cannot failover dn.\n", __LINE__);
                            goto process_finish;
                        }

                        InstanceUpdateMemberRole(group_index, member_index, other_member_index);

                        send_arbitration_command(recvMsgInfo, MSG_CM_AGENT_FAILOVER, node, instanceId);
                        cm_pending_notify_broadcast_msg(group_index, instanceId);
                        write_runlog(LOG,
                            "Failover instance, instance_id=%u, instance_type=%s[%u],"
                            " local_static_role = %s[%d], local_dynamic_role=%s[%d].\n",
                            instanceId, type_int_to_string(INSTANCE_TYPE_DATANODE), (uint32)INSTANCE_TYPE_DATANODE,
                            datanode_role_int_to_string(local_static_role), local_static_role,
                            datanode_role_int_to_string(local_dynamic_role), local_dynamic_role);

                        g_instance_group_report_status_ptr[group_index]
                            .instance_status.arbitrate_status_member[member_index]
                            .promoting_timeout = PROMOTING_TIME_OUT;
                    }
                }

                goto process_finish;
            }
        }
#endif
        cdt = ((local_dynamic_role == INSTANCE_ROLE_STANDBY) && (peer_dynamic_role == INSTANCE_ROLE_PENDING) &&
            (local_db_state != INSTANCE_HA_STATE_BUILDING));
        if (cdt) {
            int bestPrimaryIndex = find_candiate_primary_node_in_instance_role_group(group_index, member_index);
            ret = instance_delay_arbitrate_time_out(local_dynamic_role, peer_dynamic_role, group_index, member_index,
                MONITOR_INSTANCE_ARBITRATE_DELAY_CYCLE_MAX_COUNT);
            cdt = (ret == 1 && bestPrimaryIndex == member_index &&
                !check_datanode_arbitrate_status(group_index, member_index));
            if (cdt) {
                if (IsMaintenanceModeDisableOperation(CMS_FAILOVER_DN, mode)) {
                    write_runlog(LOG, "%d Maintaining cluster: cm server cannot failover dn.\n", __LINE__);
                    goto process_finish;
                }

                change_primary_member_index(group_index, member_index);

                send_arbitration_command(recvMsgInfo, MSG_CM_AGENT_FAILOVER, node, instanceId);
                /* set local dynamic role to primary now */
                g_instance_group_report_status_ptr[group_index]
                    .instance_status.data_node_member[member_index].arbitrateFlag = true;
                cm_pending_notify_broadcast_msg(group_index, instanceId);
            }
            CheckIfSetRestartFlag(group_index, member_index, bestPrimaryIndex, instanceId);
            goto process_finish;
        }

        cdt = ((local_dynamic_role == INSTANCE_ROLE_STANDBY) && (peer_dynamic_role == INSTANCE_ROLE_UNKNOWN) &&
            !is_pending_command(group_index, member_index, MSG_CM_AGENT_BUILD));
        if (cdt) {
            int bestPrimaryIndex = find_candiate_primary_node_in_instance_role_group(group_index, member_index);
            if (bestPrimaryIndex == member_index) {
                cdt = (!g_multi_az_cluster && g_instance_group_report_status_ptr[group_index]
                    .instance_status.data_node_member[(g_dn_replication_num - 1)].local_status.db_state !=
                        INSTANCE_HA_STATE_NORMAL);
                if (cdt) {
                    ret = 0;
                    write_runlog(LOG,
                        "the dummy instance status is abnormal, so standby(id:%u) instance cannot be promoted.\n",
                        instanceId);
                } else {
                    ret = instance_delay_arbitrate_time_out(local_dynamic_role, peer_dynamic_role, group_index,
                        member_index, static_cast<int>(instance_failover_delay_timeout));
                }

                cdt = (ret == 1 && !check_datanode_arbitrate_status(group_index, member_index));
                if (cdt) {
                    if (IsMaintenanceModeDisableOperation(CMS_FAILOVER_DN, mode)) {
                        write_runlog(LOG, "%d Maintaining cluster: cm server cannot failover dn.\n", __LINE__);
                        goto process_finish;
                    }

                    change_primary_member_index(group_index, static_cast<int>(member_index));

                    send_arbitration_command(recvMsgInfo, MSG_CM_AGENT_FAILOVER, node, instanceId);
                    SetMemberArbitrateFlag(group_index, member_index);
                    cm_pending_notify_broadcast_msg(group_index, instanceId);
                }
                goto process_finish;
            } else {
                g_HA_status->status = CM_STATUS_NEED_REPAIR;
                instance_delay_arbitrate_time_out_direct_clean(group_index, member_index,
                    instance_failover_delay_timeout);
                goto process_finish;
            }
        }

        /* local is pengding process */
        cdt = ((local_dynamic_role == INSTANCE_ROLE_PENDING) && (peer_dynamic_role == INSTANCE_ROLE_PRIMARY));
        if (cdt) {
            change_primary_member_index(group_index, other_member_index);
            send_arbitration_command(recvMsgInfo, MSG_CM_AGENT_NOTIFY, node, instanceId, INSTANCE_ROLE_STANDBY);
            cm_pending_notify_broadcast_msg(group_index,
                g_instance_role_group_ptr[group_index].instanceMember[other_member_index].instanceId);
            goto process_finish;
        }

        cdt = ((local_dynamic_role == INSTANCE_ROLE_PENDING) && (peer_dynamic_role == INSTANCE_ROLE_STANDBY) &&
            (peer_db_state != INSTANCE_HA_STATE_PROMOTING));
        if (cdt) {
            cdt = (mode == MAINTENANCE_MODE_UPGRADE || mode == MAINTENANCE_MODE_DILATATION);
            if (cdt) {
                NotifyDatanodeDynamicPrimary(recvMsgInfo, node, instanceId, group_index, member_index);
                write_runlog(LOG,
                    "%d Maintaining cluster: cm server arbitrates static primary (%u) to dynamic primary.\n", __LINE__,
                    instanceId);
                goto process_finish;
            }

            if (g_only_dn_cluster) {
                int bestPrimaryIndex = find_candiate_primary_node_in_instance_role_group(group_index, member_index);
                cdt = ((!XLogRecPtrIsInvalid(local_last_xlog_location)) &&
                    (!XLogRecPtrIsInvalid(peer_last_xlog_location)) &&
                    (XLByteLE(peer_last_xlog_location, local_last_xlog_location)) &&
                    (bestPrimaryIndex == member_index) && !check_datanode_arbitrate_status(group_index, member_index));
                if (cdt) {
                    send_arbitration_command(recvMsgInfo, MSG_CM_AGENT_NOTIFY, node, instanceId, INSTANCE_ROLE_PRIMARY);
                    SetMemberArbitrateFlag(group_index, member_index);
                    cm_pending_notify_broadcast_msg(group_index, instanceId);
                    goto process_finish;
                } else {
                    cdt = ((!XLogRecPtrIsInvalid(local_last_xlog_location)) &&
                        (!XLogRecPtrIsInvalid(peer_last_xlog_location)) &&
                        (XLByteLT(local_last_xlog_location, peer_last_xlog_location)) && bestPrimaryIndex != -1);
                    if (cdt) {
                        send_arbitration_command(
                            recvMsgInfo, MSG_CM_AGENT_NOTIFY, node, instanceId, INSTANCE_ROLE_STANDBY);
                        write_runlog(LOG,
                            "%d pending-standby, XLByteLE:local_last_xlog_location=%X/%X, "
                            "peer_last_xlog_location=%X/%X, LE=%d. Notify %u to be standby\n",
                            __LINE__, (uint32)(local_last_xlog_location >> 32), (uint32)local_last_xlog_location,
                            (uint32)(peer_last_xlog_location >> 32), (uint32)peer_last_xlog_location,
                            XLByteLE(peer_last_xlog_location, local_last_xlog_location), instanceId);
                        goto process_finish;
                    }
                    write_runlog(LOG,
                        "%d pending-standby, XLByteLE:local_last_xlog_location=%X/%X, peer_last_xlog_location=%X/%X, "
                        "LE=%d. Do nothing\n",
                        __LINE__, (uint32)(local_last_xlog_location >> 32), (uint32)local_last_xlog_location,
                        (uint32)(peer_last_xlog_location >> 32), (uint32)peer_last_xlog_location,
                        XLByteLE(peer_last_xlog_location, local_last_xlog_location));
                    goto process_finish;
                }
            } else {
                if (!XLogRecPtrIsInvalid(local_last_xlog_location)) {
                    write_runlog(LOG,
                        "%d pending-standby, XLByteLE:local_last_xlog_location=%X/%X, peer_last_xlog_location=%X/%X, "
                        "LE=%d. to primary.\n",
                        __LINE__, (uint32)(local_last_xlog_location >> 32), (uint32)local_last_xlog_location,
                        (uint32)(peer_last_xlog_location >> 32), (uint32)peer_last_xlog_location,
                        XLByteLE(peer_last_xlog_location, local_last_xlog_location));

                    send_arbitration_command(recvMsgInfo, MSG_CM_AGENT_NOTIFY, node, instanceId, INSTANCE_ROLE_PRIMARY);
                    cm_pending_notify_broadcast_msg(group_index, instanceId);
                    goto process_finish;
                } else {
                    write_runlog(LOG, "%d xlog invalid and do nothing.\n", __LINE__);
                    goto process_finish;
                }
            }
        }

        cdt = ((local_dynamic_role == INSTANCE_ROLE_PENDING) && (peer_dynamic_role == INSTANCE_ROLE_PENDING));
        if (cdt) {
            cdt = (mode == MAINTENANCE_MODE_UPGRADE || mode == MAINTENANCE_MODE_DILATATION);
            if (cdt) {
                ArbitratesNodeToDynamicPrimary(group_index, member_index, other_member_index, recvMsgInfo,
                    status_ptr);
                goto process_finish;
            }

            int bestPrimaryIndex = find_candiate_primary_node_in_instance_role_group(group_index, member_index);

            if (g_only_dn_cluster) {
                cdt = ((!XLogRecPtrIsInvalid(local_last_xlog_location)) &&
                    (!XLogRecPtrIsInvalid(peer_last_xlog_location)) &&
                    (XLByteLE(peer_last_xlog_location, local_last_xlog_location)) &&
                    (bestPrimaryIndex == member_index) && !check_datanode_arbitrate_status(group_index, member_index));
                if (cdt) {
                    write_runlog(LOG,
                        "%d pending-pending,XLByteLE:local_last_xlog_location=%d peer_last_xlog_location=%d LE=%d.to "
                        "primary\n",
                        __LINE__, XLogRecPtrIsInvalid(local_last_xlog_location),
                        XLogRecPtrIsInvalid(peer_last_xlog_location),
                        XLByteLE(peer_last_xlog_location, local_last_xlog_location));

                    send_arbitration_command(recvMsgInfo, MSG_CM_AGENT_NOTIFY, node, instanceId, INSTANCE_ROLE_PRIMARY);
                    SetMemberArbitrateFlag(group_index, member_index);
                    cm_pending_notify_broadcast_msg(group_index, instanceId);
                    goto process_finish;
                } else if ((!XLogRecPtrIsInvalid(local_last_xlog_location)) &&
                    (!XLogRecPtrIsInvalid(peer_last_xlog_location)) &&
                    (XLByteLT(local_last_xlog_location, peer_last_xlog_location))) {
                    write_runlog(LOG,
                        "%d pending-pending:XLByteLT:local_last_xlog_location=%d peer_last_xlog_location=%d LT=%d.to "
                        "standby\n",
                        __LINE__, XLogRecPtrIsInvalid(local_last_xlog_location),
                        XLogRecPtrIsInvalid(peer_last_xlog_location),
                        XLByteLT(local_last_xlog_location, peer_last_xlog_location));

                    change_primary_member_index(group_index, other_member_index);

                    send_arbitration_command(recvMsgInfo, MSG_CM_AGENT_NOTIFY, node, instanceId, INSTANCE_ROLE_STANDBY);
                    goto process_finish;
                } else {
                    write_runlog(LOG,
                        "%d pending-pending:XLByteLT:local_last_xlog_location=%d peer_last_xlog_location=%d.do "
                        "nothing\n",
                        __LINE__, XLogRecPtrIsInvalid(local_last_xlog_location),
                        XLogRecPtrIsInvalid(peer_last_xlog_location));

                    g_HA_status->status = CM_STATUS_NEED_REPAIR;
                    goto process_finish;
                }
            } else {
                if (!XLogRecPtrIsInvalid(local_last_xlog_location)) {
                    write_runlog(LOG,
                        "%d pending-pending: local_last_xlog_location=%X/%X, peer_last_xlog_location=%X/%X, to "
                        "primary\n",
                        __LINE__, (uint32)(local_last_xlog_location >> 32), (uint32)local_last_xlog_location,
                        (uint32)(peer_last_xlog_location >> 32), (uint32)peer_last_xlog_location);

                    send_arbitration_command(recvMsgInfo, MSG_CM_AGENT_NOTIFY, node, instanceId, INSTANCE_ROLE_PRIMARY);
                    goto process_finish;
                } else {
                    write_runlog(LOG,
                        "%d pending-pending: local_last_xlog_location=%X/%X peer_last_xlog_location=%X/%X. invalid "
                        "xlog, do nothing\n",
                        __LINE__, (uint32)(local_last_xlog_location >> 32), (uint32)local_last_xlog_location,
                        (uint32)(peer_last_xlog_location >> 32), (uint32)peer_last_xlog_location);

                    g_HA_status->status = CM_STATUS_NEED_REPAIR;
                    goto process_finish;
                }
            }
        }

        cdt = ((local_dynamic_role == INSTANCE_ROLE_PENDING) && (peer_dynamic_role == INSTANCE_ROLE_UNKNOWN) &&
            (peer_db_state == INSTANCE_HA_STATE_UNKONWN || peer_db_state == INSTANCE_HA_STATE_MANUAL_STOPPED ||
            peer_db_state == INSTANCE_HA_STATE_PORT_USED || peer_db_state == INSTANCE_HA_STATE_DISK_DAMAGED ||
            peer_db_state == INSTANCE_HA_STATE_BUILD_FAILED ||
            (peer_db_state == INSTANCE_HA_STATE_STARTING && peer_pre_restart_counts > DN_RESTART_COUNTS)));
        if (cdt) {
            if (mode == MAINTENANCE_MODE_UPGRADE || mode == MAINTENANCE_MODE_DILATATION) {
                NotifyDatanodeDynamicPrimary(recvMsgInfo, node, instanceId, group_index, member_index);
                write_runlog(LOG,
                    "%d Maintaining cluster: cm server arbitrates static primary (%u) to dynamic primary.\n", __LINE__,
                    instanceId);
                goto process_finish;
            }

            CheckIfNotifyDataNodeToStandby(group_index, member_index, other_member_index, recvMsgInfo,
                status_ptr);
            goto process_finish;
        }
    } else if (local_static_role == INSTANCE_ROLE_STANDBY) {
        /* local is primary process */
        cdt = ((local_dynamic_role == INSTANCE_ROLE_PRIMARY) && (peer_dynamic_role == INSTANCE_ROLE_PRIMARY) &&
            (local_db_state != INSTANCE_HA_STATE_DEMOTING && peer_db_state != INSTANCE_HA_STATE_DEMOTING) &&
            !is_pending_command(group_index, member_index, MSG_CM_AGENT_SWITCHOVER));
        if (cdt) {
            send_arbitration_command(recvMsgInfo, MSG_CM_AGENT_RESTART, node, instanceId);

            PeerStaticRoleCheckPrimaryProcess(group_index, member_index, other_member_index,
                status_ptr);
            goto process_finish;
        }

        if (g_instance_group_report_status_ptr[group_index]
                .instance_status.arbitrate_status_member[member_index].restarting) {
            cdt = (local_dynamic_role == INSTANCE_ROLE_PRIMARY ||
                (local_dynamic_role == INSTANCE_ROLE_STANDBY && local_db_state != INSTANCE_HA_STATE_BUILDING));
            if (cdt) {
                send_arbitration_command(recvMsgInfo, MSG_CM_AGENT_RESTART, node, instanceId);
                goto process_finish;
            }

            LocalStandbyBuildingProcess(group_index, member_index, instanceId);

            CheckIfPendingOnlyDnOrNot(group_index, member_index, other_member_index, recvMsgInfo,
                status_ptr);

            cdt = (g_instance_group_report_status_ptr[group_index]
                    .instance_status.arbitrate_status_member[member_index].restarting ||
                g_instance_group_report_status_ptr[group_index]
                    .instance_status.arbitrate_status_member[other_member_index].restarting);
            if (cdt) {
                goto process_finish;
            }
        }

        cdt = ((local_dynamic_role == INSTANCE_ROLE_PRIMARY) && (peer_dynamic_role == INSTANCE_ROLE_STANDBY));
        if (cdt) {
            cdt = ((g_instance_group_report_status_ptr[group_index].instance_status.command_member[member_index]
                    .command_status == INSTANCE_COMMAND_WAIT_EXEC_ACK) &&
                (is_pending_command(group_index, member_index, MSG_CM_AGENT_SWITCHOVER) ||
                is_pending_command(group_index, member_index, MSG_CM_AGENT_FAILOVER)));
            if (cdt) {
                cdt = (peer_db_state == INSTANCE_HA_STATE_NORMAL || peer_db_state == INSTANCE_HA_STATE_CATCH_UP);
                if (cdt) {
                    /* update the static configure state */
                    write_runlog(LOG,
                        "Perform the post-switchover work, clean the"
                        " pending command and change the static role from standby to primary for"
                        " current instance %u.\n",
                        g_instance_role_group_ptr[group_index].instanceMember[member_index].instanceId);
                    set_pending_command(group_index, member_index, MSG_CM_AGENT_BUTT);
                    change_primary_member_index(group_index, member_index);
                    /* to deal switchover fail, but notify cn success, so notify need to do when switchover success */
                    cm_pending_notify_broadcast_msg(group_index, instanceId);
                    goto process_finish;
                }
            } else {
#ifndef ENABLE_LLT
                write_runlog(LOG, "manual does the instance switchover or failover node is %u, instanceId is %u\n",
                    node, instanceId);

                cdt = (local_db_state == INSTANCE_HA_STATE_NORMAL &&
                    g_instance_group_report_status_ptr[group_index].instance_status.data_node_member[member_index]
                        .phony_dead_times < phony_dead_effective_time);
                if (cdt) {
                    change_primary_member_index(group_index, member_index);
                    /* to deal switchover fail, but notify cn success, so notify need to do when switchover success */
                    cm_pending_notify_broadcast_msg(group_index, instanceId);
                    goto process_finish;
                } else if (local_db_state == INSTANCE_HA_STATE_NEED_REPAIR) {
                    g_HA_status->status = CM_STATUS_NEED_REPAIR;
                    goto process_finish;
                } else {
                    write_runlog(LOG, "unknown status =%d  node is %u, instanceId is %u\n", local_db_state, node,
                        instanceId);
                }
#endif
            }
            goto process_finish;
        }
#ifndef ENABLE_LLT
        cdt = ((local_dynamic_role == INSTANCE_ROLE_PRIMARY) && (peer_dynamic_role == INSTANCE_ROLE_PENDING));
        if (cdt) {
            /* need no operation */
            change_primary_member_index(group_index, member_index);
            cm_pending_notify_broadcast_msg(group_index, instanceId);
            goto process_finish;
        }
        cdt = ((local_dynamic_role == INSTANCE_ROLE_PRIMARY) && (peer_dynamic_role == INSTANCE_ROLE_UNKNOWN));
        if (cdt) {
            change_primary_member_index(group_index, member_index);
            (void)WriteDynamicConfigFile(false);
            cm_pending_notify_broadcast_msg(group_index, instanceId);
            goto process_finish;
        }
#endif

        /* local is standby process */
        cdt = ((local_dynamic_role == INSTANCE_ROLE_STANDBY) && (peer_dynamic_role == INSTANCE_ROLE_PRIMARY));
        if (cdt) {
            /* need no operation */
            if (local_db_state == INSTANCE_HA_STATE_NORMAL) {
                cdt = ((g_instance_group_report_status_ptr[group_index].instance_status.command_member[member_index]
                        .command_status == INSTANCE_COMMAND_WAIT_EXEC_ACK) &&
                    is_pending_command(group_index, member_index, MSG_CM_AGENT_BUILD));
                if (cdt) {
                    ret = instance_delay_arbitrate_time_out(local_dynamic_role, peer_dynamic_role, group_index,
                        member_index, MONITOR_INSTANCE_ARBITRATE_DELAY_CYCLE_MAX_COUNT);
                    if (ret == 1) {
                        write_runlog(LOG, "clean command, pending command is %d, instance is %u.\n",
                            get_pending_command(group_index, member_index), instanceId);
                        set_pending_command(group_index, member_index, MSG_CM_AGENT_BUTT);
                    }
                } else if (g_instance_group_report_status_ptr[group_index].instance_status.command_member[member_index]
                            .command_status == INSTANCE_NONE_COMMAND &&
                    is_pending_command(group_index, member_index, MSG_CM_AGENT_BUTT) &&
                    (peer_restart_counts > DN_RESTART_COUNTS ||
                    peer_restart_counts_in_hour > DN_RESTART_COUNTS_IN_HOUR)) {
                    int bestPrimaryIndex = g_multi_az_cluster ?
                        find_auto_switchover_primary_node(group_index, member_index) :
                        member_index;
                    ret = instance_delay_arbitrate_time_out(local_dynamic_role, peer_dynamic_role, group_index,
                        member_index, (int)instance_failover_delay_timeout);
                    cdt = (ret == 1 && bestPrimaryIndex == member_index);
                    if (cdt) {
                        write_runlog(LOG, "the primary dn restarts count: %d in 10 min, %d in hour.\n",
                            peer_restart_counts, peer_restart_counts_in_hour);
                        if (IsMaintenanceModeDisableOperation(CMS_SWITCHOVER_DN, mode)) {
                            write_runlog(LOG, "%d Maintaining cluster: cm server cannot switchover dn.\n", __LINE__);
                            goto process_finish;
                        }

                        set_pending_command(group_index, member_index, MSG_CM_AGENT_SWITCHOVER,
                            SWITCHOVER_DEFAULT_WAIT);
                        write_runlog(LOG, "DN(instanceId:%u) will automatically switchover.\n", instanceId);
                    }
                    goto process_finish;
                } else {
                    instance_delay_arbitrate_time_out_direct_clean(group_index, member_index,
                        MONITOR_INSTANCE_ARBITRATE_DELAY_CYCLE_MAX_COUNT2);
                }
                goto process_finish;
            } else if (local_db_state == INSTANCE_HA_STATE_CATCH_UP) {
                cdt = ((g_instance_group_report_status_ptr[group_index].instance_status.command_member[member_index]
                        .command_status == INSTANCE_COMMAND_WAIT_EXEC_ACK) &&
                    (is_pending_command(group_index, member_index, MSG_CM_AGENT_BUILD)));
                if (cdt) {
                    ret = instance_delay_arbitrate_time_out(local_dynamic_role, peer_dynamic_role, group_index,
                        member_index, MONITOR_INSTANCE_ARBITRATE_DELAY_CYCLE_MAX_COUNT);
                    if (ret == 1) {
                        write_runlog(LOG, "clean command, pending command is %d, instance is %u.\n",
                            get_pending_command(group_index, member_index), instanceId);
                        set_pending_command(group_index, member_index, MSG_CM_AGENT_BUTT);
                    }
                }

                goto process_finish;
            } else if (local_db_state == INSTANCE_HA_STATE_NEED_REPAIR &&
                (build_reason == INSTANCE_HA_DATANODE_BUILD_REASON_WALSEGMENT_REMOVED)) {
                if (g_only_dn_cluster) {
                    write_runlog(LOG,
                        "WAL segment removed: "
                        "group_index = %u member_index = %d local_dynamic_role = %d(%s) peer_dynamic_role = %d(%s) "
                        "arbitrate_delay_set = %d arbitrate_delay_time_out = %d\n",
                        group_index, member_index, local_dynamic_role, datanode_role_int_to_string(local_dynamic_role),
                        peer_dynamic_role, datanode_role_int_to_string(peer_dynamic_role),
                        g_instance_group_report_status_ptr[group_index].instance_status.command_member[member_index]
                            .arbitrate_delay_set,
                        g_instance_group_report_status_ptr[group_index].instance_status.command_member[member_index]
                            .arbitrate_delay_time_out);

                    if (IsMaintenanceModeDisableOperation(CMS_BUILD_DN, mode)) {
                        write_runlog(LOG, "%d Maintaining cluster: cm server cannot build dn.\n", __LINE__);
                        goto process_finish;
                    }

                    send_arbitration_command(recvMsgInfo, MSG_CM_AGENT_BUILD, node, instanceId, NO_NEED_TO_SET_PARAM,
                        BUILD_TIMER_OUT, 0);

                    goto process_finish;
                } else {
                    int sender_standby_state = g_instance_group_report_status_ptr[group_index]
                        .instance_status.data_node_member[other_member_index].sender_status[0].state;
                    int sender_secondary_state = g_instance_group_report_status_ptr[group_index]
                        .instance_status.data_node_member[other_member_index].sender_status[1].state;

                    cdt = (sender_standby_state != INSTANCE_WALSNDSTATE_STREAMING &&
                        sender_secondary_state == INSTANCE_WALSNDSTATE_STREAMING);
                    if (cdt) {
                        write_runlog(LOG,
                            "primary(%u) connect bad with standby(%u) and connect ok with secondary,and standby's "
                            "ha_stat is wal segment removed,sender_standby_state = %d[%s], sender_secondary_state = "
                            "%d[%s].\n",
                            g_instance_role_group_ptr[group_index].instanceMember[other_member_index].instanceId,
                            instanceId, sender_standby_state,
                            datanode_wal_send_state_int_to_string(sender_standby_state), sender_secondary_state,
                            datanode_wal_send_state_int_to_string(sender_secondary_state));

                        if (IsMaintenanceModeDisableOperation(CMS_BUILD_DN, mode)) {
                            write_runlog(LOG, "%d Maintaining cluster: cm server cannot build dn.\n", __LINE__);
                            goto process_finish;
                        }

                        ret = instance_delay_arbitrate_time_out(local_dynamic_role, peer_dynamic_role, group_index,
                            member_index, MONITOR_INSTANCE_ARBITRATE_DELAY_CYCLE_MAX_COUNT * 2);
                        if (ret == 1) {
                            send_arbitration_command(recvMsgInfo,
                                MSG_CM_AGENT_BUILD,
                                node,
                                instanceId,
                                NO_NEED_TO_SET_PARAM,
                                BUILD_TIMER_OUT,
                                0);
                            goto process_finish;
                        }
                    } else {
                        write_runlog(LOG,
                            "primary(%u) connect bad with standby(%u) and connect bad with secondary,and standby's "
                            "ha_stat is wal segment removed,sender_standby_state = %d[%s], sender_secondary_state = "
                            "%d[%s].\n",
                            g_instance_role_group_ptr[group_index].instanceMember[other_member_index].instanceId,
                            instanceId, sender_standby_state,
                            datanode_wal_send_state_int_to_string(sender_standby_state), sender_secondary_state,
                            datanode_wal_send_state_int_to_string(sender_secondary_state));

                        goto process_finish;
                    }
                }
            } else if (local_db_state == INSTANCE_HA_STATE_NEED_REPAIR &&
                (build_reason == INSTANCE_HA_DATANODE_BUILD_REASON_SYSTEMID_NOT_MATCHED ||
                build_reason == INSTANCE_HA_DATANODE_BUILD_REASON_VERSION_NOT_MATCHED ||
                build_reason == INSTANCE_HA_DATANODE_BUILD_REASON_TIMELINE_NOT_MATCHED ||
                build_reason == INSTANCE_HA_DATANODE_BUILD_REASON_DCF_LOG_LOSS)) {
                if (IsMaintenanceModeDisableOperation(CMS_BUILD_DN, mode)) {
                    write_runlog(LOG, "%d Maintaining cluster: cm server cannot build dn.\n", __LINE__);
                    goto process_finish;
                }

                send_arbitration_command(recvMsgInfo, MSG_CM_AGENT_BUILD, node, instanceId, NO_NEED_TO_SET_PARAM,
                    BUILD_TIMER_OUT, 0);
                goto process_finish;
            } else {
                instance_delay_arbitrate_time_out_direct_clean(group_index, member_index,
                    MONITOR_INSTANCE_ARBITRATE_DELAY_CYCLE_MAX_COUNT2);
                write_runlog(ERROR, "localrole=%d instancetype =%d(node =%u  instanceid =%u) local_db_state =%d\n",
                    local_static_role, instanceType, node, instanceId, local_db_state);
            }
        }
#ifndef ENABLE_LLT
        if (g_only_dn_cluster) {
            cdt = ((local_dynamic_role == INSTANCE_ROLE_STANDBY) && (peer_dynamic_role == INSTANCE_ROLE_STANDBY) &&
                !(local_db_state == INSTANCE_HA_STATE_BUILDING && peer_db_state == INSTANCE_HA_STATE_PROMOTING) &&
                (local_db_state != INSTANCE_HA_STATE_PROMOTING && peer_db_state != INSTANCE_HA_STATE_PROMOTING) &&
                !is_pending_command(group_index, member_index, MSG_CM_AGENT_SWITCHOVER));
            if (cdt) {
                ret = instance_delay_arbitrate_time_out(local_dynamic_role, peer_dynamic_role, group_index,
                    member_index, MONITOR_INSTANCE_ARBITRATE_DELAY_CYCLE_MAX_COUNT * 2);
                if (ret == 1) {
                    send_arbitration_command(recvMsgInfo, MSG_CM_AGENT_RESTART, node, instanceId);
                    g_instance_group_report_status_ptr[group_index]
                        .instance_status.arbitrate_status_member[member_index]
                        .restarting = true;
                    g_instance_group_report_status_ptr[group_index]
                        .instance_status.arbitrate_status_member[other_member_index]
                        .restarting = true;
                    write_runlog(LOG, "double standby datanode instance, restart to pending.\n");
                }

                goto process_finish;
            }
        } else {
            cdt = ((local_dynamic_role == INSTANCE_ROLE_STANDBY) && (peer_dynamic_role == INSTANCE_ROLE_STANDBY));
            if (cdt) {
                goto process_finish;
            }
        }
#endif
        cdt = ((local_dynamic_role == INSTANCE_ROLE_STANDBY) && (peer_dynamic_role == INSTANCE_ROLE_PENDING));
        if (cdt) {
            goto process_finish;
        }

        cdt = ((local_dynamic_role == INSTANCE_ROLE_STANDBY) && (peer_dynamic_role == INSTANCE_ROLE_UNKNOWN) &&
            !is_pending_command(group_index, member_index, MSG_CM_AGENT_BUILD));
        if (cdt) {
            cdt = (g_only_dn_cluster && g_instance_group_report_status_ptr[group_index]
                    .instance_status.command_member[member_index].sync_mode == 0 &&
                g_dn_replication_num == 2);
            if (cdt) {
                write_runlog(LOG, "the standby %u is not sync mode, will don't failover.\n", instanceId);
                goto process_finish;
            }

            int bestPrimaryIndex = find_candiate_primary_node_in_instance_role_group(group_index, member_index);
            if (member_index == bestPrimaryIndex) {
                cdt = (!g_multi_az_cluster && g_instance_group_report_status_ptr[group_index]
                        .instance_status.data_node_member[(g_dn_replication_num - 1)]
                        .local_status.db_state != INSTANCE_HA_STATE_NORMAL);
                if (cdt) {
                    ret = 0;
                    write_runlog(LOG,
                        "the dummy instance status is abnormal, so standby(id:%u) instance cannot be promoted.\n",
                        instanceId);
                } else {
                    uint32 tmpDelayTime = instance_failover_delay_timeout;
                    cdt = (tmpDelayTime < instance_heartbeat_timeout &&
                        g_instance_group_report_status_ptr[group_index]
                                .instance_status.command_member[other_member_index]
                                .heat_beat < static_cast<int>(instance_heartbeat_timeout) &&
                        local_db_state != INSTANCE_HA_STATE_MANUAL_STOPPED);
                    if (cdt) {
                        if (tmpDelayTime == 0) {
                            tmpDelayTime = instance_heartbeat_timeout;
                        }
                    }
                    ret = instance_delay_arbitrate_time_out(local_dynamic_role, peer_dynamic_role, group_index,
                        member_index, (int)tmpDelayTime);
                }

                cdt = (ret == 1 && !check_datanode_arbitrate_status(group_index, member_index));
                if (cdt) {
                    write_runlog(LOG, "the heart beat for static primary is %d.\n",
                        g_instance_group_report_status_ptr[group_index]
                            .instance_status.command_member[other_member_index].heat_beat);
                    if (IsMaintenanceModeDisableOperation(CMS_FAILOVER_DN, mode)) {
                        write_runlog(LOG, "%d Maintaining cluster: cm server cannot failover dn.\n", __LINE__);
                        goto process_finish;
                    }

                    change_primary_member_index(group_index, member_index);
                    send_arbitration_command(recvMsgInfo, MSG_CM_AGENT_FAILOVER, node, instanceId);
                    g_instance_group_report_status_ptr[group_index]
                        .instance_status.data_node_member[member_index].arbitrateFlag = true;
                    cm_pending_notify_broadcast_msg(group_index, instanceId);
                }
                goto process_finish;
            } else {
                g_HA_status->status = CM_STATUS_NEED_REPAIR;
                instance_delay_arbitrate_time_out_direct_clean(group_index, member_index,
                    instance_failover_delay_timeout);
                goto process_finish;
            }
        }

        /* local is pengding process */
        cdt = ((local_dynamic_role == INSTANCE_ROLE_PENDING) && (peer_dynamic_role == INSTANCE_ROLE_PRIMARY));
        if (cdt) {
            send_arbitration_command(recvMsgInfo, MSG_CM_AGENT_NOTIFY, node, instanceId, INSTANCE_ROLE_STANDBY);
            goto process_finish;
        }

        cdt = ((local_dynamic_role == INSTANCE_ROLE_PENDING) && (peer_dynamic_role == INSTANCE_ROLE_STANDBY));
        if (cdt) {
            if (g_only_dn_cluster) {
                /* do nothing */
            } else {
                send_arbitration_command(recvMsgInfo, MSG_CM_AGENT_NOTIFY, node, instanceId, INSTANCE_ROLE_STANDBY);
            }
            /* need no operation */
            goto process_finish;
        }

        cdt = ((local_dynamic_role == INSTANCE_ROLE_PENDING) && (peer_dynamic_role == INSTANCE_ROLE_PENDING));
        if (cdt) {
            cdt = (mode == MAINTENANCE_MODE_UPGRADE || mode == MAINTENANCE_MODE_DILATATION);
            if (cdt) {
                int staticPrimaryIndex = GetDatanodeStaticPrimaryIndex(group_index);
                if (staticPrimaryIndex == -1) {
                    int initPrimaryIndex = GetDatanodeInitPrimaryIndex(group_index);
                    uint32 initNode = g_instance_role_group_ptr[group_index].instanceMember[initPrimaryIndex].node;
                    uint32 initId = g_instance_role_group_ptr[group_index].instanceMember[initPrimaryIndex].instanceId;
                    NotifyDatanodeDynamicPrimary(recvMsgInfo, initNode, initId, group_index, initPrimaryIndex);
                    write_runlog(LOG,
                        "%d Maintaining cluster with neither static nor dynamic primary: "
                        "cm server arbitrate init primary (%u) to dynamic primary.\n",
                        __LINE__, initId);
                    if (member_index == initPrimaryIndex) {
                        goto process_finish;
                    }
                }

                send_arbitration_command(recvMsgInfo, MSG_CM_AGENT_NOTIFY, node, instanceId, INSTANCE_ROLE_STANDBY);
                write_runlog(LOG, "%d Maintaining cluster: cm server arbitrates %u to standby.\n", __LINE__,
                    instanceId);
                goto process_finish;
            }

            int bestPrimaryIndex = find_candiate_primary_node_in_instance_role_group(group_index, member_index);

            if (g_only_dn_cluster) {
                cdt = ((!XLogRecPtrIsInvalid(local_last_xlog_location)) &&
                    (!XLogRecPtrIsInvalid(peer_last_xlog_location)) &&
                    (XLByteLE(local_last_xlog_location, peer_last_xlog_location)));
                if (cdt) {
                    write_runlog(LOG,
                        "%d pending-pending,XLByteLE:local_last_xlog_location=%d peer_last_xlog_location=%d LE=%d.to "
                        "standby\n",
                        __LINE__, XLogRecPtrIsInvalid(local_last_xlog_location),
                        XLogRecPtrIsInvalid(peer_last_xlog_location),
                        XLByteLE(peer_last_xlog_location, local_last_xlog_location));

                    send_arbitration_command(recvMsgInfo, MSG_CM_AGENT_NOTIFY, node, instanceId, INSTANCE_ROLE_STANDBY);
                    goto process_finish;
                } else if ((!XLogRecPtrIsInvalid(local_last_xlog_location)) &&
                    (!XLogRecPtrIsInvalid(peer_last_xlog_location)) &&
                    (XLByteLT(peer_last_xlog_location, local_last_xlog_location)) &&
                    (bestPrimaryIndex == member_index) && !check_datanode_arbitrate_status(group_index, member_index)) {
                    write_runlog(LOG,
                        "%d pending-pending,XLByteLT:local_last_xlog_location=%d peer_last_xlog_location=%d LT=%d.to "
                        "primary\n",
                        __LINE__, XLogRecPtrIsInvalid(local_last_xlog_location),
                        XLogRecPtrIsInvalid(peer_last_xlog_location),
                        XLByteLT(peer_last_xlog_location, local_last_xlog_location));

                    change_primary_member_index(group_index, member_index);

                    send_arbitration_command(recvMsgInfo, MSG_CM_AGENT_NOTIFY, node, instanceId, INSTANCE_ROLE_PRIMARY);
                    g_instance_group_report_status_ptr[group_index]
                        .instance_status.data_node_member[member_index]
                        .arbitrateFlag = true;
                    cm_pending_notify_broadcast_msg(group_index, instanceId);
                    goto process_finish;
                } else {
                    write_runlog(LOG,
                        "%d pending-pending,XLByteLT:local_last_xlog_location=%d peer_last_xlog_location=%d LE=%d.do "
                        "nothing\n",
                        __LINE__, XLogRecPtrIsInvalid(local_last_xlog_location),
                        XLogRecPtrIsInvalid(peer_last_xlog_location),
                        XLByteLT(peer_last_xlog_location, local_last_xlog_location));

                    g_HA_status->status = CM_STATUS_NEED_REPAIR;
                    goto process_finish;
                }
            } else {
                if (!XLogRecPtrIsInvalid(local_last_xlog_location)) {
                    write_runlog(LOG,
                        "%d pending-pending,XLByteLE:local_last_xlog_location=%d peer_last_xlog_location=%d LE=%d.to "
                        "standby\n",
                        __LINE__, XLogRecPtrIsInvalid(local_last_xlog_location),
                        XLogRecPtrIsInvalid(peer_last_xlog_location),
                        XLByteLE(peer_last_xlog_location, local_last_xlog_location));

                    send_arbitration_command(recvMsgInfo, MSG_CM_AGENT_NOTIFY, node, instanceId, INSTANCE_ROLE_STANDBY);
                    goto process_finish;
                } else {
                    write_runlog(LOG,
                        "%d pending-pending,XLByteLT:local_last_xlog_location=%d peer_last_xlog_location=%d LE=%d.do "
                        "nothing\n",
                        __LINE__, XLogRecPtrIsInvalid(local_last_xlog_location),
                        XLogRecPtrIsInvalid(peer_last_xlog_location),
                        XLByteLT(peer_last_xlog_location, local_last_xlog_location));

                    g_HA_status->status = CM_STATUS_NEED_REPAIR;
                    goto process_finish;
                }
            }
        }

        cdt = ((local_dynamic_role == INSTANCE_ROLE_PENDING) && (peer_dynamic_role == INSTANCE_ROLE_UNKNOWN));
        if (cdt) {
            int bestPrimaryIndex = find_candiate_primary_node_in_instance_role_group(group_index, member_index);
            uint32 tmpDelayTime = instance_heartbeat_timeout;
            if (g_instance_group_report_status_ptr[group_index]
                .instance_status.command_member[other_member_index]
                .heat_beat < static_cast<int>(instance_heartbeat_timeout)) {
                tmpDelayTime = instance_heartbeat_timeout;
                ret = instance_delay_arbitrate_time_out(local_dynamic_role, peer_dynamic_role, group_index,
                    member_index, static_cast<int>(tmpDelayTime));
            } else {
                ret = 1;
            }
            cdt = (ret == 1 &&
                (peer_db_state == INSTANCE_HA_STATE_UNKONWN || peer_db_state == INSTANCE_HA_STATE_MANUAL_STOPPED ||
                peer_db_state == INSTANCE_HA_STATE_PORT_USED || peer_db_state == INSTANCE_HA_STATE_DISK_DAMAGED));
            if (cdt) {
                send_arbitration_command(recvMsgInfo, MSG_CM_AGENT_NOTIFY, node, instanceId, INSTANCE_ROLE_STANDBY);
                write_runlog(LOG, "notify local datanode to standby.\n");

                goto process_finish;
            }

            /*
             * if peer built failed, peer must be standby last time and local is primary.
             */
            cdt = (peer_db_state == INSTANCE_HA_STATE_BUILD_FAILED && (bestPrimaryIndex == member_index) &&
                !check_datanode_arbitrate_status(group_index, member_index));
            if (cdt) {
                send_arbitration_command(recvMsgInfo, MSG_CM_AGENT_NOTIFY, node, instanceId, INSTANCE_ROLE_PRIMARY);
                g_instance_group_report_status_ptr[group_index]
                    .instance_status.data_node_member[member_index].arbitrateFlag = true;
                cm_pending_notify_broadcast_msg(group_index, instanceId);
                write_runlog(LOG, "notify local datanode to primary.\n");

                goto process_finish;
            }
        }

        cdt = ((local_dynamic_role == INSTANCE_ROLE_UNKNOWN) && (local_db_state == INSTANCE_HA_STATE_BUILD_FAILED) &&
            (g_instance_group_report_status_ptr[group_index].instance_status.command_member[member_index]
                .command_status == INSTANCE_COMMAND_WAIT_EXEC_ACK) &&
            is_pending_command(group_index, member_index, MSG_CM_AGENT_BUILD));
        if (cdt) {
            /*
             * cm_agent found both gs_build.pid and gaussdb.state do not exist during building and regard building
             * failed. but may this is just betweenness and cm_server delay to arbitrate.
             */
            ret = instance_delay_arbitrate_time_out(local_dynamic_role, peer_dynamic_role, group_index, member_index,
                MONITOR_INSTANCE_ARBITRATE_DELAY_CYCLE_MAX_COUNT);
            if (ret == 1) {
                write_runlog(LOG, "clean command when build failed, pending command is %d, instance is %u.\n",
                    get_pending_command(group_index, member_index), instanceId);
                set_pending_command(group_index, member_index, MSG_CM_AGENT_BUTT);
            }
        }
    } else {
        write_runlog(ERROR, "local_static_role unknown localrole=%d instancetype =%d(node =%u  instanceid =%u)\n",
            local_static_role, instanceType, node, instanceId);
    }
process_finish:
    (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[group_index].lk_lock));
    return;
}
