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
 * cms_global_params_utils.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_server/cms_global_params_utils.cpp
 *
 * -------------------------------------------------------------------------
 */
#include <sys/epoll.h>
#include "cm/cm_elog.h"
#include "cms_ddb.h"
#include "cms_global_params.h"
#include "cms_process_messages.h"
#include "cms_alarm.h"
#include "cms_write_dynamic_config.h"
#include "cms_arbitrate_datanode_pms_utils.h"
#include "cms_az.h"

void ChangeDnMemberIndex(const char *str, uint32 groupIdx, int32 memIdx, int32 instTypePur, int32 instTypeSor)
{
    cm_instance_role_status *instMem = g_instance_role_group_ptr[groupIdx].instanceMember;
    int32 count = g_instance_role_group_ptr[groupIdx].count;
    cm_instance_command_status *cmd = g_instance_group_report_status_ptr[groupIdx].instance_status.command_member;
    uint32 peerInstId = cmd[memIdx].peerInstId;
    write_runlog(LOG, "%s: line %d: instd(%u) instTypePur is (%d: %s), instTypeSor is (%d: %s), peerInstId is %u.\n",
        str, __LINE__, instMem[memIdx].instanceId, instTypePur, datanode_role_int_to_string(instTypePur),
        instTypeSor, datanode_role_int_to_string(instTypeSor), peerInstId);
    for (int32 i = 0; i < count; ++i) {
        /* Does not change dummy standby member index, only change primary and standby member index */
        if (i == memIdx && instMem[i].role != instTypePur) {
            write_runlog(LOG, "%s: %d: instance(%u) static role(%s) will change to be %s.\n",
                str, __LINE__, instMem[i].instanceId, datanode_role_int_to_string(instMem[i].role),
                datanode_role_int_to_string(instTypePur));
            instMem[i].role = instTypePur;
            cmd[i].role_changed = INSTANCE_ROLE_CHANGED;
        } else if (((instTypePur == INSTANCE_ROLE_PRIMARY || instTypePur == INSTANCE_ROLE_MAIN_STANDBY
                     || instTypePur == INSTANCE_ROLE_STANDBY) || peerInstId == instMem[i].instanceId)
                     && (i != memIdx) && instMem[i].role == instTypePur) {
            write_runlog(LOG, "%s: %d: instance(%u) static role(%s) will change to be %s.\n",
                str, __LINE__, instMem[i].instanceId, datanode_role_int_to_string(instMem[i].role),
                datanode_role_int_to_string(instTypeSor));
            instMem[i].role = instTypeSor;
            cmd[i].role_changed = INSTANCE_ROLE_CHANGED;
        }
    }
    SetDynamicConfigChangeToDdb(groupIdx, 0);
}

void ChangeCascadeMemberIndex(const char *str, uint32 groupIdx, int32 memIdx, int32 peerId)
{
    cm_instance_role_status *instMem = g_instance_role_group_ptr[groupIdx].instanceMember;
    int32 count = g_instance_role_group_ptr[groupIdx].count;
    cm_instance_command_status *cmd = g_instance_group_report_status_ptr[groupIdx].instance_status.command_member;
    for (int32 i = 0; i < count; ++i) {
        /* change cascade standby and one standby index */
        if (i == memIdx && instMem[i].role == INSTANCE_ROLE_CASCADE_STANDBY) {
            write_runlog(LOG, "%s: %d: instance(%u) static role(%s) will change to be %s.\n",
                str, __LINE__, instMem[i].instanceId, datanode_role_int_to_string(INSTANCE_ROLE_CASCADE_STANDBY),
                datanode_role_int_to_string(INSTANCE_ROLE_STANDBY));
            instMem[i].role = INSTANCE_ROLE_STANDBY;
            cmd[i].role_changed = INSTANCE_ROLE_CHANGED;
        } else if (i == peerId && instMem[i].role == INSTANCE_ROLE_STANDBY) {
            write_runlog(LOG, "%s: %d: instance(%u) static role(%s) will change to be %s.\n",
                str, __LINE__, instMem[i].instanceId, datanode_role_int_to_string(INSTANCE_ROLE_STANDBY),
                datanode_role_int_to_string(INSTANCE_ROLE_CASCADE_STANDBY));
            instMem[i].role = INSTANCE_ROLE_CASCADE_STANDBY;
            cmd[i].role_changed = INSTANCE_ROLE_CHANGED;
        }
    }
    SetDynamicConfigChangeToDdb(groupIdx, 0);
}

void ChangeDnPrimaryMemberIndex(uint32 group_index, int primary_member_index)
{
    if (g_one_master_multi_slave) {
        if (g_ssDoubleClusterMode == SS_DOUBLE_STANDBY) {
            ChangeDnMemberIndex("[ChangeDnPrimaryMemberIndex]",
                group_index, primary_member_index, INSTANCE_ROLE_MAIN_STANDBY, INSTANCE_ROLE_STANDBY);
        } else {
            ChangeDnMemberIndex("[ChangeDnPrimaryMemberIndex]",
                group_index, primary_member_index, INSTANCE_ROLE_PRIMARY, INSTANCE_ROLE_STANDBY);
        }
    } else {
        change_primary_member_index(group_index, primary_member_index);
    }
}


void change_primary_member_index(uint32 group_index, int primary_member_index)
{
    cm_instance_role_status* instanceMember = g_instance_role_group_ptr[group_index].instanceMember;
    int count = g_instance_role_group_ptr[group_index].count;
    cm_instance_command_status* status = g_instance_group_report_status_ptr[group_index].instance_status.command_member;

    for (int i = 0; i < count; i++) {
        /* Does not change dummy standby member index, only change primary and standby member index */
        if (i == primary_member_index &&
            (instanceMember[i].role != INSTANCE_ROLE_PRIMARY && instanceMember[i].role != INSTANCE_ROLE_MAIN_STANDBY)) {
            if (g_ssDoubleClusterMode == SS_DOUBLE_STANDBY) {
                instanceMember[i].role = INSTANCE_ROLE_MAIN_STANDBY;
            } else {
                instanceMember[i].role = INSTANCE_ROLE_PRIMARY;
            }
            status[i].role_changed = INSTANCE_ROLE_CHANGED;
            SetDynamicConfigChangeToDdb(group_index, i);
        } else if (i != primary_member_index &&
            (instanceMember[i].role == INSTANCE_ROLE_PRIMARY || instanceMember[i].role == INSTANCE_ROLE_MAIN_STANDBY)) {
            instanceMember[i].role = INSTANCE_ROLE_STANDBY;
            status[i].role_changed = INSTANCE_ROLE_CHANGED;
            SetDynamicConfigChangeToDdb(group_index, i);
        }
    }
    (void)WriteDynamicConfigFile(false);
}

int find_node_in_dynamic_configure(uint32 node, uint32 instanceId, uint32 *group_index, int *member_index)
{
    *group_index = 0;
    *member_index = 0;
    for (uint32 i = 0; i < g_dynamic_header->relationCount; i++) {
        for (int j = 0; j < Min(g_instance_role_group_ptr[i].count, CM_PRIMARY_STANDBY_MAX_NUM); j++) {
            if ((node == g_instance_role_group_ptr[i].instanceMember[j].node) &&
                (instanceId == g_instance_role_group_ptr[i].instanceMember[j].instanceId)) {
                *group_index = i;
                *member_index = j;
                return 0;
            }
        }
    }
    return -1;
}

void instance_delay_arbitrate_time_out_direct_clean(uint32 group_index, int member_index, uint32 delay_max_count)
{
    g_instance_group_report_status_ptr[group_index].instance_status.command_member[member_index].arbitrate_delay_set =
            INSTANCE_ARBITRATE_DELAY_NO_SET;
    g_instance_group_report_status_ptr[group_index].instance_status.command_member[member_index]
            .arbitrate_delay_time_out = (int)delay_max_count;
    g_instance_group_report_status_ptr[group_index].instance_status.command_member[member_index]
            .local_arbitrate_delay_role = INSTANCE_ROLE_UNKNOWN;
    g_instance_group_report_status_ptr[group_index].instance_status.command_member[member_index]
            .peerl_arbitrate_delay_role = INSTANCE_ROLE_UNKNOWN;

    write_runlog(DEBUG1,
                 "instance_delay_arbitrate_time_out_direct_clean (node =%u  instanceid =%u), delay_max_count=%u\n",
                 g_instance_role_group_ptr[group_index].instanceMember[member_index].node,
                 g_instance_role_group_ptr[group_index].instanceMember[member_index].instanceId, delay_max_count);
}

bool IsCurInstanceInVoteAz(uint32 groupIndex, int memberIndex)
{
    uint32 azPriority = g_instance_role_group_ptr[groupIndex].instanceMember[memberIndex].azPriority;
    for (int i = 0; i < AZ_MEMBER_MAX_COUNT; ++i) {
        if (azPriority == g_cmAzInfo[i].azPriority && g_cmAzInfo[i].isVoteAz == IS_VOTE_AZ) {
            write_runlog(DEBUG1, "instance(%u) in vote AZ.\n",
                g_instance_role_group_ptr[groupIndex].instanceMember[memberIndex].instanceId);
            return true;
        }
    }
    return false;
}

int GetVoteAzIndex()
{
    int voteAzIndex = AZ_ALL_INDEX;
    for (int i = 0; i < AZ_MEMBER_MAX_COUNT; ++i) {
        if (g_cmAzInfo[i].isVoteAz == IS_VOTE_AZ) {
            voteAzIndex = i;
            break;
        }
    }
    return voteAzIndex;
}

uint32 GetClusterUpgradeMode()
{
    int rcs;
    struct stat statBuf = {0};
    char pgHostPath[MAX_PATH_LEN] = {0};
    char grayscaleUpgradeCheck[MAX_PATH_LEN] = {0};
    char inplaceUpgradeFlag[MAX_PATH_LEN] = {0};
    char upgradeFlag[MAX_PATH_LEN] = {0};
    char agentConfigDir[MAX_PATH_LEN] = {0};
    errno_t rc = snprintf_s(agentConfigDir, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/cm_agent/cm_agent.conf",
        g_currentNode->cmDataPath);
    securec_check_intval(rc, (void)rc);
    check_input_for_security(agentConfigDir);
    canonicalize_path(agentConfigDir);

    uint32 upgradeMode = 0;

    FILE *fd = fopen(agentConfigDir, "r");
    if (fd == NULL) {
        write_runlog(LOG, "Cannot open the cm agent config file %s.\n", agentConfigDir);
        return upgradeMode;
    }
    (void)fclose(fd);

    rcs = cmserver_getenv("PGHOST", pgHostPath, sizeof(pgHostPath), ERROR);
    if (rcs == EOK) {
        rcs = snprintf_s(grayscaleUpgradeCheck, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/binary_upgrade", pgHostPath);
        securec_check_intval(rcs, (void)rcs);
        if (access(grayscaleUpgradeCheck, F_OK) == 0) {
            rcs = snprintf_s(
                inplaceUpgradeFlag, MAX_PATH_LEN, MAX_PATH_LEN - 1,
                "%s/inplace_upgrade_flag", grayscaleUpgradeCheck);
            securec_check_intval(rcs, (void)rcs);
            /* $PGHOST/binary_upgrade exit inplace_upgrade_flag file, cluster is in inplace_upgrade,
             * then cluster is in grayscale upgrade */
            if (stat(inplaceUpgradeFlag, &statBuf) == 0) {
                upgradeMode = get_uint32_value_from_config(agentConfigDir, "upgrade_from", 0);
                if (upgradeMode == 0) {
                    /* if upgradeMode is 0, the binary upgrade is in progress, set upgradeMode to 2(greater than 1) */
                    upgradeMode = 2;
                }
            }
            // grayscale_upgrade
            rcs = snprintf_s(upgradeFlag, MAX_PATH_LEN, MAX_PATH_LEN - 1,
                "%s/upgrade_step.csv", grayscaleUpgradeCheck);
            securec_check_intval(rcs, (void)rcs);
            if (stat(upgradeFlag, &statBuf) == 0) {
                upgradeMode = MAINTENANCE_NODE_UPGRADED_GRAYSCALE;
            }
        }
    } else {
        write_runlog(ERROR, "get PGHOST failed!\n");
    }

    write_runlog(DEBUG1, "Cluster upgrade mode is %u\n", upgradeMode);
    return upgradeMode;
}

bool ExistClusterMaintenance(bool *isInFailover)
{
    if (access(cluster_maintance_path, F_OK) == 0) {
        if (isInFailover == NULL) {
            return true;
        }
        char maintenanceInfo[MAX_PATH_LEN] = {0};
        FILE* fp = fopen(cluster_maintance_path, "r");
        if (fp == NULL) {
            return false;
        }
        if (fgets(maintenanceInfo, MAX_PATH_LEN, fp) == NULL) {
            (void)fclose(fp);
            return false;
        }
        if (strstr(maintenanceInfo, "failover") != NULL) {
            *isInFailover = true;
        }
        (void)fclose(fp);
        write_runlog(LOG, "Streaming standby cluster is in %s.\n", *isInFailover ? "failover" : "switchover");
        return true;
    }
    return false;
}

int GetSendTimes(uint32 groupIndex, int memberIndex, bool isTotal)
{
    if (memberIndex < 0 || memberIndex >= g_instance_role_group_ptr[groupIndex].count) {
        return 0;
    }
    if (isTotal) {
        return g_instance_group_report_status_ptr[groupIndex].instance_status.command_member[memberIndex].maxSendTimes;
    }
    return g_instance_group_report_status_ptr[groupIndex].instance_status.command_member[memberIndex]
        .command_send_num;
}

void SetSendTimes(uint32 groupIndex, int memberIndex, int timeOut)
{
    cm_instance_command_status *pCommand =
        g_instance_group_report_status_ptr[groupIndex].instance_status.command_member;
    if (timeOut < SWITCHOVER_SEND_CHECK_RATE) {
        pCommand[memberIndex].maxSendTimes = SWITCHOVER_SEND_CHECK_NUM;
    } else {
        pCommand[memberIndex].maxSendTimes = timeOut / SWITCHOVER_SEND_CHECK_RATE;
    }
}

bool IsArchiveMaxSendTimes(uint32 groupIndex, int memberIndex)
{
    cm_instance_command_status *pCommand =
        g_instance_group_report_status_ptr[groupIndex].instance_status.command_member;
    if (pCommand[memberIndex].maxSendTimes == 0) {
        return pCommand[memberIndex].command_send_num <= SWITCHOVER_SEND_CHECK_NUM;
    } else {
        return pCommand[memberIndex].command_send_num <= pCommand[memberIndex].maxSendTimes;
    }
}

uint32 GetInstanceIdInGroup(uint32 groupIndex, int memberIndex)
{
    if (memberIndex < 0 || memberIndex >= g_instance_role_group_ptr[groupIndex].count) {
        return g_instance_role_group_ptr[groupIndex].instanceMember[0].instanceId;
    }
    return g_instance_role_group_ptr[groupIndex].instanceMember[memberIndex].instanceId;
}

int32 GetInstanceCountsInGroup(uint32 groupIndex)
{
    return g_instance_role_group_ptr[groupIndex].count;
}

bool IncrementTermToFile()
{
    uint32 curFileTerm = GetTermForMinorityStart();
    uint32 finalTerm = curFileTerm;
    if (curFileTerm != g_termCache) {
        write_runlog(WARNING,
            "curFileTerm(%u) is not equal with cached term(%u), we choose the largest one.\n",
            curFileTerm, g_termCache);
        finalTerm = (curFileTerm > g_termCache) ? curFileTerm : g_termCache;
    }
    finalTerm += CM_INCREMENT_TERM_VALUE;
    char command[CM_MAX_COMMAND_LEN] = {0};
    int32 rc = snprintf_s(command,
        CM_MAX_COMMAND_LEN, CM_MAX_COMMAND_LEN - 1, "echo -e \'%u\' > %s;", finalTerm, cm_force_start_file_path);
    securec_check_intval(rc, (void)rc);
    write_runlog(LOG, "IncrementTermToFile, cmd: %s .\n", command);
    rc = system(command);
    if (rc != 0) {
        write_runlog(ERROR,
            "Failed to increment minority term cache to %u, result is %d-%d.\n", g_termCache, rc, WEXITSTATUS(rc));
        return false;
    }
    g_termCache = finalTerm;
    write_runlog(LOG, "Success to execute command: %s, increment minority term cache to %u.\n", command, g_termCache);
    return true;
}

bool CurAzIsNeedToStop(const char *azName)
{
    uint32 azPriority = 0;
    int32 azIndex = -1;
    int32 curAzIndex = -1;
    for (int32 i = 0; i < AZ_MEMBER_MAX_COUNT; ++i) {
        if (strcmp(azName, g_cmAzInfo[i].azName) == 0) {
            azPriority = g_cmAzInfo[i].azPriority;
            azIndex = i;
        }
        if (strcmp(g_currentNode->azName, g_cmAzInfo[i].azName) == 0) {
            curAzIndex = i;
        }
    }
    if ((azIndex == -1) || (curAzIndex == -1)) {
        write_runlog(ERROR, "can not find azName(%s) or curAzName(%s) from cmAzInfo.\n", azName, g_currentNode->azName);
        return false;
    }
    write_runlog(LOG, "dnCount is [%u: %u], azPriority is [%u: %u].\n",
        g_cmAzInfo[curAzIndex].dnCount, g_cmAzInfo[azIndex].dnCount, g_currentNode->azPriority, azPriority);

    /* 1. dnCount is less,
     * 2. azPriority is more,
     * these condition is chosen to be stopped
     */
    if (g_cmAzInfo[curAzIndex].dnCount < g_cmAzInfo[azIndex].dnCount) {
        return true;
    }
    if (g_cmAzInfo[curAzIndex].dnCount > g_cmAzInfo[azIndex].dnCount) {
        return false;
    }

    if (g_currentNode->azPriority < azPriority) {
        return false;
    }
    return true;
}

void InitClientCrt(const char *appPath)
{
    errno_t rcs =
        snprintf_s(g_tlsPath.caFile, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/share/sslcert/etcd/etcdca.crt", appPath);
    securec_check_intval(rcs, (void)rcs);
    rcs = snprintf_s(g_tlsPath.crtFile, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/share/sslcert/etcd/client.crt", appPath);
    securec_check_intval(rcs, (void)rcs);
    rcs = snprintf_s(g_tlsPath.keyFile, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/share/sslcert/etcd/client.key", appPath);
    securec_check_intval(rcs, (void)rcs);
}

bool CanArbitrate(MsgRecvInfo* recvMsgInfo, const char *arbitrateType)
{
    const uint32 stopPrintInterval = 5;

    if (g_HA_status->local_role == CM_SERVER_STANDBY) {
        write_runlog(LOG, "%s: cm_server is in standby state, skip arbitrate\n", arbitrateType);
        AsyncProcMsg(recvMsgInfo, PM_REMOVE_CONN, NULL, 0);
        return false;
    }

    if (ctl_stop_cluster_server_halt_arbitration_timeout > 0) {
        /* Meaning cm_ctl is running a full cluster stop and we should not do any arbitration */
        if (ctl_stop_cluster_server_halt_arbitration_timeout % stopPrintInterval == 0) {
            write_runlog(LOG,
                "cm_ctl is running a full cluster stop. %s are halted. "
                "Waiting for another %u seconds.\n",
                arbitrateType, ctl_stop_cluster_server_halt_arbitration_timeout);
        }
        return false;
    }

    return true;
}

void SetSwitchoverCmd(cm_instance_command_status *cmd, int32 localRole, uint32 instId, uint32 peerInstId)
{
    cmd->command_status = INSTANCE_COMMAND_WAIT_EXEC;
    cmd->pengding_command = (int)MSG_CM_AGENT_SWITCHOVER;
    if (localRole == INSTANCE_ROLE_STANDBY) {
        if (g_ssDoubleClusterMode == SS_DOUBLE_STANDBY) {
            cmd->cmdPur = INSTANCE_ROLE_MAIN_STANDBY;
        } else {
            cmd->cmdPur = INSTANCE_ROLE_PRIMARY;
        }
        cmd->cmdSour = INSTANCE_ROLE_STANDBY;
    } else if (localRole == INSTANCE_ROLE_CASCADE_STANDBY) {
        cmd->cmdPur = INSTANCE_ROLE_STANDBY;
        cmd->cmdSour = INSTANCE_ROLE_CASCADE_STANDBY;
    }
    cmd->peerInstId = peerInstId;
    write_runlog(LOG, "instd(%u) localRole(%d: %s), cmdStatus[cmdPur(%d: %s), cmdSour(%d: %s), peer(%u)].\n", instId,
        localRole, datanode_role_int_to_string(localRole), cmd->cmdPur, datanode_role_int_to_string(cmd->cmdPur),
        cmd->cmdSour, datanode_role_int_to_string(cmd->cmdSour), peerInstId);
}

void HashCascadeStandby(cm_to_ctl_instance_datanode_status *dnReport, uint32 groupIdx, int32 memIdx)
{
    int32 localRole =
        g_instance_group_report_status_ptr[groupIdx].instance_status.data_node_member[memIdx].local_status.local_role;
    if (localRole != INSTANCE_ROLE_STANDBY) {
        return;
    }
    bool hasCascade = false;
    cm_instance_role_status *dnRole = g_instance_role_group_ptr[groupIdx].instanceMember;
    for (int32 i = 0; i < g_instance_role_group_ptr[groupIdx].count; ++i) {
        if (dnRole[i].role == INSTANCE_ROLE_CASCADE_STANDBY) {
            hasCascade = true;
            write_runlog(LOG, "instd(%u) is cascade_standby.\n", dnRole[i].instanceId);
        }
    }
    if (!hasCascade) {
        return;
    }
    dnReport->sender_status[0].peer_role = INSTANCE_ROLE_CASCADE_STANDBY;
}

bool CheckCanDoSwitchover(uint32 groupIdx, int32 memIdx, int32 *pendCmd, const char *str)
{
    cm_instance_report_status *instStatus = &g_instance_group_report_status_ptr[groupIdx].instance_status;
    cm_instance_role_status *instRole = g_instance_role_group_ptr[groupIdx].instanceMember;
    for (int32 i = 0; i < g_instance_role_group_ptr[groupIdx].count; i++) {
        if (instStatus->command_member[i].command_status != INSTANCE_NONE_COMMAND) {
            write_runlog(LOG,
                "instanceId =%u try do switchover_msg, but instance(%u) is executing another command (%d)\n",
                instRole[memIdx].instanceId, instRole[i].instanceId, instStatus->command_member[i].pengding_command);
            return false;
        }
    }

    // vote az cannot get the msg abort doing synclist
    if (IsCurInstanceInVoteAz(groupIdx, memIdx)) {
        return true;
    }
    // if dn is cascade_standby, cannot consider syncList
    if (instStatus->data_node_member[memIdx].local_status.local_role != INSTANCE_ROLE_CASCADE_STANDBY &&
        CheckInstInSyncList(groupIdx, memIdx, str) != SYNCLIST_IS_FINISTH) {
        (*pendCmd) = (int32)MSG_CM_AGENT_DN_SYNC_LIST;
        return false;
    }
    return true;
}

void PrintSyncListMsg(uint32 groupIdx, int32 memIdx, const char *str)
{
    cm_instance_report_status *groupRep = &g_instance_group_report_status_ptr[groupIdx].instance_status;
    uint32 instId = g_instance_role_group_ptr[groupIdx].instanceMember[memIdx].instanceId;
    char curStr[MAX_PATH_LEN] = {0};
    char expectStr[MAX_PATH_LEN] = {0};
    char voteAzStr[MAX_PATH_LEN] = {0};
    /* covert the sync list to String. */
    GetSyncListString(&(groupRep->currentSyncList), curStr, sizeof(curStr));
    GetSyncListString(&(groupRep->exceptSyncList), expectStr, sizeof(expectStr));
    GetDnStatusString(&(groupRep->voteAzInstance), voteAzStr, sizeof(voteAzStr));
    write_runlog(LOG, "%s instd(%u) is modifing syncList, synclist is [cur:(%s), expect:(%s), voteAz:(%s)].\n",
        str, instId, curStr, expectStr, voteAzStr);
}

bool CheckGroupAndMemIndex(uint32 groupIdx, int32 memIdx, const char *str)
{
    if (groupIdx >= g_dynamic_header->relationCount) {
        write_runlog(ERROR, "%s:%d, groupIdx is [%u: %u].\n", str, __LINE__, groupIdx, g_dynamic_header->relationCount);
        return false;
    }
    if (memIdx < 0 || memIdx >= g_instance_role_group_ptr[groupIdx].count) {
        write_runlog(ERROR, "%s:%d, memidx is [%d: %d].\n", str, __LINE__, memIdx,
            g_instance_role_group_ptr[groupIdx].count);
        return false;
    }
    return true;
}

EnCheckSynclist CheckInstInSyncList(uint32 groupIdx, int32 memIdx, const char *str)
{
    // if memidx is error, this group not be consider
    if (!CheckGroupAndMemIndex(groupIdx, memIdx, str)) {
        write_runlog(ERROR, "%s:%d, groupIdx is %u, memIdx is %d, cannot checkInstInSyncList.\n", str, __LINE__,
            groupIdx, memIdx);
        return SYNCLIST_IS_FINISTH;
    }
    // if not dn, not need check whether sync is finished
    if (g_instance_role_group_ptr[groupIdx].instanceMember[memIdx].instanceType != INSTANCE_TYPE_DATANODE) {
        return SYNCLIST_IS_FINISTH;
    }
    cm_instance_report_status *groupRep = &g_instance_group_report_status_ptr[groupIdx].instance_status;
    uint32 instId = g_instance_role_group_ptr[groupIdx].instanceMember[memIdx].instanceId;
    if (!CompareCurWithExceptSyncList(groupIdx)) {
        PrintSyncListMsg(groupIdx, memIdx, str);
        return SYNCLIST_IS_NOT_SAME;
    }
    if (groupRep->data_node_member[memIdx].local_status.local_role != INSTANCE_ROLE_CASCADE_STANDBY &&
        !IsInstanceIdInSyncList(instId, &(groupRep->exceptSyncList))) {
        PrintSyncListMsg(groupIdx, memIdx, str);
        return INST_IS_NOT_IN_SYNCLIST;
    }
    return SYNCLIST_IS_FINISTH;
}

bool CheckAllDnShardSynclist(const char *str)
{
    for (uint32 i = 0; i < g_dynamic_header->relationCount; ++i) {
        if (g_instance_role_group_ptr[i].instanceMember[0].instanceType != INSTANCE_TYPE_DATANODE) {
            continue;
        }
        if (CheckInstInSyncList(i, 0, str) == SYNCLIST_IS_NOT_SAME) {
            return false;
        }
    }
    return true;
}

uint32 GetPeerInstIdWhenDnIsStandby(uint32 groupIdx, int32 memIdx)
{
    cm_instance_datanode_report_status *dnRep =
        g_instance_group_report_status_ptr[groupIdx].instance_status.data_node_member;
    cm_instance_role_status *role = g_instance_role_group_ptr[groupIdx].instanceMember;
    uint32 dyPriInstId = 0;
    int32 staPrimIdx = -1;
    int32 dyPrimIdx = -1;
    for (int32 i = 0; i < g_instance_role_group_ptr[groupIdx].count; ++i) {
        if (i == memIdx) {
            continue;
        }
        cm_local_replconninfo *dnStatus = &(dnRep[i].local_status);
        /* static primary */
        if (role[i].role == INSTANCE_ROLE_PRIMARY) {
            if (dnStatus->local_role == INSTANCE_ROLE_PRIMARY && dnStatus->db_state == INSTANCE_HA_STATE_NORMAL) {
                return role[i].instanceId;
            }
            staPrimIdx = i;
        }
        /* dynamic primary */
        if (dnStatus->local_role == INSTANCE_ROLE_PRIMARY) {
            if (dnStatus->db_state == INSTANCE_HA_STATE_NORMAL) {
                dyPriInstId = role[i].instanceId;
            }
            dyPrimIdx = i;
        }
    }
    if (dyPriInstId != 0) {
        return dyPriInstId;
    }
    if (dyPrimIdx != -1) {
        return role[dyPrimIdx].instanceId;
    }
    if (staPrimIdx != -1) {
        return role[staPrimIdx].instanceId;
    }
    int32 peerIndex = (memIdx + 1) % g_instance_role_group_ptr[groupIdx].count;
    return role[peerIndex].instanceId;
}

uint32 GetPeerInstId(uint32 groupIdx, int32 memIdx)
{
    if (!CheckGroupAndMemIndex(groupIdx, memIdx, "[GetPeerInstId]")) {
        return 0;
    }
    cm_instance_datanode_report_status *dnRep =
        g_instance_group_report_status_ptr[groupIdx].instance_status.data_node_member;
    if (dnRep[memIdx].local_status.local_role == INSTANCE_ROLE_STANDBY) {
        return GetPeerInstIdWhenDnIsStandby(groupIdx, memIdx);
    }
    return g_instance_group_report_status_ptr[groupIdx].instance_status.data_node_member[memIdx].dnLp.peerInst;
}

static maintenance_mode GetClusterMaintenanceMode()
{
    maintenance_mode mode = MAINTENANCE_MODE_NONE;
    for (uint32 groupIndex = 0; groupIndex < g_dynamic_header->relationCount; ++groupIndex) {
        mode = getMaintenanceMode(groupIndex);
        if (mode != MAINTENANCE_MODE_NONE) {
            return mode;
        }
    }
    return MAINTENANCE_MODE_NONE;
}

status_t CmsCanArbitrate(CmsArbitrateStatus *cmsSt, const char *str)
{
    cmsSt->upgradeMode = GetClusterMaintenanceMode();
    cmsSt->isDdbHealth = IsDdbHealth(DDB_PRE_CONN);
    cmsSt->cmsRole = g_HA_status->local_role;
    bool isResult =
        (cmsSt->cmsRole != CM_SERVER_PRIMARY) || !(cmsSt->isDdbHealth) ||
        (cmsSt->upgradeMode != MAINTENANCE_MODE_NONE) || g_isPauseArbitration;
    if (isResult) {
        int32 logLevel = (g_HA_status->local_role != CM_SERVER_PRIMARY) ? DEBUG1 : LOG;
        write_runlog(logLevel, "%s cannot arbitrate reduce or increase, in the condition that ddb is health is %d "
            "or upgradeMode is %u.\n", str, cmsSt->isDdbHealth, (uint32)cmsSt->upgradeMode);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t GetNodeIdxByNodeId(uint32 nodeId, uint32 *nodeIdx, const char *str)
{
    for (uint32 i = 0; i < g_node_num; ++i) {
        if (nodeId == g_node[i].node) {
            *nodeIdx = i;
            return CM_SUCCESS;
        }
    }
    write_runlog(ERROR, "%s cannot find the nodeId(%u).\n", str, nodeId);
    return CM_ERROR;
}

bool8 IsCurInstIdCascadeStandby(uint32 groupIdx, int memberIdx)
{
    if (g_instance_role_group_ptr[groupIdx].instanceMember[memberIdx].instanceType != INSTANCE_TYPE_DATANODE) {
        return false;
    }
    if (g_instance_role_group_ptr[groupIdx].instanceMember[memberIdx].role == INSTANCE_ROLE_CASCADE_STANDBY) {
        return true;
    }
    return CM_FALSE;
}
