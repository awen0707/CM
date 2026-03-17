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
 * cms_arbitrate_datanode_pms_utils.cpp
 *     DN one primary multi standby mode arbitration in cms
 *
 * IDENTIFICATION
 *    src/cm_server/cms_arbitrate_datanode_pms_utils.cpp
 *
 * -------------------------------------------------------------------------
 */
#include "cms_arbitrate_datanode_pms_utils.h"
#include  "cms_az.h"
#include "cms_process_messages.h"
#include "cms_ddb.h"

/**
 * @brief
 *
 * @return true
 * @return false
 */
bool CheckPotentialTermRollback()
{
    for (uint32 i = 0; i < g_dynamic_header->relationCount; i++) {
        for (int j = 0; j < g_instance_role_group_ptr[i].count; j++) {
            if (g_instance_group_report_status_ptr[i].instance_status.data_node_member[j].local_status.term >
                FirstTerm) {
                write_runlog(FATAL, "We are in danger of a term-rollback. Abort this arbitration!\n");
                return true;
            }
        }
    }
    return false;
}

void GroupStatusShow(const char *str, const uint32 groupIndex, const uint32 instanceId,
    const int validCount, const bool finishRedo)
{
    cm_instance_role_group *roleGroup = &g_instance_role_group_ptr[groupIndex];
    cm_instance_role_status *roleMember = roleGroup->instanceMember;
    cm_instance_report_status *reportGrp = &(g_instance_group_report_status_ptr[groupIndex].instance_status);
    cm_instance_datanode_report_status *dnReport = reportGrp->data_node_member;
    cm_instance_arbitrate_status *dnArbi = reportGrp->arbitrate_status_member;
    DnInstInfo instInfo = {{0}};
    GetSyncListStr(reportGrp, &instInfo);
    for (int i = 0; i < roleGroup->count; ++i) {
        write_runlog(LOG,
            "%s: line %d: current report instance is %u, node %u"
            ", instanceId %u, local_static_role %d=%s, local_dynamic_role %d=%s, local_term=%u"
            ", local_last_xlog_location=%X/%X, local_db_state %d=%s, local_sync_state=%d, build_reason %d=%s"
            ", double_restarting=%d, disconn_mode %u=%s, disconn_host=%s, disconn_port=%u, local_host=%s, local_port=%u"
            ", redo_finished=%d, peer_state=%d, sync_mode=%d, current_cluster_az_status=%d, validCount=%d"
            ", finishRedo=%d, group_term=%u, curSyncList is [%s], expectSyncList is [%s], voteAzList is [%s], "
            "arbitrate_time is %u, sendFailoverTimes=%u.\n",
            str, __LINE__, instanceId, roleMember[i].node, roleMember[i].instanceId, roleMember[i].role,
            datanode_role_int_to_string(roleMember[i].role), dnReport[i].local_status.local_role,
            datanode_role_int_to_string(dnReport[i].local_status.local_role), dnReport[i].local_status.term,
            (uint32)(dnReport[i].local_status.last_flush_lsn >> 32),
            (uint32)dnReport[i].local_status.last_flush_lsn, dnReport[i].local_status.db_state,
            datanode_dbstate_int_to_string(dnReport[i].local_status.db_state),
            dnReport[i].sender_status[0].sync_state, dnReport[i].local_status.buildReason,
            datanode_rebuild_reason_int_to_string(dnReport[i].local_status.buildReason),
            dnArbi[i].restarting, dnReport[i].local_status.disconn_mode,
            DatanodeLockmodeIntToString(dnReport[i].local_status.disconn_mode),
            dnReport[i].local_status.disconn_host, dnReport[i].local_status.disconn_port,
            dnReport[i].local_status.local_host, dnReport[i].local_status.local_port,
            dnReport[i].local_status.redo_finished, dnReport[i].receive_status.peer_state,
            (int)dnReport[i].sync_standby_mode, (int)current_cluster_az_status,
            validCount, finishRedo, reportGrp->term,
            instInfo.curSl, instInfo.expSl, instInfo.voteL, dnReport[i].arbiTime,
            dnReport[i].sendFailoverTimes);
    }
}

bool IsInstanceInCurrentAz(uint32 groupIndex, uint32 memberIndex, int curAzIndex, int az1Index, int az2Index)
{
    uint32 tmpPriority = g_instance_role_group_ptr[groupIndex].instanceMember[memberIndex].azPriority;
    int tmpAzIndex = 0;
    if (tmpPriority >= g_az_master && tmpPriority < g_az_slave) {
        tmpAzIndex = az1Index;
    } else if (tmpPriority >= g_az_slave && tmpPriority < g_az_arbiter) {
        tmpAzIndex = az2Index;
    }
    if (curAzIndex > 0 && curAzIndex != tmpAzIndex) {
        return false;
    }
    return true;
}

bool IsSyncListEmpty(uint32 groupIndex, uint32 instanceId, maintenance_mode mode)
{
    int onePrimaryTowStandby = 3;
    bool isVoteAz = (GetVoteAzIndex() != AZ_ALL_INDEX);
    if (GetAzDeploymentType(isVoteAz) != TWO_AZ_DEPLOYMENT || mode == MAINTENANCE_NODE_UPGRADED_GRAYSCALE ||
        cm_arbitration_mode == MINORITY_ARBITRATION ||
        g_instance_role_group_ptr[groupIndex].count <= onePrimaryTowStandby ||
        (g_isEnableUpdateSyncList != SYNCLIST_THREADS_IN_PROCESS &&
        g_isEnableUpdateSyncList != SYNCLIST_THREADS_IN_DDB_BAD)) {
        return false;
    }

    bool result = false;
    if (g_instance_group_report_status_ptr[groupIndex].instance_status.currentSyncList.count == 0) {
        result = true;
    }

    if (g_instance_group_report_status_ptr[groupIndex].instance_status.exceptSyncList.count == 0) {
        result = true;
    }

    if (result) {
        write_runlog(LOG, "instance(%u): currentSyncList or exceptSyncList in the group is empty, can not arbitrate.\n",
            instanceId);
    }
    return result;
}

bool IsTermLsnValid(uint32 term, XLogRecPtr lsn)
{
    if (TermIsInvalid(term) || XLogRecPtrIsInvalid(lsn)) {
        return false;
    }
    return true;
}

void ClearDnArbiCond(uint32 groupIndex, ClearAribType type)
{
    cm_instance_datanode_report_status *dnReportStatus =
        g_instance_group_report_status_ptr[groupIndex].instance_status.data_node_member;
    int count = g_instance_role_group_ptr[groupIndex].count;
    for (int i = 0; i < count; ++i) {
        if (type == CLEAR_ALL || type == CLEAR_ARBI_TIME) {
            dnReportStatus[i].arbiTime = 0;
        }
        if (type == CLEAR_ALL || type == CLEAR_SEND_FAILOVER_TIMES) {
            dnReportStatus[i].sendFailoverTimes = 0;
        }
    }
}

bool IsInSyncList(uint32 groupIndex, int memberIndex, int reportMemberIndex)
{
    if (memberIndex == reportMemberIndex) {
        return true;
    }
    uint32 instanceId = g_instance_role_group_ptr[groupIndex].instanceMember[memberIndex].instanceId;
    bool isInSync = IsInstanceIdInSyncList(
        instanceId, &(g_instance_group_report_status_ptr[groupIndex].instance_status.currentSyncList));
    if (!isInSync) {
        return false;
    }

    isInSync = IsInstanceIdInSyncList(
        instanceId, &(g_instance_group_report_status_ptr[groupIndex].instance_status.exceptSyncList));
    return isInSync;
}

void CheckDnBuildStatus(uint32 groupIdx, int32 memIdx, DnBuildStatus *buildStatus)
{
    int32 count = GetInstanceCountsInGroup(groupIdx);
    cm_instance_command_status *status = g_instance_group_report_status_ptr[groupIdx].instance_status.command_member;
    cm_instance_datanode_report_status *dnReport =
        g_instance_group_report_status_ptr[groupIdx].instance_status.data_node_member;
    cm_instance_role_status *role = g_instance_role_group_ptr[groupIdx].instanceMember;
    for (int32 i = 0; i < count; ++i) {
        if (memIdx != -1 && (!IsInSyncList(groupIdx, i, -1) || role[i].role == INSTANCE_ROLE_CASCADE_STANDBY)) {
            if (i == memIdx) {
                buildStatus->inSyncList = -1;
            }
            continue;
        }
        if (status[i].pengding_command == MSG_CM_AGENT_BUILD) {
            write_runlog(LOG, "instd(%u) CheckDnBuildStatus: instance(%u) is building.\n",
                GetInstanceIdInGroup(groupIdx, memIdx), GetInstanceIdInGroup(groupIdx, i));
            buildStatus->buildCount++;
        }
        if (dnReport[i].local_status.local_role == INSTANCE_ROLE_STANDBY) {
            buildStatus->standbyCount++;
        }
    }
}

int32 GetStaticPrimaryCount(uint32 groupIndex)
{
    int32 count = GetInstanceCountsInGroup(groupIndex);
    int32 staticPrimaryCount = 0;
    cm_instance_role_status *roleGroup = g_instance_role_group_ptr[groupIndex].instanceMember;
    for (int32 i = 0; i < count; ++i) {
        if (roleGroup[i].role == INSTANCE_ROLE_PRIMARY) {
            staticPrimaryCount++;
        }
    }
    return staticPrimaryCount;
}

cm_instance_command_status *GetCommand(uint32 groupIndex, int32 memberIndex)
{
    return &(g_instance_group_report_status_ptr[groupIndex].instance_status.command_member[memberIndex]);
}

cm_instance_report_status *GetReportStatus(uint32 groupIndex)
{
    return &(g_instance_group_report_status_ptr[groupIndex].instance_status);
}

cm_instance_datanode_report_status *GetLocalReportStatus(uint32 groupIndex, int32 memberIndex)
{
    return &(g_instance_group_report_status_ptr[groupIndex].instance_status.data_node_member[memberIndex]);
}

cm_instance_datanode_report_status *GetDnReportStatus(uint32 groupIndex)
{
    return (g_instance_group_report_status_ptr[groupIndex].instance_status.data_node_member);
}

cm_instance_role_status *GetRoleStatus(uint32 groupIndex, int32 memberIndex)
{
    return &(g_instance_role_group_ptr[groupIndex].instanceMember[memberIndex]);
}

void InitDnArbitInfo(DnArbitInfo *info)
{
    info->maxTerm = 0;
    info->switchoverIdx = -1;
    info->staRoleIndex = -1;
}

void UpdateGlobalTermByMaxTerm(uint32 maxTerm)
{
    (void)pthread_rwlock_wrlock(&term_update_rwlock);
    uint32 currentTerm = g_dynamic_header->term;
    if (maxTerm > currentTerm) {
        currentTerm = maxTerm + CM_INCREMENT_TERM_VALUE;
        write_runlog(LOG, "global term %u is smaller than instance maxterm %u, update global term to %u\n",
            g_dynamic_header->term, maxTerm, currentTerm);
        g_dynamic_header->term = currentTerm;
        (void)SetTermToDdb(currentTerm);
    }
    (void)pthread_rwlock_unlock(&term_update_rwlock);
}

void GetDnArbitInfo(uint32 groupIdx, DnArbitInfo *info)
{
    int32 count = GetInstanceCountsInGroup(groupIdx);
    cm_instance_datanode_report_status *dnReport = GetDnReportStatus(groupIdx);
    cm_instance_role_status *role = g_instance_role_group_ptr[groupIdx].instanceMember;
    cm_instance_command_status *cmd = g_instance_group_report_status_ptr[groupIdx].instance_status.command_member;
    for (int32 i = 0; i < count; ++i) {
        if (dnReport[i].local_status.term > info->maxTerm) {
            info->maxTerm = dnReport[i].local_status.term;
        }
        if (role[i].role == INSTANCE_ROLE_PRIMARY) {
            info->staRoleIndex = i;
        }
        if (cmd[i].pengding_command == (int32)MSG_CM_AGENT_SWITCHOVER) {
            info->switchoverIdx = i;
        }
    }
    /* term may increment without cm, the global term needs to be synchronized */
    UpdateGlobalTermByMaxTerm(info->maxTerm);
}

uint32 GetInstanceTerm(uint32 groupIndex, int memberIndex)
{
    return g_instance_group_report_status_ptr[groupIndex]
        .instance_status.data_node_member[memberIndex]
        .local_status.term;
}

bool IsFinishReduceSyncList(uint32 groupIdx, int32 memIdx, const char *str)
{
    bool res = CompareCurWithExceptSyncList(groupIdx);
    if (res) {
        return true;
    }
    PrintSyncListMsg(groupIdx, memIdx, str);
    return false;
}

void GetCandiInfoBackup(DnArbCtx *ctx, int32 memIdx)
{
    cm_local_replconninfo *localRepl = &(ctx->dnReport[memIdx].local_status);
    ctx->cond.vaildCount++;
    if (ctx->cond.maxMemArbiTime < ctx->dnReport[memIdx].arbiTime) {
        ctx->cond.maxMemArbiTime = ctx->dnReport[memIdx].arbiTime;
    }
    if (localRepl->local_role != INSTANCE_ROLE_UNKNOWN) {
        ctx->cond.onlineCount++;
    }

    if (localRepl->local_role == INSTANCE_ROLE_PRIMARY) {
        ctx->cond.hasDynamicPrimary = true;
        ctx->cond.dyPrimIdx = memIdx;
        if (localRepl->db_state == INSTANCE_HA_STATE_NORMAL) {
            ctx->cond.dyPrimNormalIdx = memIdx;
        }
        if (ctx->roleGroup->instanceMember[memIdx].role == INSTANCE_ROLE_PRIMARY) {
            ctx->cond.isPrimaryValid = true;
            ctx->cond.vaildPrimIdx = memIdx;
            if (localRepl->db_state == INSTANCE_HA_STATE_DEMOTING) {
                ctx->cond.isPrimDemoting = true;
            }
        } else {
            ctx->cond.igPrimaryCount++;
            ctx->cond.igPrimaryIdx = memIdx;
        }
        (void)clock_gettime(CLOCK_MONOTONIC, &ctx->repGroup->finishredo_time);
    }
    if (ctx->roleGroup->instanceMember[memIdx].role == INSTANCE_ROLE_PRIMARY) {
        ctx->cond.staticPriIdx = memIdx;
    }
    if (ctx->dyPrim.count == 0 && ctx->dnReport[memIdx].sendFailoverTimes >= MAX_SEND_FAILOVER_TIMES) {
        return;
    }
    if (XLByteWE_W_TERM(localRepl->term, localRepl->last_flush_lsn, ctx->cond.maxTerm, ctx->cond.maxLsn)) {
        ctx->cond.maxTerm = localRepl->term;
        ctx->cond.maxLsn = localRepl->last_flush_lsn;
    }
    if (localRepl->local_role == INSTANCE_ROLE_STANDBY) {
        if (XLByteWE_W_TERM(localRepl->term, localRepl->last_flush_lsn,
            ctx->cond.standbyMaxTerm, ctx->cond.standbyMaxLsn)) {
            ctx->cond.standbyMaxTerm = localRepl->term;
            ctx->cond.standbyMaxLsn = localRepl->last_flush_lsn;
        }
    }
}

bool CanbeCandicateBackup(const DnArbCtx *ctx, int32 memIdx, const CandicateCond *cadiCond)
{
    /* memIdx index is valid */
    if (memIdx == INVALID_INDEX) {
        return false;
    }
    /* Failover condition */
    if (cadiCond->mode == COS4FAILOVER) {
        /* memIdx failover times archive the most */
        if (ctx->dnReport[memIdx].sendFailoverTimes >= MAX_SEND_FAILOVER_TIMES) {
            return false;
        }
        /* memIdx is standby */
        if (ctx->dnReport[memIdx].local_status.local_role != INSTANCE_ROLE_STANDBY) {
            return false;
        }
    }
    uint32 localTerm = ctx->dnReport[memIdx].local_status.term;
    XLogRecPtr localLsn = ctx->dnReport[memIdx].local_status.last_flush_lsn;
    /* term and lsn is the most */
    if (!XLByteEQ_W_TERM(ctx->cond.standbyMaxTerm, ctx->cond.standbyMaxLsn, localTerm, localLsn)) {
        return false;
    }
    return true;
}

void ChooseCandicateIdxFromOtherBackup(DnArbCtx *ctx, const CandicateCond *cadiCond)
{
    /* the static primary may be the best choice */
    if (ctx->cond.candiIdx != INVALID_INDEX) {
        return;
    }
    int32 candiIdx = INVALID_INDEX;
    for (int32 i = 0; i < ctx->roleGroup->count; ++i) {
        if (!CanbeCandicateBackup(ctx, i, cadiCond)) {
            continue;
        }
        /* the smaller instanceId is the prefer choice */
        if (candiIdx == INVALID_INDEX) {
            candiIdx = i;
            break;
        }
    }
    ctx->cond.candiIdx = candiIdx;
}

void GetCandicateIdxBackup(DnArbCtx *ctx, const CandicateCond *cadiCond)
{
    ctx->cond.candiIdx = -1;
    const char *str = "[GetCandicate]";
    if (cadiCond->mode == COS4FAILOVER && ctx->cond.dyPrimNormalIdx != INVALID_INDEX &&
        ctx->cond.vaildPrimIdx != INVALID_INDEX) {
        write_runlog(DEBUG1, "%s, instanceId(%u), this group has dynamic primary(%d), validPrimIdx is %d, "
            "not need to choose candicate.\n", str, ctx->instId, ctx->cond.dyPrimNormalIdx, ctx->cond.vaildPrimIdx);
        return;
    }
    /* max term and lsn is valid */
    if (!IsTermLsnValid(ctx->cond.standbyMaxTerm, ctx->cond.standbyMaxLsn)) {
        write_runlog(LOG, "%s, instanceId(%u) standbyMaxTerm or standbyMaxLsn is invalid.\n", str, ctx->instId);
        return;
    }
    ChooseMostAvailableSyncOnTobaCandicate(ctx, cadiCond);
    if (ctx->cond.candiIdx != INVALID_INDEX) {
        return;
    }
    /* static primary is the first choice */
    if (CanbeCandicateBackup(ctx, ctx->cond.staticPriIdx, cadiCond)) {
        ctx->cond.candiIdx = ctx->cond.staticPriIdx;
        return;
    }
    /* static primary cannot be candicate */
    ChooseCandicateIdxFromOtherBackup(ctx, cadiCond);
}

void GetInstanceInfoStr(const StatusInstances *insInfo, char *logStr, size_t maxLen)
{
    if (maxLen == 0) {
        write_runlog(ERROR, "[GetInstanceInfoStr] maxLen is 0.\n");
        return;
    }
    errno_t rc = 0;
    if (insInfo->count == 0) {
        rc = strcpy_s(logStr, maxLen, "insInfo is empty");
        securec_check_errno(rc, (void)rc);
        return;
    }
    size_t strLen = 0;
    int32 idx = 0;
    for (; idx < insInfo->count; ++idx) {
        strLen = strlen(logStr);
        if (strLen >= (maxLen - 1)) {
            return;
        }
        if (idx != insInfo->count - 1) {
            rc = snprintf_s(logStr + strLen, maxLen - strLen, (maxLen - 1) - strLen, "%d: %u: %u, ",
                insInfo->itStatus[idx].memIdx, insInfo->itStatus[idx].instId, insInfo->itStatus[idx].term);
        } else {
            rc = snprintf_s(logStr + strLen, maxLen - strLen, (maxLen - 1) - strLen, "%d: %u: %u",
                insInfo->itStatus[idx].memIdx, insInfo->itStatus[idx].instId, insInfo->itStatus[idx].term);
        }
        securec_check_intval(rc, (void)rc);
    }
}

void GetSyncListStr(const cm_instance_report_status *repGroup, DnInstInfo *instInfo)
{
    /* covert the sync list to String. */
    GetSyncListString(&(repGroup->currentSyncList), instInfo->curSl, MAX_PATH_LEN);
    GetSyncListString(&(repGroup->exceptSyncList), instInfo->expSl, MAX_PATH_LEN);
    GetDnStatusString(&(repGroup->voteAzInstance), instInfo->voteL, MAX_PATH_LEN);
}

void GetDnIntanceInfo(const DnArbCtx *ctx, DnInstInfo *instInfo)
{
    GetSyncListStr(ctx->repGroup, instInfo);
    GetInstanceInfoStr(&(ctx->staCasCade), instInfo->stCasL, MAX_PATH_LEN);
    GetInstanceInfoStr(&(ctx->dyCascade), instInfo->dyCasL, MAX_PATH_LEN);
}

static int32 FindDnPeerIndex(const DnArbCtx *ctx)
{
    int32 staPrimIdx = -1;
    int32 dynaPrimIdx = -1;
    int32 promoteIdx = -1;
    int32 demoteIdx = -1;
    cm_instance_role_status *role = ctx->roleGroup->instanceMember;
    cm_instance_datanode_report_status *report = ctx->repGroup->data_node_member;
    for (int32 i = 0; i < ctx->roleGroup->count; ++i) {
        if (i == ctx->memIdx) {
            continue;
        }
        if (role[i].role == INSTANCE_ROLE_PRIMARY) {
            staPrimIdx = i;
        }
        if (report[i].local_status.local_role == INSTANCE_ROLE_PRIMARY) {
            dynaPrimIdx = i;
        }
        if (report[i].local_status.db_state == INSTANCE_HA_STATE_PROMOTING) {
            promoteIdx = i;
        }
        if (report[i].local_status.db_state == INSTANCE_HA_STATE_DEMOTING) {
            demoteIdx = i;
        }
    }

    if (dynaPrimIdx != -1) {
        return dynaPrimIdx;
    }

    if (staPrimIdx != -1) {
        return staPrimIdx;
    }

    if (promoteIdx != -1) {
        return promoteIdx;
    }

    if (demoteIdx != -1) {
        return demoteIdx;
    }

    return (ctx->memIdx + 1) % ctx->roleGroup->count;
}

void PrintCurAndPeerDnInfo(const DnArbCtx *ctx, const char *str)
{
    if (IsCurrentNodeDorado(ctx->node)) {
        write_runlog(DEBUG5, "node %u is dorado, not need print cur and peer dn info.\n", ctx->node);
        return;
    }
    int32 peerIdx = FindDnPeerIndex(ctx);
    if (peerIdx == -1) {
        peerIdx = 0;
    }
    const uint32 xlogOffset = 32;
    int32 memIdx = ctx->memIdx;
    cm_instance_role_status *role = ctx->roleGroup->instanceMember;
    cm_instance_datanode_report_status *dnRep = ctx->repGroup->data_node_member;
    cm_local_replconninfo *curInfo = &(dnRep[ctx->memIdx].local_status);
    cm_local_replconninfo *peerInfo = &(dnRep[peerIdx].local_status);
    cm_instance_arbitrate_status *dnArbi = ctx->repGroup->arbitrate_status_member;
    DnInstInfo instInfo = {{0}};
    GetSyncListStr(ctx->repGroup, &instInfo);
    write_runlog(LOG, "%s, current report instance is %u, node %u, "
        "instId[%u: %u], node[%u: %u], staticRole[%d=%s: %d=%s], dynamicRole[%d=%s: %d=%s], "
        "term[%u: %u], lsn[%X/%X: %X/%X], dbState[%d=%s: %d=%s], buildReason[%d=%s: %d=%s], doubleRestarting[%d: %d], "
        "disconn_mode[%u=%s: %u=%s], disconn[%s:%u, %s:%u], local[%s:%u, %s:%u], redoFinished[%d: %d], "
        "arbiTime[%u: %u], syncList[cur: (%s), exp: (%s), vote: (%s)], groupTerm[%u], sync_standby_mode[%d: %d: %d], "
        "sendFailoverTimes[%u: %u].\n",
        str, role[memIdx].instanceId, role[memIdx].node, role[memIdx].instanceId, role[peerIdx].instanceId,
        role[memIdx].node, role[peerIdx].node, role[memIdx].role, datanode_role_int_to_string(role[memIdx].role),
        role[peerIdx].role, datanode_role_int_to_string(role[peerIdx].role), curInfo->local_role,
        datanode_role_int_to_string(curInfo->local_role), peerInfo->local_role,
        datanode_role_int_to_string(peerInfo->local_role), curInfo->term, peerInfo->term,
        (uint32)(curInfo->last_flush_lsn >> xlogOffset), (uint32)curInfo->last_flush_lsn,
        (uint32)(peerInfo->last_flush_lsn >> xlogOffset), (uint32)peerInfo->last_flush_lsn,
        curInfo->db_state, datanode_dbstate_int_to_string(curInfo->db_state),
        peerInfo->db_state, datanode_dbstate_int_to_string(peerInfo->db_state),
        curInfo->buildReason, datanode_rebuild_reason_int_to_string(curInfo->buildReason),
        peerInfo->buildReason, datanode_rebuild_reason_int_to_string(peerInfo->buildReason), dnArbi[memIdx].restarting,
        dnArbi[peerIdx].restarting, curInfo->disconn_mode, DatanodeLockmodeIntToString(curInfo->disconn_mode),
        peerInfo->disconn_mode, DatanodeLockmodeIntToString(peerInfo->disconn_mode),
        curInfo->disconn_host, curInfo->disconn_port, peerInfo->disconn_host, peerInfo->disconn_port,
        curInfo->local_host, curInfo->local_port, peerInfo->local_host, peerInfo->local_port,
        curInfo->redo_finished, peerInfo->redo_finished, dnRep[memIdx].arbiTime, dnRep[peerIdx].arbiTime,
        instInfo.curSl, instInfo.expSl, instInfo.voteL, ctx->repGroup->term, dnRep[memIdx].sync_standby_mode,
        (int)dnRep[peerIdx].sync_standby_mode, (int)current_cluster_az_status,
        dnRep[memIdx].sendFailoverTimes, dnRep[peerIdx].sendFailoverTimes);
}

uint32 GetDnArbitateDelayTime(const DnArbCtx *ctx)
{
    const ArbiCond *cond = &(ctx->cond);
    if (!g_clusterStarting || !CheckGroupAndMemIndex(ctx->groupIdx, cond->staticPriIdx, "[GetDnArbitateDelayTime]") ||
        ctx->staPrim.count != 1) {
        return cond->arbitInterval;
    }
    /* if static primary has finished redo, not need to wait for 180s */
    cm_local_replconninfo *status = &(ctx->dnReport[cond->staticPriIdx].local_status);
    if (status->local_role == INSTANCE_ROLE_STANDBY && status->disconn_mode == PROHIBIT_CONNECTION) {
        return g_waitStaticPrimaryTimes;
    }
    return cond->arbitInterval;
}

int32 GetMemIdxByInstanceId(uint32 groupIdx, uint32 instId)
{
    if (instId == 0) {
        return -1;
    }
    cm_instance_role_status *role = g_instance_role_group_ptr[groupIdx].instanceMember;
    for (int32 i = 0; i < g_instance_role_group_ptr[groupIdx].count; ++i) {
        if (role[i].instanceId == instId) {
            return i;
        }
    }
    return -1;
}

static void ChangeStaticRoleAndNotifyCn(uint32 groupIdx, int32 memIdx)
{
    ChangeDnPrimaryMemberIndex(groupIdx, memIdx);
    /* to deal switchover fail, but notify cn success */
    cm_pending_notify_broadcast_msg(groupIdx, GetInstanceIdInGroup(groupIdx, memIdx));
}

static void DnWillChangeStaticRole(const DnArbCtx *ctx, const char *str)
{
    int32 cmdPur = ctx->localCom->cmdPur;
    int32 cmdSour = ctx->localCom->cmdSour;
    write_runlog(LOG, "%s: instd(%u) static role is (%d: %s) cmdPur is (%d: %s), cmdSour is (%d: %s).\n",
        str, ctx->instId, ctx->localRole->role, datanode_role_int_to_string(ctx->localRole->role),
        cmdPur, datanode_role_int_to_string(cmdPur), cmdSour, datanode_role_int_to_string(cmdSour));
    if (ctx->localRole->role != cmdSour) {
        return;
    }
    if (cmdPur == INSTANCE_ROLE_PRIMARY || cmdPur == INSTANCE_ROLE_MAIN_STANDBY) {
        ChangeStaticRoleAndNotifyCn(ctx->groupIdx, ctx->memIdx);
    } else {
        ChangeDnMemberIndex(str, ctx->groupIdx, ctx->memIdx, cmdPur, cmdSour);
    }
}

static void ClearSwitchoverCmd(const DnArbCtx *ctx)
{
    cm_instance_command_status *cmd = ctx->localCom;
    int32 timeOut = cmd->time_out;
    int32 cmdRealPur = cmd->cmdRealPur;
    CleanCommand(ctx->groupIdx, ctx->memIdx);
    if (cmdRealPur != INSTANCE_ROLE_INIT) {
        SetSwitchoverPendingCmd(ctx->groupIdx, ctx->memIdx, timeOut, "[CleanSwitchoverCmd]", true);
    }
}

status_t CheckSwitchOverDone(const DnArbCtx *ctx, int32 peerIdx)
{
    if (peerIdx == -1) {
        return CM_ERROR;
    }
    cm_instance_command_status *instCmd = ctx->localCom;
    int32 cmdPur = instCmd->cmdPur;
    cm_local_replconninfo *dnStatus = &(ctx->dnReport[peerIdx].local_status);
    cm_local_replconninfo *localSt = &(ctx->localRep->local_status);
    if (localSt->local_role != cmdPur) {
        return CM_ERROR;
    }
    if ((instCmd->command_status == INSTANCE_COMMAND_WAIT_EXEC_ACK) &&
        (instCmd->pengding_command == (int32)MSG_CM_AGENT_SWITCHOVER)) {
        if (localSt->db_state == INSTANCE_HA_STATE_NORMAL) {
            DnWillChangeStaticRole(ctx, "[CheckSwitchOverDone]");
            if (dnStatus->local_role != cmdPur && dnStatus->local_role != INSTANCE_ROLE_UNKNOWN) {
                ClearSwitchoverCmd(ctx);
            }
            return CM_SUCCESS;
        }
    }
    return CM_ERROR;
}

static bool IsCleanSwitchover(const DnArbCtx *ctx)
{
    int32 count = GetInstanceCountsInGroup(ctx->groupIdx);
    for (int32 i = 0; i < count; ++i) {
        /* switchover instance may restart, clean flag */
        if (ctx->dnReport[i].local_status.local_role == INSTANCE_ROLE_PENDING) {
            if (g_instance_role_group_ptr[ctx->groupIdx].instanceMember[i].role == INSTANCE_ROLE_PRIMARY) {
                write_runlog(LOG, "[CleanSwitchover] instance(%u) static primary is pending.\n",
                    GetInstanceIdInGroup(ctx->groupIdx, i));
                return true;
            }

            if (ctx->repGroup->command_member[i].pengding_command == (int32)MSG_CM_AGENT_SWITCHOVER) {
                write_runlog(LOG, "[CleanSwitchover] instance(%u) is pending, may be restart.\n",
                    GetInstanceIdInGroup(ctx->groupIdx, i));
                return true;
            }
        }

        if (ctx->repGroup->command_member[i].pengding_command == (int32)MSG_CM_AGENT_SWITCHOVER &&
            !IsArchiveMaxSendTimes(ctx->groupIdx, i)) {
            write_runlog(LOG, "[CleanSwitchover] instance(%u) send switchover times has archived the most(%d).\n",
                GetInstanceIdInGroup(ctx->groupIdx, i), GetSendTimes(ctx->groupIdx, i, true));
            return true;
        }
    }
    return false;
}

static void CleanSwitchoverCommand(const DnArbCtx *ctx)
{
    int32 count = GetInstanceCountsInGroup(ctx->groupIdx);
    for (int32 i = 0; i < count; ++i) {
        if (ctx->repGroup->command_member[i].pengding_command != (int32)MSG_CM_AGENT_SWITCHOVER) {
            continue;
        }
        write_runlog(LOG, "[CleanSwitchover] clean switchover(%u) command, command send num(%d/%d).\n",
            GetInstanceIdInGroup(ctx->groupIdx, i), GetSendTimes(ctx->groupIdx, i, false),
            GetSendTimes(ctx->groupIdx, i, true));
        CleanCommand(ctx->groupIdx, i);
    }
}

void CleanSwitchoverInfo(const DnArbCtx *ctx)
{
    int32 localRole = ctx->localRep->local_status.local_role;
    int32 cmdPur = ctx->localCom->cmdPur;
    int32 peerIdx = GetMemIdxByInstanceId(ctx->groupIdx, ctx->localCom->peerInstId);
    status_t resStatus = CheckSwitchOverDone(ctx, peerIdx);
    if (resStatus == CM_SUCCESS) {
        return;
    }
    uint32 localTerm = ctx->info.term;
    if (ctx->localCom->pengding_command == (int32)MSG_CM_AGENT_SWITCHOVER && localRole == cmdPur &&
        ctx->maxTerm == localTerm && ctx->repGroup->term <= localTerm && peerIdx != -1) {
        int32 peerRole = ctx->dnReport[peerIdx].local_status.local_role;
        if (peerRole != cmdPur && peerRole != INSTANCE_ROLE_UNKNOWN) {
            /* update the static configure state */
            write_runlog(LOG, "[cleanSwitchover] line %d: instanceId(%u) is doing switchover, "
                "do change static primary.\n", __LINE__, ctx->instId);
            GroupStatusShow("[cleanSwitchover]", ctx->groupIdx, ctx->instId, -1, false);
            DnWillChangeStaticRole(ctx, "[cleanSwitchover]");
            ClearSwitchoverCmd(ctx);
        }
    }
    /* overtime and clean command */
    bool needCleanSwitchover = IsCleanSwitchover(ctx);
    if (needCleanSwitchover) {
        CleanSwitchoverCommand(ctx);
    }
}

static uint32 GetNormalPrimaryCnt(uint32 groupIdx)
{
    uint32 cnt = 0;

    cm_instance_datanode_report_status *dnReport =
        g_instance_group_report_status_ptr[groupIdx].instance_status.data_node_member;
    for (int32 i = 0; i < g_instance_role_group_ptr[groupIdx].count; ++i) {
        if (dnReport[i].local_status.local_role == INSTANCE_ROLE_PRIMARY &&
            dnReport[i].local_status.db_state == INSTANCE_HA_STATE_NORMAL) {
            ++cnt;
        }
    }
    return cnt;
}

void ChangeStaticPrimaryByDynamicPrimary(const DnArbCtx *ctx)
{
    if (ctx->localRep->local_status.local_role != INSTANCE_ROLE_PRIMARY) {
        return;
    }
    if (ctx->localRep->local_status.db_state == INSTANCE_HA_STATE_NORMAL) {
        if (ctx->localRole->role != INSTANCE_ROLE_PRIMARY) {
            uint32 cnt = GetNormalPrimaryCnt(ctx->groupIdx);
            if (cnt != 1) {
                write_runlog(
                    DEBUG1, "instId(%u) cannot change static role, because norPrimaryCnt is %u.\n", ctx->instId, cnt);
                return;
            }
            write_runlog(LOG, "instId(%u) will change static role.\n", ctx->instId);
            const char *str = "[ChangeStaticPrimaryByDynamicPrimary]";
            GroupStatusShow(str, ctx->groupIdx, ctx->instId, -1, false);
            ChangeStaticRoleAndNotifyCn(ctx->groupIdx, ctx->memIdx);
        }
    }
}
