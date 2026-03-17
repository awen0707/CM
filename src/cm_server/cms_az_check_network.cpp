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
 * cms_az_check_network.cpp
 *    AZ net check main
 *
 * IDENTIFICATION
 *    src/cm_server/cms_az_check_network.cpp
 *
 * -------------------------------------------------------------------------
 */

#include "cm/cm_elog.h"
#include "cms_global_params.h"
#include "cms_ddb.h"
#include "cms_az.h"
#include "cms_process_messages.h"
#include "cms_common.h"

static void GetLeafAzName(ConnCheck *leaf1Az, ConnCheck *curAz)
{
    errno_t rc = 0;
    for (int32 i = 0; i < AZ_MEMBER_MAX_COUNT; ++i) {
        write_runlog(LOG, "azName(%s), dnCount is %u, azPriority is %u.\n",
            g_cmAzInfo[i].azName, g_cmAzInfo[i].dnCount, g_cmAzInfo[i].azPriority);
        if (g_cmAzInfo[i].dnCount == 0) {
            continue;
        }
        if (strcmp(g_cmAzInfo[i].azName, g_currentNode->azName) == 0) {
            rc = memcpy_s(curAz->azName, CM_AZ_NAME, g_cmAzInfo[i].azName, CM_AZ_NAME);
            securec_check_errno(rc, (void)rc);
            curAz->azPriority = g_cmAzInfo[i].azPriority;
            write_runlog(LOG, "curAz azname(%s), azPriority is %u.\n", curAz->azName, curAz->azPriority);
            continue;
        }
        rc = memcpy_s(leaf1Az->azName, CM_AZ_NAME, g_cmAzInfo[i].azName, CM_AZ_NAME);
        securec_check_errno(rc, (void)rc);
        leaf1Az->azPriority = g_cmAzInfo[i].azPriority;
        write_runlog(LOG, "leaf1Az azname(%s), azPriority is %u.\n", leaf1Az->azName, leaf1Az->azPriority);
    }
}

static bool GetAzRoleByAzPriority(uint32 azPriority, AZRole *azRole)
{
    if (azPriority >= g_az_master && azPriority < g_az_slave) {
        *azRole = AZMaster;
        return true;
    } else if (azPriority >= g_az_slave && azPriority < g_az_arbiter) {
        *azRole = AZSlave;
        return true;
    } else if (azPriority >= g_az_arbiter) {
        *azRole = AZArbiter;
        return true;
    }
    return false;
}

static bool GetLeafAzRole(ConnCheck *leaf1Az, ConnCheck *curAz)
{
    bool res = GetAzRoleByAzPriority(leaf1Az->azPriority, &(leaf1Az->azRole));
    if (!res) {
        write_runlog(
            ERROR, "leaf1Az az(%s) can not get azRole by azPriority(%u).\n", leaf1Az->azName, leaf1Az->azPriority);
        return false;
    }

    res = GetAzRoleByAzPriority(curAz->azPriority, &(curAz->azRole));
    if (!res) {
        write_runlog(ERROR, "curAz az(%s) can not get azRole by azPriority(%u).\n", curAz->azName, curAz->azPriority);
        return false;
    }
    return true;
}

static bool CheckLeafAzName(const ConnCheck *leaf1Az, const ConnCheck *leaf2Az, const ConnCheck *curAz)
{
    if ((strlen(leaf1Az->azName) == 0) || (leaf1Az->azPriority == 0)) {
        write_runlog(
            ERROR, "leaf1Az az name(%s) or azPriority(%u) is invalid.\n", leaf1Az->azName, leaf1Az->azPriority);
        return false;
    }
    if ((strlen(leaf2Az->azName) == 0) || (leaf2Az->azPriority == 0)) {
        write_runlog(
            ERROR, "leaf2Az az name(%s) or azPriority(%u) is invalid.\n", leaf2Az->azName, leaf2Az->azPriority);
        return false;
    }
    if ((strlen(curAz->azName) == 0) || (curAz->azPriority == 0)) {
        write_runlog(ERROR, "curAz az name(%s) or azPriority(%u) is invalid.\n", curAz->azName, curAz->azPriority);
        return false;
    }
    return true;
}

static bool InitConnCheck(ConnCheck *leaf1Az, ConnCheck *leaf2Az, ConnCheck *curAz, int32 nodeIdx)
{
    GetLeafAzName(leaf1Az, curAz);
    errno_t rc = memcpy_s(leaf2Az->azName, CM_AZ_NAME, g_node[nodeIdx].azName, CM_AZ_NAME);
    securec_check_errno(rc, (void)rc);
    leaf2Az->azPriority = g_node[nodeIdx].azPriority;
    leaf2Az->azRole = AZArbiter;
    bool res = CheckLeafAzName(leaf1Az, leaf2Az, curAz);
    if (!res) {
        return false;
    }
    res = GetLeafAzRole(leaf1Az, curAz);
    if (!res) {
        return false;
    }
    write_runlog(LOG, "leaf1Az(%s %u:%d), curAz(%s %u:%d), leaf2Az(%s %u:%d).\n",
        leaf1Az->azName, leaf1Az->azPriority, leaf1Az->azRole, curAz->azName, curAz->azPriority, curAz->azRole,
        leaf2Az->azName, leaf2Az->azPriority, leaf2Az->azRole);
    return true;
}

static AzPingCheckRes AzAndInnerConnectCheck(ConnCheck *leaf1Az, ConnCheck *leaf2Az, ConnCheck *curAz,
    int32 *checkTimes)
{
    const int32 checkConnMax = 5;
    bool leaf1AzConnectOK = AzPingCheck(&(leaf1Az->curConn), leaf1Az->azName);
    bool curAZConnectOK = AzPingCheck(&(curAz->curConn), curAz->azName);
    bool leaf2AzConnectOK = AzPingCheck(&(leaf2Az->curConn), leaf2Az->azName);
    if ((!leaf1Az->curConn) || (!curAz->curConn) || (!leaf2Az->curConn)) {
        write_runlog(LOG, "The AZ Conn Status %s:%d, %s:%d, %s:%d Changed this time  %d, try next time.\n",
            leaf1Az->azName, leaf1Az->curConn, curAz->azName, curAz->curConn, leaf2Az->azName, leaf2Az->lastConn,
            *checkTimes);
    }
    if ((!leaf1AzConnectOK) || (!curAZConnectOK) || (!leaf2AzConnectOK)) {
        *checkTimes = 0;
        return WAIT_NEXT_TIME;
    } else {
        if (((++(*checkTimes)) % checkConnMax) != 0) {
            return WAIT_NEXT_TIME;
        } else {
            *checkTimes = 0;
        }
    }
    if ((leaf1Az->curConn != leaf1Az->lastConn) || (curAz->curConn != curAz->lastConn) ||
        (leaf2Az->curConn != leaf2Az->lastConn) || (g_dbConn.modId == MOD_ALL)) {
        write_runlog(LOG,
            "leaf1Az(%s %d: %d), curAz(%s %d: %d), leaf2Az(%s %d: %d), will open "
            "new ddb Connect.\n",
            leaf1Az->azName, leaf1Az->lastConn, leaf1Az->curConn, curAz->azName, curAz->lastConn, curAz->curConn,
            leaf2Az->azName, leaf2Az->lastConn, leaf2Az->curConn);
        leaf1Az->lastConn = leaf1Az->curConn;
        curAz->lastConn = curAz->curConn;
        leaf2Az->lastConn = leaf2Az->curConn;
        CreateDdbConnSession(leaf1Az->lastConn, leaf2Az->lastConn, curAz->lastConn);
    }
    return CONTINUE_EXECTING;
}

void UnlinkStopFile(const int type)
{
    int rc = 0;
    char execPath[MAX_PATH_LEN] = {0};
    char stopFlagFile[MAX_PATH_LEN] = {0};
    struct stat statBuf = {0};
    if (GetHomePath(execPath, sizeof(execPath)) != 0) {
        return;
    }
    if (type == SINGLEAZ_TYPE) {
        rc = snprintf_s(stopFlagFile, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/%s", execPath, "az_node_instances_stop");
    } else if (type == SINGLENODE_TYPE) {
        rc = snprintf_s(stopFlagFile, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/%s", execPath, "node_instances_stop");
    }
    securec_check_intval(rc, (void)rc);
    if (stat(stopFlagFile, &statBuf) == 0) {
        if (unlink(stopFlagFile) != 0) {
            write_runlog(ERROR, "delete cms-node stop instances flag file: %s failed.\n", stopFlagFile);
        }
    }
}

static void DoStartCurNodeOrCurAz(const ConnCheck *curAz)
{
    if (curAz->curConn) {
        if (CheckStopFileExist(SINGLEAZ_TYPE)) {
            write_runlog(LOG, "check the single_az file, we should start current az.\n");
            StartOrStopAZ(START_AZ, curAz->azName);
            UnlinkStopFile(SINGLEAZ_TYPE);
        }
    }
    if (CheckStopFileExist(SINGLENODE_TYPE)) {
        write_runlog(LOG, "check the single_node file, We only need start current node(%u).\n", g_currentNode->node);
        StartOrStopNodeInstanceByCommand(START_AZ, g_currentNode->node);
        UnlinkStopFile(SINGLENODE_TYPE);
    }
}

static void CheckStopAzByArbitrate(const ConnCheck *leafAz, const ConnCheck *curAz, int32 nodeIdx)
{
    bool leafAzHasBeenStop = GetStopAzFlagFromDdb(leafAz->azRole);
    bool leafHealthState = doCheckAzStatus(g_node[nodeIdx].sshChannel[0], leafAz->azRole);
    if (leafHealthState && !leafAz->curConn) {
        if (SetStopAzFlagToDdb(leafAz->azRole, true)) {
            StopAZ(g_node[nodeIdx].sshChannel[0], leafAz->azRole);
            write_runlog(LOG, "%s and %s is disconnected, %s is available, stop %s.\n",
                leafAz->azName, curAz->azName, curAz->azName, leafAz->azName);
        } else {
            write_runlog(ERROR, "set stop %s key failed, can not stop %s.\n", leafAz->azName, leafAz->azName);
        }
    }
    if ((!leafHealthState) && (leafAz->curConn)) {
        if (leafAzHasBeenStop) {
            write_runlog(LOG, "%s and %s connection is ok, start %s now.\n", leafAz->azName,
                curAz->azName, leafAz->azName);
            if (SetStopAzFlagToDdb(leafAz->azRole, false)) {
                StartAZ(leafAz->azRole);
            } else {
                write_runlog(ERROR, "clear az1 stop flag failed, can not start %s.\n", leafAz->azName);
            }
        } else {
            write_runlog(LOG, "az1 may be stopped by user with cm_ctl stop -z.\n");
        }
    }
}

static void CheckStartAndStopInPrimary(
    const ConnCheck *leaf1Az, const ConnCheck *curAz, const ConnCheck *leaf2Az, int32 nodeIdx)
{
    DoStartCurNodeOrCurAz(curAz);

    if (!leaf2Az->curConn) {
        write_runlog(LOG, "%s and %s is disConnected, can not check and do stop %s.\n",
            leaf2Az->azName, curAz->azName, leaf1Az->azName);
        return;
    }

    CheckStopAzByArbitrate(leaf1Az, curAz, nodeIdx);
}

static void DoStopCurNodeOrCurAz(const ConnCheck *curAz)
{
    if (!curAz->curConn) {
        if (CheckStopFileExist(SINGLENODE_TYPE)) {
            return;
        }
        StartOrStopNodeInstanceByCommand(STOP_AZ, g_currentNode->node);
        if (CreateStopNodeInstancesFlagFile(SINGLENODE_TYPE) == -1) {
            write_runlog(ERROR, "Create stop cms node FlagFile failed.\n");
        }
        write_runlog(LOG, "The %s CMS is disconnected, and the ping result is %d.\n", curAz->azName, curAz->curConn);
    } else {
        if (CheckStopFileExist(SINGLEAZ_TYPE)) {
            return;
        }
        StartOrStopAZ(STOP_AZ, curAz->azName);
        if (CreateStopNodeInstancesFlagFile(SINGLEAZ_TYPE) == -1) {
            write_runlog(ERROR, "Create stop cms node FlagFile failed.\n");
        }
        write_runlog(LOG, "The current az(%s) is isolated and it is stopped.\n", curAz->azName);
    }
}

static void CheckStartAndStopInStandby(const ConnCheck *leaf1Az, const ConnCheck *leaf2Az, const ConnCheck *curAz)
{
    if (!leaf1Az->curConn && !leaf2Az->curConn) {
        DoStopCurNodeOrCurAz(curAz);
    }
    if (leaf1Az->curConn && leaf2Az->curConn) {
        DoStartCurNodeOrCurAz(curAz);
    }
}

void *BothAzConnectStateCheckMain(void *arg)
{
    if (GetAzDeploymentType(false) != TWO_AZ_DEPLOYMENT) {
        write_runlog(LOG, "BothAzConnectStateCheckMain exit.\n");
        return NULL;
    }

    int arbitNodeIdx = GetNodeIndexByAzRole(AZArbiter);
    if (arbitNodeIdx == -1) {
        write_runlog(ERROR, "can not get node in az3, BothAzConnectStateCheckMain exit.\n");
        return NULL;
    }
    thread_name = "BothAzCheck";
    uint32 cnt = g_loopState.count;
    g_loopState.count++;
    g_loopState.execStatus[cnt] = 1;
    write_runlog(LOG, "[reload] BothAzConnectStateCheckMain thread loop-index:%u.\n", cnt);

    ConnCheck leaf1Az = {0};
    ConnCheck leaf2Az = {0};
    ConnCheck curAz = {0};
    bool res = InitConnCheck(&leaf1Az, &leaf2Az, &curAz, arbitNodeIdx);
    if (!res) {
        write_runlog(ERROR, "can not InitConnCheck, BothAzConnectStateCheckMain exit.\n");
        return NULL;
    }
    int32 checkTimes = 0;
    AzPingCheckRes pingRes = CONTINUE_EXECTING;
    for (;;) {
        if (g_inReload) {
            cm_sleep(AZ_START_STOP_INTERVEL);
            continue;
        }
        g_loopState.execStatus[cnt] = 0;
        pingRes = AzAndInnerConnectCheck(&leaf1Az, &leaf2Az, &curAz, &checkTimes);
        if (pingRes == WAIT_NEXT_TIME) {
            g_loopState.execStatus[cnt] = 1;
            cm_sleep(AZ_START_STOP_INTERVEL);
            continue;
        }
        if (g_HA_status->local_role == CM_SERVER_PRIMARY) {
            CheckStartAndStopInPrimary(&leaf1Az, &curAz, &leaf2Az, arbitNodeIdx);
            g_loopState.execStatus[cnt] = 1;
            cm_sleep(AZ_START_STOP_INTERVEL);
            continue;
        }
        CheckStartAndStopInStandby(&leaf1Az, &leaf2Az, &curAz);
        g_loopState.execStatus[cnt] = 1;
        cm_sleep(AZ_START_STOP_INTERVEL);
    }
}
