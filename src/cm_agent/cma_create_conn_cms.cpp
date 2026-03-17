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
 * cma_create_conn_cms.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_agent/cma_create_conn_cms.cpp
 *
 * -------------------------------------------------------------------------
 */
#include "cma_global_params.h"
#include "cma_common.h"
#include "cma_connect.h"
#include "cma_create_conn_cms.h"

#define DISABLE_TIMEOUT 0

#define NOT_UPGRADED 0
#define GRAYSCALE_UPGRADED 1
#define INPLACE_UPGRADED 2

/**
 * This flag is activated after the cm agent is connected to the cm Server for the first time.
 * If this flag is not activated, we will disable some cm agent features.
 */
bool g_firstConnectFlag = false;
bool g_agentConnCmsSuccess = false;

int CreateStopNodeInstancesFlagFile(const char *stopFlagFile)
{
    char cmd[MAX_PATH_LEN] = {0};
    int ret = snprintf_s(cmd, MAX_PATH_LEN, MAX_PATH_LEN - 1, "touch %s;chmod 600 %s", stopFlagFile, stopFlagFile);
    securec_check_intval(ret, (void)ret);

    ret = system(cmd);
    if (ret != 0) {
        write_runlog(ERROR, "CreateStopNodeInstancesFlagFile failed:%s, errnum=%d, errno=%d.\n", cmd, ret, errno);
        return -1;
    }
    write_runlog(LOG, "CreateStopNodeInstancesFlagFile success: %s.\n", cmd);
    return 0;
}

void StartOrStopInstanceByCommand(OperateType operateType, uint32 nodeId, const char *instanceDataPath)
{
    errno_t rc = 0;
    char cmd[MAXPGPATH] = {0};

    if (operateType == INSTANCE_START) {
        rc = snprintf_s(cmd, MAXPGPATH, MAXPGPATH - 1,
            "cm_ctl start -n %u -D %s > /dev/null 2>&1 &", nodeId, instanceDataPath);
    } else if (operateType == INSTANCE_STOP) {
        rc = snprintf_s(cmd, MAXPGPATH, MAXPGPATH - 1,
            "cm_ctl stop -n %u -D %s -m i > /dev/null 2>&1 &", nodeId, instanceDataPath);
    } else {
        write_runlog(ERROR, "StartOrStopInstanceByCommand invaild operateType:%d\n", operateType);
        return;
    }
    securec_check_intval(rc, (void)rc);

    int ret = system(cmd);
    if (ret != 0) {
        write_runlog(ERROR, "StartOrStopInstanceByCommand failed:%s , errnum=%d, errno=%d.\n", cmd, ret, errno);
    }
    write_runlog(LOG, "StartOrStopInstanceByCommand success: %s.\n", cmd);
}

void StartOrStopNodeInstances(OperateType operateType)
{
    if (g_currentNode->coordinate == 1) {
        StartOrStopInstanceByCommand(operateType, g_currentNode->node, g_currentNode->DataPath);
    }

    for (uint32 ii = 0; ii < g_currentNode->datanodeCount; ii++) {
        StartOrStopInstanceByCommand(
            operateType, g_currentNode->node, g_currentNode->datanode[ii].datanodeLocalDataPath);
    }

    if (g_currentNode->gtm == 1) {
        StartOrStopInstanceByCommand(operateType, g_currentNode->node, g_currentNode->gtmLocalDataPath);
    }
}


/*
 *  This is a node-level judgment whether the connection is ok or disconnected.
 *  CmaDisconnectWithAllRemoteCms : Judging the connection of cm_agent with other node cm_server is ok or disconnected.
 *  If cm_agent connect cm_server regadless of cms standy or primary, the node will not commit suicide.
 *  So, return true and maintain the agent_kill_instance_timeout.
 *  Conversely, return false, and the node will commit suicide and set the agent_kill_instance_timeout to 30 seconds.
 */
static bool CmaDisconnectWithAllRemoteCms()
{
    write_runlog(DEBUG1, "cm_agent connect cm_server in other node: cmaConnectCmsInOtherNodeCount=%u.\n",
        g_cmaConnectCmsInOtherNodeCount);
    return (g_cmaConnectCmsInOtherNodeCount == 0) ? true : false;
}

/*
 *  This is a AZ-level judgment whether the connection is ok or disconnected.
 *  CmaDisconnectWithAllRemoteCmsInOtherAz:
 *      Judging the connection of cm_agent with other AZ cm_server is ok or disconnected.
 */
static bool CmaDisconnectWithAllRemoteCmsInOtherAz()
{
    /* We regard sigle AZ as node-level */
    bool isSingleAz = true;
    for (uint32 i = 0; i < g_node_num; i++) {
        if (strcmp(g_node[i].azName, g_currentNode->azName) != 0) {
            isSingleAz = false;
            break;
        }
    }
    if (isSingleAz) {
        write_runlog(DEBUG1, "CmaDisconnectWithAllRemoteCmsInOtherAz, isSingleAz=%d.\n", (int32)isSingleAz);
        return false;
    }

    write_runlog(DEBUG1, "cm_agent connect cm_server in other AZ, cmaConnectCmsInOtherAzCount=%u.\n",
        g_cmaConnectCmsInOtherAzCount);
    return (g_cmaConnectCmsInOtherAzCount == 0) ? true : false;
}

bool isUpgradeCluster()
{
    int rcs;
    struct stat stat_buf;
    char pg_host_path[MAX_PATH_LEN] = {0};
    char grayscale_upgrade_check[MAX_PATH_LEN] = {0};
    char upgrade_flag[MAX_PATH_LEN] = {0};

    rcs = cmagent_getenv("PGHOST", pg_host_path, sizeof(pg_host_path));
    if (rcs != EOK) {
        write_runlog(ERROR, "get PGHOST failed!\n");
        return false;
    }

    check_input_for_security(pg_host_path);
    rcs = snprintf_s(grayscale_upgrade_check, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/binary_upgrade", pg_host_path);
    securec_check_intval(rcs, (void)rcs);
    if (access(grayscale_upgrade_check, F_OK) == 0) {
        // inplace_upgrade
        rcs = snprintf_s(upgrade_flag, MAX_PATH_LEN, MAX_PATH_LEN - 1,
            "%s/inplace_upgrade_flag", grayscale_upgrade_check);
        securec_check_intval(rcs, (void)rcs);
        if (stat(upgrade_flag, &stat_buf) == 0) {
            return true;
        }
        // grayscale_upgrade
        rcs = snprintf_s(upgrade_flag, MAX_PATH_LEN, MAX_PATH_LEN - 1,
            "%s/upgrade_step.csv", grayscale_upgrade_check);
        securec_check_intval(rcs, (void)rcs);
        if (stat(upgrade_flag, &stat_buf) == 0) {
            return true;
        }
        // in upgrade which we don't care.
    }
    return false;
}

/**
 * @brief get cluster upgrade mode.
 * @return int NOT_UPGRADED/GRAYSCALE_UPGRADED/INPLACE_UPGRADED
 */
static int GetUpgradeMode()
{
    int rcs;
    struct stat statBufInPlace = {0};
    struct stat statBufGary = {0};
    char pgHostPath[MAX_PATH_LEN] = {0};
    char upgradeFolder[MAX_PATH_LEN] = {0};
    char inplaceUpgradeFlag[MAX_PATH_LEN] = {0};
    char grayScaleUpgradeFlag[MAX_PATH_LEN] = {0};

    rcs = cmagent_getenv("PGHOST", pgHostPath, sizeof(pgHostPath));
    if (rcs != EOK) {
        write_runlog(ERROR, "get PGHOST failed!\n");
        return NOT_UPGRADED;
    }
    check_input_for_security(pgHostPath);

    rcs = snprintf_s(upgradeFolder, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/binary_upgrade", pgHostPath);
    securec_check_intval(rcs, (void)rcs);
    if (access(upgradeFolder, F_OK) != 0) {
        write_runlog(LOG, "binary_upgrade: %s is not exist!\n", pgHostPath);
        return NOT_UPGRADED;
    }

    rcs = snprintf_s(inplaceUpgradeFlag, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/inplace_upgrade_flag", upgradeFolder);
    securec_check_intval(rcs, (void)rcs);
    if (stat(inplaceUpgradeFlag, &statBufInPlace) == 0) {
        return INPLACE_UPGRADED;
    }

    rcs = snprintf_s(grayScaleUpgradeFlag, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/upgrade_step.csv", upgradeFolder);
    securec_check_intval(rcs, (void)rcs);
    if (stat(grayScaleUpgradeFlag, &statBufGary) == 0) {
        return GRAYSCALE_UPGRADED;
    }

    return NOT_UPGRADED;
}

/**
 *  Check whether the instance in maintenance mode exists.
 *
 *  The maintenance instance flag file path.
 *  - true:     The maintenance instance flag file exists and the file contains content.
 *  - false:    The maintenance instance flag file does not exist or the file is empty.
 */
bool is_maintenance_instance(const char *file_path)
{
    char current[INSTANCE_ID_LEN] = { 0 };
    bool instance_maintenance = false;

    FILE *fd = fopen(file_path, "re");
    if (!fd) {
        write_runlog(DEBUG1, "Can't open the maintenance instance flag file: file_path=\"%s\","
            "errno=\"[%d]\".\n", file_path, errno);
        return instance_maintenance;
    }

    while (!feof(fd)) {
        if (fscanf_s(fd, "%s\n", current, INSTANCE_ID_LEN) < 0) {
            write_runlog(LOG, "Failed to get maintenance instance flag file content.\n");
            break;
        }

        if (strlen(current) != 0) {
            write_runlog(LOG, "Get maintenance instance flag file successfully: file_path=\"%s\","
                " instance_id=\"%s\".\n", file_path, current);
            instance_maintenance = true;
            break;
        }
    }

    (void)fclose(fd);
    return instance_maintenance;
}

maintenance_mode getMaintenanceMode()
{
    maintenance_mode mode = MAINTENANCE_MODE_NONE;
    if (isUpgradeCluster()) {
        mode = MAINTENANCE_MODE_UPGRADE;
    } else if (is_maintenance_instance(instance_maintance_path)) {
        mode = MAINTENANCE_MODE_DILATATION;
    }
    return mode;
}

static inline bool isDisableKillSelfInstances(const maintenance_mode &mode)
{
    return mode == MAINTENANCE_MODE_UPGRADE;
}

bool isMaintenanceModeDisableOperation(const cma_operation op)
{
    maintenance_mode mode = getMaintenanceMode();

    bool isDisable = false;
    if (op == CMA_KILL_SELF_INSTANCES) {
        return isDisableKillSelfInstances(mode);
    }

    return isDisable;
}

bool isDisconnectTimeout(const struct timespec last, int timeout)
{
    struct timespec now = {0, 0};
    (void)clock_gettime(CLOCK_MONOTONIC, &now);

    if (timeout == 0) {
        return false;
    } else {
        return (now.tv_sec - last.tv_sec) >= timeout;
    }
}

/**
 * @brief execute remote cmd function
 * @param  remoteNodeid     remoteNodeid in cluster
 * @param  cmd              command
 */
void ExecSsh(uint32 remoteNodeid, const char *cmd)
{
    int rc;
    char command[MAXPGPATH] = {0};
    uint32 ii;
    int ret;

    for (ii = 0; ii < g_node[remoteNodeid].sshCount; ii++) {
        ret = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1, "pssh %s -s -H %s '%s'", PSSH_TIMEOUT_OPTION,
            g_node[remoteNodeid].sshChannel[ii], cmd);
        securec_check_intval(ret, (void)ret);
        rc = system(command);
        if (rc == 0) {
            break;
        } else {
            write_runlog(ERROR,
                         "failed to execute the ssh command: nodeId=%u, command=\"%s\", systemReturn=%d,"
                         " commandReturn=%d, errno=%d\n",
                         g_node[remoteNodeid].node, command, rc, SHELL_RETURN_CODE(rc), errno);
            return;
        }
    }
}

/**
 * @brief check version between agent and cmserver primary, if version is not equal kill all instance
 */
static void StopNodeSelfByVersionNum()
{
    int rc;
    char upgradeVersionFile[MAX_PATH_LEN] = {0};
    char versonResultPath[MAX_PATH_LEN] = {0};
    char localVersion[MAX_PATH_LEN] = {0};
    char tmp[MAXPGPATH] = {0};
    char command[MAXPGPATH] = {0};
    char exec_path[MAX_PATH_LEN] = {0};
    const int versionLength = 6;

    if (GetHomePath(exec_path, sizeof(exec_path)) != 0) {
        return;
    }
    rc = snprintf_s(upgradeVersionFile, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/%s", exec_path, "upgrade_version");
    securec_check_intval(rc, (void)rc);
    canonicalize_path(upgradeVersionFile);
    rc = snprintf_s(versonResultPath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/%s-%u", exec_path, CHECK_VERSION_RESULT,
                    g_currentNode->node);
    securec_check_intval(rc, (void)rc);

    /* read local version number */
    FILE *fp = fopen(upgradeVersionFile, "re");
    if (fp == NULL) {
        write_runlog(ERROR, "failed to open File:%s\n", upgradeVersionFile);
        return;
    }
    (void)fgets(tmp, MAXPGPATH, fp);
    rc = memset_s(localVersion, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);

    /* get version number */
    (void)fgets(tmp, MAXPGPATH, fp);

    rc = strncpy_s(localVersion, MAX_PATH_LEN, tmp, versionLength);
    securec_check_errno(rc, (void)rc);
    check_input_for_security(localVersion);
    if (g_serverNodeId != g_currentNode->node) {
        rc = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1,
                        "args=$(sed -n '2p' %s); if [ $args = \"%s\" ]; then echo \"0\"; else touch %s; fi",
                        upgradeVersionFile, localVersion, versonResultPath);
        securec_check_intval(rc, (void)rc);
        ExecSsh(g_serverNodeId - 1, command);
        write_runlog(LOG, "try to touch file:%s, localVersion: %s, command: %s\n",
            CHECK_VERSION_RESULT, localVersion, command);
    }
    (void)fclose(fp);
}

uint64 GetTimeMinus(const struct timeval checkEnd, const struct timeval checkBegin)
{
    const int secTomicSec = 1000000;
    return (uint64)((checkEnd.tv_sec - checkBegin.tv_sec) * secTomicSec + (checkEnd.tv_usec - checkBegin.tv_usec));
}

void* ConnCmsPMain(void* arg)
{
    (void)clock_gettime(CLOCK_MONOTONIC, &g_serverHeartbeatTime);
    bool have_killed_nodes = false;
    bool isToStopInstances = false;
    struct timeval checkBeginFunction = {0, 0};
    struct timeval checkEndFunction = {0, 0};
    const int twoSec = 2;

    for (;;) {
        if (g_exitFlag || g_shutdownRequest) {
            write_runlog(LOG, "Get exit flag, ConnCmsPM thread will exit!\n");
            cm_sleep(5);
        }
        (void)gettimeofday(&checkBeginFunction, NULL);
        isToStopInstances = false;
        if (agent_cm_server_connect == NULL) {
            write_runlog(LOG, "%d cm_agent connect to cm_server start.\n", __LINE__);
            agent_cm_server_connect = GetConnToCmserver(0);
            if (agent_cm_server_connect != NULL) {
                /* When the cm agent starts not long ago, and have already connected to the cm server, set this flag. */
                g_firstConnectFlag = true;
                g_cmServerNeedReconnect = false;
                (void)clock_gettime(CLOCK_MONOTONIC, &g_serverHeartbeatTime);
                have_killed_nodes = false;
                g_agentConnCmsSuccess = true;
            } else {
                /* Firstly: We judge cma connect cms in other node is ok or disconnected.
                 * If the connection is disconnected, we need to execute the operation of stopping instances.
                 * If the connection is ok, we still need to judge the condition where cma connect cms
                 * in other AZ is ok or disconnected. And when the connection is disconnected, we also
                 * execute the operation of stopping instances.
                 * CmaDisconnectWithAllRemoteCms:
                 *     The cma in current node disconnect with all remote cms in other nodes.
                 * CmaDisconnectWithAllRemoteCmsInOtherAz:
                 *     The cma in current AZ disconnect with all remote cms in other AZ.
                 */
                if (CmaDisconnectWithAllRemoteCms()) {
                    isToStopInstances = true;
                } else if (CmaDisconnectWithAllRemoteCmsInOtherAz()) {
                    isToStopInstances = true;
                }

                /* agentStopInstanceDelayTime: The delay time of stopping instances.
                 * If isToStopInstances is true, and g_enableFenceDn is true,
                 * agentStopInstanceDelayTime is FENCE_TIMEOUT, 30 seconds.
                 * If isToStopInstances is true, and g_enableFenceDn is false,
                 * agentStopInstanceDelayTime is DISABLE_TIMEOUT, 0 seconds, never timeout.
                 * If isToStopInstances is false, agentStopInstanceDelayTime is agent_kill_instance_timeout,
                 * 0 second by default,
                 * and the operation of stopping instances will not be executed.
                 */
#ifndef ENABLE_MULTIPLE_NODES
                uint32 timeout = IsBoolCmParamTrue(g_enableFenceDn) ? FENCE_TIMEOUT : DISABLE_TIMEOUT;
                uint32 agentStopInstanceDelayTime = isToStopInstances ? timeout : agent_kill_instance_timeout;
#else
                uint32 agentStopInstanceDelayTime = isToStopInstances ? DISABLE_TIMEOUT : agent_kill_instance_timeout;
#endif
                if (isDisconnectTimeout(g_disconnectTime, (int)agentStopInstanceDelayTime) && !have_killed_nodes) {
                    if ((undocumentedVersion == 0) && isMaintenanceModeDisableOperation(CMA_KILL_SELF_INSTANCES)) {
                        have_killed_nodes = false;
                        write_runlog(LOG, "%d Maintaining cluster: cm agent cannot stop self instances.\n", __LINE__);
                    } else if (!g_firstConnectFlag) {
                        have_killed_nodes = false;
                        write_runlog(LOG, "Agent has never successfully connected to the server,"
                            " so can not stop instances of current node.\n");
                    } else {
                        write_runlog(LOG, "agent disconnect from cm_server %u seconds, stop instances in this node. "
                            "sync_dropped_coordinator change to false.\n", agentStopInstanceDelayTime);

                        if (g_isPauseArbitration) {
                            continue;
                        }

                        g_syncDroppedCoordinator = false;
                        have_killed_nodes = true;

                        #ifndef ENABLE_MULTIPLE_NODES
                        /*
                         * Kill datanode proccess, so that it can be restarted with pending mode.
                        */
                        uint32 i;
                        for (i = 0; i < g_currentNode->datanodeCount; i++) {
                            immediate_stop_one_instance(g_currentNode->datanode[i].datanodeLocalDataPath, INSTANCE_DN);
                        }
                        #endif
                    }
                }
            }
        }
        (void)gettimeofday(&checkEndFunction, NULL);
        if ((checkEndFunction.tv_sec - checkBeginFunction.tv_sec) > twoSec) {
            write_runlog(LOG, "[ConnCmsPMain] agent connect to server takes %llu.\n",
                (unsigned long long)GetTimeMinus(checkEndFunction, checkBeginFunction));
        }

        CmUsleep(AGENT_RECV_CYCLE);
    }
    return NULL;
}

void* CheckUpgradeMode(void* arg)
{
    for (;;) {
        /* When the cm agent connect primary cm server and cluster is not in Upgraded. */
        if (g_agentConnCmsSuccess && GetUpgradeMode() ==  NOT_UPGRADED) {
            /* If cmagent version number is not equals to cmserver version number stop itself */
            StopNodeSelfByVersionNum();
            g_agentConnCmsSuccess = false;
        }
        CmUsleep(AGENT_RECV_CYCLE);
    }
    return NULL;
}
