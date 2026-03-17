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
 * cma_voting_disk.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_agent/cma_voting_disk.cpp
 *
 * -------------------------------------------------------------------------
 */

#include "cma_global_params.h"
#include "cm_voting_disk.h"

static void StopCurrentNode()
{
    char command[CM_MAX_COMMAND_LEN];
    int doForce = 1;
    ShutdownMode shutdownModeNum = FAST_MODE;
    int shutdownLevel = SINGLE_NODE;

    errno_t rc = snprintf_s(command, CM_MAX_COMMAND_LEN, CM_MAX_COMMAND_LEN - 1,
        "echo -e \'%d\\n%d\\n%d\' > %s; chmod 600 %s",
        doForce, shutdownModeNum, shutdownLevel, g_cmManualStartPath, g_cmManualStartPath);
    securec_check_intval(rc, (void)rc);
    int ret = system(command);
    if (ret != 0) {
        write_runlog(ERROR, "Stop current node failed, with executing the command: \"%s\","
            " systemReturn=%d, shellReturn=%d, errno=%d.\n", command, ret, SHELL_RETURN_CODE(ret), errno);
    } else {
        write_runlog(LOG, "Stop current node success, with executing the command: \"%s\"\n", command);
    }
    return;
}

static void UpdateVotingDiskStatus(VotingDiskNodeInfo *nodeInfo)
{
    if (g_diskTimeout == 0) {
        write_runlog(DEBUG5, "g_diskTimeout is 0, stop update voting disk status\n");
        return;
    }
    uint32 expiredTime = 0;
    struct timespec startTime = {0, 0};
    struct timespec endTime = {0, 0};
    (void)clock_gettime(CLOCK_MONOTONIC, &startTime);

    while (expiredTime < g_diskTimeout) {
        if (SetVotingDiskSingleNodeInfo(nodeInfo, g_nodeId) == CM_SUCCESS) {
            write_runlog(DEBUG5, "update voting disk status success\n");
            return;
        }
        (void)clock_gettime(CLOCK_MONOTONIC, &endTime);
        expiredTime = (uint32)(endTime.tv_sec - startTime.tv_sec);
        write_runlog(ERROR, "update voting disk status failed, expiredTime=%u, diskTimeout=%u\n",
            expiredTime, g_diskTimeout);
        cm_sleep(1);
    }
    write_runlog(WARNING, "update voting disk status timeout, stop current node!\n");
    StopCurrentNode();
}

void *VotingDiskMain(void *arg)
{
    thread_name = "VotingDisk";
    pthread_t threadId = pthread_self();
    write_runlog(LOG, "Voting disk status check thread start, threadid %lu.\n", threadId);

    if (InitVotingDisk(g_votingDiskPath) != CM_SUCCESS) {
        write_runlog(FATAL, "Init voting disk failed!\n");
        exit(-1);
    }
    VotingDiskNodeInfo nodeInfo;

    for (;;) {
        if (g_shutdownRequest) {
            cm_sleep(5);
            continue;
        }
        nodeInfo.nodeTime = time(NULL);
        UpdateVotingDiskStatus(&nodeInfo);
        cm_sleep(1);
    }

    return NULL;
}
