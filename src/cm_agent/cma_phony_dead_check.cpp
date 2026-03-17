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
 * cma_phony_dead_check.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_agent/cma_phony_dead_check.cpp
 *
 * -------------------------------------------------------------------------
 */

#include "cm/libpq-fe.h"
#include "cm/libpq-int.h"
#include "cma_global_params.h"
#include "cma_instance_management.h"
#include "cma_common.h"
#include "cma_client.h"
#ifdef ENABLE_MULTIPLE_NODES
#include "cma_coordinator.h"
#endif
#include "cma_phony_dead_check.h"

#ifdef ENABLE_UT
#define static
#endif

const int PROCESS_NORMAL_RUNNING = 0;

static bool IsDNCoredump(uint32 dnId)
{
    int rcs;
    uint32 i = dnId;
    GaussState state;
    char *dataPath = g_currentNode->datanode[i].datanodeLocalDataPath;
    char gaussdbStatePath[MAXPGPATH] = {0};
    rcs = snprintf_s(gaussdbStatePath, MAXPGPATH, MAXPGPATH - 1, "%s/gaussdb.state", dataPath);
    securec_check_intval(rcs, (void)rcs);
    rcs = ReadDBStateFile(&state, gaussdbStatePath);
    if (rcs == 0) {
        if (state.state == INSTANCE_HA_STATE_COREDUMP) {
            write_runlog(WARNING, "instance(dn_%u) is coredump\n", g_currentNode->datanode[i].datanodeId);
            return true;
        }
    }
    return false;
}

static bool DnPhonyDeadProcessE2E(int dnId, int phonyDead)
{
    if (phonyDead == PROCESS_PHONY_DEAD_D) {
        if (IsDatanodeSSMode()) {
            write_runlog(LOG, "[%s] dn is D status, but in ss mode, can't process the D status.\n", __FUNCTION__);
        } else if (CheckDnStausPhonyDead(dnId, (int)agent_phony_dead_check_interval) != 0) {
            /* Verify that the short link to dn is available */
            g_dnPhonyDeadD[dnId] = true;
            write_runlog(WARNING, "dn_%u phony dead D\n", g_currentNode->datanode[dnId].datanodeId);
            return true;
        }
    }
    g_dnPhonyDeadD[dnId] = false;
    if (phonyDead == PROCESS_PHONY_DEAD_T) {
        if (IsDNCoredump((uint32)dnId)) {
            write_runlog(WARNING, "dn_%u Core Dump\n", g_currentNode->datanode[dnId].datanodeId);
            return true;
        }

        if (g_isPauseArbitration) {
            write_runlog(WARNING, "dn_%u phony dead T, but now CM is paused, so do nothing for now.\n",
                g_currentNode->datanode[dnId].datanodeId);
            return false;
        }

        write_runlog(WARNING, "dn_%u phony dead T, immediate shutdown\n", g_currentNode->datanode[dnId].datanodeId);
        immediate_stop_one_instance(g_currentNode->datanode[dnId].datanodeLocalDataPath, INSTANCE_DN);
        return true;
    }
    return false;
}

static int CheckDataPathModifyTime(char *dataPath)
{
    struct stat datapathState = {0};
    if (stat(dataPath, &datapathState) != 0) {
        write_runlog(WARNING, "find datapathj %s failed\n", dataPath);
        return -1;
    }
    time_t now = time(NULL);
    if (now - datapathState.st_mtime < agent_phony_dead_check_interval) {
        return 0;
    }
    write_runlog(WARNING,
                 "find datapath %s, it does not modify for long time (%lu:%lu)\n",
                 dataPath, now, datapathState.st_mtime);
    return -1;
}

static bool DnPhonyDeadStatusCheck(int dnId, uint32 *agentCheckTimeInterval)
{
    uint32 i = (uint32)dnId;

    int phonyDead = PROCESS_NORMAL_RUNNING;
    errno_t rc =
        check_one_instance_status(GetDnProcessName(), g_currentNode->datanode[i].datanodeLocalDataPath, &phonyDead);
    if (g_enableE2ERto == 1) {
        if (DnPhonyDeadProcessE2E(dnId, phonyDead)) {
            return true;
        }
    } else {
        g_dnPhonyDeadD[i] = false;
        if (rc != PROCESS_RUNNING) {
            return false;
        }
        if (phonyDead == PROCESS_PHONY_DEAD_D) {
            if (IsDatanodeSSMode()) {
                write_runlog(LOG, "[%s] dn is D status, but in ss mode, can't process the D status.\n", __FUNCTION__);
                return false;
            } else {
                return true;
            }
        }
        if (phonyDead == PROCESS_PHONY_DEAD_T) {
            if (g_clusterType != V3SingleInstCluster && g_agentCheckTStatusInterval > agent_phony_dead_check_interval) {
                *agentCheckTimeInterval = g_agentCheckTStatusInterval;
            }
            return true;
        }
    }
    if (phonyDead == PROCESS_PHONY_DEAD_Z) {
        return true;
    }
    if (g_dnRoleForPhonyDead[i] != INSTANCE_ROLE_PRIMARY && g_dnRoleForPhonyDead[i] != INSTANCE_ROLE_STANDBY) {
        write_runlog(DEBUG1,
            "dn(%u:%s) role is %d, can't do phony dead check.\n",
            i,
            g_currentNode->datanode[i].datanodeLocalDataPath,
            g_dnRoleForPhonyDead[i]);
        /* reset phony dead times. */
        return false;
    } else {
        rc = CheckDnStausPhonyDead(dnId, (int)*agentCheckTimeInterval);
        if (rc == 0) {
            rc = check_disc_state(g_currentNode->datanode[i].datanodeId);
        }
        if (rc != 0 && g_enableE2ERto == 1 && g_dnPhonyDeadTimes[i] >= PHONY_DEAD_THRESHOLD) {
            if (g_isPauseArbitration) {
                write_runlog(WARNING, "dn_%u phony dead, but now CM is pausing, so do nothing for now.\n",
                    g_currentNode->datanode[i].datanodeId);
            } else {
                write_runlog(WARNING, "dn_%u phony dead, immediate shutdown\n", g_currentNode->datanode[i].datanodeId);
                immediate_stop_one_instance(g_currentNode->datanode[i].datanodeLocalDataPath, INSTANCE_DN);
            }
        }
        if (rc != 0) {
            rc = CheckDataPathModifyTime(g_currentNode->datanode[i].datanodeLocalDataPath);
        }
        return (rc == 0) ? false : true;
    }
}

void *DNPhonyDeadStatusCheckMain(void * const arg)
{
    const uint32 instanceId = *(uint32 *)arg;
    int i = -1;
    bool isPhonyDead = true;
    uint32 agentCheckTimeInterval;
    for (i = 0; i < (int)g_currentNode->datanodeCount; i++) {
        if (g_currentNode->datanode[i].datanodeId == instanceId) {
            break;
        }
    }
    write_runlog(LOG, "DN instanceId is %d.\n", i);
    if (i == -1) {
        write_runlog(FATAL, "unknown instance %u.\n", instanceId);
        exit(-1);
    }

    struct timeval checkBegin, checkEnd;
    uint32 expired_time = 0;
    for (;;) {
        if (g_shutdownRequest || agent_phony_dead_check_interval == 0) {
            cm_sleep(5);
            continue;
        }
        agentCheckTimeInterval = agent_phony_dead_check_interval;
        (void)gettimeofday(&checkBegin, NULL);
        isPhonyDead = DnPhonyDeadStatusCheck(i, &agentCheckTimeInterval);
        if (isPhonyDead && !g_isPauseArbitration) {
            g_dnPhonyDeadTimes[i]++;
        } else {
            g_dnPhonyDeadTimes[i] = 0;
        }
        if (g_dnPhonyDeadTimes[i] > 0) {
            write_runlog(LOG,
                "has found %d times for instance(dn_%u) phony dead check.\n",
                g_dnPhonyDeadTimes[i],
                g_currentNode->datanode[i].datanodeId);
        }
        (void)gettimeofday(&checkEnd, NULL);

        expired_time = (uint32)(checkEnd.tv_sec - checkBegin.tv_sec);
        write_runlog(DEBUG5, "phony dead check take %u seconds.\n", expired_time);

        if (expired_time < agentCheckTimeInterval) {
            cm_sleep(agentCheckTimeInterval - expired_time);
        }
    }
    return NULL;
}

void *DNCoreDumpCheckMain(void *arg)
{
    const uint32 instanceId = *(uint32 *)arg;
    uint32 i;
    for (i = 0; i < g_currentNode->datanodeCount; i++) {
        if (g_currentNode->datanode[i].datanodeId == instanceId) {
            break;
        }
    }
    pthread_t threadId = pthread_self();
    write_runlog(LOG, "DN coredump check thread start, instanceId is %u, threadid %lu.\n", instanceId, threadId);
    if (i >= g_currentNode->datanodeCount) {
        write_runlog(FATAL, "unknown instance %u.\n", instanceId);
        exit(-1);
    }

    for (;;) {
        if (g_shutdownRequest) {
            cm_sleep(5);
            continue;
        }
        if (IsDNCoredump(i)) {
            g_dnCore[i] = true;
            write_runlog(WARNING, "dn_%u Core Dump\n", instanceId);
        } else {
            g_dnCore[i] = false;
        }
        cm_sleep(1);
    }
    return NULL;
}

void *FaultDetectMain(void *arg)
{
    bool have_killed_nodes = false;

    for (;;) {
        if (g_shutdownRequest) {
            write_runlog(LOG, "fault detect thread shutdown.\n");
            break;
        }

        if (g_agentNicDown) {
            if (!have_killed_nodes) {
                write_runlog(LOG, "nic not running, immediate shutdown nodes.\n");
                immediate_shutdown_nodes(false, false);
                have_killed_nodes = true;
            }
        } else {
            have_killed_nodes = false;
        }

        cm_sleep(5);
    }

    return NULL;
}
