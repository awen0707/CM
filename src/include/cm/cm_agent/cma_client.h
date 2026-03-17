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
 * cma_client.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_agent/cma_client.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CM_CMA_CLIENT_ADPT_H
#define CM_CMA_CLIENT_ADPT_H

#include "cm_msg.h"

void StartDatanodeCheck(void);

int CheckDnStausPhonyDead(int dnId, int agentCheckTimeInterval);

int DatanodeStatusCheck(DnStatus *dnStatus, uint32 dataNodeIndex, int32 dnProcess);

int CheckDatanodeStatus(const char *dataDir, int *role);
int ProcessUnlockCmd(const cm_to_agent_unlock *unlockMsg);
/* Agent to DN connection */
int ProcessLockNoPrimaryCmd(uint32 instId);
int ProcessLockChosenPrimaryCmd(const cm_to_agent_lock2 *msgTypeLock2Ptr);
void *DNSyncCheckMain(void *arg);
void *DNMostAvailableCheckMain(void *arg);
void ProcessStreamingStandbyClusterBuildCommand(
    int instanceType, const char* dataDir, const cm_to_agent_build *buildMsg);
void* DNBackupStatusCheckMain(void *arg);
void DnCheckFloatIp(DnStatus *dnStatus, uint32 dnIdx, bool8 isRunning);
uint32 DelFloatIpInDatanode(uint32 dnIdx);
#endif  // CM_CMA_CLIENT_ADPT_H
