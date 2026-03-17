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
 * cma_threads.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_agent/cma_threads.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CMA_THREADS_H
#define CMA_THREADS_H

void CreateETCDStatusCheckThread();
void CreatePhonyDeadCheckThread();
void CreateStartAndStopThread();
void CreateDNStatusCheckThread(int* i);
void CreateDNBackupStatusCheckThread(int* i);
void CreateDNConnectionStatusCheckThread(int* i);
void CreateDNCheckSyncListThread(int *idx);
void CreateDNCheckAvailableSyncThread(int *idx);
void CreateFaultDetectThread();
void CreateConnCmsPThread();
void CreateKerberosStatusCheckThread();
int CreateLogFileCompressAndRemoveThread();
void CreateCheckUpgradeModeThread();
void CreateDefResStatusCheckThread(void);
void CreateCusResIsregCheckThread(void);
void CreateRecvClientMessageThread(void);
void CreateSendMessageToClientThread(void);
void CreateProcessMessageThread(void);
void CreateETCDConnectionStatusCheckThread(void);
int CreateSendAndRecvCmsMsgThread();
int CreateProcessSendCmsMsgThread();
int CreateProcessRecvCmsMsgThread();
void CreateVotingDiskThread();
void CreateDiskUsageCheckThread();
void CreateOnDemandRedoCheckThread();
int CreateCheckNetworkThread(void);

#endif
