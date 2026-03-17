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
 * cms_threads.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_server/cms_threads.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CMS_THREADS_H
#define CMS_THREADS_H

#define SWITCHOVER_FLAG_FILE "cms_need_to_switchover"

int CM_CreateHA(void);
int CM_CreateMonitor(void);
int CM_CreateMonitorStopNode(void);
int CM_CreateDdbStatusCheckThread(void);
int CM_CreateWorkThreadPool(uint32 ctlWorkerCount, uint32 agentWorkerCount);
int CM_CreateIOThreadPool(uint32 thrCount);
void CreateDnGroupStatusCheckAndArbitrateThread(void);
void CreateDealGlobalBarrierThread(void);

status_t CmsCreateThreads();

#endif
