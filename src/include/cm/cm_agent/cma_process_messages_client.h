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
 * cma_process_messages_client.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_agent/cma_process_messages_client.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CMA_PROCESS_MESSAGES_CLIENT_H
#define CMA_PROCESS_MESSAGES_CLIENT_H

void ProcessResStatusList(const CmsReportResStatList *msg);
void ProcessResStatusChanged(const CmsReportResStatList *msg);
void ProcessResLockAckFromCms(const CmsReportLockResult *recvMsg);
void ProcessResRegFromCms(const CmsNotifyAgentRegMsg *recvMsg);
void ProcessIsregCheckListChanged(const CmsFlushIsregCheckList *recvMsg);
void NotifyClientConnectClose();

#endif // CMA_PROCESS_MESSAGES_CLIENT_H
