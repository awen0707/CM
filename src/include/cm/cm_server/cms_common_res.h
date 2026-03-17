/*
* Copyright (c) 2022 Huawei Technologies Co.,Ltd.
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
* cms_common.cpp
*
*
* IDENTIFICATION
*    include/cm/cm_server/cms_common_res.h
*
* -------------------------------------------------------------------------
 */

#ifndef CM_CMS_COMMON_RES_H
#define CM_CMS_COMMON_RES_H

#include "cm_msg.h"

void PrintCurrentIsregStatusList();
void InitIsregVariable();
void UpdateReportInter();
void UpdateCheckListAfterTimeout();
void CleanReportInter(uint32 nodeId);
ResIsregStatus GetIsregStatusByCmInstId(uint32 cmInstId);
void GetCheckListByNodeId(uint32 nodeId, uint32 *checkList, uint32 *checkCount);
void UpdateIsworkList(uint32 cmInstId, int newIswork);
void UpdateIsregStatusList(uint32 cmInstId, ResIsregStatus newIsreg);
void UpdateResIsregStatusList(uint32 nodeId, ResInstIsreg *isregList, uint32 isregCount, bool *needChangCheckList);
bool IsCmInstIdInCheckList(uint32 nodeId, uint32 cmInstId);
bool IsRecvCheckListMiss(uint32 nodeId, uint32 *checkList, uint32 checkCount);
bool IsRecvIsregStatValid(int stat);
void CleanAllResStatusReportInter();

status_t SaveOneResStatusToDdb(const OneResStatList *oneResStat);
status_t GetOneResStatusFromDdb(OneResStatList *resStat);
status_t GetAllResStatusFromDdb();

void NotifyCmaDoReg(uint32 destNodeId);
void NotifyCmaDoUnreg(uint32 destNodeId);

#endif  // CM_CMS_COMMON_RES_H
