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
* cma_instance_management_res.h
*
*
* IDENTIFICATION
*    include/cm/cm_agent/cma_instance_management_res.h
*
* -------------------------------------------------------------------------
*/

#ifndef CMA_INSTANCE_MANAGEMENT_RES_H
#define CMA_INSTANCE_MANAGEMENT_RES_H

#include "cm_misc.h"

status_t StartOneResInst(CmResConfList *conf);
void StopOneResInst(const CmResConfList *conf);
void OneResInstShutdown(const CmResConfList *oneResConf);
status_t RegOneResInst(const CmResConfList *conf, uint32 destInstId, bool8 needNohup);
status_t UnregOneResInst(const CmResConfList *conf, uint32 destInstId);
ResIsregStatus IsregOneResInst(const CmResConfList *conf, uint32 destInstId);
status_t CleanOneResInst(const CmResConfList *conf);
void StopAllResInst();
int CheckOneResInst(const CmResConfList *conf);
bool IsInstManualStopped(uint32 instId);
void StartResourceCheck();
void StopResourceCheck();
int ResourceStoppedCheck(void);
status_t InitLocalResConf();
uint32 GetLocalResConfCount();
bool IsCusResExistLocal();

#endif
