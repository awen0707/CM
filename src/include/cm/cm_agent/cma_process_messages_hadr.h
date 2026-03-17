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
 * cma_process_messages_hadr.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_agent/cma_process_messages_hadr.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CMA_PROCESS_MESSAGES_HADR_H
#define CMA_PROCESS_MESSAGES_HADR_H

#include "cm/cm_msg.h"

int ProcessNotifyCnRecoverCommand(const Cm2AgentNotifyCnRecoverByObs *notifyCnRecover);
int ProcessBackupCn2ObsCommand(const Cm2AgentBackupCn2Obs *backupCnMsg);
int ProcessRefreshDelText2ObsCommand(const Cm2AgentRefreshObsDelText *refreshDelTextMsg);

#endif