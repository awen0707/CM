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
 * ctl_process_message.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_ctl/ctl_process_message.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CTL_PROCESS_MESSAGE_H
#define CTL_PROCESS_MESSAGE_H

#include "c.h"
#include "cm_defs.h"
#include "ctl_global_params.h"

const int32 INVALID_EXPECT_CMD = -1;

typedef status_t (*CtlDealCmdFunc)(const char *option, char *msg);

struct cm_conn;

status_t GetExecCmdResult(const char *option, int32 expCmd = INVALID_EXPECT_CMD, struct cm_conn *conn = GetCmsConn());
void InitDdbCmdMsgFunc();
void InitCtlShowMsgFunc();

#endif