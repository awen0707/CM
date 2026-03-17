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
 * cma_connect.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_agent/cma_connect.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CMA_CONNECT_H
#define CMA_CONNECT_H

#include "cm/libpq-fe.h"
#include "cm/libpq-int.h"

#define MAX_PRE_CONN_CMS 2
#define MAX_CONN_TIMEOUT 3

extern CM_Conn* agent_cm_server_connect;
extern CM_Conn* GetConnToCmserver(uint32 nodeid);

void *SendAndRecvCmsMsgMain(void *arg);

#endif
