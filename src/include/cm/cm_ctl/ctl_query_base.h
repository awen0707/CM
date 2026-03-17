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
 * ctl_query_base.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_ctl/ctl_query_base.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CTL_QUERY_BASE_H
#define CTL_QUERY_BASE_H

#include "cm/cm_defs.h"

#define ELASTICGROUP "elastic_group"
#define DELAY_THRESHOLD (8 * 1024 * 1014)
#define MAX_IPV4_LEN (15)
#define MAX_IPV6_LEN (45)
#define INSTANCE_ID_LEN (4)
#define INSTANCE_DYNAMIC_ROLE_LEN (7)
#define ETCD_DYNAMIC_ROLE_LEN (13)
#define INSTANCE_STATIC_ROLE_LEN (1)
#define MAX_GTM_CONNECTION_STATE_LEN (14)
#define MAX_GTM_SYNC_STATE_LEN (14)
#define INSTANCE_DB_STATE_LEN (6)
#define SECONDARY_DYNAMIC_ROLE_LEN (9)
#define SPACE_LEN (1)
#define SEPERATOR_LEN (1)
#define MAX_NODE_ID_LEN (2)
#define GLOBAL_BARRIER_WAIT_SECONDS (6)


#define SPACE_NUM (2)
#define STATE_NUM (3)
#define INSTANCE_LEN (7)
#define DEFAULT_PATH_LEN (4)
#define NODE_NUM (3)


#define CYCLE_BREAK (1)
#define CYCLE_RETURN (2)


int ProcessDataBeginMsg(const char *receiveMsg, bool *recDataEnd);
void DoProcessNodeEndMsg(const char *receiveMsg);
status_t SetCmQueryContent(ctl_to_cm_query *cmQueryContent);
uint32 GetDnIpMaxLen();
uint32 GetCnIpMaxLen();
uint32 GetGtmIpMaxLen();

#endif
