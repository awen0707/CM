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
 * ctl_distribute.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_ctl/ctl_common.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CTL_GLOBAL_PARAMS_H
#define CTL_GLOBAL_PARAMS_H

#include <stdio.h>

struct cm_conn;

extern struct cm_conn *CmServer_conn;
extern struct cm_conn *CmServer_conn1;
extern struct cm_conn *CmServer_conn2;
extern FILE *g_logFilePtr;
struct cm_conn *GetCmsConn();

#endif