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
 * ctl_global_params.cpp
 *      cm_ctl finishredo functions
 *
 * IDENTIFICATION
 *    src/cm_ctl/ctl_global_params.cpp
 *
 * -------------------------------------------------------------------------
 */
#include "ctl_global_params.h"

#include "cm/libpq-fe.h"
#include "cm/libpq-int.h"

// connect to cms
CM_Conn *CmServer_conn = NULL;
CM_Conn *CmServer_conn1 = NULL;
CM_Conn *CmServer_conn2 = NULL;

// the fd of fprintf
FILE *g_logFilePtr = stdout;

CM_Conn *GetCmsConn()
{
    return CmServer_conn;
}
