/*
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd.
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
 * cma_libpq_com.h
 *
 * IDENTIFICATION
 *    include/cm/cm_agent/clients/libpq/cma_libpq_com.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CMA_LIBPQ_COM_H
#define CMA_LIBPQ_COM_H

#include "cma_libpq_api.h"

typedef void *CltResultSet;

typedef struct SqlCondT {
    const char *str;
    unsigned int instId;
} SqlCond;

typedef int (*ResultSetHandle)(CltResultSet set, const cltPqResult_t *nodeResult, const char *sqlCommand,
    const SqlCond *sqlCond);


int ExecDmlSqlCmd(ResultSetHandle handle, CltResultSet set, cltPqConn_t **conn, const char *sqlCommand,
    const SqlCond *sqlCond);

#endif
