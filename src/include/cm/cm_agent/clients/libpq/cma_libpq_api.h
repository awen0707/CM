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
 * cma_libpq_api.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_agent/clients/libpq/cma_libpq_api.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CMA_LIBPQ_API_H
#define CMA_LIBPQ_API_H

#include <assert.h>

typedef void cltPqConn_t;
typedef void cltPqResult_t;

typedef enum {
    CLTPQRES_EMPTY_QUERY = 0,
    CLTPQRES_CMD_OK,     // cmd exec success, but nothing return
    CLTPQRES_TUPLES_OK,  // a query with tuples returned
    CLTPQRES_OTHER       // add others if needed, notice that we should sync relation array too.
} cltPqStatusType_t;

#define close_and_reset_connection(conn) \
    if (conn != NULL) {                  \
        CloseConn(conn);                 \
        FreeConn(conn);                  \
        conn = NULL;                     \
    }

#define CLOSE_CONNECTION(con)            \
    do {                                 \
        close_and_reset_connection(con); \
        assert((con) == NULL);             \
        return -1;                       \
    } while (0)

#define CLEAR_AND_CLOSE_CONNECTION(node_result, con) \
    do {                                             \
        Clear(node_result);                          \
        close_and_reset_connection(con);             \
        assert((con) == NULL);                         \
        return -1;                                   \
    } while (0)

const int MAXCONNINFO = 1024;

cltPqConn_t *Connect(const char *conninfo);
bool IsConnOk(const cltPqConn_t *conn);
cltPqResult_t *Exec(cltPqConn_t *conn, const char *query);
cltPqStatusType_t ResultStatus(const cltPqResult_t *res);
void Clear(cltPqResult_t *res);
int Ntuples(const cltPqResult_t *res);
int Nfields(const cltPqResult_t *res);
void CloseConn(cltPqConn_t *conn);
void FreeConn(cltPqConn_t *conn);
void Finish(cltPqConn_t *conn);
char *Getvalue(const cltPqResult_t *res, int tupNum, int fieldNum);
int Status(const cltPqConn_t *conn);
int SendQuery(cltPqConn_t *conn, const char *query);
char *ErrorMessage(const cltPqConn_t *conn);
bool ResHasError(const cltPqResult_t *res);
const char *GetResErrMsg(const cltPqResult_t *res);

#endif  // CMA_LIBPQ_API_H
