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
 * cma_libpq_api.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_agent/client_adpts/libpq/cma_libpq_api.cpp
 *
 * -------------------------------------------------------------------------
 */
#include "cma_libpq_api.h"
#include "cm/cm_elog.h"
#include "libpq/libpq-int.h"
#include "cma_dl_load.h"

#define LIBPQ_LIBNAME "libpq.so"

typedef PGconn *(*PQconnectdbT)(const char *conninfo);
typedef PGresult *(*PQexecT)(PGconn *conn, const char *query);
typedef ExecStatusType (*PQresultStatusT)(const PGresult *res);
typedef void (*PQclearT)(PGresult *res);
typedef int (*PQntuplesT)(const PGresult *res);
typedef void (*ClosePGconnT)(PGconn *conn);
typedef void (*FreePGconnT)(PGconn *conn);
typedef void (*PQfinishT)(PGconn *conn);
typedef int (*PQnfieldsT)(const PGresult *res);
typedef char *(*PQgetvalueT)(const PGresult *res, int tupNum, int fieldNum);
typedef ConnStatusType (*PQstatusT)(const PGconn *conn);
typedef int (*PQsendQueryT)(PGconn *conn, const char *query);
typedef char *(*PQerrorMessageT)(const PGconn *conn);

typedef struct StatusTypeRelationT {
    cltPqStatusType_t me;
    ExecStatusType pq;
} StatusTypeRelation;

static StatusTypeRelation g_statTypeRelation[] = {{CLTPQRES_EMPTY_QUERY, PGRES_EMPTY_QUERY},
    {CLTPQRES_CMD_OK, PGRES_COMMAND_OK},
    {CLTPQRES_TUPLES_OK, PGRES_TUPLES_OK}};
const int STAT_TYPE_REL_LEN = sizeof(g_statTypeRelation) / sizeof(StatusTypeRelation);

typedef struct LibpqApiT {
    pthread_rwlock_t lock;
    bool initialized;

    PQconnectdbT conn;
    PQexecT exec;
    PQresultStatusT resultStatus;
    PQstatusT status;
    PQclearT clear;
    ClosePGconnT closeConn;
    FreePGconnT freeConn;
    PQfinishT finish;
    PQntuplesT ntuples;
    PQnfieldsT nfields;
    PQgetvalueT getvalue;
    PQsendQueryT sendQuery;
    PQerrorMessageT errorMsg;
} LibpqApi;

static LibpqApi g_libpqApi = {0, false};

static void LoadLibpqApi(LIB_HANDLE h)
{
    LIB_GETSYMBOL(h, "PQconnectdb", g_libpqApi.conn, PQconnectdbT);
    LIB_GETSYMBOL(h, "PQexec", g_libpqApi.exec, PQexecT);
    LIB_GETSYMBOL(h, "PQresultStatus", g_libpqApi.resultStatus, PQresultStatusT);
    LIB_GETSYMBOL(h, "PQstatus", g_libpqApi.status, PQstatusT);
    LIB_GETSYMBOL(h, "PQclear", g_libpqApi.clear, PQclearT);
    LIB_GETSYMBOL(h, "PQfinish", g_libpqApi.finish, PQfinishT);
    LIB_GETSYMBOL(h, "closePGconn", g_libpqApi.closeConn, ClosePGconnT);
    LIB_GETSYMBOL(h, "freePGconn", g_libpqApi.freeConn, FreePGconnT);
    LIB_GETSYMBOL(h, "PQntuples", g_libpqApi.ntuples, PQntuplesT);
    LIB_GETSYMBOL(h, "PQnfields", g_libpqApi.nfields, PQnfieldsT);
    LIB_GETSYMBOL(h, "PQgetvalue", g_libpqApi.getvalue, PQgetvalueT);
    LIB_GETSYMBOL(h, "PQsendQuery", g_libpqApi.sendQuery, PQsendQueryT);
    LIB_GETSYMBOL(h, "PQerrorMessage", g_libpqApi.errorMsg, PQerrorMessageT);
}

static status_t LoadLibpq()
{
    if (g_libpqApi.initialized) {
        return CM_SUCCESS;
    }

    (void)pthread_rwlock_wrlock(&(g_libpqApi.lock));
    if (g_libpqApi.initialized) {
        (void)pthread_rwlock_unlock(&(g_libpqApi.lock));
        return CM_SUCCESS;
    }

    // never close, and may open many times.
    LIB_HANDLE h = LIB_OPEN(LIBPQ_LIBNAME);
    if (h == NULL) {
        write_runlog(ERROR,
            "Failed to load libpq library file \"%s\". error code: %d. error msg: %s.\n",
            LIBPQ_LIBNAME,
            errno,
            dlerror());
        (void)pthread_rwlock_unlock(&(g_libpqApi.lock));
        return CM_ERROR;
    }

    LoadLibpqApi(h);
    g_libpqApi.initialized = true;
    (void)pthread_rwlock_unlock(&(g_libpqApi.lock));

    return g_libpqApi.initialized ? CM_SUCCESS : CM_ERROR;
}

static cltPqStatusType_t GetCltRES(ExecStatusType pq)
{
    for (int i = 0; i < STAT_TYPE_REL_LEN; i++) {
        if (g_statTypeRelation[i].pq == pq) {
            return g_statTypeRelation[i].me;
        }
    }

    return CLTPQRES_OTHER;
}

cltPqConn_t *Connect(const char *conninfo)
{
    if (LoadLibpq() != CM_SUCCESS) {
        write_runlog(ERROR, "can't connect to pg, load libpq api failed.\n");
        return NULL;
    }

    return (cltPqConn_t *)g_libpqApi.conn(conninfo);
}

bool IsConnOk(const cltPqConn_t *conn)
{
    return g_libpqApi.status((const PGconn *)conn) == CONNECTION_OK;
}

int Status(const cltPqConn_t *conn)
{
    return (int)g_libpqApi.status((const PGconn *)conn);
}

cltPqResult_t *Exec(cltPqConn_t *conn, const char *query)
{
    return (cltPqResult_t *)g_libpqApi.exec((PGconn *)conn, query);
}

cltPqStatusType_t ResultStatus(const cltPqResult_t *res)
{
    return GetCltRES(g_libpqApi.resultStatus((const PGresult *)res));
}

void Clear(cltPqResult_t *res)
{
    g_libpqApi.clear((PGresult *)res);
}

void CloseConn(cltPqConn_t *conn)
{
    g_libpqApi.closeConn((PGconn *)conn);
}

void FreeConn(cltPqConn_t *conn)
{
    g_libpqApi.freeConn((PGconn *)conn);
}

void Finish(cltPqConn_t *conn)
{
    g_libpqApi.finish((PGconn *)conn);
}

int Ntuples(const cltPqResult_t *res)
{
    return g_libpqApi.ntuples((const PGresult *)res);
}

int Nfields(const cltPqResult_t *res)
{
    return g_libpqApi.nfields((PGresult *)res);
}

char *Getvalue(const cltPqResult_t *res, int tupNum, int fieldNum)
{
    return g_libpqApi.getvalue((const PGresult *)res, tupNum, fieldNum);
}

int SendQuery(cltPqConn_t *conn, const char *query)
{
    return g_libpqApi.sendQuery((PGconn *)conn, query);
}

char *ErrorMessage(const cltPqConn_t *conn)
{
    return g_libpqApi.errorMsg((const PGconn *)conn);
}

const char *GetResErrMsg(const cltPqResult_t *res)
{
    return ((const PGresult *)res)->errMsg;
}

bool ResHasError(const cltPqResult_t *res)
{
    return GetResErrMsg(res) != NULL;
}
