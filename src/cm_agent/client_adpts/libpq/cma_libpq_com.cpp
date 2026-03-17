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
 * cma_libpq_com.cpp
 *
 * IDENTIFICATION
 *    src/cm_agent/client_adpts/libpq/cma_libpq_com.cpp
 *
 * -------------------------------------------------------------------------
 */
#include "cma_libpq_com.h"

#include "cm_elog.h"

int ExecDmlSqlCmd(ResultSetHandle handle, CltResultSet set, cltPqConn_t **conn, const char *sqlCommand,
    const SqlCond *sqlCond)
{
    uint32 instId = 0;
    const char *str = "unknown";
    if (sqlCond != NULL) {
        instId = sqlCond->instId;
        str = sqlCond->str;
    }

    if (conn == NULL || (*conn) == NULL) {
        write_runlog(ERROR, "[%s: %u] cannot execute sqlCommand[%s], bacause conn is NULL.\n", str, instId, sqlCommand);
        return -1;
    }

    cltPqResult_t *nodeResult = Exec((*conn), sqlCommand);
    if (nodeResult == NULL) {
        write_runlog(ERROR, "[%s: %u] sqlCommands[%s] fail return NULL, errmsg is %s.\n",
            str, instId, sqlCommand, ErrorMessage(*conn));
        CLOSE_CONNECTION(*conn);
    }

    if ((ResultStatus(nodeResult) != CLTPQRES_CMD_OK) && (ResultStatus(nodeResult) != CLTPQRES_TUPLES_OK)) {
        write_runlog(ERROR, "[%s: %u] sqlCommand[%s] fail ResultStatus=%d, errmsg is %s.\n",
            str, instId, sqlCommand, (int32)ResultStatus(nodeResult), ErrorMessage(*conn));
        CLEAR_AND_CLOSE_CONNECTION(nodeResult, (*conn));
    }

    if (handle != NULL) {
        if (handle(set, nodeResult, sqlCommand, sqlCond) != 0) {
            CLEAR_AND_CLOSE_CONNECTION(nodeResult, (*conn));
        }
    }
    Clear(nodeResult);
    return 0;
}
