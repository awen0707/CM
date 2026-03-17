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
* ctl_common_res.cpp
*      cm_ctl common res functions
*
* IDENTIFICATION
*    src/cm_ctl/ctl_common_res.cpp
*
* -------------------------------------------------------------------------
*/
#include "cm/libpq-fe.h"
#include "cm/libpq-int.h"
#include "cm/cm_misc.h"
#include "cm/cm_msg.h"
#include "ctl_common.h"
#include "ctl_common_res.h"

static status_t ResInstCheckConCms(CM_Conn **pCmsCon)
{
    do_conn_cmserver(false, 0, false, pCmsCon);
    if (pCmsCon == NULL) {
        return CM_ERROR;
    } else {
        if (CMPQstatus(*pCmsCon) != CONNECTION_OK) {
            FINISH_CONNECTION_WITHOUT_EXITCODE(*pCmsCon);
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

static inline void ResInstCheckGetQueryMsg(QueryOneResInstStat *queryMsg, uint32 resInstId)
{
    queryMsg->msgType = (int)MSG_CTL_CM_QUERY_RES_INST;
    queryMsg->instId = resInstId;
}

static ResStatus ResInstCheckGetResult(CM_Conn *pCmsCon)
{
    struct timespec timeBegin = {0, 0};
    (void)clock_gettime(CLOCK_MONOTONIC, &timeBegin);
    for (;;) {
        if (cm_client_flush_msg(pCmsCon) == TCP_SOCKET_ERROR_EPIPE) {
            break;
        }
        CM_BREAK_IF_TRUE(IsTimeOut(&timeBegin, "[ResInstCheckGetResult]"));
        char *recvMsg = recv_cm_server_cmd(pCmsCon);
        while (recvMsg != NULL) {
            cm_msg_type *msgTypePtr = (cm_msg_type*)recvMsg;
            if (msgTypePtr->msg_type == (int)MSG_CM_CTL_QUERY_RES_INST_ACK) {
                CmsToCtlOneResInstStat *ackMsg = (CmsToCtlOneResInstStat*)recvMsg;
                return (ResStatus)ackMsg->instStat.status;
            }
            write_runlog(DEBUG1, "unknown the msg type is %d.\n", msgTypePtr->msg_type);
            recvMsg = recv_cm_server_cmd(pCmsCon);
            CmUsleep(CTL_RECV_CYCLE);
        }
    }

    return CM_RES_STAT_UNKNOWN;
}

ResStatus GetResInstStatus(uint32 instId)
{
    CM_Conn *pCmsCon = NULL;
    if (ResInstCheckConCms(&pCmsCon) != CM_SUCCESS) {
        write_runlog(DEBUG1, "connect cms primary failed.\n");
        return CM_RES_STAT_UNKNOWN;
    }

    QueryOneResInstStat queryMsg = {0};
    ResInstCheckGetQueryMsg(&queryMsg, instId);
    if (cm_client_send_msg(pCmsCon, 'C', (char*)&queryMsg, sizeof(queryMsg)) != 0) {
        write_runlog(DEBUG1, "GetResInstStatus send query one res inst msg to cms fail!\n");
        FINISH_CONNECTION_WITHOUT_EXITCODE(pCmsCon);
        return CM_RES_STAT_UNKNOWN;
    }

    ResStatus result = ResInstCheckGetResult(pCmsCon);
    FINISH_CONNECTION_WITHOUT_EXITCODE(pCmsCon);

    return result;
}

status_t CheckResInstInfo(uint32 *nodeId, uint32 instId)
{
    for (uint32 i = 0; i < CusResCount(); ++i) {
        for (uint32 j = 0; j < g_resStatus[i].status.instanceCount; ++j) {
            if (g_resStatus[i].status.resStat[j].cmInstanceId != instId) {
                continue;
            }
            if (*nodeId == 0) {
                *nodeId = g_resStatus[i].status.resStat[j].nodeId;
                return CM_SUCCESS;
            }
            if (g_resStatus[i].status.resStat[j].nodeId != *nodeId) {
                write_runlog(FATAL, "resource(%s) instance(%u) is in node(%u) not in node(%u).\n",
                    g_resStatus[i].status.resName, instId, g_resStatus[i].status.resStat[j].nodeId, *nodeId);
                return CM_ERROR;
            }
            return CM_SUCCESS;
        }
    }
    write_runlog(FATAL, "instanceId(%u) is not a resource instanceId.\n", instId);
    return CM_ERROR;
}
