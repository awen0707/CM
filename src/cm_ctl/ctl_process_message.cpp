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
 * ctl_process_message.cpp
 *
 * IDENTIFICATION
 *    src/cm_ctl/ctl_process_message.cpp
 *
 * -------------------------------------------------------------------------
 */
#include "ctl_process_message.h"

#include "cm_msg.h"
#include "cm/libpq-fe.h"
#include "cm/libpq-int.h"

#include "ctl_common.h"
#include "ctl_show.h"

static CtlDealCmdFunc g_ctlFunc[MSG_CM_TYPE_CEIL] = {0};

static status_t OutPutCmdResult(const char *option, char *recvMsg)
{
    const ExecDdbCmdAckMsg *ackPtr = (const ExecDdbCmdAckMsg *)recvMsg;
    if (ackPtr->isSuccess) {
        if (ackPtr->outputLen < DCC_CMD_MAX_OUTPUT_LEN) {
            write_runlog(LOG, "exec ddb %s command success.\n", option);
            write_runlog(LOG, "%s\n", ackPtr->output);
        } else {
            write_runlog(LOG, "exec ddb %s command failed, error msg's buf is smaller(%d/%d).\n",
                option, DCC_CMD_MAX_OUTPUT_LEN, ackPtr->outputLen);
            write_runlog(LOG, "part result is:\n %s\n", ackPtr->output);
        }
        return CM_SUCCESS;
    } else {
        write_runlog(LOG, "exec ddb %s command failed, err msg:\n%s\n", option, ackPtr->errMsg);
    }
    return CM_ERROR;
}

static bool8 RecvAndDealCmd(status_t *cmStatus, CM_Conn *conn, const char *option, int32 expCmd)
{
    char *receiveMsg = (char *)recv_cm_server_cmd(conn);
    if (receiveMsg == NULL) {
        return CM_FALSE;
    }
    int32 msgType = ((cm_msg_type *)receiveMsg)->msg_type;
    if (expCmd != INVALID_EXPECT_CMD && msgType != expCmd) {
        return CM_FALSE;
    }
    if (msgType < 0 || msgType >= (int32)MSG_CM_TYPE_CEIL) {
        write_runlog(ERROR, "invalid msgType(%d).\n", msgType);
        return CM_FALSE;
    }
    CtlDealCmdFunc ctlFunc = g_ctlFunc[msgType];
    if (ctlFunc != NULL) {
        *cmStatus = ctlFunc(option, receiveMsg);
        return CM_TRUE;
    }
    write_runlog(DEBUG1, "msgType is %d, but ctlFunc is NULL.\n", msgType);
    *cmStatus = CM_ERROR;
    if (expCmd != INVALID_EXPECT_CMD) {
        return CM_TRUE;
    }
    return CM_FALSE;
}

status_t GetExecCmdResult(const char *option, int32 expCmd, CM_Conn *conn)
{
    int ret;
    int recvTimeOut = EXEC_DDC_CMD_TIMEOUT;
    bool8 dealRet;
    status_t cmStatus;
    for (;;) {
        ret = cm_client_flush_msg(conn);
        if (ret == TCP_SOCKET_ERROR_EPIPE) {
            FINISH_CONNECTION_WITHOUT_EXITCODE((CmServer_conn));
            write_runlog(ERROR, "failed to execute cmd(%d), tcp socket error epipe.\n", expCmd);
            return CM_ERROR;
        }
        dealRet = RecvAndDealCmd(&cmStatus, conn, option, expCmd);
        recvTimeOut--;
        if (dealRet || recvTimeOut <= 0) {
            break;
        }
        cm_sleep(1);
    }

    if (recvTimeOut <= 0) {
        write_runlog(LOG, "command timeout.\n");
        return CM_TIMEDOUT;
    }

    return cmStatus;
}

static void ResetCtlFunc()
{
    errno_t rc = memset_s(g_ctlFunc, sizeof(g_ctlFunc), 0, sizeof(g_ctlFunc));
    securec_check_errno(rc, (void)rc);
}

void InitDdbCmdMsgFunc()
{
    ResetCtlFunc();
    g_ctlFunc[EXEC_DDB_COMMAND_ACK] = OutPutCmdResult;
}

void InitCtlShowMsgFunc()
{
    ResetCtlFunc();
    g_ctlFunc[MSG_CTL_CM_RHB_STATUS_ACK] = HandleRhbAck;
    g_ctlFunc[MSG_CTL_CM_NODE_DISK_STATUS_ACK] = HandleNodeDiskAck;
    g_ctlFunc[MSG_CTL_CM_FLOAT_IP_ACK] = HandleFloatIpAck;
}
