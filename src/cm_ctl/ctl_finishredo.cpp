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
 * ctl_finishredo.cpp
 *      cm_ctl finishredo functions
 *
 * IDENTIFICATION
 *    src/cm_ctl/ctl_finishredo.cpp
 *
 * -------------------------------------------------------------------------
 */
#include <signal.h>
#include "common/config/cm_config.h"
#include "cm/libpq-fe.h"
#include "cm/cm_misc.h"
#include "ctl_common.h"
#include "cm/cm_msg.h"

#define FINISH_REDO_DEFAULT_WAIT 1200

extern char g_cmData[CM_PATH_LENGTH];
extern uint32 g_commandOperationNodeId;
extern CM_Conn* CmServer_conn;
static bool handle_finish_redo_msg(int* get_check_ack_count_ptr, int* need_finish_redo_ptr);
static void send_finish_redo_check_msg(int* time_ptr, int* send_check_ptr);
static int wait_finish_redo_handler(void);


static bool handle_finish_redo_msg(int* get_check_ack_count_ptr, int* need_finish_redo_ptr)
{
    int rt = 0;
    char* receive_msg = NULL;
    cm_msg_type* cm_msg_type_ptr = NULL;
    bool wait_finish_redo = true;
    cm_to_ctl_finish_redo_check_ack* msgFinishRedoCheckAck = NULL;
    if (CmServer_conn != NULL) {
        rt = cm_client_flush_msg(CmServer_conn);
        if (rt == TCP_SOCKET_ERROR_EPIPE) {
            CMPQfinish(CmServer_conn);
            CmServer_conn = NULL;
            return false;
        }
        receive_msg = recv_cm_server_cmd(CmServer_conn);
    }
    if (receive_msg != NULL) {
        cm_msg_type_ptr = (cm_msg_type*)receive_msg;
        switch (cm_msg_type_ptr->msg_type) {
            case MSG_CM_CTL_FINISH_REDO_CHECK_ACK:
                (*get_check_ack_count_ptr)++;
                msgFinishRedoCheckAck = (cm_to_ctl_finish_redo_check_ack*)receive_msg;
                if (msgFinishRedoCheckAck->finish_redo_count > 0) {
                    wait_finish_redo = true;
                } else {
                    wait_finish_redo = false;
                    write_runlog(LOG, "Finish redo has been processed in all groups successfully.\n");
                }
                *need_finish_redo_ptr = msgFinishRedoCheckAck->finish_redo_count;
                break;
            case MSG_CM_CTL_FINISH_REDO_ACK:
                write_runlog(LOG, "Finish redo msg has been received successfully.\n");
                wait_finish_redo = true;
                break;

            case MSG_CM_CTL_BACKUP_OPEN:
                write_runlog(ERROR, "disable do finish redo in recovery mode and cm_ctl exit.\n");
                exit(0);
            default:
                write_runlog(ERROR, "unknown the msg type is %d.\n", cm_msg_type_ptr->msg_type);
                break;
        }
    }
    return wait_finish_redo;
}

static void send_finish_redo_check_msg(int* time_ptr, int* send_check_ptr)
{
    if (CmServer_conn != NULL) {
        cm_msg_type msgFinishRedoCheck;
        msgFinishRedoCheck.msg_type = (int)MSG_CTL_CM_FINISH_REDO_CHECK;
        int rt = cm_client_send_msg(CmServer_conn, 'C', (char*)&msgFinishRedoCheck, sizeof(msgFinishRedoCheck));
        if (rt != 0) {
            CMPQfinish(CmServer_conn);
            CmServer_conn = NULL;
        }
    }
    (void)sleep(3);
    write_runlog(LOG, ".");
    *time_ptr += 3;
    (*send_check_ptr)++;
}

static int wait_finish_redo_handler(void)
{
    int ret = 0;
    int time_pass = 0;
    ctl_to_cm_finish_redo finish_redo_content = {0};
    bool wait_finish_redo = true;

    int get_check_ack_count = 0;
    int send_check_count = 0;
    int need_finish_redo = -1;
    finish_redo_content.msg_type = (int)MSG_CTL_CM_FINISH_REDO;
    for (;;) {
        if ((send_check_count - get_check_ack_count > 3) && time_pass < FINISH_REDO_DEFAULT_WAIT) {
            CMPQfinish(CmServer_conn);
            CmServer_conn = NULL;
            do_conn_cmserver(false, 0);
            if (CmServer_conn == NULL) {
                (void)sleep(3);
                write_runlog(LOG, ".");
                time_pass += 3;
                continue;
            }
            ret = cm_client_send_msg(CmServer_conn, 'C', (char*)&finish_redo_content, sizeof(finish_redo_content));
            if (ret != 0) {
                CMPQfinish(CmServer_conn);
                CmServer_conn = NULL;
            }
            send_check_count = 0;
            get_check_ack_count = 0;
        }
        wait_finish_redo = handle_finish_redo_msg(&get_check_ack_count, &need_finish_redo);
        if (wait_finish_redo) {
            send_finish_redo_check_msg(&time_pass, &send_check_count);
        } else {
            break;
        }

        if (time_pass > FINISH_REDO_DEFAULT_WAIT) {
            write_runlog(ERROR, "Finish redo command timeout.\n");
            if (need_finish_redo > 0) {
                write_runlog(ERROR, "Finish redo timeout details: %d groups not recovered.\n", need_finish_redo);
            }
            CMPQfinish(CmServer_conn);
            CmServer_conn = NULL;
            return -3;
        }
    }
    return 0;
}

int do_finish_redo(void)
{
    int ret;
    ctl_to_cm_finish_redo finish_redo_content = {0};

    /* return conn to cm_server */
    do_conn_cmserver(false, 0);
    if (CmServer_conn == NULL) {
        write_runlog(ERROR, "send finish redo msg to cm_server, connect fail. node_id:%u, data_path:%s.\n",
            g_commandOperationNodeId, g_cmData);
        return -1;
    }

    finish_redo_content.msg_type = (int)MSG_CTL_CM_FINISH_REDO;
    ret = cm_client_send_msg(CmServer_conn, 'C', (char*)&finish_redo_content, sizeof(finish_redo_content));
    if (ret != 0) {
        FINISH_CONNECTION((CmServer_conn), -1);
    }
    ret = wait_finish_redo_handler();
    if (ret != 0) {
        CMPQfinish(CmServer_conn);
        CmServer_conn = NULL;
        return ret;
    }

    (void)sleep(3);
    write_runlog(LOG, "Finish redo msg has been processed successfully.\n");
    CMPQfinish(CmServer_conn);
    CmServer_conn = NULL;
    return 0;
}
