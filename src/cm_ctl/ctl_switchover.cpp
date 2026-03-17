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
 * ctl_switch.cpp
 *    cm_ctl switchover [-z AVAILABILITY_ZONE] [-n NODEID -D DATADIR [-q] [-a [-q] [-t SECS]
 *
 * IDENTIFICATION
 *    src/cm_ctl/ctl_switch.cpp
 *
 * -------------------------------------------------------------------------
 */
#include <signal.h>
#include "common/config/cm_config.h"
#include "cm/libpq-fe.h"
#include "cm/cm_misc.h"
#include "ctl_common.h"
#include "cm/libpq-int.h"
#include "cm/cm_agent/cma_main.h"
#include "cm_elog.h"
#include "cm_msg_version_convert.h"

/* If DN switch take long time and do not complete, it will timeout, pending_command will be clear in server_main.cpp
CM_ThreadMonitorMain(), the default g_wait_seconds is 180s, we need to increase the g_wait_seconds to 1200s. */
#define SWITCHOVER_DEFAULT_WAIT 120  // It needs an integer multiple of 3, because of sleep(3)
#define PROMOTING_TIME 100
#define DYNAMIC_PRIMARY_AND_DYNAMIC_STANDBY 2

typedef struct NeedQuickSwitchoverInstanceArraySt {
    int instance_type[DYNAMIC_PRIMARY_AND_DYNAMIC_STANDBY];
    uint32 instanceId[DYNAMIC_PRIMARY_AND_DYNAMIC_STANDBY];
    uint32 nodeId[DYNAMIC_PRIMARY_AND_DYNAMIC_STANDBY];
    char datapath[DYNAMIC_PRIMARY_AND_DYNAMIC_STANDBY][CM_PATH_LENGTH];
} NeedQuickSwitchoverInstanceArray;

typedef struct SwitchoverOperT {
    int32 localRole;
    int32 peerRole;
} SwitchoverOper;

static const int UNEXPECTED_TIME = 120;
static const long QUICK_SWITCH_WAIT_SECONDS = 180;
static const int MAX_CONN_CMS_P = 30;

extern bool g_detailQuery;
extern bool g_coupleQuery;
extern bool switchover_all_quick;
extern ShutdownMode shutdown_mode_num;
extern bool wait_seconds_set;
extern int g_waitSeconds;
extern CM_Conn* CmServer_conn;
extern char *g_command_operation_azName;
SSDoubleClusterMode  g_ssDoubleClusterMode = SS_DOUBLE_NULL;
ClusterRole backup_open = CLUSTER_PRIMARY;

static int QueryNeedQuickSwitchInstances(int* need_quick_switchover_instance,
    NeedQuickSwitchoverInstanceArray* needQuickSwitchoverInstance, bool* is_cluster_balance,
    bool switchover_query_second);
static void GetNeedQuickSwitchInstances(const cm_to_ctl_instance_status* cm_to_ctl_instance_status_ptr,
    int* need_quick_switchover_instance, NeedQuickSwitchoverInstanceArray* needQuickSwitchoverInstance);
static int GetDatapathByInstanceId(uint32 instanceId, int instanceType, char* data_path, uint32 data_path_len);
static int JudgeInstanceRole(int instanceType, int member_index, int instance_role, const CommonOption *commCtx);
static int JudgeDatanodeStatus(uint32 node_id, const char *data_path, int db_state);
static int JudgeGtmStatus(uint32 node_id, const char *data_path, int gtm_state);
static void GetClusterMode();

static void SetSwitchoverOper(SwitchoverOper *oper, int32 localRole, uint32 instanceId)
{
    if (localRole == INSTANCE_ROLE_STANDBY) {
        if (g_ssDoubleClusterMode == SS_DOUBLE_STANDBY) {
            oper->localRole = INSTANCE_ROLE_MAIN_STANDBY;
            oper->peerRole = INSTANCE_ROLE_STANDBY;
        } else if (backup_open == CLUSTER_STREAMING_STANDBY) {
            oper->localRole = INSTANCE_ROLE_MAIN_STANDBY;
            oper->peerRole = INSTANCE_ROLE_CASCADE_STANDBY;
        } else {
            oper->localRole = INSTANCE_ROLE_PRIMARY;
            oper->peerRole = INSTANCE_ROLE_STANDBY;
        }
    } else if (localRole == INSTANCE_ROLE_CASCADE_STANDBY) {
        oper->localRole = INSTANCE_ROLE_STANDBY;
        oper->peerRole = INSTANCE_ROLE_CASCADE_STANDBY;
    }
    write_runlog(DEBUG1, "instd(%u) localRole is (%d: %s), oper[local(%d: %s), peer(%d: %s)].\n",
        instanceId, localRole, datanode_role_int_to_string(localRole), oper->localRole,
        datanode_role_int_to_string(oper->localRole), oper->peerRole, datanode_role_int_to_string(oper->peerRole));
}

static int DoSwitchoverBase(const CtlOption *ctx)
{
    int ret;
    int timePass = 0;
    int instanceType;
    int unExpectedTime = 0;
    bool success = false;
    bool hasWarning = false;
    bool switchoverFailed = false;
    char *receiveMsg = NULL;
    char inCompleteMsg[CM_MSG_ERR_INFORMATION_LENGTH] = {0};
    uint32 instanceId;
    cm_msg_type *msgType = NULL;
    ctl_to_cm_query queryMsg;
    ctl_to_cm_switchover switchoverMsg;
    cm_to_ctl_command_ack *ackMsg = NULL;
    cm_to_ctl_instance_status instStatusPtr = {0};
    cm_switchover_incomplete_msg *switchoverIncompletePtr = NULL;
    SwitchoverOper oper;
    if (g_ssDoubleClusterMode == SS_DOUBLE_STANDBY) {
        oper = {INSTANCE_ROLE_MAIN_STANDBY, INSTANCE_ROLE_STANDBY};
    } else if (backup_open == CLUSTER_STREAMING_STANDBY) {
        oper = {INSTANCE_ROLE_MAIN_STANDBY, INSTANCE_ROLE_CASCADE_STANDBY};
    } else {
        oper = {INSTANCE_ROLE_PRIMARY, INSTANCE_ROLE_STANDBY};
    }

    // return conn to cm_server
    do_conn_cmserver(false, 0);
    if (CmServer_conn == NULL) {
        write_runlog(ERROR,
            "send switchover msg to cm_server, connect fail node_id:%u, data_path:%s.\n",
            ctx->comm.nodeId,
            ctx->comm.dataPath);
        return -1;
    }

    write_runlog(DEBUG1, "send switchover msg to cms, nodeId:%u, dataPath:%s.\n", ctx->comm.nodeId, ctx->comm.dataPath);

    if (FindInstanceIdAndType(ctx->comm.nodeId, ctx->comm.dataPath, &instanceId, &instanceType) != 0) {
        write_runlog(ERROR, "can't find the node_id:%u, data_path:%s.\n", ctx->comm.nodeId, ctx->comm.dataPath);
        return -1;
    }

    if (!wait_seconds_set) {
        g_waitSeconds = SWITCHOVER_DEFAULT_WAIT;
    }

    if (ctx->switchover.switchoverFast) {
        switchoverMsg.msg_type = (int)MSG_CTL_CM_SWITCHOVER_FAST;
    } else {
        switchoverMsg.msg_type = (int)MSG_CTL_CM_SWITCHOVER;
    }

    switchoverMsg.node = ctx->comm.nodeId;
    switchoverMsg.instanceId = instanceId;
    switchoverMsg.wait_seconds = g_waitSeconds;

    if (cm_client_send_msg(CmServer_conn, 'C', (char*)&switchoverMsg, sizeof(ctl_to_cm_switchover)) != 0) {
        write_runlog(ERROR, "node(%u) send switchover msg to cms failed.\n", ctx->comm.nodeId);
        FINISH_CONNECTION((CmServer_conn), -1);
    }

    for (;;) {
        if (cm_client_flush_msg(CmServer_conn) == TCP_SOCKET_ERROR_EPIPE) {
            FINISH_CONNECTION((CmServer_conn), -1);
        }
        receiveMsg = recv_cm_server_cmd(CmServer_conn);
        if (receiveMsg != NULL) {
            msgType = (cm_msg_type*)receiveMsg;
            switch (msgType->msg_type) {
                case MSG_CM_CTL_COMMAND_ACK:
                    ackMsg = (cm_to_ctl_command_ack*)receiveMsg;
                    if (ackMsg->command_result == CM_ANOTHER_COMMAND_RUNNING) {
                        write_runlog(ERROR,
                            "can not do switchover, another command(%d) is running.\n", ackMsg->pengding_command);
                        FINISH_CONNECTION((CmServer_conn), -1);
                    }
                    if (ackMsg->command_result == CM_DN_IN_ONDEMAND_STATUE) {
                        write_runlog(ERROR,
                            "Can not switchover right now.!\n\n"
                            "HINT: cluster has entered a unexpected status, such as redo status.\n"
                            "You can wait for a while.\n");
                        FINISH_CONNECTION((CmServer_conn), -1);;
                    }
                    if (ackMsg->command_result == CM_INVALID_COMMAND) {
                        write_runlog(ERROR, "can not do switchover at current role,"
                            "You can execute \"cm_ctl query -v\" and check\n");
                        FINISH_CONNECTION((CmServer_conn), -1);
                    }
                    SetSwitchoverOper(&oper, ackMsg->pengding_command, instanceId);
                    break;

                case MSG_CM_CTL_DATA:
                    GetCtlInstanceStatusFromRecvMsg(receiveMsg, &instStatusPtr);
                    if (instStatusPtr.instance_type == INSTANCE_TYPE_PENDING) {
                        switchoverFailed = true;
                        success = true;
                        break;
                    }
                    if (instStatusPtr.instance_type == INSTANCE_TYPE_GTM) {
                        if ((instStatusPtr.gtm_member.local_status.local_role == oper.localRole) &&
                            (instStatusPtr.gtm_member.local_status.connect_status == CON_OK) &&
                            (instStatusPtr.gtm_member.local_status.sync_mode == INSTANCE_DATA_REPLICATION_SYNC)) {
                            success = true;
                        }
                    } else if (instStatusPtr.instance_type == INSTANCE_TYPE_DATANODE) {
                        if ((instStatusPtr.data_node_member.local_status.local_role == oper.localRole) &&
                            (instStatusPtr.data_node_member.sender_status[0].peer_role == oper.peerRole ||
                                instStatusPtr.data_node_member.sender_status[0].peer_role == INSTANCE_ROLE_INIT)) {
                            success = true;
                        }
                        if ((instStatusPtr.data_node_member.local_status.local_role == INSTANCE_ROLE_PENDING) ||
                            (instStatusPtr.data_node_member.sender_status[0].peer_role == INSTANCE_ROLE_PENDING)) {
                            write_runlog(ERROR, "can not do switchover at current role.\n");
                            FINISH_CONNECTION((CmServer_conn), -1);
                        }
                        if ((instStatusPtr.data_node_member.local_status.db_state != INSTANCE_HA_STATE_PROMOTING) &&
                            (instStatusPtr.data_node_member.local_status.db_state != INSTANCE_HA_STATE_WAITING) &&
                            (instStatusPtr.data_node_member.local_status.local_role == INSTANCE_ROLE_STANDBY)) {
                            unExpectedTime++;
                        } else {
                            unExpectedTime = 0;
                        }
                    }
                    break;

                case MSG_CM_CTL_SWITCHOVER_INCOMPLETE_ACK:
                    switchoverIncompletePtr = (cm_switchover_incomplete_msg*)receiveMsg;
                    ret = snprintf_s(inCompleteMsg,
                        CM_MSG_ERR_INFORMATION_LENGTH,
                        CM_MSG_ERR_INFORMATION_LENGTH - 1,
                        "%s",
                        switchoverIncompletePtr->errMsg);
                    securec_check_intval(ret, (void)ret);
                    hasWarning = true;
                    break;

                case MSG_CM_CTL_BACKUP_OPEN:
                    write_runlog(ERROR, "disable switchover in recovery mode.\n");
                    FINISH_CONNECTION((CmServer_conn), -1);

                default:
                    write_runlog(ERROR, "unknown the msg type is %d.\n", msgType->msg_type);
                    break;
            }
        }
        if (success) {
            break;
        }

        if (unExpectedTime >= UNEXPECTED_TIME) {
            write_runlog(ERROR, "failed to do switch-over. Wait the candidate to be promoted timeout.\n");
            FINISH_CONNECTION((CmServer_conn), -1);
        }

        queryMsg.msg_type = (int)MSG_CTL_CM_QUERY;
        queryMsg.node = ctx->comm.nodeId;
        queryMsg.instanceId = instanceId;
        queryMsg.instance_type = instanceType;
        queryMsg.wait_seconds = g_waitSeconds;
        queryMsg.relation = 0;
        queryMsg.detail = CLUSTER_QUERY_IN_SWITCHOVER;
        if (cm_client_send_msg(CmServer_conn, 'C', (char*)&queryMsg, sizeof(queryMsg)) != 0) {
            FINISH_CONNECTION((CmServer_conn), -1);
        }

        (void)sleep(1);
        write_runlog(LOG, ".");

        if (++timePass >= g_waitSeconds) {
            break;
        }
    }

    if (timePass >= g_waitSeconds) {
        write_runlog(ERROR,
            "switchover command timeout!\n\n"
            "HINT: Maybe the switchover action is continually running in the background.\n"
            "You can wait for a while and check the status of current cluster using "
            "\"cm_ctl query -Cv\".\n");
        CMPQfinish(CmServer_conn);
        CmServer_conn = NULL;
        return -3;
    }

    if (switchoverFailed) {
        write_runlog(ERROR,
            "Can not switchover right now.!\n\n"
            "HINT: cluster has entered a unexpected status, such as redo status.\n"
            "You can wait for a while.\n");
        CMPQfinish(CmServer_conn);
        CmServer_conn = NULL;
        return -3;
    }

    if (hasWarning) {
        write_runlog(WARNING, "switchover incomplete.\n");
        write_runlog(LOG, "%s\n", inCompleteMsg);
    } else {
        (void)sleep(5);
        write_runlog(LOG, "switchover successfully.\n");
    }
    FINISH_CONNECTION((CmServer_conn), 0);
}

/* This function switch all the standby instances with their master instances */
static int DoSwitchoverFull(const CtlOption *ctx)
{
    int ret;
    int timePass = 0;
    bool denied = false;
    bool inOnDemand = false;
    bool success = false;
    bool timeout = false;
    bool hasWarning = false;
    bool waitSwitchoverFull = false;
    char *receiveMsg = NULL;
    char inCompleteMsg[CM_MSG_ERR_INFORMATION_LENGTH] = {0};
    cm_msg_type *msgType = NULL;
    ctl_to_cm_switchover switchoverMsg = {0};
    cm_to_ctl_command_ack *ackMsg = NULL;
    cm_switchover_incomplete_msg *incompleteSwitchoverMsg = NULL;
    cm_to_ctl_switchover_full_check_ack *msgSwitchoverFullCheckAck = NULL;

    // return conn to cm_server
    do_conn_cmserver(false, 0);
    if (CmServer_conn == NULL) {
        write_runlog(ERROR, "send switchover msg to cm_server, connect fail node_id:%u, data_path:%s.\n",
            ctx->comm.nodeId,
            ctx->comm.dataPath);
        return -1;
    }

    if (!wait_seconds_set) {
        g_waitSeconds = SWITCHOVER_DEFAULT_WAIT;
    }

    switchoverMsg.msg_type = (int)MSG_CTL_CM_SWITCHOVER_FULL;
    switchoverMsg.wait_seconds = g_waitSeconds;
    if (cm_client_send_msg(CmServer_conn, 'C', (char*)&switchoverMsg, sizeof(switchoverMsg)) != 0) {
        FINISH_CONNECTION((CmServer_conn), -1);
    }

    for (;;) {
        if (cm_client_flush_msg(CmServer_conn) == TCP_SOCKET_ERROR_EPIPE) {
            FINISH_CONNECTION((CmServer_conn), -1);
        }
        receiveMsg = recv_cm_server_cmd(CmServer_conn);
        if (receiveMsg != NULL) {
            msgType = (cm_msg_type*)receiveMsg;
            switch (msgType->msg_type) {
                case MSG_CM_CTL_SWITCHOVER_FULL_DENIED:
                    denied = true;
                    break;

                case MSG_CM_CTL_SWITCHOVER_FULL_ACK:
                    ackMsg = (cm_to_ctl_command_ack*)receiveMsg;
                    if (ackMsg->command_result == CM_ANOTHER_COMMAND_RUNNING) {
                        write_runlog(ERROR, "can not do switchover, another command(%d) is running.\n",
                            ackMsg->pengding_command);
                        FINISH_CONNECTION((CmServer_conn), -1);
                    } else if (ackMsg->command_result == CM_INVALID_COMMAND) {
                        write_runlog(ERROR, "execute invalid command.\n");
                        FINISH_CONNECTION((CmServer_conn), -1);
                    } else if (ackMsg->command_result == CM_DN_IN_ONDEMAND_STATUE) { 
                        write_runlog(ERROR,
                            "Can not switchover right now.!\n\n"
                            "HINT: cluster has entered a unexpected status, such as redo status.\n"
                            "You can wait for a while.\n");
                        FINISH_CONNECTION((CmServer_conn), -1);
                        inOnDemand = true;
                    } else {
                        write_runlog(LOG, "cmserver is switching over all the master and standby pairs.\n");
                        waitSwitchoverFull = true;
                    }
                    break;

                case MSG_CM_CTL_SWITCHOVER_FULL_CHECK_ACK:
                    msgSwitchoverFullCheckAck = (cm_to_ctl_switchover_full_check_ack*)receiveMsg;
                    if (msgSwitchoverFullCheckAck->switchoverDone == SWITCHOVER_SUCCESS) {
                        success = true;
                    } else if (msgSwitchoverFullCheckAck->switchoverDone == SWITCHOVER_FAIL) {
                        write_runlog(ERROR, "failed to do switch-over: unknown reason.\n");
                        FINISH_CONNECTION((CmServer_conn), -1);
                    } else if (msgSwitchoverFullCheckAck->switchoverDone == INVALID_COMMAND) {
                        write_runlog(ERROR, "execute invalid command.\n");
                        FINISH_CONNECTION((CmServer_conn), -1);
                    }
                    break;

                case MSG_CM_CTL_SWITCHOVER_FULL_TIMEOUT_ACK:
                    timeout = true;
                    break;

                case MSG_CM_CTL_SWITCHOVER_INCOMPLETE_ACK:
                    incompleteSwitchoverMsg = (cm_switchover_incomplete_msg*)receiveMsg;
                    ret = snprintf_s(inCompleteMsg,
                        CM_MSG_ERR_INFORMATION_LENGTH,
                        CM_MSG_ERR_INFORMATION_LENGTH - 1,
                        "%s",
                        incompleteSwitchoverMsg->errMsg);
                    securec_check_intval(ret, (void)ret);
                    hasWarning = true;
                    break;

                case MSG_CM_CTL_BACKUP_OPEN:
                    write_runlog(ERROR, "disable switchover in recovery mode.\n");
                    FINISH_CONNECTION((CmServer_conn), -1);

                default:
                    write_runlog(ERROR, "unknown the msg type is %d.\n", msgType->msg_type);
                    break;
            }
        }
        if (success || denied || timeout || inOnDemand) {
            break;
        }

        /* check if the switchover is done */
        if (waitSwitchoverFull) {
            cm_msg_type msgSwitchoverFullCheck;
            msgSwitchoverFullCheck.msg_type = (int)MSG_CTL_CM_SWITCHOVER_FULL_CHECK;

            ret =
                cm_client_send_msg(CmServer_conn, 'C', (char*)&msgSwitchoverFullCheck, sizeof(msgSwitchoverFullCheck));
            if (ret != 0) {
                FINISH_CONNECTION((CmServer_conn), -1);
            }

            (void)sleep(3);
            write_runlog(LOG, ".");
            timePass += 3;
        }

        // timeout
        if (timePass == g_waitSeconds) {
            if (CmServer_conn != NULL) {
                cm_msg_type msgSwitchoverFullTimeout;
                msgSwitchoverFullTimeout.msg_type = (int)MSG_CTL_CM_SWITCHOVER_FULL_TIMEOUT;
                ret = cm_client_send_msg(
                    CmServer_conn, 'C', (char*)&msgSwitchoverFullTimeout, sizeof(msgSwitchoverFullTimeout));
                if (ret != 0) {
                    FINISH_CONNECTION((CmServer_conn), -1);
                }
            } else {
                timePass += 3;
            }
        }

        if (timePass > g_waitSeconds) {
            write_runlog(ERROR,
                "switchover command timeout!\n\n"
                "HINT: Maybe the switchover action is continually running in the background.\n"
                "You can wait for a while and check the status of current cluster using "
                "\"cm_ctl query -Cv\".\n");
            CMPQfinish(CmServer_conn);
            CmServer_conn = NULL;
            return -3;
        }
    }

    if (denied) {
        write_runlog(ERROR, "another 'switchover -A' command is running, please try again later.\n");
        CMPQfinish(CmServer_conn);
        CmServer_conn = NULL;
        return -2;
    } else if (timeout) {
        write_runlog(ERROR, "'switchover -A' command timeout.\n");
        return -3;
    } else if (inOnDemand) {
        write_runlog(ERROR, "'switchover -A' command failed due to in ondemand recovery.\n");
        return -4;
    } else {
        if (hasWarning) {
            write_runlog(WARNING, "switchover incomplete.\n");
            write_runlog(LOG, "%s\n", inCompleteMsg);
        } else {
            (void)sleep(5);
            write_runlog(LOG, "switchover -A successfully.\n");
        }
        FINISH_CONNECTION((CmServer_conn), 0);
    }
}

static int BalanceResultReq(int &timePass, bool waitBalance, int &sendCheckCount)
{
    if (waitBalance) {
        if (CmServer_conn != NULL) {
            cm_msg_type msgBalanceCheck;
            msgBalanceCheck.msg_type = (int)MSG_CTL_CM_BALANCE_CHECK;
            if (cm_client_send_msg(CmServer_conn, 'C', (char*)&msgBalanceCheck, sizeof(msgBalanceCheck)) != 0) {
                FINISH_CONNECTION_WITHOUT_EXITCODE((CmServer_conn));
            }
        }

        (void)sleep(3);
        write_runlog(LOG, ".");
        timePass += 3;
        sendCheckCount++;
    }

    if (timePass == g_waitSeconds) {
        if (CmServer_conn != NULL) {
            cm_msg_type msgBalanceResultReq;
            msgBalanceResultReq.msg_type = (int)MSG_CTL_CM_BALANCE_RESULT;
            if (cm_client_send_msg(CmServer_conn, 'C', (char*)&msgBalanceResultReq, sizeof(msgBalanceResultReq)) != 0) {
                FINISH_CONNECTION((CmServer_conn), -1);
            }
        } else {
            timePass += 3;
        }
    }

    if (timePass > g_waitSeconds) {
        write_runlog(ERROR,
            "switchover command timeout!\n\n"
            "HINT: Maybe the switchover action is continually running in the background.\n"
            "\"cm_ctl query -Cv\".\n");
        CMPQfinish(CmServer_conn);
        CmServer_conn = NULL;
        return -3;
    }
    return 0;
}

static int DoSwitchoverAll(const CtlOption *ctx)
{
    int ret;
    int timePass = 0;
    int sendCheckCount = 0;
    int getCheckAckCount = 0;
    bool retryFlag = false;
    bool hasWarning = false;
    bool waitBalance = false;
    char *receiveMsg = NULL;
    char inCompleteMsg[CM_MSG_ERR_INFORMATION_LENGTH] = {0};
    cm_msg_type* msgType = NULL;
    ctl_to_cm_switchover switchoverMsg = {0};
    cm_to_ctl_command_ack *ackMsg = NULL;
    cm_to_ctl_balance_result *msgBalanceResult = NULL;
    cm_to_ctl_balance_check_ack *msgBalanceCheckAck = NULL;
    cm_switchover_incomplete_msg *incompleteSwitchoverMsg = NULL;

    // return conn to cm_server
    do_conn_cmserver(false, 0);
    if (CmServer_conn == NULL) {
        write_runlog(ERROR,
            "send switchover msg to cm_server, connect fail node_id:%u, data_path:%s.\n",
            ctx->comm.nodeId,
            ctx->comm.dataPath);
        return -1;
    }

    if (!wait_seconds_set) {
        g_waitSeconds = SWITCHOVER_DEFAULT_WAIT;
    }

    switchoverMsg.msg_type = (int)MSG_CTL_CM_SWITCHOVER_ALL;
    switchoverMsg.wait_seconds = g_waitSeconds;
    if (cm_client_send_msg(CmServer_conn, 'C', (char*)&switchoverMsg, sizeof(switchoverMsg)) != 0) {
        FINISH_CONNECTION((CmServer_conn), -1);
    }

    // when have try, the warn will cause try.
    bool toTryForWarn = false;
    int tryTimeForWarn = 3;
    int connToCmsP = 0;

    for (;;) {
        if ((sendCheckCount - getCheckAckCount > 3 || toTryForWarn) && timePass < g_waitSeconds) {
            CMPQfinish(CmServer_conn);
            CmServer_conn = NULL;
            do_conn_cmserver(false, 0);
            if (CmServer_conn == NULL) {
                (void)sleep(3);
                write_runlog(LOG, ".");
                timePass += 3;
                connToCmsP++;
                if (connToCmsP > MAX_CONN_CMS_P) {
                    write_runlog(ERROR,
                        "send switchover msg to cm_server, connect fail node_id:%u, data_path:%s.\n",
                        ctx->comm.nodeId,
                        ctx->comm.dataPath);
                    return -1;
                }
                continue;
            }
            connToCmsP = 0;
            (void)cm_client_send_msg(CmServer_conn, 'C', (char*)&switchoverMsg, sizeof(switchoverMsg));
            sendCheckCount = 0;
            getCheckAckCount = 0;
            retryFlag = true;
            toTryForWarn = false;
        }
        if (CmServer_conn != NULL) {
            if (cm_client_flush_msg(CmServer_conn) == TCP_SOCKET_ERROR_EPIPE) {
                FINISH_CONNECTION_WITHOUT_EXITCODE((CmServer_conn));
            }
            receiveMsg = recv_cm_server_cmd(CmServer_conn);
        }
        if (receiveMsg != NULL) {
            msgType = (cm_msg_type*)receiveMsg;
            switch (msgType->msg_type) {
                case MSG_CM_CTL_SWITCHOVER_ALL_ACK:
                    ackMsg = (cm_to_ctl_command_ack*)receiveMsg;
                    if (ackMsg->command_result == CM_ANOTHER_COMMAND_RUNNING && !retryFlag) {
                        write_runlog(ERROR,
                            "can not do switchover, another command(%d) is running.\n",
                            ackMsg->pengding_command);
                        FINISH_CONNECTION((CmServer_conn), -1);;
                    } else if (ackMsg->command_result == CM_DN_IN_ONDEMAND_STATUE) {
                        write_runlog(ERROR,
                            "Can not switchover right now.!\n\n"
                            "HINT: cluster has entered a unexpected status, such as redo status.\n"
                            "You can wait for a while.\n");
                        FINISH_CONNECTION((CmServer_conn), -1);;
                    } else if (ackMsg->command_result == CM_INVALID_COMMAND) {
                        write_runlog(LOG, "execute invalid command on cluster.\n");
                        FINISH_CONNECTION((CmServer_conn), -1);
                    } else {
                        if (!retryFlag) {
                            write_runlog(LOG, "cmserver is rebalancing the cluster automatically.\n");
                        }
                        waitBalance = true;
                    }
                    break;

                case MSG_CM_CTL_BALANCE_CHECK_ACK:
                    getCheckAckCount++;
                    msgBalanceCheckAck = (cm_to_ctl_balance_check_ack*)receiveMsg;
                    if (msgBalanceCheckAck->switchoverDone == SWITCHOVER_SUCCESS) {
                        if (hasWarning && retryFlag && tryTimeForWarn > 0) {
                            --tryTimeForWarn;
                            toTryForWarn = true;
                            getCheckAckCount = 0;
                            hasWarning = false;
                            sendCheckCount = 0;
                        } else {
                            goto done;
                        }
                    } else if (msgBalanceCheckAck->switchoverDone == SWITCHOVER_FAIL) {
                        write_runlog(ERROR, "failed to do switch-over: unknown reason.\n");
                        CMPQfinish(CmServer_conn);
                        CmServer_conn = NULL;
                        return 1;
                    } else if (msgBalanceCheckAck->switchoverDone == SWITCHOVER_PARTLY_SUCCESS) {
                        (void)sleep(5);
#ifdef ENABLE_MULTIPLE_NODES
                        write_runlog(LOG, "switchover partly successfully.\n");
#else
                        write_runlog(LOG, "switchover failed.\n");
#endif
                        CMPQfinish(CmServer_conn);
                        CmServer_conn = NULL;
                        return 1;
                    } else if (msgBalanceCheckAck->switchoverDone == SWITCHOVER_ABNORMAL) {
#ifndef SWITCHOVER_ABNORMAL_TIMEOUT
#define SWITCHOVER_ABNORMAL_TIMEOUT 120
#endif
                        if (timePass >= SWITCHOVER_ABNORMAL_TIMEOUT) {
                            write_runlog(ERROR, "switchover failed: abnormal init primary.\n");
                            CMPQfinish(CmServer_conn);
                            CmServer_conn = NULL;
                            return -3;
                        }
                    } else if (msgBalanceCheckAck->switchoverDone == SWITCHOVER_CANNOT_RESPONSE) {
                        write_runlog(ERROR,
                            "Can not switchover right now.!\n\n"
                            "HINT: cluster has entered a unexpected status, such as redo status.\n"
                            "You can wait for a while.\n");
                        CMPQfinish(CmServer_conn);
                        CmServer_conn = NULL;
                        return 1;
                    }
                    break;

                case MSG_CM_CTL_BALANCE_RESULT_ACK:
                    msgBalanceResult = (cm_to_ctl_balance_result*)receiveMsg;
                    if (msgBalanceResult->imbalanceCount > 0) {
                        write_runlog(ERROR,
                            "%d instances have not been switched completely in %d seconds:\n",
                            msgBalanceResult->imbalanceCount,
                            timePass);

                        for (int i = 0; i < msgBalanceResult->imbalanceCount; i++) {
                            write_runlog(LOG, " instance: %u\n", msgBalanceResult->instances[i]);
                        }

                        write_runlog(LOG,
                            "use \"cm_ctl query -v -C -s\" or primary cms log to check out the detail\n");
                        CMPQfinish(CmServer_conn);
                        CmServer_conn = NULL;
                        return 1;
                    } else {
                        goto done;
                    }

                case MSG_CM_CTL_SWITCHOVER_INCOMPLETE_ACK:
                    incompleteSwitchoverMsg = (cm_switchover_incomplete_msg*)receiveMsg;
                    ret = snprintf_s(inCompleteMsg,
                        CM_MSG_ERR_INFORMATION_LENGTH,
                        CM_MSG_ERR_INFORMATION_LENGTH - 1,
                        "%s",
                        incompleteSwitchoverMsg->errMsg);
                    securec_check_intval(ret, (void)ret);
                    hasWarning = true;
                    break;

                case MSG_CM_CTL_BACKUP_OPEN:
                    write_runlog(LOG, "disable switchover in recovery mode.\n");
                    CMPQfinish(CmServer_conn);
                    CmServer_conn = NULL;
                    return -1;

                default:
                    write_runlog(ERROR, "unknown the msg type is %d.\n", msgType->msg_type);
                    break;
            }
        }

        ret = BalanceResultReq(timePass, waitBalance, sendCheckCount);
        if (ret < 0) {
            return ret;
        }
    }

done:
    (void)sleep(5);
    write_runlog(LOG, "switchover successfully.\n");
    CMPQfinish(CmServer_conn);
    CmServer_conn = NULL;
    return 0;
}

/*
 * switchover all GTM and DN's primary instances to an availability zone.
 */
static int DoSwitchoverAz(const char *azName, const CtlOption *ctx)
{
    int ret;
    int timePass = 0;
    bool denied = false;
    bool success = false;
    bool timeout = false;
    bool hasWarning = false;
    bool waitSwitchoverAz = false;
    char *receiveMsg = NULL;
    char inCompleteMsg[CM_MSG_ERR_INFORMATION_LENGTH] = {0};
    errno_t rc;
    cm_msg_type *msgType = NULL;
    ctl_to_cm_switchover switchoverMsg = {0};
    cm_switchover_incomplete_msg *incompleteSwitchoverMsg = NULL;
    cm_to_ctl_switchover_az_check_ack *msgSwitchoverAZCheckAck = NULL;
    const int errRet = -4;

    // return conn to cm_server
    do_conn_cmserver(false, 0);
    if (CmServer_conn == NULL) {
        write_runlog(ERROR, "send switchover msg to cm_server, connect fail node_id:%u, data_path:%s.\n",
            ctx->comm.nodeId,
            ctx->comm.dataPath);
        return -1;
    }

    if (!wait_seconds_set) {
        g_waitSeconds = SWITCHOVER_DEFAULT_WAIT;
    }

    switchoverMsg.msg_type = (int)MSG_CTL_CM_SWITCHOVER_AZ;
    rc = strcpy_s(switchoverMsg.azName, CM_AZ_NAME, azName);
    securec_check_errno(rc, (void)rc);
    switchoverMsg.wait_seconds = g_waitSeconds;
    if (cm_client_send_msg(CmServer_conn, 'C', (char*)&switchoverMsg, sizeof(switchoverMsg)) != 0) {
        FINISH_CONNECTION((CmServer_conn), -1);
    }

    int getCheckAckCount = 0;
    int sendCheckCount = 0;
    bool retryFlag = false;
    // when have try, the warn will cause try.
    bool toTryForWarn = false;
    int tryTimeForWarn = 3;

    for (;;) {
        if ((sendCheckCount - getCheckAckCount > 3 || toTryForWarn) && timePass < g_waitSeconds) {
            CMPQfinish(CmServer_conn);
            CmServer_conn = NULL;
            do_conn_cmserver(false, 0);
            if (CmServer_conn == NULL) {
                (void)sleep(3);
                write_runlog(LOG, ".");
                timePass += 3;
                continue;
            }
            ret = cm_client_send_msg(CmServer_conn, 'C', (char*)&switchoverMsg, sizeof(switchoverMsg));
            sendCheckCount = 0;
            getCheckAckCount = 0;
            retryFlag = true;
            toTryForWarn = false;
        }
        if (cm_client_flush_msg(CmServer_conn) == TCP_SOCKET_ERROR_EPIPE) {
            CMPQfinish(CmServer_conn);
            CmServer_conn = NULL;
        }
        receiveMsg = recv_cm_server_cmd(CmServer_conn);
        if (receiveMsg != NULL) {
            msgType = (cm_msg_type*)receiveMsg;
            switch (msgType->msg_type) {
                case MSG_CM_CTL_SWITCHOVER_AZ_DENIED:
                    if (!retryFlag) {
                        denied = true;
                    }
                    break;
                case MSG_CM_CTL_SWITCHOVER_AZ_ACK:
                    if (!retryFlag) {
#ifdef ENABLE_MULTIPLE_NODES
                        write_runlog(LOG, "cmserver is switching over all the primary GTM and DN to %s.\n", azName);
#else
                        write_runlog(LOG, "cmserver is switching over all the primary DN to %s.\n", azName);
#endif
                    }
                    waitSwitchoverAz = true;
                    break;

                case MSG_CM_CTL_SWITCHOVER_AZ_CHECK_ACK:
                    getCheckAckCount++;
                    msgSwitchoverAZCheckAck = (cm_to_ctl_switchover_az_check_ack*)receiveMsg;
                    if (msgSwitchoverAZCheckAck->switchoverDone == SWITCHOVER_SUCCESS) {
                        if (hasWarning && retryFlag && tryTimeForWarn > 0) {
                            // has warning ,will try
                            --tryTimeForWarn;
                            getCheckAckCount = 0;
                            toTryForWarn = true;
                            hasWarning = false;
                            sendCheckCount++;
                        } else {
                            success = true;
                        }
                    } else if (msgSwitchoverAZCheckAck->switchoverDone == SWITCHOVER_FAIL) {
                        write_runlog(ERROR, "failed to do switch-over: unknown reason.\n");
                        CMPQfinish(CmServer_conn);
                        CmServer_conn = NULL;
                        return errRet;
                    } else if (msgSwitchoverAZCheckAck->switchoverDone == INVALID_COMMAND) {
                        write_runlog(ERROR, "execute invalid command.\n");
                        CMPQfinish(CmServer_conn);
                        CmServer_conn = NULL;
                        return errRet;
                    }
                    break;

                case MSG_CM_CTL_SWITCHOVER_AZ_TIMEOUT_ACK:
                    timeout = true;
                    break;

                case MSG_CM_CTL_SWITCHOVER_INCOMPLETE_ACK:
                    incompleteSwitchoverMsg = (cm_switchover_incomplete_msg*)receiveMsg;
                    ret = snprintf_s(inCompleteMsg, CM_MSG_ERR_INFORMATION_LENGTH, CM_MSG_ERR_INFORMATION_LENGTH - 1,
                        "%s", incompleteSwitchoverMsg->errMsg);
                    securec_check_intval(ret, (void)ret);
                    hasWarning = true;
                    break;

                case MSG_CM_CTL_BACKUP_OPEN:
                    CMPQfinish(CmServer_conn);
                    CmServer_conn = NULL;
                    write_runlog(ERROR, "disable switchover in recovery mode.\n");
                    return -1;
                case MSG_CM_CTL_INVALID_COMMAND_ACK:
                    CMPQfinish(CmServer_conn);
                    CmServer_conn = NULL;
                    write_runlog(ERROR, "cannot switchover to vote AZ.\n");
                    return -1;
                case MSG_CM_AGENT_DN_SYNC_LIST:
                    CMPQfinish(CmServer_conn);
                    CmServer_conn = NULL;
                    write_runlog(ERROR, "cannot switchover in process of modifying syncList.\n");
                    return -1;

                default:
                    write_runlog(ERROR, "unknown the msg type is %d.\n", msgType->msg_type);
                    break;
            }
        }
        if (success || denied || timeout) {
            break;
        }

        if (timePass < g_waitSeconds) {
            /* check if the switchover is done */
            if (waitSwitchoverAz && (CmServer_conn != NULL)) {
                cm_msg_type msgSwitchoverAZCheck;
                msgSwitchoverAZCheck.msg_type = (int)MSG_CTL_CM_SWITCHOVER_AZ_CHECK;

                ret =
                    cm_client_send_msg(CmServer_conn, 'C', (char*)&msgSwitchoverAZCheck, sizeof(msgSwitchoverAZCheck));
                if (ret != 0) {
                    CMPQfinish(CmServer_conn);
                    CmServer_conn = NULL;
                }
            }
            sendCheckCount++;
        } else if (timePass == g_waitSeconds) {
            if (CmServer_conn != NULL) {
                cm_msg_type msgSwitchoverAZTimeout;
                msgSwitchoverAZTimeout.msg_type = (int)MSG_CTL_CM_SWITCHOVER_AZ_TIMEOUT;

                ret = cm_client_send_msg(
                    CmServer_conn, 'C', (char*)&msgSwitchoverAZTimeout, sizeof(msgSwitchoverAZTimeout));
                if (ret != 0) {
                    CMPQfinish(CmServer_conn);
                    CmServer_conn = NULL;
                }
            } else {
                timePass += 3;
            }
        } else {
            write_runlog(ERROR, "switchover -z %s command timeout.\n", azName);
            CMPQfinish(CmServer_conn);
            CmServer_conn = NULL;
            return -3;
        }

        (void)sleep(3);
        write_runlog(LOG, ".");
        timePass += 3;
    }

    if (denied) {
        write_runlog(ERROR, "another 'switchover -z' command is running, please try again later.\n");
        CMPQfinish(CmServer_conn);
        CmServer_conn = NULL;
        return -2;
    } else if (timeout) {
        write_runlog(ERROR, "'switchover -z %s' command timeout.\n", azName);
        CMPQfinish(CmServer_conn);
        CmServer_conn = NULL;
        return -3;
    } else {
        if (hasWarning) {
            write_runlog(WARNING, "switchover incomplete.\n");
            write_runlog(LOG, "%s\n", inCompleteMsg);
        } else {
            (void)sleep(5);
            write_runlog(LOG, "switchover -z %s successfully.\n", azName);
        }
        CMPQfinish(CmServer_conn);
        CmServer_conn = NULL;
        return 0;
    }
}

static int DoSwitchoverQuick(const CtlOption *ctx)
{
    int ret = 0;
    int instanceType = 0;
    int commandResult;
    int memberIndexStandby;
    int memberIndexPrimary = 0;
    bool successFlag = false;
    char dataPath[CM_PATH_LENGTH] = {0};
    uint32 nodeId = 0;
    uint32 instanceId = 0;
    uint32 needFailoverInstanceId;
    cm_to_ctl_get_datanode_relation_ack getInstanceMsg = {0};
    shutdown_mode_num = IMMEDIATE_MODE;

    /*

     * 1: In the single-primary-multi-standby cluster mode, the dn whose xlog is the largest will be chose to promote.
     * 2: If the dn whose xlog isn't the largest promote to primary, there will be a risk of data loss.

     *    So, in the single-primary-multi-standby cluster mode, the quick switchover will be forbidden.
    */
    if (g_multi_az_cluster) {
        write_runlog(
            ERROR, "Quick switchover is not applicable to single-primary-multi-standby cluster and cm_ctl exit.\n");
        return -1;
    }

    /* get the instance info through server */
    if (GetDatanodeRelationInfo(ctx->comm.nodeId, ctx->comm.dataPath, &getInstanceMsg) == -1) {
        write_runlog(ERROR, "can not get datanode information.\n");
        return -1;
    }
    memberIndexStandby = getInstanceMsg.member_index;

    needFailoverInstanceId = getInstanceMsg.instanceMember[memberIndexStandby].instanceId;
    commandResult = getInstanceMsg.command_result;
    if (commandResult == CM_INVALID_COMMAND) {
        write_runlog(ERROR, "can not do quick switchover at current role.\n");
        FINISH_CONNECTION((CmServer_conn), -1);
    }

    for (int i = 0; i < CM_PRIMARY_STANDBY_MAX_NUM; i++) {
        if (getInstanceMsg.instanceMember[i].role == INSTANCE_ROLE_PRIMARY) {
            instanceId = getInstanceMsg.instanceMember[i].instanceId;
            nodeId = getInstanceMsg.instanceMember[i].node;
            instanceType = getInstanceMsg.instanceMember[i].instanceType;
            memberIndexPrimary = i;
            break;
        }
    }

    if (instanceType == INSTANCE_TYPE_DATANODE) {
        write_runlog(LOG, "this operation requires the datanode standby xlog information to be up to date.\n");
    }

    if (instanceType == INSTANCE_TYPE_GTM) {
        // etcd majority failure and gtm can't do quick switchover
        if (!CheckDdbHealth()) {
            write_runlog(ERROR, "etcd majority failure and instance gtm can't do quick switchover.\n");
            return -1;
        }
    }

    // get the instance path and stop the primary instance
    if (GetDatapathByInstanceId(instanceId, instanceType, dataPath, sizeof(dataPath)) < 0) {
        write_runlog(ERROR, "get dataPath file, datapath is NULL.\n");
        return -1;
    }

    // check the standby instance status, abnormal can't do switchover
    if (instanceType == INSTANCE_TYPE_DATANODE) {
        ret =
            (getInstanceMsg.data_node_member[memberIndexStandby].local_status.db_state == INSTANCE_HA_STATE_NORMAL)
                ? 0 : -1;
    } else if (instanceType == INSTANCE_TYPE_GTM) {
        ret = (getInstanceMsg.gtm_member[memberIndexStandby].local_status.connect_status == CON_OK) ? 0 : -1;
    }
    if (ret == -1) {
        write_runlog(ERROR, "the standby instance status is abnormal and can't do switchover.\n");
        return -1;
    }

    // stop the primary instance;
    stop_instance(nodeId, dataPath);
    struct timespec checkBegin;
    (void)clock_gettime(CLOCK_MONOTONIC, &checkBegin);

    for (;;) {
        write_runlog(LOG, ".");
        ret = JudgeInstanceRole(instanceType, memberIndexStandby, INSTANCE_ROLE_PRIMARY, &ctx->comm);
        if (ret == 0) {
            write_runlog(LOG, "quick switchover instance %u successful.\n", needFailoverInstanceId);
            successFlag = true;
            break;
        }

        struct timespec checkEnd;
        (void)clock_gettime(CLOCK_MONOTONIC, &checkEnd);
        long sleepTime = checkEnd.tv_sec - checkBegin.tv_sec;
        if (sleepTime > QUICK_SWITCH_WAIT_SECONDS) {
            write_runlog(ERROR, "quick switchover one instance command failed in %ld s.\n", QUICK_SWITCH_WAIT_SECONDS);
            break;
        }
    }

    start_instance(nodeId, dataPath);
    write_runlog(LOG, "now start the stopped instance.\n");

    for (;;) {
        if (successFlag) {
            ret = JudgeInstanceRole(instanceType, memberIndexPrimary, INSTANCE_ROLE_STANDBY, &ctx->comm);
        } else {
            ret = JudgeInstanceRole(instanceType, memberIndexPrimary, INSTANCE_ROLE_PRIMARY, &ctx->comm);
        }
        if (ret == 0) {
            break;
        }

        struct timespec checkEnd = {0, 0};
        (void)clock_gettime(CLOCK_MONOTONIC, &checkEnd);
        long sleepTime = checkEnd.tv_sec - checkBegin.tv_sec;
        if (sleepTime > QUICK_SWITCH_WAIT_SECONDS) {
            write_runlog(ERROR, "final start the instance timeout in %ld s.\n", QUICK_SWITCH_WAIT_SECONDS);
            return -1;
        }
    }
    return 0;
}

static int DoSwitchoverAllQuick()
{
    int ret;
    int needQuickSwitchoverNum = 0;
    bool isClusterBalance = false;
    bool switchoverQuerySecond = false;
    g_coupleQuery = true;
    g_detailQuery = true;
    shutdown_mode_num = IMMEDIATE_MODE;

    /*
     * 1: In the single-primary-multi-standby cluster mode, the dn whose xlog is the largest will be chose to promote.
     * 2: If the dn whose xlog isn't the largest promote to primary, there will be a risk of data loss.
     * So, in the single-primary-multi-standby cluster mode, the quick switchover will be forbidden.
    */
    if (g_multi_az_cluster) {
        write_runlog(
            ERROR, "Quick all switchover is not applicable to single-primary-multi-standby cluster and cm_ctl exit.\n");
        return 0;
    }

    NeedQuickSwitchoverInstanceArray* needQuickSwitchoverInstance = (NeedQuickSwitchoverInstanceArray*)pg_malloc(
        sizeof(NeedQuickSwitchoverInstanceArray) * g_node_num * CM_MAX_INSTANCE_PER_NODE);

    ret = memset_s(needQuickSwitchoverInstance,
        sizeof(NeedQuickSwitchoverInstanceArray) * g_node_num * CM_MAX_INSTANCE_PER_NODE,
        0,
        sizeof(NeedQuickSwitchoverInstanceArray) * g_node_num * CM_MAX_INSTANCE_PER_NODE);
    securec_check_errno(ret, (void)ret);

    write_runlog(LOG, "Now process is rebalancing the cluster automatically.\n");

    ret = QueryNeedQuickSwitchInstances(
        &needQuickSwitchoverNum, needQuickSwitchoverInstance, &isClusterBalance, switchoverQuerySecond);
    if (ret == -1) {
        write_runlog(ERROR, "Failed to query instances need quick switchover.\n");
        FREE_AND_RESET(needQuickSwitchoverInstance);
        return -1;
    }

    if (needQuickSwitchoverNum == 0) {
        write_runlog(LOG, "there are no instances need to balance.\n");
        FREE_AND_RESET(needQuickSwitchoverInstance);
        return 0;
    }

    write_runlog(LOG, "this operation requires the standby datanode xlog information to be up to date.\n");

    struct timespec checkBegin = {0, 0};
    (void)clock_gettime(CLOCK_MONOTONIC, &checkBegin);

    for (int i = 0; i < needQuickSwitchoverNum; i++) {
        ret = -1;
        if (needQuickSwitchoverInstance[i].instance_type[DYNAMIC_STANDBY] == INSTANCE_TYPE_DATANODE) {
            ret = JudgeDatanodeStatus(needQuickSwitchoverInstance[i].nodeId[DYNAMIC_STANDBY],
                needQuickSwitchoverInstance[i].datapath[DYNAMIC_STANDBY],
                INSTANCE_HA_STATE_NORMAL);
        } else if (needQuickSwitchoverInstance[i].instance_type[DYNAMIC_STANDBY] == INSTANCE_TYPE_GTM) {
            ret = JudgeGtmStatus(needQuickSwitchoverInstance[i].nodeId[DYNAMIC_STANDBY],
                needQuickSwitchoverInstance[i].datapath[DYNAMIC_STANDBY],
                CON_OK);
        }
        if (ret != 0) {
            write_runlog(ERROR, "the primary instance %u's peer is abnormal and can't do switchover.\n",
                needQuickSwitchoverInstance[i].instanceId[DYNAMIC_PRIMARY]);
            continue;
        }
        stop_instance(needQuickSwitchoverInstance[i].nodeId[DYNAMIC_PRIMARY],
            needQuickSwitchoverInstance[i].datapath[DYNAMIC_PRIMARY]);
    }

    switchoverQuerySecond = true;

    for (;;) {
        int rcs;
        write_runlog(LOG, ".");
        if (isClusterBalance) {
            write_runlog(LOG, "quick switchover -a successful.\n");
            break;
        } else {
            rcs = QueryNeedQuickSwitchInstances(&needQuickSwitchoverNum,
                needQuickSwitchoverInstance,
                &isClusterBalance, switchoverQuerySecond);
            if (rcs == -1) {
                write_runlog(
                    ERROR, "query the instance status failed, please try to run the quick switchover command again.\n");
                for (int j = 0; j < needQuickSwitchoverNum; j++) {
                    start_instance(needQuickSwitchoverInstance[j].nodeId[DYNAMIC_PRIMARY],

                        needQuickSwitchoverInstance[j].datapath[DYNAMIC_PRIMARY]);
                }
                FREE_AND_RESET(needQuickSwitchoverInstance);
                return -1;
            }
            (void)sleep(1);

            struct timespec checkEnd = {0, 0};
            (void)clock_gettime(CLOCK_MONOTONIC, &checkEnd);
            long sleepTime = checkEnd.tv_sec - checkBegin.tv_sec;

            /* the PROMOTING_TIME is ensure dn has failovered, it's must lager than the sum of instance heartbeat time
               15s and failover heartbeat time 0s so we set 100s */
            if (sleepTime > PROMOTING_TIME && sleepTime < QUICK_SWITCH_WAIT_SECONDS) {
                for (int j = 0; j < needQuickSwitchoverNum; j++) {
                    start_instance(needQuickSwitchoverInstance[j].nodeId[DYNAMIC_PRIMARY],

                        needQuickSwitchoverInstance[j].datapath[DYNAMIC_PRIMARY]);
                }
            }

            if (sleepTime > QUICK_SWITCH_WAIT_SECONDS) {
                write_runlog(ERROR, "quick switchover command failed in %ld s.\n", QUICK_SWITCH_WAIT_SECONDS);
                break;
            }
        }
    }

    // if quick switchover -a successful, will start the instances in advance
    for (int j = 0; j < needQuickSwitchoverNum; j++) {
        start_instance(needQuickSwitchoverInstance[j].nodeId[DYNAMIC_PRIMARY],
            needQuickSwitchoverInstance[j].datapath[DYNAMIC_PRIMARY]);
    }

    for (int j = 0; j < needQuickSwitchoverNum; j++) {
        for (;;) {
            int stc = 0;
            (void)sleep(1);
            if (needQuickSwitchoverInstance[j].instance_type[DYNAMIC_PRIMARY] == INSTANCE_TYPE_DATANODE) {
                stc = JudgeDatanodeStatus(needQuickSwitchoverInstance[j].nodeId[DYNAMIC_PRIMARY],
                    needQuickSwitchoverInstance[j].datapath[DYNAMIC_PRIMARY],
                    INSTANCE_HA_STATE_NORMAL);
            } else if (needQuickSwitchoverInstance[j].instance_type[DYNAMIC_PRIMARY] == INSTANCE_TYPE_GTM) {
                stc = JudgeGtmStatus(needQuickSwitchoverInstance[j].nodeId[DYNAMIC_PRIMARY],
                    needQuickSwitchoverInstance[j].datapath[DYNAMIC_PRIMARY],
                    CON_OK);
            }
            if (stc == 0) {
                break;
            }

            struct timespec checkEnd = {0, 0};
            (void)clock_gettime(CLOCK_MONOTONIC, &checkEnd);
            long sleepTime = checkEnd.tv_sec - checkBegin.tv_sec;
            if (sleepTime > QUICK_SWITCH_WAIT_SECONDS) {
                write_runlog(
                    ERROR, "switchover -a final start the instance timeout in %ld s.\n", QUICK_SWITCH_WAIT_SECONDS);
                FREE_AND_RESET(needQuickSwitchoverInstance);
                return -1;
            }
        }
    }
    FREE_AND_RESET(needQuickSwitchoverInstance);
    return 0;
}

static int QueryNeedQuickSwitchInstances(int* need_quick_switchover_instance,
    NeedQuickSwitchoverInstanceArray* needQuickSwitchoverInstance, bool* is_cluster_balance,
    bool switchover_query_second)
{
    ctl_to_cm_query queryMsg;
    int wait_time;
    char* receiveMsg = NULL;
    cm_msg_type *msgType = NULL;
    cm_to_ctl_instance_status cm_to_ctl_instance_status_ptr = {0};
    cm_to_ctl_cluster_status *cm_to_ctl_cluster_status_ptr = NULL;
    int ret;

    /* return conn to cm_server */
    do_conn_cmserver(false, 0);
    if (CmServer_conn == NULL) {
        write_runlog(ERROR, "quick switchover -a query connect cms failed is NULL.");
        return -1;
    }

    queryMsg.msg_type = (int)MSG_CTL_CM_QUERY;
    queryMsg.node = INVALID_NODE_NUM;
    queryMsg.instanceId = INVALID_INSTACNE_NUM;
    queryMsg.wait_seconds = g_waitSeconds;
    queryMsg.detail = CLUSTER_COUPLE_DETAIL_STATUS_QUERY;
    queryMsg.relation = 0;

    ret = cm_client_send_msg(CmServer_conn, 'C', (char*)&queryMsg, sizeof(queryMsg));
    if (ret != 0) {
        write_runlog(ERROR, "Failed to send message \"%s\" to the CM Server.\n", "MSG_CTL_CM_QUERY");
        FINISH_CONNECTION((CmServer_conn), -1);
    }

    CmSleep(1);

    wait_time = g_waitSeconds * 1000;
    bool rec_data_end = false;
    for (; wait_time > 0;) {
        ret = cm_client_flush_msg(CmServer_conn);
        if (ret == TCP_SOCKET_ERROR_EPIPE) {
            write_runlog(ERROR, "Failed to flush message to the CM Server.\n");
            FINISH_CONNECTION((CmServer_conn), -1);
        }

        receiveMsg = recv_cm_server_cmd(CmServer_conn);
        while (receiveMsg != NULL) {
            msgType = (cm_msg_type*)receiveMsg;
            switch (msgType->msg_type) {
                case MSG_CM_CTL_DATA_BEGIN:
                    cm_to_ctl_cluster_status_ptr = (cm_to_ctl_cluster_status *)receiveMsg;
                    if (switchover_query_second) {
                        if (cm_to_ctl_cluster_status_ptr->switchedCount == 0) {
                            *is_cluster_balance = true;
                        } else {
                            *is_cluster_balance = false;
                        }
                        FINISH_CONNECTION((CmServer_conn), 0);
                    } else {
                        if (cm_to_ctl_cluster_status_ptr->switchedCount == 0) {
                            *is_cluster_balance = true;
                        }
                    }
                    break;
                case MSG_CM_CTL_DATA:
                    GetCtlInstanceStatusFromRecvMsg(receiveMsg, &cm_to_ctl_instance_status_ptr);
                    GetNeedQuickSwitchInstances(
                        &cm_to_ctl_instance_status_ptr, need_quick_switchover_instance, needQuickSwitchoverInstance);
                    break;
                case MSG_CM_CTL_NODE_END:
                    break;
                case MSG_CM_CTL_DATA_END:
                    rec_data_end = true;
                    break;
                default:
                    write_runlog(WARNING,
                        "Receive an unrecognized message type \"%d\" from CM Server.\n",
                        msgType->msg_type);
            }
            receiveMsg = recv_cm_server_cmd(CmServer_conn);
        }
        if (rec_data_end) {
            break;
        }

        CmSleep(1);
        wait_time--;
        if (wait_time <= 0) {
            break;
        }
    }

    if (wait_time <= 0) {
        write_runlog(ERROR, "Time out to get the needed response of the message MSG_CTL_CM_QUERY from CM Server.\n");
        FINISH_CONNECTION((CmServer_conn), -1);
    }

    FINISH_CONNECTION((CmServer_conn), 0);
}

static void GetNeedQuickSwitchInstances(const cm_to_ctl_instance_status* cm_to_ctl_instance_status_ptr,
    int* need_quick_switchover_instance, NeedQuickSwitchoverInstanceArray* needQuickSwitchoverInstance)
{
    uint32 i;
    uint32 j;
    uint32 node_index = 0;
    uint32 instance_index = 0;
    errno_t rc = 0;
    errno_t src = 0;

    for (i = 0; i < g_node_num; i++) {
        if (g_node[i].node == cm_to_ctl_instance_status_ptr->node) {
            node_index = i;
            break;
        }
    }

    if (i >= g_node_num) {
        write_runlog(ERROR, "Can not find the node information by the node id %u.\n",
            cm_to_ctl_instance_status_ptr->node);
        return;
    }

    if (cm_to_ctl_instance_status_ptr->instance_type == INSTANCE_TYPE_GTM) {
        // etcd majority failure and gtm can't do quick switchover
        if (!CheckDdbHealth()) {
            write_runlog(ERROR, "switchover -a etcd majority failure and instance gtm can't do quick switchover, "
                "so we don't get the gtm information.\n");
        } else {
            if (strcmp(datanode_static_role_int_to_string(g_node[node_index].gtmRole), "S") == 0 &&

                strcmp(datanode_role_int_to_string(cm_to_ctl_instance_status_ptr->gtm_member.local_status.local_role),
                    "Primary") == 0) {
                needQuickSwitchoverInstance[*need_quick_switchover_instance].instance_type[DYNAMIC_PRIMARY] =
                    INSTANCE_TYPE_GTM;
                needQuickSwitchoverInstance[*need_quick_switchover_instance].instanceId[DYNAMIC_PRIMARY] =
                    cm_to_ctl_instance_status_ptr->instanceId;
                needQuickSwitchoverInstance[*need_quick_switchover_instance].nodeId[DYNAMIC_PRIMARY] =
                    g_node[node_index].node;
                rc = strncpy_s(needQuickSwitchoverInstance[*need_quick_switchover_instance].datapath[DYNAMIC_PRIMARY],
                    CM_PATH_LENGTH, g_node[node_index].gtmLocalDataPath, CM_PATH_LENGTH - 1);
                securec_check_errno(rc, (void)rc);

                (*need_quick_switchover_instance)++;
            }
            if (strcmp(datanode_static_role_int_to_string(g_node[node_index].gtmRole), "P") == 0 &&

                strcmp(datanode_role_int_to_string(cm_to_ctl_instance_status_ptr->gtm_member.local_status.local_role),
                    "Standby") == 0) {
                if (*need_quick_switchover_instance == 1) {
                    needQuickSwitchoverInstance[*need_quick_switchover_instance - 1].instance_type[DYNAMIC_STANDBY] =
                        INSTANCE_TYPE_GTM;
                    needQuickSwitchoverInstance[*need_quick_switchover_instance - 1].instanceId[DYNAMIC_STANDBY] =
                        cm_to_ctl_instance_status_ptr->instanceId;
                    needQuickSwitchoverInstance[*need_quick_switchover_instance - 1].nodeId[DYNAMIC_STANDBY] =
                        g_node[node_index].node;
                    rc = strncpy_s(
                        needQuickSwitchoverInstance[*need_quick_switchover_instance - 1].datapath[DYNAMIC_STANDBY],
                        CM_PATH_LENGTH, g_node[node_index].gtmLocalDataPath, CM_PATH_LENGTH - 1);
                    securec_check_errno(rc, (void)rc);
                } else {
                    needQuickSwitchoverInstance[*need_quick_switchover_instance].instance_type[DYNAMIC_STANDBY] =
                        INSTANCE_TYPE_GTM;
                    needQuickSwitchoverInstance[*need_quick_switchover_instance].instanceId[DYNAMIC_STANDBY] =
                        cm_to_ctl_instance_status_ptr->instanceId;
                    needQuickSwitchoverInstance[*need_quick_switchover_instance].nodeId[DYNAMIC_STANDBY] =
                        g_node[node_index].node;
                    rc = strncpy_s(
                        needQuickSwitchoverInstance[*need_quick_switchover_instance].datapath[DYNAMIC_STANDBY],
                        CM_PATH_LENGTH, g_node[node_index].gtmLocalDataPath, CM_PATH_LENGTH - 1);
                    securec_check_errno(rc, (void)rc);
                }
            }
        }
    }

    if (cm_to_ctl_instance_status_ptr->instance_type == INSTANCE_TYPE_DATANODE) {
        for (j = 0; j < g_node[node_index].datanodeCount; j++) {
            if (g_node[node_index].datanode[j].datanodeId == cm_to_ctl_instance_status_ptr->instanceId) {
                instance_index = j;
                break;
            }
        }

        if (j >= g_node[node_index].datanodeCount) {
            write_runlog(ERROR,
                "Can not find the instance with the instance id %u and instance type %d on the node %u.\n",
                cm_to_ctl_instance_status_ptr->instanceId,

                INSTANCE_TYPE_DATANODE,

                g_node[node_index].node);
            return;
        }

        if (strcmp(datanode_static_role_int_to_string(g_node[node_index].datanode[instance_index].datanodeRole), "S") ==
                0 &&

            strcmp(datanode_role_int_to_string(cm_to_ctl_instance_status_ptr->data_node_member.local_status.local_role),
                "Primary") == 0) {
            needQuickSwitchoverInstance[*need_quick_switchover_instance].instance_type[DYNAMIC_PRIMARY] =
                INSTANCE_TYPE_DATANODE;
            needQuickSwitchoverInstance[*need_quick_switchover_instance].instanceId[DYNAMIC_PRIMARY] =
                cm_to_ctl_instance_status_ptr->instanceId;
            needQuickSwitchoverInstance[*need_quick_switchover_instance].nodeId[DYNAMIC_PRIMARY] =
                g_node[node_index].node;
            src = strncpy_s(needQuickSwitchoverInstance[*need_quick_switchover_instance].datapath[DYNAMIC_PRIMARY],
                CM_PATH_LENGTH,
                g_node[node_index].datanode[instance_index].datanodeLocalDataPath,
                CM_PATH_LENGTH - 1);
            securec_check_errno(src, (void)src);
            (*need_quick_switchover_instance)++;
        }
        if (strcmp(datanode_static_role_int_to_string(g_node[node_index].datanode[instance_index].datanodeRole), "P") ==
                0 &&

            strcmp(datanode_role_int_to_string(cm_to_ctl_instance_status_ptr->data_node_member.local_status.local_role),
                "Standby") == 0) {
            needQuickSwitchoverInstance[*need_quick_switchover_instance].instance_type[DYNAMIC_STANDBY] =
                INSTANCE_TYPE_DATANODE;
            needQuickSwitchoverInstance[*need_quick_switchover_instance].instanceId[DYNAMIC_STANDBY] =
                cm_to_ctl_instance_status_ptr->instanceId;
            needQuickSwitchoverInstance[*need_quick_switchover_instance].nodeId[DYNAMIC_STANDBY] =
                g_node[node_index].node;
            src = strncpy_s(needQuickSwitchoverInstance[*need_quick_switchover_instance].datapath[DYNAMIC_STANDBY],
                CM_PATH_LENGTH,
                g_node[node_index].datanode[instance_index].datanodeLocalDataPath,
                CM_PATH_LENGTH - 1);
            securec_check_errno(src, (void)src);
        }
    }

    return;
}

static int JudgeInstanceRole(int instanceType, int member_index, int instance_role, const CommonOption *commCtx)
{
    int rcs;
    cm_to_ctl_get_datanode_relation_ack get_instance_msg = {0};

    rcs = GetDatanodeRelationInfo(commCtx->nodeId, commCtx->dataPath, &get_instance_msg);
    if (rcs == -1) {
        return -1;
    }

    if ((instanceType == INSTANCE_TYPE_DATANODE &&
            instance_role == get_instance_msg.data_node_member[member_index].local_status.local_role) ||
        (instanceType == INSTANCE_TYPE_GTM &&
            instance_role == get_instance_msg.gtm_member[member_index].local_status.local_role)) {
        return 0;
    } else {
        return -1;
    }
}

static int JudgeDatanodeStatus(uint32 node_id, const char *data_path, int db_state)
{
    int rcs;
    cm_to_ctl_get_datanode_relation_ack get_instance_msg = {0};

    rcs = GetDatanodeRelationInfo(node_id, data_path, &get_instance_msg);
    if (rcs == -1) {
        return -1;
    }
    int member_index = get_instance_msg.member_index;

    if (get_instance_msg.data_node_member[member_index].local_status.db_state == db_state) {
        return 0;
    } else {
        return -1;
    }
}

static int JudgeGtmStatus(uint32 node_id, const char* data_path, int gtm_state)
{
    int member_index;
    int rcs;
    cm_to_ctl_get_datanode_relation_ack get_instance_msg = {0};

    rcs = GetDatanodeRelationInfo(node_id, data_path, &get_instance_msg);
    if (rcs == -1) {
        return -1;
    }
    member_index = get_instance_msg.member_index;

    if (get_instance_msg.gtm_member[member_index].local_status.connect_status == gtm_state) {
        return 0;
    } else {
        return -1;
    }
}

static int GetDatapathByInstanceId(uint32 instanceId, int instanceType, char* data_path, uint32 data_path_len)
{
    uint32 node_index;
    uint32 datanode_index;
    int rc;
    for (node_index = 0; node_index < g_node_num; node_index++) {
        if (instanceType == INSTANCE_TYPE_DATANODE) {
            for (datanode_index = 0; datanode_index < g_node[node_index].datanodeCount; datanode_index++) {
                if (g_node[node_index].datanode[datanode_index].datanodeId == instanceId) {
                    rc = strncpy_s(data_path,
                        data_path_len,
                        g_node[node_index].datanode[datanode_index].datanodeLocalDataPath,
                        data_path_len - 1);
                    securec_check_errno(rc, (void)rc);
                    return 0;
                }
            }
        } else if (instanceType == INSTANCE_TYPE_GTM) {
            if (g_node[node_index].gtmId == instanceId) {
                rc = strncpy_s(data_path, data_path_len, g_node[node_index].gtmLocalDataPath, data_path_len - 1);
                securec_check_errno(rc, (void)rc);
                return 0;
            }
        } else {
            return -1;
        }
    }
    return -1;
}

/* check whether primary dn  most_available_sync is on */
static bool CheckDnMostAvaiSync()
{
    char command[MAX_COMMAND_LEN] = "cm_ctl ddb --get /most_available_sync | grep success >> \"/dev/null\" 2>&1";
    int rc = -1;
    rc = system(command);
    if (rc == 0) {
        write_runlog(DEBUG1, "[CheckDnMostAvaiSync]cmd is %s, rc=%d\n", command, WEXITSTATUS(rc));
        return true;
    }
    return false;
}

int DoSwitchover(const CtlOption *ctx)
{
    GetClusterMode();
    // if primary dn most_available_sync is on, can not do switchover
    if (CheckDnMostAvaiSync()) {
        write_runlog(ERROR,
            "primary dn most_available_sync is on, can not do switchover.\n");
        return -1;
    }
    if (ctx->switchover.switchoverAll) {
        if (switchover_all_quick && g_clusterType != V3SingleInstCluster) {
            return DoSwitchoverAllQuick();
        }
        return DoSwitchoverAll(ctx);
    }

    if (ctx->switchover.switchoverFull && g_clusterType != V3SingleInstCluster) {
        return DoSwitchoverFull(ctx);
    }

    if (g_command_operation_azName != NULL && g_clusterType != V3SingleInstCluster) {
        return DoSwitchoverAz(g_command_operation_azName, ctx);
    }

    if (switchover_all_quick && g_clusterType != V3SingleInstCluster) {
        return DoSwitchoverQuick(ctx);
    }

    return DoSwitchoverBase(ctx);
}

static void GetClusterMode()
{
    errno_t rc;
    char cmDir[CM_PATH_LENGTH] = { 0 };
    char configDir[CM_PATH_LENGTH] = { 0 };

    rc = memcpy_s(cmDir, sizeof(cmDir), g_currentNode->cmDataPath, sizeof(cmDir));
    securec_check_errno(rc, (void)rc);

    if (cmDir[0] == '\0') {
        write_runlog(ERROR, "Failed to get cm base data path from static config file.");
        exit(-1);
    }

    rc = snprintf_s(configDir, sizeof(configDir), sizeof(configDir) - 1, "%s/cm_agent/cm_agent.conf", cmDir);
    securec_check_intval(rc, (void)rc);

    g_ssDoubleClusterMode =
        (SSDoubleClusterMode)get_uint32_value_from_config(configDir, "ss_double_cluster_mode", SS_DOUBLE_NULL);

    rc = snprintf_s(configDir, sizeof(configDir), sizeof(configDir) - 1, "%s/cm_server/cm_server.conf", cmDir);
    securec_check_intval(rc, (void)rc);

    backup_open =
        (ClusterRole)get_uint32_value_from_config(configDir, "backup_open", CLUSTER_PRIMARY);
}
