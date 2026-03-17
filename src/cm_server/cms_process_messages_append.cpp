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
 * cms_process_messages_append.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_server/cms_process_messages_append.cpp
 *
 * -------------------------------------------------------------------------
 */
#include "cms_global_params.h"
#include "cms_process_messages.h"
#include "cms_disk_check.h"
#include "cms_common.h"
#include "cms_alarm.h"
#include "cms_ddb_adapter.h"
#include "cms_threads.h"

typedef struct {
    uint32 nodeNum;
    uint32 dnRepNum;
    uint32 cnNum;
    uint32 relationNum;
    uint32 dnNum;
    uint32 etcdNum;
    uint32 cmsNum;
    uint32 gtmNum;
} NodeInstanceCnt;

void StoreGlobalValue(NodeInstanceCnt *globalValue)
{
    globalValue->nodeNum = g_node_num;
    globalValue->dnRepNum = g_dn_replication_num;
    globalValue->cnNum = g_coordinator_num;
    globalValue->relationNum = g_dynamic_header->relationCount;
    globalValue->dnNum = g_datanode_instance_count;
    globalValue->etcdNum = g_etcd_num;
    globalValue->cmsNum = g_cm_server_num;
    globalValue->gtmNum = g_gtm_num;
    return;
}

void RestoreGlobalValue(const NodeInstanceCnt lastGlobalValue)
{
    g_node_num = lastGlobalValue.nodeNum;
    g_dn_replication_num = lastGlobalValue.dnRepNum;
    g_coordinator_num = lastGlobalValue.cnNum;
    g_dynamic_header->relationCount = lastGlobalValue.relationNum;
    g_datanode_instance_count = lastGlobalValue.dnNum;
    g_etcd_num = lastGlobalValue.etcdNum;
    g_cm_server_num = lastGlobalValue.cmsNum;
    g_gtm_num = lastGlobalValue.gtmNum;
    return;
}

int CheckInstanceCnt(const NodeInstanceCnt lastGlobalValue)
{
    if (g_etcd_num != lastGlobalValue.etcdNum || g_cm_server_num != lastGlobalValue.cmsNum ||
        g_gtm_num != lastGlobalValue.gtmNum) {
        return -1;
    }

    return 0;
}

static void FreeAndInitNotifyMsg()
{
    write_runlog(DEBUG1, "[reload] begin to free notify msg.\n");
    FreeNotifyMsg();
    write_runlog(DEBUG1, "[reload] end to free notify msg.\n");
#ifdef ENABLE_MULTIPLE_NODES
    write_runlog(DEBUG1, "[reload] begin to init notify msg.\n");
    (void)cm_notify_msg_init();
    write_runlog(DEBUG1, "[reload] end to init notify msg.\n");
#endif
}


int UpdateBasicInfo(const NodeInstanceCnt lastGlobalValue)
{
    if (CheckInstanceCnt(lastGlobalValue) != 0) {
        write_runlog(ERROR, "[reload] unexpected instance type increase, only support add cn/dn instance.\n");
        return -1;
    }

    if (UpdateDynamicConfig() != 0) {
        write_runlog(ERROR, "[reload] UpdateDynamicConfig failed.\n");
        return -1;
    }

    UpdatePhonyDeadAlarm();
    FreeAndInitNotifyMsg();
    UpdateAzNodeInfo();
    UpdateNodeReadonlyInfo();

    return 0;
}

void ProcessCtlToCmReloadMsg(MsgRecvInfo* recvMsgInfo)
{
    int err = 0;
    uint32 i = 0;
    NodeInstanceCnt lastGlobalValue;
    CMToCtlReloadAck reloadAckMsg;
    timespec waitBegin = {0, 0};
    timespec waitEnd = {0, 0};

    write_runlog(LOG, "[reload] ProcessCtlToCmReloadMsg start.\n");
    StoreGlobalValue(&lastGlobalValue);
    g_inReload = true;
    (void)clock_gettime(CLOCK_MONOTONIC, &waitBegin);

    while (i < g_loopState.count) {
        (void)clock_gettime(CLOCK_MONOTONIC, &waitEnd);
        if ((waitEnd.tv_sec - waitBegin.tv_sec) > RELOADWAIT_TIMEOUT) {
            write_runlog(LOG, "execute cm_ctl reload command timeout.\n");
            return;
        }
        if (g_loopState.execStatus[i] == 0) {
            write_runlog(LOG, "[reload] unfinished thread loop-index:%u.\n", i);
            i = 0;
            cm_sleep(1);
            continue;
        }
        i++;
    }

    write_runlog(LOG, "[reload] begin to reload config file.\n");
    reloadAckMsg.msgType = MSG_CM_CTL_RELOAD_ACK;
    int status = read_config_file(g_cmStaticConfigurePath, &err, true);
    if (status != 0) {
        switch (status) {
            case OPEN_FILE_ERROR: {
                write_runlog(ERROR, "[reload] Failed to open the cluster static file: [errno %d].\n", err);
                break;
            }
            case READ_FILE_ERROR: {
                write_runlog(ERROR, "[reload] Failed to read the cluster static file: [errno %d].\n", err);
                break;
            }
            default:
                break;
        }
        reloadAckMsg.reloadOk = false;
        (void)RespondMsg(recvMsgInfo, 'S', (char*)(&reloadAckMsg), sizeof(CMToCtlReloadAck));
        g_inReload = false;
        return;
    }

    if (UpdateBasicInfo(lastGlobalValue) != 0) {
        write_runlog(ERROR, "[reload] UpdateBasicInfo failed.\n");
        RestoreGlobalValue(lastGlobalValue);
        FreeAndInitNotifyMsg();
        reloadAckMsg.reloadOk = false;
        (void)RespondMsg(recvMsgInfo, 'S', (char*)(&reloadAckMsg), sizeof(CMToCtlReloadAck));
        g_inReload = false;
        return;
    }

    write_runlog(LOG, "[reload] reload config file success.\n");

#if ((defined(ENABLE_MULTIPLE_NODES)) || (defined(ENABLE_PRIVATEGAUSS)))
    if (g_isEnableUpdateSyncList == CANNOT_START_SYNCLIST_THREADS) {
        CreateDnGroupStatusCheckAndArbitrateThread();
    }
#endif

    write_runlog(LOG, "[reload] reload config file success.\n");
    reloadAckMsg.reloadOk = true;
    (void)RespondMsg(recvMsgInfo, 'S', (char*)(&reloadAckMsg), sizeof(CMToCtlReloadAck));
    g_inReload = false;
    return;
}

void ProcessCtlToCmExecDccCmdMsg(MsgRecvInfo* recvMsgInfo, ExecDdbCmdMsg *msg)
{
    msg->cmdLine[DCC_CMD_MAX_LEN - 1] = '\0';
    errno_t rc;
    ExecDdbCmdAckMsg ackMsg;

    ackMsg.msgType = static_cast<int>(EXEC_DDB_COMMAND_ACK);

    if (g_inMaintainMode) {
        ackMsg.isSuccess = false;
        rc = strcpy_s(ackMsg.errMsg, ERR_MSG_LENGTH, "in maintain mode, can't do ddb cmd.");
        securec_check_errno(rc, (void)rc);
    } else {
        ackMsg.isSuccess = (DoDdbExecCmd(msg->cmdLine, ackMsg.output, &ackMsg.outputLen, ackMsg.errMsg,
            DCC_CMD_MAX_OUTPUT_LEN) == CM_SUCCESS);
    }

    (void)RespondMsg(recvMsgInfo, 'S', reinterpret_cast<char*>(&ackMsg), sizeof(ExecDdbCmdAckMsg));

    return;
}
