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
 *    cm_ctl switchover [-z AVAILABILITY_ZONE] | [-n NODEID -D DATADIR [-q] | [-f]] | [-a [-q]] | [-A] [-t SECS]
 *
 * IDENTIFICATION
 *    src/cm_ctl/ctl_switch.cpp
 *
 * -------------------------------------------------------------------------
 */
#include "cm/libpq-fe.h"
#include "ctl_common.h"

static const int CONN_TYRE_TIMES = 3;
static const int QUERY_TIME_OUT = 30;
static const int WAIT_PRIMARY_TIME_OUT = 30;
static const int SWITCH_TIME_OUT = 600;

using RecvResult = struct RecvResultSt {
    int status;
    bool isSwitchSuccess;
};

static status_t ConnectNormalCms(CM_Conn **conn)
{
    uint32 *cmsNodeIndex = GetCmsNodeIndex();

    for (uint32 i = 0; i < CONN_TYRE_TIMES; ++i) {
        for (uint32 j = 0; j < g_cm_server_num; ++j) {
            do_conn_cmserver(true, cmsNodeIndex[j], false, conn);
            if (*conn != NULL) {
                return CM_SUCCESS;
            }
            write_runlog(LOG, ".");
            cm_sleep(1);
        }
    }

    return CM_ERROR;
}

static inline status_t ConnectPrimaryCms(CM_Conn **pCmsConn)
{
    do_conn_cmserver(false, 0, false, pCmsConn);
    if (*pCmsConn == NULL) {
        write_runlog(DEBUG1, "connect to primary cm_server fail.\n");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static status_t ProcessAckMsgCore(char *recvMsg, RecvResult &out)
{
    CmsToCtlSwitchAck *ackMsg = NULL;
    cm_to_ctl_cluster_status *queryMsg = NULL;

    const cm_msg_type *msgType = (const cm_msg_type*)(recvMsg);
    switch (msgType->msg_type) {
        case MSG_CMS_CTL_SWITCH_ACK:
            ackMsg = (CmsToCtlSwitchAck*)(recvMsg);
            out.isSwitchSuccess = ackMsg->isSuccess;
            if (!ackMsg->isSuccess) {
                write_runlog(LOG, "switch failed, errMsg : %s\n", ackMsg->errMsg);
                return CM_SUCCESS;
            }
            return CM_SUCCESS;
        case MSG_CM_CTL_DATA_BEGIN:
            queryMsg = (cm_to_ctl_cluster_status*)(recvMsg);
            out.status = queryMsg->cluster_status;
            break;
        case MSG_CM_CTL_DATA_END:
            return CM_SUCCESS;
        default:
            break;
    }

    return CM_ERROR;
}

static void ProcessAckMsg(CM_Conn *con, int timeOut, RecvResult &out)
{
    int times = 0;
    char *recvMsg = NULL;

    out.status = -1;
    out.isSwitchSuccess = false;
    for (;;) {
        if (cm_client_flush_msg(con) == TCP_SOCKET_ERROR_EPIPE) {
            break;
        }
        recvMsg = recv_cm_server_cmd(con);
        if (recvMsg != NULL) {
            if (ProcessAckMsgCore(recvMsg, out) == CM_SUCCESS) {
                return;
            }
        }
        write_runlog(LOG, ".");
        cm_sleep(1);

        if (++times > timeOut) {
            write_runlog(LOG, "switch timeout.\n");
            break;
        }
    }

    return;
}

static status_t WaitPrimaryCmsNormal(CM_Conn **pCmsConn)
{
    uint32 times = 0;

    for (;;) {
        if (ConnectPrimaryCms(pCmsConn) == CM_SUCCESS) {
            write_runlog(DEBUG1, "connect primary cms success.\n");
            break;
        }
        write_runlog(LOG, ".");
        cm_sleep(1);
        if (++times > WAIT_PRIMARY_TIME_OUT) {
            write_runlog(LOG, "connect cms primary time out.\n");
            return CM_ERROR;
        }
    }

    return CM_SUCCESS;
}

static bool IsExistMaintainFile(const char *gausshome, uint32 index)
{
    int ret;
    char cmd[CM_PATH_LENGTH] = {0};

    ret = snprintf_s(cmd,
        CM_PATH_LENGTH,
        CM_PATH_LENGTH - 1,
        "pssh %s -H %s \" stat %s/bin/cms_maintain \" > /dev/null 2>&1",
        PSSH_TIMEOUT_OPTION,
        g_node[index].sshChannel[0],
        gausshome);
    securec_check_intval(ret, (void)ret);
    ret = system(cmd);
    if (ret != -1 && WEXITSTATUS(ret) == 0) {
        write_runlog(DEBUG1, "exec cmd(%s) success, node(%u) exist cms_maintain\n", cmd, g_node[index].node);
        return true;
    }
    write_runlog(DEBUG1, "exec cmd(%s) failed, ret = %d, errno = %d.\n", cmd, WEXITSTATUS(ret), errno);
    write_runlog(DEBUG1, "node(%u) not exist cms_maintain.\n", g_node[index].node);

    return false;
}

static status_t CheckDdbInMaintainFile(int &ddb, uint32 index, const char *gausshome)
{
    int ret;
    int ddbInFile;
    char ip[CM_IP_LENGTH] = {0};
    char buf[CM_PATH_LENGTH] = {0};
    char getDdbCmd[CM_PATH_LENGTH] = {0};

    // need skip pssh content, use sed to skip last line
    ret = snprintf_s(getDdbCmd,
        CM_PATH_LENGTH,
        CM_PATH_LENGTH - 1,
        "pssh %s -H %s \"cat %s/bin/cms_maintain\" | sed '$d' ",
        PSSH_TIMEOUT_OPTION,
        g_node[index].sshChannel[0],
        gausshome);
    securec_check_intval(ret, (void)ret);

    FILE *fp = popen(getDdbCmd, "r");
    if (fp == NULL) {
        write_runlog(DEBUG1, "execute get ddb cmd(%s) failed \n", getDdbCmd);
        return CM_ERROR;
    }

    if (fgets(buf, sizeof(buf), fp) != NULL) {
        ret = sscanf_s(buf, "%s %d", ip, CM_IP_LENGTH, &ddbInFile);
        check_sscanf_s_result(ret, 2);
        securec_check_intval(ret, (void)ret);
        if (strncmp(ip, g_node[index].sshChannel[0], strlen(g_node[index].sshChannel[0])) != 0) {
            write_runlog(DEBUG1, "get ddb type from \"%s\" fail, err ip(%s).\n", g_node[index].sshChannel[0], ip);
            (void)pclose(fp);
            return CM_ERROR;
        }
        if (ddbInFile < 0 || ddbInFile > 1) {
            write_runlog(DEBUG1, "get unknown ddb_type(%d).\n", ddbInFile);
            (void)pclose(fp);
            return CM_ERROR;
        }
    } else {
        write_runlog(DEBUG1, "get ddb type from maintain fail.\n");
        (void)pclose(fp);
        return CM_ERROR;
    }

    if (ddb != -1 && ddbInFile != ddb) {
        write_runlog(DEBUG1, "ddb=%d, ddbInFile=%d, can't do rollback\n", ddb, ddbInFile);
        (void)pclose(fp);
        return CM_ERROR;
    }
    ddb = ddbInFile;

    (void)pclose(fp);
    return CM_SUCCESS;
}

static status_t DeleteAllMaintainFile()
{
    int ret;
    char deleteCmd[CM_PATH_LENGTH] = {0};
    char gausshome[CM_PATH_LENGTH] = {0};
    uint32 *cmsNodeIndex = GetCmsNodeIndex();

    if (GetHomePath(gausshome, sizeof(gausshome)) != EOK) {
        return CM_ERROR;
    }

    for (uint32 i = 0; i < g_cm_server_num; ++i) {
        uint32 index = cmsNodeIndex[i];
        ret = snprintf_s(deleteCmd,
            CM_PATH_LENGTH,
            CM_PATH_LENGTH - 1,
            "pssh %s -H %s \" rm -f %s/bin/cms_maintain;rm -f %s/bin/cms_ddb_kv \" > /dev/null 2>&1",
            PSSH_TIMEOUT_OPTION,
            g_node[index].sshChannel[0],
            gausshome,
            gausshome);
        securec_check_intval(ret, (void)ret);
        ret = system(deleteCmd);
        if (ret != 0) {
            write_runlog(DEBUG1, "node(%u) delete cms_maintain fail, cmd = \"%s\".\n", g_node[index].node, deleteCmd);
            return CM_ERROR;
        }
        write_runlog(DEBUG1, "node(%u) delete cms_maintain success, cmd = \"%s\".\n", g_node[index].node, deleteCmd);
    }

    return CM_SUCCESS;
}

static status_t RollbackDdbTypeParam(int ddb)
{
    int ret;
    char setCmd[CM_PATH_LENGTH] = {0};

    ret = snprintf_s(setCmd,
        CM_PATH_LENGTH,
        CM_PATH_LENGTH - 1,
        "cm_ctl set --param --server -k \"ddb_type\"=\"%d\" > /dev/null 2>&1",
        ddb);
    securec_check_intval(ret, (void)ret);

    if (system(setCmd) != 0) {
        write_runlog(DEBUG1, "exe cmd fail, cmd = \"%s\".\n", setCmd);
        return CM_ERROR;
    }
    write_runlog(DEBUG1, "exe cmd success, cmd = \"%s\".\n", setCmd);

    return CM_SUCCESS;
}

static status_t RollbackCore(int ddb)
{
    CM_Conn *pCmsConn = NULL;

    if (RollbackDdbTypeParam(ddb) != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (DeleteAllMaintainFile() != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (KillAllCms(true) != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (WaitPrimaryCmsNormal(&pCmsConn) != CM_SUCCESS) {
        return CM_ERROR;
    }
    ReleaseConn(pCmsConn);

    return CM_SUCCESS;
}

static bool CanDoRollback(int &ddb)
{
    char gausshome[CM_PATH_LENGTH] = {0};
    uint32 *cmsNodeIndex = GetCmsNodeIndex();

    if (GetHomePath(gausshome, sizeof(gausshome)) != EOK) {
        return false;
    }
    for (uint32 i = 0; i < g_cm_server_num; ++i) {
        uint32 index = cmsNodeIndex[i];
        if (IsExistMaintainFile(gausshome, index)) {
            write_runlog(DEBUG1, "exist maintain file, get ddb type, index(%u).\n", index);
            if (CheckDdbInMaintainFile(ddb, index, gausshome) != CM_SUCCESS) {
                write_runlog(LOG, "the ddb type saved int maintain files are not same, please manual rollback.\n");
                return false;
            }
        }
    }
    if (ddb == -1) {
        write_runlog(LOG, "rollback success.\n");
        return false;
    }

    return true;
}

static status_t SwitchRollback(int logLevel)
{
    int ddb = -1;

    if (!CanDoRollback(ddb)) {
        return CM_ERROR;
    }
    if (RollbackCore(ddb) != CM_SUCCESS) {
        write_runlog(logLevel, "rollback fail.\n");
        return CM_ERROR;
    }
    write_runlog(logLevel, "rollback success.\n");

    return CM_SUCCESS;
}

static int GetClusterStatus()
{
    CM_Conn *pCmsConn = NULL;
    RecvResult recv = {0};
    ctl_to_cm_query sendMsg = {0};

    if (ConnectPrimaryCms(&pCmsConn) != CM_SUCCESS) {
        write_runlog(DEBUG1, "connect primary cms fail, can't do switch ddb, errno(%d).\n", errno);
        return -1;
    }

    sendMsg.msg_type = static_cast<int>(MSG_CTL_CM_QUERY);
    sendMsg.detail = CLUSTER_START_STATUS_QUERY;
    sendMsg.node = 0;
    if (cm_client_send_msg(pCmsConn, 'C', (char*)&sendMsg, sizeof(sendMsg)) != 0) {
        ReleaseConn(pCmsConn);
        write_runlog(DEBUG1, "send get cluster status msg fail, errno(%d).\n", errno);
        return -1;
    }
    recv.status = -1;
    ProcessAckMsg(pCmsConn, QUERY_TIME_OUT, recv);
    ReleaseConn(pCmsConn);

    return recv.status;
}

static bool CanDoSwitch()
{
    char gausshome[CM_PATH_LENGTH] = {0};
    uint32 *cmsNodeIndex = GetCmsNodeIndex();

    if (GetClusterStatus() != CM_STATUS_NORMAL) {
        write_runlog(LOG, "cluster status is not normal or can't get cluster status.\n");
        return false;
    }

    if (GetHomePath(gausshome, sizeof(gausshome)) != EOK) {
        return false;
    }
    for (uint32 i = 0; i < g_cm_server_num; ++i) {
        uint32 index = cmsNodeIndex[i];
        if (IsExistMaintainFile(gausshome, index)) {
            write_runlog(DEBUG1, "exist maintain file, need do rollback.\n");
            if (SwitchRollback(DEBUG1) == CM_ERROR) {
                return false;
            }
            break;
        }
    }

    if (!CheckDdbHealth()) {
        write_runlog(LOG, "ddb is not health.\n");
        return false;
    }

    return true;
}

static status_t SwitchEnterMaintainMode(CtlToCmsSwitch &sendMsg)
{
    CM_Conn *con = NULL;
    RecvResult recv = {0};

    if (ConnectNormalCms(&con) != CM_SUCCESS) {
        write_runlog(DEBUG1, "connect normal cms fail, can't do switch ddb, errno(%d).\n", errno);
        return CM_ERROR;
    }
    sendMsg.step = SWITCH_DDB_ENTER_MAINTAIN;
    if (cm_client_send_msg(con, 'C', (char*)&sendMsg, sizeof(sendMsg)) != 0) {
        write_runlog(ERROR, "send msg to normal cms fail\n");
        ReleaseConn(con);
        return CM_ERROR;
    }
    ProcessAckMsg(con, SWITCH_TIME_OUT, recv);
    ReleaseConn(con);
    if (!recv.isSwitchSuccess) {
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static status_t SwitchSaveAllKVS(CtlToCmsSwitch &sendMsg)
{
    RecvResult recv = {0};
    CM_Conn *pCmsConn = NULL;

    if (WaitPrimaryCmsNormal(&pCmsConn) != CM_SUCCESS) {
        write_runlog(DEBUG1, "connect primary cms fail, can't do switch ddb, errno(%d).\n", errno);
        return CM_ERROR;
    }

    sendMsg.step = SWITCH_DDB_SAVE_ALL_KVS;
    if (cm_client_send_msg(pCmsConn, 'C', (char*)&sendMsg, sizeof(sendMsg)) != 0) {
        write_runlog(ERROR, "send msg to normal cms fail\n");
        ReleaseConn(pCmsConn);
        return CM_ERROR;
    }
    ProcessAckMsg(pCmsConn, SWITCH_TIME_OUT, recv);
    ReleaseConn(pCmsConn);
    if (!recv.isSwitchSuccess) {
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static status_t TransferDdbData(CtlToCmsSwitch &sendMsg)
{
    RecvResult recv = {0};
    CM_Conn *pCmsConn = NULL;

    if (WaitPrimaryCmsNormal(&pCmsConn) != CM_SUCCESS) {
        write_runlog(DEBUG1, "connect primary cms fail, can't do switch ddb, errno(%d).\n", errno);
        return CM_ERROR;
    }

    sendMsg.step = SWITCH_DDB;
    if (cm_client_send_msg(pCmsConn, 'C', (char*)&sendMsg, sizeof(sendMsg)) != 0) {
        write_runlog(ERROR, "send switch ddb msg to primary cms fail.\n");
        ReleaseConn(pCmsConn);
        return CM_ERROR;
    }
    ProcessAckMsg(pCmsConn, SWITCH_TIME_OUT, recv);
    ReleaseConn(pCmsConn);
    if (recv.isSwitchSuccess) {
        return CM_SUCCESS;
    }

    return CM_ERROR;
}

static status_t SwitchDdbCore(const char *ddbType)
{
    errno_t rc;
    CtlToCmsSwitch sendMsg = {0};

    sendMsg.msgType = static_cast<int>(MSG_CTL_CMS_SWITCH);
    rc = strcpy_s(sendMsg.ddbType, CM_PATH_LENGTH, ddbType);
    securec_check_errno(rc, (void)rc);

    if (SwitchEnterMaintainMode(sendMsg) != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (KillAllCms(true) != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (SwitchSaveAllKVS(sendMsg) != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (KillAllCms(true) != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (TransferDdbData(sendMsg) != CM_SUCCESS) {
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static status_t SwitchDdb(const char *ddbType)
{
    if (!CanDoSwitch()) {
        write_runlog(LOG, "can't do switch, so switch ddb type to %s fail.\n", ddbType);
        return CM_ERROR;
    }
    if (SwitchDdbCore(ddbType) != CM_SUCCESS) {
        write_runlog(LOG, "switch ddb type to %s fail.\n", ddbType);
        return CM_ERROR;
    }
    write_runlog(LOG, "switch ddb type to %s success.\n", ddbType);

    return CM_SUCCESS;
}

static status_t CanDoCommit()
{
    int ret;
    char cmd[CM_PATH_LENGTH] = {0};
    char gausshome[CM_PATH_LENGTH] = {0};
    uint32 *cmsNodeIndex = GetCmsNodeIndex();

    if (GetHomePath(gausshome, sizeof(gausshome)) != EOK) {
        return CM_SUCCESS;
    }

    for (uint32 i = 0; i < g_cm_server_num; ++i) {
        uint32 index = cmsNodeIndex[i];
        ret = snprintf_s(cmd,
            CM_PATH_LENGTH,
            CM_PATH_LENGTH - 1,
            "pssh %s -H %s \" stat %s/bin/switch_commit_flag \" > /dev/null 2>&1",
            PSSH_TIMEOUT_OPTION,
            g_node[index].sshChannel[0],
            gausshome);
        securec_check_intval(ret, (void)ret);
        ret = system(cmd);
        if (ret != -1 && WEXITSTATUS(ret) == 0) {
            write_runlog(DEBUG1, "exe cmd(%s) success, node(%u) exist switch_commit_flag\n", cmd, g_node[index].node);
            return CM_ERROR;
        }
    }

    return CM_SUCCESS;
}

static status_t SwitchCommit()
{
    CM_Conn *pCmsConn = NULL;

    if (CanDoCommit() != CM_SUCCESS) {
        write_runlog(LOG, "can't do commit.\n");
        return CM_ERROR;
    }
    if (DeleteAllMaintainFile() != CM_SUCCESS) {
        write_runlog(LOG, "delete all maintain file fail, commit fail.\n");
        return CM_ERROR;
    }
    if (KillAllCms(true) != CM_SUCCESS) {
        write_runlog(LOG, "kill all cms fail.\n");
        return CM_ERROR;
    }
    if (WaitPrimaryCmsNormal(&pCmsConn) != CM_SUCCESS) {
        write_runlog(LOG, "cms notify primary time out, commit fail.\n");
        return CM_ERROR;
    }
    ReleaseConn(pCmsConn);
    write_runlog(LOG, "commit success.\n");

    return CM_SUCCESS;
}

int DoSwitch(const CtlOption *ctx)
{
    bool flag;

    flag = (ctx->switchOption.ddbType != NULL) && !ctx->switchOption.isRollback && !ctx->switchOption.isCommit;
    if (flag) {
        return (int)SwitchDdb(ctx->switchOption.ddbType);
    }

    flag = (ctx->switchOption.ddbType == NULL) && ctx->switchOption.isRollback && !ctx->switchOption.isCommit;
    if (flag) {
        return (int)SwitchRollback(LOG);
    }

    flag = (ctx->switchOption.ddbType == NULL) && !ctx->switchOption.isRollback && ctx->switchOption.isCommit;
    if (flag) {
        return (int)SwitchCommit();
    }
    write_runlog(LOG, "input wrong, please check the cmd.\n");

    return -1;
}
