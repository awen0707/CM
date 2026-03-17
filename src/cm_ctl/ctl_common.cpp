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
 * ctl_common.cpp
 *      cm_ctl common functions
 *
 * IDENTIFICATION
 *    src/cm_ctl/ctl_common.cpp
 *
 * -------------------------------------------------------------------------
 */
#include <signal.h>
#include "common/config/cm_config.h"
#include "cm/libpq-fe.h"
#include "cm/cm_misc.h"
#include "cm_msg_version_convert.h"
#include "cm/libpq-int.h"
#include "cs_ssl.h"
#include "cm_json_config.h"
#include "ctl_common.h"

#define STOP_DEFAULT_WAIT 1200
#define CONN_TO_CMSERVER_TIMEOUT 1
#define CONN_STRING_LEN 1024
#define START_DEFAULT_WAIT 600
#define MAX_INVALID_NODE_EXECTIMES 2

const int USEC_TO_TIMEOUT = 1000;
const int32 MAX_CONN_TIMES = 10;
const int32 SEND_MSG_TIMES = 20;
const int32 WAIT_MSG_RES_TIMES = 3;

const int32 SUCCESS_SEND_MSG = 0;
const int32 NEED_SEND_AGAIN = 1;

DdbConn *g_sess = NULL;
TlsAuthPath g_tlsPath = {0};
extern CtlCommand ctl_command;
extern uint32 g_normal_cm_server_node_index;
extern char mpp_env_separate_file[MAXPGPATH];
extern passwd* pw;
extern uint32 g_nodeIndexForCmServer[CM_PRIMARY_STANDBY_NUM];
extern char result_path[MAXPGPATH];
extern const char* g_cmServerState[CM_PRIMARY_STANDBY_NUM + 1];
extern char* g_command_operation_azName;
extern uint32 g_commandOperationNodeId;
extern uint32 g_nodeId;
extern char cluster_static_config[MAXPGPATH];
extern char hosts_path[MAXPGPATH];
extern const char* g_progname;
extern CM_Conn* CmServer_conn;
extern CM_Conn* CmServer_conn1;
extern CM_Conn* CmServer_conn2;
const int g_max_buf_len = 10;
/* estimated extra cost about one more operated node */
static const float g_node_operation_cost = 0.5;
extern bool got_stop;
extern char g_appPath[MAXPGPATH];
extern char manual_start_file[MAXPGPATH];
const int DEFAULT_GET_INFO_TIME = 5;
int g_hostInfo[CM_NODE_MAXNUM][CM_IP_NUM] = {0};
uint32 g_execNodes = 0;
bool g_stopAbnormal = false;
bool g_isRestop = false;
extern int g_waitSeconds;

static void connect_to_first_normal_cmserver(uint32 cmsNodeIdx, CM_Conn **curConn);

void DoAdvice(void)
{
    write_runlog(LOG, "Try \"%s --help\" for more information.\n", g_progname);
}

const char *GetDnProcessName(void)
{
    return g_clusterType == V3SingleInstCluster ? ZENGINE_BIN_NAME : DATANODE_BIN_NAME;
}

/*
 * Get node index in g_node by node_id.
 */
uint32 get_node_index(uint32 node_id)
{
    for (uint32 ii = 0; ii < g_node_num; ii++) {
        if (g_node[ii].node == node_id) {
            return ii;
        }
    }
    return INVALID_NODE_NUM;
}

bool isMajority(const char* cm_arbitration_mode)
{
    if (cm_arbitration_mode == NULL) {
        return false;
    } else if (strcmp("majority", cm_arbitration_mode) == 0) {
        return true;
    } else if (strcmp("MAJORITY", cm_arbitration_mode) == 0) {
        return true;
    } else {
        return false;
    }
}

bool isMinority(const char* cm_arbitration_mode)
{
    if (cm_arbitration_mode == NULL) {
        return false;
    } else if (strcmp("minority", cm_arbitration_mode) == 0) {
        return true;
    } else if (strcmp("MINORITY", cm_arbitration_mode) == 0) {
        return true;
    } else {
        return false;
    }
}

int FindInstanceIdAndType(uint32 node, const char *dataPath, uint32 *instanceId, int *instanceType)
{
    if ((node < 1) || (get_node_index(node) >= g_node_num)) {
        write_runlog(ERROR, "node(%u) is invalid, max node num(%u).\n", node, g_node_num);
        return -1;
    }
    for (uint32 j = 0; j < g_node_num; j++) {
        if (g_node[j].node != node) {
            continue;
        }

        if (g_node[j].gtm == 1) {
            if (strncmp(dataPath, g_node[j].gtmLocalDataPath, MAXPGPATH) == 0) {
                *instanceId = g_node[j].gtmId;
                *instanceType = INSTANCE_TYPE_GTM;
                return 0;
            }
        }

        if (g_node[j].coordinate == 1) {
            if (strncmp(dataPath, g_node[j].DataPath, MAXPGPATH) == 0) {
                *instanceId = g_node[j].coordinateId;
                *instanceType = INSTANCE_TYPE_COORDINATE;
                return 0;
            }
        }

        for (uint32 i = 0; i < g_node[j].datanodeCount; i++) {
            if (strncmp(dataPath, g_node[j].datanode[i].datanodeLocalDataPath, MAXPGPATH) == 0) {
                *instanceId = g_node[j].datanode[i].datanodeId;
                *instanceType = INSTANCE_TYPE_DATANODE;
                return 0;
            }
        }
    }

    write_runlog(ERROR, "can't find the node(%u) instance (%s).\n", node, dataPath);

    return -1;
}

/*
 * ssh_exec
 * exec command in remote host.
 */
int ssh_exec(const staticNodeConfig* node, const char* cmd, int32 logLevel)
{
    char actualCmd[MAX_COMMAND_LEN] = {0};
    int rc = -1;
    int ret;

    for (uint32 ii = 0; ii < node->sshCount; ii++) {
        if (mpp_env_separate_file[0] == '\0') {
            ret = snprintf_s(actualCmd, MAX_COMMAND_LEN, MAX_COMMAND_LEN - 1,
                "pssh %s -s -H %s \"( %s ) > %s 2>&1\" > /dev/null 2>&1",
                PSSH_TIMEOUT_OPTION, node->sshChannel[ii], cmd, "/dev/null");
        } else {
            ret = snprintf_s(actualCmd, MAX_COMMAND_LEN, MAX_COMMAND_LEN - 1,
                "pssh %s -s -H %s \"( source %s;%s ) > %s 2>&1\" > /dev/null 2>&1",
                PSSH_TIMEOUT_OPTION, node->sshChannel[ii], mpp_env_separate_file, cmd,
                "/dev/null");
        }
        securec_check_intval(ret, (void)ret);
        rc = system(actualCmd);
        if (rc != 0) {
            write_runlog(logLevel, "ssh failed at \"%s\".\n", node->sshChannel[ii]);
            write_runlog(DEBUG1, "cmd is %s, rc=%d, errno=%d.\n", actualCmd, WEXITSTATUS(rc), errno);
        }
    }
    return rc;
}

/*
 * ssh_exec
 * exec command in remote host.
 */
int SshExec(const staticNodeConfig *node, const char *cmd)
{
    char actualCmd[MAXPGPATH];
    int rc = -1;
    int ret = 0;

    for (uint32 ii = 0; ii < node->sshCount; ii++) {
        if (mpp_env_separate_file[0] == '\0') {
            ret = snprintf_s(actualCmd,
                MAXPGPATH,
                MAXPGPATH - 1,
                "pssh %s -s -H %s \"( %s )\"",
                PSSH_TIMEOUT_OPTION,
                node->sshChannel[ii],
                cmd);
            securec_check_intval(ret, (void)ret);
        } else {
            ret = snprintf_s(actualCmd,
                MAXPGPATH,
                MAXPGPATH - 1,
                "pssh %s -s -H %s \"( source %s;%s )\"",
                PSSH_TIMEOUT_OPTION,
                node->sshChannel[ii],
                mpp_env_separate_file,
                cmd);
            securec_check_intval(ret, (void)ret);
        }
        rc = system(actualCmd);
        if (rc != 0) {
            write_runlog(
                ERROR, "cmd execute failed on remote node:\"%s(%s)\".\n", node->nodeName, node->sshChannel[ii]);
            write_runlog(DEBUG1, "cmd is %s, rc=%d, errno=%d.\n", actualCmd, WEXITSTATUS(rc), errno);
        }
    }
    return rc;
}

int RunEtcdCmd(const char* command, uint32 nodeIndex)
{
    int ret = 0;
    if (g_node[nodeIndex].node == g_currentNode->node) {
        ret = system(command);
    } else {
        ret = ssh_exec(&g_node[nodeIndex], command);
    }
    if (ret != 0) {
        write_runlog(DEBUG1, "fail to execute command %s, errno=%d.\n", command, errno);
    }
    return ret;
}

int ProcessSslAck(const char *receiveMsg, bool *enableSsl)
{
    const cm_msg_type *cm_msg_type_ptr = (const cm_msg_type *)receiveMsg;
    if (cm_msg_type_ptr->msg_type != MSG_CM_SSL_CONN_ACK) {
        write_runlog(ERROR, "fail to get ssl ack errno=%d.\n", errno);
        return -1;
    }

    const CmToAgentConnectAck *msgAck = (const CmToAgentConnectAck *)(receiveMsg);
    if (msgAck->status == SSL_ENABLE) {
        *enableSsl = true;
        return 0;
    } else if (msgAck->status == SSL_DISABLE) {
        *enableSsl = false;
        return 0;
    }
    return -1;
}

static inline void cs_securec_clear(char *content, uint32 len)
{
    if (content != NULL) {
        errno_t rc = memset_s(content, len, 0, len);
        securec_check_errno(rc, (void)rc);
    }
    return;
}

static status_t CtlConnSslRequst(CM_Conn *conn, int ssl_req, bool *enableSsl)
{
    AgentToCmConnectRequest req_msg;
    req_msg.msg_type = ssl_req;
    req_msg.nodeid = g_nodeId;
    const int32 timesPerSec = 5;
    int64 timeOut = g_waitSeconds * timesPerSec;

    if (cm_client_send_msg(conn, 'C', (const char *)&req_msg, sizeof(AgentToCmConnectRequest)) != 0) {
        return CM_ERROR;
    }

    char *receiveMsg = NULL;

    while (timeOut >= 0) {
        if (cm_client_flush_msg(conn) != 0) {
            return CM_ERROR;
        }

        receiveMsg = recv_cm_server_cmd(conn);
        if (receiveMsg != NULL) {
            if (ProcessSslAck(receiveMsg, enableSsl) != 0) {
                continue;
            }
            return CM_SUCCESS;
        }

        timeOut--;
        CmUsleep(CTL_RECV_CYCLE);
    }

    return CM_ERROR;
}

static status_t CtlConnSslEstablish(CM_Conn *conn, conn_option_t *option, bool *enableSsl)
{
    const uint32 plainLen = CM_PASSWD_MAX_LEN + 1;
    char plain[plainLen] = {0};

    CM_RETURN_IFERR(CtlConnSslRequst(conn, MSG_CM_SSL_CONN_REQUEST, enableSsl));

    if (!*enableSsl) {
        return CM_SUCCESS;
    }

    write_runlog(DEBUG1, "begin to create ssl connection\n");
    CM_RETURN_IFERR(cm_verify_ssl_key_pwd(plain, sizeof(plain), CLIENT_CIPHER));
    g_sslOption.ssl_para.key_password = plain;
    g_sslOption.ssl_para.verify_peer = true;

    /* check certificate file access permission */
    if (strlen(option->ssl_para.ca_file) > 0) {
        CM_RETURN_IFERR_EX(cm_ssl_verify_file_stat(option->ssl_para.ca_file),
            cs_securec_clear(plain, plainLen));
    }
    if (strlen(option->ssl_para.key_file) > 0) {
        CM_RETURN_IFERR_EX(cm_ssl_verify_file_stat(option->ssl_para.key_file),
            cs_securec_clear(plain, plainLen));
    }
    if (strlen(option->ssl_para.cert_file) > 0) {
        CM_RETURN_IFERR_EX(cm_ssl_verify_file_stat(option->ssl_para.cert_file),
            cs_securec_clear(plain, plainLen));
    }

    /* create the ssl connector - init ssl and load certs */
    ssl_ctx_t *ssl_fd = cm_ssl_create_connector_fd(&option->ssl_para);

    /* erase key_password for security issue */
    cs_securec_clear(plain, plainLen);

    if (ssl_fd == NULL) {
        write_runlog(ERROR, "ssl_create_connector_fd failed.\n");
        return CM_ERROR;
    }
    conn->ssl_connector_fd = ssl_fd;

    /* connect to the server */
    if (cm_cs_ssl_connect(ssl_fd, &conn->pipe) != CM_SUCCESS) {
        write_runlog(ERROR, "create ssl connection failed.\n");
        return CM_ERROR;
    }

    conn->status = CONNECTION_OK;
    return CM_SUCCESS;
}

status_t TryGetSslConnToCmserver(CM_Conn *conn, int timeOut)
{
    const uint32 upgradeVersion = 92574;
    GetUpgradeVersionFromCmaConfig();
    if (undocumentedVersion != 0 && undocumentedVersion < upgradeVersion) {
        return CM_SUCCESS;
    }
    const int32 socketTimeout = 3 * USEC_TO_TIMEOUT;
    conn->pipe.link.tcp.sock = conn->sock;
    conn->pipe.link.tcp.closed = CM_FALSE;
    conn->pipe.link.tcp.remote = *(sock_addr_t *)&conn->raddr;
    conn->pipe.link.tcp.local = *(sock_addr_t *)&conn->laddr;
    conn->pipe.connect_timeout = timeOut * USEC_TO_TIMEOUT;
    conn->pipe.socket_timeout = socketTimeout;
    conn->pipe.l_onoff = 1;
    conn->pipe.l_linger = 1;
    conn->pipe.type = CS_TYPE_TCP;
    conn->status = CONNECTION_SSL_STARTUP;
    bool enableSsl = false;
    static int sslEstablishFailedTime = 0;
    const int sslEstablishFailedTimeOut = 5;
    if (CtlConnSslEstablish(conn, &g_sslOption, &enableSsl) != CM_SUCCESS) {
        write_runlog(ERROR, "create ssl connection failed.\n");
        sslEstablishFailedTime++;
        if (sslEstablishFailedTime > sslEstablishFailedTimeOut) {
            write_runlog(ERROR, "cm_ctl can't establish an SSL connection, please check certificate file\n");
            exit(1);
        }
        return CM_ERROR;
    }

    sslEstablishFailedTime = 0;
    if (enableSsl) {
        write_runlog(DEBUG5, "create ssl connection success.\n");
    } else {
        write_runlog(DEBUG5, "ssl connection not enable.\n");
        conn->status = CONNECTION_OK;
    }

    return CM_SUCCESS;
}

static status_t DoConnCmserver(uint32 nodeIndex, uint32 cmsIndex, uint32 cmaIndex, CM_Conn **curConn, bool isFirstCms)
{
    char connstr[CONN_STRING_LEN] = {0};
    int ret;
    const int timeOut = 5;
    // in order to prevent connect timeout in big cluster
    const int32 ComputeConnectTimeOut = 50;
    int32 connectTimeout = ((int32)g_node_num) / ComputeConnectTimeOut + CONN_TO_CMSERVER_TIMEOUT;
    if (connectTimeout >= timeOut) {
        connectTimeout = timeOut;
    }

    ret = memset_s(connstr, CONN_STRING_LEN, 0, CONN_STRING_LEN);
    securec_check_errno(ret, (void)ret);

    ret = snprintf_s(connstr, sizeof(connstr), sizeof(connstr) - 1,
        "host=%s port=%u localhost=%s connect_timeout=%d user=%s node_id=%u node_name=%s "
        "remote_type=%d %s",
        g_node[nodeIndex].cmServer[cmsIndex], g_node[nodeIndex].port,
        g_currentNode->cmAgentIP[cmaIndex], connectTimeout,
        pw->pw_name, g_nodeHeader.node, "cm_ctl", CM_CTL, isFirstCms ? "" : "postmaster=1");
        securec_check_intval(ret, (void)ret);

    CM_Conn *conn = PQconnectCM(connstr);
    if (conn != NULL && (CMPQstatus(conn) == CONNECTION_OK)) {
        write_runlog(DEBUG5, "socket is [%d]. try to get ssl connection: %s\n", conn->sock, connstr);
        if (TryGetSslConnToCmserver(conn, timeOut) != CM_SUCCESS) {
            write_runlog(ERROR, "socket is [%d], %d : create ssl failed: %s\n",
                conn->sock, __LINE__, CMPQerrorMessage(conn));
            CMPQfinish(conn);
            conn = NULL;
            return CM_ERROR;
        }
        if (isFirstCms) {
            g_normal_cm_server_node_index = nodeIndex;
        }
        CMPQfinish(*curConn);
        *curConn = conn;
        write_runlog(DEBUG1, "connect to cmserver success, remotehost is %s:%u.\n",
            g_node[nodeIndex].cmServer[cmsIndex], g_node[nodeIndex].port);
        return CM_SUCCESS;
    }
    write_runlog(DEBUG1, "%d : connect to cmserver failed: %s.\n", __LINE__, CMPQerrorMessage(conn));
    CMPQfinish(conn);
    return CM_ERROR;
}

static void ConnNormalCms(uint32 nodeIndex, CM_Conn **curConn)
{
    for (uint32 i = 0; i < g_node[nodeIndex].cmServerListenCount; ++i) {
        for (uint32 j = 0; j < g_currentNode->cmAgentListenCount; ++j) {
            if (DoConnCmserver(nodeIndex, i, j, curConn, false) == CM_SUCCESS) {
                return;
            }
        }
    }
}

static void GetFirstNormalCmsConn(uint32 cmsNodeIdx, bool queryEtcd, CM_Conn **curConn)
{
    if (curConn != NULL) {
        connect_to_first_normal_cmserver(cmsNodeIdx, curConn);
    } else if (queryEtcd) {
        connect_to_first_normal_cmserver(cmsNodeIdx, &CmServer_conn2);
    } else {
        connect_to_first_normal_cmserver(cmsNodeIdx, &CmServer_conn);
    }
}

static void ConnPrimaryCms(bool queryEtcd, CM_Conn **curConn)
{
    if (g_normal_cm_server_node_index == PG_UINT32_MAX) {
        for (uint32 kk = 0; kk < g_cm_server_num; kk++) {
            if (strcmp("Down", g_cmServerState[kk]) == 0 || strcmp("Skip", g_cmServerState[kk]) == 0) {
                continue;
            }
            GetFirstNormalCmsConn(g_nodeIndexForCmServer[kk], queryEtcd, curConn);
            if (g_normal_cm_server_node_index != PG_UINT32_MAX) {
                break;
            }
        }
    } else {
        GetFirstNormalCmsConn(g_normal_cm_server_node_index, queryEtcd, curConn);
    }
}

/* quert_etcd is true, it means the conn for query etcd from cms primary
 * because query -v need the conn CmServer_conn, if use it, will find error with same conn. */
void do_conn_cmserver(bool queryCmserver, uint32 nodeIndex, bool queryEtcd, CM_Conn **curConn)
{
    if (queryCmserver) {
        if (curConn != NULL) {
            ConnNormalCms(nodeIndex, curConn);
        } else {
            ConnNormalCms(nodeIndex, &CmServer_conn1);
        }
    } else {
        ConnPrimaryCms(queryEtcd, curConn);
    }
}

int cm_client_flush_msg(CM_Conn* conn)
{
    if (conn != NULL) {
        int ret = cmpqFlush(conn);
        if (ret != 0) {
            write_runlog(ERROR, "flush data failed: %s.\n", CMPQerrorMessage(conn));
            return ret;
        }
    } else {
        write_runlog(DEBUG1, "flush connection is NULL.\n");
        return -1;
    }

    return 0;
}

int cm_client_send_msg(CM_Conn* conn, char msgtype, const char* s, size_t len)
{
    int ret = CMPQPacketSend(conn, msgtype, s, len);
    if (ret != STATUS_OK) {
        if (ctl_command != CM_SWITCHOVER_COMMAND && ctl_command != CM_BUILD_COMMAND) {
            write_runlog(ERROR, "send message to server failed: %s.\n", CMPQerrorMessage(conn));
        } else {
            write_runlog(DEBUG1, "send message to server failed: %s.\n", CMPQerrorMessage(conn));
        }
        return -1;
    }
    return 0;
}

char* recv_cm_server_cmd(CM_Conn* conn)
{
    if (conn == NULL) {
        if (ctl_command != CM_SWITCHOVER_COMMAND) {
            write_runlog(ERROR, "cm_ctl is not connect to the cm server.\n");
        }
        return NULL;
    }

    if (cmpqReadData(conn) < 0) {
        return NULL;
    }

    CM_Result *res = cmpqGetResult(conn);
    if (res == NULL) {
        return NULL;
    }
    return (char*)&(res->gr_resdata);
}

/*
 * @Description: init hosts file used by pssh when starting or stopping cluster.
 */
void init_hosts()
{
    uint32 i, j;
    g_execNodes = 0;

    FILE* fd = fopen(hosts_path, "w");
    if (fd == NULL) {
        char errBuffer[ERROR_LIMIT_LEN];
        write_runlog(
            ERROR, "could not open hosts file \"%s\": %s\n", hosts_path, strerror_r(errno, errBuffer, ERROR_LIMIT_LEN));
        exit(1);
    }

    for (i = 0; i < g_node_num; i++) {
        for (j = 0; j < g_node[i].sshCount; j++) {
            if (g_hostInfo[i][j] > MAX_INVALID_NODE_EXECTIMES &&
                ctl_command == STOP_COMMAND) {
                continue;
            }
            g_execNodes++;
            (void)fprintf(fd, "%s\n", g_node[i].sshChannel[j]);
        }
    }

    (void)fclose(fd);
}

/**
 * @brief
 *  Check if the node is disconnected when stopping the cluster.
 *
 * @param
 *  errCode with 255 represents the pssh error.
 */
void ReportAbnormalNode(const char *errInfo)
{
    const int MAX_IP_LEN = CM_IP_LENGTH + 2;
    for (uint32 i = 0; i < g_node_num; i++) {
        for (uint32 j = 0; j < g_node[i].sshCount; j++) {
            char tmp[MAX_IP_LEN] = {0};
            int rc = snprintf_s(tmp, MAX_IP_LEN, MAX_IP_LEN - 1, " %s ", g_node[i].sshChannel[j]);
            securec_check_intval(rc, (void)rc);
            if (strstr(errInfo, tmp) == NULL) {
                continue;
            }
            g_hostInfo[i][j]++;
            if (g_hostInfo[i][j] >= MAX_INVALID_NODE_EXECTIMES) {
                write_runlog(WARNING, "abnormal node %u.\n", g_node[i].node);
                g_stopAbnormal = true;
            }
        }
    }
}

/**
 * @brief
 * Check the cluster running status.
 *
 * @return
 * 0:  Represents the following scenarios:
 *     1. The cluster is running.
 *     2. The cluster is starting.
 *     3. The cluster has been stopped.
 * -1: Represents the followign scenarios:
 *     1. Failed to check the cluster running status.
 *     2. The cluster is stopping.
 */

int CheckClusterRunningStatus()
{
    uint32 errorCount = 0;
    char command[MAXPGPATH * 2] = {0};
    char buffer[MAXPGPATH] = {0};
    char invalidStr[MAXPGPATH] = {0};
    char* exitStr = NULL;
    uint32 stoppedNode = 0;
    uint32 uninstallNode = 0;
    uint32 disConNode = 0;
    uint32 stoppingNode = 0;
    uint32 normalNode = 0;
    uint32 failedNode = 0;
    uint32 timeoutNode = 0;
    const int MAX_TRY_TIMES = 3;
    int rcs = 0;
    int errorCode = 0;
    struct timeval cluster_status_check_time_begin;
    struct timeval cluster_status_check_time_end;

    if (got_stop || g_isRestop) {
        return -1;
    }

    if (ctl_command == START_COMMAND) {
        write_runlog(LOG, "checking cluster status.\n");
    }
    (void)gettimeofday(&cluster_status_check_time_begin, NULL);

    const int ret = snprintf_s(command, MAXPGPATH * 2, MAXPGPATH * 2 - 1,
        SYSTEMQUOTE "if [ -f \"/etc/profile\" ]; then "
        "source /etc/profile; "
        "fi; "
        "if [ -f \"$HOME/.bashrc\" ]; then source $HOME/.bashrc; fi; "
        "if [ -f \"%s\" ]; then source %s; fi; "
        "pssh %s -h %s \" "
        "if [ -f \\\"/etc/profile\\\" ]; then "
        "source /etc/profile; "
        "fi; "
        "if [ -f \\\"\\$HOME/.bashrc\\\" ]; then "
        "source \\$HOME/.bashrc; "
        "fi; "
        "if [ -f \\\"%s\\\" ]; then "
        "source %s; "
        "fi; "
        "%s/bin/%s check -B %s -T %s/bin/%s > /dev/null; "
        "\" 2>&1; " SYSTEMQUOTE,
        mpp_env_separate_file, mpp_env_separate_file, PSSH_TIMEOUT_OPTION, hosts_path, mpp_env_separate_file,
        mpp_env_separate_file, g_appPath, CM_CTL_BIN_NAME, CM_AGENT_BIN_NAME, g_appPath, CM_AGENT_BIN_NAME);
    securec_check_intval(ret,);

    init_hosts();

    FILE *fp = popen(command, "re");
    if (fp == NULL) {
        char error_buffer[ERROR_LIMIT_LEN] = {0};
        (void)strerror_r(errno, error_buffer, ERROR_LIMIT_LEN);
        write_runlog(DEBUG1, "Failed to execute the shell command: error=\"[%d] %s\","
            " command=\"%s\".\n", errno, error_buffer, command);
        (void)unlink(hosts_path);
        return -1;
    }

    write_runlog(DEBUG1, "start check cluster running status with command %s.\n", command);
    while (!feof(fp)) {
        if (fgets(buffer, MAXPGPATH - 1, fp)) {
            write_runlog(DEBUG1, "%s", buffer);

            if (strstr(buffer, "SUCCESS") != NULL) {
                stoppedNode++;
            } else if (strstr(buffer, "Timed out") != NULL) {
                ReportAbnormalNode(buffer);
                timeoutNode++;
            } else if (exitStr = strstr(buffer, "Exited with error code"), exitStr != NULL) {
                rcs = sscanf_s(exitStr, "%[^1-9]%d", invalidStr, MAXPGPATH, &errorCode);
                check_sscanf_s_result(rcs, 2);
                switch (errorCode) {
                    case UNINSTALL_NODE:
                        ReportAbnormalNode(buffer);
                        uninstallNode++;
                        break;
                    case DISCONNECT_NODE:
                        ReportAbnormalNode(buffer);
                        disConNode++;
                        break;
                    case STOPPING_NODE:
                        stoppingNode++;
                        break;
                    case ONLINE_NODE:
                    case NORMAL_NODE:
                        normalNode++;
                        break;
                    case FAILED_NODE:
                        failedNode++;
                        break;
                    default:
                        break;
                }
            }
        } else {
            errorCount++;
        }

        if (errorCount >= MAX_TRY_TIMES) {
            break;
        }
    }

    const int exitCode = pclose(fp);
    if (!g_isRestop) {
        (void)unlink(hosts_path);
    }

    (void)gettimeofday(&cluster_status_check_time_end, NULL);

    if (ctl_command == START_COMMAND) {
        write_runlog(LOG, "checking finished in %ld ms.\n",
            (cluster_status_check_time_end.tv_sec - cluster_status_check_time_begin.tv_sec) * 1000 +
            (cluster_status_check_time_end.tv_usec - cluster_status_check_time_begin.tv_usec) / 1000);

        /* ALL nodes were stopped or started. */
        if (WEXITSTATUS(exitCode) == PSSH_SUCCESS) {
            write_runlog(DEBUG1, "end check cluster running status with pssh.\n");
            return 0;
        } else if (timeoutNode > 0 && stoppingNode == 0 && failedNode == 0) {
            write_runlog(WARNING, "The ssh connection time out or the ssh trust relationship is"
                            "abnormal on some nodes. But the cluster will continue to start.\n");
            return 0;
        } else {
            switch (WEXITSTATUS(exitCode)) {
                /* The pssh exit with exit code 5 represents that the shell command exit with non-zero. */
                case COMMAND_TIMEOUT:
                    if (disConNode > 0) {
                        write_runlog(ERROR, "Failed to execute the shell command with the pssh exit code %d.\n",
                            WEXITSTATUS(exitCode));
                        return -1;
                    } else if (failedNode > 0) {  /* Some nodes checked failed. */
                        write_runlog(WARNING, "Failed to call the \"cm_ctl check\" operation.\n");
                        write_runlog(WARNING, "Failed to check the cluster running status.\n");
                        return 0;
                    } else if (stoppingNode > 0) {  /* Some nodes are stopping. */
                        write_runlog(ERROR, "cluster is already running. \n"
                            "HINT: Mabybe the cluster is coninually stopping in the background.\n"
                            "You can wait for a while and check whether the cluster stops, or immediately stop"
                            " the cluster by \"cm_ctl stop -m i\".\n");
                        return -1;
                    }
                    return 0;
                /**
                 * The pssh exit with exit code 4 represents the ssh connection times out or
                 * the ssh trust relationship is abnormal on some nodes.
                 */
                case PSSH_TIMEOUT:
                    if (disConNode > 0 && stoppingNode == 0 && failedNode == 0) {
                        write_runlog(WARNING, "The ssh connection time out or the ssh trust relationship is"
                            " abnormal on some nodes. But the cluster will continue to start.\n");
                        return 0;
                    }
                    break;
                default:
                    write_runlog(ERROR, "Failed to execute the shell command with the pssh exit code %d.\n",
                        WEXITSTATUS(exitCode));
                    write_runlog(ERROR, "failed to check the cluster running status.\n");
                    return -1;
            }
        }
    } else if (ctl_command == STOP_COMMAND) {
        if (timeoutNode > 0) {
            if (timeoutNode + disConNode + uninstallNode + stoppedNode + failedNode == g_execNodes) {
                write_runlog(DEBUG1, "end check cluster with timeoutNode %u, disConNode %u, unintallNode %u, "
                                     "stoppedNode %u, failedNode %u.\n",
                    timeoutNode, disConNode, uninstallNode, stoppedNode, failedNode);
                return 0;
            } else {
                write_runlog(ERROR, "end check cluster: timeoutNode %u, disConNode %u, normalNode %u, "
                                     "stoppedNode %u, stoppingNode %u, failedNode %u, uninstallNode %u.\n",
                    timeoutNode, disConNode, normalNode, stoppedNode, stoppingNode,
                    failedNode, uninstallNode);
                return -1;
            }
        } else {
            switch (WEXITSTATUS(exitCode)) {
                /* The pssh exit with exit code 5 represents that the shell command exit with non-zero. */
                case PSSH_TIMEOUT:
                    if (disConNode > 0) {
                        if (disConNode + uninstallNode + stoppedNode + failedNode == g_execNodes) {
                            write_runlog(DEBUG1, "end check cluster with disConNode %u, unintallNode %u, "
                                                 "stoppedNode %u, failedNode %u.\n",
                                disConNode, uninstallNode, stoppedNode, failedNode);
                            return 0;
                        }
                    }
                    break;
                /**
                 * The pssh exit with exit code 4 represents the ssh connection times out or
                 * the ssh trust relationship is abnormal on some nodes.
                 */
                case COMMAND_TIMEOUT:
                    if (uninstallNode + stoppedNode + failedNode  == g_execNodes) {
                        write_runlog(DEBUG1, "end check cluster with unintallNode %u, stoppedNode %u, failedNode %u.\n",
                            uninstallNode, stoppedNode, failedNode);
                        return 0;
                    }
                    break;
                case PSSH_SUCCESS:
                    if (stoppedNode == g_execNodes) {
                        write_runlog(DEBUG1, "end check cluster with stopped node %u.\n", stoppedNode);
                        return 0;
                    }
                    break;
                /* The pssh exit with other exit codes represents an unexpected error. */
                default:
                    write_runlog(ERROR, "end check cluster pssh result %d, disConNode %u, normalNode %u, "
                                         "stoppedNode %u, stoppingNode %u, failedNode %u, uninstallNode %u.\n",
                        WEXITSTATUS(exitCode), disConNode, normalNode, stoppedNode, stoppingNode,
                        failedNode, uninstallNode);
                    return -1;
            }
        }
    }
    return -1;
}

int CheckSingleClusterRunningStatus()
{
    struct timeval cluster_status_check_time_begin;
    struct timeval cluster_status_check_time_end;
    long expired_time;
    int ret = 0;

    (void)gettimeofday(&cluster_status_check_time_begin, NULL);

    if (is_node_stopping(0, 0, manual_start_file, result_path, mpp_env_separate_file)) {
        ret = stop_check_node(0);
    }

    (void)gettimeofday(&cluster_status_check_time_end, NULL);

    expired_time = (cluster_status_check_time_end.tv_sec - cluster_status_check_time_begin.tv_sec);
    write_runlog(LOG, "check node status take %ld seconds.\n", expired_time);
    return ret;
}

bool is_node_stopping(uint32 checkNode, uint32 currentNode, const char *manualStartFile, const char *resultFile,
                      const char *mppEnvSeperateFile)
{
    int result = -1;
    char command[MAX_PATH_LEN] = {0};
    int ret;

    if (checkNode == currentNode && strstr(g_appPath, "/var/chroot") == NULL) {
        ret = snprintf_s(command, MAX_PATH_LEN, MAX_PATH_LEN - 1, "ls %s > /dev/null 2>&1 \n echo  -e  $? > %s",
            manualStartFile, resultFile);
        securec_check_intval(ret, (void)ret);
        exec_system(command, &result, resultFile);
    } else {
        ret = snprintf_s(command, MAX_PATH_LEN, MAX_PATH_LEN - 1, "ls %s\" > /dev/null 2>&1; echo  -e $? > %s",
            manualStartFile, resultFile);
        securec_check_intval(ret, (void)ret);
        exec_system_ssh(checkNode, command, &result, resultFile, mppEnvSeperateFile);
    }

    return result == 0;
}

char* xstrdup(const char* s)
{
    char* result = NULL;
    result = strdup(s);
    if (result == NULL) {
        write_runlog(FATAL, "out of memory\n");
        exit(1);
    }
    return result;
}

void CheckDnNodeStatusById(uint32 node_id_check, int* result, uint32 dnIndex)
{
    char command[MAXPGPATH] = {0};
    char resultPath[MAXPGPATH] = {0};
    char checkDnProcessResultPath[MAX_PATH_LEN] = {0};
    int fd;
    bool flag = false;
    int ret = GetHomePath(resultPath, sizeof(resultPath));
    if (ret != EOK) {
        return;
    }
    errno_t tnRet = snprintf_s(checkDnProcessResultPath, MAX_PATH_LEN, MAX_PATH_LEN - 1,
        "%s/bin/checkDnProcessResult-XXXXXX", resultPath);
    securec_check_intval(tnRet, (void)tnRet);

    fd = mkstemp(checkDnProcessResultPath);
    if (fd <= 0) {
        write_runlog(ERROR, "failed to create the dn process check result file: errno=%d.\n", errno);
        flag = true;
    }

    if (node_id_check == g_nodeId && strstr(g_appPath, "/var/chroot") == NULL) {
        tnRet = snprintf_s(command,
            MAXPGPATH, MAXPGPATH - 1,
            "cm_ctl check -B %s -T %s  \n echo  -e  $? > %s",
            GetDnProcessName(),
            g_node[node_id_check].datanode[dnIndex].datanodeLocalDataPath,
            flag ? result_path : checkDnProcessResultPath);
        securec_check_intval(tnRet, (void)tnRet);
        exec_system(command, result, flag ? result_path : checkDnProcessResultPath);
    } else {
        tnRet = snprintf_s(command,
            MAXPGPATH, MAXPGPATH - 1,
            "cm_ctl check -B %s -T %s\" > /dev/null 2>&1; echo  -e $? > %s",
            GetDnProcessName(),
            g_node[node_id_check].datanode[dnIndex].datanodeLocalDataPath,
            flag ? result_path : checkDnProcessResultPath);
        securec_check_intval(tnRet, (void)tnRet);
        exec_system_ssh(node_id_check, command, result,
            flag ? result_path : checkDnProcessResultPath, mpp_env_separate_file);
    }
    if (fd > 0) {
        (void)close(fd);
    }
    (void)unlink(flag ? result_path : checkDnProcessResultPath);
}

void CheckCnNodeStatusById(uint32 node_id_check, int* result)
{
    errno_t tnRet = 0;
    char command[MAXPGPATH] = {0};
    char resultPath[MAXPGPATH] = {0};
    char checkCnProcessResultPath[MAX_PATH_LEN] = {0};
    int fd;
    bool flag = false;

    int ret = GetHomePath(resultPath, MAXPGPATH);
    if (ret != EOK) {
        return;
    }
    ret = snprintf_s(checkCnProcessResultPath, MAX_PATH_LEN, MAX_PATH_LEN - 1,
        "%s/bin/checkCnProcessResult-XXXXXX", resultPath);
    securec_check_intval(ret, (void)ret);

    fd = mkstemp(checkCnProcessResultPath);
    if (fd <= 0) {
        write_runlog(ERROR, "failed to create the cn process check result file: errno=%d.\n", errno);
        flag = true;
    }

    if (node_id_check == g_nodeId && strstr(g_appPath, "/var/chroot") == NULL) {
        tnRet = snprintf_s(command,
            MAXPGPATH, MAXPGPATH - 1,
            "cm_ctl check -B %s -T %s  \n echo  -e  $? > %s",
            COORDINATE_BIN_NAME,
            g_node[node_id_check].DataPath,
            flag ? result_path : checkCnProcessResultPath);
        securec_check_intval(tnRet, (void)tnRet);
        exec_system(command, result, flag ? result_path : checkCnProcessResultPath);
    } else {
        tnRet = snprintf_s(command,
            MAXPGPATH, MAXPGPATH - 1,
            "cm_ctl check -B %s -T %s\" > /dev/null 2>&1; echo  -e $? > %s",
            COORDINATE_BIN_NAME,
            g_node[node_id_check].DataPath,
            flag ? result_path : checkCnProcessResultPath);
        securec_check_intval(tnRet, (void)tnRet);
        exec_system_ssh(node_id_check, command, result, flag ? result_path : checkCnProcessResultPath,
            mpp_env_separate_file);
    }
    if (fd > 0) {
        (void)close(fd);
    }
    (void)unlink(flag ? result_path : checkCnProcessResultPath);
}


void CheckGtmNodeStatusById(uint32 node_id_check, int* result)
{
    errno_t tnRet = 0;
    char command[MAXPGPATH] = {0};
    char resultPath[MAXPGPATH] = {0};
    char checkGTMProcessResultPath[MAX_PATH_LEN] = {0};
    int fd;
    bool flag = false;
    int ret = GetHomePath(resultPath, MAXPGPATH);
    if (ret != EOK) {
        return;
    }
    ret = snprintf_s(checkGTMProcessResultPath, MAX_PATH_LEN, MAX_PATH_LEN - 1,
        "%s/bin/checkGTMProcessResult-XXXXXX", resultPath);
    securec_check_intval(ret, (void)ret);

    fd = mkstemp(checkGTMProcessResultPath);
    if (fd <= 0) {
        write_runlog(ERROR, "failed to create the gtm process check result file: errno=%d.\n", errno);
        flag = true;
    }

    if (node_id_check == g_nodeId && strstr(g_appPath, "/var/chroot") == NULL) {
        tnRet = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1, "cm_ctl check -B %s -T %s  \n echo  -e  $? > %s",
            GTM_BIN_NAME, g_node[node_id_check].gtmLocalDataPath, flag ? result_path : checkGTMProcessResultPath);
        securec_check_intval(tnRet, (void)tnRet);
        exec_system(command, result, flag ? result_path : checkGTMProcessResultPath);
    } else {
        tnRet = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1,
            "cm_ctl check -B %s -T %s\" > /dev/null 2>&1; echo  -e $? > %s",
            GTM_BIN_NAME, g_node[node_id_check].gtmLocalDataPath, flag ? result_path : checkGTMProcessResultPath);
        securec_check_intval(tnRet, (void)tnRet);
        exec_system_ssh(node_id_check, command, result,
            flag ? result_path : checkGTMProcessResultPath, mpp_env_separate_file);
    }
    if (fd > 0) {
        (void)close(fd);
    }
    (void)unlink(flag ? result_path : checkGTMProcessResultPath);
}

/**
 * @brief Check whether the static config file exist in the target node.
 *
 * @param [in] nodeIndex: The node index in the cluster config.
 *
 * @return 0: if the static config file exist, return 0.
 * @return 1: if the static config file does not exist, return 1.
 * @return -1: if failed to check the static config file status, return -1.
 */
int checkStaticConfigExist(uint32 nodeIndex)
{
    int result = -1;
    char command[MAXPGPATH] = {0};
    int ret;
    char resultPath[MAXPGPATH] = {0};
    char checkStaticConfigPath[MAX_PATH_LEN] = {0};
    int fd;
    
    ret = GetHomePath(resultPath, MAXPGPATH);
    if (ret != EOK) {
        return -1;
    }
    ret = snprintf_s(checkStaticConfigPath, MAX_PATH_LEN, MAX_PATH_LEN - 1,
        "%s/bin/checkStaticConfig-XXXXXX", resultPath);
    securec_check_intval(ret, (void)ret);

    fd = mkstemp(checkStaticConfigPath);
    if (fd <= 0) {
        write_runlog(ERROR, "failed to create the result file: errno=%d.\n", errno);
        return -1;
    }

    /* Check whether the cluster static config file exist. */
    if (nodeIndex == g_nodeId && strstr(g_appPath, "/var/chroot") == NULL) {
        ret = snprintf_s(command,
            MAXPGPATH, MAXPGPATH - 1,
            "ls %s > /dev/null 2>&1 \n echo -e $? > %s",
            cluster_static_config,
            checkStaticConfigPath);
        securec_check_intval(ret, (void)ret);
        exec_system(command, &result, checkStaticConfigPath);
    } else {
        ret = snprintf_s(command,
            MAXPGPATH, MAXPGPATH - 1,
            "ls %s\" > /dev/null 2>&1; echo -e $? > %s",
            cluster_static_config,
            checkStaticConfigPath);
        securec_check_intval(ret, (void)ret);
        exec_system_ssh(nodeIndex, command, &result, checkStaticConfigPath, mpp_env_separate_file);
    }

    (void)close(fd);
    (void)unlink(checkStaticConfigPath);

    return result;
}

static status_t GetCmsConnect(CM_Conn **curConn)
{
    status_t st = CM_SUCCESS;
    int32 tryTime = MAX_CONN_TIMES;
    const uint32 waitForCms = 10;
    const uint32 sleepInterval = 3;
    static bool isFirst = true;
    if (isFirst) {
        cm_sleep(waitForCms);
        isFirst = false;
    }
    do {
        do_conn_cmserver(false, 0, false, curConn);
        if ((*curConn) == NULL) {
            write_runlog(DEBUG1, "send ddb msg to cm_server, connect fail. node_id:%u.\n",
                g_commandOperationNodeId);
            st = CM_ERROR;
            write_runlog(LOG, ".");
            cm_sleep(sleepInterval);
        } else {
            break;
        }
        --tryTime;
    } while (st != CM_SUCCESS && (tryTime > 0));

    if ((*curConn) == NULL) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static void GetCltSendDdbOper(
    const char *key, const char *value, const char *threadName, CltSendDdbOper *sendOper, DDB_OPER dbOper)
{
    sendOper->msgType = (int32)MSG_CLIENT_CM_DDB_OPER;
    sendOper->dbOper = dbOper;
    sendOper->node = g_currentNode->node;
    errno_t rc = strcpy_s(sendOper->threadName, THREAD_NAME_LEN, threadName);
    securec_check_errno(rc, (void)rc);
    sendOper->keyLen = (uint32)strlen(key);
    rc = strcpy_s(sendOper->key, MAX_PATH_LEN, key);
    securec_check_errno(rc, (void)rc);
    if (value != NULL) {
        sendOper->valueLen = (uint32)strlen(value);
        rc = strcpy_s(sendOper->value, MAX_PATH_LEN, value);
        securec_check_errno(rc, (void)rc);
    }
}

static bool HandleCmsDdbMsg(const char *key, const char *threadName, DDB_OPER dbOper, CM_Conn **curConn)
{
    if (*curConn == NULL) {
        return false;
    }
    int32 ret = cm_client_flush_msg(*curConn);
    if (ret == TCP_SOCKET_ERROR_EPIPE) {
        CMPQfinish(*curConn);
        *curConn = NULL;
        return false;
    }
    char *receiveMsg = recv_cm_server_cmd(*curConn);
    if (receiveMsg == NULL) {
        return false;
    }
    cm_msg_type *cmMsgType = (cm_msg_type *)receiveMsg;
    if (cmMsgType->msg_type != (int32)MSG_CM_CLIENT_DDB_OPER_ACK) {
        return false;
    }
    CmSendDdbOperRes *msgDdbOper = (CmSendDdbOperRes *)receiveMsg;
    if (msgDdbOper->dbOper != dbOper) {
        return false;
    }
    if (strcmp(key, msgDdbOper->key) != 0 || strcmp(threadName, msgDdbOper->threadName) != 0) {
        write_runlog(DEBUG1, "key is [%s: %s], threadName is [%s: %s].\n",
            key, msgDdbOper->key, threadName, msgDdbOper->threadName);
        return false;
    }
    return msgDdbOper->exeStatus;
}

static int32 SendDdbMsgAndGetDdbRes(
    const char *key, const char *threadName, CltSendDdbOper *sendOper, CM_Conn **curConn)
{
    int32 ret = cm_client_send_msg(*curConn, 'C', (char *)sendOper, sizeof(CltSendDdbOper));
    if (ret != 0) {
        FINISH_CONNECTION_WITHOUT_EXITCODE((*curConn));
        return -1;
    }
    int32 tryTimes = WAIT_MSG_RES_TIMES;
    bool rt = false;
    do {
        rt = HandleCmsDdbMsg(key, threadName, sendOper->dbOper, curConn);
        if (!rt) {
            cm_sleep(1);
        }
        --tryTimes;
    } while (!rt && (tryTimes > 0));
    if (!rt) {
        return NEED_SEND_AGAIN;
    }
    write_runlog(DEBUG1, "success to get handleCmsDdbMsg, key_value is (%s: %s), threadName is %s.\n",
        key, sendOper->value, threadName);
    return SUCCESS_SEND_MSG;
}

status_t SendKVToCms(const char *key, const char *value, const char *threadName)
{
    CM_Conn *curConn = NULL;
    status_t st = GetCmsConnect(&curConn);
    if (st != CM_SUCCESS) {
        return CM_ERROR;
    }
    CltSendDdbOper sendOper = {0};
    GetCltSendDdbOper(key, value, threadName, &sendOper, DDB_SET_OPER);
    int32 tryTime = SEND_MSG_TIMES;
    int32 ret = 0;
    do {
        ret = SendDdbMsgAndGetDdbRes(key, threadName, &sendOper, &curConn);
        if (ret == -1) {
            FINISH_CONNECTION_WITHOUT_EXITCODE(curConn);
            return CM_ERROR;
        }
        if (ret != SUCCESS_SEND_MSG) {
            write_runlog(LOG, ".");
            cm_sleep(1);
        }
        --tryTime;
    } while (ret != SUCCESS_SEND_MSG && (tryTime > 0));
    FINISH_CONNECTION_WITHOUT_EXITCODE(curConn);
    if (ret != SUCCESS_SEND_MSG) {
        write_runlog(DEBUG1, "Failed to send msg(%s: %s) threadName is %s to cms.\n", key, value, threadName);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

int cmctl_getenv(const char* env_var, char* output_env_value, uint32 env_value_len)
{
    return cm_getenv(env_var, output_env_value, env_value_len);
}

static void connect_to_first_normal_cmserver(uint32 cmsNodeIdx, CM_Conn **curConn)
{
    for (uint32 jj = 0; jj < g_node[cmsNodeIdx].cmServerListenCount; jj++) {
        for (uint32 ii = 0; ii < g_currentNode->cmAgentListenCount; ii++) {
            if (DoConnCmserver(cmsNodeIdx, jj, ii, curConn, true) == CM_SUCCESS) {
                return;
            }
            g_normal_cm_server_node_index = PG_UINT32_MAX;
        }
    }
}

/**
 * @brief
 *  Obtains the current time and get the exact number of seconds (counted from January 1, 1970).
 *
 * @note
 *  You do not need to pay attention to the return value of the system function "gettimeofday".
 *   If the "timeval" parameter is NULL, an error is returned.
 *
 * @return
 *  Returns the exact number of seconds (counted from January 1, 1970).
 */
time_t get_start_time()
{
    timespec tv = {0, 0};

    (void)clock_gettime(CLOCK_MONOTONIC, &tv);

    return tv.tv_sec;
}


/**
 * @brief
 *  Obtain the current time and compare it with the input time.
 *
 * @note
 *  We will not think about that the current time minus the start time will be out of range.
 *
 * @return
 *  Return the number of the current time minus the start time.
 */
time_t check_with_end_time(const time_t start_time)
{
    Assert(start_time > 0);

    timespec tv = {0, 0};
    (void)clock_gettime(CLOCK_MONOTONIC, &tv);

    return tv.tv_sec - start_time;
}

void exec_system(const char *cmd, int *result, const char *resultPath)
{
    char result_str[g_max_buf_len + 1] = {0};
    if (resultPath == NULL) {
        resultPath = result_path;
    }

    int rc = system(cmd);
    if (rc != 0) {
        write_runlog(ERROR,
                     "failed to execute the command: command=\"%s\", systemReturn=%d, commandReturn=%d,"
                     " errno=%d.\n",
                     cmd, rc, SHELL_RETURN_CODE(rc), errno);
        *result = -1;
        return;
    }
    char realPath[MAX_PATH_LEN] = {0};
    GetRealFile(realPath, MAX_PATH_LEN, resultPath);
    FILE *fd = fopen(realPath, "r");
    if (fd == NULL) {
        write_runlog(DEBUG1, "failed to open the result file: errno=%d.\n", errno);
        *result = -1;
        return;
    }
    /* read result */
    size_t bytesread = fread(result_str, 1, (size_t)g_max_buf_len, fd);
    if (bytesread > (size_t)g_max_buf_len) {
        write_runlog(ERROR, "exec_system fread failed! file=%s, bytesread=%u\n", realPath, (uint32)bytesread);
        (void)fclose(fd);
        *result = -1;
        return;
    }

    *result = atoi(result_str);
    (void)fclose(fd);
}

void exec_system_ssh(uint32 remote_nodeid, const char *cmd, int *result, const char *resultPath,
                     const char *mppEnvSeperateFile)
{
    const int SHELL_COMMAND_NOT_EXIST = 127;
    const int COMMAND_NOT_EXIST_FIND_NUM = 20;
    int rc;
    char command[MAXPGPATH] = {0};
    char result_str[g_max_buf_len + 1] = {0};
    int command_not_exist_num = 0;
    int ret;

    if (resultPath == NULL) {
        resultPath = result_path;
    }

    if (g_node[remote_nodeid].sshCount != 0) {
        if (mppEnvSeperateFile[0] == '\0') {
            ret = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1, "pssh %s -s -H %s \"%s", PSSH_TIMEOUT_OPTION,
                             g_node[remote_nodeid].sshChannel[0], cmd);
            securec_check_intval(ret, (void)ret);
        } else {
            ret = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1, "pssh %s -s -H %s \"source %s;%s", PSSH_TIMEOUT_OPTION,
                             g_node[remote_nodeid].sshChannel[0], mppEnvSeperateFile, cmd);
            securec_check_intval(ret, (void)ret);
        }

        rc = system(command);
        if (rc != 0) {
            write_runlog(ERROR,
                         "failed to execute the ssh command: nodeId=%u, command=\"%s\", systemReturn=%d,"
                         " commandReturn=%d, errno=%d.\n",
                         g_node[remote_nodeid].node, command, rc, SHELL_RETURN_CODE(rc), errno);
            *result = -1;
            return;
        }
    }
    char realPath[MAX_PATH_LEN] = {0};
    GetRealFile(realPath, MAX_PATH_LEN, resultPath);
    FILE *fd = fopen(realPath, "r");
    if (fd == NULL) {
        write_runlog(ERROR, "failed to open the result file: errno=%d.\n", errno);
        *result = -1;
        return;
    }
    /* read result */
    size_t bytesread = fread(result_str, 1, g_max_buf_len, fd);
    if (bytesread > (size_t)g_max_buf_len) {
        write_runlog(ERROR, "exec_system_ssh fread failed! file=%s, bytesread=%u\n", realPath, (uint32)bytesread);
        (void)fclose(fd);
        *result = -1;
        return;
    }
    *result = atoi(result_str);
    if (*result != 0) {
        write_runlog(DEBUG1,
                     "execute the ssh command: nodeId=%u, command=\"%s\", "
                     " commandReturn=%d.\n",
                     g_node[remote_nodeid].node, cmd, *result);
    }
    if (*result == SHELL_COMMAND_NOT_EXIST) {
        command_not_exist_num++;
        if (command_not_exist_num >= COMMAND_NOT_EXIST_FIND_NUM) {
            (void)fclose(fd);
            write_runlog(FATAL, "command:%s failed, error is 127, command not exist on node %u. \n", command,
                         remote_nodeid);
            exit(-1);
        }
    }
    (void)fclose(fd);
}


/*
 * routines to check memory allocations and fail noisily.
 */
void* pg_malloc(size_t size)
{
    /* Avoid unportable behavior of malloc(0) */
    if (size == 0) {
        size = 1;
    }
    void *result = malloc(size);
    if (result == NULL) {
        write_runlog(FATAL, "out of memory\n");
        exit(1);
    }
    return result;
}

int runCmdByNodeId(const char* command, uint32 nodeid)
{
    int ret = 0;
    uint32 ii;
    if (nodeid == g_currentNode->node) {
        ret = system(command);
    } else {
        for (ii = 0; ii < g_node_num; ii++) {
            if (g_node[ii].node == nodeid) {
                break;
            }
        }
        if (ii < g_node_num) {
            ret = ssh_exec(&g_node[ii], command);
        } else {
            write_runlog(ERROR, "can't find the nodeid: %u\n", nodeid);
            ret = -1;
        }
    }
    if (ret != 0) {
        write_runlog(DEBUG1, "fail to execute command %s, errno=%d.\n", command, errno);
    }
    return ret;
}

/* estimate how many times required to wait for operation's completion. */
int caculate_default_timeout(CtlCommand cmd)
{
    uint32 base_timeout, node_count;

    switch (cmd) {
        case STOP_COMMAND:
            base_timeout = STOP_DEFAULT_WAIT;
            break;
        case START_COMMAND:
            base_timeout = START_DEFAULT_WAIT;
            break;
        default:
            base_timeout = DEFAULT_WAIT;
            break;
    }

    if (g_command_operation_azName == NULL && g_commandOperationNodeId == 0) {
        /* cluster */
        node_count = g_node_num;
    } else if (g_command_operation_azName != NULL) {
        /* AZ */
        node_count = 0;
        for (uint32 ii = 0; ii < g_node_num; ii++) {
            if (strcmp(g_node[ii].azName, g_command_operation_azName) == 0) {
                node_count++;
            }
        }
    } else {
        /* one node or instance */
        node_count = 1;
    }

    return (int)(base_timeout + g_node_operation_cost * node_count);
}

int GetDatanodeRelationInfo(uint32 nodeId, const char *cmData, cm_to_ctl_get_datanode_relation_ack *getInstanceMsg)
{
    uint32 instanceId = 0;
    int instanceType = 0;
    int ret;
    int i = 0;
    int timePass = 0;
    char* receiveMsg = NULL;
    cm_to_ctl_get_datanode_relation_ack *getInstanceMsgPtr = NULL;
    cm_to_ctl_get_datanode_relation_ack_ipv4 *getInstanceMsgPtrIpv4 = NULL;
    ctl_to_cm_datanode_relation_info cmDatanodeRelationInfoContent = {0};

    ret = FindInstanceIdAndType(nodeId, cmData, &instanceId, &instanceType);
    if (ret != 0) {
        write_runlog(ERROR, "can't find the nodeId:%u, data_path:%s.\n", nodeId, cmData);
        return -1;
    }

    do_conn_cmserver(false, 0);
    if (CmServer_conn == NULL) {
        write_runlog(ERROR, "this time connect cms failed is NULL.\n ");
        return -1;
    }

    cmDatanodeRelationInfoContent.msg_type = (int)MSG_CTL_CM_GET_DATANODE_RELATION;
    cmDatanodeRelationInfoContent.instanceId = instanceId;
    cmDatanodeRelationInfoContent.instance_type = instanceType;
    cmDatanodeRelationInfoContent.node = nodeId;

    ret = cm_client_send_msg(
        CmServer_conn, 'C', (char*)&cmDatanodeRelationInfoContent, sizeof(cmDatanodeRelationInfoContent));
    if (ret != 0) {
        FINISH_CONNECTION((CmServer_conn), -1);
    }

    for (;;) {
        (void)sleep(1);
        timePass++;
        if (CmServer_conn != NULL) {
            ret = cm_client_flush_msg(CmServer_conn);
            if (ret == TCP_SOCKET_ERROR_EPIPE) {
                FINISH_CONNECTION((CmServer_conn), -1);
            }
            receiveMsg = recv_cm_server_cmd(CmServer_conn);
        }
        if (receiveMsg != NULL) {
            if (undocumentedVersion != 0 && undocumentedVersion < SUPPORT_IPV6_VERSION) {
                getInstanceMsgPtrIpv4 = (cm_to_ctl_get_datanode_relation_ack_ipv4 *)receiveMsg;
                CmToCtlGetDatanodeRelationAckV1ToV2(getInstanceMsgPtrIpv4, getInstanceMsg);
                break;
            }
            getInstanceMsgPtr = (cm_to_ctl_get_datanode_relation_ack *)receiveMsg;
            getInstanceMsg->command_result = getInstanceMsgPtr->command_result;
            getInstanceMsg->member_index = getInstanceMsgPtr->member_index;
            for (i = 0; i < CM_PRIMARY_STANDBY_MAX_NUM; i++) {
                getInstanceMsg->data_node_member[i] = getInstanceMsgPtr->data_node_member[i];
                getInstanceMsg->instanceMember[i] = getInstanceMsgPtr->instanceMember[i];
                getInstanceMsg->gtm_member[i] = getInstanceMsgPtr->gtm_member[i];
            }
            break;
        }
        if (timePass > DEFAULT_GET_INFO_TIME) {
            write_runlog(ERROR,
                "Get the datanode relation information timeout in %d.\n",
                DEFAULT_GET_INFO_TIME);
            FINISH_CONNECTION((CmServer_conn), -1);
        }
    }
    CMPQfinish(CmServer_conn);
    CmServer_conn = NULL;
    return 0;
}

void InstanceInformationRecord(uint32 nodeIndex, const cm_to_ctl_instance_status* cmToCtlInstanceStatusPtr)
{
    uint32 j = 0;
    uint32 instanceIndex = 0;
    switch (cmToCtlInstanceStatusPtr->instance_type) {
        case INSTANCE_TYPE_COORDINATE:
            write_runlog(DEBUG1,
                "Coordinator State: node=%u nodeName=%s ip=%s port=%u instanceId=%u DataPath=%s status=%s\n",
                g_node[nodeIndex].node, g_node[nodeIndex].nodeName, g_node[nodeIndex].coordinateListenIP[0],
                g_node[nodeIndex].coordinatePort, cmToCtlInstanceStatusPtr->instanceId,
                g_node[nodeIndex].DataPath,
                datanode_role_int_to_string(cmToCtlInstanceStatusPtr->coordinatemember.status));
            break;
        case INSTANCE_TYPE_GTM:
            write_runlog(DEBUG1,
                "GTM State: node=%u nodeName=%s ip=%s instanceId=%u DataPath=%s static_role=%s role=%s "
                "connect_status=%s sync_mode=%s\n",
                g_node[nodeIndex].node, g_node[nodeIndex].nodeName, g_node[nodeIndex].gtmLocalListenIP[0],
                cmToCtlInstanceStatusPtr->instanceId, g_node[nodeIndex].gtmLocalDataPath,
                datanode_static_role_int_to_string(g_node[nodeIndex].gtmRole),
                datanode_role_int_to_string(cmToCtlInstanceStatusPtr->gtm_member.local_status.local_role),
                gtm_con_int_to_string(cmToCtlInstanceStatusPtr->gtm_member.local_status.connect_status),
                datanode_wal_sync_state_int_to_string(
                    cmToCtlInstanceStatusPtr->gtm_member.local_status.sync_mode));
            break;
        case INSTANCE_TYPE_DATANODE:
            for (j = 0; j < g_node[nodeIndex].datanodeCount; j++) {
                if (g_node[nodeIndex].datanode[j].datanodeId == cmToCtlInstanceStatusPtr->instanceId) {
                    instanceIndex = j;
                    break;
                }
            }
            write_runlog(DEBUG1,
                "Datanode State: node=%u nodeName=%s ip=%s port=%u instanceId=%u DataPath=%s static_role=%s role=%s "
                "state=%s buildReason=%s\n",
                g_node[nodeIndex].node, g_node[nodeIndex].nodeName,
                g_node[nodeIndex].datanode[instanceIndex].datanodeListenIP[0],
                g_node[nodeIndex].datanode[instanceIndex].datanodePort, cmToCtlInstanceStatusPtr->instanceId,
                g_node[nodeIndex].datanode[instanceIndex].datanodeLocalDataPath,
                datanode_static_role_int_to_string(g_node[nodeIndex].datanode[instanceIndex].datanodeRole),
                datanode_role_int_to_string(cmToCtlInstanceStatusPtr->data_node_member.local_status.local_role),
                datanode_dbstate_int_to_string(cmToCtlInstanceStatusPtr->data_node_member.local_status.db_state),
                datanode_rebuild_reason_int_to_string(
                    cmToCtlInstanceStatusPtr->data_node_member.local_status.buildReason));
            break;
        default:
            write_runlog(DEBUG1, "Unknown instance_type\n");
            break;
    }
    return;
}

void SetServerSocketWithEtcdInfo(ServerSocket *server, staticNodeConfig *node)
{
    server->nodeIdInfo.azName = node->azName;
    server->nodeIdInfo.nodeId = node->node;
    server->nodeIdInfo.instd = node->etcdId;
    server->nodeInfo.nodeName = node->etcdName;
    server->nodeInfo.len = CM_NODE_NAME;
    server->host = node->etcdClientListenIPs[0];
    server->port = node->etcdClientListenPort;
}

void EtcdIpPortInfoBalance(ServerSocket *server)
{
    uint32 j = 0;
    for (uint32 i = 0; i < g_node_num; i++) {
        if (g_node[i].etcd) {
            SetServerSocketWithEtcdInfo(&(server[j]), &(g_node[i]));
            ++j;
        }
    }
}

static status_t InitDdbServerList(DrvApiInfo *drvApiInfo)
{
    size_t len = (g_etcd_num + 1) * sizeof(ServerSocket);
    ServerSocket *server = (ServerSocket *)malloc(len);
    if (server == NULL) {
        write_runlog(FATAL, "out of memory!\n");
        return CM_ERROR;
    }
    errno_t rc = memset_s(server, len, 0, len);
    securec_check_errno(rc, FREE_AND_RESET(server));

    EtcdIpPortInfoBalance(server);
    server[g_etcd_num].host = NULL;

    drvApiInfo->serverList = server;
    drvApiInfo->serverLen = g_etcd_num + 1;
    drvApiInfo->nodeNum = g_etcd_num;
    return CM_SUCCESS;
}

status_t InitDdbCfgApi(DrvApiInfo *drvApiInfo, int32 timeOut)
{
    status_t initServer = InitDdbServerList(drvApiInfo);
    if (initServer != CM_SUCCESS) {
        FREE_AND_RESET(drvApiInfo->serverList);
        return CM_ERROR;
    }
    drvApiInfo->modId = MOD_CMCTL;
    drvApiInfo->nodeId = g_currentNode->node;
    drvApiInfo->timeOut = timeOut;

    drvApiInfo->client_t.tlsPath = &g_tlsPath;
    return CM_SUCCESS;
}

status_t ServerDdbInit()
{
    if (g_etcd_num == 0) {
        write_runlog(DEBUG1, "g_etcd_num is %u, cannot create ddb conn.\n", g_etcd_num);
        return CM_SUCCESS;
    }
    g_sess = (DdbConn *)malloc(sizeof(DdbConn));
    if (g_sess == NULL) {
        write_runlog(ERROR, "g_sess is NULL.\n");
        return CM_ERROR;
    }
    errno_t rc = memset_s(g_sess, sizeof(DdbConn), 0, sizeof(DdbConn));
    securec_check_errno(rc, FREE_AND_RESET(g_sess));
    DdbInitConfig config;
    rc = memset_s(&config, sizeof(DdbInitConfig), 0, sizeof(DdbInitConfig));
    securec_check_errno(rc, (void)rc);
    config.type = DB_ETCD;
    status_t st = InitDdbCfgApi(&config.drvApiInfo, DDB_DEFAULT_TIMEOUT);
    CM_RETURN_IFERR(st);
    st = InitDdbConn(g_sess, &config);
    FREE_AND_RESET(config.drvApiInfo.serverList);
    return st;
}

void FreeDdbInfo()
{
    if (g_sess == NULL) {
        return;
    }
    DdbFreeNodeInfo(g_sess);
    if (DdbFreeConn(g_sess) != CM_SUCCESS) {
        write_runlog(DEBUG1, "failed to free conn.\n");
    }
    FREE_AND_RESET(g_sess);
}

bool CheckDdbHealth()
{
    if (g_sess == NULL) {
        return true;
    }
    const int ddbHealthTimeout = 4000;
    return DdbIsValid(g_sess, DDB_HEAL_COUNT, ddbHealthTimeout);
}

bool IsCmsPrimary(const staticNodeConfig *node)
{
    const char *primaryIp = CmServer_conn->pghost;

    for (uint32 i = 0; i < node->sshCount; ++i) {
        if (strcmp(node->sshChannel[i], primaryIp) == 0) {
            return true;
        }
    }

    return false;
}

static status_t KillOneCms(uint32 nodeIndex)
{
    int ret;
    char killCmd[CM_PATH_LENGTH] = {0};
    char gausshomePath[CM_PATH_LENGTH] = {0};

    if (GetHomePath(gausshomePath, sizeof(gausshomePath)) != EOK) {
        return CM_ERROR;
    }
    if (g_node[nodeIndex].node == g_currentNode->node) {
        ret = snprintf_s(killCmd, CM_PATH_LENGTH, CM_PATH_LENGTH - 1,
            "ps -eo pid,cmd|grep -v grep|grep %s/bin/cm_server |awk '{print $1}'|xargs kill -9 > /dev/null 2>&1 &",
            gausshomePath);
        securec_check_intval(ret, (void)ret);
        ret = system(killCmd);
    } else {
        ret = snprintf_s(killCmd, CM_PATH_LENGTH, CM_PATH_LENGTH - 1,
            "ps -eo pid,cmd|grep -v grep|grep %s/bin/cm_server |awk '{print \\$1}'|xargs kill -9 > /dev/null 2>&1 &",
            gausshomePath);
        securec_check_intval(ret, (void)ret);
        ret = ssh_exec(&g_node[nodeIndex], killCmd);
    }
    if (ret != 0) {
        write_runlog(ERROR, "cm_ctl exec ssh failed, node(%u), errno=%d.\n", g_node[nodeIndex].node, errno);
        return CM_ERROR;
    }
    write_runlog(DEBUG1, "kill cms node(%u) success.\n", g_node[nodeIndex].node);

    return CM_SUCCESS;
}

// if not need kill primary cms, connect primary cms first, then kill cms
status_t KillAllCms(bool isNeedKillPrimaryCms)
{
    status_t killResult = CM_SUCCESS;
    uint32 *cmsNodeIndex = GetCmsNodeIndex();

    for (uint32 i = 0; i < g_cm_server_num; ++i) {
        if (!isNeedKillPrimaryCms && IsCmsPrimary(&g_node[cmsNodeIndex[i]])) {
            write_runlog(DEBUG1, "The node(%u) is primary or has no cms, can't kill it.\n", g_node[i].node);
            continue;
        }
        if (KillOneCms(cmsNodeIndex[i]) != CM_SUCCESS) {
            killResult = CM_ERROR;
            write_runlog(DEBUG1, "kill the cms(node=%u) failed.\n", g_node[i].node);
        }
    }

    return killResult;
}

void ReleaseConn(CM_Conn *con)
{
    if (con != NULL) {
        CMPQfinish(con);
    }
}

bool SetOfflineNode(uint32 nodeIndex, CM_Conn *con)
{
    if (!IsCmSharedStorageMode()) {
        return false;
    }

    int times = 0;
    char *receiveMsg = NULL;
    cm_msg_type *msgType = NULL;
    GetSharedStorageInfo sendMsg = {0};
    CmsSharedStorageInfo *msgAck = NULL;

    sendMsg.msg_type = (int)MSG_GET_SHARED_STORAGE_INFO;
    if (cm_client_send_msg(con, 'C', (char*)&sendMsg, sizeof(sendMsg)) != 0) {
        write_runlog(DEBUG1, "SetOfflineNode send msg to cms fail!\n");
        return false;
    }

    for (;;) {
        if (times++ > SHARED_STORAGE_MODE_TIMEOUT) {
            break;
        }
        if (cm_client_flush_msg(con) == TCP_SOCKET_ERROR_EPIPE) {
            ReleaseConn(con);
            return false;
        }
        receiveMsg = recv_cm_server_cmd(con);
        if (receiveMsg != NULL) {
            msgType = (cm_msg_type*)receiveMsg;
            if (msgType->msg_type != (int)MSG_GET_SHARED_STORAGE_INFO_ACK) {
                write_runlog(DEBUG1, "SetOfflineNode get unknown msg!\n");
                return false;
            }
            msgAck = (CmsSharedStorageInfo*)(receiveMsg);
            if (msgAck->doradoIp[0] == '\0') {
                write_runlog(DEBUG1, "can't get dorado ip!\n");
                return false;
            }
            break;
        }
        cm_sleep(1);
    }
    if (msgAck == NULL) {
        write_runlog(DEBUG1, "SetOfflineNode msgAck is NULL.\n");
        return false;
    }
    if (strcmp(trim(msgAck->doradoIp), g_node[nodeIndex].sshChannel[0]) == 0) {
        write_runlog(DEBUG1, "Line:%d node is offline, ip is %s.\n", __LINE__, g_currentNode->sshChannel[0]);
        return true;
    }

    return false;
}

void GetUpgradeVersionFromCmaConfig()
{
    int rc;
    char cmAgentConfigFile[MAX_PATH_LEN] = {0};
    char gausshomePath[MAXPGPATH] = {0};
    rc = cmctl_getenv("GAUSSHOME", gausshomePath, sizeof(gausshomePath));
    if (rc != EOK) {
        write_runlog(FATAL, "Line: %d.Get GAUSSHOME failed, please check.\n", __LINE__);
        return;
    }

    if (strstr(gausshomePath, "/var/chroot") == NULL) {
        rc = snprintf_s(cmAgentConfigFile, MAX_PATH_LEN, MAX_PATH_LEN - 1,
            "%s/cm_agent/cm_agent.conf", g_currentNode->cmDataPath);
    } else {
        rc = snprintf_s(cmAgentConfigFile, MAX_PATH_LEN, MAX_PATH_LEN - 1,
            "/var/chroot/%s/cm_agent/cm_agent.conf", g_currentNode->cmDataPath);
    }
    securec_check_intval(rc, (void)rc);

    if (access(cmAgentConfigFile, R_OK) != 0) {
        write_runlog(WARNING, "The cm_agent.conf is unreadable, set undocumentedVersion 0\n");
        undocumentedVersion = 0;
        return;
    }
    undocumentedVersion = get_uint32_value_from_config(cmAgentConfigFile, "upgrade_from", 0);
}

void CtlGetCmJsonConf()
{
    int ret = ReadCmConfJson(NULL);
    if (!IsReadConfJsonSuccess(ret)) {
        write_runlog(DEBUG1, "read cm conf json failed, ret=%d, reason=\"%s\".\n", ret, ReadConfJsonFailStr(ret));
    }
    if (InitAllResStat(DEBUG1) != CM_SUCCESS) {
        write_runlog(DEBUG1, "init res status failed.\n");
    }
}

bool IsTimeOut(const cmTime_t *lastTime, const char *str)
{
    cmTime_t curTime = {0};
    (void)clock_gettime(CLOCK_MONOTONIC, &curTime);
    const long maxTimeInterval = 60;
    if(curTime.tv_sec - lastTime->tv_sec > maxTimeInterval) {
        write_runlog(DEBUG1, "%s this has timeout(%ld), it will exit.\n", str, maxTimeInterval);
        return true;
    }
    return false;
}
