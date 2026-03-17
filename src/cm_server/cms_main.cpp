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
 * cms_main.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_server/cms_main.cpp
 *
 * -------------------------------------------------------------------------
 */
#include <sys/epoll.h>
#include "alarm/alarm_log.h"
#include "cm/cm_cgroup.h"
#include "hotpatch/hotpatch.h"
#include "cms_global_params.h"
#include "cms_alarm.h"
#include "cms_process_messages.h"
#include "cms_threads.h"
#include "cms_ddb.h"
#include "cms_common.h"
#include "cms_common_res.h"
#include "config.h"
#include "cm/cs_ssl.h"
#include "cm/cm_cipher.h"
#include "cm/cm_json_config.h"
#include "cms_rhb.h"
#include "cms_main.h"

static const char *g_force_start_file_str = "force_start.info";

typedef struct unauth_connection_t {
    CM_Connection* conn;
    struct unauth_connection_t* next;
} unauth_connection;

static unauth_connection* g_unauth_conn_list = NULL;
static int g_unauthConnCount = 0;
volatile sig_atomic_t got_stop = 0;
volatile sig_atomic_t g_gotParameterReload = 0;
volatile sig_atomic_t g_SetReplaceCnStatus = 0;

/* main thread exit after HA thread close connection */
volatile sig_atomic_t ha_connection_closed = 0;
pid_t cm_agent = 0;
uint64 gConnSeq = 0;

const char* g_progname;
static char g_appPath[MAXPGPATH] = {0};
char cm_server_bin_path[MAX_PATH_LEN] = {0};
char g_replaceCnStatusFile[MAX_PATH_LEN] = {0};

int check_process_status(const char *processName);

static int ServerListenSocket[MAXLISTEN] = {0};

int cm_server_send_msg(CM_Connection* con, char msgtype, const char* s, size_t len, int log_level)
{
    int ret = 0;
    if (con != NULL && con->fd >= 0) {
        if (con->port == NULL || con->port->remote_type == CM_CTL) {
            log_level = DEBUG1;
        }
        if (msgtype == 'S') {
            if (((const cm_msg_type*)s)->msg_type == (int32)MSG_CM_AGENT_NOTIFY_CN_CENTRAL_NODE) {
                if (g_centralNode.instanceId != ((const cm_to_agent_notify_cn_central_node*)s)->instanceId &&
                    g_centralNode.node != ((const cm_to_agent_notify_cn_central_node*)s)->node) {
                    write_runlog(log_level, "cmserver send msg to node %u, msgtype: %s\n",
                        con->port->node_id, cluster_msg_int_to_string(((const cm_msg_type*)s)->msg_type));
                }
            } else if (((const cm_msg_type*)s)->msg_type != (int32)MSG_CM_AGENT_DROPPED_CN) {
                write_runlog(log_level, "cmserver send msg to node %u, msgtype: %s\n",
                    con->port->node_id, cluster_msg_int_to_string(((const cm_msg_type*)s)->msg_type));
            }
        }
        ret = pq_putmessage(con->port, msgtype, s, len);
        if (ret != 0) {
            write_runlog(ERROR, "pq_putmessage return error ret=%d\n", ret);
            return ret;
        }
    }
    return 0;
}

int CmsSendAndFlushMsg(CM_Connection* con, char msgType, const char *s, size_t len, int logLevel)
{
    int ret = cm_server_send_msg(con, msgType, s, len, logLevel);
    if (ret == 0) {
        ret = cm_server_flush_msg(con);
    }
    return ret;
}

static void GetCmdlineOpt(int argc, char* argv[])
{
    long logChoice = 0;
    const int base = 10;
    if (argc > 1) {
        logChoice = strtol(argv[1], NULL, base);

        switch (logChoice) {
            case LOG_DESTION_STDERR:
                log_destion_choice = LOG_DESTION_FILE;
                break;

            case LOG_DESTION_SYSLOG:
                log_destion_choice = LOG_DESTION_SYSLOG;
                break;

            case LOG_DESTION_FILE:
                log_destion_choice = LOG_DESTION_FILE;
                break;

            case LOG_DESTION_DEV_NULL:
                log_destion_choice = LOG_DESTION_DEV_NULL;
                break;

            default:
                log_destion_choice = LOG_DESTION_FILE;
                break;
        }
    }
}

static void stop_signal_reaper(int arg)
{
    got_stop = 1;
}

static void close_all_agent_connections(int arg)
{
    for (uint32 i = 0; i < gIOThreads.count; i++) {
        gIOThreads.threads[i].gotConnClose = 1;
    }
}

static void reload_cmserver_parameters(int arg)
{
    g_gotParameterReload = 1;
}

static void SetReloadDdbConfigFlag(int arg)
{
    if (g_HA_status->local_role == CM_SERVER_PRIMARY) {
        g_SetReplaceCnStatus = 1;
    }
}

static int get_prog_path()
{
    errno_t rc = memset_s(g_cmManualStartPath, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(g_cmInstanceManualStartPath, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(minority_az_start_file, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(g_cmsPModeFilePath, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(g_minorityAzArbitrateFile, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(cm_server_bin_path, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(g_replaceCnStatusFile, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(cm_dynamic_configure_path, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(g_cmStaticConfigurePath, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(g_tlsPath.caFile, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(g_tlsPath.crtFile, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(g_tlsPath.keyFile, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(g_logicClusterListPath, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(instance_maintance_path, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(cm_force_start_file_path, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(cluster_maintance_path, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(g_cmManualPausePath, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    if (GetHomePath(g_appPath, sizeof(g_appPath)) != 0) {
        (void)fprintf(stderr, "Get GAUSSHOME failed, please check.\n");
        return -1;
    } else {
        int rcs = snprintf_s(
            g_cmManualStartPath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/%s", g_appPath, CM_CLUSTER_MANUAL_START);
        canonicalize_path(g_cmManualStartPath);
        securec_check_intval(rcs, (void)rcs);
        rcs = snprintf_s(g_cmInstanceManualStartPath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/%s",
            g_appPath, CM_INSTANCE_MANUAL_START);
        securec_check_intval(rcs, (void)rcs);
        rcs = snprintf_s(
            minority_az_start_file, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/%s", g_appPath, MINORITY_AZ_START);
        securec_check_intval(rcs, (void)rcs);
        canonicalize_path(minority_az_start_file);
        rcs = snprintf_s(
            g_cmsPModeFilePath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/%s", g_appPath, CMS_PMODE_FILE_NAME);
        securec_check_intval(rcs, (void)rcs);
        canonicalize_path(g_cmsPModeFilePath);
        rcs = snprintf_s(
            g_minorityAzArbitrateFile, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/%s", g_appPath, MINORITY_AZ_ARBITRATE);
        securec_check_intval(rcs, (void)rcs);
        rcs =
            snprintf_s(g_replaceCnStatusFile, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/replace_cn_status", g_appPath);
        securec_check_intval(rcs, (void)rcs);
        canonicalize_path(g_replaceCnStatusFile);
        rcs = snprintf_s(
            cm_dynamic_configure_path, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/%s", g_appPath, DYNAMC_CONFIG_FILE);
        securec_check_intval(rcs, (void)rcs);
        canonicalize_path(cm_dynamic_configure_path);
        rcs = snprintf_s(
            g_cmStaticConfigurePath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/%s", g_appPath, CM_STATIC_CONFIG_FILE);
        securec_check_intval(rcs, (void)rcs);
        rcs = snprintf_s(
            g_logicClusterListPath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/%s", g_appPath, LOGIC_CLUSTER_LIST);
        securec_check_intval(rcs, (void)rcs);
        rcs = snprintf_s(
            instance_maintance_path, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/%s", g_appPath, INSTANCE_MAINTANCE);
        securec_check_intval(rcs, (void)rcs);
        rcs = snprintf_s(
            cm_force_start_file_path, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/%s", g_appPath, g_force_start_file_str);
        securec_check_intval(rcs, (void)rcs);
        canonicalize_path(cm_force_start_file_path);
        rcs = snprintf_s(
            cluster_maintance_path, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/%s", g_appPath, CLUSTER_MAINTANCE);
        securec_check_intval(rcs, (void)rcs);
        canonicalize_path(cluster_maintance_path);
        rcs = snprintf_s(
            g_cmManualPausePath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/%s", g_appPath, CM_CLUSTER_MANUAL_PAUSE);
        securec_check_intval(rcs, (void)rcs);
        InitClientCrt(g_appPath);
    }

    return 0;
}

static void init_cluster_state_mode()
{
    instance_heartbeat_timeout = INIT_CLUSTER_MODE_INSTANCE_DEAL_TIME;
    g_init_cluster_mode = true;
    g_init_cluster_delay_time = INIT_CLUSTER_MODE_INSTANCE_DEAL_TIME;
    write_runlog(LOG, "cluster is on init mode, set instance timeout to %d.\n", INIT_CLUSTER_MODE_INSTANCE_DEAL_TIME);
}

static void SetCmsIndexStr(char *cmServerIdxStr, uint32 strLen, uint32 cmServerIdx, uint32 nodeIdx)
{
    char cmServerStr[MAX_PATH_LEN];
    errno_t rc = snprintf_s(cmServerStr, MAX_PATH_LEN, MAX_PATH_LEN - 1,
        "[%u node:%u, cmserverId:%u, cmServerIndex:%u], ",
        cmServerIdx, g_node[nodeIdx].node, g_node[nodeIdx].cmServerId, nodeIdx);
    securec_check_intval(rc, (void)rc);
    rc = strcat_s(cmServerIdxStr, strLen, cmServerStr);
    securec_check_errno(rc, (void)rc);
}

static void initialize_cm_server_node_index(void)
{
    uint32 i;
    uint32 j = 0;
    uint32 k;
    char cmServerIdxStr[MAX_PATH_LEN] = {0};
    uint32 cm_instance_id[CM_PRIMARY_STANDBY_NUM] = {0};
    uint32 cmServerNum = 0;
    /* get cmserver instance id */
    for (i = 0; i < g_node_num; i++) {
        if (g_node[i].cmServerLevel == 1) {
            cm_instance_id[j] = g_node[i].cmServerId;
            j++;
            cmServerNum++;
        }
    }
#undef qsort
    qsort(cm_instance_id, cmServerNum, sizeof(uint32), node_index_Comparator);

    j = 0;
    for (k = 0; k < cmServerNum; k++) {
        for (i = 0; i < g_node_num; i++) {
            if (cm_instance_id[k] != g_node[i].cmServerId) {
                continue;
            }
            g_nodeIndexForCmServer[j] = i;
            SetCmsIndexStr(cmServerIdxStr, MAX_PATH_LEN, j, i);
            j++;
            break;
        }
    }
    (void)fprintf(stderr, "[%s]: cmserverNum is %u, and cmserver info is %s.\n",
        g_progname, cmServerNum, cmServerIdxStr);
}

static int read_config_file_check(void)
{
    int err_no = 0;

    int status = read_config_file(g_cmStaticConfigurePath, &err_no, false);
    if (status == 0) {
        if (g_nodeHeader.node == 0) {
            write_runlog(ERROR, "current node self is invalid  node =%u\n", g_nodeHeader.node);
            return -1;
        }

        int ret = find_node_index_by_nodeid(g_nodeHeader.node, &g_current_node_index);
        if (ret != 0) {
            write_runlog(ERROR, "find_node_index_by_nodeid failed, nodeId=%u.\n", g_nodeHeader.node);
            return -1;
        }

        ret = find_current_node_by_nodeid();
        if (ret != 0) {
            write_runlog(ERROR, "find_current_node_by_nodeid failed, nodeId=%u.\n", g_nodeHeader.node);
            return -1;
        }

        initialize_cm_server_node_index();
    } else if (status == OUT_OF_MEMORY) {
        write_runlog(ERROR, "read staticNodeConfig failed! out of memeory.\n");
        return -1;
    } else {
        write_runlog(ERROR, "read staticNodeConfig failed! errno = %d.\n", err_no);
        return -1;
    }

    if (access(g_logicClusterListPath, F_OK) == 0) {
        status = read_logic_cluster_config_files(g_logicClusterListPath, &err_no);
        char errBuffer[ERROR_LIMIT_LEN] = {0};
        switch (status) {
            case OPEN_FILE_ERROR: {
                write_runlog(FATAL, "%s: could not open the logic cluster static config file: %s\n",
                    g_progname, strerror_r(err_no, errBuffer, ERROR_LIMIT_LEN));
                exit(1);
            }
            case READ_FILE_ERROR: {
                write_runlog(FATAL, "%s: could not read logic cluster static config files: %s\n",
                    g_progname, strerror_r(err_no, errBuffer, ERROR_LIMIT_LEN));
                exit(1);
            }
            case OUT_OF_MEMORY:
                write_runlog(FATAL, "%s: out of memory\n", g_progname);
                exit(1);
            default:
                break;
        }
    }

    return 0;
}

int AddNodeInDynamicConfigure(const cm_instance_role_group* instance_role_group_ptr)
{
    errno_t rc = memcpy_s((void*)(&(g_instance_role_group_ptr[g_dynamic_header->relationCount])),
        sizeof(cm_instance_role_group),
        instance_role_group_ptr,
        sizeof(cm_instance_role_group));
    securec_check_errno(rc, (void)rc);

    g_dynamic_header->relationCount++;
    return 0;
}

int search_HA_node(int node_type, uint32 localPort, uint32 LocalHAListenCount, const char (*LocalHAIP)[CM_IP_LENGTH],
    uint32 peerPort, uint32 PeerHAListenCount, const char (*PeerHAIP)[CM_IP_LENGTH], int *node_index,
    int *instance_index)
{
    int i;
    int max_node_count;
    char input_local_listen_ip[CM_IP_ALL_NUM_LENGTH];
    char input_peer_listen_ip[CM_IP_ALL_NUM_LENGTH];
    char local_listen_ip[CM_IP_ALL_NUM_LENGTH];
    char peer_listen_ip[CM_IP_ALL_NUM_LENGTH];
    int j = 0;
    errno_t rc;

    *node_index = 0;
    *instance_index = 0;

    max_node_count = (int)g_node_num;
    rc = memset_s(input_local_listen_ip, CM_IP_ALL_NUM_LENGTH, 0, CM_IP_ALL_NUM_LENGTH);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(input_peer_listen_ip, CM_IP_ALL_NUM_LENGTH, 0, CM_IP_ALL_NUM_LENGTH);
    securec_check_errno(rc, (void)rc);
    listen_ip_merge(LocalHAListenCount, LocalHAIP, input_local_listen_ip, CM_IP_ALL_NUM_LENGTH);
    listen_ip_merge(PeerHAListenCount, PeerHAIP, input_peer_listen_ip, CM_IP_ALL_NUM_LENGTH);

    if (node_type == CM_DATANODE && !g_multi_az_cluster) {
        for (i = 0; i < max_node_count; i++) {
            for (j = 0; j < (int)g_node[i].datanodeCount; j++) {
                if (g_node[i].datanode[j].datanodePeerRole == PRIMARY_DN) {
                    if ((g_node[i].datanode[j].datanodeLocalHAPort != peerPort) ||
                        (g_node[i].datanode[j].datanodePeerHAPort != localPort)) {
                        continue;
                    }
                } else if (g_node[i].datanode[j].datanodePeer2Role == PRIMARY_DN) {
                    if ((g_node[i].datanode[j].datanodeLocalHAPort != peerPort) ||
                        (g_node[i].datanode[j].datanodePeer2HAPort != localPort)) {
                        continue;
                    }
                } else {
                    continue;
                }

                rc = memset_s(local_listen_ip, CM_IP_ALL_NUM_LENGTH, 0, CM_IP_ALL_NUM_LENGTH);
                securec_check_errno(rc, (void)rc);
                rc = memset_s(peer_listen_ip, CM_IP_ALL_NUM_LENGTH, 0, CM_IP_ALL_NUM_LENGTH);
                securec_check_errno(rc, (void)rc);
                listen_ip_merge(g_node[i].datanode[j].datanodeLocalHAListenCount,
                    g_node[i].datanode[j].datanodeLocalHAIP,
                    local_listen_ip, CM_IP_ALL_NUM_LENGTH);
                if (g_node[i].datanode[j].datanodePeerRole == PRIMARY_DN) {
                    listen_ip_merge(g_node[i].datanode[j].datanodePeerHAListenCount,
                        g_node[i].datanode[j].datanodePeerHAIP,
                        peer_listen_ip, CM_IP_ALL_NUM_LENGTH);
                } else if (g_node[i].datanode[j].datanodePeer2Role == PRIMARY_DN) {
                    listen_ip_merge(g_node[i].datanode[j].datanodePeer2HAListenCount,
                        g_node[i].datanode[j].datanodePeer2HAIP,
                        peer_listen_ip, CM_IP_ALL_NUM_LENGTH);
                }
                if ((strncmp(local_listen_ip, input_peer_listen_ip, CM_IP_ALL_NUM_LENGTH) == 0) &&
                    (strncmp(peer_listen_ip, input_local_listen_ip, CM_IP_ALL_NUM_LENGTH) == 0)) {
                    *node_index = i;
                    *instance_index = j;
                    return 0;
                }
            }
        }
    }

    if (node_type == CM_DATANODE && g_multi_az_cluster) {
        for (i = 0; i < max_node_count; i++) {
            for (j = 0; j < (int)g_node[i].datanodeCount; j++) {
                bool be_continue = true;
                uint32 primary_dn_idx = 0;
                for (uint32 dnId = 1; dnId < g_dn_replication_num; ++dnId) {
                    be_continue = true;
                    if (g_node[i].datanode[j].peerDatanodes[dnId - 1].datanodePeerRole == PRIMARY_DN) {
                        be_continue = false;  /* may won't continue if get one primary dn */
                        primary_dn_idx = (dnId - 1);
                        if ((g_node[i].datanode[j].datanodeLocalHAPort != peerPort) ||
                            (g_node[i].datanode[j].peerDatanodes[dnId - 1].datanodePeerHAPort != localPort)) {
                            be_continue = true;  /* still continue if the port is not right */
                        }
                        break;  /* break if we get one primary DN */
                    }
                }
                if (be_continue) {
                    continue;
                }

                rc = memset_s(local_listen_ip, CM_IP_ALL_NUM_LENGTH, 0, CM_IP_ALL_NUM_LENGTH);
                securec_check_errno(rc, (void)rc);
                rc = memset_s(peer_listen_ip, CM_IP_ALL_NUM_LENGTH, 0, CM_IP_ALL_NUM_LENGTH);
                securec_check_errno(rc, (void)rc);
                listen_ip_merge(g_node[i].datanode[j].datanodeLocalHAListenCount,
                    g_node[i].datanode[j].datanodeLocalHAIP,
                    local_listen_ip, CM_IP_ALL_NUM_LENGTH);

                if (g_node[i].datanode[j].peerDatanodes[primary_dn_idx].datanodePeerRole == PRIMARY_DN) {
                    listen_ip_merge(g_node[i].datanode[j].peerDatanodes[primary_dn_idx].datanodePeerHAListenCount,
                        g_node[i].datanode[j].peerDatanodes[primary_dn_idx].datanodePeerHAIP,
                        peer_listen_ip, CM_IP_ALL_NUM_LENGTH);
                }
                if ((strncmp(local_listen_ip, input_peer_listen_ip, CM_IP_ALL_NUM_LENGTH) == 0) &&
                    (strncmp(peer_listen_ip, input_local_listen_ip, CM_IP_ALL_NUM_LENGTH) == 0)) {
                    *node_index = i;
                    *instance_index = (int)j;
                    return 0;
                }
            }
        }
    }

#ifdef ENABLE_MULTIPLE_NODES
    if (node_type == CM_GTM) {
        execParam para;
        para.localPort = localPort;
        para.peerPort = peerPort;
        para.local_listen_ip = local_listen_ip;
        para.peer_listen_ip = peer_listen_ip;
        para.input_local_listen_ip = input_local_listen_ip;
        para.input_peer_listen_ip = input_peer_listen_ip;
        para.node_index = node_index;
        para.instance_index = instance_index;
        return SearchHaGtmNode((const execParam*)&para);
    }
#endif

    return -1;
}

int InitInstanceData(int *instance_index_arry, int *node_index_arry, int i, int j)
{
    int node_index = 0;
    int instance_index = 0;
    int ret = 0;
    for (uint32 dnId = 1; dnId < g_dn_replication_num; dnId++) {
        node_index = 0;
        instance_index = 0;
        if (g_node[i].datanode[j].peerDatanodes[dnId - 1].datanodePeerRole == STANDBY_DN ||
            g_node[i].datanode[j].peerDatanodes[dnId - 1].datanodePeerRole == CASCADE_STANDBY_DN) {
            ret = search_HA_node(CM_DATANODE,
                g_node[i].datanode[j].datanodeLocalHAPort,
                g_node[i].datanode[j].datanodeLocalHAListenCount,
                g_node[i].datanode[j].datanodeLocalHAIP,
                g_node[i].datanode[j].peerDatanodes[dnId - 1].datanodePeerHAPort,
                g_node[i].datanode[j].peerDatanodes[dnId - 1].datanodePeerHAListenCount,
                g_node[i].datanode[j].peerDatanodes[dnId - 1].datanodePeerHAIP,
                &node_index, &instance_index);
            node_index_arry[dnId - 1] = node_index;
            instance_index_arry[dnId - 1] = instance_index;
        } else {
            ret = -1;
        }
        if (ret != 0) {
            break;
        }
    }
    return ret;
}

static int32 CfgRole2StaticRole(uint32 cfgRole)
{
    switch (cfgRole) {
        case PRIMARY_DN:
            return INSTANCE_ROLE_PRIMARY;
        case STANDBY_DN:
            return INSTANCE_ROLE_STANDBY;
        case DUMMY_STANDBY_DN:
            return INSTANCE_ROLE_DUMMY_STANDBY;
        case CASCADE_STANDBY_DN:
            return INSTANCE_ROLE_CASCADE_STANDBY;
        default:
            write_runlog(ERROR, "invalid cfgRole(%u).\n", cfgRole);
            return INSTANCE_ROLE_STANDBY;
    }
}

void PutInstanceDataWhenSuccess(
    cm_instance_role_group *instance_group, const int *instance_index_arry, const int *node_index_arry, int i, int j)
{
    int node_index = 0;
    int instance_index = 0;
    uint32 instanceMember_count = sizeof(instance_group->instanceMember) / sizeof(cm_instance_role_status);
    uint32 min_count =
        instanceMember_count < g_dn_replication_num ? instanceMember_count : g_dn_replication_num;
    error_t rc = memset_s(instance_group, sizeof(cm_instance_role_group), 0, sizeof(cm_instance_role_group));
    securec_check_errno(rc, (void)rc);
    instance_group->count = 1;
    /* copy az info from static to dynamic config */
    rc = memcpy_s(instance_group->instanceMember[0].azName, CM_AZ_NAME, g_node[i].azName, CM_AZ_NAME);
    securec_check_errno(rc, (void)rc);
    instance_group->instanceMember[0].azPriority = g_node[i].azPriority;

    instance_group->instanceMember[0].node = g_node[i].node;
    instance_group->instanceMember[0].instanceId = g_node[i].datanode[j].datanodeId;
    instance_group->instanceMember[0].instanceType = INSTANCE_TYPE_DATANODE;
    instance_group->instanceMember[0].role = INSTANCE_ROLE_PRIMARY;
    instance_group->instanceMember[0].dataReplicationMode = INSTANCE_DATA_REPLICATION_ASYNC;
    instance_group->instanceMember[0].instanceRoleInit = INSTANCE_ROLE_PRIMARY;

    for (int idx = 1; idx < (int)min_count; ++idx) {
        instance_group->count++;
        node_index = node_index_arry[idx - 1];
        instance_index = instance_index_arry[idx - 1];
        /* copy az info from static to dynamic config */
        rc =
            memcpy_s(instance_group->instanceMember[idx].azName, CM_AZ_NAME, g_node[node_index].azName, CM_AZ_NAME);
        securec_check_errno(rc, (void)rc);
        instance_group->instanceMember[idx].azPriority = g_node[node_index].azPriority;
        instance_group->instanceMember[idx].node = g_node[node_index].node;
        instance_group->instanceMember[idx].instanceId = g_node[node_index].datanode[instance_index].datanodeId;
        instance_group->instanceMember[idx].instanceType = INSTANCE_TYPE_DATANODE;
        instance_group->instanceMember[idx].role =
            CfgRole2StaticRole(g_node[node_index].datanode[instance_index].datanodeRole);
        instance_group->instanceMember[idx].dataReplicationMode = INSTANCE_DATA_REPLICATION_ASYNC;
        instance_group->instanceMember[idx].instanceRoleInit =
            CfgRole2StaticRole(g_node[node_index].datanode[instance_index].datanodeRole);
    }
}

void PutInstanceDataWhenError(cm_instance_role_group *instance_group, int i, int j)
{
    error_t rc = memset_s(instance_group, sizeof(cm_instance_role_group), 0, sizeof(cm_instance_role_group));
    securec_check_errno(rc, (void)rc);
    instance_group->count = 1;
    /* copy az info from static to dynamic config */
    rc = memcpy_s(instance_group->instanceMember[0].azName, CM_AZ_NAME, g_node[i].azName, CM_AZ_NAME);
    securec_check_errno(rc, (void)rc);
    instance_group->instanceMember[0].azPriority = g_node[i].azPriority;
    instance_group->instanceMember[0].node = g_node[i].node;
    instance_group->instanceMember[0].instanceId = g_node[i].datanode[j].datanodeId;
    instance_group->instanceMember[0].instanceType = INSTANCE_TYPE_DATANODE;
    instance_group->instanceMember[0].role = INSTANCE_ROLE_PRIMARY;
    instance_group->instanceMember[0].dataReplicationMode = INSTANCE_DATA_REPLICATION_ASYNC;
    instance_group->instanceMember[0].instanceRoleInit = INSTANCE_ROLE_PRIMARY;
    return;
}

void BuildDynamicDnMazConfig(cm_instance_role_group *instance_group, bool *dynamicModified, int i, int j)
{
    uint32 group_index;
    int member_index;
    int ret =
        find_node_in_dynamic_configure(g_node[i].node, g_node[i].datanode[j].datanodeId, &group_index, &member_index);
    if (ret == 0) {
        /* do nothing. */
    } else {
        int instance_index_arry[CM_NODE_MAXNUM] = {0};
        int node_index_arry[CM_NODE_MAXNUM] = {0};
        ret = InitInstanceData(instance_index_arry, node_index_arry, i, j);
        if (ret == 0) {
            PutInstanceDataWhenSuccess(instance_group, instance_index_arry, node_index_arry, i, j);
        } else {
            PutInstanceDataWhenError(instance_group, i, j);
        }

        *dynamicModified = true;
        (void)AddNodeInDynamicConfigure(instance_group);
    }

    return;
}

void SetInstanceGroupStatus(cm_instance_role_group *instance_group, int node_index, int instance_index)
{
    const int index = 2;
    instance_group->count++;
    instance_group->instanceMember[index].node = g_node[node_index].node;
    instance_group->instanceMember[index].instanceId = g_node[node_index].datanode[instance_index].datanodeId;
    instance_group->instanceMember[index].instanceType = INSTANCE_TYPE_DATANODE;
    instance_group->instanceMember[index].role = INSTANCE_ROLE_DUMMY_STANDBY;
    instance_group->instanceMember[index].dataReplicationMode = INSTANCE_DATA_REPLICATION_ASYNC;
    instance_group->instanceMember[index].instanceRoleInit = INSTANCE_ROLE_DUMMY_STANDBY;
    return;
}

void BuildDynamicDnSazConfigIfSucc(
    cm_instance_role_group *instGrp, int32 i, int32 j, int32 curNodeIdx, int32 curInstIdx)
{
    int ret = 0;
    int32 nodeIdx = 0;
    int32 instIdx = 0;
    int rc = memset_s(instGrp, sizeof(cm_instance_role_group), 0, sizeof(cm_instance_role_group));
    securec_check_errno(rc, (void)rc);
    instGrp->count = 2;
    instGrp->instanceMember[0].node = g_node[i].node;
    instGrp->instanceMember[0].instanceId = g_node[i].datanode[j].datanodeId;
    instGrp->instanceMember[0].instanceType = INSTANCE_TYPE_DATANODE;
    instGrp->instanceMember[0].role = INSTANCE_ROLE_PRIMARY;
    instGrp->instanceMember[0].dataReplicationMode = INSTANCE_DATA_REPLICATION_ASYNC;
    instGrp->instanceMember[0].instanceRoleInit = INSTANCE_ROLE_PRIMARY;

    instGrp->instanceMember[1].node = g_node[curNodeIdx].node;
    instGrp->instanceMember[1].instanceId = g_node[curNodeIdx].datanode[curInstIdx].datanodeId;
    instGrp->instanceMember[1].instanceType = INSTANCE_TYPE_DATANODE;
    instGrp->instanceMember[1].role = INSTANCE_ROLE_STANDBY;
    instGrp->instanceMember[1].dataReplicationMode = INSTANCE_DATA_REPLICATION_ASYNC;
    instGrp->instanceMember[1].instanceRoleInit = INSTANCE_ROLE_STANDBY;

    if (g_node[i].datanode[j].datanodePeerRole == DUMMY_STANDBY_DN) {
        ret = search_HA_node(CM_DATANODE,
            g_node[i].datanode[j].datanodeLocalHAPort, g_node[i].datanode[j].datanodeLocalHAListenCount,
            g_node[i].datanode[j].datanodeLocalHAIP, g_node[i].datanode[j].datanodePeerHAPort,
            g_node[i].datanode[j].datanodePeerHAListenCount, g_node[i].datanode[j].datanodePeerHAIP,
            &nodeIdx,
            &instIdx);
    } else if (g_node[i].datanode[j].datanodePeer2Role == DUMMY_STANDBY_DN) {
        ret = search_HA_node(CM_DATANODE,
            g_node[i].datanode[j].datanodeLocalHAPort, g_node[i].datanode[j].datanodeLocalHAListenCount,
            g_node[i].datanode[j].datanodeLocalHAIP, g_node[i].datanode[j].datanodePeer2HAPort,
            g_node[i].datanode[j].datanodePeer2HAListenCount, g_node[i].datanode[j].datanodePeer2HAIP,
            &nodeIdx,
            &instIdx);
    } else {
        ret = -1;
    }

    if (ret == 0) {
        SetInstanceGroupStatus(instGrp, nodeIdx, instIdx);
    }
    return;
}

void BuildDynamicDnSazConfig(
    cm_instance_role_group *instance_group, bool *dynamicModified, int i, int j)
{
    int node_index = 0;
    int instance_index = 0;
    uint32 group_index;
    int member_index;
    int ret =
        find_node_in_dynamic_configure(g_node[i].node, g_node[i].datanode[j].datanodeId, &group_index, &member_index);
    if (ret == 0) {
        /* do nothing */
    } else {
        if (g_node[i].datanode[j].datanodePeerRole == STANDBY_DN) {
            ret = search_HA_node(CM_DATANODE,
                g_node[i].datanode[j].datanodeLocalHAPort, g_node[i].datanode[j].datanodeLocalHAListenCount,
                g_node[i].datanode[j].datanodeLocalHAIP, g_node[i].datanode[j].datanodePeerHAPort,
                g_node[i].datanode[j].datanodePeerHAListenCount, g_node[i].datanode[j].datanodePeerHAIP,
                &node_index,
                &instance_index);
        } else if (g_node[i].datanode[j].datanodePeer2Role == STANDBY_DN) {
            ret = search_HA_node(CM_DATANODE,
                g_node[i].datanode[j].datanodeLocalHAPort, g_node[i].datanode[j].datanodeLocalHAListenCount,
                g_node[i].datanode[j].datanodeLocalHAIP, g_node[i].datanode[j].datanodePeer2HAPort,
                g_node[i].datanode[j].datanodePeer2HAListenCount, g_node[i].datanode[j].datanodePeer2HAIP,
                &node_index,
                &instance_index);
        } else {
            ret = -1;
        }

        if (ret == 0) {
            BuildDynamicDnSazConfigIfSucc(instance_group, i, j, node_index, instance_index);
        } else {
            int rc = memset_s(instance_group, sizeof(cm_instance_role_group), 0, sizeof(cm_instance_role_group));
            securec_check_errno(rc, (void)rc);
            instance_group->count = 1;
            instance_group->instanceMember[0].node = g_node[i].node;
            instance_group->instanceMember[0].instanceId = g_node[i].datanode[j].datanodeId;
            instance_group->instanceMember[0].instanceType = INSTANCE_TYPE_DATANODE;
            instance_group->instanceMember[0].role = INSTANCE_ROLE_PRIMARY;
            instance_group->instanceMember[0].dataReplicationMode = INSTANCE_DATA_REPLICATION_ASYNC;
            instance_group->instanceMember[0].instanceRoleInit = INSTANCE_ROLE_PRIMARY;
        }
        *dynamicModified = true;
        (void)AddNodeInDynamicConfigure(instance_group);
    }
    return;
}

int BuildDynamicConfigFile(bool* dynamicModified)
{
    int i;
    int j;
    cm_instance_role_group instance_group;
    uint32 actual_relation_count = 0;
    uint32 dnInstanceCnt = 0;
    *dynamicModified = false;

    instance_group.count = 0;
    for (i = 0; i < (int)g_node_num; i++) {
#ifdef ENABLE_MULTIPLE_NODES
        if (g_node[i].coordinate == 1) {
            actual_relation_count++;
            BuildDynamicCoordConfig(&instance_group, dynamicModified, i);
        }
#endif
        if (g_multi_az_cluster) {
#ifdef ENABLE_MULTIPLE_NODES
            if ((g_node[i].gtm == 1) && (g_node[i].gtmRole == PRIMARY_GTM)) {
                actual_relation_count++;
                BuildDynamicGtmMazConfig(&instance_group, dynamicModified, i);
            }
#endif
            for (j = 0; j < (int)g_node[i].datanodeCount; j++) {
                if (g_node[i].datanode[j].datanodeRole != PRIMARY_DN) {
                    continue;
                }
                actual_relation_count++;
                dnInstanceCnt++;
                BuildDynamicDnMazConfig(&instance_group, dynamicModified, i, j);
            }
        } else {
#ifdef ENABLE_MULTIPLE_NODES
            if ((g_node[i].gtm == 1) && (g_node[i].gtmRole == PRIMARY_GTM)) {
                actual_relation_count++;
                BuildDynamicGtmSazConfig(&instance_group, dynamicModified, i);
            }
#endif
            for (j = 0; j < (int)g_node[i].datanodeCount; j++) {
                if (g_node[i].datanode[j].datanodeRole != PRIMARY_DN) {
                    continue;
                }
                actual_relation_count++;
                dnInstanceCnt++;
                BuildDynamicDnSazConfig(&instance_group, dynamicModified, i, j);
            }
        }
    }

    /* update the dynamic header relation count and node num. */
    write_runlog(LOG,
        "build dynamic config file: dynamic header relation count is:%u, actual relation count is:%u, "
        "dynamic header node num is:%u, actual node num is:%u\n",
        g_dynamic_header->relationCount,
        actual_relation_count,
        g_dynamic_header->nodeCount,
        g_node_num);
    g_dynamic_header->relationCount = actual_relation_count;
    g_dynamic_header->nodeCount = g_node_num;
    g_datanode_instance_count = dnInstanceCnt;
    return 0;
}

static int get_dynamic_configure_version()
{
    int fd;
    ssize_t returnCode;
    dynamicConfigHeader headerinfo;

    fd = open(cm_dynamic_configure_path, O_RDONLY | O_CLOEXEC, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        write_runlog(LOG, "failed to open dynamic configure file.\n");
        if (errno == ENOENT) {
            write_runlog(LOG, "there is no dynamic config file.\n");
            return -1;
        } else if ((errno == EMFILE) || (errno == ENFILE)) {
            write_runlog(LOG, "there are many dynamic config file.\n");
            return -1;
        } else {
            write_runlog(ERROR, "OPEN dynamic config file error.\n");
            return -1;
        }
    } else {
        returnCode = read(fd, &headerinfo, sizeof(dynamicConfigHeader));
        if (returnCode != (ssize_t)sizeof(dynamicConfigHeader)) {
            write_runlog(LOG, "failed to read dynamic configure header failed!\n");
            (void)close(fd);
            return -1;
        }
    }
    (void)close(fd);
    return (int)headerinfo.version;
}

static int init_dynamic_configure_global_ptr()
{
    size_t header_size;
    size_t header_aglinment_size;
    size_t cms_state_timeline_size;
    size_t instance_role_aglinment_size;
    size_t instance_report_aglinment_size;
    size_t cn_dn_disconnect_size;
    size_t total_size;
    errno_t rc;

    total_size = 0;
    header_size = sizeof(dynamicConfigHeader);
    header_aglinment_size =
        (header_size / AGLINMENT_SIZE + ((header_size % AGLINMENT_SIZE == 0) ? 0 : 1)) * AGLINMENT_SIZE;
    total_size = total_size + header_aglinment_size;

    cms_state_timeline_size = sizeof(dynamic_cms_timeline);
    total_size = total_size + cms_state_timeline_size;

    instance_role_aglinment_size = sizeof(cm_instance_role_group) * MAX_INSTANCE_NUM;
    total_size = total_size + instance_role_aglinment_size;

    instance_report_aglinment_size = sizeof(cm_instance_group_report_status) * MAX_INSTANCE_NUM;
    total_size = total_size + instance_report_aglinment_size;

    char* dynamci_ptr = (char*)malloc(total_size);
    if (dynamci_ptr == NULL) {
        write_runlog(ERROR, "malloc memory failed! size = %lu\n", total_size);
        return -1;
    }
    g_dynamic_header = (dynamicConfigHeader*)dynamci_ptr;
    rc = memset_s(g_dynamic_header, header_aglinment_size, 0, header_aglinment_size);
    securec_check_errno(rc, (void)rc);
    g_dynamic_header->version = CMS_CURRENT_VERSION;

    g_timeline = (dynamic_cms_timeline*)(dynamci_ptr + header_aglinment_size);
    rc = memset_s(g_timeline, cms_state_timeline_size, 0, cms_state_timeline_size);
    securec_check_errno(rc, (void)rc);

    g_instance_role_group_ptr =
        (cm_instance_role_group*)(dynamci_ptr + header_aglinment_size + cms_state_timeline_size);
    rc = memset_s(g_instance_role_group_ptr, instance_role_aglinment_size, 0, instance_role_aglinment_size);
    securec_check_errno(rc, (void)rc);
    g_instance_group_report_status_ptr =
        (cm_instance_group_report_status*)(dynamci_ptr + header_aglinment_size + cms_state_timeline_size +
                                           instance_role_aglinment_size);
    for (uint32 i = 0; i < MAX_INSTANCE_NUM; i++) {
        (void)pthread_rwlock_init(&(g_instance_group_report_status_ptr[i].lk_lock), NULL);
        rc = memset_s(&(g_instance_group_report_status_ptr[i].instance_status),
            sizeof(cm_instance_report_status),
            0,
            sizeof(cm_instance_report_status));
        securec_check_errno(rc, (void)rc);
    }
    (void)pthread_rwlock_init(&(g_global_barrier->barrier_lock), NULL);
    cn_dn_disconnect_size = sizeof(int) * MAX_INSTANCE_NUM;
    cn_dn_disconnect_times = (int*)malloc(cn_dn_disconnect_size);
    if (cn_dn_disconnect_times == NULL) {
        write_runlog(ERROR, "malloc memory failed! size = %lu\n", cn_dn_disconnect_size);
        return -1;
    }
    rc = memset_s(cn_dn_disconnect_times, cn_dn_disconnect_size, 0, cn_dn_disconnect_size);
    securec_check_errno(rc, (void)rc);

    g_lastCnDnDisconnectTimes = (int*)malloc(cn_dn_disconnect_size);
    if (g_lastCnDnDisconnectTimes == NULL) {
        write_runlog(ERROR, "malloc memory failed! size = %lu\n", cn_dn_disconnect_size);
        return -1;
    }
    rc = memset_s(g_lastCnDnDisconnectTimes, cn_dn_disconnect_size, 0, cn_dn_disconnect_size);
    securec_check_errno(rc, (void)rc);

    g_dynamic_header->term = 0;
    return 0;
}

static int init_new_instance_role_group_ptr(const cm_instance_role_group_0* instance_role_group_ptr_0)
{
    if (instance_role_group_ptr_0 == NULL || g_instance_role_group_ptr == NULL) {
        return -1;
    }

    int count = (int)g_dynamic_header->relationCount;
    for (int i = 0; i < count; i++) {
        g_instance_role_group_ptr[i].count = instance_role_group_ptr_0[i].count;
        for (int j = 0; j < instance_role_group_ptr_0[i].count; j++) {
            g_instance_role_group_ptr[i].instanceMember[j].node = instance_role_group_ptr_0[i].instanceMember[j].node;
            g_instance_role_group_ptr[i].instanceMember[j].instanceId =
                instance_role_group_ptr_0[i].instanceMember[j].instanceId;
            g_instance_role_group_ptr[i].instanceMember[j].instanceType =
                instance_role_group_ptr_0[i].instanceMember[j].instanceType;
            g_instance_role_group_ptr[i].instanceMember[j].role = instance_role_group_ptr_0[i].instanceMember[j].role;
            g_instance_role_group_ptr[i].instanceMember[j].dataReplicationMode =
                instance_role_group_ptr_0[i].instanceMember[j].dataReplicationMode;
            g_instance_role_group_ptr[i].instanceMember[j].instanceRoleInit =
                instance_role_group_ptr_0[i].instanceMember[j].instanceRoleInit;
        }
    }
    return 0;
}

/*
 * Init notify msg for each coordinator instance.
 * In the worst scenario, all the datanodes got primaryed, so we only need to
 * allocate appropriate memory size for recording datanode instanceId.
 */
#ifdef ENABLE_MULTIPLE_NODES
int cm_notify_msg_init(void)
{
    WITHOUT_CN_CLUSTER_WITH_VALUE("init cn notify msg");

    cm_notify_msg_status* notify_msg = NULL;
    write_runlog(LOG, "g_dynamic_header->relationCount: %u.\n", g_dynamic_header->relationCount);

    int ret = CmNotifyCnMsgInit(&notify_msg);
    if (ret != 0) {
        return ret;
    }
    if (notify_msg == NULL) {
        write_runlog(ERROR, "cm_notify_msg_init:no coordinator configed in cluster.\n");
        ret = CM_EXIT;
        return ret;
    }

    /*
     * Init the last datanode index array during to datanode instance in group index.
     * Then, mirror this array to others 'causing for every coordinator it's potential
     * marked datanodes are all the same.
     */
    uint32 i;
    uint32 j = 0;
    cm_notify_msg_status *last_notify_msg = notify_msg;
    for (i = 0; i < g_dynamic_header->relationCount; i++) {
        if (g_instance_role_group_ptr[i].instanceMember[0].instanceType == INSTANCE_TYPE_DATANODE) {
            last_notify_msg->datanode_index[j++] = i;
        }
    }
    Assert(j == g_datanode_instance_count);

    for (i = 0; i < g_dynamic_header->relationCount; i++) {
        if (g_instance_role_group_ptr[i].instanceMember[0].instanceType == INSTANCE_TYPE_COORDINATE) {
            notify_msg = &g_instance_group_report_status_ptr[i].instance_status.coordinatemember.notify_msg;
            for (j = 0; j < g_datanode_instance_count; j++) {
                notify_msg->datanode_index[j] = last_notify_msg->datanode_index[j];
            }
            notify_msg->gtmIdBroadCast = last_notify_msg->gtmIdBroadCast;
        }
    }
    return ret;
}
#endif

static int static_dynamic_config_file_check(void)
{
    int fd = 0;
    size_t header_aglinment_size = 0;
    size_t cms_state_timeline_size = 0;
    size_t instance_role_aglinment_size = 0;
    uint32 i;
    bool dynamic_modified = false;
    errno_t rc;
    ssize_t returnCode;
    int dynamic_version;
    cm_instance_role_group_0* instance_role_group_ptr_0 = NULL;
    static bool cm_static_dynamic_need_check = true;
    if (!cm_static_dynamic_need_check) {
        return 0;
    }

    /* get version */
    dynamic_version = get_dynamic_configure_version();
    rc = init_dynamic_configure_global_ptr();
    if (rc < 0) {
        write_runlog(LOG, "failed to init dynamic configure info.\n");
        goto read_failed;
    }

    /*
     * Initialize the basic information of the central node,
     * including: the name of the central node, instance id,
     * and read-write lock
     */
    rc = memset_s(&g_centralNode, sizeof(cm_instance_central_node), 0, sizeof(cm_instance_central_node));
    securec_check_errno(rc, (void)rc);

    (void)pthread_mutex_init(&g_centralNode.mt_lock, NULL);

    g_fenced_UDF_report_status_ptr =
        (cm_fenced_UDF_report_status*)malloc(sizeof(cm_fenced_UDF_report_status) * CM_NODE_MAXNUM);
    if (g_fenced_UDF_report_status_ptr == NULL) {
        write_runlog(ERROR, "malloc memory failed! size = %lu\n", sizeof(cm_fenced_UDF_report_status) * CM_NODE_MAXNUM);
        return -1;
    }
    rc = memset_s(g_fenced_UDF_report_status_ptr,
        sizeof(cm_fenced_UDF_report_status) * CM_NODE_MAXNUM,
        0,
        sizeof(cm_fenced_UDF_report_status) * CM_NODE_MAXNUM);
    securec_check_errno(rc, (void)rc);
    for (i = 0; i < CM_NODE_MAXNUM; i++) {
        (void)pthread_rwlock_init(&(g_fenced_UDF_report_status_ptr[i].lk_lock), NULL);
    }

    header_aglinment_size =
        (sizeof(dynamicConfigHeader) / AGLINMENT_SIZE + ((sizeof(dynamicConfigHeader) % AGLINMENT_SIZE == 0) ? 0 : 1)) *
        AGLINMENT_SIZE;
    fd = open(cm_dynamic_configure_path, O_RDWR | O_CLOEXEC, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        if (errno == ENOENT) {
            write_runlog(LOG, "there is no dynamic config file.\n");
            g_dynamic_header->nodeCount = g_node_num;
            g_dynamic_header->relationCount = 0;
            g_dynamic_header->version = CMS_CURRENT_VERSION;
            g_datanode_instance_count = 0;
            fd = open(cm_dynamic_configure_path, O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
            if (fd < 0) {
                write_runlog(LOG, "create the file failed! file is %s\n", cm_dynamic_configure_path);
                goto read_failed;
            }
        } else if ((errno == EMFILE) || (errno == ENFILE)) {
            write_runlog(LOG, "there are many dynamic config file.\n");
            goto read_failed;
        } else {
            write_runlog(ERROR, "OPEN dynamic config file error.\n");
            goto read_failed;
        }
    } else {
        returnCode = read(fd, g_dynamic_header, header_aglinment_size);
        if (returnCode != (ssize_t)header_aglinment_size) {
            write_runlog(ERROR, "read header failed!\n");
            goto read_failed;
        }
        returnCode = lseek(fd, (long)header_aglinment_size, SEEK_SET);
        if (returnCode < 0) {
            write_runlog(ERROR, "seek header failed!\n");
            goto read_failed;
        }
        /* set version number */
        g_dynamic_header->version = CMS_CURRENT_VERSION;

        if (dynamic_version == 0) {
            write_runlog(LOG,
                "dynamic configuration file history version is %d,current version is %d, need to update.\n",
                dynamic_version,
                CMS_CURRENT_VERSION);
            dynamic_modified = true;
            instance_role_aglinment_size = sizeof(cm_instance_role_group_0) * g_cluster_total_instance_group_num;
            instance_role_group_ptr_0 = (cm_instance_role_group_0*)malloc(instance_role_aglinment_size);
            if (instance_role_group_ptr_0 == NULL) {
                write_runlog(ERROR, "malloc memory failed! size = %lu\n", instance_role_aglinment_size);
                goto read_failed;
            }
            returnCode = read(fd, instance_role_group_ptr_0,
                              (g_dynamic_header->relationCount) * sizeof(cm_instance_role_group_0));
            if (returnCode != (ssize_t)((g_dynamic_header->relationCount) * sizeof(cm_instance_role_group_0))) {
                write_runlog(ERROR, "read instance role failed %ld %ld %ld %ld!\n", returnCode,
                             (ssize_t)g_dynamic_header->relationCount, (ssize_t)sizeof(cm_instance_role_group_0),
                             (ssize_t)((g_dynamic_header->relationCount) * sizeof(cm_instance_role_group_0)));
                goto read_failed;
            }

            rc = init_new_instance_role_group_ptr(instance_role_group_ptr_0);
            if (rc < 0) {
                write_runlog(ERROR, "faild to updata dynamic instance role group.\n");
                goto read_failed;
            }

            free(instance_role_group_ptr_0);
            instance_role_group_ptr_0 = NULL;
            write_runlog(LOG, "update dynamic configure file successfully.\n");
        } else {
            cms_state_timeline_size = sizeof(dynamic_cms_timeline);
            returnCode = read(fd, g_timeline, cms_state_timeline_size);
            if (returnCode != (ssize_t)cms_state_timeline_size) {
                write_runlog(ERROR, "read timeline failed!\n");
                goto read_failed;
            }
            returnCode = lseek(fd, (ssize_t)(cms_state_timeline_size + header_aglinment_size), SEEK_SET);
            if (returnCode < 0) {
                write_runlog(ERROR, "seek timeline failed!\n");
                goto read_failed;
            }
            returnCode = read(fd, g_instance_role_group_ptr,
                              (g_dynamic_header->relationCount) * sizeof(cm_instance_role_group));
            write_runlog(ERROR, "read instance role failed %ld %ld %ld %ld!\n", returnCode,
                         (ssize_t)g_dynamic_header->relationCount, (ssize_t)sizeof(cm_instance_role_group_0),
                         (ssize_t)((g_dynamic_header->relationCount) * sizeof(cm_instance_role_group)));
            if (returnCode != (ssize_t)((g_dynamic_header->relationCount) * sizeof(cm_instance_role_group))) {
                write_runlog(ERROR, "read instance role failed %ld %ld %ld %ld!\n", returnCode,
                             (ssize_t)g_dynamic_header->relationCount, (ssize_t)sizeof(cm_instance_role_group_0),
                             (ssize_t)((g_dynamic_header->relationCount) * sizeof(cm_instance_role_group_0)));
                goto read_failed;
            }
        }
    }

    (void)BuildDynamicConfigFile(&dynamic_modified);
    g_dynamic_header->term = 0;

    if (dynamic_modified) {
        init_cluster_state_mode();

        cms_state_timeline_size = sizeof(dynamic_cms_timeline);
        rc = ftruncate(fd, 0);
        if (rc != 0) {
            char errBuffer[ERROR_LIMIT_LEN];
            write_runlog(ERROR,
                "ftruncate dynamic config file failed, errno=%d, errmsg=%s\n",
                errno,
                strerror_r(errno, errBuffer, ERROR_LIMIT_LEN));
            goto read_failed;
        }
        returnCode = lseek(fd, 0, SEEK_SET);
        if (returnCode < 0) {
            write_runlog(ERROR, "seek to the begin of file failed!\n");
            goto read_failed;
        }
        returnCode = write(fd,
            g_dynamic_header,
            header_aglinment_size + cms_state_timeline_size +
                (g_dynamic_header->relationCount) * sizeof(cm_instance_role_group));
        if (returnCode != (ssize_t)(header_aglinment_size + cms_state_timeline_size +
                                    (g_dynamic_header->relationCount) * sizeof(cm_instance_role_group))) {
            write_runlog(ERROR, "write instance configure faile!\n");
            goto read_failed;
        }

        rc = fsync(fd);
        if (rc != 0) {
            char errBuffer[ERROR_LIMIT_LEN];
            write_runlog(ERROR,
                "write_dynamic_config_file fsync file failed, errno=%d, errmsg=%s\n",
                errno,
                strerror_r(errno, errBuffer, ERROR_LIMIT_LEN));
            goto read_failed;
        }
    }

    /*
     * After build the dynamic config file, we now know the count of all the instance
     * type, so it's possible to init all the coordinator notify message report status.
     */
#ifdef ENABLE_MULTIPLE_NODES
    rc = cm_notify_msg_init();
    if (rc != 0) {
        goto read_failed;
    }
#endif
    cm_static_dynamic_need_check = false;
    (void)close(fd);
    return 0;

read_failed:
    free(g_dynamic_header);
    g_dynamic_header = NULL;
    g_instance_role_group_ptr = NULL;
    g_instance_group_report_status_ptr = NULL;
    g_datanode_instance_count = 0;
    if (fd >= 0) {
        (void)close(fd);
    }
    write_runlog(ERROR, "read dyamicConfig failed!");

    if (instance_role_group_ptr_0 != NULL) {
        free(instance_role_group_ptr_0);
        instance_role_group_ptr_0 = NULL;
    }
    return -1;
}

static void abort_unauthen_connection(int epollfd, bool all)
{
    static long last_process_time = 0;
    const long process_interval = 5;
    unauth_connection* pre = NULL;
    unauth_connection* cur = g_unauth_conn_list;
    long cur_time = time(NULL);
    /* do check with 5 seconds interval */
    if (!all && last_process_time != 0 && cur_time < last_process_time + process_interval) {
        return;
    }

    while (cur != NULL) {
        /* reject it while authentication have not been finished in 60s. */
        if (all || cur_time >= cur->conn->last_active + AUTHENTICATION_TIMEOUT) {
            /* remove this item from list */
            if (pre != NULL) {
                pre->next = cur->next;
            } else {
                g_unauth_conn_list = cur->next;
            }
            g_unauthConnCount--;
            /* abort this connection */
            EventDel(epollfd, cur->conn);
            write_runlog(LOG, "connection TIMEOUT abort\n");
            ConnCloseAndFree(cur->conn);
            free(cur);

            /* process next one connection. */
            cur = (pre != NULL) ? pre->next : g_unauth_conn_list;
        } else {
            pre = cur;
            cur = cur->next;
        }
    }

    /* refresh lastest process time */
    last_process_time = cur_time;
}

static void cm_server_stop_command_check(int epollfd)
{
    if (got_stop == 1 && ha_connection_closed == 1) {
        abort_unauthen_connection(epollfd, true);
        delete_lock_file(CM_PID_FILE);
        write_runlog(LOG, "cm server receive the stop command and stop !\n");
        FreeNotifyMsg();
        exit(0);
    }
    return;
}

static void cm_server_listen_socket_init(void)
{
    int i;

    for (i = 0; i < MAXLISTEN; i++) {
        ServerListenSocket[i] = -1;
    }
    return;
}

static int cm_server_build_listen_socket_check(void)
{
    int status;
    int success;
    static bool cm_need_build_listen = true;

    if (!cm_need_build_listen || (g_node == NULL)) {
        return -1;
    }

    if (g_currentNode->cmServerLevel != CM_SERVER_LEVEL_1) {
        write_runlog(LOG, "the node is not cm server  ,should not start cm server!\n");
        return -1;
    }

    success = 0;
    for (uint32 ii = 0; ii < g_currentNode->cmServerListenCount; ii++) {
        status = StreamServerPort(
            AF_UNSPEC, g_currentNode->cmServer[ii], (unsigned short)g_currentNode->port, ServerListenSocket, MAXLISTEN);
        if (status == STATUS_OK) {
            success++;
        } else {
            write_runlog(LOG, "build cm server listen failed! ip is %s\n", g_currentNode->cmServer[ii]);
        }
    }

    if (!success && (ServerListenSocket[0] == -1)) {
        write_runlog(ERROR, "no socket created for server listening!\n");
        return -1;
    }

    cm_need_build_listen = false;
    return STATUS_OK;
}

static int cm_server_init_ha_status(void)
{
    int ret;
    g_HA_status->status = CM_STATUS_STARTING;
    g_HA_status->local_role = CM_SERVER_STANDBY;
    ret = pthread_rwlock_init(&(g_HA_status->ha_lock), NULL);
    if (ret != 0) {
        write_runlog(LOG, "CMThreadsData init lock failed !\n");
        return -1;
    }
    return 0;
}

/*
 * Change working directory to t_thrd.proc_cxt.DataDir.  Most of the postmaster and backend
 * code assumes that we are in t_thrd.proc_cxt.DataDir so it can use relative paths to access
 * stuff in and under the data directory.  For convenience during path
 * setup, however, we don't force the chdir to occur during SetDataDir.
 */
static void ChangeToDataDir(void)
{
    if (chdir(cm_server_dataDir) < 0) {
        write_runlog(FATAL, "could not change directory to \"%s\"!\n", cm_server_dataDir);
    }
}

/**
 * @brief Check the process list for recording.
 *
 * @note This function is used only to print the process list information. Therefore, the error
 *   information will not be recorded.
 *
 * @param  keywords         My Param doc
 */
static void check_process_list(const char *keywords)
{
    char    command[MAXPGPATH] = { 0 };
    char    buffer[MAXPGPATH] = { 0 };
    int     ret;
    uint32  error_count = 0;

    /* The keyword can be NULL. */
    if (!keywords) {
        keywords = "";
    }

    ret = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1, "ps ux | grep -v grep | grep \"%s\"", keywords);
    securec_check_intval(ret, (void)ret);

    FILE *fp = popen(command, "re");
    if (fp == NULL) {
        return;
    }

    write_runlog(LOG, "start check process.\n");
    while (!feof(fp)) {
        if (fgets(buffer, MAXPGPATH - 1, fp)) {
            write_runlog(LOG, "%s", buffer);
        } else {
            error_count++;
        }

        if (error_count >= 3) {
            break;
        }
    }
    write_runlog(LOG, "end check process.\n");

    (void)pclose(fp);
}


int check_process_status(const char *processName)
{
    struct dirent *de;
    char pid_path[MAX_PATH_LEN];
    FILE *fp = NULL;
    char getBuff[MAX_PATH_LEN];
    char paraName[MAX_PATH_LEN];
    char paraValue[MAX_PATH_LEN];
    int tgid = 0;
    int spid = 0;
    int pid = 0;
    int ppid = 0;
    char state = '0';
    uid_t uid = 0;
    uid_t uid1 = 0;
    uid_t uid2 = 0;
    uid_t uid3 = 0;
    bool nameFound = false;
    bool nameGet = false;
    bool tgidGet = false;
    bool spidGet = false;
    bool ppidGet = false;
    bool stateGet = false;
    bool haveFound = false;
    bool uidGet = false;
    errno_t rc;
    int rcs;
    DIR *dir = opendir("/proc");
    if (dir == NULL) {
        write_runlog(ERROR, "opendir(/proc) failed, errno=%d! \n ", errno);
        return -1;
    }

    while ((de = readdir(dir)) != NULL) {
        /*
         * judging whether the directory name is composed by digitals,if so,we will
         * check whether there are files under the directory ,these files includes
         * all detailed information about the process
         */
        if (CM_is_str_all_digit(de->d_name) != 0) {
            continue;
        }

        rc = memset_s(pid_path, MAX_PATH_LEN, 0, MAX_PATH_LEN);
        securec_check_errno(rc, (void)rc);
        pid = (int)strtol(de->d_name, NULL, 10); {
            rcs = snprintf_s(pid_path, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/proc/%d/status", pid);
            securec_check_intval(rcs, (void)rcs);
        }

        /* maybe fail because of privilege */
        fp = fopen(pid_path, "r");
        if (fp == NULL) {
            continue;
        }

        nameGet = false;
        tgidGet = false;
        spidGet = false;
        ppidGet = false;
        stateGet = false;
        uidGet = false;
        rc = memset_s(paraValue, MAX_PATH_LEN, 0, MAX_PATH_LEN);
        securec_check_errno(rc, (void)rc);
        tgid = 0;
        spid = 0;
        ppid = 0;
        state = '0';
        uid = 0;
        rc = memset_s(getBuff, MAX_PATH_LEN, 0, MAX_PATH_LEN);
        securec_check_errno(rc, (void)rc);
        nameFound = false;

        while (fgets(getBuff, MAX_PATH_LEN - 1, fp) != NULL) {
            rc = memset_s(paraName, MAX_PATH_LEN, 0, MAX_PATH_LEN);
            securec_check_errno(rc, (void)rc);

            if (!nameGet && (strstr(getBuff, "Name:") != NULL)) {
                nameGet = true;
                rcs = sscanf_s(getBuff, "%s %s", paraName, MAX_PATH_LEN, paraValue, MAX_PATH_LEN);
                check_sscanf_s_result(rcs, 2);
                securec_check_intval(rcs, (void)rcs);

                if (strcmp(processName, paraValue) == 0) {
                    nameFound = true;
                } else {
                    break;
                }
            }

            if (!tgidGet && (strstr(getBuff, "Tgid:") != NULL)) {
                tgidGet = true;
                rcs = sscanf_s(getBuff, "%s    %d", paraName, MAX_PATH_LEN, &tgid);
                check_sscanf_s_result(rcs, 2);
                securec_check_intval(rcs, (void)rcs);
            }

            if (!spidGet && (strstr(getBuff, "Pid:") != NULL)) {
                spidGet = true;
                rcs = sscanf_s(getBuff, "%s    %d", paraName, MAX_PATH_LEN, &spid);
                check_sscanf_s_result(rcs, 2);
                securec_check_intval(rcs, (void)rcs);
            }

            if (!ppidGet && (strstr(getBuff, "PPid:") != NULL)) {
                ppidGet = true;
                rcs = sscanf_s(getBuff, "%s    %d", paraName, MAX_PATH_LEN, &ppid);
                check_sscanf_s_result(rcs, 2);
                securec_check_intval(rcs, (void)rcs);
            }

            if (!stateGet && (strstr(getBuff, "State:") != NULL)) {
                stateGet = true;
                rcs = sscanf_s(getBuff, "%s    %c", paraName, MAX_PATH_LEN, &state, 1);
                check_sscanf_s_result(rcs, 2);
                securec_check_intval(rcs, (void)rcs);
            }

            if (!uidGet && (strstr(getBuff, "Uid:") != NULL)) {
                uidGet = true;
                rcs = sscanf_s(getBuff,
                    "%s    %u    %u    %u    %u",
                    paraName, MAX_PATH_LEN, &uid, &uid1, &uid2, &uid3);
                check_sscanf_s_result(rcs, 5);
                securec_check_intval(rcs, (void)rcs);
            }

            if (nameGet && tgidGet && spidGet && ppidGet && stateGet && uidGet) {
                break;
            }
        }

        (void)fclose(fp);

        if (nameFound) {
            if (getpid() == spid) {
                continue;
            }

            if (tgid != spid) {
                continue;
            }

            if (getuid() != uid) {
                continue;
            }

            if (!haveFound) {
                haveFound = true;
            } else {
                continue;
            }
        } else {
            continue;
        }
    }

    (void)closedir(dir);

    if (haveFound) {
        return PROCESS_RUNNING;
    } else {
        return PROCESS_NOT_EXIST;
    }
}

/**
 * @brief Create a Data Dir Lock File object
 * When this is called, we must have already switched the working
 * directory to t_thrd.proc_cxt.DataDir, so we can just use a relative path.  This
 * helps ensure that we are locking the directory we should be.
 *
 */
static void CreateDataDirLockFile()
{
    int ret = create_lock_file(CM_PID_FILE, cm_server_dataDir);
    if (ret == -1) {
        write_runlog(FATAL, "failed to create the cm server pid file.\n");
        exit(1);
    } else if (ret == EEXIST) {
        if (check_process_status(CM_SERVER_BIN_NAME) == PROCESS_RUNNING) {
            write_runlog(FATAL, "The CM Server process is running, failed to start another CM Server process.\n");
        } else {
            delete_lock_file(CM_PID_FILE);
            write_runlog(FATAL, "The CM Server process is not running, delete the file and restart the CM Server"
                " to try again.\n");
        }

        check_process_list(CM_SERVER_BIN_NAME);
        exit(1);
    }
}

/**
 * @brief BaseInit
 *
 */
static void BaseInit()
{
    char cm_server_data_path[MAX_PATH_LEN];
    int rc;

    rc = snprintf_s(cm_server_data_path, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/cm_server", g_currentNode->cmDataPath);
    securec_check_intval(rc, (void)rc);

    cm_server_dataDir = strdup(cm_server_data_path);

    ChangeToDataDir();

    CreateDataDirLockFile();
}

static int32 CmSetConnState(CM_Connection *con)
{
    CMPerformAuthentication(con);
    CM_resetStringInfo(con->inBuffer);

    if (con->fd >= 0) {
        MsgRecvInfo recvMsg;
        errno_t rc = memset_s(&recvMsg, sizeof(MsgRecvInfo), 0, sizeof(MsgRecvInfo));
        securec_check_errno(rc, (void)rc);
        recvMsg.connID.agentNodeId = con->port->node_id;
        recvMsg.connID.connSeq = con->connSeq;
        recvMsg.connID.remoteType = con->port->remote_type;
        AsyncProcMsg(&recvMsg, PM_ASSIGN_CONN, (const char *)&con, sizeof(CM_Connection *));
    } else {
        return -1;
    }
    return 0;
}

static int cm_server_process_startup_packet(int epollfd, CM_Connection* con, CM_StringInfo msg)
{
    char error_msg[CM_SERVER_PACKET_ERROR_MSG] = {0};
    int nRet = 0;
    bool isDdbHealth = false;

    /* check msg bytes */
    const CM_StartupPacket* sp = (const CM_StartupPacket *)CmGetmsgbytes(msg, sizeof(CM_StartupPacket));
    if (sp == NULL) {
        write_runlog(LOG, "start message is invalid. msg->qtype: %d \n", msg->qtype);
        EventDel(epollfd, con);
        return -1;
    }
    
    if (sp->node_id <= (int)g_node_num && con->port != NULL && sp->sp_remotetype == CM_AGENT) {
        write_runlog(LOG,
            "process startup packet, remote_type %d, nodeid %d, node name %s, postmaster is %s.\n",
            sp->sp_remotetype, sp->node_id, sp->sp_node_name, sp->sp_ispostmaster ? "true" : "false");
    } else {
        write_runlog(DEBUG1,
            "process startup packet, remote_type %d, nodeid %d, node name %s.\n",
            sp->sp_remotetype, sp->node_id, sp->sp_node_name);
    }

    if (con->port != NULL) {
        con->port->user_name = strdup(sp->sp_user);
        con->port->node_name = strdup(sp->sp_node_name);
        con->port->remote_host = strdup(sp->sp_host);
        con->port->remote_type = sp->sp_remotetype;
        con->port->is_postmaster = sp->sp_ispostmaster;
        con->port->node_id = (uint32)sp->node_id;
        write_runlog(DEBUG5, "socket is [%d], make a new connect(%d).\n", con->port->sock, con->port->remote_type);
        uint32 tmpNodeId = con->port->node_id;

        /* check ip */
        if (!is_valid_host(con, con->port->remote_type)) {
            EventDel(epollfd, con);

            nRet = snprintf_s(error_msg, CM_SERVER_PACKET_ERROR_MSG, sizeof(error_msg) - 1, "%s", "invalid host");
            securec_check_intval(nRet, (void)nRet);
            if (CmsSendAndFlushMsg(con, 'E', error_msg, CM_SERVER_PACKET_ERROR_MSG) != 0) {
                RemoveConnAfterSendMsgFailed(con);
                write_runlog(ERROR, "[%s][line:%d] CmsSendAndFlushMsg fail.\n", __FUNCTION__, __LINE__);
            }
            return -1;
        }

        if (!con->port->is_postmaster && g_HA_status->local_role != CM_SERVER_PRIMARY) {
            if (con->port->remote_type == CM_AGENT) {
                ProcPreNodeConn(tmpNodeId);
            }
            EventDel(epollfd, con);
            write_runlog(DEBUG1,
                "local cmserver role(%d) is not primary(%d)\n",
                g_HA_status->local_role, CM_SERVER_PRIMARY);

            nRet = snprintf_s(error_msg, CM_SERVER_PACKET_ERROR_MSG, sizeof(error_msg) - 1,
                "%s", "local cmserver is not the primary");
            securec_check_intval(nRet, (void)nRet);
            if (CmsSendAndFlushMsg(con, 'E', error_msg, CM_SERVER_PACKET_ERROR_MSG) != 0) {
                RemoveConnAfterSendMsgFailed(con);
                write_runlog(ERROR, "[%s][line:%d] CmsSendAndFlushMsg fail.\n", __FUNCTION__, __LINE__);
            }
            return -1;
        }

        /* check msg type */
        switch (con->port->remote_type) {
            case CM_AGENT:
                write_runlog(LOG, "new connection type is CM_AGENT\n");

                if (tmpNodeId >= CM_MAX_CONNECTIONS) {
                    write_runlog(LOG, "new connection is discard due its node id (%u) is invalid.", tmpNodeId);
                    EventDel(epollfd, con);
                    return -1;
                }

                EventDel(epollfd, con);
                Assert(con != NULL);

                uint32 connCount, preConnCount;
                getConnInfo(connCount, preConnCount);
                /* The conditions of cmserver will promote to primary:
                * 1. When it is not cluster of etcd, the number of cm_agent pre-connections must be more than half.
                * 2. When it is cluster of etcd, the number of healthy etcd instance must be more than half
                *     and the cm_agent pre-connections that are not local cm_server node must be more than 1.
                */
                isDdbHealth = IsDdbHealth(DDB_PRE_CONN);
                if (((preConnCount <= g_node_num / 2 && !g_multi_az_cluster &&
                    (g_etcd_num == 0 || !isDdbHealth)) || (preConnCount == 0 && g_multi_az_cluster) ||
                    (preConnCount == 0 && !g_multi_az_cluster && isDdbHealth)) &&
                    cm_arbitration_mode == MAJORITY_ARBITRATION && g_cmsPromoteMode == PMODE_AUTO &&
                    g_node_num >= 3 && connCount == 0 &&
                    !con->port->is_postmaster) {
                    ProcPreNodeConn(tmpNodeId);
                    write_runlog(LOG, "the pre conn count is %u, less than half.\n", preConnCount);
                    nRet = snprintf_s(error_msg,
                        CM_SERVER_PACKET_ERROR_MSG,
                        sizeof(error_msg) - 1,
                        "%s",
                        "the pre conn number is less than half.");
                    securec_check_intval(nRet, (void)nRet);
                    if (CmsSendAndFlushMsg(con, 'E', error_msg, CM_SERVER_PACKET_ERROR_MSG) != 0) {
                        RemoveConnAfterSendMsgFailed(con);
                        write_runlog(ERROR, "[%s][line:%d] CmsSendAndFlushMsg fail.\n", __FUNCTION__, __LINE__);
                    }
                    return -1;
                }

                return CmSetConnState(con);

            case CM_CTL:
                write_runlog(DEBUG1, "new connection type is CM_CTL\n");
                /* to do: save CM_CTL  connection info: con */
                EventDel(epollfd, con);
                Assert(con != NULL);

                if ((con->port->user_name != NULL) && strncmp(con->port->user_name, pw->pw_name, SP_USER - 1)) {
                    write_runlog(WARNING, "invalid connection\n");
                    if (CmsSendAndFlushMsg(con, 'E', "invalid connection", sizeof("invalid connection")) != 0) {
                        RemoveConnAfterSendMsgFailed(con);
                        write_runlog(ERROR, "[%s][line:%d] CmsSendAndFlushMsg fail.\n", __FUNCTION__, __LINE__);
                    }
                    return -1;
                }

                return CmSetConnState(con);

            default:
                EventDel(epollfd, con);
                write_runlog(LOG, "invalid remote type %d\n", con->port->remote_type);
                nRet = snprintf_s(error_msg, CM_SERVER_PACKET_ERROR_MSG, sizeof(error_msg) - 1,
                    "%s", "invalid remote type");
                securec_check_intval(nRet, (void)nRet);
                if (CmsSendAndFlushMsg(con, 'E', error_msg, CM_SERVER_PACKET_ERROR_MSG) != 0) {
                    RemoveConnAfterSendMsgFailed(con);
                    write_runlog(ERROR, "[%s][line:%d] CmsSendAndFlushMsg fail.\n", __FUNCTION__, __LINE__);
                }
                return -1;
        }
    }
    return 0;
}

static void remove_unauthen_connection(const CM_Connection* conn)
{
    unauth_connection* pre = NULL;
    unauth_connection* cur = g_unauth_conn_list;

    while (cur != NULL) {
        /* identify specified connection with its address */
        if (cur->conn == conn) {
            if (pre != NULL) {
                pre->next = cur->next;
            } else {
                g_unauth_conn_list = cur->next;
            }
            g_unauthConnCount--;
            free(cur);
            /* it is sole, stop it. */
            break;
        }
        pre = cur;
        cur = cur->next;
    }
}

static void CheckReadNoMessage(CM_Connection *con, int epollFd)
{
    write_runlog(DEBUG5, "StartupPacket read no message on fd %d\n", con->fd);

    bool isRecvTimeOut = false;
    if (con->msgFirstPartRecvTime != 0 && time(NULL) >= con->msgFirstPartRecvTime + AUTHENTICATION_TIMEOUT) {
        isRecvTimeOut = true;
    }
    if (time(NULL) >= con->last_active + AUTHENTICATION_TIMEOUT || isRecvTimeOut) {
        EventDel(epollFd, con);
        if (con->port != NULL) {
            write_runlog(LOG, "connection TIMEOUT, node=[%s: %u], socket=%d, isRecvTimeOut=%d.\n",
                con->port->node_name, con->port->node_id, con->port->sock, isRecvTimeOut);
        } else {
            write_runlog(LOG, "connection TIMEOUT.\n");
        }
        ConnCloseAndFree(con);
    }
}

void ProcessStartupPacket(int epollFd, void* arg)
{
    int qtype;
    CM_Connection* con = (CM_Connection*)arg;
    if (con == NULL) {
        return;
    }

    remove_unauthen_connection(con);
    set_socket_timeout(con->port, AUTHENTICATION_TIMEOUT);
    qtype = ReadCommand(con, "ProcessStartupPacket");
    write_runlog(DEBUG5, "Startup pack type is %d, msglen =%d len =%d ,msg:%s\n",
        qtype, con->inBuffer->msglen, con->inBuffer->len, con->inBuffer->data);
    switch (qtype) {
        case 'A':
#ifdef KRB5
            con->gss_check = false;
#endif // KRB5
            con->last_active = time(NULL);
            con->msgFirstPartRecvTime = 0;
            if (cm_server_process_startup_packet(epollFd, con, con->inBuffer) == 0) {
                /* new connection has been assigned to other thread */
                return;
            }

            write_runlog(DEBUG1, "process startup packet error, new connection refused,[fd=%d]\n", con->fd);
            if (con->port != NULL) {
                RemoveConnection(con);
            }
            break;
        case 'X':
        case EOF:
            EventDel(epollFd, con);
            write_runlog(LOG, "connection closed by client\n");
            ConnCloseAndFree(con);
            break;

        case TCP_SOCKET_ERROR_NO_MESSAGE:
        case 0:
            CheckReadNoMessage(con, epollFd);
            break;

        case TCP_SOCKET_ERROR_EPIPE:
            EventDel(epollFd, con);
            write_runlog(LOG, "connection was broken\n");
            ConnCloseAndFree(con);
            break;

        default:
            write_runlog(LOG, "StartupPacket read Unknown msg qtype %d, fd %d.\n", qtype, con->fd);
            EventDel(epollFd, con);
            ConnCloseAndFree(con);
            break;
    }

    Assert(con != NULL);
    if (con->fd == INVALIDFD) {
        FREE_AND_RESET(con);
    }
}

static CM_Connection* makeConnection(int fd, Port* port)
{
    CM_Connection* listenCon = (CM_Connection*)malloc(sizeof(CM_Connection));
    errno_t rc;

    if (listenCon == NULL) {
        write_runlog(ERROR, "malloc CM_Connection failed,out of memory.\n");
        return NULL;
    }

    rc = memset_s(listenCon, sizeof(CM_Connection), 0, sizeof(CM_Connection));
    securec_check_errno(rc, FREE_AND_RESET(listenCon));

    listenCon->fd = fd;
    listenCon->port = port;
    listenCon->inBuffer = CM_makeStringInfo();
    listenCon->connSeq = gConnSeq++;

    Assert(listenCon->inBuffer != NULL);

    return listenCon;
}

static bool add_unauthen_connection(CM_Connection* conn)
{
    if (g_unauthConnCount > MAX_UNAUTH_CONN) {
        return false;
    }
    unauth_connection* tmp = (unauth_connection*)malloc(sizeof(unauth_connection));

    if (tmp == NULL) {
        return false;
    }

    tmp->conn = conn;
    tmp->next = g_unauth_conn_list;
    g_unauth_conn_list = tmp;
    g_unauthConnCount++;

    return true;
}

static void AcceptConn(int epollFd, void* arg)
{
    CM_Connection* listenCon = (CM_Connection*)arg;
    if (listenCon == NULL) {
        write_runlog(ERROR, "AcceptConn arg is NULL.\n");
        return;
    }

    Port* port = ConnCreate(listenCon->fd);
    if (port != NULL) {
        CM_Connection* newCon = makeConnection(port->sock, port);
        if (newCon == NULL) {
            if (port->sock >= 0) {
                StreamClose(port->sock);
            }
            ConnFree(port);
            port = NULL;
            return;
        }

        newCon->callback = ProcessStartupPacket;
        newCon->arg = newCon;
        newCon->epHandle = epollFd;
        newCon->last_active = time(NULL);

        if (!add_unauthen_connection(newCon)) {
            write_runlog(ERROR, "Add new connection to unauth list failed.\n");
            ConnCloseAndFree(newCon);
            FREE_AND_RESET(newCon);
            return;
        }

        /* add new connection fd to main thread to precess startup packet */
        if (EventAdd(epollFd, (int)EPOLLIN, newCon)) {
            write_runlog(ERROR, "Add new connection socket failed[fd=%d], events[%03X].\n", port->sock, EPOLLIN);
            remove_unauthen_connection(newCon);
            ConnCloseAndFree(newCon);
            FREE_AND_RESET(newCon);
            return;
        }

        write_runlog(DEBUG1, "Accept new connection, socket [fd=%d], events[%03X].\n", port->sock, EPOLLIN);
    }
}

static int InitListenSocket(int epollFd)
{
    int i;
    int ret;

    for (i = 0; i < MAXLISTEN; i++) {
        int listenFd = ServerListenSocket[i];

        if (listenFd == -1) {
            break;
        }

        ret = SetSocketNoBlock(listenFd);
        if (ret != STATUS_OK) {
            write_runlog(ERROR, "SetSocketNoBlock failed.\n");
            return -1;
        }

        CM_Connection* listenCon = makeConnection(listenFd, NULL);
        if (listenCon == NULL) {
            write_runlog(
                ERROR, "makeConnection failed, listenCon is NULL,epollFd=%d, listenFd=%d.\n", epollFd, listenFd);
            return -1;
        }

        listenCon->callback = AcceptConn;
        listenCon->arg = listenCon;
        listenCon->epHandle = epollFd;

        addListenConn(i, listenCon);

        if (EventAdd(epollFd, EPOLLIN, listenCon)) {
            write_runlog(ERROR, "Add listen socket failed[fd=%d].\n", listenFd);
            return -1;
        }
        write_runlog(LOG, "Add listen socket [fd=%d] OK , events[%03X]\n", listenCon->fd, EPOLLIN);
    }
    return 0;
}

status_t cms_chk_ssl_cert_expire()
{
    if (g_ssl_acceptor_fd == NULL) {
        return CM_SUCCESS;
    }

    if (g_sslOption.expire_time < CM_MIN_SSL_EXPIRE_THRESHOLD ||
        g_sslOption.expire_time > CM_MAX_SSL_EXPIRE_THRESHOLD) {
        write_runlog(ERROR, "invalid ssl expire alert threshold %u, must between %u and %u\n",
            g_sslOption.expire_time, CM_MIN_SSL_EXPIRE_THRESHOLD, CM_MAX_SSL_EXPIRE_THRESHOLD);
        return CM_ERROR;
    }
    cm_ssl_ca_cert_expire(g_ssl_acceptor_fd, (int)g_sslOption.expire_time);
    return CM_SUCCESS;
}

static void CheckFileExists()
{
    if (!CmFileExist((const char *)g_sslOption.ssl_para.ca_file)) {
        write_runlog(DEBUG5, "cms_init_ssl key_file is not exist.\n");
        free(g_sslOption.ssl_para.ca_file);
        g_sslOption.ssl_para.ca_file = NULL;
    }
    if (!CmFileExist((const char *)g_sslOption.ssl_para.key_file)) {
        write_runlog(DEBUG5, "cms_init_ssl key_file is not exist.\n");
        free(g_sslOption.ssl_para.key_file);
        g_sslOption.ssl_para.key_file = NULL;
    }
    if (!CmFileExist((const char *)g_sslOption.ssl_para.cert_file)) {
        write_runlog(DEBUG5, "cms_init_ssl cert_file is not exist.\n");
        free(g_sslOption.ssl_para.cert_file);
        g_sslOption.ssl_para.cert_file = NULL;
    }
    return;
}

static status_t cms_init_ssl()
{
    char plain[CM_PASSWD_MAX_LEN + 1];

    g_ssl_acceptor_fd = NULL;
    write_runlog(LOG, "cms_init_ssl get config.\n");
    if (g_sslOption.enable_ssl == CM_FALSE) {
        write_runlog(WARNING, "[INST] srv_init_ssl: ssl is not enable.\n");
        return CM_SUCCESS;
    }

    if (g_sslOption.ssl_para.ca_file == NULL) {
        write_runlog(ERROR, "ca_file is null.\n");
        return CM_ERROR;
    }

    g_sslOption.verify_peer = strlen(g_sslOption.ssl_para.ca_file) == 0 ? CM_FALSE : g_sslOption.verify_peer;
    write_runlog(LOG, "cms_init_ssl verify_file_stat.\n");
    CheckFileExists();

    if (g_sslOption.ssl_para.ca_file == NULL || g_sslOption.ssl_para.key_file == NULL ||
        g_sslOption.ssl_para.cert_file == NULL) {
        write_runlog(ERROR, "[INST] Cert file or Key file is not exists.\n");
        return CM_ERROR;
    }

    /* require no public access to key file */
    CM_RETURN_IFERR(cm_ssl_verify_file_stat(g_sslOption.ssl_para.key_file));
    CM_RETURN_IFERR(cm_ssl_verify_file_stat(g_sslOption.ssl_para.cert_file));
    CM_RETURN_IFERR(cm_ssl_verify_file_stat(g_sslOption.ssl_para.ca_file));

    write_runlog(LOG, "cms_init_ssl  verify ssl key password.\n");
    // verify ssl key password
    if (cm_verify_ssl_key_pwd(plain, sizeof(plain) - 1, SERVER_CIPHER) != CM_SUCCESS) {
        write_runlog(ERROR, "[INST] srv verify ssl keypwd failed.\n");
        return CM_ERROR;
    }

    g_sslOption.ssl_para.key_password = plain;
    // create acceptor context
    write_runlog(LOG, "cms_init_ssl create acceptor contex.\n");
    g_ssl_acceptor_fd = cm_ssl_create_acceptor_fd(&g_sslOption.ssl_para);
    errno_t rc = memset_s(plain, sizeof(plain), 0, sizeof(plain));
    securec_check_errno(rc, (void)rc);
    if (g_ssl_acceptor_fd == NULL) {
        write_runlog(ERROR, "srv create ssl acceptor context failed.\n");
        return CM_ERROR;
    }
    CM_RETURN_IFERR(cms_chk_ssl_cert_expire());

    write_runlog(LOG, "[INST] srv_init_ssl: ssl init success.\n");
    return CM_SUCCESS;
}

void cms_deinit_ssl()
{
    if (g_ssl_acceptor_fd != NULL) {
        cm_ssl_free_context(g_ssl_acceptor_fd);
        g_ssl_acceptor_fd = NULL;
    }
}

static int CreateListenSocket(void)
{
    /* create epoll fd, MAX_EVENTS just a HINT */
    int epollfd = epoll_create(MAX_EVENTS);
    if (epollfd < 0) {
        write_runlog(ERROR, "create epoll failed %d.\n", epollfd);
        return (int)CM_ERROR;
    }

    if (InitListenSocket(epollfd)) {
        write_runlog(ERROR, "init listen socket failed.\n");
        return (int)CM_ERROR;
    }
    return epollfd;
}

static int server_loop(void)
{
    struct timespec startTime = {0, 0};
    struct timespec endTime = {0, 0};
    struct timespec lastTime = {0, 0};
    const unsigned int totalTime = 300;

    (void)clock_gettime(CLOCK_MONOTONIC, &startTime);
    (void)clock_gettime(CLOCK_MONOTONIC, &lastTime);

    int epollfd = CreateListenSocket();
    if (epollfd == CM_ERROR) {
        return 1;
    }

    /* event loop */
    struct epoll_event events[MAX_EVENTS];

    const int pauseLogInterval = 5;
    int pauseLogTimes = 0;
    for (;;) {
        if (got_stop == 1) {
            return 1;
        }

        // if cluster_manual_pause file exists
        if (access(g_cmManualPausePath, F_OK) == 0) {
            g_isPauseArbitration = true;
            // avoid log swiping
            if (pauseLogTimes == 0) {
                write_runlog(LOG, "The cluster has been paused.\n");
            }
            ++pauseLogTimes;
            pauseLogTimes = pauseLogTimes % pauseLogInterval;
        } else {
            g_isPauseArbitration = false;
            pauseLogTimes = 0;
        }

        (void)clock_gettime(CLOCK_MONOTONIC, &endTime);
        if (g_HA_status->local_role == CM_SERVER_PRIMARY) {
            if (g_isStart && (endTime.tv_sec - startTime.tv_sec) >= totalTime) {
                g_isStart = false;
            }
        }
        /* check ssl cert_expire per day */
        if (g_sslOption.enable_ssl && (endTime.tv_sec - lastTime.tv_sec) >= (time_t)g_sslCertExpireCheckInterval) {
            (void)cms_chk_ssl_cert_expire();
            (void)clock_gettime(CLOCK_MONOTONIC, &lastTime);
        }
        clean_system_alarm_log(system_alarm_log, sys_log_path);
        cm_server_stop_command_check(epollfd);

        /* wait for events to happen, 10s timeout */
        int fds = epoll_wait(epollfd, events, MAX_EVENTS, 10000);
        if (fds < 0) {
            if (errno != EINTR && errno != EWOULDBLOCK) {
                write_runlog(ERROR, "epoll_wait error : %d, main thread exit.\n", errno);
                break;
            }
        }

        for (int i = 0; i < fds; i++) {
            CM_Connection* con = (CM_Connection*)events[i].data.ptr;

            /* read event */
            if (events[i].events & EPOLLIN) {
                if (con != NULL) {
                    con->callback(epollfd, con->arg);
                }
            }
        }

        abort_unauthen_connection(epollfd, false);
        (void)usleep(20);
    }

    (void)close(epollfd);
    return 1;
}

static void DoHelp(void)
{
    (void)printf(_("%s is a utility to arbitrate an instance.\n\n"), g_progname);

    (void)printf(_("Usage:\n"));
    (void)printf(_("  %s\n"), g_progname);
    (void)printf(_("  %s 0\n"), g_progname);
    (void)printf(_("  %s 1\n"), g_progname);
    (void)printf(_("  %s 2\n"), g_progname);
    (void)printf(_("  %s 3\n"), g_progname);

    (void)printf(_("\nCommon options:\n"));
    (void)printf(_("  -?, -h, --help         show this help, then exit\n"));
    (void)printf(_("  -V, --version          output version information, then exit\n"));

    (void)printf(_("\nlocation of the log information options:\n"));
    (void)printf(_("  0                      LOG_DESTION_FILE\n"));
    (void)printf(_("  1                      LOG_DESTION_SYSLOG\n"));
    (void)printf(_("  2                      LOG_DESTION_FILE\n"));
    (void)printf(_("  3                      LOG_DESTION_DEV_NULL\n"));
}


/*
 * GetMultiAzNodeInfo: Get AZ Info including azName and nodes in az
 * @g_azNum: The num of AZ
 * @g_azArray: Save the AZ info including g_azArray[ii].nodes and g_azArray[ii].azName
 *
 */
void GetMultiAzNodeInfo()
{
    errno_t rc = 0;
    uint32 ii;
    uint32 jj;

    for (ii = 0; ii < g_node_num; ii++) {
        bool isRepeatAz = false;
        for (jj = ii + 1; jj < g_node_num; jj++) {
            if (strcmp(g_node[ii].azName, g_node[jj].azName) == 0) {
                isRepeatAz = true;
                break;
            }
        }
        if (!isRepeatAz) {
            rc = memcpy_s(g_azArray[g_azNum++].azName, CM_AZ_NAME, g_node[ii].azName, CM_AZ_NAME);
            securec_check_errno(rc, (void)rc);
        }
    }

    for (ii = 0; ii < g_azNum; ii++) {
        uint32 azNodeIndex = 0;
        for (jj = 0; jj < g_node_num; jj++) {
            if (strcmp(g_azArray[ii].azName, g_node[jj].azName) == 0) {
                g_azArray[ii].nodes[azNodeIndex] = g_node[jj].node;
                azNodeIndex++;
            }
        }
    }
    return;
}

static void SetCmAzInfo(uint32 groupIndex, int memberIndex, int32 azIndex, uint32 priority)
{
    g_cmAzInfo[azIndex].azIndex = azIndex;
    g_cmAzInfo[azIndex].azPriority = priority;
    errno_t rc = memcpy_s(g_cmAzInfo[azIndex].azName, CM_AZ_NAME,
        g_instance_role_group_ptr[groupIndex].instanceMember[memberIndex].azName, CM_AZ_NAME);
    securec_check_errno(rc, (void)rc);
    int instanceType = g_instance_role_group_ptr[groupIndex].instanceMember[memberIndex].instanceType;
    switch (instanceType) {
        case INSTANCE_TYPE_GTM:
            g_cmAzInfo[azIndex].gtmCount++;
            break;
        case INSTANCE_TYPE_COORDINATE:
            g_cmAzInfo[azIndex].cnCount++;
            break;
        case INSTANCE_TYPE_DATANODE:
            g_cmAzInfo[azIndex].dnCount++;
            break;
        case INSTANCE_TYPE_FENCED_UDF:
            g_cmAzInfo[azIndex].udfCount++;
            break;
        case INSTANCE_TYPE_UNKNOWN:
            g_cmAzInfo[azIndex].unkownCount++;
            break;
        default:
            break;
    }
}

static void GetCmDuplicate(uint32 groupIndex, uint32 *gtmDup, uint32 *dnDup, uint32 *cnDup)
{
    int instanceType = g_instance_role_group_ptr[groupIndex].instanceMember[0].instanceType;
    switch (instanceType) {
        case INSTANCE_TYPE_GTM:
            ++(*gtmDup);
            break;
        case INSTANCE_TYPE_COORDINATE:
            ++(*cnDup);
            break;
        case INSTANCE_TYPE_DATANODE:
            ++(*dnDup);
            break;
        default:
            break;
    }
}

static void GetCmAzInfo()
{
    const uint32 arbitAzpriorityMin = 1000;
    const uint32 arbitAzpriorityMax = 2000;
    uint32 gtmDup = 0;
    uint32 dnDup = 0;
    uint32 cnDup = 0;
    if (g_dynamic_header->relationCount == 0 || g_instance_role_group_ptr == NULL) {
        write_runlog(ERROR, "g_dynamic_header or g_instance_role_group_ptr has not been inited.\n");
        return;
    }

    for (uint32 i = 0; i < g_dynamic_header->relationCount; ++i) {
        for (int j = 0; j < g_instance_role_group_ptr[i].count; ++j) {
            uint32 priority = g_instance_role_group_ptr[i].instanceMember[j].azPriority;
            if (priority < g_az_master) {
                write_runlog(ERROR,
                    "Invalid priority: az name is %s, priority=%u.\n",
                    g_instance_role_group_ptr[i].instanceMember[j].azName,
                    priority);
                return;
            } else if (priority >= g_az_master && priority < g_az_slave) {
                SetCmAzInfo(i, j, AZ1_INDEX, priority);
            } else if (priority >= g_az_slave && priority < g_az_arbiter) {
                SetCmAzInfo(i, j, AZ2_INDEX, priority);
            } else {
                SetCmAzInfo(i, j, AZ3_INDEX, priority);
            }
        }
        GetCmDuplicate(i, &gtmDup, &dnDup, &cnDup);
    }

    for (int k = 0; k < AZ_MEMBER_MAX_COUNT; ++k) {
        if (g_cmAzInfo[k].azPriority >= arbitAzpriorityMin && g_cmAzInfo[k].azPriority < arbitAzpriorityMax) {
            g_cmAzInfo[k].isVoteAz = (int32)IS_VOTE_AZ;
            g_cmAzInfo[k].cnDuplicate = cnDup;
            g_cmAzInfo[k].dnDuplicate = dnDup;
            g_cmAzInfo[k].gtmDuplicate = gtmDup;
        } else {
            g_cmAzInfo[k].isVoteAz = (int32)IS_NOT_VOTE_AZ;
            g_cmAzInfo[k].cnDuplicate = cnDup;
            g_cmAzInfo[k].dnDuplicate = dnDup;
            g_cmAzInfo[k].gtmDuplicate = gtmDup;
        }
    }
}

#if defined (ENABLE_MULTIPLE_NODES) || defined (ENABLE_PRIVATEGAUSS)
static void cmserver_hotpatch_log_callback(int level, const char *logstr)
{
    write_runlog(level, "%s", logstr);
}
#endif

static void InitDdbAbrCfg()
{
    errno_t rc = memset_s(&g_ddbArbicfg, sizeof(DdbArbiCfg), 0, sizeof(DdbArbiCfg));
    securec_check_errno(rc, (void)rc);
    rc = pthread_rwlock_init(&(g_ddbArbicfg.lock), NULL);
    if (rc != 0) {
        write_runlog(FATAL, "failed to InitDdbAbrCfg.\n");
        exit(1);
    }
    const uint32 delayBaseTimeOut = 10;
    const uint32 haHeartBeatTimeOut = 6;
    g_ddbArbicfg.haStatusInterval = 1;
    g_ddbArbicfg.arbiDelayBaseTimeOut = delayBaseTimeOut;
    g_ddbArbicfg.arbiDelayIncrementalTimeOut = CM_SERVER_ARBITRATE_DELAY_CYCLE_MAX_COUNT;
    g_ddbArbicfg.haHeartBeatTimeOut = haHeartBeatTimeOut;
}

static bool IsMaintainFileExist()
{
    struct stat st;
    char maintainFile[CM_PATH_LENGTH] = {0};

    if (GetMaintainPath(maintainFile, CM_PATH_LENGTH) != CM_SUCCESS) {
        write_runlog(ERROR, "get maintain file path fail.\n");
        return false;
    }
    if (stat(maintainFile, &st) == 0) {
        write_runlog(LOG, "current node exist maintain file, is in maintain mode.\n");
        return true;
    }

    return false;
}

static void CpDnInfo(DatanodelocalPeer *dnLp, uint32 instId, uint32 nodeId)
{
    for (uint32 i = 0; i < g_node_num; i++) {
        if (g_node[i].node != nodeId) {
            continue;
        }
        for (uint32 j = 0; j < g_node[i].datanodeCount; ++j) {
            dataNodeInfo *dnInfo = &(g_node[i].datanode[j]);
            if (dnInfo->datanodeId != instId) {
                continue;
            }
            errno_t rc = memcpy_s(
                dnLp->localIp, sizeof(dnLp->localIp), dnInfo->datanodeLocalHAIP, sizeof(dnInfo->datanodeLocalHAIP));
            securec_check_errno(rc, (void)rc);
            dnLp->ipCount = dnInfo->datanodeLocalHAListenCount;
            dnLp->localPort = dnInfo->datanodeLocalHAPort;
        }
    }
}

static void InitDnIpInfo()
{
    for (uint32 i = 0; i < g_dynamic_header->relationCount; ++i) {
        if (g_instance_role_group_ptr[i].instanceMember[0].instanceType != INSTANCE_TYPE_DATANODE) {
            continue;
        }
        for (int32 j = 0; j < g_instance_role_group_ptr[i].count; ++j) {
            DatanodelocalPeer *dnLp = &(g_instance_group_report_status_ptr[i].instance_status.data_node_member[j].dnLp);
            CpDnInfo(dnLp, GetInstanceIdInGroup(i, j), g_instance_role_group_ptr[i].instanceMember[j].node);
        }
    }
}

void ClearResource()
{
    got_stop = 1;
    if (g_dbType == DB_DCC) {
        CloseAllDdbSession();
    }
    write_runlog(WARNING, "receive exit message, cms has cleared resource, and cms will exit.\n");
}

static status_t InitCusResVariable()
{
    uint32 resNodeCount = GetResNodeCount();
    if (resNodeCount > CM_MAX_RES_NODE_COUNT || resNodeCount == 0) {
        write_runlog(ERROR,
            "cus res, not support (%u) node, node count range:(0, %d].\n", resNodeCount, CM_MAX_RES_NODE_COUNT);
        return CM_ERROR;
    }
    InitNodeReportVar();
    InitIsregVariable();

    return CM_SUCCESS;
}

int main(int argc, char** argv)
{
    uid_t uid = getuid();
    if (uid == 0) {
        (void)printf("current user is the root user (uid = 0), exit.\n");
        return -1;
    }

    int status;
    errno_t rc = 0;
    int rcs;
    char cm_pid_file_path[MAX_PATH_LEN];
    struct stat stat_buf = {0};
    bool &isSharedStorageMode = GetIsSharedStorageMode();
    g_progname = "cm_server";
    prefix_name = g_progname;

    thread_name = "MAIN";
    (void)syscalllockInit(&g_cmEnvLock);

    GetCmdlineOpt(argc, argv);

    if (argc > 1) {
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-?") == 0) {
            DoHelp();
            exit(0);
        } else if (strcmp(argv[1], "-V") == 0 || strcmp(argv[1], "--version") == 0) {
            (void)puts("cm_server " DEF_CM_VERSION);
            exit(0);
        }
    }

    /* init the sigset and register the signal handle */
    init_signal_mask();
    (void)sigprocmask(SIG_SETMASK, &block_sig, NULL);
    setup_signal_handle(SIGINT, stop_signal_reaper);
    setup_signal_handle(SIGQUIT, stop_signal_reaper);
    setup_signal_handle(SIGUSR1, close_all_agent_connections);
    setup_signal_handle(SIGUSR2, SetReloadDdbConfigFlag);
    setup_signal_handle(SIGHUP, reload_cmserver_parameters);

    status = get_prog_path();
    if (status < 0) {
        write_runlog(ERROR, "get_prog_path  failed!\n");
        return -1;
    }

    pw = getpwuid(getuid());
    if (pw == NULL || pw->pw_name == NULL) {
        write_runlog(ERROR, "can not get current user name.\n");
        return -1;
    }

    cm_server_listen_socket_init();

    status = cm_server_init_ha_status();
    if (status < 0) {
        write_runlog(ERROR, "cm_server_init_ha_status failed!\n");
        return -1;
    }

    (void)read_config_file_check();
    max_logic_cluster_name_len = (max_logic_cluster_name_len < strlen("logiccluster_name"))
                                     ? (uint32)strlen("logiccluster_name")
                                     : max_logic_cluster_name_len;

    if (g_node == NULL) {
        write_runlog(ERROR, "read_config_file_check failed!\n");
        return -1;
    }

    /* check cm_server.pid file */
    rcs = snprintf_s(
        cm_pid_file_path, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/cm/%s", g_currentNode->cmDataPath, CM_PID_FILE);
    securec_check_intval(rcs, (void)rcs);
    if (stat(cm_pid_file_path, &stat_buf) != 0) {
        /* if the pid file does not exist */
        g_isStart = true;
    }

    (void)logfile_init();
    InitDdbAbrCfg();
    
    status = CmSSlConfigInit(false);
    if (status < 0) {
        write_runlog(ERROR, "read ssl config failed!\n");
        return -1;
    }

    get_parameters_from_configfile();

    /* deal sys_log_path is null.save log to cmData dir. */
    if (sys_log_path[0] == '\0') {
        rc = strncpy_s(sys_log_path, sizeof(sys_log_path), g_currentNode->cmDataPath, MAXPGPATH - 1);
        securec_check_errno(rc, (void)rc);

        rc = strncat_s(sys_log_path, sizeof(sys_log_path), "/cm/log", strlen("/cm/log"));
        securec_check_errno(rc, (void)rc);
        check_input_for_security(sys_log_path);
        canonicalize_path(sys_log_path);
        (void)mkdir(sys_log_path, S_IRWXU);
    } else {
        if (sys_log_path[0] == '/') {
            (void)mkdir(sys_log_path, S_IRWXU);
        } else {
            char buf[MAXPGPATH] = {0};

            rc = memset_s(buf, sizeof(buf), 0, MAXPGPATH);
            securec_check_errno(rc, (void)rc);

            rc = strncpy_s(buf, sizeof(buf), g_currentNode->cmDataPath, MAXPGPATH - 1);
            securec_check_errno(rc, (void)rc);

            rc = strncat_s(buf, sizeof(buf), "/cm_server/", strlen("/cm_server/"));
            securec_check_errno(rc, (void)rc);

            rc = strncat_s(buf, sizeof(buf), sys_log_path, strlen(sys_log_path));
            securec_check_errno(rc, (void)rc);

            rc = memcpy_s(sys_log_path, sizeof(sys_log_path), buf, MAXPGPATH);
            securec_check_errno(rc, (void)rc);
            check_input_for_security(sys_log_path);
            canonicalize_path(sys_log_path);
            (void)mkdir(sys_log_path, S_IRWXU);
        }
    }
    if (syslogFile == NULL) {
        syslogFile = logfile_open(sys_log_path, "a");
        if (syslogFile == NULL) {
            (void)printf("server_main,open log file failed\n");
        }
    }

    print_environ();
    AlarmEnvInitialize();
    create_system_alarm_log(sys_log_path);
    CreateKeyEventLogFile(sys_log_path);
    UnbalanceAlarmItemInitialize();
    InitDbListsByStaticConfig();
#ifdef ENABLE_MULTIPLE_NODES
    /* initialize cm cgroup and attach it if the relative path is not NULL. */
    char* cmcgroup_relpath = gscgroup_cm_init();
    if (cmcgroup_relpath != NULL) {
        write_runlog(FATAL, "cmserver attach task!\n");
        gscgroup_cm_attach_task(cmcgroup_relpath);
        free(cmcgroup_relpath);
    }
#endif
    /*
     * Some basic initialization must happen before we do anything
     * useful
     */
    BaseInit();
    InitCltCmdProc();
    isSharedStorageMode = IsSharedStorageMode();
#if defined (ENABLE_MULTIPLE_NODES) || defined (ENABLE_PRIVATEGAUSS)
    rcs = hotpatch_init(cm_server_dataDir, (HOTPATCH_LOG_FUNC)cmserver_hotpatch_log_callback);
    if (rcs != HP_OK) {
        write_runlog(LOG, "hotpatch init failed ! rcs is %d\n", rcs);
    }
#endif

    int ret = InitConn();
    if (ret != 0) {
        return -1;
    }

    status = static_dynamic_config_file_check();
    if (status < 0) {
        write_runlog(ERROR, "static_dynamic_config_file_check  failed!\n");
        return -1;
    }

    status = cm_server_build_listen_socket_check();
    if (status != STATUS_OK) {
        write_runlog(ERROR, "cm_server_build_listen_socket_check failed!\n");
        FreeNotifyMsg();
        return -1;
    }
    InitDnIpInfo();
    status_t st = CreateCmsInstInfo();
    if (st != CM_SUCCESS) {
        write_runlog(ERROR, "CreateCmsInstInfo failed.\n");
        FreeNotifyMsg();
        return -1;
    }
    (void)DdbRegisterStatusNotify(CmsNotifyStatus);
    st = ServerDdbInit();
    if (st != CM_SUCCESS) {
        write_runlog(ERROR, "ServerDdbInit failed.\n");
        CloseAllDdbSession();
        FreeNotifyMsg();
        return -1;
    }
    (void)atexit(ClearResource);
    GetBackupOpenConfig();
    InstanceAlarmItemInitialize();
    ReadOnlyAlarmItemInitialize();
    GetCmAzInfo();
    ret = ReadCmConfJson((void*)write_runlog);
    if (!IsReadConfJsonSuccess(ret)) {
        write_runlog(FATAL, "read cm conf json failed, ret=%d, reason=\"%s\".\n", ret, ReadConfJsonFailStr(ret));
        return -1;
    }
    if (InitAllResStat() != CM_SUCCESS) {
        write_runlog(FATAL, "init res status failed.\n");
        return -1;
    }
    if (IsCusResExist() && (InitCusResVariable() != CM_SUCCESS)) {
        write_runlog(FATAL, "init cus res variable failed.\n");
        return -1;
    }

    status = CM_CreateMonitor();
    if (status < 0) {
        write_runlog(ERROR, "CM_CreateMonitor  failed!\n");
        CloseAllDdbSession();
        FreeNotifyMsg();
        return -1;
    }

    if (IsNeedSyncDdb()) {
        status = CM_CreateMonitorStopNode();
        if (status < 0) {
            write_runlog(ERROR, "CM_CreateMonitorStopNode failed!\n");
            CloseAllDdbSession();
            FreeNotifyMsg();
            return -1;
        }
    }

    // worker：     total [5,1000] s  5     6   10  32 50  100 200 500 1000
    // IO worker      a = s/3         1  2   3   10 16  33  66  166  333
    // clt worker     b = (s-a)/2     2  2   3   11 17  33  66  167  333
    // agent worker   c = s-a-b       2  2   4   11 17  34  68  167  334
 
    // node num                       <32    <32  >32  >32
    // agent worker                   <=4    >4   <=4  >4
    // ctl worker                      2     2    2    4
 
    const uint32 workerCountPerNode = 3;
    uint32 totalWorker = cm_thread_count;
    if ((uint32)cm_thread_count > g_node_num * workerCountPerNode) {
        totalWorker = g_node_num * workerCountPerNode;
    }
    if (totalWorker < workerCountPerNode) {
        totalWorker = workerCountPerNode;
    }
 
    uint32 ioWorkerCount = totalWorker / 3;
    uint32 cltWorkerCount = (totalWorker - ioWorkerCount) / 2;
    uint32 agentWorkerCount = (totalWorker - ioWorkerCount) - cltWorkerCount;
 
    status = CM_CreateIOThreadPool(ioWorkerCount);
    if (status < 0) {
        write_runlog(ERROR, "Create IOThreads failed!\n");
        CloseAllDdbSession();
        FreeNotifyMsg();
        return -1;
    }
 
    status = CM_CreateWorkThreadPool(cltWorkerCount, agentWorkerCount);
    if (status < 0) {
        write_runlog(ERROR, "Create Threads Pool failed!\n");
        CloseAllDdbSession();
        FreeNotifyMsg();
        return -1;
    }
    
    g_inMaintainMode = IsMaintainFileExist();

    status = CM_CreateHA();
    if (status < 0) {
        write_runlog(ERROR, "CM_CreateHA failed!\n");
        CloseAllDdbSession();
        FreeNotifyMsg();
        return -1;
    }

    if (g_cm_server_num == CMS_ONE_PRIMARY_ONE_STANDBY && g_dbType == DB_DCC) {
        status = CM_CreateDdbStatusCheckThread();
        if (status < 0) {
            write_runlog(ERROR, "CM_CreateDdbStatusCheckThread  failed!\n");
            CloseAllDdbSession();
            FreeNotifyMsg();
            return -1;
        }
    }

    GetMultiAzNodeInfo();
    g_loopState.count = 1;
    st = CmsCreateThreads();
    if (st != CM_SUCCESS) {
        write_runlog(ERROR, "Cms Create Threads failed!\n");
        CloseAllDdbSession();
        FreeNotifyMsg();
        return -1;
    }

    if (cms_init_ssl() != CM_SUCCESS) {
        write_runlog(ERROR, "ssl init failed.\n");
        CloseAllDdbSession();
        FreeNotifyMsg();
        return -1;
    }
    status = server_loop();
    CloseAllDdbSession();
    FreeNotifyMsg();
    exit(status);
}
