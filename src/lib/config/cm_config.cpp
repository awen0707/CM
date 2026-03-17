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
 * cm_config.cpp
 *    functions to read cluster static config file
 *
 * IDENTIFICATION
 *    src/lib/config/cm_config.cpp
 *
 * -------------------------------------------------------------------------
 */

#include <map>
#include <algorithm>
#include <string>
#include "securec.h"
#include "securec_check.h"
#include "common/config/cm_config.h"

using namespace std;

/* This macro was used to replace the "goto" statement of the function "read_logic_config_file". */
#define READ_LOGICAL_CONFIG_FAILED(fd)                      \
    do {                                                \
        if (NULL != LCStaticConfig->logicClusterNode) { \
            free(LCStaticConfig->logicClusterNode);     \
            LCStaticConfig->logicClusterNode = NULL;    \
        }                                               \
        (void)fclose(fd);                               \
        *err_no = errno;                                \
        return READ_FILE_ERROR;                         \
    } while (0)

staticConfigHeader g_nodeHeader;
staticNodeConfig *g_node = NULL;
uint32 g_az_master = PG_UINT32_MAX;
uint32 g_az_slave = PG_UINT32_MAX;
uint32 g_az_arbiter = PG_UINT32_MAX;
logicClusterStaticConfig g_logicClusterStaticConfig[LOGIC_CLUSTER_NUMBER] = {0};
uint32 g_logic_cluster_count = 0;
uint32 max_logic_cluster_state_len = 20;
uint32 max_logic_cluster_name_len = 0;
bool logic_cluster_query = false;
bool logic_cluster_restart = false;
staticNodeConfig *g_currentNode = NULL;
bool g_single_node_cluster = false;
bool g_multi_az_cluster = false;
bool g_one_master_multi_slave = false;
bool g_only_dn_cluster = false;
ClusterType g_clusterType = InvalidCluster;
uint32 g_node_num = 0;
uint32 g_cluster_total_instance_group_num = 0;
uint32 g_coordinator_num = 0;
uint32 g_etcd_num = 0;
uint32 g_cm_server_num = 0;
uint32 g_dn_replication_num = 0;
uint32 g_gtm_num = 0;
uint32 max_node_name_len = 0;
uint32 max_az_name_len = 0;
uint32 max_datapath_len = 0;
uint32 max_cnpath_len = 0;
uint32 max_gtmpath_len = 0;
uint32 max_etcdpath_len = 0;
uint32 max_cmpath_len = 0;

/* the local node name and idx */
uint32 g_local_node_idx = 0;
char *g_local_node_name = NULL;

// the logical cluster name
char *g_lcname = NULL;

/* for datanode alarm */
uint32 g_datanodeid = 0;
char *g_logicClusterName = NULL;
bool g_isCmRead = false;

#define FREAD1(ptr, nitems, size, stream)                         \
    do {                                                          \
        if (fread((ptr), (size), (nitems), (stream)) != (nitems)) \
            return READ_FILE_ERROR;                               \
    } while (0)

#define FREAD(ptr, nitems, size, stream)                          \
    do {                                                          \
        if (fread((ptr), (size), (nitems), (stream)) != (nitems)) \
            goto read_failed;                                     \
    } while (0)

#define RETURN_IFERR(ret) \
    do {                  \
        if ((ret) != 0) { \
            return (ret); \
        }                 \
    } while (0)

static int read_all_logic_config_file(const logicClusterList lcList, int *err_no);
static int read_logic_config_file(const logicClusterInfo lcInfo, int *err_no);

void check_input_for_security(const char *input)
{
    const char *danger_character_list[] = {"|", ";", "&", "$", "<", ">", "`", "\\", "'", "\"", "{", "}",
        "(", ")", "[", "]", "~", "*", "?", "!", "\n", NULL};

    for (int32 i = 0; danger_character_list[i] != NULL; i++) {
        if (strstr(input, danger_character_list[i]) != NULL) {
            (void)fprintf(stderr, "FATAL invalid token \"%s\" in input_value: (%s)\n", danger_character_list[i], input);
            exit(1);
        }
    }
}

int cmconfig_getenv(const char *env_var, char *output_env_value, uint32 env_value_len)
{
    if (env_var == NULL) {
        (void)fprintf(stderr, "cmconfig_getenv: invalid env_var !\n");
        return -1;
    }

    char *env_value = getenv(env_var);
    if (env_value == NULL || env_value[0] == '\0') {
        (void)fprintf(stderr,
            "cmconfig_getenv: failed to get environment variable:%s. Please check and make sure it is configured!\n",
            env_var);
        return -1;
    }
    check_input_for_security(env_value);

    int32 rc = strcpy_s(output_env_value, env_value_len, env_value);
    if (rc != EOK) {
        (void)fprintf(stderr,
            "cmconfig_getenv: failed to get environment variable:%s, variable length:%lu.\n",
            env_var,
            strlen(env_value));
        return -1;
    }
    return EOK;
}

/*
 * qsort comparison function for server node index
 */
int node_index_Comparator(const void *arg1, const void *arg2)
{
    uint32 index1 = *(const uint32 *)arg1;
    uint32 index2 = *(const uint32 *)arg2;

    if (index1 > index2) {
        return 1;
    } else if (index1 < index2) {
        return -1;
    } else {
        return 0;
    }
}

int find_node_index_by_nodeid(uint32 nodeId, uint32 *node_index)
{
    for (uint32 i = 0; i < g_node_num; i++) {
        if (g_node[i].node == nodeId) {
            *node_index = i;
            return 0;
        }
    }
    return -1;
}

int find_current_node_by_nodeid()
{
    uint32 node_index = 0;
    int ret = find_node_index_by_nodeid(g_nodeHeader.node, &node_index);
    if (ret != 0) {
        return -1;
    }
    g_currentNode = &g_node[node_index];
    return 0;
}

/* read config file to get azPriority for each AZ
 * rule 1: the priority value in different AZ must satisfy: AZ3 > AZ2 > AZ1
 * rule 2: the priority value can be different unsigned integer among a AZ, such as 1, 3, etc
 * rule 3: the priority of a AZ is the smallest priority value
 * */
void setAZPriority()
{
    map<string, uint32> nameAndPriority;
    map<string, uint32>::iterator it;
    const int azNumber = 3;
    int zeroIndex = 0;
    uint32 priorities[azNumber] = {PG_UINT32_MAX, PG_UINT32_MAX, PG_UINT32_MAX};

    for (uint32 i = 0; i < g_node_num; i++) {
        if (!g_multi_az_cluster) {
            break;
        }

        string azName = g_node[i].azName;
        uint32 azPriority = g_node[i].azPriority;
        it = nameAndPriority.find(azName);
        if (it != nameAndPriority.end() && it->second > azPriority) {
            it->second = azPriority;
        } else {
            (void)nameAndPriority.emplace(pair<string, uint32>(azName, azPriority));
        }
    }

    it = nameAndPriority.begin();
    for (uint32 i = 0; i < azNumber; ++i) {
        if (it == nameAndPriority.end()) {
            break;
        }
        priorities[i] = it->second;
        (void)(it++);
    }

    sort(priorities, priorities + azNumber);
    g_az_master = priorities[zeroIndex];
    g_az_slave = priorities[++zeroIndex];
    g_az_arbiter = priorities[++zeroIndex];
}

using ReadConfigContext = struct StReadConfigContext {
    uint32 cmServerNum;
    uint32 gtmNum;
    uint32 dnReplicationNum;
    uint32 etcdNum;
    uint32 cnNum;
    uint32 datanodeMirrorID;
    bool datanodeMirrorIDInit;
};

static FILE *open_config_file(const char *file_path, int *err_no)
{
    char configFilePath[MAX_PATH_LEN];

    int32 rcs = strncpy_s(configFilePath, MAX_PATH_LEN, file_path, MAX_PATH_LEN - 1);
    securec_check_c(rcs, "", "");
    canonicalize_path(configFilePath);
    FILE *fd = fopen(configFilePath, "r");
    if (fd == NULL) {
        *err_no = errno;
        return NULL;
    }

    return fd;
}

static int read_config_header(FILE *fd)
{
    const uint32 v3SingleInstClusterVersionBegin = 9301;
    const uint32 v3SingleInstClusterVersionEnd = 10301;
    const uint32 headerVersion1 = 100;
    const uint32 headerVersion2 = 200;
    const uint32 headerVersion3 = 300;
    const uint32 headerVersion4 = 400;
    const uint32 headerVersion5 = 500;

    /********************************************************************************
     *  DISCLAIMER: Any Change in file format need to update the Version Number      *
     *              Version Number Offset should not be changed                      *
     ********************************************************************************/
    int32 rcs = memset_s(&g_nodeHeader, sizeof(staticConfigHeader), 0, sizeof(staticConfigHeader));
    securec_check_c(rcs, "", "");

    // read head info
    FREAD1(&g_nodeHeader.crc, 1, sizeof(uint32), fd);
    FREAD1(&g_nodeHeader.len, 1, sizeof(uint32), fd);
    FREAD1(&g_nodeHeader.version, 1, sizeof(uint32), fd);
    // version in [101, 200] means single node cluster.
    if (g_nodeHeader.version <= headerVersion1) {
        g_single_node_cluster = false;
        g_multi_az_cluster = false;
        g_clusterType = MasterStandbyDummyCluster;
    } else if ((g_nodeHeader.version > headerVersion1) && (g_nodeHeader.version <= headerVersion2)) {
        g_single_node_cluster = true;
        g_multi_az_cluster = false;
        g_clusterType = SingleCluster;
    } else if ((g_nodeHeader.version > headerVersion2) && (g_nodeHeader.version <= headerVersion3)) {
        g_multi_az_cluster = true;
        g_one_master_multi_slave = true;
        g_clusterType = SinglePrimaryMultiStandbyCluster;
    } else if ((g_nodeHeader.version > headerVersion3) && (g_nodeHeader.version <= headerVersion4)) {
        g_only_dn_cluster = true;
        // only dn is a subset for multi az
        g_multi_az_cluster = true;
        g_one_master_multi_slave = true;
        g_clusterType = SingleInstCluster;
    } else if ((g_nodeHeader.version >= headerVersion4) && (g_nodeHeader.version <= headerVersion5)) {
        g_single_node_cluster = true;
        g_only_dn_cluster = true;
        g_multi_az_cluster = false;
        g_clusterType = SingleInstClusterCent;
    } else if ((g_nodeHeader.version >= v3SingleInstClusterVersionBegin) &&
               (g_nodeHeader.version <= v3SingleInstClusterVersionEnd)) {
        g_only_dn_cluster = true;
        g_multi_az_cluster = true;
        g_one_master_multi_slave = true;
        g_clusterType = V3SingleInstCluster;
    }
    FREAD1(&g_nodeHeader.time, 1, sizeof(int64), fd);
    FREAD1(&g_nodeHeader.nodeCount, 1, sizeof(uint32), fd);
    FREAD1(&g_nodeHeader.node, 1, sizeof(uint32), fd);

    if (g_nodeHeader.nodeCount > CM_NODE_MAXNUM || g_nodeHeader.nodeCount == 0) {
        return READ_FILE_ERROR;
    }

    return 0;
}

static int alloc_node_buffer(bool inReload)
{
    int rcs = 0;
    if (inReload) {
        return 0;
    }

    if (g_node == NULL) {
        g_node = (staticNodeConfig *)malloc(sizeof(staticNodeConfig) * g_nodeHeader.nodeCount);
        if (g_node == NULL) {
            return OUT_OF_MEMORY;
        }
    }

    /* g_node size may be larger than SECUREC_STRING_MAX_LEN in large cluster. */
    rcs = memset_s(g_node, sizeof(staticNodeConfig) * g_nodeHeader.nodeCount,
        0, sizeof(staticNodeConfig) * g_nodeHeader.nodeCount);
    if (rcs != EOK && rcs != ERANGE) {
        (void)printf("FATAL at %s : %d : Initialize is failed, error num is: %d.\n", __FUNCTION__, __LINE__, rcs);
        free(g_node);
        g_node = NULL;
        exit(1);
    }

    return 0;
}

static int ReadNodeInfo(FILE *fd, uint32 nodeId)
{
    /* read node info */
    FREAD1(&g_node[nodeId].crc, 1, sizeof(uint32), fd);
    FREAD1(&g_node[nodeId].node, 1, sizeof(uint32), fd);
    FREAD1(g_node[nodeId].nodeName, 1, (CM_NODE_NAME - 1), fd);
    g_node[nodeId].nodeName[CM_NODE_NAME - 1] = '\0';
    check_input_for_security(g_node[nodeId].nodeName);

    max_node_name_len = (max_node_name_len < (uint32)strlen(g_node[nodeId].nodeName)) ?
        (uint32)strlen(g_node[nodeId].nodeName) : max_node_name_len;

    if (g_clusterType >= SinglePrimaryMultiStandbyCluster && g_clusterType <= V3SingleInstCluster) {
        /* read az info */
        FREAD1(g_node[nodeId].azName, 1, (CM_AZ_NAME - 1), fd);
        g_node[nodeId].azName[CM_AZ_NAME - 1] = '\0';
        check_input_for_security(g_node[nodeId].azName);
        FREAD1(&g_node[nodeId].azPriority, 1, sizeof(uint32), fd);
        max_az_name_len = (max_az_name_len < (uint32)strlen(g_node[nodeId].azName)) ?
            (uint32)strlen(g_node[nodeId].azName) : max_az_name_len;
    }

    return 0;
}

static int ReadNodeBackIp(FILE *fd, uint32 nodeId)
{
    FREAD1(&g_node[nodeId].backIpCount, 1, sizeof(uint32), fd);
    if (g_node[nodeId].backIpCount > CM_IP_NUM) {
        return READ_FILE_ERROR;
    }
    for (int jj = 0; jj < CM_IP_NUM; jj++) {
        FREAD1(g_node[nodeId].backIps[jj], 1, CM_IP_LENGTH, fd);
        g_node[nodeId].backIps[jj][CM_IP_LENGTH - 1] = '\0';
        check_input_for_security(g_node[nodeId].backIps[jj]);
    }

    return 0;
}

static int ReadNodeSsh(FILE *fd, uint32 nodeId)
{
    FREAD1(&g_node[nodeId].sshCount, 1, sizeof(uint32), fd);
    if (g_node[nodeId].sshCount > CM_IP_NUM) {
        return READ_FILE_ERROR;
    }
    for (int jj = 0; jj < CM_IP_NUM; jj++) {
        FREAD1(g_node[nodeId].sshChannel[jj], 1, CM_IP_LENGTH, fd);
        g_node[nodeId].sshChannel[jj][CM_IP_LENGTH - 1] = '\0';
        check_input_for_security(g_node[nodeId].sshChannel[jj]);
    }
    return 0;
}

static int ReadNodeCmserver(FILE *fd, uint32 nodeId, ReadConfigContext *ctx)
{
    /* read CMServer info */
    FREAD1(&g_node[nodeId].cmServerId, 1, sizeof(uint32), fd);
    if (g_node[nodeId].cmServerId != 0) {
        ctx->cmServerNum++;
    }
    FREAD1(&g_node[nodeId].cmServerMirrorId, 1, sizeof(uint32), fd);
    FREAD1(g_node[nodeId].cmDataPath, 1, CM_PATH_LENGTH, fd);
    g_node[nodeId].cmDataPath[CM_PATH_LENGTH - 1] = '\0';
    check_input_for_security(g_node[nodeId].cmDataPath);

    max_cmpath_len = (max_cmpath_len < (uint32)strlen(g_node[nodeId].cmDataPath)) ?
        (uint32)strlen(g_node[nodeId].cmDataPath) : max_cmpath_len;

    FREAD1(&g_node[nodeId].cmServerLevel, 1, sizeof(uint32), fd);
    FREAD1(g_node[nodeId].cmServerFloatIP, 1, CM_IP_LENGTH, fd);
    g_node[nodeId].cmServerFloatIP[CM_IP_LENGTH - 1] = '\0';

    check_input_for_security(g_node[nodeId].cmServerFloatIP);
    FREAD1(&g_node[nodeId].cmServerListenCount, 1, sizeof(uint32), fd);
    if (g_node[nodeId].cmServerListenCount > CM_IP_NUM) {
        return READ_FILE_ERROR;
    }
    for (int jj = 0; jj < CM_IP_NUM; jj++) {
        FREAD1(g_node[nodeId].cmServer[jj], 1, CM_IP_LENGTH, fd);
        g_node[nodeId].cmServer[jj][CM_IP_LENGTH - 1] = '\0';
        check_input_for_security(g_node[nodeId].cmServer[jj]);
    }
    FREAD1(&g_node[nodeId].port, 1, sizeof(uint32), fd);
    FREAD1(&g_node[nodeId].cmServerLocalHAListenCount, 1, sizeof(uint32), fd);
    if (g_node[nodeId].cmServerLocalHAListenCount > CM_IP_NUM) {
        return READ_FILE_ERROR;
    }
    for (int jj = 0; jj < CM_IP_NUM; jj++) {
        FREAD1(g_node[nodeId].cmServerLocalHAIP[jj], 1, CM_IP_LENGTH, fd);
        g_node[nodeId].cmServerLocalHAIP[jj][CM_IP_LENGTH - 1] = '\0';
        check_input_for_security(g_node[nodeId].cmServerLocalHAIP[jj]);
    }
    FREAD1(&g_node[nodeId].cmServerLocalHAPort, 1, sizeof(uint32), fd);
    FREAD1(&g_node[nodeId].cmServerRole, 1, sizeof(uint32), fd);

    FREAD1(&g_node[nodeId].cmServerPeerHAListenCount, 1, sizeof(uint32), fd);
    if (g_node[nodeId].cmServerPeerHAListenCount > CM_IP_NUM) {
        return READ_FILE_ERROR;
    }
    for (int jj = 0; jj < CM_IP_NUM; jj++) {
        FREAD1(g_node[nodeId].cmServerPeerHAIP[jj], 1, CM_IP_LENGTH, fd);
        g_node[nodeId].cmServerPeerHAIP[jj][CM_IP_LENGTH - 1] = '\0';
        check_input_for_security(g_node[nodeId].cmServerPeerHAIP[jj]);
    }
    FREAD1(&g_node[nodeId].cmServerPeerHAPort, 1, sizeof(uint32), fd);

    return 0;
}

static int ReadNodeGtm(FILE *fd, uint32 nodeId, ReadConfigContext *ctx)
{
    /* read GTM info */
    FREAD1(&g_node[nodeId].cmAgentId, 1, sizeof(uint32), fd);
    FREAD1(&g_node[nodeId].cmAgentMirrorId, 1, sizeof(uint32), fd);
    FREAD1(&g_node[nodeId].cmAgentListenCount, 1, sizeof(uint32), fd);
    if (g_node[nodeId].cmAgentListenCount > CM_IP_NUM) {
        return READ_FILE_ERROR;
    }
    for (int jj = 0; jj < CM_IP_NUM; jj++) {
        FREAD1(g_node[nodeId].cmAgentIP[jj], 1, CM_IP_LENGTH, fd);
        g_node[nodeId].cmAgentIP[jj][CM_IP_LENGTH - 1] = '\0';
        check_input_for_security(g_node[nodeId].cmAgentIP[jj]);
    }
    FREAD1(&g_node[nodeId].gtmId, 1, sizeof(uint32), fd);
    FREAD1(&g_node[nodeId].gtmMirrorId, 1, sizeof(uint32), fd);
    FREAD1(&g_node[nodeId].gtm, 1, sizeof(uint32), fd);
    if (g_node[nodeId].gtm == 1) {
        ctx->gtmNum++;
    }

    /* g_cluster_total_instance_group_num: current total instance number in cluster includeing cn dn and gtm */
    /* calculate gtm group number */
    if (g_node[nodeId].gtm == 1 && g_node[nodeId].gtmRole == PRIMARY_GTM) {
        g_cluster_total_instance_group_num++;
    }

    FREAD1(g_node[nodeId].gtmLocalDataPath, 1, CM_PATH_LENGTH, fd);
    g_node[nodeId].gtmLocalDataPath[CM_PATH_LENGTH - 1] = '\0';
    check_input_for_security(g_node[nodeId].gtmLocalDataPath);

    max_gtmpath_len = (max_gtmpath_len < (uint32)strlen(g_node[nodeId].gtmLocalDataPath)) ?
        (uint32)strlen(g_node[nodeId].gtmLocalDataPath) : max_gtmpath_len;

    FREAD1(&g_node[nodeId].gtmLocalListenCount, 1, sizeof(uint32), fd);
    if (g_node[nodeId].gtmLocalListenCount > CM_IP_NUM) {
        return READ_FILE_ERROR;
    }
    for (int jj = 0; jj < CM_IP_NUM; jj++) {
        FREAD1(g_node[nodeId].gtmLocalListenIP[jj], 1, CM_IP_LENGTH, fd);
        g_node[nodeId].gtmLocalListenIP[jj][CM_IP_LENGTH - 1] = '\0';
        check_input_for_security(g_node[nodeId].gtmLocalListenIP[jj]);
    }
    FREAD1(&g_node[nodeId].gtmLocalport, 1, sizeof(uint32), fd);
    FREAD1(&g_node[nodeId].gtmRole, 1, sizeof(uint32), fd);
    FREAD1(&g_node[nodeId].gtmLocalHAListenCount, 1, sizeof(uint32), fd);
    if (g_node[nodeId].gtmLocalHAListenCount > CM_IP_NUM) {
        return READ_FILE_ERROR;
    }
    for (int jj = 0; jj < CM_IP_NUM; jj++) {
        FREAD1(g_node[nodeId].gtmLocalHAIP[jj], 1, CM_IP_LENGTH, fd);
        g_node[nodeId].gtmLocalHAIP[jj][CM_IP_LENGTH - 1] = '\0';
        check_input_for_security(g_node[nodeId].gtmLocalHAIP[jj]);
    }
    FREAD1(&g_node[nodeId].gtmLocalHAPort, 1, sizeof(uint32), fd);
    FREAD1(g_node[nodeId].gtmPeerDataPath, 1, CM_PATH_LENGTH, fd);
    g_node[nodeId].gtmPeerDataPath[CM_PATH_LENGTH - 1] = '\0';
    check_input_for_security(g_node[nodeId].gtmPeerDataPath);

    FREAD1(&g_node[nodeId].gtmPeerHAListenCount, 1, sizeof(uint32), fd);

    for (int jj = 0; jj < CM_IP_NUM; jj++) {
        FREAD1(g_node[nodeId].gtmPeerHAIP[jj], 1, CM_IP_LENGTH, fd);
        g_node[nodeId].gtmPeerHAIP[jj][CM_IP_LENGTH - 1] = '\0';
        check_input_for_security(g_node[nodeId].gtmPeerHAIP[jj]);
    }
    FREAD1(&g_node[nodeId].gtmPeerHAPort, 1, sizeof(uint32), fd);
    FREAD1(&g_node[nodeId].gtmProxyId, 1, sizeof(uint32), fd);
    FREAD1(&g_node[nodeId].gtmProxyMirrorId, 1, sizeof(uint32), fd);
    FREAD1(&g_node[nodeId].gtmProxy, 1, sizeof(uint32), fd);
    FREAD1(&g_node[nodeId].gtmProxyListenCount, 1, sizeof(uint32), fd);
    if (g_node[nodeId].gtmProxyListenCount > CM_IP_NUM) {
        return READ_FILE_ERROR;
    }
    for (int jj = 0; jj < CM_IP_NUM; jj++) {
        FREAD1(g_node[nodeId].gtmProxyListenIP[jj], 1, CM_IP_LENGTH, fd);
        g_node[nodeId].gtmProxyListenIP[jj][CM_IP_LENGTH - 1] = '\0';
        check_input_for_security(g_node[nodeId].gtmProxyListenIP[jj]);
    }
    FREAD1(&g_node[nodeId].gtmProxyPort, 1, sizeof(uint32), fd);

    return 0;
}

static int ReadNodeCn(FILE *fd, uint32 nodeId)
{
    /* read CN info */
    FREAD1(&g_node[nodeId].coordinateId, 1, sizeof(uint32), fd);
    FREAD1(&g_node[nodeId].coordinateMirrorId, 1, sizeof(uint32), fd);
    FREAD1(&g_node[nodeId].coordinate, 1, sizeof(uint32), fd);
    FREAD1(g_node[nodeId].DataPath, 1, CM_PATH_LENGTH, fd);
    g_node[nodeId].DataPath[CM_PATH_LENGTH - 1] = '\0';
    check_input_for_security(g_node[nodeId].DataPath);

    FREAD1(g_node[nodeId].SSDDataPath, 1, CM_PATH_LENGTH, fd);
    g_node[nodeId].SSDDataPath[CM_PATH_LENGTH - 1] = '\0';
    check_input_for_security(g_node[nodeId].SSDDataPath);

    max_cnpath_len = (max_cnpath_len < (uint32)strlen(g_node[nodeId].DataPath)) ?
        (uint32)strlen(g_node[nodeId].DataPath) : max_cnpath_len;

    FREAD1(&g_node[nodeId].coordinateListenCount, 1, sizeof(uint32), fd);
    if (g_node[nodeId].coordinateListenCount > CM_IP_NUM) {
        return READ_FILE_ERROR;
    }
    for (int jj = 0; jj < CM_IP_NUM; jj++) {
        FREAD1(g_node[nodeId].coordinateListenIP[jj], 1, CM_IP_LENGTH, fd);
        g_node[nodeId].coordinateListenIP[jj][CM_IP_LENGTH - 1] = '\0';
        check_input_for_security(g_node[nodeId].coordinateListenIP[jj]);
    }
    FREAD1(&g_node[nodeId].coordinatePort, 1, sizeof(uint32), fd);
    FREAD1(&g_node[nodeId].coordinateHAPort, 1, sizeof(uint32), fd);

    return 0;
}

static int ReadNodeOneDnListenIp(FILE *fd, uint32 nodeId, uint32 dnId)
{
    FREAD1(&g_node[nodeId].datanode[dnId].datanodeListenCount, 1, sizeof(uint32), fd);
    if (g_node[nodeId].datanode[dnId].datanodeListenCount > CM_IP_NUM) {
        return READ_FILE_ERROR;
    }
    for (int nn = 0; nn < CM_IP_NUM; nn++) {
        FREAD1(g_node[nodeId].datanode[dnId].datanodeListenIP[nn], 1, CM_IP_LENGTH, fd);
        g_node[nodeId].datanode[dnId].datanodeListenIP[nn][CM_IP_LENGTH - 1] = '\0';
        check_input_for_security(g_node[nodeId].datanode[dnId].datanodeListenIP[nn]);
    }

    return 0;
}

static int ReadNodeOneDnListenHaip(FILE *fd, uint32 nodeId, uint32 dnId)
{
    FREAD1(&g_node[nodeId].datanode[dnId].datanodeLocalHAListenCount, 1, sizeof(uint32), fd);
    if (g_node[nodeId].datanode[dnId].datanodeLocalHAListenCount > CM_IP_NUM) {
        return READ_FILE_ERROR;
    }
    for (int nn = 0; nn < CM_IP_NUM; nn++) {
        FREAD1(g_node[nodeId].datanode[dnId].datanodeLocalHAIP[nn], 1, CM_IP_LENGTH, fd);
        g_node[nodeId].datanode[dnId].datanodeLocalHAIP[nn][CM_IP_LENGTH - 1] = '\0';
        check_input_for_security(g_node[nodeId].datanode[dnId].datanodeLocalHAIP[nn]);
    }
    FREAD1(&g_node[nodeId].datanode[dnId].datanodeLocalHAPort, 1, sizeof(uint32), fd);

    return 0;
}

static int ReadNodeOneDnPeerDataNode(FILE *fd, uint32 nodeId, uint32 dnId)
{
    for (uint32 peerdnId = 0; peerdnId < CM_MAX_DATANODE_STANDBY_NUM; peerdnId++) {
        FREAD1(g_node[nodeId].datanode[dnId].peerDatanodes[peerdnId].datanodePeerDataPath, 1, CM_PATH_LENGTH, fd);
        g_node[nodeId].datanode[dnId].peerDatanodes[peerdnId].datanodePeerDataPath[CM_PATH_LENGTH - 1] = '\0';
        check_input_for_security(g_node[nodeId].datanode[dnId].peerDatanodes[peerdnId].datanodePeerDataPath);

        FREAD1(&g_node[nodeId].datanode[dnId].peerDatanodes[peerdnId].datanodePeerHAListenCount, 1, sizeof(uint32), fd);
        if (g_node[nodeId].datanode[dnId].peerDatanodes[peerdnId].datanodePeerHAListenCount > CM_IP_NUM) {
            return READ_FILE_ERROR;
        }
        for (int nn = 0; nn < CM_IP_NUM; nn++) {
            FREAD1(g_node[nodeId].datanode[dnId].peerDatanodes[peerdnId].datanodePeerHAIP[nn], 1, CM_IP_LENGTH, fd);
            g_node[nodeId].datanode[dnId].peerDatanodes[peerdnId].datanodePeerHAIP[nn][CM_IP_LENGTH - 1] = '\0';
            check_input_for_security(g_node[nodeId].datanode[dnId].peerDatanodes[peerdnId].datanodePeerHAIP[nn]);
        }
        FREAD1(&g_node[nodeId].datanode[dnId].peerDatanodes[peerdnId].datanodePeerHAPort, 1, sizeof(uint32), fd);
        FREAD1(&g_node[nodeId].datanode[dnId].peerDatanodes[peerdnId].datanodePeerRole, 1, sizeof(uint32), fd);
    }

    return 0;
}

static int ReadNodeOneDnPeerDataNode1(FILE *fd, uint32 nodeId, uint32 dnId)
{
    /* former cluster: single primary, single standby and single dummy standby */
    FREAD1(g_node[nodeId].datanode[dnId].datanodePeerDataPath, 1, CM_PATH_LENGTH, fd);
    g_node[nodeId].datanode[dnId].datanodePeerDataPath[CM_PATH_LENGTH - 1] = '\0';
    check_input_for_security(g_node[nodeId].datanode[dnId].datanodePeerDataPath);

    FREAD1(&g_node[nodeId].datanode[dnId].datanodePeerHAListenCount, 1, sizeof(uint32), fd);
    if (g_node[nodeId].datanode[dnId].datanodePeerHAListenCount > CM_IP_NUM) {
        return READ_FILE_ERROR;
    }
    for (int nn = 0; nn < CM_IP_NUM; nn++) {
        FREAD1(g_node[nodeId].datanode[dnId].datanodePeerHAIP[nn], 1, CM_IP_LENGTH, fd);
        g_node[nodeId].datanode[dnId].datanodePeerHAIP[nn][CM_IP_LENGTH - 1] = '\0';
        check_input_for_security(g_node[nodeId].datanode[dnId].datanodePeerHAIP[nn]);
    }
    FREAD1(&g_node[nodeId].datanode[dnId].datanodePeerHAPort, 1, sizeof(uint32), fd);
    FREAD1(&g_node[nodeId].datanode[dnId].datanodePeerRole, 1, sizeof(uint32), fd);
    FREAD1(g_node[nodeId].datanode[dnId].datanodePeer2DataPath, 1, CM_PATH_LENGTH, fd);
    g_node[nodeId].datanode[dnId].datanodePeer2DataPath[CM_PATH_LENGTH - 1] = '\0';
    check_input_for_security(g_node[nodeId].datanode[dnId].datanodePeer2DataPath);

    FREAD1(&g_node[nodeId].datanode[dnId].datanodePeer2HAListenCount, 1, sizeof(uint32), fd);
    if (g_node[nodeId].datanode[dnId].datanodePeer2HAListenCount > CM_IP_NUM) {
        return READ_FILE_ERROR;
    }
    for (int nn = 0; nn < CM_IP_NUM; nn++) {
        FREAD1(g_node[nodeId].datanode[dnId].datanodePeer2HAIP[nn], 1, CM_IP_LENGTH, fd);
        g_node[nodeId].datanode[dnId].datanodePeer2HAIP[nn][CM_IP_LENGTH - 1] = '\0';
        check_input_for_security(g_node[nodeId].datanode[dnId].datanodePeer2HAIP[nn]);
    }
    FREAD1(&g_node[nodeId].datanode[dnId].datanodePeer2HAPort, 1, sizeof(uint32), fd);
    FREAD1(&g_node[nodeId].datanode[dnId].datanodePeer2Role, 1, sizeof(uint32), fd);
    return 0;
}

static int ReadNodeOneDn(FILE *fd, uint32 nodeId, uint32 dnId, ReadConfigContext *ctx)
{
    /* calculate datanode group number */
    if (g_node[nodeId].datanode[dnId].datanodeRole == PRIMARY_DN) {
        g_cluster_total_instance_group_num++;
    }

    FREAD1(&g_node[nodeId].datanode[dnId].datanodeId, 1, sizeof(uint32), fd);
    FREAD1(&g_node[nodeId].datanode[dnId].datanodeMirrorId, 1, sizeof(uint32), fd);
    if (!ctx->datanodeMirrorIDInit) {
        ctx->datanodeMirrorIDInit = true;
        ctx->datanodeMirrorID = g_node[nodeId].datanode[dnId].datanodeMirrorId;
        ctx->dnReplicationNum++;
    } else if (ctx->datanodeMirrorID == g_node[nodeId].datanode[dnId].datanodeMirrorId) {
        ctx->dnReplicationNum++;
    }
    FREAD1(g_node[nodeId].datanode[dnId].datanodeLocalDataPath, 1, CM_PATH_LENGTH, fd);
    g_node[nodeId].datanode[dnId].datanodeLocalDataPath[CM_PATH_LENGTH - 1] = '\0';
    check_input_for_security(g_node[nodeId].datanode[dnId].datanodeLocalDataPath);

    FREAD1(g_node[nodeId].datanode[dnId].datanodeXlogPath, 1, CM_PATH_LENGTH, fd);
    g_node[nodeId].datanode[dnId].datanodeXlogPath[CM_PATH_LENGTH - 1] = '\0';
    check_input_for_security(g_node[nodeId].datanode[dnId].datanodeXlogPath);

    FREAD1(g_node[nodeId].datanode[dnId].datanodeSSDDataPath, 1, CM_PATH_LENGTH, fd);
    g_node[nodeId].datanode[dnId].datanodeSSDDataPath[CM_PATH_LENGTH - 1] = '\0';
    check_input_for_security(g_node[nodeId].datanode[dnId].datanodeSSDDataPath);

    max_datapath_len = (max_datapath_len < (uint32)strlen(g_node[nodeId].datanode[dnId].datanodeLocalDataPath)) ?
        (uint32)strlen(g_node[nodeId].datanode[dnId].datanodeLocalDataPath) : max_datapath_len;

    int32 ret = ReadNodeOneDnListenIp(fd, nodeId, dnId);
    RETURN_IFERR(ret);

    FREAD1(&g_node[nodeId].datanode[dnId].datanodePort, 1, sizeof(uint32), fd);
    FREAD1(&g_node[nodeId].datanode[dnId].datanodeRole, 1, sizeof(uint32), fd);

    ret = ReadNodeOneDnListenHaip(fd, nodeId, dnId);
    RETURN_IFERR(ret);

    if (g_clusterType >= SinglePrimaryMultiStandbyCluster && g_clusterType <= V3SingleInstCluster) {
        ret = ReadNodeOneDnPeerDataNode(fd, nodeId, dnId);
        RETURN_IFERR(ret);
    } else {
        ret = ReadNodeOneDnPeerDataNode1(fd, nodeId, dnId);
        RETURN_IFERR(ret);
    }

    return 0;
}

static int ReadNodeAllDn(FILE *fd, uint32 nodeId, ReadConfigContext *ctx)
{
    int ret = 0;
    /* read DNs info */
    FREAD1(&g_node[nodeId].datanodeCount, 1, sizeof(uint32), fd);
    /* check datacodeCount not overflow */
    if (g_node[nodeId].datanodeCount > CM_MAX_DATANODE_PER_NODE) {
        return READ_FILE_ERROR;
    }
    for (uint32 dnId = 0; dnId < g_node[nodeId].datanodeCount; dnId++) {
        ret = ReadNodeOneDn(fd, nodeId, dnId, ctx);
        RETURN_IFERR(ret);
    }

    return 0;
}

static int ReadNodeEtcd(FILE *fd, uint32 nodeId, ReadConfigContext *ctx)
{
    FREAD1(&g_node[nodeId].etcd, 1, sizeof(uint32), fd);
    if (g_node[nodeId].etcd == 1) {
        ctx->etcdNum++;
    }

    FREAD1(&g_node[nodeId].etcdId, 1, sizeof(uint32), fd);
    FREAD1(&g_node[nodeId].etcdMirrorId, 1, sizeof(uint32), fd);
    FREAD1(g_node[nodeId].etcdName, 1, (CM_NODE_NAME - 1), fd);
    g_node[nodeId].etcdName[CM_NODE_NAME - 1] = '\0';
    check_input_for_security(g_node[nodeId].etcdName);
    FREAD1(g_node[nodeId].etcdDataPath, 1, CM_PATH_LENGTH, fd);
    g_node[nodeId].etcdDataPath[CM_PATH_LENGTH - 1] = '\0';
    check_input_for_security(g_node[nodeId].etcdDataPath);

    max_etcdpath_len = (max_etcdpath_len < (uint32)strlen(g_node[nodeId].etcdDataPath)) ?
        (uint32)strlen(g_node[nodeId].etcdDataPath) : max_etcdpath_len;

    FREAD1(&g_node[nodeId].etcdClientListenIPCount, 1, sizeof(uint32), fd);
    if (g_node[nodeId].etcdClientListenIPCount > CM_IP_NUM) {
        return READ_FILE_ERROR;
    }
    for (int kk = 0; kk < CM_IP_NUM; kk++) {
        FREAD1(g_node[nodeId].etcdClientListenIPs[kk], 1, CM_IP_LENGTH, fd);
        g_node[nodeId].etcdClientListenIPs[kk][CM_IP_LENGTH - 1] = '\0';
        check_input_for_security(g_node[nodeId].etcdClientListenIPs[kk]);
    }
    FREAD1(&g_node[nodeId].etcdClientListenPort, 1, sizeof(uint32), fd);
    FREAD1(&g_node[nodeId].etcdHAListenIPCount, 1, sizeof(uint32), fd);
    if (g_node[nodeId].etcdHAListenIPCount > CM_IP_NUM) {
        return READ_FILE_ERROR;
    }
    for (int kk = 0; kk < CM_IP_NUM; kk++) {
        FREAD1(g_node[nodeId].etcdHAListenIPs[kk], 1, CM_IP_LENGTH, fd);
        g_node[nodeId].etcdHAListenIPs[kk][CM_IP_LENGTH - 1] = '\0';
        check_input_for_security(g_node[nodeId].etcdHAListenIPs[kk]);
    }
    FREAD1(&g_node[nodeId].etcdHAListenPort, 1, sizeof(uint32), fd);

    return 0;
}

static int ReadOneNode(FILE *fd, uint32 nodeId, ReadConfigContext *ctx)
{
    int ret = ReadNodeInfo(fd, nodeId);
    RETURN_IFERR(ret);

    ret = ReadNodeBackIp(fd, nodeId);
    RETURN_IFERR(ret);

    ret = ReadNodeSsh(fd, nodeId);
    RETURN_IFERR(ret);

    ret = ReadNodeCmserver(fd, nodeId, ctx);
    RETURN_IFERR(ret);

    ret = ReadNodeGtm(fd, nodeId, ctx);
    RETURN_IFERR(ret);

    ret = ReadNodeCn(fd, nodeId);
    RETURN_IFERR(ret);

    /* calculate coordinate group number */
    if (g_node[nodeId].coordinate == 1) {
        ctx->cnNum++;
        g_cluster_total_instance_group_num++;
    }

    ret = ReadNodeAllDn(fd, nodeId, ctx);
    RETURN_IFERR(ret);

    ret = ReadNodeEtcd(fd, nodeId, ctx);
    RETURN_IFERR(ret);

    FREAD1(&g_node[nodeId].sctpBeginPort, 1, sizeof(uint32), fd);
    FREAD1(&g_node[nodeId].sctpEndPort, 1, sizeof(uint32), fd);

    return 0;
}

static int ReadAllNodes(FILE *fd, ReadConfigContext *ctx)
{
    int ret = 0;
    uint32 header_size = sizeof(staticConfigHeader);
    uint32 header_aglinment_size =
        (header_size / AGLINMENT_SIZE + ((header_size % AGLINMENT_SIZE) == 0 ? 0 : 1)) * AGLINMENT_SIZE;

    if (fseek(fd, (off_t)(header_aglinment_size), SEEK_SET) != 0) {
        return READ_FILE_ERROR;
    }

    for (uint32 nodeId = 0; nodeId < g_nodeHeader.nodeCount; nodeId++) {
        ret = ReadOneNode(fd, nodeId, ctx);
        RETURN_IFERR(ret);

        long current_pos = ftell(fd);
        if (current_pos == -1L) {
            return READ_FILE_ERROR;
        }

        long body_aglinment_size =
            (current_pos / AGLINMENT_SIZE + ((current_pos % AGLINMENT_SIZE == 0) ? 0 : 1)) * AGLINMENT_SIZE;

        if (fseek(fd, (off_t)body_aglinment_size, SEEK_SET)) {
            return READ_FILE_ERROR;
        }
    }

    return ret;
}

static int ReadConfigContent(FILE *fd, bool inReload, ReadConfigContext *ctx)
{
    int ret = read_config_header(fd);
    RETURN_IFERR(ret);

    ret = alloc_node_buffer(inReload);
    RETURN_IFERR(ret);

    ret = ReadAllNodes(fd, ctx);
    RETURN_IFERR(ret);

    return ret;
}

int read_config_file(const char *file_path, int *err_no, bool inReload)
{
    ReadConfigContext ctx;
    ctx.datanodeMirrorIDInit = false;
    ctx.datanodeMirrorID = 0;
    ctx.cmServerNum = 0;
    ctx.gtmNum = 0;
    ctx.dnReplicationNum = 0;
    ctx.etcdNum = 0;
    ctx.cnNum = 0;

    FILE *fd = open_config_file(file_path, err_no);
    if (fd == NULL) {
        return OPEN_FILE_ERROR;
    }

    int32 rcs = ReadConfigContent(fd, inReload, &ctx);
    if (rcs != 0) {
        (void)fclose(fd);
        fd = NULL;
        *err_no = errno;
        if (inReload) {
            return rcs;
        }
        if (g_node != NULL) {
            free(g_node);
            g_node = NULL;
        }
        /* test only dn cluster */
        g_multi_az_cluster = false;
        g_one_master_multi_slave = false;
        return rcs;
    }

    g_node_num = g_nodeHeader.nodeCount;
    g_cm_server_num = ctx.cmServerNum;
    g_gtm_num = ctx.gtmNum;
    g_dn_replication_num = ctx.dnReplicationNum;
    g_etcd_num = ctx.etcdNum;
    g_coordinator_num = ctx.cnNum;
    setAZPriority();
    (void)fclose(fd);
    fd = 0;

    return 0;
}

void set_para_for_cm_read(const logicClusterList lcList)
{
    const char *lcName = NULL;

    max_logic_cluster_name_len = 0;
    int rcs = memset_s(g_logicClusterStaticConfig,
        sizeof(logicClusterStaticConfig) * LOGIC_CLUSTER_NUMBER,
        0,
        sizeof(logicClusterStaticConfig) * LOGIC_CLUSTER_NUMBER);
    securec_check_c(rcs, "", "");

    g_logic_cluster_count = lcList.logicClusterCount;
    for (uint32 i = 0; i < g_logic_cluster_count; ++i) {
        lcName = lcList.lcInfoArray[i].logicClusterName;
        rcs = strcpy_s(g_logicClusterStaticConfig[i].LogicClusterName, CM_LOGIC_CLUSTER_NAME_LEN, lcName);
        securec_check_c(rcs, "", "");
        if (strlen(lcName) > max_logic_cluster_name_len) {
            max_logic_cluster_name_len = (uint32)strlen(lcName);
        }
    }
}

int read_logic_cluster_config_files(const char *file_path, int *err_no)
{
    logicClusterList lcList;
    int rcs = memset_s(&lcList, sizeof(logicClusterList), 0, sizeof(logicClusterList));
    securec_check_c(rcs, "", "");

    /* g_node not null means cm read */
    if (g_node != NULL) {
        g_isCmRead = true;
    }

    int32 status = read_logic_cluster_name(file_path, lcList, err_no);
    if (status == 0) {
        status = read_all_logic_config_file(lcList, err_no);
    }

    return status;
}

int read_lc_config_file(const char *file_path, int *err_no)
{
    uint32 ii = 0;
    long current_pos = 0;

    uint32 header_size = sizeof(staticConfigHeader);
    uint32 header_aglinment_size =
        (header_size / AGLINMENT_SIZE + ((header_size % AGLINMENT_SIZE) == 0 ? 0 : 1)) * AGLINMENT_SIZE;

    FILE *fd = fopen(file_path, "r");
    if (fd == NULL) {
        *err_no = errno;
        return OPEN_FILE_ERROR;
    }

    /********************************************************************************
     *  DISCLAIMER: Any Change in file format need to update the Version Number      *
     *              Version Number Offset should not be changed                      *
     ********************************************************************************/
    // read head info
    FREAD(&g_nodeHeader.crc, 1, sizeof(uint32), fd);
    FREAD(&g_nodeHeader.len, 1, sizeof(uint32), fd);
    FREAD(&g_nodeHeader.version, 1, sizeof(uint32), fd);
    FREAD(&g_nodeHeader.time, 1, sizeof(int64), fd);
    FREAD(&g_nodeHeader.nodeCount, 1, sizeof(uint32), fd);
    FREAD(&g_nodeHeader.node, 1, sizeof(uint32), fd);

    if (fseek(fd, (off_t)(header_aglinment_size), SEEK_SET) != 0) {
        goto read_failed;
    }

    /* The cluster must be primary_standby_salve */
    g_node_num = g_nodeHeader.nodeCount;
    if (g_node_num > CM_NODE_MAXNUM) {
        (void)fclose(fd);
        return READ_FILE_ERROR;
    }

    if (g_node == NULL) {
        g_node = (staticNodeConfig *)malloc(sizeof(staticNodeConfig) * g_node_num);
        if (g_node == NULL) {
            (void)fclose(fd);
            return OUT_OF_MEMORY;
        }
    }

    for (ii = 0; ii < g_node_num; ii++) {
        uint32 jj = 0;
        uint32 kk = 0;
        long body_aglinment_size = 0;

        /* read node info */
        FREAD(&g_node[ii].crc, 1, sizeof(uint32), fd);
        FREAD(&g_node[ii].node, 1, sizeof(uint32), fd);
        FREAD(g_node[ii].nodeName, 1, (CM_NODE_NAME - 1), fd);
        g_node[ii].nodeName[CM_NODE_NAME - 1] = '\0';
        check_input_for_security(g_node[ii].nodeName);

        max_node_name_len =
            (max_node_name_len < strlen(g_node[ii].nodeName)) ? (uint32)strlen(g_node[ii].nodeName) : max_node_name_len;

        FREAD(&g_node[ii].backIpCount, 1, sizeof(uint32), fd);
        if (g_node[ii].backIpCount > CM_IP_NUM) {
            goto read_failed;
        }
        for (jj = 0; jj < CM_IP_NUM; jj++) {
            FREAD(g_node[ii].backIps[jj], 1, CM_IP_LENGTH, fd);
            g_node[ii].backIps[jj][CM_IP_LENGTH - 1] = '\0';
            check_input_for_security(g_node[ii].backIps[jj]);
        }
        FREAD(&g_node[ii].sshCount, 1, sizeof(uint32), fd);
        if (g_node[ii].sshCount > CM_IP_NUM) {
            goto read_failed;
        }
        for (jj = 0; jj < CM_IP_NUM; jj++) {
            FREAD(g_node[ii].sshChannel[jj], 1, CM_IP_LENGTH, fd);
            g_node[ii].sshChannel[jj][CM_IP_LENGTH - 1] = '\0';
            check_input_for_security(g_node[ii].sshChannel[jj]);
        }

        /* read DNs info */
        FREAD(&g_node[ii].datanodeCount, 1, sizeof(uint32), fd);

        if (g_node[ii].datanodeCount > CM_MAX_DATANODE_PER_NODE) {
            goto read_failed;
        }

        for (kk = 0; kk < g_node[ii].datanodeCount; kk++) {
            uint32 nn = 0;

            FREAD(&g_node[ii].datanode[kk].datanodeId, 1, sizeof(uint32), fd);
            FREAD(&g_node[ii].datanode[kk].datanodeMirrorId, 1, sizeof(uint32), fd);
            FREAD(g_node[ii].datanode[kk].datanodeLocalDataPath, 1, CM_PATH_LENGTH, fd);
            g_node[ii].datanode[kk].datanodeLocalDataPath[CM_PATH_LENGTH - 1] = '\0';
            check_input_for_security(g_node[ii].datanode[kk].datanodeLocalDataPath);

            FREAD(g_node[ii].datanode[kk].datanodeSSDDataPath, 1, CM_PATH_LENGTH, fd);
            g_node[ii].datanode[kk].datanodeSSDDataPath[CM_PATH_LENGTH - 1] = '\0';
            check_input_for_security(g_node[ii].datanode[kk].datanodeSSDDataPath);

            max_datapath_len = (max_datapath_len < strlen(g_node[ii].datanode[kk].datanodeLocalDataPath))
                                   ? (uint32)strlen(g_node[ii].datanode[kk].datanodeLocalDataPath)
                                   : max_datapath_len;

            FREAD(&g_node[ii].datanode[kk].datanodeListenCount, 1, sizeof(uint32), fd);
            if (g_node[ii].datanode[kk].datanodeListenCount > CM_IP_NUM) {
                goto read_failed;
            }
            for (nn = 0; nn < CM_IP_NUM; nn++) {
                FREAD(g_node[ii].datanode[kk].datanodeListenIP[nn], 1, CM_IP_LENGTH, fd);
                g_node[ii].datanode[kk].datanodeListenIP[nn][CM_IP_LENGTH - 1] = '\0';
                check_input_for_security(g_node[ii].datanode[kk].datanodeListenIP[nn]);
            }
            FREAD(&g_node[ii].datanode[kk].datanodePort, 1, sizeof(uint32), fd);
            FREAD(&g_node[ii].datanode[kk].datanodeRole, 1, sizeof(uint32), fd);
            FREAD(&g_node[ii].datanode[kk].datanodeLocalHAListenCount, 1, sizeof(uint32), fd);
            if (g_node[ii].datanode[kk].datanodeLocalHAListenCount > CM_IP_NUM) {
                goto read_failed;
            }
            for (nn = 0; nn < CM_IP_NUM; nn++) {
                FREAD(g_node[ii].datanode[kk].datanodeLocalHAIP[nn], 1, CM_IP_LENGTH, fd);
                g_node[ii].datanode[kk].datanodeLocalHAIP[nn][CM_IP_LENGTH - 1] = '\0';
                check_input_for_security(g_node[ii].datanode[kk].datanodeLocalHAIP[nn]);
            }
            FREAD(&g_node[ii].datanode[kk].datanodeLocalHAPort, 1, sizeof(uint32), fd);
            FREAD(g_node[ii].datanode[kk].datanodePeerDataPath, 1, CM_PATH_LENGTH, fd);
            g_node[ii].datanode[kk].datanodePeerDataPath[CM_PATH_LENGTH - 1] = '\0';
            check_input_for_security(g_node[ii].datanode[kk].datanodePeerDataPath);

            FREAD(&g_node[ii].datanode[kk].datanodePeerHAListenCount, 1, sizeof(uint32), fd);
            if (g_node[ii].datanode[kk].datanodePeerHAListenCount > CM_IP_NUM) {
                goto read_failed;
            }
            for (nn = 0; nn < CM_IP_NUM; nn++) {
                FREAD(g_node[ii].datanode[kk].datanodePeerHAIP[nn], 1, CM_IP_LENGTH, fd);
                g_node[ii].datanode[kk].datanodePeerHAIP[nn][CM_IP_LENGTH - 1] = '\0';
                check_input_for_security(g_node[ii].datanode[kk].datanodePeerHAIP[nn]);
            }
            FREAD(&g_node[ii].datanode[kk].datanodePeerHAPort, 1, sizeof(uint32), fd);
            FREAD(&g_node[ii].datanode[kk].datanodeRole, 1, sizeof(uint32), fd);
            FREAD(g_node[ii].datanode[kk].datanodePeer2DataPath, 1, CM_PATH_LENGTH, fd);
            g_node[ii].datanode[kk].datanodePeer2DataPath[CM_PATH_LENGTH - 1] = '\0';
            check_input_for_security(g_node[ii].datanode[kk].datanodePeer2DataPath);

            FREAD(&g_node[ii].datanode[kk].datanodePeer2HAListenCount, 1, sizeof(uint32), fd);
            if (g_node[ii].datanode[kk].datanodePeer2HAListenCount > CM_IP_NUM) {
                goto read_failed;
            }
            for (nn = 0; nn < CM_IP_NUM; nn++) {
                FREAD(g_node[ii].datanode[kk].datanodePeer2HAIP[nn], 1, CM_IP_LENGTH, fd);
                g_node[ii].datanode[kk].datanodePeer2HAIP[nn][CM_IP_LENGTH - 1] = '\0';
                check_input_for_security(g_node[ii].datanode[kk].datanodePeer2HAIP[nn]);
            }
            FREAD(&g_node[ii].datanode[kk].datanodePeer2HAPort, 1, sizeof(uint32), fd);
            FREAD(&g_node[ii].datanode[kk].datanodePeer2Role, 1, sizeof(uint32), fd);
        }

        FREAD(&g_node[ii].sctpBeginPort, 1, sizeof(uint32), fd);
        FREAD(&g_node[ii].sctpEndPort, 1, sizeof(uint32), fd);

        current_pos = ftell(fd);
        if (current_pos == -1L) {
            goto read_failed;
        }
        body_aglinment_size =
            (current_pos / AGLINMENT_SIZE + ((current_pos % AGLINMENT_SIZE == 0) ? 0 : 1)) * AGLINMENT_SIZE;

        if (fseek(fd, (off_t)body_aglinment_size, SEEK_SET)) {
            goto read_failed;
        }
    }

    (void)fclose(fd);
    return 0;
read_failed:
    if (g_node != NULL) {
        free(g_node);
        g_node = NULL;
    }
    (void)fclose(fd);
    g_node_num = 0;
    *err_no = errno;
    return READ_FILE_ERROR;
}

/* g_isCmRead means whether need save data in global var */
void set_cm_read_flag(bool falg)
{
    g_isCmRead = falg;
}

/* read the logic_cluster_name.txt file */
int read_logic_cluster_name(const char *file_path, logicClusterList &lcList, int *err_no)
{
    uint32 logic_cluster_Index = 0;

    FILE *fd = fopen(file_path, "r");
    if (fd == NULL) {
        *err_no = errno;
        return OPEN_FILE_ERROR;
    }

    while (logic_cluster_Index < LOGIC_CLUSTER_NUMBER && !feof(fd)) {
        if (fscanf_s(fd, "%s\n", lcList.lcInfoArray[logic_cluster_Index].logicClusterName, CM_LOGIC_CLUSTER_NAME_LEN) <
            0) {
            (void)fclose(fd);
            *err_no = errno;
            return READ_FILE_ERROR;
        }
        if (strlen(lcList.lcInfoArray[logic_cluster_Index].logicClusterName) != 0) {
            lcList.lcInfoArray[logic_cluster_Index].logicClusterId = logic_cluster_Index;
            logic_cluster_Index++;
        }
    }
    lcList.logicClusterCount = logic_cluster_Index;
    if (g_isCmRead) {
        set_para_for_cm_read(lcList);
    }
    (void)fclose(fd);
    return 0;
}

static int read_all_logic_config_file(const logicClusterList lcList, int *err_no)
{
    int status = 0;

    for (uint32 logic_cluster_index = 0; logic_cluster_index < lcList.logicClusterCount; logic_cluster_index++) {
        status = read_logic_config_file(lcList.lcInfoArray[logic_cluster_index], err_no);
        /* means has found dn's logicCluster */
        if (!g_isCmRead && g_logicClusterName[0] != '\0') {
            return 0;
        }
        if (status == 0 && g_logicClusterStaticConfig[logic_cluster_index].logicClusterNodeHeader.node == 0) {
            *err_no = errno;
            return READ_FILE_ERROR;
        } else if (status != 0) {
            return status;
        }
    }
    return 0;
}

static FILE *OpenLogicConfigFile(const char *logicClusterName, int *err_no)
{
    char file_path[MAX_PATH_LEN] = {0};
    char exec_path[MAX_PATH_LEN] = {0};

    int rcs = cmconfig_getenv("GAUSSHOME", exec_path, sizeof(exec_path));
    if (rcs != EOK) {
        (void)fprintf(stderr, "Get GAUSSHOME failed, please check.\n");
        return NULL;
    } else {
        errno_t rc = snprintf_s(file_path,
            MAX_PATH_LEN,
            MAX_PATH_LEN - 1,
            "%s/bin/%s.cluster_static_config",
            exec_path,
            logicClusterName);
        securec_check_ss_c(rc, "", "");
    }
    canonicalize_path(file_path);

    FILE *fd = fopen(file_path, "r");
    if (fd == NULL) {
        *err_no = errno;
        return NULL;
    }

    return fd;
}

static int read_logic_config_file(const logicClusterInfo lcInfo, int *err_no)
{
    int rcs = 0;
    uint32 ii = 0;
    uint32 header_size = 0;
    uint32 node_index = 0;
    uint32 logicClusterNodeNum = 0;
    uint32 header_aglinment_size = 0;
    long current_pos = 0;
    uint32 datanodeCount = 0;
    uint32 datanodeId = 0;

    errno_t rc = 0;

    logicClusterStaticConfig *LCStaticConfig = &g_logicClusterStaticConfig[lcInfo.logicClusterId];

    FILE *fd = OpenLogicConfigFile(lcInfo.logicClusterName, err_no);
    if (fd == NULL) {
        return OPEN_FILE_ERROR;
    }

    /********************************************************************************
     *  DISCLAIMER: Any Change in file format need to update the Version Number      *
     *              Version Number Offset should not be changed                      *
     ********************************************************************************/
    // read head info
    FREAD(&LCStaticConfig->logicClusterNodeHeader.crc, 1, sizeof(uint32), fd);
    FREAD(&LCStaticConfig->logicClusterNodeHeader.len, 1, sizeof(uint32), fd);
    FREAD(&LCStaticConfig->logicClusterNodeHeader.version, 1, sizeof(uint32), fd);
    FREAD(&LCStaticConfig->logicClusterNodeHeader.time, 1, sizeof(int64), fd);
    FREAD(&LCStaticConfig->logicClusterNodeHeader.nodeCount, 1, sizeof(uint32), fd);
    FREAD(&LCStaticConfig->logicClusterNodeHeader.node, 1, sizeof(uint32), fd);

    header_size = sizeof(staticConfigHeader);
    header_aglinment_size =
        (header_size / AGLINMENT_SIZE + ((header_size % AGLINMENT_SIZE) == 0 ? 0 : 1)) * AGLINMENT_SIZE;
    if (fseek(fd, (off_t)(header_aglinment_size), SEEK_SET) != 0) {
        READ_LOGICAL_CONFIG_FAILED(fd);
    }

    logicClusterNodeNum = LCStaticConfig->logicClusterNodeHeader.nodeCount;
    /*
     * Check whether the number of logic cluster nodes read from the configuration file is greater
     * than the maximum number limit of logic cluster nodes.
     */
    if (logicClusterNodeNum == 0 || logicClusterNodeNum > CM_NODE_MAXNUM) {
        (void)fprintf(stderr,
            "The logic cluster node number [count=%u] is greater than the max node number [max_num=%d].\n",
            logicClusterNodeNum,
            CM_NODE_MAXNUM);
        (void)fclose(fd);
        return -1;
    }

    if (g_isCmRead) {
        /* initialize logic cluster node ptr to reread the node info */
        if (LCStaticConfig->logicClusterNode != NULL) {
            free(LCStaticConfig->logicClusterNode);
            LCStaticConfig->logicClusterNode = NULL;
        }
        LCStaticConfig->logicClusterNode =
            (staticLogicNodeConfig *)malloc(sizeof(staticLogicNodeConfig) * logicClusterNodeNum);
        if (LCStaticConfig->logicClusterNode == NULL) {
            (void)fclose(fd);
            return OUT_OF_MEMORY;
        } else {
            rcs = memset_s(LCStaticConfig->logicClusterNode,
                sizeof(staticLogicNodeConfig) * logicClusterNodeNum,
                0,
                sizeof(staticLogicNodeConfig) * logicClusterNodeNum);
            securec_check_c(rcs, "", "");
        }
    }

    for (ii = 0; ii < logicClusterNodeNum; ii++) {
        uint32 jj = 0;
        uint32 kk = 0;
        long body_aglinment_size = 0;
        uint32 datanode_index = 0;

        /* read node header info */
        if (g_isCmRead) {
            FREAD(&LCStaticConfig->logicClusterNode[ii].crc, 1, sizeof(uint32), fd);
            FREAD(&LCStaticConfig->logicClusterNode[ii].node, 1, sizeof(uint32), fd);
            FREAD(LCStaticConfig->logicClusterNode[ii].nodeName, 1, (CM_NODE_NAME - 1), fd);
            LCStaticConfig->logicClusterNode[ii].nodeName[CM_NODE_NAME - 1] = '\0';
            check_input_for_security(LCStaticConfig->logicClusterNode[ii].nodeName);
            FREAD(&LCStaticConfig->logicClusterNode[ii].backIpCount, 1, sizeof(uint32), fd);
            if (LCStaticConfig->logicClusterNode[ii].backIpCount > CM_IP_NUM) {
                goto read_failed;
            }
            for (jj = 0; jj < CM_IP_NUM; jj++) {
                FREAD(LCStaticConfig->logicClusterNode[ii].backIps[jj], 1, CM_IP_LENGTH, fd);
                LCStaticConfig->logicClusterNode[ii].backIps[jj][CM_IP_LENGTH - 1] = '\0';
                check_input_for_security(LCStaticConfig->logicClusterNode[ii].backIps[jj]);
            }
            FREAD(&LCStaticConfig->logicClusterNode[ii].sshCount, 1, sizeof(uint32), fd);
            if (LCStaticConfig->logicClusterNode[ii].sshCount > CM_IP_NUM) {
                goto read_failed;
            }
            for (jj = 0; jj < CM_IP_NUM; jj++) {
                FREAD(LCStaticConfig->logicClusterNode[ii].sshChannel[jj], 1, CM_IP_LENGTH, fd);
                LCStaticConfig->logicClusterNode[ii].sshChannel[jj][CM_IP_LENGTH - 1] = '\0';
                check_input_for_security(LCStaticConfig->logicClusterNode[ii].sshChannel[jj]);
            }

            /* find the correspond node in g_node */
            for (node_index = 0; node_index < g_nodeHeader.nodeCount; node_index++) {
                if (g_node[node_index].node == LCStaticConfig->logicClusterNode[ii].node) {
                    break;
                }
            }
        } else {
            /* seek to datanodeInfo */
            current_pos = ftell(fd);
            long node_head_size = (long)sizeof(uint32) * 4 + (CM_NODE_NAME - 1) + (CM_IP_NUM * CM_IP_LENGTH * 2);
            body_aglinment_size = current_pos + node_head_size;
            if (fseek(fd, (off_t)body_aglinment_size, SEEK_SET)) {
                READ_LOGICAL_CONFIG_FAILED(fd);
            }
        }

        /* read DNs info, the datanodeCount is the num of datanode in logic cluster */
        FREAD(&datanodeCount, 1, sizeof(uint32), fd);
        /*
         * Check whether the number of data nodes read from the configuration file is greater
         * than the maximum data node limit of a single node.
         */
        if (datanodeCount > CM_MAX_DATANODE_PER_NODE) {
            (void)fprintf(stderr,
                "The logic cluster data node number [count=%u] is greater than the max data node number per node "
                "[max_num=%d].\n",
                datanodeCount,
                CM_MAX_DATANODE_PER_NODE);
            (void)fclose(fd);
            return -1;
        }

        if (g_isCmRead) {
            LCStaticConfig->logicClusterNode[ii].datanodeCount = datanodeCount;
        }
        for (kk = 0; kk < datanodeCount; kk++) {
            FREAD(&datanodeId, 1, sizeof(uint32), fd);

            if (g_isCmRead) {
                LCStaticConfig->logicClusterNode[ii].datanodeId[kk] = datanodeId;
                /* Traverse all nodes and find the corresponding datanodeid and assignment for LogicClusterName */
                for (datanode_index = 0; datanode_index < g_node[node_index].datanodeCount; datanode_index++) {
                    if (g_node[node_index].datanode[datanode_index].datanodeId ==
                        LCStaticConfig->logicClusterNode[ii].datanodeId[kk]) {
                        rc = strcpy_s(g_node[node_index].datanode[datanode_index].LogicClusterName,
                            CM_LOGIC_CLUSTER_NAME_LEN,
                            g_logicClusterStaticConfig[lcInfo.logicClusterId].LogicClusterName);
                        securec_check_c(rc, "", "");
                        break;
                    }
                }
            } else if (datanodeId == g_datanodeid) {
                rc = strcpy_s(g_logicClusterName, CM_LOGIC_CLUSTER_NAME_LEN, lcInfo.logicClusterName);
                securec_check_c(rc, "", "");
                (void)fclose(fd);
                return 0;
            }

            /* seek to next datanode */
            current_pos = ftell(fd);
            body_aglinment_size = current_pos + (long)sizeof(dataNodeInfo) - (long)sizeof(uint32) -
                                  (long)sizeof(peerDatanodeInfo) * CM_MAX_DATANODE_STANDBY_NUM -
                                  CM_LOGIC_CLUSTER_NAME_LEN;
            if (fseek(fd, (off_t)body_aglinment_size, SEEK_SET)) {
                READ_LOGICAL_CONFIG_FAILED(fd);
            }
        }

        /* seek to next node */
        current_pos = ftell(fd) + (long)(sizeof(uint32) * 2);
        body_aglinment_size =
            (current_pos / AGLINMENT_SIZE + ((current_pos % AGLINMENT_SIZE == 0) ? 0 : 1)) * AGLINMENT_SIZE;
        if (fseek(fd, (off_t)body_aglinment_size, SEEK_SET)) {
            READ_LOGICAL_CONFIG_FAILED(fd);
        }
    }
    /* means not found dn's logicCluster */
    if (!g_isCmRead) {
        g_logicClusterName[0] = '\0';
    }

    (void)fclose(fd);
    return 0;

read_failed:
    READ_LOGICAL_CONFIG_FAILED(fd);
}

char *getAZNamebyPriority(uint32 azPriority)
{
    for (uint32 i = 0; i < g_node_num; i++) {
        if (azPriority == g_node[i].azPriority) {
            return g_node[i].azName;
        }
    }

    return NULL;
}

bool read_single_file_local(uint32 node_index)
{
    int ret = 0;
    bool find = false;
    bool isLocal = false;
    for (uint32 i = 0; i < g_node_num; i++) {
        find = false;
        if (node_index >= CM_MAX_DATANODE_PER_NODE) {
            break;
        }
        for (uint32 j = 0; j < g_node[i].datanodeCount; j++) {
            if (strcmp(g_node[node_index].datanode[node_index].datanodeLocalDataPath,
                g_node[i].datanode[j].datanodeLocalDataPath) == 0) {
                if (g_nodeHeader.node == g_node[i].node) {
                    isLocal = true;
                }
                find = true;
                g_node[i].datanodeCount = 1;
                if (j > 0) {
                    ret = memcpy_s((void *)(&(g_node[i].datanode[0])),
                        sizeof(dataNodeInfo),
                        (void *)(&(g_node[i].datanode[j])),
                        sizeof(dataNodeInfo));
                    securec_check_c(ret, "", "");
                }
            }
            for (uint32 m = 0; (m < g_dn_replication_num - 1) && !find; m++) {
                if (m >= CM_MAX_DATANODE_STANDBY_NUM) {
                    break;
                }

                if (strcmp(g_node[node_index].datanode[node_index].peerDatanodes[m].datanodePeerDataPath,
                    g_node[i].datanode[j].datanodeLocalDataPath) == 0 &&
                    strcmp(g_node[node_index].datanode[node_index].peerDatanodes[m].datanodePeerHAIP[0],
                    g_node[i].datanode[j].datanodeListenIP[0]) == 0) {
                    if (g_nodeHeader.node == g_node[i].node) {
                        isLocal = false;
                    }
                    find = true;
                    g_node[i].datanodeCount = 1;
                    if (j > 0) {
                        ret = memcpy_s((void *)(&(g_node[i].datanode[0])),
                            sizeof(dataNodeInfo),
                            (void *)(&(g_node[i].datanode[j])),
                            sizeof(dataNodeInfo));
                        securec_check_c(ret, "", "");
                    }
                    break;
                }
            }
            if (find) {
                break;
            }
        }
        if (!find) {
            g_node[i].datanodeCount = 0;
        }
    }
    return isLocal;
}

int read_single_file(const char *file_path, int *err_no, uint32 nodeId, const char *dataPath)
{
    int ret = read_config_file(file_path, err_no);
    if (ret != 0) {
        return ret;
    }

    uint32 node_index = 0;
    bool find = false;
    for (uint32 i = 0; i < g_node_num; i++) {
        if (g_node[i].datanodeCount > CM_MAX_DATANODE_PER_NODE) {
            break;
        }
        if (g_node[i].node == nodeId) {
            for (uint32 j = 0; j < g_node[i].datanodeCount; j++) {
                if (strcmp(dataPath, g_node[i].datanode[j].datanodeLocalDataPath) == 0) {
                    node_index = i;
                    find = true;
                    break;
                }
            }
        }
    }
    if (!find) {
        return -1;
    }
    bool isLocal = read_single_file_local(node_index);
    if (!isLocal) {
        return -2;
    }
    return 0;
}

int get_dynamic_dn_role(void)
{
    char path[MAXPGPATH];
    char line_info[MAXPGPATH] = {0};
    char *node_name = NULL;
    char *dn_role = NULL;
    struct stat statbuf;

    char *gausshome = gs_getenv_r("GAUSSHOME");
    check_input_for_security(gausshome);

    int nRet = snprintf_s(path, MAXPGPATH, MAXPGPATH - 1, "%s/bin/%s", gausshome, DYNAMIC_DNROLE_FILE);
    securec_check_ss_c(nRet, "", "");

    if (lstat(path, &statbuf) != 0) {
        return 0;
    }

    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        return OPEN_FILE_ERROR;
    }

    while ((fgets(line_info, 1023 - 1, fp)) != NULL) {
        line_info[(int)strlen(line_info) - 1] = '\0';
        node_name = strtok_r(line_info, "=", &dn_role);
        for (uint32 nodeidx = 0; node_name && (nodeidx < g_node_num); nodeidx++) {
            if (strncmp(g_node[nodeidx].nodeName, node_name, strlen(node_name)) == 0) {
                g_node[nodeidx].datanode[0].datanodeRole = (uint32)atoi(dn_role);
                break;
            }
        }
    }

    (void)fclose(fp);
    return 0;
}

/*
 ******************************************************************************
 Function    : get_nodename_list_by_AZ
 Description : get node name list by azName, don't include local node
 Input       : AZName -
 Output      : nodename list
 Return      : None
 ******************************************************************************
*/
int get_nodename_list_by_AZ(const char *AZName, const char *data_dir, char **nodeNameList)
{
    uint32 nodeidx;
    uint32 count = 0;
    uint32 j = 0;
    uint32 tmpAZPriority = 0;
    char *tmpNodeName = NULL;
    size_t buflen = 1;
    size_t curlen = 0;

    // get the node number which in azName
    for (nodeidx = 0; nodeidx < g_node_num; nodeidx++) {
        if (strcmp(g_node[nodeidx].azName, AZName) == 0) {
            count++;
        }
    }
    // maybe the AZName is incorrect, so return null
    if (count < 1) {
        return 0;
    }

    // init azList, i must less than count
    AZList *azList = (AZList *)malloc(sizeof(AZList) * count);
    if (azList == NULL) {
        return OUT_OF_MEMORY;
    }

    dataNodeInfo *dni = NULL;
    {
        for (uint32 idx = 0; idx < g_currentNode->datanodeCount; idx++) {
            dataNodeInfo *dni_tmp = &(g_currentNode->datanode[idx]);
            if (strcmp(dni_tmp->datanodeLocalDataPath, data_dir) == 0) {
                dni = dni_tmp;
                break;
            }
        }
    }

    if (dni == NULL) {
        free(azList);
        azList = NULL;
        return OPEN_FILE_ERROR;
    }

    uint32 i = 0;
    for (nodeidx = 0; nodeidx < g_node_num; nodeidx++) {
        staticNodeConfig *dest = &(g_node[nodeidx]);
        bool get_dn_in_same_shard = false;

        if (nodeidx != g_local_node_idx && strcmp(dest->azName, AZName) == 0) {
            for (uint32 l = 0; l < dest->datanodeCount && !get_dn_in_same_shard; l++) {
                dataNodeInfo *dn = &(dest->datanode[l]);

                if (dn->datanodeId == 0) {
                    continue;
                }

                if (dn->datanodeRole == CASCADE_STANDBY_TYPE) {
                    continue;
                }

                for (int32 n = 0; n < CM_MAX_DATANODE_STANDBY_NUM && !get_dn_in_same_shard; n++) {
                    peerDatanodeInfo *peer_datanode = &(dn->peerDatanodes[n]);
                    if (strlen(peer_datanode->datanodePeerHAIP[0]) == 0) {
                        continue;
                    }

                    if (strcmp(peer_datanode->datanodePeerHAIP[0], dni->datanodeLocalHAIP[0]) == 0 &&
                        peer_datanode->datanodePeerHAPort == dni->datanodeLocalHAPort) {
                        char dn_instance_id[64] = {0};
                        int nRc = snprintf_s(dn_instance_id,
                            sizeof(dn_instance_id) / sizeof(char),
                            sizeof(dn_instance_id) / sizeof(char) - 1,
                            "dn_%4u",
                            dn->datanodeId);
                        securec_check_ss_c(nRc, "", "");
                        azList[i].nodeName = strdup(dn_instance_id);
                        azList[i].azPriority = dest->azPriority;
                        buflen += strlen(azList[i].nodeName) + 1;
                        i++;
                        get_dn_in_same_shard = true;
                        break;
                    }
                }
            }
        }
    }

    // the real node name number
    uint32 len = i;
    // sort by azPriority asc
    for (i = 0; len > 0 && i < len - 1; i++) {
        for (j = 0; len > 0 && j < (len - i) - 1; j++) {
            if (azList[j].azPriority > azList[j + 1].azPriority) {
                // swap azPriority
                tmpAZPriority = azList[j].azPriority;
                azList[j].azPriority = azList[j + 1].azPriority;
                azList[j + 1].azPriority = tmpAZPriority;
                // swap nodename
                tmpNodeName = strdup(azList[j].nodeName);
                free(azList[j].nodeName);
                azList[j].nodeName = NULL;
                azList[j].nodeName = strdup(azList[j + 1].nodeName);
                free(azList[j + 1].nodeName);
                azList[j + 1].nodeName = NULL;
                azList[j + 1].nodeName = strdup(tmpNodeName);
                free(tmpNodeName);
                tmpNodeName = NULL;
            }
        }
    }

    // Exclude the local node name and output the remaining information
    char *buffer = (char *)malloc(sizeof(char) * (buflen + 1));
    if (buffer == NULL) {
        // free AZList
        for (i = 0; i < len; i++) {
            if (azList[i].nodeName != NULL) {
                free(azList[i].nodeName);
                azList[i].nodeName = NULL;
            }
        }

        free(azList);
        azList = NULL;
        return OUT_OF_MEMORY;
    }
    int32 nRet = memset_s(buffer, buflen + 1, 0, buflen + 1);
    securec_check_c(nRet, buffer, "");

    for (i = 0; i < len; i++) {
        if (strcmp(g_local_node_name, azList[i].nodeName) == 0) {
            continue;
        }
        // the type like this: node1,node2,
        nRet = snprintf_s(buffer + curlen, (buflen + 1 - curlen), (buflen - curlen), "%s,", azList[i].nodeName);
        securec_check_ss_c(nRet, buffer, "");
        curlen = curlen + (size_t)nRet;
    }
    // skip the last character ','
    if (strlen(buffer) >= 1) {
        buffer[strlen(buffer) - 1] = '\0';
    }

    // free AZList
    for (i = 0; i < len; i++) {
        if (azList[i].nodeName != NULL) {
            free(azList[i].nodeName);
            azList[i].nodeName = NULL;
        }
    }

    free(azList);
    azList = NULL;
    *nodeNameList = buffer;
    return 0;
}

/*
 ******************************************************************************
 Function    : checkPath
 Input       : fileName
 Output      : None
 Return      : None
 ******************************************************************************
*/
int checkPath(const char *fileName)
{
    char realFileName[MAX_REALPATH_LEN + 1] = {0};
    char *retVal = realpath(fileName, realFileName);
    if (retVal == NULL) {
        return -1;
    }
    return 0;
}

bool has_static_config()
{
    char path[MAXPGPATH];
    int nRet = 0;
    struct stat statbuf;

    char *gausshome = gs_getenv_r("GAUSSHOME");
    check_input_for_security(gausshome);

    if (g_lcname != NULL) {
        nRet = snprintf_s(path, MAXPGPATH, MAXPGPATH - 1, "%s/bin/%s.%s", gausshome, g_lcname, STATIC_CONFIG_FILE);
    } else {
        nRet = snprintf_s(path, MAXPGPATH, MAXPGPATH - 1, "%s/bin/%s", gausshome, STATIC_CONFIG_FILE);
    }
    securec_check_ss_c(nRet, "", "");

    if (checkPath(path) != 0) {
        return false;
    }

    if (lstat(path, &statbuf) == 0) {
        return true;
    }

    return false;
}

/*
 ******************************************************************************
 ******************************************************************************
 Function    : check_datanodename_value
 Description : check the input datanode Name.
  Input       :nodeName            data node name
  return      :true                input datanode name is correct
               false               input datanode name is incorrect
 ******************************************************************************
 */
bool CheckDataNameValue(const char *datanodeName, const char *dataDir)
{
    int nRet;
    int dnIdMaxLen = 64;
    char dnId[dnIdMaxLen];

    if ((datanodeName == NULL) || (*datanodeName == '\0')) {
        return false;
    }

    dataNodeInfo *dnI = NULL;

    for (uint32 datanodeIdx = 0; datanodeIdx < g_currentNode->datanodeCount; datanodeIdx++) {
        dataNodeInfo *dniTmp = &(g_currentNode->datanode[datanodeIdx]);
        if (strcmp(dniTmp->datanodeLocalDataPath, dataDir) == 0) {
            dnI = dniTmp;
            break;
        }
    }

    if (dnI == NULL) {
        (void)fprintf(stderr, "Failed: cannot find the expected data dir\n");
        return false;
    }

    for (uint32 nodeIdx = 0; nodeIdx < g_node_num; ++nodeIdx) {
        staticNodeConfig *dest = &(g_node[nodeIdx]);
        for (uint32 datanodeIdx = 0; datanodeIdx < dest->datanodeCount; ++datanodeIdx) {
            dataNodeInfo *dn = &(dest->datanode[datanodeIdx]);
            if (dn->datanodeId == 0 || dn->datanodeId == dnI->datanodeId) {
                continue;
            }
            nRet = memset_s(dnId, sizeof(dnId), '\0', sizeof(dnId));
            securec_check_c(nRet, "", "");
            nRet = snprintf_s(
                dnId, sizeof(dnId) / sizeof(char), sizeof(dnId) / sizeof(char) - 1, "dn_%4u", dn->datanodeId);
            securec_check_ss_c(nRet, "", "");
            if (strncmp(dnId, datanodeName,
                ((strlen(dnId) > strlen(datanodeName)) ? strlen(dnId) : strlen(datanodeName))) != 0) {
                continue;
            }
            for (int peerIndex = 0; peerIndex < CM_MAX_DATANODE_STANDBY_NUM; ++peerIndex) {
                peerDatanodeInfo *peerDatanode = &(dnI->peerDatanodes[peerIndex]);
                if (strlen(peerDatanode->datanodePeerHAIP[0]) == 0) {
                    continue;
                }
                if (strcmp(peerDatanode->datanodePeerHAIP[0], dn->datanodeLocalHAIP[0]) == 0 &&
                    peerDatanode->datanodePeerHAPort == dn->datanodeLocalHAPort) {
                    return true;
                }
            }
        }
    }
    return false;
}
