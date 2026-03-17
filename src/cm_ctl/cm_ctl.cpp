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
 * ctl_ctl.cpp
 *      cm_ctl main files
 *
 * IDENTIFICATION
 *    src/cm_ctl/ctl_ctl.cpp
 *
 * -------------------------------------------------------------------------
 */
#include <fcntl.h>
#include "postgres_fe.h"
#include "cm/libpq-fe.h"
#include "cm/libpq-int.h"
#include "cm/pqsignal.h"

#include <arpa/inet.h>
#include <unordered_map>
#include "getopt_long.h"
#include "securec.h"

#include "common/config/cm_config.h"
#include "cm/cm_agent/cma_main.h"
#include "cm/cm_misc.h"
#include "cm_ddb_adapter.h"

#include "hotpatch/hotpatch_client.h"
#include "ctl_common.h"
#include "ctl_global_params.h"
#include "config.h"
#include "cm_util.h"
#include "ctl_help.h"
#include <string>
#include <vector>

#define ETCD_NUM_UPPER_LIMIT 50

#define CLUSTER_MANUAL_START "cluster_manual_start"
#define INSTANCE_MANUAL_START "instance_manual_start"
#define ETCD_MANUAL_START "etcd_manual_start"
#define MINORITY_AZ_START "minority_az_start"
#define MINORITY_AZ_ARBITRATE "minority_az_arbitrate_hist"
#define RESUMING_CN_STOP "resuming_cn_stop"
#define CLUSTER_MANUAL_PAUSE "cluster_manual_pause"
#define CLUSTER_MANUAL_STARTING "cluster_manual_starting"

char* g_bin_name = NULL;
char* g_bin_path = NULL;

extern char sys_log_path[MAXPGPATH];
extern const char* prefix_name;
extern volatile int log_min_messages;

/* The unit is second. */
static bool lc_operation = false;

bool got_stop = false;
bool g_detailQuery = false;
bool g_formatQuery = false;
bool g_coupleQuery = false;
bool backup_process_query = false;
bool g_balanceQuery = false;
bool g_startStatusQuery = false;
bool g_abnormalQuery = false;
bool g_portQuery = false;
bool g_paralleRedoState = false;
bool g_dataPathQuery = false;
bool g_ipQuery = false;
bool g_availabilityZoneCommand = false;
bool switchover_all_quick = false;
int do_force = 0;
int g_fencedUdfQuery = 0;
int shutdown_level = 0;  // cm_ctl stop single instance, single node or all nodes
extern bool g_logFileSet;
bool g_nodeIdSet = false;
char g_cmdLine[MAX_PATH_LEN] = {0};
ShutdownMode shutdown_mode_num = FAST_MODE;  // cm_ctl stop -m smart, fast, immediate

bool wait_seconds_set = false;
int g_waitSeconds = DEFAULT_WAIT;
CtlCommand ctl_command = NO_COMMAND;
uint32 g_normal_cm_server_node_index = PG_UINT32_MAX;
time_t CHECK_BUILDING_DN_TIMEOUT = 60; // in seconds
bool is_check_building_dn = true;

char g_appPath[MAXPGPATH] = {0};
const char* g_progname;
static char* pgdata_opt = NULL;
char* g_logFile = NULL;
char* log_level_set = NULL;
bool log_level_get = false;
char* cm_arbitration_mode_set = NULL;
bool cm_arbitration_mode_get = false;
char* cm_switchover_az_mode_set = NULL;
bool cm_switchover_az_mode_get = false;
char* cm_logic_cluster_restart_mode_set = NULL;
char *g_dcfXMode = NULL;
int g_dcfVoteNum = 0;
char *g_cmsPromoteMode = NULL;

bool g_gtmBalance = true;
bool g_datanodesBalance = true;
cm_to_ctl_central_node_status g_centralNode;

#if ((defined(ENABLE_MULTIPLE_NODES)) || (defined(ENABLE_PRIVATEGAUSS)))
static char* hotpatch_exec = NULL;
static char* hotpatch_path = NULL;
#endif

char manual_start_file[MAXPGPATH];
char instance_manual_start_file[MAXPGPATH];
char cluster_manual_starting_file[MAXPGPATH];
char etcd_manual_start_file[MAXPGPATH];
static bool coordinator_dynamic_view = false;
#ifndef ENABLE_MULTIPLE_NODES
const char* g_ltranManualStart = "ltran_manual_start";
const char* g_libnetManualStart = "libnet_manual_start";
char g_ltranManualStartFile[MAXPGPATH];
char g_libnetManualStartFile[MAXPGPATH];
#else
#include "ctl_distribute.h"
bool cn_resumes_restart = false;
char resuming_cn_stop_file[MAX_PATH_LEN];
#endif
char cluster_static_config[MAXPGPATH];
static char cluster_dynamic_config[MAXPGPATH];
static char cm_server_bin[MAXPGPATH];
static char g_logicClusterListPath[MAX_PATH_LEN];
char minority_az_start_file[MAX_PATH_LEN];
char g_minorityAzArbitrateFile[MAX_PATH_LEN];
char manual_pause_file[MAXPGPATH];

uint32 g_nodeId = 0;
uint32 g_commandOperationNodeId = 0;
uint32 g_commandOperationInstanceId = 0;
char* g_command_operation_lcName = NULL;
char* g_command_operation_azName = NULL;
char* g_commandMinortityAzName = NULL;
uint32 g_nodeIndexForCmServer[CM_PRIMARY_STANDBY_NUM] = {INVALID_NODE_NUM,
    INVALID_NODE_NUM,
    INVALID_NODE_NUM,
    INVALID_NODE_NUM,
    INVALID_NODE_NUM,
    INVALID_NODE_NUM,
    INVALID_NODE_NUM,
    INVALID_NODE_NUM};
// we should make sure g_cmServerState str array's inited len >= 9
const char* g_cmServerState[CM_PRIMARY_STANDBY_NUM  + 1] = {
    "Init", "Init", "Init", "Init", "Init", "Init", "Init", "Init", "Init"};
static bool g_execute_cmctl_success = false;
char result_path[MAXPGPATH] = {0};
char hosts_path[MAXPGPATH] = {0};
char pssh_out_path[MAXPGPATH] = {0};
char g_cmData[CM_PATH_LENGTH] = {0};
bool g_commandRelationship = false;
bool g_isSharedStorageMode = false;
passwd* pw = NULL;
char mpp_env_separate_file[MAXPGPATH] = {0};

const int DCF_XMODE = 5;
const int DCF_VOTE_NUM = 6;
const int DCF_ROLE_MODE = 7;
const int MINORITY_AZ = 8;
const int CMS_P_MODE = 9;
const int CM_AGENT_MODE = 10;
const int CM_SERVER_MODE = 11;
const int CM_SWITCH_DDB = 12;
const int CM_SWITCH_COMMIT = 13;
const int CM_SWITCH_ROLLBACK = 14;
const int CM_SET_PARAM = 15;
const int DCF_GROUP = 16;
const int DCF_PRIORITY = 17;
const int RES_ADD = 18;
const int RES_EDIT = 19;
const int RES_DEL = 20;
const int RES_CHECK = 21;
const int RES_NAME_INPUT = 22;
const int RES_ATTR_INPUT = 23;
const int RES_ADD_INST_INPUT = 24;
const int RES_DEL_INST_INPUT = 25;
const int RES_EDIT_INST_INPUT = 27;
const int RES_INST_ATTR_INPUT = 28;
const int RES_LIST = 29;
const int RES_LIST_INST_INPUT = 30;
const int ErrorCode = -2;

// short and long Options corresponds to CtlCommand.Need to change the options here, if options of the commands are added or modified
static const char* g_allowedOptions = "aAb:B:cCD:dE:fFgil:I:j:k:L:m:M:n:NP:pqrRsSt:T:vwxz:";
static const vector<vector<int>> g_allowedActionOptions = {
        {}, // no command
        { 'L' }, // "restart" command
        { 'z', 'n', 'D', 'R', 'I', 'm', 't', 2 }, // "start" command
        { 'z', 'n', 'D', 'I', 'R', 't', 'm' }, // "stop" command
        { 'z', 'n', 'D', 'q', 'f', 'a', 'A', 't' }, // "switchover" command
        {'c', 'n', 'D', 't', 'f', 'b', 'j'}, // "build" command
        {}, // CM_REMOVE_COMMAND -- no corresponding commands need user to input in the commandline
        {'z', 'n', 'D', 'R', 'l', 'v', 'w', 'C', 's', 'S', 'd', 'i', 'F', 'L', 'x', 'p', 'r', 't', 'g', MINORITY_AZ}, // "query" command
        {'I', 'n', 'k', 1, 2, 3, CMS_P_MODE, CM_SET_PARAM, CM_AGENT_MODE, CM_SERVER_MODE}, // "set" command
        {1, 2, 3}, // "get" command
        {}, // CM_STARTCM_COMMAND -- no corresponding commands need user to input in the commandline
        {}, // CM_STOPCM_COMMAND -- no corresponding commands need user to input in the commandline
        {}, // CM_SYNC_COMMAND -- no corresponding commands need user to input in the commandline
        {'v', 'n', 'N', 'c', 'l'}, // "view" command
        {'B', 'T'}, // "check" command
        {}, // "setmode" command
        {'E', 'P'}, // "hotpatch" command
        {'n', 'D', 't'}, // "disable" command
        {}, // "finishredo" command
        {'n', 'D', DCF_XMODE, DCF_VOTE_NUM}, // "setrunmode" command
        {'n', 'D', 't', DCF_ROLE_MODE}, // "changerole" command
        {'n', 'D', 't', DCF_ROLE_MODE, DCF_GROUP, DCF_PRIORITY}, // "changemember" command
        {'n', CM_SET_PARAM, CM_AGENT_MODE, CM_SERVER_MODE}, // "reload" command
        {'n', CM_SET_PARAM, CM_AGENT_MODE, CM_SERVER_MODE}, // "list" command
        {'M', 'D'}, // "encrypt" command
        {CM_SWITCH_DDB, CM_SWITCH_COMMIT, CM_SWITCH_ROLLBACK}, // "switch" command
        {RES_ADD, RES_NAME_INPUT, RES_ATTR_INPUT, RES_DEL, RES_EDIT, RES_LIST, RES_ADD_INST_INPUT, RES_DEL_INST_INPUT,
         RES_EDIT_INST_INPUT, RES_INST_ATTR_INPUT, RES_LIST_INST_INPUT, RES_CHECK}, // "res" command
         {}, // "show" command
         {}, // "pause" command
         {} // "resume" command
};
unordered_map<string, CtlCommand> g_optToCommand {
#ifdef ENABLE_MULTIPLE_NODES
    {"restart", RESTART_COMMAND},
    {"disable", CM_DISABLE_COMMAND},
#endif
#if ((defined(ENABLE_MULTIPLE_NODES)) || (defined(ENABLE_PRIVATEGAUSS)))
    {"hotpatch", CM_HOTPATCH_COMMAND},
#endif
    {"set", CM_SET_COMMAND},
    {"get", CM_GET_COMMAND},
    {"view", CM_VIEW_COMMAND},
    {"stop", STOP_COMMAND},
    {"list", CM_LIST_COMMAND},
    {"start", START_COMMAND},
    {"build", CM_BUILD_COMMAND},
    {"query", CM_QUERY_COMMAND},
    {"check", CM_CHECK_COMMAND},
    {"reload", CM_RELOAD_COMMAND},
    {"switch", CM_SWITCH_COMMAND},
    {"encrypt", CM_ENCRYPT_COMMAND},
    {"setmode", CM_SETMODE_COMMAND},
#ifdef ENABLE_LIBPQ
    {"finishredo", CM_FINISHREDO_COMMAND},
    {"setrunmode", CM_DCF_SETRUNMODE_COMMAND},
    {"changerole", CM_DCF_CHANGEROLE_COMMAND},
    {"changemember", CM_DCF_CHANGEMEMBER_COMMAND},
#endif
    {"switchover", CM_SWITCHOVER_COMMAND},
    {"res", CM_RES_COMMAND},
    {"show", CM_SHOW_COMMAND},
    {"pause", CM_PAUSE_COMMAND},
    {"resume", CM_RESUME_COMMAND}
};

static string CheckActionOptions(CtlCommand ctlCommandAction, vector<int> optionIn, option* longActionOptions, int lengthLong)
{
    string notMatched;
    vector<int> checkInterOptions = g_allowedActionOptions[ctlCommandAction];
    option optionInter;
    int optionInLength = (int) optionIn.size();
    for (int checkIndexO = 0; checkIndexO < optionInLength; ++checkIndexO) {
        bool checkInArr = false;
        int checkIndexI = 0;
        while (checkIndexI < (int)checkInterOptions.size() && checkInterOptions[checkIndexI]!= 0) {
            if (optionIn[checkIndexO] == checkInterOptions[checkIndexI]) {
                checkInArr = true;
                break;
            }
            ++checkIndexI;
        }
        if (!checkInArr) {
            if (!notMatched.empty()) {
                notMatched.append(",");
            }
            if (optionIn[checkIndexO] <= RES_LIST_INST_INPUT) {
                int checkInter = 0;
                while (checkInter < lengthLong) {
                    optionInter = longActionOptions[checkInter];
                    if (optionIn[checkIndexO] == optionInter.val) {
                        notMatched.append(optionInter.name);
                        break;
                    }
                    ++checkInter;
                }
            } else {
                notMatched.push_back(char(optionIn[checkIndexO]));
            }
        }
    }
    return notMatched;
}

static status_t CheckActionOptionMatches(CtlCommand ctlCommandAction, vector<int> optionIn, option* longActionOptions, int lengthLong)
{
    if (ctlCommandAction == NO_COMMAND) {
        write_runlog2(FATAL, errcode(ERRCODE_READ_FILE_FAILURE),
                      errmsg("option requires an argument, NO_COMMAND only support 'V' and 'h'."));
        DoAdvice();
        return CM_ERROR;
    }
    string checkUnmatchedOption = CheckActionOptions(ctlCommandAction, optionIn, longActionOptions, lengthLong);
    if (!checkUnmatchedOption.empty()) {
        write_runlog2(FATAL, errcode(ERRCODE_PARAMETER_FAILURE),
                      errmsg("Commands and options do not match.\n"),
                      errmodule(MOD_CMCTL),
                      errcause("%s: The cmdline and options entered by the user is incorrect.\n", g_progname),
                      erraction("These options \"%s\" are not incorrect or not matched with the command.",
                                checkUnmatchedOption.c_str()));
        DoAdvice();
        return CM_ERROR;
    }
    return CM_SUCCESS;
}
static void InitializeCmServerNodeIndex(void)
{
    uint32 i = 0;

    for (uint32 curIndex = 0; curIndex < g_node_num; ++curIndex) {
        if (g_node[curIndex].cmServerLevel != 1) {
            continue;
        }
        g_nodeIndexForCmServer[i++] = curIndex;
    }
}

uint32 *GetCmsNodeIndex()
{
    return g_nodeIndexForCmServer;
}

/*
 * read cluster static config and init global parameters
 */
static int read_config_file_check()
{
    int err_no = 0;

    if (access(cluster_static_config, F_OK) != 0) {
        write_runlog2(ERROR, errcode(ERRCODE_OPEN_FILE_FAILURE),
            errmsg("Fail to access the cluster static config file."),
            errdetail("The cluster static config file does not exist."), errmodule(MOD_CMCTL),
            errcause("The cluster static config file is not generated or is manually deleted."),
            erraction("Please check the cluster static config file."));
        return 1;
    }

    /* parse config file. */
    int status = read_config_file(cluster_static_config, &err_no);
    char errBuffer[ERROR_LIMIT_LEN] = {0};
    switch (status) {
        case OPEN_FILE_ERROR: {
            write_runlog2(ERROR, errcode(ERRCODE_OPEN_FILE_FAILURE), errmsg("Fail to open the cluster static file."),
                errdetail("[errno %d] %s.", err_no, strerror_r(err_no, errBuffer, ERROR_LIMIT_LEN)),
                errmodule(MOD_CMCTL),
                errcause("The cluster static config file is not generated or is manually deleted."),
                erraction("Please check the cluster static config file."));
            return 1;
        }
        case READ_FILE_ERROR: {
            write_runlog2(ERROR, errcode(ERRCODE_READ_FILE_FAILURE), errmsg("Fail to read the cluster static file."),
                errdetail("[errno %d] %s.\n", err_no, strerror_r(err_no, errBuffer, ERROR_LIMIT_LEN)),
                errmodule(MOD_CMCTL), errcause("The cluster static file permission is insufficient."),
                erraction("Please check the cluster static config file."));
            return 1;
        }
        case OUT_OF_MEMORY:
            write_runlog2(ERROR, errcode(ERRCODE_OUT_OF_MEMORY), errmsg("Failed to read the static config file."),
                errdetail("N/A"), errmodule(MOD_CMCTL), errcause("out of memeory."),
                erraction("Please check the system memory and try again."));

            return 1;
        default:
            break;
    }

    uint32 node_index = get_node_index(g_nodeHeader.node);
    if (node_index >= g_node_num) {
        write_runlog2(ERROR, errcode(ERRCODE_CONFIG_FILE_FAILURE),
            errmsg("Could not find the current node in the cluster by the node id %u.", g_nodeHeader.node),
            errdetail("N/A"), errmodule(MOD_CMCTL),
            errcause("The static config file probably contained content error."),
            erraction("Please check static config file."));
        return 1;
    }

    g_nodeId = node_index;
    g_currentNode = &g_node[node_index];

    InitializeCmServerNodeIndex();

    if (lc_operation && access(g_logicClusterListPath, F_OK) == 0) {
        status = read_logic_cluster_config_files(g_logicClusterListPath, &err_no);
        char errBuff[ERROR_LIMIT_LEN] = {0};
        switch (status) {
            case OPEN_FILE_ERROR: {
                write_runlog2(ERROR, errcode(ERRCODE_OPEN_FILE_FAILURE),
                    errmsg("Failed to open the logic config file."),
                    errdetail("[errno %d] %s", err_no, strerror_r(err_no, errBuff, ERROR_LIMIT_LEN)),
                    errmodule(MOD_CMCTL), errcause("The logic config file is not generated or is manually deleted."),
                    erraction("Please check the cluster static config file."));
                return 1;
            }
            case READ_FILE_ERROR: {
                write_runlog2(ERROR, errcode(ERRCODE_READ_FILE_FAILURE),
                    errmsg("Fail to read the logic static config file."),
                    errdetail("[errno %d] %s", err_no, strerror_r(err_no, errBuff, ERROR_LIMIT_LEN)),
                    errmodule(MOD_CMCTL), errcause("The logic static config file permission is insufficient."),
                    erraction("Please check the logic static config file."));
                return 1;
            }
            case OUT_OF_MEMORY:
                write_runlog2(ERROR,
                    errcode(ERRCODE_OUT_OF_MEMORY), errmsg("Failed to open or read the static config file."),
                    errdetail("N/A"), errmodule(MOD_CMCTL), errcause("out of memeory."),
                    erraction("Please check the system memory and try again."));
                return 1;
            default:
                break;
        }
    }

    return 0;
}

static bool SetOutputFile(bool logFileSet, const char* logFile)
{
    char errBuffer[ERROR_LIMIT_LEN];
    if (logFileSet) {
        g_logFilePtr = fopen(logFile, "w");
        if (g_logFilePtr == NULL) {
            if (errno == ENOENT) {
                write_runlog(ERROR, "log file not found.\n");
                return false;
            } else {
                write_runlog(ERROR,
                    "could not open log file \"%s\": %s\n",
                    logFile,
                    strerror_r(errno, errBuffer, ERROR_LIMIT_LEN));
                return false;
            }
        }
    } else {
        g_logFilePtr = stdout;
    }
    return true;
}

static void RecordCommonInfo()
{
    (void)fprintf(g_logFilePtr, "NodeHeader:\n");
    (void)fprintf(g_logFilePtr, "version:%u\n", g_nodeHeader.version);
    (void)fprintf(g_logFilePtr, "time:%ld\n", g_nodeHeader.time);
    (void)fprintf(g_logFilePtr, "nodeCount:%u\n", g_nodeHeader.nodeCount);
    (void)fprintf(g_logFilePtr, "node:%u\n", g_nodeHeader.node);
}

static void RecordNodeInfo(uint32 nodeId)
{
    if (g_multi_az_cluster) {
        (void)fprintf(g_logFilePtr, "azName:%s\n", g_node[nodeId].azName);
        (void)fprintf(g_logFilePtr, "azPriority:%u\n", g_node[nodeId].azPriority);
    }
    (void)fprintf(g_logFilePtr, "node :%u\n", g_node[nodeId].node);
    (void)fprintf(g_logFilePtr, "nodeName:%s\n", g_node[nodeId].nodeName);
    (void)fprintf(g_logFilePtr, "ssh channel :\n");
    for (uint32 jj = 0; jj < g_node[nodeId].sshCount; jj++) {
        (void)fprintf(g_logFilePtr, "sshChannel %u:%s\n", jj + 1, g_node[nodeId].sshChannel[jj]);
    }
}

static void RecordCmsInfo(uint32 nodeId)
{
    if (g_node[nodeId].cmServerLevel != 1) {
        return;
    }
    if (g_detailQuery || g_nodeIdSet) {
        (void)fprintf(g_logFilePtr, "cmseverInstanceID :%u\n", g_node[nodeId].cmServerId);
    }
    (void)fprintf(g_logFilePtr, "cmDataPath :%s\n", g_node[nodeId].cmDataPath);
    for (uint32 i = 0; i < g_node[nodeId].cmServerListenCount; i++) {
        (void)fprintf(g_logFilePtr, "cmServer %u:%s\n", i + 1, g_node[nodeId].cmServer[i]);
    }
    (void)fprintf(g_logFilePtr, "port :%u\n", g_node[nodeId].port);
    for (uint32 i = 0; i < g_node[nodeId].cmServerLocalHAListenCount; i++) {
        (void)fprintf(g_logFilePtr, "cmServerLocalHAIP %u:%s\n", i + 1, g_node[nodeId].cmServerLocalHAIP[i]);
    }
    (void)fprintf(g_logFilePtr, "cmServerLocalHAPort :%u\n", g_node[nodeId].cmServerLocalHAPort);
    for (uint32 i = 0; i < g_node[nodeId].cmServerPeerHAListenCount; i++) {
        (void)fprintf(g_logFilePtr, "cmServerPeerHAIP %u:%s\n", i + 1, g_node[nodeId].cmServerPeerHAIP[i]);
    }
    (void)fprintf(g_logFilePtr, "cmServerPeerHAPort :%u\n", g_node[nodeId].cmServerPeerHAPort);
}
static void RecordCmaInfo(uint32 nodeId)
{
    for (uint32 i = 0; i < g_node[nodeId].cmAgentListenCount; i++) {
        (void)fprintf(g_logFilePtr, "cmAgentIP :%s\n", g_node[nodeId].cmAgentIP[i]);
    }
}

static void RecordDnInfo(uint32 nodeId)
{
    if (g_node[nodeId].datanodeCount == 0) {
        return;
    }
    (void)fprintf(g_logFilePtr, "datanodeCount :%u\n", g_node[nodeId].datanodeCount);
    for (uint32 kk = 0; kk < g_node[nodeId].datanodeCount; kk++) {
        (void)fprintf(g_logFilePtr, "datanode %u:\n", kk + 1);
        if (g_detailQuery || g_nodeIdSet) {
            (void)fprintf(g_logFilePtr, "datanodeInstanceID :%u\n", g_node[nodeId].datanode[kk].datanodeId);
        }
        (void)fprintf(g_logFilePtr, "datanodeLocalDataPath :%s\n", g_node[nodeId].datanode[kk].datanodeLocalDataPath);
        (void)fprintf(g_logFilePtr, "datanodeXlogPath :%s\n", g_node[nodeId].datanode[kk].datanodeXlogPath);
        for (uint32 tt = 0; tt < g_node[nodeId].datanode[kk].datanodeListenCount; tt++) {
            (void)fprintf(g_logFilePtr, "datanodeListenIP %u:%s\n",
                tt + 1, g_node[nodeId].datanode[kk].datanodeListenIP[tt]);
        }
        (void)fprintf(g_logFilePtr, "datanodePort :%u\n", g_node[nodeId].datanode[kk].datanodePort);
        for (uint32 tt = 0; tt < g_node[nodeId].datanode[kk].datanodeLocalHAListenCount; tt++) {
            (void)fprintf(
                g_logFilePtr, "datanodeLocalHAIP %u:%s\n", tt + 1, g_node[nodeId].datanode[kk].datanodeLocalHAIP[tt]);
        }
        (void)fprintf(g_logFilePtr, "datanodeLocalHAPort :%u\n", g_node[nodeId].datanode[kk].datanodeLocalHAPort);
        if (g_multi_az_cluster) {
            (void)fprintf(g_logFilePtr, "dn_replication_num: %u\n", g_dn_replication_num);
            for (uint32 dnId = 0; dnId < g_dn_replication_num - 1; dnId++) {
                (void)fprintf(g_logFilePtr, "datanodePeer%uDataPath :%s\n", dnId,
                    g_node[nodeId].datanode[kk].peerDatanodes[dnId].datanodePeerDataPath);
                for (uint32 tt = 0; tt < g_node[nodeId].datanode[kk].peerDatanodes[dnId].datanodePeerHAListenCount;
                     tt++) {
                    (void)fprintf(g_logFilePtr, "datanodePeer%uHAIP %u:%s\n", dnId, tt + 1,
                        g_node[nodeId].datanode[kk].peerDatanodes[dnId].datanodePeerHAIP[tt]);
                }
                (void)fprintf(g_logFilePtr, "datanodePeer%uHAPort :%u\n", dnId,
                    g_node[nodeId].datanode[kk].peerDatanodes[dnId].datanodePeerHAPort);
            }
        } else {
            (void)fprintf(g_logFilePtr, "datanodePeerDataPath :%s\n", g_node[nodeId].datanode[kk].datanodePeerDataPath);
            for (uint32 tt = 0; tt < g_node[nodeId].datanode[kk].datanodePeerHAListenCount; tt++) {
                (void)fprintf(
                    g_logFilePtr, "datanodePeerHAIP %u:%s\n", tt + 1, g_node[nodeId].datanode[kk].datanodePeerHAIP[tt]);
            }
            (void)fprintf(g_logFilePtr, "datanodePeerHAPort :%u\n", g_node[nodeId].datanode[kk].datanodePeerHAPort);
            (void)fprintf(g_logFilePtr, "datanodePeer2DataPath :%s\n",
                g_node[nodeId].datanode[kk].datanodePeer2DataPath);
            for (uint32 tt = 0; tt < g_node[nodeId].datanode[kk].datanodePeer2HAListenCount; tt++) {
                (void)fprintf(g_logFilePtr, "datanodePeer2HAIP %u:%s\n", tt + 1,
                    g_node[nodeId].datanode[kk].datanodePeer2HAIP[tt]);
            }
            (void)fprintf(g_logFilePtr, "datanodePeer2HAPort :%u\n", g_node[nodeId].datanode[kk].datanodePeer2HAPort);
        }
    }
}

static void RecordEtcdInfo(uint32 nodeId)
{
    if (g_node[nodeId].etcd != 1) {
        return;
    }
    (void)fprintf(g_logFilePtr, "etcdName :%s\n", g_node[nodeId].etcdName);
    (void)fprintf(g_logFilePtr, "etcdDataPath :%s\n", g_node[nodeId].etcdDataPath);
    for (uint32 kk = 0; kk < g_node[nodeId].etcdClientListenIPCount; kk++) {
        (void)fprintf(g_logFilePtr, "etcdClientListenIPs %u:%s\n", kk + 1, g_node[nodeId].etcdClientListenIPs[kk]);
    }
    (void)fprintf(g_logFilePtr, "etcdClientListenPort :%u\n", g_node[nodeId].etcdClientListenPort);
    for (uint32 kk = 0; kk < g_node[nodeId].etcdHAListenIPCount; kk++) {
        (void)fprintf(g_logFilePtr, "etcdHAListenIPs %u:%s\n", kk + 1, g_node[nodeId].etcdHAListenIPs[kk]);
    }
    (void)fprintf(g_logFilePtr, "etcdHAListenPort :%u\n", g_node[nodeId].etcdHAListenPort);
}

static void do_view()
{
    if (!SetOutputFile(g_logFileSet, g_logFile)) {
        write_runlog(ERROR, "Execution failed.\n");
        return;
    }
    RecordCommonInfo();
    for (uint32 ii = 0; ii < g_node_num; ii++) {
        if (g_nodeIdSet && ((ii + 1) != g_commandOperationNodeId)) {
            continue;
        }
        RecordNodeInfo(ii);
        RecordCmsInfo(ii);
        RecordCmaInfo(ii);
#ifdef ENABLE_MULTIPLE_NODES
        RecordGtmInfo(ii, g_logFilePtr);
        RecordCnInfo(ii, g_logFilePtr);
#endif
        RecordDnInfo(ii);
        RecordEtcdInfo(ii);
    }

    if (g_logFileSet && (g_logFilePtr != NULL)) {
        (void)fclose(g_logFilePtr);
        g_logFilePtr = NULL;
    }
}

bool do_dynamic_view()
{
    int fd;
    ssize_t returnCode;
    char clusterDynamicConfig[MAXPGPATH] = {0};

    int ret = snprintf_s(clusterDynamicConfig, MAXPGPATH, MAXPGPATH - 1, "%s/bin/%s", g_appPath, DYNAMC_CONFIG_FILE);
    securec_check_intval(ret, (void)ret);
    check_input_for_security(clusterDynamicConfig);
    canonicalize_path(clusterDynamicConfig);
    fd = open(clusterDynamicConfig, O_RDWR | O_CLOEXEC, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        char errBuffer[ERROR_LIMIT_LEN];
        write_runlog2(FATAL,
            errcode(ERRCODE_OPEN_FILE_FAILURE),
            errmsg("Failed to open the dynamic config file \"%s\".", DYNAMC_CONFIG_FILE),
            errdetail("reason : %s.", strerror_r(errno, errBuffer, ERROR_LIMIT_LEN)),
            errmodule(MOD_CMCTL),
            errcause("The dynamic config file permission is insufficient."),
            erraction("Please check the dynamic config file."));
        return false;
    }

    size_t header_size = sizeof(dynamicConfigHeader);
    size_t header_aglinment_size =
        (header_size / AGLINMENT_SIZE + ((header_size % AGLINMENT_SIZE == 0) ? 0 : 1)) * AGLINMENT_SIZE;
    dynamicConfigHeader *g_dynamic_header = (dynamicConfigHeader *)malloc(header_aglinment_size);
    if (g_dynamic_header == NULL) {
        write_runlog2(FATAL, errcode(ERRCODE_OUT_OF_MEMORY),
            errmsg("Failed to malloc memory, size = %lu.", header_aglinment_size),
            errdetail("N/A"), errmodule(MOD_CMCTL), errcause("out of memeory."),
            erraction("Please check the system memory and try again."));
        (void)close(fd);
        return false;
    }

    returnCode = read(fd, g_dynamic_header, header_aglinment_size);
    if (returnCode != (ssize_t)header_aglinment_size) {
        write_runlog(FATAL, "read header failed!\n");
        (void)close(fd);
        FREE_AND_RESET(g_dynamic_header);
        return false;
    }

    returnCode = lseek(fd, (ssize_t)(header_aglinment_size), SEEK_SET);
    if (returnCode < 0) {
        write_runlog(FATAL, "seek header failed!\n");
        (void)close(fd);
        FREE_AND_RESET(g_dynamic_header);
        return false;
    }
    size_t cms_state_timeline_size = sizeof(dynamic_cms_timeline);
    dynamic_cms_timeline *g_timeline = (dynamic_cms_timeline *)malloc(cms_state_timeline_size);
    if (g_timeline == NULL) {
        write_runlog2(FATAL,
            errcode(ERRCODE_OUT_OF_MEMORY), errmsg("Failed to malloc memory, size = %lu.", cms_state_timeline_size),
            errdetail("N/A"), errmodule(MOD_CMCTL), errcause("out of memeory."),
            erraction("Please check the system memory and try again."));
        (void)close(fd);
        FREE_AND_RESET(g_dynamic_header);
        return false;
    }
    returnCode = read(fd, g_timeline, cms_state_timeline_size);
    if (returnCode != (ssize_t)cms_state_timeline_size) {
        write_runlog(FATAL, "read timeline failed!\n");
        (void)close(fd);
        FREE_AND_RESET(g_dynamic_header);
        FREE_AND_RESET(g_timeline);
        return false;
    }
    returnCode = lseek(fd, (ssize_t)(cms_state_timeline_size + header_aglinment_size), SEEK_SET);
    if (returnCode < 0) {
        write_runlog(FATAL, "seek timeline failed!\n");
        (void)close(fd);
        FREE_AND_RESET(g_dynamic_header);
        FREE_AND_RESET(g_timeline);
        return false;
    }

    cm_instance_role_group *g_instance_role_group_ptr =
        (cm_instance_role_group *)malloc(sizeof(cm_instance_role_group) * g_dynamic_header->relationCount);
    if (g_instance_role_group_ptr == NULL) {
        write_runlog2(FATAL, errcode(ERRCODE_OUT_OF_MEMORY),
            errmsg("Failed to malloc memory, size = %lu.",
                sizeof(cm_instance_role_group) * g_dynamic_header->relationCount),
            errdetail("N/A"), errmodule(MOD_CMCTL), errcause("out of memeory."),
            erraction("Please check the system memory and try again."));
        (void)close(fd);
        FREE_AND_RESET(g_dynamic_header);
        FREE_AND_RESET(g_timeline);
        return false;
    }

    returnCode =
        read(fd, g_instance_role_group_ptr, (g_dynamic_header->relationCount) * sizeof(cm_instance_role_group));
    if (returnCode != (ssize_t)((g_dynamic_header->relationCount) * sizeof(cm_instance_role_group))) {
        write_runlog(FATAL, "read instance role failed!\n");
        (void)close(fd);
        FREE_AND_RESET(g_dynamic_header);
        FREE_AND_RESET(g_instance_role_group_ptr);
        FREE_AND_RESET(g_timeline);
        return false;
    }

    (void)close(fd);

    for (uint32 i = 0; i < g_dynamic_header->relationCount; i++) {
        if (g_instance_role_group_ptr[i].instanceMember[0].instanceType == INSTANCE_TYPE_COORDINATE) {
            (void)printf("node                      : %u\n", g_instance_role_group_ptr[i].instanceMember[0].node);
            (void)printf("instance_id               : %u\n", g_instance_role_group_ptr[i].instanceMember[0].instanceId);
            if (g_instance_role_group_ptr[i].instanceMember[0].role == INSTANCE_ROLE_DELETED) {
                (void)printf("role                      : Deleted\n\n");
            } else {
                (void)printf("role                      : Not deleted\n\n");
            }
        }
    }

    FREE_AND_RESET(g_dynamic_header);
    FREE_AND_RESET(g_instance_role_group_ptr);
    FREE_AND_RESET(g_timeline);
    return true;
}

/*
 * @Description: Check user input AZ name.
 */
static void checkCmdAZName(const char* azName)
{
    for (uint32 i = 0; i < g_node_num; i++) {
        if (strcmp(g_node[i].azName, azName) == 0) {
            g_command_operation_azName = xstrdup(azName);
            return;
        }
    }

    if (strcmp("ALL", azName) == 0) {
        g_availabilityZoneCommand = true;
    } else {
        write_runlog2(FATAL, errcode(ERRCODE_PARAMETER_FAILURE), errmsg("unrecognized AZ name \"%s\".", azName),
            errdetail("N/A"), errmodule(MOD_CMCTL),
            errcause("The parameter(%s) entered by the user is incorrect.", azName),
            erraction("Please check the parameter entered by the user and try again."));
        if (g_logFileSet && (g_logFilePtr != NULL)) {
            (void)fclose(g_logFilePtr);
            g_logFilePtr = NULL;
        }
        exit(1);
    }
}

/*
 * @Description: Check user input AZ name.
 */
static void CheckMinorityAZName(const char *azName)
{
    bool found = false;

    for (uint32 i = 0; i < g_node_num; i++) {
        if (strcmp(g_node[i].azName, azName) == 0) {
            FREE_AND_RESET(g_commandMinortityAzName);
            g_commandMinortityAzName = xstrdup(azName);
            found = true;
            break;
        }
    }

    if (!found) {
        write_runlog2(FATAL, errcode(ERRCODE_PARAMETER_FAILURE),
            errmsg("unrecognized minorityAz name \"%s\".", azName),
            errdetail("N/A"), errmodule(MOD_CMCTL),
            errcause("The parameter(%s) entered by the user is incorrect.", azName),
            erraction("Please check the parameter entered by the user and try again."));
        exit(1);
    }
}

/*
 * @Description: Check if user input AZ name is in cluster.
 */
static bool checkAZNameInCluster(const char* azName)
{
    uint32 i;
    bool isAzNameInCluster = false;

    for (i = 0; i < g_node_num; i++) {
        if (strcmp(g_node[i].azName, azName) == 0) {
            isAzNameInCluster = true;
            break;
        }
    }

    return isAzNameInCluster;
}

/**
 * @brief: Get the logger path from the environment variable. And set the log file path.
 *
 * @return: void
 */
static void InitializeLogger()
{
    char logPath[MAXPGPATH] = {0};

    /* Get the program name. */
    prefix_name = g_progname;

    /* Initialize the logger. */
    (void)logfile_init();

    /* Set the log path. */
    int ret = cmctl_getenv("GAUSSLOG", logPath, MAXPGPATH - 1);
    if (ret == EOK) {
        check_input_for_security(logPath);

        ret = snprintf_s(sys_log_path, MAXPGPATH, MAXPGPATH - 1, "%s/cm/%s/", logPath, "cm_ctl");
        securec_check_intval(ret, (void)ret);
    } else {
        ret = snprintf_s(sys_log_path, MAXPGPATH, MAXPGPATH - 1, "%s/bin/", g_appPath);
        securec_check_intval(ret, (void)ret);
    }

    /* Store the log directory path, and make sure the directory exist. */
    if (sys_log_path[0] == '/') {
        (void)CmMkdirP(sys_log_path, S_IRWXU);
    } else {
        (void)mkdir(sys_log_path, S_IRWXU);
    }

    /* Set log level to DEBUG1. */
    log_min_messages = DEBUG1;
}

static bool CtlIsSharedStorageMode()
{
    char env[MAX_PATH_LEN] = {0};

    if (cm_getenv("DORADO_REARRANGE", env, sizeof(env), DEBUG5) != EOK) {
        return false;
    }
    write_runlog(DEBUG1, "Get DORADO_REARRANGE success, is shared storage mode.\n");

    return true;
}

static void init_ctl_global_variable()
{
    int ret = GetHomePath(g_appPath, sizeof(g_appPath), DEBUG5);
    if (ret == EOK) {
        ret =
            snprintf_s(g_logicClusterListPath, MAXPGPATH, MAXPGPATH - 1, "%s/bin/%s", g_appPath, LOGIC_CLUSTER_LIST);
        securec_check_intval(ret, (void)ret);
        ret = snprintf_s(manual_start_file, MAXPGPATH, MAXPGPATH - 1, "%s/bin/%s", g_appPath, CLUSTER_MANUAL_START);
        securec_check_intval(ret, (void)ret);
        ret = snprintf_s(
            instance_manual_start_file, MAXPGPATH, MAXPGPATH - 1, "%s/bin/%s", g_appPath, INSTANCE_MANUAL_START);
        securec_check_intval(ret, (void)ret);
        ret = snprintf_s(
            cluster_manual_starting_file, MAXPGPATH, MAXPGPATH - 1, "%s/bin/%s", g_appPath, CLUSTER_MANUAL_STARTING);
        securec_check_intval(ret, (void)ret);
        ret = snprintf_s(etcd_manual_start_file, MAXPGPATH, MAXPGPATH - 1, "%s/bin/%s", g_appPath, ETCD_MANUAL_START);
        securec_check_intval(ret, (void)ret);
#ifndef ENABLE_MULTIPLE_NODES
        ret = snprintf_s(g_ltranManualStartFile, MAXPGPATH, MAXPGPATH - 1, "%s/bin/%s", g_appPath, g_ltranManualStart);
        securec_check_intval(ret, (void)ret);
        canonicalize_path(g_ltranManualStartFile);
        ret =
            snprintf_s(g_libnetManualStartFile, MAXPGPATH, MAXPGPATH - 1, "%s/bin/%s", g_appPath, g_libnetManualStart);
        securec_check_intval(ret, (void)ret);
        canonicalize_path(g_libnetManualStartFile);
#else
        ret = snprintf_s(resuming_cn_stop_file, MAXPGPATH, MAXPGPATH - 1, "%s/bin/%s", g_appPath, RESUMING_CN_STOP);
        securec_check_intval(ret, (void)ret);
#endif
        ret = snprintf_s(minority_az_start_file, MAXPGPATH, MAXPGPATH - 1, "%s/bin/%s", g_appPath, MINORITY_AZ_START);
        securec_check_intval(ret, (void)ret);
        ret = snprintf_s(g_minorityAzArbitrateFile, MAXPGPATH, MAXPGPATH - 1, "%s/bin/%s",
            g_appPath, MINORITY_AZ_ARBITRATE);
        securec_check_intval(ret, (void)ret);
        ret = snprintf_s(cluster_static_config, MAXPGPATH, MAXPGPATH - 1, "%s/bin/%s", g_appPath, STATIC_CONFIG_FILE);
        securec_check_intval(ret, (void)ret);
        ret = snprintf_s(cluster_dynamic_config, MAXPGPATH, MAXPGPATH - 1, "%s/bin/%s", g_appPath, DYNAMC_CONFIG_FILE);
        securec_check_intval(ret, (void)ret);
        ret = snprintf_s(cm_server_bin, MAXPGPATH, MAXPGPATH - 1, "%s/bin/%s", g_appPath, CM_SERVER_BIN_NAME);
        securec_check_intval(ret, (void)ret);
        ret = snprintf_s(result_path, MAXPGPATH, MAXPGPATH - 1, "%s/bin/result", g_appPath);
        securec_check_intval(ret, (void)ret);
        canonicalize_path(result_path);
        ret = snprintf_s(hosts_path, MAXPGPATH, MAXPGPATH - 1, "%s/bin/hosts", g_appPath);
        securec_check_intval(ret, (void)ret);
        canonicalize_path(hosts_path);
        ret = snprintf_s(pssh_out_path, MAXPGPATH, MAXPGPATH - 1, "%s/bin/pssh.out", g_appPath);
        securec_check_intval(ret, (void)ret);
        ret = snprintf_s(g_tlsPath.caFile, ETCD_MAX_PATH_LEN, ETCD_MAX_PATH_LEN - 1,
            "%s/share/sslcert/etcd/etcdca.crt", g_appPath);
        securec_check_intval(ret, (void)ret);
        ret = snprintf_s(g_tlsPath.crtFile, ETCD_MAX_PATH_LEN, ETCD_MAX_PATH_LEN - 1,
            "%s/share/sslcert/etcd/client.crt", g_appPath);
        securec_check_intval(ret, (void)ret);
        ret = snprintf_s(g_tlsPath.keyFile, ETCD_MAX_PATH_LEN, ETCD_MAX_PATH_LEN - 1,
            "%s/share/sslcert/etcd/client.key", g_appPath);
        securec_check_intval(ret, (void)ret);
        ret = snprintf_s(manual_pause_file, MAXPGPATH, MAXPGPATH - 1, "%s/bin/%s", g_appPath, CLUSTER_MANUAL_PAUSE);
        securec_check_intval(ret, (void)ret);
    } else {
        write_runlog2(FATAL, errcode(ERRCODE_PARAMETER_FAILURE), errmsg("Get GAUSSHOME failed."),
            errdetail("N/A"), errmodule(MOD_CMCTL),
            errcause("The environment variable(\"GAUSSHOME\") is incorrectly configured."),
            erraction("Please check the environment variable(\"GAUSSHOME\")."));
        exit(1);
    }

    /* Initialize the logger. */
    InitializeLogger();

    ret = cmctl_getenv("MPPDB_ENV_SEPARATE_PATH", mpp_env_separate_file, sizeof(mpp_env_separate_file));
    if (ret == EOK) {
        check_input_for_security(mpp_env_separate_file);
    }

    pw = getpwuid(getuid());
    if (pw == NULL || pw->pw_name == NULL) {
        write_runlog2(FATAL, errcode(ERRCODE_PARAMETER_FAILURE), errmsg("Get current user name failed."),
            errdetail("N/A"), errmodule(MOD_CMCTL), errcause("N/A"), erraction("Please check the environment."));
        exit(1);
    }
    g_isSharedStorageMode = CtlIsSharedStorageMode();
}

static int CheckInputParameter()
{
    if (g_bin_name == NULL) {
        write_runlog2(ERROR, errcode(ERRCODE_PARAMETER_FAILURE),
            errmsg("-B option must be specified."), errdetail("N/A"),
            errmodule(MOD_CMCTL), errcause("%s: The cmdline entered by the user is incorrect.", g_progname),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        return 1;
    }
    check_input_for_security(g_bin_name);
    if (g_bin_path == NULL) {
        write_runlog2(ERROR, errcode(ERRCODE_PARAMETER_FAILURE),
            errmsg("-T option must be specified.\n"), errdetail("N/A"),
            errmodule(MOD_CMCTL), errcause("%s: The cmdline entered by the user is incorrect.", g_progname),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        return 1;
    }
    check_input_for_security(g_bin_path);
    return 0;
}

static int CheckStopParameter()
{
    bool cond = (ctl_command == STOP_COMMAND) && (shutdown_mode_num == SMART_MODE) && (g_commandOperationNodeId > 0);
    if (cond) {
        write_runlog2(ERROR,
            errcode(ERRCODE_PARAMETER_FAILURE), errmsg("can't stop one node or instance with -m normal."),
            errdetail("N/A"), errmodule(MOD_CMCTL), errcause("The cmdline entered by the user is incorrect."),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        return 1;
    }

    cond = (ctl_command == STOP_COMMAND) && (shutdown_mode_num == RESUME_MODE) && (g_commandOperationNodeId > 0);
    if (cond) {
        write_runlog2(ERROR, errcode(ERRCODE_PARAMETER_FAILURE),
            errmsg("can't stop one node or instance with -m resume."),
            errdetail("N/A"), errmodule(MOD_CMCTL),
            errcause("%s: The cmdline entered by the user is incorrect.", g_progname),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        return 1;
    }

    cond = (ctl_command == STOP_COMMAND) && (shutdown_mode_num == RESUME_MODE) &&
        (g_command_operation_azName != NULL);
    if (cond) {
        write_runlog2(ERROR, errcode(ERRCODE_PARAMETER_FAILURE),
            errmsg("can't stop one availability zone with -m resume."),
            errdetail("N/A"), errmodule(MOD_CMCTL),
            errcause("%s: The cmdline entered by the user is incorrect.", g_progname),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        return 1;
    }
    return 0;
}

static int SetAndGetCheckParameter()
{
    bool cond = (log_level_set == NULL) && (cm_arbitration_mode_set == NULL) && (cm_switchover_az_mode_set == NULL) &&
        (cm_logic_cluster_restart_mode_set == NULL) && (g_cmsPromoteMode == NULL) && (ctl_command == CM_SET_COMMAND);
    if (cond) {
        write_runlog2(ERROR, errcode(ERRCODE_PARAMETER_FAILURE),
            errmsg("log level or cm server arbitration mode must be specified."), errdetail("N/A"),
            errmodule(MOD_CMCTL), errcause("%s: The cmdline entered by the user is incorrect.", g_progname),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        return 1;
    }

    cond = ((log_level_set != NULL) || (cm_arbitration_mode_set != NULL) || (cm_switchover_az_mode_set != NULL) ||
        (cm_logic_cluster_restart_mode_set != NULL)) && (g_cmsPromoteMode == NULL) && (ctl_command == CM_GET_COMMAND);
    if (cond) {
        write_runlog2(ERROR, errcode(ERRCODE_PARAMETER_FAILURE),
            errmsg("log level or cm server arbitration mode need not be specified."), errdetail("N/A"),
            errmodule(MOD_CMCTL), errcause("%s: The cmdline entered by the user is incorrect.", g_progname),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        return 1;
    }
    return 0;
}

static int QueryCheckParameter(const CtlOption *ctx)
{
    bool cond = (ctl_command == CM_QUERY_COMMAND) && (g_cmData[0] != '\0') && !g_commandRelationship &&
        (g_commandOperationNodeId != 0);
    if (cond) {
        write_runlog2(ERROR, errcode(ERRCODE_PARAMETER_FAILURE), errmsg("-R is needed."), errdetail("N/A"),
            errmodule(MOD_CMCTL), errcause("%s: The cmdline entered by the user is incorrect.", g_progname),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        return 1;
    }

    cond = (ctl_command == CM_QUERY_COMMAND) && (g_cmData[0] == '\0') && g_commandRelationship &&
        (g_commandOperationNodeId != 0);
    if (cond) {
        write_runlog2(ERROR, errcode(ERRCODE_PARAMETER_FAILURE), errmsg("-D is needed."), errdetail("N/A"),
            errmodule(MOD_CMCTL), errcause("%s: The cmdline entered by the user is incorrect.", g_progname),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        return 1;
    }

    cond = (ctl_command == CM_QUERY_COMMAND) && (g_cmData[0] != '\0') && !g_commandRelationship &&
        (g_commandOperationNodeId == 0);
    if (cond) {
        write_runlog2(ERROR, errcode(ERRCODE_PARAMETER_FAILURE), errmsg("-n and -R are needed."), errdetail("N/A"),
            errmodule(MOD_CMCTL), errcause("%s: The cmdline entered by the user is incorrect.", g_progname),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        return 1;
    }

    cond = (ctl_command == CM_QUERY_COMMAND) && (g_cmData[0] == '\0') && g_commandRelationship &&
        (g_commandOperationNodeId == 0);
    if (cond) {
        write_runlog2(ERROR, errcode(ERRCODE_PARAMETER_FAILURE), errmsg("-n and -D are needed."), errdetail("N/A"),
            errmodule(MOD_CMCTL), errcause("%s: The cmdline entered by the user is incorrect.", g_progname),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        return 1;
    }

    cond = (ctl_command == CM_QUERY_COMMAND) && ((do_force != 0) || switchover_all_quick ||
        ctx->switchover.switchoverAll || ctx->switchover.switchoverFull || ctx->build.isNeedCmsBuild);
    if (cond) {
        write_runlog2(ERROR, errcode(ERRCODE_PARAMETER_FAILURE), errmsg("unsupported parameters."), errdetail("N/A"),
            errmodule(MOD_CMCTL), errcause("%s: The cmdline entered by the user is incorrect.", g_progname),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        return 1;
    }

    return 0;
}

static int CheckAbnormal(const CtlOption *ctx)
{
    if (ctl_command == NO_COMMAND) {
        write_runlog2(ERROR, errcode(ERRCODE_PARAMETER_FAILURE), errmsg("no operation specified."),
            errdetail("N/A"), errmodule(MOD_CMCTL), errcause("The cmdline entered by the user is incorrect."),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        return 1;
    }
    /* 0 indicates that no node is specified */
    if (ctx->comm.nodeId == 0) {
        return 0;
    }
    uint32 nodeIndex = get_node_index(ctx->comm.nodeId);
    if (nodeIndex == INVALID_NODE_NUM) {
        write_runlog2(ERROR, errcode(ERRCODE_PARAMETER_FAILURE),
            errmsg("-n node(%u) is invalid.", ctx->comm.nodeId),
            errdetail("N/A"), errmodule(MOD_CMCTL), errcause("The cmdline entered by the user is incorrect."),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        return 1;
    }
    return 0;
}

static int CheckCommandNotSwitchoverAll(const CtlOption *ctx)
{
    bool cond = (g_commandOperationNodeId == 0) ||
        (get_node_index(g_commandOperationNodeId) >= g_nodeHeader.nodeCount);
    if (cond) {
        write_runlog2(ERROR, errcode(ERRCODE_PARAMETER_FAILURE),
            errmsg("-n node(%u) is invalid.", g_commandOperationNodeId),
            errdetail("N/A"), errmodule(MOD_CMCTL), errcause("The cmdline entered by the user is incorrect."),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        return 1;
    }

    cond = (ctx->build.parallel < PARALLELISM_MIN) || (ctx->build.parallel > PARALLELISM_MAX);
    if (cond) {
        write_runlog2(ERROR, errcode(ERRCODE_PARAMETER_FAILURE),
            errmsg("-j parallelism(%d) is invalid.", ctx->build.parallel),
            errdetail("it must in the range of 0 to 16."), errmodule(MOD_CMCTL),
            errcause("The cmdline entered by the user is incorrect."),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        return 1;
    }
    return 0;
}

static int CheckCommandSwitchoverAll(void)
{
    if (g_commandOperationNodeId != 0 || g_cmData[0] != '\0') {
        write_runlog2(ERROR, errcode(ERRCODE_PARAMETER_FAILURE),
            errmsg("switchover -a don't need other parameter."),
            errdetail("N/A"), errmodule(MOD_CMCTL), errcause("The cmdline entered by the user is incorrect."),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        return 1;
    }
    return 0;
}

static int CheckCommandQueryLcOperation(void)
{
    if (g_coupleQuery) {
        return 0;
    }
    if (ctl_command == CM_QUERY_COMMAND && lc_operation) {
        if (g_detailQuery) {
            write_runlog2(ERROR, errcode(ERRCODE_PARAMETER_FAILURE), errmsg("-C is needed."), errdetail("N/A"),
                          errmodule(MOD_CMCTL), errcause("%s: The cmdline entered by the user is incorrect.", g_progname),
                          erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        } else {
            write_runlog2(ERROR, errcode(ERRCODE_PARAMETER_FAILURE), errmsg("-Cv is needed."),
                          errdetail("N/A"), errmodule(MOD_CMCTL),
                          errcause("%s: The cmdline entered by the user is incorrect.", g_progname),
                          erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        }
        return 1;
    }
    return 0;
}

static int CheckCommandQuery(void)
{
    bool cond = (ctl_command == CM_QUERY_COMMAND) && (!g_availabilityZoneCommand) &&
        (g_command_operation_azName != NULL);
    if (cond) {
        write_runlog2(ERROR, errcode(ERRCODE_PARAMETER_FAILURE),
            errmsg("-z value must be \"ALL\" when query mppdb cluster."), errdetail("N/A"),
            errmodule(MOD_CMCTL), errcause("%s: The cmdline entered by the user is incorrect.", g_progname),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        return 1;
    }

    cond = (g_coupleQuery && !g_detailQuery) || (g_paralleRedoState && !g_detailQuery);
    if (cond) {
        write_runlog2(ERROR, errcode(ERRCODE_PARAMETER_FAILURE), errmsg("-v is needed."), errdetail("N/A"),
            errmodule(MOD_CMCTL), errcause("%s: The cmdline entered by the user is incorrect.", g_progname),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        return 1;
    }

    cond = (g_formatQuery && !g_coupleQuery && !g_detailQuery);
    if (cond) {
        write_runlog2(ERROR, errcode(ERRCODE_PARAMETER_FAILURE), errmsg("-Cv is needed."), errdetail("N/A"),
                      errmodule(MOD_CMCTL), errcause("%s: The cmdline entered by the user is incorrect.", g_progname),
                      erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        return 1;
    }

    cond = (g_formatQuery && !g_coupleQuery && g_detailQuery);
    if (cond) {
        write_runlog2(ERROR, errcode(ERRCODE_PARAMETER_FAILURE), errmsg("-C is needed."), errdetail("N/A"),
                      errmodule(MOD_CMCTL), errcause("%s: The cmdline entered by the user is incorrect.", g_progname),
                      erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        return 1;
    }

    CM_RETURN_INT_IFERR(CheckCommandQueryLcOperation());

    cond = (ctl_command == CM_QUERY_COMMAND) && !logic_cluster_query &&
        (g_command_operation_lcName != NULL) && (g_logic_cluster_count > 0);
    if (cond) {
        write_runlog2(ERROR, errcode(ERRCODE_PARAMETER_FAILURE),
            errmsg("-L value must be \"ALL\" when query logic cluster."), errdetail("N/A"),
            errmodule(MOD_CMCTL), errcause("%s: The cmdline entered by the user is incorrect.", g_progname),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        return 1;
    }
    return 0;
}

static int CheckCommandExceptSwitchover()
{
    bool cond = (g_commandOperationNodeId > 0) &&
        (get_node_index(g_commandOperationNodeId) >= g_nodeHeader.nodeCount);
    if (cond) {
        write_runlog2(ERROR, errcode(ERRCODE_PARAMETER_FAILURE),
            errmsg("-n node(%u) is invalid.", g_commandOperationNodeId),
            errdetail("N/A"), errmodule(MOD_CMCTL), errcause("The cmdline entered by the user is incorrect."),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        return 1;
    }

    cond = (g_cmData[0] != '\0') && !g_commandOperationNodeId;
    if (cond) {
        write_runlog2(ERROR, errcode(ERRCODE_PARAMETER_FAILURE), errmsg("-n node is needed."),
            errdetail("N/A"), errmodule(MOD_CMCTL), errcause("The cmdline entered by the user is incorrect."),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        return 1;
    }

    CM_RETURN_INT_IFERR(CheckStopParameter());

    cond = (g_balanceQuery || g_ipQuery || g_dataPathQuery || g_fencedUdfQuery || g_abnormalQuery || g_portQuery ||
        g_startStatusQuery) && !g_coupleQuery;
    if (cond) {
        write_runlog2(ERROR, errcode(ERRCODE_PARAMETER_FAILURE), errmsg("%s: -C is needed.", g_progname),
            errdetail("N/A"), errmodule(MOD_CMCTL), errcause("The cmdline entered by the user is incorrect."),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        return 1;
    }

    CM_RETURN_INT_IFERR(CheckCommandQuery());

    cond = (ctl_command == RESTART_COMMAND) && !logic_cluster_restart && (g_command_operation_lcName != NULL) &&
        (g_logic_cluster_count > 0);
    if (cond) {
        write_runlog2(ERROR, errcode(ERRCODE_PARAMETER_FAILURE),
            errmsg("unrecognized LC name \"%s\".", g_command_operation_lcName), errdetail("N/A"),
            errmodule(MOD_CMCTL), errcause("%s: The cmdline entered by the user is incorrect.", g_progname),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        return 1;
    }
    return 0;
}

static int CheckCommandCore(const CtlOption *ctx)
{
    bool condNotSwitchoverAll = (ctl_command == CM_SWITCHOVER_COMMAND && !ctx->switchover.switchoverAll &&
        !ctx->switchover.switchoverFull && (g_command_operation_azName == NULL && !switchover_all_quick)) ||
        (ctl_command == CM_BUILD_COMMAND && !(ctx->build.isNeedCmsBuild && (g_commandOperationNodeId == 0)));
    bool condSwitchoverAll = (ctl_command == CM_SWITCHOVER_COMMAND) && ctx->switchover.switchoverAll;
    bool condExceptSwitchover = (ctl_command == START_COMMAND) || (ctl_command == STOP_COMMAND) ||
        (ctl_command == CM_QUERY_COMMAND) || (ctl_command == RESTART_COMMAND) ||
        (ctl_command == CM_FINISHREDO_COMMAND);

    if (condNotSwitchoverAll) {
        CM_RETURN_INT_IFERR(CheckCommandNotSwitchoverAll(ctx));
    } else if (condSwitchoverAll) {
        CM_RETURN_INT_IFERR(CheckCommandSwitchoverAll());
    } else if (condExceptSwitchover) {
        CM_RETURN_INT_IFERR(CheckCommandExceptSwitchover());
    }
    return 0;
}

static void CheckCommandOperationNodeId(void)
{
    if ((g_cmData[0] == '\0') && g_commandOperationNodeId != 0) {
        write_runlog2(ERROR, errcode(ERRCODE_PARAMETER_FAILURE), errmsg("-D is needed."), errdetail("N/A"),
            errmodule(MOD_CMCTL), errcause("%s: The cmdline entered by the user is incorrect.", g_progname),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
    } else if ((g_cmData[0] != '\0') && g_commandOperationNodeId == 0) {
        write_runlog2(ERROR, errcode(ERRCODE_PARAMETER_FAILURE), errmsg("-n is needed."), errdetail("N/A"),
            errmodule(MOD_CMCTL), errcause("%s: The cmdline entered by the user is incorrect.", g_progname),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
    } else {
        write_runlog2(ERROR, errcode(ERRCODE_PARAMETER_FAILURE), errmsg("-n and -D are needed."),
            errdetail("N/A"), errmodule(MOD_CMCTL),
            errcause("%s: The cmdline entered by the user is incorrect.", g_progname),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
    }
}

static int CheckCommandRelationship(const CtlOption *ctx)
{
    bool cond = (ctl_command == CM_QUERY_COMMAND) && (g_cmData[0] != '\0') && g_commandRelationship &&
        (g_commandOperationNodeId == 0);
    if (cond) {
        write_runlog2(ERROR, errcode(ERRCODE_PARAMETER_FAILURE), errmsg("-n is needed."), errdetail("N/A"),
            errmodule(MOD_CMCTL), errcause("%s: The cmdline entered by the user is incorrect.", g_progname),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        return 1;
    }

    CM_RETURN_INT_IFERR(QueryCheckParameter(ctx));

    cond = g_commandRelationship && ((g_cmData[0] == '\0') || g_commandOperationNodeId == 0);
    if (cond) {
        CheckCommandOperationNodeId();
        return 1;
    }
    return 0;
}

static int CheckForOtherCommands(const CtlOption *ctx)
{
    bool cond = (ctx->switchover.switchoverAll && g_commandOperationNodeId) ||
        (ctx->switchover.switchoverFull && g_commandOperationNodeId) ||
        (g_command_operation_azName != NULL && ctx->switchover.switchoverAll) ||
        (g_command_operation_azName != NULL && ctx->switchover.switchoverFull) ||
        (ctx->switchover.switchoverAll && ctx->switchover.switchoverFull);
    if (cond) {
        write_runlog2(ERROR, errcode(ERRCODE_PARAMETER_FAILURE), errmsg("Please check the usage of switchover."),
            errdetail("N/A"), errmodule(MOD_CMCTL), errcause("The cmdline entered by the user is incorrect."),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        return 1;
    }

    cond = ((g_command_operation_azName != NULL) && g_commandOperationNodeId);
    if (cond) {
        write_runlog2(ERROR, errcode(ERRCODE_PARAMETER_FAILURE),
            errmsg("-n and -z cannot be specified at the same time."),
            errdetail("N/A"),
            errmodule(MOD_CMCTL), errcause("The cmdline entered by the user is incorrect."),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        return 1;
    }
#ifdef ENABLE_MULTIPLE_NODES
    cond = cn_resumes_restart && (g_command_operation_azName != NULL || g_commandOperationNodeId);
    if (cond) {
        write_runlog2(ERROR, errcode(ERRCODE_PARAMETER_FAILURE),
            errmsg("-m cannot be specified at the same time with -n or -z."), errdetail("N/A"),
            errmodule(MOD_CMCTL), errcause("%s: The cmdline entered by the user is incorrect.", g_progname),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        return 1;
    }
#endif
    CM_RETURN_INT_IFERR(CheckCommandCore(ctx));
    CM_RETURN_INT_IFERR(CheckCommandRelationship(ctx));

    cond = (ctl_command == CM_SET_COMMAND) && (ctx->guc.nodeType != NODE_TYPE_UNDEF);
    if (cond) {
        if (CheckGucSetParameter(ctx) != CM_SUCCESS) {
            return 1;
        }
    } else {
        CM_RETURN_INT_IFERR(SetAndGetCheckParameter());
    }

    return 0;
}

static int CheckCtlInputAzName(void)
{
    bool condition = (g_command_operation_azName != NULL) && !checkAZNameInCluster(g_command_operation_azName);
    if (condition) {
        write_runlog2(ERROR, errcode(ERRCODE_PARAMETER_FAILURE),
            errmsg("There is no \"%s\" information in cluster.", g_command_operation_azName), errdetail("N/A"),
            errmodule(MOD_CMCTL), errcause("%s: The cmdline entered by the user is incorrect.", g_progname),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        return 1;
    }
    return 0;
}

static int CheckCtlInputParameter(const CtlOption *ctx)
{
    CM_RETURN_INT_IFERR(CheckAbnormal(ctx));

    /* need -D */
    bool condition = (ctl_command == CM_SWITCHOVER_COMMAND && !ctx->switchover.switchoverAll &&
        !ctx->switchover.switchoverFull && (g_command_operation_azName == NULL && !switchover_all_quick)) ||
        (ctl_command == CM_BUILD_COMMAND && !ctx->build.isNeedCmsBuild) || ctl_command == CM_REMOVE_COMMAND ||
        ctl_command == CM_STARTCM_COMMAND || ctl_command == CM_STOPCM_COMMAND || ctl_command == CM_DISABLE_COMMAND ||
        ctl_command == CM_ENCRYPT_COMMAND;
    if (condition) {
        if (g_cmData[0] == '\0') {
            write_runlog2(ERROR, errcode(ERRCODE_PARAMETER_FAILURE), errmsg("no data directory specified."),
                errdetail("N/A"), errmodule(MOD_CMCTL), errcause("The cmdline entered by the user is incorrect."),
                erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
            return 1;
        }
    }

    /* check other commands except 'CM_CHECK_COMMAND' */
    if (ctl_command != CM_CHECK_COMMAND) {
        CM_RETURN_INT_IFERR(CheckForOtherCommands(ctx));
    } else {
        CM_RETURN_INT_IFERR(CheckInputParameter());
    }

    /* Check if user input az name is in the cluster */
    CM_RETURN_INT_IFERR(CheckCtlInputAzName());

    return 0;
}

void stop_flag(void)
{
    got_stop = true;
    if (!g_execute_cmctl_success) {
        cm_sleep(6);
    }
}

static void PathStrCheck(const char *inPath, char *outPath)
{
    if (inPath == NULL) {
        return;
    }
    size_t length = strlen(inPath);
    if (length == 0) {
        return;
    }

    char tempChar;
    while ((tempChar = *inPath++) != '\0') {
        if (tempChar == '/' && *inPath == '/') {
            continue;
        }
        *outPath = tempChar;
        outPath++;
    }
    if (length > 1 && outPath[strlen(outPath) - 1] == '/') {
        outPath[strlen(outPath) - 1] = '\0';
    }
    return;
}

static void ReleaseResource()
{
    if (CmServer_conn != NULL) {
        CMPQfinish(CmServer_conn);
        CmServer_conn = NULL;
    }
    FreeSslOpton();
    FREE_AND_RESET(g_logFile);

#if ((defined(ENABLE_MULTIPLE_NODES)) || (defined(ENABLE_PRIVATEGAUSS)))
    FREE_AND_RESET(hotpatch_path);
#endif
    FreeDdbInfo();
}

static status_t GetCtlCommand(int argc, char **argv)
{
    if (optind >= argc) {
        return CM_SUCCESS;
    }

    /* Process an action */
    if (ctl_command != NO_COMMAND) {
        write_runlog2(FATAL, errcode(ERRCODE_PARAMETER_FAILURE),
            errmsg("too many command-line arguments (first is \"%s\").", argv[optind]), errdetail("N/A"),
            errmodule(MOD_CMCTL), errcause("%s: The cmdline entered by the user is incorrect.", g_progname),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        DoAdvice();
        return CM_ERROR;
    }

    unordered_map<string, CtlCommand>::iterator it = g_optToCommand.find(argv[optind]);
    if (it != g_optToCommand.end()) {
        ctl_command = it->second;
    } else {
        write_runlog2(FATAL, errcode(ERRCODE_PARAMETER_FAILURE),
            errmsg("unrecognized operation mode \"%s\".", argv[optind]), errdetail("N/A"),
            errmodule(MOD_CMCTL), errcause("%s: The cmdline entered by the user is incorrect.", g_progname),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        DoAdvice();
        return CM_ERROR;
    }

    ++optind;

    return CM_SUCCESS;
}

void InitCtlOptionParams(CtlOption *ctx)
{
    errno_t rc = memset_s(ctx, sizeof(CtlOption), 0, sizeof(CtlOption));
    securec_check_errno(rc, (void)rc);

    ctx->guc.keyMod = SERVER_MODE;
    ctx->dcfOption.group = -1;
    ctx->dcfOption.priority = -1;
}

status_t GetSetParameterAndValue(char *str, GucOption *gucCtx)
{
    char *para;
    char *val;
    char *buf;

    if (str[0] == '=') {
        write_runlog(LOG, "need input parameter.\n");
        return CM_ERROR;
    }
    para = strtok_s(str, "=", &buf);
    if (para == NULL) {
        write_runlog(LOG, "need input parameter.\n");
        return CM_ERROR;
    }
    val = strtok_s(NULL, "=", &buf);
    if (val == NULL) {
        write_runlog(LOG, "need input value.\n");
        return CM_ERROR;
    }
    if (strcmp(buf, "") != 0) {
        write_runlog(LOG, "too many command line arguments.\n");
        return CM_ERROR;
    }
    gucCtx->parameter = xstrdup(para);
    gucCtx->value = xstrdup(val);

    return CM_SUCCESS;
}

static status_t CheckKeyMode(const char* mode, GucOption *gucCtx)
{
    size_t sLen = strlen("server");
    size_t clen = strlen("client");

    if (mode == NULL || mode[0] == '\0' || (strcmp(mode, "-D") == 0)) {
        write_runlog(LOG, "-M is invalid, try \"%s --help\" for more information.\n", g_progname);
        return CM_ERROR;
    }
    if ((strncmp(mode, "server", sLen) == 0) && (mode[sLen] == '\0')) {
        gucCtx->keyMod = SERVER_MODE;
    } else if ((strncmp(mode, "client", clen) == 0) && (mode[clen] == '\0')) {
        gucCtx->keyMod = CLIENT_MODE;
    } else {
        write_runlog(LOG, "mode \"%s\" is not support, try \"%s --help\" for more information.\n", mode, g_progname);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static void CheckArgcType(int argc, const char * const *argv)
{
    if (argc > 1) {
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-?") == 0) {
            DoHelp(g_progname);
            exit(0);
        } else if (strcmp(argv[1], "-V") == 0 || strcmp(argv[1], "--version") == 0) {
            (void)puts("cm_ctl " DEF_CM_VERSION);
            exit(0);
        }
    }
}

static int MakeupCmdline(int argc, char** argv)
{
    if (argc > 1 && (strcmp(argv[1], "ddb") == 0)) {
        return 0;
    }
    uint32 cmdLen;
    int ret = sprintf_s(g_cmdLine, MAX_PATH_LEN, "%s", argv[0]);
    securec_check_intval(ret, (void)ret);
    cmdLen = (uint32)strlen(g_cmdLine);
    for (int32 i = 1; i < argc; i++) {
        uint32 optLen = ((uint32)strlen(argv[i]) + 1);
        if ((cmdLen + optLen) >= MAX_PATH_LEN) {
            (void)printf(_("cmd is too long, %u.\n"), (uint32)(cmdLen + optLen));
            return CM_EXIT;
        }
        ret = sprintf_s(g_cmdLine + cmdLen, MAX_PATH_LEN - cmdLen, " %s", argv[i]);
        securec_check_intval(ret, (void)ret);
        cmdLen += optLen;
    }
    return 0;
}

static void CtlDccCommand(int argc, char** argv)
{
    if (argc > 1 && (strcmp(argv[1], "ddb") == 0)) {
        write_runlog(DEBUG1, "ip: \"%s\", cmd: cm_ctl ddb ...\n", g_currentNode->sshChannel[0]);
        DoDccCmd(argc, argv);
        exit(0);
    }
}

static void MatchCmdArgb(CtlOption *ctlCtx)
{
    if (optarg != NULL && strcmp("full", optarg) == 0) {
        ctlCtx->build.doFullBuild = 1;
    } else {
        if (optarg == NULL) {
            write_runlog2(FATAL, errcode(ERRCODE_PARAMETER_FAILURE),
                errmsg("unrecognized build mode."), errdetail("N/A"), errmodule(MOD_CMCTL),
                errcause("%s: The cmdline entered by the user is incorrect.", g_progname),
                erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
            exit(1);
        }
        write_runlog2(FATAL, errcode(ERRCODE_PARAMETER_FAILURE),
            errmsg("unrecognized build mode \"%s\".", optarg), errdetail("N/A"), errmodule(MOD_CMCTL),
            errcause("%s: The cmdline entered by the user is incorrect.", g_progname),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        exit(1);
    }
}

static void MatchCmdArgD(bool *setDataPath)
{
    if (optarg != NULL) {
        if (strlen(optarg) > (MAX_PATH_LEN - 1)) {
            write_runlog2(FATAL, errcode(ERRCODE_PARAMETER_FAILURE),
                errmsg("-D path is too long.\n"), errdetail("N/A"), errmodule(MOD_CMCTL),
                errcause("%s: The cmdline entered by the user is incorrect.", g_progname),
                erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
            exit(1);
        }
        /* envVar cannot be free, see putenv */
        char* envVar = (char*)pg_malloc(strlen(optarg) + 8);
        *setDataPath = true;

        char *cmDataPath = xstrdup(optarg);
        check_input_for_security(cmDataPath);
        /* check '/' in the cmDataPath */
        char outPath[MAX_PATH_LEN] = {0};
        PathStrCheck(cmDataPath, outPath);
        int ret = snprintf_s(cmDataPath, strlen(outPath) + 1, strlen(outPath), "%s", outPath);
        securec_check_intval(ret, (void)ret);

        ret = snprintf_s(envVar, strlen(optarg) + 8, strlen(optarg) + 7, "CMDATA=%s", cmDataPath);
        securec_check_intval(ret, (void)ret);
        (void)putenv(envVar);
        /*
         * We could pass PGDATA just in an environment
         * variable but we do -D too for clearer postmaster
         * 'ps' display
         */
        FREE_AND_RESET(pgdata_opt);
        pgdata_opt = (char*)pg_malloc(strlen(cmDataPath) + 7);
        ret = snprintf_s(pgdata_opt, strlen(cmDataPath) + 7, strlen(cmDataPath) + 6,
            "-D \"%s\" ", cmDataPath);
        securec_check_intval(ret, (void)ret);
        check_input_for_security(pgdata_opt);
        FREE_AND_RESET(cmDataPath);
    } else {
        write_runlog2(FATAL, errcode(ERRCODE_PARAMETER_FAILURE),
            errmsg("-D path is invalid."),
            errdetail("N/A"), errmodule(MOD_CMCTL),
            errcause("%s: The cmdline entered by the user is incorrect.", g_progname),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        DoAdvice();
        exit(1);
    }
}

static void MatchCmdArgn(CtlOption *ctlCtx)
{
    if (CM_is_str_all_digit(optarg) != 0 || CmAtoi(optarg, 0) == 0) {
        write_runlog2(FATAL, errcode(ERRCODE_PARAMETER_FAILURE),
            errmsg("-n node(%s) is invalid.", optarg), errdetail("N/A"),
            errmodule(MOD_CMCTL),
            errcause("%s: The cmdline entered by the user is incorrect.", g_progname),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        DoAdvice();
        exit(1);
    }
    if (g_nodeIdSet) {
        write_runlog2(FATAL, errcode(ERRCODE_PARAMETER_FAILURE),
            errmsg("-n and -N can not be set at the same time."), errdetail("N/A"),
            errmodule(MOD_CMCTL),
            errcause("%s: The cmdline entered by the user is incorrect.", g_progname),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        DoAdvice();
        exit(1);
    }
    g_nodeIdSet = true;
    g_commandOperationNodeId = (uint32)CmAtoi(optarg, 0);
    ctlCtx->comm.nodeId = static_cast<uint32>(CmAtoi(optarg, 0));
}

static void MatchCmdArgN(void)
{
    if (g_nodeIdSet) {
        write_runlog2(FATAL, errcode(ERRCODE_PARAMETER_FAILURE),
            errmsg("-n and -N can not be set at the same time."), errdetail("N/A"),
            errmodule(MOD_CMCTL),
            errcause("%s: The cmdline entered by the user is incorrect.", g_progname),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        DoAdvice();
        exit(1);
    }
    g_nodeIdSet = true;
    g_commandOperationNodeId = g_currentNode->node;
}

static void MatchCmdArgI(void)
{
    if (CM_is_str_all_digit(optarg) != 0 || CmAtoi(optarg, 0) == 0) {
        write_runlog2(FATAL, errcode(ERRCODE_PARAMETER_FAILURE),
            errmsg("-I instance(%s) is invalid.", optarg), errdetail("N/A"),
            errmodule(MOD_CMCTL),
            errcause("%s: The cmdline entered by the user is incorrect.", g_progname),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        DoAdvice();
        exit(1);
    }
    g_commandOperationInstanceId = (uint32)CmAtoi(optarg, 0);
}

#ifdef ENABLE_MULTIPLE_NODES
static void MatchCmdArgR(void)
{
    g_commandRelationship = true;
    if (g_only_dn_cluster) {
        write_runlog2(FATAL, errcode(ERRCODE_PARAMETER_FAILURE),
            errmsg("-R only support when the cluster is single-inst."), errdetail("N/A"),
            errmodule(MOD_CMCTL),
            errcause("%s: The cmdline entered by the user is incorrect.", g_progname),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        exit(1);
    }
}
#endif

static void MatchCmdArgt(void)
{
    if (CM_is_str_all_digit(optarg) != 0) {
        write_runlog2(FATAL, errcode(ERRCODE_PARAMETER_FAILURE),
            errmsg("-t time is invalid."), errdetail("N/A"), errmodule(MOD_CMCTL),
            errcause("%s: The cmdline entered by the user is incorrect.", g_progname),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        DoAdvice();
        exit(1);
    }
    wait_seconds_set = true;
    g_waitSeconds = CmAtoi(optarg, 0);
}

#ifdef ENABLE_MULTIPLE_NODES
static void MatchCmdArgL(void)
{
    if (optarg != NULL) {
        lc_operation = true;
        if (!checkCmdLcName(optarg)) {
            exit(1);
        }
    }
}
#endif

static void MatchCmdArg1(void)
{
    if (optarg != NULL) {
        FREE_AND_RESET(log_level_set);
        log_level_set = xstrdup(optarg);
    } else {
        log_level_get = true;
    }
}

static void MatchCmdArg2(void)
{
    if (optarg != NULL) {
        FREE_AND_RESET(cm_arbitration_mode_set);
        cm_arbitration_mode_set = xstrdup(optarg);
    } else {
        cm_arbitration_mode_get = true;
    }
}

static void MatchCmdArg3(void)
{
    if (optarg != NULL) {
        FREE_AND_RESET(cm_switchover_az_mode_set);
        cm_switchover_az_mode_set = xstrdup(optarg);
    } else {
        cm_switchover_az_mode_get = true;
    }
}

static void MatchCmdArg4(void)
{
    if (optarg != NULL) {
        FREE_AND_RESET(cm_logic_cluster_restart_mode_set);
        cm_logic_cluster_restart_mode_set = xstrdup(optarg);
    }
}

static void MatchCmdArgDcfXmode(void)
{
    if (optarg != NULL) {
        FREE_AND_RESET(g_dcfXMode);
        g_dcfXMode = xstrdup(optarg);
    }
}

static void MatchCmdArgDcfVoteNum(void)
{
    if (CM_is_str_all_digit(optarg) != 0) {
        write_runlog2(FATAL, errcode(ERRCODE_PARAMETER_FAILURE), errmsg("-votenum is invalid."),
            errdetail("N/A"), errmodule(MOD_CMCTL),
            errcause("%s: The cmdline entered by the user is incorrect.", g_progname),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        DoAdvice();
        exit(1);
    }
    g_dcfVoteNum = CmAtoi(optarg, 0);
}

static void MatchCmdArgDcfRole(CtlOption *ctlCtx)
{
    if (optarg != NULL) {
        FREE_AND_RESET(ctlCtx->dcfOption.role);
        ctlCtx->dcfOption.role = xstrdup(optarg);
    }
}

static void MatchCmdArgDcfGroup(CtlOption *ctlCtx)
{
    if (CM_is_str_all_digit(optarg) != 0 || CmAtoi(optarg, -1) < 0) {
        write_runlog(ERROR, "dcfGroup is invalid.\n");
        DoAdvice();
        ctlCtx->dcfOption.group = ErrorCode;
        return;
    }
    ctlCtx->dcfOption.group = CmAtoi(optarg, -1);
}

static void MatchCmdArgDcfPriority(CtlOption *ctlCtx)
{
    if (CM_is_str_all_digit(optarg) != 0 || CmAtoi(optarg, -1) < 0) {
        write_runlog(ERROR, "dcfPriority is invalid.\n");
        DoAdvice();
        ctlCtx->dcfOption.priority = ErrorCode;
        return;
    }
    ctlCtx->dcfOption.priority = CmAtoi(optarg, -1);
}

static void MatchCmdArgMinorityAz(void)
{
    if (optarg != NULL) {
        CheckMinorityAZName(optarg);
    }
}

static void MatchCmdArgCmsPmode(void)
{
    if (optarg != NULL) {
        FREE_AND_RESET(g_cmsPromoteMode);
        g_cmsPromoteMode = xstrdup(optarg);
    }
}

static void ParseCmdArgsCore(int cmd, bool *setDataPath, CtlOption *ctlCtx)
{
    switch (cmd) {
        case 'a':
            ctlCtx->switchover.switchoverAll = true;
            break;
        case 'A':
            ctlCtx->switchover.switchoverFull = true;
            break;
        case 'b':
            MatchCmdArgb(ctlCtx);
            break;
        case 'D':
            MatchCmdArgD(setDataPath);
            break;
        case 'f':
            do_force = 1;
            ctlCtx->switchover.switchoverFast = true;
            break;
        case 'F':
            g_fencedUdfQuery = 1;
            break;
        case 'l':
            g_logFileSet = true;
            FREE_AND_RESET(g_logFile);
            g_logFile = xstrdup(optarg);
            canonicalize_path(g_logFile);
            check_input_for_security(g_logFile);
            break;
        case 'm':
            if (optarg != NULL) {
                set_mode(optarg);
            }
            break;
        case 'M':
            if (CheckKeyMode(optarg, &ctlCtx->guc) != CM_SUCCESS) {
                exit(1);
            }
            break;
        case 'n':
            MatchCmdArgn(ctlCtx);
            break;
        case 'N': /* Native node */
            MatchCmdArgN();
            break;
        case 'I':
            MatchCmdArgI();
            break;
#if ((defined(ENABLE_MULTIPLE_NODES)) || (defined(ENABLE_PRIVATEGAUSS)))
        case 'P':
            if (optarg != NULL) {
                hotpatch_path = xstrdup(optarg);
            }
            break;
        case 'E':
            if (optarg != NULL) {
                hotpatch_exec = xstrdup(optarg);
            }
            break;
#endif
#ifdef ENABLE_MULTIPLE_NODES
        case 'R':
            MatchCmdArgR();
            break;
#endif
        case 'x':
            g_abnormalQuery = true;
            break;
        case 'p':
            g_portQuery = true;
            break;
        case 'q':
            switchover_all_quick = true;
            break;
        case 't':
            MatchCmdArgt();
            break;
        case 'v':
            g_detailQuery = true;
            break;
        case 'w':
            g_formatQuery = true;
            break;
        case 'c':
            ctlCtx->build.isNeedCmsBuild = true;
            coordinator_dynamic_view = true;
            break;
        case 'C':
            g_coupleQuery = true;
            break;
        case 'g':
            backup_process_query = true;
            break;
        case 'd':
            g_dataPathQuery = true;
            break;
        case 'i':
            g_ipQuery = true;
            break;
#ifdef ENABLE_MULTIPLE_NODES
        case 'L':
            MatchCmdArgL();
            break;
#endif
        case 'B':
            FREE_AND_RESET(g_bin_name);
            g_bin_name = xstrdup(optarg);
            break;
        case 'j':
            if (optarg != NULL) {
                ctlCtx->build.parallel = CmAtoi(optarg, 0);
            }
            break;
        case 's':
            g_balanceQuery = true;
            break;
        case 'S':
            g_startStatusQuery = true;
            break;
        case 'T':
            FREE_AND_RESET(g_bin_path);
            g_bin_path = xstrdup(optarg);
            break;
        case 'r':
            g_paralleRedoState = true;
            break;
        case 'k':
            if (GetSetParameterAndValue(optarg, &ctlCtx->guc) == CM_ERROR) {
                exit(1);
            }
            break;
        case 'z':
            if (optarg != NULL) {
                checkCmdAZName(optarg);
            }
            break;
        case 1:
            MatchCmdArg1();
            break;
        case 2:
            MatchCmdArg2();
            break;
        case 3:
            MatchCmdArg3();
            break;
        case 4:
            MatchCmdArg4();
            break;
        case DCF_XMODE:
            MatchCmdArgDcfXmode();
            break;
        case DCF_VOTE_NUM:
            MatchCmdArgDcfVoteNum();
            break;
        case DCF_ROLE_MODE:
            MatchCmdArgDcfRole(ctlCtx);
            break;
        case MINORITY_AZ:
            MatchCmdArgMinorityAz();
            break;
        case CMS_P_MODE:
            MatchCmdArgCmsPmode();
            break;
        case CM_AGENT_MODE:
            ctlCtx->guc.nodeType = NODE_TYPE_AGENT;
            break;
        case CM_SERVER_MODE:
            ctlCtx->guc.nodeType = NODE_TYPE_SERVER;
            break;
        case CM_SWITCH_DDB:
            if (optarg != NULL) {
                ctlCtx->switchOption.ddbType = xstrdup(optarg);
            }
            break;
        case CM_SWITCH_COMMIT:
            ctlCtx->switchOption.isCommit = true;
            break;
        case CM_SWITCH_ROLLBACK:
            ctlCtx->switchOption.isRollback = true;
            break;
        case CM_SET_PARAM:
            ctlCtx->guc.needDoGuc = true;
            break;
        case DCF_GROUP:
            MatchCmdArgDcfGroup(ctlCtx);
            break;
        case DCF_PRIORITY:
            MatchCmdArgDcfPriority(ctlCtx);
            break;
        case RES_ADD:
            ctlCtx->resOpt.mode = RES_OP_ADD;
            break;
        case RES_EDIT:
            ctlCtx->resOpt.mode = RES_OP_EDIT;
            break;
        case RES_DEL:
            ctlCtx->resOpt.mode = RES_OP_DEL;
            break;
        case RES_CHECK:
            ctlCtx->resOpt.mode = RES_OP_CHECK;
            break;
        case RES_NAME_INPUT:
            ctlCtx->resOpt.resName = xstrdup(optarg);
            break;
        case RES_ATTR_INPUT:
            ctlCtx->resOpt.resAttr = xstrdup(optarg);
            break;
        case RES_ADD_INST_INPUT:
            ctlCtx->resOpt.inst.instName = xstrdup(optarg);
            ctlCtx->resOpt.inst.mode = RES_OP_ADD;
            break;
        case RES_DEL_INST_INPUT:
            ctlCtx->resOpt.inst.instName = xstrdup(optarg);
            ctlCtx->resOpt.inst.mode = RES_OP_DEL;
            break;
        case RES_EDIT_INST_INPUT:
            ctlCtx->resOpt.inst.instName = xstrdup(optarg);
            ctlCtx->resOpt.inst.mode = RES_OP_EDIT;
            break;
        case RES_INST_ATTR_INPUT:
            ctlCtx->resOpt.inst.instAttr = xstrdup(optarg);
            break;
        case RES_LIST:
            ctlCtx->resOpt.mode = RES_OP_LIST;
            break;
        case RES_LIST_INST_INPUT:
            ctlCtx->resOpt.inst.mode = RES_OP_LIST;
            break;
        default:
            /* getopt_long already issued a suitable error message */
            DoAdvice();
            exit(1);
    }
}

static void SetCommonDataPath(bool setDataPath, CtlOption *ctlCtx)
{
    int ret;
    if (setDataPath) {
        ret = cmctl_getenv("CMDATA", g_cmData, sizeof(g_cmData));
        if (ret != EOK) {
            write_runlog2(FATAL, errcode(ERRCODE_PARAMETER_FAILURE),
                errmsg("no cm directory specified."), errdetail("N/A"),
                errmodule(MOD_CMCTL), errcause("%s: The cmdline entered by the user is incorrect.", g_progname),
                erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
            exit(1);
        }

        check_input_for_security(g_cmData);
    }
    ctlCtx->comm.dataPath = xstrdup(g_cmData);
}

#if ((defined(ENABLE_MULTIPLE_NODES)) || (defined(ENABLE_PRIVATEGAUSS)))
static void CtlHotPatchComand(void)
{
    if (ctl_command == CM_HOTPATCH_COMMAND) {
        bool is_list = false;
        if (hotpatch_check(hotpatch_path, hotpatch_exec, &is_list) != 0) {
            write_runlog2(FATAL, errcode(ERRCODE_PARAMETER_FAILURE),
                errmsg("[PATCH-ERROR] hotpatch command or path set error."),
                errdetail("N/A"), errmodule(MOD_CMCTL), errcause("The cmdline entered by the user is incorrect."),
                erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
            DoAdvice();
            exit(1);
        }
    }
}
#endif

static void SetLogicClusterName(void)
{
    max_logic_cluster_name_len = (max_logic_cluster_name_len < strlen("logiccluster_name"))
        ? (uint32)strlen("logiccluster_name") : max_logic_cluster_name_len;
}

static void CtlCheckComandType(void)
{
    if (ctl_command != CM_CHECK_COMMAND) {
        SetLogicClusterName();

        if (g_etcd_num > 0 && g_etcd_num < ETCD_NUM_UPPER_LIMIT) {
            status_t st = ServerDdbInit();
            if (st != CM_SUCCESS) {
                write_runlog2(ERROR, errcode(ERRCODE_ETCD_OPEN_FAILURE), errmsg("Failed to open etcd."),
                    errdetail("N/A"), errmodule(MOD_CMCTL), errcause("Etcd is abnoraml."),
                    erraction("Please check the Cluster Status and try again."));
                FreeDdbInfo();
                exit(1);
            }
        }

#if ((defined(ENABLE_MULTIPLE_NODES)) || (defined(ENABLE_PRIVATEGAUSS)))
        CtlHotPatchComand();
#endif
     }
}

static void ExitFlagForCommand(void)
{
    bool cond = (ctl_command != CM_CHECK_COMMAND) && (ctl_command != START_COMMAND) &&
        (ctl_command != STOP_COMMAND) && (g_etcd_num != 0);
    if (cond) {
        (void)atexit(stop_flag);
    }
}

static void CtlCheckOther(const CtlOption *ctlCtx)
{
    if (CheckCtlInputParameter(ctlCtx) != 0) {
        DoAdvice();
        exit(1);
    }

    /* single node cluster can not do switchover/build operation, because there is no standby datanode. */
    if (g_single_node_cluster && (ctl_command == CM_SWITCHOVER_COMMAND || ctl_command == CM_BUILD_COMMAND)) {
        write_runlog2(FATAL, errcode(ERRCODE_PARAMETER_FAILURE), errmsg("no standby datanode in single node cluster."),
            errdetail("N/A"), errmodule(MOD_CMCTL), errcause("The cmdline entered by the user is incorrect."),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        DoAdvice();
        exit(1);
    }

    ExitFlagForCommand();
}

#ifdef ENABLE_MULTIPLE_NODES
static void DoRestartCommand(void)
{
    if (logic_cluster_restart && (g_logic_cluster_count > 0)) {
        do_logic_cluster_restart();
    } else if (g_logic_cluster_count == 0) {
        write_runlog2(FATAL, errcode(ERRCODE_PARAMETER_FAILURE), errmsg("restart logic cluster failed."),
            errdetail("there are no logic clusters, can't do restart."), errmodule(MOD_CMCTL),
            errcause("The cmdline entered by the user is incorrect."),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        exit(1);
    } else {
        write_runlog2(FATAL, errcode(ERRCODE_PARAMETER_FAILURE), errmsg("restart logic cluster failed"),
            errdetail("-L is need."), errmodule(MOD_CMCTL),
            errcause("The cmdline entered by the user is incorrect."),
            erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
        exit(1);
    }
}
#endif

static void DoQueryCommand(int *status)
{
    if (backup_process_query) {
        *status = do_global_barrier_query();
    } else {
        *status = do_query();
    }

    if (g_logFileSet && (g_logFilePtr != NULL)) {
        (void)fclose(g_logFilePtr);
        g_logFilePtr = NULL;
    }
}

static void DoSetCommand(int *status, CtlOption *ctlCtx)
{
    if (ctlCtx->guc.needDoGuc || ctlCtx->guc.nodeType != NODE_TYPE_UNDEF) {
        ctlCtx->guc.gucCommand = SET_CONF_COMMAND;
        *status = DoGuc(ctlCtx);
    } else {
        *status = do_set();
    }
}

static int DoViewCommand(void)
{
    if (coordinator_dynamic_view) {
        if (!do_dynamic_view()) {
            return 1;
        }
    } else {
        do_view();
    }
    return 0;
}

static void DoReloadCommand(int *status, CtlOption *ctlCtx)
{
    if (ctlCtx->guc.needDoGuc || ctlCtx->guc.nodeType != NODE_TYPE_UNDEF) {
        ctlCtx->guc.gucCommand = RELOAD_CONF_COMMAND;
        *status = DoGuc(ctlCtx);
    } else {
        if (g_clusterType == V3SingleInstCluster) {
            write_runlog(LOG, "can't do cms reload, please add --agent or --server.\n");
            return;
        }
        *status = DoReload();
    }
}

static void CtlCommandProcessCore(int *status, CtlOption *ctlCtx)
{
    switch (ctl_command) {
#ifdef ENABLE_MULTIPLE_NODES
        case RESTART_COMMAND:
            DoRestartCommand();
            break;
#endif
        case START_COMMAND:
            *status = do_start();
            break;
        case CM_SWITCHOVER_COMMAND:
            *status = DoSwitchover(ctlCtx);
            break;
        case CM_BUILD_COMMAND:
            *status = DoBuild(ctlCtx);
            break;
        case STOP_COMMAND:
            *status = DoStop();
            break;
        case CM_QUERY_COMMAND:
            DoQueryCommand(status);
            break;
        case CM_SET_COMMAND:
            DoSetCommand(status, ctlCtx);
            break;
        case CM_GET_COMMAND:
            *status = do_get();
            break;
        case CM_VIEW_COMMAND:
            *status = DoViewCommand();
            break;
        case CM_CHECK_COMMAND:
            *status = do_check();
            break;
        case CM_SETMODE_COMMAND:
            *status = do_setmode();
            break;
#if ((defined(ENABLE_MULTIPLE_NODES)) || (defined(ENABLE_PRIVATEGAUSS)))
        case CM_HOTPATCH_COMMAND:
            *status = do_hotpatch(hotpatch_exec, hotpatch_path);
            break;
#endif
#ifdef ENABLE_MULTIPLE_NODES
        case CM_DISABLE_COMMAND:
            *status = do_disable_cn();
            break;
#endif
#ifdef ENABLE_LIBPQ
        case CM_FINISHREDO_COMMAND:
            *status = do_finish_redo();
            break;
        case CM_DCF_SETRUNMODE_COMMAND:
            *status = DoSetRunMode();
            break;
        case CM_DCF_CHANGEROLE_COMMAND:
            *status = DoChangeRole(ctlCtx);
            break;
        case CM_DCF_CHANGEMEMBER_COMMAND:
            *status = DoChangeMember(ctlCtx);
            break;
#endif
        case CM_RELOAD_COMMAND:
            DoReloadCommand(status, ctlCtx);
            break;
        case CM_LIST_COMMAND:
            ctlCtx->guc.gucCommand = LIST_CONF_COMMAND;
            *status = DoGuc(ctlCtx);
            break;
        case CM_ENCRYPT_COMMAND:
            *status = DoEncrypt(ctlCtx);
            break;
        case CM_SWITCH_COMMAND:
            *status = DoSwitch(ctlCtx);
            break;
        case CM_RES_COMMAND:
            *status = DoResCommand(&(ctlCtx->resOpt));
            break;
        case CM_SHOW_COMMAND:
            *status = DoShowCommand();
            break;
        case CM_PAUSE_COMMAND:
            *status = DoPause();
            break;
        case CM_RESUME_COMMAND:
            *status = DoResume();
            break;
        default:
            write_runlog2(ERROR, errcode(ERRCODE_PARAMETER_FAILURE), errmsg("The option parameter is not specified."),
                errdetail("N/A"), errmodule(MOD_CMCTL), errcause("The cmdline entered by the user is incorrect."),
                erraction("Please check the cmdline entered by the user(%s).", g_cmdLine));
            break;
    }
}

bool CheckInputForSecurity(const char *input)
{
    if (strstr(input, "%") == NULL) {
        return true;
    }
    (void)printf("input constains invalid character.");
    return false;
}

static bool RecordCommands(int argc, char **argv)
{
    int rc;
    char commands[MAXPGPATH] = "cm_ctl";
    for (int i = 1; i < argc; i++) {
        if (!CheckInputForSecurity(argv[i])) {
            return false;
        }
        rc = strcat_s(commands, MAXPGPATH, " ");
        securec_check_errno(rc, (void)rc);
        rc = strcat_s(commands, MAXPGPATH, argv[i]);
        securec_check_errno(rc, (void)rc);
    }
    write_runlog(DEBUG1, "ip: \"%s\", cmd: \"%s\". \n", g_currentNode->sshChannel[0], commands);
    return true;
}

bool IsCmSharedStorageMode()
{
    return g_isSharedStorageMode;
}

int main(int argc, char** argv)
{
    uid_t uid = getuid();
    if (uid == 0) {
        (void)printf("current user is the root user (uid = 0), exit.\n");
        return 1;
    }

    g_progname = "cm_ctl";
    /* support --help and --version even if invoked as root */
    CheckArgcType(argc, argv);

    static struct option longOptions[] = {
        {"help", no_argument, NULL, '?'},
        {"version", no_argument, NULL, 'V'},
        {"log", required_argument, NULL, 'l'},
        {"log_level", optional_argument, NULL, 1},
        {"cm_arbitration_mode", optional_argument, NULL, 2},
        {"cm_switchover_az_mode", optional_argument, NULL, 3},
        {"cm_failover_delay_time", optional_argument, NULL, 4},
        {"xmode", optional_argument, NULL, DCF_XMODE},
        {"votenum", optional_argument, NULL, DCF_VOTE_NUM},
        {"minorityAz", required_argument, NULL, MINORITY_AZ},
        {"cmsPromoteMode", required_argument, NULL, CMS_P_MODE},
        {"mode", required_argument, NULL, 'm'},
        {"pgdata", required_argument, NULL, 'D'},
        {"bin_name", required_argument, NULL, 'B'},
        {"data_path", required_argument, NULL, 'T'},
#ifdef ENABLE_LIBPQ
        {"role", required_argument, NULL, DCF_ROLE_MODE},
        {"group", required_argument, NULL, DCF_GROUP},
        {"priority", required_argument, NULL, DCF_PRIORITY},
#endif
        {"node", required_argument, NULL, 'n'},
        {"timeout", required_argument, NULL, 't'},
        {"force", no_argument, NULL, 'f'},
#ifdef ENABLE_MULTIPLE_NODES
        {"logic_name", required_argument, NULL, 'L'},
#endif

#if ((defined(ENABLE_MULTIPLE_NODES)) || (defined(ENABLE_PRIVATEGAUSS)))
        {"hotpatch", required_argument, NULL, 'h'},
#endif
        {"agent", no_argument, NULL, CM_AGENT_MODE},
        {"server", no_argument, NULL, CM_SERVER_MODE},
        {"ddb_type", optional_argument, NULL, CM_SWITCH_DDB},
        {"commit", no_argument, NULL, CM_SWITCH_COMMIT},
        {"rollback", no_argument, NULL, CM_SWITCH_ROLLBACK},
        {"param", no_argument, NULL, CM_SET_PARAM},
        {"add", no_argument, NULL, RES_ADD},
        {"edit", no_argument, NULL, RES_EDIT},
        {"del", no_argument, NULL, RES_DEL},
        {"check", no_argument, NULL, RES_CHECK},
        {"list", no_argument, NULL, RES_LIST},
        {"res_name", required_argument, NULL, RES_NAME_INPUT},
        {"res_attr", required_argument, NULL, RES_ATTR_INPUT},
        {"add_inst", required_argument, NULL, RES_ADD_INST_INPUT},
        {"del_inst", required_argument, NULL, RES_DEL_INST_INPUT},
        {"edit_inst", required_argument, NULL, RES_EDIT_INST_INPUT},
        {"inst_attr", required_argument, NULL, RES_INST_ATTR_INPUT},
        {"list_inst", no_argument, NULL, RES_LIST_INST_INPUT},

        {NULL, 0, NULL, 0}
    };

    int optionIndex;
    int c;
    int status = 0;
    bool set_data_path = false;

    CtlOption ctlCtx;

    InitCtlOptionParams(&ctlCtx);

    (void)pthread_mutex_init(&g_cmEnvLock, NULL);

    /* makeup global cmdline from args */
    int err_no = MakeupCmdline(argc, argv);
    if (err_no == CM_EXIT) {
        exit(1);
    }

    /* init cm_ctl part global variable */
    init_ctl_global_variable();

    /* Set up signal handlers and masks. */
    setup_signal_handle(SIGPIPE, SIG_IGN); /* ignored */

    /*
     * save argv[0] so do_start() can look for the postmaster if necessary. we
     * don't look for postmaster here because in many cases we won't need it.
     */

    (void)umask(S_IRWXG | S_IRWXO);

    logicClusterList lcList = {0};
    set_cm_read_flag(true);
    if (read_config_file_check() != 0) {
        exit(-1);
    }
    (void)read_logic_cluster_name(g_logicClusterListPath, lcList, &err_no);
    if (CmSSlConfigInit(true) != 0) {
        write_runlog(ERROR, "CmSSlConfigInit init failed.\n");
        exit(-1);
    }
    /* support cm_ctl ddb */
    CtlDccCommand(argc, argv);
    if (!RecordCommands(argc, argv)) {
        exit(-1);
    }
    /*
     * 'Action' can be before or after args so loop over both. Some
     * getopt_long() implementations will reorder argv[] to place all flags
     * first (GNU?), but we don't rely on it. Our /port version doesn't do
     * that.
     */
    optind = 1;
    vector<int> actionOptionsCode;
    int lengthLongOptions = sizeof (longOptions)/sizeof (longOptions[0]);
    /* process command-line options */
    while (optind < argc) {
        while ((c = getopt_long(argc, argv, g_allowedOptions, longOptions, &optionIndex)) != -1) {
            actionOptionsCode.push_back(c);
            /* parse command type */
            ParseCmdArgsCore(c, &set_data_path, &ctlCtx);
        }

        if (GetCtlCommand(argc, argv) == CM_ERROR) {
            exit(1);
        }

        if (CheckActionOptionMatches(ctl_command, actionOptionsCode, longOptions, lengthLongOptions) == CM_ERROR) {
            exit(1);
        }
    }

    /* set global data path from cmdline */
    SetCommonDataPath(set_data_path, &ctlCtx);

    /* check command type */
    CtlCheckComandType();

    /* check other */
    CtlCheckOther(&ctlCtx);

    /* dealing with every clt commands */
    CtlCommandProcessCore(&status, &ctlCtx);

    g_execute_cmctl_success = true;
    ReleaseResource();
    exit(status);
}
