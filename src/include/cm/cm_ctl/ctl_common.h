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
 * ctl_distribute.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_ctl/ctl_common.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CTL_COMMON_H
#define CTL_COMMON_H

#include "cjson/cJSON.h"
#include "cm/cm_msg.h"
#include "cm/cm_misc.h"
#include "cm/cm_defs.h"
#include "cm_ddb_adapter.h"
#include "cm_cipher.h"
#include "ctl_global_params.h"
#include "cm_json_config.h"
#include "ctl_res.h"

#define DEFAULT_WAIT 60
#define DYNAMIC_PRIMARY 0
#define DYNAMIC_STANDBY 1
#define RELOAD_WAIT_TIME 60
#define MAX_COMMAND_LEN 2048

#define ETCD_BIN_NAME "etcd"
#ifndef ENABLE_MULTIPLE_NODES
// add for libnet
#define ITRAN_BIN_NAME "ltran"
#endif
#define CM_CTL_BIN_NAME "cm_ctl"

/*
* ssh connect does not exit automatically when the network is fault,
* this will cause cm_ctl hang for several hours,
* so we should add the following timeout options for ssh
*/
#define SSH_CONNECT_TIMEOUT "5"
#define SSH_CONNECT_ATTEMPTS "3"
#define SSH_SERVER_ALIVE_INTERVAL "15"
#define SSH_SERVER_ALIVE_COUNT_MAX "3"

#define PSSH_TIMEOUT_OPTION                                                                        \
    " -t 60 -O ConnectTimeout=" SSH_CONNECT_TIMEOUT " -O ConnectionAttempts=" SSH_CONNECT_ATTEMPTS \
    " -O ServerAliveInterval=" SSH_SERVER_ALIVE_INTERVAL " -O ServerAliveCountMax=" SSH_SERVER_ALIVE_COUNT_MAX " "

const int OPTION_POS = 2;
const int EXEC_DDC_CMD_TIMEOUT = 60;
const int PARALLELISM_MIN = 0;
const int PARALLELISM_MAX = 16;
const int SHARED_STORAGE_MODE_TIMEOUT = 120;

const int CTL_RECV_CYCLE = 200000;

#define FINISH_CONNECTION(conn, ret)     \
    do {                                 \
        CMPQfinish(conn);                \
        (conn) = NULL;                   \
        return ret;                      \
    } while (0)

#define FINISH_CONNECTION_WITHOUT_EXITCODE(conn) \
    do {                         \
        CMPQfinish(conn);        \
        (conn) = NULL;           \
    } while (0)

typedef enum {
    NO_COMMAND = 0,
    RESTART_COMMAND,
    START_COMMAND,
    STOP_COMMAND,
    CM_SWITCHOVER_COMMAND,
    CM_BUILD_COMMAND,
    CM_REMOVE_COMMAND,
    CM_QUERY_COMMAND,
    CM_SET_COMMAND,
    CM_GET_COMMAND,
    CM_STARTCM_COMMAND,
    CM_STOPCM_COMMAND,
    CM_SYNC_COMMAND,
    CM_VIEW_COMMAND,
    CM_CHECK_COMMAND,
    CM_SETMODE_COMMAND,
    CM_HOTPATCH_COMMAND,
    CM_DISABLE_COMMAND,
    CM_FINISHREDO_COMMAND,
    CM_DCF_SETRUNMODE_COMMAND,
    CM_DCF_CHANGEROLE_COMMAND,
    CM_DCF_CHANGEMEMBER_COMMAND,
    CM_RELOAD_COMMAND,
    CM_LIST_COMMAND,
    CM_ENCRYPT_COMMAND,
    CM_SWITCH_COMMAND,
    CM_RES_COMMAND,
    CM_SHOW_COMMAND,
    CM_PAUSE_COMMAND,
    CM_RESUME_COMMAND
} CtlCommand;


typedef enum {
    UNKNOWN_NODE = 0,
    FAILED_NODE = 1,
    ONLINE_NODE = 2,
    STOPPING_NODE = 3,
    NORMAL_NODE = 4,
    UNINSTALL_NODE = 127,
    DISCONNECT_NODE = 255
} ErrCode;

typedef enum {
    PSSH_SUCCESS = 0,
    PSSH_TIMEOUT = 4,
    COMMAND_TIMEOUT = 5,
} ExitCode;

typedef enum GucCommandSt {
    UNKNOWN_COMMAND = 0,
    SET_CONF_COMMAND,
    RELOAD_CONF_COMMAND,
    LIST_CONF_COMMAND
} GucCommand;

typedef enum NodeTypeEn {
    NODE_TYPE_UNDEF = 0,
    NODE_TYPE_AGENT,    /* cm_agent.conf */
    NODE_TYPE_SERVER,   /* cm_server.conf */
} NodeType;

typedef struct CommonOptionSt {
    uint32 nodeId;
    char *dataPath;
} CommonOption;

typedef struct SwitchoverOptionSt {
    bool switchoverAll;
    bool switchoverFull;
    bool switchoverFast;
} SwitchoverOption;

typedef struct GucOptionSt {
    GucCommand gucCommand;
    NodeType nodeType;
    KeyMode keyMod;
    char *parameter;
    char *value;
    bool needDoGuc;
} GucOption;

typedef struct BuildOptionSt {
    bool isNeedCmsBuild;
    int parallel;
    int doFullBuild;
} BuildOption;

typedef struct SwitchOptionSt {
    char *ddbType;
    bool isCommit;
    bool isRollback;
} SwitchOption;

typedef struct DcfOptionSt {
    char *role;
    int group;
    int priority;
} DcfOption;

typedef struct CtlOptionSt {
    CommonOption comm;
    GucOption guc;
    BuildOption build;
    SwitchoverOption switchover;
    SwitchOption switchOption;
    DcfOption dcfOption;
    ResOption resOpt;
} CtlOption;

extern bool g_isRestop;
extern DdbConn *g_sess;
extern TlsAuthPath g_tlsPath;
extern bool g_isPauseArbitration;

status_t do_start(void);
int DoStop(void);
int do_query(void);
int do_global_barrier_query(void);
int DoSwitchover(const CtlOption *ctx);
int do_finish_redo(void);
#ifdef ENABLE_MULTIPLE_NODES
void do_logic_cluster_restart(void);
#endif
int do_set(void);
int do_get(void);
int do_check(void);
int DoBuild(const CtlOption *ctx);
void set_mode(const char* modeopt);
int do_disable_cn();
int do_hotpatch(const char* command, const char* path);
int do_setmode();
void DoAdvice(void);
int DoSetRunMode(void);
int DoChangeMember(const CtlOption *ctx);
int DoReload();
int DoChangeRole(const CtlOption *ctx);
int CheckInstanceStatus(const char* processName, const char* cmdLine);
void DoDccCmd(int argc, char **argv);
int DoGuc(CtlOption *ctx);
int DoEncrypt(const CtlOption *ctx);
int DoSwitch(const CtlOption *ctx);
int DoShowCommand();

void stop_etcd_cluster(void);
int stop_check_node(uint32 node_id_check);
void stop_etcd_node(uint32 nodeid);
void stop_instance(uint32 nodeid, const char *datapath);
void start_instance(uint32 nodeid, const char* datapath);

void* pg_malloc(size_t size);
uint32 get_node_index(uint32 node_id);
bool isMajority(const char* cm_arbitration_mode);
bool isMinority(const char* cm_arbitration_mode);
int FindInstanceIdAndType(uint32 node, const char* dataPath, uint32* instanceId, int* instanceType);
int ssh_exec(const staticNodeConfig* node, const char* cmd, int32 logLevel = ERROR);
int SshExec(const staticNodeConfig* node, const char* cmd);
int RunEtcdCmd(const char* command, uint32 nodeIndex);
void do_conn_cmserver(bool queryCmserver, uint32 nodeIndex, bool queryEtcd = false, struct cm_conn **curConn = NULL);
int cm_client_flush_msg(struct cm_conn* conn);
int cm_client_send_msg(struct cm_conn* conn, char msgtype, const char* s, size_t len);
char* recv_cm_server_cmd(struct cm_conn* conn);
void init_hosts();
bool is_node_stopping(uint32 checkNode, uint32 currentNode, const char *manualStartFile, const char *resultFile,
                      const char *mppEnvSeperateFile);
char* xstrdup(const char* s);
void CheckDnNodeStatusById(uint32 node_id_check, int* result, uint32 dnIndex);
void CheckGtmNodeStatusById(uint32 node_id_check, int* result);
void CheckCnNodeStatusById(uint32 node_id_check, int* result);
int checkStaticConfigExist(uint32 nodeIndex);
status_t SendKVToCms(const char *key, const char *value, const char *threadName);
int cmctl_getenv(const char* env_var, char* output_env_value, uint32 env_value_len);
time_t get_start_time();
time_t check_with_end_time(const time_t start_time);
void exec_system_ssh(uint32 remote_nodeid, const char *cmd, int *result, const char *resultPath,
                     const char *mppEnvSeperateFile);
void exec_system(const char *cmd, int *result, const char *resultPath);
int runCmdByNodeId(const char* command, uint32 nodeid);
int caculate_default_timeout(CtlCommand cmd);
int CheckClusterRunningStatus();
int CheckSingleClusterRunningStatus();

extern bool backup_process_query;
int GetDatanodeRelationInfo(uint32 nodeId, const char *cmData, cm_to_ctl_get_datanode_relation_ack *getInstanceMsg);
void InstanceInformationRecord(uint32 nodeIndex, const cm_to_ctl_instance_status* cmToCtlInstanceStatusPtr);
status_t ServerDdbInit(void);
void FreeDdbInfo(void);
bool CheckDdbHealth(void);
bool IsCmsPrimary(const staticNodeConfig *node);

void InitCtlOptionParams(CtlOption *ctx);
status_t CheckGucSetParameter(const CtlOption *ctx);
status_t ExeGucCommand(const GucOption *gucCtx);
status_t ProcessInLocalInstance(const GucOption *gucCtx);
status_t CheckConfigFileStatus(struct stat statBuf, struct stat tmpBuf);
void SetServerSocketWithEtcdInfo(ServerSocket *server, staticNodeConfig *node);
status_t ProcessClusterGucOption(CtlOption *ctx);
status_t KillAllCms(bool isNeedKillPrimaryCms);
uint32 *GetCmsNodeIndex(void);
status_t CheckGucOptionValidate(const GucOption &gucCtx);
void GetUpgradeVersionFromCmaConfig();
bool SetOfflineNode(uint32 nodeIndex, struct cm_conn *con);
void ReleaseConn(struct cm_conn *con);
bool IsCmSharedStorageMode();
void CtlGetCmJsonConf();
int DoRhbPrint();
int DoPause();
int DoResume();
bool CheckTrustAndNet();
bool IsTimeOut(const cmTime_t *lastTime, const char *str);
void RemoveStartingFile();
void getPauseStatus();

#endif
