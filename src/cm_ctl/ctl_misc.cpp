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
 * ctl_misc.cpp
 *    cm_ctl check -B BINNAME -T DATAPATH
 *    cm_ctl build -n NODEID -D DATADIR [-t SECS] [-f] [-b full]
 *    cm_ctl disable -n NODEID -D DATADIR [-t SECS]
 *    cm_ctl hotpatch -E PATCH_COMMAND -P PATCH_NAME
 *    cm_ctl set [--log_level=LOG_LEVEL] [--cm_arbitration_mode=ARBITRATION_MODE]
 *               [--cm_switchover_az_mode=SWITCHOVER_AZ_MODE]
 *    cm_ctl get [--log_level] [--cm_arbitration_mode] [--cm_switchover_az_mode]
 *
 * IDENTIFICATION
 *    src/cm_ctl/ctl_misc.cpp
 *
 * -------------------------------------------------------------------------
 */
#include <signal.h>
#include "common/config/cm_config.h"
#include "cm/libpq-fe.h"
#include "cm/cm_misc.h"
#include "ctl_common.h"
#include "ctl_process_message.h"
#include "cm_msg_version_convert.h"
#include "cm/libpq-int.h"
#include "cm/cm_agent/cma_main.h"

#define MAX_INSTANCE_ROLE_ABNORMAL_TIMES 40

extern char* g_bin_name;
extern char* g_bin_path;
extern int do_force;
extern ShutdownMode shutdown_mode_num;
extern bool wait_seconds_set;
extern int g_waitSeconds;
extern char mpp_env_separate_file[MAXPGPATH];
extern uint32 g_nodeIndexForCmServer[CM_PRIMARY_STANDBY_NUM];
extern char g_cmData[CM_PATH_LENGTH];
extern char result_path[MAXPGPATH];
extern uint32 g_commandOperationNodeId;
extern uint32 g_commandOperationInstanceId;
extern char g_appPath[MAXPGPATH];
extern uint32 g_nodeId;
extern char manual_start_file[MAXPGPATH];
extern char instance_manual_start_file[MAXPGPATH];
extern char etcd_manual_start_file[MAXPGPATH];
#ifndef ENABLE_MULTIPLE_NODES
extern char g_ltranManualStartFile[MAXPGPATH];
extern char g_libnetManualStartFile[MAXPGPATH];
#else
extern bool cn_resumes_restart;
#endif
extern char* cm_logic_cluster_restart_mode_set;
extern bool cm_switchover_az_mode_get;
extern char* cm_switchover_az_mode_set;
extern bool cm_arbitration_mode_get;
extern char* cm_arbitration_mode_set;
extern bool log_level_get;
extern char* log_level_set;
extern const char* g_progname;
extern CM_Conn* CmServer_conn;
extern CM_Conn* CmServer_conn1;
extern char *g_dcfXMode;
extern int g_dcfVoteNum;
extern char *g_cmsPromoteMode;

static pid_t get_instances_pid(const char* pid_path);
static bool is_etcd_stopping(void);
#ifndef ENABLE_MULTIPLE_NODES
static bool IsLtranStopping(void);
#endif
static bool is_instance_stopping(const char* dataPath);
static int do_hotpatch_cmserver(const char* command, const char* path, uint32 nodeid);
static bool checkManualStartFile(const char* binaryName, const char* dataPath);
static status_t DoSetCmsPromoteMode();

const int BUILD_CMS_TIMEOUT = 120;
const int BUILD_DN_TIMEOUT = 600;
static const uint32 PRIMARY_STANDBY_MODE = 2;

int do_set(void)
{
    ctl_to_cm_set cm_ctl_cm_set_content;
    int ret;
    int time_pass = 0;
    bool success = false;
    char* receive_msg = NULL;
    cm_msg_type* cm_msg_type_ptr = NULL;

    if (g_cmsPromoteMode != NULL) {
        if (DoSetCmsPromoteMode() != CM_SUCCESS) {
            return 1;
        }
        return 0;
    }

    if (cm_arbitration_mode_set != NULL) {
        for (uint32 kk = 0; kk < g_node_num; kk++) {
            do_conn_cmserver(true, kk);
            if (CmServer_conn1 != NULL) {
                break;
            }
        }
        CMPQfinish(CmServer_conn);
        CmServer_conn = CmServer_conn1;
    } else {
        do_conn_cmserver(false, 0);
    }
    if (CmServer_conn == NULL) {
        write_runlog(ERROR, "send set msg to cm_server connect fail.\n");
        return -1;
    }

    write_runlog(LOG, "send set msg to cm_server.\n");

    cm_ctl_cm_set_content.msg_type = (int)MSG_CTL_CM_SET;
    cm_ctl_cm_set_content.log_level = UNKNOWN_LEVEL;
    cm_ctl_cm_set_content.cm_arbitration_mode = UNKNOWN_ARBITRATION;
    cm_ctl_cm_set_content.cm_switchover_az_mode = UNKNOWN_SWITCHOVER_AZ;
    cm_ctl_cm_set_content.cm_logic_cluster_restart_mode = UNKNOWN_LOGIC_CLUSTER_RESTART;

    if (log_level_set != NULL) {
        cm_ctl_cm_set_content.log_level = log_level_string_to_int(log_level_set);
        if (cm_ctl_cm_set_content.log_level == UNKNOWN_LEVEL) {
            CMPQfinish(CmServer_conn);
            CmServer_conn = NULL;
            write_runlog(FATAL, "invalid log level.\n");
            DoAdvice();
            exit(1);
        }
    }

    if (cm_arbitration_mode_set != NULL) {
        if (isMajority(cm_arbitration_mode_set)) {
            cm_ctl_cm_set_content.cm_arbitration_mode = MAJORITY_ARBITRATION;
        } else if (isMinority(cm_arbitration_mode_set)) {
            write_runlog(LOG, "Minority cluster! The cluster data may be lost: RPO !=0.\n");

            cm_ctl_cm_set_content.cm_arbitration_mode = MINORITY_ARBITRATION;
        } else {
            CMPQfinish(CmServer_conn);
            CmServer_conn = NULL;
            write_runlog(FATAL, "invalid cm server arbitration mode.\n");
            DoAdvice();
            exit(1);
        }
    }

    if (cm_switchover_az_mode_set != NULL) {
        if (strcasecmp("NON_AUTO", cm_switchover_az_mode_set) == 0) {
            cm_ctl_cm_set_content.cm_switchover_az_mode = NON_AUTOSWITCHOVER_AZ;
        } else if (strcasecmp("AUTO", cm_switchover_az_mode_set) == 0) {
            cm_ctl_cm_set_content.cm_switchover_az_mode = AUTOSWITCHOVER_AZ;
        } else {
            CMPQfinish(CmServer_conn);
            CmServer_conn = NULL;
            write_runlog(FATAL, "invalid cm server switchover az mode.\n");
            DoAdvice();
            exit(1);
        }
    }

    if (cm_logic_cluster_restart_mode_set != NULL) {
        cm_ctl_cm_set_content.logic_cluster_delay = (uint32)CmAtoi(cm_logic_cluster_restart_mode_set, 0);
        if (cm_ctl_cm_set_content.logic_cluster_delay == 0) {
            CMPQfinish(CmServer_conn);
            CmServer_conn = NULL;
            write_runlog(FATAL, "invalid cm server failover delay time.\n");
            DoAdvice();
            exit(1);
        } else {
            cm_ctl_cm_set_content.cm_logic_cluster_restart_mode = MODIFY_LOGIC_CLUSTER_RESTART;
        }
    }

    ret = cm_client_send_msg(CmServer_conn, 'C', (char*)&cm_ctl_cm_set_content, sizeof(ctl_to_cm_set));
    if (ret != 0) {
        FINISH_CONNECTION((CmServer_conn), -1);
    }

    for (;;) {
        ret = cm_client_flush_msg(CmServer_conn);
        if (ret == TCP_SOCKET_ERROR_EPIPE) {
            FINISH_CONNECTION((CmServer_conn), -1);
        }

        receive_msg = recv_cm_server_cmd(CmServer_conn);
        if (receive_msg != NULL) {
            cm_msg_type_ptr = (cm_msg_type *)receive_msg;
            if (cm_msg_type_ptr->msg_type == (int)MSG_CM_CTL_SET_ACK) {
                write_runlog(LOG, "cm server has been set.\n");
                success = true;
            } else {
                write_runlog(ERROR, "unknown the msg type is %d.\n", cm_msg_type_ptr->msg_type);
            }
        }

        if (success) {
            break;
        }

        (void)sleep(1);
        write_runlog(LOG, ".");
        time_pass++;

        if (time_pass >= g_waitSeconds) {
            break;
        }
    }

    if (time_pass >= g_waitSeconds) {
        write_runlog(ERROR,
            "set command timeout!\n\n"
            "HINT: Maybe the set action is continually running in the background.\n"
            "You can wait for a while and check the value of item has been set using "
            "\"cm_ctl get <item>\".\n");
        CMPQfinish(CmServer_conn);
        CmServer_conn = NULL;
        return -3;
    } else {
        write_runlog(LOG, "new value set successfully.\n");
        CMPQfinish(CmServer_conn);
        CmServer_conn = NULL;
        return 0;
    }
}


int do_get(void)
{
    cm_msg_type cm_msg;
    int ret;
    int time_pass = 0;
    char* receive_msg = NULL;
    bool success = false;

    do_conn_cmserver(false, 0);
    if (CmServer_conn == NULL) {
        write_runlog(ERROR, "send get msg to cm_server connect fail.\n");
        return -1;
    }

    write_runlog(LOG, "send get msg to cm_server.\n");

    cm_msg.msg_type = (int)MSG_CTL_CM_GET;
    ret = cm_client_send_msg(CmServer_conn, 'C', (char*)&cm_msg, sizeof(cm_msg));
    if (ret != 0) {
        FINISH_CONNECTION((CmServer_conn), -1);
    }

    for (;;) {
        ret = cm_client_flush_msg(CmServer_conn);
        if (ret == TCP_SOCKET_ERROR_EPIPE) {
            FINISH_CONNECTION((CmServer_conn), -1);
        }

        receive_msg = recv_cm_server_cmd(CmServer_conn);
        if (receive_msg != NULL) {
            cm_to_ctl_get *cm_to_ctl_get_ptr = (cm_to_ctl_get*)receive_msg;
            switch (cm_to_ctl_get_ptr->msg_type) {
                case MSG_CM_CTL_GET_ACK:
                    write_runlog(WARNING, "cm server has been get.\n");
                    success = true;

                    if (log_level_get) {
                        write_runlog(LOG, "log_level=%s\n", log_level_int_to_string(cm_to_ctl_get_ptr->log_level));
                    }

                    if (cm_arbitration_mode_get) {
                        if (cm_to_ctl_get_ptr->cm_arbitration_mode == MAJORITY_ARBITRATION) {
                            write_runlog(LOG, "cm_arbitration_mode=MAJORITY\n");
                        } else if (cm_to_ctl_get_ptr->cm_arbitration_mode == MINORITY_ARBITRATION) {
                            write_runlog(LOG, "cm_arbitration_mode=MINORITY\n");
                        } else {
                            write_runlog(LOG, "cm_arbitration_mode=UNKNOWN\n");
                        }
                    }

                    if (cm_switchover_az_mode_get) {
                        if (cm_to_ctl_get_ptr->cm_switchover_az_mode == AUTOSWITCHOVER_AZ) {
                            write_runlog(LOG, "cm_switchover_az_mode=AUTO\n");
                        } else if (cm_to_ctl_get_ptr->cm_switchover_az_mode == NON_AUTOSWITCHOVER_AZ) {
                            write_runlog(LOG, "cm_switchover_az_mode=NON_AUTO\n");
                        } else {
                            write_runlog(LOG, "cm_switchover_az_mode=UNKNOWN\n");
                        }
                    }
                    break;

                default:
                    write_runlog(ERROR, "unknown the msg type is %d.\n", cm_to_ctl_get_ptr->msg_type);
                    break;
            }
        }

        if (success) {
            break;
        }

        (void)sleep(1);
        write_runlog(LOG, ".");
        time_pass++;

        if (time_pass >= g_waitSeconds) {
            break;
        }
    }

    if (time_pass >= g_waitSeconds) {
        write_runlog(ERROR, "get command timeout.\n");
        CMPQfinish(CmServer_conn);
        CmServer_conn = NULL;
        return -3;
    } else {
        write_runlog(LOG, "gets it successfully.\n");
        CMPQfinish(CmServer_conn);
        CmServer_conn = NULL;
        return 0;
    }
}

int do_check(void)
{
    /*
     *  0 : nothingness
     *  2 : running
     */
    int status = CheckInstanceStatus(g_bin_name, g_bin_path);
    /* check status again to prevent it from running in a instant. */
    if (status == PROCESS_RUNNING) {
        CmSleep(10);
        status = CheckInstanceStatus(g_bin_name, g_bin_path);
    }

    return status;
}

int CheckInstanceStatus(const char* processName, const char* cmdLine)
{
    char pid_path[MAX_PATH_LEN];
    char cmd_path[MAX_PATH_LEN];
    FILE* fp = NULL;
    char getBuff[MAX_PATH_LEN];
    char* get_result = NULL;
    char paraName[MAX_PATH_LEN];
    char paraValue[MAX_PATH_LEN];
    int pid = 0;
    int ppid = 0;
    char state = '0';
    uid_t uid = 0;
    uid_t uid1 = 0;
    uid_t uid2 = 0;
    uid_t uid3 = 0;
    bool nameFound = false;
    bool nameGet = false;
    bool ppidGet = false;
    bool stateGet = false;
    bool haveFound = false;
    bool uidGet = false;
    char* p = NULL;
    int i = 0;
    int paralen;
    int ret;
    errno_t tnRet = 0;
    int rcs;
    int pid_post = 0;
    char pid_post_path[MAX_PATH_LEN];
    const char* procPath = "/proc";

    rcs = snprintf_s(pid_post_path, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/%s", cmdLine, "postmaster.pid");
    securec_check_intval(rcs, (void)rcs);
    canonicalize_path(pid_post_path);

    if (strcmp(processName, "gaussdb") == 0) {
        pid_post = get_instances_pid(pid_post_path);
    }

    DIR *dir = opendir(procPath);
    if (dir == NULL) {
        char errBuffer[ERROR_LIMIT_LEN];
        write_runlog(ERROR,
            "failed to open the directory: dir=\"%s\", errno=%d, errMessage=\"%s\".\n",
            procPath,
            errno,
            strerror_r(errno, errBuffer, ERROR_LIMIT_LEN));

        return -1;
    }
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
        /* judging whether the directory name is composed by digitals,if so,we will
        check whether there are files under the directory ,these files includes
        all detailed information about the process */
        if (CM_is_str_all_digit(de->d_name) != 0) {
            continue;
        }

        tnRet = memset_s(pid_path, MAX_PATH_LEN, 0, MAX_PATH_LEN);
        securec_check_errno(tnRet, (void)tnRet);
        pid = atoi(de->d_name);
        {
            ret = snprintf_s(pid_path, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/proc/%d/status", pid);
            securec_check_intval(ret, (void)ret);
        }

        /* maybe fail because of privilege */
        fp = fopen(pid_path, "r");
        if (fp == NULL) {
            continue;
        }

        nameGet = false;
        ppidGet = false;
        stateGet = false;
        uidGet = false;
        tnRet = memset_s(paraValue, MAX_PATH_LEN, 0, MAX_PATH_LEN);
        securec_check_errno(tnRet, (void)tnRet);
        ppid = 0;
        state = '0';
        uid = 0;
        tnRet = memset_s(getBuff, MAX_PATH_LEN, 0, MAX_PATH_LEN);
        securec_check_errno(tnRet, (void)tnRet);
        nameFound = false;

        while ((get_result = fgets(getBuff, MAX_PATH_LEN - 1, fp)) != NULL) {
            tnRet = memset_s(paraName, MAX_PATH_LEN, 0, MAX_PATH_LEN);
            securec_check_errno(tnRet, (void)tnRet);

            if (!nameGet && ((get_result = strstr(getBuff, "Name:")) != NULL)) {
                nameGet = true;
                ret = sscanf_s(getBuff, "%s %s", paraName, MAX_PATH_LEN, paraValue, MAX_PATH_LEN);
                check_sscanf_s_result(ret, 2);
                securec_check_intval(ret, (void)ret);

                if (strcmp(processName, paraValue) == 0) {
                    nameFound = true;
                } else {
                    break;
                }
            }

            if (!ppidGet && ((get_result = strstr(getBuff, "PPid:")) != NULL)) {
                ppidGet = true;
                ret = sscanf_s(getBuff, "%s %d", paraName, MAX_PATH_LEN, &ppid);
                check_sscanf_s_result(ret, 2);
                securec_check_intval(ret, (void)ret);
            }

            if (!stateGet && ((get_result = strstr(getBuff, "State:")) != NULL)) {
                stateGet = true;
                ret = sscanf_s(getBuff, "%s %c", paraName, MAX_PATH_LEN, &state, 1);
                check_sscanf_s_result(ret, 2);
                securec_check_intval(ret, (void)ret);
            }

            if (!uidGet && ((get_result = strstr(getBuff, "Uid:")) != NULL)) {
                uidGet = true;
                ret = sscanf_s(
                    getBuff, "%s    %u    %u    %u    %u", paraName, MAX_PATH_LEN, &uid, &uid1, &uid2, &uid3);
                check_sscanf_s_result(ret, 5);
                securec_check_intval(ret, (void)ret);
            }

            if (nameGet && ppidGet && stateGet && uidGet) {
                break;
            }
        }

        (void)fclose(fp);

        if (!nameFound) {
            continue;
        }

        if (getuid() != uid) {
            continue;
        }

        tnRet = memset_s(cmd_path, MAX_PATH_LEN, 0, MAX_PATH_LEN);
        securec_check_errno(tnRet, (void)tnRet);
        ret = snprintf_s(cmd_path, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/proc/%d/cmdline", pid);
        securec_check_intval(ret, (void)ret);
        fp = fopen(cmd_path, "r");
        if (fp == NULL) {
            continue;
        }
        tnRet = memset_s(getBuff, MAX_PATH_LEN, 0, MAX_PATH_LEN);
        securec_check_errno(tnRet, (void)tnRet);
        if ((get_result = fgets(getBuff, MAX_PATH_LEN - 1, fp)) != NULL) {
            p = getBuff;
            i = 0;
            while (i < MAX_PATH_LEN - 1) {
                if (*p == '/') {
                    if (strcmp(p, cmdLine) == 0) {
                        haveFound = true;
                        break;
                    } else {
                        char* cmd_line_tmp = xstrdup(cmdLine);
                        canonicalize_path(cmd_line_tmp);
                        if (strcmp(p, cmd_line_tmp) == 0) {
                            haveFound = true;
                            FREE_AND_RESET(cmd_line_tmp);
                            break;
                        }
                        FREE_AND_RESET(cmd_line_tmp);
                        paralen = (int)strlen(p);
                        p = p + paralen;
                        i = i + paralen;
                    }
                } else if (*p == 'l') {
                    if (strstr(p, cmdLine) != NULL) {
                        haveFound = true;
                        break;
                    } else {
                        p++;
                        i++;
                    }
                } else {
                    p++;
                    i++;
                }
            }
            tnRet = memset_s(getBuff, MAX_PATH_LEN, 0, MAX_PATH_LEN);
            securec_check_errno(tnRet, (void)tnRet);
        }
        (void)fclose(fp);
        if (haveFound) {
            break;
        }
    }
    (void)closedir(dir);
    bool foundStartFile = checkManualStartFile(processName, cmdLine);
    /* Check the node manual start file and the instance manual start file. */
    write_runlog(DEBUG1,
        "check the manual start file and the instance process: foundStartFile=%d, haveFound=%d,"
        " binaryName=\"%s\", dataPath=\"%s\".\n",
        foundStartFile,
        haveFound,
        processName,
        cmdLine);
    if (haveFound && !foundStartFile) {
        if (strcmp(processName, "gaussdb") == 0) {
            if ((pid_post == pid) && (pid > 0)) {
                return PROCESS_RUNNING;
            } else {
                return PROCESS_WAIT_START;
            }
        } else {
            return PROCESS_RUNNING;
        }
    } else if (!haveFound && foundStartFile) {
        return PROCESS_NOT_EXIST;
    } else if (haveFound && foundStartFile) {
        return PROCESS_WAIT_STOP;
    } else {
        return PROCESS_WAIT_START;
    }
}

static pid_t get_instances_pid(const char* pid_path)
{
    pid_t pid;

    FILE *pidf = fopen(pid_path, "r");
    if (pidf == NULL) {
        /* No pid file, not an error on startup */
        char errBuffer[ERROR_LIMIT_LEN];
        if (errno == ENOENT) {
            write_runlog(DEBUG1,
                "PID file :\"%s\" does not exist: %s\n.",
                pid_path,
                strerror_r(errno, errBuffer, ERROR_LIMIT_LEN));
        } else {
            write_runlog(DEBUG1,
                "could not open PID file \"%s\": %s\n.",
                pid_path,
                strerror_r(errno, errBuffer, ERROR_LIMIT_LEN));
        }
        return 0;
    }
    if (fscanf_s(pidf, "%d", &pid) != 1) {
        write_runlog(DEBUG1, "invalid data in PID file \"%s\"\n", pid_path);
        (void)fclose(pidf);
        return 0;
    }
    (void)fclose(pidf);
    return pid;
}


/**
 * @brief Check whether the manual start file exist in the target node.
 *
 * @param [in] binaryName: The binary name string.
 * @param [in] dataPath: The data path string.
 *
 * @return true: if the instance is manual stopped.
 * @return false: if the instance is not manual stopped.
 */
static bool checkManualStartFile(const char* binaryName, const char* dataPath)
{
    /* If the input binary name is NULL, exit. */
    if (binaryName == NULL) {
        write_runlog(DEBUG1, "Binary name is null.\n");
        return false;
    }

    /* If the instance is etcd, return the etcd instance stopping status. */
    if (strncmp(binaryName, ETCD_BIN_NAME, sizeof(ETCD_BIN_NAME)) == 0) {
        return is_etcd_stopping();
    }
#ifndef ENABLE_MULTIPLE_NODES
    if (strncmp(binaryName, ITRAN_BIN_NAME, sizeof(ITRAN_BIN_NAME)) == 0) {
        return IsLtranStopping();
    }
#endif
    /* Check whether the current node is stopping. */
    if (is_node_stopping(g_nodeId, g_nodeId, manual_start_file, result_path, mpp_env_separate_file)) {
        write_runlog(DEBUG1,
            "manual_start_file(%s) successfully write at node(%u, %s).\n",
            manual_start_file,
            g_nodeId,
            g_node[g_nodeId].nodeName);
        return true;
    }

    /* If the instance is cm_agent, do not need to check other scene. */
    if (strncmp(binaryName, CM_AGENT_BIN_NAME, sizeof(CM_AGENT_BIN_NAME)) == 0 ||
        strncmp(binaryName, CM_SERVER_BIN_NAME, sizeof(CM_SERVER_BIN_NAME)) == 0) {
        return false;
    }

    return is_instance_stopping(dataPath);
}

static bool is_etcd_stopping(void)
{
    int result = -1;
    char command[MAXPGPATH] = {0};
    int ret;

    ret = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1, "ls %s > /dev/null 2>&1 \n echo  -e  $? > %s",
        etcd_manual_start_file, result_path);
    securec_check_intval(ret, (void)ret);
    exec_system(command, &result, result_path);

    return (result == 0);
}
#ifndef ENABLE_MULTIPLE_NODES
static bool IsLtranStopping(void)
{
    int result = -1;
    char command[MAXPGPATH * 3] = {0};
    int ret;

    ret = snprintf_s(command,
        MAXPGPATH * 3,
        MAXPGPATH * 3 - 1,
        "ls %s > /dev/null 2>&1 \n echo  -e  $? > %s",
        g_ltranManualStartFile,
        result_path);
    securec_check_ss_c(ret, "", "");
    exec_system(command, &result, result_path);
    return (result == 0) ? true : false;
}
#endif
static bool is_instance_stopping(const char* dataPath)
{
    int result = -1;
    char command[MAX_PATH_LEN] = {0};
    int ret;
    uint32 instanceId = 0;
    int instanceType = 0;

    ret = FindInstanceIdAndType(g_currentNode->node, dataPath, &instanceId, &instanceType);
    if (ret != 0) {
        write_runlog(FATAL, "can't find the node_id:%u, data_path:%s.\n", g_currentNode->node, dataPath);
        exit(-1);
    }

    ret = snprintf_s(command, MAX_PATH_LEN, MAX_PATH_LEN - 1, "ls %s_%u > /dev/null 2>&1 \n echo  -e  $? > %s",
        instance_manual_start_file, instanceId, result_path);
    securec_check_intval(ret, (void)ret);
    exec_system(command, &result, result_path);

    return (result == 0);
}

int do_disable_cn()
{
    int ret;
    int instance_type = 0;
    uint32 instanceId = 0;
    char* receive_msg = NULL;
    cm_msg_type* cm_msg_type_ptr = NULL;
    ctl_to_cm_disable_cn ctl_to_cm_disable_cn_content = {0};
    ctl_to_cm_disable_cn_ack* ctl_to_cm_disable_cn_ack_ptr = NULL;
    cm_to_ctl_instance_status* cm_to_ctl_instance_status_ptr = NULL;
    cm_to_ctl_instance_status_ipv4* cm_to_ctl_instance_status_ptr_ipv4 = NULL;
    ctl_to_cm_query cm_ctl_cm_query_content = {0};
    int wait_time = DEFAULT_WAIT;
    int sendQueryCount = 0;
    int getQueryCount = 0;
    bool success = false;
    int checkSendDisableTime = 3;
    bool tryFlag = false;
    int checkCNStateCnt = 10;
    bool tryCheckStateFlag = false;

    ret = FindInstanceIdAndType(g_commandOperationNodeId, g_cmData, &instanceId, &instance_type);
    if (ret != 0) {
        write_stderr(
            _("%s: can't find the node_id:%u, data_path:%s.\n"), g_progname, g_commandOperationNodeId, g_cmData);
        return -1;
    }

    if (instance_type != INSTANCE_TYPE_COORDINATE) {
        write_stderr(_("%s: the instance is not coordinator, only coordinator can be disabled.\n"), g_progname);
        return -1;
    }

    do_conn_cmserver(false, 0);
    if (CmServer_conn == NULL) {
        write_stderr(_("%s: send disable cn msg to cm_server, connect fail node_id:%u, data_path:%s.\n"),
            g_progname,
            g_commandOperationNodeId,
            g_cmData);
        return -1;
    }

    ctl_to_cm_disable_cn_content.msg_type = (int)MSG_CTL_CM_DISABLE_CN;
    ctl_to_cm_disable_cn_content.instanceId = instanceId;
    if (wait_seconds_set) {
        ctl_to_cm_disable_cn_content.wait_seconds = g_waitSeconds;
        wait_time = g_waitSeconds;
    } else {
        ctl_to_cm_disable_cn_content.wait_seconds = DEFAULT_WAIT * 2;
        wait_time = DEFAULT_WAIT * 2;
    }

    ret = cm_client_send_msg(CmServer_conn, 'C', (char*)&ctl_to_cm_disable_cn_content, sizeof(ctl_to_cm_disable_cn));
    if (ret != 0) {
        FINISH_CONNECTION((CmServer_conn), -1);
    }

    for (;;) {
        tryCheckStateFlag = false;
        if (CmServer_conn != NULL) {
            ret = cm_client_flush_msg(CmServer_conn);
            if (ret == TCP_SOCKET_ERROR_EPIPE) {
                CMPQfinish(CmServer_conn);
                CmServer_conn = NULL;
            }
            receive_msg = recv_cm_server_cmd(CmServer_conn);
        }
        if (receive_msg != NULL) {
            cm_msg_type_ptr = (cm_msg_type*)receive_msg;
            switch (cm_msg_type_ptr->msg_type) {
                case MSG_CTL_CM_DISABLE_CN_ACK:
                    ctl_to_cm_disable_cn_ack_ptr = (ctl_to_cm_disable_cn_ack*)receive_msg;
                    if (ctl_to_cm_disable_cn_ack_ptr != NULL && !ctl_to_cm_disable_cn_ack_ptr->disable_ok && !tryFlag) {
                        if ((strstr(ctl_to_cm_disable_cn_ack_ptr->errMsg, "state is not down") != NULL) &&
                            checkCNStateCnt > 0) {
                            tryCheckStateFlag = true;
                            break;
                        }
                        write_stderr(_("\n%s:%s"), g_progname, ctl_to_cm_disable_cn_ack_ptr->errMsg);
                        return -1;
                    }
                    break;
                case MSG_CM_CTL_DATA:
                    getQueryCount++;
                    if (undocumentedVersion !=0 && undocumentedVersion < SUPPORT_IPV6_VERSION) {
                        cm_to_ctl_instance_status_ptr_ipv4 = (cm_to_ctl_instance_status_ipv4*)receive_msg;
                        if (cm_to_ctl_instance_status_ptr_ipv4->coordinatemember.status == INSTANCE_ROLE_DELETED) {
                            success = true;
                        }
                    } else {
                        cm_to_ctl_instance_status_ptr = (cm_to_ctl_instance_status*)receive_msg;
                        if (cm_to_ctl_instance_status_ptr->coordinatemember.status == INSTANCE_ROLE_DELETED) {
                            success = true;
                        }
                    }
                    break;
                default:
                    write_stderr(_("\n%s: unknown the msg type is %d.\n"), g_progname, cm_msg_type_ptr->msg_type);
                    break;
            }
        }

        if (tryCheckStateFlag) {
            (void)cm_client_send_msg(
                CmServer_conn, 'C', (char*)&ctl_to_cm_disable_cn_content, sizeof(ctl_to_cm_disable_cn));
            checkCNStateCnt--;
            (void)sleep(1);
            write_stderr(_("."));
            wait_time--;
            continue;
        }

        if ((sendQueryCount - getQueryCount) > 3) {
            if (checkSendDisableTime > 0) {
                checkSendDisableTime--;
                (void)sleep(1);
                write_stderr(_("."));
                wait_time--;
                continue;
            } else {
                CMPQfinish(CmServer_conn);
                CmServer_conn = NULL;
                do_conn_cmserver(false, 0);
                if (CmServer_conn != NULL) {
                    write_stderr(_("\n%s: will send disable msg again.\n"), g_progname);
                    (void)cm_client_send_msg(
                        CmServer_conn, 'C', (char*)&ctl_to_cm_disable_cn_content, sizeof(ctl_to_cm_disable_cn));
                }
                checkSendDisableTime = 3;
                sendQueryCount = 0;
                getQueryCount = 0;
                tryFlag = true;
                (void)sleep(1);
                write_stderr(_("."));
                wait_time--;
                continue;
            }
        }
        if (success) {
            break;
        }

        cm_ctl_cm_query_content.msg_type = (int)MSG_CTL_CM_QUERY;
        cm_ctl_cm_query_content.node = g_commandOperationNodeId;
        cm_ctl_cm_query_content.instanceId = instanceId;
        cm_ctl_cm_query_content.instance_type = instance_type;
        cm_ctl_cm_query_content.wait_seconds = DEFAULT_WAIT;
        if (CmServer_conn != NULL) {
            (void)cm_client_send_msg(
                CmServer_conn, 'C', (char*)&cm_ctl_cm_query_content, sizeof(cm_ctl_cm_query_content));
        }
        sendQueryCount++;

        wait_time--;
        if (wait_time <= 0) {
            break;
        }
        write_stderr(_("."));
        (void)sleep(1);
    }

    if (wait_time <= 0) {
        CMPQfinish(CmServer_conn);
        CmServer_conn = NULL;
        write_stderr(_("\n%s: disable coordinator %u command timeout.\n"), g_progname, instanceId);
        return -3;
    }

    write_stderr(_("\n%s: disable coordinator %u successfully.\n"), g_progname, instanceId);
    CMPQfinish(CmServer_conn);
    CmServer_conn = NULL;
    return 0;
}

static status_t GetCmsBuildStepResult()
{
    int waitTime = BUILD_CMS_TIMEOUT;
    char *receiveMsg = NULL;
    cm_to_ctl_command_ack *cmsAckPtr;

    for (;;) {
        if (CmServer_conn != NULL) {
            if (cm_client_flush_msg(CmServer_conn) == TCP_SOCKET_ERROR_EPIPE) {
                FINISH_CONNECTION_WITHOUT_EXITCODE((CmServer_conn));
            }
            receiveMsg = recv_cm_server_cmd(CmServer_conn);
        }
        if (receiveMsg != NULL) {
            const cm_msg_type *type = reinterpret_cast<cm_msg_type *>(reinterpret_cast<void *>(receiveMsg));

            switch (type->msg_type) {
                case MSG_CM_CTL_BACKUP_OPEN:
                    write_runlog(ERROR, "disable build cms in recovery mode.\n");
                    return CM_ERROR;
                case MSG_CM_CTL_COMMAND_ACK:
                    cmsAckPtr = reinterpret_cast<cm_to_ctl_command_ack *>(reinterpret_cast<void *>(receiveMsg));
                    if (cmsAckPtr->isCmsBuildStepSuccess) {
                        return CM_SUCCESS;
                    }
                    return CM_ERROR;
                default:
                    break;
            }
        }

        cm_sleep(1);
        waitTime--;
        write_runlog(LOG, ".");

        if (waitTime <= 0) {
            break;
        }
    }
    write_runlog(DEBUG1, "the step of cms build timeout.\n");

    return CM_ERROR;
}

static bool IsCmsStatusNormal(uint32 nodeIndex)
{
    CM_Conn *conn = NULL;
    do_conn_cmserver(true, nodeIndex, false, &conn);
    if (conn != NULL) {
        CMPQfinish(conn);
        return true;
    }
    return false;
}

static status_t NotifyCmsBuild(ctl_to_cm_build &buildMsg, const CmsBuildStep &step)
{
    buildMsg.cmsBuildStep = step;

    if (cm_client_send_msg(CmServer_conn, 'C', (char*)&buildMsg, sizeof(buildMsg)) != 0) {
        write_runlog(DEBUG1, "send step(%d) of cms build node(%u) msg to cms failed.\n", (int)step, buildMsg.node);
        return CM_ERROR;
    }

    if (GetCmsBuildStepResult() != CM_SUCCESS) {
        write_runlog(DEBUG1, "the step(%d) of cms build node(%u) failed.\n", (int)step, buildMsg.node);
        return CM_ERROR;
    }
    write_runlog(DEBUG1, "the step(%d) of cms build node(%u) success.\n", (int)step, buildMsg.node);

    return CM_SUCCESS;
}

static status_t SendBuildCmsMsgAndGetAck(uint32 nodeIndex, ctl_to_cm_build &buildMsg)
{
    if (IsCmsPrimary(&g_node[nodeIndex])) {
        write_runlog(LOG, "The node(%u) is primary, can't do build cms.\n", g_node[nodeIndex].node);
        return CM_ERROR;
    }
    if (IsCmsStatusNormal(nodeIndex)) {
        write_runlog(LOG, "The node(%u) cms is normal, can't do build cms.\n", g_node[nodeIndex].node);
        return CM_ERROR;
    }

    buildMsg.msg_type = (int)MSG_CTL_CM_BUILD;
    buildMsg.node = g_node[nodeIndex].node;

    if (NotifyCmsBuild(buildMsg, CMS_BUILD_LOCK) == CM_ERROR) {
        return CM_ERROR;
    }
    if (NotifyCmsBuild(buildMsg, CMS_BUILD_DOING) == CM_ERROR) {
        return CM_ERROR;
    }
    if (NotifyCmsBuild(buildMsg, CMS_BUILD_UNLOCK) == CM_ERROR) {
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static status_t DoCmsBuild(ctl_to_cm_build &buildMsg)
{
    uint32 buildNode = (g_commandOperationNodeId != 0) ? g_commandOperationNodeId : g_currentNode->node;

    if (g_dn_replication_num != PRIMARY_STANDBY_MODE) {
        write_runlog(LOG, "build -c only used in primary-standby mode, can't do build cms.\n");
        return CM_ERROR;
    }

    for (uint32 i = 0; i < g_cm_server_num; ++i) {
        if (g_node[g_nodeIndexForCmServer[i]].node == buildNode) {
            return SendBuildCmsMsgAndGetAck(g_nodeIndexForCmServer[i], buildMsg);
        }
    }
    write_runlog(LOG, "node(%u) have no cms, can't do build cms.\n", buildNode);

    return CM_ERROR;
}

void SendQuery(uint32 instanceId, int instanceType)
{
    ctl_to_cm_query queryMsg = {0};

    queryMsg.msg_type = (int)MSG_CTL_CM_QUERY;
    queryMsg.node = g_commandOperationNodeId;
    queryMsg.instanceId = instanceId;
    queryMsg.instance_type = instanceType;
    queryMsg.wait_seconds = g_waitSeconds;
    queryMsg.relation = 0;

    if (CmServer_conn != NULL) {
        (void)cm_client_send_msg(CmServer_conn, 'C', (char*)&queryMsg, sizeof(queryMsg));
    }

    return;
}

static bool CheckBuildCond(int32 localRole)
{
    return (localRole == INSTANCE_ROLE_STANDBY || localRole == INSTANCE_ROLE_CASCADE_STANDBY);
}

int DoBuild(const CtlOption *ctx)
{
    CtlGetCmJsonConf();
    if (g_enableSharedStorage) {
        write_runlog(LOG, "in shared storage mode, can't do cm_ctl build.\n");
        return 0;
    }

    int waitTime = BUILD_DN_TIMEOUT;
    int instanceType = 0;
    int getQueryCount = 0;
    int dnRoleAbnormal = 0;
    int sendQueryCount = 0;
    int checkSendBuildTime = 3;
    bool tryFlag = false;
    bool success;
    bool sendBuildFlag = false;
    char *receiveMsg = NULL;
    uint32 instanceId = 0;
    cm_msg_type *msgType = NULL;
    ctl_to_cm_build buildMsg = {0};
    cm_to_ctl_command_ack *commandAckPtr = NULL;
    cm_to_ctl_instance_status instStatusPtr = {0};
    cm_to_ctl_instance_status_ipv4 *instStatusPtrIpv4 = NULL;
    errno_t rc;

    do_conn_cmserver(false, 0);
    if (CmServer_conn == NULL) {
        write_runlog(ERROR, "send build msg to cm_server, connect fail, node_id:%u, data_path:%s.\n",
            ctx->comm.nodeId,
            g_cmData);
        return -1;
    }

    if (ctx->build.isNeedCmsBuild) {
        if (DoCmsBuild(buildMsg) != CM_SUCCESS) {
            write_runlog(LOG, "cm_ctl build cms failed.\n");
            FINISH_CONNECTION((CmServer_conn), -1);
        }
        write_runlog(LOG, "cm_ctl build cms success.\n");
        FINISH_CONNECTION((CmServer_conn), 0);
    }

    write_runlog(DEBUG1, "send build msg to cm_server, node_id:%u, data_path:%s.\n", ctx->comm.nodeId, g_cmData);

    if (FindInstanceIdAndType(ctx->comm.nodeId, g_cmData, &instanceId, &instanceType) != 0) {
        write_runlog(ERROR, "can't find the node_id:%u, data_path:%s.\n", ctx->comm.nodeId, g_cmData);
        return -1;
    }

    buildMsg.msg_type = (int)MSG_CTL_CM_BUILD;
    buildMsg.node = ctx->comm.nodeId;
    buildMsg.instanceId = instanceId;
    buildMsg.full_build = ctx->build.doFullBuild;
    buildMsg.parallel = ctx->build.parallel;

    if (wait_seconds_set) {
        buildMsg.wait_seconds = g_waitSeconds;
        waitTime = g_waitSeconds;
    } else {
        buildMsg.wait_seconds = DEFAULT_WAIT * 60 * 2;
        waitTime = DEFAULT_WAIT * 60 * 2;
    }

    if (do_force == 1) {
        buildMsg.force_build = CM_CTL_FORCE_BUILD;
    } else {
        buildMsg.force_build = CM_CTL_UNFORCE_BUILD;
    }

    if (cm_client_send_msg(CmServer_conn, 'C', (char*)&buildMsg, sizeof(ctl_to_cm_build)) != 0) {
        FINISH_CONNECTION((CmServer_conn), -1);
    }

    success = false;
    for (;;) {
        if (CmServer_conn != NULL) {
            if (cm_client_flush_msg(CmServer_conn) == TCP_SOCKET_ERROR_EPIPE) {
                FINISH_CONNECTION_WITHOUT_EXITCODE((CmServer_conn));
            }
            receiveMsg = recv_cm_server_cmd(CmServer_conn);
        }
        if (receiveMsg != NULL) {
            msgType = (cm_msg_type*)receiveMsg;
            switch (msgType->msg_type) {
                case MSG_CM_CTL_COMMAND_ACK:
                    commandAckPtr = (cm_to_ctl_command_ack*)receiveMsg;
                    if ((commandAckPtr->command_result == CM_ANOTHER_COMMAND_RUNNING) && !tryFlag) {
                        write_runlog(ERROR, "another command(%d) is running.\n", commandAckPtr->pengding_command);
                        FINISH_CONNECTION((CmServer_conn), -1);
                    } else if (commandAckPtr->command_result == CM_INVALID_COMMAND) {
                        write_runlog(ERROR, "can not build at current role.\n");
                        FINISH_CONNECTION((CmServer_conn), -1);
                    } else if (commandAckPtr->command_result == CM_DN_NORMAL_STATE) {
                        write_runlog(LOG, "build successfully.\n");
                        FINISH_CONNECTION((CmServer_conn), 0);
                    }
                    sendBuildFlag = true;
                    break;

                case MSG_CM_CTL_DATA:
                    getQueryCount++;
                    if (undocumentedVersion !=0 && undocumentedVersion < SUPPORT_IPV6_VERSION) {
                        instStatusPtrIpv4 = (cm_to_ctl_instance_status_ipv4*)receiveMsg;
                        CmToCtlInstanceStatusV1ToV2(instStatusPtrIpv4, &instStatusPtr);
                    } else {
                        rc = memcpy_s(&instStatusPtr,
                            sizeof(cm_to_ctl_instance_status),
                            receiveMsg,
                            sizeof(cm_to_ctl_instance_status));
                        securec_check_errno(rc, (void)rc);
                    }
                    if (instStatusPtr.instance_type == INSTANCE_TYPE_GTM) {
                        if (instStatusPtr.gtm_member.local_status.local_role == INSTANCE_ROLE_STANDBY) {
                            success = true;
                        }
                    } else if (instStatusPtr.instance_type == INSTANCE_TYPE_DATANODE) {
                        if ((CheckBuildCond(instStatusPtr.data_node_member.local_status.local_role)) &&
                            (instStatusPtr.data_node_member.local_status.db_state == INSTANCE_HA_STATE_NORMAL)) {
                            success = true;
                        }

                        if ((instStatusPtr.data_node_member.local_status.local_role == INSTANCE_ROLE_UNKNOWN) &&
                            (instStatusPtr.data_node_member.local_status.db_state == INSTANCE_HA_STATE_BUILD_FAILED)) {
                            write_runlog(ERROR,
                                "build failed, please refer to the log of cm_agent(nodeid:%u) for detailed reasons.\n",
                                ctx->comm.nodeId);
                            FINISH_CONNECTION((CmServer_conn), -1);
                        }

                        if (!CheckBuildCond(instStatusPtr.data_node_member.local_status.local_role) &&
                            instStatusPtr.data_node_member.local_status.db_state != INSTANCE_HA_STATE_BUILDING) {
                            dnRoleAbnormal++;
                        } else {
                            dnRoleAbnormal = 0;
                        }

                        if (dnRoleAbnormal > MAX_INSTANCE_ROLE_ABNORMAL_TIMES) {
                            if (instStatusPtr.data_node_member.local_status.db_state ==
                                INSTANCE_HA_STATE_MANUAL_STOPPED) {
                                write_runlog(ERROR, "build failed, instance is stopped.\n");
                            } else {
                                write_runlog(ERROR, "build failed, instance role is not standby or cascade standby.\n");
                            }
                            FINISH_CONNECTION((CmServer_conn), -1);
                        }
                    }
                    break;

                case MSG_CM_BUILD_DOING:
                    getQueryCount++;
                    break;

                case MSG_CM_BUILD_DOWN:
                    write_runlog(ERROR, "rm -f the cm instance manual start file failed and quit.\n");
                    return -1;

                case MSG_CM_CTL_BACKUP_OPEN:
                    write_runlog(ERROR, "disable do build in recovery mode.\n");
                    FINISH_CONNECTION((CmServer_conn), -1);

                default:
                    write_runlog(ERROR, "unknown the msg type is %d.\n", msgType->msg_type);
                    break;
            }
        }
        if (!sendBuildFlag || (sendQueryCount - getQueryCount) > 3) {
            if (checkSendBuildTime > 0) {
                checkSendBuildTime--;
                (void)sleep(1);
                write_runlog(LOG, ".");
                waitTime--;
                continue;
            } else {
                FINISH_CONNECTION_WITHOUT_EXITCODE((CmServer_conn));
                do_conn_cmserver(false, 0);
                if ((CmServer_conn != NULL) && !sendBuildFlag) {
                    write_runlog(LOG, "will send build msg again.\n");
                    (void)cm_client_send_msg(CmServer_conn, 'C', (char*)&buildMsg, sizeof(ctl_to_cm_build));
                }
                checkSendBuildTime = 3;
                sendQueryCount = 0;
                getQueryCount = 0;
                tryFlag = true;
                (void)sleep(1);
                write_runlog(LOG, ".");
                waitTime--;
                continue;
            }
        }
        if (success) {
            break;
        }
        SendQuery(instanceId, instanceType);
        sendQueryCount++;

        write_runlog(LOG, ".");
        (void)sleep(1);
        waitTime--;

        if (waitTime <= 0) {
            break;
        }
    }

    if (waitTime <= 0) {
        write_runlog(ERROR,
            "build command timeout!\n\n"
            "HINT: Maybe the build action is continually running in the background.\n"
            "You can wait for a while and check the status of current cluster using "
            "\"cm_ctl query -Cv\".\n");
        FINISH_CONNECTION_WITHOUT_EXITCODE((CmServer_conn));
        return -3;
    }
    FINISH_CONNECTION_WITHOUT_EXITCODE((CmServer_conn));

    /* sleep 6 util create node group finished */
    (void)sleep(6);
    write_runlog(LOG, "build successfully.\n");

    return 0;
}

int do_setmode()
{
    cm_msg_type msgsetmode;
    int ret;

    // return conn to cm_server
    do_conn_cmserver(false, 0);
    if (CmServer_conn == NULL) {
        write_runlog(ERROR, "send mode change msg to cm_server, connect fail  node_id:%u, data_path:%s.\n",
            g_commandOperationNodeId,
            g_cmData);
        return -1;
    }

    msgsetmode.msg_type = (int)MSG_CTL_CM_SETMODE;
    ret = cm_client_send_msg(CmServer_conn, 'C', (char*)&msgsetmode, sizeof(msgsetmode));
    if (ret != 0) {
        FINISH_CONNECTION((CmServer_conn), -1);
    }

    ret = cm_client_flush_msg(CmServer_conn);
    if (ret == TCP_SOCKET_ERROR_EPIPE) {
        FINISH_CONNECTION((CmServer_conn), -1);
    }
    char *receive_msg = recv_cm_server_cmd(CmServer_conn);
    if (receive_msg != NULL) {
        cm_msg_type* cm_msg_type_ptr = (cm_msg_type *)receive_msg;
        if (cm_msg_type_ptr->msg_type == (int)MSG_CM_CTL_SETMODE_ACK) {
            write_runlog(WARNING, "Postupgrade mode has been set.\n");
        } else {
            write_runlog(ERROR, "unknown the msg type is %d.\n", cm_msg_type_ptr->msg_type);
            FINISH_CONNECTION((CmServer_conn), -1);
        }
    }

    write_runlog(LOG, "new mode set successfully.\n");
    CMPQfinish(CmServer_conn);
    CmServer_conn = NULL;
    return 0;
}

static int do_hotpatch_cmserver(const char* command, const char* path, uint32 nodeid)
{
    int wait_time;
    cm_hotpatch_msg msg_hotpatch;
    int ret;
    char* ret_msg = NULL;

    // return conn to cm_server
    do_conn_cmserver(true, nodeid);

    if (CmServer_conn1 == NULL) {
        write_runlog(LOG, "cm_server[%s]\n[PATCH-ERROR] Connection ERR.\n", g_node[nodeid].nodeName);
        return -1;
    }

    msg_hotpatch.msg_type = (int)MSG_CTL_CM_HOTPATCH;
    ret = snprintf_s(msg_hotpatch.command, MAX_LENGTH_HP_CMD, MAX_LENGTH_HP_CMD - 1, "%s", command);
    securec_check_intval(ret, (void)ret);
    ret = snprintf_s(msg_hotpatch.path, MAX_LENGTH_HP_PATH, MAX_LENGTH_HP_PATH - 1, "%s", path);
    securec_check_intval(ret, (void)ret);

    ret = cm_client_send_msg(CmServer_conn1, 'C', (char*)&msg_hotpatch, sizeof(msg_hotpatch));
    if (ret != 0) {
        CMPQfinish(CmServer_conn1);
        CmServer_conn1 = NULL;
        return -1;
    }

    ret = cm_client_flush_msg(CmServer_conn1);
    if (ret == TCP_SOCKET_ERROR_EPIPE) {
        CMPQfinish(CmServer_conn1);
        CmServer_conn1 = NULL;
        return -1;
    }

    for (wait_time = g_waitSeconds * 1000; wait_time > 0; wait_time--) {
        CmSleep(1);

        ret_msg = recv_cm_server_cmd(CmServer_conn1);
        if (ret_msg != NULL) {
            write_runlog(LOG, "cm_server[%s]\n%s\n", g_node[nodeid].nodeName, ret_msg);
            break;
        }
    }

    if (ret_msg == NULL) {
        write_runlog(LOG, "cm_server[%s]\n[PATCH-ERROR] TIMEOUT ERR.\n", g_node[nodeid].nodeName);
    }
    CMPQfinish(CmServer_conn1);
    CmServer_conn1 = NULL;

    return 0;
}

int do_hotpatch(const char* command, const char* path)
{
    for (uint32 kk = 0; kk < g_cm_server_num; kk++) {
        uint32 cm_server_node_index = g_nodeIndexForCmServer[kk];
        (void)do_hotpatch_cmserver(command, path, cm_server_node_index);
    }

    return 0;
}

void set_mode(const char* modeopt)
{
    if (strcmp(modeopt, "f") == 0 || strcmp(modeopt, "fast") == 0) {
        shutdown_mode_num = FAST_MODE;
    } else if (strcmp(modeopt, "i") == 0 || strcmp(modeopt, "immediate") == 0) {
        shutdown_mode_num = IMMEDIATE_MODE;
    } else if (strcmp(modeopt, "s") == 0 || strcmp(modeopt, "smart") == 0) {
        shutdown_mode_num = SMART_MODE;
#ifdef ENABLE_MULTIPLE_NODES
    } else if (strcmp(modeopt, "r") == 0 || strcmp(modeopt, "resume") == 0) {
        shutdown_mode_num = RESUME_MODE;
        cn_resumes_restart = true;
#endif
    } else {
        write_runlog(FATAL, "unrecognized shutdown mode \"%s\"\n", modeopt);
        DoAdvice();
        exit(1);
    }
}

int DoSetRunMode(void)
{
    char cmd[MAXPGPATH] = {0};
    int rc = 0;

    if (g_dcfXMode == NULL) {
        write_runlog(ERROR, "g_dcfXMode is NULL.\n");
        return 1;
    }

    if (strcasecmp(g_dcfXMode, "minority") == 0) {
        rc = snprintf_s(cmd, MAXPGPATH,
            MAXPGPATH - 1,
            SYSTEMQUOTE "%s setrunmode -D %s --xmode=%s --votenum=%d" SYSTEMQUOTE,
            PG_CTL_NAME,
            g_cmData, g_dcfXMode, g_dcfVoteNum);
    } else if (strcasecmp(g_dcfXMode, "normal") == 0) {
        rc = snprintf_s(cmd,
            MAXPGPATH,
            MAXPGPATH - 1,
            SYSTEMQUOTE "%s setrunmode -D %s --xmode=%s" SYSTEMQUOTE,
            PG_CTL_NAME,
            g_cmData, g_dcfXMode);
    } else {
        write_runlog(LOG, "set datanode run mode, unexpected xmode:(%s).\n", g_dcfXMode);
        return 1;
    }
    securec_check_intval(rc, (void)rc);

    write_runlog(DEBUG1, "set datanode run mode, cmd:%s.\n", cmd);

    if (g_commandOperationNodeId == g_currentNode->node) {
        write_runlog(LOG, "set datanode run mode on current node(%u).\n", g_commandOperationNodeId);
        rc = system(cmd);
    } else {
        uint32 i;
        for (i = 0; i < g_node_num; i++) {
            if (g_node[i].node == g_commandOperationNodeId) {
                break;
            }
        }
        if (i < g_node_num) {
            write_runlog(
                LOG, "set datanode run mode on remote node: %s(%u).\n", g_node[i].nodeName, g_commandOperationNodeId);
            rc = SshExec(&g_node[i], cmd);
        } else {
            write_runlog(
                ERROR, "Could not find the node in the cluster by the node id %u.\n", g_commandOperationNodeId);
            return 1;
        }
    }

    if (rc != 0) {
        write_runlog(ERROR, "set datanode run mode failed, gs_ctl return code: %d, errno=%d.\n",
            SHELL_RETURN_CODE(rc), errno);
        return SHELL_RETURN_CODE(rc);
    }

    write_runlog(LOG, "set datanode run mode success.\n");
    return 0;
}

int DoGsCtlCommand(const char *commond, const char *cmdName)
{
    uint32 i = 0;
    int rc;
    char gausshomePath[CM_PATH_LENGTH] = {0};
    int result = 1;
    char cmd[CM_PATH_LENGTH] = {0};
    rc = GetHomePath(gausshomePath, sizeof(gausshomePath));
    if (rc != EOK) {
        return 1;
    }

    if (g_commandOperationNodeId == g_currentNode->node && strstr(gausshomePath, "/var/chroot") == NULL) {
        rc = snprintf_s(cmd, CM_PATH_LENGTH, CM_PATH_LENGTH - 1,
            SYSTEMQUOTE "%s -D %s -t %d \n echo -e  $? > %s" SYSTEMQUOTE,
            commond, g_cmData, g_waitSeconds, result_path);
        securec_check_intval(rc, (void)rc);
        write_runlog(LOG, "execute %s on current node(%u).\n", cmdName, g_commandOperationNodeId);
        exec_system(cmd, &result, result_path);
    } else {
        for (i = 0; i < g_node_num; i++) {
            if (g_node[i].node == g_commandOperationNodeId) {
                break;
            }
        }
        if (i < g_node_num) {
            rc = snprintf_s(cmd, CM_PATH_LENGTH, CM_PATH_LENGTH - 1,
                SYSTEMQUOTE "%s -D %s -t %d\" > /dev/null 2>&1; echo -e  $? > %s" SYSTEMQUOTE,
                commond, g_cmData, g_waitSeconds, result_path);
            securec_check_intval(rc, (void)rc);
            write_runlog(LOG, "execute %s on remote node: %s(%u).\n",
                cmdName, g_node[i].nodeName, g_commandOperationNodeId);
            exec_system_ssh(g_commandOperationNodeId - 1, cmd, &result, result_path, mpp_env_separate_file);
        } else {
            write_runlog(
                ERROR, "Could not find the node in the cluster by the node id %u.\n", g_commandOperationNodeId);
            return 1;
        }
    }

    write_runlog(DEBUG1, "execute %s, cmd:%s.\n", cmdName, cmd);
    return result;
}

int CalcDcfVoterNum(const cm_to_ctl_instance_status* cmToCtlInstanceStatusPtr, int *voteNum)
{
    uint32 i;
    uint32 j;
    uint32 nodeIndex = 0;
    int role = 0;

    for (i = 0; i < g_node_num; i++) {
        if (g_node[i].node == cmToCtlInstanceStatusPtr->node) {
            nodeIndex = i;
            break;
        }
    }

    if (i >= g_node_num) {
        write_runlog(ERROR, "can't find the node(%u).", cmToCtlInstanceStatusPtr->node);
        return -1;
    }

    if (g_cm_server_num > CM_PRIMARY_STANDBY_NUM) {
        write_runlog(ERROR, "the number of cm_server is bigger than %d.\n", CM_PRIMARY_STANDBY_NUM);
        return -1;
    }

    if (cmToCtlInstanceStatusPtr->instance_type == INSTANCE_TYPE_DATANODE) {
        for (j = 0; j < g_node[nodeIndex].datanodeCount; j++) {
            if (g_node[nodeIndex].datanode[j].datanodeId == cmToCtlInstanceStatusPtr->instanceId) {
                break;
            }
        }

        if (j >= g_node[nodeIndex].datanodeCount) {
            write_runlog(ERROR, "can't find the instance(%u).", cmToCtlInstanceStatusPtr->instanceId);
            return -1;
        }

        role = cmToCtlInstanceStatusPtr->data_node_member.receive_status.local_role;
        if (role == DCF_ROLE_LEADER || role == DCF_ROLE_LOGGER || role == DCF_ROLE_FOLLOWER) {
            (*voteNum)++;
        }
    }

    return 0;
}

int ProcessRecvMsg(int *voterNum)
{
    char *receiveMsg = NULL;
    cm_msg_type *cmMsgTypePtr = NULL;
    cm_to_ctl_instance_status cmToCtlInstanceStatusPtr = {0};
    const int microSecond = 1000;
    int voterDnNum = 0;
    int ret;

    int waitTime = g_waitSeconds * microSecond;
    bool recDataEnd = false;
    for (; waitTime > 0;) {
        ret = cm_client_flush_msg(CmServer_conn);
        if (ret == TCP_SOCKET_ERROR_EPIPE) {
            break;
        }
        receiveMsg = recv_cm_server_cmd(CmServer_conn);
        while (receiveMsg != NULL) {
            cmMsgTypePtr = (cm_msg_type *)receiveMsg;
            switch (cmMsgTypePtr->msg_type) {
                case MSG_CM_CTL_DATA_BEGIN:
                case MSG_CM_CTL_NODE_END:
                    break;
                case MSG_CM_CTL_DATA:
                    GetCtlInstanceStatusFromRecvMsg(receiveMsg, &cmToCtlInstanceStatusPtr);
                    if (CalcDcfVoterNum(&cmToCtlInstanceStatusPtr, &voterDnNum) != 0) {
                        return -1;
                    }
                    break;
                case MSG_CM_CTL_DATA_END:
                    recDataEnd = true;
                    break;
                default:
                    write_runlog(ERROR, "unknown the msg type is %d.\n", cmMsgTypePtr->msg_type);
                    break;
            }
            receiveMsg = recv_cm_server_cmd(CmServer_conn);
        }
        CmSleep(1);
        waitTime--;
        if (recDataEnd || waitTime <= 0) {
            break;
        }
    }

    *voterNum = voterDnNum;
    if (ret != 0 || waitTime <= 0) {
        CMPQfinish(CmServer_conn);
        CmServer_conn = NULL;
        write_runlog(ERROR, "send query msg to cm_server failed.\n");
        return -1;
    }
    return 0;
}

int DoQueryInner(int *voterNum)
{
    ctl_to_cm_query cmCtlCmQueryContent;
    int voterNodeNum = 0;
    int ret;
    
    if (g_cm_server_num > CM_PRIMARY_STANDBY_NUM) {
        write_runlog(ERROR, "the number of cm_server is bigger than %d.\n", CM_PRIMARY_STANDBY_NUM);
        exit(1);
    }

    /* return conn to cm_server */
    do_conn_cmserver(false, 0);
    if (CmServer_conn == NULL) {
        write_runlog(ERROR, "can't connect to cm_server.\n"
            "Maybe cm_server is not running, or timeout expired. Please try again.\n");
        return -1;
    }
    cmCtlCmQueryContent.msg_type = (int)MSG_CTL_CM_QUERY;
    cmCtlCmQueryContent.node = INVALID_NODE_NUM;
    cmCtlCmQueryContent.relation = 0;
    cmCtlCmQueryContent.instanceId = INVALID_INSTACNE_NUM;
    cmCtlCmQueryContent.wait_seconds = g_waitSeconds;
    cmCtlCmQueryContent.detail = CLUSTER_DETAIL_STATUS_QUERY;

    ret = cm_client_send_msg(CmServer_conn, 'C', (char*)&cmCtlCmQueryContent, sizeof(cmCtlCmQueryContent));
    if (ret != 0) {
        CMPQfinish(CmServer_conn);
        CmServer_conn = NULL;
        return -1;
    }
    CmSleep(1);

    if (ProcessRecvMsg(&voterNodeNum) != 0) {
        return -1;
    }
    *voterNum = voterNodeNum;
    
    CMPQfinish(CmServer_conn);
    CmServer_conn = NULL;
    return 0;
}


int PreCondCheck(void)
{
    const int minVoterNum = 3;
    int voterCount = 0;
    
    if (DoQueryInner(&voterCount) != 0) {
        write_runlog(ERROR, "Dcf role query error.\n");
        return 1;
    }

    if (voterCount <= minVoterNum) {
        write_runlog(ERROR, "Operation is invalid, voter role node should be more than 3.\n");
        return 1;
    }
    return 0;
}

static status_t DoCheck(const CtlOption *ctx)
{
    const int errcode = -2;
    if (ctx->comm.nodeId == 0 || ctx->comm.dataPath[0] == '\0') {
        write_runlog(ERROR, "unexpected arg (node_id:%u) (data:%s).\n", ctx->comm.nodeId, ctx->comm.dataPath);
        return CM_ERROR;
    }

    if (ctx->dcfOption.group == errcode || ctx->dcfOption.priority == errcode) {
        write_runlog(ERROR, "input is invalid\n");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static int DoCheckRole(const DcfOption *ctx)
{
    if (ctx->role == NULL) {
        return 1;
    }

    if (strcasecmp(ctx->role, "passive") != 0 && strcasecmp(ctx->role, "follower") != 0) {
        write_runlog(ERROR, "error, unexpected role :(%s).\n", ctx->role);
        return -1;
    }

    if (strcasecmp(ctx->role, "passive") == 0 && PreCondCheck() != 0) {
        write_runlog(ERROR, "You can execute \"cm_ctl query -v\" and check dcf_role.\n");
        return -1;
    }

    return 0;
}

char *DoConcatCmd(const CtlOption *ctx)
{
    char tmp[CM_PATH_LENGTH] = {0};
    char *cmd = (char *)malloc(CM_PATH_LENGTH);
    if (cmd == NULL) {
        write_runlog(ERROR, "error, cmd is NULL.\n");
        return NULL;
    }

    int rc = memset_s(cmd, CM_PATH_LENGTH, 0, CM_PATH_LENGTH);
    securec_check_errno(rc, (void)rc);
    if (DoCheckRole(&ctx->dcfOption) == -1) {
        free(cmd);
        return NULL;
    }

    if (DoCheckRole(&ctx->dcfOption) == 0) {
        rc = snprintf_s(tmp, CM_PATH_LENGTH, CM_PATH_LENGTH - 1, "-R %s ", ctx->dcfOption.role);
        securec_check_intval(rc, (void)rc);
        rc = strcat_s(cmd, CM_PATH_LENGTH, tmp);
        securec_check_errno(rc, (void)rc);
    }

    if (ctx->dcfOption.group >= 0) {
        rc = snprintf_s(tmp, CM_PATH_LENGTH, CM_PATH_LENGTH - 1, "-G %d ", ctx->dcfOption.group);
        securec_check_intval(rc, (void)rc);
        rc = strcat_s(cmd, CM_PATH_LENGTH, tmp);
        securec_check_errno(rc, (void)rc);
    }

    if (ctx->dcfOption.priority >= 0) {
        rc = snprintf_s(tmp, CM_PATH_LENGTH, CM_PATH_LENGTH - 1, "--priority %d ", ctx->dcfOption.priority);
        securec_check_intval(rc, (void)rc);
        rc = strcat_s(cmd, CM_PATH_LENGTH, tmp);
        securec_check_errno(rc, (void)rc);
    }
    return cmd;
}

int DoChangeMember(const CtlOption *ctx)
{
    int result;
    int errTimeout = 2;
    char command[CM_PATH_LENGTH] = {0};
    char cmdName[CM_PATH_LENGTH] = "changemember";
    if (DoCheck(ctx) == CM_ERROR) {
        return 1;
    }

    char *tmp = DoConcatCmd(ctx);
    if (tmp == NULL) {
        write_runlog(ERROR, "error, command is NULL.\n");
        return 1;
    }
    
    int rc = snprintf_s(command, CM_PATH_LENGTH, CM_PATH_LENGTH - 1, "%s member -O change %s", PG_CTL_NAME, tmp);
    securec_check_intval(rc, (void)rc);
    result = DoGsCtlCommand(command, cmdName);

    FREE_AND_RESET(tmp);
    if (result == 0) {
        write_runlog(LOG, "execute changemember successfully.\n");
    } else if (result == 1) {
        write_runlog(ERROR, "execute changemember failed, you can check the gs_ctl log.\n");
    } else if (result == errTimeout) {
        write_runlog(ERROR, "execute changemember timeout.\n");
    } else {
        write_runlog(ERROR, "unexpect execute result code: %d.\n", result);
    }

    return result;
}

int DoChangeRole(const CtlOption *ctx)
{
    int result;
    int errTimeout = 2;
    int rc;
    char command[CM_PATH_LENGTH] = {0};
    char cmdName[CM_PATH_LENGTH] = "changeRole";

    if (g_commandOperationNodeId == 0 || g_cmData[0] == '\0' || strlen(ctx->dcfOption.role) == 0) {
        write_runlog(ERROR, "unexpected arg (node_id:%u) (data:%s) (role:%s).\n",
            g_commandOperationNodeId, g_cmData, ctx->dcfOption.role);
        return 1;
    }

    if (strcasecmp(ctx->dcfOption.role, "passive") != 0 && strcasecmp(ctx->dcfOption.role, "follower") != 0) {
        write_runlog(ERROR, "error, unexpected role :(%s).\n", ctx->dcfOption.role);
        return 1;
    }

    if (strcasecmp(ctx->dcfOption.role, "passive") == 0 && PreCondCheck() != 0) {
        write_runlog(ERROR, "You can execute \"cm_ctl query -v\" and check dcf_role.\n");
        return 1;
    }

    rc = snprintf_s(
        command, CM_PATH_LENGTH, CM_PATH_LENGTH - 1, "%s changerole -R %s ", PG_CTL_NAME, ctx->dcfOption.role);
    securec_check_intval(rc, (void)rc);
    result = DoGsCtlCommand(command, cmdName);
    if (result == 0) {
        write_runlog(LOG, "execute change dcf role successfully.\n");
    } else if (result == 1) {
        write_runlog(ERROR, "execute change dcf role failed, you can check the gs_ctl log.\n");
    } else if (result == errTimeout) {
        write_runlog(ERROR, "execute change dcf timeout.\n");
    } else {
        write_runlog(ERROR, "unexpect execute result code: %d.\n", result);
    }

    return result;
}

int DoReload()
{
    int ret;
    CtlToCMReload ctlToCMReloadContent = {0};
    cm_msg_type* cm_msg_type_ptr = NULL;
    CMToCtlReloadAck* reloadAckMsg = NULL;
    int waitTime = RELOAD_WAIT_TIME;

    do_conn_cmserver(false, 0);
    if (CmServer_conn == NULL) {
        write_runlog(ERROR, "send reload msg to cm_server, connect fail.\n");
        return -1;
    }
    ctlToCMReloadContent.msgType = (int)MSG_CTL_CM_RELOAD;
    ret = cm_client_send_msg(CmServer_conn, 'C', (char*)&ctlToCMReloadContent, sizeof(CtlToCMReload));
    if (ret != 0) {
        FINISH_CONNECTION((CmServer_conn), -1);
    }
    for (;;) {
        ret = cm_client_flush_msg(CmServer_conn);
        if (ret == TCP_SOCKET_ERROR_EPIPE) {
            FINISH_CONNECTION((CmServer_conn), -1);
        }
        char *receive_msg = recv_cm_server_cmd(CmServer_conn);
        if (receive_msg != NULL) {
            cm_msg_type_ptr = (cm_msg_type*)receive_msg;
            if (cm_msg_type_ptr->msg_type == (int)MSG_CM_CTL_RELOAD_ACK) {
                reloadAckMsg = (CMToCtlReloadAck *)receive_msg;
                if (reloadAckMsg->reloadOk && (KillAllCms(false) == CM_SUCCESS)) {
                    write_runlog(LOG, "cm_ctl reload success.\n");
                    FINISH_CONNECTION((CmServer_conn), 0);
                } else {
                    write_runlog(LOG, "cm_ctl reload failed.\n");
                    FINISH_CONNECTION((CmServer_conn), -1);
                }
            } else {
                write_runlog(ERROR, "unknown the msg type is %d.\n", cm_msg_type_ptr->msg_type);
            }
        }
        waitTime--;
        if (waitTime <= 0) {
            break;
        }
        write_runlog(LOG, ".");
        (void)sleep(1);
    }
    CMPQfinish(CmServer_conn);
    CmServer_conn = NULL;
    if (waitTime <= 0) {
        write_runlog(LOG, "execute cm_ctl reload command timeout.\n");
        return -1;
    }
    return 0;
}

static void SetNodeInstBaseInfo(NodeInstBaseInfo *info, uint32 nodeIdx, uint32 instIdx)
{
    info->nodeIdx = nodeIdx;
    info->instIdx = instIdx;
}

int FindInstanceByInstId(uint32 instId, Instance *inst)
{
    for (uint32 nodeIdx = 0; nodeIdx < g_node_num; nodeIdx++) {
        staticNodeConfig *curNode = &g_node[nodeIdx];
        if (curNode->gtm == 1) {
            if (curNode->gtmId == instId) {
                inst->instType = INST_TYPE_GTM;
                inst->node = curNode->node;
                inst->InstNode = curNode;
                SetNodeInstBaseInfo(&(inst->baseInfo), nodeIdx, 0);
                return 0;
            }
        }

        if (curNode->coordinate == 1) {
            if (curNode->coordinateId == instId) {
                inst->instType = INST_TYPE_CN;
                inst->node = curNode->node;
                inst->InstNode = curNode;
                SetNodeInstBaseInfo(&(inst->baseInfo), nodeIdx, 0);
                return 0;
            }
        }

        if (curNode->cmServerLevel == 1) {
            if (curNode->cmServerId == instId) {
                inst->instType = INST_TYPE_CMSERVER;
                inst->node = curNode->node;
                inst->InstNode = curNode;
                SetNodeInstBaseInfo(&(inst->baseInfo), nodeIdx, 0);
                return 0;
            }
        }

        for (uint32 i = 0; i < curNode->datanodeCount; i++) {
            if (curNode->datanode[i].datanodeId == instId) {
                inst->instType = INST_TYPE_DN;
                inst->node = curNode->node;
                inst->dnInst = &curNode->datanode[i];
                SetNodeInstBaseInfo(&(inst->baseInfo), nodeIdx, i);
                return 0;
            }
        }
    }

    write_runlog(FATAL, "can't find instance by instanceId: %u.\n", instId);
    return -1;
}

const char *GetInstTypeStr(InstanceType type)
{
    switch (type) {
        case INST_TYPE_CMSERVER:
            return "CM_SERVER";
        case INST_TYPE_GTM:
            return "GTM";
        case INST_TYPE_CN:
            return "COORDINATOR";
        case INST_TYPE_DN:
            return "DATANODE";
        case INST_TYPE_FENCED_UDF:
            return "UDF";
        case INST_TYPE_INIT:
        default:
            return "UNKNOWN";
    }
}

static status_t SetCmsPromoteModeCore(const Instance *inst, PromoteMode pMode)
{
    if (inst->instType != INST_TYPE_CMSERVER) {
        write_runlog(FATAL, "'we only support cm_server force promote but pointed instance's role is %s.\n",
            GetInstTypeStr(inst->instType));
        return CM_ERROR;
    }

    char cmsPModeFile[MAXPGPATH] = {0};
    errno_t rcs =
        snprintf_s(cmsPModeFile, sizeof(cmsPModeFile), sizeof(cmsPModeFile) - 1, "%s/bin/promote_mode_cms", g_appPath);
    securec_check_intval(rcs, (void)rcs);

    char command[MAXPGPATH];
    int ret;
    switch (pMode) {
        case PMODE_AUTO:
            ret = snprintf_s(command,
                sizeof(command),
                sizeof(command) - 1,
                SYSTEMQUOTE "rm -f %s > \"%s\" 2>&1" SYSTEMQUOTE,
                cmsPModeFile,
                DEVNULL);
            break;
        case PMODE_FORCE_PRIMAYR:
        default:
            ret = snprintf_s(command,
                sizeof(command),
                sizeof(command) - 1,
                SYSTEMQUOTE "echo %d > %s; chmod 600 %s" SYSTEMQUOTE,
                (int32)pMode,
                cmsPModeFile,
                cmsPModeFile);
            break;
    }
    securec_check_intval(ret, (void)ret);

    write_runlog(LOG, "set CMS promote mode(%d), nodeid: %u, instanceid %u.\n",
        (int32)pMode, inst->node, inst->InstNode->cmServerId);

    ret = runCmdByNodeId(command, inst->node);
    if (ret != 0) {
        write_runlog(DEBUG1, "Failed to set CMS promote mode with executing the command: command=\"%s\","
            " nodeId=%u, systemReturn=%d, shellReturn=%d, errno=%d.\n",
            command, inst->node, ret, SHELL_RETURN_CODE(ret), errno);
        return CM_ERROR;
    }

    write_runlog(LOG, "set CMS promote mode successfully.\n");
    return CM_SUCCESS;
}

static status_t CheckSetCmsPromoteModeParam()
{
    if (g_cmsPromoteMode == NULL) {
        // should never happen
        write_runlog(FATAL, "'--cmsPromoteMode=[AUTO|PRIMARY_F]' is needed.\n");
        return CM_ERROR;
    }

    if (g_commandOperationNodeId != 0 && get_node_index(g_commandOperationNodeId) == INVALID_NODE_NUM) {
        write_runlog(FATAL, "'-n $nodeId' value is illegal. \n");
        return CM_ERROR;
    }

    if (g_commandOperationInstanceId == 0) {
        write_runlog(FATAL, "'-I $instId' is needed.\n");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

// cm_ctl set --cmsPromoteMode=[AUTO|PRIMARY_F] -I 1
static status_t DoSetCmsPromoteMode()
{
    if (CheckSetCmsPromoteModeParam() != CM_SUCCESS) {
        DoAdvice();
        return CM_ERROR;
    }

    Instance curInst;
    errno_t rc = memset_s(&curInst, sizeof(curInst), 0, sizeof(curInst));
    securec_check_errno(rc, (void)rc);
    if (FindInstanceByInstId(g_commandOperationInstanceId, &curInst) != 0) {
        write_runlog(FATAL, "we can't find instance: %u.\n", g_commandOperationInstanceId);
        return CM_ERROR;
    }

    if (g_commandOperationNodeId != 0 && curInst.node != g_commandOperationNodeId) {
        write_runlog(FATAL, "'-n'(node:%u) is not same with '-I'(node:%u).\n", g_commandOperationNodeId, curInst.node);
        return CM_ERROR;
    }

    PromoteMode pMode = PMODE_AUTO;
    if (strcasecmp(g_cmsPromoteMode, "AUTO") == 0) {
        pMode = PMODE_AUTO;
    } else if (strcasecmp(g_cmsPromoteMode, "PRIMARY_F") == 0) {
        pMode = PMODE_FORCE_PRIMAYR;
    } else {
        write_runlog(FATAL, "'--cmsPromoteMode' illegal(%s), must be 'AUTO' or 'PRIMARY_F'.\n", g_cmsPromoteMode);
        return CM_ERROR;
    }

    return SetCmsPromoteModeCore(&curInst, pMode);
}

static status_t SendDdbCmdMsgToCms(const char *cmd)
{
    errno_t rc;
    ExecDdbCmdMsg sendMsg;

    write_runlog(DEBUG1, "Sending msg to cm_server to do ddb cmd.\n");

    rc = memset_s(sendMsg.cmdLine, DCC_CMD_MAX_LEN, 0, DCC_CMD_MAX_LEN);
    securec_check_errno(rc, (void)rc);

    sendMsg.msgType = static_cast<int>(MSG_EXEC_DDB_COMMAND);
    rc = strcpy_s(sendMsg.cmdLine, DCC_CMD_MAX_LEN, cmd);
    securec_check_errno(rc, (void)rc);

    if (cm_client_send_msg(CmServer_conn, 'C', (char*)(&sendMsg), sizeof(ExecDdbCmdMsg)) != 0) {
        FINISH_CONNECTION_WITHOUT_EXITCODE((CmServer_conn));
        write_runlog(ERROR, "ctl send exec ddb cmd msg to cms failed.\n");
        (void)printf(_("exec ddb cmd fail.\n"));
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

void DoDccCmd(int argc, char **argv)
{
    int ret;
    size_t curLen = 0;
    char cmd[DCC_CMD_MAX_LEN];

    if (argc <= OPTION_POS) {
        write_runlog(ERROR, "exec ddb command without param.\n");
        return;
    }
    InitDdbCmdMsgFunc();
    for (int i = OPTION_POS; i < argc; ++i) {
        size_t optionLen = strlen(argv[i]);
        if (optionLen > CM_PATH_LENGTH) {
            write_runlog(ERROR, "The option len(%zu) is more than 1k, can't exec the cmd.\n", optionLen);
            return;
        }
        ++optionLen;
        if ((curLen + optionLen) >= sizeof(cmd)) {
            write_runlog(ERROR, "The cmd len is longer than %d, can't exec the cmd.\n", DCC_CMD_MAX_LEN);
            return;
        }
        ret = snprintf_s((cmd + curLen), (sizeof(cmd) - curLen), ((sizeof(cmd) - curLen) - 1),
            " %s", argv[i]);
        securec_check_intval(ret, (void)ret);
        curLen += optionLen;
    }

    do_conn_cmserver(false, 0);
    if (CmServer_conn == NULL) {
        write_runlog(LOG, "exec ddb cmd fail, can't connect to cmserver.\n");
        return;
    }

    if (SendDdbCmdMsgToCms(cmd) != CM_SUCCESS) {
        return;
    }

    GetExecCmdResult(argv[OPTION_POS], (int)EXEC_DDB_COMMAND_ACK);

    // close conn
    FINISH_CONNECTION_WITHOUT_EXITCODE(CmServer_conn);

    return;
}
