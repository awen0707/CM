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
 * cma_instance_management.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_agent/cma_instance_management.cpp
 *
 * -------------------------------------------------------------------------
 */
#include <sys/wait.h>
#include <netdb.h>
#include <ifaddrs.h>
#include "cma_global_params.h"
#include "cm/stringinfo.h"
#include "cm/libpq-fe.h"
#include "cm/libpq-int.h"
#include "common/config/cm_config.h"
#include "cma_alarm.h"
#include "cma_common.h"
#include "cma_client.h"
#include "cma_process_messages.h"
#ifdef ENABLE_MULTIPLE_NODES
#include "cma_coordinator.h"
#include "cma_coordinator_utils.h"
#include "cma_cn_gtm_instance_management.h"
#endif
#include "cma_instance_management_res.h"
#include "cma_network_check.h"
#include "cma_instance_management.h"

#ifdef ENABLE_UT
#define static
#endif


static bool IsCmsReplaceFlagFileExists();
static void StopCmInstance();
static void StopOneZengine(uint32 index);
static bool StopCurDnFloatIp(uint32 index);

#ifdef ENABLE_GCOV
static const int SIG_TYPE = 2;
#else
static const int SIG_TYPE = 9;
#endif
bool g_isDnFirstStart = true;

typedef void (*StartCheck)(void);
typedef bool (*StartDnCheck)(void);


/*
 * @brief A helper function to indicate whether the gs_relpace command is running to repair the faulty cms
 *
 * @return true gs_replace command is running, and the cms replace flag file is existed.
 * @return false gs_replace command is not executed or finished, and the cms replace flag file is not existed.
 *
 */
static bool IsCmsReplaceFlagFileExists()
{
    errno_t rc;
    struct stat cmsStatBuf = {0};
    bool cmsReplace = false;
    char instanceReplace[MAX_PATH_LEN] = {0};

    rc = snprintf_s(instanceReplace,
        MAX_PATH_LEN,
        MAX_PATH_LEN - 1,
        "%s/%s_%s_%u",
        g_binPath,
        CM_INSTANCE_REPLACE,
        "cmserver",
        g_currentNode->cmServerId);
    securec_check_intval(rc, (void)rc);

    if (stat(instanceReplace, &cmsStatBuf) == 0) {
        cmsReplace = true;
        write_runlog(LOG, "the cms %u is being repaired by gs_replace, do not start it!\n", g_currentNode->cmServerId);
    } else {
        write_runlog(DEBUG1, "the cms %u is not being repaired by gs_replace!\n", g_currentNode->cmServerId);
    }

    return cmsReplace;
}

void start_cmserver_check(void)
{
    int ret;
    int alarmReason = UNKNOWN_BAD_REASON;
    int rc;
    char command[MAXPGPATH] = {0};
    char instanceName[CM_NODE_NAME] = {0};
    struct stat cluster_stat_buf = {0};
    AlarmAdditionalParam tempAdditionalParam;
    bool cdt;

    /* If the current node does not deploy cms, we do not need to execute the operation of cms start-detection. */
    if (g_currentNode->cmServerLevel != 1) {
        return;
    }

    uint32 alarmIndex = g_currentNode->datanodeCount;
    rc = snprintf_s(
        instanceName, sizeof(instanceName), sizeof(instanceName) - 1, "%s_%u", "cms", g_currentNode->cmServerId);
    securec_check_intval(rc, (void)rc);
    rc = memset_s(command, MAXPGPATH, 0, MAXPGPATH);
    securec_check_errno(rc, (void)rc);
    rc = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1, "%s/%s", g_binPath, CM_SERVER_BIN_NAME);
    securec_check_intval(rc, (void)rc);

    /*
     * If cmserver data path disk fault, kill cmserver
     */
    if (stat(g_cmManualStartPath, &cluster_stat_buf) != 0) {
        cdt = (!agentCheckDisc(g_currentNode->cmDataPath) || !agentCheckDisc(g_logBasePath));
        if (cdt) {
            write_runlog(ERROR, "data path disk writable test failed, %s.\n", g_currentNode->cmDataPath);
            g_cmsDiskDamage = true;
            set_instance_not_exist_alarm_value(&alarmReason, DISC_BAD_REASON);
        } else {
            g_cmsDiskDamage = false;
        }
    } else {
        g_cmsDiskDamage = false;
    }

    if (!GetNicStatus(g_currentNode->cmServerId, CM_INSTANCE_TYPE_CMS)) {
        write_runlog(WARNING, "nic related with cmserver not up.\n");
        g_cmsNicDown = true;
        set_instance_not_exist_alarm_value(&alarmReason, NIC_BAD_REASON);
    } else {
        g_cmsNicDown = false;
    }

    ret = check_one_instance_status(CM_SERVER_BIN_NAME, command, NULL);
    switch (ret) {
        case PROCESS_RUNNING:
            cdt = (g_cmsDiskDamage || g_cmsNicDown);
            if (cdt) {
                write_runlog(LOG,
                    "cms_%u is killed because disk fault or nic fault, g_cmsDiskDamage=%d, g_cmsNicDown=%d.\n",
                    g_currentNode->cmServerId,
                    g_cmsDiskDamage,
                    g_cmsNicDown);
                if (g_startupAlarmList != NULL) {
                    g_startCmsCount = 0;
                    /* fill the alarm message */
                    WriteAlarmAdditionalInfo(&tempAdditionalParam,
                        instanceName,
                        "",
                        "",
                        "",
                        &(g_startupAlarmList[alarmIndex]),
                        ALM_AT_Fault,
                        instanceName,
                        instance_not_exist_reason_to_string(alarmReason));
                    /* report the alarm */
                    AlarmReporter(&(g_startupAlarmList[alarmIndex]), ALM_AT_Fault, &tempAdditionalParam);
                }
                StopCmInstance();
            } else {
                if (g_startupAlarmList != NULL) {
                    g_startCmsCount = 0;
                    /* fill the alarm message */
                    WriteAlarmAdditionalInfo(&tempAdditionalParam, instanceName, "", "", "",
                        &(g_startupAlarmList[alarmIndex]), ALM_AT_Resume);
                    /* report the alarm */
                    AlarmReporter(&(g_startupAlarmList[alarmIndex]), ALM_AT_Resume, &tempAdditionalParam);
                }
            }
            break;
        case PROCESS_NOT_EXIST:
            if (g_startCmsCount < STARTUP_CMS_CHECK_TIMES) {
                /*
                 * the value is -1, it meas the
                 * cluster is starting now ,and cmserver don't start any one
                 */
                if (g_startCmsCount == -1) {
                    g_startCmsCount = 1;
                } else {
                    ++g_startCmsCount;
                }
            } else {
                if (g_startupAlarmList != NULL) {
                    /* fill the alarm message */
                    WriteAlarmAdditionalInfo(&tempAdditionalParam,
                        instanceName,
                        "",
                        "",
                        "",
                        &(g_startupAlarmList[alarmIndex]),
                        ALM_AT_Fault,
                        instanceName);
                    /* report the alarm */
                    AlarmReporter(&(g_startupAlarmList[alarmIndex]), ALM_AT_Fault, &tempAdditionalParam);
                }
            }

            if (g_cmsDiskDamage || g_cmsNicDown) {
                write_runlog(LOG, "g_cmsDiskDamage is %d, and g_cmsNicDown is %d, cannot start cms.\n",
                    g_cmsDiskDamage, g_cmsNicDown);
                return;
            }

            /* Judge the current node cms whether the cms is under replacing */
            if (IsCmsReplaceFlagFileExists()) {
                write_runlog(LOG, "the node(%u) cms is being replaced, do not start it!\n", g_currentNode->node);
                return;
            }

            cdt = (agentCheckPort(g_currentNode->port) <= 0 && agentCheckPort(g_currentNode->cmServerLocalHAPort) <= 0);
            if (cdt) {
                rc = memset_s(command, MAXPGPATH, 0, MAXPGPATH);
                securec_check_errno(rc, (void)rc);
                rc = snprintf_s(command,
                    MAXPGPATH,
                    MAXPGPATH - 1,
                    SYSTEMQUOTE "%s/%s >> \"%s\" 2>&1 &" SYSTEMQUOTE,
                    g_binPath,
                    CM_SERVER_BIN_NAME,
                    system_call_log);
                securec_check_intval(rc, (void)rc);

                write_runlog(LOG, "CM_SERVER START system(command:%s).\n", command);
                ret = system(command);
                if (ret != 0) {
                    write_runlog(ERROR, "run system command failed %d! %s, errno=%d.\n", ret, command, errno);
                }
            }
            break;
        default:
            write_runlog(ERROR, "error.cm_server,ret=%d\n", ret);
            break;
    }
}

static void CheckProcessNum(const char* cmdLine)
{
    char    command[MAXPGPATH] = { 0 };
    char    line[MAXPGPATH] = { 0 };
    char    buffer[MAXPGPATH] = { 0 };
    uint32  processCount = 0;
 
    int ret = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1, "ps ux | grep -v grep | grep \"%s\"", cmdLine);
    securec_check_intval(ret, (void)ret);
 
    FILE *fp = popen(command, "re");
    if (fp == NULL) {
        return;
    }

    while (!feof(fp)) {
        if (fgets(line, MAXPGPATH - 1, fp)) {
            ret = strcat_s(buffer, MAXPGPATH, line);
            securec_check_errno(ret, (void)ret);
            processCount++;
        }
    }
    (void)pclose(fp);
 
    if (processCount > 1) {
        write_runlog(ERROR, "Multiple processes <%s>, buf is\n%s", cmdLine, buffer);
        ret = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1,
            "ps ux | grep -v grep| grep \"%s\"| awk '{print $2}'| xargs kill -9", cmdLine);
        securec_check_intval(ret, (void)ret);
        ret = system(command);
        if (ret != 0) {
            write_runlog(ERROR, "[CheckProcessNum] Failed to execute the command: command=\"%s\","
                "errno=%d.\n", command, errno);
            return;
        }
        write_runlog(LOG, "[CheckProcessNum] kill all <%s> process success.\n", cmdLine);
    }
}

/*
 * check if fenced UDF is not running and start it.
 */
void start_fenced_UDF_check(void)
{
    int ret;

    ret = check_one_instance_status(FENCED_MASTER_BIN_NAME, "fenced", NULL);
    if (ret == PROCESS_NOT_EXIST) {
        char command[MAXPGPATH];
        errno_t rc;
        int rcs;

        g_fencedUdfStopped = true;

        rc = memset_s(command, MAXPGPATH, 0, MAXPGPATH);
        securec_check_errno(rc, (void)rc);
        rcs = snprintf_s(command,
            MAXPGPATH,
            MAXPGPATH - 1,
            SYSTEMQUOTE "%s/%s --fenced -k %s -D %s >> \"%s\" 2>&1 &" SYSTEMQUOTE,
            g_binPath,
            FENCED_MASTER_BIN_NAME,
            g_unixSocketDirectory,
            sys_log_path,
            system_call_log);
        securec_check_intval(rcs, (void)rcs);

        write_runlog(LOG, "FENCED UDF START system(command:%s).\n", command);
        ret = system(command);
        if (ret != 0) {
            write_runlog(ERROR, "run system command failed %d! %s, errno=%d.\n", ret, command, errno);
        }
    } else {
        CheckProcessNum("gaussdb fenced UDF master");
        g_fencedUdfStopped = false;
    }
}

void CheckAgentNicDown()
{
    if (!GetNicStatus(g_currentNode->cmAgentId, CM_INSTANCE_TYPE_CMA)) {
        write_runlog(WARNING, "nic related with cm_agent not up.\n");
        g_agentNicDown = true;
    } else {
        g_agentNicDown = false;
    }
}

static void ComputeCheckTime(const cmTime_t *checkBegin, const char *str)
{
    const long ddbTime = 2;
    struct timespec checkEnd = {0, 0};
    (void)clock_gettime(CLOCK_MONOTONIC, &checkEnd);
    if (checkEnd.tv_sec - checkBegin->tv_sec > ddbTime) {
        write_runlog(LOG, "%s, it takes %ld s.\n", str, (checkEnd.tv_sec - checkBegin->tv_sec));
    }
}

static void StartInstanceAndCheck(StartCheck startCheck, const char *str)
{
    if (startCheck == NULL) {
        return;
    }
    cmTime_t checkBegin = {0, 0};
    (void)clock_gettime(CLOCK_MONOTONIC, &checkBegin);
    startCheck();
    ComputeCheckTime(&checkBegin, str);
}

static bool CheckDnCanStart(StartDnCheck startCheck, const char *str)
{
    if (startCheck == NULL) {
        return true;
    }
    cmTime_t checkBegin = {0, 0};
    (void)clock_gettime(CLOCK_MONOTONIC, &checkBegin);
    bool needStartDnCheck = startCheck();
    ComputeCheckTime(&checkBegin, str);
    return needStartDnCheck;
}

void start_instance_check(void)
{
    if (g_shutdownRequest) {
        return;
    }
#ifdef ENABLE_MULTIPLE_NODES
    StartInstanceAndCheck(start_gtm_check, "[start_gtm_check]");

    StartInstanceAndCheck(start_coordinator_check, "[start_coordinator_check]");
#endif

    StartInstanceAndCheck(start_cmserver_check, "[start_cmserver_check]");

    bool needStartDnCheck = CheckDnCanStart(CheckStartDN, "[CheckStartDN]");
    /* ignore pausing state when firstly starting, otherwise 
     * skip StartDatanodeCheck and StartResourceCheck in pausing state
     */
    if (g_isDnFirstStart) {
        if (needStartDnCheck && !g_enableSharedStorage) {
            StartInstanceAndCheck(StartDatanodeCheck, "[StartDatanodeCheck]");
        }
    } else {
        if (!g_isPauseArbitration && needStartDnCheck && !g_enableSharedStorage) {
            StartInstanceAndCheck(StartDatanodeCheck, "[StartDatanodeCheck]");
        }
    }

    StartInstanceAndCheck(CheckAgentNicDown, "[CheckAgentNicDown]");

    if (IsCusResExistLocal() && !(g_isPauseArbitration && !g_isStarting)) {
        StartInstanceAndCheck(StartResourceCheck, "[StartResourceCheck]");
    }

    if (g_clusterType == V3SingleInstCluster) {
        return;
    }

#ifdef ENABLE_MULTIPLE_NODES
    if (g_currentNode->coordinate == 1 || g_currentNode->datanodeCount > 0) {
#else
    if (g_currentNode->datanodeCount > 0 && needStartDnCheck) {
#endif
        StartInstanceAndCheck(start_fenced_UDF_check, "[start_fenced_UDF_check]");
    } else {
        g_fencedUdfStopped = true;
    }
}

static ShutdownMode GetShutdownMode(int32 mode)
{
    if (mode < (int32)FAST_MODE || mode >= (int32)SHUTDOWN_CEIL_MODE) {
        return FAST_MODE;
    }
    return (ShutdownMode)mode;
}

/* get the lines from a text file - return NULL if file can't be opened */
void get_stop_mode(const char *path)
{
    FILE *infile;
    int linelen = 0;
    int nlines = 0;
    int c;
    const int bufferLen = 8;
    char buffer[bufferLen];

    g_cmDoForce = false;
    g_cmShutdownMode = FAST_MODE;
    g_cmShutdownLevel = SINGLE_INSTANCE;

    if ((infile = fopen(path, "re")) == NULL) {
        write_runlog(ERROR, "fopen error.\n");
        return;
    }

    while ((c = fgetc(infile)) != EOF) {
        linelen++;
        if (c == '\n') {
            nlines++;
            linelen = 0;
        }
    }

    /* handle last line without a terminating newline (yuck) */
    if (linelen) {
        nlines++;
    }
    /* cluster_manual_start file damaged. */
    if (nlines < 3) {
        write_runlog(LOG, "cluster_manual_start file damaged.\n");
        (void)fclose(infile);
        return;
    }

    write_runlog(LOG, "[%s] nlines :%d\n", __FUNCTION__, nlines);
    rewind(infile);
    if (fgets(buffer, bufferLen, infile) != NULL) {
        g_cmDoForce = CmAtoBool(buffer);
    }
    if (fgets(buffer, bufferLen, infile) != NULL) {
        g_cmShutdownMode = GetShutdownMode(CmAtoi(buffer, (int)FAST_MODE));
    }
    if (fgets(buffer, bufferLen, infile) != NULL) {
        g_cmShutdownLevel = CmAtoi(buffer, SINGLE_INSTANCE);
    }

    write_runlog(LOG, "g_cmDoForce :%d,g_cmShutdownMode:%d, g_cmShutdownLevel:%d\n",
        g_cmDoForce, g_cmShutdownMode, g_cmShutdownLevel);
    (void)fclose(infile);
    return;
}

/*
 * 0 if read pid failed,
 * pid if success.
 */
static pid_t get_instances_pid(const char *pidPath)
{
    pid_t pid;

    FILE *pidf = fopen(pidPath, "re");
    if (pidf == NULL) {
        /* No pid file, not an error on startup */
        char errBuffer[ERROR_LIMIT_LEN];
        if (errno == ENOENT) {
            write_runlog(ERROR, "PID file :\"%s\" does not exist: %s\n.", pidPath,
                strerror_r(errno, errBuffer, ERROR_LIMIT_LEN));
        } else {
            write_runlog(
                ERROR, "could not open PID file \"%s\": %s\n.", pidPath, strerror_r(errno, errBuffer, ERROR_LIMIT_LEN));
        }
        return 0;
    }
    if (fscanf_s(pidf, "%d", &pid) != 1) {
        write_runlog(ERROR, "invalid data in PID file \"%s\"\n", pidPath);
        (void)fclose(pidf);
        return 0;
    }
    (void)fclose(pidf);
    return pid;
}

void fast_stop_one_instance(const char *instDataPath, InstanceTypes instance_type)
{
    int fast_sig = SIGINT;
    pid_t pid;
    char pid_path[MAXPGPATH] = {0};
    int ret;
    int rcs = 0;

    if (instance_type == INSTANCE_CN) {
        rcs = snprintf_s(pid_path, MAXPGPATH, MAXPGPATH - 1, "%s/%s", instDataPath, "postmaster.pid");
    } else if (instance_type == INSTANCE_DN) {
        rcs = snprintf_s(pid_path, MAXPGPATH, MAXPGPATH - 1, "%s/%s", instDataPath, "postmaster.pid");
    } else if (instance_type == INSTANCE_GTM) {
        rcs = snprintf_s(pid_path, MAXPGPATH, MAXPGPATH - 1, "%s/%s", instDataPath, "gtm.pid");
    }
    securec_check_intval(rcs, (void)rcs);

    pid = get_instances_pid(pid_path);
    if (pid == 0) {
        ret = check_one_instance_status(type_int_to_str_binname(instance_type), instDataPath, NULL);
        if (ret == PROCESS_RUNNING) {
            write_runlog(ERROR,
                "%s' pid is 0, but still running, use kill_instance_force(): %s.\n",
                type_int_to_str_name(instance_type),
                instDataPath);
            kill_instance_force(instDataPath, instance_type);
        }
        return;
    }
    /* now  just send sig once. */
    if (kill(pid, fast_sig) != 0) {
        write_runlog(ERROR,
            "fast shutdown ,could not send stop signal (PID: %d), kill_instance_force():%s.\n",
            pid,
            instDataPath);
        kill_instance_force(instDataPath, instance_type);
        return;
    }

    if ((instance_type == INSTANCE_GTM) && (g_cmShutdownLevel != ALL_NODES)) {
        cm_sleep(2);
        ret = check_one_instance_status(type_int_to_str_binname(instance_type), instDataPath, NULL);
        if (ret == PROCESS_RUNNING) {
            write_runlog(ERROR,
                "%s is still running, use kill_instance_force to kill : %s.\n",
                type_int_to_str_name(instance_type),
                instDataPath);
            kill_instance_force(instDataPath, instance_type);
        }
    }

    if (instance_type == INSTANCE_DN) {
        ExecuteEventTrigger(EVENT_STOP);
    }

    write_runlog(LOG, "%s shutting down.\n", type_int_to_str_name(instance_type));
}

void CheckOfflineNode(uint32 i)
{
    int rcs = 0;
    if (!CheckStartDN()) {
        rcs = check_one_instance_status(DATANODE_BIN_NAME, g_currentNode->datanode[i].datanodeLocalDataPath, NULL);
        if (rcs == PROCESS_RUNNING) {
            immediate_stop_one_instance(g_currentNode->datanode[i].datanodeLocalDataPath, INSTANCE_DN);
        }
        rcs = check_one_instance_status(FENCED_MASTER_BIN_NAME, "fenced", NULL);
        if (rcs == PROCESS_RUNNING) {
            g_fencedUdfStopped = true;
            kill_instance_force("fenced", INSTANCE_FENCED);
        }
    }
}

void stop_datanode_check(uint32 i)
{
    bool cdt;
    struct stat instanceStatBuf = {0};
    struct stat clusterStatBuf = {0};
    errno_t rc;
    int rcs;
    char instanceManualStartPath[MAX_PATH_LEN] = {0};
    char instanceReplace[MAX_PATH_LEN] = {0};

    rc = memset_s(instanceManualStartPath, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rcs = snprintf_s(instanceManualStartPath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s_%u",
        g_cmInstanceManualStartPath, g_currentNode->datanode[i].datanodeId);
    securec_check_intval(rcs, (void)rcs);
    check_input_for_security(instanceManualStartPath);
    canonicalize_path(instanceManualStartPath);
    rcs = snprintf_s(instanceReplace, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/%s_%u",
        g_binPath, CM_INSTANCE_REPLACE, g_currentNode->datanode[i].datanodeId);
    securec_check_intval(rcs, (void)rcs);
    CheckOfflineNode(i);
    cdt = (stat(instanceManualStartPath, &instanceStatBuf) == 0 || stat(g_cmManualStartPath, &clusterStatBuf) == 0);
    if (cdt) {
        if (stat(instanceReplace, &instanceStatBuf) == 0) {
            write_runlog(LOG,
                "datanode(%s) is being replaced and can't be stopped.\n",
                g_currentNode->datanode[i].datanodeLocalDataPath);
            return;
        }
        get_stop_mode(instanceManualStartPath);
        cdt = (g_cmShutdownMode == IMMEDIATE_MODE || (g_cmShutdownMode == FAST_MODE && g_isCmaBuildingDn[i]));
        if (cdt) {
            char build_pid_path[MAXPGPATH];

            rc = memset_s(build_pid_path, MAXPGPATH, 0, MAXPGPATH);
            securec_check_errno(rc, (void)rc);
            rcs = snprintf_s(build_pid_path,
                MAXPGPATH,
                MAXPGPATH - 1,
                "%s/gs_build.pid",
                g_currentNode->datanode[i].datanodeLocalDataPath);
            securec_check_intval(rcs, (void)rcs);
            pgpid_t pid = get_pgpid(build_pid_path, MAXPGPATH);
            cdt = (pid > 0 && is_process_alive(pid));
            if (cdt) {
                char cmd[MAXPGPATH];

                rc = memset_s(cmd, MAXPGPATH, 0, MAXPGPATH);
                securec_check_errno(rc, (void)rc);
                rcs = snprintf_s(cmd, MAXPGPATH, MAXPGPATH - 1, "kill -9 %ld >>%s 2>&1", pid, system_call_log);
                securec_check_intval(rcs, (void)rcs);
                write_runlog(LOG, "datanode immediate shutdown: %s \n", cmd);
                const char *shutdownModeStr = (g_cmShutdownMode == IMMEDIATE_MODE) ? "immediate" : "fast";
                write_runlog(LOG, "Shutdown the datanode %s : %s\n", shutdownModeStr, cmd);

                int ret = system(cmd);
                if (ret != 0) {
                    write_runlog(
                        ERROR, "datanode immediate shutdown: run system command failed! %s, errno=%d.\n", cmd, errno);
                } else {
                    if (g_isCmaBuildingDn[i]) {
                        g_isCmaBuildingDn[i] = false;
                        write_runlog(LOG,
                            "Shutdown the datanode %s successfully: %s. Then set g_isCmaBuildingDn to false.\n",
                            shutdownModeStr,
                            cmd);
                    }
                    ExecuteEventTrigger(EVENT_STOP);
                }
            } else {
                if (g_isCmaBuildingDn[i]) {
                    g_isCmaBuildingDn[i] = false;
                    write_runlog(LOG,
                        "Datanode %u shutdown: set g_isCmaBuildingDn to false.\n",
                        g_currentNode->datanode[i].datanodeId);
                }
            }
        }
        if (check_one_instance_status(GetDnProcessName(), g_currentNode->datanode[i].datanodeLocalDataPath, NULL) ==
            PROCESS_RUNNING) {
            if (g_cmShutdownMode == FAST_MODE) {
                write_runlog(
                    LOG, "datanode fast shutdown, datapath: %s.\n", g_currentNode->datanode[i].datanodeLocalDataPath);
                fast_stop_one_instance(g_currentNode->datanode[i].datanodeLocalDataPath, INSTANCE_DN);
            } else {
                write_runlog(LOG,
                    "datanode immediate shutdown, kill_instance_force(): %s.\n",
                    g_currentNode->datanode[i].datanodeLocalDataPath);
                immediate_stop_one_instance(g_currentNode->datanode[i].datanodeLocalDataPath, INSTANCE_DN);
            }
        }

        if (!g_isDnFirstStart) {
            g_isDnFirstStart = true;
        }

        (void)StopCurDnFloatIp(i);
    }
}

static void StopAllDatanode()
{
    for (uint32 i = 0; i < g_currentNode->datanodeCount; i++) {
        if (g_clusterType == V3SingleInstCluster) {
            StopOneZengine(i);
        } else {
            stop_datanode_check(i);
        }
    }
}

void stop_instances_check(void)
{
#ifdef ENABLE_MULTIPLE_NODES
    if (g_currentNode->gtm == 1) {
        stop_gtm_check();
    }

    if (g_currentNode->coordinate == 1) {
        stop_coordinator_check();
    }
#endif

    if (!g_enableSharedStorage) {
        StopAllDatanode();
    }

    if (IsCusResExistLocal()) {
        StopResourceCheck();
    }
}

static int cmserver_stopped_check(void)
{
    char command[MAXPGPATH];
    errno_t rc;
    int rcs;

    if (g_currentNode->cmServerLevel == 1) {
        rc = memset_s(command, MAXPGPATH, 0, MAXPGPATH);
        securec_check_errno(rc, (void)rc);
        rcs = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1, "%s/%s", g_binPath, CM_SERVER_BIN_NAME);
        securec_check_intval(rcs, (void)rcs);
        return check_one_instance_status(CM_SERVER_BIN_NAME, command, NULL);
    }

    return PROCESS_NOT_EXIST;
}

static NetworkState CheckCurDnFloatIpStatus(uint32 index)
{
    DnFloatIp *dnFloatIp = GetDnFloatIpByDnIdx(index);
    if (dnFloatIp == NULL || dnFloatIp->dnFloatIpCount == 0) {
        return NETWORK_STATE_UNKNOWN;
    }
    NetworkState state[MAX_FLOAT_IP_COUNT];
    GetFloatIpNicStatus(dnFloatIp->instId, CM_INSTANCE_TYPE_DN, state, dnFloatIp->dnFloatIpCount);
    for (uint32 i = 0; i < dnFloatIp->dnFloatIpCount; ++i) {
        if (state[i] == NETWORK_STATE_UP) {
            return NETWORK_STATE_UP;
        }
    }
    return NETWORK_STATE_DOWN;
}

static int32 CheckFloatIpStateInDn(uint32 index)
{
    uint32 count = DelFloatIpInDatanode(index);
    if (count != 0) {
        write_runlog(
            LOG, "line: %d: datanode(%u) floatIp is running.\n", __LINE__, g_currentNode->datanode[index].datanodeId);
        return PROCESS_RUNNING;
    }
    NetworkState state = CheckCurDnFloatIpStatus(index);
    if (state == NETWORK_STATE_UP) {
        write_runlog(
            LOG, "line: %d: datanode(%u) floatIp is running.\n", __LINE__, g_currentNode->datanode[index].datanodeId);
        return PROCESS_RUNNING;
    }
    return PROCESS_NOT_EXIST;
}

static int datanode_stopped_check(void)
{
    int ret;
    errno_t rc;

    const char *processName = GetDnProcessName();
    for (uint32 ii = 0; ii < g_currentNode->datanodeCount; ii++) {
        char build_pid_path[MAXPGPATH];

        ret = check_one_instance_status(processName, g_currentNode->datanode[ii].datanodeLocalDataPath, NULL);

        rc = memset_s(build_pid_path, MAXPGPATH, 0, MAXPGPATH);
        securec_check_errno(rc, (void)rc);
        rc = snprintf_s(build_pid_path,
            MAXPGPATH,
            MAXPGPATH - 1,
            "%s/gs_build.pid",
            g_currentNode->datanode[ii].datanodeLocalDataPath);
        securec_check_intval(rc, (void)rc);
        pgpid_t pid = get_pgpid(build_pid_path, MAXPGPATH);
        if ((ret == PROCESS_RUNNING) || (pid > 0 && is_process_alive(pid))) {
            write_runlog(LOG, "data  node is running path is %s\n", g_currentNode->datanode[ii].datanodeLocalDataPath);
            return PROCESS_RUNNING;
        }
        if (CheckFloatIpStateInDn(ii) == PROCESS_RUNNING) {
            return PROCESS_RUNNING;
        }
    }

    return PROCESS_NOT_EXIST;
}

/**
 * @brief stop the internal processes of CM instance
 *
 * @param  cm_path       the path of CM instance
 */
void stop_cm_instance_internal(const char *cm_path)
{
    char system_cmd[MAXPGPATH] = {'\0'};
    int ret;
    char toolPath[MAX_PATH_LEN] = {'\0'};
    char pyPstreePath[MAX_PATH_LEN] = {'\0'};

    /* Get tool path */
    ret = cmagent_getenv("GPHOME", toolPath, sizeof(toolPath));
    if (ret != EOK) {
        write_runlog(FATAL, "get env GPHOME fail.\n");
        exit(ret);
    }

    ret = snprintf_s(pyPstreePath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/script/py_pstree.py", toolPath);
    securec_check_intval(ret, (void)ret);

    ret = access(pyPstreePath, F_OK);
    if (ret != EOK) {
        write_runlog(FATAL, "%s may be not exist.\n", pyPstreePath);
        exit(ret);
    }

    ret = snprintf_s(system_cmd,
        MAXPGPATH,
        MAXPGPATH - 1,
        "pidList=`ps aux | grep \"%s\" | grep -v 'grep' | awk '{print $2}' | xargs `; for pid in $pidList; do "
        "%s -c $pid -s $pid | xargs -r -n 100 kill -%d; done",
        cm_path, pyPstreePath, SIG_TYPE);
    securec_check_intval(ret, (void)ret);

    struct stat statBuf = {0};
    if (stat(system_call_log, &statBuf) == 0) {
        /* redirect to system_call.log */
        ret = strncat_s(system_cmd, MAXPGPATH, " >> ", strlen(" >> "));
        securec_check_errno(ret, (void)ret);
        ret = strncat_s(system_cmd, MAXPGPATH, system_call_log, strlen(system_call_log));
        securec_check_errno(ret, (void)ret);
        ret = strncat_s(system_cmd, MAXPGPATH, " 2>&1", strlen(" 2>&1"));
        securec_check_errno(ret, (void)ret);
    }

    struct timeval timeOut = {0};
    timeOut.tv_sec = 10;
    timeOut.tv_usec = 0;

    write_runlog(LOG, "stop_cm_instance: command= %s \n", system_cmd);

    if (ExecuteCmd(system_cmd, timeOut)) {
        write_runlog(WARNING, "stop_cm_instance: execute command failed. %s \n", system_cmd);
    } else {
        write_runlog(LOG, "cm_server shutting down.\n");
    }
}

static int check_process_status(const char *processName, int pid, char state, const char *cmd_line, int *isPhonyDead)
{
    static bool persist_T_status = false;
    bool isCMS = (strcmp(processName, CM_SERVER_BIN_NAME) == 0);

    if (state == 'd' || state == 'D') {
        write_runlog(LOG, "process (%s %d) is pending, can not receive signal, path is %s,"
            " state is D (TASK_UNINTERRUPTIBLE)\n", processName, pid, cmd_line);
        if (isPhonyDead != NULL) {
            *isPhonyDead = PROCESS_PHONY_DEAD_D;
        }
    } else if (state == 't' || state == 'T') {
        write_runlog(ERROR, "process (%s %d) is T (STOPPED), path is %s\n", processName, pid, cmd_line);

        if (isCMS && persist_T_status) {
            write_runlog(LOG, "kill CMS process (%s:%d) due to STOPPED!\n", processName, pid);
            stop_cm_instance_internal(cmd_line);
            return PROCESS_NOT_EXIST;
        }

        if (isPhonyDead != NULL) {
            *isPhonyDead = PROCESS_PHONY_DEAD_T;
        }

        /* mark the process as corpse, only do it for CMS now. */
        persist_T_status = isCMS || persist_T_status;
    } else if (state == 'z' || state == 'Z') {
        write_runlog(ERROR, "process (%s %d) is Z (STOPPED), path is %s\n", processName, pid, cmd_line);
        if (isPhonyDead != NULL) {
            *isPhonyDead = PROCESS_PHONY_DEAD_Z;
        }
    } else {
        persist_T_status = !isCMS && persist_T_status;
        write_runlog(DEBUG5, "process (%s %d) is running, path is %s, haveFound is 1\n", processName, pid, cmd_line);
    }
    return PROCESS_RUNNING;
}

static int GetProcessInfo(const char *processName, const char *cmdLine, int *processId, char *processState)
{
    DIR *dir;
    struct dirent *de = NULL;
    char pidPath[MAX_PATH_LEN];
    char cmdPath[MAX_PATH_LEN];
    FILE *fp = NULL;
    char getBuff[MAX_PATH_LEN];
    char paraName[MAX_PATH_LEN];
    char paraValue[MAX_PATH_LEN];
    int pid = 0, ppid = 0;
    char state = '0';
    uid_t uid = 0, uid1 = 0, uid2 = 0, uid3 = 0;
    bool nameFound = false, stateGet = false, ppidGet = false;
    bool nameGet = false, haveFound = false, uidGet = false;
    char *p = NULL;
    int i = 0;
    int paralen;
    errno_t rc;
    int rcs;
    bool isProcessFile = false;
    bool cdt;

    if ((dir = opendir("/proc")) == NULL) {
        write_runlog(LOG, "opendir(/proc) failed! \n");
        return PROCESS_UNKNOWN;
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

        isProcessFile = true;

        rc = memset_s(pidPath, MAX_PATH_LEN, 0, MAX_PATH_LEN);
        securec_check_errno(rc, (void)rc);
        pid = (int)strtol(de->d_name, NULL, 10);
        {
            rcs = snprintf_s(pidPath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/proc/%d/status", pid);
            securec_check_intval(rcs, (void)rcs);
        }

        /* maybe fail because of privilege */
        fp = fopen(pidPath, "re");
        if (fp == NULL) {
            continue;
        }

        nameGet = false;
        ppidGet = false;
        stateGet = false;
        uidGet = false;
        rc = memset_s(paraValue, MAX_PATH_LEN, 0, MAX_PATH_LEN);
        securec_check_errno(rc, (void)rc);
        ppid = 0;
        state = '0';
        uid = 0;
        rc = memset_s(getBuff, MAX_PATH_LEN, 0, MAX_PATH_LEN);
        securec_check_errno(rc, (void)rc);
        nameFound = false;

        while (fgets(getBuff, MAX_PATH_LEN - 1, fp) != NULL) {
            rc = memset_s(paraName, MAX_PATH_LEN, 0, MAX_PATH_LEN);
            securec_check_errno(rc, (void)rc);

            cdt = (!nameGet && (strstr(getBuff, "Name:") != NULL));
            if (cdt) {
                nameGet = true;
                rcs = sscanf_s(getBuff, "%s %s", paraName, MAX_PATH_LEN, paraValue, MAX_PATH_LEN);
                check_sscanf_s_result(rcs, 2);
                securec_check_intval(rcs, (void)rcs);

                if (strcmp(processName, paraValue) != 0) {
                    break;
                }
                nameFound = true;
            }

            cdt = (!ppidGet && (strstr(getBuff, "PPid:") != NULL));
            if (cdt) {
                ppidGet = true;
                rcs = sscanf_s(getBuff, "%s %d", paraName, MAX_PATH_LEN, &ppid);
                check_sscanf_s_result(rcs, 2);
                securec_check_intval(rcs, (void)rcs);
            }

            cdt = (!stateGet && (strstr(getBuff, "State:") != NULL));
            if (cdt) {
                stateGet = true;
                rcs = sscanf_s(getBuff, "%s %c", paraName, MAX_PATH_LEN, &state, 1);
                check_sscanf_s_result(rcs, 2);
                securec_check_intval(rcs, (void)rcs);
            }

            cdt = (!uidGet && (strstr(getBuff, "Uid:") != NULL));
            if (cdt) {
                uidGet = true;
                rcs = sscanf_s(
                    getBuff, "%s    %u    %u    %u    %u", paraName, MAX_PATH_LEN, &uid, &uid1, &uid2, &uid3);
                check_sscanf_s_result(rcs, 5);
                securec_check_intval(rcs, (void)rcs);
            }

            cdt = (nameGet && ppidGet && stateGet && uidGet);
            if (cdt) {
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

        rc = memset_s(cmdPath, MAX_PATH_LEN, 0, MAX_PATH_LEN);
        securec_check_errno(rc, (void)rc);
        rcs = snprintf_s(cmdPath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/proc/%d/cmdline", pid);
        securec_check_intval(rcs, (void)rcs);
        fp = fopen(cmdPath, "re");
        if (fp == NULL) {
            continue;
        }
        rc = memset_s(getBuff, MAX_PATH_LEN, 0, MAX_PATH_LEN);
        securec_check_errno(rc, (void)rc);

        if (fgets(getBuff, MAX_PATH_LEN - 1, fp) != NULL) {
            p = getBuff;
            i = 0;
            while (i < MAX_PATH_LEN - 1) {
                /* cmdline of CN,DN,GTM and CM begin with '/', and fenced UDF begin with '-', and kerberos with 'k'. */
                if (*p == '/') {
                    if (strcmp(p, cmdLine) == 0) {
                        haveFound = true;
                        break;
                    } else {
                        char *cmd_line_tmp = strdup(cmdLine);
                        if (cmd_line_tmp != NULL) {
                            canonicalize_path(cmd_line_tmp);
                            if (strcmp(p, cmd_line_tmp) == 0) {
                                haveFound = true;
                                FREE_AND_RESET(cmd_line_tmp);
                                break;
                            }
                            FREE_AND_RESET(cmd_line_tmp);
                        }
                        paralen = (int)strlen(p);
                        p = p + paralen;
                        i = i + paralen;
                    }
                } else if (*p == 'f') {
                    if (strstr(p, cmdLine) != NULL) {
                        haveFound = true;
                        break;
                    } else {
                        p++;
                        i++;
                    }
                } else if (*p == 'k') {
                    if (strstr(p, cmdLine) != NULL) {
                        haveFound = true;
                        break;
                    } else {
                        p++;
                        i++;
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
            rc = memset_s(getBuff, MAX_PATH_LEN, 0, MAX_PATH_LEN);
            securec_check_errno(rc, (void)rc);
        }
        (void)fclose(fp);

        if (haveFound) {
            break;
        }
    }

    (void)closedir(dir);

    if (!isProcessFile) {
        write_runlog(ERROR, "the process files may not exist in /proc.\n");
        return PROCESS_UNKNOWN;
    }
    
    if (haveFound) {
        *processId = pid;
        if (processState != NULL) {
            *processState = state;
        }
        return PROCESS_RUNNING;
    }
    write_runlog(LOG, "process (%s) is not running, path is %s, haveFound is 0\n", processName, cmdLine);
    return PROCESS_NOT_EXIST;
}

int killInstanceByPid(const char *processName, const char *cmdLine)
{
    int pid = 0;
    int runningState = GetProcessInfo(processName, cmdLine, &pid, NULL);
    if (runningState == PROCESS_RUNNING) {
        char killCmd[MAX_PATH_LEN] = {0};
        int rcs = snprintf_s(killCmd, MAX_PATH_LEN, MAX_PATH_LEN - 1, "kill -9 %d", pid);
        securec_check_intval(rcs, (void)rcs);

        write_runlog(LOG, "kill process %s, path is %s, command: %s\n", processName, cmdLine, killCmd);
        int ret = system(killCmd);
        if (ret != 0) {
            write_runlog(ERROR, "kill_instance_by_pid: system command failed, errno=%d.\n", errno);
            return -1;
        }
    }

    return 0;
}

int check_one_instance_status(const char *processName, const char *cmdLine, int *isPhonyDead)
{
    int32 processId = 0;
    char processState = '0';
    int32 runningState = GetProcessInfo(processName, cmdLine, &processId, &processState);
    if (runningState == PROCESS_RUNNING) {
        return check_process_status(processName, processId, processState, cmdLine, isPhonyDead);
    }
    write_runlog(LOG, "process (%s) is not running, path is %s, haveFound is 0\n", processName, cmdLine);
    return PROCESS_NOT_EXIST;
}

static int all_nodes_stopped_check()
{
    int ret;
    int count = 0;

#ifdef ENABLE_MULTIPLE_NODES
    ret = gtm_stopped_check();
    if (ret == PROCESS_RUNNING) {
        count++;
    }

    ret = coordinator_stopped_check();
    if (ret == PROCESS_RUNNING) {
        count++;
    }
#endif

    ret = cmserver_stopped_check();
    if (ret == PROCESS_RUNNING) {
        count++;
    }

    ret = datanode_stopped_check();
    if (ret == PROCESS_RUNNING) {
        count++;
    }

    ret = ResourceStoppedCheck();
    if (ret == PROCESS_RUNNING) {
        count++;
    }

    ret = check_one_instance_status(FENCED_MASTER_BIN_NAME, "fenced", NULL);
    if (ret == PROCESS_RUNNING) {
        count++;
    }
    return count;
}

static void StopCmInstance()
{
    char pid_path[MAXPGPATH] = {0};
    char cm_path[MAXPGPATH] = {0};
    char instanceDataPath[MAX_PATH_LEN] = {0};
    errno_t rcs = snprintf_s(
        instanceDataPath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/%s", g_currentNode->cmDataPath, CM_SERVER_DATA_DIR);
    securec_check_intval(rcs, (void)rcs);

    rcs = snprintf_s(pid_path, MAXPGPATH, MAXPGPATH - 1, "%s/%s", instanceDataPath, "cm_server.pid");
    securec_check_intval(rcs, (void)rcs);

    rcs = snprintf_s(cm_path, MAXPGPATH, MAXPGPATH - 1, "%s/%s", g_binPath, CM_SERVER_BIN_NAME);
    securec_check_intval(rcs, (void)rcs);

    pid_t pid = get_instances_pid(pid_path);
    if (pid == 0) {
        int ret = check_one_instance_status(type_int_to_str_binname(INSTANCE_CM), cm_path, NULL);
        if (ret == PROCESS_RUNNING) {
            write_runlog(ERROR,
                "%s' pid is 0, but still running, use kill_intance_force(): %s.\n",
                type_int_to_str_name(INSTANCE_CM),
                instanceDataPath);
            kill_instance_force(instanceDataPath, INSTANCE_CM);
        }
    } else {
        stop_cm_instance_internal(cm_path);
    }
}

static int stop_primary_check(const char *ssh_channel, const char *data_path)
{
    char command[MAXPGPATH] = {0};
    char result_str[MAX_BUF_LEN + 1] = {0};
    char mpprvFile[MAXPGPATH] = {0};
    int rc;

    int ret = cmagent_getenv("MPPDB_ENV_SEPARATE_PATH", mpprvFile, sizeof(mpprvFile));
    if (ret != EOK) {
        rc = snprintf_s(command,
            MAXPGPATH,
            MAXPGPATH - 1,
            "pssh %s -H %s \"cm_ctl check -B %s -T %s\" > /dev/null 2>&1; echo  -e $? > %s",
            PSSH_TIMEOUT_OPTION,
            ssh_channel,
            DATANODE_BIN_NAME,
            data_path,
            result_path);
    } else {
        check_input_for_security(mpprvFile);
        rc = snprintf_s(command,
            MAXPGPATH,
            MAXPGPATH - 1,
            "pssh %s -H %s \"source %s;cm_ctl check -B %s -T %s\" > /dev/null 2>&1; echo  -e $? > %s",
            PSSH_TIMEOUT_OPTION,
            ssh_channel,
            mpprvFile,
            DATANODE_BIN_NAME,
            data_path,
            result_path);
    }
    securec_check_intval(rc, (void)rc);

    ret = system(command);
    if (ret != 0) {
        write_runlog(LOG, "exec command failed !  command is %s, errno=%d.\n", command, errno);
        (void)unlink(result_path);
        return -1;
    }

    FILE *fd = fopen(result_path, "re");
    if (fd == NULL) {
        write_runlog(LOG, "fopen failed, errno[%d]!\n", errno);
        (void)unlink(result_path);
        return -1;
    }

    size_t bytesread = fread(result_str, 1, MAX_BUF_LEN, fd);
    if (bytesread > MAX_BUF_LEN) {
        write_runlog(LOG, "stop_primary_check fread file failed! file=%s, bytesread=%lu\n", result_path, bytesread);
        (void)fclose(fd);
        (void)unlink(result_path);
        return -1;
    }

    (void)fclose(fd);
    (void)unlink(result_path);
    return (int)strtol(result_str, NULL, 10);
}

static void normal_stop_one_instance(const char *instDataPath, InstanceTypes instance_type)
{
    int fast_sig = SIGTERM; /* normal mode */
    pid_t pid;
    char pid_path[MAXPGPATH] = {0};
    int ret;
    int rcs = 0;

    if (instance_type == INSTANCE_DN) {
        rcs = snprintf_s(pid_path, MAXPGPATH, MAXPGPATH - 1, "%s/%s", instDataPath, "postmaster.pid");
        securec_check_intval(rcs, (void)rcs);
    }

    pid = get_instances_pid(pid_path);
    if (pid == 0) {
        ret = check_one_instance_status(type_int_to_str_binname(instance_type), instDataPath, NULL);
        if (ret == PROCESS_RUNNING) {
            write_runlog(ERROR,
                "%s' pid is 0, but still running, use kill_instance_force(): %s.\n",
                type_int_to_str_name(instance_type),
                instDataPath);
            kill_instance_force(instDataPath, instance_type);
        }
        return;
    }
    /* now  just send sig once. */
    if (kill(pid, fast_sig) != 0) {
        write_runlog(ERROR,
            "normal shutdown ,could not send stop signal (PID: %d), kill_instance_force():%s.\n",
            pid,
            instDataPath);
        kill_instance_force(instDataPath, instance_type);
        return;
    }

    if (instance_type == INSTANCE_DN) {
        ExecuteEventTrigger(EVENT_STOP);
    }

    write_runlog(LOG, "%s shutting down.\n", type_int_to_str_name(instance_type));
}

static status_t StopPrimaryDatanode(uint32 role, const char *ip, const char *path)
{
    if (role != DUMMY_STANDBY_DN) {
        write_runlog(LOG, "peer ip: %s, datapath: %s.\n", ip, path);
        if (stop_primary_check(ip, path) == PROCESS_RUNNING) {
            write_runlog(LOG, "peer is still running.\n");
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

static void NormalShutdownOneDatanode(const dataNodeInfo *dnInfo, int localRole)
{
    if (localRole == INSTANCE_ROLE_STANDBY) {
        if (g_multi_az_cluster) {
            bool beContinue = false;
            for (uint32 j = 0; j < g_dn_replication_num - 1; ++j) {
                beContinue = false;
                if (StopPrimaryDatanode(dnInfo->peerDatanodes[j].datanodePeerRole,
                    dnInfo->peerDatanodes[j].datanodePeerHAIP[0],
                    dnInfo->peerDatanodes[j].datanodePeerDataPath) != CM_SUCCESS) {
                    beContinue = true;
                    break;
                }
            }
            if (beContinue && g_normalStopTryTimes < 3) {
                g_normalStopTryTimes++;
                return;
            }
        } else {
            if ((StopPrimaryDatanode(dnInfo->datanodePeerRole, dnInfo->datanodePeerHAIP[0],
                dnInfo->datanodePeerDataPath) != CM_SUCCESS) ||
                (StopPrimaryDatanode(dnInfo->datanodePeer2Role, dnInfo->datanodePeer2HAIP[0],
                dnInfo->datanodePeer2DataPath) != CM_SUCCESS)) {
                return;
            }
        }
    }

    write_runlog(LOG, "datanode normal shutdown, datapath: %s.\n", dnInfo->datanodeLocalDataPath);
    normal_stop_one_instance(dnInfo->datanodeLocalDataPath, INSTANCE_DN);
}

static void NormalShutdownAllDatanode()
{
    for (uint32 i = 0; i < g_currentNode->datanodeCount; ++i) {
        const dataNodeInfo *dnInfo = &g_currentNode->datanode[i];
        write_runlog(LOG, "local_role is %s, datapath: %s.\n",
            datanode_role_int_to_string(g_dnReportMsg[i].dnStatus.reportMsg.local_status.local_role),
            dnInfo->datanodeLocalDataPath);
        if (g_clusterType == V3SingleInstCluster) {
            StopOneZengine(i);
        } else {
            NormalShutdownOneDatanode(dnInfo, g_dnReportMsg[i].dnStatus.reportMsg.local_status.local_role);
        }
        DelAndDownFloatIpInDn(i);
    }
}

static void normal_shutdown_nodes(void)
{
    /* coordinator */
    if (g_currentNode->coordinate == 1) {
        write_runlog(LOG, "coordinator normal shutdown, datapath: %s.\n", g_currentNode->DataPath);
        fast_stop_one_instance(g_currentNode->DataPath, INSTANCE_CN);
    }

    /* datanode */
    if (!g_enableSharedStorage) {
        write_runlog(LOG, "datanode normal shutdown.\n");
        NormalShutdownAllDatanode();
    }

    /* resource */
    if (IsCusResExistLocal()) {
        write_runlog(LOG, "normal_shutdown_nodes, %u resource will be stopped.\n", GetLocalResConfCount());
        StopAllResInst();
    }

    /* cm_server */
    if (g_currentNode->cmServerLevel == 1) {
        write_runlog(LOG, "cm_server normal shutdown, datapath: %s.\n", g_currentNode->cmDataPath);
        StopCmInstance();
    }

    /* gtm */
    if (g_currentNode->gtm == 1) {
        write_runlog(LOG, "gtm normal shutdown, path: %s.\n", g_currentNode->gtmLocalDataPath);
        fast_stop_one_instance(g_currentNode->gtmLocalDataPath, INSTANCE_GTM);
    }
}

static void ShutdownOneDatanode(const dataNodeInfo *dnInfo)
{
    char buildPidPath[MAX_PATH_LEN] = {0};
    int ret = snprintf_s(buildPidPath,
        MAX_PATH_LEN,
        MAX_PATH_LEN - 1,
        "%s/gs_build.pid",
        dnInfo->datanodeLocalDataPath);
    securec_check_intval(ret, (void)ret);
    pgpid_t pid = get_pgpid(buildPidPath, MAX_PATH_LEN);
    if (pid > 0 && is_process_alive(pid)) {
        char cmd[MAX_PATH_LEN] = {0};
        ret = snprintf_s(cmd,
            MAX_PATH_LEN,
            MAX_PATH_LEN - 1,
            "killall %s %s >>%s 2>&1",
            PG_CTL_NAME,
            PG_REWIND_NAME,
            system_call_log);
        securec_check_intval(ret, (void)ret);
        write_runlog(LOG, "immediate_shutdown_nodes: %s \n", cmd);

        if (system(cmd) != 0) {
            write_runlog(ERROR, "immediate_shutdown_nodes: run system command failed! %s, errno=%d.\n", cmd, errno);
        }
    }

    write_runlog(LOG, "datanode immediate shutdown, kill_instance_force(): %s.\n", dnInfo->datanodeLocalDataPath);
    immediate_stop_one_instance(dnInfo->datanodeLocalDataPath, INSTANCE_DN);
}

void DelAndDownFloatIpInDn(uint32 index)
{
    (void)DelFloatIpInDatanode(index);
    SetNicOper(g_currentNode->datanode[index].datanodeId, CM_INSTANCE_TYPE_DN, NETWORK_TYPE_FLOATIP, NETWORK_OPER_DOWN);
}

static void ImmediateShutdownAllDatanode()
{
    for (uint32 ii = 0; ii < g_currentNode->datanodeCount; ii++) {
        if (g_clusterType == V3SingleInstCluster) {
            StopOneZengine(ii);
        } else {
            ShutdownOneDatanode(&g_currentNode->datanode[ii]);
        }
        DelAndDownFloatIpInDn(ii);
    }
}

void immediate_shutdown_nodes(bool kill_cmserver, bool kill_cn)
{
    /* coordinate */
    if (g_currentNode->coordinate == 1 && kill_cn) {
        write_runlog(LOG, "coordinator immediate shutdown, kill_instance_force(): %s.\n", g_currentNode->DataPath);
        immediate_stop_one_instance(g_currentNode->DataPath, INSTANCE_CN);
    }

    /* datanode */
    if (!g_enableSharedStorage) {
        write_runlog(LOG, "all datanode immediate shutdown.\n");
        ImmediateShutdownAllDatanode();
    }

    /* resource */
    if (IsCusResExistLocal()) {
        write_runlog(LOG, "immediate_shutdown_nodes, %u resource will be stopped.\n", GetLocalResConfCount());
        StopAllResInst();
    }

    /* cm_server */
    if (g_currentNode->cmServerLevel == 1 && kill_cmserver) {
        write_runlog(LOG, "cm_server immediate shutdown, kill_intance_force():%s.\n", g_currentNode->cmDataPath);
        StopCmInstance();
    }

    /* gtm */
    if (g_currentNode->gtm == 1) {
        write_runlog(LOG, "gtm immediate shutdown, kill_instance_force(): %s.\n", g_currentNode->gtmLocalDataPath);
        immediate_stop_one_instance(g_currentNode->gtmLocalDataPath, INSTANCE_GTM);
    }
}

static void FastShutdownAllDatanode()
{
    for (uint32 ii = 0; ii < g_currentNode->datanodeCount; ii++) {
        write_runlog(LOG, "datanode fast shutdown, datapath: %s.\n", g_currentNode->datanode[ii].datanodeLocalDataPath);
        if (g_clusterType == V3SingleInstCluster) {
            StopOneZengine(ii);
        } else {
            fast_stop_one_instance(g_currentNode->datanode[ii].datanodeLocalDataPath, INSTANCE_DN);
        }
        DelAndDownFloatIpInDn(ii);
    }
}

void fast_shutdown_nodes(void)
{
    /* coordinator */
    if (g_currentNode->coordinate == 1) {
        write_runlog(LOG, "coordinator fast shutdown, datapath: %s.\n", g_currentNode->DataPath);
        fast_stop_one_instance(g_currentNode->DataPath, INSTANCE_CN);
    }

    /* datanode */
    if (!g_enableSharedStorage) {
        write_runlog(LOG, "all datanode fast shutdown.\n");
        FastShutdownAllDatanode();
    }

    /* resource */
    if (IsCusResExistLocal()) {
        write_runlog(LOG, "fast shutdown, %u resource process will be stopped.\n", GetLocalResConfCount());
        StopAllResInst();
    }
       
    /* cm_server */
    if (g_currentNode->cmServerLevel == 1) {
        write_runlog(LOG, "cm_server fast shutdown, datapath: %s.\n", g_currentNode->cmDataPath);

        /* Check if all resources have been cleaned up */
        bool areResourcesCleaned = true;
        for (uint32 i = 0; i < GetLocalResConfCount(); ++i) {
           if (CheckOneResInst(&g_resConf[i]) == CUS_RES_CHECK_STAT_ONLINE) {
               areResourcesCleaned = false;
           }
        }
        if (areResourcesCleaned) {
            StopCmInstance();
        }
    }

    /* gtm */
    if (g_currentNode->gtm == 1) {
        write_runlog(LOG, "gtm fast shutdown, path: %s.\n", g_currentNode->gtmLocalDataPath);
        fast_stop_one_instance(g_currentNode->gtmLocalDataPath, INSTANCE_GTM);
    }
}

void GetStopZengineCmd(char *cmd, unsigned long cmdLen, uint32 index)
{
    int rcs = 0;
    if (!IsBoolCmParamTrue(g_agentEnableDcf)) {
        rcs = snprintf_s(cmd,
                cmdLen,
                cmdLen - 1,
                "%s/cm_script/dn_zenith_ha/stopdb.sh %s %s %u",
                g_binPath,
                g_currentNode->datanode[index].datanodeLocalDataPath,
                g_currentNode->datanode[index].datanodeListenIP[0],
                g_currentNode->datanode[index].datanodePort);
    } else {
        rcs = snprintf_s(cmd,
                cmdLen,
                cmdLen - 1,
                "%s/cm_script/dn_zenith_zpaxos/stopdb.sh %s %u",
                g_binPath,
                g_currentNode->datanode[index].datanodeLocalDataPath,
                g_currentNode->datanode[index].datanodePort);
    }
    securec_check_intval(rcs, (void)rcs);
}

void StopZengineByCmd(uint32 index)
{
    int rcs;
    char instance_manual_start_path[MAX_PATH_LEN] = {0};
    struct stat cluster_stat_buf = {0};
    rcs = snprintf_s(instance_manual_start_path, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s_%u",
        g_cmInstanceManualStartPath, g_currentNode->datanode[index].datanodeId);
    securec_check_intval(rcs, (void)rcs);
    check_input_for_security(instance_manual_start_path);
    canonicalize_path(instance_manual_start_path);

    if (stat(g_cmManualStartPath, &cluster_stat_buf) == 0) {
        get_stop_mode(g_cmManualStartPath);
    } else {
        get_stop_mode(instance_manual_start_path);
    }
    if (g_cmShutdownMode == FAST_MODE || g_cmShutdownMode == SMART_MODE) {
        write_runlog(
            LOG, "datanode fast shutdown, datapath: %s.\n", g_currentNode->datanode[index].datanodeLocalDataPath);
        char cmd[MAXPGPATH] = {0};
        GetStopZengineCmd(cmd, MAXPGPATH, index);
        rcs = ExecuteSystemCmd(cmd);
        if (rcs != 0) {
            return;
        }
        write_runlog(LOG,
            "%s %s stopped by cmd %s.\n",
            type_int_to_str_name(INSTANCE_DN),
            g_currentNode->datanode[index].datanodeLocalDataPath,
            cmd);
        return;
    }

    write_runlog(
        LOG, "datanode immediate shutdown, stopZengine(): %s.\n", g_currentNode->datanode[index].datanodeLocalDataPath);
    immediate_stop_one_instance(g_currentNode->datanode[index].datanodeLocalDataPath, INSTANCE_DN);
}

static bool StopCurDnFloatIp(uint32 index)
{
    uint32 count = DelFloatIpInDatanode(index);
    if (count != 0) {
        return false;
    }
    NetworkState state = CheckCurDnFloatIpStatus(index);
    if (state != NETWORK_STATE_UP) {
        return true;
    }
    write_runlog(
        LOG, "instId(%u) FloatIp is running, it need to be stopped.\n", g_currentNode->datanode[index].datanodeId);
    SetNicOper(g_currentNode->datanode[index].datanodeId, CM_INSTANCE_TYPE_DN, NETWORK_TYPE_FLOATIP, NETWORK_OPER_DOWN);
    return false;
}

static void StopOneZengine(uint32 index)
{
    bool dnManualStop = DnManualStop(index);
    if (dnManualStop) {
        char instance_replace[MAX_PATH_LEN] = {0};
        struct stat instance_stat_buf = {0};
        int rcs;
        rcs = snprintf_s(instance_replace, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/%s_%u",
            g_binPath, CM_INSTANCE_REPLACE, g_currentNode->datanode[index].datanodeId);
        securec_check_intval(rcs, (void)rcs);
        if (stat(instance_replace, &instance_stat_buf) == 0) {
            write_runlog(LOG,
                "datanode(%s) is being replaced and can't be stopped.\n",
                g_currentNode->datanode[index].datanodeLocalDataPath);
            return;
        }
        if (check_one_instance_status(ZENGINE_BIN_NAME, g_currentNode->datanode[index].datanodeLocalDataPath, NULL) ==
            PROCESS_RUNNING) {
            StopZengineByCmd(index);
            return;
        }

        if (!StopCurDnFloatIp(index)) {
            return;
        }

        write_runlog(LOG,
            "datanode is not running, no need to shutdown: %s.\n",
            g_currentNode->datanode[index].datanodeLocalDataPath);
    }
}

int stop_instance_check(void)
{
    struct stat stat_buf = {0};
    int ret;

    if (stat(g_cmManualStartPath, &stat_buf) == 0) {
        g_shutdownRequest = true;
        write_runlog(LOG, "shutdown requested, find start file!\n");
    }

    if (!g_shutdownRequest) {
        /* check and stop one instance */
        stop_instances_check();

        write_runlog(DEBUG5, "stat stop file error!\n");
        return 1;
    }

    /* check and stop all instances on current node */
    ret = all_nodes_stopped_check();
    if (ret == 0) {
        write_runlog(LOG, "all instances have been stopped!\n");
        return 0;
    }

    get_stop_mode(g_cmManualStartPath);

    if (g_cmShutdownMode == FAST_MODE) {
        write_runlog(LOG, "fast shutdown!\n");
        fast_shutdown_nodes();
    } else if (g_cmShutdownMode == IMMEDIATE_MODE) {
        write_runlog(LOG, "immediate shutdown!\n");
        immediate_shutdown_nodes(true, true);
    } else {
        write_runlog(LOG, "normal shutdown!\n");
        normal_shutdown_nodes();
    }

    if (g_clusterType != V3SingleInstCluster) {
        kill_instance_force("fenced", INSTANCE_FENCED);
    }

    return 2;
}

bool isNodeNormal()
{
    bool cdt;
    if (g_currentNode->gtm) {
        (void)pthread_rwlock_wrlock(&(g_gtmReportMsg.lk_lock));
        cdt = (!((g_gtmReportMsg.report_msg.status.local_role == INSTANCE_ROLE_PRIMARY ||
                  g_gtmReportMsg.report_msg.status.local_role == INSTANCE_ROLE_STANDBY) &&
                g_gtmReportMsg.report_msg.status.connect_status == CON_OK &&
                g_gtmReportMsg.report_msg.status.sync_mode == INSTANCE_DATA_REPLICATION_SYNC));
        if (cdt) {
            (void)pthread_rwlock_unlock(&(g_gtmReportMsg.lk_lock));
            return false;
        }
        (void)pthread_rwlock_unlock(&(g_gtmReportMsg.lk_lock));
    }

    if (g_currentNode->coordinate) {
        (void)pthread_rwlock_wrlock(&(g_cnReportMsg.lk_lock));
        if (g_cnReportMsg.cnStatus.reportMsg.connectStatus != AGENT_TO_INSTANCE_CONNECTION_OK) {
            (void)pthread_rwlock_unlock(&(g_cnReportMsg.lk_lock));
            return false;
        }
        (void)pthread_rwlock_unlock(&(g_cnReportMsg.lk_lock));
    }

    for (uint32 ii = 0; ii < g_currentNode->datanodeCount; ii++) {
        (void)pthread_rwlock_wrlock(&(g_dnReportMsg[ii].lk_lock));
        cdt = (!(g_dnReportMsg[ii].dnStatus.reportMsg.local_status.local_role == INSTANCE_ROLE_PRIMARY ||
                (g_dnReportMsg[ii].dnStatus.reportMsg.local_status.local_role == INSTANCE_ROLE_STANDBY &&
                    g_dnReportMsg[ii].dnStatus.reportMsg.local_status.db_state == INSTANCE_HA_STATE_NORMAL) ||
                (g_currentNode->datanode[ii].datanodeRole == DUMMY_STANDBY_DN &&
                    g_dnReportMsg[ii].dnStatus.reportMsg.processStatus == INSTANCE_PROCESS_RUNNING)));
        if (cdt) {
            (void)pthread_rwlock_unlock(&(g_dnReportMsg[ii].lk_lock));
            return false;
        }
        (void)pthread_rwlock_unlock(&(g_dnReportMsg[ii].lk_lock));
    }

    return true;
}

static void clean_semp_and_shm()
{
    if (g_cmShutdownMode == IMMEDIATE_MODE) {
        char user_name[256] = {0};
        int ret = cmagent_getenv("USER", user_name, sizeof(user_name));
        if (ret == EOK) {
            errno_t rc;
            char cmd[MAX_PATH_LEN];

            check_input_for_security(user_name);
            rc = snprintf_s(
                cmd, MAX_PATH_LEN, MAX_PATH_LEN - 1, "ipcrm `ipcs -s | grep %s | awk '{print \"-s \" $2}'`", user_name);
            securec_check_intval(rc, (void)rc);
            if (system(cmd)) {
                write_runlog(ERROR, "clean semp failed!, erron=%d.\n", errno);
            }

            rc = snprintf_s(cmd,
                MAX_PATH_LEN,
                MAX_PATH_LEN - 1,
                "ipcrm `ipcs -m | grep %s | awk '{if($6==\"0\") print \"-m \" $2}'`",
                user_name);
            securec_check_intval(rc, (void)rc);
            if (system(cmd)) {
                write_runlog(ERROR, "clean shm failed!, erron=%d.\n", errno);
            }
        } else {
            write_runlog(ERROR, "get USER failed!\n");
        }
    }
}

void *agentStartAndStopMain(void *arg)
{
    bool cdt;
    int status;
    int pid;
    int st;
    int rcs;
    char instance_replace[MAX_PATH_LEN] = {0};
    struct stat stat_buf = {0};
    char pg_host_path[MAX_PATH_LEN] = {0};
    char gauss_replace[MAX_PATH_LEN] = {0};
    pthread_t threadId = pthread_self();

    thread_name = "StartAndStop";
    write_runlog(LOG, "agent start and stop thread start, threadid %lu.\n", threadId);

    /*
     * init alarm check, check ALM_AI_AbnormalGTMProcess,
     * ALM_AI_AbnormalCoordinatorProcess and ALM_AI_AbnormalDatanodeProcess
     */
    StartupAlarmItemInitialize(g_currentNode);

    rcs = snprintf_s(instance_replace, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/%s_%u", g_binPath, CM_INSTANCE_REPLACE,
        g_currentNode->coordinateId);
    securec_check_intval(rcs, (void)rcs);

    rcs = cmagent_getenv("PGHOST", pg_host_path, sizeof(pg_host_path));
    if (rcs == EOK) {
        check_input_for_security(pg_host_path);
        rcs = snprintf_s(gauss_replace, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/GaussReplace.dat", pg_host_path);
        securec_check_intval(rcs, (void)rcs);
    } else {
        write_runlog(FATAL, "get PGHOST failed!\n");
        exit(-1);
    }

    for (;;) {
        if (g_exitFlag) {
            write_runlog(LOG, "receive exit request in cma startAndStop.\n");
            cm_sleep(1);
            continue;
        }

        set_thread_state(threadId);
        pid = waitpid(-1, &st, WNOHANG);
        if (pid > 0) {
            write_runlog(LOG, "child process have die! pid is %d exit status is %d\n ", pid, st);
        }

        status = stop_instance_check();
        if (status == 0) {
            clean_semp_and_shm();
            write_runlog(LOG, "stop_instance_check find.exit.\n");
            exit(0);
        }
#ifdef ENABLE_MULTIPLE_NODES
        if (cm_agent_need_check_libcomm_port) {
            g_autoRepairCnt = 0;
            RemoveStopAutoRepairFile();
            write_runlog(LOG, "update libcomm config start.\n");
            if (UpdateLibcommConfig()) {
                cm_agent_need_check_libcomm_port = false;
                write_runlog(LOG, "update libcomm config complete.\n");
            }
        }
#endif
        start_instance_check();
#ifdef ENABLE_MULTIPLE_NODES
        if (g_syncDroppedCoordinator) {
            cdt = (stat(instance_replace, &stat_buf) == 0 || g_repairCn || g_restoreCn);
            if (cdt) {
                write_runlog(LOG, "coordinator is being replaced/repiared/restore, can't create node or group.\n");
            } else {
                cm_static_config_check_to_coordinate();
            }
        }
#endif
        cdt = (stat(gauss_replace, &stat_buf) == 0 && isNodeNormal());
        if (cdt) {
            if (unlink(gauss_replace)) {
                write_runlog(ERROR, "could not remove gauss replace file, errno[%d].\n", errno);
            }
        }

        cm_sleep(1);
    }
}
