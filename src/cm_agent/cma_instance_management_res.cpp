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
 * cma_instance_management_ext.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_agent/cma_instance_management_ext.cpp
 *
 * -------------------------------------------------------------------------
 */
#include <sys/wait.h>
#include "cm/cm_json_config.h"
#include "cma_global_params.h"
#include "cma_alarm.h"
#include "cma_instance_management.h"
#include "cma_instance_management_res.h"

uint32 g_localResConfCount = 0;

static const char* StatToString(int stat)
{
    switch (stat) {
        case CUS_RES_CHECK_STAT_ONLINE:
            return "online";
        case CUS_RES_CHECK_STAT_OFFLINE:
            return "offline";
        case CUS_RES_CHECK_STAT_UNKNOWN:
            return "unknown";
        case CUS_RES_CHECK_STAT_ABNORMAL:
            return "abnormal";
        case CUS_RES_CHECK_STAT_TIMEOUT:
            return "timeout";
        case CUS_RES_CHECK_STAT_FAILED:
            return "failed";
        default:
            return "invalid status";
    }
}

static int CusResCmdExecute(const char *scriptPath, const char *oper, uint32 timeout, bool8 needNohup)
{
    char command[MAX_PATH_LEN + MAX_OPTION_LEN] = {0};
    int ret;
    if (needNohup) {
        ret = snprintf_s(command,
            MAX_PATH_LEN + MAX_OPTION_LEN,
            MAX_PATH_LEN + MAX_OPTION_LEN - 1,
            SYSTEMQUOTE "nohup timeout -s SIGKILL %us %s %s > %s &" SYSTEMQUOTE,
            timeout,
            scriptPath,
            oper,
            CM_DEVNULL);
    } else {
        ret = snprintf_s(command,
            MAX_PATH_LEN + MAX_OPTION_LEN,
            MAX_PATH_LEN + MAX_OPTION_LEN - 1,
            SYSTEMQUOTE "timeout -s SIGKILL %us %s %s > %s" SYSTEMQUOTE,
            timeout,
            scriptPath,
            oper,
            CM_DEVNULL);
    }
    securec_check_intval(ret, (void)ret);
    int status = system(command);
    if (status == -1) {
        write_runlog(ERROR, "run system command failed %s, errno(%d).\n", command, errno);
        return -1;
    }
    if (WIFEXITED(status)) {
        ret = WEXITSTATUS(status);
        write_runlog(DEBUG1, "run script command %s, ret=%d.\n", command, ret);
        return ret;
    } else {
        write_runlog(ERROR, "run system command failed %s, ret=%d, errno(%d).\n", command, WEXITSTATUS(status), errno);
    }
    return -1;
}

status_t StartOneResInst(CmResConfList *conf)
{
    int ret;
    char oper[MAX_OPTION_LEN] = {0};
    if (conf->resType == CUSTOM_RESOURCE_DN && undocumentedVersion > 0) {
        ret = snprintf_s(oper, MAX_OPTION_LEN, MAX_OPTION_LEN - 1, "-start %u %s '-u %u'", conf->resInstanceId,
            conf->arg, undocumentedVersion);
    } else if (conf->resType == CUSTOM_RESOURCE_DN && g_ssDoubleClusterMode != SS_DOUBLE_NULL) {
        ret = snprintf_s(oper, MAX_OPTION_LEN, MAX_OPTION_LEN - 1, "-start %u %s '-z %s'", conf->resInstanceId,
            conf->arg, type_int_to_str_ss_double(g_ssDoubleClusterMode));
    } else {
        ret = snprintf_s(oper, MAX_OPTION_LEN, MAX_OPTION_LEN - 1, "-start %u %s", conf->resInstanceId, conf->arg);
    }
    securec_check_intval(ret, (void)ret);

    ret = CusResCmdExecute(conf->script, oper, (uint32)conf->checkInfo.timeOut, CM_FALSE);
    if (ret == 0) {
        conf->checkInfo.startCount++;
        write_runlog(LOG, "StartOneResInst: run start script (%s %s) successfully.\n", conf->script, oper);
    } else if (ret == CUS_RES_START_FAIL_DEPEND_NOT_ALIVE) {
        write_runlog(LOG, "StartOneResInst: res(%s) inst(%u) can't do restart, cause depend resource inst not alive.\n",
            conf->resName, conf->cmInstanceId);
        return CM_ERROR;
    } else {
        conf->checkInfo.startCount++;
        write_runlog(ERROR, "StartOneResInst: run start script (%s %s) failed, ret=%d.\n", conf->script, oper, ret);
    }

    return CM_SUCCESS;
}

void StopOneResInst(const CmResConfList *conf)
{
    char oper[MAX_OPTION_LEN] = {0};
    int ret = snprintf_s(oper, MAX_OPTION_LEN, MAX_OPTION_LEN - 1, "-stop %u %s", conf->resInstanceId, conf->arg);
    securec_check_intval(ret, (void)ret);

    ret = CusResCmdExecute(conf->script, oper, (uint32)conf->checkInfo.timeOut, CM_FALSE);
    if (ret == 0) {
        write_runlog(LOG, "StopOneResInst: run stop command (%s %s) successfully.\n", conf->script, oper);
    } else {
        write_runlog(ERROR, "StopOneResInst: run stop command (%s %s) failed, ret=%d.\n", conf->script, oper, ret);
    }
}

void OneResInstShutdown(const CmResConfList *oneResConf)
{
    if (CheckOneResInst(oneResConf) != CUS_RES_CHECK_STAT_OFFLINE) {
        write_runlog(LOG, "custom resource(%s:%u) shutdown.\n", oneResConf->resName, oneResConf->cmInstanceId);
        StopOneResInst(oneResConf);
    }
}

void OneResInstClean(const CmResConfList *oneResConf)
{
    if (CheckOneResInst(oneResConf) != CUS_RES_CHECK_STAT_OFFLINE) {
        (void)CleanOneResInst(oneResConf);
    }
}

status_t RegOneResInst(const CmResConfList *conf, uint32 destInstId, bool8 needNohup)
{
    char oper[MAX_OPTION_LEN] = {0};
    int ret = snprintf_s(oper, MAX_OPTION_LEN, MAX_OPTION_LEN - 1, "-reg %u %s", destInstId, conf->arg);
    securec_check_intval(ret, (void)ret);

    ret = CusResCmdExecute(conf->script, oper, (uint32)conf->checkInfo.timeOut, needNohup);
    if (ret != 0) {
        write_runlog(ERROR, "[%s]: cmd:(%s %s) execute failed, ret=%d.\n", __FUNCTION__, conf->script, oper, ret);
        return CM_ERROR;
    }

    write_runlog(LOG, "[%s]: cmd:(%s %s) is executing.\n", __FUNCTION__, conf->script, oper);
    return CM_SUCCESS;
}

status_t UnregOneResInst(const CmResConfList *conf, uint32 destInstId)
{
    char oper[MAX_OPTION_LEN] = {0};
    int ret = snprintf_s(oper, MAX_OPTION_LEN, MAX_OPTION_LEN - 1, "-unreg %u %s", destInstId, conf->arg);
    securec_check_intval(ret, (void)ret);

    ret = CusResCmdExecute(conf->script, oper, (uint32)conf->checkInfo.timeOut, CM_TRUE);
    if (ret != 0) {
        write_runlog(ERROR, "[%s]: cmd:(%s %s) execute failed, ret=%d.\n", __FUNCTION__, conf->script, oper, ret);
        return CM_ERROR;
    }

    write_runlog(LOG, "[%s]: cmd:(%s %s) is executing.\n", __FUNCTION__, conf->script, oper);
    return CM_SUCCESS;
}

// -1:error, 0:unreg, 1:pending, 2:reg
ResIsregStatus IsregOneResInst(const CmResConfList *conf, uint32 destInstId)
{
    char oper[MAX_OPTION_LEN];
    int ret = snprintf_s(oper, MAX_OPTION_LEN, MAX_OPTION_LEN - 1, "-isreg %u %s", destInstId, conf->arg);
    securec_check_intval(ret, (void)ret);

    ret = CusResCmdExecute(conf->script, oper, (uint32)conf->checkInfo.timeOut, CM_FALSE);
    switch (ret) {
        case RES_INST_ISREG_UNKNOWN:
            write_runlog(DEBUG5, "IsregOneResInst: res(%s) inst(%u) get isreg error.\n", conf->resName, destInstId);
            return CM_RES_ISREG_UNKNOWN;
        case RES_INST_ISREG_UNREG:
            write_runlog(DEBUG5, "IsregOneResInst: res(%s) inst(%u) has been unreg.\n", conf->resName, destInstId);
            return CM_RES_ISREG_UNREG;
        case RES_INST_ISREG_PENDING:
            write_runlog(DEBUG5, "IsregOneResInst: res(%s) inst(%u) has been pending.\n", conf->resName, destInstId);
            return CM_RES_ISREG_PENDING;
        case RES_INST_ISREG_REG:
            write_runlog(DEBUG5, "IsregOneResInst: res(%s) inst(%u) has been reg.\n", conf->resName, destInstId);
            return CM_RES_ISREG_REG;
        case RES_INST_ISREG_NOT_SUPPORT:
            write_runlog(DEBUG5, "IsregOneResInst: res(%s) inst(%u) not support isreg.\n", conf->resName, destInstId);
            return CM_RES_ISREG_NOT_SUPPORT;
        default:
            write_runlog(ERROR, "IsregOneResInst: res(%s) inst(%u) get unknown isreg ret(%d).\n",
                conf->resName, destInstId, ret);
            break;
    }

    return CM_RES_ISREG_UNKNOWN;
}

status_t CleanOneResInst(const CmResConfList *conf)
{
    char oper[MAX_OPTION_LEN];
    int ret = snprintf_s(oper, MAX_OPTION_LEN, MAX_OPTION_LEN - 1, "-clean %u %s", conf->resInstanceId, conf->arg);
    securec_check_intval(ret, (void)ret);

    ret = CusResCmdExecute(conf->script, oper, (uint32)conf->checkInfo.timeOut, CM_FALSE);
    if (ret != 0) {
        write_runlog(ERROR, "CleanOneResInst: clean inst cmd(%s %s) failed, ret=%d\n", conf->script, oper, ret);
        return CM_ERROR;
    }
    write_runlog(LOG, "CleanOneResInst: clean inst cmd(%s %s) success\n", conf->script, oper);
    return CM_SUCCESS;
}

static void StopCurNodeFloatIp()
{
    for (uint32 i = 0; i < g_currentNode->datanodeCount; ++i) {
        DelAndDownFloatIpInDn(i);
    }
}

static inline void CleanOneInstCheckCount(CmResConfList *resConf)
{
    if (resConf->checkInfo.startCount != 0) {
        write_runlog(LOG, "res(%s) inst(%u) restart times clean.\n", resConf->resName, resConf->cmInstanceId);
    }
    resConf->checkInfo.startCount = 0;
    resConf->checkInfo.startTime = 0;
    resConf->checkInfo.brokeTime = 0;
}

static inline void CleanOneInstAbnormalStat(CmResConfList *resConf, int curStat)
{
    if (resConf->checkInfo.abnormalTime != 0) {
        write_runlog(LOG, "res(%s) inst(%u) status from abnormal change to %s.\n",
            resConf->resName, resConf->cmInstanceId, StatToString(curStat));
        resConf->checkInfo.abnormalTime = 0;
    }
}

static inline void CleanOneInstOnlineTimes(CmResConfList *resConf)
{
    resConf->checkInfo.onlineTimes = 0;
}

void StopAllResInst()
{
    for (uint32 i = 0; i < GetLocalResConfCount(); ++i) {
        OneResInstClean(&g_resConf[i]);
    }
    StopCurNodeFloatIp();
}

int CheckOneResInst(const CmResConfList *conf)
{
    char oper[MAX_OPTION_LEN] = {0};
    int ret = snprintf_s(oper, MAX_OPTION_LEN, MAX_OPTION_LEN - 1, "-check %u %s", conf->resInstanceId, conf->arg);
    securec_check_intval(ret, (void)ret);

    ret = CusResCmdExecute(conf->script, oper, (uint32)conf->checkInfo.timeOut, CM_FALSE);
    if ((ret != CUS_RES_CHECK_STAT_ONLINE) && (ret != CUS_RES_CHECK_STAT_OFFLINE) &&
        (ret != CUS_RES_CHECK_STAT_ABNORMAL)) {
        write_runlog(LOG, "CheckOneResInst, run system command(%s %s) special result=%d\n",  conf->script, oper, ret);
    }

    if (ret < 0) {
        return CUS_RES_CHECK_STAT_FAILED;
    }

    return ret;
}

static status_t ManualStopOneLocalResInst(CmResConfList *conf)
{
    char instanceStartFile[MAX_PATH_LEN] = {0};
    int ret = snprintf_s(instanceStartFile, MAX_PATH_LEN, MAX_PATH_LEN - 1,
        "%s_%u", g_cmInstanceManualStartPath, conf->cmInstanceId);
    securec_check_intval(ret, (void)ret);

    if (CmFileExist(instanceStartFile)) {
        write_runlog(LOG, "instanceStartFile(%s) is exist, can't create again.\n", instanceStartFile);
        return CM_SUCCESS;
    }
    
    char command[MAX_PATH_LEN] = {0};
    ret = snprintf_s(command, MAX_PATH_LEN, MAX_PATH_LEN - 1,
        SYSTEMQUOTE "touch %s;chmod 600 %s < \"%s\" 2>&1" SYSTEMQUOTE,
        instanceStartFile, instanceStartFile, DEVNULL);
    securec_check_intval(ret, (void)ret);
    
    ret = system(command);
    if (ret != 0) {
        write_runlog(ERROR, "manual stop res(%s) inst(%u) failed, ret=%d.\n", conf->resName, conf->resInstanceId, ret);
        return CM_ERROR;
    }

    write_runlog(LOG, "manual stop res(%s) inst(%u) success.\n", conf->resName, conf->resInstanceId);
    return CM_SUCCESS;
}

static status_t ManuallStopAllLocalResInst()
{
    status_t result = CM_SUCCESS;
    for (uint32 i = 0; i < GetLocalResConfCount(); ++i) {
        if (ManualStopOneLocalResInst(&g_resConf[i]) != CM_SUCCESS) {
            result = CM_ERROR;
        }
    }

    return result;
}

static void ManualStopLocalResInst(CmResConfList *conf)
{
    if (ManuallStopAllLocalResInst() == CM_SUCCESS) {
        CleanOneInstCheckCount(conf);
    }
}

bool IsInstManualStopped(uint32 instId)
{
    char manualStart[MAX_PATH_LEN] = {0};
    int ret = snprintf_s(manualStart, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s_%u", g_cmInstanceManualStartPath, instId);
    securec_check_intval(ret, (void)ret);
    if (CmFileExist(manualStart)) {
        write_runlog(DEBUG5, "res inst(%u) has been stop.\n", instId);
        return true;
    }
    return false;
}

static inline void RestartOneResInst(CmResConfList *conf)
{
    ResIsregStatus stat = IsregOneResInst(conf, conf->resInstanceId);
    if ((stat != CM_RES_ISREG_REG) && (stat != CM_RES_ISREG_NOT_SUPPORT)) {
        write_runlog(LOG, "cur inst(%u) isreg stat=(%u), and reg failed, restart failed.\n",
            conf->cmInstanceId, (uint32)stat);
        conf->checkInfo.startCount++;
        return;
    }
    (void)StartOneResInst(conf);
}

static void ProcessOfflineInstance(CmResConfList *conf)
{
    long curTime = GetCurMonotonicTimeSec();

    if (conf->checkInfo.restartTimes == -1) {
        RestartOneResInst(conf);
        return;
    }
    if (conf->checkInfo.brokeTime == 0) {
        conf->checkInfo.brokeTime = curTime;
        return;
    }
    if (conf->checkInfo.startCount >= conf->checkInfo.restartTimes) {
        write_runlog(LOG, "res(%s) inst(%u) is offline, but restart times (%d) >= limit (%d), can't do restart again, "
            "will do manually stop.\n", conf->resName, conf->cmInstanceId, conf->checkInfo.startCount,
            conf->checkInfo.restartTimes);
        ManualStopLocalResInst(conf);
        return;
    }
    if ((curTime - conf->checkInfo.brokeTime) < conf->checkInfo.restartDelay) {
        write_runlog(DEBUG5, "[CLIENT] res(%s) inst(%u) curTime=%ld, brokeTime=%ld, restartDelay=%d.\n",
            conf->resName, conf->resInstanceId, curTime, conf->checkInfo.brokeTime, conf->checkInfo.restartDelay);
        return;
    }
    if ((curTime - conf->checkInfo.startTime) < conf->checkInfo.restartPeriod) {
        write_runlog(DEBUG5, "[CLIENT] res(%s) inst(%u) startTime = %ld, restartPeriod = %d.\n",
            conf->resName, conf->resInstanceId, conf->checkInfo.startTime, conf->checkInfo.restartPeriod);
        return;
    }
    RestartOneResInst(conf);
    conf->checkInfo.startTime = curTime;
    write_runlog(LOG, "res(%s) inst(%u) has been restart (%d) times, restart more than (%d) time will manually stop.\n",
        conf->resName, conf->cmInstanceId, conf->checkInfo.startCount, conf->checkInfo.restartTimes);
}

static void ProcessAbnormalInstance(CmResConfList *conf)
{
    long curTime = GetCurMonotonicTimeSec();
    if (conf->checkInfo.abnormalTime == 0) {
        conf->checkInfo.abnormalTime = curTime;
    }

    const int writeLogInterval = 10;
    int duration = (int)(curTime - conf->checkInfo.abnormalTime);
    if (duration < conf->checkInfo.abnormalTimeout) {
        if ((duration > 0) && (duration % writeLogInterval == 0)) {
            write_runlog(LOG, "res(%s) inst(%u) has been abnormal (%d)s, timeout is (%d)s.\n",
                conf->resName, conf->cmInstanceId, duration, conf->checkInfo.abnormalTimeout);
        }
        return;
    }

    if ((conf->checkInfo.startCount >= conf->checkInfo.restartTimes) && (conf->checkInfo.restartTimes != -1)) {
        write_runlog(LOG, "res(%s) inst(%u) is abnormal, but restart times (%d) >= limit (%d), can't do restart again, "
            "will do manually stop.\n",
            conf->resName, conf->cmInstanceId, conf->checkInfo.startCount, conf->checkInfo.restartTimes);
        ManualStopLocalResInst(conf);
        return;
    }

    write_runlog(LOG, "res(%s) inst(%u) has been abnormal (%d)s, >= timeout(%d)s, need kill it.\n",
        conf->resName, conf->cmInstanceId, duration, conf->checkInfo.abnormalTimeout);

    if (CleanOneResInst(conf) == CM_SUCCESS) {
        write_runlog(LOG, "res(%s) inst(%u) clean abnormal time.\n", conf->resName, conf->cmInstanceId);
    } else {
        conf->checkInfo.startCount++;
    }
    conf->checkInfo.startTime = curTime;
}

static inline bool NeedStopResInst(const char *resName, uint32 cmInstId)
{
    return (IsInstManualStopped(cmInstId) || CmFileExist(g_cmManualStartPath) || !IsOneResInstWork(resName, cmInstId) ||
        g_agentNicDown);
}

static void ProcessOnlineInstance(CmResConfList *resConf)
{
    // continue 5 times, check inst status is online, clean check count
    const int instNormalTimes = 5;
    if (resConf->checkInfo.onlineTimes < instNormalTimes) {
        ++resConf->checkInfo.onlineTimes;
    } else {
        CleanOneInstCheckCount(resConf);
    }
}

void StartResourceCheck()
{
    for (uint32 i = 0; i < GetLocalResConfCount(); ++i) {
        int ret = CheckOneResInst(&g_resConf[i]);
        switch (ret) {
            case CUS_RES_CHECK_STAT_ONLINE:
                ProcessOnlineInstance(&g_resConf[i]);
                CleanOneInstAbnormalStat(&g_resConf[i], CUS_RES_CHECK_STAT_ONLINE);
                break;
            case CUS_RES_CHECK_STAT_OFFLINE:
                CleanOneInstOnlineTimes(&g_resConf[i]);
                CleanOneInstAbnormalStat(&g_resConf[i], CUS_RES_CHECK_STAT_OFFLINE);
                if (NeedStopResInst(g_resConf[i].resName, g_resConf[i].cmInstanceId)) {
                    CleanOneInstCheckCount(&g_resConf[i]);
                    break;
                }
                ProcessOfflineInstance(&g_resConf[i]);
                break;
            case CUS_RES_CHECK_STAT_ABNORMAL:
                CleanOneInstOnlineTimes(&g_resConf[i]);
                if (!IsOneResInstWork(g_resConf[i].resName, g_resConf[i].cmInstanceId)) {
                    write_runlog(LOG, "res(%s) inst(%u) is abnormal, but has been kick out, need stop it.\n",
                        g_resConf[i].resName, g_resConf[i].cmInstanceId);
                    (void)CleanOneResInst(&g_resConf[i]);
                    break;
                }
                if (IsInstManualStopped(g_resConf[i].cmInstanceId) || CmFileExist(g_cmManualStartPath)) {
                    CleanOneInstCheckCount(&g_resConf[i]);
                    break;
                }
                ProcessAbnormalInstance(&g_resConf[i]);
                break;
            default:
                write_runlog(ERROR, "StartResourceCheck, special status(%d).\n", ret);
                break;
        }
    }
}

static bool IsInstReplaced(uint32 cmInstId)
{
    char flag[MAX_PATH_LEN] = {0};
    int ret = snprintf_s(flag, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/%s_%u", g_binPath, CM_INSTANCE_REPLACE, cmInstId);
    securec_check_intval(ret, (void)ret);
    if (CmFileExist(flag)) {
        return true;
    }
    return false;
}

void StopResourceCheck()
{
    for (uint32 i = 0; i < GetLocalResConfCount(); ++i) {
        if (IsInstReplaced(g_resConf[i].cmInstanceId)) {
            write_runlog(LOG, "custom resource instance(%s:%u) is being replaced and can't be stopped.\n",
                g_resConf[i].resName, g_resConf[i].cmInstanceId);
            continue;
        }

        if (IsInstManualStopped(g_resConf[i].cmInstanceId)) {
            OneResInstShutdown(&g_resConf[i]);
        }
        if ((!IsOneResInstWork(g_resConf[i].resName, g_resConf[i].cmInstanceId) && !g_isPauseArbitration) || CmFileExist(g_cmManualStartPath)) {
            OneResInstClean(&g_resConf[i]);
        }
    }
}

int ResourceStoppedCheck(void)
{
    for (uint32 i = 0; i < GetLocalResConfCount(); ++i) {
        int ret = CheckOneResInst(&g_resConf[i]);
        if (ret == CUS_RES_CHECK_STAT_ONLINE || ret == CUS_RES_CHECK_STAT_ABNORMAL) {
            write_runlog(LOG, "resource is running, script is %s\n", g_resConf[i].script);
            return PROCESS_RUNNING;
        }
    }
    return PROCESS_NOT_EXIST;
}

static inline status_t PaddingResConf(const CmResConfList *oneConf)
{
    if (g_localResConfCount >= CM_MAX_RES_INST_COUNT) {
        write_runlog(ERROR, "custom resource inst count overflow, max:%d.\n", CM_MAX_RES_COUNT);
        return CM_ERROR;
    }
    errno_t rc = memcpy_s(&g_resConf[g_localResConfCount], sizeof(CmResConfList), oneConf, sizeof(CmResConfList));
    securec_check_errno(rc, (void)rc);
    ++g_localResConfCount;
    return CM_SUCCESS;
}

static status_t InitResNameConf(const char *resNameJson, char *resNameConf)
{
    if (CM_IS_EMPTY_STR(resNameJson)) {
        write_runlog(ERROR, "[InitLocalRes] resource name is empty.\n");
        return CM_ERROR;
    }

    if (strlen(resNameJson) >= CM_MAX_RES_NAME) {
        write_runlog(ERROR, "[InitLocalRes] resName(%s) is longer than %d.\n", resNameJson, (CM_MAX_RES_NAME - 1));
        return CM_ERROR;
    }

    errno_t rc = strcpy_s(resNameConf, CM_MAX_RES_NAME, resNameJson);
    securec_check_errno(rc, (void)rc);
    return CM_SUCCESS;
}

static inline void InitOneConfOfRes(const char *paraName, int value, int *newValue)
{
    if (IsResConfValid(paraName, value)) {
        *newValue = value;
    } else {
        *newValue = CmAtoi(ResConfDefValue(paraName), 0);
        write_runlog(ERROR, "\"%s\":%d out of range, range [%d, %d], use default value(%d).\n",
            paraName, value, ResConfMinValue(paraName), ResConfMaxValue(paraName), *newValue);
    }
}

static status_t InitLocalCommConfOfDefRes(const CusResConfJson *resJson, CmResConfList *localConf)
{
    localConf->nodeId = g_currentNode->node;

    CM_RETURN_IFERR(InitResNameConf(resJson->resName, localConf->resName));

    errno_t rc = strcpy_s(localConf->script, MAX_PATH_LEN, resJson->resScript);
    securec_check_errno(rc, (void)rc);
    canonicalize_path(localConf->script);

    InitOneConfOfRes("check_interval", resJson->checkInterval, &localConf->checkInfo.checkInterval);
    InitOneConfOfRes("time_out", resJson->timeOut, &localConf->checkInfo.timeOut);
    InitOneConfOfRes("restart_delay", resJson->restartDelay, &localConf->checkInfo.restartDelay);
    InitOneConfOfRes("restart_period", resJson->restartPeriod, &localConf->checkInfo.restartPeriod);
    InitOneConfOfRes("restart_times", resJson->restartTimes, &localConf->checkInfo.restartTimes);
    InitOneConfOfRes("abnormal_timeout", resJson->abnormalTimeout, &localConf->checkInfo.abnormalTimeout);

    return CM_SUCCESS;
}

static uint32 GetCmInstId(const CmResConfList *newConf)
{
    for (uint32 i = 0; i < CusResCount(); ++i) {
        if (strcmp(g_resStatus[i].status.resName, newConf->resName) != 0) {
            continue;
        }
        uint32 cmInstId = 0;
        for (uint32 k = 0; k < g_resStatus[i].status.instanceCount; ++k) {
            if (g_resStatus[i].status.resStat[k].resInstanceId == newConf->resInstanceId) {
                cmInstId = g_resStatus[i].status.resStat[k].cmInstanceId;
                break;
            }
        }
        return cmInstId;
    }
    return 0;
}

static void InitLocalOneAppInstConf(const CusResInstConf *appInst, CmResConfList *newConf)
{
    errno_t rc = memset_s(newConf->arg, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = strcpy_s(newConf->arg, MAX_PATH_LEN, appInst->resArgs);
    securec_check_errno(rc, (void)rc);
    newConf->nodeId = (uint32)appInst->nodeId;
    newConf->resInstanceId = (uint32)appInst->resInstId;
    newConf->cmInstanceId = GetCmInstId(newConf);
}

static status_t InitLocalAllAppResInstConf(const AppCusResConfJson *appResJson, CmResConfList *newLocalConf)
{
    for (uint32 i = 0; i < appResJson->instance.count; ++i) {
        if (appResJson->instance.conf[i].nodeId == (int)newLocalConf->nodeId) {
            InitLocalOneAppInstConf(&appResJson->instance.conf[i], newLocalConf);
            CM_RETURN_IFERR(PaddingResConf(newLocalConf));
        }
    }
    return CM_SUCCESS;
}

static void InitLocalOneDnInstConfByStaticConf(const dataNodeInfo *dnInfo, CmResConfList *newConf)
{
    errno_t rc = memset_s(newConf->arg, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);
    rc = strcpy_s(newConf->arg, MAX_PATH_LEN, dnInfo->datanodeLocalDataPath);
    securec_check_errno(rc, (void)rc);
    newConf->cmInstanceId = dnInfo->datanodeId;
    newConf->resInstanceId = dnInfo->datanodeId;
}

static void InitLocalOneDnInstConfByJsonConf(const CusResConfJson *resJson, CmResConfList *newConf)
{
    for (uint32 i = 0; i < resJson->instance.count; ++i) {
        if ((resJson->instance.conf[i].nodeId == (int)newConf->nodeId) &&
            (resJson->instance.conf[i].resInstId == (int)newConf->resInstanceId)) {
            errno_t rc = strcpy_s(newConf->arg, MAX_PATH_LEN, resJson->instance.conf[i].resArgs);
            securec_check_errno(rc, (void)rc);
        }
    }
}

static status_t InitLocalAllDnResInstConf(const CusResConfJson *resJson, CmResConfList *newLocalConf)
{
    for (uint32 i = 0; i < g_node_num; ++i) {
        if (g_node[i].node != newLocalConf->nodeId) {
            continue;
        }
        for (uint32 k = 0; k < g_node[i].datanodeCount; ++k) {
            InitLocalOneDnInstConfByStaticConf(&g_node[i].datanode[k], newLocalConf);
            InitLocalOneDnInstConfByJsonConf(resJson, newLocalConf);
            CM_RETURN_IFERR(PaddingResConf(newLocalConf));
        }
        break;
    }
    return CM_SUCCESS;
}

static status_t InitLocalOneResConf(const OneCusResConfJson *oneResJson)
{
    CmResConfList newLocalConf = {{0}};
    newLocalConf.resType = (int)oneResJson->resType;
    if (oneResJson->resType == CUSTOM_RESOURCE_APP) {
        CM_RETURN_IFERR(InitLocalCommConfOfDefRes(&oneResJson->appResConf, &newLocalConf));
        CM_RETURN_IFERR(InitLocalAllAppResInstConf(&oneResJson->appResConf, &newLocalConf));
    } else if (oneResJson->resType == CUSTOM_RESOURCE_DN) {
        CM_RETURN_IFERR(InitLocalCommConfOfDefRes(&oneResJson->dnResConf, &newLocalConf));
        CM_RETURN_IFERR(InitLocalAllDnResInstConf(&oneResJson->dnResConf, &newLocalConf));
    }

    return CM_SUCCESS;
}

status_t InitLocalResConf()
{
    if (IsConfJsonEmpty()) {
        write_runlog(LOG, "[InitLocalRes] no resource exist.\n");
        return CM_SUCCESS;
    }

    for (uint32 i = 0; i < g_confJson->resource.count; ++i) {
        CM_RETURN_IFERR(InitLocalOneResConf(&g_confJson->resource.conf[i]));
    }

    return CM_SUCCESS;
}

uint32 GetLocalResConfCount()
{
    return g_localResConfCount;
}

bool IsCusResExistLocal()
{
    return (g_localResConfCount > 0);
}
