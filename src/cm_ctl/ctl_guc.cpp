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
 * ctl_guc.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_ctl/ctl_guc.cpp
 *
 * -------------------------------------------------------------------------
 */

#include <string>
#include <termios.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/unistd.h>
#include "cm_misc.h"
#include "securec_check.h"
#include "cm/libpq-fe.h"
#include "ctl_common.h"

static const int MAX_PARAM_VALUE_LEN = 2048;
static const int CONF_COMMAND_LEN = 16;
static const int NODE_TYPE_LEN = 32;
static const int KEY_LEN = 16;
static char g_pidFile[CM_PATH_LENGTH];
static char g_tmpFile[CM_PATH_LENGTH];
static char g_confFile[CM_PATH_LENGTH];

extern char g_appPath[MAXPGPATH];
extern char mpp_env_separate_file[MAXPGPATH];
extern CtlCommand ctl_command;

static status_t CheckGucOption(const GucOption &gucCtx);

static inline void SkipSpace(char *&ptr)
{
    while (isspace((unsigned char)*ptr)) {
        ++ptr;
    }
}

status_t CheckGucSetParameter(const CtlOption *ctx)
{
    if (ctx->guc.parameter == NULL) {
        write_runlog2(ERROR, errcode(ERRCODE_PARAMETER_FAILURE),
            errmsg("The guc set option parameter is not specified."),
            errdetail("N/A"), errmodule(MOD_CMCTL),
            errcause("The guc set parameter is NULL."),
            erraction("Please check the cmdline entered by the user."));
        return CM_ERROR;
    }
    if (ctx->guc.value == NULL) {
        write_runlog2(ERROR, errcode(ERRCODE_PARAMETER_FAILURE),
            errmsg("The guc set option parameter is not specified."),
            errdetail("N/A"), errmodule(MOD_CMCTL),
            errcause("The guc set value is NULL."),
            erraction("Please check the cmdline entered by the user."));
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t CheckConfigFileStatus(struct stat statBuf, struct stat tmpBuf)
{
    if ((lstat(g_confFile, &statBuf) != 0) && (lstat(g_tmpFile, &tmpBuf) != 0)) {
        char *pchBaseName = strrchr(g_confFile, '/');

        if (pchBaseName == NULL) {
            pchBaseName = g_confFile;
        } else {
            ++pchBaseName;
        }
        write_runlog(ERROR, "cm_ctl: %s does not exist.\n", pchBaseName);

        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static bool IsLineCommented(const char *optLine)
{
    if (optLine == NULL) {
        return false;
    }

    char *tmp = (char*)(optLine);

    while (isspace((unsigned char)*tmp)) {
        ++tmp;
    }

    if (*tmp == '#') {
        return true;
    }

    return false;
}

static bool IsMatchParameterName(char *optLine, const char *paraName, size_t &valueOffset, size_t &valueLength)
{
    char *ptr = optLine;
    char *valuePtr = NULL;
    size_t paraLen = (size_t)strlen(paraName);

    SkipSpace(ptr);
    if (*ptr == '#') {
        ++ptr;
    }
    SkipSpace(ptr);

    if (strncmp(ptr, paraName, paraLen) != 0) {
        return false;
    }
    ptr += paraLen;
    SkipSpace(ptr);

    if (*ptr != '=') {
        return false;
    }
    ++ptr;
    SkipSpace(ptr);

    if (strlen(ptr) != 0) {
        valuePtr = ptr + 1;
        while ((*valuePtr != '\n') || (*valuePtr != '#')) {
            if (isspace((unsigned char) *valuePtr) != 0) {
                break;
            }
            ++valuePtr;
        }
    }
    valueOffset = (size_t)(ptr - optLine);
    valueLength = (valuePtr == NULL) ? 0 : (size_t)(valuePtr - ptr);

    return true;
}

static void PrintResults(bool isSuccess, const CtlOption *ctx)
{
    errno_t rc1 = 0;
    errno_t rc2 = 0;
    char nodeType[NODE_TYPE_LEN];
    char gucType[CONF_COMMAND_LEN];
    char cmNodeType[NODE_TYPE_LEN];

    if (isSuccess && ctx->guc.gucCommand == LIST_CONF_COMMAND) {
        return;
    }

    switch (ctx->guc.nodeType) {
        case NODE_TYPE_AGENT:
            rc1 = strcpy_s(nodeType, NODE_TYPE_LEN, "cm_agent.conf");
            rc2 = strcpy_s(cmNodeType, NODE_TYPE_LEN, "agent");
            break;
        case NODE_TYPE_SERVER:
            rc1 = strcpy_s(nodeType, NODE_TYPE_LEN, "cm_server.conf");
            rc2 = strcpy_s(cmNodeType, NODE_TYPE_LEN, "server");
            break;
        case NODE_TYPE_UNDEF:
        default:
            rc1 = strcpy_s(nodeType, NODE_TYPE_LEN, "unknown");
            rc2 = strcpy_s(cmNodeType, NODE_TYPE_LEN, "unknown");
            break;
    }
    securec_check_errno(rc1, (void)rc1);
    securec_check_errno(rc2, (void)rc2);

    switch (ctx->guc.gucCommand) {
        case SET_CONF_COMMAND:
            rc1 = strcpy_s(gucType, CONF_COMMAND_LEN, "set");
            break;
        case RELOAD_CONF_COMMAND:
            rc1 = strcpy_s(gucType, CONF_COMMAND_LEN, "reload");
            break;
        case LIST_CONF_COMMAND:
            rc1 = strcpy_s(gucType, CONF_COMMAND_LEN, "list");
            break;
        case UNKNOWN_COMMAND:
        default:
            break;
    }
    securec_check_errno(rc1, (void)rc1);

    if (isSuccess) {
        write_runlog(LOG, "%s %s success.\n", gucType, nodeType);
        if (ctl_command == CM_SET_COMMAND) {
            write_runlog(LOG, "HINT: For the setting to take effect, you should execute \'cm_ctl reload --param --%s\'.\n",
                cmNodeType);
        }
        return;
    }
    write_runlog(ERROR, "%s %s fail.\n", gucType, nodeType);
    return;
}

static void GetInstanceConfigfile(const NodeType &type, const char* dataDir)
{
    errno_t rc;

    switch (type) {
        case NODE_TYPE_AGENT:
            rc = snprintf_s(g_pidFile, CM_PATH_LENGTH, CM_PATH_LENGTH - 1, "%s/cm_agent.pid", dataDir);
            securec_check_intval(rc, (void)rc);
            rc = snprintf_s(g_confFile, CM_PATH_LENGTH, CM_PATH_LENGTH - 1, "%s/cm_agent.conf", dataDir);
            securec_check_intval(rc, (void)rc);
            rc = snprintf_s(g_tmpFile, CM_PATH_LENGTH, CM_PATH_LENGTH - 1, "%s/%s", dataDir, "cm_agent.conf.bak");
            securec_check_intval(rc, (void)rc);
            break;
        case NODE_TYPE_SERVER:
            rc = snprintf_s(g_pidFile, CM_PATH_LENGTH, CM_PATH_LENGTH - 1, "%s/cm_server.pid", dataDir);
            securec_check_intval(rc, (void)rc);
            rc = snprintf_s(g_confFile, CM_PATH_LENGTH, CM_PATH_LENGTH - 1, "%s/cm_server.conf", dataDir);
            securec_check_intval(rc, (void)rc);
            rc = snprintf_s(g_tmpFile, CM_PATH_LENGTH, CM_PATH_LENGTH - 1, "%s/%s", dataDir, "cm_server.conf.bak");
            securec_check_intval(rc, (void)rc);
            break;
        default:
            break;
    }
}

static int GetLinesIndex(char **optLines, const char *parameter, size_t &valueOffset, size_t &valueLength)
{
    int matchTimes = 0;
    int targetLine = 0;

    if (parameter == NULL) {
        return -1;
    }

    /* The first loop is to deal with the line with no commented by '#' in begin */
    for (int i = 0; optLines[i] != NULL; ++i) {
        if (!IsLineCommented(optLines[i])) {
            if (IsMatchParameterName(optLines[i], parameter, valueOffset, valueLength)) {
                ++matchTimes;
                targetLine = i;
            }
        }
    }
    if (matchTimes > 0) {
        if (matchTimes > 1) {
            write_runlog(LOG, "WARNING: There are %d \'%s\' commented in conf, and only the "
                              "last one in %dth line will be set and used.\n",
                matchTimes, parameter, (targetLine + 1));
        }
        return targetLine;
    }

    /* The second loop is to deal with the lines commented by '#' */
    matchTimes = 0;
    for (int i = 0; optLines[i] != NULL; ++i) {
        if (IsLineCommented(optLines[i])) {
            if (IsMatchParameterName(optLines[i], parameter, valueOffset, valueLength)) {
                ++matchTimes;
                targetLine = i;
            }
        }
    }
    if (matchTimes > 0) {
        return targetLine;
    }

    return -1;
}

static const char *GetCtlCommandType(const GucCommand &command)
{
    switch (command) {
        case SET_CONF_COMMAND:
            return "set";
        case RELOAD_CONF_COMMAND:
            return "reload";
        case LIST_CONF_COMMAND:
            return "list";
        default:
            break;
    }

    return NULL;
}

static const char *GetInstanceType(const NodeType &type)
{
    switch (type) {
        case NODE_TYPE_SERVER:
            return "--server";
        case NODE_TYPE_AGENT:
            return "--agent";
        default:
            return " ";
    }
}

static void GetRemoteGucCommand(const CtlOption *ctx, char *cmd, size_t cmdLen)
{
    int ret;
    char nodeIdStr[CONF_COMMAND_LEN];
    size_t curLen;

    ret = snprintf_s(nodeIdStr, sizeof(nodeIdStr), sizeof(nodeIdStr) - 1, "%u", ctx->comm.nodeId);
    securec_check_intval(ret, (void)ret);

    ret = snprintf_s(cmd, cmdLen, cmdLen - 1, "%s/bin/%s %s --param %s -n %s ", g_appPath, CM_CTL_BIN_NAME,
        GetCtlCommandType(ctx->guc.gucCommand), GetInstanceType(ctx->guc.nodeType), nodeIdStr);
    securec_check_intval(ret, (void)ret);
    curLen = (size_t)ret;

    if (ctx->guc.gucCommand != SET_CONF_COMMAND || ctx->guc.value == NULL || ctx->guc.parameter == NULL) {
        return;
    }

    if (strcmp(ctx->guc.parameter, "event_triggers") != 0) {
        ret = snprintf_s((cmd + curLen), (cmdLen - curLen), ((cmdLen - curLen) - 1),
            SYSTEMQUOTE "-k %s=\\\"%s\\\" " SYSTEMQUOTE, ctx->guc.parameter, ctx->guc.value);
        securec_check_intval(ret, (void)ret);
    } else {
        // event_triggers value contain double quotes, so an escape character is added before remote execution
        const char *value = ctx->guc.value;
        char valueCopy[cmdLen] = {0};
        int j = 0;
        for (size_t i = 0; i < strlen(value); ++i) {
            if (value[i] == '"') {
                valueCopy[j++] = '\\';
                valueCopy[j++] = '\\';
                valueCopy[j++] = '\\';
            }
            valueCopy[j++] = value[i];
        }
        ret = snprintf_s((cmd + curLen), (cmdLen - curLen), ((cmdLen - curLen) - 1),
            SYSTEMQUOTE "-k %s=\\\"%s\\\" " SYSTEMQUOTE, ctx->guc.parameter, valueCopy);
        securec_check_intval(ret, (void)ret);
    }
}

static void PrintOneParameterAndValue(char *line)
{
    char *ptr = line;
    string parameter;
    string value;
    
    SkipSpace(ptr);
    parameter.clear();
    while ((ptr != NULL) && (*ptr != '=') && !isspace((unsigned char)*ptr)) {
        parameter.push_back(*ptr);
        ++ptr;
    }

    SkipSpace(ptr);
    if (*ptr == '=') {
        ++ptr;
    } else {
        return;
    }

    SkipSpace(ptr);
    value.clear();
    while ((ptr != NULL) && (*ptr != '#') && !isspace((unsigned char)*ptr)) {
        value.push_back(*ptr);
        ++ptr;
    }

    if (!parameter.empty() && !value.empty()) {
        (void)printf(_("%s = %s\n"), parameter.c_str(), value.c_str());
    }
}

static void PrintValueAndParameter(char **lines)
{
    (void)printf(_("\n[conf of node(%u)]\n"), g_currentNode->node);
    for (int i = 0; lines[i] != NULL; ++i) {
        if (IsLineCommented(lines[i]) || (strcmp(lines[i], "\n") == 0)) {
            continue;
        }
        PrintOneParameterAndValue(lines[i]);
    }

    return;
}

static void FreeFile(char **file)
{
    char **tmp = file;
    while (*tmp != NULL) {
        free(*tmp);
        *tmp = NULL;
        ++tmp;
    }
    free(file);
}

// Write module is overwrite
static status_t WriteFile(char *path, uint32 pathLen, char **lines)
{
    if (pathLen == 0) {
        write_runlog(ERROR, "path(%s) len is zero.\n", path);
        return CM_ERROR;
    }
    int fd;

    canonicalize_path(path);
    FILE *outFile = fopen(path, "w");
    if (outFile == NULL) {
        write_runlog(ERROR, "cm_ctl: could not open file \"%s\" for writing: %s.\n", path, gs_strerror(errno));
        return CM_ERROR;
    }
    fd = fileno(outFile);
    if ((fd >= 0) && (fchmod(fd, S_IRUSR | S_IWUSR) == -1)) {
        write_runlog(ERROR, "could not set permissions of file  \"%s\".\n", path);
    }
    rewind(outFile);
    char **line = lines;
    while (*line != NULL) {
        if (fputs(*line, outFile) < 0) {
            write_runlog(ERROR, "cm_ctl: could not write file \"%s\": %s.\n", path, gs_strerror(errno));
            (void)fclose(outFile);
            return CM_ERROR;
        }
        ++line;
    }

    if (fsync(fileno(outFile)) != 0) {
        (void)fclose(outFile);
        write_runlog(ERROR, "could not fsync file \"%s\": %s.\n", path, gs_strerror(errno));
        return CM_ERROR;
    }

    if (fclose(outFile) != 0) {
        write_runlog(ERROR, "could not write file \"%s\": %s.\n", path, gs_strerror(errno));
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static char **ReadAndBackupConfigFile(const char *readFile, char *writeFile, uint32 len)
{
    status_t ret;

    char **configLines = CmReadfile(readFile);
    if (configLines == NULL) {
        write_runlog(ERROR, "read conf file failed: %s.\n", gs_strerror(errno));
        return NULL;
    }

    ret = WriteFile(writeFile, len, configLines);
    if (ret != CM_SUCCESS) {
        write_runlog(ERROR, "could not write file \"%s\": %s.\n", writeFile, gs_strerror(errno));
        freefile(configLines);
        return NULL;
    }

    return configLines;
}

void GenerateNewLine(char *oldLine, char *newLine, const char *value, const size_t valueOff, const size_t valueLen)
{
    char *oldLinePtr = oldLine;
    char *newLinePtr = newLine;

    errno_t rc;
    size_t newValueLen = (size_t)strlen(value);

    rc = strncat_s(newLinePtr, MAX_PARAM_VALUE_LEN, oldLinePtr, valueOff);
    securec_check_errno(rc, (void)rc);

    rc = strncat_s(newLinePtr, MAX_PARAM_VALUE_LEN, value, newValueLen);
    securec_check_errno(rc, (void)rc);

    oldLinePtr += (valueOff + valueLen);
    size_t lastLen = (size_t)strlen(oldLinePtr);

    rc = strncat_s(newLinePtr, MAX_PARAM_VALUE_LEN, oldLinePtr, lastLen);
    securec_check_errno(rc, (void)rc);
}

static status_t SetParameter(const GucOption *gucCtx, char **optLines)
{
    errno_t rc;
    size_t lineLen;

    int linesIndex;
    size_t optValueOff = 0;
    size_t optValueLen = 0;
    char newConfLine[MAX_PARAM_VALUE_LEN] = { 0 };

    if (gucCtx->parameter == NULL) {
        return CM_ERROR;
    }

    linesIndex = GetLinesIndex(optLines, gucCtx->parameter, optValueOff, optValueLen);
    if (linesIndex == -1) {
        return CM_ERROR;
    }
    lineLen = strlen(optLines[linesIndex]);

    if (gucCtx->value != NULL) {
        GenerateNewLine(optLines[linesIndex], newConfLine, gucCtx->value, optValueOff, optValueLen);
    } else {
        if (IsLineCommented(optLines[linesIndex])) {
            rc = strncpy_s(newConfLine, MAX_PARAM_VALUE_LEN,
                optLines[linesIndex], (size_t)Min(lineLen, (MAX_PARAM_VALUE_LEN - 1)));
            securec_check_errno(rc, (void)rc);
        } else {
            rc = snprintf_s(newConfLine, MAX_PARAM_VALUE_LEN,
                (MAX_PARAM_VALUE_LEN - 1), "#%s", optLines[linesIndex]);
            securec_check_intval(rc, (void)rc);
        }
    }

    free(optLines[linesIndex]);
    optLines[linesIndex] = NULL;
    optLines[linesIndex] = strdup(newConfLine);

    return CM_SUCCESS;
}

static status_t ExeGucParameterValueWrite(char **optLines)
{
    errno_t rc;
    status_t ret;
    char newTempFile[CM_PATH_LENGTH + CM_PATH_LENGTH] = { 0 };

    rc = snprintf_s(newTempFile, (CM_PATH_LENGTH + CM_PATH_LENGTH), (CM_PATH_LENGTH + CM_PATH_LENGTH - 1),
        "%s_bak", g_tmpFile);
    securec_check_intval(rc, (void)rc);

    ret = WriteFile(g_tmpFile, CM_PATH_LENGTH, optLines);
    if (ret != CM_SUCCESS) {
        write_runlog(ERROR, "write file %s failed, errmsg: %s.\n", g_tmpFile, gs_strerror(errno));
        return CM_ERROR;
    }

    char **newLines = CmReadfile(g_tmpFile);
    if (newLines == NULL || *newLines == NULL) {
        write_runlog(ERROR, "read file \"%s\" failed: %s.\n", g_tmpFile, gs_strerror(errno));
        return CM_ERROR;
    }
    ret = WriteFile(newTempFile, (CM_PATH_LENGTH + CM_PATH_LENGTH), newLines);
    freefile(newLines);
    if (ret != CM_SUCCESS) {
        write_runlog(ERROR, "could not write file \"%s\": %s.\n", newTempFile, gs_strerror(errno));
        return CM_ERROR;
    }

    if (rename(newTempFile, g_confFile) != 0) {
        write_runlog(ERROR, "err while move file (%s to %s):%s.\n", newTempFile, g_confFile, gs_strerror(errno));
        (void)unlink(newTempFile);
        return CM_ERROR;
    }

    /* fsync the file_dest file immediately, in case of an unfortunate system crash */
    FILE *fp = fopen(g_confFile, "r");
    if (fp == NULL) {
        write_runlog(ERROR, "could not open file \"%s\", errmsg: %s.\n", g_confFile, gs_strerror(errno));
        return CM_ERROR;
    }
    if (fsync(fileno(fp)) != 0) {
        write_runlog(ERROR, "could not fsync file \"%s\": %s.\n", g_confFile, gs_strerror(errno));
        (void)fclose(fp);
        return CM_ERROR;
    }
    (void)fclose(fp);

    return CM_SUCCESS;
}

static status_t ExeGucConfigReload()
{
    long pid;
    FILE* pidFd = fopen(g_pidFile, "r");
    if (pidFd == NULL) {
        if (errno != ENOENT) {
            write_runlog(ERROR, "cm_ctl: could not open PID file \"%s\":%s.\n", g_pidFile, gs_strerror(errno));
            return CM_ERROR;
        }
        pid = 0;
    } else {
        if (fscanf_s(pidFd, "%ld", &pid) != 1) {
            write_runlog(ERROR, "cm_ctl: invalid data in PID file \"%s\".\n", g_pidFile);
            (void)fclose(pidFd);
            return CM_ERROR;
        }
        (void)fclose(pidFd);
    }

    if (pid == 0) {
        write_runlog(ERROR, "cm_ctl: PID file \"%s\" does not exist.\n", g_pidFile);
        write_runlog(ERROR, "Is cma or cms running\n");
        return CM_ERROR;
    } else if (pid < 0) {
        pid = -pid;
        write_runlog(ERROR, "cm_ctl: cannot reload, single-user server is running (PID: %ld).\n", pid);
        write_runlog(ERROR, "Please terminate the single-user server and try again.\n");
        return CM_ERROR;
    }

    if (kill((pid_t)pid, SIGHUP) != 0) {
        write_runlog(ERROR, "cm_ctl: could not send reload signal(SIGHUP) PID:%ld %s.\n", pid, gs_strerror(errno));
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static status_t ExeGucConfigSet(const GucOption *gucCtx)
{
    status_t result;
    struct stat statBuf = { 0 };
    struct stat tempBuf = { 0 };
    char **configLines = NULL;

    if (CheckConfigFileStatus(statBuf, tempBuf) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (statBuf.st_size == 0 && tempBuf.st_size != 0) {
        write_runlog(ERROR, "The last signal is now, waiting....\n");
        return CM_ERROR;
    }

    if (lstat(g_confFile, &statBuf) != 0) {
        configLines = ReadAndBackupConfigFile(g_tmpFile, g_confFile, CM_PATH_LENGTH);
    } else {
        configLines = ReadAndBackupConfigFile(g_confFile, g_tmpFile, CM_PATH_LENGTH);
    }

    if (configLines == NULL) {
        return CM_ERROR;
    }

    if (SetParameter(gucCtx, configLines) != CM_SUCCESS) {
        write_runlog(ERROR, "can't find the parameter in conf.\n");
        FreeFile(configLines);
        return CM_ERROR;
    }
    result = ExeGucParameterValueWrite(configLines);

    FreeFile(configLines);

    return result;
}

static status_t ExeGucConfigList()
{
    struct stat statBuf = { 0 };
    struct stat tempBuf = { 0 };

    if (CheckConfigFileStatus(statBuf, tempBuf) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (statBuf.st_size == 0 && tempBuf.st_size != 0) {
        write_runlog(ERROR, "The last signal is now, waiting....\n");
        return CM_ERROR;
    }

    char **configLines = CmReadfile(g_confFile);
    if (configLines == NULL || *configLines == NULL) {
        write_runlog(ERROR, "read conf file failed: %s.\n", gs_strerror(errno));
        return CM_ERROR;
    }

    PrintValueAndParameter(configLines);
    FreeFile(configLines);
    return CM_SUCCESS;
}

status_t ExeGucCommand(const GucOption *gucCtx)
{
    status_t result;

    switch (gucCtx->gucCommand) {
        case SET_CONF_COMMAND:
            result = ExeGucConfigSet(gucCtx);
            break;
        case RELOAD_CONF_COMMAND:
            result = ExeGucConfigReload();
            break;
        case LIST_CONF_COMMAND:
            result = ExeGucConfigList();
            break;
        default:
            result = CM_ERROR;
            break;
    }

    return result;
}

static uint32 GetNodeIndex(uint32 nodeId)
{
    for (uint32 i = 0; i < g_node_num; ++i) {
        if (g_node[i].node == nodeId) {
            return i;
        }
    }
    return 0;
}

static status_t ListRemoteConf(const char *actualCmd, uint32 nodeId)
{
    char buf[MAX_PATH_LEN] = {0};
    FILE *fp = popen(actualCmd, "r");

    if (fp == NULL) {
        write_runlog(DEBUG1, "execute cmd(%s) failed.\n", actualCmd);
        return CM_ERROR;
    }
    if (fgets(buf, sizeof(buf), fp) != NULL) {
        (void)printf(_("%s"), buf);
    } else {
        write_runlog(LOG, "execute cmd (%s) failed, or conf of node(%u) is empty.\n", actualCmd, nodeId);
        (void)pclose(fp);
        return CM_ERROR;
    }
    while (fgets(buf, sizeof(buf), fp) != NULL) {
        (void)printf(_("%s"), buf);
    }
    (void)pclose(fp);

    return CM_SUCCESS;
}

static status_t ListRemoteConfMain(staticNodeConfig *node, const char *cmd)
{
    int ret;
    char actualCmd[MAX_PATH_LEN] = {0};

    for (uint32 i = 0; i < node->sshCount; ++i) {
        // need skip pssh content, use sed to skip first line and last line
        if (mpp_env_separate_file[0] == '\0') {
            ret = snprintf_s(actualCmd, MAX_PATH_LEN, MAX_PATH_LEN - 1,
                "pssh %s -H %s \"%s\" | sed '1d;$d'",
                PSSH_TIMEOUT_OPTION, node->sshChannel[i], cmd);
            securec_check_intval(ret, (void)ret);
        } else {
            ret = snprintf_s(actualCmd, MAX_PATH_LEN, MAX_PATH_LEN - 1,
                "pssh %s -H %s \"source %s;%s \" | sed '1d;$d'",
                PSSH_TIMEOUT_OPTION, node->sshChannel[i], mpp_env_separate_file, cmd);
            securec_check_intval(ret, (void)ret);
        }
        if (ListRemoteConf(actualCmd, node->node) == CM_SUCCESS) {
            write_runlog(DEBUG1, "execute remote cmd(%s) success.\n", actualCmd);
            return CM_SUCCESS;
        }
    }
    return CM_ERROR;
}

status_t ProcessInLocalInstanceExec(const GucOption *gucCtx)
{
    errno_t rc;
    char cmDir[CM_PATH_LENGTH] = { 0 };
    char instanceDir[CM_PATH_LENGTH] = { 0 };

    rc = memcpy_s(cmDir, sizeof(cmDir), g_currentNode->cmDataPath, sizeof(cmDir));
    securec_check_errno(rc, (void)rc);

    if (cmDir[0] == '\0') {
        write_runlog(ERROR, "Failed to get cm base data path from static config file.");
        return CM_ERROR;
    }

    if (gucCtx->nodeType == NODE_TYPE_AGENT) {
        rc = snprintf_s(instanceDir, sizeof(instanceDir), sizeof(instanceDir) - 1, "%s/cm_agent", cmDir);
        securec_check_intval(rc, (void)rc);
    } else {
        if (g_currentNode->cmServerLevel != 1) {
            write_runlog(LOG, "There is no cmserver instance on local node.");
            return CM_ERROR;
        }
        rc = snprintf_s(instanceDir, sizeof(instanceDir), sizeof(instanceDir) - 1, "%s/cm_server", cmDir);
        securec_check_intval(rc, (void)rc);
    }
    GetInstanceConfigfile(gucCtx->nodeType, instanceDir);
    if (ExeGucCommand(gucCtx) != CM_SUCCESS) {
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t ProcessInLocalInstance(const CtlOption *ctx)
{
    if (CheckGucOption(ctx->guc) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (ctx->guc.gucCommand == SET_CONF_COMMAND && CheckGucOptionValidate(ctx->guc) != CM_SUCCESS) {
        DoAdvice();
        return CM_ERROR;
    }

    return ProcessInLocalInstanceExec(&ctx->guc);
}

static status_t ProcessInRemoteInstance(const CtlOption *ctx)
{
    char remoteCmd[MAX_COMMAND_LEN] = {0};
    GetRemoteGucCommand(ctx, remoteCmd, sizeof(remoteCmd));
    if (ctx->guc.gucCommand == LIST_CONF_COMMAND) {
        return ListRemoteConfMain(&g_node[GetNodeIndex(ctx->comm.nodeId)], remoteCmd);
    }

    if (ssh_exec(&g_node[GetNodeIndex(ctx->comm.nodeId)], remoteCmd) != 0) {
        write_runlog(DEBUG1, "cm_ctl fail to execute command %s, errno=%d.\n", remoteCmd, errno);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t ProcessInAllNodesInstance(CtlOption *ctx)
{
    status_t result = CM_SUCCESS;

    for (uint32 i = 0; i < g_node_num; ++i) {
        if (g_node[i].cmServerLevel != 1 && ctx->guc.nodeType == NODE_TYPE_SERVER) {
            continue;
        }
        ctx->comm.nodeId = g_node[i].node;
        if (ctx->comm.nodeId == g_currentNode->node) {
            result = ProcessInLocalInstance(ctx);
        } else {
            result = ProcessInRemoteInstance(ctx);
        }
    }

    return result;
}

status_t ProcessClusterGucOption(CtlOption *ctx)
{
    if (ctx->comm.nodeId == 0) {
        return ProcessInAllNodesInstance(ctx);
    }

    if (ctx->comm.nodeId != g_currentNode->node) {
        return ProcessInRemoteInstance(ctx);
    }

    status_t res = ProcessInLocalInstance(ctx);
    if (res == CM_ERROR) {
        write_runlog(DEBUG1, "cm_ctl fail to execute in local.\n");
    }

    return res;

}

static status_t CheckGucOption(const GucOption &gucCtx)
{
    if (!gucCtx.needDoGuc) {
        write_runlog(LOG, "command wrong, need add \"--param\".\n");
        return CM_ERROR;
    }
    if (gucCtx.nodeType == NODE_TYPE_UNDEF) {
        write_runlog(LOG, "command wrong, need add \"--agent\" or \"--server\".\n");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

// cm_ctl integration guc set reload and check capacity
int DoGuc(CtlOption *ctx)
{
    status_t res = ProcessClusterGucOption(ctx);
    PrintResults(res == CM_SUCCESS, ctx);

    return (int)res;
}

static void MemsetPassword(char **password)
{
    if (password == NULL || (*password) == NULL) {
        return;
    }
    size_t len = strlen(*password);
    const int32 tryTimes = 3;
    for (int32 i = 0; i < tryTimes; ++i) {
        errno_t rc = memset_s((*password), len, 0, len);
        securec_check_errno(rc, (void)rc);
    }
    FREE_AND_RESET((*password));
}

static const char *GetModeString(const KeyMode &mode)
{
    switch (mode) {
        case SERVER_MODE:
            return "server";
        case CLIENT_MODE:
            return "client";
        default:
            break;
    }
    return "";
}

static inline bool IsPathPermissionRight(const char *path)
{
    bool isR = (access(path, R_OK) == 0);
    bool isW = (access(path, W_OK) == 0);
    bool isX = (access(path, X_OK) == 0);

    return (isR && isW && isX);
}

static char *CmSimplePrompt(const char *tipsStr, uint32 maxlen, bool echo)
{
    char *destBuff = (char *)malloc((size_t)maxlen + 1);
    if (destBuff == NULL) {
        return NULL;
    }

    struct termios oldTms, t;
    FILE *termIn = fopen("/dev/tty", "r");
    FILE *termOut = fopen("/dev/tty", "w");
    if ((termIn == NULL) || (termOut == NULL)) {
        if (termIn != NULL) {
            (void)fclose(termIn);
        }
        if (termOut != NULL) {
            (void)fclose(termOut);
        }
        termIn = stdin;
        termOut = stderr;
    }

    if (!echo) {
        /* disable echo via tcgetattr/tcsetattr */
        (void)tcgetattr(fileno(termIn), &t);
        oldTms = t;
        t.c_lflag &= ~ECHO;
        (void)tcsetattr(fileno(termIn), TCSAFLUSH, &t);
    }

    if (tipsStr != NULL) {
        (void)fputs(_(tipsStr), termOut);
        (void)fflush(termOut);
    }

    if (fgets(destBuff, (int)maxlen + 1, termIn) == NULL) {
        destBuff[0] = '\0';
    }
    size_t destBuffLen = strlen(destBuff);
    if (destBuffLen > 0 && destBuff[destBuffLen - 1] != '\n') {
        char buf[128];
        size_t bufLen;

        do {
            if (fgets(buf, sizeof(buf), termIn) == NULL) {
                break;
            }
            bufLen = strlen(buf);
        } while (bufLen > 0 && buf[bufLen - 1] != '\n');
    }

    if (destBuffLen > 0 && destBuff[destBuffLen - 1] == '\n') {
        destBuff[destBuffLen - 1] = '\0';
    }
    if (!echo) {
        /* restore previous echo behavior, then echo \n */
        (void)tcsetattr(fileno(termIn), TCSAFLUSH, &oldTms);
        (void)fputs("\n", termOut);
        (void)fflush(termOut);
    }

    if (termIn != stdin) {
        (void)fclose(termIn);
        (void)fclose(termOut);
    }

    return destBuff;
}

int DoEncrypt(const CtlOption *ctx)
{
    int ret;

    write_runlog(DEBUG1, "exec \"cm_ctl encrypt -M %s -D %s\".\n", GetModeString(ctx->guc.keyMod), ctx->comm.dataPath);
    if (!IsPathPermissionRight(ctx->comm.dataPath)) {
        write_runlog(LOG, "-D path not exist or permission denied.\n");
        return 1;
    }

    write_runlog(DEBUG1, "enter password.\n");
    char *password = CmSimplePrompt("please enter the password:", KEY_LEN + 1, false);
    if (!CheckInputPassword(password)) {
        write_runlog(LOG, "The input key must be 8~15 bytes and contain at least three kinds of characters!\n");
        MemsetPassword(&password);
        return 1;
    }

    write_runlog(DEBUG1, "enter password again.\n");
    char *passwordAgain = CmSimplePrompt("please enter the password again:", KEY_LEN + 1, false);
    if (passwordAgain == NULL || strcmp(password, passwordAgain) != 0) {
        write_runlog(LOG, "two passwords do not match!\n");
        MemsetPassword(&passwordAgain);
        MemsetPassword(&password);
        return 1;
    }

    write_runlog(DEBUG1, "clear secondary input.\n");
    MemsetPassword(&passwordAgain);

    write_runlog(DEBUG1, "begin to generate cipher file.\n");
    ret = GenCipherRandFiles(ctx->guc.keyMod, password, ctx->comm.dataPath);

    write_runlog(DEBUG1, "clear password.\n");
    MemsetPassword(&password);

    if (ret == 0) {
        write_runlog(LOG, "encrypt success.\n");
        return 0;
    }
    write_runlog(LOG, "encrypt fail.\n");
    return 1;
}
