/*
 * Copyright (c) 2022 Huawei Technologies Co.,Ltd.
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
 * cm_ddb_sharedisk_cmd.cpp
 *
 * IDENTIFICATION
 *    src/cm_adapter/cm_sharedisk_adapter/cm_ddb_sharedisk_cmd.cpp
 *
 * -------------------------------------------------------------------------
 */
#include "cm/cm_elog.h"
#include "cm_text.h"
#include "cm_disk_rw.h"
#include "cm_ddb_adapter.h"
#include "cm_ddb_sharedisk_cmd.h"

const int CMD_PARAMETER_CNT = 5;

static status_t CheckDupCommand(const DdbCommand *ddbCmd)
{
    if (ddbCmd->type != CMD_KEYWORD_UNKNOWN) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t ParseHelpCmd(char **argv, int32 argc, int *cur, DdbCommand *ddbCmd)
{
    CM_RETURN_IFERR(CheckDupCommand(ddbCmd));
    ddbCmd->type = CMD_KEYWORD_HELP;
    return CM_SUCCESS;
}

static status_t ParseKey(char **argv, int32 argc, int *cur, DdbCommand *ddbCmd)
{
    CM_RETVALUE_IFTRUE(*cur >= argc, CM_ERROR);
    ddbCmd->key = argv[*cur];
    ddbCmd->keyLen = (unsigned int)strlen(argv[*cur]);
    ++(*cur);
    return CM_SUCCESS;
}

static status_t ParseValue(char **argv, int32 argc, int *cur, DdbCommand *ddbCmd)
{
    CM_RETVALUE_IFTRUE(*cur >= argc, CM_ERROR);
    ddbCmd->val = argv[*cur];
    ddbCmd->valLen = (unsigned int)strlen(argv[*cur]);
    ++(*cur);
    return CM_SUCCESS;
}


static status_t ParseGetCmd(char** argv, int32 argc, int *cur, DdbCommand *ddbCmd)
{
    CM_RETURN_IFERR(CheckDupCommand(ddbCmd));
    ddbCmd->type = CMD_KEYWORD_GET;
    return ParseKey(argv, argc, cur, ddbCmd);
}

static status_t ParseDeleteCmd(char** argv, int32 argc, int *cur, DdbCommand *ddbCmd)
{
    CM_RETURN_IFERR(CheckDupCommand(ddbCmd));
    ddbCmd->type = CMD_KEYWORD_DELETE;
    return ParseKey(argv, argc, cur, ddbCmd);
}

static status_t ParsePutCmd(char** argv, int32 argc, int *cur, DdbCommand *ddbCmd)
{
    CM_RETURN_IFERR(CheckDupCommand(ddbCmd));
    ddbCmd->type = CMD_KEYWORD_PUT;
    CM_RETURN_IFERR(ParseKey(argv, argc, cur, ddbCmd));
    return ParseValue(argv, argc, cur, ddbCmd);
}

static status_t ParsePrefixCmd(char** argv, int32 argc, int *cur, DdbCommand *ddbCmd)
{
    if (ddbCmd->prefix) {
        return CM_ERROR;
    }
    ddbCmd->prefix = true;
    return CM_SUCCESS;
}

typedef status_t (*DdbCmdParse)(char** argv, int32 argc, int *cur, DdbCommand *ddbCmd);
typedef struct st_ddb_cmd_option_item {
    const char *optionName;
    DdbCmdParse parseCommand;
} DdbCmdOptionItem;

DdbCmdOptionItem g_cmdOptions[] = {
    {"--help",    ParseHelpCmd},
    {"-h",        ParseHelpCmd},
    {"--prefix",  ParsePrefixCmd},
    {"--get",     ParseGetCmd},
    {"--delete",  ParseDeleteCmd},
    {"--put",     ParsePutCmd},
};

status_t ParseDdbCmd(char **argv, int32 argc, int cur, DdbCommand *ddbCommand)
{
    if (argc == cur) {
        return CM_SUCCESS;
    }
    bool hasCmd = false;
    uint32 count = ELEMENT_COUNT(g_cmdOptions);
    for (uint32 i = 0; i < count; i++) {
        if (strcmp(argv[cur], g_cmdOptions[i].optionName) == 0) {
            if (g_cmdOptions[i].parseCommand == NULL) {
                break;
            }
            ++cur;
            hasCmd = true;
            if (g_cmdOptions[i].parseCommand(argv, argc, &cur, ddbCommand) != CM_SUCCESS) {
                CM_SET_DISKRW_ERROR(ERR_DDB_CMD_INVALID);
                return CM_ERROR;
            }
            break;
        }
    }

    if (!hasCmd) {
        CM_SET_DISKRW_ERROR(ERR_DDB_CMD_UNKNOWN, argv[cur]);
        return CM_ERROR;
    }
    return ParseDdbCmd(argv, argc, cur, ddbCommand);
}

status_t ExecuteDdbHelp(char *output, int *outputLen, uint32 maxBufLen)
{
    const char *help = "\nOptions:\n"
                       "   --help, -h      Shows help information\n"
                       "\nCommand:\n"
                       "   --get key       Queries the value of a specified key\n"
                       "       Command options:\n"
                       "           --prefix: Prefix matching query\n"
                       "   --put key val   Updates or insert the value of a specified key\n"
                       "   --delete key    Deletes the specified key\n"
                       "       Command options:\n"
                       "           --prefix: Prefix matching query\n";
    uint32 len = (uint32)strlen(help);
    *outputLen = (int)(len + 1);
    uint32 copyLen = len;
    if (maxBufLen <= len) {
        copyLen = maxBufLen - 1;
    }
    errno_t rc = memcpy_s(output, maxBufLen, help, copyLen);
    securec_check_errno(rc, (void)rc);
    output[copyLen] = '\0';
    return CM_SUCCESS;
}

status_t ExecuteDdbGet(DdbCommand *ddbCmd, char *output, int *outputLen, uint32 maxBufLen)
{
    char getOutPut[DDB_MAX_KEY_VALUE_LEN] = {0};
    uint32 len = 0;
    errno_t rc;
    if (!ddbCmd->prefix) {
        status_t res = DiskCacheRead(ddbCmd->key, getOutPut, DDB_MAX_KEY_VALUE_LEN);
        if (res != CM_SUCCESS) {
            return CM_ERROR;
        }
        len = (uint32)strlen(getOutPut);
    } else {
        char kvBuff[DDB_MAX_KEY_VALUE_LEN] = {0};
        status_t res = DiskCacheRead(ddbCmd->key, kvBuff, DDB_MAX_KEY_VALUE_LEN, true);
        if (res != CM_SUCCESS) {
            write_runlog(DEBUG1, "ExecuteDdbGet: failed to get all value of key %s.\n", ddbCmd->key);
            return CM_ERROR;
        }
        write_runlog(
            DEBUG1, "ExecuteDdbGet: get all values, key is %s, result_key_value is %s.\n", ddbCmd->key, kvBuff);

        char *pLeft = NULL;
        char *pKey = strtok_r(kvBuff, ",", &pLeft);
        char *pValue = strtok_r(NULL, ",", &pLeft);
        uint32 i = 0;
        while (pKey && pValue) {
            rc = snprintf_s(getOutPut + len,
                (size_t)(DDB_MAX_KEY_VALUE_LEN - len),
                (size_t)((DDB_MAX_KEY_VALUE_LEN - len) - 1),
                "%s",
                pKey);
            securec_check_intval(rc, (void)rc);
            len += (uint32)strlen(pKey);

            rc = snprintf_s(getOutPut + len,
                (size_t)(DDB_MAX_KEY_VALUE_LEN - len),
                (size_t)((DDB_MAX_KEY_VALUE_LEN - len) - 1),
                "%s",
                "\n");
            securec_check_intval(rc, (void)rc);
            len += 1;

            rc = snprintf_s(getOutPut + len,
                (size_t)(DDB_MAX_KEY_VALUE_LEN - len),
                (size_t)((DDB_MAX_KEY_VALUE_LEN - len) - 1),
                "%s",
                pValue);
            securec_check_intval(rc, (void)rc);
            len += (uint32)strlen(pValue);

            rc = snprintf_s(getOutPut + len,
                (size_t)(DDB_MAX_KEY_VALUE_LEN - len),
                (size_t)((DDB_MAX_KEY_VALUE_LEN - len) - 1),
                "%s",
                "\n");
            securec_check_intval(rc, (void)rc);
            len += 1;

            pKey = strtok_r(NULL, ",", &pLeft);
            pValue = strtok_r(NULL, ",", &pLeft);
            ++i;
        }
        if (i == 0) {
            write_runlog(ERROR,
                "ExecuteDdbGet: get all values is empty, key is %s result_key_value is %s.\n",
                ddbCmd->key,
                kvBuff);
            return CM_ERROR;
        }
    }

    *outputLen = (int)(len + 1);
    uint32 copyLen = len;
    if (maxBufLen <= len) {
        copyLen = maxBufLen - 1;
    }
    rc = memcpy_s(output, (size_t)maxBufLen, getOutPut, (size_t)copyLen);
    securec_check_errno(rc, (void)rc);
    output[copyLen] = '\0';
    return CM_SUCCESS;
}

status_t ExecuteDdbPut(DdbCommand *ddbCmd)
{
    status_t res = DiskCacheWrite(ddbCmd->key, ddbCmd->keyLen, ddbCmd->val, ddbCmd->valLen, NULL);
    if (res != CM_SUCCESS) {
        write_runlog(ERROR, "DrvSdSetKV: set key %s to value %s failed.\n", ddbCmd->key, ddbCmd->val);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t ExecuteDdbDelete(DdbCommand *ddbCmd)
{
    status_t res;
    if (ddbCmd->prefix) {
        res = DiskCacheDeletePrefix(ddbCmd->key);
    } else {
        res = DiskCacheDelete(ddbCmd->key);
    }

    if (res != CM_SUCCESS) {
        write_runlog(ERROR, "ExecuteDdbDelete: del key %s failed.\n", ddbCmd->key);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t ProcessDdbCmd(DdbCommand *ddbCmd, char *output, int *outputLen, uint32 maxBufLen)
{
    status_t ret = CM_SUCCESS;
    *outputLen = 0;
    *output = 0;
    switch (ddbCmd->type) {
        case CMD_KEYWORD_HELP:
            ret = ExecuteDdbHelp(output, outputLen, maxBufLen);
            break;
        case CMD_KEYWORD_GET:
            ret = ExecuteDdbGet(ddbCmd, output, outputLen, maxBufLen);
            break;
        case CMD_KEYWORD_PUT:
            ret = ExecuteDdbPut(ddbCmd);
            break;
        case CMD_KEYWORD_DELETE:
            ret = ExecuteDdbDelete(ddbCmd);
            break;
        default:
            ret = CM_ERROR;
            break;
    }
    return ret;
}

status_t ExecuteDdbCmd(char *cmd, char *output, int *outputLen, uint32 maxBufLen)
{
    int argc = 0;
    char *argv[CMD_PARAMETER_CNT];
    char *pSave;
    char *pLeft = strtok_r(cmd, " ", &pSave);
    while (pLeft) {
        argv[argc] = pLeft;
        argc++;
        if (argc >= CMD_PARAMETER_CNT) {
            write_runlog(ERROR, "ExecuteDdbCmd: server command:%s has %d parameters.\n", cmd, argc);
            CM_SET_DISKRW_ERROR(ERR_DDB_CMD_ARG_INVALID);
            return CM_ERROR;
        }
        pLeft = strtok_r(NULL, " ", &pSave);
    }

    DdbCommand ddbCmd;
    errno_t rc = memset_s(&ddbCmd, sizeof(ddbCmd), 0, sizeof(ddbCmd));
    securec_check_errno(rc, (void)rc);
    if (ParseDdbCmd(argv, argc, 0, &ddbCmd) != CM_SUCCESS) {
        write_runlog(ERROR, "ExecuteDdbCmd: parse server command content %s failed.\n", cmd);
        return CM_ERROR;
    }

    if (ddbCmd.prefix && (ddbCmd.type != CMD_KEYWORD_GET && ddbCmd.type != CMD_KEYWORD_DELETE)) {
        write_runlog(ERROR,
            "ExecuteDdbCmd: parse server command content %s failed for prefix only used with get or delete cmd.\n",
            cmd);
        CM_SET_DISKRW_ERROR(ERR_DDB_CMD_PREFIX_INVALID);
        return CM_ERROR;
    }

    return ProcessDdbCmd(&ddbCmd, output, outputLen, maxBufLen);
}

