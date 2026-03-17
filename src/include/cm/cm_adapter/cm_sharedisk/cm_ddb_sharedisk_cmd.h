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
 * share_disk_api.cpp
 *
 * IDENTIFICATION
 *    src/cm_adapter/cm_sharedisk/cm_ddb_sharedisk_cmd.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CM_DDB_SHAREDISK_CMD_H
#define CM_DDB_SHAREDISK_CMD_H

#include "cm/cm_defs.h"
#include "c.h"

typedef enum en_ddb_cmd_type {
    CMD_KEYWORD_UNKNOWN = 0,
    CMD_KEYWORD_HELP,
    CMD_KEYWORD_VERSION,
    CMD_KEYWORD_PREFIX,
    CMD_KEYWORD_GET,
    CMD_KEYWORD_DELETE,
    CMD_KEYWORD_PUT,
} DDB_CMD_TYPE;

typedef struct st_ddb_command {
    DDB_CMD_TYPE type;
    bool prefix;
    unsigned int keyLen;
    char *key;
    unsigned int valLen;
    char *val;
} DdbCommand;

status_t ExecuteDdbCmd(char *cmd, char *output, int *outputLen, uint32 maxBufLen);
#endif
