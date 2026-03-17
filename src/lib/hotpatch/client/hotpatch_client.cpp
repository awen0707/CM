/*
 * Copyright (c) 2021 Huawei Technologies Co.,Ltd.
 *
 * openGauss is licensed under Mulan PSL v2.
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
 * hotpatch_client.cpp
 *    hotpatch client functions
 *
 * IDENTIFICATION
 *    src/lib/hotpatch/client/hotpatch_client.cpp
 *
 * -------------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <stddef.h>
#include "securec.h"
#include "securec_check.h"

#include "hotpatch/hotpatch.h"
#include "hotpatch/hotpatch_client.h"

char* strip_path_from_pathname(const char* name_withpath)
{
    if (name_withpath == NULL) {
        return NULL;
    }

    // no "/"
    char *name_without_path = strrchr((char *)name_withpath, '/');
    if (name_without_path == NULL) {
        return (char*)name_withpath;
    }

    // only "/"
    if (strlen(name_without_path) <= 1) {
        return NULL;
    }

    return (char*)(name_without_path + 1);
}

int hotpatch_check(const char* path, const char* command, bool* is_list)
{
    const char* support_action[] = {"list", "load", "unload", "active", "deactive", "info"};

    if (command == NULL) {
        return -1;
    }

    size_t cmd_number = sizeof(support_action) / sizeof(char*);
    for (size_t i = 0; i < cmd_number; i++) {
        if (strncmp(support_action[i], command, g_max_length_act) == 0) {
            if (i == 0) {
                *is_list = true;
            } else if (path == NULL) {
                return -1;
            }
            return 0;
        }
    }

    return -1;
}
