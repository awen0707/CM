/*
 * Copyright (c) 2020 Huawei Technologies Co.,Ltd.
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
 * ---------------------------------------------------------------------------------------
 * 
 * hotpatch_client.h
 * 
 * 
 * 
 * IDENTIFICATION
 *        src/include/hotpatch/hotpatch_client.h
 *
 * ---------------------------------------------------------------------------------------
 */

#ifndef HOTPATCH_CLIENT_H
#define HOTPATCH_CLIENT_H

const int g_millisecond = 1000;
const int g_hotpatch_wait_counter = 2000;

typedef void (*LogFunc)(const char*, ...) __attribute__((format(printf, 1, 2)));

extern int hotpatch_check(const char* path, const char* command, bool* is_list);
#endif
