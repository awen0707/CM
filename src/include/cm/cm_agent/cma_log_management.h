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
 * cma_log_management.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_agent/cma_log_management.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CMA_LOG_MANAGEMENT_H
#define CMA_LOG_MANAGEMENT_H

/* compress buffer size */
#define GZ_BUFFER_LEN 65535
/*
 * trace will be deleted directly if exceeded LOG_GUARD_COUNT
 * the priority of this guard higher than save days but lower than maximum capacity
 */
#define LOG_GUARD_COUNT 20000
#define LOG_GUARD_COUNT_BUF 21000

/* Initialize log pattern and log count when started */
extern LogPattern* g_logPattern;

int isLogFile(const char* fileName);
int get_log_pattern();
void* CompressAndRemoveLogFile(void* arg);
#endif
