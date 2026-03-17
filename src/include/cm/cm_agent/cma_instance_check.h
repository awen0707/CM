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
 * cma_instance_check.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_agent/cma_instance_check.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CM_CMA_INSTANCE_CHECK_H
#define CM_CMA_INSTANCE_CHECK_H

#define CHECK_INTERVAL (4)
#define DECIMAL_NOTATION (10)
#define SHUTDOWN_SLEEP_TIME (5)

using EnvThreshold = struct EnvThresholdSt {
    int mem;
    int cpu;
    int disk;
    int instMem;
    int instPool;
};

int CreateCnDnConnectCheckThread(void);
void CheckAllInstStatus(const EnvThreshold *threshold);

#endif  // CM_CMA_INSTANCE_CHECK_H
