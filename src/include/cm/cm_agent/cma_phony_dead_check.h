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
 * cma_phony_dead_check.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_agent/cma_phony_dead_check.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CMA_PHONY_DEAD_CHECK_H
#define CMA_PHONY_DEAD_CHECK_H

void* DNPhonyDeadStatusCheckMain(void * const arg);
void* DNCoreDumpCheckMain(void *arg);
void* FaultDetectMain(void* arg);

#ifdef ENABLE_UT
extern bool DnPhonyDeadStatusCheck(int dnId, uint32 *agentCheckTimeInterval);
extern bool DnPhonyDeadProcessE2E(int dnId, int phonyDead);
#endif

#endif