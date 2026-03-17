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
 * cma_mes.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_agent/cma_mes.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CMA_MES_H
#define CMA_MES_H

#include <time.h>

void CreateRhbCheckThreads();

void GetHbs(time_t *hbs, unsigned int *hwl);

int SetMesSslParam(const char* param_name, const char* param_value);

#endif
