/*
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd.
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
 * ctl_res_list.h
 *
 * IDENTIFICATION
 *    include/cm/cm_ctl/ctl_res_list.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CTL_RES_LIST_H
#define CTL_RES_LIST_H

#include "c.h"
#include "cm_defs.h"

#include "cjson/cJSON.h"

#include "ctl_res.h"

status_t ListResInJson(cJSON *resArray, const ResOption *resCtx);

#endif
