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
 * cms_cluster_switchover.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_server/cms_cluster_switchover.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CMS_CLUSTER_SWITCHOVER_H
#define CMS_CLUSTER_SWITCHOVER_H

#include "cm_server.h"

#define MAX_CYCLE 600

extern char switchover_flag_file_path[MAX_PATH_LEN];
extern void* Deal_switchover_for_init_cluster(void* arg);

#endif