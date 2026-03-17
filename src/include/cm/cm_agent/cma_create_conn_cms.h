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
 * cma_create_conn_cms.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_agent/cma_create_conn_cms.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CMA_CREATE_CONN_CMS_H
#define CMA_CREATE_CONN_CMS_H

typedef enum CMA_OPERATION_ {
    CMA_KILL_SELF_INSTANCES = 0,
    CMA_OPERATION_CEIL,
} cma_operation;

int CreateStopNodeInstancesFlagFile(const char *stopFlagFile);
void StartOrStopNodeInstances(OperateType operateType);
bool isMaintenanceModeDisableOperation(const cma_operation op);
void* ConnCmsPMain(void* arg);
extern bool isUpgradeCluster();
void* CheckUpgradeMode(void* arg);
#endif
