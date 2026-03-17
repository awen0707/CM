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
 * cm_ddb_etcd_stub.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_adapter/cm_etcd_adapter/cm_ddb_etcd_stub.cpp
 *
 * -------------------------------------------------------------------------
 */
#include "cm/cm_elog.h"
#include "cm_ddb_etcd.h"

static status_t EtcdLoadStubApi(const DrvApiInfo *apiInfo);

static DdbDriver g_drvEtcd = {PTHREAD_RWLOCK_INITIALIZER, false, DB_ETCD, "etcd conn", EtcdLoadStubApi};

DdbDriver *DrvEtcdGet(void)
{
    return &g_drvEtcd;
}

static void DrvEtcdFreeInfo(void)
{
    return;
}

static status_t EtcdLoadStubApi(const DrvApiInfo *apiInfo)
{
    DdbDriver *drv = DrvEtcdGet();
    drv->freeNodeInfo = DrvEtcdFreeInfo;
    write_runlog(ERROR, "EtcdLoadStubApi:Etcd client not support!\n");
    return CM_ERROR;
}