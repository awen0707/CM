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
 * cm_etcdapi.h
 *    etcd client interface
 *
 * IDENTIFICATION
 *    include/cm/cm_adapter/cm_etcdapi.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef _CM_ETCD_API_H_
#define _CM_ETCD_API_H_

#include "etcdapi.h"

int EtcdGetAllValues(EtcdSession session, char* key, char *keyValue, const GetEtcdOption* option, int valueSize);

#endif
