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
 * cm_ddb_etcd.h
 *    API for etcd adapter
 *
 * IDENTIFICATION
 *    include/cm/cm_adapter/cm_ddb_etcd.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CM_DDB_ETCD_H
#define CM_DDB_ETCD_H

#include "cm_ddb_adapter.h"
#include "cm_etcdapi.h"

#define MAX_ETCD_NODE_NUM (1024)
#define PRIMARY_STANDBY_NUM (8)
#define MAX_VALUE_PRIMARY_HEARTBEAT (86400)

#define INSTANCE_ARBITRATE_DELAY_NO_SET (0)
#define INSTANCE_ARBITRATE_DELAY_HAVE_SET (1)

#define ARBITRATE_DELAY_CYCLE_MAX_COUNT (3)
#define CM_PRMOTE_DELAT_COUNT (3)
typedef struct EtcdSessPool_t {
    EtcdSession sess;
    DdbNodeState nodeState;
} EtcdSessPool;

extern uint32 g_etcdNum;
extern uint32 g_healthEtcdCountForPreConn;
extern ServerSocket *g_etcdInfo;
extern EtcdTlsAuthPath g_etcdTlsPath;
extern int32 g_timeOut;

DdbDriver *DrvEtcdGet(void);
status_t CreateEtcdSession(EtcdSession *session, const DrvApiInfo *apiInfo);
status_t DrvEtcdGetAllKV(
    const DrvCon_t session, DrvText *key, DrvKeyValue *keyValue, uint32 length, const DrvGetOption *option);
status_t DrvEtcdSaveAllKV(const DrvCon_t session, const DrvText *key, DrvSaveOption *option);
status_t CreateEtcdThread(const DrvApiInfo *apiInfo);
void DrvNotifyEtcd(DDB_ROLE dbRole);
void DrvEtcdSetMinority(bool isMinority);
status_t DrvEtcdNodeState(DrvCon_t session, char *memberName, DdbNodeState *nodeState);
status_t DrvEtcdNodeHealth(DrvCon_t session, char *memberName, DdbNodeState *nodeState);
status_t DrvEtcdRestConn(DrvCon_t sess, int32 timeOut);
status_t InitEtcdServerSocket(EtcdServerSocket **etcdServerList, const DrvApiInfo *apiInfo);
Alarm *DrvEtcdGetAlarm(int alarmIndex);

#endif