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
 * cms_ddb.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_server/cms_ddb.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CMS_DDB_H
#define CMS_DDB_H
#include "cm_server.h"
#include "cms_global_params.h"
#include "cms_ddb_adapter.h"

extern volatile bool g_arbitrationChangedFromMinority;
uint32 ReadTermFromDdb(uint32 groupIdx);
void ClearSyncWithDdbFlag(void);
void CmsGetKerberosInfoFromDdb(void);
int SetTermIfArbitrationChanged(uint32 *term);
bool SetHeartbeatToEtcd(char *key);
bool GetFinishRedoFlagFromDdb(uint32 groupIdx);
bool GetFinishRedoFlagFromDdbNew(void);

void SetDynamicConfigChangeToDdb(uint32 groupIdx, int32 memIdx);
void GetCoordinatorDynamicConfigChangeFromDdb(uint32 groupIdx);
void GetCoordinatorDynamicConfigChangeFromDdbNew(uint32 groupIdx);
void GetDatanodeDynamicConfigChangeFromDdb(uint32 groupIdx);
void GetDatanodeDynamicConfigChangeFromDdbNew(uint32 groupIdx);
void GetGtmDynamicConfigChangeFromDdb(uint32 groupIdx);
void SetStaticPrimaryRole(const uint32 groupIndex, const int staticPrimaryIndex);
int SetReplaceCnStatusToDdb(void);
status_t GetNodeReadOnlyStatusFromDdb();
void SetNodeReadOnlyStatusToDdb();

status_t TryDdbGet(const char *key, char *value, int32 maxSize, int32 tryTimes, int32 logLevel = ERROR);
uint64 GetTimeMinus(const struct timeval checkEnd, const struct timeval checkBegin);
DDB_RESULT GetHistoryClusterCurSyncListFromDdb(void);
DDB_RESULT GetHistoryClusterExceptSyncListFromDdb(void);
bool SetGroupExpectSyncList(uint32 groupIndex, const CurrentInstanceStatus *statusInstance);

int SetTermToDdb(uint32 term);
int IncrementTermToDdb(uint32 incTerm = CM_INCREMENT_TERM_VALUE);
#endif