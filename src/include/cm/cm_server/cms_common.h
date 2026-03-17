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
 * cms_common.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_server/cms_common.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CMS_COMMON_H
#define CMS_COMMON_H

#include "cm_server.h"

uint32 findMinCmServerInstanceIdIndex();
NotifyCn_t setNotifyCnFlagByNodeId(uint32 nodeId);
bool is_valid_host(const CM_Connection* con, int remote_type);
void get_parameters_from_configfile();
void FreeNotifyMsg();
#ifdef ENABLE_MULTIPLE_NODES
void get_paramter_coordinator_heartbeat_timeout();
int cm_notify_msg_init(void);
#endif
void clean_init_cluster_state();
void get_config_param(const char* config_file, const char* srcParam, char* destParam, int destLen);
int StopCheckNode(uint32 nodeIdCheck);
void SendSignalToAgentThreads();
extern int GetCtlThreadNum();
int UpdateDynamicConfig();
void UpdateAzNodeInfo();
void GetDdbTypeParam(void);
void GetDdbArbiCfg(int32 loadWay);
void GetTwoNodesArbitrateParams(void);
status_t GetMaintainPath(char *maintainFile, uint32 fileLen);
status_t GetDdbKVFilePath(char *kvFile, uint32 fileLen);
bool IsUpgradeCluster(void);
bool MaintanceOrInstallCluster(void);
void GetDoradoOfflineIp(char *ip, uint32 ipLen);
bool SetOfflineNode(void);
void GetDelayArbitTimeFromConf();
void GetBackupOpenConfig();
void GetDelayArbitClusterTimeFromConf();
void GetDnArbitrateMode();
void CmsSyncStandbyMode();

bool EnableShareDisk();

#endif
