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
 * cma_datanode_utils.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_agent/clients/libpq/cma_datanode_utils.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CMA_DATANODE_UTILS_H
#define CMA_DATANODE_UTILS_H

#include "cma_libpq_api.h"
#include "cma_main.h"


#ifdef ENABLE_MULTIPLE_NODES
int GetAllDatabaseInfo(int index, DNDatabaseInfo **dnDatabaseInfo, int *dnDatabaseCount);
int GetDBTableFromSQL(int index, uint32 databaseId, uint32 tableId, uint32 tableIdSize, DNDatabaseInfo *dnDatabaseInfo,
    int dnDatabaseCount, char *databaseName, char *tableName);
#endif
int cmagent_execute_query_and_check_result(cltPqConn_t *db_connection, const char *run_command);
int cmagent_execute_query(cltPqConn_t *db_connection, const char *run_command);

extern cltPqConn_t *g_dnConn[CM_MAX_DATANODE_PER_NODE];
extern THR_LOCAL cltPqConn_t *g_Conn;

extern void check_parallel_redo_status_by_file(
    agent_to_cm_datanode_status_report *reportMsg, const char *redoStatePath);
extern void check_datanode_realtime_build_status_by_file(
    agent_to_cm_datanode_status_report *reportMsg, const char *dataPath);
extern int check_datanode_status_by_SQL0(agent_to_cm_datanode_status_report *report_msg, uint32 ii);
extern int check_datanode_status_by_SQL1(agent_to_cm_datanode_status_report *report_msg, uint32 ii);
extern int check_datanode_status_by_SQL2(agent_to_cm_datanode_status_report *report_msg, uint32 ii);
extern int check_datanode_status_by_SQL3(agent_to_cm_datanode_status_report *report_msg, uint32 ii);
extern int check_datanode_status_by_SQL4(
    agent_to_cm_datanode_status_report *report_msg, DnLocalPeer *lpInfo, uint32 ii);
extern void check_datanode_status_by_SQL5(uint32 instanceId, uint32 ii, const char *data_path);
extern int check_datanode_status_by_SQL6(
    agent_to_cm_datanode_status_report *report_msg, uint32 ii, const char *data_path);
extern int CheckDatanodeStatusBySqL10(agent_to_cm_datanode_status_report *reportMsg, uint32 ii);
extern int check_flush_lsn_by_preparse(agent_to_cm_datanode_status_report* report_msg, uint32 dataNodeIndex);
extern int CheckDatanodeSyncList(uint32 instd, AgentToCmserverDnSyncList *syncListMsg, cltPqConn_t **curDnConn);
extern int CheckDatanodeSyncCommit(uint32 instd, AgentToCmserverDnSyncAvailable *syncMsg, cltPqConn_t **curDnConn);
extern int CheckDatanodeCurSyncLists(uint32 instd, AgentToCmserverDnSyncAvailable *syncMsg, cltPqConn_t **curDnConn);
extern int CheckMostAvailableSync(uint32 index);
void CheckTransactionReadOnly(cltPqConn_t* Conn, uint32 index, int instanceType);
extern int cmagent_execute_query(cltPqConn_t *db_connection, const char *run_command);
extern int cmagent_execute_query_and_check_result(cltPqConn_t *db_connection, const char *run_command);

extern int cmagent_to_coordinator_connect(const char *pid_path);
uint32 find_cn_active_info_index(const agent_to_cm_coordinate_status_report_old *report_msg, uint32 coordinatorId);
extern int is_cn_connect_ok(uint32 coordinatorId);
extern int datanode_rebuild_reason_enum_to_int(HaRebuildReason reason);
extern cltPqConn_t *get_connection(const char *pid_path, bool isCoordinater = false, int connectTimeOut = 5,
    const int32 rwTimeout = 5);
extern bool isUpgradeCluster();
int32 CheckDnSyncDone(uint32 instd, AgentToCmserverDnSyncList *syncListMsg, cltPqConn_t **curDnConn);
extern int StandbyClusterCheckQueryBarrierID(cltPqConn_t* &conn, AgentToCmBarrierStatusReport *barrierInfo);
extern int StandbyClusterSetTargetBarrierID(cltPqConn_t* &conn);
extern int StandbyClusterGetBarrierInfo(cltPqConn_t* &conn, AgentToCmBarrierStatusReport *barrierInfo);
extern int StandbyClusterCheckCnWaiting(cltPqConn_t* &conn);
void ShowPgThreadWaitStatus(cltPqConn_t* Conn, uint32 index, int instanceType);
void ProcessCrossClusterBuildCommand(int instanceType, const char *dataDir);
void ExecuteCascadeStandbyDnBuildCommand(const char *dataDir);
void CleanStandbyClusterCnAlarm();
extern void check_datanode_realtime_build_status_by_sql(agent_to_cm_datanode_status_report* report_msg, uint32 ii);

#endif
