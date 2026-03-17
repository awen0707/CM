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
 * cma_common.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_agent/cma_common.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CMA_COMMON_H
#define CMA_COMMON_H

#include "cm_misc.h"
#include "cma_main.h"
#include "cm_msg_buf_pool.h"
#include "cma_msg_queue.h"

#ifndef CM_IP_LENGTH
#define CM_IP_LENGTH 128
#endif
#define CM_EXECUTE_CMD_TIME_OUT 2

const int max_instance_start = 3;
typedef enum {
    CM_RES_UNKNOWN = 0,
    CM_RES_ONLINE  = 1,
    CM_RES_OFFLINE = 2,
    CM_RES_CORPSE = 3,
} CM_ResStatus;

const int ERROR_EXECUTE_CMD = -2;
const int FAILED_EXECUTE_CMD = -1;
const int SUCCESS_EXECUTE_CMD = 0;

void save_thread_id(pthread_t thrId);
void set_thread_state(pthread_t thrId);
void immediate_stop_one_instance(const char* instance_data_path, InstanceTypes instance_type);

const char *GetDnProcessName(void);
const char* type_int_to_str_binname(InstanceTypes ins_type);
const char* type_int_to_str_name(InstanceTypes ins_type);
int ExecuteCmd(const char* command, struct timeval timeout);
int cmagent_getenv(const char* env_var, char* output_env_value, uint32 env_value_len);

void ReloadParametersFromConfigfile();
int ReadDBStateFile(GaussState *state, const char *statePath);
void UpdateDBStateFile(const char *path, const GaussState *state);
extern uint64 g_obsDropCnXlog;

pgpid_t get_pgpid(char* pid_path, uint32 len);
bool is_process_alive(pgpid_t pid);
void set_disc_check_state(uint32 instanceId);
bool agentCheckDisc(const char* path);
void set_instance_not_exist_alarm_value(int *val, int state);
void record_pid(const char* DataPath);
uint32 GetLibcommPort(const char* file_path, uint32 base_port, int port_type);
uint32 GetDatanodeNumSort(const staticNodeConfig* p_node_config, uint32 sort);
int check_disc_state(uint32 instanceId);
int search_HA_node(uint32 localPort, uint32 LocalHAListenCount, char LocalHAIP[][CM_IP_LENGTH], uint32 peerPort,
    uint32 PeerHAListenCount, char PeerHAIP[][CM_IP_LENGTH], uint32* node_index, uint32* instance_index,
    uint32 loal_role);
int agentCheckPort(uint32 port);
uint32 CheckDiskForLogPath(void);
uint32 GetDiskUsageForPath(const char *pathName);
uint32 GetDiskUsageForLinkPath(const char *pathName);
bool IsLinkPathDestroyedOrDamaged(const char *pathName);
int ExecuteSystemCmd(const char *cmd, int32 logLevel = ERROR, int32 *errCode = NULL);
void CheckDnNicDown(uint32 index);
void CheckDnDiskDamage(uint32 index);
bool IsDirectoryDestroyed(const char *path);
bool DnManualStop(uint32 index);
bool DirectoryIsDestroyed(const char *path);
void ReportCMAEventAlarm(Alarm *alarmItem, AlarmAdditionalParam *additionalParam);
bool CheckStartDN(void);
int ProcessDnBarrierInfoResp(const cm_to_agent_barrier_info *barrierRespMsg);
int ProcessGsGucDnCommand(const CmToAgentGsGucSyncList *msgTypeDoGsGuc);
void ExecuteCrossClusterCnBuildCommand(const char *dataDir, char *userInfo);
void PrintInstanceStack(const char* dataPath, bool isPrintedOnce);
void *DiskUsageCheckMain(void *arg);
void *PGControlDataCheckMain(void *arg);
void CheckDiskForCNDataPath();
void CheckDiskForDNDataPath();
void PGDataControlCheck();
bool FindDnIdxInCurNode(uint32 instId, uint32 *dnIdx, const char *str);
CmResConfList *CmaGetResConfByResName(const char *resName);
#endif
