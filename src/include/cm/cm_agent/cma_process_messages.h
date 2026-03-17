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
 * cma_process_messages.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_agent/cma_process_messages.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CMA_PROCESS_MESSAGES_H
#define CMA_PROCESS_MESSAGES_H

#ifndef CM_IP_LENGTH
#define CM_IP_LENGTH 128
#endif

void immediate_stop_one_instance(const char* instance_data_path, InstanceTypes instance_type);
void kill_instance_force(const char* data_path, InstanceTypes ins_type);
char* get_logicClusterName_by_dnInstanceId(uint32 dnInstanceId);
void CmServerCmdProcessorInit(void);
void *ProcessSendCmsMsgMain(void *arg);
void *ProcessRecvCmsMsgMain(void *arg);

#ifdef ENABLE_UT
extern void process_notify_command(const char* data_dir, int instance_type, int role, uint32 term);
extern void process_restart_command(const char* data_dir, int instance_type);
extern int FindInstancePathAndType(uint32 node, uint32 instanceId, char* data_path, int* instance_type);
extern void process_failover_command(const char* dataDir, int instance_type,
    uint32 instance_id, uint32 term, int32 staPrimId);
extern void process_rep_most_available_command(const char* dataDir, int instance_type);
extern void process_heartbeat_command(int cluster_status);
#endif

extern void RunCmd(const char* command);


#endif