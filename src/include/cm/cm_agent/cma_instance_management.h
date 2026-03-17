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
 * cma_instance_management.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_agent/cma_instance_management.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CMA_INSTANCE_MANAGEMENT_H
#define CMA_INSTANCE_MANAGEMENT_H

#ifndef CM_IP_LENGTH
#define CM_IP_LENGTH 128
#endif

#define MAX_BUF_LEN 10
#define CHECK_DN_BUILD_TIME 25

#define MAX_OPTION_LEN 1048

void kill_instance_force(const char* data_path, InstanceTypes ins_type);
void immediate_stop_one_instance(const char* instance_data_path, InstanceTypes instance_type);
void immediate_shutdown_nodes(bool kill_cmserver, bool kill_cn);
void* agentStartAndStopMain(void* arg);
bool ExecuteCmdWithResult(char* cmd, char* result, int resultLen);
int agentCheckPort(uint32 port);
void CheckOfflineNode(uint32 i);
uint32 GetLibcommPort(const char* file_path, uint32 base_port, int port_type);
extern bool UpdateLibcommConfig();
int stop_instance_check(void);
int killInstanceByPid(const char *processName, const char *cmdLine);
void DelAndDownFloatIpInDn(uint32 index);

#ifdef ENABLE_UT
extern void StopOneZengine(uint32 index);
#endif

#endif
