/*
 * Copyright (c) 2022 Huawei Technologies Co.,Ltd.
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
 * cma_network_check.h
 *
 * IDENTIFICATION
 *    include/cm/cm_agent/cma_network_check.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CMA_NETWORK_CHECK_H
#define CMA_NETWORK_CHECK_H
#include "cm_defs.h"

#include "common/config/cm_config.h"

#include "cm_msg_common.h"
#include "cm_json_parse_floatIp.h"

typedef enum CmaInstTypeE {
    CM_INSTANCE_TYPE_CMA = 0,  // it cannot smaller than 0
    CM_INSTANCE_TYPE_CMS,
    CM_INSTANCE_TYPE_CN,
    CM_INSTANCE_TYPE_GTM,
    CM_INSTANCE_TYPE_DN,
    CM_INSTANCE_TYPE_CEIL  // it must be end
} CmaInstType;

typedef enum NetworkTypeE {
    NETWORK_TYPE_LISTEN = 0,  // it cannot smaller than 0
    NETWORK_TYPE_HA,
    NETWORK_TYPE_FLOATIP,
    NETWORK_TYPE_CEIL  // it must be end
} NetworkType;

typedef struct DnFloatIpOperMapT {
    uint32 count;
    NetworkOper oper[CM_MAX_DATANODE_PER_NODE];
    DnFloatIp floatIp[CM_MAX_DATANODE_PER_NODE];
} DnFloatIpMapOper;

bool GetNicStatus(unsigned int instId, CmaInstType instType, NetworkType type = NETWORK_TYPE_LISTEN);
void SetNicOper(uint32 instId, CmaInstType instType, NetworkType type, NetworkOper oper);
void GetFloatIpNicStatus(uint32 instId, CmaInstType instType, NetworkState *state, uint32 count);
void *CmaCheckNetWorkMain(void *arg);
status_t CreateNetworkResource();
NetworkState GetNetworkStateByOper(NetworkOper oper);
NetworkOper GetNetworkOperByState(NetworkState state);
NetworkOper ChangeInt2NetworkOper(int32 oper);
void SetFloatIpOper(uint32 dnIdx, NetworkOper oper, const char *str);
NetworkOper GetFloatIpOper(uint32 dnIdx);
DnFloatIp *GetDnFloatIpByDnIdx(uint32 dnIdx);
const char *GetOperMapString(NetworkOper oper);
bool8 CheckNetworkStatusByIps(const char (*ips)[CM_IP_LENGTH], uint32 cnt);
void SetNeedResetFloatIp(const CmSendPingDnFloatIpFail *recvMsg, uint32 dnIdx);
bool CheckSupportIpV6();

#endif
