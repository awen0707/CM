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
 * cms_arbitrate_cms.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_server/cms_arbitrate_cluster.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CMS_ARBITRATE_CLUSTER_H
#define CMS_ARBITRATE_CLUSTER_H

typedef enum MaxClusterResStatusE {
    MAX_CLUSTER_STATUS_INIT = 0, // no message
    MAX_CLUSTER_STATUS_UNKNOWN,
    MAX_CLUSTER_STATUS_AVAIL,
    MAX_CLUSTER_STATUS_UNAVAIL,
    MAX_CLUSTER_STATUS_CEIL  // it must be the end
} MaxClusterResStatus;

typedef enum MaxClusterResTypeE {
    MAX_CLUSTER_TYPE_INIT = 0,
    MAX_CLUSTER_TYPE_UNKNOWN,
    MAX_CLUSTER_TYPE_RES_STATUS,
    MAX_CLUSTER_TYPE_VOTE_DISK,
    MAX_CLUSTER_TYPE_NETWORK,
    MAX_CLUSTER_TYPE_CEIL  // it must be the end
} MaxClusterResType;

struct MsgRecvInfo;
void SetDelayArbiClusterTime();
void NotifyResRegOrUnreg();
void CheckMaxClusterHeartbeartValue();
void SetMaxClusterHeartBeatTimeout(int32 resIdx, MaxClusterResType type);
bool IsCurResAvail(int32 resIdx, MaxClusterResType type, MaxClusterResStatus status);
void *MaxNodeClusterArbitrateMain(void *arg);

#endif
