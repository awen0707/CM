/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: for common function.
 * Filename: cm_voting_disk.h.
 *
 */

#ifndef CM_VOTING_DISK_H
#define CM_VOTING_DISK_H

#include "share_disk_api.h"

#define VOTING_DISK_MAX_NODE_NUM (64)
#define VOTING_DISK_ALIGN_SIZE (512)
#define VOTING_HEADER_PAGE_SPACE (20 * 1024 * 1024)
#define VOTING_DISK_NODE_PAGE_OFFSET VOTING_HEADER_PAGE_SPACE
#define VOTING_DISK_EACH_NODE_OFFSET (1024 * 1024)
#define VOTING_DISK_DATA_SIZE (VOTING_DISK_MAX_NODE_NUM * VOTING_DISK_EACH_NODE_OFFSET)

typedef enum {
    VOTING_DISK_STATUS_INIT = 0, // no message
    VOTING_DISK_STATUS_UNKNOWN,
    VOTING_DISK_STATUS_AVAIL,
    VOTING_DISK_STATUS_UNAVAIL,
    VOTING_DISK_STATUS_CEIL  // it must be the end
} VotingDiskStatus;

typedef struct {
    time_t nodeTime;
    char reserved[MAX_BYTE_LENGTH - 8];
} VotingDiskNodeInfo;

typedef struct {
    pthread_rwlock_t lock;
    VotingDiskNodeInfo nodeInfo;
} VotingDiskNode;

void GetNodeDiskStat(time_t nodeDiskStats[VOTING_DISK_MAX_NODE_NUM], unsigned int *hwl);
status_t SetVotingDiskData(const char *data, uint32 dataLen, uint32 offset);
status_t SetVotingDiskSingleNodeInfo(const VotingDiskNodeInfo *nodeInfo, uint32 nodeIndex);
status_t GetVotingDiskData(char *data, uint32 dataLen, uint32 offset);
status_t GetVotingDiskSingleNodeInfo(VotingDiskNodeInfo *nodeInfo, uint32 nodeIndex);
status_t InitVotingDiskHandler(const char *scsiDev, uint32 offset);
status_t InitVotingDisk(const char *votingDiskPath);
status_t UpdateAllNodeHeartBeat(uint32 nodeNum);
void ResetVotingdiskHeartBeat();
VotingDiskStatus GetNodeHeartbeatStat(uint32 nodeIndex, uint32 diskTimeout, int logLevel);
status_t AllocVotingDiskMem();
void FreeVotingDiskMem();

#endif
