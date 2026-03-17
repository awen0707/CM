/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: for common function.
 * Filename: cm_voting_disk.cpp
 *
 */
#include "cm_voting_disk.h"

#include <fcntl.h>
#include <malloc.h>
#include <pthread.h>
#include "elog.h"

#include "cm_config.h"
#include "cm_rhb.h"

diskLrwHandler g_vdHandler;
pthread_rwlock_t g_vdRwLock;
uint32 g_vdBaseOffset;
static char *g_nodeDataBuff = NULL;
static time_t g_heartbeat[VOTING_DISK_MAX_NODE_NUM] = {0};

void GetNodeDiskStat(time_t nodeDiskStats[VOTING_DISK_MAX_NODE_NUM], unsigned int *hwl)
{
    *hwl = g_node_num;
    const size_t ndSize = sizeof(time_t) * VOTING_DISK_MAX_NODE_NUM;
    errno_t rc = memcpy_s(nodeDiskStats, ndSize, g_heartbeat, ndSize);
    securec_check_errno(rc, (void)rc);
}

status_t SetVotingDiskData(const char *data, uint32 dataLen, uint32 offset)
{
    (void)pthread_rwlock_wrlock(&(g_vdRwLock));
    g_vdHandler.offset = g_vdBaseOffset + offset;
    int rc = memcpy_s(g_vdHandler.rwBuff, VOTING_DISK_DATA_SIZE, data, dataLen);
    securec_check_errno(rc, (void)rc);
    if (ShareDiskWrite(&g_vdHandler, g_vdHandler.rwBuff, dataLen) != CM_SUCCESS) {
        write_runlog(ERROR, "[%s] update data to disk failed.\n", __FUNCTION__);
        (void)pthread_rwlock_unlock(&(g_vdRwLock));
        return CM_ERROR;
    }
    (void)pthread_rwlock_unlock(&(g_vdRwLock));
    write_runlog(DEBUG1, "[%s] update data to disk succ.\n", __FUNCTION__);
    return CM_SUCCESS;
}

status_t SetVotingDiskSingleNodeInfo(const VotingDiskNodeInfo *nodeInfo, uint32 nodeIndex)
{
    if (nodeIndex >= VOTING_DISK_MAX_NODE_NUM) {
        write_runlog(ERROR, "[%s] node index %u exceeds max node number of voting disk.\n", __FUNCTION__, nodeIndex);
        return CM_ERROR;
    }
    uint32 offset = VOTING_DISK_NODE_PAGE_OFFSET + nodeIndex * VOTING_DISK_EACH_NODE_OFFSET;
    if (SetVotingDiskData((const char *)nodeInfo, sizeof(VotingDiskNodeInfo), offset) != CM_SUCCESS) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t GetVotingDiskData(char *data, uint32 dataLen, uint32 offset)
{
    (void)pthread_rwlock_wrlock(&(g_vdRwLock));
    g_vdHandler.offset = g_vdBaseOffset + offset;
    if (ShareDiskRead(&g_vdHandler, data, dataLen) != CM_SUCCESS) {
        (void)pthread_rwlock_unlock(&(g_vdRwLock));
        write_runlog(ERROR, "[%s] get data failed.\n", __FUNCTION__);
        return CM_ERROR;
    }
    (void)pthread_rwlock_unlock(&(g_vdRwLock));
    write_runlog(DEBUG1, "[%s] get data success.\n", __FUNCTION__);
    return CM_SUCCESS;
}

status_t GetVotingDiskSingleNodeInfo(VotingDiskNodeInfo *nodeInfo, uint32 nodeIndex)
{
    if (nodeIndex >= VOTING_DISK_MAX_NODE_NUM) {
        write_runlog(ERROR, "[%s] node index %u exceeds max node number of voting disk.\n", __FUNCTION__, nodeIndex);
        return CM_ERROR;
    }
    uint32 offset = VOTING_DISK_NODE_PAGE_OFFSET + nodeIndex * VOTING_DISK_EACH_NODE_OFFSET;
    if (GetVotingDiskData((char *)nodeInfo, sizeof(VotingDiskNodeInfo), offset) != CM_SUCCESS) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t GetVotingDiskNodeData(char *data, uint32 dataLen)
{
    uint32 offset = VOTING_DISK_NODE_PAGE_OFFSET;
    uint32 maxDataLen = VOTING_DISK_DATA_SIZE;
    if (dataLen > maxDataLen) {
        write_runlog(ERROR, "[%s] get dataLen %u exceeds the total length of node data(64M).\n", __FUNCTION__, dataLen);
        return CM_ERROR;
    }
    if (GetVotingDiskData(data, dataLen, offset) != CM_SUCCESS) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t SetVotingDiskNodeData(char *data, uint32 dataLen)
{
    uint32 offset = VOTING_DISK_NODE_PAGE_OFFSET;
    uint32 maxDataLen = VOTING_DISK_DATA_SIZE;
    if (dataLen > maxDataLen) {
        write_runlog(ERROR, "[%s] set dataLen %u exceeds the total length of node data(64M).\n", __FUNCTION__, dataLen);
        return CM_ERROR;
    }
    if (SetVotingDiskData(data, dataLen, offset) != CM_SUCCESS) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t UpdateAllNodeHeartBeat(uint32 nodeNum)
{
    uint32 dataLen = nodeNum * VOTING_DISK_EACH_NODE_OFFSET;
    if (GetVotingDiskNodeData(g_nodeDataBuff, dataLen) != CM_SUCCESS) {
        write_runlog(ERROR, "[%s] get voting disk node data failed.\n", __FUNCTION__);
        return CM_ERROR;
    }
    for (uint32 i = 0; i < nodeNum; i++) {
        uint32 offset = i * VOTING_DISK_EACH_NODE_OFFSET;
        VotingDiskNodeInfo *nodeInfo = (VotingDiskNodeInfo*)(g_nodeDataBuff + offset);
        if (nodeInfo->nodeTime == 0) {
            continue;
        }
        g_heartbeat[i] = nodeInfo->nodeTime;
    }
    write_runlog(DEBUG5, "[%s] update all node heartbeat from voting disk success.\n", __FUNCTION__);
    return CM_SUCCESS;
}

void ResetVotingdiskHeartBeat()
{
    errno_t rc = memset_s(g_heartbeat, sizeof(g_heartbeat), 0, sizeof(g_heartbeat));
    securec_check_errno(rc, (void)rc);
}

void FreeVdHandler()
{
    FREE_AND_RESET(g_vdHandler.rwBuff);
    (void)close(g_vdHandler.fd);
}

status_t InitVotingDiskHandler(const char *scsiDev, uint32 offset)
{
    (void)pthread_rwlock_wrlock(&(g_vdRwLock));
    g_vdHandler.scsiDev[0] = '\0';
    int32 ret = strcpy_s(g_vdHandler.scsiDev, MAX_PATH_LENGTH, scsiDev);
    if (ret != 0) {
        write_runlog(ERROR, "[%s] copy string %s failed\n", __FUNCTION__, scsiDev);
        (void)pthread_rwlock_unlock(&(g_vdRwLock));
        return CM_ERROR;
    }
    g_vdBaseOffset = offset;
    g_vdHandler.offset = g_vdBaseOffset;
    g_vdHandler.fd = open(g_vdHandler.scsiDev, O_RDWR | O_DIRECT | O_SYNC);
    if (g_vdHandler.fd < 0) {
        write_runlog(ERROR, "[%s] open disk %s failed, errno %d.\n", __FUNCTION__, g_vdHandler.scsiDev, errno);
        (void)pthread_rwlock_unlock(&(g_vdRwLock));
        return CM_ERROR;
    }
    g_vdHandler.rwBuff = (char *)memalign(VOTING_DISK_ALIGN_SIZE, VOTING_DISK_DATA_SIZE);
    if (g_vdHandler.rwBuff == NULL) {
        write_runlog(ERROR, "[%s] alloc memory failed\n", __FUNCTION__);
        (void)close(g_vdHandler.fd);
        (void)pthread_rwlock_unlock(&(g_vdRwLock));
        return CM_ERROR;
    }

    (void)pthread_rwlock_unlock(&(g_vdRwLock));
    return CM_SUCCESS;
}

status_t InitVotingDisk(const char *votingDiskPath)
{
    uint32 offset = 0;
    char devPath[MAX_PATH_LENGTH];
    int ret = strcpy_s(devPath, MAX_PATH_LENGTH, votingDiskPath);
    if (ret != 0) {
        write_runlog(ERROR, "Get voting disk path failed!\n");
        return CM_ERROR;
    }
    if (InitVotingDiskHandler(devPath, offset) != CM_SUCCESS) {
        return CM_ERROR;
    }
    write_runlog(LOG, "Init voting disk success, devpath: %s, offset: %u\n", devPath, offset);
    return CM_SUCCESS;
}

VotingDiskStatus GetNodeHeartbeatStat(uint32 nodeIndex, uint32 diskTimeout, int logLevel)
{
    if (nodeIndex >= VOTING_DISK_MAX_NODE_NUM) {
        write_runlog(logLevel, "[%s] node index %u exceeds max node of voting disk .\n", __FUNCTION__, nodeIndex);
        return VOTING_DISK_STATUS_UNAVAIL;
    }
    if (diskTimeout == 0) {
        return VOTING_DISK_STATUS_AVAIL;
    }
    if (g_heartbeat[nodeIndex] == 0) {
        return VOTING_DISK_STATUS_UNKNOWN;
    }
    const uint32 timeBufMaxLen = 128;
    struct tm result;
    char timeBuf[timeBufMaxLen] = {0};
    GetLocalTime(&g_heartbeat[nodeIndex], &result);
    (void)strftime(timeBuf, timeBufMaxLen, "%Y-%m-%d %H:%M:%S", &result);
    write_runlog(DEBUG5, "[%s] nodeIndex %u, diskTimeout %u, nodeTime: %s\n",
        __FUNCTION__, nodeIndex, diskTimeout, timeBuf);

    time_t curTime = time(NULL);
    if (IsRhbTimeout(g_heartbeat[nodeIndex], curTime, (int)diskTimeout)) {
        write_runlog(logLevel, "[%s] nodeIndex %u heartbeat timeout, diskTimeout=%u, nodeTime: %s\n",
            __FUNCTION__, nodeIndex, diskTimeout, timeBuf);
        return VOTING_DISK_STATUS_UNAVAIL;
    }
    return VOTING_DISK_STATUS_AVAIL;
}

status_t AllocVotingDiskMem()
{
    if (g_nodeDataBuff == NULL) {
        g_nodeDataBuff = (char*)malloc(VOTING_DISK_DATA_SIZE);
        if (g_nodeDataBuff == NULL) {
            write_runlog(ERROR, "g_nodeDataBuff is NULL.\n");
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

void FreeVotingDiskMem()
{
    FREE_AND_RESET(g_nodeDataBuff);
}
