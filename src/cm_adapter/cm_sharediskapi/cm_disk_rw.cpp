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
 * cm_disk_rw.cpp
 *
 * IDENTIFICATION
 *    src/cm_adapter/cm_sharediskapi/cm_disk_rw.cpp
 *
 * -------------------------------------------------------------------------
 */
#include <malloc.h>
#include "securec.h"
#include "cm/cm_elog.h"
#include "cm_disk_rw.h"

using namespace std;

uint32 g_sdBaseOffset = 0;
diskLrwHandler g_sdLrwHandler;
pthread_rwlock_t g_sdRwLock;
cache_area_list g_sdCacheList;

static uint8 GetOffsetUsedFlag(uint8 value, uint32 offset);
status_t CheckKey(uint32 bitMap, const char *key);
status_t ReadDiskKeyArea(uint32 bitMap, char *key, uint32 keyLen);
status_t ReadDiskDataArea(uint32 bitMap, const char *key, char *data, uint32 dataLen);
status_t ReloadAllDataFromDisk(void);
status_t UpdateDiskHeaderArea(uint32 bitMap);
status_t CreateKeyListFromDisk();
uint8 FindCache(const char *key, uint32 *findBitMap);
status_t UpdateDiskDataArea(uint32 bitMap, const char *data, uint32 dataLen, DATA_TYPE type);

status_t OpenDiskFileHandle(const char *scsi_dev, uint32 offset, int64 instId)
{
    (void)pthread_rwlock_wrlock(&(g_sdRwLock));
    int32 ret = strcpy_s(g_sdLrwHandler.scsiDev, MAX_PATH_LENGTH, scsi_dev);
    if (ret != 0) {
        write_runlog(ERROR, "OpenDiskFileHandle: copy string %s failed\n", scsi_dev);
        (void)pthread_rwlock_unlock(&(g_sdRwLock));
        return CM_ERROR;
    }
    g_sdLrwHandler.instId = instId;
    g_sdBaseOffset = offset;
    g_sdLrwHandler.offset = g_sdBaseOffset;
    g_sdLrwHandler.fd = open(g_sdLrwHandler.scsiDev, O_RDWR | O_DIRECT | O_SYNC);
    if (g_sdLrwHandler.fd < 0) {
        write_runlog(ERROR, "OpenDiskFileHandle: open disk %s failed\n", g_sdLrwHandler.scsiDev);
        (void)pthread_rwlock_unlock(&(g_sdRwLock));
        return CM_ERROR;
    }

    g_sdLrwHandler.rwBuff = (char *)memalign(DISK_WRITE_512BYTES, BITMAP_BYTE_LENGTH);
    if (g_sdLrwHandler.rwBuff == NULL) {
        write_runlog(ERROR, "OpenDiskFileHandle: alloc memory failed\n");
        (void)close(g_sdLrwHandler.fd);
        (void)pthread_rwlock_unlock(&(g_sdRwLock));
        return CM_ERROR;
    }
    (void)pthread_rwlock_unlock(&(g_sdRwLock));
    return CM_SUCCESS;
}

status_t InsertCache(const char *key, uint32 bitMap)
{
    pair<map<string, uint32>::iterator, bool> ret = g_sdCacheList.sdCacheMap.insert(pair<string, uint32>(key, bitMap));
    if (!ret.second) {
        write_runlog(ERROR, "InsertCache: insert key %s, bitMap %u failed.\n", key, bitMap);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t CreateKeyListFromDisk()
{
    uint8 value = 0;
    uint32 bitMap = 0;

    char key[MAX_KEY_LENGTH] = {0};
    for (uint32 ind = 0; ind <= g_sdCacheList.cacheHeaderList->maxBitMap; ind++) {
        value = g_sdCacheList.cacheHeaderList->bitMapArray[ind];
        uint32 offset;
        for (offset = 0; offset < BIT_NUM; offset++) {
            if (GetOffsetUsedFlag(value, offset) == CM_FALSE) {
                continue;
            }
            bitMap = BIT_NUM * ind + offset;
            CM_RETURN_IFERR(ReadDiskKeyArea(bitMap, key, MAX_KEY_LENGTH));
            if (FindCache(key, NULL) == CM_TRUE) {
                write_runlog(ERROR, "CreateKeyListFromDisk: find duplicate key %s.\n", key);
                continue;
            }

            if (strlen(key) == 0) {
                write_runlog(ERROR, "CreateKeyListFromDisk: find blank key bitMap %u\n", bitMap);
                continue;
            }
            if (InsertCache(key, bitMap) != CM_SUCCESS) {
                return CM_ERROR;
            }
        }
    }
    return CM_SUCCESS;
}

void CacheListClear(void)
{
    g_sdCacheList.sdCacheMap.clear();
}

status_t AllocHeaderListMem()
{
    g_sdCacheList.cacheHeaderList = (ByteNode_t *)malloc(sizeof(ByteNode_t));
    if (g_sdCacheList.cacheHeaderList == NULL) {
        write_runlog(ERROR, "AllocHeaderListMem: alloc header memory failed!\n");
        return CM_ERROR;
    }
    g_sdCacheList.cacheHeaderList->bitMapArray = (uint8 *)malloc(BITMAP_BYTE_LENGTH * sizeof(uint8));
    if (g_sdCacheList.cacheHeaderList->bitMapArray == NULL) {
        write_runlog(ERROR, "AllocHeaderListMem: alloc bitMap memory %d failed!\n", BITMAP_BYTE_LENGTH);
        FREE_AND_RESET(g_sdCacheList.cacheHeaderList);
        return CM_ERROR;
    }
    g_sdCacheList.cacheHeaderList->maxBitMap = 0;
    g_sdCacheList.cacheHeaderList->version = 0;
    return CM_SUCCESS;
}
void FreeHeaderListMem()
{
    FREE_AND_RESET(g_sdCacheList.cacheHeaderList->bitMapArray);
    FREE_AND_RESET(g_sdCacheList.cacheHeaderList);
}

void FreeLrwHandler()
{
    FREE_AND_RESET(g_sdLrwHandler.rwBuff);
    (void)close(g_sdLrwHandler.fd);
}

status_t InitDiskData(const char *scsi_dev, uint32 offset, int64 instId)
{
    CM_RETURN_IFERR(OpenDiskFileHandle(scsi_dev, offset, instId));
    if (AllocHeaderListMem() != CM_SUCCESS) {
        FreeLrwHandler();
        return CM_ERROR;
    }
    if (ReloadAllDataFromDisk() != CM_SUCCESS) {
        FreeHeaderListMem();
        FreeLrwHandler();
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t HeaderListReset(const char *buffer)
{
    write_runlog(DEBUG1, "HeaderListReset: begin to copy header data!\n");
    int32 rc = memcpy_s(
        (void *)&g_sdCacheList.cacheHeaderList->version, DISK_HEADER_PAGE_OFFSET, buffer, DISK_HEADER_PAGE_OFFSET);
    if (rc != 0) {
        write_runlog(ERROR, "HeaderListReset: copy header data %s failed!\n", buffer);
        return CM_ERROR;
    }

    write_runlog(LOG, "HeaderListReset: get header version %u, maxBitMap %u!\n",
        g_sdCacheList.cacheHeaderList->version, g_sdCacheList.cacheHeaderList->maxBitMap);
    return CM_SUCCESS;
}

status_t ReloadAllDataFromDisk(void)
{
    char buffer[MAX_BYTE_LENGTH + 1] = {0};

    write_runlog(DEBUG1, "ReloadAllDataFromDisk: \n");
    uint32 offset = DISK_PAGE_LOCK_OFFSET;
    (void)pthread_rwlock_wrlock(&(g_sdCacheList.lk_lock));
    (void)pthread_rwlock_wrlock(&(g_sdRwLock));
    g_sdLrwHandler.offset = g_sdBaseOffset + offset;
    if (ShareDiskRead(&(g_sdLrwHandler), buffer, MAX_BYTE_LENGTH) != CM_SUCCESS) {
        (void)pthread_rwlock_unlock(&(g_sdRwLock));
        (void)pthread_rwlock_unlock(&(g_sdCacheList.lk_lock));
        write_runlog(ERROR, "ReloadAllDataFromDisk: try to read header data failed, offset %u.\n", offset);
        return CM_ERROR;
    }
    offset = DISK_BITMAP_OFFSET;
    g_sdLrwHandler.offset = g_sdBaseOffset + offset;
    if (ShareDiskRead(&(g_sdLrwHandler), (char *)g_sdCacheList.cacheHeaderList->bitMapArray, BITMAP_BYTE_LENGTH) !=
        CM_SUCCESS) {
        (void)pthread_rwlock_unlock(&(g_sdRwLock));
        (void)pthread_rwlock_unlock(&(g_sdCacheList.lk_lock));
        write_runlog(ERROR, "ReloadAllDataFromDisk: try to read bitmap data failed!\n");
        return CM_ERROR;
    }
    (void)pthread_rwlock_unlock(&(g_sdRwLock));

    if (HeaderListReset(buffer) != CM_SUCCESS) {
        (void)pthread_rwlock_unlock(&(g_sdCacheList.lk_lock));
        write_runlog(ERROR, "ReloadAllDataFromDisk: reset header list failed\n");
        return CM_ERROR;
    }
    CacheListClear();
    if (CreateKeyListFromDisk() != CM_SUCCESS) {
        (void)pthread_rwlock_unlock(&(g_sdCacheList.lk_lock));
        write_runlog(ERROR, "ReloadAllDataFromDisk: create key and bitMap relation from disk failed!\n");
        return CM_ERROR;
    }
    (void)pthread_rwlock_unlock(&(g_sdCacheList.lk_lock));
    write_runlog(DEBUG1, "ReloadAllDataFromDisk: read data from disk finish\n");
    return CM_SUCCESS;
}

static uint32 GetAvailableFlagOffset(const uint8 *value)
{
    uint32 offset;
    if (((*value) & 0x80) == 0) { /* 10000000 */
        offset = OFFSET_0;
    } else if (((*value) & 0x40) == 0) { /* 01000000 */
        offset = OFFSET_1;
    } else if (((*value) & 0x20) == 0) { /* 00100000 */
        offset = OFFSET_2;
    } else if (((*value) & 0x10) == 0) { /* 00010000 */
        offset = OFFSET_3;
    } else if (((*value) & 0x08) == 0) { /* 00001000 */
        offset = OFFSET_4;
    } else if (((*value) & 0x04) == 0) { /* 00000100 */
        offset = OFFSET_5;
    } else if (((*value) & 0x02) == 0) { /* 00000010 */
        offset = OFFSET_6;
    } else if (((*value) & 0x01) == 0) { /* 00000001 */
        offset = OFFSET_7;
    } else {
        offset = 0xFFFFFFFF;
    }

    write_runlog(DEBUG1, "GetAvailableFlagOffset: get offset %u\n", offset);
    return offset;
}

static status_t AddUpdateOffsetFlag(uint8 *value, uint32 offset)
{
    status_t ret = CM_SUCCESS;
    switch (offset) {
        case OFFSET_0:
            *value = (*value | 0x80); /* 10000000 */
            break;
        case OFFSET_1:
            *value = (*value | 0x40); /* 01000000 */
            break;
        case OFFSET_2:
            *value = (*value | 0x20); /* 00100000 */
            break;
        case OFFSET_3:
            *value = (*value | 0x10); /* 00010000 */
            break;
        case OFFSET_4:
            *value = (*value | 0x08); /* 00001000 */
            break;
        case OFFSET_5:
            *value = (*value | 0x04); /* 00000100 */
            break;
        case OFFSET_6:
            *value = (*value | 0x02); /* 00000010 */
            break;
        case OFFSET_7:
            *value = (*value | 0x01); /* 00000001 */
            break;
        default:
            ret = CM_ERROR;
            break;
    }
    write_runlog(DEBUG1, "AddUpdateOffsetFlag: get value %u with offset %u\n", (uint32)(*value), offset);
    return ret;
}

static status_t DeleteUpdateOffsetFlag(uint8 *value, uint32 offset)
{
    status_t ret = CM_SUCCESS;

    if (*value == (uint8)0) {
        write_runlog(LOG, "DeleteUpdateOffsetFlag: data has been deleted.\n");
        return CM_SUCCESS;
    }
    switch (offset) {
        case OFFSET_0:
            *value = (*value & 0x7F); /* 01111111 */
            break;
        case OFFSET_1:
            *value = (*value & 0xBF); /* 10111111 */
            break;
        case OFFSET_2:
            *value = (*value & 0xDF); /* 11011111 */
            break;
        case OFFSET_3:
            *value = (*value & 0xEF); /* 11101111 */
            break;
        case OFFSET_4:
            *value = (*value & 0xF7); /* 11110111 */
            break;
        case OFFSET_5:
            *value = (*value & 0xFB); /* 11111011 */
            break;
        case OFFSET_6:
            *value = (*value & 0xFD); /* 11111101 */
            break;
        case OFFSET_7:
            *value = (*value & 0xFE); /* 11111110 */
            break;
        default:
            ret = CM_ERROR;
            break;
    }
    write_runlog(DEBUG1, "DeleteUpdateOffsetFlag: get value %u with offset %u\n", (uint32)(*value), offset);
    return ret;
}

static uint8 GetOffsetUsedFlag(uint8 value, uint32 offset)
{
    uint8 ret = CM_FALSE;
    if (value == 0 || offset >= BIT_NUM) {
        return CM_FALSE;
    }
    switch (offset) {
        case OFFSET_0:
            value = (value & 0x80); /* 10000000 */
            break;
        case OFFSET_1:
            value = (value & 0x40); /* 01000000 */
            break;
        case OFFSET_2:
            value = (value & 0x20); /* 00100000 */
            break;
        case OFFSET_3:
            value = (value & 0x10); /* 00010000 */
            break;
        case OFFSET_4:
            value = (value & 0x08); /* 00001000 */
            break;
        case OFFSET_5:
            value = (value & 0x04); /* 00000100 */
            break;
        case OFFSET_6:
            value = (value & 0x02); /* 00000010 */
            break;
        case OFFSET_7:
            value = (value & 0x01); /* 00000001 */
            break;
        default:
            ret = CM_FALSE;
            break;
    }

    if (value > 0) {
        ret = CM_TRUE;
    }
    return ret;
}

status_t ReadDiskDataLine(const char *key, char *buff, uint32 bufLen, uint32 bitMap)
{
    write_runlog(DEBUG1, "ReadDiskDataLine: begin to get data with key:%s\n", key);
    if (bitMap >= MAX_BIT_LENGTH) {
        write_runlog(ERROR, "ReadDiskDataLine: get data with key %s failed for bitMap %u is invalid.\n", key, bitMap);
        return CM_ERROR;
    }
    if (CheckKey(bitMap, key) != CM_SUCCESS) {
        write_runlog(ERROR, "ReadDiskDataLine: get data with key %s bitMap %u failed.\n", key, bitMap);
        return CM_ERROR;
    }
    CM_RETURN_IFERR(ReadDiskDataArea(bitMap, key, buff, bufLen));
    return CM_SUCCESS;
}

status_t UpdateDiskDataLine(
    const char *key, const char *data, uint32 dataLen, uint32 bitMap, const update_option *option)
{
    write_runlog(DEBUG1, "UpdateDiskDataLine: begin to update key  %s to value %s\n", key, data);
    if (bitMap >= MAX_BIT_LENGTH || dataLen > MAX_VALUE_LENGTH) {
        write_runlog(ERROR,
            "UpdateDiskDataLine: update key %s to value %s failed for bitMap %u or datalen %u is invalid.\n",
            key,
            data,
            bitMap,
            dataLen);
        return CM_ERROR;
    }

    if (CheckKey(bitMap, key) != CM_SUCCESS) {
        write_runlog(ERROR,
            "UpdateDiskDataLine: update key %s to value %s failed, please check bitMap %u data on disk.\n",
            key,
            data,
            bitMap);
        return CM_ERROR;
    }

    if (option != NULL && option->preValue != NULL) {
        char buff[MAX_VALUE_LENGTH] = {0};
        CM_RETURN_IFERR(ReadDiskDataArea(bitMap, key, buff, MAX_VALUE_LENGTH));
        if (strcmp(buff, option->preValue) != 0) {
            write_runlog(ERROR,
                "UpdateDiskDataLine: update key %s to value %s failed,get data buff %s with bitMap %u is not equal "
                "preValue %s.\n",
                key,
                data,
                buff,
                bitMap,
                option->preValue);
            return CM_ERROR;
        }
    }

    status_t status = UpdateDiskDataArea(bitMap, data, dataLen, UPDATE_DATA);
    return status;
}

status_t GetDiskHeaderVersion(uint32 *version)
{
    char byteValue[MAX_BYTE_LENGTH + 1] = {0};

    uint64 offset = DISK_PAGE_LOCK_OFFSET;
    write_runlog(DEBUG1, "GetDiskHeaderVersion: current header version %u\n", g_sdCacheList.cacheHeaderList->version);

    (void)pthread_rwlock_wrlock(&(g_sdRwLock));
    g_sdLrwHandler.offset = g_sdBaseOffset + offset;
    if (ShareDiskRead(&g_sdLrwHandler, byteValue, MAX_BYTE_LENGTH) != CM_SUCCESS) {
        (void)pthread_rwlock_unlock(&(g_sdRwLock));
        write_runlog(ERROR, "GetDiskHeaderVersion: get disk header version failed!\n");
        return CM_ERROR;
    }
    (void)pthread_rwlock_unlock(&(g_sdRwLock));
    *version = *(uint32 *)byteValue;
    return CM_SUCCESS;
}

status_t CheckHeaderVersion()
{
    uint32 version;
    uint32 diskVersion;
    
    (void)pthread_rwlock_wrlock(&(g_sdCacheList.lk_lock));
    if (GetDiskHeaderVersion(&diskVersion) != CM_SUCCESS) {
        (void)pthread_rwlock_unlock(&(g_sdCacheList.lk_lock));
        return CM_ERROR;
    }

    version = g_sdCacheList.cacheHeaderList->version;
    (void)pthread_rwlock_unlock(&(g_sdCacheList.lk_lock));

    if (diskVersion != version) {
        write_runlog(LOG,
            "CheckHeaderVersion: get disk header version %u is not equal memory version %u\n",
            diskVersion,
            version);
        CM_RETURN_IFERR(ReloadAllDataFromDisk());
    }
    return CM_SUCCESS;
}

status_t CheckKey(uint32 bitMap, const char *key)
{
    char buffer[MAX_KEY_LENGTH + 1] = {0};
    uint64 offset = DISK_DATA_PAGE_OFFSET + bitMap * KEY_VALUE_LENGTH;

    write_runlog(DEBUG1, "CheckKey: begin to check key %s on disk.\n", key);
    (void)pthread_rwlock_wrlock(&(g_sdRwLock));
    g_sdLrwHandler.offset = g_sdBaseOffset + offset;
    status_t ret = ShareDiskRead(&g_sdLrwHandler, buffer, MAX_KEY_LENGTH);
    (void)pthread_rwlock_unlock(&(g_sdRwLock));
    if (ret != CM_SUCCESS) {
        write_runlog(ERROR, "CheckKey: read disk data with bitMap %u failed, key %s.\n", bitMap, key);
        return CM_ERROR;
    }
    if (strcmp(buffer, key) != 0) {
        write_runlog(ERROR, "CheckKey: strcmp error buffer %s, key %s.\n", buffer, key);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t AllocDiskHeaderFlag(const char *key, uint32 *bitMap)
{
    uint32 ind;

    write_runlog(DEBUG1, "AllocDiskHeaderFlag: begin to alloc header flag for key: %s.\n", key);
    for (ind = 0; ind < BITMAP_BYTE_LENGTH; ind++) {
        if (g_sdCacheList.cacheHeaderList->bitMapArray[ind] == MAX_BYTE_VALUE) {
            continue;
        }
        break;
    }
    if (ind == BITMAP_BYTE_LENGTH) {
        return CM_ERROR;
    }
    if (ind > g_sdCacheList.cacheHeaderList->maxBitMap) {
        g_sdCacheList.cacheHeaderList->maxBitMap = ind;
    }

    uint8 *value = &g_sdCacheList.cacheHeaderList->bitMapArray[ind];
    uint32 offset = GetAvailableFlagOffset(value);
    write_runlog(DEBUG1,
        "AllocDiskHeaderFlag: get bitMap index: %u, maxBitMap %u, value %u\n",
        ind,
        g_sdCacheList.cacheHeaderList->maxBitMap,
        (uint32)(*value));

    if (AddUpdateOffsetFlag(value, offset) != CM_SUCCESS) {
        write_runlog(ERROR,
            "AllocDiskHeaderFlag: update offset flag failed with key %s, value %u, offset:%u.\n",
            key,
            (uint32)(*value),
            offset);
        return CM_ERROR;
    }

    *bitMap = BIT_NUM * ind + offset;
    return CM_SUCCESS;
}

void MinusMaxBitMap(uint32 ind)
{
    if (ind != g_sdCacheList.cacheHeaderList->maxBitMap) {
        return;
    }

    while (g_sdCacheList.cacheHeaderList->maxBitMap > 0) {
        uint32 maxBitMapInd = g_sdCacheList.cacheHeaderList->maxBitMap;
        uint8 value = g_sdCacheList.cacheHeaderList->bitMapArray[maxBitMapInd];
        if (value != 0) {
            break;
        }

        --g_sdCacheList.cacheHeaderList->maxBitMap;
        write_runlog(DEBUG1, "MinusMaxBitMap: now max bitMap is %u.\n", g_sdCacheList.cacheHeaderList->maxBitMap);
    }
}

status_t DeleteDiskDataLine(const char *key, uint32 bitMap)
{
    if (bitMap >= MAX_BIT_LENGTH) {
        return CM_ERROR;
    }

    uint32 ind = bitMap / BIT_NUM;
    uint32 offset = bitMap % BIT_NUM;
    write_runlog(DEBUG1, "DeleteDiskDataLine: begin delete data with key %s, bitMap %u.\n", key, bitMap);
    uint8 *value = &g_sdCacheList.cacheHeaderList->bitMapArray[ind];
    if (DeleteUpdateOffsetFlag(value, offset) != CM_SUCCESS) {
        write_runlog(ERROR,
            "DeleteDiskDataLine: update offset flag failed key %s, bitMap %u, value %u, offset %u.\n",
            key,
            bitMap,
            (uint32)(*value),
            offset);
        return CM_ERROR;
    }
    MinusMaxBitMap(ind);
    return CM_SUCCESS;
}


uint32 GetBitMapOffset(uint32 bitMapInd)
{
    // bitMapInd / 512 * 512
    return (bitMapInd >> DISK_WRITE_512BYTES_MOVE) << DISK_WRITE_512BYTES_MOVE;
}

status_t UpdateDiskBitMapArea(uint32 bitMap)
{
    uint32 bitMapInd = bitMap / BIT_NUM;
    uint32 bitMapOffset = GetBitMapOffset(bitMapInd);
    uint32 offset = DISK_BITMAP_OFFSET + bitMapOffset;
    g_sdLrwHandler.offset = g_sdBaseOffset + offset;
    // only write 512 bytes which bitMap has been changed
    errno_t rc = memcpy_s(g_sdLrwHandler.rwBuff,
        BITMAP_BYTE_LENGTH,
        (const char *)(g_sdCacheList.cacheHeaderList->bitMapArray + bitMapOffset),
        DISK_WRITE_512BYTES);
    securec_check_errno(rc, (void)pthread_rwlock_unlock(&(g_sdRwLock)));
    if (ShareDiskWrite(&g_sdLrwHandler,
        g_sdLrwHandler.rwBuff,
        DISK_WRITE_512BYTES) != CM_SUCCESS) {
        write_runlog(ERROR,
            "UpdateDiskBitMapArea: write bitMap to disk failed,bitMapInd %u bitMapOffset %u.\n",
            bitMapInd,
            bitMapOffset);
        return CM_ERROR;
    }
    write_runlog(DEBUG1, "UpdateDiskBitMapArea: bitMapInd %u bitMapOffset %u.\n", bitMapInd, bitMapOffset);
    return CM_SUCCESS;
}

status_t UpdateDiskHeaderArea(uint32 bitMap)
{
    uint32 offset = DISK_PAGE_LOCK_OFFSET;
    ++g_sdCacheList.cacheHeaderList->version;
    (void)pthread_rwlock_wrlock(&(g_sdRwLock));
    g_sdLrwHandler.offset = g_sdBaseOffset + offset;
    errno_t rc = memcpy_s(g_sdLrwHandler.rwBuff,
        BITMAP_BYTE_LENGTH,
        (const char *)&g_sdCacheList.cacheHeaderList->version,
        MAX_BYTE_LENGTH);
    securec_check_errno(rc, (void)pthread_rwlock_unlock(&(g_sdRwLock)));
    if (ShareDiskWrite(&g_sdLrwHandler, g_sdLrwHandler.rwBuff, MAX_BYTE_LENGTH) != CM_SUCCESS) {
        (void)pthread_rwlock_unlock(&(g_sdRwLock));
        write_runlog(ERROR,
            "UpdateDiskHeaderArea: update header data failed, version %u,maxBitMap %u\n",
            g_sdCacheList.cacheHeaderList->version,
            g_sdCacheList.cacheHeaderList->maxBitMap);
        return CM_ERROR;
    }
    CM_RETURN_IFERR_EX(UpdateDiskBitMapArea(bitMap), (void)pthread_rwlock_unlock(&(g_sdRwLock)));
    (void)pthread_rwlock_unlock(&(g_sdRwLock));
    write_runlog(DEBUG1, "UpdateDiskHeaderArea: update header and bitMap data success.\n");
    return CM_SUCCESS;
}

status_t WriteDiskData(const char *key, uint32 keyLen, const char *data, uint32 dataLen, uint32 bitMap)
{
    if (UpdateDiskDataArea(bitMap, key, keyLen, UPDATE_KEY) != CM_SUCCESS) {
        CM_SET_DISKRW_ERROR(ERR_DISKRW_WRITE_KEY, key);
        return CM_ERROR;
    }
    if (UpdateDiskDataArea(bitMap, data, dataLen, UPDATE_DATA) != CM_SUCCESS) {
        CM_SET_DISKRW_ERROR(ERR_DISKRW_UPDATE_DATA, key, data);
        return CM_ERROR;
    }

    if (UpdateDiskHeaderArea(bitMap) != CM_SUCCESS) {
        CM_SET_DISKRW_ERROR(ERR_DISKRW_UPDATE_HEADER, key);
        return CM_ERROR;
    }

    write_runlog(DEBUG1, "WriteDiskData: update header and bitMap data success.\n");
    return CM_SUCCESS;
}

status_t UpdateDiskDataArea(uint32 bitMap, const char *data, uint32 dataLen, DATA_TYPE type)
{
    uint64 offset = 0;
    uint32 keyOrValueLen = (type == UPDATE_KEY) ? MAX_KEY_LENGTH : MAX_VALUE_LENGTH;
    if (dataLen > keyOrValueLen) {
        write_runlog(ERROR, "UpdateDiskDataArea: data len %u is too long, data type %u.\n", dataLen, (uint32)type);
        return CM_ERROR;
    }
    if (type == UPDATE_KEY) {
        offset = DISK_DATA_PAGE_OFFSET + bitMap * KEY_VALUE_LENGTH;
    } else {
        offset = DISK_DATA_PAGE_OFFSET + bitMap * KEY_VALUE_LENGTH + MAX_KEY_LENGTH;
    }

    write_runlog(DEBUG1, "UpdateDiskDataArea: begin to update data %s, bitMap:%u.\n", data, bitMap);
    (void)pthread_rwlock_wrlock(&(g_sdRwLock));
    g_sdLrwHandler.offset = g_sdBaseOffset + offset;
    errno_t rc = memcpy_s(g_sdLrwHandler.rwBuff, BITMAP_BYTE_LENGTH, data, dataLen);
    securec_check_errno(rc, (void)pthread_rwlock_unlock(&(g_sdRwLock)));
    *(g_sdLrwHandler.rwBuff + dataLen) = 0;
    if (ShareDiskWrite(&g_sdLrwHandler, g_sdLrwHandler.rwBuff, keyOrValueLen) != CM_SUCCESS) {
        (void)pthread_rwlock_unlock(&(g_sdRwLock));
        write_runlog(ERROR, "UpdateDiskDataArea: update data %s bitMap %u to disk failed.\n", data, bitMap);
        return CM_ERROR;
    }
    (void)pthread_rwlock_unlock(&(g_sdRwLock));
    write_runlog(DEBUG1, "UpdateDiskDataArea: update data %s, bitMap %u to disk succ.\n", data, bitMap);
    return CM_SUCCESS;
}

status_t ReadDiskKeyArea(uint32 bitMap, char *key, uint32 keyLen)
{
    uint64 offset = DISK_DATA_PAGE_OFFSET + bitMap * KEY_VALUE_LENGTH;
    write_runlog(DEBUG1, "ReadDiskKeyArea: begin to get key with bitMap %u.\n", bitMap);
    (void)pthread_rwlock_wrlock(&(g_sdRwLock));
    g_sdLrwHandler.offset = g_sdBaseOffset + offset;
    if (ShareDiskRead(&g_sdLrwHandler, key, keyLen) != CM_SUCCESS) {
        (void)pthread_rwlock_unlock(&(g_sdRwLock));
        write_runlog(ERROR, "ReadDiskKeyArea: get key %s with bitMap %u failed.\n", key, bitMap);
        return CM_ERROR;
    }
    (void)pthread_rwlock_unlock(&(g_sdRwLock));
    write_runlog(DEBUG1, "ReadDiskKeyArea: get key %s with bitMap %u success.\n", key, bitMap);
    return CM_SUCCESS;
}

status_t ReadDiskDataArea(uint32 bitMap, const char *key, char *data, uint32 dataLen)
{
    uint64 offset = DISK_DATA_PAGE_OFFSET + bitMap * KEY_VALUE_LENGTH + MAX_KEY_LENGTH;
    write_runlog(DEBUG1, "ReadDiskDataArea: begin to get data with key %s bitMap:%u.\n", key, bitMap);
    (void)pthread_rwlock_wrlock(&(g_sdRwLock));
    g_sdLrwHandler.offset = g_sdBaseOffset + offset;
    if (ShareDiskRead(&g_sdLrwHandler, data, dataLen) != CM_SUCCESS) {
        (void)pthread_rwlock_unlock(&(g_sdRwLock));
        write_runlog(ERROR, "ReadDiskDataArea: get data with key %s bitMap:%u failed.\n", key, bitMap);
        return CM_ERROR;
    }

    (void)pthread_rwlock_unlock(&(g_sdRwLock));
    write_runlog(DEBUG1, "ReadDiskDataArea: get data %s with key %s bitMap:%u success.\n", data, key, bitMap);
    return CM_SUCCESS;
}

void DeleteNodeFromList(const char *key)
{
    (void)g_sdCacheList.sdCacheMap.erase(key);
    write_runlog(DEBUG1, "DeleteNodeFromList succ, key %s.\n", key);
}

uint8 FindCache(const char *key, uint32 *findBitMap)
{
    map<string, uint32>::iterator ptr = g_sdCacheList.sdCacheMap.find(key);
    if (ptr != g_sdCacheList.sdCacheMap.end()) {
        if (findBitMap != NULL) {
            *findBitMap = (*ptr).second;
        }
        return CM_TRUE;
    }
    return CM_FALSE;
}

status_t FindCacheByMultiLevel(const char *key, char *buff, uint32 buffLen)
{
    uint32 bitMap = 0;
    uint32 offset = 0;
    errno_t rc = 0;

    write_runlog(DEBUG1, "FindCacheByMultiLevel: try to get all value of key %s.\n", key);
    (void)pthread_rwlock_wrlock(&(g_sdCacheList.lk_lock));
    map<string, uint32>::iterator mapIter = g_sdCacheList.sdCacheMap.begin();
    while (mapIter != g_sdCacheList.sdCacheMap.end() && (buffLen - offset) > MAX_VALUE_LENGTH) {
        if (strncmp((*mapIter).first.c_str(), key, strlen(key)) == 0) {
            bitMap = (*mapIter).second;
            size_t tmpLength = buffLen - offset;
            rc = snprintf_s(buff + offset, tmpLength, tmpLength - 1, "%s,", (*mapIter).first.c_str());
            if (rc < 0) {
                write_runlog(WARNING,
                    "FindCacheByMultiLevel: get all value of key %s failed for buffLen %u offset %u.\n",
                    (*mapIter).first.c_str(),
                    buffLen,
                    offset);
                (void)pthread_rwlock_unlock(&g_sdCacheList.lk_lock);
                CM_SET_DISKRW_ERROR(ERR_SYSTEM_CALL, rc);
                return CM_ERROR;
            }
            offset += (uint32)(strlen((*mapIter).first.c_str()) + 1);
            if (ReadDiskDataLine((*mapIter).first.c_str(), buff + offset, MAX_VALUE_LENGTH, bitMap) != CM_SUCCESS) {
                (void)pthread_rwlock_unlock(&g_sdCacheList.lk_lock);
                CM_SET_DISKRW_ERROR(ERR_DISKRW_GET_DATA, (*mapIter).first.c_str());
                return CM_ERROR;
            }
            offset += (uint32)strlen(buff + offset);
            tmpLength = buffLen - offset;
            rc = strcat_s(buff + offset, tmpLength, ",");
            if (rc != 0) {
                (void)pthread_rwlock_unlock(&g_sdCacheList.lk_lock);
                write_runlog(WARNING,
                    "FindCacheByMultiLevel: get all value of key %s failed for offset %u buffLen %u.\n",
                    key,
                    offset,
                    buffLen);
                CM_SET_DISKRW_ERROR(ERR_SYSTEM_CALL, rc);
                return CM_ERROR;
            }
            offset += 1;
        }
        ++mapIter;
    }

    (void)pthread_rwlock_unlock(&g_sdCacheList.lk_lock);

    if (offset == 0) {
        write_runlog(DEBUG1, "FindCacheByMultiLevel: can't find key %s or buffLen %u is invalid.\n",
            key,
            buffLen);
        CM_SET_DISKRW_ERROR(ERR_DISKRW_KEY_NOTFOUND, key);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t DiskCacheWrite(const char *key, uint32 keyLen, const char *data, uint32 dataLen, const update_option *option)
{
    uint32 bitMap = 0;

    write_runlog(DEBUG1, "DiskCacheWrite: begin to write key %s value %s to disk.\n", key, data);
    CM_RETURN_IFERR_EX(CheckHeaderVersion(), CM_SET_DISKRW_ERROR(ERR_DISKRW_CHECK_HEADER, key));
    (void)pthread_rwlock_wrlock(&(g_sdCacheList.lk_lock));
    if (FindCache(key, &bitMap) == CM_TRUE) {
        (void)pthread_rwlock_unlock(&g_sdCacheList.lk_lock);
        CM_RETURN_IFERR_EX(UpdateDiskDataLine(key, data, dataLen, bitMap, option),
            CM_SET_DISKRW_ERROR(ERR_DISKRW_UPDATE_DATA, key, data));
        return CM_SUCCESS;
    }

    if (option != NULL && option->preValue != NULL) {
        (void)pthread_rwlock_unlock(&g_sdCacheList.lk_lock);
        write_runlog(ERROR,
            "DiskCacheWrite: write key %s value %s preValue %s to disk failed for key not found.\n",
            key,
            data,
            option->preValue);
        CM_SET_DISKRW_ERROR(ERR_DISKRW_KEY_NOTFOUND, key);
        return CM_ERROR;
    }

    if (AllocDiskHeaderFlag(key, &bitMap) != CM_SUCCESS) {
        (void)pthread_rwlock_unlock(&(g_sdCacheList.lk_lock));
        write_runlog(
            ERROR, "DiskCacheWrite: write key %s value %s to disk failed when alloc disk head flag.\n", key, data);
        CM_SET_DISKRW_ERROR(ERR_DISKRW_DISK_HEAD_FULL, key, data);
        return CM_ERROR;
    }

    if (WriteDiskData(key, keyLen, data, dataLen, bitMap) != CM_SUCCESS) {
        (void)pthread_rwlock_unlock(&(g_sdCacheList.lk_lock));
        write_runlog(ERROR,
            "DiskCacheWrite: write key %s value %s bitMap %u to disk failed.\n",
            key,
            data,
            bitMap);
        return CM_ERROR;
    }
    if (InsertCache(key, bitMap) != CM_SUCCESS) {
        (void)pthread_rwlock_unlock(&(g_sdCacheList.lk_lock));
        CM_SET_DISKRW_ERROR(ERR_DISKRW_INSERT_KEY, key);
        write_runlog(ERROR, "DiskCacheWrite: write key %s value %s to disk failed when insert cache.\n", key, data);
        return CM_ERROR;
    }
    (void)pthread_rwlock_unlock(&(g_sdCacheList.lk_lock));

    return CM_SUCCESS;
}

status_t DiskCacheRead(const char *key, char *buff, uint32 buffLen)
{
    uint32 bitMap = 0;

    char dataBuffer[MAX_VALUE_LENGTH] = {0};
    write_runlog(DEBUG1, "DiskCacheRead: begin to get value of key %s.\n", key);
    CM_RETURN_IFERR_EX(CheckHeaderVersion(), CM_SET_DISKRW_ERROR(ERR_DISKRW_CHECK_HEADER, key));
    (void)pthread_rwlock_wrlock(&(g_sdCacheList.lk_lock));
    if (FindCache(key, &bitMap) != CM_TRUE) {
        (void)pthread_rwlock_unlock(&g_sdCacheList.lk_lock);
        write_runlog(DEBUG1, "DiskCacheRead: can't find key %s.\n", key);
        CM_SET_DISKRW_ERROR(ERR_DISKRW_KEY_NOTFOUND, key);
        return CM_ERROR;
    }

    (void)pthread_rwlock_unlock(&g_sdCacheList.lk_lock);
    CM_RETURN_IFERR_EX(
        ReadDiskDataLine(key, dataBuffer, MAX_VALUE_LENGTH, bitMap), CM_SET_DISKRW_ERROR(ERR_DISKRW_GET_DATA, key));

    size_t dataBufferLen = strlen(dataBuffer);
    if (dataBufferLen > buffLen) {
        write_runlog(ERROR,
            "DiskCacheRead: input buffer len %u is short than disk data buffer len %lu.\n",
            buffLen,
            dataBufferLen);
        CM_SET_DISKRW_ERROR(ERR_SYSTEM_CALL, dataBufferLen);
        return CM_ERROR;
    }

    int32 ret = strncpy_s(buff, buffLen, dataBuffer, dataBufferLen);
    if (ret != 0) {
        write_runlog(ERROR,
            "DiskCacheRead: copy data buffer %s to buff failed, buffer len %u dataBufferLen %lu.\n",
            dataBuffer,
            buffLen,
            dataBufferLen);
        CM_SET_DISKRW_ERROR(ERR_SYSTEM_CALL, ret);
        return CM_ERROR;
    }
    write_runlog(DEBUG1, "DiskCacheRead: success to get value of key %s.\n", key);
    return CM_SUCCESS;
}

status_t DiskCacheRead(const char *key, char *buff, uint32 buffLen, bool isMultiLevel)
{
    write_runlog(DEBUG1, "DiskCacheRead: begin to get value of key %s.\n", key);
    if (!isMultiLevel) {
        return DiskCacheRead(key, buff, buffLen);
    }

    CM_RETURN_IFERR_EX(CheckHeaderVersion(), CM_SET_DISKRW_ERROR(ERR_DISKRW_CHECK_HEADER, key));
    CM_RETURN_IFERR(FindCacheByMultiLevel(key, buff, buffLen));

    write_runlog(DEBUG1, "DiskCacheRead: success to get all value of key %s\n", key);
    return CM_SUCCESS;
}

status_t DiskCacheUpdate(const char *key, const char *data, uint32 dataLen, const update_option *option)
{
    uint32 bitMap = 0;
    write_runlog(DEBUG1, "DiskCacheUpdate: begin to update key %s with value %s.\n", key, data);
    CM_RETURN_IFERR_EX(CheckHeaderVersion(), CM_SET_DISKRW_ERROR(ERR_DISKRW_CHECK_HEADER, key));
    (void)pthread_rwlock_wrlock(&(g_sdCacheList.lk_lock));
    if (FindCache(key, &bitMap) != CM_TRUE) {
        (void)pthread_rwlock_unlock(&(g_sdCacheList.lk_lock));
        write_runlog(ERROR, "DiskCacheUpdate: can't find key %s.\n", key);
        CM_SET_DISKRW_ERROR(ERR_DISKRW_KEY_NOTFOUND, key);
        return CM_ERROR;
    }

    (void)pthread_rwlock_unlock(&g_sdCacheList.lk_lock);
    CM_RETURN_IFERR_EX(
        UpdateDiskDataLine(key, data, dataLen, bitMap, option), CM_SET_DISKRW_ERROR(ERR_DISKRW_UPDATE_DATA, key, data));
    write_runlog(DEBUG1, "DiskCacheUpdate: success to update key %s with value %s.\n", key, data);
    return CM_SUCCESS;
}

status_t DiskCacheDelete(const char *key)
{
    uint32 bitMap = 0;

    write_runlog(DEBUG1, "DiskCacheDelete: begin to delete key %s.\n", key);
    CM_RETURN_IFERR_EX(CheckHeaderVersion(), CM_SET_DISKRW_ERROR(ERR_DISKRW_CHECK_HEADER, key));
    (void)pthread_rwlock_wrlock(&(g_sdCacheList.lk_lock));
    if (FindCache(key, &bitMap) != CM_TRUE) {
        (void)pthread_rwlock_unlock(&g_sdCacheList.lk_lock);
        CM_SET_DISKRW_ERROR(ERR_DISKRW_KEY_NOTFOUND, key);
        write_runlog(ERROR, "DiskCacheDelete: can't find key %s.\n", key);
        return CM_ERROR;
    }

    if (DeleteDiskDataLine(key, bitMap) != CM_SUCCESS) {
        (void)pthread_rwlock_unlock(&g_sdCacheList.lk_lock);
        CM_SET_DISKRW_ERROR(ERR_DISKRW_DELETE_DATA, key);
        write_runlog(ERROR, "DiskCacheDelete: delete key %s bitMap %u failed when delete disk data.\n", key, bitMap);
        return CM_ERROR;
    }

    if (UpdateDiskHeaderArea(bitMap) != CM_SUCCESS) {
        (void)pthread_rwlock_unlock(&g_sdCacheList.lk_lock);
        CM_SET_DISKRW_ERROR(ERR_DISKRW_UPDATE_HEADER, key);
        write_runlog(ERROR, "DiskCacheDelete: delete key %s bitMap %u failed when update header area.\n", key, bitMap);
        return CM_ERROR;
    }
    DeleteNodeFromList(key);
    (void)pthread_rwlock_unlock(&g_sdCacheList.lk_lock);
    write_runlog(DEBUG1, "DiskCacheDelete: succ to delete key %s.\n", key);
    return CM_SUCCESS;
}

status_t DiskCacheDeletePrefix(const char *key)
{
    uint32 bitMap = 0;
    bool hasFoundKey = false;
    write_runlog(DEBUG1, "DiskCacheDeletePrefix: begin to delete key %s.\n", key);
    CM_RETURN_IFERR_EX(CheckHeaderVersion(), CM_SET_DISKRW_ERROR(ERR_DISKRW_CHECK_HEADER, key));
    (void)pthread_rwlock_wrlock(&(g_sdCacheList.lk_lock));
    map<string, uint32>::iterator mapIter = g_sdCacheList.sdCacheMap.begin();
    while (mapIter != g_sdCacheList.sdCacheMap.end()) {
        const char *tmpKey = (*mapIter).first.c_str();
        if (strncmp(tmpKey, key, strlen(key)) == 0) {
            hasFoundKey = true;
            bitMap = (*mapIter).second;
            if (DeleteDiskDataLine(tmpKey, bitMap) != CM_SUCCESS) {
                (void)pthread_rwlock_unlock(&g_sdCacheList.lk_lock);
                CM_SET_DISKRW_ERROR(ERR_DISKRW_DELETE_DATA, key);
                write_runlog(ERROR,
                    "DiskCacheDeletePrefix: delete key %s bitMap %u failed when delete disk data.\n",
                    tmpKey,
                    bitMap);
                return CM_ERROR;
            }

            if (UpdateDiskHeaderArea(bitMap) != CM_SUCCESS) {
                (void)pthread_rwlock_unlock(&g_sdCacheList.lk_lock);
                CM_SET_DISKRW_ERROR(ERR_DISKRW_UPDATE_HEADER, key);
                write_runlog(ERROR,
                    "DiskCacheDeletePrefix: delete key %s bitMap %u failed when update header area.\n",
                    tmpKey,
                    bitMap);
                return CM_ERROR;
            }
            (void)g_sdCacheList.sdCacheMap.erase(mapIter++);
        } else {
            ++mapIter;
        }
    }

    (void)pthread_rwlock_unlock(&g_sdCacheList.lk_lock);

    if (!hasFoundKey) {
        write_runlog(WARNING, "DiskCacheDeletePrefix: can't find key %s.\n", key);
        CM_SET_DISKRW_ERROR(ERR_DISKRW_KEY_NOTFOUND, key);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}
