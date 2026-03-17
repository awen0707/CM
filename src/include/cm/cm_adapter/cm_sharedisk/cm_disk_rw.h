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
 * share_disk_api.cpp
 *
 * IDENTIFICATION
 *    src/cm_adapter/cm_sharedisk/cm_disk_rw.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CM_DISK_RW_H
#define CM_DISK_RW_H

#include <sys/shm.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <iostream>
#include <map>
#include <string>
#include "c.h"
#include "share_disk_api.h"
#include "cm_error.h"

#define OFFSET_0 (0)
#define OFFSET_1 (1)
#define OFFSET_2 (2)
#define OFFSET_3 (3)
#define OFFSET_4 (4)
#define OFFSET_5 (5)
#define OFFSET_6 (6)
#define OFFSET_7 (7)
#define OFFSET_8 (8)

// Header List
typedef struct BYTE_NODE_T {
    uint32 version;
    uint32 maxBitMap;
    uint8 reservedHeader[MAX_BYTE_LENGTH - VERSION_LENGTH - BITMAP_LENGTH];
    uint8 *bitMapArray; // array with BITMAP_BYTE_LENGTH length, memory is alloced
} ByteNode_t;

typedef struct _CACHE_AREA_LIST_ {
    pthread_rwlock_t lk_lock;
    std::map<std::string, uint32> sdCacheMap;
    ByteNode_t *cacheHeaderList;
} cache_area_list;

typedef enum { UPDATE_KEY = 1, UPDATE_DATA = 2 } DATA_TYPE;

typedef struct _UPDATE_OPTION_ {
    char *preValue;
    uint32 len;
} update_option;

status_t DiskCacheDelete(const char *key);
status_t DiskCacheDeletePrefix(const char *key);
status_t DiskCacheUpdate(const char *key, const char *data, uint32 dataLen, const update_option *option = NULL);
status_t DiskCacheRead(const char *key, char *buff, uint32 buffLen);
status_t DiskCacheWrite(const char *key, uint32 keyLen, const char *data, uint32 dataLen, const update_option *option);
status_t DiskCacheRead(const char *key, char *buff, uint32 buffLen, bool isMultiLevel);
status_t InitDiskData(const char *scsi_dev, uint32 offset, int64 instId);
#endif
