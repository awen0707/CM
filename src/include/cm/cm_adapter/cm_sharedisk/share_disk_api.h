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
 *    src/cm_adapter/cm_sharedisk/share_disk_api.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef SHARE_DISK_API_H
#define SHARE_DISK_API_H

#include "cm_defs.h"
#include "c.h"
#define MAX_PATH_LENGTH (1024)

#ifndef NULL
#define NULL ((void *)0)
#endif

#ifndef O_DIRECT
#define O_DIRECT 0
#endif

#define VERSION_LENGTH (4)
#define BITMAP_LENGTH (4)
#define BIT_NUM (8)
#define MAX_BYTE_VALUE (255)
#define MAX_BYTE_LENGTH (512)
#define MAX_KEY_LENGTH (1024)
#define MAX_VALUE_LENGTH (2048)
#define KEY_VALUE_LENGTH (MAX_KEY_LENGTH + MAX_VALUE_LENGTH)
#define BITMAP_BYTE_LENGTH (10 * 1024 * 1024)
#define MAX_BIT_LENGTH (BITMAP_BYTE_LENGTH * BIT_NUM)
#define RESERVED_BITMAP_LENGTH (10 * 1024 * 1024)

// lock for cmserver arbitrate primary
#define DISK_ARBITRATE_LOCK_SPACE (512)
#define DISK_PAGE_LOCK_OFFSET (512)
#define DISK_HEADER_PAGE_OFFSET (512)
#define DISK_BITMAP_OFFSET (DISK_PAGE_LOCK_OFFSET + DISK_HEADER_PAGE_OFFSET)
#define DISK_DATA_PAGE_OFFSET (DISK_BITMAP_OFFSET + BITMAP_BYTE_LENGTH + RESERVED_BITMAP_LENGTH)
#define DISK_DATA_VALUE_OFFSET (1024)
#define DISK_DATA_RECORED_LENGTH (2048)
#define DISK_WRITE_512BYTES_MOVE (9)
#define DISK_WRITE_512BYTES (512)
#define DISK_RESERVED_LEN_AFTER_CMSLOCK (128 * 1024 * 1024)

typedef struct _DISK_LRW_HANDLER {
    char scsiDev[MAX_PATH_LENGTH];
    int64 instId;
    uint64 offset;
    char *rwBuff;
    int fd;
} diskLrwHandler;

status_t ShareDiskRead(diskLrwHandler *handler, char *data, uint32 dataLen);
status_t ShareDiskWrite(diskLrwHandler *handler, const char *data, uint32 dataLen);
#endif