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
 * cm_ddb_sharedisk_disklock.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_adapter/cm_sharedisk/cm_ddb_sharedisk_disklock.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CM_DISKLOCK_H
#define CM_DISKLOCK_H

#include "c.h"
typedef unsigned char uchar;
typedef unsigned int bool32;

typedef enum {
    DISK_LOCK_MGR_NORMAL = 0,
    DISK_LOCK_MGR_DORADO = 1
} SharediskLockType;

typedef struct DiskLockInfo {
    const char* path;
    int64 owner_id;
    int64 inst_id;
    time_t lock_time;
    int lock_result;
} disk_lock_info_t;

extern SharediskLockType g_shareDiskLockType;
void initializeDiskLockManager();
int cm_init_disklock(const char *scsi_dev, uint64 lock_addr, int64 inst_id);
disk_lock_info_t cm_lock_disklock();
int cm_unlock_disklock();
int cm_lockf_disklock();
void cm_destroy_disklock();

#endif
