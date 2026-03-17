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
 * cm_ddb_sharedisk_disklock.cpp
 *
 * IDENTIFICATION
 *    src/cm_adapter/cm_sharedisk_adapter/cm_ddb_sharedisk_disklock.cpp
 *
 * -------------------------------------------------------------------------
 */

#include "cm_ddb_sharedisk_disklock.h"
#include "cm_dlock.h"
#include "cm_disklock.h"
#include <time.h>
#include <unistd.h>
#include <memory>

#define MAX_EXIT_STATUS 128
#define MAX_RETRIES 3
#define RETRY_DELAY_MS 1000

// Global variables
SharediskLockType g_shareDiskLockType = DISK_LOCK_MGR_NORMAL;
disk_lock_info_t g_disk_lock_info = {0};

// Abstract base class for disk lock managers
class DiskLockManager {
public:
    virtual ~DiskLockManager() = default;

    virtual int initDiskLock(const char *path, uint64 lock_addr, int64 inst_id) = 0;
    virtual disk_lock_info_t lockDiskLock() = 0;
    virtual int lockfDiskLock() = 0;
    virtual int unlockDiskLock() = 0;
    virtual void destroyDiskLock() = 0;
};

// Implementation for Dorado disk lock manager
class DiskLockDorado : public DiskLockManager {
private:
    dlock_t g_disk_lock;

public:
    DiskLockDorado() {
        g_disk_lock = {0};
    }

    int initDiskLock(const char *path, uint64 lock_addr, int64 inst_id) override {
        if (path == nullptr) {
            return -1; // Invalid path
        }
        g_disk_lock_info.path = path;
        g_disk_lock_info.inst_id = inst_id;

        if (cm_alloc_dlock(&g_disk_lock, lock_addr, inst_id) != 0) {
            return -1; // Allocation failed
        }
        if (cm_init_dlock(&g_disk_lock, lock_addr, inst_id) != 0) {
            return -1; // Initialization failed
        }
        return 0; // Success
    }

    disk_lock_info_t lockDiskLock() override {
        do {
            g_disk_lock_info.lock_result = cm_disk_lock_s(&g_disk_lock, g_disk_lock_info.path);
            if (g_disk_lock_info.lock_result == 0) {
                break; // Lock acquired successfully
            }
            time_t lockTime = LOCKR_LOCK_TIME(g_disk_lock);
            if (lockTime <= 0) {
                break; // Invalid lock time
            }
            g_disk_lock_info.lock_time = (int)(lockTime % MAX_EXIT_STATUS);
        } while (0);
        return g_disk_lock_info;
    }

    int lockfDiskLock() override {
        cm_get_dlock_info_s(&g_disk_lock, g_disk_lock_info.path);
        LOCKR_LOCK_TIME(g_disk_lock) = g_disk_lock_info.lock_time;
        return cm_disk_lock_s(&g_disk_lock, g_disk_lock_info.path);
    }

    int unlockDiskLock() override {
        return cm_disk_unlock_s(&g_disk_lock, g_disk_lock_info.path);
    }

    void destroyDiskLock() override {
        cm_destory_dlock(&g_disk_lock);
    }
};

// Implementation for Normal disk lock manager
class DiskLockNormal : public DiskLockManager {
private:
    unsigned int g_lock_id;

public:
    DiskLockNormal() : g_lock_id(0) {}

    int initDiskLock(const char *scsi_dev, uint64 lock_addr, int64 inst_id) override {
        g_disk_lock_info.path = scsi_dev;
        g_disk_lock_info.inst_id = inst_id;

        int ret = cm_dl_alloc(scsi_dev, lock_addr, inst_id);
        if (ret < 0) {
            return ret; // Allocation failed
        }
        g_lock_id = ret;
        return 0; // Allocation successful
    }

    disk_lock_info_t lockDiskLock() override {
        int res = 0;
        unsigned long long owner_inst_id = 0;

        do {
            g_disk_lock_info.lock_result = cm_dl_lock(g_lock_id, 0);
            if (g_disk_lock_info.lock_result == 0) {
                break; // Lock acquired successfully
            }
            unsigned long long lockTime = 0;
            res = cm_dl_getlocktime(g_lock_id, &lockTime);
            if (res != 0) {
                break; // Failed to get lock time
            }
            res = cm_dl_getowner(g_lock_id, &owner_inst_id);
            if (res != 0) {
                break; // Failed to get owner
            }
            g_disk_lock_info.owner_id = owner_inst_id;
            g_disk_lock_info.lock_time = (int)(lockTime % MAX_EXIT_STATUS);
        } while (0);
        return g_disk_lock_info;
    }

    int lockfDiskLock() override {
        int res;
        unsigned long long owner_inst_id;

        // Get the owner of the lock
        res = cm_dl_getowner(g_lock_id, &owner_inst_id);
        if (res != 0 || (int64)owner_inst_id != g_disk_lock_info.owner_id) {
            return -1; // Owner mismatch or failed to get owner
        }

        res = cm_dl_clean(g_lock_id, owner_inst_id);
        if (res != 0) {
            return res; // Failed to clean lock
        }

        res = cm_dl_lock(g_lock_id, 0);
        if (res == 0) {
            return 0; // Lock acquired successfully
        }

        return res; // Return last error
    }

    int unlockDiskLock() override {
        return cm_dl_unlock(g_lock_id);
    }

    void destroyDiskLock() override {
        cm_dl_dealloc(g_lock_id);
    }
};

// Global instance of DiskLockManager
static std::shared_ptr<DiskLockManager> g_diskLockMgr;

// Function to initialize the disk lock manager
void initializeDiskLockManager() {
    if (g_shareDiskLockType == DISK_LOCK_MGR_DORADO) {
        g_diskLockMgr = std::shared_ptr<DiskLockManager>(new DiskLockDorado());
    } else {
        g_diskLockMgr = std::shared_ptr<DiskLockManager>(new DiskLockNormal());
    }
}

// Public API functions
int cm_init_disklock(const char* path, uint64 lock_addr, int64 inst_id) {
    return g_diskLockMgr->initDiskLock(path, lock_addr, inst_id);
}

disk_lock_info_t cm_lock_disklock() {
    return g_diskLockMgr->lockDiskLock();
}

int cm_lockf_disklock() {
    return g_diskLockMgr->lockfDiskLock();
}

int cm_unlock_disklock() {
    return g_diskLockMgr->unlockDiskLock();
}

void cm_destroy_disklock() {
    g_diskLockMgr->destroyDiskLock();
}