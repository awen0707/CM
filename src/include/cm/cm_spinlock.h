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
 * cm_spinlock.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_spinlock.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CM_SPINLOCK_H
#define CM_SPINLOCK_H

#include "cm_defs.h"
#include "cm_ssl_base.h"

#ifndef WIN32
#include <time.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define GS_SPIN_COUNT             1000
#define SPIN_STAT_INC(stat, item) \
    do {                          \
        if ((stat) != NULL) {     \
            ((stat)->item)++;     \
        }                         \
    } while (0)

typedef struct st_spin_statis {
    uint64 spins;
    uint64 wait_usecs;
    uint64 fails;
} spin_statis_t;

#if defined(__arm__) || defined(__aarch64__)
#define fas_cpu_pause()          \
    do {                            \
        __asm__ volatile("nop"); \
    } while (0)
#else
#define fas_cpu_pause()            \
    do {                              \
        __asm__ volatile("pause"); \
    } while (0)
#endif

void cm_spin_sleep_and_stat(spin_statis_t *stat);

#ifdef WIN32

static inline uint32 cm_spin_set(spinlock_t *ptr, uint32 value)
{
    return (uint32)InterlockedExchange(ptr, value);
}

static inline void cm_spin_sleep(void)
{
    Sleep(1);
}

#else

#if defined(__arm__) || defined(__aarch64__)
static inline uint32 cm_spin_set(spinlock_t *ptr, uint32 value)
{
    uint32 oldvalue = 0;
    return !__atomic_compare_exchange_n(ptr, &oldvalue, value, CM_FALSE, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
}
static inline void cm_spin_unlock(spinlock_t *lock)
{
    __atomic_store_n(lock, 0, __ATOMIC_SEQ_CST);
}

#else
static inline uint32 cm_spin_set(spinlock_t *ptr, uint32 value)
{
    uint32 oldvalue = 0;
    return (uint32)__sync_val_compare_and_swap(ptr, oldvalue, value);
}
#endif

static inline void cm_spin_sleep(void)
{
    const int nsecValue = 100;
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = nsecValue;
    (void)nanosleep(&ts, NULL);
}

#endif

#if !defined(__arm__) && !defined(__aarch64__)
static inline void cm_spin_unlock(spinlock_t *lock)
{
    if (SECUREC_UNLIKELY(lock == NULL)) {
        return;
    }

    *lock = 0;
}
#endif

#ifdef __cplusplus
}
#endif

#endif
