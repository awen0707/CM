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
 * cm_spinlock.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_communication/cm_protocol/cm_spinlock.cpp
 *
 * -------------------------------------------------------------------------
 */
#include "cm_spinlock.h"

#ifdef WIN32
__declspec(thread) uint64 g_tls_spin_sleeps = 0;
#else
__thread uint64 g_tls_spin_sleeps = 0;
#endif

void cm_spin_sleep_and_stat(spin_statis_t *stat)
{
    uint64 usecs;
    timeval_t tv_begin, tv_end;

    (void)cm_gettimeofday(&tv_begin);
    cm_spin_sleep();
    (void)cm_gettimeofday(&tv_end);
    usecs = TIMEVAL_DIFF_US(&tv_begin, &tv_end);
    if (stat != NULL) {
        stat->wait_usecs = usecs;
    }

    /* tls_spin_sleeps can overflow only if a thread sleep 0xffffffffffffffff us. But this will not take place. */
    g_tls_spin_sleeps += usecs;
}

void cm_sleep_tx(uint32 ms)
{
    struct timespec tq, tr;
    tq.tv_sec = (time_t)(ms / 1000);
    tq.tv_nsec = (long)(ms % 1000) * 1000000;

    (void)nanosleep(&tq, &tr);
}
