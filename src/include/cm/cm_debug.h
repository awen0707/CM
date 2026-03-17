/*
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd.
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
 * cm_debug.h
 *
 * IDENTIFICATION
 *    include/cm/cm_debug.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CM_DEBUG_H
#define CM_DEBUG_H

#include "c.h"
static inline void cm_assert(bool condition)
{
    if (!condition) {
        *((uint32 *)NULL) = 1;
    }
}

#ifdef CM_DEBUG_VERSION
#define CM_ASSERT(expr) cm_assert((bool)(expr))
#else
#define CM_ASSERT(expr) ((void)(expr))
#endif

static inline void cm_exit(int32 exitcode)
{
    _exit(exitcode);
}
#endif
