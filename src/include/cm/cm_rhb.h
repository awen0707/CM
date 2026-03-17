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
 * cm_rhb.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_rhb.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CM_RHB_H
#define CM_RHB_H

#include <time.h>

#include "c.h"

#define MAX_RHB_NUM (9) // used by net message, can't change

inline void GetLocalTime(const time_t *t, struct tm *result)
{
#ifdef WIN32
    errno_t err = localtime_s(result, t);
    if (err != EOK) {
        write_runlog(FATAL, "get local time failed!, errno=%d", err);
    }
    return;
#else
    (void)localtime_r(t, result);
#endif
}

// the following func need free!
char *GetRhbSimple(time_t *hbs, uint32 rowMax, uint32 hwl, time_t baseTime, uint32 timeout);
bool IsRhbTimeout(time_t t1, time_t baseTime, int timeout);
void PrintRhb(time_t *hbs, uint32 count, const char *str);

#endif