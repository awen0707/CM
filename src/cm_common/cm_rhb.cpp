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
 * cm_rhb.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_common/cm_rhb.cpp
 *
 * -------------------------------------------------------------------------
 */
#include "cm_rhb.h"

#include "cm_config.h"

#include "cm_elog.h"

bool IsRhbTimeout(time_t t1, time_t baseTime, int timeout)
{
    return (int)difftime(baseTime, t1) > timeout;
}

/*
 * | D\S |  1  |  2  |  3  |
 * |  1  |  \  |  Y  |  Y  |
 * |  2  |  Y  |  \  |  Y  |
 * |  3  |  Y  |  Y  |  \  |
 */
char *GetRhbSimple(time_t *hbs, uint32 rowMax, uint32 hwl, time_t baseTime, uint32 timeout)
{
    uint32 head = 0;
    if (hwl != g_node_num) {
        write_runlog(WARNING, "rhb hwl(%u) not equal to nodeNum(%u), get rhb info without head.\n", hwl, g_node_num);
    } else {
        head = 1;
    }

    const uint32 fixLen = 6;
    size_t bufLen = ((fixLen + 1) * (hwl + head) + 2) * (hwl + head);
    char *buf = (char *)malloc(bufLen);
    if (buf == NULL) {
        write_runlog(ERROR, "can't alloc mem for rhb infos, needed:%u\n", (uint32)bufLen);
        return NULL;
    }
    error_t rc = memset_s(buf, bufLen, 0, bufLen);
    securec_check_errno(rc, (void)rc);

    for (uint32 i = 0; i < hwl; i++) {
        PrintRhb(&hbs[i * rowMax], hwl, "RHB");
        buf[strlen(buf)] = '|';
        for (uint32 j = 0; j < hwl; j++) {
            uint32 rIdx = i * rowMax + j;
            const char *stat =
                (i == j ? "  \\  |" : (IsRhbTimeout(hbs[rIdx], baseTime, (int32)timeout) ? "  N  |" : "  Y  |"));
            rc = strncat_s(buf, bufLen, stat, strlen(stat));
            securec_check_errno(rc, (void)rc);
        }
        if (strlen(buf) < (bufLen - 1)) {
            buf[strlen(buf)] = '\n';
        }
    }

    return buf;
}

void PrintRhb(time_t *hbs, uint32 count, const char *str)
{
    const uint32 timeBufMaxLen = 128;
    struct tm result;
    char buf[MAX_LOG_BUFF_LEN] = {0};
    buf[0] = '|';
    for (uint32 i = 0; i < count; i++) {
        char timeBuf[timeBufMaxLen] = {0};
        GetLocalTime(&hbs[i], &result);
        (void)strftime(timeBuf, timeBufMaxLen, "%Y-%m-%d %H:%M:%S", &result);
        timeBuf[strlen(timeBuf)] = '|';
        errno_t rc = strncat_s(buf, MAX_LOG_BUFF_LEN, timeBuf, strlen(timeBuf));
        securec_check_errno(rc, (void)rc);
    }

    write_runlog(DEBUG1, "[%s] hb infos: %s\n", str, buf);
}
