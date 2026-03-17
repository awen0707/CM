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
 * cm_stringinfo.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_common/cm_stringinfo.cpp
 *
 * -------------------------------------------------------------------------
 */
#include "cm/cm_c.h"
#include "cm/stringinfo.h"
#include "cm/cm_elog.h"

/*
 * makeStringInfo
 *
 * Create an empty 'StringInfoData' & return a pointer to it.
 */
CM_StringInfo CM_makeStringInfo(void)
{
    CM_StringInfo res;

    res = (CM_StringInfo)malloc(sizeof(CM_StringInfoData));
    if (res == NULL) {
        write_runlog(FATAL, "malloc CM_StringInfo failed, out of memory.\n");
        exit(1);
    }

    CM_initStringInfo(res);

    return res;
}

/*
 * makeStringInfo
 *
 * Create an empty 'StringInfoData' & return a pointer to it.
 */
void CM_destroyStringInfo(CM_StringInfo str)
{
    if (str != NULL) {
        if (str->maxlen > 0) {
            FREE_AND_RESET(str->data);
        }
        free(str);
    }
    return;
}

/*
 * makeStringInfo
 *
 * Create an empty 'StringInfoData' & return a pointer to it.
 */
void CM_freeStringInfo(CM_StringInfo str)
{
    if (str->maxlen > 0) {
        FREE_AND_RESET(str->data);
    }
    return;
}

/*
 * initStringInfo
 *
 * Initialize a StringInfoData struct (with previously undefined contents)
 * to describe an empty string.
 */
void CM_initStringInfo(CM_StringInfo str)
{
    const uint32 size = 1024; /* initial default buffer size */

    str->data = (char*)malloc(size);
    if (str->data == NULL) {
        write_runlog(FATAL, "malloc CM_StringInfo->data failed, out of memory.\n");
        exit(1);
    }
    str->maxlen = (int)size;
    CM_resetStringInfo(str);
}

/*
 * resetStringInfo
 *
 * Reset the StringInfo: the data buffer remains valid, but its
 * previous content, if any, is cleared.
 */
void CM_resetStringInfo(CM_StringInfo str)
{
    if (str == NULL) {
        return;
    }

    str->data[0] = '\0';
    str->len = 0;
    str->cursor = 0;
    str->qtype = 0;
    str->msglen = 0;
    str->msgReadData[0] = '\0';
    str->msgReadLen = 0;
}

/*
 * enlargeStringInfo
 *
 * Make sure there is enough space for 'needed' more bytes
 * ('needed' does not include the terminating null).
 *
 * External callers usually need not concern themselves with this, since
 * all stringinfo.c routines do it automatically.  However, if a caller
 * knows that a StringInfo will eventually become X bytes large, it
 * can save some palloc overhead by enlarging the buffer before starting
 * to store data in it.
 *
 * NB: because we use repalloc() to enlarge the buffer, the string buffer
 * will remain allocated in the same memory context that was current when
 * initStringInfo was called, even if another context is now current.
 * This is the desired and indeed critical behavior!
 */
int CM_enlargeStringInfo(CM_StringInfo str, int needed)
{
    /*
     * Guard against out-of-range "needed" values.	Without this, we can get
     * an overflow or infinite loop in the following.
     */
    if (needed < 0) {
        write_runlog(ERROR, "invalid string enlargement request size: %d\n", needed);
        return -1;
    }

    if (((Size)needed) >= (CM_MaxAllocSize - (Size)str->len)) {
        write_runlog(ERROR,
            "out of memory !Cannot enlarge string buffer containing %d bytes by %d more bytes.\n",
            str->len,
            needed);
        return -1;
    }

    needed += str->len + 1; /* total space required now */

    if (needed <= str->maxlen) {
        return 0; /* got enough space already */
    }

    size_t newlen = 2 * (size_t)str->maxlen;
    while ((size_t)needed > newlen) {
        newlen = 2 * newlen;
    }

    if (newlen > (size_t)CM_MaxAllocSize) {
        newlen = (size_t)CM_MaxAllocSize;
    }

    char *newdata = (char*)malloc(newlen);
    if (newdata != NULL) {
        if (str->data != NULL) {
            errno_t rc = memcpy_s(newdata, newlen, str->data, str->maxlen);
            securec_check_errno(rc, (void)rc);
            FREE_AND_RESET(str->data);
        }
        str->data = newdata;
        str->maxlen = (int)newlen;
    } else {
        if (str->data != NULL) {
            FREE_AND_RESET(str->data);
            str->maxlen = 0;
        }
        write_runlog(ERROR, "enlarge string info malloc failed, out of memory.\n");
        return -1;
    }
    return 0;
}

int CM_is_str_all_digit(const char* name)
{
    if (name == NULL) {
        write_runlog(ERROR, "CM_is_str_all_digit input null\n");
        return -1;
    }
    for (size_t i = 0; i < strlen(name); i++) {
        if (name[i] < '0' || name[i] > '9') {
            return -1;
        }
    }
    return 0;
}