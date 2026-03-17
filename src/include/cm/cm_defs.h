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
 * cm_defs.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_defs.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CM_DEFS_H
#define CM_DEFS_H

#include <stdlib.h>
#include <stdio.h>
#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <unistd.h>
#include <time.h>
#endif
#ifdef __cplusplus
extern "C" {
#endif

typedef enum en_status {
    CM_ERROR = -1,
    CM_SUCCESS = 0,
    CM_TIMEDOUT = 1
} status_t;

typedef enum ResStatusEn {
    CM_RES_STAT_UNKNOWN = 0,
    CM_RES_STAT_ONLINE = 1,
    CM_RES_STAT_OFFLINE = 2,
    /********************/
    CM_RES_STAT_COUNT = 3,
} ResStatus;

typedef enum ClientErrorEn {
    CM_RES_CLIENT_SUCCESS = 0,
    CM_RES_CLIENT_CANNOT_DO = 1,
    CM_RES_CLIENT_DDB_ERR = 2,
    CM_RES_CLIENT_VERSION_ERR = 3,
    CM_RES_CLIENT_CONNECT_ERR = 4,
    CM_RES_CLIENT_TIMEOUT = 5,
    CM_RES_CLIENT_NO_LOCK_OWNER = 6,
} ClientError;

typedef enum StartExitCodeEn {
    CM_START_EXIT_FAILED = -1,
    CM_START_EXIT_SUCCESS = 0,
    CM_START_EXIT_INIT = 2,
} StartExitCode;

typedef unsigned char bool8;

#define CMS_ONE_PRIMARY_ONE_STANDBY 2
#define CM_EXIT ((int)-2)
#define CM_FALSE (uint8)0
#define CM_TRUE  (uint8)1

/* is letter */
#define CM_IS_LETER(c) (((c) >= 'a' && (c) <= 'z') || ((c) >= 'A' && (c) <= 'Z'))
/* is naming leter */
#define CM_IS_NAMING_LETER(c) \
    (((c) >= 'a' && (c) <= 'z') || ((c) >= 'A' && (c) <= 'Z') \
    || ((c) >= '0' && (c) <= '9') || (c) == '_' || (c) == '$' || (c) == '#')

#define CM_ALIGN4_SIZE 4

typedef int socket_t;

#define SIZE_K(n) (uint32)((n) * 1024)
#define SIZE_M(n) (1024 * SIZE_K(n))
#define SIZE_G(n) (1024 * (uint64)SIZE_M(n))
#define SIZE_T(n) (1024 * (uint64)SIZE_G(n))

#ifdef WIN32
#define CM_CHECK_FMT(a, b)
#else
#define CM_CHECK_FMT(a, b) __attribute__((format(printf, a, b)))
#endif  // WIN32

/* size alignment */
#define CM_ALIGN4(size)  ((((size)&0x03) == 0) ? (size) : ((size) + 0x04 - ((size)&0x03)))
#define CM_ALIGN8(size)  ((((size)&0x07) == 0) ? (size) : ((size) + 0x08 - ((size)&0x07)))
#define CM_ALIGN16(size) ((((size)&0x0F) == 0) ? (size) : ((size) + 0x10 - ((size)&0x0F)))
// align to power of 2
#define CM_CALC_ALIGN(size, align) (((size) + (align)-1) & (~((align)-1)))
#define CM_CALC_ALIGN_FLOOR(size, align) (((size) -1) & (~((align)-1)))
/* align to any positive integer */
#define CM_ALIGN_ANY(size, align) (((size) + (align)-1) / (align) * (align))

#define CM_ALIGN_CEIL(size, align) (((size) + (align)-1) / (align))

#define CM_IS_ALIGN2(size) (((size)&0x01) == 0)
#define CM_IS_ALIGN4(size) (((size)&0x03) == 0)
#define CM_IS_ALIGN8(size) (((size)&0x07) == 0)

#define CM_ALIGN16_CEIL(size) ((((size)&0x0F) == 0) ? ((size) + 0x10) : ((size) + 0x10 - ((size)&0x0F)))
#define CM_ALIGN4_FLOOR(size) ((((size)&0x03) == 0) ? (size) : ((size) - ((size)&0x03)))
#define CM_ALIGN_8K(size)     (((size) + 0x00001FFF) & 0xFFFFE000)

#define CM_RETSUCCESS_IFYES(cond) \
    do {                          \
        if (cond) {               \
            return CM_SUCCESS;    \
        }                         \
    } while (0)

// return CM_ERROR if error occurs
#define CM_RETURN_IFERR(ret)          \
    do {                              \
        status_t _status_ = (ret);    \
        if (_status_ != CM_SUCCESS) { \
            return _status_;          \
        }                             \
    } while (0)

#define CM_RETURN_INT_IFERR(ret)      \
    do {                              \
        int _status_ = (ret);         \
        if (_status_ != 0) {          \
            return _status_;          \
        }                             \
    } while (0)

#define CM_RETURN_ERR_IF_INTERR(ret)  \
    do {                              \
        int _status_ = (ret);    \
        if (_status_ != 0) { \
            return CM_ERROR;          \
        }                             \
    } while (0)

#define CM_RETERR_IF_FALSE(ret) \
    do {                        \
        if ((ret) != CM_TRUE) { \
            return CM_ERROR;    \
        }                       \
    } while (0)

#define CM_RETURN_IF_TRUE(ret)  \
    do {                        \
        if ((ret) == CM_TRUE) { \
            return CM_ERROR;    \
        }                       \
    } while (0)

#define CM_RETURN_IF_NULL(ret) \
    do {                       \
        if ((ret) == NULL) {   \
            return;            \
        }                      \
    } while (0)

#define CM_RETERR_IF_NULL(ret) \
    do {                       \
        if ((ret) == NULL) {   \
            return CM_ERROR;   \
        }                      \
    } while (0)

#define CM_RETERR_IF_NULL_EX(ret, func) \
    do {                                \
        if ((ret) == NULL) {            \
            func;                            \
            return CM_ERROR;            \
        }                               \
    } while (0)

// return NULLL if error occurs
#define CM_RETNULL_IFERR(ret)      \
    do {                           \
        if ((ret) != CM_SUCCESS) { \
            return NULL;           \
        }                          \
    } while (0)

// return NULLL if error occurs
#define CM_RETVOID_IFERR(ret)      \
    do {                           \
        if ((ret) != CM_SUCCESS) { \
            return;           \
        }                          \
    } while (0)

// return CM_FALSE if cond is not true
#define CM_RETFALSE_IFNOT(cond) \
    do {                        \
        if (!(cond)) {          \
            return CM_FALSE;    \
        }                       \
    } while (0)

// return specific value if cond is true
#define CM_RETVALUE_IFTRUE(cond, value) \
    do {                                \
        if (cond) {                     \
            return (value);             \
        }                               \
    } while (0)

#define CM_BREAK_IF_ERROR(ret) \
    if ((ret) != CM_SUCCESS) { \
        break;                 \
    }

#define CM_BREAK_IF_TRUE(cond) \
    if (cond) {                \
        break;                 \
    }

#define CM_BREAK_IF_NULL(cond) \
    if ((cond) == NULL) {      \
        break;                 \
    }

#define CM_BREAK_IF_FALSE(cond) \
    if (!(cond)) {              \
        break;                  \
    }

// continue the loop if cond is true
#define CM_CONTINUE_IFYES(cond) \
    if (cond) {                 \
        continue;               \
    }

#define CM_RETURN_IF_FALSE(ret) \
    do {                        \
        if ((ret) != CM_TRUE) { \
            return CM_ERROR;    \
        }                       \
    } while (0)

#define CM_RETURN_IF_FALSE_EX(ret, func) \
    do {                                 \
        if ((ret) != CM_TRUE) {          \
            (func);                      \
            return CM_ERROR;             \
        }                                \
    } while (0)

#define CM_RETURN_IFERR_EX(ret, func)                   \
    do {                                                \
        status_t _status_ = (ret);                      \
        if (SECUREC_UNLIKELY(_status_ != CM_SUCCESS)) { \
            func;                                       \
            return _status_;                            \
        }                                               \
    } while (0)

/* To decide whether a pointer is null */
#define CM_IS_NULL(ptr) ((ptr) == NULL)

#define CM_SET_VALUE_IF_NOTNULL(ptr, v) \
    do {                                \
        if ((ptr) != NULL) {            \
            *(ptr) = (v);               \
        }                               \
    } while (0)

#define CM_MAX_IP_LEN 64

#define CM_IS_EMPTY_STR(str)     (((str) == NULL) || ((str)[0] == 0))

/* simple mathematical calculation */
#define CM_MIN(A, B) ((B) < (A) ? (B) : (A))
#define CM_MAX(A, B) ((B) > (A) ? (B) : (A))
#define CM_SWAP(type, A, B) \
    do {                    \
        type t_ = (A);      \
        (A) = (B);          \
        (B) = t_;           \
    } while (0)
#define CM_DELTA(A, B) (((A) > (B)) ? ((A) - (B)) : ((B) - (A)))

#define CM_PASSWORD_BUFFER_SIZE (uint32)512
#ifndef ITERATE_TIMES
#define ITERATE_TIMES 10000
#endif
#ifndef MAX_PATH_LEN
#define MAX_PATH_LEN 1024
#endif

#define GS_FILE_NAME_BUFFER_SIZE        (uint32)256
#define GS_MAX_FILE_NAME_LEN            (uint32)(GS_FILE_NAME_BUFFER_SIZE - 1)
#define CM_FULL_PATH_BUFFER_SIZE        (uint32)256
#define O_BINARY            0

#ifdef WIN32
#define SLASH '\\'
#else
#define SLASH '/'
#endif

#ifdef WIN32
#define inline __inline
#define CmSleep(ms) Sleep(ms)
#else
static inline void CmSleep(int ms)
{
    struct timespec tq, tr;
    tq.tv_sec = ms / 1000;
    tq.tv_nsec = (ms % 1000) * 1000000;

    (void)nanosleep(&tq, &tr);
}
#endif

#ifndef FREE_AND_RESET
#define FREE_AND_RESET(ptr)  \
    do {                     \
        if (NULL != (ptr)) { \
            free(ptr);       \
            (ptr) = NULL;    \
        }                    \
    } while (0)
#endif

#ifdef __cplusplus
}
#endif

#endif
