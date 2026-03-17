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
 * cm_error.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_error.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CM_ERROR_H
#define CM_ERROR_H

#include "cm_defs.h"
#include "securec.h"
#include "cm_ssl_base.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * @Note
 * Attention1: add error code to the corresponding range
 *
 * ERROR                                  |   RANGE
 * OS errors                              |   1 - 99
 * internal errors or common errors       |   100 - 199
 * configuration errors                   |   200 - 299
 * network errors                         |   300 - 399
 * replication errors                     |   400 - 499
 * storage errors                         |   500 - 599
 */
typedef enum en_cm_errno {
    ERR_ERRNO_BASE               = 0,
    ERR_SYSTEM_CALL = 1,
    ERR_RESET_MEMORY = 2,
    ERR_ALLOC_MEMORY_REACH_LIMIT = 3,
    ERR_ALLOC_MEMORY = 4,
    ERR_LOAD_LIBRARY = 5,
    ERR_LOAD_SYMBOL = 6,
    ERR_DATAFILE_FSYNC = 7,
    ERR_DATAFILE_FDATASYNC = 8,
    ERR_INVALID_FILE_NAME = 9,
    ERR_CREATE_FILE = 10,
    ERR_OPEN_FILE = 11,
    ERR_READ_FILE = 12,
    ERR_WRITE_FILE = 13,
    ERR_WRITE_FILE_PART_FINISH = 14,
    ERR_SEEK_FILE = 15,
    ERR_CREATE_DIR = 16,
    ERR_RENAME_FILE = 17,
    ERR_FILE_SIZE_MISMATCH = 18,
    ERR_REMOVE_FILE = 19,
    ERR_TRUNCATE_FILE = 20,
    ERR_LOCK_FILE = 21,
    ERR_CREATE_THREAD = 22,
    ERR_INIT_THREAD = 23,
    ERR_SET_THREAD_STACKSIZE = 24,
    ERR_INVALID_DIR = 25,
    ERR_COMPRESS_INIT_ERROR = 26,
    ERR_COMPRESS_ERROR = 27,
    ERR_DECOMPRESS_ERROR = 28,
    ERR_COMPRESS_FREE_ERROR = 29,
    ERR_MEM_ZONE_INIT_FAIL = 30,
    ERR_MEM_OUT_OF_MEMORY = 31,
    ERR_CREATE_EVENT = 32,
    ERR_SSL_INIT_FAILED = 33,
    ERR_SSL_RECV_FAILED = 34,
    ERR_SSL_VERIFY_CERT = 35,
    ERR_SSL_CONNECT_FAILED = 36,
    ERR_SSL_FILE_PERMISSION = 37,
    ERR_PEER_CLOSED_REASON = 38,
    ERR_PEER_CLOSED = 39,
    ERR_TCP_TIMEOUT = 40,
    ERR_DISKRW_KEY_NOTFOUND   = 41,
    ERR_DISKRW_CHECK_HEADER   = 42,
    ERR_DISKRW_GET_DATA       = 43,
    ERR_DISKRW_UPDATE_DATA    = 44,
    ERR_DISKRW_DELETE_DATA    = 45,
    ERR_DISKRW_UPDATE_HEADER  = 46,
    ERR_DISKRW_DISK_HEAD_FULL = 47,
    ERR_DISKRW_WRITE_KEY      = 48,
    ERR_DISKRW_INSERT_KEY     = 49,
    ERR_DDB_CMD_INVALID       = 50,
    ERR_DDB_CMD_UNKNOWN       = 51,
    ERR_DDB_CMD_PREFIX_INVALID = 52,
    ERR_DDB_CMD_ARG_INVALID   = 53,
    ERR_MAX_COUNT
} cm_errno_t;

// buf in thread local storage, which used for converting text to string
#define CM_T2S_BUFFER_SIZE (uint32)256
#define CM_T2S_LARGER_BUFFER_SIZE SIZE_K(16)

/* using for client communication with server, such as error buffer */
#define CM_MESSAGE_BUFFER_SIZE (uint32)2048

#define CM_MAX_LOG_CONTENT_LENGTH CM_MESSAGE_BUFFER_SIZE

typedef struct st_error_info_t {
    int32 code;
    char t2s_buf1[CM_T2S_LARGER_BUFFER_SIZE];
    char t2s_buf2[CM_T2S_BUFFER_SIZE];
    char message[CM_MESSAGE_BUFFER_SIZE];
} error_info_t;

#ifndef EOK
#define EOK (0)
#endif

int CmGetSockError(void);
void CmSetSockError(int32 e);

#define CM_THROW_ERROR(error_no, ...)                                                                            \
    do {                                                                                                         \
        CmSetError(                                                                                              \
            (char *)__FUNCTION__, (uint32)__LINE__, (cm_errno_t)error_no, g_errorDesc[error_no], ##__VA_ARGS__); \
    } while (0)

#define CM_THROW_ERROR_EX(error_no, format, ...)                                              \
    do {                                                                                      \
        CmSetErrorEx((char *)__FUNCTION__, (uint32)__LINE__, (cm_errno_t)error_no, format, ##__VA_ARGS__); \
    } while (0)

void CmSetError(const char *file, uint32 line, cm_errno_t code, const char *format, ...) CM_CHECK_FMT(4, 5);
void CmSetErrorEx(const char *file, uint32 line, cm_errno_t code, const char *format, ...) CM_CHECK_FMT(4, 5);

extern const char *g_errorDesc[ERR_MAX_COUNT];

void SetDiskRwError(const char *format, ...);
const char *GetDiskRwError();

#define CM_SET_DISKRW_ERROR(error_no, ...)                    \
    do {                                                      \
        SetDiskRwError(g_errorDesc[error_no], ##__VA_ARGS__); \
    } while (0)

#ifdef __cplusplus
}
#endif
#endif
