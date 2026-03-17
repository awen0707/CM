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
 * cm_error.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_communication/cm_protocol/cm_error.cpp
 *
 * -------------------------------------------------------------------------
 */
#include "cm_error.h"
#include "cm/cm_elog.h"
#include "cm_text.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
__declspec(thread) error_info_t g_tlsError = {0};
#else
__thread error_info_t g_tlsError = {0};
#endif
const int DISKRW_ERR_LENGTH = 1024;

static THR_LOCAL char g_diskRwErr[DISKRW_ERR_LENGTH] = {0};

/*
 * one error no corresponds to one error desc
 * Attention: keep the array index same as error no
 */
const char *g_errorDesc[ERR_MAX_COUNT] = {
    [ERR_ERRNO_BASE] = "Normal, no error reported",
    [ERR_SYSTEM_CALL] = "Secure C lib has thrown an error %d",
    [ERR_RESET_MEMORY] = "Secure C lib has thrown an error %d",
    [ERR_ALLOC_MEMORY_REACH_LIMIT] = "Have reach the memory limit %lld",
    [ERR_ALLOC_MEMORY] = "Failed to allocate %llu bytes for %s",
    [ERR_LOAD_LIBRARY] = "Failed to load library '%s': error code %d",
    [ERR_LOAD_SYMBOL] = "Failed to load symbol '%s': error reason %s",
    [ERR_DATAFILE_FSYNC] = "Failed to fsync the file, the error code was %d",
    [ERR_DATAFILE_FDATASYNC] = "Failed to fdatasync the file, the error code was %d",
    [ERR_INVALID_FILE_NAME] = "The file name (%s) exceeded the maximum length (%u)",
    [ERR_CREATE_FILE] = "Failed to create the file %s, the error code was %d",
    [ERR_OPEN_FILE] = "Failed to open the file %s, the error code was %d",
    [ERR_READ_FILE] = "Failed to read data from the file, the error code was %d",
    [ERR_WRITE_FILE] = "Failed to write the file, the error code was %d",
    [ERR_WRITE_FILE_PART_FINISH] = "Write size %d, expected size %d, mostly because file size is larger than disk, "
                                   "please delete the incomplete file",
    [ERR_SEEK_FILE] = "Failed to seek file, offset:%llu, origin:%d, error code %d",
    [ERR_CREATE_DIR] = "Failed to create the path %s, error code %d",
    [ERR_RENAME_FILE] = "Failed to rename the file %s to %s, error code %d",
    [ERR_FILE_SIZE_MISMATCH] = "File size(%lld) does not match with the expected(%llu)",
    [ERR_REMOVE_FILE] = "Failed to remove file %s, error code %d",
    [ERR_TRUNCATE_FILE] = "Failed to truncate file, offset:%llu, error code %d",
    [ERR_LOCK_FILE] = "Failed to lock file, error code %d",
    [ERR_CREATE_THREAD] = "Failed to create a new thread, %s",
    [ERR_INIT_THREAD] = "Failed to init thread attribute",
    [ERR_SET_THREAD_STACKSIZE] = "Failed to set thread stacksize",
    [ERR_INVALID_DIR] = "Directory '%s' not exist or not reachable or invalid",
    [ERR_COMPRESS_INIT_ERROR] = "%s failed to init stream context, errno=%d, %s",
    [ERR_COMPRESS_ERROR] = "%s failed to compress, errno=%d, %s",
    [ERR_DECOMPRESS_ERROR] = "%s failed to decompress, errno=%d, %s",
    [ERR_COMPRESS_FREE_ERROR] = "%s failed to free stream context, errno=%d, %s",
    [ERR_MEM_ZONE_INIT_FAIL] = "Failed to init buddy memory zone",
    [ERR_MEM_OUT_OF_MEMORY] = "Failed to allocate %llu bytes from buddy memory pool",
    [ERR_CREATE_EVENT] = "Failed to initialize event notification, error code %d",
    [ERR_SSL_INIT_FAILED]          = "SSL init error: %s",
    [ERR_SSL_RECV_FAILED]          = "Failed to recv from ssl pipe, sslerr: %d, errno: %d, errmsg: %s",
    [ERR_SSL_VERIFY_CERT]          = "Failed to verify SSL certificate, reason %s",
    [ERR_SSL_CONNECT_FAILED]       = "The SSL connection failed, %s",
    [ERR_SSL_FILE_PERMISSION]      = "SSL certificate file \"%s\" has write, execute, group or world access permission",
    [ERR_PEER_CLOSED_REASON]       = "%s connection is closed, reason: %d",
    [ERR_PEER_CLOSED]              = "%s connection is closed",
    [ERR_TCP_TIMEOUT]              = "%s timeout",
    [ERR_DISKRW_KEY_NOTFOUND]      = "can't find the key %s",
    [ERR_DISKRW_CHECK_HEADER]      = "check header data with key %s failed",
    [ERR_DISKRW_GET_DATA]          = "get data with key %s failed",
    [ERR_DISKRW_UPDATE_DATA]       = "write key %s value %s to disk failed",
    [ERR_DISKRW_DELETE_DATA]       = "delete key %s from disk failed",
    [ERR_DISKRW_UPDATE_HEADER]     = "update header data with key %s failed",
    [ERR_DISKRW_DISK_HEAD_FULL]    = "disk head is already full when write key %s value %s",
    [ERR_DISKRW_WRITE_KEY]         = "write key %s to disk failed",
    [ERR_DISKRW_INSERT_KEY]        = "insert key %s to memory failed",
    [ERR_DDB_CMD_INVALID]          = "ddb command content is invalid",
    [ERR_DDB_CMD_UNKNOWN]          = "ddb command %s is unknown",
    [ERR_DDB_CMD_PREFIX_INVALID]   = "ddb command --prefix only used with --get or --delete command",
    [ERR_DDB_CMD_ARG_INVALID]      = "ddb command has too many args",
    };

void CmStrUpper(char *str)
{
    char *tmp = str;
    while (*tmp != '\0') {
        *tmp = UPPER(*tmp);
        tmp++;
    }

    return;
}

void CmStrLower(char *str)
{
    char *tmp = str;
    while (*tmp != '\0') {
        *tmp = LOWER(*tmp);
        tmp++;
    }

    return;
}

int CmGetSockError()
{
#ifdef WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

void CmSetSockError(int32 e)
{
#ifdef WIN32
    WSASetLastError(e);
#else
    errno = e;
#endif
}

status_t cm_set_srv_error(const char *file, uint32 line, cm_errno_t code, const char *format, va_list args)
{
    char log_msg[CM_MESSAGE_BUFFER_SIZE] = {0};

    errno_t err = vsnprintf_s(log_msg, CM_MESSAGE_BUFFER_SIZE, CM_MESSAGE_BUFFER_SIZE - 1, format, args);
    if (SECUREC_UNLIKELY(err == -1)) {
        write_runlog(ERROR, "Secure C lib has thrown an error %d while setting error, %s:%u.\n", err, file, line);
    }

    write_runlog(ERROR, "%s:%u errCode:%d,errMsg:%s.\n", file, line, code, log_msg);

    return CM_SUCCESS;
}

void CmSetError(const char *file, uint32 line, cm_errno_t code, const char *format, ...)
{
    va_list args;

    va_start(args, format);

    (void)cm_set_srv_error(file, line, code, format, args);

    va_end(args);
}

void CmSetErrorEx(const char *file, uint32 line, cm_errno_t code, const char *format, ...)
{
    va_list args;

    va_start(args, format);
    char tmp[CM_MAX_LOG_CONTENT_LENGTH];
    errno_t err = vsnprintf_s(tmp, CM_MAX_LOG_CONTENT_LENGTH, CM_MAX_LOG_CONTENT_LENGTH - 1, format, args);
    if (SECUREC_UNLIKELY(err == -1)) {
        write_runlog(ERROR, "Secure C lib has thrown an error %d while setting error, %s:%u", err, file, line);
    }
    CmSetError(file, line, code, g_errorDesc[code], tmp);

    va_end(args);
}

void SetDiskRwError(const char *format, ...)
{
    va_list args;

    va_start(args, format);

    errno_t err = vsnprintf_s(g_diskRwErr, DISKRW_ERR_LENGTH, DISKRW_ERR_LENGTH - 1, format, args);
    if (SECUREC_UNLIKELY(err == -1)) {
        write_runlog(ERROR, "Secure C lib has thrown an error while setting disk error.\n");
    }

    va_end(args);
}

const char *GetDiskRwError()
{
    return g_diskRwErr;
}

#ifdef __cplusplus
}
#endif
