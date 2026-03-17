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
 * share_disk_api.cpp
 *
 * IDENTIFICATION
 *    src/cm_adapter/cm_sharediskapi/share_disk_api.cpp
 *
 * -------------------------------------------------------------------------
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <malloc.h>
#include "cm_misc_base.h"
#include "share_disk_api.h"

status_t ShareDiskRead(diskLrwHandler *handler, char *data, uint32 dataLen)
{
    if (dataLen % DISK_WRITE_512BYTES != 0) {
        write_runlog(ERROR, "dataLen errno %u.\n", dataLen);
        return CM_ERROR;
    }

    if (handler->fd < 0) {
        write_runlog(ERROR, "fd errno %d. reopen\n", handler->fd);
        handler->fd = open(handler->scsiDev, O_RDWR | O_DIRECT | O_SYNC);
        if (handler->fd < 0) {
            write_runlog(ERROR, "reopen fd failed when read data from disk.\n");
            return CM_ERROR;
        }
    }

    long size = pread(handler->fd, handler->rwBuff, (size_t)dataLen, (off_t)(handler->offset));
    if (size != dataLen) {
        write_runlog(ERROR,
            "Read dev size %u, read real size %ld, offset %lu, errno %d.\n",
            dataLen,
            size,
            handler->offset,
            errno);
        return CM_ERROR;
    }

    int rc = memcpy_s(data, dataLen, handler->rwBuff, dataLen);
    securec_check_errno(rc, (void)rc);

    return CM_SUCCESS;
}

status_t ShareDiskWrite(diskLrwHandler *handler, const char *data, uint32 dataLen)
{
    if (dataLen % DISK_WRITE_512BYTES != 0) {
        write_runlog(ERROR, "Write data to disk error for dataLen %u is invalid.\n", dataLen);
        return CM_ERROR;
    }

    if (handler->fd < 0) {
        write_runlog(ERROR, "fd errno %d. reopen\n", handler->fd);
        handler->fd = open(handler->scsiDev, O_RDWR | O_DIRECT | O_SYNC);
        if (handler->fd < 0) {
            write_runlog(ERROR, "reOpen dev %s failed, errno %d.\n", handler->scsiDev, errno);
            return CM_ERROR;
        }
    }

    long size = pwrite(handler->fd, data, (size_t)dataLen, (off_t)(handler->offset));
    if (size != dataLen) {
        write_runlog(ERROR, "Write data %s to dev %s failed, dataLen %u size %ld offset %lu errno %d.\n",
            data, handler->scsiDev, dataLen, size, handler->offset, errno);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}
