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
 * cm_msg_buf_pool.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_msg_buf_pool.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CM_MSG_BUF_POOL_H
#define CM_MSG_BUF_POOL_H

#include "c.h"

void MsgPoolInit(uint32 maxPoolSize, uint32 maxBufCount = 0);
void MsgPoolClean(uint32 leaveBufCount = 0);
void *AllocBufFromMsgPool(uint32 msgSize);
void FreeBufFromMsgPool(void *buf);

void PrintMsgPoolInfo(int logLevel);
void PrintMsgBufPoolUsage(int logLevel);
void GetTotalBufInfo(uint32 *freeCount, uint32 *allocCount, uint32 *typeCount);
void GetTypeBufInfo(uint32 bufSize, uint32 *freeCount, uint32 *allocCount);
void GetTmpBufInfo(uint32 *tmpBufCount);

#endif  // CM_MSG_BUF_POOL_H
