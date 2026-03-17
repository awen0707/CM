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
 * cm_msg_buf_pool.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_common/cm_msg_buf_pool.cpp
 *
 * -------------------------------------------------------------------------
 */

#include <pthread.h>
#include "cm/cm_elog.h"
#include "cm_c.h"
#include "cm_msg_buf_pool.h"

typedef struct CmMsgBufSt {
    uint32 size;
    CmMsgBufSt *next;
    char data[0];
} CmMsgBuf;

typedef struct CmMsgBufTypeSt {
    uint32 bufSize;
    uint32 freeCount;
    uint32 allocCount;
    CmMsgBuf *freeList;
    CmMsgBuf *allocList;
    CmMsgBufTypeSt *next;
} CmMsgBufType;

typedef struct CmMsgPoolSt {
    uint32 curBufCount;
    uint32 maxBufCount;
    uint32 curPoolSize;
    uint32 maxPoolSize;
    CmMsgBufType *list;
    CmMsgBuf *tmpList;
    pthread_rwlock_t rwlock;
} CmMsgPool;

#ifndef ENABLE_UT
#define static
#endif

static CmMsgPool g_msgPool;

static void PrintMsgPoolInfoCore(int logLevel);

void MsgPoolInit(uint32 maxPoolSize, uint32 maxBufCount)
{
    static volatile bool isInit = false;
    if (isInit) {
        write_runlog(LOG, "[MsgPool] msg pool has init, can't do init again.\n");
        return;
    }
    g_msgPool.list = NULL;
    g_msgPool.tmpList = NULL;
    g_msgPool.curPoolSize = 0;
    g_msgPool.curBufCount = 0;
    g_msgPool.maxBufCount = maxBufCount;
    g_msgPool.maxPoolSize = maxPoolSize;
    (void)pthread_rwlock_init(&g_msgPool.rwlock, NULL);
    isInit = true;
    write_runlog(LOG, "[MsgPool] init msg pool success, maxPoolSize=%u, maxBufCount=%u.\n", maxPoolSize, maxBufCount);
}

static inline void CleanFreeBuf(CmMsgBuf *freePtr, uint32 bufSize)
{
    while (freePtr != NULL) {
        char *tmpPtr = (char*)freePtr;
        freePtr = freePtr->next;
        free(tmpPtr);
        --g_msgPool.curBufCount;
        g_msgPool.curPoolSize -= bufSize;
    }
}

static void CleanBufType(CmMsgBufType *&typePrePtr, CmMsgBufType *&typePtr)
{
    CmMsgBufType *tmpPtr = typePtr;
    if (typePtr == typePrePtr) {
        g_msgPool.list = typePtr->next;
        typePrePtr = typePtr->next;
    } else {
        typePrePtr->next = typePtr->next;
    }
    typePtr = typePtr->next;
    free(tmpPtr);
}

static void DestroyFreeBufCore(uint32 leaveBufCount)
{
    CmMsgBufType *typePtr = g_msgPool.list;
    CmMsgBufType *typePrePtr = typePtr;
    while (typePtr != NULL) {
        if (typePtr->freeCount <= leaveBufCount) {
            typePrePtr = typePtr;
            typePtr = typePtr->next;
            continue;
        }
        typePtr->freeCount = leaveBufCount;
        uint32 count = leaveBufCount;
        CmMsgBuf *freePtr = typePtr->freeList;
        CmMsgBuf *prePtr = freePtr;
        while (freePtr != NULL) {
            if (count > 0) {
                --count;
                prePtr = freePtr;
                freePtr = freePtr->next;
                continue;
            }
            if (prePtr == freePtr) {
                typePtr->freeList = NULL;
            } else {
                prePtr->next = NULL;
            }
            CleanFreeBuf(freePtr, typePtr->bufSize);
            break;
        }
        if (typePtr->freeList == NULL && typePtr->allocList == NULL) {
            CleanBufType(typePrePtr, typePtr);
            continue;
        }
        typePrePtr = typePtr;
        typePtr = typePtr->next;
    }
}

void MsgPoolClean(uint32 leaveBufCount)
{
    (void)pthread_rwlock_wrlock(&g_msgPool.rwlock);
    DestroyFreeBufCore(leaveBufCount);
    (void)pthread_rwlock_unlock(&g_msgPool.rwlock);
}

static bool IsMsgPoolExtraSpace(uint32 bufSize)
{
    return ((g_msgPool.maxBufCount != 0) && ((g_msgPool.curBufCount + 1) > g_msgPool.maxBufCount)) ||
           ((g_msgPool.curPoolSize + bufSize) > g_msgPool.maxPoolSize);
}

static bool CanCreateNewBuf(uint32 bufSize)
{
    if (IsMsgPoolExtraSpace(bufSize)) {
        write_runlog(LOG, "[MsgPool] pool is full, try to destroy free buf.\n");
        DestroyFreeBufCore(0);
    } else {
        return true;
    }

    if (IsMsgPoolExtraSpace(bufSize)) {
        write_runlog(ERROR, "[MsgPool] newBufSize=(%u), msg pool have no space.\n", bufSize);
        return false;
    }

    return true;
}

static CmMsgBuf *CreateNewBuf(uint32 bufSize)
{
    void *tmpPtr = malloc(sizeof(CmMsgBuf) + sizeof(char) * bufSize);
    if (tmpPtr == NULL) {
        write_runlog(ERROR, "[MsgPool] out of memory, CreateNewBuf.\n");
        return NULL;
    }

    CmMsgBuf *newBuf = (CmMsgBuf*)tmpPtr;
    newBuf->size = bufSize;
    newBuf->next = NULL;

    return newBuf;
}

static char *CreateNewTmpBuf(uint32 bufSize)
{
    CmMsgBuf *newTmpBuf = CreateNewBuf(bufSize);
    if (newTmpBuf == NULL) {
        write_runlog(ERROR, "[MsgPool] create tmp buf failed.\n");
        return NULL;
    }

    if (g_msgPool.tmpList != NULL) {
        newTmpBuf->next = g_msgPool.tmpList;
    }
    g_msgPool.tmpList = newTmpBuf;

    write_runlog(DEBUG1, "[MsgPool] create tmp buf (%u) success.\n", bufSize);

    return newTmpBuf->data;
}

static CmMsgBufType *CreateNewBufType(uint32 bufSize)
{
    CmMsgBufType *typePtr = (CmMsgBufType*)malloc(sizeof(CmMsgBufType));
    if (typePtr == NULL) {
        write_runlog(ERROR, "[MsgPool] out of memory, CreateNewBufType.\n");
        return NULL;
    }
    typePtr->bufSize = bufSize;
    typePtr->freeCount = 0;
    typePtr->allocCount = 0;
    typePtr->freeList = NULL;
    typePtr->allocList = NULL;
    typePtr->next = NULL;

    return typePtr;
}

static char *GetBufFromTypeList(CmMsgBufType *typePtr, uint32 bufSize)
{
    CmMsgBuf *freePtr = typePtr->freeList;
    if (freePtr != NULL) {
        typePtr->freeList = freePtr->next;
        freePtr->next = typePtr->allocList;
        typePtr->allocList = freePtr;
        --typePtr->freeCount;
        ++typePtr->allocCount;
        return freePtr->data;
    }
    write_runlog(DEBUG1, "[MsgPool] have no free buf(size=%u), need create new buf.\n", bufSize);

    if (!CanCreateNewBuf(bufSize)) {
        write_runlog(ERROR, "[MsgPool] can't find free buf, and can't create new buf.\n");
        return NULL;
    }

    CmMsgBuf *newBuf = CreateNewBuf(bufSize);
    if (newBuf == NULL) {
        write_runlog(ERROR, "[MsgPool] GetBufFromTypeList, can't create new buf.\n");
        return NULL;
    }
    newBuf->next = typePtr->allocList;
    typePtr->allocList = newBuf;
    ++typePtr->allocCount;

    ++g_msgPool.curBufCount;
    g_msgPool.curPoolSize += bufSize;

    return newBuf->data;
}

static CmMsgBufType *GetBufTypeFromPool(uint32 bufSize)
{
    CmMsgBufType *typePtr = g_msgPool.list;
    CmMsgBufType *perPtr = typePtr;
    while (typePtr != NULL) {
        if (typePtr->bufSize == bufSize) {
            return typePtr;
        }
        if (typePtr->bufSize > bufSize) {
            break;
        }
        perPtr = typePtr;
        typePtr = typePtr->next;
    }
    write_runlog(DEBUG1, "[MsgPool] can't find msg type, need create new msg type, bufSize=%u.\n", bufSize);

    if (!CanCreateNewBuf(bufSize)) {
        write_runlog(ERROR, "[MsgPool] can't find suit type list, and can't create new type list.\n");
        return NULL;
    }

    CmMsgBufType *newType = CreateNewBufType(bufSize);
    if (newType == NULL) {
        write_runlog(ERROR, "[MsgPool] GetBufTypeFromPool, can't create new buf type.\n");
        return NULL;
    }
    if (perPtr == typePtr) {
        g_msgPool.list = newType;
    } else {
        perPtr->next = newType;
    }
    newType->next = typePtr;

    return newType;
}

void *AllocBufFromMsgPool(uint32 msgSize)
{
#ifndef ENABLE_UT
    char *tmp = (char *)malloc(msgSize);
    if (tmp == NULL) {
        return NULL;
    }
    errno_t rc = memset_s(tmp, msgSize, 0, msgSize);
    securec_check_errno(rc, (void)rc);
    return tmp;
#else
    if (msgSize > g_msgPool.maxPoolSize) {
        write_runlog(ERROR, "[MsgPool] alloc buf size (%u) is big, max size (%u).\n", msgSize, g_msgPool.maxPoolSize);
        return NULL;
    }
    if (msgSize == 0) {
        write_runlog(ERROR, "[MsgPool] alloc invalid buf size (%u).\n", msgSize);
        return NULL;
    }

    (void)pthread_rwlock_wrlock(&g_msgPool.rwlock);
    CmMsgBufType *typePtr = GetBufTypeFromPool(msgSize);
    if (typePtr == NULL) {
        write_runlog(ERROR, "[MsgPool] can't get buf type from pool, msgSize=%u.\n", msgSize);
        PrintMsgPoolInfoCore(LOG);
        char *tmpBuf = CreateNewTmpBuf(msgSize);
        (void)pthread_rwlock_unlock(&g_msgPool.rwlock);
        return tmpBuf;
    }
    char *bufPtr = GetBufFromTypeList(typePtr, msgSize);
    if (bufPtr == NULL) {
        write_runlog(ERROR, "[MsgPool] can't get free buf from type list, msgSize=%u.\n", msgSize);
        PrintMsgPoolInfoCore(LOG);
        char *tmpBuf = CreateNewTmpBuf(msgSize);
        (void)pthread_rwlock_unlock(&g_msgPool.rwlock);
        return tmpBuf;
    }
    (void)pthread_rwlock_unlock(&g_msgPool.rwlock);

    write_runlog(DEBUG5, "[MsgPool] AllocBufFromMsgPool, alloc buf success.\n");

    return (void*)bufPtr;
#endif
}

status_t FreeBufFromAllocList(CmMsgBufType *typePtr, const char *bufPtr)
{
    CmMsgBuf *allocPtr = typePtr->allocList;
    CmMsgBuf *perPtr = allocPtr;
    while (allocPtr != NULL) {
        if (allocPtr->data != bufPtr) {
            perPtr = allocPtr;
            allocPtr = allocPtr->next;
            continue;
        }
        errno_t rc = memset_s(allocPtr->data, typePtr->bufSize, 0, typePtr->bufSize);
        securec_check_errno(rc, (void)rc);
        if (perPtr == allocPtr) {
            typePtr->allocList = allocPtr->next;
        } else {
            perPtr->next = allocPtr->next;
        }
        allocPtr->next = typePtr->freeList;
        typePtr->freeList = allocPtr;
        --typePtr->allocCount;
        ++typePtr->freeCount;
        return CM_SUCCESS;
    }
    return CM_ERROR;
}

bool IsBufInFreeList(CmMsgBuf *freePtr, const char *buf)
{
    while (freePtr != NULL) {
        if (freePtr->data == buf) {
            return true;
        }
        freePtr = freePtr->next;
    }
    return false;
}

static status_t FreeBufFromTmpList(const char *buf)
{
    CmMsgBuf *tmpBufPtr = g_msgPool.tmpList;
    CmMsgBuf *prePtr = g_msgPool.tmpList;
    while (tmpBufPtr != NULL) {
        if (tmpBufPtr->data != buf) {
            prePtr = tmpBufPtr;
            tmpBufPtr = tmpBufPtr->next;
            continue;
        }
        if (prePtr == tmpBufPtr) {
            g_msgPool.tmpList = tmpBufPtr->next;
        } else {
            prePtr->next = tmpBufPtr->next;
        }
        free(tmpBufPtr);
        return CM_SUCCESS;
    }
    return CM_ERROR;
}

void FreeBufFromMsgPool(void *buf)
{
    if (buf == NULL) {
        write_runlog(ERROR, "[MsgPool] buf is NULL, can't do free.\n");
        return;
    }
#ifndef ENABLE_UT
    FREE_AND_RESET(buf);
    return;
#else
    CmMsgBuf *bufPtr = (CmMsgBuf*)((char*)buf - sizeof(CmMsgBuf));
    (void)pthread_rwlock_wrlock(&g_msgPool.rwlock);
    CmMsgBufType *typePtr = g_msgPool.list;
    while (typePtr != NULL) {
        if (typePtr->bufSize < bufPtr->size) {
            typePtr = typePtr->next;
            continue;
        }
        if (typePtr->bufSize > bufPtr->size) {
            break;
        }
        if (FreeBufFromAllocList(typePtr, bufPtr->data) == CM_SUCCESS) {
            (void)pthread_rwlock_unlock(&g_msgPool.rwlock);
            write_runlog(DEBUG5, "[MsgPool] buf free success.\n");
            return;
        }
        if (IsBufInFreeList(typePtr->freeList, bufPtr->data)) {
            (void)pthread_rwlock_unlock(&g_msgPool.rwlock);
            write_runlog(FATAL, "[MsgPool] buf has been free, can't do free again.\n");
            Assert(false);
            exit(1);
        }
        break;
    }
    if (FreeBufFromTmpList((char*)buf) == CM_SUCCESS) {
        (void)pthread_rwlock_unlock(&g_msgPool.rwlock);
        write_runlog(DEBUG1, "[MsgPool] tmp buf free success.\n");
        return;
    }
    (void)pthread_rwlock_unlock(&g_msgPool.rwlock);
    write_runlog(FATAL, "[MsgPool] buf not find buf in msg pool.\n");
    Assert(false);
    exit(1);
#endif
}

static void PrintMsgPoolInfoCore(int logLevel)
{
    write_runlog(logLevel, "[MsgPool] total info: curBufCount=%u, maxBufCount=%u, curPoolSize=%u, maxPoolSize=%u.\n",
        g_msgPool.curBufCount, g_msgPool.maxBufCount, g_msgPool.curPoolSize, g_msgPool.maxPoolSize);
    CmMsgBufType *typePtr = g_msgPool.list;
    while (typePtr != NULL) {
        write_runlog(logLevel, "[MsgPool] buf type info: bufSize=%u, freeCount=%u, allocCount=%u, toolCount=%u.\n",
            typePtr->bufSize, typePtr->freeCount, typePtr->allocCount, (typePtr->freeCount + typePtr->allocCount));
        typePtr = typePtr->next;
    }
}

void PrintMsgPoolInfo(int logLevel)
{
    (void)pthread_rwlock_rdlock(&g_msgPool.rwlock);
    PrintMsgPoolInfoCore(logLevel);
    (void)pthread_rwlock_unlock(&g_msgPool.rwlock);
}

void PrintMsgBufPoolUsage(int logLevel)
{
    uint32 freeCount = 0;
    uint32 allocCount = 0;
    uint32 freeSize = 0;
    uint32 allocSize = 0;
    (void)pthread_rwlock_rdlock(&g_msgPool.rwlock);
    CmMsgBufType *typePtr = g_msgPool.list;
    while (typePtr != NULL) {
        freeCount += typePtr->freeCount;
        allocCount += typePtr->allocCount;
        freeSize = (typePtr->freeCount * typePtr->bufSize);
        allocSize = (typePtr->allocCount * typePtr->bufSize);
        typePtr = typePtr->next;
    }
    (void)pthread_rwlock_unlock(&g_msgPool.rwlock);
    uint32 totalCount = freeCount + allocCount;
    uint32 totalSize = freeSize + allocSize;
    uint32 usageRate = 0;
    if (totalSize != 0) {
        usageRate = (allocSize * 100) / totalSize;
    }
    write_runlog(logLevel, "[MsgPool] usage: total_buf_count=%u, freeCount=%u, allocCount=%u; "
        "total_buf_size=%u, freeSize=%u, allocSize=%u, usage_rate=%u%%.\n",
        totalCount, freeCount, allocCount, totalSize, freeSize, allocSize, usageRate);
}

void GetTotalBufInfo(uint32 *freeCount, uint32 *allocCount, uint32 *typeCount)
{
    uint32 getFreeCount = 0;
    uint32 getAllocCount = 0;
    uint32 getTypeCount = 0;
    (void)pthread_rwlock_rdlock(&g_msgPool.rwlock);
    CmMsgBufType *typePtr = g_msgPool.list;
    while (typePtr != NULL) {
        getFreeCount += typePtr->freeCount;
        getAllocCount += typePtr->allocCount;
        ++getTypeCount;
        typePtr = typePtr->next;
    }
    (void)pthread_rwlock_unlock(&g_msgPool.rwlock);
    if (freeCount != NULL) {
        *freeCount = getFreeCount;
    }
    if (allocCount != NULL) {
        *allocCount = getAllocCount;
    }
    if (typeCount != NULL) {
        *typeCount = getTypeCount;
    }
}

void GetTypeBufInfo(uint32 bufSize, uint32 *freeCount, uint32 *allocCount)
{
    (void)pthread_rwlock_rdlock(&g_msgPool.rwlock);
    CmMsgBufType *typePtr = g_msgPool.list;
    while (typePtr != NULL) {
        if (typePtr->bufSize == bufSize) {
            if (freeCount != NULL) {
                *freeCount = typePtr->freeCount;
            }
            if (allocCount != NULL) {
                *allocCount = typePtr->allocCount;
            }
            (void)pthread_rwlock_unlock(&g_msgPool.rwlock);
            return;
        }
        if (typePtr->bufSize > bufSize) {
            break;
        }
        typePtr = typePtr->next;
    }
    (void)pthread_rwlock_unlock(&g_msgPool.rwlock);
    write_runlog(LOG, "[MsgPool] buf size(%u) not found.\n", bufSize);
}

void GetTmpBufInfo(uint32 *tmpBufCount)
{
    uint32 getTmpBufCount = 0;
    (void)pthread_rwlock_rdlock(&g_msgPool.rwlock);
    CmMsgBuf *tmpPtr = g_msgPool.tmpList;
    while (tmpPtr != NULL) {
        ++getTmpBufCount;
        tmpPtr = tmpPtr->next;
    }
    (void)pthread_rwlock_unlock(&g_msgPool.rwlock);
    if (tmpBufCount != NULL) {
        *tmpBufCount = getTmpBufCount;
    }
}
