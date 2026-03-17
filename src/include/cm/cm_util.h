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
 * cm_util.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_util.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CM_UTIL_H
#define CM_UTIL_H

#include <pthread.h>
#include "c.h"

const int CM_NSEC_COUNT_PER_MS  = 1000000;
const int  CM_MS_COUNT_PER_SEC  = 1000;

int CmMkdirP(char *path, unsigned int omode);
char *gs_getenv_r(const char *name);
uint64 GetMonotonicTimeMs();
uint64 GetMonotonicTimeS();

enum class CMFairMutexType {
    CM_MUTEX_NODE,
    CM_MUTEX_READ,
    CM_MUTEX_WRITE,
};
 
using CMFairMutex = struct CMFairMutexSt {
    pthread_mutex_t lock;
    pthread_mutex_t innerLock;
    pthread_cond_t cond;
    uint32 readerCount;
    uint32 writerCount;
    CMFairMutexType curType;
};
 
void CMFairMutexInit(CMFairMutex &mutex);
int CMFairMutexLock(CMFairMutex &mutex, CMFairMutexType type);
void CMFairMutexUnLock(CMFairMutex &mutex);
char *GetDynamicMem(char *dynamicPtr, size_t *curSize, size_t memSize);

#endif  // CM_UTIL_H
