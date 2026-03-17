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
 * cma_dl_load.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_agent/clients/libpq/cma_dl_load.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CMA_DL_LOAD_H
#define CMA_DL_LOAD_H

#define LIB_OPEN_FLAGS RTLD_NOW

#if defined(WIN32)
#define LIB_HANDLE HMODULE
#define LIB_OPEN(l) LoadLibrary(l)
#define LIB_CLOSE FreeLibrary
#define LIB_GETSYMBOL(h, s, p, t)   p = (t) GetProcAddress(h, s); assert(NULL != p)

#else

#include <dlfcn.h>

#define LIB_HANDLE void *
#define LIB_OPEN(l) dlopen(l, LIB_OPEN_FLAGS)
#define LIB_CLOSE dlclose
#define LIB_GETSYMBOL(h, s, p, t) p = (t)dlsym(h, s)

#endif

#endif  // CMA_DL_LOAD_H
