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
* ctl_common_res.h
*
*
* IDENTIFICATION
*    include/cm/cm_ctl/ctl_common_res.h
*
* -------------------------------------------------------------------------
*/
#ifndef CM_CTL_COMMON_RES_H
#define CM_CTL_COMMON_RES_H

#include "c.h"
#include "cm_defs.h"

ResStatus GetResInstStatus(uint32 instId);
status_t CheckResInstInfo(uint32 *nodeId, uint32 instId);

#endif  // CM_CTL_COMMON_RES_H
