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
 * ctl_show.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_ctl/ctl_show.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CTL_SHOW_H
#define CTL_SHOW_H

#include "cm_defs.h"
status_t HandleRhbAck(const char *option, char *recvMsg);
status_t HandleNodeDiskAck(const char *option, char *recvMsg);
status_t HandleFloatIpAck(const char *option, char *recvMsg);

#endif
