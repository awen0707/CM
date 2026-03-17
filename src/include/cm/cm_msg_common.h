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
 * cm_msg_common.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_msg_common.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CM_MSG_COMMON_H
#define CM_MSG_COMMON_H

typedef enum NetworkOperE {
    NETWORK_OPER_UNKNOWN = 0,
    NETWORK_OPER_UP,
    NETWORK_OPER_DOWN,
    NETWORK_OPER_CEIL  // it must be end
} NetworkOper;

typedef enum NetworkStateE {
    NETWORK_STATE_UNKNOWN = 0,
    NETWORK_STATE_UP,
    NETWORK_STATE_DOWN,
    NETWORK_STATE_CEIL  // it must be end
} NetworkState;

typedef enum ProcessStatusE {
    PROCESS_STATUS_INIT = 0,
    PROCESS_STATUS_UNKNOWN,
    PROCESS_STATUS_SUCCESS,
    PROCESS_STATUS_FAIL,
    PROCESS_STATUS_CEIL  // it must be end
} ProcessStatus;

#endif
