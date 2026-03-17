/*
* Copyright (c) 2023 Huawei Technologies Co.,Ltd.
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
* cms_cus_res.h
*
*
* IDENTIFICATION
*    include/cm/cm_server/cms_cus_res.h
*
* -------------------------------------------------------------------------
*/
#ifndef CMS_CUS_RES_H
#define CMS_CUS_RES_H

bool8 CanProcessResStatus();
void *UpdateResStatusListMain(void *arg);

#endif  // CMS_CUS_RES_H
