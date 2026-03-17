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
 * cms_rhb.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_server/cms_rhb.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CMS_RHB_H
#define CMS_RHB_H

#include <time.h>

#define TIME_STR_MAX_LEN 20

void InitDbListsByStaticConfig();
void RefreshNodeRhbInfo(unsigned int nodeId, const time_t *hbs, unsigned int hwl);
void GetRhbStat(time_t hbs[MAX_RHB_NUM][MAX_RHB_NUM], unsigned int *hwl);
void ResetNodeConnStat();
void PrintHbsInfo(int resIdx1, uint32 nodeId1, int resIdx2, uint32 nodeId2, int logLevel);
void GetTimeStr(time_t baseTime, char *timeStr, uint32 strLen);

#endif
