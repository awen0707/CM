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
* cms_cus_res.cpp
*
*
* IDENTIFICATION
*    src/cm_server/cms_cus_res.cpp
*
* -------------------------------------------------------------------------
*/
#include "cjson/cJSON.h"
#include "cms_ddb_adapter.h"
#include "cms_global_params.h"
#include "cms_common_res.h"

static ThreadProcessStatus g_resStatListStatus = THREAD_PROCESS_INIT;

bool8 CanProcessResStatus()
{
    return (g_resStatListStatus == THREAD_PROCESS_RUNNING) ? CM_TRUE : CM_FALSE;
}

static void SaveLatestResStat(unsigned long long *oldVersion)
{
    for (uint32 i = 0; i < CusResCount(); ++i) {
        (void)pthread_rwlock_rdlock(&g_resStatus[i].rwlock);
        if (oldVersion[i] < g_resStatus[i].status.version) {
            OneResStatList tmpResStat = g_resStatus[i].status;
            (void)pthread_rwlock_unlock(&g_resStatus[i].rwlock);

            if (SaveOneResStatusToDdb(&tmpResStat) == CM_SUCCESS) {
                oldVersion[i] = tmpResStat.version;
            }
            continue;
        }
        (void)pthread_rwlock_unlock(&g_resStatus[i].rwlock);
    }
}

static inline void UpdateOldVersion(unsigned long long *oldVersion)
{
    for (uint32 i = 0; i < CusResCount(); ++i) {
        (void)pthread_rwlock_rdlock(&g_resStatus[i].rwlock);
        oldVersion[i] = g_resStatus[i].status.version;
        (void)pthread_rwlock_unlock(&g_resStatus[i].rwlock);
    }
}

static inline void GetResStatAndSetThreadStat(ThreadProcessStatus threadStat, unsigned long long *oldVersion)
{
    if (GetAllResStatusFromDdb() == CM_SUCCESS) {
        UpdateOldVersion(oldVersion);
        g_resStatListStatus = threadStat;
    } else {
        write_runlog(ERROR, "get all res status list failed, can't process cus res.\n");
    }
}

void *UpdateResStatusListMain(void *arg)
{
    thread_name = "UpdateResStat";
    write_runlog(LOG, "UpdateResStatusListMain will start, and threadId is %lu.\n", (uint64)pthread_self());

    unsigned long long *oldResVersion = (unsigned long long *)CmMalloc(sizeof(unsigned long long) * CusResCount());

    for (;;) {
        if (got_stop) {
            g_resStatListStatus = THREAD_PROCESS_STOP;
            cm_sleep(1);
            break;
        }

        if (g_resStatListStatus == THREAD_PROCESS_INIT) {
            ThreadProcessStatus processStat =
                (g_HA_status->local_role == CM_SERVER_PRIMARY) ? THREAD_PROCESS_RUNNING : THREAD_PROCESS_READY;
            GetResStatAndSetThreadStat(processStat, oldResVersion);
            cm_sleep(1);
            continue;
        }

        if (g_HA_status->local_role == CM_SERVER_PRIMARY) {
            if (g_resStatListStatus == THREAD_PROCESS_READY) {
                GetResStatAndSetThreadStat(THREAD_PROCESS_RUNNING, oldResVersion);
                CleanAllResStatusReportInter();
            }
            if (g_resStatListStatus == THREAD_PROCESS_RUNNING) {
                SaveLatestResStat(oldResVersion);
            }
        } else {
            if (g_resStatListStatus != THREAD_PROCESS_READY) {
                g_resStatListStatus = THREAD_PROCESS_READY;
            }
        }

        cm_sleep(1);
    }

    write_runlog(LOG, "UpdateResStatusListMain will exit, and threadId is %lu.\n", (uint64)pthread_self());
    free(oldResVersion);
    return NULL;
}
