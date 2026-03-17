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
 * cms_threads.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_server/cms_threads.cpp
 *
 * -------------------------------------------------------------------------
 */
#include <sys/epoll.h>
#include "cms_global_params.h"
#include "cms_arbitrate_cms.h"
#include "cms_az.h"
#include "cms_cluster_switchover.h"
#include "cms_disk_check.h"
#include "cms_monitor_main.h"
#include "cms_phony_dead_check.h"
#include "cms_sync_dynamic_info.h"
#include "cms_common.h"
#include "cms_write_dynamic_config.h"
#include "cms_barrier_check.h"
#include "cms_arbitrate_cluster.h"
#include "cms_cus_res.h"
#include "cms_threads.h"

static const int GET_DORADO_IP_TIMES = 3;

/**
 * @brief cm_server arbitrate self
 *
 * @return int
 */
int CM_CreateHA(void)
{
    CM_HAThread* pHAthread = NULL;
    int err;
    errno_t rc = 0;

    for (int i = 0; i < CM_HA_THREAD_NUM; i++) {
        pHAthread = &(gHAThreads.threads[i]);

        rc = memset_s(pHAthread, sizeof(CM_HAThread), 0, sizeof(CM_HAThread));
        securec_check_errno(rc, (void)rc);
        if ((err = pthread_create(&(pHAthread->thread.tid), NULL, CM_ThreadHAMain, pHAthread)) != 0) {
            write_runlog(ERROR, "Create HA thread failed %d: %d\n", err, errno);
            return -1;
        }
        gHAThreads.count++;
    }
    return 0;
}
/**
 * @brief Create a monitor Thread object
 *
 * @return int
 */
int CM_CreateMonitor(void)
{
    CM_MonitorThread* monitor = &gMonitorThread;
    errno_t rc = memset_s(monitor, sizeof(CM_MonitorThread), 0, sizeof(CM_MonitorThread));
    securec_check_errno(rc, (void)rc);
    if (pthread_create(&(gMonitorThread.thread.tid), NULL, CM_ThreadMonitorMain, monitor) != 0) {
        return -1;
    }
    return 0;
}

/**
 * @brief Create a ddb cluster status check Thread object
 *
 * @return int
 */
int CM_CreateDdbStatusCheckThread(void)
{
    CM_DdbStatusCheckAndSetThread* pCheckThread = &gDdbCheckThread;
    errno_t rc = memset_s(pCheckThread, sizeof(CM_DdbStatusCheckAndSetThread), 0, sizeof(CM_DdbStatusCheckAndSetThread));
    securec_check_errno(rc, (void)rc);
    if (pthread_create(&(gDdbCheckThread.thread.tid), NULL, CM_ThreadDdbStatusCheckAndSetMain, pCheckThread) != 0) {
        return -1;
    }
    return 0;
}

#ifdef ENABLE_MULTIPLE_NODES
status_t CmCreateCheckGtmModThread()
{
    pthread_t thrId;
    int32 err = pthread_create(&thrId, NULL, CheckGtmModMain, NULL);
    if (err != 0) {
        write_runlog(ERROR, "Failed to create a new thread: error %d\n", err);
        return CM_ERROR;
    }
    if ((err = pthread_detach(thrId)) != 0) {
        write_runlog(ERROR, "Failed to detach a new gtm mod thread: error %d.\n", err);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}
#endif

/**
 * @brief Create a Storage Threshold Check Thread object
 *
 */
static void CreateStorageThresholdCheckThread()
{
    int err;
    pthread_t thr_id;

    if ((err = pthread_create(&thr_id, NULL, StorageDetectMain, NULL)) != 0) {
        write_runlog(ERROR, "Failed to create a new thread: error %d\n", err);
    }
}

/**
 * @brief Create a deal phony alarm thread object
 *
 */
static void CreateDealPhonyAlarmThread()
{
    int err;
    pthread_t thr_id;

    if ((err = pthread_create(&thr_id, NULL, deal_phony_dead_alarm, NULL)) != 0) {
        write_runlog(ERROR, "Failed to create a new thread for deal phony alarm: error %d\n", err);
    }
}

/**
 * @brief Create a deal global barrier thread object
 */
void CreateDealGlobalBarrierThread()
{
    int err;
    pthread_t thr_id;
    if (backup_open == CLUSTER_PRIMARY || g_clusterInstallType != INSTALL_TYPE_STREAMING) {
        return;
    }
    if ((err = pthread_create(&thr_id, NULL, DealGlobalBarrier, NULL)) != 0) {
        write_runlog(ERROR, "Failed to create a new thread for deal global barrier: error %d\n", err);
    }
    if ((err = pthread_create(&thr_id, NULL, DealBackupOpenStatus, NULL)) != 0) {
        write_runlog(ERROR, "Failed to create a new thread for deal global barrier: error %d\n", err);
    }
}

void *CheckDoradoIp(void *arg)
{
    for (;;) {
        char tmpIp[CM_IP_LENGTH] = {0};
        GetDoradoOfflineIp(tmpIp, CM_IP_LENGTH);
        if (tmpIp[0] == '\0') {
            write_runlog(LOG, "cms get g_doradoIp is NULL.\n");
            cm_sleep(GET_DORADO_IP_TIMES);
            continue;
        }
        if (strcmp(tmpIp, g_doradoIp) != 0) {
            write_runlog(LOG, "cms get g_doradoIp has change from \"%s\" to \"%s\"\n", g_doradoIp, tmpIp);
            errno_t rc = strcpy_s(g_doradoIp, CM_IP_LENGTH, tmpIp);
            securec_check_errno(rc, (void)rc);
        } else {
            write_runlog(DEBUG1, "cms get g_doradoIp = %s\n", tmpIp);
        }
        cm_sleep(GET_DORADO_IP_TIMES);
    }

    return NULL;
}

void CreateDoradoCheckThread()
{
    int err;
    pthread_t thrId;
    if (!GetIsSharedStorageMode()) {
        return;
    }
    if ((err = pthread_create(&thrId, NULL, CheckDoradoIp, NULL)) != 0) {
        write_runlog(ERROR, "Failed to create a new thread for CreateDoradoCheckThread: error %d\n", err);
    }
    return;
}

/**
 * @brief
 *
 * @return int
 */
int CM_CreateMonitorStopNode(void)
{
    CM_MonitorNodeStopThread* monitor = &gMonitorNodeStopThread;
    errno_t rc = memset_s(monitor, sizeof(CM_MonitorNodeStopThread), 0, sizeof(CM_MonitorNodeStopThread));
    securec_check_errno(rc, (void)rc);

    if (pthread_create(&(gMonitorNodeStopThread.thread.tid), NULL, CM_ThreadMonitorNodeStopMain, monitor) != 0) {
        return -1;
    }
    return 0;
}

int CM_CreateIOThread(CM_IOThread &ioThread, uint32 id)
{
    errno_t rc = memset_s(&ioThread, sizeof(CM_IOThread), 0, sizeof(CM_IOThread));
    securec_check_errno(rc, (void)rc);

    /* create epoll fd, MAX_EVENTS just a HINT */
    int epollFd = epoll_create(MAX_EVENTS);
    if (epollFd < 0) {
        write_runlog(ERROR, "create epoll failed %d.\n", epollFd);
        return -1;
    }

    ioThread.epHandle = epollFd;
    ioThread.id = id;
    ioThread.isBusy = false;
    ioThread.recvMsgQue = new PriMsgQues;
    ioThread.sendMsgQue = new PriMsgQues;
    InitMsgQue(*((PriMsgQues *)ioThread.sendMsgQue));
    InitMsgQue(*((PriMsgQues *)ioThread.recvMsgQue));

    if (pthread_create(&(ioThread.tid), NULL, CM_IOThreadMain, &ioThread) != 0) {
        return -1;
    }

    return 0;
}

int CM_CreateIOThreadPool(uint32 thrCount)
{
    int err;
    for (uint32 i = 0; i < thrCount; i++) {
        err = CM_CreateIOThread(gIOThreads.threads[i], i);
        if (err != 0) {
            return err;
        }
        gIOThreads.count++;
    }

    return 0;
}

static int createWorkerThread(uint32 thrCount, int type)
{
    CM_WorkThread* thrinfo = NULL;
    errno_t rc = 0;
    int err;

    for (uint32 i = 0; i < thrCount; i++) {
        uint32 thread_idx = gWorkThreads.count;
        thrinfo = &(gWorkThreads.threads[thread_idx]);

        rc = memset_s(thrinfo, sizeof(CM_WorkThread), 0, sizeof(CM_WorkThread));
        securec_check_errno(rc, (void)rc);

        thrinfo->type = type;
        thrinfo->isBusy = false;
        thrinfo->id = i;

        if ((err = pthread_create(&thrinfo->tid, NULL, CM_WorkThreadMain, thrinfo)) != 0) {
            write_runlog(ERROR, "Failed to create a new CM_WorkThreadMain %d: %d\n", err, errno);
            return -1;
        }

        gWorkThreads.count++;
    }

    return 0;
}

int CM_CreateWorkThreadPool(uint32 ctlWorkerCount, uint32 agentWorkerCount)
{
    gWorkThreads.count = 0;
    if (createWorkerThread(ctlWorkerCount, CM_CTL) != 0) {
        return -1;
    }

    if (createWorkerThread(agentWorkerCount, CM_AGENT) != 0) {
        return -1;
    }

    return 0;
}

void SetVoteAzInstanceId()
{
    bool result = false;
    for (uint32 groupIndex = 0; groupIndex < g_dynamic_header->relationCount; ++groupIndex) {
        if (g_instance_role_group_ptr[groupIndex].instanceMember[0].instanceType != INSTANCE_TYPE_DATANODE) {
            continue;
        }
        for (int memberIndex = 0; memberIndex < g_instance_role_group_ptr[groupIndex].count; ++memberIndex) {
            result = IsCurInstanceInVoteAz(groupIndex, memberIndex);
            if (result) {
                DatanodeDynamicStatus *voteAzInstance =
                    &g_instance_group_report_status_ptr[groupIndex].instance_status.voteAzInstance;
                voteAzInstance->dnStatus[voteAzInstance->count++] =
                    g_instance_role_group_ptr[groupIndex].instanceMember[memberIndex].instanceId;
            }
        }
    }
}

#if ((defined(ENABLE_MULTIPLE_NODES)) || (defined(ENABLE_PRIVATEGAUSS)))
void CreateDnGroupStatusCheckAndArbitrateThread()
{
    if (!g_multi_az_cluster) {
        g_isEnableUpdateSyncList = CANNOT_START_SYNCLIST_THREADS;
        return;
    }
    if (IsBoolCmParamTrue(g_enableDcf)) {
        write_runlog(WARNING, "current mode is dcf, cannot start CreateDnGroupStatusCheckAndArbitrateThread.\n");
        g_isEnableUpdateSyncList = CANNOT_START_SYNCLIST_THREADS;
        return;
    }
    bool isVoteAz = (GetVoteAzIndex() != AZ_ALL_INDEX);
    if (GetAzDeploymentType(isVoteAz) != TWO_AZ_DEPLOYMENT) {
        g_isEnableUpdateSyncList = CANNOT_START_SYNCLIST_THREADS;
        write_runlog(LOG, "DnGroupStatusCheckAndArbitrateMain exit, because this is not two az deployment.\n");
        return;
    }
    const int onePrimaryTwoStandby = 3;
    if (g_dn_replication_num <= onePrimaryTwoStandby) {
        g_isEnableUpdateSyncList = CANNOT_START_SYNCLIST_THREADS;
        write_runlog(LOG, "DnGroupStatusCheckAndArbitrateMain exit, because this is one Primary Two Standby.\n");
        return;
    }
    if (backup_open == CLUSTER_STREAMING_STANDBY) {
        g_isEnableUpdateSyncList = CANNOT_START_SYNCLIST_THREADS;
        write_runlog(LOG, "DnGroupStatusCheckAndArbitrateMain exit, because this is streaming standby cluster.\n");
        return;
    }
    SetVoteAzInstanceId();
    int err;
    pthread_t thr_id;
    if ((err = pthread_create(&thr_id, NULL, DnGroupStatusCheckAndArbitrateMain, NULL)) != 0) {
        write_runlog(ERROR, "Failed to create a new thread for az: error %d\n", err);
        return;
    }
    return;
}
#endif

/**
 * @brief create check az1 and az2 connect state
 *
 */
static void CreateBothConnectStateCheckThread()
{
    if (!g_multi_az_cluster) {
        return;
    }
    if (IsBoolCmParamTrue(g_enableDcf)) {
        write_runlog(WARNING, "current mode is dcf, cannot start CreateBothConnectStateCheckThread.\n");
        return;
    }
    int err;
    pthread_t thr_id;
    if ((err = pthread_create(&thr_id, NULL, BothAzConnectStateCheckMain, NULL)) != 0) {
        write_runlog(ERROR, "Failed to create a new thread for both connect state check: error %d\n", err);
    }
}

/*
 * @brief create check multiAz connect state
 *
 */
static void CreateMultiAzConnectStateCheckThread()
{
    if (!g_multi_az_cluster) {
        return;
    }
    if (IsBoolCmParamTrue(g_enableDcf)) {
        write_runlog(WARNING, "current mode is dcf, cannot start MultiAzConnectStateCheckThread.\n");
        return;
    }
    int err;
    pthread_t thr_id;

    if ((err = pthread_create(&thr_id, NULL, MultiAzConnectStateCheckMain, NULL)) != 0) {
        write_runlog(ERROR, "Failed to create a new thread for multiAz connect stste chheck: error %d\n", err);
    }
}

static void Init_cluster_to_switchover()
{
    char execPath[MAX_PATH_LEN] = {0};
    errno_t rcs;
    if (GetHomePath(execPath, sizeof(execPath)) != 0) {
        write_runlog(FATAL, "GetHomePath failed, will exit.\n");
        FreeNotifyMsg();
        exit(-1);
    }
    rcs = memset_s(switchover_flag_file_path, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rcs, (void)rcs);
    rcs = snprintf_s(
        switchover_flag_file_path, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/%s", execPath, SWITCHOVER_FLAG_FILE);
    securec_check_intval(rcs, (void)rcs);

    if (access(switchover_flag_file_path, 0) != 0) {
        write_runlog(LOG, "don't have switchover flag file.\n");
    } else {
        pthread_t thr_id;
        if ((rcs = pthread_create(&thr_id, NULL, Deal_switchover_for_init_cluster, NULL)) != 0) {
            write_runlog(ERROR, "Failed to create a new thread for switchover: error %d\n", rcs);
        }
    }
}

/**
 * @brief create thread for deal the arbitrate DN for deal with ddb and dynamic config
 *
 */
static void CreateSyncDynamicInfoThread()
{
    pthread_t thrId;
    int err = pthread_create(&thrId, NULL, SyncDynamicInfoFromDdb, NULL);
    if (err != 0) {
        write_runlog(ERROR, "Failed to create new thread for SyncDynamicInfo: error %d\n", err);
    }
}

static void CreateCheckBlackListThread()
{
    pthread_t thrId;
    int err = pthread_create(&thrId, NULL, CheckBlackList, NULL);
    if (err != 0) {
        write_runlog(ERROR, "Failed to create CheckBlackList: error %d\n", err);
    }
}

static void CreateDynamicCfgSyncThread()
{
    pthread_t thr_id;
    if (!NeedCreateWriteDynamicThread()) {
        return;
    }
    int err = pthread_create(&thr_id, NULL, WriteDynamicCfgMain, NULL);
    if (err != 0) {
        write_runlog(ERROR, "Failed to create CreateDynamicCfgSyncThread: error %d\n", err);
    }
}

static void CreateArbitrateClusterThread()
{
    int err;
    pthread_t thrId;

    if (g_dnArbitrateMode != SHARE_DISK || !IsCusResExist()) {
        return;
    }
    if ((err = pthread_create(&thrId, NULL, MaxNodeClusterArbitrateMain, NULL)) != 0) {
        write_runlog(ERROR, "Failed to create CreateArbitrateClusterThread: error %d\n", err);
    }
}

static void CreateUpdateResStatusListThread()
{
    int err;
    pthread_t thrId;

    if (!IsCusResExist()) {
        return;
    }
    if ((err = pthread_create(&thrId, NULL, UpdateResStatusListMain, NULL)) != 0) {
        write_runlog(ERROR, "Failed to create CreateArbitrateClusterThread: error %d\n", err);
    }
}

status_t CmsCreateThreads()
{
#ifdef ENABLE_MULTIPLE_NODES
    status_t st = CmCreateCheckGtmModThread();
    if (st != CM_SUCCESS) {
        return CM_ERROR;
    }
#endif

#if ((defined(ENABLE_MULTIPLE_NODES)) || (defined(ENABLE_PRIVATEGAUSS)))
    if (backup_open == CLUSTER_PRIMARY && g_clusterInstallType != INSTALL_TYPE_SHARE_STORAGE) {
        CreateDnGroupStatusCheckAndArbitrateThread();
    }
#endif

    CreateBothConnectStateCheckThread();
    CreateSyncDynamicInfoThread();
    CreateCheckBlackListThread();
    CreateDynamicCfgSyncThread();
    Init_cluster_to_switchover();
    CreateMultiAzConnectStateCheckThread();

    /* Data disk storage threshold check */
    CreateStorageThresholdCheckThread();

    CreateDealPhonyAlarmThread();
    CreateDealGlobalBarrierThread();
    CreateDoradoCheckThread();
    CreateArbitrateClusterThread();
    CreateUpdateResStatusListThread();

    return CM_SUCCESS;
}
