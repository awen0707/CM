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
 * cm_ddb_etcd_arbitrate.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_adapter/cm_etcd_adapter/cm_ddb_etcd_arbitrate.cpp
 *
 * -------------------------------------------------------------------------
 */

#include <time.h>
#include "cm_ddb_etcd.h"
#include "cm/cm_elog.h"
#include "cm/cm_c.h"

uint32 g_healthEtcdCountForPreConn = 0;
static const int32 MONITOR_WAIT_TIME = 60; // 60s

static DdbArbiCon *g_arbiCon = NULL;
static char g_primaryKey[DDB_MAX_PATH_LEN] = {0};
static char g_heartBeatKey[DDB_MAX_PATH_LEN] = {0};
static int32 g_haHeartbeatTimeout[PRIMARY_STANDBY_NUM] = {0};
static int32 g_haHeartbeatFromEtcd[PRIMARY_STANDBY_NUM] = {0};
static int32 g_delaySet = 0;
static volatile uint32 g_delayTimeout = ARBITRATE_DELAY_CYCLE_MAX_COUNT;
static int32 g_haHeartBeat = 0;
static EtcdSession g_etcdSess;
static DDB_ROLE g_cmRole = DDB_ROLE_FOLLOWER;
static DrvKeyValue *g_keyValue = NULL;
static int32 g_promoteDelayCount = 0;
static uint32 g_lastCmNum = 0;
static DDB_ROLE g_notifyEtcd = DDB_ROLE_UNKNOWN;
static pthread_rwlock_t g_notifyEtcdLock;
static pthread_rwlock_t g_notityCmsLock;
static pthread_rwlock_t g_checkEtcdSessLock;
static bool g_isMinority = false;
static EtcdSessPool *g_etcdSessPool = NULL;
static uint32 g_etcdHealthCount = 0;
static EtcdServerSocket *g_allServerSocket = NULL;
static int64 g_waitTime = 0;
static volatile int64 g_waitForChangeTime = 0;

int32 EtcdNotifyStatus(DDB_ROLE ddbRole)
{
    (void)pthread_rwlock_wrlock(&g_notityCmsLock);
    write_runlog(LOG, "node(%u) last role is %d, ready to %d.\n",
        g_arbiCon->curInfo.nodeId, (int32)g_cmRole, (int32)ddbRole);
    g_cmRole = ddbRole;
    DdbNotifyStatusFunc ddbNotiSta = GetDdbStatusFunc();
    if (ddbNotiSta == NULL) {
        (void)pthread_rwlock_unlock(&g_notityCmsLock);
        return 0;
    }
    int32 res = ddbNotiSta(ddbRole);
    (void)pthread_rwlock_unlock(&g_notityCmsLock);
    return res;
}

static void EtcdNotifyPrimary(const char *str)
{
    write_runlog(LOG, "[%s]: pre_agent_count is %u, node(%u) cm role is %d, to primary.\n",
        str, g_arbiCon->getPreConnCount(), g_arbiCon->curInfo.nodeId, (int32)g_cmRole);
    (void)EtcdNotifyStatus(DDB_ROLE_LEADER);
}

static void EtcdNotifyStandby(const char *str)
{
    write_runlog(LOG, "[%s]: pre_agent_count is %u, node(%u) cm role is %d, to standby.\n",
        str, g_arbiCon->getPreConnCount(), g_arbiCon->curInfo.nodeId, (int32)g_cmRole);
    (void)EtcdNotifyStatus(DDB_ROLE_FOLLOWER);
}

static void InitPrimaryInfo()
{
    errno_t rc = snprintf_s(g_primaryKey, DDB_MAX_PATH_LEN, DDB_MAX_PATH_LEN - 1, "/%s/CMServer/primary_node_id",
        g_arbiCon->userName);
    securec_check_intval(rc, (void)rc);
    rc = snprintf_s(g_heartBeatKey, DDB_MAX_PATH_LEN, DDB_MAX_PATH_LEN - 1, "/%s/CMServer/heart_beat/%u",
        g_arbiCon->userName, g_arbiCon->curInfo.nodeId);
    securec_check_intval(rc, (void)rc);
}

void CheckHeartTimeout(int32 *printInterval, uint32 index)
{
    if (g_haHeartbeatTimeout[index] > 0) {
        printInterval[index] = MONITOR_WAIT_TIME;
        --g_haHeartbeatTimeout[index];
        return;
    }
    --printInterval[index];
    int32 logLevel = DEBUG1;
    if (printInterval[index] == 0) {
        logLevel = LOG;
        printInterval[index] = MONITOR_WAIT_TIME;
    }
    write_runlog(logLevel, "instanceId is %u, g_haHeartbeatTimeout[%u] is %d.\n",
        g_arbiCon->instInfo[index].instd, index, g_haHeartbeatTimeout[index]);
}

void *EtcdMonitorMain(void *argp)
{
    thread_name = "ETCD_MONITOR";
    write_runlog(LOG, "Starting ETCD monitor thread.\n");
    uint32 i = 0;
    int32 printInterval[PRIMARY_STANDBY_NUM];
    for (i = 0; i < PRIMARY_STANDBY_NUM; ++i) {
        printInterval[i] = MONITOR_WAIT_TIME;
    }
    for (;;) {
        for (i = 0; i < g_arbiCon->instNum; ++i) {
            if (g_isMinority) {
                write_runlog(LOG, "current cm in minority heartbeat is 0.\n");
                break;
            }
            CheckHeartTimeout(printInterval, i);
        }
        if (g_delayTimeout > 0) {
            --g_delayTimeout;
        }
        if (g_waitForChangeTime > 0) {
            --g_waitForChangeTime;
        }
        (void)sleep(1);
    }
    return NULL;
}

bool SetHeartbeatToEtcd()
{
    if (g_notifyEtcd == DDB_ROLE_FOLLOWER) {
        write_runlog(DEBUG1, "cms will be follwer, cannot set heartbeat to etcd.\n");
        return true;
    }
    char value[MAX_PATH_LEN] = {0};
    int rc = snprintf_s(value, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%d", g_haHeartBeat);
    securec_check_intval(rc, (void)rc);

    int etcdSetResult = etcd_set(g_etcdSess, g_heartBeatKey, value, NULL);
    if (etcdSetResult != (int32)ETCD_OK) {
        write_runlog(ERROR, "%d: etcd set failed. heartbeatKey=%s, value=%s, error is %s.\n",
            __LINE__, g_heartBeatKey, value, get_last_error());
        return false;
    }
    if (g_haHeartBeat >= MAX_VALUE_PRIMARY_HEARTBEAT) {
        /* for cm primary, heart beat begin at 1
         * when heart beat it bigger than MAX_VALUE_OF_CM_PRIMARY_HEARTBEAT, will start to 1. */
        g_haHeartBeat = 1;
    } else {
        ++g_haHeartBeat;
    }
    write_runlog(DEBUG1, "%d: heartbeat set. primary_key=%s, value=%s, g_cms_ha_heartbeat=%d \n",
        __LINE__, g_heartBeatKey, value, g_haHeartBeat);

    return true;
}

static status_t GetMemForHeartbeat()
{
    if (g_lastCmNum != g_arbiCon->instNum) {
        write_runlog(WARNING, "the cmNum(%u) is change to %u, free the g_keyValue.\n", g_lastCmNum, g_arbiCon->instNum);
        FREE_AND_RESET(g_keyValue);
        g_lastCmNum = g_arbiCon->instNum;
    }
    size_t len = sizeof(DrvKeyValue) * g_arbiCon->instNum;
    if (g_keyValue == NULL) {
        g_keyValue = (DrvKeyValue *)malloc(len);
        if (g_keyValue == NULL) {
            write_runlog(ERROR, "malloc keyValue failed, out of memory.\n");
            return CM_ERROR;
        }
    }
    errno_t rc = memset_s(g_keyValue, len, 0, len);
    securec_check_errno(rc, FREE_AND_RESET(g_keyValue));
    return CM_SUCCESS;
}

static bool GetEtcdPrimaryKey(uint32 *primaryNodeId, EtcdSession etcdSess, int32 logLevel)
{
    char primaryValue[MAX_PATH_LEN] = {0};
    GetEtcdOption getOption = {false, false, true};
    int32 etcdResult = etcd_get(etcdSess, g_primaryKey, primaryValue, DDB_MAX_PATH_LEN, &getOption);
    if (etcdResult != (int32)ETCD_OK) {
        const char *errNow = get_last_error();
        write_runlog(logLevel, "%d: etcd get failed, cannot get key(%s), value(%s), error is %s.\n",
            __LINE__, g_primaryKey, primaryValue, errNow);
        if (strstr(errNow, "can't find the key") != NULL) {
            if (primaryNodeId != NULL) {
                *primaryNodeId = 0;
            }
            return true;
        }
        return false;
    }
    write_runlog(DEBUG1, "%d: etcd get successfully, get key(%s), value(%s).\n", __LINE__, g_primaryKey, primaryValue);
    if (primaryNodeId != NULL) {
        *primaryNodeId = (uint32)strtol(primaryValue, NULL, 10);
    }
    return true;
}

static status_t CmSetPrimary2Etcd()
{
    char primaryValue[MAX_PATH_LEN] = {0};
    errno_t rc = snprintf_s(primaryValue, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%u", g_arbiCon->curInfo.nodeId);
    securec_check_intval(rc, (void)rc);
    const char *str = "[CmSetPrimary2Etcd]";
    write_runlog(LOG, "%s: node(%u) role is %d, ready to promote.\n", str, g_arbiCon->curInfo.nodeId, (int32)g_cmRole);
    int32 etcdSetResult = etcd_set(g_etcdSess, g_primaryKey, primaryValue, NULL);
    if (etcdSetResult != 0) {
        write_runlog(ERROR, "%s: etcd set failed, key=%s, value = %s, error is %s.\n", str, g_primaryKey, primaryValue,
            get_last_error());
        return CM_ERROR;
    } else {
        write_runlog(LOG, "%s: node(%u) last role is %d, promote to primary.\n",
            str, g_arbiCon->curInfo.nodeId, (int32)g_cmRole);
        EtcdNotifyPrimary("CmSetPrimary2Etcd");
        return CM_SUCCESS;
    }
}

static void CmPrimaryToStandbyInit(uint32 primaryNodeId)
{
    if (primaryNodeId != g_arbiCon->curInfo.nodeId) {
        EtcdNotifyStandby("CmPrimaryToStandbyInit");
        return;
    }
    SetEtcdOption setOption = {0};
    char preValue[MAX_PATH_LEN] = {0};
    errno_t rc = snprintf_s(preValue, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%u", primaryNodeId);
    securec_check_intval(rc, (void)rc);
    setOption.prevValue = preValue;
    char primaryValue[MAX_PATH_LEN] = {0};
    rc = snprintf_s(primaryValue, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%u", 0);
    securec_check_intval(rc, (void)rc);
    int32 etcdSetResult = etcd_set(g_etcdSess, g_primaryKey, primaryValue, &setOption);
    const char *str = "[CmPrimaryToStandbyInit]";
    if (etcdSetResult != (int32)ETCD_OK) {
        write_runlog(ERROR, "%s: etcd set failed, primary_key is %s, primary is %s, last value is %s.\n",
            str, g_primaryKey, primaryValue, preValue);
    } else {
        write_runlog(LOG, "%s: etcd set successfully, primary_key is %s, primary is %s, last value is %s.\n",
            str, g_primaryKey, primaryValue, preValue);
    }
    EtcdNotifyStandby("CmPrimaryToStandbyInit");
}

static void RecordHeartbeat(uint32 idx, int32 heartbeat, const char* key, const InstInfo *instInfo)
{
    const char *str = "[RecordHeartbeat]";
    if (heartbeat > 0) {
        if (g_delaySet == INSTANCE_ARBITRATE_DELAY_HAVE_SET) {
            write_runlog(LOG, "%s: node(%u) heart beat is %d from etcd, heart beat is %d from history, "
                "heartbeat is %d.\n", str, instInfo->nodeId, heartbeat,
                g_haHeartbeatFromEtcd[idx], g_haHeartbeatTimeout[idx]);
        }
        if (heartbeat - g_haHeartbeatFromEtcd[idx] != 0) {
            g_haHeartbeatTimeout[idx] = (int32)g_arbiCon->arbiCfg->haHeartBeatTimeOut;
        }
        g_haHeartbeatFromEtcd[idx] = heartbeat;
    } else {
        write_runlog(ERROR, "%s: get a unexpected heartbeat %d, key is %s.\n", str, heartbeat, key);
    }
    write_runlog(DEBUG1, "%s: idx is %u, key is %s, node(%u) heart beat: %d from etcd, heart beat: %d from history, "
        "heartbeat: %d.\n", str, idx, key, instInfo->nodeId, heartbeat, g_haHeartbeatFromEtcd[idx],
        g_haHeartbeatTimeout[idx]);
}

static status_t GetAllHeartbeatFromEtcd()
{
    status_t st = GetMemForHeartbeat();
    if (st != CM_SUCCESS) {
        return CM_ERROR;
    }
    char key[MAX_PATH_LEN] = {0};
    errno_t rc = snprintf_s(key, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/CMServer/heart_beat/", g_arbiCon->userName);
    securec_check_intval(rc, (void)rc);
    DrvText drvKey = {key, MAX_PATH_LEN};
    st = DrvEtcdGetAllKV((DrvCon_t)(&g_etcdSess), &drvKey, g_keyValue, g_arbiCon->instNum, NULL);
    if (st != CM_SUCCESS) {
        write_runlog(ERROR, "%d: etcd get failed. key=%s, error info is %s.\n", __LINE__, key, get_last_error());
        return CM_ERROR;
    }

    for (uint32 i = 0; i < g_arbiCon->instNum; ++i) {
        InstInfo *instInfo = &(g_arbiCon->instInfo[i]);
        rc = snprintf_s(key, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/CMServer/heart_beat/%u",
            g_arbiCon->userName, instInfo->nodeId);
        securec_check_intval(rc, (void)rc);
        for (uint32 j = 0; j < g_arbiCon->instNum; ++j) {
            write_runlog(DEBUG1, "i = %u, key is %s, g_keyValue[%u].key is %s.\n", i, key, j, g_keyValue[j].key);
            if (strcmp(key, g_keyValue[j].key) != 0) {
                continue;
            }
            int32 heartbeat = (int32)strtol(g_keyValue[j].value, NULL, 10);
            RecordHeartbeat(i, heartbeat, key, instInfo);
            break;
        }
    }
    return CM_SUCCESS;
}

static int32 GetHeartbeatOfPrimaryFromEtcd(uint32 primaryNodeId)
{
    if (primaryNodeId == 0) {
        return -1;
    }
    for (uint32 i = 0; i < g_arbiCon->instNum; ++i) {
        if (g_arbiCon->instInfo[i].nodeId == primaryNodeId) {
            int32 logLevel = DEBUG1;
            if (g_haHeartbeatTimeout[i] <= 0) {
                logLevel = LOG;
            }
            write_runlog(logLevel, "idx is %u, primary(%u) ha heartbeat is %d.\n",
                i, primaryNodeId, g_haHeartbeatTimeout[i]);
            return g_haHeartbeatTimeout[i];
        }
    }
    return -1;
}

static void RestPreAgentConn(uint32 primaryNodeId)
{
    if (primaryNodeId == 0) {
        return;
    }
    if (g_delaySet == INSTANCE_ARBITRATE_DELAY_NO_SET) {
        g_arbiCon->resetPreConn();
    }
}

static void SetArbiDelay(uint32 curInstIdx, bool isNeedSet)
{
    if (g_delaySet != INSTANCE_ARBITRATE_DELAY_NO_SET && isNeedSet) {
        return;
    }
    DdbArbiCfg *arbiCfg = g_arbiCon->arbiCfg;
    (void)pthread_rwlock_wrlock(&(arbiCfg->lock));
    g_delaySet = isNeedSet ? INSTANCE_ARBITRATE_DELAY_HAVE_SET : INSTANCE_ARBITRATE_DELAY_NO_SET;
    g_delayTimeout = arbiCfg->arbiDelayBaseTimeOut + curInstIdx * arbiCfg->arbiDelayIncrementalTimeOut;
    (void)pthread_rwlock_unlock(&(arbiCfg->lock));
}

static bool FindMinCmId(uint32 primaryNodeId)
{
    uint32 minNodId = 0;
    uint32 nodeIdx = 0;
    uint32 minNodeIdForCmId = 0;
    for (uint32 i = 0; i < g_arbiCon->instNum; ++i) {
        InstInfo *instInfo = &(g_arbiCon->instInfo[i]);
        write_runlog(LOG, "idx=%u, node=%u, instId is %u, heartbeat=%d, etcdHeartbeat=%d, primaryNodeId=%u.\n",
            i, instInfo->nodeId, instInfo->instd, g_haHeartbeatTimeout[i], g_haHeartbeatFromEtcd[i], primaryNodeId);
        if (g_haHeartbeatTimeout[i] > 0 && primaryNodeId != instInfo->nodeId) {
            minNodId = instInfo->nodeId;
            nodeIdx = i;
            minNodeIdForCmId = instInfo->instd;
            break;
        }
    }
    write_runlog(LOG, "minNodeId=%u, nodeIndex=%u, currentNode=%u, role=%d, minNodeIdForCmId=%u.\n",
        minNodId, nodeIdx, g_arbiCon->curInfo.nodeId, (int32)g_cmRole, minNodeIdForCmId);
    if (minNodId == g_arbiCon->curInfo.nodeId) {
        write_runlog(LOG, "find the min cm id=%u, the cm could be the best primary.\n", minNodId);
        return true;
    }
    return false;
}

static int32 DelayArbiTimeout(uint32 primaryNodeId, uint32 curInstIdx)
{
    write_runlog(LOG, "g_pre_agent_conn_count=%u, primaryNodeId is %u, curInstIdx is %u, g_cmRole is %d, "
        "g_delayTimeout is %u.\n",
        g_arbiCon->getPreConnCount(), primaryNodeId, curInstIdx, (int32)g_cmRole, g_delayTimeout);
    if (g_arbiCon->curInfo.isVoteAz) {
        return 0;
    }
    if (g_cmRole == DDB_ROLE_LEADER) {
        write_runlog(LOG, "current note(%u) role is primary, but primaryNodeId(%u) is not it, "
            "so this note can promote primary.\n", g_arbiCon->curInfo.nodeId, primaryNodeId);
        return 1;
    }
    if (g_arbiCon->getPreConnCount() >= 1) {
        if (FindMinCmId(primaryNodeId)) {
            SetArbiDelay(curInstIdx, false);
            write_runlog(LOG, "cm_delay_arbitrate_time_out End: server_node_index = %u, g_pre_agent_conn_count=%u, "
                "g_cmRole is %d.\n", curInstIdx, g_arbiCon->getPreConnCount(), (int32)g_cmRole);
            return 1;
        } else if (g_delayTimeout <= 1) {
            ++g_promoteDelayCount;
            if (g_promoteDelayCount >= CM_PRMOTE_DELAT_COUNT) {
                SetArbiDelay(curInstIdx, false);
                write_runlog(LOG, "cm_delay_arbitrate_time_out End: arbitrate_delay_time_out = %u\n", g_delayTimeout);
                g_promoteDelayCount = 0;
                return 1;
            }
        }
    }
    if (g_delayTimeout <= 1) {
        write_runlog(LOG, "local role is %d, pre conn count is %u\n", (int32)g_cmRole, g_arbiCon->getPreConnCount());
    }
    write_runlog(DEBUG1, "cm_server_delay_arbitrate_time_out Running: arbitrate_delay_time_out = %u, "
        "cm_server_node_index = %u\n", g_delayTimeout, curInstIdx);
    return 0;
}

static void Choose2BePrimary(uint32 primaryNodeId, uint32 curInstIdx)
{
    if (primaryNodeId == g_arbiCon->curInfo.nodeId) {
        return;
    }
    SetArbiDelay(curInstIdx, true);
    int32 res = DelayArbiTimeout(primaryNodeId, curInstIdx);
    if (res == 1) {
        status_t st = CmSetPrimary2Etcd();
        if (st != CM_SUCCESS) {
            if (g_cmRole == DDB_ROLE_LEADER) {
                write_runlog(LOG, "[Choose2BePrimary]: found cms double primary, current node is not primary_key and"
                    "turn to standby, and reset the cn notify msg.\n");
                EtcdNotifyStandby("CmSetPrimary2Etcd");
            }
        }
    } else {
        if (g_cmRole != DDB_ROLE_FOLLOWER && g_cmRole != DDB_ROLE_LEADER && g_arbiCon->getPreConnCount() < 1) {
            const char *str = "[Choose2BePrimary]";
            write_runlog(LOG, "%s: current node is %u, g_cmRole is %d, pre_agent_conn is %u, primaryNodeId is %u, "
                "curInstIdx is %u.\n", str, g_arbiCon->curInfo.nodeId, (int32)g_cmRole, g_arbiCon->getPreConnCount(),
                primaryNodeId, curInstIdx);
            EtcdNotifyStandby("Choose2BePrimary");
        }
    }
}

static void RestDelaySet(uint32 primaryNodeId)
{
    /* if some cm recovers before timeout expired,  HA thread resets the arbitrate time out. */
    if (g_delaySet == INSTANCE_ARBITRATE_DELAY_HAVE_SET) {
        write_runlog(LOG, "clean cm delay arbitrate, primary is %u.\n", primaryNodeId);
        g_delaySet = INSTANCE_ARBITRATE_DELAY_NO_SET;
        g_delayTimeout = ARBITRATE_DELAY_CYCLE_MAX_COUNT;
    }
}

static void Direct2BePrimary(uint32 primaryNodeId)
{
    static bool isChangeToStandby = false;
    const char *str = "[Direct2BePrimary]";
    write_runlog(LOG, "pre con count is %u.\n", g_arbiCon->getPreConnCount());
    if (g_arbiCon->getPreConnCount() >= 1) {
        write_runlog(LOG, "%s: primaryNodeId is current node(%u), cm role is %d, pre_agent_conn is %u, to primary.\n",
            str, g_arbiCon->curInfo.nodeId, (int32)g_cmRole, g_arbiCon->getPreConnCount());
        EtcdNotifyPrimary("Direct2BePrimary");
        isChangeToStandby = false;
    } else {
        /* wait for a turn, if the pre_agent_conn is also 0, and then set 0 to etcd. */
        if (!isChangeToStandby) {
            write_runlog(LOG, "%s: wait a turn to set key(0) to etcd, pre_agent_conn is 0.\n", str);
        }
        if (isChangeToStandby) {
            isChangeToStandby = false;
            write_runlog(LOG, "%s: current node is %u, failed to change it's role(standby) to primary, "
                "because pre_agent_conn is 0, set key to 0.\n", str, g_arbiCon->curInfo.nodeId);
            CmPrimaryToStandbyInit(primaryNodeId);
        }
        isChangeToStandby = true;
        if (g_cmRole != DDB_ROLE_FOLLOWER) {
            write_runlog(LOG, "%s: the primaryNode is current node(%u), but pre_agent_conn is 0, and cm role is %d, "
                "so only set to standby.\n", str, g_arbiCon->curInfo.nodeId, (int32)g_cmRole);
            EtcdNotifyStandby("Direct2BePrimary");
        }
    }
}

static void CheckCurrentIsPrimary(uint32 primaryNodeId)
{
    if (g_cmRole == DDB_ROLE_LEADER) {
        if (g_arbiCon->curInfo.isVoteAz) {
            const char *str = "[CheckCurrentIsPrimary]";
            write_runlog(LOG, "%s: current node(%u) is voteAz, and current role is primary, set key to 0.\n",
                str, g_arbiCon->curInfo.nodeId);
            CmPrimaryToStandbyInit(primaryNodeId);
        }
        return;
    }
    Direct2BePrimary(primaryNodeId);
}

static void CmArbitrateStart(uint32 primaryNodeId)
{
    uint32 curInstIdx = g_arbiCon->curInfo.instIdx;
    status_t st = GetAllHeartbeatFromEtcd();
    if (st != CM_SUCCESS) {
        write_runlog(ERROR, "cannot get all cm_server heartbeat from etcd, cms cannot promote primary.\n");
        return;
    }
    int32 heartBeatOfPrimary = GetHeartbeatOfPrimaryFromEtcd(primaryNodeId);
    if (heartBeatOfPrimary <= 0) {
        RestPreAgentConn(primaryNodeId);
        write_runlog(LOG, "cmserver on node(%u) is down, heartbeat_of_primary=%d, and then choose to promte primary.\n",
            primaryNodeId, heartBeatOfPrimary);
        Choose2BePrimary(primaryNodeId, curInstIdx);
        return;
    }
    /* etcd has no primary key. */
    if (primaryNodeId == 0) {
        return;
    }
    RestDelaySet(primaryNodeId);
    if (primaryNodeId == g_arbiCon->curInfo.nodeId) {
        CheckCurrentIsPrimary(primaryNodeId);
    } else {
        if (g_cmRole != DDB_ROLE_FOLLOWER) {
            write_runlog(LOG, "primaryNodeId(%u) is not current node(%u), and cm role is %d, to standby.\n",
                primaryNodeId, g_arbiCon->curInfo.nodeId, (int32)g_cmRole);
            EtcdNotifyStandby("CmArbitrateStart");
        }
    }
}

static void Promote2Primary(uint32 primaryNodeId, const char *str)
{
    if (primaryNodeId != g_arbiCon->curInfo.nodeId) {
        write_runlog(LOG, "%s, current node is %u, will change it's role(%d) to primary.\n",
            str, g_arbiCon->curInfo.nodeId, (int32)g_cmRole);
        (void)CmSetPrimary2Etcd();
    }
    if (g_cmRole != DDB_ROLE_LEADER) {
        write_runlog(LOG, "%s: node(%u) cm_server role is %d, to primary.\n",
            str, g_arbiCon->curInfo.nodeId, (int32)g_cmRole);
        EtcdNotifyPrimary("CheckIsInMinority");
    }
}

static bool CheckIsInMinority(uint32 primaryNodeId)
{
    if (!g_isMinority) {
        return false;
    }
    write_runlog(LOG, "current node is %u, will change it's role(%d) to minority primary.\n",
        g_arbiCon->curInfo.nodeId, (int32)g_cmRole);
    Promote2Primary(primaryNodeId, "[CheckIsInMinority]");
    write_runlog(DEBUG1, "current node is %u, it's in minority, must be primary.\n", g_arbiCon->curInfo.nodeId);
    return true;
}

static bool HaveNotifyEtcd(uint32 primaryNodeId)
{
    if (g_notifyEtcd == DDB_ROLE_UNKNOWN) {
        return false;
    }
    write_runlog(LOG, "g_notifyEtcd is %d, primaryNodeId is %u, curnodeId is %u will notify etcd, g_waitForChangeTime "
        "is %ld.\n", (int)g_notifyEtcd, primaryNodeId, g_arbiCon->curInfo.nodeId, g_waitForChangeTime);
    if (g_notifyEtcd == DDB_ROLE_FOLLOWER && (primaryNodeId == g_arbiCon->curInfo.nodeId)) {
        write_runlog(LOG, "receive notify msg, it will change to standby, and set key(0) to etcd.\n");
        CmPrimaryToStandbyInit(primaryNodeId);
    } else if (g_notifyEtcd == DDB_ROLE_LEADER && (primaryNodeId != g_arbiCon->curInfo.nodeId)) {
        write_runlog(LOG, "receive notify msg, it will change to primary, and set key(%u) to etcd.\n",
            g_arbiCon->curInfo.nodeId);
        Promote2Primary(primaryNodeId, "[HaveNotifyEtcd]");
    }
    // wait for all cms can be promoted, in order to prevent two-cms turn.
    if (g_waitForChangeTime > 0) {
        write_runlog(LOG, "receive notify msg, it will change to %d, and time is %ld.\n", (int32)g_notifyEtcd,
            g_waitForChangeTime);
        return true;
    }
    (void)pthread_rwlock_wrlock(&g_notifyEtcdLock);
    g_notifyEtcd = DDB_ROLE_UNKNOWN;
    (void)pthread_rwlock_unlock(&g_notifyEtcdLock);
    return true;
}

static bool NotifyEtcd2ChangeRole(uint32 primaryNodeId)
{
    bool res = CheckIsInMinority(primaryNodeId);
    if (res) {
        return true;
    }
    res = HaveNotifyEtcd(primaryNodeId);
    return res;
}

static void CmNormalArbitrate()
{
    if (g_delaySet == INSTANCE_ARBITRATE_DELAY_HAVE_SET) {
        write_runlog(LOG, "end to get health count of etcd when delay have set.\n");
    }
    uint32 primaryNodeId = 0;
    bool res = GetEtcdPrimaryKey(&primaryNodeId, g_etcdSess, ERROR);
    if (!res) {
        write_runlog(ERROR, "cannot get the primary, and primary key is %s.\n", g_primaryKey);
        return;
    }
    res = NotifyEtcd2ChangeRole(primaryNodeId);
    if (res) {
        return;
    }
    if (g_delaySet == INSTANCE_ARBITRATE_DELAY_HAVE_SET) {
        write_runlog(LOG, "begin to get new primary when delay have set.\n");
    }
    CmArbitrateStart(primaryNodeId);
    if (g_delaySet == INSTANCE_ARBITRATE_DELAY_HAVE_SET) {
        write_runlog(LOG, "end to get new primary when delay have set.\n");
    }
    write_runlog(DEBUG5, "local role is %d.\n", (int32)g_cmRole);
}

static void UpdateEtcdServerSocket(EtcdServerSocket *serverList, ServerSocket *serverSocket)
{
    serverList->host = serverSocket->host;
    serverList->port = (unsigned short)serverSocket->port;
}

static status_t GetEtcdSession(EtcdSession *sess, EtcdServerSocket *serverList, int32 timeOut)
{
    if (etcd_open(sess, serverList, &g_etcdTlsPath, timeOut) != 0) {
        write_runlog(ERROR, "open etcd server failed: %s.\n", get_last_error());
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t DrvEtcdRestConn(DrvCon_t sess, int32 timeOut)
{
    if (g_allServerSocket == NULL) {
        write_runlog(ERROR, "g_allServerSocket is NULL, cannot reset etcd conn.\n");
        return CM_SUCCESS;
    }
    write_runlog(LOG, "cannot interacter with etcd, begin to reset etcd Session.\n");
    EtcdSession *etcdSess = (EtcdSession *)sess;
    (void)etcd_close(*etcdSess);
    (void)pthread_rwlock_wrlock(&g_checkEtcdSessLock);
    uint32 etcdNum = g_etcdHealthCount;
    (void)pthread_rwlock_unlock(&g_checkEtcdSessLock);
    status_t st = CM_SUCCESS;
    if (etcdNum == 0) {
        write_runlog(ERROR, "etcdnum is zero, open etcd session with all etcd serverList.\n");
        st = GetEtcdSession(etcdSess, g_allServerSocket, timeOut);
        return st;
    }
    size_t len = sizeof(EtcdServerSocket) * (etcdNum + 1);
    EtcdServerSocket *serverList = (EtcdServerSocket *)malloc(len);
    if (serverList == NULL) {
        write_runlog(ERROR, "serverList is NULL.\n");
        return CM_SUCCESS;
    }
    errno_t rc = memset_s(serverList, len, 0, len);
    securec_check_errno(rc, FREE_AND_RESET(serverList));
    uint32 num = 0;
    for (uint32 i = 0; i < g_etcdNum; ++i) {
        if (num >= etcdNum) {
            break;
        }
        (void)pthread_rwlock_wrlock(&g_checkEtcdSessLock);
        if (g_etcdSessPool[i].nodeState.health == DDB_STATE_HEALTH) {
            UpdateEtcdServerSocket(&serverList[num], &g_etcdInfo[i]);
            ++num;
        }
        (void)pthread_rwlock_unlock(&g_checkEtcdSessLock);
    }
    serverList[num].host = NULL;
    st = GetEtcdSession(etcdSess, serverList, timeOut);
    FREE_AND_RESET(serverList);
    if (st != CM_SUCCESS) {
        write_runlog(LOG, "cannot interacter with etcd, failed to reset etcd Session.\n");
        return CM_ERROR;
    }
    write_runlog(LOG, "cannot interacter with etcd, success to reset etcd Session.\n");
    return st;
}

void *EtcdHaMain(void *argp)
{
    thread_name = "ETCD_HA";
    struct timespec checkBeginFunction = {0, 0};
    struct timespec checkEndFunction = {0, 0};
    write_runlog(LOG, "Starting ETCD HA thread.\n");
    uint32 twoSec = 2;
    uint32 sleepInterval = 0;
    for (uint32 i = 0; i < g_arbiCon->instNum; ++i) {
        g_haHeartbeatTimeout[i] = (int32)g_arbiCon->arbiCfg->haHeartBeatTimeOut;
    }
    uint32 checkEtcdCount = 0;
    status_t checkEtcdSessSt = CM_SUCCESS;
    uint32 mins = 0;
    for (;;) {
        (void)clock_gettime(CLOCK_MONOTONIC, &checkBeginFunction);
        sleepInterval = g_arbiCon->arbiCfg->haStatusInterval;
        if (g_delaySet == INSTANCE_ARBITRATE_DELAY_HAVE_SET) {
            write_runlog(LOG, "begin to get health count of etcd when delay have set.\n");
        }
        if (checkEtcdSessSt == CM_SUCCESS && SetHeartbeatToEtcd()) {
            g_healthEtcdCountForPreConn = g_etcdNum;
        } else {
            write_runlog(ERROR, "cm set heartBeat failed.\n");
            g_healthEtcdCountForPreConn = 0;
        }
        if (g_healthEtcdCountForPreConn == g_etcdNum) {
            CmNormalArbitrate();
        } else {
            /* will update etcdsession every 2 times, or checkEtcdSessSt != CM_SUCCESS */
            if (checkEtcdCount >= 1 || checkEtcdSessSt != CM_SUCCESS) {
                checkEtcdSessSt = DrvEtcdRestConn((DrvCon_t)&g_etcdSess, g_timeOut);
                checkEtcdCount = 0;
            }
            ++checkEtcdCount;
        }
        (void)clock_gettime(CLOCK_MONOTONIC, &checkEndFunction);
        mins = (uint32)(checkEndFunction.tv_sec - checkBeginFunction.tv_sec);
        if (mins > twoSec) {
            write_runlog(LOG, "it takes %u to etcd arbitrate.\n", mins);
        } else {
            (void)sleep(sleepInterval);
        }
    }
    return NULL;
}

static status_t CreateMonitorThread()
{
    pthread_t thrId;
    int32 res = pthread_create(&thrId, NULL, EtcdMonitorMain, NULL);
    if (res != 0) {
        write_runlog(ERROR, "Failed to create EtcdMonitorMain.\n");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t CreateEtcdHaThread()
{
    pthread_t thrId;
    int32 res = pthread_create(&thrId, NULL, EtcdHaMain, NULL);
    if (res != 0) {
        write_runlog(ERROR, "Failed to create EtcdMonitorMain.\n");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t CreateEtcdSessionPool()
{
    if (g_etcdInfo == NULL) {
        return CM_ERROR;
    }
    const uint32 serverLen = 2;
    status_t st = CM_SUCCESS;
    for (uint32 i = 0; i < g_etcdNum; ++i) {
        EtcdServerSocket server[serverLen] = {{0}};
        server[0].host = g_etcdInfo[i].host;
        server[0].port = (unsigned short)g_etcdInfo[i].port;
        server[1].host = NULL;
        st = GetEtcdSession(&g_etcdSessPool[i].sess, server, g_timeOut);
        if (st != CM_SUCCESS) {
            for (uint32 j = 0; j < i; ++j) {
                (void)etcd_close(g_etcdSessPool[i].sess);
                g_etcdSessPool[i].nodeState.health = DDB_STATE_DOWN;
            }
            return CM_ERROR;
        }
        g_etcdSessPool[i].nodeState.health = DDB_STATE_HEALTH;
    }
    return CM_SUCCESS;
}

static status_t InitEtcdSesionPool()
{
    static uint32 etcdNum = 0;
    static status_t st = CM_SUCCESS;
    if (etcdNum == g_etcdNum && g_etcdSessPool != NULL && st == CM_SUCCESS) {
        return CM_SUCCESS;
    }
    if (etcdNum != g_etcdNum) {
        write_runlog(WARNING, "will reset etcdSessPool, because etcdNum is %u, g_etcdNum is %u.\n", etcdNum, g_etcdNum);
        FREE_AND_RESET(g_etcdSessPool);
        etcdNum = g_etcdNum;
    }
    if (g_etcdSessPool == NULL) {
        size_t len = sizeof(EtcdSessPool) * g_etcdNum;
        g_etcdSessPool = (EtcdSessPool *)malloc(len);
        if (g_etcdSessPool == NULL) {
            write_runlog(ERROR, "g_etcdSessPool is NULL.\n");
            return CM_ERROR;
        }
        errno_t rc = memset_s(g_etcdSessPool, len, 0, len);
        securec_check_errno(rc, FREE_AND_RESET(g_etcdSessPool));
    }
    st = CreateEtcdSessionPool();
    return st;
}

static void UpdateEtcdSessPool(DDB_STATE dbState, uint32 idx)
{
    write_runlog(LOG, "update etcd(%s) health from %d to %d.\n",
        g_etcdInfo[idx].nodeInfo.nodeName, (int32)g_etcdSessPool[idx].nodeState.health, (int32)dbState);
    (void)pthread_rwlock_wrlock(&g_checkEtcdSessLock);
    g_etcdSessPool[idx].nodeState.health = dbState;
    if (dbState == DDB_STATE_HEALTH) {
        if (g_etcdHealthCount < g_etcdNum) {
            ++g_etcdHealthCount;
        }
    } else {
        if (g_etcdHealthCount > 0) {
            --g_etcdHealthCount;
        }
    }
    (void)pthread_rwlock_unlock(&g_checkEtcdSessLock);
}

static void *CheckEtcdHealthMain(void *argp)
{
    thread_name = "ETCD_HEALTH";
    struct timespec checkBeginFunction = {0, 0};
    struct timespec checkEndFunction = {0, 0};
    const uint32 waitTime = (g_etcdNum / 2 + 1) * ((uint32)g_timeOut);
    write_runlog(LOG, "Starting ETCD HEALTH thread, etcdNum is %u, timeout is %d, waitTime is %u.\n",
        g_etcdNum, g_timeOut, waitTime);
    status_t st = CM_SUCCESS;
    bool res = false;
    g_etcdHealthCount = g_etcdNum;
    uint32 mins = 0;
    for (;;) {
        (void)clock_gettime(CLOCK_MONOTONIC, &checkBeginFunction);
        st = InitEtcdSesionPool();
        if (st != CM_SUCCESS) {
            (void)sleep(1);
            continue;
        }
        for (uint32 i = 0; i < g_etcdNum; ++i) {
            res = GetEtcdPrimaryKey(NULL, g_etcdSessPool[i].sess, DEBUG1);
            if (!res && g_etcdSessPool[i].nodeState.health == DDB_STATE_HEALTH) {
                UpdateEtcdSessPool(DDB_STATE_DOWN, i);
            } else if (res && g_etcdSessPool[i].nodeState.health == DDB_STATE_DOWN) {
                UpdateEtcdSessPool(DDB_STATE_HEALTH, i);
            }
        }
        (void)clock_gettime(CLOCK_MONOTONIC, &checkEndFunction);
        mins = (uint32)(checkEndFunction.tv_sec - checkBeginFunction.tv_sec);
        if (mins >= waitTime) {
            write_runlog(LOG, "it takes %u to etcd check.\n", mins);
        } else {
            (void)sleep(1);
        }
    }
    return NULL;
}

static status_t CreateCheckEtcdHealthThread()
{
    pthread_t thrId;
    int32 res = pthread_create(&thrId, NULL, CheckEtcdHealthMain, NULL);
    if (res != 0) {
        write_runlog(ERROR, "Failed to create CheckEtcdHealthMain.\n");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t InitNotifyLock()
{
    int32 ret = pthread_rwlock_init(&(g_notifyEtcdLock), NULL);
    if (ret != 0) {
        write_runlog(ERROR, "init g_notifyEtcdLock failed.\n");
        return CM_ERROR;
    }
    ret = pthread_rwlock_init(&(g_notityCmsLock), NULL);
    if (ret != 0) {
        write_runlog(ERROR, "init g_notityCmsLock failed.\n");
        return CM_ERROR;
    }
    ret = pthread_rwlock_init(&(g_checkEtcdSessLock), NULL);
    if (ret != 0) {
        write_runlog(ERROR, "init g_checkEtcdSessLock failed.\n");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t InitThreadInfo(const DrvApiInfo *apiInfo)
{
    g_arbiCon = apiInfo->cmsArbiCon;
    g_lastCmNum = g_arbiCon->instNum;
    g_waitTime = apiInfo->client_t.waitTime;
    status_t st = InitEtcdServerSocket(&g_allServerSocket, apiInfo);
    if (st != CM_SUCCESS) {
        write_runlog(ERROR, "failed to init g_allServerSocket.\n");
        return CM_ERROR;
    }
    st = InitNotifyLock();
    if (st != CM_SUCCESS) {
        write_runlog(ERROR, "failed to init notify lock.\n");
        return CM_ERROR;
    }
    InitPrimaryInfo();
    return CM_SUCCESS;
}

status_t CreateEtcdThread(const DrvApiInfo *apiInfo)
{
    int32 logLevel = (apiInfo->modId == MOD_CMS) ? ERROR : DEBUG5;
    if (apiInfo->modId != MOD_CMS) {
        write_runlog(logLevel, "mod is %d, cannot create etcdTheard.\n", (int32)MOD_CMS);
        return CM_SUCCESS;
    }
    if (g_etcdNum == 0) {
        write_runlog(logLevel, "g_etcdNum is 0, cannot create etcdTheard.\n");
        return CM_SUCCESS;
    }
    write_runlog(LOG, "cms will init g_allServerSocket.\n");
    status_t st = InitEtcdServerSocket(&g_allServerSocket, apiInfo);
    if (st != CM_SUCCESS) {
        write_runlog(ERROR, "failed to init g_allServerSocket.\n");
        return CM_ERROR;
    }
    if (apiInfo->cmsArbiCon == NULL) {
        write_runlog(logLevel, "cmsArbiCon is NULL, cannot create etcdTheard.\n");
        return CM_SUCCESS;
    }
    st = InitThreadInfo(apiInfo);
    if (st != CM_SUCCESS) {
        write_runlog(ERROR, "failed to init Thread Info.\n");
        return CM_ERROR;
    }
    st = CreateEtcdSession(&g_etcdSess, apiInfo);
    if (st != CM_SUCCESS) {
        write_runlog(logLevel, "failed to Create Etcd Session.\n");
        return CM_ERROR;
    }
    write_runlog(logLevel, "line %s:%d successfully get g_etcdSess(%d).\n", __FUNCTION__, __LINE__, g_etcdSess);
    st = CreateMonitorThread();
    if (st != CM_SUCCESS) {
        write_runlog(logLevel, "failed to Create Monitor Thread.\n");
        return CM_ERROR;
    }
    st = CreateCheckEtcdHealthThread();
    if (st != CM_SUCCESS) {
        write_runlog(logLevel, "failed to Create Check Etcd Health Thread.\n");
        return CM_ERROR;
    }
    st = CreateEtcdHaThread();
    if (st != CM_SUCCESS) {
        write_runlog(logLevel, "failed to Create etcd Ha Thread.\n");
    }
    return st;
}

void DrvNotifyEtcd(DDB_ROLE dbRole)
{
    if (g_cmRole != dbRole) {
        write_runlog(LOG, "receive notify msg, it will set g_notifyEtcd(%d) to %d, g_cmRole is %d.\n",
            (int32)g_notifyEtcd, (int32)dbRole, (int32)g_cmRole);
        (void)pthread_rwlock_wrlock(&g_notifyEtcdLock);
        g_notifyEtcd = dbRole;
        g_waitForChangeTime = g_waitTime;
        (void)pthread_rwlock_unlock(&g_notifyEtcdLock);
        write_runlog(LOG, "receive notify msg, it has set g_notifyEtcd(%d) to %d, g_cmRole is %d.\n",
            (int32)g_notifyEtcd, (int32)dbRole, (int32)g_cmRole);
        (void)EtcdNotifyStatus(dbRole);
    }
}

void DrvEtcdSetMinority(bool isMinority)
{
    g_isMinority = isMinority;
}
