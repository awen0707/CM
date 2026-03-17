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
 * cms_disk_check.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_server/cms_disk_check.cpp
 *
 * -------------------------------------------------------------------------
 */

#include "cm_server.h"
#include "cms_alarm.h"
#include "cms_ddb.h"
#include "cms_global_params.h"
#include "cms_common.h"
#include "cms_disk_check.h"

#ifdef ENABLE_UT
#define static
#endif

typedef enum {
    NOT_READ_ONLY_AND_DDB_0,
    NOT_READ_ONLY_AND_DDB_1,
    NOT_READ_ONLY_AND_DDB_2,
    NOT_READ_ONLY_AND_DDB_3,
    READ_ONLY_AND_DDB_0,
    READ_ONLY_AND_DDB_1,
    READ_ONLY_AND_DDB_2,
    READ_ONLY_AND_DDB_3,
    READ_ONLY_INIT_STATE,
    READ_ONLY_STATE_MAX
} ReadOnlyFsmState;

typedef enum {
    DISK_USAGE_INIT,
    DISK_USAGE_NORMAL,
    DISK_USAGE_EXCEEDS_THRESHOLD,
    READ_ONLY_EVENT_MAX
} ReadOnlyFsmEvent;

typedef enum {
    DO_NOTING,
    SET_DDB_0,
    SET_DDB_1,
    SET_DDB_2,
    SET_DDB_3,
    SET_READ_ONLY_ON,
    SET_READ_ONLY_OFF,
    RECORD_MANUALLY_SET_READ_ONLY,
    SET_DDB_1_CONDITIONAL,
    RECORD_INIT_STATE,
    READ_ONLY_ACT_MAX
} ReadOnlyFsmAct;

typedef struct {
    ReadOnlyFsmAct action;
    AlarmType alarmType;
} ReadOnlyFsmEntry;

typedef bool (*ReadOnlyFsmActFunc)(DataNodeReadOnlyInfo *instance);
static ReadOnlyFsmActFunc g_readOnlyActFunc[READ_ONLY_ACT_MAX] = {0};
static bool g_allHealth = true;

bool CheckReadOnlyStatusAll()
{
    if (!IsBoolCmParamTrue(g_enableSetReadOnly)) {
        return false;
    }

    for (uint32 i = 0; i < g_node_num; i++) {
        if (g_dynamicNodeReadOnlyInfo[i].coordinateNode.readOnly == READ_ONLY_ON) {
            return true;
        }
        for (uint32 j = 0; j < g_dynamicNodeReadOnlyInfo[i].dataNodeCount; j++) {
            uint32 groupIdx = g_dynamicNodeReadOnlyInfo[i].dataNode[j].groupIndex;
            int memberIdx = g_dynamicNodeReadOnlyInfo[i].dataNode[j].memberIndex;
            if (IsCurInstIdCascadeStandby(groupIdx, memberIdx)) {
                continue;
            }
            if (g_dynamicNodeReadOnlyInfo[i].dataNode[j].readOnly == READ_ONLY_ON) {
                return true;
            }
        }
    }
    return false;
}

bool CheckReadOnlyStatus(uint32 groupIdx, int memberIdx)
{
    if (!IsBoolCmParamTrue(g_enableSetReadOnly)) {
        return false;
    }
    if (IsCurInstIdCascadeStandby(groupIdx, memberIdx)) {
        return false;
    }
    cm_instance_report_status *repStatus = &(g_instance_group_report_status_ptr[groupIdx].instance_status);
    if (g_instance_role_group_ptr[groupIdx].instanceMember[memberIdx].instanceType == INSTANCE_TYPE_COORDINATE) {
        if (repStatus->coordinatemember.readOnly != NULL) {
            return repStatus->coordinatemember.readOnly->readOnly == READ_ONLY_ON;
        }
    }
    if (g_instance_role_group_ptr[groupIdx].instanceMember[memberIdx].instanceType == INSTANCE_TYPE_DATANODE) {
        if (repStatus->data_node_member[memberIdx].readOnly != NULL) {
            return repStatus->data_node_member[memberIdx].readOnly->readOnly == READ_ONLY_ON;
        }
    }
    return false;
}

bool IsReadOnlyFinalState(uint32 groupIdx, int memberIdx, ReadOnlyState expectedState)
{
    if (!IsBoolCmParamTrue(g_enableSetReadOnly)) {
        return false;
    }
    const char *str = expectedState == READ_ONLY_ON ? "read only" : "not read only";
    cm_instance_report_status *repStatus = &(g_instance_group_report_status_ptr[groupIdx].instance_status);
    uint32 instanceId = g_instance_role_group_ptr[groupIdx].instanceMember[memberIdx].instanceId;
    int instanceType = g_instance_role_group_ptr[groupIdx].instanceMember[memberIdx].instanceType;
    if (instanceType == INSTANCE_TYPE_COORDINATE) {
        if (repStatus->coordinatemember.readOnly == NULL) {
            return false;
        }
        if (repStatus->coordinatemember.readOnly->readOnly == expectedState &&
            repStatus->coordinatemember.readOnly->finalState) {
            write_runlog(LOG, "[%s] instance %u is in %s final state\n", __FUNCTION__, instanceId, str);
            return true;
        }
    }
    if (instanceType == INSTANCE_TYPE_DATANODE) {
        if (repStatus->data_node_member[memberIdx].readOnly->readOnly == expectedState &&
            repStatus->data_node_member[memberIdx].readOnly->finalState) {
            write_runlog(LOG, "[%s] instance %u is in %s final state\n", __FUNCTION__, instanceId, str);
            return true;
        }
    }

    return false;
}

static bool IsReadOnlySetByCM(uint32 groupIdx, int memberIdx)
{
    DataNodeReadOnlyInfo *dnInfo =
        g_instance_group_report_status_ptr[groupIdx].instance_status.data_node_member[memberIdx].readOnly;
    if (dnInfo->ddbValue == READ_ONLY_ALREADY && dnInfo->readOnly == READ_ONLY_ON) {
        write_runlog(LOG, "[%s] instanceId: %u was set read only by cm\n", __FUNCTION__,
            g_instance_role_group_ptr[groupIdx].instanceMember[memberIdx].instanceId);
        return true;
    }
    return false;
}

static void InitDnReadOnlyInfo(DataNodeReadOnlyInfo *instance, uint32 i, uint32 j)
{
    instance->instanceId = g_node[i].datanode[j].datanodeId;
    instance->dataDiskUsage = INVALID_DISK_USAGE;
    instance->vgdataDiskUsage = 0;
    instance->vglogDiskUsage = 0;
    instance->ddbValue = READ_ONLY_DDB_INIT;
    instance->node = g_node[i].node;
    instance->finalState = false;
    instance->readOnly = READ_ONLY_INIT;
    instance->instanceType = INSTANCE_TYPE_DATANODE;
    errno_t rc = strncpy_s(instance->dataNodePath, CM_PATH_LENGTH,
        g_node[i].datanode[j].datanodeLocalDataPath, CM_PATH_LENGTH - 1);
    securec_check_errno(rc, (void)rc);
    rc = strncpy_s(instance->nodeName, CM_NODE_NAME, g_node[i].nodeName, CM_NODE_NAME - 1);
    securec_check_errno(rc, (void)rc);
    rc = snprintf_s(instance->instanceName, CM_NODE_NAME, CM_NODE_NAME - 1, "dn_%u", g_node[i].datanode[j].datanodeId);
    securec_check_intval(rc, (void)rc);
    (void)find_node_in_dynamic_configure(instance->node, instance->instanceId, &instance->groupIndex,
        &instance->memberIndex);
    g_instance_group_report_status_ptr[instance->groupIndex].instance_status.data_node_member[instance->memberIndex]
        .readOnly = instance;
}

static void InitCnReadOnlyInfo(DataNodeReadOnlyInfo *instance, uint32 i)
{
    instance->instanceId = g_node[i].coordinateId;
    instance->dataDiskUsage = INVALID_DISK_USAGE;
    instance->ddbValue = READ_ONLY_DDB_INIT;
    instance->node = g_node[i].node;
    instance->finalState = false;
    instance->readOnly = READ_ONLY_INIT;
    instance->instanceType = INSTANCE_TYPE_COORDINATE;
    errno_t rc = strncpy_s(instance->dataNodePath, CM_PATH_LENGTH, g_node[i].DataPath, CM_PATH_LENGTH - 1);
    securec_check_errno(rc, (void)rc);
    rc = strncpy_s(instance->nodeName, CM_NODE_NAME, g_node[i].nodeName, CM_NODE_NAME - 1);
    securec_check_errno(rc, (void)rc);
    rc = snprintf_s(instance->instanceName, CM_NODE_NAME, CM_NODE_NAME - 1, "cn_%u", g_node[i].coordinateId);
    securec_check_intval(rc, (void)rc);
    (void)find_node_in_dynamic_configure(instance->node, instance->instanceId, &instance->groupIndex,
        &instance->memberIndex);
    g_instance_group_report_status_ptr[instance->groupIndex].instance_status.coordinatemember.readOnly = instance;
}

void UpdateNodeReadonlyInfo()
{
    for (uint32 i = 0; i < g_node_num; ++i) {
        DynamicNodeReadOnlyInfo *curNodeInfo = &g_dynamicNodeReadOnlyInfo[i];
        curNodeInfo->dataNodeCount = g_node[i].datanodeCount;
        curNodeInfo->logDiskUsage = 0;
        errno_t rc = snprintf_s(curNodeInfo->instanceName, CM_NODE_NAME, CM_NODE_NAME - 1,
            "%s", g_node[i].nodeName);
        securec_check_intval(rc, FREE_AND_RESET(g_dynamicNodeReadOnlyInfo));
        for (uint32 j = 0; j < g_dynamicNodeReadOnlyInfo[i].dataNodeCount; j++) {
            DataNodeReadOnlyInfo *curdn = &curNodeInfo->dataNode[j];
            InitDnReadOnlyInfo(curdn, i, j);
        }
        if (g_node[i].coordinate == 1) {
            DataNodeReadOnlyInfo *curCn = &curNodeInfo->coordinateNode;
            InitCnReadOnlyInfo(curCn, i);
        }
    }
}

void ResetReadOnlyInfo(DataNodeReadOnlyInfo *instance)
{
    instance->dataDiskUsage = INVALID_DISK_USAGE;
    instance->ddbValue = 0;
    instance->finalState = false;
    instance->readOnly = READ_ONLY_INIT;
}

void ResetNodeReadonlyInfo()
{
    for (uint32 i = 0; i < g_node_num; ++i) {
        DynamicNodeReadOnlyInfo *curNodeInfo = &g_dynamicNodeReadOnlyInfo[i];
        curNodeInfo->logDiskUsage = 0;
        for (uint32 j = 0; j < g_dynamicNodeReadOnlyInfo[i].dataNodeCount; j++) {
            DataNodeReadOnlyInfo *curdn = &curNodeInfo->dataNode[j];
            ResetReadOnlyInfo(curdn);
        }
        if (g_node[i].coordinate == 1) {
            DataNodeReadOnlyInfo *curCn = &curNodeInfo->coordinateNode;
            ResetReadOnlyInfo(curCn);
        }
    }
}

static DynamicNodeReadOnlyInfo* AllocDynamicNodeReadOnlyInfo()
{
    size_t bufSize = sizeof(DynamicNodeReadOnlyInfo) * CM_NODE_MAXNUM;
    DynamicNodeReadOnlyInfo* buf = (DynamicNodeReadOnlyInfo*)malloc(bufSize);
    if (buf == NULL) {
        write_runlog(ERROR, "[%s] malloc failed!\n", __FUNCTION__);
        return NULL;
    }
    errno_t rc = memset_s(buf, bufSize, 0, bufSize);
    securec_check_errno(rc, (void)rc);
    return buf;
}

static int InitNodeReadonlyInfo()
{
    g_dynamicNodeReadOnlyInfo = AllocDynamicNodeReadOnlyInfo();
    if (g_dynamicNodeReadOnlyInfo == NULL) {
        return -1;
    }

    for (uint32 i = 0; i < g_node_num; ++i) {
        DynamicNodeReadOnlyInfo *curNodeInfo = &g_dynamicNodeReadOnlyInfo[i];
        curNodeInfo->dataNodeCount = g_node[i].datanodeCount;
        curNodeInfo->logDiskUsage = 0;
        errno_t rc = snprintf_s(curNodeInfo->instanceName, sizeof(curNodeInfo->instanceName),
            sizeof(curNodeInfo->instanceName) - 1, "%s", g_node[i].nodeName);
        securec_check_intval(rc, FREE_AND_RESET(g_dynamicNodeReadOnlyInfo));
        for (uint32 j = 0; j < g_dynamicNodeReadOnlyInfo[i].dataNodeCount; j++) {
            DataNodeReadOnlyInfo *curdn = &curNodeInfo->dataNode[j];
            InitDnReadOnlyInfo(curdn, i, j);
        }
        if (g_node[i].coordinate == 1) {
            DataNodeReadOnlyInfo *curCn = &curNodeInfo->coordinateNode;
            InitCnReadOnlyInfo(curCn, i);
        }
    }
    return 0;
}

static ReadOnlyFsmEvent GetReadOnlyFsmEvent(const DataNodeReadOnlyInfo *instance)
{
    if (instance->dataDiskUsage == INVALID_DISK_USAGE) {
        return DISK_USAGE_INIT;
    } else if (g_dnArbitrateMode == SHARE_DISK && instance->vgdataDiskUsage == 0) {
        return DISK_USAGE_INIT;
    } else if (instance->vgdataDiskUsage >= g_readOnlyThreshold ||
        instance->vglogDiskUsage >= g_readOnlyThreshold ||
        (instance->dataDiskUsage >= (int)g_readOnlyThreshold &&
        (g_dnArbitrateMode != SHARE_DISK || g_ss_enable_check_sys_disk_usage))) {
        g_allHealth = false;
        return DISK_USAGE_EXCEEDS_THRESHOLD;
    } else {
        return DISK_USAGE_NORMAL;
    }
}

static ReadOnlyFsmState GetReadOnlyFsmState(const DataNodeReadOnlyInfo *instance)
{
    if (instance->readOnly == READ_ONLY_ON) {
        switch (instance->ddbValue) {
            case READ_ONLY_DDB_INIT:
                return READ_ONLY_AND_DDB_0;
            case READ_ONLY_EXPECT:
                return READ_ONLY_AND_DDB_1;
            case READ_ONLY_ALREADY:
                return READ_ONLY_AND_DDB_2;
            case READ_ONLY_NOT_EXPECT:
                return READ_ONLY_AND_DDB_3;
            case READ_ONLY_DDB_MAX:
            default:
                return READ_ONLY_INIT_STATE;
        }
    } else if (instance->readOnly == READ_ONLY_OFF) {
        switch (instance->ddbValue) {
            case READ_ONLY_DDB_INIT:
                return NOT_READ_ONLY_AND_DDB_0;
            case READ_ONLY_EXPECT:
                return NOT_READ_ONLY_AND_DDB_1;
            case READ_ONLY_ALREADY:
                return NOT_READ_ONLY_AND_DDB_2;
            case READ_ONLY_NOT_EXPECT:
                return NOT_READ_ONLY_AND_DDB_3;
            case READ_ONLY_DDB_MAX:
            default:
                return READ_ONLY_INIT_STATE;
        }
    }
    return READ_ONLY_INIT_STATE;
}

static ReadOnlyFsmEntry g_readOnlyEntry[READ_ONLY_EVENT_MAX][READ_ONLY_STATE_MAX] = {
    /* DISK_USAGE_INIT */
    {
        {RECORD_INIT_STATE, ALM_AT_Resume},    /* NOT_READ_ONLY_AND_DDB_0 */
        {RECORD_INIT_STATE, ALM_AT_Resume},    /* NOT_READ_ONLY_AND_DDB_1 */
        {RECORD_INIT_STATE, ALM_AT_Resume},    /* NOT_READ_ONLY_AND_DDB_2 */
        {RECORD_INIT_STATE, ALM_AT_Resume},    /* NOT_READ_ONLY_AND_DDB_3 */
        {RECORD_INIT_STATE, ALM_AT_Resume},    /* READ_ONLY_AND_DDB_0 */
        {RECORD_INIT_STATE, ALM_AT_Resume},    /* READ_ONLY_AND_DDB_1 */
        {RECORD_INIT_STATE, ALM_AT_Resume},    /* READ_ONLY_AND_DDB_2 */
        {RECORD_INIT_STATE, ALM_AT_Resume},    /* READ_ONLY_AND_DDB_3 */
        {RECORD_INIT_STATE, ALM_AT_Resume},    /* READ_ONLY_INIT_STATE */
    },
    /* DISK_USAGE_NORMAL */
    {
        {DO_NOTING, ALM_AT_Resume},                     /* NOT_READ_ONLY_AND_DDB_0 */
        {SET_READ_ONLY_ON, ALM_AT_Resume},              /* NOT_READ_ONLY_AND_DDB_1 */
        {SET_DDB_0, ALM_AT_Resume},                     /* NOT_READ_ONLY_AND_DDB_2 */
        {SET_DDB_0, ALM_AT_Resume},                     /* NOT_READ_ONLY_AND_DDB_3 */
        {SET_DDB_1_CONDITIONAL, ALM_AT_Resume},         /* READ_ONLY_AND_DDB_0 */
        {SET_DDB_3, ALM_AT_Resume},             		/* READ_ONLY_AND_DDB_1 */
        {SET_DDB_3, ALM_AT_Resume},             		/* READ_ONLY_AND_DDB_2 */
        {SET_READ_ONLY_OFF, ALM_AT_Resume},             /* READ_ONLY_AND_DDB_3 */
        {RECORD_INIT_STATE, ALM_AT_Resume},    /* READ_ONLY_INIT_STATE */
    },
    /* DISK_USAGE_EXCEEDS_THRESHOLD */
    {
        {SET_DDB_1, ALM_AT_Resume},                    /* NOT_READ_ONLY_AND_DDB_0 */
        {SET_READ_ONLY_ON, ALM_AT_Resume},             /* NOT_READ_ONLY_AND_DDB_1 */
        {SET_DDB_1, ALM_AT_Resume},             		/* NOT_READ_ONLY_AND_DDB_2 */
        {SET_DDB_1, ALM_AT_Resume},             		/* NOT_READ_ONLY_AND_DDB_3 */
        {RECORD_MANUALLY_SET_READ_ONLY, ALM_AT_Fault}, /* READ_ONLY_AND_DDB_0 */
        {SET_DDB_2, ALM_AT_Fault},                     /* READ_ONLY_AND_DDB_1 */
        {DO_NOTING, ALM_AT_Fault},                     /* READ_ONLY_AND_DDB_2 */
        {SET_READ_ONLY_OFF, ALM_AT_Fault},             /* READ_ONLY_AND_DDB_3 */
        {RECORD_INIT_STATE, ALM_AT_Resume},    /* READ_ONLY_INIT_STATE */
    },
};

static ReadOnlyFsmEntry ReadOnlyFsmGetEntryPtr(ReadOnlyFsmEvent event, ReadOnlyFsmState state)
{
    return g_readOnlyEntry[event][state];
}

static bool ReadOnlyFsmActRun(ReadOnlyFsmAct action, DataNodeReadOnlyInfo *instance)
{
    ReadOnlyFsmActFunc actionFunc = g_readOnlyActFunc[action];
    if (actionFunc != NULL && !g_isPauseArbitration) {
        return actionFunc(instance);
    }
    return false;
}

static bool ReadOnlyFsmExecute(DataNodeReadOnlyInfo *instance)
{
    ReadOnlyFsmEvent event = GetReadOnlyFsmEvent(instance);
    ReadOnlyFsmState state = GetReadOnlyFsmState(instance);

    ReadOnlyFsmEntry entry = ReadOnlyFsmGetEntryPtr(event, state);

    bool haveAction = ReadOnlyFsmActRun(entry.action, instance);
    ReportReadOnlyAlarm(entry.alarmType, instance->instanceName, instance->instanceId);
    return haveAction;
}

static bool CheckAndSetReadOnly()
{
    g_allHealth = true;
    bool haveAction = false;
    for (uint32 i = 0; i < g_node_num; i++) {
        DynamicNodeReadOnlyInfo *curNodeInfo = &g_dynamicNodeReadOnlyInfo[i];
        /* CN */
        if (g_node[i].coordinate == 1) {
            DataNodeReadOnlyInfo *curCn = &curNodeInfo->coordinateNode;
            haveAction |= ReadOnlyFsmExecute(curCn);
        }
        /* DN */
        for (uint32 j = 0; j < curNodeInfo->dataNodeCount; j++) {
            DataNodeReadOnlyInfo *curDn = &curNodeInfo->dataNode[j];
            haveAction |= ReadOnlyFsmExecute(curDn);
        }
    }

    if (g_allHealth) {
        isNeedCancel = false;
    } else {
        isNeedCancel = true;
    }
    return haveAction;
}

static void PreAlarmForNodeThreshold()
{
    const uint32 preAlarmThreshhold = (g_readOnlyThreshold * 4) / 5;
    
    write_runlog(DEBUG1, "[%s] Starting check for disk alarm, preAlarmThreshhold=%u.\n",
        __FUNCTION__, preAlarmThreshhold);
    for (uint32 i = 0; i < g_node_num; i++) {
        DynamicNodeReadOnlyInfo *curNodeInfo = &g_dynamicNodeReadOnlyInfo[i];
        /* log usage */
        if (curNodeInfo->logDiskUsage >= preAlarmThreshhold) {
            write_runlog(LOG, "[%s] [logDisk usage] Pre Alarm threshold reached, node=%u, log_disk_usage=%u.\n",
                __FUNCTION__, g_node[i].node, curNodeInfo->logDiskUsage);
            ReportLogStorageAlarm(ALM_AT_Fault, curNodeInfo->instanceName, i);
        } else {
            ReportLogStorageAlarm(ALM_AT_Resume, curNodeInfo->instanceName, i);
        }
        /* CN */
        if (g_node[i].coordinate == 1) {
            DataNodeReadOnlyInfo *curCn = &curNodeInfo->coordinateNode;
            if (curCn->dataDiskUsage >= (int)preAlarmThreshhold) {
                write_runlog(LOG, "[%s] [dataDisk usage] Pre Alarm threshold reached, instanceId=%u, usage=%u\n",
                    __FUNCTION__, curCn->instanceId, curCn->dataDiskUsage);
                ReportReadOnlyPreAlarm(ALM_AT_Fault, curCn->instanceName, curCn->instanceId);
            } else {
                ReportReadOnlyPreAlarm(ALM_AT_Resume, curCn->instanceName, curCn->instanceId);
            }
        }
        /* DN */
        for (uint32 j = 0; j < curNodeInfo->dataNodeCount; j++) {
            DataNodeReadOnlyInfo *curDn = &curNodeInfo->dataNode[j];
            if (curDn->dataDiskUsage >= (int)preAlarmThreshhold || curDn->vgdataDiskUsage >= preAlarmThreshhold ||
                curDn->vglogDiskUsage >= preAlarmThreshhold) {
                write_runlog(LOG, "[%s] [dataDisk usage] Pre Alarm threshold reached, instanceId=%u,"
                    "disk_usage=%u, shared_disk_usage_for_data=%u, shared_disk_usage_for_log=%u.\n",
                    __FUNCTION__,  curDn->instanceId, curDn->dataDiskUsage,
                    curDn->vgdataDiskUsage, curDn->vglogDiskUsage);
                ReportReadOnlyPreAlarm(ALM_AT_Fault, curDn->instanceName, curDn->instanceId);
            } else {
                ReportReadOnlyPreAlarm(ALM_AT_Resume, curDn->instanceName, curDn->instanceId);
            }
        }
    }
}

static bool IsStorageDetectContinue()
{
    bool isEnable = IsBoolCmParamTrue(g_enableSetReadOnly);
    bool isPrimary = g_HA_status->local_role == CM_SERVER_PRIMARY;
    bool isNeedSyncDdb = IsNeedSyncDdb();
    bool isNotUpgrade = undocumentedVersion == 0;
    return (isEnable && isPrimary && isNeedSyncDdb && isNotUpgrade);
}

bool IsCurrentPrimaryDn(uint32 groupIdx, int memberIdx)
{
    if (g_instance_role_group_ptr[groupIdx].instanceMember[memberIdx].instanceType == INSTANCE_TYPE_COORDINATE) {
        return false;
    }
    return g_instance_role_group_ptr[groupIdx].instanceMember[memberIdx].role == INSTANCE_ROLE_PRIMARY;
}

void SetGroupDdbTo1(uint32 groupIdx, int memberIdx)
{
    cm_instance_role_group *curRoleGroup = &g_instance_role_group_ptr[groupIdx];
    for (int i = 0; i < curRoleGroup->count; i++) {
        if (i == memberIdx) {
            continue;
        }
        DataNodeReadOnlyInfo *instance =
            g_instance_group_report_status_ptr[groupIdx].instance_status.data_node_member[i].readOnly;
        instance->ddbValue = READ_ONLY_EXPECT;
        write_runlog(LOG, "[%s] instance %u will synchronize read-only from primary, set ddb to 1\n",
            __FUNCTION__, instance->instanceId);
    }
}

static void GetReadOnlyCmd(char *command, size_t commandLen, const DataNodeReadOnlyInfo *instance, bool readOnly)
{
    errno_t rc = snprintf_s(command, commandLen, commandLen - 1,
        "gs_guc reload -Z %s -N %s -D %s -c 'default_transaction_read_only = %s'",
        instance->instanceType == INSTANCE_TYPE_DATANODE ? "datanode" : "coordinator",
        instance->nodeName, instance->dataNodePath, readOnly ? "on" : "off");
    securec_check_intval(rc, (void)rc);
}

bool ReadOnlyActDoNoting(DataNodeReadOnlyInfo *instance)
{
    if (instance->dataDiskUsage >= (int)g_readOnlyThreshold || instance->vgdataDiskUsage >= g_readOnlyThreshold ||
        instance->vglogDiskUsage >= g_readOnlyThreshold) {
        write_runlog(LOG, "[%s] instance %u is transaction read only, disk_usage:%u,"
            "shared_disk_usage_for_data:%u, shared_disk_usage_for_log:%u, read_only_threshold:%u\n",
            __FUNCTION__, instance->instanceId, instance->dataDiskUsage,
            instance->vgdataDiskUsage, instance->vglogDiskUsage, g_readOnlyThreshold);
    }
    instance->finalState = true;
    return false;
}

bool ReadOnlyActSetDdbTo0(DataNodeReadOnlyInfo *instance)
{
    write_runlog(LOG, "[%s] instance %u is not read only, ddb is %d, need set ddb to 0,"
        "disk_usage:%u, shared_disk_usage_for_data:%u, shared_disk_usage_for_log:%u, read_only_threshold:%u\n",
        __FUNCTION__, instance->instanceId, (int)instance->ddbValue, instance->dataDiskUsage,
        instance->vgdataDiskUsage, instance->vglogDiskUsage, g_readOnlyThreshold);
    instance->ddbValue = READ_ONLY_DDB_INIT;
    instance->finalState = false;
    return true;
}

bool ReadOnlyActSetDdbTo1(DataNodeReadOnlyInfo *instance)
{
    write_runlog(LOG, "[%s] instance %u is not read only, ddb is %d, need set ddb to 1,"
        " disk_usage:%u, shared_disk_usage_for_data:%u, shared_disk_usage_for_log:%u, read_only_threshold:%u\n",
        __FUNCTION__, instance->instanceId, (int)instance->ddbValue, instance->dataDiskUsage,
        instance->vgdataDiskUsage, instance->vglogDiskUsage, g_readOnlyThreshold);
    instance->ddbValue = READ_ONLY_EXPECT;
    instance->finalState = false;
    return true;
}

bool ReadOnlyActSetDdbTo2(DataNodeReadOnlyInfo *instance)
{
    write_runlog(LOG, "[%s] instance %u is not read only, ddb is %d, need set ddb to 2,"
        " disk_usage:%u, shared_disk_usage_for_data:%u, shared_disk_usage_for_log:%u, read_only_threshold:%u\n",
        __FUNCTION__, instance->instanceId, (int)instance->ddbValue, instance->dataDiskUsage,
        instance->vgdataDiskUsage, instance->vglogDiskUsage, g_readOnlyThreshold);
    instance->ddbValue = READ_ONLY_ALREADY;
    instance->finalState = false;
    return true;
}

bool ReadOnlyActSetDdbTo3(DataNodeReadOnlyInfo *instance)
{
    write_runlog(LOG, "[%s] instance %u is not read only, ddb is %d, need set ddb to 3,"
        " disk_usage:%u, shared_disk_usage_for_data:%u, shared_disk_usage_for_log:%u, read_only_threshold:%u\n",
        __FUNCTION__, instance->instanceId, (int)instance->ddbValue, instance->dataDiskUsage,
        instance->vgdataDiskUsage, instance->vglogDiskUsage, g_readOnlyThreshold);
    instance->ddbValue = READ_ONLY_NOT_EXPECT;
    instance->finalState = false;
    return true;
}

bool ReadOnlyActSetReadOnlyOn(DataNodeReadOnlyInfo *instance)
{
    write_runlog(LOG, "[%s] instance %u is not read only and ddb is 1, set default_transaction_read_only on,"
        " disk_usage:%u, shared_disk_usage_for_data:%u, shared_disk_usage_for_log:%u, read_only_threshold:%u\n",
        __FUNCTION__, instance->instanceId, instance->dataDiskUsage,
        instance->vgdataDiskUsage, instance->vglogDiskUsage, g_readOnlyThreshold);

    instance->finalState = false;
    if (IsCurrentPrimaryDn(instance->groupIndex, instance->memberIndex)) {
        SetGroupDdbTo1(instance->groupIndex, instance->memberIndex);
    }
    char command[CM_MAX_COMMAND_LEN] = {0};
    GetReadOnlyCmd(command, sizeof(command), instance, true);
    int ret = system(command);
    if (ret == 0) {
        write_runlog(LOG, "[%s] instance %u set default_transaction_read_only on is success\n",
            __FUNCTION__, instance->instanceId);
        return true;
    } else {
        write_runlog(ERROR, "[%s] instance %u set default_transaction_read_only on is failed, errno=%d\n",
            __FUNCTION__, instance->instanceId, errno);
        return false;
    }
}

bool ReadOnlyActSetReadOnlyOff(DataNodeReadOnlyInfo *instance)
{
    write_runlog(LOG, "[%s] instance %u is read only and ddb is 3, set default_transaction_read_only off,"
        " disk_usage:%u, shared_disk_usage_for_data:%u, shared_disk_usage_for_log:%u, read_only_threshold:%u\n",
        __FUNCTION__, instance->instanceId, instance->dataDiskUsage,
        instance->vgdataDiskUsage, instance->vglogDiskUsage, g_readOnlyThreshold);

    instance->finalState = false;
    char command[CM_MAX_COMMAND_LEN] = {0};
    GetReadOnlyCmd(command, sizeof(command), instance, false);
    int ret = system(command);
    if (ret == 0) {
        write_runlog(LOG, "[%s] instance %u set default_transaction_read_only off is success\n",
            __FUNCTION__, instance->instanceId);
        return true;
    } else {
        write_runlog(ERROR, "[%s] instance %u set default_transaction_read_only off is failed, errno=%d\n",
            __FUNCTION__, instance->instanceId, errno);
        return false;
    }
}

bool IsGroupReadOnly(uint32 groupIdx)
{
    cm_instance_role_group *curRoleGroup = &g_instance_role_group_ptr[groupIdx];
    for (int i = 0; i< curRoleGroup->count; i++) {
        if (IsReadOnlySetByCM(groupIdx, i)) {
            return true;
        }
    }
    return false;
}

bool ReadOnlyActRecordManuallySetReadOnly(DataNodeReadOnlyInfo *instance)
{
    write_runlog(WARNING, "[%s] instance %u set read only manually, disk_usage:%u,"
        "shared_disk_usage_for_data:%u, shared_disk_usage_for_log:%u, read_only_threshold:%u\n",
        __FUNCTION__, instance->instanceId, instance->dataDiskUsage,
        instance->vgdataDiskUsage, instance->vglogDiskUsage, g_readOnlyThreshold);
    instance->ddbValue = 1;
    instance->finalState = false;
    return false;
}

bool ReadOnlyActSetDdbTo1Conditional(DataNodeReadOnlyInfo *instance)
{
    write_runlog(WARNING, "[%s] instance %u set read only manually, disk_usage:%u,"
        "shared_disk_usage_for_data:%u, shared_disk_usage_for_log:%u, read_only_threshold:%u\n",
        __FUNCTION__, instance->instanceId, instance->dataDiskUsage,
        instance->vgdataDiskUsage, instance->vglogDiskUsage, g_readOnlyThreshold);

    instance->finalState = false;
    if (instance->instanceType == INSTANCE_TYPE_COORDINATE) {
        return false;
    }
    if (IsGroupReadOnly(instance->groupIndex)) {
        write_runlog(WARNING, "[%s] instance %u sync read only from primary, set ddb to 1\n",
            __FUNCTION__, instance->instanceId);
        /* Primary is set to read-only by cm, means total group is set to read-only by the CM */
        instance->ddbValue = READ_ONLY_NOT_EXPECT;
        return true;
    }
    return false;
}

bool ReadOnlyActRecordDiskUsageAbnormal(DataNodeReadOnlyInfo *instance)
{
    write_runlog(WARNING, "[%s] instance %u disk usage abnormal, disk_usage:%u,"
        "shared_disk_usage_for_data:%u, shared_disk_usage_for_log:%u, read_only_threshold:%u\n",
        __FUNCTION__, instance->instanceId, instance->dataDiskUsage,
        instance->vgdataDiskUsage, instance->vglogDiskUsage, g_readOnlyThreshold);
    instance->finalState = false;
    return false;
}

static void InitReadOnlyFsmActFunc()
{
    g_readOnlyActFunc[DO_NOTING] = ReadOnlyActDoNoting;
    g_readOnlyActFunc[SET_DDB_0] = ReadOnlyActSetDdbTo0;
    g_readOnlyActFunc[SET_DDB_1] = ReadOnlyActSetDdbTo1;
    g_readOnlyActFunc[SET_DDB_2] = ReadOnlyActSetDdbTo2;
    g_readOnlyActFunc[SET_DDB_3] = ReadOnlyActSetDdbTo3;
    g_readOnlyActFunc[SET_READ_ONLY_ON] = ReadOnlyActSetReadOnlyOn;
    g_readOnlyActFunc[SET_READ_ONLY_OFF] = ReadOnlyActSetReadOnlyOff;
    g_readOnlyActFunc[RECORD_MANUALLY_SET_READ_ONLY] = ReadOnlyActRecordManuallySetReadOnly;
    g_readOnlyActFunc[SET_DDB_1_CONDITIONAL] = ReadOnlyActSetDdbTo1Conditional;
    g_readOnlyActFunc[RECORD_INIT_STATE] = ReadOnlyActRecordDiskUsageAbnormal;
}

void* StorageDetectMain(void* arg)
{
    thread_name = "StorageDetect";
    pthread_t threadId = pthread_self();
    write_runlog(LOG, "Storage detect thread start, threadid %lu.\n", threadId);

    InitReadOnlyFsmActFunc();
    int ret = InitNodeReadonlyInfo();
    if (ret != 0) {
        write_runlog(ERROR, "[%s] initialize datanode readonly status failed!\n", __FUNCTION__);
        return NULL;
    }
    const int sleepInterval = 2;
    bool needReset = false;

    for (;;) {
        if (!IsStorageDetectContinue()) {
            cm_sleep(datastorage_threshold_check_interval);
            needReset = true;
            continue;
        }
        if (needReset) {
            ResetNodeReadonlyInfo();
            needReset = false;
        }
        if (GetNodeReadOnlyStatusFromDdb() != CM_SUCCESS) {
            cm_sleep(datastorage_threshold_check_interval);
            continue;
        }
        PreAlarmForNodeThreshold();
        bool haveAction = CheckAndSetReadOnly();
        SetNodeReadOnlyStatusToDdb();
        /* If the updated ddb or set read-only, the fsm needs to be executed immediately after a round of reporting */
        if (haveAction) {
            cm_sleep(sleepInterval);
            continue;
        }
        cm_sleep(datastorage_threshold_check_interval);
    }
}
