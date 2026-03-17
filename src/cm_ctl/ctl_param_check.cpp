/*-------------------------------------------------------------------------
*
* Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
*
* Description: show help information of cm_ctl
*
* Filename: /cm_ctl/ctl_param_check.cpp
*
* -------------------------------------------------------------------------
 */

#include <cmath>
#include <cstdlib>
#include "securec.h"
#include "cm_misc.h"
#include "securec_check.h"
#include "cm/libpq-fe.h"
#include "ctl_common.h"
#include "cjson/cJSON.h"

const char *g_cmaParamInfo[] = {
    "log_dir|string|0,0|NULL|NULL|",
    "log_file_size|int|0,2047|MB|NULL|",
    "log_min_messages|enum|debug5,debug1,log,warning,error,fatal|NULL|NULL|",
    "incremental_build|bool|0,0|NULL|NULL|",
    "security_mode|bool|0,0|NULL|NULL|",
    "upgrade_from|int|0,4294967295|NULL|For upgrading, specify which version we are upgrading from.|",
    "alarm_component|string|0,0|NULL|NULL|",
    "agent_report_interval|int|0,2147483647|NULL|NULL|",
    "agent_heartbeat_timeout|int|2,2147483647|NULL|NULL|",
    "agent_connect_timeout|int|0,2147483647|NULL|NULL|",
    "agent_connect_retries|int|0,2147483647|NULL|NULL|",
    "agent_kill_instance_timeout|int|0,2147483647|NULL|NULL|",
    "alarm_report_interval|int|0,2147483647|NULL|NULL|",
    "alarm_report_max_count|int|1,2592000|NULL|NULL|",
    "agent_check_interval|int|0,2147483647|NULL|NULL|",
    "enable_log_compress|bool|0,0|NULL|NULL|",
    "enable_ssl|bool|0,0|NULL|NULL|",
    "ssl_cert_expire_alert_threshold|int|7,180|NULL|NULL|",
    "ssl_cert_expire_check_interval|int|0,2147483647|NULL|NULL|",
    "process_cpu_affinity|int|0,2|NULL|Only the ARM architecture is supported.|",
    "enable_xc_maintenance_mode|bool|0,0|NULL|NULL|",
    "log_threshold_check_interval|int|0,2147483647|NULL|NULL|",
    "log_max_size|int|0,2147483647|NULL|NULL|",
    "log_max_count|int|0,10000|NULL|NULL|",
    "log_saved_days|int|0,1000|NULL|NULL|",
    "agent_phony_dead_check_interval|int|0,2147483647|NULL|NULL|",
    "unix_socket_directory|string|0,0|NULL|NULL|",
    "dilatation_shard_count_for_disk_capacity_alarm|int|0,2147483647|NULL|NULL|",
    "enable_dcf|bool|0,0|NULL|NULL|",
    "disaster_recovery_type|int|0,2|NULL|NULL|",
    "agent_backup_open|int|0,2|NULL|NULL|",
    "enable_e2e_rto|int|0,1|NULL|NULL|",
    "disk_timeout|int|0,2147483647|NULL|NULL|",
    "voting_disk_path|string|0,0|NULL|NULL|",
    "agent_rhb_interval|int|0,2147483647|NULL|NULL|",
#ifndef ENABLE_MULTIPLE_NODES
    "enable_fence_dn|string|0,0|NULL|NULL|",
#else
    "enable_cn_auto_repair|bool|0,0|NULL|NULL|",
    "enable_gtm_phony_dead_check|int|0,1|NULL|NULL|",
    "environment_threshold|string|0,0|NULL|NULL|",
#endif
    "db_service_vip|string|0,0|NULL|NULL|",
    "event_triggers|string|0,0|NULL|NULL|",
    "ss_double_cluster_mode|int|0,2|NULL|NULL|",
};

const char *g_cmsParamInfo[] = {
    "log_dir|string|0,0|NULL|NULL|",
    "log_file_size|int|0,2047|MB|NULL|",
    "log_min_messages|enum|debug5,debug1,log,warning,error,fatal|NULL|NULL|",
    "thread_count|int|2,1000|NULL|NULL|",
    "instance_heartbeat_timeout|int|1,2147483647|NULL|NULL|",
    "instance_failover_delay_timeout|int|0,2147483647|NULL|NULL|",
    "cmserver_ha_connect_timeout|int|0,2147483647|NULL|NULL|",
    "cmserver_ha_heartbeat_timeout|int|1,2147483647|NULL|NULL|",
    "cmserver_ha_status_interval|int|1,2147483647|NULL|NULL|",
    "cmserver_self_vote_timeout|int|0,2147483647|NULL|NULL|",
    "phony_dead_effective_time|int|1,2147483647|NULL|NULL|",
    "cm_server_arbitrate_delay_base_time_out|int|0,2147483647|NULL|NULL|",
    "cm_server_arbitrate_delay_incrememtal_time_out|int|0,2147483647|NULL|NULL|",
    "alarm_component|string|0,0|NULL|NULL|",
    "alarm_report_interval|int|0,2147483647|NULL|NULL|",
    "alarm_report_max_count|int|1,2592000|NULL|NULL|",
    "instance_keep_heartbeat_timeout|int|0,2147483647|NULL|NULL|",
    "az_switchover_threshold|int|1,100|NULL|NULL|",
    "az_check_and_arbitrate_interval|int|1,2147483647|NULL|NULL|",
    "az_connect_check_interval|int|1,2147483647|NULL|NULL|",
    "az_connect_check_delay_time|int|1,2147483647|NULL|NULL|",
    "cmserver_demote_delay_on_etcd_fault|int|1,2147483647|NULL|NULL|",
    "instance_phony_dead_restart_interval|int|0,2147483647|NULL|NULL|",
    "enable_transaction_read_only|bool|0,0|NULL|NULL|",
    "datastorage_threshold_check_interval|int|1,2592000|NULL|NULL|",
    "datastorage_threshold_value_check|int|1,99|NULL|NULL|",
    "ss_enable_check_sys_disk_usage|bool|0,0|NULL|NULL|",
    "max_datastorage_threshold_check|int|1,2592000|NULL|NULL|",
    "enable_az_auto_switchover|int|0,1|NULL|NULL|",
    "cm_auth_method|enum|trust,gss|NULL|NULL|",
    "cm_krb_server_keyfile|string|0,0|NULL|NULL|",
    "switch_rto|int|60,2147483647|NULL|NULL|",
    "force_promote|int|0,1|NULL|NULL|",
    "backup_open|int|0,2|NULL|NULL|",
    "enable_dcf|bool|0,0|NULL|NULL|",
    "ddb_type|int|0,1|NULL|NULL|",
    "enable_ssl|bool|0,0|NULL|NULL|",
    "ssl_cert_expire_alert_threshold|int|7,180|NULL|NULL|",
    "ssl_cert_expire_check_interval|int|0,2147483647|NULL|NULL|",
    "delay_arbitrate_timeout|int|0,2147483647|NULL|NULL|",
    "delay_arbitrate_max_cluster_timeout|int|0,1000|NULL|NULL|",
    "ddb_log_level|string|0,0|NULL|NULL|",
    "ddb_log_backup_file_count|int|1,100|NULL|NULL|",
    "ddb_max_log_file_size|string|0,0|NULL|NULL|",
    "ddb_log_suppress_enable|int|0,1|NULL|NULL|",
    "ddb_election_timeout|int|1,600|NULL|NULL|",
    "enable_e2e_rto|int|0,1|NULL|NULL|",
    "disk_timeout|int|0,2147483647|NULL|NULL|",
    "agent_network_timeout|int|0,2147483647|NULL|NULL|",
    "share_disk_path|string|0,0|NULL|NULL|",
    "voting_disk_path|string|0,0|NULL|NULL|",
    "dn_arbitrate_mode|enum|quorum,paxos,share_disk|NULL|NULL|",
    "agent_fault_timeout|int|0,2147483647|NULL|NULL|",
#ifdef ENABLE_MULTIPLE_NODES
    "coordinator_heartbeat_timeout|int|0,2592000|NULL|if set 0,the function is disabled|",
    "cluster_starting_aribt_delay|int|1,2592000|NULL|NULL|",
#endif
    "third_party_gateway_ip|string|0,0|NULL|NULL|",
    "cms_enable_failover_on2nodes|bool|0,0|NULL|NULL|",
    "cms_enable_db_crash_recovery|bool|0,0|NULL|NULL|",
    "cms_network_isolation_timeout|int|10,2147483647|NULL|NULL|",
    "enable_set_most_available_sync|bool|0,0|NULL|NULL|",
    "cmserver_set_most_available_sync_delay_times|int|0,2147483647|NULL|NULL|",
#ifndef ENABLE_PRIVATEGAUSS
    "wait_static_primary_times|int|5,2147483647|NULL|NULL|",
#endif
    "ss_double_cluster_mode|int|0,2|NULL|NULL|",
    "share_disk_lock_type|int|0,1|NULL|NULL|",
    "upgrade_from|int|0,4294967295|NULL|For upgrading, specify which version we are upgrading from.|",
    "cms_enable_failover_cascade|bool|0,0|NULL|NULL|",
};

const char *g_valueTypeStr[] = {
    "bool",
    "enum",
    "integer",
    "string",
};

const char *g_boolValueList[] = {
    "true",
    "false",
    "on",
    "off",
    "yes",
    "no",
    "0",
    "1",
};

const char *g_ddbLogLevelList[] {
    "RUN_ERR",
    "RUN_WAR",
    "RUN_INF",
    "DEBUG_ERR",
    "DEBUG_WAR",
    "DEBUG_INF",
    "TRACE",
    "PROFILE",
    "OPER"
};

using UnitType = enum UnitTypeEn {
    UNIT_ERROR = -1,
    UNIT_KB,
    UNIT_MB,
    UNIT_GB,
    UNIT_MS,
    UNIT_S,
    UNIT_MIN,
    UNIT_H,
    UNIT_D
};

using CmParaType = enum CmParaTypeEn {
    CM_PARA_ERROR = -1,
    CM_PARA_BOOL,  /* bool    */
    CM_PARA_ENUM,  /* enum    */
    CM_PARA_INT,   /* int     */
    CM_PARA_STRING /* string  */
};

using ParamEnumEntry = struct ParamEnumEntrySt {
    CmParaType type;
    char name[MAX_PATH_LEN];
    char value[MAX_PATH_LEN];
    char unit[MAX_PATH_LEN];
    char message[MAX_PATH_LEN];
};

using  ParamMinMaxValue = struct ParamMinMaxValueSt {
    char minValStr[MAX_PATH_LEN];
    char maxValStr[MAX_PATH_LEN];
};

static const int UNIT_BITNESS = 2;
static const int DECIMAL_NOTATION = 10;
static const int MAX_DDB_LOG_FILE_SIZE = 1000;
static const int THRESHOLD_FORMAT = 4;
static const int THRESHOLD_MAX_VALUE = 100;
static const int THRESHOLD_MIN_VALUE = 0;

using EventTriggerType = enum EventTriggerTypeEn {
    EVENT_UNKNOWN = -1,
    EVENT_START = 0,
    EVENT_STOP,
    EVENT_FAILOVER,
    EVENT_SWITCHOVER,
    EVENT_COUNT
};

typedef struct TriggerTypeStringMap {
    EventTriggerType type;
    char *typeStr;
} TriggerTypeStringMap;

const TriggerTypeStringMap triggerTypeStringMap[EVENT_COUNT] = {
    {EVENT_START, "on_start"},
    {EVENT_STOP, "on_stop"},
    {EVENT_FAILOVER, "on_failover"},
    {EVENT_SWITCHOVER, "on_switchover"}
};

static status_t CheckEventTriggers(const char *value);

static status_t CheckParameterNameType(const char *param)
{
    if (param == NULL) {
        write_runlog(ERROR, "The parameter is NULL.\n");
        return CM_ERROR;
    }

    int paramLen = (int)strnlen(param, MAX_PATH_LEN);
    /* parameter must start with alpha, 0-9 or '_', start with '_' and end with '_' both are illegal */
    if (param[0] == '_' || param[paramLen - 1] == '_') {
        write_runlog(ERROR, "The param(%s) start or end with illegal character '_'.\n", param);
        return CM_ERROR;
    }
    for (int i = 0; i < paramLen; ++i) {
        if (!isalpha((unsigned char)(param[i])) && !isdigit((unsigned char)(param[i])) && (param[i] != '_')) {
            write_runlog(ERROR, "The param(%s) exists illegal character:%c.\n", param, param[i]);
            return CM_ERROR;
        }
    }

    return CM_SUCCESS;
}

static status_t CheckParameterValueType(const char *value)
{
    int count = 0;

    if (value == NULL) {
        write_runlog(ERROR, "The value is NULL.\n");
        return CM_ERROR;
    }
    if ((!isdigit((unsigned char)(value[0]))) && (value[0] != '\'') && (value[0] != '(') &&
        (!isalpha((unsigned char)(value[0]))) && (value[0] != '-') && (value[0] != ')') && (value[0] != '{')) {
        write_runlog(ERROR, "The parameter value(%s) exists illegal character:\"%c\".\n", value, value[0]);
        return CM_ERROR;
    }
    for (int i = 0; i < (int)strnlen(value, MAX_PATH_LEN); ++i) {
        if (value[i] == '\'') {
            ++count;
        }
        if (value[i] == '#') {
            write_runlog(ERROR, "The parameter value(%s) exists illegal character:\"%c\".\n", value, value[i]);
            return CM_ERROR;
        }
    }
    if (count == 1) {
        write_runlog(ERROR, "%s: the character '\'' can not make a pair or to many.\n", value);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static void MakeStrTolower(const char *source, char *dest, const int destLen)
{
    int len = (int)strlen(source);
    if (len > destLen) {
        len = destLen;
    }
    for (int i = 0; i < len; i++) {
        dest[i] = (char)tolower(source[i]);
    }
    dest[len] = '\0';
}

char *GetParamLineInfo(const char *paramName, const char * const *paramInfos, int paramInfosLen)
{
    int ret;
    char *info;
    char tmpParaName[MAX_PATH_LEN] = {0};
    char newParaName[MAX_PATH_LEN] = {0};

    info = (char*)malloc(MAX_PATH_LEN * sizeof(char));
    if (info == NULL) {
        write_runlog(ERROR, "Out of memory: GetParamLineInfo.\n");
        return NULL;
    }
    ret = memset_s(info, (MAX_PATH_LEN * sizeof(char)), 0, (MAX_PATH_LEN * sizeof(char)));
    securec_check_errno(ret, (void)ret);

    if (paramInfos == NULL) {
        write_runlog(ERROR, "Fail to get param info.\n");
        free(info);
        return NULL;
    }

    for (int i = 0; i < paramInfosLen; ++i) {
        MakeStrTolower(paramName, tmpParaName, sizeof(tmpParaName));
        ret = snprintf_s(newParaName, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s|", tmpParaName);
        securec_check_intval(ret, (void)ret);

        if (strncmp(paramInfos[i], newParaName, strnlen(newParaName, MAX_PATH_LEN)) != 0) {
            continue;
        }

        ret = snprintf_s(info, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s", paramInfos[i]);
        securec_check_intval(ret, (void)ret);

        return info;
    }

    return NULL;
}

static char *GetOneParamInfo(const GucOption &gucCtx)
{
    if (gucCtx.nodeType == NODE_TYPE_AGENT) {
        return GetParamLineInfo(gucCtx.parameter, g_cmaParamInfo, (int)lengthof(g_cmaParamInfo));
    }
    if (gucCtx.nodeType == NODE_TYPE_SERVER) {
        return GetParamLineInfo(gucCtx.parameter, g_cmsParamInfo, (int)lengthof(g_cmsParamInfo));
    }
    write_runlog(ERROR, "unrecognized -Z parameter.\n");

    return NULL;
}

static CmParaType GetParamType(const char *type)
{
    if (strncmp(type, "bool", strlen("bool")) == 0) {
        return CM_PARA_BOOL;
    }
    if (strncmp(type, "int", strlen("int")) == 0) {
        return CM_PARA_INT;
    }
    if (strncmp(type, "enum", strlen("enum")) == 0) {
        return CM_PARA_ENUM;
    }
    if (strncmp(type, "string", strlen("string")) == 0) {
        return CM_PARA_STRING;
    }

    return CM_PARA_ERROR;
}

static status_t GetConfigParamType(const char *ptr, ParamEnumEntry &varList)
{
    if (ptr != NULL) {
        CmParaType paramType = GetParamType(ptr);
        if (paramType == CM_PARA_ERROR) {
            write_runlog(DEBUG1, "Failed to parse \"%s\" info. The type \"%s\" is incorrect.\n", varList.name, ptr);
            return CM_ERROR;
        }
        varList.type = paramType;
    }

    return CM_SUCCESS;
}

static status_t GetConfigParamValue(const char *ptr, ParamEnumEntry &varList)
{
    int ret;

    if (ptr == NULL) {
        write_runlog(DEBUG1, "Failed to parse the \"%s\" info. The value is null.\n", varList.name);
        return CM_ERROR;
    }

    ret = snprintf_s(varList.value, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s", ptr);
    securec_check_intval(ret, (void)ret);

    return CM_SUCCESS;
}

static status_t GetConfigParamUnit(const char *ptr, ParamEnumEntry &varList)
{
    int ret;

    if (ptr == NULL) {
        write_runlog(DEBUG1, "Failed to parse the \"%s\" info. The parameter unit is incorrect.\n", varList.name);
        return CM_ERROR;
    }

    if (strncmp(ptr, "NULL", strlen("NULL")) == 0) {
        ret = memset_s(varList.unit, MAX_PATH_LEN, 0, MAX_PATH_LEN);
        securec_check_errno(ret, (void)ret);
    } else {
        ret = snprintf_s(varList.unit, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s", ptr);
        securec_check_intval(ret, (void)ret);
    }

    return CM_SUCCESS;
}

static status_t GetConfigParamMessage(const char *ptr, ParamEnumEntry &varList)
{
    int ret;

    if (ptr == NULL) {
        write_runlog(DEBUG1, "Failed to parse \"%s\" info. The param relation message is incorrect.\n", varList.name);
        return CM_ERROR;
    }

    if (strncmp(ptr, "NULL", strlen("NULL")) == 0) {
        ret = memset_s(varList.message, MAX_PATH_LEN, 0, MAX_PATH_LEN);
        securec_check_errno(ret, (void)ret);
    } else {
        ret = snprintf_s(varList.message, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s", ptr);
        securec_check_intval(ret, (void)ret);
    }

    return CM_SUCCESS;
}

static status_t ParseParamInfo(const char *infoStr, ParamEnumEntry &varList)
{
    int ret;
    char* ptr;
    char* buf = NULL;
    const char *delim = "|";
    char info[MAX_PATH_LEN] = {0};

    ret = snprintf_s(info, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s", infoStr);
    securec_check_intval(ret, (void)ret);

    /* param_name */
    ptr = strtok_r(info, delim, &buf);
    if (ptr != NULL) {
        ret = snprintf_s(varList.name, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s", ptr);
        securec_check_intval(ret, (void)ret);
    }

    /* param_type */
    ptr = strtok_r(NULL, delim, &buf);
    if (GetConfigParamType(ptr, varList) != CM_SUCCESS) {
        return CM_ERROR;
    }

    /* param_value */
    ptr = strtok_r(NULL, delim, &buf);
    if (GetConfigParamValue(ptr, varList) != CM_SUCCESS) {
        return CM_ERROR;
    }

    /* param_unit */
    ptr = strtok_r(NULL, delim, &buf);
    if (GetConfigParamUnit(ptr, varList) != CM_SUCCESS) {
        return CM_ERROR;
    }

    /* param_message */
    ptr = strtok_r(NULL, delim, &buf);
    if (GetConfigParamMessage(ptr, varList) != CM_SUCCESS) {
        return CM_ERROR;
    }

    ptr = strtok_r(NULL, delim, &buf);
    if (ptr != NULL && ptr[0] != '\n') {
        write_runlog(DEBUG1, "The param \"%s\" conf info is incorrect.\n", varList.name);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static bool IsStringInList(const char *str, const char * const *strList, uint32 listNums)
{
    for (uint32 i = 0; i < listNums; i++) {
        if (strcmp(strList[i], str) == 0) {
            return true;
        }
    }

    return false;
}

static bool IsValueInRange(const char *listValue, const char *value)
{
    int ret;
    char *ptr;
    char *buf = NULL;
    char confParamVal[MAX_PATH_LEN] = {0};
    const char *delim = ",";

    ret = snprintf_s(confParamVal, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s", listValue);
    securec_check_intval(ret, (void)ret);

    ptr = strtok_r(confParamVal, delim, &buf);
    while (ptr != NULL) {
        if (strcmp(ptr, value) == 0) {
            return true;
        }
        ptr = strtok_r(NULL, delim, &buf);
    }

    return false;
}

static status_t CheckBoolTypeValue(const char *param, const char *value)
{
    /* the length of value list */
    uint32 listNums = lengthof(g_boolValueList);
    if (IsStringInList(value, g_boolValueList, listNums)) {
        return CM_SUCCESS;
    }
    write_runlog(ERROR, "The value \"%s\" is outside the valid range(on|off|yes|no|true|false|1|0) for parameter "
                        "\"%s\".\n", value, param);

    return CM_ERROR;
}

static status_t CheckEnumTypeValue(const char *param, const char *value, const char *listValue)
{
    char *buf = NULL;
    char *tmpPtr = NULL;
    char *valuePtr = NULL;
    const char *delim = ",";
    char tmpValue[MAX_PATH_LEN] = {0};

    if (listValue == NULL || listValue[0] == '\0') {
        write_runlog(ERROR, "Failed to obtain the range information of parameter \"%s\".\n", param);
        return CM_ERROR;
    }

    MakeStrTolower(value, tmpValue, sizeof(tmpValue));
    if (strlen(tmpValue) > 0) {
        valuePtr = strtok_r(tmpValue, delim, &buf);
    } else {
        write_runlog(ERROR, "Unrecognized the value \"%s\".\n", value);
        return CM_ERROR;
    }

    while (valuePtr != NULL) {
        tmpPtr = valuePtr;
        while (isspace((unsigned char)*tmpPtr)) {
            tmpPtr++;
        }
        if (IsValueInRange(listValue, tmpPtr)) {
            valuePtr = strtok_r(NULL, delim, &buf);
        } else {
            write_runlog(ERROR, "The value \"%s\" is outside the valid range(%s) for parameter \"%s\".\n",
                value, listValue, param);
            return CM_ERROR;
        }
    }

    return CM_SUCCESS;
}

UnitType GetParamUnit(const char *unit)
{
    if (strncmp(unit, "KB", strlen("KB")) == 0) {
        return UNIT_KB;
    }
    if (strncmp(unit, "MB", strlen("MB")) == 0) {
        return UNIT_MB;
    }
    if (strncmp(unit, "GB", strlen("GB")) == 0) {
        return UNIT_GB;
    }
    if (strncmp(unit, "ms", strlen("ms")) == 0) {
        return UNIT_MS;
    }
    if (strncmp(unit, "s", strlen("s")) == 0) {
        return UNIT_S;
    }
    if (strncmp(unit, "min", strlen("min")) == 0) {
        return UNIT_MIN;
    }
    if (strncmp(unit, "h", strlen("h")) == 0) {
        return UNIT_H;
    }
    if (strncmp(unit, "d", strlen("d")) == 0) {
        return UNIT_D;
    }
    return UNIT_ERROR;
}

static status_t ProcessMemUnit(const UnitType &unit, char *&endPtr, const char *param)
{
    if (unit == UNIT_KB) {
        if (strncmp(endPtr, "KB", UNIT_BITNESS) != 0) {
            write_runlog(ERROR, "Valid units for this parameter \"%s\" is \"KB\".\n", param);
            return CM_ERROR;
        }
        endPtr += UNIT_BITNESS;
    }
    if (unit == UNIT_MB) {
        if (strncmp(endPtr, "MB", UNIT_BITNESS) != 0) {
            write_runlog(ERROR, "Valid units for this parameter \"%s\" is, \"MB\".\n", param);
            return CM_ERROR;
        }
        endPtr += UNIT_BITNESS;
    }
    if (unit == UNIT_GB) {
        if (strncmp(endPtr, "GB", UNIT_BITNESS) != 0) {
            write_runlog(ERROR, "Valid units for this parameter \"%s\" is \"GB\".\n", param);
            return CM_ERROR;
        }
        endPtr += UNIT_BITNESS;
    }

    return CM_SUCCESS;
}

static status_t ProcessTimeUnit(const UnitType &unit, char *&endPtr, const char *param)
{
    if (unit == UNIT_MS) {
        if (strncmp(endPtr, "ms", UNIT_BITNESS) != 0) {
            write_runlog(ERROR, "Valid units for this parameter \"%s\" is \"ms\".\n", param);
            return CM_ERROR;
        }
        endPtr += UNIT_BITNESS;
    }
    if (unit == UNIT_S) {
        if ((strncmp(endPtr, "s", UNIT_BITNESS) != 0)) {
            write_runlog(ERROR, "Valid units for this parameter \"%s\" is \"s\".\n", param);
            return CM_ERROR;
        }
        endPtr += UNIT_BITNESS;
    }
    if (unit == UNIT_MIN) {
        if (strncmp(endPtr, "min", UNIT_BITNESS) != 0) {
            write_runlog(ERROR, "Valid units for this parameter \"%s\" is \"min\".\n", param);
            return CM_ERROR;
        }
        endPtr += UNIT_BITNESS;
    }
    if (unit == UNIT_H) {
        if (strncmp(endPtr, "h", UNIT_BITNESS) != 0) {
            write_runlog(ERROR, "Valid units for this parameter \"%s\" is \"h\".\n", param);
            return CM_ERROR;
        }
        endPtr += UNIT_BITNESS;
    }
    if (unit == UNIT_D) {
        if (strncmp(endPtr, "d", UNIT_BITNESS) != 0) {
            write_runlog(ERROR, "Valid units for this parameter \"%s\" is \"d\".\n", param);
            return CM_ERROR;
        }
        endPtr += UNIT_BITNESS;
    }

    return CM_SUCCESS;
}

static status_t ProcessUnit(const UnitType &unit, char *&endPtr, const char *param)
{
    if (unit == UNIT_ERROR) {
        write_runlog(ERROR, "Invalid units for this parameter \"%s\".\n", param);
        return CM_ERROR;
    }
    if (ProcessMemUnit(unit, endPtr, param) != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (ProcessTimeUnit(unit, endPtr, param) != CM_SUCCESS) {
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static status_t ParseIntegerValue(const char *param, const char *value, const char *listUnit, int64 &resultInt)
{
    int64 intVal;
    UnitType unit;
    long double tmpDoubleVal;
    char *endPtr = NULL;
    bool haveSpace = false;

    /* transform value into long int */
    errno = 0;
    intVal = strtoll(value, &endPtr, 0);
    if (endPtr == value || errno == ERANGE) {
        return CM_ERROR;
    }
    tmpDoubleVal = (long double)intVal;

    /* skill the blank */
    while (isspace((unsigned char)*endPtr)) {
        haveSpace = true;
        endPtr++;
    }

    if (*endPtr != '\0') {
        /* if unit is NULL, it means the value is incorrect */
        if (listUnit == NULL || listUnit[0] == '\0') {
            write_runlog(DEBUG1, "The unit info is NULL.\n");
            return CM_ERROR;
        }
        if (haveSpace) {
            write_runlog(ERROR, "There should not hava space between value and unit.\n");
            return CM_ERROR;
        }

        unit = GetParamUnit(listUnit);
        if (ProcessUnit(unit, endPtr, param) != CM_SUCCESS) {
            return CM_ERROR;
        }
    }

    while (isspace((unsigned char)*endPtr)) {
        endPtr++;
    }

    if (*endPtr != '\0') {
        write_runlog(ERROR, "There are extra characters after the unit.\n");
        return CM_ERROR;
    }

    if (tmpDoubleVal > LLONG_MAX || tmpDoubleVal < LLONG_MIN) {
        write_runlog(ERROR, "The value is too large or too small.\n");
        return CM_ERROR;
    }

    resultInt = (int64)tmpDoubleVal;

    return CM_SUCCESS;
}

static status_t GetMinMaxValue(const char *listValue, ParamMinMaxValue &range)
{
    int ret;
    char* ptr;
    char* buf = NULL;
    const char *delim = ",";
    char tmpListVal[MAX_PATH_LEN] = {0};

    ret = snprintf_s(tmpListVal, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s", listValue);
    securec_check_intval(ret, (void)ret);

    /* min value string */
    ptr = strtok_r(tmpListVal, delim, &buf);
    if (ptr == NULL) {
        write_runlog(ERROR, "The minimum value information is incorrect.\n");
        return CM_ERROR;
    }
    ret = snprintf_s(range.minValStr, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s", ptr);
    securec_check_intval(ret, (void)ret);

    /* max value string */
    ptr = strtok_r(NULL, delim, &buf);
    if (ptr == NULL) {
        write_runlog(ERROR, "The maximum value information is incorrect.\n");
        return CM_ERROR;
    }
    ret = snprintf_s(range.maxValStr, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s", ptr);
    securec_check_intval(ret, (void)ret);

    ptr = strtok_r(NULL, delim, &buf);
    if (ptr != NULL) {
        write_runlog(ERROR, "The min and max information for parameter is incorrect.\n");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static status_t CheckIntTypeValue(const char *param, const char *value, const char *listValue, const char *listUnit)
{
    int64 intMinVal = LLONG_MIN;
    int64 intMaxVal = LLONG_MAX;
    int64 newIntVal = INT_MIN;
    ParamMinMaxValue range = {{0}};

    // parse int value
    if (ParseIntegerValue(param, value, listUnit, newIntVal) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (GetMinMaxValue(listValue, range) != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (range.minValStr[0] == '\0' || range.maxValStr[0] == '\0') {
        write_runlog(ERROR, "The min and max information for parameter \"%s\" is incorrect.\n", param);
        return CM_ERROR;
    }

    if ((ParseIntegerValue(param, range.minValStr, NULL, intMinVal) != CM_SUCCESS) ||
        (ParseIntegerValue(param, range.maxValStr, NULL, intMaxVal) != CM_SUCCESS)) {
        write_runlog(ERROR, "The minmax value of parameter \"%s\" requires an integer value.\n", param);
        return CM_ERROR;
    }
    /* if newIntVal < intMinVal or newIntVal > intMaxVal, print error message */
    if (newIntVal < intMinVal || newIntVal > intMaxVal) {
        write_runlog(ERROR, "The value %ld is outside the valid range for parameter \"%s\" (%ld .. %ld).\n",
            newIntVal, param, intMinVal, intMaxVal);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static status_t CheckStringLen(const char *value)
{
    if (strlen(value) > MAX_PATH_LEN) {
        write_runlog(ERROR, "The string value \"%s\" is longer than 1024.\n", value);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static status_t CheckDdbLogLevel(const char *param, const char *value)
{
    int ret;
    char* ptr;
    char* buf = NULL;
    const char *delim = "|";
    char tmpValue[MAX_PATH_LEN] = {0};

    ret = snprintf_s(tmpValue, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s", value);
    securec_check_intval(ret, (void)ret);

    ptr = strtok_r(tmpValue, delim, &buf);
    if (ptr == NULL) {
        return CM_ERROR;
    }

    while (ptr != NULL) {
        if (!IsStringInList(ptr, g_ddbLogLevelList, (uint32)lengthof(g_ddbLogLevelList))) {
            write_runlog(ERROR, "The %s is outside the valid range for parameter \"%s\".\n", ptr, param);
            return CM_ERROR;
        }
        ptr = strtok_r(NULL, delim, &buf);
    }

    return CM_SUCCESS;
}

static status_t CheckDdbMaxLogFileSize(const char *value)
{
    int pos = 0;
    int size = 0;
    int endPos = (int)strlen(value) - 1;
    if (value[endPos] != 'M') {
        write_runlog(ERROR, "Valid units for parameter \"ddb_max_log_file_size\" is \"M\".\n");
        return CM_ERROR;
    }
    for (int i = endPos - 1; i >= 0; --i) {
        if (value[i] > '9' || value[i] < '0') {
            write_runlog(ERROR, "The value \"%s\" is outside the valid range [1M, 1000M].\n", value);
            return CM_ERROR;
        }
        size += ((int)(value[i] - '0') * (int)pow(DECIMAL_NOTATION, pos));
        ++pos;
        if (size > MAX_DDB_LOG_FILE_SIZE) {
            write_runlog(ERROR, "The value \"%s\" is outside the valid range [1M, 1000M].\n", value);
            return CM_ERROR;
        }
    }
    if (size < 1) {
        write_runlog(ERROR, "The value \"%s\" is outside the valid range [1M, 1000M].\n", value);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static bool IsValueSymbolRight(const char *value)
{
    int symbolCount = 0;

    for (int i = 0; value[i] != '\0'; ++i) {
        if (value[i] == ',') {
            ++symbolCount;
        }
    }
    if (symbolCount != THRESHOLD_FORMAT) {
        return false;
    }

    return true;
}

static bool IsParamValueRight(const char *value)
{
    int result;

    if (value == NULL) {
        write_runlog(ERROR, "The environment_threshold value = NULL.\n");
        return false;
    }
    if (CM_is_str_all_digit(value) != 0) {
        write_runlog(ERROR, "The element(%s) in environment_threshold parameter value, is not digit.\n", value);
        return false;
    }
    result = (int)strtol(value, NULL, DECIMAL_NOTATION);
    if (result < THRESHOLD_MIN_VALUE || result > THRESHOLD_MAX_VALUE) {
        write_runlog(ERROR, "The element(%s) in environment_threshold parameter value, out of range[0, 100].\n", value);
        return false;
    }

    return true;
}

static status_t CheckEnvThresholdSize(const char *value)
{
    int valueNum = THRESHOLD_FORMAT + 1;
    char *pLeft = NULL;
    char *pValue;
    char envStr[CM_PATH_LENGTH] = {0};

    if (strcmp(value, "") == 0) {
        write_runlog(DEBUG1, "The value is NULL.\n");
        return CM_ERROR;
    }
    errno_t rc = strcpy_s(envStr, CM_PATH_LENGTH, value);
    securec_check_errno(rc, (void)rc);
    char *tmp = trim(envStr);
    write_runlog(DEBUG1, "environment_threshold, tmp=%s.\n", tmp);

    if (tmp[strlen(tmp) - 1] == ')') {
        tmp[strlen(tmp) - 1] = '\0';
    } else {
        write_runlog(ERROR, "The parameter value's format is wrong, current example: \"(0,0,0,0,0)\".\n");
        return CM_ERROR;
    }
    if (tmp[0] == '(') {
        tmp++;
    } else {
        write_runlog(ERROR, "The parameter value's format is wrong, current example: \"(0,0,0,0,0)\".\n");
        return CM_ERROR;
    }

    if (!IsValueSymbolRight(tmp)) {
        write_runlog(ERROR, "The parameter value's format is wrong, current example: \"(0,0,0,0,0)\".\n");
        return CM_ERROR;
    }

    pValue = strtok_r(tmp, ",", &pLeft);
    while (valueNum--) {
        if (!IsParamValueRight(pValue)) {
            return CM_ERROR;
        }
        pValue = strtok_r(NULL, ",", &pLeft);
    }

    return CM_SUCCESS;
}

static status_t CheckStringTypeValue(const char *param, const char *value)
{
    size_t valueLen = strlen(value);
    for (size_t i = 0; i < valueLen; ++i) {
        if (value[i] == ' ') {
            write_runlog(ERROR, "The parameter value(%s) exists illegal character:\" \".\n", value);
            return CM_ERROR;
        }
    }
    if ((strncmp(param, "log_dir", strlen("log_dir")) == 0) ||
        (strncmp(param, "alarm_component", strlen("alarm_component")) == 0) ||
        (strncmp(param, "unix_socket_directory", strlen("unix_socket_directory")) == 0)) {
        return CheckStringLen(value);
    }
    if (strncmp(param, "ddb_log_level", strlen("ddb_log_level")) == 0) {
        return CheckDdbLogLevel(param, value);
    }
    if (strncmp(param, "ddb_max_log_file_size", strlen("ddb_max_log_file_size")) == 0) {
        return CheckDdbMaxLogFileSize(value);
    }
    if (strncmp(param, "environment_threshold", strlen("environment_threshold")) == 0) {
        return CheckEnvThresholdSize(value);
    }
    if (strncmp(param, "event_triggers", strlen("event_triggers")) == 0) {
        return CheckEventTriggers(value);
    }

    return CM_SUCCESS;
}

static status_t CheckParamValue(const char *param, const char *newValue, const ParamEnumEntry &varList)
{
    switch (varList.type) {
        case CM_PARA_BOOL:
            return CheckBoolTypeValue(param, newValue);
        case CM_PARA_ENUM:
            return CheckEnumTypeValue(param, newValue, varList.value);
        case CM_PARA_INT:
            return CheckIntTypeValue(param, newValue, varList.value, varList.unit);
        case CM_PARA_STRING:
            return CheckStringTypeValue(param, newValue);
        case CM_PARA_ERROR:
        default:
            break;
    }
    return CM_ERROR;
}

static uint32 CleanZeroOfInt(const char *value, uint32 valueLen)
{
    for (uint32 i = 0; i < (valueLen - 1); ++i) {
        if (value[i] != '0') {
            return i;
        }
    }
    return (valueLen - 1);
}

static status_t GetNewValue(const CmParaType &type, char *newValue, const char *value, int valueLen, const char *param)
{
    int ret;

    if (type == CM_PARA_ENUM) {
        if (strchr(value, ',') != NULL) {
            if (!((value[0] == '\'' || value[0] == '"') && (value[0] == value[valueLen - 1]))) {
                write_runlog(ERROR, "The value \"%s\" for parameter \"%s\" is incorrect. Please do it like this "
                                    "\"parameter = \'value\'\".\n", value, param);
                return CM_ERROR;
            }
        }
    }
    if (type == CM_PARA_INT || type == CM_PARA_ENUM || type == CM_PARA_BOOL) {
        /* the value like this "XXX" or 'XXXX' */
        char tmpValue[MAX_PATH_LEN] = {0};
        if ((value[0] == '\'' || value[0] == '"') && (value[0] == value[valueLen - 1])) {
            for (int i = 1, j = 0; i < valueLen - 1 && j < MAX_PATH_LEN; i++, j++) {
                tmpValue[j] = value[i];
            }
        } else {
            ret = snprintf_s(tmpValue, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s", value);
            securec_check_intval(ret, (void)ret);
        }
        uint32 pos = 0;
        if (type == CM_PARA_INT) {
            pos = CleanZeroOfInt(tmpValue, (uint32)strlen(tmpValue));
        }
        ret = snprintf_s(newValue, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s", (tmpValue + pos));
        securec_check_intval(ret, (void)ret);
    }
    if (type == CM_PARA_STRING) {
        ret = snprintf_s(newValue, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s", value);
        securec_check_intval(ret, (void)ret);
    }

    return CM_SUCCESS;
}

static bool IsParameterValueValid(const char *infoStr, const char *param, const char *value)
{
    errno_t rc;
    ParamEnumEntry varList;
    int valueLen;
    char newValue[MAX_PATH_LEN] = {0};

    rc = memset_s(&varList, sizeof(varList), 0, sizeof(varList));
    securec_check_errno(rc, (void)rc);
    varList.type = CM_PARA_ERROR;

    if (ParseParamInfo(infoStr, varList) != CM_SUCCESS) {
        write_runlog(LOG, "Get parameter \"%s\" conf info error, can't do set.\n", param);
        return false;
    }
    /* if message is not NULL, print it */
    if (varList.message[0] != '\0') {
        write_runlog(LOG, "NOTICE: %s\n", varList.message);
    }
    valueLen = (int)strlen(value);
    if (GetNewValue(varList.type, newValue, value, valueLen, param) != CM_SUCCESS) {
        return false;
    }

    if (CheckParamValue(param, newValue, varList) != CM_SUCCESS) {
        if (varList.type != CM_PARA_ERROR) {
            write_runlog(ERROR, "The value \"%s\" for parameter \"%s\" is incorrect, requires a %s value\n",
                value, param, g_valueTypeStr[varList.type]);
        } else {
            write_runlog(ERROR, "The value \"%s\" for parameter \"%s\" is incorrect.\n", value, param);
        }
        return false;
    }

    return true;
}

static status_t CheckParameter(const GucOption &gucCtx)
{
    char *oneParamInfo = GetOneParamInfo(gucCtx);
    if (oneParamInfo == NULL || oneParamInfo[0] == '\0') {
        write_runlog(ERROR, "The parameter \"%s\" is incorrect. Please check if the parameter in the required range.\n",
            gucCtx.parameter);
        free(oneParamInfo);
        return CM_ERROR;
    }

    if (!IsParameterValueValid(oneParamInfo, gucCtx.parameter, gucCtx.value)) {
        free(oneParamInfo);
        return CM_ERROR;
    }
    free(oneParamInfo);

    return CM_SUCCESS;
}

status_t CheckGucOptionValidate(const GucOption &gucCtx)
{
    if (CheckParameterNameType(gucCtx.parameter) != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (CheckParameterValueType(gucCtx.value) != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (CheckParameter(gucCtx) != CM_SUCCESS) {
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static EventTriggerType GetTriggerTypeFromStr(const char *typeStr)
{
    for (int i = EVENT_START; i < EVENT_COUNT; ++i) {
        if (strcmp(typeStr, triggerTypeStringMap[i].typeStr) == 0) {
            return triggerTypeStringMap[i].type;
        }
    }
    write_runlog(ERROR, "Event trigger type %s is not supported.\n", typeStr);
    return EVENT_UNKNOWN;
}

/*
 * check trigger item, key and value can't be empty and must be string,
 * value must be shell script file, current user has right permission.
 */
static status_t CheckEventTriggersItem(const cJSON *item)
{
    if (!cJSON_IsString(item)) {
        write_runlog(ERROR, "The trigger value must be string.\n");
        return CM_ERROR;
    }

    char *valuePtr = item->valuestring;
    if (valuePtr == NULL || strlen(valuePtr) == 0) {
        write_runlog(ERROR, "The trigger value can't be empty.\n");
        return CM_ERROR;
    }

    if (valuePtr[0] != '/') {
        write_runlog(ERROR, "The trigger script path must be absolute path.\n");
        return CM_ERROR;
    }

    const char *extention = ".sh";
    const size_t shExtLen = strlen(extention);
    size_t pathLen = strlen(valuePtr);
    if (pathLen < shExtLen ||
        strncmp((valuePtr + (pathLen - shExtLen)), extention, shExtLen) != 0) {
        write_runlog(ERROR, "The trigger value %s is not shell script.\n", valuePtr);
        return CM_ERROR;
    }

    if (access(valuePtr, F_OK) != 0) {
        write_runlog(ERROR, "The trigger script %s is not a file or does not exist.\n", valuePtr);
        return CM_ERROR;
    }
    if (access(valuePtr, R_OK | X_OK) != 0) {
        write_runlog(ERROR, "Current user has no permission to access the "
            "trigger script %s.\n", valuePtr);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

/*
 * event_triggers sample:
 * {
 *     "on_start": "/dir/on_start.sh",
 *     "on_stop": "/dir/on_stop.sh",
 *     "on_failover": "/dir/on_failover.sh",
 *     "on_switchover": "/dir/on_switchover.sh"
 * }
 */
static status_t CheckEventTriggers(const char *value)
{
    if (value == NULL || value[0] == 0) {
        write_runlog(ERROR, "The value of event_triggers is empty.\n");
        return CM_ERROR;
    }
    if (CheckStringLen(value) == CM_ERROR) {
        return CM_ERROR;
    }

    cJSON *root = NULL;
    root = cJSON_Parse(value);
    if (!root) {
        write_runlog(ERROR, "The value of event_triggers is not a json.\n");
        return CM_ERROR;
    }
    if (!cJSON_IsObject(root)) {
        write_runlog(ERROR, "The value of event_triggers must be an object.\n");
        cJSON_Delete(root);
        return CM_ERROR;
    }

    int triggerNums[EVENT_COUNT] = {0};
    cJSON *item = root->child;
    while (item != NULL) {
        if (CheckEventTriggersItem(item) == CM_ERROR) {
            cJSON_Delete(root);
            return CM_ERROR;
        }

        char *typeStr = item->string;
        EventTriggerType type = GetTriggerTypeFromStr(typeStr);
        if (type == EVENT_UNKNOWN) {
            write_runlog(ERROR, "The trigger type %s does support.\n", typeStr);
            cJSON_Delete(root);
            return CM_ERROR;
        }

        ++triggerNums[type];
        if (triggerNums[type] > 1) {
            write_runlog(ERROR, "Duplicated trigger %s are supported.\n", typeStr);
            cJSON_Delete(root);
            return CM_ERROR;
        }

        item = item->next;
    }
    cJSON_Delete(root);
    return CM_SUCCESS;
}
