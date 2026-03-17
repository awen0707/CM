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
 * cm_ddb_dcc.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_adapter/cm_dcc_adapter/cm_ddb_dcc.cpp
 *
 * -------------------------------------------------------------------------
 */
#include "cm_ddb_dcc.h"
#include "dcc_interface.h"
#include "cm/cm_elog.h"
#include "cm/cm_c.h"
#include "cm/cs_ssl.h"
#include "cm/cm_cipher.h"


static status_t DccLoadApi(const DrvApiInfo *apiInfo);
static void GetErrorMsg(const char *key);

static DdbDriver g_drvDcc = {PTHREAD_RWLOCK_INITIALIZER, false, DB_DCC, "dcc conn", DccLoadApi};

static const uint32 PASSWD_MAX_LEN = 64;
static const int32 MAX_NUM_LEN = 64;
static const uint32 DCC_MAX_PRIORITY = 1000;
static const uint32 DCC_AVG_PRIORITY = 100;
static const uint32 DCC_MIN_PRIORITY = 0;
static const uint32 ONE_PRIMARY_ONE_STANDBY = 2;
static const uint32 PROMOTE_LEADER_TIME = 30000; // ms
static const uint32 MAX_ERR_LEN = 2048;
static const char* KEY_NOT_FOUND = "can't find the key";

static const int32 CANNOT_FIND_DCC_LEAD = -1;
static const int32 CAN_FIND_DCC_LEAD = 0;
static const int32 LEAD_IS_CURRENT_INSTANCE = 1;

static uint32 g_cmServerNum = 0;
static volatile int64 g_waitForChangeTime = 0;
static int64 g_waitForTime = 0;
static ServerSocket *g_dccInfo = NULL;
static DDB_ROLE g_dbRole = DDB_ROLE_FOLLOWER;
static volatile uint32 g_expectPriority = DCC_AVG_PRIORITY;
static int32 g_curIdx = -1;
static uint32 g_timeOut = 0;
static THR_LOCAL char g_err[MAX_ERR_LEN] = {0};

/* this paramter is not suitable for dcc */
static const char *g_invalidParmeter[] = {"ddb_type", NULL};

static DDB_ROLE DccRoleToDdbRole(dcc_role_t roleType)
{
    switch (roleType) {
        case DCC_ROLE_LEADER:
            return DDB_ROLE_LEADER;
        case DCC_ROLE_FOLLOWER:
            return DDB_ROLE_FOLLOWER;
        case DCC_ROLE_LOGGER:
            return DDB_ROLE_LOGGER;
        case DCC_ROLE_PASSIVE:
            return DDB_ROLE_PASSIVE;
        case DCC_ROLE_PRE_CANDIDATE:
            return DDB_ROLE_PRE_CANDIDATE;
        case DCC_ROLE_CANDIDATE:
            return DDB_ROLE_CANDIDATE;
        case DCC_ROLE_CEIL:
            return DDB_ROLE_CEIL;
        case DCC_ROLE_UNKNOWN:
        default:
            return DDB_ROLE_UNKNOWN;
    }
}

int32 DccNotifyStatus(dcc_role_t roleType)
{
    g_dbRole = DccRoleToDdbRole(roleType);
    DdbNotifyStatusFunc ddbNotiSta = GetDdbStatusFunc();
    if (ddbNotiSta == NULL) {
        return 0;
    }
    write_runlog(LOG, "[DccNotifyStatus] g_dbRole is %d, roleType is %d.\n", g_dbRole, roleType);
    return ddbNotiSta(g_dbRole);
}

status_t DrvDccFreeConn(DrvCon_t *session)
{
    srv_dcc_free_handle(*session);
    *session = NULL;
    return CM_SUCCESS;
}

status_t DrvDccAllocConn(DrvCon_t *session, const DrvApiInfo *apiInfo)
{
    int32 res = srv_dcc_alloc_handle(session);
    if (res != 0) {
        GetErrorMsg("srv_dcc_alloc_handle");
        *session = NULL;
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static void SetDccText(dcc_text_t *dccText, char *data, size_t len)
{
    dccText->value = data;
    dccText->len = (uint32)len;
}

static void GetErrorMsg(const char *key)
{
    errno_t rc = memset_s(g_err, MAX_ERR_LEN, 0, MAX_ERR_LEN);
    securec_check_errno(rc, (void)rc);
    int32 code = srv_dcc_get_errorno();
    const char *errMsg = srv_dcc_get_error(code);
    if (errMsg != NULL && strstr(errMsg, "Key not found") != NULL) {
        if (key == NULL) {
            rc = snprintf_s(g_err, MAX_ERR_LEN, MAX_ERR_LEN - 1, "[%s, %d: %s]", KEY_NOT_FOUND, code, errMsg);
            securec_check_intval(rc, (void)rc);
        } else {
            rc = snprintf_s(g_err, MAX_ERR_LEN, MAX_ERR_LEN - 1, "[key is %s, %s, %d: %s]",
                key, KEY_NOT_FOUND, code, errMsg);
            securec_check_intval(rc, (void)rc);
        }
        return;
    }
    if (key == NULL) {
        rc = snprintf_s(g_err, MAX_ERR_LEN, MAX_ERR_LEN - 1, "[%d: %s]", code, errMsg);
        securec_check_intval(rc, (void)rc);
    } else {
        rc = snprintf_s(g_err, MAX_ERR_LEN, MAX_ERR_LEN - 1, "[key is %s, %d: %s]", key, code, errMsg);
        securec_check_intval(rc, (void)rc);
    }
}

static status_t GetDccText(dcc_text_t *dccText, char *data, uint32 len)
{
    if (data == NULL || dccText == NULL || len == 0) {
        write_runlog(ERROR, "data is NULL, dccText is NULL, or len is 0.\n");
        return CM_ERROR;
    }
    if ((len - 1) < dccText->len || dccText->len == 0) {
        write_runlog(ERROR, "dccText(%s) len(%u) is more than dest len(%u), cannot copy dcctext.\n",
            dccText->value, dccText->len, len);
        return CM_ERROR;
    }
    errno_t rc = memcpy_s(data, (len - 1), dccText->value, dccText->len);
    securec_check_errno(rc, (void)rc);
    return CM_SUCCESS;
}

status_t DrvDccGetValue(const DrvCon_t session, DrvText *key, DrvText *value, const DrvGetOption *option)
{
    uint32 eof = 0;
    dcc_option_t dccOption = {0};
    dccOption.read_op.read_level = DCC_READ_LEVEL_CONSISTENT;
    dccOption.cmd_timeout = g_timeOut;
    dcc_text_t dccKey = {0};
    dcc_text_t dccValue = {0};
    dcc_text_t range = {0};
    SetDccText(&range, key->data, strlen(key->data));
    int32 res = srv_dcc_get(session, &range, &dccOption, &dccKey, &dccValue, &eof);
    if (res != 0) {
        write_runlog(DEBUG1, "line %d: failed to dcc get(keyValue: [%s:%u, %s:%u]), res is %d, eof=%u.\n",
            __LINE__, dccKey.value, dccKey.len, dccValue.value, dccValue.len, res, eof);
        GetErrorMsg(key->data);
        return CM_ERROR;
    }
    write_runlog(DEBUG1, "line %d: dcc get(keyValue: [%s:%u, %s:%u]), res is %d, eof=%u.\n",
        __LINE__, dccKey.value, dccKey.len, dccValue.value, dccValue.len, res, eof);
    return GetDccText(&dccValue, value->data, value->len);
}

static void RestDccTextKV(dcc_text_t *dccKey, dcc_text_t *dccValue)
{
    errno_t rc = memset_s(dccKey, sizeof(dcc_text_t), 0, sizeof(dcc_text_t));
    securec_check_errno(rc, (void)rc);
    rc = memset_s(dccValue, sizeof(dcc_text_t), 0, sizeof(dcc_text_t));
    securec_check_errno(rc, (void)rc);
}

status_t DrvDccGetAllKV(
    const DrvCon_t session, DrvText *key, DrvKeyValue *keyValue, uint32 length, const DrvGetOption *option)
{
    uint32 eof = 0;
    uint32 idx = 0;
    dcc_option_t dccOption = {0};
    dccOption.read_op.is_prefix = 1;
    dccOption.read_op.read_level = DCC_READ_LEVEL_CONSISTENT;
    dccOption.cmd_timeout = g_timeOut;
    dcc_text_t dccKey = {0};
    dcc_text_t dccValue = {0};
    dcc_text_t range = {0};
    SetDccText(&range, key->data, strlen(key->data));
    int32 res = srv_dcc_get(session, &range, &dccOption, &dccKey, &dccValue, &eof);
    if (res != 0) {
        write_runlog(DEBUG1, "line %d: failed to dcc get(keyValue: [%s:%u, %s:%u]), res is %d, eof=%u.\n",
            __LINE__, dccKey.value, dccKey.len, dccValue.value, dccValue.len, res, eof);
        GetErrorMsg(key->data);
        return CM_ERROR;
    }

    if (dccValue.value == NULL || dccValue.len == 0) {
        GetErrorMsg(key->data);
        return CM_ERROR;
    }

    status_t st = GetDccText(&dccKey, keyValue[idx].key, DDB_KEY_LEN);
    CM_RETURN_IFERR(st);
    st = GetDccText(&dccValue, keyValue[idx].value, DDB_KEY_LEN);
    CM_RETURN_IFERR(st);
    while (eof != 1) {
        ++idx;
        if (idx >= length) {
            break;
        }
        RestDccTextKV(&dccKey, &dccValue);
        res = srv_dcc_fetch(session, &dccKey, &dccValue, &dccOption, &eof);
        if (res != 0 || dccValue.value == NULL || dccValue.len == 0) {
            write_runlog(DEBUG1, "line %d: failed to dcc get(keyValue: [%s:%u, %s:%u]), res is %d.\n",
                __LINE__, dccKey.value, dccKey.len, dccValue.value, dccValue.len, res);
            GetErrorMsg(key->data);
            return (eof == 1) ? CM_SUCCESS : CM_ERROR;
        }
        st = GetDccText(&dccKey, keyValue[idx].key, DDB_KEY_LEN);
        CM_RETURN_IFERR(st);
        st = GetDccText(&dccValue, keyValue[idx].value, DDB_KEY_LEN);
        CM_RETURN_IFERR(st);
    }
    return CM_SUCCESS;
}

static status_t SaveAllKV(const dcc_text_t &dccKey, const dcc_text_t &dccValue, FILE *fp)
{
    if (fp == NULL) {
        write_runlog(ERROR, "line:%d, fp is NULL.\n", __LINE__);
        return CM_ERROR;
    }
    if (fwrite(dccKey.value, dccKey.len, 1, fp) == 0) {
        write_runlog(ERROR, "line:%d, write kv file failed, key(%s).\n", __LINE__, dccKey.value);
        return CM_ERROR;
    }
    if (fputc('\n', fp) == EOF) {
        write_runlog(ERROR, "line:%d, write kv file failed.\n", __LINE__);
        return CM_ERROR;
    }
    if (fwrite(dccValue.value, dccValue.len, 1, fp) == 0) {
        write_runlog(ERROR, "line:%d, write kv file failed, key(%s).\n", __LINE__, dccValue.value);
        return CM_ERROR;
    }
    if (fputc('\n', fp) == EOF) {
        write_runlog(ERROR, "line:%d, write kv file failed.\n", __LINE__);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t DrvDccSaveAllKV(const DrvCon_t session, const DrvText *key, DrvSaveOption *option)
{
    uint32 eof = 0;
    dcc_text_t range = {0};
    dcc_text_t dccKey = {0};
    dcc_text_t dccValue = {0};
    dcc_option_t dccOption = {0};
    dccOption.read_op.is_prefix = 1;
    dccOption.read_op.read_level = DCC_READ_LEVEL_CONSISTENT;
    dccOption.cmd_timeout = g_timeOut;
    SetDccText(&range, const_cast<char*>(""), 0);
    int32 res = srv_dcc_get(session, &range, &dccOption, &dccKey, &dccValue, &eof);
    if (res != 0) {
        write_runlog(DEBUG1, "line %d: failed to dcc get, res is %d, eof=%u.\n", __LINE__, res, eof);
        GetErrorMsg(key->data);
        return CM_ERROR;
    }
    if (dccValue.value == NULL || dccValue.len == 0) {
        GetErrorMsg(key->data);
        return CM_ERROR;
    }
    if (option->kvFile == NULL) {
        write_runlog(ERROR, "open kvs file is null.\n");
        return CM_ERROR;
    }
    FILE *fp = fopen(option->kvFile, "w+");
    if (fp == NULL) {
        write_runlog(ERROR, "open kvs file \"%s\" failed.\n", option->kvFile);
        return CM_ERROR;
    }
    if (SaveAllKV(dccKey, dccValue, fp) != CM_SUCCESS) {
        (void)fclose(fp);
        return CM_ERROR;
    }
    while (eof != 1) {
        RestDccTextKV(&dccKey, &dccValue);
        res = srv_dcc_fetch(session, &dccKey, &dccValue, &dccOption, &eof);
        if (res != 0 || dccValue.value == NULL || dccValue.len == 0) {
            write_runlog(DEBUG1, "dcc failed to key: [%s:%u], res is %d.\n", dccKey.value, dccKey.len, res);
            GetErrorMsg(key->data);
            (void)fclose(fp);
            return (eof == 1) ? CM_SUCCESS : CM_ERROR;
        }
        if (SaveAllKV(dccKey, dccValue, fp) != CM_SUCCESS) {
            (void)fclose(fp);
            return CM_ERROR;
        }
    }
    (void)fclose(fp);

    return CM_SUCCESS;
}

status_t DrvDccSetKV(const DrvCon_t session, DrvText *key, DrvText *value, DrvSetOption *option)
{
    dcc_text_t dccKey = {0};
    SetDccText(&dccKey, key->data, strlen(key->data));
    dcc_text_t dccValue = {0};
    if (option != NULL && option->isSetBinary) {
        SetDccText(&dccValue, value->data, value->len);
    } else {
        SetDccText(&dccValue, value->data, strlen(value->data));
    }
    dcc_option_t dccOption = {0};
    dccOption.write_op.is_prefix = 0;
    dccOption.cmd_timeout = g_timeOut;
    if (option != NULL) {
        dccOption.write_op.expect_value = option->preValue;
        dccOption.write_op.expect_val_size = option->len;
    }
    int32 res = srv_dcc_put(session, &dccKey, &dccValue, &dccOption);
    write_runlog(DEBUG1, "dcc set key(%s:%u), value(%s:%u), res is %d.\n", dccKey.value, dccKey.len,
        dccValue.value, dccValue.len, res);
    if (res != 0) {
        GetErrorMsg(key->data);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t DrvDccDelKV(const DrvCon_t session, DrvText *key)
{
    dcc_text_t dccKey = {0};
    SetDccText(&dccKey, key->data, strlen(key->data));
    dcc_option_t dccOption = {0};
    dccOption.cmd_timeout = g_timeOut;
    int32 res = srv_dcc_delete(session, &dccKey, &dccOption);
    write_runlog(DEBUG1, "dcc del key(%s:%u), res is %d.\n", dccKey.value, dccKey.len, res);
    if (res != 0) {
        GetErrorMsg(key->data);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t DrvDccNodeState(DrvCon_t session, char *memberName, DdbNodeState *nodeState)
{
    int32 res = 0;
    dcc_node_status_t dccNodeState = {0};
    res = srv_dcc_get_node_status(&dccNodeState);
    if (res != 0) {
        nodeState->health = DDB_STATE_DOWN;
        nodeState->role = DDB_ROLE_UNKNOWN;
        GetErrorMsg(memberName);
        return CM_ERROR;
    }
    if (dccNodeState.is_healthy == 0) {
        nodeState->health = DDB_STATE_DOWN;
        nodeState->role = DDB_ROLE_UNKNOWN;
        GetErrorMsg(memberName);
        return CM_ERROR;
    }
    nodeState->health = DDB_STATE_HEALTH;
    nodeState->role = DccRoleToDdbRole(dccNodeState.role_type);
    return CM_SUCCESS;
}

const char *DrvDccLastError(void)
{
    return g_err;
}

static int32 SetDccWeight(uint32 idx)
{
    const int32 moreWeight = 2;
    const int32 lessWeight = 1;
    if (g_cmServerNum == ONE_PRIMARY_ONE_STANDBY && idx == 0) {
        return moreWeight;
    }
    return lessWeight;
}

status_t GetCfgPar(char *cfg, size_t maxLen, const DrvApiInfo *apiInfo)
{
    size_t curLen = 0;
    size_t leftLen = 0;
    errno_t rc = 0;
    bool hasFound = false;
    if (cfg == NULL) {
        write_runlog(ERROR, "cfg is NULL.\n");
        return CM_ERROR;
    }
    for (uint32 i = 0; i < apiInfo->serverLen; ++i) {
        curLen = strlen(cfg);
        if (curLen >= maxLen) {
            break;
        }
        if (apiInfo->serverList[i].host != NULL && apiInfo->serverList[i].port != 0) {
            if (!hasFound &&
                (apiInfo->serverList[i].nodeIdInfo.instd == apiInfo->server_t.curServer.nodeIdInfo.instd)) {
                hasFound = true;
            }
            leftLen = maxLen - curLen;
            if (i == 0) {
                rc = snprintf_s(cfg + curLen, leftLen, leftLen - 1,
                    "[\{\"stream_id\":1,\"node_id\":%u,\"ip\":\"%s\",\"port\":%u,\"role\":\"LEADER\", \"weight\":%d}",
                    apiInfo->serverList[i].nodeIdInfo.instd, apiInfo->serverList[i].host,
                    apiInfo->serverList[i].port, SetDccWeight(i));
            } else {
                rc = snprintf_s(cfg + curLen, leftLen, leftLen - 1,
                    ",\{\"stream_id\":1,\"node_id\":%u,\"ip\":\"%s\",\"port\":%u,\"role\":\"FOLLOWER\", \"weight\":%d}",
                    apiInfo->serverList[i].nodeIdInfo.instd, apiInfo->serverList[i].host,
                    apiInfo->serverList[i].port, SetDccWeight(i));
            }
            securec_check_intval(rc, FREE_AND_RESET(cfg));
        }
        if (i == apiInfo->serverLen - 1) {
            curLen = strlen(cfg);
            if (curLen >= maxLen) {
                break;
            }
            rc = strcat_s(cfg, maxLen, "]");
            securec_check_errno(rc, FREE_AND_RESET(cfg));
        }
    }
    if (!hasFound || strlen(cfg) == 0) {
        write_runlog(ERROR, "cfg is %s, but curIdx is %u.\n", cfg, apiInfo->server_t.curServer.nodeIdInfo.instd);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static int32 SetSsl2Dcc(const SslConfig *sslCfg)
{
    if (!sslCfg->enableSsl) {
        return 0;
    }
    int32 ret = srv_dcc_set_param("SSL_CA", sslCfg->sslPath.caFile);
    if (ret != 0) {
        write_runlog(ERROR, "Failed set SSL_CA to dcc.\n");
        return -1;
    }
    ret = srv_dcc_set_param("SSL_KEY", sslCfg->sslPath.keyFile);
    if (ret != 0) {
        write_runlog(ERROR, "Failed set SSL_KEY to dcc.\n");
        return -1;
    }
    ret = srv_dcc_set_param("SSL_CERT", sslCfg->sslPath.crtFile);
    if (ret != 0) {
        write_runlog(ERROR, "Failed set SSL_CERT to dcc.\n");
        return -1;
    }
    char notifyTime[PASSWD_MAX_LEN] = {0};
    errno_t rc = snprintf_s(notifyTime, PASSWD_MAX_LEN, PASSWD_MAX_LEN - 1, "%u", sslCfg->expireTime);
    securec_check_intval(rc, (void)rc);
    ret = srv_dcc_set_param("SSL_CERT_NOTIFY_TIME", notifyTime);
    if (ret != 0) {
        write_runlog(ERROR, "Failed set SSL_CERT_NOTIFY_TIME to dcc.\n");
        return -1;
    }
    char plain[PASSWD_MAX_LEN + 1] = {0};
    if (cm_verify_ssl_key_pwd(plain, PASSWD_MAX_LEN, SERVER_CIPHER) != CM_SUCCESS) {
        write_runlog(ERROR, "Failed to ssl text, cms will exit.\n");
        return CM_ERROR;
    }
    ret = srv_dcc_set_param("SSL_PWD_PLAINTEXT", plain);
    // memset plain
    const int32 tryTime = 3;
    for (int32 i = 0; i < tryTime; ++i) {
        rc = memset_s(plain, PASSWD_MAX_LEN + 1, 0, PASSWD_MAX_LEN + 1);
        securec_check_errno(rc, (void)rc);
    }
    if (ret != 0) {
        write_runlog(ERROR, "Failed set SSL_TEXT to dcc.\n");
        return -1;
    }
    return 0;
}

status_t StartDccProcess(const DrvApiInfo *apiInfo)
{
    size_t maxLen = (apiInfo->serverLen * DDB_MAX_PATH_LEN) * sizeof(char);
    char *cfg = (char *)malloc(maxLen);
    if (cfg == NULL) {
        write_runlog(ERROR, "cfg cannot malloc mem.\n");
        return CM_ERROR;
    }
    errno_t rc = memset_s(cfg, maxLen, 0, maxLen);
    securec_check_errno(rc, FREE_AND_RESET(cfg));
    status_t st = GetCfgPar(cfg, maxLen, apiInfo);
    if (st == CM_ERROR) {
        FREE_AND_RESET(cfg);
        return CM_ERROR;
    }
    char curIdxStr[MAX_NUM_LEN] = {0};
    rc = snprintf_s(curIdxStr, MAX_NUM_LEN, MAX_NUM_LEN - 1, "%u", apiInfo->server_t.curServer.nodeIdInfo.instd);
    securec_check_intval(rc, FREE_AND_RESET(cfg));
    char dccLogPath[DDB_MAX_PATH_LEN] = {0};
    rc = snprintf_s(dccLogPath, DDB_MAX_PATH_LEN, DDB_MAX_PATH_LEN - 1, "%s/dcc", apiInfo->server_t.logPath);
    securec_check_intval(rc, FREE_AND_RESET(cfg));
    write_runlog(LOG, "cfg is %s, curIdx is %s, datapath is %s, logPath is %s.\n", cfg, curIdxStr,
        apiInfo->server_t.dataPath, dccLogPath);
    (void)srv_dcc_set_param("DATA_PATH", apiInfo->server_t.dataPath);
    (void)srv_dcc_set_param("ENDPOINT_LIST", cfg);
    (void)srv_dcc_set_param("NODE_ID", curIdxStr);
    (void)srv_dcc_set_param("LOG_PATH", dccLogPath);
    (void)srv_dcc_set_param("LOG_LEVEL", "RUN_ERR|RUN_WAR|DEBUG_ERR|DEBUG_INF|OPER|RUN_INF|PROFILE");
    (void)srv_dcc_register_status_notify(DccNotifyStatus);
    int32 ret = SetSsl2Dcc(&(apiInfo->server_t.sslcfg));
    if (ret != 0) {
        FREE_AND_RESET(cfg);
        write_runlog(ERROR, "Failed to Set ssl to dcc.\n");
        return CM_ERROR;
    }
    ret = srv_dcc_start();
    FREE_AND_RESET(cfg);
    if (ret != 0) {
        write_runlog(ERROR, "Failed to start dcc.\n");
        return CM_ERROR;
    }
    write_runlog(LOG, "success to start dcc.\n");
    return CM_SUCCESS;
}

static bool IsDrvDccHeal(DDB_CHECK_MOD checkMod, int timeOut)
{
    return true;
}

static void DrvDccFreeNodeInfo(void)
{
    return;
}

static void DrvNotifyDcc(DDB_ROLE dbRole)
{
    const char *str = "[DrvNotifyDcc]";
    write_runlog(LOG, "%s %d: receive notify msg, it will set prority, dbRole is [%d: %d], g_expectPriority is %u, "
        "g_cmServerNum is %u.\n", str, __LINE__, (int32)dbRole, (int32)g_dbRole, g_expectPriority, g_cmServerNum);
    if (g_dbRole != dbRole && g_cmServerNum > ONE_PRIMARY_ONE_STANDBY) {
        if (dbRole == DDB_ROLE_FOLLOWER) {
            g_expectPriority = DCC_MIN_PRIORITY;
            g_waitForChangeTime = g_waitForTime;
        } else if (dbRole == DDB_ROLE_LEADER) {
            g_expectPriority = DCC_MAX_PRIORITY;
            g_waitForChangeTime = g_waitForTime;
        }
        write_runlog(LOG, "%s receive notify msg, it has setted prority, dbRole is [%d: %d], g_expectPriority is %u, "
            "g_waitForChangeTime is %ld, g_waitForTime is %ld.\n", str, (int32)dbRole, (int32)g_dbRole,
            g_expectPriority, (long int)g_waitForChangeTime, (long int)g_waitForTime);
    }
    return;
}

static void DrvDccSetMinority(bool isMinority)
{
    return;
}

Alarm *DrvDccGetAlarm(int alarmIndex)
{
    return NULL;
}

static status_t DrvDccLeaderNodeId(NodeIdInfo *idInfo, const char *azName)
{
    uint32 instd = 0;
    int32 ret = srv_dcc_query_leader_info(&instd);
    if (ret != 0) {
        return CM_ERROR;
    }
    for (uint32 i = 0; i < g_cmServerNum; ++i) {
        if (g_dccInfo[i].nodeIdInfo.azName == NULL) {
            write_runlog(ERROR, "[DrvDccLeaderNodeId]: i=%u, azName is NULL.\n", i);
            return CM_ERROR;
        }
        if ((azName != NULL) && (strcmp(g_dccInfo[i].nodeIdInfo.azName, azName) != 0)) {
            continue;
        }
        if (g_dccInfo[i].nodeIdInfo.instd == instd) {
            idInfo->azName = g_dccInfo[i].nodeIdInfo.azName;
            idInfo->nodeId = g_dccInfo[i].nodeIdInfo.nodeId;
            return CM_SUCCESS;
        }
    }
    return CM_ERROR;
}

static status_t DrvDccRestConn(DrvCon_t sess, int32 timeOut)
{
    return CM_SUCCESS;
}

status_t DrvExecDccCmd(DrvCon_t session, char *cmdLine, char *output, int *outputLen, uint32 maxBufLen)
{
    int ret;
    errno_t rc;
    dcc_text_t cmdText = {0};
    dcc_text_t getText = {0};

    SetDccText(&cmdText, cmdLine, strlen(cmdLine));

    ret = srv_dcc_exec_cmd(session, &cmdText, &getText);
    if (ret != 0) {
        write_runlog(ERROR, "Failed to exec dcc cmd(%s), ret is %d.\n", cmdLine, ret);
        GetErrorMsg(NULL);
        return CM_ERROR;
    }

    if (output != NULL && getText.len != 0) {
        uint32 copyLen = getText.len;
        if (maxBufLen <= getText.len) {
            copyLen = maxBufLen - 1;
        }
        rc = memcpy_s(output, copyLen, getText.value, copyLen);
        securec_check_errno(rc, (void)rc);
        output[copyLen] = '\0';
    }

    if (outputLen != NULL) {
        *outputLen = static_cast<int>(getText.len);
    }

    if (g_cmServerNum != ONE_PRIMARY_ONE_STANDBY) {
        write_runlog(LOG, "Success to exec dcc cmd(%s).\n", cmdLine);
    } else {
        write_runlog(DEBUG5, "Success to exec dcc cmd(%s).\n", cmdLine);
    }

    return CM_SUCCESS;
}

static status_t DrvDccSetBlocked(unsigned int setBlock, unsigned int waitTimeoutMs)
{
    int ret;

    ret = srv_dcc_set_blocked(setBlock, waitTimeoutMs);
    if (ret != 0) {
        write_runlog(ERROR, "Failed to set blocked.\n");
        GetErrorMsg("Failed to set blocked");
        return CM_ERROR;
    }
    write_runlog(LOG, "Success to set blocked.\n");
    return CM_SUCCESS;
}

static bool IsFilterParameter(const char *key)
{
    if (g_invalidParmeter == NULL || key == NULL) {
        write_runlog(ERROR, "g_invalidParmeter is NULL, or key is NULL.\n");
        return false;
    }
    for (int32 i = 0; g_invalidParmeter[i] != NULL; ++i) {
        if (strncmp(key, g_invalidParmeter[i], strlen(g_invalidParmeter[i])) == 0) {
            return true;
        }
    }
    return false;
}

static status_t DrvDccSetParam(const char *key, const char *value)
{
    if (key == NULL || value == NULL) {
        write_runlog(ERROR, "failed to set dcc param, because key(%s) or value(%s) is null.\n", key, value);
        return CM_ERROR;
    }
    if (strlen(key) <= strlen("ddb_")) {
        write_runlog(ERROR, "this is not ddb parameter(key %s: value %s).\n", key, value);
        return CM_ERROR;
    }
    if (IsFilterParameter(key)) {
        write_runlog(WARNING, "key_value is [%s, %s], not need set param.\n", key, value);
        return CM_SUCCESS;
    }
    const char *dccKey = key + strlen("ddb_");
    int32 ret = srv_dcc_set_param(dccKey, value);
    if (ret != 0) {
        write_runlog(
            ERROR, "failed to set dcc param(key %s: value %s), error msg is %s.\n", dccKey, value, DrvDccLastError());
        return CM_ERROR;
    }
    write_runlog(LOG, "sucess to set param(key %s: value %s) to dcc.\n", dccKey, value);
    return CM_SUCCESS;
}

static void PrintDccInfo()
{
    char dccStr[DDB_MAX_KEY_VALUE_LEN] = {0};
    size_t dccSize = 0;
    errno_t rc = 0;
    for (uint32 ii = 0; ii < g_cmServerNum; ++ii) {
        dccSize = strlen(dccStr);
        if (dccSize >= (DDB_MAX_KEY_VALUE_LEN - 1)) {
            break;
        }
        rc = snprintf_s(dccStr + dccSize, (DDB_MAX_KEY_VALUE_LEN - dccSize), ((DDB_MAX_KEY_VALUE_LEN - 1) - dccSize),
            "%s:%u:%s:%u:%u:%s; ", g_dccInfo[ii].host, g_dccInfo[ii].port, g_dccInfo[ii].nodeInfo.nodeName,
            g_dccInfo[ii].nodeIdInfo.nodeId, g_dccInfo[ii].nodeIdInfo.instd, g_dccInfo[ii].nodeIdInfo.azName);
        securec_check_intval(rc, (void)rc);
    }
    write_runlog(LOG, "dccStr is %s.\n", dccStr);
}

static status_t InitDccInfo(const DrvApiInfo *apiInfo)
{
    g_cmServerNum = apiInfo->nodeNum;
    if (g_cmServerNum == 0) {
        write_runlog(ERROR, "g_cmServerNum is zero, failed to init dcc info.\n");
        return CM_ERROR;
    }
    size_t len = g_cmServerNum * sizeof(ServerSocket);
    g_dccInfo = (ServerSocket *)malloc(len);
    if (g_dccInfo == NULL) {
        write_runlog(ERROR, "g_dccInof is NULL.\n");
        return CM_ERROR;
    }
    errno_t rc = memset_s(g_dccInfo, len, 0, len);
    securec_check_errno(rc, FREE_AND_RESET(g_dccInfo));
    uint32 jj = 0;
    ServerSocket *srNode = NULL;
    for (uint32 ii = 0; ii < apiInfo->serverLen; ++ii) {
        if (jj >= g_cmServerNum) {
            break;
        }
        srNode = &apiInfo->serverList[ii];
        if (srNode->host == NULL || srNode->port == 0 || srNode->nodeInfo.nodeName == NULL ||
            srNode->nodeInfo.len == 0) {
            continue;
        }
        g_dccInfo[jj] = *srNode;
        ++jj;
    }
    if (jj == 0 || jj != g_cmServerNum) {
        write_runlog(ERROR, "%s :%d, failed to init dcc info, jj: %u, g_dccNum is %u.\n",
            __FUNCTION__, __LINE__, jj, g_cmServerNum);
        return CM_ERROR;
    }
    PrintDccInfo();
    return CM_SUCCESS;
}

static int32 SetPriority(uint32 priority)
{
    int32 ret = srv_dcc_set_election_priority((unsigned long long)priority);
    write_runlog(LOG, "will set ELECTION_PRIORITY, and value is %u, ret is %d.\n", priority, ret);
    if (ret != 0) {
        write_runlog(ERROR, "set PRIORITY failed, error msg is %s.\n", DrvDccLastError());
    }
    return ret;
}

static int32 CheckDccLeader()
{
    uint32 instd = 0;
    int32 ret = srv_dcc_query_leader_info(&instd);
    write_runlog(
        LOG, "get dcc leader (%u), curNode is %u, ret is %d.\n", instd, g_dccInfo[g_curIdx].nodeIdInfo.instd, ret);
    if (ret != 0) {
        return CANNOT_FIND_DCC_LEAD;
    }
    if (instd == g_dccInfo[g_curIdx].nodeIdInfo.instd) {
        return LEAD_IS_CURRENT_INSTANCE;
    }
    return CAN_FIND_DCC_LEAD;
}

static bool CheckDccDemote()
{
    if (g_expectPriority != DCC_MIN_PRIORITY) {
        return false;
    }
    int32 ret = 0;
    if (g_dbRole == DDB_ROLE_LEADER) {
        ret = SetPriority(g_expectPriority);
        ret = srv_dcc_demote_follower();
        (void)DccRoleToDdbRole(DCC_ROLE_FOLLOWER);
        write_runlog(LOG, "[CheckDccDemote] dcc will demote follower, ret is %d.\n", ret);
        if (ret != 0) {
            write_runlog(ERROR, "[CheckDccDemote] dcc failed to demote follower, error msg is %s.\n",
                DrvDccLastError());
        }
        return true;
    }
    if (CheckDccLeader() != CAN_FIND_DCC_LEAD) {
        return true;
    }
    // wait for all cms can be promoted, in order to prevent two-cms turn.
    if (g_waitForChangeTime > 0) {
        write_runlog(DEBUG1, "[CheckDccDemote] g_waitForChangeTime is %ld, cannot reset g_expectPriority.\n",
            (long int)g_waitForChangeTime);
        return true;
    }
    write_runlog(LOG, "[CheckDccDemote] line %s:%d, will reset g_expectPriority from %u to %u.\n",
        __FUNCTION__, __LINE__, g_expectPriority, DCC_AVG_PRIORITY);
    g_expectPriority = DCC_AVG_PRIORITY;
    return false;
}

static bool CheckDccPromote()
{
    if (g_expectPriority != DCC_MAX_PRIORITY) {
        return false;
    }
    if (g_dbRole != DDB_ROLE_LEADER) {
        if (CheckDccLeader() == CANNOT_FIND_DCC_LEAD) {
            return true;
        }
        int32 ret = SetPriority(g_expectPriority);
        write_runlog(LOG, "[CheckDccPromote] line %s:%d set priority(%u), ret is %d.\n", __FUNCTION__, __LINE__,
            g_expectPriority, ret);
        ret = srv_dcc_promote_leader(g_dccInfo[g_curIdx].nodeIdInfo.instd, PROMOTE_LEADER_TIME);
        if (ret != 0) {
            write_runlog(ERROR, "[CheckDccPromote] failed to set dcc promote leader, error msg is %s.\n",
                DrvDccLastError());
        }
        return true;
    }
    if (g_waitForChangeTime > 0) {
        write_runlog(DEBUG1, "[CheckDccDemote] g_waitForChangeTime is %ld, cannot reset g_expectPriority.\n",
            (long int)g_waitForChangeTime);
        return true;
    }
    write_runlog(LOG, "[CheckDccPromote] line %s:%d, will reset g_expectPriority from %u to %u.\n",
        __FUNCTION__, __LINE__, g_expectPriority, DCC_AVG_PRIORITY);
    g_expectPriority = DCC_AVG_PRIORITY;
    return false;
}

static uint32 GetCurPriority()
{
    bool res = false;
    if (g_expectPriority != DCC_AVG_PRIORITY) {
        write_runlog(LOG, "g_expectPriority is %u, g_dbRole is %d.\n", g_expectPriority, g_dbRole);
        res = CheckDccDemote();
        if (res) {
            return DCC_MIN_PRIORITY;
        }
        res = CheckDccPromote();
        if (res) {
            return DCC_MAX_PRIORITY;
        }
    }
    return DCC_AVG_PRIORITY;
}

bool CheckSetPriority(uint32 *lastPrio, uint32 *curPriority, int32 ret)
{
    if (ret != 0) {
        return true;
    }
    (*curPriority) = GetCurPriority();
    if ((*curPriority) == (*lastPrio)) {
        return false;
    }
    *lastPrio = (*curPriority);
    return true;
}

void *SetPriorityMain(void *arg)
{
    thread_name = "DCC_SET";
    write_runlog(LOG, "Starting DCC SET priority thread.\n");
    int32 ret = 0;
    uint32 curPriority = 0;
    uint32 lastPrority = 0;
    bool isNeedSet = false;
    for (;;) {
        isNeedSet = CheckSetPriority(&lastPrority, &curPriority, ret);
        if (isNeedSet) {
            ret = SetPriority(curPriority);
        }
        write_runlog(DEBUG1, "prority is [%u/%u], isNeedSet is %d, g_dbRole is %d.\n", lastPrority, g_expectPriority,
            isNeedSet, g_dbRole);
        (void)sleep(1);
    }
    return NULL;
}

static status_t CreateSetPriorityThread()
{
    pthread_t thrId;
    int32 res = pthread_create(&thrId, NULL, SetPriorityMain, NULL);
    if (res != 0) {
        write_runlog(ERROR, "Failed to create SetPriorityMain.\n");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

void *DccMonitorMain(void *argp)
{
    thread_name = "DCC_MONITOR";
    write_runlog(LOG, "Starting DCC monitor thread.\n");
    for (;;) {
        if (g_waitForChangeTime > 0) {
            --g_waitForChangeTime;
        }
        (void)sleep(1);
    }
    return NULL;
}

static status_t CreateMonitorThread()
{
    pthread_t thrId;
    int32 res = pthread_create(&thrId, NULL, DccMonitorMain, NULL);
    if (res != 0) {
        write_runlog(ERROR, "Failed to create DccMonitorMain.\n");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t CreateDccThread(const DrvApiInfo *apiInfo)
{
    if (g_cmServerNum <= ONE_PRIMARY_ONE_STANDBY) {
        write_runlog(LOG, "this cmServer is %u, cannot CreateSetPriorityThread.\n", g_cmServerNum);
        return CM_SUCCESS;
    }
    status_t st = CreateMonitorThread();
    if (st != CM_SUCCESS) {
        return CM_ERROR;
    }
    st = CreateSetPriorityThread();
    return st;
}

static status_t GetCurNodeIdx(const DrvApiInfo *apiInfo)
{
    for (uint32 i = 0; i < g_cmServerNum; ++i) {
        if (g_dccInfo[i].nodeIdInfo.nodeId == apiInfo->nodeId) {
            g_curIdx = (int32)i;
            break;
        }
    }
    write_runlog(LOG, "get curidx(%d) from server.\n", g_curIdx);
    if (g_curIdx == -1) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t InitDccInfoAndCreateThread(const DrvApiInfo *apiInfo)
{
    status_t st = InitDccInfo(apiInfo);
    CM_RETURN_IFERR(st);
    if (apiInfo->timeOut < 0) {
        write_runlog(ERROR, "timeout(%d) is invalid.\n", apiInfo->timeOut);
        return CM_ERROR;
    }
    const int32 toSec = 1000;
    if (apiInfo->timeOut < toSec) {
        g_timeOut = 1;
    } else {
        g_timeOut = (uint32)(apiInfo->timeOut / toSec);
    }
    st = GetCurNodeIdx(apiInfo);
    CM_RETURN_IFERR(st);
    g_waitForTime = apiInfo->server_t.waitTime;
    st = CreateDccThread(apiInfo);
    return st;
}

static status_t DrvDccStop(bool *ddbStop)
{
    int32 ret = srv_dcc_stop();
    write_runlog(LOG, "dcc has stopped, and ret is %d.\n", ret);
    if (ret == 0) {
        *ddbStop = true;
        return CM_SUCCESS;
    }
    return CM_ERROR;
}

status_t DrvDccSetWorkMode(DrvCon_t session, unsigned int workMode, unsigned int voteNum)
{
    int32 res = 0;
    res = srv_dcc_set_work_mode((dcc_work_mode_t)workMode, voteNum);
    if (res != CM_SUCCESS) {
        write_runlog(ERROR, "set work mode failed. %d \n", res);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t DrvDccDemoteDdbRole(DrvCon_t session)
{
    int32 res = 0;
    res = srv_dcc_demote_follower();
    if (res != CM_SUCCESS) {
        write_runlog(ERROR, "dcc demote follower failed. %d \n", res);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t DccLoadApi(const DrvApiInfo *apiInfo)
{
    DdbDriver *drv = DrvDccGet();
    drv->allocConn = DrvDccAllocConn;
    drv->freeConn = DrvDccFreeConn;
    drv->getValue = DrvDccGetValue;
    drv->getAllKV = DrvDccGetAllKV;
    drv->saveAllKV = DrvDccSaveAllKV;
    drv->setKV = DrvDccSetKV;
    drv->delKV = DrvDccDelKV;
    drv->drvNodeState = DrvDccNodeState;
    drv->lastError = DrvDccLastError;

    drv->isHealth = IsDrvDccHeal;
    drv->freeNodeInfo = DrvDccFreeNodeInfo;
    drv->notifyDdb = DrvNotifyDcc;
    drv->setMinority = DrvDccSetMinority;
    drv->getAlarm = DrvDccGetAlarm;
    drv->leaderNodeId = DrvDccLeaderNodeId;
    drv->restConn = DrvDccRestConn;
    drv->execCmd = DrvExecDccCmd;
    drv->setBlocked = DrvDccSetBlocked;
    drv->setParam = DrvDccSetParam;
    drv->stop = DrvDccStop;
    drv->setWorkMode = DrvDccSetWorkMode;
    drv->demoteDdbRole = DrvDccDemoteDdbRole;
    g_cmServerNum = apiInfo->nodeNum;
    status_t st = StartDccProcess(apiInfo);
    if (st != CM_SUCCESS) {
        return CM_ERROR;
    }
    st = InitDccInfoAndCreateThread(apiInfo);
    return st;
}

DdbDriver *DrvDccGet(void)
{
    return &g_drvDcc;
}

