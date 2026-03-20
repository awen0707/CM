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

