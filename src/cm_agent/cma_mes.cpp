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
 * cma_mes.cpp
 *
 * IDENTIFICATION
 *    src/cm_agent/cma_mes.cpp
 *
 * -------------------------------------------------------------------------
 */
#include "mes_interface.h"

#include "cm_debug.h"

#include "cm_config.h"
#include "cm_elog.h"
#include "cm_rhb.h"
#include "cm_cipher.h"
#include "cma_global_params.h"

#define AGENT_RHB_PORT_INC (2)
#define AGENT_RHB_MSG_BUFF_POOL_NUM (1)
#define AGENT_RHB_MSG_BUFF_QUEUE_NUM (8)
#define AGENT_RHB_MSG_SHARED_POOL_QUEUE_NUM (1)
#define AGENT_RHB_BUFF_COUNT (10)
#define AGENT_RHB_BUFF_SIZE (1024)
#define AGENT_MES_MSG_EXTRA_SIZE (3 * 1024) // compress head:2k, mes head:64 and other
#define AGENT_MES_MSG_POOL_METADATA_SIZE (1024 * 1024)
#define AGENT_RHB_CHECK_SID (0)

const uint32 CMA_MES_PRIORITY = 0;

typedef struct CmaMesMsgHeadT {
    uint32 version;
    uint32 cmd; // command
    char reserved[64];
    uint32 bufSize;
    char buf[0];
} CmaMesMsgHead; // total size is 76

static pthread_t g_rhbThread;
static const uint32 PASSWD_MAX_LEN = 64;

typedef struct RhbCtx_ {
    uint32 sid;
    uint32 instId;  // mes use index as id
    uint32 instCount;
    uint32 hbWorkThreadCount;
    inst_type instType[MAX_RHB_NUM];
    uint64 instMap;
    staticNodeConfig *nodeList[MAX_RHB_NUM];  // node list to be check, it's idx as it's instId
    mes_addr_t instAddrs[MES_MAX_IP_LEN];
} RhbCtx;
RhbCtx g_ctx = {0};

static uint32 FindMinServerPort()
{
    const uint32 defaultCmsPort = 5000;
    for (uint32 i = 0; i < g_node_num; ++i) {
        if (g_node[i].cmServerLevel == 1) {
            return g_node[i].port;
        }
    }
    return defaultCmsPort;
}

static void InitAgentAddrs(
    uint32 *instCount, mes_addr_t *instAddrs, staticNodeConfig **nodeList, uint32 *curInstId, uint64 *instMap)
{
    *instCount = 0;

    char buf[MAX_LOG_BUFF_LEN] = {0};
    const uint32 maxInfoLen = 80;
    char info[maxInfoLen] = {0};
    uint32 port = FindMinServerPort();
    for (uint32 i = 0; i < g_node_num; i++) {
        if (g_node[i].node == g_nodeHeader.node) {
            *curInstId = (*instCount);
        }

        if (g_node[i].datanodeCount == 0) {
            continue;
        }
        if ((*instCount) >= MAX_RHB_NUM) {
            write_runlog(ERROR, "[InitAgentAddrs] we supported res count less than %d", MAX_RHB_NUM);
            return;
        }

        (*instMap) ^= ((uint64)1 << (*instCount));
        nodeList[(*instCount)] = &g_node[i];

        int rc = strncpy_s(instAddrs[(*instCount)].ip,
            sizeof(char) * MES_MAX_IP_LEN,
            g_node[i].datanode[0].datanodeLocalHAIP[0],
            sizeof(char) * MES_MAX_IP_LEN - 1);
        securec_check_errno(rc, (void)rc);
        instAddrs[(*instCount)].port = (uint16)port + AGENT_RHB_PORT_INC;
        instAddrs[(*instCount)].inst_id = (*instCount);
        instAddrs[(*instCount)].need_connect = CM_TRUE;

        int rcs =
            snprintf_s(info, maxInfoLen, maxInfoLen - 1, " [%u-%u](%s)", i, g_node[i].node, instAddrs[(*instCount)].ip);
        securec_check_intval(rcs, (void)rcs);
        rcs = strncat_s(buf, MAX_LOG_BUFF_LEN, info, strlen(info));
        securec_check_errno(rcs, (void)rcs);
        (*instCount)++;
    }

    write_runlog(LOG, "[InitAgentAddrs], detail:%s\n", buf);
}

void InitInstType(RhbCtx *ctx)
{
    uint32 index = 0;
    for (uint32 i = 0; i < ctx->instCount; ++i) {
        if (i == ctx->instId) {
            continue;
        }
        ctx->instType[index] = i;
        ++index;
    }
}

static void InitRhbCtxByStaticConfig(RhbCtx *ctx)
{
    InitAgentAddrs(&ctx->instCount, ctx->instAddrs, ctx->nodeList, &ctx->instId, &ctx->instMap);
    InitInstType(ctx);
}

typedef enum RhbMsgCmd_ {
    RHB_MSG_BEGIN = 0,
    RHB_MSG_HB_BC = RHB_MSG_BEGIN,  // hb broadcast
    RHB_MSG_CEIL,
} RhbMsgCmd;

static void InitBuffPool(mes_profile_t *pf)
{
    pf->priority_cnt = 1;
    mes_msg_pool_attr_t *mpa = &pf->msg_pool_attr;
    mpa->enable_inst_dimension = CM_TRUE;
    mpa->buf_pool_count = 1;
    mpa->buf_pool_attr[0].buf_size = AGENT_RHB_BUFF_SIZE;
    mpa->buf_pool_attr[0].proportion = (double)1;
    mpa->buf_pool_attr[0].shared_pool_attr.queue_num = AGENT_RHB_MSG_SHARED_POOL_QUEUE_NUM;
    mpa->buf_pool_attr[0].priority_pool_attr[CMA_MES_PRIORITY].queue_num = AGENT_RHB_MSG_BUFF_QUEUE_NUM;
    mpa->max_buf_size[CMA_MES_PRIORITY] = mpa->buf_pool_attr[0].buf_size;
    mes_msg_pool_minimum_info_t minimum_info = { 0 };
    uint64 metadata_size = 0;
    int ret = mes_get_message_pool_minimum_info(pf, CM_FALSE, &minimum_info);
    if (ret != 0) {
        write_runlog(WARNING, "get minimum buff size failed, ret(%d), set metadata size to 1M.\n", ret);
        metadata_size = AGENT_MES_MSG_POOL_METADATA_SIZE;
    } else {
        metadata_size = minimum_info.metadata_size;
    }
    uint64 estimated_size = ((mpa->buf_pool_attr[0].buf_size + AGENT_MES_MSG_EXTRA_SIZE) * AGENT_RHB_BUFF_COUNT) +
        metadata_size;
    mpa->total_size = estimated_size;
}

static void InitTaskWork(mes_profile_t *pf)
{
    pf->send_task_count[CMA_MES_PRIORITY] = 1;
    pf->recv_task_count[CMA_MES_PRIORITY] = 1;
}

static void initPfile(mes_profile_t *pf, const RhbCtx *ctx)
{
    pf->inst_id = ctx->instId;
    pf->pipe_type = MES_TYPE_TCP;
    pf->conn_created_during_init = 1;
    pf->channel_cnt = 1;

    pf->mes_elapsed_switch = 0;

    pf->inst_cnt = ctx->instCount;
    errno_t rc = memcpy_s(
        pf->inst_net_addr, sizeof(mes_addr_t) * MES_MAX_INSTANCES, ctx->instAddrs, sizeof(mes_addr_t) * MAX_RHB_NUM);
    securec_check_errno(rc, (void)rc);

    InitTaskWork(pf);
    InitBuffPool(pf);
    pf->frag_size = AGENT_RHB_BUFF_SIZE;
    pf->max_wait_time = CM_MAX_WAIT_TIME;
    pf->connect_timeout = CM_CONNECT_TIMEOUT;
    pf->socket_timeout = CM_SOCKET_TIMEOUT;
    pf->send_directly = CM_TRUE;
    pf->tpool_attr.enable_threadpool = CM_FALSE;
}

// it's from CBB cm_log.h
typedef enum CbbLogLevel_ {
    LEVEL_ERROR = 0,  // error conditions
    LEVEL_WARN,       // warning conditions
    LEVEL_INFO,       // informational messages
} CbbLogLevel;

typedef enum CbbLogType_ {
    LOG_RUN = 0,
    LOG_DEBUG,
    LOG_ALARM,
    LOG_AUDIT,
    LOG_OPER,
    LOG_MEC,
    LOG_TRACE,
    LOG_PROFILE,
    LOG_COUNT  // LOG COUNT
} CbbLogType;

static void LogCallBack(int logType, int logLevel, const char *codeFileName, unsigned int codeLineNum,
    const char *moduleName, const char *fmt, ...) __attribute__((format(printf, 6, 7)));

static void LogCallBack(int logType, int logLevel, const char *codeFileName, unsigned int codeLineNum,
    const char *moduleName, const char *fmt, ...)
{
    int loglvl;
    switch (logLevel) {
        case LEVEL_ERROR:
            loglvl = ERROR;
            break;
        case LEVEL_WARN:
            loglvl = WARNING;
            break;
        case LEVEL_INFO:
            loglvl = (logType == (int)LOG_DEBUG) ? DEBUG5 : LOG;
            break;
        default:
            loglvl = LOG;
            break;
    }

    char newFmt[MAX_LOG_BUFF_LEN] = {0};
    char pathSep;
#ifdef WIN32
    pathSep = '\\';
#else
    pathSep = '/';
#endif

    const char *lastFile = strrchr(codeFileName, pathSep);
    if (lastFile == NULL) {
        lastFile = "unknow";
    }
    int32 rcs =
        snprintf_s(newFmt, MAX_LOG_BUFF_LEN, MAX_LOG_BUFF_LEN - 1, "%s [%s:%u]\n", fmt, lastFile + 1, codeLineNum);
    securec_check_intval(rcs, (void)rcs);

    va_list ap;
    va_start(ap, fmt);
    WriteRunLogv(loglvl, newFmt, ap);
    va_end(ap);
}

typedef void (*CmMesMsgProc)(mes_msg_t *mgs);

typedef struct ProcessorFunc_ {
    RhbMsgCmd cmd;
    CmMesMsgProc proc;
    uint8 isEnqueue;  // Whether to let the worker thread process
    const char *desc;
} ProcessorFunc;

typedef struct Hbs_ {
    unsigned int hwl;
    time_t hbs[MAX_RHB_NUM];
} Hbs;

static Hbs g_curNodeHb = {0};

void GetHbs(time_t *hbs, unsigned int *hwl)
{
    // concurrency lock?
    *hwl = g_curNodeHb.hwl;
    errno_t rc = memcpy_s(hbs, sizeof(time_t) * (*hwl), g_curNodeHb.hbs, sizeof(time_t) * (*hwl));
    securec_check_errno(rc, (void)rc);
}

void CmaHdlRhbReq(mes_msg_t *msg)
{
    write_runlog(DEBUG1, "[RHB] receive a hb msg from inst[%hhu]!\n", msg->src_inst);
    if (msg->src_inst < g_curNodeHb.hwl) {
        g_curNodeHb.hbs[msg->src_inst] = time(NULL);
    }
}

static const ProcessorFunc g_processors[RHB_MSG_CEIL] = {
    {RHB_MSG_HB_BC, CmaHdlRhbReq, CM_FALSE, "handle cma rhb broadcast message"},
};

void MesMsgProc(unsigned int work_idx, ruid_type ruid, mes_msg_t *msg)
{
    if (msg == NULL || msg->buffer == NULL) {
        write_runlog(ERROR, "invaild msg, when msg or buffer is null.\n");
        return;
    }

    if (msg->size < sizeof(CmaMesMsgHead)) {
        write_runlog(ERROR, "unknown msg head from inst:[%u], size:[%u].\n", msg->src_inst, msg->size);
        return;
    }

    CmaMesMsgHead *head = (CmaMesMsgHead *)msg->buffer;
    if (head->cmd >= (uint32)RHB_MSG_CEIL) {
        write_runlog(ERROR, "unknow cmd(%hhu) from inst:[%hhu], size:[%hu]!\n",
            head->cmd, msg->src_inst, head->bufSize);
        return;
    }

    const ProcessorFunc *processor = &g_processors[head->cmd];

    CM_ASSERT(processor->proc != NULL);

    processor->proc(msg);
}

status_t CmaRhbInit(const RhbCtx *ctx)
{
    mes_profile_t pf = {0};
    initPfile(&pf, ctx);
    g_curNodeHb.hwl = ctx->instCount;

    // regist mes log func callback
    mes_init_log();
    mes_register_log_output(LogCallBack);

    mes_register_proc_func(MesMsgProc);

    // ssl decode func
    if (IsBoolCmParamTrue(g_enableMesSsl)) {
        CM_RETURN_ERR_IF_INTERR(mes_set_param("SSL_CA", g_sslOption.ssl_para.ca_file));
        CM_RETURN_ERR_IF_INTERR(mes_set_param("SSL_KEY", g_sslOption.ssl_para.key_file));
        CM_RETURN_ERR_IF_INTERR(mes_set_param("SSL_CERT", g_sslOption.ssl_para.cert_file));
        if (g_sslOption.ssl_para.crl_file != NULL) {
            CM_RETURN_ERR_IF_INTERR(mes_set_param("SSL_CRL", g_sslOption.ssl_para.cert_file));
        }

        char notifyTime[PASSWD_MAX_LEN] = {0};
        errno_t rc = snprintf_s(notifyTime, PASSWD_MAX_LEN, PASSWD_MAX_LEN - 1, "%u", g_sslOption.expire_time);
        securec_check_intval(rc, (void)rc);
        CM_RETURN_ERR_IF_INTERR(mes_set_param("SSL_CERT_NOTIFY_TIME", notifyTime));

        char plain[PASSWD_MAX_LEN + 1] = {0};
        CM_RETURN_IFERR(cm_verify_ssl_key_pwd(plain, PASSWD_MAX_LEN, CLIENT_CIPHER));
        CM_RETURN_ERR_IF_INTERR(mes_set_param("SSL_PWD_PLAINTEXT", plain));

        const int32 tryTime = 3;
        for (int32 i = 0; i < tryTime; ++i) {
            rc = memset_s(plain, PASSWD_MAX_LEN + 1, 0, PASSWD_MAX_LEN + 1);
            securec_check_errno(rc, (void)rc);
        }
        write_runlog(LOG, "enable mes ssl.\n");
    } else {
        write_runlog(WARNING, "mes ssl not enable!.\n");
    }

    status_t ret = (status_t)mes_init(&pf);
    if (ret != CM_SUCCESS) {
        write_runlog(ERROR, "mes init failed!.\n");
        return ret;
    }

    write_runlog(LOG, "RHB mes init success!\n");
    return CM_SUCCESS;
}

static void InitMsgHead(CmaMesMsgHead *head, const RhbCtx *ctx)
{
    head->version = 0;
    head->cmd = (uint32)RHB_MSG_HB_BC;
    head->bufSize = 0;
}

static void checkMesSslCertExpire()
{
    write_runlog(LOG, "start check mes ssl cert expire time.\n");
    if (mes_chk_ssl_cert_expire() != 0) {
        write_runlog(ERROR, "check mes ssl cert expire time failed.\n");
        return;
    }

    write_runlog(LOG, "check mes ssl cert expire time done.\n");
}

void CmaRhbUnInit()
{
    g_exitFlag = true;
    write_runlog(LOG, "Got exit, set g_exitFlag to true and wait rhb thread exit!\n");
    (void)pthread_join(g_rhbThread, NULL);
}

void *CmaRhbMain(void *args)
{
    thread_name = "RHB";

    RhbCtx *ctx = (RhbCtx *)args;

    // for ssl cleanup
    (void)atexit(CmaRhbUnInit);

    write_runlog(LOG, "RHB check is ready to work!\n");
    CmaMesMsgHead head = {0};
    InitMsgHead(&head, ctx);
    int32 ret = 0;
    int itv = 0;
    struct timespec curTime = {0, 0};
    struct timespec lastTime = {0, 0};
    for (;;) {
        if (g_exitFlag || g_shutdownRequest) {
            write_runlog(LOG, "Get exit flag, RHB thread will exit!\n");
            break;
        }

        (void)clock_gettime(CLOCK_MONOTONIC, &curTime);
        if (IsBoolCmParamTrue(g_enableMesSsl) &&
            (curTime.tv_sec - lastTime.tv_sec) >= (time_t)g_sslCertExpireCheckInterval) {
            checkMesSslCertExpire();
            (void)clock_gettime(CLOCK_MONOTONIC, &lastTime);
        }

        write_runlog(DEBUG1, "RHB broadcast hb to all nodes.!\n");
        ret = mes_broadcast_sp(ctx->instType, ctx->instCount - 1, 0, (char*)&head, sizeof(CmaMesMsgHead));
        if (ret != 0) {
            write_runlog(DEBUG1, "bc not all success, ret=%d.\n", ret);
        }

        const int printItv = 5;
        if (itv++ % printItv == 0) {
            PrintRhb(g_curNodeHb.hbs, g_curNodeHb.hwl, "RHB");
        }

        CmSleep((int32)g_cmaRhbItvl);
    }

    write_runlog(LOG, "mes_uninit before exit!\n");
    mes_uninit();
    write_runlog(LOG, "RHB thread exit!\n");
    return NULL;
}

void CreateRhbCheckThreads()
{
    if (g_cmaRhbItvl == 0) {
        write_runlog(LOG, "agent_rhb_interval is 0, no need rhb.\n");
        return;
    }

    if (g_currentNode->datanodeCount == 0) {
        write_runlog(LOG, "current node has no datanode, no need rhb.\n");
        return;
    }

    g_ctx.sid = AGENT_RHB_CHECK_SID;
    InitRhbCtxByStaticConfig(&g_ctx);

    if (CmaRhbInit(&g_ctx) != CM_SUCCESS) {
        write_runlog(FATAL, "init cma heartbeat conn by mes failed, RHB check thread will exit.\n");
        exit(1);
    }

    int err;
    if ((err = pthread_create(&g_rhbThread, NULL, CmaRhbMain, &g_ctx)) != 0) {
        write_runlog(ERROR, "Failed to create cma mes thread %d: %d\n", err, errno);
    } else {
        write_runlog(LOG, "start rhb check thread success.\n");
    }
}
