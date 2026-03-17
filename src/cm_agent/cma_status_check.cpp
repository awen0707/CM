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
 * cma_status_check.cpp
 *    cma process cms messages functions
 *
 * IDENTIFICATION
 *    src/cm_agent/cma_status_check.cpp
 *
 * -------------------------------------------------------------------------
 */
#include <mntent.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "cma_connect.h"
#include "cma_global_params.h"
#include "cma_common.h"
#include "cma_client.h"
#include "cma_instance_management.h"
#include "cma_instance_management_res.h"
#include "cma_process_messages.h"
#include "cma_connect.h"
#include "cma_instance_check.h"
#ifdef ENABLE_MULTIPLE_NODES
#include "cma_coordinator.h"
#endif
#include "cma_status_check.h"
#include "cm_ip.h"
#include "cm_msg_version_convert.h"

/*
 * dilatation status. If the cluster in dilatation status, we query  coordinate and report status for every loop. Or,
 * only query once. If you want to use this flag, you need to restart cm_agent. The default value is true means, we need
 * to query coordinate at least once at the start time.
 */
const int ETCD_CHECK_TIMES = 3;
static const int THRESHOLD_FORMAT = 4;
static const int THRESHOLD_MAX_VALUE = 100;
static const int THRESHOLD_MIN_VALUE = 0;
static const int INFO_POS = 5;

using CpuInfo = struct CpuInfoSt {
    uint64 cpuUser;
    uint64 cpuNice;
    uint64 cpuSys;
    uint64 cpuIdle;
    uint64 cpuIwait;
    uint64 cpuHardirq;
    uint64 cpuSoftirq;
    uint64 cpuSteal;
    uint64 cpuGuest;
    uint64 cpuGuestNice ;
};

void etcd_status_check_and_report(void)
{
    if (g_currentNode->etcd == 0) {
        return;
    }

    cm_query_instance_status reportMsg = {0};
    (void)pthread_rwlock_wrlock(&(g_etcdReportMsg.lk_lock));
    errno_t rc = memcpy_s(&reportMsg, sizeof(cm_query_instance_status),
        &(g_etcdReportMsg.report_msg), sizeof(cm_query_instance_status));
    securec_check_errno(rc, (void)rc);
    (void)pthread_rwlock_unlock(&(g_etcdReportMsg.lk_lock));

    PushMsgToCmsSendQue((char *)&reportMsg, (uint32)sizeof(cm_query_instance_status), "etcd status");
}

static status_t GetCpuInfo(IoStat *stat, CpuInfo &cpu, const char *line)
{
    int ret;

    ret = sscanf_s(line + INFO_POS, "%lu %lu %lu %lu %lu %lu %lu %lu %lu %lu", &cpu.cpuUser, &cpu.cpuNice, &cpu.cpuSys,
        &cpu.cpuIdle, &cpu.cpuIwait, &cpu.cpuHardirq, &cpu.cpuSoftirq, &cpu.cpuSteal, &cpu.cpuGuest, &cpu.cpuGuestNice);
    if (ret == -1) {
        write_runlog(ERROR, "get cpu info fail, result is %d.\n", ret);
        return CM_ERROR;
    }
    if (stat != NULL) {
        stat->idle = cpu.cpuIdle;
        stat->uptime = cpu.cpuUser + cpu.cpuNice + cpu.cpuSys + cpu.cpuIdle + cpu.cpuIwait + cpu.cpuHardirq +
            cpu.cpuSteal + cpu.cpuSoftirq;
    }

    return CM_SUCCESS;
}

static int ReadCpuStatus(int cpu_nr, IoStat *stat, bool getTotalCpuHave)
{
    FILE* cpufp;
    char line[8192];
    CpuInfo cpu = {0};

    if ((cpufp = fopen(FILE_CPUSTAT, "re")) == NULL) {
        write_runlog(ERROR, "cannot open file: %s \n", FILE_CPUSTAT);
        return -1;
    }
    while (fgets(line, sizeof(line), cpufp) != NULL) {
        /* first line -- total cpu */
        if (!strncmp(line, "cpu ", 4) && (cpu_nr == 1 || getTotalCpuHave)) {
            /* for non smp iostat or cpu stat, get the total jiffies */
            if (GetCpuInfo(stat, cpu, line) != CM_SUCCESS) {
                (void)fclose(cpufp);
                return -1;
            }
            (void)fclose(cpufp);
            uint64 tmp = cpu.cpuUser + cpu.cpuNice + cpu.cpuSys;
            uint64 total = tmp + cpu.cpuIdle;
            if (total == 0) {
                write_runlog(ERROR, "abnormal cpu info.\n");
                return -1;
            }

            return (int)((PERCENT * tmp) / total);
        }

        /* for smp, cpu0 is enough for iostat */
        if (cpu_nr > 1 && !strncmp(line, "cpu0", 4)) {
            if (GetCpuInfo(stat, cpu, line) != CM_SUCCESS) {
                (void)fclose(cpufp);
                return -1;
            }
            (void)fclose(cpufp);

            return 0;
        }
    }
    write_runlog(ERROR, "get cpu info fail.\n");
    (void)fclose(cpufp);

    return 0;
}

void ReadDiskstatsStatus(const char* device, IoStat* stat)
{
    FILE* iofp;
    char line[MAX_PATH_LEN] = {0};
    char dev_name[MAX_DEVICE_DIR] = {0};
    int i;
    uint64 rd_ios, rd_merges_or_rd_sec, rd_ticks_or_wr_sec;
    uint64 wr_ios, wr_merges, rd_sec_or_wr_ios, wr_sec;
    uint32 major, minor;
    uint32 rq_ticks, ios_pgr, wr_ticks;

    if ((iofp = fopen(FILE_DISKSTAT, "re")) == NULL) {
        write_runlog(ERROR, "failed to open file %s", FILE_DISKSTAT);
        return;
    }

    while (fgets(line, MAX_PATH_LEN, iofp) != NULL) {
        i = sscanf_s(line,
            "%u %u %s %lu %lu %lu %lu %lu %lu %lu %u %u %lu %u",
            &major,
            &minor,
            dev_name,
            MAX_DEVICE_DIR - 1,
            &rd_ios,
            &rd_merges_or_rd_sec,
            &rd_sec_or_wr_ios,
            &rd_ticks_or_wr_sec,
            &wr_ios,
            &wr_merges,
            &wr_sec,
            &wr_ticks,
            &ios_pgr,
            &stat->tot_ticks,
            &rq_ticks);
        check_sscanf_s_result(i, 14);
        securec_check_intval(i, (void)i);

        if (i == 14) {
            if (strcmp(dev_name, device) != 0) {
                continue;
            } else {
                break;
            }
        }
    }

    if (*dev_name == '\0') {
        write_runlog(LOG, "cannot get the information of the file %s.\n", FILE_DISKSTAT);
    }

    (void)fclose(iofp);
}

uint64 GetAverageValue(uint64 value1, uint64 value2, uint64 itv, uint32 unit)
{
    if (itv == 0) {
        return 0;
    }
    if ((value2 < value1) && (value1 <= 0xffffffff)) {
        /* Counter's type was unsigned long and has overflown */
        return (((value2 - value1) & 0xffffffff)) * unit / itv;
    } else {
        return ((value2 - value1) * unit / itv);
    }
}

static uint64 ReadDiskIOStat(const char* device, int cpu_nr, IoStat* oldIoStatus, bool needWriteLog)
{
    long ticks;
    IoStat ioStatus = {0};

    if ((ticks = sysconf(_SC_CLK_TCK)) == -1) {
        write_runlog(ERROR, "get ticks fail.\n");
        return 0;
    }

    uint32 hz = (unsigned int)ticks;

    (void)ReadCpuStatus(cpu_nr, &ioStatus, false);
    if (ioStatus.uptime == 0) {
        write_runlog(LOG, "get cpu time iz 0.\n");
        return 0;
    }
    uint64 totalTime = ioStatus.uptime - oldIoStatus->uptime;
    uint64 idleTime = ioStatus.idle - oldIoStatus->idle;
    if (oldIoStatus->uptime == 0 || totalTime == 0) {
        write_runlog(DEBUG1, "uptime is %lu, old_uptime is %lu,\n", ioStatus.uptime, oldIoStatus->uptime);
        oldIoStatus->uptime = ioStatus.uptime;
        oldIoStatus->idle = ioStatus.idle;
        ReadDiskstatsStatus(device, oldIoStatus);
        return 0;
    }

    /* get block io info for the specified device */
    ReadDiskstatsStatus(device, &ioStatus);

    /* get iostat */
    /* tot_ticks unit: ms, itv/HZ unit:s, util is percentage, unit: %. */
    const uint32 percent = 100;
    uint64 ioUtil = GetAverageValue(oldIoStatus->tot_ticks, ioStatus.tot_ticks, totalTime, hz) / 10;
    uint64 cpuUtil = percent * (totalTime - idleTime) / totalTime;

    oldIoStatus->tot_ticks = ioStatus.tot_ticks;
    oldIoStatus->uptime = ioStatus.uptime;
    oldIoStatus->idle = ioStatus.idle;

    if (ioUtil > PERCENT) {
        ioUtil = PERCENT;
    }

    if (!needWriteLog) {
        write_runlog(DEBUG1, "device %s, [Io util: %lu%%]\n", device, ioUtil);
        return ioUtil;
    }

    if (ioUtil > 60) {
        write_runlog(LOG, "device %s, [Cpu util: %lu%%], [Io util: %lu%%]\n", device, cpuUtil, ioUtil);
    } else {
        write_runlog(DEBUG1, "device %s, [Cpu util: %lu%%], [Io util: %lu%%]\n", device, cpuUtil, ioUtil);
    }
    return ioUtil;
}

static void CmGetDisk(const char* datadir, char* devicename, uint32 nameLen)
{
    char dfcommand[MAX_PATH_LEN] = {0};
    char devicePath[MAX_PATH_LEN] = {0};
    errno_t rc = snprintf_s(dfcommand, MAX_PATH_LEN, MAX_PATH_LEN - 1, "df -h %s", datadir);
    securec_check_intval(rc, (void)rc);
    const char* mode = "r";
    FILE* fp = popen(dfcommand, mode);
    if (fp == NULL) {
        write_runlog(ERROR, "execute %s fail\n", dfcommand);
        return;
    }
    char buf[CM_MAX_COMMAND_LONG_LEN] = {0};
    if (fgets(buf, sizeof(buf), fp) == NULL) {
        (void)pclose(fp);
        write_runlog(ERROR, "get first line fail.\n");
        return;
    } else {
        write_runlog(LOG, "first line is %s.\n", buf);
    }
    if (fgets(buf, sizeof(buf), fp) != NULL) {
        write_runlog(LOG, "second line is %s.\n", buf);
        uint32 length = (uint32)strlen(buf);
        if (length == 0) {
            (void)pclose(fp);
            write_runlog(LOG, "execute %s, result is empty.\n", dfcommand);
            return;
        }
        uint32 lengthDevice = 0;
        for (uint32 i = 0; i < length; i++) {
            if (lengthDevice >= MAX_PATH_LEN - 1) {
                (void)pclose(fp);
                write_runlog(LOG, "length is not enough for etcd data path device.\n");
                return;
            }
            /* read end */
            if ((buf[i] == ' ' || buf[i] == 10)) {
                break;
            }
            devicePath[lengthDevice] = buf[i];
            lengthDevice++;
        }
    } else {
        (void)pclose(fp);
        write_runlog(ERROR, "get second line fail.\n");
        return;
    }

    (void)pclose(fp);

    rc = snprintf_s(dfcommand, MAX_PATH_LEN, MAX_PATH_LEN - 1, "ls -l %s", devicePath);
    securec_check_intval(rc, (void)rc);

    fp = popen(dfcommand, mode);
    if (fp == NULL) {
        write_runlog(ERROR, "execute %s fail\n", dfcommand);
        return;
    } else {
        write_runlog(LOG, "execute %s success.\n", dfcommand);
    }
    if (fgets(buf, sizeof(buf), fp) != NULL) {
        uint32 length = (uint32)strlen(buf);
        bool findDevice = false;
        if (length == 0) {
            (void)pclose(fp);
            write_runlog(LOG, "execute %s, result is empty.\n", dfcommand);
            return;
        }
        uint lengthDevice = 0;
        for (uint32 i = 0; i < length; i++) {
            if (lengthDevice >= MAX_DEVICE_DIR - 1) {
                (void)pclose(fp);
                write_runlog(LOG, "length is not enough for etcd data path device.\n");
                return;
            }
            if (buf[i] != '>' && lengthDevice == 0 && !findDevice) {
                continue;
            }
            if (buf[i] == '>') {
                findDevice = true;
                continue;
            }
            if (findDevice && (lengthDevice != 0 || buf[i] == '/')) {
                if (buf[i] == '/') {
                    i++;
                }
                if ((buf[i] == ' ' || buf[i] == 10)) {
                    break;
                }
                if (i < length && lengthDevice < nameLen) {
                    devicename[lengthDevice] = buf[i];
                    lengthDevice++;
                }
            }
        }
        if (findDevice) {
            write_runlog(LOG, "device name is %s.\n", devicename);
            (void)pclose(fp);
            return;
        }
    }
    (void)pclose(fp);

    size_t buf_len = 0;
    struct mntent* ent;
    struct mntent tempEnt = {};

    FILE *mtfp = fopen(FILE_MOUNTS, "re");
    if (mtfp == NULL) {
        write_runlog(LOG, "cannot open file %s.\n", FILE_MOUNTS);
        return;
    }

    /* The buffer is too big, so it can not be stored in the stack space. */
    char *mntentBuffer = (char *)malloc(4 * FILENAME_MAX);
    if (mntentBuffer == NULL) {
        write_runlog(ERROR,
            "Failed to allocate memory: Out of memory. RequestSize=%d.\n", 4 * FILENAME_MAX);
        (void)fclose(mtfp);
        return;
    }

    while ((ent = getmntent_r(mtfp, &tempEnt, mntentBuffer, 4 * FILENAME_MAX)) != NULL) {
        buf_len = strlen(ent->mnt_fsname);
        /*
         * get the file system with type of ext* or xfs.
         * find the best fit for the data directory
         */
        const size_t offset = strlen("/dev/");
        if (strncmp(ent->mnt_fsname, devicePath, buf_len) == 0 && strlen(datadir) >= buf_len &&
            buf_len == strlen(devicePath)) {
            rc = strncpy_s(devicename, MAX_DEVICE_DIR, ent->mnt_fsname + offset, strlen(ent->mnt_fsname + offset));
            if (rc != 0) {
                write_runlog(ERROR, "memcpy device name fail.\n");
                (void)fclose(mtfp);
                FREE_AND_RESET(mntentBuffer);
                return;
            } else {
                break;
            }
        }
    }

    write_runlog(LOG, "devicename is %s.\n", devicename);

    (void)fclose(mtfp);
    FREE_AND_RESET(mntentBuffer);
}

static int GetCpuCount(void)
{
    char pathbuf[4096] = {0};
    int ret = 0;
    int cpucnt = 0;
    errno_t rc;

    if (access("/sys/devices/system", F_OK) == 0) {
        do {
            rc = snprintf_s(pathbuf, sizeof(pathbuf), sizeof(pathbuf) - 1, "/sys/devices/system/cpu/cpu%d", cpucnt);
            securec_check_intval(rc, (void)rc);

            ret = access(pathbuf, F_OK);
            if (ret == 0) {
                cpucnt++;
            }
        } while (ret == 0);
    } else if (access("/proc/cpuinfo", F_OK) == 0) {
        FILE* fd;

        if ((fd = fopen("/proc/cpuinfo", "re")) == NULL) {
            return -1;
        }

        while (fgets(pathbuf, sizeof(pathbuf), fd) != NULL) {
            if (strncmp("processor", pathbuf, strlen("processor")) == 0) {
                cpucnt++;
            }
        }
        (void)fclose(fd);
    }

    return cpucnt ? cpucnt : -1;
}
void etcd_disk_quota_check(const char *instanceName, const char *etcdData)
{
    char check_cmd[CM_MAX_COMMAND_LONG_LEN] = {0};
    const uint64 warningDiskQuota = 8160437862;    /* 8G * 95%. */
    int needWarning = 0;
    int rcs;

    rcs = sprintf_s(check_cmd, sizeof(check_cmd),
        "if [ `ls -l \"%s/member/snap/db\" | awk '{print $5}'` -ge %lu ]; then echo '1'; else echo '0'; fi;",
        etcdData, warningDiskQuota);
    securec_check_intval(rcs, (void)rcs);

    FILE *fp = popen(check_cmd, "r");
    if (fp == NULL) {
        write_runlog(ERROR, "etcd_disk_quota_check fail: %s\n", check_cmd);
        return;
    }

    rcs = fscanf_s(fp, "%d", &needWarning);
    if (rcs > 0) {
        /* used to control whether or not print local log */
        static int appear_cnt = 0;

        if (needWarning == 1) {
            if (appear_cnt++ % 5 == 0) {
                appear_cnt = 1;
                write_runlog(LOG, "etcd db files takes too much disk space.\n");
            }
            report_ddb_fail_alarm(ALM_AT_Fault, instanceName, 2, DB_ETCD);
        } else {
            if (appear_cnt != 0) {
                write_runlog(LOG, "etcd db files takes normal disk space.\n");
                appear_cnt = 0;
            }
            report_ddb_fail_alarm(ALM_AT_Resume, instanceName, 2, DB_ETCD);
        }
    } else {
        write_runlog(LOG, "Failed to get etcd db files's disk space.\n");
    }
    (void)pclose(fp);
}

static void GetDdbCfgApi(DrvApiInfo *drvApiInfo, ServerSocket *server, uint32 serverLen)
{
    drvApiInfo->nodeNum = serverLen - 1;
    drvApiInfo->serverList = server;
    drvApiInfo->serverLen = serverLen;
    drvApiInfo->modId = MOD_CMA;
    drvApiInfo->nodeId = g_currentNode->node;

    drvApiInfo->client_t.tlsPath = &g_tlsPath;
    drvApiInfo->timeOut = DDB_DEFAULT_TIMEOUT;
}

static void SetServerSocketWithEtcdInfo(ServerSocket *server, staticNodeConfig *node)
{
    server->nodeIdInfo.azName = node->azName;
    server->nodeIdInfo.nodeId = node->node;
    server->nodeIdInfo.instd = node->etcdId;
    server->nodeInfo.nodeName = node->etcdName;
    server->nodeInfo.len = CM_NODE_NAME;
    server->host = node->etcdClientListenIPs[0];
    server->port = node->etcdClientListenPort;
}

int CheckCertFilePermission(const char *certFile)
{
    struct stat buf;
    if (stat(certFile, &buf) != 0) {
        write_runlog(WARNING, "Try to stat cert key file \"%s\" failed!\n", certFile);
        return -1;
    }
    if (!S_ISREG(buf.st_mode) || (buf.st_mode & (S_IRWXG | S_IRWXO)) || ((buf.st_mode & S_IRWXU) == S_IRWXU)) {
        write_runlog(WARNING, "The file \"%s\" permission should be u=rw(600) or less.\n", certFile);
        return -1;
    }
    return 0;
}
bool EtcdCertFileExpire(const char *certFile)
{
    int rcs;
    const int expireDays = 90;
    int expireSeconds = expireDays * 24 * 60 * 60;
    char command[CM_PATH_LENGTH] = {0};
    char result[CM_PATH_LENGTH] = {0};
    const char *certExpire = "Certificate will expire";
    rcs = snprintf_s(command, CM_PATH_LENGTH, CM_PATH_LENGTH - 1, "openssl x509 -in %s -checkend %d 2>&1 &", certFile,
        expireSeconds);
    securec_check_intval(rcs, (void)rcs);
    if (!ExecuteCmdWithResult(command, result, CM_PATH_LENGTH)) {
        write_runlog(WARNING, "Execute check etcd cert file expire cmd %s failed, result=%s\n", command, result);
        return false;
    }
    if (strstr(result, certExpire) != NULL) {
        write_runlog(WARNING,
            "etcd cert file %s may has been expired or will be expired in less %d days, please check!\n", certFile,
            expireDays);
        return true;
    }
    return false;
}
void CheckEtcdClientCertFile()
{
    (void)CheckCertFilePermission(g_tlsPath.caFile);
    (void)CheckCertFilePermission(g_tlsPath.crtFile);
    (void)CheckCertFilePermission(g_tlsPath.keyFile);
    (void)EtcdCertFileExpire(g_tlsPath.caFile);
}
void CheckEtcdServerCertFile()
{
    int rcs;
    char caFile[MAX_PATH_LEN] = {0};
    char keyFile[MAX_PATH_LEN] = {0};
    rcs = snprintf_s(caFile, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/etcd.crt", g_currentNode->etcdDataPath);
    securec_check_intval(rcs, (void)rcs);
    rcs = snprintf_s(keyFile, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/etcd.key", g_currentNode->etcdDataPath);
    securec_check_intval(rcs, (void)rcs);
    (void)CheckCertFilePermission(caFile);
    (void)CheckCertFilePermission(keyFile);
    (void)EtcdCertFileExpire(caFile);
}
void CheckEtcdCertFile()
{
    static int checkTimes = 0;
    const int everyCheckTime = 60;
    // every 10 or 5 minutes, check etcd cert file permission or expire time in ETCDStatusCheckMain thread
    // just to avoid warning log print too many
    if (checkTimes >= everyCheckTime) {
        CheckEtcdClientCertFile();
        CheckEtcdServerCertFile();
        checkTimes = 0;
    } else {
        checkTimes++;
    }
}
void* ETCDStatusCheckMain(void* arg)
{
    thread_name = "ETCD_CHECK";
    pthread_t threadId = pthread_self();
    write_runlog(LOG, "etcd status check thread start, threadid %lu.\n", threadId);
    int etcdReportFre = ETCD_NODE_UNHEALTH_FRE;
    char devicename[MAX_DEVICE_DIR] = {0};
    CmGetDisk(g_currentNode->etcdDataPath, devicename, MAX_DEVICE_DIR);
    uint64 devicenamelength = strlen(devicename);
    IoStat ioStatus = {0};
    int cpu_nr = GetCpuCount();
    errno_t rc;
    cm_query_instance_status cm_query_instance_status_content = {0};
    cm_query_instance_status_content.nodeId = g_currentNode->node;
    cm_query_instance_status_content.msg_type = MSG_CM_QUERY_INSTANCE_STATUS;
    cm_query_instance_status_content.msg_step = QUERY_STATUS_CMAGENT_STEP;
    cm_query_instance_status_content.instanceType = PROCESS_ETCD;
    cm_query_instance_status_content.pending = false;

    char instanceName[CM_NODE_NAME] = {0};
    rc = snprintf_s(
        instanceName, sizeof(instanceName), sizeof(instanceName) - 1, "%s_%u", "etcd", g_currentNode->etcdId);
    securec_check_intval(rc, (void)rc);
    char command[MAXPGPATH * 2] = {0};
    int checkInvalidEtcdTimes = 0;
    const uint32 serverLen = 2;
    ServerSocket server[serverLen] = {{0}};
    SetServerSocketWithEtcdInfo(&server[0], g_currentNode);
    server[1].host = NULL;
    status_t st = CM_SUCCESS;
    DdbInitConfig config = {DB_ETCD};
    GetDdbCfgApi(&config.drvApiInfo, server, serverLen);
    DdbNodeState nodeState;
    for (;;) {
        if (devicenamelength > 0) {
            (void)ReadDiskIOStat(devicename, cpu_nr, &ioStatus, true);
        }
        CheckEtcdCertFile();

        if (g_shutdownRequest || (agent_cm_server_connect == NULL) || g_exitFlag) {
            write_runlog(LOG, "receive exit request in cma ETCDStatusCheckMain.\n");
            cm_sleep(5);
            continue;
        }
        if (cpu_nr <= 0) {
            cpu_nr = GetCpuCount();
        }
        int tryTime = 0;
        int tryTime1 = 0;

        rc = memset_s(&nodeState, sizeof(DdbNodeState), 0, sizeof(DdbNodeState));
        securec_check_errno(rc, (void)rc);

        DdbConn dbCon = {0};
        st = InitDdbConn(&dbCon, &config);
        if (st != CM_SUCCESS) {
            (void)pthread_rwlock_wrlock(&(g_etcdReportMsg.lk_lock));
            cm_query_instance_status_content.status = CM_ETCD_DOWN;
            rc = memcpy_s((void*)&(g_etcdReportMsg.report_msg),
                sizeof(cm_query_instance_status_content),
                (void*)&cm_query_instance_status_content,
                sizeof(cm_query_instance_status_content));
            securec_check_errno(rc, (void)rc);
            (void)pthread_rwlock_unlock(&(g_etcdReportMsg.lk_lock));
            write_runlog(ERROR, "etcd open failed when query etcd status. %s\n", DdbGetLastError(&dbCon));
            cm_sleep(agent_check_interval);
            continue;
        }
        do {
            st = DdbInstanceState(&dbCon, g_currentNode->etcdName, &nodeState);
            if (st != CM_SUCCESS) {
                write_runlog(FATAL, "get ddb instance state failed, error is %s\n", DdbGetLastError(&dbCon));
            }

            tryTime1++;
            if (st != CM_SUCCESS) {
                if (nodeState.health == DDB_STATE_HEALTH) {
                    do {
                        st = DdbInstanceState(&dbCon, g_currentNode->etcdName, &nodeState);
                        tryTime++;
                        if (st != CM_SUCCESS) {
                            write_runlog(FATAL, "ddb instance is health, get state failed, error is %s\n",
                                DdbGetLastError(&dbCon));
                        }
                    } while ((st != CM_SUCCESS) && tryTime <= ETCD_CHECK_TIMES);
                }
            }
        } while ((st != CM_SUCCESS) && tryTime1 <= ETCD_CHECK_TIMES);

        if ((st != CM_SUCCESS) || (nodeState.health != DDB_STATE_HEALTH && nodeState.role == DDB_ROLE_LEADER)) {
            checkInvalidEtcdTimes++;
        } else {
            checkInvalidEtcdTimes = 0;
        }
        if (checkInvalidEtcdTimes >= CHECK_INVALID_ETCD_TIMES) {
            write_runlog(
                ERROR, "can't get majority etcd state, but local is unhealthy and leader, will kill local etcd now.\n");
            checkInvalidEtcdTimes = 0;
            rc = strcpy_s(command, 2 * MAXPGPATH, SYSTEMQUOTE "killall etcd > /dev/null  2>&1 &" SYSTEMQUOTE);
            securec_check_errno(rc, (void)rc);
            int rct = system(command);
            if (rct != -1) {
                write_runlog(LOG, "killall etcd result is %d, shell result is %d.\n", rc, WEXITSTATUS(rc));
            } else {
                char error_buffer[ERROR_LIMIT_LEN] = {0};
                (void)strerror_r(errno, error_buffer, ERROR_LIMIT_LEN);

                write_runlog(ERROR, "Failed to call the system function: error=\"[%d] %s\","
                    " function=\"%s\", command=\"%s\".\n", errno, error_buffer, "system", command);
            }
        }

        if (DdbFreeConn(&dbCon) != CM_SUCCESS) {
            write_runlog(WARNING, "etcd_close failed,%s\n", DdbGetLastError(&dbCon));
        }
        if (st != CM_SUCCESS) {
            cm_query_instance_status_content.status = CM_ETCD_DOWN;
        } else {
            if (nodeState.role == DDB_ROLE_LEADER) {
                write_runlog(DEBUG1, "etcd state is StateLeader.\n");
                cm_query_instance_status_content.status = CM_ETCD_LEADER;
            } else if (nodeState.role == DDB_ROLE_FOLLOWER) {
                write_runlog(DEBUG1, "etcd state is StateFollower.\n");
                cm_query_instance_status_content.status = CM_ETCD_FOLLOWER;
            }
        }
        if (cm_query_instance_status_content.status == CM_ETCD_DOWN) {
            if (etcdReportFre > ETCD_NODE_UNHEALTH_FRE) {
                etcdReportFre = ETCD_NODE_UNHEALTH_FRE;
            }
            if (etcdReportFre > 0) {
                etcdReportFre--;
            }
            if (etcdReportFre <= 0) {
                /* report the alarm. */
                report_ddb_fail_alarm(ALM_AT_Fault, instanceName, 1, DB_ETCD);
            }
        } else {
            etcdReportFre = ETCD_NODE_UNHEALTH_FRE;
            report_ddb_fail_alarm(ALM_AT_Resume, instanceName, 1, DB_ETCD);
        }
        (void)pthread_rwlock_wrlock(&(g_etcdReportMsg.lk_lock));
        rc = memcpy_s((void*)&(g_etcdReportMsg.report_msg), sizeof(cm_query_instance_status_content),
            (void*)&cm_query_instance_status_content,
            sizeof(cm_query_instance_status_content));
        securec_check_errno(rc, (void)rc);
        (void)pthread_rwlock_unlock(&(g_etcdReportMsg.lk_lock));

        /* check and warn etcd db file's disk space */
        etcd_disk_quota_check(instanceName, g_currentNode->etcdDataPath);

        cm_sleep(10);
        continue;
    }
}

/* agent send report_msg to cm_server */
void kerberos_status_check_and_report()
{
    if (agent_cm_server_connect == NULL) {
        return;
    }
    char kerberosConfigPath[MAX_PATH_LEN] = {0};
    if (cmagent_getenv("MPPDB_KRB5_FILE_PATH", kerberosConfigPath, sizeof(kerberosConfigPath)) != EOK) {
        write_runlog(DEBUG1, "kerberos_status_check_and_report: MPPDB_KRB5_FILE_PATH get fail.\n");
        return;
    }

    struct stat stat_buf = {0};
    if (stat(kerberosConfigPath, &stat_buf) != 0) {
        write_runlog(DEBUG1, "kerberos_status_check_and_report: kerberos config file not exist.\n");
        return;
    }
    agent_to_cm_kerberos_status_report reportMsg = {0};
    (void)pthread_rwlock_wrlock(&(g_kerberosReportMsg.lk_lock));
    errno_t rc = memcpy_s(&reportMsg, sizeof(agent_to_cm_kerberos_status_report),
        &(g_kerberosReportMsg.report_msg), sizeof(agent_to_cm_kerberos_status_report));
    securec_check_errno(rc, (void)rc);
    (void)pthread_rwlock_unlock(&(g_kerberosReportMsg.lk_lock));

    PushMsgToCmsSendQue((char *)&reportMsg, (uint32)sizeof(agent_to_cm_kerberos_status_report), "kerberos status");
}

static void SendDnReportMsg(const DnStatus *pkgDnStatus, uint32 datanodeId)
{
    if (undocumentedVersion != 0 && undocumentedVersion < SUPPORT_IPV6_VERSION) {
        agent_to_cm_datanode_status_report_ipv4 reportMsg = {0};
        AgentToCmDatanodeStatusReportV2ToV1(&pkgDnStatus->reportMsg, &reportMsg);
        write_runlog(DEBUG5, "dn(%u) reportMsg will send to cms.\n", datanodeId);
        PushMsgToCmsSendQue((char *)&reportMsg, (uint32)sizeof(agent_to_cm_datanode_status_report_ipv4), "dn report");
    } else {
        agent_to_cm_datanode_status_report reportMsg = {0};
        errno_t rc = memcpy_s(&reportMsg, sizeof(agent_to_cm_datanode_status_report),
            &pkgDnStatus->reportMsg, sizeof(agent_to_cm_datanode_status_report));
        securec_check_errno(rc, (void)rc);
        write_runlog(DEBUG5, "dn(%u) reportMsg will send to cms.\n", datanodeId);
        PushMsgToCmsSendQue((char *)&reportMsg, (uint32)sizeof(agent_to_cm_datanode_status_report), "dn report");
    }
}

static void SendBarrierMsg(const DnStatus *pkgDnStatus, uint32 datanodeId)
{
    AgentToCmBarrierStatusReport barrierMsg = {0};
    errno_t rc = memcpy_s(&barrierMsg, sizeof(AgentToCmBarrierStatusReport),
        &pkgDnStatus->barrierMsg, sizeof(AgentToCmBarrierStatusReport));
    securec_check_errno(rc, (void)rc);

    write_runlog(DEBUG5, "dn(%u) barrier(%d) will send to cms.\n", datanodeId, (int)pkgDnStatus->barrierMsgType);
    PushMsgToCmsSendQue((char *)&barrierMsg, (uint32)sizeof(AgentToCmBarrierStatusReport), "dn barrier");
}

static void SendLpInfoMsg(const DnStatus *pkgDnStatus, uint32 datanodeId)
{
    AgentCmDnLocalPeer lpInfo = {0};
    errno_t rc = memcpy_s(&lpInfo, sizeof(AgentCmDnLocalPeer), &pkgDnStatus->lpInfo, sizeof(AgentCmDnLocalPeer));
    securec_check_errno(rc, (void)rc);

    write_runlog(DEBUG5, "dn(%u) dnLocalPeer will send to cms.\n", datanodeId);
    PushMsgToCmsSendQue((char *)&lpInfo, (uint32)sizeof(AgentCmDnLocalPeer), "dnLocalPeer");
}

static void SendDiskUsageMsg(const DnStatus *pkgDnStatus, uint32 datanodeId)
{
    AgentToCmDiskUsageStatusReport diskUsageMsg = {0};
    errno_t rc = memcpy_s(&diskUsageMsg, sizeof(AgentToCmDiskUsageStatusReport),
        &pkgDnStatus->diskUsageMsg, sizeof(AgentToCmDiskUsageStatusReport));
    securec_check_errno(rc, (void)rc);

    write_runlog(DEBUG5, "dn(%u) dnDiskUsage will send to cms.\n", datanodeId);
    PushMsgToCmsSendQue((char *)&diskUsageMsg, (uint32)sizeof(AgentToCmDiskUsageStatusReport), "dnDiskUsage");
}

static void SendFloatIpMsg(const CmaDnFloatIpInfo *floatIpInfo, uint32 dnId)
{
    if (!IsNeedCheckFloatIp() || (agent_backup_open != CLUSTER_PRIMARY)) {
        return;
    }
    if (floatIpInfo->info.count == 0) {
        return;
    }
    write_runlog(DEBUG5, "dn(%u) floatIpMsg will send to cms.\n", dnId);
    PushMsgToCmsSendQue((const char *)floatIpInfo, (uint32)sizeof(CmaDnFloatIpInfo), "dn floatIpMsg");
}

static void SendDnReportMsgCore(const DnStatus *pkgDnStatus, uint32 datanodeId, AgentToCmserverDnSyncList *syncListMsg)
{
    SendDnReportMsg(pkgDnStatus, datanodeId);
    SendFloatIpMsg(&(pkgDnStatus->floatIpInfo), datanodeId);
    if (g_clusterType == V3SingleInstCluster) {
        return;
    }
#if ((defined(ENABLE_MULTIPLE_NODES)) || (defined(ENABLE_PRIVATEGAUSS)))
    write_runlog(DEBUG5, "dn(%u) syncListMsg will send to cms.\n", datanodeId);
    PushMsgToCmsSendQue((char *)syncListMsg, (uint32)sizeof(AgentToCmserverDnSyncList), "dn syncListMsg");
#endif
    if (pkgDnStatus->barrierMsgType == MSG_AGENT_CM_DATANODE_INSTANCE_BARRIER) {
        SendBarrierMsg(pkgDnStatus, datanodeId);
        return;
    }
    SendDiskUsageMsg(pkgDnStatus, datanodeId);
    // only cascade standby cannot report lpInfo
    if (pkgDnStatus->reportMsg.receive_status.local_role != INSTANCE_ROLE_CASCADE_STANDBY) {
        return;
    }

    SendLpInfoMsg(pkgDnStatus, datanodeId);
}

static void DnStatusFinalProcessing(DnStatus* pkgDnStatus, uint32 dnId)
{
    if (pkgDnStatus->reportMsg.local_status.db_state == INSTANCE_HA_STATE_NORMAL ||
        pkgDnStatus->reportMsg.local_status.db_state == INSTANCE_HA_STATE_NEED_REPAIR ||
        pkgDnStatus->reportMsg.local_status.db_state == INSTANCE_HA_STATE_UNKONWN ||
        (pkgDnStatus->reportMsg.local_status.db_state == INSTANCE_HA_STATE_DEMOTING && 
         !g_isStorageWithDMSorDSS)) {
        g_dnRoleForPhonyDead[dnId] = pkgDnStatus->reportMsg.local_status.local_role;
    } else {
        g_dnRoleForPhonyDead[dnId] = INSTANCE_ROLE_INIT;
    }
    if (g_dnPhonyDeadD[dnId] || g_dnCore[dnId]) {
        pkgDnStatus->reportMsg.local_status.local_role = INSTANCE_ROLE_UNKNOWN;
        write_runlog(WARNING, "datenode phony dead D or Core, set local_role Unknown\n");
    }
    if (g_dnPingFault[dnId]) {
        pkgDnStatus->reportMsg.local_status.local_role = INSTANCE_ROLE_UNKNOWN;
        pkgDnStatus->reportMsg.local_status.db_state = INSTANCE_HA_STATE_UNKONWN;
        write_runlog(WARNING, "datenode ping fault, set local_role Unknown\n");
    }
}

static void CopyDnReportMsg(AgentToCmserverDnSyncList *syncList, uint32 ii)
{
    (void)pthread_rwlock_wrlock(&(g_dnSyncListInfo[ii].lk_lock));
    errno_t rcs = memcpy_s(syncList, sizeof(AgentToCmserverDnSyncList), &(g_dnSyncListInfo[ii].dnSyncListMsg),
        sizeof(AgentToCmserverDnSyncList));
    securec_check_errno(rcs, (void)rcs);
    g_dnSyncListInfo[ii].dnSyncListMsg.syncDone = FAILED_SYNC_DATA;
    (void)pthread_rwlock_unlock(&(g_dnSyncListInfo[ii].lk_lock));
}

void DatanodeStatusReport(void)
{
    errno_t rc;
    for (uint32 ii = 0; ii < g_currentNode->datanodeCount; ii++) {
        if (agent_cm_server_connect == NULL) {
            continue;
        }

        (void)pthread_rwlock_wrlock(&(g_dnReportMsg[ii].lk_lock));
        if (g_dnReportMsg[ii].dnStatus.reportMsg.local_status.local_role == INSTANCE_ROLE_PENDING ||
            (g_dnReportMsg[ii].dnStatus.reportMsg.processStatus != INSTANCE_PROCESS_RUNNING &&
                g_dnReportMsg[ii].dnStatus.reportMsg.connectStatus != AGENT_TO_INSTANCE_CONNECTION_OK)) {
            if (g_dnPhonyDeadTimes[ii] != 0) {
                g_dnPhonyDeadTimes[ii] = 0;
                write_runlog(
                    LOG, "reset dn(%u) phony dead time to zero.\n", g_dnReportMsg[ii].dnStatus.reportMsg.instanceId);
            }
        }
        if (g_dnReportMsg[ii].dnStatus.reportMsg.connectStatus == AGENT_TO_INSTANCE_CONNECTION_OK) {
            DnStatus dnStatus;
            rc = memcpy_s(&(dnStatus), sizeof(DnStatus), &(g_dnReportMsg[ii].dnStatus), sizeof(DnStatus));
            securec_check_errno(rc, (void)rc);
            (void)pthread_rwlock_unlock(&(g_dnReportMsg[ii].lk_lock));

            AgentToCmserverDnSyncList syncList = {0};
            CopyDnReportMsg(&syncList, ii);
            DnStatusFinalProcessing(&dnStatus, ii);
            dnStatus.reportMsg.phony_dead_times = g_dnPhonyDeadTimes[ii];

            SendDnReportMsgCore(&dnStatus, g_currentNode->datanode[ii].datanodeId, &syncList);
        } else if (g_dnReportMsg[ii].dnStatus.reportMsg.processStatus == INSTANCE_PROCESS_RUNNING) {
            (void)pthread_rwlock_unlock(&(g_dnReportMsg[ii].lk_lock));
            g_dnRoleForPhonyDead[ii] = INSTANCE_ROLE_INIT;
            agent_to_cm_heartbeat hbMsg = {0};
            hbMsg.msg_type = (int)MSG_AGENT_CM_HEARTBEAT;
            hbMsg.node = g_currentNode->node;
            hbMsg.instanceId = g_currentNode->datanode[ii].datanodeId;
            hbMsg.instanceType = INSTANCE_TYPE_DATANODE;

            PushMsgToCmsSendQue((char *)&hbMsg, (uint32)sizeof(agent_to_cm_heartbeat), "dn heartbeat");
        } else {
            DnStatus pkgDnStatus;
            rc = memcpy_s(&(pkgDnStatus), sizeof(DnStatus), &(g_dnReportMsg[ii].dnStatus), sizeof(DnStatus));
            securec_check_errno(rc, (void)rc);
            (void)pthread_rwlock_unlock(&(g_dnReportMsg[ii].lk_lock));

            AgentToCmserverDnSyncList syncList = {0};
            CopyDnReportMsg(&syncList, ii);
            g_dnRoleForPhonyDead[ii] = pkgDnStatus.reportMsg.local_status.local_role;

            SendDnReportMsgCore(&pkgDnStatus, g_currentNode->datanode[ii].datanodeId, &syncList);
        }
    }
}

void fenced_UDF_status_check_and_report(void)
{
    if (agent_cm_server_connect == NULL) {
        return;
    }

    agent_to_cm_fenced_UDF_status_report reportMsg = {0};
    reportMsg.msg_type = (int)MSG_AGENT_CM_FENCED_UDF_INSTANCE_STATUS;
    reportMsg.nodeid = g_nodeId;

    if (!g_fencedUdfStopped) {
        reportMsg.status = INSTANCE_ROLE_NORMAL;
    } else {
        reportMsg.status = INSTANCE_ROLE_UNKNOWN;
    }
    write_runlog(DEBUG5, "node(%u) fenced UDF status will send to cms.\n", reportMsg.nodeid);
    PushMsgToCmsSendQue((char *)&reportMsg, (uint32)sizeof(agent_to_cm_fenced_UDF_status_report), "fenced UDF status");
}

void InitReportMsg(agent_to_cm_datanode_status_report *reportMsg, int index)
{
    errno_t rc =
        memset_s(reportMsg, sizeof(agent_to_cm_datanode_status_report), 0, sizeof(agent_to_cm_datanode_status_report));
    securec_check_errno(rc, (void)rc);
    reportMsg->msg_type = MSG_AGENT_CM_DATA_INSTANCE_REPORT_STATUS;
    reportMsg->node = g_currentNode->node;
    reportMsg->instanceId = g_currentNode->datanode[index].datanodeId;
    reportMsg->instanceType = INSTANCE_TYPE_DATANODE;
    reportMsg->dn_restart_counts = g_dnReportMsg[index].dnStatus.reportMsg.dn_restart_counts;
}

void InitDnLocalPeerMsg(AgentCmDnLocalPeer *lpInfo, int32 index)
{
    errno_t rc = memset_s(lpInfo, sizeof(AgentCmDnLocalPeer), 0, sizeof(AgentCmDnLocalPeer));
    securec_check_errno(rc, (void)rc);
    lpInfo->msgType = (int32)MSG_AGENT_CM_DATANODE_LOCAL_PEER;
    lpInfo->instanceId = g_currentNode->datanode[index].datanodeId;
    lpInfo->node = g_currentNode->node;
    lpInfo->instanceType = INSTANCE_TYPE_DATANODE;
}

static void SetDnBaseMsg(BaseInstInfo *baseInfo, int32 index, int32 msgType)
{
    baseInfo->msgType = msgType;
    baseInfo->instId = g_currentNode->datanode[index].datanodeId;
    baseInfo->node = g_currentNode->node;
    baseInfo->instType = INSTANCE_TYPE_DATANODE;
}

static void InitDnFloatIpMsg(CmaDnFloatIpInfo *ipInfo, int32 index)
{
    errno_t rc = memset_s(ipInfo, sizeof(CmaDnFloatIpInfo), 0, sizeof(CmaDnFloatIpInfo));
    securec_check_errno(rc, (void)rc);
    SetDnBaseMsg(&(ipInfo->baseInfo), index, (int32)MSG_AGENT_CM_FLOAT_IP);
}

void InitDNStatus(DnStatus *dnStatus, int i)
{
    InitReportMsg(&dnStatus->reportMsg, i);
    InitDnLocalPeerMsg(&(dnStatus->lpInfo), i);
    InitDnFloatIpMsg(&(dnStatus->floatIpInfo), i);
}

static void ChangeLocalRoleInBackup(int dnIdx, int *localDnRole)
{
    if (*localDnRole == INSTANCE_ROLE_PRIMARY) {
        write_runlog(ERROR, "dn_%u is Primary in cluster standby.\n", g_currentNode->datanode[dnIdx].datanodeId);
        immediate_stop_one_instance(g_currentNode->datanode[dnIdx].datanodeLocalDataPath, INSTANCE_DN);
    }
    if (*localDnRole == INSTANCE_ROLE_MAIN_STANDBY) {
        *localDnRole = INSTANCE_ROLE_PRIMARY;
    } else if (*localDnRole == INSTANCE_ROLE_CASCADE_STANDBY) {
        *localDnRole = INSTANCE_ROLE_STANDBY;
    }
}

static void SendAlarmMsg(int alarmIndex, const char* logicClusterName, const char *instanceName, AlarmType type)
{
    AlarmAdditionalParam tempAdditionalParam;
    if ((g_abnormalAlarmList != NULL) && (!g_suppressAlarm)) {
        /* fill the alarm message */
        if (type == ALM_AT_Resume) {
            WriteAlarmAdditionalInfo(&tempAdditionalParam,
                instanceName, "", "", logicClusterName,
                &(g_abnormalAlarmList[alarmIndex]), ALM_AT_Resume);
            /* report the alarm */
            AlarmReporter(&(g_abnormalAlarmList[alarmIndex]), ALM_AT_Resume, &tempAdditionalParam);
        } else {
            WriteAlarmAdditionalInfo(&tempAdditionalParam,
                instanceName, "", "", logicClusterName,
                &(g_abnormalAlarmList[alarmIndex]), ALM_AT_Fault, instanceName);
            /* report the alarm */
            AlarmReporter(&(g_abnormalAlarmList[alarmIndex]), ALM_AT_Fault, &tempAdditionalParam);
        }
    }
    return;
}

static void CheckAlmLocalPrimary(
    DnStatus *dnStatus, int alarmIndex, const char *logicClusterName, const char *instanceName)
{
    bool peerRoleStandby = (dnStatus->reportMsg.sender_status[0].peer_role == INSTANCE_ROLE_STANDBY ||
        (agent_backup_open == CLUSTER_STREAMING_STANDBY &&
        dnStatus->reportMsg.sender_status[0].peer_role == INSTANCE_ROLE_CASCADE_STANDBY));

    if (peerRoleStandby) {
        /* the primary dn and standby dn instance are NORMAL */
        if ((dnStatus->reportMsg.local_status.db_state == INSTANCE_HA_STATE_NORMAL) &&
            ((dnStatus->reportMsg.sender_status[0].peer_state == INSTANCE_HA_STATE_NORMAL) ||
            (dnStatus->reportMsg.sender_status[0].peer_state == INSTANCE_HA_STATE_CATCH_UP))) {
            SendAlarmMsg(alarmIndex, logicClusterName, instanceName, ALM_AT_Resume);
        } else {
            SendAlarmMsg(alarmIndex, logicClusterName, instanceName, ALM_AT_Fault);
        }
    } else {
        if (dnStatus->reportMsg.sender_status[0].peer_role != INSTANCE_ROLE_PENDING) {
            SendAlarmMsg(alarmIndex, logicClusterName, instanceName, ALM_AT_Fault);
        }
    }
    return;
}

static void CheckAlmLocalStandby(
    DnStatus *dnStatus, int alarmIndex, const char *logicClusterName, const char *instanceName)
{
    bool peerRolePrimary = (dnStatus->reportMsg.receive_status.peer_role == INSTANCE_ROLE_PRIMARY ||
        (agent_backup_open == CLUSTER_STREAMING_STANDBY &&
        dnStatus->reportMsg.receive_status.peer_role == INSTANCE_ROLE_MAIN_STANDBY));

    if (peerRolePrimary) {
        /* the standby dn and primary dn instance are NORMAL */
        if ((dnStatus->reportMsg.receive_status.peer_state == INSTANCE_HA_STATE_NORMAL) &&
            ((dnStatus->reportMsg.local_status.db_state == INSTANCE_HA_STATE_NORMAL) ||
            (dnStatus->reportMsg.local_status.db_state == INSTANCE_HA_STATE_CATCH_UP))) {
            SendAlarmMsg(alarmIndex, logicClusterName, instanceName, ALM_AT_Resume);
        } else {
            SendAlarmMsg(alarmIndex, logicClusterName, instanceName, ALM_AT_Fault);
        }
    } else {
        if (dnStatus->reportMsg.receive_status.peer_role != INSTANCE_ROLE_PENDING) {
            SendAlarmMsg(alarmIndex, logicClusterName, instanceName, ALM_AT_Fault);
        }
    }
    return;
}

void* DNStatusCheckMain(void *arg)
{
    DnStatus dnStatus;
    int32 i = *(int32*)arg;
    errno_t rc;
    pthread_t threadId = pthread_self();
    uint32 dn_restart_count_check_time = 0;
    uint32 dn_restart_count_check_time_in_hour = 0;
    g_dnReportMsg[i].dnStatus.reportMsg.dn_restart_counts = 0;
    uint32 check_dn_sql5_timer = g_check_dn_sql5_interval;
    char* logicClusterName = NULL;
    char instanceName[CM_NODE_NAME] = {0};
    int alarmIndex = i;

    write_runlog(LOG, "dn(%d) status check thread start, threadid %lu.\n", i, threadId);

    int checkDummyTimes = CHECK_DUMMY_STATE_TIMES;

    int ret = snprintf_s(instanceName, sizeof(instanceName), sizeof(instanceName) - 1,
        "%s_%u", "dn", g_currentNode->datanode[i].datanodeId);
    securec_check_intval(ret, (void)ret);
    int32 running = PROCESS_UNKNOWN;

    for (;;) {
        set_thread_state(threadId);
        struct stat instance_stat_buf = {0};
        struct stat cluster_stat_buf = {0};

        if (g_shutdownRequest || g_exitFlag) {
            cm_sleep(5);
            continue;
        }

        InitDNStatus(&dnStatus, i);
        running = check_one_instance_status(GetDnProcessName(), g_currentNode->datanode[i].datanodeLocalDataPath, NULL);
        if (g_currentNode->datanode[i].datanodeRole != DUMMY_STANDBY_DN) {
            ret = DatanodeStatusCheck(&dnStatus, (uint32)i, running);
        }

        if (ret < 0 || g_currentNode->datanode[i].datanodeRole == DUMMY_STANDBY_DN) {
            if (g_currentNode->datanode[i].datanodeRole != DUMMY_STANDBY_DN) {
                write_runlog(ERROR, "DatanodeStatusCheck failed, ret=%d\n", ret);
            }

            if (g_currentNode->datanode[i].datanodeRole == DUMMY_STANDBY_DN &&
                dnStatus.reportMsg.processStatus != INSTANCE_PROCESS_RUNNING && running != PROCESS_RUNNING) {
                checkDummyTimes = CHECK_DUMMY_STATE_TIMES;
            }
            if (running == PROCESS_RUNNING) {
                if (g_currentNode->datanode[i].datanodeRole == DUMMY_STANDBY_DN && checkDummyTimes > 0) {
                    checkDummyTimes--;
                }
                if (checkDummyTimes <= 0 || g_currentNode->datanode[i].datanodeRole != DUMMY_STANDBY_DN) {
                    dnStatus.reportMsg.processStatus = INSTANCE_PROCESS_RUNNING;
                }
            } else {
                write_runlog(LOG, "set %u on offline.\n", dnStatus.reportMsg.instanceId);
                char instance_manual_start_path[MAX_PATH_LEN] = {0};

                dnStatus.reportMsg.processStatus = INSTANCE_PROCESS_DIED;
                dnStatus.reportMsg.local_status.local_role = INSTANCE_ROLE_UNKNOWN;
                rc = snprintf_s(instance_manual_start_path, MAX_PATH_LEN, MAX_PATH_LEN - 1,
                    "%s_%u",
                    g_cmInstanceManualStartPath,
                    g_currentNode->datanode[i].datanodeId);
                securec_check_intval(rc, (void)rc);
                if (stat(instance_manual_start_path, &instance_stat_buf) == 0 ||
                    stat(g_cmManualStartPath, &cluster_stat_buf) == 0 || !CheckStartDN()) {
                    dnStatus.reportMsg.local_status.db_state = INSTANCE_HA_STATE_MANUAL_STOPPED;
                } else if (g_dnDiskDamage[i]) {
                    dnStatus.reportMsg.local_status.db_state = INSTANCE_HA_STATE_DISK_DAMAGED;
                } else if (agentCheckPort(g_currentNode->datanode[i].datanodePort) > 0 ||
                           agentCheckPort(g_currentNode->datanode[i].datanodeLocalHAPort) > 0) {
                    dnStatus.reportMsg.local_status.db_state = INSTANCE_HA_STATE_PORT_USED;
                } else {
                    /*
                     * if instance is not running, cm_agent try to retsart it. if instance is still not running
                     * after MAX_INSTANCE_START times' trying, think it down.
                     */
                    if (g_dnStartCounts[i] > max_instance_start) {
                        char build_pid_path[MAXPGPATH];
                        int rcs = snprintf_s(build_pid_path, MAXPGPATH, MAXPGPATH - 1,
                            "%s/gs_build.pid",
                            g_currentNode->datanode[i].datanodeLocalDataPath);
                        securec_check_intval(rcs, (void)rcs);
                        pgpid_t pid = get_pgpid(build_pid_path, MAXPGPATH);
                        if ((pid > 0 && !is_process_alive(pid)) || pid < 0) {
                            dnStatus.reportMsg.local_status.db_state = INSTANCE_HA_STATE_BUILD_FAILED;
                        } else {
                            dnStatus.reportMsg.local_status.db_state = INSTANCE_HA_STATE_UNKONWN;
                        }
                    } else {
                        dnStatus.reportMsg.local_status.db_state = INSTANCE_HA_STATE_STARTING;
                    }
                }
                dnStatus.reportMsg.local_status.buildReason = INSTANCE_HA_DATANODE_BUILD_REASON_UNKNOWN;
            }
        }
        if (agent_backup_open == CLUSTER_STREAMING_STANDBY) {
            /* In streaming buackup cluster, role shoule change to primary and standby for arbitrate */
            ChangeLocalRoleInBackup(i, &dnStatus.reportMsg.local_status.local_role);
            if (dnStatus.reportMsg.local_status.local_role == INSTANCE_ROLE_PRIMARY &&
                dnStatus.reportMsg.local_status.db_state == INSTANCE_HA_STATE_NEED_REPAIR &&
                dnStatus.reportMsg.local_status.buildReason == INSTANCE_HA_DATANODE_BUILD_REASON_DISCONNECT) {
                ReportStreamingDRAlarm(ALM_AT_Fault, instanceName, alarmIndex, instanceName);
            } else {
                ReportStreamingDRAlarm(ALM_AT_Resume, instanceName, alarmIndex, NULL);
            }
        } else {
            ReportStreamingDRAlarm(ALM_AT_Resume, instanceName, alarmIndex, NULL);
        }
        if (g_clusterType != V3SingleInstCluster &&
            dnStatus.reportMsg.connectStatus == AGENT_TO_INSTANCE_CONNECTION_OK &&
            g_currentNode->datanode[i].datanodeRole != DUMMY_STANDBY_DN) {
            logicClusterName = get_logicClusterName_by_dnInstanceId(dnStatus.reportMsg.instanceId);
            if (strcmp(g_agentEnableDcf, "on") != 0) {
                if (dnStatus.reportMsg.local_status.local_role == INSTANCE_ROLE_PRIMARY) {
                    CheckAlmLocalPrimary(
                        &dnStatus, alarmIndex, (const char *)logicClusterName, (const char *)instanceName);
                } else if (dnStatus.reportMsg.local_status.local_role == INSTANCE_ROLE_STANDBY) {
                    CheckAlmLocalStandby(
                        &dnStatus, alarmIndex, (const char *)logicClusterName, (const char *)instanceName);
                }
            }
        }

        /* Number of times that dn is restarted within 10 minutes. */
        dnStatus.reportMsg.dn_restart_counts = g_primaryDnRestartCounts[i];
        if (dn_restart_count_check_time >= (DN_RESTART_COUNT_CHECK_TIME / agent_report_interval) ||
            dnStatus.reportMsg.local_status.local_role == INSTANCE_ROLE_STANDBY) {
            dn_restart_count_check_time = 0;
            dnStatus.reportMsg.dn_restart_counts = 0;
            g_primaryDnRestartCounts[i] = 0;
        }

        /* Number of times that dn is restarted within 1 hour. */
        dnStatus.reportMsg.dn_restart_counts_in_hour = g_primaryDnRestartCountsInHour[i];
        if (dn_restart_count_check_time_in_hour >= (DN_RESTART_COUNT_CHECK_TIME_HOUR / agent_report_interval) ||
            dnStatus.reportMsg.local_status.local_role == INSTANCE_ROLE_STANDBY) {
            dn_restart_count_check_time_in_hour = 0;
            dnStatus.reportMsg.dn_restart_counts_in_hour = 0;
            g_primaryDnRestartCountsInHour[i] = 0;
        }

        if (dnStatus.reportMsg.local_status.db_state == INSTANCE_HA_STATE_BUILD_FAILED) {
            report_build_fail_alarm(ALM_AT_Fault, instanceName, i);
        }
        if (dnStatus.reportMsg.local_status.db_state == INSTANCE_HA_STATE_NORMAL ||
            dnStatus.reportMsg.local_status.db_state == INSTANCE_HA_STATE_BUILDING) {
            report_build_fail_alarm(ALM_AT_Resume, instanceName, i);
        }

        write_runlog(DEBUG1, "DatanodeStatusCheck: local role is %d, db state is %d, build reason is %d\n",
            dnStatus.reportMsg.local_status.local_role, dnStatus.reportMsg.local_status.db_state,
            dnStatus.reportMsg.local_status.buildReason);
        DnCheckFloatIp(&dnStatus, (uint32)i, (bool8)(running == PROCESS_RUNNING));
        (void)pthread_rwlock_wrlock(&(g_dnReportMsg[i].lk_lock));
        rc = memcpy_s((void *)&(g_dnReportMsg[i].dnStatus.lpInfo), sizeof(AgentCmDnLocalPeer),
            (void *)&dnStatus.lpInfo, sizeof(AgentCmDnLocalPeer));
        securec_check_errno(rc, (void)rc);
        rc = memcpy_s((void *)&(g_dnReportMsg[i].dnStatus.reportMsg), sizeof(agent_to_cm_datanode_status_report),
            (void *)&dnStatus.reportMsg, sizeof(agent_to_cm_datanode_status_report));
        securec_check_errno(rc, (void)rc);
        rc = memcpy_s((void *)&(g_dnReportMsg[i].dnStatus.floatIpInfo), sizeof(CmaDnFloatIpInfo),
            (void *)&dnStatus.floatIpInfo, sizeof(CmaDnFloatIpInfo));
        securec_check_errno(rc, (void)rc);
        (void)pthread_rwlock_unlock(&(g_dnReportMsg[i].lk_lock));

        cm_sleep(agent_report_interval);
        check_dn_sql5_timer = (check_dn_sql5_timer > 0) ? (check_dn_sql5_timer - 1) : g_check_dn_sql5_interval;
        dn_restart_count_check_time++;
        dn_restart_count_check_time_in_hour++;
    }
}

/* kerberos status check */
uint32 check_kerberos_state(const char* username)
{
    /* commad: $GAUSSHOME/bin/kinit -k -t $KRB_HOME/kerberos/omm.keytab omm/opengauss.org@OPENGAUSS.ORG */
    if (check_one_instance_status("krb5kdc", "krb5kdc", NULL) == PROCESS_RUNNING) {
        char actualCmd[MAX_PATH_LEN] = {0};
        char kerberosCommandPath[MAX_PATH_LEN] = {0};
        pid_t status;
        int rcs = cmagent_getenv("KRB_HOME", kerberosCommandPath, sizeof(kerberosCommandPath));
        if (rcs != EOK) {
            write_runlog(LOG, "Get KRB_HOME failed, please check.\n");
            return KERBEROS_STATUS_UNKNOWN;
        } else {
            check_input_for_security(kerberosCommandPath);
            int32 ret = snprintf_s(actualCmd, MAX_PATH_LEN, MAX_PATH_LEN - 1,
                "%s/bin/kinit -k -t %s/kerberos/%s.keytab %s/opengauss.org@OPENGAUSS.ORG",
                kerberosCommandPath, kerberosCommandPath, username, username);
            securec_check_intval(ret, (void)ret);
            check_input_for_security(actualCmd);
            status = system(actualCmd);
            if (status == -1) {
                write_runlog(ERROR, "fail to execute command %s, and errno=%d.", actualCmd, errno);
                return KERBEROS_STATUS_UNKNOWN;
            } else {
                if (WIFEXITED(status)) {
                    if (WEXITSTATUS(status) == 0) {
                        return KERBEROS_STATUS_NORMAL;
                    } else {
                        return KERBEROS_STATUS_ABNORMAL;
                    }
                } else {
                    return KERBEROS_STATUS_UNKNOWN;
                }
            }
        }
    } else {
        return KERBEROS_STATUS_DOWN;
    }
}

/* get kerberos ip and port */
void get_kerberosConfigFile_info(const char* kerberosConfigFile, char* kerberosIp, uint32* kerberosPort, int* roleFlag)
{
    FILE* kerberos_config_fd;
    char buff[MAX_BUFF] = {0};
    char validstring[MAX_BUFF] = {0};
    errno_t rc;
    int rcs;
    char ip[CM_IP_LENGTH] = {0};
    int port = 0;
    if ((kerberos_config_fd = fopen(kerberosConfigFile, "re")) != NULL) {
        while (!feof(kerberos_config_fd)) {
            if (fgets(buff, MAX_BUFF, kerberos_config_fd) == NULL) {
                write_runlog(DEBUG1, "kerberos ip and port unkonw !\n");
                break;
            }
            if (strstr(buff, "kdc ") != NULL || strstr(buff, "kdc=") != NULL) {
                /* acquire kerberos ip and port */
                rcs = sscanf_s(buff, "%[^1-9]%[^:]%*c%d", validstring, MAX_BUFF, ip, CM_IP_LENGTH, &port);
                check_sscanf_s_result(rcs, 3);
                securec_check_intval(rcs, (void)fclose(kerberos_config_fd));
                if (strcmp(ip, g_currentNode->backIps[0]) == 0 && port != 0) {
                    rc = strncpy_s(kerberosIp, CM_IP_LENGTH, ip, strlen(ip));
                    securec_check_errno(rc, (void)fclose(kerberos_config_fd));
                    *kerberosPort = (uint32)port;
                    break;
                }
                *roleFlag = *roleFlag + 1;
            }
        }
        if (port == 0) {
            write_runlog(LOG, "Please reinstall kerberos!\n");
        }
        (void)fclose(kerberos_config_fd);
        return;
    } else {
        write_runlog(LOG, "kerberos config open error !\n");
        return;
    }
}
/* kerberos thread main funcation */
void* KerberosStatusCheckMain(void* arg)
{
    agent_to_cm_kerberos_status_report report_msg;
    errno_t rc;
    pthread_t threadId = pthread_self();
    set_thread_state(threadId);
    char kerberos_config_path[MAX_PATH_LEN] = {0};
    write_runlog(LOG, "kerberos status check thread start, threadid %lu.\n", threadId);
    char kerberosIp[CM_IP_LENGTH] = {0};
    uint32 kerberosPort = 0;
    int roleFlag = 0;

    rc = memset_s(
        &report_msg, sizeof(agent_to_cm_kerberos_status_report), 0, sizeof(agent_to_cm_kerberos_status_report));
    securec_check_errno(rc, (void)rc);
    report_msg.msg_type = MSG_AGENT_CM_KERBEROS_STATUS;
    int isKerberos = cmagent_getenv("MPPDB_KRB5_FILE_PATH", kerberos_config_path, sizeof(kerberos_config_path));
    if (isKerberos != EOK) {
        write_runlog(DEBUG1, "KerberosStatusCheckMain: MPPDB_KRB5_FILE_PATH get fail.\n");
        return NULL;
    }
    struct stat stat_buf = {0};
    check_input_for_security(kerberos_config_path);
    canonicalize_path(kerberos_config_path);
    if (stat(kerberos_config_path, &stat_buf) != 0) {
        write_runlog(DEBUG1, "KerberosStatusCheckMain: kerberos config file not exist.\n");
        return NULL;
    }
    /* get kerberos node and node_name */
    report_msg.node = g_currentNode->node;
    rc = strncpy_s(report_msg.nodeName, MAXLEN, g_currentNode->nodeName, strlen(g_currentNode->nodeName));
    securec_check_errno(rc, (void)rc);

    /* get kerberos ip and port and primary or standby */
    get_kerberosConfigFile_info(kerberos_config_path, kerberosIp, &kerberosPort, &roleFlag);
    rc = strncpy_s(report_msg.kerberos_ip, CM_IP_LENGTH, kerberosIp, strlen(kerberosIp));
    securec_check_errno(rc, (void)rc);

    report_msg.port = kerberosPort;
    if (roleFlag == 0) {
        rc = strncpy_s(report_msg.role, MAXLEN, "Primary", strlen("Primary"));
        securec_check_errno(rc, (void)rc);
    } else {
        rc = strncpy_s(report_msg.role, MAXLEN, "Standby", strlen("Standby"));
        securec_check_errno(rc, (void)rc);
    }

    for (;;) {
        if (g_shutdownRequest) {
            cm_sleep(5);
            continue;
        }

        /* get kerberos status */
        report_msg.status = check_kerberos_state(pw->pw_name);

        /* restart kerberos */
        int ret = 0;
        if (report_msg.status == KERBEROS_STATUS_ABNORMAL || report_msg.status == KERBEROS_STATUS_DOWN) {
            kill_instance_force("krb5kdc", INSTANCE_KERBEROS);
            cm_sleep(1);
            ret = system("krb5kdc");
            if (ret != 0) {
                write_runlog(ERROR, "run krb5kdc command failed and restart fail, errno=%d.!\n", errno);
            }
        }

        /* save report msg */
        (void)pthread_rwlock_wrlock(&(g_kerberosReportMsg.lk_lock));
        rc = memcpy_s((void*)&(g_kerberosReportMsg.report_msg),
            sizeof(agent_to_cm_kerberos_status_report),
            (void*)&report_msg,
            sizeof(agent_to_cm_kerberos_status_report));
        securec_check_errno(rc, (void)rc);
        (void)pthread_rwlock_unlock(&(g_kerberosReportMsg.lk_lock));
        cm_sleep(g_agentKerberosStatusCheckInterval);
    }
}


void CheckSharedDiskUsage(uint32 &vgdataPathUsage, uint32 &vglogPathUsage)
{
    FILE *fp;
    char result[1024];
    double percent1 = 0.0, percent2 = 0.0;

    fp = popen("dsscmd lsvg | awk 'NR==2 || NR==3 {print $NF}'", "r");
    if (fp == NULL) {
        write_runlog(ERROR, "Failed to exec command(dsscmd lsvg).\n");
    }

    if (fgets(result, sizeof(result)-1, fp) != NULL) {
        sscanf(result, "%lf", &percent1);
    }
    if (fgets(result, sizeof(result)-1, fp) != NULL) {
        sscanf(result, "%lf", &percent2);
    }
    
    // If the value is greater than 0 and less than 1, consider it as 1.
    if (percent1 > 0 && percent1 < 1) {
        percent1 = 1;
    }
    if (percent2 > 0 && percent2 < 1) {
        percent2 = 1;
    }
    vgdataPathUsage = (uint)percent1;
    vglogPathUsage = (uint)percent2;

    pclose(fp);
}

/**
 * @brief Get DN node log path disk usage and datapath disk usage, send them to the CMS
 *
 */
void CheckDiskForDNDataPath()
{
    for (uint32 ii = 0; ii < g_currentNode->datanodeCount; ii++) {
        AgentToCmDiskUsageStatusReport status;
        status.msgType = (int)MSG_AGENT_CM_DISKUSAGE_STATUS;
        status.instanceId = g_currentNode->datanode[ii].datanodeId;
        status.logPathUsage = CheckDiskForLogPath();
        uint32 dataPathUsage = GetDiskUsageForPath(g_currentNode->datanode[ii].datanodeLocalDataPath);
        uint32 linkPathUsage = GetDiskUsageForLinkPath(g_currentNode->datanode[ii].datanodeLocalDataPath);
        status.dataPathUsage = (dataPathUsage > linkPathUsage) ? dataPathUsage : linkPathUsage;
        status.readOnly = g_dnReadOnly[ii];
        status.instanceType = INSTANCE_TYPE_DATANODE;
        if (IsCusResExistLocal()) {
            CheckSharedDiskUsage(status.vgdataPathUsage, status.vglogPathUsage);
            write_runlog(DEBUG1, "vgdataPathUsage:%u, vglogPathUsage:%u.\n",
                status.vgdataPathUsage, status.vglogPathUsage);
        } else {
            status.vgdataPathUsage = 0;
            status.vglogPathUsage = 0;
        }

        write_runlog(DEBUG1, "[%s] msgType:%d, instanceId:%u, logPathUsage:%u, linkPathUsage: %u, dataPathUsage:%u.\n",
            __FUNCTION__, status.msgType, status.instanceId, status.logPathUsage, linkPathUsage, status.dataPathUsage);

        (void)pthread_rwlock_wrlock(&(g_dnReportMsg[ii].lk_lock));
        errno_t rc = memcpy_s((void *)&(g_dnReportMsg[ii].dnStatus.diskUsageMsg),
            sizeof(AgentToCmDiskUsageStatusReport), (void *)&status, sizeof(AgentToCmDiskUsageStatusReport));
        securec_check_errno(rc, (void)rc);
        (void)pthread_rwlock_unlock(&(g_dnReportMsg[ii].lk_lock));
    }
}

/* 
 * This function is used to ensure whether the status modify;
 */
static int IsClusterInRedoState() 
{
    FILE *fp;
    char buffer[1024] = {0};
    const char* expectedString = "in on-demand redo";
    char *foundString = NULL;

    fp = popen("pg_controldata +data | grep 'Cluster status:' | "
               "awk '{for (i=NF-2;i<=NF;i++) printf \"%s \", $i; printf \"\\n\"}'", "r");
    if (fp == NULL) {
        write_runlog(LOG, "Failed to exec command(pg_controldata +data).\n");
        return UNEXPECT_ONDEMAND_RECOVERY;
    }

    if (fgets(buffer, sizeof(buffer), fp) == NULL) {
        pclose(fp);
        return UNEXPECT_ONDEMAND_RECOVERY;
    }
    pclose(fp);

    foundString = buffer;

    char *end = foundString + strlen(foundString) - 1;
    while (end >= foundString && (*end == '\n' || *end == '\r' || *end == '\t' || *end == ' ')) {
        *end = '\0';
        end--; 
    }
    /* If we found nothing, it must be something wrong with gaussdb or DSS. */
    if (*foundString == '\0') {
        return UNEXPECT_ONDEMAND_RECOVERY;
    }

    if (!strcmp(foundString, expectedString)) {
        return IN_ONDEMAND_RECOVERY;
    } else {
        return NOT_IN_ONDEMAND_RECOVERY;
    }
}


/* Report the in on-demand-status by msg, notify the CM server no need to wait switchover complated. */
static void AgentSendOnDemandStatus(int onDemandStatus)
{
    agent_to_cm_ondemand_status_report reportMsg = {0};
    reportMsg.msg_type = (int)MSG_AGENT_ONDEMAND_STATUES_REPORT;
    reportMsg.onDemandStatus = onDemandStatus;
    reportMsg.reportTime = time(NULL);
    reportMsg.nodeId = g_nodeHeader.node;
    PushMsgToCmsSendQue((char *)&reportMsg, (uint32)sizeof(agent_to_cm_ondemand_status_report), "ondemand status");
    write_runlog(DEBUG1, "Node(%u) ondemand status send to cms, status is: %d\n", reportMsg.nodeId, onDemandStatus);
}

/*
 * This function is main entry for pgdata charge.
 * It can be extended in the future.
 */
void PGDataControlCheck()
{
    int clusterStatusUnderOnDemand = IsClusterInRedoState();
    AgentSendOnDemandStatus(clusterStatusUnderOnDemand);
}

static void PingPeerIP(int* count, const char localIP[CM_IP_LENGTH], const char peerIP[CM_IP_LENGTH])
{
    char command[MAXPGPATH] = {0};
    char buf[MAXPGPATH];
    int rc;
    uint32 tryTimes = 3;

    const char *pingStr = GetPingStr(GetIpVersion(peerIP));
    rc = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1,
        "%s -c 1 -w 1 -I %s %s > /dev/null;if [ $? == 0 ];then echo success;else echo fail;fi;",
        pingStr, localIP, peerIP);
    securec_check_intval(rc, (void)rc);
    write_runlog(DEBUG1, "ping command is: %s.\n", command);

    while (tryTimes > 0) {
        FILE* fp = popen(command, "r");
        if (fp == NULL) {
            write_runlog(ERROR, "popen failed\n.");
            return;
        }
        if (fgets(buf, sizeof(buf), fp) != NULL) {
            if (strstr(buf, "success") != NULL) {
                (*count)++;
                (void)pclose(fp);
                return;
            }
        }
        cm_sleep(1);
        tryTimes--;
        (void)pclose(fp);
    }
    write_runlog(ERROR, "ping peer ip failed: %s, command is: %s\n.", buf, command);
    return;
}

void* DNConnectionStatusCheckMain(void *arg)
{
    int i = *(int*)arg;
    pthread_t threadId = pthread_self();

    if (g_currentNode->datanode[i].datanodeListenCount == 1 &&
        g_currentNode->datanode[i].datanodeLocalHAListenCount == 1 &&
        strcmp(g_currentNode->datanode[i].datanodeListenIP[0], g_currentNode->datanode[i].datanodeLocalHAIP[0]) == 0) {
        write_runlog(LOG, "datanodeListenIP is same with datanodeLocalHAIP no need connection status check.\n");
        return NULL;
    }
    if (g_single_node_cluster || IsBoolCmParamTrue(g_agentEnableDcf)) {
        return NULL;
    }
    write_runlog(LOG, "dn(%d) connection status check thread start, threadid %lu.\n", i, threadId);
    for (;;) {
        set_thread_state(threadId);
        if (g_shutdownRequest) {
            cm_sleep(5);
            continue;
        }

        if (!g_mostAvailableSync[i]) {
            int count = 0;
            if (g_multi_az_cluster) {
                for (uint32 j = 0; j < g_dn_replication_num - 1; ++j) {
                    PingPeerIP(&count, g_currentNode->datanode[i].datanodeLocalHAIP[0],
                        g_currentNode->datanode[i].peerDatanodes[j].datanodePeerHAIP[0]);
                }
            } else {
                PingPeerIP(&count, g_currentNode->datanode[i].datanodeLocalHAIP[0],
                    g_currentNode->datanode[i].datanodePeerHAIP[0]);
                PingPeerIP(&count, g_currentNode->datanode[i].datanodeLocalHAIP[0],
                    g_currentNode->datanode[i].datanodePeer2HAIP[0]);
            }
            if (count == 0) {
                write_runlog(LOG, "dn(%u) is disconnected from other dn.\n", g_currentNode->datanode[i].datanodeId);
                g_dnPingFault[i] = true;
                if (g_dnReportMsg[i].dnStatus.reportMsg.local_status.local_role == INSTANCE_ROLE_PRIMARY  && 
                    !g_isPauseArbitration) {
                    immediate_stop_one_instance(g_currentNode->datanode[i].datanodeLocalDataPath, INSTANCE_DN);
                }
            } else {
                g_dnPingFault[i] = false;
            }
        } else {
            g_dnPingFault[i] = false;
        }

        cm_sleep(agent_report_interval);
    }
}

static bool IsDeviceNameSame(const char *device, int deviceCount, char * const *deviceName)
{
    for (int i = 0; i < deviceCount; ++i) {
        if (strcmp(device, deviceName[i]) == 0) {
            return true;
        }
    }

    return false;
}

static char **GetAllDisk(int &deviceCount)
{
    char **result;
    char tmpName[MAX_DEVICE_DIR] = {0};
    errno_t rc;
    size_t resultLen = (g_currentNode->datanodeCount + 1) * sizeof(char*);

    result = (char**)malloc(resultLen);
    if (result == NULL) {
        write_runlog(ERROR, "[CmReadfile] malloc failed, out of memory.\n");
        return NULL;
    }
    rc = memset_s(result, resultLen, 0, resultLen);
    securec_check_errno(rc, (void)rc);

    deviceCount = 0;
    if (g_currentNode->coordinate == 1) {
        CmGetDisk(g_currentNode->DataPath, tmpName, MAX_DEVICE_DIR);
        result[deviceCount] = strdup(tmpName);
        if (result[deviceCount] == NULL) {
            write_runlog(ERROR, "out of memory, deviceCount = %d\n", deviceCount);
            return NULL;
        }
        ++deviceCount;
        rc = memset_s(tmpName, MAX_DEVICE_DIR, 0, MAX_DEVICE_DIR);
        securec_check_errno(rc, (void)rc);
    }
    for (uint32 i = 0; i < g_currentNode->datanodeCount; ++i) {
        CmGetDisk(g_currentNode->datanode[i].datanodeLocalDataPath, tmpName, MAX_DEVICE_DIR);
        if (!IsDeviceNameSame(tmpName, deviceCount, result)) {
            result[deviceCount] = strdup(tmpName);
            if (result[deviceCount] == NULL) {
                write_runlog(ERROR, "out of memory, deviceCount = %d\n", deviceCount);
                return NULL;
            }
            ++deviceCount;
        }
        rc = memset_s(tmpName, MAX_DEVICE_DIR, 0, MAX_DEVICE_DIR);
        securec_check_errno(rc, (void)rc);
    }

    return result;
}

static bool IsSymbolRight(const char *str)
{
    int count = 0;

    for (int i = 0; str[i] != '\0'; ++i) {
        if (str[i] == ',') {
            ++count;
        }
    }

    if (count == THRESHOLD_FORMAT) {
        return true;
    }

    return false;
}

static bool IsValueRight(const char *value, int &param)
{
    if (value == NULL) {
        write_runlog(ERROR, "threshold value = NULL.\n");
        return false;
    }
    if (CM_is_str_all_digit(value) != 0) {
        write_runlog(ERROR, "threshold value = %s, is wrong.\n", value);
        return false;
    }
    param = (int)strtol(value, NULL, DECIMAL_NOTATION);
    if (param < THRESHOLD_MIN_VALUE || param > THRESHOLD_MAX_VALUE) {
        write_runlog(ERROR, "threshold value = %s, out of range.\n", value);
        return false;
    }

    return true;
}

static status_t GetThreshold(EnvThreshold &threshold)
{
    char *pLeft = NULL;
    char *pValue;
    char envStr[CM_PATH_LENGTH] = {0};

    if (strcmp(g_environmentThreshold, "") == 0) {
        write_runlog(DEBUG1, "environment_threshold is NULL.\n");
        return CM_ERROR;
    }
    errno_t rc = strcpy_s(envStr, CM_PATH_LENGTH, g_environmentThreshold);
    securec_check_errno(rc, (void)rc);
    char *tmp = trim(envStr);
    write_runlog(DEBUG1, "environment threshold, tmp=%s.\n", tmp);

    if (tmp[strlen(tmp) - 1] == ')') {
        tmp[strlen(tmp) - 1] = '\0';
    } else {
        write_runlog(ERROR, "line:%d, environment threshold format is wrong.\n", __LINE__);
        return CM_ERROR;
    }
    if (tmp[0] == '(') {
        tmp++;
    } else {
        write_runlog(ERROR, "line:%d, environment threshold format is wrong.\n", __LINE__);
        return CM_ERROR;
    }

    if (!IsSymbolRight(tmp)) {
        write_runlog(ERROR, "line:%d, environment threshold format is wrong.\n", __LINE__);
        return CM_ERROR;
    }

    pValue = strtok_r(tmp, ",", &pLeft);
    if (!IsValueRight(pValue, threshold.mem)) {
        return CM_ERROR;
    }
    pValue = strtok_r(NULL, ",", &pLeft);
    if (!IsValueRight(pValue, threshold.cpu)) {
        return CM_ERROR;
    }
    pValue = strtok_r(NULL, ",", &pLeft);
    if (!IsValueRight(pValue, threshold.disk)) {
        return CM_ERROR;
    }
    pValue = strtok_r(NULL, ",", &pLeft);
    if (!IsValueRight(pValue, threshold.instMem)) {
        return CM_ERROR;
    }
    if (!IsValueRight(pLeft, threshold.instPool)) {
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static int CheckMemoryHave()
{
    FILE *fp;
    uint64 memFree = 0;
    uint64 memTotal = 0;
    int ret;
    bool haveGetFree = false;
    bool haveGetTotal = false;
    char line[CM_PATH_LENGTH] = {0};

    if ((fp = fopen(FILE_MEMINFO, "re")) == NULL) {
        write_runlog(ERROR, "failed to open file %s.\n", FILE_MEMINFO);
        return -1;
    }

    while (fgets(line, CM_PATH_LENGTH, fp) != NULL) {
        if (strncmp(line, "MemTotal", strlen("MemTotal")) == 0) {
            ret = sscanf_s(line, "MemTotal: %lu kB\n", &memTotal);
            check_sscanf_s_result(ret, 1);
            securec_check_intval(ret, (void)ret);
            write_runlog(DEBUG1, "CheckMemoryHave memTotal = %lu.\n", memTotal);
            haveGetTotal = true;
        }
        if (strncmp(line, "MemFree", strlen("MemFree")) == 0) {
            ret = sscanf_s(line, "MemFree: %lu kB", &memFree);
            check_sscanf_s_result(ret, 1);
            securec_check_intval(ret, (void)ret);
            write_runlog(DEBUG1, "CheckMemoryHave memTotal = %lu.\n", memFree);
            haveGetFree = true;
        }
        if (haveGetTotal && haveGetFree) {
            break;
        }
    }
    (void)fclose(fp);

    if (memTotal == 0) {
        write_runlog(ERROR, "get memTotal(%lu) info is 0.\n", memTotal);
        return -1;
    }

    return (int)(PERCENT - (memFree * PERCENT / memTotal));
}

static int CheckCpuHave()
{
    return ReadCpuStatus(1, NULL, true);
}

static void CheckDiskIoHave(const char *deviceName, int disk)
{
    int cpuNum;
    int diskIoHave;
    static IoStat ioStatus = {0};

    if (deviceName == NULL) {
        write_runlog(LOG, "device name is NULL, can't check its disk IO.\n");
        return;
    }
    cpuNum = GetCpuCount();
    diskIoHave = (int)ReadDiskIOStat(deviceName, cpuNum, &ioStatus, false);
    if (diskIoHave > disk) {
        write_runlog(LOG, "{\"CMA disk IO is more than threshold\":"
            "{\"disk IO\":{\"name\":\"%s\",\"actual\":\"%d%%\", \"threshold\":\"%d%%\"}}}\n",
            deviceName, diskIoHave, disk);
    }

    return;
}

static void CheckSysStatus(const EnvThreshold &threshold)
{
    int memHave = 0;
    int cpuHave = 0;
    bool isOverflow;

    if (threshold.mem == 0 && threshold.cpu == 0) {
        write_runlog(DEBUG5, "threshold mem and cpu is 0, not need do check.\n");
        return;
    }

    if (threshold.mem != 0) {
        if ((memHave = CheckMemoryHave()) < 0) {
            write_runlog(ERROR, "get memory info fail.\n");
            return;
        }
    }
    if (threshold.cpu != 0) {
        if ((cpuHave = CheckCpuHave()) < 0) {
            write_runlog(ERROR, "get cpu info fail.\n");
            return;
        }
    }

    isOverflow = (memHave > threshold.mem) || (cpuHave > threshold.cpu);
    if (isOverflow) {
        write_runlog(LOG, "{\"CMA physical resource is more than threshold\":"
            "{\"memory\":{\"actual\":\"%d%%\",\"threshold\":\"%d%%\"},"
            "\"CPU\":{\"actual\":\"%d%%\",\"threshold\":\"%d%%\"}}}\n",
            memHave, threshold.mem, cpuHave, threshold.cpu);
    }

    return;
}

static void CheckDiskStatus(const EnvThreshold &threshold, const char * const *deviceName, int deviceCount)
{
    if (threshold.disk == 0) {
        write_runlog(DEBUG5, "threshold disk is 0, not need do check.\n");
        return;
    }

    for (int i = 0; i < deviceCount; ++i) {
        CheckDiskIoHave(deviceName[i], threshold.disk);
    }

    return;
}

void *CheckNodeStatusThreadMain(void * const arg)
{
    int deviceCount = 0;
    long expiredTime;
    struct timeval checkEnd;
    struct timeval checkBegin;
    EnvThreshold threshold = {0};
    char **deviceName = GetAllDisk(deviceCount);
    if (deviceName == NULL) {
        write_runlog(ERROR, "CheckNodeStatusThreadMain, out of memory.\n");
        return NULL;
    }

    write_runlog(LOG, "CMA deviceCount = %d.\n", deviceCount);
    for (;;) {
        if (g_shutdownRequest) {
            cm_sleep(SHUTDOWN_SLEEP_TIME);
            continue;
        }

        (void)gettimeofday(&checkBegin, NULL);
        if (GetThreshold(threshold) != CM_SUCCESS) {
            threshold = {0, 0, 0, 0, 0};
        }
        CheckSysStatus(threshold);
        CheckDiskStatus(threshold, deviceName, deviceCount);
#ifdef ENABLE_MULTIPLE_NODES
        CheckAllInstStatus(&threshold);
#endif
        (void)gettimeofday(&checkEnd, NULL);

        expiredTime = (checkEnd.tv_sec - checkBegin.tv_sec);
        write_runlog(DEBUG5, "CheckNodeStatusThreadMain take %ld seconds.\n", expiredTime);

        if (expiredTime < CHECK_INTERVAL) {
            cm_sleep((unsigned int)(CHECK_INTERVAL - expiredTime));
        }
    }

    return NULL;
}

int CreateCheckNodeStatusThread()
{
    int err;
    pthread_t thrId;

    if ((err = pthread_create(&thrId, NULL, CheckNodeStatusThreadMain, NULL)) != 0) {
        write_runlog(ERROR, "Failed to create new thread: error %d.\n", err);
        return err;
    }
    return 0;
}

static DDB_ROLE GetCurrentEtcdRole()
{
    const uint32 serverLen = 2;
    ServerSocket server[serverLen] = {{0}};
    SetServerSocketWithEtcdInfo(&server[0], g_currentNode);
    server[1].host = NULL;
    DdbInitConfig config = {DB_ETCD};
    GetDdbCfgApi(&config.drvApiInfo, server, serverLen);
    DdbNodeState nodeState;
    DdbConn dbCon = {0};
    status_t st = InitDdbConn(&dbCon, &config);
    if (st != CM_SUCCESS) {
        write_runlog(ERROR, "etcd open failed when query etcd status. %s\n", DdbGetLastError(&dbCon));
        return DDB_ROLE_UNKNOWN;
    }
    st = DdbInstanceState(&dbCon, g_currentNode->etcdName, &nodeState);
    if (DdbFreeConn(&dbCon) != CM_SUCCESS) {
        write_runlog(WARNING, "etcd_close failed,%s\n", DdbGetLastError(&dbCon));
    }
    if (st != CM_SUCCESS) {
        write_runlog(ERROR, "[GetCurrentEtcdRole] failed ,error is %s\n", DdbGetLastError(&dbCon));
        return DDB_ROLE_UNKNOWN;
    }
    return nodeState.role;
}

static void StopCurrentETCD(void)
{
    char command[MAXPGPATH];
    int ret = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1, "echo -e %s > %s; chmod 600 %s",
        CM_AGENT_BIN_NAME, g_cmEtcdManualStartPath, g_cmEtcdManualStartPath);
    securec_check_intval(ret, (void)ret);
    ret = system(command);
    if (ret != 0) {
        write_runlog(ERROR, "Failed to stop the etcd node with executing the command: command=\"%s\","
            " nodeId=%u, systemReturn=%d, shellReturn=%d, errno=%d.\n",
            command, g_currentNode->node, ret, SHELL_RETURN_CODE(ret), errno);
    }
}

static void StartCurrentETCD(void)
{
    char command[MAXPGPATH];
    int ret = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1, "rm -f %s", g_cmEtcdManualStartPath);
    securec_check_intval(ret, (void)ret);
    ret = system(command);
    if (ret != 0) {
        write_runlog(ERROR, "Failed to start the etcd node with executing the command: command=\"%s\","
            " nodeId=%u, systemReturn=%d, shellReturn=%d, errno=%d.\n",
            command, g_currentNode->node, ret, SHELL_RETURN_CODE(ret), errno);
    }
}

static bool IsEtcdStopByCmAgent(const char* path)
{
    char stopType[MAX_PATH_LEN] = {0};
    char realPath[PATH_MAX] = {0};
    if (realpath(path, realPath) == NULL) {
        write_runlog(DEBUG1, "Canonical etcd_manual_start file failed errno=%d.\n", errno);
        return false;
    }
    FILE* fd = fopen(realPath, "re");
    if (fd == NULL) {
        write_runlog(ERROR, "Open etcd_manual_start failed \n");
        return false;
    }
    if (fscanf_s(fd, "%s", stopType, sizeof(stopType)) != 1) {
        write_runlog(ERROR, "invalid data in etcd_manual_start file \"%s\"\n", path);
        (void)fclose(fd);
        return false;
    }
    (void)fclose(fd);
    if (strcmp(stopType, CM_AGENT_BIN_NAME) == 0) {
        return true;
    }
    return false;
}

void* ETCDConnectionStatusCheckMain(void* arg)
{
    pthread_t threadId = pthread_self();
    write_runlog(LOG, "etcd connection status check thread start, threadid %lu.\n", threadId);
    int count;
    DDB_ROLE etcdRole = DDB_ROLE_UNKNOWN;
    for (;;) {
        set_thread_state(threadId);
        if (g_shutdownRequest || g_exitFlag) {
            cm_sleep(5);
            continue;
        }
        count = 0;
        for (uint32 i = 0; i < g_node_num; ++i) {
            if (!g_node[i].etcd || g_currentNode->etcdId == g_node[i].etcdId) {
                continue;
            }
            PingPeerIP(&count, g_currentNode->etcdClientListenIPs[0], g_node[i].etcdClientListenIPs[0]);
        }
        DDB_ROLE tmpRole = GetCurrentEtcdRole();
        etcdRole = tmpRole == DDB_ROLE_UNKNOWN ? etcdRole : tmpRole;
        if (count == 0) {
            write_runlog(WARNING, "current etcd is disconnected from other, etcd num=%u.\n", g_etcd_num);
            if (access(g_cmEtcdManualStartPath, F_OK) != 0 && etcdRole == DDB_ROLE_LEADER) {
                write_runlog(WARNING, "current etcd is leader, cmagent need stop it for etcd availability.\n");
                StopCurrentETCD();
            }
        } else {
            if (IsEtcdStopByCmAgent(g_cmEtcdManualStartPath)) {
                write_runlog(LOG, "current etcd is stop by cmagent and connection is normal, need start it.\n");
                StartCurrentETCD();
            }
        }
        cm_sleep(agent_report_interval);
    }

    return NULL;
}
