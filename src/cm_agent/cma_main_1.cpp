

static void DoHelp(void)
{
    (void)printf(_("%s is a utility to monitor an instance.\n\n"), g_progname);

    (void)printf(_("Usage:\n"));
    (void)printf(_("  %s\n"), g_progname);
    (void)printf(_("  %s 0\n"), g_progname);
    (void)printf(_("  %s 1\n"), g_progname);
    (void)printf(_("  %s 2\n"), g_progname);
    (void)printf(_("  %s 3\n"), g_progname);
    (void)printf(_("  %s normal\n"), g_progname);
    (void)printf(_("  %s abnormal\n"), g_progname);

    (void)printf(_("\nCommon options:\n"));
    (void)printf(_("  -?, -h, --help         show this help, then exit\n"));
    (void)printf(_("  -V, --version          output version information, then exit\n"));

    (void)printf(_("\nlocation of the log information options:\n"));
    (void)printf(_("  0                      LOG_DESTION_FILE\n"));
    (void)printf(_("  1                      LOG_DESTION_SYSLOG\n"));
    (void)printf(_("  2                      LOG_DESTION_FILE\n"));
    (void)printf(_("  3                      LOG_DESTION_DEV_NULL\n"));

    (void)printf(_("\nstarted mode options:\n"));
    (void)printf(_("  normal                 cm_agent is started normally\n"));
    (void)printf(_("  abnormal               cm_agent is started by killed\n"));
}

/*
 * Replace character to another.
 */
int replaceStr(char *sSrc, const char *sMatchStr, const char *sReplaceStr)
{
    char caNewString[MAX_PATH_LEN];
    errno_t rc;
    if (sMatchStr == NULL) {
        return -1;
    }
    char *FindPos = strstr(sSrc, sMatchStr);
    if (FindPos == NULL) {
        return 0; /* if sSrc does not contain sMatchStr, we think it relpaces successfully */
    }

    while (FindPos != NULL) {
        rc = memset_s(caNewString, MAX_PATH_LEN, 0, MAX_PATH_LEN);
        securec_check_errno(rc, (void)rc);
        long StringLen = FindPos - sSrc;
        rc = strncpy_s(caNewString, MAX_PATH_LEN, sSrc, (size_t)StringLen);
        securec_check_errno(rc, (void)rc);
        rc = strcat_s(caNewString, MAX_PATH_LEN, sReplaceStr);
        securec_check_errno(rc, (void)rc);
        rc = strcat_s(caNewString, MAX_PATH_LEN, FindPos + strlen(sMatchStr));
        securec_check_errno(rc, (void)rc);
        rc = strcpy_s(sSrc, MAX_PATH_LEN, caNewString);
        securec_check_errno(rc, (void)rc);

        FindPos = strstr(sSrc, sMatchStr);
    }

    return 0;
}

/*
 * Cut time from trace name.
 * This time will be used to sort traces.
 */
void cutTimeFromFileLog(const char *fileName, char *pattern, uint32 patternLen, char *strTime)
{
    errno_t rc;
    char subStr2[MAX_PATH_LEN] = {'\0'};
    char subStr5[MAX_PATH_LEN] = {'\0'};
    char *saveStr = NULL;
    char *saveStr2 = NULL;
    char subStr3[MAX_PATH_LEN] = {'\0'};
    char tempTimeStamp[MAX_TIME_LEN] = {'\0'};
    /* Copy file name avoid modifying the value */
    rc = memcpy_s(subStr2, MAX_PATH_LEN, fileName, strlen(fileName) + 1);
    securec_check_errno(rc, (void)rc);
    rc = memcpy_s(subStr5, MAX_PATH_LEN, fileName, strlen(fileName) + 1);
    securec_check_errno(rc, (void)rc);
    char *subStr4 = strstr(subStr5, "-");
    char *subStr = strtok_r(subStr2, "-", &saveStr);
    if (subStr == NULL) {
        write_runlog(ERROR, "file path name get failed.\n");
        return;
    }
    rc = snprintf_s(subStr3, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s%s", subStr, "-");
    securec_check_intval(rc, (void)rc);
    rc = memcpy_s(pattern, patternLen, subStr3, MAX_PATH_LEN);
    securec_check_errno(rc, (void)rc);

    // assin a biggest data to current log in order to avoid compressing current log file when time changed
    // also for etcd and system_call current log filename doesn't contain timestamp. So, we assign a date to it
    if (strstr(fileName, "-current.log") != NULL) {
        rc = snprintf_s(tempTimeStamp, MAX_TIME_LEN, MAX_TIME_LEN - 1, "%s", MAX_LOGFILE_TIMESTAMP);
        securec_check_intval(rc, (void)rc);
        rc = memcpy_s(strTime, MAX_TIME_LEN, tempTimeStamp, MAX_TIME_LEN);
        securec_check_errno(rc, (void)rc);
        return;
    }

    /* Replace invalid character of strTime */
    if (subStr4 != NULL) {
        subStr = strtok_r(subStr4, ".", &saveStr2);
        if (subStr != NULL) {
            (void)replaceStr(subStr, "-current", "");
            if (subStr != NULL) {
                (void)replaceStr(subStr, "-", "");
                if (subStr != NULL) {
                    (void)replaceStr(subStr, "_", "");
                    if (is_digit_string(subStr)) {
                        rc = memcpy_s(strTime, MAX_TIME_LEN, subStr, strlen(subStr) + 1);
                        securec_check_errno(rc, (void)rc);
                    }
                }
            }
        }
    }
}

/*
 * Read all traces by log pattern,including zip file and non zip file.
 * Trace information are file time,file size,file path.These traces are
 * saved in the global variable.
 */
int readFileList(const char *basePath, LogFile *logFile, uint32 *count, int64 *totalSize, uint32 maxCount)
{
    errno_t rc;
    DIR *dir;
    struct dirent *ptr = NULL;
    char base[MAX_PATH_LEN] = {'\0'};
    char path[MAX_PATH_LEN] = {'\0'};
    char strTime[MAX_TIME_LEN] = {'\0'};
    char pattern[MAX_PATH_LEN] = {'\0'};

    if ((dir = opendir(basePath)) == NULL) {
        write_runlog(ERROR, "could not open file %s", basePath);
        return -1;
    }

    while (*count < maxCount && (ptr = readdir(dir)) != NULL) {
        struct stat stat_buf;
        /* Filter current directory and parent directory */
        if (strcmp(ptr->d_name, ".") == 0 || strcmp(ptr->d_name, "..") == 0) {
            continue;
        }

        rc = snprintf_s(path, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/%s", basePath, ptr->d_name);
        securec_check_intval(rc, (void)rc);
        if (unlikely(stat(path, &stat_buf) < 0)) {
            write_runlog(LOG, "could not stat file %s\n", path);
            continue;
        }
        /* Process file */
        if (S_ISREG(stat_buf.st_mode) && isLogFile(ptr->d_name)) {
            cutTimeFromFileLog(ptr->d_name, pattern, sizeof(pattern), strTime);
            /* Filter traces by pattern,trace name should contains date */
            if (strTime[0] != 0) {
                if (logFile != NULL) {
                    *totalSize += stat_buf.st_size;
                    rc = memcpy_s(logFile[*count].fileName, MAX_PATH_LEN, path, MAX_PATH_LEN);
                    securec_check_errno(rc, (void)rc);
                    rc = memcpy_s(logFile[*count].basePath, MAX_PATH_LEN, basePath, MAX_PATH_LEN);
                    securec_check_errno(rc, (void)rc);
                    rc = memcpy_s(logFile[*count].timestamp, MAX_TIME_LEN, strTime, MAX_TIME_LEN);
                    securec_check_errno(rc, (void)rc);
                    rc = memcpy_s(logFile[*count].pattern, MAX_PATH_LEN, pattern, MAX_PATH_LEN);
                    securec_check_errno(rc, (void)rc);
                    rc = memcpy_s(&logFile[*count].fileSize, sizeof(int64), &stat_buf.st_size, sizeof(int64));
                    securec_check_errno(rc, (void)rc);
                }
                *count += 1;
            }
        } else if (S_ISDIR(stat_buf.st_mode)) { /* Process directory */
            rc = memset_s(base, sizeof(base), '\0', sizeof(base));
            securec_check_errno(rc, (void)rc);
            rc = strcpy_s(base, MAX_PATH_LEN, basePath);
            securec_check_errno(rc, (void)rc);
            rc = strcat_s(base, MAX_PATH_LEN, "/");
            securec_check_errno(rc, (void)rc);
            rc = strcat_s(base, MAX_PATH_LEN, ptr->d_name);
            securec_check_errno(rc, (void)rc);
            if (readFileList(base, logFile, count, totalSize, maxCount) < 0) {
                write_runlog(ERROR, "readFileList() fail.");
            }
        }
    }
    (void)closedir(dir);
    return 0;
}

static int cmagent_unlock(void)
{
    int ret = flock(fileno(g_lockfile), LOCK_UN);
    if (g_lockfile != NULL) {
        (void)fclose(g_lockfile);
        g_lockfile = NULL;
    }
    return ret;
}

static int cmagent_lock(void)
{
    int ret;
    struct stat statbuf = {0};

    /* If gtm_ctl.lock dose not exist,create it */
    if (stat(g_cmagentLockfile, &statbuf) != 0) {
        char content[MAX_PATH_LEN] = {0};
        g_lockfile = fopen(g_cmagentLockfile, PG_BINARY_W);
        if (g_lockfile == NULL) {
            (void)fprintf(stderr, "FATAL %s: can't open lock file \"%s\" : %s\n",
                g_progname, g_cmagentLockfile, strerror(errno));
            exit(1);
        }
        (void)chmod(g_cmagentLockfile, S_IRUSR | S_IWUSR);
        if (fwrite(content, MAX_PATH_LEN, 1, g_lockfile) != 1) {
            (void)fclose(g_lockfile);
            g_lockfile = NULL;
            (void)fprintf(stderr,
                "FATAL %s: can't write lock file \"%s\" : %s\n",
                g_progname, g_cmagentLockfile, strerror(errno));
            exit(1);
        }
        (void)fclose(g_lockfile);
        g_lockfile = NULL;
        (void)chmod(g_cmagentLockfile, S_IRUSR | S_IWUSR);
    }
    if ((g_lockfile = fopen(g_cmagentLockfile, PG_BINARY_W)) == NULL) {
        (void)fprintf(stderr, "FATAL %s: could not open lock file \"%s\" : %s\n",
            g_progname, g_cmagentLockfile, strerror(errno));
        exit(1);
    }

    if (SetFdCloseExecFlag(g_lockfile) < 0) {
        (void)fprintf(stderr, "%s: can't set file flag\"%s\" : %s\n", g_progname, g_cmagentLockfile, strerror(errno));
    }

    ret = flock(fileno(g_lockfile), LOCK_EX | LOCK_NB);

    return ret;
}

void GetAgentConfigEx()
{
    /* Create thread of compressed and remove task. */
    if (get_config_param(configDir, "enable_cn_auto_repair", g_enableCnAutoRepair, sizeof(g_enableCnAutoRepair)) < 0) {
        (void)fprintf(stderr, "get_config_param() get enable_cn_auto_repair fail.\n");
    }

    if (get_config_param(configDir, "enable_log_compress", g_enableLogCompress, sizeof(g_enableLogCompress)) < 0) {
        (void)fprintf(stderr, "get_config_param() get enable_log_compress fail.\n");
    }

    if (get_config_param(configDir, "enable_ssl", g_enableMesSsl, sizeof(g_enableMesSsl)) < 0) {
        (void)fprintf(stderr, "get_config_param() get enable_ssl fail.\n");
    }

    if (get_config_param(configDir, "security_mode", g_enableOnlineOrOffline, sizeof(g_enableOnlineOrOffline)) < 0) {
        (void)fprintf(stderr, "get_config_param() get security_mode fail.\n");
    }

    if (get_config_param(configDir, "unix_socket_directory", g_unixSocketDirectory, sizeof(g_unixSocketDirectory)) <
        0) {
        (void)fprintf(stderr, "get_config_param() get unix_socket_directory fail.\n");
    } else {
        check_input_for_security(g_unixSocketDirectory);
    }
    if (get_config_param(configDir, "voting_disk_path", g_votingDiskPath, sizeof(g_votingDiskPath)) < 0) {
        (void)fprintf(stderr, "get_config_param() get voting_disk_path fail.\n");
    }
    canonicalize_path(g_votingDiskPath);
    g_diskTimeout = get_uint32_value_from_config(configDir, "disk_timeout", 200);
    log_max_size = get_int_value_from_config(configDir, "log_max_size", 10240);
    log_saved_days = get_uint32_value_from_config(configDir, "log_saved_days", 90);
    log_max_count = get_uint32_value_from_config(configDir, "log_max_count", 10000);

    g_cmaRhbItvl = get_uint32_value_from_config(configDir, "agent_rhb_interval", 1000);

    g_sslOption.expire_time = get_uint32_value_from_config(configDir, "ssl_cert_expire_alert_threshold",
        CM_DEFAULT_SSL_EXPIRE_THRESHOLD);
    g_sslCertExpireCheckInterval = get_uint32_value_from_config(configDir, "ssl_cert_expire_check_interval",
        SECONDS_PER_DAY);
    if (g_sslOption.expire_time < CM_MIN_SSL_EXPIRE_THRESHOLD ||
        g_sslOption.expire_time > CM_MAX_SSL_EXPIRE_THRESHOLD) {
        write_runlog(ERROR, "invalid ssl expire alert threshold %u, must between %u and %u\n",
            g_sslOption.expire_time, CM_MIN_SSL_EXPIRE_THRESHOLD, CM_MAX_SSL_EXPIRE_THRESHOLD);
    }
}

static void GetAlarmConf()
{
    char alarmPath[MAX_PATH_LEN] = {0};
    int rcs = GetHomePath(alarmPath, sizeof(alarmPath));
    if (rcs != EOK) {
        write_runlog(ERROR, "Get GAUSSHOME failed, please check.\n");
        return;
    }
    canonicalize_path(alarmPath);
    int rc =
        snprintf_s(g_alarmConfigDir, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin/alarmConfig.conf", alarmPath);
    securec_check_intval(rc, (void)rc);
    GetAlarmConfig(g_alarmConfigDir);
}

int get_agent_global_params_from_configfile()
{
    int rc =
    snprintf_s(configDir, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/cm_agent/cm_agent.conf", g_currentNode->cmDataPath);
    securec_check_intval(rc, (void)rc);
    check_input_for_security(configDir);
    canonicalize_path(configDir);
    if (cmagent_lock() == -1) {
        return -1;
    }
    GetAlarmConf();
    get_log_paramter(configDir);
    GetStringFromConf(configDir, sys_log_path, sizeof(sys_log_path), "log_dir");
    check_input_for_security(sys_log_path);
    get_build_mode(configDir);
    get_start_mode(configDir);
    get_connection_mode(configDir);
    GetStringFromConf(configDir, g_environmentThreshold, sizeof(g_environmentThreshold), "environment_threshold");
    
    GetStringFromConf(configDir, g_dbServiceVip, sizeof(g_dbServiceVip), "db_service_vip");
    if (g_dbServiceVip[0] == '\0') {
        write_runlog(LOG, "parameter \"db_service_vip\" is not provided, please check!\n");
    } else if (!IsIPAddrValid(g_dbServiceVip)) {
        write_runlog(ERROR, "value of parameter \"db_service_vip\" is invalid, please check!\n");
        return -1;
    }
    agent_report_interval = get_uint32_value_from_config(configDir, "agent_report_interval", 1);
    agent_heartbeat_timeout = get_uint32_value_from_config(configDir, "agent_heartbeat_timeout", 8);
    agent_connect_timeout = get_uint32_value_from_config(configDir, "agent_connect_timeout", 1);
    agent_backup_open = (ClusterRole)get_uint32_value_from_config(configDir, "agent_backup_open", CLUSTER_PRIMARY);
    agent_connect_retries = get_uint32_value_from_config(configDir, "agent_connect_retries", 15);
    agent_check_interval = get_uint32_value_from_config(configDir, "agent_check_interval", 2);
    agent_kill_instance_timeout = get_uint32_value_from_config(configDir, "agent_kill_instance_timeout", 0);
    agent_phony_dead_check_interval = get_uint32_value_from_config(configDir, "agent_phony_dead_check_interval", 10);
    enable_gtm_phony_dead_check = get_uint32_value_from_config(configDir, "enable_gtm_phony_dead_check", 1);
    g_enableE2ERto = (uint32)get_int_value_from_config(configDir, "enable_e2e_rto", 0);
    g_disasterRecoveryType =
        (DisasterRecoveryType)get_uint32_value_from_config(configDir, "disaster_recovery_type", DISASTER_RECOVERY_NULL);
    agent_phony_dead_check_interval = g_enableE2ERto == 1 ? 1 : agent_phony_dead_check_interval;
    g_ssDoubleClusterMode =
        (SSDoubleClusterMode)get_uint32_value_from_config(configDir, "ss_double_cluster_mode", SS_DOUBLE_NULL);

    log_threshold_check_interval =
        get_uint32_value_from_config(configDir, "log_threshold_check_interval", log_threshold_check_interval);
    undocumentedVersion = get_uint32_value_from_config(configDir, "upgrade_from", 0);
    dilatation_shard_count_for_disk_capacity_alarm = get_uint32_value_from_config(
        configDir, "dilatation_shard_count_for_disk_capacity_alarm", dilatation_shard_count_for_disk_capacity_alarm);
    if (get_config_param(configDir, "enable_dcf", g_agentEnableDcf, sizeof(g_agentEnableDcf)) < 0) {
        write_runlog(ERROR, "get_config_param() get enable_dcf fail.\n");
    }

#ifndef ENABLE_MULTIPLE_NODES
    if (get_config_param(configDir, "enable_fence_dn", g_enableFenceDn, sizeof(g_enableFenceDn)) < 0)
        write_runlog(ERROR, "get_config_param() get enable_fence_dn fail.\n");
#endif
    GetEventTrigger();

#ifdef __aarch64__
    agent_process_cpu_affinity = get_uint32_value_from_config(configDir, "process_cpu_affinity", 0);
    if (agent_process_cpu_affinity > CPU_AFFINITY_MAX) {
        (void)fprintf(stderr, "CM parameter 'process_cpu_affinity':%d is bigger than limit:%d\n",
            agent_process_cpu_affinity, CPU_AFFINITY_MAX);
        agent_process_cpu_affinity = 0;
    }

    total_cpu_core_num = get_nprocs();
    (void)fprintf(stdout, "total_cpu_core_num is %d, agent_process_cpu_affinity is %d\n",
        total_cpu_core_num, agent_process_cpu_affinity);
#endif
    GetAgentConfigEx();
    return 0;
}

static status_t InitSendDdbOperRes()
{
    if (g_currentNode->coordinate == 0) {
        return CM_SUCCESS;
    }
    (void)pthread_rwlock_init(&(g_gtmSendDdbOper.lock), NULL);
    (void)pthread_rwlock_init(&(g_gtmCmDdbOperRes.lock), NULL);
    size_t sendLen = sizeof(CltSendDdbOper);
    CltSendDdbOper *sendOper = (CltSendDdbOper *)malloc(sendLen);
    if (sendOper == NULL) {
        write_runlog(ERROR, "sendOper is NULL, cma will exit.\n");
        return CM_ERROR;
    }
    errno_t rc = memset_s(sendOper, sendLen, 0, sendLen);
    securec_check_errno(rc, FREE_AND_RESET(sendOper));
    g_gtmSendDdbOper.sendOper = sendOper;
    size_t operResLen = sizeof(CmSendDdbOperRes);
    CmSendDdbOperRes *ddbOperRes = (CmSendDdbOperRes *)malloc(operResLen);
    if (ddbOperRes == NULL) {
        free(sendOper);
        sendOper = NULL;
        write_runlog(ERROR, "ddbOperRes is NULL, cma will exit.\n");
        return CM_ERROR;
    }
    rc = memset_s(ddbOperRes, operResLen, 0, operResLen);
    securec_check_errno(rc, FREE_AND_RESET(ddbOperRes));
    g_gtmCmDdbOperRes.ddbOperRes = ddbOperRes;
    return CM_SUCCESS;
}

static void InitNeedInfoRes()
{
    size_t syncListLen = sizeof(DnSyncListInfo) * CM_MAX_DATANODE_PER_NODE;
    errno_t rc = memset_s(g_dnSyncListInfo, syncListLen, 0, syncListLen);
    securec_check_errno(rc, (void)rc);
    size_t doWriteLen = sizeof(CmDoWriteOper) * CM_MAX_DATANODE_PER_NODE;
    rc = memset_s(g_cmDoWriteOper, doWriteLen, 0, doWriteLen);
    securec_check_errno(rc, (void)rc);
}

static inline void InitResReportMsg()
{
    errno_t rc = memset_s(&g_resReportMsg, sizeof(OneNodeResStatusInfo), 0, sizeof(OneNodeResStatusInfo));
    securec_check_errno(rc, (void)rc);
    InitResStatCommInfo(&g_resReportMsg.resStat);
    (void)pthread_rwlock_init(&(g_resReportMsg.rwlock), NULL);
}

static void CreateCusResThread()
{
    if (IsCusResExistLocal()) {
        CreateRecvClientMessageThread();
        CreateSendMessageToClientThread();
        CreateProcessMessageThread();
        InitResReportMsg();
        CreateDefResStatusCheckThread();
        CreateCusResIsregCheckThread();
    } else {
        write_runlog(LOG, "[CLIENT] no resource, start client thread is unnecessary.\n");
    }
}

static status_t CmaReadCusResConf()
{
    int ret = ReadCmConfJson((void*)write_runlog);
    if (!IsReadConfJsonSuccess(ret)) {
        write_runlog(FATAL, "read cm conf json failed, ret=%d, reason=\"%s\".\n", ret, ReadConfJsonFailStr(ret));
        return CM_ERROR;
    }
    if (InitAllResStat() != CM_SUCCESS) {
        write_runlog(FATAL, "init res status failed.\n");
        return CM_ERROR;
    }
    if (InitLocalResConf() != CM_SUCCESS) {
        write_runlog(FATAL, "init local res conf failed.\n");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static void InitAgentGlobalVariable()
{
    //Init is openGauss with dms or dss mode
    for (uint32 i = 0; i < GetLocalResConfCount(); ++i) {
        if (strcmp(g_resConf[i].resName, "dss") == 0 || strcmp(g_resConf[i].resName, "dms_res") == 0) {
            g_isStorageWithDMSorDSS = true;
            write_runlog(LOG, "This node has dms or dss enabled.\n");
            return;
        }
    }
}

int main(int argc, char** argv)
{
    uid_t uid = getuid();
    if (uid == 0) {
        (void)printf("current user is the root user (uid = 0), exit.\n");
        return 1;
    }

    int status;
    uint32 i;
    size_t lenth = 0;
    int *thread_index = NULL;
    errno_t rc;
    const int maxArgcNum = 2;
    bool &isSharedStorageMode = GetIsSharedStorageMode();

    if (argc > maxArgcNum) {
        (void)printf(_("the argv is error, try cm_agent -h for more information!\n"));
        return -1;
    }

    GetCmdlineOpt(argc, argv);

    g_progname = "cm_agent";
    prefix_name = g_progname;
    if (argc > 1) {
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-?") == 0) {
            DoHelp();
            exit(0);
        } else if (strcmp(argv[1], "-V") == 0 || strcmp(argv[1], "--version") == 0) {
            (void)puts("cm_agent " DEF_CM_VERSION);
            exit(0);
        } else if (strcmp("normal", argv[1]) == 0) {
            g_isStart = true;
            lenth = strlen(argv[1]);
            rc = memset_s(argv[1], lenth, 0, lenth);
            securec_check_errno(rc, (void)rc);
        } else if (strcmp("abnormal", argv[1]) == 0) {
            g_isStart = false;
            lenth = strlen(argv[1]);
            rc = memset_s(argv[1], lenth, 0, lenth);
            securec_check_errno(rc, (void)rc);
        }
    }
    (void)syscalllockInit(&g_cmEnvLock);

    /* init the sigset and register the signal handle */
    init_signal_mask();
    (void)sigprocmask(SIG_SETMASK, &block_sig, NULL);
    setup_signal_handle(SIGHUP, reload_cmagent_parameters);
    setup_signal_handle(SIGUSR1, RecvSigusrSingle);
#ifdef ENABLE_MULTIPLE_NODES
    setup_signal_handle(SIGUSR2, SetFlagToUpdatePortForCnDn);
#endif
    status = get_prog_path();
    if (status < 0) {
        (void)fprintf(stderr, "get_prog_path  failed!\n");
        return -1;
    }

    pw = getpwuid(getuid());
    if (pw == NULL || pw->pw_name == NULL) {
        (void)fprintf(stderr, "can not get current user name.\n");
        return -1;
    }
    SetEnvSupportIpV6(CheckSupportIpV6());

    /* Initialize OPENSSL, and register a signal handler to clean up when use exit() */
    if (RegistOpensslExitSignal(g_progname)) {
        return -1;
    }

    status = CmSSlConfigInit(true);
    if (status < 0) {
        (void)fprintf(stderr, "read ssl cerfication files when start!\n");
        return -1;
    }

    status = read_config_file_check();
    if (status < 0) {
        (void)fprintf(stderr, "read_config_file_check failed when start!\n");
        return -1;
    }

    max_logic_cluster_name_len = (max_logic_cluster_name_len < strlen("logiccluster_name"))
                                     ? (uint32)strlen("logiccluster_name")
                                     : max_logic_cluster_name_len;

    (void)logfile_init();
    if (get_agent_global_params_from_configfile() == -1) {
        (void)fprintf(stderr, "Another cm_agent command is still running, start failed !\n");
        return -1;
    }
    /* deal sys_log_path is null.save log to cmData dir. */
    if (sys_log_path[0] == '\0') {
        rc = strncpy_s(sys_log_path, sizeof(sys_log_path), g_currentNode->cmDataPath, MAXPGPATH - 1);
        securec_check_errno(rc, (void)rc);

        rc = strncat_s(sys_log_path, sizeof(sys_log_path), "/cm_agent/log", strlen("/cm_agent/log"));
        securec_check_errno(rc, (void)rc);
        (void)mkdir(sys_log_path, S_IRWXU);
    } else {
        if (sys_log_path[0] == '/') {
            (void)CmMkdirP(sys_log_path, S_IRWXU);
        } else {
            char buf[MAXPGPATH] = {0};

            rc = memset_s(buf, sizeof(buf), 0, MAXPGPATH);
            securec_check_errno(rc, (void)rc);

            rc = strncpy_s(buf, sizeof(buf), g_currentNode->cmDataPath, MAXPGPATH - 1);
            securec_check_errno(rc, (void)rc);

            rc = strncat_s(buf, sizeof(buf), "/cm_agent/", strlen("/cm_agent/"));
            securec_check_errno(rc, (void)rc);
            rc = strncat_s(buf, sizeof(buf), sys_log_path, strlen(sys_log_path));
            securec_check_errno(rc, (void)rc);

            rc = memcpy_s(sys_log_path, sizeof(sys_log_path), buf, MAXPGPATH);
            securec_check_errno(rc, (void)rc);
            (void)mkdir(sys_log_path, S_IRWXU);
        }
    }
    status_t st = CreateSysLogFile();
    if (st != CM_SUCCESS) {
        exit(-1);
    }

    rc = memset_s(system_call_log, MAXPGPATH, 0, MAXPGPATH);
    securec_check_errno(rc, (void)rc);

    create_system_call_log();

    create_system_alarm_log(sys_log_path);

    print_environ();

    if (g_currentNode->datanodeCount > CM_MAX_DATANODE_PER_NODE) {
        write_runlog(FATAL,
            "%u datanodes deployed on this node more than limit(%d)\n",
            g_currentNode->datanodeCount,
            CM_MAX_DATANODE_PER_NODE);
        exit(1);
    }

    AlarmEnvInitialize();
    InitializeAlarmItem(g_currentNode);
    rc = snprintf_s(g_agentDataDir, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/cm_agent/", g_currentNode->cmDataPath);
    securec_check_intval(rc, (void)rc);

    (void)atexit(stop_flag);

    if (CmaReadCusResConf() != CM_SUCCESS) {
        exit(-1);
    }

    InitAgentGlobalVariable();

    CmServerCmdProcessorInit();
    status = CreateCheckNetworkThread();
    if (status != 0) {
        exit(status);
    }
#ifdef ENABLE_MULTIPLE_NODES
    if (g_currentNode->gtm == 1) {
        (void)pthread_rwlock_init(&(g_gtmReportMsg.lk_lock), NULL);
        CreateGTMStatusCheckThread();
    }

    if (g_currentNode->coordinate == 1) {
        (void)pthread_rwlock_init(&(g_cnReportMsg.lk_lock), NULL);
        CreateCNStatusCheckThread();
        /* start ccn status checker */
        CreateCCNStatusCheckThread();
        CreateCNBackupStatusCheckThread();
    }
#endif
    InitNeedInfoRes();
    if (g_currentNode->datanodeCount > 0) {
        thread_index = (int *)malloc(sizeof(int) * g_currentNode->datanodeCount);
        if (thread_index == NULL) {
            write_runlog(FATAL, "out of memory\n");
            exit(1);
        }

        for (i = 0; i < g_currentNode->datanodeCount; i++) {
            thread_index[i] = (int)i;
#ifdef __aarch64__
            /* Get the initial primary datanode number */
            g_datanode_primary_num += (PRIMARY_DN == g_currentNode->datanode[i].datanodeRole) ? 1 : 0;
            g_datanode_primary_and_standby_num += (DUMMY_STANDBY_DN != g_currentNode->datanode[i].datanodeRole) ? 1 : 0;
#endif
        }

        for (i = 0; i < g_currentNode->datanodeCount; i++) {
            (void)pthread_rwlock_init(&(g_dnReportMsg[i].lk_lock), NULL);
            (void)pthread_rwlock_init(&(g_dnSyncListInfo[i].lk_lock), NULL);
            (void)pthread_rwlock_init(&(g_cmDoWriteOper[i].lock), NULL);
            int *ind = thread_index + i;
            CreateDNStatusCheckThread(ind);
            CreateDNConnectionStatusCheckThread(ind);
            CreateDNCheckSyncListThread(ind);
            CreateDNCheckAvailableSyncThread(ind);
#ifdef ENABLE_MULTIPLE_NODES
            CreateDNBackupStatusCheckThread(ind);
            CreateDNStorageScalingAlarmThread(ind);
#endif
        }
    }

    /* Get log path that is used in start&stop thread and log compress&remove thread. */
    status = cmagent_getenv("GAUSSLOG", g_logBasePath, sizeof(g_logBasePath));
    if (status != EOK) {
        write_runlog(FATAL, "get env GAUSSLOG fail.\n");
        exit(status);
    }
    isSharedStorageMode = IsSharedStorageMode();

    AllocCmaMsgQueueMemory();
    AllQueueInit();
    MsgPoolInit(MAX_MSG_BUF_POOL_SIZE, MAX_MSG_BUF_POOL_COUNT);
    st = InitSendDdbOperRes();
    if (st != CM_SUCCESS) {
        write_runlog(FATAL, "failed to InitSendDdbOperRes.\n");
        exit(-1);
    }
    check_input_for_security(g_logBasePath);
    CreatePhonyDeadCheckThread();
    CreateStartAndStopThread();
    CreateFaultDetectThread();
    CreateConnCmsPThread();
    CreateCheckUpgradeModeThread();
    CreateRhbCheckThreads();
    CreateVotingDiskThread();
    CreateCusResThread();
    int err = CreateSendAndRecvCmsMsgThread();
    if (err != 0) {
        write_runlog(FATAL, "Failed to create send and recv thread: error %d\n", err);
        exit(err);
    }
    err = CreateProcessSendCmsMsgThread();  // inst status report thread
    if (err != 0) {
        write_runlog(FATAL, "Failed to create send msg thread: error %d\n", err);
        exit(err);
    }
    err = CreateProcessRecvCmsMsgThread();
    if (err != 0) {
        write_runlog(FATAL, "Failed to create process recv msg thread: error %d\n", err);
        exit(err);
    }
    CreateKerberosStatusCheckThread();
    CreateDiskUsageCheckThread();
    CreateOnDemandRedoCheckThread();

#ifdef ENABLE_MULTIPLE_NODES
    err = CreateCheckNodeStatusThread();
    if (err != 0) {
        write_runlog(FATAL, "Failed to create check node status thread: error %d\n", err);
        exit(err);
    }
    if (g_currentNode->coordinate > 0) {
        err = CreateCnDnConnectCheckThread();
        if (err != 0) {
            write_runlog(FATAL, "Failed to create check conn status thread: error %d\n", err);
            exit(err);
        }
        CreatePgxcNodeCheckThread();
    }

    /* if g_etcd_num = 0, cms change to dcc arbitrate, so can check gtm mode */
    if (g_currentNode->coordinate > 0) {
        CreateGtmModeThread();
    }
#endif

    if (g_currentNode->etcd) {
        (void)pthread_rwlock_init(&(g_etcdReportMsg.lk_lock), NULL);
        CreateETCDStatusCheckThread();
        CreateETCDConnectionStatusCheckThread();
    }

    /* Parameter is on then start compress thread */
    if (CreateLogFileCompressAndRemoveThread() != 0) {
        write_runlog(FATAL, "CreateLogFileCompressAndRemoveThread failed!\n");
        exit(-1);
    }

    server_loop();
    (void)cmagent_unlock();

    write_runlog(LOG, "cm_agent exit\n");
    if (thread_index != NULL) {
        FREE_AND_RESET(thread_index);
    }

    exit(status);
}

uint32 GetLibcommDefaultPort(uint32 base_port, int port_type)
{
    /* DWS: default port, other: cn_port +2 */
    if (port_type == COMM_PORT_TYPE_DATA) {
        if (security_mode) {
            return COMM_DATA_DFLT_PORT;
        } else {
            return (base_port + 2);
        }
    } else {
        /* DWS: default port, other: cn_port +3 */
        if (security_mode) {
            return COMM_CTRL_DFLT_PORT;
        } else {
            return (base_port + 3);
        }
    }
}

bool ExecuteCmdWithResult(char *cmd, char *result, int resultLen)
{
    FILE *cmd_fd = popen(cmd, "r");
    if (cmd_fd == NULL) {
        write_runlog(ERROR, "popen %s failed, errno[%d].\n", cmd, errno);
        return false;
    }

    if (fgets(result, resultLen - 1, cmd_fd) == NULL) {
        (void)pclose(cmd_fd);
        /* has error or result is really null */
        write_runlog(LOG, "fgets result for %s failed, errno[%d].\n", cmd, errno);
        return false;
    }
    (void)pclose(cmd_fd);

    return true;
}

uint32 GetLibcommPort(const char *file_path, uint32 base_port, int port_type)
{
    char get_cmd[MAXPGPATH * 2];
    char result[NAMEDATALEN] = {0};
    int retry_cnt = 0;
    uint32 port = 0;
    const char *Keywords = NULL;

    if (port_type == COMM_PORT_TYPE_DATA) {
        Keywords = "comm_sctp_port";
    } else {
        Keywords = "comm_control_port";
    }

    /* read port from postgres.conf */
    int ret = snprintf_s(get_cmd,
        sizeof(get_cmd),
        MAXPGPATH * 2 - 1,
        "grep \"^%s\" %s/postgresql.conf|awk \'{print $3}\'|tail -1",
        Keywords,
        file_path);
    securec_check_intval(ret, (void)ret);

    while (retry_cnt < MAX_RETRY_TIME) {
        if (!ExecuteCmdWithResult(get_cmd, result, NAMEDATALEN)) {
            retry_cnt++;
            continue;
        }

        port = (uint32)strtol(result, NULL, 10);
        /* guc param is out of range */
        if (port == 0 || port > 65535) {
            port = GetLibcommDefaultPort(base_port, port_type);
            write_runlog(
                WARNING, "Custom %s: %ld is invalid, use the default:%u.\n", Keywords, strtol(result, NULL, 10), port);
            return port;
        } else {
            write_runlog(LOG, "Custom %s: %u has found.\n", Keywords, port);
            return port;
        }
    }

    port = GetLibcommDefaultPort(base_port, port_type);
    write_runlog(LOG, "No custom %s found, use the default:%u.\n", Keywords, port);
    return port;
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
static void ParseEventTriggers(const char *value)
{
    if (value == NULL || value[0] == 0) {
        write_runlog(WARNING, "The value of event_triggers is empty.\n");
        return;
    }
    if (strlen(value) > MAX_PATH_LEN) {
        write_runlog(ERROR, "The string value \"%s\" is longer than 1024.\n", value);
        return;
    }

    cJSON *root = NULL;
    root = cJSON_Parse(value);
    if (!root) {
        write_runlog(ERROR, "The value of event_triggers is not a json.\n");
        return;
    }
    if (cJSON_IsArray(root)) {
        write_runlog(ERROR, "The value of event_triggers can't be a json item array.\n");
        cJSON_Delete(root);
        return;
    }

    int triggerNums[EVENT_COUNT] = {0};
    cJSON *item = root->child;
    /* when the new value is invalid, the old value should not be modify at all,
     * so a temporary backup is needed, to avoid partial modifications
     */
    char *eventTriggers[EVENT_COUNT] = {NULL};
    bool isValueInvalid = false;
    while (item != NULL) {
        if (CheckEventTriggersItem(item) == CM_ERROR) {
            isValueInvalid = true;
            break;
        }

        char *typeStr = item->string;
        EventTriggerType type = GetTriggerTypeFromStr(typeStr);
        if (type == EVENT_UNKNOWN) {
            write_runlog(ERROR, "The trigger type %s does support.\n", typeStr);
            isValueInvalid = true;
            break;
        }

        char *valuePtr = item->valuestring;
        ++triggerNums[type];
        if (triggerNums[type] > 1) {
            write_runlog(ERROR, "Duplicated trigger %s are supported.\n", typeStr);
            isValueInvalid = true;
            break;
        }

        eventTriggers[type] = (char*)CmMalloc(strlen(valuePtr));
        int ret = snprintf_s(eventTriggers[type], MAX_PATH_LEN,
            MAX_PATH_LEN - 1, "%s", valuePtr);
        securec_check_intval(ret, (void)ret);
        item = item->next;
    }

    if (isValueInvalid) {
        for (int i = 0; i < EVENT_COUNT; ++i) {
            if (eventTriggers[i] != NULL) {
                FREE_AND_RESET(eventTriggers[i]);
            }
        }
        cJSON_Delete(root);
        return;
    }

    // copy the temporary backup to the global variable and clean up the temporary backup
    for (int i = 0; i < EVENT_COUNT; ++i) {
        if (eventTriggers[i] == NULL) {
            if (g_eventTriggers[i] != NULL) {
                FREE_AND_RESET(g_eventTriggers[i]);
            }
        } else {
            if (g_eventTriggers[i] == NULL) {
                g_eventTriggers[i] = (char*)CmMalloc(strlen(eventTriggers[i]));
            }
            int ret = snprintf_s(g_eventTriggers[i], MAX_PATH_LEN,
                MAX_PATH_LEN - 1, "%s", eventTriggers[i]);
            securec_check_intval(ret, (void)ret);
            FREE_AND_RESET(eventTriggers[i]);
            write_runlog(LOG, "Event trigger %s was added, script path = %s.\n",
                triggerTypeStringMap[i].typeStr, g_eventTriggers[i]);
        }
    }
    cJSON_Delete(root);
}

void GetEventTrigger()
{
    char eventTriggerString[MAX_PATH_LEN] = {0};
    if (get_config_param(configDir, "event_triggers", eventTriggerString, MAX_PATH_LEN) < 0) {
        write_runlog(ERROR, "get_config_param() get event_triggers fail.\n");
        return;
    }
    ParseEventTriggers(eventTriggerString);
}

void ExecuteEventTrigger(const EventTriggerType triggerType, int32 staPrimId)
{
    if (g_eventTriggers[triggerType] == NULL) {
        return;
    }
    write_runlog(LOG, "Event trigger %s was triggered.\n", triggerTypeStringMap[triggerType].typeStr);
    char execTriggerCmd[MAX_COMMAND_LEN] = {0};
    int rc;
    if (staPrimId != INVALID_ID && triggerType == EVENT_FAILOVER) {
        rc = snprintf_s(execTriggerCmd, MAX_COMMAND_LEN, MAX_COMMAND_LEN - 1,
        SYSTEMQUOTE "%s %d >> %s 2>&1 &" SYSTEMQUOTE, g_eventTriggers[triggerType], staPrimId, system_call_log);
    } else {
        rc = snprintf_s(execTriggerCmd, MAX_COMMAND_LEN, MAX_COMMAND_LEN - 1,
        SYSTEMQUOTE "%s >> %s 2>&1 &" SYSTEMQUOTE, g_eventTriggers[triggerType], system_call_log);
    }
    securec_check_intval(rc, (void)rc);
    write_runlog(LOG, "event trigger command: \"%s\".\n", execTriggerCmd);
    RunCmd(execTriggerCmd);
}