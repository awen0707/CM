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
 * cma_main.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_agent/cma_main.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CMA_MAIN_H
#define CMA_MAIN_H


#include "common/config/cm_config.h"
#include "alarm/alarm.h"
#include "cm/cm_msg.h"
#include "cma_alarm.h"

#define STOP_PRIMARY_RESULT "stop_primary_result"
#define CHECK_VERSION_RESULT "check_version_result"

#define CM_AGENT_LOG_FILE "cm_agent.log"
#define CM_STATIC_CONFIG_FILE "cluster_static_config"
#define CM_CLUSTER_MANUAL_START "cluster_manual_start"
#define CM_INSTANCE_MANUAL_START "instance_manual_start"
#define CM_ETCD_MANUAL_START "etcd_manual_start"
#define CM_RESUMING_CN_STOP "resuming_cn_stop"
#define CM_CLUSTER_RESIZE "cluster_resize.progress"
#define CM_CLUSTER_REPLACE "cluster_replace.progress"
#define LOGIC_CLUSTER_LIST "logic_cluster_name.txt"
#define CM_AGENT_DATA_DIR "cm_agent"
#define INSTANCE_MAINTANCE "instance_maintance"
#define SYSTEM_CALL_LOG "system_call"
#define MAX_LOGFILE_TIMESTAMP "99991231235959"
#define CM_CLUSTER_MANUAL_PAUSE "cluster_manual_pause"
#define CM_CLUSTER_MANUAL_STARTING "cluster_manual_starting"

#define CONN_FAIL_TIMES 3
/* time style length */
#define MAX_TIME_LEN 20
#define NO_RES_CHANGED (-1)
const int cn_repair_retry_times = 3;
/* interval set to 10s to reduce invalid log */
const uint32 g_check_dn_sql5_interval = 10;

typedef long pgpid_t;

/* These global variables are used to compressed traces */
typedef struct {
    char fileName[MAX_PATH_LEN];
    char basePath[MAX_PATH_LEN];
    char pattern[MAX_PATH_LEN];
    char timestamp[MAX_TIME_LEN];
    int64 fileSize;
} LogFile;

/* Log pattern for compress */
typedef struct LogPatternSt {
    const char *patternName;
} LogPattern;

/* get local max lsn */
typedef struct {
    bool checked;
    XLogRecPtr max_lsn;
} LocalMaxLsnMng;

/* get dn database info */
typedef struct {
    char dbname[NAMEDATALEN];
    uint32 oid;
} DNDatabaseInfo;

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

extern void GetEventTrigger();

/*
 *        Cut time from trace name.
 *        This time will be used to sort traces.
 */
void cutTimeFromFileLog(const char *fileName, char *pattern, uint32 patternLen, char *strTime);
/*
 *        Sort of trace file by time asc.
 *        This time is part of trace name.
 */
void sortLogFileByTimeAsc(LogFile* logFile, int low, int high);

/*
 *        get the mode of the cluster.
 */
void get_start_mode(char* config_file);

/*
 *        used for connection mode or option between cm_agent and cn/dn.
 */
void get_connection_mode(char* config_file);

/*
 *        Read parameter from cm_agent.conf by accurate parameter name.
 */
int get_config_param(const char* config_file, const char* srcParam, char* destParam, int destLen);

/*
 *        Compressed trace to gz by zlib.
 *        The gzread() function shall read data from the compressed file referenced by file,
 *        which shall have been opened in a read mode (see gzopen() and gzdopen()). The gzread()
 *        function shall read data from file, and   *        uncompress it into buf. At most, len
 *        bytes of uncompressed data shall be copied to buf. If the file is not compressed,
 *        gzread() shall simply copy data from file to buf without alteration.
 *        The gzwrite() function shall write data to the compressed file referenced by file, which shall
 *        have been opened in a write mode (see gzopen() and gzdopen()). On entry, buf shall point to a
 *        buffer containing lenbytes of uncompressed data. The gzwrite() function shall compress this
 *        data and write it to file. The gzwrite() function shall return the number of uncompressed
 *        bytes actually written.
 */

int GZCompress(char *inpath, uint32 inLen, char *outpath, uint32 outLen);

/*
 *        Get trace pattern from cm_agent.conf.
 *        All trace pattern to be compressed are defined in cm_agent.conf.
 */

/*
 *        Create compress and remove thread for trace.
 *        Use Thread for this task avoid taking too much starting time of cm server.
 */
void CreateLogFileCompressAndRemoveThread(const char* patternName);

/*
 *        Read all traces by log pattern,including zip file and non zip file.
 *        Trace information are file time,file size,file path.These traces are
 *        saved in the global variable.
 */
int readFileList(const char* basePath, LogFile* logFile, uint32* count, int64* totalSize, uint32 maxCount);
/*
 *        Remove a file.
 *        It's always used to remove a trace compressed.
 */
void delLogFile(const char* fileName);
typedef enum { STARTING, ALL_NORMAL, INSTANCE_NEED_REPAIR, ALL_PENDING } ClusterStatus;

typedef enum { INSTANCE_CN, INSTANCE_DN, INSTANCE_GTM, INSTANCE_CM, INSTANCE_FENCED, INSTANCE_KERBEROS} InstanceTypes;

typedef enum { DOWN, PRIMARY, STANDBY, PENDING } InstanceStatus;

typedef enum { UNKNOWN_HA_STATE, NORMAL_HA_STATE, NEED_REPAIR, BUILD } HAStatus;

typedef enum { NA, SYSTEM_MARK_INCONSISTENT, TIMELINE_INCONSISTENT, LOG_NOT_EXIST } BuildReason;

typedef enum { SMART_MODE, FAST_MODE, IMMEDIATE_MODE, RESUME_MODE, SHUTDOWN_CEIL_MODE } ShutdownMode;

typedef enum { INSTANCE_START, INSTANCE_STOP } OperateType;

typedef struct {
    uint32 node;

    char DataPath[CM_PATH_LENGTH];
    uint32 type;
    uint32 InstanceStatus;

    char LogPath[CM_PATH_LENGTH];
    uint32 HAStatus;
    uint32 reason;
} InstanceStatusReport;

typedef enum { NORMAL, UNKNOWN } CoordinateStatus;

typedef struct {
    uint32 node;
    char nodeName[CM_NODE_NAME];
    uint32 isCn;
    uint32 CoordinateStatus;
    uint32 isGtm;
    InstanceStatusReport gtm;
    uint32 datanodesNum;
    InstanceStatusReport datanodes[CM_MAX_DATANODE_PER_NODE];
} NodeStatusReport;

typedef struct {
    bool datanodes[CM_MAX_DATANODE_PER_NODE];
    bool coordinator;
} datanode_failover;

typedef struct {
    bool gtmnodes;
    bool coordinator;
} gtm_failover;

typedef struct {
    int cn_status;
    bool delayed_repair;
} coordinator_status;

extern volatile bool g_repairCn;
extern volatile uint g_restoreCn;
extern coordinator_status* g_cnStatus;
extern bool* g_coordinatorsDrop;
extern pthread_rwlock_t g_cnDropLock;
extern uint32* g_droppedCoordinatorId;
extern bool g_coordinatorsCancel;
extern pthread_rwlock_t g_coordinatorsCancelLock;
extern cm_instance_central_node_msg g_ccnNotify;

/* Control whether agent request cluster state */
extern bool g_poolerPingEndRequest;
/* Control whether agent close the pooler ping switch */
extern bool g_poolerPingEnd;

extern datanode_failover* g_datanodesFailover;
extern gtm_failover* g_gtmsFailover;
extern pthread_rwlock_t g_datanodesFailoverLock;
extern pthread_rwlock_t g_gtmsFailoverLock;
extern int g_gtmMode;
extern char *g_eventTriggers[EVENT_COUNT];
extern void ExecuteEventTrigger(const EventTriggerType triggerType, int32 staPrimId = -1);

extern int node_match_find(const char *node_type, const char *node_port, const char *node_host, const char *node_port1,
    const char *node_host1, int *node_index, int *instance_index, int *inode_type);
extern int check_one_instance_status(const char *processName, const char *cmdLine, int *isPhonyDead);
extern void report_conn_fail_alarm(AlarmType alarmType, InstanceTypes instance_type, uint32 instanceId);
extern int get_connection_to_coordinator();
#ifdef __aarch64__
void process_bind_cpu(uint32 instance_index, uint32 primary_dn_index, pgpid_t pid);
#endif
uint32 GetLibcommPort(const char* file_path, uint32 base_port, int port_type);
#endif
