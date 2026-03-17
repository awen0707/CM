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
 * cm_misc.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_common/cm_misc.cpp
 *
 * -------------------------------------------------------------------------
 */
#include <sys/types.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>
#include <limits.h>
#include <sys/procfs.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "openssl/x509.h"
#include "openssl/hmac.h"
#include "openssl/rand.h"
#include "cjson/cJSON.h"

#include "cm/cm_elog.h"
#include "cm/cm_c.h"
#include "cm/stringinfo.h"
#include "cm/cm_msg.h"
#include "common/config/cm_config.h"
#include "cm/cm_cipher.h"
#include "cm/cm_misc.h"
#include "cm/cm_ip.h"

/*
 * ssh connect does not exit automatically when the network is fault,
 * this will cause cm_ctl hang for several hours,
 * so we should add the following timeout options for ssh.
 */
#define SSH_CONNECT_TIMEOUT "5"
#define SSH_CONNECT_ATTEMPTS "3"
#define SSH_SERVER_ALIVE_INTERVAL "15"
#define SSH_SERVER_ALIVE_COUNT_MAX "3"
#define PSSH_TIMEOUT_OPTION                                                                        \
    " -t 60 -O ConnectTimeout=" SSH_CONNECT_TIMEOUT " -O ConnectionAttempts=" SSH_CONNECT_ATTEMPTS \
    " -O ServerAliveInterval=" SSH_SERVER_ALIVE_INTERVAL " -O ServerAliveCountMax=" SSH_SERVER_ALIVE_COUNT_MAX " "

conn_option_t g_sslOption;

#define SSL_CONNECT_TIMEOUT (5000)
#define SSL_SOCKET_TIMEOUT (5000)

/* two nodes arch usage */
ArbitrateParamsOn2Nodes g_paramsOn2Nodes = {"", false, false, 20};
static const int VAILD_IP_ADDR = 1;

bool CmFileExist(const char *file_path)
{
    int32 ret;
#ifdef WIN32
    struct _stat stat_buf;
#else
    struct stat stat_buf;
#endif

#ifdef WIN32
    ret = _stat(file_path, &stat_buf);
#else
    ret = stat(file_path, &stat_buf);
#endif
    if (ret != 0) {
        return false;
    }

#ifdef WIN32
    if (_S_IFREG == (stat_buf.st_mode & _S_IFREG)) {
#else
    /* S_ISREG: judge whether it's a regular file or not by the flag */
    if (S_ISREG(stat_buf.st_mode)) {
#endif
        return true;
    }

    return false;
}

void GetRealFile(char *realFile, uint32 fileLen, const char *path)
{
    errno_t rc = strcpy_s(realFile, fileLen, path);
    securec_check_errno(rc, (void)rc);
    check_input_for_security(realFile);
    canonicalize_path(realFile);
}

void *CmMalloc(size_t size)
{
    if (size == 0) {
        write_runlog(FATAL, "[CmMalloc] malloc 0.\n");
        exit(1);
    }
    void *result = malloc(size);
    if (result == NULL) {
        write_runlog(FATAL, "[CmMalloc] malloc failed, out of memory.\n");
        exit(1);
    }
    errno_t rc = memset_s(result, size, 0, size);
    securec_check_errno(rc, (void)rc);

    return result;
}

char** CmReadfile(const char* path)
{
    char** result;
    struct stat statbuf = {0};
    errno_t rc;

    /*
     * We expect there to be a newline after each full line, including one at the end of file.
     * If there isn't a newline at the end, any characters after the last newline will be ignored.
     */
    int fd = open(path, O_RDONLY | PG_BINARY | O_CLOEXEC, 0);
    if (fd < 0) {
        return NULL;
    }
    if (fstat(fd, &statbuf) < 0) {
        (void)close(fd);
        return NULL;
    }
    if (statbuf.st_size == 0) {
        (void)close(fd);
        return NULL;
    }
    char* buffer = (char*)CmMalloc(statbuf.st_size + 1);
    ssize_t len = read(fd, buffer, uint32(statbuf.st_size + 1));
    (void)close(fd);
    if (len != statbuf.st_size) {
        FREE_AND_RESET(buffer);
        return NULL;
    }

    int nlines = 0;
    for (int i = 0; i < len; i++) {
        if (buffer[i] == '\n') {
            nlines++;
        }
    }

    result = (char**)CmMalloc((size_t)(nlines + 1) * sizeof(char*));
    char* linebegin = buffer;
    int idx = 0;
    for (int i = 0; i < len; i++) {
        if (buffer[i] == '\n') {
            size_t slen = size_t(&buffer[i] - linebegin) + 1;
            char* linebuf = (char*)CmMalloc(slen + 1);
            rc = memcpy_s(linebuf, slen + 1, linebegin, slen);
            securec_check_errno(rc, (void)rc);
            linebuf[slen] = '\0';
            result[idx++] = linebuf;
            linebegin = &buffer[i + 1];
        }
    }
    result[idx] = NULL;
    FREE_AND_RESET(buffer);
    return result;
}

void freefile(char** lines)
{
    if (lines == NULL) {
        return;
    }
    char **line = lines;
    while (*line != NULL) {
        FREE_AND_RESET(*line);
        line++;
    }
    free(lines);
}

log_level_string log_level_map_string[] = {

    {"DEBUG5", DEBUG5},
    {"DEBUG1", DEBUG1},
    {"WARNING", WARNING},
    {"LOG", LOG},
    {"ERROR", ERROR},
    {"FATAL", FATAL},
    {NULL, UNKNOWN_LEVEL}

};

int log_level_string_to_int(const char* log_level)
{
    int i;
    for (i = 0; log_level_map_string[i].level_string != NULL; i++) {
        if (strcasecmp(log_level_map_string[i].level_string, log_level) == 0) {
            return log_level_map_string[i].level_val;
        }
    }
    return UNKNOWN_LEVEL;
}

const char* log_level_int_to_string(int log_level)
{
    int i;
    for (i = 0; log_level_map_string[i].level_string != NULL; i++) {
        if (log_level_map_string[i].level_val == log_level) {
            return log_level_map_string[i].level_string;
        }
    }
    return "Unknown";
}

const char* DcfRoleToString(int role)
{
    switch (role) {
        case DCF_ROLE_LEADER:
            return "LEADER";
        case DCF_ROLE_FOLLOWER:
            return "FOLLOWER";
        case DCF_ROLE_LOGGER:
            return "LOGGER";
        case DCF_ROLE_PASSIVE:
            return "PASSIVE";
        case DCF_ROLE_PRE_CANDIDATE:
            return "PRE_CANDIDATE";
        case DCF_ROLE_CANDIDATE:
            return "CANDIDATE";
        default:
            return "UNKNOWN";
    }
}

instance_datanode_build_reason_string datanode_build_reason_map_string[] = {

    {"Normal", INSTANCE_HA_DATANODE_BUILD_REASON_NORMAL},
    {"WAL segment removed", INSTANCE_HA_DATANODE_BUILD_REASON_WALSEGMENT_REMOVED},
    {"Disconnected", INSTANCE_HA_DATANODE_BUILD_REASON_DISCONNECT},
    {"Version not matched", INSTANCE_HA_DATANODE_BUILD_REASON_VERSION_NOT_MATCHED},
    {"Mode not matched", INSTANCE_HA_DATANODE_BUILD_REASON_MODE_NOT_MATCHED},
    {"System id not matched", INSTANCE_HA_DATANODE_BUILD_REASON_SYSTEMID_NOT_MATCHED},
    {"Timeline not matched", INSTANCE_HA_DATANODE_BUILD_REASON_TIMELINE_NOT_MATCHED},
    {"DCF log loss", INSTANCE_HA_DATANODE_BUILD_REASON_DCF_LOG_LOSS},
    {"Unknown", INSTANCE_HA_DATANODE_BUILD_REASON_UNKNOWN},
    {"User/Password invalid", INSTANCE_HA_DATANODE_BUILD_REASON_USER_PASSWD_INVALID},
    {"Connecting", INSTANCE_HA_DATANODE_BUILD_REASON_CONNECTING},
    {NULL, INSTANCE_HA_DATANODE_BUILD_REASON_UNKNOWN}

};

int datanode_rebuild_reason_string_to_int(const char* reason)
{
    int i;

    for (i = 0; datanode_build_reason_map_string[i].reason_string != NULL; i++) {
        if (strstr(reason, datanode_build_reason_map_string[i].reason_string) != NULL) {
            return datanode_build_reason_map_string[i].reason_val;
        }
    }

    return INSTANCE_HA_DATANODE_BUILD_REASON_UNKNOWN;
}

const char* datanode_rebuild_reason_int_to_string(int reason)
{
    int i;

    for (i = 0; datanode_build_reason_map_string[i].reason_string != NULL; i++) {
        if (datanode_build_reason_map_string[i].reason_val == reason) {
            return datanode_build_reason_map_string[i].reason_string;
        }
    }
    return "Unknown";
}

instacne_type_string type_map_string[] = {

    {"GTM", INSTANCE_TYPE_GTM},
    {"Datanode", INSTANCE_TYPE_DATANODE},
    {"Coordinator", INSTANCE_TYPE_COORDINATE},
    {"Fenced UDF", INSTANCE_TYPE_FENCED_UDF},
    {NULL, INSTANCE_TYPE_UNKNOWN}};

const char* type_int_to_string(int type)
{
    int i;
    for (i = 0; type_map_string[i].type_string != NULL; i++) {
        if (type_map_string[i].type_val == type) {
            return type_map_string[i].type_string;
        }
    }
    return "Unknown";
}

const char *type_int_to_str_ss_double(SSDoubleClusterMode ss_double_type)
{
    switch (ss_double_type) {
        case SS_DOUBLE_PRIMARY:
            return "cluster_primary";
        case SS_DOUBLE_STANDBY:
            return "cluster_standby";
        case SS_DOUBLE_NULL:
            return "cluster_normal";
    }
    return "unknown";
}

gtm_con_string gtm_con_map_string[] = {{"Connection ok", CON_OK},
    {"Connection bad", CON_BAD},
    {"Connection started", CON_STARTED},
    {"Connection made", CON_MADE},
    {"Connection awaiting response", CON_AWAITING_RESPONSE},
    {"Connection authentication ok", CON_AUTH_OK},
    {"Connection prepare environment", CON_SETEN},
    {"Connection prepare SSL", CON_SSL_STARTUP},
    {"Connection needed", CON_NEEDED},
    {"Unknown", CON_UNKNOWN},
    {"Manually stopped", CON_MANUAL_STOPPED},
    {"Disk damaged", CON_DISK_DEMAGED},
    {"Port conflicting", CON_PORT_USED},
    {"Nic down", CON_NIC_DOWN},
    {"Starting", CON_GTM_STARTING},
    {NULL, CON_UNKNOWN}};

const char* gtm_con_int_to_string(int con)
{
    int i;
    for (i = 0; gtm_con_map_string[i].con_string != NULL; i++) {
        if (gtm_con_map_string[i].con_val == con) {
            return gtm_con_map_string[i].con_string;
        }
    }
    return "Unknown";
}

server_role_string server_role_string_map[] = {{CM_SERVER_UNKNOWN, "UNKNOWN"},
    {CM_SERVER_PRIMARY, "Primary"},
    {CM_SERVER_STANDBY, "Standby"},
    {CM_SERVER_INIT, "Init"},
    {CM_SERVER_DOWN, "Down"}};

server_role_string etcd_role_string_map[] = {{CM_ETCD_UNKNOWN, "UNKNOWN"},
    {CM_ETCD_FOLLOWER, "StateFollower"},
    {CM_ETCD_LEADER, "StateLeader"},
    {CM_ETCD_DOWN, "Down"}};

server_role_string kerberos_role_string_map[] = {{KERBEROS_STATUS_UNKNOWN, "UNKNOWN"},
    {KERBEROS_STATUS_NORMAL, "Normal"},
    {KERBEROS_STATUS_ABNORMAL, "Abnormal"},
    {KERBEROS_STATUS_DOWN, "Down"}};

DbStateRoleString g_dbStaticRoleMap[] = {{INSTANCE_ROLE_INIT, '0'},
    {INSTANCE_ROLE_PRIMARY, '1'},
    {INSTANCE_ROLE_STANDBY, '2'},
    {INSTANCE_ROLE_PENDING, '3'},
    {INSTANCE_ROLE_NORMAL, '4'},
    {INSTANCE_ROLE_UNKNOWN, '5'},
    {INSTANCE_ROLE_DUMMY_STANDBY, '6'},
    {INSTANCE_ROLE_DELETED, '7'},
    {INSTANCE_ROLE_DELETING, '8'},
    {INSTANCE_ROLE_READONLY, '9'},
    {INSTANCE_ROLE_OFFLINE, 'A'},
    {INSTANCE_ROLE_MAIN_STANDBY, 'B'},
    {INSTANCE_ROLE_CASCADE_STANDBY, 'C'},
    {INSTANCE_ROLE_END, '\0'}};

char GetDbStaticRoleStr(int32 role)
{
    if (role < INSTANCE_ROLE_INIT || role >= INSTANCE_ROLE_END) {
        return '\0';
    }
    return g_dbStaticRoleMap[role].roleString;
}

int32 GetDbStaticRoleInt(char c)
{
    if (c == '\0') {
        return INSTANCE_ROLE_END;
    }
    for (int32 i = 0; g_dbStaticRoleMap[i].roleString != '\0'; ++i) {
        if (c == g_dbStaticRoleMap[i].roleString) {
            return i;
        }
    }
    return INSTANCE_ROLE_END;
}

const char* etcd_role_to_string(int role)
{
    if (role <= CM_ETCD_UNKNOWN || role > CM_ETCD_DOWN) {
        return etcd_role_string_map[CM_ETCD_UNKNOWN].role_string;
    } else {
        return etcd_role_string_map[role].role_string;
    }
}

const char* server_role_to_string(int role)
{
    if (role <= CM_SERVER_UNKNOWN || role >= CM_SERVER_INIT) {
        return "Unknown";
    } else {
        return server_role_string_map[role].role_string;
    }
}

instance_datanode_lockmode_string g_datanode_lockmode_map_string[] = {{"polling_connection", POLLING_CONNECTION},
    {"specify_connection", SPECIFY_CONNECTION},
    {"prohibit_connection", PROHIBIT_CONNECTION},
    {"pre_prohibit_connection", PRE_PROHIBIT_CONNECTION},
    {NULL, UNDEFINED_LOCKMODE}};

uint32 datanode_lockmode_string_to_int(const char* lockmode)
{
    int i;
    if (lockmode == NULL || strlen(lockmode) == 0) {
        write_runlog(ERROR, "datanode_lockmode_string_to_int failed, input string role is: NULL\n");
        return UNDEFINED_LOCKMODE;
    } else {
        for (i = 0; g_datanode_lockmode_map_string[i].lockmode_string != NULL; i++) {
            if (strncmp(g_datanode_lockmode_map_string[i].lockmode_string, lockmode, strlen(lockmode)) == 0) {
                return g_datanode_lockmode_map_string[i].lockmode_val;
            }
        }
    }
    write_runlog(ERROR, "datanode_lockmode_string_to_int failed, input lockmode is: (%s)\n", lockmode);
    return UNDEFINED_LOCKMODE;
}

const char *DatanodeLockmodeIntToString(uint32 lockmode)
{
    for (int32 i = 0; g_datanode_lockmode_map_string[i].lockmode_string != NULL; ++i) {
        if (lockmode == g_datanode_lockmode_map_string[i].lockmode_val) {
            return g_datanode_lockmode_map_string[i].lockmode_string;
        }
    }
    return "Undefined_lockmode";
}

instacne_datanode_role_string datanode_role_map_string[] = {

    {"Primary", INSTANCE_ROLE_PRIMARY},
    {"Standby", INSTANCE_ROLE_STANDBY},
    {"Pending", INSTANCE_ROLE_PENDING},
    {"Normal", INSTANCE_ROLE_NORMAL},
    {"Down", INSTANCE_ROLE_UNKNOWN},
    {"Secondary", INSTANCE_ROLE_DUMMY_STANDBY},
    {"Deleted", INSTANCE_ROLE_DELETED},
    {"ReadOnly", INSTANCE_ROLE_READONLY},
    {"Offline", INSTANCE_ROLE_OFFLINE},
    {"Main Standby", INSTANCE_ROLE_MAIN_STANDBY},
    {"Cascade Standby", INSTANCE_ROLE_CASCADE_STANDBY},
    {NULL, INSTANCE_ROLE_UNKNOWN}};

int datanode_role_string_to_int(const char* role)
{
    int i;
    if (role == NULL) {
        write_runlog(ERROR, "datanode_role_string_to_int failed, input string role is: NULL\n");
        return INSTANCE_ROLE_UNKNOWN;
    }
    for (i = 0; datanode_role_map_string[i].role_string != NULL; i++) {
        if (strcmp(datanode_role_map_string[i].role_string, role) == 0) {
            return (int)datanode_role_map_string[i].role_val;
        }
    }
    write_runlog(ERROR, "datanode_role_string_to_int failed, input string role is: (%s)\n", role);
    return INSTANCE_ROLE_UNKNOWN;
}

const char* datanode_role_int_to_string(int role)
{
    int i;
    for (i = 0; datanode_role_map_string[i].role_string != NULL; i++) {
        if ((int)datanode_role_map_string[i].role_val == role) {
            return datanode_role_map_string[i].role_string;
        }
    }
    return "Unknown";
}

instacne_datanode_role_string datanode_static_role_map_string[] = {{"P", PRIMARY_DN},
    {"S", STANDBY_DN},
    {"R", DUMMY_STANDBY_DN},
    {"C", CASCADE_STANDBY_DN},
    {NULL, INSTANCE_ROLE_NORMAL}};

const char* datanode_static_role_int_to_string(uint32 role)
{
    int i;
    for (i = 0; datanode_static_role_map_string[i].role_string != NULL; i++) {
        if (datanode_static_role_map_string[i].role_val == role) {
            return datanode_static_role_map_string[i].role_string;
        }
    }
    return "Unknown";
}

instacne_datanode_dbstate_string datanode_dbstate_map_string[] = {{"Unknown", INSTANCE_HA_STATE_UNKONWN},
    {"Normal", INSTANCE_HA_STATE_NORMAL},
    {"Need repair", INSTANCE_HA_STATE_NEED_REPAIR},
    {"Starting", INSTANCE_HA_STATE_STARTING},
    {"Wait promoting", INSTANCE_HA_STATE_WAITING},
    {"Demoting", INSTANCE_HA_STATE_DEMOTING},
    {"Promoting", INSTANCE_HA_STATE_PROMOTING},
    {"Building", INSTANCE_HA_STATE_BUILDING},
    {"Manually stopped", INSTANCE_HA_STATE_MANUAL_STOPPED},
    {"Disk damaged", INSTANCE_HA_STATE_DISK_DAMAGED},
    {"Port conflicting", INSTANCE_HA_STATE_PORT_USED},
    {"Build failed", INSTANCE_HA_STATE_BUILD_FAILED},
    {"Catchup", INSTANCE_HA_STATE_CATCH_UP},
    {"CoreDump", INSTANCE_HA_STATE_COREDUMP},
    {"ReadOnly", INSTANCE_HA_STATE_READ_ONLY},
    {NULL, INSTANCE_ROLE_NORMAL}};

int datanode_dbstate_string_to_int(const char* dbstate)
{
    int i;
    if (dbstate == NULL) {
        write_runlog(ERROR, "datanode_dbstate_string_to_int failed, input string dbstate is: NULL\n");
        return INSTANCE_HA_STATE_UNKONWN;
    }
    for (i = 0; datanode_dbstate_map_string[i].dbstate_string != NULL; i++) {
        if (strcmp(datanode_dbstate_map_string[i].dbstate_string, dbstate) == 0) {
            return datanode_dbstate_map_string[i].dbstate_val;
        }
    }
    write_runlog(ERROR, "datanode_dbstate_string_to_int failed, input string dbstate is: (%s)\n", dbstate);
    return INSTANCE_HA_STATE_UNKONWN;
}

const char* datanode_dbstate_int_to_string(int dbstate)
{
    int i;
    for (i = 0; datanode_dbstate_map_string[i].dbstate_string != NULL; i++) {
        if (datanode_dbstate_map_string[i].dbstate_val == dbstate) {
            return datanode_dbstate_map_string[i].dbstate_string;
        }
    }
    return "Unknown";
}

instacne_datanode_wal_send_state_string datanode_wal_send_state_map_string[] = {
    {"Startup", INSTANCE_WALSNDSTATE_STARTUP},
    {"Backup", INSTANCE_WALSNDSTATE_BACKUP},
    {"Catchup", INSTANCE_WALSNDSTATE_CATCHUP},
    {"Streaming", INSTANCE_WALSNDSTATE_STREAMING},
    {"Dump syslog", INSTANCE_WALSNDSTATE_DUMPLOG},
    {"Normal", INSTANCE_WALSNDSTATE_NORMAL},
    {"Unknown", INSTANCE_WALSNDSTATE_UNKNOWN},
    {NULL, INSTANCE_WALSNDSTATE_UNKNOWN}};

int datanode_wal_send_state_string_to_int(const char* dbstate)
{
    int i;
    if (dbstate == NULL) {
        write_runlog(ERROR, "datanode_wal_send_state_string_to_int failed, input string dbstate is: NULL\n");
        return INSTANCE_WALSNDSTATE_UNKNOWN;
    }
    for (i = 0; datanode_wal_send_state_map_string[i].wal_send_state_string != NULL; i++) {
        if (strcmp(datanode_wal_send_state_map_string[i].wal_send_state_string, dbstate) == 0) {
            return datanode_wal_send_state_map_string[i].wal_send_state_val;
        }
    }
    write_runlog(ERROR, "datanode_wal_send_state_string_to_int failed, input string dbstate is: (%s)\n", dbstate);
    return INSTANCE_WALSNDSTATE_UNKNOWN;
}

const char* datanode_wal_send_state_int_to_string(int dbstate)
{
    int i;
    for (i = 0; datanode_wal_send_state_map_string[i].wal_send_state_string != NULL; i++) {
        if (datanode_wal_send_state_map_string[i].wal_send_state_val == dbstate) {
            return      datanode_wal_send_state_map_string[i].wal_send_state_string;
        }
    }
    return "Unknown";
}

instacne_datanode_sync_state_string datanode_wal_sync_state_map_string[] = {{"Async", INSTANCE_DATA_REPLICATION_ASYNC},
    {"Sync", INSTANCE_DATA_REPLICATION_SYNC},
    {"Most available", INSTANCE_DATA_REPLICATION_MOST_AVAILABLE},
    {"Potential", INSTANCE_DATA_REPLICATION_POTENTIAL_SYNC},
    {"Quorum", INSTANCE_DATA_REPLICATION_QUORUM},
    {NULL, INSTANCE_DATA_REPLICATION_UNKONWN}};

int datanode_wal_sync_state_string_to_int(const char* dbstate)
{
    int i;
    if (dbstate == NULL) {
        write_runlog(ERROR, "datanode_wal_sync_state_string_to_int failed, input string dbstate is: NULL\n");
        return INSTANCE_DATA_REPLICATION_UNKONWN;
    }
    for (i = 0; datanode_wal_sync_state_map_string[i].wal_sync_state_string != NULL; i++) {
        if (strcmp(datanode_wal_sync_state_map_string[i].wal_sync_state_string, dbstate) == 0) {
            return datanode_wal_sync_state_map_string[i].wal_sync_state_val;
        }
    }
    write_runlog(ERROR, "datanode_wal_sync_state_string_to_int failed, input string dbstate is: (%s)\n", dbstate);
    return INSTANCE_DATA_REPLICATION_UNKONWN;
}

const char* datanode_wal_sync_state_int_to_string(int dbstate)
{
    int i;
    for (i = 0; datanode_wal_sync_state_map_string[i].wal_sync_state_string != NULL; i++) {
        if (datanode_wal_sync_state_map_string[i].wal_sync_state_val == dbstate) {
            return datanode_wal_sync_state_map_string[i].wal_sync_state_string;
        }
    }
    return "Unknown";
}

cluster_state_string cluster_state_map_string[] = {
    {"Starting", CM_STATUS_STARTING},
    {"Redistributing", CM_STATUS_PENDING},
    {"Normal", CM_STATUS_NORMAL},
    {"Unavailable", CM_STATUS_NEED_REPAIR},
    {"Degraded", CM_STATUS_DEGRADE},
    {"Unknown", CM_STATUS_UNKNOWN},
    {"NormalCNDeleted", CM_STATUS_NORMAL_WITH_CN_DELETED},
    {NULL, CM_STATUS_UNKNOWN},
};

const char* cluster_state_int_to_string(int cluster_state)
{
    int i;
    for (i = 0; cluster_state_map_string[i].cluster_state_string != NULL; i++) {
        if (cluster_state_map_string[i].cluster_state_val == cluster_state) {
            return cluster_state_map_string[i].cluster_state_string;
        }
    }
    return "Unknown";
}

/* this map should be sync with CM_MessageType in cm_msg.h file. */
cluster_msg_string cluster_msg_map_string[] = {

    {"MSG_CTL_CM_SWITCHOVER", MSG_CTL_CM_SWITCHOVER},
    {"MSG_CTL_CM_BUILD", MSG_CTL_CM_BUILD},
    {"MSG_CTL_CM_SYNC", MSG_CTL_CM_SYNC},
    {"MSG_CTL_CM_QUERY", MSG_CTL_CM_QUERY},
    {"MSG_CTL_CM_NOTIFY", MSG_CTL_CM_NOTIFY},
    {"MSG_CTL_CM_BUTT", MSG_CTL_CM_BUTT},
    {"MSG_CM_CTL_DATA_BEGIN", MSG_CM_CTL_DATA_BEGIN},
    {"MSG_CM_CTL_DATA", MSG_CM_CTL_DATA},
    {"MSG_CM_CTL_NODE_END", MSG_CM_CTL_NODE_END},
    {"MSG_CM_CTL_DATA_END", MSG_CM_CTL_DATA_END},
    {"MSG_CM_CTL_COMMAND_ACK", MSG_CM_CTL_COMMAND_ACK},

    {"MSG_CM_AGENT_SWITCHOVER", MSG_CM_AGENT_SWITCHOVER},
    {"MSG_CM_AGENT_FAILOVER", MSG_CM_AGENT_FAILOVER},
    {"MSG_CM_AGENT_BUILD", MSG_CM_AGENT_BUILD},
    {"MSG_CM_AGENT_SYNC", MSG_CM_AGENT_SYNC},
    {"MSG_CM_AGENT_NOTIFY", MSG_CM_AGENT_NOTIFY},
    {"MSG_CM_AGENT_NOTIFY_CN", MSG_CM_AGENT_NOTIFY_CN},
    {"MSG_CM_AGENT_NOTIFY_CN_CENTRAL_NODE", MSG_CM_AGENT_NOTIFY_CN_CENTRAL_NODE},
    {"MSG_AGENT_CM_NOTIFY_CN_FEEDBACK", MSG_AGENT_CM_NOTIFY_CN_FEEDBACK},
    {"MSG_CM_AGENT_DROP_CN", MSG_CM_AGENT_DROP_CN},
    {"MSG_CM_AGENT_CANCEL_SESSION", MSG_CM_AGENT_CANCEL_SESSION},
    {"MSG_CM_AGENT_DROPPED_CN", MSG_CM_AGENT_DROPPED_CN},
    {"MSG_CM_AGENT_RESTART", MSG_CM_AGENT_RESTART},
    {"MSG_CM_AGENT_RESTART_BY_MODE", MSG_CM_AGENT_RESTART_BY_MODE},
    {"MSG_CM_AGENT_REP_SYNC", MSG_CM_AGENT_REP_SYNC},
    {"MSG_CM_AGENT_REP_ASYNC", MSG_CM_AGENT_REP_ASYNC},
    {"MSG_CM_AGENT_REP_MOST_AVAILABLE", MSG_CM_AGENT_REP_MOST_AVAILABLE},
    {"MSG_CM_AGENT_MODIFY_MOST_AVAILABLE", MSG_CM_AGENT_MODIFY_MOST_AVAILABLE},
    {"MSG_CM_AGENT_BUTT", MSG_CM_AGENT_BUTT},

    {"MSG_AGENT_CM_DATA_INSTANCE_REPORT_STATUS", MSG_AGENT_CM_DATA_INSTANCE_REPORT_STATUS},
    {"MSG_AGENT_CM_COORDINATE_INSTANCE_STATUS", MSG_AGENT_CM_COORDINATE_INSTANCE_STATUS},
    {"MSG_AGENT_CM_GTM_INSTANCE_STATUS", MSG_AGENT_CM_GTM_INSTANCE_STATUS},
    {"MSG_AGENT_CM_FENCED_UDF_INSTANCE_STATUS", MSG_AGENT_CM_FENCED_UDF_INSTANCE_STATUS},
    {"MSG_AGENT_CM_BUTT", MSG_AGENT_CM_BUTT},

    {"MSG_CM_CM_VOTE", MSG_CM_CM_VOTE},
    {"MSG_CM_CM_BROADCAST", MSG_CM_CM_BROADCAST},
    {"MSG_CM_CM_NOTIFY", MSG_CM_CM_NOTIFY},
    {"MSG_CM_CM_SWITCHOVER", MSG_CM_CM_SWITCHOVER},
    {"MSG_CM_CM_FAILOVER", MSG_CM_CM_FAILOVER},
    {"MSG_CM_CM_SYNC", MSG_CM_CM_SYNC},
    {"MSG_CM_CM_SWITCHOVER_ACK", MSG_CM_CM_SWITCHOVER_ACK},
    {"MSG_CM_CM_FAILOVER_ACK", MSG_CM_CM_FAILOVER_ACK},
    {"MSG_CM_CM_ROLE_CHANGE_NOTIFY", MSG_CM_CM_ROLE_CHANGE_NOTIFY},
    {"MSG_CM_CM_REPORT_SYNC", MSG_CM_CM_REPORT_SYNC},

    {"MSG_AGENT_CM_HEARTBEAT", MSG_AGENT_CM_HEARTBEAT},
    {"MSG_CM_AGENT_HEARTBEAT", MSG_CM_AGENT_HEARTBEAT},
    {"MSG_CTL_CM_SET", MSG_CTL_CM_SET},
    {"MSG_CTL_CM_SWITCHOVER_ALL", MSG_CTL_CM_SWITCHOVER_ALL},
    {"MSG_CM_CTL_SWITCHOVER_ALL_ACK", MSG_CM_CTL_SWITCHOVER_ALL_ACK},
    {"MSG_CTL_CM_BALANCE_CHECK", MSG_CTL_CM_BALANCE_CHECK},
    {"MSG_CM_CTL_BALANCE_CHECK_ACK", MSG_CM_CTL_BALANCE_CHECK_ACK},
    {"MSG_CTL_CM_BALANCE_RESULT", MSG_CTL_CM_BALANCE_RESULT},
    {"MSG_CM_CTL_BALANCE_RESULT_ACK", MSG_CM_CTL_BALANCE_RESULT_ACK},
    {"MSG_CTL_CM_QUERY_CMSERVER", MSG_CTL_CM_QUERY_CMSERVER},
    {"MSG_CM_CTL_CMSERVER", MSG_CM_CTL_CMSERVER},
    {"MSG_TYPE_BUTT", MSG_TYPE_BUTT},
    {"MSG_CTL_CM_SWITCHOVER_FULL", MSG_CTL_CM_SWITCHOVER_FULL},
    {"MSG_CM_CTL_SWITCHOVER_FULL_ACK", MSG_CM_CTL_SWITCHOVER_FULL_ACK},
    {"MSG_CM_CTL_SWITCHOVER_FULL_DENIED", MSG_CM_CTL_SWITCHOVER_FULL_DENIED},
    {"MSG_CTL_CM_SWITCHOVER_FULL_CHECK", MSG_CTL_CM_SWITCHOVER_FULL_CHECK},
    {"MSG_CM_CTL_SWITCHOVER_FULL_CHECK_ACK", MSG_CM_CTL_SWITCHOVER_FULL_CHECK_ACK},
    {"MSG_CTL_CM_SWITCHOVER_FULL_TIMEOUT", MSG_CTL_CM_SWITCHOVER_FULL_TIMEOUT},
    {"MSG_CM_CTL_SWITCHOVER_FULL_TIMEOUT_ACK", MSG_CM_CTL_SWITCHOVER_FULL_TIMEOUT_ACK},
    {"MSG_CTL_CM_SETMODE", MSG_CTL_CM_SETMODE},
    {"MSG_CM_CTL_SETMODE_ACK", MSG_CM_CTL_SETMODE_ACK},

    {"MSG_CTL_CM_SWITCHOVER_AZ", MSG_CTL_CM_SWITCHOVER_AZ},
    {"MSG_CM_CTL_SWITCHOVER_AZ_ACK", MSG_CM_CTL_SWITCHOVER_AZ_ACK},
    {"MSG_CM_CTL_SWITCHOVER_AZ_DENIED", MSG_CM_CTL_SWITCHOVER_AZ_DENIED},
    {"MSG_CTL_CM_SWITCHOVER_AZ_CHECK", MSG_CTL_CM_SWITCHOVER_AZ_CHECK},
    {"MSG_CM_CTL_SWITCHOVER_AZ_CHECK_ACK", MSG_CM_CTL_SWITCHOVER_AZ_CHECK_ACK},
    {"MSG_CTL_CM_SWITCHOVER_AZ_TIMEOUT", MSG_CTL_CM_SWITCHOVER_AZ_TIMEOUT},
    {"MSG_CM_CTL_SWITCHOVER_AZ_TIMEOUT_ACK", MSG_CM_CTL_SWITCHOVER_AZ_TIMEOUT_ACK},

    {"MSG_CM_CTL_SET_ACK", MSG_CM_CTL_SET_ACK},
    {"MSG_CTL_CM_GET", MSG_CTL_CM_GET},
    {"MSG_CM_CTL_GET_ACK", MSG_CM_CTL_GET_ACK},

    {"MSG_CM_AGENT_GS_GUC", MSG_CM_AGENT_GS_GUC},
    {"MSG_AGENT_CM_GS_GUC_ACK", MSG_AGENT_CM_GS_GUC_ACK},
    {"MSG_CM_CTL_SWITCHOVER_INCOMPLETE_ACK", MSG_CM_CTL_SWITCHOVER_INCOMPLETE_ACK},
    {"MSG_CM_CM_TIMELINE", MSG_CM_CM_TIMELINE},
    {"MSG_CM_BUILD_DOING", MSG_CM_BUILD_DOING},
    {"MSG_AGENT_CM_ETCD_CURRENT_TIME", MSG_AGENT_CM_ETCD_CURRENT_TIME},
    {"MSG_CM_QUERY_INSTANCE_STATUS", MSG_CM_QUERY_INSTANCE_STATUS},
    {"MSG_CM_SERVER_TO_AGENT_CONN_CHECK", MSG_CM_SERVER_TO_AGENT_CONN_CHECK},
    {"MSG_CTL_CM_GET_DATANODE_RELATION", MSG_CTL_CM_GET_DATANODE_RELATION},
    {"MSG_CM_BUILD_DOWN", MSG_CM_BUILD_DOWN},
    {"MSG_CM_SERVER_REPAIR_CN_ACK", MSG_CM_SERVER_REPAIR_CN_ACK},
    {"MSG_CTL_CM_SETMODE", MSG_CTL_CM_DISABLE_CN},
    {"MSG_CM_CTL_SETMODE_ACK", MSG_CTL_CM_DISABLE_CN_ACK},
    {"MSG_CM_AGENT_LOCK_NO_PRIMARY", MSG_CM_AGENT_LOCK_NO_PRIMARY},
    {"MSG_CM_AGENT_LOCK_CHOSEN_PRIMARY", MSG_CM_AGENT_LOCK_CHOSEN_PRIMARY},
    {"MSG_CM_AGENT_UNLOCK", MSG_CM_AGENT_UNLOCK},
    {"MSG_CTL_CM_STOP_ARBITRATION", MSG_CTL_CM_STOP_ARBITRATION},
    {"MSG_CTL_CM_FINISH_REDO", MSG_CTL_CM_FINISH_REDO},
    {"MSG_CM_CTL_FINISH_REDO_ACK", MSG_CM_CTL_FINISH_REDO_ACK},
    {"MSG_CM_AGENT_FINISH_REDO", MSG_CM_AGENT_FINISH_REDO},
    {"MSG_CTL_CM_FINISH_REDO_CHECK", MSG_CTL_CM_FINISH_REDO_CHECK},
    {"MSG_CM_CTL_FINISH_REDO_CHECK_ACK", MSG_CM_CTL_FINISH_REDO_CHECK_ACK},
    {"MSG_AGENT_CM_KERBEROS_STATUS", MSG_AGENT_CM_KERBEROS_STATUS},
    {"MSG_CTL_CM_QUERY_KERBEROS", MSG_CTL_CM_QUERY_KERBEROS},
    {"MSG_CTL_CM_QUERY_KERBEROS_ACK", MSG_CTL_CM_QUERY_KERBEROS_ACK},
    {"MSG_AGENT_CM_DISKUSAGE_STATUS", MSG_AGENT_CM_DISKUSAGE_STATUS},
    {"MSG_CM_AGENT_OBS_DELETE_XLOG", MSG_CM_AGENT_OBS_DELETE_XLOG},
    {"MSG_CM_AGENT_DROP_CN_OBS_XLOG", MSG_CM_AGENT_DROP_CN_OBS_XLOG},
    {"MSG_AGENT_CM_DATANODE_INSTANCE_BARRIER", MSG_AGENT_CM_DATANODE_INSTANCE_BARRIER},
    {"MSG_CTL_CM_GLOBAL_BARRIER_QUERY", MSG_CTL_CM_GLOBAL_BARRIER_QUERY},
    {"MSG_AGENT_CM_COORDINATE_INSTANCE_BARRIER", MSG_AGENT_CM_COORDINATE_INSTANCE_BARRIER},
    {"MSG_CM_CTL_GLOBAL_BARRIER_DATA_BEGIN", MSG_CM_CTL_GLOBAL_BARRIER_DATA_BEGIN},
    {"MSG_CM_CTL_GLOBAL_BARRIER_DATA", MSG_CM_CTL_GLOBAL_BARRIER_DATA},
    {"MSG_CM_CTL_BARRIER_DATA_END", MSG_CM_CTL_BARRIER_DATA_END},
    {"MSG_CM_CTL_BACKUP_OPEN", MSG_CM_CTL_BACKUP_OPEN},
    {"MSG_CM_AGENT_DN_SYNC_LIST", MSG_CM_AGENT_DN_SYNC_LIST},
    {"MSG_AGENT_CM_DN_SYNC_LIST", MSG_AGENT_CM_DN_SYNC_LIST},
    {"MSG_AGENT_CM_DN_MOST_AVAILABLE", MSG_AGENT_CM_DN_MOST_AVAILABLE},
    {"MSG_CTL_CM_SWITCHOVER_FAST", MSG_CTL_CM_SWITCHOVER_FAST},
    {"MSG_CM_AGENT_SWITCHOVER_FAST", MSG_CM_AGENT_SWITCHOVER_FAST},
    {"MSG_CTL_CM_RELOAD", MSG_CTL_CM_RELOAD},
    {"MSG_CM_CTL_RELOAD_ACK", MSG_CM_CTL_RELOAD_ACK},
    {"MSG_CM_CTL_INVALID_COMMAND_ACK", MSG_CM_CTL_INVALID_COMMAND_ACK},
    {"MSG_AGENT_CM_CN_OBS_STATUS", MSG_AGENT_CM_CN_OBS_STATUS},
    {"MSG_CM_AGENT_NOTIFY_CN_RECOVER", MSG_CM_AGENT_NOTIFY_CN_RECOVER},
    {"MSG_CM_AGENT_FULL_BACKUP_CN_OBS", MSG_CM_AGENT_FULL_BACKUP_CN_OBS},
    {"MSG_AGENT_CM_BACKUP_STATUS_ACK", MSG_AGENT_CM_BACKUP_STATUS_ACK},
    {"MSG_CM_AGENT_REFRESH_OBS_DEL_TEXT", MSG_CM_AGENT_REFRESH_OBS_DEL_TEXT},
    {"MSG_AGENT_CM_INSTANCE_BARRIER_NEW", MSG_AGENT_CM_INSTANCE_BARRIER_NEW},
    {"MSG_CTL_CM_GLOBAL_BARRIER_QUERY_NEW", MSG_CTL_CM_GLOBAL_BARRIER_QUERY_NEW},
    {"MSG_CM_CTL_GLOBAL_BARRIER_DATA_BEGIN_NEW", MSG_CM_CTL_GLOBAL_BARRIER_DATA_BEGIN_NEW},
    {"MSG_AGENT_CM_RESOURCE_STATUS", MSG_AGENT_CM_RESOURCE_STATUS},
    {"MSG_CTL_CM_RESOURCE_STATUS", (int32)MSG_CTL_CM_RESOURCE_STATUS},
    {"MSG_CM_AGENT_RES_STATUS_LIST", MSG_CM_AGENT_RES_STATUS_LIST},
    {"MSG_CM_AGENT_RES_STATUS_CHANGED", MSG_CM_AGENT_RES_STATUS_CHANGED},
    {"MSG_CM_AGENT_SET_INSTANCE_DATA_STATUS", MSG_CM_AGENT_SET_INSTANCE_DATA_STATUS},
    {"MSG_CM_AGENT_REPORT_SET_STATUS", MSG_CM_AGENT_REPORT_SET_STATUS},
    {"MSG_CM_AGENT_REPORT_RES_DATA", MSG_CM_AGENT_REPORT_RES_DATA},
    {"MSG_AGENT_CM_REQUEST_RES_STATUS_LIST", MSG_AGENT_CM_REQUEST_RES_STATUS_LIST},
    {"MSG_AGENT_CM_GET_LATEST_STATUS_LIST", MSG_AGENT_CM_GET_LATEST_STATUS_LIST},
    {"MSG_AGENT_CM_SET_RES_DATA", MSG_AGENT_CM_SET_RES_DATA},
    {"MSG_AGENT_CM_GET_RES_DATA", MSG_AGENT_CM_GET_RES_DATA},
    {"MSG_CLIENT_AGENT_HEARTBEAT", MSG_CLIENT_AGENT_HEARTBEAT},
    {"MSG_CLIENT_AGENT_INIT_DATA", MSG_CLIENT_AGENT_INIT_DATA},
    {"MSG_CLIENT_AGENT_SET_DATA", MSG_CLIENT_AGENT_SET_DATA},
    {"MSG_CLIENT_AGENT_SET_RES_DATA", MSG_CLIENT_AGENT_SET_RES_DATA},
    {"MSG_CLIENT_AGENT_GET_RES_DATA", MSG_CLIENT_AGENT_GET_RES_DATA},
    {"MSG_AGENT_CLIENT_HEARTBEAT_ACK", MSG_AGENT_CLIENT_HEARTBEAT_ACK},
    {"MSG_AGENT_CLIENT_RES_STATUS_LIST", MSG_AGENT_CLIENT_RES_STATUS_LIST},
    {"MSG_AGENT_CLIENT_RES_STATUS_CHANGE", MSG_AGENT_CLIENT_RES_STATUS_CHANGE},
    {"MSG_AGENT_CLIENT_NOTIFY_CONN_CLOSE", MSG_AGENT_CLIENT_NOTIFY_CONN_CLOSE},
    {"MSG_AGENT_CLIENT_REPORT_RES_DATA", MSG_AGENT_CLIENT_REPORT_RES_DATA},
    {"MSG_EXEC_DDB_COMMAND", MSG_EXEC_DDB_COMMAND},
    {"EXEC_DDB_COMMAND_ACK", EXEC_DDB_COMMAND_ACK},
    {"MSG_CLIENT_CM_DDB_OPER", MSG_CLIENT_CM_DDB_OPER},
    {"MSG_CM_CLIENT_DDB_OPER_ACK", MSG_CM_CLIENT_DDB_OPER_ACK},
    {"MSG_CM_SSL_CONN_REQUEST", MSG_CM_SSL_CONN_REQUEST},
    {"MSG_CM_SSL_CONN_ACK", MSG_CM_SSL_CONN_ACK},
    {"MSG_CTL_CMS_SWITCH", (int32)MSG_CTL_CMS_SWITCH},
    {"MSG_CMS_CTL_SWITCH_ACK", (int32)MSG_CMS_CTL_SWITCH_ACK},
    {"MSG_CM_AGENT_DATANODE_INSTANCE_BARRIER", (int32)MSG_CM_AGENT_DATANODE_INSTANCE_BARRIER},
    {"MSG_CM_AGENT_COORDINATE_INSTANCE_BARRIER", (int32)MSG_CM_AGENT_COORDINATE_INSTANCE_BARRIER},
    {"MSG_AGENT_CM_DATANODE_LOCAL_PEER", (int32)MSG_AGENT_CM_DATANODE_LOCAL_PEER},
    {"MSG_GET_SHARED_STORAGE_INFO", (int32)MSG_GET_SHARED_STORAGE_INFO},
    {"MSG_GET_SHARED_STORAGE_INFO_ACK", (int32)MSG_GET_SHARED_STORAGE_INFO_ACK},
    {"MSG_AGENT_CLIENT_INIT_ACK", (int32)MSG_AGENT_CLIENT_INIT_ACK},
    {"MSG_CM_RES_LOCK", (int32)MSG_CM_RES_LOCK},
    {"MSG_CM_RES_LOCK_ACK", (int32)MSG_CM_RES_LOCK_ACK},
    {"MSG_CM_RES_REG", (int32)MSG_CM_RES_REG},
    {"MSG_CM_RES_REG_ACK", (int32)MSG_CM_RES_REG_ACK},
    {"MSG_CTL_CM_QUERY_RES_INST", (int32)MSG_CTL_CM_QUERY_RES_INST},
    {"MSG_CM_CTL_QUERY_RES_INST_ACK", (int32)MSG_CM_CTL_QUERY_RES_INST_ACK},
    {"MSG_CM_RHB", (int32)MSG_CM_RHB},
    {"MSG_CTL_CM_RHB_STATUS_REQ", (int32)MSG_CTL_CM_RHB_STATUS_REQ},
    {"MSG_CTL_CM_RHB_STATUS_ACK", (int32)MSG_CTL_CM_RHB_STATUS_ACK},
    {"MSG_CTL_CM_NODE_DISK_STATUS_REQ", (int32)MSG_CTL_CM_NODE_DISK_STATUS_REQ},
    {"MSG_CTL_CM_NODE_DISK_STATUS_ACK", (int32)MSG_CTL_CM_NODE_DISK_STATUS_ACK},
    {"MSG_AGENT_CM_FLOAT_IP", (int32)MSG_AGENT_CM_FLOAT_IP},
    {"MSG_CTL_CM_FLOAT_IP_REQ", (int32)MSG_CTL_CM_FLOAT_IP_REQ},
    {"MSG_CM_AGENT_FLOAT_IP_ACK", (int32)MSG_CM_AGENT_FLOAT_IP_ACK},
    {"MSG_AGENT_CM_ISREG_REPORT", (int32)MSG_AGENT_CM_ISREG_REPORT},
    {"MSG_CMA_PING_DN_FLOAT_IP_FAIL", (int32)MSG_CMA_PING_DN_FLOAT_IP_FAIL},
    {"MSG_CMS_NOTIFY_PRIMARY_DN_RESET_FLOAT_IP", (int32)MSG_CMS_NOTIFY_PRIMARY_DN_RESET_FLOAT_IP},
    {"MSG_CM_AGENT_ISREG_CHECK_LIST_CHANGED", (int32)MSG_CM_AGENT_ISREG_CHECK_LIST_CHANGED},
    {NULL, MSG_TYPE_BUTT},
};

const char* cluster_msg_int_to_string(int cluster_msg)
{
    for (int i = 0; cluster_msg_map_string[i].cluster_msg_str != NULL; ++i) {
        if (cluster_msg_map_string[i].cluster_msg_val == cluster_msg) {
            return cluster_msg_map_string[i].cluster_msg_str;
        }
    }
    write_runlog(ERROR, "cluster_msg_int_to_string failed, input int cluster_msg is: (%d)\n", cluster_msg);
    return "Unknown message type";
}

instance_not_exist_reason_string instance_not_exist_reason[] = {
    {"unknown", UNKNOWN_BAD_REASON},
    {"check port fail", PORT_BAD_REASON},
    {"nic not up", NIC_BAD_REASON},
    {"data path disc writable test failed", DISC_BAD_REASON},
    {"stopped by users", STOPPED_REASON},
    {"cn deleted, please repair quickly", CN_DELETED_REASON},
    {NULL, MSG_TYPE_BUTT},
};

const char* instance_not_exist_reason_to_string(int reason)
{
    for (int i = 0; instance_not_exist_reason[i].level_string != NULL; i++) {
        if (instance_not_exist_reason[i].level_val == reason) {
            return instance_not_exist_reason[i].level_string;
        }
    }
    return "unknown";
}

void print_environ(void)
{
    int i;

    write_runlog(LOG, "begin printing environment variables.\n");
    for (i = 0; environ[i] != NULL; i++) {
        if (strcasestr(environ[i], "SESSION_ID") != NULL || strcasestr(environ[i], "PASSWD") != NULL) {
            continue;
        }
        write_runlog(LOG, "%s\n", environ[i]);
    }
    write_runlog(LOG, "end printing environment variables\n");
}

void cm_pthread_rw_lock(pthread_rwlock_t* rwlock)
{
    int ret = pthread_rwlock_wrlock(rwlock);
    if (ret != 0) {
        write_runlog(FATAL, "pthread_rwlock_wrlock failed.\n");
        exit(1);
    }
}

void cm_pthread_rw_unlock(pthread_rwlock_t* rwlock)
{
    int ret = pthread_rwlock_unlock(rwlock);
    if (ret != 0) {
        write_runlog(FATAL, "pthread_rwlock_unlock failed.\n");
        exit(1);
    }
}

/**
 * @brief Creates a lock file for a process with a specified PID.
 *
 * @note When the parameter "pid" is set to -1, the specified process is the current process.
 * @param  filename         The name of the g_lockfile to create.
 * @param  data_path        The data path of the instance.
 * @param  pid              The pid of the process.
 * @return 0 Create successfully, -1 Create failure.
 */
int create_lock_file(const char* filename, const char* data_path, const pid_t pid)
{
    int         fd;
    char        buffer[MAXPGPATH + 100] = { 0 };
    const pid_t my_pid = (pid >= 0) ? pid : getpid();
    int         try_times = 0;

    do {
        /* The maximum number of attempts is 3. */
        if (try_times++ > 3) {
            write_runlog(ERROR, "could not create lock file: filename=\"%s\", error_no=%d.\n", filename, errno);
            return -1;
        }

        /* Attempt to create a specified PID file. */
        fd = open(filename, O_RDWR | O_CREAT | O_EXCL, 0600);
        if (fd >= 0) {
            break;
        }

        /* If the creation fails, try to open the existing pid file. */
        fd = open(filename, O_RDONLY | O_CLOEXEC, 0600);
        if (fd < 0) {
            write_runlog(ERROR, "could not open lock file: filename=\"%s\", error_no=%d.\n", filename, errno);
            return EEXIST;
        }

        /* If the file is opened successfully, the system attempts to read the file content. */
        int len = (int)read(fd, buffer, sizeof(buffer) - 1);
        (void)close(fd);
        if (len < 0 || len >= (MAXPGPATH + 100)) {
            write_runlog(ERROR, "could not read lock file: filename=\"%s\", error_no=%d.\n", filename, errno);
            return EEXIST;
        }

        /* Obtains the PID information in a PID file. */
        const pid_t other_pid = static_cast<pid_t>(atoi(buffer));
        if (other_pid <= 0) {
            write_runlog(ERROR,
                "bogus data in lock file: filename=\"%s\", buffer=\"%s\", error_no=%d.\n",
                filename, buffer, errno);
            return EEXIST;
        }

        /* If the obtained PID is not the specified process ID or parent process ID. */
        if (other_pid != my_pid
#ifndef WIN32
            && other_pid != getppid()
#endif
                ) {
            /* Sends signals to the specified PID. */
            if (kill(other_pid, 0) == 0 || (errno != ESRCH && errno != EPERM)) {
                write_runlog(WARNING,
                    "lock file \"%s\"  exists, Is another instance (PID %d) running in data directory \"%s\"?\n",
                    filename, (int)(other_pid), data_path);
            }
        }

        /* Attempt to delete the specified PID file. */
        if (unlink(filename) < 0) {
            write_runlog(ERROR,
                "could not remove old lock file \"%s\", The file seems accidentally"
                " left over, but it could not be removed. Please remove the file by hand and try again: errno=%d.\n",
                filename, errno);
            return -1;
        }
    } while (true);

    int rc = snprintf_s(buffer, sizeof(buffer), sizeof(buffer) - 1, "%d\n%s\n%d\n", (int)(my_pid), data_path, 0);
    securec_check_intval(rc, (void)rc);

    /* Writes PID information. */
    errno = 0;
    if (write(fd, buffer, strlen(buffer)) != (int)(strlen(buffer))) {
        write_runlog(ERROR, "could not write lock file: filename=\"%s\", error_no=%d.\n", filename, errno);

        (void)close(fd);
        (void)unlink(filename);
        return EEXIST;
    }

    /* Close the pid file. */
    if (close(fd)) {
        write_runlog(FATAL, "could not write lock file: filename=\"%s\", error_no=%d.\n", filename, errno);

        (void)unlink(filename);
        return -1;
    }

    return 0;
}

/**
 * @brief Delete pid file.
 *
 * @param  filename         The pid file to be deleted.
 */
void delete_lock_file(const char* filename)
{
    struct stat stat_buf = {0};

    /* Check whether the pid file exists. */
    if (stat(filename, &stat_buf) != 0) {
        return;
    }

    /* Delete the PID file. */
    if (unlink(filename) < 0) {
        write_runlog(FATAL, "could not remove old lock file \"%s\"", filename);
    }
}

/* kerberos status to string */
const char* kerberos_status_to_string(int role)
{
    if (role <= KERBEROS_STATUS_UNKNOWN || role > KERBEROS_STATUS_DOWN) {
        return kerberos_role_string_map[KERBEROS_STATUS_UNKNOWN].role_string;
    } else {
        return kerberos_role_string_map[role].role_string;
    }
}

int InitSslOption()
{
    errno_t rcs;
    g_sslOption.ssl_para.ca_file = (char *)malloc(MAX_PATH_LEN);
    if (g_sslOption.ssl_para.ca_file == NULL) {
        write_runlog(ERROR, "g_sslOption.ssl_para.ca_file malloc failed !\n");
        return -1;
    }

    rcs = memset_s(g_sslOption.ssl_para.ca_file, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rcs, (void)rcs);

    g_sslOption.ssl_para.cert_file = (char *)malloc(MAX_PATH_LEN);
    if (g_sslOption.ssl_para.cert_file == NULL) {
        write_runlog(ERROR, "g_sslOption.ssl_para.cert_file malloc failed !\n");
        return -1;
    }

    rcs = memset_s(g_sslOption.ssl_para.cert_file, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rcs, (void)rcs);

    g_sslOption.ssl_para.key_file = (char *)malloc(MAX_PATH_LEN);
    if (g_sslOption.ssl_para.key_file == NULL) {
        write_runlog(ERROR, "g_sslOption.ssl_para.key_file malloc failed !\n");
        return -1;
    }

    rcs = memset_s(g_sslOption.ssl_para.key_file, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rcs, (void)rcs);

    g_sslOption.ssl_para.crl_file = (char *)malloc(MAX_PATH_LEN);
    if (g_sslOption.ssl_para.crl_file == NULL) {
        write_runlog(ERROR, "g_sslOption.ssl_para.crl_file malloc failed !\n");
        return -1;
    }

    rcs = memset_s(g_sslOption.ssl_para.crl_file, MAX_PATH_LEN, 0, MAX_PATH_LEN);
    securec_check_errno(rcs, (void)rcs);
    return 0;
}

void FreeSslOpton()
{
    ssl_config_t *sslPara = &(g_sslOption.ssl_para);
    FREE_AND_RESET(sslPara->ca_file);
    FREE_AND_RESET(sslPara->cert_file);
    FREE_AND_RESET(sslPara->key_file);
    FREE_AND_RESET(sslPara->crl_file);
}

int CmSSlConfigInit(bool is_client)
{
    errno_t rcs;
    char homePath[MAX_PATH_LEN] = {0};
    if (GetHomePath(homePath, sizeof(homePath)) != 0) {
        return -1;
    }

    char certFilePath[MAX_PATH_LEN] = {0};
    rcs = snprintf_s(certFilePath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/share/sslcert/cm", homePath);
    securec_check_intval(rcs, (void)rcs);

    if (InitSslOption() != 0) {
        FreeSslOpton();
        return -1;
    }

    const char* type = is_client ? "client" : "server";

    rcs = snprintf_s(g_sslOption.ssl_para.ca_file, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/cacert.pem", certFilePath);
    securec_check_intval(rcs, (void)rcs);

    rcs = snprintf_s(g_sslOption.ssl_para.cert_file, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/%s.crt", certFilePath, type);
    securec_check_intval(rcs, (void)rcs);

    rcs = snprintf_s(g_sslOption.ssl_para.key_file, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/%s.key", certFilePath, type);
    securec_check_intval(rcs, (void)rcs);

    rcs = snprintf_s(g_sslOption.ssl_para.crl_file, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/%s.crl", certFilePath, type);
    securec_check_intval(rcs, (void)rcs);

    if (!CmFileExist((const char*)g_sslOption.ssl_para.crl_file)) {
        free(g_sslOption.ssl_para.crl_file);
        g_sslOption.ssl_para.crl_file = NULL;
    }

    g_sslOption.connect_timeout = SSL_CONNECT_TIMEOUT;
    g_sslOption.socket_timeout = SSL_SOCKET_TIMEOUT;
    g_sslOption.enable_ssl = CM_FALSE;
    g_sslOption.verify_peer = 0;
    return 0;
}

const char* CmGetmsgtype(const CM_StringInfo msg, int datalen)
{
    if (datalen < 0 || datalen > (msg->len - msg->cursor)) {
        write_runlog(ERROR,
            "CmGetmsgtype: insufficient data left in message, datalen=%d, msg->len=%d, msg->cursor=%d.\n",
            datalen,
            msg->len,
            msg->cursor);
        return NULL;
    }
    const char *result = &msg->data[msg->cursor];
    return result;
}

const char* CmGetmsgbytes(CM_StringInfo msg, int datalen)
{
    const int printMsgLen = 101;
    char dataLog[printMsgLen] = {0};
    if (datalen < 0 || datalen > (msg->len - msg->cursor)) {
        write_runlog(ERROR,
            "CmGetmsgbytes: insufficient data left in message, "
            "datalen=%d, msg->len=%d, msg->maxlen=%d, msg->cursor=%d,"
            " msg->qtype=%d, msg->msglen=%d.\n",
            datalen,
            msg->len,
            msg->maxlen,
            msg->cursor,
            msg->qtype,
            msg->msglen);
        if (msg->len < printMsgLen) {
            errno_t rc = memcpy_s(dataLog, printMsgLen, msg->data, msg->len);
            securec_check_errno(rc, (void)rc);
            write_runlog(ERROR, "CmGetmsgbytes: msg->data=%s.\n", dataLog);
        }
        return NULL;
    }

    const char *result = &msg->data[msg->cursor];
    msg->cursor += datalen;
    return result;
}

const char *CmGetmsgbytesPtr(const CM_Result *msg, int datalen)
{
    if (datalen < 0 || datalen > msg->gr_msglen) {
        write_runlog(ERROR,
            "CmGetmsgbytes: insufficient data left in message, "
            "datalen=%d, res->gr_msglen=%d.\n",
            datalen,
            msg->gr_msglen);
        return NULL;
    }
    return (const char*)&(msg->gr_resdata);
}

static int GetBuffInput(const char *str, long *result)
{
    int ret = -1;
    char *endptr = NULL;

    /* Some versions of strtol treat the empty string as an error, but some seem not to */
    if (str == NULL) {
        write_runlog(DEBUG1, "[GetBuffInput] str is NULL, use default value.\n");
        return ret;
    }
    if (*str == 0) {
        write_runlog(DEBUG1, "[GetBuffInput] str is empty, use default value.\n");
        return ret;
    }
    *result = strtol(str, &endptr, 10);
    if (str == endptr) {
        write_runlog(DEBUG1, "[GetBuffInput] str is %s, use default value.\n", str);
        return ret;
    }
    return 0;
}

int CmAtoi(const char *str, int defaultValue)
{
    return (int)CmAtol(str, defaultValue);
}

long CmAtol(const char *str, int defaultValue)
{
    long result;
    int ret;
    errno = 0;

    ret = GetBuffInput(str, &result);
    if (ret != 0) {
        return defaultValue;
    }

    bool cdt = (errno == ERANGE || result < INT_MIN || result > INT_MAX);
    if (cdt) {
        write_runlog(WARNING, "[CmAtol] str is %s errno:%d, use default value:%d\n", str, errno, defaultValue);
        return defaultValue;
    }
    return result;
}

bool CmAtoBool(const char *str)
{
    long result;
    int ret;

    ret = GetBuffInput(str, &result);
    if (ret != 0) {
        return false;
    }

    bool cdt = (errno == ERANGE || result == 0);
    if (cdt) {
        write_runlog(WARNING, "[CmAtoBool] str is %s errno:%d\n", str, errno);
        return false;
    }
    return true;
}

bool IsNodeOfflineFromEtcd(uint32 nodeIndex, int instanceType)
{
    char command[CM_MAX_COMMAND_LEN] = {0};
    char clientUrl[MAX_PATH_LEN];
    char key[MAX_PATH_LEN];
    char execPath[MAX_PATH_LEN] = {0};
    int logLevel = instanceType == CM_AGENT ? LOG : DEBUG1;
    int ret = cm_getenv("GAUSSHOME", execPath, sizeof(execPath), ERROR);
    if (ret != 0) {
        write_runlog(logLevel, "[%s] Get GAUSSHOME failed, please check.\n", __FUNCTION__);
        return false;
    }

    struct passwd* pw = getpwuid(getuid());
    errno_t rc = snprintf_s(key, MAX_PATH_LEN, MAX_PATH_LEN - 1, "/%s/dorado_offline_node", pw->pw_name);
    securec_check_intval(rc, (void)rc);
    for (uint32 ii = 0; ii < g_node_num; ii++) {
        if (g_node[ii].etcd) {
            rc = snprintf_s(clientUrl, MAX_PATH_LEN, MAX_PATH_LEN - 1,
                "https://%s:%u", g_node[ii].etcdClientListenIPs[0], g_node[ii].etcdClientListenPort);
            securec_check_intval(rc, (void)rc);
            break;
        }
    }

    rc = snprintf_s(command, CM_MAX_COMMAND_LEN, CM_MAX_COMMAND_LEN - 1,
        "export ETCDCTL_API=3;"
        " etcdctl --cacert %s/share/sslcert/etcd/etcdca.crt"
        " --cert %s/share/sslcert/etcd/client.crt"
        " --key %s/share/sslcert/etcd/client.key"
        " --command-timeout 60s --endpoints %s get --print-value-only %s",
        execPath, execPath, execPath, clientUrl, key);
    securec_check_intval(rc, (void)rc);

    FILE* fp = popen(command, "r");
    if (fp == NULL) {
        write_runlog(logLevel, "[%s] Execute failed, command: %s\n", __FUNCTION__, command);
        return false;
    }

    char buf[CM_IP_LENGTH] = {0};
    if (fgets(buf, CM_IP_LENGTH, fp) == NULL) {
        (void)pclose(fp);
        write_runlog(logLevel, "[%s] fgets result null\n", __FUNCTION__);
        return false;
    }
    if (strstr(buf, g_node[nodeIndex].sshChannel[0]) == NULL) {
        write_runlog(logLevel, "Get ignore node(%s) from etcd successfully.\n", g_node[nodeIndex].sshChannel[0]);
        (void)pclose(fp);
        return false;
    }

    (void)pclose(fp);
    return true;
}

void listen_ip_merge(uint32 ipCnt, const char (*ipListen)[CM_IP_LENGTH], char *retIpMerge, uint32 ipMergeLength)
{
    errno_t rc;
    char ipTmp[MAX_PATH_LEN] = {0};
    for (uint32 i = 0; i < ipCnt; ++i) {
        if (i == 0) {
            rc = strcpy_s(retIpMerge, ipMergeLength, ipListen[i]);
            securec_check_errno(rc, (void)rc);
            continue;
        }
        rc = snprintf_s(ipTmp, MAX_PATH_LEN, MAX_PATH_LEN - 1, ",%s", ipListen[i]);
        securec_check_intval(rc, (void)rc);
        rc = strcat_s(retIpMerge, ipMergeLength, ipTmp);
        securec_check_errno(rc, (void)rc);
    }
    if (strlen(retIpMerge) == 0) {
        write_runlog(ERROR, "ip count is invalid ip_count =%u\n", ipCnt);
    }
}

bool IsNodeIdValid(int nodeId)
{
    if (nodeId <= 0) {
        return false;
    }
    for (uint32 i = 0; i < g_node_num; ++i) {
        if (g_node[i].node == (uint32)nodeId) {
            return true;
        }
    }
    return false;
}

status_t IsReachableIP(char *ip)
{
    if (ip == nullptr) {
        return CM_ERROR;
    }
    char cmd[MAXPGPATH] = {0};
    int rc;
    const char *pingStr = GetPingStr(GetIpVersion(ip));
    rc = snprintf_s(cmd, MAXPGPATH, MAXPGPATH - 1, "timeout 2 %s -c 2 %s > /dev/null 2>&1", pingStr, ip);
    securec_check_intval(rc, (void)rc);
    rc = system(cmd);
    return rc == 0 ? CM_SUCCESS : CM_ERROR;
}

bool IsIPAddrValid(const char *ipAddr)
{
    if (ipAddr == nullptr) {
        return false;
    }

    unsigned char ipAddrBuf[sizeof(struct in6_addr)];
    // return value of function 'inet_pton' is 1 only when valid ip addr
    if (inet_pton(AF_INET, ipAddr, &ipAddrBuf) == VAILD_IP_ADDR ||
        inet_pton(AF_INET6, ipAddr, &ipAddrBuf) == VAILD_IP_ADDR) {
        return true;
    }
    return false;
}

bool IsNeedCheckFloatIp()
{
    if (g_clusterType == SingleInstCluster) {
        return true;
    }
    return false;
}
