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
 * alarm.cpp
 *    alarm functions
 *
 * IDENTIFICATION
 *    src/lib/alarm/alarm.cpp
 *
 * -------------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>
#include "common/config/cm_config.h"
#include "syslog.h"
#include "securec.h"
#include "securec_check.h"
#include "alarm/alarm_log.h"

#ifdef ENABLE_UT
#define static
#endif

static char MyHostName[CM_NODE_NAME] = {0};
static char MyHostIP[CM_NODE_NAME] = {0};
static char WarningType[CM_NODE_NAME] = {0};
static char ClusterName[CLUSTER_NAME_LEN] = {0};
// declare the guc variable of alarm module
char* Alarm_component = NULL;
THR_LOCAL int AlarmReportInterval = 10;
const int ALARM_RETRY_TIMES = 3;

// if report alarm succeed(component), return 0
#define ALARM_REPORT_SUCCEED 0
// if report alarm suppress(component), return 2
#define ALARM_REPORT_SUPPRESS 2
#define CLUSTERNAME "MPP_CLUSTER"
#define FUSIONINSIGHTTYPE "1"
#define ICBCTYPE "2"
#define CBGTYPE "5"
#define ALARMITEMNUMBER 64
#define ALARM_LOGEXIT(ErrMsg, fp)        \
    do {                                 \
        AlarmLog(ALM_LOG, "%s", ErrMsg); \
        if ((fp) != NULL) {              \
            (void)fclose(fp);            \
        }                                \
        return;                          \
    } while (0)

static AlarmName AlarmNameMap[ALARMITEMNUMBER];

static const char* AlarmIdToAlarmNameEn(AlarmId id);
static const char* AlarmIdToAlarmNameCh(AlarmId id);
static const char* AlarmIdToAlarmInfoEn(AlarmId id);
static const char* AlarmIdToAlarmInfoCh(AlarmId id);
static const char* AlarmIdToAlarmLevel(AlarmId id);
static void ReadAlarmItem(void);
static void GetHostName(char* myHostName, unsigned int myHostNameLen);
static void GetHostIP(const char* myHostName, char* myHostIP, unsigned int myHostIPLen);
static void GetClusterName(char* clusterName, unsigned int clusterNameLen);
static bool CheckAlarmComponent(const char* alarmComponentPath);
static bool SuppressComponentAlarmReport(Alarm* alarmItem, AlarmType type, int timeInterval);
static bool SuppressSyslogAlarmReport(Alarm* alarmItem, AlarmType type, int timeInterval);
static void ComponentReport(char *alarmComponentPath, const Alarm *alarmItem, AlarmType type,
    AlarmAdditionalParam *additionalParam);
static void SyslogReport(const Alarm *alarmItem, const AlarmAdditionalParam *additionalParam);
static void check_input_for_security1(char *input);
static void AlarmScopeInitialize(void);
void AlarmReporter(Alarm *alarmItem, AlarmType type, AlarmAdditionalParam *additionalParam);
void AlarmLog(int level, const char *fmt, ...);

static void check_input_for_security1(char* input)
{
    const char* danger_token[] = {"|",
        ";",
        "&",
        "$",
        "<",
        ">",
        "`",
        "\\",
        "'",
        "\"",
        "{",
        "}",
        "(",
        ")",
        "[",
        "]",
        "~",
        "*",
        "?",
        "!",
        "\n",
        NULL};

    for (int i = 0; danger_token[i] != NULL; ++i) {
        if (strstr(input, danger_token[i]) != NULL) {
            (void)printf("invalid token \"%s\"\n", danger_token[i]);
            exit(1);
        }
    }
}

static const char* AlarmIdToAlarmNameEn(AlarmId id)
{
    for (unsigned int i = 0; i < sizeof(AlarmNameMap) / sizeof(AlarmName); ++i) {
        if (id == AlarmNameMap[i].id) {
            return AlarmNameMap[i].nameEn;
        }
    }
    return "unknown";
}

static const char* AlarmIdToAlarmNameCh(AlarmId id)
{
    for (unsigned int i = 0; i < sizeof(AlarmNameMap) / sizeof(AlarmName); ++i) {
        if (id == AlarmNameMap[i].id) {
            return AlarmNameMap[i].nameCh;
        }
    }
    return "unknown";
}

static const char* AlarmIdToAlarmInfoEn(AlarmId id)
{
    for (unsigned int i = 0; i < sizeof(AlarmNameMap) / sizeof(AlarmName); ++i) {
        if (id == AlarmNameMap[i].id) {
            return AlarmNameMap[i].alarmInfoEn;
        }
    }
    return "unknown";
}

static const char* AlarmIdToAlarmInfoCh(AlarmId id)
{
    for (unsigned int i = 0; i < sizeof(AlarmNameMap) / sizeof(AlarmName); ++i) {
        if (id == AlarmNameMap[i].id) {
            return AlarmNameMap[i].alarmInfoCh;
        }
    }
    return "unknown";
}

static const char* AlarmIdToAlarmLevel(AlarmId id)
{
    for (unsigned int i = 0; i < sizeof(AlarmNameMap) / sizeof(AlarmName); ++i) {
        if (id == AlarmNameMap[i].id) {
            return AlarmNameMap[i].alarmLevel;
        }
    }
    return "unknown";
}

static void ReadAlarmItem(void)
{
    const int MAX_ERROR_MSG = 128;
    char alarmItemPath[MAXPGPATH];
    char Lrealpath[MAXPGPATH * 4] = {0};
    char* endptr = NULL;
    int alarmItemIndex;
    char tempStr[MAXPGPATH];
    char* subStr1 = NULL;
    char* subStr2 = NULL;
    char* subStr3 = NULL;
    char* subStr4 = NULL;
    char* subStr5 = NULL;
    char* subStr6 = NULL;

    char* savePtr1 = NULL;
    char* savePtr2 = NULL;
    char* savePtr3 = NULL;
    char* savePtr4 = NULL;
    char* savePtr5 = NULL;
    char* savePtr6 = NULL;

    char ErrMsg[MAX_ERROR_MSG];

    char* gaussHomeDir = gs_getenv_r("GAUSSHOME");
    if (gaussHomeDir == NULL) {
        AlarmLog(ALM_LOG, "ERROR: environment variable $GAUSSHOME is not set!\n");
        return;
    }
    check_input_for_security1(gaussHomeDir);

    int nRet = snprintf_s(alarmItemPath, MAXPGPATH, MAXPGPATH - 1, "%s/bin/alarmItem.conf", gaussHomeDir);
    securec_check_ss_c(nRet, "", "");

    char* realPathPtr = realpath(alarmItemPath, Lrealpath);
    if (realPathPtr == NULL) {
        AlarmLog(ALM_LOG, "Get real path of alarmItem.conf failed!\n");
        return;
    }

    FILE* fp = fopen(Lrealpath, "r");
    if (fp == NULL) {
        AlarmLog(ALM_LOG, "AlarmItem file is not exist!\n");
        return;
    }

    errno_t rc = memset_s(ErrMsg, MAX_ERROR_MSG, 0, MAX_ERROR_MSG);
    securec_check_c(rc, "", "");

    for (alarmItemIndex = 0; alarmItemIndex < ALARMITEMNUMBER; ++alarmItemIndex) {
        if (fgets(tempStr, MAXPGPATH - 1, fp) == NULL) {
            nRet = snprintf_s(ErrMsg,
                MAX_ERROR_MSG,
                MAX_ERROR_MSG - 1,
                "Get line in AlarmItem file failed! line: %d\n",
                alarmItemIndex + 1);
            securec_check_ss_c(nRet, "", "");
            ALARM_LOGEXIT(ErrMsg, fp);
        }
        subStr1 = strtok_r(tempStr, "\t", &savePtr1);
        if (subStr1 == NULL) {
            nRet = snprintf_s(ErrMsg,
                MAX_ERROR_MSG,
                MAX_ERROR_MSG - 1,
                "Invalid data in AlarmItem file! Read alarm ID failed! line: %d\n",
                alarmItemIndex + 1);
            securec_check_ss_c(nRet, "", "");
            ALARM_LOGEXIT(ErrMsg, fp);
        }
        subStr2 = strtok_r(savePtr1, "\t", &savePtr2);
        if (subStr2 == NULL) {
            nRet = snprintf_s(ErrMsg,
                MAX_ERROR_MSG,
                MAX_ERROR_MSG - 1,
                "Invalid data in AlarmItem file! Read alarm English name failed! line: %d\n",
                alarmItemIndex + 1);
            securec_check_ss_c(nRet, "", "");
            ALARM_LOGEXIT(ErrMsg, fp);
        }
        subStr3 = strtok_r(savePtr2, "\t", &savePtr3);
        if (subStr3 == NULL) {
            nRet = snprintf_s(ErrMsg,
                MAX_ERROR_MSG,
                MAX_ERROR_MSG - 1,
                "Invalid data in AlarmItem file! Read alarm Chinese name failed! line: %d\n",
                alarmItemIndex + 1);
            securec_check_ss_c(nRet, "", "");
            ALARM_LOGEXIT(ErrMsg, fp);
        }
        subStr4 = strtok_r(savePtr3, "\t", &savePtr4);
        if (subStr4 == NULL) {
            nRet = snprintf_s(ErrMsg,
                MAX_ERROR_MSG,
                MAX_ERROR_MSG - 1,
                "Invalid data in AlarmItem file! Read alarm English info failed! line: %d\n",
                alarmItemIndex + 1);
            securec_check_ss_c(nRet, "", "");
            ALARM_LOGEXIT(ErrMsg, fp);
        }
        subStr5 = strtok_r(savePtr4, "\t", &savePtr5);
        if (subStr5 == NULL) {
            nRet = snprintf_s(ErrMsg,
                MAX_ERROR_MSG,
                MAX_ERROR_MSG - 1,
                "Invalid data in AlarmItem file! Read alarm Chinese info failed! line: %d\n",
                alarmItemIndex + 1);
            securec_check_ss_c(nRet, "", "");
            ALARM_LOGEXIT(ErrMsg, fp);
        }
        subStr6 = strtok_r(savePtr5, "\t", &savePtr6);
        if (subStr6 == NULL) {
            nRet = snprintf_s(ErrMsg,
                MAX_ERROR_MSG,
                MAX_ERROR_MSG - 1,
                "Invalid data in AlarmItem file! Read alarm Level info failed! line: %d\n",
                alarmItemIndex + 1);
            securec_check_ss_c(nRet, "", "");
            ALARM_LOGEXIT(ErrMsg, fp);
        }

        // get alarm ID
        errno = 0;
        AlarmNameMap[alarmItemIndex].id = (AlarmId)(strtol(subStr1, &endptr, 10));
        if ((endptr != NULL && *endptr != '\0') || errno == ERANGE) {
            ALARM_LOGEXIT("Get alarm ID failed!\n", fp);
        }

        // get alarm EN name
        size_t len = (strlen(subStr2) < (sizeof(AlarmNameMap[alarmItemIndex].nameEn) - 1))
                  ? strlen(subStr2)
                  : (sizeof(AlarmNameMap[alarmItemIndex].nameEn) - 1);
        rc = memcpy_s(AlarmNameMap[alarmItemIndex].nameEn, sizeof(AlarmNameMap[alarmItemIndex].nameEn), subStr2, len);
        securec_check_c(rc, "", "");
        AlarmNameMap[alarmItemIndex].nameEn[len] = '\0';

        // get alarm CH name
        len = (strlen(subStr3) < (sizeof(AlarmNameMap[alarmItemIndex].nameCh) - 1))
                  ? strlen(subStr3)
                  : (sizeof(AlarmNameMap[alarmItemIndex].nameCh) - 1);
        rc = memcpy_s(AlarmNameMap[alarmItemIndex].nameCh, sizeof(AlarmNameMap[alarmItemIndex].nameCh), subStr3, len);
        securec_check_c(rc, "", "");
        AlarmNameMap[alarmItemIndex].nameCh[len] = '\0';

        // get alarm EN info
        len = (strlen(subStr4) < (sizeof(AlarmNameMap[alarmItemIndex].alarmInfoEn) - 1))
                  ? strlen(subStr4)
                  : (sizeof(AlarmNameMap[alarmItemIndex].alarmInfoEn) - 1);
        rc = memcpy_s(
            AlarmNameMap[alarmItemIndex].alarmInfoEn, sizeof(AlarmNameMap[alarmItemIndex].alarmInfoEn), subStr4, len);
        securec_check_c(rc, "", "");
        AlarmNameMap[alarmItemIndex].alarmInfoEn[len] = '\0';

        // get alarm CH info
        len = (strlen(subStr5) < (sizeof(AlarmNameMap[alarmItemIndex].alarmInfoCh) - 1))
                  ? strlen(subStr5)
                  : (sizeof(AlarmNameMap[alarmItemIndex].alarmInfoCh) - 1);
        rc = memcpy_s(
            AlarmNameMap[alarmItemIndex].alarmInfoCh, sizeof(AlarmNameMap[alarmItemIndex].alarmInfoCh), subStr5, len);
        securec_check_c(rc, "", "");
        AlarmNameMap[alarmItemIndex].alarmInfoCh[len] = '\0';

        /* get alarm LEVEL info */
        len = (strlen(subStr6) < (sizeof(AlarmNameMap[alarmItemIndex].alarmLevel) - 1))
                  ? strlen(subStr6)
                  : (sizeof(AlarmNameMap[alarmItemIndex].alarmLevel) - 1);
        rc = memcpy_s(
            AlarmNameMap[alarmItemIndex].alarmLevel, sizeof(AlarmNameMap[alarmItemIndex].alarmLevel), subStr6, len);
        securec_check_c(rc, "", "");
        /* alarm level is the last one in alarmItem.conf, we should delete line break */
        AlarmNameMap[alarmItemIndex].alarmLevel[len - 1] = '\0';
    }
    (void)fclose(fp);
}

static void GetHostName(char* myHostName, unsigned int myHostNameLen)
{
    char hostName[CM_NODE_NAME];

    (void)gethostname(hostName, CM_NODE_NAME);
    size_t len = (strlen(hostName) < (myHostNameLen - 1)) ? strlen(hostName) : (myHostNameLen - 1);
    errno_t rc = memcpy_s(myHostName, myHostNameLen, hostName, len);
    securec_check_c(rc, "", "");
    myHostName[len] = '\0';
    AlarmLog(ALM_LOG, "Host Name: %s \n", myHostName);
}

static void GetHostIP(const char* myHostName, char* myHostIP, unsigned int myHostIPLen)
{
    struct hostent* hp = gethostbyname(myHostName);
    if (hp == NULL) {
        AlarmLog(ALM_LOG, "GET host IP by name failed.\n");
    } else {
        char* ipstr = inet_ntoa(*((struct in_addr*)hp->h_addr));
        size_t len = (strlen(ipstr) < (myHostIPLen - 1)) ? strlen(ipstr) : (myHostIPLen - 1);
        errno_t rc = memcpy_s(myHostIP, myHostIPLen, ipstr, len);
        securec_check_c(rc, "", "");
        myHostIP[len] = '\0';
        AlarmLog(ALM_LOG, "Host IP: %s \n", myHostIP);
    }
}

static void GetClusterName(char* clusterName, unsigned int clusterNameLen)
{
    errno_t rc = 0;
    char* gsClusterName = gs_getenv_r("GS_CLUSTER_NAME");

    if (gsClusterName != NULL) {
        check_input_for_security1(gsClusterName);
        size_t len = (strlen(gsClusterName) < (clusterNameLen - 1)) ? strlen(gsClusterName) : (clusterNameLen - 1);
        rc = memcpy_s(clusterName, clusterNameLen, gsClusterName, len);
        securec_check_c(rc, "", "");
        clusterName[len] = '\0';
        AlarmLog(ALM_LOG, "Cluster Name: %s \n", clusterName);
    } else {
        size_t len = strlen(CLUSTERNAME);
        rc = memcpy_s(clusterName, clusterNameLen, CLUSTERNAME, len);
        securec_check_c(rc, "", "");
        clusterName[len] = '\0';
        AlarmLog(ALM_LOG, "Get ENV GS_CLUSTER_NAME failed!\n");
    }
}

void AlarmEnvInitialize()
{
    char* warningType = gs_getenv_r("GAUSS_WARNING_TYPE");
    if ((warningType == NULL) || (warningType[0] == '\0')) {
        AlarmLog(ALM_LOG, "can not read GAUSS_WARNING_TYPE env.\n");
    } else {
        check_input_for_security1(warningType);
        // save warningType into WarningType array
        // WarningType is a static global variable
        int  nRet = snprintf_s(WarningType, sizeof(WarningType), sizeof(WarningType) - 1, "%s", warningType);
        securec_check_ss_c(nRet, "", "");
    }

    // save this host name into MyHostName array
    // MyHostName is a static global variable
    GetHostName(MyHostName, sizeof(MyHostName));

    // save this host IP into MyHostIP array
    // MyHostIP is a static global variable
    GetHostIP(MyHostName, MyHostIP, sizeof(MyHostIP));

    // save this cluster name into ClusterName array
    // ClusterName is a static global variable
    GetClusterName(ClusterName, sizeof(ClusterName));

    // read alarm item info from the configure file(alarmItem.conf)
    ReadAlarmItem();

    // read alarm scope info from the configure file(alarmItem.conf)
    AlarmScopeInitialize();
}

/*
Fill in the structure AlarmAdditionalParam with alarmItem has been filled.
*/
static void FillAlarmAdditionalInfo(AlarmAdditionalParam* additionalParam, const char* instanceName,
    const char* databaseName, const char* dbUserName, const char* logicClusterName, const Alarm* alarmItem)
{
    size_t lenAdditionInfo = sizeof(additionalParam->additionInfo);

    // fill in the addition Info field
    int nRet = snprintf_s(additionalParam->additionInfo, lenAdditionInfo, lenAdditionInfo - 1, "%s", alarmItem->infoEn);
    securec_check_ss_c(nRet, "", "");

    // fill in the cluster name field
    size_t lenClusterName = strlen(ClusterName);
    errno_t rc =
        memcpy_s(additionalParam->clusterName, sizeof(additionalParam->clusterName) - 1, ClusterName, lenClusterName);
    securec_check_c(rc, "", "");
    additionalParam->clusterName[lenClusterName] = '\0';

    // fill in the host IP field
    size_t lenHostIP = strlen(MyHostIP);
    rc = memcpy_s(additionalParam->hostIP, sizeof(additionalParam->hostIP) - 1, MyHostIP, lenHostIP);
    securec_check_c(rc, "", "");
    additionalParam->hostIP[lenHostIP] = '\0';

    // fill in the host name field
    size_t lenHostName = strlen(MyHostName);
    rc = memcpy_s(additionalParam->hostName, sizeof(additionalParam->hostName) - 1, MyHostName, lenHostName);
    securec_check_c(rc, "", "");
    additionalParam->hostName[lenHostName] = '\0';

    // fill in the instance name field
    size_t lenInstanceName = (strlen(instanceName) < (sizeof(additionalParam->instanceName) - 1))
                                 ? strlen(instanceName)
                                 : (sizeof(additionalParam->instanceName) - 1);
    rc = memcpy_s(
        additionalParam->instanceName, sizeof(additionalParam->instanceName) - 1, instanceName, lenInstanceName);
    securec_check_c(rc, "", "");
    additionalParam->instanceName[lenInstanceName] = '\0';

    // fill in the database name field
    size_t lenDatabaseName = (strlen(databaseName) < (sizeof(additionalParam->databaseName) - 1))
                                 ? strlen(databaseName)
                                 : (sizeof(additionalParam->databaseName) - 1);
    rc = memcpy_s(
        additionalParam->databaseName, sizeof(additionalParam->databaseName) - 1, databaseName, lenDatabaseName);
    securec_check_c(rc, "", "");
    additionalParam->databaseName[lenDatabaseName] = '\0';

    // fill in the dbuser name field
    size_t lenDbUserName = (strlen(dbUserName) < (sizeof(additionalParam->dbUserName) - 1))
                               ? strlen(dbUserName)
                               : (sizeof(additionalParam->dbUserName) - 1);
    rc = memcpy_s(additionalParam->dbUserName, sizeof(additionalParam->dbUserName) - 1, dbUserName, lenDbUserName);
    securec_check_c(rc, "", "");
    additionalParam->dbUserName[lenDbUserName] = '\0';

    if (logicClusterName == NULL) {
        return;
    }

    // fill in the logic cluster name field
    size_t lenLogicClusterName = strlen(logicClusterName);
    size_t bufLen = sizeof(additionalParam->logicClusterName) - 1;
    if (lenLogicClusterName > bufLen) {
        lenLogicClusterName = bufLen;
    }

    rc = memcpy_s(additionalParam->logicClusterName, bufLen, logicClusterName, lenLogicClusterName);
    securec_check_c(rc, "", "");
    additionalParam->logicClusterName[lenLogicClusterName] = '\0';
}

/*
Fill in the structure AlarmAdditionalParam for logic cluster.
*/
void WriteAlarmAdditionalInfo(AlarmAdditionalParam* additionalParam, const char* instanceName,
    const char* databaseName, const char* dbUserName, const char* logicClusterName, Alarm* alarmItem, AlarmType type,
    ...)
{
    int nRet = 0;
    size_t lenInfoEn = sizeof(alarmItem->infoEn);
    size_t lenInfoCh = sizeof(alarmItem->infoCh);
    va_list argp1;
    va_list argp2;

    // initialize the additionalParam
    errno_t rc = memset_s(additionalParam, sizeof(AlarmAdditionalParam), 0, sizeof(AlarmAdditionalParam));
    securec_check_c(rc, "", "");
    // initialize the alarmItem->infoEn
    rc = memset_s(alarmItem->infoEn, lenInfoEn, 0, lenInfoEn);
    securec_check_c(rc, "", "");
    // initialize the alarmItem->infoCh
    rc = memset_s(alarmItem->infoCh, lenInfoCh, 0, lenInfoCh);
    securec_check_c(rc, "", "");

    if (type == ALM_AT_Fault || type == ALM_AT_Event) {
        va_start(argp1, type);
        va_start(argp2, type);
        nRet = vsnprintf_s(alarmItem->infoEn, lenInfoEn, lenInfoEn - 1, AlarmIdToAlarmInfoEn(alarmItem->id), argp1);
        securec_check_ss_c(nRet, "", "");
        nRet = vsnprintf_s(alarmItem->infoCh, lenInfoCh, lenInfoCh - 1, AlarmIdToAlarmInfoCh(alarmItem->id), argp2);
        securec_check_ss_c(nRet, "", "");
        va_end(argp1);
        va_end(argp2);
    }
    FillAlarmAdditionalInfo(additionalParam, instanceName, databaseName, dbUserName, logicClusterName, alarmItem);
}

// check whether the alarm component exists
static bool CheckAlarmComponent(const char* alarmComponentPath)
{
    static int accessCount = 0;
    if (access(alarmComponentPath, F_OK) != 0) {
        if (accessCount == 0) {
            AlarmLog(ALM_LOG, "Alarm component does not exist.");
        }
        if (accessCount < 1000) {
            ++accessCount;
        } else {
            accessCount = 0;
        }
        return false;
    } else {
        return true;
    }
}

static bool SuppressAlarmFaultReport(Alarm* alarmItem, time_t thisTime, int timeInterval)
{
    // only report alarm and event
    const int maxReportCount = 5;
    if (alarmItem->stat == ALM_AS_Reported) {
        // original stat is fault
        // check whether the interval between now and the last report time is more than $timeInterval secs
        if (thisTime - alarmItem->lastReportTime >= timeInterval && alarmItem->reportCount < maxReportCount) {
            ++(alarmItem->reportCount);
            alarmItem->lastReportTime = thisTime;
            // need report
            return true;
        }

        return false;
    } else if (alarmItem->stat == ALM_AS_Normal) {
        // original state is resume
        alarmItem->reportCount = 1;
        alarmItem->lastReportTime = thisTime;
        alarmItem->stat = ALM_AS_Reported;
        return true;
    }

    return false;
}

/* suppress the component alarm report, don't suppress the event report */
static bool SuppressComponentAlarmReport(Alarm* alarmItem, AlarmType type, int timeInterval)
{
    time_t thisTime = time(NULL);

    /* alarm suppression */
    if (type == ALM_AT_Fault) {                    // now the state is fault
        return SuppressAlarmFaultReport(alarmItem, thisTime, timeInterval);
    } else if (type == ALM_AT_Resume) {            // now the state is resume
        if (alarmItem->stat == ALM_AS_Reported) {  // original state is fault
            // now the state have changed, report the resume immediately
            alarmItem->reportCount = 1;
            alarmItem->lastReportTime = thisTime;
            alarmItem->stat = ALM_AS_Normal;
            // need report
            return true;
        } else if (alarmItem->stat == ALM_AS_Normal) {  // original state is resume
            // check whether the interval between now and last report time is more than $timeInterval secs
            if (thisTime - alarmItem->lastReportTime >= timeInterval && alarmItem->reportCount < 5) {
                ++(alarmItem->reportCount);
                alarmItem->lastReportTime = thisTime;
                // need report
                return true;
            } else {
                // don't need report
                return false;
            }
        }
    } else if (type == ALM_AT_Event) {
        // report immediately
        return true;
    }

    return false;
}

// suppress the syslog alarm report, filter the resume, only report alarm
static bool SuppressSyslogAlarmReport(Alarm* alarmItem, AlarmType type, int timeInterval)
{
    time_t thisTime = time(NULL);

    if (type == ALM_AT_Fault) {
        return SuppressAlarmFaultReport(alarmItem, thisTime, timeInterval);
        // only report alarm and event
    } else if (type == ALM_AT_Event) {
        // report immediately
        return true;
    } else if (type == ALM_AT_Resume) {
        alarmItem->stat = ALM_AS_Normal;
        return false;
    }

    return false;
}

/* suppress the alarm log */
static bool SuppressAlarmLogReport(Alarm* alarmItem, AlarmType type, int timeInterval, int maxReportCount)
{
    struct timeval thisTime;
    (void)gettimeofday(&thisTime, NULL);

    /* alarm suppression */
    if (type == ALM_AT_Fault) {                   /* now the state is fault */
        if (alarmItem->stat == ALM_AS_Reported) { /* original state is fault */
            /* check whether the interval between now and last report time is more than $timeInterval secs */
            if (thisTime.tv_sec - alarmItem->lastReportTime >= timeInterval &&
                alarmItem->reportCount < maxReportCount) {
                ++(alarmItem->reportCount);
                alarmItem->lastReportTime = thisTime.tv_sec;
                if (alarmItem->startTimeStamp == 0) {
                    alarmItem->startTimeStamp = thisTime.tv_sec * 1000 + thisTime.tv_usec / 1000;
                }
                /* need report */
                return false;
            } else {
                /* don't need report */
                return true;
            }
        } else if (alarmItem->stat == ALM_AS_Normal) { /* original state is resume */
            /* now the state have changed, report the alarm immediately */
            alarmItem->reportCount = 1;
            alarmItem->lastReportTime = thisTime.tv_sec;
            alarmItem->stat = ALM_AS_Reported;
            alarmItem->startTimeStamp = thisTime.tv_sec * 1000 + thisTime.tv_usec / 1000;
            alarmItem->endTimeStamp = 0;
            /* need report */
            return false;
        }
    } else if (type == ALM_AT_Resume) {           /* now the state is resume */
        if (alarmItem->stat == ALM_AS_Reported) { /* original state is fault */
            /* now the state have changed, report the resume immediately */
            alarmItem->reportCount = 1;
            alarmItem->lastReportTime = thisTime.tv_sec;
            alarmItem->stat = ALM_AS_Normal;
            alarmItem->endTimeStamp = thisTime.tv_sec * 1000 + thisTime.tv_usec / 1000;
            alarmItem->startTimeStamp = 0;
            /* need report */
            return false;
        } else if (alarmItem->stat == ALM_AS_Normal) { /* original state is resume */
            /* check whether the interval between now and last report time is more than $timeInterval secs */
            if (thisTime.tv_sec - alarmItem->lastReportTime >= timeInterval &&
                alarmItem->reportCount < maxReportCount) {
                ++(alarmItem->reportCount);
                alarmItem->lastReportTime = thisTime.tv_sec;
                if (alarmItem->endTimeStamp == 0) {
                    alarmItem->endTimeStamp = thisTime.tv_sec * 1000 + thisTime.tv_usec / 1000;
                }
                /* need report */
                return false;
            } else {
                /* don't need report */
                return true;
            }
        }
    } else if (type == ALM_AT_Event) {
        /* need report */
        alarmItem->startTimeStamp = thisTime.tv_sec * 1000 + thisTime.tv_usec / 1000;
        return false;
    }

    return true;
}

static void GetFormatLenStr(char* outputLen, size_t inputLen)
{
    outputLen[4] = '\0';
    outputLen[3] = '0' + (char)(inputLen % 10);
    inputLen /= 10;
    outputLen[2] = '0' + (char)(inputLen % 10);
    inputLen /= 10;
    outputLen[1] = '0' + (char)(inputLen % 10);
    inputLen /= 10;
    outputLen[0] = '0' + (char)(inputLen % 10);
}

static void ComponentReport(
    char* alarmComponentPath, const Alarm* alarmItem, AlarmType type, AlarmAdditionalParam* additionalParam)
{
    char reportCmd[4096] = {0};
    int retCmd = 0;
    int cnt = 0;
    char tempBuff[4096] = {0};
    char clusterNameLen[5] = {0};
    char databaseNameLen[5] = {0};
    char dbUserNameLen[5] = {0};
    char hostIPLen[5] = {0};
    char hostNameLen[5] = {0};
    char instanceNameLen[5] = {0};
    char additionInfoLen[5] = {0};
    char clusterName[512] = {0};

    errno_t rc = 0;

    /* Set the host ip and the host name of the feature permission alarm to make that alarms of different hosts can be
     * suppressed. */
    if (alarmItem->id == ALM_AI_UnbalancedCluster || alarmItem->id == ALM_AI_FeaturePermissionDenied) {
        rc = memset_s(additionalParam->hostIP, sizeof(additionalParam->hostIP), 0, sizeof(additionalParam->hostIP));
        securec_check_c(rc, "", "");
        rc = memset_s(
            additionalParam->hostName, sizeof(additionalParam->hostName), 0, sizeof(additionalParam->hostName));
        securec_check_c(rc, "", "");
    }

    if (additionalParam->logicClusterName[0] != '\0') {
        rc = snprintf_s(clusterName,
            sizeof(clusterName),
            sizeof(clusterName) - 1,
            "%s:%s",
            additionalParam->clusterName,
            additionalParam->logicClusterName);
        securec_check_ss_c(rc, "", "");
    } else {
        rc = memcpy_s(
            clusterName, sizeof(clusterName), additionalParam->clusterName, sizeof(additionalParam->clusterName));
        securec_check_ss_c(rc, "", "");
    }

    GetFormatLenStr(clusterNameLen, strlen(clusterName));
    GetFormatLenStr(databaseNameLen, strlen(additionalParam->databaseName));
    GetFormatLenStr(dbUserNameLen, strlen(additionalParam->dbUserName));
    GetFormatLenStr(hostIPLen, strlen(additionalParam->hostIP));
    GetFormatLenStr(hostNameLen, strlen(additionalParam->hostName));
    GetFormatLenStr(instanceNameLen, strlen(additionalParam->instanceName));
    GetFormatLenStr(additionInfoLen, strlen(additionalParam->additionInfo));

    for (int i = 0; i < (int)strlen(additionalParam->additionInfo); ++i) {
        if (additionalParam->additionInfo[i] == ' ') {
            additionalParam->additionInfo[i] = '#';
        }
    }

    int nRet = snprintf_s(tempBuff,
        sizeof(tempBuff),
        sizeof(tempBuff) - 1,
        "%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
        clusterNameLen,
        databaseNameLen,
        dbUserNameLen,
        hostIPLen,
        hostNameLen,
        instanceNameLen,
        additionInfoLen,
        clusterName,
        additionalParam->databaseName,
        additionalParam->dbUserName,
        additionalParam->hostIP,
        additionalParam->hostName,
        additionalParam->instanceName,
        additionalParam->additionInfo);
    securec_check_ss_c(nRet, "", "");

    check_input_for_security1(alarmComponentPath);
    check_input_for_security1(tempBuff);
    nRet = snprintf_s(reportCmd,
        sizeof(reportCmd),
        sizeof(reportCmd) - 1,
        "%s alarm %ld %d %s",
        alarmComponentPath,
        (long)alarmItem->id,
        (int)type,
        tempBuff);
    securec_check_ss_c(nRet, "", "");

    do {
        retCmd = system(reportCmd);
        // return ALARM_REPORT_SUPPRESS, represent alarm report suppressed
        if (WEXITSTATUS(retCmd) == ALARM_REPORT_SUPPRESS) {
            break;
        }
        if (++cnt > ALARM_RETRY_TIMES) {
            break;
        }
    } while (WEXITSTATUS(retCmd) != ALARM_REPORT_SUCCEED);

    if (WEXITSTATUS(retCmd) != ALARM_REPORT_SUCCEED && WEXITSTATUS(retCmd) != ALARM_REPORT_SUPPRESS) {
        AlarmLog(ALM_LOG, "Component alarm report failed! Cmd: %s, retCmd: %d.", reportCmd, WEXITSTATUS(retCmd));
    } else if (WEXITSTATUS(retCmd) == ALARM_REPORT_SUCCEED) {
        if (type != ALM_AT_Resume) {
            AlarmLog(ALM_LOG, "Component alarm report succeed! Cmd: %s, retCmd: %d.", reportCmd, WEXITSTATUS(retCmd));
        }
    }
}

static void SyslogReport(const Alarm* alarmItem, const AlarmAdditionalParam* additionalParam)
{
    char reportInfo[4096] = {0};

    int nRet = snprintf_s(reportInfo,
        sizeof(reportInfo),
        sizeof(reportInfo) - 1,
        "%s||%s||%s||||||||%s||%s||%s||%s||%s||%s||%s||%s||%s||%s||%s||||||||||||||%s||%s||||||||||||||||||||",
        "Syslog MPPDB",
        additionalParam->hostName,
        additionalParam->hostIP,
        "Database",
        "MppDB",
        additionalParam->logicClusterName,
        "SYSLOG",
        additionalParam->instanceName,
        "Alarm",
        AlarmIdToAlarmNameEn(alarmItem->id),
        AlarmIdToAlarmNameCh(alarmItem->id),
        "1",
        "0",
        "6",
        alarmItem->infoEn,
        alarmItem->infoCh);

    securec_check_ss_c(nRet, "", "");
    syslog(LOG_ERR, "%s", reportInfo);
}

/* Check this line is comment line or not, which is in AlarmItem.conf file */
static bool isValidScopeLine(const char* str)
{
    size_t ii = 0;

    for (;;) {
        if (*(str + ii) == ' ') {
            ii++; /* skip blank */
        } else {
            break;
        }
    }

    if (*(str + ii) == '#') {
        return true; /* comment line */
    }

    return false; /* not comment line */
}

static void AlarmScopeInitialize(void)
{
    char* subStr = NULL;
    char* subStr1 = NULL;
    char* subStr2 = NULL;
    char* saveptr1 = NULL;
    char* saveptr2 = NULL;
    char alarmItemPath[MAXPGPATH];
    char buf[MAX_BUF_SIZE] = {0};
    errno_t nRet, rc;
    char* gaussHomeDir = gs_getenv_r("GAUSSHOME");
    if (gaussHomeDir == NULL) {
        AlarmLog(ALM_LOG, "ERROR: environment variable $GAUSSHOME is not set!\n");
        return;
    }
    check_input_for_security1(gaussHomeDir);

    nRet = snprintf_s(alarmItemPath, MAXPGPATH, MAXPGPATH - 1, "%s/bin/alarmItem.conf", gaussHomeDir);
    securec_check_ss_c(nRet, "", "");
    canonicalize_path(alarmItemPath);
    FILE* fd = fopen(alarmItemPath, "r");
    if (fd == NULL) {
        return;
    }

    while (!feof(fd)) {
        rc = memset_s(buf, MAX_BUF_SIZE, 0, MAX_BUF_SIZE);
        securec_check_c(rc, "", "");
        if (fgets(buf, MAX_BUF_SIZE, fd) == NULL) {
            continue;
        }

        if (isValidScopeLine(buf)) {
            continue;
        }

        subStr = strstr(buf, "alarm_scope");
        if (subStr == NULL) {
            continue;
        }

        subStr = strstr(subStr + strlen("alarm_scope"), "=");
        if (subStr == NULL || *(subStr + 1) == '\0') { /* '=' is last char */
            continue;
        }

        int ii = 1;
        for (;;) {
            if (*(subStr + ii) == ' ') {
                ii++; /* skip blank */
            } else {
                break;
            }
        }

        subStr = subStr + ii;
        subStr1 = strtok_r(subStr, "\n", &saveptr1);
        if (subStr1 == NULL) {
            continue;
        }
        subStr2 = strtok_r(subStr1, "\r", &saveptr2);
        if (subStr2 == NULL) {
            continue;
        }
        rc = memcpy_s(g_alarm_scope, MAX_BUF_SIZE, subStr2, strlen(subStr2));
        securec_check_c(rc, "", "");
    }
    (void)fclose(fd);
}

void AlarmReporter(Alarm* alarmItem, AlarmType type, AlarmAdditionalParam* additionalParam)
{
    if (alarmItem == NULL) {
        AlarmLog(ALM_LOG, "alarmItem is NULL.");
        return;
    }
    if (strcmp(WarningType, FUSIONINSIGHTTYPE) == 0) {  // the warning type is FusionInsight type
        // check whether the alarm component exists
        if (!CheckAlarmComponent(g_alarmComponentPath)) {
            // the alarm component does not exist
            return;
        }
        // suppress the component alarm
        if (SuppressComponentAlarmReport(alarmItem, type, g_alarmReportInterval)) {  // check whether report the alarm
            ComponentReport(g_alarmComponentPath, alarmItem, type, additionalParam);
        }
    } else if (strcmp(WarningType, ICBCTYPE) == 0) {  // the warning type is ICBC type
        // suppress the syslog alarm
        if (SuppressSyslogAlarmReport(alarmItem, type, g_alarmReportInterval)) {  // check whether report the alarm
            SyslogReport(alarmItem, additionalParam);
        }
    } else if (strcmp(WarningType, CBGTYPE) == 0) {
        if (!SuppressAlarmLogReport(alarmItem, type, g_alarmReportInterval, g_alarmReportMaxCount)) {
            write_alarm(alarmItem,
                AlarmIdToAlarmNameEn(alarmItem->id),
                AlarmIdToAlarmLevel(alarmItem->id),
                type,
                additionalParam);
        }
    }
}

/*
---------------------------------------------------------------------------
The first report method:
We register check function in the alarm module.
And we will check and report all the alarm(alarm or resume) item in a loop.
The second report method:
We don't register any check function in the alarm module.
And we don't initialize the alarm item(typedef struct Alarm) structure here.
We will initialize the alarm item(typedef struct Alarm) in the begining of alarm module.
We invoke report function internally in the monitor process.
We fill the report message and then invoke the AlarmReporter.
The third report method:
We don't register any check function in the alarm module.
When we detect some errors occur, we will report some alarm.
Firstly, initialize the alarm item(typedef struct Alarm).
Secondly, fill the report message(typedef struct AlarmAdditionalParam).
Thirdly, invoke the AlarmReporter, report the alarm.
---------------------------------------------------------------------------
*/
void AlarmCheckerLoop(Alarm* checkList, int checkListSize)
{
    int i;
    AlarmAdditionalParam tempAdditionalParam;

    if (checkList == NULL || checkListSize <= 0) {
        AlarmLog(ALM_LOG, "AlarmCheckerLoop failed.");
        return;
    }

    for (i = 0; i < checkListSize; ++i) {
        Alarm* alarmItem = &(checkList[i]);
        AlarmCheckResult result = ALM_ACR_UnKnown;

        AlarmType type = ALM_AT_Fault;

        if (alarmItem->checker != NULL) {
            // execute alarm check function and output check result
            result = alarmItem->checker(alarmItem, &tempAdditionalParam);
            if (result == ALM_ACR_UnKnown) {
                continue;
            }
            if (result == ALM_ACR_Normal) {
                type = ALM_AT_Resume;
            }
            AlarmReporter(alarmItem, type, &tempAdditionalParam);
        }
    }
}

void AlarmLog(int level, const char *fmt, ...)
{
    va_list args;
    char buf[MAXPGPATH] = {0}; /* enough for log module */

    va_start(args, fmt);
    int nRet = vsnprintf_s(buf, sizeof(buf), sizeof(buf) - 1, fmt, args);
    securec_check_ss_c(nRet, "", "");
    va_end(args);

    AlarmLogImplementation(level, AlarmLogPrefix, buf);
}

/*
Initialize the alarm item
reportTime:  express the last time of alarm report. the default value is 0.
*/
void AlarmItemInitialize(
    Alarm* alarmItem, AlarmId alarmId, AlarmStat alarmStat, CheckerFunc checkerFunc, time_t reportTime, int reportCount)
{
    alarmItem->checker = checkerFunc;
    alarmItem->id = alarmId;
    alarmItem->stat = alarmStat;
    alarmItem->lastReportTime = reportTime;
    alarmItem->reportCount = reportCount;
    alarmItem->startTimeStamp = 0;
    alarmItem->endTimeStamp = 0;
}
