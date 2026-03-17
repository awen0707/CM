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
 * cm_etcdapi.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_adapter/cm_etcdapi/cm_etcdapi.cpp
 *
 * -------------------------------------------------------------------------
 */
#include <iostream>
#include <regex.h>
#include <thread>
#include <unistd.h>
#include "libclientv3.h"
#include "cm/cm_c.h"
#include "cm_etcdapi.h"

#define ETCD_SERVER_SEPARATOR "\n\r\t ,;"
#define IP_PATTERN\
    "([0-9]|[1-9][0-9]|1[0-9]{1,2}|2[0-4][0-9]|25[0-5]).([0-9]|[1-9][0-9]|1[0-9]{1,2}|2[0-4][0-9]|25[0-5]).([0-9]|[1-" \
    "9][0-9]|1[0-9]{1,2}|2[0-4][0-9]|25[0-5]).([0-9]|[1-9][0-9]|1[0-9]{1,2}|2[0-4][0-9]|25[0-5])"\
    "|(^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$)"\
    "|(^([0-9a-fA-F]{1,4}:){1,7}:$)"\
    "|(^([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$)"

#define PORT_PATTERN "([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])"
#define URL_PATTERN "^(" IP_PATTERN ":" PORT_PATTERN "([" ETCD_SERVER_SEPARATOR "]" IP_PATTERN ":" PORT_PATTERN ")*)$"
const int DECIMAL_BASE = 10;
const unsigned short MAX_PORT_NUMBER = 65535;

static THR_LOCAL char g_err[ERR_LEN] = {0};

/* the url format is: etcd_ip1:etcd_port1,etcd_ip2:etcd_port2 */
bool IsFormatCorrect(const char* url)
{
    bool isCorrect = false;
    regex_t reg;
    int retval = regcomp(&reg, URL_PATTERN, REG_EXTENDED | REG_NEWLINE);
    if (retval != 0) {
        regfree(&reg);
        return isCorrect;
    }

    retval = regexec(&reg, url, 0, NULL, 0);
    if (retval == 0) {
        isCorrect = true;
    }

    regfree(&reg);
    return isCorrect;
}

/*
 * Convert the parameters required by the etcd_open_client into the GO language
 * to facilitate the invoking of the golang interface.
 */
errno_t EtcdOpenInit(EtcdServerSocket* serverList, GoSlice* serverListInGo, const EtcdTlsAuthPath* tlsPath,
    EtcdTlsAuth* tlsPathInGo)
{
    errno_t rc = 0;
    EtcdServerSocket* srv;
    int i = 0;

    /* The server list is converted into the form of the EtcdServer structure in the golang. */
    for (srv = serverList; srv->host; srv++) {
        ((EtcdServer*)(*serverListInGo).data + i)->listen_ips = srv->host;
        ((EtcdServer*)(*serverListInGo).data + i)->listen_ports = srv->port;
        i++;
    }

    /* Don't use tls */
    if (tlsPath == NULL || (tlsPath->etcd_ca_path[0] == '\0' && tlsPath->client_crt_path[0] == '\0' &&
                            tlsPath->client_key_path[0] == '\0')) {
        rc = strncpy_s(g_err, ERR_LEN, "Don't use tls.", ERR_LEN - 1);
        securec_check_c(rc, "", "");
        return 0;
    }

    /*
     * Check whether the certificate file exists and read permission. Transfer the content
     * of the certificate structure to the EtcdTlsAuth structure defined in golang
     */
    if (access(tlsPath->etcd_ca_path, F_OK) == 0 && access(tlsPath->etcd_ca_path, R_OK) == 0) {
        tlsPathInGo->etcd_client_ca_path = tlsPath->etcd_ca_path;
    } else {
        rc = strncpy_s(
            g_err, ERR_LEN, "The file etcd_ca_path does not exist or does not have read permissions", ERR_LEN - 1);
        securec_check_c(rc, "", "");
        return -1;
    }

    if (access((*tlsPath).client_crt_path, F_OK) == 0 && access((*tlsPath).client_crt_path, R_OK) == 0) {
        tlsPathInGo->etcd_client_crt_path = tlsPath->client_crt_path;
    } else {
        rc = strncpy_s(
            g_err, ERR_LEN, "The file client_crt_path does not exist or does not have read permissions", ERR_LEN - 1);
        securec_check_c(rc, "", "");
        return -1;
    }

    if (access((*tlsPath).client_key_path, F_OK) == 0 && access((*tlsPath).client_key_path, R_OK) == 0) {
        tlsPathInGo->etcd_client_key_path = tlsPath->client_key_path;
    } else {
        rc = strncpy_s(
            g_err, ERR_LEN, "The file client_key_path does not exist or does not have read permissions", ERR_LEN - 1);
        securec_check_c(rc, "", "");
        return -1;
    }

    return 0;
}

/*
 * The server list, certificate path, and timeout interval are transferred to the golang format.
 * The input parameter is transferred to the etcd_open_client. The etcd_open_client returns the
 * corresponding session index.If the operation is successful, 0 is returned. If the operation
 * fails, -1 is returned.
 * If you don't need encryption communication, the tls_path or it's children can set be null.
 */
int etcd_open(EtcdSession* session, EtcdServerSocket* serverList, const EtcdTlsAuthPath* tlsPath, int timeout)
{
    /* The max timeout is 60s and the min timeout is 1s */
    const int maxTimeout = 60000;
    const int minTimeout = 1000;
    int serverCount = 0;
    /* Defines and initialize the variables required by the golang interface */
    GoSlice serverListInGo = {0};
    EtcdTlsAuth tlsPathInGo = {0};
    errno_t rc = memset_s(g_err, sizeof(g_err), 0, sizeof(g_err));
    securec_check_c(rc, "", "");

    /* Check whether the data is NULL */
    if (session == NULL) {
        rc = strncpy_s(g_err, ERR_LEN, "etcd session is null\n", ERR_LEN - 1);
        securec_check_c(rc, "", "");
        return -1;
    }

    if (serverList == NULL) {
        rc = strncpy_s(g_err, ERR_LEN, "etcd server_list is null\n", ERR_LEN - 1);
        securec_check_c(rc, "", "");
        return -1;
    }

    /* There's no reasons to limit the value of timeout. Just to protect the callers not to set a big value */
    if (timeout > maxTimeout || timeout < minTimeout) {
        rc = strncpy_s(g_err, ERR_LEN, "The value of timeout must be in the range of [1s,60s]\n", ERR_LEN - 1);
        securec_check_c(rc, "", "");
        return -1;
    }

    /* Convert C variable to go variable */
    for (EtcdServerSocket* srv = serverList; srv->host; srv++) {
        serverCount++;
    }
    if (serverCount == 0) {
        rc = strncpy_s(g_err, ERR_LEN, "etcd server_list is empty\n", ERR_LEN - 1);
        securec_check_c(rc, "", "");
        return -1;
    }
    serverListInGo.data = (char *)malloc((size_t)serverCount * sizeof(EtcdServer));
    if (serverListInGo.data == NULL) {
        rc = strncpy_s(g_err, ERR_LEN, "Failed to apply for the memory of server_list_in_go.data\n", ERR_LEN - 1);
        securec_check_c(rc, "", "");
        return -1;
    }
    serverListInGo.len = serverCount;
    serverListInGo.cap = serverCount;
    rc = EtcdOpenInit(serverList, &serverListInGo, tlsPath, &tlsPathInGo);
    if (rc != 0) {
        FREE_AND_RESET(serverListInGo.data);
        return -1;
    }
    /* Invoke the bottom-layer interface to obtain the index of the corresponding session. */
    *session = EtcdOpen(serverListInGo, &tlsPathInGo, timeout, timeout);
    FREE_AND_RESET(serverListInGo.data);
    return 0;
}

/* Delete the session corresponding to the index from the session pool. */
int etcd_close(EtcdSession session)
{
    char* err = EtcdClose(session);
    if (err != NULL) {
        errno_t rc = strncpy_s(g_err, ERR_LEN, err, ERR_LEN - 1);
        securec_check_c(rc, "", "");
        /* Free out of the go */
        free(err);
        return -1;
    }
    return 0;
}

/* Convert the operation information in the C language to the operation information of the cgo */
void EtcdSetInit(SetEtcdOption *option, EtcdSetOption *setOption)
{
    if (option == NULL) {
        return;
    }
    setOption->prev_value = option->prevValue;
    setOption->dir = option->dir;
    setOption->no_value_on_success = option->noValueOnSuccess;
    setOption->prev_exist = option->prevExist;
    setOption->prev_index = option->prevIndex;
    setOption->refresh = option->refresh;
    setOption->ttl = option->ttl;
}

/*
 * Change the value of the corresponding parameter to golang and transfer the value of etcd_set_client.
 * If the setting is successful, 0 is returned. If the operation fails, -1 is returned
 */
int etcd_set(EtcdSession session, char* key, char* value, SetEtcdOption* option)
{
    errno_t rc = memset_s(g_err, sizeof(g_err), 0, sizeof(g_err));
    securec_check_c(rc, "", "");

    if (key == NULL) {
        rc = strncpy_s(g_err, ERR_LEN, "etcd set key is null\n", ERR_LEN - 1);
        securec_check_c(rc, "", "");
        return -1;
    }
    if (value == NULL) {
        rc = strncpy_s(g_err, ERR_LEN, "etcd set value is null\n", ERR_LEN - 1);
        securec_check_c(rc, "", "");
        return -1;
    }

    /* Variable initialization and  convert C variable to go variable */
    EtcdSetOption setOption;
    rc = memset_s(&setOption, sizeof(EtcdSetOption), 0, sizeof(EtcdSetOption));
    securec_check_c(rc, "", "");

    EtcdSetInit(option, &setOption);

    char* errInGo = EtcdPut(session, key, value, &setOption);
    if (errInGo != NULL) {
        rc = strncpy_s(g_err, ERR_LEN, errInGo, ERR_LEN - 1);
        securec_check_c(rc, "", "");
        /* free out of the go */
        free(errInGo);
        return -1;
    }
    return 0;
}

/* get the length of the first field of text splited by separator */
int GetFirstFieldLen(const char *text, const char *separator)
{
    int lenAnswer = 0;

    for (; *text; text++) {
        if (strchr(separator, *text) != NULL) {
            break;
        }
        ++lenAnswer;
    }
    return lenAnswer;
}

int InitServerList(const char *serverPtr, EtcdServerSocket **serverList)
{
    errno_t rc;
    int serverLen;
    size_t numServers = 0;

    while (*serverPtr) {
        serverLen = GetFirstFieldLen(serverPtr, ETCD_SERVER_SEPARATOR);
        if (!serverLen) {
            /* end of server_ptr */
            break;
        }

        ++numServers;
        /* add server_len and one byte separator len */
        serverPtr += serverLen + 1;
    }

    if (!numServers) {
        rc = strncpy_s(g_err, ERR_LEN, "The server_names don't have any server\n", ERR_LEN - 1);
        securec_check_c(rc, "", "");
        return -1;
    }

    size_t size = (numServers + 1) * sizeof(EtcdServerSocket);
    *serverList = (EtcdServerSocket*)malloc(size);
    if (*serverList == NULL) {
        rc = strncpy_s(g_err, ERR_LEN, "Failed to apply for the memory of server_list\n", ERR_LEN - 1);
        securec_check_c(rc, "", "");
        return -1;
    }

    rc = memset_s(*serverList, size, 0, size);
    if (rc != 0) {
        FREE_AND_RESET(*serverList);
        securec_check_c(rc, "", "");
        return -1;
    }

    return 0;
}

void FreeServerList(EtcdServerSocket *serverList)
{
    size_t numServers;

    for (numServers = 0; serverList[numServers].host; numServers++) {
        FREE_AND_RESET(serverList[numServers].host);
    }
    FREE_AND_RESET(serverList);
}

/*
 * Enter a string containing multiple sockets, parse server list, and then invoke etcd_open
 * to obtain the corresponding session index.
 */
int etcd_open_str(EtcdSession* session, char* serverNames, const EtcdTlsAuthPath* tlsPath, int timeOut)
{
    errno_t rc;
    int serverLen;
    int hostLen;
    int openAnswer;
    size_t serverIndex = 0;
    EtcdServerSocket* serverList = NULL;

    rc = memset_s(g_err, sizeof(g_err), 0, sizeof(g_err));
    securec_check_c(rc, "", "");

    /* check whether the fomat of server_names is corret */
    if (!IsFormatCorrect(serverNames)) {
        rc = strncpy_s(g_err, ERR_LEN, "The format of server_names is not correct\n", ERR_LEN - 1);
        securec_check_c(rc, "", "");
        return -1;
    }

    /*
     * Yeah, we iterate over the string twice so we can allocate an
     * appropriately sized array instead of turning it into a linked list.
     * Unfortunately this means we can't use strtok* whiserver_ptr is destructive
     * with no platform-independent way to reverse the destructive effects.
     */
    if (InitServerList(serverNames, &serverList) == -1) {
        return -1;
    }

    char *serverPtr = serverNames;
    while (*serverPtr) {
        serverLen = GetFirstFieldLen(serverPtr, ETCD_SERVER_SEPARATOR);
        if (!serverLen) {
            /* end of server_ptr */
            break;
        }
        hostLen = GetFirstFieldLen(serverPtr, ":");
        if ((serverLen - hostLen) > 1) {
            serverList[serverIndex].host = strndup(serverPtr, (size_t)hostLen);
            serverList[serverIndex].port = (unsigned short)strtoul(serverPtr + hostLen + 1, NULL, DECIMAL_BASE);
            if (serverList[serverIndex].port == 0) {
                goto ERR_OUT;
            }
        } else {
            goto ERR_OUT;
        }
        ++serverIndex;
        /* add server_len and one byte separator len */
        serverPtr += serverLen + 1;
    }
    openAnswer = etcd_open(session, serverList, tlsPath, timeOut);
    FreeServerList(serverList);
    if (openAnswer != 0) {
        return -1;
    }
    return ETCD_OK;

ERR_OUT:
    /* It should never happen, as has checked format before. */
    FreeServerList(serverList);
    return -1;
}

/* Convert the operation information in the C language to the operation information of the cgo */
void EtcdGetInit(const GetEtcdOption* option, EtcdGetOption* getOption)
{
    if (option == NULL) {
        return;
    }

    getOption->quorum = option->quorum;
    getOption->recursive = option->recursive;
    getOption->sort = option->sort;
    return;
}

/*
 * Change the value of the corresponding parameter to golang and transfer the value of etcd_get_client.
 * If the getting is successful, 0 is returned. If the operation fails, -1 is returned.The obtained
 * value is transferred in the form of an input parameter. The callers must guarantee the buffer size of
 * the value is larger than the data size + 1;
 */
int etcd_get(EtcdSession session, char* key, char* value, int maxSize, const GetEtcdOption* option)
{
    errno_t rc = memset_s(g_err, sizeof(g_err), 0, sizeof(g_err));
    securec_check_c(rc, "", "");

    if (key == NULL) {
        rc = strncpy_s(g_err, ERR_LEN, "etcd get key is null\n", ERR_LEN - 1);
        securec_check_c(rc, "", "");
        return -1;
    }
    if (value == NULL || maxSize <= 0) {
        rc = strncpy_s(g_err, ERR_LEN, "etcd get value is null or size is 0\n", ERR_LEN - 1);
        securec_check_c(rc, "", "");
        return -1;
    }

    rc = memset_s(value, (size_t)maxSize, 0, (size_t)maxSize);
    securec_check_c(rc, "", "");

    /* Variable initialization and  convert C variable to go variable */
    EtcdGetOption getOption = {0};
    EtcdGetInit(option, &getOption);

    EtcdGet_return ret = EtcdGet(session, key, &getOption);
    char* valueInGo = ret.r0;
    char* errInGo = ret.r1;

    if (errInGo != NULL) {
        rc = strncpy_s(g_err, ERR_LEN, errInGo, ERR_LEN - 1);
        securec_check_c(rc, "", "");
        free(errInGo);
        return -1;
    }

    rc = strncpy_s(value, (size_t)maxSize, valueInGo, strlen(valueInGo));
    securec_check_c(rc, "", "");
    value[maxSize - 1] = '\0';
    free(valueInGo);

    return 0;
}

/*
 * Change the value of the corresponding parameter to golang and transfer the value of etcd_get_client.
 * If the getting is successful, 0 is returned. If the operation fails, -1 is returned.The obtained
 * value is transferred in the form of an input parameter. The callers must guarantee the buffer size of
 * the value is larger than the data size + 1;
 */
int EtcdGetAllValues(EtcdSession session, char* key, char *keyValue, const GetEtcdOption* option, int valueSize)
{
    errno_t rc = memset_s(g_err, sizeof(g_err), 0, sizeof(g_err));
    securec_check_c(rc, "", "");

    if (key == NULL) {
        rc = strncpy_s(g_err, ERR_LEN, "etcd get key is null\n", ERR_LEN - 1);
        securec_check_c(rc, "", "");
        return -1;
    }
    if (keyValue == NULL) {
        rc = strncpy_s(g_err, ERR_LEN, "etcd get value is null or size is 0\n", ERR_LEN - 1);
        securec_check_c(rc, "", "");
        return -1;
    }

    /* Variable initialization and  convert C variable to go variable */
    EtcdGetOption getOption = {0};
    EtcdGetInit(option, &getOption);

    EtcdGetAllValue_return ret = EtcdGetAllValue(session, key, &getOption);
    char *keyValueInGo = ret.r0;
    char *errInGo = ret.r1;
    if (errInGo != NULL) {
        rc = strncpy_s(g_err, ERR_LEN, errInGo, ERR_LEN - 1);
        securec_check_c(rc, "", "");
        free(errInGo);
        return -1;
    }
    rc = strncpy_s(keyValue, (size_t)valueSize, keyValueInGo, (size_t)valueSize - 1);
    securec_check_c(rc, "", "");
    free(keyValueInGo);
    return 0;
}

/* Convert the operation information in the C language to the operation information of the cgo */
void EtcdDeleteInit(DeleteEtcdOption* option, EtcdDeleteOption* deleteOption)
{
    if (option == NULL) {
        return;
    }

    deleteOption->dir = option->dir;
    deleteOption->prev_index = option->prevIndex;
    deleteOption->prev_value = option->prevValue;
    deleteOption->recursive = option->recursive;
}

/*
 * Change the value of the corresponding parameter to golang and transfer the value
 * to etcd_delete_client. If the key is successfully deleted, 0 is returned.
 * If the operation fails, -1 is returned.
 */
int etcd_delete(EtcdSession session, char* key, DeleteEtcdOption* option)
{
    errno_t rc = memset_s(g_err, sizeof(g_err), 0, sizeof(g_err));
    securec_check_c(rc, "", "");

    if (key == NULL) {
        rc = strncpy_s(g_err, ERR_LEN, "etcd delete key is null\n", ERR_LEN - 1);
        securec_check_c(rc, "", "");
        return -1;
    }

    /* Variable initialization and  convert C variable to go variable */
    EtcdDeleteOption deleteOption = {0};
    EtcdDeleteInit(option, &deleteOption);

    char* errInGo = EtcdDelete(session, key, &deleteOption);
    if (errInGo != NULL) {
        rc = strncpy_s(g_err, ERR_LEN, errInGo, ERR_LEN - 1);
        securec_check_c(rc, "", "");
        free(errInGo);
        return -1;
    }
    return 0;
}

/*
 * etcd_cluster_health obtains the etcd server state by member_name. If the
 * If the member_name is not set the cluter state will be returned.
 */
int etcd_cluster_health(EtcdSession session, char* memberName, char* healthState, int stateSize)
{
    errno_t rc = memset_s(g_err, sizeof(g_err), 0, sizeof(g_err));
    securec_check_c(rc, "", "");

    if (healthState == NULL || stateSize <= 0) {
        rc = strncpy_s(g_err, ERR_LEN, "The health_state parameter is null or the buffer size is 0\n", ERR_LEN - 1);
        securec_check_c(rc, "", "");
        return -1;
    }
    rc = memset_s(healthState, (size_t)stateSize, 0, (size_t)stateSize);
    securec_check_c(rc, "", "");

    /* Variable initialization and  convert C variable to go variable */
    EtcdClusterHealth_return healthRet = EtcdClusterHealth(session, memberName);
    char* healthMemberInGo = healthRet.r0;
    char* errInGo = healthRet.r1;
    if (errInGo != NULL) {
        rc = strncpy_s(g_err, ERR_LEN, errInGo, ERR_LEN - 1);
        securec_check_c(rc, "", "");
        free(errInGo);
        /* EtcdClusterHealth should assure health_member_in_go is NULL when err_in_go is not NULL. */
        return -1;
    }

    rc = strncpy_s(healthState, (size_t)stateSize, healthMemberInGo, strlen(healthMemberInGo));
    securec_check_c(rc, "", "");
    healthState[stateSize - 1] = '\0';
    free(healthMemberInGo);
    return 0;
}

/*
 * The parameter is converted to the golang format and transferred to the
 * etcd_cluster_state_client as the input parameter. If the parameter is
 * successfully set, 0 is returned. If the parameter fails to be returned,
 * -1 is returned. Check whether a node is a leader through the is_leader.
 */
int etcd_cluster_state(EtcdSession session, char* memberName, bool* isLeader)
{
    errno_t rc = memset_s(g_err, sizeof(g_err), 0, sizeof(g_err));
    securec_check_c(rc, "", "");

    if (memberName == NULL) {
        rc = strncpy_s(g_err, ERR_LEN, "etcd member_name is null\n", ERR_LEN - 1);
        securec_check_c(rc, "", "");
        return -1;
    }
    if (isLeader == NULL) {
        rc = strncpy_s(g_err, ERR_LEN, "etcd cluster state is_leader is null\n", ERR_LEN - 1);
        securec_check_c(rc, "", "");
        return -1;
    }

    /* Variable initialization and  convert C variable to go variable */
    EtcdServerState_return ret = EtcdServerState(session, memberName);
    char* errInGo = ret.r1;
    *isLeader = ret.r0;
    if (errInGo != NULL) {
        rc = strncpy_s(g_err, ERR_LEN, errInGo, ERR_LEN - 1);
        securec_check_c(rc, "", "");
        free(errInGo);
        return -1;
    }
    return 0;
}

/*
 * Obtains the information that fails to be invoked
 */
const char* get_last_error()
{
    return g_err;
}
