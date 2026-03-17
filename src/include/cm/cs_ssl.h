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
 * cs_ssl.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cs_ssl.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CS_SSL_H
#define CS_SSL_H

#include "cm_defs.h"
#include "cm_ssl_base.h"
#include "utils/syscall_lock.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SERVER_CIPHER,
    CLIENT_CIPHER,
    HADR_CIPHER
} CipherMode;

typedef struct st_ssl_config {
    char *ca_file;
    char *cert_file;
    char *key_file;
    char *key_password;
    char *crl_file;
    char *cipher;
    bool verify_peer;
} ssl_config_t;

typedef enum en_ssl_verify {
    VERIFY_SSL,
    VERIFY_CERT,
    VERIFY_ISSUER,
    VERIFY_SUBJECT
} ssl_verify_t;

typedef enum en_cert_type {
    CERT_TYPE_SERVER_CERT,
    CERT_TYPE_CA_CERT
} cert_type_t;

/**
 * create a new ssl context object for acceptor (server side).
 * @param [in]   ca_file      SSL CA file path
 * @param [in]   cert_file    SSL certificate file path
 * @param [in]   key_file     SSL private key file path
 * @param [in]   verify_client Indicates whether verify the client cert
 * @return  ssl context worked as a framework for ssl/tls function on success, NULL on failure
 */
ssl_ctx_t *cm_ssl_create_acceptor_fd(ssl_config_t *config);

/**
 * create a new ssl context object for connector (client side).
 * @param [in]   ca_file      SSL CA file path
 * @param [in]   cert_file    SSL certificate file path
 * @param [in]   key_file     SSL private key file path
 * @param [in]   is_client    setting for ssl
 * @return  ssl context worked as a framework for ssl/tls function on success, NULL on failure
 */
ssl_ctx_t *cm_ssl_create_connector_fd(ssl_config_t *config);

/**
 * free a ssl context object.
 * @param [in] pSslContext ssl context
 * @return  void
 */
void cm_ssl_free_context(ssl_ctx_t *sslCtx);

/**
 * accept a client with a tcp socket
 * @param [in,out]  link   ssl link with context created
 * @param [in]      sock   tcp socket already accepted
 * @param [in]      timeout       timeout, unit:ms; block if < 0
 * @return
 * @retval CM_SUCCESS  accept a client successfully
 * @retval GS_TIMEOUT  accept timeout, no incoming client
 * @retval CM_ERROR   ssl connection is shutdown
 */
status_t cm_cs_ssl_accept_socket(ssl_link_t *link, socket_t sock, uint32 timeout);

/**
 * create a ssl connect with a tcp socket
 * @param [in|out]  SSL link with context created
 * @param [in]      sock tcp socket already connected
 * @param [in]      timeout  timeout, unit: ms
 * @return
 * @retval CM_SUCCESS  connect to the server successfully
 * @retval GS_TIMEOUT  connect timeout
 * @retval CM_ERROR    ssl connection is shutdown or other errors
 */
status_t cm_ssl_connect_socket(ssl_link_t *link, socket_t sock, int32 timeout);

status_t cm_cs_ssl_accept(ssl_ctx_t *fd, cs_pipe_t *pipe);

/**
 * write specified number of bytes, till success or timeout
 * @param [in]      link      ssl socket link
 * @param [in]      buf       data buffer
 * @param [in]      size      input data length
 * @param [out]     send_size sent data length
 * @return
 * @retval CM_SUCCESS      write successfully
 * @retval CM_ERROR        other error
*/
status_t cm_cs_ssl_send(ssl_link_t *link, const char *buf, uint32 size, int32 *send_size);
status_t cm_cs_ssl_send_timed(ssl_link_t *link, const char *buf, uint32 size, uint32 timeout);

/**
 * read specified number of bytes, till success or timeout
 * @param [in]      link      ssl socket link
 * @param [in]      buf       data buffer
 * @param [in]      size      data buffer max length
 * @param [out]     recv_size read data length
 * @return
 * @retval CM_SUCCESS      write successfully
 * @retval CM_ERROR        other error
*/
status_t cm_cs_ssl_recv(ssl_link_t *link, char *buf, uint32 size, int32 *recv_size, uint32 *wait_event);

/**
 * wait on SSL socket, till success or timeout
 * @param [in]      link      ssl socket link
 * @param [in]      wait_for  wait event
 * @param [in]      timeout   wait timeout
 * @param [out]     ready     wait event occured
 * @return
 * @retval CM_SUCCESS      write successfully
 * @retval CM_ERROR        other error
 */
status_t cm_cs_ssl_wait(ssl_link_t *link, uint32 wait_for, int32 timeout, bool *ready);

/*
  Check ssl certificate file access permission,
  the file should not have group or world access permission

  @param[in] file_name    ssl certificate file name

  RETURN VALUES
  @retval CM_SUCCESS Success
  @retval CM_ERROR   Failed to verify
*/


status_t cm_ssl_verify_file_stat(const char *file_name);

void cm_ssl_ca_cert_expire(const ssl_ctx_t *ssl_context, int32 alert_day);

status_t cm_cs_ssl_connect(ssl_ctx_t *fd, cs_pipe_t *pipe);

bool ReadContentFromFile(const char *filename, void *content, size_t csize);

status_t cm_verify_ssl_key_pwd(char *plain, uint32 size, CipherMode mode);

void CsDisconnect(cs_pipe_t *pipe, int32 type, int32 *socket);

#ifdef __cplusplus
}
#endif

#endif
