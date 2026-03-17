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
 * cs_ssl.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_communication/cm_protocol/cs_ssl.cpp
 *
 * -------------------------------------------------------------------------
 */
#include "cs_ssl.h"

#include <fcntl.h>
#include <sys/stat.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/x509v3.h"
#include "cm_spinlock.h"
#include "cm_error.h"
#include "securec.h"
#include "cm_cipher.h"
#include "cm_elog.h"
#include "cm_misc_base.h"
#include "cm_text.h"
#include "cm_debug.h"

#ifdef __cplusplus
extern "C" {
#endif

const int SSL_VERIFY_DEPTH = 10;
status_t cm_cs_tcp_wait(tcp_link_t *link, uint32 wait_for, int32 timeout, bool *ready);
int32 cm_cs_tcp_poll(struct pollfd *fds, uint32 nfds, int32 timeout);
void cm_cs_tcp_disconnect(tcp_link_t *link);
static status_t CmRealpathFile(const char *filename, char *realfile, uint32 real_path_len);

#define CM_SSL_FREE_CTX_AND_RETURN(err, ctx, ret)                         \
    do {                                                                  \
        CM_THROW_ERROR(ERR_SSL_INIT_FAILED, cm_cs_ssl_init_err_string(err)); \
        SSL_CTX_free(ctx);                                                \
        return ret;                                                       \
    } while (0)

#define CM_SSL_EMPTY_STR_TO_NULL(str)        \
    if ((str) != NULL && (str)[0] == '\0') { \
        (str) = NULL;                        \
    }

#define SSL_CTX_PTR(ctx) ((SSL_CTX*)(ctx))
#define SSL_SOCK(sock)   ((SSL*)(sock))

static spinlock_t g_ssl_init_lock = 0;
static volatile bool g_ssl_initialized = false;
static spinlock_t g_get_pem_passwd_lock = 0;

static const char * const g_sslDefaultCipherList = "ECDHE-ECDSA-AES256-GCM-SHA384:"
                                        "ECDHE-ECDSA-AES128-GCM-SHA256:"
                                        "ECDHE-RSA-AES256-GCM-SHA384:"
                                        "ECDHE-RSA-AES128-GCM-SHA256";

static const char * const g_sslTls13DefaultCipherList = "TLS_AES_256_GCM_SHA384:"
                                              "TLS_CHACHA20_POLY1305_SHA256:"
                                              "TLS_AES_128_GCM_SHA256:"
                                              "TLS_AES_128_CCM_8_SHA256:"
                                              "TLS_AES_128_CCM_SHA256";

const char *g_sslCipherNames[] = {
    // GCM
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256",
    NULL
};

const char *g_sslTls13CipherNames[] = {
    // TLS1.3
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_128_CCM_8_SHA256",
    "TLS_AES_128_CCM_SHA256",
    // TERM
    NULL
};

typedef enum en_ssl_init_error {
    SSL_INITERR_NONE = 0,
    SSL_INITERR_CERT,
    SSL_INITERR_KEY,
    SSL_INITERR_KEYPWD,
    SSL_INITERR_NOMATCH,
    SSL_INITERR_LOAD_CA,
    SSL_INITERR_LOAD_CRL,
    SSL_INITERR_CIPHERS,
    SSL_INITERR_MEMFAIL,
    SSL_INITERR_NO_USABLE_CTX,
    SSL_INITERR_DHFAIL,
    SSL_INITERR_VERIFY,
    SSL_INITERR_VERSION_INVALID,
    SSL_INITERR_SIGNATURE_ALG,
    SSL_INITERR_SET_PURPOSE,
    SSL_INITERR_LASTERR
} ssl_init_error_t;

static const char *g_ssl_error_string[] = {
    "No error",
    "Unable to get certificate",
    "Unable to get private key",
    "Private key password is invalid",
    "Private key does not match the certificate public key",
    "Load CA certificate file failed",
    "Load Certificate revocation list failed",
    "Failed to set ciphers to use",
    "Create new SSL_CTX failed",
    "SSL context is not usable without certificate and private key",
    "SSL_CTX_SET_TEMPDH failed",
    "SSL set verify mode or depth failed",
    "TLS version is invalid",
    "Failed to set signature algorithms",
    "SSL_CTX_set_purpose failed",
    "",
};

#define cs_close_socket   close

bool ReadContentFromFile(const char* filename, void* content, size_t csize)
{
    /* open and read file */
    FILE *pfRead = fopen(filename, "rb");
    if (pfRead == NULL) {
        write_runlog(ERROR, "could not open file \"%s\": %s\n", filename, gs_strerror(errno));
        return false;
    }
    size_t cnt = fread(content, csize, 1, pfRead);
    if (cnt == 0) {
        (void)fclose(pfRead);
        write_runlog(ERROR, "could not read file \"%s\": %s\n", filename, gs_strerror(errno));
        return false;
    }
    if (fclose(pfRead)) {
        write_runlog(ERROR, "could not close file \"%s\": %s\n", filename, gs_strerror(errno));
        return false;
    }

    return true;
}

time_t CmCurrentTime()
{
    return time(NULL);
}

static const char *cm_cs_ssl_init_err_string(ssl_init_error_t err)
{
    if (err > SSL_INITERR_NONE && err < SSL_INITERR_LASTERR) {
        return g_ssl_error_string[err];
    }
    return g_ssl_error_string[0];
}

/*
  Get the last SSL error code and reason
*/
static const char *cm_cs_ssl_last_err_string(char *buf, uint32 size)
{
    buf[0] = '\0';

    ulong err = ERR_get_error();
    if (err) {
        const char *fstr = ERR_func_error_string(err);
        const char *rstr = ERR_reason_error_string(err);

        if (snprintf_s(buf, size, size - 1, "error code = %lu, reason code = %d, ssl function = %s:%s ",
            err, ERR_GET_REASON(err), (fstr ? fstr : "<null>"), (rstr ? rstr : "<null>")) == -1) {
            return buf;
        }
    }
    return buf;
}

/*
Diffie-Hellman key.
Generated using: >openssl dhparam -5 -C 3072
*/
static unsigned char g_dh3072_p[] = {
    0x8D,
    0xAF,
    0xE5,
    0xD7,
    0x9A,
    0x0A,
    0x6A,
    0x9A,
    0xF0,
    0x7F,
    0xF2,
    0xBD,
    0xC2,
    0xE5,
    0x4B,
    0x56,
    0x07,
    0x3F,
    0x81,
    0x02,
    0x0E,
    0x64,
    0xC9,
    0xA4,
    0xA0,
    0x49,
    0x78,
    0xE8,
    0x4C,
    0xD0,
    0x8E,
    0xD7,
    0x1F,
    0x71,
    0xC7,
    0x97,
    0x3F,
    0x5D,
    0x42,
    0x7D,
    0x9F,
    0xC3,
    0x1C,
    0x69,
    0x8C,
    0x81,
    0xA3,
    0x5C,
    0x18,
    0xCA,
    0xED,
    0xBC,
    0xA0,
    0x82,
    0xD8,
    0x01,
    0x78,
    0x6E,
    0x64,
    0xAC,
    0x4A,
    0xB2,
    0x2C,
    0x74,
    0xC1,
    0x8C,
    0x66,
    0x13,
    0xBE,
    0xC8,
    0x7F,
    0x32,
    0x3D,
    0x68,
    0xA5,
    0x12,
    0x98,
    0x86,
    0x86,
    0x3E,
    0xDA,
    0x20,
    0x62,
    0x5F,
    0x47,
    0xDC,
    0x8B,
    0xF6,
    0xF4,
    0x37,
    0xF6,
    0x0A,
    0x9C,
    0xF9,
    0x10,
    0xE9,
    0x5D,
    0x82,
    0xE3,
    0x41,
    0xC1,
    0x9C,
    0x7A,
    0xA3,
    0x77,
    0x54,
    0x28,
    0x6F,
    0x76,
    0xF6,
    0xD5,
    0x29,
    0xCB,
    0x8D,
    0xA8,
    0x18,
    0x51,
    0xCA,
    0xE5,
    0xB3,
    0xF2,
    0xCF,
    0xDA,
    0xB5,
    0x26,
    0x6E,
    0xA5,
    0xB5,
    0x22,
    0x12,
    0x2C,
    0xFC,
    0x53,
    0xAA,
    0x16,
    0xD8,
    0x74,
    0x79,
    0x17,
    0x83,
    0x54,
    0xE8,
    0x40,
    0xC0,
    0x1C,
    0x9E,
    0x95,
    0x7D,
    0x87,
    0x46,
    0x8D,
    0x2F,
    0xA4,
    0x8C,
    0x48,
    0x43,
    0x3C,
    0xC8,
    0x50,
    0x7C,
    0x14,
    0x9A,
    0x5B,
    0x00,
    0xFF,
    0xA0,
    0x7E,
    0x76,
    0xD2,
    0x0E,
    0x97,
    0x56,
    0x2E,
    0xEB,
    0x03,
    0x20,
    0xAC,
    0x41,
    0x61,
    0x73,
    0xB8,
    0x7A,
    0x9F,
    0x07,
    0xDB,
    0xA5,
    0x4F,
    0x20,
    0x3D,
    0x9D,
    0x01,
    0x7C,
    0x06,
    0x56,
    0x3E,
    0xA1,
    0x18,
    0x22,
    0xB9,
    0x36,
    0x1D,
    0x80,
    0xD3,
    0xC5,
    0x9B,
    0x4F,
    0x03,
    0x99,
    0x72,
    0x1A,
    0x86,
    0xC6,
    0x82,
    0xC9,
    0x87,
    0x75,
    0x9A,
    0xF9,
    0xFA,
    0xC1,
    0x6F,
    0x71,
    0x0E,
    0x83,
    0x80,
    0x3B,
    0x1E,
    0x92,
    0xA5,
    0x7D,
    0xB3,
    0x82,
    0xB0,
    0xB9,
    0x92,
    0x08,
    0x40,
    0x32,
    0x50,
    0xEE,
    0x95,
    0x08,
    0x48,
    0x4C,
    0x0A,
    0x2D,
    0x88,
    0x82,
    0x94,
    0x1A,
    0x47,
    0x22,
    0xE2,
    0x98,
    0x0B,
    0x80,
    0x22,
    0xBB,
    0x65,
    0x7C,
    0x45,
    0x63,
    0xC9,
    0xF4,
    0xC1,
    0x90,
    0x89,
    0xBE,
    0x61,
    0x3A,
    0x88,
    0xF4,
    0x3A,
    0x24,
    0xE2,
    0x7E,
    0x0D,
    0xF1,
    0x4C,
    0xFF,
    0x47,
    0xF9,
    0x7E,
    0xFA,
    0x1D,
    0xE4,
    0x59,
    0x43,
    0xFD,
    0xDE,
    0x0F,
    0xF5,
    0x36,
    0x9E,
    0x36,
    0x63,
    0x54,
    0x9A,
    0x6C,
    0xB1,
    0xDD,
    0x65,
    0x2F,
    0x11,
    0xF4,
    0x89,
    0xC6,
    0xD2,
    0x21,
    0x1A,
    0x2E,
    0x5A,
    0x2B,
    0x8B,
    0x26,
    0xDF,
    0x5B,
    0x68,
    0x6A,
    0xF3,
    0xFE,
    0xA7,
    0x3D,
    0x2F,
    0x1D,
    0x45,
    0xFB,
    0xAE,
    0xE2,
    0x98,
    0x78,
    0x2F,
    0xB8,
    0x74,
    0x94,
    0x87,
    0x3A,
    0x6B,
    0x1A,
    0xB4,
    0x45,
    0xB5,
    0xAA,
    0x13,
    0x3E,
    0xDD,
    0x70,
    0x49,
    0x6F,
    0x97,
    0x78,
    0x9B,
    0xDA,
    0xED,
    0xF1,
    0x6B,
    0x33,
    0x76,
    0x49,
    0xEE,
    0xB3,
    0xFF,
    0xF2,
    0x14,
    0x12,
    0xB4,
    0xE3,
    0xEE,
    0xE5,
    0xB0,
    0xA7,
    0x0B,
    0xDA,
    0xFA,
    0x5B,
    0x22,
    0xCF,
    0x61,
    0xBF,
    0x26,
    0x78,
    0x72,
    0x7B,
    0x1B,
};

static unsigned char g_dh3072_g[] = {
    0x05,
};

/* function to generate DH key pair */
static DH *get_dh3072(void)
{
    DH *dh = DH_new();
    if (dh == NULL) {
        return NULL;
    }

    BIGNUM *p = BN_bin2bn(g_dh3072_p, sizeof(g_dh3072_p), NULL);
    BIGNUM *g = BN_bin2bn(g_dh3072_g, sizeof(g_dh3072_g), NULL);
    if ((p == NULL) || (g == NULL) || !DH_set0_pqg(dh, p, NULL, g)) {
        DH_free(dh);
        BN_free(p);
        BN_free(g);
        return NULL;
    }

    return dh;
}

static void cm_spin_lock(spinlock_t *lock, spin_statis_t *stat)
{
    uint32 spin_times = 0;
    uint32 sleep_times = 0;

    if (SECUREC_UNLIKELY(lock == NULL)) {
        return;
    }

    for (;;) {
#if defined(__arm__) || defined(__aarch64__)
        while (__atomic_load_n(lock, __ATOMIC_SEQ_CST) != 0) {
#else
        while (*lock != 0) {
#endif
            SPIN_STAT_INC(stat, spins);
            spin_times++;
            if (SECUREC_UNLIKELY(spin_times == GS_SPIN_COUNT)) {
                cm_spin_sleep_and_stat(stat);
                spin_times = 0;
            }
        }

        if (SECUREC_LIKELY(cm_spin_set(lock, 1) == 0)) {
            break;
        }

        SPIN_STAT_INC(stat, fails);
        sleep_times++;
#ifndef WIN32
        for (uint32 i = 0; i < sleep_times; i++) {
            fas_cpu_pause();
        }
#endif
    }
}

/**
* Callback function for get PEM info for SSL, add thread lock protect call for 'PEM_def_callback'.
*/
static int32 cm_cs_ssl_cb_get_pem_passwd(char *buf, int size, int rwflag, void *userdata)
{
    int32 ret;
    if (userdata == NULL) {
        cm_spin_lock(&g_get_pem_passwd_lock, NULL);
        ret = PEM_def_callback(buf, size, rwflag, userdata);
        cm_spin_unlock(&g_get_pem_passwd_lock);
    } else {
        ret = PEM_def_callback(buf, size, rwflag, userdata);
    }
    return ret;
}

static status_t cm_cs_ssl_init()
{
    if (g_ssl_initialized) {
        return CM_SUCCESS;
    }

    cm_spin_lock(&g_ssl_init_lock, NULL);

    if (g_ssl_initialized) {
        cm_spin_unlock(&g_ssl_init_lock);
        return CM_SUCCESS;
    }

    if (OPENSSL_init_ssl(OPENSSL_INIT_SSL_DEFAULT, NULL) == 0) {
        cm_spin_unlock(&g_ssl_init_lock);
        write_runlog(ERROR, "Init SSL library failed");
        return CM_ERROR;
    }

    g_ssl_initialized = true;
    cm_spin_unlock(&g_ssl_init_lock);
    return CM_SUCCESS;
}

static void cm_cs_ssl_deinit()
{
    if (!g_ssl_initialized) {
        return;
    }
}

/**
 * Obtain the equivalent system error status for the last SSL I/O operation.
 *
 * @param ssl_err  The result code of the failed TLS/SSL I/O operation.
 */
static void cm_cs_ssl_set_sys_error(int32 ssl_err)
{
    int32 error = 0;
    switch (ssl_err) {
        case SSL_ERROR_ZERO_RETURN:
            error = ECONNRESET;
            break;
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_CONNECT:
        case SSL_ERROR_WANT_ACCEPT:
            error = EWOULDBLOCK;
            break;
        case SSL_ERROR_SSL:
        /* Protocol error */
#ifdef EPROTO
            error = EPROTO;
#else
            error = ECONNRESET;
#endif
            break;
        default:
            error = ECONNRESET;
            break;
    }

    /* Set error status to equivalent of the SSL error */
    if (error != 0) {
        CmSetSockError(error);
    }
}

static status_t cm_cs_ssl_match_cipher(const text_t *left, char *cipher, uint32_t *offset, bool *support, bool is_tls13)
{
    uint32 i, count;
    errno_t errcode;
    const char** cipher_list;
    if (is_tls13) {
        count = ELEMENT_COUNT(g_sslTls13CipherNames) - 1;
        cipher_list = g_sslTls13CipherNames;
    } else {
        count = ELEMENT_COUNT(g_sslCipherNames) - 1;
        cipher_list = g_sslCipherNames;
    }

    for (i = 0; i < count; i++) {
        if (!CmTextStrEqualIns(left, cipher_list[i])) {
            continue;
        }
        *support = true;
        if (*offset > 0) {
            errcode = strncpy_s(cipher + *offset, CM_MAX_SSL_CIPHER_LEN - *offset, ":", strlen(":"));
            if (errcode != EOK) {
                write_runlog(ERROR, "[cm_cs_ssl_match_cipher] system call error, offset > 0");
                return CM_ERROR;
            }
            *offset += 1;
        }
        errcode = strncpy_s(cipher + *offset, CM_MAX_SSL_CIPHER_LEN - *offset, left->str, left->len);
        if (errcode != EOK) {
            write_runlog(ERROR, "[cm_cs_ssl_match_cipher] system call error");
            return CM_ERROR;
        }
        *offset += left->len;
        break;
    }

    return CM_SUCCESS;
}

static status_t cm_cs_ssl_distinguish_cipher(const char *cipher, char *tls12_cipher, uint32_t *tls12_offset,
    char *tls13_cipher, uint32_t *tls13_offset)
{
    bool support = false;
    text_t text, left, right;

    CmStr2Text((char *)cipher, &text);
    CmSplitText(&text, ':', '\0', &left, &right);
    text = right;

    while (left.len > 0) {
        support = false;
        // match TLS1.2-cipher
        if (cm_cs_ssl_match_cipher(&left, tls12_cipher, tls12_offset, &support, false) != CM_SUCCESS) {
            return CM_ERROR;
        }

        if (!support) {
            // match TLS1.3-cipher
            if (cm_cs_ssl_match_cipher(&left, tls13_cipher, tls13_offset, &support, true) != CM_SUCCESS) {
                return CM_ERROR;
            }
        }

        /* cipher not supported or invalid */
        if (!support) {
            return CM_ERROR;
        }

        CmSplitText(&text, ':', '\0', &left, &right);
        text = right;
    }

    return CM_SUCCESS;
}

static status_t cm_cs_ssl_set_cipher(SSL_CTX *ctx, const ssl_config_t *config, bool *is_using_tls13)
{
    char tls12_cipher[CM_MAX_SSL_CIPHER_LEN] = { 0 };
    char tls13_cipher[CM_MAX_SSL_CIPHER_LEN] = { 0 };
    uint32_t tls12_len = 0;
    uint32_t tls13_len = 0;
    const char *tls12_cipher_str = NULL;
    const char *tls13_cipher_str = NULL;

    if (!CM_IS_EMPTY_STR(config->cipher)) {
        if (cm_cs_ssl_distinguish_cipher(config->cipher, tls12_cipher, &tls12_len, tls13_cipher, &tls13_len) !=
            CM_SUCCESS) {
            return CM_ERROR;
        }

        if (tls12_len > 0) {
            tls12_cipher_str = tls12_cipher;
        } else {
            tls12_cipher_str = g_sslDefaultCipherList;
        }

        if (tls13_len > 0) {
            *is_using_tls13 = true;
            tls13_cipher_str = tls13_cipher;
        } else {
            tls13_cipher_str = g_sslTls13DefaultCipherList;
        }
    } else {
        /* load default cipher list if SSL_CIPHER is not specified */
        tls12_cipher_str = g_sslDefaultCipherList;
        tls13_cipher_str = g_sslTls13DefaultCipherList;
        *is_using_tls13 = true;
    }

    if (tls12_cipher_str != NULL && SSL_CTX_set_cipher_list(ctx, tls12_cipher_str) != 1) {
        return CM_ERROR;
    }

    if (tls13_cipher_str != NULL && SSL_CTX_set_ciphersuites(ctx, tls13_cipher_str) != 1) {
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static inline void cm_cs_ssl_fetch_file_name(text_t *files, text_t *name)
{
    if (!CmFetchText(files, ',', '\0', name)) {
        return;
    }

    CmTrimText(name);
    if (name->str[0] == '\'') {
        name->str++;
        if (name->len >= 2) {
            name->len -= 2;
        } else {
            name->len = 0;
        }

        CmTrimText(name);
    }
}

static status_t cm_cs_ssl_set_ca_chain(SSL_CTX *ctx, ssl_config_t *config, bool is_client)
{
    text_t file_list, file_name;
    char filepath[CM_FILE_NAME_BUFFER_SIZE] = {0};

    if (config->ca_file == NULL) {
        return CM_SUCCESS;
    }
    CmStr2Text((char *)config->ca_file, &file_list);
    CmRemoveBrackets(&file_list);

    cm_cs_ssl_fetch_file_name(&file_list, &file_name);
    while (file_name.len > 0) {
        CM_RETURN_IFERR(CmText2Str(&file_name, filepath, sizeof(filepath)));

        if (cm_ssl_verify_file_stat(filepath) != CM_SUCCESS) {
            if (!is_client) {
                write_runlog(FATAL, "exit\n");
                cm_exit(-1);
            }
            return CM_ERROR;
        }

        if (SSL_CTX_load_verify_locations(ctx, filepath, NULL) == 0) {
            write_runlog(ERROR, "SSL_CTX_load_verify_locations failed\n");
            return CM_ERROR;
        }
        cm_cs_ssl_fetch_file_name(&file_list, &file_name);
    }

    return CM_SUCCESS;
}

static status_t cm_cs_load_crl_file(SSL_CTX *ctx, const char *file)
{
    long ret;

    BIO *in = BIO_new(BIO_s_file());
    if (in == NULL || BIO_read_filename(in, file) <= 0) {
        return CM_ERROR;
    }

    X509_CRL *crl = PEM_read_bio_X509_CRL(in, NULL, NULL, NULL);
    if (crl == NULL) {
        (void)BIO_free(in);
        return CM_ERROR;
    }

    X509_STORE *st = SSL_CTX_get_cert_store(ctx);
    if (!X509_STORE_add_crl(st, crl)) {
        X509_CRL_free(crl);
        (void)BIO_free(in);
        return CM_ERROR;
    }

    ret = SSL_CTX_set1_verify_cert_store(ctx, st);
    X509_CRL_free(crl);
    (void)BIO_free(in);

    return ret == 1 ? CM_SUCCESS : CM_ERROR;
}

static status_t cm_cs_ssl_set_crl_file(SSL_CTX *ctx, ssl_config_t *config)
{
    text_t file_list, file_name;
    char filepath[CM_FILE_NAME_BUFFER_SIZE];

    if (config->crl_file != NULL) {
        CmStr2Text((char *)config->crl_file, &file_list);
        CmRemoveBrackets(&file_list);

        cm_cs_ssl_fetch_file_name(&file_list, &file_name);
        while (file_name.len > 0) {
            CM_RETURN_IFERR(CmText2Str(&file_name, filepath, sizeof(filepath)));
            if (cm_cs_load_crl_file(ctx, filepath) != CM_SUCCESS) {
                return CM_ERROR;
            }

            cm_cs_ssl_fetch_file_name(&file_list, &file_name);
        }

        /* Enable CRL checking when performing certificate verification during SSL connections
           associated with an SSL_CTX structure ctx */
        X509_VERIFY_PARAM *param = X509_VERIFY_PARAM_new();
        (void)X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_CRL_CHECK);

        if (!SSL_CTX_set1_param(ctx, param)) {
            X509_VERIFY_PARAM_free(param);
            return CM_ERROR;
        }

        X509_VERIFY_PARAM_free(param);
    }

    return CM_SUCCESS;
}

/**
    This function indicates whether the SSL I / O operation must be retried in the future,
    and clear the SSL error queue, so the next SSL operation can be performed even after
    the iPSI-SSL call fails.

    @param ssl  SSL connection.
    @param ret  a SSL I/O function.
    @param [out] event             The type of I/O event to wait/retry.
    @param [out] ssl_err_holder    The SSL error code.

    @return Whether the SSL I / O operation should be delayed.
    @retval true    Temporary failure, retry operation.
    @retval false   Indeterminate failure.
*/
static bool cm_cs_ssl_should_retry(ssl_link_t *link, int32 ret, uint32 *wait_event, int32 *ssl_err_holder)
{
    int32 ssl_err;
    bool retry = true;
    SSL *ssl = SSL_SOCK(link->ssl_sock);

    /* Retrieve the result for the SSL I/O operation */
    ssl_err = SSL_get_error(ssl, ret);

    switch (ssl_err) {
        case SSL_ERROR_WANT_READ:
            if (wait_event != NULL) {
                *wait_event = CS_WAIT_FOR_READ;
            }
            break;
        case SSL_ERROR_WANT_WRITE:
            if (wait_event != NULL) {
                *wait_event = CS_WAIT_FOR_WRITE;
            }
            break;
        default:
            write_runlog(DEBUG1, "SSL read/write failed. SSL error: %d\n", ssl_err);
            retry = false;
            break;
    }

    if (ssl_err_holder != NULL) {
        (*ssl_err_holder) = ssl_err;
    }

    return retry;
}

static status_t cm_cs_ssl_wait_on_error(ssl_link_t *link, int32 ret, int32 timeout)
{
    int32 ssl_err;
    long v_result;
    uint32 cs_event;
    bool is_ready = false;
    char err_buf[CM_BUFLEN_256] = {0};
    const char *err_msg = NULL;
    SSL *ssl = SSL_SOCK(link->ssl_sock);

    ssl_err = SSL_get_error(ssl, ret);

    switch (ssl_err) {
        case SSL_ERROR_NONE:
            return CM_SUCCESS;
        case SSL_ERROR_WANT_READ:
            cs_event = CS_WAIT_FOR_READ;
            break;
        case SSL_ERROR_WANT_WRITE:
            cs_event = CS_WAIT_FOR_WRITE;
            break;
        default:
            v_result = SSL_get_verify_result(ssl);
            if (v_result != X509_V_OK) {
                err_msg = X509_verify_cert_error_string(v_result);
                write_runlog(ERROR, "SSL verify certificate failed: result code is %ld, %s", v_result, err_msg);
            } else {
                err_msg = cm_cs_ssl_last_err_string(err_buf, sizeof(err_buf));
                write_runlog(ERROR, "SSL connect failed: SSL error %d, %s\n", ssl_err, err_msg);
            }
            ERR_clear_error();
            cm_cs_ssl_set_sys_error(ssl_err);
            return CM_ERROR;
    }

    CM_RETURN_IFERR(cm_cs_tcp_wait(&link->tcp, cs_event, timeout, &is_ready));

    return (is_ready ? CM_SUCCESS : CM_TIMEDOUT);
}

static status_t cm_cs_ssl_resolve_file_name(const char *filename, char *buf, uint32 buf_len, const char **res_buf)
{
    text_t text;
    if (CM_IS_EMPTY_STR(filename) || filename[0] != '\'') {
        *res_buf = filename;
        return CM_SUCCESS;
    }
    CmStr2Text((char *)filename, &text);
    CM_REMOVE_ENCLOSED_CHAR(&text);
    CM_RETURN_IFERR(CmText2Str(&text, buf, buf_len));
    *res_buf = buf;
    return CM_SUCCESS;
}

static status_t cm_cs_ssl_set_cert_auth(SSL_CTX *ctx, const char *cert_file, const char *key_file,
                                     const char *key_pwd)
{
    char file_name[CM_FILE_NAME_BUFFER_SIZE];

    if (cert_file == NULL && key_file != NULL) {
        cert_file = key_file;
    }
    if (cert_file != NULL && key_file == NULL) {
        key_file = cert_file;
    }

    if (cert_file != NULL) {
        CM_RETURN_IFERR(cm_cs_ssl_resolve_file_name(cert_file, file_name, sizeof(file_name), &cert_file));

        if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) != 1) {
            CM_SSL_FREE_CTX_AND_RETURN(SSL_INITERR_CERT, ctx, CM_ERROR);
        }
    }
    if (key_file != NULL) {
        CM_RETURN_IFERR(cm_cs_ssl_resolve_file_name(key_file, file_name, sizeof(file_name), &key_file));

        if (!CM_IS_EMPTY_STR(key_pwd)) {
            SSL_CTX_set_default_passwd_cb_userdata(ctx, (void *)key_pwd);
        }

        if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) != 1) {
            CM_SSL_FREE_CTX_AND_RETURN(SSL_INITERR_KEY, ctx, CM_ERROR);
        }
    }

    if (cert_file != NULL && SSL_CTX_check_private_key(ctx) != 1) {
        CM_SSL_FREE_CTX_AND_RETURN(SSL_INITERR_NOMATCH, ctx, CM_ERROR);
    }
    return CM_SUCCESS;
}

static status_t cm_cs_ssl_set_tmp_dh(SSL_CTX *ctx)
{
    DH *dh = get_dh3072();
    if (dh == NULL) {
        return CM_ERROR;
    }

    if (SSL_CTX_set_tmp_dh(ctx, dh) == 0) {
        DH_free(dh);
        return CM_ERROR;
    }

    DH_free(dh);
    return CM_SUCCESS;
}

/**
 * create a new ssl context object.
 * @param [in]   ca_file      SSL CA file path
 * @param [in]   cert_file    SSL certificate file path
 * @param [in]   key_file     SSL private key file path
 * @param [in]   is_client    setting for ssl
 * @return  pointer to SSL_CTX on success, NULL on failure
 */
static SSL_CTX *cm_ssl_create_context(ssl_config_t *config, bool is_client)
{
    int purpose;
    bool is_using_tls13 = false;

    /* Init SSL library */
    if (cm_cs_ssl_init() != CM_SUCCESS) {
        return NULL;
    }

    /* Set empty string to null */
    CM_SSL_EMPTY_STR_TO_NULL(config->ca_file);
    CM_SSL_EMPTY_STR_TO_NULL(config->cert_file);
    CM_SSL_EMPTY_STR_TO_NULL(config->key_file);
    CM_SSL_EMPTY_STR_TO_NULL(config->crl_file);

    /* Negotiate highest available SSL/TLS version */
    const SSL_METHOD *method = is_client ? TLS_client_method() : TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        CM_THROW_ERROR(ERR_SSL_INIT_FAILED, cm_cs_ssl_init_err_string(SSL_INITERR_MEMFAIL));
        return NULL;
    }

    /* set peer cert's purpose */
    purpose = is_client ? X509_PURPOSE_SSL_SERVER : X509_PURPOSE_SSL_CLIENT;
    if (!SSL_CTX_set_purpose(ctx, purpose)) {
        CM_SSL_FREE_CTX_AND_RETURN(SSL_INITERR_SET_PURPOSE, ctx, NULL);
    }

    /* disable SSLv2, SSLv3, TLSv1.0 and TLSv1.1 */
    (void)SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    /*
      Disable moving-write-buffer sanity check, because it may causes
      unnecessary failures in non-blocking send cases.
     */
    (void)SSL_CTX_set_mode(ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    /* setup PEM info callback. */
    SSL_CTX_set_default_passwd_cb(ctx, cm_cs_ssl_cb_get_pem_passwd);

    /* When choosing a cipher, use the server's preferences instead of the client preferences */
    (void)SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);

    /* Set available cipher suite */
    if (cm_cs_ssl_set_cipher(ctx, config, &is_using_tls13) != CM_SUCCESS) {
        CM_SSL_FREE_CTX_AND_RETURN(SSL_INITERR_CIPHERS, ctx, NULL);
    }

    /* disable TLSv1.3 */
    if (!is_using_tls13) {
        (void)SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_3);
    }

    /* Support CA file chain */
    if (cm_cs_ssl_set_ca_chain(ctx, config, is_client) != CM_SUCCESS) {
        CM_SSL_FREE_CTX_AND_RETURN(SSL_INITERR_LOAD_CA, ctx, NULL);
    }

    /* Load CRL */
    if (cm_cs_ssl_set_crl_file(ctx, config) != CM_SUCCESS) {
        CM_SSL_FREE_CTX_AND_RETURN(SSL_INITERR_LOAD_CRL, ctx, NULL);
    }

    /* Verify cert and key files */
    if (cm_cs_ssl_set_cert_auth(ctx, config->cert_file, config->key_file, config->key_password) != CM_SUCCESS) {
        return NULL;
    }

    /* Server specific check: Must have certificate and key file */
    if (!is_client && config->key_file == NULL && config->cert_file == NULL) {
        CM_SSL_FREE_CTX_AND_RETURN(SSL_INITERR_NO_USABLE_CTX, ctx, NULL);
    }

    /* DH stuff */
    if (cm_cs_ssl_set_tmp_dh(ctx) != CM_SUCCESS) {
        CM_SSL_FREE_CTX_AND_RETURN(SSL_INITERR_DHFAIL, ctx, NULL);
    }

    /* ECDH stuff : ECDH is always enabled now in openssl 1.1.1 version, no need to set */
    return ctx;
}

/*
 * Certificate verification callback
 *
 * This callback allows us to log intermediate problems during
 * verification, but for now we'll see if the final error message
 * contains enough information.
 *
 * This callback also allows us to override the default acceptance
 * criteria(e.g. accepting self-signed or expired certs), but
 * for now we accept the default checks.
 *
 */
static int32 cm_cs_ssl_verify_cb(int32 ok, X509_STORE_CTX *ctx)
{
    return ok;
}

int32 cm_ssl_get_expire_day(const ASN1_TIME *ctm, time_t *curr_time)
{
    int day, sec;

    ASN1_TIME *asn1_cmp_time = X509_time_adj(NULL, 0, curr_time);
    if (asn1_cmp_time == NULL) {
        return -1;
    }

    if (!ASN1_TIME_diff(&day, &sec, asn1_cmp_time, ctm)) {
        return -1;
    }

    return day;
}

void cm_ssl_check_cert_expire(X509 *cert, int32 alert_day, cert_type_t type)
{
    int32 expire_day;
    const char* cert_type = (type == CERT_TYPE_SERVER_CERT) ? "server certificate" : "ca";
    if (cert == NULL) {
        return;
    }

    const ASN1_TIME *not_after = X509_get0_notAfter(cert);
    if (X509_cmp_current_time(not_after) <= 0) {
        write_runlog(ERROR, "[cm_ssl_check_cert_expire] The %s is expired\n", cert_type);
    } else {
        time_t curr_time = CmCurrentTime();
        expire_day = cm_ssl_get_expire_day(not_after, &curr_time);
        write_runlog(DEBUG5, "[cm_ssl_check_cert_expire] The %s expire day is %d\n", cert_type, expire_day);
        if (expire_day >= 0 && alert_day >= expire_day) {
            write_runlog(WARNING, "[cm_ssl_check_cert_expire] The %s will expire in %d days\n", cert_type, expire_day);
        }
    }
}

void cm_ssl_ca_cert_expire(const ssl_ctx_t *ssl_context, int32 alert_day)
{
    SSL_CTX *ctx = SSL_CTX_PTR(ssl_context);

    if (ssl_context == NULL) {
        return;
    }

    X509 *cert = SSL_CTX_get0_certificate(ctx);
    if (cert != NULL) {
        cm_ssl_check_cert_expire(cert, alert_day, CERT_TYPE_SERVER_CERT);
    }

    X509_STORE *cert_store = SSL_CTX_get_cert_store(ctx);
    if (cert_store == NULL) {
        return;
    }

    STACK_OF(X509_OBJECT)* objects = X509_STORE_get0_objects(cert_store);
    for (int i = 0; i < sk_X509_OBJECT_num(objects); i++) {
        X509_OBJECT *obj = sk_X509_OBJECT_value(objects, i);
        /* only check for CA certificate, no need for CRL */
        if (X509_OBJECT_get_type(obj) == X509_LU_X509) {
            cert = X509_OBJECT_get0_X509(obj);
            cm_ssl_check_cert_expire(cert, alert_day, CERT_TYPE_CA_CERT);
        }
    }

    return;
}

ssl_ctx_t *cm_ssl_create_acceptor_fd(ssl_config_t *config)
{
    int32 verify = SSL_VERIFY_PEER;

    /* Cannot verify peer if the server don't have the CA */
    if (CM_IS_EMPTY_STR(config->ca_file)) {
        verify = SSL_VERIFY_NONE;
    } else if (config->verify_peer) {
        verify |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    }

    SSL_CTX *ssl_fd = cm_ssl_create_context(config, false);
    if (ssl_fd == NULL) {
        return NULL;
    }

    /* Init the SSL_CTX as a "acceptor" ie. the server side
       Set max number of cached sessions, returns the previous size */
    (void)SSL_CTX_sess_set_cache_size(ssl_fd, CM_BUFLEN_128);

    /* Set maximum verify depth */
    SSL_CTX_set_verify(ssl_fd, verify, cm_cs_ssl_verify_cb);
    SSL_CTX_set_verify_depth(ssl_fd, SSL_VERIFY_DEPTH);

    /*
      Set session_id - an identifier for this server session
    */
    (void)SSL_CTX_set_session_id_context(ssl_fd, (const unsigned char *)&ssl_fd, sizeof(ssl_fd));
    return (ssl_ctx_t *)ssl_fd;
}

ssl_ctx_t *cm_ssl_create_connector_fd(ssl_config_t *config)
{
    int32 verify = SSL_VERIFY_PEER;
    /*
      Turn off verification of servers certificate if both
      ca_file and ca_path is set to NULL
    */
    if (CM_IS_EMPTY_STR(config->ca_file)) {
        verify = SSL_VERIFY_NONE;
    }

    SSL_CTX *ssl_fd = cm_ssl_create_context(config, true);
    if (ssl_fd == NULL) {
        return NULL;
    }

    /* Init the SSL_CTX as a "connector" ie. the client side */
    SSL_CTX_set_verify(ssl_fd, verify, NULL);
    SSL_CTX_set_verify_depth(ssl_fd, SSL_VERIFY_DEPTH);

    return (ssl_ctx_t *)ssl_fd;
}

void cm_ssl_free_context(ssl_ctx_t *sslCtx)
{
    if (sslCtx == NULL) {
        cm_cs_ssl_deinit();
        return;
    }
    SSL_CTX_free(SSL_CTX_PTR(sslCtx));
    cm_cs_ssl_deinit();
}

static SSL *cm_cs_ssl_create_socket(SSL_CTX *ctx, socket_t sock)
{
    SSL *ssl_sock = SSL_new(ctx);
    if (ssl_sock == NULL) {
        CM_THROW_ERROR(ERR_SSL_INIT_FAILED, "Create SSL socket failed");
        return NULL;
    }
    (void)SSL_clear(ssl_sock);
    if (SSL_set_fd(ssl_sock, (int)sock) == 0) {
        SSL_free(ssl_sock);
        return NULL;
    }
    return ssl_sock;
}

static char *cm_get_common_name(X509_NAME *cert_name, char *buf, uint32 len)
{
    int32 cn_loc;
    errno_t errcode;

    // find cn location in the subject
    cn_loc = X509_NAME_get_index_by_NID(cert_name, NID_commonName, -1);
    if (cn_loc < 0) {
        write_runlog(DEBUG1, "[MEC]failed to get CN location in the certificate subject");
        return "NONE";
    }
    // get cn entry for given location
    X509_NAME_ENTRY *cn_entry = X509_NAME_get_entry(cert_name, cn_loc);
    if (cn_entry == NULL) {
        write_runlog(DEBUG1, "[MEC]failed to get CN entry using CN location");
        return "NONE";
    }
    // get CN from common name entry
    ASN1_STRING *cn_asn1 = X509_NAME_ENTRY_get_data(cn_entry);
    if (cn_asn1 == NULL) {
        write_runlog(DEBUG1, "[MEC]failed to get CN from CN entry");
        return "NONE";
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    char *name = (char *)ASN1_STRING_data(cn_asn1);
#else
    char *name = (char *)ASN1_STRING_get0_data(cn_asn1);
#endif
    if (name == NULL) {
        write_runlog(DEBUG1, "[MEC]failed to get ASN1 data");
        return "NONE";
    }

    if ((size_t)ASN1_STRING_length(cn_asn1) != strlen(name)) {
        write_runlog(DEBUG1, "[MEC]NULL embedded in the certificate CN");
        return "NONE";
    }
    errcode = strncpy_s(buf, len, name, strlen(name));
    if (errcode != EOK) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return "NONE";
    }
    return buf;
}

static void cm_cs_ssl_show_certs(SSL *ssl)
{
    char buf[CM_BUFLEN_512] = {0};

    write_runlog(DEBUG5, "[MEC]SSL connection succeeded");

    const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
    write_runlog(DEBUG5, "[MEC]Using cipher: %s", (cipher == NULL) ? "NONE" : SSL_CIPHER_get_name(cipher));

    write_runlog(DEBUG5, "[MEC]Peer certificate:");
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL) {
        X509_NAME *cert_name = X509_get_subject_name(cert);
        if (cert_name != NULL) {
            write_runlog(DEBUG5, "\tSubject: %s", cm_get_common_name(cert_name, buf, sizeof(buf)));
        }
        cert_name = X509_get_issuer_name(cert);
        if (cert_name != NULL) {
            write_runlog(DEBUG5, "\tIssuer: %s", cm_get_common_name(cert_name, buf, sizeof(buf)));
        }
        X509_free(cert);
    } else {
        write_runlog(DEBUG5, "[MEC]Peer does not have certificate.");
    }
    write_runlog(DEBUG5, "\tSRV_TLS_VERSION: %s", SSL_get_version(ssl));
}

status_t cm_cs_ssl_accept_socket(ssl_link_t *link, socket_t sock, uint32 timeout)
{
    int32 ret;
    uint32 tv = 0;
    status_t status;
    SSL *ssl;

    SSL_CTX *ctx = SSL_CTX_PTR(link->ssl_ctx);
    if (ctx == NULL) {
        return CM_ERROR;
    }

    if (link->ssl_sock == NULL) {
        ssl = cm_cs_ssl_create_socket(ctx, sock);
        if (ssl == NULL) {
            return CM_ERROR;
        }
        link->ssl_sock = (ssl_sock_t *)ssl;
    } else {
        ssl = (SSL *)link->ssl_sock;
    }

    link->tcp.sock = sock;
    
    do {
        ret = SSL_accept(ssl);
        if (ret == 1) {
            status = CM_SUCCESS;
            break;
        }
        status = cm_cs_ssl_wait_on_error(link, ret, (int32)CM_NETWORK_IO_TIMEOUT);
        if (status == CM_ERROR) {
            break;
        } else if (status == CM_TIMEDOUT) {
            tv += (uint32)CM_NETWORK_IO_TIMEOUT;
        }
    } while (tv < timeout && !SSL_is_init_finished(ssl));

    if (status == CM_SUCCESS) {
        cm_cs_ssl_show_certs(ssl);
        return CM_SUCCESS;
    }

    if (status == CM_TIMEDOUT) {
        write_runlog(DEBUG1, "ssl accept timeout(%u ms)\n", timeout);
    }

    return status;
}

status_t cm_ssl_connect_socket(ssl_link_t *link, socket_t sock, int32 timeout)
{
    int32 ret;
    int32 tv = 0;
    status_t status = CM_SUCCESS;

    SSL_CTX *ctx = SSL_CTX_PTR(link->ssl_ctx);
    if (ctx == NULL) {
        return CM_ERROR;
    }

    SSL *ssl = cm_cs_ssl_create_socket(ctx, sock);
    if (ssl == NULL) {
        return CM_ERROR;
    }
    link->tcp.sock = sock;
    link->ssl_sock = (ssl_sock_t *)ssl;

    do {
        ret = SSL_connect(ssl);
        status = cm_cs_ssl_wait_on_error(link, ret, (int32)CM_NETWORK_IO_TIMEOUT);
        if (status == CM_ERROR) {
            break;
        } else if (status == CM_TIMEDOUT) {
            tv += (int32)CM_NETWORK_IO_TIMEOUT;
        }
    } while (tv < timeout && !SSL_is_init_finished(ssl));

    if (status == CM_SUCCESS) {
        return CM_SUCCESS;
    }

    SSL_free(ssl);
    link->ssl_sock = NULL;
    return CM_ERROR;
}

status_t cm_cs_ssl_send(ssl_link_t *link, const char *buf, uint32 size, int32 *send_size)
{
    int32 ret, err;
    SSL *ssl = SSL_SOCK(link->ssl_sock);

    if (size == 0) {
        *send_size = 0;
        return CM_SUCCESS;
    }

    /* clear the error queue before the SSL I/O operation */
    CmSetSockError(0);
    ERR_clear_error();

    ret = SSL_write(ssl, buf, (int)size);
    if (ret > 0) {
        (*send_size) = ret;
        return CM_SUCCESS;
    }

    if (!cm_cs_ssl_should_retry(link, ret, NULL, &err)) {
        if (CmGetSockError() == EWOULDBLOCK) {
            (*send_size) = 0;
            return CM_SUCCESS;
        }
        CM_THROW_ERROR(ERR_PEER_CLOSED_REASON, "ssl", err);
        return CM_ERROR;
    }
    (*send_size) = 0;
    return CM_SUCCESS;
}

status_t cm_cs_ssl_send_timed(ssl_link_t *link, const char *buf, uint32 size, uint32 timeout)
{
    uint32 remain_size;
    uint32 offset = 0;
    int32 writen_size = 0;
    uint32 wait_interval = 0;
    bool ready = false;

    if (link->ssl_sock == NULL) {
        CM_THROW_ERROR(ERR_PEER_CLOSED, "ssl");
        return CM_ERROR;
    }

    /* for most cases, all data are written by the following call */
    if (cm_cs_ssl_send(link, buf, size, &writen_size) != CM_SUCCESS) {
        return CM_ERROR;
    }

    remain_size = size;
    if (writen_size > 0) {
        remain_size = size - (uint32)writen_size;
        offset = (uint32)writen_size;
    }

    while (remain_size > 0) {
        if (cm_cs_ssl_wait(link, CS_WAIT_FOR_WRITE, (int32)CM_POLL_WAIT, &ready) != CM_SUCCESS) {
            return CM_ERROR;
        }

        if (!ready) {
            wait_interval += CM_POLL_WAIT;
            if (wait_interval >= timeout) {
                CM_THROW_ERROR(ERR_TCP_TIMEOUT, "send data");
                return CM_ERROR;
            }

            continue;
        }

        if (cm_cs_ssl_send(link, buf + offset, remain_size, &writen_size) != CM_SUCCESS) {
            return CM_ERROR;
        }

        if (writen_size > 0) {
            remain_size -= (uint32)writen_size;
            offset += (uint32)writen_size;
        }
    }

    return CM_SUCCESS;
}

status_t cm_cs_ssl_recv(ssl_link_t *link, char *buf, uint32 size, int32 *recv_size, uint32 *wait_event)
{
    int32 ret, err;
    SSL *ssl = SSL_SOCK(link->ssl_sock);

    if (size == 0) {
        (*recv_size) = 0;
        return CM_SUCCESS;
    }

    for (;;) {
        /* clear the error queue before the SSL I/O operation */
        CmSetSockError(0);
        ERR_clear_error();

        ret = SSL_read(ssl, (void *)buf, (int32)size);
        if (ret > 0) {
            break;
        }

        if (!cm_cs_ssl_should_retry(link, ret, wait_event, &err)) {
            err = CmGetSockError();
            if (err == EINTR || err == EAGAIN) {
                continue;
            }

            if (err == ECONNRESET) {
                CM_THROW_ERROR(ERR_PEER_CLOSED, "ssl");
            }

            return CM_ERROR;
        }

        *recv_size = 0;
        return CM_SUCCESS;
    }

    *recv_size = ret;
    return CM_SUCCESS;
}

status_t cm_cs_ssl_recv_remain(ssl_link_t *link, char *buf, uint32 offset, uint32 remain_size,
                            uint32 wait_event, uint32 timeout)
{
    int32 recv_size;
    uint32 wait_interval = 0;
    bool ready = false;

    while (remain_size > 0) {
        CM_RETURN_IFERR(cm_cs_ssl_wait(link, wait_event, (int32)CM_POLL_WAIT, &ready));

        if (!ready) {
            wait_interval += CM_POLL_WAIT;
            if (wait_interval >= timeout) {
                CM_THROW_ERROR(ERR_TCP_TIMEOUT, "recv data");
                return CM_ERROR;
            }

            continue;
        }

        CM_RETURN_IFERR(cm_cs_ssl_recv(link, buf + offset, remain_size, &recv_size, &wait_event));
        remain_size -= (uint32)recv_size;
        offset += (uint32)recv_size;
    }

    return CM_SUCCESS;
}

status_t cm_cs_ssl_wait(ssl_link_t *link, uint32 wait_for, int32 timeout, bool *ready)
{
    return cm_cs_tcp_wait(&link->tcp, wait_for, timeout, ready);
}

static status_t CmRealpathFile(const char *filename, char *realfile, uint32 real_path_len)
{
#ifdef WIN32
    if (!_fullpath(realfile, filename, real_path_len - 1)) {
        CM_THROW_ERROR(ERR_OPEN_FILE, filename, errno);
        return CM_ERROR;
    }
#else
    errno_t errcode;
    char resolved_path[PATH_MAX] = {0};

    if (!realpath(filename, resolved_path)) {
        if (errno != ENOENT && errno != EACCES) {
            CM_THROW_ERROR(ERR_OPEN_FILE, filename, errno);
            return CM_ERROR;
        }
    }

    errcode = strncpy_s(realfile, real_path_len, resolved_path, real_path_len - 1);
    if (errcode != EOK) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return CM_ERROR;
    }
#endif
    return CM_SUCCESS;
}

status_t cm_ssl_verify_file_stat(const char *file_name)
{
    char real_path[CM_FILE_NAME_BUFFER_SIZE] = { 0 };
    CM_RETURN_IFERR(CmRealpathFile(file_name, real_path, CM_FILE_NAME_BUFFER_SIZE));
#ifndef WIN32
    struct stat stat_buf;
    if (file_name && stat(file_name, &stat_buf) == 0) {
        if (!S_ISREG(stat_buf.st_mode) || stat_buf.st_mode & (S_IRWXG | S_IRWXO | S_IXUSR | S_IWUSR)) {
            CM_THROW_ERROR(ERR_SSL_FILE_PERMISSION, file_name);
            write_runlog(ERROR, "[cm_ssl_verify_file_stat] SSL server certificate file \"%s\" has execute, "
                "group or world access permission.\n", real_path);
            return CM_ERROR;
        }
    }
#endif
    return CM_SUCCESS;
}

void cm_cs_tcp_disconnect(tcp_link_t *link)
{
    if (link->closed) {
        return;
    }

    (void)cs_close_socket(link->sock);
    link->closed = CM_TRUE;
    link->sock = CS_INVALID_SOCKET;
}

int32 cm_cs_tcp_poll(struct pollfd *fds, uint32 nfds, int32 timeout)
{
#ifndef WIN32
    int32 ret = poll(fds, nfds, timeout);
    if (ret < 0 && errno == EINTR) {
        return 0;
    }
    return ret;
#else
    int32 ret = 0;
    fd_set wfds;
    fd_set rfds;
    fd_set efds;
    uint32 i = 0;
    struct pollfd *pfds = fds;
    struct timeval tv, *tvptr = NULL;
    if (nfds >= FD_SETSIZE) {
        CM_THROW_ERROR_EX(ERR_ASSERT_ERROR, "nfds(%u) < FD_SETSIZE(%u)", nfds, (uint32)FD_SETSIZE);
        return CM_ERROR;
    }

    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    FD_ZERO(&efds);
    if (timeout >= 0) {
        tv.tv_sec = timeout / CM_TIME_THOUSAND_UN;
        tv.tv_usec = (timeout % CM_TIME_THOUSAND_UN) * CM_TIME_THOUSAND_UN;
        tvptr = &tv;
    }

    cs_tcp_poll_set_fd(pfds, nfds, &wfds, &rfds, &efds);

    ret = select(0, &rfds, &wfds, &efds, tvptr);
    if (ret <= 0) {
        return (ret < 0 && EINTR == errno) ? 0 : ret;
    }

    pfds = fds;
    cs_tcp_poll_set_event(pfds, nfds, &wfds, &rfds, &efds);
    return ret;
#endif
}

status_t cm_cs_ssl_accept(ssl_ctx_t *fd, cs_pipe_t *pipe)
{
    status_t status;
    ssl_link_t *link = &pipe->link.ssl;
    link->ssl_ctx = fd;
    status = cm_cs_ssl_accept_socket(link, pipe->link.tcp.sock, CM_SSL_ACCEPT_TIMEOUT);
    if (status != CM_SUCCESS) {
        return status;
    }
    pipe->type = CS_TYPE_SSL;
    return status;
}

status_t cm_cs_tcp_wait(tcp_link_t *link, uint32 wait_for, int32 timeout, bool *ready)
{
    struct pollfd fd;
    int32 ret;
    int32 tv;

    if (ready != NULL) {
        *ready = false;
    }

    if (link->closed) {
        CM_THROW_ERROR(ERR_PEER_CLOSED, "tcp");
        return CM_ERROR;
    }

    tv = (timeout < 0 ? -1 : timeout);

    fd.fd = link->sock;
    fd.revents = 0;
    if (wait_for == CS_WAIT_FOR_WRITE) {
        fd.events = POLLOUT;
    } else {
        fd.events = POLLIN;
    }

    ret = cm_cs_tcp_poll(&fd, 1, tv);
    if (ret >= 0) {
        if (ready != NULL) {
            *ready = ((ret == 0 && errno == EINTR) || ret > 0);
        }
        return CM_SUCCESS;
    }

    if (errno != EINTR) {
        link->closed = CM_TRUE;
        CM_THROW_ERROR(ERR_PEER_CLOSED, "tcp");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t cm_cs_ssl_connect(ssl_ctx_t *fd, cs_pipe_t *pipe)
{
    ssl_link_t *link = &pipe->link.ssl;
    link->ssl_ctx = fd;
    if (cm_ssl_connect_socket(link, pipe->link.tcp.sock, (int32)CM_SSL_IO_TIMEOUT) != CM_SUCCESS) {
        return CM_ERROR;
    }
    pipe->type = CS_TYPE_SSL;
    return CM_SUCCESS;
}

void ReconstructCipherContent(cipher_t *cipher_content, const RandkeyFile *randkey, const CipherkeyFile *cipherKey)
{
    int rc = memcpy_s(cipher_content->cipher_text, CM_PASSWORD_BUFFER_SIZE, cipherKey->cipherkey, CIPHER_LEN);
    securec_check_errno(rc, (void)rc);

    /* pulCLen in CRYPT_encrypt is a fixed value 16 */
    const uint32 pulCLen = 16;
    cipher_content->cipher_len = pulCLen;

    rc = memcpy_s(cipher_content->IV, (RANDOM_LEN + 1), cipherKey->vectorSalt, RANDOM_LEN);
    securec_check_errno(rc, (void)rc);

    rc = memcpy_s(cipher_content->salt, (RANDOM_LEN + 1), cipherKey->keySalt, RANDOM_LEN);
    securec_check_errno(rc, (void)rc);

    rc = memcpy_s(cipher_content->rand, (RANDOM_LEN + 1), randkey->randkey, RANDOM_LEN);
    securec_check_errno(rc, (void)rc);

    return;
}

static status_t InitKeyFile(char *randKeyFilePath, char *cipherKeyFilePath, uint32 filePathLen, CipherMode mode)
{
    int rcs = 0;
    char filePath[MAX_PATH_LEN] = {0};
    if (GetHomePath(filePath, sizeof(filePath)) != 0) {
        return CM_ERROR;
    }
    canonicalize_path(filePath);
    char certFilePath[MAX_PATH_LEN] = {0};

    const char *keyRandFile;
    const char *keyCipherFile;
    switch (mode) {
        case SERVER_CIPHER:
            keyRandFile = SERVER_KEY_RAND_FILE;
            keyCipherFile = SERVER_KEY_CIPHER_FILE;
            rcs = snprintf_s(certFilePath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/share/sslcert/cm", filePath);
            securec_check_intval(rcs, (void)rcs);
            break;
        case CLIENT_CIPHER:
            keyRandFile = CLIENT_KEY_RAND_FILE;
            keyCipherFile = CLIENT_KEY_CIPHER_FILE;
            rcs = snprintf_s(certFilePath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/share/sslcert/cm", filePath);
            securec_check_intval(rcs, (void)rcs);
            break;
        case HADR_CIPHER:
            keyRandFile = HADR_KEY_RAND_FILE;
            keyCipherFile = HADR_KEY_CIPHER_FILE;
            rcs = snprintf_s(certFilePath, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/bin", filePath);
            securec_check_intval(rcs, (void)rcs);
            break;
        default:
            write_runlog(LOG, "KeyMode is unknown !\n");
            return CM_ERROR;
    }

    rcs = snprintf_s(randKeyFilePath, filePathLen, filePathLen - 1, "%s/%s", certFilePath, keyRandFile);
    securec_check_intval(rcs, (void)rcs);

    rcs = snprintf_s(cipherKeyFilePath, filePathLen, filePathLen - 1, "%s/%s", certFilePath, keyCipherFile);
    securec_check_intval(rcs, (void)rcs);
    return CM_SUCCESS;
}

status_t cm_verify_ssl_key_pwd(char *plain, uint32 size, CipherMode mode)
{
    int rcs = 0;
    status_t ret;
    cipher_t cipher = {{0}};

    char randKeyFilePath[MAX_PATH_LEN] = {0};
    char cipherKeyFilePath[MAX_PATH_LEN] = {0};
    ret = InitKeyFile(randKeyFilePath, cipherKeyFilePath, MAX_PATH_LEN, mode);
    if (ret != CM_SUCCESS) {
        write_runlog(ERROR, "Init key file failed\n");
    }

    RandkeyFile randKey;
    (void)ReadContentFromFile(randKeyFilePath, &randKey, sizeof(RandkeyFile));

    CipherkeyFile cipherKey;
    (void)ReadContentFromFile(cipherKeyFilePath, &cipherKey, sizeof(CipherkeyFile));

    ReconstructCipherContent(&cipher, &randKey, &cipherKey);

    if (CmDecryptPwd(&cipher, (unsigned char *)plain, &size) != CM_SUCCESS) {
        rcs = memset_s(&cipher, sizeof(cipher), 0, sizeof(cipher));
        securec_check_errno(rcs, (void)rcs);
        return CM_ERROR;
    }

    rcs = memset_s(&cipher, sizeof(cipher), 0, sizeof(cipher));
    securec_check_errno(rcs, (void)rcs);
    return CM_SUCCESS;
}

static void CsTcpDisconnect(tcp_link_t *link, int32 type, int32 *socket)
{
    if (link == NULL) {
        write_runlog(ERROR, "[CsTcpDisconnect] type is %d: link is NULL.\n", type);
        return;
    }

    if (link->closed) {
        CM_ASSERT(link->sock == CS_INVALID_SOCKET);
        return;
    }
    if (*socket < 0) {
        write_runlog(DEBUG1, "socket has been closed [%d]. type is %d: disconnect tcp socket.\n", link->sock, type);
        link->closed = CM_TRUE;
        link->sock = CS_INVALID_SOCKET;
        return;
    }
    write_runlog(DEBUG5, "socket is [%d]. type is %d: disconnect tcp socket.\n", link->sock, type);

    (void)cs_close_socket(link->sock);
    link->closed = CM_TRUE;
    link->sock = CS_INVALID_SOCKET;
    if (socket != NULL) {
        (*socket) = CS_INVALID_SOCKET;
    }
}

static void CsSslDisconnect(ssl_link_t *link, int32 type, int32 *socket)
{
    if (link == NULL) {
        write_runlog(ERROR, "[CsSslDisconnect] type is %d: link is NULL.\n", type);
        return;
    }

    if (link->tcp.closed) {
        CM_ASSERT(link->tcp.sock == CS_INVALID_SOCKET);
    } else {
        /* Close tcp socket */
        CsTcpDisconnect(&(link->tcp), type, socket);
    }

    SSL *ssl = SSL_SOCK(link->ssl_sock);
    if (ssl == NULL) {
        return;
    }

    SSL_set_quiet_shutdown(ssl, 1);
    if (SSL_shutdown(ssl) != 1) {
        write_runlog(ERROR, "type is %d: shutdown SSL failed.\n", type);
    }

    SSL_free(ssl);
    link->ssl_sock = NULL;
    write_runlog(DEBUG5, "type is %d: disconnect ssl socket.\n", type);
}

void CsDisconnect(cs_pipe_t *pipe, int32 type, int32 *socket)
{
    write_runlog(DEBUG5, "type is %d: begin to disconnect pipe.\n", type);
    if (pipe == NULL) {
        write_runlog(ERROR, "type is %d: pip is NULL.\n", type);
        return;
    }
    if (pipe->type == CS_TYPE_TCP) {
        CsTcpDisconnect(&(pipe->link.tcp), type, socket);
    }

    CsSslDisconnect(&(pipe->link.ssl), type, socket);

    write_runlog(DEBUG5, "type is %d: end to disconnect pipe.\n", type);
}

#ifdef __cplusplus
}
#endif
