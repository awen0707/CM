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
 * cm_cipher.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_cipher.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __CM_CIPHER_H__
#define __CM_CIPHER_H__

#include "cm_error.h"
#include "cm_defs.h"
#include "utils/pg_crc.h"
#include "openssl/ossl_typ.h"

#ifdef ENABLE_LIBPQ
#define RANDOM_LEN 16
#define CIPHER_LEN 16
#define EVP_CIPHER_TYPE NID_aes_128_cbc
#else
#define RANDOM_LEN 32
#define CIPHER_LEN 32
#define EVP_CIPHER_TYPE NID_aes_256_cbc
#endif


#define PASSWD_KINDS 4
#define MIN_KEY_LEN 8
#define MAX_KEY_LEN 15

#define SERVER_KEY_RAND_FILE       "server.key.rand"
#define SERVER_KEY_CIPHER_FILE     "server.key.cipher"
#define CLIENT_KEY_RAND_FILE       "client.key.rand"
#define CLIENT_KEY_CIPHER_FILE     "client.key.cipher"
#define HADR_KEY_RAND_FILE       "hadr.key.rand"
#define HADR_KEY_CIPHER_FILE     "hadr.key.cipher"

typedef struct st_cipher {
    unsigned char  rand[RANDOM_LEN + 1];   /* rand used to derive key */
    unsigned char  salt[RANDOM_LEN + 1];   /* salt used to derive key */
    unsigned char  IV[RANDOM_LEN + 1];     /* IV used to encrypt/decrypt text */
    unsigned char  cipher_text[CM_PASSWORD_BUFFER_SIZE]; /* cipher text */
    uint32 cipher_len;             /* cipher text length */
} cipher_t;

typedef struct {
    unsigned char cipherkey[CIPHER_LEN + 1];   /* cipher text vector */
    unsigned char keySalt[RANDOM_LEN + 1];    /* salt vector used to derive key */
    unsigned char vectorSalt[RANDOM_LEN + 1]; /* salt vector used to encrypt/decrypt text */
    uint32 crc;
} CipherkeyFile;

const int KEDF2_KEY_SIZE = 32;

typedef enum {
    UNKNOWN_KEY_MODE,
    SERVER_MODE,
    CLIENT_MODE,
    HADR_MODE,
    OBS_MODE,
    SOURCE_MODE,
    GDS_MODE,
    USER_MAPPING_MODE
} KeyMode;

typedef enum {
    OBS_CLOUD_TYPE = 0,     /* on cloud obs cipher for encrypt and decrypt ak/sk */
    INITDB_NOCLOUDOBS_TYPE, /* non-cloud obs use the cipher same as initdb */
    GSQL_SSL_TYPE,          /* gsql ssl connection cipher */
    GDS_SSL_TYPE,           /* gds ssl connection cipher */
    CIPHER_TYPE_MAX         /* The max number of types should be at the end */
} CipherType;

typedef struct {
    unsigned char randkey[CIPHER_LEN + 1];
    uint32 crc;
} RandkeyFile;

status_t CmDecryptPwd(const cipher_t *cipher, unsigned char *plainText, uint32 *plainLen);

int GenCipherRandFiles(KeyMode mode, const char* plainKey, const char* datadir);
bool CheckInputPassword(const char* password);
bool EncryptInputKey(const char* pucPlainText, unsigned char* initrand, unsigned char* keySaltVector,
    unsigned char* encryptVector, unsigned char* pucCipherText, int &pulCLen);
status_t CRYPT_encrypt(uint32 ulAlgId, unsigned char* pucKey, unsigned char* pucIV,
    const unsigned char* pucPlainText, int ulPlainLen, unsigned char* pucCipherText, int &pulCLen);

int32 RegistOpensslExitSignal(const char* program);
#endif
