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
 * cm_cipher.cpp
 *    cm communication with ssl
 *
 * IDENTIFICATION
 *    src/cm_communication/cm_protocol/cm_cipher.cpp
 *
 * -------------------------------------------------------------------------
 */

#include "cm_cipher.h"
#include "securec.h"
#include "openssl/rand.h"
#include "openssl/evp.h"
#include "openssl/ossl_typ.h"
#include "openssl/x509.h"
#include "openssl/ssl.h"
#include "openssl/asn1.h"
#include "openssl/hmac.h"
#include "cm/cm_elog.h"
#include "utils/pg_crc_tables.h"

/* GetEvpCipherById: if you need to be use,you can add some types */
static const EVP_CIPHER *GetEvpCipherById(uint32 algId)
{
    const EVP_CIPHER *evpCipher = NULL;
    switch (algId & 0xFFFF) {
        case NID_aes_128_cbc:
            evpCipher = EVP_aes_128_cbc();
            break;
        case NID_aes_256_cbc:
            evpCipher = EVP_aes_256_cbc();
            break;
        case NID_undef:
            evpCipher = EVP_enc_null();
            break;
        default:
            write_runlog(DEBUG1, "invalid algorithm for evpCipher");
            break;
    }
    return evpCipher;
}

/*
 * @Brief        : uint32 CRYPT_decrypt()
 * @Description  : decrypts cipher text to plain text using decryption algorithm.
 *		  It creates symmetric context by creating algorithm object, padding object,
 *		  opmode object. After decryption, symmetric context needs to be freed.
 * @return       : success: 0, failed: 1.
 *
 * @Notes        : the last block is not full. so here need to padding the last block.(the block size is an
 * algorithm-related parameter) 1.here *ISO/IEC 7816-4* padding method is adoptted:the first byte uses "0x80" to padding
 * ,and the others uses "0x00". Example(in the following example the block size is 8 bytes): when the last block is not
 * full: The last block has 4 bits,so padding is required for 4 bytes
 *                                ... | DD DD DD DD DD DD DD DD | DD DD DD DD 80 00 00 00 |
 *                       when the last block is full: here need to add a new block
 *                                ... | DD DD DD DD DD DD DD DD | 80 00 00 00 00 00 00 00 |
 */
static status_t CRYPT_decrypt(
    uint32 algId, const unsigned char *key, const cipher_t *cipher, unsigned char *plainText, uint32 *plainLen)
{
    errno_t rc;
    uint32 plainSize = *plainLen;
    const EVP_CIPHER *cipherAlg = GetEvpCipherById(algId);
    if (cipherAlg == NULL) {
        return CM_ERROR;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return CM_ERROR;
    }
    (void)EVP_CipherInit_ex(ctx, cipherAlg, NULL, key, cipher->IV, CM_FALSE);

    (void)EVP_CIPHER_CTX_set_padding(ctx, CM_FALSE);

    uint32 decNum = 0;
    if (!EVP_DecryptUpdate(ctx, plainText, (int32*)&decNum, cipher->cipher_text, (int)cipher->cipher_len)) {
        EVP_CIPHER_CTX_free(ctx);
        rc = memset_s(plainText, plainSize, 0, plainSize);
        securec_check_errno(rc, (void)rc);
        return CM_ERROR;
    }

    *plainLen = decNum;
    if (!EVP_DecryptFinal(ctx, plainText + decNum, (int32*)&decNum)) {
        EVP_CIPHER_CTX_free(ctx);
        rc = memset_s(plainText, plainSize, 0, plainSize);
        securec_check_errno(rc, (void)rc);
        return CM_ERROR;
    }

    *plainLen += decNum;
    /* padding bytes of the last block need to be removed */
    uint32 blockSize = (uint32)EVP_CIPHER_CTX_block_size(ctx);
    uint32 pwdLen = (*plainLen) - 1;
    while (*(plainText + pwdLen) == 0) {
        pwdLen--;
    }

    if (pwdLen < ((*plainLen) - blockSize) || *(plainText + pwdLen) != 0x80) {
        EVP_CIPHER_CTX_free(ctx);
        rc = memset_s(plainText, plainSize, 0, plainSize);
        securec_check_errno(rc, (void)rc);
        return CM_ERROR;
    }
    (*plainLen) = pwdLen;
    plainText[pwdLen] = '\0';
    EVP_CIPHER_CTX_free(ctx);
    return CM_SUCCESS;
}

status_t CmDecryptPwd(const cipher_t *cipher, unsigned char *plainText, uint32 *plainLen)
{
    unsigned char key[RANDOM_LEN] = { 0 };

    /* get the decrypt key value */
    int32 ret = PKCS5_PBKDF2_HMAC((const char*)cipher->rand, RANDOM_LEN,
        cipher->salt, RANDOM_LEN, ITERATE_TIMES, EVP_sha256(), RANDOM_LEN, key);
    if (ret != 1) {
        write_runlog(DEBUG1, "PKCS5_PBKDF2_HMAC generate the derived key failed, errcode:%d", ret);
        return CM_ERROR;
    }

    /* decrypt the cipher */
    if (CRYPT_decrypt(EVP_CIPHER_TYPE, key, cipher, plainText, plainLen) != CM_SUCCESS) {
        return CM_ERROR;
    }
    (void)memset_s(key, RANDOM_LEN, 0, RANDOM_LEN);
    return CM_SUCCESS;
}

static void InitVectorRandom(unsigned char* initVector, size_t vectorLen)
{
    errno_t errorno = EOK;
    unsigned char randomVector[RANDOM_LEN] = {0};

    int retval = RAND_priv_bytes(randomVector, RANDOM_LEN);
    if (retval != 1) {
        errorno = memset_s(randomVector, RANDOM_LEN, '\0', RANDOM_LEN);
        securec_check_errno(errorno, (void)errorno);
        write_runlog(ERROR, "generate random initial vector failed, errcode:%d\n", retval);
        return;
    }

    errorno = memcpy_s(initVector, vectorLen, randomVector, RANDOM_LEN);
    securec_check_errno(errorno, (void)errorno);
    errorno = memset_s(randomVector, RANDOM_LEN, '\0', RANDOM_LEN);
    securec_check_errno(errorno, (void)errorno);
    return;
}

/* check whether the character is special characters */
static bool IsSpecialCharacter(char ch)
{
    const char* specLetters = "~!@#$%^&*()-_=+\\|[{}];:,<.>/?";
    const char* ptr = specLetters;
    while (*ptr != '\0') {
        if (*ptr == ch) {
            return true;
        }
        ptr++;
    }
    return false;
}

/* check whether the input password(for key derivation) meet the requirements of the length and complexity */
bool CheckInputPassword(const char* password)
{
    int kinds[PASSWD_KINDS] = {0};
    int kindsNum = 0;
    if (password == NULL) {
        write_runlog(ERROR, "Invalid password,please check it\n");
        return false;
    }
    size_t keyInputLen = strlen(password);
    if (keyInputLen < MIN_KEY_LEN) {
        write_runlog(ERROR, "Invalid password,it must contain at least eight characters\n");
        return false;
    }
    if (keyInputLen > MAX_KEY_LEN) {
        write_runlog(ERROR, "Invalid password,the length exceed %d\n", MAX_KEY_LEN);
        return false;
    }
    const char* ptr = password;
    while (*ptr != '\0') {
        if (*ptr >= 'A' && *ptr <= 'Z') {
            kinds[0]++;
        } else if (*ptr >= 'a' && *ptr <= 'z') {
            kinds[1]++;
        } else if (*ptr >= '0' && *ptr <= '9') {
            kinds[2]++;
        } else if (IsSpecialCharacter(*ptr)) {
            kinds[3]++;
        }
        ptr++;
    }
    for (int i = 0; i < PASSWD_KINDS; ++i) {
        if (kinds[i] > 0) {
            kindsNum++;
        }
    }
    if (kindsNum < PASSWD_KINDS - 1) {
        write_runlog(ERROR, "Invalid password,it must contain at least three kinds of characters\n");
        return false;
    }
    return true;
}

/* encrypt the plain text to cipher text */
bool EncryptInputKey(const char* pucPlainText, const char* initrand, unsigned char* keySaltVector,
    unsigned char* encryptVector, unsigned char* pucCipherText, int &pulCLen)
{
    unsigned char deriverKey[KEDF2_KEY_SIZE] = {0};
    errno_t rc;

    if (pucPlainText == NULL) {
        write_runlog(ERROR, "invalid plain text, please check it!\n");
        return false;
    }
    int ulPlainLen = (int)strlen(pucPlainText);

    /* use PKCS5 HMAC sha256 to dump the key for encryption */
    int retval = PKCS5_PBKDF2_HMAC(initrand, RANDOM_LEN, keySaltVector, RANDOM_LEN, ITERATE_TIMES,
        EVP_sha256(), KEDF2_KEY_SIZE, deriverKey);
    if (retval != 1) {
        rc = memset_s(deriverKey, KEDF2_KEY_SIZE, 0, KEDF2_KEY_SIZE);
        securec_check_errno(rc, (void)rc);
        write_runlog(ERROR, "generate the derived key failed, errcode:%d\n", retval);
        return false;
    }

    status_t st = CRYPT_encrypt((uint32)EVP_CIPHER_TYPE, deriverKey, encryptVector,
        (const unsigned char*)pucPlainText, ulPlainLen, pucCipherText, pulCLen);
    if (st != CM_SUCCESS) {
        rc = memset_s(deriverKey, KEDF2_KEY_SIZE, 0, KEDF2_KEY_SIZE);
        securec_check_errno(rc, (void)rc);
        write_runlog(ERROR, "encrypt plain text to cipher text failed, errcode:%d\n", (int)st);
        return false;
    }

    rc = memset_s(deriverKey, KEDF2_KEY_SIZE, 0, KEDF2_KEY_SIZE);
    securec_check_errno(rc, (void)rc);
    return true;
}

/* copy the cipher text to CipherkeyFile */
static void CopyCipher(const unsigned char* cipherStr, const unsigned char* keySalt,
    const unsigned char* vectorSalt, CipherkeyFile* content)
{
    errno_t rc = memcpy_s(content->cipherkey, CIPHER_LEN + 1, cipherStr, CIPHER_LEN);
    securec_check_errno(rc, (void)rc);

    rc = memcpy_s(content->keySalt, RANDOM_LEN + 1, keySalt, RANDOM_LEN);
    securec_check_errno(rc, (void)rc);

    rc = memcpy_s(content->vectorSalt, RANDOM_LEN + 1, vectorSalt, RANDOM_LEN);
    securec_check_errno(rc, (void)rc);

    /* generate the crc value to protect the value in case someone modify it */
    INIT_CRC32(content->crc);
    COMP_CRC32(content->crc, (char*)content, offsetof(CipherkeyFile, crc));
    FIN_CRC32(content->crc);
}

/* copy the cipher text to RandkeyFile */
static void CopyRand(const char* randStr, RandkeyFile* randfile)
{
    /* append rand_key to the front part of cipher text */
    errno_t rc = memcpy_s(randfile->randkey, RANDOM_LEN + 1, randStr, RANDOM_LEN);
    securec_check_errno(rc, (void)rc);

    /* generate the crc value to protect the value in case someone modify it */
    INIT_CRC32(randfile->crc);
    COMP_CRC32(randfile->crc, (char*)randfile, offsetof(RandkeyFile, crc));
    FIN_CRC32(randfile->crc);
}


/* write data in buffer to file */
static bool WriteContentToFile(const char* filename, const void* content, size_t csize)
{
    FILE* pfWrite = fopen(filename, "wb");
    if (pfWrite == NULL) {
        write_runlog(ERROR, "could not open file \"%s\" for writing: %s\n", filename, gs_strerror(errno));
        return false;
    }
    if (fwrite(content, csize, 1, pfWrite) != 1) {
        (void)fclose(pfWrite);
        write_runlog(ERROR, "could not write file \"%s\": %s\n", filename, gs_strerror(errno));
        return false;
    }

#ifdef WIN32
    int ret = _chmod(filename, 0400);
#else
    int ret = fchmod(pfWrite->_fileno, 0400);
#endif

    if (fclose(pfWrite)) {
        write_runlog(ERROR, "could not close file \"%s\": %s\n", filename, gs_strerror(errno));
        return false;
    }

    if (ret == -1) {
        write_runlog(ERROR, "could not set permissions of file \"%s\": %s\n", filename, gs_strerror(errno));
        return false;
    }
    return true;
}

/* Judge if the KeyMode is legal */
static bool isModeExists(KeyMode mode)
{
    if (mode != SERVER_MODE && mode != CLIENT_MODE) {
#ifndef ENABLE_LLT
        write_runlog(ERROR, "AK/SK encrypt/decrypt encounters invalid key mode.\n");
        return false;
#endif
    }
    return true;
}

/* encrypt the input key,and write the cipher to file */
static bool GenCipherFile(KeyMode mode, const char* initRand, unsigned char serverVector[],
    unsigned char clientVector[], const char* plainKey, const char* datadir)
{
    int ret = 0;

    char cipherkeyfile[MAXPGPATH] = {0x00};
    unsigned char encryptRand[RANDOM_LEN] = {0};
    unsigned char ciphertext[CIPHER_LEN] = {0};
    unsigned char* keySalt = NULL;

    int cipherlen = 0;
    int retval = 0;

    CipherkeyFile cipherFileContent;

    /* check whether the key mode is valid */
    if (!isModeExists(mode)) {
#ifndef ENABLE_LLT
        goto RETURNFALSE;
#endif
    }

    /* generate init rand key */
    retval = RAND_priv_bytes(encryptRand, RANDOM_LEN);
    if (retval != 1) {
#ifndef ENABLE_LLT
        write_runlog(ERROR, "generate random key failed,errcode:%d\n", retval);
        goto RETURNFALSE;
#endif
    }

    if (mode == SERVER_MODE) {
        ret = snprintf_s(cipherkeyfile, MAXPGPATH, MAXPGPATH - 1, "%s/%s", datadir, SERVER_KEY_CIPHER_FILE);
        securec_check_intval(ret, (void)ret);
        keySalt = serverVector;
    } else if (mode == CLIENT_MODE) {
        ret = snprintf_s(cipherkeyfile, MAXPGPATH, MAXPGPATH - 1, "%s/%s", datadir, CLIENT_KEY_CIPHER_FILE);
        securec_check_intval(ret, (void)ret);
        keySalt = clientVector;
    } else {
        return false;
    }

    if (!EncryptInputKey(plainKey, initRand, keySalt, encryptRand, ciphertext, cipherlen)) {
#ifndef ENABLE_LLT
        goto RETURNFALSE;
#endif
    }

    /*
     * Write ciphertext and encrypt rand vector to cipherFileContent
     * and generate cipher_file_context's CRC and append to the end of
     * cipher_file_context.
     */
    CopyCipher(ciphertext, keySalt, encryptRand, &cipherFileContent);

    if (!WriteContentToFile(cipherkeyfile, (const void*)&cipherFileContent, sizeof(CipherkeyFile))) {
#ifndef ENABLE_LLT
        goto RETURNFALSE;
#endif
    }

    /*
     * Change the privileges: include read & write
     * Note: it should be checked by OM tool: gs_ec.
     */
    if (mode == CLIENT_MODE || mode == SERVER_MODE) {
#ifdef WIN32
        ret = _chmod(cipherkeyfile, 0600);
#else
        ret = chmod(cipherkeyfile, 0600);
#endif
        if (ret != 0) {
#ifndef ENABLE_LLT
            write_runlog(ERROR, "could not set permissions of file \"%s\": %s\n", cipherkeyfile, gs_strerror(errno));
            goto RETURNFALSE;
#endif
        }
    }

    /*
     * Empty ciphertext and cipherFileContent.
     * This is useful. Although ciphertext and cipherFileContent is in stack,
     * we should manually clear them.
     */
    ret = memset_s(ciphertext, (CIPHER_LEN), 0, (CIPHER_LEN));
    securec_check_errno(ret, (void)ret);
    ret = memset_s((char*)&cipherFileContent, sizeof(CipherkeyFile), 0, sizeof(CipherkeyFile));
    securec_check_errno(ret, (void)ret);

    return true;

#ifndef ENABLE_LLT
RETURNFALSE:
    /*
     * Empty ciphertext and cipherFileContent.
     * This is useful. Although ciphertext and cipherFileContent is in stack,
     * we should manually clear them.
     */
    ret = memset_s(ciphertext, (CIPHER_LEN), 0, (CIPHER_LEN));
    securec_check_errno(ret, (void)ret);
    ret = memset_s((void*)&cipherFileContent, sizeof(CipherkeyFile), 0, sizeof(CipherkeyFile));
    securec_check_errno(ret, (void)ret);

    return false;
#endif
}

/* write encryption factor to files */
static bool GenRandFile(KeyMode mode, const char* initRand, const char* datadir)
{
    int ret;
    char randfile[MAXPGPATH] = {0x00};
    RandkeyFile randFileContent;
    FILE* pfWrite = NULL;

    if (!isModeExists(mode)) {
#ifndef ENABLE_LLT
        goto RETURNFALSE;
#endif
    }

    if (mode == SERVER_MODE) {
        ret = snprintf_s(randfile, MAXPGPATH, MAXPGPATH - 1, "%s/%s", datadir, SERVER_KEY_RAND_FILE);
        securec_check_intval(ret, (void)ret);
    } else if (mode == CLIENT_MODE) {
        ret = snprintf_s(randfile, MAXPGPATH, MAXPGPATH - 1, "%s/%s", datadir, CLIENT_KEY_RAND_FILE);
        securec_check_intval(ret, (void)ret);
    }
    CopyRand(initRand, &randFileContent);
    if (!WriteContentToFile(randfile, (const void*)&randFileContent, sizeof(RandkeyFile))) {
#ifndef ENABLE_LLT
        goto RETURNFALSE;
#endif
    }

    /*
     * Change the privileges: include read & write
     * Note: it should be checked by OM tool: gs_ec.
     */
    if (mode == CLIENT_MODE || mode == SERVER_MODE) {
        if ((pfWrite = fopen(randfile, "r")) == NULL) {
            write_runlog(ERROR, "could not open file \"%s\" for writing: %s\n", randfile, gs_strerror(errno));
            return false;
        }

#ifdef WIN32
        ret = _chmod(randfile, 0600);
#else
        ret = fchmod(pfWrite->_fileno, 0600);
#endif

        if (fclose(pfWrite)) {
            write_runlog(ERROR, "could not close file \"%s\": %s\n", randfile, gs_strerror(errno));
            return false;
        }

        if (ret != 0) {
            write_runlog(ERROR, "could not set permissions of file \"%s\": %s\n", randfile, gs_strerror(errno));
            return false;
        }
    }

    /*
     * Empty randFileContent.
     * This is useful. Although randFileContent is in stack,
     * we should manually clear it.
     */
    ret = memset_s((void*)&randFileContent, sizeof(RandkeyFile), 0, sizeof(RandkeyFile));
    securec_check_errno(ret, (void)ret);

    return true;

#ifndef ENABLE_LLT
RETURNFALSE:
    /*
     * Empty randFileContent.
     * This is useful. Although randFileContent is in stack,
     * we should manually clear it.
     */
    ret = memset_s((void*)&randFileContent, sizeof(RandkeyFile), 0, sizeof(RandkeyFile));
    securec_check_errno(ret, (void)ret);

    return false;
#endif
}

/*
 * generate the files of cipher text and encryption factor
 */
int GenCipherRandFiles(KeyMode mode, const char* plainKey, const char* datadir)
{
    unsigned char initRand[RANDOM_LEN] = {0};
    unsigned char serverVector[RANDOM_LEN] = {0};
    unsigned char clientVector[RANDOM_LEN] = {0};

    int retval = RAND_priv_bytes(initRand, RANDOM_LEN);
    if (retval != 1) {
        write_runlog(ERROR, "generate random key failed,errcode:%d\n", retval);
        return 1;
    }

    if (mode == SERVER_MODE) {
        InitVectorRandom(serverVector, RANDOM_LEN);
    } else if (mode == CLIENT_MODE) {
        InitVectorRandom(clientVector, RANDOM_LEN);
    } else {
        write_runlog(ERROR, "generate cipher file failed, unknown mode:%d.\n", (int)mode);
        return 1;
    }

    if (!GenCipherFile(mode, (const char*)initRand, serverVector, clientVector, plainKey, datadir)) {
#ifndef ENABLE_LLT
        write_runlog(ERROR, "generate cipher file failed.\n");
        return 1;
#endif
    }
    if (!GenRandFile(mode, (const char*)initRand, datadir)) {
#ifndef ENABLE_LLT
        write_runlog(ERROR, "generate random parameter file failed.\n");
        return 1;
#endif
    }

    return 0;
}

/*
 * @Brief        : uint32 CRYPT_encrypt()
 * @Description  : encrypts plain text to cipher text using encryption algorithm.
 *		  It creates symmetric context by creating algorithm object, padding object,
 *		  opmode object.After encryption, symmetric context needs to be freed.
 * @return       : success: 0, failed: 1.
 *
 * @Notes	: the last block is not full. so here need to padding the last block.(the block size is an algorithm-related
 * parameter) 1.here *ISO/IEC 7816-4* padding method is adoptted: the first byte uses "0x80" to padding ,and the others
 * uses "0x00". Example(in the following example the block size is 8 bytes): when the last block is not full: The last
 * block has 4 bytes, so four bytes need to be filled
 *	 	 	 	 ... | DD DD DD DD DD DD DD DD | DD DD DD DD 80 00 00 00 |
 *			when the last block is full: here need to add a new block
 *				 ... | DD DD DD DD DD DD DD DD | 80 00 00 00 00 00 00 00 |
 *		  2.Default padding method of OPENSSL(this method is closed at here): Each byte is filled with the number of
 * remaining bytes Example(in the following example the block size is 8 bytes): when the last block is not full:
 * The last block has 4 bytes, so four bytes need to be filled
 *                                ... | DD DD DD DD DD DD DD DD | DD DD DD DD 04 04 04 04 |
 *                       when the last block is full: here need to add a new block
 *                                ... | DD DD DD DD DD DD DD DD | 08 08 08 08 08 08 08 08 |
 */
status_t CRYPT_encrypt(uint32 ulAlgId, unsigned char* pucKey, unsigned char* pucIV,
    const unsigned char* pucPlainText, int ulPlainLen, unsigned char* pucCipherText, int &pulCLen)
{
    int encNum = 0;
    if (pucPlainText == NULL) {
        write_runlog(ERROR, "invalid plain text,please check it!\n");
        return CM_ERROR;
    }
    const EVP_CIPHER* cipher = GetEvpCipherById(ulAlgId);
    if (cipher == NULL) {
        write_runlog(ERROR, "invalid ulAlgType for cipher,please check it!\n");
        return CM_ERROR;
    }
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        write_runlog(ERROR, "ERROR in EVP_CIPHER_CTX_new:\n");
        return CM_ERROR;
    }
    (void)EVP_CipherInit_ex(ctx, cipher, NULL, pucKey, pucIV, 1);

    /* open padding mode */
    (void)EVP_CIPHER_CTX_set_padding(ctx, 1);

    /* handling the last block */
    int blocksize = EVP_CIPHER_CTX_block_size(ctx);
    if (blocksize == 0) {
        write_runlog(ERROR, "invalid blocksize, ERROR in EVP_CIPHER_CTX_block_size\n");
        EVP_CIPHER_CTX_free(ctx);
        return CM_ERROR;
    }

    int nInbufferLen = ulPlainLen % blocksize;
    int padding_size = blocksize - nInbufferLen;
    unsigned char* pchInbuffer = (unsigned char*)OPENSSL_malloc(blocksize);
    if (pchInbuffer == NULL) {
        write_runlog(ERROR, "malloc failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return CM_ERROR;
    }
    /* the first byte uses "0x80" to padding ,and the others uses "0x00" */
    errno_t rc = memcpy_s(pchInbuffer, blocksize, pucPlainText + (ulPlainLen - nInbufferLen), nInbufferLen);
    securec_check_errno(rc, (void)rc);
    rc = memset_s(pchInbuffer + nInbufferLen, padding_size, 0, padding_size);
    securec_check_errno(rc, (void)rc);
    pchInbuffer[nInbufferLen] = 0x80;

    /* close padding mode, default padding method of OPENSSL is forbidden */
    (void)EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (!EVP_EncryptUpdate(ctx, pucCipherText, &encNum, pucPlainText, ulPlainLen - nInbufferLen)) {
        write_runlog(ERROR, "ERROR in EVP_EncryptUpdate\n");
        goto err;
    }
    pulCLen = encNum;
    if (!EVP_EncryptUpdate(ctx, pucCipherText + encNum, &encNum, pchInbuffer, blocksize)) {
        write_runlog(ERROR, "ERROR in EVP_EncryptUpdate\n");
        goto err;
    }
    pulCLen += encNum;
    if (!EVP_EncryptFinal(ctx, pucCipherText + pulCLen, &encNum)) {
        write_runlog(ERROR, "ERROR in EVP_EncryptUpdate\n");
        goto err;
    }
    pulCLen += encNum;
    rc = memset_s(pchInbuffer, blocksize, 0, blocksize);
    securec_check_errno(rc, (void)rc);
    OPENSSL_free(pchInbuffer);
    EVP_CIPHER_CTX_free(ctx);
    return CM_SUCCESS;

err:
    rc = memset_s(pchInbuffer, blocksize, 0, blocksize);
    securec_check_errno(rc, (void)rc);
    OPENSSL_free(pchInbuffer);
    EVP_CIPHER_CTX_free(ctx);
    return CM_ERROR;
}

/*
 * This function is mean to initial OPENSSL by cm_agent.
 * It will initialize OPENSSL, and register a signal handler to clean up
 * OpenSSL when the program exits. And do not use it in other places.
 */
int32 RegistOpensslExitSignal(const char* program)
{
    if (OPENSSL_init_crypto(OPENSSL_INIT_NO_ATEXIT, NULL) == 0) {
        (void)fprintf(stderr, "[%s] OPENSSL_init_crypto failed!\n", program);
        return -1;
    }

    if (atexit(OPENSSL_cleanup) != 0) {
        (void)fprintf(stderr, "[%s] OPENSSL_cleanup atexit failed!\n", program);
        return -1;
    }
    return 0;
}
