/*
 * Copyright (c) 2022 Huawei Technologies Co.,Ltd.
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
 * cm_text.cpp
 *
 * IDENTIFICATION
 *    src/cm_common/cm_text.cpp
 *
 * -------------------------------------------------------------------------
 */
#include <ctype.h>
#include <climits>
#include "cm_text.h"

#include "securec.h"
#include "cm_debug.h"
#include "cm_error.h"

#include "cm_elog.h"
#include "cm_config.h"

bool8 IsCmBracketText(const text_t *text)
{
    bool8 inString = CM_FALSE;
    uint32 depth;
    const int minLen = 2;

    if (text->len < minLen) {
        return CM_FALSE;
    }

    bool8 flag = (bool8)(CM_TEXT_BEGIN(text) != '(' || CM_TEXT_END(text) != ')');
    if (flag) {
        return CM_FALSE;
    }

    depth = 1;
    for (uint32 i = 1; i < text->len; i++) {
        if (text->str[i] == '\'') {
            inString = (bool8)(!inString);
            continue;
        }

        if (inString) {
            continue;
        } else if (text->str[i] == '(') {
            depth++;
        } else if (text->str[i] == ')') {
            depth--;
            if (depth == 0) {
                return (bool8)(i == text->len - 1);
            }
        }
    }

    return CM_FALSE;
}

bool8 IsCmSquareBracketText(const text_t *text)
{
    bool8 inString = CM_FALSE;
    uint32 depth;
    const int minLen = 2;

    if (text->len < minLen) {
        return CM_FALSE;
    }

    bool8 flag = (bool8)(CM_TEXT_BEGIN(text) != '[' || CM_TEXT_END(text) != ']');
    if (flag) {
        return CM_FALSE;
    }

    depth = 1;
    for (uint32 i = 1; i < text->len; i++) {
        if (text->str[i] == '\'') {
            inString = (bool8)(!inString);
            continue;
        }

        if (inString) {
            continue;
        } else if (text->str[i] == '[') {
            depth++;
        } else if (text->str[i] == ']') {
            depth--;
            if (depth == 0) {
                return (bool8)(i == text->len - 1);
            }
        }
    }

    return CM_FALSE;
}

void CmRtrimText(text_t *text)
{
    int32 index;

    if (text->str == NULL) {
        text->len = 0;
        return;
    } else if (text->len == 0) {
        return;
    }

    index = (int32)text->len - 1;
    while (index >= 0) {
        if ((unsigned char)text->str[index] > (unsigned char)' ') {
            text->len = (uint32)(index + 1);
            return;
        }

        --index;
    }
}

void CmLtrimText(text_t *text)
{
    if (text->str == NULL) {
        text->len = 0;
        return;
    } else if (text->len == 0) {
        return;
    }

    while (text->len > 0) {
        if ((unsigned char)*text->str > ' ') {
            break;
        }
        text->str++;
        text->len--;
    }
}

void CmTrimText(text_t *text)
{
    CmLtrimText(text);
    CmRtrimText(text);
}

static void CmRTrimStr(char *str)
{
    int32 strLen = (int32)strlen(str);
    int32 i = strLen - 1;
    for (; i >= 0; --i) {
        if (!isspace(str[i])) {
            if (i < strLen - 1) {
                str[i + 1] = '\0';
            }
            break;
        }
    }
}

static void CmLTrimStr(char *str)
{
    uint32 index = 0;
    uint32 strLen = (uint32)strlen(str);
    for (uint32 i = 0; i < strLen; ++i) {
        if (isspace(str[i])) {
            ++index;
        } else {
            break;
        }
    }
    if (index == 0) {
        return;
    }
    char *tempStr = str + index;
    uint32 curLen = (uint32)strlen(tempStr);
    if (curLen == 0) {
        str[0] = '\0';
        return;
    }
    errno_t rc = memmove_s(str, strlen(str), tempStr, curLen);
    securec_check_errno(rc, (void)rc);
    str[curLen] = '\0';
}

void CmTrimStr(char *str)
{
    if (CM_IS_EMPTY_STR(str)) {
        return;
    }
    CmRTrimStr(str);
    CmLTrimStr(str);
}

void CmRemoveBrackets(text_t *text)
{
    const int lenReduce = 2;
    while (IsCmBracketText(text)) {
        text->str++;
        text->len -= lenReduce;
        CmTrimText(text);
    }
}

void CmRemoveSquareBrackets(text_t *text)
{
    const int lenReduce = 2;
    while (IsCmSquareBracketText(text)) {
        text->str++;
        text->len -= lenReduce;
        CmTrimText(text);
    }
}

void CmSplitText(const text_t *text, char splitChar, char encloseChar, text_t *left, text_t *right)
{
    uint32 i;
    bool8 isEnclosed = CM_FALSE;

    left->str = text->str;

    for (i = 0; i < text->len; i++) {
        if (encloseChar != 0 && text->str[i] == encloseChar) {
            isEnclosed = (bool8)(!isEnclosed);
            continue;
        }

        if (isEnclosed) {
            continue;
        }

        if (text->str[i] == splitChar) {
            left->len = i;
            right->str = text->str + i + 1;
            right->len = text->len - (i + 1);
            return;
        }
    }
    /* if the split_char is not found */
    left->len = text->len;
    right->len = 0;
    right->str = NULL;
}

bool8 CmFetchText(text_t *text, char splitChar, char encloseChar, text_t *sub)
{
    text_t remain;
    if (text->len == 0) {
        CM_TEXT_CLEAR(sub);
        return CM_FALSE;
    }

    CmSplitText(text, splitChar, encloseChar, sub, &remain);

    text->len = remain.len;
    text->str = remain.str;
    return CM_TRUE;
}

bool8 CmTextStrEqualIns(const text_t *text, const char *str)
{
    uint32 i;

    for (i = 0; i < text->len; i++) {
        if (UPPER(text->str[i]) != UPPER(str[i]) || str[i] == '\0') {
            return CM_FALSE;
        }
    }

    return (bool8)(str[text->len] == '\0');
}

void CmFetchFileName(text_t *files, text_t *name)
{
    if (!CmFetchText(files, ',', '\0', name)) {
        return;
    }

    CmTrimText(name);
    const uint32 quotaionLen = 2;
    if (name->str[0] == '\'') {
        name->str++;
        if (name->len >= quotaionLen) {
            name->len -= quotaionLen;
        } else {
            name->len = 0;
        }

        CmTrimText(name);
    }
}

status_t CmText2Str(const text_t *text, char *buf, uint32 bufSize)
{
    if (buf == NULL) {
        return CM_ERROR;
    }
    uint32 copy_size;
    CM_ASSERT(bufSize > 1);
    copy_size = (text->len >= bufSize) ? bufSize - 1 : text->len;
    if (copy_size > 0) {
        int res = memcpy_s(buf, bufSize, text->str, copy_size);
        if (res != 0) {
            return CM_ERROR;
        }
    }

    buf[copy_size] = '\0';
    return CM_SUCCESS;
}

status_t CmText2Uint16(const text_t *textSrc, uint16 *value)
{
    char buf[CM_MAX_NUMBER_LENGTH + 1] = {0};
    text_t text = *textSrc;

    CmTrimText(&text);

    if (text.len > CM_MAX_NUMBER_LENGTH) {
        write_runlog(ERROR,
            "[%s] Convert uint16 failed,the length of text %u can't be larger than %u.\n",
            __FUNCTION__,
            text.len,
            CM_MAX_NUMBER_LENGTH);
        return CM_ERROR;
    }
    CM_RETURN_IFERR(CmText2Str(&text, buf, CM_MAX_NUMBER_LENGTH + 1));

    return CmStr2Uint16(buf, value);
}

status_t CmStr2Uint16(const char *str, uint16 *value)
{
    char *err = NULL;
    int ret = CmCheckIsNumber(str);
    if (ret != CM_SUCCESS) {
        write_runlog(ERROR,
            "[%s] Convert uint16 failed, the text is not number, text = %s.\n", __FUNCTION__, str);
        return CM_ERROR;
    }

    int64_t valInt64 = strtol(str, &err, CM_DEFAULT_DIGIT_RADIX);
    if (CmIsErr(err)) {
        write_runlog(ERROR, "[%s] Convert uint32 failed, text = %s.\n", __FUNCTION__, str);
        return CM_ERROR;
    }

    if (valInt64 > UINT_MAX || valInt64 < 0) {
        write_runlog(ERROR,
            "[%s] Convert uint32 failed, the text is not in the range of uint32, text = %s.\n",
            __FUNCTION__, str);
        return CM_ERROR;
    }

    *value = (uint32)valInt64;
    return CM_SUCCESS;
}

status_t CmCheckIsNumber(const char *str)
{
    size_t len = strlen(str);
    if (len == 0) {
        return CM_ERROR;
    }

    for (size_t i = 0; i < len; i++) {
        if (!CM_IS_DIGITAL_LETER(str[i])) {
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

bool CmIsErr(const char *err)
{
    if (err == NULL) {
        return false;
    }

    while (*err != '\0') {
        if (*err != ' ') {
            return true;
        }
        err++;
    }
    return false;
}
