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
 * cm_text.h
 *
 *
 * IDENTIFICATION
 *    include/cm/cm_text.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CM_TEXT_H
#define CM_TEXT_H

#include <string.h>

#include "c.h"
#include "cm_defs.h"

#pragma pack(4)
typedef struct st_text {
    char *str;
    uint32 len;
} text_t;

typedef struct CmConstTextT {
    const char *str;
    uint32 len;
} CmConstText;
#pragma pack()

#define CM_TEXT_BEGIN(text)  ((text)->str[0])
#define CM_TEXT_FIRST(text)  ((text)->str[0])
#define CM_TEXT_SECOND(text) ((text)->str[1])
#define CM_TEXT_END(text)    ((text)->str[(text)->len - 1])
#define CM_TEXT_SECONDTOLAST(text)      (((text)->len >= 2) ? ((text)->str[(text)->len - 2]) : '\0')
#define CM_NULL_TERM(text)   \
    {                                    \
        (text)->str[(text)->len] = '\0'; \
    }
#define CM_IS_EMPTY(text) (((text)->str == NULL) || ((text)->len == 0))
#define CM_IS_QUOTE_CHAR(c1) ((c1) == '\'' || (c1) == '"' || (c1) == '`')
#define CM_IS_QUOTE_STRING(c1, c2) ((c1) == (c2) && CM_IS_QUOTE_CHAR(c1))
#define CM_IS_DIGITAL_LETER(c)        ((c) >= '0' && ((c) <= '9'))

#define CM_TEXT_CLEAR(text) ((text)->len = 0)

#define CM_FILE_NAME_BUFFER_SIZE        (uint32)256
#define CM_MAX_FILE_NAME_LEN            (uint32)(CM_FILE_NAME_BUFFER_SIZE - 1)

#define UPPER(c) (((c) >= 'a' && (c) <= 'z') ? ((c) - 32) : (c))
#define LOWER(c) (((c) >= 'A' && (c) <= 'Z') ? ((c) + 32) : (c))

#ifndef ELEMENT_COUNT
#define ELEMENT_COUNT(x) ((uint32)(sizeof(x) / sizeof((x)[0])))
#endif

#define CM_C2D(c) ((c) - '0')

#ifdef WIN32
#define cm_strcmpi _strcmpi
#define cm_strcmpni _strnicmp
#define cm_strstri stristr
#else
#define cm_strcmpi strcasecmp
#define cm_strcmpni strncasecmp
#define cm_strstri strcasestr
#endif

#define cm_compare_str(str1, str2) strcmp(str1, str2)
#define cm_compare_str_ins(str1, str2) cm_strcmpi(str1, str2)
#define cm_str_str(str1, str2) strstr(str1, str)
#define cm_str_str_ins(str1, str2) cm_strstri(str1, str2)
#define cm_str_equal(str1, str2) (strcmp(str1, str2) == 0)
#define cm_str_equal_ins(str1, str2) (cm_strcmpi(str1, str2) == 0)
#define cm_str_match(str1, str2) (strstr(str1, str2) != NULL)
#define cm_str_match_ins(str1, str2) (cm_strstri(str1, str2) != NULL)

static inline void CmStr2Text(char *str, text_t *text)
{
    text->str = str;
    text->len = (str == NULL) ? 0 : (uint32)strlen(str);
}

static inline void CmConststr2Text(const char *str, CmConstText *text)
{
    text->str = str;
    text->len = (str == NULL) ? 0 : (uint32)strlen(str);
}

/* Remove the enclosed char or the head and the tail of the text */
#define CM_REMOVE_ENCLOSED_CHAR(text) \
    do {                              \
        ++((text)->str);              \
        (text)->len -= 2;             \
    } while (0)

#define CM_TEXT_EMPTY_STR_TO_NULL(str)       \
    if ((str) != NULL && (str)[0] == '\0') { \
        (str) = NULL;                        \
    }

void CmFetchFileName(text_t *files, text_t *name);
bool8 CmTextStrEqualIns(const text_t *text, const char *str);
bool8 CmFetchText(text_t *text, char splitChar, char encloseChar, text_t *sub);
void CmSplitText(const text_t *text, char splitChar, char encloseChar, text_t *left, text_t *right);
void CmRemoveBrackets(text_t *text);
void CmRemoveSquareBrackets(text_t *text);
void CmTrimText(text_t *text);
void CmLtrimText(text_t *text);
void CmRtrimText(text_t *text);
bool8 IsCmBracketText(const text_t *text);
status_t CmText2Str(const text_t *text, char *buf, uint32 bufSize);
void CmTrimStr(char *str);
status_t CmText2Uint16(const text_t *textSrc, uint16 *value);
status_t CmStr2Uint16(const char *str, uint16 *value);
status_t CmCheckIsNumber(const char *str);
bool CmIsErr(const char *err);

#endif
