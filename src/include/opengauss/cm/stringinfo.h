/* ---------------------------------------------------------------------------------------
 * 
 * stringinfo.h
 *        Declarations/definitions for "StringInfo" functions.
 *
 * StringInfo provides an indefinitely-extensible string data type.
 * It can be used to buffer either ordinary C strings (null-terminated text)
 * or arbitrary binary data.  All storage is allocated with palloc().
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 * Portions Copyright (c) 2010-2012 Postgres-XC Development Group
 * 
 * IDENTIFICATION
 *        src/include/cm/stringinfo.h
 *
 * ---------------------------------------------------------------------------------------
 */
#ifndef CM_STRINGINFO_H
#define CM_STRINGINFO_H

#include <stdarg.h>

/*-------------------------
 * StringInfoData holds information about an extensible string.
 *		data	is the current buffer for the string (allocated with palloc).
 *		len		is the current string length.  There is guaranteed to be
 *				a terminating '\0' at data[len], although this is not very
 *				useful when the string holds binary data rather than text.
 *		maxlen	is the allocated size in bytes of 'data', i.e. the maximum
 *				string size (including the terminating '\0' char) that we can
 *				currently store in 'data' without having to reallocate
 *				more space.  We must always have maxlen > len.
 *		cursor	is initialized to zero by makeStringInfo or initStringInfo,
 *				but is not otherwise touched by the stringinfo.c routines.
 *				Some routines use it to scan through a StringInfo.
 *-------------------------
 */
#define MSG_READ_LEN (4)
typedef struct CM_StringInfoData {
    char* data;
    int len;
    int maxlen;
    int cursor;
    int qtype;
    int msglen;
    char msgReadData[MSG_READ_LEN];
    int msgReadLen;
} CM_StringInfoData;

typedef CM_StringInfoData* CM_StringInfo;

#define CM_MaxAllocSize ((Size)(70 * 1024)) /* CM_MSG_MAX_LENGTH */

/*------------------------
 * There are two ways to create a StringInfo object initially:
 *
 * StringInfo stringptr = makeStringInfo();
 *		Both the StringInfoData and the data buffer are palloc'd.
 *
 * StringInfoData string;
 * initStringInfo(&string);
 *		The data buffer is palloc'd but the StringInfoData is just local.
 *		This is the easiest approach for a StringInfo object that will
 *		only live as long as the current routine.
 *
 * To destroy a StringInfo, pfree() the data buffer, and then pfree() the
 * StringInfoData if it was palloc'd.  There's no special support for this.
 *
 * NOTE: some routines build up a string using StringInfo, and then
 * release the StringInfoData but return the data string itself to their
 * caller.	At that point the data string looks like a plain palloc'd
 * string.
 *-------------------------
 */

/*------------------------
 * makeStringInfo
 * Create an empty 'StringInfoData' & return a pointer to it.
 */
extern CM_StringInfo CM_makeStringInfo(void);

/*------------------------
 * initStringInfo
 * Initialize a StringInfoData struct (with previously undefined contents)
 * to describe an empty string.
 */
extern void CM_initStringInfo(CM_StringInfo str);

/*------------------------
 * resetStringInfo
 * Clears the current content of the StringInfo, if any. The
 * StringInfo remains valid.
 */
extern void CM_resetStringInfo(CM_StringInfo str);

/*------------------------
 * enlargeStringInfo
 * Make sure a StringInfo's buffer can hold at least 'needed' more bytes.
 */
extern int CM_enlargeStringInfo(CM_StringInfo str, int needed);

extern int CM_is_str_all_digit(const char* name);
extern void CM_destroyStringInfo(CM_StringInfo str);
extern void CM_freeStringInfo(CM_StringInfo str);

#endif /* STRINGINFO_H */
