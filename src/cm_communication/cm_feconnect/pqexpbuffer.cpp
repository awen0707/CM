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
 * pqexpbuffer.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_communication/cm_feconnect/pqexpbuffer.cpp
 *
 * -------------------------------------------------------------------------
 */

#include "cm/cm_c.h"

#include <limits.h>

#include "elog.h"
#include "cm/pqexpbuffer.h"

/* All "broken" PQExpBuffers point to this string. */
static const char oomBuf[1] = "";

/*
 * markPQExpBufferBroken
 *
 * Put a PQExpBuffer in "broken" state if it isn't already.
 */
static void markPQExpBufferBroken(PQExpBuffer strBuf)
{
    if (strBuf->data != oomBuf) {
        FREE_AND_RESET(strBuf->data);
    }
    /*
     * Casting away const here is a bit ugly, but it seems preferable to
     * not marking oom_buffer const.  We want to do that to encourage the
     * compiler to put oom_buffer in read-only storage, so that anyone who
     * tries to scribble on a broken PQExpBuffer will get a failure.
     */
    strBuf->data = (char*)oomBuf;
    strBuf->len = 0;
    strBuf->maxlen = 0;
}

/*
 * initCMPQExpBuffer
 *
 * Initialize a PQExpBufferData struct (with previously undefined contents)
 * to describe an empty string.
 */
void initCMPQExpBuffer(PQExpBuffer strBuf)
{
    strBuf->data = (char*)malloc(INITIAL_EXPBUFFER_SIZE);
    if (strBuf->data == NULL) {
        strBuf->data = (char*)oomBuf; /* see comment above */
        strBuf->maxlen = 0;
        strBuf->len = 0;
    } else {
        strBuf->maxlen = INITIAL_EXPBUFFER_SIZE;
        strBuf->len = 0;
        strBuf->data[0] = '\0';
    }
}

/*
 * termCMPQExpBuffer(strBuf)
 *		free()s the data buffer but not the PQExpBufferData itself.
 *		This is the inverse of initCMPQExpBuffer().
 */
void termCMPQExpBuffer(PQExpBuffer strBuf)
{
    if (strBuf->data != oomBuf) {
        FREE_AND_RESET(strBuf->data);
    }

    /* just for luck, make the buffer validly empty. */
    strBuf->data = (char*)oomBuf; /* see comment above */
    strBuf->maxlen = 0;
    strBuf->len = 0;
}

/*
 * resetCMPQExpBuffer
 *		Reset a PQExpBuffer to empty
 *
 * Note: if possible, a "broken" PQExpBuffer is returned to normal.
 */
void resetCMPQExpBuffer(PQExpBuffer strBuf)
{
    if (strBuf != NULL) {
        if ((strBuf->data != NULL) && strBuf->data != oomBuf) {
            strBuf->len = 0;
            strBuf->data[0] = '\0';
        } else {
            /* try to reinitialize to valid state */
            initCMPQExpBuffer(strBuf);
        }
    }
}

/*
 * enlargeCMPQExpBuffer
 * Make sure there is enough space for 'needed' more bytes in the buffer
 * ('needed' does not include the terminating null).
 *
 * Returns 1 if OK, 0 if failed to enlarge buffer.  (In the latter case
 * the buffer is left in "broken" state.)
 */
int enlargeCMPQExpBuffer(PQExpBuffer strBuf, size_t needed)
{
    size_t newlen;

    if (PQExpBufferBroken(strBuf)) {
        return 0; /* already failed */
    }

    /*
     * Guard against ridiculous "needed" values, which can occur if we're fed
     * bogus data.	Without this, we can get an overflow or infinite loop in
     * the following.
     */
    if (needed >= ((size_t)INT_MAX - strBuf->len)) {
        markPQExpBufferBroken(strBuf);
        return 0;
    }

    needed += strBuf->len + 1; /* total space required now */

    /* Because of the above test, we now have needed <= INT_MAX */
    if (needed <= strBuf->maxlen) {
        return 1; /* got enough space already */
    }

    /*
     * We don't want to allocate just a little more space with each append;
     * for efficiency, double the buffer size each time it overflows.
     * Actually, we might need to more than double it if 'needed' is big...
     */
    newlen = (strBuf->maxlen > 0) ? (2 * strBuf->maxlen) : 64;
    while (needed > newlen) {
        newlen = 2 * newlen;
    }

    /*
     * Clamp to INT_MAX in case we went past it.  Note we are assuming here
     * that INT_MAX <= UINT_MAX/2, else the above loop could overflow.	We
     * will still have newlen >= needed.
     */
    if (newlen > (size_t)INT_MAX) {
        newlen = (size_t)INT_MAX;
    }

    char *newdata = (char*)malloc(newlen);
    if (newdata != NULL) {
        if (strBuf->data != NULL) {
            errno_t rc = memcpy_s(newdata, newlen, strBuf->data, strBuf->maxlen);
            securec_check_errno(rc, (void)rc);
            FREE_AND_RESET(strBuf->data);
        }
        strBuf->data = newdata;
        strBuf->maxlen = newlen;
        return 1;
    }

    markPQExpBufferBroken(strBuf);
    return 0;
}

/*
 * printfCMPQExpBuffer
 * Format text data under the control of fmt (an sprintf-like format string)
 * and insert it into strBuf.	More space is allocated to strBuf if necessary.
 * This is a convenience routine that does the same thing as
 * resetCMPQExpBuffer() followed by appendCMPQExpBuffer().
 */
void printfCMPQExpBuffer(PQExpBuffer strBuf, const char* fmt, ...)
{
    va_list args;
    size_t avail;
    int nprinted;

    resetCMPQExpBuffer(strBuf);

    if (PQExpBufferBroken(strBuf)) {
        return; /* already failed */
    }

    for (;;) {
        /*
         * Try to format the given string into the available space; but if
         * there's hardly any space, don't bother trying, just fall through to
         * enlarge the buffer first.
         */
        if (strBuf->maxlen > strBuf->len + 16) {
            avail = strBuf->maxlen - strBuf->len - 1;
            va_start(args, fmt);
            nprinted = vsnprintf_s(strBuf->data + strBuf->len, strBuf->maxlen - strBuf->len, avail, fmt, args);
            va_end(args);

            /*
             * Note: some versions of vsnprintf return the number of chars
             * actually stored, but at least one returns -1 on failure. Be
             * conservative about believing whether the print worked.
             */
            if (nprinted >= 0 && nprinted < (int)avail - 1) {
                /* Success.  Note nprinted does not include trailing null. */
                strBuf->len += (size_t)nprinted;
                break;
            }
        }
        /* Double the buffer size and try again. */
        if (!enlargeCMPQExpBuffer(strBuf, strBuf->maxlen)) {
            return; /* oops, out of memory */
        }
    }
}

/*
 * appendCMPQExpBuffer
 *
 * Format text data under the control of fmt (an sprintf-like format string)
 * and append it to whatever is already in str.  More space is allocated
 * to str if necessary.  This is sort of like a combination of sprintf and
 * strcat.
 */
void appendCMPQExpBuffer(PQExpBuffer strBuf, const char* fmt, ...)
{
    va_list args;
    size_t avail;
    int nprinted;

    if (PQExpBufferBroken(strBuf)) {
        return; /* already failed */
    }

    for (;;) {
        /*
         * Try to format the given string into the available space; but if
         * there's hardly any space, don't bother trying, just fall through to
         * enlarge the buffer first.
         */
        if (strBuf->maxlen > strBuf->len + 16) {
            avail = strBuf->maxlen - strBuf->len - 1;
            va_start(args, fmt);
            nprinted = vsnprintf_s(strBuf->data + strBuf->len, strBuf->maxlen - strBuf->len, avail, fmt, args);
            va_end(args);

            /*
             * Note: some versions of vsnprintf return the number of chars
             * actually stored, but at least one returns -1 on failure. Be
             * conservative about believing whether the print worked.
             */
            if (nprinted >= 0 && nprinted < (int)avail - 1) {
                /* Success.  Note nprinted does not include trailing null. */
                strBuf->len += (size_t)nprinted;
                break;
            }
        }
        /* Double the buffer size and try again. */
        if (!enlargeCMPQExpBuffer(strBuf, strBuf->maxlen)) {
            return; /* oops, out of memory */
        }
    }
}

/*
 * appendBinaryCMPQExpBuffer
 *
 * Append arbitrary binary data to a PQExpBuffer, allocating more space
 * if necessary.
 */
void appendBinaryCMPQExpBuffer(PQExpBuffer strBuf, const char* data, size_t datalen)
{
    /* Make more room if needed */
    if (!enlargeCMPQExpBuffer(strBuf, datalen)) {
        return;
    }

    /* OK, append the data */
    errno_t rc = memcpy_s(strBuf->data + strBuf->len, strBuf->maxlen - strBuf->len, data, datalen);
    securec_check_errno(rc, (void)rc);
    strBuf->len += datalen;

    /*
     * Keep a trailing null in place, even though it's probably useless for
     * binary data...
     */
    strBuf->data[strBuf->len] = '\0';
}
