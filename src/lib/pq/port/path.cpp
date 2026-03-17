/* -------------------------------------------------------------------------
 *
 * path.c
 *	  portable path handling routines
 *
 * Portions Copyright (c) 1996-2012, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/port/path.c
 *
 * -------------------------------------------------------------------------
 */

#include <sys/stat.h>
#include <stdlib.h>
#include <securec.h>
#include "cm/elog.h"

#ifndef ERROR_LIMIT_LEN
#define ERROR_LIMIT_LEN 256
#endif

#ifndef THR_LOCAL
#ifndef WIN32
#define THR_LOCAL __thread
#else
#define THR_LOCAL __declspec(thread)
#endif
#endif

THR_LOCAL char gs_error_buf[ERROR_LIMIT_LEN];
#ifdef __sparc
int gs_strerror(int errnum)
#else
char *gs_strerror(int errnum)
#endif
{
    return strerror_r(errnum, gs_error_buf, ERROR_LIMIT_LEN);
}

static void trim_directory(char *path)
{
    char *p = NULL;

    if (path[0] == '\0') {
        return;
    }
    /* back up over trailing slash(es) */
    for (p = path + strlen(path) - 1; IS_DIR_SEP(*p) && p > path; p--) {}
    /* back up over directory name */
    for (; !IS_DIR_SEP(*p) && p > path; p--) {}
    /* if multiple slashes before directory name, remove 'em all */
    for (; p > path && IS_DIR_SEP(*(p - 1)); p--) {}
    /* don't erase a leading slash */
    if (p == path && IS_DIR_SEP(*p)) {
        p++;
    }
    *p = '\0';
}

/*
 *	trim_trailing_separator
 *
 * trim off trailing slashes, but not a leading slash
 */
static void trim_trailing_separator(char *path)
{
    char *p = NULL;

    p = path + strlen(path);
    if (p > path) {
        for (p--; p > path && IS_DIR_SEP(*p); p--) {
            *p = '\0';
        }
    }
}

/*
 *	Clean up path by:
 *      o  remove trailing slash
 *      o  remove duplicate adjacent separators
 *      o  remove trailing '.'
 *      o  process trailing '..' ourselves
 */
void canonicalize_path(char *path)
{
    size_t oldLen = strlen(path);
    errno_t ret = 0;

    trim_trailing_separator(path);

    // Remove duplicate adjacent separators
    char *p = path;
    char *to_p = p;
    bool isSep = false;
    for (; *p; p++, to_p++) {
        // Handle many '/', like "/a///b"
        while (*p == '/' && isSep) {
            p++;
        }
        if (to_p != p) {
            *to_p = *p;
        }
        isSep = (*p == '/');
    }
    *to_p = '\0';
    char *spath = path;
    int pendingStrips = 0;
    for (;;) {
        int len = strlen(spath);

        if (len >= 2 && strcmp(spath + len - 2, "/.") == 0) {
            trim_directory(path);
        } else if (strcmp(spath, ".") == 0) {
            // Want to leave "." alone, but "./.." has to become ".."
            if (pendingStrips > 0) {
                *spath = '\0';
            }
            break;
        } else if ((len >= 3 && strcmp(spath + len - 3, "/..") == 0) || strcmp(spath, "..") == 0) {
            trim_directory(path);
            pendingStrips++;
        } else if (pendingStrips > 0 && *spath != '\0') {
            trim_directory(path);
            pendingStrips--;
            // foo/.. should become ".", not empty
            if (*spath == '\0') {
                ret = strcpy_s(spath, len, ".");
                securec_check_errno(ret, (void)ret);
            }
        } else {
            break;
        }
    }

    if (pendingStrips > 0) {
        while (pendingStrips-- > 0) {
            ret = strcat_s(path, oldLen, "../");
            securec_check_errno(ret, (void)ret);
        }
    }
}
