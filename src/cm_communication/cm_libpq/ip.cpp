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
 * ip.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_communication/cm_libpq/ip.cpp
 *
 * -------------------------------------------------------------------------
 */

/* This is intended to be used in both frontend and backend, so use c.h */
#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif
#include "cm/cm_c.h"

/*
 * cmpg_getaddrinfo_all - get address info for Unix, IPv4 and IPv6 sockets
 */
int cmpg_getaddrinfo_all(
    const char* hostname, const char* servname, const struct addrinfo* hintp, struct addrinfo** result)
{
    int rc;

    /* not all versions of getaddrinfo() zero *result on failure */
    *result = NULL;

    /* NULL has special meaning to getaddrinfo(). */
    rc = getaddrinfo(((hostname == NULL) || hostname[0] == '\0') ? NULL : hostname, servname, hintp, result);

    return rc;
}

/*
 * pg_freeaddrinfo_all - free addrinfo structures for IPv4, IPv6, or Unix
 *
 * Note: the ai_family field of the original hint structure must be passed
 * so that we can tell whether the addrinfo struct was built by the system's
 * getaddrinfo() routine or our own getaddrinfo_unix() routine.  Some versions
 * of getaddrinfo() might be willing to return AF_UNIX addresses, so it's
 * not safe to look at ai_family in the addrinfo itself.
 */
void cmpg_freeaddrinfo_all(struct addrinfo* ai)
{
    /* struct was built by getaddrinfo() */
    if (ai != NULL) {
        freeaddrinfo(ai);
    }
}
