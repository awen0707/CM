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
 * pqsignal.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_communication/cm_libpq/pqsignal.cpp
 *
 * -------------------------------------------------------------------------
 */
#include <signal.h>
#include "cm/cm_c.h"
#include "cm/pqsignal.h"

sigset_t unblock_sig, block_sig;

/*
 * Initialize BlockSig, UnBlockSig, and AuthBlockSig.
 *
 * BlockSig is the set of signals to block when we are trying to block
 * signals.  This includes all signals we normally expect to get, but NOT
 * signals that should never be turned off.
 *
 * AuthBlockSig is the set of signals to block during authentication;
 * it's essentially BlockSig minus SIGTERM, SIGQUIT, SIGALRM.
 *
 * UnBlockSig is the set of signals to block when we don't want to block
 * signals (is this ever nonzero??)
 */
void init_signal_mask(void)
{
#ifdef HAVE_SIGPROCMASK

    (void)sigemptyset(&unblock_sig);
    /* First set all signals, then clear some. */
    (void)sigfillset(&block_sig);

    /*
     * Unmark those signals that should never be blocked. Some of these signal
     * names don't exist on all platforms.  Most do, but might as well ifdef
     * them all for consistency...
     */
#ifdef SIGTRAP
    (void)sigdelset(&block_sig, SIGTRAP);
#endif
#ifdef SIGABRT
    (void)sigdelset(&block_sig, SIGABRT);
#endif
#ifdef SIGILL
    (void)sigdelset(&block_sig, SIGILL);
#endif
#ifdef SIGFPE
    (void)sigdelset(&block_sig, SIGFPE);
#endif
#ifdef SIGSEGV
    (void)sigdelset(&block_sig, SIGSEGV);
#endif
#ifdef SIGBUS
    (void)sigdelset(&block_sig, SIGBUS);
#endif
#ifdef SIGSYS
    (void)sigdelset(&block_sig, SIGSYS);
#endif
#ifdef SIGCONT
    (void)sigdelset(&block_sig, SIGCONT);
#endif
#ifdef SIGQUIT
    (void)sigdelset(&block_sig, SIGQUIT);
#endif
#ifdef SIGTERM
    (void)sigdelset(&block_sig, SIGTERM);
#endif
#ifdef SIGALRM
    (void)sigdelset(&block_sig, SIGALRM);
#endif
#ifdef SIGCHLD
    (void)sigdelset(&block_sig, SIGCHLD);
#endif
#ifdef SIGINT
    (void)sigdelset(&block_sig, SIGINT);
#endif
#ifdef SIGUSR1
    (void)sigdelset(&block_sig, SIGUSR1);
#endif
#ifdef SIGUSR2
    (void)sigdelset(&block_sig, SIGUSR2);
#endif
#ifdef SIGHUP
    (void)sigdelset(&block_sig, SIGHUP);
#endif

#else
    /* Set the signals we want. */
    block_sig = sigmask(SIGQUIT) | sigmask(SIGTERM) | sigmask(SIGALRM) |
                /* common signals between two */
                sigmask(SIGHUP) | sigmask(SIGINT) | sigmask(SIGUSR1) | sigmask(SIGUSR2) | sigmask(SIGWINCH) |
                sigmask(SIGFPE);
#endif
}

/* Win32 signal handling is in backend/port/win32/signal.c */
#ifndef WIN32
void setup_signal_handle(int signo, sigfunc func)
{
#if !defined(HAVE_POSIX_SIGNALS)
    return;
#else
    struct sigaction act, oact;

    act.sa_handler = func;
    (void)sigemptyset(&act.sa_mask);
    act.sa_flags = SA_ONSTACK;
    if (signo != SIGALRM) {
        act.sa_flags |= SA_RESTART;
    }
#ifdef SA_NOCLDSTOP
    if (signo == SIGCHLD) {
        act.sa_flags |= SA_NOCLDSTOP;
    }
#endif
    if (sigaction(signo, &act, &oact) < 0) {
        return;
    }
    return;
#endif /* !HAVE_POSIX_SIGNALS */
}
#endif /* WIN32 */
