/*
 lib-signals.c : Handling of commonly used signals

    Copyright (c) 2001-2002 Timo Sirainen

    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the
    "Software"), to deal in the Software without restriction, including
    without limitation the rights to use, copy, modify, merge, publish,
    distribute, sublicense, and/or sell copies of the Software, and to
    permit persons to whom the Software is furnished to do so, subject to
    the following conditions:

    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
    SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "lib.h"
#include "lib-signals.h"

#include <stdio.h>
#include <signal.h>

int lib_signal_hup, lib_signal_kill;
static void (*quit_handler) (int);

static void sig_hup(int signo)
{
#ifndef HAVE_SIGACTION
	/* some systems may have changed the signal handler to default one */
        signal(SIGHUP, sig_hup);
#endif

	lib_signal_hup = signo;
}

static void sig_quit(int signo)
{
	/* if we get killed after this, just die instead of coming back here. */
	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);

	/* quit the I/O loop, deinitialization is be done properly */
	lib_signal_kill = signo;
	quit_handler(signo);
}

void lib_init_signals(void (*sig_quit_handler) (int))
{
#ifdef HAVE_SIGACTION
	struct sigaction act;
#endif

        lib_signal_kill = 0;
	lib_signal_hup = 0;
	quit_handler = sig_quit_handler;

	/* signal() behaviour is a bit inconsistent between systems
	   after the signal handler has been called. If the signal
	   isn't ignored, or your handler doesn't kill the program,
	   sigaction() should be used. */
#ifdef HAVE_SIGACTION
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	act.sa_handler = sig_hup;
	sigaction(SIGHUP, &act, NULL);
#else
        signal(SIGHUP, sig_hup);
#endif

	/* these signals should be called only once, so it's safe to use
	   signal() */
	signal(SIGINT, sig_quit);
        signal(SIGTERM, sig_quit);
        signal(SIGPIPE, SIG_IGN);
}
