/* Copyright (c) 2001-2003 Timo Sirainen */

#include "lib.h"
#include "lib-signals.h"

#include <stdio.h>
#include <signal.h>

int lib_signal_kill;
unsigned int lib_signal_hup_count;

static void (*quit_handler) (int);

static void sig_hup(int signo __attr_unused__)
{
#ifndef HAVE_SIGACTION
	/* some systems may have changed the signal handler to default one */
        signal(SIGHUP, sig_hup);
#endif

        lib_signal_hup_count++;
}

static void sig_quit(int signo)
{
	/* if we get killed after this, just die instead of coming back here. */
	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);

	lib_signal_kill = signo;
	quit_handler(signo);
}

void lib_init_signals(void (*sig_quit_handler) (int))
{
#ifdef HAVE_SIGACTION
	struct sigaction act;
#endif

        lib_signal_kill = 0;
	lib_signal_hup_count = 0;
	quit_handler = sig_quit_handler;

	/* signal() behaviour is a bit inconsistent between systems
	   after the signal handler has been called. If the signal
	   isn't ignored, or your handler doesn't kill the program,
	   sigaction() should be used. */
#ifdef HAVE_SIGACTION
	if (sigemptyset(&act.sa_mask) < 0)
		i_fatal("sigemptyset(): %m");
	act.sa_flags = 0;
	act.sa_handler = sig_hup;
	while (sigaction(SIGHUP, &act, NULL) < 0) {
		if (errno != EINTR)
			i_fatal("sigaction(): %m");
	}
#else
        signal(SIGHUP, sig_hup);
#endif

	/* these signals should be called only once, so it's safe to use
	   signal() */
	signal(SIGINT, sig_quit);
        signal(SIGTERM, sig_quit);
        signal(SIGPIPE, SIG_IGN);
        signal(SIGALRM, SIG_IGN);
}
