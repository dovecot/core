/* Copyright (c) 2001-2003 Timo Sirainen */

#include "lib.h"
#include "lib-signals.h"

#include <stdio.h>
#include <signal.h>

int lib_signal_kill;
unsigned int lib_signal_hup_count;
unsigned int lib_signal_usr1_count, lib_signal_usr2_count;

static void (*quit_handler) (int);

static void sig_counter(int signo)
{
#ifndef HAVE_SIGACTION
	/* some systems may have changed the signal handler to default one */
        signal(signo, sig_counter);
#endif

	switch (signo) {
	case SIGHUP:
		lib_signal_hup_count++;
		break;
	case SIGUSR1:
		lib_signal_usr1_count++;
		break;
	case SIGUSR2:
		lib_signal_usr2_count++;
		break;
	}
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
	act.sa_handler = sig_counter;
	while (sigaction(SIGHUP, &act, NULL) < 0) {
		if (errno != EINTR)
			i_fatal("sigaction(): %m");
	}
	while (sigaction(SIGUSR1, &act, NULL) < 0) {
		if (errno != EINTR)
			i_fatal("sigaction(): %m");
	}
	while (sigaction(SIGUSR2, &act, NULL) < 0) {
		if (errno != EINTR)
			i_fatal("sigaction(): %m");
	}

	/* we want to just ignore SIGALRM, but to get it to abort syscalls
	   with EINTR we can't just set it to SIG_IGN. sig_counter handler
	   is good enough. */
	while (sigaction(SIGALRM, &act, NULL) < 0) {
		if (errno != EINTR)
			i_fatal("sigaction(): %m");
	}
#else
        signal(SIGHUP, sig_counter);
        signal(SIGUSR1, sig_counter);
        signal(SIGUSR2, sig_counter);
        signal(SIGALRM, sig_counter);
#endif

	/* these signals should be called only once, so it's safe to use
	   signal() */
	signal(SIGINT, sig_quit);
        signal(SIGTERM, sig_quit);
        signal(SIGPIPE, SIG_IGN);
}
