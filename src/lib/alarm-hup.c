/* Copyright (c) 2002-2003 Timo Sirainen */

#include "lib.h"
#include "alarm-hup.h"

#include <signal.h>
#include <unistd.h>
#include <stdlib.h>

static int initialized = FALSE;
static unsigned int alarm_timeout = 30;

unsigned int alarm_hup_set_interval(unsigned int timeout)
{
	unsigned int old;

	old = alarm_timeout;
	alarm_timeout = timeout;

	alarm(alarm_timeout);
	return old;
}

static void sig_alarm(int signo __attr_unused__)
{
	/* do it again */
	alarm(alarm_timeout);
}

void alarm_hup_init(void)
{
	struct sigaction act;

	if (initialized)
		return;
	initialized = TRUE;

	if (sigemptyset(&act.sa_mask) < 0)
		i_fatal("sigemptyset(): %m");
	act.sa_flags = 0;
	act.sa_handler = sig_alarm;

	while (sigaction(SIGALRM, &act, NULL) < 0) {
		if (errno != EINTR)
			i_fatal("sigaction(): %m");
	}

	alarm(alarm_timeout);
}

void alarm_hup_deinit(void)
{
	struct sigaction act;

	if (!initialized)
		return;
	initialized = FALSE;

	alarm(0);

	if (sigemptyset(&act.sa_mask) < 0)
		i_fatal("sigemptyset(): %m");
	act.sa_flags = 0;
	act.sa_handler = SIG_DFL;
	while (sigaction(SIGALRM, &act, NULL) < 0) {
		if (errno != EINTR)
			i_fatal("sigaction(): %m");
	}
}
