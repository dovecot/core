/*
 alarm-hup.c - Send SIGHUP once in a while to avoid infinitely blocking calls

    Copyright (c) 2002 Timo Sirainen

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
#include "alarm-hup.h"

#include <signal.h>
#include <unistd.h>

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
	/* we need fcntl() to stop with EINTR */
	if (raise(SIGHUP) < 0)
		i_fatal("kill(): %m");

	/* do it again */
	alarm(alarm_timeout);

#ifndef HAVE_SIGACTION
	signal(SIGALRM, sig_alarm);
#endif
}

void alarm_hup_init(void)
{
#ifdef HAVE_SIGACTION
	struct sigaction act;
#endif

	if (initialized)
		return;
	initialized = TRUE;

#ifdef HAVE_SIGACTION
	if (sigemptyset(&act.sa_mask) < 0)
		i_fatal("sigemptyset(): %m");
	act.sa_flags = 0;
	act.sa_handler = sig_alarm;

	while (sigaction(SIGALRM, &act, NULL) < 0) {
		if (errno != EINTR)
			i_fatal("sigaction(): %m");
	}
#else
	/* at least Linux blocks raise(SIGHUP) inside SIGALRM
	   handler if it's added with signal().. sigaction() should
	   be pretty much everywhere though, so this code is pretty
	   useless. */
#warning timeouting may not work
	signal(SIGALRM, sig_alarm);
#endif

	alarm(alarm_timeout);
}

void alarm_hup_deinit(void)
{
#ifdef HAVE_SIGACTION
	struct sigaction act;
#endif

	if (!initialized)
		return;
	initialized = FALSE;

	alarm(0);

#ifdef HAVE_SIGACTION
	act.sa_handler = SIG_DFL;
	while (sigaction(SIGALRM, &act, NULL) < 0) {
		if (errno != EINTR)
			i_fatal("sigaction(): %m");
	}
#else
	signal(SIGALRM, SIG_DFL);
#endif
}
