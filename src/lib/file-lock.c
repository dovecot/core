/*
 file-lock.c - Simple way to lock whole file descriptor

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
#include "file-lock.h"

#include <signal.h>

static int got_alarm = FALSE;

static void sig_alarm(int signo __attr_unused__)
{
	got_alarm = TRUE;

	/* we need fcntl() to stop with EINTR */
	if (raise(SIGHUP) < 0)
		i_fatal("kill(): %m");
}

static int file_lock(int fd, int wait_lock, int lock_type)
{
	struct flock fl;

	fl.l_type = lock_type;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;

	while (fcntl(fd, wait_lock ? F_SETLKW : F_SETLK, &fl) < 0) {
		if (!wait_lock && (errno == EACCES || errno == EAGAIN))
			return 0;

		if (errno != EINTR)
			return -1;

		if (got_alarm) {
			errno = EAGAIN;
			return 0;
		}
	}

	return 1;
}

int file_try_lock(int fd, int lock_type)
{
        got_alarm = FALSE;
	return file_lock(fd, FALSE, lock_type);
}

int file_wait_lock(int fd, int lock_type, unsigned int timeout __attr_unused__)
{
#ifdef HAVE_SIGACTION
	struct sigaction act;
#endif
	int ret;

	got_alarm = FALSE;

	if (timeout > 0 && lock_type != F_UNLCK) {
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
#warning file_wait_lock() timeouting may not work
		signal(SIGALRM, sig_alarm);
#endif

		alarm(timeout);
	}

	ret = file_lock(fd, TRUE, lock_type);

	if (timeout > 0 && lock_type != F_UNLCK) {
		alarm(0);

#ifdef HAVE_SIGACTION
		act.sa_handler = SIG_DFL;
		while (sigaction(SIGALRM, &act, NULL) < 0) {
			if (errno != EINTR)
				i_fatal("sigaction(): %m");
		}
#else
		signal(SIGALRM, SIG_IGN);
#endif
	}
	return ret;
}
