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
#include "alarm-hup.h"
#include "file-lock.h"

#include <time.h>
#include <signal.h>

int file_try_lock(int fd, int lock_type)
{
	return file_wait_lock_full(fd, lock_type, 0, NULL, NULL);
}

int file_wait_lock(int fd, int lock_type)
{
	return file_wait_lock_full(fd, lock_type, DEFAULT_LOCK_TIMEOUT,
				   NULL, NULL);
}

int file_wait_lock_full(int fd, int lock_type, unsigned int timeout,
			void (*callback)(unsigned int secs_left, void *context),
			void *context)
{
	struct flock fl;
	time_t timeout_time, now;

	if (timeout == 0)
		timeout_time = 0;
	else {
		alarm_hup_init();
		timeout_time = time(NULL) + timeout;
	}

	fl.l_type = lock_type;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;

	while (fcntl(fd, timeout != 0 ? F_SETLKW : F_SETLK, &fl) < 0) {
		if (timeout == 0 && (errno == EACCES || errno == EAGAIN))
			return 0;

		if (errno != EINTR)
			return -1;

		now = time(NULL);
		if (timeout != 0 && now >= timeout_time) {
			errno = EAGAIN;
			return 0;
		}

		if (callback != NULL)
			callback(timeout_time - now, context);
	}

	return 1;
}
