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

static int file_lock(int fd, int wait_lock, int lock_type,
		     unsigned int timeout)
{
	struct flock fl;
	time_t timeout_time;

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

	while (fcntl(fd, wait_lock ? F_SETLKW : F_SETLK, &fl) < 0) {
		if (!wait_lock && (errno == EACCES || errno == EAGAIN))
			return 0;

		if (errno != EINTR)
			return -1;

		if (timeout != 0 && time(NULL) >= timeout_time) {
			errno = EAGAIN;
			return 0;
		}
	}

	return 1;
}

int file_try_lock(int fd, int lock_type)
{
	return file_lock(fd, FALSE, lock_type, 0);
}

int file_wait_lock(int fd, int lock_type, unsigned int timeout)
{
	int ret;

	ret = file_lock(fd, TRUE, lock_type, timeout);
	return ret;
}
