/* Copyright (c) 2002-2003 Timo Sirainen */

#include "lib.h"
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
	unsigned int next_alarm;

	if (timeout == 0)
		timeout_time = 0;
	else {
		timeout_time = time(NULL) + timeout;
		alarm(I_MIN(timeout, 5));
	}

	fl.l_type = lock_type;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;

	while (fcntl(fd, timeout != 0 ? F_SETLKW : F_SETLK, &fl) < 0) {
		if (timeout == 0 && (errno == EACCES || errno == EAGAIN)) {
			alarm(0);
			return 0;
		}

		if (errno != EINTR) {
			alarm(0);
			return -1;
		}

		now = time(NULL);
		if (timeout != 0 && now >= timeout_time) {
			errno = EAGAIN;
			alarm(0);
			return 0;
		}

		next_alarm = (timeout_time - now) % 5;
		if (next_alarm == 0)
			next_alarm = 5;
		alarm(next_alarm);

		if (callback != NULL)
			callback(timeout_time - now, context);
	}

	alarm(0);
	return 1;
}
