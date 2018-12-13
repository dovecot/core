/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "sleep.h"

#include <time.h>

static bool ATTR_NOWARN_UNUSED_RESULT
sleep_timespec(const struct timespec *ts_sleep, bool interruptible)
{
	struct timespec ts_remain = *ts_sleep;

	while (nanosleep(&ts_remain, &ts_remain) < 0) {
		if (errno != EINTR)
			i_fatal("nanosleep(): %m");
		if (interruptible)
			return FALSE;
	}
	return TRUE;
}

void i_sleep_usecs(unsigned long long usecs)
{
	struct timespec ts_sleep;

	ts_sleep.tv_sec = (time_t)(usecs / 1000000);
	ts_sleep.tv_nsec = (long)(usecs % 1000000) * 1000;
	sleep_timespec(&ts_sleep, FALSE);
}

void i_sleep_msecs(unsigned int msecs)
{
	struct timespec ts_sleep;

	ts_sleep.tv_sec = (time_t)(msecs / 1000);
	ts_sleep.tv_nsec = (long)(msecs % 1000) * 1000000;
	sleep_timespec(&ts_sleep, FALSE);
}

void i_sleep_secs(time_t secs)
{
	struct timespec ts_sleep;

	ts_sleep.tv_sec = secs;
	ts_sleep.tv_nsec = 0;
	sleep_timespec(&ts_sleep, FALSE);
}

bool i_sleep_intr_usecs(unsigned long long usecs)
{
	struct timespec ts_sleep;

	ts_sleep.tv_sec = (time_t)(usecs / 1000000);
	ts_sleep.tv_nsec = (long)(usecs % 1000000) * 1000;
	return sleep_timespec(&ts_sleep, TRUE);
}

bool i_sleep_intr_msecs(unsigned int msecs)
{
	struct timespec ts_sleep;

	ts_sleep.tv_sec = (time_t)(msecs / 1000);
	ts_sleep.tv_nsec = (long)(msecs % 1000) * 1000000;
	return sleep_timespec(&ts_sleep, TRUE);
}

bool i_sleep_intr_secs(time_t secs)
{
	struct timespec ts_sleep;

	ts_sleep.tv_sec = secs;
	ts_sleep.tv_nsec = 0;
	return sleep_timespec(&ts_sleep, TRUE);
}
