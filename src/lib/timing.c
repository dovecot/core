/* Copyright (c) 2015 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "bsearch-insert-pos.h"
#include "timing.h"

#define TIMING_MAX_BUCKET_COUNT 20

struct timing {
	unsigned int count;
	uint64_t min, max, sum;
};

struct timing *timing_init(void)
{
	return i_new(struct timing, 1);
}

void timing_deinit(struct timing **_timing)
{
	i_free_and_null(*_timing);
}


void timing_add_usecs(struct timing *timing, uint64_t usecs)
{
	if (timing->count++ == 0) {
		timing->min = timing->max = timing->sum = usecs;
	} else {
		if (timing->min > usecs)
			timing->min = usecs;
		if (timing->max < usecs)
			timing->max = usecs;
		timing->sum += usecs;
	}
}

unsigned int timing_get_count(const struct timing *timing)
{
	return timing->count;
}

uint64_t timing_get_min(const struct timing *timing)
{
	return timing->min;
}

uint64_t timing_get_max(const struct timing *timing)
{
	return timing->max;
}

uint64_t timing_get_avg(const struct timing *timing)
{
	if (timing->count == 0)
		return 0;

	return timing->sum / timing->count;
}
