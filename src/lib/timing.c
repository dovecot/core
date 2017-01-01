/* Copyright (c) 2015-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "timing.h"
#include "sort.h"

/* In order to have a vaguely accurate 95th percentile, you need way
   more than 20 in your subsample. */
#define TIMING_SUBSAMPLING_BUFFER (20*24) /* 20*24 fits in a page */

struct timing {
	unsigned int count;
	bool     sorted;
	uint64_t min;
	uint64_t samples[TIMING_SUBSAMPLING_BUFFER];
	uint64_t max;
	uint64_t sum;
};

struct timing *timing_init(void)
{
	return i_new(struct timing, 1);
}

void timing_deinit(struct timing **_timing)
{
	i_free_and_null(*_timing);
}

void timing_reset(struct timing *timing)
{
	i_zero(timing);
}

void timing_add_usecs(struct timing *timing, uint64_t usecs)
{
	if (timing->count < TIMING_SUBSAMPLING_BUFFER) {
		timing->samples[timing->count] = usecs;
		if (timing->count == 0)
			timing->min = timing->max = usecs;
	} else {
		unsigned int count = timing->count;
		unsigned int idx;
		if (count > RAND_MAX >> 6)
			idx = (rand()*((uint64_t)RAND_MAX+1) + rand()) % count;
		else
			idx = rand() % count;
		if (idx < TIMING_SUBSAMPLING_BUFFER)
			timing->samples[idx] = usecs;
	}

	timing->count++;
	timing->sum += usecs;
	if (timing->max < usecs)
		timing->max = usecs;
	if (timing->min > usecs)
		timing->min = usecs;
	timing->sorted = FALSE;
}

unsigned int timing_get_count(const struct timing *timing)
{
	return timing->count;
}

uint64_t timing_get_sum(const struct timing *timing)
{
	return timing->sum;
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

	return (timing->sum + timing->count/2) / timing->count;
}

static void timing_ensure_sorted(struct timing *timing)
{
	if (timing->sorted)
		return;

	unsigned int count = (timing->count < TIMING_SUBSAMPLING_BUFFER)
		? timing->count
		: TIMING_SUBSAMPLING_BUFFER;
	i_qsort(timing->samples, count, sizeof(*timing->samples),
		uint64_cmp);
	timing->sorted = TRUE;
}

uint64_t timing_get_median(const struct timing *timing)
{
	if (timing->count == 0)
		return 0;
	/* cast-away const - reading requires sorting */
	timing_ensure_sorted((struct timing *)timing);
	unsigned int count = (timing->count < TIMING_SUBSAMPLING_BUFFER)
		? timing->count
		: TIMING_SUBSAMPLING_BUFFER;
	unsigned int idx1 = (count-1)/2, idx2 = count/2;
	return (timing->samples[idx1] + timing->samples[idx2]) / 2;
}

uint64_t timing_get_95th(const struct timing *timing)
{
	if (timing->count == 0)
		return 0;
	/* cast-away const - reading requires sorting */
	timing_ensure_sorted((struct timing *)timing);
	unsigned int count = (timing->count < TIMING_SUBSAMPLING_BUFFER)
		? timing->count
		: TIMING_SUBSAMPLING_BUFFER;
	unsigned int idx = count - count/20 - 1;
	return timing->samples[idx];
}
