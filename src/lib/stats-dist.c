/* Copyright (c) 2015-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "stats-dist.h"
#include "sort.h"

/* In order to have a vaguely accurate 95th percentile, you need way
   more than 20 in your subsample. */
#define TIMING_DEFAULT_SUBSAMPLING_BUFFER (20*24) /* 20*24 fits in a page */

struct stats_dist {
	unsigned int sample_count;
	unsigned int count;
	bool     sorted;
	uint64_t min;
	uint64_t max;
	uint64_t sum;
	uint64_t samples[];
};

struct stats_dist *stats_dist_init(void)
{
	return stats_dist_init_with_size(TIMING_DEFAULT_SUBSAMPLING_BUFFER);
}

struct stats_dist *stats_dist_init_with_size(unsigned int sample_count)
{
	i_assert(sample_count > 0);

	struct stats_dist *stats =
		i_malloc(sizeof(struct stats_dist) +
			 sizeof(uint64_t) * sample_count);
	stats->sample_count = sample_count;
	return stats;
}

void stats_dist_deinit(struct stats_dist **_stats)
{
	i_free_and_null(*_stats);
}

void stats_dist_reset(struct stats_dist *stats)
{
	unsigned int sample_count = stats->sample_count;
	i_zero(stats);
	stats->sample_count = sample_count;
}

void stats_dist_add(struct stats_dist *stats, uint64_t value)
{
	if (stats->count < stats->sample_count) {
		stats->samples[stats->count] = value;
		if (stats->count == 0)
			stats->min = stats->max = value;
	} else {
		unsigned int idx = i_rand_limit(stats->count);
		if (idx < stats->sample_count)
			stats->samples[idx] = value;
	}

	stats->count++;
	stats->sum += value;
	if (stats->max < value)
		stats->max = value;
	if (stats->min > value)
		stats->min = value;
	stats->sorted = FALSE;
}

unsigned int stats_dist_get_count(const struct stats_dist *stats)
{
	return stats->count;
}

uint64_t stats_dist_get_sum(const struct stats_dist *stats)
{
	return stats->sum;
}

uint64_t stats_dist_get_min(const struct stats_dist *stats)
{
	return stats->min;
}

uint64_t stats_dist_get_max(const struct stats_dist *stats)
{
	return stats->max;
}

double stats_dist_get_avg(const struct stats_dist *stats)
{
	if (stats->count == 0)
		return 0;

	return (double)stats->sum / stats->count;
}

static void stats_dist_ensure_sorted(struct stats_dist *stats)
{
	if (stats->sorted)
		return;

	unsigned int count = (stats->count < stats->sample_count)
		? stats->count
		: stats->sample_count;
	i_qsort(stats->samples, count, sizeof(*stats->samples),
		uint64_cmp);
	stats->sorted = TRUE;
}

uint64_t stats_dist_get_median(const struct stats_dist *stats)
{
	if (stats->count == 0)
		return 0;
	/* cast-away const - reading requires sorting */
	stats_dist_ensure_sorted((struct stats_dist *)stats);
	unsigned int count = (stats->count < stats->sample_count)
		? stats->count
		: stats->sample_count;
	unsigned int idx1 = (count-1)/2, idx2 = count/2;
	return (stats->samples[idx1] + stats->samples[idx2]) / 2;
}

double stats_dist_get_variance(const struct stats_dist *stats)
{
	double sum = 0;
	if (stats->count == 0)
		return 0;

	double avg = stats_dist_get_avg(stats);
	double count = (stats->count < stats->sample_count)
		? stats->count
		: stats->sample_count;

	for(unsigned int i = 0; i < count; i++) {
		sum += (stats->samples[i] - avg)*(stats->samples[i] - avg);
	}

	return sum / count;
}

/* This is independent of the stats framework, useful for any selection task */
static unsigned int stats_dist_get_index(unsigned int range, double fraction)
{
	/* With out of range fractions, we can give the caller what
	   they probably want rather than just crashing. */
	if (fraction >= 1.)
		return range - 1;
	if (fraction <= 0.)
		return 0;

	double idx_float = range * fraction;
	unsigned int idx = idx_float; /* C defaults to rounding down */
	idx_float -= idx;
	/* Exact boundaries belong to the open range below them.
	   As FP isn't exact, and ratios may be specified inexactly,
	   include a small amount of fuzz around the exact boundary. */
	if (idx_float < 1e-8*range)
		idx--;

	return idx;
}

uint64_t stats_dist_get_percentile(const struct stats_dist *stats, double fraction)
{
	if (stats->count == 0)
		return 0;
	/* cast-away const - reading requires sorting */
	stats_dist_ensure_sorted((struct stats_dist *)stats);
	unsigned int count = (stats->count < stats->sample_count)
		? stats->count
		: stats->sample_count;
	unsigned int idx = stats_dist_get_index(count, fraction);
	return stats->samples[idx];
}

const uint64_t *stats_dist_get_samples(const struct stats_dist *stats,
				       unsigned int *count_r)
{
	*count_r = (stats->count < stats->sample_count)
		? stats->count
		: stats->sample_count;
	return stats->samples;
}
