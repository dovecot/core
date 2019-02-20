#ifndef STATS_DIST_H
#define STATS_DIST_H

struct stats_dist *stats_dist_init(void);
struct stats_dist *stats_dist_init_with_size(unsigned int sample_count);
void stats_dist_deinit(struct stats_dist **stats);

/* Reset all events. */
void stats_dist_reset(struct stats_dist *stats);

/* Add a new event. */
void stats_dist_add(struct stats_dist *stats, uint64_t value);

/* Returns number of events added. */
unsigned int stats_dist_get_count(const struct stats_dist *stats);
/* Returns the sum of all events. */
uint64_t stats_dist_get_sum(const struct stats_dist *stats);

/* Returns events' minimum. */
uint64_t stats_dist_get_min(const struct stats_dist *stats);
/* Returns events' maximum. */
uint64_t stats_dist_get_max(const struct stats_dist *stats);
/* Returns events' average. */
double stats_dist_get_avg(const struct stats_dist *stats);
/* Returns events' approximate (through random subsampling) median. */
uint64_t stats_dist_get_median(const struct stats_dist *stats);
/* Returns events' variance */
double stats_dist_get_variance(const struct stats_dist *stats);
/* Returns events' approximate (through random subsampling) percentile.
   fraction parameter is in the range (0., 1.], so 95th %-ile is 0.95. */
uint64_t stats_dist_get_percentile(const struct stats_dist *stats, double fraction);
/* Returns events' approximate (through random subsampling) 95th percentile. */
static inline uint64_t stats_dist_get_95th(const struct stats_dist *stats)
{
	return stats_dist_get_percentile(stats, 0.95);
}
/* Returns the sample array */
const uint64_t *stats_dist_get_samples(const struct stats_dist *stats,
				       unsigned int *count_r);
#endif
