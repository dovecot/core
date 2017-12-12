#ifndef TIMING_H
#define TIMING_H

struct timing *timing_init(void);
struct timing *timing_init_with_size(unsigned int sample_count);
void timing_deinit(struct timing **timing);

/* Reset all events. */
void timing_reset(struct timing *timing);

/* Add a new event that took the specified number of usecs. */
void timing_add_usecs(struct timing *timing, uint64_t usecs);

/* Returns number of events added. */
unsigned int timing_get_count(const struct timing *timing);
/* Returns the sum of all usecs added. */
uint64_t timing_get_sum(const struct timing *timing);

/* Returns events' minimum. */
uint64_t timing_get_min(const struct timing *timing);
/* Returns events' maximum. */
uint64_t timing_get_max(const struct timing *timing);
/* Returns events' average. */
uint64_t timing_get_avg(const struct timing *timing);
/* Returns events' approximate (through random subsampling) median. */
uint64_t timing_get_median(const struct timing *timing);
/* Returns events' approximate (through random subsampling) percentile.
   fraction parameter is in the range (0., 1.], so 95th %-ile is 0.95. */
uint64_t timing_get_percentile(const struct timing *timing, double fraction);
/* Returns events' approximate (through random subsampling) 95th percentile. */
static inline uint64_t timing_get_95th(const struct timing *timing)
{
	return timing_get_percentile(timing, 0.95);
}

#endif
