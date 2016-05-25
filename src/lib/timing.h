#ifndef TIMING_H
#define TIMING_H

struct timing *timing_init(void);
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
/* Returns events' approximate (through random subsampling) 95th percentile. */
uint64_t timing_get_95th(const struct timing *timing);

#endif
