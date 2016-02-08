#ifndef AUTH_STATS_H
#define AUTH_STATS_H

struct auth_stats {
	uint32_t auth_success_count;
	uint32_t auth_master_success_count;
	uint32_t auth_failure_count;
	uint32_t auth_db_tempfail_count;

	uint32_t auth_cache_hit_count;
	uint32_t auth_cache_miss_count;
};

extern const struct stats_vfuncs auth_stats_vfuncs;

#endif
