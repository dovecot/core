/* Copyright (c) 2016-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "stats.h"
#include "stats-parser.h"
#include "auth-stats.h"

static struct stats_parser_field auth_stats_fields[] = {
#define E(parsename, name, type) { parsename, offsetof(struct auth_stats, name), sizeof(((struct auth_stats *)0)->name), type }
#define EN(parsename, name) E(parsename, name, STATS_PARSER_TYPE_UINT)
	EN("auth_successes", auth_success_count),
	EN("auth_master_successes", auth_master_success_count),
	EN("auth_failures", auth_failure_count),
	EN("auth_db_tempfails", auth_db_tempfail_count),

	EN("auth_cache_hits", auth_cache_hit_count),
	EN("auth_cache_misses", auth_cache_miss_count)
};

static size_t auth_stats_alloc_size(void)
{
	return sizeof(struct auth_stats);
}

static unsigned int auth_stats_field_count(void)
{
	return N_ELEMENTS(auth_stats_fields);
}

static const char *auth_stats_field_name(unsigned int n)
{
	i_assert(n < N_ELEMENTS(auth_stats_fields));

	return auth_stats_fields[n].name;
}

static void
auth_stats_field_value(string_t *str, const struct stats *stats,
		       unsigned int n)
{
	i_assert(n < N_ELEMENTS(auth_stats_fields));

	stats_parser_value(str, &auth_stats_fields[n], stats);
}

static bool
auth_stats_diff(const struct stats *stats1, const struct stats *stats2,
		struct stats *diff_stats_r, const char **error_r)
{
	return stats_parser_diff(auth_stats_fields, N_ELEMENTS(auth_stats_fields),
				 stats1, stats2, diff_stats_r, error_r);
}

static void auth_stats_add(struct stats *dest, const struct stats *src)
{
	stats_parser_add(auth_stats_fields, N_ELEMENTS(auth_stats_fields),
			 dest, src);
}

static bool
auth_stats_have_changed(const struct stats *_prev, const struct stats *_cur)
{
	return memcmp(_prev, _cur, sizeof(struct auth_stats)) != 0;
}

static void auth_stats_export(buffer_t *buf, const struct stats *_stats)
{
	const struct auth_stats *stats = (const struct auth_stats *)_stats;

	buffer_append(buf, stats, sizeof(*stats));
}

static bool
auth_stats_import(const unsigned char *data, size_t size, size_t *pos_r,
		  struct stats *_stats, const char **error_r)
{
	struct auth_stats *stats = (struct auth_stats *)_stats;

	if (size < sizeof(*stats)) {
		*error_r = "auth_stats too small";
		return FALSE;
	}
	memcpy(stats, data, sizeof(*stats));
	*pos_r = sizeof(*stats);
	return TRUE;
}

const struct stats_vfuncs auth_stats_vfuncs = {
	"auth",
	auth_stats_alloc_size,
	auth_stats_field_count,
	auth_stats_field_name,
	auth_stats_field_value,
	auth_stats_diff,
	auth_stats_add,
	auth_stats_have_changed,
	auth_stats_export,
	auth_stats_import
};

/* for the stats_auth plugin: */
void stats_auth_init(void);
void stats_auth_deinit(void);

static struct stats_item *auth_stats_item;

void stats_auth_init(void)
{
	auth_stats_item = stats_register(&auth_stats_vfuncs);
}

void stats_auth_deinit(void)
{
	stats_unregister(&auth_stats_item);
}
