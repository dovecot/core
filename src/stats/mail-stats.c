/* Copyright (c) 2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "time-util.h"
#include "mail-stats.h"

struct mail_stats_parse_map {
	const char *name;
	unsigned int offset;
	unsigned int size;
} parse_map[] = {
#define E(parsename, name) { parsename, offsetof(struct mail_stats, name), sizeof(((struct mail_stats *)0)->name) }
	E("diskin", disk_input),
	E("diskout", disk_output),
	E("lpath", lookup_path),
	E("lattr", lookup_attr),
	E("rcount", read_count),
	E("rbytes", read_bytes),
	E("cache", cache_hits)
};

static int mail_stats_parse_cpu(const char *value, struct mail_stats *stats)
{
	const char *p, *secs_str;
	unsigned long secs, usecs;

	p = strchr(value, '.');
	if (p == NULL)
		return -1;

	secs_str = t_strdup_until(value, p++);
	if (str_to_ulong(secs_str, &secs) < 0 ||
	    str_to_ulong(p, &usecs) < 0 ||
	    usecs > 1000000)
		return -1;

	stats->cpu_secs.tv_sec = secs;
	stats->cpu_secs.tv_usec = usecs;
	return 0;
}

static struct mail_stats_parse_map *
parse_map_find(const char *name)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(parse_map); i++) {
		if (strcmp(parse_map[i].name, name) == 0)
			return &parse_map[i];
	}
	return NULL;
}

static int
mail_stats_parse_one(const char *key, const char *value,
		     struct mail_stats *stats, const char **error_r)
{
	struct mail_stats_parse_map *map;
	void *dest;

	map = parse_map_find(key);
	if (map == NULL)
		return 0;

	dest = PTR_OFFSET(stats, map->offset);
	switch (map->size) {
	case sizeof(uint32_t):
		if (str_to_uint32(value, dest) < 0) {
			*error_r = "invalid number";
			return -1;
		}
		break;
	case sizeof(uint64_t):
		if (str_to_uint64(value, dest) < 0) {
			*error_r = "invalid number";
			return -1;
		}
		break;
	default:
		i_unreached();
	}
	return 0;
}

int mail_stats_parse(const char *const *args, struct mail_stats *stats_r,
		     const char **error_r)
{
	const char *p, *key, *value;
	unsigned int i;

	memset(stats_r, 0, sizeof(*stats_r));
	for (i = 0; args[i] != NULL; i++) {
		p = strchr(args[i], '=');
		if (p == NULL) {
			*error_r = "mail stats parameter missing '='";
			return -1;
		}
		key = t_strdup_until(args[i], p);
		value = p + 1;
		if (strcmp(key, "cpu") == 0) {
			if (mail_stats_parse_cpu(value, stats_r) < 0) {
				*error_r = "invalid cpu parameter";
				return -1;
			}
		} else {
			if (mail_stats_parse_one(key, value,
						 stats_r, error_r) < 0)
				return -1;
		}
	}
	return 0;
}

bool mail_stats_diff(const struct mail_stats *stats1,
		     const struct mail_stats *stats2,
		     struct mail_stats *diff_stats_r)
{
	long long diff_usecs;

	memset(diff_stats_r, 0, sizeof(*diff_stats_r));

	diff_usecs = timeval_diff_usecs(&stats2->cpu_secs, &stats1->cpu_secs);
	if (diff_usecs < 0)
		return FALSE;
	diff_stats_r->cpu_secs.tv_sec = diff_usecs / 1000000;
	diff_stats_r->cpu_secs.tv_usec = diff_usecs % 1000000;

	if (stats1->disk_input > stats2->disk_input)
		return FALSE;
	diff_stats_r->disk_input = stats2->disk_input - stats1->disk_input;
	if (stats1->disk_output > stats2->disk_output)
		return FALSE;
	diff_stats_r->disk_output = stats2->disk_output - stats1->disk_output;

	if (stats1->lookup_path > stats2->lookup_path)
		return FALSE;
	diff_stats_r->lookup_path = stats2->lookup_path - stats1->lookup_path;
	if (stats1->lookup_attr > stats2->lookup_attr)
		return FALSE;
	diff_stats_r->lookup_attr = stats2->lookup_attr - stats1->lookup_attr;
	if (stats1->read_count > stats2->read_count)
		return FALSE;
	diff_stats_r->read_count = stats2->read_count - stats1->read_count;
	if (stats1->cache_hits > stats2->cache_hits)
		return FALSE;
	diff_stats_r->cache_hits = stats2->cache_hits - stats1->cache_hits;
	if (stats1->read_bytes > stats2->read_bytes)
		return FALSE;
	diff_stats_r->read_bytes = stats2->read_bytes - stats1->read_bytes;

	return TRUE;
}

void mail_stats_add(struct mail_stats *dest, const struct mail_stats *src)
{
	dest->cpu_secs.tv_sec += src->cpu_secs.tv_sec;
	dest->cpu_secs.tv_usec += src->cpu_secs.tv_usec;
	if (dest->cpu_secs.tv_usec > 1000000) {
		dest->cpu_secs.tv_usec -= 1000000;
		dest->cpu_secs.tv_sec++;
	}
	dest->disk_input += src->disk_input;
	dest->disk_output += src->disk_output;

	dest->lookup_path += src->lookup_path;
	dest->lookup_attr += src->lookup_attr;
	dest->read_count += src->read_count;
	dest->cache_hits += src->cache_hits;
	dest->read_bytes += src->read_bytes;
}
