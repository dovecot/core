/* Copyright (c) 2011-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "time-util.h"
#include "mail-stats.h"

enum mail_stats_type {
	TYPE_NUM,
	TYPE_TIMEVAL
};

struct mail_stats_parse_map {
	const char *name;
	unsigned int offset;
	unsigned int size;
	enum mail_stats_type type;
} parse_map[] = {
#define E(parsename, name, type) { parsename, offsetof(struct mail_stats, name), sizeof(((struct mail_stats *)0)->name), type }
#define EN(parsename, name) E(parsename, name, TYPE_NUM)
	E("ucpu", user_cpu, TYPE_TIMEVAL),
	E("scpu", sys_cpu, TYPE_TIMEVAL),
	EN("minflt", min_faults),
	EN("majflt", maj_faults),
	EN("volcs", vol_cs),
	EN("involcs", invol_cs),
	EN("diskin", disk_input),
	EN("diskout", disk_output),

	EN("rchar", read_bytes),
	EN("wchar", write_bytes),
	EN("syscr", read_count),
	EN("syscw", write_count),

	EN("mlpath", mail_lookup_path),
	EN("mlattr", mail_lookup_attr),
	EN("mrcount", mail_read_count),
	EN("mrbytes", mail_read_bytes),
	EN("mcache", mail_cache_hits)
};

static int mail_stats_parse_timeval(const char *value, struct timeval *tv)
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

	tv->tv_sec = secs;
	tv->tv_usec = usecs;
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
	switch (map->type) {
	case TYPE_NUM:
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
		break;
	case TYPE_TIMEVAL:
		if (mail_stats_parse_timeval(value, dest) < 0) {
			*error_r = "invalid cpu parameter";
			return -1;
		}
		break;
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
		if (mail_stats_parse_one(key, value, stats_r, error_r) < 0)
			return -1;
	}
	return 0;
}

static bool mail_stats_diff_timeval(struct timeval *dest,
				    const struct timeval *src1,
				    const struct timeval *src2)
{
	long long diff_usecs;

	diff_usecs = timeval_diff_usecs(src2, src1);
	if (diff_usecs < 0)
		return FALSE;
	dest->tv_sec = diff_usecs / 1000000;
	dest->tv_usec = diff_usecs % 1000000;
	return TRUE;
}

static bool
mail_stats_diff_uint32(uint32_t *dest, const uint32_t *src1,
		       const uint32_t *src2)
{
	if (*src1 > *src2)
		return FALSE;
	*dest = *src2 - *src1;
	return TRUE;
}

static bool
mail_stats_diff_uint64(uint64_t *dest, const uint64_t *src1,
		       const uint64_t *src2)
{
	if (*src1 > *src2)
		return FALSE;
	*dest = *src2 - *src1;
	return TRUE;
}

bool mail_stats_diff(const struct mail_stats *stats1,
		     const struct mail_stats *stats2,
		     struct mail_stats *diff_stats_r, const char **error_r)
{
	unsigned int i;

	memset(diff_stats_r, 0, sizeof(*diff_stats_r));

	for (i = 0; i < N_ELEMENTS(parse_map); i++) {
		unsigned int offset = parse_map[i].offset;
		void *dest = PTR_OFFSET(diff_stats_r, offset);
		const void *src1 = CONST_PTR_OFFSET(stats1, offset);
		const void *src2 = CONST_PTR_OFFSET(stats2, offset);

		switch (parse_map[i].type) {
		case TYPE_NUM:
			switch (parse_map[i].size) {
			case sizeof(uint32_t):
				if (!mail_stats_diff_uint32(dest, src1, src2)) {
					*error_r = t_strdup_printf("%s %u < %u",
						parse_map[i].name,
						*(const uint32_t *)src2,
						*(const uint32_t *)src1);
					return FALSE;
				}
				break;
			case sizeof(uint64_t):
				if (!mail_stats_diff_uint64(dest, src1, src2)) {
					const uint64_t *n1 = src1, *n2 = src2;

					*error_r = t_strdup_printf("%s %llu < %llu",
						parse_map[i].name,
						(unsigned long long)*n2,
						(unsigned long long)*n1);
					return FALSE;
				}
				break;
			default:
				i_unreached();
			}
			break;
		case TYPE_TIMEVAL:
			if (!mail_stats_diff_timeval(dest, src1, src2)) {
				const struct timeval *tv1 = src1, *tv2 = src2;

				*error_r = t_strdup_printf("%s %ld.%d < %ld.%d",
					parse_map[i].name,
					(long)tv2->tv_sec, (int)tv2->tv_usec,
					(long)tv1->tv_sec, (int)tv1->tv_usec);
				return FALSE;
			}
			break;
		}
	}
	return TRUE;
}

static void timeval_add(struct timeval *dest, const struct timeval *src)
{
	dest->tv_sec += src->tv_sec;
	dest->tv_usec += src->tv_usec;
	if (dest->tv_usec > 1000000) {
		dest->tv_usec -= 1000000;
		dest->tv_sec++;
	}
}

void mail_stats_add(struct mail_stats *dest, const struct mail_stats *src)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(parse_map); i++) {
		unsigned int offset = parse_map[i].offset;
		void *f_dest = PTR_OFFSET(dest, offset);
		const void *f_src = CONST_PTR_OFFSET(src, offset);

		switch (parse_map[i].type) {
		case TYPE_NUM:
			switch (parse_map[i].size) {
			case sizeof(uint32_t): {
				uint32_t *n_dest = f_dest;
				const uint32_t *n_src = f_src;

				*n_dest += *n_src;
				break;
			}
			case sizeof(uint64_t): {
				uint64_t *n_dest = f_dest;
				const uint64_t *n_src = f_src;

				*n_dest += *n_src;
				break;
			}
			default:
				i_unreached();
			}
			break;
		case TYPE_TIMEVAL:
			timeval_add(f_dest, f_src);
			break;
		}
	}
}
