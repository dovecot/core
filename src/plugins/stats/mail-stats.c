/* Copyright (c) 2011-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "time-util.h"
#include "stats.h"
#include "stats-parser.h"
#include "mail-stats.h"

static struct stats_parser_field mail_stats_fields[] = {
#define E(parsename, name, type) { parsename, offsetof(struct mail_stats, name), sizeof(((struct mail_stats *)0)->name), type }
#define EN(parsename, name) E(parsename, name, STATS_PARSER_TYPE_UINT)
	E("user_cpu", user_cpu, STATS_PARSER_TYPE_TIMEVAL),
	E("sys_cpu", sys_cpu, STATS_PARSER_TYPE_TIMEVAL),
	E("clock_time", clock_time, STATS_PARSER_TYPE_TIMEVAL),
	EN("min_faults", min_faults),
	EN("maj_faults", maj_faults),
	EN("vol_cs", vol_cs),
	EN("invol_cs", invol_cs),
	EN("disk_input", disk_input),
	EN("disk_output", disk_output),

	EN("read_count", read_count),
	EN("read_bytes", read_bytes),
	EN("write_count", write_count),
	EN("write_bytes", write_bytes),

	/*EN("mopen", trans_stats.open_lookup_count),
	EN("mstat", trans_stats.stat_lookup_count),
	EN("mfstat", trans_stats.fstat_lookup_count),*/
	EN("mail_lookup_path", trans_lookup_path),
	EN("mail_lookup_attr", trans_lookup_attr),
	EN("mail_read_count", trans_files_read_count),
	EN("mail_read_bytes", trans_files_read_bytes),
	EN("mail_cache_hits", trans_cache_hit_count)
};

static size_t mail_stats_alloc_size(void)
{
	return sizeof(struct mail_stats);
}

static unsigned int mail_stats_field_count(void)
{
	return N_ELEMENTS(mail_stats_fields);
}

static const char *mail_stats_field_name(unsigned int n)
{
	i_assert(n < N_ELEMENTS(mail_stats_fields));

	return mail_stats_fields[n].name;
}

static void
mail_stats_field_value(string_t *str, const struct stats *stats,
		       unsigned int n)
{
	i_assert(n < N_ELEMENTS(mail_stats_fields));

	stats_parser_value(str, &mail_stats_fields[n], stats);
}

static bool
mail_stats_diff(const struct stats *stats1, const struct stats *stats2,
		struct stats *diff_stats_r, const char **error_r)
{
	return stats_parser_diff(mail_stats_fields, N_ELEMENTS(mail_stats_fields),
				 stats1, stats2, diff_stats_r, error_r);
}

static void mail_stats_add(struct stats *dest, const struct stats *src)
{
	stats_parser_add(mail_stats_fields, N_ELEMENTS(mail_stats_fields),
			 dest, src);
}

static bool
mail_stats_have_changed(const struct stats *_prev, const struct stats *_cur)
{
	const struct mail_stats *prev = (const struct mail_stats *)_prev;
	const struct mail_stats *cur = (const struct mail_stats *)_cur;

	if (cur->disk_input != prev->disk_input ||
	    cur->disk_output != prev->disk_output ||
	    cur->trans_lookup_path != prev->trans_lookup_path ||
	    cur->trans_lookup_attr != prev->trans_lookup_attr ||
	    cur->trans_files_read_count != prev->trans_files_read_count ||
	    cur->trans_files_read_bytes != prev->trans_files_read_bytes ||
	    cur->trans_cache_hit_count != prev->trans_cache_hit_count)
		return TRUE;

	/* allow a tiny bit of changes that are caused by this
	   timeout handling */
	if (timeval_diff_msecs(&cur->user_cpu, &prev->user_cpu) != 0)
		return TRUE;
	if (timeval_diff_msecs(&cur->sys_cpu, &prev->sys_cpu) != 0)
		return TRUE;

	if (cur->maj_faults > prev->maj_faults+10)
		return TRUE;
	if (cur->invol_cs > prev->invol_cs+10)
		return TRUE;
	/* don't check for read/write count/bytes changes, since they get
	   changed by stats checking itself */
	return FALSE;
}

static void mail_stats_export(buffer_t *buf, const struct stats *_stats)
{
	const struct mail_stats *stats = (const struct mail_stats *)_stats;

	buffer_append(buf, stats, sizeof(*stats));
}

static bool
mail_stats_import(const unsigned char *data, size_t size, size_t *pos_r,
		  struct stats *_stats, const char **error_r)
{
	struct mail_stats *stats = (struct mail_stats *)_stats;

	if (size < sizeof(*stats)) {
		*error_r = "mail_stats too small";
		return FALSE;
	}
	memcpy(stats, data, sizeof(*stats));
	*pos_r = sizeof(*stats);
	return TRUE;
}

void mail_stats_add_transaction(struct mail_stats *stats,
				const struct mailbox_transaction_stats *trans_stats)
{
	stats->trans_lookup_path += trans_stats->open_lookup_count;
	stats->trans_lookup_attr += trans_stats->stat_lookup_count +
		trans_stats->fstat_lookup_count;
	stats->trans_files_read_count += trans_stats->files_read_count;
	stats->trans_files_read_bytes += trans_stats->files_read_bytes;
	stats->trans_cache_hit_count += trans_stats->cache_hit_count;
}

const struct stats_vfuncs mail_stats_vfuncs = {
	"mail",
	mail_stats_alloc_size,
	mail_stats_field_count,
	mail_stats_field_name,
	mail_stats_field_value,
	mail_stats_diff,
	mail_stats_add,
	mail_stats_have_changed,
	mail_stats_export,
	mail_stats_import
};

/* for the stats_mail plugin: */
void stats_mail_init(void);
void stats_mail_deinit(void);

static struct stats_item *mail_stats_item;

void stats_mail_init(void)
{
	mail_stats_item = stats_register(&mail_stats_vfuncs);
}

void stats_mail_deinit(void)
{
	stats_unregister(&mail_stats_item);
}
