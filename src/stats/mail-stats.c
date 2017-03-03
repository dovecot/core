/* Copyright (c) 2011-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "mail-stats.h"
#include "stats-carbon.h"
#include "stats-settings.h"
#include "str.h"
#include "hash.h"

struct mail_global mail_global_stats;

static void
mail_global_stats_sent(void *ctx)
{
	struct mail_global *stats = ctx;
	stats_carbon_destroy(&stats->stats_send_ctx);
}

static void
mail_global_stats_send(void *u0 ATTR_UNUSED)
{
	unsigned long ts = (unsigned long)ioloop_time;
	if (*stats_settings->carbon_name != '\0' &&
	    *stats_settings->carbon_server != '\0') {
		string_t *str = t_str_new(256);
		const char *prefix = t_strdup_printf("%s.global",
						     stats_settings->carbon_name);
		str_printfa(str, "%s.logins %u %lu\r\n", prefix,
			    mail_global_stats.num_logins, ts);
		str_printfa(str, "%s.cmds %u %lu\r\n", prefix,
			    mail_global_stats.num_cmds, ts);
		str_printfa(str, "%s.last_reset %lu %lu\r\n", prefix,
			    mail_global_stats.reset_timestamp, ts);
		/* then export rest of the stats */
		for(size_t i = 0; i < stats_field_count(); i++) {
			str_printfa(str, "%s.%s ", prefix,
				    stats_field_name(i));
			stats_field_value(str, mail_global_stats.stats, i);
			str_printfa(str, " %lu\r\n", ts);
		}

		/* Send per service session counts */
		struct hash_iterate_context *iter;
		const char *service;
		unsigned int *count;
		iter = hash_table_iterate_init(mail_global_stats.num_connected_sessions);
		while (hash_table_iterate(iter, mail_global_stats.num_connected_sessions,
		                          &service, &count)) {
			str_printfa(str, "%s.connected_sessions_%s %u %lu\r\n", prefix,
			            service, *count, ts);
		}
		hash_table_iterate_deinit(&iter);

		/* and send them along */
		(void)stats_carbon_send(stats_settings->carbon_server, str_c(str),
					mail_global_stats_sent, &mail_global_stats,
					&mail_global_stats.stats_send_ctx);
	}
}

void mail_global_init(void)
{
	mail_global_stats.reset_timestamp = ioloop_time;
	mail_global_stats.stats = stats_alloc(default_pool);
	mail_global_stats.to_stats_send = timeout_add(stats_settings->carbon_interval*1000,
						      mail_global_stats_send,
						      NULL);
	hash_table_create(&mail_global_stats.num_connected_sessions,
	                  default_pool, 0, str_hash, strcmp);
}

void mail_global_deinit(void)
{
	if (mail_global_stats.stats_send_ctx != NULL)
		stats_carbon_destroy(&mail_global_stats.stats_send_ctx);
	timeout_remove(&mail_global_stats.to_stats_send);
	hash_table_destroy(&mail_global_stats.num_connected_sessions);
	i_free(mail_global_stats.stats);
}

void mail_global_login(const char *service)
{
	mail_global_stats.num_logins++;

	unsigned int *count;
	count = hash_table_lookup(mail_global_stats.num_connected_sessions, service);
	if (count) {
		(*count)++;
	} else {
		count = p_new(default_pool, unsigned int, 1);
		*count = 1;
		hash_table_insert(mail_global_stats.num_connected_sessions,
		                  (const char *)i_strdup(service), count);
	}
	mail_global_stats.num_connected_sessions_combined++;
}

void mail_global_disconnected(const char *service)
{
	unsigned int *count;
	count = hash_table_lookup(mail_global_stats.num_connected_sessions, service);
	if (count) {
		i_assert(*count > 0);
		(*count)--;
	}
	mail_global_stats.num_connected_sessions_combined--;
}

void mail_global_refresh(const struct stats *diff_stats)
{
	if (diff_stats != NULL)
		stats_add(mail_global_stats.stats, diff_stats);
	mail_global_stats.last_update = ioloop_timeval;
}
