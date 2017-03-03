/* Copyright (c) 2011-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "mail-stats.h"
#include "stats-carbon.h"
#include "stats-settings.h"
#include "str.h"

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
		str_printfa(str, "%s.connected_sessions %u %lu\r\n", prefix,
			    mail_global_stats.num_connected_sessions,
			    ts);
		str_printfa(str, "%s.last_reset %lu %lu\r\n", prefix,
			    mail_global_stats.reset_timestamp, ts);
		/* then export rest of the stats */
		for(size_t i = 0; i < stats_field_count(); i++) {
			str_printfa(str, "%s.%s ", prefix,
				    stats_field_name(i));
			stats_field_value(str, mail_global_stats.stats, i);
			str_printfa(str, " %lu\r\n", ts);
		}

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
}

void mail_global_deinit(void)
{
	if (mail_global_stats.stats_send_ctx != NULL)
		stats_carbon_destroy(&mail_global_stats.stats_send_ctx);
	timeout_remove(&mail_global_stats.to_stats_send);
	i_free(mail_global_stats.stats);
}

void mail_global_login(void)
{
	mail_global_stats.num_logins++;
	mail_global_stats.num_connected_sessions++;
}

void mail_global_disconnected(void)
{
	i_assert(mail_global_stats.num_connected_sessions > 0);
	mail_global_stats.num_connected_sessions--;
}

void mail_global_refresh(const struct stats *diff_stats)
{
	if (diff_stats != NULL)
		stats_add(mail_global_stats.stats, diff_stats);
	mail_global_stats.last_update = ioloop_timeval;
}
