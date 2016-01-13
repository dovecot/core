/* Copyright (c) 2011-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "time-util.h"
#include "mail-stats.h"

struct mail_global mail_global_stats;

void mail_global_init(void)
{
	mail_global_stats.reset_timestamp = ioloop_time;
	mail_global_stats.stats = stats_alloc(default_pool);
}

void mail_global_deinit(void)
{
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
