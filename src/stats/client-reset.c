/* Copyright (c) 2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ostream.h"
#include "strescape.h"
#include "mail-stats.h"
#include "client.h"
#include "client-reset.h"

int client_stats_reset(struct client *client, const char *const *args ATTR_UNUSED,
			const char **error_r ATTR_UNUSED)
{
	struct mail_global *g = &mail_global_stats;
	stats_reset(g->stats);
	g->num_logins = 0;
	g->num_cmds = 0;
	g->reset_timestamp = ioloop_time;
	memset(&(g->last_update), 0, sizeof(g->last_update));
	o_stream_nsend_str(client->output, "OK\n");
	return 0;
}
