/* Copyright (c) 2011-2015 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "net.h"
#include "ostream.h"
#include "str.h"
#include "strescape.h"
#include "mail-stats.h"
#include "mail-command.h"
#include "mail-session.h"
#include "mail-user.h"
#include "mail-domain.h"
#include "mail-ip.h"
#include "client.h"
#include "client-reset.h"

int client_stats_reset(struct client *client, const char *const *args ATTR_UNUSED,
			const char **error_r ATTR_UNUSED)
{
	struct mail_global *g = &mail_global_stats;
	stats_reset(g->stats);
	o_stream_nsend_str(client->output, "OK\n");
	return 0;
}
