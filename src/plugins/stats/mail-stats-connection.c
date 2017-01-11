/* Copyright (c) 2011-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "base64.h"
#include "hostpid.h"
#include "net.h"
#include "str.h"
#include "strescape.h"
#include "mail-storage.h"
#include "stats.h"
#include "stats-plugin.h"
#include "mail-stats-connection.h"

int mail_stats_connection_connect(struct stats_connection *conn,
				  struct mail_user *user)
{
	struct stats_user *suser = STATS_USER_CONTEXT(user);
	string_t *str = t_str_new(128);

	str_append(str, "CONNECT\t");
	/* required fields */
	str_append(str, suser->stats_session_id);
	str_append_c(str, '\t');
	str_append_tabescaped(str, user->username);
	str_append_c(str, '\t');
	str_append_tabescaped(str, user->service);
	str_printfa(str, "\t%s", my_pid);

	/* optional fields */
	if (user->local_ip != NULL) {
		str_append(str, "\tlip=");
		str_append(str, net_ip2addr(user->local_ip));
	}
	if (user->remote_ip != NULL) {
		str_append(str, "\trip=");
		str_append(str, net_ip2addr(user->remote_ip));
	}
	str_append_c(str, '\n');
	return stats_connection_send(conn, str);
}

void mail_stats_connection_disconnect(struct stats_connection *conn,
				      struct mail_user *user)
{
	struct stats_user *suser = STATS_USER_CONTEXT(user);
	string_t *str = t_str_new(128);

	str_append(str, "DISCONNECT\t");
	str_append(str, suser->stats_session_id);
	str_append_c(str, '\n');
	if (stats_connection_send(conn, str) < 0) {
		/* we could retry this later, but stats process will forget it
		   anyway after 15 minutes. */
	}
}

void mail_stats_connection_send_session(struct stats_connection *conn,
					struct mail_user *user,
					const struct stats *stats)
{
	struct stats_user *suser = STATS_USER_CONTEXT(user);
	string_t *str = t_str_new(256);
	buffer_t *buf;

	buf = buffer_create_dynamic(pool_datastack_create(), 128);
	stats_export(buf, stats);

	str_append(str, "UPDATE-SESSION\t");
	str_append(str, suser->stats_session_id);
	str_append_c(str, '\t');
	base64_encode(buf->data, buf->used, str);

	str_append_c(str, '\n');
	(void)stats_connection_send(conn, str);
}
