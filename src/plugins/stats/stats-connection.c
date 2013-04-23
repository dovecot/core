/* Copyright (c) 2011-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hostpid.h"
#include "net.h"
#include "str.h"
#include "strescape.h"
#include "master-service.h"
#include "mail-storage.h"
#include "stats-plugin.h"
#include "stats-connection.h"

struct stats_connection {
	int refcount;

	int fd;
	char *path;

	bool open_failed;
};

static bool stats_connection_open(struct stats_connection *conn)
{
	if (conn->open_failed)
		return FALSE;

	conn->fd = open(conn->path, O_WRONLY | O_NONBLOCK);
	if (conn->fd == -1) {
		i_error("stats: open(%s) failed: %m", conn->path);
		conn->open_failed = TRUE;
		return FALSE;
	}
	return TRUE;
}

struct stats_connection *
stats_connection_create(const char *path)
{
	struct stats_connection *conn;

	conn = i_new(struct stats_connection, 1);
	conn->refcount = 1;
	conn->path = i_strdup(path);
	(void)stats_connection_open(conn);
	return conn;
}

void stats_connection_ref(struct stats_connection *conn)
{
	conn->refcount++;
}

void stats_connection_unref(struct stats_connection **_conn)
{
	struct stats_connection *conn = *_conn;

	i_assert(conn->refcount > 0);
	if (--conn->refcount > 0)
		return;

	*_conn = NULL;
	if (conn->fd != -1) {
		if (close(conn->fd) < 0)
			i_error("close(%s) failed: %m", conn->path);
	}
	i_free(conn->path);
	i_free(conn);
}

void stats_connection_send(struct stats_connection *conn, const string_t *str)
{
	static bool pipe_warned = FALSE;
	ssize_t ret;

	/* if master process has been stopped (and restarted), don't even try
	   to notify the stats process anymore. even if one exists, it doesn't
	   know about us. */
	if (master_service_is_master_stopped(master_service))
		return;

	if (conn->fd == -1) {
		if (!stats_connection_open(conn))
			return;
	}

	if (str_len(str) > PIPE_BUF && !pipe_warned) {
		i_warning("stats update sent more bytes that PIPE_BUF "
			  "(%"PRIuSIZE_T" > %u), this may break statistics",
			  str_len(str), (unsigned int)PIPE_BUF);
		pipe_warned = TRUE;
	}

	ret = write(conn->fd, str_data(str), str_len(str));
	if (ret != (ssize_t)str_len(str)) {
		if (ret < 0) {
			/* don't log EPIPE errors. they can happen when
			   Dovecot is stopped. */
			if (errno != EPIPE)
				i_error("write(%s) failed: %m", conn->path);
		} else if ((size_t)ret != str_len(str))
			i_error("write(%s) wrote partial update", conn->path);
		if (close(conn->fd) < 0)
			i_error("close(%s) failed: %m", conn->path);
		conn->fd = -1;
	}
}

void stats_connection_connect(struct stats_connection *conn,
			      struct mail_user *user)
{
	struct stats_user *suser = STATS_USER_CONTEXT(user);
	string_t *str = t_str_new(128);

	str_append(str, "CONNECT\t");
	/* required fields */
	str_append(str, guid_128_to_string(suser->session_guid));
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
	stats_connection_send(conn, str);
}

void stats_connection_disconnect(struct stats_connection *conn,
				 struct mail_user *user)
{
	struct stats_user *suser = STATS_USER_CONTEXT(user);
	string_t *str = t_str_new(128);

	str_append(str, "DISCONNECT\t");
	str_append(str, guid_128_to_string(suser->session_guid));
	str_append_c(str, '\n');
	stats_connection_send(conn, str);
}

void stats_connection_send_session(struct stats_connection *conn,
				   struct mail_user *user,
				   const struct mail_stats *stats)
{
	struct stats_user *suser = STATS_USER_CONTEXT(user);
	string_t *str = t_str_new(128);

	str_append(str, "UPDATE-SESSION\t");
	str_append(str, guid_128_to_string(suser->session_guid));

	mail_stats_export(str, stats);

	str_append_c(str, '\n');
	stats_connection_send(conn, str);
}
