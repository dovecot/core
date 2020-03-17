/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "str.h"
#include "master-service.h"
#include "stats-connection.h"

#include <unistd.h>
#include <fcntl.h>

#define STATS_EAGAIN_WARN_INTERVAL_SECS 30

struct stats_connection {
	int refcount;

	int fd;
	char *path;

	bool open_failed;
	time_t next_warning_timestamp;
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
	i_close_fd_path(&conn->fd, conn->path);
	i_free(conn->path);
	i_free(conn);
}

int stats_connection_send(struct stats_connection *conn, const string_t *str)
{
	static bool pipe_warned = FALSE;
	ssize_t ret;

	/* if master process has been stopped (and restarted), don't even try
	   to notify the stats process anymore. even if one exists, it doesn't
	   know about us. */
	if (master_service_is_master_stopped(master_service))
		return -1;

	if (conn->fd == -1) {
		if (!stats_connection_open(conn))
			return -1;
		i_assert(conn->fd != -1);
	}

	if (str_len(str) > PIPE_BUF && !pipe_warned) {
		i_warning("stats update sent more bytes that PIPE_BUF "
			  "(%zu > %u), this may break statistics",
			  str_len(str), (unsigned int)PIPE_BUF);
		pipe_warned = TRUE;
	}

	ret = write(conn->fd, str_data(str), str_len(str));
	if (ret == (ssize_t)str_len(str)) {
		/* success */
		return 0;
	} else if (ret < 0 && errno == EAGAIN) {
		/* stats process is busy */
		if (ioloop_time > conn->next_warning_timestamp) {
			i_warning("write(%s) failed: %m (stats process is busy)", conn->path);
			conn->next_warning_timestamp = ioloop_time +
				STATS_EAGAIN_WARN_INTERVAL_SECS;
		}
		return -1;
	} else {
		/* error - reconnect */
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
		return -1;
	}
}
