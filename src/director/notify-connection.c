/* Copyright (c) 2010-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "istream.h"
#include "master-service.h"
#include "director.h"
#include "user-directory.h"
#include "notify-connection.h"

#include <unistd.h>

struct notify_connection {
	int fd;
	struct io *io;
	struct istream *input;
	struct director *dir;
};

static void notify_connection_input(struct notify_connection *conn)
{
	struct user *user;
	const char *line;
	unsigned int hash;
	int diff;

	while ((line = i_stream_read_next_line(conn->input)) != NULL) {
		hash = user_directory_get_username_hash(conn->dir->users, line);
		user = user_directory_lookup(conn->dir->users, hash);
		if (user != NULL) {
			diff = ioloop_time - user->timestamp;
			if (diff >= (int)conn->dir->set->director_user_expire) {
				i_warning("notify: User %s refreshed too late "
					  "(%d secs)", line, diff);
			}
			user_directory_refresh(conn->dir->users, user);
			director_update_user(conn->dir, conn->dir->self_host,
					     user);
		}
	}
	if (conn->input->eof) {
		i_error("notify: read() unexpectedly returned EOF");
		notify_connection_deinit(&conn);
	} else if (conn->input->stream_errno != 0) {
		i_error("notify: read() failed: %m");
		notify_connection_deinit(&conn);
	}
}

struct notify_connection *
notify_connection_init(struct director *dir, int fd)
{
	struct notify_connection *conn;

	conn = i_new(struct notify_connection, 1);
	conn->fd = fd;
	conn->dir = dir;
	conn->input = i_stream_create_fd(conn->fd, 1024, FALSE);
	conn->io = io_add(conn->fd, IO_READ, notify_connection_input, conn);
	return conn;
}

void notify_connection_deinit(struct notify_connection **_conn)
{
	struct notify_connection *conn = *_conn;

	*_conn = NULL;

	io_remove(&conn->io);
	i_stream_unref(&conn->input);
	if (close(conn->fd) < 0)
		i_error("close(notify connection) failed: %m");
	i_free(conn);
}
