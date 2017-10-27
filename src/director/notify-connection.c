/* Copyright (c) 2010-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "llist.h"
#include "ioloop.h"
#include "istream.h"
#include "master-service.h"
#include "director.h"
#include "mail-host.h"
#include "notify-connection.h"

#include <unistd.h>

struct notify_connection {
	struct notify_connection *prev, *next;

	int fd;
	struct io *io;
	struct istream *input;
	struct director *dir;

	bool fifo:1;
};

static struct notify_connection *notify_connections = NULL;

static void notify_connection_deinit(struct notify_connection **_conn);

static void notify_update_user(struct director *dir, struct mail_tag *tag,
			       const char *username, unsigned int username_hash)
{
	struct user *user;
	int diff;

	user = user_directory_lookup(tag->users, username_hash);
	if (user == NULL)
		return;

	diff = ioloop_time - user->timestamp;
	if (diff >= (int)dir->set->director_user_expire) {
		i_warning("notify: User %s refreshed too late (%d secs)",
			  username, diff);
	}
	user_directory_refresh(tag->users, user);
	director_update_user(dir, dir->self_host, user);
}

static void notify_connection_input(struct notify_connection *conn)
{
	struct mail_tag *const *tagp;
	const char *line;
	unsigned int hash;

	while ((line = i_stream_read_next_line(conn->input)) != NULL) {
		hash = director_get_username_hash(conn->dir, line);
		array_foreach(mail_hosts_get_tags(conn->dir->mail_hosts), tagp)
			notify_update_user(conn->dir, *tagp, line, hash);
	}
	if (conn->input->eof) {
		if (conn->fifo)
			i_error("notify: read() unexpectedly returned EOF");
		notify_connection_deinit(&conn);
	} else if (conn->input->stream_errno != 0) {
		i_error("notify: read() failed: %s",
			i_stream_get_error(conn->input));
		notify_connection_deinit(&conn);
	}
}

void notify_connection_init(struct director *dir, int fd, bool fifo)
{
	struct notify_connection *conn;

	conn = i_new(struct notify_connection, 1);
	conn->fd = fd;
	conn->fifo = fifo;
	conn->dir = dir;
	conn->input = i_stream_create_fd(conn->fd, 1024, FALSE);
	conn->io = io_add(conn->fd, IO_READ, notify_connection_input, conn);
	DLLIST_PREPEND(&notify_connections, conn);
}

static void notify_connection_deinit(struct notify_connection **_conn)
{
	struct notify_connection *conn = *_conn;

	*_conn = NULL;

	DLLIST_REMOVE(&notify_connections, conn);
	io_remove(&conn->io);
	i_stream_unref(&conn->input);
	if (close(conn->fd) < 0)
		i_error("close(notify connection) failed: %m");
	if (!conn->fifo)
		master_service_client_connection_destroyed(master_service);
	i_free(conn);
}

void notify_connections_deinit(void)
{
	while (notify_connections != NULL) {
		struct notify_connection *conn = notify_connections;
		notify_connection_deinit(&conn);
	}
}
