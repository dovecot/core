/* Copyright (c) 2011-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "llist.h"
#include "strescape.h"
#include "istream.h"
#include "ostream.h"
#include "master-service.h"
#include "mail-session.h"
#include "mail-user.h"
#include "mail-command.h"
#include "fifo-input-connection.h"

#include <unistd.h>

#define MAX_INBUF_SIZE (PIPE_BUF*2)

struct fifo_input_connection {
	struct fifo_input_connection *prev, *next;

	int fd;
	struct istream *input;
	struct io *io;
};

static struct fifo_input_connection *fifo_conns = NULL;

static int
fifo_input_connection_request(const char *const *args, const char **error_r)
{
	const char *cmd = args[0];

	if (cmd == NULL) {
		*error_r = "Missing command";
		return -1;
	}
	args++;

	if (strcmp(cmd, "CONNECT") == 0)
		return mail_session_connect_parse(args, error_r);
	if (strcmp(cmd, "DISCONNECT") == 0)
		return mail_session_disconnect_parse(args, error_r);
	if (strcmp(cmd, "UPDATE-SESSION") == 0)
		return mail_session_update_parse(args, error_r);
	if (strcmp(cmd, "ADD-USER") == 0)
		return mail_user_add_parse(args, error_r);
	if (strcmp(cmd, "UPDATE-CMD") == 0)
		return mail_command_update_parse(args, error_r);

	*error_r = "Unknown command";
	return -1;
}

static void fifo_input_connection_input(struct fifo_input_connection *conn)
{
	const char *line, *const *args, *error;

	switch (i_stream_read(conn->input)) {
	case -2:
		i_error("BUG: Mail server sent too much data");
		fifo_input_connection_destroy(&conn);
		return;
	case -1:
		fifo_input_connection_destroy(&conn);
		return;
	}

	while ((line = i_stream_next_line(conn->input)) != NULL) T_BEGIN {
		args = t_strsplit_tabescaped(line);
		if (fifo_input_connection_request(args, &error) < 0)
			i_error("FIFO input error: %s", error);
	} T_END;
}

struct fifo_input_connection *fifo_input_connection_create(int fd)
{
	struct fifo_input_connection *conn;

	conn = i_new(struct fifo_input_connection, 1);
	conn->fd = fd;
	conn->input = i_stream_create_fd(fd, MAX_INBUF_SIZE, FALSE);
	conn->io = io_add(fd, IO_READ, fifo_input_connection_input, conn);
	DLLIST_PREPEND(&fifo_conns, conn);
	return conn;
}

void fifo_input_connection_destroy(struct fifo_input_connection **_conn)
{
	struct fifo_input_connection *conn = *_conn;

	*_conn = NULL;

	DLLIST_REMOVE(&fifo_conns, conn);
	io_remove(&conn->io);
	i_stream_destroy(&conn->input);
	if (close(conn->fd) < 0)
		i_error("close(conn) failed: %m");
	i_free(conn);
}

void fifo_input_connections_destroy_all(void)
{
	while (fifo_conns != NULL) {
		struct fifo_input_connection *conn = fifo_conns;

		fifo_input_connection_destroy(&conn);
	}
}
