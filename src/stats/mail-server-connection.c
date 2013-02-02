/* Copyright (c) 2011-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "strescape.h"
#include "istream.h"
#include "ostream.h"
#include "master-service.h"
#include "mail-session.h"
#include "mail-command.h"
#include "mail-server-connection.h"

#include <unistd.h>

#define MAX_INBUF_SIZE (PIPE_BUF*2)

struct mail_server_connection {
	int fd;
	struct istream *input;
	struct io *io;
};

static const char *const*
mail_server_connection_next_line(struct mail_server_connection *conn)
{
	const char *line;
	char **args;
	unsigned int i;

	line = i_stream_next_line(conn->input);
	if (line == NULL)
		return NULL;

	args = p_strsplit(pool_datastack_create(), line, "\t");
	for (i = 0; args[i] != NULL; i++)
		args[i] = str_tabunescape(args[i]);
	return (void *)args;
}

static int
mail_server_connection_request(const char *const *args, const char **error_r)
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
	if (strcmp(cmd, "UPDATE-CMD") == 0)
		return mail_command_update_parse(args, error_r);

	*error_r = "Unknown command";
	return -1;
}

static void mail_server_connection_input(struct mail_server_connection *conn)
{
	const char *const *args, *error;

	switch (i_stream_read(conn->input)) {
	case -2:
		i_error("BUG: Mail server sent too much data");
		mail_server_connection_destroy(&conn);
		return;
	case -1:
		mail_server_connection_destroy(&conn);
		return;
	}

	while ((args = mail_server_connection_next_line(conn)) != NULL) {
		if (mail_server_connection_request(args, &error) < 0)
			i_error("Mail server input error: %s", error);
	}
}

struct mail_server_connection *mail_server_connection_create(int fd)
{
	struct mail_server_connection *conn;

	conn = i_new(struct mail_server_connection, 1);
	conn->fd = fd;
	conn->input = i_stream_create_fd(fd, MAX_INBUF_SIZE, FALSE);
	conn->io = io_add(fd, IO_READ, mail_server_connection_input, conn);
	return conn;
}

void mail_server_connection_destroy(struct mail_server_connection **_conn)
{
	struct mail_server_connection *conn = *_conn;

	*_conn = NULL;

	io_remove(&conn->io);
	i_stream_destroy(&conn->input);
	if (close(conn->fd) < 0)
		i_error("close(conn) failed: %m");
	i_free(conn);
}
