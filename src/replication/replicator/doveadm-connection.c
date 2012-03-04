/* Copyright (c) 2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "network.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "strescape.h"
#include "doveadm-connection.h"

#include <unistd.h>

#define DOVEADM_FAIL_TIMEOUT_MSECS (1000*5)
#define DOVEADM_HANDSHAKE "VERSION\tdoveadm-server\t1\t0\n"
#define MAX_INBUF_SIZE 1024

struct doveadm_connection {
	char *path;
	int fd;
	struct io *io;
	struct istream *input;
	struct ostream *output;
	struct timeout *to;

	doveadm_callback_t *callback;
	void *context;

	time_t last_connect_failure;
	unsigned int handshaked:1;
	unsigned int end_of_print:1;
};

struct doveadm_connection *doveadm_connection_init(const char *path)
{
	struct doveadm_connection *conn;

	conn = i_new(struct doveadm_connection, 1);
	conn->path = i_strdup(path);
	conn->fd = -1;
	return conn;
}

static void doveadm_callback(struct doveadm_connection *conn,
			     enum doveadm_reply reply)
{
	doveadm_callback_t *callback = conn->callback;
	void *context = conn->context;

	if (conn->to != NULL)
		timeout_remove(&conn->to);

	conn->callback = NULL;
	conn->context = NULL;
	callback(reply, context);
}

static void doveadm_disconnect(struct doveadm_connection *conn)
{
	if (conn->fd == -1)
		return;

	io_remove(&conn->io);
	o_stream_destroy(&conn->output);
	i_stream_destroy(&conn->input);
	if (close(conn->fd) < 0)
		i_error("close(doveadm) failed: %m");
	conn->fd = -1;

	if (conn->callback != NULL)
		doveadm_callback(conn, DOVEADM_REPLY_FAIL);
}

void doveadm_connection_deinit(struct doveadm_connection **_conn)
{
	struct doveadm_connection *conn = *_conn;

	*_conn = NULL;

	doveadm_disconnect(conn);
	i_free(conn->path);
	i_free(conn);
}

static int doveadm_input_line(struct doveadm_connection *conn, const char *line)
{
	if (!conn->handshaked) {
		if (strcmp(line, "+") != 0) {
			i_error("%s: Unexpected handshake: %s",
				conn->path, line);
			return -1;
		}
		conn->handshaked = TRUE;
		return 0;
	}
	if (conn->callback == NULL) {
		i_error("%s: Unexpected input: %s", conn->path, line);
		return -1;
	}
	if (!conn->end_of_print) {
		if (line[0] == '\0')
			conn->end_of_print = TRUE;
		return 0;
	}
	if (line[0] == '+')
		doveadm_callback(conn, DOVEADM_REPLY_OK);
	else if (line[0] == '-') {
		if (strcmp(line+1, "NOUSER") == 0)
			doveadm_callback(conn, DOVEADM_REPLY_NOUSER);
		else
			doveadm_callback(conn, DOVEADM_REPLY_FAIL);
	} else {
		i_error("%s: Invalid input: %s", conn->path, line);
		return -1;
	}
	conn->end_of_print = FALSE;
	/* FIXME: disconnect after each request for now.
	   doveadm server's getopt() handling seems to break otherwise */
	return -1;
}

static void doveadm_input(struct doveadm_connection *conn)
{
	const char *line;

	while ((line = i_stream_read_next_line(conn->input)) != NULL) {
		if (doveadm_input_line(conn, line) < 0) {
			doveadm_disconnect(conn);
			return;
		}
	}
	if (conn->input->eof)
		doveadm_disconnect(conn);
}

static int doveadm_connect(struct doveadm_connection *conn)
{
	if (conn->fd != -1)
		return 0;

	if (conn->last_connect_failure == ioloop_time)
		return -1;

	conn->fd = net_connect_unix(conn->path);
	if (conn->fd == -1) {
		i_error("net_connect_unix(%s) failed: %m", conn->path);
		conn->last_connect_failure = ioloop_time;
		return -1;
	}
	conn->last_connect_failure = 0;
	conn->io = io_add(conn->fd, IO_READ, doveadm_input, conn);
	conn->input = i_stream_create_fd(conn->fd, MAX_INBUF_SIZE, FALSE);
	conn->output = o_stream_create_fd(conn->fd, (size_t)-1, FALSE);
	o_stream_send_str(conn->output, DOVEADM_HANDSHAKE);
	return 0;
}

static void doveadm_fail_timeout(struct doveadm_connection *conn)
{
	doveadm_callback(conn, DOVEADM_REPLY_FAIL);
}

void doveadm_connection_sync(struct doveadm_connection *conn,
			     const char *username, bool full,
			     doveadm_callback_t *callback, void *context)
{
	string_t *cmd;

	i_assert(callback != NULL);
	i_assert(!doveadm_connection_is_busy(conn));

	conn->callback = callback;
	conn->context = context;

	if (doveadm_connect(conn) < 0) {
		i_assert(conn->to == NULL);
		conn->to = timeout_add(DOVEADM_FAIL_TIMEOUT_MSECS,
				       doveadm_fail_timeout, conn);
	} else {
		/* <flags> <username> <command> [<args>] */
		cmd = t_str_new(256);
		str_append_c(cmd, '\t');
		str_tabescape_write(cmd, username);
		str_append(cmd, "\tsync\t-d");
		if (full)
			str_append(cmd, "\t-f");
		str_append_c(cmd, '\n');
		o_stream_send(conn->output, str_data(cmd), str_len(cmd));
	}
}

bool doveadm_connection_is_busy(struct doveadm_connection *conn)
{
	return conn->callback != NULL;
}
