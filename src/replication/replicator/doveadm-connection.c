/* Copyright (c) 2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "net.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "strescape.h"
#include "doveadm-connection.h"

#include <unistd.h>

#define DOVEADM_FAIL_TIMEOUT_MSECS (1000*5)
#define DOVEADM_HANDSHAKE "VERSION\tdoveadm-server\t1\t0\n"

/* normally there shouldn't be any need for locking, since replicator doesn't
   start dsync in parallel for the same user. we'll do locking just in case
   anyway */
#define DSYNC_LOCK_TIMEOUT_SECS 30

struct doveadm_connection {
	char *path;
	int fd;
	struct io *io;
	struct istream *input;
	struct ostream *output;
	struct timeout *to;

	char *state;
	doveadm_callback_t *callback;
	void *context;

	time_t last_connect_failure;
	unsigned int handshaked:1;
	unsigned int cmd_sent:1;
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
			     const char *state, enum doveadm_reply reply)
{
	doveadm_callback_t *callback = conn->callback;
	void *context = conn->context;

	if (conn->to != NULL)
		timeout_remove(&conn->to);

	conn->callback = NULL;
	conn->context = NULL;

	/* make sure callback doesn't try to reuse this connection, since
	   we can't currently handle it */
	i_assert(!conn->cmd_sent);
	conn->cmd_sent = TRUE;
	callback(reply, state, context);
	conn->cmd_sent = FALSE;
}

static void doveadm_close(struct doveadm_connection *conn)
{
	if (conn->fd == -1)
		return;

	io_remove(&conn->io);
	o_stream_destroy(&conn->output);
	i_stream_destroy(&conn->input);
	if (close(conn->fd) < 0)
		i_error("close(doveadm) failed: %m");
	conn->fd = -1;
	i_free_and_null(conn->state);
	conn->cmd_sent = FALSE;
	conn->handshaked = FALSE;
}

static void doveadm_disconnect(struct doveadm_connection *conn)
{
	doveadm_close(conn);
	if (conn->callback != NULL)
		doveadm_callback(conn, "", DOVEADM_REPLY_FAIL);
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
	const char *state;

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
	if (conn->state == NULL) {
		conn->state = i_strdup(t_strcut(line, '\t'));
		return 0;
	}
	state = t_strdup(conn->state);
	line = t_strdup(line);
	doveadm_close(conn);

	if (line[0] == '+')
		doveadm_callback(conn, state, DOVEADM_REPLY_OK);
	else if (line[0] == '-') {
		if (strcmp(line+1, "NOUSER") == 0)
			doveadm_callback(conn, "", DOVEADM_REPLY_NOUSER);
		else
			doveadm_callback(conn, "", DOVEADM_REPLY_FAIL);
	} else {
		i_error("%s: Invalid input: %s", conn->path, line);
		return -1;
	}
	/* FIXME: disconnect after each request for now.
	   doveadm server's getopt() handling seems to break otherwise.
	   also with multiple UIDs doveadm-server fails because setid() fails */
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
	conn->input = i_stream_create_fd(conn->fd, (size_t)-1, FALSE);
	conn->output = o_stream_create_fd(conn->fd, (size_t)-1, FALSE);
	o_stream_set_no_error_handling(conn->output, TRUE);
	o_stream_nsend_str(conn->output, DOVEADM_HANDSHAKE);
	return 0;
}

static void doveadm_fail_timeout(struct doveadm_connection *conn)
{
	doveadm_disconnect(conn);
}

void doveadm_connection_sync(struct doveadm_connection *conn,
			     const char *username, const char *state, bool full,
			     doveadm_callback_t *callback, void *context)
{
	string_t *cmd;

	i_assert(callback != NULL);
	i_assert(!doveadm_connection_is_busy(conn));

	conn->cmd_sent = TRUE;
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
		str_append_tabescaped(cmd, username);
		str_printfa(cmd, "\tsync\t-d\t-l\t%u", DSYNC_LOCK_TIMEOUT_SECS);
		if (full)
			str_append(cmd, "\t-f");
		str_append(cmd, "\t-s\t");
		if (state != NULL)
			str_append(cmd, state);
		str_append_c(cmd, '\n');
		o_stream_nsend(conn->output, str_data(cmd), str_len(cmd));
	}
}

bool doveadm_connection_is_busy(struct doveadm_connection *conn)
{
	return conn->cmd_sent;
}
