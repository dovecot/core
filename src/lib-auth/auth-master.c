/* Copyright (c) 2005-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "lib-signals.h"
#include "array.h"
#include "ioloop.h"
#include "network.h"
#include "istream.h"
#include "ostream.h"
#include "auth-master.h"

#include <stdlib.h>
#include <unistd.h>

#define AUTH_PROTOCOL_MAJOR 1
#define AUTH_PROTOCOL_MINOR 0

#define AUTH_REQUEST_TIMEOUT_SECS 30
#define AUTH_MASTER_IDLE_SECS 60

#define MAX_INBUF_SIZE 8192
#define MAX_OUTBUF_SIZE 1024

struct auth_master_connection {
	char *auth_socket_path;

	int fd;
	struct ioloop *ioloop;
	struct io *io;
	struct istream *input;
	struct ostream *output;
	struct timeout *to;

	unsigned int request_counter;
	pool_t pool;
	const char *user;
	struct auth_user_reply *user_reply;
	int return_value;

	unsigned int debug:1;
	unsigned int sent_handshake:1;
	unsigned int handshaked:1;
	unsigned int aborted:1;
};

static void auth_input(struct auth_master_connection *conn);

struct auth_master_connection *
auth_master_init(const char *auth_socket_path, bool debug)
{
	struct auth_master_connection *conn;

	conn = i_new(struct auth_master_connection, 1);
	conn->auth_socket_path = i_strdup(auth_socket_path);
	conn->fd = -1;
	conn->debug = debug;
	return conn;
}

static void auth_connection_close(struct auth_master_connection *conn)
{
	if (conn->to != NULL)
		timeout_remove(&conn->to);
	if (conn->fd != -1) {
		if (close(conn->fd) < 0)
			i_error("close(%s) failed: %m", conn->auth_socket_path);
		conn->fd = -1;
	}

	conn->sent_handshake = FALSE;
	conn->handshaked = FALSE;
}

void auth_master_deinit(struct auth_master_connection **_conn)
{
	struct auth_master_connection *conn = *_conn;

	*_conn = NULL;
	auth_connection_close(conn);
	i_free(conn->auth_socket_path);
	i_free(conn);
}

static void auth_request_lookup_abort(struct auth_master_connection *conn)
{
	io_loop_stop(conn->ioloop);
	conn->aborted = TRUE;
}

static void auth_parse_input(struct auth_master_connection *conn,
			     const char *const *args)
{
	struct auth_user_reply *reply = conn->user_reply;

	memset(reply, 0, sizeof(*reply));
	reply->uid = (uid_t)-1;
	reply->gid = (gid_t)-1;
	p_array_init(&reply->extra_fields, conn->pool, 64);

	reply->user = p_strdup(conn->pool, *args);
	for (args++; *args != NULL; args++) {
		if (conn->debug)
			i_info("auth input: %s", *args);

		if (strncmp(*args, "uid=", 4) == 0)
			reply->uid = strtoul(*args + 4, NULL, 10);
		else if (strncmp(*args, "gid=", 4) == 0)
			reply->gid = strtoul(*args + 4, NULL, 10);
		else if (strncmp(*args, "home=", 5) == 0)
			reply->home = p_strdup(conn->pool, *args + 5);
		else if (strncmp(*args, "chroot=", 7) == 0)
			reply->chroot = p_strdup(conn->pool, *args + 7);
		else {
			const char *field = p_strdup(conn->pool, *args);
			array_append(&reply->extra_fields, &field, 1);
		}
	}
}

static int auth_input_handshake(struct auth_master_connection *conn)
{
	const char *line, *const *tmp;

	while ((line = i_stream_next_line(conn->input)) != NULL) {
		tmp = t_strsplit(line, "\t");
		if (strcmp(tmp[0], "VERSION") == 0 &&
		    tmp[1] != NULL && tmp[2] != NULL) {
			if (strcmp(tmp[1], dec2str(AUTH_PROTOCOL_MAJOR)) != 0) {
				i_error("userdb lookup(%s): "
					"Auth protocol version mismatch "
					"(%s vs %d)", conn->user, tmp[1],
					AUTH_PROTOCOL_MAJOR);
				auth_request_lookup_abort(conn);
				return -1;
			}
		} else if (strcmp(tmp[0], "SPID") == 0) {
			conn->handshaked = TRUE;
			break;
		}
	}
	return 0;
}

static void auth_input(struct auth_master_connection *conn)
{
	const char *line, *cmd, *const *args, *id, *wanted_id;

	switch (i_stream_read(conn->input)) {
	case 0:
		return;
	case -1:
		/* disconnected */
		i_error("userdb lookup(%s): Disconnected unexpectedly",
			conn->user);
		auth_request_lookup_abort(conn);
		return;
	case -2:
		/* buffer full */
		i_error("userdb lookup(%s): BUG: Received more than %d bytes",
			conn->user, MAX_INBUF_SIZE);
		auth_request_lookup_abort(conn);
		return;
	}

	if (!conn->handshaked) {
		if (auth_input_handshake(conn) < 0)
			return;
	}

	line = i_stream_next_line(conn->input);
	if (line == NULL)
		return;

	args = t_strsplit(line, "\t");
	cmd = *args; args++;
	if (*args == NULL)
		id = "";
	else {
		id = *args;
		args++;
	}

	wanted_id = dec2str(conn->request_counter);
	if (strcmp(id, wanted_id) == 0) {
		io_loop_stop(conn->ioloop);
		if (strcmp(cmd, "USER") == 0) {
			auth_parse_input(conn, args);
			conn->return_value = 1;
			return;
		}
		if (strcmp(cmd, "NOTFOUND") == 0) {
			conn->return_value = 0;
			return;
		}
		if (strcmp(cmd, "FAIL") == 0) {
			i_error("userdb lookup(%s) failed: %s",
				conn->user, *args != NULL ? *args :
				"Internal failure");
			return;
		}
	}
	
	if (strcmp(cmd, "CUID") == 0) {
		i_error("userdb lookup(%s): %s is an auth client socket. "
			"It should be a master socket.",
			conn->user, conn->auth_socket_path);
	} else {
		i_error("userdb lookup(%s): BUG: Unexpected input: %s",
			conn->user, line);
	}
	auth_request_lookup_abort(conn);
}

static int auth_master_connect(struct auth_master_connection *conn)
{
	int fd, try;

	i_assert(conn->fd == -1);

	/* max. 1 second wait here. */
	for (try = 0; try < 10; try++) {
		fd = net_connect_unix(conn->auth_socket_path);
		if (fd != -1 || (errno != EAGAIN && errno != ECONNREFUSED))
			break;

		/* busy. wait for a while. */
		usleep(((rand() % 10) + 1) * 10000);
	}
	if (fd == -1) {
		i_error("userdb lookup: connect(%s) failed: %m",
			conn->auth_socket_path);
		return -1;
	}
	conn->fd = fd;
	return 0;
}

static void auth_request_timeout(struct auth_master_connection *conn)
{
	if (!conn->handshaked)
		i_error("userdb lookup(%s): Connecting timed out", conn->user);
	else
		i_error("userdb lookup(%s): Request timed out", conn->user);
	auth_request_lookup_abort(conn);
}

static void auth_idle_timeout(struct auth_master_connection *conn)
{
	auth_connection_close(conn);
}

static void auth_master_set_io(struct auth_master_connection *conn)
{
	if (conn->to != NULL)
		timeout_remove(&conn->to);

	conn->ioloop = io_loop_create();
	conn->input = i_stream_create_fd(conn->fd, MAX_INBUF_SIZE, FALSE);
	conn->output = o_stream_create_fd(conn->fd, MAX_OUTBUF_SIZE, FALSE);
	conn->io = io_add(conn->fd, IO_READ, auth_input, conn);
	conn->to = timeout_add(1000*AUTH_REQUEST_TIMEOUT_SECS,
			       auth_request_timeout, conn);
	lib_signals_reset_ioloop();
}

static void auth_master_unset_io(struct auth_master_connection *conn,
				 struct ioloop *prev_ioloop)
{
	io_loop_set_current(prev_ioloop);
	lib_signals_reset_ioloop();
	io_loop_set_current(conn->ioloop);

	timeout_remove(&conn->to);
	io_remove(&conn->io);
	i_stream_unref(&conn->input);
	o_stream_unref(&conn->output);
	io_loop_destroy(&conn->ioloop);

	conn->to = timeout_add(1000*AUTH_MASTER_IDLE_SECS,
			       auth_idle_timeout, conn);
}

static bool is_valid_string(const char *str)
{
	const char *p;

	/* make sure we're not sending any characters that have a special
	   meaning. */
	for (p = str; *p != '\0'; p++) {
		if (*p == '\t' || *p == '\n' || *p == '\r')
			return FALSE;
	}
	return TRUE;
}

int auth_master_user_lookup(struct auth_master_connection *conn,
			    const char *user, const char *service,
			    pool_t pool, struct auth_user_reply *reply_r)
{
	struct ioloop *prev_ioloop;
	const char *str;

	if (!is_valid_string(user) || !is_valid_string(service)) {
		/* non-allowed characters, the user can't exist */
		return 0;
	}
	if (conn->fd == -1) {
		if (auth_master_connect(conn) < 0)
			return -1;
	}

	prev_ioloop = current_ioloop;
	auth_master_set_io(conn);
	conn->return_value = -1;
	conn->pool = pool;
	conn->user = user;
	conn->user_reply = reply_r;
	if (++conn->request_counter == 0) {
		/* avoid zero */
		conn->request_counter++;
	}

	o_stream_cork(conn->output);
	if (!conn->sent_handshake) {
		str = t_strdup_printf("VERSION\t%d\t%d\n",
				      AUTH_PROTOCOL_MAJOR, AUTH_PROTOCOL_MINOR);
		o_stream_send_str(conn->output, str);
		conn->sent_handshake = TRUE;
	}

	str = t_strdup_printf("USER\t%u\t%s\tservice=%s\n",
			      conn->request_counter, user, service);
	o_stream_send_str(conn->output, str);
	o_stream_uncork(conn->output);

	if (conn->output->stream_errno != 0) {
		errno = conn->output->stream_errno;
		i_error("write(auth socket) failed: %m");
	} else {
		io_loop_run(conn->ioloop);
	}

	auth_master_unset_io(conn, prev_ioloop);
	if (conn->aborted) {
		conn->aborted = FALSE;
		auth_connection_close(conn);
	}
	conn->user = NULL;
	conn->pool = NULL;
	conn->user_reply = NULL;
	return conn->return_value;
}
