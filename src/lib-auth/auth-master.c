/* Copyright (c) 2005-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "network.h"
#include "istream.h"
#include "ostream.h"
#include "env-util.h"
#include "restrict-access.h"
#include "auth-master.h"

#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <sysexits.h>

#define AUTH_REQUEST_TIMEOUT 60
#define MAX_INBUF_SIZE 8192
#define MAX_OUTBUF_SIZE 512

struct auth_connection {
	int fd;
	struct timeout *to;
	struct io *io;
	struct istream *input;
	struct ostream *output;

	struct ioloop *ioloop;
	const char *auth_socket;
	const char *user;
	pool_t pool;
	struct auth_user_reply *user_reply;
	int return_value;

	unsigned int handshaked:1;
	bool debug;
};

static void auth_input(struct auth_connection *conn);

struct auth_connection *auth_master_init(const char *auth_socket, bool debug)
{
	struct auth_connection *conn;
	int fd, try;

	/* max. 1 second wait here. */
	for (try = 0; try < 10; try++) {
		fd = net_connect_unix(auth_socket);
		if (fd != -1 || (errno != EAGAIN && errno != ECONNREFUSED))
			break;

		/* busy. wait for a while. */
		usleep(((rand() % 10) + 1) * 10000);
	}
	if (fd == -1) {
		i_error("Can't connect to auth server at %s: %m", auth_socket);
		return NULL;
	}

	conn = i_new(struct auth_connection, 1);
	conn->auth_socket = auth_socket;
	conn->fd = fd;
	conn->input = i_stream_create_fd(fd, MAX_INBUF_SIZE, FALSE);
	conn->output = o_stream_create_fd(fd, MAX_OUTBUF_SIZE, FALSE);
	conn->io = io_add(fd, IO_READ, auth_input, conn);
	conn->ioloop = current_ioloop;
	conn->debug = debug;
	return conn;
}

static void auth_connection_close(struct auth_connection *conn)
{
	if (conn->fd == -1)
		return;

	io_loop_stop(conn->ioloop);

	if (conn->to != NULL)
		timeout_remove(&conn->to);
	io_remove(&conn->io);
	i_stream_unref(&conn->input);
	o_stream_unref(&conn->output);
	if (close(conn->fd) < 0)
		i_error("close() failed: %m");

	conn->fd = -1;
}

void auth_master_deinit(struct auth_connection *conn)
{
	auth_connection_close(conn);
	i_free(conn);
}

static void auth_parse_input(struct auth_connection *conn, const char *args)
{
	struct auth_user_reply *reply = conn->user_reply;
	const char *const *tmp;
	uid_t uid = (uid_t)-1;
	gid_t gid = (gid_t)-1;
	const char *chroot_dir = NULL;
	const char *home_dir = NULL;

	reply->extra_fields = p_new(conn->pool, ARRAY_TYPE(string), 1);
	p_array_init(reply->extra_fields, conn->pool, 64);

	for (tmp = t_strsplit(args, "\t"); *tmp != NULL; tmp++) {
		if (conn->debug)
			i_info("auth input: %s", *tmp);

		if (strncmp(*tmp, "uid=", 4) == 0)
			uid = strtoul(*tmp + 4, NULL, 10);
		else if (strncmp(*tmp, "gid=", 4) == 0) {
			gid = strtoul(*tmp + 4, NULL, 10);

		} else if (strncmp(*tmp, "chroot=", 7) == 0) {
			chroot_dir = *tmp + 7;
		} else {
			char *field = p_strdup(conn->pool, *tmp);

			if (strncmp(field, "home=", 5) == 0)
				home_dir = field + 5;

			if (reply->extra_fields != NULL)
				array_append(reply->extra_fields, &field, 1);
		}
	}

	reply->uid = uid;
	reply->gid = gid;
	if (home_dir != NULL)
		reply->home = p_strdup(conn->pool, home_dir);
	else
		reply->home = NULL;
	reply->chroot = p_strdup(conn->pool, chroot_dir);
	
	conn->return_value = 1;
}

static void auth_input(struct auth_connection *conn)
{
	const char *line;

	switch (i_stream_read(conn->input)) {
	case 0:
		return;
	case -1:
		/* disconnected */
		i_error("Auth lookup disconnected unexpectedly");
		auth_connection_close(conn);
		return;
	case -2:
		/* buffer full */
		i_error("BUG: Auth master sent us more than %d bytes",
			MAX_INBUF_SIZE);
		auth_connection_close(conn);
		return;
	}

	if (!conn->handshaked) {
		while ((line = i_stream_next_line(conn->input)) != NULL) {
			if (strncmp(line, "VERSION\t", 8) == 0) {
				if (strncmp(line + 8, "1\t", 2) != 0) {
					i_error("Auth master version mismatch");
					auth_connection_close(conn);
					return;
				}
			} else if (strncmp(line, "SPID\t", 5) == 0) {
				conn->handshaked = TRUE;
				break;
			}
		}
	}

	line = i_stream_next_line(conn->input);
	if (line != NULL) {
		if (strncmp(line, "USER\t1\t", 7) == 0) {
			auth_parse_input(conn, line + 7);
		} else if (strcmp(line, "NOTFOUND\t1") == 0)
			conn->return_value = 0;
		else if (strncmp(line, "FAIL\t1", 6) == 0) {
			i_error("Auth lookup returned failure");
			conn->return_value = -1;
		} else if (strncmp(line, "CUID\t", 5) == 0) {
			i_error("%s is an auth client socket. "
				"It should be a master socket.",
				conn->auth_socket);
			conn->return_value = -1;
		} else {
			i_error("BUG: Unexpected input from auth master: %s",
				line);
		}
		auth_connection_close(conn);
	}
}


static void auth_client_timeout(struct auth_connection *conn)
{
	if (!conn->handshaked)
		i_error("Connecting to dovecot-auth timed out");
	else
		i_error("User request from dovecot-auth timed out");
	auth_connection_close(conn);
}

int auth_master_user_lookup(struct auth_connection *conn,
			    const char *user,
			    const char *service,
			    pool_t pool,
			    struct auth_user_reply *reply_r)
{
	if (conn == NULL)
		return -1;

	conn->user = user;
	conn->return_value = -1;
	conn->to = timeout_add(1000*AUTH_REQUEST_TIMEOUT,
			       auth_client_timeout, conn);
	conn->pool = pool;
	conn->user_reply = reply_r;

	o_stream_send_str(conn->output,
			  t_strconcat("VERSION\t1\t0\n"
				      "USER\t1\t", user, "\t"
				      "service=", service, "\n",
				      NULL));

	io_loop_run(conn->ioloop);
	return conn->return_value;
}
