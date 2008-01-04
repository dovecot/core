/* Copyright (c) 2005-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "network.h"
#include "istream.h"
#include "ostream.h"
#include "env-util.h"
#include "restrict-access.h"
#include "auth-client.h"

#include <stdlib.h>
#include <unistd.h>

#define MAX_INBUF_SIZE 8192
#define MAX_OUTBUF_SIZE 512

struct auth_connection {
	char *auth_socket;

	int fd;
	struct io *io;
	struct istream *input;
	struct ostream *output;

	uid_t orig_uid, current_uid;
	const char *current_user;
	int return_value;

	unsigned int handshaked:1;
};

static void auth_input(struct auth_connection *conn);

static int auth_connection_connect(struct auth_connection *conn)
{
	int fd;

	if (conn->fd != -1)
		return 0;

	fd = net_connect_unix(conn->auth_socket);
	if (fd < 0) {
		i_error("net_connect(%s) failed: %m", conn->auth_socket);
		return -1;
	}

	conn->fd = fd;
	conn->input = i_stream_create_fd(fd, MAX_INBUF_SIZE, FALSE);
	conn->output = o_stream_create_fd(fd, MAX_OUTBUF_SIZE, FALSE);
	conn->io = io_add(fd, IO_READ, auth_input, conn);

	o_stream_send_str(conn->output, "VERSION\t1\t0\n");
	return 0;
}

static void auth_connection_close(struct auth_connection *conn)
{
	if (conn->fd == -1)
		return;

	io_remove(&conn->io);
	i_stream_unref(&conn->input);
	o_stream_unref(&conn->output);

	if (close(conn->fd) < 0)
		i_error("close() failed: %m");
	conn->fd = -1;
}

struct auth_connection *auth_connection_init(const char *auth_socket)
{
	struct auth_connection *conn;

	conn = i_new(struct auth_connection, 1);
	conn->auth_socket = i_strdup(auth_socket);
	conn->orig_uid = conn->current_uid = geteuid();
	conn->fd = -1;

	(void)auth_connection_connect(conn);
	return conn;
}

void auth_connection_deinit(struct auth_connection *conn)
{
	auth_connection_close(conn);
	i_free(conn->auth_socket);
	i_free(conn);
}

static void auth_parse_input(struct auth_connection *conn, const char *args)
{
	const char *const *tmp, *key, *value;
	uid_t uid = (uid_t)-1;
	int home_found = FALSE;

	for (tmp = t_strsplit(args, "\t"); *tmp != NULL; tmp++) {
		if (strncmp(*tmp, "uid=", 4) == 0)
			uid = strtoul(*tmp + 4, NULL, 10);
		else if (strncmp(*tmp, "gid=", 4) == 0) {
			gid_t gid = strtoul(*tmp + 4, NULL, 10);

			if (conn->orig_uid == 0 || getegid() != gid) {
				env_put(t_strconcat("RESTRICT_SETGID=",
						    *tmp + 4, NULL));
			}
		} else if (strncmp(*tmp, "chroot=", 7) == 0) {
			env_put(t_strconcat("RESTRICT_CHROOT=",
					    *tmp + 7, NULL));
		} else if (strncmp(*tmp, "home=", 5) == 0) {
			home_found = TRUE;
			env_put(t_strconcat("HOME=", *tmp + 5, NULL));
		} else {
			key = t_str_ucase(t_strcut(*tmp, '='));
			value = strchr(*tmp, '=');
			if (value != NULL)
				env_put(t_strconcat(key, "=", value+1, NULL));
		}
	}

	if (!home_found) {
		/* we must have a home directory */
		i_error("userdb(%s) didn't return a home directory",
			conn->current_user);
		return;
	}

	if (uid == (uid_t)-1) {
		i_error("userdb(%s) didn't return uid", conn->current_user);
		return;
	}

	/* we'll change only effective UID. This is a bit unfortunate since
	   it allows reverting back to root, but we'll have to be able to
	   access different users' mailboxes.. */
	if (uid != conn->current_uid) {
		if (conn->current_uid != 0) {
			if (seteuid(0) != 0)
				i_fatal("seteuid(0) failed: %m");
		}
		if (seteuid(uid) < 0)
			i_fatal("seteuid(%s) failed: %m", dec2str(uid));
		conn->current_uid = uid;
	}

	restrict_access_by_env(FALSE);
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
		else if (strncmp(line, "FAIL\t1\t", 7) == 0)
			conn->return_value = -1;
		else {
			i_error("BUG: Unexpected input from auth master: %s",
				line);
			auth_connection_close(conn);
		}
		io_loop_stop(current_ioloop);
	}
}

int auth_client_put_user_env(struct auth_connection *conn,
			     const char *user)
{
	if (auth_connection_connect(conn) < 0)
		return -1;

	conn->current_user = user;
	conn->return_value = -1;

	o_stream_send_str(conn->output,
			  t_strconcat("USER\t1\t", user, "\t"
				      "service=expire\n", NULL));

	io_loop_run(current_ioloop);

	conn->current_user = NULL;
	return conn->return_value;
}
