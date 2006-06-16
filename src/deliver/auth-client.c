/* Copyright (C) 2005-2006 Timo Sirainen */

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
#include <sysexits.h>

#define MAX_INBUF_SIZE 8192
#define MAX_OUTBUF_SIZE 512

static int return_value;

struct auth_connection {
	int fd;
	struct io *io;
	struct istream *input;
	struct ostream *output;

	struct ioloop *ioloop;
	uid_t euid;
	const char *user;

	unsigned int handshaked:1;
};

static void auth_connection_destroy(struct auth_connection *conn)
{
	io_loop_stop(conn->ioloop);

	io_remove(&conn->io);
	i_stream_unref(&conn->input);
	o_stream_unref(&conn->output);
	if (close(conn->fd) < 0)
		i_error("close() failed: %m");
	i_free(conn);
}

static void auth_parse_input(struct auth_connection *conn, const char *args)
{
	const char *const *tmp, *key, *value;
	uid_t uid = 0;
	gid_t gid = 0;
	int home_found = FALSE;

	for (tmp = t_strsplit(args, "\t"); *tmp != NULL; tmp++) {
		if (strncmp(*tmp, "uid=", 4) == 0) {
			uid = strtoul(*tmp + 4, NULL, 10);

			if (uid == 0) {
				i_error("userdb(%s) returned 0 as uid",
					conn->user);
				return_value = EX_TEMPFAIL;
			}
			if (conn->euid != uid) {
				env_put(t_strconcat("RESTRICT_SETUID=",
						    dec2str(uid), NULL));
			}
		} else if (strncmp(*tmp, "gid=", 4) == 0) {
			gid = strtoul(*tmp + 4, NULL, 10);

			if (gid == 0) {
				i_error("userdb(%s) returned 0 as gid",
					conn->user);
				return_value = EX_TEMPFAIL;
			}

			if (conn->euid == 0 || getegid() != gid) {
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
			conn->user);
		return_value = EX_TEMPFAIL;
		return;
	}
	if (uid == 0) {
		i_error("userdb(%s) didn't return uid", conn->user);
		return_value = EX_TEMPFAIL;
		return;
	}
	if (gid == 0) {
		i_error("userdb(%s) didn't return gid", conn->user);
		return_value = EX_TEMPFAIL;
		return;
	}

	restrict_access_by_env(TRUE);
	return_value = EX_OK;
}

static void auth_input(void *context)
{
	struct auth_connection *conn = context;
	const char *line;

	switch (i_stream_read(conn->input)) {
	case 0:
		return;
	case -1:
		/* disconnected */
		auth_connection_destroy(conn);
		return;
	case -2:
		/* buffer full */
		i_error("BUG: Auth master sent us more than %d bytes",
			MAX_INBUF_SIZE);
		auth_connection_destroy(conn);
		return;
	}

	if (!conn->handshaked) {
		while ((line = i_stream_next_line(conn->input)) != NULL) {
			if (strncmp(line, "VERSION\t", 8) == 0) {
				if (strncmp(line + 8, "1\t", 2) != 0) {
					i_error("Auth master version mismatch");
					auth_connection_destroy(conn);
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
			return_value = EX_NOUSER;
		else if (strncmp(line, "FAIL\t1\t", 7) == 0)
			return_value = EX_TEMPFAIL;
		else {
			i_error("BUG: Unexpected input from auth master: %s",
				line);
		}
		auth_connection_destroy(conn);
	}
}

static struct auth_connection *auth_connection_new(const char *auth_socket)
{
	struct auth_connection *conn;
	int fd;

	fd = net_connect_unix(auth_socket);
	if (fd < 0) {
		i_error("net_connect(%s) failed: %m", auth_socket);
		return NULL;
	}

	conn = i_new(struct auth_connection, 1);
	conn->fd = fd;
	conn->input =
		i_stream_create_file(fd, default_pool, MAX_INBUF_SIZE, FALSE);
	conn->output =
		o_stream_create_file(fd, default_pool, MAX_OUTBUF_SIZE, FALSE);
	conn->io = io_add(fd, IO_READ, auth_input, conn);
	return conn;
}

int auth_client_put_user_env(struct ioloop *ioloop, const char *auth_socket,
			     const char *user, uid_t euid)
{
        struct auth_connection *conn;

	conn = auth_connection_new(auth_socket);
	if (conn == NULL)
		return EX_TEMPFAIL;

	conn->ioloop = ioloop;
	conn->euid = euid;
	conn->user = user;

	o_stream_send_str(conn->output,
			  t_strconcat("VERSION\t1\t0\n"
				      "USER\t1\t", user, "\t"
				      "service=deliver\n", NULL));

	return_value = EX_TEMPFAIL;
	io_loop_run(ioloop);
	return return_value;
}

