/* Copyright (c) 2005-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "network.h"
#include "istream.h"
#include "ostream.h"
#include "env-util.h"
#include "restrict-access.h"
#include "auth-client.h"

#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <sysexits.h>

#define AUTH_REQUEST_TIMEOUT 60
#define MAX_INBUF_SIZE 8192
#define MAX_OUTBUF_SIZE 512

static int return_value;

struct auth_connection {
	int fd;
	struct timeout *to;
	struct io *io;
	struct istream *input;
	struct ostream *output;

	struct ioloop *ioloop;
	uid_t euid;
	const char *auth_socket;
	const char *user;
	ARRAY_TYPE(string) *extra_fields;

	unsigned int handshaked:1;
};

static void auth_connection_destroy(struct auth_connection *conn)
{
	io_loop_stop(conn->ioloop);

	if (conn->to != NULL)
		timeout_remove(&conn->to);
	io_remove(&conn->io);
	i_stream_unref(&conn->input);
	o_stream_unref(&conn->output);
	if (close(conn->fd) < 0)
		i_error("close() failed: %m");
	i_free(conn);
}

static bool parse_uid(const char *str, uid_t *uid_r)
{
	struct passwd *pw;
	char *p;

	if (*str >= '0' && *str <= '9') {
		*uid_r = (uid_t)strtoul(str, &p, 10);
		if (*p == '\0')
			return TRUE;
	}

	pw = getpwnam(str);
	if (pw == NULL)
		return FALSE;

	*uid_r = pw->pw_uid;
	return TRUE;
}

static bool parse_gid(const char *str, gid_t *gid_r)
{
	struct group *gr;
	char *p;

	if (*str >= '0' && *str <= '9') {
		*gid_r = (gid_t)strtoul(str, &p, 10);
		if (*p == '\0')
			return TRUE;
	}

	gr = getgrnam(str);
	if (gr == NULL)
		return FALSE;

	*gid_r = gr->gr_gid;
	return TRUE;
}

static void auth_parse_input(struct auth_connection *conn, const char *args)
{
	const char *const *tmp, *extra_groups;
	uid_t uid = 0;
	gid_t gid = 0;
	const char *chroot_dir = getenv("MAIL_CHROOT");
	const char *home_dir = NULL;
	bool debug = getenv("DEBUG") != NULL;
	unsigned int len;

	for (tmp = t_strsplit(args, "\t"); *tmp != NULL; tmp++) {
		if (debug)
			i_info("auth input: %s", *tmp);

		if (strncmp(*tmp, "uid=", 4) == 0) {
			uid = strtoul(*tmp + 4, NULL, 10);

			if (uid == 0) {
				i_error("userdb(%s) returned 0 as uid",
					conn->user);
				return_value = EX_TEMPFAIL;
			}
		} else if (strncmp(*tmp, "gid=", 4) == 0) {
			gid = strtoul(*tmp + 4, NULL, 10);

			if (gid == 0) {
				i_error("userdb(%s) returned 0 as gid",
					conn->user);
				return_value = EX_TEMPFAIL;
			}
		} else if (strncmp(*tmp, "chroot=", 7) == 0) {
			chroot_dir = *tmp + 7;
		} else {
			char *field = i_strdup(*tmp);

			if (strncmp(field, "home=", 5) == 0)
				home_dir = field + 5;

			array_append(conn->extra_fields, &field, 1);
		}
	}

	if (uid == 0 && getenv("MAIL_UID") != NULL) {
		if (!parse_uid(getenv("MAIL_UID"), &uid) || uid == 0) {
			i_error("mail_uid setting is invalid");
			return_value = EX_TEMPFAIL;
			return;
		}
	}
	if (uid == 0) {
		i_error("User %s is missing UID (set mail_uid)", conn->user);
		return_value = EX_TEMPFAIL;
		return;
	}
	if (gid == 0 && getenv("MAIL_GID") != NULL) {
		if (!parse_gid(getenv("MAIL_GID"), &gid) || gid == 0) {
			i_error("mail_gid setting is invalid");
			return_value = EX_TEMPFAIL;
			return;
		}
	}
	if (gid == 0) {
		i_error("User %s is missing GID (set mail_gid)", conn->user);
		return_value = EX_TEMPFAIL;
		return;
	}

	if (conn->euid != uid)
		env_put(t_strconcat("RESTRICT_SETUID=", dec2str(uid), NULL));
	if (conn->euid == 0 || getegid() != gid)
		env_put(t_strconcat("RESTRICT_SETGID=", dec2str(gid), NULL));

	if (chroot_dir != NULL) {
		len = strlen(chroot_dir);
		if (len > 2 && strcmp(chroot_dir + len - 2, "/.") == 0 &&
		    home_dir != NULL &&
		    strncmp(home_dir, chroot_dir, len - 2) == 0) {
			/* strip chroot dir from home dir */
			home_dir += len - 2;
		}
		env_put(t_strconcat("RESTRICT_CHROOT=", chroot_dir, NULL));
	}
	if (home_dir != NULL)
		env_put(t_strconcat("HOME=", home_dir, NULL));

	extra_groups = getenv("MAIL_EXTRA_GROUPS");
	if (extra_groups != NULL) {
		env_put(t_strconcat("RESTRICT_SETEXTRAGROUPS=",
				    extra_groups, NULL));
	}

	restrict_access_by_env(TRUE);
	return_value = EX_OK;
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
		else if (strncmp(line, "FAIL\t1", 6) == 0) {
			i_error("Auth lookup returned failure");
			return_value = EX_TEMPFAIL;
		} else if (strncmp(line, "CUID\t", 5) == 0) {
			i_error("%s is an auth client socket. "
				"It should be a master socket.",
				conn->auth_socket);
		} else {
			i_error("BUG: Unexpected input from auth master: %s",
				line);
		}
		auth_connection_destroy(conn);
	}
}

static struct auth_connection *auth_connection_new(const char *auth_socket)
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
	conn->fd = fd;
	conn->input = i_stream_create_fd(fd, MAX_INBUF_SIZE, FALSE);
	conn->output = o_stream_create_fd(fd, MAX_OUTBUF_SIZE, FALSE);
	conn->io = io_add(fd, IO_READ, auth_input, conn);
	return conn;
}

static void auth_client_timeout(struct auth_connection *conn)
{
	if (!conn->handshaked)
		i_error("Connecting to dovecot-auth timed out");
	else
		i_error("User request from dovecot-auth timed out");
	auth_connection_destroy(conn);
}

int auth_client_lookup_and_restrict(struct ioloop *ioloop,
				    const char *auth_socket,
				    const char *user, uid_t euid,
				    ARRAY_TYPE(string) *extra_fields_r)
{
        struct auth_connection *conn;

	conn = auth_connection_new(auth_socket);
	if (conn == NULL)
		return EX_TEMPFAIL;

	conn->ioloop = ioloop;
	conn->euid = euid;
	conn->user = user;
	conn->auth_socket = auth_socket;
	conn->to = timeout_add(1000*AUTH_REQUEST_TIMEOUT,
			       auth_client_timeout, conn);
	conn->extra_fields = extra_fields_r;

	o_stream_send_str(conn->output,
			  t_strconcat("VERSION\t1\t0\n"
				      "USER\t1\t", user, "\t"
				      "service=deliver\n", NULL));

	return_value = EX_TEMPFAIL;
	io_loop_run(ioloop);
	return return_value;
}
