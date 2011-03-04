/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "network.h"
#include "ostream.h"
#include "llist.h"
#include "master-service.h"
#include "director.h"
#include "director-request.h"
#include "auth-connection.h"
#include "login-connection.h"

#include <unistd.h>

struct login_connection {
	struct login_connection *prev, *next;

	int refcount;

	int fd;
	struct io *io;
	struct ostream *output;
	struct auth_connection *auth;
	struct director *dir;

	unsigned int destroyed:1;
	unsigned int userdb:1;
};

struct login_host_request {
	struct login_connection *conn;
	char *line;
};

static struct login_connection *login_connections;

static void login_connection_unref(struct login_connection **_conn);

static void login_connection_input(struct login_connection *conn)
{
	unsigned char buf[4096];
	ssize_t ret;

	ret = read(conn->fd, buf, sizeof(buf));
	if (ret <= 0) {
		if (ret < 0) {
			if (errno == EAGAIN)
				return;
			i_error("read(login connection) failed: %m");
		}
		login_connection_deinit(&conn);
		return;
	}
	auth_connection_send(conn->auth, buf, ret);
}

static void
login_connection_send_line(struct login_connection *conn, const char *line)
{
	struct const_iovec iov[2];

	if (conn->destroyed)
		return;

	iov[0].iov_base = line;
	iov[0].iov_len = strlen(line);
	iov[1].iov_base = "\n";
	iov[1].iov_len = 1;
	(void)o_stream_sendv(conn->output, iov, N_ELEMENTS(iov));
}

static void login_host_callback(const struct ip_addr *ip, void *context)
{
	struct login_host_request *request = context;
	struct director *dir = request->conn->dir;
	const char *line;
	unsigned int secs;

	T_BEGIN {
		if (ip != NULL) {
			secs = dir->set->director_user_expire / 2;
			line = t_strdup_printf("%s\thost=%s\tproxy_refresh=%u",
					       request->line, net_ip2addr(ip),
					       secs);
		} else {
			i_assert(strncmp(request->line, "OK\t", 3) == 0);
			line = t_strconcat("FAIL\t",
					   t_strcut(request->line + 3, '\t'),
					   "\ttemp", NULL);
		}
		login_connection_send_line(request->conn, line);
	} T_END;

	login_connection_unref(&request->conn);
	i_free(request->line);
	i_free(request);
}

static void auth_input_line(const char *line, void *context)
{
	struct login_connection *conn = context;
	struct login_host_request *request;
	const char *const *args, *line_params, *username = NULL;
	bool proxy = FALSE, host = FALSE;

	if (line == NULL) {
		/* auth connection died -> kill also this login connection */
		login_connection_deinit(&conn);
		return;
	}
	if (!conn->userdb && strncmp(line, "OK\t", 3) == 0)
		line_params = line + 3;
	else if (conn->userdb && strncmp(line, "PASS\t", 5) == 0)
		line_params = line + 5;
	else {
		login_connection_send_line(conn, line);
		return;
	}

	/* OK <id> [<parameters>] */
	args = t_strsplit(line_params, "\t");
	if (*args != NULL) {
		/* we should always get here, but in case we don't just
		   forward as-is and let login process handle the error. */
		args++;
	}

	for (; *args != NULL; args++) {
		if (strncmp(*args, "proxy", 5) == 0 &&
		    ((*args)[5] == '=' || (*args)[5] == '\0'))
			proxy = TRUE;
		else if (strncmp(*args, "host=", 5) == 0)
			host = TRUE;
		else if (strncmp(*args, "destuser=", 9) == 0)
			username = *args + 9;
		else if (strncmp(*args, "user=", 5) == 0) {
			if (username == NULL)
				username = *args + 5;
		}
	}
	if (*conn->dir->set->master_user_separator != '\0') {
		/* with master user logins we still want to use only the
		   login username */
		username = t_strcut(username,
				    *conn->dir->set->master_user_separator);
	}

	if (!proxy || host || username == NULL) {
		login_connection_send_line(conn, line);
		return;
	}

	/* we need to add the host. the lookup might be asynchronous */
	request = i_new(struct login_host_request, 1);
	request->conn = conn;
	request->line = i_strdup(line);

	conn->refcount++;
	director_request(conn->dir, username, login_host_callback, request);
}

struct login_connection *
login_connection_init(struct director *dir, int fd,
		      struct auth_connection *auth, bool userdb)
{
	struct login_connection *conn;

	conn = i_new(struct login_connection, 1);
	conn->refcount = 1;
	conn->fd = fd;
	conn->auth = auth;
	conn->dir = dir;
	conn->output = o_stream_create_fd(conn->fd, (size_t)-1, FALSE);
	conn->io = io_add(conn->fd, IO_READ, login_connection_input, conn);
	conn->userdb = userdb;

	auth_connection_set_callback(conn->auth, auth_input_line, conn);
	DLLIST_PREPEND(&login_connections, conn);
	return conn;
}

void login_connection_deinit(struct login_connection **_conn)
{
	struct login_connection *conn = *_conn;

	*_conn = NULL;

	if (conn->destroyed)
		return;
	conn->destroyed = TRUE;

	DLLIST_REMOVE(&login_connections, conn);
	io_remove(&conn->io);
	o_stream_unref(&conn->output);
	if (close(conn->fd) < 0)
		i_error("close(login connection) failed: %m");
	conn->fd = -1;

	auth_connection_deinit(&conn->auth);
	login_connection_unref(&conn);

	master_service_client_connection_destroyed(master_service);
}

static void login_connection_unref(struct login_connection **_conn)
{
	struct login_connection *conn = *_conn;

	*_conn = NULL;

	i_assert(conn->refcount > 0);
	if (--conn->refcount == 0)
		i_free(conn);
}

void login_connections_deinit(void)
{
	while (login_connections != NULL) {
		struct login_connection *conn = login_connections;

		login_connection_deinit(&conn);
	}
}
