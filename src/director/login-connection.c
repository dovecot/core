/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "net.h"
#include "str.h"
#include "istream.h"
#include "ostream.h"
#include "llist.h"
#include "strescape.h"
#include "master-service.h"
#include "director.h"
#include "director-request.h"
#include "mail-host.h"
#include "auth-client-interface.h"
#include "auth-connection.h"
#include "login-connection.h"

#include <unistd.h>

#define AUTHREPLY_PROTOCOL_MAJOR_VERSION 1
#define AUTHREPLY_PROTOCOL_MINOR_VERSION 0

struct login_connection {
	struct login_connection *prev, *next;

	int refcount;
	enum login_connection_type type;

	int fd;
	struct io *io;
	struct istream *input;
	struct ostream *output;
	struct auth_connection *auth;
	struct director *dir;

	bool handshaked:1;
	bool destroyed:1;
};

struct login_host_request {
	struct login_connection *conn;
	char *line, *username;

	struct ip_addr local_ip;
	in_port_t local_port;
	in_port_t dest_port;
	bool director_proxy_maybe;
};

static struct login_connection *login_connections;

static void auth_input_line(const char *line, void *context);
static void login_connection_unref(struct login_connection **_conn);

static void login_connection_input(struct login_connection *conn)
{
	struct ostream *output;
	unsigned char buf[4096];
	ssize_t ret;

	ret = read(conn->fd, buf, sizeof(buf));
	if (ret <= 0) {
		if (ret < 0) {
			if (errno == EAGAIN)
				return;
			if (errno != ECONNRESET)
				i_error("read(login connection) failed: %m");
		}
		login_connection_deinit(&conn);
		return;
	}
	output = auth_connection_get_output(conn->auth);
	o_stream_nsend(output, buf, ret);
}

static void login_connection_authreply_input(struct login_connection *conn)
{
	bool bail = FALSE;
	const char *line;

	while (!bail && (line = i_stream_read_next_line(conn->input)) != NULL) T_BEGIN {
		if (!conn->handshaked) {
			if (!version_string_verify(line, "director-authreply-client",
						   AUTHREPLY_PROTOCOL_MAJOR_VERSION)) {
				i_error("authreply client sent invalid handshake: %s", line);
				login_connection_deinit(&conn);
				bail = TRUE; /* don't return from within a T_BEGIN {...} T_END */
			} else {
				conn->handshaked = TRUE;
			}
		} else {
			auth_input_line(line, conn);
		}
	} T_END;

	if (bail)
		return;

	if (conn->input->eof) {
		if (conn->input->stream_errno != 0 &&
		    conn->input->stream_errno != ECONNRESET) {
			i_error("read(authreply connection) failed: %s",
				i_stream_get_error(conn->input));
		}
		login_connection_deinit(&conn);
	}
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
	o_stream_nsendv(conn->output, iov, N_ELEMENTS(iov));
}

static bool login_host_request_is_self(struct login_host_request *request,
				       const struct ip_addr *dest_ip)
{
	if (!net_ip_compare(dest_ip, &request->local_ip))
		return FALSE;
	if (request->dest_port != 0 && request->local_port != 0 &&
	    request->dest_port != request->local_port)
		return FALSE;
	return TRUE;
}

static void
login_host_callback(const struct mail_host *host, const char *hostname,
		    const char *errormsg, void *context)
{
	struct login_host_request *request = context;
	struct director *dir = request->conn->dir;
	const char *line, *line_params;
	unsigned int secs;

	if (host == NULL) {
		if (str_begins(request->line, "OK\t"))
			line_params = request->line + 3;
		else if (str_begins(request->line, "PASS\t"))
			line_params = request->line + 5;
		else
			i_panic("BUG: Unexpected line: %s", request->line);

		i_error("director: User %s host lookup failed: %s",
			request->username, errormsg);
		line = t_strconcat("FAIL\t", t_strcut(line_params, '\t'),
				   "\tcode="AUTH_CLIENT_FAIL_CODE_TEMPFAIL, NULL);
	} else if (request->director_proxy_maybe &&
		   login_host_request_is_self(request, &host->ip)) {
		line = request->line;
	} else {
		string_t *str = t_str_new(64);
		char secs_buf[MAX_INT_STRLEN];

		secs = dir->set->director_user_expire / 2;
		str_append(str, request->line);
		str_append(str, "\tproxy_refresh=");
		str_append(str, dec2str_buf(secs_buf, secs));
		str_append(str, "\thost=");
		if (hostname == NULL || hostname[0] == '\0')
			str_append(str, host->ip_str);
		else {
			str_append(str, hostname);
			str_append(str, "\thostip=");
			str_append(str, host->ip_str);
		}
		line = str_c(str);
	}
	login_connection_send_line(request->conn, line);

	login_connection_unref(&request->conn);
	i_free(request->username);
	i_free(request->line);
	i_free(request);
}

static void auth_input_line(const char *line, void *context)
{
	struct login_connection *conn = context;
	struct login_host_request *request, temp_request;
	const char *const *args, *line_params, *username = NULL, *tag = "";
	bool proxy = FALSE, host = FALSE;

	if (line == NULL) {
		/* auth connection died -> kill also this login connection */
		login_connection_deinit(&conn);
		return;
	}
	if (conn->type != LOGIN_CONNECTION_TYPE_USERDB &&
	    str_begins(line, "OK\t"))
		line_params = line + 3;
	else if (conn->type == LOGIN_CONNECTION_TYPE_USERDB &&
		 str_begins(line, "PASS\t"))
		line_params = line + 5;
	else {
		login_connection_send_line(conn, line);
		return;
	}

	/* OK <id> [<parameters>] */
	args = t_strsplit_tabescaped(line_params);
	if (*args != NULL) {
		/* we should always get here, but in case we don't just
		   forward as-is and let login process handle the error. */
		args++;
	}

	i_zero(&temp_request);
	for (; *args != NULL; args++) {
		if (str_begins(*args, "proxy") &&
		    ((*args)[5] == '=' || (*args)[5] == '\0'))
			proxy = TRUE;
		else if (str_begins(*args, "host="))
			host = TRUE;
		else if (str_begins(*args, "lip=")) {
			if (net_addr2ip((*args) + 4, &temp_request.local_ip) < 0)
				i_error("auth sent invalid lip field: %s", (*args) + 6);
		} else if (str_begins(*args, "lport=")) {
			if (net_str2port((*args) + 6, &temp_request.local_port) < 0)
				i_error("auth sent invalid lport field: %s", (*args) + 6);
		} else if (str_begins(*args, "port=")) {
			if (net_str2port((*args) + 5, &temp_request.dest_port) < 0)
				i_error("auth sent invalid port field: %s", (*args) + 6);
		} else if (str_begins(*args, "destuser="))
			username = *args + 9;
		else if (str_begins(*args, "director_tag="))
			tag = *args + 13;
		else if (str_begins(*args, "director_proxy_maybe") &&
			 ((*args)[20] == '=' || (*args)[20] == '\0'))
			temp_request.director_proxy_maybe = TRUE;
		else if (str_begins(*args, "user=")) {
			if (username == NULL)
				username = *args + 5;
		}
	}
	if ((!proxy && !temp_request.director_proxy_maybe) ||
	    host || username == NULL) {
		login_connection_send_line(conn, line);
		return;
	}
	if (*conn->dir->set->master_user_separator != '\0') {
		/* with master user logins we still want to use only the
		   login username */
		username = t_strcut(username,
				    *conn->dir->set->master_user_separator);
	}

	/* we need to add the host. the lookup might be asynchronous */
	request = i_new(struct login_host_request, 1);
	*request = temp_request;
	request->conn = conn;
	request->line = i_strdup(line);
	request->username = i_strdup(username);

	conn->refcount++;
	director_request(conn->dir, username, tag, login_host_callback, request);
}

struct login_connection *
login_connection_init(struct director *dir, int fd,
		      struct auth_connection *auth,
		      enum login_connection_type type)
{
	struct login_connection *conn;

	conn = i_new(struct login_connection, 1);
	conn->refcount = 1;
	conn->fd = fd;
	conn->dir = dir;
	conn->output = o_stream_create_fd(conn->fd, (size_t)-1);
	o_stream_set_no_error_handling(conn->output, TRUE);
	if (type != LOGIN_CONNECTION_TYPE_AUTHREPLY) {
		i_assert(auth != NULL);
		conn->auth = auth;
		conn->io = io_add(conn->fd, IO_READ,
				  login_connection_input, conn);
		auth_connection_set_callback(conn->auth, auth_input_line, conn);
	} else {
		i_assert(auth == NULL);
		conn->input = i_stream_create_fd(conn->fd, IO_BLOCK_SIZE);
		conn->io = io_add(conn->fd, IO_READ,
				  login_connection_authreply_input, conn);
		o_stream_nsend_str(conn->output, t_strdup_printf(
			"VERSION\tdirector-authreply-server\t%d\t%d\n",
			AUTHREPLY_PROTOCOL_MAJOR_VERSION,
			AUTHREPLY_PROTOCOL_MINOR_VERSION));
	}
	conn->type = type;

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
	i_stream_destroy(&conn->input);
	o_stream_destroy(&conn->output);
	if (close(conn->fd) < 0)
		i_error("close(login connection) failed: %m");
	conn->fd = -1;

	if (conn->auth != NULL)
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
