/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "array.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "network.h"
#include "hex-binary.h"
#include "hostpid.h"
#include "str.h"
#include "str-sanitize.h"
#include "randgen.h"
#include "safe-memset.h"
#include "master-service.h"
#include "mech.h"
#include "auth-stream.h"
#include "auth-request-handler.h"
#include "auth-client-interface.h"
#include "auth-client-connection.h"
#include "auth-master-connection.h"

#include <stdlib.h>

#define OUTBUF_THROTTLE_SIZE (1024*50)

static ARRAY_DEFINE(auth_client_connections, struct auth_client_connection *);

static void auth_client_connection_unref(struct auth_client_connection **_conn);
static void auth_client_input(struct auth_client_connection *conn);

static const char *reply_line_hide_pass(const char *line)
{
	const char *p, *p2;

	/* hide proxy reply password */
	p = strstr(line, "\tpass=");
	if (p == NULL)
		return line;
	p += 6;

	p2 = strchr(p, '\t');
	return t_strconcat(t_strdup_until(line, p), PASSWORD_HIDDEN_STR,
			   p2, NULL);
}

static void auth_client_send(struct auth_client_connection *conn,
			     const char *cmd)
{
	struct const_iovec iov[2];

	iov[0].iov_base = cmd;
	iov[0].iov_len = strlen(cmd);
	iov[1].iov_base = "\n";
	iov[1].iov_len = 1;
	(void)o_stream_sendv(conn->output, iov, 2);

	if (o_stream_get_buffer_used_size(conn->output) >=
	    OUTBUF_THROTTLE_SIZE) {
		/* stop reading new requests until client has read the pending
		   replies. */
		if (conn->io != NULL)
			io_remove(&conn->io);
	}

	if (conn->auth->set->debug) {
		i_debug("client out: %s", conn->auth->set->debug_passwords ?
			cmd : reply_line_hide_pass(cmd));
	}
}

static void auth_callback(struct auth_stream_reply *reply,
			  struct auth_client_connection *conn)
{
	if (reply == NULL) {
		/* handler destroyed */
		auth_client_connection_unref(&conn);
		return;
	}

	auth_client_send(conn, auth_stream_reply_export(reply));
}

static bool
auth_client_input_cpid(struct auth_client_connection *conn, const char *args)
{
        struct auth_client_connection *old;
	unsigned int pid;

	i_assert(conn->pid == 0);

	if (str_to_uint(args, &pid) < 0 || pid == 0) {
		i_error("BUG: Authentication client said it's PID 0");
		return FALSE;
	}

	old = auth_client_connection_lookup(pid);
	if (old != NULL) {
		/* already exists. it's possible that it just reconnected,
		   see if the old connection is still there. */
		i_assert(old != conn);
		if (i_stream_read(old->input) == -1) {
                        auth_client_connection_destroy(&old);
			old = NULL;
		}
	}

	if (old != NULL) {
		i_error("BUG: Authentication client gave a PID "
			"%u of existing connection", pid);
		return FALSE;
	}

	/* handshake complete, we can now actually start serving requests */
        conn->refcount++;
	conn->request_handler =
		auth_request_handler_create(auth_callback, conn,
					    !conn->login_requests ? NULL :
					    auth_master_request_callback);
	auth_request_handler_set(conn->request_handler, conn->connect_uid, pid);

	conn->pid = pid;
	if (conn->auth->set->debug)
		i_debug("auth client connected (pid=%u)", conn->pid);
	return TRUE;
}

static int auth_client_output(struct auth_client_connection *conn)
{
	if (o_stream_flush(conn->output) < 0) {
		auth_client_connection_destroy(&conn);
		return 1;
	}

	if (o_stream_get_buffer_used_size(conn->output) <=
	    OUTBUF_THROTTLE_SIZE/3 && conn->io == NULL) {
		/* allow input again */
		conn->io = io_add(conn->fd, IO_READ, auth_client_input, conn);
	}
	return 1;
}

static const char *auth_line_hide_pass(const char *line)
{
	const char *p, *p2;

	p = strstr(line, "\tresp=");
	if (p == NULL)
		return line;
	p += 6;

	p2 = strchr(p, '\t');
	return t_strconcat(t_strdup_until(line, p), PASSWORD_HIDDEN_STR,
			   p2, NULL);
}

static const char *cont_line_hide_pass(const char *line)
{
	const char *p;

	p = strchr(line, '\t');
	if (p == NULL)
		return line;

	return t_strconcat(t_strdup_until(line, p), PASSWORD_HIDDEN_STR, NULL);
}

static bool
auth_client_cancel(struct auth_client_connection *conn, const char *line)
{
	unsigned int client_id;

	if (str_to_uint(line, &client_id) < 0) {
		i_error("BUG: Authentication client sent broken CANCEL");
		return FALSE;
	}

	auth_request_handler_cancel_request(conn->request_handler, client_id);
	return TRUE;
}

static bool
auth_client_handle_line(struct auth_client_connection *conn, const char *line)
{
	if (strncmp(line, "AUTH\t", 5) == 0) {
		if (conn->auth->set->debug) {
			i_debug("client in: %s",
				conn->auth->set->debug_passwords ? line :
				auth_line_hide_pass(line));
		}
		return auth_request_handler_auth_begin(conn->request_handler,
						       line + 5);
	}
	if (strncmp(line, "CONT\t", 5) == 0) {
		if (conn->auth->set->debug) {
			i_debug("client in: %s",
				conn->auth->set->debug_passwords ? line :
				cont_line_hide_pass(line));
		}
		return auth_request_handler_auth_continue(conn->request_handler,
							  line + 5);
	}
	if (strncmp(line, "CANCEL\t", 7) == 0) {
		if (conn->auth->set->debug)
			i_debug("client in: %s", line);
		return auth_client_cancel(conn, line + 7);
	}

	i_error("BUG: Authentication client sent unknown command: %s",
		str_sanitize(line, 80));
	return FALSE;
}

static void auth_client_input(struct auth_client_connection *conn)
{
	char *line;
	bool ret;

	switch (i_stream_read(conn->input)) {
	case 0:
		return;
	case -1:
		/* disconnected */
		auth_client_connection_destroy(&conn);
		return;
	case -2:
		/* buffer full */
		i_error("BUG: Auth client %u sent us more than %d bytes",
			conn->pid, (int)AUTH_CLIENT_MAX_LINE_LENGTH);
		auth_client_connection_destroy(&conn);
		return;
	}

	while (conn->request_handler == NULL) {
		/* still handshaking */
		line = i_stream_next_line(conn->input);
		if (line == NULL)
			return;

		if (!conn->version_received) {
			/* make sure the major version matches */
			if (strncmp(line, "VERSION\t", 8) != 0 ||
			    !str_uint_equals(t_strcut(line + 8, '\t'),
					     AUTH_CLIENT_PROTOCOL_MAJOR_VERSION)) {
				i_error("Authentication client "
					"not compatible with this server "
					"(mixed old and new binaries?)");
				auth_client_connection_destroy(&conn);
				return;
			}
			conn->version_received = TRUE;
			continue;
		}

		if (strncmp(line, "CPID\t", 5) == 0) {
			if (!auth_client_input_cpid(conn, line + 5)) {
				auth_client_connection_destroy(&conn);
				return;
			}
		} else {
			i_error("BUG: Authentication client sent "
				"unknown handshake command: %s",
				str_sanitize(line, 80));
			auth_client_connection_destroy(&conn);
			return;
		}
	}

        conn->refcount++;
	while ((line = i_stream_next_line(conn->input)) != NULL) {
		T_BEGIN {
			ret = auth_client_handle_line(conn, line);
			safe_memset(line, 0, strlen(line));
		} T_END;

		if (!ret) {
			struct auth_client_connection *tmp_conn = conn;
			auth_client_connection_destroy(&tmp_conn);
			break;
		}
	}
	auth_client_connection_unref(&conn);
}

struct auth_client_connection *
auth_client_connection_create(struct auth *auth, int fd, bool login_requests)
{
	static unsigned int connect_uid_counter = 0;
	struct auth_client_connection *conn;
	string_t *str;

	conn = i_new(struct auth_client_connection, 1);
	conn->auth = auth;
	conn->refcount = 1;
	conn->connect_uid = ++connect_uid_counter;
	conn->login_requests = login_requests;
	random_fill(conn->cookie, sizeof(conn->cookie));

	conn->fd = fd;
	conn->input = i_stream_create_fd(fd, AUTH_CLIENT_MAX_LINE_LENGTH,
					 FALSE);
	conn->output = o_stream_create_fd(fd, (size_t)-1, FALSE);
	o_stream_set_flush_callback(conn->output, auth_client_output, conn);
	conn->io = io_add(fd, IO_READ, auth_client_input, conn);

	array_append(&auth_client_connections, &conn, 1);

	str = t_str_new(128);
	str_printfa(str, "VERSION\t%u\t%u\n%sSPID\t%s\nCUID\t%u\nCOOKIE\t",
                    AUTH_CLIENT_PROTOCOL_MAJOR_VERSION,
                    AUTH_CLIENT_PROTOCOL_MINOR_VERSION,
		    str_c(auth->reg->handshake), my_pid, conn->connect_uid);
	binary_to_hex_append(str, conn->cookie, sizeof(conn->cookie));
	str_append(str, "\nDONE\n");

	if (o_stream_send(conn->output, str_data(str), str_len(str)) < 0)
		auth_client_connection_destroy(&conn);

	return conn;
}

void auth_client_connection_destroy(struct auth_client_connection **_conn)
{
        struct auth_client_connection *conn = *_conn;
	struct auth_client_connection *const *clients;
	unsigned int idx;

	*_conn = NULL;
	if (conn->fd == -1)
		return;

	array_foreach(&auth_client_connections, clients) {
		if (*clients == conn) {
			idx = array_foreach_idx(&auth_client_connections,
						clients);
			array_delete(&auth_client_connections, idx, 1);
			break;
		}
	}

	i_stream_close(conn->input);
	o_stream_close(conn->output);

	if (conn->io != NULL)
		io_remove(&conn->io);

	net_disconnect(conn->fd);
	conn->fd = -1;

	if (conn->request_handler != NULL) {
		auth_request_handler_abort_requests(conn->request_handler);
		auth_request_handler_destroy(&conn->request_handler);
	}

        master_service_client_connection_destroyed(master_service);
        auth_client_connection_unref(&conn);
}

static void auth_client_connection_unref(struct auth_client_connection **_conn)
{
        struct auth_client_connection *conn = *_conn;

	*_conn = NULL;
	if (--conn->refcount > 0)
		return;

	i_stream_unref(&conn->input);
	o_stream_unref(&conn->output);
	i_free(conn);
}

struct auth_client_connection *
auth_client_connection_lookup(unsigned int pid)
{
	struct auth_client_connection *const *clients;

	array_foreach(&auth_client_connections, clients) {
		struct auth_client_connection *client = *clients;

		if (client->pid == pid)
			return client;
	}

	return NULL;
}

void auth_client_connections_init(void)
{
	i_array_init(&auth_client_connections, 16);
}

void auth_client_connections_deinit(void)
{
	struct auth_client_connection **clients;
	unsigned int i, count;

	clients = array_get_modifiable(&auth_client_connections, &count);
	for (i = count; i > 0; i--)
		auth_client_connection_destroy(&clients[i-1]);
	array_free(&auth_client_connections);
}
