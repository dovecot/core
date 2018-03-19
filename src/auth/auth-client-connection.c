/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "net.h"
#include "hex-binary.h"
#include "hostpid.h"
#include "llist.h"
#include "str.h"
#include "str-sanitize.h"
#include "randgen.h"
#include "safe-memset.h"
#include "master-service.h"
#include "mech.h"
#include "auth-fields.h"
#include "auth-request-handler.h"
#include "auth-client-interface.h"
#include "auth-client-connection.h"
#include "auth-master-connection.h"


#define OUTBUF_THROTTLE_SIZE (1024*50)

#define AUTH_DEBUG_SENSITIVE_SUFFIX \
	" (previous base64 data may contain sensitive data)"

static void auth_client_disconnected(struct auth_client_connection **_conn);
static void auth_client_connection_unref(struct auth_client_connection **_conn);
static void auth_client_input(struct auth_client_connection *conn);

static struct auth_client_connection *auth_client_connections;

static const char *reply_line_hide_pass(const char *line)
{
	string_t *newline;
	const char *p, *p2;

	if (strstr(line, "pass") == NULL)
		return line;

	newline = t_str_new(strlen(line));

	const char *const *fields = t_strsplit(line, "\t");

	while(*fields != NULL) {
		p = strstr(*fields, "pass");
		p2 = strchr(*fields, '=');
		if (p == NULL || p2 == NULL || p2 < p) {
			str_append(newline, *fields);
		} else {
			/* include = */
			str_append_data(newline, *fields, (p2 - *fields)+1);
			str_append(newline, PASSWORD_HIDDEN_STR);
		}
		str_append_c(newline, '\t');
		fields++;
	}

	return str_c(newline);
}

static void auth_client_send(struct auth_client_connection *conn,
			     const char *cmd)
{
	struct const_iovec iov[2];

	iov[0].iov_base = cmd;
	iov[0].iov_len = strlen(cmd);
	iov[1].iov_base = "\n";
	iov[1].iov_len = 1;
	o_stream_nsendv(conn->output, iov, 2);

	if (o_stream_get_buffer_used_size(conn->output) >=
	    OUTBUF_THROTTLE_SIZE) {
		/* stop reading new requests until client has read the pending
		   replies. */
		io_remove(&conn->io);
	}

	e_debug(conn->event, "client passdb out: %s",
		conn->auth->set->debug_passwords ?
		cmd : reply_line_hide_pass(cmd));
}

static void auth_callback(const char *reply,
			  struct auth_client_connection *conn)
{
	if (reply == NULL) {
		/* handler destroyed */
		auth_client_connection_unref(&conn);
	} else {
		auth_client_send(conn, reply);
	}
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

	if (conn->login_requests)
		old = auth_client_connection_lookup(pid);
	else {
		/* the client is only authenticating, not logging in.
		   the PID isn't necessary, and since we allow authentication
		   via TCP sockets the PIDs may conflict, so ignore them. */
		old = NULL;
		pid = 0;
	}

	if (old != NULL) {
		/* already exists. it's possible that it just reconnected,
		   see if the old connection is still there. */
		i_assert(old != conn);
		if (i_stream_read(old->input) == -1) {
			auth_client_disconnected(&old);
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
		auth_request_handler_create(conn->token_auth, auth_callback, conn,
					    !conn->login_requests ? NULL :
					    auth_master_request_callback);
	auth_request_handler_set(conn->request_handler, conn->connect_uid, pid);

	conn->pid = pid;
	e_debug(conn->event, "auth client connected (pid=%u)", conn->pid);
	return TRUE;
}

static int auth_client_output(struct auth_client_connection *conn)
{
	if (o_stream_flush(conn->output) < 0) {
		auth_client_disconnected(&conn);
		return 1;
	}

	if (o_stream_get_buffer_used_size(conn->output) <=
	    OUTBUF_THROTTLE_SIZE/3 && conn->io == NULL) {
		/* allow input again */
		conn->io = io_add(conn->fd, IO_READ, auth_client_input, conn);
	}
	return 1;
}

static const char *
auth_line_hide_pass(struct auth_client_connection *conn, const char *line)
{
	const char *p, *p2;

	p = strstr(line, "\tresp=");
	if (p == NULL)
		return line;
	p += 6;

	if (conn->auth->set->debug_passwords)
		return t_strconcat(line, AUTH_DEBUG_SENSITIVE_SUFFIX, NULL);

	p2 = strchr(p, '\t');
	return t_strconcat(t_strdup_until(line, p), PASSWORD_HIDDEN_STR,
			   p2, NULL);
}

static const char *
cont_line_hide_pass(struct auth_client_connection *conn, const char *line)
{
	const char *p;

	if (conn->auth->set->debug_passwords)
		return t_strconcat(line, AUTH_DEBUG_SENSITIVE_SUFFIX, NULL);

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
	if (str_begins(line, "AUTH\t")) {
		if (conn->auth->set->debug) {
			e_debug(conn->event, "client in: %s",
				auth_line_hide_pass(conn, line));
		}
		return auth_request_handler_auth_begin(conn->request_handler,
						       line + 5);
	}
	if (str_begins(line, "CONT\t")) {
		if (conn->auth->set->debug) {
			e_debug(conn->event, "client in: %s",
				cont_line_hide_pass(conn, line));
		}
		return auth_request_handler_auth_continue(conn->request_handler,
							  line + 5);
	}
	if (str_begins(line, "CANCEL\t")) {
		if (conn->auth->set->debug)
			e_debug(conn->event, "client in: %s", line);
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
		auth_client_disconnected(&conn);
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
			unsigned int vmajor, vminor;
			const char *p;

			/* split the version line */
			if (!str_begins(line, "VERSION\t") ||
			    str_parse_uint(line + 8, &vmajor, &p) < 0 ||
			    *(p++) != '\t' || str_to_uint(p, &vminor) < 0) {
				i_error("Authentication client "
					"sent invalid VERSION line: %s", line);
				auth_client_connection_destroy(&conn);
				return;
			}
			/* make sure the major version matches */
			if (vmajor != AUTH_MASTER_PROTOCOL_MAJOR_VERSION) {
				i_error("Authentication client "
					"not compatible with this server "
					"(mixed old and new binaries?)");
				auth_client_connection_destroy(&conn);
				return;
			}
			conn->version_minor = vminor;
			conn->version_received = TRUE;
			continue;
		}

		if (str_begins(line, "CPID\t")) {
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

void auth_client_connection_create(struct auth *auth, int fd,
				   bool login_requests, bool token_auth)
{
	static unsigned int connect_uid_counter = 0;
	struct auth_client_connection *conn;
	const char *mechanisms;
	string_t *str;

	conn = i_new(struct auth_client_connection, 1);
	conn->auth = auth;
	conn->refcount = 1;
	conn->connect_uid = ++connect_uid_counter;
	conn->login_requests = login_requests;
	conn->token_auth = token_auth;
	conn->event = event_create(NULL);
	if (auth->set->debug)
		event_set_forced_debug(conn->event, TRUE);
	event_add_category(conn->event, &event_category_auth);
	random_fill(conn->cookie, sizeof(conn->cookie));

	conn->fd = fd;
	conn->input = i_stream_create_fd(fd, AUTH_CLIENT_MAX_LINE_LENGTH);
	conn->output = o_stream_create_fd(fd, (size_t)-1);
	o_stream_set_no_error_handling(conn->output, TRUE);
	o_stream_set_flush_callback(conn->output, auth_client_output, conn);
	conn->io = io_add(fd, IO_READ, auth_client_input, conn);

	DLLIST_PREPEND(&auth_client_connections, conn);

	if (token_auth) {
		mechanisms = t_strconcat("MECH\t",
			mech_dovecot_token.mech_name, "\n", NULL);
	} else {
		mechanisms = str_c(auth->reg->handshake);
	}

	str = t_str_new(128);
	str_printfa(str, "VERSION\t%u\t%u\n%sSPID\t%s\nCUID\t%u\nCOOKIE\t",
                    AUTH_CLIENT_PROTOCOL_MAJOR_VERSION,
                    AUTH_CLIENT_PROTOCOL_MINOR_VERSION,
		    mechanisms, my_pid, conn->connect_uid);
	binary_to_hex_append(str, conn->cookie, sizeof(conn->cookie));
	str_append(str, "\nDONE\n");

	if (o_stream_send(conn->output, str_data(str), str_len(str)) < 0)
		auth_client_disconnected(&conn);
}

void auth_client_connection_destroy(struct auth_client_connection **_conn)
{
        struct auth_client_connection *conn = *_conn;

	*_conn = NULL;
	if (conn->fd == -1)
		return;

	DLLIST_REMOVE(&auth_client_connections, conn);

	i_stream_close(conn->input);
	o_stream_close(conn->output);

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

static void auth_client_disconnected(struct auth_client_connection **_conn)
{
	struct auth_client_connection *conn = *_conn;
	unsigned int request_count;
	int err;

	*_conn = NULL;

	if (conn->input->stream_errno != 0)
		err = conn->input->stream_errno;
	else if (conn->output->stream_errno != 0)
		err = conn->output->stream_errno;
	else
		err = 0;

	request_count = conn->request_handler == NULL ? 0 :
		auth_request_handler_get_request_count(conn->request_handler);
	if (request_count > 0) {
		i_warning("auth client %u disconnected with %u "
			  "pending requests: %s", conn->pid, request_count,
			  err == 0 ? "EOF" : strerror(err));
	}
	auth_client_connection_destroy(&conn);
}

static void auth_client_connection_unref(struct auth_client_connection **_conn)
{
        struct auth_client_connection *conn = *_conn;

	*_conn = NULL;
	if (--conn->refcount > 0)
		return;

	event_unref(&conn->event);
	i_stream_unref(&conn->input);
	o_stream_unref(&conn->output);
	i_free(conn);
}

struct auth_client_connection *
auth_client_connection_lookup(unsigned int pid)
{
	struct auth_client_connection *conn;

	for (conn = auth_client_connections; conn != NULL; conn = conn->next) {
		if (conn->pid == pid)
			return conn;
	}
	return NULL;
}

void auth_client_connections_destroy_all(void)
{
	struct auth_client_connection *conn;

	while (auth_client_connections != NULL) {
		conn = auth_client_connections;
		auth_client_connection_destroy(&conn);
	}
}
