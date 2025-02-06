/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "istream.h"
#include "ostream.h"
#include "hex-binary.h"
#include "hostpid.h"
#include "str.h"
#include "strescape.h"
#include "str-sanitize.h"
#include "randgen.h"
#include "master-service.h"
#include "mech.h"
#include "auth-request-handler.h"
#include "auth-client-interface.h"
#include "auth-client-connection.h"
#include "auth-master-connection.h"


#define OUTBUF_THROTTLE_SIZE (1024*50)

#define AUTH_DEBUG_SENSITIVE_SUFFIX \
	" (previous base64 data may contain sensitive data)"

static void auth_client_connection_unref(struct auth_client_connection **_conn);

static struct connection_list *auth_client_connections = NULL;

static const char *reply_line_hide_pass(const char *line)
{
	string_t *newline;
	const char *p, *p2;

	if (strstr(line, "pass") == NULL)
		return line;

	newline = t_str_new(strlen(line));

	const char *const *fields = t_strsplit_tabescaped(line);

	while(*fields != NULL) {
		p = strstr(*fields, "pass");
		p2 = strchr(*fields, '=');
		if (p == NULL || p2 == NULL || p2 < p) {
			str_append_tabescaped(newline, *fields);
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
	if(conn->conn.disconnected)
		return;
	const struct const_iovec iov[] = {
		{ .iov_base = cmd, .iov_len = strlen(cmd), },
		{ .iov_base = "\n", .iov_len = 1 },
	};
	o_stream_nsendv(conn->conn.output, iov, N_ELEMENTS(iov));

	e_debug(conn->conn.event, "client passdb out: %s",
		conn->auth->protocol_set->debug_passwords ?
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

static int
auth_client_input_cpid(struct auth_client_connection *conn, const char *const *args)
{
	struct auth_client_connection *old;
	unsigned int pid;

	i_assert(conn->pid == 0);

	if (args[0] == NULL || str_to_uint(args[0], &pid) < 0 || pid == 0) {
		e_error(conn->conn.event, "BUG: Authentication client said it's PID 0");
		return -1;
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
		if (i_stream_read(old->conn.input) == -1)
			auth_client_connection_unref(&old);
	}

	if (old != NULL) {
		e_error(conn->conn.event, "BUG: Authentication client gave a PID "
			"%u of existing connection", pid);
		return -1;
	}

	/* handshake complete, we can now actually start serving requests */
	conn->refcount++;
	conn->request_handler =
		auth_request_handler_create(conn->token_auth, auth_callback, conn,
					    !conn->login_requests ? NULL :
					    auth_master_request_callback);
	auth_request_handler_set(conn->request_handler, conn->connect_uid, pid);

	conn->pid = pid;
	e_debug(conn->conn.event, "auth client connected (pid=%u)", conn->pid);
	return 0;
}

static const char *
auth_line_hide_pass(struct auth_client_connection *conn, const char *const *args)
{
	string_t *newline = t_str_new(128);
	for (const char *const *arg = args; *arg != NULL; arg++) {
		if (arg != args)
			str_append_c(newline, '\t');
		if (str_begins_with(*arg, "resp=")) {
			if (conn->auth->protocol_set->debug_passwords) {
				str_append_tabescaped(newline, *arg);
				str_append(newline, AUTH_DEBUG_SENSITIVE_SUFFIX);
				break;
			} else {
				str_append_tabescaped(newline, "resp="PASSWORD_HIDDEN_STR);
			}
		} else {
			str_append_tabescaped(newline, *arg);
		}
	}

	return str_c(newline);
}

static const char *
cont_line_hide_pass(struct auth_client_connection *conn, const char *const *args)
{
	if (args[1] == NULL)
		return args[0];

	if (conn->auth->protocol_set->debug_passwords) {
		return t_strconcat(t_strarray_join(args, "\t"),
				   AUTH_DEBUG_SENSITIVE_SUFFIX, NULL);
	}

	return t_strconcat(args[0], PASSWORD_HIDDEN_STR, NULL);
}

static int
auth_client_cancel(struct auth_client_connection *conn, const char *const *args)
{
	unsigned int client_id;

	if (args[0] == NULL || str_to_uint(args[0], &client_id) < 0) {
		e_error(conn->conn.event, "BUG: Authentication client sent broken CANCEL");
		return -1;
	}

	auth_request_handler_cancel_request(conn->request_handler, client_id);
	return 1;
}

static void auth_client_finish_handshake(struct auth_client_connection *conn)
{
	const char *mechanisms, *mechanisms_cbind = "";
	string_t *str;

	if (conn->handshake_finished)
		return;

	if (conn->token_auth) {
		mechanisms = t_strconcat("MECH\t",
			mech_dovecot_token.mech_name, "\tprivate\n", NULL);
	} else {
		mechanisms = str_c(conn->auth->reg->handshake);
		if (conn->conn.minor_version >= AUTH_CLIENT_MINOR_VERSION_CHANNEL_BINDING) {
			mechanisms_cbind =
				str_c(conn->auth->reg->handshake_cbind);
		}
	}

	str = t_str_new(128);
	str_printfa(str, "%s%sSPID\t%s\nCUID\t%u\nCOOKIE\t",
		    mechanisms, mechanisms_cbind, my_pid, conn->connect_uid);
	binary_to_hex_append(str, conn->cookie, sizeof(conn->cookie));
	str_append(str, "\nDONE\n");

	o_stream_nsend(conn->conn.output, str_data(str), str_len(str));
	conn->handshake_finished = TRUE;
}

static int auth_client_handshake_args(struct connection *conn, const char *const *args)
{
	struct auth_client_connection *aconn =
		container_of(conn, struct auth_client_connection, conn);

	if (!conn->version_received && strcmp(args[0], "VERSION") == 0) {
		unsigned int major_version, minor_version;

		/* VERSION <tab> service_name <tab> major version <tab> minor version */
		if (str_array_length(args) != 3 ||
		    strcmp(args[0], "VERSION") != 0 ||
		    str_to_uint(args[1], &major_version) < 0 ||
		    str_to_uint(args[2], &minor_version) < 0) {
			e_error(conn->event, "didn't reply with a valid VERSION line: %s",
				t_strarray_join(args, "\t"));
			return -1;
		}

		if (major_version != conn->list->set.major_version) {
			e_error(conn->event, "Socket supports major version %u, "
				"but we support only %u (mixed old and new binaries?)",
				major_version, conn->list->set.major_version);
			return -1;
		}
		conn->minor_version = minor_version;
		conn->version_received = TRUE;
		auth_client_finish_handshake(aconn);
		return 0;
	} else if (conn->version_received && strcmp(args[0], "CPID") == 0) {
		if (auth_client_input_cpid(aconn, args + 1) < 0)
			return -1;
		return 1;
	} else {
		e_error(conn->event, "BUG: Authentication client sent unknown handshake command %s",
			args[0]);
	}
	return -1;
}

static int
auth_client_input_args(struct connection *conn, const char *const *args)
{
	struct auth_client_connection *aconn =
		container_of(conn, struct auth_client_connection, conn);

	if (strcmp(args[0], "AUTH") == 0) {
		e_debug(conn->event, "client in: %s",
			auth_line_hide_pass(aconn, args));
		return auth_request_handler_auth_begin(aconn->request_handler,
						       args + 1);
	}
	if (strcmp(args[0], "CONT") == 0) {
		e_debug(conn->event, "client in: %s",
			cont_line_hide_pass(aconn, args));
		return auth_request_handler_auth_continue(aconn->request_handler,
							  args + 1);
	}
	if (strcmp(args[0], "CANCEL") == 0) {
		e_debug(conn->event, "client in: %s", args[1]);
		return auth_client_cancel(aconn, args + 1);
	}

	e_error(conn->event, "BUG: Authentication client sent unknown command: %s",
		str_sanitize(args[0], 80));
	return -1;
}

static void auth_client_connection_destroy(struct connection *conn)
{
	struct auth_client_connection *aconn =
		container_of(conn, struct auth_client_connection, conn);

	if (conn->disconnected)
		return;

	if (aconn->request_handler != NULL) {
		auth_request_handler_abort_requests(aconn->request_handler);
		auth_request_handler_destroy(&aconn->request_handler);
	}

	unsigned int request_count = aconn->request_handler == NULL ? 0 :
		auth_request_handler_get_request_count(aconn->request_handler);

	if (request_count > 0) {
		e_error(conn->event, "auth client %u disconnected with %u "
			  "pending requests: %s", aconn->pid, request_count,
			  connection_disconnect_reason(conn));
	}

	connection_deinit(conn);
	master_service_client_connection_destroyed(master_service);
	auth_client_connection_unref(&aconn);
}

static const struct connection_vfuncs auth_client_connection_vfuncs = {
	.input_args = auth_client_input_args,
	.handshake_args = auth_client_handshake_args,
	.destroy = auth_client_connection_destroy,
};

static const struct connection_settings auth_client_connection_set = {
	.dont_send_version = TRUE,
	.service_name_in = "auth-client",
	.service_name_out = "auth-client",
	.major_version = AUTH_CLIENT_PROTOCOL_MAJOR_VERSION,
	.minor_version = AUTH_CLIENT_PROTOCOL_MINOR_VERSION,
	.input_max_size = AUTH_CLIENT_MAX_LINE_LENGTH,
	.output_throttle_size = OUTBUF_THROTTLE_SIZE,
	.output_max_size = SIZE_MAX,
	.log_connection_id = TRUE,
};

void auth_client_connection_create(struct auth *auth, int fd, const char *name,
				   enum auth_client_connection_flags flags)
{
	static unsigned int connect_uid_counter = 0;
	struct auth_client_connection *conn;
	string_t *str;

	if (auth_client_connections == NULL) {
		auth_client_connections =
			connection_list_init(&auth_client_connection_set,
					     &auth_client_connection_vfuncs);
	}

	conn = i_new(struct auth_client_connection, 1);
	conn->auth = auth;
	conn->refcount = 1;
	conn->connect_uid = ++connect_uid_counter;
	conn->login_requests =
		(flags & AUTH_CLIENT_CONNECTION_FLAG_LOGIN_REQUESTS) != 0;
	conn->token_auth =
		(flags & AUTH_CLIENT_CONNECTION_FLAG_TOKEN_AUTH) != 0;
	conn->conn.event_parent = auth_event;
	random_fill(conn->cookie, sizeof(conn->cookie));

	connection_init_server(auth_client_connections, &conn->conn, name, fd, fd);

	/* send fields */
	str = t_str_new(32);
	str_printfa(str, "VERSION\t%u\t%u\n",
		    conn->conn.list->set.major_version,
		    conn->conn.list->set.minor_version);
	o_stream_nsend(conn->conn.output, str_data(str), str_len(str));

	if ((flags & AUTH_CLIENT_CONNECTION_FLAG_LEGACY) != 0)
		auth_client_finish_handshake(conn);
}

static void auth_client_connection_unref(struct auth_client_connection **_conn)
{
	struct auth_client_connection *conn = *_conn;

	*_conn = NULL;
	if (--conn->refcount > 0)
		return;

	auth_client_connection_destroy(&conn->conn);
	i_free(conn);
}

struct auth_client_connection *
auth_client_connection_lookup(unsigned int pid)
{
	struct connection *conn;

	if (auth_client_connections == NULL)
		return NULL;

	for (conn = auth_client_connections->connections; conn != NULL; conn = conn->next) {
		struct auth_client_connection *aconn =
			container_of(conn, struct auth_client_connection, conn);
		if (aconn->pid == pid && !conn->disconnected)
			return aconn;
	}
	return NULL;
}

void auth_client_connections_destroy_all(void)
{
	if (auth_client_connections != NULL)
		connection_list_deinit(&auth_client_connections);
}
