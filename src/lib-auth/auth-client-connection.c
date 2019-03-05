/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "hostpid.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "net.h"
#include "strescape.h"
#include "eacces-error.h"
#include "auth-client-private.h"

#include <unistd.h>

#define AUTH_SERVER_CONN_MAX_LINE_LENGTH AUTH_CLIENT_MAX_LINE_LENGTH
#define AUTH_SERVER_RECONNECT_TIMEOUT_SECS 5

static void auth_client_connection_connected(struct connection *_conn,
					     bool success);
static int
auth_client_connection_input_line(struct connection *_conn,
				  const char *line);
static int
auth_client_connection_handshake_line(struct connection *_conn,
				      const char *line);
static void auth_client_connection_handshake_ready(struct connection *_conn);
static void auth_client_connection_destroy(struct connection *_conn);
static void
auth_client_connection_reconnect(struct auth_client_connection *conn,
				 const char *disconnect_reason);

static const struct connection_vfuncs auth_client_connection_vfuncs = {
	.destroy = auth_client_connection_destroy,
	.handshake_line = auth_client_connection_handshake_line,
	.handshake_ready = auth_client_connection_handshake_ready,
	.input_line = auth_client_connection_input_line,
	.client_connected = auth_client_connection_connected,
};

static const struct connection_settings auth_client_connection_set = {
	.dont_send_version = TRUE,
	.service_name_in = "auth-client",
	.service_name_out = "auth-client",
	.major_version = AUTH_CLIENT_PROTOCOL_MAJOR_VERSION,
	.minor_version = AUTH_CLIENT_PROTOCOL_MINOR_VERSION,
	.unix_client_connect_msecs = 1000,
	.input_max_size = AUTH_SERVER_CONN_MAX_LINE_LENGTH,
	.output_max_size = (size_t)-1,
	.client = TRUE,
};

struct connection_list *
auth_client_connection_list_init(void)
{
	return connection_list_init(&auth_client_connection_set,
				    &auth_client_connection_vfuncs);
}

static int
auth_server_input_mech(struct auth_client_connection *conn,
		       const char *const *args)
{
	struct auth_mech_desc mech_desc;

	if (args[0] == NULL) {
		e_error(conn->event,
			"BUG: Authentication server sent broken MECH line");
		return -1;
	}

	i_zero(&mech_desc);
	mech_desc.name = p_strdup(conn->pool, args[0]);

	if (strcmp(mech_desc.name, "PLAIN") == 0)
		conn->has_plain_mech = TRUE;

	for (args++; *args != NULL; args++) {
		if (strcmp(*args, "private") == 0)
			mech_desc.flags |= MECH_SEC_PRIVATE;
		else if (strcmp(*args, "anonymous") == 0)
			mech_desc.flags |= MECH_SEC_ANONYMOUS;
		else if (strcmp(*args, "plaintext") == 0)
			mech_desc.flags |= MECH_SEC_PLAINTEXT;
		else if (strcmp(*args, "dictionary") == 0)
			mech_desc.flags |= MECH_SEC_DICTIONARY;
		else if (strcmp(*args, "active") == 0)
			mech_desc.flags |= MECH_SEC_ACTIVE;
		else if (strcmp(*args, "forward-secrecy") == 0)
			mech_desc.flags |= MECH_SEC_FORWARD_SECRECY;
		else if (strcmp(*args, "mutual-auth") == 0)
			mech_desc.flags |= MECH_SEC_MUTUAL_AUTH;
	}
	array_push_back(&conn->available_auth_mechs, &mech_desc);
	return 0;
}

static int
auth_server_input_spid(struct auth_client_connection *conn,
		       const char *const *args)
{
	if (str_to_uint(args[0], &conn->server_pid) < 0) {
		e_error(conn->event,
			"BUG: Authentication server sent invalid PID");
		return -1;
	}
	return 0;
}

static int
auth_server_input_cuid(struct auth_client_connection *conn,
		       const char *const *args)
{
	if (args[0] == NULL ||
	    str_to_uint(args[0], &conn->connect_uid) < 0) {
		e_error(conn->event,
			"BUG: Authentication server sent broken CUID line");
		return -1;
	}
	return 0;
}

static int
auth_server_input_cookie(struct auth_client_connection *conn,
			 const char *const *args)
{
	if (conn->cookie != NULL) {
		e_error(conn->event,
			"BUG: Authentication server already sent cookie");
		return -1;
	}
	conn->cookie = p_strdup(conn->pool, args[0]);
	return 0;
}

static int auth_server_input_done(struct auth_client_connection *conn)
{
	if (array_count(&conn->available_auth_mechs) == 0) {
		e_error(conn->event,
			"BUG: Authentication server returned no mechanisms");
		return -1;
	}
	if (conn->cookie == NULL) {
		e_error(conn->event,
			"BUG: Authentication server didn't send a cookie");
		return -1;
	}
	return 1;
}

static int
auth_client_connection_handshake_line(struct connection *_conn,
				      const char *line)
{
	struct auth_client_connection *conn =
		container_of(_conn, struct auth_client_connection, conn);
	unsigned int major_version, minor_version;
	const char *const *args;

	args = t_strsplit_tabescaped(line);
	if (strcmp(args[0], "VERSION") == 0 &&
	    args[1] != NULL && args[2] != NULL) {
		if (str_to_uint(args[1], &major_version) < 0 ||
		    str_to_uint(args[2], &minor_version) < 0) {
			e_error(conn->event,
				"Auth server sent invalid version line: %s",
				line);
			return -1;
		}

		if (connection_verify_version(_conn, "auth-client",
					      major_version,
					      minor_version) < 0) {
			return -1;
		}

		return 0;
	} else if (strcmp(args[0], "MECH") == 0) {
		return auth_server_input_mech(conn, args + 1);
	} else if (strcmp(args[0], "SPID") == 0) {
		return auth_server_input_spid(conn, args + 1);
	} else if (strcmp(args[0], "CUID") == 0) {
		return auth_server_input_cuid(conn, args + 1);
	} else if (strcmp(args[0], "COOKIE") == 0) {
		return auth_server_input_cookie(conn, args + 1);
	} else if (strcmp(args[0], "DONE") == 0) {
		return auth_server_input_done(conn);
	}

	e_error(conn->event, "Auth server sent unknown handshake: %s", line);
	return -1;
}

static void auth_client_connection_handshake_ready(struct connection *_conn)
{
	struct auth_client_connection *conn =
		container_of(_conn, struct auth_client_connection, conn);

	timeout_remove(&conn->to);
	if (conn->client->connect_notify_callback != NULL) {
		conn->client->connect_notify_callback(conn->client, TRUE,
				conn->client->connect_notify_context);
	}
}

static int
auth_server_lookup_request(struct auth_client_connection *conn,
			   const char *id_arg, bool remove,
			   struct auth_client_request **request_r)
{
	struct auth_client_request *request;
	unsigned int id;

	if (id_arg == NULL || str_to_uint(id_arg, &id) < 0) {
		e_error(conn->event,
			"BUG: Authentication server input missing ID");
		return -1;
	}

	request = hash_table_lookup(conn->requests, POINTER_CAST(id));
	if (request == NULL) {
		e_error(conn->event,
			"BUG: Authentication server sent unknown id %u", id);
		return -1;
	}
	if (remove || auth_client_request_is_aborted(request))
		hash_table_remove(conn->requests, POINTER_CAST(id));

	*request_r = request;
	return 0;
}

static int
auth_server_input_ok(struct auth_client_connection *conn,
		     const char *const *args)
{
	struct auth_client_request *request;

	if (auth_server_lookup_request(conn, args[0], TRUE, &request) < 0)
		return -1;
	auth_client_request_server_input(request, AUTH_REQUEST_STATUS_OK,
					 args + 1);
	return 0;
}

static int auth_server_input_cont(struct auth_client_connection *conn,
				  const char *const *args)
{
	struct auth_client_request *request;

	if (str_array_length(args) < 2) {
		e_error(conn->event,
			"BUG: Authentication server sent broken CONT line");
		return -1;
	}

	if (auth_server_lookup_request(conn, args[0], FALSE, &request) < 0)
		return -1;
	auth_client_request_server_input(request, AUTH_REQUEST_STATUS_CONTINUE,
					 args + 1);
	return 0;
}

static int auth_server_input_fail(struct auth_client_connection *conn,
				  const char *const *args)
{
	struct auth_client_request *request;

	if (auth_server_lookup_request(conn, args[0], TRUE, &request) < 0)
		return -1;
	auth_client_request_server_input(request, AUTH_REQUEST_STATUS_FAIL,
					 args + 1);
	return 0;
}

static int
auth_client_connection_handle_line(struct auth_client_connection *conn,
				   const char *line)
{
	const char *const *args;

	e_debug(conn->event, "auth input: %s", line);

	args = t_strsplit_tabescaped(line);
	if (args[0] == NULL) {
		e_error(conn->event, "Auth server sent empty line");
		return -1;
	}
	if (strcmp(args[0], "OK") == 0)
		return auth_server_input_ok(conn, args + 1);
	else if (strcmp(args[0], "CONT") == 0)
		return auth_server_input_cont(conn, args + 1);
	else if (strcmp(args[0], "FAIL") == 0)
		return auth_server_input_fail(conn, args + 1);
	else {
		e_error(conn->event,
			"Auth server sent unknown response: %s", args[0]);
		return -1;
	}
}

static int
auth_client_connection_input_line(struct connection *_conn,
				  const char *line)
{
	struct auth_client_connection *conn =
		container_of(_conn, struct auth_client_connection, conn);
	int ret;

	ret = auth_client_connection_handle_line(conn, line);
	if (ret < 0) {
		auth_client_connection_disconnect(conn, t_strdup_printf(
			"Received broken input: %s", line));
		return -1;
	}
	return 1;
}

struct auth_client_connection *
auth_client_connection_init(struct auth_client *client)
{
	struct auth_client_connection *conn;
	pool_t pool;

	pool = pool_alloconly_create("auth server connection", 1024);
	conn = p_new(pool, struct auth_client_connection, 1);
	conn->pool = pool;

	conn->client = client;

	conn->conn.event_parent = client->event;
	connection_init_client_unix(client->clist, &conn->conn,
				    client->auth_socket_path);
	conn->event = conn->conn.event;

	hash_table_create_direct(&conn->requests, pool, 100);
	i_array_init(&conn->available_auth_mechs, 8);
	return conn;
}

static void
auth_client_connection_remove_requests(struct auth_client_connection *conn,
				       const char *disconnect_reason)
{
	static const char *const temp_failure_args[] = { "temp", NULL };
	struct hash_iterate_context *iter;
	void *key;
	struct auth_client_request *request;
	time_t created, oldest = 0;
	unsigned int request_count = 0;

	if (hash_table_count(conn->requests) == 0)
		return;

	iter = hash_table_iterate_init(conn->requests);
	while (hash_table_iterate(iter, conn->requests, &key, &request)) {
		if (!auth_client_request_is_aborted(request)) {
			request_count++;
			created = auth_client_request_get_create_time(request);
			if (oldest > created || oldest == 0)
				oldest = created;
		}

		auth_client_request_server_input(request,
			AUTH_REQUEST_STATUS_INTERNAL_FAIL,
			temp_failure_args);
	}
	hash_table_iterate_deinit(&iter);
	hash_table_clear(conn->requests, FALSE);

	if (request_count > 0) {
		e_warning(conn->event,
			  "Auth connection closed with %u pending requests "
			  "(max %u secs, pid=%s, %s)", request_count,
			  (unsigned int)(ioloop_time - oldest),
			  my_pid, disconnect_reason);
	}
}

void auth_client_connection_disconnect(struct auth_client_connection *conn,
				       const char *reason) ATTR_NULL(2)
{
	if (reason == NULL)
		reason = "Disconnected from auth server, aborting";

	if (conn->connected)
		connection_disconnect(&conn->conn);
	conn->connected = FALSE;

	conn->has_plain_mech = FALSE;
	conn->server_pid = 0;
	conn->connect_uid = 0;
	conn->cookie = NULL;
	array_clear(&conn->available_auth_mechs);

	timeout_remove(&conn->to);

	auth_client_connection_remove_requests(conn, reason);

	if (conn->client->connect_notify_callback != NULL) {
		conn->client->connect_notify_callback(conn->client, FALSE,
				conn->client->connect_notify_context);
	}
}

static void auth_client_connection_destroy(struct connection *_conn)
{
	struct auth_client_connection *conn =
		container_of(_conn, struct auth_client_connection, conn);

	switch (_conn->disconnect_reason) {
	case CONNECTION_DISCONNECT_HANDSHAKE_FAILED:
		auth_client_connection_disconnect(
			conn, "Handshake with auth service failed");
		break;
	case CONNECTION_DISCONNECT_BUFFER_FULL:
		/* buffer full - can't happen unless auth is buggy */
		e_error(conn->event,
			"BUG: Auth server sent us more than %d bytes of data",
			AUTH_SERVER_CONN_MAX_LINE_LENGTH);
		auth_client_connection_disconnect(conn, "Buffer full");
		break;
	default:
		/* disconnected */
		auth_client_connection_reconnect(
			conn, (conn->conn.input->stream_errno != 0 ?
			       strerror(conn->conn.input->stream_errno) :
			       "EOF"));
	}
}

static void auth_server_reconnect_timeout(struct auth_client_connection *conn)
{
	(void)auth_client_connection_connect(conn);
}

static void
auth_client_connection_reconnect(struct auth_client_connection *conn,
				 const char *disconnect_reason)
{
	time_t next_connect;

	auth_client_connection_disconnect(conn, disconnect_reason);

	next_connect = conn->last_connect + AUTH_SERVER_RECONNECT_TIMEOUT_SECS;
	conn->to = timeout_add(ioloop_time >= next_connect ? 0 :
			       (next_connect - ioloop_time) * 1000,
			       auth_server_reconnect_timeout, conn);
}

void auth_client_connection_deinit(struct auth_client_connection **_conn)
{
        struct auth_client_connection *conn = *_conn;

	*_conn = NULL;

	auth_client_connection_disconnect(conn, "deinitializing");
	i_assert(hash_table_count(conn->requests) == 0);
	hash_table_destroy(&conn->requests);
	timeout_remove(&conn->to);
	array_free(&conn->available_auth_mechs);
	connection_deinit(&conn->conn);
	pool_unref(&conn->pool);
}

static void auth_client_handshake_timeout(struct auth_client_connection *conn)
{
	e_error(conn->event, "Timeout waiting for handshake from auth server. "
		"my pid=%u, input bytes=%"PRIuUOFF_T,
		conn->client->client_pid, conn->conn.input->v_offset);
	auth_client_connection_reconnect(conn, "auth server timeout");
}

static void
auth_client_connection_connected(struct connection *_conn, bool success)
{
	struct auth_client_connection *conn =
		container_of(_conn, struct auth_client_connection, conn);

	/* Cannot get here unless connect() was successful */
	i_assert(success);

	conn->connected = TRUE;
}

int auth_client_connection_connect(struct auth_client_connection *conn)
{
	const char *handshake;

	i_assert(!conn->connected);

	conn->last_connect = ioloop_time;
	timeout_remove(&conn->to);

	/* max. 1 second wait here. */
	if (connection_client_connect(&conn->conn) < 0) {
		if (errno == EACCES) {
			e_error(conn->event, "%s",
				eacces_error_get("connect",
					conn->client->auth_socket_path));
		} else {
			e_error(conn->event, "connect(%s) failed: %m",
				conn->client->auth_socket_path);
		};
		return -1;
	}

	handshake = t_strdup_printf("VERSION\t%u\t%u\nCPID\t%u\n",
				    AUTH_CLIENT_PROTOCOL_MAJOR_VERSION,
                                    AUTH_CLIENT_PROTOCOL_MINOR_VERSION,
				    conn->client->client_pid);
	if (o_stream_send_str(conn->conn.output, handshake) < 0) {
		e_warning(conn->event,
			  "Error sending handshake to auth server: %s",
			  o_stream_get_error(conn->conn.output));
		auth_client_connection_disconnect(conn,
			o_stream_get_error(conn->conn.output));
		return -1;
	}

	conn->to = timeout_add(conn->client->connect_timeout_msecs,
			       auth_client_handshake_timeout, conn);
	return 0;
}

unsigned int
auth_client_connection_add_request(struct auth_client_connection *conn,
				   struct auth_client_request *request)
{
	unsigned int id;

	i_assert(conn->conn.handshake_received);

	id = ++conn->client->request_id_counter;
	if (id == 0) {
		/* wrapped - ID 0 not allowed */
		id = ++conn->client->request_id_counter;
	}
	i_assert(hash_table_lookup(conn->requests, POINTER_CAST(id)) == NULL);
	hash_table_insert(conn->requests, POINTER_CAST(id), request);
	return id;
}

void auth_client_connection_remove_request(struct auth_client_connection *conn,
					   unsigned int id)
{
	i_assert(conn->conn.handshake_received);
	hash_table_remove(conn->requests, POINTER_CAST(id));
}
