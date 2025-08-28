/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "lib-signals.h"
#include "array.h"
#include "hash.h"
#include "ioloop.h"
#include "eacces-error.h"
#include "net.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "strescape.h"
#include "time-util.h"
#include "master-service.h"

#include "auth-master-private.h"

/*
 * Forward declarations
 */

static void auth_master_connected(struct connection *_conn, bool success);
static int
auth_master_input_args(struct connection *_conn, const char *const *args);
static int
auth_master_handshake_line(struct connection *_conn, const char *line);
static int auth_master_input_line(struct connection *_conn, const char *line);
static void auth_master_destroy(struct connection *_conn);

/*
 * Connection
 */

static const struct connection_vfuncs auth_master_vfuncs = {
	.destroy = auth_master_destroy,
	.handshake_line = auth_master_handshake_line,
	.input_args = auth_master_input_args,
	.input_line = auth_master_input_line,
	.client_connected = auth_master_connected,
};

static const struct connection_settings auth_master_set = {
	.dont_send_version = TRUE,
	.service_name_in = "auth-master",
	.service_name_out = "auth-master",
	.major_version = AUTH_CLIENT_PROTOCOL_MAJOR_VERSION,
	.minor_version = AUTH_CLIENT_PROTOCOL_MINOR_VERSION,
	.unix_client_connect_msecs = 1000,
	.input_max_size = MAX_INBUF_SIZE,
	.output_max_size = MAX_OUTBUF_SIZE,
	.client = TRUE,
};

struct auth_master_connection *
auth_master_init(const char *auth_socket_path, enum auth_master_flags flags)
{
	struct auth_master_connection *conn;
	struct event *event_parent;
	pool_t pool;

	pool = pool_alloconly_create("auth_master_connection", 1024);
	conn = p_new(pool, struct auth_master_connection, 1);
	conn->pool = pool;
	conn->refcount = 1;
	conn->ioloop = current_ioloop;
	conn->auth_socket_path = p_strdup(pool, auth_socket_path);
	conn->flags = flags;
	conn->timeout_msecs = 1000*MASTER_AUTH_LOOKUP_TIMEOUT_SECS;
	conn->clist = connection_list_init(&auth_master_set,
					   &auth_master_vfuncs);

	event_parent = event_create(NULL);
	event_add_category(event_parent, &event_category_auth_client);
	event_set_append_log_prefix(event_parent, "auth-master: ");
	event_set_forced_debug(event_parent,
			       HAS_ALL_BITS(flags, AUTH_MASTER_FLAG_DEBUG));

	conn->conn.event_parent = event_parent;
	connection_init_client_unix(conn->clist, &conn->conn,
				    conn->auth_socket_path);
	event_unref(&event_parent);

	hash_table_create_direct(&conn->requests, pool, 0);

	/* Try to use auth request ID numbers from wider range to ease
	   debugging. */
	conn->id_counter = i_rand_limit(32767) * 131072U;

	return conn;
}

static void
auth_master_connection_failure(struct auth_master_connection *conn,
			       const char *reason)
{
	struct auth_master_request *req;

	if (reason == NULL)
		reason = "Disconnected from auth service";

	if (conn->connected)
		e_debug(conn->conn.event, "%s", reason);

	conn->connected = FALSE;
	conn->sent_handshake = FALSE;

	timeout_remove(&conn->to_connect);
	timeout_remove(&conn->to_request);
	timeout_remove(&conn->to_idle);
	timeout_remove(&conn->to_invalid);

	while (conn->requests_head != NULL) {
		req = conn->requests_head;

		auth_master_request_fail(&req, reason);
	}
	i_assert(hash_table_count(conn->requests) == 0);

	if (conn->ioloop != NULL && conn->waiting)
		io_loop_stop(conn->ioloop);
}

static void
auth_master_connection_abort_requests(struct auth_master_connection *conn)
{
	struct auth_master_request *req;

	while (conn->requests_head != NULL) {
		req = conn->requests_head;

		auth_master_request_abort(&req);
	}
	i_assert(hash_table_count(conn->requests) == 0);
}

void auth_master_disconnect(struct auth_master_connection *conn)
{
	connection_disconnect(&conn->conn);
	auth_master_connection_failure(conn, NULL);
}

static void
auth_master_ref(struct auth_master_connection *conn)
{
	conn->refcount++;
}

static void
auth_master_unref(struct auth_master_connection **_conn)
{
	struct auth_master_connection *conn = *_conn;
	struct connection_list *clist = conn->clist;

	*_conn = NULL;

	i_assert(conn->refcount > 0);
	if (--conn->refcount > 0)
		return;

	auth_master_disconnect(conn);
	connection_deinit(&conn->conn);
	connection_list_deinit(&clist);
	hash_table_destroy(&conn->requests);
	pool_unref(&conn->pool);
}

void auth_master_deinit(struct auth_master_connection **_conn)
{
	struct auth_master_connection *conn = *_conn;

	*_conn = NULL;

	auth_master_disconnect(conn);
	auth_master_unref(&conn);
}

void auth_master_set_timeout(struct auth_master_connection *conn,
			     unsigned int msecs)
{
	conn->timeout_msecs = msecs;
}

const char *auth_master_get_socket_path(struct auth_master_connection *conn)
{
	return conn->auth_socket_path;
}

static void auth_master_destroy(struct connection *_conn)
{
	struct auth_master_connection *conn =
		container_of(_conn, struct auth_master_connection, conn);

	if (conn->connected)
		connection_disconnect(&conn->conn);
	conn->connected = FALSE;
	conn->sent_handshake = FALSE;

	switch (_conn->disconnect_reason) {
	case CONNECTION_DISCONNECT_HANDSHAKE_FAILED:
		auth_master_connection_failure(
			conn, "Handshake with auth service failed");
		break;
	case CONNECTION_DISCONNECT_BUFFER_FULL:
		e_error(conn->conn.event, "BUG: Received more than %d bytes",
			MAX_INBUF_SIZE);
		auth_master_connection_failure(conn, NULL);
		break;
	default:
		if (conn->requests_head != NULL) {
			e_error(conn->conn.event, "Disconnected unexpectedly");
			auth_master_connection_failure(conn,
				"Unexpectedly disconnected from auth service");
			break;
		}
		auth_master_connection_failure(conn, NULL);
	}
}

static void
auth_master_connection_timeout(struct auth_master_connection *conn)
{
	struct auth_master_request *req;
	const char *reason;

	timeout_remove(&conn->to_request);

	conn->in_timeout = TRUE;
	req = conn->requests_head;
	while (req != NULL && auth_master_request_get_timeout_msecs(req) == 0) {
		struct auth_master_request *req_next = req->next;
		int msecs;

		if (req->in_callback) {
			req = req_next;
			continue;
		}

		msecs = timeval_diff_msecs(&ioloop_timeval, &req->create_stamp);
		reason = t_strdup_printf(
			"Auth server request timed out after %u.%03u secs",
			 msecs / 1000, msecs % 1000);
		auth_master_request_fail(&req, reason);

		req = req_next;
	}
	conn->in_timeout = FALSE;

	auth_master_connection_update_timeout(conn);
}

void auth_master_connection_update_timeout(struct auth_master_connection *conn)
{
	struct auth_master_request *req;

	if (conn->in_timeout)
		return;
	if (!conn->connected) {
		i_assert(conn->to_request == NULL);
		return;
	}

	req = conn->requests_head;
	while (req != NULL && req->in_callback)
		req = req->next;

	timeout_remove(&conn->to_request);
	if (req == NULL)
		return;

	conn->to_request = timeout_add_to(
		conn->ioloop, auth_master_request_get_timeout_msecs(req),
		auth_master_connection_timeout, conn);
}

void auth_master_connection_start_timeout(struct auth_master_connection *conn)
{
	if (conn->to_request != NULL || conn->to_connect != NULL)
		return;

	auth_master_connection_update_timeout(conn);
}

static int
auth_master_handshake_line(struct connection *_conn, const char *line)
{
	struct auth_master_connection *conn =
		container_of(_conn, struct auth_master_connection, conn);
	const char *const *tmp;
	unsigned int major_version, minor_version;

	tmp = t_strsplit_tabescaped(line);
	if (strcmp(tmp[0], "VERSION") == 0 &&
	    tmp[1] != NULL && tmp[2] != NULL) {
		if (str_to_uint(tmp[1], &major_version) < 0 ||
		    str_to_uint(tmp[2], &minor_version) < 0) {
			e_error(conn->conn.event,
				"Auth server sent invalid version line: %s",
				line);
			return -1;
		}

		if (connection_verify_version(_conn, "auth-master",
					      major_version,
					      minor_version) < 0)
			return -1;
		return 0;
	} else if (strcmp(tmp[0], "SPID") != 0) {
		return 0;
	}

	if (str_to_pid(tmp[1], &conn->auth_server_pid) < 0) {
		e_error(conn->conn.event,
			"Authentication server sent invalid SPID: %s", line);
		return -1;
	}

	/* Handshake complete */
	timeout_remove(&conn->to_connect);
	auth_master_connection_update_timeout(conn);
	return 1;
}

static int
auth_master_handle_input(struct auth_master_connection *conn,
			 const char *const *args)
{
	struct auth_master_request *req;
	unsigned int id;

	if (strcmp(args[0], "CUID") == 0) {
		e_error(conn->conn.event, "%s is an auth client socket. "
			"It should be a master socket.",
			conn->auth_socket_path);
		return -1;
	}

	if (args[1] == NULL || str_to_uint(args[1], &id) < 0) {
		e_error(conn->conn.event, "BUG: Unexpected input: %s",
			t_strarray_join(args, "\t"));
		return -1;
	}

	req = hash_table_lookup(conn->requests, POINTER_CAST(id));
	if (req == NULL) {
		e_debug(conn->conn.event,
			"Auth server sent reply with unknown ID %u "
			"(this request was probably aborted)", id);
		return -1;
	}

	e_debug(conn->conn.event, "auth input: %s",
		t_strarray_join(args, "\t"));

	return auth_master_request_got_reply(&req, args[0], args + 2);
}

static int
auth_master_input_args(struct connection *_conn, const char *const *args)
{
	struct auth_master_connection *conn =
		container_of(_conn, struct auth_master_connection, conn);
	int ret;

	ret = auth_master_handle_input(conn, args);
	if (ret < 0) {
		auth_master_disconnect(conn);
		return -1;
	}
	return 1;
}

static void
auth_master_handle_output_error(struct auth_master_connection *conn)
{
	struct ostream *output = conn->conn.output;

	if (output->stream_errno != EPIPE &&
	    output->stream_errno != ECONNRESET) {
		e_error(conn->conn.event, "write(%s) failed: %s",
			o_stream_get_name(output), o_stream_get_error(output));
	} else {
		e_error(conn->conn.event, "Remote disconnected");
	}
	auth_master_disconnect(conn);
}

static int
auth_master_connection_output(struct auth_master_connection *conn)
{
	int ret;

	if ((ret = o_stream_flush(conn->conn.output)) <= 0) {
		if (ret < 0)
			auth_master_handle_output_error(conn);
		return ret;
	}

	if (o_stream_get_buffer_used_size(conn->conn.output) >= MAX_OUTBUF_SIZE)
		return 1;

	o_stream_cork(conn->conn.output);
	if (!conn->sent_handshake) {
		const struct connection_settings *set = &conn->conn.list->set;

		o_stream_nsend_str(conn->conn.output,
			t_strdup_printf("VERSION\t%u\t%u\n",
					set->major_version,
					set->minor_version));
		conn->sent_handshake = TRUE;
	}

	e_debug(conn->conn.event, "Sending requests");

	while (conn->requests_unsent != NULL) {
		auth_master_request_send(conn->requests_unsent);
		conn->requests_unsent = conn->requests_unsent->next;
		if (o_stream_get_buffer_used_size(conn->conn.output) >=
		    MAX_OUTBUF_SIZE)
			break;
	}

	if (conn->conn.output != NULL &&
	    o_stream_uncork_flush(conn->conn.output) < 0) {
		auth_master_handle_output_error(conn);
		return -1;
	}
	return 1;
}

static int auth_master_input_line(struct connection *_conn, const char *line)
{
	struct auth_master_connection *conn =
		container_of(_conn, struct auth_master_connection, conn);
	struct ioloop *cur_ioloop = conn->ioloop;
	int ret;

	auth_master_ref(conn);

	ret = connection_input_line_default(_conn, line);
	if (ret > 0 && !io_loop_is_running(cur_ioloop))
		ret = 0;

	auth_master_unref(&conn);

	return ret;
}

static void auth_master_connected(struct connection *_conn, bool success)
{
	struct auth_master_connection *conn =
		container_of(_conn, struct auth_master_connection, conn);

	/* Cannot get here unless connect() was successful */
	i_assert(success);

	conn->connected = TRUE;

	o_stream_set_flush_callback(_conn->output,
				    auth_master_connection_output, conn);
	auth_master_handle_requests(conn);
}

static void auth_master_connect_timeout(struct auth_master_connection *conn)
{
	e_error(conn->conn.event, "Connecting timed out");
	auth_master_connection_failure(conn, "Connecting timed out");
}

static void
auth_master_delayed_connect_failure(struct auth_master_connection *conn)
{
	e_debug(conn->conn.event, "Delayed connect failure");

	i_assert(conn->to_connect != NULL);
	timeout_remove(&conn->to_connect);
	auth_master_connection_failure(conn,
		"Failed to connect to auth service");
}

int auth_master_connect(struct auth_master_connection *conn)
{
	if (conn->connected)
		return 0;

	i_assert(conn->to_connect == NULL);
	i_assert(conn->to_request == NULL);

	if (conn->ioloop != NULL)
		connection_switch_ioloop_to(&conn->conn, conn->ioloop);
	if (connection_client_connect(&conn->conn) < 0) {
		if (errno == EACCES) {
			e_error(conn->conn.event,
				"%s", eacces_error_get("connect",
						       conn->auth_socket_path));
		} else {
			e_error(conn->conn.event, "connect(%s) failed: %m",
				conn->auth_socket_path);
		}
		conn->to_connect = timeout_add_to(
			conn->ioloop, 0,
			auth_master_delayed_connect_failure, conn);
		return -1;
	}

	conn->to_connect = timeout_add_to(conn->ioloop, conn->timeout_msecs,
					  auth_master_connect_timeout, conn);
	return 0;
}

void auth_master_handle_requests(struct auth_master_connection *conn)
{
	if (conn->requests_unsent == NULL)
		return;

	if (!conn->connected) {
		e_debug(conn->conn.event, "Need to connect");

		(void)auth_master_connect(conn);
		return;
	}

	i_assert(conn->conn.output != NULL);
	o_stream_set_flush_pending(conn->conn.output, TRUE);
}

static void
auth_master_abort_invalid_requests(struct auth_master_connection *conn)
{
	struct auth_master_request *req, *req_next;

	timeout_remove(&conn->to_invalid);

	req = conn->requests_unsent;
	while (req != NULL) {
		req_next = req->next;
		if (req->invalid)
			auth_master_request_abort_invalid(&req);
		req = req_next;
	}
}

void auth_master_handle_invalid_requests(struct auth_master_connection *conn)
{
	if (conn->to_invalid != NULL)
		return;

	conn->to_invalid = timeout_add_to(
		conn->ioloop, 0,
		auth_master_abort_invalid_requests, conn);
}

void auth_master_switch_ioloop_to(struct auth_master_connection *conn,
				  struct ioloop *ioloop)
{
	conn->ioloop = ioloop;

	if (conn->to_connect != NULL) {
		conn->to_connect =
			io_loop_move_timeout_to(ioloop, &conn->to_connect);
	}
	if (conn->to_request != NULL) {
		conn->to_request =
			io_loop_move_timeout_to(ioloop, &conn->to_request);
	}
	if (conn->to_idle != NULL)
		conn->to_idle = io_loop_move_timeout_to(ioloop, &conn->to_idle);
	if (conn->to_invalid != NULL) {
		conn->to_idle =
			io_loop_move_timeout_to(ioloop, &conn->to_invalid);
	}
	connection_switch_ioloop_to(&conn->conn, conn->ioloop);
}

void auth_master_switch_ioloop(struct auth_master_connection *conn)
{
	auth_master_switch_ioloop_to(conn, current_ioloop);
}

static void auth_master_idle_timeout(struct auth_master_connection *conn)
{
	e_debug(conn->conn.event, "Idle timeout");
	auth_master_disconnect(conn);
}

void auth_master_check_idle(struct auth_master_connection *conn)
{
	if ((conn->flags & AUTH_MASTER_FLAG_NO_IDLE_TIMEOUT) != 0)
		return;
	if (current_ioloop == NULL)
		return;
	i_assert(conn->to_idle == NULL);
	if (conn->requests_head != NULL)
		return;
	conn->to_idle = timeout_add_to(conn->ioloop,
				       1000 * AUTH_MASTER_IDLE_SECS,
				       auth_master_idle_timeout, conn);
}

void auth_master_stop_idle(struct auth_master_connection *conn)
{
	timeout_remove(&conn->to_idle);
}

static void auth_master_stop(struct auth_master_connection *conn)
{
	if (master_service_is_killed(master_service)) {
		auth_master_connection_abort_requests(conn);
		io_loop_stop(conn->ioloop);
	}
}

void auth_master_wait(struct auth_master_connection *conn)
{
	struct ioloop *ioloop, *prev_ioloop;
	struct timeout *to;
	bool waiting = conn->waiting, was_corked = FALSE;

	i_assert(conn->ioloop == NULL);
	i_assert(auth_master_request_count(conn) > 0);

	auth_master_ref(conn);

	e_debug(conn->conn.event, "Waiting for all requests to complete");

	prev_ioloop = conn->ioloop;
	if (!waiting)
		conn->prev_ioloop = prev_ioloop;
	ioloop = io_loop_create();
	auth_master_switch_ioloop_to(conn, ioloop);

	if (conn->conn.input != NULL &&
	    i_stream_get_data_size(conn->conn.input) > 0)
		i_stream_set_input_pending(conn->conn.input, TRUE);
	o_stream_set_flush_pending(conn->conn.output, TRUE);
	if (conn->conn.output != NULL) {
		was_corked = o_stream_is_corked(conn->conn.output);
		o_stream_uncork(conn->conn.output);
	}

	/* either we're waiting for network I/O or we're getting out of a
	   callback using timeout_add_short(0) */
	i_assert(io_loop_have_ios(ioloop) ||
		 io_loop_have_immediate_timeouts(ioloop));

	/* add stop handler */
	to = timeout_add_short(100, auth_master_stop, conn);

	conn->waiting = TRUE;
	while (auth_master_request_count(conn) > 0)
		io_loop_run(ioloop);
	conn->waiting = waiting;

	timeout_remove(&to);

	if (conn->conn.output != NULL && was_corked)
		o_stream_cork(conn->conn.output);

	auth_master_switch_ioloop_to(conn, prev_ioloop);
	io_loop_destroy(&ioloop);
	if (!waiting)
		conn->prev_ioloop = NULL;

	e_debug(conn->conn.event, "Finished waiting for requests");

	auth_master_unref(&conn);
}

/*
 * Lookup common
 */

struct auth_master_lookup {
	struct auth_master_request *req;
	struct event *event;

	char *user;
	const char *expected_reply;

	void (*finished)(struct auth_master_lookup *lookup,
			 int result, const char *const *fields);
};

static bool is_valid_string(const char *str)
{
	const char *p;

	/* make sure we're not sending any characters that have a special
	   meaning. */
	for (p = str; *p != '\0'; p++) {
		if (*p == '\t' || *p == '\n' || *p == '\r')
			return FALSE;
	}
	return TRUE;
}

static const char *const *args_hide_passwords(const char *const *args)
{
	ARRAY_TYPE(const_string) new_args;
	const char *p, *p2;
	unsigned int i;

	/* if there are any keys that contain "pass" string */
	for (i = 0; args[i] != NULL; i++) {
		p = strstr(args[i], "pass");
		if (p != NULL && p < strchr(args[i], '='))
			break;
	}
	if (args[i] == NULL)
		return args;

	/* there are. replace their values with <hidden> */
	t_array_init(&new_args, i + 16);
	array_append(&new_args, args, i);
	for (; args[i] != NULL; i++) {
		p = strstr(args[i], "pass");
		p2 = strchr(args[i], '=');
		if (p != NULL && p < p2) {
			p = t_strconcat(t_strdup_until(args[i], p2),
					"=<hidden>", NULL);
			array_push_back(&new_args, &p);
		} else {
			array_push_back(&new_args, &args[i]);
		}
	}
	array_append_zero(&new_args);
	return array_front(&new_args);
}

void auth_user_info_export(string_t *str, const struct auth_user_info *info)
{
	const char *const *fieldp;

	if (info->protocol != NULL) {
		str_append(str, "\tprotocol=");
		str_append(str, info->protocol);
	}
	if (info->session_id != NULL) {
		str_append(str, "\tsession=");
		str_append_tabescaped(str, info->session_id);
	}
	if (info->local_name != NULL) {
		str_append(str, "\tlocal_name=");
		str_append_tabescaped(str, info->local_name);
	}
	if (info->local_ip.family != 0)
		str_printfa(str, "\tlip=%s", net_ip2addr(&info->local_ip));
	if (info->local_port != 0)
		str_printfa(str, "\tlport=%d", info->local_port);
	if (info->remote_ip.family != 0)
		str_printfa(str, "\trip=%s", net_ip2addr(&info->remote_ip));
	if (info->remote_port != 0)
		str_printfa(str, "\trport=%d", info->remote_port);
	if (info->real_remote_ip.family != 0 &&
	    !net_ip_compare(&info->real_remote_ip, &info->remote_ip))
		str_printfa(str, "\treal_rip=%s", net_ip2addr(&info->real_remote_ip));
	if (info->real_local_ip.family != 0 &&
	    !net_ip_compare(&info->real_local_ip, &info->local_ip))
		str_printfa(str, "\treal_lip=%s", net_ip2addr(&info->real_local_ip));
	if (info->real_local_port != 0 &&
	    info->real_local_port != info->local_port)
		str_printfa(str, "\treal_lport=%d", info->real_local_port);
	if (info->real_remote_port != 0 &&
	    info->real_remote_port != info->remote_port)
		str_printfa(str, "\treal_rport=%d", info->real_remote_port);
	if (info->debug)
		str_append(str, "\tdebug");
	if (info->forward_fields != NULL && info->forward_fields[0] != NULL) {
		string_t *forward = t_str_new(64);
		str_append_tabescaped(forward, info->forward_fields[0]);
		for (unsigned int i = 1; info->forward_fields[i] != NULL; i++) {
			str_append_c(forward, '\t');
			str_append_tabescaped(forward, info->forward_fields[i]);
		}
		str_append(str, "\tforward_fields=");
		str_append_tabescaped(str, str_c(forward));
	}
	if (array_is_created(&info->extra_fields)) {
		array_foreach(&info->extra_fields, fieldp) {
			str_append_c(str, '\t');
			str_append_tabescaped(str, *fieldp);
		}
	}
}

static struct event *
auth_master_user_event_create(struct auth_master_connection *conn,
			      const char *prefix,
			      const struct auth_user_info *info)
{
	struct event *event;

	event = event_create(conn->conn.event);
	event_drop_parent_log_prefixes(event, 1);
	event_set_append_log_prefix(event, prefix);

	if (info != NULL) {
		if (info->protocol != NULL)
			event_add_str(event, "protocol", info->protocol);
		if (info->session_id != NULL)
			event_add_str(event, "session", info->session_id);
		if (info->local_name != NULL)
			event_add_str(event, "local_name", info->local_name);
		if (info->local_ip.family != 0)
			event_add_ip(event, "local_ip", &info->local_ip);
		if (info->local_port != 0)
			event_add_int(event, "local_port", info->local_port);
		if (info->remote_ip.family != 0)
			event_add_ip(event, "remote_ip", &info->remote_ip);
		if (info->remote_port != 0)
			event_add_int(event, "remote_port", info->remote_port);
		if (info->real_local_ip.family != 0)
			event_add_ip(event, "real_local_ip",
				     &info->real_local_ip);
		if (info->real_remote_ip.family != 0)
			event_add_ip(event, "real_remote_ip",
				     &info->real_remote_ip);
		if (info->real_local_port != 0)
			event_add_int(event, "real_local_port",
				      info->real_local_port);
		if (info->real_remote_port != 0)
			event_add_int(event, "real_remote_port",
				      info->real_remote_port);
	}

	return event;
}

static int
parse_reply(struct auth_master_lookup *lookup, const char *reply,
	    const char *const *args)
{
	if (strcmp(reply, lookup->expected_reply) == 0)
		return 1;
	if (strcmp(reply, "NOTFOUND") == 0)
		return 0;
	if (strcmp(reply, "FAIL") == 0) {
		if (*args == NULL) {
			e_error(lookup->event, "Auth %s lookup failed",
				lookup->expected_reply);
		} else {
			e_debug(lookup->event,
				"Auth %s lookup returned temporary failure: %s",
				lookup->expected_reply, *args);
		}
		return -2;
	}
	e_error(lookup->event, "Unknown reply: %s", reply);
	return -1;
}

static int
auth_lookup_reply_callback(const struct auth_master_reply *reply,
			   struct auth_master_lookup *lookup)
{
	const char *value;
	const char *const *args = reply->args, *const *fields;
	unsigned int i, len;
	const char *error_fields[2];
	int result;

	if (reply->errormsg != NULL) {
		i_zero(&error_fields);
		error_fields[0] = reply->errormsg;
		e_debug(lookup->event, "auth %s error: %s",
			lookup->expected_reply, reply->errormsg);
		lookup->finished(lookup, -1, error_fields);
		return 1;
	}
	i_assert(reply->reply != NULL);
	i_assert(args != NULL);

	result = parse_reply(lookup, reply->reply, args);

	fields = args;
	len = str_array_length(args);
	i_assert(*args != NULL || len == 0); /* for static analyzer */
	if (result >= 0) {
		if (len == 0) {
			e_debug(lookup->event, "auth %s input: (empty)",
				lookup->expected_reply);
		} else {
			args = args_hide_passwords(args);
			e_debug(lookup->event, "auth %s input: %s",
				lookup->expected_reply,
				t_strarray_join(args, " "));
		}
	} else {
		/* put the reason string into first field */
		i_zero(&error_fields);
		for (i = 0; i < len; i++) {
			if (str_begins(args[i], "reason=", &value)) {
				error_fields[0] = value;
				break;
			}
		}
		if (error_fields[0] != NULL) {
			e_debug(lookup->event, "auth %s error: %s",
				lookup->expected_reply, error_fields[0]);
		} else {
			e_debug(lookup->event, "auth %s error: (unknown)",
				lookup->expected_reply);
		}
		fields = error_fields;
	}

	lookup->finished(lookup, result, fields);
	return 1;
}

/*
 * PassDB
 */

/* PASS */

struct auth_master_pass_lookup {
	struct auth_master_lookup lookup;

	auth_master_pass_lookup_callback_t *callback;
	void *context;
};

struct auth_master_pass_lookup_ctx {
	pool_t pool;

	int result;
	const char *const *fields;
};

static void
auth_master_pass_lookup_callback(struct auth_master_pass_lookup_ctx *ctx,
				 int result, const char *const *fields)
{
	ctx->result = result;
	ctx->fields = p_strarray_dup(ctx->pool, fields);
}

int auth_master_pass_lookup(struct auth_master_connection *conn,
			    const char *user, const struct auth_user_info *info,
			    pool_t pool, const char *const **fields_r)
{
	struct auth_master_request *req;

	if (!is_valid_string(user) || !is_valid_string(info->protocol)) {
		/* non-allowed characters, the user can't exist */
		*fields_r = NULL;
		return 0;
	}
	if (auth_master_connect(conn) < 0) {
		*fields_r = empty_str_array;
		return -1;
	}

	struct auth_master_pass_lookup_ctx ctx = {
		.pool = pool,
		.result = -1,
	};

	req = auth_master_pass_lookup_async(conn, user, info,
					    auth_master_pass_lookup_callback,
					    &ctx);
	(void)auth_master_request_wait(req);

	*fields_r = ctx.fields != NULL ? ctx.fields :
		p_new(pool, const char *, 1);
	return ctx.result;
}

static void
auth_master_pass_lookup_destroyed(struct auth_master_pass_lookup *lookup)
{
	event_unref(&lookup->lookup.event);
	i_free(lookup->lookup.user);
	i_free(lookup);
}

static void
auth_master_pass_lookup_finished(struct auth_master_lookup *_lookup,
				 int result, const char *const *fields)
{
	struct auth_master_pass_lookup *lookup =
		container_of(_lookup, struct auth_master_pass_lookup, lookup);

	if (result <= 0) {
		struct event_passthrough *e =
			event_create_passthrough(_lookup->event)->
			set_name("auth_client_passdb_lookup_finished");
		if (fields == NULL || fields[0] == NULL) {
			e->add_str("error", "Lookup failed");
			e_debug(e->event(), "Passdb lookup failed");
		} else {
			e->add_str("error", fields[0]);
			e_debug(e->event(), "Passdb lookup failed: %s",
				fields[0]);
		}
	} else {
		struct event_passthrough *e =
			event_create_passthrough(_lookup->event)->
			set_name("auth_client_passdb_lookup_finished");
		e_debug(e->event(), "Finished passdb lookup (%s)",
			(fields == NULL ? "" : t_strarray_join(fields, " ")));
	}

	lookup->callback(lookup->context, result, fields);
}

#undef auth_master_pass_lookup_async
struct auth_master_request *
auth_master_pass_lookup_async(struct auth_master_connection *conn,
			      const char *user,
			      const struct auth_user_info *info,
			      auth_master_pass_lookup_callback_t *callback,
			      void *context)
{
	struct auth_master_request *req;
	struct auth_master_pass_lookup *lookup;
	string_t *args;

	lookup = i_new(struct auth_master_pass_lookup, 1);
	lookup->lookup.finished = auth_master_pass_lookup_finished;
	lookup->callback = callback;
	lookup->context = context;

	if (!is_valid_string(user) || !is_valid_string(info->protocol)) {
		/* non-allowed characters, the user can't exist */
		req = auth_master_request_invalid(conn,
			auth_lookup_reply_callback, &lookup->lookup);
		auth_master_request_add_destroy_callback(req,
			auth_master_pass_lookup_destroyed, lookup);
		lookup->lookup.req = req;
		return req;
	}

	lookup->lookup.expected_reply = "PASS";
	lookup->lookup.user = i_strdup(user);

	args = t_str_new(128);
	str_append(args, user);
	auth_user_info_export(args, info);

	lookup->lookup.event = auth_master_user_event_create(
		conn, t_strdup_printf("passdb lookup(%s): ", user), info);
	event_add_str(lookup->lookup.event, "user", user);

	struct event_passthrough *e =
		event_create_passthrough(lookup->lookup.event)->
		set_name("auth_client_passdb_lookup_started");
	e_debug(e->event(), "Started passdb lookup");

	req = auth_master_request(conn, "PASS", str_data(args), str_len(args),
				  auth_lookup_reply_callback, &lookup->lookup);

	auth_master_request_set_event(req, lookup->lookup.event);
	auth_master_request_add_destroy_callback(req,
		auth_master_pass_lookup_destroyed, lookup);
	lookup->lookup.req = req;

	return req;
}

/*
 * UserDB
 */

/* USER */

struct auth_master_user_lookup {
	struct auth_master_lookup lookup;

	auth_master_user_lookup_callback_t *callback;
	void *context;
};

struct auth_master_user_lookup_ctx {
	pool_t pool;

	int result;
	const char *username;
	const char *const *fields;
};

static void
auth_master_user_lookup_callback(struct auth_master_user_lookup_ctx *ctx,
				 int result, const char *username,
				 const char *const *fields)
{
	ctx->result = result;
	ctx->username = p_strdup(ctx->pool, username);
	ctx->fields = p_strarray_dup(ctx->pool, fields);
}

int auth_master_user_lookup(struct auth_master_connection *conn,
			    const char *user, const struct auth_user_info *info,
			    pool_t pool, const char **username_r,
			    const char *const **fields_r)
{
	struct auth_master_request *req;

	if (!is_valid_string(user) || !is_valid_string(info->protocol)) {
		/* non-allowed characters, the user can't exist */
		*username_r = NULL;
		*fields_r = NULL;
		return 0;
	}
	if (auth_master_connect(conn) < 0) {
		*fields_r = empty_str_array;
		return -1;
	}

	struct auth_master_user_lookup_ctx ctx = {
		.pool = pool,
		.result = -1,
	};

	req = auth_master_user_lookup_async(conn, user, info,
					    auth_master_user_lookup_callback,
					    &ctx);
	(void)auth_master_request_wait(req);

	*username_r = ctx.username;
	*fields_r = ctx.fields != NULL ? ctx.fields :
		p_new(pool, const char *, 1);
	return ctx.result;
}

static void
auth_master_user_lookup_destroyed(struct auth_master_user_lookup *lookup)
{
	event_unref(&lookup->lookup.event);
	i_free(lookup->lookup.user);
	i_free(lookup);
}

static void
auth_master_user_lookup_finished(struct auth_master_lookup *_lookup,
				 int result, const char *const *fields)
{
	struct auth_master_user_lookup *lookup =
		container_of(_lookup, struct auth_master_user_lookup, lookup);
	const char *username = NULL;

	if (result <= 0 || fields[0] == NULL) {
		struct event_passthrough *e =
			event_create_passthrough(_lookup->event)->
			set_name("auth_client_userdb_lookup_finished");

		if (result > 0) {
			e->add_str("error", "Lookup didn't return username");
			e_error(e->event(), "Userdb lookup failed: "
				"Lookup didn't return username");
			result = -2;
		} else if (fields == NULL || fields[0] == NULL) {
			e->add_str("error", "Lookup failed");
			e_debug(e->event(), "Userdb lookup failed");
		} else {
			e->add_str("error", fields[0]);
			e_debug(e->event(), "Userdb lookup failed: %s",
				fields[0]);
		}
	} else {
		username = fields[0];
		fields = fields + 1;

		struct event_passthrough *e =
			event_create_passthrough(_lookup->event)->
			set_name("auth_client_userdb_lookup_finished");
		e_debug(e->event(), "Finished userdb lookup (username=%s %s)",
			username, t_strarray_join(fields, " "));
	}

	lookup->callback(lookup->context, result, username, fields);
}

#undef auth_master_user_lookup_async
struct auth_master_request *
auth_master_user_lookup_async(struct auth_master_connection *conn,
			      const char *user,
			      const struct auth_user_info *info,
			      auth_master_user_lookup_callback_t *callback,
			      void *context)
{
	struct auth_master_request *req;
	struct auth_master_user_lookup *lookup;
	string_t *args;

	lookup = i_new(struct auth_master_user_lookup, 1);
	lookup->lookup.finished = auth_master_user_lookup_finished;
	lookup->callback = callback;
	lookup->context = context;

	if (!is_valid_string(user) || !is_valid_string(info->protocol)) {
		/* non-allowed characters, the user can't exist */
		req = auth_master_request_invalid(conn,
			auth_lookup_reply_callback, &lookup->lookup);
		auth_master_request_add_destroy_callback(req,
			auth_master_user_lookup_destroyed, lookup);
		lookup->lookup.req = req;
		return req;
	}

	lookup->lookup.expected_reply = "USER";
	lookup->lookup.user = i_strdup(user);

	args = t_str_new(128);
	str_append(args, user);
	auth_user_info_export(args, info);

	lookup->lookup.event = auth_master_user_event_create(
		conn, t_strdup_printf("userdb lookup(%s): ", user), info);
	event_add_str(lookup->lookup.event, "user", user);

	struct event_passthrough *e =
		event_create_passthrough(lookup->lookup.event)->
		set_name("auth_client_userdb_lookup_started");
	e_debug(e->event(), "Started userdb lookup");

	req = auth_master_request(conn, "USER", str_data(args), str_len(args),
				  auth_lookup_reply_callback, &lookup->lookup);

	auth_master_request_set_event(req, lookup->lookup.event);
	auth_master_request_add_destroy_callback(req,
		auth_master_user_lookup_destroyed, lookup);
	lookup->lookup.req = req;

	return req;
}

int auth_user_fields_parse(const char *const *fields, pool_t pool,
			   struct auth_user_reply *reply_r, const char **error_r)
{
	i_zero(reply_r);
	reply_r->uid = (uid_t)-1;
	reply_r->gid = (gid_t)-1;
	p_array_init(&reply_r->extra_fields, pool, 64);

	for (; *fields != NULL; fields++) {
		const char *key, *value;
		t_split_key_value_eq(*fields, &key, &value);

		if (strcmp(key, "uid") == 0) {
			if (str_to_uid(value, &reply_r->uid) < 0) {
				*error_r = "Invalid uid in reply";
				return -1;
			}
		} else if (strcmp(key, "gid") == 0) {
			if (str_to_gid(value, &reply_r->gid) < 0) {
				*error_r = "Invalid gid in reply";
				return -1;
			}
		} else if (strcmp(key, "home") == 0)
			reply_r->home = p_strdup(pool, value);
		else if (strcmp(key, "chroot") == 0)
			reply_r->chroot = p_strdup(pool, value);
		else if (strcmp(*fields, "anonymous") == 0)
			reply_r->anonymous = TRUE;
		else {
			const char *field = p_strdup(pool, *fields);
			array_push_back(&reply_r->extra_fields, &field);
		}
	}
	return 0;
}

/* LIST */

struct auth_master_user_list_ctx {
	struct auth_master_connection *conn;
	struct event *event;
	struct auth_master_request *req;
	string_t *username;
	bool finished;
	bool failed;
};

static int
auth_user_list_reply_callback(const struct auth_master_reply *reply,
			      struct auth_master_user_list_ctx *ctx)
{
	const char *const *args = reply->args;

	if (reply->errormsg != NULL) {
		e_error(ctx->event, "User listing failed: %s", reply->errormsg);
		ctx->req = NULL;
		ctx->failed = TRUE;
		ctx->finished = TRUE;
		return 1;
	}
	i_assert(reply->reply != NULL);
	i_assert(args != NULL);

	if (strcmp(reply->reply, "DONE") == 0) {
		ctx->req = NULL;
		if (args[0] != NULL && strcmp(args[0], "fail") == 0) {
			e_error(ctx->event, "User listing returned failure");
			ctx->failed = TRUE;
		}
		ctx->finished = TRUE;
		return 1;
	}
	if (strcmp(reply->reply, "LIST") != 0 || args[0] == NULL) {
		e_error(ctx->event, "User listing returned invalid input");
		ctx->req = NULL;
		ctx->failed = TRUE;
		return -1;
	}

	/* We'll just read all the users into memory. otherwise we'd have to use
	   a separate connection for listing and there's a higher chance of a
	   failure since the connection could be open to dovecot-auth for a long
	   time. */
	str_append(ctx->username, args[0]);
	return 0;
}

struct auth_master_user_list_ctx *
auth_master_user_list_init(struct auth_master_connection *conn,
			   const char *user_mask,
			   const struct auth_user_info *info)
{
	struct auth_master_user_list_ctx *ctx;
	string_t *args;

	i_assert(auth_master_request_count(conn) == 0);

	ctx = i_new(struct auth_master_user_list_ctx, 1);
	ctx->conn = conn;
	ctx->username = str_new(default_pool, 128);

	args = t_str_new(128);
	if (*user_mask != '\0')
		str_printfa(args, "\tuser=%s", user_mask);
	if (info != NULL)
		auth_user_info_export(args, info);

	ctx->event = auth_master_user_event_create(conn, "userdb list: ", info);
	event_add_str(ctx->event," user_mask", user_mask);

	struct event_passthrough *e =
		event_create_passthrough(ctx->event)->
		set_name("auth_client_userdb_list_started");
	e_debug(e->event(), "Started listing users (user_mask=%s)", user_mask);

	ctx->req = auth_master_request(conn, "LIST",
				       str_data(args), str_len(args),
				       auth_user_list_reply_callback, ctx);
	auth_master_request_set_event(ctx->req, ctx->event);

	connection_input_halt(&conn->conn);

	return ctx;
}

static const char *
auth_master_user_do_list_next(struct auth_master_user_list_ctx *ctx)
{
	struct auth_master_connection *conn = ctx->conn;
	const char *line;

	if (ctx->finished || ctx->failed || ctx->req == NULL)
		return NULL;

	i_assert(!conn->waiting);
	str_truncate(ctx->username, 0);

	/* try to read already buffered input */
	if (conn->to_connect == NULL) {
		line = i_stream_next_line(conn->conn.input);
		if (line != NULL) {
			T_BEGIN {
				conn->conn.v.input_line(&conn->conn, line);
			} T_END;
		}
		if (ctx->finished || ctx->failed)
			return NULL;
		if (str_len(ctx->username) > 0)
			return str_c(ctx->username);
	}

	/* wait for more data */
	if (!conn->conn.disconnected)
		connection_input_resume(&conn->conn);
	if (auth_master_request_wait(ctx->req))
		ctx->req = NULL;
	connection_input_halt(&conn->conn);

	if (ctx->finished || ctx->failed)
		return NULL;
	return str_c(ctx->username);
}

const char *auth_master_user_list_next(struct auth_master_user_list_ctx *ctx)
{
	const char *username;

	username = auth_master_user_do_list_next(ctx);
	if (username == NULL)
		return NULL;

	e_debug(ctx->event, "Returned username: %s", username);
	return username;
}

int auth_master_user_list_deinit(struct auth_master_user_list_ctx **_ctx)
{
	struct auth_master_user_list_ctx *ctx = *_ctx;
	struct auth_master_connection *conn = ctx->conn;
	int ret = ctx->failed ? -1 : 0;

	*_ctx = NULL;

	if (ret < 0) {
		struct event_passthrough *e =
			event_create_passthrough(ctx->event)->
			set_name("auth_client_userdb_list_finished");
		e->add_str("error", "Listing users failed");
		e_debug(e->event(), "Listing users failed");
	} else {
		struct event_passthrough *e =
			event_create_passthrough(ctx->event)->
			set_name("auth_client_userdb_list_finished");
		e_debug(e->event(), "Finished listing users");
	}

	auth_master_request_abort(&ctx->req);
	if (!conn->conn.disconnected)
		connection_input_resume(&conn->conn);

	str_free(&ctx->username);
	event_unref(&ctx->event);
	i_free(ctx);
	return ret;
}

/*
 * Auth cache
 */

/* CACHE-FLUSH */

struct auth_master_cache_ctx {
	struct auth_master_connection *conn;
	struct event *event;
	unsigned int count;
	bool failed;
};

static int
auth_cache_flush_reply_callback(const struct auth_master_reply *reply,
				struct auth_master_cache_ctx *ctx)
{
	const char *const *args = reply->args;

	if (reply->errormsg != NULL) {
		ctx->failed = TRUE;
		return 1;
	}
	i_assert(reply->reply != NULL);
	i_assert(args != NULL);

	if (strcmp(reply->reply, "OK") != 0)
		ctx->failed = TRUE;
	else if (args[0] == NULL || str_to_uint(args[0], &ctx->count) < 0)
		ctx->failed = TRUE;

	return 1;
}

int auth_master_cache_flush(struct auth_master_connection *conn,
			    const char *const *users, unsigned int *count_r)
{
	struct auth_master_cache_ctx ctx;
	struct auth_master_request *req;
	string_t *args;

	if (auth_master_connect(conn) < 0)
		return -1;

	i_zero(&ctx);
	ctx.conn = conn;

	args = t_str_new(128);
	if (users != NULL) {
		for (; *users != NULL; users++) {
			if (str_len(args) > 0)
				str_append_c(args, '\t');
			str_append_tabescaped(args, *users);
		}
	}

	ctx.event = event_create(conn->conn.event);
	event_drop_parent_log_prefixes(ctx.event, 1);
	event_set_append_log_prefix(ctx.event, "auth cache flush: ");

	e_debug(ctx.event, "Started cache flush");

	req = auth_master_request(conn, "CACHE-FLUSH",
				  str_data(args), str_len(args),
				  auth_cache_flush_reply_callback, &ctx);
	auth_master_request_set_event(req, ctx.event);
	(void)auth_master_request_wait(req);

	if (ctx.failed)
		e_debug(ctx.event, "Cache flush failed");
	else
		e_debug(ctx.event, "Finished cache flush");
	event_unref(&ctx.event);

	*count_r = ctx.count;
	return ctx.failed ? -1 : 0;
}
