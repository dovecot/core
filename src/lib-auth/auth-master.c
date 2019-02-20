/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "lib-signals.h"
#include "array.h"
#include "ioloop.h"
#include "eacces-error.h"
#include "net.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "strescape.h"
#include "connection.h"
#include "master-interface.h"
#include "auth-master.h"

#include <unistd.h>

#define AUTH_PROTOCOL_MAJOR 1
#define AUTH_PROTOCOL_MINOR 0

#define AUTH_MASTER_IDLE_SECS 60

#define MAX_INBUF_SIZE 8192
#define MAX_OUTBUF_SIZE 1024

static struct event_category event_category_auth_master_client = {
	.name = "auth-master-client"
};

struct auth_master_connection {
	struct connection conn;
	struct connection_list *clist;
	struct event *event_parent, *event;

	char *auth_socket_path;
	enum auth_master_flags flags;

	struct ioloop *ioloop, *prev_ioloop;
	struct timeout *to;

	unsigned int request_counter;

	bool (*reply_callback)(const char *cmd, const char *const *args,
			       void *context);
	void *reply_context;

	unsigned int timeout_msecs;

	bool connected:1;
	bool sent_handshake:1;
	bool aborted:1;
};

struct auth_master_lookup_ctx {
	struct auth_master_connection *conn;
	const char *user;
	const char *expected_reply;
	int return_value;

	pool_t pool;
	const char **fields;
};

struct auth_master_user_list_ctx {
	struct auth_master_connection *conn;
	string_t *username;
	bool finished;
	bool failed;
};

static void auth_master_connected(struct connection *_conn, bool success);
static int
auth_master_input_args(struct connection *_conn, const char *const *args);
static int
auth_master_handshake_line(struct connection *_conn, const char *line);
static int auth_master_input_line(struct connection *_conn, const char *line);
static void auth_master_destroy(struct connection *_conn);

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
	.major_version = AUTH_PROTOCOL_MAJOR,
	.minor_version = AUTH_PROTOCOL_MINOR,
	.unix_client_connect_msecs = 1000,
	.input_max_size = MAX_INBUF_SIZE,
	.output_max_size = MAX_OUTBUF_SIZE,
	.client = TRUE,
};

struct auth_master_connection *
auth_master_init(const char *auth_socket_path, enum auth_master_flags flags)
{
	struct auth_master_connection *conn;

	conn = i_new(struct auth_master_connection, 1);
	conn->auth_socket_path = i_strdup(auth_socket_path);
	conn->flags = flags;
	conn->timeout_msecs = 1000*MASTER_AUTH_LOOKUP_TIMEOUT_SECS;
	conn->clist = connection_list_init(&auth_master_set,
					   &auth_master_vfuncs);

	conn->event_parent = conn->event = event_create(NULL);
	event_add_category(conn->event_parent, &event_category_auth_master_client);
	event_set_append_log_prefix(conn->event_parent, "auth-master: ");
	event_set_forced_debug(conn->event_parent,
			       HAS_ALL_BITS(flags, AUTH_MASTER_FLAG_DEBUG));

	conn->conn.event_parent = conn->event_parent;
	connection_init_client_unix(conn->clist, &conn->conn,
				    conn->auth_socket_path);

	return conn;
}

static void auth_connection_close(struct auth_master_connection *conn)
{
	conn->connected = FALSE;
	connection_disconnect(&conn->conn);

	timeout_remove(&conn->to);

	conn->sent_handshake = FALSE;
}

void auth_master_deinit(struct auth_master_connection **_conn)
{
	struct auth_master_connection *conn = *_conn;
	struct connection_list *clist = conn->clist;

	*_conn = NULL;

	auth_connection_close(conn);
	connection_deinit(&conn->conn);
	connection_list_deinit(&clist);
	event_unref(&conn->event_parent);
	i_free(conn->auth_socket_path);
	i_free(conn);
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

static void auth_request_lookup_abort(struct auth_master_connection *conn)
{
	io_loop_stop(conn->ioloop);
	conn->aborted = TRUE;
}

static void auth_master_destroy(struct connection *_conn)
{
	struct auth_master_connection *conn =
		container_of(_conn, struct auth_master_connection, conn);

	conn->connected = FALSE;
	conn->sent_handshake = FALSE;

	switch (_conn->disconnect_reason) {
	case CONNECTION_DISCONNECT_HANDSHAKE_FAILED:
		break;
	case CONNECTION_DISCONNECT_BUFFER_FULL:
		e_error(conn->event, "BUG: Received more than %d bytes",
			MAX_INBUF_SIZE);
		break;
	default:
		if (!conn->aborted)
			e_error(conn->event, "Disconnected unexpectedly");
	}
	auth_request_lookup_abort(conn);
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
			e_error(conn->event,
				"Auth server sent invalid version line: %s",
				line);
			auth_request_lookup_abort(conn);
			return -1;
		}

		if (connection_verify_version(_conn, "auth-master",
					      major_version,
					      minor_version) < 0) {
			auth_request_lookup_abort(conn);
			return -1;
		}
	} else if (strcmp(tmp[0], "SPID") == 0) {
		return 1;
	}
	return 0;
}

static int
parse_reply(struct auth_master_lookup_ctx *ctx, const char *cmd,
	    const char *const *args)
{
	struct auth_master_connection *conn = ctx->conn;

	if (strcmp(cmd, ctx->expected_reply) == 0)
		return 1;
	if (strcmp(cmd, "NOTFOUND") == 0)
		return 0;
	if (strcmp(cmd, "FAIL") == 0) {
		if (*args == NULL) {
			e_error(conn->event, "Auth %s lookup failed",
				ctx->expected_reply);
		} else {
			e_debug(conn->event,
				"Auth %s lookup returned temporary failure: %s",
				ctx->expected_reply, *args);
		}
		return -2;
	}
	e_error(conn->event, "Unknown reply: %s", cmd);
	return -1;
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

static bool auth_lookup_reply_callback(const char *cmd, const char *const *args,
				       void *context)
{
	struct auth_master_lookup_ctx *ctx = context;
	unsigned int i, len;

	io_loop_stop(ctx->conn->ioloop);

	ctx->return_value = parse_reply(ctx, cmd, args);

	len = str_array_length(args);
	if (ctx->return_value >= 0) {
		ctx->fields = p_new(ctx->pool, const char *, len + 1);
		for (i = 0; i < len; i++)
			ctx->fields[i] = p_strdup(ctx->pool, args[i]);
	} else {
		/* put the reason string into first field */
		ctx->fields = p_new(ctx->pool, const char *, 2);
		for (i = 0; i < len; i++) {
			if (str_begins(args[i], "reason=")) {
				ctx->fields[0] =
					p_strdup(ctx->pool, args[i] + 7);
				break;
			}
		}
	}
	args = args_hide_passwords(args);
	e_debug(ctx->conn->event, "auth %s input: %s",
		ctx->expected_reply, t_strarray_join(args, " "));
	return TRUE;
}

static int
auth_master_input_args(struct connection *_conn, const char *const *args)
{
	struct auth_master_connection *conn =
		container_of(_conn, struct auth_master_connection, conn);
	const char *const *in_args = args;
	const char *cmd, *id, *wanted_id;

	cmd = *args; args++;
	if (*args == NULL)
		id = "";
	else {
		id = *args;
		args++;
	}

	wanted_id = dec2str(conn->request_counter);
	if (strcmp(id, wanted_id) == 0) {
		return (conn->reply_callback(cmd, args, conn->reply_context) ?
			0 : 1);
	}

	if (strcmp(cmd, "CUID") == 0) {
		e_error(conn->event, "%s is an auth client socket. "
			"It should be a master socket.",
			conn->auth_socket_path);
	} else {
		e_error(conn->event, "BUG: Unexpected input: %s",
			t_strarray_join(in_args, "\t"));
	}
	auth_request_lookup_abort(conn);
	return -1;
}

static int auth_master_input_line(struct connection *_conn, const char *line)
{
	struct auth_master_connection *conn =
		container_of(_conn, struct auth_master_connection, conn);
	int ret;

	ret = connection_input_line_default(_conn, line);
	return (io_loop_is_running(conn->ioloop) ? ret : 0);
}

static void auth_master_connected(struct connection *_conn, bool success)
{
	struct auth_master_connection *conn =
		container_of(_conn, struct auth_master_connection, conn);

	/* Cannot get here unless connect() was successful */
	i_assert(success);

	conn->connected = TRUE;
}

static int auth_master_connect(struct auth_master_connection *conn)
{
	i_assert(!conn->connected);

	if (conn->ioloop != NULL)
		connection_switch_ioloop_to(&conn->conn, conn->ioloop);
	if (connection_client_connect(&conn->conn) < 0) {
		if (errno == EACCES) {
			e_error(conn->event,
				"%s", eacces_error_get("connect",
						       conn->auth_socket_path));
		} else {
			e_error(conn->event, "connect(%s) failed: %m",
				conn->auth_socket_path);
		}
		return -1;
	}

	connection_input_halt(&conn->conn);
	return 0;
}

static void auth_request_timeout(struct auth_master_connection *conn)
{
	if (!conn->conn.handshake_received)
		e_error(conn->event, "Connecting timed out");
	else
		e_error(conn->event, "Request timed out");
	auth_request_lookup_abort(conn);
}

static void auth_idle_timeout(struct auth_master_connection *conn)
{
	auth_connection_close(conn);
}

static void auth_master_set_io(struct auth_master_connection *conn)
{
	if (conn->ioloop != NULL)
		return;

	timeout_remove(&conn->to);

	conn->prev_ioloop = current_ioloop;
	conn->ioloop = io_loop_create();
	connection_switch_ioloop_to(&conn->conn, conn->ioloop);
	connection_input_resume(&conn->conn);

	conn->to = timeout_add_to(conn->ioloop, conn->timeout_msecs,
				  auth_request_timeout, conn);
}

static void auth_master_unset_io(struct auth_master_connection *conn)
{
	if (conn->prev_ioloop != NULL) {
		io_loop_set_current(conn->prev_ioloop);
	}
	if (conn->ioloop != NULL) {
		io_loop_set_current(conn->ioloop);
		connection_switch_ioloop_to(&conn->conn, conn->ioloop);
		connection_input_halt(&conn->conn);
		timeout_remove(&conn->to);
		io_loop_destroy(&conn->ioloop);
	}

	if ((conn->flags & AUTH_MASTER_FLAG_NO_IDLE_TIMEOUT) == 0) {
		if (conn->prev_ioloop == NULL)
			auth_connection_close(conn);
		else {
			i_assert(conn->to == NULL);
			conn->to = timeout_add(1000*AUTH_MASTER_IDLE_SECS,
					       auth_idle_timeout, conn);
		}
	}
}

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

static int auth_master_run_cmd_pre(struct auth_master_connection *conn,
				   const char *cmd)
{
	if (!conn->connected) {
		if (auth_master_connect(conn) < 0)
			return -1;
		i_assert(conn->connected);
	}
	auth_master_set_io(conn);

	o_stream_cork(conn->conn.output);
	if (!conn->sent_handshake) {
		const struct connection_settings *set = &conn->conn.list->set;

		o_stream_nsend_str(conn->conn.output,
			t_strdup_printf("VERSION\t%u\t%u\n",
					set->major_version,
					set->minor_version));
		conn->sent_handshake = TRUE;
	}

	o_stream_nsend_str(conn->conn.output, cmd);
	o_stream_uncork(conn->conn.output);

	if (o_stream_flush(conn->conn.output) < 0) {
		e_error(conn->event, "write(auth socket) failed: %s",
			o_stream_get_error(conn->conn.output));
		auth_master_unset_io(conn);
		auth_connection_close(conn);
		return -1;
	}
	return 0;
}

static int auth_master_run_cmd_post(struct auth_master_connection *conn)
{
	auth_master_unset_io(conn);
	if (conn->aborted) {
		conn->aborted = FALSE;
		auth_connection_close(conn);
		return -1;
	}
	return 0;
}

static int auth_master_run_cmd(struct auth_master_connection *conn,
			       const char *cmd)
{
	if (auth_master_run_cmd_pre(conn, cmd) < 0)
		return -1;
	io_loop_run(conn->ioloop);
	return auth_master_run_cmd_post(conn);
}

static unsigned int
auth_master_next_request_id(struct auth_master_connection *conn)
{
	if (++conn->request_counter == 0) {
		/* avoid zero */
		conn->request_counter++;
	}
	return conn->request_counter;
}

static void
auth_user_info_export(string_t *str, const struct auth_user_info *info)
{
	if (info->service != NULL) {
		str_append(str, "\tservice=");
		str_append(str, info->service);
	}

	if (info->local_ip.family != 0)
		str_printfa(str, "\tlip=%s", net_ip2addr(&info->local_ip));
	if (info->local_port != 0)
		str_printfa(str, "\tlport=%d", info->local_port);
	if (info->remote_ip.family != 0)
		str_printfa(str, "\trip=%s", net_ip2addr(&info->remote_ip));
	if (info->remote_port != 0)
		str_printfa(str, "\trport=%d", info->remote_port);
	if (info->debug)
		str_append(str, "\tdebug");
}

static void
auth_master_event_create(struct auth_master_connection *conn,
			 const char *prefix)
{
	i_assert(conn->event == conn->event_parent);
	conn->event = event_create(conn->event_parent);
	event_set_append_log_prefix(conn->event, prefix);
}

static void
auth_master_user_event_create(struct auth_master_connection *conn,
			      const char *prefix,
			      const struct auth_user_info *info)
{
	auth_master_event_create(conn, prefix);

	if (info != NULL) {
		if (info->service != NULL)
			event_add_str(conn->event, "service", info->service);
		if (info->local_ip.family != 0) {
			event_add_str(conn->event, "local_ip",
				      net_ip2addr(&info->local_ip));
		}
		if (info->local_port != 0) {
			event_add_int(conn->event, "local_port",
				      info->local_port);
		}
		if (info->remote_ip.family != 0) {
			event_add_str(conn->event, "remote_ip",
				      net_ip2addr(&info->remote_ip));
		}
		if (info->remote_port != 0) {
			event_add_int(conn->event, "remote_port",
				      info->remote_port);
		}
	}
}

static void
auth_master_event_finish(struct auth_master_connection *conn)
{
	i_assert(conn->event != conn->event_parent);
	event_unref(&conn->event);
	conn->event = conn->event_parent;
}

int auth_master_user_lookup(struct auth_master_connection *conn,
			    const char *user, const struct auth_user_info *info,
			    pool_t pool, const char **username_r,
			    const char *const **fields_r)
{
	struct auth_master_lookup_ctx ctx;
	string_t *str;

	if (!is_valid_string(user) || !is_valid_string(info->service)) {
		/* non-allowed characters, the user can't exist */
		*username_r = NULL;
		*fields_r = NULL;
		return 0;
	}

	i_zero(&ctx);
	ctx.conn = conn;
	ctx.return_value = -1;
	ctx.pool = pool;
	ctx.expected_reply = "USER";
	ctx.user = user;

	conn->reply_callback = auth_lookup_reply_callback;
	conn->reply_context = &ctx;

	str = t_str_new(128);
	str_printfa(str, "USER\t%u\t%s",
		    auth_master_next_request_id(conn), user);
	auth_user_info_export(str, info);
	str_append_c(str, '\n');

	auth_master_user_event_create(
		conn, t_strdup_printf("userdb lookup(%s): ", user), info);
	event_add_str(conn->event, "user", user);

	struct event_passthrough *e =
		event_create_passthrough(conn->event)->
		set_name("auth_client_userdb_lookup_started");
	e_debug(e->event(), "Started userdb lookup");

	(void)auth_master_run_cmd(conn, str_c(str));

	if (ctx.return_value <= 0 || ctx.fields[0] == NULL) {
		*username_r = NULL;
		*fields_r = ctx.fields != NULL ? ctx.fields :
			p_new(pool, const char *, 1);

		struct event_passthrough *e =
			event_create_passthrough(conn->event)->
			set_name("auth_client_userdb_lookup_finished");

		if (ctx.return_value > 0) {
			e->add_str("error", "Lookup didn't return username");
			e_error(e->event(), "Userdb lookup failed: "
				"Lookup didn't return username");
			ctx.return_value = -2;
		} else if ((*fields_r)[0] == NULL) {
			e->add_str("error", "Lookup failed");
			e_debug(e->event(), "Userdb lookup failed");
		} else {
			e->add_str("error", (*fields_r)[0]);
			e_debug(e->event(), "Userdb lookup failed: %s",
				(*fields_r)[0]);
		}
	} else {
		*username_r = ctx.fields[0];
		*fields_r = ctx.fields + 1;

		struct event_passthrough *e =
			event_create_passthrough(conn->event)->
			set_name("auth_client_userdb_lookup_finished");
		e_debug(e->event(), "Finished userdb lookup (username=%s %s)",
			*username_r, t_strarray_join(*fields_r, " "));
	}
	auth_master_event_finish(conn);

	conn->reply_context = NULL;
	return ctx.return_value;
}

void auth_user_fields_parse(const char *const *fields, pool_t pool,
			    struct auth_user_reply *reply_r)
{
	i_zero(reply_r);
	reply_r->uid = (uid_t)-1;
	reply_r->gid = (gid_t)-1;
	p_array_init(&reply_r->extra_fields, pool, 64);

	for (; *fields != NULL; fields++) {
		if (str_begins(*fields, "uid=")) {
			if (str_to_uid(*fields + 4, &reply_r->uid) < 0)
				i_error("Invalid uid in reply");
		} else if (str_begins(*fields, "gid=")) {
			if (str_to_gid(*fields + 4, &reply_r->gid) < 0)
				i_error("Invalid gid in reply");
		} else if (str_begins(*fields, "home="))
			reply_r->home = p_strdup(pool, *fields + 5);
		else if (str_begins(*fields, "chroot="))
			reply_r->chroot = p_strdup(pool, *fields + 7);
		else if (strcmp(*fields, "anonymous") == 0)
			reply_r->anonymous = TRUE;
		else {
			const char *field = p_strdup(pool, *fields);
			array_push_back(&reply_r->extra_fields, &field);
		}
	}
}

int auth_master_pass_lookup(struct auth_master_connection *conn,
			    const char *user, const struct auth_user_info *info,
			    pool_t pool, const char *const **fields_r)
{
	struct auth_master_lookup_ctx ctx;
	string_t *str;

	if (!is_valid_string(user) || !is_valid_string(info->service)) {
		/* non-allowed characters, the user can't exist */
		*fields_r = NULL;
		return 0;
	}

	i_zero(&ctx);
	ctx.conn = conn;
	ctx.return_value = -1;
	ctx.pool = pool;
	ctx.expected_reply = "PASS";
	ctx.user = user;

	conn->reply_callback = auth_lookup_reply_callback;
	conn->reply_context = &ctx;

	str = t_str_new(128);
	str_printfa(str, "PASS\t%u\t%s",
		    auth_master_next_request_id(conn), user);
	auth_user_info_export(str, info);
	str_append_c(str, '\n');

	auth_master_user_event_create(
		conn, t_strdup_printf("passdb lookup(%s): ", user), info);
	event_add_str(conn->event, "user", user);

	struct event_passthrough *e =
		event_create_passthrough(conn->event)->
		set_name("auth_client_passdb_lookup_started");
	e_debug(e->event(), "Started passdb lookup");

	(void)auth_master_run_cmd(conn, str_c(str));

	*fields_r = ctx.fields != NULL ? ctx.fields :
		p_new(pool, const char *, 1);

	if (ctx.return_value <= 0) {
		struct event_passthrough *e =
			event_create_passthrough(conn->event)->
			set_name("auth_client_passdb_lookup_finished");
		if ((*fields_r)[0] == NULL) {
			e->add_str("error", "Lookup failed");
			e_debug(e->event(), "Passdb lookup failed");
		} else {
			e->add_str("error", (*fields_r)[0]);
			e_debug(e->event(), "Passdb lookup failed: %s",
				(*fields_r)[0]);
		}
	} else {
		struct event_passthrough *e =
			event_create_passthrough(conn->event)->
			set_name("auth_client_passdb_lookup_finished");
		e_debug(e->event(), "Finished passdb lookup (%s)",
			t_strarray_join(*fields_r, " "));
	}
	auth_master_event_finish(conn);

	conn->reply_context = NULL;
	return ctx.return_value;
}

struct auth_master_cache_ctx {
	struct auth_master_connection *conn;
	unsigned int count;
	bool failed;
};

static bool
auth_cache_flush_reply_callback(const char *cmd, const char *const *args,
				void *context)
{
	struct auth_master_cache_ctx *ctx = context;

	if (strcmp(cmd, "OK") != 0)
		ctx->failed = TRUE;
	else if (args[0] == NULL || str_to_uint(args[0], &ctx->count) < 0)
		ctx->failed = TRUE;

	io_loop_stop(ctx->conn->ioloop);
	return TRUE;
}

int auth_master_cache_flush(struct auth_master_connection *conn,
			    const char *const *users, unsigned int *count_r)
{
	struct auth_master_cache_ctx ctx;
	string_t *str;

	i_zero(&ctx);
	ctx.conn = conn;

	conn->reply_callback = auth_cache_flush_reply_callback;
	conn->reply_context = &ctx;

	str = t_str_new(128);
	str_printfa(str, "CACHE-FLUSH\t%u", auth_master_next_request_id(conn));
	if (users != NULL) {
		for (; *users != NULL; users++) {
			str_append_c(str, '\t');
			str_append_tabescaped(str, *users);
		}
	}
	str_append_c(str, '\n');

	auth_master_event_create(conn, "auth cache flush: ");

	struct event_passthrough *e =
		event_create_passthrough(conn->event)->
		set_name("auth_client_cache_flush_started");
	e_debug(e->event(), "Started cache flush");

	(void)auth_master_run_cmd(conn, str_c(str));

	if (ctx.failed) {
		struct event_passthrough *e =
			event_create_passthrough(conn->event)->
			set_name("auth_client_cache_flush_finished");
		e->add_str("error", "Cache flush failed");
		e_debug(e->event(), "Cache flush failed");
	} else {
		struct event_passthrough *e =
			event_create_passthrough(conn->event)->
			set_name("auth_client_cache_flush_finished");
		e_debug(e->event(), "Finished cache flush");
	}
	auth_master_event_finish(conn);

	conn->reply_context = NULL;
	*count_r = ctx.count;
	return ctx.failed ? -1 : 0;
}

static bool
auth_user_list_reply_callback(const char *cmd, const char *const *args,
			      void *context)
{
	struct auth_master_user_list_ctx *ctx = context;
	struct auth_master_connection *conn = ctx->conn;

	timeout_reset(ctx->conn->to);
	io_loop_stop(ctx->conn->ioloop);

	if (strcmp(cmd, "DONE") == 0) {
		if (args[0] != NULL && strcmp(args[0], "fail") == 0) {
			e_error(conn->event, "User listing returned failure");
			ctx->failed = TRUE;
		}
		ctx->finished = TRUE;
	} else if (strcmp(cmd, "LIST") == 0 && args[0] != NULL) {
		/* we'll just read all the users into memory. otherwise we'd
		   have to use a separate connection for listing and there's
		   a higher chance of a failure since the connection could be
		   open to dovecot-auth for a long time. */
		str_append(ctx->username, args[0]);
	} else {
		e_error(conn->event, "User listing returned invalid input");
		ctx->failed = TRUE;
	}
	return FALSE;
}

struct auth_master_user_list_ctx *
auth_master_user_list_init(struct auth_master_connection *conn,
			   const char *user_mask,
			   const struct auth_user_info *info)
{
	struct auth_master_user_list_ctx *ctx;
	string_t *str;

	ctx = i_new(struct auth_master_user_list_ctx, 1);
	ctx->conn = conn;
	ctx->username = str_new(default_pool, 128);

	conn->reply_callback = auth_user_list_reply_callback;
	conn->reply_context = ctx;

	str = t_str_new(128);
	str_printfa(str, "LIST\t%u",
		    auth_master_next_request_id(conn));
	if (*user_mask != '\0')
		str_printfa(str, "\tuser=%s", user_mask);
	if (info != NULL)
		auth_user_info_export(str, info);
	str_append_c(str, '\n');

	auth_master_user_event_create(conn, "userdb list: ", info);

	struct event_passthrough *e =
		event_create_passthrough(conn->event)->
		set_name("auth_client_userdb_list_started");
	e_debug(e->event(), "Started listing users (user_mask=%s)", user_mask);

	if (auth_master_run_cmd_pre(conn, str_c(str)) < 0)
		ctx->failed = TRUE;
	if (conn->prev_ioloop != NULL)
		io_loop_set_current(conn->prev_ioloop);

	return ctx;
}

static const char *
auth_master_user_do_list_next(struct auth_master_user_list_ctx *ctx)
{
	struct auth_master_connection *conn = ctx->conn;
	const char *line;

	if (!conn->connected)
		return NULL;

	str_truncate(ctx->username, 0);

	/* try to read already buffered input */
	line = i_stream_next_line(conn->conn.input);
	if (line != NULL) {
		T_BEGIN {
			conn->conn.v.input_line(&conn->conn, line);
		} T_END;
	}
	if (conn->aborted)
		ctx->failed = TRUE;
	if (ctx->finished || ctx->failed)
		return NULL;
	if (str_len(ctx->username) > 0)
		return str_c(ctx->username);

	/* wait for more data */
	io_loop_set_current(conn->ioloop);
	i_stream_set_input_pending(conn->conn.input, TRUE);
	io_loop_run(conn->ioloop);
	io_loop_set_current(conn->prev_ioloop);

	if (conn->aborted)
		ctx->failed = TRUE;
	if (ctx->finished || ctx->failed)
		return NULL;
	return str_c(ctx->username);
}

const char *auth_master_user_list_next(struct auth_master_user_list_ctx *ctx)
{
	struct auth_master_connection *conn = ctx->conn;
	const char *username;

	username = auth_master_user_do_list_next(ctx);
	if (username == NULL)
		return NULL;

	e_debug(conn->event, "Returned username: %s", username);
	return username;
}

int auth_master_user_list_deinit(struct auth_master_user_list_ctx **_ctx)
{
	struct auth_master_user_list_ctx *ctx = *_ctx;
	struct auth_master_connection *conn = ctx->conn;
	int ret = ctx->failed ? -1 : 0;

	*_ctx = NULL;
	auth_master_run_cmd_post(ctx->conn);

	if (ret < 0) {
		struct event_passthrough *e =
			event_create_passthrough(conn->event)->
			set_name("auth_client_userdb_list_finished");
		e->add_str("error", "Listing users failed");
		e_debug(e->event(), "Listing users failed");
	} else {
		struct event_passthrough *e =
			event_create_passthrough(conn->event)->
			set_name("auth_client_userdb_list_finished");
		e_debug(e->event(), "Finished listing users");
	}
	auth_master_event_finish(conn);

	str_free(&ctx->username);
	i_free(ctx);
	return ret;
}
