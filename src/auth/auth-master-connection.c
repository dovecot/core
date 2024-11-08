/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "buffer.h"
#include "connection.h"
#include "str.h"
#include "strescape.h"
#include "str-sanitize.h"
#include "time-util.h"
#include "hostpid.h"
#include "hex-binary.h"
#include "ioloop.h"
#include "ostream.h"
#include "wildcard-match.h"
#include "ipwd.h"
#include "master-service.h"
#include "userdb.h"
#include "userdb-blocking.h"
#include "passdb-cache.h"
#include "auth-request-handler.h"
#include "auth-client-connection.h"
#include "auth-master-connection.h"

#include <sys/stat.h>
#include <unistd.h>

#define MAX_INBUF_SIZE 1024
#define MAX_OUTBUF_SIZE (1024 * 50)

struct master_userdb_request {
	struct auth_master_connection *conn;
	struct auth_request *auth_request;
};

struct master_list_iter_ctx {
	struct auth_master_connection *conn;
	struct userdb_iterate_context *iter;
	struct auth_request *auth_request;
	bool failed;
};

static void auth_master_connection_destroy(struct connection *conn);

static struct connection_list *auth_master_connections = NULL;

static const char *
auth_master_reply_hide_passwords(struct auth_master_connection *conn,
				 const char *str)
{
	char **args, *p, *p2;
	unsigned int i;

	if (conn->auth->protocol_set->debug_passwords)
		return str;

	/* hide all parameters that have "pass" in their key */
	args = p_strsplit(pool_datastack_create(), str, "\t");
	for (i = 0; args[i] != NULL; i++) {
		p = strstr(args[i], "pass");
		p2 = strchr(args[i], '=');
		if (p != NULL && p < p2) {
			*p2 = '\0';
			args[i] = p_strconcat(pool_datastack_create(), args[i],
					      "=<hidden>", NULL);
		}
	}
	return t_strarray_join((void *)args, "\t");
}

void auth_master_request_callback(const char *reply,
				  struct auth_master_connection *conn)
{
	if (conn->destroyed)
		return;

	e_debug(auth_event, "master userdb out: %s",
		auth_master_reply_hide_passwords(conn, reply));

	const struct const_iovec iov[] = {
		{ .iov_base = reply, .iov_len = strlen(reply) },
		{ .iov_base = "\n", .iov_len = 1 },
	};

	o_stream_nsendv(conn->conn.output, iov, N_ELEMENTS(iov));
}

static const char *
auth_master_event_log_callback(struct auth_master_connection *conn,
			       enum log_type log_type ATTR_UNUSED,
			       const char *message)
{
	string_t *str = t_str_new(128);

	str_printfa(str, "auth-master client: %s (created %lld msecs ago",
		    message,
		    timeval_diff_msecs(&ioloop_timeval, &conn->conn.connect_finished));
	if (conn->conn.handshake_finished.tv_sec != 0) {
		str_printfa(str, ", handshake %lld msecs ago",
			    timeval_diff_msecs(&ioloop_timeval,
					       &conn->conn.handshake_finished));
	}
	str_append_c(str, ')');
	return str_c(str);
}

static int master_input_request(struct auth_master_connection *conn,
				 const char *const *args)
{
	struct auth_client_connection *client_conn;
	const char *const *params;
	unsigned int id, client_pid, client_id;
	uint8_t cookie[LOGIN_REQUEST_COOKIE_SIZE];
	buffer_t buf;

	/* <id> <client-pid> <client-id> <cookie> [<parameters>] */
	if (str_array_length(args) < 4 || str_to_uint(args[0], &id) < 0 ||
	    str_to_uint(args[1], &client_pid) < 0 ||
	    str_to_uint(args[2], &client_id) < 0) {
		e_error(conn->conn.event, "BUG: Master sent broken REQUEST");
		return -1;
	}

	buffer_create_from_data(&buf, cookie, sizeof(cookie));
	if (strlen(args[3]) != sizeof(cookie) * 2 ||
	    hex_to_binary(args[3], &buf) < 0) {
		e_error(conn->conn.event, "BUG: Master sent broken REQUEST cookie");
		return -1;
	}
	params = args + 4;

	client_conn = auth_client_connection_lookup(client_pid);
	if (client_conn == NULL) {
		e_error(conn->conn.event,
			"Master requested auth for nonexistent client %u",
			client_pid);
		o_stream_nsend_str(conn->conn.output,
				   t_strdup_printf("FAIL\t%u\n", id));
	} else if (!mem_equals_timing_safe(client_conn->cookie, cookie,
					   sizeof(cookie))) {
		e_error(conn->conn.event,
			"Master requested auth for client %u with invalid cookie",
			client_pid);
		o_stream_nsend_str(conn->conn.output,
				   t_strdup_printf("FAIL\t%u\n", id));
	} else if (!auth_request_handler_master_request(
			   client_conn->request_handler, conn, id, client_id,
			   params)) {
		e_error(conn->conn.event,
			"Master requested auth for non-login client %u",
			client_pid);
		o_stream_nsend_str(conn->conn.output,
				   t_strdup_printf("FAIL\t%u\n", id));
	}
	return 1;
}

static int master_input_cache_flush(struct auth_master_connection *conn,
				     const char *const *args)
{
	unsigned int count;

	/* <id> [<user> [<user> [..]] */
	if (args[0] == NULL) {
		e_error(conn->conn.event, "BUG: doveadm sent broken CACHE-FLUSH");
		return -1;
	}

	if (passdb_cache == NULL) {
		/* cache disabled */
		count = 0;
	} else if (args[1] == NULL) {
		/* flush the whole cache */
		count = auth_cache_clear(passdb_cache);
	} else {
		count = auth_cache_clear_users(passdb_cache, args + 1);
	}
	o_stream_nsend_str(conn->conn.output,
			   t_strdup_printf("OK\t%s\t%u\n", args[0], count));
	return 1;
}

static int master_input_auth_request(struct auth_master_connection *conn,
				     const char *const *args, const char *cmd,
				     struct auth_request **request_r,
				     const char **error_r)
{
	struct auth_request *auth_request;
	const char *name, *arg, *username;
	unsigned int id;

	/* <id> <userid> [<parameters>] */
	if (args[0] == NULL || args[1] == NULL ||
	    str_to_uint(args[0], &id) < 0) {
		e_error(conn->conn.event, "BUG: Master sent broken %s", cmd);
		return -1;
	}

	auth_request = auth_request_new_dummy(auth_event);
	auth_request->id = id;
	auth_request->master = conn;
	auth_master_connection_ref(conn);
	username = args[1];

	for (args += 2; *args != NULL; args++) {
		arg = strchr(*args, '=');
		if (arg == NULL) {
			name = *args;
			arg = "";
		} else {
			name = t_strdup_until(*args, arg);
			arg++;
		}

		(void)auth_request_import_info(auth_request, name, arg);
	}

	if (auth_request->fields.protocol == NULL) {
		e_error(conn->conn.event,
			"BUG: Master sent %s request without protocol", cmd);
		auth_request_unref(&auth_request);
		auth_master_connection_unref(&conn);
		return -1;
	}

	auth_request_init(auth_request);

	if (!auth_request_set_username(auth_request, username, error_r)) {
		*request_r = auth_request;
		return 0;
	}
	*request_r = auth_request;
	return 1;
}

static int user_verify_restricted_uid(struct auth_request *auth_request)
{
	struct auth_master_connection *conn = auth_request->master;
	struct auth_fields *reply = auth_request->fields.userdb_reply;
	const char *value, *reason;
	uid_t uid;

	if (conn->userdb_restricted_uid == 0)
		return 0;

	value = auth_fields_find(reply, "uid");
	if (value == NULL)
		reason = "userdb reply doesn't contain uid";
	else if (str_to_uid(value, &uid) < 0)
		reason = "userdb reply contains invalid uid";
	else if (uid != conn->userdb_restricted_uid) {
		reason = t_strdup_printf(
			"userdb uid (%s) doesn't match peer uid (%s)",
			dec2str(uid), dec2str(conn->userdb_restricted_uid));
	} else {
		return 0;
	}

	e_error(auth_request->event,
		"userdb: "
		"client doesn't have lookup permissions for this user: %s "
		"(to bypass this check, set: service auth { unix_listener %s { mode=0777 } })",
		reason, conn->conn.base_name);
	return -1;
}

static void user_callback(enum userdb_result result,
			  struct auth_request *auth_request)
{
	struct auth_master_connection *conn = auth_request->master;
	string_t *str;
	const char *value;

	if (auth_request->userdb_lookup_tempfailed)
		result = USERDB_RESULT_INTERNAL_FAILURE;

	if (result == USERDB_RESULT_OK) {
		if (user_verify_restricted_uid(auth_request) < 0)
			result = USERDB_RESULT_INTERNAL_FAILURE;
	}

	str = t_str_new(128);
	switch (result) {
	case USERDB_RESULT_INTERNAL_FAILURE:
		str_printfa(str, "FAIL\t%u", auth_request->id);
		if (auth_request->userdb_lookup_tempfailed) {
			value = auth_fields_find(
				auth_request->fields.userdb_reply, "reason");
			if (value != NULL)
				str_printfa(str, "\treason=%s", value);
		}
		break;
	case USERDB_RESULT_USER_UNKNOWN:
		str_printfa(str, "NOTFOUND\t%u", auth_request->id);
		break;
	case USERDB_RESULT_OK:
		str_printfa(str, "USER\t%u\t", auth_request->id);
		str_append_tabescaped(str, auth_request->fields.user);
		if (auth_request->fields.local_name != NULL) {
			str_append(str, "\tlocal_name=");
			str_append_tabescaped(str,
					      auth_request->fields.local_name);
			str_append_c(str, '\t');
		}
		auth_fields_append(auth_request->fields.userdb_reply, str,
				   AUTH_FIELD_FLAG_HIDDEN, 0, TRUE);
		if (*auth_request->set->anonymous_username != '\0' &&
		    strcmp(auth_request->fields.user,
			   auth_request->set->anonymous_username) == 0) {
			/* this is an anonymous login, either via ANONYMOUS
			   SASL mechanism or simply logging in as the anonymous
			   user via another mechanism */
			str_append(str, "\tanonymous");
		}
		break;
	}

	e_debug(auth_event, "userdb out: %s",
		auth_master_reply_hide_passwords(conn, str_c(str)));

	str_append_c(str, '\n');
	o_stream_nsend(conn->conn.output, str_data(str), str_len(str));

	auth_request_unref(&auth_request);
	auth_master_connection_unref(&conn);
}

static int master_input_user(struct auth_master_connection *conn,
			      const char *const *args)
{
	struct auth_request *auth_request;
	const char *error;
	int ret;

	ret = master_input_auth_request(conn, args, "USER", &auth_request,
					&error);
	if (ret <= 0) {
		if (ret < 0)
			return -1;
		e_info(auth_request->event, "userdb: %s", error);
		user_callback(USERDB_RESULT_USER_UNKNOWN, auth_request);
	} else {
		auth_request_set_state(auth_request, AUTH_REQUEST_STATE_USERDB);
		auth_request_lookup_user(auth_request, user_callback);
	}
	return 1;
}

static void pass_callback_finish(struct auth_request *auth_request,
				 enum passdb_result result)
{
	struct auth_master_connection *conn = auth_request->master;
	string_t *str;

	str = t_str_new(128);
	switch (result) {
	case PASSDB_RESULT_OK:
		if (auth_request->failed || !auth_request->passdb_success) {
			str_printfa(str, "FAIL\t%u", auth_request->id);
			break;
		}
		str_printfa(str, "PASS\t%u\tuser=", auth_request->id);
		str_append_tabescaped(str, auth_request->fields.user);
		auth_fields_append(auth_request->fields.extra_fields, str,
				   AUTH_FIELD_FLAG_HIDDEN, 0, TRUE);
		break;
	case PASSDB_RESULT_USER_UNKNOWN:
	case PASSDB_RESULT_USER_DISABLED:
	case PASSDB_RESULT_PASS_EXPIRED:
		str_printfa(str, "NOTFOUND\t%u", auth_request->id);
		break;
	case PASSDB_RESULT_NEXT:
	case PASSDB_RESULT_PASSWORD_MISMATCH:
	case PASSDB_RESULT_INTERNAL_FAILURE:
		str_printfa(str, "FAIL\t%u", auth_request->id);
		break;
	case PASSDB_RESULT_SCHEME_NOT_AVAILABLE:
		str_printfa(
			str,
			"FAIL\t%u\treason=Configured passdbs don't support credentials lookups",
			auth_request->id);
		break;
	}

	e_debug(auth_event, "passdb out: %s", str_c(str));

	str_append_c(str, '\n');
	o_stream_nsend(conn->conn.output, str_data(str), str_len(str));

	auth_request_unref(&auth_request);
	auth_master_connection_unref(&conn);
}

static void auth_master_pass_proxy_finish(bool success,
					  struct auth_request *auth_request)
{
	pass_callback_finish(auth_request,
			     success ? PASSDB_RESULT_OK :
					     PASSDB_RESULT_INTERNAL_FAILURE);
}

static void pass_callback(enum passdb_result result,
			  const unsigned char *credentials ATTR_UNUSED,
			  size_t size ATTR_UNUSED,
			  struct auth_request *auth_request)
{
	int ret;

	if (result != PASSDB_RESULT_OK)
		auth_request_proxy_finish_failure(auth_request);
	else {
		ret = auth_request_proxy_finish(auth_request,
						auth_master_pass_proxy_finish);
		if (ret == 0)
			return;
		if (ret < 0)
			result = PASSDB_RESULT_INTERNAL_FAILURE;
	}
	pass_callback_finish(auth_request, result);
}

static const char *auth_restricted_reason(struct auth_master_connection *conn)
{
	struct passwd pw;
	const char *namestr;

	if (i_getpwuid(conn->userdb_restricted_uid, &pw) <= 0)
		namestr = "";
	else
		namestr = t_strdup_printf("(%s)", pw.pw_name);
	return t_strdup_printf("%s mode=0666, but not owned by UID %lu%s",
			       conn->conn.base_name,
			       (unsigned long)conn->userdb_restricted_uid,
			       namestr);
}

static int master_input_pass(struct auth_master_connection *conn,
			      const char *const *args)
{
	struct auth_request *auth_request;
	const char *error;
	int ret;

	ret = master_input_auth_request(conn, args, "PASS", &auth_request,
					&error);
	if (ret <= 0) {
		if (ret < 0)
			return -1;
		e_info(auth_request->event, "passdb: %s", error);
		pass_callback(PASSDB_RESULT_USER_UNKNOWN, uchar_empty_ptr, 0,
			      auth_request);
	} else if (conn->userdb_restricted_uid != 0) {
		/* no permissions to do this lookup */
		e_error(auth_request->event,
			"passdb: "
			"Auth client doesn't have permissions to do "
			"a PASS lookup: %s",
			auth_restricted_reason(conn));
		pass_callback(PASSDB_RESULT_INTERNAL_FAILURE, uchar_empty_ptr,
			      0, auth_request);
	} else {
		auth_request_set_state(auth_request,
				       AUTH_REQUEST_STATE_MECH_CONTINUE);
		auth_request_lookup_credentials(auth_request, "",
						pass_callback);
	}
	return 1;
}

static void master_input_list_finish(struct master_list_iter_ctx *ctx)
{
	i_assert(ctx->conn->iter_ctx == ctx);

	ctx->conn->iter_ctx = NULL;
	connection_input_resume(&ctx->conn->conn);

	if (ctx->iter != NULL)
		(void)userdb_blocking_iter_deinit(&ctx->iter);
	o_stream_uncork(ctx->conn->conn.output);
	o_stream_unset_flush_callback(ctx->conn->conn.output);
	auth_request_unref(&ctx->auth_request);
	auth_master_connection_unref(&ctx->conn);
	i_free(ctx);
}

static int master_output_list(struct master_list_iter_ctx *ctx)
{
	int ret;

	if ((ret = o_stream_flush(ctx->conn->conn.output)) < 0) {
		master_input_list_finish(ctx);
		return 1;
	}
	if (ret > 0) {
		o_stream_cork(ctx->conn->conn.output);
		userdb_blocking_iter_next(ctx->iter);
	}
	return 1;
}

static int match_user(const char *user, struct auth_request *request, bool *match_r)
{
	struct auth_userdb *db = request->userdb;
	const char *mask = request->fields.user;

	if (*db->auth_set->username_format != '\0') {
		/* normalize requested mask to match userdb */
		string_t *dest = t_str_new(32);
		const char *error;
		if (auth_request_var_expand(dest, db->auth_set->username_format,
					    request, NULL, &error) < 0) {
			e_error(authdb_event(request), "Iteration failed: %s",
				error);
			return -1;
		}
		mask = str_c(dest);
	}

	*match_r = wildcard_match_icase(user, mask);
	return 0;
}

static void master_input_list_callback(const char *user, void *context)
{
	struct master_list_iter_ctx *ctx = context;
	struct auth_userdb *userdb = ctx->auth_request->userdb;
	int ret = 0;

	if (user == NULL || ctx->failed) {
		if (userdb_blocking_iter_deinit(&ctx->iter) < 0)
			ctx->failed = TRUE;

		do {
			userdb = userdb->next;
		} while (userdb != NULL &&
			 userdb->userdb->iface->iterate_init == NULL);
		if (userdb == NULL || ctx->failed) {
			/* iteration is finished */
			const char *str;

			str = t_strdup_printf("DONE\t%u\t%s\n",
					      ctx->auth_request->id,
					      ctx->failed ? "fail" : "");
			o_stream_nsend_str(ctx->conn->conn.output, str);
			master_input_list_finish(ctx);
			return;
		}

		/* continue iterating next userdb */
		ctx->auth_request->userdb = userdb;
		ctx->iter = userdb_blocking_iter_init(
			ctx->auth_request, master_input_list_callback, ctx);
		return;
	}

	T_BEGIN {
		const char *str;
		bool match;
		if (match_user(user, ctx->auth_request, &match) < 0)
			ctx->failed = TRUE;
		else if (match) {
			str = t_strdup_printf("LIST\t%u\t%s\n", ctx->auth_request->id,
					      str_tabescape(user));
			ret = o_stream_send_str(ctx->conn->conn.output, str);
		}
	} T_END;
	if (o_stream_get_buffer_used_size(ctx->conn->conn.output) >= MAX_OUTBUF_SIZE)
		ret = o_stream_flush(ctx->conn->conn.output);
	if (ret < 0) {
		/* disconnected, don't bother finishing */
		master_input_list_finish(ctx);
		return;
	}
	if (o_stream_get_buffer_used_size(ctx->conn->conn.output) < MAX_OUTBUF_SIZE)
		userdb_blocking_iter_next(ctx->iter);
	else
		o_stream_uncork(ctx->conn->conn.output);
}

static int master_input_list(struct auth_master_connection *conn,
			      const char *const *args)
{
	struct auth_userdb *userdb = conn->auth->userdbs;
	struct auth_request *auth_request;
	struct master_list_iter_ctx *ctx;
	const char *str, *name, *arg;
	unsigned int id;

	/* <id> [<parameters>] */
	if (args[0] == NULL || str_to_uint(args[0], &id) < 0) {
		e_error(conn->conn.event, "BUG: Master sent broken LIST");
		return -1;
	}
	args++;

	if (conn->iter_ctx != NULL) {
		e_error(conn->conn.event, "Auth client is already iterating users");
		str = t_strdup_printf("DONE\t%u\tfail\n", id);
		o_stream_nsend_str(conn->conn.output, str);
		return 1;
	}

	if (conn->userdb_restricted_uid != 0) {
		e_error(conn->conn.event,
			"Auth client doesn't have permissions to list users: %s",
			auth_restricted_reason(conn));
		str = t_strdup_printf("DONE\t%u\tfail\n", id);
		o_stream_nsend_str(conn->conn.output, str);
		return 1;
	}

	while (userdb != NULL && userdb->userdb->iface->iterate_init == NULL)
		userdb = userdb->next;
	if (userdb == NULL) {
		e_error(conn->conn.event,
			"Trying to iterate users, but userdbs don't support it");
		str = t_strdup_printf("DONE\t%u\tfail\n", id);
		o_stream_nsend_str(conn->conn.output, str);
		return 1;
	}

	auth_request = auth_request_new_dummy(auth_event);
	auth_request->id = id;
	auth_request->master = conn;
	auth_master_connection_ref(conn);

	for (; *args != NULL; args++) {
		arg = strchr(*args, '=');
		if (arg == NULL) {
			name = *args;
			arg = "";
		} else {
			name = t_strdup_until(*args, arg);
			arg++;
		}

		if (!auth_request_import_info(auth_request, name, arg) &&
		    strcmp(name, "user") == 0) {
			/* username mask */
			auth_request_set_username_forced(auth_request, arg);
		}
	}

	/* rest of the code doesn't like NULL user or service */
	if (auth_request->fields.user == NULL)
		auth_request_set_username_forced(auth_request, "");
	if (auth_request->fields.protocol == NULL) {
		if (!auth_request_import(auth_request, "protocol", ""))
			i_unreached();
		i_assert(auth_request->fields.protocol != NULL);
	}

	ctx = i_new(struct master_list_iter_ctx, 1);
	ctx->conn = conn;
	ctx->auth_request = auth_request;
	ctx->auth_request->userdb = userdb;
	connection_input_halt(&ctx->conn->conn);
	o_stream_set_flush_callback(conn->conn.output, master_output_list, ctx);
	ctx->iter = userdb_blocking_iter_init(auth_request,
					      master_input_list_callback, ctx);
	conn->iter_ctx = ctx;
	return 1;
}

static int auth_master_input_args(struct connection *_conn,
				   const char *const *args)
{
	struct auth_master_connection *conn =
		container_of(_conn, struct auth_master_connection, conn);

	e_debug(auth_event, "master in: %s", t_strarray_join(args, "\t"));

	if (strcmp(args[0], "USER") == 0)
		return master_input_user(conn, args + 1);
	if (strcmp(args[0], "LIST") == 0)
		return master_input_list(conn, args + 1);
	if (strcmp(args[0], "PASS") == 0)
		return master_input_pass(conn, args + 1);

	if (!conn->userdb_only) {
		i_assert(conn->userdb_restricted_uid == 0);
		if (strcmp(args[0], "REQUEST") == 0)
			return master_input_request(conn, args + 1);
		if (strcmp(args[0], "CACHE-FLUSH") == 0)
			return master_input_cache_flush(conn, args + 1);
		if (strcmp(args[0], "CPID") == 0) {
			e_error(_conn->event,
				"Authentication client trying to connect to "
				"master socket");
			return -1;
		}
	}

	e_error(_conn->event, "BUG: Unknown command in %s socket: %s",
		conn->userdb_only ? "userdb" : "master",
		str_sanitize(args[0], 80));
	return -1;
}

static int auth_master_handshake_args(struct connection *conn,
				      const char *const *args)
{
	i_assert(!conn->version_received);
	if (strcmp(args[0], "VERSION") == 0) {
		unsigned int major_version, minor_version;

		/* VERSION <tab> service_name <tab> major version <tab> minor version */
		if (str_array_length(args) != 3 ||
		    strcmp(args[0], "VERSION") != 0 ||
		    str_to_uint(args[1], &major_version) < 0 ||
		    str_to_uint(args[2], &minor_version) < 0) {
			e_error(conn->event, "didn't reply with a valid VERSION line: %s",
				t_strarray_join(args, "\t"));
		} else if (major_version != conn->list->set.major_version) {
			e_error(conn->event, "Socket supports major version %u, "
				"but we support only %u (mixed old and new binaries?)",
				major_version, conn->list->set.major_version);
		} else {
			conn->minor_version = minor_version;
			conn->version_received = TRUE;
			return 1;
		}
	} else {
		e_error(conn->event, "BUG: Authentication client sent unknown handshake command %s",
			args[0]);
	}
	return -1;
}

static const struct connection_vfuncs auth_master_connection_vfuncs = {
	.input_args = auth_master_input_args,
	.handshake_args = auth_master_handshake_args,
	.destroy = auth_master_connection_destroy,
};

static const struct connection_settings auth_master_connection_set = {
	.service_name_in = "auth-master",
	.service_name_out = "auth-master",
	.major_version = AUTH_CLIENT_PROTOCOL_MAJOR_VERSION,
	.minor_version = AUTH_CLIENT_PROTOCOL_MINOR_VERSION,
	.dont_send_version = TRUE,
	.input_max_size = MAX_INBUF_SIZE,
	.output_max_size = SIZE_MAX,
	.output_throttle_size = MAX_OUTBUF_SIZE,
};

static int
auth_master_connection_set_permissions(struct auth_master_connection *conn,
				       const struct stat *st)
{
	if (st == NULL)
		return 0;

	/* figure out what permissions we want to give to this client */
	if ((st->st_mode & 0777) != 0666) {
		/* permissions were already restricted by the socket
		   permissions. also +x bit indicates that we shouldn't do
		   any permission checks. */
		return 0;
	}

	connection_update_properties(&conn->conn);
	if (!conn->conn.have_unix_credentials) {
		e_error(conn->conn.event,
			"userdb connection: Failed to get peer's credentials");
		return -1;
	}

	if (conn->conn.remote_uid == st->st_uid || conn->conn.remote_gid == st->st_gid) {
		/* full permissions */
		return 0;
	} else {
		/* restrict permissions: return only lookups whose returned
		   uid matches the peer's uid */
		conn->userdb_restricted_uid = conn->conn.remote_uid;
		return 0;
	}
}

struct auth_master_connection *
auth_master_connection_create(struct auth *auth, int fd, const char *path,
			      const struct stat *socket_st, bool userdb_only)
{
	struct auth_master_connection *conn;
	const char *line;

	i_assert(path != NULL);

	if (auth_master_connections == NULL) {
		auth_master_connections =
			connection_list_init(&auth_master_connection_set,
					     &auth_master_connection_vfuncs);
	}

	conn = i_new(struct auth_master_connection, 1);
	conn->refcount = 1;
	conn->conn.event_parent = auth_event;
	conn->auth = auth;
	conn->userdb_only = userdb_only;

	connection_init_server(auth_master_connections, &conn->conn, path,
			       fd, fd);

	event_set_log_message_callback(conn->conn.event,
				       auth_master_event_log_callback, conn);

	line = t_strdup_printf("VERSION\t%u\t%u\nSPID\t%s\n",
			       conn->conn.list->set.major_version,
			       conn->conn.list->set.minor_version, my_pid);
	o_stream_nsend_str(conn->conn.output, line);

	if (auth_master_connection_set_permissions(conn, socket_st) < 0) {
		auth_master_connection_unref(&conn);
		return NULL;
	}
	return conn;
}

static void auth_master_connection_destroy(struct connection *_conn)
{
	struct auth_master_connection *conn =
		container_of(_conn, struct auth_master_connection, conn);
	if (conn->destroyed)
		return;
	conn->destroyed = TRUE;

	connection_disconnect(_conn);
	master_service_client_connection_destroyed(master_service);
	auth_master_connection_unref(&conn);
}

void auth_master_connection_ref(struct auth_master_connection *conn)
{
	i_assert(conn->refcount > 0);

	conn->refcount++;
}

void auth_master_connection_unref(struct auth_master_connection **_conn)
{
	struct auth_master_connection *conn = *_conn;

	*_conn = NULL;
	i_assert(conn->refcount > 0);

	if (--conn->refcount > 0)
		return;

	auth_master_connection_destroy(&conn->conn);
	connection_deinit(&conn->conn);
	i_free(conn);
}

void auth_master_connections_destroy_all(void)
{
	if (auth_master_connections != NULL)
		connection_list_deinit(&auth_master_connections);
}
