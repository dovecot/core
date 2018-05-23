/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "buffer.h"
#include "hash.h"
#include "llist.h"
#include "str.h"
#include "strescape.h"
#include "str-sanitize.h"
#include "time-util.h"
#include "hostpid.h"
#include "hex-binary.h"
#include "ioloop.h"
#include "net.h"
#include "istream.h"
#include "ostream.h"
#include "ipwd.h"
#include "master-service.h"
#include "userdb.h"
#include "userdb-blocking.h"
#include "master-interface.h"
#include "passdb-cache.h"
#include "auth-request-handler.h"
#include "auth-client-connection.h"
#include "auth-master-connection.h"

#include <unistd.h>

#define MAX_INBUF_SIZE 1024
#define MAX_OUTBUF_SIZE (1024*50)

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

static void master_input(struct auth_master_connection *conn);

static struct auth_master_connection *auth_master_connections;

static const char *
auth_master_reply_hide_passwords(struct auth_master_connection *conn,
				 const char *str)
{
	char **args, *p, *p2;
	unsigned int i;

	if (conn->auth->set->debug_passwords)
		return str;

	/* hide all parameters that have "pass" in their key */
	args = p_strsplit(pool_datastack_create(), str, "\t");
	for (i = 0; args[i] != NULL; i++) {
		p = strstr(args[i], "pass");
		p2 = strchr(args[i], '=');
		if (p != NULL && p < p2) {
			*p2 = '\0';
			args[i] = p_strconcat(pool_datastack_create(),
					      args[i], "=<hidden>", NULL);
		}
	}
	return t_strarray_join((void *)args, "\t");
}

void auth_master_request_callback(const char *reply, struct auth_master_connection *conn)
{
	struct const_iovec iov[2];

	e_debug(auth_event, "master userdb out: %s",
		auth_master_reply_hide_passwords(conn, reply));

	iov[0].iov_base = reply;
	iov[0].iov_len = strlen(reply);
	iov[1].iov_base = "\n";
	iov[1].iov_len = 1;

	o_stream_nsendv(conn->output, iov, 2);
}

void auth_master_log_error(struct auth_master_connection *conn,
			   const char *fmt, ...)
{
	va_list args;
	string_t *str = t_str_new(128);

	str_printfa(str, "created %d msecs ago",
		    timeval_diff_msecs(&ioloop_timeval, &conn->create_time));
	if (conn->handshake_time.tv_sec != 0) {
		str_printfa(str, ", handshake %d msecs ago",
			    timeval_diff_msecs(&ioloop_timeval, &conn->create_time));
	}

	va_start(args, fmt);
	i_error("%s (%s)", t_strdup_vprintf(fmt, args), str_c(str));
	va_end(args);
}

static bool
master_input_request(struct auth_master_connection *conn, const char *args)
{
	struct auth_client_connection *client_conn;
	const char *const *list, *const *params;
	unsigned int id, client_pid, client_id;
	uint8_t cookie[MASTER_AUTH_COOKIE_SIZE];
	buffer_t buf;

	/* <id> <client-pid> <client-id> <cookie> [<parameters>] */
	list = t_strsplit_tabescaped(args);
	if (str_array_length(list) < 4 ||
	    str_to_uint(list[0], &id) < 0 ||
	    str_to_uint(list[1], &client_pid) < 0 ||
	    str_to_uint(list[2], &client_id) < 0) {
		auth_master_log_error(conn, "BUG: Master sent broken REQUEST");
		return FALSE;
	}

	buffer_create_from_data(&buf, cookie, sizeof(cookie));
	if (hex_to_binary(list[3], &buf) < 0) {
		auth_master_log_error(conn,
			"BUG: Master sent broken REQUEST cookie");
		return FALSE;
	}
	params = list + 4;

	client_conn = auth_client_connection_lookup(client_pid);
	if (client_conn == NULL) {
		auth_master_log_error(conn,
			"Master requested auth for nonexistent client %u",
			client_pid);
		o_stream_nsend_str(conn->output,
				   t_strdup_printf("FAIL\t%u\n", id));
	} else if (!mem_equals_timing_safe(client_conn->cookie, cookie, sizeof(cookie))) {
		auth_master_log_error(conn,
			"Master requested auth for client %u with invalid cookie",
			client_pid);
		o_stream_nsend_str(conn->output,
				   t_strdup_printf("FAIL\t%u\n", id));
	} else if (!auth_request_handler_master_request(
			client_conn->request_handler, conn, id, client_id, params)) {
		auth_master_log_error(conn,
			"Master requested auth for non-login client %u",
			client_pid);
		o_stream_nsend_str(conn->output,
				   t_strdup_printf("FAIL\t%u\n", id));
	}
	return TRUE;
}

static bool
master_input_cache_flush(struct auth_master_connection *conn, const char *args)
{
	const char *const *list;
	unsigned int count;

	/* <id> [<user> [<user> [..]] */
	list = t_strsplit_tabescaped(args);
	if (list[0] == NULL) {
		auth_master_log_error(conn,
			"BUG: doveadm sent broken CACHE-FLUSH");
		return FALSE;
	}

	if (passdb_cache == NULL) {
		/* cache disabled */
		count = 0;
	} else if (list[1] == NULL) {
		/* flush the whole cache */
		count = auth_cache_clear(passdb_cache);
	} else {
		count = auth_cache_clear_users(passdb_cache, list+1);
	}
	o_stream_nsend_str(conn->output,
		t_strdup_printf("OK\t%s\t%u\n", list[0], count));
	return TRUE;
}

static int
master_input_auth_request(struct auth_master_connection *conn, const char *args,
			  const char *cmd, struct auth_request **request_r,
			  const char **error_r)
{
	struct auth_request *auth_request;
	const char *const *list, *name, *arg, *username;
	unsigned int id;

	/* <id> <userid> [<parameters>] */
	list = t_strsplit_tabescaped(args);
	if (list[0] == NULL || list[1] == NULL ||
	    str_to_uint(list[0], &id) < 0) {
		auth_master_log_error(conn, "BUG: Master sent broken %s", cmd);
		return -1;
	}

	auth_request = auth_request_new_dummy();
	auth_request->id = id;
	auth_request->master = conn;
	auth_master_connection_ref(conn);
	username = list[1];

	for (list += 2; *list != NULL; list++) {
		arg = strchr(*list, '=');
		if (arg == NULL) {
			name = *list;
			arg = "";
		} else {
			name = t_strdup_until(*list, arg);
			arg++;
		}

		(void)auth_request_import_info(auth_request, name, arg);
	}

	if (auth_request->service == NULL) {
		auth_master_log_error(conn,
			"BUG: Master sent %s request without service", cmd);
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

static int
user_verify_restricted_uid(struct auth_request *auth_request)
{
	struct auth_master_connection *conn = auth_request->master;
	struct auth_fields *reply = auth_request->userdb_reply;
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

	auth_request_log_error(auth_request, "userdb",
		"client doesn't have lookup permissions for this user: %s "
		"(to bypass this check, set: service auth { unix_listener %s { mode=0777 } })",
		reason, conn->path);
	return -1;
}

static void
user_callback(enum userdb_result result,
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
			value = auth_fields_find(auth_request->userdb_reply,
						 "reason");
			if (value != NULL)
				str_printfa(str, "\treason=%s", value);
		}
		break;
	case USERDB_RESULT_USER_UNKNOWN:
		str_printfa(str, "NOTFOUND\t%u", auth_request->id);
		break;
	case USERDB_RESULT_OK:
		str_printfa(str, "USER\t%u\t", auth_request->id);
		str_append_tabescaped(str, auth_request->user);
		str_append_c(str, '\t');
		auth_fields_append(auth_request->userdb_reply, str,
				   AUTH_FIELD_FLAG_HIDDEN, 0);
		break;
	}

	e_debug(auth_event, "userdb out: %s",
		auth_master_reply_hide_passwords(conn, str_c(str)));

	str_append_c(str, '\n');
	o_stream_nsend(conn->output, str_data(str), str_len(str));

	auth_request_unref(&auth_request);
	auth_master_connection_unref(&conn);
}

static bool
master_input_user(struct auth_master_connection *conn, const char *args)
{
	struct auth_request *auth_request;
	const char *error;
	int ret;

	ret = master_input_auth_request(conn, args, "USER",
					&auth_request, &error);
	if (ret <= 0) {
		if (ret < 0)
			return FALSE;
		auth_request_log_info(auth_request, "userdb", "%s", error);
		user_callback(USERDB_RESULT_USER_UNKNOWN, auth_request);
	} else {
		auth_request_set_state(auth_request, AUTH_REQUEST_STATE_USERDB);
		auth_request_lookup_user(auth_request, user_callback);
	}
	return TRUE;
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
		str_append_tabescaped(str, auth_request->user);
		if (!auth_fields_is_empty(auth_request->extra_fields)) {
			str_append_c(str, '\t');
			auth_fields_append(auth_request->extra_fields,
					   str, AUTH_FIELD_FLAG_HIDDEN, 0);
		}
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
		str_printfa(str, "FAIL\t%u\treason=Configured passdbs don't support credentials lookups",
			    auth_request->id);
		break;
	}

	e_debug(auth_event, "passdb out: %s", str_c(str));

	str_append_c(str, '\n');
	o_stream_nsend(conn->output, str_data(str), str_len(str));

	auth_request_unref(&auth_request);
	auth_master_connection_unref(&conn);
}

static void
auth_master_pass_proxy_finish(bool success, struct auth_request *auth_request)
{
	pass_callback_finish(auth_request, success ? PASSDB_RESULT_OK :
			     PASSDB_RESULT_INTERNAL_FAILURE);
}

static void
pass_callback(enum passdb_result result,
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
			       conn->path,
			       (unsigned long)conn->userdb_restricted_uid,
			       namestr);
}

static bool
master_input_pass(struct auth_master_connection *conn, const char *args)
{
	struct auth_request *auth_request;
	const char *error;
	int ret;

	ret = master_input_auth_request(conn, args, "PASS",
					&auth_request, &error);
	if (ret <= 0) {
		if (ret < 0)
			return FALSE;
		auth_request_log_info(auth_request, "passdb", "%s", error);
		pass_callback(PASSDB_RESULT_USER_UNKNOWN,
			      uchar_empty_ptr, 0, auth_request);
	} else if (conn->userdb_restricted_uid != 0) {
		/* no permissions to do this lookup */
		auth_request_log_error(auth_request, "passdb",
			"Auth client doesn't have permissions to do "
			"a PASS lookup: %s", auth_restricted_reason(conn));
		pass_callback(PASSDB_RESULT_INTERNAL_FAILURE,
			      uchar_empty_ptr, 0, auth_request);
	} else {
		auth_request_set_state(auth_request,
				       AUTH_REQUEST_STATE_MECH_CONTINUE);
		auth_request_lookup_credentials(auth_request, "",
						pass_callback);
	}
	return TRUE;
}

static void master_input_list_finish(struct master_list_iter_ctx *ctx)
{
	i_assert(ctx->conn->iter_ctx == ctx);

	ctx->conn->iter_ctx = NULL;
	ctx->conn->io = io_add(ctx->conn->fd, IO_READ, master_input, ctx->conn);

	if (ctx->iter != NULL)
		(void)userdb_blocking_iter_deinit(&ctx->iter);
	o_stream_uncork(ctx->conn->output);
	o_stream_unset_flush_callback(ctx->conn->output);
	auth_request_unref(&ctx->auth_request);
	auth_master_connection_unref(&ctx->conn);
	i_free(ctx);
}

static int master_output_list(struct master_list_iter_ctx *ctx)
{
	int ret;

	if ((ret = o_stream_flush(ctx->conn->output)) < 0) {
		master_input_list_finish(ctx);
		return 1;
	}
	if (ret > 0) {
		o_stream_cork(ctx->conn->output);
		userdb_blocking_iter_next(ctx->iter);
	}
	return 1;
}

static void master_input_list_callback(const char *user, void *context)
{
	struct master_list_iter_ctx *ctx = context;
	struct auth_userdb *userdb = ctx->auth_request->userdb;
	int ret;

	if (user == NULL) {
		if (userdb_blocking_iter_deinit(&ctx->iter) < 0)
			ctx->failed = TRUE;

		do {
			userdb = userdb->next;
		} while (userdb != NULL &&
			 userdb->userdb->iface->iterate_init == NULL);
		if (userdb == NULL) {
			/* iteration is finished */
			const char *str;

			str = t_strdup_printf("DONE\t%u\t%s\n",
					      ctx->auth_request->id,
					      ctx->failed ? "fail" : "");
			o_stream_nsend_str(ctx->conn->output, str);
			master_input_list_finish(ctx);
			return;
		}

		/* continue iterating next userdb */
		ctx->auth_request->userdb = userdb;
		ctx->iter = userdb_blocking_iter_init(ctx->auth_request,
					master_input_list_callback, ctx);
		userdb_blocking_iter_next(ctx->iter);
		return;
	}

	T_BEGIN {
		const char *str;

		str = t_strdup_printf("LIST\t%u\t%s\n", ctx->auth_request->id,
				      str_tabescape(user));
		ret = o_stream_send_str(ctx->conn->output, str);
	} T_END;
	if (o_stream_get_buffer_used_size(ctx->conn->output) >= MAX_OUTBUF_SIZE)
		ret = o_stream_flush(ctx->conn->output);
	if (ret < 0) {
		/* disconnected, don't bother finishing */
		master_input_list_finish(ctx);
		return;
	}
	if (o_stream_get_buffer_used_size(ctx->conn->output) < MAX_OUTBUF_SIZE)
		userdb_blocking_iter_next(ctx->iter);
	else
		o_stream_uncork(ctx->conn->output);
}

static bool
master_input_list(struct auth_master_connection *conn, const char *args)
{
	struct auth_userdb *userdb = conn->auth->userdbs;
	struct auth_request *auth_request;
	struct master_list_iter_ctx *ctx;
	const char *str, *name, *arg, *const *list;
	unsigned int id;

	/* <id> [<parameters>] */
	list = t_strsplit_tabescaped(args);
	if (list[0] == NULL || str_to_uint(list[0], &id) < 0) {
		auth_master_log_error(conn, "BUG: Master sent broken LIST");
		return FALSE;
	}
	list++;

	if (conn->iter_ctx != NULL) {
		auth_master_log_error(conn,
			"Auth client is already iterating users");
		str = t_strdup_printf("DONE\t%u\tfail\n", id);
		o_stream_nsend_str(conn->output, str);
		return TRUE;
	}

	if (conn->userdb_restricted_uid != 0) {
		auth_master_log_error(conn,
			"Auth client doesn't have permissions to list users: %s",
			auth_restricted_reason(conn));
		str = t_strdup_printf("DONE\t%u\tfail\n", id);
		o_stream_nsend_str(conn->output, str);
		return TRUE;
	}

	while (userdb != NULL && userdb->userdb->iface->iterate_init == NULL)
		userdb = userdb->next;
	if (userdb == NULL) {
		auth_master_log_error(conn,
			"Trying to iterate users, but userdbs don't support it");
		str = t_strdup_printf("DONE\t%u\tfail\n", id);
		o_stream_nsend_str(conn->output, str);
		return TRUE;
	}

	auth_request = auth_request_new_dummy();
	auth_request->id = id;
	auth_request->master = conn;
	auth_master_connection_ref(conn);

	for (; *list != NULL; list++) {
		arg = strchr(*list, '=');
		if (arg == NULL) {
			name = *list;
			arg = "";
		} else {
			name = t_strdup_until(*list, arg);
			arg++;
		}

		if (!auth_request_import_info(auth_request, name, arg) &&
		    strcmp(name, "user") == 0) {
			/* username mask */
			auth_request->user = p_strdup(auth_request->pool, arg);
		}
	}

	/* rest of the code doesn't like NULL user or service */
	if (auth_request->user == NULL)
		auth_request->user = "";
	if (auth_request->service == NULL)
		auth_request->service = "";

	ctx = i_new(struct master_list_iter_ctx, 1);
	ctx->conn = conn;
	ctx->auth_request = auth_request;
	ctx->auth_request->userdb = userdb;

	io_remove(&conn->io);
	o_stream_cork(conn->output);
	o_stream_set_flush_callback(conn->output, master_output_list, ctx);
	ctx->iter = userdb_blocking_iter_init(auth_request,
					      master_input_list_callback, ctx);
	conn->iter_ctx = ctx;
	return TRUE;
}

static bool
auth_master_input_line(struct auth_master_connection *conn, const char *line)
{
	e_debug(auth_event, "master in: %s", line);

	if (str_begins(line, "USER\t"))
		return master_input_user(conn, line + 5);
	if (str_begins(line, "LIST\t"))
		return master_input_list(conn, line + 5);
	if (str_begins(line, "PASS\t"))
		return master_input_pass(conn, line + 5);

	if (!conn->userdb_only) {
		i_assert(conn->userdb_restricted_uid == 0);
		if (str_begins(line, "REQUEST\t"))
			return master_input_request(conn, line + 8);
		if (str_begins(line, "CACHE-FLUSH\t"))
			return master_input_cache_flush(conn, line + 12);
		if (str_begins(line, "CPID\t")) {
			auth_master_log_error(conn,
				"Authentication client trying to connect to "
				"master socket");
			return FALSE;
		}
	}

	auth_master_log_error(conn, "BUG: Unknown command in %s socket: %s",
		conn->userdb_only ? "userdb" : "master",
		str_sanitize(line, 80));
	return FALSE;
}

static void master_input(struct auth_master_connection *conn)
{
 	char *line;
	bool ret;

	switch (i_stream_read(conn->input)) {
	case 0:
		return;
	case -1:
		/* disconnected */
                auth_master_connection_destroy(&conn);
		return;
	case -2:
		/* buffer full */
		auth_master_log_error(conn,
			"BUG: Master sent us more than %d bytes",
			(int)MAX_INBUF_SIZE);
                auth_master_connection_destroy(&conn);
		return;
	}

	if (!conn->version_received) {
		line = i_stream_next_line(conn->input);
		if (line == NULL)
			return;

		/* make sure the major version matches */
		if (!str_begins(line, "VERSION\t") ||
		    !str_uint_equals(t_strcut(line + 8, '\t'),
				     AUTH_MASTER_PROTOCOL_MAJOR_VERSION)) {
			auth_master_log_error(conn,
				"Master not compatible with this server "
				"(mixed old and new binaries?)");
			auth_master_connection_destroy(&conn);
			return;
		}
		conn->version_received = TRUE;
		conn->handshake_time = ioloop_timeval;
	}

	while ((line = i_stream_next_line(conn->input)) != NULL) {
		T_BEGIN {
			ret = auth_master_input_line(conn, line);
		} T_END;
		if (!ret) {
			auth_master_connection_destroy(&conn);
			return;
		}
	}
}

static int master_output(struct auth_master_connection *conn)
{
	if (o_stream_flush(conn->output) < 0) {
		/* transmit error, probably master died */
		auth_master_connection_destroy(&conn);
		return 1;
	}

	if (conn->io == NULL &&
	    o_stream_get_buffer_used_size(conn->output) <= MAX_OUTBUF_SIZE/2) {
		/* allow input again */
		conn->io = io_add(conn->fd, IO_READ, master_input, conn);
	}
	return 1;
}

static int
auth_master_connection_set_permissions(struct auth_master_connection *conn,
				       const struct stat *st)
{
	struct net_unix_cred cred;

	if (st == NULL)
		return 0;

	/* figure out what permissions we want to give to this client */
	if ((st->st_mode & 0777) != 0666) {
		/* permissions were already restricted by the socket
		   permissions. also +x bit indicates that we shouldn't do
		   any permission checks. */
		return 0;
	}

	if (net_getunixcred(conn->fd, &cred) < 0) {
		auth_master_log_error(conn,
			"userdb connection: Failed to get peer's credentials");
		return -1;
	}

	if (cred.uid == st->st_uid || cred.gid == st->st_gid) {
		/* full permissions */
		return 0;
	} else {
		/* restrict permissions: return only lookups whose returned
		   uid matches the peer's uid */
		conn->userdb_restricted_uid = cred.uid;
		return 0;
	}
}

struct auth_master_connection *
auth_master_connection_create(struct auth *auth, int fd,
			      const char *path, const struct stat *socket_st,
			      bool userdb_only)
{
	struct auth_master_connection *conn;
	const char *line;

	i_assert(path != NULL);

	conn = i_new(struct auth_master_connection, 1);
	conn->refcount = 1;
	conn->fd = fd;
	conn->create_time = ioloop_timeval;
	conn->path = i_strdup(path);
	conn->auth = auth;
	conn->input = i_stream_create_fd(fd, MAX_INBUF_SIZE);
	conn->output = o_stream_create_fd(fd, (size_t)-1);
	o_stream_set_no_error_handling(conn->output, TRUE);
	o_stream_set_flush_callback(conn->output, master_output, conn);
	conn->io = io_add(fd, IO_READ, master_input, conn);
	conn->userdb_only = userdb_only;

	line = t_strdup_printf("VERSION\t%u\t%u\nSPID\t%s\n",
			       AUTH_MASTER_PROTOCOL_MAJOR_VERSION,
			       AUTH_MASTER_PROTOCOL_MINOR_VERSION,
			       my_pid);
	o_stream_nsend_str(conn->output, line);
	DLLIST_PREPEND(&auth_master_connections, conn);

	if (auth_master_connection_set_permissions(conn, socket_st) < 0) {
		auth_master_connection_destroy(&conn);
		return NULL;
	}
	return conn;
}

void auth_master_connection_destroy(struct auth_master_connection **_conn)
{
        struct auth_master_connection *conn = *_conn;

	*_conn = NULL;
	if (conn->destroyed)
		return;
	conn->destroyed = TRUE;

	DLLIST_REMOVE(&auth_master_connections, conn);

	if (conn->iter_ctx != NULL)
		master_input_list_finish(conn->iter_ctx);
	i_stream_close(conn->input);
	o_stream_close(conn->output);
	io_remove(&conn->io);
	i_close_fd_path(&conn->fd, conn->path);

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

	i_stream_unref(&conn->input);
	o_stream_unref(&conn->output);

	i_free(conn->path);
	i_free(conn);
}

void auth_master_connections_destroy_all(void)
{
	struct auth_master_connection *conn;

	while (auth_master_connections != NULL) {
		conn = auth_master_connections;
		auth_master_connection_destroy(&conn);
	}
}
