/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "base64.h"
#include "connection.h"
#include "ioloop.h"
#include "net.h"
#include "istream.h"
#include "ostream.h"
#include "hex-binary.h"
#include "str.h"
#include "strescape.h"
#include "process-title.h"
#include "master-service.h"
#include "auth-request.h"
#include "auth-worker-server.h"


#define AUTH_WORKER_WARN_DISCONNECTED_LONG_CMD_SECS 30
#define OUTBUF_THROTTLE_SIZE (1024*10)

#define WORKER_STATE_HANDSHAKE "handshaking"
#define WORKER_STATE_IDLE "idling"
#define WORKER_STATE_STOP "waiting for shutdown"

static unsigned int auth_worker_max_service_count = 0;
static unsigned int auth_worker_service_count = 0;

struct auth_worker_server {
	struct connection conn;
	int refcount;

	struct auth *auth;
	struct event *event;
	time_t cmd_start;

	bool error_sent:1;
	bool destroyed:1;
};

struct auth_worker_command {
	struct auth_worker_server *server;
	struct event *event;
};

struct auth_worker_list_context {
	struct auth_worker_command *cmd;
	struct auth_worker_server *server;
	struct auth_request *auth_request;
	struct userdb_iterate_context *iter;
	bool sending, sent, done;
};

static struct connection_list *clients = NULL;
static bool auth_worker_server_error = FALSE;

static int auth_worker_output(struct auth_worker_server *server);
static void auth_worker_server_destroy(struct connection *conn);
static void auth_worker_server_unref(struct auth_worker_server **_client);

void auth_worker_set_max_service_count(unsigned int count)
{
	auth_worker_max_service_count = count;
}

static struct auth_worker_server *auth_worker_get_client(void)
{
	if (!auth_worker_has_connections())
		return NULL;
	struct auth_worker_server *server =
		container_of(clients->connections, struct auth_worker_server, conn);
	return server;
}

void auth_worker_refresh_proctitle(const char *state)
{
	if (!global_auth_settings->verbose_proctitle || !worker)
		return;

	if (auth_worker_server_error)
		state = "error";
	else if (!auth_worker_has_connections())
		state = "waiting for connection";
	process_title_set(t_strdup_printf("worker: %s", state));
}

static void
auth_worker_server_check_throttle(struct auth_worker_server *server)
{
	if (o_stream_get_buffer_used_size(server->conn.output) >=
	    OUTBUF_THROTTLE_SIZE) {
		/* stop reading new requests until client has read the pending
		   replies. */
		connection_input_halt(&server->conn);
	}
}

static void
auth_worker_request_finished_full(struct auth_worker_command *cmd,
				  const char *error, bool log_as_error)
{
	event_set_name(cmd->event, "auth_worker_request_finished");
	if (error != NULL) {
		event_add_str(cmd->event, "error", error);
		if (log_as_error)
			e_error(cmd->event, "Finished: %s", error);
		else
			e_debug(cmd->event, "Finished: %s", error);
	} else {
		e_debug(cmd->event, "Finished");
	}
	auth_worker_server_check_throttle(cmd->server);
	auth_worker_server_unref(&cmd->server);
	event_unref(&cmd->event);
	i_free(cmd);

	auth_worker_refresh_proctitle(WORKER_STATE_IDLE);
}

static void auth_worker_request_finished(struct auth_worker_command *cmd,
					 const char *error)
{
	auth_worker_request_finished_full(cmd, error, FALSE);
}

static void auth_worker_request_finished_bug(struct auth_worker_command *cmd,
					     const char *error)
{
	auth_worker_request_finished_full(cmd, error, TRUE);
}

bool auth_worker_auth_request_new(struct auth_worker_command *cmd, unsigned int id,
				  const char *const *args, struct auth_request **request_r)
{
	struct auth_request *auth_request;
	const char *key, *value;

	auth_request = auth_request_new_dummy(cmd->event);

	cmd->server->refcount++;
	auth_request->context = cmd;
	auth_request->id = id;

	for (; *args != NULL; args++) {
		value = strchr(*args, '=');
		if (value == NULL)
			(void)auth_request_import(auth_request, *args, "");
		else {
			key = t_strdup_until(*args, value++);
			(void)auth_request_import(auth_request, key, value);
		}
	}
	if (auth_request->fields.user == NULL ||
	    auth_request->fields.service == NULL) {
		auth_request_unref(&auth_request);
		return FALSE;
	}

	/* reset changed-fields, so we'll export only the ones that were
	   changed by this lookup. */
	auth_fields_snapshot(auth_request->fields.extra_fields);
	if (auth_request->fields.userdb_reply != NULL)
		auth_fields_snapshot(auth_request->fields.userdb_reply);

	auth_request_init(auth_request);
	*request_r = auth_request;

	return TRUE;
}

static void auth_worker_send_reply(struct auth_worker_server *server,
				   struct auth_request *request,
				   string_t *str)
{
	time_t cmd_duration = time(NULL) - server->cmd_start;
	const char *p;

	if (worker_restart_request)
		o_stream_nsend_str(server->conn.output, "RESTART\n");
	o_stream_nsend(server->conn.output, str_data(str), str_len(str));
	if (o_stream_flush(server->conn.output) < 0 && request != NULL &&
	    cmd_duration > AUTH_WORKER_WARN_DISCONNECTED_LONG_CMD_SECS) {
		p = i_strchr_to_next(str_c(str), '\t');
		p = p == NULL ? "BUG" : t_strcut(p, '\t');

		e_warning(server->conn.event, "Auth master disconnected us while handling "
			  "request for %s for %ld secs (result=%s)",
			  request->fields.user, (long)cmd_duration, p);
	}
}

static void
reply_append_extra_fields(string_t *str, struct auth_request *request)
{
	if (!auth_fields_is_empty(request->fields.extra_fields)) {
		str_append_c(str, '\t');
		/* export only the fields changed by this lookup, so the
		   changed-flag gets preserved correctly on the master side as
		   well. */
		auth_fields_append(request->fields.extra_fields, str,
				   AUTH_FIELD_FLAG_CHANGED,
				   AUTH_FIELD_FLAG_CHANGED);
	}
	if (request->fields.userdb_reply != NULL &&
	    auth_fields_is_empty(request->fields.userdb_reply)) {
		/* all userdb_* fields had NULL values. we'll still
		   need to tell this to the master */
		str_append(str, "\tuserdb_"AUTH_REQUEST_USER_KEY_IGNORE);
	}
}

static void verify_plain_callback(enum passdb_result result,
				  struct auth_request *request)
{
	struct auth_worker_command *cmd = request->context;
	struct auth_worker_server *server = cmd->server;
	const char *error = NULL;
	string_t *str;

	if (request->failed && result == PASSDB_RESULT_OK)
		result = PASSDB_RESULT_PASSWORD_MISMATCH;

	str = t_str_new(128);
	str_printfa(str, "%u\t", request->id);

	if (result == PASSDB_RESULT_OK)
		if (auth_fields_exists(request->fields.extra_fields, "noauthenticate"))
			str_append(str, "NEXT");
		else
			str_append(str, "OK");
	else {
		str_printfa(str, "FAIL\t%d", result);
		error = passdb_result_to_string(result);
	}
	if (result != PASSDB_RESULT_INTERNAL_FAILURE) {
		str_append_c(str, '\t');
		if (request->user_changed_by_lookup)
			str_append_tabescaped(str, request->fields.user);
		str_append_c(str, '\t');
		if (request->passdb_password != NULL)
			str_append_tabescaped(str, request->passdb_password);
		reply_append_extra_fields(str, request);
	}
	str_append_c(str, '\n');
	auth_worker_send_reply(server, request, str);

	auth_request_passdb_lookup_end(request, result);
	auth_worker_request_finished(cmd, error);
	auth_request_unref(&request);
}

static bool
auth_worker_handle_passv(struct auth_worker_command *cmd,
			 unsigned int id, const char *const *args,
			 const char **error_r)
{
	/* verify plaintext password */
	struct auth_request *auth_request;
	struct auth_passdb *passdb;
	const char *password;
	unsigned int passdb_id;

	/* <passdb id> <password> [<args>] */
	if (str_to_uint(args[0], &passdb_id) < 0 || args[1] == NULL) {
		*error_r = "BUG: Auth worker server sent us invalid PASSV";
		return FALSE;
	}
	password = args[1];

	if (!auth_worker_auth_request_new(cmd, id, args + 2, &auth_request)) {
		*error_r = "BUG: Auth worker server sent us invalid PASSV";
		return FALSE;
	}
	auth_request->mech_password =
		p_strdup(auth_request->pool, password);

	passdb = auth_request->passdb;
	while (passdb != NULL && passdb->passdb->id != passdb_id)
		passdb = passdb->next;

	if (passdb == NULL) {
		/* could be a masterdb */
		passdb = auth_request_get_auth(auth_request)->masterdbs;
		while (passdb != NULL && passdb->passdb->id != passdb_id)
			passdb = passdb->next;

		if (passdb == NULL) {
			*error_r = "BUG: PASSV had invalid passdb ID";
			auth_request_unref(&auth_request);
			return FALSE;
		}
	}

	auth_request->passdb = passdb;
	auth_request_passdb_lookup_begin(auth_request);
	passdb->passdb->iface.
		verify_plain(auth_request, password, verify_plain_callback);
	return TRUE;
}

static bool
auth_worker_handle_passw(struct auth_worker_command *cmd,
			 unsigned int id, const char *const *args,
			 const char **error_r)
{
	struct auth_worker_server *server = cmd->server;
	struct auth_request *request;
	string_t *str;
	const char *password;
	const char *crypted, *scheme, *error;
	unsigned int passdb_id;
	int ret;

	if (str_to_uint(args[0], &passdb_id) < 0 || args[1] == NULL ||
	    args[2] == NULL) {
		*error_r = "BUG: Auth worker server sent us invalid PASSW";
		return FALSE;
	}
	password = args[1];
	crypted = args[2];
	scheme = password_get_scheme(&crypted);
	if (scheme == NULL) {
		*error_r = "BUG: Auth worker server sent us invalid PASSW (scheme is NULL)";
		return FALSE;
	}

	if (!auth_worker_auth_request_new(cmd, id, args + 3, &request)) {
		*error_r = "BUG: PASSW had missing parameters";
		return FALSE;
	}
	request->mech_password =
		p_strdup(request->pool, password);

	ret = auth_request_password_verify(request, password,
					   crypted, scheme, "cache");
	str = t_str_new(128);
	str_printfa(str, "%u\t", request->id);

	if (ret == 1) {
		str_printfa(str, "OK\t\t");
		error = NULL;
	} else if (ret == 0) {
		str_printfa(str, "FAIL\t%d", PASSDB_RESULT_PASSWORD_MISMATCH);
		error = passdb_result_to_string(PASSDB_RESULT_PASSWORD_MISMATCH);
	} else {
		str_printfa(str, "FAIL\t%d", PASSDB_RESULT_INTERNAL_FAILURE);
		error = passdb_result_to_string(PASSDB_RESULT_INTERNAL_FAILURE);
	}

	str_append_c(str, '\n');
	auth_worker_send_reply(server, request, str);

	auth_worker_request_finished(cmd, error);
	auth_request_unref(&request);
	return TRUE;
}

static void
lookup_credentials_callback(enum passdb_result result,
			    const unsigned char *credentials, size_t size,
			    struct auth_request *request)
{
	struct auth_worker_command *cmd = request->context;
	struct auth_worker_server *server = cmd->server;
	string_t *str;

	if (request->failed && result == PASSDB_RESULT_OK)
		result = PASSDB_RESULT_PASSWORD_MISMATCH;

	str = t_str_new(128);
	str_printfa(str, "%u\t", request->id);

	if (result != PASSDB_RESULT_OK && result != PASSDB_RESULT_NEXT)
		str_printfa(str, "FAIL\t%d", result);
	else {
		if (result == PASSDB_RESULT_NEXT)
			str_append(str, "NEXT\t");
		else
			str_append(str, "OK\t");
		if (request->user_changed_by_lookup)
			str_append_tabescaped(str, request->fields.user);
		str_append_c(str, '\t');
		if (request->wanted_credentials_scheme[0] != '\0') {
			str_printfa(str, "{%s.b64}", request->wanted_credentials_scheme);
			base64_encode(credentials, size, str);
		} else {
			i_assert(size == 0);
		}
		reply_append_extra_fields(str, request);
	}
	str_append_c(str, '\n');
	auth_worker_send_reply(server, request, str);

	auth_request_passdb_lookup_end(request, result);
	auth_request_unref(&request);
	auth_worker_request_finished(cmd, NULL);
}

static bool
auth_worker_handle_passl(struct auth_worker_command *cmd,
			 unsigned int id, const char *const *args,
			 const char **error_r)
{
	/* lookup credentials */
	struct auth_request *auth_request;
	const char *scheme;
	unsigned int passdb_id;

	/* <passdb id> <scheme> [<args>] */
	if (str_to_uint(args[0], &passdb_id) < 0 || args[1] == NULL) {
		*error_r = "BUG: Auth worker server sent us invalid PASSL";
		return FALSE;
	}
	scheme = args[1];

	if (!auth_worker_auth_request_new(cmd, id, args + 2, &auth_request)) {
		*error_r = "BUG: PASSL had missing parameters";
		return FALSE;
	}
	auth_request->wanted_credentials_scheme =
		p_strdup(auth_request->pool, scheme);

	while (auth_request->passdb->passdb->id != passdb_id) {
		auth_request->passdb = auth_request->passdb->next;
		if (auth_request->passdb == NULL) {
			*error_r = "BUG: PASSL had invalid passdb ID";
			auth_request_unref(&auth_request);
			return FALSE;
		}
	}

	if (auth_request->passdb->passdb->iface.lookup_credentials == NULL) {
		*error_r = "BUG: PASSL lookup not supported by given passdb";
		auth_request_unref(&auth_request);
		return FALSE;
	}

	auth_request->prefer_plain_credentials = TRUE;
	auth_request_passdb_lookup_begin(auth_request);
	auth_request->passdb->passdb->iface.
		lookup_credentials(auth_request, lookup_credentials_callback);
	return TRUE;
}

static void
set_credentials_callback(bool success, struct auth_request *request)
{
	struct auth_worker_command *cmd = request->context;
	struct auth_worker_server *server = cmd->server;

	string_t *str;

	str = t_str_new(64);
	str_printfa(str, "%u\t%s\n", request->id, success ? "OK" : "FAIL");
	auth_worker_send_reply(server, request, str);

	auth_worker_request_finished(cmd, success ? NULL :
				     "Failed to set credentials");
	auth_request_unref(&request);
}

static bool
auth_worker_handle_setcred(struct auth_worker_command *cmd,
			   unsigned int id, const char *const *args,
			   const char **error_r)
{
	struct auth_request *auth_request;
	unsigned int passdb_id;
	const char *creds;

	/* <passdb id> <credentials> [<args>] */
	if (str_to_uint(args[0], &passdb_id) < 0 || args[1] == NULL) {
		*error_r = "BUG: Auth worker server sent us invalid SETCRED";
		return FALSE;
	}
	creds = args[1];

	if (!auth_worker_auth_request_new(cmd, id, args + 2, &auth_request)) {
		*error_r = "BUG: SETCRED had missing parameters";
		return FALSE;
	}

	while (auth_request->passdb->passdb->id != passdb_id) {
		auth_request->passdb = auth_request->passdb->next;
		if (auth_request->passdb == NULL) {
			*error_r = "BUG: SETCRED had invalid passdb ID";
			auth_request_unref(&auth_request);
			return FALSE;
		}
	}

	auth_request->passdb->passdb->iface.
		set_credentials(auth_request, creds, set_credentials_callback);
	return TRUE;
}

static void
lookup_user_callback(enum userdb_result result,
		     struct auth_request *auth_request)
{
	struct auth_worker_command *cmd = auth_request->context;
	struct auth_worker_server *server = cmd->server;
	const char *error;
	string_t *str;

	str = t_str_new(128);
	str_printfa(str, "%u\t", auth_request->id);
	switch (result) {
	case USERDB_RESULT_INTERNAL_FAILURE:
		str_append(str, "FAIL\t");
		break;
	case USERDB_RESULT_USER_UNKNOWN:
		str_append(str, "NOTFOUND\t");
		break;
	case USERDB_RESULT_OK:
		str_append(str, "OK\t");
		if (auth_request->user_changed_by_lookup)
			str_append_tabescaped(str, auth_request->fields.user);
		str_append_c(str, '\t');
		/* export only the fields changed by this lookup */
		auth_fields_append(auth_request->fields.userdb_reply, str,
				   AUTH_FIELD_FLAG_CHANGED,
				   AUTH_FIELD_FLAG_CHANGED);
		if (auth_request->userdb_lookup_tempfailed)
			str_append(str, "\ttempfail");
		break;
	}
	str_append_c(str, '\n');

	auth_worker_send_reply(server, auth_request, str);

	auth_request_userdb_lookup_end(auth_request, result);
	error = result == USERDB_RESULT_OK ? NULL :
		userdb_result_to_string(result);
	auth_worker_request_finished(cmd, error);
	auth_request_unref(&auth_request);
}

static struct auth_userdb *
auth_userdb_find_by_id(struct auth_userdb *userdbs, unsigned int id)
{
	struct auth_userdb *db;

	for (db = userdbs; db != NULL; db = db->next) {
		if (db->userdb->id == id)
			return db;
	}
	return NULL;
}

static bool
auth_worker_handle_user(struct auth_worker_command *cmd,
			unsigned int id, const char *const *args,
			const char **error_r)
{
	/* lookup user */
	struct auth_request *auth_request;
	unsigned int userdb_id;

	/* <userdb id> [<args>] */
	if (str_to_uint(args[0], &userdb_id) < 0) {
		*error_r = "BUG: Auth worker server sent us invalid USER";
		return FALSE;
	}

	if (!auth_worker_auth_request_new(cmd, id, args + 1, &auth_request)) {
		*error_r = "BUG: USER had missing parameters";
		return FALSE;
	}

	auth_request->userdb_lookup = TRUE;
	auth_request->userdb =
		auth_userdb_find_by_id(auth_request->userdb, userdb_id);
	if (auth_request->userdb == NULL) {
		*error_r = "BUG: USER had invalid userdb ID";
		auth_request_unref(&auth_request);
		return FALSE;
	}

	if (auth_request->fields.userdb_reply == NULL)
		auth_request_init_userdb_reply(auth_request, TRUE);
	auth_request_userdb_lookup_begin(auth_request);
	auth_request->userdb->userdb->iface->
		lookup(auth_request, lookup_user_callback);
	return TRUE;
}

static void
auth_worker_server_idle_kill(struct connection *conn ATTR_UNUSED)
{
	auth_worker_server_send_shutdown();
}

static void list_iter_deinit(struct auth_worker_list_context *ctx)
{
	struct auth_worker_command *cmd = ctx->cmd;
	struct auth_worker_server *server = ctx->server;
	const char *error = NULL;
	string_t *str;

	i_assert(server->conn.io == NULL);

	str = t_str_new(32);
	if (ctx->auth_request->userdb->userdb->iface->
	    			iterate_deinit(ctx->iter) < 0) {
		error = "Iteration failed";
		str_printfa(str, "%u\tFAIL\n", ctx->auth_request->id);
	} else
		str_printfa(str, "%u\tOK\n", ctx->auth_request->id);
	auth_worker_send_reply(server, NULL, str);

	connection_input_resume(&server->conn);
	o_stream_set_flush_callback(server->conn.output, auth_worker_output,
				    server);
	auth_request_userdb_lookup_end(ctx->auth_request, USERDB_RESULT_OK);
	auth_worker_request_finished(cmd, error);
	auth_request_unref(&ctx->auth_request);
	i_free(ctx);
}

static void list_iter_callback(const char *user, void *context)
{
	struct auth_worker_list_context *ctx = context;
	string_t *str;

	if (user == NULL) {
		if (ctx->sending)
			ctx->done = TRUE;
		else
			list_iter_deinit(ctx);
		return;
	}

	if (!ctx->sending)
		o_stream_cork(ctx->server->conn.output);
	T_BEGIN {
		str = t_str_new(128);
		str_printfa(str, "%u\t*\t%s\n", ctx->auth_request->id, user);
		o_stream_nsend(ctx->server->conn.output, str_data(str), str_len(str));
	} T_END;

	if (ctx->sending) {
		/* avoid recursively looping to this same function */
		ctx->sent = TRUE;
		return;
	}

	do {
		ctx->sending = TRUE;
		ctx->sent = FALSE;
		T_BEGIN {
			ctx->auth_request->userdb->userdb->iface->
				iterate_next(ctx->iter);
		} T_END;
		if (o_stream_get_buffer_used_size(ctx->server->conn.output) > OUTBUF_THROTTLE_SIZE) {
			if (o_stream_flush(ctx->server->conn.output) < 0) {
				ctx->done = TRUE;
				break;
			}
		}
	} while (ctx->sent &&
		 o_stream_get_buffer_used_size(ctx->server->conn.output) <= OUTBUF_THROTTLE_SIZE);
	o_stream_uncork(ctx->server->conn.output);
	ctx->sending = FALSE;
	if (ctx->done)
		list_iter_deinit(ctx);
	else
		o_stream_set_flush_pending(ctx->server->conn.output, TRUE);
}

static int auth_worker_list_output(struct auth_worker_list_context *ctx)
{
	int ret;

	if ((ret = o_stream_flush(ctx->server->conn.output)) < 0) {
		list_iter_deinit(ctx);
		return 1;
	}
	if (ret > 0) T_BEGIN {
		ctx->auth_request->userdb->userdb->iface->
			iterate_next(ctx->iter);
	} T_END;
	return 1;
}

static bool
auth_worker_handle_list(struct auth_worker_command *cmd,
			unsigned int id, const char *const *args,
			const char **error_r)
{
	struct auth_worker_server *server = cmd->server;
	struct auth_worker_list_context *ctx;
	struct auth_userdb *userdb;
	unsigned int userdb_id;

	if (str_to_uint(args[0], &userdb_id) < 0) {
		*error_r = "BUG: Auth worker server sent us invalid LIST";
		return FALSE;
	}

	userdb = auth_userdb_find_by_id(server->auth->userdbs, userdb_id);
	if (userdb == NULL) {
		*error_r = "BUG: LIST had invalid userdb ID";
		return FALSE;
	}

	ctx = i_new(struct auth_worker_list_context, 1);
	ctx->cmd = cmd;
	ctx->server = server;
	if (!auth_worker_auth_request_new(cmd, id, args + 1, &ctx->auth_request)) {
		*error_r = "BUG: LIST had missing parameters";
		i_free(ctx);
		return FALSE;
	}
	ctx->auth_request->userdb = userdb;

	connection_input_halt(&ctx->server->conn);

	o_stream_set_flush_callback(ctx->server->conn.output,
				    auth_worker_list_output, ctx);
	ctx->auth_request->userdb_lookup = TRUE;
	auth_request_userdb_lookup_begin(ctx->auth_request);
	ctx->iter = ctx->auth_request->userdb->userdb->iface->
		iterate_init(ctx->auth_request, list_iter_callback, ctx);
	ctx->auth_request->userdb->userdb->iface->iterate_next(ctx->iter);
	return TRUE;
}

static bool auth_worker_verify_db_hash(const char *passdb_hash, const char *userdb_hash)
{
	string_t *str = t_str_new(MD5_RESULTLEN*2);
	unsigned char passdb_md5[MD5_RESULTLEN];
	unsigned char userdb_md5[MD5_RESULTLEN];

	passdbs_generate_md5(passdb_md5);
	userdbs_generate_md5(userdb_md5);

	binary_to_hex_append(str, passdb_md5, sizeof(passdb_md5));
	if (strcmp(str_c(str), passdb_hash) != 0)
		return FALSE;
	str_truncate(str, 0);
	binary_to_hex_append(str, userdb_md5, sizeof(userdb_md5));
	return strcmp(str_c(str), userdb_hash) == 0;
};

static int auth_worker_server_handshake_args(struct connection *conn, const char *const *args)
{
	if (!conn->version_received) {
		if (connection_handshake_args_default(conn, args) < 0)
			return -1;
		return 0;
	}

	if (str_array_length(args) < 3 ||
	    strcmp(args[0], "DBHASH") != 0) {
		e_error(conn->event, "BUG: Invalid input: %s",
			t_strarray_join(args, "\t"));
		return -1;
	}

	if (!auth_worker_verify_db_hash(args[1], args[2])) {
		e_error(conn->event,
			"Auth worker sees different passdbs/userdbs "
			"than auth server. Maybe config just changed "
			"and this goes away automatically?");
		return -1;
	}
	return 1;
}

static int
auth_worker_server_input_args(struct connection *conn, const char *const *args)
{
	unsigned int id;
	bool ret = FALSE;
	const char *error = NULL;
	struct auth_worker_command *cmd;
	struct auth_worker_server *server =
		container_of(conn, struct auth_worker_server, conn);

	if (str_array_length(args) < 3 ||
	    str_to_uint(args[0], &id) < 0) {
		e_error(conn->event, "BUG: Invalid input: %s",
			t_strarray_join(args, "\t"));
		return -1;
	}

	io_loop_time_refresh();

	cmd = i_new(struct auth_worker_command, 1);
	cmd->server = server;
	cmd->event = event_create(server->conn.event);
	event_add_category(cmd->event, &event_category_auth);
	event_add_str(cmd->event, "command", args[1]);
	event_add_int(cmd->event, "command_id", id);
	event_set_append_log_prefix(cmd->event, t_strdup_printf("auth-worker<%u>: ", id));
	server->cmd_start = ioloop_time;
	server->refcount++;
	e_debug(cmd->event, "Handling %s request", args[1]);

	/* Check if we have reached service_count */
	if (auth_worker_max_service_count > 0) {
		auth_worker_service_count++;
		if (auth_worker_service_count >= auth_worker_max_service_count)
			worker_restart_request = TRUE;
	}

	auth_worker_refresh_proctitle(args[1]);
	if (strcmp(args[1], "PASSV") == 0)
		ret = auth_worker_handle_passv(cmd, id, args + 2, &error);
	else if (strcmp(args[1], "PASSL") == 0)
		ret = auth_worker_handle_passl(cmd, id, args + 2, &error);
	else if (strcmp(args[1], "PASSW") == 0)
		ret = auth_worker_handle_passw(cmd, id, args + 2, &error);
	else if (strcmp(args[1], "SETCRED") == 0)
		ret = auth_worker_handle_setcred(cmd, id, args + 2, &error);
	else if (strcmp(args[1], "USER") == 0)
		ret = auth_worker_handle_user(cmd, id, args + 2, &error);
	else if (strcmp(args[1], "LIST") == 0)
		ret = auth_worker_handle_list(cmd, id, args + 2, &error);
	else {
		error = t_strdup_printf("BUG: Auth-worker received unknown command: %s",
			args[1]);
	}

	i_assert(ret || error != NULL);

	if (!ret) {
		auth_worker_request_finished_bug(cmd, error);
		return -1;
	}
	auth_worker_server_unref(&server);
	return 1;
}

static int auth_worker_output(struct auth_worker_server *server)
{
	if (o_stream_flush(server->conn.output) < 0) {
		auth_worker_server_destroy(&server->conn);
		return 1;
	}

	if (o_stream_get_buffer_used_size(server->conn.output) <=
	    OUTBUF_THROTTLE_SIZE/3 && server->conn.io == NULL) {
		/* allow input again */
		connection_input_resume(&server->conn);
	}
	return 1;
}

static void auth_worker_server_unref(struct auth_worker_server **_client)
{
	struct auth_worker_server *server = *_client;
	if (server == NULL)
		return;
	if (--server->refcount > 0)
		return;

	/* the connection should've been destroyed before getting here */
	i_assert(server->destroyed);
	connection_deinit(&server->conn);
	i_free(server);
}

static void auth_worker_server_destroy(struct connection *conn)
{
	struct auth_worker_server *server =
		container_of(conn, struct auth_worker_server, conn);

	i_assert(!server->destroyed);
	server->destroyed = TRUE;
	connection_input_halt(conn);
	i_stream_close(conn->input);
	o_stream_close(conn->output);
	net_disconnect(conn->fd_in);
	conn->fd_out = conn->fd_in = -1;
	auth_worker_server_unref(&server);
	master_service_client_connection_destroyed(master_service);
}

static const struct connection_vfuncs auth_worker_server_v =
{
	.input_args = auth_worker_server_input_args,
	.handshake_args = auth_worker_server_handshake_args,
	.destroy = auth_worker_server_destroy,
	.idle_timeout = auth_worker_server_idle_kill,
};

static const struct connection_settings auth_worker_server_set =
{
	.service_name_in = AUTH_MASTER_NAME,
	.service_name_out = AUTH_WORKER_NAME,
	.major_version = AUTH_WORKER_PROTOCOL_MAJOR_VERSION,
	.minor_version = AUTH_WORKER_PROTOCOL_MINOR_VERSION,
	.input_max_size = SIZE_MAX,
	.output_max_size = SIZE_MAX, /* we use throttling */
};

static void auth_worker_server_send_handshake(struct connection *conn)
{
	o_stream_nsend_str(conn->output, t_strdup_printf("PROCESS-LIMIT\t%u\n",
			   master_service_get_process_limit(master_service)));
}

struct auth_worker_server *
auth_worker_server_create(struct auth *auth,
			  const struct master_service_connection *master_conn)
{
	struct auth_worker_server *server;

	if (clients == NULL)
		clients = connection_list_init(&auth_worker_server_set,
					       &auth_worker_server_v);

	server = i_new(struct auth_worker_server, 1);
	server->refcount = 1;
	server->auth = auth;
	server->conn.event_parent = auth_event;
	server->conn.input_idle_timeout_secs = master_service_get_idle_kill_secs(master_service);
	connection_init_server(clients, &server->conn, master_conn->name,
			       master_conn->fd, master_conn->fd);
	auth_worker_server_send_handshake(&server->conn);

	auth_worker_refresh_proctitle(WORKER_STATE_HANDSHAKE);

	if (auth_worker_server_error)
		auth_worker_server_send_error();
	return server;
}

void auth_worker_server_send_error(void)
{
	struct auth_worker_server *auth_worker_server =
		auth_worker_get_client();
	auth_worker_server_error = TRUE;
	if (auth_worker_server != NULL &&
	    !auth_worker_server->error_sent) {
		o_stream_nsend_str(auth_worker_server->conn.output, "ERROR\n");
		auth_worker_server->error_sent = TRUE;
	}
	auth_worker_refresh_proctitle("");
}

void auth_worker_server_send_success(void)
{
	struct auth_worker_server *auth_worker_server =
		auth_worker_get_client();
	auth_worker_server_error = FALSE;
	if (auth_worker_server == NULL)
		return;
	if (auth_worker_server->error_sent) {
		o_stream_nsend_str(auth_worker_server->conn.output,
				   "SUCCESS\n");
		auth_worker_server->error_sent = FALSE;
	}
	if (auth_worker_server->conn.io != NULL)
		auth_worker_refresh_proctitle(WORKER_STATE_IDLE);
}

void auth_worker_server_send_shutdown(void)
{
	struct auth_worker_server *auth_worker_server =
		auth_worker_get_client();
	if (auth_worker_server != NULL)
		o_stream_nsend_str(auth_worker_server->conn.output,
				   "SHUTDOWN\n");
	auth_worker_refresh_proctitle(WORKER_STATE_STOP);
}

void auth_worker_connections_destroy_all(void)
{
	if (clients == NULL)
		return;
	while (clients->connections != NULL)
		connection_deinit(clients->connections);
	connection_list_deinit(&clients);
}

bool auth_worker_has_connections(void)
{
	return clients != NULL && clients->connections_count > 0;
}
