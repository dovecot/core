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
#include "auth-worker-client.h"


#define AUTH_WORKER_WARN_DISCONNECTED_LONG_CMD_SECS 30
#define OUTBUF_THROTTLE_SIZE (1024*10)

#define CLIENT_STATE_HANDSHAKE "handshaking"
#define CLIENT_STATE_ITER "iterating users"
#define CLIENT_STATE_IDLE "idling"
#define CLIENT_STATE_STOP "waiting for shutdown"

struct auth_worker_client {
	struct connection conn;
	int refcount;

        struct auth *auth;
	struct event *event;
	time_t cmd_start;

	bool error_sent:1;
	bool destroyed:1;
};

struct auth_worker_list_context {
	struct auth_worker_client *client;
	struct auth_request *auth_request;
	struct userdb_iterate_context *iter;
	bool sending, sent, done;
};

static struct connection_list *clients = NULL;
static struct auth_worker_client *auth_worker_client = NULL;
static bool auth_worker_client_error = FALSE;

static int auth_worker_output(struct auth_worker_client *client);
static void auth_worker_client_destroy(struct connection *conn);
static void auth_worker_client_unref(struct auth_worker_client **_client);

static void auth_worker_log_finished(struct auth_worker_client *client,
				     const char *error)
{
	struct event_passthrough *e = event_create_passthrough(client->event)->
		set_name("auth_worker_request_finished");
	if (error != NULL) {
		e->add_str("error", error);
		e_error(e->event(), "Finished: %s", error);
	} else {
		e_debug(e->event(), "Finished");
	}
}

void auth_worker_refresh_proctitle(const char *state)
{
	if (!global_auth_settings->verbose_proctitle || !worker)
		return;

	if (auth_worker_client_error)
		state = "error";
	else if (auth_worker_client == NULL)
		state = "waiting for connection";
	process_title_set(t_strdup_printf("worker: %s", state));
}

static void
auth_worker_client_check_throttle(struct auth_worker_client *client)
{
	if (o_stream_get_buffer_used_size(client->conn.output) >=
	    OUTBUF_THROTTLE_SIZE) {
		/* stop reading new requests until client has read the pending
		   replies. */
		connection_input_halt(&client->conn);
	}
}

bool auth_worker_auth_request_new(struct auth_worker_client *client, unsigned int id,
				  const char *const *args, struct auth_request **request_r)
{
	struct auth_request *auth_request;
	const char *key, *value;

	auth_request = auth_request_new_dummy();

	client->refcount++;
	auth_request->context = client;
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
	if (auth_request->user == NULL || auth_request->service == NULL) {
		auth_request_unref(&auth_request);
		return FALSE;
	}

	/* reset changed-fields, so we'll export only the ones that were
	   changed by this lookup. */
	auth_fields_snapshot(auth_request->extra_fields);
	if (auth_request->userdb_reply != NULL)
		auth_fields_snapshot(auth_request->userdb_reply);

	auth_request_init(auth_request);
	*request_r = auth_request;

	return TRUE;
}

static void auth_worker_send_reply(struct auth_worker_client *client,
				   struct auth_request *request,
				   string_t *str)
{
	time_t cmd_duration = time(NULL) - client->cmd_start;
	const char *p;

	if (worker_restart_request)
		o_stream_nsend_str(client->conn.output, "RESTART\n");
	o_stream_nsend(client->conn.output, str_data(str), str_len(str));
	if (o_stream_flush(client->conn.output) < 0 && request != NULL &&
	    cmd_duration > AUTH_WORKER_WARN_DISCONNECTED_LONG_CMD_SECS) {
		p = i_strchr_to_next(str_c(str), '\t');
		p = p == NULL ? "BUG" : t_strcut(p, '\t');

		e_warning(client->event, "Auth master disconnected us while handling "
			  "request for %s for %ld secs (result=%s)",
			  request->user, (long)cmd_duration, p);
	}
}

static void
reply_append_extra_fields(string_t *str, struct auth_request *request)
{
	if (!auth_fields_is_empty(request->extra_fields)) {
		str_append_c(str, '\t');
		/* export only the fields changed by this lookup, so the
		   changed-flag gets preserved correctly on the master side as
		   well. */
		auth_fields_append(request->extra_fields, str,
				   AUTH_FIELD_FLAG_CHANGED,
				   AUTH_FIELD_FLAG_CHANGED);
	}
	if (request->userdb_reply != NULL &&
	    auth_fields_is_empty(request->userdb_reply)) {
		/* all userdb_* fields had NULL values. we'll still
		   need to tell this to the master */
		str_append(str, "\tuserdb_"AUTH_REQUEST_USER_KEY_IGNORE);
	}
}

static void verify_plain_callback(enum passdb_result result,
				  struct auth_request *request)
{
	struct auth_worker_client *client = request->context;
	string_t *str;

	if (request->failed && result == PASSDB_RESULT_OK)
		result = PASSDB_RESULT_PASSWORD_MISMATCH;

	str = t_str_new(128);
	str_printfa(str, "%u\t", request->id);

	if (result == PASSDB_RESULT_OK)
		if (auth_fields_exists(request->extra_fields, "noauthenticate"))
			str_append(str, "NEXT");
		else
			str_append(str, "OK");
	else
		str_printfa(str, "FAIL\t%d", result);
	if (result != PASSDB_RESULT_INTERNAL_FAILURE) {
		str_append_c(str, '\t');
		if (request->user_changed_by_lookup)
			str_append_tabescaped(str, request->user);
		str_append_c(str, '\t');
		if (request->passdb_password != NULL)
			str_append_tabescaped(str, request->passdb_password);
		reply_append_extra_fields(str, request);
	}
	str_append_c(str, '\n');
	auth_worker_send_reply(client, request, str);

	auth_worker_log_finished(client, NULL);
	auth_request_unref(&request);
	auth_worker_client_check_throttle(client);
	auth_worker_client_unref(&client);
}

static bool
auth_worker_handle_passv(struct auth_worker_client *client,
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

	if (!auth_worker_auth_request_new(client, id, args + 2, &auth_request)) {
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
	passdb->passdb->iface.
		verify_plain(auth_request, password, verify_plain_callback);
	return TRUE;
}

static bool
auth_worker_handle_passw(struct auth_worker_client *client,
			 unsigned int id, const char *const *args,
			 const char **error_r)
{
	struct auth_request *request;
	string_t *str;
	const char *password;
	const char *crypted, *scheme;
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

	if (!auth_worker_auth_request_new(client, id, args + 3, &request)) {
		*error_r = "BUG: PASSW had missing parameters";
		return FALSE;
	}
	request->mech_password =
		p_strdup(request->pool, password);

	ret = auth_request_password_verify(request, password,
					   crypted, scheme, "cache");
	str = t_str_new(128);
	str_printfa(str, "%u\t", request->id);

	if (ret == 1)
		str_printfa(str, "OK\t\t");
	else if (ret == 0)
		str_printfa(str, "FAIL\t%d", PASSDB_RESULT_PASSWORD_MISMATCH);
	else
		str_printfa(str, "FAIL\t%d", PASSDB_RESULT_INTERNAL_FAILURE);

	str_append_c(str, '\n');
	auth_worker_send_reply(client, request, str);

	auth_worker_log_finished(client, NULL);
	auth_request_unref(&request);
	auth_worker_client_check_throttle(client);
	auth_worker_client_unref(&client);
	return TRUE;
}

static void
lookup_credentials_callback(enum passdb_result result,
			    const unsigned char *credentials, size_t size,
			    struct auth_request *request)
{
	struct auth_worker_client *client = request->context;
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
			str_append_tabescaped(str, request->user);
		str_append_c(str, '\t');
		if (request->credentials_scheme[0] != '\0') {
			str_printfa(str, "{%s.b64}", request->credentials_scheme);
			base64_encode(credentials, size, str);
		} else {
			i_assert(size == 0);
		}
		reply_append_extra_fields(str, request);
	}
	str_append_c(str, '\n');
	auth_worker_send_reply(client, request, str);

	auth_request_unref(&request);
	auth_worker_log_finished(client, NULL);
	auth_worker_client_check_throttle(client);
	auth_worker_client_unref(&client);
}

static bool
auth_worker_handle_passl(struct auth_worker_client *client,
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

	if (!auth_worker_auth_request_new(client, id, args + 2, &auth_request)) {
		*error_r = "BUG: PASSL had missing parameters";
		return FALSE;
	}
	auth_request->credentials_scheme = p_strdup(auth_request->pool, scheme);

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
	auth_request->passdb->passdb->iface.
		lookup_credentials(auth_request, lookup_credentials_callback);
	return TRUE;
}

static void
set_credentials_callback(bool success, struct auth_request *request)
{
	struct auth_worker_client *client = request->context;

	string_t *str;

	str = t_str_new(64);
	str_printfa(str, "%u\t%s\n", request->id, success ? "OK" : "FAIL");
	auth_worker_send_reply(client, request, str);

	auth_worker_log_finished(client, NULL);
	auth_request_unref(&request);
	auth_worker_client_check_throttle(client);
	auth_worker_client_unref(&client);
}

static bool
auth_worker_handle_setcred(struct auth_worker_client *client,
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

	if (!auth_worker_auth_request_new(client, id, args + 2, &auth_request)) {
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
	struct auth_worker_client *client = auth_request->context;
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
			str_append_tabescaped(str, auth_request->user);
		str_append_c(str, '\t');
		/* export only the fields changed by this lookup */
		auth_fields_append(auth_request->userdb_reply, str,
				   AUTH_FIELD_FLAG_CHANGED,
				   AUTH_FIELD_FLAG_CHANGED);
		if (auth_request->userdb_lookup_tempfailed)
			str_append(str, "\ttempfail");
		break;
	}
	str_append_c(str, '\n');

	auth_worker_send_reply(client, auth_request, str);

	auth_worker_log_finished(client, NULL);
	auth_request_unref(&auth_request);
	auth_worker_client_check_throttle(client);
	auth_worker_client_unref(&client);
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
auth_worker_handle_user(struct auth_worker_client *client,
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

	if (!auth_worker_auth_request_new(client, id, args + 1, &auth_request)) {
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

	if (auth_request->userdb_reply == NULL)
		auth_request_init_userdb_reply(auth_request);
	auth_request->userdb->userdb->iface->
		lookup(auth_request, lookup_user_callback);
	return TRUE;
}

static void
auth_worker_client_idle_kill(struct connection *conn ATTR_UNUSED)
{
	auth_worker_client_send_shutdown();
}

static void list_iter_deinit(struct auth_worker_list_context *ctx)
{
	struct auth_worker_client *client = ctx->client;
	string_t *str;

	i_assert(client->conn.io == NULL);

	str = t_str_new(32);
	if (ctx->auth_request->userdb->userdb->iface->
	    		iterate_deinit(ctx->iter) < 0)
		str_printfa(str, "%u\tFAIL\n", ctx->auth_request->id);
	else
		str_printfa(str, "%u\tOK\n", ctx->auth_request->id);
	auth_worker_send_reply(client, NULL, str);

	connection_input_resume(&client->conn);
	o_stream_set_flush_callback(client->conn.output, auth_worker_output,
				    client);
	auth_worker_log_finished(client, NULL);
	auth_request_unref(&ctx->auth_request);
	auth_worker_client_unref(&client);
	i_free(ctx);

	auth_worker_refresh_proctitle(CLIENT_STATE_IDLE);
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
		o_stream_cork(ctx->client->conn.output);
	T_BEGIN {
		str = t_str_new(128);
		str_printfa(str, "%u\t*\t%s\n", ctx->auth_request->id, user);
		o_stream_nsend(ctx->client->conn.output, str_data(str), str_len(str));
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
		if (o_stream_get_buffer_used_size(ctx->client->conn.output) > OUTBUF_THROTTLE_SIZE) {
			if (o_stream_flush(ctx->client->conn.output) < 0) {
				ctx->done = TRUE;
				break;
			}
		}
	} while (ctx->sent &&
		 o_stream_get_buffer_used_size(ctx->client->conn.output) <= OUTBUF_THROTTLE_SIZE);
	o_stream_uncork(ctx->client->conn.output);
	ctx->sending = FALSE;
	if (ctx->done)
		list_iter_deinit(ctx);
	else
		o_stream_set_flush_pending(ctx->client->conn.output, TRUE);
}

static int auth_worker_list_output(struct auth_worker_list_context *ctx)
{
	int ret;

	if ((ret = o_stream_flush(ctx->client->conn.output)) < 0) {
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
auth_worker_handle_list(struct auth_worker_client *client,
			unsigned int id, const char *const *args,
			const char **error_r)
{
	struct auth_worker_list_context *ctx;
	struct auth_userdb *userdb;
	unsigned int userdb_id;

	if (str_to_uint(args[0], &userdb_id) < 0) {
		*error_r = "BUG: Auth worker server sent us invalid LIST";
		return FALSE;
	}

	userdb = auth_userdb_find_by_id(client->auth->userdbs, userdb_id);
	if (userdb == NULL) {
		*error_r = "BUG: LIST had invalid userdb ID";
		return FALSE;
	}

	ctx = i_new(struct auth_worker_list_context, 1);
	ctx->client = client;
	if (!auth_worker_auth_request_new(client, id, args + 1, &ctx->auth_request)) {
		*error_r = "BUG: LIST had missing parameters";
		i_free(ctx);
		return FALSE;
	}
	ctx->auth_request->userdb = userdb;

	connection_input_halt(&ctx->client->conn);

	o_stream_set_flush_callback(ctx->client->conn.output,
				    auth_worker_list_output, ctx);
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

static int auth_worker_client_handshake_args(struct connection *conn, const char *const *args)
{
	if (!conn->version_received) {
		if (connection_handshake_args_default(conn, args) < 0)
			return -1;
		return 0;
	}

	if (str_array_length(args) < 3 ||
	    strcmp(args[0], "DBHASH") != 0) {
		i_error("BUG: Invalid input: %s", t_strarray_join(args, "\t"));
		return -1;
	}

	if (!auth_worker_verify_db_hash(args[1], args[2])) {
		i_error("Auth worker sees different passdbs/userdbs "
			"than auth server. Maybe config just changed "
			"and this goes away automatically?");
		return -1;
	}
	return 1;
}

static int
auth_worker_client_input_args(struct connection *conn, const char *const *args)
{
	unsigned int id;
	bool ret = FALSE;
	const char *error = NULL;
	struct auth_worker_client *client =
		container_of(conn, struct auth_worker_client, conn);

	if (str_array_length(args) < 3 ||
	    str_to_uint(args[0], &id) < 0) {
		i_error("BUG: Invalid input: %s", t_strarray_join(args, "\t"));
		return -1;
	}

	io_loop_time_refresh();
	if (client->event == NULL)
		client->event = event_create(client->conn.event);
	event_add_str(client->event, "command", args[1]);
	event_add_int(client->event, "id", id);
	event_set_append_log_prefix(client->event, t_strdup_printf("auth-worker<%u>: ", id));
	client->cmd_start = ioloop_time;
	client->refcount++;
	e_debug(client->event, "Handling %s request", args[1]);

	auth_worker_refresh_proctitle(args[1]);
	if (strcmp(args[1], "PASSV") == 0)
		ret = auth_worker_handle_passv(client, id, args + 2, &error);
	else if (strcmp(args[1], "PASSL") == 0)
		ret = auth_worker_handle_passl(client, id, args + 2, &error);
	else if (strcmp(args[1], "PASSW") == 0)
		ret = auth_worker_handle_passw(client, id, args + 2, &error);
	else if (strcmp(args[1], "SETCRED") == 0)
		ret = auth_worker_handle_setcred(client, id, args + 2, &error);
	else if (strcmp(args[1], "USER") == 0)
		ret = auth_worker_handle_user(client, id, args + 2, &error);
	else if (strcmp(args[1], "LIST") == 0)
		ret = auth_worker_handle_list(client, id, args + 2, &error);
	else {
		error = t_strdup_printf("BUG: Auth-worker received unknown command: %s",
			args[1]);
	}

	i_assert(ret || error != NULL);

	if (!ret) {
		auth_worker_log_finished(client, error);
	} else if (client->conn.io == NULL) {
		auth_worker_refresh_proctitle(CLIENT_STATE_IDLE);
	}
	auth_worker_client_unref(&client);
	return ret ? 1 : -1;
}

static int auth_worker_output(struct auth_worker_client *client)
{
	if (o_stream_flush(client->conn.output) < 0) {
		auth_worker_client_destroy(&client->conn);
		return 1;
	}

	if (o_stream_get_buffer_used_size(client->conn.output) <=
	    OUTBUF_THROTTLE_SIZE/3 && client->conn.io == NULL) {
		/* allow input again */
		connection_input_resume(&client->conn);
	}
	return 1;
}

static void auth_worker_client_unref(struct auth_worker_client **_client)
{
	struct auth_worker_client *client = *_client;
	if (client == NULL)
		return;
	if (--client->refcount > 0)
		return;

	/* the connection should've been destroyed before getting here */
	i_assert(client->destroyed);
	connection_deinit(&client->conn);
	i_free(client);
}

static void auth_worker_client_destroy(struct connection *conn)
{
	struct auth_worker_client *client =
		container_of(conn, struct auth_worker_client, conn);

	i_assert(!client->destroyed);
	client->destroyed = TRUE;
	connection_input_halt(conn);
	i_stream_close(conn->input);
	o_stream_close(conn->output);
	net_disconnect(conn->fd_in);
	conn->fd_out = conn->fd_in = -1;
	auth_worker_client_unref(&client);
	master_service_client_connection_destroyed(master_service);
}

static const struct connection_vfuncs auth_worker_client_v =
{
	.input_args = auth_worker_client_input_args,
	.handshake_args = auth_worker_client_handshake_args,
	.destroy = auth_worker_client_destroy,
	.idle_timeout = auth_worker_client_idle_kill,
};

static const struct connection_settings auth_worker_client_set =
{
	.service_name_in = "auth-worker",
	.service_name_out = "auth-worker",
	.major_version = AUTH_WORKER_PROTOCOL_MAJOR_VERSION,
	.minor_version = AUTH_WORKER_PROTOCOL_MINOR_VERSION,
	.input_max_size = (size_t)-1,
	.output_max_size = (size_t)-1, /* we use throttling */
};

struct auth_worker_client *
auth_worker_client_create(struct auth *auth,
			  const struct master_service_connection *master_conn)
{
	struct auth_worker_client *client;

	if (clients == NULL)
		clients = connection_list_init(&auth_worker_client_set, &auth_worker_client_v);

	client = i_new(struct auth_worker_client, 1);
	client->refcount = 1;
	client->auth = auth;
	client->conn.event_parent = auth_event;
	client->conn.input_idle_timeout_secs = master_service_get_idle_kill_secs(master_service);
	connection_init_server(clients, &client->conn, master_conn->name,
			       master_conn->fd, master_conn->fd);

	auth_worker_refresh_proctitle(CLIENT_STATE_HANDSHAKE);

	auth_worker_client = client;
	if (auth_worker_client_error)
		auth_worker_client_send_error();
	return client;
}

void auth_worker_client_send_error(void)
{
	auth_worker_client_error = TRUE;
	if (auth_worker_client != NULL &&
	    !auth_worker_client->error_sent) {
		o_stream_nsend_str(auth_worker_client->conn.output, "ERROR\n");
		auth_worker_client->error_sent = TRUE;
	}
	auth_worker_refresh_proctitle("");
}

void auth_worker_client_send_success(void)
{
	auth_worker_client_error = FALSE;
	if (auth_worker_client == NULL)
		return;
	if (auth_worker_client->error_sent) {
		o_stream_nsend_str(auth_worker_client->conn.output,
				   "SUCCESS\n");
		auth_worker_client->error_sent = FALSE;
	}
	if (auth_worker_client->conn.io != NULL)
		auth_worker_refresh_proctitle(CLIENT_STATE_IDLE);
}

void auth_worker_client_send_shutdown(void)
{
	if (auth_worker_client != NULL)
		o_stream_nsend_str(auth_worker_client->conn.output,
				   "SHUTDOWN\n");
	auth_worker_refresh_proctitle(CLIENT_STATE_STOP);
}

void auth_worker_connections_destroy_all(void)
{
	if (clients == NULL)
		return;
	while (clients->connections != NULL)
		connection_deinit(clients->connections);
	connection_list_deinit(&clients);
}

bool auth_worker_has_client(void)
{
	return clients != NULL && clients->connections_count > 0;
}
