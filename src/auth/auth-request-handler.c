/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "ioloop.h"
#include "array.h"
#include "aqueue.h"
#include "base64.h"
#include "hash.h"
#include "net.h"
#include "str.h"
#include "strescape.h"
#include "str-sanitize.h"
#include "master-interface.h"
#include "auth-penalty.h"
#include "auth-request.h"
#include "auth-token.h"
#include "auth-client-connection.h"
#include "auth-master-connection.h"
#include "auth-request-handler.h"
#include "auth-request-handler-private.h"
#include "auth-policy.h"

#define AUTH_FAILURE_DELAY_CHECK_MSECS 500
static ARRAY(struct auth_request *) auth_failures_arr;
static struct aqueue *auth_failures;
static struct timeout *to_auth_failures;

static void auth_failure_timeout(void *context) ATTR_NULL(1);


static void
auth_request_handler_default_reply_callback(struct auth_request *request,
					    enum auth_client_result result,
					    const void *auth_reply,
					    size_t reply_size);

static void
auth_request_handler_default_reply_continue(struct auth_request *request,
					    const void *reply,
					    size_t reply_size);

struct auth_request_handler *
auth_request_handler_create(bool token_auth, auth_client_request_callback_t *callback,
			    struct auth_client_connection *conn,
			    auth_master_request_callback_t *master_callback)
{
	struct auth_request_handler *handler;
	pool_t pool;

	pool = pool_alloconly_create("auth request handler", 4096);

	handler = p_new(pool, struct auth_request_handler, 1);
	handler->refcount = 1;
	handler->pool = pool;
	hash_table_create_direct(&handler->requests, pool, 0);
	handler->callback = callback;
	handler->conn = conn;
	handler->master_callback = master_callback;
	handler->token_auth = token_auth;
	handler->reply_callback =
		auth_request_handler_default_reply_callback;
	handler->reply_continue_callback =
		auth_request_handler_default_reply_continue;
	handler->verify_plain_continue_callback =
		auth_request_default_verify_plain_continue;
	return handler;
}

unsigned int
auth_request_handler_get_request_count(struct auth_request_handler *handler)
{
	return hash_table_count(handler->requests);
}

void auth_request_handler_abort_requests(struct auth_request_handler *handler)
{
	struct hash_iterate_context *iter;
	void *key;
	struct auth_request *auth_request;

	iter = hash_table_iterate_init(handler->requests);
	while (hash_table_iterate(iter, handler->requests, &key, &auth_request)) {
		switch (auth_request->state) {
		case AUTH_REQUEST_STATE_NEW:
		case AUTH_REQUEST_STATE_MECH_CONTINUE:
		case AUTH_REQUEST_STATE_FINISHED:
			auth_request->removed_from_handler = TRUE;
			auth_request_unref(&auth_request);
			hash_table_remove(handler->requests, key);
			break;
		case AUTH_REQUEST_STATE_PASSDB:
		case AUTH_REQUEST_STATE_USERDB:
			/* can't abort a pending passdb/userdb lookup */
			break;
		case AUTH_REQUEST_STATE_MAX:
			i_unreached();
		}
	}
	hash_table_iterate_deinit(&iter);
}

void auth_request_handler_unref(struct auth_request_handler **_handler)
{
        struct auth_request_handler *handler = *_handler;

	if (handler == NULL)
		return;
	*_handler = NULL;

	i_assert(handler->refcount > 0);
	if (--handler->refcount > 0)
		return;

	i_assert(hash_table_count(handler->requests) == 0);

	/* notify parent that we're done with all requests */
	handler->callback(NULL, handler->conn);

	hash_table_destroy(&handler->requests);
	pool_unref(&handler->pool);
}

void auth_request_handler_destroy(struct auth_request_handler **_handler)
{
	struct auth_request_handler *handler = *_handler;

	*_handler = NULL;

	i_assert(!handler->destroyed);

	handler->destroyed = TRUE;
	auth_request_handler_unref(&handler);
}

void auth_request_handler_set(struct auth_request_handler *handler,
			      unsigned int connect_uid,
			      unsigned int client_pid)
{
	handler->connect_uid = connect_uid;
	handler->client_pid = client_pid;
}

static void auth_request_handler_remove(struct auth_request_handler *handler,
					struct auth_request *request)
{
	i_assert(request->handler == handler);

	if (request->removed_from_handler) {
		/* already removed it */
		return;
	}
	request->removed_from_handler = TRUE;

	/* if db lookup is stuck, this call doesn't actually free the auth
	   request, so make sure we don't get back here. */
	timeout_remove(&request->to_abort);

	hash_table_remove(handler->requests, POINTER_CAST(request->id));
	auth_request_unref(&request);
}

static void
auth_str_add_keyvalue(string_t *dest, const char *key, const char *value)
{
	str_append_c(dest, '\t');
	str_append(dest, key);
	str_append_c(dest, '=');
	str_append_tabescaped(dest, value);
}

static void
auth_str_append_extra_fields(struct auth_request *request, string_t *dest)
{
	const struct auth_request_fields *fields = &request->fields;

	auth_fields_append(fields->extra_fields, dest,
			   AUTH_FIELD_FLAG_HIDDEN, 0, TRUE);

	if (fields->original_username != NULL &&
	    null_strcmp(fields->original_username, fields->user) != 0 &&
	    !auth_fields_exists(fields->extra_fields, "original_user")) {
		auth_str_add_keyvalue(dest, "original_user",
				      fields->original_username);
	}
	if (fields->master_user != NULL &&
	    !auth_fields_exists(fields->extra_fields, "auth_user"))
		auth_str_add_keyvalue(dest, "auth_user", fields->master_user);
	if (*request->set->anonymous_username != '\0' &&
	    null_strcmp(fields->user, request->set->anonymous_username) == 0) {
		/* this is an anonymous login, either via ANONYMOUS
		   SASL mechanism or simply logging in as the anonymous
		   user via another mechanism */
		str_append(dest, "\tanonymous");
	}
	if (!request->auth_only &&
	    auth_fields_exists(fields->extra_fields, "proxy")) {
		/* we're proxying */
		if (!auth_fields_exists(fields->extra_fields, "pass") &&
		    request->mech_password != NULL) {
			/* send back the password that was sent by user
			   (not the password in passdb). */
			auth_str_add_keyvalue(dest, "pass",
					      request->mech_password);
		}
		if (fields->master_user != NULL &&
		    !auth_fields_exists(fields->extra_fields, "master") &&
		    *fields->master_user != '\0') {
			/* the master username needs to be forwarded */
			auth_str_add_keyvalue(dest, "master",
					      fields->master_user);
		}
	}
}

static bool auth_request_want_failure_delay(struct auth_request *request)
{
	if (request->failure_nodelay) {
		/* passdb specifically requested not to delay the reply. */
		e_debug(request->event, "immediate auth failure due to nodelay");
		return FALSE;
	}
	if (request->internal_failure) {
		/* internal failures have their own delay */
		e_debug(request->event, "immediate auth failure due to internal failure");
		return FALSE;
	}
	if (request->set->failure_delay == 0) {
		/* Auth failure delays are disabled entirely. This is mainly
		   intended for making tests faster. */
		e_debug(request->event, "immediate auth failure due to auth_failure_delay=0");
		return FALSE;
	}
	if (shutting_down) {
		/* process is shutting down - finish failures immediately. */
		e_debug(request->event, "immediate auth failure due to shutting down");
		return FALSE;
	}
	return TRUE;
}

static void
auth_request_handle_failure(struct auth_request *request, const char *reply)
{
        struct auth_request_handler *handler = request->handler;

	/* handle failure here */
	auth_request_log_finished(request);

	if (request->in_delayed_failure_queue) {
		/* we came here from flush_failures() */
		handler->callback(reply, handler->conn);
		return;
	}

	/* remove the request from requests-list */
	auth_request_ref(request);
	auth_request_handler_remove(handler, request);

	if (request->set->policy_report_after_auth)
		auth_policy_report(request);

	if (!auth_request_want_failure_delay(request)) {
		handler->callback(reply, handler->conn);
		auth_request_unref(&request);
		return;
	}
	e_debug(request->event, "delaying auth failure");

	/* failure. don't announce it immediately to avoid
	   a) timing attacks, b) flooding */
	request->in_delayed_failure_queue = TRUE;
	handler->refcount++;

	if (auth_penalty != NULL) {
		auth_penalty_update(auth_penalty, request,
				    request->last_penalty + 1);
	}

	auth_request_refresh_last_access(request);
	aqueue_append(auth_failures, &request);
	if (to_auth_failures == NULL) {
		to_auth_failures =
			timeout_add_short(AUTH_FAILURE_DELAY_CHECK_MSECS,
					  auth_failure_timeout, NULL);
	}
}

static void
auth_request_handler_reply_continue_finish(struct auth_request *request,
					   const void *auth_reply,
					   size_t reply_size)
{
        struct auth_request_handler *handler = request->handler;
	string_t *str;

	str = t_str_new(64 + MAX_BASE64_ENCODED_SIZE(reply_size));
	str_printfa(str, "CONT\t%u\t", request->id);
	if (auth_reply == NULL) {
		/* Send out-of-band challenge */
		str_append_c(str, '#');
	} else {
		/* Send normal challenge */
		base64_encode(auth_reply, reply_size, str);
	}
	if (request->fields.channel_binding.type != NULL &&
	    handler->conn->conn.minor_version >=
		AUTH_CLIENT_MINOR_VERSION_CHANNEL_BINDING) {
		auth_str_add_keyvalue(str, "channel_binding",
				      request->fields.channel_binding.type);
	}

	request->accept_cont_input = TRUE;
	handler->callback(str_c(str), handler->conn);
}

static void
auth_request_handler_reply_success_finish(struct auth_request *request)
{
        struct auth_request_handler *handler = request->handler;
	string_t *str = t_str_new(128);

	auth_request_log_finished(request);

	if (request->last_penalty != 0 && auth_penalty != NULL) {
		/* reset penalty */
		auth_penalty_update(auth_penalty, request, 0);
	}

	str_printfa(str, "OK\t%u\tuser=", request->id);
	str_append_tabescaped(str, request->fields.user);
	auth_str_append_extra_fields(request, str);

	if (request->set->policy_report_after_auth)
		auth_policy_report(request);

	if (handler->master_callback == NULL ||
	    auth_fields_exists(request->fields.extra_fields, "nologin") ||
	    auth_fields_exists(request->fields.extra_fields, "proxy")) {
		/* this request doesn't have to wait for master
		   process to pick it up. delete it */
		auth_request_handler_remove(handler, request);
	}

	handler->callback(str_c(str), handler->conn);
}

static void
auth_request_handler_reply_failure_finish(struct auth_request *request)
{
	const char *code = NULL;
	string_t *str = t_str_new(128);

	auth_fields_remove(request->fields.extra_fields, "nologin");

	str_printfa(str, "FAIL\t%u", request->id);
	if (request->fields.user != NULL)
		auth_str_add_keyvalue(str, "user", request->fields.user);
	else if (request->fields.original_username != NULL) {
		auth_str_add_keyvalue(str, "user",
				      request->fields.original_username);
	}

	if (request->internal_failure) {
		code = AUTH_CLIENT_FAIL_CODE_TEMPFAIL;
	} else if (request->fields.master_user != NULL) {
		/* authentication succeeded, but we can't log in
		   as the wanted user */
		code = AUTH_CLIENT_FAIL_CODE_AUTHZFAILED;
	} else {
		switch (request->passdb_result) {
		case PASSDB_RESULT_NEXT:
		case PASSDB_RESULT_INTERNAL_FAILURE:
		case PASSDB_RESULT_SCHEME_NOT_AVAILABLE:
		case PASSDB_RESULT_USER_UNKNOWN:
		case PASSDB_RESULT_PASSWORD_MISMATCH:
		case PASSDB_RESULT_OK:
			break;
		case PASSDB_RESULT_USER_DISABLED:
			code = AUTH_CLIENT_FAIL_CODE_USER_DISABLED;
			break;
		case PASSDB_RESULT_PASS_EXPIRED:
			code = AUTH_CLIENT_FAIL_CODE_PASS_EXPIRED;
			break;
		}
	}

	if (code != NULL) {
		str_append(str, "\tcode=");
		str_append(str, code);
	}
	auth_str_append_extra_fields(request, str);

	auth_request_handle_failure(request, str_c(str));
}

static void
auth_request_handler_proxy_callback(bool success, struct auth_request *request)
{
        struct auth_request_handler *handler = request->handler;

	if (success && !request->internal_failure)
		auth_request_handler_reply_success_finish(request);
	else
		auth_request_handler_reply_failure_finish(request);
        auth_request_handler_unref(&handler);
}

void auth_request_handler_reply(struct auth_request *request,
				enum auth_client_result result,
				const void *auth_reply, size_t reply_size)
{
	struct auth_request_handler *handler = request->handler;

	request->handler_pending_reply = FALSE;
	handler->reply_callback(request, result, auth_reply, reply_size);
}

static void
auth_request_handler_default_reply_callback(struct auth_request *request,
					    enum auth_client_result result,
					    const void *auth_reply,
					    size_t reply_size)
{
        struct auth_request_handler *handler = request->handler;
	string_t *str;
	int ret;

	if (handler->destroyed) {
		/* the client connection was already closed. we can't do
		   anything but abort this request */
		request->internal_failure = TRUE;
		result = AUTH_CLIENT_RESULT_FAILURE;
		/* make sure this request is set to finished state
		   (it's not with result=continue) */
		auth_request_set_state(request, AUTH_REQUEST_STATE_FINISHED);
	}

	switch (result) {
	case AUTH_CLIENT_RESULT_CONTINUE:
		auth_request_handler_reply_continue_finish(request, auth_reply,
							   reply_size);
		break;
	case AUTH_CLIENT_RESULT_SUCCESS:
		if (reply_size > 0) {
			str = t_str_new(MAX_BASE64_ENCODED_SIZE(reply_size));
			base64_encode(auth_reply, reply_size, str);
			auth_fields_add(request->fields.extra_fields, "resp",
					str_c(str), 0);
		}
		ret = auth_request_proxy_finish(request,
				auth_request_handler_proxy_callback);
		if (ret < 0)
			auth_request_handler_reply_failure_finish(request);
		else if (ret > 0)
			auth_request_handler_reply_success_finish(request);
		else
			return;
		break;
	case AUTH_CLIENT_RESULT_FAILURE:
		auth_request_proxy_finish_failure(request);
		if (reply_size > 0) {
			str = t_str_new(MAX_BASE64_ENCODED_SIZE(reply_size));
			base64_encode(auth_reply, reply_size, str);
			auth_fields_add(request->fields.extra_fields, "resp",
					str_c(str), 0);
		}
		auth_request_handler_reply_failure_finish(request);
		break;
	}
	/* NOTE: request may be destroyed now */

        auth_request_handler_unref(&handler);
}

void auth_request_handler_reply_continue(struct auth_request *request,
					 const void *reply, size_t reply_size)
{
	request->handler->reply_continue_callback(request, reply, reply_size);
}

static void
auth_request_handler_default_reply_continue(struct auth_request *request,
					    const void *reply,
					    size_t reply_size)
{
	auth_request_handler_reply(request, AUTH_CLIENT_RESULT_CONTINUE,
				   reply, reply_size);
}

void auth_request_handler_abort(struct auth_request *request)
{
	i_assert(request->handler_pending_reply);

	/* request destroyed while waiting for auth_request_penalty_finish()
	   to be called. */
	auth_request_handler_unref(&request->handler);
}

static void
auth_request_handler_auth_fail_code(struct auth_request_handler *handler,
					   struct auth_request *request,
					   const char *fail_code, const char *reason)
{
	string_t *str = t_str_new(128);

	e_info(request->event, "%s", reason);

	str_printfa(str, "FAIL\t%u", request->id);
	if (*fail_code != '\0') {
		str_append(str, "\tcode=");
		str_append(str, fail_code);
	}
	str_append(str, "\treason=");
	str_append_tabescaped(str, reason);

	handler->callback(str_c(str), handler->conn);
	auth_request_handler_remove(handler, request);
}

static void auth_request_handler_auth_fail
(struct auth_request_handler *handler, struct auth_request *request,
					   const char *reason)
{
	auth_request_handler_auth_fail_code(handler, request, "", reason);
}

static void auth_request_timeout(struct auth_request *request)
{
	unsigned int secs = (unsigned int)(time(NULL) - request->last_access);

	if (request->state != AUTH_REQUEST_STATE_MECH_CONTINUE) {
		/* client's fault */
		e_error(request->event,
			"Request %u.%u timed out after %u secs, state=%d",
			request->handler->client_pid, request->id,
			secs, request->state);
	} else {
		e_info(request->event,
		       "Request timed out waiting for client to continue authentication "
		       "(%u secs)", secs);
	}
	auth_request_handler_remove(request->handler, request);
}

static void auth_request_penalty_finish(struct auth_request *request)
{
	timeout_remove(&request->to_penalty);
	auth_request_initial(request);
}

static void
auth_penalty_callback(unsigned int penalty, struct auth_request *request)
{
	unsigned int secs;

	request->last_penalty = penalty;

	if (penalty == 0)
		auth_request_initial(request);
	else {
		secs = auth_penalty_to_secs(penalty);
		request->to_penalty = timeout_add(secs * 1000,
						  auth_request_penalty_finish,
						  request);
	}
}

int auth_request_handler_auth_begin(struct auth_request_handler *handler,
				    const char *const *args)
{
	const struct mech_module *mech;
	struct auth_request *request;
	const char *name, *arg, *initial_resp;
	void *initial_resp_data;
	unsigned int id;
	buffer_t *buf;

	i_assert(!handler->destroyed);

	/* <id> <mechanism> [...] */
	if (args[0] == NULL || args[1] == NULL ||
	    str_to_uint(args[0], &id) < 0 || id == 0) {
		e_error(handler->conn->conn.event,
			"BUG: Authentication client %u "
			"sent broken AUTH request", handler->client_pid);
		return -1;
	}

	if (handler->token_auth) {
		mech = &mech_dovecot_token;
		if (strcmp(args[1], mech->mech_name) != 0) {
			/* unsupported mechanism */
			e_error(handler->conn->conn.event,
				"BUG: Authentication client %u requested invalid "
				"authentication mechanism %s (DOVECOT-TOKEN required)",
				handler->client_pid, str_sanitize(args[1], MAX_MECH_NAME_LEN));
			return -1;
		}
	} else {
		struct auth *auth_default = auth_default_protocol();
		mech = mech_register_find(auth_default->reg, args[1]);
		if (mech == NULL) {
			/* unsupported mechanism */
			e_error(handler->conn->conn.event,
				"BUG: Authentication client %u requested unsupported "
				"authentication mechanism %s", handler->client_pid,
				str_sanitize(args[1], MAX_MECH_NAME_LEN));
			return -1;
		}
	}

	request = auth_request_new(mech, handler->conn->conn.event);
	request->handler = handler;
	request->connect_uid = handler->connect_uid;
	request->client_pid = handler->client_pid;
	request->id = id;
	request->auth_only = handler->master_callback == NULL;

	/* parse optional parameters */
	initial_resp = NULL;
	for (args += 2; *args != NULL; args++) {
		arg = strchr(*args, '=');
		if (arg == NULL) {
			name = *args;
			arg = "";
		} else {
			name = t_strdup_until(*args, arg);
			arg++;
		}

		if (auth_request_import_auth(request, name, arg))
			;
		else if (strcmp(name, "resp") == 0) {
			initial_resp = arg;
			/* this must be the last parameter */
			args++;
			break;
		}
	}

	if (*args != NULL) {
		e_error(handler->conn->conn.event,
			"BUG: Authentication client %u "
			"sent AUTH parameters after 'resp'",
			handler->client_pid);
		auth_request_unref(&request);
		return -1;
	}

	if (request->fields.protocol == NULL) {
		e_error(handler->conn->conn.event,
			"BUG: Authentication client %u "
			"didn't specify protocol in request",
			handler->client_pid);
		auth_request_unref(&request);
		return -1;
	}
	if (hash_table_lookup(handler->requests, POINTER_CAST(id)) != NULL) {
		e_error(handler->conn->conn.event,
			"BUG: Authentication client %u "
			"sent a duplicate ID %u", handler->client_pid, id);
		auth_request_unref(&request);
		return -1;
	}
	auth_request_init(request);

	request->to_abort = timeout_add(MASTER_AUTH_SERVER_TIMEOUT_SECS * 1000,
					auth_request_timeout, request);
	hash_table_insert(handler->requests, POINTER_CAST(id), request);

	if (request->set->ssl_require_client_cert &&
	    !request->fields.valid_client_cert) {
		/* we fail without valid certificate */
                auth_request_handler_auth_fail(handler, request,
			"Client didn't present valid SSL certificate");
		return 1;
	}

	 if (request->set->ssl_require_client_cert &&
	     request->set->ssl_username_from_cert &&
	     !request->fields.cert_username) {
		  auth_request_handler_auth_fail(handler, request,
			 "SSL certificate didn't contain username");
		 return 1;
	 }

	/* Handle initial response */
	if (initial_resp == NULL) {
		/* No initial response */
		request->initial_response = NULL;
		request->initial_response_len = 0;
	} else if (handler->conn->conn.minor_version < 2 && *initial_resp == '\0') {
		/* Some authentication clients like Exim send and empty initial
		   response field when it is in fact absent in the
		   authentication command. This was allowed for older versions
		   of the Dovecot authentication protocol. */
		request->initial_response = NULL;
		request->initial_response_len = 0;
	} else if (*initial_resp == '\0' || strcmp(initial_resp, "=") == 0 ) {
		/* Empty initial response - Protocols that use SASL often
		   use '=' to indicate an empty initial response; i.e., to
		   distinguish it from an absent initial response. However, that
		   should not be conveyed to the SASL layer (it is not even
		   valid Base64); only the empty string should be passed on.
		   Still, we recognize it here anyway, because we used to make
		   the same mistake. */
		request->initial_response = uchar_empty_ptr;
		request->initial_response_len = 0;
	} else {
		size_t len = strlen(initial_resp);

		/* Initial response encoded in Bas64 */
		buf = t_buffer_create(MAX_BASE64_DECODED_SIZE(len));
		if (base64_decode(initial_resp, len, buf) < 0) {
			auth_request_handler_auth_fail_code(handler, request,
				AUTH_CLIENT_FAIL_CODE_INVALID_BASE64,
				"Invalid base64 data in initial response");
			return 1;
		}
		initial_resp_data =
			p_malloc(request->pool, I_MAX(buf->used, 1));
		memcpy(initial_resp_data, buf->data, buf->used);
		request->initial_response = initial_resp_data;
		request->initial_response_len = buf->used;
	}

	/* handler is referenced until auth_request_handler_reply()
	   is called. */
	handler->refcount++;
	request->handler_pending_reply = TRUE;

	/* before we start authenticating, see if we need to wait first */
	auth_penalty_lookup(auth_penalty, request, auth_penalty_callback);
	return 1;
}

int auth_request_handler_auth_continue(struct auth_request_handler *handler,
				       const char *const *args)
{
	struct auth_request *request;
	const char *name, *arg;
	const char *data;
	size_t data_len;
	buffer_t *buf;
	unsigned int id;

	if (args[0] == NULL || str_to_uint(args[0], &id) < 0) {
		e_error(handler->conn->conn.event,
			"BUG: Authentication client sent broken CONT request");
		return -1;
	}

	request = hash_table_lookup(handler->requests, POINTER_CAST(id));
	if (request == NULL) {
		const char *reply = t_strdup_printf(
			"FAIL\t%u\treason=Authentication request timed out", id);
		handler->callback(reply, handler->conn);
		return 1;
	}

	/* accept input only once after mechanism has sent a CONT reply */
	if (!request->accept_cont_input) {
		auth_request_handler_auth_fail(handler, request,
					       "Unexpected continuation");
		return 1;
	}
	if (args[1] == NULL) {
		e_error(handler->conn->conn.event,
			"BUG: Authentication client sent broken CONT request");
		return -1;
	}

	request->accept_cont_input = FALSE;

	data = args[1];
	data_len = strlen(data);
	if (data_len == 1 && *data == '#') {
		/* Out-of-band response */
		buf = NULL;
	} else {
		/* Normal SASL response */
		buf = t_buffer_create(MAX_BASE64_DECODED_SIZE(data_len));
		if ((handler->conn->conn.minor_version <
			AUTH_CLIENT_MINOR_VERSION_CHANNEL_BINDING &&
		     args[2] != NULL) ||
		    base64_decode(data, data_len, buf) < 0) {
			auth_request_handler_auth_fail_code(handler, request,
				AUTH_CLIENT_FAIL_CODE_INVALID_BASE64,
				"Invalid base64 data in continued response");
			return -1;
		}
	}

	for (args += 2; *args != NULL; args++) {
		t_split_key_value_eq(*args, &name, &arg);
		auth_request_import_continue(request, name, arg);
	}

	/* handler is referenced until auth_request_handler_reply()
	   is called. */
	handler->refcount++;
	if (buf == NULL)
		auth_request_continue(request, NULL, 0);
	else
		auth_request_continue(request, buf->data, buf->used);
	return 1;
}

static void auth_str_append_userdb_extra_fields(struct auth_request *request,
						string_t *dest)
{
	auth_fields_append(request->fields.userdb_reply, dest,
			   AUTH_FIELD_FLAG_HIDDEN, 0, TRUE);

	if (request->fields.master_user != NULL &&
	    !auth_fields_exists(request->fields.userdb_reply, "master_user")) {
		auth_str_add_keyvalue(dest, "master_user",
				      request->fields.master_user);
	}
	auth_str_add_keyvalue(dest, "auth_mech", request->mech->mech_name);
	if (*request->set->anonymous_username != '\0' &&
	    strcmp(request->fields.user, request->set->anonymous_username) == 0) {
		/* this is an anonymous login, either via ANONYMOUS
		   SASL mechanism or simply logging in as the anonymous
		   user via another mechanism */
		str_append(dest, "\tanonymous");
	}
	/* generate auth_token when master service provided session_pid */
	if (request->request_auth_token &&
	    request->session_pid != (pid_t)-1) {
		const char *auth_token =
			auth_token_get(request->fields.protocol,
				       dec2str(request->session_pid),
				       request->fields.user,
				       request->fields.session_id);
		auth_str_add_keyvalue(dest, "auth_token", auth_token);
	}
	if (request->fields.master_user != NULL) {
		auth_str_add_keyvalue(dest, "auth_user",
				      request->fields.master_user);
	} else if (request->fields.original_username != NULL &&
		   strcmp(request->fields.original_username,
			  request->fields.user) != 0) {
		auth_str_add_keyvalue(dest, "auth_user",
				      request->fields.original_username);
	}
	if (request->fields.local_name != NULL) {
		auth_str_add_keyvalue(dest, "local_name",
				      request->fields.local_name);
	}
}

static void userdb_callback(enum userdb_result result,
			    struct auth_request *request)
{
        struct auth_request_handler *handler = request->handler;
	string_t *str;
	const char *value;

	i_assert(request->state == AUTH_REQUEST_STATE_USERDB);

	auth_request_set_state(request, AUTH_REQUEST_STATE_FINISHED);

	if (request->userdb_lookup_tempfailed)
		result = USERDB_RESULT_INTERNAL_FAILURE;

	str = t_str_new(128);
	switch (result) {
	case USERDB_RESULT_INTERNAL_FAILURE:
		str_printfa(str, "FAIL\t%u", request->id);
		if (request->userdb_lookup_tempfailed) {
			value = auth_fields_find(request->fields.userdb_reply,
						 "reason");
			if (value != NULL)
				auth_str_add_keyvalue(str, "reason", value);
		}
		break;
	case USERDB_RESULT_USER_UNKNOWN:
		str_printfa(str, "NOTFOUND\t%u", request->id);
		break;
	case USERDB_RESULT_OK:
		str_printfa(str, "USER\t%u\t", request->id);
		str_append_tabescaped(str, request->fields.user);
		auth_str_append_userdb_extra_fields(request, str);
		break;
	}
	handler->master_callback(str_c(str), request->master);

	auth_master_connection_unref(&request->master);
	auth_request_unref(&request);
        auth_request_handler_unref(&handler);
}

static bool
auth_master_request_failed(struct auth_request_handler *handler,
			   struct auth_master_connection *master,
			   unsigned int id)
{
	if (handler->master_callback == NULL)
		return FALSE;
	handler->master_callback(t_strdup_printf("FAIL\t%u", id), master);
	return TRUE;
}

bool auth_request_handler_master_request(struct auth_request_handler *handler,
					 struct auth_master_connection *master,
					 unsigned int id, unsigned int client_id,
					 const char *const *params)
{
	struct auth_request *request;
	struct net_unix_cred cred;

	request = hash_table_lookup(handler->requests, POINTER_CAST(client_id));
	if (request == NULL) {
		e_error(master->conn.event, "Master request %u.%u not found",
			handler->client_pid, client_id);
		return auth_master_request_failed(handler, master, id);
	}

	auth_request_ref(request);
	auth_request_handler_remove(handler, request);

	for (; *params != NULL; params++) {
		const char *name, *param = strchr(*params, '=');

		if (param == NULL) {
			name = *params;
			param = "";
		} else {
			name = t_strdup_until(*params, param);
			param++;
		}

		(void)auth_request_import_master(request, name, param);
	}

	/* verify session pid if specified and possible */
	if (request->session_pid != (pid_t)-1 &&
	    net_getunixcred(master->conn.fd_in, &cred) == 0 &&
	    cred.pid != (pid_t)-1 && request->session_pid != cred.pid) {
		e_error(master->conn.event,
			"Session pid %ld provided by master for request %u.%u "
			"did not match peer credentials (pid=%ld, uid=%ld)",
			(long)request->session_pid,
			handler->client_pid, client_id,
			(long)cred.pid, (long)cred.uid);
		return auth_master_request_failed(handler, master, id);
	}

	if (request->state != AUTH_REQUEST_STATE_FINISHED ||
	    !request->fields.successful) {
		e_error(master->conn.event,
			"Master requested unfinished authentication request "
			"%u.%u", handler->client_pid, client_id);
		handler->master_callback(t_strdup_printf("FAIL\t%u", id),
					 master);
		auth_request_unref(&request);
	} else {
		/* the request isn't being referenced anywhere anymore,
		   so we can do a bit of kludging.. replace the request's
		   old client_id with master's id. */
		auth_request_set_state(request, AUTH_REQUEST_STATE_USERDB);
		request->id = id;
		request->master = master;

		/* master and handler are referenced until userdb_callback i
		   s called. */
		auth_master_connection_ref(master);
		handler->refcount++;
		auth_request_lookup_user(request, userdb_callback);
	}
	return TRUE;
}

void auth_request_handler_cancel_request(struct auth_request_handler *handler,
					 unsigned int client_id)
{
	struct auth_request *request;

	request = hash_table_lookup(handler->requests, POINTER_CAST(client_id));
	if (request != NULL)
		auth_request_handler_remove(handler, request);
}

void auth_request_handler_flush_failures(bool flush_all)
{
	struct auth_request **auth_requests, *auth_request;
	unsigned int i, j, count;
	time_t diff;

	count = aqueue_count(auth_failures);
	if (count == 0) {
		timeout_remove(&to_auth_failures);
		return;
	}

	auth_requests = array_front_modifiable(&auth_failures_arr);
	/* count the number of requests that we need to flush */
	for (i = 0; i < count; i++) {
		auth_request = auth_requests[aqueue_idx(auth_failures, i)];

		/* FIXME: assumes that failure_delay is always the same. */
		diff = ioloop_time - auth_request->last_access;
		if (diff < (time_t)auth_request->set->failure_delay &&
		    !flush_all)
			break;
	}

	/* shuffle these requests to try to prevent any kind of timing attacks
	   where attacker performs multiple requests in parallel and attempts
	   to figure out results based on the order of replies. */
	count = i;
	for (i = 0; i < count; i++) {
		j = i_rand_minmax(i, count - 1);
		auth_request = auth_requests[aqueue_idx(auth_failures, i)];

		/* swap i & j */
		auth_requests[aqueue_idx(auth_failures, i)] =
			auth_requests[aqueue_idx(auth_failures, j)];
		auth_requests[aqueue_idx(auth_failures, j)] = auth_request;
	}

	/* flush the requests */
	for (i = 0; i < count; i++) T_BEGIN {
		auth_request = auth_requests[aqueue_idx(auth_failures, 0)];
		aqueue_delete_tail(auth_failures);

		i_assert(auth_request != NULL);
		i_assert(auth_request->state == AUTH_REQUEST_STATE_FINISHED);
		auth_request_handler_reply(auth_request,
					   AUTH_CLIENT_RESULT_FAILURE,
					   uchar_empty_ptr, 0);
		auth_request_unref(&auth_request);
	} T_END;
}

static void auth_failure_timeout(void *context ATTR_UNUSED)
{
	auth_request_handler_flush_failures(FALSE);
}

void auth_request_handler_init(void)
{
	i_array_init(&auth_failures_arr, 128);
	auth_failures = aqueue_init(&auth_failures_arr.arr);
}

void auth_request_handler_deinit(void)
{
	auth_request_handler_flush_failures(TRUE);
	array_free(&auth_failures_arr);
	aqueue_deinit(&auth_failures);

	timeout_remove(&to_auth_failures);
}
