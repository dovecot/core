/* Copyright (c) 2005-2008 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "ioloop.h"
#include "buffer.h"
#include "base64.h"
#include "hash.h"
#include "str.h"
#include "str-sanitize.h"
#include "auth-request.h"
#include "auth-master-connection.h"
#include "auth-request-handler.h"

#include <stdlib.h>

struct auth_request_handler {
	int refcount;
	pool_t pool;
	struct hash_table *requests;

        struct auth *auth;
        unsigned int connect_uid, client_pid;

	auth_request_callback_t *callback;
	void *context;

	auth_request_callback_t *master_callback;
};

static buffer_t *auth_failures_buf;
static struct timeout *to_auth_failures;

#undef auth_request_handler_create
struct auth_request_handler *
auth_request_handler_create(struct auth *auth,
			    auth_request_callback_t *callback, void *context,
			    auth_request_callback_t *master_callback)
{
	struct auth_request_handler *handler;
	pool_t pool;

	pool = pool_alloconly_create("auth request handler", 4096);

	handler = p_new(pool, struct auth_request_handler, 1);
	handler->refcount = 1;
	handler->pool = pool;
	handler->requests = hash_create(default_pool, pool, 0, NULL, NULL);
	handler->auth = auth;
	handler->callback = callback;
	handler->context = context;
	handler->master_callback = master_callback;
	return handler;
}

void auth_request_handler_unref(struct auth_request_handler **_handler)
{
        struct auth_request_handler *handler = *_handler;
	struct hash_iterate_context *iter;
	void *key, *value;

	*_handler = NULL;
	i_assert(handler->refcount > 0);
	if (--handler->refcount > 0)
		return;

	iter = hash_iterate_init(handler->requests);
	while (hash_iterate(iter, &key, &value)) {
		struct auth_request *auth_request = value;

		auth_request_unref(&auth_request);
	}
	hash_iterate_deinit(&iter);

	/* notify parent that we're done with all requests */
	handler->callback(NULL, handler->context);

	hash_destroy(&handler->requests);
	pool_unref(&handler->pool);
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
	hash_remove(handler->requests, POINTER_CAST(request->id));
	auth_request_unref(&request);
}

void auth_request_handler_check_timeouts(struct auth_request_handler *handler)
{
	struct hash_iterate_context *iter;
	void *key, *value;

	iter = hash_iterate_init(handler->requests);
	while (hash_iterate(iter, &key, &value)) {
		struct auth_request *request = value;

		if (request->last_access + AUTH_REQUEST_TIMEOUT < ioloop_time)
			auth_request_handler_remove(handler, request);
	}
	hash_iterate_deinit(&iter);
}

static const char *get_client_extra_fields(struct auth_request *request)
{
	string_t *str;
	const char **fields, *extra_fields;
	unsigned int src, dest;
	bool seen_pass = FALSE;

	if (auth_stream_is_empty(request->extra_fields))
		return NULL;

	extra_fields = auth_stream_reply_export(request->extra_fields);

	if (!request->proxy) {
		/* we only wish to remove all fields prefixed with "userdb_" */
		if (strstr(extra_fields, "userdb_") == NULL)
			return extra_fields;
	}

	str = t_str_new(128);
	fields = t_strsplit(extra_fields, "\t");
	for (src = dest = 0; fields[src] != NULL; src++) {
		if (strncmp(fields[src], "userdb_", 7) != 0) {
			if (str_len(str) > 0)
				str_append_c(str, '\t');
			if (!seen_pass && strncmp(fields[src], "pass=", 5) == 0)
				seen_pass = TRUE;
			str_append(str, fields[src]);
		}
	}

	if (request->proxy && !seen_pass && request->mech_password != NULL) {
		/* we're proxying - send back the password that was
		   sent by user (not the password in passdb). */
		str_printfa(str, "\tpass=%s", request->mech_password);
	}

	return str_len(str) == 0 ? NULL : str_c(str);
}

static void auth_callback(struct auth_request *request,
			  enum auth_client_result result,
			  const void *reply, size_t reply_size)
{
        struct auth_request_handler *handler = request->context;
	string_t *str;
	const char *fields;

	str = t_str_new(128 + MAX_BASE64_ENCODED_SIZE(reply_size));
	switch (result) {
	case AUTH_CLIENT_RESULT_CONTINUE:
		str_printfa(str, "CONT\t%u\t", request->id);
		base64_encode(reply, reply_size, str);
                request->accept_input = TRUE;
		handler->callback(str_c(str), handler->context);
		break;
	case AUTH_CLIENT_RESULT_SUCCESS:
		str_printfa(str, "OK\t%u\tuser=%s", request->id, request->user);
		if (reply_size > 0) {
			str_append(str, "\tresp=");
			base64_encode(reply, reply_size, str);
		}
		fields = get_client_extra_fields(request);
		if (fields != NULL) {
			str_append_c(str, '\t');
			str_append(str, fields);
		}

		if (request->no_login || handler->master_callback == NULL) {
			/* this request doesn't have to wait for master
			   process to pick it up. delete it */
			auth_request_handler_remove(handler, request);
		}
		handler->callback(str_c(str), handler->context);
		break;
	case AUTH_CLIENT_RESULT_FAILURE:
		str_printfa(str, "FAIL\t%u", request->id);
		if (request->user != NULL)
			str_printfa(str, "\tuser=%s", request->user);
		if (request->internal_failure)
			str_append(str, "\ttemp");
		fields = get_client_extra_fields(request);
		if (fields != NULL) {
			str_append_c(str, '\t');
			str_append(str, fields);
		}

		if (request->delayed_failure) {
			/* we came here from flush_failures() */
			handler->callback(str_c(str), handler->context);
			break;
		}

		/* remove the request from requests-list */
		auth_request_ref(request);
		auth_request_handler_remove(handler, request);

		if (request->no_failure_delay) {
			/* passdb specifically requested not to delay the
			   reply. */
			handler->callback(str_c(str), handler->context);
			auth_request_unref(&request);
		} else {
			/* failure. don't announce it immediately to avoid
			   a) timing attacks, b) flooding */
			request->delayed_failure = TRUE;
			handler->refcount++;
			buffer_append(auth_failures_buf,
				      &request, sizeof(request));
		}
		break;
	}
	/* NOTE: request may be destroyed now */

        auth_request_handler_unref(&handler);
}

static void auth_request_handler_auth_fail(struct auth_request_handler *handler,
					   struct auth_request *request,
					   const char *reason)
{
	string_t *reply = t_str_new(64);

	auth_request_log_info(request, request->mech->mech_name, "%s", reason);

	str_printfa(reply, "FAIL\t%u\treason=%s", request->id, reason);
	handler->callback(str_c(reply), handler->context);

	auth_request_handler_remove(handler, request);
}

bool auth_request_handler_auth_begin(struct auth_request_handler *handler,
				     const char *args)
{
	const struct mech_module *mech;
	struct auth_request *request;
	const char *const *list, *name, *arg, *initial_resp;
	const void *initial_resp_data;
	size_t initial_resp_len;
	unsigned int id;
	buffer_t *buf;
	bool valid_client_cert;

	/* <id> <mechanism> [...] */
	list = t_strsplit(args, "\t");
	if (list[0] == NULL || list[1] == NULL) {
		i_error("BUG: Authentication client %u "
			"sent broken AUTH request", handler->client_pid);
		return FALSE;
	}

	id = (unsigned int)strtoul(list[0], NULL, 10);

	mech = mech_module_find(list[1]);
	if (mech == NULL) {
		/* unsupported mechanism */
		i_error("BUG: Authentication client %u requested unsupported "
			"authentication mechanism %s", handler->client_pid,
			str_sanitize(list[1], MAX_MECH_NAME_LEN));
		return FALSE;
	}

	request = auth_request_new(handler->auth, mech, auth_callback, handler);
	request->connect_uid = handler->connect_uid;
	request->client_pid = handler->client_pid;
	request->id = id;

	/* parse optional parameters */
	initial_resp = NULL;
	valid_client_cert = FALSE;
	for (list += 2; *list != NULL; list++) {
		arg = strchr(*list, '=');
		if (arg == NULL) {
			name = *list;
			arg = "";
		} else {
			name = t_strdup_until(*list, arg);
			arg++;
		}

		if (auth_request_import(request, name, arg))
			;
		else if (strcmp(name, "valid-client-cert") == 0)
			valid_client_cert = TRUE;
		else if (strcmp(name, "resp") == 0) {
			initial_resp = arg;
			/* this must be the last parameter */
			list++;
			break;
		}
	}

	if (*list != NULL) {
		i_error("BUG: Authentication client %u "
			"sent AUTH parameters after 'resp'",
			handler->client_pid);
		return FALSE;
	}

	if (request->service == NULL) {
		i_error("BUG: Authentication client %u "
			"didn't specify service in request",
			handler->client_pid);
		return FALSE;
	}

	hash_insert(handler->requests, POINTER_CAST(id), request);

	if (request->auth->ssl_require_client_cert && !valid_client_cert) {
		/* we fail without valid certificate */
                auth_request_handler_auth_fail(handler, request,
			"Client didn't present valid SSL certificate");
		return TRUE;
	}

	if (initial_resp == NULL) {
		initial_resp_data = NULL;
		initial_resp_len = 0;
	} else {
		size_t len = strlen(initial_resp);
		buf = buffer_create_dynamic(pool_datastack_create(),
					    MAX_BASE64_DECODED_SIZE(len));
		if (base64_decode(initial_resp, len, NULL, buf) < 0) {
                        auth_request_handler_auth_fail(handler, request,
				"Invalid base64 data in initial response");
			return TRUE;
		}
		initial_resp_data = buf->data;
		initial_resp_len = buf->used;
	}

	/* handler is referenced until auth_callback is called. */
	handler->refcount++;
	auth_request_initial(request, initial_resp_data, initial_resp_len);
	return TRUE;
}

bool auth_request_handler_auth_continue(struct auth_request_handler *handler,
					const char *args)
{
	struct auth_request *request;
	const char *data;
	size_t data_len;
	buffer_t *buf;
	unsigned int id;

	data = strchr(args, '\t');
	if (data == NULL) {
		i_error("BUG: Authentication client sent broken CONT request");
		return FALSE;
	}
	data++;

	id = (unsigned int)strtoul(args, NULL, 10);

	request = hash_lookup(handler->requests, POINTER_CAST(id));
	if (request == NULL) {
		string_t *reply = t_str_new(64);

		str_printfa(reply, "FAIL\t%u\treason=Timeouted", id);
		handler->callback(str_c(reply), handler->context);
		return TRUE;
	}

	/* accept input only once after mechanism has sent a CONT reply */
	if (!request->accept_input) {
		auth_request_handler_auth_fail(handler, request,
					       "Unexpected continuation");
		return TRUE;
	}
	request->accept_input = FALSE;

	data_len = strlen(data);
	buf = buffer_create_dynamic(pool_datastack_create(),
				    MAX_BASE64_DECODED_SIZE(data_len));
	if (base64_decode(data, data_len, NULL, buf) < 0) {
		auth_request_handler_auth_fail(handler, request,
			"Invalid base64 data in continued response");
		return TRUE;
	}

	/* handler is referenced until auth_callback is called. */
	handler->refcount++;
	auth_request_continue(request, buf->data, buf->used);
	return TRUE;
}

static void userdb_callback(enum userdb_result result,
			    struct auth_request *request)
{
        struct auth_request_handler *handler = request->context;
	struct auth_stream_reply *reply = request->userdb_reply;
	string_t *str;

	i_assert(request->state == AUTH_REQUEST_STATE_USERDB);

	request->state = AUTH_REQUEST_STATE_FINISHED;

	if (request->userdb_lookup_failed)
		result = USERDB_RESULT_INTERNAL_FAILURE;

	str = t_str_new(256);
	switch (result) {
	case USERDB_RESULT_INTERNAL_FAILURE:
		str_printfa(str, "FAIL\t%u", request->id);
		break;
	case USERDB_RESULT_USER_UNKNOWN:
		str_printfa(str, "NOTFOUND\t%u", request->id);
		break;
	case USERDB_RESULT_OK:
		if (request->master_user != NULL) {
			auth_stream_reply_add(reply, "master_user",
					      request->master_user);
		}
		str_printfa(str, "USER\t%u\t", request->id);
		str_append(str, auth_stream_reply_export(reply));
		break;
	}
	handler->master_callback(str_c(str), request->master);

	auth_master_connection_unref(&request->master);
	auth_request_unref(&request);
        auth_request_handler_unref(&handler);
}

void auth_request_handler_master_request(struct auth_request_handler *handler,
					 struct auth_master_connection *master,
					 unsigned int id,
					 unsigned int client_id)
{
	struct auth_request *request;
	string_t *reply;

	reply = t_str_new(64);

	request = hash_lookup(handler->requests, POINTER_CAST(client_id));
	if (request == NULL) {
		i_error("Master request %u.%u not found",
			handler->client_pid, client_id);
		str_printfa(reply, "NOTFOUND\t%u", id);
		handler->master_callback(str_c(reply), master);
		return;
	}

	auth_request_ref(request);
	auth_request_handler_remove(handler, request);

	if (request->state != AUTH_REQUEST_STATE_FINISHED ||
	    !request->successful) {
		i_error("Master requested unfinished authentication request "
			"%u.%u", handler->client_pid, client_id);
		str_printfa(reply, "NOTFOUND\t%u", id);
		handler->master_callback(str_c(reply), master);
		auth_request_unref(&request);
	} else {
		/* the request isn't being referenced anywhere anymore,
		   so we can do a bit of kludging.. replace the request's
		   old client_id with master's id. */
		request->state = AUTH_REQUEST_STATE_USERDB;
		request->id = id;
		request->context = handler;
		request->master = master;

		/* master and handler are referenced until userdb_callback i
		   s called. */
		auth_master_connection_ref(master);
		handler->refcount++;
		auth_request_lookup_user(request, userdb_callback);
	}
}

void auth_request_handler_flush_failures(void)
{
	struct auth_request **auth_request;
	size_t i, size;

	auth_request = buffer_get_modifiable_data(auth_failures_buf, &size);
	size /= sizeof(*auth_request);

	for (i = 0; i < size; i++) {
		i_assert(auth_request[i]->state == AUTH_REQUEST_STATE_FINISHED);
		auth_request[i]->callback(auth_request[i],
					  AUTH_CLIENT_RESULT_FAILURE, NULL, 0);
		auth_request_unref(&auth_request[i]);
	}
	buffer_set_used_size(auth_failures_buf, 0);
}

static void auth_failure_timeout(void *context ATTR_UNUSED)
{
	auth_request_handler_flush_failures();
}

void auth_request_handler_init(void)
{
	auth_failures_buf = buffer_create_dynamic(default_pool, 1024);
        to_auth_failures = timeout_add(2000, auth_failure_timeout, NULL);
}

void auth_request_handler_deinit(void)
{
	auth_request_handler_flush_failures();
	buffer_free(&auth_failures_buf);
	timeout_remove(&to_auth_failures);
}
