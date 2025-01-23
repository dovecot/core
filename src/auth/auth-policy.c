/* Copyright (c) 2016-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "net.h"
#include "passdb.h"
#include "str.h"
#include "istream.h"
#include "ioloop.h"
#include "base64.h"
#include "hex-binary.h"
#include "hash-method.h"
#include "http-url.h"
#include "http-client.h"
#include "json-generator.h"
#include "json-istream.h"
#include "json-ostream.h"
#include "master-service.h"
#include "settings.h"
#include "auth-request.h"
#include "auth-penalty.h"
#include "auth-settings.h"
#include "auth-policy.h"
#include "auth-common.h"
#include "iostream-ssl.h"

static char *auth_policy_json_template;

static struct http_client *http_client;

struct policy_lookup_ctx {
	pool_t pool;
	string_t *json;
	struct auth_request *request;
	struct http_client_request *http_request;
	struct json_istream *json_input;
	const struct auth_settings *set;
	const char *url;
	bool expect_result;
	int result;
	const char *message;
	auth_policy_callback_t callback;
	void *callback_context;

	struct istream *payload;
	struct io *io;
	struct event *event;

	bool parse_error;
	bool have_status;
};

struct policy_template_keyvalue {
	const char *key;
	const char *value;
};

static int
auth_policy_attribute_comparator(const struct policy_template_keyvalue *a,
				 const struct policy_template_keyvalue *b)
{
	return strcmp(a->key, b->key);
}

static int
auth_policy_strptrcmp(const char *a0, const char *a1,
		      const char *b0, const char *b1)
{
	i_assert(a0 <= a1 && b0 <= b1);
	return memcmp(a0, b0, I_MIN((a1-a0),(b1-b0)));
}

static void
auth_policy_open_key(struct json_ostream *json_output, const char *key)
{
	const char *ptr;

	while((ptr = strchr(key, '/')) != NULL) {
		json_ostream_ndescend_object(json_output,
					     t_strdup_until(key, ptr));
		key = ptr+1;
	}
}

static void
auth_policy_close_key(struct json_ostream *json_output, const char *key)
{
	while ((key = strchr(key, '/')) != NULL) {
		json_ostream_nascend_object(json_output);
		key++;
	}
}

static void
auth_policy_open_and_close_to_key(struct json_ostream *json_output,
				  const char *fromkey, const char *tokey)
{
	const char *fptr,*tptr,*fdash,*tdash;

	fptr = strrchr(fromkey, '/');
	tptr = strrchr(tokey, '/');

	if (fptr == NULL && tptr == NULL) return; /* nothing to do */

	if (fptr == NULL && tptr != NULL) {
		auth_policy_open_key(json_output, tokey);
		return;
	}

	if (fptr != NULL && tptr == NULL) {
		auth_policy_close_key(json_output, fromkey);
		return;
	}

	if (auth_policy_strptrcmp(fromkey, fptr, tokey, tptr) == 0) {
		/* nothing to do, again */
		return;
	}

	fptr = fromkey;
	tptr = tokey;

	while (fptr != NULL && tptr != NULL) {
		fdash = strchr(fptr, '/');
		tdash = strchr(tptr, '/');

		if (fdash == NULL) {
			auth_policy_open_key(json_output, tptr);
			break;
		}
		if (tdash == NULL) {
			auth_policy_close_key(json_output, fptr);
			break;
		}
		if (auth_policy_strptrcmp(fptr, fdash, tptr, tdash) != 0) {
			auth_policy_close_key(json_output, fptr);
			auth_policy_open_key(json_output, tptr);
			break;
		}
		fptr = fdash+1;
		tptr = tdash+1;
	}
}

void auth_policy_init(void)
{
	const char *error;
	struct event *event = event_create(auth_event);
	settings_event_add_filter_name(event, "auth_policy");
	if (http_client_init_auto(event, &http_client, &error) < 0)
		i_fatal("%s", error);
	event_unref(&event);

	/* prepare template */

	ARRAY(struct policy_template_keyvalue) attribute_pairs;
	const struct policy_template_keyvalue *kvptr;
	string_t *template = t_str_new(64);
	struct json_ostream *json_output;

	const struct auth_policy_request_settings *set;
	if (settings_get(auth_event, &auth_policy_request_setting_parser_info,
			 SETTINGS_GET_FLAG_NO_EXPAND, &set, &error) < 0)
		i_fatal("%s", error);

	t_array_init(&attribute_pairs, 8);
	unsigned int i, count;
	const char *const *list =
		array_get(&set->policy_request_attributes, &count);
	i_assert(count % 2 == 0);
	for (i = 0; i < count; i += 2) {
		struct policy_template_keyvalue *pair =
			array_append_space(&attribute_pairs);
		pair->key = list[i];
		pair->value = list[i + 1];
	}

	/* then we sort it */
	array_sort(&attribute_pairs, auth_policy_attribute_comparator);

	/* and build a template string */
	const char *prevkey = "";

	json_output = json_ostream_create_str(template,
					      JSON_GENERATOR_FLAG_HIDE_ROOT);
	json_ostream_ndescend_object(json_output, NULL);
	array_foreach(&attribute_pairs, kvptr) {
		const char *kptr = strchr(kvptr->key, '/');
		auth_policy_open_and_close_to_key(json_output,
						  prevkey, kvptr->key);
		json_ostream_nwrite_string(
			json_output, (kptr != NULL ? kptr + 1 : kvptr->key),
			kvptr->value);
		prevkey = kvptr->key;
	}
	auth_policy_open_and_close_to_key(json_output, prevkey, "");
	json_ostream_nascend_object(json_output);
	json_ostream_nfinish_destroy(&json_output);

	auth_policy_json_template = i_strdup(str_c(template));

	if (global_auth_settings->policy_log_only) {
		e_warning(auth_event,
			  "auth-policy: Currently in log-only mode. Ignoring "
			  "tarpit and disconnect instructions from policy server");
	}
	settings_free(set);
}

void auth_policy_deinit(void)
{
	if (http_client != NULL)
		http_client_deinit(&http_client);
	i_free(auth_policy_json_template);
}

static void auth_policy_log_result(struct policy_lookup_ctx *context)
{
	const char *action;
	struct event_passthrough *e = event_create_passthrough(context->event)->
		set_name("auth_policy_request_finished");
	if (!context->expect_result) {
		e_debug(e->event(), "Policy report action finished");
		return;
	}
	int result = context->result;
	e->add_int("policy_response", context->result);
	if (result < 0)
		action = "drop connection";
	else if (context->result == 0)
		action = "continue";
	else
		action = t_strdup_printf("tarpit %d second(s)", context->result);
	if (context->request->set->policy_log_only && result != 0) {
		e_info(e->event(), "Policy check action '%s' ignored",
		       action);
	} else if (result != 0) {
		e_info(e->event(), "Policy check action is %s",
		       action);
	} else {
		e_debug(e->event(), "Policy check action is %s",
			action);
	}
}

static void auth_policy_finish(struct policy_lookup_ctx *context)
{
	json_istream_destroy(&context->json_input);
	http_client_request_abort(&context->http_request);
	if (context->request != NULL)
		auth_request_unref(&context->request);
	event_unref(&context->event);
	pool_unref(&context->pool);
}

static void auth_policy_callback(struct policy_lookup_ctx *context)
{
	if (context->callback != NULL)
		context->callback(context->result, context->callback_context);
	if (context->event != NULL)
		auth_policy_log_result(context);
}

static void auth_policy_parse_response(struct policy_lookup_ctx *context)
{
	struct json_node jnode;
	const char *value;
	int ret;

	ret = 1;
	while (ret > 0) {
		ret = json_istream_read(context->json_input, &jnode);
		if (ret <= 0)
			break;
		i_assert(jnode.name != NULL);

		if (strcmp(jnode.name, "status") == 0) {
			if (json_node_get_int(&jnode, &context->result) != 0)
				break;
			context->have_status = TRUE;
		} else if (strcmp(jnode.name, "msg") == 0) {
			if (!json_node_is_string(&jnode))
				break;
			value = json_node_get_str(&jnode);
			if (*value != '\0')
				context->message = p_strdup(context->pool, value);
		}
		json_istream_skip(context->json_input);
	}

	if (ret == 0)
		return;

	context->parse_error = TRUE;

	io_remove(&context->io);

	if (context->payload->stream_errno != 0) {
		e_error(context->event,
			"Error reading policy server result: %s",
			i_stream_get_error(context->payload));
	} else if (ret > 0) {
		e_error(context->event,
			"Policy server response was malformed");
	} else {
		const char *error;

		ret = json_istream_finish(&context->json_input, &error);
		i_assert(ret != 0);
		if (ret < 0) {
			e_error(context->event,
				"Policy server response JSON parse error: %s",
				error);
		} else if (!context->have_status) {
			e_error(context->event,
				"Policy server response is missing status field");
		} else {
			context->parse_error = FALSE;
		}
	}
	json_istream_destroy(&context->json_input);

	if (context->parse_error) {
		context->result = (context->set->policy_reject_on_fail ?
				   -1 : 0);
	}

	context->request->policy_refusal = FALSE;

	if (context->result < 0) {
		if (context->message != NULL) {
			/* set message here */
			e_debug(context->event,
				"Policy response %d with message: %s",
				context->result, context->message);
			auth_request_set_field(context->request, "reason",
					       context->message, NULL);
		}
		context->request->policy_refusal = TRUE;
	} else {
		e_debug(context->event,
			"Policy response %d", context->result);
	}

	if (context->request->policy_refusal) {
		e_info(context->event,
		       "Authentication failure due to policy server refusal%s%s",
		       (context->message!=NULL?": ":""),
		       (context->message!=NULL?context->message:""));
	}

	auth_policy_callback(context);
	i_stream_unref(&context->payload);
}

static void
auth_policy_process_response(const struct http_response *response, void *ctx)
{
	struct policy_lookup_ctx *context = ctx;

	context->payload = response->payload;

	if ((response->status / 10) != 20) {
		e_error(context->event,
			"Policy server HTTP error: %s",
			http_response_get_message(response));
		auth_policy_callback(context);
		return;
	}

	if (response->payload == NULL) {
		if (context->expect_result)
			e_error(context->event,
				"Policy server result was empty");
		auth_policy_callback(context);
		return;
	}

	if (context->expect_result) {
		i_stream_ref(response->payload);
		context->io = io_add_istream(
			response->payload, auth_policy_parse_response, context);
		context->json_input = json_istream_create_object(
			response->payload, NULL, 0);
		auth_policy_parse_response(ctx);
	} else {
		auth_policy_callback(context);
	}
}

static void auth_policy_send_request(struct policy_lookup_ctx *context)
{
	const char *error;
	struct http_url *url;

	auth_request_ref(context->request);
	if (http_url_parse(context->url, NULL, HTTP_URL_ALLOW_USERINFO_PART,
			   context->pool, &url, &error) != 0) {
		e_error(context->event,
			"Could not parse url %s: %s", context->url, error);
		auth_policy_callback(context);
		auth_policy_finish(context);
		return;
	}

	context->http_request = http_client_request_url(http_client,
		"POST", url, auth_policy_process_response, (void*)context);
	http_client_request_set_destroy_callback(
		context->http_request, auth_policy_finish, context);
	http_client_request_add_header(context->http_request,
				       "Content-Type", "application/json");
	if (*context->set->policy_server_api_header != 0) {
		const char *ptr;

		ptr = strstr(context->set->policy_server_api_header, ":");
		if (ptr != NULL) {
			const char *header = t_strcut(
				context->set->policy_server_api_header, ':');
			http_client_request_add_header(context->http_request,
						       header, ptr + 1);
		} else {
			http_client_request_add_header(
				context->http_request, "X-API-Key",
				context->set->policy_server_api_header);
		}
	}
	if (url->user != NULL) {
		/* allow empty password */
		http_client_request_set_auth_simple(
			context->http_request, url->user,
			(url->password != NULL ? url->password : ""));
	}

	struct istream *is = i_stream_create_from_buffer(context->json);
	http_client_request_set_payload(context->http_request, is, FALSE);
	i_stream_unref(&is);
	http_client_request_submit(context->http_request);
}

static const char *
auth_policy_escape_function(const char *string,
			    const struct auth_request *auth_request ATTR_UNUSED)
{
	string_t *tmp = t_str_new(64);
	json_append_escaped(tmp, string);
	return str_c(tmp);
}

static
const char* auth_policy_fail_type(struct auth_request *request)
{
	if (request->policy_refusal)
		return "policy";
	/* wait until it's finished */
	if (request->state != AUTH_REQUEST_STATE_FINISHED)
		return "";
	switch (request->passdb_result) {
	case PASSDB_RESULT_OK:
	case PASSDB_RESULT_NEXT:
		return "";
	case PASSDB_RESULT_SCHEME_NOT_AVAILABLE:
	case PASSDB_RESULT_INTERNAL_FAILURE:
		return "internal";
	case PASSDB_RESULT_PASSWORD_MISMATCH:
		return "credentials";
	case PASSDB_RESULT_PASS_EXPIRED:
		return "expired";
	case PASSDB_RESULT_USER_DISABLED:
		return "disabled";
	case PASSDB_RESULT_USER_UNKNOWN:
		return "account";
	}
	i_unreached();
}

static const struct var_expand_table *
policy_get_var_expand_table(struct auth_request *auth_request,
			    const char *hashed_password,
			    const char *requested_username)
{
	struct var_expand_table *table;
	unsigned int count = 3;

	table = auth_request_get_var_expand_table_full(
			auth_request, auth_request->fields.user,
			&count);
	table[0].key = "hashed_password";
	table[0].value = hashed_password;
	table[1].key = "requested_username";
	table[1].value = requested_username;
	table[2].key = "fail_type";
	table[2].value = auth_policy_fail_type(auth_request);

	return table;
}

static void
auth_policy_create_json(struct policy_lookup_ctx *context,
			const char *password, bool include_success)
{
	const struct var_expand_table *var_table;
	context->json = str_new(context->pool, 64);
	unsigned char *ptr;
	const char *requested_username;
	const struct hash_method *digest =
		hash_method_lookup(context->set->policy_hash_mech);

	i_assert(digest != NULL);

	void *ctx = t_malloc_no0(digest->context_size);
	buffer_t *buffer = t_buffer_create(64);

	digest->init(ctx);
	digest->loop(ctx, context->set->policy_hash_nonce,
		     strlen(context->set->policy_hash_nonce));
	if (context->request->fields.requested_login_user != NULL) {
		requested_username =
			context->request->fields.requested_login_user;
	} else if (context->request->fields.user != NULL) {
		requested_username = context->request->fields.user;
	} else {
		requested_username = "";
	}

	/* use +1 to make sure \0 gets included */
	digest->loop(ctx, requested_username, strlen(requested_username)+1);
	if (password != NULL)
		digest->loop(ctx, password, strlen(password));
	ptr = buffer_get_modifiable_data(buffer, NULL);
	digest->result(ctx, ptr);
	buffer_set_used_size(buffer, digest->digest_size);
	if (context->set->policy_hash_truncate > 0) {
		buffer_truncate_rshift_bits(
			buffer, context->set->policy_hash_truncate);
	}

	const char *hashed_password = binary_to_hex(buffer->data, buffer->used);
	struct json_ostream *json_output;
	const char *error;

	json_output = json_ostream_create_str(context->json, 0);
	json_ostream_ndescend_object(json_output, NULL);

	json_ostream_nopen_space(json_output, NULL);
	var_table = policy_get_var_expand_table(
		context->request, hashed_password, requested_username);
	if (auth_request_var_expand_with_table(context->json,
					       auth_policy_json_template,
					       context->request, var_table,
					       auth_policy_escape_function,
					       &error) < 0) {
		e_error(context->event,
			"Failed to expand auth policy template: %s", error);
	}

	json_ostream_close_space(json_output);

	if (include_success) {
		if (!context->request->failed &&
		    context->request->fields.successful &&
		    !context->request->internal_failure) {
			json_ostream_nwrite_true(json_output,
						   "success");
		} else {
			json_ostream_nwrite_false(json_output,
						   "success");
		}
		json_ostream_nwrite_bool(json_output, "policy_reject",
					 context->request->policy_refusal);
	}
	json_ostream_nwrite_bool(json_output, "tls",
				 context->request->fields.conn_secured ==
				 AUTH_REQUEST_CONN_SECURED_TLS);
	json_ostream_nascend_object(json_output);
	json_ostream_nfinish_destroy(&json_output);

	e_debug(context->event,
		"Policy server request JSON: %s", str_c(context->json));
}

static void auth_policy_url(struct policy_lookup_ctx *context,
			    const char *command)
{
	size_t len = strlen(context->set->policy_server_url);
	if (context->set->policy_server_url[len-1] == '&') {
		context->url = p_strdup_printf(
			context->pool, "%scommand=%s",
			context->set->policy_server_url, command);
	} else {
		context->url = p_strdup_printf(
			context->pool, "%s?command=%s",
			context->set->policy_server_url, command);
	}
}

void auth_policy_check(struct auth_request *request, const char *password,
	auth_policy_callback_t cb, void *context)
{
	if (request->master != NULL ||
	    *(request->set->policy_server_url) == '\0') {
		cb(0, context);
		return;
	}

	pool_t pool = pool_alloconly_create("auth policy", 512);
	struct policy_lookup_ctx *ctx =
		p_new(pool, struct policy_lookup_ctx, 1);

	ctx->pool = pool;
	ctx->request = request;
	ctx->expect_result = TRUE;
	ctx->callback = cb;
	ctx->callback_context = context;
	ctx->set = request->set;
	ctx->event = event_create(request->event);
	event_add_str(ctx->event, "mode", "allow");
	event_set_append_log_prefix(ctx->event, "policy: ");
	auth_policy_url(ctx, "allow");
	ctx->result = (ctx->set->policy_reject_on_fail ? -1 : 0);
	e_debug(ctx->event, "Policy request %s", ctx->url);
	T_BEGIN {
		auth_policy_create_json(ctx, password, FALSE);
	} T_END;
	auth_policy_send_request(ctx);
}

void auth_policy_report(struct auth_request *request)
{
	if (request->master != NULL)
		return;

	if (*(request->set->policy_server_url) == '\0')
		return;

	pool_t pool = pool_alloconly_create("auth policy", 512);
	struct policy_lookup_ctx *ctx =
		p_new(pool, struct policy_lookup_ctx, 1);

	ctx->pool = pool;
	ctx->request = request;
	ctx->expect_result = FALSE;
	ctx->set = request->set;
	ctx->event = event_create(request->event);
	event_add_str(ctx->event, "mode", "report");
	event_set_append_log_prefix(ctx->event, "policy: ");
	auth_policy_url(ctx, "report");
	e_debug(ctx->event, "Policy request %s", ctx->url);
	T_BEGIN {
		auth_policy_create_json(ctx, request->mech_password, TRUE);
	} T_END;
	auth_policy_send_request(ctx);
}
