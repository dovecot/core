/* Copyright (c) 2016-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "net.h"
#include "str.h"
#include "istream.h"
#include "ioloop.h"
#include "base64.h"
#include "hex-binary.h"
#include "hash-method.h"
#include "http-url.h"
#include "http-client.h"
#include "json-parser.h"
#include "auth-request.h"
#include "auth-penalty.h"
#include "auth-settings.h"
#include "auth-policy.h"
#include "iostream-ssl.h"

#define AUTH_POLICY_DNS_SOCKET_PATH "dns-client"

static struct http_client_settings http_client_set = {
	.dns_client_socket_path = AUTH_POLICY_DNS_SOCKET_PATH,
	.max_connect_attempts = 1,
	.max_idle_time_msecs = 10000,
	.max_parallel_connections = 100,
	.debug = 0,
	.user_agent = "dovecot/auth-policy-client"
};

static char *auth_policy_json_template;

static struct http_client *http_client;

struct policy_lookup_ctx {
	pool_t pool;
	string_t *json;
	struct auth_request *request;
	struct http_client_request *http_request;
	struct json_parser *parser;
	const struct auth_settings *set;
	const char *url;
	bool expect_result;
	int result;
	const char *message;
	auth_policy_callback_t callback;
	void *callback_context;

	struct istream *payload;
	struct io *io;

	enum {
		POLICY_RESULT = 0,
		POLICY_RESULT_VALUE_STATUS,
		POLICY_RESULT_VALUE_MESSAGE
	} parse_state;

	bool parse_error;
};

struct policy_template_keyvalue {
	const char *key;
	const char *value;
};

static
int auth_policy_attribute_comparator(const struct policy_template_keyvalue *a,
	const struct policy_template_keyvalue *b)
{
	return strcmp(a->key, b->key);
}

static
int auth_policy_strptrcmp(const char *a0, const char *a1,
			  const char *b0, const char *b1)
{
	i_assert(a0 <= a1 && b0 <= b1);
	return memcmp(a0, b0, I_MIN((a1-a0),(b1-b0)));
}

static
void auth_policy_open_key(const char *key, string_t *template)
{
	const char *ptr;
	while((ptr = strchr(key, '/')) != NULL) {
		str_append_c(template,'"');
		json_append_escaped(template, t_strndup(key, (ptr-key)));
		str_append_c(template,'"');
		str_append_c(template,':');
		str_append_c(template,'{');
		key = ptr+1;
	}
}

static
void auth_policy_close_key(const char *key, string_t *template)
{
	while((key = strchr(key, '/')) != NULL) { str_append_c(template,'}'); key++; }
}

static
void auth_policy_open_and_close_to_key(const char *fromkey, const char *tokey, string_t *template)
{
	const char *fptr,*tptr,*fdash,*tdash;

	fptr = strrchr(fromkey, '/');
	tptr = strrchr(tokey, '/');

	if (fptr == NULL && tptr == NULL) return; /* nothing to do */

	if (fptr == NULL && tptr != NULL) {
		auth_policy_open_key(tokey, template);
		return;
	}

	if (fptr != NULL && tptr == NULL) {
		str_truncate(template, str_len(template)-1);

		auth_policy_close_key(fromkey, template);
		str_append_c(template, ',');
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
			auth_policy_open_key(tptr, template);
			break;
		}
		if (tdash == NULL) {
			str_truncate(template, str_len(template)-1);
			auth_policy_close_key(fptr, template);
			str_append_c(template, ',');
			break;
		}
		if (auth_policy_strptrcmp(fptr, fdash, tptr, tdash) != 0) {
			str_truncate(template, str_len(template)-1);
			auth_policy_close_key(fptr, template);
			str_append_c(template, ',');
			auth_policy_open_key(tptr, template);
			break;
		}
		fptr = fdash+1;
		tptr = tdash+1;
	}
}

void auth_policy_init(void)
{
	struct ssl_iostream_settings ssl_set;
	i_zero(&ssl_set);

	http_client_set.request_absolute_timeout_msecs = global_auth_settings->policy_server_timeout_msecs;
	if (global_auth_settings->debug)
		http_client_set.debug = 1;
	ssl_set.ca_dir = global_auth_settings->ssl_client_ca_dir;
	ssl_set.ca_file = global_auth_settings->ssl_client_ca_file;
	if (*ssl_set.ca_dir == '\0' &&
	    *ssl_set.ca_file == '\0')
		ssl_set.allow_invalid_cert = TRUE;

	http_client_set.ssl = &ssl_set;
	http_client = http_client_init(&http_client_set);

	/* prepare template */

	ARRAY(struct policy_template_keyvalue) attribute_pairs;
	const struct policy_template_keyvalue *kvptr;
	string_t *template = t_str_new(64);
	const char **ptr;
	const char *key = NULL;
	const char **list = t_strsplit_spaces(global_auth_settings->policy_request_attributes, "= ");

	t_array_init(&attribute_pairs, 8);
	for(ptr = list; *ptr != NULL; ptr++) {
		struct policy_template_keyvalue pair;
		if (key == NULL) {
			key = *ptr;
		} else {
			pair.key = key;
			pair.value = *ptr;
			key = NULL;
			array_append(&attribute_pairs, &pair, 1);
		}
	}
	if (key != NULL) {
		i_fatal("auth_policy_request_attributes contains invalid value");
	}

	/* then we sort it */
	array_sort(&attribute_pairs, auth_policy_attribute_comparator);

	/* and build a template string */
	const char *prevkey = "";

	array_foreach(&attribute_pairs, kvptr) {
		const char *kptr = strchr(kvptr->key, '/');
		auth_policy_open_and_close_to_key(prevkey, kvptr->key, template);
		str_append_c(template,'"');
		json_append_escaped(template, (kptr != NULL?kptr+1:kvptr->key));
		str_append_c(template,'"');
		str_append_c(template,':');
		str_append_c(template,'"');
		str_append(template,kvptr->value);
		str_append_c(template,'"');
		str_append_c(template,',');
		prevkey = kvptr->key;
	}

	auth_policy_open_and_close_to_key(prevkey, "", template);
	str_truncate(template, str_len(template)-1);
	auth_policy_json_template = i_strdup(str_c(template));

	if (global_auth_settings->policy_log_only)
		i_warning("auth-policy: Currently in log-only mode. Ignoring "
			  "tarpit and disconnect instructions from policy server");
}

void auth_policy_deinit(void)
{
	if (http_client != NULL)
		http_client_deinit(&http_client);
	i_free(auth_policy_json_template);
}

static
void auth_policy_finish(struct policy_lookup_ctx *context)
{
	if (context->parser != NULL) {
		const char *error ATTR_UNUSED;
		(void)json_parser_deinit(&context->parser, &error);
	}
	http_client_request_abort(&context->http_request);
	if (context->request != NULL)
		auth_request_unref(&context->request);
}

static
void auth_policy_parse_response(struct policy_lookup_ctx *context)
{
	enum json_type type;
	const char *value;
	int ret;

	while((ret = json_parse_next(context->parser, &type, &value)) == 1) {
		if (context->parse_state == POLICY_RESULT) {
			if (type != JSON_TYPE_OBJECT_KEY)
				continue;
			else if (strcmp(value, "status") == 0)
				context->parse_state = POLICY_RESULT_VALUE_STATUS;
			else if (strcmp(value, "msg") == 0)
				context->parse_state = POLICY_RESULT_VALUE_MESSAGE;
			else
				continue;
		} else if (context->parse_state == POLICY_RESULT_VALUE_STATUS) {
			if (type != JSON_TYPE_NUMBER || str_to_int(value, &context->result) != 0)
				break;
			context->parse_state = POLICY_RESULT;
		} else if (context->parse_state == POLICY_RESULT_VALUE_MESSAGE) {
			if (type != JSON_TYPE_STRING)
				break;
			if (*value != '\0')
				context->message = p_strdup(context->pool, value);
			context->parse_state = POLICY_RESULT;
		} else {
			break;
		}
	}

	if (ret == 0 && !context->payload->eof)
		return;

	context->parse_error = TRUE;

	io_remove(&context->io);

	if (context->payload->stream_errno != 0) {
		auth_request_log_error(context->request, "policy",
			"Error reading policy server result: %s",
			i_stream_get_error(context->payload));
	} else if (ret == 0 && context->payload->eof) {
		auth_request_log_error(context->request, "policy",
			"Policy server result was too short");
	} else if (ret == 1) {
		auth_request_log_error(context->request, "policy",
			"Policy server response was malformed");
	} else {
		const char *error = "unknown";
		if (json_parser_deinit(&context->parser, &error) != 0)
			auth_request_log_error(context->request, "policy",
				"Policy server response JSON parse error: %s", error);
		else if (context->parse_state == POLICY_RESULT)
			context->parse_error = FALSE;
	}
	i_stream_unref(&context->payload);

	if (context->parse_error) {
		context->result = (context->set->policy_reject_on_fail ? -1 : 0);
	}

	context->request->policy_refusal = FALSE;

	if (context->result < 0) {
		if (context->message != NULL) {
			/* set message here */
			auth_request_log_debug(context->request, "policy",
				"Policy response %d with message: %s",
				context->result, context->message);
			auth_request_set_field(context->request, "reason", context->message, NULL);
		}
		context->request->policy_refusal = TRUE;
	} else {
		auth_request_log_debug(context->request, "policy",
			"Policy response %d", context->result);
	}

	if (context->request->policy_refusal == TRUE && context->set->verbose == TRUE) {
		auth_request_log_info(context->request, "policy", "Authentication failure due to policy server refusal%s%s",
			(context->message!=NULL?": ":""),
			(context->message!=NULL?context->message:""));
	}

	if (context->callback != NULL) {
		context->callback(context->result, context->callback_context);
	}
}

static
void auth_policy_process_response(const struct http_response *response,
	void *ctx)
{
	struct policy_lookup_ctx *context = ctx;

	context->payload = response->payload;

	if ((response->status / 10) != 20) {
		auth_request_log_error(context->request, "policy",
			"Policy server HTTP error: %s",
			http_response_get_message(response));
		if (context->callback != NULL)
			context->callback(context->result, context->callback_context);
		return;
	}

	if (response->payload == NULL) {
		if (context->expect_result)
			auth_request_log_error(context->request, "policy",
				"Policy server result was empty");
		if (context->callback != NULL)
			context->callback(context->result, context->callback_context);
		return;
	}

	if (context->expect_result) {
		i_stream_ref(response->payload);
		context->io = io_add_istream(response->payload, auth_policy_parse_response, context);
		context->parser = json_parser_init(response->payload);
		auth_policy_parse_response(ctx);
	} else {
		auth_request_log_debug(context->request, "policy",
			"Policy response %d", context->result);
		if (context->callback != NULL)
			context->callback(context->result, context->callback_context);
	}
}

static
void auth_policy_send_request(struct policy_lookup_ctx *context)
{
	const char *error;
	struct http_url *url;
	if (http_url_parse(context->url, NULL, HTTP_URL_ALLOW_USERINFO_PART,
			   context->pool, &url, &error) != 0) {
		auth_request_log_error(context->request, "policy",
			"Could not parse url %s: %s", context->url, error);
		auth_policy_finish(context);
		return;
	}
	context->http_request = http_client_request_url(http_client,
		"POST", url, auth_policy_process_response, (void*)context);
	http_client_request_set_destroy_callback(context->http_request, auth_policy_finish, context);
	http_client_request_add_header(context->http_request, "Content-Type", "application/json");
	if (*context->set->policy_server_api_header != 0) {
		const char *ptr;
		if ((ptr = strstr(context->set->policy_server_api_header, ":")) != NULL) {
			const char *header = t_strcut(context->set->policy_server_api_header, ':');
			http_client_request_add_header(context->http_request, header, ptr + 1);
		} else {
			http_client_request_add_header(context->http_request,
				"X-API-Key", context->set->policy_server_api_header);
		}
	}
	if (url->user != NULL) {
		/* allow empty password */
		http_client_request_set_auth_simple(context->http_request, url->user,
			(url->password != NULL ? url->password : ""));
	}
	struct istream *is = i_stream_create_from_buffer(context->json);
	http_client_request_set_payload(context->http_request, is, FALSE);
	i_stream_unref(&is);
	http_client_request_submit(context->http_request);
	auth_request_ref(context->request);
}

static
const char *auth_policy_escape_function(const char *string,
	const struct auth_request *auth_request ATTR_UNUSED)
{
	string_t *tmp = t_str_new(64);
	json_append_escaped(tmp, string);
	return str_c(tmp);
}

static
const struct var_expand_table *policy_get_var_expand_table(struct auth_request *auth_request,
	const char *hashed_password, const char *requested_username)
{
	struct var_expand_table *table;
	unsigned int count = 2;

	table = auth_request_get_var_expand_table_full(auth_request, auth_policy_escape_function,
						       &count);
	table[0].key = '\0';
	table[0].long_key = "hashed_password";
	table[0].value = hashed_password;
	table[1].key = '\0';
	table[1].long_key = "requested_username";
	table[1].value = requested_username;
	if (table[0].value != NULL)
		table[0].value = auth_policy_escape_function(table[0].value, auth_request);
	if (table[1].value != NULL)
		table[1].value = auth_policy_escape_function(table[1].value, auth_request);

	return table;
}

static
void auth_policy_create_json(struct policy_lookup_ctx *context,
	const char *password, bool include_success)
{
	const struct var_expand_table *var_table;
	context->json = str_new(context->pool, 64);
	unsigned char *ptr;
	const char *requested_username;
	const struct hash_method *digest = hash_method_lookup(context->set->policy_hash_mech);

	i_assert(digest != NULL);

	void *ctx = t_malloc_no0(digest->context_size);
	buffer_t *buffer = t_buffer_create(64);

	digest->init(ctx);
	digest->loop(ctx,
		context->set->policy_hash_nonce,
		strlen(context->set->policy_hash_nonce));
	if (context->request->requested_login_user != NULL)
		requested_username = context->request->requested_login_user;
	else if (context->request->user != NULL)
		requested_username = context->request->user;
	else
		requested_username = "";
	/* use +1 to make sure \0 gets included */
	digest->loop(ctx, requested_username, strlen(requested_username)+1);
	if (password != NULL)
		digest->loop(ctx, password, strlen(password));
	ptr = buffer_get_modifiable_data(buffer, NULL);
	digest->result(ctx, ptr);
	buffer_set_used_size(buffer, digest->digest_size);
	if (context->set->policy_hash_truncate > 0) {
		buffer_truncate_rshift_bits(buffer, context->set->policy_hash_truncate);
	}
	const char *hashed_password = binary_to_hex(buffer->data, buffer->used);
	str_append_c(context->json, '{');
	var_table = policy_get_var_expand_table(context->request, hashed_password, requested_username);
	const char *error;
	if (auth_request_var_expand_with_table(context->json, auth_policy_json_template,
					       context->request, var_table,
					       auth_policy_escape_function, &error) <= 0) {
		auth_request_log_error(context->request, "policy",
			"Failed to expand auth policy template: %s", error);
	}
	if (include_success) {
		str_append(context->json, ",\"success\":");
		if (!context->request->failed && context->request->successful &&
		    !context->request->internal_failure)
			str_append(context->json, "true");
		else
			str_append(context->json, "false");
		str_append(context->json, ",\"policy_reject\":");
		str_append(context->json, context->request->policy_refusal ? "true" : "false");
	}
	str_append(context->json, ",\"tls\":");
	if (context->request->secured == AUTH_REQUEST_SECURED_TLS)
		str_append(context->json, "true");
	else
		str_append(context->json, "false");
	str_append_c(context->json, '}');
	auth_request_log_debug(context->request, "policy",
		"Policy server request JSON: %s", str_c(context->json));
}

static
void auth_policy_url(struct policy_lookup_ctx *context, const char *command)
{
	size_t len = strlen(context->set->policy_server_url);
	if (context->set->policy_server_url[len-1] == '&')
		context->url = p_strdup_printf(context->pool, "%scommand=%s",
			context->set->policy_server_url, command);
	else
		context->url = p_strdup_printf(context->pool, "%s?command=%s",
			context->set->policy_server_url, command);
}

void auth_policy_check(struct auth_request *request, const char *password,
	auth_policy_callback_t cb, void *context)
{
	if (request->master != NULL || *(request->set->policy_server_url) == '\0') {
		cb(0, context);
		return;
	}
	struct policy_lookup_ctx *ctx = p_new(request->pool, struct policy_lookup_ctx, 1);
	ctx->pool = request->pool;
	ctx->request = request;
	ctx->expect_result = TRUE;
	ctx->callback = cb;
	ctx->callback_context = context;
	ctx->set = request->set;

	auth_policy_url(ctx, "allow");
	ctx->result = (ctx->set->policy_reject_on_fail ? -1 : 0);
	auth_request_log_debug(request, "policy", "Policy request %s", ctx->url);
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
	struct policy_lookup_ctx *ctx = p_new(request->pool, struct policy_lookup_ctx, 1);
	ctx->pool = request->pool;
	ctx->request = request;
	ctx->expect_result = FALSE;
	ctx->set = request->set;
	auth_policy_url(ctx, "report");
	auth_request_log_debug(request, "policy", "Policy request %s", ctx->url);
	T_BEGIN {
		auth_policy_create_json(ctx, request->mech_password, TRUE);
	} T_END;
	auth_policy_send_request(ctx);
}
