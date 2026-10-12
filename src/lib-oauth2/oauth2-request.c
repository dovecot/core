/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "istream.h"
#include "str.h"
#include "http-client.h"
#include "http-url.h"
#include "json-istream.h"
#include "oauth2.h"
#include "oauth2-private.h"

static void oauth2_request_free(struct oauth2_request *req)
{
	json_istream_destroy(&req->json_istream);
	io_remove(&req->io);
	i_stream_unref(&req->is);

	timeout_remove(&req->to_delayed_error);
	pool_unref(&req->pool);
}

static void
oauth2_request_callback(struct oauth2_request *req,
			struct oauth2_request_result *res)
{
	i_assert(req->req_callback != NULL);
	oauth2_request_callback_t *callback = req->req_callback;
	req->req_callback = NULL;
	callback(res, req->req_context);
	oauth2_request_free(req);
}

static bool
oauth2_request_field_parse(const struct oauth2_field *field,
			   struct oauth2_request_result *res)
{
	if (strcasecmp(field->name, "expires_in") == 0) {
		uint32_t expires_in = 0;
		if (str_to_uint32(field->value, &expires_in) < 0) {
			res->error = t_strdup_printf(
				"Malformed number '%s' in expires_in",
				field->value);
			return FALSE;
		} else {
			res->expires_at = ioloop_time + expires_in;
		}
	} else if (strcasecmp(field->name, "token_type") == 0) {
		if (strcasecmp(field->value, "bearer") != 0) {
			res->error = t_strdup_printf(
				"Expected Bearer token, got '%s'",
				field->value);
			return FALSE;
		}
	}
	return TRUE;
}

static void
oauth2_request_continue(struct oauth2_request *req, const char *error)
{
	struct oauth2_request_result res;
	i_zero(&res);

	unsigned int status_hi = req->response_status/100;
	i_assert(status_hi == 2 || status_hi == 4);

	if (error != NULL)
		res.error = error;
	else {
		const struct oauth2_field *field;
		/* see if we can figure out when it expires */
		array_foreach(&req->fields, field) {
			if (!oauth2_request_field_parse(field, &res))
				break;
		}
		res.valid = (status_hi == 2) && res.error == NULL;
	}

	res.fields = &req->fields;

	oauth2_request_callback(req, &res);
}

static int request_field_cmp(const char *key, const struct oauth2_field *field)
{
	return strcmp(key, field->name);
}

void oauth2_request_parse_json(struct oauth2_request *req)
{
	struct json_node jnode;
	struct json_istream *jinput = req->json_istream;
	const char *error;
	int ret;

	ret = 1;
	while (ret > 0) {
		ret = json_istream_read_next(jinput, &jnode);
		if (ret <= 0)
			break;
		i_assert(jnode.name != NULL);
		if (json_node_is_singular(&jnode)) {
			if (!array_is_created(&req->fields))
				p_array_init(&req->fields, req->pool, 4);
			struct oauth2_field *field =
				array_append_space(&req->fields);
			field->name = p_strdup(req->pool, jnode.name);
			field->value = p_strdup(req->pool,
						json_node_get_str(&jnode));
		}
	}

	if (ret == 0) {
		/* need more data */
		return;
	}

	if (i_stream_read_eof(req->is) &&
	    req->is->v_offset == 0 && req->is->stream_errno == 0) {
		/* discard error, empty response is OK. */
		error = NULL;
	} else {
		ret = json_istream_finish(&req->json_istream, &error);
		i_assert(ret != 0);
		if (ret < 0) {
			error = t_strdup_printf("Invalid JSON in response: %s",
						error);
		}
	}

	json_istream_destroy(&req->json_istream);
	io_remove(&req->io);
	i_stream_unref(&req->is);

	/* check if fields contain error now */
	const struct oauth2_field *error_field =
		array_lsearch(&req->fields, "error", request_field_cmp);
	if (error_field != NULL) {
		/* seems it failed, though */
		error = error_field->value;
		/* check for detailed error */
		error_field = array_lsearch(&req->fields, "error_description",
					    request_field_cmp);
		if (error_field != NULL)
			error = error_field->value;
	}

	req->json_parsed_cb(req, error);
}

static void
oauth2_request_response(const struct http_response *response,
			struct oauth2_request *req)
{
	req->response_status = response->status;
	unsigned int status_hi = req->response_status/100;

	if (status_hi != 2 && status_hi != 4) {
		/* Unexpected internal error */
		struct oauth2_request_result res = {
			.error = http_response_get_message(response),
		};
		oauth2_request_callback(req, &res);
		return;
	}

	if (response->payload != NULL) {
		req->is = response->payload;
		i_stream_ref(req->is);
	} else {
		req->is = i_stream_create_from_data("", 0);
	}

	p_array_init(&req->fields, req->pool, 1);
	req->json_istream = json_istream_create_object(
		req->is, NULL, JSON_PARSER_FLAG_NUMBERS_AS_STRING);
	req->json_parsed_cb = oauth2_request_continue;
	req->io = io_add_istream(req->is, oauth2_request_parse_json, req);
	oauth2_request_parse_json(req);
}

static void
oauth2_request_fail(struct oauth2_request *req)
{
	struct oauth2_request_result res = {
		.error = req->delayed_error != NULL ?
			 req->delayed_error : "No token provided",
		.valid = FALSE,
	};
	oauth2_request_callback(req, &res);
}

/* Allocate a request that fails asynchronously with error, without ever
   issuing an HTTP request. error == NULL means "No token provided".
   db-oauth2.c asserts that every lookup returns a non-NULL request. */
static struct oauth2_request *
oauth2_request_start_failed(const struct oauth2_settings *set,
			    oauth2_request_callback_t *callback, void *context,
			    pool_t p, const char *error)
{
	pool_t pool = (p == NULL) ?
		pool_alloconly_create_clean("oauth2 request", 1024) : p;
	struct oauth2_request *req = p_new(pool, struct oauth2_request, 1);

	req->pool = pool;
	req->set = set;
	req->req_callback = callback;
	req->req_context = context;
	req->delayed_error = p_strdup(pool, error);
	req->to_delayed_error = timeout_add_short(0, oauth2_request_fail, req);
	return req;
}

static void
oauth2_request_set_headers(struct oauth2_request *req,
			   const struct oauth2_request_input *input)
{
	if (!req->set->send_auth_headers)
		return;
	if (input->protocol != NULL) {
		http_client_request_add_header(
			req->req, "X-Dovecot-Auth-Protocol", input->protocol);
	}
	if (input->local_ip.family != 0) {
		http_client_request_add_header(
			req->req, "X-Dovecot-Auth-Local",
			net_ipport2str(&input->local_ip,
				       input->local_port));
	}
	if (input->remote_ip.family != 0) {
		http_client_request_add_header(
			req->req, "X-Dovecot-Auth-Remote",
			net_ipport2str(&input->remote_ip,
				       input->remote_port));
	}
}

static struct oauth2_request *
oauth2_request_start(const struct oauth2_settings *set,
		     const struct oauth2_request_input *input,
		     oauth2_request_callback_t *callback,
		     void *context,
		     pool_t p,
		     const char *method,
		     const struct http_url *url,
		     const string_t *payload,
		     bool add_auth_bearer,
		     bool no_token)
{
	if (!no_token && !oauth2_valid_token(input->token)) {
		return oauth2_request_start_failed(set, callback, context, p,
						   NULL);
	}

	pool_t pool = (p == NULL) ?
		pool_alloconly_create_clean("oauth2 request", 1024) : p;
	struct oauth2_request *req =
		p_new(pool, struct oauth2_request, 1);

	req->pool = pool;
	req->set = set;
	req->req_callback = callback;
	req->req_context = context;

	req->req = http_client_request_url(req->set->client, method, url,
					   oauth2_request_response, req);

	oauth2_request_set_headers(req, input);

	if (payload != NULL && strcmp(method, "POST") == 0) {
		struct istream *is = i_stream_create_from_string(payload);

		http_client_request_add_header(
			req->req, "Content-Type",
			"application/x-www-form-urlencoded");

		http_client_request_set_payload(req->req, is, FALSE);
		i_stream_unref(&is);
	}
	if (add_auth_bearer &&
	    set->introspection_mode == INTROSPECTION_MODE_GET_AUTH) {
		http_client_request_add_header(req->req,
					       "Authorization",
					       t_strdup_printf("Bearer %s",
							       input->token));
	}
	http_client_request_submit(req->req);

	return req;
}

#undef oauth2_refresh_start
struct oauth2_request *
oauth2_refresh_start(const struct oauth2_settings *set,
		     const struct oauth2_request_input *input,
		     oauth2_request_callback_t *callback, void *context)
{
	if (set->refresh_url == NULL ||
	    http_url_is_empty(set->refresh_url)) {
		return oauth2_request_start_failed(
			set, callback, context, NULL,
			"oauth2_refresh_url must be set");
	}

	pool_t pool = pool_alloconly_create_clean("oauth2 request", 1024);
	string_t *payload = str_new(pool, 128);

	str_append(payload, "grant_type=refresh_token&refresh_token=");
	http_url_escape_param(payload, input->token);

	return oauth2_request_start(set, input, callback, context,
				    pool, "POST", set->refresh_url,
				    payload, FALSE, FALSE);
}

/* Expand url_template with the request's access token and parse the
   result, for use as the request URL. Returns a request that fails
   asynchronously with a descriptive error on expansion or parse
   failure; p is used for the eventual oauth2_request_start() pool if
   given, same as there. */
static struct oauth2_request *
oauth2_url_template_start(const struct oauth2_settings *set,
			  const struct oauth2_request_input *input,
			  oauth2_request_callback_t *callback, void *context,
			  pool_t p, const char *setting_name,
			  const struct var_expand_program *url_template,
			  struct http_url **url_r)
{
	string_t *dest = t_str_new(64);
	const char *error;

	if (oauth2_url_template_expand(url_template, input->token, dest,
				       &error) < 0 ||
	    http_url_parse(str_c(dest), NULL, HTTP_URL_ALLOW_USERINFO_PART,
			   pool_datastack_create(), url_r, &error) < 0) {
		return oauth2_request_start_failed(
			set, callback, context, p,
			t_strdup_printf("%s: %s", setting_name, error));
	}
	return NULL;
}

#undef oauth2_introspection_start
struct oauth2_request *
oauth2_introspection_start(const struct oauth2_settings *set,
			   const struct oauth2_request_input *input,
			   oauth2_request_callback_t *callback, void *context)
{
	struct http_url *url;
	const char *method;
	string_t *payload = NULL;
	pool_t p = NULL;
	struct oauth2_request *failed;

	if (!oauth2_valid_token(input->token))
		return oauth2_request_start_failed(set, callback, context,
						   NULL, NULL);

	failed = oauth2_url_template_start(set, input, callback, context,
					   NULL, "oauth2_introspection_url",
					   set->introspection_url, &url);
	if (failed != NULL)
		return failed;

	switch (set->introspection_mode) {
	case INTROSPECTION_MODE_GET: {
		string_t *enc = t_str_new(64);

		if (url->enc_query != NULL)
			str_append(enc, url->enc_query);
		if (*set->client_id != '\0') {
			if (str_len(enc) > 0)
				str_append_c(enc, '&');
			str_append(enc, "client_id=");
			http_url_escape_param(enc, set->client_id);
		}
		if (*set->client_secret != '\0') {
			if (str_len(enc) > 0)
				str_append_c(enc, '&');
			str_append(enc, "client_secret=");
			http_url_escape_param(enc, set->client_secret);
		}
		url->enc_query = str_len(enc) > 0 ? str_c(enc) : NULL;
		method = "GET";
		break;
	}
	case INTROSPECTION_MODE_GET_AUTH:
		method = "GET";
		break;
	case INTROSPECTION_MODE_POST:
		p = pool_alloconly_create_clean("oauth2 request", 1024);
		payload = str_new(p, strlen(input->token)+6);
		str_append(payload, "token=");
		http_url_escape_param(payload, input->token);
		method = "POST";
		break;
	default:
		i_unreached();
	}

	return oauth2_request_start(set, input, callback, context, p,
				    method, url, payload, TRUE, FALSE);
}

#undef oauth2_token_validation_start
struct oauth2_request *
oauth2_token_validation_start(const struct oauth2_settings *set,
			      const struct oauth2_request_input *input,
			      oauth2_request_callback_t *callback,
			      void *context)
{
	struct http_url *url;
	struct oauth2_request *failed;

	if (!oauth2_valid_token(input->token))
		return oauth2_request_start_failed(set, callback, context,
						   NULL, NULL);

	failed = oauth2_url_template_start(set, input, callback, context,
					   NULL, "oauth2_tokeninfo_url",
					   set->tokeninfo_url, &url);
	if (failed != NULL)
		return failed;

	return oauth2_request_start(set, input, callback, context,
				    NULL, "GET", url, NULL, TRUE, FALSE);
}

#undef oauth2_passwd_grant_start
struct oauth2_request *
oauth2_passwd_grant_start(const struct oauth2_settings *set,
			  const struct oauth2_request_input *input,
			  const char *username, const char *password,
			  oauth2_request_callback_t *callback, void *context)
{
	if (http_url_is_empty(set->grant_url)) {
		return oauth2_request_start_failed(
			set, callback, context, NULL,
			"oauth2_grant_url must be set");
	}

	pool_t pool = pool_alloconly_create_clean("oauth2 request", 1024);
	string_t *payload = str_new(pool, 128);

	/* add token */
	str_append(payload, "grant_type=password&username=");
	http_url_escape_param(payload, username);
	str_append(payload, "&password=");
	http_url_escape_param(payload, password);
	if (*set->client_id != '\0') {
		str_append(payload, "&client_id=");
		http_url_escape_param(payload, set->client_id);
	}
	if (*set->client_secret != '\0') {
		str_append(payload, "&client_secret=");
		http_url_escape_param(payload, set->client_secret);
	}
	if (set->scope[0] != '\0') {
		str_append(payload, "&scope=");
		http_url_escape_param(payload, set->scope);
	}

	return oauth2_request_start(set, input, callback, context,
				    pool, "POST", set->grant_url,
				    payload, FALSE, FALSE);
}

#undef oauth2_client_secret_start
struct oauth2_request*
oauth2_client_secret_start(const struct oauth2_settings *set,
			  const struct oauth2_request_input *input,
			  const char *resource,
			  oauth2_request_callback_t *callback,
			  void *context)
{
	if (http_url_is_empty(set->grant_url)) {
		return oauth2_request_start_failed(
			set, callback, context, NULL,
			"oauth2_grant_url must be set");
	}

	pool_t pool = pool_alloconly_create_clean("oauth2 request", 1024);
	string_t *payload = str_new(pool, 128);

	str_append(payload, "grant_type=client_credentials");
	if (*set->client_id != '\0') {
		str_append(payload, "&client_id=");
		http_url_escape_param(payload, set->client_id);
	}
	if (*set->client_secret != '\0') {
		str_append(payload, "&client_secret=");
		http_url_escape_param(payload, set->client_secret);
	}
	str_append(payload, "&resource=");
	http_url_escape_param(payload, resource);

	return oauth2_request_start(set, input, callback, context,
				    pool, "POST", set->grant_url,
				    payload, FALSE, TRUE);
}

#undef oauth2_jwt_bearer_grant_start
struct oauth2_request *
oauth2_jwt_bearer_grant_start(const struct oauth2_settings *set,
			      const struct oauth2_request_input *input,
			      const char *assertion,
			      oauth2_request_callback_t *callback,
			      void *context)
{
	if (http_url_is_empty(set->grant_url)) {
		return oauth2_request_start_failed(
			set, callback, context, NULL,
			"oauth2_grant_url must be set");
	}

	pool_t pool = pool_alloconly_create_clean("oauth2 request", 1024);
	string_t *payload = str_new(pool, 128);

	/* Pre-escaped: http_url_escape_param() leaves ':' literal */
	str_append(payload, "grant_type="
		   "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer");
	str_append(payload, "&assertion=");
	http_url_escape_param(payload, assertion);
	if (set->client_id != NULL && *set->client_id != '\0') {
		str_append(payload, "&client_id=");
		http_url_escape_param(payload, set->client_id);
	}
	if (set->client_secret != NULL && *set->client_secret != '\0') {
		str_append(payload, "&client_secret=");
		http_url_escape_param(payload, set->client_secret);
	}
	if (set->scope != NULL && *set->scope != '\0') {
		str_append(payload, "&scope=");
		http_url_escape_param(payload, set->scope);
	}

	return oauth2_request_start(set, input, callback, context,
				    pool, "POST", set->grant_url,
				    payload, FALSE, TRUE);
}

void oauth2_request_abort(struct oauth2_request **_req)
{
	struct oauth2_request *req = *_req;
	*_req = NULL;

	if (req == NULL)
		return;

	http_client_request_abort(&req->req);
	oauth2_request_free(req);
}
