/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "istream.h"
#include "str.h"
#include "http-client.h"
#include "http-url.h"
#include "json-parser.h"
#include "oauth2.h"
#include "oauth2-private.h"

static void
oauth2_request_callback(struct oauth2_request *req,
			struct oauth2_request_result *res)
{
	i_assert(res->success == (res->error == NULL));
	i_assert(req->req_callback != NULL);
	oauth2_request_callback_t *callback = req->req_callback;
	req->req_callback = NULL;
	callback(res, req->req_context);
	oauth2_request_free_internal(req);
}

static bool
oauth2_request_field_parse(const struct oauth2_field *field,
			   struct oauth2_request_result *res)
{
	if (strcasecmp(field->name, "expires_in") == 0) {
		uint32_t expires_in = 0;
		if (str_to_uint32(field->value, &expires_in) < 0) {
			res->success = FALSE;
			res->error = t_strdup_printf(
				"Malformed number '%s' in expires_in",
				field->value);
			return FALSE;
		} else {
			res->expires_at = ioloop_time + expires_in;
		}
	} else if (strcasecmp(field->name, "token_type") == 0) {
		if (strcasecmp(field->value, "bearer") != 0) {
			res->success = FALSE;
			res->error = t_strdup_printf(
				"Expected Bearer token, got '%s'",
				field->value);
			return FALSE;
		}
	}
	return TRUE;
}

static void
oauth2_request_continue(struct oauth2_request *req, bool success,
			const char *error)
{
	struct oauth2_request_result res;
	i_zero(&res);

	unsigned int status_hi = req->response_status/100;

	res.success = success && (status_hi == 2 || status_hi == 4);
	res.valid = success && (status_hi == 2);
	res.error = error;

	if (res.success) {
		const struct oauth2_field *field;
		/* see if we can figure out when it expires */
		array_foreach(&req->fields, field) {
			if (!oauth2_request_field_parse(field, &res))
				break;
		}
	} else if (res.error == NULL)
		res.error = "Internal Server Error";

	res.fields = &req->fields;

	oauth2_request_callback(req, &res);
}

static void
oauth2_request_response(const struct http_response *response,
			struct oauth2_request *req)
{
	if (response->payload == NULL) {
		struct oauth2_request_result res;
		i_zero(&res);
		res.error = http_response_get_message(response);
		oauth2_request_callback(req, &res);
		return;
	}
	req->response_status = response->status;
	p_array_init(&req->fields, req->pool, 1);
	req->is = response->payload;
	i_stream_ref(req->is);
	req->parser = json_parser_init(req->is);
	req->json_parsed_cb = oauth2_request_continue;
	req->io = io_add_istream(req->is, oauth2_parse_json, req);
	oauth2_parse_json(req);
}

static struct oauth2_request *
oauth2_request_start(const struct oauth2_settings *set,
		     const struct oauth2_request_input *input,
		     oauth2_request_callback_t *callback,
		     void *context,
		     pool_t p,
		     const char *method,
		     const char *url,
		     const string_t *payload,
		     bool add_auth_bearer)
{
	i_assert(oauth2_valid_token(input->token));

	pool_t pool = (p == NULL) ?
		pool_alloconly_create_clean("oauth2 request", 1024) : p;
	struct oauth2_request *req =
		p_new(pool, struct oauth2_request, 1);

	req->pool = pool;
	req->set = set;
	req->req_callback = callback;
	req->req_context = context;

	req->req = http_client_request_url_str(req->set->client, method, url,
					       oauth2_request_response, req);

	oauth2_request_set_headers(req, input);

	if (payload != NULL && strcmp(method, "POST") == 0) {
		struct istream *is = i_stream_create_from_string(payload);

		http_client_request_add_header(req->req, "Content-Type",
					       "application/x-www-form-urlencoded");

		http_client_request_set_payload(req->req, is, FALSE);
		i_stream_unref(&is);
	}
	if (add_auth_bearer &&
	    http_client_request_get_origin_url(req->req)->user == NULL &&
	    set->introspection_mode == INTROSPECTION_MODE_GET_AUTH)
		http_client_request_add_header(req->req,
					       "Authorization",
					       t_strdup_printf("Bearer %s",
							       input->token));
	http_client_request_set_timeout_msecs(req->req,
					      req->set->timeout_msecs);
	http_client_request_submit(req->req);

	return req;
}

#undef oauth2_refresh_start
struct oauth2_request *
oauth2_refresh_start(const struct oauth2_settings *set,
		     const struct oauth2_request_input *input,
		     oauth2_request_callback_t *callback,
		     void *context)
{
	string_t *payload = t_str_new(128);
	str_append(payload, "client_secret=");
	http_url_escape_param(payload, set->client_secret);
	str_append(payload, "&grant_type=refresh_token&refresh_token=");
	http_url_escape_param(payload, input->token);
	str_append(payload, "&client_id=");
	http_url_escape_param(payload, set->client_id);

	return oauth2_request_start(set, input, callback, context, NULL,
				    "POST", set->refresh_url, NULL, FALSE);
}

#undef oauth2_introspection_start
struct oauth2_request *
oauth2_introspection_start(const struct oauth2_settings *set,
			   const struct oauth2_request_input *input,
			   oauth2_request_callback_t *callback,
			   void *context)
{

	string_t *enc;
	const char *url;
	const char *method;
	string_t *payload = NULL;
	pool_t p = NULL;
	switch (set->introspection_mode) {
	case INTROSPECTION_MODE_GET:
		enc = t_str_new(64);
		str_append(enc, set->introspection_url);
		http_url_escape_param(enc, input->token);
		str_append(enc, "&client_id=");
		http_url_escape_param(enc, set->client_id);
		str_append(enc, "&client_secret=");
		http_url_escape_param(enc, set->client_secret);
		url = str_c(enc);
		method = "GET";
		break;
	case INTROSPECTION_MODE_GET_AUTH:
		url = set->introspection_url;
		method = "GET";
		break;
	case INTROSPECTION_MODE_POST:
		p = pool_alloconly_create_clean("oauth2 request", 1024);
		payload = str_new(p, strlen(input->token)+6);
		str_append(payload, "token=");
		http_url_escape_param(payload, input->token);
		str_append(payload, "&client_id=");
		http_url_escape_param(payload, set->client_id);
		str_append(payload, "&client_secret=");
		http_url_escape_param(payload, set->client_secret);
		url = set->introspection_url;
		method = "POST";
		break;
	default:
		i_unreached();
		break;
	}

	return oauth2_request_start(set, input, callback, context, p,
				    method, url, payload, TRUE);
}

#undef oauth2_token_validation_start
struct oauth2_request *
oauth2_token_validation_start(const struct oauth2_settings *set,
			      const struct oauth2_request_input *input,
			      oauth2_request_callback_t *callback,
			      void *context)
{
	string_t *enc = t_str_new(64);
	str_append(enc, set->tokeninfo_url);
	http_url_escape_param(enc, input->token);

	return oauth2_request_start(set, input, callback, context,
				    NULL, "GET", str_c(enc), NULL, TRUE);
}

#undef oauth2_passwd_grant_start
struct oauth2_request *
oauth2_passwd_grant_start(const struct oauth2_settings *set,
			  const struct oauth2_request_input *input,
			  const char *username,
			  const char *password,
			  oauth2_request_callback_t *callback,
			  void *context)
{
	pool_t pool = pool_alloconly_create_clean("oauth2 request", 1024);
	string_t *payload = str_new(pool, 128);
	/* add token */
	str_append(payload, "grant_type=password&username=");
	http_url_escape_param(payload, username);
	str_append(payload, "&password=");
	http_url_escape_param(payload, password);
	str_append(payload, "&client_id=");
	http_url_escape_param(payload, set->client_id);
	str_append(payload, "&client_secret=");
	http_url_escape_param(payload, set->client_secret);
	if (set->scope[0] != '\0') {
		str_append(payload, "&scope=");
		http_url_escape_param(payload, set->scope);
	}

	return oauth2_request_start(set, input, callback, context,
				    pool, "POST", set->grant_url,
				    payload, FALSE);
}
