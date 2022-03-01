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

static void oauth2_request_free(struct oauth2_request *req)
{
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

void oauth2_request_parse_json(struct oauth2_request *req)
{
	enum json_type type;
	const char *token, *error;
	int ret;

	while((ret = json_parse_next(req->parser, &type, &token)) > 0) {
		if (req->field_name == NULL) {
			if (type != JSON_TYPE_OBJECT_KEY) break;
			/* cannot use t_strdup because we might
			   have to read more */
			req->field_name = p_strdup(req->pool, token);
		} else if (type < JSON_TYPE_STRING) {
			/* this should be last allocation */
			p_free(req->pool, req->field_name);
			json_parse_skip(req->parser);
		} else {
			if (!array_is_created(&req->fields))
				p_array_init(&req->fields, req->pool, 4);
			struct oauth2_field *field =
				array_append_space(&req->fields);
			field->name = req->field_name;
			req->field_name = NULL;
			field->value = p_strdup(req->pool, token);
		}
	}

	/* read more */
	if (ret == 0) return;

	io_remove(&req->io);

	if (ret > 0) {
		(void)json_parser_deinit(&req->parser, &error);
		error = "Invalid response data";
	} else if (i_stream_read_eof(req->is) &&
		   req->is->v_offset == 0 && req->is->stream_errno == 0) {
		/* discard error, empty response is OK. */
		(void)json_parser_deinit(&req->parser, &error);
		error = NULL;
	} else if (json_parser_deinit(&req->parser, &error) == 0) {
		error = NULL;
	} else {
		i_assert(error != NULL);
	}

	i_stream_unref(&req->is);

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
	req->parser = json_parser_init(req->is);
	req->json_parsed_cb = oauth2_request_continue;
	req->io = io_add_istream(req->is, oauth2_request_parse_json, req);
	oauth2_request_parse_json(req);
}

static void
oauth2_request_set_headers(struct oauth2_request *req,
			   const struct oauth2_request_input *input)
{
	if (!req->set->send_auth_headers)
		return;
	if (input->service != NULL) {
		http_client_request_add_header(
			req->req, "X-Dovecot-Auth-Service", input->service);
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

		http_client_request_add_header(
			req->req, "Content-Type",
			"application/x-www-form-urlencoded");

		http_client_request_set_payload(req->req, is, FALSE);
		i_stream_unref(&is);
	}
	if (add_auth_bearer &&
	    http_client_request_get_origin_url(req->req)->user == NULL &&
	    set->introspection_mode == INTROSPECTION_MODE_GET_AUTH) {
		http_client_request_add_header(req->req,
					       "Authorization",
					       t_strdup_printf("Bearer %s",
							       input->token));
	}
	http_client_request_set_timeout_msecs(req->req,
					      req->set->timeout_msecs);
	http_client_request_submit(req->req);

	return req;
}

#undef oauth2_refresh_start
struct oauth2_request *
oauth2_refresh_start(const struct oauth2_settings *set,
		     const struct oauth2_request_input *input,
		     oauth2_request_callback_t *callback, void *context)
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
			   oauth2_request_callback_t *callback, void *context)
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
			  const char *username, const char *password,
			  oauth2_request_callback_t *callback, void *context)
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

void oauth2_request_abort(struct oauth2_request **_req)
{
	struct oauth2_request *req = *_req;
	*_req = NULL;

	http_client_request_abort(&req->req);
	oauth2_request_free(req);
}
