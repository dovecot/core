/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

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
oauth2_refresh_callback(struct oauth2_request *req,
			struct oauth2_refresh_result *res)
{
	i_assert(res->success == (res->error == NULL));
	i_assert(req->re_callback != NULL);
	oauth2_refresh_callback_t *callback = req->re_callback;
	req->re_callback = NULL;
	callback(res, req->re_context);
	oauth2_request_free_internal(req);
}

static bool
oauth2_refresh_field_parse(const struct oauth2_field *field,
			   struct oauth2_refresh_result *res)
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
		if (strcasecmp(field->value,"bearer") != 0) {
			res->success = FALSE;
			res->error = t_strdup_printf(
				"Expected Bearer token, got '%s'",
				field->value);
			return FALSE;
		}
	} else if (strcasecmp(field->name, "access_token") == 0) {
			/* pooled memory */
			res->bearer_token = field->value;
	}
	return TRUE;
}

static void
oauth2_refresh_continue(struct oauth2_request *req, bool success,
			const char *error)
{
	struct oauth2_refresh_result res;
	i_zero(&res);

	res.success = success;
	res.error = error;

	if (res.success) {
		const struct oauth2_field *field;
		/* see if we can figure out when it expires */
		array_foreach(&req->fields, field) {
			if (!oauth2_refresh_field_parse(field, &res))
				break;
		}
	}

	res.fields = &req->fields;

	oauth2_refresh_callback(req, &res);
}

static void
oauth2_refresh_response(const struct http_response *response,
			struct oauth2_request *req)
{
	if (response->status / 100 != 2) {
		oauth2_refresh_continue(req, FALSE, response->reason);
	} else {
		if (response->payload == NULL) {
			oauth2_refresh_continue(req, FALSE, "Missing response body");
			return;
		}
		p_array_init(&req->fields, req->pool, 1);
		req->is = response->payload;
		i_stream_ref(req->is);
		req->parser = json_parser_init(req->is);
		req->json_parsed_cb = oauth2_refresh_continue;
		req->io = io_add_istream(req->is, oauth2_parse_json, req);
		req->field_name = NULL;
		oauth2_parse_json(req);
	}
}

#undef oauth2_refresh_start
struct oauth2_request*
oauth2_refresh_start(const struct oauth2_settings *set,
		     const struct oauth2_request_input *input,
		     oauth2_refresh_callback_t *callback,
		     void *context)
{
	i_assert(oauth2_valid_token(input->token));

	pool_t pool = pool_alloconly_create_clean("oauth2 refresh", 1024);
	struct oauth2_request *req =
		p_new(pool, struct oauth2_request, 1);

	req->pool = pool;
	req->set = set;
	req->re_callback = callback;
	req->re_context = context;

	req->req = http_client_request_url_str(req->set->client, "POST",
					       req->set->refresh_url,
					       oauth2_refresh_response,
					       req);
	string_t *payload = str_new(req->pool, 128);
	str_append(payload, "client_secret=");
	http_url_escape_param(payload, req->set->client_secret);
	str_append(payload, "&grant_type=refresh_token&refresh_token=");
	http_url_escape_param(payload, input->token);
	str_append(payload, "&client_id=");
	http_url_escape_param(payload, req->set->client_id);

	struct istream *is = i_stream_create_from_string(payload);

	http_client_request_add_header(req->req, "Content-Type",
				       "application/x-www-form-urlencoded");

	oauth2_request_set_headers(req, input);

	http_client_request_set_payload(req->req, is, FALSE);
	i_stream_unref(&is);
	http_client_request_set_timeout_msecs(req->req,
					      req->set->timeout_msecs);
	http_client_request_submit(req->req);

	return req;
}
