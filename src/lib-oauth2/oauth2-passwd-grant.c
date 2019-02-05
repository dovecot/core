/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "ioloop.h"
#include "istream.h"
#include "strnum.h"
#include "http-client.h"
#include "http-url.h"
#include "json-parser.h"
#include "oauth2.h"
#include "oauth2-private.h"

static void
oauth2_passwd_grant_callback(struct oauth2_request *req,
			     struct oauth2_passwd_grant_result *res)
{
	i_assert(res->success == (res->error == NULL));
	i_assert(req->pg_callback != NULL);
	oauth2_passwd_grant_callback_t *callback = req->pg_callback;
	req->pg_callback = NULL;
	callback(res, req->pg_context);
	oauth2_request_free_internal(req);
}

static void
oauth2_passwd_grant_continue(struct oauth2_request *req, bool success,
			     const char *error)
{
	struct oauth2_passwd_grant_result res;
	i_zero(&res);

	i_assert(array_is_created(&req->fields) || !success);

	res.success = success;
	res.error = error;
	res.valid = req->valid;

	if (res.success) {
		const struct oauth2_field *field;
		/* see if we can figure out when it expires */
		array_foreach(&req->fields, field) {
			if (strcasecmp(field->name, "expires_in") == 0) {
				uint32_t expires_in = 0;
				if (str_to_uint32(field->value, &expires_in) < 0) {
					res.success = FALSE;
					res.error = "Malformed number in expires_in";
				} else {
					res.expires_at = ioloop_time + expires_in;
				}
				break;
			}
		}
	}

	res.fields = &req->fields;

	oauth2_passwd_grant_callback(req, &res);
}

static void
oauth2_passwd_grant_response(const struct http_response *response,
			     struct oauth2_request *req)
{
	unsigned int status_1 = response->status / 100;

	if (status_1 != 2 && status_1 != 4) {
		oauth2_passwd_grant_continue(req, FALSE, response->reason);
	} else {
		if (status_1 == 2)
			req->valid = TRUE;
		else
			req->valid = FALSE;
		p_array_init(&req->fields, req->pool, 1);
		/* 2xx is sufficient for token validation */
		if (response->payload == NULL) {
			oauth2_passwd_grant_continue(req, TRUE, NULL);
			return;
		}
		req->is = response->payload;
		i_stream_ref(req->is);
		req->parser = json_parser_init(req->is);
		req->json_parsed_cb = oauth2_passwd_grant_continue;
		req->io = io_add_istream(req->is, oauth2_parse_json, req);
		oauth2_parse_json(req);
	}
}

#undef oauth2_passwd_grant_start
struct oauth2_request *
oauth2_passwd_grant_start(const struct oauth2_settings *set,
			  const struct oauth2_request_input *input,
			  const char *username,
			  const char *password,
			  oauth2_passwd_grant_callback_t *callback,
			  void *context)
{
	i_assert(oauth2_valid_token(input->token));

	pool_t pool = pool_alloconly_create_clean("oauth2 passwd_grant", 1024);
	struct oauth2_request *req =
		p_new(pool, struct oauth2_request, 1);

	req->pool = pool;
	req->set = set;
	req->pg_callback = callback;
	req->pg_context = context;

	req->req = http_client_request_url_str(req->set->client, "POST",
					       req->set->grant_url,
					       oauth2_passwd_grant_response,
					       req);
	string_t *payload = str_new(pool, 128);
	/* add token */
	str_append(payload, "grant_type=password&username=");
	http_url_escape_param(payload, username);
	str_append(payload, "&password=");
	http_url_escape_param(payload, password);
	str_append(payload, "&client_id=");
	http_url_escape_param(payload, req->set->client_id);
	http_client_request_add_header(req->req, "Content-Type",
				       "application/x-www-form-urlencoded");
	http_client_request_set_payload_data(req->req, payload->data, payload->used);

	oauth2_request_set_headers(req, input);

	http_client_request_set_timeout_msecs(req->req,
					      req->set->timeout_msecs);
	http_client_request_submit(req->req);

	return req;
}
