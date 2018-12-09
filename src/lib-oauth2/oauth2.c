/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "istream.h"
#include "http-client.h"
#include "json-parser.h"
#include "oauth2.h"
#include "oauth2-private.h"
#include "safe-memset.h"

void
oauth2_parse_json(struct oauth2_request *req)
{
	bool success;
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
			json_parse_skip_next(req->parser);
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
		success = FALSE;
	} else if (i_stream_read_eof(req->is) &&
		   req->is->v_offset == 0 && req->is->stream_errno == 0) {
		/* discard error, empty response is OK. */
		(void)json_parser_deinit(&req->parser, &error);
		error = NULL;
		success = TRUE;
	} else {
		ret = json_parser_deinit(&req->parser, &error);
		success = (ret == 0);
	}

	i_stream_unref(&req->is);

	req->json_parsed_cb(req, success, error);
}

void
oauth2_request_abort(struct oauth2_request **_req)
{
	struct oauth2_request *req = *_req;
	*_req = NULL;

	http_client_request_abort(&req->req);
	oauth2_request_free_internal(req);
}

void
oauth2_request_free_internal(struct oauth2_request *req)
{
	timeout_remove(&req->to_delayed_error);
	pool_unref(&req->pool);
}

bool oauth2_valid_token(const char *token)
{
	if (token == NULL || *token == '\0' || strpbrk(token, "\r\n") != NULL)
		return FALSE;
	return TRUE;
}

void oauth2_request_set_headers(struct oauth2_request *req,
				const struct oauth2_request_input *input)
{
	if (!req->set->send_auth_headers)
		return;
	if (input->service != NULL) {
		http_client_request_add_header(req->req, "X-Dovecot-Auth-Service",
					       input->service);
	}
	if (input->local_ip.family != 0) {
		const char *addr;
		if (net_ipport2str(&input->local_ip, input->local_port, &addr) == 0)	
			http_client_request_add_header(req->req, "X-Dovecot-Auth-Local", addr);
	}
	if (input->remote_ip.family != 0) {
		const char *addr;
		if (net_ipport2str(&input->remote_ip, input->remote_port, &addr) == 0)    
			http_client_request_add_header(req->req, "X-Dovecot-Auth-Remote", addr);
	}
}
