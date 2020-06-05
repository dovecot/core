/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "http-client.h"
#include "json-tree.h"
#include "oauth2.h"
#include "oauth2-private.h"
#include "safe-memset.h"

int oauth2_json_tree_build(const buffer_t *json, struct json_tree **tree_r,
			   const char **error_r)
{
	struct istream *is = i_stream_create_from_buffer(json);
	struct json_parser *parser = json_parser_init(is);
	struct json_tree *tree = json_tree_init();
	enum json_type type;
	const char *value;
	int ret;

	while ((ret = json_parse_next(parser, &type, &value)) > 0) {
		/* this is safe to reuse here because it gets rewritten in while
		   loop */
		ret = json_tree_append(tree, type, value);
		i_assert(ret == 0);
	}
	i_assert(ret != 0);
	ret = json_parser_deinit(&parser, error_r);
	i_stream_unref(&is);
	if (ret != 0)
		json_tree_deinit(&tree);
	else
		*tree_r = tree;
	return ret;
}

void oauth2_request_abort(struct oauth2_request **_req)
{
	struct oauth2_request *req = *_req;
	*_req = NULL;

	http_client_request_abort(&req->req);
	oauth2_request_free_internal(req);
}

void oauth2_request_free_internal(struct oauth2_request *req)
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
		http_client_request_add_header(
			req->req, "X-Dovecot-Auth-Service", input->service);
	}
	if (input->local_ip.family != 0) {
		const char *addr;
		if (net_ipport2str(&input->local_ip, input->local_port,
				   &addr) == 0)	 {
			http_client_request_add_header(
				req->req, "X-Dovecot-Auth-Local", addr);
		}
	}
	if (input->remote_ip.family != 0) {
		const char *addr;
		if (net_ipport2str(&input->remote_ip, input->remote_port,
				   &addr) == 0) {
			http_client_request_add_header(
				req->req, "X-Dovecot-Auth-Remote", addr);
		}
	}
}
