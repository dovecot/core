/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */
#ifndef OAUTH2_PRIVATE_H
#define OAUTH2_PRIVATE_H 1

struct json_tree;

struct oauth2_request {
	pool_t pool;

	const struct oauth2_settings *set;
	struct http_client_request *req;
	struct json_parser *parser;
	struct istream *is;
	struct io *io;

	const char *delayed_error;
	struct timeout *to_delayed_error;

	const char *username;

	void (*json_parsed_cb)(struct oauth2_request*, bool success,
			       const char *error);

	ARRAY_TYPE(oauth2_field) fields;
	char *field_name;

	oauth2_request_callback_t *req_callback;
	void *req_context;
	/* indicates whether token is valid */
	unsigned int response_status;
};

void oauth2_request_set_headers(struct oauth2_request *req,
				const struct oauth2_request_input *input);

void oauth2_request_free_internal(struct oauth2_request *req);

void oauth2_parse_json(struct oauth2_request *req);
int oauth2_json_tree_build(const buffer_t *json, struct json_tree **tree_r,
			   const char **error_r);

#endif
