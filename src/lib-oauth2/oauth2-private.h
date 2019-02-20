/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */
#ifndef OAUTH2_PRIVATE_H
#define OAUTH2_PRIVATE_H 1

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

	oauth2_token_validation_callback_t *tv_callback;
	void *tv_context;

	oauth2_passwd_grant_callback_t *pg_callback;
	void *pg_context;

	oauth2_introspection_callback_t *is_callback;
	void *is_context;

	oauth2_refresh_callback_t *re_callback;
	void *re_context;

	/* indicates whether token is valid */
	bool valid:1;
};

void oauth2_request_set_headers(struct oauth2_request *req,
				const struct oauth2_request_input *input);

void oauth2_request_free_internal(struct oauth2_request *req);

void oauth2_parse_json(struct oauth2_request *req);

#endif
