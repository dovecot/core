/* Copyright (c) 2013-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"

#include "http-request.h"

bool http_request_has_connection_option(const struct http_request *req,
	const char *option)
{
	const char *const *opt_idx;

	array_foreach(&req->connection_options, opt_idx) {
		if (strcasecmp(*opt_idx, option) == 0)
			return TRUE;
	}
	return FALSE;
}

int http_request_get_payload_size(const struct http_request *req,
	uoff_t *size_r)
{
	if (req->payload == NULL) {
		*size_r = 0;
		return 1;
	}

	return i_stream_get_size(req->payload, TRUE, size_r);
}
