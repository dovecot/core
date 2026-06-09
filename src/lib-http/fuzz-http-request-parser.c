/* Copyright (c) 2026 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "test-common.h"
#include "http-request.h"
#include "http-request-parser.h"
#include "fuzzer.h"

FUZZ_BEGIN_DATA(const unsigned char *data, size_t size)
{
	const struct http_request_limits limits = {
		.max_target_length = HTTP_REQUEST_DEFAULT_MAX_TARGET_LENGTH,
		.max_payload_size = HTTP_REQUEST_DEFAULT_MAX_PAYLOAD_SIZE,
		.header = {
			.max_size = HTTP_REQUEST_DEFAULT_MAX_HEADER_SIZE,
			.max_field_size = HTTP_REQUEST_DEFAULT_MAX_HEADER_FIELD_SIZE,
			.max_fields = HTTP_REQUEST_DEFAULT_MAX_HEADER_FIELDS,
		},
	};
	struct istream *input = test_istream_create_data(data, size);
	struct http_request_parser *parser =
		http_request_parser_init(input, NULL, &limits, 0);
	pool_t pool = pool_datastack_create();
	struct http_request request;
	enum http_request_parse_error error_code;
	const char *error;

	while (http_request_parse_next(parser, pool, &request,
				       &error_code, &error) > 0) ;

	http_request_parser_deinit(&parser);
	i_stream_unref(&input);
}
FUZZ_END
