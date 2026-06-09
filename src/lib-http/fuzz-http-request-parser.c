/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "istream.h"
#include "test-common.h"
#include "http-request.h"
#include "http-request-parser.h"
#include "fuzzer.h"

FUZZ_BEGIN_DATA(const unsigned char *data, size_t size)
{
	struct istream *input = test_istream_create_data(data, size);
	struct http_request_parser *parser =
		http_request_parser_init(input, NULL, NULL, 0);
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
