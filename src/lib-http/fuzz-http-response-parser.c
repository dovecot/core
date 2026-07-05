/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "istream.h"
#include "test-common.h"
#include "http-response.h"
#include "http-response-parser.h"
#include "fuzzer.h"

FUZZ_BEGIN_DATA(const unsigned char *data, size_t size)
{
	struct istream *input = test_istream_create_data(data, size);
	struct http_response_parser *parser =
		http_response_parser_init(input, NULL, 0);
	struct http_response response;
	const char *error;

	while (http_response_parse_next(parser,
					HTTP_RESPONSE_PAYLOAD_TYPE_ALLOWED,
					&response, &error) > 0) ;

	http_response_parser_deinit(&parser);
	i_stream_unref(&input);
}
FUZZ_END
