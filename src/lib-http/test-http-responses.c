/* Copyright (c) 2012 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "buffer.h"
#include "str.h"
#include "str-sanitize.h"
#include "istream.h"
#include "ostream.h"
#include "test-common.h"
#include "http-response-parser.h"

#include <stdio.h>

// FIXME: debug tool; can be removed

int main(int argc, char **argv)
{
	struct istream *input;
	struct http_response_parser *parser;
	struct http_response *response;
	const char *payload, *error = NULL;
	int ret;

	if (argc < 2)
		return 1;

	input = i_stream_create_file(argv[1], 32);
	parser = http_response_parser_init(input);

	payload = NULL;
	while ((ret=http_response_parse_next(parser, FALSE, &response, &error)) > 0) {
		printf("RESPONSE: %u %s\n", response->status, response->reason);
	}

	printf("RET: %d %s\n", ret, error);

	http_response_parser_deinit(&parser);
}

