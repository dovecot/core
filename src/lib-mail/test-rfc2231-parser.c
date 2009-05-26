/* Copyright (c) 2007-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "rfc822-parser.h"
#include "rfc2231-parser.h"
#include "test-common.h"

static void test_rfc2231_parser(void)
{
	const char *input =
		"; key*2=ba%"
		"; key2*0=a"
		"; key3*0*=us-ascii'en'xyz"
		"; key*0=\"foo\""
		"; key2*1*=b%25"
		"; key3*1=plop%"
		"; key*1=baz";
	const char *output[] = {
		"key",
		"foobazba%",
		"key2*",
		"''ab%25",
		"key3*",
		"us-ascii'en'xyzplop%25",
		NULL
	};
	struct rfc822_parser_context parser;
	const char *const *result;
	unsigned int i;
	bool success;

	rfc822_parser_init(&parser, (const void *)input, strlen(input), NULL);
	if (rfc2231_parse(&parser, &result) < 0)
		success = FALSE;
	else {
		success = TRUE;
		for (i = 0; output[i] != NULL && result[i] != NULL; i++) {
			if (strcmp(output[i], result[i]) != 0)
				break;
		}
		if (output[i] != NULL || result[i] != NULL)
			success = FALSE;
	}
	test_out("rfc2231_parse()", success);
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_rfc2231_parser,
		NULL
	};
	return test_run(test_functions);
}
