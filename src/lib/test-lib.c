/* Copyright (c) 2007-2016 Dovecot authors, see the included COPYING file */

#include "test-lib.h"

int main(int argc, char **argv)
{
	const char *match = "";
	if (argc > 2 && strcmp(argv[1], "--match") == 0)
		match = argv[2];

	static const struct named_test test_functions[] = {
#define TEST(x) TEST_NAMED(x)
#define FATAL(x)
#include "test-lib.inc"
#undef TEST
#undef FATAL
		{ NULL, NULL }
	};
	static const struct named_fatal fatal_functions[] = {
#define TEST(x)
#define FATAL(x) FATAL_NAMED(x)
#include "test-lib.inc"
#undef TEST
#undef FATAL
		{ NULL, NULL }
	};
	return test_run_named_with_fatals(match, test_functions, fatal_functions);
}
