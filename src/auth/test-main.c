/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "test-common.h"
#include "test-auth.h"
#include "password-scheme.h"

int main(int argc, const char *argv[])
{
	const char *match = "";
	static const struct named_test test_functions[] = {
		TEST_NAMED(test_auth_request_var_expand)
		TEST_NAMED(test_db_dict_parse_cache_key)
		TEST_NAMED(test_username_filter)
#if defined(BUILTIN_LUA)
		TEST_NAMED(test_db_lua)
#endif
		{ NULL, NULL }
	};

	password_schemes_init();

	if (argc > 2 && strcasecmp(argv[1], "--match") == 0)
		match = argv[2];

	return test_run_named(test_functions, match);
}
