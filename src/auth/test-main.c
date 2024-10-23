/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "master-service.h"
#include "auth-settings.h"
#include "test-common.h"
#include "test-auth.h"
#include "auth-common.h"
#include "password-scheme.h"
#include "passdb.h"

int main(int argc, char *argv[])
{
	const char *match = "";
	const enum master_service_flags service_flags =
		MASTER_SERVICE_FLAG_NO_CONFIG_SETTINGS |
		MASTER_SERVICE_FLAG_STANDALONE |
		MASTER_SERVICE_FLAG_STD_CLIENT |
		MASTER_SERVICE_FLAG_DONT_SEND_STATS;
	int ret;
	static const struct named_test test_functions[] = {
		TEST_NAMED(test_auth_request_var_expand)
		TEST_NAMED(test_auth_request_fields)
		TEST_NAMED(test_username_filter)
#if defined(BUILTIN_LUA)
		TEST_NAMED(test_db_lua)
#endif
		{ NULL, NULL }
	};

	master_service = master_service_init("test-auth",
		service_flags, &argc, &argv, "");
	master_service_init_finish(master_service);

	auth_event = event_create(NULL);
	password_schemes_init();
	passdbs_init();
	passdb_mock_mod_init();

	if (argc > 2 && strcasecmp(argv[1], "--match") == 0)
		match = argv[2];

	ret = test_run_named(test_functions, match);

	passdb_mock_mod_deinit();
	password_schemes_deinit();
	passdbs_deinit();
	event_unref(&auth_event);

	master_service_deinit(&master_service);

	return ret;
}
