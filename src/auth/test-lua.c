/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "test-auth.h"

#ifdef BUILTIN_LUA
#include "istream.h"
#include "auth-settings.h"
#include "auth-request.h"
#include "db-lua.h"

static void test_db_lua_auth_verify(void)
{
	struct auth_settings set;
	i_zero(&set);
	global_auth_settings = &set;

	struct auth_request *req = auth_request_new_dummy();
	req->passdb = passdb_mock();
	req->debug = TRUE;
	req->user = "testuser";

	static const char *luascript =
"function auth_password_verify(req, pass)\n"
"  req:log_debug(\"user \" .. req.user)\n"
"  if req:password_verify(\"{SHA256-CRYPT}$5$XtUywQCSjW0zAJgE$YjuPKQnsLuH4iE9kranZyy1lbil5IrRUfs7X6EyJyG1\", pass) then\n"
"      return dovecot.auth.PASSDB_RESULT_OK, {}\n"
"  end\n"
"end\n";
	const char *error = NULL;
	struct dlua_script *script = NULL;

	test_begin("auth db lua passdb_verify");

	test_assert(dlua_script_create_string(luascript, &script, NULL, &error) == 0);
	if (script != NULL) {
		test_assert(auth_lua_script_init(script, &error) == 0);
		test_assert(auth_lua_call_password_verify(script, req, "password", &error) == 1);
		dlua_script_unref(&script);
	}
	if (error != NULL) {
		i_error("Test failed: %s", error);
	}
	i_free(req->passdb);
	auth_request_unref(&req);

	test_end();
}

static void test_db_lua_auth_lookup(void)
{
	const char *scheme,*pass;
	struct auth_settings set;
	i_zero(&set);
	global_auth_settings = &set;

	struct auth_request *req = auth_request_new_dummy();
	req->passdb = passdb_mock();
	req->debug = TRUE;
	req->user = "testuser";

	static const char *luascript =
"function auth_passdb_lookup(req)\n"
"  req:log_debug(\"user \" .. req.user)\n"
"  return dovecot.auth.PASSDB_RESULT_OK, req:var_expand(\"password=pass\")\n"
"end\n";
	const char *error = NULL;
	struct dlua_script *script = NULL;

	test_begin("auth db lua passdb_lookup");

	test_assert(dlua_script_create_string(luascript, &script, NULL, &error) == 0);
	if (script != NULL) {
		test_assert(auth_lua_script_init(script, &error) == 0);
		test_assert(auth_lua_call_passdb_lookup(script, req, &scheme, &pass, &error) == 1);
		dlua_script_unref(&script);
	}
	if (error != NULL) {
		i_error("Test failed: %s", error);
	}
	i_free(req->passdb);
	auth_request_unref(&req);

	test_end();
}

void test_db_lua(void) {
	test_db_lua_auth_lookup();
	test_db_lua_auth_verify();
}

#endif
