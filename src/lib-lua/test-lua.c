/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "dlua-script-private.h"

static void test_lua(void)
{
	static const char *luascript =
"function script_init(req)\n"
"  dovecot.i_debug(\"lua script init called\")\n"
"  local e = dovecot.event()\n"
"  e:log_debug(\"lua script init called from event\")\n"
"  return 0\n"
"end\n"
"function lua_function()\n"
"end\n";
	const char *error = NULL;
	struct dlua_script *script = NULL;

	test_begin("lua script");

	test_assert(dlua_script_create_string(luascript, &script, NULL, &error) == 0);
	dlua_dovecot_register(script);
	test_assert(dlua_script_init(script, &error) == 0);
	test_assert(dlua_script_has_function(script, "lua_function"));

	dlua_script_unref(&script);

	test_end();
}

int main(void) {
	void (*tests[])(void) = {
		test_lua,
		NULL
	};

	return test_run(tests);
}
