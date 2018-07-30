/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "dlua-script-private.h"

static int dlua_test_assert(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	const char *what = luaL_checkstring(script->L, 1);
	bool cond = lua_toboolean(script->L, 2);

	if (!cond) {
		lua_Debug ar;
		i_assert(lua_getinfo(L, ">Sl", &ar) == 0);
		test_assert_failed(what, ar.source, ar.currentline);
	}

	return 0;
}

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
"end\n"
"function lua_test_flags()\n"
"  local flag = 0\n"
"  flag = dovecot.set_flag(flag, 2)\n"
"  flag = dovecot.set_flag(flag, 4)\n"
"  flag = dovecot.set_flag(flag, 16)\n"
"  test_assert(\"has_flag(flag, 8) == false\", dovecot.has_flag(flag, 8) == false)\n"
"  test_assert(\"has_flag(flag, 4) == true\", dovecot.has_flag(flag, 4) == true)\n"
"  flag = dovecot.clear_flag(flag, 4)\n"
"  test_assert(\"has_flag(flag, 4) == false\", dovecot.has_flag(flag, 4) == false)\n"
"  test_assert(\"has_flag(flag, 16) == true\", dovecot.has_flag(flag, 16) == true)\n"
"end\n";

	const char *error = NULL;
	struct dlua_script *script = NULL;

	test_begin("lua script");

	test_assert(dlua_script_create_string(luascript, &script, NULL, &error) == 0);
	dlua_dovecot_register(script);

	lua_pushcfunction(script->L, dlua_test_assert);
	lua_setglobal(script->L, "test_assert");

	test_assert(dlua_script_init(script, &error) == 0);
	test_assert(dlua_script_has_function(script, "lua_function"));

	lua_getglobal(script->L, "lua_test_flags");
	test_assert(lua_pcall(script->L, 0, 0, 0) == 0);

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
