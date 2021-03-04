/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "dlua-script-private.h"

#include <math.h>

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

	dlua_register(script, "test_assert", dlua_test_assert);

	test_assert(dlua_script_init(script, &error) == 0);
	test_assert(dlua_script_has_function(script, "lua_function"));

	lua_getglobal(script->L, "lua_test_flags");
	test_assert(lua_pcall(script->L, 0, 0, 0) == 0);

	dlua_script_unref(&script);

	test_end();
}

/* check lua_tointegerx against top-of-stack item */
static void check_tointegerx_compat(lua_State *L, int expected_isnum,
				    int expected_isint,
				    lua_Integer expected_value)
{
	lua_Integer value;
	int isnum;

	value = lua_tointegerx(L, -1, &isnum);
	test_assert(isnum == expected_isnum);

	if (isnum == 1)
		test_assert(value == expected_value);

	test_assert(lua_isinteger(L, -1) == expected_isint);

	lua_pop(L, 1);
}

static void test_compat_tointegerx_and_isinteger(void)
{
	static const struct {
		const char *input;
		lua_Integer output;
		int isnum;
	} str_tests[] = {
		{ "-1", -1, 1 },
		{ "0", 0, 1 },
		{ "1", 1, 1 },
		{ "-2147483648", -2147483648, 1 },
		{ "2147483647", 2147483647, 1 },
		{ "0x123", 0x123, 1 },
		{ "0123", 123, 1 }, /* NB: lua doesn't use leading zero for octal */
		{ "0xabcdef", 0xabcdef, 1 },
		{ "0xabcdefg", 0, 0 },
		{ "abc", 0, 0 },

		/*
		 * The following tests fail with Lua 5.2, but work on 5.1 &
		 * 5.3.  (See lua_tointegerx() comment in dlua-compat.h.)
		 *
		 * We just hack around it and provide a different set of
		 * expected test results for 5.2.
		 */
#if LUA_VERSION_NUM != 502
		{ "1.525", 0, 0 },
		{ "52.51", 0, 0 },
#else
		{ "52.51", 52, 1 },
#endif
	};
	static const struct {
		lua_Number input;
		lua_Integer output;
		int isnum;
	} num_tests[] = {
		{ -1, -1, 1 },
		{ 0, 0, 1 },
		{ 1, 1, 1 },
		{ INT_MIN, INT_MIN, 1 },
		{ INT_MAX, INT_MAX, 1 },

		/*
		 * The following tests fail with Lua 5.2, but work on 5.1 &
		 * 5.3.  (See lua_tointegerx() comment in dlua-compat.h.)
		 *
		 * We just hack around it and provide a different set of
		 * expected test results for 5.2.
		 */
#if LUA_VERSION_NUM != 502
		{ 1.525, 0, 0 },
		{ 52.51, 0, 0 },
		{ NAN, 0, 0 },
		{ +INFINITY, 0, 0},
		{ -INFINITY, 0, 0},
#else
		{ 1.525, 1, 1 },
		{ 52.51, 52, 1 },
#endif
	};
	static const struct {
		lua_Integer input;
		lua_Integer output;
	} int_tests[] = {
		{ -1, -1 },
		{ 0, 0 },
		{ 1, 1 },
		{ INT_MIN, INT_MIN },
		{ INT_MAX, INT_MAX },
	};
	struct dlua_script *script;
	const char *error;
	size_t i;

	test_begin("lua compat tostringx/isinteger");

	test_assert(dlua_script_create_string("", &script, NULL, &error) == 0);

	for (i = 0; i < N_ELEMENTS(str_tests); i++) {
		lua_pushstring(script->L, str_tests[i].input);
		check_tointegerx_compat(script->L, str_tests[i].isnum, 0,
					str_tests[i].output);
	}

	for (i = 0; i < N_ELEMENTS(num_tests); i++) {
		int isint;

		/* See lua_isinteger() comment in dlua-compat.h */
#if LUA_VERSION_NUM == 503
		isint = 0;
#else
		isint = num_tests[i].isnum;
#endif

		lua_pushnumber(script->L, num_tests[i].input);
		check_tointegerx_compat(script->L, num_tests[i].isnum,
					isint,
					num_tests[i].output);
	}

	for (i = 0; i < N_ELEMENTS(int_tests); i++) {
		lua_pushinteger(script->L, int_tests[i].input);
		check_tointegerx_compat(script->L, 1, 1,
					int_tests[i].output);
	}

	dlua_script_unref(&script);

	test_end();
}

int main(void) {
	void (*tests[])(void) = {
		test_lua,
		test_compat_tointegerx_and_isinteger,
		NULL
	};

	return test_run(tests);
}
