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

#define GENERATE_GETTERS(name, ctype)					\
static void check_table_get_##name##_ok(struct dlua_script *script,	\
					int idx, ctype expected_value,	\
					const char *str_key,		\
					lua_Integer int_key)		\
{									\
	ctype value;							\
	int ret;							\
									\
	/* check string key */						\
	ret = dlua_table_get_##name##_by_str(script->L, idx,		\
					     str_key, &value);		\
	test_assert(ret == 1);						\
	test_assert(value == expected_value);				\
									\
	/* check int key */						\
	ret = dlua_table_get_##name##_by_int(script->L, idx,		\
					     int_key, &value);		\
	test_assert(ret == 1);						\
	test_assert(value == expected_value);				\
}									\
static void check_table_get_##name##_err(struct dlua_script *script,	\
					 int idx, int expected_ret,	\
					 const char *str_key,		\
					 lua_Integer int_key)		\
{									\
	ctype value;							\
	int ret;							\
									\
	/* check string key */						\
	ret = dlua_table_get_##name##_by_str(script->L, idx,		\
					     str_key, &value);		\
	test_assert(ret == expected_ret);				\
									\
	/* check int key */						\
	ret = dlua_table_get_##name##_by_int(script->L, idx,		\
					     int_key, &value);		\
	test_assert(ret == expected_ret);				\
}

GENERATE_GETTERS(luainteger, lua_Integer);
GENERATE_GETTERS(int, int);
GENERATE_GETTERS(intmax, intmax_t);
GENERATE_GETTERS(uint, unsigned int);
GENERATE_GETTERS(uintmax, uintmax_t);
GENERATE_GETTERS(number, lua_Number);
GENERATE_GETTERS(bool, bool);

/* the string comparison requires us to open-code this */
static void check_table_get_string_ok(struct dlua_script *script,
				      int idx, const char *expected_value,
				      const char *str_key,
				      lua_Integer int_key)
{
	const char *value;
	int ret;

	/* check string key */
	ret = dlua_table_get_string_by_str(script->L, idx,
					   str_key, &value);
	test_assert(ret == 1);
	test_assert_strcmp(value, expected_value);

	/* check int key */
	ret = dlua_table_get_string_by_int(script->L, idx,
					   int_key, &value);
	test_assert(ret == 1);
	test_assert_strcmp(value, expected_value);

	/* TODO: check thread key, which is difficult */
}

/* the string comparison of the _ok function requires us to open-code this */
static void check_table_get_string_err(struct dlua_script *script,
				       int idx, int expected_ret,
				       const char *str_key,
				       lua_Integer int_key)
{
	const char *value;
	int ret;

	/* check string key */
	ret = dlua_table_get_string_by_str(script->L, idx,
					   str_key, &value);
	test_assert(ret == expected_ret);

	/* check int key */
	ret = dlua_table_get_string_by_int(script->L, idx,
					   int_key, &value);
	test_assert(ret == expected_ret);

	/* TODO: check thread key, which is difficult */
}

static void check_table_missing(struct dlua_script *script, int idx,
				const char *str_key,
				lua_Integer int_key)
{
	check_table_get_luainteger_err(script, idx, 0, str_key, int_key);
	check_table_get_int_err(script, idx, 0, str_key, int_key);
	check_table_get_intmax_err(script, idx, 0, str_key, int_key);
	check_table_get_uint_err(script, idx, 0, str_key, int_key);
	check_table_get_uintmax_err(script, idx, 0, str_key, int_key);
	check_table_get_number_err(script, idx, 0, str_key, int_key);
	check_table_get_bool_err(script, idx, 0, str_key, int_key);
	check_table_get_string_err(script, idx, 0, str_key, int_key);
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
"end\n"
"function lua_test_get_table()\n"
"  t = {}\n"
"  -- zero\n"
"  t[\"zero\"] = 0\n"
"  t[-2] = 0\n"
"  -- small positive values\n"
"  t[\"small-positive-int\"] = 1\n"
"  t[-1] = 1\n"
"  -- small negative values\n"
"  t[\"small-negative-int\"] = -5\n"
"  t[0] = -5\n"
"  -- large positive float\n"
"  t[\"large-positive-int\"] = 2^48\n"
"  t[1] = 2^48\n"
"  -- large negative float\n"
"  t[\"large-negative-int\"] = -2^48\n"
"  t[2] = -2^48\n"
"  -- small float\n"
"  t[\"small-float\"] = 1.525\n"
"  t[3] = 1.525\n"
"  -- bool: true\n"
"  t[\"bool-true\"] = true\n"
"  t[4] = true\n"
"  -- bool: false\n"
"  t[\"bool-false\"] = false\n"
"  t[5] = false\n"
"  -- string\n"
"  t[\"str\"] = \"string\"\n"
"  t[6] = \"string\"\n"
"  return t\n"
"end\n"
"function lua_test_get_strtable()\n"
"  return {\n"
"    ['key1'] = 'value1',\n"
"    [2] = 123\n"
"  }\n"
"end\n"
"function lua_test_get_strtable_badvalue()\n"
"  return {\n"
"    ['key1'] = 'value1',\n"
"    ['key2'] = {}\n"
"  }\n"
"end\n"
;

	const char *error = NULL;
	struct dlua_script *script = NULL;

	test_begin("lua script");

	test_assert(dlua_script_create_string(luascript, &script, NULL, &error) == 0);
	if (error != NULL)
		i_fatal("dlua_script_init failed: %s", error);

	dlua_dovecot_register(script);

	dlua_register(script, "test_assert", dlua_test_assert);

	test_assert(dlua_script_init(script, &error) == 0);
	test_assert(dlua_script_has_function(script, "lua_function"));

	test_assert(dlua_pcall(script->L, "lua_test_flags", 0, 0, &error) == 0);

	lua_getglobal(script->L, "lua_test_get_table");
	test_assert(lua_pcall(script->L, 0, 1, 0) == 0);

	/*
	 * Check table getters
	 */

	/* lua_Integer */
	check_table_get_luainteger_ok(script, -1, 0, "zero", -2);
	check_table_get_luainteger_ok(script, -1, 1, "small-positive-int", -1);
	check_table_get_luainteger_ok(script, -1, -5, "small-negative-int", 0);
	check_table_get_luainteger_ok(script, -1, 1ll<<48, "large-positive-int", 1);
	check_table_get_luainteger_ok(script, -1, -(1ll<<48), "large-negative-int", 2);
	check_table_get_luainteger_err(script, -1, -1, "small-float", 3);
	check_table_get_luainteger_err(script, -1, -1, "bool-true", 4);
	check_table_get_luainteger_err(script, -1, -1, "bool-false", 5);
	check_table_get_luainteger_err(script, -1, -1, "str", 6);

	/* int */
	check_table_get_int_ok(script, -1, 0, "zero", -2);
	check_table_get_int_ok(script, -1, 1, "small-positive-int", -1);
	check_table_get_int_ok(script, -1, -5, "small-negative-int", 0);
	check_table_get_int_err(script, -1, -1, "large-positive-int", 1);
	check_table_get_int_err(script, -1, -1, "large-negative-int", 2);
	check_table_get_int_err(script, -1, -1, "small-float", 3);
	check_table_get_int_err(script, -1, -1, "bool-true", 4);
	check_table_get_int_err(script, -1, -1, "bool-false", 5);
	check_table_get_int_err(script, -1, -1, "str", 6);

	/* intmax_t */
	check_table_get_intmax_ok(script, -1, 0, "zero", -2);
	check_table_get_intmax_ok(script, -1, 1, "small-positive-int", -1);
	check_table_get_intmax_ok(script, -1, -5, "small-negative-int", 0);
	check_table_get_intmax_ok(script, -1, 1ll<<48, "large-positive-int", 1);
	check_table_get_intmax_ok(script, -1, -(1ll<<48), "large-negative-int", 2);
	check_table_get_intmax_err(script, -1, -1, "small-float", 3);
	check_table_get_intmax_err(script, -1, -1, "bool-true", 4);
	check_table_get_intmax_err(script, -1, -1, "bool-false", 5);
	check_table_get_intmax_err(script, -1, -1, "str", 6);

	/* unsigned int */
	check_table_get_uint_ok(script, -1, 0, "zero", -2);
	check_table_get_uint_ok(script, -1, 1, "small-positive-int", -1);
	check_table_get_uint_err(script, -1, -1, "small-negative-int", 0);
	check_table_get_uint_err(script, -1, -1, "large-positive-int", 1);
	check_table_get_uint_err(script, -1, -1, "large-negative-int", 2);
	check_table_get_uint_err(script, -1, -1, "small-float", 3);
	check_table_get_uint_err(script, -1, -1, "bool-true", 4);
	check_table_get_uint_err(script, -1, -1, "bool-false", 5);
	check_table_get_uint_err(script, -1, -1, "str", 6);

	/* uintmax_t */
	check_table_get_uintmax_ok(script, -1, 0, "zero", -2);
	check_table_get_uintmax_ok(script, -1, 1, "small-positive-int", -1);
	check_table_get_uintmax_err(script, -1, -1, "small-negative-int", 0);
	check_table_get_uintmax_ok(script, -1, 1ll<<48, "large-positive-int", 1);
	check_table_get_uintmax_err(script, -1, -1, "large-negative-int", 2);
	check_table_get_uintmax_err(script, -1, -1, "small-float", 3);
	check_table_get_uintmax_err(script, -1, -1, "bool-true", 4);
	check_table_get_uintmax_err(script, -1, -1, "bool-false", 5);
	check_table_get_uintmax_err(script, -1, -1, "str", 6);

	/* lua_Number */
	check_table_get_number_ok(script, -1, 0, "zero", -2);
	check_table_get_number_ok(script, -1, 1, "small-positive-int", -1);
	check_table_get_number_ok(script, -1, -5, "small-negative-int", 0);
	check_table_get_number_ok(script, -1, 1ll<<48, "large-positive-int", 1);
	check_table_get_number_ok(script, -1, -(1ll<<48), "large-negative-int", 2);
	check_table_get_number_ok(script, -1, 1.525, "small-float", 3);
	check_table_get_number_err(script, -1, -1, "bool-true", 4);
	check_table_get_number_err(script, -1, -1, "bool-false", 5);
	check_table_get_number_err(script, -1, -1, "str", 6);

	/* bool */
	check_table_get_bool_err(script, -1, -1, "zero", -2);
	check_table_get_bool_err(script, -1, -1, "small-positive-int", -1);
	check_table_get_bool_err(script, -1, -1, "small-negative-int", 0);
	check_table_get_bool_err(script, -1, -1, "large-positive-int", 1);
	check_table_get_bool_err(script, -1, -1, "large-negative-int", 2);
	check_table_get_bool_err(script, -1, -1, "small-float", 3);
	check_table_get_bool_ok(script, -1, TRUE, "bool-true", 4);
	check_table_get_bool_ok(script, -1, FALSE, "bool-false", 5);
	check_table_get_bool_err(script, -1, -1, "str", 6);

	/* const char * */
	check_table_get_string_err(script, -1, -1, "zero", -2);
	check_table_get_string_err(script, -1, -1, "small-positive-int", -1);
	check_table_get_string_err(script, -1, -1, "small-negative-int", 0);
	check_table_get_string_err(script, -1, -1, "large-positive-int", 1);
	check_table_get_string_err(script, -1, -1, "large-negative-int", 2);
	check_table_get_string_err(script, -1, -1, "small-float", 3);
	check_table_get_string_err(script, -1, -1, "bool-true", 4);
	check_table_get_string_err(script, -1, -1, "bool-false", 5);
	check_table_get_string_ok(script, -1, "string", "str", 6);

	check_table_missing(script, -1, "missing", -10);

	lua_pop(script->L, 1);

	/* strtable */
	lua_getglobal(script->L, "lua_test_get_strtable");
	test_assert(lua_pcall(script->L, 0, 1, 0) == 0);
	const char *const *arr;
	test_assert(dlua_strtable_to_kvarray(script->L, -1,
					     pool_datastack_create(),
					     &arr, &error) == 0);
	/* the keys could be in any order */
	if (strcmp(arr[0], "key1") == 0) {
		test_assert_strcmp(arr[1], "value1");
		test_assert_strcmp(arr[2], "2");
		test_assert_strcmp(arr[3], "123");
	} else {
		test_assert_strcmp(arr[0], "2");
		test_assert_strcmp(arr[1], "123");
		test_assert_strcmp(arr[2], "key1");
		test_assert_strcmp(arr[3], "value1");
	}
	test_assert(arr[4] == NULL);
	test_assert(dlua_table_to_array(script->L, -1, pool_datastack_create(),
					&arr, &error) == 0);
	if (strcmp(arr[0], "value1") == 0)
		test_assert_strcmp(arr[1], "123");
	else {
		test_assert_strcmp(arr[0], "123");
		test_assert_strcmp(arr[1], "value1");
	}
	lua_pop(script->L, 1);

	/* strtable - bad value */
	lua_getglobal(script->L, "lua_test_get_strtable_badvalue");
	test_assert(lua_pcall(script->L, 0, 1, 0) == 0);
	test_assert(dlua_strtable_to_kvarray(script->L, -1,
					     pool_datastack_create(),
					     &arr, &error) == -1);
	test_assert(dlua_table_to_array(script->L, -1, pool_datastack_create(),
					&arr, &error) == -1);
	lua_pop(script->L, 1);

	dlua_script_unref(&script);

	test_end();
}

static void test_tls(void)
{
	const char *error = NULL;
	struct dlua_script *script = NULL;
	lua_State *L1, *L2;

	test_begin("lua thread local storage");

	test_assert(dlua_script_create_string("", &script, NULL, &error) == 0);
	if (error != NULL)
		i_fatal("dlua_script_init failed: %s", error);

	L1 = dlua_script_new_thread(script);
	L2 = dlua_script_new_thread(script);

	dlua_tls_set_ptr(L1, "ptr", L1);
	test_assert(dlua_tls_get_ptr(L1, "ptr") == L1);
	test_assert(dlua_tls_get_ptr(L2, "ptr") == NULL);
	test_assert(dlua_tls_get_int(L1, "int") == 0);
	test_assert(dlua_tls_get_int(L2, "int") == 0);

	dlua_tls_set_ptr(L2, "ptr", L2);
	test_assert(dlua_tls_get_ptr(L1, "ptr") == L1);
	test_assert(dlua_tls_get_ptr(L2, "ptr") == L2);
	test_assert(dlua_tls_get_int(L1, "int") == 0);
	test_assert(dlua_tls_get_int(L2, "int") == 0);

	dlua_tls_set_int(L1, "int", 1);
	dlua_tls_set_int(L2, "int", 2);
	test_assert(dlua_tls_get_int(L1, "int") == 1);
	test_assert(dlua_tls_get_int(L2, "int") == 2);

	dlua_tls_clear(L1, "ptr");
	test_assert(dlua_tls_get_ptr(L1, "ptr") == NULL);
	test_assert(dlua_tls_get_ptr(L2, "ptr") == L2);
	test_assert(dlua_tls_get_int(L1, "int") == 1);
	test_assert(dlua_tls_get_int(L2, "int") == 2);

	dlua_script_close_thread(script, &L1);

	test_assert(dlua_tls_get_ptr(L2, "ptr") == L2);
	test_assert(dlua_tls_get_int(L2, "int") == 2);

	dlua_tls_clear(L2, "ptr");
	dlua_script_close_thread(script, &L2);

	dlua_script_unref(&script);

	test_end();
}

/* check lua_tointegerx against top-of-stack item */
static void check_tointegerx_compat(lua_State *L, bool expected_isnum,
				    bool expected_isint,
				    lua_Integer expected_value)
{
	lua_Integer value;
	int isnum;

	value = lua_tointegerx(L, -1, &isnum);
	test_assert((isnum == 1) == expected_isnum);

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
		bool isnum;
	} str_tests[] = {
		{ "-1", -1, TRUE },
		{ "0", 0, TRUE },
		{ "1", 1, TRUE },
		{ "-2147483648", -2147483648, TRUE },
		{ "2147483647", 2147483647, TRUE },
		{ "0x123", 0x123, TRUE },
		{ "0123", 123, TRUE }, /* NB: lua doesn't use leading zero for octal */
		{ "0xabcdef", 0xabcdef, TRUE },
		{ "0xabcdefg", 0, FALSE },
		{ "abc", 0, FALSE },
		{ "1.525", 0, FALSE },
		{ "52.51", 0, FALSE },
	};
	static const struct {
		lua_Number input;
		lua_Integer output;
		bool isnum;
	} num_tests[] = {
		{ -1, -1, TRUE },
		{ 0, 0, TRUE },
		{ 1, 1, TRUE },
		{ INT_MIN, INT_MIN, TRUE },
		{ INT_MAX, INT_MAX, TRUE },
		{ 1.525, 0, FALSE },
		{ 52.51, 0, FALSE },
		{ NAN, 0, FALSE },
		{ +INFINITY, 0, FALSE },
		{ -INFINITY, 0, FALSE },
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
		check_tointegerx_compat(script->L, str_tests[i].isnum, FALSE,
					str_tests[i].output);
	}

	for (i = 0; i < N_ELEMENTS(num_tests); i++) {
		bool isint;

		/* See lua_isinteger() comment in dlua-compat.h */
#if LUA_VERSION_NUM >= 503
		isint = FALSE;
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
		check_tointegerx_compat(script->L, TRUE, TRUE,
					int_tests[i].output);
	}

	dlua_script_unref(&script);

	test_end();
}

int main(void) {
	void (*tests[])(void) = {
		test_lua,
		test_tls,
		test_compat_tointegerx_and_isinteger,
		NULL
	};

	return test_run(tests);
}
