/* Copyright (c) 2025 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "str.h"
#include "istream.h"
#include "ostream.h"
#include "dlua-script-private.h"
#include "test-common.h"

static unsigned int assert_count = 0;

static int dlua_test_assert(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	const char *what = luaL_checkstring(script->L, 1);
	bool cond = lua_toboolean(script->L, 2);

	if (!cond) {
		lua_Debug ar;
		i_zero(&ar);
		(void)lua_getinfo(L, ">Sl", &ar);
		test_assert_failed(what, ar.source, ar.currentline);
	}

	assert_count++;

	return 0;
}

static void test_io_lua(void)
{
	test_begin("io lua");
	buffer_t *buf = t_buffer_create(32);
	struct ostream *os = test_ostream_create(buf);
	struct dlua_script *script;
	const char *error;

	if (dlua_script_create_file(TEST_LUA_SCRIPT_DIR "/test-io-lua.lua",
				    &script, NULL, &error) < 0)
		i_fatal("%s", error);

	dlua_dovecot_register(script);
	dlua_dovecot_io_register(script);
	dlua_register(script, "test_assert", dlua_test_assert);

	if (dlua_script_init(script, &error) < 0)
		i_fatal("%s", error);

	dlua_push_ostream(script, os);
	o_stream_unref(&os);
	if (dlua_pcall(script->L, "test_write_ostream", 1, 0, &error) < 0)
		i_fatal("%s", error);
	test_assert_strcmp(str_c(buf), "hello, world");

	struct istream *is = test_istream_create(str_c(buf));
	dlua_push_istream(script, is);
	i_stream_unref(&is);
	if (dlua_pcall(script->L, "test_read_simple_istream", 1, 0, &error) < 0)
		i_fatal("%s", error);
	is = test_istream_create_data("line1\nline2\nline3\nline4\0hello\nworld", 35);
	i_stream_set_max_buffer_size(is, 1);
	dlua_push_istream(script, is);
	i_stream_unref(&is);
	if (dlua_pcall(script->L, "test_read_many", 1, 0, &error) < 0)
		i_fatal("%s", error);
	is = test_istream_create_data("hello\0world\0\1\2\3\4\5", 17);
	dlua_push_istream(script, is);
	i_stream_unref(&is);
	if (dlua_pcall(script->L, "test_read_bytes", 1, 0, &error) < 0)
		i_fatal("%s", error);

	/* Check error handling. */
	is = i_stream_create_error(EINVAL);
	dlua_push_istream(script, is);
	i_stream_unref(&is);
	if (dlua_pcall(script->L, "test_read_error", 1, 0, &error) < 0)
		i_fatal("%s", error);

	dlua_script_unref(&script);

	/* ensure all tests were actually ran */
	test_assert_ucmp(assert_count, ==, 21);

	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_io_lua,
		NULL
	};
	return test_run(test_functions);
}
