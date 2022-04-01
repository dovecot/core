/* Copyright (c) 2021 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "dlua-script-private.h"
#include "dict-private.h"
#include "dict-lua.h"
#include "test-common.h"

#include <fcntl.h>
#include <sys/stat.h>

static void test_dict_register(void)
{
	dict_driver_register(&dict_driver_file);
}

static void test_dict_finished(lua_State *L, struct ioloop *ioloop, int res)
{
	if (res < 0) {
		i_error("%s", lua_tostring(L, -1));
		lua_pop(L, 1);
	}
	io_loop_stop(ioloop);
}

static void test_dict_lua(void)
{
	static const char *luascript =
"function test_dict(dict)\n"
"  local trans = dict:transaction_begin()\n"
"  trans:set('shared/testkey', 'testvalue')\n"
"  trans:set('shared/testkey2', 'testvalue2')\n"
"  trans:commit()\n"
"\n"
"  assert(dict:lookup('shared/testkey')[1] == 'testvalue')\n"
"  assert(dict:lookup('shared/testkey2')[1] == 'testvalue2')\n"
"\n"
"  local key, values\n"
"  local table = {}\n"
"  for key, values in dict:iterate('shared/', 0) do\n"
"    assert(#values == 1)\n"
"    table[key] = values[1]\n"
"  end\n"
"  assert(table['shared/testkey'] == 'testvalue')\n"
"  assert(table['shared/testkey2'] == 'testvalue2')\n"
"\n"
"  trans = dict:transaction_begin()\n"
"  trans:set_timestamp({['tv_sec'] = 1631278269, ['tv_nsec'] = 999999999})\n"
"  trans:set('shared/testkey', 'updated')\n"
"  trans:unset('shared/testkey2')\n"
"  trans:commit()\n"
"\n"
"  assert(dict:lookup('shared/testkey')[1] == 'updated')\n"
"  assert(dict:lookup('shared/testkey2') == nil)\n"
"end\n";
	struct dict_settings set = {
		.base_dir = NULL,
	};
	struct dict *dict;
	const char *error;

	test_begin("dict lua");
	struct ioloop *ioloop = io_loop_create();
	i_unlink_if_exists(".test.dict");
	if (dict_init("file:.test.dict", &set, &dict, &error) < 0)
		i_fatal("dict_init(.test.dict) failed: %s", error);

	struct dlua_script *script;
	if (dlua_script_create_string(luascript, &script, NULL, &error) < 0)
		i_fatal("dlua_script_create_string() failed: %s", error);
	dlua_dovecot_register(script);
	if (dlua_script_init(script, &error) < 0)
		i_fatal("dlua_script_init() failed: %s", error);

	lua_State *thread = dlua_script_new_thread(script);
	dlua_push_dict(thread, dict);
	if (dlua_pcall_yieldable(thread, "test_dict", 1, test_dict_finished,
				 ioloop, &error) < 0)
		i_fatal("dlua_pcall() failed: %s", error);
	io_loop_run(ioloop);
	i_assert(lua_gettop(thread) == 0);
	dlua_script_close_thread(script, &thread);

	dlua_script_unref(&script);
	dict_deinit(&dict);
	io_loop_destroy(&ioloop);

	i_unlink(".test.dict");
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_dict_register,
		test_dict_lua,
		NULL
	};
	return test_run(test_functions);
}
