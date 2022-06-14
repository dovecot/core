/* Copyright (c) 2021 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "dict.h"
#include "dlua-script-private.h"
#include "dict-lua-private.h"
#include "dlua-wrapper.h"

#define DICT_LUA_DOVECOT_DICT "dovecot_dict"

static int lua_dict_lookup(lua_State *);

static luaL_Reg lua_dict_methods[] = {
	{ "lookup", lua_dict_lookup },
	{ "iterate", lua_dict_iterate },
	{ "transaction_begin", lua_dict_transaction_begin },
	{ NULL, NULL },
};

/* no actual ref counting */
static void lua_dict_unref(struct dict *dict ATTR_UNUSED)
{
}

DLUA_WRAP_C_DATA(dict, struct dict, lua_dict_unref, lua_dict_methods);

static int lua_dict_async_continue(lua_State *L,
				   int status ATTR_UNUSED,
				   lua_KContext ctx ATTR_UNUSED)
{
	/*
	 * lua_dict_*_callback() already pushed the result table/nil or error
	 * string.  We simply need to return/error out.
	 */

	if (lua_istable(L, -1) || lua_isnil(L, -1))
		return 1;
	else
		return lua_error(L);
}

static void lua_dict_lookup_callback(const struct dict_lookup_result *result,
				     lua_State *L)
{
	if (result->ret < 0) {
		lua_pushstring(L, result->error);
	} else if (result->ret == 0) {
		lua_pushnil(L);
	} else {
		unsigned int i;

		lua_newtable(L);

		for (i = 0; i < str_array_length(result->values); i++) {
			lua_pushstring(L, result->values[i]);
			lua_seti(L, -2, i + 1);
		}
	}

	dlua_pcall_yieldable_resume(L, 1);
}

void lua_dict_check_key_prefix(lua_State *L, const char *key,
			       const char *username)
{
	if (str_begins_with(key, DICT_PATH_SHARED))
		;
	else if (str_begins_with(key, DICT_PATH_PRIVATE)) {
		if (username == NULL || username[0] == '\0')
			luaL_error(L, DICT_PATH_PRIVATE" dict key prefix requires username");
	} else {
		luaL_error(L, "Invalid dict key prefix");
	}
}

/*
 * Lookup a key in dict [-(2|3),+1,e]
 *
 * Args:
 *   1) userdata: struct dict *dict
 *   2) string: key
 *   3*) string: username
 *
 * Returns:
 *   If key is found, returns a table with values.  If key is not found,
 *   returns nil.
 *   Username will be NULL if not provided in args.
 */
static int lua_dict_lookup(lua_State *L)
{
	struct dict *dict;
	const char *key, *username = NULL;

	DLUA_REQUIRE_ARGS_IN(L, 2, 3);

	dict = xlua_dict_getptr(L, 1, NULL);
	key = luaL_checkstring(L, 2);
	if (lua_gettop(L) >= 3)
		username = luaL_checkstring(L, 3);
	lua_dict_check_key_prefix(L, key, username);

	struct dict_op_settings set = {
		.username = username,
	};
	dict_lookup_async(dict, &set, key, lua_dict_lookup_callback, L);

	return lua_dict_async_continue(L,
		lua_yieldk(L, 0, 0, lua_dict_async_continue), 0);
}

void dlua_push_dict(lua_State *L, struct dict *dict)
{
	xlua_pushdict(L, dict, FALSE);
}

struct dict *dlua_check_dict(lua_State *L, int idx)
{
	return xlua_dict_getptr(L, idx, NULL);
}

static struct dlua_table_values dict_lua_values[] = {
	DLUA_TABLE_ENUM_NOPREFIX(DICT_, ITERATE_FLAG_RECURSE),
	DLUA_TABLE_ENUM_NOPREFIX(DICT_, ITERATE_FLAG_SORT_BY_KEY),
	DLUA_TABLE_ENUM_NOPREFIX(DICT_, ITERATE_FLAG_SORT_BY_VALUE),
	DLUA_TABLE_ENUM_NOPREFIX(DICT_, ITERATE_FLAG_NO_VALUE),
	DLUA_TABLE_ENUM_NOPREFIX(DICT_, ITERATE_FLAG_EXACT_KEY),
	DLUA_TABLE_ENUM_NOPREFIX(DICT_, ITERATE_FLAG_ASYNC),

	DLUA_TABLE_END
};

void dlua_dovecot_dict_register(struct dlua_script *script)
{
	lua_State *L = script->L;

	dlua_get_dovecot(L);
	/* Create new table for holding values */
	lua_newtable(L);

	/* register constants */
	dlua_set_members(L, dict_lua_values, -1);

	/* push new metatable to stack */
	luaL_newmetatable(L, DICT_LUA_DOVECOT_DICT);
	/* point __index to self */
	lua_pushvalue(L, -1);
	lua_setfield(L, -1, "__index");
	/* set table's metatable, pops stack */
	lua_setmetatable(L, -2);

	/* put this as "dovecot.dict" */
	lua_setfield(L, -2, "dict");

	/* pop dovecot */
	lua_pop(L, 1);
}
