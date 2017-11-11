/* Copyright (c) 2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "dlua-script-private.h"

#define LUA_SCRIPT_DOVECOT "dovecot"

static int dlua_i_debug(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	const char *msg = luaL_checkstring(script->L, 1);
	i_debug("%s", msg);
	return 0;
}

static int dlua_i_info(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	const char *msg = luaL_checkstring(script->L, 1);
	i_info("%s", msg);
	return 0;
}

static int dlua_i_warning(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	const char *msg = luaL_checkstring(script->L, 1);
	i_warning("%s", msg);
	return 0;
}

static int dlua_i_error(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	const char *msg = luaL_checkstring(script->L, 1);
	i_error("%s", msg);
	return 0;
}

static luaL_Reg lua_dovecot_methods[] = {
	{ "i_debug", dlua_i_debug },
	{ "i_info", dlua_i_info },
	{ "i_warning", dlua_i_warning },
	{ "i_error", dlua_i_error },
	{ NULL, NULL }
};

void dlua_getdovecot(struct dlua_script *script)
{
	lua_getglobal(script->L, LUA_SCRIPT_DOVECOT);
}

void dlua_dovecot_register(struct dlua_script *script)
{
	/* Create table for holding values */
	lua_newtable(script->L);

	/* push new metatable to stack */
	luaL_newmetatable(script->L, LUA_SCRIPT_DOVECOT);
	/* this will register functions to the metatable itself */
	luaL_setfuncs(script->L, lua_dovecot_methods, 0);
	/* point __index to self */
	lua_pushvalue(script->L, -1);
	lua_setfield(script->L, -1, "__index");
	/* set table's metatable, pops stack */
	lua_setmetatable(script->L, -2);

	/* register table as global */
	lua_setglobal(script->L, LUA_SCRIPT_DOVECOT);
}
