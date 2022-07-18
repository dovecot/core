/* Copyright (c) 2022 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "strescape.h"
#include "dlua-script-private.h"
#include "dlua-wrapper.h"
#include "doveadm-client.h"
#include "doveadm-client-lua.h"

#define DOVEADM_LUA_DOVECOT_DOVEADM_CLIENT "dovecot_doveadm_client"

static int lua_doveadm_client_cmd(lua_State *);

static luaL_Reg lua_doveadm_client_methods[] = {
	{ "cmd", lua_doveadm_client_cmd },
	{ NULL, NULL },
};

/* no actual ref counting */
static void lua_doveadm_client_unref(struct doveadm_client *client)
{
	doveadm_client_unref(&client);
}

DLUA_WRAP_C_DATA(doveadm_client, struct doveadm_client,
		 lua_doveadm_client_unref, lua_doveadm_client_methods);

static int
lua_doveadm_client_async_continue(lua_State *L ATTR_UNUSED,
				  int status ATTR_UNUSED,
				  lua_KContext ctx ATTR_UNUSED)
{
	/* The stack was filled by lua_doveadm_client_run_callback().
	   We return exit_code and error string to caller without converting
	   them to a Lua error. */
	return 2;
}

static void
lua_doveadm_client_run_callback(const struct doveadm_server_reply *reply,
				void *context)
{
	lua_State *L = context;

	lua_pushinteger(L, reply->exit_code);
	lua_pushstring(L, reply->error);

	dlua_pcall_yieldable_resume(L, 1);
}

static int
lua_doveadm_get_kvarray(lua_State *L, int idx, const char *const **arr_r,
			const char **error_r)
{
	const char *const *fields;

	if (dlua_strtable_to_kvarray(L, idx, pool_datastack_create(),
				     &fields, error_r) < 0)
		return -1;

	/* [ key1, value1, ... ] -> [ key1=value2, ... ] */
	ARRAY_TYPE(const_string) arr;
	t_array_init(&arr, str_array_length(fields)/2+1);

	for (unsigned int i = 0; fields[i] != NULL; i += 2) {
		i_assert(fields[i+1] != NULL);
		const char *value =
			t_strdup_printf("%s=%s", fields[i], fields[i+1]);
		array_push_back(&arr, &value);
	}
	array_append_zero(&arr);
	*arr_r = array_front(&arr);
	return 0;
}

static int
lua_doveadm_get_strescaped_str(lua_State *L, int idx, const char **value_r,
			       const char **error_r)
{
	const char *const *fields;

	if (dlua_table_to_array(L, idx, pool_datastack_create(),
				&fields, error_r) < 0)
		return -1;

	string_t *str = t_str_new(128);
	for (unsigned int i = 0; fields[i] != NULL; i++) {
		if (i > 0)
			str_append_c(str, '\t');
		str_append_tabescaped(str, fields[i]);
	}
	str_append_c(str, '\n');

	*value_r = str_c(str);
	return 0;
}

/*
 * Run a doveadm command [-(2|3),+2,e]
 *
 * Args:
 *   1) userdata: struct doveadm_client *client
 *   2) table: array of unescaped command line elements
 *   3) table: command settings
 *
 * Returns:
 *   1) integer: exit_code,
 *   2) string: error
 */
static int lua_doveadm_client_cmd(lua_State *L)
{
	struct doveadm_client *client;
	struct doveadm_client_cmd_settings set;
	const char *line, *error;

	DLUA_REQUIRE_ARGS_IN(L, 2, 3);

	i_zero(&set);
	client = xlua_doveadm_client_getptr(L, 1, NULL);

	luaL_checktype(L, 2, LUA_TTABLE);
	if (lua_doveadm_get_strescaped_str(L, 2, &line, &error) < 0)
		return luaL_error(L, "Invalid command line parameter: %s", error);

	if (lua_gettop(L) < 3)
		set.proxy_ttl = DOVEADM_PROXY_TTL;
	else {
		luaL_checktype(L, 3, LUA_TTABLE);

		lua_getfield(L, 3, "proxy_ttl");
		if (lua_isnil(L, -1))
			set.proxy_ttl = DOVEADM_PROXY_TTL;
		else
			set.proxy_ttl = luaL_checkinteger(L, -1);
		lua_pop(L, 1);

		lua_getfield(L, 3, "forward_fields");
		if (!lua_isnil(L, -1)) {
			luaL_checktype(L, -1, LUA_TTABLE);
			if (lua_doveadm_get_kvarray(L, -1, &set.forward_fields, &error) < 0)
				return luaL_error(L, "invalid forward_fields: %s", error);
		}
		lua_pop(L, 1);
	}

	doveadm_client_cmd(client, &set, line, NULL,
			   lua_doveadm_client_run_callback, L);
	return lua_doveadm_client_async_continue(L,
		lua_yieldk(L, 0, 0, lua_doveadm_client_async_continue), 0);
}

void dlua_push_doveadm_client(lua_State *L, struct doveadm_client *client)
{
	xlua_pushdoveadm_client(L, client, FALSE);
}

struct doveadm_client *dlua_check_doveadm_client(lua_State *L, int idx)
{
	return xlua_doveadm_client_getptr(L, idx, NULL);
}

static struct dlua_table_values doveadm_client_lua_values[] = {
	DLUA_TABLE_ENUM(DOVEADM_PROXY_TTL),

	DLUA_TABLE_END
};

void dlua_dovecot_doveadm_client_register(struct dlua_script *script)
{
	lua_State *L = script->L;

	dlua_get_dovecot(L);
	/* Create new table for holding values */
	lua_newtable(L);

	/* register constants */
	dlua_set_members(L, doveadm_client_lua_values, -1);

	/* push new metatable to stack */
	luaL_newmetatable(L, DOVEADM_LUA_DOVECOT_DOVEADM_CLIENT);
	/* point __index to self */
	lua_pushvalue(L, -1);
	lua_setfield(L, -1, "__index");
	/* set table's metatable, pops stack */
	lua_setmetatable(L, -2);

	/* put this as "dovecot.doveadm_client" */
	lua_setfield(L, -2, "doveadm_client");

	/* pop dovecot */
	lua_pop(L, 1);
}
