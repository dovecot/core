/* Copyright (c) 2022 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "net.h"
#include "dns-lookup.h"
#include "dlua-script-private.h"
#include "dlua-wrapper.h"
#include "dns-lua.h"

struct lua_dns_lookup {
	lua_State *L;
	bool resume;
};

static int lua_dns_client_lookup(lua_State *);

static luaL_Reg lua_dns_client_methods[] = {
	{ "lookup", lua_dns_client_lookup },
	{ NULL, NULL },
};

/* no actual ref counting */
static void lua_dns_client_unref(struct dns_client *client ATTR_UNUSED)
{
}

DLUA_WRAP_C_DATA(dns_client, struct dns_client,
		 lua_dns_client_unref, lua_dns_client_methods);

static int
lua_dns_client_async_continue(lua_State *L, int status ATTR_UNUSED,
			      lua_KContext ctx ATTR_UNUSED)
{
	if (lua_isnil(L, -1))
		return 3;
	else
		return 1;
}

static void
lua_dns_client_lookup_callback(const struct dns_lookup_result *result,
			       struct lua_dns_lookup *lua_lookup)
{
	lua_State *L = lua_lookup->L;

	if (result->ret != 0) {
		lua_pushnil(L);
		lua_pushstring(L, result->error);
		lua_pushinteger(L, result->ret);
	} else {
		lua_newtable(L);
		for (unsigned int i = 0; i < result->ips_count; i++) {
			lua_pushstring(L, net_ip2addr(&result->ips[i]));
			lua_seti(L, -2, i + 1);
		}
	}

	if (lua_lookup->resume)
		dlua_pcall_yieldable_resume(L, 1);
	i_free(lua_lookup);
}

/* Lookup dns record [-(2|3),+(1|3),e]

   Args:
     1) userdata: struct dns_client *dns_client
     2) string: hostname
     3) optional event

   Returns:

   On successful DNS lookup, returns a table with IP addresses (which has at
   least one IP).

   On failure, returns nil, error string, net_gethosterror() compatible error
   code (similar to e.g. Lua io.* calls).
 */
static int lua_dns_client_lookup(lua_State *L)
{
	struct dns_client *client;
	const char *host;
	struct event *event = NULL;

	DLUA_REQUIRE_ARGS_IN(L, 2, 3);

	client = xlua_dns_client_getptr(L, 1, NULL);
	host = luaL_checkstring(L, 2);
	if (lua_gettop(L) >= 3)
		event = dlua_check_event(L, 3);

	struct lua_dns_lookup *lua_lookup =
		i_new(struct lua_dns_lookup, 1);
	lua_lookup->L = L;
	struct dns_lookup *lookup;
	if (dns_client_lookup(client, host, event,
			      lua_dns_client_lookup_callback, lua_lookup,
			      &lookup) < 0) {
		/* return values are pushed to stack by the callback */
		return 3;
	}
	lua_lookup->resume = TRUE;

	return lua_dns_client_async_continue(L,
		lua_yieldk(L, 0, 0, lua_dns_client_async_continue), 0);
}

void dlua_push_dns_client(lua_State *L, struct dns_client *client)
{
	xlua_pushdns_client(L, client, FALSE);
}

struct dns_client *dlua_check_dns_client(lua_State *L, int idx)
{
	return xlua_dns_client_getptr(L, idx, NULL);
}
