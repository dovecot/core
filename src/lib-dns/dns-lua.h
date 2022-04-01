#ifndef DNS_LUA_H
#define DNS_LUA_H

struct dns_client;

#ifdef DLUA_WITH_YIELDS
/* Internally, the dns methods yield via lua_yieldk() as implemented in Lua
   5.3 and newer. */

void dlua_push_dns_client(lua_State *L, struct dns_client *cliet);
struct dns_client *dlua_check_dns_client(lua_State *L, int idx);

#endif

#endif
