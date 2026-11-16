#ifndef DNS_LUA_H
#define DNS_LUA_H

struct dns_client;

void dlua_push_dns_client(lua_State *L, struct dns_client *client);
struct dns_client *dlua_check_dns_client(lua_State *L, int idx);

#endif
