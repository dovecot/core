#ifndef DOVEADM_CLIENT_LUA_H
#define DOVEADM_CLIENT_LUA_H

struct doveadm_client;

#ifdef DLUA_WITH_YIELDS
/*
 * Internally, the doveadm_client methods yield via lua_yieldk() as implemented
 * in Lua 5.3 and newer.
 */

void dlua_push_doveadm_client(lua_State *L, struct doveadm_client *client);
struct doveadm_client *dlua_check_doveadm_client(lua_State *L, int idx);

void dlua_dovecot_doveadm_client_register(struct dlua_script *script);

#endif

#endif
