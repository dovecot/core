#ifndef DICT_LUA_H
#define DICT_LUA_H

struct dict;

void lua_dict_check_key_prefix(lua_State *L, const char *key,
			       const char *username);

void dlua_push_dict(lua_State *L, struct dict *dict);
struct dict *dlua_check_dict(lua_State *L, int idx);

void dlua_dovecot_dict_register(struct dlua_script *script);

#endif
