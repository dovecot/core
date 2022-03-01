#ifndef DICT_LUA_PRIVATE_H
#define DICT_LUA_PRIVATE_H

#include "dict-lua.h"

int lua_dict_iterate(lua_State *l);
int lua_dict_transaction_begin(lua_State *l);

#endif
