/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "strnum.h"
#include "dlua-script-private.h"

#ifndef HAVE_LUAL_SETFUNCS
void luaL_setfuncs(lua_State *L, const luaL_Reg *l, int nup)
{
	luaL_checkstack(L, nup + 1, "too many upvalues");
	for (; l->name != NULL; l++) {
		int i;
		lua_pushstring(L, l->name);
		for (i = 0; i < nup; i++)
			lua_pushvalue(L, -(nup + 1));
		lua_pushcclosure(L, l->func, nup);
		lua_settable(L, -(nup + 3));
	}
	lua_pop(L, nup);
}
#endif

#ifndef HAVE_LUAL_SETMETATABLE
void luaL_setmetatable(lua_State *L, const char *tname)
{
	luaL_checkstack(L, 1, "not enough stack slots");
	luaL_getmetatable(L, tname);
	lua_setmetatable(L, -2);
}
#endif

#ifndef HAVE_LUA_ISINTEGER
#  if LUA_VERSION_NUM >= 503
#    error "Lua 5.3+ should have lua_isinteger()"
#  endif
/*
 * Lua 5.3 added lua_isinteger() which tells us whether or not the input is
 * an integer.  In Lua 5.1 and 5.2, we have to emulate it.
 */
int lua_isinteger(lua_State *L, int idx)
{
	int isnum;

	if (lua_type(L, idx) != LUA_TNUMBER)
		return 0;

	(void) lua_tointegerx(L, idx, &isnum);

	return isnum;
}
#endif

#ifndef HAVE_LUA_TOINTEGERX
#  if LUA_VERSION_NUM >= 502
#    error "Lua 5.2+ should have lua_tointegerx()"
#  endif
/*
 * Lua 5.2 added lua_tointegerx() which tells us whether or not the
 * input was an integer. In Lua 5.1, we have to emulate it to the best of
 * our ability.
 */
lua_Integer lua_tointegerx(lua_State *L, int idx, int *isnum_r)
{
	lua_Integer integer;
	lua_Number number;
	unsigned long ulong;
	const char *str;

	switch (lua_type(L, idx)) {
	case LUA_TSTRING:
		/* convert using str_to_long() */
		str = lua_tostring(L, idx);

		if (str_to_long(str, &integer) == 0) {
			*isnum_r = 1;
			return integer;
		}

		/* skip over leading 0x */
		if (strncasecmp(str, "0x", 2) != 0)
			break; /* no leading 0x ==> not a hex number */

		str += 2;

		if (str_to_ulong_hex(str, &ulong) == 0) {
			bool ok;

			if (sizeof(lua_Integer) == sizeof(int32_t))
				ok = ulong <= INT32_MAX;
			else if (sizeof(lua_Integer) == sizeof(int64_t))
				ok = ulong <= INT64_MAX;
			else
				i_panic("Don't know how to convert from lua_Integer to C99 type");

			*isnum_r = ok ? 1 : 0;
			return ulong;
		}

		break;
	case LUA_TNUMBER:
		/* use lua helper macro */
		number = lua_tonumber(L, idx);

		/* Lua 5.1-only macro from luaconf.h */
		lua_number2integer(integer, number);

		*isnum_r = (((lua_Number) integer) == number) ? 1 : 0;

		return integer;
	default:
		break;
	}

	/* not an integer */
	*isnum_r = 0;
	return 0;
}
#endif
