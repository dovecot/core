/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "strnum.h"
#include "dlua-script-private.h"

#if LUA_VERSION_NUM == 502
#  error "Lua 5.2 is not supported.  Use Lua 5.1 or 5.3 instead."
#endif

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
#undef lua_isinteger
int lua_isinteger(lua_State *L, int idx)
{
	int isnum;

	if (lua_type(L, idx) != LUA_TNUMBER)
		return 0;

	(void) lua_tointegerx(L, idx, &isnum);

	return isnum;
}
#endif

#ifndef HAVE_LUA_SETI
void lua_seti(lua_State *L, int index, lua_Integer n)
{
	/* stack: value (top) */
	lua_pushinteger(L, n);
	/* stack: value, n (top) */
	lua_insert(L, -2);
	/* stack: n, value (top) */

	/* adjust relative stack position */
	if (index < 0)
		index--;

	lua_settable(L, index);
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
	const char *str;

	/*
	 * Unfortunately, Lua 5.1 doesn't provide MIN/MAX value macros for
	 * the lua_Integer type, so we hardcode the assumption that it is
	 * the same size as ptrdiff_t.  This matches what Lua does by
	 * default.
	 *
	 * If this compile-time assertion fails, don't forget to change the
	 * PTRDIFF_{MIN,MAX} usage below as well.
	 */
	(void) COMPILE_ERROR_IF_TRUE(sizeof(lua_Integer) != sizeof(ptrdiff_t));

	switch (lua_type(L, idx)) {
	case LUA_TSTRING:
		/* convert using str_to_long() */
		str = lua_tostring(L, idx);

		if (str_begins_icase(str, "0x", &str)) {
			/* hex */
			uintmax_t tmp;

			if (str_to_uintmax_hex(str, &tmp) < 0)
				break;

			*isnum_r = (tmp <= PTRDIFF_MAX) ? 1 : 0;
			return tmp;
		} else {
			/* try decimal */
			intmax_t tmp;

			if (str_to_intmax(str, &tmp) < 0)
				break;

			*isnum_r = ((tmp >= PTRDIFF_MIN) && (tmp <= PTRDIFF_MAX)) ? 1 : 0;
			return tmp;
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

#if LUA_VERSION_NUM > 501 && LUA_VERSION_NUM < 504
#  undef lua_resume
int lua_resume_compat(lua_State *L, lua_State *from, int nargs, int *nresults)
{
	*nresults = 1;
	return lua_resume(L, from, nargs);
}
#endif
