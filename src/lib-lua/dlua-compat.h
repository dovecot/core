#ifndef DLUA_COMPAT_H
#define DLUA_COMPAT_H

/*
 * In general, make whatever Lua version we have behave more like Lua 5.3.
 */

#if !defined(LUA_OK)
#  define LUA_OK 0
#endif

/* functionality missing from <= 5.2 */
#if LUA_VERSION_NUM <= 502
#  define luaL_newmetatable(L, tn) \
	((luaL_newmetatable(L, tn) != 0) ? \
	 (lua_pushstring((L), (tn)), lua_setfield((L), -2, "__name"), 1) : \
	 0)
#endif

/* functionality missing from <= 5.1 */
#if LUA_VERSION_NUM <= 501
#  define lua_load(L, r, s, fn, m) lua_load(L, r, s, fn)
#  define luaL_newlibtable(L, l) (lua_createtable(L, 0, sizeof(l)/sizeof(*(l))-1))
#  define luaL_newlib(L, l) (luaL_newlibtable(L, l), luaL_register(L, NULL, l))
#endif

#ifndef HAVE_LUAL_SETFUNCS
void luaL_setfuncs (lua_State *L, const luaL_Reg *l, int nup);
#endif

#ifndef HAVE_LUAL_SETMETATABLE
void luaL_setmetatable (lua_State *L, const char *tname);
#endif

#ifndef HAVE_LUA_ISINTEGER
/*
 * Lua 5.3 can actually keep track of intergers vs. numbers.  As a
 * consequence, lua_isinteger() tells us if the internal representation of
 * the number is an integer (vs. a number).  In previous versions, there was
 * no way to check for this and our compatibility wrapper is not quite
 * capable of matching the 5.3 behavior exactly.  Therefore, it returns 1
 * when the number is representable as an integer instead.
 */
int lua_isinteger(lua_State *L, int idx);
#endif

#ifndef HAVE_LUA_SETI
void lua_seti(lua_State *L, int index, lua_Integer n);
#endif

#ifndef HAVE_LUA_TOINTEGERX
/*
 * Lua 5.2 and 5.3 both have lua_tointegerx(), but their behavior is subtly
 * different.  Our compatibility wrapper matches the 5.3 behavior.
 */
lua_Integer lua_tointegerx(lua_State *L, int idx, int *isnum_r);
#endif

#if LUA_VERSION_NUM > 501 && LUA_VERSION_NUM < 504
/*
 * lua_resume() compatibility function. Lua 5.4 expects an extra "nresults"
 * argeument.
 */
#  define lua_resume(L, from, nargs, nresults) \
	lua_resume_compat(L, from, nargs, nresults)
int lua_resume_compat(lua_State *L, lua_State *from, int nargs, int *nresults);
#endif

#endif
