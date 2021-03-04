#ifndef DLUA_COMPAT_H
#define DLUA_COMPAT_H

/*
 * In general, make whatever Lua version we have behave more like Lua 5.3.
 */

#ifndef HAVE_LUA_TOINTEGERX
/*
 * Lua 5.2 and 5.3 both have lua_tointegerx(), but their behavior is subtly
 * different.  Our compatibility wrapper matches the 5.3 behavior.
 */
lua_Integer lua_tointegerx(lua_State *L, int idx, int *isnum_r);
#endif

#endif
