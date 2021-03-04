#ifndef DLUA_COMPAT_H
#define DLUA_COMPAT_H

/*
 * In general, make whatever Lua version we have behave more like Lua 5.3.
 */

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

#ifndef HAVE_LUA_TOINTEGERX
/*
 * Lua 5.2 and 5.3 both have lua_tointegerx(), but their behavior is subtly
 * different.  Our compatibility wrapper matches the 5.3 behavior.
 */
lua_Integer lua_tointegerx(lua_State *L, int idx, int *isnum_r);
#endif

#endif
