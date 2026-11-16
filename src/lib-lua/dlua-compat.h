#ifndef DLUA_COMPAT_H
#define DLUA_COMPAT_H

#if LUA_VERSION_NUM < 503
#  error "Lua 5.3 or newer is required"
#endif

#if LUA_VERSION_NUM < 504
/*
 * lua_resume() compatibility function. Lua 5.4 expects an extra "nresults"
 * argument.
 */
#  define lua_resume(L, from, nargs, nresults) \
	lua_resume_compat(L, from, nargs, nresults)
int lua_resume_compat(lua_State *L, lua_State *from, int nargs, int *nresults);
#endif

#endif
