/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "dlua-script-private.h"

#if LUA_VERSION_NUM < 504
#  undef lua_resume
int lua_resume_compat(lua_State *L, lua_State *from, int nargs, int *nresults)
{
	*nresults = 1;
	return lua_resume(L, from, nargs);
}
#endif
