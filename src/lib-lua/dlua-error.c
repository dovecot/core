/* Copyright (c) 2021 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "dlua-script-private.h"

int dluaL_error(lua_State *L, const char *fmt, ...)
{
	va_list argp;
	va_start(argp, fmt);
	(void)dlua_push_vfstring(L, fmt, argp);
	va_end(argp);
	return lua_error(L);
}
