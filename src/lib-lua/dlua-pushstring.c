/* Copyright (c) 2021 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "dlua-script-private.h"

const char *dlua_push_vfstring(lua_State *L, const char *fmt, va_list argp)
{
	const char *str;
	T_BEGIN {
		str = t_strdup_vprintf(fmt, argp);
		(void)lua_pushstring(L, str);
		str = lua_tostring(L, -1);
	} T_END;
	return str;
}

const char *dlua_push_fstring(lua_State *L, const char *fmt, ...)
{
	const char *str;
	va_list argp;
	va_start(argp, fmt);
	str = dlua_push_vfstring(L, fmt, argp);
	va_end(argp);
	return str;
}
