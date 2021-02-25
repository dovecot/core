/*
 * Copyright (c) 2020 Josef 'Jeff' Sipek <jeffpc@josefsipek.net>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef DLUA_WRAPPER_H
#define DLUA_WRAPPER_H

#define DLUA_WRAP_C_DATA(typename, type, putref, extra_fxns_arg)	\
struct lua_wrapper_##typename {						\
	type *ptr;							\
	bool ro;							\
};									\
									\
static inline type *xlua_##typename##_getptr(lua_State *state, int idx,	\
					 bool *ro_r)			\
{									\
	struct lua_wrapper_##typename *wrapper;				\
									\
	wrapper = luaL_checkudata(state, idx, #type);			\
									\
	if (ro_r != NULL)						\
		*ro_r = wrapper->ro;					\
									\
	return wrapper->ptr;						\
}									\
									\
static int xlua_wrapper_##typename##_gc(lua_State *state)		\
{									\
	putref(xlua_##typename##_getptr(state, -1, NULL));		\
									\
	return 0;							\
}									\
									\
static const luaL_Reg provided_##typename##_fxns[] = {			\
	{ "__gc", xlua_wrapper_##typename##_gc },			\
	{ NULL, NULL },							\
};									\
									\
/* push [-0,+1,e] */							\
static void xlua_push##typename(lua_State *state, type *ptr, bool ro)	\
{									\
	struct lua_wrapper_##typename *wrapper;				\
									\
	if (ptr == NULL) {						\
		lua_pushnil(state);					\
		return;							\
	}								\
									\
	wrapper = lua_newuserdata(state, sizeof(struct lua_wrapper_##typename)); \
	i_assert(wrapper != NULL);					\
									\
	wrapper->ptr = (ptr);						\
	wrapper->ro = ro;						\
									\
	/* get the current metatable */					\
	luaL_getmetatable(state, #type);				\
	if (lua_type(state, -1) != LUA_TTABLE) {			\
		/* initialize a new metatable */			\
		luaL_Reg *extra_fxns = (extra_fxns_arg);		\
		lua_CFunction index;					\
									\
		lua_pop(state, 1);					\
		luaL_newmetatable(state, #type);			\
		luaL_setfuncs(state, provided_##typename##_fxns, 0);	\
									\
		index = NULL;						\
		if (extra_fxns != NULL) {				\
			unsigned i;					\
									\
			luaL_setfuncs(state, extra_fxns, 0);		\
									\
			for (i = 0; extra_fxns[i].name != NULL; i++) {	\
				if (strcmp(extra_fxns[i].name,		\
					   "__index") == 0) {		\
					index = extra_fxns[i].func;	\
					break;				\
				}					\
			}						\
		}							\
									\
		if (index == NULL) {					\
			/* set __index == metatable */			\
			lua_pushliteral(state, "__index");		\
			lua_pushvalue(state, -2); /* dup the table */	\
			lua_settable(state, -3);			\
		}							\
	}								\
									\
	/* set the metatable */						\
	lua_setmetatable(state, -2);					\
}

#endif
