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

/*
 * The following macro generates everything necessary to wrap a C structure
 * and easily push it onto Lua stacks as well as check that a value on the
 * stack is of this type.
 *
 * To generate the necessary API, simply use the macro in your .c file.  The
 * arguments consist of:
 *
 *   <typename> = the name for the structure to use in generated symbols
 *   <type> = the exposed structure's C type
 *   <putref> = the function to remove a reference from the C structure,
 *       called from the automatically generated __gc metamethod
 *   <extra_fxns_arg> = a C array of luaL_Reg structs passed to luaL_setfuncs
 *       to add Lua methods to the type
 *
 * For example, to expose struct timespec with a tostring method, one would
 * use the following in a .c file:
 *
 *   // struct timespec isn't refcounted
 *   static inline void timespec_putref(struct timespec *ts)
 *   {
 *   }
 *
 *   static int timespec_tostring(lua_State *L);
 *
 *   static const luaL_Reg timespec_fxns[] = {
 *           { "__tostring", timespec_tostring },
 *           { NULL, NULL },
 *   };
 *
 *   DLUA_WRAP_C_DATA(timespec, struct timespec, timespec_putref, timespec_fxns)
 *
 *   static int timespec_tostring(lua_State *L)
 *   {
 *           struct timespec *ts;
 *
 *           ts = xlua_timespec_getptr(L, -1, NULL);
 *
 *           lua_pushfstring(L, "%d.%09ld", ts->tv_sec, ts->tv_nsec);
 *
 *           return 1;
 *   }
 *
 *
 * The two functions making up the exposed structure API are:
 *
 *   static void xlua_push<typename>(lua_State *, <type> *, bool);
 *   static inline <type> *xlua_<typename>_getptr(lua_State *, int, bool *);
 *
 * The first pushes the supplied pointer onto the Lua stack, while the
 * second returns the previously pushed C pointer (or generates a Lua error
 * if there is a type mismatch).
 *
 * The push function tracks the passed in bool argument alongside the C
 * pointer itself.  The getptr function fills in the bool pointer (if not
 * NULL) with the pushed bool value.  While this bool isn't used directly by
 * the generated code and therefore it can be used for anything, the
 * intention is to allow the API consumers to mark certain pointers as
 * "read-only" to prevent Lua scripts from attempting to mutate them.  This
 * allows one to push const pointers while "notifying" the methods that
 * mutation of any of the members is undefined behavior.
 *
 * Also note that the functions are static.  That is, they are intended to
 * only be used in the file where they are generated since they are somewhat
 * low-level functions.  If some public form of a push/get function is
 * desired, it is up to the API consumer to write wrappers around these and
 * expose them to the rest of the codebase.
 *
 * Revisiting the struct timespec example above, the generated API would
 * be:
 *
 *   static void xlua_pushtimespec(lua_State *, struct timespec *, bool);
 *   static inline struct timespec *xlua_timespec_getptr(lua_State *, int,
 *                                                       bool *);
 */
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
		const luaL_Reg *extra_fxns = (extra_fxns_arg);		\
		lua_CFunction index;					\
									\
		lua_pop(state, 1);					\
		luaL_newmetatable(state, #type);			\
		luaL_setfuncs(state, provided_##typename##_fxns, 0);	\
									\
		index = NULL;						\
		if (extra_fxns != NULL) {				\
			unsigned int i;					\
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
