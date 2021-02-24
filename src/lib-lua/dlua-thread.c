/* Copyright (c) 2021 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "dlua-script-private.h"

/*
 * dlua support for threads & thread local storage (TLS)
 *
 * The following code keeps a table in (global) registry.  This table is
 * indexed by the thread objects, each mapping to another table used to hold
 * thread local storage.  That is:
 *
 *   registry[thread] = {}  -- threads table
 *   registry[thread]["foo"] = ... -- TLS value for "foo"
 *
 * This serves two purposes:
 *
 *  (1) It provides TLS.
 *  (2) It acts as a reference to the thread object, preventing it from
 *      being garbage collected.
 *
 * The table is allocated during struct dlua_script's creation and is freed
 * during the scripts destruction.  Any lua threads created using
 * dlua_script_new_thread() will automatically get added to this table.
 */

/* the registry entry with a table with all the lua threads */
#define LUA_THREAD_REGISTRY_KEY "DLUA_THREADS"

static void warn_about_tls_leaks(struct dlua_script *script, lua_State *L);
static void get_tls_table(lua_State *L);

void dlua_init_thread_table(struct dlua_script *script)
{
	lua_newtable(script->L);
	lua_setfield(script->L, LUA_REGISTRYINDEX, LUA_THREAD_REGISTRY_KEY);

	/*
	 * Note that we are *not* adding the main lua state since it is not
	 * a thread.  This implies that it will not have any TLS.
	 */
}

static void warn_about_leaked_threads(struct dlua_script *script)
{
	lua_State *L = script->L;

	lua_getfield(L, LUA_REGISTRYINDEX, LUA_THREAD_REGISTRY_KEY);

	i_assert(lua_type(L, -1) == LUA_TTABLE);

	lua_pushnil(L);
	while (lua_next(L, -2) != 0) {
		/* stack: table, thread, per-thread table */

		/* check the key */
		if (lua_type(L, -2) != LUA_TTHREAD) {
			e_error(script->event, "Unexpected %s key in thread table",
				lua_typename(L, lua_type(L, -2)));
		} else {
			e_error(script->event, "Lua thread %p leaked", lua_tothread(L, -2));
		}

		/* check the value */
		if (lua_type(L, -1) != LUA_TTABLE) {
			e_error(script->event, "Unexpected %s value in thread table",
				lua_typename(L, lua_type(L, -1)));
		} else {
			warn_about_tls_leaks(script, L);
		}

		/* pop the value for lua_next() */
		lua_pop(L, 1);
	}

	lua_pop(L, 1);
}

void dlua_free_thread_table(struct dlua_script *script)
{
	/* all threads should have been closed by now */
	warn_about_leaked_threads(script);

	/* set the thread table to nil - letting GC clean everything up */
	lua_pushnil(script->L);
	lua_setfield(script->L, LUA_REGISTRYINDEX, LUA_THREAD_REGISTRY_KEY);
}

lua_State *dlua_script_new_thread(struct dlua_script *script)
{
	lua_State *thread;

	/* get the threads table */
	lua_getfield(script->L, LUA_REGISTRYINDEX, LUA_THREAD_REGISTRY_KEY);

	/* allocate a new thread */
	thread = lua_newthread(script->L);
	i_assert(thread != NULL);

	/* allocate new TLS table */
	lua_newtable(script->L);

	/* stack: threads-table, thread, TLS-table (top) */

	/* threads-table[thread] = TLS-table */
	lua_settable(script->L, -3);

	return thread;
}

static void log_tls_leak(struct dlua_script *script, lua_State *L, bool full)
{
	const char *name = NULL;

	/* stack: TLS key, TLS value (top) */

	if (full) {
		lua_getmetatable(L, -1);

		if (dlua_table_get_string_by_str(L, -1, "__name", &name) < 0)
			name = NULL;

		lua_pop(L, 1); /* pop the metatable */
	}

	e_error(script->event, "Lua TLS data in %p thread leaked: key '%s', "
		"value %s %p (%s)", L, lua_tostring(L, -2),
		full ? "userdata" : "lightuserdata",
		lua_touserdata(L, -1), (name != NULL) ? name : "<no name>");
}

static void warn_about_tls_leaks(struct dlua_script *script, lua_State *L)
{
	i_assert(lua_type(L, -1) == LUA_TTABLE);

	lua_pushnil(L);
	while (lua_next(L, -2) != 0) {
		/* stack: table, key, value (top) */

		switch (lua_type(L, -1)) {
		case LUA_TNIL:
		case LUA_TNUMBER:
		case LUA_TBOOLEAN:
		case LUA_TSTRING:
		case LUA_TFUNCTION:
		case LUA_TTHREAD:
			/* these are trivially freed by the Lua GC */
			break;
		case LUA_TTABLE:
			/* recurse into the table */
			warn_about_tls_leaks(script, L);
			break;
		case LUA_TUSERDATA:
			log_tls_leak(script, L, TRUE);
			break;
		case LUA_TLIGHTUSERDATA:
			log_tls_leak(script, L, FALSE);
			break;
		}

		/* pop the value for lua_next() */
		lua_pop(L, 1);
	}
}

void dlua_script_close_thread(struct dlua_script *script, lua_State **_L)
{
	if (*_L == NULL)
		return;

	/* log any TLS userdata leaks */
	get_tls_table(*_L);
	warn_about_tls_leaks(script, *_L);
	lua_pop(*_L, 1);

	/* get the threads table */
	lua_getfield(*_L, LUA_REGISTRYINDEX, LUA_THREAD_REGISTRY_KEY);

	/* push the thread to destroy */
	i_assert(lua_pushthread(*_L) != 1);

	lua_pushnil(*_L);

	/* stack: threads-table, thread, nil (top) */

	/*
	 * threads-table[thread] = nil
	 *
	 * This assignment (1) frees all TLS for the thread, and (2) removes
	 * the reference to the thread saving it from GC.
	 */
	lua_settable(*_L, -3);

	*_L = NULL;
}

/* get the current thread's TLS table */
static void get_tls_table(lua_State *L)
{
	int ret;

	/* get the threads table */
	ret = dlua_table_get_by_str(L, LUA_REGISTRYINDEX, LUA_TTABLE,
				    LUA_THREAD_REGISTRY_KEY);
	if (ret < 1)
		luaL_error(L, "lua threads table is %s",
			   (ret == 0) ? "missing" : "not a table");

	/* get the TLS-table */
	ret = dlua_table_get_by_thread(L, -1, LUA_TTABLE);
	if (ret < 1)
		luaL_error(L, "lua TLS table for thread %p is not a table", L);

	/* stack: threads-table, TLS-table (top) */

	/* remove threads-table from stack */
	lua_remove(L, -2);
}

void dlua_tls_set_ptr(lua_State *L, const char *name, void *ptr)
{
	get_tls_table(L);
	lua_pushlightuserdata(L, ptr);
	lua_setfield(L, -2, name);
	lua_pop(L, 1);
}

void *dlua_tls_get_ptr(lua_State *L, const char *name)
{
	void *ptr;

	get_tls_table(L);
	lua_getfield(L, -1, name);

	ptr = lua_touserdata(L, -1);

	lua_pop(L, 2);

	return ptr;
}

void dlua_tls_set_int(lua_State *L, const char *name, lua_Integer i)
{
	get_tls_table(L);
	lua_pushinteger(L, i);
	lua_setfield(L, -2, name);
	lua_pop(L, 1);
}

lua_Integer dlua_tls_get_int(lua_State *L, const char *name)
{
	lua_Integer i;

	get_tls_table(L);
	lua_getfield(L, -1, name);

	i = lua_tointeger(L, -1);

	lua_pop(L, 2);

	return i;
}

void dlua_tls_clear(lua_State *L, const char *name)
{
	get_tls_table(L);
	lua_pushnil(L);
	lua_setfield(L, -2, name);
	lua_pop(L, 1);
}
