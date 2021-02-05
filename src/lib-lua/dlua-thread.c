/* Copyright (c) 2021 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "dlua-script-private.h"

/*
 * dlua support for threads
 *
 * The following code keeps a table in (global) registry.  This table is
 * indexed by the thread objects, each mapping to another table.  That is:
 *
 *   registry[thread] = {}  -- threads table
 *
 * This acts as a reference to the thread object, preventing it from being
 * garbage collected.
 *
 * The table is allocated during struct dlua_script's creation and is freed
 * during the scripts destruction.  Any lua threads created using
 * dlua_script_new_thread() will automatically get added to this table.
 */

/* the registry entry with a table with all the lua threads */
#define LUA_THREAD_REGISTRY_KEY "DLUA_THREADS"

void dlua_init_thread_table(struct dlua_script *script)
{
	lua_newtable(script->L);
	lua_setfield(script->L, LUA_REGISTRYINDEX, LUA_THREAD_REGISTRY_KEY);

	/*
	 * Note that we are *not* adding the main lua state since it is not
	 * a thread.
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

	/* allocate new per-thread table */
	lua_newtable(script->L);

	/* stack: threads-table, thread, per-thread-table (top) */

	/* threads-table[thread] = per-thread-table */
	lua_settable(script->L, -3);

	return thread;
}

void dlua_script_close_thread(struct dlua_script *script, lua_State **_L)
{
	if (*_L == NULL)
		return;

	/* get the threads table */
	lua_getfield(*_L, LUA_REGISTRYINDEX, LUA_THREAD_REGISTRY_KEY);

	/* push the thread to destroy */
	i_assert(lua_pushthread(*_L) != 1);

	lua_pushnil(*_L);

	/* stack: threads-table, thread, nil (top) */

	/*
	 * threads-table[thread] = nil
	 *
	 * This assignment removes the reference to the thread saving it
	 * from GC.
	 */
	lua_settable(*_L, -3);

	*_L = NULL;
}
