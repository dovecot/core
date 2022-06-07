/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "llist.h"
#include "istream.h"
#include "sha1.h"
#include "str.h"
#include "hex-binary.h"
#include "eacces-error.h"
#include "ioloop.h"
#include "dlua-script-private.h"

#include <fcntl.h>
#include <unistd.h>

/* the registry entry with a pointer to struct dlua_script */
#define LUA_SCRIPT_REGISTRY_KEY	"DLUA_SCRIPT"

#define LUA_SCRIPT_INIT_FN "script_init"
#define LUA_SCRIPT_DEINIT_FN "script_deinit"

struct event_category event_category_lua = {
	.name = "lua",
};

static struct dlua_script *dlua_scripts = NULL;

static int
dlua_script_create_finish(struct dlua_script *script, const char **error_r);

static void *dlua_alloc(void *ctx, void *ptr, size_t osize, size_t nsize)
{
	struct dlua_script *script =
		(struct dlua_script*)ctx;

	if (nsize == 0) {
		p_free(script->pool, ptr);
		return NULL;
	} else {
		return p_realloc(script->pool, ptr, osize, nsize);
	}
}

static const char *dlua_reader(lua_State *L, void *ctx, size_t *size_r)
{
	struct dlua_script *script =
		(struct dlua_script*)ctx;
	const unsigned char *data;
	i_stream_skip(script->in, script->last_read);
	if (i_stream_read_more(script->in, &data, size_r) == -1 &&
	    script->in->stream_errno != 0) {
		luaL_error(L, "read(%s) failed: %s",
			   script->filename,
			   i_stream_get_error(script->in));
		*size_r = 0;
		return NULL;
	}
	script->last_read = *size_r;
	return (const char*)data;
}

struct dlua_script *dlua_script_from_state(lua_State *L)
{
	struct dlua_script *script;

	/* get light pointer from globals */
	lua_pushstring(L, LUA_SCRIPT_REGISTRY_KEY);
	lua_gettable(L, LUA_REGISTRYINDEX);
	script = lua_touserdata(L, -1);
	lua_pop(L, 1);
	i_assert(script != NULL);

	return script;
}

int dlua_pcall(lua_State *L, const char *func_name, int nargs, int nresults,
	       const char **error_r)
{
	/* record the stack position */
	int ret = 0, debugh_idx, top = lua_gettop(L) - nargs;

	lua_getglobal(L, func_name);

	if (lua_isfunction(L, -1)) {
		/* stack on entry
			args
			func <-- top
		*/
		/* move func name before arguments */
		lua_insert(L, -(nargs + 1));
		/* stack now
			func
			args <-- top
		*/
		lua_getglobal(L, "debug");
		lua_getfield(L, -1, "traceback");
		lua_replace(L, -2);
		/* stack now
			func
			args
			traceback <-- top
		*/
		/* move error handler before func name */
		lua_insert(L, -(nargs + 2));
		/* stack now
			traceback
			func
			args <-- top
		*/
		/* record where traceback is so it's easy to get rid of even
		   if LUA_MULTRET is used. */
		debugh_idx = lua_gettop(L) - nargs - 1;
		ret = lua_pcall(L, nargs, nresults, -(nargs + 2));
		if (ret != LUA_OK) {
			*error_r = t_strdup_printf("lua_pcall(%s, %d, %d) failed: %s",
						   func_name, nargs, nresults,
						   lua_tostring(L, -1));
			/* Remove error and debug handler */
			lua_pop(L, 2);
			ret = -1;
		} else {
			/* remove debug handler from known location */
			lua_remove(L, debugh_idx);
			if (nresults == LUA_MULTRET)
				nresults = lua_gettop(L) - top;
			ret = nresults;
		}
	} else {
		/* ensure stack is clean, remove function and arguments */
		lua_pop(L, nargs + 1);
		*error_r = t_strdup_printf("'%s' is not a function",
					   func_name);
		ret = -1;
	}
#ifdef DEBUG
	if ((ret == -1 && lua_gettop(L) != top) ||
	    (ret >= 0 &&
	     lua_gettop(L) != top + ret)) {
		i_debug("LUA STACK UNCLEAN BEGIN for %s", func_name);
		dlua_dump_stack(L);
		i_debug("LUA STACK UNCLEAN END");
	}
#endif
	/* enforce that stack is clean after call */
	if (ret == -1)
		i_assert(lua_gettop(L) == top);
	else
		i_assert(ret >= 0 && lua_gettop(L) == top + ret);
	return ret;
}

static void dlua_call_deinit_function(struct dlua_script *script)
{
	const char *error;
	if (!dlua_script_has_function(script, LUA_SCRIPT_DEINIT_FN))
		return;
	if (dlua_pcall(script->L, LUA_SCRIPT_DEINIT_FN, 0, 0, &error) < 0)
		e_error(script->event, LUA_SCRIPT_DEINIT_FN"() failed: %s",
			error);
}

int dlua_script_init(struct dlua_script *script, const char **error_r)
{
	if (script->init)
		return 0;
	script->init = TRUE;

	if (dlua_script_create_finish(script, error_r) < 0)
		return -1;

	/* lets not fail on missing function... */
	if (!dlua_script_has_function(script, LUA_SCRIPT_INIT_FN))
		return 0;

	int ret = 0;

	if (dlua_pcall(script->L, LUA_SCRIPT_INIT_FN, 0, 1, error_r) < 0)
		return -1;

	if (lua_isinteger(script->L, -1)) {
		ret = lua_tointeger(script->L, -1);
		if (ret != 0) {
			*error_r = "Script init failed";
			ret = -1;
		}
	} else {
		*error_r = LUA_SCRIPT_INIT_FN"() returned non-number";
		ret = -1;
	}

	lua_pop(script->L, 1);

	i_assert(lua_gettop(script->L) == 0);
	return ret;
}

static int dlua_atpanic(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	const char *error = lua_tostring(L, -1);
	i_panic("Lua script '%s': %s", script->filename, error);
}

static struct dlua_script *dlua_create_script(const char *name,
					      struct event *event_parent)
{
	pool_t pool = pool_allocfree_create(t_strdup_printf("lua script %s", name));
	struct dlua_script *script = p_new(pool, struct dlua_script, 1);
	script->pool = pool;
	script->filename = p_strdup(pool, name);
	/* lua API says that lua_newstate will return NULL only if it's out of
	   memory. this cannot really happen with our allocator as it will
	   call i_fatal_status anyways if it runs out of memory */
	script->L = lua_newstate(dlua_alloc, script);
	i_assert(script->L != NULL);
	script->ref = 1;
	lua_atpanic(script->L, dlua_atpanic);
	luaL_openlibs(script->L);
	script->event = event_create(event_parent);
	event_add_str(script->event, "script", script->filename);
	event_add_category(script->event, &event_category_lua);

	dlua_init_thread_table(script);

	DLLIST_PREPEND(&dlua_scripts, script);
	return script;
}

static int dlua_run_script(struct dlua_script *script, const char **error_r)
{
	/* put the error handler before script being called */
	lua_getglobal(script->L, "debug");
	lua_getfield(script->L, -1, "traceback");
	lua_replace(script->L, -2);
	lua_insert(script->L, -2);

	/* we don't want anything to be returned here */
	/* stack before lua_pcall
		debug.traceback
		loaded script as function
	*/
	int err = lua_pcall(script->L, 0, 0, 1);
	if (err != LUA_OK) {
		*error_r = t_strdup_printf("lua_pcall(%s) failed: %s",
					   script->filename,
					   lua_tostring(script->L, -1));
		/* pop error and debug handler */
		lua_pop(script->L, 2);
		err = -1;
	} else {
		/* pop debug handler */
		lua_pop(script->L, 1);
	}
	return err;
}

static int
dlua_script_create_finish(struct dlua_script *script, const char **error_r)
{
	/* store pointer as light data to registry before calling the script */
	lua_pushstring(script->L, LUA_SCRIPT_REGISTRY_KEY);
	lua_pushlightuserdata(script->L, script);
	lua_settable(script->L, LUA_REGISTRYINDEX);

	if (dlua_run_script(script, error_r) < 0)
		return -1;
	i_assert(lua_gettop(script->L) == 0);
	return 0;
}

int dlua_script_create_string(const char *str, struct dlua_script **script_r,
			      struct event *event_parent, const char **error_r)
{
	struct dlua_script *script;
	unsigned char scripthash[SHA1_RESULTLEN];
	const char *fn;

	*script_r = NULL;
	sha1_get_digest(str, strlen(str), scripthash);
	fn = binary_to_hex(scripthash, sizeof(scripthash));

	script = dlua_create_script(fn, event_parent);
	if (luaL_loadstring(script->L, str) == LUA_OK) {
		*script_r = script;
		return 0;
	}
	*error_r = t_strdup_printf("lua_load(<string>) failed: %s",
				   lua_tostring(script->L, -1));
	lua_pop(script->L, 1);
	dlua_script_unref(&script);
	return -1;
}

int dlua_script_create_file(const char *file, struct dlua_script **script_r,
			    struct event *event_parent, const char **error_r)
{
	struct dlua_script *script;

	/* lua reports file access errors poorly */
	if (access(file, O_RDONLY) < 0) {
		if (errno == EACCES)
			*error_r = eacces_error_get("access", file);
		else
			*error_r = t_strdup_printf("access(%s) failed: %m",
						   file);
		return -1;
	}

	script = dlua_create_script(file, event_parent);
	if (luaL_loadfile(script->L, file) != LUA_OK) {
		*error_r = t_strdup_printf("lua_load(%s) failed: %s",
					   file, lua_tostring(script->L, -1));
		dlua_script_unref(&script);
		return -1;
	}

	*script_r = script;
	return 0;
}

int dlua_script_create_stream(struct istream *is, struct dlua_script **script_r,
			      struct event *event_parent, const char **error_r)
{
	struct dlua_script *script;
	const char *filename = i_stream_get_name(is);

	i_assert(filename != NULL && *filename != '\0');

	script = dlua_create_script(filename, event_parent);
	script->in = is;
	script->filename = p_strdup(script->pool, filename);
	if (lua_load(script->L, dlua_reader, script, filename, 0) != LUA_OK) {
		*error_r = t_strdup_printf("lua_load(%s) failed: %s",
					   filename, lua_tostring(script->L, -1));
		dlua_script_unref(&script);
		return -1;
	}

	*script_r = script;
	return 0;
}

static void dlua_script_destroy(struct dlua_script *script)
{
	dlua_call_deinit_function(script);

	/* close all threads */
	dlua_free_thread_table(script);

	/* close base lua */
	lua_close(script->L);

	/* remove from list */
	DLLIST_REMOVE(&dlua_scripts, script);

	event_unref(&script->event);
	/* then just release memory */
	pool_unref(&script->pool);
}

void dlua_script_ref(struct dlua_script *script)
{
	i_assert(script->ref > 0);
	script->ref++;
}

void dlua_script_unref(struct dlua_script **_script)
{
	struct dlua_script *script = *_script;
	*_script = NULL;

	if (script == NULL) return;

	i_assert(script->ref > 0);
	if (--script->ref > 0)
		return;

	dlua_script_destroy(script);
}

bool dlua_script_has_function(struct dlua_script *script, const char *fn)
{
	i_assert(script != NULL);
	lua_getglobal(script->L, "_G");
	lua_pushstring(script->L, fn);
	lua_rawget(script->L, -2);
	bool ret = lua_isfunction(script->L, -1);
	lua_pop(script->L, 2);
	return ret;
}

void dlua_set_members(lua_State *L, const struct dlua_table_values *values,
		     int idx)
{
	i_assert(L != NULL);
	i_assert(lua_istable(L, idx));
	while(values->name != NULL) {
		switch(values->type) {
		case DLUA_TABLE_VALUE_STRING:
			lua_pushstring(L, values->v.s);
			break;
		case DLUA_TABLE_VALUE_INTEGER:
			lua_pushnumber(L, values->v.i);
			break;
		case DLUA_TABLE_VALUE_DOUBLE:
			lua_pushnumber(L, values->v.d);
			break;
		case DLUA_TABLE_VALUE_BOOLEAN:
			lua_pushboolean(L, values->v.b);
			break;
		case DLUA_TABLE_VALUE_NULL:
			lua_pushnil(L);
			break;
		default:
			i_unreached();
		}
		lua_setfield(L, idx - 1, values->name);
		values++;
	}
}

void dlua_dump_stack(lua_State *L)
{
	/* get everything in stack */
	int top = lua_gettop(L);
	for (int i = 1; i <= top; i++) T_BEGIN {  /* repeat for each level */
		int t = lua_type(L, i);
		string_t *line = t_str_new(32);
		str_printfa(line, "#%d: ", i);
		switch (t) {
		case LUA_TSTRING:  /* strings */
			str_printfa(line, "`%s'", lua_tostring(L, i));
			break;
		case LUA_TBOOLEAN:  /* booleans */
			str_printfa(line, "`%s'", lua_toboolean(L, i) ? "true" : "false");
			break;
		case LUA_TNUMBER:  /* numbers */
			str_printfa(line, "%g", lua_tonumber(L, i));
			break;
		default:  /* other values */
			str_printfa(line, "%s", lua_typename(L, t));
			break;
		}
		i_debug("%s", str_c(line));
	} T_END;
}

/* assorted wrappers */
void dlua_register(struct dlua_script *script, const char *name,
		   lua_CFunction f)
{
	lua_register(script->L, name, f);
}
