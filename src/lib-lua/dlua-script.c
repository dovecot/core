/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "llist.h"
#include "istream.h"
#include "sha1.h"
#include "str.h"
#include "hex-binary.h"
#include "eacces-error.h"
#include "dlua-script-private.h"

#include <fcntl.h>
#include <unistd.h>

#define LUA_SCRIPT_INIT_FN "script_init"
#define LUA_SCRIPT_DEINIT_FN "script_deinit"

struct event_category event_category_lua = {
	.name = "lua",
};

static struct dlua_script *dlua_scripts = NULL;

static const char *dlua_errstr(int err)
{
	switch(err) {
#ifdef LUA_OK
	case LUA_OK:
		return "ok";
#endif
	case LUA_YIELD:
		return "yield";
	case LUA_ERRRUN:
		return "runtime error";
	case LUA_ERRSYNTAX:
		return "syntax error";
	case LUA_ERRMEM:
		return "out of memory";
#ifdef LUA_ERRGCMM
	case LUA_ERRGCMM:
		return "gc management error";
#endif
	case LUA_ERRERR:
		return "error while handling error";
#ifdef LUA_ERRFILE
	case LUA_ERRFILE:
		return "error loading file";
#endif
	default:
		return "unknown error";
	}
}

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
		luaL_error(L, t_strdup_printf("read(%s) failed: %s",
					      script->filename,
					      i_stream_get_error(script->in)));
		*size_r = 0;
		return NULL;
	}
	script->last_read = *size_r;
	return (const char*)data;
}

struct dlua_script *dlua_script_from_state(lua_State *L)
{
	struct dlua_script *script;
	for(script = dlua_scripts; script != NULL; script = script->next)
		if (script->L == L)
			return script;
	i_unreached();
}

int dlua_script_init(struct dlua_script *script, const char **error_r)
{
	int ret = 0;

	if (script->init)
		return 0;
	script->init = TRUE;

	/* see if there is a symbol for init */
	lua_getglobal(script->L, LUA_SCRIPT_INIT_FN);

	if (lua_isfunction(script->L, -1)) {
		ret = lua_pcall(script->L, 0, 1, 0);
		if (ret != 0) {
			*error_r = t_strdup_printf("lua_pcall("LUA_SCRIPT_INIT_FN") failed: %s",
						   lua_tostring(script->L, -1));
			ret = -1;
		} else if (lua_isnumber(script->L, -1)) {
			ret = lua_tointeger(script->L, -1);
			if (ret != 0)
				*error_r = "Script init failed";
		} else {
			*error_r = t_strdup_printf(LUA_SCRIPT_INIT_FN "() returned non-number");
			ret = -1;
		}
	}

	lua_pop(script->L, 1);
	return ret;
}

static int dlua_atpanic(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	const char *error = lua_tostring(script->L, -1);
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
	event_add_category(script->event, &event_category_lua);

	return script;
}

static int dlua_run_script(struct dlua_script *script, const char **error_r)
{
	int err = lua_pcall(script->L, 0, 0, 0);
	if (err != 0) {
		*error_r = t_strdup_printf("lua_pcall(%s) failed: %s",
					   script->filename,
					   lua_tostring(script->L, -1));
		lua_pop(script->L,1);
		return -1;
	}
	return 0;
}

static struct dlua_script *
dlua_script_find_previous_script(const char *filename)
{
	struct dlua_script *script;
	for(script = dlua_scripts; script != NULL; script = script->next)
		if (strcmp(script->filename, filename)==0)
			return script;
	return NULL;
}

static int
dlua_script_create_finish(struct dlua_script *script, struct dlua_script **script_r,
			  const char **error_r)
{
	if (dlua_run_script(script, error_r) < 0) {
		dlua_script_unref(&script);
		return -1;
	}

	event_add_str(script->event, "script", script->filename);
	DLLIST_PREPEND(&dlua_scripts, script);

	*script_r = script;

	return 0;
}

int dlua_script_create_string(const char *str, struct dlua_script **script_r,
			      struct event *event_parent, const char **error_r)
{
	struct dlua_script *script;
	int err;
	unsigned char scripthash[SHA1_RESULTLEN];
	const char *fn;

	*script_r = NULL;
	sha1_get_digest(str, strlen(str), scripthash);
	fn = binary_to_hex(scripthash, sizeof(scripthash));

	if ((script = dlua_script_find_previous_script(fn)) != NULL) {
		dlua_script_ref(script);
		*script_r = script;
		return 0;
	}

	script = dlua_create_script(fn, event_parent);
	if ((err = luaL_loadstring(script->L, str)) != 0) {
		*error_r = t_strdup_printf("lua_load(<string>) failed: %s",
					   dlua_errstr(err));
		dlua_script_unref(&script);
		return -1;
	}

	return dlua_script_create_finish(script, script_r, error_r);
}

int dlua_script_create_file(const char *file, struct dlua_script **script_r,
			    struct event *event_parent, const char **error_r)
{
	struct dlua_script *script;
	int err;

	if ((script = dlua_script_find_previous_script(file)) != NULL) {
		dlua_script_ref(script);
		*script_r = script;
		return 0;
	}

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
	if ((err = luaL_loadfile(script->L, file)) != 0) {
		*error_r = t_strdup_printf("lua_load(%s) failed: %s",
					   file, dlua_errstr(err));
		dlua_script_unref(&script);
		return -1;
	}

	return dlua_script_create_finish(script, script_r, error_r);
}

int dlua_script_create_stream(struct istream *is, struct dlua_script **script_r,
			      struct event *event_parent, const char **error_r)
{
	struct dlua_script *script;
	const char *filename = i_stream_get_name(is);
	int err;

	i_assert(filename != NULL && *filename != '\0');

	if ((script = dlua_script_find_previous_script(filename)) != NULL) {
		dlua_script_ref(script);
		*script_r = script;
		return 0;
	}

	script = dlua_create_script(filename, event_parent);
	script->in = is;
	script->filename = p_strdup(script->pool, filename);
	if ((err = lua_load(script->L, dlua_reader, script, filename, 0)) < 0) {
		*error_r = t_strdup_printf("lua_load(%s) failed: %s",
					   filename, dlua_errstr(err));
		dlua_script_unref(&script);
		return -1;
	}

	return dlua_script_create_finish(script, script_r, error_r);
}

static void dlua_script_destroy(struct dlua_script *script)
{
	/* courtesy call */
	int ret;
	/* see if there is a symbol for deinit */
	lua_getglobal(script->L, LUA_SCRIPT_DEINIT_FN);
	if (lua_isfunction(script->L, -1)) {
		ret = lua_pcall(script->L, 0, 0, 0);
		if (ret != 0) {
			i_warning("lua_pcall("LUA_SCRIPT_DEINIT_FN") failed: %s",
				  lua_tostring(script->L, -1));
			lua_pop(script->L, 1);
		}
	} else {
		lua_pop(script->L, 1);
	}
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
	lua_getglobal(script->L, fn);
	bool ret = lua_isfunction(script->L, -1);
	lua_pop(script->L, 1);
	return ret;
}

void dlua_setmembers(struct dlua_script *script,
		     const struct dlua_table_values *values, int idx)
{
	i_assert(script != NULL);
	i_assert(lua_istable(script->L, idx));
	while(values->name != NULL) {
		switch(values->type) {
		case DLUA_TABLE_VALUE_STRING:
			lua_pushstring(script->L, values->v.s);
			break;
		case DLUA_TABLE_VALUE_INTEGER:
			lua_pushnumber(script->L, values->v.i);
			break;
		case DLUA_TABLE_VALUE_DOUBLE:
			lua_pushnumber(script->L, values->v.d);
			break;
		case DLUA_TABLE_VALUE_BOOLEAN:
			lua_pushboolean(script->L, values->v.b);
			break;
		case DLUA_TABLE_VALUE_NULL:
			lua_pushnil(script->L);
			break;
		default:
			i_unreached();
		}
		lua_setfield(script->L, idx-1, values->name);
		values++;
	}
}

void dlua_dump_stack(struct dlua_script *script)
{
	/* get everything in stack */
	int top = lua_gettop(script->L);
	for (int i = 1; i <= top; i++) T_BEGIN {  /* repeat for each level */
		int t = lua_type(script->L, i);
		string_t *line = t_str_new(32);
		str_printfa(line, "#%d: ", i);
		switch (t) {
		case LUA_TSTRING:  /* strings */
			str_printfa(line, "`%s'", lua_tostring(script->L, i));
			break;
		case LUA_TBOOLEAN:  /* booleans */
			str_printfa(line, "`%s'", lua_toboolean(script->L, i) ? "true" : "false");
			break;
		case LUA_TNUMBER:  /* numbers */
			str_printfa(line, "%g", lua_tonumber(script->L, i));
			break;
		default:  /* other values */
			str_printfa(line, "%s", lua_typename(script->L, t));
			break;
		}
		i_debug("%s", str_c(line));
	} T_END;
}
