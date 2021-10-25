/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "str.h"
#include "dlua-script-private.h"

#include <libgen.h>

#define LUA_SCRIPT_DOVECOT "dovecot"
#define DLUA_EVENT_PASSTHROUGH "struct event_passthrough"
#define DLUA_EVENT "struct event"

static void dlua_event_log(lua_State *L, struct event *event,
			   enum log_type log_type, const char *str);

static void dlua_get_file_line(lua_State *L, int arg, const char **file_r,
			       unsigned int *line_r)
{
	const char *ptr;
	lua_Debug ar;
	lua_getstack(L, arg, &ar);
	lua_getinfo(L, "Sl", &ar);
	/* basename would be better, but basename needs memory
	   allocation, since it might modify the buffer contents,
	   so we use this which is good enough */
	if (ar.source[0] != '@')
		ptr = "<non-file location>";
	else if ((ptr = strrchr(ar.source, '/')) == NULL)
		ptr = ar.source;
	else
		ptr++;
	*file_r = ptr;
	*line_r = ar.currentline;
}

static struct event_passthrough *
dlua_check_event_passthrough(lua_State *L, int arg)
{
	if (!lua_istable(L, arg)) {
		(void)luaL_error(L, "Bad argument #%d, expected %s got %s",
				 arg, DLUA_EVENT,
				 lua_typename(L, lua_type(L, arg)));
	}
	lua_pushliteral(L, "item");
	lua_rawget(L, arg);
	void *bp = (void*)lua_touserdata(L, -1);
	lua_pop(L, 1);
	return (struct event_passthrough*)bp;
}

static void dlua_push_event_passthrough(lua_State *L,
					struct event_passthrough *event)
{
	luaL_checkstack(L, 3, "out of memory");
	lua_createtable(L, 0, 1);
	luaL_setmetatable(L, DLUA_EVENT_PASSTHROUGH);

	lua_pushlightuserdata(L, event);
	lua_setfield(L, -2, "item");
}

static int dlua_event_pt_append_log_prefix(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 2);
	struct event_passthrough *event = dlua_check_event_passthrough(L, 1);
	const char *prefix = luaL_checkstring(L, 2);

	event->append_log_prefix(prefix);

	lua_pushvalue(L, 1);

	return 1;
}

static int dlua_event_pt_replace_log_prefix(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 2);
	struct event_passthrough *event = dlua_check_event_passthrough(L, 1);
	const char *prefix = luaL_checkstring(L, 2);

	event->replace_log_prefix(prefix);

	lua_pushvalue(L, 1);

	return 1;
}

static int dlua_event_pt_set_name(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 2);
	struct event_passthrough *event = dlua_check_event_passthrough(L, 1);
	const char *name = luaL_checkstring(L, 2);

	event->set_name(name);

	lua_pushvalue(L, 1);

	return 1;
}


static int dlua_event_pt_set_always_log_source(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 1);
	struct event_passthrough *event = dlua_check_event_passthrough(L, 1);

	event->set_always_log_source();

	lua_pushvalue(L, 1);

	return 1;
}

static int dlua_event_pt_add_str(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 3);
	struct event_passthrough *event = dlua_check_event_passthrough(L, 1);
	const char *name = luaL_checkstring(L, 2);
	const char *value = luaL_checkstring(L, 3);

	event->add_str(name, value);

	lua_pushvalue(L, 1);

	return 1;
}

static int dlua_event_pt_add_int(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 3);
	struct event_passthrough *event = dlua_check_event_passthrough(L, 1);
	const char *name = luaL_checkstring(L, 2);
	lua_Integer value = luaL_checkinteger(L, 3);

	event->add_int(name, value);

	lua_pushvalue(L, 1);

	return 1;
}

static int dlua_event_pt_add_timeval(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 3);
	struct event_passthrough *event = dlua_check_event_passthrough(L, 1);
	const char *name = luaL_checkstring(L, 2);
	/* this is time in seconds */
	lua_Integer value = luaL_checkinteger(L, 3);
	struct timeval tv = {
		.tv_sec = value,
	};

	event->add_timeval(name, &tv);

	lua_pushvalue(L, 1);

	return 1;
}

static int dlua_event_pt_inc_int(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 3);
	struct event_passthrough *event = dlua_check_event_passthrough(L, 1);
	const char *name = luaL_checkstring(L, 2);
	lua_Integer value = luaL_checkinteger(L, 3);

	event->inc_int(name, value);

	lua_pushvalue(L, 1);

	return 1;
}

static int dlua_event_pt_log_debug(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 2);
	struct event_passthrough *event = dlua_check_event_passthrough(L, 1);
	const char *str = luaL_checkstring(L, 2);

	dlua_event_log(L, event->event(), LOG_TYPE_DEBUG, str);

	lua_pushvalue(L, 1);

	return 1;
}

static int dlua_event_pt_log_info(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 2);
	struct event_passthrough *event = dlua_check_event_passthrough(L, 1);
	const char *str = luaL_checkstring(L, 2);

	dlua_event_log(L, event->event(), LOG_TYPE_INFO, str);

	lua_pushvalue(L, 1);

	return 1;
}

static int dlua_event_pt_log_warning(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 2);
	struct event_passthrough *event = dlua_check_event_passthrough(L, 1);
	const char *str = luaL_checkstring(L, 2);

	dlua_event_log(L, event->event(), LOG_TYPE_WARNING, str);

	lua_pushvalue(L, 1);

	return 1;
}

static int dlua_event_pt_log_error(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 2);
	struct event_passthrough *event = dlua_check_event_passthrough(L, 1);
	const char *str = luaL_checkstring(L, 2);

	dlua_event_log(L, event->event(), LOG_TYPE_ERROR, str);

	lua_pushvalue(L, 1);

	return 1;
}

static const luaL_Reg event_passthrough_methods[] ={
	{ "append_log_prefix", dlua_event_pt_append_log_prefix },
	{ "replace_log_prefix", dlua_event_pt_replace_log_prefix },
	{ "set_always_log_source", dlua_event_pt_set_always_log_source },
	{ "set_name", dlua_event_pt_set_name },
	{ "add_str", dlua_event_pt_add_str },
	{ "add_int", dlua_event_pt_add_int },
	{ "add_timeval", dlua_event_pt_add_timeval },
	{ "inc_int", dlua_event_pt_inc_int },
	{ "log_debug", dlua_event_pt_log_debug },
	{ "log_info", dlua_event_pt_log_info },
	{ "log_warning", dlua_event_pt_log_warning },
	{ "log_error", dlua_event_pt_log_error },
	{ NULL, NULL }
};

static int dlua_event_gc(lua_State *L)
{
	struct event **event = lua_touserdata(L, 1);
	event_unref(event);
	return 0;
}

struct event *dlua_check_event(lua_State *L, int arg)
{
	if (!lua_istable(L, arg)) {
		(void)luaL_error(L, "Bad argument #%d, expected %s got %s",
				 arg, DLUA_EVENT,
				 lua_typename(L, lua_type(L, arg)));
	}
	lua_pushliteral(L, "item");
	lua_rawget(L, arg);
	struct event **bp = (void*)lua_touserdata(L, -1);
	lua_pop(L, 1);
	return *bp;
}

void dlua_push_event(lua_State *L, struct event *event)
{
	luaL_checkstack(L, 3, "out of memory");
	lua_createtable(L, 0, 1);
	luaL_setmetatable(L, DLUA_EVENT);

	/* we need to attach gc to userdata to support older lua*/
	struct event **ptr = lua_newuserdata(L, sizeof(struct event*));
	*ptr = event;
	event_ref(event);
	lua_createtable(L, 0, 1);
	lua_pushcfunction(L, dlua_event_gc);
	lua_setfield(L, -2, "__gc");
	lua_setmetatable(L, -2);
	lua_setfield(L, -2, "item");
}

static int dlua_event_append_log_prefix(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 2);
	struct event *event = dlua_check_event(L, 1);
	const char *prefix = luaL_checkstring(L, 2);

	event_set_append_log_prefix(event, prefix);

	lua_pushvalue(L, 1);

	return 1;
}

static int dlua_event_replace_log_prefix(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 2);
	struct event *event = dlua_check_event(L, 1);
	const char *prefix = luaL_checkstring(L, 2);

	event_replace_log_prefix(event, prefix);

	lua_pushvalue(L, 1);

	return 1;
}

static int dlua_event_set_name(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 2);
	struct event *event = dlua_check_event(L, 1);
	const char *name = luaL_checkstring(L, 2);

	event_set_name(event, name);

	lua_pushvalue(L, 1);

	return 1;
}


static int dlua_event_set_always_log_source(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 1);
	struct event *event = dlua_check_event(L, 1);

	event_set_always_log_source(event);

	lua_pushvalue(L, 1);

	return 1;
}

static int dlua_event_add_str(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 3);
	struct event *event = dlua_check_event(L, 1);
	const char *name = luaL_checkstring(L, 2);
	const char *value = luaL_checkstring(L, 3);

	event_add_str(event, name, value);

	lua_pushvalue(L, 1);

	return 1;
}

static int dlua_event_add_int(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 3);
	struct event *event = dlua_check_event(L, 1);
	const char *name = luaL_checkstring(L, 2);
	lua_Integer value = luaL_checkinteger(L, 3);

	event_add_int(event, name, value);

	lua_pushvalue(L, 1);

	return 1;
}

static int dlua_event_add_timeval(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 3);
	struct event *event = dlua_check_event(L, 1);
	const char *name = luaL_checkstring(L, 2);
	/* this is time in seconds */
	lua_Integer value = luaL_checkinteger(L, 3);
	struct timeval tv = {
		.tv_sec = value,
	};

	event_add_timeval(event, name, &tv);

	lua_pushvalue(L, 1);

	return 1;
}

static int dlua_event_inc_int(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 3);
	struct event *event = dlua_check_event(L, 1);
	const char *name = luaL_checkstring(L, 2);
	lua_Integer value = luaL_checkinteger(L, 3);

	event_inc_int(event, name, value);

	lua_pushvalue(L, 1);

	return 1;
}

static int dlua_event_log_debug(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 2);
	struct event *event = dlua_check_event(L, 1);
	const char *str = luaL_checkstring(L, 2);

	dlua_event_log(L, event, LOG_TYPE_DEBUG, str);

	lua_pushvalue(L, 1);

	return 1;
}

static int dlua_event_log_info(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 2);
	struct event *event = dlua_check_event(L, 1);
	const char *str = luaL_checkstring(L, 2);

	dlua_event_log(L, event, LOG_TYPE_INFO, str);

	lua_pushvalue(L, 1);

	return 1;
}

static int dlua_event_log_warning(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 2);
	struct event *event = dlua_check_event(L, 1);
	const char *str = luaL_checkstring(L, 2);

	dlua_event_log(L, event, LOG_TYPE_WARNING, str);

	lua_pushvalue(L, 1);

	return 1;
}

static int dlua_event_log_error(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 2);
	struct event *event = dlua_check_event(L, 1);
	const char *str = luaL_checkstring(L, 2);

	dlua_event_log(L, event, LOG_TYPE_ERROR, str);

	lua_pushvalue(L, 1);

	return 1;
}

#undef event_create_passthrough
#undef event_create
static int dlua_event_passthrough_event(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 1);
	struct event *event = dlua_check_event(L, 1);
	const char *file;
	unsigned int line;

	dlua_get_file_line(L, 1, &file, &line);
	struct event_passthrough *e =
		event_create_passthrough(event, file, line);
	dlua_push_event_passthrough(L, e);

	return 1;
}

static int dlua_event_new(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	DLUA_REQUIRE_ARGS_IN(L, 0, 1);
	struct event *event, *parent = script->event;
	const char *file;
	unsigned int line;

	if (lua_gettop(L) == 1)
		parent = dlua_check_event(L, 1);
	dlua_get_file_line(L, 1, &file, &line);
	event = event_create(parent, file, line);
	dlua_push_event(L, event);
	event_unref(&event);
	return 1;
}

static const luaL_Reg event_methods[] ={
	{ "append_log_prefix", dlua_event_append_log_prefix },
	{ "replace_log_prefix", dlua_event_replace_log_prefix },
	{ "set_always_log_source", dlua_event_set_always_log_source },
	{ "set_name", dlua_event_set_name },
	{ "add_str", dlua_event_add_str },
	{ "add_int", dlua_event_add_int },
	{ "add_timeval", dlua_event_add_timeval },
	{ "inc_int", dlua_event_inc_int },
	{ "log_debug", dlua_event_log_debug },
	{ "log_info", dlua_event_log_info },
	{ "log_warning", dlua_event_log_warning },
	{ "log_error", dlua_event_log_error },
	{ "passthrough_event", dlua_event_passthrough_event },
	{ NULL, NULL }
};

static void dlua_event_register(struct dlua_script *script){
	i_assert(script != NULL);

	luaL_newmetatable(script->L, DLUA_EVENT_PASSTHROUGH);
	lua_pushvalue(script->L, -1);
	lua_setfield(script->L, -2, "__index");
	luaL_setfuncs(script->L, event_passthrough_methods, 0);
	lua_pop(script->L, 1);

	luaL_newmetatable(script->L, DLUA_EVENT);
	lua_pushvalue(script->L, -1);
	lua_setfield(script->L, -2, "__index");
	luaL_setfuncs(script->L, event_methods, 0);
	lua_pop(script->L, 1);
}

static int dlua_i_debug(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 1);
	const char *msg = luaL_checkstring(L, 1);
	i_debug("%s", msg);
	return 0;
}

static int dlua_i_info(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 1);
	const char *msg = luaL_checkstring(L, 1);
	i_info("%s", msg);
	return 0;
}

static int dlua_i_warning(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 1);
	const char *msg = luaL_checkstring(L, 1);
	i_warning("%s", msg);
	return 0;
}

static int dlua_i_error(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 1);
	const char *msg = luaL_checkstring(L, 1);
	i_error("%s", msg);
	return 0;
}

static int dlua_has_flag(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 2);
	/* we rather deal with unsigned value here */
	lua_Integer value = luaL_checkinteger(L, 1);
	lua_Integer flag = luaL_checkinteger(L, 2);

	lua_pushboolean(L, (value & flag) == flag);
	return 1;
}

static int dlua_set_flag(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 2);
	lua_Integer value = luaL_checkinteger(L, 1);
	lua_Integer flag = luaL_checkinteger(L, 2);

	lua_pushinteger(L, value | flag);
	return 1;
}

static int dlua_clear_flag(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 2);
	lua_Integer value = luaL_checkinteger(L, 1);
	lua_Integer flag = luaL_checkinteger(L, 2);

	lua_pushinteger(L, value & (lua_Integer)~flag);
	return 1;
}

static int dlua_script_strict_index(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 2);
	const char *name = luaL_checkstring(L, 2);
	return luaL_error(L, "attempt to write to read undeclared global variable %s",
			  name);
}

static int dlua_script_strict_newindex(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 3);
	if (lua_type(L, 3) == LUA_TFUNCTION) {
		/* allow defining global functions */
		lua_rawset(L, 1);
	} else {
		const char *name = luaL_checkstring(L, 2);
		return luaL_error(L, "attempt to write to undeclared global variable %s",
				  name);
	}
	return 0;
}

static luaL_Reg env_strict_metamethods[] = {
	{ "__index", dlua_script_strict_index },
	{ "__newindex", dlua_script_strict_newindex },
	{ NULL, NULL }
};

static int dlua_restrict_global_variables(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 1);

	if (lua_toboolean(L, 1)) {
		/* disable defining global variables */
		lua_getglobal(L, "_G");
		lua_newtable(L);
		luaL_setfuncs(L, env_strict_metamethods, 0);
	} else {
		/* revert restrictions */
		lua_getglobal(L, "_G");
		lua_newtable(L);
	}
	lua_setmetatable(L, -2);
	lua_pop(L, 1);
	return 0;
}

static luaL_Reg lua_dovecot_methods[] = {
	{ "i_debug", dlua_i_debug },
	{ "i_info", dlua_i_info },
	{ "i_warning", dlua_i_warning },
	{ "i_error", dlua_i_error },
	{ "event", dlua_event_new },
	{ "has_flag", dlua_has_flag },
	{ "set_flag", dlua_set_flag },
	{ "clear_flag", dlua_clear_flag },
	{ "restrict_global_variables", dlua_restrict_global_variables },
	{ NULL, NULL }
};

void dlua_get_dovecot(lua_State *L)
{
	lua_getglobal(L, LUA_SCRIPT_DOVECOT);
}

void dlua_dovecot_register(struct dlua_script *script)
{
	i_assert(script != NULL);

	dlua_event_register(script);

	/* Create table for holding values */
	lua_newtable(script->L);

	/* push new metatable to stack */
	luaL_newmetatable(script->L, LUA_SCRIPT_DOVECOT);
	/* this will register functions to the metatable itself */
	luaL_setfuncs(script->L, lua_dovecot_methods, 0);
	/* point __index to self */
	lua_pushvalue(script->L, -1);
	lua_setfield(script->L, -1, "__index");
	/* set table's metatable, pops stack */
	lua_setmetatable(script->L, -2);

	/* register table as global */
	lua_setglobal(script->L, LUA_SCRIPT_DOVECOT);

	/* register http methods */
	dlua_dovecot_http_register(script);
}

#undef event_want_level
static void dlua_event_log(lua_State *L, struct event *event,
			   enum log_type log_type, const char *str)
{
	struct event_log_params parms;
	i_zero(&parms);
	parms.log_type = log_type;
	dlua_get_file_line(L, 1, &parms.source_filename, &parms.source_linenum);
	if (log_type != LOG_TYPE_DEBUG ||
	    event_want_level(event, LOG_TYPE_DEBUG, parms.source_filename,
			     parms.source_linenum)) {
		event_log(event, &parms, "%s", str);
	} else {
		event_send_abort(event);
	}
}
