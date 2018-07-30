/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "dlua-script-private.h"

#define LUA_SCRIPT_DOVECOT "dovecot"
#define DLUA_EVENT_PASSTHROUGH "struct event_passthrough"
#define DLUA_EVENT "struct event"

static struct event_passthrough *
dlua_check_event_passthrough(struct dlua_script *script, int arg)
{
	if (!lua_istable(script->L, arg)) {
		(void)luaL_error(script->L, "Bad argument #%d, expected %s got %s",
				 arg, DLUA_EVENT,
				 lua_typename(script->L, lua_type(script->L, arg)));
	}
	lua_pushliteral(script->L, "item");
	lua_rawget(script->L, arg);
	void *bp = (void*)lua_touserdata(script->L, -1);
	lua_pop(script->L, 1);
	return (struct event_passthrough*)bp;
}

static void dlua_push_event_passthrough(struct dlua_script *script,
					struct event_passthrough *event)
{
	luaL_checkstack(script->L, 3, "out of memory");
	lua_createtable(script->L, 0, 1);
	luaL_setmetatable(script->L, DLUA_EVENT_PASSTHROUGH);

	lua_pushlightuserdata(script->L, event);
	lua_setfield(script->L, -2, "item");
}

static int dlua_event_pt_append_log_prefix(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	struct event_passthrough *event = dlua_check_event_passthrough(script, 1);
	const char *prefix = luaL_checkstring(script->L, 2);

	event->append_log_prefix(prefix);

	lua_pushvalue(script->L, 1);

	return 1;
}

static int dlua_event_pt_replace_log_prefix(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	struct event_passthrough *event = dlua_check_event_passthrough(script, 1);
	const char *prefix = luaL_checkstring(script->L, 2);

	event->replace_log_prefix(prefix);

	lua_pushvalue(script->L, 1);

	return 1;
}

static int dlua_event_pt_set_name(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	struct event_passthrough *event = dlua_check_event_passthrough(script, 1);
	const char *name = luaL_checkstring(script->L, 2);

	event->set_name(name);

	lua_pushvalue(script->L, 1);

	return 1;
}


static int dlua_event_pt_set_always_log_source(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	struct event_passthrough *event = dlua_check_event_passthrough(script, 1);

	event->set_always_log_source();

	lua_pushvalue(script->L, 1);

	return 1;
}

static int dlua_event_pt_add_str(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	struct event_passthrough *event = dlua_check_event_passthrough(script, 1);
	const char *name = luaL_checkstring(script->L, 2);
	const char *value = luaL_checkstring(script->L, 3);

	event->add_str(name, value);

	lua_pushvalue(script->L, 1);

	return 1;
}

static int dlua_event_pt_add_int(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	struct event_passthrough *event = dlua_check_event_passthrough(script, 1);
	const char *name = luaL_checkstring(script->L, 2);
	lua_Integer value = luaL_checkinteger(script->L, 3);

	event->add_int(name, value);

	lua_pushvalue(script->L, 1);

	return 1;
}

static int dlua_event_pt_add_timeval(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	struct event_passthrough *event = dlua_check_event_passthrough(script, 1);
	const char *name = luaL_checkstring(script->L, 2);
	/* this is time in seconds */
	lua_Integer value = luaL_checkinteger(script->L, 3);
	struct timeval tv = {
		.tv_sec = value,
	};

	event->add_timeval(name, &tv);

	lua_pushvalue(script->L, 1);

	return 1;
}

static int dlua_event_pt_inc_int(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	struct event_passthrough *event = dlua_check_event_passthrough(script, 1);
	const char *name = luaL_checkstring(script->L, 2);
	lua_Integer value = luaL_checkinteger(script->L, 3);

	event->inc_int(name, value);

	lua_pushvalue(script->L, 1);

	return 1;
}

static int dlua_event_pt_log_debug(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	struct event_passthrough *event = dlua_check_event_passthrough(script, 1);
	const char *str = luaL_checkstring(script->L, 2);

	e_debug(event->event(), "%s", str);

	lua_pushvalue(script->L, 1);

	return 1;
}

static int dlua_event_pt_log_info(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	struct event_passthrough *event = dlua_check_event_passthrough(script, 1);
	const char *str = luaL_checkstring(script->L, 2);

	e_info(event->event(), "%s", str);

	lua_pushvalue(script->L, 1);

	return 1;
}

static int dlua_event_pt_log_warning(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	struct event_passthrough *event = dlua_check_event_passthrough(script, 1);
	const char *str = luaL_checkstring(script->L, 2);

	e_warning(event->event(), "%s", str);

	lua_pushvalue(script->L, 1);

	return 1;
}

static int dlua_event_pt_log_error(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	struct event_passthrough *event = dlua_check_event_passthrough(script, 1);
	const char *str = luaL_checkstring(script->L, 2);

	e_error(event->event(), "%s", str);

	lua_pushvalue(script->L, 1);

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

struct event *
dlua_check_event(struct dlua_script *script, int arg)
{
	if (!lua_istable(script->L, arg)) {
		(void)luaL_error(script->L, "Bad argument #%d, expected %s got %s",
				 arg, DLUA_EVENT,
				 lua_typename(script->L, lua_type(script->L, arg)));
	}
	lua_pushliteral(script->L, "item");
	lua_rawget(script->L, arg);
	void *bp = (void*)lua_touserdata(script->L, -1);
	lua_pop(script->L, 1);
	return (struct event*)bp;
}

void dlua_push_event(struct dlua_script *script, struct event *event)
{
	luaL_checkstack(script->L, 3, "out of memory");
	lua_createtable(script->L, 0, 1);
	luaL_setmetatable(script->L, DLUA_EVENT);

	lua_pushlightuserdata(script->L, event);
	lua_setfield(script->L, -2, "item");
}

static int dlua_event_append_log_prefix(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	struct event *event = dlua_check_event(script, 1);
	const char *prefix = luaL_checkstring(script->L, 2);

	event_set_append_log_prefix(event, prefix);

	lua_pushvalue(script->L, 1);

	return 1;
}

static int dlua_event_replace_log_prefix(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	struct event *event = dlua_check_event(script, 1);
	const char *prefix = luaL_checkstring(script->L, 2);

	event_replace_log_prefix(event, prefix);

	lua_pushvalue(script->L, 1);

	return 1;
}

static int dlua_event_set_name(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	struct event *event = dlua_check_event(script, 1);
	const char *name = luaL_checkstring(script->L, 2);

	event_set_name(event, name);

	lua_pushvalue(script->L, 1);

	return 1;
}


static int dlua_event_set_always_log_source(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	struct event *event = dlua_check_event(script, 1);

	event_set_always_log_source(event);

	lua_pushvalue(script->L, 1);

	return 1;
}

static int dlua_event_add_str(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	struct event *event = dlua_check_event(script, 1);
	const char *name = luaL_checkstring(script->L, 2);
	const char *value = luaL_checkstring(script->L, 3);

	event_add_str(event, name, value);

	lua_pushvalue(script->L, 1);

	return 1;
}

static int dlua_event_add_int(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	struct event *event = dlua_check_event(script, 1);
	const char *name = luaL_checkstring(script->L, 2);
	lua_Integer value = luaL_checkinteger(script->L, 3);

	event_add_int(event, name, value);

	lua_pushvalue(script->L, 1);

	return 1;
}

static int dlua_event_add_timeval(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	struct event *event = dlua_check_event(script, 1);
	const char *name = luaL_checkstring(script->L, 2);
	/* this is time in seconds */
	lua_Integer value = luaL_checkinteger(script->L, 3);
	struct timeval tv = {
		.tv_sec = value,
	};

	event_add_timeval(event, name, &tv);

	lua_pushvalue(script->L, 1);

	return 1;
}

static int dlua_event_inc_int(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	struct event *event = dlua_check_event(script, 1);
	const char *name = luaL_checkstring(script->L, 2);
	lua_Integer value = luaL_checkinteger(script->L, 3);

	event_inc_int(event, name, value);

	lua_pushvalue(script->L, 1);

	return 1;
}

static int dlua_event_log_debug(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	struct event *event = dlua_check_event(script, 1);
	const char *str = luaL_checkstring(script->L, 2);

	e_debug(event, "%s", str);

	lua_pushvalue(script->L, 1);

	return 1;
}

static int dlua_event_log_info(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	struct event *event = dlua_check_event(script, 1);
	const char *str = luaL_checkstring(script->L, 2);

	e_info(event, "%s", str);

	lua_pushvalue(script->L, 1);

	return 1;
}

static int dlua_event_log_warning(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	struct event *event = dlua_check_event(script, 1);
	const char *str = luaL_checkstring(script->L, 2);

	e_warning(event, "%s", str);

	lua_pushvalue(script->L, 1);

	return 1;
}

static int dlua_event_log_error(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	struct event *event = dlua_check_event(script, 1);
	const char *str = luaL_checkstring(script->L, 2);

	e_error(event, "%s", str);

	lua_pushvalue(script->L, 1);

	return 1;
}

static int dlua_event_passthrough_event(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	struct event *event = dlua_check_event(script, 1);
	struct event_passthrough *e = event_create_passthrough(event);
	dlua_push_event_passthrough(script, e);

	return 1;
}

static int dlua_event_gc(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	struct event *event = dlua_check_event(script, 1);
	event_unref(&event);
	return 0;
}

static int dlua_event_new(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	lua_Debug ar;
	struct event *event, *parent = script->event;
	if (lua_gettop(script->L) == 1)
		parent = dlua_check_event(script, 1);
        event = event_create(parent);
	lua_getstack(script->L, 1, &ar);
	lua_getinfo(script->L, "Sl", &ar);
	event_set_source(event, ar.source, ar.currentline, TRUE);
	dlua_push_event(script, event);
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
	{ "__gc", dlua_event_gc },
	{ NULL, NULL }
};

static void dlua_event_register(struct dlua_script *script){
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
	struct dlua_script *script = dlua_script_from_state(L);
	const char *msg = luaL_checkstring(script->L, 1);
	i_debug("%s", msg);
	return 0;
}

static int dlua_i_info(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	const char *msg = luaL_checkstring(script->L, 1);
	i_info("%s", msg);
	return 0;
}

static int dlua_i_warning(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	const char *msg = luaL_checkstring(script->L, 1);
	i_warning("%s", msg);
	return 0;
}

static int dlua_i_error(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	const char *msg = luaL_checkstring(script->L, 1);
	i_error("%s", msg);
	return 0;
}

static int dlua_has_flag(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	/* we rather deal with unsigned value here */
	lua_Integer value = luaL_checkinteger(script->L, 1);
	lua_Integer flag = luaL_checkinteger(script->L, 2);

	lua_pushboolean(script->L, (value & flag) == flag);
	return 1;
}

static int dlua_set_flag(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	lua_Integer value = luaL_checkinteger(script->L, 1);
	lua_Integer flag = luaL_checkinteger(script->L, 2);

	lua_pushinteger(script->L, value | flag);
	return 1;
}

static int dlua_clear_flag(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	lua_Integer value = luaL_checkinteger(script->L, 1);
	lua_Integer flag = luaL_checkinteger(script->L, 2);

	lua_pushinteger(script->L, value & (~flag));
	return 1;
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
	{ NULL, NULL }
};

void dlua_getdovecot(struct dlua_script *script)
{
	lua_getglobal(script->L, LUA_SCRIPT_DOVECOT);
}

void dlua_dovecot_register(struct dlua_script *script)
{
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
}
