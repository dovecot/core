#ifndef LUA_SCRIPT_PRIVATE_H
#define LUA_SCRIPT_PRIVATE_H 1

#include "dlua-script.h"
#include "lualib.h"
#include "lauxlib.h"
#include "dlua-compat.h"

/* consistency helpers */
#define lua_isstring(L, n) (lua_isstring(L, n) == 1)
#define lua_isnumber(L, n) (lua_isnumber(L, n) == 1)
#define lua_toboolean(L, n) (lua_toboolean(L, n) == 1)
#define lua_pushboolean(L, b) lua_pushboolean((L), (b) ? 1 : 0)

#define DLUA_TABLE_STRING(n, val) { .name = (n), .type = DLUA_TABLE_VALUE_STRING, .v.s = (val) }
#define DLUA_TABLE_INTEGER(n, val) { .name = (n), .type = DLUA_TABLE_VALUE_INTEGER, .v.i = (val) }
#define DLUA_TABLE_ENUM(n) { .name = #n, .type = DLUA_TABLE_VALUE_INTEGER, .v.i = (n) }
#define DLUA_TABLE_DOUBLE(n, val) { .name = (n), .type = DLUA_TABLE_VALUE_DOUBLE, .v.d = (val) }
#define DLUA_TABLE_BOOLEAN(n, val) { .name = (n), .type = DLUA_TABLE_VALUE_BOOLEAN, .v.b = (val) }
#define DLUA_TABLE_NULL(n, s) { .name = (n), .type = DLUA_TABLE_VALUE_NULL }
#define DLUA_TABLE_END { .name = NULL }

#define DLUA_REQUIRE_ARGS_IN(L, x, y) \
	STMT_START { \
		if (lua_gettop(L) < (x) || lua_gettop(L) > (y)) { \
			return luaL_error((L), "expected %d to %d arguments, got %d", \
					  (x), (y), lua_gettop(L)); \
		} \
	} STMT_END
#define DLUA_REQUIRE_ARGS(L, x) \
	STMT_START { \
		if (lua_gettop(L) != (x)) { \
			return luaL_error((L), "expected %d arguments, got %d", \
					  (x), lua_gettop(L)); \
		} \
	} STMT_END

struct dlua_script {
	struct dlua_script *prev,*next;
	pool_t pool;

	lua_State *L;

	struct event *event;
	const char *filename;
	struct istream *in;
	ssize_t last_read;

	int ref;
	bool init:1;
};

enum dlua_table_value_type {
	DLUA_TABLE_VALUE_STRING = 0,
	DLUA_TABLE_VALUE_INTEGER,
	DLUA_TABLE_VALUE_DOUBLE,
	DLUA_TABLE_VALUE_BOOLEAN,
	DLUA_TABLE_VALUE_NULL
};

struct dlua_table_values {
	const char *name;
	enum dlua_table_value_type type;
	union {
		const char *s;
		ptrdiff_t i;
		double d;
		bool b;
	} v;
};

extern struct event_category event_category_lua;

/* assorted wrappers for lua_foo(), but operating on a struct dlua_script */
void dlua_register(struct dlua_script *script, const char *name,
		   lua_CFunction f);

/* Get dlua_script from lua_State */
struct dlua_script *dlua_script_from_state(lua_State *L);

/* register 'dovecot' global */
void dlua_dovecot_register(struct dlua_script *script);

/* push 'dovecot' global on top of stack */
void dlua_getdovecot(lua_State *L);

/* assign values to table on idx */
void dlua_setmembers(lua_State *L, const struct dlua_table_values *values, int idx);

/* push event to top of stack */
void dlua_push_event(lua_State *L, struct event *event);

/* get event from given stack position */
struct event *dlua_check_event(lua_State *L, int arg);

/* dumps current stack as i_debug lines */
void dlua_dump_stack(lua_State *L);

#endif
