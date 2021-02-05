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

	lua_State *L; /* base lua context */

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

/*
 * Returns field from a Lua table
 *
 * There are different variants of these that allow for different key types
 * and different value types.  In general, the function name scheme is:
 *
 *	dlua_table_get_<return type>_by_<key type>
 *
 * The _by_{str,int} variants use the supplied field value as the table key.
 *
 * The _by_thread variants use the current thread's thread object as the
 * table key.
 *
 * Returns:
 *   -1 = incompatible value type
 *    0 = nil or not found
 *    1 = value found
 */
int dlua_table_get_luainteger_by_str(lua_State *L, int idx, const char *field, lua_Integer *value_r);
int dlua_table_get_int_by_str(lua_State *L, int idx, const char *field, int *value_r);
int dlua_table_get_intmax_by_str(lua_State *L, int idx, const char *field, intmax_t *value_r);
int dlua_table_get_uint_by_str(lua_State *L, int idx, const char *field, unsigned int *value_r);
int dlua_table_get_uintmax_by_str(lua_State *L, int idx, const char *field, uintmax_t *value_r);
int dlua_table_get_number_by_str(lua_State *L, int idx, const char *field, lua_Number *value_r);
int dlua_table_get_bool_by_str(lua_State *L, int idx, const char *field, bool *value_r);
int dlua_table_get_string_by_str(lua_State *L, int idx, const char *field, const char **value_r);
int dlua_table_get_data_by_str(lua_State *L, int idx, const char *field, const unsigned char **value_r, size_t *len_r);

int dlua_table_get_luainteger_by_int(lua_State *L, int idx, lua_Integer field, lua_Integer *value_r);
int dlua_table_get_int_by_int(lua_State *L, int idx, lua_Integer field, int *value_r);
int dlua_table_get_intmax_by_int(lua_State *L, int idx, lua_Integer field, intmax_t *value_r);
int dlua_table_get_uint_by_int(lua_State *L, int idx, lua_Integer field, unsigned int *value_r);
int dlua_table_get_uintmax_by_int(lua_State *L, int idx, lua_Integer field, uintmax_t *value_r);
int dlua_table_get_number_by_int(lua_State *L, int idx, lua_Integer field, lua_Number *value_r);
int dlua_table_get_bool_by_int(lua_State *L, int idx, lua_Integer field, bool *value_r);
int dlua_table_get_string_by_int(lua_State *L, int idx, lua_Integer field, const char **value_r);
int dlua_table_get_data_by_int(lua_State *L, int idx, lua_Integer field, const unsigned char **value_r, size_t *len_r);

int dlua_table_get_luainteger_by_thread(lua_State *L, int idx, lua_Integer *value_r);
int dlua_table_get_int_by_thread(lua_State *L, int idx, int *value_r);
int dlua_table_get_intmax_by_thread(lua_State *L, int idx, intmax_t *value_r);
int dlua_table_get_uint_by_thread(lua_State *L, int idx, unsigned int *value_r);
int dlua_table_get_uintmax_by_thread(lua_State *L, int idx, uintmax_t *value_r);
int dlua_table_get_number_by_thread(lua_State *L, int idx, lua_Number *value_r);
int dlua_table_get_bool_by_thread(lua_State *L, int idx, bool *value_r);
int dlua_table_get_string_by_thread(lua_State *L, int idx, const char **value_r);
int dlua_table_get_data_by_thread(lua_State *L, int idx, const unsigned char **value_r, size_t *len_r);

/*
 * Pushes onto the stack the value t[k], where t is the value at the given
 * index and k is field argument.  Unlike lua_gettable(), this function
 * checks the type of the retrieved value against the passed in type.
 * [-1,+0..1,e]
 *
 * There are different variants of these that allow for different key types.
 * In general, the function name scheme is:
 *
 *	dlua_table_get_by_<key type>
 *
 * The _by_{str,int} variants use the supplied field value as the table key.
 *
 * The _by_thread variants use the current thread's thread object as the
 * table key.
 *
 * Returns:
 *   -1 = incompatible value type (nothing is pushed)
 *    0 = nil or not found (nothing is pushed)
 *    1 = value found (retrieved value is pushed to the top of the stack)
 */
int dlua_table_get_by_str(lua_State *L, int idx, int type, const char *field);
int dlua_table_get_by_int(lua_State *L, int idx, int type, lua_Integer field);
int dlua_table_get_by_thread(lua_State *L, int idx, int type);

/* dumps current stack as i_debug lines */
void dlua_dump_stack(lua_State *L);

/* Create new thread and keep track of it. */
lua_State *dlua_script_new_thread(struct dlua_script *script);

/* Close thread. */
void dlua_script_close_thread(struct dlua_script *script, lua_State **_L);

/* initialize/free script's thread table */
void dlua_init_thread_table(struct dlua_script *script);
void dlua_free_thread_table(struct dlua_script *script);

#endif
