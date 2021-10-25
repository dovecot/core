#ifndef LUA_SCRIPT_PRIVATE_H
#define LUA_SCRIPT_PRIVATE_H 1

#include "dlua-script.h"
#include "lualib.h"
#include "lauxlib.h"
#include "dlua-compat.h"

/* consistency helpers */
#define lua_isstring(L, n) (lua_isstring((L), (n)) == 1)
#define lua_isnumber(L, n) (lua_isnumber((L), (n)) == 1)
#define lua_toboolean(L, n) (lua_toboolean((L), (n)) == 1)
#define lua_pushboolean(L, b) lua_pushboolean((L), (b) ? 1 : 0)
#define lua_isinteger(L, n) (lua_isinteger((L), (n)) == 1)

#define DLUA_TABLE_STRING(n, val) { .name = (n),\
				    .type = DLUA_TABLE_VALUE_STRING, .v.s = (val) }
#define DLUA_TABLE_INTEGER(n, val) { .name = (n), \
				    .type = DLUA_TABLE_VALUE_INTEGER, .v.i = (val) }
#define DLUA_TABLE_ENUM(n) { .name = #n, \
			     .type = DLUA_TABLE_VALUE_INTEGER, .v.i = (n) }
#define DLUA_TABLE_DOUBLE(n, val) { .name = (n), \
				    .type = DLUA_TABLE_VALUE_DOUBLE, .v.d = (val) }
#define DLUA_TABLE_BOOLEAN(n, val) { .name = (n), \
				     .type = DLUA_TABLE_VALUE_BOOLEAN, .v.b = (val) }
#define DLUA_TABLE_NULL(n, s) { .name = (n), \
			        .type = DLUA_TABLE_VALUE_NULL }
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

typedef void dlua_pcall_yieldable_callback_t(lua_State *L, void *context, int status);

extern struct event_category event_category_lua;

/* assorted wrappers for lua_foo(), but operating on a struct dlua_script */
void dlua_register(struct dlua_script *script, const char *name,
		   lua_CFunction f);

/* Get dlua_script from lua_State */
struct dlua_script *dlua_script_from_state(lua_State *L);

/* register 'dovecot' global */
void dlua_dovecot_register(struct dlua_script *script);

/* push 'dovecot' global on top of stack */
void dlua_get_dovecot(lua_State *L);

/* register 'http' methods to 'dovecot' */
void dlua_dovecot_http_register(struct dlua_script *script);

/* assign values to table on idx */
void dlua_set_members(lua_State *L, const struct dlua_table_values *values, int idx);

/* push event to top of stack */
void dlua_push_event(lua_State *L, struct event *event);

/* get event from given stack position */
struct event *dlua_check_event(lua_State *L, int arg);

/* improved lua_pushfstring, can handle full C format support */
const char *dlua_push_vfstring(lua_State *L, const char *fmt, va_list argp) ATTR_FORMAT(2, 0);
const char *dlua_push_fstring(lua_State *L, const char *fmt, ...) ATTR_FORMAT(2, 3);

/* improved luaL_error, can handle full C format support */
int dluaL_error(lua_State *L, const char *fmt, ...) ATTR_FORMAT(2, 3);
#define luaL_error(...) dluaL_error(__VA_ARGS__)

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

/* call a function in a script.

  **NOTE**: This function works differently than lua_pcall:

    return value:
     -1 = error
     0+ = number of result(s)

*/
int dlua_pcall(lua_State *L, const char *func_name, int nargs, int nresults,
	       const char **error_r);

/* dumps current stack as i_debug lines */
void dlua_dump_stack(lua_State *L);

/* Create new thread and keep track of it. */
lua_State *dlua_script_new_thread(struct dlua_script *script);

/* Close thread. */
void dlua_script_close_thread(struct dlua_script *script, lua_State **_L);

#ifdef DLUA_WITH_YIELDS
/*
 * Call a function with nargs in a way that supports yielding.
 *
 * When the specified function returns, the callback will be called with the
 * supplied context pointer and a status integer indicating whether an error
 * occurred (-1) or whether execution completed successfully (0+).  In the
 * case of a successful completion, the status will indicate the number of
 * results returned by the function.  On failure, the top of the stack
 * contains the error object.
 *
 * Returns:
 *  -1 = if function name refers to a non-function type
 *   0 = function called, callback will be called in the future
 */
int dlua_pcall_yieldable(lua_State *L, const char *func_name, int nargs,
			 dlua_pcall_yieldable_callback_t *callback,
			 void *context, const char **error_r);
#define dlua_pcall_yieldable(L, func_name, nargs, callback, context, error_r) \
	dlua_pcall_yieldable(L, TRUE ? func_name : \
		CALLBACK_TYPECHECK(callback, void (*)(lua_State *, typeof(context), int)), \
		nargs, (dlua_pcall_yieldable_callback_t *)callback, context, error_r)
/*
 * Resume yielded function execution.
 *
 * The nargs argument indicates how many items from the top of the stack
 * should be "returned" by the yield.
 *
 * This function is to be called from other API callbacks to resume
 * execution of the Lua script.  For example, if a Lua script invokes a
 * function to perform I/O, the function would start the async I/O and yield
 * from the script.  Eventually, the I/O completion callback executes, which
 * would call dlua_pcall_yieldable_resume() to continue executing the Lua
 * script with the supplied arguments.
 *
 * Note: The actual execution doesn't resume immediately.  Rather, it is
 * scheduled to start in the near future via a timeout.
 */
void dlua_pcall_yieldable_resume(lua_State *L, int nargs);
#endif

/* initialize/free script's thread table */
void dlua_init_thread_table(struct dlua_script *script);
void dlua_free_thread_table(struct dlua_script *script);

/* thread local storage (TLS) getters & setters */
void dlua_tls_set_ptr(lua_State *L, const char *name, void *ptr);
void *dlua_tls_get_ptr(lua_State *L, const char *name);
void dlua_tls_set_int(lua_State *L, const char *name, lua_Integer i);
lua_Integer dlua_tls_get_int(lua_State *L, const char *name);

/* free a thread local storage (TLS) value */
void dlua_tls_clear(lua_State *L, const char *name);

#endif
