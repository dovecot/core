#ifndef DB_LUA_H
#define DB_LUA_H 1

#include "dlua-script.h"

#define DB_LUA_CACHE_KEY "%u"

#define AUTH_LUA_PASSWORD_VERIFY "auth_password_verify"

struct dlua_script;

enum auth_lua_script_type {
	AUTH_LUA_SCRIPT_TYPE_PASSDB,
	AUTH_LUA_SCRIPT_TYPE_USERDB,
};

struct auth_lua_script_parameters {
	enum auth_lua_script_type stype;
	struct dlua_script *script;
};

int auth_lua_script_init(const struct auth_lua_script_parameters *params,
		         const char **error_r);

int auth_lua_call_password_verify(struct dlua_script *script,
				  struct auth_request *req, const char *password,
				  const char **error_r);

enum passdb_result
auth_lua_call_passdb_lookup(struct dlua_script *script,
			    struct auth_request *req, const char **scheme_r,
			    const char **password_r, const char **error_r);

enum userdb_result
auth_lua_call_userdb_lookup(struct dlua_script *script,
			    struct auth_request *req, const char **error_r);

struct userdb_iterate_context *
auth_lua_call_userdb_iterate_init(struct dlua_script *script, struct auth_request *req,
				  userdb_iter_callback_t *callback, void *context);
void auth_lua_userdb_iterate_next(struct userdb_iterate_context *ctx);
int auth_lua_userdb_iterate_deinit(struct userdb_iterate_context *ctx);

#endif
