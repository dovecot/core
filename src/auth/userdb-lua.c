/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "userdb.h"
#include "auth-cache.h"
#include "settings.h"

#if defined(BUILTIN_LUA) || defined(PLUGIN_BUILD)

#include "db-lua.h"

static void userdb_lua_lookup(struct auth_request *auth_request,
			      userdb_callback_t *callback)
{
	struct userdb_module *_module = auth_request->userdb->userdb;
	struct dlua_userdb_module *module =
		(struct dlua_userdb_module *)_module;
	const char *error;

	if (auth_request_set_userdb_fields(auth_request, NULL) < 0) {
		callback(USERDB_RESULT_INTERNAL_FAILURE, auth_request);
		return;
	}
	enum userdb_result result =
		auth_lua_call_userdb_lookup(module->script, auth_request, &error);
	if (result == USERDB_RESULT_INTERNAL_FAILURE)
		e_error(authdb_event(auth_request),
			"userdb-lua: %s", error);
	callback(result, auth_request);
}

static int
userdb_lua_preinit(pool_t pool, struct event *event,
		   struct userdb_module **module_r, const char **error_r)
{
	struct dlua_userdb_module *module;

	module = p_new(pool, struct dlua_userdb_module, 1);

	if (dlua_script_create_auto(event, &module->script, error_r) <= 0)
		i_fatal("userdb-lua: %s", *error_r);

	const struct auth_lua_script_parameters params = {
		.script = module->script,
		.stype = AUTH_LUA_SCRIPT_TYPE_USERDB,
		.userdb_module = module,
		.pool = pool,
	};
	if (auth_lua_script_init(&params, error_r) < 0)
		i_fatal("userdb-lua: script_init() failed: %s", *error_r);
	if (auth_lua_script_get_default_cache_key(&params, error_r) < 0)
		i_fatal("userdb-lua: auth_userdb_get_cache_key() failed: %s",
			*error_r);

	*module_r = &module->module;
	return 0;
}

static void userdb_lua_deinit(struct userdb_module *_module)
{
	struct dlua_userdb_module *module =
		(struct dlua_userdb_module *)_module;
	dlua_script_unref(&module->script);
}

static struct userdb_iterate_context *
userdb_lua_iterate_init(struct auth_request *auth_request,
			userdb_iter_callback_t *callback,
			void *context)
{
	struct userdb_module *_module = auth_request->userdb->userdb;
	struct dlua_userdb_module *module =
		(struct dlua_userdb_module *)_module;
	return auth_lua_call_userdb_iterate_init(module->script, auth_request,
						 callback, context);
}

static void userdb_lua_iterate_next(struct userdb_iterate_context *ctx)
{
	auth_lua_userdb_iterate_next(ctx);
}

static int userdb_lua_iterate_deinit(struct userdb_iterate_context *ctx)
{
	return auth_lua_userdb_iterate_deinit(ctx);
}

#ifndef PLUGIN_BUILD
struct userdb_module_interface userdb_lua =
#else
struct userdb_module_interface userdb_lua_plugin =
#endif
{
	.name = "lua",

	.preinit = userdb_lua_preinit,
	.deinit = userdb_lua_deinit,

	.lookup = userdb_lua_lookup,

	.iterate_init = userdb_lua_iterate_init,
	.iterate_next = userdb_lua_iterate_next,
	.iterate_deinit = userdb_lua_iterate_deinit
};
#else
struct userdb_module_interface userdb_lua = {
	.name = "lua"
};
#endif
