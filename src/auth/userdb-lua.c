/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "userdb.h"
#include "auth-cache.h"

#if defined(BUILTIN_LUA) || defined(PLUGIN_BUILD)

#include "db-lua.h"

struct dlua_userdb_module {
	struct userdb_module module;
	struct dlua_script *script;
	const char *file;
};

static void userdb_lua_lookup(struct auth_request *auth_request,
			      userdb_callback_t *callback)
{
	struct userdb_module *_module = auth_request->userdb->userdb;
	struct dlua_userdb_module *module =
		(struct dlua_userdb_module *)_module;
	const char *error;
	enum userdb_result result =
		auth_lua_call_userdb_lookup(module->script, auth_request, &error);
	if (result == USERDB_RESULT_INTERNAL_FAILURE)
		auth_request_log_error(auth_request, AUTH_SUBSYS_DB,
				       "userdb-lua: %s", error);
	callback(result, auth_request);
}

static struct userdb_module *
userdb_lua_preinit(pool_t pool, const char *args)
{
	struct dlua_userdb_module *module;
	const char *cache_key = "%u";
	bool blocking = TRUE;

	module = p_new(pool, struct dlua_userdb_module, 1);
	const char *const *fields = t_strsplit_spaces(args, " ");
	while(*fields != NULL) {
		if (str_begins(*fields, "file=")) {
			 module->file = p_strdup(pool, (*fields)+5);
		} else if (str_begins(*fields, "blocking=")) {
			const char *value = (*fields)+9;
			if (strcmp(value, "yes") == 0) {
				blocking = TRUE;
			} else if (strcmp(value, "no") == 0) {
				blocking = FALSE;
			} else {
				i_fatal("Invalid value %s. "
					"Field blocking must be yes or no",
					value);
			}
		} else if (str_begins(*fields, "cache_key=")) {
			if (*((*fields)+10) != '\0')
				cache_key = (*fields)+10;
			else /* explicitly disable auth caching for lua */
				cache_key = NULL;
		} else {
			i_fatal("Unsupported parameter %s", *fields);
		}
		fields++;
	}

	if (module->file == NULL)
		i_fatal("userdb-lua: Missing mandatory file= parameter");

	module->module.blocking = blocking;
	if (cache_key != NULL) {
		module->module.default_cache_key =
			auth_cache_parse_key(pool, cache_key);
	}
	return &module->module;
}

static void userdb_lua_init(struct userdb_module *_module)
{
	struct dlua_userdb_module *module =
		(struct dlua_userdb_module *)_module;
	const char *error;

	if (dlua_script_create_file(module->file, &module->script, auth_event, &error) < 0 ||
	    auth_lua_script_init(module->script, &error) < 0)
		i_fatal("userdb-lua: initialization failed: %s", error);
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
	"lua",

	userdb_lua_preinit,
	userdb_lua_init,
	userdb_lua_deinit,

	userdb_lua_lookup,

	userdb_lua_iterate_init,
	userdb_lua_iterate_next,
	userdb_lua_iterate_deinit
};
#else
struct userdb_module_interface userdb_lua = {
	.name = "lua"
};
#endif
