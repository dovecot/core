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
	const char *const *arguments;
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
		e_error(authdb_event(auth_request),
			"userdb-lua: %s", error);
	callback(result, auth_request);
}

static struct userdb_module *
userdb_lua_preinit(pool_t pool, const char *args)
{
	struct dlua_userdb_module *module;
	const char *cache_key = DB_LUA_CACHE_KEY;
	bool blocking = TRUE;

	module = p_new(pool, struct dlua_userdb_module, 1);
	const char *const *fields = t_strsplit_spaces(args, " ");
	ARRAY_TYPE(const_string) arguments;
	t_array_init(&arguments, 8);

	while(*fields != NULL) {
		const char *key, *value;
		if (!t_split_key_value_eq(*fields, &key, &value)) {
			/* pass */
		} else if (strcmp(key, "file") == 0) {
			 module->file = p_strdup(pool, value);
		} else if (strcmp(key, "blocking") == 0) {
			if (strcmp(value, "yes") == 0) {
				blocking = TRUE;
			} else if (strcmp(value, "no") == 0) {
				blocking = FALSE;
			} else {
				i_fatal("Invalid value %s. "
					"Field blocking must be yes or no",
					value);
			}
                } else if (strcmp(key, "cache_key") == 0) {
                        if (value[0] != '\0')
                                cache_key = value;
                        else /* explicitly disable auth caching for lua */
                                cache_key = NULL;
		}

		/* Catch arguments for lua initialization */
		const char **argument = array_append_space(&arguments);
		*argument = key;
		argument = array_append_space(&arguments);
		*argument = value;
		fields++;
	}

	if (module->file == NULL)
		i_fatal("userdb-lua: Missing mandatory file= parameter");

	module->module.blocking = blocking;
	if (cache_key != NULL) {
		module->module.default_cache_key =
			auth_cache_parse_key(pool, cache_key);
	}
	if (array_count(&arguments) > 0) {
		array_append_zero(&arguments);
		module->arguments = array_front(&arguments);
	}
	return &module->module;
}

static void userdb_lua_init(struct userdb_module *_module)
{
	struct dlua_userdb_module *module =
		(struct dlua_userdb_module *)_module;
	const char *error;

	if (dlua_script_create_file(module->file, &module->script, auth_event, &error) < 0)
		i_fatal("userdb-lua: failed to load '%s': %s", module->file, error);

	const struct auth_lua_script_parameters params = {
		.script = module->script,
		.stype = AUTH_LUA_SCRIPT_TYPE_USERDB,
		.arguments = module->arguments,
	};
	if (auth_lua_script_init(&params, &error) < 0)
		i_fatal("userdb-lua: auth_userdb_init() failed: %s", error);
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
