/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "passdb.h"
#include "auth-cache.h"

#if defined(BUILTIN_LUA) || defined(PLUGIN_BUILD)

#include "db-lua.h"

struct dlua_passdb_module {
	struct passdb_module module;
	struct dlua_script *script;
	const char *file;
	const char *const *arguments;
	bool has_password_verify;
};

static enum passdb_result
passdb_lua_verify_password(struct dlua_passdb_module *module,
			   struct auth_request *request, const char *password)
{
	const char *error = NULL;
	enum passdb_result result =
		auth_lua_call_password_verify(module->script, request,
					      password, &error);
	if (result == PASSDB_RESULT_PASSWORD_MISMATCH) {
		auth_request_log_password_mismatch(request, AUTH_SUBSYS_DB);
	} else if (result == PASSDB_RESULT_INTERNAL_FAILURE && error != NULL) {
		e_error(authdb_event(request), "passdb-lua: %s",
			error);
	}
	return result;
}

static enum passdb_result
passdb_lua_lookup(struct auth_request *request,
		  const char **scheme_r, const char **password_r)
{
	const char *error = NULL;
	enum passdb_result result;
	struct dlua_passdb_module *module =
		(struct dlua_passdb_module *)request->passdb->passdb;

	*scheme_r = *password_r = NULL;

	result = auth_lua_call_passdb_lookup(module->script, request, scheme_r,
					     password_r, &error);

	if (result == PASSDB_RESULT_INTERNAL_FAILURE && error != NULL) {
		e_error(authdb_event(request), "db-lua: %s", error);
	} else if (result != PASSDB_RESULT_OK) {
		/* skip next bit */
	} else if (!auth_fields_exists(request->fields.extra_fields, "nopassword")) {
		if (*password_r == NULL || **password_r == '\0') {
			result = auth_request_password_missing(request);
		} else {
			if (*scheme_r == NULL)
				*scheme_r = request->passdb->passdb->default_pass_scheme;
			auth_request_set_field(request, "password",
					       *password_r, *scheme_r);
		}
	} else if (*password_r != NULL && **password_r != '\0') {
		e_info(authdb_event(request),
		       "nopassword given and password is not empty");
		result = PASSDB_RESULT_PASSWORD_MISMATCH;
	}
	return result;
}

static void
passdb_lua_lookup_credentials(struct auth_request *request,
			      lookup_credentials_callback_t *callback)
{
	const char *lua_password, *lua_scheme;
	enum passdb_result result =
		passdb_lua_lookup(request, &lua_scheme, &lua_password);

	passdb_handle_credentials(result, lua_password, lua_scheme, callback, request);
}

static void
passdb_lua_verify_plain(struct auth_request *request, const char *password,
			verify_plain_callback_t *callback)
{
	struct dlua_passdb_module *module =
		(struct dlua_passdb_module *)request->passdb->passdb;
	const char *lua_password, *lua_scheme;
	enum passdb_result result;

	if (module->has_password_verify) {
		result = passdb_lua_verify_password(module, request, password);
	} else {
		result = passdb_lua_lookup(request, &lua_scheme, &lua_password);
		if (result == PASSDB_RESULT_OK) {
			if (lua_scheme == NULL)
				lua_scheme = "PLAIN";
			result = auth_request_password_verify(request, password,
							      lua_password,
							      lua_scheme,
							      AUTH_SUBSYS_DB);
		}
	}
	callback(result, request);
}

static struct passdb_module *
passdb_lua_preinit(pool_t pool, const char *args)
{
	const char *cache_key = DB_LUA_CACHE_KEY;
	const char *scheme = "PLAIN";
	struct dlua_passdb_module *module;
	bool blocking = TRUE;

	module = p_new(pool, struct dlua_passdb_module, 1);
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
		} else if (strcmp(key, "scheme") == 0) {
			scheme = p_strdup(pool, value);
		}

		/* Catch arguments for lua initialization */
		const char **argument = array_append_space(&arguments);
		*argument = p_strdup(pool, key);
		argument = array_append_space(&arguments);
		*argument = p_strdup(pool, value);
		fields++;
	}

	if (module->file == NULL)
		i_fatal("passdb-lua: Missing mandatory file= parameter");

	module->module.blocking = blocking;
	module->module.default_cache_key =
		auth_cache_parse_key(pool, cache_key);
	module->module.default_pass_scheme = scheme;
	if (array_count(&arguments) > 0) {
		array_append_zero(&arguments);
		module->arguments = array_front(&arguments);
	}
	return &module->module;
}

static void passdb_lua_init(struct passdb_module *_module)
{
	struct dlua_passdb_module *module =
		(struct dlua_passdb_module *)_module;
	const char *error;

	if (dlua_script_create_file(module->file, &module->script, auth_event, &error) < 0)
		i_fatal("passdb-lua: failed to load '%s': %s", module->file, error);

	const struct auth_lua_script_parameters params = {
		.script = module->script,
		.stype = AUTH_LUA_SCRIPT_TYPE_PASSDB,
		.arguments = module->arguments,
	};
	if (auth_lua_script_init(&params, &error) < 0)
		i_fatal("passdb-lua: auth_passdb_init() failed: %s", error);

	module->has_password_verify =
		dlua_script_has_function(module->script, AUTH_LUA_PASSWORD_VERIFY);
}

static void passdb_lua_deinit(struct passdb_module *_module)
{
	struct dlua_passdb_module *module =
		(struct dlua_passdb_module *)_module;
	dlua_script_unref(&module->script);
}

#ifndef PLUGIN_BUILD
struct passdb_module_interface passdb_lua =
#else
struct passdb_module_interface passdb_lua_plugin =
#endif
{
	"lua",

	passdb_lua_preinit,
	passdb_lua_init,
	passdb_lua_deinit,

	passdb_lua_verify_plain,
	passdb_lua_lookup_credentials,
	NULL
};
#else
struct passdb_module_interface passdb_lua = {
	.name = "lua"
};
#endif
