/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "passdb.h"
#include "auth-cache.h"
#include "settings.h"

#if defined(BUILTIN_LUA) || defined(PLUGIN_BUILD)

#include "db-lua.h"

static enum passdb_result
passdb_lua_verify_password(struct dlua_passdb_module *module,
			   struct auth_request *request, const char *password)
{
	const char *error = NULL;
	enum passdb_result result =
		auth_lua_call_password_verify(module->script, request,
					      password, &error);
	if (result == PASSDB_RESULT_PASSWORD_MISMATCH) {
		auth_request_db_log_password_mismatch(request);
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

	if (auth_request_set_passdb_fields(request, NULL) < 0) {
		callback(PASSDB_RESULT_INTERNAL_FAILURE, NULL, 0, request);
		return;
	}
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

	if (auth_request_set_passdb_fields(request, NULL) < 0) {
		callback(PASSDB_RESULT_INTERNAL_FAILURE, request);
		return;
	}
	if (module->has_password_verify) {
		result = passdb_lua_verify_password(module, request, password);
	} else {
		result = passdb_lua_lookup(request, &lua_scheme, &lua_password);
		if (result == PASSDB_RESULT_OK) {
			if (lua_scheme == NULL)
				lua_scheme = "PLAIN";
			result = auth_request_db_password_verify(
				request, password, lua_password, lua_scheme);
		}
	}
	callback(result, request);
}

static int
passdb_lua_preinit(pool_t pool, struct event *event,
		   struct passdb_module **module_r, const char **error_r)
{
	struct dlua_passdb_module *module;
	module = p_new(pool, struct dlua_passdb_module, 1);

	if (dlua_script_create_auto(event, &module->script, error_r) <= 0)
		i_fatal("passdb-lua: %s", *error_r);

	const struct auth_lua_script_parameters params = {
		.script = module->script,
		.stype = AUTH_LUA_SCRIPT_TYPE_PASSDB,
		.passdb_module = module,
		.pool = pool,
	};
	if (auth_lua_script_init(&params, error_r) < 0)
		i_fatal("passdb-lua: script_init() failed: %s", *error_r);
	if (auth_lua_script_get_default_cache_key(&params, error_r) < 0)
		i_fatal("passdb-lua: auth_passdb_get_cache_key() failed: %s",
			*error_r);

	*module_r = &module->module;
	return 0;
}

static void passdb_lua_init(struct passdb_module *_module)
{
	struct dlua_passdb_module *module =
		(struct dlua_passdb_module *)_module;

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
	.name = "lua",

	.preinit = passdb_lua_preinit,
	.init = passdb_lua_init,
	.deinit = passdb_lua_deinit,

	.verify_plain = passdb_lua_verify_plain,
	.lookup_credentials = passdb_lua_lookup_credentials,
};
#else
struct passdb_module_interface passdb_lua = {
	.name = "lua"
};
#endif
