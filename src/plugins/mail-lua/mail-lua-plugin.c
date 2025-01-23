/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "module-dir.h"
#include "var-expand-private.h"
#include "mail-lua-plugin.h"
#include "mail-storage-lua.h"
#include "mail-storage-private.h"
#include "mail-storage-hooks.h"
#include "settings.h"
#include "mail-lua-settings.h"
#include "dlua-script-private.h"

#define MAIL_LUA_USER_CREATED_FN "mail_user_created"
#define MAIL_LUA_USER_DEINIT_FN "mail_user_deinit"
#define MAIL_LUA_USER_DEINIT_PRE_FN "mail_user_deinit_pre"
#define MAIL_LUA_USER_CONTEXT(obj) \
	MODULE_CONTEXT(obj, mail_lua_user_module)

static MODULE_CONTEXT_DEFINE_INIT(mail_lua_user_module,
				  &mail_user_module_register);

struct mail_lua_user_context {
	union mail_user_module_context module_ctx;
	struct dlua_script *script;
};

static int mail_lua_call_hook(struct dlua_script *script,
			      struct mail_user *user,
			      const char *hook,
			      const char **error_r)
{
	const char *error;

	if (!dlua_script_has_function(script, hook))
		return 0;

	e_debug(user->event, "mail-lua: Calling %s(user)", hook);

	dlua_push_mail_user(script->L, user);

	if (dlua_pcall(script->L, hook, 1, 2, &error) < 0) {
		*error_r = t_strdup_printf("%s(user) failed: %s", hook, error);
		return -1;
	}

	int ret = lua_tonumber(script->L, -2);
	const char *errmsg = lua_tostring(script->L, -1);

	if (ret < 0) {
		*error_r = t_strdup_printf("%s(user) failed: %s",
					   hook, errmsg);
	}

	lua_pop(script->L, 2);
	(void)lua_gc(script->L, LUA_GCCOLLECT, 0);

	return ret < 0 ? -1 : 1;
}

static void mail_lua_user_deinit_pre(struct mail_user *user)
{
	struct mail_lua_user_context *luser = MAIL_LUA_USER_CONTEXT(user);
	const char *error;

	if (luser == NULL)
		return;

	if (mail_lua_call_hook(luser->script, user, MAIL_LUA_USER_DEINIT_PRE_FN,
			       &error) < 0) {
		e_error(user->event, "mail-lua: %s", error);
	}

	luser->module_ctx.super.deinit_pre(user);
}

static void mail_lua_user_deinit(struct mail_user *user)
{
	struct mail_lua_user_context *luser = MAIL_LUA_USER_CONTEXT(user);
	const char *error;

	if (luser == NULL)
		return;

	luser->module_ctx.super.deinit(user);

	if (mail_lua_call_hook(luser->script, user, MAIL_LUA_USER_DEINIT_FN,
			       &error) < 0) {
		e_error(user->event, "mail-lua: %s", error);
	}

	dlua_script_unref(&luser->script);
}

static void mail_lua_user_created(struct mail_user *user)
{
	struct mail_lua_user_context *luser;
	struct mail_user_vfuncs *v = user->vlast;
	struct dlua_script *script;
	const char *error;
	struct event *event;
	int ret;

	event = event_create(user->event);
	settings_event_add_filter_name(event, MAIL_LUA_FILTER);
	if ((ret = dlua_script_create_auto(event, &script, &error)) < 0) {
		user->error = p_strdup_printf(user->pool,
					      "dlua_script_create_auto() failed: %s",
					      error);
		event_unref(&event);
		return;
	}
	event_unref(&event);
	if (ret == 0)
		return;
	dlua_dovecot_register(script);
	dlua_register_mail_storage(script);

	/* init */
	if (dlua_script_init(script, &error) < 0) {
		user->error = p_strdup_printf(user->pool,
					      "dlua_script_init(%s) failed: %s",
					      script->filename, error);
		dlua_script_unref(&script);
		return;
	}

	/* call postlogin hook */
	if ((ret = mail_lua_call_hook(script, user, MAIL_LUA_USER_CREATED_FN,
				      &error)) <= 0) {
		if (ret < 0)
			user->error = p_strdup(user->pool, error);
		dlua_script_unref(&script);
		return;
	}

	luser = p_new(user->pool, struct mail_lua_user_context, 1);
	luser->module_ctx.super = *v;
	v->deinit_pre = mail_lua_user_deinit_pre;
	v->deinit = mail_lua_user_deinit;
	luser->script = script;
	user->vlast = &luser->module_ctx.super;

	MODULE_CONTEXT_SET(user, mail_lua_user_module, luser);
}

struct mail_lua_script {
	char *file;
	struct dlua_script *script;
};

static ARRAY(struct mail_lua_script) lua_scripts = ARRAY_INIT;

static int
mail_lua_script_cmp(const char *key, const struct mail_lua_script *script)
{
	return strcmp(key, script->file);
}

static void mail_lua_scripts_free(void)
{
	struct mail_lua_script *script;
	if (array_is_empty(&lua_scripts))
		return;
	array_foreach_modifiable(&lua_scripts, script) {
		i_free(script->file);
		dlua_script_unref(&script->script);
	}
	array_free(&lua_scripts);
}

static int mail_lua_script_load(const char *file, struct dlua_script **script_r,
				const char **error_r)
{
	/* check if it's already there */
	if (!array_is_empty(&lua_scripts)) {
		const struct mail_lua_script *lookup =
			array_lsearch(&lua_scripts, file, mail_lua_script_cmp);
		if (lookup != NULL) {
			*script_r = lookup->script;
			return 0;
		}
	}
	struct dlua_script *script;
	if (dlua_script_create_file(file, &script, NULL, error_r) < 0)
		return -1;
	dlua_dovecot_register(script);
	if (dlua_script_init(script, error_r) < 0) {
		dlua_script_unref(&script);
		return -1;
	}
	/* register the script */
	if (!array_is_created(&lua_scripts))
		i_array_init(&lua_scripts, 1);
	struct mail_lua_script *entry = array_append_space(&lua_scripts);
	entry->file = i_strdup(file);
	entry->script = script;
	*script_r = script;
	return 0;
}

bool mail_lua_plugin_get_script(struct mail_user *user,
				struct dlua_script **script_r)
{
	struct mail_lua_user_context *luser = MAIL_LUA_USER_CONTEXT(user);
	if (luser != NULL) {
		*script_r = luser->script;
		return TRUE;
	}
	return FALSE;
}

static int mail_lua_script_call(const char *fn, struct mail_user *user,
				ARRAY_TYPE(const_string) *params,
				struct var_expand_state *state,
				struct dlua_script *script,
				const char **error_r)
{
	const char *value;
	const char *error;
	int npar = 0;

	/* Push user as first parameter */
	if (user != NULL) {
		npar++;
		dlua_push_mail_user(script->L, user);
	}

	/* Any user provided parameters come next */
	array_foreach_elem(params, value) {
		lua_pushstring(script->L, value);
		npar++;
	}

	/* If there is state, push that too */
	if (state->transfer_set) {
		lua_pushlstring(script->L, state->transfer->data,
				state->transfer->used);
		npar++;
	}

	/* Call fn(user, provided params.., state) */
	if (dlua_pcall(script->L, fn, npar, 2, &error) < 0) {
		*error_r = t_strdup_printf("%s(user) failed: %s", fn, error);
		return -1;
	}

	int ret = lua_tonumber(script->L, -2);

	if (ret < 0) {
		var_expand_state_unset_transfer(state);
		const char *errmsg = lua_tostring(script->L, -1);
		*error_r = t_strdup_printf("%s(user) failed: %s",
					   fn, errmsg);
	} else {
		size_t len;
		const void *value = lua_tolstring(script->L, -1, &len);
		if (value == NULL)
			value = "";
		var_expand_state_set_transfer_data(state, value, len);
	}

	lua_pop(script->L, 2);
	(void)lua_gc(script->L, LUA_GCCOLLECT, 0);

	return ret;
}

static int mail_lua_var_expand_lua_file(const struct var_expand_statement *stmt,
				        struct var_expand_state *state,
					const char **error_r)
{
	const char *file = NULL;
	const char *fn = NULL;
	const char *value;

	ARRAY_TYPE(const_string) params;
	t_array_init(&params, 1);
	struct var_expand_parameter_iter_context *iter =
		var_expand_parameter_iter_init(stmt);
	while (var_expand_parameter_iter_more(iter)) {
		const struct var_expand_parameter *par =
			var_expand_parameter_iter_next(iter);
		const char *key = var_expand_parameter_key(par);
		if (key != NULL) {
			*error_r = t_strdup_printf("Unsupported key '%s'", key);
			return -1;
		}
		switch (var_expand_parameter_idx(par)) {
		case 0:
			if (var_expand_parameter_string_or_var(state, par, &file, error_r) < 0)
				return -1;
			break;
		case 1:
			if (var_expand_parameter_string_or_var(state, par, &fn, error_r) < 0)
				return -1;
			break;
		default:
			if (var_expand_parameter_any_or_var(state, par, &value, error_r) < 0)
				return -1;
			array_push_back(&params, &value);
		}
	}

	if (file == NULL || fn == NULL) {
		*error_r = "Missing parameters";
		return -1;
	}

	struct dlua_script *script;
	if (mail_lua_script_load(file, &script, error_r) < 0)
		return -1;

	int ret = mail_lua_script_call(fn, NULL, &params, state, script, error_r);

	/* normalize return value */
	return ret < 0 ? -1 : 0;
}

static int mail_lua_var_expand_lua_call(const struct var_expand_statement *stmt,
				        struct var_expand_state *state,
					const char **error_r)
{
	const char *fn = NULL;
	const char *value;

	ARRAY_TYPE(const_string) params;
	t_array_init(&params, 1);
	struct var_expand_parameter_iter_context *iter =
		var_expand_parameter_iter_init(stmt);
	while (var_expand_parameter_iter_more(iter)) {
		const struct var_expand_parameter *par =
			var_expand_parameter_iter_next(iter);
		const char *key = var_expand_parameter_key(par);
		if (key != NULL) {
			*error_r = t_strdup_printf("Unsupported key '%s'", key);
			return -1;
		}
		if (var_expand_parameter_idx(par) == 0) {
			if (var_expand_parameter_string_or_var(state, par, &fn, error_r) < 0)
				return -1;
		} else {
			if (var_expand_parameter_any_or_var(state, par, &value, error_r) < 0)
				return -1;
			array_push_back(&params, &value);
		}
	}

	if (fn == NULL) {
		*error_r = "Missing parameters";
		return -1;
	}

	if (state->params->event == NULL) {
		*error_r = "No mail user available";
		return -1;
	}

	struct mail_user *user =
		event_get_ptr(state->params->event, SETTINGS_EVENT_MAIL_USER);
	if (user == NULL) {
		*error_r = "No mail user available";
		return -1;
	}
	struct dlua_script *script;

	if (!mail_lua_plugin_get_script(user, &script)) {
		 *error_r = "User has no Lua script loaded";
		 return -1;
	}

	int ret = mail_lua_script_call(fn, user, &params, state, script, error_r);

	/* normalize return value */
	return ret < 0 ? -1 : 0;
}

static const struct mail_storage_hooks mail_lua_hooks = {
	.mail_user_created = mail_lua_user_created,
};

void mail_lua_plugin_init(struct module *module)
{
	mail_storage_hooks_add(module, &mail_lua_hooks);
	var_expand_register_filter("lua_call", mail_lua_var_expand_lua_call);
	var_expand_register_filter("lua_file", mail_lua_var_expand_lua_file);
}

void mail_lua_plugin_deinit(void)
{
	mail_storage_hooks_remove(&mail_lua_hooks);
	mail_lua_scripts_free();
	var_expand_unregister_filter("lua_call");
	var_expand_unregister_filter("lua_file");
}

const char *mail_lua_plugin_dependencies[] = { NULL };
