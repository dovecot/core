/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "module-dir.h"
#include "mail-lua-plugin.h"
#include "mail-storage-lua.h"
#include "mail-storage-private.h"
#include "mail-storage-hooks.h"
#include "dlua-script-private.h"

#define MAIL_LUA_SCRIPT "mail_lua_script"
#define MAIL_LUA_USER_CREATED_FN "mail_user_created"
#define MAIL_LUA_USER_DEINIT_FN "mail_user_deinit"
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
	lua_getglobal(script->L, hook);

	/* not found, disable */
	if (!lua_isfunction(script->L, -1))
		return 0;

	if (user->mail_debug)
		e_debug(user->event, "mail-lua: Calling %s(user)", hook);

	dlua_push_mail_user(script, user);

	if (lua_pcall(script->L, 1, 2, 0) != 0) {
		*error_r = t_strdup_printf("%s(user) failed: %s",
					   hook, lua_tostring(script->L, -1));
		return -1;
	}

	int ret = lua_tonumber(script->L, -2);
	const char *errmsg = lua_tostring(script->L, -1);

	if (ret < 0) {
		*error_r = t_strdup_printf("%s(user) failed: %s",
					   hook, errmsg);
	}

	(void)lua_gc(script->L, LUA_GCCOLLECT, 0);

	return ret < 0 ? -1 : 1;
}

static void mail_lua_user_deinit(struct mail_user *user)
{
	struct mail_lua_user_context *luser = MAIL_LUA_USER_CONTEXT(user);
	const char *error;
	int ret;

	if (luser == NULL)
		return;

	luser->module_ctx.super.deinit(user);

	if ((ret = mail_lua_call_hook(luser->script, user, MAIL_LUA_USER_DEINIT_FN,
				      &error)) < 0) {
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
	const char *script_fn = mail_user_plugin_getenv(user, MAIL_LUA_SCRIPT);
	int ret;

	if (script_fn == NULL)
		return;

	if (dlua_script_create_file(script_fn, &script, &error) < 0) {
		user->error = p_strdup_printf(user->pool, "dlua_script_create_file(%s) failed: %s",
					      script_fn, error);
		return;
	}

	dlua_dovecot_register(script);
	dlua_register_mail_storage(script);

	/* init */
	if (dlua_script_init(script, &error) < 0) {
		user->error = p_strdup_printf(user->pool, "dlua_script_init(%s) failed: %s",
					      script_fn, error);
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
	v->deinit = mail_lua_user_deinit;
	luser->script = script;
	user->vlast = &luser->module_ctx.super;

	MODULE_CONTEXT_SET(user, mail_lua_user_module, luser);
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

static const struct mail_storage_hooks mail_lua_hooks = {
	.mail_user_created = mail_lua_user_created,
};

void mail_lua_plugin_init(struct module *module)
{
	mail_storage_hooks_add(module, &mail_lua_hooks);
}

void mail_lua_plugin_deinit(void)
{
	mail_storage_hooks_remove(&mail_lua_hooks);
}

const char *mail_lua_plugin_dependencies[] = { NULL };
