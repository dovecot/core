/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "module-dir.h"
#include "randgen.h"
#include "settings.h"
#include "settings-parser.h"
#include "mail-user.h"
#include "mail-storage-private.h"
#include "mail-storage-hooks.h"
#include <sys/apparmor.h>

const char *apparmor_plugin_version = DOVECOT_ABI_VERSION;

/* hooks into user creation and deinit, will try to use
   hats provided by apparmor_hat, apparmor_hat1... etc */

#define APPARMOR_USER_CONTEXT(obj) \
	(struct apparmor_mail_user*)MODULE_CONTEXT(obj, apparmor_mail_user_module)

static MODULE_CONTEXT_DEFINE_INIT(apparmor_mail_user_module,
				  &mail_user_module_register);

struct apparmor_mail_user {
	union mail_user_module_context module_ctx;
	unsigned long token;
};

struct apparmor_settings {
	pool_t pool;

	ARRAY_TYPE(const_string) apparmor_hats;
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct apparmor_settings)
static const struct setting_define apparmor_setting_defines[] = {
	DEF(BOOLLIST, apparmor_hats),

	SETTING_DEFINE_LIST_END
};
static const struct apparmor_settings apparmor_default_settings = {
	.apparmor_hats = ARRAY_INIT,
};

const struct setting_parser_info apparmor_setting_parser_info = {
	.name = "apparmor",
	.plugin_dependency = "lib01_apparmor_plugin",

	.defines = apparmor_setting_defines,
	.defaults = &apparmor_default_settings,

	.struct_size = sizeof(struct apparmor_settings),
	.pool_offset1 = 1 + offsetof(struct apparmor_settings, pool),
};

void apparmor_plugin_init(struct module*);
void apparmor_plugin_deinit(void);

static void apparmor_log_current_context(struct mail_user *user)
{
	char *con, *mode;

	if (aa_getcon(&con, &mode) < 0) {
		e_debug(user->event, "aa_getcon() failed: %m");
	} else {
		e_debug(user->event, "apparmor: Current context=%s, mode=%s",
			con, mode);
		free(con);
	}
}

static void apparmor_mail_user_deinit(struct mail_user *user)
{
	struct apparmor_mail_user *auser = APPARMOR_USER_CONTEXT(user);

	i_assert(auser != NULL);
	auser->module_ctx.super.deinit(user);

	if (aa_change_hat(NULL, auser->token)<0)
		i_fatal("aa_change_hat(NULL) failed: %m");

	apparmor_log_current_context(user);
}

static void apparmor_mail_user_created(struct mail_user *user)
{
	struct mail_user_vfuncs *v = user->vlast;
	struct apparmor_mail_user *auser;
	const struct apparmor_settings *set;
	const char *error;

	if (settings_get(user->event, &apparmor_setting_parser_info, 0,
			 &set, &error) < 0) {
		user->error = p_strdup(user->pool, error);
		return;
	}
	if (array_is_empty(&set->apparmor_hats)) {
		settings_free(set);
		return;
	}

	/* we got hat(s) to try */
	auser = p_new(user->pool, struct apparmor_mail_user, 1);
	auser->module_ctx.super = *v;
	user->vlast = &auser->module_ctx.super;
	v->deinit = apparmor_mail_user_deinit;
	MODULE_CONTEXT_SET(user, apparmor_mail_user_module, auser);

	/* generate a magic token */
	random_fill(&auser->token, sizeof(auser->token));

	/* try change hat */
	const char *const *hats = settings_boollist_get(&set->apparmor_hats);
	if (aa_change_hatv((const char **)hats, auser->token) < 0) {
		i_fatal("aa_change_hatv(%s) failed: %m",
			t_array_const_string_join(&set->apparmor_hats, ","));
	}
	settings_free(set);

	apparmor_log_current_context(user);
}

static const struct mail_storage_hooks apparmor_hooks = {
	.mail_user_created = apparmor_mail_user_created
};

void apparmor_plugin_init(struct module *module)
{
	mail_storage_hooks_add(module, &apparmor_hooks);
}

void apparmor_plugin_deinit(void)
{
	mail_storage_hooks_remove(&apparmor_hooks);
}
