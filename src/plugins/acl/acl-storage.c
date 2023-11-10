/* Copyright (c) 2006-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "mail-namespace.h"
#include "mailbox-list-private.h"
#include "acl-api-private.h"
#include "acl-lookup-dict.h"
#include "acl-plugin.h"


struct acl_storage_module acl_storage_module =
	MODULE_CONTEXT_INIT(&mail_storage_module_register);
struct acl_user_module acl_user_module =
	MODULE_CONTEXT_INIT(&mail_user_module_register);

static void acl_user_deinit(struct mail_user *user)
{
	struct acl_user *auser = ACL_USER_CONTEXT(user);

	i_assert(auser != NULL);
	acl_lookup_dict_deinit(&auser->acl_lookup_dict);
	auser->module_ctx.super.deinit(user);
}

static void acl_mail_user_create(struct mail_user *user, const char *env)
{
	struct mail_user_vfuncs *v = user->vlast;
	struct acl_user *auser;
	const char *error;
	int ret;

	auser = p_new(user->pool, struct acl_user, 1);
	auser->module_ctx.super = *v;
	user->vlast = &auser->module_ctx.super;
	v->deinit = acl_user_deinit;
	if ((ret = acl_lookup_dict_init(user, &auser->acl_lookup_dict, &error)) < 0) {
		e_error(user->event, "acl: dict_init() failed: %s", error);
		user->error = p_strdup(user->pool, error);
	} else if (ret == 0) {
		e_debug(user->event, "acl: Shared mailbox listing disabled: %s", error);
	} else {
		e_debug(user->event, "acl: Shared mailbox listing enabled");
	}

	struct acl_settings *set = p_new(user->pool, struct acl_settings, 1);
	auser->acl_env = env;
	set->acl_globals_only =
		mail_user_plugin_getenv_bool(user, "acl_globals_only");
	set->acl_defaults_from_inbox =
		mail_user_plugin_getenv_bool(user, "acl_defaults_from_inbox");
	set->acl_user = mail_user_plugin_getenv(user, "acl_user");
	if (set->acl_user == NULL)
		set->acl_user = mail_user_plugin_getenv(user, "master_user");

	env = mail_user_plugin_getenv(user, "acl_groups");
	if (env != NULL) {
		p_array_init(&set->acl_groups, user->pool, 1);
		const char *const *groups = (const char *const *)
			p_strsplit_spaces(user->pool, env, ", ");
		array_append(&set->acl_groups, groups, str_array_length(groups));
		array_sort(&set->acl_groups, i_strcmp_p);
	}

	MODULE_CONTEXT_SET(user, acl_user_module, auser);
}

void acl_mail_user_created(struct mail_user *user)
{
	const char *env;

	env = mail_user_plugin_getenv(user, "acl");
	if (env != NULL && *env != '\0')
		acl_mail_user_create(user, env);
	else {
		e_debug(user->event, "acl: No acl setting - ACLs are disabled");
	}
}
