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

void acl_mail_user_created(struct mail_user *user)
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

	MODULE_CONTEXT_SET(user, acl_user_module, auser);
}
