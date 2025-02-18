/* Copyright (c) the Dovecot authors, based on code by Michael Slusarz.
 * See the included COPYING file */

#include "lib.h"
#include "settings.h"
#include "mail-storage-hooks.h"
#include "str-parse.h"
#include "fts-user.h"
#include "fts-backend-flatcurve.h"
#include "fts-backend-flatcurve-xapian.h"
#include "fts-flatcurve-plugin.h"

const char *fts_flatcurve_plugin_version = DOVECOT_ABI_VERSION;

struct fts_flatcurve_user_module fts_flatcurve_user_module =
	MODULE_CONTEXT_INIT(&mail_user_module_register);

static void fts_flatcurve_mail_user_deinit(struct mail_user *user)
{
	struct fts_flatcurve_user *fuser =
		FTS_FLATCURVE_USER_CONTEXT_REQUIRE(user);

	fuser->module_ctx.super.deinit(user);
	settings_free(fuser->set);
}

int fts_flatcurve_mail_user_get(struct mail_user *user, struct event *event,
				struct fts_flatcurve_user **fuser_r,
				const char **error_r)
{
	struct fts_flatcurve_user *fuser =
		FTS_FLATCURVE_USER_CONTEXT_REQUIRE(user);
	struct fts_flatcurve_settings *set;

	if (settings_get(event, &fts_flatcurve_setting_parser_info, 0,
			 &set, error_r) < 0)
		return -1;

	/* Reference the user even when fuser is already initialized */
	if (fts_mail_user_init(user, event, TRUE, error_r) < 0) {
		settings_free(set);
		return -1;
	}
	if (fuser->set == NULL)
		fuser->set = set;
	else
		settings_free(set);

	*fuser_r = fuser;
	return 0;
}

static void fts_flatcurve_mail_user_created(struct mail_user *user)
{
	struct fts_flatcurve_user *fuser;
	struct mail_user_vfuncs *v = user->vlast;

	fuser = p_new(user->pool, struct fts_flatcurve_user, 1);
	fuser->module_ctx.super = *v;
	user->vlast = &fuser->module_ctx.super;
	v->deinit = fts_flatcurve_mail_user_deinit;
	MODULE_CONTEXT_SET(user, fts_flatcurve_user_module, fuser);
}

static struct mail_storage_hooks fts_backend_mail_storage_hooks = {
	.mail_user_created = fts_flatcurve_mail_user_created
};

void fts_flatcurve_plugin_init(struct module *module ATTR_UNUSED)
{
	fts_backend_register(&fts_backend_flatcurve);
	mail_storage_hooks_add(module, &fts_backend_mail_storage_hooks);
}

void fts_flatcurve_plugin_deinit(void)
{
	fts_backend_unregister(fts_backend_flatcurve.name);
	mail_storage_hooks_remove(&fts_backend_mail_storage_hooks);
}

const char *fts_flatcurve_plugin_dependencies[] = { "fts", NULL };
