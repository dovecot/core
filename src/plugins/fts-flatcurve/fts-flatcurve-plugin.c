/* Copyright (c) the Dovecot authors, based on code by Michael Slusarz.
 * See the included COPYING file */

#include "lib.h"
#include "settings.h"
#include "mail-storage-hooks.h"
#include "mail-storage-private.h"
#include "str-parse.h"
#include "mailbox-list-private.h"
#include "fts-user.h"
#include "fts-backend-flatcurve.h"
#include "fts-backend-flatcurve-xapian.h"
#include "fts-flatcurve-plugin.h"

const char *fts_flatcurve_plugin_version = DOVECOT_ABI_VERSION;

static MODULE_CONTEXT_DEFINE_INIT(fts_flatcurve_mailbox_list_module,
				  &mailbox_list_module_register);
struct fts_flatcurve_user_module fts_flatcurve_user_module =
	MODULE_CONTEXT_INIT(&mail_user_module_register);

struct fts_flatcurve_mailbox_list {
	union mailbox_list_module_context module_ctx;
};

#define FTS_FLATCURVE_LIST_CONTEXT(obj) \
	MODULE_CONTEXT(obj, fts_flatcurve_mailbox_list_module)

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

static bool
fts_flatcurve_is_internal_name(struct mailbox_list *list, const char *name)
{
	struct fts_flatcurve_mailbox_list *flist = FTS_FLATCURVE_LIST_CONTEXT(list);

	/* We need to recognize the fts-flatcurve directory as an internal
	   mailbox directory. This ensures that Maildir's non-recursive
	   mailbox deletion (which only deletes known internal directories
	   and skips potential sub-mailboxes) will successfully delete
	   the FTS data. */
	if (strcmp(name, FTS_FLATCURVE_LABEL) == 0)
		return TRUE;

	if (flist->module_ctx.super.is_internal_name != NULL)
		return flist->module_ctx.super.is_internal_name(list, name);

	return FALSE;
}

static void fts_flatcurve_mailbox_list_created(struct mailbox_list *list)
{
	struct fts_flatcurve_mailbox_list *flist;
	struct mailbox_list_vfuncs *v = list->vlast;

	flist = p_new(list->pool, struct fts_flatcurve_mailbox_list, 1);
	flist->module_ctx.super = *v;
	list->vlast = &flist->module_ctx.super;
	v->is_internal_name = fts_flatcurve_is_internal_name;

	MODULE_CONTEXT_SET(list, fts_flatcurve_mailbox_list_module, flist);
}

static struct mail_storage_hooks fts_backend_mail_storage_hooks = {
	.mail_user_created = fts_flatcurve_mail_user_created,
	.mailbox_list_created = fts_flatcurve_mailbox_list_created,
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
