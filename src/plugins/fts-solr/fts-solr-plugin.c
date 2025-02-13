/* Copyright (c) 2006-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "http-client.h"
#include "mail-user.h"
#include "mail-storage-hooks.h"
#include "solr-connection.h"
#include "fts-user.h"
#include "fts-solr-plugin.h"
#include "settings.h"
#include "fts-solr-settings.h"

const char *fts_solr_plugin_version = DOVECOT_ABI_VERSION;
struct http_client *solr_http_client = NULL;

struct fts_solr_user_module fts_solr_user_module =
	MODULE_CONTEXT_INIT(&mail_user_module_register);

static void fts_solr_mail_user_deinit(struct mail_user *user)
{
	struct fts_solr_user *fuser = FTS_SOLR_USER_CONTEXT_REQUIRE(user);

	settings_free(fuser->set);
	fuser->module_ctx.super.deinit(user);
}

int fts_solr_mail_user_get(struct mail_user *user, struct event *event,
			   struct fts_solr_user **fuser_r,
			   const char **error_r)
{
	struct fts_solr_user *fuser = FTS_SOLR_USER_CONTEXT_REQUIRE(user);
	const struct fts_solr_settings *set;

	if (fts_solr_settings_get(event, &fts_solr_setting_parser_info,
				  &set, error_r) < 0)
		return -1;

	/* Reference the user even when fuser is already initialized */
	if (fts_mail_user_init(user, event, FALSE, error_r) < 0) {
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

static void fts_solr_mail_user_created(struct mail_user *user)
{
	struct mail_user_vfuncs *v = user->vlast;
	struct fts_solr_user *fuser;

	fuser = p_new(user->pool, struct fts_solr_user, 1);
	fuser->module_ctx.super = *v;
	user->vlast = &fuser->module_ctx.super;
	v->deinit = fts_solr_mail_user_deinit;
	MODULE_CONTEXT_SET(user, fts_solr_user_module, fuser);
}

static struct mail_storage_hooks fts_solr_mail_storage_hooks = {
	.mail_user_created = fts_solr_mail_user_created
};

void fts_solr_plugin_init(struct module *module ATTR_UNUSED)
{
	fts_backend_register(&fts_backend_solr);
	mail_storage_hooks_add(module, &fts_solr_mail_storage_hooks);
}

void fts_solr_plugin_deinit(void)
{
	fts_backend_unregister(fts_backend_solr.name);
	mail_storage_hooks_remove(&fts_solr_mail_storage_hooks);
	if (solr_http_client != NULL)
		http_client_deinit(&solr_http_client);

}

const char *fts_solr_plugin_dependencies[] = { "fts", NULL };
