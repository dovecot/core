/* Copyright (c) 2006-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "http-client.h"
#include "mail-user.h"
#include "mail-storage-hooks.h"
#include "solr-connection.h"
#include "fts-user.h"
#include "fts-solr-plugin.h"

#define DEFAULT_SOLR_BATCH_SIZE 1000

const char *fts_solr_plugin_version = DOVECOT_ABI_VERSION;
struct http_client *solr_http_client = NULL;

struct fts_solr_user_module fts_solr_user_module =
	MODULE_CONTEXT_INIT(&mail_user_module_register);

static int
fts_solr_plugin_init_settings(struct mail_user *user,
			      struct fts_solr_settings *set, const char *str)
{
	const char *const *tmp;

	if (str == NULL)
		str = "";

	for (tmp = t_strsplit_spaces(str, " "); *tmp != NULL; tmp++) {
		if (str_begins(*tmp, "url=")) {
			set->url = p_strdup(user->pool, *tmp + 4);
		} else if (strcmp(*tmp, "debug") == 0) {
			set->debug = TRUE;
		} else if (strcmp(*tmp, "use_libfts") == 0) {
			set->use_libfts = TRUE;
		} else if (str_begins(*tmp, "default_ns=")) {
			set->default_ns_prefix =
				p_strdup(user->pool, *tmp + 11);
		} else if (str_begins(*tmp, "rawlog_dir=")) {
			set->rawlog_dir = p_strdup(user->pool, *tmp + 11);
		} else if (str_begins(*tmp, "batch_size=")) {
			set->batch_size = atoi(*tmp + 11);
		} else if (str_begins(*tmp, "no_soft_commit")) {
			set->no_soft_commit = TRUE;
		} else {
			i_error("fts_solr: Invalid setting: %s", *tmp);
			return -1;
		}
	}
	if (set->url == NULL) {
		i_error("fts_solr: url setting missing");
		return -1;
	}
	if (set->batch_size <= 0) set->batch_size = DEFAULT_SOLR_BATCH_SIZE;
	return 0;
}

static void fts_solr_mail_user_deinit(struct mail_user *user)
{
	struct fts_solr_user *fuser = FTS_SOLR_USER_CONTEXT_REQUIRE(user);

	if (fuser->set.use_libfts)
		fts_mail_user_deinit(user);
	fuser->module_ctx.super.deinit(user);
}

static void fts_solr_mail_user_create(struct mail_user *user, const char *env)
{
	struct mail_user_vfuncs *v = user->vlast;
	struct fts_solr_user *fuser;
	const char *error;

	fuser = p_new(user->pool, struct fts_solr_user, 1);
	if (fts_solr_plugin_init_settings(user, &fuser->set, env) < 0) {
		/* invalid settings, disabling */
		return;
	}
	if (fuser->set.use_libfts) {
		if (fts_mail_user_init(user, &error) < 0) {
			i_error("fts-solr: %s", error);
			return;
		}
	}

	fuser->module_ctx.super = *v;
	user->vlast = &fuser->module_ctx.super;
	v->deinit = fts_solr_mail_user_deinit;
	MODULE_CONTEXT_SET(user, fts_solr_user_module, fuser);
}

static void fts_solr_mail_user_created(struct mail_user *user)
{
	const char *env;

	env = mail_user_plugin_getenv(user, "fts_solr");
	if (env != NULL)
		fts_solr_mail_user_create(user, env);
}

static struct mail_storage_hooks fts_solr_mail_storage_hooks = {
	.mail_user_created = fts_solr_mail_user_created
};

void fts_solr_plugin_init(struct module *module)
{
	fts_backend_register(&fts_backend_solr);
	fts_backend_register(&fts_backend_solr_old);
	mail_storage_hooks_add(module, &fts_solr_mail_storage_hooks);
}

void fts_solr_plugin_deinit(void)
{
	fts_backend_unregister(fts_backend_solr.name);
	fts_backend_unregister(fts_backend_solr_old.name);
	mail_storage_hooks_remove(&fts_solr_mail_storage_hooks);
	if (solr_http_client != NULL)
		http_client_deinit(&solr_http_client);

}

const char *fts_solr_plugin_dependencies[] = { "fts", NULL };
