/* Copyright (c) 2006-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mail-user.h"
#include "mail-storage-hooks.h"
#include "fts-solr-plugin.h"

#include <stdlib.h>

const char *fts_solr_plugin_version = DOVECOT_VERSION;

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
		if (strncmp(*tmp, "url=", 4) == 0) {
			set->url = p_strdup(user->pool, *tmp + 4);
		} else if (strcmp(*tmp, "debug") == 0) {
			set->debug = TRUE;
		} else if (strcmp(*tmp, "break-imap-search") == 0) {
			set->substring_search = TRUE;
		} else if (strcmp(*tmp, "default_ns=") == 0) {
			set->default_ns_prefix =
				p_strdup(user->pool, *tmp + 11);
		} else {
			i_error("fts_solr: Invalid setting: %s", *tmp);
			return -1;
		}
	}
	if (set->url == NULL) {
		i_error("fts_solr: url setting missing");
		return -1;
	}
	return 0;
}

static void fts_solr_mail_user_create(struct mail_user *user, const char *env)
{
	struct fts_solr_user *fuser;

	fuser = p_new(user->pool, struct fts_solr_user, 1);
	if (fts_solr_plugin_init_settings(user, &fuser->set, env) < 0) {
		/* invalid settings, disabling */
		return;
	}

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
	mail_storage_hooks_add(module, &fts_solr_mail_storage_hooks);
}

void fts_solr_plugin_deinit(void)
{
	fts_backend_unregister(fts_backend_solr.name);
	mail_storage_hooks_remove(&fts_solr_mail_storage_hooks);
}

const char *fts_solr_plugin_dependencies[] = { "fts", NULL };
