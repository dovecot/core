/* Copyright (c) 2006-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "crc32.h"
#include "mail-storage-hooks.h"
#include "lucene-wrapper.h"
#include "fts-lucene-plugin.h"

const char *fts_lucene_plugin_version = DOVECOT_ABI_VERSION;

struct fts_lucene_user_module fts_lucene_user_module =
	MODULE_CONTEXT_INIT(&mail_user_module_register);

static int
fts_lucene_plugin_init_settings(struct mail_user *user,
				struct fts_lucene_settings *set,
				const char *str)
{
	const char *const *tmp;

	for (tmp = t_strsplit_spaces(str, " "); *tmp != NULL; tmp++) {
		if (strncmp(*tmp, "default_language=", 17) == 0) {
			set->default_language =
				p_strdup(user->pool, *tmp + 17);
		} else if (strncmp(*tmp, "textcat_conf=", 13) == 0) {
			set->textcat_conf = p_strdup(user->pool, *tmp + 13);
		} else if (strncmp(*tmp, "textcat_dir=", 12) == 0) {
			set->textcat_dir = p_strdup(user->pool, *tmp + 12);
		} else if (strncmp(*tmp, "whitespace_chars=", 17) == 0) {
			set->whitespace_chars = p_strdup(user->pool, *tmp + 17);
		} else if (strcmp(*tmp, "normalize") == 0) {
			set->normalize = TRUE;
		} else if (strcmp(*tmp, "no_snowball") == 0) {
			set->no_snowball = TRUE;
		} else {
			i_error("fts_lucene: Invalid setting: %s", *tmp);
			return -1;
		}
	}
	if (set->textcat_conf != NULL && set->textcat_dir == NULL) {
		i_error("fts_lucene: textcat_conf set, but textcat_dir unset");
		return -1;
	}
	if (set->textcat_conf == NULL && set->textcat_dir != NULL) {
		i_error("fts_lucene: textcat_dir set, but textcat_conf unset");
		return -1;
	}
	if (set->whitespace_chars == NULL)
		set->whitespace_chars = "";
#ifndef HAVE_LUCENE_STEMMER
	if (set->default_language != NULL) {
		i_error("fts_lucene: default_language set, "
			"but Dovecot built without stemmer support");
		return -1;
	}
#else
	if (set->default_language == NULL)
		set->default_language = "english";
#endif
#ifndef HAVE_LUCENE_TEXTCAT
	if (set->textcat_conf != NULL) {
		i_error("fts_lucene: textcat_dir set, "
			"but Dovecot built without textcat support");
		return -1;
	}
#endif
	return 0;
}

uint32_t fts_lucene_settings_checksum(const struct fts_lucene_settings *set)
{
	uint32_t crc;

	/* checksum is always different when compiling with/without stemmer */
	crc = set->default_language == NULL ? 0 :
		crc32_str(set->default_language);
	crc = crc32_str_more(crc, set->whitespace_chars);
	if (set->normalize)
		crc = crc32_str_more(crc, "n");
	if (set->no_snowball)
		crc = crc32_str_more(crc, "s");
	return crc;
}

static void fts_lucene_mail_user_created(struct mail_user *user)
{
	struct fts_lucene_user *fuser;
	const char *env;

	fuser = p_new(user->pool, struct fts_lucene_user, 1);
	env = mail_user_plugin_getenv(user, "fts_lucene");
	if (env == NULL)
		env = "";

	if (fts_lucene_plugin_init_settings(user, &fuser->set, env) < 0) {
		/* invalid settings, disabling */
		return;
	}
	MODULE_CONTEXT_SET(user, fts_lucene_user_module, fuser);
}

static struct mail_storage_hooks fts_lucene_mail_storage_hooks = {
	.mail_user_created = fts_lucene_mail_user_created
};

void fts_lucene_plugin_init(struct module *module ATTR_UNUSED)
{
	fts_backend_register(&fts_backend_lucene);
	mail_storage_hooks_add(module, &fts_lucene_mail_storage_hooks);
}

void fts_lucene_plugin_deinit(void)
{
	fts_backend_unregister(fts_backend_lucene.name);
	mail_storage_hooks_remove(&fts_lucene_mail_storage_hooks);
	lucene_shutdown();
}

const char *fts_lucene_plugin_dependencies[] = { "fts", NULL };
