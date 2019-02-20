/* Copyright (c) 2006-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "crc32.h"
#include "mail-storage-hooks.h"
#include "lucene-wrapper.h"
#include "fts-user.h"
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
		if (str_begins(*tmp, "default_language=")) {
			set->default_language =
				p_strdup(user->pool, *tmp + 17);
		} else if (str_begins(*tmp, "textcat_conf=")) {
			set->textcat_conf = p_strdup(user->pool, *tmp + 13);
		} else if (str_begins(*tmp, "textcat_dir=")) {
			set->textcat_dir = p_strdup(user->pool, *tmp + 12);
		} else if (str_begins(*tmp, "whitespace_chars=")) {
			set->whitespace_chars = p_strdup(user->pool, *tmp + 17);
		} else if (strcmp(*tmp, "normalize") == 0) {
			set->normalize = TRUE;
		} else if (strcmp(*tmp, "no_snowball") == 0) {
			set->no_snowball = TRUE;
		} else if (strcmp(*tmp, "mime_parts") == 0) {
			set->mime_parts = TRUE;
		} else if (strcmp(*tmp, "use_libfts") == 0) {
			set->use_libfts = TRUE;
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
#ifndef HAVE_FTS_STEMMER
	if (set->default_language != NULL) {
		i_error("fts_lucene: default_language set, "
			"but Dovecot built without stemmer support");
		return -1;
	}
#else
	if (set->default_language == NULL)
		set->default_language = "english";
#endif
#ifndef HAVE_FTS_TEXTCAT
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

	if (set->use_libfts)
		return crc32_str("l");

	/* checksum is always different when compiling with/without stemmer */
	crc = set->default_language == NULL ? 0 :
		crc32_str(set->default_language);
	crc = crc32_str_more(crc, set->whitespace_chars);
	if (set->normalize)
		crc = crc32_str_more(crc, "n");
	if (set->no_snowball)
		crc = crc32_str_more(crc, "s");
	/* don't include mime_parts here, since changing it doesn't
	   necessarily need the index to be rebuilt */
	return crc;
}

static void fts_lucene_mail_user_deinit(struct mail_user *user)
{
	struct fts_lucene_user *fuser = FTS_LUCENE_USER_CONTEXT_REQUIRE(user);

	if (fuser->set.use_libfts)
		fts_mail_user_deinit(user);
	fuser->module_ctx.super.deinit(user);
}

static void fts_lucene_mail_user_created(struct mail_user *user)
{
	struct mail_user_vfuncs *v = user->vlast;
	struct fts_lucene_user *fuser;
	const char *env, *error;

	fuser = p_new(user->pool, struct fts_lucene_user, 1);
	env = mail_user_plugin_getenv(user, "fts_lucene");
	if (env == NULL)
		env = "";

	if (fts_lucene_plugin_init_settings(user, &fuser->set, env) < 0) {
		/* invalid settings, disabling */
		return;
	}
	if (fuser->set.use_libfts) {
		if (fts_mail_user_init(user, &error) < 0) {
			i_error("fts_lucene: %s", error);
			return;
		}
	}

	fuser->module_ctx.super = *v;
	user->vlast = &fuser->module_ctx.super;
	v->deinit = fts_lucene_mail_user_deinit;
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
