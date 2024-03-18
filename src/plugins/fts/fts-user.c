/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "module-context.h"
#include "str-parse.h"
#include "mail-user.h"
#include "mail-storage-private.h"
#include "language.h"
#include "lang-filter.h"
#include "lang-tokenizer.h"
#include "lang-user.h"
#include "fts-user.h"
#include "settings.h"
#include "fts-settings.h"

#define FTS_USER_CONTEXT(obj) \
	MODULE_CONTEXT(obj, fts_user_module)
#define FTS_USER_CONTEXT_REQUIRE(obj) \
	MODULE_CONTEXT_REQUIRE(obj, fts_user_module)

struct fts_user {
	union mail_user_module_context module_ctx;
	const struct fts_settings *set;
	int refcount;
};

static MODULE_CONTEXT_DEFINE_INIT(fts_user_module,
				  &mail_user_module_register);

const struct fts_settings *fts_user_get_settings(struct mail_user *user)
{
	struct fts_user *fuser = FTS_USER_CONTEXT_REQUIRE(user);
	return fuser->set;
}

size_t fts_mail_user_message_max_size(struct mail_user *user)
{
	struct fts_user *fuser = FTS_USER_CONTEXT_REQUIRE(user);
	return fuser->set->message_max_size;
}

int fts_mail_user_init(struct mail_user *user, bool initialize_libfts,
		       const char **error_r)
{
	struct fts_user *fuser = FTS_USER_CONTEXT(user);

	if (fuser != NULL) {
		/* multiple fts plugins are loaded */
		fuser->refcount++;
		return 0;
	}

	const struct fts_settings *set;
	if (settings_get(user->event, &fts_setting_parser_info, 0, &set, error_r) < 0)
		return -1;

	if (lang_user_init(user, user->event, initialize_libfts, error_r) < 0) {
		settings_free(set);
		return -1;
	}

	fuser = p_new(user->pool, struct fts_user, 1);
	fuser->set = set;
	fuser->refcount = 1;

	MODULE_CONTEXT_SET(user, fts_user_module, fuser);
	return 0;
}

void fts_mail_user_deinit(struct mail_user *user)
{
	struct fts_user *fuser = FTS_USER_CONTEXT(user);

	if (fuser != NULL) {
		i_assert(fuser->refcount > 0);
		if (--fuser->refcount == 0) {
			settings_free(fuser->set);
			lang_user_deinit(user);
		}
	}
}
