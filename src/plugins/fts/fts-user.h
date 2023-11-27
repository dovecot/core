#ifndef FTS_USER_H
#define FTS_USER_H

#include "fts-settings.h"

struct fts_user_language {
	const struct language *lang;
	struct lang_filter *filter;
	struct lang_tokenizer *index_tokenizer, *search_tokenizer;
};
ARRAY_DEFINE_TYPE(fts_user_language, struct fts_user_language *);

struct fts_user_language *
fts_user_language_find(struct mail_user *user,
                       const struct language *lang);
struct language_list *fts_user_get_language_list(struct mail_user *user);
const ARRAY_TYPE(fts_user_language) *
fts_user_get_all_languages(struct mail_user *user);
struct fts_user_language *fts_user_get_data_lang(struct mail_user *user);
const ARRAY_TYPE(fts_user_language) *
fts_user_get_data_languages(struct mail_user *user);

const struct fts_settings *fts_user_get_settings(struct mail_user *user);
int fts_user_try_get_settings(struct mail_user *user,
			      const struct fts_settings **set_r);

bool fts_user_autoindex_exclude(struct mailbox *box);
size_t fts_mail_user_message_max_size(struct mail_user *user);

int fts_mail_user_init(struct mail_user *user, bool initialize_libfts,
		       const char **error_r);
void fts_mail_user_deinit(struct mail_user *user);

#endif
