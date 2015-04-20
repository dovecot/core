#ifndef FTS_USER_H
#define FTS_USER_H

struct fts_user_language {
	const struct fts_language *lang;
	struct fts_filter *filter;
};
ARRAY_DEFINE_TYPE(fts_user_language, struct fts_user_language *);

int fts_user_language_get(struct mail_user *user,
			  const struct fts_language *lang,
			  struct fts_user_language **user_lang_r,
			  const char **error_r);
int fts_user_languages_fill_all(struct mail_user *user, const char **error_r);

struct fts_language_list *fts_user_get_language_list(struct mail_user *user);
const ARRAY_TYPE(fts_user_language) *
fts_user_get_all_languages(struct mail_user *user);

void fts_mail_user_created(struct mail_user *user);

#endif
