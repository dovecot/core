#ifndef FTS_USER_H
#define FTS_USER_H

#include "fts-settings.h"

const struct fts_settings *fts_user_get_settings(struct mail_user *user);
int fts_user_try_get_settings(struct mail_user *user,
			      const struct fts_settings **set_r);

size_t fts_mail_user_message_max_size(struct mail_user *user);

int fts_mail_user_init(struct mail_user *user, bool initialize_libfts,
		       const char **error_r);
void fts_mail_user_deinit(struct mail_user *user);

#endif
