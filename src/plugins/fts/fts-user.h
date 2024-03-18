#ifndef FTS_USER_H
#define FTS_USER_H

#include "fts-settings.h"

const struct fts_settings *fts_user_get_settings(struct mail_user *user);

size_t fts_mail_user_message_max_size(struct mail_user *user);

int fts_mail_user_init(struct mail_user *user, struct event *event,
		       bool initialize_libfts, const char **error_r);
void fts_mail_user_created(struct mail_user *user);

#endif
