#ifndef __MAILDIR_FILENAME_H
#define __MAILDIR_FILENAME_H

struct maildir_keywords_sync_ctx;

const char *maildir_generate_tmp_filename(const struct timeval *tv);

void maildir_filename_get_flags(struct maildir_keywords_sync_ctx *ctx,
				const char *fname, enum mail_flags *flags_r,
				ARRAY_TYPE(keyword_indexes) *keywords_r);

const char *maildir_filename_set_flags(struct maildir_keywords_sync_ctx *ctx,
				       const char *fname, enum mail_flags flags,
				       ARRAY_TYPE(keyword_indexes) *keywords);

bool maildir_filename_get_size(const char *fname, char type, uoff_t *size_r);

unsigned int maildir_hash(const void *p);
int maildir_cmp(const void *p1, const void *p2);

#endif
