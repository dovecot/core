#ifndef MAILDIR_FILENAME_FLAGS_H
#define MAILDIR_FILENAME_FLAGS_H

void maildir_filename_flags_get(struct maildir_keywords_sync_ctx *ctx,
			       const char *fname, enum mail_flags *flags_r,
                               ARRAY_TYPE(keyword_indexes) *keywords_r);

const char *maildir_filename_flags_set(const char *fname, enum mail_flags flags);
const char *maildir_filename_flags_kw_set(struct maildir_keywords_sync_ctx *ctx,
					  const char *fname, enum mail_flags flags,
					  ARRAY_TYPE(keyword_indexes) *keywords);

#endif
