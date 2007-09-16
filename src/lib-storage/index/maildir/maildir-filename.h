#ifndef MAILDIR_FILENAME_H
#define MAILDIR_FILENAME_H

struct maildir_keywords_sync_ctx;

const char *maildir_filename_generate(void);

void maildir_filename_get_flags(struct maildir_keywords_sync_ctx *ctx,
			       const char *fname, enum mail_flags *flags_r,
                               ARRAY_TYPE(keyword_indexes) *keywords_r);

const char *maildir_filename_set_flags(struct maildir_keywords_sync_ctx *ctx,
				       const char *fname, enum mail_flags flags,
				       ARRAY_TYPE(keyword_indexes) *keywords);

bool maildir_filename_get_size(const char *fname, char type, uoff_t *size_r);

unsigned int maildir_filename_base_hash(const void *p);
int maildir_filename_base_cmp(const void *p1, const void *p2);
int maildir_filename_sort_cmp(const char *fname1, const char *fname2);

#endif
