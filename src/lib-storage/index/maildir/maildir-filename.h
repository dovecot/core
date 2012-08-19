#ifndef MAILDIR_FILENAME_H
#define MAILDIR_FILENAME_H

struct maildir_keywords_sync_ctx;

const char *maildir_filename_generate(void);

bool maildir_filename_get_size(const char *fname, char type, uoff_t *size_r);

unsigned int maildir_filename_base_hash(const char *fname);
int maildir_filename_base_cmp(const char *fname1, const char *fname2);
int maildir_filename_sort_cmp(const char *fname1, const char *fname2);

#endif
