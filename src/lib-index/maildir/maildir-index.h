#ifndef __MAILDIR_INDEX_H
#define __MAILDIR_INDEX_H

struct mail_cache_transaction_ctx;

#include <sys/time.h>
#include "mail-index.h"

/* How often to try to flush dirty flags. */
#define MAILDIR_DIRTY_FLUSH_TIMEOUT (60*5)

/* Return -1 = error, 0 = file not found, 1 = ok */
typedef int maildir_file_do_func(struct mail_index *index,
				 const char *path, void *context);

struct mail_index *
maildir_index_alloc(const char *maildir, const char *index_dir,
		    const char *control_dir);

/* Return new filename base to save into tmp/ */
const char *maildir_generate_tmp_filename(const struct timeval *tv);
int maildir_create_tmp(struct mail_index *index, const char *dir, mode_t mode,
		       const char **path);

const char *maildir_get_location(struct mail_index *index,
				 struct mail_index_record *rec, int *new_dir);
int maildir_file_do(struct mail_index *index, struct mail_index_record *rec,
		    maildir_file_do_func *func, void *context);
enum mail_flags maildir_filename_get_flags(const char *fname,
					   enum mail_flags default_flags);
const char *maildir_filename_set_flags(const char *fname,
				       enum mail_flags flags);
void maildir_index_update_filename(struct mail_index *index, unsigned int uid,
				   const char *fname, int new_dir);

int maildir_index_sync_readonly(struct mail_index *index,
				const char *fname, int *found);
int maildir_index_sync(struct mail_index *index, int minimal_sync,
		       enum mail_lock_type lock_type, int *changes);

int maildir_cache_update_file(struct mail_cache_transaction_ctx **trans_ctx,
			      struct mail_index *index,
			      struct mail_index_record *rec, const char *fname,
			      int new_dir);
int maildir_index_append_file(struct mail_cache_transaction_ctx **trans_ctx,
			      struct mail_index *index, const char *fname,
			      int new_dir);
int maildir_index_update_flags(struct mail_index *index,
			       struct mail_index_record *rec, unsigned int seq,
			       enum modify_type modify_type,
			       enum mail_flags flags, int external_change);
int maildir_try_flush_dirty_flags(struct mail_index *index, int force);

struct istream *maildir_open_mail(struct mail_index *index,
				  struct mail_index_record *rec,
				  time_t *received_date, int *deleted);

int maildir_expunge_mail(struct mail_index *index,
			 struct mail_index_record *rec);

void maildir_clean_tmp(const char *dir);

#endif
