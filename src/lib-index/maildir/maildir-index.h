#ifndef __MAILDIR_INDEX_H
#define __MAILDIR_INDEX_H

#include "mail-index.h"

/* ":2,DFRST" - leave the 2 extra for other clients' additions */
#define MAILDIR_LOCATION_EXTRA_SPACE 10

struct mail_index *maildir_index_alloc(const char *dir, const char *maildir);

enum mail_flags maildir_filename_get_flags(const char *fname,
					   enum mail_flags default_flags);
const char *maildir_filename_set_flags(const char *fname,
				       enum mail_flags flags);

int maildir_index_rebuild(struct mail_index *index);
int maildir_index_sync(struct mail_index *index,
		       enum mail_lock_type lock_type, int *changes);

int maildir_index_append_file(struct mail_index *index, const char *dir,
			      const char *fname);
int maildir_index_build_dir(struct mail_index *index, const char *source_dir,
			    const char *dest_dir);

struct istream *maildir_open_mail(struct mail_index *index,
				  struct mail_index_record *rec,
				  time_t *internal_date, int *deleted);

int maildir_record_update(struct mail_index *index,
			  struct mail_index_update *update, int fd);

#endif
