#ifndef __MAILDIR_INDEX_H
#define __MAILDIR_INDEX_H

#include <sys/time.h>
#include <dirent.h>
#include "mail-index.h"

/* ":2,DFRST" - leave the 2 extra for other clients' additions */
#define MAILDIR_LOCATION_EXTRA_SPACE 10

struct mail_index *
maildir_index_alloc(const char *maildir, const char *index_dir,
		    const char *control_dir);

/* Return new filename base to save into tmp/ */
const char *maildir_generate_tmp_filename(const struct timeval *tv);
int maildir_create_tmp(struct mail_index *index, const char *dir,
		       const char **path);

const char *maildir_get_location(struct mail_index *index,
				 struct mail_index_record *rec);
enum mail_flags maildir_filename_get_flags(const char *fname,
					   enum mail_flags default_flags);
const char *maildir_filename_set_flags(const char *fname,
				       enum mail_flags flags);

int maildir_index_rebuild(struct mail_index *index);
int maildir_index_sync(struct mail_index *index,
		       enum mail_lock_type lock_type, int *changes);

int maildir_index_append_file(struct mail_index *index, const char *dir,
			      const char *fname);

struct istream *maildir_open_mail(struct mail_index *index,
				  struct mail_index_record *rec,
				  time_t *internal_date, int *deleted);

void maildir_clean_tmp(const char *dir);

#endif
