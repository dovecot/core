#ifndef __MAILDIR_INDEX_H
#define __MAILDIR_INDEX_H

#include "mail-index.h"

/* ":2,DFRST" - leave the 2 extra for other clients' additions */
#define MAILDIR_LOCATION_EXTRA_SPACE 10

MailIndex *maildir_index_alloc(const char *dir);

MailFlags maildir_filename_get_flags(const char *fname,
				     MailFlags default_flags);
const char *maildir_filename_set_flags(const char *fname, MailFlags flags);

int maildir_index_rebuild(MailIndex *index);
int maildir_index_sync(MailIndex *index, MailLockType lock_type, int *changes);

int maildir_index_append_file(MailIndex *index, const char *dir,
			      const char *fname);
int maildir_index_build_dir(MailIndex *index, const char *source_dir,
			    const char *dest_dir);

IBuffer *maildir_open_mail(MailIndex *index, MailIndexRecord *rec,
			   time_t *internal_date, int *deleted);

int maildir_record_update(MailIndex *index, MailIndexUpdate *update, int fd);

#endif
