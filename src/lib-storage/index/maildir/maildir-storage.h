#ifndef __MAILDIR_STORAGE_H
#define __MAILDIR_STORAGE_H

#include "index-storage.h"

int maildir_storage_copy(struct mailbox *box, struct mailbox *destbox,
			 const char *messageset, int uidset);
int maildir_storage_save(struct mailbox *box, enum mail_flags flags,
			 const char *custom_flags[],
			 time_t internal_date, int timezone_offset,
			 struct istream *data, uoff_t data_size);

int maildir_find_mailboxes(struct mail_storage *storage, const char *mask,
			   MailboxFunc func, void *context);
int maildir_find_subscribed(struct mail_storage *storage, const char *mask,
			    MailboxFunc func, void *context);

int maildir_expunge_locked(struct index_mailbox *ibox, int notify);

/* Return new filename base to save into tmp/ */
const char *maildir_generate_tmp_filename(void);

#endif
