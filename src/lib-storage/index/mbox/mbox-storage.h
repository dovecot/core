#ifndef __MBOX_STORAGE_H
#define __MBOX_STORAGE_H

#include "index-storage.h"

int mbox_storage_copy(struct mailbox *box, struct mailbox *destbox,
		      const char *messageset, int uidset);
int mbox_storage_save(struct mailbox *box, enum mail_flags flags,
		      const char *custom_flags[], time_t internal_date,
		      int timezone_offset,
		      struct istream *data, uoff_t data_size);

int mbox_find_mailboxes(struct mail_storage *storage, const char *mask,
			MailboxFunc func, void *context);
int mbox_find_subscribed(struct mail_storage *storage, const char *mask,
			 MailboxFunc func, void *context);

int mbox_expunge_locked(struct index_mailbox *ibox, int notify);

int mbox_is_valid_mask(const char *mask);

#endif
