#ifndef __MBOX_STORAGE_H
#define __MBOX_STORAGE_H

#include "index-storage.h"

int mbox_storage_copy(Mailbox *box, Mailbox *destbox,
		      const char *messageset, int uidset);
int mbox_storage_save(Mailbox *box, MailFlags flags, const char *custom_flags[],
		      time_t internal_date, IOBuffer *data, uoff_t data_size);

int mbox_find_mailboxes(MailStorage *storage, const char *mask,
			MailboxFunc func, void *context);
int mbox_find_subscribed(MailStorage *storage, const char *mask,
			 MailboxFunc func, void *context);

int mbox_expunge_locked(IndexMailbox *ibox,
			MailExpungeFunc expunge_func, void *context);

#endif
