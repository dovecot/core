#ifndef __MAILDIR_STORAGE_H
#define __MAILDIR_STORAGE_H

#include "index-storage.h"

int maildir_storage_copy(Mailbox *box, Mailbox *destbox,
			 const char *messageset, int uidset);
int maildir_storage_save(Mailbox *box, MailFlags flags,
			 const char *custom_flags[], time_t internal_date,
			 IOBuffer *data, size_t data_size);

int maildir_find_mailboxes(MailStorage *storage, const char *mask,
			   MailboxFunc func, void *user_data);
int maildir_find_subscribed(MailStorage *storage, const char *mask,
			    MailboxFunc func, void *user_data);

int maildir_expunge_locked(IndexMailbox *ibox,
			   MailExpungeFunc expunge_func, void *user_data);

#endif
