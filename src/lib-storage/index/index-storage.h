#ifndef __INDEX_STORAGE_H
#define __INDEX_STORAGE_H

#include "mail-storage.h"
#include "mail-index.h"
#include "imap-message-cache.h"
#include "flags-file/flags-file.h"

typedef struct _IndexMailbox IndexMailbox;

struct _IndexMailbox {
	Mailbox box;

	/* expunge messages marked as deleted, requires index to be
	   exclusively locked */
	int (*expunge_locked)(IndexMailbox *ibox,
			      MailExpungeFunc expunge_func, void *user_data);

	MailIndex *index;
	FlagsFile *flagsfile;
	ImapMessageCache *cache;
	unsigned int synced_messages_count;
};

IndexMailbox *index_storage_init(MailStorage *storage, Mailbox *box,
				 MailIndex *index, const char *name,
				 int readonly);
void index_storage_close(Mailbox *box);

int mail_storage_set_index_error(IndexMailbox *ibox);

int index_mailbox_fix_custom_flags(IndexMailbox *ibox, MailFlags *flags,
				   const char *custom_flags[]);

MailIndexRecord *index_expunge_seek_first(IndexMailbox *ibox,
					  unsigned int *seq);

int index_storage_save_into_fd(MailStorage *storage, int fd, const char *path,
			       IOBuffer *buf, size_t data_size);

/* Mailbox methods: */
int index_storage_copy(Mailbox *box, Mailbox *destbox,
		       const char *messageset, int uidset);
int index_storage_expunge(Mailbox *box);
int index_storage_get_status(Mailbox *box, MailboxStatusItems items,
			     MailboxStatus *status);
int index_storage_sync(Mailbox *box, unsigned int *messages, int expunge,
		       MailExpungeFunc expunge_func,
		       MailFlagUpdateFunc flag_func,
		       void *user_data);
int index_storage_update_flags(Mailbox *box, const char *messageset, int uidset,
			       MailFlags flags, const char *custom_flags[],
			       ModifyType modify_type,
			       MailFlagUpdateFunc func, void *user_data,
			       int *all_found);
int index_storage_fetch(Mailbox *box, MailFetchData *fetch_data,
			IOBuffer *outbuf, int *all_found);
int index_storage_search(Mailbox *box, MailSearchArg *args,
			 IOBuffer *outbuf, int uid_result);

#endif
