#ifndef __INDEX_STORAGE_H
#define __INDEX_STORAGE_H

#include "mail-storage.h"
#include "mail-index.h"
#include "imap-message-cache.h"

typedef struct _IndexMailbox IndexMailbox;

struct _IndexMailbox {
	Mailbox box;

	/* expunge messages marked as deleted, requires index to be
	   exclusively locked */
	int (*expunge_locked)(IndexMailbox *ibox, int notify);

        MailboxSyncCallbacks sync_callbacks;
	void *sync_context;

	MailIndex *index;
	ImapMessageCache *cache;
	unsigned int synced_messages_count;

	unsigned int sent_diskspace_warning:1;
};

extern ImapMessageCacheIface index_msgcache_iface;

int mail_storage_set_index_error(IndexMailbox *ibox);

void index_storage_add(MailIndex *index);
MailIndex *index_storage_lookup_ref(const char *path);
void index_storage_unref(MailIndex *index);

IndexMailbox *index_storage_init(MailStorage *storage, Mailbox *box,
				 MailIndex *index, const char *name,
				 int readonly, int fast);
void index_storage_close(Mailbox *box);

int index_storage_sync_index_if_possible(IndexMailbox *ibox, int sync_size);
int index_storage_sync_modifylog(IndexMailbox *ibox);

int index_mailbox_fix_custom_flags(IndexMailbox *ibox, MailFlags *flags,
                                   const char *custom_flags[]);

unsigned int index_storage_get_recent_count(MailIndex *index);

int index_expunge_seek_first(IndexMailbox *ibox, unsigned int *seq,
			     MailIndexRecord **rec);
int index_expunge_mail(IndexMailbox *ibox, MailIndexRecord *rec,
		       unsigned int seq, int notify);

int index_storage_save_into_fd(MailStorage *storage, int fd, const char *path,
			       IBuffer *buf, uoff_t data_size);

void *index_msgcache_get_context(MailIndex *index, MailIndexRecord *rec);

/* Mailbox methods: */
void index_storage_set_sync_callbacks(Mailbox *box,
				      MailboxSyncCallbacks *callbacks,
				      void *context);
int index_storage_copy(Mailbox *box, Mailbox *destbox,
		       const char *messageset, int uidset);
int index_storage_expunge(Mailbox *box, int notify);
int index_storage_get_status(Mailbox *box, MailboxStatusItems items,
			     MailboxStatus *status);
int index_storage_sync(Mailbox *box, int sync_expunges);
int index_storage_update_flags(Mailbox *box, const char *messageset, int uidset,
			       MailFlags flags, const char *custom_flags[],
			       ModifyType modify_type, int notify,
			       int *all_found);
int index_storage_fetch(Mailbox *box, MailFetchData *fetch_data,
			OBuffer *outbuf, int *all_found);
int index_storage_search(Mailbox *box, MailSearchArg *args,
			 OBuffer *outbuf, int uid_result);

#endif
