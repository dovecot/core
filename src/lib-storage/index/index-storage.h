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

	char *check_path;
	Timeout check_to;
	time_t check_file_stamp;
	time_t last_check;

	unsigned int synced_messages_count;

	unsigned int sent_diskspace_warning:1;
	unsigned int delay_save_unlocking:1; /* For COPYing inside mailbox */
};

extern ImapMessageCacheIface index_msgcache_iface;

int mail_storage_set_index_error(IndexMailbox *ibox);

void index_storage_add(MailIndex *index);
MailIndex *index_storage_lookup_ref(const char *path);
void index_storage_unref(MailIndex *index);

IndexMailbox *index_storage_init(MailStorage *storage, Mailbox *box,
				 MailIndex *index, const char *name,
				 int readonly, int fast);
int index_storage_close(Mailbox *box);

int index_storage_sync_and_lock(IndexMailbox *ibox, int sync_size,
				MailLockType data_lock_type);
int index_storage_sync_modifylog(IndexMailbox *ibox, int hide_deleted);

int index_mailbox_fix_custom_flags(IndexMailbox *ibox, MailFlags *flags,
                                   const char *custom_flags[]);

unsigned int index_storage_get_recent_count(MailIndex *index);

int index_expunge_seek_first(IndexMailbox *ibox, unsigned int *seq,
			     MailIndexRecord **rec);
int index_expunge_mail(IndexMailbox *ibox, MailIndexRecord *rec,
		       unsigned int seq, int notify);

int index_storage_save(MailStorage *storage, const char *path,
		       IBuffer *inbuf, OBuffer *outbuf, uoff_t data_size);

int index_msgcache_open(ImapMessageCache *cache, MailIndex *index,
			MailIndexRecord *rec, ImapCacheField fields);

void index_mailbox_check_add(IndexMailbox *ibox, const char *path);
void index_mailbox_check_remove(IndexMailbox *ibox);

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
int index_storage_search(Mailbox *box, const char *charset, MailSearchArg *args,
			 OBuffer *outbuf, int uid_result);

#endif
