#ifndef __INDEX_STORAGE_H
#define __INDEX_STORAGE_H

#include "mail-storage.h"
#include "mail-index.h"
#include "imap-message-cache.h"

struct index_mailbox {
	struct mailbox box;

	/* expunge messages marked as deleted, requires index to be
	   exclusively locked */
	int (*expunge_locked)(struct index_mailbox *ibox, int notify);

	struct mail_index *index;
	struct imap_message_cache *cache;

	char *check_path;
	struct timeout *check_to;
	time_t check_file_stamp;
	time_t last_check;

	unsigned int synced_messages_count;

	time_t next_lock_notify; /* temporary */

	unsigned int sent_diskspace_warning:1;
	unsigned int delay_save_unlocking:1; /* For COPYing inside mailbox */
};

extern struct imap_message_cache_iface index_msgcache_iface;

int mail_storage_set_index_error(struct index_mailbox *ibox);
void index_storage_init_lock_notify(struct index_mailbox *ibox);
int index_storage_lock(struct index_mailbox *ibox,
		       enum mail_lock_type lock_type);

void index_storage_add(struct mail_index *index);
struct mail_index *index_storage_lookup_ref(const char *path);
void index_storage_unref(struct mail_index *index);

struct index_mailbox *
index_storage_init(struct mail_storage *storage, struct mailbox *box,
		   struct mail_index *index, const char *name,
		   int readonly, int fast);
int index_storage_close(struct mailbox *box);

int index_storage_sync_and_lock(struct index_mailbox *ibox, int sync_size,
				enum mail_lock_type data_lock_type);
int index_storage_sync_modifylog(struct index_mailbox *ibox, int hide_deleted);

int index_mailbox_fix_custom_flags(struct index_mailbox *ibox,
				   enum mail_flags *flags,
                                   const char *custom_flags[]);

unsigned int index_storage_get_recent_count(struct mail_index *index);

int index_expunge_seek_first(struct index_mailbox *ibox, unsigned int *seq,
			     struct mail_index_record **rec);
int index_expunge_mail(struct index_mailbox *ibox,
		       struct mail_index_record *rec,
		       unsigned int seq, int notify);

int index_storage_save(struct mail_storage *storage, const char *path,
		       struct istream *input, struct ostream *output,
		       uoff_t data_size);

int index_msgcache_open(struct imap_message_cache *cache,
			struct mail_index *index, struct mail_index_record *rec,
			enum imap_cache_field fields);

void index_mailbox_check_add(struct index_mailbox *ibox, const char *path);
void index_mailbox_check_remove(struct index_mailbox *ibox);

/* mailbox methods: */
void index_storage_set_callbacks(struct mail_storage *storage,
				 struct mail_storage_callbacks *callbacks,
				 void *context);
int index_storage_copy(struct mailbox *box, struct mailbox *destbox,
		       const char *messageset, int uidset);
int index_storage_expunge(struct mailbox *box, int notify);
int index_storage_get_status(struct mailbox *box,
			     enum mailbox_status_items items,
			     struct mailbox_status *status);
int index_storage_sync(struct mailbox *box, int sync_expunges);
int index_storage_update_flags(struct mailbox *box, const char *messageset,
			       int uidset, enum mail_flags flags,
			       const char *custom_flags[],
			       enum modify_type modify_type, int notify,
			       int *all_found);
int index_storage_fetch(struct mailbox *box, struct mail_fetch_data *fetch_data,
			struct ostream *output, int *all_found);
int index_storage_search(struct mailbox *box, const char *charset,
			 struct mail_search_arg *args,
			 enum mail_sort_type *sorting,
                         enum mail_thread_type threading,
			 struct ostream *output, int uid_result);

#endif
