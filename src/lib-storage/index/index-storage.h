#ifndef __INDEX_STORAGE_H
#define __INDEX_STORAGE_H

#include "mail-storage.h"
#include "mail-index.h"
#include "index-mail.h"

struct index_autosync_file {
	struct index_autosync_file *next;

	char *path;
	time_t last_stamp;
};

struct index_mailbox {
	struct mailbox box;

	/* expunge messages marked as deleted, requires index to be
	   exclusively locked */
	void (*mail_init)(struct index_mail *mail);

	struct mail_index *index;
        enum mailbox_lock_type lock_type;

	struct timeout *autosync_to;
        struct index_autosync_file *autosync_files;
	enum mailbox_sync_type autosync_type;
	time_t sync_last_check;
	unsigned int min_newmail_notify_interval;

	struct index_mail fetch_mail; /* fetch_uid() or fetch_seq() */
	unsigned int synced_messages_count;

	time_t next_lock_notify; /* temporary */
	enum mail_lock_notify_type last_notify_type;

	unsigned int readonly:1;
	unsigned int inconsistent:1;
	unsigned int sent_diskspace_warning:1;
	unsigned int sent_readonly_flags_warning:1;
};

int mail_storage_set_index_error(struct index_mailbox *ibox);
void index_storage_init_lock_notify(struct index_mailbox *ibox);
int index_storage_lock(struct index_mailbox *ibox,
		       enum mail_lock_type lock_type);

void index_storage_add(struct mail_index *index);
struct mail_index *index_storage_lookup_ref(const char *path);
void index_storage_unref(struct mail_index *index);
void index_storage_destroy_unrefed(void);

void index_storage_init(struct mail_storage *storage);
void index_storage_deinit(struct mail_storage *storage);

struct index_mailbox *
index_storage_mailbox_init(struct mail_storage *storage, struct mailbox *box,
			   struct mail_index *index, const char *name,
			   enum mailbox_open_flags flags);
int index_storage_mailbox_free(struct mailbox *box);

int index_storage_is_readonly(struct mailbox *box);
int index_storage_allow_new_custom_flags(struct mailbox *box);
int index_storage_is_inconsistency_error(struct mailbox *box);

int index_storage_sync_and_lock(struct index_mailbox *ibox,
				int sync_size, int minimal_sync,
				enum mail_lock_type data_lock_type);
int index_storage_sync_modifylog(struct index_mailbox *ibox, int hide_deleted);

int index_mailbox_fix_custom_flags(struct index_mailbox *ibox,
				   enum mail_flags *flags,
				   const char *custom_flags[],
				   unsigned int custom_flags_count);

unsigned int index_storage_get_recent_count(struct mail_index *index);

void index_mailbox_check_add(struct index_mailbox *ibox, const char *path);
void index_mailbox_check_remove_all(struct index_mailbox *ibox);

/* mailbox methods: */
void index_storage_set_callbacks(struct mail_storage *storage,
				 struct mail_storage_callbacks *callbacks,
				 void *context);
int index_storage_get_status(struct mailbox *box,
			     enum mailbox_status_items items,
			     struct mailbox_status *status);
int index_storage_sync(struct mailbox *box, enum mail_sync_flags flags);

struct mail_fetch_context *
index_storage_fetch_init(struct mailbox *box,
			 enum mail_fetch_field wanted_fields,
			 const char *messageset, int uidset);
int index_storage_fetch_deinit(struct mail_fetch_context *ctx, int *all_found);
struct mail *index_storage_fetch_next(struct mail_fetch_context *ctx);

struct mail *index_storage_fetch_uid(struct mailbox *box, unsigned int uid,
				     enum mail_fetch_field wanted_fields);
struct mail *index_storage_fetch_seq(struct mailbox *box, unsigned int seq,
				     enum mail_fetch_field wanted_fields);

int index_storage_search_get_sorting(struct mailbox *box,
				     enum mail_sort_type *sort_program);
struct mail_search_context *
index_storage_search_init(struct mailbox *box, const char *charset,
			  struct mail_search_arg *args,
			  const enum mail_sort_type *sort_program,
			  enum mail_fetch_field wanted_fields,
			  const char *const wanted_headers[]);
int index_storage_search_deinit(struct mail_search_context *ctx);
struct mail *index_storage_search_next(struct mail_search_context *ctx);

struct mail_copy_context *index_storage_copy_init(struct mailbox *box);
int index_storage_copy_deinit(struct mail_copy_context *ctx, int rollback);
int index_storage_copy(struct mail *mail, struct mail_copy_context *ctx);

int index_storage_update_flags(struct mail *mail,
			       const struct mail_full_flags *flags,
			       enum modify_type modify_type);

#endif
