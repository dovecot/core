#ifndef __INDEX_STORAGE_H
#define __INDEX_STORAGE_H

#include "file-dotlock.h"
#include "mail-storage-private.h"
#include "mail-index.h"
#include "index-mail.h"

/* Max. mmap()ed size for a message */
#define MAIL_MMAP_BLOCK_SIZE (1024*256)
/* Block size when read()ing message. */
#define MAIL_READ_BLOCK_SIZE (1024*8)

#define MAILBOX_FULL_SYNC_INTERVAL 5

enum mailbox_lock_notify_type {
	MAILBOX_LOCK_NOTIFY_NONE,

	/* Mailbox is locked, will abort in secs_left */
	MAILBOX_LOCK_NOTIFY_MAILBOX_ABORT,
	/* Mailbox lock looks stale, will override in secs_left */
	MAILBOX_LOCK_NOTIFY_MAILBOX_OVERRIDE
};

struct index_autosync_file {
	struct index_autosync_file *next;

	char *path;
	time_t last_stamp;
};

struct index_autosync_io {
	struct index_autosync_io *next;
	struct io *io;
	int fd;
};

struct index_storage {
	struct mail_storage storage;

	char *dir; /* root directory */
	char *index_dir;
	char *control_dir;
	char *inbox_path; /* INBOX location */
        char *temp_prefix; /* prefix for temporary files */

	char *user; /* name of user accessing the storage */

	struct mail_storage_callbacks *callbacks;
	void *callback_context;
};

struct index_mailbox {
	struct mailbox box;
	struct index_storage *storage;
	char *path, *control_dir;

	struct mail_index *index;
	struct mail_index_view *view;
	struct mail_cache *cache;
	struct mail_cache_view *cache_view;
	struct mail *mail_interface;

	uint32_t (*get_recent_count)(struct index_mailbox *ibox);
	void (*mail_deinit)(struct index_mail *mail);
	unsigned int last_recent_count;

	struct timeout *autosync_to;
	struct index_autosync_file *autosync_files;
        struct index_autosync_io *autosync_ios;
	enum mailbox_sync_flags autosync_flags;
	time_t sync_last_check, sync_last_notify;
	unsigned int min_newmail_notify_interval;

	time_t next_lock_notify; /* temporary */
	enum mailbox_lock_notify_type last_notify_type;

	uint32_t commit_log_file_seq;
	uoff_t commit_log_file_offset;

	/* mbox: */
	int mbox_fd;
	struct istream *mbox_stream, *mbox_file_stream;
	int mbox_lock_type;
	dev_t mbox_dev;
	ino_t mbox_ino;
	unsigned int mbox_locks;
	struct dotlock mbox_dotlock;
	unsigned int mbox_lock_id, mbox_mail_lock_id;

	uint32_t mbox_extra_idx;

	/* maildir sync: */
	struct maildir_uidlist *uidlist;
	time_t last_new_mtime, last_cur_mtime, last_new_sync_time;
	time_t dirty_cur_time;

        mode_t mail_create_mode;
	unsigned int private_flags_mask;

	unsigned int readonly:1;
	unsigned int keep_recent:1;
	unsigned int sent_diskspace_warning:1;
	unsigned int sent_readonly_flags_warning:1;
	unsigned int autosync_pending:1;
	unsigned int mail_read_mmaped:1;
	unsigned int last_recent_count_initialized:1;
};

struct index_transaction_context {
	struct mailbox_transaction_context mailbox_ctx;
	struct index_mailbox *ibox;
	struct mail_index_transaction *trans;
	struct mail_cache_transaction_ctx *cache_trans;

	struct index_mail fetch_mail; /* for index_storage_fetch() */
};

int mail_storage_set_index_error(struct index_mailbox *ibox);

void index_storage_lock_notify(struct index_mailbox *ibox,
			       enum mailbox_lock_notify_type notify_type,
			       unsigned int secs_left);
void index_storage_lock_notify_reset(struct index_mailbox *ibox);

struct mail_index *
index_storage_alloc(const char *index_dir, const char *mailbox_path,
		    const char *prefix);
void index_storage_unref(struct mail_index *index);
void index_storage_destroy_unrefed(void);

void index_storage_init(struct index_storage *storage);
void index_storage_deinit(struct index_storage *storage);

struct index_mailbox *
index_storage_mailbox_init(struct index_storage *storage, struct mailbox *box,
			   struct mail_index *index, const char *name,
			   enum mailbox_open_flags flags);
void index_storage_mailbox_free(struct mailbox *box);

int index_storage_is_readonly(struct mailbox *box);
int index_storage_allow_new_keywords(struct mailbox *box);
int index_storage_is_inconsistent(struct mailbox *box);

int index_mailbox_fix_keywords(struct index_mailbox *ibox,
			       enum mail_flags *flags,
			       const char *keywords[],
			       unsigned int keywords_count);

unsigned int index_storage_get_recent_count(struct mail_index_view *view);

void index_mailbox_check_add(struct index_mailbox *ibox,
			     const char *path, int dir);
void index_mailbox_check_remove_all(struct index_mailbox *ibox);

int index_storage_sync(struct mailbox *box, enum mailbox_sync_flags flags);

/* mailbox methods: */
void index_storage_set_callbacks(struct mail_storage *storage,
				 struct mail_storage_callbacks *callbacks,
				 void *context);
int index_storage_get_status(struct mailbox *box,
			     enum mailbox_status_items items,
			     struct mailbox_status *status);

struct mail *
index_storage_fetch(struct mailbox_transaction_context *t, uint32_t seq,
		    enum mail_fetch_field wanted_fields);
int index_storage_get_uids(struct mailbox *box, uint32_t uid1, uint32_t uid2,
			   uint32_t *seq1_r, uint32_t *seq2_r);

int index_storage_search_get_sorting(struct mailbox *box,
				     enum mail_sort_type *sort_program);
struct mail_search_context *
index_storage_search_init(struct mailbox_transaction_context *t,
			  const char *charset, struct mail_search_arg *args,
			  const enum mail_sort_type *sort_program,
			  enum mail_fetch_field wanted_fields,
			  const char *const wanted_headers[]);
int index_storage_search_deinit(struct mail_search_context *ctx);
struct mail *index_storage_search_next(struct mail_search_context *ctx);

struct mailbox_transaction_context *
index_transaction_begin(struct mailbox *box);
int index_transaction_commit(struct mailbox_transaction_context *t);
void index_transaction_rollback(struct mailbox_transaction_context *t);

#endif
