#ifndef MBOX_STORAGE_H
#define MBOX_STORAGE_H

#include "index-storage.h"
#include "mbox-settings.h"

/* Padding to leave in X-Keywords header when rewriting mbox */
#define MBOX_HEADER_PADDING 50
/* Don't write Content-Length header unless it's value is larger than this. */
#define MBOX_MIN_CONTENT_LENGTH_SIZE 1024

#define MBOX_STORAGE_NAME "mbox"
#define MBOX_SUBSCRIPTION_FILE_NAME ".subscriptions"
#define MBOX_INDEX_PREFIX "dovecot.index"
#define MBOX_INDEX_DIR_NAME ".imap"

struct mbox_index_header {
	uint64_t sync_size;
	uint32_t sync_mtime;
	uint8_t dirty_flag;
	uint8_t unused[3];
	uint8_t mailbox_guid[MAIL_GUID_128_SIZE];
};
struct mbox_storage {
	struct mail_storage storage;

	const struct mbox_settings *set;
	enum mbox_lock_type *read_locks;
	enum mbox_lock_type *write_locks;
	unsigned int lock_settings_initialized:1;
};

struct mbox_mailbox {
	struct mailbox box;
	struct mbox_storage *storage;

	int mbox_fd;
	struct istream *mbox_stream, *mbox_file_stream;
	int mbox_lock_type;
	dev_t mbox_dev;
	ino_t mbox_ino;
	unsigned int mbox_excl_locks, mbox_shared_locks;
	struct dotlock *mbox_dotlock;
	unsigned int mbox_lock_id, mbox_global_lock_id;
	struct timeout *keep_lock_to;
	bool mbox_writeonly;

	uint32_t mbox_ext_idx, md5hdr_ext_idx;
	struct mbox_index_header mbox_hdr;
	const struct mailbox_update *sync_hdr_update;

	unsigned int no_mbox_file:1;
	unsigned int invalid_mbox_file:1;
	unsigned int mbox_broken_offsets:1;
	unsigned int mbox_save_md5:1;
	unsigned int mbox_dotlocked:1;
	unsigned int mbox_used_privileges:1;
	unsigned int mbox_privileged_locking:1;
	unsigned int syncing:1;
};

struct mbox_transaction_context {
	struct index_transaction_context ictx;
	unsigned int mbox_lock_id;
};

extern struct mail_vfuncs mbox_mail_vfuncs;
extern const char *mbox_hide_headers[], *mbox_save_drop_headers[];
extern unsigned int mbox_hide_headers_count, mbox_save_drop_headers_count;

int mbox_set_syscall_error(struct mbox_mailbox *mbox, const char *function);

struct mailbox_sync_context *
mbox_storage_sync_init(struct mailbox *box, enum mailbox_sync_flags flags);

struct mail_save_context *
mbox_save_alloc(struct mailbox_transaction_context *_t);
int mbox_save_begin(struct mail_save_context *ctx, struct istream *input);
int mbox_save_continue(struct mail_save_context *ctx);
int mbox_save_finish(struct mail_save_context *ctx);
void mbox_save_cancel(struct mail_save_context *ctx);

int mbox_transaction_save_commit_pre(struct mail_save_context *ctx);
void mbox_transaction_save_commit_post(struct mail_save_context *ctx,
				       struct mail_index_transaction_commit_result *result);
void mbox_transaction_save_rollback(struct mail_save_context *ctx);

#endif
