#ifndef __MBOX_STORAGE_H
#define __MBOX_STORAGE_H

/* Padding to leave in X-Keywords header when rewriting mbox */
#define MBOX_HEADER_PADDING 50
/* Don't write Content-Length header unless it's value is larger than this. */
#define MBOX_MIN_CONTENT_LENGTH_SIZE 1024

#define SUBSCRIPTION_FILE_NAME ".subscriptions"
#define MBOX_INDEX_PREFIX "dovecot.index"

#include "index-storage.h"

struct mbox_transaction_context {
	struct index_transaction_context ictx;

	struct mbox_save_context *save_ctx;
	unsigned int mbox_lock_id;
	unsigned int mbox_modified:1;
};

extern struct mail mbox_mail;
extern const char *mbox_hide_headers[];
extern size_t mbox_hide_headers_count;

int mbox_set_syscall_error(struct index_mailbox *ibox, const char *function);

struct mailbox_list_context *
mbox_mailbox_list_init(struct mail_storage *storage,
		       const char *ref, const char *mask,
		       enum mailbox_list_flags flags);
int mbox_mailbox_list_deinit(struct mailbox_list_context *ctx);
struct mailbox_list *mbox_mailbox_list_next(struct mailbox_list_context *ctx);

struct mailbox_transaction_context *
mbox_transaction_begin(struct mailbox *box, int hide);
int mbox_transaction_commit(struct mailbox_transaction_context *t,
			    enum mailbox_sync_flags flags);
void mbox_transaction_rollback(struct mailbox_transaction_context *t);

struct mailbox_sync_context *
mbox_storage_sync_init(struct mailbox *box, enum mailbox_sync_flags flags);

struct mail_save_context *
mbox_save_init(struct mailbox_transaction_context *_t,
	       const struct mail_full_flags *flags,
	       time_t received_date, int timezone_offset,
	       const char *from_envelope, struct istream *input, int want_mail);
int mbox_save_continue(struct mail_save_context *ctx);
int mbox_save_finish(struct mail_save_context *ctx, struct mail **mail_r);
void mbox_save_cancel(struct mail_save_context *ctx);

int mbox_transaction_save_commit(struct mbox_save_context *ctx);
void mbox_transaction_save_rollback(struct mbox_save_context *ctx);

int mbox_is_valid_mask(const char *mask);

#endif
