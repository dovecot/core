#ifndef __MBOX_STORAGE_H
#define __MBOX_STORAGE_H

/* Extra space to leave in X-Keywords header when rewriting mbox */
#define MBOX_HEADER_EXTRA_SPACE 50

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
mbox_mailbox_list_init(struct mail_storage *storage, const char *mask,
		       enum mailbox_list_flags flags);
int mbox_mailbox_list_deinit(struct mailbox_list_context *ctx);
struct mailbox_list *mbox_mailbox_list_next(struct mailbox_list_context *ctx);

struct mailbox_transaction_context *
mbox_transaction_begin(struct mailbox *box, int hide);
int mbox_transaction_commit(struct mailbox_transaction_context *t);
void mbox_transaction_rollback(struct mailbox_transaction_context *t);

int mbox_storage_sync(struct mailbox *box, enum mailbox_sync_flags flags);

int mbox_save(struct mailbox_transaction_context *t,
	      const struct mail_full_flags *flags,
	      time_t received_date, int timezone_offset,
	      const char *from_envelope, struct istream *data,
	      struct mail **mail_r);
int mbox_save_commit(struct mbox_save_context *ctx);
void mbox_save_rollback(struct mbox_save_context *ctx);

const char *mbox_fix_mailbox_name(struct index_storage *istorage,
				  const char *name, int remove_namespace);
int mbox_is_valid_mask(const char *mask);

#endif
