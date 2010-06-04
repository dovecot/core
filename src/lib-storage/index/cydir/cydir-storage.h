#ifndef CYDIR_STORAGE_H
#define CYDIR_STORAGE_H

#include "index-storage.h"

#define CYDIR_STORAGE_NAME "cydir"
#define CYDIR_SUBSCRIPTION_FILE_NAME "subscriptions."
#define CYDIR_INDEX_PREFIX "dovecot.index"

struct cydir_storage {
	struct mail_storage storage;
};

struct cydir_mailbox {
	struct mailbox box;
	struct cydir_storage *storage;
};

extern struct mail_vfuncs cydir_mail_vfuncs;

struct mail_save_context *
cydir_save_alloc(struct mailbox_transaction_context *_t);
int cydir_save_begin(struct mail_save_context *ctx, struct istream *input);
int cydir_save_continue(struct mail_save_context *ctx);
int cydir_save_finish(struct mail_save_context *ctx);
void cydir_save_cancel(struct mail_save_context *ctx);

int cydir_transaction_save_commit_pre(struct mail_save_context *ctx);
void cydir_transaction_save_commit_post(struct mail_save_context *ctx,
					struct mail_index_transaction_commit_result *result);
void cydir_transaction_save_rollback(struct mail_save_context *ctx);

#endif
