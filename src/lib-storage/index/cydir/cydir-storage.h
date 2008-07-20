#ifndef CYDIR_STORAGE_H
#define CYDIR_STORAGE_H

#include "index-storage.h"
#include "mailbox-list-private.h"

#define CYDIR_STORAGE_NAME "cydir"
#define CYDIR_SUBSCRIPTION_FILE_NAME "subscriptions."
#define CYDIR_INDEX_PREFIX "dovecot.index"

struct cydir_storage {
	struct mail_storage storage;
	union mailbox_list_module_context list_module_ctx;
};

struct cydir_mailbox {
	struct index_mailbox ibox;
	struct cydir_storage *storage;

	const char *path;
};

struct cydir_transaction_context {
	struct index_transaction_context ictx;
	union mail_index_transaction_module_context module_ctx;

	uint32_t first_saved_mail_seq;
	struct cydir_save_context *save_ctx;
};

extern struct mail_vfuncs cydir_mail_vfuncs;

void cydir_transaction_class_init(void);
void cydir_transaction_class_deinit(void);

int cydir_save_init(struct mailbox_transaction_context *_t,
		    enum mail_flags flags, struct mail_keywords *keywords,
		    time_t received_date, int timezone_offset,
		    const char *from_envelope, struct istream *input,
		    struct mail **dest_mail, struct mail_save_context **ctx_r);
int cydir_save_continue(struct mail_save_context *ctx);
int cydir_save_finish(struct mail_save_context *ctx);
void cydir_save_cancel(struct mail_save_context *ctx);

int cydir_transaction_save_commit_pre(struct cydir_save_context *ctx);
void cydir_transaction_save_commit_post(struct cydir_save_context *ctx);
void cydir_transaction_save_rollback(struct cydir_save_context *ctx);

#endif
