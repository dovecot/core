#ifndef IMAPC_STORAGE_H
#define IMAPC_STORAGE_H

#include "index-storage.h"

#define IMAPC_STORAGE_NAME "imapc"

struct imap_arg;
struct imapc_untagged_reply;
struct imapc_command_reply;
struct imapc_mailbox;
struct imapc_storage;

typedef void imapc_storage_callback_t(const struct imapc_untagged_reply *reply,
				      struct imapc_storage *storage);
typedef void imapc_mailbox_callback_t(const struct imapc_untagged_reply *reply,
				      struct imapc_mailbox *mbox);

struct imapc_storage_event_callback {
	const char *name;
	imapc_storage_callback_t *callback;
};

struct imapc_mailbox_event_callback {
	const char *name;
	imapc_mailbox_callback_t *callback;
};

struct imapc_storage {
	struct mail_storage storage;
	struct imapc_mailbox_list *list;
	struct imapc_client *client;

	struct imapc_mailbox *cur_status_box;
	struct mailbox_status *cur_status;

	ARRAY_DEFINE(untagged_callbacks, struct imapc_storage_event_callback);
};

struct imapc_mailbox {
	struct mailbox box;
	struct imapc_storage *storage;
	struct imapc_client_mailbox *client_box;

	struct mail_index_transaction *delayed_sync_trans;
	struct mail_index_view *delayed_sync_view;
	struct timeout *to_idle;

	struct mail *cur_fetch_mail;

	ARRAY_DEFINE(untagged_callbacks, struct imapc_mailbox_event_callback);
	ARRAY_DEFINE(resp_text_callbacks, struct imapc_mailbox_event_callback);

	unsigned int new_msgs:1;
};

struct imapc_simple_context {
	struct imapc_storage *storage;
	int ret;
};

extern struct mail_vfuncs imapc_mail_vfuncs;

struct mail_save_context *
imapc_save_alloc(struct mailbox_transaction_context *_t);
int imapc_save_begin(struct mail_save_context *ctx, struct istream *input);
int imapc_save_continue(struct mail_save_context *ctx);
int imapc_save_finish(struct mail_save_context *ctx);
void imapc_save_cancel(struct mail_save_context *ctx);

int imapc_transaction_save_commit_pre(struct mail_save_context *ctx);
void imapc_transaction_save_commit_post(struct mail_save_context *ctx,
					struct mail_index_transaction_commit_result *result);
void imapc_transaction_save_rollback(struct mail_save_context *ctx);

void imapc_mail_fetch(struct mail *mail);
struct mail_search_context *
imapc_search_init(struct mailbox_transaction_context *t,
		  struct mail_search_args *args,
		  const enum mail_sort_type *sort_program);
bool imapc_search_next_nonblock(struct mail_search_context *_ctx,
				struct mail *mail, bool *tryagain_r);
void imapc_fetch_mail_update(struct mail *mail, const struct imap_arg *args);

void imapc_simple_callback(const struct imapc_command_reply *reply,
			   void *context);
void imapc_async_stop_callback(const struct imapc_command_reply *reply,
			       void *context);

void imapc_storage_register_untagged(struct imapc_storage *storage,
				     const char *name,
				     imapc_storage_callback_t *callback);
void imapc_mailbox_register_untagged(struct imapc_mailbox *mbox,
				     const char *name,
				     imapc_mailbox_callback_t *callback);
void imapc_mailbox_register_resp_text(struct imapc_mailbox *mbox,
				      const char *key,
				      imapc_mailbox_callback_t *callback);

void imapc_mailbox_register_callbacks(struct imapc_mailbox *mbox);

#endif
