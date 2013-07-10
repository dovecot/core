#ifndef IMAPC_STORAGE_H
#define IMAPC_STORAGE_H

#include "index-storage.h"
#include "imapc-settings.h"

#define IMAPC_STORAGE_NAME "imapc"
#define IMAPC_LIST_ESCAPE_CHAR '%'
#define IMAPC_LIST_BROKEN_CHAR '~'

struct imap_arg;
struct imapc_untagged_reply;
struct imapc_command_reply;
struct imapc_mailbox;
struct imapc_storage_client;

typedef void imapc_storage_callback_t(const struct imapc_untagged_reply *reply,
				      struct imapc_storage_client *client);
typedef void imapc_mailbox_callback_t(const struct imapc_untagged_reply *reply,
				      struct imapc_mailbox *mbox);

struct imapc_storage_event_callback {
	char *name;
	imapc_storage_callback_t *callback;
};

struct imapc_mailbox_event_callback {
	const char *name;
	imapc_mailbox_callback_t *callback;
};

#define IMAPC_HAS_FEATURE(mstorage, feature) \
	(((mstorage)->set->parsed_features & feature) != 0)
#define IMAPC_BOX_HAS_FEATURE(mbox, feature) \
	(((mbox)->storage->set->parsed_features & feature) != 0)

struct imapc_namespace {
	const char *prefix;
	char separator;
	enum mail_namespace_type type;
};

struct imapc_storage_client {
	int refcount;

	/* either one of these may not be available: */
	struct imapc_storage *_storage;
	struct imapc_mailbox_list *_list;

	struct imapc_client *client;

	ARRAY(struct imapc_storage_event_callback) untagged_callbacks;
};

struct imapc_storage {
	struct mail_storage storage;
	const struct imapc_settings *set;

	struct ioloop *root_ioloop;
	struct imapc_storage_client *client;

	struct imapc_mailbox *cur_status_box;
	struct mailbox_status *cur_status;
	unsigned int reopen_count;

	ARRAY(struct imapc_namespace) remote_namespaces;

	unsigned int namespaces_requested:1;
};

struct imapc_mail_cache {
	uint32_t uid;

	/* either fd != -1 or buf != NULL */
	int fd;
	buffer_t *buf;
};

struct imapc_mailbox {
	struct mailbox box;
	struct imapc_storage *storage;
	struct imapc_client_mailbox *client_box;

	struct mail_index_transaction *delayed_sync_trans;
	struct mail_index_view *sync_view, *delayed_sync_view;
	struct timeout *to_idle_check, *to_idle_delay;

	ARRAY(struct imapc_mail *) fetch_mails;

	ARRAY(struct imapc_mailbox_event_callback) untagged_callbacks;
	ARRAY(struct imapc_mailbox_event_callback) resp_text_callbacks;

	enum mail_flags permanent_flags;

	ARRAY_TYPE(uint32_t) delayed_expunged_uids;
	uint32_t sync_uid_validity;
	uint32_t sync_uid_next;
	uint32_t sync_fetch_first_uid;
	uint32_t sync_next_lseq;
	uint32_t sync_next_rseq;
	uint32_t exists_count;
	uint32_t min_append_uid;

	/* keep the previous fetched message body cached,
	   mainly for partial IMAP fetches */
	struct imapc_mail_cache prev_mail_cache;

	uint32_t prev_skipped_rseq, prev_skipped_uid;
	struct imapc_sync_context *sync_ctx;

	const char *guid_fetch_field_name;

	unsigned int selecting:1;
	unsigned int syncing:1;
	unsigned int initial_sync_done:1;
	unsigned int selected:1;
	unsigned int exists_received:1;
};

struct imapc_simple_context {
	struct imapc_storage_client *client;
	int ret;
};

int imapc_storage_client_create(struct mail_namespace *ns,
				const struct imapc_settings *imapc_set,
				const struct mail_storage_settings *mail_set,
				struct imapc_storage_client **client_r,
				const char **error_r);
void imapc_storage_client_unref(struct imapc_storage_client **client);

struct mail_save_context *
imapc_save_alloc(struct mailbox_transaction_context *_t);
int imapc_save_begin(struct mail_save_context *ctx, struct istream *input);
int imapc_save_continue(struct mail_save_context *ctx);
int imapc_save_finish(struct mail_save_context *ctx);
void imapc_save_cancel(struct mail_save_context *ctx);
int imapc_copy(struct mail_save_context *ctx, struct mail *mail);

int imapc_transaction_save_commit_pre(struct mail_save_context *ctx);
void imapc_transaction_save_commit_post(struct mail_save_context *ctx,
					struct mail_index_transaction_commit_result *result);
void imapc_transaction_save_rollback(struct mail_save_context *ctx);

void imapc_storage_run(struct imapc_storage *storage);
void imapc_mail_cache_free(struct imapc_mail_cache *cache);
int imapc_mailbox_select(struct imapc_mailbox *mbox);

bool imap_resp_text_code_parse(const char *str, enum mail_error *error_r);
void imapc_copy_error_from_reply(struct imapc_storage *storage,
				 enum mail_error default_error,
				 const struct imapc_command_reply *reply);
void imapc_simple_context_init(struct imapc_simple_context *sctx,
			       struct imapc_storage_client *client);
void imapc_simple_run(struct imapc_simple_context *sctx);
void imapc_simple_callback(const struct imapc_command_reply *reply,
			   void *context);
int imapc_mailbox_commit_delayed_trans(struct imapc_mailbox *mbox,
				       bool *changes_r);
void imapc_mailbox_noop(struct imapc_mailbox *mbox);
void imapc_mailbox_set_corrupted(struct imapc_mailbox *mbox,
				 const char *reason, ...) ATTR_FORMAT(2, 3);

void imapc_storage_client_register_untagged(struct imapc_storage_client *client,
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
