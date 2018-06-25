#ifndef IMAPC_STORAGE_H
#define IMAPC_STORAGE_H

#include "index-storage.h"
#include "imapc-settings.h"
#include "imapc-client.h"

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

	/* IMAPC_COMMAND_STATE_OK if no auth failure (yet), otherwise result to
	   the LOGIN/AUTHENTICATE command. */
	enum imapc_command_state auth_failed_state;
	char *auth_failed_reason;

	/* Authentication reply was received (success or failure) */
	bool auth_returned:1;
	bool destroying:1;
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

	bool namespaces_requested:1;
};

struct imapc_mail_cache {
	uint32_t uid;

	/* either fd != -1 or buf != NULL */
	int fd;
	buffer_t *buf;
};

struct imapc_fetch_request {
	ARRAY(struct imapc_mail *) mails;
};

struct imapc_mailbox {
	struct mailbox box;
	struct imapc_storage *storage;
	struct imapc_client_mailbox *client_box;
	enum imapc_capability capabilities;

	struct mail_index_transaction *delayed_sync_trans;
	struct mail_index_view *sync_view, *delayed_sync_view;
	struct mail_cache_view *delayed_sync_cache_view;
	struct mail_cache_transaction_ctx *delayed_sync_cache_trans;
	struct timeout *to_idle_check, *to_idle_delay;

	ARRAY(struct imapc_fetch_request *) fetch_requests;
	/* if non-empty, contains the latest FETCH command we're going to be
	   sending soon (but still waiting to see if we can increase its
	   UID range) */
	string_t *pending_fetch_cmd;
	struct imapc_fetch_request *pending_fetch_request;
	struct timeout *to_pending_fetch_send;

	ARRAY(struct imapc_mailbox_event_callback) untagged_callbacks;
	ARRAY(struct imapc_mailbox_event_callback) resp_text_callbacks;

	enum mail_flags permanent_flags;
	uint32_t highest_nonrecent_uid;

	ARRAY(uint64_t) rseq_modseqs;
	ARRAY_TYPE(seq_range) delayed_expunged_uids;
	uint32_t sync_uid_validity;
	uint32_t sync_uid_next;
	uint64_t sync_highestmodseq;
	uint32_t sync_fetch_first_uid;
	uint32_t sync_next_lseq;
	uint32_t sync_next_rseq;
	uint32_t exists_count;
	uint32_t min_append_uid;
	char *sync_gmail_pop3_search_tag;

	/* keep the previous fetched message body cached,
	   mainly for partial IMAP fetches */
	struct imapc_mail_cache prev_mail_cache;

	uint32_t prev_skipped_rseq, prev_skipped_uid;
	struct imapc_sync_context *sync_ctx;

	const char *guid_fetch_field_name;
	struct imapc_search_context *search_ctx;

	bool selecting:1;
	bool syncing:1;
	bool initial_sync_done:1;
	bool selected:1;
	bool exists_received:1;
	bool state_fetching_uid1:1;
	bool state_fetched_success:1;
};

struct imapc_simple_context {
	struct imapc_storage_client *client;
	int ret;
};

#define IMAPC_STORAGE(s)	container_of(s, struct imapc_storage, storage)
#define IMAPC_MAILBOX(s)	container_of(s, struct imapc_mailbox, box)

int imapc_storage_client_create(struct mail_namespace *ns,
				const struct imapc_settings *imapc_set,
				const struct mail_storage_settings *mail_set,
				struct imapc_storage_client **client_r,
				const char **error_r);
void imapc_storage_client_unref(struct imapc_storage_client **client);
bool imapc_storage_client_handle_auth_failure(struct imapc_storage_client *client);

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

void imapc_mailbox_run(struct imapc_mailbox *mbox);
void imapc_mailbox_run_nofetch(struct imapc_mailbox *mbox);
void imapc_mail_cache_free(struct imapc_mail_cache *cache);
int imapc_mailbox_select(struct imapc_mailbox *mbox);
void imap_mailbox_select_finish(struct imapc_mailbox *mbox);

bool imapc_mailbox_has_modseqs(struct imapc_mailbox *mbox);
bool imap_resp_text_code_parse(const char *str, enum mail_error *error_r);
void imapc_copy_error_from_reply(struct imapc_storage *storage,
				 enum mail_error default_error,
				 const struct imapc_command_reply *reply);
void imapc_simple_context_init(struct imapc_simple_context *sctx,
			       struct imapc_storage_client *client);
void imapc_simple_run(struct imapc_simple_context *sctx,
		      struct imapc_command **cmd);
void imapc_simple_callback(const struct imapc_command_reply *reply,
			   void *context);
int imapc_mailbox_commit_delayed_trans(struct imapc_mailbox *mbox,
				       bool force, bool *changes_r);
void imapc_mailbox_noop(struct imapc_mailbox *mbox);
void imapc_mailbox_set_corrupted(struct imapc_mailbox *mbox,
				 const char *reason, ...) ATTR_FORMAT(2, 3);
const char *imapc_mailbox_get_remote_name(struct imapc_mailbox *mbox);

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
