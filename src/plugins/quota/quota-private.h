#ifndef QUOTA_PRIVATE_H
#define QUOTA_PRIVATE_H

#include "mail-storage-private.h"
#include "mail-namespace.h"
#include "quota.h"
#include "quota-settings.h"

/* Modules should use do "my_id = quota_module_id++" and
   use quota_module_contexts[id] for their own purposes. */
extern unsigned int quota_module_id;

struct quota {
	struct mail_user *user;
	struct event *event;

	/* Global quota roots. These are filled when initializing the user.
	   These quota roots will be used only for private namespaces. */
	ARRAY(struct quota_root *) global_private_roots;
	/* All seen quota roots, which may be specific to only some namespaces.
	   Quota roots are added lazily when a new quota_name is seen for a
	   namespace. It's assumed that the relevant quota backend settings
	   don't change for the same quota_name. */
	ARRAY(struct quota_root *) all_roots;

	enum quota_alloc_result (*test_alloc)(
		struct quota_transaction_context *ctx, uoff_t size,
		struct mailbox *expunged_box, uoff_t expunged_size,
		const struct quota_overrun **overruns_r, const char **error_r);

	bool vsizes:1;
};

struct quota_backend_vfuncs {
	struct quota_root *(*alloc)(void);
	int (*init)(struct quota_root *root, const char **error_r);
	void (*deinit)(struct quota_root *root);

	/* called once for each namespace */
	void (*namespace_added)(struct quota_root *root,
				struct mail_namespace *ns);

	const char *const *(*get_resources)(struct quota_root *root);
	/* Backends return success as QUOTA_GET_RESULT_LIMITED, and returning
	   QUOTA_GET_RESULT_UNLIMITED is prohibited by quota_get_resource(),
	   which is the only caller of this vfunc. */
	enum quota_get_result (*get_resource)(struct quota_root *root,
					      const char *name,
					      uint64_t *value_r,
					      const char **error_r);

	int (*update)(struct quota_root *root,
		      struct quota_transaction_context *ctx,
		      const char **error_r);
	bool (*match_box)(struct quota_root *root, struct mailbox *box);
	void (*flush)(struct quota_root *root);
};

struct quota_backend {
	/* quota backends equal if backend1.name == backend2.name */
	const char *name;
	struct event *event;
	bool use_vsize;
	struct quota_backend_vfuncs v;
};

struct quota_root {
	pool_t pool;

	const char *set_filter_name;
	const struct quota_root_settings *set;

	struct quota *quota;
	struct quota_backend backend;

	/* All namespaces using this quota root */
	ARRAY(struct mail_namespace *) namespaces;

	/* initially the same as set->quota_storage_size and
	   set->quota_message_count, but some backends may change these by
	   reading the limits elsewhere (e.g. imapc, FS quota) */
	int64_t bytes_limit, count_limit;

	/* Module-specific contexts. See quota_module_id. */
	ARRAY(void) quota_module_contexts;

	/* quota is automatically updated. update() should be called but the
	   bytes won't be changed. count is still changed, because it's cheap
	   to do and it's internally used to figure out whether there have
	   been some changes and that quota_warnings should be checked. */
	bool auto_updating:1;
	/* Set while quota is being recalculated to avoid recursion. */
	bool recounting:1;
	/* Did we already check quota_over_status correctness? */
	bool quota_over_status_checked:1;
	/* Are there any quota warnings with threshold=under? */
	bool have_under_warnings:1;
};

struct quota_transaction_root_context {
	/* how many bytes/mails can be saved until limit is reached.
	   (set once, not updated by bytes_used/count_used).

	   if last_mail_max_extra_bytes>0, the bytes_ceil is initially
	   increased by that much, while bytes_ceil2 contains the real ceiling.
	   after the first allocation is done, bytes_ceil is set to
	   bytes_ceil2. */
	uint64_t bytes_ceil, bytes_ceil2, count_ceil;
	/* How many bytes/mails we are over quota. Like *_ceil, these are set
	   only once and not updated by bytes_used/count_used. (Either *_ceil
	   or *_over is always zero.) */
	uint64_t bytes_over, count_over;

	/* Quota resource usage reduction performed in separate transactions.
	   Hence, these changes are already committed and must not be counted
	   a second time in this transaction. These values are used in the
	   limit calculations though, since the limits were recorded at the
	   start of the transaction and these reductions were performed some
	   time later. */
	uint64_t bytes_expunged, count_expunged;
};

struct quota_transaction_context {
	union mailbox_transaction_module_context module_ctx;

	struct quota *quota;
	struct mailbox *box;

	const struct quota_settings *set;

	struct quota_transaction_root_context *roots;

	/* Quota resource usage changes relative to the start of the
	   transaction. */
	int64_t bytes_used, count_used;
	/* Quota resource usage reduction performed in separate transactions.
	   Hence, these changes are already committed and must not be counted
	   a second time in this transaction. These values are used in the
	   limit calculations though, since the limits were recorded at the
	   start of the transaction and these reductions were performed some
	   time later. */
	uint64_t bytes_expunged, count_expunged;

	/* how many bytes/mails can be saved until limit is reached.
	   (set once, not updated by bytes_used/count_used).

	   if quota_storage_grace>0, the bytes_ceil is initially
	   increased by that much, while bytes_ceil2 contains the real ceiling.
	   after the first allocation is done, bytes_ceil is set to
	   bytes_ceil2. */
	uint64_t bytes_ceil, bytes_ceil2, count_ceil;
	/* How many bytes/mails we are over quota. Like *_ceil, these are set
	   only once and not updated by bytes_used/count_used. (Either *_ceil
	   or *_over is always zero.) */
	uint64_t bytes_over, count_over;

	struct mail *tmp_mail;
	enum quota_recalculate recalculate;

	bool limits_set:1;
	bool failed:1;
	bool sync_transaction:1;
	/* TRUE if all roots have auto_updating=TRUE */
	bool auto_updating:1;
	/* Quota doesn't need to be updated within this transaction. */
	bool no_quota_updates:1;
};

void quota_add_user_namespace(struct quota *quota, const char *root_name,
			      struct mail_namespace *ns);
void quota_remove_user_namespace(struct mail_namespace *ns);

struct quota *quota_get_mail_user_quota(struct mail_user *user);

bool quota_root_is_visible(struct quota_root *root, struct mailbox *box);

/* Returns 1 if values were returned successfully, 0 if we're recursing into
   the same function, -1 if error. */
int quota_count(struct quota_root *root, uint64_t *bytes_r, uint64_t *count_r,
		enum quota_get_result *error_result_r, const char **error_r);

bool quota_warning_match(const struct quota_root_settings *w,
			 uint64_t bytes_before, uint64_t bytes_current,
			 uint64_t count_before, uint64_t count_current,
			 const char **reason_r);

int quota_get_mail_size(struct quota_transaction_context *ctx,
			struct mail *mail, uoff_t *size_r);
void quota_used_apply_expunged(int64_t *used, uint64_t expunged);
bool quota_transaction_is_over(struct quota_transaction_context *ctx, uoff_t size);
bool quota_root_is_over(struct quota_transaction_context *ctx,
			struct quota_transaction_root_context *root,
			uoff_t count_alloc, uoff_t bytes_alloc,
			uoff_t count_expunged, uoff_t bytes_expunged,
			uoff_t *count_overrun_r, uoff_t *bytes_overrun_r);

void quota_transaction_root_expunged(
	struct quota_transaction_root_context *rctx,
	uint64_t count_expunged, uint64_t bytes_expunged);
void quota_transaction_update_expunged(struct quota_transaction_context *ctx);

int quota_transaction_set_limits(struct quota_transaction_context *ctx,
				 enum quota_get_result *error_result_r,
				 const char **error_r);

const struct quota_backend *quota_backend_find(const char *name);
void quota_backend_register(const struct quota_backend *backend);
void quota_backend_unregister(const struct quota_backend *backend);

#define QUOTA_UNKNOWN_RESOURCE_ERROR_STRING "Unknown quota resource"

#endif
