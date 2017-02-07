#ifndef QUOTA_PRIVATE_H
#define QUOTA_PRIVATE_H

#include "mail-storage-private.h"
#include "mail-namespace.h"
#include "quota.h"

/* Modules should use do "my_id = quota_module_id++" and
   use quota_module_contexts[id] for their own purposes. */
extern unsigned int quota_module_id;

struct quota {
	struct mail_user *user;
	struct quota_settings *set;

	ARRAY(struct quota_root *) roots;
	ARRAY(struct mail_namespace *) namespaces;
	struct mail_namespace *unwanted_ns;
};

struct quota_settings {
	pool_t pool;

	ARRAY(struct quota_root_settings *) root_sets;
	int (*test_alloc)(struct quota_transaction_context *ctx,
			  uoff_t size, bool *too_large_r);

	const char *quota_exceeded_msg;
	bool debug:1;
	bool initialized:1;
	bool vsizes:1;
};

struct quota_rule {
	const char *mailbox_mask;

	int64_t bytes_limit, count_limit;
	/* relative to default_rule */
	int bytes_percent, count_percent;

	/* Don't include this mailbox in quota */
	bool ignore:1;
};

struct quota_warning_rule {
	struct quota_rule rule;
	const char *command;
	bool reverse:1;
};

struct quota_backend_vfuncs {
	struct quota_root *(*alloc)(void);
	int (*init)(struct quota_root *root, const char *args,
		    const char **error_r);
	void (*deinit)(struct quota_root *root);

	bool (*parse_rule)(struct quota_root_settings *root_set,
			   struct quota_rule *rule,
			   const char *str, const char **error_r);
	int (*init_limits)(struct quota_root *root);

	/* called once for each namespace */
	void (*namespace_added)(struct quota *quota,
				struct mail_namespace *ns);

	const char *const *(*get_resources)(struct quota_root *root);
	int (*get_resource)(struct quota_root *root,
			    const char *name, uint64_t *value_r);

	int (*update)(struct quota_root *root, 
		      struct quota_transaction_context *ctx);
	bool (*match_box)(struct quota_root *root, struct mailbox *box);
	void (*flush)(struct quota_root *root);
};

struct quota_backend {
	/* quota backends equal if backend1.name == backend2.name */
	const char *name;
	struct quota_backend_vfuncs v;
};

struct quota_root_settings {
	/* Unique quota root name. */
	const char *name;
	/* Name in settings, e.g. "quota", "quota2", .. */
	const char *set_name;

	struct quota_settings *set;
	const char *args;

	const struct quota_backend *backend;
	struct quota_rule default_rule;
	ARRAY(struct quota_rule) rules;
	ARRAY(struct quota_warning_rule) warning_rules;
	const char *limit_set;

	/* If user is under quota before saving a mail, allow the last mail to
	   bring the user over quota by this many bytes. */
	uint64_t last_mail_max_extra_bytes;
	struct quota_rule grace_rule;

	/* Limits in default_rule override backend's quota limits */
	bool force_default_rule:1;
};

struct quota_root {
	pool_t pool;

	struct quota_root_settings *set;
	struct quota *quota;
	struct quota_backend backend;
	struct dict *limit_set_dict;

	/* this quota root applies only to this namespace. it may also be
	   a public namespace without an owner. */
	struct mail_namespace *ns;
	/* this is set in quota init(), because namespaces aren't known yet.
	   when accessing shared users the ns_prefix may be non-NULL but
	   ns=NULL, so when checking if quota root applies only to a specific
	   namespace use the ns_prefix!=NULL check. */
	const char *ns_prefix;

	/* initially the same as set->default_rule.*_limit, but some backends
	   may change these by reading the limits elsewhere (e.g. Maildir++,
	   FS quota) */
	int64_t bytes_limit, count_limit;
	/* 1 = quota root has resources and should be returned when iterating
	   quota roots, 0 = not, -1 = unknown. */
	int resource_ret;

	/* Module-specific contexts. See quota_module_id. */
	ARRAY(void) quota_module_contexts;

	/* Set to the current quota_over_flag, regardless of whether
	   it matches quota_over_flag_value mask. */
	const char *quota_over_flag;

	/* don't enforce quota when saving */
	bool no_enforcing:1;
	/* quota is automatically updated. update() should be called but the
	   bytes/count won't be used. */
	bool auto_updating:1;
	/* If user has unlimited quota, disable quota tracking */
	bool disable_unlimited_tracking:1;
	/* Set while quota is being recalculated to avoid recursion. */
	bool recounting:1;
	/* Quota root is hidden (to e.g. IMAP GETQUOTAROOT) */
	bool hidden:1;
	/* Is quota_over_flag* initialized yet? */
	bool quota_over_flag_initialized:1;
	/* Is user currently over quota? */
	bool quota_over_flag_status:1;
	/* Did we already check quota_over_flag correctness? */
	bool quota_over_flag_checked:1;
};

struct quota_transaction_context {
	union mailbox_transaction_module_context module_ctx;

	struct quota *quota;
	struct mailbox *box;

	int64_t bytes_used, count_used;
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

/* Register storage to all user's quota roots. */
void quota_add_user_namespace(struct quota *quota, struct mail_namespace *ns);
void quota_remove_user_namespace(struct mail_namespace *ns);

int quota_root_default_init(struct quota_root *root, const char *args,
			    const char **error_r);
struct quota *quota_get_mail_user_quota(struct mail_user *user);

bool quota_root_is_namespace_visible(struct quota_root *root,
				     struct mail_namespace *ns);
struct quota_rule *
quota_root_rule_find(struct quota_root_settings *root_set, const char *name);

void quota_root_recalculate_relative_rules(struct quota_root_settings *root_set,
					   int64_t bytes_limit,
					   int64_t count_limit);
/* Returns 1 if values were returned successfully, 0 if we're recursing into
   the same function, -1 if error. */
int quota_count(struct quota_root *root, uint64_t *bytes_r, uint64_t *count_r);

int quota_root_parse_grace(struct quota_root_settings *root_set,
			   const char *value, const char **error_r);
bool quota_warning_match(const struct quota_warning_rule *w,
			 uint64_t bytes_before, uint64_t bytes_current,
			 uint64_t count_before, uint64_t count_current,
			 const char **reason_r);
bool quota_transaction_is_over(struct quota_transaction_context *ctx, uoff_t size);
int quota_transaction_set_limits(struct quota_transaction_context *ctx);

#endif
