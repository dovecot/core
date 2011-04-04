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

	ARRAY_DEFINE(roots, struct quota_root *);
	ARRAY_DEFINE(namespaces, struct mail_namespace *);
};

struct quota_settings {
	pool_t pool;

	ARRAY_DEFINE(root_sets, struct quota_root_settings *);
	int (*test_alloc)(struct quota_transaction_context *ctx,
			  uoff_t size, bool *too_large_r);

	const char *quota_exceeded_msg;
	unsigned int debug:1;
};

struct quota_rule {
	const char *mailbox_name;

	int64_t bytes_limit, count_limit;
	/* relative to default_rule */
	unsigned int bytes_percent, count_percent;

	/* Don't include this mailbox in quota */
	unsigned int ignore:1;
};

struct quota_warning_rule {
	struct quota_rule rule;
	const char *command;
	unsigned int reverse:1;
};

struct quota_backend_vfuncs {
	struct quota_root *(*alloc)(void);
	int (*init)(struct quota_root *root, const char *args);
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

};

struct quota_backend {
	/* quota backends equal if backend1.name == backend2.name */
	const char *name;
	struct quota_backend_vfuncs v;
};

struct quota_root_settings {
	/* Unique quota root name. */
	const char *name;

	struct quota_settings *set;
	const char *args;

	const struct quota_backend *backend;
	struct quota_rule default_rule;
	ARRAY_DEFINE(rules, struct quota_rule);
	ARRAY_DEFINE(warning_rules, struct quota_warning_rule);

	/* Limits in default_rule override backend's quota limits */
	unsigned int force_default_rule:1;
};

struct quota_root {
	pool_t pool;

	struct quota_root_settings *set;
	struct quota *quota;
	struct quota_backend backend;

	/* this quota root applies only to this namespace. it may also be
	   a public namespace without an owner. */
	struct mail_namespace *ns;
	/* this is set in quota init(), because namespaces aren't known yet */
	const char *ns_prefix;

	/* initially the same as set->default_rule.*_limit, but some backends
	   may change these by reading the limits elsewhere (e.g. Maildir++,
	   FS quota) */
	int64_t bytes_limit, count_limit;
	/* 1 = quota root has resources and should be returned when iterating
	   quota roots, 0 = not, -1 = unknown. */
	int resource_ret;

	/* Module-specific contexts. See quota_module_id. */
	ARRAY_DEFINE(quota_module_contexts, void);

	/* don't enforce quota when saving */
	unsigned int no_enforcing:1;
	/* If user has unlimited quota, disable quota tracking */
	unsigned int disable_unlimited_tracking:1;
	/* Set while quota is being recalculated to avoid recursion. */
	unsigned int recounting:1;
};

struct quota_transaction_context {
	union mailbox_transaction_module_context module_ctx;

	struct quota *quota;
	struct mailbox *box;

	int64_t bytes_used, count_used;
	/* how many bytes/mails can be saved until limit is reached.
	   (set once, not updated by bytes_used/count_used) */
	uint64_t bytes_ceil, count_ceil;

	struct mail *tmp_mail;

	unsigned int limits_set:1;
	unsigned int failed:1;
	unsigned int recalculate:1;
};

/* Register storage to all user's quota roots. */
void quota_add_user_namespace(struct quota *quota, struct mail_namespace *ns);
void quota_remove_user_namespace(struct mail_namespace *ns);

struct quota *quota_get_mail_user_quota(struct mail_user *user);

bool quota_root_is_namespace_visible(struct quota_root *root,
				     struct mail_namespace *ns);
struct quota_rule *
quota_root_rule_find(struct quota_root_settings *root_set, const char *name);

void quota_root_recalculate_relative_rules(struct quota_root_settings *root_set,
					   int64_t bytes_limit,
					   int64_t count_limit);
int quota_count(struct quota_root *root, uint64_t *bytes_r, uint64_t *count_r);

#endif
