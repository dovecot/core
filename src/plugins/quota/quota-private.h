#ifndef QUOTA_PRIVATE_H
#define QUOTA_PRIVATE_H

#include "mail-storage-private.h"
#include "quota.h"

/* Modules should use do "my_id = quota_module_id++" and
   use quota_module_contexts[id] for their own purposes. */
extern unsigned int quota_module_id;

struct quota {
	ARRAY_DEFINE(roots, struct quota_root *);
	ARRAY_DEFINE(storages, struct mail_storage *);

	int (*test_alloc)(struct quota_transaction_context *ctx,
			  uoff_t size, bool *too_large_r);

	unsigned int debug:1;
};

struct quota_rule {
	char *mailbox_name;

	int64_t bytes_limit, count_limit;
};

struct quota_warning_rule {
	uint64_t bytes_limit;
	uint64_t count_limit;

	char *command;
};

struct quota_backend_vfuncs {
	struct quota_root *(*alloc)(void);
	int (*init)(struct quota_root *root, const char *args);
	void (*deinit)(struct quota_root *root);

	bool (*parse_rule)(struct quota_root *root, struct quota_rule *rule,
			   const char *str, const char **error_r);

	/* called once for each backend */
	void (*storage_added)(struct quota *quota,
			      struct mail_storage *storage);

	const char *const *(*get_resources)(struct quota_root *root);
	/* the limit is set by default, so it shouldn't normally need to
	   be changed. */
	int (*get_resource)(struct quota_root *root, const char *name,
			    uint64_t *value_r, uint64_t *limit);

	int (*update)(struct quota_root *root, 
		      struct quota_transaction_context *ctx);
};

struct quota_backend {
	/* quota backends equal if backend1.name == backend2.name */
	const char *name;
	struct quota_backend_vfuncs v;
};

struct quota_root {
	pool_t pool;

	/* Unique quota root name. */
	const char *name;

	/* pointer to the quota that owns this root */
	struct quota *quota;

	struct quota_backend backend;
	struct quota_rule default_rule;
	ARRAY_DEFINE(rules, struct quota_rule);
	ARRAY_DEFINE(warning_rules, struct quota_warning_rule);

	/* Module-specific contexts. See quota_module_id. */
	ARRAY_DEFINE(quota_module_contexts, void);

	/* don't enforce quota when saving */
	unsigned int no_enforcing:1;
};

struct quota_transaction_context {
	union mailbox_transaction_module_context module_ctx;

	struct quota *quota;
	struct mailbox *box;

	int64_t bytes_used, count_used;
	uint64_t bytes_left, count_left;

	struct mail *tmp_mail;

	unsigned int limits_set:1;
	unsigned int failed:1;
	unsigned int recalculate:1;
};

/* Register storage to all user's quota roots. */
void quota_add_user_storage(struct quota *quota, struct mail_storage *storage);
void quota_remove_user_storage(struct quota *quota, 
			       struct mail_storage *storage);

int quota_count(struct quota *quota, uint64_t *bytes_r, uint64_t *count_r);

#endif
