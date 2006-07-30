#ifndef __QUOTA_PRIVATE_H
#define __QUOTA_PRIVATE_H

#include "mail-storage-private.h"
#include "quota.h"

/* Modules should use do "my_id = quota_module_id++" and
   use quota_module_contexts[id] for their own purposes. */
extern unsigned int quota_module_id;

struct quota {
	ARRAY_DEFINE(roots, struct quota_root *);
	ARRAY_DEFINE(storages, struct mail_storage *);
};

struct quota_backend_vfuncs {
	struct quota_root *(*alloc)(void);
	int (*init)(struct quota_root *root, const char *args);
	void (*deinit)(struct quota_root *root);

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
	const char *name;
	struct quota_backend_vfuncs v;
};

struct quota_rule {
	char *mailbox_name;

	int64_t bytes_limit, count_limit;
};

struct quota_root {
	pool_t pool;

	/* Unique quota root name. */
	char *name;

	/* pointer to the quota that owns this root */
	struct quota *quota;

	struct quota_backend *backend;
	struct quota_rule default_rule;
	ARRAY_DEFINE(rules, struct quota_rule);

	/* Module-specific contexts. See quota_module_id. */
	ARRAY_DEFINE(quota_module_contexts, void);
};

struct quota_transaction_context {
	struct quota *quota;
	struct mailbox *box;

	int64_t bytes_used, count_used;
	uint64_t bytes_left, count_left;

	struct mail *tmp_mail;

	unsigned int failed:1;
};

/* Register storage to all user's quota roots. */
void quota_add_user_storage(struct quota *quota, struct mail_storage *storage);
void quota_remove_user_storage(struct quota *quota, 
			       struct mail_storage *storage);

void quota_set_error(struct quota *quota, const char *errormsg);

#endif
