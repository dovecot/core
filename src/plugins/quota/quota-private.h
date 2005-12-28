#ifndef __QUOTA_PRIVATE_H
#define __QUOTA_PRIVATE_H

#include "mail-storage-private.h"
#include "quota.h"

/* Modules should use do "my_id = quota_module_id++" and
   use quota_module_contexts[id] for their own purposes. */
extern unsigned int quota_module_id;

struct quota {
	const char *name;

	struct quota *(*init)(const char *data);
	void (*deinit)(struct quota *quota);

	struct quota_root_iter *
		(*root_iter_init)(struct quota *quota, struct mailbox *box);
	struct quota_root *(*root_iter_next)(struct quota_root_iter *iter);
	int (*root_iter_deinit)(struct quota_root_iter *iter);

	struct quota_root *(*root_lookup)(struct quota *quota,
					  const char *name);

	const char *(*root_get_name)(struct quota_root *root);
	const char *const *(*root_get_resources)(struct quota_root *root);

	int (*root_create)(struct quota *quota, const char *name,
			   struct quota_root **root_r);
	int (*get_resource)(struct quota_root *root, const char *name,
			    uint64_t *value_r, uint64_t *limit_r);
	int (*set_resource)(struct quota_root *root,
			    const char *name, uint64_t value);

	struct quota_transaction_context *
		(*transaction_begin)(struct quota *quota);
	int (*transaction_commit)(struct quota_transaction_context *ctx);
	void (*transaction_rollback)(struct quota_transaction_context *ctx);

	int (*try_alloc)(struct quota_transaction_context *ctx,
			 struct mail *mail, int *too_large_r);
	void (*alloc)(struct quota_transaction_context *ctx, struct mail *mail);
	void (*free)(struct quota_transaction_context *ctx, struct mail *mail);

	const char *(*last_error)(struct quota *quota);

	/* Module-specific contexts. See quota_module_id. */
	array_t ARRAY_DEFINE(quota_module_contexts, void);
};

struct quota_root {
	struct quota *quota;
};

struct quota_root_iter {
	struct quota *quota;
};

struct quota_transaction_context {
	struct quota *quota;

	int count_diff;
	int64_t bytes_diff;

	uint64_t storage_limit;
	uint64_t storage_current;
};

#endif
