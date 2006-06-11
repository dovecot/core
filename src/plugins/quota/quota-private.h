#ifndef __QUOTA_PRIVATE_H
#define __QUOTA_PRIVATE_H

#include "mail-storage-private.h"
#include "quota.h"

/* Modules should use do "my_id = quota_module_id++" and
   use quota_module_contexts[id] for their own purposes. */
extern unsigned int quota_module_id;

struct quota {
	array_t ARRAY_DEFINE(setups, struct quota_setup *);
	char *last_error;
};

struct quota_setup {
	struct quota *quota;

	struct quota_backend *backend;
	char *data;

	/* List of quota roots. It's array because there shouldn't be many. */
	array_t ARRAY_DEFINE(roots, struct quota_root *);

	unsigned int user_root:1;
};

struct quota_backend_vfuncs {
	struct quota_root *(*init)(struct quota_setup *setup, const char *name);
	void (*deinit)(struct quota_root *root);

	bool (*add_storage)(struct quota_root *root,
			    struct mail_storage *storage);
	void (*remove_storage)(struct quota_root *root,
			       struct mail_storage *storage);

	const char *const *(*get_resources)(struct quota_root *root);
	int (*get_resource)(struct quota_root *root, const char *name,
			    uint64_t *value_r, uint64_t *limit_r);
	int (*set_resource)(struct quota_root *root,
			    const char *name, uint64_t value);

	struct quota_root_transaction_context *
		(*transaction_begin)(struct quota_root *root,
				     struct quota_transaction_context *ctx);
	int (*transaction_commit)(struct quota_root_transaction_context *ctx);
	void (*transaction_rollback)
		(struct quota_root_transaction_context *ctx);

	int (*try_alloc)(struct quota_root_transaction_context *ctx,
			 struct mail *mail, bool *too_large_r);
	int (*try_alloc_bytes)(struct quota_root_transaction_context *ctx,
			       uoff_t size, bool *too_large_r);
	int (*test_alloc_bytes)(struct quota_root_transaction_context *ctx,
				uoff_t size, bool *too_large_r);
	void (*alloc)(struct quota_root_transaction_context *ctx,
		      struct mail *mail);
	void (*free)(struct quota_root_transaction_context *ctx,
		     struct mail *mail);
};

struct quota_backend {
	const char *name;
	struct quota_backend_vfuncs v;
};

struct quota_root {
	struct quota_setup *setup;

	/* Unique quota root name. */
	char *name;

	struct quota_backend_vfuncs v;

	/* Mail storages using this quota root. */
	array_t ARRAY_DEFINE(storages, struct mail_storage *);
	/* Module-specific contexts. See quota_module_id. */
	array_t ARRAY_DEFINE(quota_module_contexts, void);

	unsigned int user_root:1;
};

struct quota_root_iter {
	struct quota_mail_storage *qstorage;
	unsigned int idx;
};

struct quota_transaction_context {
	struct quota *quota;

	array_t ARRAY_DEFINE(root_transactions,
			     struct quota_root_transaction_context *);
	struct mail *mail;
};

struct quota_root_transaction_context {
	struct quota_root *root;
	struct quota_transaction_context *ctx;

	int count_diff;
	int64_t bytes_diff;

	uint64_t bytes_limit, count_limit;
	uint64_t bytes_current, count_current;

	unsigned int disabled:1;
};

/* Register storage to all user's quota roots. */
void quota_add_user_storage(struct quota *quota, struct mail_storage *storage);

/* Likn root and storage together. Returns TRUE if successful, FALSE if it
   can't be done (eg. different filesystems with filesystem quota) */
bool quota_mail_storage_add_root(struct mail_storage *storage,
				 struct quota_root *root);
void quota_mail_storage_remove_root(struct mail_storage *storage,
				    struct quota_root *root);

void quota_set_error(struct quota *quota, const char *errormsg);

/* default simple implementations for bytes/count updating */
void
quota_default_transaction_rollback(struct quota_root_transaction_context *ctx);
int quota_default_try_alloc(struct quota_root_transaction_context *ctx,
			    struct mail *mail, bool *too_large_r);
int quota_default_try_alloc_bytes(struct quota_root_transaction_context *ctx,
				  uoff_t size, bool *too_large_r);
int quota_default_test_alloc_bytes(struct quota_root_transaction_context *ctx,
				   uoff_t size, bool *too_large_r);
void quota_default_alloc(struct quota_root_transaction_context *ctx,
			 struct mail *mail);
void quota_default_free(struct quota_root_transaction_context *ctx,
			struct mail *mail);

#endif
