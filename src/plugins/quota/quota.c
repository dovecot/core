/* Copyright (C) 2005 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "quota-private.h"
#include "quota-fs.h"

unsigned int quota_module_id = 0;

extern struct quota_backend quota_backend_dict;
extern struct quota_backend quota_backend_dirsize;
extern struct quota_backend quota_backend_fs;
extern struct quota_backend quota_backend_maildir;

static struct quota_backend *quota_backends[] = {
#ifdef HAVE_FS_QUOTA
	&quota_backend_fs,
#endif
	&quota_backend_dict,
	&quota_backend_dirsize,
	&quota_backend_maildir
};
#define QUOTA_CLASS_COUNT (sizeof(quota_backends)/sizeof(quota_backends[0]))

void (*hook_quota_root_created)(struct quota_root *root);

struct quota *quota_init(void)
{
	struct quota *quota;

	quota = i_new(struct quota, 1);
	ARRAY_CREATE(&quota->setups, default_pool, struct quota_setup *, 4);
	return quota;
}

void quota_deinit(struct quota *quota)
{
	while (array_count(&quota->setups) > 0) {
		struct quota_setup *const *setup;

		setup = array_idx(&quota->setups, 0);
		quota_setup_deinit(*setup);
	}

	array_free(&quota->setups);
	i_free(quota);
}

struct quota_setup *
quota_setup_init(struct quota *quota, const char *data, bool user_root)
{
	struct quota_setup *setup;
	const char *backend_name, *p;
	unsigned int i;

	setup = i_new(struct quota_setup, 1);
	setup->quota = quota;
	setup->data = i_strdup(data);
	setup->user_root = user_root;
	ARRAY_CREATE(&setup->roots, default_pool, struct quota_root *, 4);

	t_push();
	p = strchr(setup->data, ':');
	if (p == NULL) {
		backend_name = setup->data;
		data = "";
	} else {
		backend_name = t_strdup_until(setup->data, p);
		data = p+1;
	}
	for (i = 0; i < QUOTA_CLASS_COUNT; i++) {
		if (strcmp(quota_backends[i]->name, backend_name) == 0) {
			setup->backend = quota_backends[i];
			break;
		}
	}

	if (setup->backend == NULL)
		i_fatal("Unknown quota backend: %s", backend_name);

	t_pop();

	array_append(&quota->setups, &setup, 1);
	return setup;
}

void quota_setup_deinit(struct quota_setup *setup)
{
	struct quota_setup *const *setups;
	unsigned int i, count;

	setups = array_get(&setup->quota->setups, &count);
	for (i = 0; i < count; i++) {
		if (setups[i] == setup) {
			array_delete(&setup->quota->setups, i, 1);
			break;
		}
	}
	i_assert(i != count);

	while (array_count(&setup->roots) > 0) {
		struct quota_root *const *root;

		root = array_idx(&setup->roots, 0);
		quota_root_deinit(*root);
	}

	array_free(&setup->roots);
	i_free(setup->data);
	i_free(setup);
}

struct quota_root *
quota_root_init(struct quota_setup *setup, const char *name)
{
	struct quota_root *root;

	root = setup->backend->v.init(setup, name);
	root->setup = setup;
	ARRAY_CREATE(&root->storages, default_pool, struct mail_storage *, 8);
	array_create(&root->quota_module_contexts,
		     default_pool, sizeof(void *), 5);
	array_append(&setup->roots, &root, 1);

	if (hook_quota_root_created != NULL)
		hook_quota_root_created(root);
	return root;
}

void quota_root_deinit(struct quota_root *root)
{
	/* make a copy, since root is freed */
	struct array module_contexts = root->quota_module_contexts.arr;
	struct mail_storage *const *storage_p;
	struct quota_root *const *roots;
	unsigned int i, count;

	/* remove from all storages */
	while (array_count(&root->storages) > 0) {
		storage_p = array_idx(&root->storages, 0);
		quota_mail_storage_remove_root(*storage_p, root);
	}

	/* remove from setup */
	roots = array_get(&root->setup->roots, &count);
	for (i = 0; i < count; i++) {
		if (roots[i] == root) {
			array_delete(&root->setup->roots, i, 1);
			break;
		}
	}
	i_assert(i != count);

	array_free(&root->storages);
	root->v.deinit(root);
	_array_free(&module_contexts);
}

void quota_add_user_storage(struct quota *quota, struct mail_storage *storage)
{
	struct quota_setup *const *setups;
	struct quota_root *const *roots;
	unsigned int i, j, setup_count, root_count;
	bool found = FALSE;

	setups = array_get(&quota->setups, &setup_count);
	for (i = 0; i < setup_count; i++) {
		roots = array_get(&setups[i]->roots, &root_count);
		for (j = 0; j < root_count; j++) {
			if (!roots[j]->user_root)
				continue;

			if (quota_mail_storage_add_root(storage, roots[j]))
				found = TRUE;
		}
	}

	if (!found && setup_count > 0) {
		/* create a new quota root for the storage */
		struct quota_root *root;

		root = quota_root_init(setups[0], ""); // FIXME: name?
		found = quota_mail_storage_add_root(storage, root);
		i_assert(found);
	}
}

struct quota_root *quota_root_lookup(struct quota *quota, const char *name)
{
	struct quota_setup *const *setups;
	struct quota_root *const *roots;
	unsigned int i, j, setup_count, root_count;

	setups = array_get(&quota->setups, &setup_count);
	for (i = 0; i < setup_count; i++) {
		roots = array_get(&setups[i]->roots, &root_count);
		for (j = 0; j < root_count; j++) {
			if (strcmp(roots[j]->name, name) == 0)
				return roots[j];
		}
	}
	return NULL;
}

const char *quota_root_get_name(struct quota_root *root)
{
	return root->name;
}

const char *const *quota_root_get_resources(struct quota_root *root)
{
	return root->v.get_resources(root);
}

int quota_get_resource(struct quota_root *root, const char *name,
		       uint64_t *value_r, uint64_t *limit_r)
{
	return root->v.get_resource(root, name, value_r, limit_r);
}

int quota_set_resource(struct quota_root *root,
		       const char *name, uint64_t value)
{
	return root->v.set_resource(root, name, value);
}

struct quota_transaction_context *quota_transaction_begin(struct mailbox *box)
{
	struct quota_transaction_context *ctx;
	struct quota_root_transaction_context *root_ctx;
	struct quota_root_iter *iter;
	struct quota_root *root;

	ctx = i_new(struct quota_transaction_context, 1);
	ARRAY_CREATE(&ctx->root_transactions, default_pool,
		     struct quota_root_transaction_context *, 4);

	iter = quota_root_iter_init(box);
	while ((root = quota_root_iter_next(iter)) != NULL) {
		root_ctx = root->v.transaction_begin(root, ctx);
		array_append(&ctx->root_transactions, &root_ctx, 1);
	}
	quota_root_iter_deinit(iter);
	return ctx;
}

static void quota_transaction_free(struct quota_transaction_context *ctx)
{
	array_free(&ctx->root_transactions);
	i_free(ctx);
}

int quota_transaction_commit(struct quota_transaction_context *ctx)
{
	struct quota_root_transaction_context *const *root_transactions;
	unsigned int i, count;
	int ret = 0;

	root_transactions = array_get(&ctx->root_transactions, &count);
	for (i = 0; i < count; i++) {
		struct quota_root_transaction_context *t =
			root_transactions[i];

		if (t->root->v.transaction_commit(t) < 0)
			ret = -1;
	}

	quota_transaction_free(ctx);
	return ret;
}

void quota_transaction_rollback(struct quota_transaction_context *ctx)
{
	struct quota_root_transaction_context *const *root_transactions;
	unsigned int i, count;

	root_transactions = array_get(&ctx->root_transactions, &count);
	for (i = 0; i < count; i++) {
		struct quota_root_transaction_context *t =
			root_transactions[i];

		t->root->v.transaction_rollback(t);
	}

	quota_transaction_free(ctx);
}

int quota_try_alloc(struct quota_transaction_context *ctx,
		    struct mail *mail, bool *too_large_r)
{
	struct quota_root_transaction_context *const *root_transactions;
	unsigned int i, count;
	int ret = 1;

	root_transactions = array_get(&ctx->root_transactions, &count);
	for (i = 0; i < count; i++) {
		struct quota_root_transaction_context *t =
			root_transactions[i];

		ret = t->root->v.try_alloc(t, mail, too_large_r);
		if (ret <= 0)
			break;
	}
	return ret;
}

int quota_try_alloc_bytes(struct quota_transaction_context *ctx,
			  uoff_t size, bool *too_large_r)
{
	struct quota_root_transaction_context *const *root_transactions;
	unsigned int i, count;
	int ret = 1;

	root_transactions = array_get(&ctx->root_transactions, &count);
	for (i = 0; i < count; i++) {
		struct quota_root_transaction_context *t =
			root_transactions[i];

		ret = t->root->v.try_alloc_bytes(t, size, too_large_r);
		if (ret <= 0)
			break;
	}
	return ret;
}

int quota_test_alloc_bytes(struct quota_transaction_context *ctx,
			   uoff_t size, bool *too_large_r)
{
	struct quota_root_transaction_context *const *root_transactions;
	unsigned int i, count;
	int ret = 1;

	root_transactions = array_get(&ctx->root_transactions, &count);
	for (i = 0; i < count; i++) {
		struct quota_root_transaction_context *t =
			root_transactions[i];

		ret = t->root->v.test_alloc_bytes(t, size, too_large_r);
		if (ret <= 0)
			break;
	}
	return ret;
}

void quota_alloc(struct quota_transaction_context *ctx, struct mail *mail)
{
	struct quota_root_transaction_context *const *root_transactions;
	unsigned int i, count;

	root_transactions = array_get(&ctx->root_transactions, &count);
	for (i = 0; i < count; i++) {
		struct quota_root_transaction_context *t =
			root_transactions[i];

		t->root->v.alloc(t, mail);
	}
}

void quota_free(struct quota_transaction_context *ctx, struct mail *mail)
{
	struct quota_root_transaction_context *const *root_transactions;
	unsigned int i, count;

	root_transactions = array_get(&ctx->root_transactions, &count);
	for (i = 0; i < count; i++) {
		struct quota_root_transaction_context *t =
			root_transactions[i];

		t->root->v.free(t, mail);
	}
}

const char *quota_last_error(struct quota *quota)
{
	return quota->last_error != NULL ? quota->last_error : "Unknown error";
}

void quota_set_error(struct quota *quota, const char *errormsg)
{
	i_free(quota->last_error);
	quota->last_error = i_strdup(errormsg);
}

void
quota_default_transaction_rollback(struct quota_root_transaction_context *ctx)
{
	i_free(ctx);
}

int quota_default_try_alloc_bytes(struct quota_root_transaction_context *ctx,
				  uoff_t size, bool *too_large_r)
{
	int ret;

	ret = quota_default_test_alloc_bytes(ctx, size, too_large_r);
	if (ret <= 0 || ctx->disabled)
		return ret;

	ctx->count_diff++;
	ctx->bytes_diff += size;
	return 1;
}

int quota_default_test_alloc_bytes(struct quota_root_transaction_context *ctx,
				   uoff_t size, bool *too_large_r)
{
	if (ctx->disabled) {
		*too_large_r = FALSE;
		return 1;
	}
	if (ctx->bytes_current == (uint64_t)-1) {
		/* failure in transaction initialization */
		return -1;
	}

	*too_large_r = size > ctx->bytes_limit;

	if (ctx->bytes_current + ctx->bytes_diff + size > ctx->bytes_limit)
		return 0;
	if (ctx->count_current + ctx->count_diff + 1 > ctx->count_limit)
		return 0;
	return 1;
}

int quota_default_try_alloc(struct quota_root_transaction_context *ctx,
			    struct mail *mail, bool *too_large_r)
{
	uoff_t size;

	if (ctx->disabled)
		return 1;

	size = mail_get_physical_size(mail);
	if (size == (uoff_t)-1) {
		mail_storage_set_critical(mail->box->storage,
			"Quota: Couldn't get new message's size");
		return -1;
	}

	return quota_default_try_alloc_bytes(ctx, size, too_large_r);
}

void quota_default_alloc(struct quota_root_transaction_context *ctx,
			 struct mail *mail)
{
	uoff_t size;

	if (ctx->disabled)
		return;

	size = mail_get_physical_size(mail);
	if (size != (uoff_t)-1)
		ctx->bytes_diff += size;
	ctx->count_diff++;
}

void quota_default_free(struct quota_root_transaction_context *ctx,
			struct mail *mail)
{
	uoff_t size;

	if (ctx->disabled)
		return;

	size = mail_get_physical_size(mail);
	if (size != (uoff_t)-1)
		ctx->bytes_diff -= size;
	ctx->count_diff--;
}
