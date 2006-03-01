/* Copyright (C) 2005-2006 Timo Sirainen */

#include "lib.h"
#include "str.h"
#include "dict.h"
#include "quota-private.h"

#include <stdlib.h>

#define DICT_QUOTA_LIMIT_PATH DICT_PATH_PRIVATE"quota/limit/"
#define DICT_QUOTA_CURRENT_PATH DICT_PATH_PRIVATE"quota/current/"

struct dict_quota_root {
	struct quota_root root;
	struct dict *dict;
};

extern struct quota_backend quota_backend_dict;

static struct quota_root *
dict_quota_init(struct quota_setup *setup, const char *name)
{
	struct dict_quota_root *root;
	struct dict *dict;

	if (getenv("DEBUG") != NULL)
		i_info("dict quota uri = %s", setup->data);

	dict = dict_init(setup->data, getenv("USER"));
	if (dict == NULL)
		return NULL;

	root = i_new(struct dict_quota_root, 1);
	root->root.name = i_strdup(name);
	root->root.v = quota_backend_dict.v;
	root->dict = dict;

	return &root->root;
}

static void dict_quota_deinit(struct quota_root *_root)
{
	struct dict_quota_root *root = (struct dict_quota_root *)_root;

	i_free(root->root.name);
	i_free(root);
}

static bool
dict_quota_add_storage(struct quota_root *root __attr_unused__,
		       struct mail_storage *storage __attr_unused__)
{
	return TRUE;
}

static void
dict_quota_remove_storage(struct quota_root *root __attr_unused__,
			  struct mail_storage *storage __attr_unused__)
{
}

static const char *const *
dict_quota_root_get_resources(struct quota_root *root __attr_unused__)
{
	static const char *resources[] = { QUOTA_NAME_STORAGE, NULL };

	return resources;
}

static int
dict_quota_get_resource(struct quota_root *_root, const char *name,
			uint64_t *value_r, uint64_t *limit_r)
{
	struct dict_quota_root *root = (struct dict_quota_root *)_root;
	const char *value;
	int ret;

	if (root->dict == NULL)
		return 0;

	t_push();
	ret = dict_lookup(root->dict, unsafe_data_stack_pool,
			  t_strconcat(DICT_QUOTA_LIMIT_PATH, name, NULL),
			  &value);
	*limit_r = value == NULL ? 0 : strtoull(value, NULL, 10);

	if (value == NULL) {
		/* resource doesn't exist */
		*value_r = 0;
	} else {
		ret = dict_lookup(root->dict, unsafe_data_stack_pool,
				  t_strconcat(DICT_QUOTA_CURRENT_PATH,
					      name, NULL), &value);
		*value_r = value == NULL ? 0 : strtoull(value, NULL, 10);
	}
	t_pop();

	*limit_r /= 1024;
	*value_r /= 1024;

	return ret;
}

static int
dict_quota_set_resource(struct quota_root *root,
			const char *name __attr_unused__,
			uint64_t value __attr_unused__)
{
	quota_set_error(root->setup->quota, MAIL_STORAGE_ERR_NO_PERMISSION);
	return -1;
}

static struct quota_root_transaction_context *
dict_quota_transaction_begin(struct quota_root *_root,
			     struct quota_transaction_context *_ctx)
{
	struct dict_quota_root *root = (struct dict_quota_root *)_root;
	struct quota_root_transaction_context *ctx;
	const char *value;

	ctx = i_new(struct quota_root_transaction_context, 1);
	ctx->root = _root;
	ctx->ctx = _ctx;

	if (root->dict != NULL) {
		t_push();
		(void)dict_lookup(root->dict, unsafe_data_stack_pool,
				  DICT_QUOTA_LIMIT_PATH"storage", &value);
		ctx->storage_limit = value == NULL ? 0 :
			strtoull(value, NULL, 10);

		(void)dict_lookup(root->dict, unsafe_data_stack_pool,
				  DICT_QUOTA_CURRENT_PATH"storage", &value);
		ctx->storage_current = value == NULL ? 0 :
			strtoull(value, NULL, 10);
		t_pop();
	} else {
		ctx->storage_limit = (uint64_t)-1;
	}

	return ctx;
}

static int
dict_quota_transaction_commit(struct quota_root_transaction_context *ctx)
{
	struct dict_quota_root *root = (struct dict_quota_root *)ctx->root;

	if (root->dict != NULL) {
		struct dict_transaction_context *dt;

		dt = dict_transaction_begin(root->dict);
		dict_atomic_inc(dt, DICT_QUOTA_CURRENT_PATH"storage",
				ctx->bytes_diff);
		if (dict_transaction_commit(dt) < 0)
			i_error("dict_quota: Couldn't update quota");
	}

	i_free(ctx);
	return 0;
}

static void
dict_quota_transaction_rollback(struct quota_root_transaction_context *ctx)
{
	i_free(ctx);
}

static int
dict_quota_try_alloc_bytes(struct quota_root_transaction_context *ctx,
			   uoff_t size, bool *too_large_r)
{
	*too_large_r = size > ctx->storage_limit;

	if (ctx->storage_current + ctx->bytes_diff + size > ctx->storage_limit)
		return 0;

	ctx->bytes_diff += size;
	return 1;
}

static int
dict_quota_try_alloc(struct quota_root_transaction_context *ctx,
		     struct mail *mail, bool *too_large_r)
{
	uoff_t size;

	size = mail_get_physical_size(mail);
	if (size == (uoff_t)-1)
		return -1;

	return dict_quota_try_alloc_bytes(ctx, size, too_large_r);
}

static void
dict_quota_alloc(struct quota_root_transaction_context *ctx, struct mail *mail)
{
	uoff_t size;

	size = mail_get_physical_size(mail);
	if (size != (uoff_t)-1)
		ctx->bytes_diff += size;
}

static void
dict_quota_free(struct quota_root_transaction_context *ctx, struct mail *mail)
{
	uoff_t size;

	size = mail_get_physical_size(mail);
	if (size != (uoff_t)-1)
		ctx->bytes_diff -= size;
}

struct quota_backend quota_backend_dict = {
	"dict",

	{
		dict_quota_init,
		dict_quota_deinit,

		dict_quota_add_storage,
		dict_quota_remove_storage,

		dict_quota_root_get_resources,

		dict_quota_get_resource,
		dict_quota_set_resource,

		dict_quota_transaction_begin,
		dict_quota_transaction_commit,
		dict_quota_transaction_rollback,

		dict_quota_try_alloc,
		dict_quota_try_alloc_bytes,
		dict_quota_alloc,
		dict_quota_free
	}
};
