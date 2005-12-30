/* Copyright (C) 2005 Timo Sirainen */

#include "lib.h"
#include "str.h"
#include "dict.h"
#include "quota-private.h"

#include <stdlib.h>

#define DICT_QUOTA_LIMIT_PATH DICT_PATH_PRIVATE"quota/limit/"
#define DICT_QUOTA_CURRENT_PATH DICT_PATH_PRIVATE"quota/current/"

struct dict_quota {
	struct quota quota;

	pool_t pool;
	const char *error;
	struct quota_root root;

	struct dict *dict;
};

struct dict_quota_root_iter {
	struct quota_root_iter iter;

	int sent;
};

extern struct quota dict_quota;

static struct quota *dict_quota_init(const char *data)
{
	struct dict_quota *quota;
	struct dict *dict;
	pool_t pool;

	if (getenv("DEBUG") != NULL)
		i_info("dict quota uri = %s", data);

	dict = dict_init(data);
	if (dict == NULL)
		return NULL;

	pool = pool_alloconly_create("quota", 1024);
	quota = p_new(pool, struct dict_quota, 1);
	quota->pool = pool;
	quota->quota = dict_quota;
	quota->dict = dict;

	quota->root.quota = &quota->quota;
	return &quota->quota;
}

static void dict_quota_deinit(struct quota *_quota)
{
	struct dict_quota *quota = (struct dict_quota *)_quota;

	pool_unref(quota->pool);
}

static struct quota_root_iter *
dict_quota_root_iter_init(struct quota *quota,
			  struct mailbox *box __attr_unused__)
{
	struct dict_quota_root_iter *iter;

	iter = i_new(struct dict_quota_root_iter, 1);
	iter->iter.quota = quota;
	return &iter->iter;
}

static struct quota_root *
dict_quota_root_iter_next(struct quota_root_iter *_iter)
{
	struct dict_quota_root_iter *iter =
		(struct dict_quota_root_iter *)_iter;
	struct dict_quota *quota = (struct dict_quota *)_iter->quota;

	if (iter->sent)
		return NULL;

	iter->sent = TRUE;
	return &quota->root;
}

static int dict_quota_root_iter_deinit(struct quota_root_iter *iter)
{
	i_free(iter);
	return 0;
}

static struct quota_root *
dict_quota_root_lookup(struct quota *_quota, const char *name)
{
	struct dict_quota *quota = (struct dict_quota *)_quota;

	if (*name == '\0')
		return &quota->root;
	else
		return NULL;
}

static const char *
dict_quota_root_get_name(struct quota_root *root __attr_unused__)
{
	return "";
}

static const char *const *
dict_quota_root_get_resources(struct quota_root *root __attr_unused__)
{
	static const char *resources[] = { QUOTA_NAME_STORAGE, NULL };

	return resources;
}

static int
dict_quota_root_create(struct quota *_quota,
		       const char *name __attr_unused__,
		       struct quota_root **root_r __attr_unused__)
{
	struct dict_quota *quota = (struct dict_quota *)_quota;

        quota->error = "Permission denied";
	return -1;
}

static int
dict_quota_get_resource(struct quota_root *root, const char *name,
			uint64_t *value_r, uint64_t *limit_r)
{
	struct dict_quota *quota = (struct dict_quota *)root->quota;
	const char *value;
	int ret;

	if (quota->dict == NULL)
		return 0;

	t_push();
	ret = dict_lookup(quota->dict, unsafe_data_stack_pool,
			  t_strconcat(DICT_QUOTA_LIMIT_PATH, name, NULL),
			  &value);
	*limit_r = value == NULL ? 0 : strtoull(value, NULL, 10);

	if (value == NULL) {
		/* resource doesn't exist */
		*value_r = 0;
	} else {
		ret = dict_lookup(quota->dict, unsafe_data_stack_pool,
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
	struct dict_quota *quota = (struct dict_quota *)root->quota;

	quota->error = "Permission denied";
	return -1;
}

static struct quota_transaction_context *
dict_quota_transaction_begin(struct quota *_quota)
{
	struct dict_quota *quota = (struct dict_quota *)_quota;
	struct quota_transaction_context *ctx;
	const char *value;

	ctx = i_new(struct quota_transaction_context, 1);
	ctx->quota = _quota;

	if (quota->dict != NULL) {
		t_push();
		(void)dict_lookup(quota->dict, unsafe_data_stack_pool,
				  DICT_QUOTA_LIMIT_PATH"storage", &value);
		ctx->storage_limit = value == NULL ? 0 :
			strtoull(value, NULL, 10);

		(void)dict_lookup(quota->dict, unsafe_data_stack_pool,
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
dict_quota_transaction_commit(struct quota_transaction_context *ctx)
{
	struct dict_quota *quota = (struct dict_quota *)ctx->quota;

	if (quota->dict != NULL) {
		struct dict_transaction_context *dt;

		dt = dict_transaction_begin(quota->dict);
		dict_atomic_inc(dt, DICT_QUOTA_CURRENT_PATH"storage",
				ctx->bytes_diff);
		if (dict_transaction_commit(dt) < 0)
			i_error("dict_quota: Couldn't update quota");
	}

	i_free(ctx);
	return 0;
}

static void
dict_quota_transaction_rollback(struct quota_transaction_context *ctx)
{
	i_free(ctx);
}

static int
dict_quota_try_alloc(struct quota_transaction_context *ctx,
		     struct mail *mail, int *too_large_r)
{
	uoff_t size;

	size = mail_get_physical_size(mail);
	*too_large_r = size > ctx->storage_limit;

	if (ctx->storage_current + ctx->bytes_diff + size > ctx->storage_limit)
		return 0;

	ctx->bytes_diff += size;
	return 1;
}

static void
dict_quota_alloc(struct quota_transaction_context *ctx, struct mail *mail)
{
	uoff_t size;

	size = mail_get_physical_size(mail);
	if (size != (uoff_t)-1)
		ctx->bytes_diff += size;
}

static void
dict_quota_free(struct quota_transaction_context *ctx, struct mail *mail)
{
	uoff_t size;

	size = mail_get_physical_size(mail);
	if (size != (uoff_t)-1)
		ctx->bytes_diff -= size;
}

static const char *dict_quota_last_error(struct quota *_quota)
{
	struct dict_quota *quota = (struct dict_quota *)_quota;

	return quota->error;
}

struct quota dict_quota = {
	"dict",

	dict_quota_init,
	dict_quota_deinit,

	dict_quota_root_iter_init,
	dict_quota_root_iter_next,
	dict_quota_root_iter_deinit,

	dict_quota_root_lookup,

	dict_quota_root_get_name,
	dict_quota_root_get_resources,

	dict_quota_root_create,
	dict_quota_get_resource,
	dict_quota_set_resource,

	dict_quota_transaction_begin,
	dict_quota_transaction_commit,
	dict_quota_transaction_rollback,

	dict_quota_try_alloc,
	dict_quota_alloc,
	dict_quota_free,

	dict_quota_last_error,

	ARRAY_INIT
};
