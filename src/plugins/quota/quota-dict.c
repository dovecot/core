/* Copyright (C) 2005-2006 Timo Sirainen */

#include "lib.h"
#include "str.h"
#include "dict.h"
#include "quota-private.h"

#include <stdlib.h>

#define DICT_QUOTA_CURRENT_PATH DICT_PATH_PRIVATE"quota/"
#define DICT_QUOTA_CURRENT_BYTES_PATH DICT_QUOTA_CURRENT_PATH"storage"
#define DICT_QUOTA_CURRENT_COUNT_PATH DICT_QUOTA_CURRENT_PATH"messages"

struct dict_quota_root {
	struct quota_root root;
	struct dict *dict;

	uint64_t message_bytes_limit;
	uint64_t message_count_limit;
};

extern struct quota_backend quota_backend_dict;

static struct quota_root *
dict_quota_init(struct quota_setup *setup, const char *name)
{
	struct dict_quota_root *root;
	struct dict *dict;
	const char *uri, *const *args;
	unsigned long long message_bytes_limit = 0, message_count_limit = 0;

	uri = strchr(setup->data, ' ');
	if (uri == NULL) {
		i_error("dict quota: URI missing from parameters: %s",
			setup->data);
		return NULL;
	}

	t_push();
	args = t_strsplit(t_strdup_until(setup->data, uri++), ":");
	for (; *args != '\0'; args++) {
		if (strncmp(*args, "storage=", 8) == 0) {
			message_bytes_limit =
				strtoull(*args + 8, NULL, 10) * 1024;
		} else if (strncmp(*args, "messages=", 9) == 0)
			message_bytes_limit = strtoull(*args + 9, NULL, 10);
	}
	t_pop();

	if (getenv("DEBUG") != NULL) {
		i_info("dict quota: uri = %s", uri);
		i_info("dict quota: byte limit = %llu", message_bytes_limit);
		i_info("dict quota: count limit = %llu", message_count_limit);
	}

	dict = dict_init(uri, getenv("USER"));
	if (dict == NULL)
		return NULL;

	root = i_new(struct dict_quota_root, 1);
	root->root.name = i_strdup(name);
	root->root.v = quota_backend_dict.v;
	root->dict = dict;

	root->message_bytes_limit =
		message_bytes_limit == 0 ? (uint64_t)-1 : message_bytes_limit;
	root->message_count_limit =
		message_count_limit == 0 ? (uint64_t)-1 : message_count_limit;
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

	if (strcmp(name, QUOTA_NAME_STORAGE) == 0) {
		if (root->message_bytes_limit == (uint64_t)-1)
			return 0;

		*limit_r = root->message_bytes_limit / 1024;
		t_push();
		ret = dict_lookup(root->dict, unsafe_data_stack_pool,
				  DICT_QUOTA_CURRENT_BYTES_PATH, &value);
		*value_r = ret <= 0 ? 0 : strtoull(value, NULL, 10) / 1024;
		t_pop();
	} else if (strcmp(name, QUOTA_NAME_MESSAGES) == 0) {
		if (root->message_count_limit == (uint64_t)-1)
			return 0;

		*limit_r = root->message_count_limit;
		t_push();
		ret = dict_lookup(root->dict, unsafe_data_stack_pool,
				  DICT_QUOTA_CURRENT_COUNT_PATH, &value);
		*value_r = ret <= 0 ? 0 : strtoull(value, NULL, 10);
		t_pop();
	} else {
		return 0;
	}

	return 1;
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

	ctx->bytes_limit = root->message_bytes_limit;
	ctx->count_limit = root->message_count_limit;

	t_push();
	if (ctx->bytes_limit != (uint64_t)-1) {
		(void)dict_lookup(root->dict, unsafe_data_stack_pool,
				  DICT_QUOTA_CURRENT_BYTES_PATH, &value);
		ctx->bytes_current = value == NULL ? 0 :
			strtoull(value, NULL, 10);
	}
	if (ctx->count_limit != (uint64_t)-1) {
		(void)dict_lookup(root->dict, unsafe_data_stack_pool,
				  DICT_QUOTA_CURRENT_COUNT_PATH, &value);
		ctx->count_current = value == NULL ? 0 :
			strtoull(value, NULL, 10);
	}
	t_pop();
	return ctx;
}

static int
dict_quota_transaction_commit(struct quota_root_transaction_context *ctx)
{
	struct dict_quota_root *root = (struct dict_quota_root *)ctx->root;
	struct dict_transaction_context *dt;

	dt = dict_transaction_begin(root->dict);
	if (ctx->bytes_limit != (uint64_t)-1) {
		dict_atomic_inc(dt, DICT_QUOTA_CURRENT_BYTES_PATH,
				ctx->bytes_diff);
	}
	if (ctx->count_limit != (uint64_t)-1) {
		dict_atomic_inc(dt, DICT_QUOTA_CURRENT_COUNT_PATH,
				ctx->count_diff);
	}
	if (dict_transaction_commit(dt) < 0)
		i_error("dict_quota: Couldn't update quota");

	i_free(ctx);
	return 0;
}

static void
dict_quota_transaction_rollback(struct quota_root_transaction_context *ctx)
{
	i_free(ctx);
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

		quota_default_try_alloc,
		quota_default_try_alloc_bytes,
		quota_default_test_alloc_bytes,
		quota_default_alloc,
		quota_default_free
	}
};
