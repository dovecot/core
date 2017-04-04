/* Copyright (c) 2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "dict.h"
#include "dict-private.h"

struct dict_iterate_context dict_iter_unsupported =
{
	.dict = &dict_driver_fail,
};

struct dict_transaction_context dict_transaction_unsupported =
{
        .dict = &dict_driver_fail,
};

static int dict_fail_init(struct dict *dict_driver ATTR_UNUSED,
			  const char *uri ATTR_UNUSED,
			  const struct dict_settings *set ATTR_UNUSED,
			  struct dict **dict_r ATTR_UNUSED, const char **error_r)
{
	*error_r = "Unsupported operation (dict does not support this feature)";
	return -1;
}

static void dict_fail_deinit(struct dict *dict ATTR_UNUSED)
{
}

static void dict_fail_wait(struct dict *dict ATTR_UNUSED)
{
}

static int dict_fail_lookup(struct dict *dict ATTR_UNUSED, pool_t pool ATTR_UNUSED,
			    const char *key ATTR_UNUSED, const char **value_r ATTR_UNUSED,
			    const char **error_r)
{
	*error_r = "Unsupported operation (dict does not support this feature)";
	return -1;
}

static struct dict_iterate_context *
dict_fail_iterate_init(struct dict *dict ATTR_UNUSED, const char *const *paths ATTR_UNUSED,
		       enum dict_iterate_flags flags ATTR_UNUSED)
{
	return &dict_iter_unsupported;
}

static bool dict_fail_iterate(struct dict_iterate_context *ctx ATTR_UNUSED,
			      const char **key_r ATTR_UNUSED, const char **value_r ATTR_UNUSED)
{
	return FALSE;
}

static int dict_fail_iterate_deinit(struct dict_iterate_context *ctx ATTR_UNUSED,
				    const char **error_r)
{
	*error_r = "Unsupported operation (dict does not support this feature)";
	return -1;
}

static struct dict_transaction_context *dict_fail_transaction_init(struct dict *dict ATTR_UNUSED)
{
	return &dict_transaction_unsupported;
}

static void dict_fail_transaction_commit(struct dict_transaction_context *ctx ATTR_UNUSED,
					 bool async ATTR_UNUSED,
					 dict_transaction_commit_callback_t *callback,
					 void *context)
{
	struct dict_commit_result res = {
		.ret = DICT_COMMIT_RET_FAILED,
		.error = "Unsupported operation (dict does not support this feature)"
	};
	if (callback != NULL)
		callback(&res, context);
}

static void dict_fail_transaction_rollback(struct dict_transaction_context *ctx ATTR_UNUSED)
{
}

static void dict_fail_set(struct dict_transaction_context *ctx ATTR_UNUSED,
			  const char *key ATTR_UNUSED, const char *value ATTR_UNUSED)
{
}

static void dict_fail_unset(struct dict_transaction_context *ctx ATTR_UNUSED,
			    const char *key ATTR_UNUSED)
{
}

static void dict_fail_atomic_inc(struct dict_transaction_context *ctx ATTR_UNUSED,
				 const char *key ATTR_UNUSED, long long diff ATTR_UNUSED)
{
}

static bool dict_fail_switch_ioloop(struct dict *dict ATTR_UNUSED)
{
	return TRUE;
}

static void dict_fail_set_timestamp(struct dict_transaction_context *ctx ATTR_UNUSED,
				    const struct timespec *ts ATTR_UNUSED)
{
}

struct dict dict_driver_fail = {
	.name = "fail",
	.v = {
		.init = dict_fail_init,
		.deinit = dict_fail_deinit,
		.wait = dict_fail_wait,
		.lookup = dict_fail_lookup,
		.iterate_init = dict_fail_iterate_init,
		.iterate = dict_fail_iterate,
		.iterate_deinit = dict_fail_iterate_deinit,
		.transaction_init = dict_fail_transaction_init,
		.transaction_commit = dict_fail_transaction_commit,
		.transaction_rollback = dict_fail_transaction_rollback,
		.set = dict_fail_set,
		.unset = dict_fail_unset,
		.atomic_inc = dict_fail_atomic_inc,
		.lookup_async = NULL,
		.switch_ioloop = dict_fail_switch_ioloop,
		.set_timestamp = dict_fail_set_timestamp
	},
};
