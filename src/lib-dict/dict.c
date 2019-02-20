/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "llist.h"
#include "str.h"
#include "dict-private.h"

static ARRAY(struct dict *) dict_drivers;

static struct dict *dict_driver_lookup(const char *name)
{
	struct dict *const *dicts;

	array_foreach(&dict_drivers, dicts) {
		struct dict *dict = *dicts;

		if (strcmp(dict->name, name) == 0)
			return dict;
	}
	return NULL;
}

void dict_transaction_commit_async_noop_callback(
	const struct dict_commit_result *result ATTR_UNUSED,
	void *context ATTR_UNUSED)
{
	/* do nothing */
}

void dict_driver_register(struct dict *driver)
{
	if (!array_is_created(&dict_drivers))
		i_array_init(&dict_drivers, 8);

	if (dict_driver_lookup(driver->name) != NULL) {
		i_fatal("dict_driver_register(%s): Already registered",
			driver->name);
	}
	array_push_back(&dict_drivers, &driver);
}

void dict_driver_unregister(struct dict *driver)
{
	struct dict *const *dicts;
	unsigned int idx = UINT_MAX;

	array_foreach(&dict_drivers, dicts) {
		if (*dicts == driver) {
			idx = array_foreach_idx(&dict_drivers, dicts);
			break;
		}
	}
	i_assert(idx != UINT_MAX);
	array_delete(&dict_drivers, idx, 1);

	if (array_count(&dict_drivers) == 0)
		array_free(&dict_drivers);
}

int dict_init(const char *uri, const struct dict_settings *set,
	      struct dict **dict_r, const char **error_r)
{
	struct dict *dict;
	const char *p, *name, *error;

	i_assert(set->username != NULL);

	p = strchr(uri, ':');
	if (p == NULL) {
		*error_r = t_strdup_printf("Dictionary URI is missing ':': %s",
					   uri);
		return -1;
	}

	name = t_strdup_until(uri, p);
	dict = dict_driver_lookup(name);
	if (dict == NULL) {
		*error_r = t_strdup_printf("Unknown dict module: %s", name);
		return -1;
	}
	if (dict->v.init(dict, p+1, set, dict_r, &error) < 0) {
		*error_r = t_strdup_printf("dict %s: %s", name, error);
		return -1;
	}
	i_assert(*dict_r != NULL);

	return 0;
}

void dict_deinit(struct dict **_dict)
{
	struct dict *dict = *_dict;

	*_dict = NULL;

	i_assert(dict->iter_count == 0);
	i_assert(dict->transaction_count == 0);
	i_assert(dict->transactions == NULL);

	dict->v.deinit(dict);
}

void dict_wait(struct dict *dict)
{
	if (dict->v.wait != NULL)
		dict->v.wait(dict);
}

bool dict_switch_ioloop(struct dict *dict)
{
	if (dict->v.switch_ioloop != NULL)
		return dict->v.switch_ioloop(dict);
	else
		return FALSE;
}

static bool dict_key_prefix_is_valid(const char *key)
{
	return str_begins(key, DICT_PATH_SHARED) ||
		str_begins(key, DICT_PATH_PRIVATE);
}

int dict_lookup(struct dict *dict, pool_t pool, const char *key,
		const char **value_r, const char **error_r)
{
	i_assert(dict_key_prefix_is_valid(key));
	return dict->v.lookup(dict, pool, key, value_r, error_r);
}

void dict_lookup_async(struct dict *dict, const char *key,
		       dict_lookup_callback_t *callback, void *context)
{
	if (dict->v.lookup_async == NULL) {
		struct dict_lookup_result result;

		i_zero(&result);
		result.ret = dict_lookup(dict, pool_datastack_create(),
					 key, &result.value, &result.error);
		const char *const values[] = { result.value, NULL };
		result.values = values;
		callback(&result, context);
		return;
	}
	dict->v.lookup_async(dict, key, callback, context);
}

struct dict_iterate_context *
dict_iterate_init(struct dict *dict, const char *path, 
		  enum dict_iterate_flags flags)
{
	const char *paths[2];

	paths[0] = path;
	paths[1] = NULL;
	return dict_iterate_init_multiple(dict, paths, flags);
}

struct dict_iterate_context *
dict_iterate_init_multiple(struct dict *dict, const char *const *paths,
			   enum dict_iterate_flags flags)
{
	struct dict_iterate_context *ctx;
	unsigned int i;

	i_assert(paths[0] != NULL);
	for (i = 0; paths[i] != NULL; i++)
		i_assert(dict_key_prefix_is_valid(paths[i]));

	if (dict->v.iterate_init == NULL) {
		/* not supported by backend */
		ctx = &dict_iter_unsupported;
	} else {
		ctx = dict->v.iterate_init(dict, paths, flags);
	}
	/* the dict in context can differ from the dict
	   passed as parameter, e.g. it can be dict-fail when
	   iteration is not supported. */
	ctx->dict->iter_count++;
	return ctx;
}

bool dict_iterate(struct dict_iterate_context *ctx,
		  const char **key_r, const char **value_r)
{
	if (ctx->max_rows > 0 && ctx->row_count >= ctx->max_rows) {
		/* row count was limited */
		ctx->has_more = FALSE;
		return FALSE;
	}
	if (!ctx->dict->v.iterate(ctx, key_r, value_r))
		return FALSE;
	ctx->row_count++;
	return TRUE;
}

void dict_iterate_set_async_callback(struct dict_iterate_context *ctx,
				     dict_iterate_callback_t *callback,
				     void *context)
{
	ctx->async_callback = callback;
	ctx->async_context = context;
}

void dict_iterate_set_limit(struct dict_iterate_context *ctx,
			    uint64_t max_rows)
{
	ctx->max_rows = max_rows;
}

bool dict_iterate_has_more(struct dict_iterate_context *ctx)
{
	return ctx->has_more;
}

int dict_iterate_deinit(struct dict_iterate_context **_ctx,
			const char **error_r)
{
	struct dict_iterate_context *ctx = *_ctx;

	i_assert(ctx->dict->iter_count > 0);
	ctx->dict->iter_count--;

	*_ctx = NULL;
	return ctx->dict->v.iterate_deinit(ctx, error_r);
}

struct dict_transaction_context *dict_transaction_begin(struct dict *dict)
{
	struct dict_transaction_context *ctx;
	if (dict->v.transaction_init == NULL)
		ctx = &dict_transaction_unsupported;
	else
		ctx = dict->v.transaction_init(dict);
	/* the dict in context can differ from the dict
	   passed as parameter, e.g. it can be dict-fail when
	   transactions are not supported. */
	ctx->dict->transaction_count++;
	DLLIST_PREPEND(&ctx->dict->transactions, ctx);
	return ctx;
}

void dict_transaction_no_slowness_warning(struct dict_transaction_context *ctx)
{
	ctx->no_slowness_warning = TRUE;
}

void dict_transaction_set_timestamp(struct dict_transaction_context *ctx,
				    const struct timespec *ts)
{
	/* These asserts are mainly here to guarantee a possibility in future
	   to change the API to support multiple timestamps within the same
	   transaction, so this call would apply only to the following
	   changes. */
	i_assert(!ctx->changed);
	i_assert(ctx->timestamp.tv_sec == 0);
	i_assert(ts->tv_sec > 0);

	ctx->timestamp = *ts;
	if (ctx->dict->v.set_timestamp != NULL)
		ctx->dict->v.set_timestamp(ctx, ts);
}

struct dict_commit_sync_result {
	int ret;
	char *error;
};

static void
dict_transaction_commit_sync_callback(const struct dict_commit_result *result,
				      void *context)
{
	struct dict_commit_sync_result *sync_result = context;

	sync_result->ret = result->ret;
	sync_result->error = i_strdup(result->error);
}

int dict_transaction_commit(struct dict_transaction_context **_ctx,
			    const char **error_r)
{
	struct dict_transaction_context *ctx = *_ctx;
	struct dict_commit_sync_result result;

	*_ctx = NULL;

	i_zero(&result);
	i_assert(ctx->dict->transaction_count > 0);
	ctx->dict->transaction_count--;
	DLLIST_REMOVE(&ctx->dict->transactions, ctx);
	ctx->dict->v.transaction_commit(ctx, FALSE,
		dict_transaction_commit_sync_callback, &result);
	*error_r = t_strdup(result.error);
	i_free(result.error);
	return result.ret;
}

void dict_transaction_commit_async(struct dict_transaction_context **_ctx,
				   dict_transaction_commit_callback_t *callback,
				   void *context)
{
	struct dict_transaction_context *ctx = *_ctx;

	*_ctx = NULL;
	i_assert(ctx->dict->transaction_count > 0);
	ctx->dict->transaction_count--;
	DLLIST_REMOVE(&ctx->dict->transactions, ctx);
	if (callback == NULL)
		callback = dict_transaction_commit_async_noop_callback;
	ctx->dict->v.transaction_commit(ctx, TRUE, callback, context);
}

void dict_transaction_rollback(struct dict_transaction_context **_ctx)
{
	struct dict_transaction_context *ctx = *_ctx;

	*_ctx = NULL;
	i_assert(ctx->dict->transaction_count > 0);
	ctx->dict->transaction_count--;
	DLLIST_REMOVE(&ctx->dict->transactions, ctx);
	ctx->dict->v.transaction_rollback(ctx);
}

void dict_set(struct dict_transaction_context *ctx,
	      const char *key, const char *value)
{
	i_assert(dict_key_prefix_is_valid(key));

	T_BEGIN {
		ctx->dict->v.set(ctx, key, value);
	} T_END;
	ctx->changed = TRUE;
}

void dict_unset(struct dict_transaction_context *ctx,
		const char *key)
{
	i_assert(dict_key_prefix_is_valid(key));

	T_BEGIN {
		ctx->dict->v.unset(ctx, key);
	} T_END;
	ctx->changed = TRUE;
}

void dict_atomic_inc(struct dict_transaction_context *ctx,
		     const char *key, long long diff)
{
	i_assert(dict_key_prefix_is_valid(key));

	if (diff != 0) T_BEGIN {
		ctx->dict->v.atomic_inc(ctx, key, diff);
		ctx->changed = TRUE;
	} T_END;
}

const char *dict_escape_string(const char *str)
{
	const char *p;
	string_t *ret;

	/* see if we need to escape it */
	for (p = str; *p != '\0'; p++) {
		if (*p == '/' || *p == '\\')
			break;
	}

	if (*p == '\0')
		return str;

	/* escape */
	ret = t_str_new((size_t) (p - str) + 128);
	str_append_data(ret, str, (size_t) (p - str));

	for (; *p != '\0'; p++) {
		switch (*p) {
		case '/':
			str_append_c(ret, '\\');
			str_append_c(ret, '|');
			break;
		case '\\':
			str_append_c(ret, '\\');
			str_append_c(ret, '\\');
			break;
		default:
			str_append_c(ret, *p);
			break;
		}
	}
	return str_c(ret);
}

const char *dict_unescape_string(const char *str)
{
	const char *p;
	string_t *ret;

	/* see if we need to unescape it */
	for (p = str; *p != '\0'; p++) {
		if (*p == '\\')
			break;
	}

	if (*p == '\0')
		return str;

	/* unescape */
	ret = t_str_new((size_t) (p - str) + strlen(p) + 1);
	str_append_data(ret, str, (size_t) (p - str));

	for (; *p != '\0'; p++) {
		if (*p != '\\')
			str_append_c(ret, *p);
		else {
			if (*++p == '|')
				str_append_c(ret, '/');
			else if (*p == '\0')
				break;
			else
				str_append_c(ret, *p);
		}
	}
	return str_c(ret);
}
