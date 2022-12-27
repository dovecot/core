/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "guid.h"
#include "llist.h"
#include "ioloop.h"
#include "str.h"
#include "ioloop.h"
#include "dict-private.h"

struct dict_commit_callback_ctx {
	pool_t pool;
	struct dict_commit_callback_ctx *prev, *next;
	struct dict *dict;
	struct event *event;
	dict_transaction_commit_callback_t *callback;
	struct dict_op_settings_private set;
	struct timeout *to;
	void *context;
	struct dict_commit_result result;
	bool delayed_callback:1;
};

struct dict_lookup_callback_ctx {
	struct dict *dict;
	struct event *event;
	dict_lookup_callback_t *callback;
	void *context;
};

static ARRAY(struct dict *) dict_drivers;

static void
dict_commit_async_timeout(struct dict_commit_callback_ctx *ctx);
static void dict_rollback_async_timeout(struct dict_transaction_context *ctx);

static struct event_category event_category_dict = {
	.name = "dict",
};

static struct dict *dict_driver_lookup(const char *name)
{
	struct dict *dict;

	array_foreach_elem(&dict_drivers, dict) {
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
	struct dict_settings set_dup = *set;
	struct dict *dict;
	const char *p, *name, *error;

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
	struct event *event = event_create(set->event_parent);
	event_add_category(event, &event_category_dict);
	event_add_str(event, "driver", dict->name);
	event_set_append_log_prefix(event, t_strdup_printf("dict(%s): ",
				    dict->name));
	set_dup.event_parent = event;
	if (dict->v.init(dict, p+1, &set_dup, dict_r, &error) < 0) {
		*error_r = t_strdup_printf("dict %s: %s", name, error);
		event_unref(&event);
		return -1;
	}
	i_assert(*dict_r != NULL);
	(*dict_r)->refcount++;
	(*dict_r)->event = event;
	e_debug(event_create_passthrough(event)->set_name("dict_created")->event(),
		"dict created (uri=%s, base_dir=%s)", uri, set->base_dir);

	return 0;
}

static void dict_ref(struct dict *dict)
{
	i_assert(dict->refcount > 0);

	dict->refcount++;
}

static void dict_unref(struct dict **_dict)
{
	struct dict *dict = *_dict;
	*_dict = NULL;
	if (dict == NULL)
		return;
	struct event *event = dict->event;
	i_assert(dict->refcount > 0);
	if (--dict->refcount == 0) {
		T_BEGIN {
			dict->v.deinit(dict);
		} T_END;
		e_debug(event_create_passthrough(event)->
			set_name("dict_destroyed")->event(), "dict destroyed");
		event_unref(&event);
	}
}

void dict_deinit(struct dict **_dict)
{
	struct dict *dict = *_dict;

	if (dict == NULL)
		return;
	*_dict = NULL;

	i_assert(!dict_have_async_operations(dict));
	i_assert(dict->transactions == NULL);
	dict_unref(&dict);
}

void dict_wait(struct dict *dict)
{
	struct dict_commit_callback_ctx *commit, *next;
	struct dict_transaction_context *rollback, *next_rollback;

	e_debug(dict->event, "Waiting for dict to finish pending operations");
	if (dict->v.wait != NULL) T_BEGIN {
		dict->v.wait(dict);
	} T_END;
	for (commit = dict->commits; commit != NULL; commit = next) {
		next = commit->next;
		dict_commit_async_timeout(commit);
	}
	for (rollback = dict->rollbacks; rollback != NULL; rollback = next_rollback) {
		next_rollback = rollback->next;
		dict_rollback_async_timeout(rollback);
	}
}

bool dict_have_async_operations(struct dict *dict)
{
	return dict->iter_count != 0 ||
		dict->transaction_count != 0 ||
		dict->commits != NULL;
}

bool dict_switch_ioloop(struct dict *dict)
{
	struct dict_commit_callback_ctx *commit;
	bool ret = FALSE;

	for (commit = dict->commits; commit != NULL; commit = commit->next) {
		commit->to = io_loop_move_timeout(&commit->to);
		ret = TRUE;
	}
	if (dict->v.switch_ioloop != NULL) {
		bool ret;
		T_BEGIN {
			ret = dict->v.switch_ioloop(dict);
		} T_END;
		if (ret)
			return TRUE;
	}
	return ret;
}

int dict_expire_scan(struct dict *dict, const char **error_r)
{
	if (dict->v.expire_scan == NULL)
		return 0;

	int ret;
	T_BEGIN {
		ret = dict->v.expire_scan(dict, error_r);
	} T_END_PASS_STR_IF(ret < 0, error_r);
	return ret;
}

static bool dict_key_prefix_is_valid(const char *key, const char *username)
{
	if (str_begins_with(key, DICT_PATH_SHARED))
		return TRUE;
	if (str_begins_with(key, DICT_PATH_PRIVATE)) {
		i_assert(username != NULL && username[0] != '\0');
		return TRUE;
	}
	return FALSE;

}

void dict_pre_api_callback(struct dict *dict)
{
	if (dict->prev_ioloop != NULL) {
		/* Don't let callback see that we've created our
		   internal ioloop in case it wants to add some ios
		   or timeouts. */
		io_loop_set_current(dict->prev_ioloop);
	}
}

void dict_post_api_callback(struct dict *dict)
{
	if (dict->prev_ioloop != NULL) {
		io_loop_set_current(dict->ioloop);
		io_loop_stop(dict->ioloop);
	}
}

static void dict_lookup_finished(struct event *event, int ret, const char *error)
{
	i_assert(ret >= 0 || error != NULL);
	const char *key = event_find_field_recursive_str(event, "key");
	if (ret < 0)
		event_add_str(event, "error", error);
	else if (ret == 0)
		event_add_str(event, "key_not_found", "yes");
	event_set_name(event, "dict_lookup_finished");
	e_debug(event, "Lookup finished for '%s': %s",  key, ret > 0 ?
			"found" :
			"not found");
}

static void dict_transaction_finished(struct event *event, enum dict_commit_ret ret,
				      bool rollback, const char *error)
{
	i_assert(ret > DICT_COMMIT_RET_FAILED || error != NULL);
	if (ret == DICT_COMMIT_RET_FAILED || ret == DICT_COMMIT_RET_WRITE_UNCERTAIN) {
		 if (ret == DICT_COMMIT_RET_WRITE_UNCERTAIN)
			event_add_str(event, "write_uncertain", "yes");
		event_add_str(event, "error", error);
	} else if (rollback) {
		event_add_str(event, "rollback", "yes");
	} else if (ret == 0) {
		event_add_str(event, "key_not_found", "yes");
	}
	event_set_name(event, "dict_transaction_finished");
	e_debug(event, "Dict transaction finished");
}

static void
dict_lookup_callback(const struct dict_lookup_result *result,
		     void *context)
{
	struct dict_lookup_callback_ctx *ctx = context;

	dict_pre_api_callback(ctx->dict);
	ctx->callback(result, ctx->context);
	dict_post_api_callback(ctx->dict);
	dict_lookup_finished(ctx->event, result->ret, result->error);
	event_unref(&ctx->event);

	dict_unref(&ctx->dict);
	i_free(ctx);
}

static void dict_transaction_rollback_run(struct dict_transaction_context *ctx)
{
	struct event *event = ctx->event;
	struct dict_op_settings_private set_copy = ctx->set;
	T_BEGIN {
		ctx->dict->v.transaction_rollback(ctx);
	} T_END;
	dict_transaction_finished(event, DICT_COMMIT_RET_OK, TRUE, NULL);
	dict_op_settings_private_free(&set_copy);
	event_unref(&event);
}

static void dict_rollback_async_timeout(struct dict_transaction_context *ctx)
{
	DLLIST_REMOVE(&ctx->dict->rollbacks, ctx);
	timeout_remove(&ctx->to_rollback);
	dict_transaction_rollback_run(ctx);
}

static void
dict_commit_async_timeout(struct dict_commit_callback_ctx *ctx)
{
	DLLIST_REMOVE(&ctx->dict->commits, ctx);
	timeout_remove(&ctx->to);
	dict_pre_api_callback(ctx->dict);
	if (ctx->callback != NULL)
		ctx->callback(&ctx->result, ctx->context);
	else if (ctx->result.ret < 0)
		e_error(ctx->event, "Commit failed: %s", ctx->result.error);
	dict_post_api_callback(ctx->dict);

	dict_transaction_finished(ctx->event, ctx->result.ret, FALSE, ctx->result.error);
	dict_op_settings_private_free(&ctx->set);
	event_unref(&ctx->event);
	dict_unref(&ctx->dict);
	pool_unref(&ctx->pool);
}

static void dict_commit_callback(const struct dict_commit_result *result,
				 void *context)
{
	struct dict_commit_callback_ctx *ctx = context;

	i_assert(result->ret >= 0 || result->error != NULL);
	ctx->result = *result;
	if (ctx->delayed_callback) {
		ctx->result.error = p_strdup(ctx->pool, ctx->result.error);
		ctx->to = timeout_add_short(0, dict_commit_async_timeout, ctx);
	} else {
		dict_commit_async_timeout(ctx);
	}
}

static struct event *
dict_event_create(struct dict *dict, const struct dict_op_settings *set)
{
	struct event *event = event_create(dict->event);
	if (set->username != NULL)
		event_add_str(event, "user", set->username);
	return event;
}

int dict_lookup(struct dict *dict, const struct dict_op_settings *set,
		pool_t pool, const char *key,
		const char **value_r, const char **error_r)
{
	const char *const *values;
	int ret = dict_lookup_values(dict, set, pool, key, &values, error_r);
	if (ret > 0)
		*value_r = values[0];
	else if (ret == 0)
		*value_r = NULL;
	return ret;
}

int dict_lookup_values(struct dict *dict, const struct dict_op_settings *set,
		       pool_t pool, const char *key,
		       const char *const **values_r, const char **error_r)
{
	struct event *event = dict_event_create(dict, set);
	int ret;
	i_assert(dict_key_prefix_is_valid(key, set->username));

	e_debug(event, "Looking up '%s'", key);
	event_add_str(event, "key", key);
	ret = dict->v.lookup(dict, set, pool, key, values_r, error_r);
	if (ret == 0)
		*values_r = NULL;
	dict_lookup_finished(event, ret, *error_r);
	event_unref(&event);
	return ret;
}

#undef dict_lookup_async
void dict_lookup_async(struct dict *dict, const struct dict_op_settings *set,
		       const char *key, dict_lookup_callback_t *callback,
		       void *context)
{
	i_assert(dict_key_prefix_is_valid(key, set->username));
	if (dict->v.lookup_async == NULL) {
		struct dict_lookup_result result;

		i_zero(&result);
		/* event is going to be sent by dict_lookup */
		result.ret = dict_lookup(dict, set, pool_datastack_create(),
					 key, &result.value, &result.error);
		const char *const values[] = { result.value, NULL };
		result.values = values;
		callback(&result, context);
		return;
	}
	struct dict_lookup_callback_ctx *lctx =
		i_new(struct dict_lookup_callback_ctx, 1);
	lctx->dict = dict;
	dict_ref(lctx->dict);
	lctx->callback = callback;
	lctx->context = context;
	lctx->event = dict_event_create(dict, set);
	event_add_str(lctx->event, "key", key);
	e_debug(lctx->event, "Looking up (async) '%s'", key);
	T_BEGIN {
		dict->v.lookup_async(dict, set, key, dict_lookup_callback, lctx);
	} T_END;
}

struct dict_iterate_context *
dict_iterate_init(struct dict *dict, const struct dict_op_settings *set,
		  const char *path, enum dict_iterate_flags flags)
{
	struct dict_iterate_context *ctx;

	i_assert(path != NULL);
	i_assert(dict_key_prefix_is_valid(path, set->username));

	if (dict->v.iterate_init == NULL) {
		/* not supported by backend */
		ctx = &dict_iter_unsupported;
	} else T_BEGIN {
		ctx = dict->v.iterate_init(dict, set, path, flags);
	} T_END;
	/* the dict in context can differ from the dict
	   passed as parameter, e.g. it can be dict-fail when
	   iteration is not supported. */
	ctx->event = dict_event_create(dict, set);
	ctx->flags = flags;
	dict_op_settings_dup(set, &ctx->set);

	event_add_str(ctx->event, "key", path);
	event_set_name(ctx->event, "dict_iteration_started");
	e_debug(ctx->event, "Iterating prefix %s", path);
	ctx->dict->iter_count++;
	return ctx;
}

bool dict_iterate(struct dict_iterate_context *ctx,
		  const char **key_r, const char **value_r)
{
	const char *const *values;

	if (!dict_iterate_values(ctx, key_r, &values))
		return FALSE;
	if ((ctx->flags & DICT_ITERATE_FLAG_NO_VALUE) == 0)
		*value_r = values[0];
	else
		*value_r = NULL;
	return TRUE;
}

bool dict_iterate_values(struct dict_iterate_context *ctx,
			 const char **key_r, const char *const **values_r)
{

	if (ctx->max_rows > 0 && ctx->row_count >= ctx->max_rows) {
		e_debug(ctx->event, "Maximum row count (%"PRIu64") reached",
			ctx->max_rows);
		/* row count was limited */
		ctx->has_more = FALSE;
		return FALSE;
	}
	bool ret;
	T_BEGIN {
		ret = ctx->dict->v.iterate(ctx, key_r, values_r);
	} T_END;
	if (!ret)
		return FALSE;
	if ((ctx->flags & DICT_ITERATE_FLAG_NO_VALUE) != 0) {
		/* always return value as NULL to be consistent across
		   drivers */
		*values_r = NULL;
	} else {
		i_assert(values_r[0] != NULL);
	}
	ctx->row_count++;
	return TRUE;
}

#undef dict_iterate_set_async_callback
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

	if (ctx == NULL)
		return 0;

	struct event *event = ctx->event;
	int ret;
	uint64_t rows;

	i_assert(ctx->dict->iter_count > 0);
	ctx->dict->iter_count--;

	*_ctx = NULL;
	rows = ctx->row_count;
	struct dict_op_settings_private set_copy = ctx->set;
	T_BEGIN {
		ret = ctx->dict->v.iterate_deinit(ctx, error_r);
	} T_END_PASS_STR_IF(ret < 0, error_r);
	dict_op_settings_private_free(&set_copy);

	event_add_int(event, "rows", rows);
	event_set_name(event, "dict_iteration_finished");

	if (ret < 0) {
		event_add_str(event, "error", *error_r);
		e_debug(event, "Iteration finished: %s", *error_r);
	} else {
		if (rows == 0)
			event_add_str(event, "key_not_found", "yes");
		e_debug(event, "Iteration finished, got %"PRIu64" rows", rows);
	}

	event_unref(&event);
	return ret;
}

struct dict_transaction_context *
dict_transaction_begin(struct dict *dict, const struct dict_op_settings *set)
{
	struct dict_transaction_context *ctx;
	guid_128_t guid;
	if (dict->v.transaction_init == NULL)
		ctx = &dict_transaction_unsupported;
	else T_BEGIN {
		ctx = dict->v.transaction_init(dict);
	} T_END;
	/* the dict in context can differ from the dict
	   passed as parameter, e.g. it can be dict-fail when
	   transactions are not supported. */
	if (set->expire_secs > 0 &&
	    (dict->flags & DICT_DRIVER_FLAG_SUPPORT_EXPIRE_SECS) == 0)
		ctx->error = "Expiration not supported by dict driver";
	ctx->dict->transaction_count++;
	DLLIST_PREPEND(&ctx->dict->transactions, ctx);
	ctx->event = dict_event_create(dict, set);
	dict_op_settings_dup(set, &ctx->set);
	guid_128_generate(guid);
	event_add_str(ctx->event, "txid", guid_128_to_string(guid));
	event_set_name(ctx->event, "dict_transaction_started");
	e_debug(ctx->event, "Starting transaction");
	return ctx;
}

void dict_transaction_set_hide_log_values(struct dict_transaction_context *ctx,
					  bool hide_log_values)
{
	/* Apply hide_log_values to the current transactions dict op settings */
	ctx->set.hide_log_values = hide_log_values;
	if (ctx->dict->v.set_hide_log_values != NULL) T_BEGIN {
		ctx->dict->v.set_hide_log_values(ctx, hide_log_values);
	} T_END;
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
	struct event_passthrough *e = event_create_passthrough(ctx->event)->
		set_name("dict_set_timestamp");

	e_debug(e->event(), "Setting timestamp on transaction to (%"PRIdTIME_T", %ld)",
		 ts->tv_sec, ts->tv_nsec);
	if (ctx->dict->v.set_timestamp != NULL) T_BEGIN {
		ctx->dict->v.set_timestamp(ctx, ts);
	} T_END;
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

	if (ctx->error != NULL) {
		*error_r = t_strdup(ctx->error);
		dict_transaction_rollback(_ctx);
		return -1;
	}

	*_ctx = NULL;

	pool_t pool = pool_alloconly_create("dict_commit_callback_ctx", 64);
	struct dict_commit_callback_ctx *cctx =
		p_new(pool, struct dict_commit_callback_ctx, 1);
	cctx->pool = pool;
	i_zero(&result);
	i_assert(ctx->dict->transaction_count > 0);
	ctx->dict->transaction_count--;
	DLLIST_REMOVE(&ctx->dict->transactions, ctx);
	DLLIST_PREPEND(&ctx->dict->commits, cctx);
	cctx->dict = ctx->dict;
	dict_ref(cctx->dict);
	cctx->callback = dict_transaction_commit_sync_callback;
	cctx->context = &result;
	cctx->event = ctx->event;
	cctx->set = ctx->set;

	T_BEGIN {
		ctx->dict->v.transaction_commit(ctx, FALSE,
						dict_commit_callback, cctx);
	} T_END;
	*error_r = t_strdup(result.error);
	i_free(result.error);
	return result.ret;
}

#undef dict_transaction_commit_async
void dict_transaction_commit_async(struct dict_transaction_context **_ctx,
				   dict_transaction_commit_callback_t *callback,
				   void *context)
{
	struct dict_transaction_context *ctx = *_ctx;

	*_ctx = NULL;
	i_assert(ctx->dict->transaction_count > 0);
	ctx->dict->transaction_count--;
	DLLIST_REMOVE(&ctx->dict->transactions, ctx);

	if (ctx->error != NULL) {
		ctx->to_rollback = timeout_add_short(0,
			dict_rollback_async_timeout, ctx);
		return;
	}
	pool_t pool = pool_alloconly_create("dict_commit_callback_ctx", 64);
	struct dict_commit_callback_ctx *cctx =
		p_new(pool, struct dict_commit_callback_ctx, 1);
	DLLIST_PREPEND(&ctx->dict->commits, cctx);
	if (callback == NULL)
		callback = dict_transaction_commit_async_noop_callback;
	cctx->pool = pool;
	cctx->dict = ctx->dict;
	dict_ref(cctx->dict);
	cctx->callback = callback;
	cctx->context = context;
	cctx->event = ctx->event;
	cctx->set = ctx->set;
	cctx->delayed_callback = TRUE;
	T_BEGIN {
		ctx->dict->v.transaction_commit(ctx, TRUE,
						dict_commit_callback, cctx);
	} T_END;
	cctx->delayed_callback = FALSE;
}

void dict_transaction_commit_async_nocallback(
	struct dict_transaction_context **ctx)
{
	dict_transaction_commit_async(ctx, NULL, NULL);
}

void dict_transaction_rollback(struct dict_transaction_context **_ctx)
{
	struct dict_transaction_context *ctx = *_ctx;

	if (ctx == NULL)
		return;

	*_ctx = NULL;
	i_assert(ctx->dict->transaction_count > 0);
	ctx->dict->transaction_count--;
	DLLIST_REMOVE(&ctx->dict->transactions, ctx);

	dict_transaction_rollback_run(ctx);
}

void dict_set(struct dict_transaction_context *ctx,
	      const char *key, const char *value)
{
	i_assert(dict_key_prefix_is_valid(key, ctx->set.username));
	struct event_passthrough *e = event_create_passthrough(ctx->event)->
		set_name("dict_set_key")->
		add_str("key", key);

	e_debug(e->event(), "Setting '%s' to '%s'", key, value);

	T_BEGIN {
		ctx->dict->v.set(ctx, key, value);
	} T_END;
	ctx->changed = TRUE;
}

void dict_unset(struct dict_transaction_context *ctx,
		const char *key)
{
	i_assert(dict_key_prefix_is_valid(key, ctx->set.username));
	struct event_passthrough *e = event_create_passthrough(ctx->event)->
		set_name("dict_unset_key")->
		add_str("key", key);

	e_debug(e->event(), "Unsetting '%s'", key);

	T_BEGIN {
		ctx->dict->v.unset(ctx, key);
	} T_END;
	ctx->changed = TRUE;
}

void dict_atomic_inc(struct dict_transaction_context *ctx,
		     const char *key, long long diff)
{
	i_assert(dict_key_prefix_is_valid(key, ctx->set.username));
	struct event_passthrough *e = event_create_passthrough(ctx->event)->
		set_name("dict_increment_key")->
		add_str("key", key);

	e_debug(e->event(), "Incrementing '%s' with %lld", key, diff);

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

void dict_op_settings_dup(const struct dict_op_settings *source,
			  struct dict_op_settings_private *dest_r)
{
	i_zero(dest_r);
	dest_r->username = i_strdup(source->username);
	dest_r->home_dir = i_strdup(source->home_dir);
	dest_r->expire_secs = source->expire_secs;
	dest_r->no_slowness_warning = source->no_slowness_warning;
	dest_r->hide_log_values = source->hide_log_values;
}

void dict_op_settings_private_free(struct dict_op_settings_private *set)
{
	i_free(set->username);
	i_free(set->home_dir);
}
