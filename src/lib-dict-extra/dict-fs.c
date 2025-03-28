/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "fs-api.h"
#include "istream.h"
#include "str.h"
#include "dict-transaction-memory.h"
#include "dict-private.h"

struct fs_dict {
	struct dict dict;
	struct fs *fs;
};

struct fs_dict_iterate_context {
	struct dict_iterate_context ctx;
	char *path;
	enum dict_iterate_flags flags;
	unsigned int key_count;
	pool_t value_pool;
	struct fs_iter *fs_iter;
	const char *const *values;
	char *error;
};

static int
fs_dict_init(const struct dict *dict_driver, struct event *event,
	     struct dict **dict_r, const char **error_r)
{
	struct fs_parameters fs_param;
	struct fs *fs;
	struct fs_dict *dict;

	i_zero(&fs_param);
	if (fs_init_auto(event, &fs_param, &fs, error_r) <= 0)
		return -1;

	dict = i_new(struct fs_dict, 1);
	dict->dict = *dict_driver;
	dict->fs = fs;

	*dict_r = &dict->dict;
	return 0;
}

static void fs_dict_deinit(struct dict *_dict)
{
	struct fs_dict *dict = (struct fs_dict *)_dict;

	fs_deinit(&dict->fs);
	i_free(dict);
}

/* Remove unsafe paths */
static const char *fs_dict_escape_key(const char *key)
{
	const char *ptr;
	string_t *new_key = NULL;
	/* we take the slow path always if we see potential
	   need for escaping */
	while ((ptr = strstr(key, "/.")) != NULL) {
		/* move to the first dot */
		const char *ptr2 = ptr + 1;
		/* find position of non-dot */
		while (*ptr2 == '.') ptr2++;
		if (new_key == NULL)
			new_key = t_str_new(strlen(key));
		str_append_data(new_key, key, ptr - key);
		/* if ptr2 is / or end of string, escape */
		if (*ptr2 == '/' || *ptr2 == '\0')
			str_append(new_key, "/...");
		else
			str_append(new_key, "/.");
		key = ptr + 2;
	}
	if (new_key == NULL)
		return key;
	str_append(new_key, key);
	return str_c(new_key);
}

static const char *fs_dict_get_full_key(const char *username, const char *key)
{
	key = fs_dict_escape_key(key);
	if (str_begins(key, DICT_PATH_SHARED, &key))
		return key;
	else if (str_begins(key, DICT_PATH_PRIVATE, &key))
		return t_strdup_printf("%s/%s", username, key);
	else
		i_unreached();
}

static int fs_dict_lookup(struct dict *_dict, const struct dict_op_settings *set,
			  pool_t pool, const char *key,
			  const char *const **values_r, const char **error_r)
{
	struct fs_dict *dict = (struct fs_dict *)_dict;
	struct fs_file *file;
	struct istream *input;
	const unsigned char *data;
	size_t size;
	const char *path;
	string_t *str;
	int ret;

	path = fs_dict_get_full_key(set->username, key);
	file = fs_file_init(dict->fs, path, FS_OPEN_MODE_READONLY);
	input = fs_read_stream(file, IO_BLOCK_SIZE);
	(void)i_stream_read(input);

	str = str_new(pool, i_stream_get_data_size(input)+1);
	while ((ret = i_stream_read_more(input, &data, &size)) > 0) {
		str_append_data(str, data, size);
		i_stream_skip(input, size);
	}
	i_assert(ret == -1);

	if (input->stream_errno == 0) {
		const char **values = p_new(pool, const char *, 2);
		values[0] = str_c(str);
		*values_r = values;
		ret = 1;
	} else {
		if (input->stream_errno == ENOENT)
			ret = 0;
		else {
			*error_r = t_strdup_printf("read(%s) failed: %s",
				path, i_stream_get_error(input));
		}
	}

	i_stream_unref(&input);
	fs_file_deinit(&file);
	return ret;
}

static struct dict_iterate_context *
fs_dict_iterate_init(struct dict *_dict, const struct dict_op_settings *set,
		     const char *path, enum dict_iterate_flags flags)
{
	struct fs_dict *dict = (struct fs_dict *)_dict;
	struct fs_dict_iterate_context *iter;

	iter = i_new(struct fs_dict_iterate_context, 1);
	iter->ctx.dict = _dict;
	iter->path = i_strdup(path);
	iter->flags = flags;
	iter->value_pool = pool_alloconly_create("iterate value pool", 128);
	iter->fs_iter = fs_iter_init(dict->fs,
				     fs_dict_get_full_key(set->username, path), 0);

	const char *unsupported = NULL;
	if ((flags & DICT_ITERATE_FLAG_RECURSE) != 0)
		unsupported = "DICT_ITERATE_FLAG_RECURSE";
	else if ((flags & DICT_ITERATE_FLAG_SORT_BY_KEY) != 0)
		unsupported = "DICT_ITERATE_FLAG_SORT_BY_KEY";
	else if ((flags & DICT_ITERATE_FLAG_SORT_BY_VALUE) != 0)
		unsupported = "DICT_ITERATE_FLAG_SORT_BY_VALUE";
	if (unsupported != NULL) {
		iter->error = i_strdup_printf(
			"dict-fs doesn't currently support %s", unsupported);
	}
	return &iter->ctx;
}

static bool fs_dict_iterate(struct dict_iterate_context *ctx,
			    const char **key_r, const char *const **values_r)
{
	struct fs_dict_iterate_context *iter =
		(struct fs_dict_iterate_context *)ctx;
	const char *path, *error;
	int ret;

	if (iter->error != NULL || iter->fs_iter == NULL)
		return FALSE;

	*key_r = fs_iter_next(iter->fs_iter);
	if (*key_r == NULL) {
		if (iter->key_count > 0 ||
		    (iter->flags & DICT_ITERATE_FLAG_EXACT_KEY) == 0)
			return FALSE;

		if (fs_iter_deinit(&iter->fs_iter, &error) == 0)
			return FALSE;
		if (errno != ENOTDIR) {
			iter->error = i_strdup(error);
			return FALSE;
		}
		/* the path itself is the only key we are going to return */
		*key_r = "";
	}
	iter->key_count++;

	p_clear(iter->value_pool);
	path = p_strconcat(iter->value_pool, iter->path, *key_r, NULL);
	if ((iter->flags & DICT_ITERATE_FLAG_NO_VALUE) != 0) {
		*key_r = path;
		return TRUE;
	}
	struct dict_op_settings set = {
		.username = ctx->set.username,
	};
	ret = fs_dict_lookup(ctx->dict, &set, iter->value_pool, path,
			     &iter->values, &error);
	if (ret < 0) {
		/* I/O error */
		iter->error = i_strdup(error);
		return FALSE;
	} else if (ret == 0) {
		/* file was just deleted, just skip to next one */
		return fs_dict_iterate(ctx, key_r, values_r);
	}
	*key_r = path;
	*values_r = iter->values;
	return TRUE;
}

static int fs_dict_iterate_deinit(struct dict_iterate_context *ctx,
				  const char **error_r)
{
	struct fs_dict_iterate_context *iter =
		(struct fs_dict_iterate_context *)ctx;
	const char *error;
	int ret;

	if (fs_iter_deinit(&iter->fs_iter, &error) < 0 && iter->error == NULL)
		iter->error = i_strdup(error);

	ret = iter->error != NULL ? -1 : 0;
	*error_r = t_strdup(iter->error);

	pool_unref(&iter->value_pool);
	i_free(iter->path);
	i_free(iter->error);
	i_free(iter);
	return ret;
}

static struct dict_transaction_context *
fs_dict_transaction_init(struct dict *_dict)
{
	struct dict_transaction_memory_context *ctx;
	pool_t pool;

	pool = pool_alloconly_create("file dict transaction", 2048);
	ctx = p_new(pool, struct dict_transaction_memory_context, 1);
	dict_transaction_memory_init(ctx, _dict, pool);
	return &ctx->ctx;
}

static int fs_dict_write_changes(struct dict_transaction_memory_context *ctx,
				 const char **error_r)
{
	struct fs_dict *dict = (struct fs_dict *)ctx->ctx.dict;
	struct fs_file *file;
	const struct dict_transaction_memory_change *change;
	const char *key;
	int ret = 0;

	array_foreach(&ctx->changes, change) {
		key = fs_dict_get_full_key(ctx->ctx.set.username, change->key);
		switch (change->type) {
		case DICT_CHANGE_TYPE_SET:
			file = fs_file_init(dict->fs, key,
					    FS_OPEN_MODE_REPLACE);
			if (fs_write(file, change->value.str, strlen(change->value.str)) < 0) {
				*error_r = t_strdup_printf(
					"fs_write(%s) failed: %s", key,
					fs_file_last_error(file));
				ret = -1;
			}
			fs_file_deinit(&file);
			break;
		case DICT_CHANGE_TYPE_UNSET:
			file = fs_file_init(dict->fs, key, FS_OPEN_MODE_READONLY);
			if (fs_delete(file) < 0) {
				*error_r = t_strdup_printf(
					"fs_delete(%s) failed: %s", key,
					fs_file_last_error(file));
				ret = -1;
			}
			fs_file_deinit(&file);
			break;
		case DICT_CHANGE_TYPE_INC:
			i_unreached();
		}
		if (ret < 0)
			return -1;
	}
	return 0;
}

static void
fs_dict_transaction_commit(struct dict_transaction_context *_ctx,
			   bool async ATTR_UNUSED,
			   dict_transaction_commit_callback_t *callback,
			   void *context)
{
	struct dict_transaction_memory_context *ctx =
		(struct dict_transaction_memory_context *)_ctx;
	struct dict_commit_result result = { .ret = 1 };


	if (fs_dict_write_changes(ctx, &result.error) < 0)
		result.ret = -1;
	pool_unref(&ctx->pool);

	callback(&result, context);
}

struct dict dict_driver_fs = {
	.name = "fs",
	.v = {
		.init = fs_dict_init,
		.deinit = fs_dict_deinit,
		.lookup = fs_dict_lookup,
		.iterate_init = fs_dict_iterate_init,
		.iterate = fs_dict_iterate,
		.iterate_deinit = fs_dict_iterate_deinit,
		.transaction_init = fs_dict_transaction_init,
		.transaction_commit = fs_dict_transaction_commit,
		.transaction_rollback = dict_transaction_memory_rollback,
		.set = dict_transaction_memory_set,
		.unset = dict_transaction_memory_unset,
	}
};
