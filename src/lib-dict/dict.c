/* Copyright (c) 2005-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "dict-sql.h"
#include "dict-private.h"

static ARRAY_DEFINE(dict_drivers, struct dict *);

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

void dict_driver_register(struct dict *driver)
{
	if (!array_is_created(&dict_drivers))
		i_array_init(&dict_drivers, 8);

	if (dict_driver_lookup(driver->name) != NULL) {
		i_fatal("dict_driver_register(%s): Already registered",
			driver->name);
	}
	array_append(&dict_drivers, &driver, 1);
}

void dict_driver_unregister(struct dict *driver)
{
	struct dict *const *dicts;
	unsigned int idx = -1U;

	array_foreach(&dict_drivers, dicts) {
		if (*dicts == driver) {
			idx = array_foreach_idx(&dict_drivers, dicts);
			break;
		}
	}
	i_assert(idx != -1U);
	array_delete(&dict_drivers, idx, 1);

	if (array_count(&dict_drivers) == 0)
		array_free(&dict_drivers);
}

void dict_drivers_register_builtin(void)
{
	dict_driver_register(&dict_driver_client);
	dict_driver_register(&dict_driver_file);
}

void dict_drivers_unregister_builtin(void)
{
	dict_driver_unregister(&dict_driver_client);
	dict_driver_unregister(&dict_driver_file);
}

struct dict *dict_init(const char *uri, enum dict_data_type value_type,
		       const char *username, const char *base_dir)
{
	struct dict *dict;
	const char *p, *name;

	i_assert(username != NULL);

	p = strchr(uri, ':');
	if (p == NULL) {
		i_error("Dictionary URI is missing ':': %s", uri);
		return NULL;
	}

	T_BEGIN {
		name = t_strdup_until(uri, p);
		dict = dict_driver_lookup(name);
		if (dict == NULL)
			i_error("Unknown dict module: %s", name);
	} T_END;

	return dict == NULL ? NULL :
		dict->v.init(dict, p+1, value_type, username, base_dir);
}

void dict_deinit(struct dict **_dict)
{
	struct dict *dict = *_dict;

	*_dict = NULL;
	dict->v.deinit(dict);
}

int dict_wait(struct dict *dict)
{
	return dict->v.wait == NULL ? 1 : dict->v.wait(dict);
}

static bool dict_key_prefix_is_valid(const char *key)
{
	return strncmp(key, DICT_PATH_SHARED, strlen(DICT_PATH_SHARED)) == 0 ||
		strncmp(key, DICT_PATH_PRIVATE, strlen(DICT_PATH_PRIVATE)) == 0;
}

int dict_lookup(struct dict *dict, pool_t pool, const char *key,
		const char **value_r)
{
	i_assert(dict_key_prefix_is_valid(key));
	return dict->v.lookup(dict, pool, key, value_r);
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
	unsigned int i;

	i_assert(paths[0] != NULL);
	for (i = 0; paths[i] != NULL; i++)
		i_assert(dict_key_prefix_is_valid(paths[i]));
	return dict->v.iterate_init(dict, paths, flags);
}

bool dict_iterate(struct dict_iterate_context *ctx,
		  const char **key_r, const char **value_r)
{
	return ctx->dict->v.iterate(ctx, key_r, value_r);
}

int dict_iterate_deinit(struct dict_iterate_context **_ctx)
{
	struct dict_iterate_context *ctx = *_ctx;

	*_ctx = NULL;
	return ctx->dict->v.iterate_deinit(ctx);
}

struct dict_transaction_context *dict_transaction_begin(struct dict *dict)
{
	return dict->v.transaction_init(dict);
}

int dict_transaction_commit(struct dict_transaction_context **_ctx)
{
	struct dict_transaction_context *ctx = *_ctx;

	*_ctx = NULL;
	return ctx->dict->v.transaction_commit(ctx, FALSE, NULL, NULL);
}

void dict_transaction_commit_async(struct dict_transaction_context **_ctx,
				   dict_transaction_commit_callback_t *callback,
				   void *context)
{
	struct dict_transaction_context *ctx = *_ctx;

	*_ctx = NULL;
	ctx->dict->v.transaction_commit(ctx, TRUE, callback, context);
}

void dict_transaction_rollback(struct dict_transaction_context **_ctx)
{
	struct dict_transaction_context *ctx = *_ctx;

	*_ctx = NULL;
	ctx->dict->v.transaction_rollback(ctx);
}

void dict_set(struct dict_transaction_context *ctx,
	      const char *key, const char *value)
{
	i_assert(dict_key_prefix_is_valid(key));

	ctx->dict->v.set(ctx, key, value);
	ctx->changed = TRUE;
}

void dict_unset(struct dict_transaction_context *ctx,
		const char *key)
{
	i_assert(dict_key_prefix_is_valid(key));

	ctx->dict->v.unset(ctx, key);
	ctx->changed = TRUE;
}

void dict_atomic_inc(struct dict_transaction_context *ctx,
		     const char *key, long long diff)
{
	i_assert(dict_key_prefix_is_valid(key));

	if (diff != 0) {
		ctx->dict->v.atomic_inc(ctx, key, diff);
		ctx->changed = TRUE;
	}
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
	str_append_n(ret, str, (size_t) (p - str));

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
	str_append_n(ret, str, (size_t) (p - str));

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
