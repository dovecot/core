/* Copyright (C) 2005 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "dict-sql.h"
#include "dict-private.h"

static array_t ARRAY_DEFINE(dict_classes, struct dict *);
static int dict_count = 0;

static void dict_class_register_all(void)
{
	dict_sql_register();
}

static void dict_class_unregister_all(void)
{
	dict_sql_unregister();
}

static struct dict *dict_class_lookup(const char *name)
{
	struct dict *const *dicts;
	unsigned int i, count;

	dicts = array_get(&dict_classes, &count);
	for (i = 0; i < count; i++) {
		if (strcmp(dicts[i]->name, name) == 0)
			return dicts[i];
	}
	return NULL;
}

void dict_class_register(struct dict *dict_class)
{
	if (!array_is_created(&dict_classes))
		ARRAY_CREATE(&dict_classes, default_pool, struct dict *, 8);

	if (dict_class_lookup(dict_class->name) != NULL) {
		i_fatal("dict_class_register(%s): Already registered",
			dict_class->name);
	}
	array_append(&dict_classes, &dict_class, 1);
}

void dict_class_unregister(struct dict *dict_class)
{
	struct dict *const *dicts;
	unsigned int i, count;

	dicts = array_get(&dict_classes, &count);
	for (i = 0; i < count; i++) {
		if (dicts[i] == dict_class) {
			array_delete(&dict_classes, i, 1);
			break;
		}
	}

	i_assert(i < count);

	if (array_count(&dict_classes) == 0)
		array_free(&dict_classes);
}

struct dict *dict_init(const char *uri)
{
	struct dict *dict;
	const char *p;

	if (dict_count++ == 0)
		dict_class_register_all();

	p = strchr(uri, ':');
	if (p == NULL) {
		i_error("URI is missing ':': %s", uri);
		return NULL;
	}

	t_push();
	dict = dict_class_lookup(t_strdup_until(uri, p));
	t_pop();
	if (dict == NULL)
		return NULL;

	return dict->v.init(dict, p+1);
}

void dict_deinit(struct dict *dict)
{
	dict->v.deinit(dict);

	if (--dict_count == 0)
		dict_class_unregister_all();
}

char *dict_lookup(struct dict *dict, pool_t pool, const char *key)
{
	return dict->v.lookup(dict, pool, key);
}

struct dict_iterate_context *
dict_iterate_init(struct dict *dict, const char *path, int recurse)
{
	return dict->v.iterate_init(dict, path, recurse);
}

int dict_iterate(struct dict_iterate_context *ctx,
		 const char **key_r, const char **value_r)
{
	return ctx->dict->v.iterate(ctx, key_r, value_r);
}

void dict_iterate_deinit(struct dict_iterate_context *ctx)
{
	ctx->dict->v.iterate_deinit(ctx);
}

struct dict_transaction_context *dict_transaction_begin(struct dict *dict)
{
	return dict->v.transaction_init(dict);
}

int dict_transaction_commit(struct dict_transaction_context *ctx)
{
	return ctx->dict->v.transaction_commit(ctx);
}

void dict_transaction_rollback(struct dict_transaction_context *ctx)
{
	ctx->dict->v.transaction_rollback(ctx);
}

void dict_set(struct dict_transaction_context *ctx,
	      const char *key, const char *value)
{
	ctx->dict->v.set(ctx, key, value);
}

void dict_atomic_inc(struct dict_transaction_context *ctx,
		     const char *key, long long diff)
{
	ctx->dict->v.atomic_inc(ctx, key, diff);
}
