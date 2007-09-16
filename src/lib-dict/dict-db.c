/* Copyright (C) 2006 PT.COM / SAPO. Code by Tianyan Liu */

#include "lib.h"
#include "dict-private.h"

#ifdef BUILD_DB
#include <stdlib.h>
#include <db.h>

struct db_dict {
	struct dict dict;
	enum dict_data_type value_type;
	pool_t pool;
	
	DB_ENV *db_env;
	DB *pdb;
	DB *sdb;
};

struct db_dict_iterate_context {
	struct dict_iterate_context ctx;
	pool_t pool;

	DBC *cursor;
	char *path;
	unsigned int path_len;

	DBT pkey, pdata;

	int (*iterate_next)(struct db_dict_iterate_context *ctx,
			    const char **key_r, const char **value_r);

	enum dict_iterate_flags flags;
};

struct db_dict_transaction_context {
	struct dict_transaction_context ctx;

	DB_TXN *tid;
};

static void db_dict_deinit(struct dict *_dict);

static int associate_key(DB *pdb ATTR_UNUSED,
			 const DBT *pkey ATTR_UNUSED,
			 const DBT *pdata, DBT *skey)
{
	memset(skey, 0, sizeof(*skey));
	skey->data = pdata->data;
	skey->size = pdata->size;
	return 0;
}

static int uint32_t_compare(DB *db ATTR_UNUSED,
			    const DBT *keya, const DBT *keyb)
{
	const uint32_t *ua = keya->data, *ub = keyb->data;

	return *ua > *ub ? 1 :
		(*ua < *ub ? -1 : 0);
}

static struct dict *db_dict_init(struct dict *driver, const char *uri,
				 enum dict_data_type value_type,
				 const char *username ATTR_UNUSED)
{
	struct db_dict *dict;
	const char *hdir;
	DB_TXN *tid = NULL;
	pool_t pool;
	int ret;
	
	pool = pool_alloconly_create("db dict", 1024);
	dict = p_new(pool, struct db_dict, 1);
	dict->pool = pool;
	dict->dict = *driver;

	/* prepare the environment */
	ret = db_env_create(&dict->db_env, 0);
	if (ret != 0) {
		i_error("db_env:%s\n", db_strerror(ret));
		pool_unref(&pool);
		return NULL;
	}

	dict->db_env->set_errfile(dict->db_env, stderr);
	dict->db_env->set_errpfx(dict->db_env, "db_env");

	hdir = strrchr(uri, '/');
	if (hdir != NULL)
		hdir = t_strndup(uri, hdir - uri);

	ret = dict->db_env->open(dict->db_env, hdir, DB_CREATE | 
				 DB_INIT_MPOOL | DB_INIT_TXN, 0);
	if (ret != 0) {
		pool_unref(&pool);
		return NULL;
	}

	ret = dict->db_env->txn_begin(dict->db_env, NULL, &tid, 0);
	if (ret != 0) {
		pool_unref(&pool);
		return NULL;
	}

	/* create both primary and secondary databases */
	ret = db_create(&dict->pdb, dict->db_env, 0);
	if (ret != 0) {
		i_error("primary db:%s\n", db_strerror(ret));
		db_dict_deinit(&dict->dict);
		return NULL;
	}
	dict->pdb->set_errfile(dict->pdb, stderr);
	dict->pdb->set_errpfx(dict->pdb, "primary db");

	ret = db_create(&dict->sdb, dict->db_env, 0);
	if (ret != 0) {
		i_error("secondary db:%s\n", db_strerror(ret));
		db_dict_deinit(&dict->dict);
		return NULL;
	}
	dict->pdb->set_errfile(dict->pdb, stderr);
	dict->pdb->set_errpfx(dict->pdb, "secondary db");

	if (dict->pdb->open(dict->pdb, tid, uri, NULL,
			    DB_BTREE, DB_CREATE, 0) != 0) {
		db_dict_deinit(&dict->dict);
		return NULL;
	}

	if (dict->sdb->set_flags(dict->sdb, DB_DUP) != 0) {
		db_dict_deinit(&dict->dict);
		return NULL;
	}
	
	/* by default db compare keys as if they are strings.
	   if we store uint32_t, then we need a customized
	   compare function */
	dict->value_type = value_type;
	if (value_type == DICT_DATA_TYPE_UINT32) {
		if (dict->sdb->set_bt_compare(dict->sdb,
					      uint32_t_compare) != 0) {
			db_dict_deinit(&dict->dict);
			return NULL;
		}
	}

	if (dict->sdb->open(dict->sdb, tid, NULL, NULL,
			    DB_BTREE, DB_CREATE, 0) != 0) {
		db_dict_deinit(&dict->dict);
		return NULL;
	}
	
	if (dict->pdb->associate(dict->pdb, tid, dict->sdb,
				 associate_key, DB_CREATE) != 0) {
		db_dict_deinit(&dict->dict);
		return NULL;
	}
	
	return &dict->dict;
}

static void db_dict_deinit(struct dict *_dict)
{
	struct db_dict *dict = (struct db_dict *)_dict;

	if (dict->pdb != NULL)
		dict->pdb->close(dict->pdb, 0);
	if (dict->sdb != NULL)
		dict->sdb->close(dict->sdb, 0);
	pool_unref(&dict->pool);
}

static int db_dict_iterate_set(struct db_dict_iterate_context *ctx, int ret,
			       const char **key_r, const char **value_r)
{
	struct db_dict *dict = (struct db_dict *)ctx->ctx.dict;

	if (ret == DB_NOTFOUND)
		return 0;
	else if (ret != 0)
		return -1;
	
	p_clear(ctx->pool);
	*key_r = p_strndup(ctx->pool, ctx->pkey.data, ctx->pkey.size);

	switch (dict->value_type) {
	case DICT_DATA_TYPE_UINT32:
		i_assert(ctx->pdata.size == sizeof(uint32_t));
		*value_r = p_strdup(ctx->pool,
				    dec2str(*((uint32_t *)ctx->pdata.data)));
		break;
	case DICT_DATA_TYPE_STRING:
		*value_r = p_strndup(ctx->pool,
				     ctx->pdata.data, ctx->pdata.size);
		break;
	}
	return 1;
}

static int db_dict_lookup(struct dict *_dict, pool_t pool,
			  const char *key, const char **value_r)
{
	struct db_dict *dict = (struct db_dict *)_dict;
	DBT pkey, pdata;
	int ret;

	memset(&pkey, 0, sizeof(DBT));
	memset(&pdata, 0, sizeof(DBT));

	pkey.data = (char *)key;
	pkey.size = strlen(key);

	ret = dict->pdb->get(dict->pdb, NULL, &pkey, &pdata, 0);
	if (ret == DB_NOTFOUND)
		return 0;
	else if (ret != 0)
		return -1;

	switch (dict->value_type) {
	case DICT_DATA_TYPE_UINT32:
		i_assert(pdata.size == sizeof(uint32_t));
		*value_r = p_strdup(pool, dec2str(*((uint32_t *)pdata.data)));
		break;
	case DICT_DATA_TYPE_STRING:
		*value_r = p_strndup(pool, pdata.data, pdata.size);
		break;
	}
	return 1;
}

static int db_dict_iterate_next(struct db_dict_iterate_context *ctx,
				const char **key_r, const char **value_r)
{
	DBT pkey, pdata, skey;
	int ret;

	memset(&pkey, 0, sizeof(pkey));
	memset(&pdata, 0, sizeof(pdata));
	memset(&skey, 0, sizeof(skey));

	if ((ctx->flags & DICT_ITERATE_FLAG_SORT_BY_VALUE) != 0) {
		while ((ret = ctx->cursor->c_pget(ctx->cursor, &skey,
						  &ctx->pkey, &ctx->pdata,
						  DB_NEXT)) == 0) {
			/* make sure the path matches */
			if (ctx->path == NULL)
				break;
			if (ctx->path_len <= ctx->pkey.size &&
			    strncmp(ctx->path, ctx->pkey.data,
				    ctx->path_len) == 0)
				break;
		}
	} else {
		ret = ctx->cursor->c_get(ctx->cursor, &ctx->pkey, &ctx->pdata,
					 DB_NEXT);
		if (ctx->path != NULL && ret == 0 &&
		    (ctx->path_len > ctx->pkey.size ||
		     strncmp(ctx->path, ctx->pkey.data, ctx->path_len) != 0)) {
			/* there are no more matches */
			return 0;
		}
	}

	return db_dict_iterate_set(ctx, ret, key_r, value_r);
}

static int db_dict_iterate_first(struct db_dict_iterate_context *ctx,
				 const char **key_r, const char **value_r)
{
	struct db_dict *dict = (struct db_dict *)ctx->ctx.dict;
	int ret;

	ctx->iterate_next = db_dict_iterate_next;

	if ((ctx->flags & DICT_ITERATE_FLAG_SORT_BY_VALUE) != 0) {
		/* iterating through secondary database returns values sorted */
		ret = dict->sdb->cursor(dict->sdb, NULL, &ctx->cursor, 0);
	} else {
		ret = dict->pdb->cursor(dict->pdb, NULL, &ctx->cursor, 0);
		if (ret == 0 && ctx->path != NULL) {
			ctx->pkey.data = ctx->path;
			ctx->pkey.size = strlen(ctx->path);

			ret = ctx->cursor->c_get(ctx->cursor, &ctx->pkey,
						 &ctx->pdata, DB_SET_RANGE);
			if (ret == 0 && strncmp(ctx->path, ctx->pkey.data,
						ctx->pkey.size) != 0)
				return 0;
			return db_dict_iterate_set(ctx, ret, key_r, value_r);
		}
	}
	return db_dict_iterate_next(ctx, key_r, value_r);
}

static struct dict_iterate_context *
db_dict_iterate_init(struct dict *_dict, const char *path,
		     enum dict_iterate_flags flags)
{
        struct db_dict_iterate_context *ctx;

	ctx = i_new(struct db_dict_iterate_context, 1);
	ctx->pool = pool_alloconly_create("db iter", 1024);
	ctx->cursor = NULL;
	ctx->ctx.dict = _dict;
	ctx->flags = flags;
	ctx->path = i_strdup_empty(path);
	ctx->path_len = ctx->path == NULL ? 0 : strlen(ctx->path);
	
	ctx->iterate_next = db_dict_iterate_first;
	return &ctx->ctx;
}

static int db_dict_iterate(struct dict_iterate_context *_ctx,
			   const char **key_r, const char **value_r)
{
	struct db_dict_iterate_context *ctx =
		(struct db_dict_iterate_context *)_ctx;

	return ctx->iterate_next(ctx, key_r, value_r);
}

static void db_dict_iterate_deinit(struct dict_iterate_context *_ctx)
{
	struct db_dict_iterate_context *ctx =
		(struct db_dict_iterate_context *)_ctx;

	ctx->cursor->c_close(ctx->cursor);
	pool_unref(&ctx->pool);
	i_free(ctx->path);
	i_free(ctx);
}

static struct dict_transaction_context *
db_dict_transaction_init(struct dict *_dict)
{
	struct db_dict *dict = (struct db_dict *)_dict;
	struct db_dict_transaction_context *ctx;

	ctx = i_new(struct db_dict_transaction_context, 1);
	ctx->ctx.dict = _dict;
	dict->db_env->txn_begin(dict->db_env, NULL, &ctx->tid, 0);

	return &ctx->ctx;
}

static int db_dict_transaction_commit(struct dict_transaction_context *_ctx)
{
	struct db_dict_transaction_context *ctx =
		(struct db_dict_transaction_context *)_ctx;
	int ret;

	ret = ctx->tid->commit(ctx->tid, 0);
	i_free(ctx);
	return ret == 0 ? 0 : -1;
}

static void db_dict_transaction_rollback(struct dict_transaction_context *_ctx)
{
	struct db_dict_transaction_context *ctx =
		(struct db_dict_transaction_context *)_ctx;

	ctx->tid->discard(ctx->tid, 0);
	i_free(ctx);
}

static void db_dict_set(struct dict_transaction_context *_ctx,
			const char *key, const char *value)
{
	struct db_dict_transaction_context *ctx =
		(struct db_dict_transaction_context *)_ctx;
	struct db_dict *dict = (struct db_dict *)_ctx->dict;
	DBT dkey, ddata;

	memset(&dkey, 0, sizeof(dkey));
	memset(&ddata, 0, sizeof(ddata));

	dkey.data = (char *)key;
	dkey.size = strlen(key);

	if (dict->value_type == DICT_DATA_TYPE_UINT32) {
		uint32_t ivalue = (uint32_t)strtoul(value, NULL, 10);

		ddata.data = &ivalue;
		ddata.size = sizeof(ivalue);
	} else {
		ddata.data = (char *)value;
		ddata.size = strlen(value);
	}

	dict->pdb->put(dict->pdb, ctx->tid, &dkey, &ddata, 0);
}

static void db_dict_unset(struct dict_transaction_context *_ctx,
			  const char *key)
{
	struct db_dict_transaction_context *ctx =
		(struct db_dict_transaction_context *)_ctx;
	struct db_dict *dict = (struct db_dict *)_ctx->dict;
	DBT dkey;

	memset(&dkey, 0, sizeof(dkey));
	dkey.data = (char *)key;
	dkey.size = strlen(key);
	
	dict->pdb->del(dict->pdb, ctx->tid, &dkey, 0);
}

static void db_dict_atomic_inc(struct dict_transaction_context *_ctx,
			       const char *key, long long diff)
{
	/* FIXME */
}

struct dict dict_driver_db = {
	MEMBER(name) "db",
	{
		db_dict_init,
		db_dict_deinit,
		db_dict_lookup,
		db_dict_iterate_init,
		db_dict_iterate,
		db_dict_iterate_deinit,
		db_dict_transaction_init,
		db_dict_transaction_commit,
		db_dict_transaction_rollback,
		db_dict_set,
		db_dict_unset,
		db_dict_atomic_inc
	}
};
#endif
