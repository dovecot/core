/* Copyright (c) 2004-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "sql-api-private.h"
#include "sql-pool.h"

#define SQL_POOL_CONTEXT(obj) \
	MODULE_CONTEXT(obj, sql_pool_module)

struct sql_pool_context {
	union sql_db_module_context module_ctx;
	struct sql_db *prev, *next; /* These are set while refcount=0 */

	struct sql_pool *pool;
	int refcount;
	char *key;
	void (*orig_deinit)(struct sql_db *db);
};

struct sql_pool {
	struct hash_table *dbs;
	unsigned int unused_count, max_unused_connections;
	struct sql_db *unused_tail, *unused_head;
};

static MODULE_CONTEXT_DEFINE_INIT(sql_pool_module, &sql_db_module_register);

static void sql_pool_db_deinit(struct sql_db *db)
{
	struct sql_pool_context *ctx = SQL_POOL_CONTEXT(db);
	struct sql_pool_context *head_ctx;

	if (--ctx->refcount > 0)
		return;

	ctx->pool->unused_count++;
	if (ctx->pool->unused_tail == NULL)
		ctx->pool->unused_tail = db;
	else {
		head_ctx = SQL_POOL_CONTEXT(ctx->pool->unused_head);
		head_ctx->next = db;
	}
	ctx->prev = ctx->pool->unused_head;
	ctx->pool->unused_head = db;
}

static void sql_pool_unlink(struct sql_pool_context *ctx)
{
	struct sql_pool_context *prev_ctx, *next_ctx;

	i_assert(ctx->refcount == 0);

	if (ctx->prev == NULL)
		ctx->pool->unused_tail = ctx->next;
	else {
		prev_ctx = SQL_POOL_CONTEXT(ctx->prev);
		prev_ctx->next = ctx->next;
	}
	if (ctx->next == NULL)
		ctx->pool->unused_head = ctx->prev;
	else {
		next_ctx = SQL_POOL_CONTEXT(ctx->next);
		next_ctx->prev = ctx->prev;
	}
	ctx->pool->unused_count--;
}

static void sql_pool_drop_oldest(struct sql_pool *pool)
{
	struct sql_db *db;
	struct sql_pool_context *ctx;

	while (pool->unused_count >= pool->max_unused_connections) {
		db = pool->unused_tail;
		ctx = SQL_POOL_CONTEXT(db);
		sql_pool_unlink(ctx);

		i_free(ctx->key);
		ctx->orig_deinit(db);
	}
}

struct sql_db *sql_pool_new(struct sql_pool *pool,
			    const char *db_driver, const char *connect_string)
{
	struct sql_pool_context *ctx;
	struct sql_db *db;
	char *key;

	key = i_strdup_printf("%s\t%s", db_driver, connect_string);
	db = hash_table_lookup(pool->dbs, key);
	if (db != NULL) {
		ctx = SQL_POOL_CONTEXT(db);
		if (ctx->refcount == 0) {
			sql_pool_unlink(ctx);
			ctx->prev = ctx->next = NULL;
		}
		i_free(key);
	} else {
		sql_pool_drop_oldest(pool);

		ctx = i_new(struct sql_pool_context, 1);
		ctx->pool = pool;
		ctx->key = key;

		db = sql_init(db_driver, connect_string);
		ctx->orig_deinit = db->v.deinit;
		db->v.deinit = sql_pool_db_deinit;

		MODULE_CONTEXT_SET(db, sql_pool_module, ctx);
		hash_table_insert(pool->dbs, ctx->key, db);
	}

	ctx->refcount++;
	return db;
}

struct sql_pool *sql_pool_init(unsigned int max_unused_connections)
{
	struct sql_pool *pool;

	pool = i_new(struct sql_pool, 1);
	pool->dbs = hash_table_create(default_pool, default_pool, 0, str_hash,
				      (hash_cmp_callback_t *)strcmp);
	pool->max_unused_connections = max_unused_connections;
	return pool;
}

void sql_pool_deinit(struct sql_pool **_pool)
{
	struct sql_pool *pool = *_pool;

	*_pool = NULL;
	hash_table_destroy(&pool->dbs);
	i_free(pool);
}
