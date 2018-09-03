/* Copyright (c) 2004-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "sql-api-private.h"
#include "sql-db-cache.h"

#define SQL_DB_CACHE_CONTEXT(obj) \
	MODULE_CONTEXT_REQUIRE(obj, sql_db_cache_module)

struct sql_db_cache_context {
	union sql_db_module_context module_ctx;
	struct sql_db *prev, *next; /* These are set while refcount=0 */

	struct sql_db_cache *cache;
	int refcount;
	char *key;
	void (*orig_deinit)(struct sql_db *db);
};

struct sql_db_cache {
	HASH_TABLE(char *, struct sql_db *) dbs;
	unsigned int unused_count, max_unused_connections;
	struct sql_db *unused_tail, *unused_head;
};

static MODULE_CONTEXT_DEFINE_INIT(sql_db_cache_module, &sql_db_module_register);

static void sql_db_cache_db_deinit(struct sql_db *db)
{
	struct sql_db_cache_context *ctx = SQL_DB_CACHE_CONTEXT(db);
	struct sql_db_cache_context *head_ctx;

	if (--ctx->refcount > 0)
		return;

	ctx->cache->unused_count++;
	if (ctx->cache->unused_tail == NULL)
		ctx->cache->unused_tail = db;
	else {
		head_ctx = SQL_DB_CACHE_CONTEXT(ctx->cache->unused_head);
		head_ctx->next = db;
	}
	ctx->prev = ctx->cache->unused_head;
	ctx->cache->unused_head = db;
}

static void sql_db_cache_unlink(struct sql_db_cache_context *ctx)
{
	struct sql_db_cache_context *prev_ctx, *next_ctx;

	i_assert(ctx->refcount == 0);

	if (ctx->prev == NULL)
		ctx->cache->unused_tail = ctx->next;
	else {
		prev_ctx = SQL_DB_CACHE_CONTEXT(ctx->prev);
		prev_ctx->next = ctx->next;
	}
	if (ctx->next == NULL)
		ctx->cache->unused_head = ctx->prev;
	else {
		next_ctx = SQL_DB_CACHE_CONTEXT(ctx->next);
		next_ctx->prev = ctx->prev;
	}
	ctx->cache->unused_count--;
}

static void sql_db_cache_free_tail(struct sql_db_cache *cache)
{
	struct sql_db *db;
	struct sql_db_cache_context *ctx;

	db = cache->unused_tail;
	ctx = SQL_DB_CACHE_CONTEXT(db);
	sql_db_cache_unlink(ctx);
	hash_table_remove(cache->dbs, ctx->key);

	i_free(ctx->key);
	ctx->orig_deinit(db);
	i_free(ctx);
}

static void sql_db_cache_drop_oldest(struct sql_db_cache *cache)
{
	while (cache->unused_count >= cache->max_unused_connections)
		sql_db_cache_free_tail(cache);
}

int sql_db_cache_new2(struct sql_db_cache *cache, const struct sql_settings *set,
		      struct sql_db **db_r, const char **error_r)
{
	struct sql_db_cache_context *ctx;
	struct sql_db *db;
	char *key;

	key = i_strdup_printf("%s\t%s", set->driver, set->connect_string);
	db = hash_table_lookup(cache->dbs, key);
	if (db != NULL) {
		ctx = SQL_DB_CACHE_CONTEXT(db);
		if (ctx->refcount == 0) {
			sql_db_cache_unlink(ctx);
			ctx->prev = ctx->next = NULL;
		}
		i_free(key);
	} else {
		sql_db_cache_drop_oldest(cache);

		if (sql_init_full(set, &db, error_r) < 0) {
			i_free(key);
			return -1;
		}

		ctx = i_new(struct sql_db_cache_context, 1);
		ctx->cache = cache;
		ctx->key = key;
		ctx->orig_deinit = db->v.deinit;
		db->v.deinit = sql_db_cache_db_deinit;

		MODULE_CONTEXT_SET(db, sql_db_cache_module, ctx);
		hash_table_insert(cache->dbs, ctx->key, db);
	}

	ctx->refcount++;
	*db_r = db;
	return 0;
}

struct sql_db *
sql_db_cache_new(struct sql_db_cache *cache,
		 const char *db_driver, const char *connect_string)
{
	const char *error;
	struct sql_db *db;
	struct sql_settings set = {
		.driver = db_driver,
		.connect_string = connect_string,
	};

	if (sql_db_cache_new2(cache, &set, &db, &error) < 0)
		i_fatal("%s", error);

	return db;
}

struct sql_db_cache *sql_db_cache_init(unsigned int max_unused_connections)
{
	struct sql_db_cache *cache;

	cache = i_new(struct sql_db_cache, 1);
	hash_table_create(&cache->dbs, default_pool, 0, str_hash, strcmp);
	cache->max_unused_connections = max_unused_connections;
	return cache;
}

void sql_db_cache_deinit(struct sql_db_cache **_cache)
{
	struct sql_db_cache *cache = *_cache;

	*_cache = NULL;
	while (cache->unused_tail != NULL)
		sql_db_cache_free_tail(cache);
	hash_table_destroy(&cache->dbs);
	i_free(cache);
}
