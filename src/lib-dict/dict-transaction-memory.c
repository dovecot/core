/* Copyright (c) 2005-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "dict-transaction-memory.h"

void dict_transaction_memory_init(struct dict_transaction_memory_context *ctx,
				  struct dict *dict, pool_t pool)
{
	ctx->ctx.dict = dict;
	ctx->pool = pool;
	p_array_init(&ctx->changes, pool, 32);
}

void dict_transaction_memory_rollback(struct dict_transaction_context *_ctx)
{
	struct dict_transaction_memory_context *ctx =
		(struct dict_transaction_memory_context *)_ctx;

	pool_unref(&ctx->pool);
}

void dict_transaction_memory_set(struct dict_transaction_context *_ctx,
				 const char *key, const char *value)
{
	struct dict_transaction_memory_context *ctx =
		(struct dict_transaction_memory_context *)_ctx;
	struct dict_transaction_memory_change *change;

	change = array_append_space(&ctx->changes);
	change->type = DICT_CHANGE_TYPE_SET;
	change->key = p_strdup(ctx->pool, key);
	change->value.str = p_strdup(ctx->pool, value);
}

void dict_transaction_memory_unset(struct dict_transaction_context *_ctx,
				   const char *key)
{
	struct dict_transaction_memory_context *ctx =
		(struct dict_transaction_memory_context *)_ctx;
	struct dict_transaction_memory_change *change;

	change = array_append_space(&ctx->changes);
	change->type = DICT_CHANGE_TYPE_UNSET;
	change->key = p_strdup(ctx->pool, key);
}

void dict_transaction_memory_append(struct dict_transaction_context *_ctx,
				    const char *key, const char *value)
{
	struct dict_transaction_memory_context *ctx =
		(struct dict_transaction_memory_context *)_ctx;
	struct dict_transaction_memory_change *change;

	change = array_append_space(&ctx->changes);
	change->type = DICT_CHANGE_TYPE_APPEND;
	change->key = p_strdup(ctx->pool, key);
	change->value.str = p_strdup(ctx->pool, value);
}

void dict_transaction_memory_atomic_inc(struct dict_transaction_context *_ctx,
					const char *key, long long diff)
{
	struct dict_transaction_memory_context *ctx =
		(struct dict_transaction_memory_context *)_ctx;
	struct dict_transaction_memory_change *change;

	change = array_append_space(&ctx->changes);
	change->type = DICT_CHANGE_TYPE_INC;
	change->key = p_strdup(ctx->pool, key);
	change->value.diff = diff;
}
