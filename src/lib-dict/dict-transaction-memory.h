#ifndef DICT_TRANSACTION_MEMORY_H
#define DICT_TRANSACTION_MEMORY_H

#include "dict-private.h"

enum dict_change_type {
	DICT_CHANGE_TYPE_SET,
	DICT_CHANGE_TYPE_UNSET,
	DICT_CHANGE_TYPE_APPEND,
	DICT_CHANGE_TYPE_INC
};

struct dict_transaction_memory_change {
	enum dict_change_type type;
	const char *key;
	union {
		const char *str;
		long long diff;
	} value;
};

struct dict_transaction_memory_context {
	struct dict_transaction_context ctx;
	pool_t pool;
	ARRAY(struct dict_transaction_memory_change) changes;
};

void dict_transaction_memory_init(struct dict_transaction_memory_context *ctx,
				  struct dict *dict, pool_t pool);
void dict_transaction_memory_rollback(struct dict_transaction_context *ctx);

void dict_transaction_memory_set(struct dict_transaction_context *ctx,
				 const char *key, const char *value);
void dict_transaction_memory_unset(struct dict_transaction_context *ctx,
				   const char *key);
void dict_transaction_memory_append(struct dict_transaction_context *_ctx,
				    const char *key, const char *value);
void dict_transaction_memory_atomic_inc(struct dict_transaction_context *ctx,
					const char *key, long long diff);

#endif
