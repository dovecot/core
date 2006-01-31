#ifndef __DICT_PRIVATE_H
#define __DICT_PRIVATE_H

#include "dict.h"

struct dict_vfuncs {
	struct dict *(*init)(struct dict *dict_class, const char *uri,
			     const char *username);
	void (*deinit)(struct dict *dict);

	int (*lookup)(struct dict *dict, pool_t pool,
		      const char *key, const char **value_r);

	struct dict_iterate_context *
		(*iterate_init)(struct dict *dict, const char *path,
				bool recurse);
	int (*iterate)(struct dict_iterate_context *ctx,
		       const char **key_r, const char **value_r);
	void (*iterate_deinit)(struct dict_iterate_context *ctx);

	struct dict_transaction_context *(*transaction_init)(struct dict *dict);
	int (*transaction_commit)(struct dict_transaction_context *ctx);
	void (*transaction_rollback)(struct dict_transaction_context *ctx);

	void (*set)(struct dict_transaction_context *ctx,
		    const char *key, const char *value);
	void (*atomic_inc)(struct dict_transaction_context *ctx,
			   const char *key, long long diff);
};

struct dict {
	const char *name;

	struct dict_vfuncs v;
};

struct dict_iterate_context {
	struct dict *dict;
};

struct dict_transaction_context {
	struct dict *dict;
};

#endif
