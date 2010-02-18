#ifndef DICT_PRIVATE_H
#define DICT_PRIVATE_H

#include "dict.h"

struct dict_vfuncs {
	struct dict *(*init)(struct dict *dict_driver, const char *uri,
			     enum dict_data_type value_type,
			     const char *username, const char *base_dir);
	void (*deinit)(struct dict *dict);
	int (*wait)(struct dict *dict);

	int (*lookup)(struct dict *dict, pool_t pool,
		      const char *key, const char **value_r);

	struct dict_iterate_context *
		(*iterate_init)(struct dict *dict, const char *const *paths,
				enum dict_iterate_flags flags);
	bool (*iterate)(struct dict_iterate_context *ctx,
			const char **key_r, const char **value_r);
	int (*iterate_deinit)(struct dict_iterate_context *ctx);

	struct dict_transaction_context *(*transaction_init)(struct dict *dict);
	int (*transaction_commit)(struct dict_transaction_context *ctx,
				  bool async,
				  dict_transaction_commit_callback_t *callback,
				  void *context);
	void (*transaction_rollback)(struct dict_transaction_context *ctx);

	void (*set)(struct dict_transaction_context *ctx,
		    const char *key, const char *value);
	void (*unset)(struct dict_transaction_context *ctx,
		      const char *key);
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

	unsigned int changed:1;
};

extern struct dict dict_driver_file;
extern struct dict dict_driver_client;

#endif
