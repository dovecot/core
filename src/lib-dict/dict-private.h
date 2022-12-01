
#ifndef DICT_PRIVATE_H
#define DICT_PRIVATE_H

#include <time.h>
#include "dict.h"

struct ioloop;

enum dict_driver_flags {
	DICT_DRIVER_FLAG_SUPPORT_EXPIRE_SECS	= BIT(0),
};

struct dict_vfuncs {
	int (*init)(struct dict *dict_driver, const char *uri,
		    const struct dict_settings *set,
		    struct dict **dict_r, const char **error_r);
	void (*deinit)(struct dict *dict);
	void (*wait)(struct dict *dict);
	int (*expire_scan)(struct dict *dict, const char **error_r);

	int (*lookup)(struct dict *dict, const struct dict_op_settings *set,
		      pool_t pool, const char *key, const char *const **values_r,
		      const char **error_r);

	struct dict_iterate_context *
		(*iterate_init)(struct dict *dict,
				const struct dict_op_settings *set,
				const char *path,
				enum dict_iterate_flags flags);
	bool (*iterate)(struct dict_iterate_context *ctx,
			const char **key_r, const char *const **values_r);
	int (*iterate_deinit)(struct dict_iterate_context *ctx,
			      const char **error_r);

	struct dict_transaction_context *(*transaction_init)(struct dict *dict);
	/* call the callback before returning if non-async commits */
	void (*transaction_commit)(struct dict_transaction_context *ctx,
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

	void (*lookup_async)(struct dict *dict, const struct dict_op_settings *set,
			     const char *key, dict_lookup_callback_t *callback,
			     void *context);
	bool (*switch_ioloop)(struct dict *dict);
	void (*set_timestamp)(struct dict_transaction_context *ctx,
			      const struct timespec *ts);
	void (*set_hide_log_values)(struct dict_transaction_context *ctx,
			            bool hide_log_values);
};

struct dict_commit_callback_ctx;

struct dict_op_settings_private {
	char *username;
	char *home_dir;
	unsigned int expire_secs;
	bool no_slowness_warning;
	bool hide_log_values;
};

struct dict {
	const char *name;
	enum dict_driver_flags flags;

	struct dict_vfuncs v;
	unsigned int iter_count;
	unsigned int transaction_count;
	struct dict_transaction_context *transactions;
	int refcount;
	struct event *event;
	struct ioloop *ioloop, *prev_ioloop;
	struct dict_commit_callback_ctx *commits;
	struct dict_transaction_context *rollbacks;
};

struct dict_iterate_context {
	struct dict *dict;
	struct event *event;
	struct dict_op_settings_private set;
	enum dict_iterate_flags flags;

	dict_iterate_callback_t *async_callback;
	void *async_context;

	uint64_t row_count, max_rows;

	bool has_more:1;
};

struct dict_transaction_context {
	struct dict *dict;
	struct dict_op_settings_private set;
	struct dict_transaction_context *prev, *next;

	struct event *event;
	struct timespec timestamp;

	struct timeout *to_rollback;
	const char *error;

	bool changed:1;
};

void dict_transaction_commit_async_noop_callback(
	const struct dict_commit_result *result, void *context);

extern struct dict dict_driver_client;
extern struct dict dict_driver_file;
extern struct dict dict_driver_fs;
extern struct dict dict_driver_redis;
extern struct dict dict_driver_cdb;
extern struct dict dict_driver_fail;

extern struct dict_iterate_context dict_iter_unsupported;
extern struct dict_transaction_context dict_transaction_unsupported;

void dict_pre_api_callback(struct dict *dict);
void dict_post_api_callback(struct dict *dict);

/* Duplicate an object of type dict_op_settings. Used for initializing/freeing
   iterator and transaction contexts. */
void dict_op_settings_dup(const struct dict_op_settings *source,
			  struct dict_op_settings_private *dest_r);
void dict_op_settings_private_free(struct dict_op_settings_private *set);

#endif
