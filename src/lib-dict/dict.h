#ifndef DICT_H
#define DICT_H

#define DICT_PATH_PRIVATE "priv/"
#define DICT_PATH_SHARED "shared/"

struct timespec;
struct dict;
struct dict_iterate_context;

enum dict_iterate_flags {
	/* Recurse to all the sub-hierarchies (e.g. iterating "foo/" will
	   return "foo/a", but should it return "foo/a/b"?) */
	DICT_ITERATE_FLAG_RECURSE             = 0x01,
	/* Sort returned results by key */
	DICT_ITERATE_FLAG_SORT_BY_KEY         = 0x02,
	/* Sort returned results by value */
	DICT_ITERATE_FLAG_SORT_BY_VALUE       = 0x04,
	/* Don't return values, only keys */
	DICT_ITERATE_FLAG_NO_VALUE            = 0x08,
	/* Don't recurse at all. This is basically the same as dict_lookup(),
	   but it'll return all the rows instead of only the first one. */
	DICT_ITERATE_FLAG_EXACT_KEY           = 0x10,
	/* Perform iteration asynchronously. */
	DICT_ITERATE_FLAG_ASYNC               = 0x20
};

enum dict_data_type {
	DICT_DATA_TYPE_STRING = 0,
	DICT_DATA_TYPE_UINT32,
	DICT_DATA_TYPE_LAST
};

struct dict_settings {
	const char *base_dir;
	/* set to parent event, if exists */
	struct event *event_parent;
};

struct dict_op_settings {
	const char *username;
	/* home directory for the user, if known */
	const char *home_dir;

	/* If non-zero, number of seconds until the added keys expire. See the
	   documentation how this is implemented for different drivers. */
	unsigned int expire_secs;

	/* Don't log a warning if the transaction commit took a long time.
	   This is needed if there are no guarantees that an asynchronous
	   commit will finish up anytime soon. Mainly useful for transactions
	   which aren't especially important whether they finish or not. */
	bool no_slowness_warning;
	/* Hide values when logging about this transaction. */
	bool hide_log_values;
};

struct dict_lookup_result {
	int ret;

	/* First returned value (ret > 0) */
	const char *value;
	/* NULL-terminated list of all returned values (ret > 0) */
	const char *const *values;

	/* Error message for a failed lookup (ret < 0) */
	const char *error;
};

enum dict_commit_ret {
	DICT_COMMIT_RET_OK = 1,
	DICT_COMMIT_RET_NOTFOUND = 0,
	DICT_COMMIT_RET_FAILED = -1,
	/* write may or may not have succeeded (e.g. write timeout or
	   disconnected from server) */
	DICT_COMMIT_RET_WRITE_UNCERTAIN = -2,
};

struct dict_commit_result {
	enum dict_commit_ret ret;
	const char *error;
};

typedef void dict_lookup_callback_t(const struct dict_lookup_result *result,
				    void *context);
typedef void dict_iterate_callback_t(void *context);
typedef void
dict_transaction_commit_callback_t(const struct dict_commit_result *result,
				   void *context);

void dict_driver_register(struct dict *driver);
void dict_driver_unregister(struct dict *driver);

void dict_drivers_register_builtin(void);
void dict_drivers_unregister_builtin(void);

void dict_drivers_register_all(void);
void dict_drivers_unregister_all(void);

/* Open dictionary with given URI (type:data).
   Returns 0 if ok, -1 if URI is invalid. */
int dict_init(const char *uri, const struct dict_settings *set,
	      struct dict **dict_r, const char **error_r);
/* Close dictionary. */
void dict_deinit(struct dict **dict);
/* Wait for all pending asynchronous operations to finish. */
void dict_wait(struct dict *dict);
/* Returns TRUE if there are any pending async operations. */
bool dict_have_async_operations(struct dict *dict);
/* Switch the dict to the current ioloop. This can be used to do dict_wait()
   among other IO work. Returns TRUE if there is actually some work that can
   be waited on. */
bool dict_switch_ioloop(struct dict *dict) ATTR_NOWARN_UNUSED_RESULT;

/* Scan the dict for expired entries and delete them. Returns 0 if dict does
   not support expire scanning (and there is no need to call this function
   again), 1 if expire scanning was run successfully, -1 if expire scanning
   failed. */
int dict_expire_scan(struct dict *dict, const char **error_r);

/* Lookup the first value for the key. Set it to NULL if it's not found.
   Returns 1 if found, 0 if not found and -1 if lookup failed. */
int dict_lookup(struct dict *dict, const struct dict_op_settings *set, pool_t pool,
		const char *key, const char **value_r, const char **error_r);
/* Lookup all the values for the key. Set it to NULL if it's not found.
   Returns 1 if found, 0 if not found and -1 if lookup failed. */
int dict_lookup_values(struct dict *dict, const struct dict_op_settings *set,
		       pool_t pool, const char *key,
		       const char *const **values_r, const char **error_r);
/* Asynchronously lookup values for the key. */
void dict_lookup_async(struct dict *dict, const struct dict_op_settings *set,
		       const char *key, dict_lookup_callback_t *callback,
		       void *context);
#define dict_lookup_async(dict, set, key, callback, context) \
	dict_lookup_async(dict, set, key, (dict_lookup_callback_t *)(callback), \
		1 ? (context) : \
		CALLBACK_TYPECHECK(callback, \
			void (*)(const struct dict_lookup_result *, typeof(context))))

/* Iterate through all values in a path. flag indicates how iteration
   is carried out */
struct dict_iterate_context *
dict_iterate_init(struct dict *dict, const struct dict_op_settings *set,
		  const char *path, enum dict_iterate_flags flags);
/* Set async callback. Note that if dict_iterate_init() already did all the
   work, this callback may never be called. So after dict_iterate_init() you
   should call dict_iterate() in any case to see if all the results are
   already available. */
void dict_iterate_set_async_callback(struct dict_iterate_context *ctx,
				     dict_iterate_callback_t *callback,
				     void *context);
#define dict_iterate_set_async_callback(ctx, callback, context) \
	dict_iterate_set_async_callback(ctx, (dict_iterate_callback_t *)(callback), \
		1 ? (context) : \
		CALLBACK_TYPECHECK(callback, void (*)(typeof(context))))
/* Limit how many rows will be returned by the iteration (0 = unlimited).
   This allows backends to optimize the query (e.g. use LIMIT 1 with SQL). */
void dict_iterate_set_limit(struct dict_iterate_context *ctx,
			    uint64_t max_rows);
/* If dict_iterate() returns FALSE, the iteration may be finished or if this
   is an async iteration it may be waiting for more data. If this function
   returns TRUE, the dict callback is called again with more data. If dict
   supports multiple values, dict_iterate_values() can be used to return all
   of them. dict_iterate() returns only the first value and ignores the rest. */
bool dict_iterate_has_more(struct dict_iterate_context *ctx);
bool dict_iterate(struct dict_iterate_context *ctx,
		  const char **key_r, const char **value_r);
bool dict_iterate_values(struct dict_iterate_context *ctx,
			 const char **key_r, const char *const **values_r);
/* Returns 0 = ok, -1 = iteration failed */
int dict_iterate_deinit(struct dict_iterate_context **ctx, const char **error_r);

/* Start a new dictionary transaction. */
struct dict_transaction_context *
dict_transaction_begin(struct dict *dict, const struct dict_op_settings *set);
/* Set write timestamp for the entire transaction. This must be set before
   any changes are done and can't be changed afterwards. Currently only
   dict-sql with Cassandra backend does anything with this. */
void dict_transaction_set_timestamp(struct dict_transaction_context *ctx,
				    const struct timespec *ts);

/* Set hide_log_values for the transaction. Currently only
   dict-sql with Cassandra backend does anything with this. */
void dict_transaction_set_hide_log_values(struct dict_transaction_context *ctx,
					  bool hide_log_values);
/* Commit the transaction. Returns 1 if ok, 0 if dict_atomic_inc() was used
   on a nonexistent key, -1 if failed. */
int dict_transaction_commit(struct dict_transaction_context **ctx,
			    const char **error_r);
/* Commit the transaction, but don't wait to see if it finishes successfully.
   The callback is called when the transaction is finished. If it's not called
   by the time you want to deinitialize dict, call dict_flush() to wait for the
   result. */
void dict_transaction_commit_async(struct dict_transaction_context **ctx,
				   dict_transaction_commit_callback_t *callback,
				   void *context) ATTR_NULL(2, 3);
#define dict_transaction_commit_async(ctx, callback, context) \
	dict_transaction_commit_async(ctx, (dict_transaction_commit_callback_t *)(callback), \
		1 ? (context) : \
		CALLBACK_TYPECHECK(callback, \
			void (*)(const struct dict_commit_result *, typeof(context))))
/* Same as dict_transaction_commit_async(), but don't call a callback. */
void dict_transaction_commit_async_nocallback(
	struct dict_transaction_context **ctx);
/* Rollback all changes made in transaction. */
void dict_transaction_rollback(struct dict_transaction_context **ctx);

/* Set key=value in dictionary. */
void dict_set(struct dict_transaction_context *ctx,
	      const char *key, const char *value);
/* Unset a record in dictionary, identified by key*/
void dict_unset(struct dict_transaction_context *ctx,
		const char *key);
/* Increase/decrease a numeric value in dictionary. Note that the value is
   changed when transaction is being committed, so you can't know beforehand
   what the value will become. The value is updated only if it already exists,
   otherwise commit() will return 0. */
void dict_atomic_inc(struct dict_transaction_context *ctx,
		     const char *key, long long diff);

/* Escape/unescape '/' characters in a string, so that it can be safely added
   into path components in dict keys. */
const char *dict_escape_string(const char *str);
const char *dict_unescape_string(const char *str);

#endif
