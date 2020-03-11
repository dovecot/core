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
	enum dict_data_type value_type;
	const char *username;
	const char *base_dir;
	/* home directory for the user, if known */
	const char *home_dir;
	/* set to parent event, if exists */
	struct event *event_parent;
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
/* Switch the dict to the current ioloop. This can be used to do dict_wait()
   among other IO work. Returns TRUE if there is actually some work that can
   be waited on. */
bool dict_switch_ioloop(struct dict *dict) ATTR_NOWARN_UNUSED_RESULT;

/* Lookup value for key. Set it to NULL if it's not found.
   Returns 1 if found, 0 if not found and -1 if lookup failed. */
int dict_lookup(struct dict *dict, pool_t pool,
		const char *key, const char **value_r, const char **error_r);
void dict_lookup_async(struct dict *dict, const char *key,
		       dict_lookup_callback_t *callback, void *context);

/* Iterate through all values in a path. flag indicates how iteration
   is carried out */
struct dict_iterate_context *
dict_iterate_init(struct dict *dict, const char *path, 
		  enum dict_iterate_flags flags);
struct dict_iterate_context *
dict_iterate_init_multiple(struct dict *dict, const char *const *paths,
			   enum dict_iterate_flags flags);
/* Set async callback. Note that if dict_iterate_init() already did all the
   work, this callback may never be called. So after dict_iterate_init() you
   should call dict_iterate() in any case to see if all the results are
   already available. */
void dict_iterate_set_async_callback(struct dict_iterate_context *ctx,
				     dict_iterate_callback_t *callback,
				     void *context);
/* Limit how many rows will be returned by the iteration (0 = unlimited).
   This allows backends to optimize the query (e.g. use LIMIT 1 with SQL). */
void dict_iterate_set_limit(struct dict_iterate_context *ctx,
			    uint64_t max_rows);
/* If dict_iterate() returns FALSE, the iteration may be finished or if this
   is an async iteration it may be waiting for more data. If this function
   returns TRUE, the dict callback is called again with more data. */
bool dict_iterate_has_more(struct dict_iterate_context *ctx);
bool dict_iterate(struct dict_iterate_context *ctx,
		  const char **key_r, const char **value_r);
/* Returns 0 = ok, -1 = iteration failed */
int dict_iterate_deinit(struct dict_iterate_context **ctx, const char **error_r);

/* Start a new dictionary transaction. */
struct dict_transaction_context *dict_transaction_begin(struct dict *dict);
/* Don't log a warning if the transaction commit took a long time.
   This is needed if there are no guarantees that an asynchronous commit will
   finish up anytime soon. Mainly useful for transactions which aren't
   especially important whether they finish or not. */
void dict_transaction_no_slowness_warning(struct dict_transaction_context *ctx);
/* Set write timestamp for the entire transaction. This must be set before
   any changes are done and can't be changed afterwards. Currently only
   dict-sql with Cassandra backend does anything with this. */
void dict_transaction_set_timestamp(struct dict_transaction_context *ctx,
				    const struct timespec *ts);
/* Commit the transaction. Returns 1 if ok, 0 if dict_atomic_inc() was used
   on a nonexistent key, -1 if failed. */
int dict_transaction_commit(struct dict_transaction_context **ctx,
			    const char **error_r);
/* Commit the transaction, but don't wait to see if it finishes successfully.
   If callback isn't NULL, it's called eventually. If it's not called by the
   time you want to deinitialize dict, call dict_flush() to wait for the
   result. */
void dict_transaction_commit_async(struct dict_transaction_context **ctx,
				   dict_transaction_commit_callback_t *callback,
				   void *context) ATTR_NULL(2, 3);
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
