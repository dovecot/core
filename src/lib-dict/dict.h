#ifndef DICT_H
#define DICT_H

#define DICT_PATH_PRIVATE "priv/"
#define DICT_PATH_SHARED "shared/"

struct dict;

enum dict_iterate_flags {
	DICT_ITERATE_FLAG_RECURSE             = 0x01,
	DICT_ITERATE_FLAG_SORT_BY_KEY         = 0x02,
	DICT_ITERATE_FLAG_SORT_BY_VALUE       = 0x04
};

enum dict_data_type {
	DICT_DATA_TYPE_STRING,
	DICT_DATA_TYPE_UINT32
};

void dict_driver_register(struct dict *driver);
void dict_driver_unregister(struct dict *driver);

void dict_drivers_register_all(void);
void dict_drivers_unregister_all(void);

/* Open dictionary with given URI (type:data).
   If URI is invalid, returns NULL. */
struct dict *dict_init(const char *uri, enum dict_data_type value_type,
		       const char *username);
/* Close dictionary. */
void dict_deinit(struct dict **dict);

/* Lookup value for key. Set it to NULL if it's not found.
   Returns 1 if found, 0 if not found and -1 if lookup failed. */
int dict_lookup(struct dict *dict, pool_t pool,
		const char *key, const char **value_r);

/* Iterate through all values in a path. flag indicates how iteration
   is carried out */
struct dict_iterate_context *
dict_iterate_init(struct dict *dict, const char *path, 
		  enum dict_iterate_flags flags);
/* Returns -1 = error, 0 = finished, 1 = key/value set */
int dict_iterate(struct dict_iterate_context *ctx,
		 const char **key_r, const char **value_r);
void dict_iterate_deinit(struct dict_iterate_context *ctx);

/* Start a new dictionary transaction. */
struct dict_transaction_context *dict_transaction_begin(struct dict *dict);
/* Commit the transaction. Returns 0 if ok, -1 if failed. */
int dict_transaction_commit(struct dict_transaction_context *ctx);
/* Rollback all changes made in transaction. */
void dict_transaction_rollback(struct dict_transaction_context *ctx);

/* Set key=value in dictionary. */
void dict_set(struct dict_transaction_context *ctx,
	      const char *key, const char *value);
/* Unset a record in dictionary, identified by key*/
void dict_unset(struct dict_transaction_context *ctx,
		const char *key);
/* Increase/decrease a numeric value in dictionary. Note that the value is
   changed when transaction is being committed, so you can't know beforehand
   what the value will become. */
void dict_atomic_inc(struct dict_transaction_context *ctx,
		     const char *key, long long diff);

#endif
