#ifndef DB_DICT_H
#define DB_DICT_H

#include "sql-api.h"

struct auth_request;
struct db_dict_value_iter;

enum db_dict_value_format {
	DB_DICT_VALUE_FORMAT_VALUE = 0,
	DB_DICT_VALUE_FORMAT_JSON
};

struct db_dict_key {
	const char *name;
	const char *key;
	const char *format;
	const char *default_value;

	enum db_dict_value_format parsed_format;
};
ARRAY_DEFINE_TYPE(db_dict_key, struct db_dict_key);
ARRAY_DEFINE_TYPE(db_dict_key_p, const struct db_dict_key *);

struct db_dict_field {
	const char *name;
	const char *value;
};
ARRAY_DEFINE_TYPE(db_dict_field, struct db_dict_field);

struct db_dict_settings {
	const char *uri;
	const char *default_pass_scheme;
	const char *iterate_prefix;
	bool iterate_disable;

	ARRAY_TYPE(db_dict_key) keys;

	const char *passdb_objects;
	const char *userdb_objects;
	ARRAY_TYPE(db_dict_field) passdb_fields;
	ARRAY_TYPE(db_dict_field) userdb_fields;

	ARRAY_TYPE(db_dict_key_p) parsed_passdb_objects;
	ARRAY_TYPE(db_dict_key_p) parsed_userdb_objects;
};

struct dict_connection {
	struct dict_connection *next;

	pool_t pool;
	int refcount;

	char *config_path;
	struct db_dict_settings set;
	struct dict *dict;
};

struct dict_connection *db_dict_init(const char *config_path);
void db_dict_unref(struct dict_connection **conn);

/* Returns 1 if ok, 0 if a key without default_value wasn't returned
   ("user doesn't exist"), -1 if internal error */
int db_dict_value_iter_init(struct dict_connection *conn,
			    struct auth_request *auth_request,
			    const ARRAY_TYPE(db_dict_field) *fields,
			    const ARRAY_TYPE(db_dict_key_p) *objects,
			    struct db_dict_value_iter **iter_r);
bool db_dict_value_iter_next(struct db_dict_value_iter *iter,
			     const char **key_r, const char **value_r);
int db_dict_value_iter_deinit(struct db_dict_value_iter **iter,
			      const char **error_r);

const char *db_dict_parse_cache_key(const ARRAY_TYPE(db_dict_key) *keys,
				    const ARRAY_TYPE(db_dict_field) *fields,
				    const ARRAY_TYPE(db_dict_key_p) *objects);

/* private: */
const struct db_dict_key *
db_dict_set_key_find(const ARRAY_TYPE(db_dict_key) *keys, const char *name);

#endif
