#ifndef DB_DICT_H
#define DB_DICT_H

#include "sql-api.h"

struct db_dict_settings {
	const char *uri;
	const char *password_key;
	const char *user_key;
	const char *iterate_prefix;
	bool iterate_disable;
	const char *value_format;
	const char *default_pass_scheme;
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

struct db_dict_value_iter *
db_dict_value_iter_init(struct dict_connection *conn, const char *value);
bool db_dict_value_iter_next(struct db_dict_value_iter *iter,
			     const char **key_r, const char **value_r);
int db_dict_value_iter_deinit(struct db_dict_value_iter **iter,
			      const char **error_r);

#endif
