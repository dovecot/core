#ifndef DICT_SQL_PRIVATE_H
#define DICT_SQL_PRIVATE_H 1

struct sql_dict {
	struct dict dict;

	pool_t pool;
	struct sql_db *db;
	const char *username;
	const struct dict_sql_settings *set;

	bool has_on_duplicate_key:1;
};

#endif
