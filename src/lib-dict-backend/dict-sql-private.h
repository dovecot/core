#ifndef DICT_SQL_PRIVATE_H
#define DICT_SQL_PRIVATE_H 1

struct sql_dict {
	struct dict dict;

	pool_t pool;
	struct sql_db *db;
	const struct dict_sql_settings *set;
};

#endif
