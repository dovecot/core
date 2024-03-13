#ifndef DICT_SQL_PRIVATE_H
#define DICT_SQL_PRIVATE_H 1

struct sql_dict {
	struct dict dict;

	pool_t pool;
	struct sql_db *db;
	struct dict_sql_map_settings *set;
};

#endif
