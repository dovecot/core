#ifndef DICT_SQL_PRIVATE_H
#define DICT_SQL_PRIVATE_H 1

struct sql_dict {
	struct dict dict;

	pool_t pool;
	struct sql_db *db;
	const char *username;
	const struct dict_sql_settings *set;

	/* query template => prepared statement */
	HASH_TABLE(const char *, struct sql_prepared_statement *) prep_stmt_hash;

	bool has_on_duplicate_key:1;
};

#endif
