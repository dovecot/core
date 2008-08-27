#ifndef DICT_SQL_SETTINGS_H
#define DICT_SQL_SETTINGS_H

struct dict_sql_map {
	/* pattern is in simplified form: all variables are stored as simple
	   '$' character. fields array is sorted by the variable index. */
	const char *pattern;
	const char *table;
	const char *username_field;
	const char *value_field;

	ARRAY_TYPE(const_string) sql_fields;
};

struct dict_sql_settings {
	const char *connect;

	unsigned int max_field_count;
	ARRAY_DEFINE(maps, struct dict_sql_map);
};

struct dict_sql_settings *dict_sql_settings_read(pool_t pool, const char *path);

#endif
