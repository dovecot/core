#ifndef DICT_SQL_SETTINGS_H
#define DICT_SQL_SETTINGS_H

enum dict_sql_type {
	DICT_SQL_TYPE_STRING = 0,
	DICT_SQL_TYPE_UINT,
	DICT_SQL_TYPE_HEXBLOB
};

struct dict_sql_field {
	const char *name;
	enum dict_sql_type value_type;
};

struct dict_sql_map {
	/* pattern is in simplified form: all variables are stored as simple
	   '$' character. fields array is sorted by the variable index. */
	const char *pattern;
	const char *table;
	const char *username_field;
	const char *value_field;
	const char *value_type;
	bool value_hexblob;

	ARRAY(struct dict_sql_field) sql_fields;

	/* generated: */
	unsigned int values_count;
	const char *const *value_fields;
	const enum dict_sql_type *value_types;
};

struct dict_sql_settings {
	const char *connect;

	unsigned int max_field_count;
	ARRAY(struct dict_sql_map) maps;
};

struct dict_sql_settings *
dict_sql_settings_read(const char *path, const char **error_r);

void dict_sql_settings_deinit(void);

#endif
