#ifndef DICT_SQL_SETTINGS_H
#define DICT_SQL_SETTINGS_H

enum dict_sql_type {
	DICT_SQL_TYPE_STRING = 0,
	DICT_SQL_TYPE_INT,
	DICT_SQL_TYPE_UINT,
	DICT_SQL_TYPE_DOUBLE,
	DICT_SQL_TYPE_HEXBLOB,
	DICT_SQL_TYPE_UUID,
	DICT_SQL_TYPE_COUNT
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
	const char *expire_field;

	/* SQL field names, one for each $ variable in the pattern */
	ARRAY(struct dict_sql_field) pattern_fields;

	/* generated: */
	unsigned int values_count;
	const enum dict_sql_type *value_types;
};

struct dict_map_key_field_settings {
	pool_t pool;

	const char *name;
	const char *type;
	const char *value;
};

struct dict_map_value_field_settings {
	pool_t pool;

	const char *name;
	const char *type;
};

struct dict_map_settings {
	pool_t pool;

	const char *pattern;
	const char *sql_table;
	const char *username_field;
	const char *expire_field;
	ARRAY_TYPE(const_string) fields;
	ARRAY_TYPE(const_string) values;

	ARRAY_TYPE(const_string) maps;
};

struct dict_sql_map_settings {
	pool_t pool;
	ARRAY(struct dict_sql_map) maps;
};

extern const char *dict_sql_type_names[];
extern const struct setting_parser_info dict_map_key_field_setting_parser_info;
extern const struct setting_parser_info dict_map_value_field_setting_parser_info;
extern const struct setting_parser_info dict_map_setting_parser_info;

int dict_sql_settings_get(struct event *event,
			  struct dict_sql_map_settings **set_r,
			  const char **error_r);

#endif
