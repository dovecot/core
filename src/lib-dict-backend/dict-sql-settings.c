/* Copyright (c) 2024 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "settings.h"
#include "settings-parser.h"
#include "dict-sql-settings.h"

#include <ctype.h>

/* <settings checks> */
#define DICT_MAP_FIELD_TYPES_ENUM \
	"string:int:uint:double:hexblob:uuid"
/* </settings checks> */

struct dict_sql_map_key_field {
	struct dict_sql_field sql_field;
	const char *variable;
};

const char *dict_sql_type_names[] = {
	"string",
	"int",
	"uint",
	"double",
	"hexblob",
	"uuid",
};
static_assert_array_size(dict_sql_type_names, DICT_SQL_TYPE_COUNT);

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("dict_map_key_field_"#name, name, struct dict_map_key_field_settings)
static const struct setting_define dict_map_key_field_setting_defines[] = {
	DEF(STR, name),
	DEF(STR, value),
	DEF(ENUM, type),

	SETTING_DEFINE_LIST_END
};
static const struct dict_map_key_field_settings dict_map_key_field_default_settings = {
	.name = "",
	.type = DICT_MAP_FIELD_TYPES_ENUM,
	.value = "",
};
const struct setting_parser_info dict_map_key_field_setting_parser_info = {
	.name = "dict_map_key_field",

	.defines = dict_map_key_field_setting_defines,
	.defaults = &dict_map_key_field_default_settings,

	.struct_size = sizeof(struct dict_map_key_field_settings),
	.pool_offset1 = 1 + offsetof(struct dict_map_key_field_settings, pool),
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("dict_map_value_field_"#name, name, struct dict_map_value_field_settings)
static const struct setting_define dict_map_value_field_setting_defines[] = {
	DEF(STR, name),
	DEF(ENUM, type),

	SETTING_DEFINE_LIST_END
};
static const struct dict_map_value_field_settings dict_map_value_field_default_settings = {
	.name = "",
	.type = DICT_MAP_FIELD_TYPES_ENUM,
};
const struct setting_parser_info dict_map_value_field_setting_parser_info = {
	.name = "dict_map_value_field",

	.defines = dict_map_value_field_setting_defines,
	.defaults = &dict_map_value_field_default_settings,

	.struct_size = sizeof(struct dict_map_value_field_settings),
	.pool_offset1 = 1 + offsetof(struct dict_map_value_field_settings, pool),
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("dict_map_"#name, name, struct dict_map_settings)
static const struct setting_define dict_map_setting_defines[] = {
	DEF(STR, pattern),
	DEF(STR, sql_table),
	DEF(STR, username_field),
	DEF(STR, expire_field),
	{ .type = SET_FILTER_ARRAY, .key = "dict_map_key_field",
	  .offset = offsetof(struct dict_map_settings, fields),
	  .filter_array_field_name = "dict_map_key_field_name", },
	{ .type = SET_FILTER_ARRAY, .key = "dict_map_value_field",
	  .offset = offsetof(struct dict_map_settings, values),
	  .filter_array_field_name = "dict_map_value_field_name", },

	{ .type = SET_FILTER_ARRAY, .key = "dict_map",
	  .offset = offsetof(struct dict_map_settings, maps),
	  .filter_array_field_name = "dict_map_pattern", },

	SETTING_DEFINE_LIST_END
};
static const struct dict_map_settings dict_map_default_settings = {
	.pattern = "",
	.sql_table = "",
	.username_field = "",
	.expire_field = "",
};
const struct setting_parser_info dict_map_setting_parser_info = {
	.name = "dict_map",

	.defines = dict_map_setting_defines,
	.defaults = &dict_map_default_settings,

	.struct_size = sizeof(struct dict_map_settings),
	.pool_offset1 = 1 + offsetof(struct dict_map_settings, pool),
};

static enum dict_sql_type dict_sql_type_parse(const char *value_type)
{
	for (enum dict_sql_type type = DICT_SQL_TYPE_STRING;
	    type < DICT_SQL_TYPE_COUNT; type++) {
		if (strcmp(value_type, dict_sql_type_names[type]) == 0)
			return type;
	}
	/* settings parsing should have failed before getting here */
	i_panic("BUG: Unknown dict_sql_type '%s'", value_type);
}

static const char *pattern_read_name(const char **pattern)
{
	const char *p = *pattern, *name;

	if (*p == '{') {
		/* ${name} */
		name = ++p;
		p = strchr(p, '}');
		if (p == NULL) {
			/* error, but allow anyway */
			*pattern += strlen(*pattern);
			return "";
		}
		*pattern = p + 1;
	} else {
		/* $name - ends at the first non-alnum_ character */
		name = p;
		for (; *p != '\0'; p++) {
			if (!i_isalnum(*p) && *p != '_')
				break;
		}
		*pattern = p;
	}
	name = t_strconcat("$", t_strdup_until(name, p), NULL);
	return name;
}

static int dict_sql_fields_map(struct event *event, pool_t pool,
			       const struct dict_map_settings *map_set,
			       struct dict_sql_map *map,
			       const char **error_r)
{
	struct dict_sql_map_key_field *fields;
	string_t *pattern;
	const char *p, *name, *const *field_names;
	unsigned int i, count;

	/* go through the variables in the pattern, replace them with plain
	   '$' character and add its sql field */
	pattern = t_str_new(strlen(map->pattern) + 1);

	if (!array_is_empty(&map_set->fields))
		field_names = array_get(&map_set->fields, &count);
	else {
		field_names = NULL;
		count = 0;
	}
	fields = count == 0 ? NULL :
		t_new(struct dict_sql_map_key_field, count);
	for (i = 0; i < count; i++) {
		const struct dict_map_key_field_settings *field_set;
		if (settings_get_filter(event, "dict_map_key_field",
					field_names[i],
					&dict_map_key_field_setting_parser_info,
					0, &field_set, error_r) < 0)
			return -1;
		pool_add_external_ref(pool, field_set->pool);
		fields[i].sql_field.name = field_set->name;
		fields[i].sql_field.value_type =
			dict_sql_type_parse(field_set->type);
		fields[i].variable = field_set->value;
		settings_free(field_set);
	}

	p_array_init(&map->pattern_fields, pool, count);
	for (p = map->pattern; *p != '\0';) {
		if (*p != '$') {
			str_append_c(pattern, *p);
			p++;
			continue;
		}
		p++;
		str_append_c(pattern, '$');

		name = pattern_read_name(&p);
		for (i = 0; i < count; i++) {
			if (fields[i].variable != NULL &&
			    strcmp(fields[i].variable, name) == 0)
				break;
		}
		if (i == count) {
			*error_r = t_strconcat("Missing SQL field for variable: ",
					       name, NULL);
			return -1;
		}

		/* mark this field as used */
		fields[i].variable = NULL;
		array_push_back(&map->pattern_fields,
				&fields[i].sql_field);
	}

	/* make sure there aren't any unused fields */
	for (i = 0; i < count; i++) {
		if (fields[i].variable != NULL) {
			*error_r = t_strconcat("Unused variable: ",
					       fields[i].variable, NULL);
			return -1;
		}
	}

	map->pattern = p_strdup(pool, str_c(pattern));
	return 0;
}

static int
dict_sql_map_settings_get(struct event *event,
			  struct dict_sql_map_settings *set,
			  const char **error_r)
{
	const struct dict_map_settings *map_set;
	const struct dict_map_value_field_settings *value_set;
	const char *name;

	if (settings_get(event, &dict_map_setting_parser_info, 0,
			 &map_set, error_r) < 0)
		return -1;
	pool_add_external_ref(set->pool, map_set->pool);
	pool_t pool_copy = map_set->pool;
	pool_unref(&pool_copy);

	if (array_is_empty(&map_set->values)) {
		*error_r = "dict_map_value_field { .. } named list filter is missing";
		return -1;
	}

	struct dict_sql_map *map = array_append_space(&set->maps);
	map->pattern = map_set->pattern;
	map->table = map_set->sql_table;
	map->username_field = map_set->username_field;
	map->expire_field = map_set->expire_field[0] != '\0' ?
		map_set->expire_field : NULL;
	map->values_count = array_count(&map_set->values);
	if (dict_sql_fields_map(event, set->pool, map_set, map, error_r) < 0)
		return -1;

	string_t *value_field = t_str_new(32);
	ARRAY(enum dict_sql_type) value_types;
	p_array_init(&value_types, map_set->pool, map->values_count);

	array_foreach_elem(&map_set->values, name) {
		if (settings_get_filter(event, "dict_map_value_field", name,
					&dict_map_value_field_setting_parser_info,
					0, &value_set, error_r) < 0)
			return -1;

		if (str_len(value_field) > 0)
			str_append_c(value_field, ',');
		str_append(value_field, value_set->name);
		enum dict_sql_type field_type =
			dict_sql_type_parse(value_set->type);
		array_push_back(&value_types, &field_type);
		settings_free(value_set);
	}
	map->value_field = p_strdup(set->pool, str_c(value_field));
	map->value_types = array_front(&value_types);
	return 0;
}

int dict_sql_settings_get(struct event *event,
			  struct dict_sql_map_settings **set_r,
			  const char **error_r)
{
	const struct dict_map_settings *maps_set;
	struct dict_sql_map_settings *set;
	const char *name, *error;
	int ret = 0;

	pool_t pool = pool_alloconly_create("dict sql map settings", 128);
	set = p_new(pool, struct dict_sql_map_settings, 1);
	set->pool = pool;
	p_array_init(&set->maps, pool, 8);

	if (settings_get(event, &dict_map_setting_parser_info, 0,
			 &maps_set, error_r) < 0) {
		pool_unref(&pool);
		return -1;
	}
	if (array_is_created(&maps_set->maps)) {
		array_foreach_elem(&maps_set->maps, name) {
			struct event *map_event = event_create(event);
			settings_event_add_list_filter_name(map_event,
							    "dict_map", name);
			if (dict_sql_map_settings_get(map_event, set, &error) < 0) {
				*error_r = t_strdup_printf(
					"Failed to get dict_map %s: %s", name, error);
				ret = -1;
			}
			event_unref(&map_event);
			if (ret < 0)
				break;

		}
	}
	settings_free(maps_set);
	if (ret < 0)
		pool_unref(&pool);
	else
		*set_r = set;
	return ret;
}
