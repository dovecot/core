/* Copyright (c) 2008-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "hash.h"
#include "settings.h"
#include "dict-sql-settings.h"

#include <ctype.h>

enum section_type {
	SECTION_ROOT = 0,
	SECTION_MAP,
	SECTION_FIELDS
};

struct dict_sql_map_field {
	struct dict_sql_field sql_field;
	const char *variable;
};

struct setting_parser_ctx {
	pool_t pool;
	struct dict_sql_settings *set;
	enum section_type type;

	struct dict_sql_map cur_map;
	ARRAY(struct dict_sql_map_field) cur_fields;
};

#define DEF_STR(name) DEF_STRUCT_STR(name, dict_sql_map)
#define DEF_BOOL(name) DEF_STRUCT_BOOL(name, dict_sql_map)

static const struct setting_def dict_sql_map_setting_defs[] = {
	DEF_STR(pattern),
	DEF_STR(table),
	DEF_STR(username_field),
	DEF_STR(value_field),
	DEF_STR(value_type),
	DEF_BOOL(value_hexblob),

	{ 0, NULL, 0 }
};

struct dict_sql_settings_cache {
	pool_t pool;
	const char *path;
	struct dict_sql_settings *set;
};

static HASH_TABLE(const char *, struct dict_sql_settings_cache *) dict_sql_settings_cache;

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
	name = t_strdup_until(name, p);
	return name;
}

static const char *dict_sql_fields_map(struct setting_parser_ctx *ctx)
{
	struct dict_sql_map_field *fields;
	string_t *pattern;
	const char *p, *name;
	unsigned int i, count;

	/* go through the variables in the pattern, replace them with plain
	   '$' character and add its sql field */
	pattern = t_str_new(strlen(ctx->cur_map.pattern) + 1);
	fields = array_get_modifiable(&ctx->cur_fields, &count);

	p_array_init(&ctx->cur_map.sql_fields, ctx->pool, count);
	for (p = ctx->cur_map.pattern; *p != '\0';) {
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
			return t_strconcat("Missing SQL field for variable: ",
					   name, NULL);
		}

		/* mark this field as used */
		fields[i].variable = NULL;
		array_push_back(&ctx->cur_map.sql_fields,
				&fields[i].sql_field);
	}

	/* make sure there aren't any unused fields */
	for (i = 0; i < count; i++) {
		if (fields[i].variable != NULL) {
			return t_strconcat("Unused variable: ",
					   fields[i].variable, NULL);
		}
	}

	if (ctx->set->max_field_count < count)
		ctx->set->max_field_count = count;
	ctx->cur_map.pattern = p_strdup(ctx->pool, str_c(pattern));
	return NULL;
}

static bool
dict_sql_value_type_parse(const char *value_type, enum dict_sql_type *type_r)
{
	if (strcmp(value_type, "string") == 0)
		*type_r = DICT_SQL_TYPE_STRING;
	else if (strcmp(value_type, "hexblob") == 0)
		*type_r = DICT_SQL_TYPE_HEXBLOB;
	else if (strcmp(value_type, "int") == 0)
		*type_r = DICT_SQL_TYPE_INT;
	else if (strcmp(value_type, "uint") == 0)
		*type_r = DICT_SQL_TYPE_UINT;
	else
		return FALSE;
	return TRUE;
}

static const char *dict_sql_map_finish(struct setting_parser_ctx *ctx)
{
	unsigned int i;

	if (ctx->cur_map.pattern == NULL)
		return "Missing setting: pattern";
	if (ctx->cur_map.table == NULL)
		return "Missing setting: table";
	if (ctx->cur_map.value_field == NULL)
		return "Missing setting: value_field";

	ctx->cur_map.value_fields = (const char *const *)
		p_strsplit_spaces(ctx->pool, ctx->cur_map.value_field, ",");
	ctx->cur_map.values_count = str_array_length(ctx->cur_map.value_fields);

	enum dict_sql_type *value_types =
		p_new(ctx->pool, enum dict_sql_type, ctx->cur_map.values_count);
	if (ctx->cur_map.value_type != NULL) {
		const char *const *types =
			t_strsplit_spaces(ctx->cur_map.value_type, ",");
		if (str_array_length(types) != ctx->cur_map.values_count)
			return "Number of fields in value_fields doesn't match value_type";
		for (i = 0; i < ctx->cur_map.values_count; i++) {
			if (!dict_sql_value_type_parse(types[i], &value_types[i]))
				return "Invalid value in value_type";
		}
	} else {
		for (i = 0; i < ctx->cur_map.values_count; i++) {
			value_types[i] = ctx->cur_map.value_hexblob ?
				DICT_SQL_TYPE_HEXBLOB : DICT_SQL_TYPE_STRING;
		}
	}
	ctx->cur_map.value_types = value_types;

	if (ctx->cur_map.username_field == NULL) {
		/* not all queries require this */
		ctx->cur_map.username_field = "'username_field not set'";
	}

	if (!array_is_created(&ctx->cur_map.sql_fields)) {
		/* no fields besides value. allocate the array anyway. */
		p_array_init(&ctx->cur_map.sql_fields, ctx->pool, 1);
		if (strchr(ctx->cur_map.pattern, '$') != NULL)
			return "Missing fields for pattern variables";
	}
	array_push_back(&ctx->set->maps, &ctx->cur_map);
	i_zero(&ctx->cur_map);
	return NULL;
}

static const char *
parse_setting(const char *key, const char *value,
	      struct setting_parser_ctx *ctx)
{
	struct dict_sql_map_field *field;
	size_t value_len;

	switch (ctx->type) {
	case SECTION_ROOT:
		if (strcmp(key, "connect") == 0) {
			ctx->set->connect = p_strdup(ctx->pool, value);
			return NULL;
		}
		break;
	case SECTION_MAP:
		return parse_setting_from_defs(ctx->pool,
					       dict_sql_map_setting_defs,
					       &ctx->cur_map, key, value);
	case SECTION_FIELDS:
		if (*value != '$') {
			return t_strconcat("Value is missing '$' for field: ",
					   key, NULL);
		}
		field = array_append_space(&ctx->cur_fields);
		field->sql_field.name = p_strdup(ctx->pool, key);
		value_len = strlen(value);
		if (str_begins(value, "${hexblob:") &&
		    value[value_len-1] == '}') {
			field->variable = p_strndup(ctx->pool, value + 10,
						    value_len-10-1);
			field->sql_field.value_type = DICT_SQL_TYPE_HEXBLOB;
		} else if (str_begins(value, "${int:") &&
			   value[value_len-1] == '}') {
			field->variable = p_strndup(ctx->pool, value + 6,
						    value_len-6-1);
			field->sql_field.value_type = DICT_SQL_TYPE_INT;
		} else if (str_begins(value, "${uint:") &&
			   value[value_len-1] == '}') {
			field->variable = p_strndup(ctx->pool, value + 7,
						    value_len-7-1);
			field->sql_field.value_type = DICT_SQL_TYPE_UINT;
		} else {
			field->variable = p_strdup(ctx->pool, value + 1);
		}
		return NULL;
	}
	return t_strconcat("Unknown setting: ", key, NULL);
}

static bool
parse_section(const char *type, const char *name ATTR_UNUSED,
	      struct setting_parser_ctx *ctx, const char **error_r)
{
	switch (ctx->type) {
	case SECTION_ROOT:
		if (type == NULL)
			return FALSE;
		if (strcmp(type, "map") == 0) {
			array_clear(&ctx->cur_fields);
			ctx->type = SECTION_MAP;
			return TRUE;
		}
		break;
	case SECTION_MAP:
		if (type == NULL) {
			ctx->type = SECTION_ROOT;
			*error_r = dict_sql_map_finish(ctx);
			return FALSE;
		}
		if (strcmp(type, "fields") == 0) {
			ctx->type = SECTION_FIELDS;
			return TRUE;
		}
		break;
	case SECTION_FIELDS:
		if (type == NULL) {
			ctx->type = SECTION_MAP;
			*error_r = dict_sql_fields_map(ctx);
			return FALSE;
		}
		break;
	}
	*error_r = t_strconcat("Unknown section: ", type, NULL);
	return FALSE;
}

struct dict_sql_settings *
dict_sql_settings_read(const char *path, const char **error_r)
{
	struct setting_parser_ctx ctx;
	struct dict_sql_settings_cache *cache;
	pool_t pool;

	if (!hash_table_is_created(dict_sql_settings_cache)) {
		hash_table_create(&dict_sql_settings_cache, default_pool, 0,
				  str_hash, strcmp);
	}

	cache = hash_table_lookup(dict_sql_settings_cache, path);
	if (cache != NULL)
		return cache->set;

	i_zero(&ctx);
	pool = pool_alloconly_create("dict sql settings", 1024);
	ctx.pool = pool;
	ctx.set = p_new(pool, struct dict_sql_settings, 1);
	t_array_init(&ctx.cur_fields, 16);
	p_array_init(&ctx.set->maps, pool, 8);

	if (!settings_read(path, NULL, parse_setting, parse_section,
			   &ctx, error_r)) {
		pool_unref(&pool);
		return NULL;
	}

	if (ctx.set->connect == NULL) {
		*error_r = t_strdup_printf("Error in configuration file %s: "
					   "Missing connect setting", path);
		pool_unref(&pool);
		return NULL;
	}

	cache = p_new(pool, struct dict_sql_settings_cache, 1);
	cache->pool = pool;
	cache->path = p_strdup(pool, path);
	cache->set = ctx.set;

	hash_table_insert(dict_sql_settings_cache, cache->path, cache);
	return ctx.set;
}

void dict_sql_settings_deinit(void)
{
	struct hash_iterate_context *iter;
	struct dict_sql_settings_cache *cache;
	const char *key;

	if (!hash_table_is_created(dict_sql_settings_cache))
		return;

	iter = hash_table_iterate_init(dict_sql_settings_cache);
	while (hash_table_iterate(iter, dict_sql_settings_cache, &key, &cache))
		pool_unref(&cache->pool);
	hash_table_iterate_deinit(&iter);
	hash_table_destroy(&dict_sql_settings_cache);
}
