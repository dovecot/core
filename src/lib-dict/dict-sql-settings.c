/* Copyright (c) 2008-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "settings.h"
#include "dict-sql-settings.h"

#include <ctype.h>

enum section_type {
	SECTION_ROOT = 0,
	SECTION_MAP,
	SECTION_FIELDS
};

struct dict_sql_map_field {
	const char *sql_field, *variable;
};

struct setting_parser_ctx {
	pool_t pool;
	struct dict_sql_settings *set;
	enum section_type type;

	struct dict_sql_map cur_map;
	ARRAY_DEFINE(cur_fields, struct dict_sql_map_field);
};

#define DEF_STR(name) DEF_STRUCT_STR(name, dict_sql_map)

static const struct setting_def dict_sql_map_setting_defs[] = {
	DEF_STR(pattern),
	DEF_STR(table),
	DEF_STR(username_field),
	DEF_STR(value_field),

	{ 0, NULL, 0 }
};

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
		array_append(&ctx->cur_map.sql_fields,
			     &fields[i].sql_field, 1);
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

static const char *dict_sql_map_finish(struct setting_parser_ctx *ctx)
{
	if (ctx->cur_map.pattern == NULL)
		return "Missing setting: pattern";
	if (ctx->cur_map.table == NULL)
		return "Missing setting: table";
	if (ctx->cur_map.value_field == NULL)
		return "Missing setting: value_field";

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
	array_append(&ctx->set->maps, &ctx->cur_map, 1);
	memset(&ctx->cur_map, 0, sizeof(ctx->cur_map));
	return NULL;
}

static const char *
parse_setting(const char *key, const char *value,
	      struct setting_parser_ctx *ctx)
{
	struct dict_sql_map_field *field;

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
		field->sql_field = p_strdup(ctx->pool, key);
		field->variable = p_strdup(ctx->pool, value + 1);
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

struct dict_sql_settings *dict_sql_settings_read(pool_t pool, const char *path)
{
	struct setting_parser_ctx ctx;

	memset(&ctx, 0, sizeof(ctx));
	ctx.pool = pool;
	ctx.set = p_new(pool, struct dict_sql_settings, 1);
	t_array_init(&ctx.cur_fields, 16);
	p_array_init(&ctx.set->maps, pool, 8);

	if (!settings_read(path, NULL, parse_setting, parse_section, &ctx))
		return NULL;

	if (ctx.set->connect == NULL) {
		i_error("Error in configuration file %s: "
			"Missing connect setting", path);
		return NULL;
	}

	return ctx.set;
}
