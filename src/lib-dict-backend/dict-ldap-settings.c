/* Copyright (c) 2008-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"

#if defined(BUILTIN_LDAP) || defined(PLUGIN_BUILD)

#include "array.h"
#include "str.h"
#include "settings.h"
#include "dict-ldap-settings.h"

#include <ctype.h>

static const char *dict_ldap_commonName = "cn";
static const char *dict_ldap_empty_filter = "";

enum section_type {
	SECTION_ROOT = 0,
	SECTION_MAP,
	SECTION_FIELDS
};

struct dict_ldap_map_attribute {
	const char *name;
	const char *variable;
};

struct setting_parser_ctx {
	pool_t pool;
	struct dict_ldap_settings *set;
	enum section_type type;

	struct dict_ldap_map cur_map;
	ARRAY(struct dict_ldap_map_attribute) cur_attributes;
};

#undef DEF_STR
#undef DEF_BOOL
#undef DEF_UINT

#define DEF_STR(name) DEF_STRUCT_STR(name, dict_ldap_map)
#define DEF_BOOL(name) DEF_STRUCT_BOOL(name, dict_ldap_map)
#define DEF_UINT(name) DEF_STRUCT_UINT(name ,dict_ldap_map)

static const struct setting_def dict_ldap_map_setting_defs[] = {
	DEF_STR(pattern),
	DEF_STR(filter),
	DEF_STR(filter_iter),
	DEF_STR(username_attribute),
	DEF_STR(value_attribute),
	DEF_STR(base_dn),
	DEF_STR(scope),
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

static const char *dict_ldap_attributes_map(struct setting_parser_ctx *ctx)
{
	struct dict_ldap_map_attribute *attributes;
	string_t *pattern;
	const char *p, *name;
	unsigned int i, count;

	/* go through the variables in the pattern, replace them with plain
	   '$' character and add its ldap attribute */
	pattern = t_str_new(strlen(ctx->cur_map.pattern) + 1);
	attributes = array_get_modifiable(&ctx->cur_attributes, &count);

	p_array_init(&ctx->cur_map.ldap_attributes, ctx->pool, count);
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
			if (attributes[i].variable != NULL &&
			    strcmp(attributes[i].variable, name) == 0)
				break;
		}
		if (i == count) {
			return t_strconcat("Missing LDAP attribute for variable: ",
					   name, NULL);
		}

		/* mark this attribute as used */
		attributes[i].variable = NULL;
		array_push_back(&ctx->cur_map.ldap_attributes,
				&attributes[i].name);
	}

	/* make sure there aren't any unused attributes */
	for (i = 0; i < count; i++) {
		if (attributes[i].variable != NULL) {
			return t_strconcat("Unused variable: ",
					   attributes[i].variable, NULL);
		}
	}

	if (ctx->set->max_attribute_count < count)
		ctx->set->max_attribute_count = count;
	ctx->cur_map.pattern = p_strdup(ctx->pool, str_c(pattern));
	return NULL;
}

static const char *dict_ldap_map_finish(struct setting_parser_ctx *ctx)
{
	if (ctx->cur_map.pattern == NULL)
		return "Missing setting: pattern";
	if (ctx->cur_map.filter == NULL)
		ctx->cur_map.filter = dict_ldap_empty_filter;
	if (*ctx->cur_map.filter != '\0') {
		const char *ptr = ctx->cur_map.filter;
		if (*ptr != '(')
			return "Filter must start with (";
		while(*ptr != '\0') ptr++;
		ptr--;
		if (*ptr != ')')
			return "Filter must end with )";
	}
	if (ctx->cur_map.value_attribute == NULL)
		return "Missing setting: value_attribute";

	if (ctx->cur_map.username_attribute == NULL) {
		/* default to commonName */
		ctx->cur_map.username_attribute = dict_ldap_commonName;
	}
	if (ctx->cur_map.scope == NULL) {
		ctx->cur_map.scope_val = 2; /* subtree */
	} else {
		if (strcasecmp(ctx->cur_map.scope, "one") == 0) ctx->cur_map.scope_val = 1;
		else if (strcasecmp(ctx->cur_map.scope, "base") == 0) ctx->cur_map.scope_val = 0;
		else if (strcasecmp(ctx->cur_map.scope, "subtree") == 0) ctx->cur_map.scope_val = 2;
		else return "Scope must be one, base or subtree";
	}
	if (!array_is_created(&ctx->cur_map.ldap_attributes)) {
		/* no attributes besides value. allocate the array anyway. */
		p_array_init(&ctx->cur_map.ldap_attributes, ctx->pool, 1);
		if (strchr(ctx->cur_map.pattern, '$') != NULL)
			return "Missing attributes for pattern variables";
	}
	array_push_back(&ctx->set->maps, &ctx->cur_map);
	i_zero(&ctx->cur_map);
	return NULL;
}

static const char *
parse_setting(const char *key, const char *value,
	      struct setting_parser_ctx *ctx)
{
	struct dict_ldap_map_attribute *attribute;

	switch (ctx->type) {
	case SECTION_ROOT:
		if (strcmp(key, "uri") == 0) {
			ctx->set->uri = p_strdup(ctx->pool, value);
			return NULL;
		}
		if (strcmp(key, "bind_dn") == 0) {
			ctx->set->bind_dn = p_strdup(ctx->pool, value);
			return NULL;
		}
		if (strcmp(key, "password") == 0) {
			ctx->set->password = p_strdup(ctx->pool, value);
			return NULL;
		}
		if (strcmp(key, "timeout") == 0) {
			if (str_to_uint(value, &ctx->set->timeout) != 0) {
				return "Invalid timeout value";
			}
			return NULL;
		}
		if (strcmp(key, "max_idle_time") == 0) {
			if (str_to_uint(value, &ctx->set->max_idle_time) != 0) {
				return "Invalid max_idle_time value";
			}
			return NULL;
		}
		if (strcmp(key, "debug") == 0) {
			if (str_to_uint(value, &ctx->set->debug) != 0) {
				return "invalid debug value";
			}
			return NULL;
		}
		if (strcmp(key, "tls") == 0) {
			if (strcasecmp(value, "yes") == 0) {
				ctx->set->require_ssl = TRUE;
				ctx->set->start_tls = TRUE;
			} else if (strcasecmp(value, "no") == 0) {
				ctx->set->require_ssl = FALSE;
				ctx->set->start_tls = FALSE;
			} else if (strcasecmp(value, "try") == 0) {
				ctx->set->require_ssl = FALSE;
				ctx->set->start_tls = TRUE;
			} else {
				return "tls must be yes, try or no";
			}
			return NULL;
		}
		break;
	case SECTION_MAP:
		return parse_setting_from_defs(ctx->pool,
					       dict_ldap_map_setting_defs,
					       &ctx->cur_map, key, value);
	case SECTION_FIELDS:
		if (*value != '$') {
			return t_strconcat("Value is missing '$' for attribute: ",
					   key, NULL);
		}
		attribute = array_append_space(&ctx->cur_attributes);
		attribute->name = p_strdup(ctx->pool, key);
		attribute->variable = p_strdup(ctx->pool, value + 1);
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
			array_clear(&ctx->cur_attributes);
			ctx->type = SECTION_MAP;
			return TRUE;
		}
		break;
	case SECTION_MAP:
		if (type == NULL) {
			ctx->type = SECTION_ROOT;
			*error_r = dict_ldap_map_finish(ctx);
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
			*error_r = dict_ldap_attributes_map(ctx);
			return FALSE;
		}
		break;
	}
	*error_r = t_strconcat("Unknown section: ", type, NULL);
	return FALSE;
}

struct dict_ldap_settings *
dict_ldap_settings_read(pool_t pool, const char *path, const char **error_r)
{
	struct setting_parser_ctx ctx;

	i_zero(&ctx);
	ctx.pool = pool;
	ctx.set = p_new(pool, struct dict_ldap_settings, 1);
	t_array_init(&ctx.cur_attributes, 16);
	p_array_init(&ctx.set->maps, pool, 8);

	ctx.set->timeout = 30; /* default timeout */
	ctx.set->require_ssl = FALSE; /* try to start SSL */
	ctx.set->start_tls = TRUE;

	if (!settings_read(path, NULL, parse_setting, parse_section,
			   &ctx, error_r))
		return NULL;

	if (ctx.set->uri == NULL) {
		*error_r = t_strdup_printf("Error in configuration file %s: "
					   "Missing ldap uri", path);
		return NULL;
	}

	return ctx.set;
}

#endif
