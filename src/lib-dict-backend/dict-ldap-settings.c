/* Copyright (c) 2008-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"

#if defined(BUILTIN_LDAP) || defined(PLUGIN_BUILD)

#include "array.h"
#include "str.h"
#include "settings.h"
#include "settings-parser.h"
#include "dict-ldap-settings.h"

#include <ctype.h>

/* <settings checks> */
#include "ldap-settings-parse.h"
/* </settings checks> */

#undef DEF
#undef DEFN
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("dict_map_"#name, name, struct dict_ldap_map_settings)
#define DEFN(type, field, name) \
	SETTING_DEFINE_STRUCT_##type(#name, field, struct dict_ldap_map_settings)
static const struct setting_define dict_ldap_map_setting_defines[] = {
	DEF(STR, pattern),
	DEFN(STR, base, ldap_base),
	DEFN(STR, filter, ldap_filter),
	DEFN(ENUM, scope, ldap_scope),
	DEF(STR, username_attribute),
	DEF(STR, value_attribute),
	DEF(STRLIST, fields),
	SETTING_DEFINE_LIST_END
};

static const struct dict_ldap_map_settings dict_ldap_map_default_settings = {
	.pattern = "",
	.filter = "",
	.username_attribute = "cn",
	.value_attribute = "",
	.base = "",
	.scope = "subtree:onelevel:base",
	.fields = ARRAY_INIT,
	.parsed_pattern_keys = ARRAY_INIT,
};

const struct setting_parser_info dict_ldap_map_setting_parser_info = {
	.name = "dict_ldap_map",

	.defines = dict_ldap_map_setting_defines,
	.defaults = &dict_ldap_map_default_settings,

	.struct_size = sizeof(struct dict_ldap_map_settings),
	.pool_offset1 = 1 + offsetof(struct dict_ldap_map_settings, pool),
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("ldap_"#name, name, struct dict_ldap_settings)
static const struct setting_define dict_ldap_setting_defines[] = {
	{ .type = SET_FILTER_ARRAY, .key = "dict_map",
	  .offset = offsetof(struct dict_ldap_settings, maps),
	  .filter_array_field_name = "dict_map_pattern", },
	SETTING_DEFINE_LIST_END
};

static const struct dict_ldap_settings dict_ldap_default_settings = {
	.maps = ARRAY_INIT,
};

const struct setting_parser_info dict_ldap_setting_parser_info = {
	.name = "dict_ldap",

	.defines = dict_ldap_setting_defines,
	.defaults = &dict_ldap_default_settings,

	.struct_size = sizeof(struct dict_ldap_settings),
	.pool_offset1 = 1 + offsetof(struct dict_ldap_settings, pool),
};

static int
dict_ldap_map_settings_postcheck(struct dict_ldap_map_settings *set,
			     const char **error_r)
{
	if (!str_begins_with(pre->filter, "(")) {
		*error_r = "ldap_filter must start with '('";
		return -1;
	}
	if (set->filter[strlen(set->filter) - 1]!= ')') {
		*error_r = "ldap_filter must end with ')'";
		return -1;
	}

	if (*set->pattern == '\0') {
		*error_r = "ldap_map_pattern not set";
		return -1;
	}

	if (*set->username_attribute == '\0') {
		*error_r = "username_attribute not set";
		return -1;
	}

	if (*set->value_attribute == '\0') {
		*error_r = "value_attribute  not set";
		return -1;
	}

	if (array_is_empty(&set->fields)) {
		if (strchr(set->pattern, '$') != NULL) {
			*error_r = "ldap_attributes missing for pattern variables";
			return -1;
		}
		p_array_init(&set->fields, set->pool, 1);
	} else {
		unsigned int count;
		const char *const *fields = array_get(&set->fields, &count);
		for (unsigned index = 0; index < count; index += 2, fields += 2) {
			if (**fields != '$') {
				*error_r = t_strdup_printf(
					"value not starting with '$' for attribute %s",
					*fields);
				return -1;
			}
		}
	}

	if (ldap_parse_scope(set->scope, &set->parsed_scope) < 0) {
		*error_r = t_strdup_printf("Unknown ldap_scope: %s",
					   set->scope);
		return -1;
	}

	return 0;
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
	name = t_strdup_until(name, p);
	return name;
}

static int
dict_ldap_settings_parse_pattern(struct dict_ldap_map_settings *map,
				 const char **error_r)
{
	const char *attribute, *variable, *p;
	unsigned int count, index;

	const char **const fields = array_get_modifiable(&map->fields, &count);
	p_array_init(&map->parsed_pattern_keys, map->pool, count / 2);
	string_t *pattern = t_str_new(strlen(map->pattern) + 1);

	for (index = 0; index < count; ) {
		attribute = fields[index++];
		variable = fields[index++];
		if (*variable != '$') {
			*error_r = t_strdup_printf(
				"value not starting with '$' for attribute %s",
				attribute);
			return -1;
		}
	}

	/* go through the variables in the pattern, replace them with plain
	   '$' character and add its ldap attribute */

	for (p = map->pattern; *p != '\0';) {
		if (*p != '$') {
			str_append_c(pattern, *p);
			p++;
			continue;
		}
		p++;
		str_append_c(pattern, '$');

		const char *name = pattern_read_name(&p);
		for (index = 0; index < count; ) {
			attribute = fields[index++];
			variable = fields[index++];
			if (variable != NULL &&
			    strcmp(variable, name) == 0)
				break;
		}
		if (index == count) {
			*error_r = t_strdup_printf(
				"Missing LDAP attribute for variable: %s", name);
			return -1;
		}

		/* mark this attribute as used */
		array_push_back(&map->parsed_pattern_keys, &attribute);
		variable = NULL;
	}

	/* make sure there aren't any unused attributes */
	for (index = 1; index < count; index += 2) {
		variable = fields[index];
		if (variable != NULL) {
			*error_r = t_strdup_printf("Unused variable: %s",
						   variable);
			return -1;
		}
	}

	map->parsed_pattern = p_strdup(map->pool, str_c(pattern));
	return 0;
}

static int
dict_ldap_settings_parse_maps(struct event *event, struct dict_ldap_settings *set,
			      const char **error_r)
{
	if (array_is_empty(&set->maps)) {
		*error_r = "no dict_maps found by dict ldap driver";
		return -1;
	}

	p_array_init(&set->parsed_maps, set->pool, array_count(&set->maps));

	const char *name;
	array_foreach_elem(&set->maps, name) {
		struct dict_ldap_map_settings *map;
		if (settings_get_filter(event, "dict_map", name,
					&dict_ldap_map_setting_parser_info,
					SETTINGS_GET_FLAG_NO_EXPAND, &map,
					error_r) < 0) {
			*error_r = t_strdup_printf("Failed to get dict_map %s: %s",
						   name, *error_r);
			return -1;
		}

		if (dict_ldap_map_settings_postcheck(map, error_r) < 0) {
			settings_free(map);
			return -1;
		}

		if (dict_ldap_settings_parse_pattern(map, error_r) < 0) {
			settings_free(map);
			return -1;
		}

		pool_add_external_ref(set->pool, map->pool);
		pool_t pool_copy = map->pool;
		pool_unref(&pool_copy);

		array_push_back(&set->parsed_maps, map);
	}

	return 0;
}

int dict_ldap_settings_get(struct event *event,
			   const struct dict_ldap_settings **set_r,
			   const char **error_r)
{
	struct dict_ldap_settings *set = NULL;
	if (settings_get(event, &dict_ldap_setting_parser_info, 0, &set, error_r) < 0 ||
	    dict_ldap_settings_parse_maps(event, set, error_r) < 0) {
		settings_free(set);
		return -1;
	}

	*set_r = set;
	*error_r = NULL;
	return 0;
}

#endif
