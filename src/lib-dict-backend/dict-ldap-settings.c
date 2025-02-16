/* Copyright (c) 2008-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"

#if defined(HAVE_LDAP) && (defined(BUILTIN_LDAP) || defined(PLUGIN_BUILD))

#include "array.h"
#include "str.h"
#include "settings.h"
#include "settings-parser.h"
#include "dict-ldap-settings.h"
#include "dict.h"

#include <ctype.h>

/* <settings checks> */
#include "ldap-settings-parse.h"

static bool
dict_ldap_map_settings_post_check(void *set, pool_t pool, const char **error_r);

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
	DEFN(ENUM, scope, ldap_scope),
	SETTING_DEFINE_LIST_END
};

static const struct dict_ldap_map_settings dict_ldap_map_default_settings = {
	.pattern = "",
	.base = "",
	.scope = "subtree:onelevel:base",
};

const struct setting_parser_info dict_ldap_map_setting_parser_info = {
	.name = "dict_ldap_map",

	.defines = dict_ldap_map_setting_defines,
	.defaults = &dict_ldap_map_default_settings,

	.struct_size = sizeof(struct dict_ldap_map_settings),
	.pool_offset1 = 1 + offsetof(struct dict_ldap_map_settings, pool),
};

#undef DEFN
#define DEFN(type, field, name) \
	SETTING_DEFINE_STRUCT_##type(#name, field, struct dict_ldap_map_pre_settings)

static const struct setting_define dict_ldap_map_pre_setting_defines[] = {
	DEFN(STR, filter, dict_map_ldap_filter),
	SETTING_DEFINE_LIST_END
};

static const struct dict_ldap_map_pre_settings dict_ldap_map_pre_default_settings = {
	.filter = "",
};

const struct setting_parser_info dict_ldap_map_pre_setting_parser_info = {
	.name = "dict_ldap_map_pre",

	.defines = dict_ldap_map_pre_setting_defines,
	.defaults = &dict_ldap_map_pre_default_settings,

	.struct_size = sizeof(struct dict_ldap_map_pre_settings),
	.pool_offset1 = 1 + offsetof(struct dict_ldap_map_pre_settings, pool),
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("dict_map_"#name, name, struct dict_ldap_map_post_settings)

static const struct setting_define dict_ldap_map_post_setting_defines[] = {
	DEF(STR, value),
	SETTING_DEFINE_LIST_END
};

static const struct dict_ldap_map_post_settings dict_ldap_map_post_default_settings = {
	.value = "",
};

const struct setting_parser_info dict_ldap_map_post_setting_parser_info = {
	.name = "dict_ldap_map_post",

	.defines = dict_ldap_map_post_setting_defines,
	.defaults = &dict_ldap_map_post_default_settings,
	.check_func = dict_ldap_map_settings_post_check,

	.struct_size = sizeof(struct dict_ldap_map_post_settings),
	.pool_offset1 = 1 + offsetof(struct dict_ldap_map_post_settings, pool),
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

/* <settings checks> */

static bool
dict_ldap_map_settings_post_check(void *_set, pool_t pool,
				  const char **error_r ATTR_UNUSED)
{
	struct dict_ldap_map_post_settings *set = _set;
	p_array_init(&set->values, pool, 1);
	if (*set->value != '\0')
		array_push_back(&set->values, &set->value);
	return TRUE;
}

/* </settings checks> */

static int ldap_parse_attributes(struct dict_ldap_map_settings *set,
				 struct dict_ldap_map_post_settings *post,
				 const char **error_r)
{
	const char *value;
	p_array_init(&set->parsed_attributes, set->pool, 2);
	array_foreach_elem(&post->values, value) {
		struct var_expand_program *prog;

		if (var_expand_program_create(value, &prog, error_r) < 0) {
			*error_r = t_strdup_printf("Invalid ldap_map_value %s: %s",
						   value, *error_r);
			return -1;
		}

		const char *const *vars = var_expand_program_variables(prog);
		for (; *vars != NULL; vars++) {
			const char *ldap_attr;
			if (!str_begins(*vars, "ldap:", &ldap_attr) &&
			    !str_begins(*vars, "ldap_multi:", &ldap_attr))
			    	continue;

			/* When we free program, this name would be invalid,
			   so dup it here. */
			ldap_attr = p_strdup(set->pool, ldap_attr);
			array_push_back(&set->parsed_attributes, &ldap_attr);
		}
		var_expand_program_free(&prog);
	}
	return 0;
}

static int
dict_ldap_map_settings_postcheck(struct dict_ldap_map_settings *set,
				 struct dict_ldap_map_pre_settings *pre,
				 struct dict_ldap_map_post_settings *post,
				 const char **error_r)
{
	if (!str_begins_with(pre->filter, "(")) {
		*error_r = "ldap_filter must start with '('";
		return -1;
	}
	if (!str_ends_with(pre->filter, ")")) {
		*error_r = "ldap_filter must end with ')'";
		return -1;
	}

	if (*set->pattern == '\0') {
		*error_r = "ldap_map_pattern not set";
		return -1;
	}

	if (array_is_empty(&post->values)) {
		*error_r = "ldap_map_value not set";
		return -1;
	}

	if (ldap_parse_scope(set->scope, &set->parsed_scope) < 0) {
		*error_r = t_strdup_printf("Unknown ldap_scope: %s",
					   set->scope);
		return -1;
	}

	return ldap_parse_attributes(set, post, error_r);
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

static void dict_ldap_settings_parse_pattern(struct dict_ldap_map_settings *map)
{
	string_t *pattern = t_str_new(strlen(map->pattern) + 1);
	p_array_init(&map->parsed_pattern_keys, map->pool, 2);

	/* go through the variables in the pattern, replace them with plain
	   '$' character and add its key */

	for (const char *p = map->pattern; *p != '\0';) {
		if (*p != '$') {
			str_append_c(pattern, *p);
			p++;
			continue;
		}
		p++;
		str_append_c(pattern, '$');

		const char *key = p_strdup(map->pool, pattern_read_name(&p));
		array_push_back(&map->parsed_pattern_keys, &key);
	}

	map->parsed_pattern = p_strdup(map->pool, str_c(pattern));
}

#define chain_ref(dst, src) \
STMT_START { 				 \
 	pool_add_external_ref(dst, src); \
	pool_t tmp = (src);              \
	pool_unref(&tmp);                \
} STMT_END

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
		struct dict_ldap_map_settings *map = NULL;
		struct dict_ldap_map_pre_settings *pre = NULL;
		struct dict_ldap_map_post_settings *post = NULL;
		if (settings_get_filter(event, "dict_map", name,
					&dict_ldap_map_setting_parser_info,
					0, &map, error_r) < 0 ||
		    settings_get_filter(event, "dict_map", name,
					&dict_ldap_map_pre_setting_parser_info,
					SETTINGS_GET_FLAG_NO_EXPAND,
					&pre, error_r) < 0 ||
		    settings_get_filter(event, "dict_map", name,
					&dict_ldap_map_post_setting_parser_info,
					SETTINGS_GET_FLAG_NO_EXPAND,
					&post, error_r) < 0) {
			*error_r = t_strdup_printf("Failed to get dict_map %s: %s",
						   name, *error_r);
			settings_free(map);
			settings_free(pre);
			settings_free(post);
			return -1;
		}

		if (dict_ldap_map_settings_postcheck(map, pre, post, error_r) < 0) {
			settings_free(map);
			settings_free(pre);
			settings_free(post);
			return -1;
		}
		settings_free(pre);
		settings_free(post);

		dict_ldap_settings_parse_pattern(map);
		chain_ref(set->pool, map->pool);
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
