/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "settings.h"
#include "settings-parser.h"

#include "acl-settings.h"
#include "acl-api-private.h"

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("acl_"#name, name, struct acl_rights_settings)

static const struct setting_define acl_rights_setting_defines[] = {
	DEF(STR, id),
	DEF(STR, rights),
	SETTING_DEFINE_LIST_END,
};

static const struct acl_rights_settings acl_rights_default_settings = {
	.id = "",
	.rights = "",
};

static bool acl_rights_settings_check(void *_set, pool_t ATTR_UNUSED pool,
				     const char **error_r);

const struct setting_parser_info acl_rights_setting_parser_info = {
	.name = "acl_rights",
	.plugin_dependency = "lib01_acl_plugin",

	.defines = acl_rights_setting_defines,
	.defaults = &acl_rights_default_settings,

	.struct_size = sizeof(struct acl_rights_settings),

	.check_func = acl_rights_settings_check,

	.pool_offset1 = 1 + offsetof(struct acl_rights_settings, pool),
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct acl_settings)

static const struct setting_define acl_setting_defines[] = {
	DEF(STR, acl_user),
	DEF(BOOLLIST, acl_groups),
	DEF(STR, acl_driver),
	DEF(STR, acl_global_path),
	DEF(TIME, acl_cache_ttl),
	DEF(BOOL, acl_globals_only),
	DEF(BOOL, acl_defaults_from_inbox),
	DEF(BOOL, acl_ignore),
	{ .type = SET_FILTER_NAME, .key = "acl_sharing_map",
		.required_setting = "dict", },
	{ .type = SET_FILTER_ARRAY,
		.key = "acl",
		.filter_array_field_name = "acl_id",
		.required_setting = "acl_rights",
		.offset = offsetof(struct acl_settings, acl_rights)},
	SETTING_DEFINE_LIST_END,
};

static const struct acl_settings acl_default_settings = {
	.acl_user = "%{master_user}",
	.acl_groups = ARRAY_INIT,
	.acl_rights = ARRAY_INIT,
	.acl_driver = "",
	.acl_global_path = "",
	.acl_cache_ttl = ACL_DEFAULT_CACHE_TTL_SECS,
	.acl_globals_only = FALSE,
	.acl_defaults_from_inbox = FALSE,
	.acl_ignore = FALSE,
};

static bool acl_settings_check(void *_set ATTR_UNUSED, pool_t pool ATTR_UNUSED,
			       const char **error_r ATTR_UNUSED);

const struct setting_parser_info acl_setting_parser_info = {
	.name = "acl",
	.plugin_dependency = "lib01_acl_plugin",

	.defines = acl_setting_defines,
	.defaults = &acl_default_settings,

	.struct_size = sizeof(struct acl_settings),

	.check_func = acl_settings_check,

	.pool_offset1 = 1 + offsetof(struct acl_settings, pool),
};

/* <settings checks> */
static bool acl_rights_settings_check(void *_set, pool_t pool, const char **error_r)
{
	struct acl_rights_settings *set = _set;
	const char *const *right_names;
	const char *id_str = set->id;
	const char *rights_str = set->rights;

	/* Empty id */
	if (*id_str == '\0')
		return TRUE;

	bool neg = *rights_str == '-';
	if (neg)
		rights_str++;

	set->parsed = p_new(pool, struct acl_rights, 1);

	if (acl_identifier_parse(set->id, set->parsed) < 0) {
		*error_r = t_strdup_printf("Invalid identifier '%s'", set->id);
		return FALSE;
	}

	right_names = acl_right_names_parse(pool, rights_str, error_r);
	if (right_names == NULL)
		return FALSE;

	if (neg) {
		set->parsed->neg_rights = right_names;
	} else {
		set->parsed->rights = right_names;
	}
	return TRUE;
}

static bool acl_settings_check(void *_set ATTR_UNUSED, pool_t pool ATTR_UNUSED,
			       const char **error_r ATTR_UNUSED)
{
	struct acl_settings *set = _set;
	if (array_is_created(&set->acl_groups))
		array_sort(&set->acl_groups, i_strcmp_p);
	return TRUE;
}

/* </settings checks> */
