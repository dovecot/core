/* Copyright (c) 2005-2024 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "settings.h"
#include "db-ldap-settings.h"

#ifdef HAVE_LDAP

/* <settings checks> */
#include "ldap-settings-parse.h"

static bool ldap_setting_check(void *_set, pool_t pool, const char **error_r);
/* </settings checks> */

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("ldap_"#name, name, struct ldap_settings)

static const struct setting_define ldap_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "passdb_ldap", },
	{ .type = SET_FILTER_NAME, .key = "userdb_ldap", },
	DEF(STR, uris),
	DEF(STR, connection_group),
	DEF(STR, auth_dn),
	DEF(STR, auth_dn_password),
	DEF(BOOLLIST, auth_sasl_mechanisms),
	DEF(STR, auth_sasl_realm),
	DEF(STR, auth_sasl_authz_id),
	DEF(BOOL, starttls),
	DEF(ENUM, deref),
	DEF(ENUM, scope),
	DEF(UINT, version),
	DEF(UINT, debug_level),
	SETTING_DEFINE_LIST_END
};

static const struct ldap_settings ldap_default_settings = {
	.uris = "",
	.connection_group = "",
	.auth_dn = "",
	.auth_dn_password = "",
	.auth_sasl_mechanisms = ARRAY_INIT,
	.auth_sasl_realm = "",
	.auth_sasl_authz_id = "",
	.starttls = FALSE,
	.deref = "never:searching:finding:always",
	.scope = "subtree:onelevel:base",
	.version = 3,
	.debug_level = 0,
};

static const struct setting_keyvalue ldap_default_settings_keyvalue[] = {
	{ "passdb_ldap/passdb_default_password_scheme", "crypt" },
	{ "passdb_ldap/passdb_fields_import_all", "no" },
	{ "userdb_ldap/userdb_fields_import_all", "no" },
	{ NULL, NULL }
};

const struct setting_parser_info ldap_setting_parser_info = {
	.name = "auth_ldap",
#ifndef BUILTIN_LDAP
	.plugin_dependency = "auth/libauthdb_ldap",
#endif

	.check_func = ldap_setting_check,
	.defines = ldap_setting_defines,
	.defaults = &ldap_default_settings,
	.default_settings = ldap_default_settings_keyvalue,

	.struct_size = sizeof(struct ldap_settings),
	.pool_offset1 = 1 + offsetof(struct ldap_settings, pool),
};

#undef DEF
#undef DEFN
#define DEF(type, field) \
	SETTING_DEFINE_STRUCT_##type(#field, field, struct ldap_pre_settings)

static const struct setting_define ldap_pre_setting_defines[] = {
	DEF(STR, ldap_base),
	DEF(BOOL, passdb_ldap_bind),
	DEF(STR, passdb_ldap_filter),
	DEF(STR, passdb_ldap_bind_userdn),
	DEF(STR, userdb_ldap_filter),
	DEF(STR, userdb_ldap_iterate_filter),
	SETTING_DEFINE_LIST_END
};

static const struct ldap_pre_settings ldap_pre_default_settings = {
	.ldap_base = "",
	.passdb_ldap_bind = FALSE,
	.passdb_ldap_filter = "",
	.passdb_ldap_bind_userdn = "",
	.userdb_ldap_filter = "",
	.userdb_ldap_iterate_filter = "",
};

const struct setting_parser_info ldap_pre_setting_parser_info = {
	.name = "auth_ldap_pre",
#ifndef BUILTIN_LDAP
	.plugin_dependency = "auth/libauthdb_ldap",
#endif

	.defines = ldap_pre_setting_defines,
	.defaults = &ldap_pre_default_settings,

	.struct_size = sizeof(struct ldap_pre_settings),
	.pool_offset1 = 1 + offsetof(struct ldap_pre_settings, pool),
};

#undef DEF
#define DEF(type, field) \
	SETTING_DEFINE_STRUCT_##type("userdb_ldap_"#field, field, struct ldap_post_settings)

static const struct setting_define ldap_post_setting_defines[] = {
	DEF(STRLIST, iterate_fields),
	SETTING_DEFINE_LIST_END
};

static const struct ldap_post_settings ldap_post_default_settings = {
	.iterate_fields = ARRAY_INIT,
};

const struct setting_parser_info ldap_post_setting_parser_info = {
	.name = "auth_ldap_post",
#ifndef BUILTIN_LDAP
	.plugin_dependency = "auth/libauthdb_ldap",
#endif

	.defines = ldap_post_setting_defines,
	.defaults = &ldap_post_default_settings,

	.struct_size = sizeof(struct ldap_post_settings),
	.pool_offset1 = 1 + offsetof(struct ldap_post_settings, pool),
};

/* <settings checks> */

static int ldap_parse_deref(const char *str, int *ref_r)
{
	if (strcasecmp(str, "never") == 0)
		*ref_r = LDAP_DEREF_NEVER;
	else if (strcasecmp(str, "searching") == 0)
		*ref_r = LDAP_DEREF_SEARCHING;
	else if (strcasecmp(str, "finding") == 0)
		*ref_r = LDAP_DEREF_FINDING;
	else if (strcasecmp(str, "always") == 0)
		*ref_r = LDAP_DEREF_ALWAYS;
	else
		return -1;
	return 0;
}

static bool ldap_setting_check(void *_set, pool_t pool ATTR_UNUSED,
			       const char **error_r)
{
	struct ldap_settings *set = _set;

        if (ldap_parse_deref(set->deref, &set->parsed_deref) < 0) {
		*error_r = t_strdup_printf("Unknown ldap_deref option '%s'",
					   set->deref);
		return FALSE;
	}

	if (ldap_parse_scope(set->scope, &set->parsed_scope) < 0) {
		*error_r = t_strdup_printf("Unknown ldap_scope option '%s'",
					   set->scope);
		return FALSE;
	}

#ifndef HAVE_LDAP_SASL
	if (!array_is_empty(&set->auth_sasl_mechanisms)) {
		*error_r = "ldap_auth_sasl_mechanism set, but no SASL support compiled in";
		return FALSE;
	}
#endif

	return TRUE;
}

/* </settings checks> */

int ldap_setting_post_check(const struct ldap_settings *set, const char **error_r)
{
	if (*set->uris == '\0') {
		*error_r = "ldap_uris not set";
		return -1;
	}

	if (set->version < 3) {
		if (!array_is_empty(&set->auth_sasl_mechanisms)) {
			*error_r = "ldap_auth_sasl_mechanism requires ldap_version=3";
			return -1;
		}
		if (set->starttls) {
			*error_r = "ldap_starttls=yes requires ldap_version=3";
			return -1;
		}
	}

	return 0;
}

int ldap_pre_settings_post_check(const struct ldap_pre_settings *set,
				 enum db_ldap_lookup_type type,
				 const char **error_r)
{
	if (*set->ldap_base == '\0') {
		*error_r = "No ldap_base given";
		return -1;
	}
	switch (type) {
	case DB_LDAP_LOOKUP_TYPE_PASSDB:
		if (set->passdb_ldap_filter[0] == '\0') {
			*error_r = "No passdb_ldap_filter given";
			return -1;
		}
		break;
	case DB_LDAP_LOOKUP_TYPE_USERDB:
		if (set->userdb_ldap_filter[0] == '\0') {
			*error_r = "No userdb_ldap_filter given";
			return -1;
		}
		break;
	case DB_LDAP_LOOKUP_TYPE_ITERATE:
		if (set->userdb_ldap_iterate_filter[0] == '\0') {
			*error_r = "No userdb_ldap_iterate_filter given";
			return -1;
		}
		break;
	}

	return 0;
}

#endif
