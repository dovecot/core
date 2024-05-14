/* Copyright (c) 2005-2024 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings.h"
#include "db-ldap-settings.h"

/* <settings checks> */

#include "ldap.h"
static bool ldap_setting_check(void *_set, pool_t pool, const char **error_r);

/* </settings checks> */

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("ldap_"#name, name, struct ldap_settings)
#define DEFN(type, field, name) \
	SETTING_DEFINE_STRUCT_##type(#name, field, struct ldap_settings)

static const struct setting_define ldap_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "passdb_ldap", },
	{ .type = SET_FILTER_NAME, .key = "userdb_ldap", },
	DEF(STR, hosts),
	DEF(STR, uris),
	DEF(STR, auth_dn),
	DEF(STR, auth_dn_password),
	DEFN(BOOL, passdb_ldap_bind, passdb_ldap_bind),
	DEFN(STR, passdb_ldap_bind_userdn, passdb_ldap_bind_userdn),
	DEF(STR, auth_sasl_mechanism),
	DEF(STR, auth_sasl_realm),
	DEF(STR, auth_sasl_authz_id),
	DEF(BOOL, starttls),
	DEF(STR, deref),
	DEF(STR, scope),
	DEF(STR, base),
	DEF(UINT, version),
	DEF(STR, debug_level),
	DEF(STR, user_attrs),
	DEF(STR, user_filter),
	DEF(STR, pass_attrs),
	DEF(STR, pass_filter),
	DEF(STR, iterate_attrs),
	DEF(STR, iterate_filter),
	SETTING_DEFINE_LIST_END
};

static const struct ldap_settings ldap_default_settings = {
	.hosts = "",
	.uris = "",
	.auth_dn = "",
	.auth_dn_password = "",
	.passdb_ldap_bind = FALSE,
	.passdb_ldap_bind_userdn = "",
	.auth_sasl_mechanism = "",
	.auth_sasl_realm = "",
	.auth_sasl_authz_id = "",
	.starttls = FALSE,
	.deref = "never",
	.scope = "subtree",
	.base = "",
	.version = 3,
	.debug_level = "0",
	.user_attrs = "homeDirectory=home,uidNumber=uid,gidNumber=gid",
	.user_filter = "(&(objectClass=posixAccount)(uid=%u))",
	.pass_attrs = "uid=user,userPassword=password",
	.pass_filter = "(&(objectClass=posixAccount)(uid=%u))",
	.iterate_attrs = "uid=user",
	.iterate_filter = "(objectClass=posixAccount)",
};

static const struct setting_keyvalue ldap_default_settings_keyvalue[] = {
	{ "passdb_ldap/passdb_default_password_scheme", "crypt" },
	{ NULL, NULL }
};

const struct setting_parser_info ldap_setting_parser_info = {
	.name = "auth_ldap",

	.check_func = ldap_setting_check,
	.defines = ldap_setting_defines,
	.defaults = &ldap_default_settings,
	.default_settings = ldap_default_settings_keyvalue,

	.struct_size = sizeof(struct ldap_settings),
	.pool_offset1 = 1 + offsetof(struct ldap_settings, pool),
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

static int ldap_parse_scope(const char *str, int *scope_r)
{
	if (strcasecmp(str, "base") == 0)
		*scope_r = LDAP_SCOPE_BASE;
	else if (strcasecmp(str, "onelevel") == 0)
		*scope_r = LDAP_SCOPE_ONELEVEL;
	else if (strcasecmp(str, "subtree") == 0)
		*scope_r = LDAP_SCOPE_SUBTREE;
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

#ifndef LDAP_HAVE_INITIALIZE
	if (*set->uris != '\0') {
		*error_r = "ldap_uris set, but Dovecot compiled without support for LDAP uris "
			   "(ldap_initialize() not supported by LDAP library)";
		return FALSE;
	}
#endif

#ifndef LDAP_HAVE_START_TLS_S
	if (set->starttls) {
		*error_r = "ldap_starttls=yes, but your LDAP library doesn't support TLS";
		return FALSE;
	}
#endif

#ifndef HAVE_LDAP_SASL
	if (*set->auth_sasl_mechanism != '\0') {
		*error_r = "ldap_auth_sasl_mechanism set, but no SASL support compiled in";
		return FALSE;
	}
#endif

	return TRUE;
}

/* </settings checks> */

int ldap_setting_post_check(const struct ldap_settings *set, const char **error_r)
{
	if (*set->base == '\0') {
		*error_r = "No ldap_base given";
		return -1;
	}

	if (*set->uris == '\0' && *set->hosts == '\0') {
		*error_r = "Neither ldap_uris nor ldap_hosts set";
		return -1;
	}

	if (set->version < 3) {
		if (*set->auth_sasl_mechanism != '\0') {
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
