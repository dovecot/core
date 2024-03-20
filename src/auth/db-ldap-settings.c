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

static const struct setting_define ldap_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "passdb_ldap", },
	{ .type = SET_FILTER_NAME, .key = "userdb_ldap", },
	DEF(STR, hosts),
	DEF(STR, uris),
	DEF(STR, dn),
	DEF(STR, dnpass),
	DEF(BOOL, auth_bind),
	DEF(STR, auth_bind_userdn),
	DEF(BOOL, tls),
	DEF(BOOL, sasl_bind),
	DEF(STR, sasl_mech),
	DEF(STR, sasl_realm),
	DEF(STR, sasl_authz_id),
	DEF(STR, tls_ca_cert_file),
	DEF(STR, tls_ca_cert_dir),
	DEF(STR, tls_cert_file),
	DEF(STR, tls_key_file),
	DEF(STR, tls_cipher_suite),
	DEF(STR, tls_require_cert),
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
	DEF(STR, default_pass_scheme),
	DEF(BOOL, blocking),
	SETTING_DEFINE_LIST_END
};

static const struct ldap_settings ldap_default_settings = {
	.hosts = "",
	.uris = "",
	.dn = "",
	.dnpass = "",
	.auth_bind = FALSE,
	.auth_bind_userdn = "",
	.tls = FALSE,
	.sasl_bind = FALSE,
	.sasl_mech = "",
	.sasl_realm = "",
	.sasl_authz_id = "",
	.tls_ca_cert_file = "",
	.tls_ca_cert_dir = "",
	.tls_cert_file = "",
	.tls_key_file = "",
	.tls_cipher_suite = "",
	.tls_require_cert = "",
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
	.default_pass_scheme = "crypt",
	.blocking = FALSE
};

const struct setting_parser_info ldap_setting_parser_info = {
	.name = "auth_ldap",

	.check_func = ldap_setting_check,
	.defines = ldap_setting_defines,
	.defaults = &ldap_default_settings,

	.struct_size = sizeof(struct ldap_settings),
	.pool_offset1 = 1 + offsetof(struct ldap_settings, pool),
};

/* <settings checks> */

#ifdef OPENLDAP_TLS_OPTIONS
static int ldap_parse_tls_require_cert(const char *str, int *value_r)
{
	if (strcasecmp(str, "never") == 0)
		*value_r = LDAP_OPT_X_TLS_NEVER;
	else if (strcasecmp(str, "hard") == 0)
		*value_r = LDAP_OPT_X_TLS_HARD;
	else if (strcasecmp(str, "demand") == 0)
		*value_r = LDAP_OPT_X_TLS_DEMAND;
	else if (strcasecmp(str, "allow") == 0)
		*value_r = LDAP_OPT_X_TLS_ALLOW;
	else if (strcasecmp(str, "try") == 0)
		*value_r = LDAP_OPT_X_TLS_TRY;
	else
		return -1;
	return 1;
}
#endif

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

        if (ldap_parse_deref(set->deref, &set->ldap_deref) < 0) {
		*error_r = t_strdup_printf("Unknown ldap_deref option '%s'",
					   set->deref);
		return FALSE;
	}

	if (ldap_parse_scope(set->scope, &set->ldap_scope) < 0) {
		*error_r = t_strdup_printf("Unknown ldap_scope option '%s'",
					   set->scope);
		return FALSE;
	}

#ifdef OPENLDAP_TLS_OPTIONS
	if (ldap_parse_tls_require_cert(set->tls_require_cert,
					     &set->ldap_tls_require_cert_parsed) < 0) {
		*error_r = t_strdup_printf("Unknown tls_require_cert value '%s'",
					   set->tls_require_cert);
		return FALSE;
	}
#endif

	return TRUE;
}

/* </settings checks> */
