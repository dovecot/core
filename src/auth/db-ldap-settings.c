/* Copyright (c) 2005-2024 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings.h"
#include "db-ldap-settings.h"

#undef DEF
/*
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("passdb_"#name, name, struct auth_passdb_settings)
*/
#define DEF_STR(name) DEF_STRUCT_STR(name, ldap_settings)
#define DEF_INT(name) DEF_STRUCT_INT(name, ldap_settings)
#define DEF_BOOL(name) DEF_STRUCT_BOOL(name, ldap_settings)

static struct setting_def ldap_setting_defs[] = {
	DEF_STR(hosts),
	DEF_STR(uris),
	DEF_STR(dn),
	DEF_STR(dnpass),
	DEF_BOOL(auth_bind),
	DEF_STR(auth_bind_userdn),
	DEF_BOOL(tls),
	DEF_BOOL(sasl_bind),
	DEF_STR(sasl_mech),
	DEF_STR(sasl_realm),
	DEF_STR(sasl_authz_id),
	DEF_STR(tls_ca_cert_file),
	DEF_STR(tls_ca_cert_dir),
	DEF_STR(tls_cert_file),
	DEF_STR(tls_key_file),
	DEF_STR(tls_cipher_suite),
	DEF_STR(tls_require_cert),
	DEF_STR(deref),
	DEF_STR(scope),
	DEF_STR(base),
	DEF_INT(ldap_version),
	DEF_STR(debug_level),
	DEF_STR(ldaprc_path),
	DEF_STR(user_attrs),
	DEF_STR(user_filter),
	DEF_STR(pass_attrs),
	DEF_STR(pass_filter),
	DEF_STR(iterate_attrs),
	DEF_STR(iterate_filter),
	DEF_STR(default_pass_scheme),
	DEF_BOOL(blocking),

	{ 0, NULL, 0 }
};

static struct ldap_settings ldap_default_settings = {
	.hosts = NULL,
	.uris = NULL,
	.dn = NULL,
	.dnpass = NULL,
	.auth_bind = FALSE,
	.auth_bind_userdn = NULL,
	.tls = FALSE,
	.sasl_bind = FALSE,
	.sasl_mech = NULL,
	.sasl_realm = NULL,
	.sasl_authz_id = NULL,
	.tls_ca_cert_file = NULL,
	.tls_ca_cert_dir = NULL,
	.tls_cert_file = NULL,
	.tls_key_file = NULL,
	.tls_cipher_suite = NULL,
	.tls_require_cert = NULL,
	.deref = "never",
	.scope = "subtree",
	.base = NULL,
	.ldap_version = 3,
	.debug_level = "0",
	.ldaprc_path = "",
	.user_attrs = "homeDirectory=home,uidNumber=uid,gidNumber=gid",
	.user_filter = "(&(objectClass=posixAccount)(uid=%u))",
	.pass_attrs = "uid=user,userPassword=password",
	.pass_filter = "(&(objectClass=posixAccount)(uid=%u))",
	.iterate_attrs = "uid=user",
	.iterate_filter = "(objectClass=posixAccount)",
	.default_pass_scheme = "crypt",
	.blocking = FALSE
};
