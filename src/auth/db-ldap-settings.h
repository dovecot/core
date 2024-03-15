#ifndef DB_LDAP_SETTINGS_H
#define DB_LDAP_SETTINGS_H

struct ldap_settings {
	pool_t pool;

	const char *hosts;
	const char *uris;
	const char *dn;
	const char *dnpass;
	const char *auth_bind_userdn;

	const char *sasl_mech;
	const char *sasl_realm;
	const char *sasl_authz_id;

	const char *tls_ca_cert_file;
	const char *tls_ca_cert_dir;
	const char *tls_cert_file;
	const char *tls_key_file;
	const char *tls_cipher_suite;
	const char *tls_require_cert;

	const char *deref;
	const char *scope;
	const char *base;

	const char *ldaprc_path;
	const char *debug_level;

	const char *user_attrs;
	const char *user_filter;
	const char *pass_attrs;
	const char *pass_filter;
	const char *iterate_attrs;
	const char *iterate_filter;

	const char *default_pass_scheme;

	unsigned int ldap_version;

	int ldap_deref;
	int ldap_scope;
	int ldap_tls_require_cert_parsed;

	uid_t uid;
	gid_t gid;

	bool auth_bind;
	bool tls;
	bool sasl_bind;
	bool blocking;
};

extern const struct setting_parser_info ldap_setting_parser_info;

#endif
