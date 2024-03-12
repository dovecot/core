#ifndef DB_LDAP_SETTINGS_H
#define DB_LDAP_SETTINGS_H

struct ldap_settings {
	const char *hosts;
	const char *uris;
	const char *dn;
	const char *dnpass;
	bool auth_bind;
	const char *auth_bind_userdn;

	bool tls;
	bool sasl_bind;
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
	unsigned int ldap_version;

	const char *ldaprc_path;
	const char *debug_level;

	const char *user_attrs;
	const char *user_filter;
	const char *pass_attrs;
	const char *pass_filter;
	const char *iterate_attrs;
	const char *iterate_filter;

	const char *default_pass_scheme;
	bool blocking;

	/* ... */
	int ldap_deref, ldap_scope, ldap_tls_require_cert_parsed;
	uid_t uid;
	gid_t gid;
};

#endif
