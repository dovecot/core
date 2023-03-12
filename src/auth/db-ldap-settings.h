#ifndef DB_LDAP_SETTINGS_H
#define DB_LDAP_SETTINGS_H

enum db_ldap_lookup_type {
	DB_LDAP_LOOKUP_TYPE_PASSDB,
	DB_LDAP_LOOKUP_TYPE_USERDB,
	DB_LDAP_LOOKUP_TYPE_ITERATE,
};

struct ldap_settings {
	pool_t pool;

	const char *uris;

	/* This field prevents ldap_conn_find() from reusing the same
	   connection across stanzas that would otherwise do it.

	   Settings with different connection_group will NOT share the
	   connections, allowing parallel async execution if configured.

	   Note that this field is not explicitly used anywhere, but it
	   affects how ldap_conn_find() compares the settings against an
	   existing connection */
	const char *connection_group;

	const char *auth_dn;
	const char *auth_dn_password;

	ARRAY_TYPE(const_string) auth_sasl_mechanisms;
	const char *auth_sasl_realm;
	const char *auth_sasl_authz_id;

	const char *deref;
	const char *scope;

	unsigned int debug_level;
	unsigned int version;

	uid_t uid;
	gid_t gid;

	bool starttls;

	/* parsed */
	int parsed_deref;
	int parsed_scope;
};

struct ldap_pre_settings {
	pool_t pool;

	/* shared: */
	const char *ldap_base;

	/* passdb: */
	bool passdb_ldap_bind;
	const char *passdb_ldap_filter;
	const char *passdb_ldap_bind_userdn;

	/* userdb: */
	const char *userdb_ldap_filter;
	const char *userdb_ldap_iterate_filter;
};

struct ldap_post_settings {
	pool_t pool;
	ARRAY_TYPE(const_string) iterate_fields;
};

extern const struct setting_parser_info ldap_setting_parser_info;
extern const struct setting_parser_info ldap_pre_setting_parser_info;
extern const struct setting_parser_info ldap_post_setting_parser_info;

int ldap_setting_post_check(const struct ldap_settings *set, const char **error_r);
int ldap_pre_settings_post_check(const struct ldap_pre_settings *set,
				 enum db_ldap_lookup_type type,
				 const char **error_r);

#endif
