#ifndef DB_LDAP_SETTINGS_H
#define DB_LDAP_SETTINGS_H

struct ldap_settings {
	pool_t pool;

	const char *hosts;
	const char *uris;
	const char *auth_dn;
	const char *auth_dn_password;
	const char *passdb_ldap_bind_userdn;

	const char *auth_sasl_mechanism;
	const char *auth_sasl_realm;
	const char *auth_sasl_authz_id;

	const char *deref;
	const char *scope;
	const char *base;

	const char *debug_level;

	const char *user_attrs;
	const char *user_filter;
	const char *pass_attrs;
	const char *pass_filter;
	const char *iterate_attrs;
	const char *iterate_filter;

	unsigned int version;

	uid_t uid;
	gid_t gid;

	bool passdb_ldap_bind;
	bool auth_sasl_bind;
	bool starttls;

	/* parsed */
	int parsed_deref;
	int parsed_scope;
};

extern const struct setting_parser_info ldap_setting_parser_info;
int ldap_setting_post_check(const struct ldap_settings *set, const char **error_r);

#endif
