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

	bool auth_bind;
	bool starttls;
	bool sasl_bind;
	bool blocking;

	/* parsed */
	int parsed_deref;
	int parsed_scope;
};

extern const struct setting_parser_info ldap_setting_parser_info;

#endif
