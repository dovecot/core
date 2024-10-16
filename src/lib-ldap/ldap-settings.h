#ifndef LDAP_SETTINGS_H
#define LDAP_SETTINGS_H

struct ssl_settings;

struct ldap_client_settings {
	pool_t pool;

	const char *uris;
	const char *auth_dn;
	const char *auth_dn_password;

	unsigned int timeout_secs;
	unsigned int max_idle_time_secs;
	unsigned int debug_level;
	bool starttls;
};

extern const struct setting_parser_info ldap_client_setting_parser_info;

int ldap_client_settings_get(struct event *event,
			     const struct ldap_client_settings **set_r,
			     const struct ssl_settings **ssl_set_r,
			     const char **error_r);

#endif
