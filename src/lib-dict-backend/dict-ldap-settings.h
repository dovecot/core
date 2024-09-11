#ifndef DICT_LDAP_SETTINGS_H
#define DICT_LDAP_SETTINGS_H

struct dict_ldap_map_settings {
	/* pattern is in simplified form: all variables are stored as simple
	   '$' character. fields array is sorted by the variable index. */
	const char *pattern;
	const char *filter;
	const char *username_attribute;
	const char *value_attribute;
	const char *base_dn;
	const char *scope;
	int scope_val;
	unsigned int timeout;

	ARRAY_TYPE(const_string) ldap_attributes;
};

struct dict_ldap_settings {
	const char *uri;
	const char *bind_dn;
	const char *password;
	unsigned int timeout;
	unsigned int max_idle_time;
	unsigned int debug;
	bool require_ssl;
	bool start_tls;
	ARRAY(struct dict_ldap_map_settings) parsed_maps;
};

struct dict_ldap_settings *
dict_ldap_settings_read(pool_t pool, const char *path, const char **error_r);

#endif
