#ifndef DICT_LDAP_SETTINGS_H
#define DICT_LDAP_SETTINGS_H

struct dict_ldap_map_settings {
	const char *filter;
	const char *username_attribute;
	const char *value_attribute;
	const char *base;
	const char *scope;
	unsigned int timeout;

	/* parsed */
	ARRAY_TYPE(const_string) parsed_pattern_keys;
	int parsed_scope;

	/* the variables are in the same order as parsed_pattern_keys. */
	const char *parsed_pattern;
};

struct dict_ldap_settings {
	ARRAY(struct dict_ldap_map_settings) parsed_maps;
};

struct dict_ldap_settings *
dict_ldap_settings_read(pool_t pool, const char *path, const char **error_r);

#endif
