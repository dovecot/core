#ifndef DICT_LDAP_SETTINGS_H
#define DICT_LDAP_SETTINGS_H

struct dict_ldap_map_settings {
	pool_t pool;

	const char *pattern;
	const char *base;
	const char *scope;

	/* parsed */

	ARRAY_TYPE(const_string) parsed_attributes;

	/* attributes sorted by the position in parsed_pattern. */
	ARRAY_TYPE(const_string) parsed_pattern_keys;
	int parsed_scope;

	/* the variables are in the same order as parsed_pattern_keys. */
	const char *parsed_pattern;
};

struct dict_ldap_map_pre_settings {
	pool_t pool;
	const char *filter;
};

struct dict_ldap_map_post_settings {
	pool_t pool;
	const char *value;

	/* parsed */

	/* This is preliminary support for supporting multiple values.
	   For now the array contains only the single value coming
	   from 'value' above. */
	ARRAY_TYPE(const_string) values;
};

struct dict_ldap_settings {
	pool_t pool;
	ARRAY_TYPE(const_string) maps;

	/* parsed */
	ARRAY(const struct dict_ldap_map_settings) parsed_maps;
};

extern const struct setting_parser_info dict_ldap_map_setting_parser_info;
extern const struct setting_parser_info dict_ldap_map_pre_setting_parser_info;
extern const struct setting_parser_info dict_ldap_map_post_setting_parser_info;
extern const struct setting_parser_info dict_ldap_setting_parser_info;

int dict_ldap_settings_get(struct event *event,
			   const struct dict_ldap_settings **set_r,
			   const char **error_r);

#endif
