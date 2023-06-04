#ifndef MASTER_SETTINGS_H
#define MASTER_SETTINGS_H

#include "service-settings.h"

struct master_settings {
	pool_t pool;
	const char *base_dir;
	const char *state_dir;
	const char *libexec_dir;
	const char *instance_name;
	const char *protocols;
	const char *listen;
	const char *ssl;
	const char *default_internal_user;
	const char *default_internal_group;
	const char *default_login_user;

	bool version_ignore;

	unsigned int first_valid_uid, last_valid_uid;
	unsigned int first_valid_gid, last_valid_gid;

	ARRAY_TYPE(const_string) services;

	ARRAY_TYPE(service_settings) parsed_services;
	char **protocols_split;
};

extern const struct setting_parser_info master_setting_parser_info;

void master_settings_do_fixes(const struct master_settings *set);

#endif
