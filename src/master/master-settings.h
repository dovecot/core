#ifndef MASTER_SETTINGS_H
#define MASTER_SETTINGS_H

#include "service-settings.h"

struct master_settings {
	const char *base_dir;
	const char *libexec_dir;
	const char *import_environment;
	const char *protocols;
	const char *listen;
	const char *ssl;
	const char *default_internal_user;
	const char *default_login_user;
	unsigned int default_process_limit;
	unsigned int default_client_limit;
	unsigned int default_idle_kill;
	uoff_t default_vsz_limit;

	bool version_ignore;

	unsigned int first_valid_uid, last_valid_uid;
	unsigned int first_valid_gid, last_valid_gid;

	ARRAY_TYPE(service_settings) services;
	char **protocols_split;
};

extern const struct setting_parser_info master_setting_parser_info;

bool master_settings_do_fixes(const struct master_settings *set);

#endif
