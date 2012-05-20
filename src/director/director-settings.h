#ifndef DIRECTOR_SETTINGS_H
#define DIRECTOR_SETTINGS_H

struct director_settings {
	const char *master_user_separator;

	const char *director_servers;
	const char *director_mail_servers;
	const char *director_username_hash;
	unsigned int director_user_expire;
	unsigned int director_doveadm_port;
};

extern const struct setting_parser_info director_setting_parser_info;

#endif
