#ifndef CONVERT_SETTINGS_H
#define CONVERT_SETTINGS_H

struct mail_user_settings;

struct convert_settings {
	const char *auth_socket_path;

	ARRAY_DEFINE(plugin_envs, const char *);
};

void convert_settings_read(const struct convert_settings **set_r,
			   const struct mail_user_settings **user_set_r);

#endif
