#ifndef CONVERT_SETTINGS_H
#define CONVERT_SETTINGS_H

struct mail_user_settings;

struct expire_settings {
	const char *base_dir;
	const char *auth_socket_path;

	ARRAY_DEFINE(plugin_envs, const char *);
};

void expire_settings_read(const struct expire_settings **set_r,
			  const struct mail_user_settings **user_set_r);

#endif
