#ifndef DOVEADM_SETTINGS_H
#define DOVEADM_SETTINGS_H

#include "net.h"

/* <settings checks> */
enum dsync_features {
	DSYNC_FEATURE_EMPTY_HDR_WORKAROUND = 0x1,
};
/* </settings checks> */

struct doveadm_settings {
	const char *base_dir;
	const char *libexec_dir;
	const char *mail_plugins;
	const char *mail_plugin_dir;
	const char *mail_temp_dir;
	bool auth_debug;
	const char *auth_socket_path;
	const char *doveadm_socket_path;
	unsigned int doveadm_worker_count;
	in_port_t doveadm_port;
	const char *doveadm_username;
	const char *doveadm_password;
	const char *doveadm_allowed_commands;
	const char *dsync_alt_char;
	const char *dsync_remote_cmd;
	const char *director_username_hash;
	const char *doveadm_api_key;
	const char *dsync_features;
	const char *dsync_hashed_headers;
	unsigned int dsync_commit_msgs_interval;
	const char *doveadm_http_rawlog_dir;
	enum dsync_features parsed_features;
	ARRAY(const char *) plugin_envs;
};

extern const struct setting_parser_info doveadm_setting_parser_info;
extern struct doveadm_settings *doveadm_settings;
extern const struct master_service_settings *service_set;
extern const struct master_service_ssl_settings *doveadm_ssl_set;
struct ssl_iostream_settings;

void doveadm_get_ssl_settings(struct ssl_iostream_settings *set_r, pool_t pool);
void doveadm_settings_expand(struct doveadm_settings *set, pool_t pool);

#endif
