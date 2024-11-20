#ifndef DOVEADM_SETTINGS_H
#define DOVEADM_SETTINGS_H

#include "net.h"

struct ssl_iostream_settings;

/* <settings checks> */
enum dsync_features {
	DSYNC_FEATURE_EMPTY_HDR_WORKAROUND = 0x1,
	DSYNC_FEATURE_NO_HEADER_HASHES = 0x2,
};

#define DOVEADM_SERVER_FILTER "doveadm_server"
/* </settings checks> */

struct doveadm_settings {
	pool_t pool;
	const char *base_dir;
	const char *libexec_dir;
	ARRAY_TYPE(const_string) mail_plugins;
	const char *mail_plugin_dir;
	const char *mail_temp_dir;
	bool auth_debug;
	const char *auth_socket_path;
	const char *doveadm_socket_path;
	unsigned int doveadm_worker_count;
	in_port_t doveadm_port;
	const char *doveadm_ssl;
	const char *doveadm_username;
	const char *doveadm_password;
	ARRAY_TYPE(const_string) doveadm_allowed_commands;
	const char *dsync_alt_char;
	const char *dsync_remote_cmd;
	const char *doveadm_api_key;
	const char *dsync_features;
	const char *dsync_hashed_headers;
	unsigned int dsync_commit_msgs_interval;
	enum dsync_features parsed_features;
};


extern const struct setting_parser_info doveadm_setting_parser_info;
extern const struct doveadm_settings *doveadm_settings;
extern bool doveadm_verbose_proctitle;

void doveadm_read_settings(void);
/* Returns the global binary config fd. Note that it may be -1 if doveadm was
   called with -O parameter. */
int doveadm_settings_get_config_fd(void);

void doveadm_settings_deinit(void);

#endif
