#ifndef MASTER_SETTINGS_H
#define MASTER_SETTINGS_H

#include "network.h"

#define DOVECOT_CONFIG_BIN_PATH BINDIR"/doveconf"

enum mail_protocol {
        MAIL_PROTOCOL_ANY,
        MAIL_PROTOCOL_IMAP,
	MAIL_PROTOCOL_POP3,
	MAIL_PROTOCOL_LDA
};

struct listener {
	struct ip_addr ip;
	unsigned int port;
	int fd;
	bool wanted;
};
ARRAY_DEFINE_TYPE(listener, struct listener);

struct master_auth_socket_unix_settings {
	const char *path;
};

struct master_auth_socket_settings {
	const char *type;

	ARRAY_DEFINE(masters, struct master_auth_socket_unix_settings *);
};

struct master_auth_settings {
	const char *name;
	const char *executable;
	const char *user;
	const char *chroot;

	unsigned int count;
	unsigned int process_size;

	const char *mechanisms;
	bool debug;

	ARRAY_DEFINE(sockets, struct master_auth_socket_settings *);

	/* .. */
	uid_t uid;
	gid_t gid;
};

struct master_settings {
	/* common */
	const char *base_dir;
	const char *log_path;
	const char *info_log_path;
	const char *log_timestamp;
	const char *syslog_facility;

	/* general */
	const char *protocols;
	const char *listen;
	const char *ssl_listen;

	const char *ssl;
	const char *ssl_key_file;
	unsigned int ssl_parameters_regenerate;
	bool nfs_check;
	bool version_ignore;

	/* login */
	const char *login_dir;
	const char *login_executable;
	const char *login_user;

	bool login_process_per_connection;
	bool login_chroot;
	bool disable_plaintext_auth;

	unsigned int login_process_size;
	unsigned int login_processes_count;
	unsigned int login_max_processes_count;

	/* mail */
	const char *valid_chroot_dirs;
	const char *mail_chroot;
	unsigned int max_mail_processes;
	unsigned int mail_max_userip_connections;
	bool verbose_proctitle;

	unsigned int first_valid_uid, last_valid_uid;
	unsigned int first_valid_gid, last_valid_gid;
	const char *mail_access_groups;
	const char *mail_privileged_group;
	const char *mail_uid;
	const char *mail_gid;

	const char *mail_plugins;
	const char *imap_capability;

	const char *mail_location;
	bool mail_debug;
	bool mail_nfs_index;
	unsigned int umask;
	bool mail_drop_priv_before_exec;

	const char *mail_executable;
	unsigned int mail_process_size;
	const char *mail_log_prefix;
	unsigned int mail_log_max_lines_per_sec;

	/* dict */
	const char *dict_db_config;
	unsigned int dict_process_count;

	ARRAY_DEFINE(auths, struct master_auth_settings *);

	ARRAY_DEFINE(dicts, const char *);
	ARRAY_DEFINE(plugin_envs, const char *);

#ifndef CONFIG_BINARY
	/* .. */
	struct master_server_settings *server;
	enum mail_protocol protocol;

	ARRAY_TYPE(listener) listens;
	ARRAY_TYPE(listener) ssl_listens;

	uid_t login_uid, mail_uid_t;
	gid_t mail_gid_t, mail_priv_gid_t;

	const char *imap_generated_capability;
	ARRAY_TYPE(const_string) all_settings;
#endif
};

struct master_server_settings {
	struct master_settings *defaults;
	struct master_settings *imap;
	struct master_settings *pop3;

	gid_t login_gid;
};

extern struct master_server_settings *master_set;
extern struct setting_parser_info master_setting_parser_info;

int master_settings_read(const char *path,
			 struct master_server_settings **set_r);
bool master_settings_check(struct master_server_settings *set,
			   bool nochecks, bool nofixes);
void master_settings_export_to_env(const struct master_settings *set);

void master_settings_init(void);
void master_settings_deinit(void);

#endif
