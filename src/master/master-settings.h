#ifndef __MASTER_SETTINGS_H
#define __MASTER_SETTINGS_H

enum mail_protocol {
        MAIL_PROTOCOL_ANY,
        MAIL_PROTOCOL_IMAP,
        MAIL_PROTOCOL_POP3
};

struct settings {
	struct server_settings *server;
	enum mail_protocol protocol;

	/* common */
	const char *base_dir;
	const char *log_path;
	const char *info_log_path;
	const char *log_timestamp;

	/* general */
	const char *protocols;
	const char *listen;
	const char *ssl_listen;

	int ssl_disable;
	const char *ssl_cert_file;
	const char *ssl_key_file;
	const char *ssl_parameters_file;
	unsigned int ssl_parameters_regenerate;
	int disable_plaintext_auth;
	int verbose_ssl;

	/* login */
	const char *login_dir;
	const char *login_executable;
	const char *login_user;

	int login_process_per_connection;
	int login_chroot;

	unsigned int login_process_size;
	unsigned int login_processes_count;
	unsigned int login_max_processes_count;
	unsigned int login_max_logging_users;

	/* mail */
	const char *valid_chroot_dirs;
	unsigned int max_mail_processes;
	int verbose_proctitle;

	unsigned int first_valid_uid, last_valid_uid;
	unsigned int first_valid_gid, last_valid_gid;

	const char *default_mail_env;
	const char *mail_cache_fields;
	const char *mail_never_cache_fields;
	const char *client_workarounds;
	unsigned int mailbox_check_interval;
	unsigned int mailbox_idle_check_interval;
	int mail_full_filesystem_access;
	int mail_max_flag_length;
	int mail_save_crlf;
	int mail_read_mmaped;
	int maildir_copy_with_hardlinks;
	int maildir_check_content_changes;
	const char *mbox_locks;
	int mbox_read_dotlock;
	unsigned int mbox_lock_timeout;
	unsigned int mbox_dotlock_change_timeout;
	unsigned int umask;
	int mail_drop_priv_before_exec;
	int index_mmap_invalidate;

	const char *mail_executable;
	unsigned int mail_process_size;
	int mail_use_modules;
	const char *mail_modules;

	/* imap */
	unsigned int imap_max_line_length;

	/* .. */
	uid_t login_uid;

	int listen_fd, ssl_listen_fd;
};

struct auth_settings {
	struct server_settings *parent;
	struct auth_settings *next;

	const char *name;
	const char *mechanisms;
	const char *realms;
	const char *default_realm;
	const char *userdb;
	const char *passdb;
	const char *executable;
	const char *user;
	const char *chroot;
	const char *username_chars;
	const char *anonymous_username;

	int use_cyrus_sasl, verbose;

	unsigned int count;
	unsigned int process_size;

	/* .. */
	uid_t uid;
	gid_t gid;
};

struct namespace_settings {
	struct server_settings *parent;
	struct namespace_settings *next;

	const char *type;
	const char *separator;
	const char *prefix;
	const char *location;
};

struct server_settings {
	struct server_settings *next;

	const char *name;
	struct settings *defaults;
	struct settings *imap;
	struct settings *pop3;
	struct auth_settings *auths;
	struct auth_settings auth_defaults;
        struct namespace_settings *namespaces;

	gid_t login_gid;
};

extern struct server_settings *settings_root;

int master_settings_read(const char *path);

void master_settings_init(void);
void master_settings_deinit(void);

#endif
