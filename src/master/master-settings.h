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
	const char *ssl_ca_file;
	const char *ssl_cert_file;
	const char *ssl_key_file;
	const char *ssl_parameters_file;
	unsigned int ssl_parameters_regenerate;
	const char *ssl_cipher_list;
	int ssl_verify_client_cert;
	int disable_plaintext_auth;
	int verbose_ssl;

	/* login */
	const char *login_dir;
	const char *login_executable;
	const char *login_user;
	const char *login_greeting;

	int login_process_per_connection;
	int login_chroot;
	int login_greeting_capability;

	unsigned int login_process_size;
	unsigned int login_processes_count;
	unsigned int login_max_processes_count;
	unsigned int login_max_logging_users;

	/* mail */
	const char *valid_chroot_dirs;
	const char *mail_chroot;
	unsigned int max_mail_processes;
	int verbose_proctitle;

	unsigned int first_valid_uid, last_valid_uid;
	unsigned int first_valid_gid, last_valid_gid;
	const char *mail_extra_groups;

	const char *default_mail_env;
	const char *mail_cache_fields;
	const char *mail_never_cache_fields;
	unsigned int mailbox_idle_check_interval;
	int mail_full_filesystem_access;
	int mail_max_keyword_length;
	int mail_save_crlf;
	int mail_read_mmaped;
	int mmap_disable;
	int mmap_no_write;
	const char *lock_method;
	int maildir_stat_dirs;
	int maildir_copy_with_hardlinks;
	int maildir_check_content_changes;
	const char *mbox_read_locks;
	const char *mbox_write_locks;
	unsigned int mbox_lock_timeout;
	unsigned int mbox_dotlock_change_timeout;
	int mbox_dirty_syncs;
	int mbox_very_dirty_syncs;
	int mbox_lazy_writes;
	unsigned int umask;
	int mail_drop_priv_before_exec;

	const char *mail_executable;
	unsigned int mail_process_size;
	int mail_use_modules;
	const char *mail_modules;
	const char *mail_log_prefix;

	/* imap */
	unsigned int imap_max_line_length;
	const char *imap_capability;
	const char *imap_client_workarounds;

	/* pop3 */
	int pop3_no_flag_updates;
	int pop3_enable_last;
	const char *pop3_client_workarounds;

	/* .. */
	uid_t login_uid;

	int listen_fd, ssl_listen_fd;
};

struct socket_settings {
	const char *path;
	unsigned int mode;
	const char *user;
	const char *group;
};

struct auth_socket_settings {
	struct auth_settings *parent;
	struct auth_socket_settings *next;

	const char *type;
	struct socket_settings master;
        struct socket_settings client;
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
	unsigned int cache_size;
	unsigned int cache_ttl;
	const char *executable;
	const char *user;
	const char *chroot;
	const char *username_chars;
	const char *username_translation;
	const char *anonymous_username;

	int verbose, debug;
	int ssl_require_client_cert;

	unsigned int count;
	unsigned int process_size;

	/* .. */
	uid_t uid;
	gid_t gid;
	struct auth_socket_settings *sockets;
};

struct namespace_settings {
	struct server_settings *parent;
	struct namespace_settings *next;

	const char *type;
	const char *separator;
	const char *prefix;
	const char *location;

	int inbox;
	int hidden;
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

int master_settings_read(const char *path, int nochecks);

void master_settings_init(void);
void master_settings_deinit(void);

#endif
