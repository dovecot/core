#ifndef __MASTER_SETTINGS_H
#define __MASTER_SETTINGS_H

struct settings {
	/* common */
	const char *base_dir;
	const char *log_path;
	const char *info_log_path;
	const char *log_timestamp;

	/* general */
	const char *protocols;
	const char *imap_listen;
	const char *imaps_listen;
	const char *pop3_listen;
	const char *pop3s_listen;

	int ssl_disable;
	const char *ssl_cert_file;
	const char *ssl_key_file;
	const char *ssl_parameters_file;
	unsigned int ssl_parameters_regenerate;
	int disable_plaintext_auth;

	/* login */
	const char *login_dir;
	int login_chroot;

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
	int mail_save_crlf;
	int mail_read_mmaped;
	int maildir_copy_with_hardlinks;
	int maildir_check_content_changes;
	char *mbox_locks;
	int mbox_read_dotlock;
	unsigned int mbox_lock_timeout;
	unsigned int mbox_dotlock_change_timeout;
	int overwrite_incompatible_index;
	unsigned int umask;

	/* imap */
	const char *imap_executable;
	unsigned int imap_process_size;

	/* pop3 */
	const char *pop3_executable;
	unsigned int pop3_process_size;

	/* .. */
	gid_t login_gid;

	struct auth_settings *auths;
	struct login_settings *logins;
};

struct login_settings {
	struct login_settings *next;

	const char *name;
	const char *executable;
	const char *user;

	int process_per_connection;

	unsigned int process_size;
	unsigned int processes_count;
	unsigned int max_processes_count;
	unsigned int max_logging_users;

	uid_t uid; /* gid must be always same with all login processes */
};

struct auth_settings {
	struct auth_settings *next;

	const char *name;
	const char *mechanisms;
	const char *realms;
	const char *userdb;
	const char *passdb;
	const char *executable;
	const char *user;
	const char *chroot;

	int use_cyrus_sasl, verbose;

	unsigned int count;
	unsigned int process_size;
};

extern struct settings *set;

void master_settings_read(const char *path);

void master_settings_init(void);
void master_settings_deinit(void);

#endif
