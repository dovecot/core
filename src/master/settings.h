#ifndef __SETTINGS_H
#define __SETTINGS_H

/* common */
extern char *set_log_path;
extern char *set_log_timestamp;

/* general */
extern unsigned int set_imap_port;
extern unsigned int set_imaps_port;
extern char *set_imap_listen;
extern char *set_imaps_listen;

extern char *set_ssl_cert_file;
extern char *set_ssl_key_file;
extern char *set_ssl_parameters_file;
extern unsigned int set_ssl_parameters_regenerate;
extern int set_disable_plaintext_auth;

/* login */
extern char *set_login_executable;
extern char *set_login_user;
extern char *set_login_dir;
extern int set_login_chroot;
extern int set_login_process_per_connection;
extern unsigned int set_login_processes_count;
extern unsigned int set_login_max_processes_count;
extern unsigned int set_max_logging_users;

extern uid_t set_login_uid;
extern gid_t set_login_gid;

/* imap */
extern char *set_imap_executable;
extern char *set_valid_chroot_dirs;
extern unsigned int set_max_imap_processes;
extern int set_verbose_proctitle;

extern unsigned int set_first_valid_uid, set_last_valid_uid;
extern unsigned int set_first_valid_gid, set_last_valid_gid;

extern char *set_mail_cache_fields;
extern char *set_mail_never_cache_fields;
extern unsigned int set_mailbox_check_interval;
extern int set_mail_save_crlf;
extern int set_maildir_copy_with_hardlinks;
extern int set_maildir_check_content_changes;
extern int set_overwrite_incompatible_index;
extern unsigned int set_umask;

/* auth */
typedef struct _AuthConfig AuthConfig;

struct _AuthConfig {
	AuthConfig *next;

	char *name;
	char *methods;
	char *realms;
	char *userinfo, *userinfo_args;
	char *executable;
	char *user;
	char *chroot;

	int count;
};

extern AuthConfig *auth_processes_config;

void settings_read(const char *path);

void settings_init(void);

#endif
