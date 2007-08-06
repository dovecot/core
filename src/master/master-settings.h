#ifndef __MASTER_SETTINGS_H
#define __MASTER_SETTINGS_H

#include "network.h"

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

struct settings {
	struct server_settings *server;
	enum mail_protocol protocol;

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

	bool ssl_disable;
	const char *ssl_ca_file;
	const char *ssl_cert_file;
	const char *ssl_key_file;
	const char *ssl_key_password;
	unsigned int ssl_parameters_regenerate;
	const char *ssl_cipher_list;
	bool ssl_verify_client_cert;
	bool disable_plaintext_auth;
	bool verbose_ssl;
	bool shutdown_clients;
	bool nfs_check;
	bool version_ignore;

	/* login */
	const char *login_dir;
	const char *login_executable;
	const char *login_user;
	const char *login_greeting;
	const char *login_log_format_elements;
	const char *login_log_format;

	bool login_process_per_connection;
	bool login_chroot;
	bool login_greeting_capability;

	unsigned int login_process_size;
	unsigned int login_processes_count;
	unsigned int login_max_processes_count;
	unsigned int login_max_connections;

	/* mail */
	const char *valid_chroot_dirs;
	const char *mail_chroot;
	unsigned int max_mail_processes;
	unsigned int mail_max_userip_connections;
	bool verbose_proctitle;

	unsigned int first_valid_uid, last_valid_uid;
	unsigned int first_valid_gid, last_valid_gid;
	const char *mail_extra_groups;
	const char *mail_uid;
	const char *mail_gid;

	const char *default_mail_env;
	const char *mail_location;
	const char *mail_cache_fields;
	const char *mail_never_cache_fields;
	unsigned int mail_cache_min_mail_count;
	unsigned int mailbox_idle_check_interval;
	bool mail_debug;
	bool mail_full_filesystem_access;
	unsigned int mail_max_keyword_length;
	bool mail_save_crlf;
	bool mmap_disable;
	bool dotlock_use_excl;
	bool fsync_disable;
	bool mail_nfs_storage;
	bool mail_nfs_index;
	bool mailbox_list_index_disable;
	const char *lock_method;
	bool maildir_stat_dirs;
	bool maildir_copy_with_hardlinks;
	bool maildir_copy_preserve_filename;
	const char *mbox_read_locks;
	const char *mbox_write_locks;
	unsigned int mbox_lock_timeout;
	unsigned int mbox_dotlock_change_timeout;
	unsigned int mbox_min_index_size;
	bool mbox_dirty_syncs;
	bool mbox_very_dirty_syncs;
	bool mbox_lazy_writes;
	unsigned int dbox_rotate_size;
	unsigned int dbox_rotate_min_size;
	unsigned int dbox_rotate_days;
	unsigned int umask;
	bool mail_drop_priv_before_exec;

	const char *mail_executable;
	unsigned int mail_process_size;
	const char *mail_plugins;
	const char *mail_plugin_dir;
	const char *mail_log_prefix;
	unsigned int mail_log_max_lines_per_sec;

	/* imap */
	unsigned int imap_max_line_length;
	const char *imap_capability;
	const char *imap_client_workarounds;
	const char *imap_logout_format;

	/* pop3 */
	bool pop3_no_flag_updates;
	bool pop3_enable_last;
	bool pop3_reuse_xuidl;
	bool pop3_lock_session;
	const char *pop3_uidl_format;
	const char *pop3_client_workarounds;
	const char *pop3_logout_format;

	/* .. */
	ARRAY_TYPE(listener) listens;
	ARRAY_TYPE(listener) ssl_listens;

	uid_t login_uid, mail_uid_t;
	gid_t mail_gid_t;

	const char *imap_generated_capability;

	ARRAY_DEFINE(plugin_envs, const char *);
};

struct socket_settings {
	const char *path;
	unsigned int mode;
	const char *user;
	const char *group;

	unsigned int used:1;
};

struct auth_socket_settings {
	struct auth_settings *parent;
	struct auth_socket_settings *next;

	const char *type;
	struct socket_settings master;
        struct socket_settings client;
};

struct auth_passdb_settings {
	struct auth_settings *parent;
	struct auth_passdb_settings *next;

	const char *driver;
	const char *args;
	bool deny;
	bool pass;
	bool master;
};

struct auth_userdb_settings {
	struct auth_settings *parent;
	struct auth_userdb_settings *next;

	const char *driver;
	const char *args;
};

struct auth_settings {
	struct server_settings *parent;
	struct auth_settings *next;

	const char *name;
	const char *mechanisms;
	const char *realms;
	const char *default_realm;
	unsigned int cache_size;
	unsigned int cache_ttl;
	unsigned int cache_negative_ttl;
	const char *executable;
	const char *user;
	const char *chroot;
	const char *username_chars;
	const char *username_translation;
	const char *username_format;
	const char *master_user_separator;
	const char *anonymous_username;
	const char *krb5_keytab;
	const char *gssapi_hostname;

	bool verbose, debug, debug_passwords;
	bool ssl_require_client_cert;
	bool ssl_username_from_cert;

	unsigned int count;
	unsigned int worker_max_count;
	unsigned int process_size;

	/* .. */
	uid_t uid;
	gid_t gid;
        struct auth_passdb_settings *passdbs;
        struct auth_userdb_settings *userdbs;
	struct auth_socket_settings *sockets;
};

struct namespace_settings {
	struct server_settings *parent;
	struct namespace_settings *next;

	const char *type;
	const char *separator;
	const char *prefix;
	const char *location;

	bool inbox;
	bool hidden;
	bool list;
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

	ARRAY_DEFINE(dicts, const char *);

	gid_t login_gid;
};

extern struct server_settings *settings_root;

bool master_settings_read(const char *path, bool nochecks, bool nofixes);

void master_settings_dump(struct server_settings *set, bool nondefaults);

void master_settings_init(void);
void master_settings_deinit(void);

#endif
