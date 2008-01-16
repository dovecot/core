/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "array.h"
#include "str.h"
#include "istream.h"
#include "fd-close-on-exec.h"
#include "safe-mkdir.h"
#include "mkdir-parents.h"
#include "unlink-directory.h"
#include "syslog-util.h"
#include "mail-process.h"
#include "master-login-interface.h"
#include "settings.h"

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <pwd.h>
#include <grp.h>
#ifdef HAVE_SYS_RESOURCE_H
#  include <sys/resource.h>
#endif

enum settings_type {
	SETTINGS_TYPE_ROOT,
	SETTINGS_TYPE_SERVER,
	SETTINGS_TYPE_AUTH,
	SETTINGS_TYPE_AUTH_SOCKET,
	SETTINGS_TYPE_AUTH_PASSDB,
	SETTINGS_TYPE_AUTH_USERDB,
        SETTINGS_TYPE_NAMESPACE,
	SETTINGS_TYPE_SOCKET,
	SETTINGS_TYPE_DICT,
	SETTINGS_TYPE_PLUGIN
};

struct settings_parse_ctx {
	enum settings_type type, parent_type;
	enum mail_protocol protocol;

	struct server_settings *root, *server;
	struct auth_settings *auth;
	struct socket_settings *socket;
	struct auth_socket_settings *auth_socket;
	struct auth_passdb_settings *auth_passdb;
	struct auth_userdb_settings *auth_userdb;
        struct namespace_settings *namespace;

	int level;
};

#include "master-settings-defs.c"

#undef DEF_STR
#undef DEF_INT
#undef DEF_BOOL
#define DEF_STR(name) DEF_STRUCT_STR(name, auth_settings)
#define DEF_INT(name) DEF_STRUCT_INT(name, auth_settings)
#define DEF_BOOL(name) DEF_STRUCT_BOOL(name, auth_settings)

static struct setting_def auth_setting_defs[] = {
	DEF_STR(mechanisms),
	DEF_STR(realms),
	DEF_STR(default_realm),
	DEF_INT(cache_size),
	DEF_INT(cache_ttl),
	DEF_INT(cache_negative_ttl),
	DEF_STR(executable),
	DEF_STR(user),
	DEF_STR(chroot),
	DEF_STR(username_chars),
	DEF_STR(username_translation),
	DEF_STR(username_format),
	DEF_STR(master_user_separator),
	DEF_STR(anonymous_username),
	DEF_STR(krb5_keytab),
	DEF_STR(gssapi_hostname),
	DEF_STR(winbind_helper_path),
	DEF_INT(failure_delay),

	DEF_BOOL(verbose),
	DEF_BOOL(debug),
	DEF_BOOL(debug_passwords),
	DEF_BOOL(ssl_require_client_cert),
	DEF_BOOL(ssl_username_from_cert),
	DEF_BOOL(ntlm_use_winbind),

	DEF_INT(count),
	DEF_INT(worker_max_count),
	DEF_INT(worker_max_request_count),
	DEF_INT(process_size),

	{ 0, NULL, 0 }
};

#undef DEF_STR
#undef DEF_INT
#undef DEF_BOOL
#define DEF_STR(name) DEF_STRUCT_STR(name, socket_settings)
#define DEF_INT(name) DEF_STRUCT_INT(name, socket_settings)
#define DEF_BOOL(name) DEF_STRUCT_BOOL(name, socket_settings)

static struct setting_def socket_setting_defs[] = {
	DEF_STR(path),
	DEF_INT(mode),
	DEF_STR(user),
	DEF_STR(group),

	{ 0, NULL, 0 }
};

static struct setting_def auth_socket_setting_defs[] = {
	DEF_STRUCT_STR(type, auth_socket_settings),

	{ 0, NULL, 0 }
};

#undef DEF_STR
#undef DEF_INT
#undef DEF_BOOL
#define DEF_STR(name) DEF_STRUCT_STR(name, auth_passdb_settings)
#define DEF_INT(name) DEF_STRUCT_INT(name, auth_passdb_settings)
#define DEF_BOOL(name) DEF_STRUCT_BOOL(name, auth_passdb_settings)

static struct setting_def auth_passdb_setting_defs[] = {
	DEF_STR(driver),
	DEF_STR(args),
	DEF_BOOL(deny),
	DEF_BOOL(pass),
	DEF_BOOL(master),

	{ 0, NULL, 0 }
};

static struct setting_def auth_userdb_setting_defs[] = {
	DEF_STRUCT_STR(driver, auth_userdb_settings),
	DEF_STRUCT_STR(args, auth_userdb_settings),

	{ 0, NULL, 0 }
};

#undef DEF_STR
#undef DEF_INT
#undef DEF_BOOL
#define DEF_STR(name) DEF_STRUCT_STR(name, namespace_settings)
#define DEF_INT(name) DEF_STRUCT_INT(name, namespace_settings)
#define DEF_BOOL(name) DEF_STRUCT_BOOL(name, namespace_settings)

static struct setting_def namespace_setting_defs[] = {
	DEF_STR(type),
	DEF_STR(separator),
	DEF_STR(prefix),
	DEF_STR(location),
	DEF_BOOL(inbox),
	DEF_BOOL(hidden),
	DEF_BOOL(list),
	DEF_BOOL(subscriptions),

	{ 0, NULL, 0 }
};

struct settings default_settings = {
	MEMBER(server) NULL,
	MEMBER(protocol) 0,

	/* common */
	MEMBER(base_dir) PKG_RUNDIR,
	MEMBER(log_path) "",
	MEMBER(info_log_path) "",
	MEMBER(log_timestamp) DEFAULT_FAILURE_STAMP_FORMAT,
	MEMBER(syslog_facility) "mail",

	/* general */
	MEMBER(protocols) "imap imaps",
	MEMBER(listen) "*",
	MEMBER(ssl_listen) "",

	MEMBER(ssl_disable) FALSE,
	MEMBER(ssl_ca_file) "",
	MEMBER(ssl_cert_file) SSLDIR"/certs/dovecot.pem",
	MEMBER(ssl_key_file) SSLDIR"/private/dovecot.pem",
	MEMBER(ssl_key_password) "",
	MEMBER(ssl_parameters_regenerate) 168,
	MEMBER(ssl_cipher_list) "",
	MEMBER(ssl_cert_username_field) "commonName",
	MEMBER(ssl_verify_client_cert) FALSE,
	MEMBER(disable_plaintext_auth) TRUE,
	MEMBER(verbose_ssl) FALSE,
	MEMBER(shutdown_clients) TRUE,
	MEMBER(nfs_check) TRUE,
	MEMBER(version_ignore) FALSE,

	/* login */
	MEMBER(login_dir) "login",
	MEMBER(login_executable) NULL,
	MEMBER(login_user) "dovecot",
	MEMBER(login_greeting) "Dovecot ready.",
	MEMBER(login_log_format_elements) "user=<%u> method=%m rip=%r lip=%l %c",
	MEMBER(login_log_format) "%$: %s",

	MEMBER(login_process_per_connection) TRUE,
	MEMBER(login_chroot) TRUE,
	MEMBER(login_greeting_capability) FALSE,

	MEMBER(login_process_size) 64,
	MEMBER(login_processes_count) 3,
	MEMBER(login_max_processes_count) 128,
	MEMBER(login_max_connections) 256,

	/* mail */
	MEMBER(valid_chroot_dirs) "",
	MEMBER(mail_chroot) "",
	MEMBER(max_mail_processes) 512,
	MEMBER(mail_max_userip_connections) 10,
	MEMBER(verbose_proctitle) FALSE,

	MEMBER(first_valid_uid) 500,
	MEMBER(last_valid_uid) 0,
	MEMBER(first_valid_gid) 1,
	MEMBER(last_valid_gid) 0,
	MEMBER(mail_extra_groups) "",
	MEMBER(mail_uid) "",
	MEMBER(mail_gid) "",

	MEMBER(mail_location) "",
	MEMBER(mail_cache_fields) "",
	MEMBER(mail_never_cache_fields) "imap.envelope",
	MEMBER(mail_cache_min_mail_count) 0,
	MEMBER(mailbox_idle_check_interval) 30,
	MEMBER(mail_debug) FALSE,
	MEMBER(mail_full_filesystem_access) FALSE,
	MEMBER(mail_max_keyword_length) 50,
	MEMBER(mail_save_crlf) FALSE,
#ifdef MMAP_CONFLICTS_WRITE
	MEMBER(mmap_disable) TRUE,
#else
	MEMBER(mmap_disable) FALSE,
#endif
	MEMBER(dotlock_use_excl) TRUE,
	MEMBER(fsync_disable) FALSE,
	MEMBER(mail_nfs_storage) FALSE,
	MEMBER(mail_nfs_index) FALSE,
	MEMBER(mailbox_list_index_disable) TRUE,
	MEMBER(lock_method) "fcntl",
	MEMBER(maildir_stat_dirs) FALSE,
	MEMBER(maildir_copy_with_hardlinks) TRUE,
	MEMBER(maildir_copy_preserve_filename) FALSE,
	MEMBER(mbox_read_locks) "fcntl",
	MEMBER(mbox_write_locks) "dotlock fcntl",
	MEMBER(mbox_lock_timeout) 300,
	MEMBER(mbox_dotlock_change_timeout) 120,
	MEMBER(mbox_min_index_size) 0,
	MEMBER(mbox_dirty_syncs) TRUE,
	MEMBER(mbox_very_dirty_syncs) FALSE,
	MEMBER(mbox_lazy_writes) TRUE,
	MEMBER(dbox_rotate_size) 2048,
	MEMBER(dbox_rotate_min_size) 16,
	MEMBER(dbox_rotate_days) 1,
	MEMBER(umask) 0077,
	MEMBER(mail_drop_priv_before_exec) FALSE,

	MEMBER(mail_executable) PKG_LIBEXECDIR"/imap",
	MEMBER(mail_process_size) 256,
	MEMBER(mail_plugins) "",
	MEMBER(mail_plugin_dir) MODULEDIR"/imap",
	MEMBER(mail_log_prefix) "%Us(%u): ",
	MEMBER(mail_log_max_lines_per_sec) 10,

	/* imap */
	MEMBER(imap_max_line_length) 65536,
	MEMBER(imap_capability) "",
	MEMBER(imap_client_workarounds) "",
	MEMBER(imap_logout_format) "bytes=%i/%o",

	/* pop3 */
	MEMBER(pop3_no_flag_updates) FALSE,
	MEMBER(pop3_enable_last) FALSE,
	MEMBER(pop3_reuse_xuidl) FALSE,
	MEMBER(pop3_lock_session) FALSE,
	MEMBER(pop3_uidl_format) "%08Xu%08Xv",
	MEMBER(pop3_client_workarounds) "",
	MEMBER(pop3_logout_format) "top=%t/%p, retr=%r/%b, del=%d/%m, size=%s",

	/* .. */
};

struct auth_settings default_auth_settings = {
	MEMBER(parent) NULL,
	MEMBER(next) NULL,

	MEMBER(name) NULL,
	MEMBER(mechanisms) "plain",
	MEMBER(realms) "",
	MEMBER(default_realm) "",
	MEMBER(cache_size) 0,
	MEMBER(cache_ttl) 3600,
	MEMBER(cache_negative_ttl) 3600,
	MEMBER(executable) PKG_LIBEXECDIR"/dovecot-auth",
	MEMBER(user) "root",
	MEMBER(chroot) "",
	MEMBER(username_chars) "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890.-_@",
	MEMBER(username_translation) "",
	MEMBER(username_format) "",
	MEMBER(master_user_separator) "",
	MEMBER(anonymous_username) "anonymous",
	MEMBER(krb5_keytab) "",
	MEMBER(gssapi_hostname) "",
	MEMBER(winbind_helper_path) "/usr/bin/ntlm_auth",
	MEMBER(failure_delay) 2,

	MEMBER(verbose) FALSE,
	MEMBER(debug) FALSE,
	MEMBER(debug_passwords) FALSE,
	MEMBER(ssl_require_client_cert) FALSE,
	MEMBER(ssl_username_from_cert) FALSE,
	MEMBER(ntlm_use_winbind) FALSE,

	MEMBER(count) 1,
	MEMBER(worker_max_count) 30,
	MEMBER(worker_max_request_count) 0,
	MEMBER(process_size) 256,

	/* .. */
	MEMBER(uid) 0,
	MEMBER(gid) 0,
	MEMBER(passdbs) NULL,
	MEMBER(userdbs) NULL,
	MEMBER(sockets) NULL
};

struct socket_settings default_socket_settings = {
#define DEFAULT_MASTER_SOCKET_PATH "auth-master"
#define DEFAULT_CLIENT_SOCKET_PATH "auth-client"
	MEMBER(path) "",
	MEMBER(mode) 0600,
	MEMBER(user) "",
	MEMBER(group) ""
};

struct namespace_settings default_namespace_settings = {
	MEMBER(parent) NULL,
	MEMBER(next) NULL,
	MEMBER(type) NULL,

	MEMBER(separator) "",
	MEMBER(prefix) "",
	MEMBER(location) "",

	MEMBER(inbox) FALSE,
	MEMBER(hidden) FALSE,
	MEMBER(list) TRUE,
	MEMBER(subscriptions) TRUE
};

static pool_t settings_pool, settings2_pool;
struct server_settings *settings_root = NULL;

static void fix_base_path(struct settings *set, const char **str)
{
	if (*str != NULL && **str != '\0' && **str != '/') {
		*str = p_strconcat(settings_pool,
				   set->base_dir, "/", *str, NULL);
	}
}

static bool parse_uid(const char *str, uid_t *uid_r)
{
	struct passwd *pw;
	char *p;

	if (*str >= '0' && *str <= '9') {
		*uid_r = (uid_t)strtoul(str, &p, 10);
		if (*p == '\0')
			return TRUE;
	}

	pw = getpwnam(str);
	if (pw == NULL)
		return FALSE;

	*uid_r = pw->pw_uid;
	return TRUE;
}

static bool parse_gid(const char *str, gid_t *gid_r)
{
	struct group *gr;
	char *p;

	if (*str >= '0' && *str <= '9') {
		*gid_r = (gid_t)strtoul(str, &p, 10);
		if (*p == '\0')
			return TRUE;
	}

	gr = getgrnam(str);
	if (gr == NULL)
		return FALSE;

	*gid_r = gr->gr_gid;
	return TRUE;
}

static bool get_login_uid(struct settings *set)
{
	struct passwd *pw;

	if ((pw = getpwnam(set->login_user)) == NULL) {
		i_error("Login user doesn't exist: %s", set->login_user);
		return FALSE;
	}

	if (set->server->login_gid == 0)
		set->server->login_gid = pw->pw_gid;
	else if (set->server->login_gid != pw->pw_gid) {
		i_error("All login process users must belong to same group "
			"(%s vs %s)", dec2str(set->server->login_gid),
			dec2str(pw->pw_gid));
		return FALSE;
	}

	set->login_uid = pw->pw_uid;
	return TRUE;
}

static bool auth_settings_verify(struct auth_settings *auth)
{
	struct passwd *pw;
	struct auth_socket_settings *s;

	if ((pw = getpwnam(auth->user)) == NULL) {
		i_error("Auth user doesn't exist: %s", auth->user);
		return FALSE;
	}

	if (auth->parent->defaults->login_uid == pw->pw_uid &&
	    master_uid != pw->pw_uid) {
		i_error("login_user %s (uid %s) must not be same as auth_user",
			auth->user, dec2str(pw->pw_uid));
		return FALSE;
	}
	auth->uid = pw->pw_uid;
	auth->gid = pw->pw_gid;

	if (access(t_strcut(auth->executable, ' '), X_OK) < 0) {
		i_error("Can't use auth executable %s: %m",
			t_strcut(auth->executable, ' '));
		return FALSE;
	}

	fix_base_path(auth->parent->defaults, &auth->chroot);
	if (*auth->chroot != '\0' && access(auth->chroot, X_OK) < 0) {
		i_error("Can't access auth chroot directory %s: %m",
			auth->chroot);
		return FALSE;
	}

	if (auth->ssl_require_client_cert || auth->ssl_username_from_cert) {
		/* if we require valid cert, make sure we also ask for it */
		if (auth->parent->pop3 != NULL)
			auth->parent->pop3->ssl_verify_client_cert = TRUE;
		if (auth->parent->imap != NULL)
			auth->parent->imap->ssl_verify_client_cert = TRUE;
	}

	for (s = auth->sockets; s != NULL; s = s->next) {
		fix_base_path(auth->parent->defaults, &s->master.path);
		fix_base_path(auth->parent->defaults, &s->client.path);
	}
	return TRUE;
}

static bool namespace_settings_verify(struct namespace_settings *ns)
{
	const char *name;

	name = ns->prefix != NULL ? ns->prefix : "";

	if (ns->separator != NULL &&
	    ns->separator[0] != '\0' && ns->separator[1] != '\0') {
		i_error("Namespace '%s': "
			"Hierarchy separator must be only one character long",
			name);
		return FALSE;
	}

	return TRUE;
}

static const char *get_directory(const char *path)
{
	char *str, *p;

	str = t_strdup_noconst(path);
	p = strrchr(str, '/');
	if (p == NULL)
		return ".";
	else {
		*p = '\0';
		return str;
	}
}

static bool settings_is_active(struct settings *set)
{
	if (*set->protocols == '\0') {
		/* we're probably using this with --exec-mail */
		return TRUE;
	}

	if (set->protocol == MAIL_PROTOCOL_IMAP) {
		if (strstr(set->protocols, "imap") == NULL)
			return FALSE;
	} else {
		if (strstr(set->protocols, "pop3") == NULL)
			return FALSE;
	}

	return TRUE;
}

static bool settings_have_connect_sockets(struct settings *set)
{
	struct auth_settings *auth;
	struct server_settings *server;

	for (server = set->server; server != NULL; server = server->next) {
		for (auth = server->auths; auth != NULL; auth = auth->next) {
			if (auth->sockets != NULL &&
			    strcmp(auth->sockets->type, "connect") == 0)
				return TRUE;
		}
	}

	return FALSE;
}

static void unlink_auth_sockets(const char *path, const char *prefix)
{
	DIR *dirp;
	struct dirent *dp;
	struct stat st;
	string_t *str;
	unsigned int prefix_len;

	dirp = opendir(path);
	if (dirp == NULL) {
		i_error("opendir(%s) failed: %m", path);
		return;
	}

	prefix_len = strlen(prefix);
	str = t_str_new(256);
	while ((dp = readdir(dirp)) != NULL) {
		if (dp->d_name[0] == '.')
			continue;

		if (strncmp(dp->d_name, prefix, prefix_len) != 0)
			continue;

		str_truncate(str, 0);
		str_printfa(str, "%s/%s", path, dp->d_name);
		if (lstat(str_c(str), &st) < 0) {
			if (errno != ENOENT)
				i_error("lstat(%s) failed: %m", str_c(str));
			continue;
		}
		if (!S_ISSOCK(st.st_mode))
			continue;

		/* try to avoid unlinking sockets if someone's already
		   listening in them. do this only at startup, because
		   when SIGHUPing a child process might catch the new
		   connection before it notices that it's supposed
		   to die. null_fd == -1 check is a bit kludgy, but works.. */
		if (null_fd == -1) {
			int fd = net_connect_unix(str_c(str));
			if (fd != -1 || errno != ECONNREFUSED) {
				i_fatal("Dovecot is already running? "
					"Socket already exists: %s",
					str_c(str));
			}
		}

		if (unlink(str_c(str)) < 0 && errno != ENOENT)
			i_error("unlink(%s) failed: %m", str_c(str));
	}
	(void)closedir(dirp);
}

#ifdef HAVE_MODULES
static bool get_imap_capability(struct settings *set)
{
	/* FIXME: pretty ugly code just for getting the capability
	   automatically */
	static const char *generated_capability = NULL;
	static const char *args[] = {
		"uid=65534",
		"gid=65534",
		NULL
	};
	enum master_login_status login_status;
	struct ip_addr ip;
	char buf[4096];
	int fd[2], status;
	ssize_t ret;
	unsigned int pos;
	uid_t uid;

	if (generated_capability != NULL) {
		/* Reloading configuration. Don't try to execute the imap
		   process again. Too risky and the wait() call below will
		   break it anyway. Just use the previous capability list we
		   already had generated. */
		set->imap_generated_capability =
			p_strdup(settings_pool, generated_capability);
		return TRUE;
	}

	uid = geteuid();
	if (uid != 0) {
		/* use the current user */
		args[0] = t_strdup_printf("uid=%s", dec2str(uid));
		args[1] = t_strdup_printf("gid=%s", dec2str(getegid()));
	}

	memset(&ip, 0, sizeof(ip));
	if (pipe(fd) < 0) {
		i_error("pipe() failed: %m");
		return FALSE;
	}
	fd_close_on_exec(fd[0], TRUE);
	fd_close_on_exec(fd[1], TRUE);
	login_status = create_mail_process(PROCESS_TYPE_IMAP, set, fd[1],
					   &ip, &ip, "dump-capability",
					   args, TRUE);
	if (login_status != MASTER_LOGIN_STATUS_OK) {
		(void)close(fd[0]);
		(void)close(fd[1]);
		return FALSE;
	}
	(void)close(fd[1]);

	alarm(5);
	if (wait(&status) == -1)
		i_fatal("imap dump-capability process got stuck");
	alarm(0);

	if (status != 0) {
		(void)close(fd[0]);
		if (WIFSIGNALED(status)) {
			i_error("imap dump-capability process "
				"killed with signal %d", WTERMSIG(status));
		} else {
			i_error("imap dump-capability process returned %d",
				WIFEXITED(status) ? WEXITSTATUS(status) :
				status);
		}
		return FALSE;
	}

	pos = 0;
	while ((ret = read(fd[0], buf + pos, sizeof(buf) - pos)) > 0)
		pos += ret;

	if (ret < 0) {
		i_error("read(imap dump-capability process) failed: %m");
		(void)close(fd[0]);
		return FALSE;
	}
	(void)close(fd[0]);

	if (pos == 0 || buf[pos-1] != '\n') {
		i_error("imap dump-capability: Couldn't read capability "
			"(got %u bytes)", pos);
		return FALSE;
	}
	buf[pos-1] = '\0';

	generated_capability = i_strdup(buf);
	set->imap_generated_capability =
		p_strdup(settings_pool, generated_capability);
	return TRUE;
}
#endif

static bool settings_verify(struct settings *set)
{
	const char *dir;
	int facility;

	if (!get_login_uid(set))
		return FALSE;

	set->mail_uid_t = (uid_t)-1;
	set->mail_gid_t = (gid_t)-1;

	if (*set->mail_uid != '\0') {
		if (!parse_uid(set->mail_uid, &set->mail_uid_t))
			return FALSE;
	}
	if (*set->mail_gid != '\0') {
		if (!parse_gid(set->mail_gid, &set->mail_gid_t))
			return FALSE;
	}

	if (set->protocol != MAIL_PROTOCOL_ANY &&
	    access(t_strcut(set->mail_executable, ' '), X_OK) < 0) {
		i_error("Can't use mail executable %s: %m",
			t_strcut(set->mail_executable, ' '));
		return FALSE;
	}

	if (*set->log_path != '\0' && access(set->log_path, W_OK) < 0) {
		dir = get_directory(set->log_path);
		if (access(dir, W_OK) < 0) {
			i_error("Can't write to log directory %s: %m", dir);
			return FALSE;
		}
	}

	if (*set->info_log_path != '\0' &&
	    access(set->info_log_path, W_OK) < 0) {
		dir = get_directory(set->info_log_path);
		if (access(dir, W_OK) < 0) {
			i_error("Can't write to info log directory %s: %m",
				dir);
			return FALSE;
		}
	}

	if (!syslog_facility_find(set->syslog_facility, &facility)) {
		i_error("Unknown syslog_facility '%s'", set->syslog_facility);
		return FALSE;
	}

#ifdef HAVE_SSL
	if (!set->ssl_disable) {
		if (*set->ssl_ca_file != '\0' &&
		    access(set->ssl_ca_file, R_OK) < 0) {
			i_fatal("Can't use SSL CA file %s: %m",
				set->ssl_ca_file);
		}

		if (access(set->ssl_cert_file, R_OK) < 0) {
			i_error("Can't use SSL certificate %s: %m",
				set->ssl_cert_file);
			return FALSE;
		}

		if (access(set->ssl_key_file, R_OK) < 0) {
			i_error("Can't use SSL key file %s: %m",
				set->ssl_key_file);
			return FALSE;
		}
	}
#else
	if (!set->ssl_disable) {
		i_error("SSL support not compiled in but ssl_disable=no");
		return FALSE;
	}
#endif

	if (set->max_mail_processes < 1) {
		i_error("max_mail_processes must be at least 1");
		return FALSE;
	}

	if (set->last_valid_uid != 0 &&
	    set->first_valid_uid > set->last_valid_uid) {
		i_error("first_valid_uid can't be larger than last_valid_uid");
		return FALSE;
	}
	if (set->last_valid_gid != 0 &&
	    set->first_valid_gid > set->last_valid_gid) {
		i_error("first_valid_gid can't be larger than last_valid_gid");
		return FALSE;
	}
	if (set->mail_drop_priv_before_exec && *set->mail_chroot != '\0') {
		i_error("mail_drop_priv_before_exec=yes and mail_chroot "
			"don't work together");
		return FALSE;
	}

	if (set->protocol != MAIL_PROTOCOL_ANY &&
	    access(t_strcut(set->login_executable, ' '), X_OK) < 0) {
		i_error("Can't use login executable %s: %m",
			t_strcut(set->login_executable, ' '));
		return FALSE;
	}

	if (set->login_processes_count < 1) {
		i_error("login_processes_count must be at least 1");
		return FALSE;
	}
	if (set->login_max_connections < 1) {
		i_error("login_max_connections must be at least 1");
		return FALSE;
	}

	if (set->mail_nfs_index && !set->mmap_disable) {
		i_error("mail_nfs_index=yes requires mmap_disable=yes");
		return FALSE;
	}
	if (set->mail_nfs_index && set->fsync_disable) {
		i_error("mail_nfs_index=yes requires fsync_disable=no");
		return FALSE;
	}

#ifdef HAVE_MODULES
	if (*set->mail_plugins != '\0' &&
	    access(set->mail_plugin_dir, R_OK | X_OK) < 0) {
		i_error("Can't access mail module directory: %s: %m",
			set->mail_plugin_dir);
		return FALSE;
	}
#else
	if (*set->mail_plugins != '\0') {
		i_error("Module support wasn't built into Dovecot, "
			"can't load modules: %s", set->mail_plugins);
		return FALSE;
	}
#endif
	return TRUE;
}

static bool settings_do_fixes(struct settings *set)
{
	struct stat st;

	/* since base dir is under /var/run by default, it may have been
	   deleted. */
	if (mkdir_parents(set->base_dir, 0777) < 0 && errno != EEXIST) {
		i_error("mkdir(%s) failed: %m", set->base_dir);
		return FALSE;
	}
	/* allow base_dir to be a symlink, so don't use lstat() */
	if (stat(set->base_dir, &st) < 0) {
		i_error("stat(%s) failed: %m", set->base_dir);
		return FALSE;
	}
	if ((st.st_mode & 0310) != 0310 || (st.st_mode & 0777) == 0777) {
		/* FIXME: backwards compatibility: fix permissions so that
		   login processes can find ssl-parameters file. Group rx is
		   enough, but change it to world-rx so that we don't have to
		   start changing groups and causing possibly other problems.

		   The second check is to fix 1.0beta1's accidental 0777
		   mode change.. */
		i_warning("Fixing permissions of %s to be world-readable",
			  set->base_dir);
		if (chmod(set->base_dir, 0755) < 0)
			i_error("chmod(%s) failed: %m", set->base_dir);
	}

	/* remove auth worker sockets left by unclean exits */
	unlink_auth_sockets(set->base_dir, "auth-worker.");

	/* Make sure our permanent state directory exists */
	if (mkdir_parents(PKG_STATEDIR, 0750) < 0 && errno != EEXIST) {
		i_error("mkdir(%s) failed: %m", PKG_STATEDIR);
		return FALSE;
	}

	if (!settings_have_connect_sockets(set)) {
		/* we are not using external authentication, so make sure the
		   login directory exists with correct permissions and it's
		   empty. with external auth we wouldn't want to delete
		   existing sockets or break the permissions required by the
		   auth server. */
		if (safe_mkdir(set->login_dir, 0750,
			       master_uid, set->server->login_gid) == 0) {
			i_warning("Corrected permissions for login directory "
				  "%s", set->login_dir);
		}

		unlink_auth_sockets(set->login_dir, "");
	}

#ifdef HAVE_MODULES
	if (*set->mail_plugins != '\0' && set->protocol == MAIL_PROTOCOL_IMAP &&
	    *set->imap_capability == '\0') {
		if (!get_imap_capability(set))
			return FALSE;
	}
#endif
	return TRUE;
}

static bool settings_fix(struct settings *set, bool nochecks, bool nofixes)
{
	/* fix relative paths */
	fix_base_path(set, &set->login_dir);

	if (nochecks)
		return TRUE;
	if (!settings_verify(set))
		return FALSE;
	return nofixes ? TRUE : settings_do_fixes(set);
}

static void pid_file_check_running(const char *path)
{
	char buf[32];
	int fd;
	ssize_t ret;

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		if (errno == ENOENT)
			return;
		i_fatal("open(%s) failed: %m", path);
	}

	ret = read(fd, buf, sizeof(buf));
	if (ret <= 0) {
		if (ret == 0)
			i_error("Empty PID file in %s, overriding", path);
		else
			i_fatal("read(%s) failed: %m", path);
	} else {
		pid_t pid;

		if (buf[ret-1] == '\n')
			ret--;
		buf[ret] = '\0';
		pid = atoi(buf);
		if (pid == getpid() || (kill(pid, 0) < 0 && errno == ESRCH)) {
			/* doesn't exist */
		} else {
			i_fatal("Dovecot is already running with PID %s "
				"(read from %s)", buf, path);
		}
	}
	(void)close(fd);
}

static struct auth_settings *
auth_settings_new(struct server_settings *server, const char *name)
{
	struct auth_settings *auth;

	auth = p_new(settings_pool, struct auth_settings, 1);

	/* copy defaults */
	*auth = server->auth_defaults;
	auth->parent = server;
	auth->name = p_strdup(settings_pool, name);

	auth->next = server->auths;
	server->auths = auth;

	return auth;
}

static struct auth_settings *
parse_new_auth(struct server_settings *server, const char *name,
	       const char **errormsg)
{
	struct auth_settings *auth;

	if (strchr(name, '/') != NULL) {
		*errormsg = "Authentication process name must not contain '/'";
		return NULL;
	}

	for (auth = server->auths; auth != NULL; auth = auth->next) {
		if (strcmp(auth->name, name) == 0) {
			*errormsg = "Authentication process already exists "
				"with the same name";
			return NULL;
		}
	}

	return auth_settings_new(server, name);
}

static struct auth_passdb_settings *
auth_passdb_settings_new(struct auth_settings *auth, const char *type)
{
	struct auth_passdb_settings *as, **as_p;

	as = p_new(settings_pool, struct auth_passdb_settings, 1);

	as->parent = auth;
	as->driver = str_lcase(p_strdup(settings_pool, type));

	as_p = &auth->passdbs;
	while (*as_p != NULL)
		as_p = &(*as_p)->next;
	*as_p = as;

	return as;
}

static struct auth_userdb_settings *
auth_userdb_settings_new(struct auth_settings *auth, const char *type)
{
	struct auth_userdb_settings *as, **as_p;

	as = p_new(settings_pool, struct auth_userdb_settings, 1);

	as->parent = auth;
	as->driver = str_lcase(p_strdup(settings_pool, type));

	as_p = &auth->userdbs;
	while (*as_p != NULL)
		as_p = &(*as_p)->next;
	*as_p = as;

	return as;
}

static struct auth_socket_settings *
auth_socket_settings_new(struct auth_settings *auth, const char *type)
{
	struct auth_socket_settings *as, **as_p;

	as = p_new(settings_pool, struct auth_socket_settings, 1);

	as->parent = auth;
	as->type = str_lcase(p_strdup(settings_pool, type));
	as->master = default_socket_settings;
	as->client = default_socket_settings;

	as->master.path = DEFAULT_MASTER_SOCKET_PATH;
	as->client.path = DEFAULT_CLIENT_SOCKET_PATH;

	as_p = &auth->sockets;
	while (*as_p != NULL)
		as_p = &(*as_p)->next;
	*as_p = as;

	return as;
}

static struct auth_socket_settings *
parse_new_auth_socket(struct auth_settings *auth, const char *name,
		      const char **errormsg)
{
	if (strcmp(name, "connect") != 0 && strcmp(name, "listen") != 0) {
		*errormsg = "Unknown auth socket type";
		return NULL;
	}

	if ((auth->sockets != NULL && strcmp(name, "connect") == 0) ||
	    (auth->sockets != NULL &&
	     strcmp(auth->sockets->type, "listen") == 0)) {
		*errormsg = "With connect auth socket no other sockets "
			"can be used in same auth section";
		return NULL;
	}

	return auth_socket_settings_new(auth, name);
}

static struct namespace_settings *
namespace_settings_new(struct server_settings *server, const char *type)
{
	struct namespace_settings *ns, **ns_p;

	ns = p_new(settings_pool, struct namespace_settings, 1);
	*ns = default_namespace_settings;

	ns->parent = server;
	ns->type = str_lcase(p_strdup(settings_pool, type));

	ns_p = &server->namespaces;
	while (*ns_p != NULL)
		ns_p = &(*ns_p)->next;
	*ns_p = ns;

	return ns;
}

static struct namespace_settings *
parse_new_namespace(struct server_settings *server, const char *name,
		    const char **errormsg)
{
	if (strcasecmp(name, "private") != 0 &&
	    strcasecmp(name, "shared") != 0 &&
	    strcasecmp(name, "public") != 0) {
		*errormsg = "Unknown namespace type";
		return NULL;
	}

	return namespace_settings_new(server, name);
}

static const char *parse_setting(const char *key, const char *value,
				 struct settings_parse_ctx *ctx)
{
	const char *error;

	/* backwards compatibility */
	if (strcmp(key, "auth") == 0) {
		ctx->auth = parse_new_auth(ctx->server, value, &error);
		return ctx->auth == NULL ? error : NULL;
	}

	if (strcmp(key, "login") == 0) {
		i_warning("Ignoring deprecated 'login' section handling. "
			  "Use protocol imap/pop3 { .. } instead. "
			  "Some settings may have been read incorrectly.");
		return NULL;
	}

	switch (ctx->type) {
	case SETTINGS_TYPE_ROOT:
	case SETTINGS_TYPE_SERVER:
		error = NULL;
		if (ctx->protocol == MAIL_PROTOCOL_ANY ||
		    ctx->protocol == MAIL_PROTOCOL_IMAP) {
			error = parse_setting_from_defs(settings_pool,
							setting_defs,
							ctx->server->imap,
							key, value);
		}

		if (error == NULL &&
		    (ctx->protocol == MAIL_PROTOCOL_ANY ||
		     ctx->protocol == MAIL_PROTOCOL_POP3)) {
			error = parse_setting_from_defs(settings_pool,
							setting_defs,
							ctx->server->pop3,
							key, value);
		}

		if (error == NULL)
			return NULL;

		if (strncmp(key, "auth_", 5) == 0) {
			return parse_setting_from_defs(settings_pool,
						       auth_setting_defs,
						       ctx->auth,
						       key + 5, value);
		}
		return error;
	case SETTINGS_TYPE_AUTH:
		if (strncmp(key, "auth_", 5) == 0)
			key += 5;
		return parse_setting_from_defs(settings_pool, auth_setting_defs,
					       ctx->auth, key, value);
	case SETTINGS_TYPE_AUTH_SOCKET:
		return parse_setting_from_defs(settings_pool,
					       auth_socket_setting_defs,
					       ctx->auth_socket, key, value);
	case SETTINGS_TYPE_AUTH_PASSDB:
		return parse_setting_from_defs(settings_pool,
					       auth_passdb_setting_defs,
					       ctx->auth_passdb, key, value);
	case SETTINGS_TYPE_AUTH_USERDB:
		return parse_setting_from_defs(settings_pool,
					       auth_userdb_setting_defs,
					       ctx->auth_userdb, key, value);
	case SETTINGS_TYPE_NAMESPACE:
		return parse_setting_from_defs(settings_pool,
					       namespace_setting_defs,
					       ctx->namespace, key, value);
	case SETTINGS_TYPE_SOCKET:
		return parse_setting_from_defs(settings_pool,
					       socket_setting_defs,
					       ctx->socket, key, value);
	case SETTINGS_TYPE_DICT:
		key = p_strdup(settings_pool, key);
		value = p_strdup(settings_pool, value);

		array_append(&ctx->server->dicts, &key, 1);
		array_append(&ctx->server->dicts, &value, 1);
		return NULL;
	case SETTINGS_TYPE_PLUGIN:
		key = p_strdup(settings_pool, key);
		value = p_strdup(settings_pool, value);

		if (ctx->protocol == MAIL_PROTOCOL_ANY ||
		    ctx->protocol == MAIL_PROTOCOL_IMAP) {
			array_append(&ctx->server->imap->plugin_envs, &key, 1);
			array_append(&ctx->server->imap->plugin_envs,
				     &value, 1);
		}
		if (ctx->protocol == MAIL_PROTOCOL_ANY ||
		    ctx->protocol == MAIL_PROTOCOL_POP3) {
			array_append(&ctx->server->pop3->plugin_envs, &key, 1);
			array_append(&ctx->server->pop3->plugin_envs,
				     &value, 1);
		}
		return NULL;
	}

	i_unreached();
}

static struct server_settings *
create_new_server(const char *name,
		  struct settings *imap_defaults,
		  struct settings *pop3_defaults)
{
	struct server_settings *server;

	server = p_new(settings_pool, struct server_settings, 1);
	server->name = p_strdup(settings_pool, name);
	server->imap = p_new(settings_pool, struct settings, 1);
	server->pop3 = p_new(settings_pool, struct settings, 1);
	server->auth_defaults = default_auth_settings;

	*server->imap = *imap_defaults;
	*server->pop3 = *pop3_defaults;

	p_array_init(&server->dicts, settings_pool, 4);
	p_array_init(&server->imap->plugin_envs, settings_pool, 8);
	p_array_init(&server->pop3->plugin_envs, settings_pool, 8);

	server->imap->server = server;
	server->imap->protocol = MAIL_PROTOCOL_IMAP;
	server->imap->login_executable = PKG_LIBEXECDIR"/imap-login";
	server->imap->mail_executable = PKG_LIBEXECDIR"/imap";
	server->imap->mail_plugin_dir = MODULEDIR"/imap";

	server->pop3->server = server;
	server->pop3->protocol = MAIL_PROTOCOL_POP3;
	server->pop3->login_executable = PKG_LIBEXECDIR"/pop3-login";
	server->pop3->mail_executable = PKG_LIBEXECDIR"/pop3";
	server->pop3->mail_plugin_dir = MODULEDIR"/pop3";

	return server;
}

static bool parse_section(const char *type, const char *name,
			  struct settings_parse_ctx *ctx, const char **errormsg)
{
	struct server_settings *server;

	if (type == NULL) {
		/* section closing */
		if (ctx->level-- > 0) {
			ctx->type = ctx->parent_type;
			ctx->protocol = MAIL_PROTOCOL_ANY;

			switch (ctx->type) {
			case SETTINGS_TYPE_AUTH_SOCKET:
				ctx->parent_type = SETTINGS_TYPE_AUTH;
				break;
			default:
				ctx->parent_type = SETTINGS_TYPE_ROOT;
				break;
			}
		} else {
			ctx->type = SETTINGS_TYPE_ROOT;
			ctx->server = ctx->root;
			ctx->auth = &ctx->root->auth_defaults;
			ctx->namespace = NULL;
		}
		return TRUE;
	}

	ctx->level++;
	ctx->parent_type = ctx->type;

	if (strcmp(type, "server") == 0) {
		if (ctx->type != SETTINGS_TYPE_ROOT) {
			*errormsg = "Server section not allowed here";
			return FALSE;
		}

		ctx->type = SETTINGS_TYPE_SERVER;
		ctx->server = create_new_server(name, ctx->server->imap,
						ctx->server->pop3);
                server = ctx->root;
		while (server->next != NULL)
			server = server->next;
		server->next = ctx->server;
		return TRUE;
	}

	if (strcmp(type, "protocol") == 0) {
		if ((ctx->type != SETTINGS_TYPE_ROOT &&
		     ctx->type != SETTINGS_TYPE_SERVER) ||
		    ctx->level != 1) {
			*errormsg = "Protocol section not allowed here";
			return FALSE;
		}

		if (strcmp(name, "imap") == 0)
			ctx->protocol = MAIL_PROTOCOL_IMAP;
		else if (strcmp(name, "pop3") == 0)
			ctx->protocol = MAIL_PROTOCOL_POP3;
		else if (strcmp(name, "lda") == 0)
			ctx->protocol = MAIL_PROTOCOL_LDA;
		else {
			*errormsg = "Unknown protocol name";
			return FALSE;
		}
		return TRUE;
	}

	if (strcmp(type, "auth") == 0) {
		if (ctx->type != SETTINGS_TYPE_ROOT &&
		    ctx->type != SETTINGS_TYPE_SERVER) {
			*errormsg = "Auth section not allowed here";
			return FALSE;
		}

		ctx->type = SETTINGS_TYPE_AUTH;
		ctx->auth = parse_new_auth(ctx->server, name, errormsg);
		return ctx->auth != NULL;
	}

	if (ctx->type == SETTINGS_TYPE_AUTH &&
	    strcmp(type, "socket") == 0) {
		ctx->type = SETTINGS_TYPE_AUTH_SOCKET;
		ctx->auth_socket = parse_new_auth_socket(ctx->auth,
							 name, errormsg);
		return ctx->auth_socket != NULL;
	}

	if (ctx->type == SETTINGS_TYPE_AUTH && strcmp(type, "passdb") == 0) {
		ctx->type = SETTINGS_TYPE_AUTH_PASSDB;
		ctx->auth_passdb = auth_passdb_settings_new(ctx->auth, name);
		return TRUE;
	}

	if (ctx->type == SETTINGS_TYPE_AUTH && strcmp(type, "userdb") == 0) {
		ctx->type = SETTINGS_TYPE_AUTH_USERDB;
		ctx->auth_userdb = auth_userdb_settings_new(ctx->auth, name);
		return TRUE;
	}

	if (ctx->type == SETTINGS_TYPE_AUTH_SOCKET) {
		ctx->type = SETTINGS_TYPE_SOCKET;

		if (strcmp(type, "master") == 0) {
			ctx->socket = &ctx->auth_socket->master;
			ctx->socket->used = TRUE;
			return TRUE;
		}

		if (strcmp(type, "client") == 0) {
			ctx->socket = &ctx->auth_socket->client;
			ctx->socket->used = TRUE;
			return TRUE;
		}
	}

	if (strcmp(type, "namespace") == 0) {
		if (ctx->type != SETTINGS_TYPE_ROOT &&
		    ctx->type != SETTINGS_TYPE_SERVER) {
			*errormsg = "Namespace section not allowed here";
			return FALSE;
		}

		ctx->type = SETTINGS_TYPE_NAMESPACE;
		ctx->namespace = parse_new_namespace(ctx->server, name,
						     errormsg);
		return ctx->namespace != NULL;
	}

	if (strcmp(type, "dict") == 0) {
		if (ctx->type != SETTINGS_TYPE_ROOT &&
		    ctx->type != SETTINGS_TYPE_SERVER) {
			*errormsg = "Plugin section not allowed here";
			return FALSE;
		}

		ctx->type = SETTINGS_TYPE_DICT;
		return TRUE;
	}

	if (strcmp(type, "plugin") == 0) {
		if (ctx->type != SETTINGS_TYPE_ROOT &&
		    ctx->type != SETTINGS_TYPE_SERVER) {
			*errormsg = "Plugin section not allowed here";
			return FALSE;
		}

		ctx->type = SETTINGS_TYPE_PLUGIN;
		return TRUE;
	}

	*errormsg = "Unknown section type";
	return FALSE;
}

static void
settings_warn_needed_fds(struct server_settings *server ATTR_UNUSED)
{
#ifdef HAVE_SETRLIMIT
	struct rlimit rlim;
	unsigned int fd_count = 0;

	if (getrlimit(RLIMIT_NOFILE, &rlim) < 0)
		return;

	/* count only log pipes needed for login and mail processes. we need
	   more, but they're the ones that can use up most of the fds */
	for (; server != NULL; server = server->next) {
		if (server->imap != NULL)
			fd_count += server->imap->login_max_processes_count;
		if (server->pop3 != NULL)
			fd_count += server->pop3->login_max_processes_count;
		fd_count += server->defaults->max_mail_processes;
	}

	if (rlim.rlim_cur < fd_count) {
		i_warning("fd limit %d is lower than what Dovecot can use under "
			  "full load (more than %u). Either grow the limit or "
			  "change login_max_processes_count and "
			  "max_mail_processes settings",
			  (int)rlim.rlim_cur, fd_count);
	}
#endif
}

bool master_settings_read(const char *path, bool nochecks, bool nofixes)
{
	struct settings_parse_ctx ctx;
	struct server_settings *server, *prev;
	struct auth_settings *auth;
	struct namespace_settings *ns;
	pool_t temp;

	memset(&ctx, 0, sizeof(ctx));

	p_clear(settings_pool);

	ctx.type = SETTINGS_TYPE_ROOT;
	ctx.protocol = MAIL_PROTOCOL_ANY;
	ctx.server = ctx.root =
		create_new_server("default",
				  &default_settings, &default_settings);
	ctx.auth = &ctx.server->auth_defaults;

	if (!settings_read(path, NULL, parse_setting, parse_section, &ctx))
		return FALSE;

	if (ctx.level != 0) {
		i_error("Missing '}'");
		return FALSE;
	}

	/* If server sections were defined, skip the root */
	if (ctx.root->next != NULL)
		ctx.root = ctx.root->next;

	if (!nochecks && !nofixes) {
		ctx.root->defaults = settings_is_active(ctx.root->imap) ?
			ctx.root->imap : ctx.root->pop3;

		path = t_strconcat(ctx.root->defaults->base_dir,
				   "/master.pid", NULL);
		pid_file_check_running(path);
	}

	prev = NULL;
	for (server = ctx.root; server != NULL; server = server->next) {
		if ((*server->imap->protocols == '\0' ||
		     *server->pop3->protocols == '\0') && !nochecks) {
			i_error("No protocols given in configuration file");
			return FALSE;
		}
		/* --exec-mail is used if nochecks=TRUE. Allow it regardless
		   of what's in protocols setting. */
		if (!settings_is_active(server->imap) && !nochecks) {
			if (strcmp(server->imap->protocols, "none") == 0) {
				server->imap->protocol = MAIL_PROTOCOL_ANY;
				if (!settings_fix(server->imap, nochecks,
						  nofixes))
					return FALSE;
				server->defaults = server->imap;
			}
			server->imap = NULL;
		} else {
			if (!settings_fix(server->imap, nochecks, nofixes))
				return FALSE;
			server->defaults = server->imap;
		}

		if (!settings_is_active(server->pop3) && !nochecks)
			server->pop3 = NULL;
		else {
			if (!settings_fix(server->pop3, nochecks, nofixes))
				return FALSE;
			if (server->defaults == NULL)
				server->defaults = server->pop3;
		}

		if (server->defaults == NULL) {
			if (prev == NULL)
				ctx.root = server->next;
			else
				prev->next = server->next;
		} else {
			auth = server->auths;
			if (auth == NULL) {
				i_error("Missing auth section for server %s",
					server->name);
				return FALSE;
			}

			if (!nochecks) {
				for (; auth != NULL; auth = auth->next) {
					if (!auth_settings_verify(auth))
						return FALSE;
				}
				ns = server->namespaces;
				for (; ns != NULL; ns = ns->next) {
					if (!namespace_settings_verify(ns))
						return FALSE;
				}
			}
			prev = server;
		}
	}

	if (ctx.root == NULL) {
		/* We aren't actually checking them separately, but if it
		   contains only invalid protocols we'll get here.. */
		i_error("Invalid protocols given in configuration file");
		return FALSE;
	}

	if (!nochecks)
		settings_warn_needed_fds(ctx.root);

	/* settings ok, swap them */
	temp = settings_pool;
	settings_pool = settings2_pool;
	settings2_pool = temp;

	settings_root = ctx.root;
	return TRUE;
}

static void settings_dump(const struct setting_def *def, const void **sets,
			  const char **set_names, unsigned int count,
			  bool nondefaults, unsigned int indent)
{
	const char **str;
	unsigned int i;

	str = t_new(const char *, count);
	for (; def->name != NULL; def++) {
		bool same = TRUE;

		switch (def->type) {
		case SET_STR: {
			const char *const *strp;

			for (i = 0; i < count; i++) {
				strp = CONST_PTR_OFFSET(sets[i], def->offset);
				str[i] = *strp != NULL ? *strp : "";
			}
			break;
		}
		case SET_INT: {
			const unsigned int *n;

			for (i = 0; i < count; i++) {
				n = CONST_PTR_OFFSET(sets[i], def->offset);
				str[i] = dec2str(*n);
			}
			break;
		}
		case SET_BOOL: {
			const bool *b;

			for (i = 0; i < count; i++) {
				b = CONST_PTR_OFFSET(sets[i], def->offset);
				str[i] = *b ? "yes" : "no";
			}
			break;
		}
		}

		for (i = 2; i < count; i++) {
			if (strcmp(str[i], str[i-1]) != 0)
				same = FALSE;
		}
		if (same) {
			if (!nondefaults || strcmp(str[0], str[1]) != 0) {
				for (i = 0; i < indent; i++)
					putc(' ', stdout);
				printf("%s: %s\n", def->name, str[1]);
			}
		} else {
			for (i = 0; i < indent; i++)
				putc(' ', stdout);
			for (i = 1; i < count; i++) {
				printf("%s(%s): %s\n", def->name,
				       set_names[i], str[i]);
			}
		}
	}
}

static void
namespace_settings_dump(struct namespace_settings *ns, bool nondefaults)
{
	const void *sets[2];

	sets[0] = t_malloc0(sizeof(struct namespace_settings));
	for (; ns != NULL; ns = ns->next) {
		printf("namespace:\n");
		sets[1] = ns;
		settings_dump(namespace_setting_defs, sets, NULL, 2,
			      nondefaults, 2);
	}
}

static void auth_settings_dump(struct auth_settings *auth, bool nondefaults)
{
	const struct auth_passdb_settings *passdb;
	const struct auth_userdb_settings *userdb;
	const struct auth_socket_settings *socket;
	const void *sets[2], *sets2[2];
	const void *empty_defaults;

	empty_defaults = t_malloc0(sizeof(struct auth_passdb_settings) +
				   sizeof(struct auth_userdb_settings) +
				   sizeof(struct auth_socket_settings));

	sets[0] = &default_auth_settings;
	sets2[0] = empty_defaults;

	for (; auth != NULL; auth = auth->next) {
		printf("auth %s:\n", auth->name);
		sets[1] = auth;
		settings_dump(auth_setting_defs, sets, NULL, 2, nondefaults, 2);

		passdb = auth->passdbs;
		for (; passdb != NULL; passdb = passdb->next) {
			printf("  passdb:\n");
			sets2[1] = passdb;
			settings_dump(auth_passdb_setting_defs, sets2, NULL, 2,
				      nondefaults, 4);
		}

		userdb = auth->userdbs;
		for (; userdb != NULL; userdb = userdb->next) {
			printf("  userdb:\n");
			sets2[1] = userdb;
			settings_dump(auth_userdb_setting_defs, sets2, NULL, 2,
				      nondefaults, 4);
		}

		socket = auth->sockets;
		for (; socket != NULL; socket = socket->next) {
			printf("  socket:\n");
			sets2[1] = socket;
			settings_dump(auth_socket_setting_defs, sets2, NULL, 2,
				      nondefaults, 4);

			if (socket->client.used) {
				printf("    client:\n");
				sets2[1] = &socket->client;
				settings_dump(socket_setting_defs, sets2, NULL,
					      2, nondefaults, 6);
			}

			if (socket->master.used) {
				printf("    master:\n");
				sets2[1] = &socket->master;
				settings_dump(socket_setting_defs, sets2, NULL,
					      2, nondefaults, 6);
			}
		}
	}
}

static void plugin_settings_dump(const struct settings *set)
{
	const char *const *envs;
	unsigned int i, count;

	envs = array_get(&set->plugin_envs, &count);
	i_assert((count % 2) == 0);

	if (count == 0)
		return;

	printf("plugin:\n");
	for (i = 0; i < count; i += 2)
		printf("  %s: %s\n", envs[i], envs[i+1]);
}

static void dict_settings_dump(const struct server_settings *set)
{
	const char *const *dicts;
	unsigned int i, count;

	dicts = array_get(&set->dicts, &count);
	i_assert((count % 2) == 0);

	if (count == 0)
		return;

	printf("dict:\n");
	for (i = 0; i < count; i += 2)
		printf("  %s: %s\n", dicts[i], dicts[i+1]);
}

void master_settings_dump(struct server_settings *set, bool nondefaults)
{
	const void *sets[4];
	const char *set_names[4];
	unsigned int count;

	sets[0] = &default_settings;
	sets[1] = set->defaults;

	set_names[0] = NULL;
	set_names[1] = "default";

	count = 2;
	if (set->imap != NULL) {
		sets[count] = set->imap;
		set_names[count] = "imap";
		count++;
	}
	if (set->pop3 != NULL) {
		sets[count] = set->pop3;
		set_names[count] = "pop3";
		count++;
	}
	settings_dump(setting_defs, sets, set_names, count, nondefaults, 0);
	namespace_settings_dump(set->namespaces, nondefaults);
	auth_settings_dump(set->auths, nondefaults);
	plugin_settings_dump(set->defaults);
	dict_settings_dump(set);
}

void master_settings_init(void)
{
	settings_pool = pool_alloconly_create("settings", 4096);
	settings2_pool = pool_alloconly_create("settings2", 4096);
}

void master_settings_deinit(void)
{
	pool_unref(&settings_pool);
	pool_unref(&settings2_pool);
}
