/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "istream.h"
#include "safe-mkdir.h"
#include "unlink-directory.h"
#include "settings.h"

#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>

#define DEF(type, name) \
	{ type, #name, offsetof(struct settings, name) }

static struct setting_def setting_defs[] = {
	/* common */
	DEF(SET_STR, base_dir),
	DEF(SET_STR, log_path),
	DEF(SET_STR, info_log_path),
	DEF(SET_STR, log_timestamp),

	/* general */
	DEF(SET_STR, protocols),
	DEF(SET_STR, imap_listen),
	DEF(SET_STR, imaps_listen),
	DEF(SET_STR, pop3_listen),
	DEF(SET_STR, pop3s_listen),

	DEF(SET_BOOL, ssl_disable),
	DEF(SET_STR, ssl_cert_file),
	DEF(SET_STR, ssl_key_file),
	DEF(SET_STR, ssl_parameters_file),
	DEF(SET_STR, ssl_parameters_regenerate),
	DEF(SET_BOOL, disable_plaintext_auth),

	/* login */
	DEF(SET_STR, login_dir),
	DEF(SET_BOOL, login_chroot),

	/* mail */
	DEF(SET_STR, valid_chroot_dirs),
	DEF(SET_INT, max_mail_processes),
	DEF(SET_BOOL, verbose_proctitle),

	DEF(SET_INT, first_valid_uid),
	DEF(SET_INT, last_valid_uid),
	DEF(SET_INT, first_valid_gid),
	DEF(SET_INT, last_valid_gid),

	DEF(SET_STR, default_mail_env),
	DEF(SET_STR, mail_cache_fields),
	DEF(SET_STR, mail_never_cache_fields),
	DEF(SET_STR, client_workarounds),
	DEF(SET_INT, mailbox_check_interval),
	DEF(SET_BOOL, mail_full_filesystem_access),
	DEF(SET_INT, mail_max_flag_length),
	DEF(SET_BOOL, mail_save_crlf),
	DEF(SET_BOOL, mail_read_mmaped),
	DEF(SET_BOOL, maildir_copy_with_hardlinks),
	DEF(SET_BOOL, maildir_check_content_changes),
	DEF(SET_STR, mbox_locks),
	DEF(SET_BOOL, mbox_read_dotlock),
	DEF(SET_INT, mbox_lock_timeout),
	DEF(SET_INT, mbox_dotlock_change_timeout),
	DEF(SET_BOOL, overwrite_incompatible_index),
	DEF(SET_INT, umask),

	/* imap */
	DEF(SET_STR, imap_executable),
	DEF(SET_INT, imap_process_size),

	/* pop3 */
	DEF(SET_STR, pop3_executable),
	DEF(SET_INT, pop3_process_size),

	{ 0, NULL, 0 }
};

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct login_settings, name) }

static struct setting_def login_setting_defs[] = {
	DEF(SET_STR, executable),
	DEF(SET_STR, user),

	DEF(SET_BOOL, process_per_connection),

	DEF(SET_INT, process_size),
	DEF(SET_INT, processes_count),
	DEF(SET_INT, max_processes_count),
	DEF(SET_INT, max_logging_users),

	{ 0, NULL, 0 }
};

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct auth_settings, name) }

static struct setting_def auth_setting_defs[] = {
	DEF(SET_STR, mechanisms),
	DEF(SET_STR, realms),
	DEF(SET_STR, userdb),
	DEF(SET_STR, passdb),
	DEF(SET_STR, executable),
	DEF(SET_STR, user),
	DEF(SET_STR, chroot),

	DEF(SET_BOOL, use_cyrus_sasl),
	DEF(SET_BOOL, verbose),

	DEF(SET_INT, count),
	DEF(SET_INT, process_size),

	{ 0, NULL, 0 }
};

struct settings default_settings = {
	/* common */
	MEMBER(base_dir) PKG_RUNDIR,
	MEMBER(log_path) NULL,
	MEMBER(info_log_path) NULL,
	MEMBER(log_timestamp) DEFAULT_FAILURE_STAMP_FORMAT,

	/* general */
	MEMBER(protocols) "imap imaps",
	MEMBER(imap_listen) "*",
	MEMBER(imaps_listen) NULL,
	MEMBER(pop3_listen) "*",
	MEMBER(pop3s_listen) NULL,

	MEMBER(ssl_disable) FALSE,
	MEMBER(ssl_cert_file) SSLDIR"/certs/dovecot.pem",
	MEMBER(ssl_key_file) SSLDIR"/private/dovecot.pem",
	MEMBER(ssl_parameters_file) "ssl-parameters.dat",
	MEMBER(ssl_parameters_regenerate) 24,
	MEMBER(disable_plaintext_auth) FALSE,

	/* login */
	MEMBER(login_dir) "login",
	MEMBER(login_chroot) TRUE,

	/* mail */
	MEMBER(valid_chroot_dirs) NULL,
	MEMBER(max_mail_processes) 1024,
	MEMBER(verbose_proctitle) FALSE,

	MEMBER(first_valid_uid) 500,
	MEMBER(last_valid_uid) 0,
	MEMBER(first_valid_gid) 1,
	MEMBER(last_valid_gid) 0,

	MEMBER(default_mail_env) NULL,
	MEMBER(mail_cache_fields) "MessagePart",
	MEMBER(mail_never_cache_fields) NULL,
	MEMBER(client_workarounds) NULL,
	MEMBER(mailbox_check_interval) 0,
	MEMBER(mail_full_filesystem_access) FALSE,
	MEMBER(mail_max_flag_length) 50,
	MEMBER(mail_save_crlf) FALSE,
	MEMBER(mail_read_mmaped) FALSE,
	MEMBER(maildir_copy_with_hardlinks) FALSE,
	MEMBER(maildir_check_content_changes) FALSE,
	MEMBER(mbox_locks) "dotlock fcntl",
	MEMBER(mbox_read_dotlock) FALSE,
	MEMBER(mbox_lock_timeout) 300,
	MEMBER(mbox_dotlock_change_timeout) 30,
	MEMBER(overwrite_incompatible_index) FALSE,
	MEMBER(umask) 0077,

	/* imap */
	MEMBER(imap_executable) PKG_LIBEXECDIR"/imap",
	MEMBER(imap_process_size) 256,

	/* pop3 */
	MEMBER(pop3_executable) PKG_LIBEXECDIR"/pop3",
	MEMBER(pop3_process_size) 256,

	MEMBER(login_gid) 0,
	MEMBER(auths) NULL,
	MEMBER(logins) NULL
};

struct login_settings default_login_settings = {
	MEMBER(next) NULL,
	MEMBER(name) NULL,

	MEMBER(executable) NULL,
	MEMBER(user) "dovecot",

	MEMBER(process_per_connection) TRUE,

	MEMBER(process_size) 16,
	MEMBER(processes_count) 3,
	MEMBER(max_processes_count) 128,
	MEMBER(max_logging_users) 256,

	MEMBER(uid) 0 /* generated */
};

static pool_t settings_pool;
struct settings *set = NULL;

static void fix_base_path(struct settings *set, const char **str)
{
	if (*str != NULL && **str != '\0' && **str != '/') {
		*str = p_strconcat(settings_pool,
				   set->base_dir, "/", *str, NULL);
	}
}

static void get_login_uid(struct settings *set,
			  struct login_settings *login_set)
{
	struct passwd *pw;

	if ((pw = getpwnam(login_set->user)) == NULL)
		i_fatal("Login user doesn't exist: %s", login_set->user);

	if (set->login_gid == 0)
		set->login_gid = pw->pw_gid;
	else if (set->login_gid != pw->pw_gid) {
		i_fatal("All login process users must belong to same group "
			"(%s vs %s)", dec2str(set->login_gid),
			dec2str(pw->pw_gid));
	}

	login_set->uid = pw->pw_uid;
}

static void auth_settings_verify(struct auth_settings *auth)
{
	if (access(auth->executable, X_OK) < 0)
		i_fatal("Can't use auth executable %s: %m", auth->executable);

	fix_base_path(set, &auth->chroot);
	if (auth->chroot != NULL && access(auth->chroot, X_OK) < 0) {
		i_fatal("Can't access auth chroot directory %s: %m",
			auth->chroot);
	}
}

static void login_settings_verify(struct login_settings *login)
{
	if (strstr(set->protocols, login->name) != NULL) {
		if (access(login->executable, X_OK) < 0)
			i_fatal("Can't use login executable %s: %m",
				login->executable);
	}

	if (login->processes_count < 1)
		i_fatal("login_processes_count must be at least 1");
	if (login->max_logging_users < 1)
		i_fatal("max_logging_users must be at least 1");
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

static void settings_verify(struct settings *set)
{
	struct login_settings *login;
	struct auth_settings *auth;
	const char *const *str;
	const char *dir;
	int dotlock_got, fcntl_got, flock_got;

	for (login = set->logins; login != NULL; login = login->next) {
		get_login_uid(set, login);
		login_settings_verify(login);
	}

	if (strstr(set->protocols, "imap") != NULL) {
		if (access(set->imap_executable, X_OK) < 0) {
			i_fatal("Can't use imap executable %s: %m",
				set->imap_executable);
		}
	}

	if (strstr(set->protocols, "pop3") != NULL) {
		if (access(set->pop3_executable, X_OK) < 0) {
			i_fatal("Can't use pop3 executable %s: %m",
				set->pop3_executable);
		}
	}

	if (set->log_path != NULL && access(set->log_path, W_OK) < 0) {
		dir = get_directory(set->log_path);
		if (access(dir, W_OK) < 0)
			i_fatal("Can't write to log directory %s: %m", dir);
	}

	if (set->info_log_path != NULL &&
	    access(set->info_log_path, W_OK) < 0) {
		dir = get_directory(set->info_log_path);
		if (access(dir, W_OK) < 0) {
			i_fatal("Can't write to info log directory %s: %m",
				dir);
		}
	}

#ifdef HAVE_SSL
	if (!set->ssl_disable) {
		if (access(set->ssl_cert_file, R_OK) < 0) {
			i_fatal("Can't use SSL certificate %s: %m",
				set->ssl_cert_file);
		}

		if (access(set->ssl_key_file, R_OK) < 0) {
			i_fatal("Can't use SSL key file %s: %m",
				set->ssl_key_file);
		}
	}
#endif

	/* fix relative paths */
	fix_base_path(set, &set->ssl_parameters_file);
	fix_base_path(set, &set->login_dir);

	/* since they're under /var/run by default, they may have been
	   deleted. */
	if (safe_mkdir(set->base_dir, 0700, geteuid(), getegid()) == 0) {
		i_warning("Corrected permissions for base directory %s",
			  PKG_RUNDIR);
	}

	/* wipe out contents of login directory, if it exists */
	if (unlink_directory(set->login_dir, FALSE) < 0)
		i_fatal("unlink_directory() failed for %s: %m", set->login_dir);

	if (safe_mkdir(set->login_dir, 0750, geteuid(), set->login_gid) == 0) {
		i_warning("Corrected permissions for login directory %s",
			  set->login_dir);
	}

	if (set->max_mail_processes < 1)
		i_fatal("max_mail_processes must be at least 1");

	if (set->last_valid_uid != 0 &&
	    set->first_valid_uid > set->last_valid_uid)
		i_fatal("first_valid_uid can't be larger than last_valid_uid");
	if (set->last_valid_gid != 0 &&
	    set->first_valid_gid > set->last_valid_gid)
		i_fatal("first_valid_gid can't be larger than last_valid_gid");

	dotlock_got = fcntl_got = flock_got = FALSE;
	for (str = t_strsplit(set->mbox_locks, " "); *str != NULL; str++) {
		if (strcasecmp(*str, "dotlock") == 0)
			dotlock_got = TRUE;
		else if (strcasecmp(*str, "fcntl") == 0)
			fcntl_got = TRUE;
		else if (strcasecmp(*str, "flock") == 0)
			flock_got = TRUE;
		else
			i_fatal("mbox_locks: Invalid value %s", *str);
	}

#ifndef HAVE_FLOCK
	if (fcntl_got && !dotlock_got && !flock_got) {
		i_fatal("mbox_locks: Only flock selected, "
			"and flock() isn't supported in this system");
	}
	flock_got = FALSE;
#endif

	if (!dotlock_got && !fcntl_got && !flock_got)
		i_fatal("mbox_locks: No mbox locking methods selected");

	if (dotlock_got && !set->mbox_read_dotlock &&
	    !fcntl_got && !flock_got) {
		i_warning("mbox_locks: Only dotlock selected, forcing "
			  "mbox_read_dotlock = yes to avoid corruption.");
                set->mbox_read_dotlock = TRUE;
	}

	for (auth = set->auths; auth != NULL; auth = auth->next)
		auth_settings_verify(auth);
}

static void auth_settings_new(struct settings *set, const char *name)
{
	struct auth_settings *auth;

	auth = p_new(settings_pool, struct auth_settings, 1);
	auth->name = p_strdup(settings_pool, name);
	auth->executable = p_strdup(settings_pool,
				    PKG_LIBEXECDIR"/dovecot-auth");
	auth->count = 1;

	auth->next = set->auths;
        set->auths = auth;
}

static const char *parse_new_auth(struct settings *set, const char *name)
{
	struct auth_settings *auth;

	if (strchr(name, '/') != NULL)
		return "Authentication process name must not contain '/'";

	for (auth = set->auths; auth != NULL; auth = auth->next) {
		if (strcmp(auth->name, name) == 0) {
			return "Authentication process already exists "
				"with the same name";
		}
	}

	auth_settings_new(set, name);
	return NULL;
}

static void login_settings_new(struct settings *set, const char *name)
{
	struct login_settings *login;

	login = p_new(settings_pool, struct login_settings, 1);

	/* copy defaults */
	*login = set->logins != NULL ? *set->logins :
		default_login_settings;

	if (strcasecmp(name, "imap") == 0) {
		login->name = "imap";
		login->executable = PKG_LIBEXECDIR"/imap-login";
	} else if (strcasecmp(name, "pop3") == 0) {
		login->name = "pop3";
		login->executable = PKG_LIBEXECDIR"/pop3-login";
	} else {
		i_fatal("Unknown login process type '%s'", name);
	}

	login->next = set->logins;
	set->logins = login;
}

static const char *parse_new_login(struct settings *set, const char *name)
{
	struct login_settings *login;

	for (login = set->logins; login != NULL; login = login->next) {
		if (strcmp(login->name, name) == 0) {
			return "Login process already exists "
				"with the same name";
		}
	}

	login_settings_new(set, name);
	return NULL;
}

static const char *parse_setting(const char *key, const char *value,
				 void *context)
{
	struct settings *set = context;
	const char *error;

	/* check defaults first, there's a few login_ settings defined in it
	   which need to be checked before trying to feed it to login
	   handler.. */
	error = parse_setting_from_defs(settings_pool, setting_defs,
					set, key, value);
	if (error == NULL)
		return NULL;

	if (strcmp(key, "auth") == 0)
		return parse_new_auth(set, value);
	if (strncmp(key, "auth_", 5) == 0) {
		if (set->auths == NULL)
			return "Authentication process name not defined yet";

		return parse_setting_from_defs(settings_pool, auth_setting_defs,
					       set->auths, key + 5, value);
	}

	if (strcmp(key, "login") == 0)
		return parse_new_login(set, value);
	if (strncmp(key, "login_", 6) == 0) {
		if (set->logins == NULL)
			return "Login process name not defined yet";

		return parse_setting_from_defs(settings_pool,
					       login_setting_defs,
					       set->logins, key + 6, value);
	}

	return error;
}

void master_settings_read(const char *path)
{
	p_clear(settings_pool);
	set = p_new(settings_pool, struct settings, 1);
	*set = default_settings;

	settings_read(path, parse_setting, set);

        settings_verify(set);
}

void master_settings_init(void)
{
	settings_pool = pool_alloconly_create("settings", 1024);
}

void master_settings_deinit(void)
{
	pool_unref(settings_pool);
}
