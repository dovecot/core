/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ibuffer.h"
#include "settings.h"

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/stat.h>

typedef enum {
	SET_STR,
	SET_INT,
	SET_BOOL
} SettingType;

typedef struct {
	const char *name;
	SettingType type;
	void *ptr;
} Setting;

static Setting settings[] = {
	{ "log_path",		SET_STR, &set_log_path },
	{ "log_timestamp",	SET_STR, &set_log_timestamp },

	{ "imap_port",		SET_INT, &set_imap_port },
	{ "imaps_port",		SET_INT, &set_imaps_port },
	{ "imap_listen",	SET_STR, &set_imap_listen },
	{ "imaps_listen",	SET_STR, &set_imaps_listen },
	{ "ssl_cert_file",	SET_STR, &set_ssl_cert_file },
	{ "ssl_key_file",	SET_STR, &set_ssl_key_file },
	{ "ssl_parameters_file",SET_STR, &set_ssl_parameters_file },
	{ "ssl_parameters_regenerate",
				SET_INT, &set_ssl_parameters_regenerate },
	{ "disable_plaintext_auth",
				SET_BOOL,&set_disable_plaintext_auth },

	{ "login_executable",	SET_STR, &set_login_executable },
	{ "login_user",		SET_STR, &set_login_user },
	{ "login_dir",		SET_STR, &set_login_dir },
	{ "login_chroot",	SET_BOOL,&set_login_chroot },
	{ "login_process_per_connection",
				SET_BOOL,&set_login_process_per_connection },
	{ "login_processes_count",
				SET_INT, &set_login_processes_count },
	{ "max_logging_users",	SET_INT, &set_max_logging_users },

	{ "imap_executable",	SET_STR, &set_imap_executable },
	{ "valid_chroot_dirs",	SET_STR, &set_valid_chroot_dirs },
	{ "max_imap_processes",	SET_INT, &set_max_imap_processes },
	{ "verbose_proctitle",	SET_BOOL,&set_verbose_proctitle },
	{ "first_valid_uid",	SET_INT, &set_first_valid_uid },
	{ "last_valid_uid",	SET_INT, &set_last_valid_uid },
	{ "first_valid_gid",	SET_INT, &set_first_valid_gid },
	{ "last_valid_gid",	SET_INT, &set_last_valid_gid },
	{ "mail_cache_fields",	SET_STR, &set_mail_cache_fields },
	{ "mail_never_cache_fields",
				SET_STR, &set_mail_never_cache_fields },
	{ "mailbox_check_interval",
				SET_INT, &set_mailbox_check_interval },
	{ "mail_save_crlf",	SET_BOOL,&set_mail_save_crlf },
	{ "maildir_copy_with_hardlinks",
				SET_BOOL,&set_maildir_copy_with_hardlinks },
	{ "maildir_check_content_changes",
				SET_BOOL,&set_maildir_check_content_changes },
	{ "mbox_locks",		SET_STR, &set_mbox_locks, },
	{ "mbox_read_dotlock",	SET_BOOL,&set_mbox_read_dotlock, },
	{ "mbox_lock_timeout",	SET_INT, &set_mbox_lock_timeout, },
	{ "mbox_dotlock_change_timeout",
				SET_INT, &set_mbox_dotlock_change_timeout, },
	{ "overwrite_incompatible_index",
				SET_BOOL,&set_overwrite_incompatible_index },
	{ "umask",		SET_INT, &set_umask },

	{ NULL, 0, NULL }
};

/* common */
char *set_log_path = NULL;
char *set_log_timestamp = DEFAULT_FAILURE_STAMP_FORMAT;

/* general */
unsigned int set_imap_port = 143;
unsigned int set_imaps_port = 993;
char *set_imap_listen = NULL;
char *set_imaps_listen = NULL;

char *set_ssl_cert_file = "/etc/ssl/certs/imapd.pem";
char *set_ssl_key_file = "/etc/ssl/private/imapd.pem";
char *set_ssl_parameters_file = PKG_RUNDIR"/ssl-parameters.dat";
unsigned int set_ssl_parameters_regenerate = 24;
int set_disable_plaintext_auth = FALSE;

/* login */
char *set_login_executable = PKG_LIBDIR "/imap-login";
char *set_login_user = "imapd";
char *set_login_dir = PKG_RUNDIR"/login";

int set_login_chroot = TRUE;
int set_login_process_per_connection = TRUE;
unsigned int set_login_processes_count = 3;
unsigned int set_login_max_processes_count = 128;
unsigned int set_max_logging_users = 256;

uid_t set_login_uid; /* generated from set_login_user */
gid_t set_login_gid; /* generated from set_login_user */

/* imap */
char *set_imap_executable = PKG_LIBDIR "/imap";
char *set_valid_chroot_dirs = NULL;
unsigned int set_max_imap_processes = 1024;
int set_verbose_proctitle = FALSE;

unsigned int set_first_valid_uid = 500, set_last_valid_uid = 0;
unsigned int set_first_valid_gid = 1, set_last_valid_gid = 0;

char *set_mail_cache_fields = "MessagePart";
char *set_mail_never_cache_fields = NULL;
unsigned int set_mailbox_check_interval = 30;
int set_mail_save_crlf = FALSE;
int set_maildir_copy_with_hardlinks = FALSE;
int set_maildir_check_content_changes = FALSE;
char *set_mbox_locks = "dotlock fcntl flock";
int set_mbox_read_dotlock = FALSE;
unsigned int set_mbox_lock_timeout = 300;
unsigned int set_mbox_dotlock_change_timeout = 30;
int set_overwrite_incompatible_index = FALSE;
unsigned int set_umask = 0077;

/* auth */
AuthConfig *auth_processes_config = NULL;

static void get_login_uid(void)
{
	struct passwd *pw;

	if ((pw = getpwnam(set_login_user)) == NULL)
		i_fatal("Login user doesn't exist: %s", set_login_user);

	set_login_uid = pw->pw_uid;
	set_login_gid = pw->pw_gid;
}

static void auth_settings_verify(void)
{
	AuthConfig *auth;

	for (auth = auth_processes_config; auth != NULL; auth = auth->next) {
		if (access(auth->executable, X_OK) < 0) {
			i_fatal("Can't use auth executable %s: %m",
				auth->executable);
		}
		if (auth->chroot != NULL && *auth->chroot != '\0' &&
		    access(auth->chroot, X_OK) < 0) {
			i_fatal("Can't access auth chroot directory %s: %m",
				auth->chroot);
		}
	}
}

static void settings_verify(void)
{
	char *const *str;
	int dotlock_got, fcntl_got, flock_got;

	get_login_uid();

	if (access(set_login_executable, X_OK) < 0) {
		i_fatal("Can't use login executable %s: %m",
			set_login_executable);
	}

	if (access(set_imap_executable, X_OK) < 0) {
		i_fatal("Can't use imap executable %s: %m",
			set_imap_executable);
	}

	/* since they're under /var/run by default, they may have been
	   deleted */
	(void)mkdir(PKG_RUNDIR, 0700);
	if (mkdir(set_login_dir, 0700) == 0)
		(void)chown(set_login_dir, set_login_uid, set_login_gid);
	if (access(set_login_dir, X_OK) < 0)
		i_fatal("Can't access login directory %s: %m", set_login_dir);

	if (set_max_imap_processes < 1)
		i_fatal("max_imap_processes must be at least 1");
	if (set_login_processes_count < 1)
		i_fatal("login_processes_count must be at least 1");
	if (set_max_logging_users < 1)
		i_fatal("max_logging_users must be at least 1");

	if (set_last_valid_uid != 0 &&
	    set_first_valid_uid > set_last_valid_uid)
		i_fatal("first_valid_uid can't be larger than last_valid_uid");
	if (set_last_valid_gid != 0 &&
	    set_first_valid_gid > set_last_valid_gid)
		i_fatal("first_valid_gid can't be larger than last_valid_gid");

	dotlock_got = fcntl_got = flock_got = FALSE;
	for (str = t_strsplit(set_mbox_locks, " "); *str != NULL; str++) {
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

	if (dotlock_got && !set_mbox_read_dotlock && !fcntl_got && !flock_got) {
		i_warning("mbox_locks: Only dotlock selected, forcing "
			  "mbox_read_dotlock = yes to avoid corruption.");
                set_mbox_read_dotlock = TRUE;
	}

	auth_settings_verify();
}

static AuthConfig *auth_config_new(const char *name)
{
	AuthConfig *auth;

	auth = i_new(AuthConfig, 1);
	auth->name = i_strdup(name);
	auth->executable = i_strdup(PKG_LIBDIR "/imap-auth");
	auth->count = 1;

	auth->next = auth_processes_config;
        auth_processes_config = auth;
	return auth;
}

static void auth_config_free(AuthConfig *auth)
{
	i_free(auth->name);
	i_free(auth->methods);
	i_free(auth->realms);
	i_free(auth->userinfo);
	i_free(auth->userinfo_args);
	i_free(auth->executable);
	i_free(auth->user);
	i_free(auth->chroot);
	i_free(auth);
}

static const char *parse_new_auth(const char *name)
{
	AuthConfig *auth;

	if (strchr(name, '/') != NULL)
		return "Authentication process name must not contain '/'";

	for (auth = auth_processes_config; auth != NULL; auth = auth->next) {
		if (strcmp(auth->name, name) == 0) {
			return "Authentication process already exists "
				"with the same name";
		}
	}

	(void)auth_config_new(name);
	return NULL;
}

static const char *parse_auth(const char *key, const char *value)
{
	AuthConfig *auth = auth_processes_config;
	const char *p;
	char **ptr;

	if (auth == NULL)
		return "Authentication process name not defined yet";

	/* check the easy string values first */
	if (strcmp(key, "auth_methods") == 0)
		ptr = &auth->methods;
	else if (strcmp(key, "auth_realms") == 0)
		ptr = &auth->realms;
	else if (strcmp(key, "auth_executable") == 0)
		ptr = &auth->executable;
	else if (strcmp(key, "auth_user") == 0)
		ptr = &auth->user;
	else if (strcmp(key, "auth_chroot") == 0)
		ptr = &auth->chroot;
	else
		ptr = NULL;

	if (ptr != NULL) {
		i_strdup_replace(ptr, value);
		return NULL;
	}

	if (strcmp(key, "auth_userinfo") == 0) {
		/* split it into userinfo + userinfo_args */
		for (p = value; *p != ' ' && *p != '\0'; )
			p++;

		i_free(auth->userinfo);
		auth->userinfo = i_strdup_until(value, p);

		while (*p == ' ') p++;

		i_free(auth->userinfo_args);
		auth->userinfo_args = i_strdup(p);
		return NULL;
	}

	if (strcmp(key, "auth_count") == 0) {
		if (!sscanf(value, "%i", &auth->count))
			return t_strconcat("Invalid number: ", value, NULL);
		return NULL;
	}


	return t_strconcat("Unknown setting: ", key, NULL);
}

static const char *parse_setting(const char *key, const char *value)
{
	Setting *set;

	if (strcmp(key, "auth") == 0)
		return parse_new_auth(value);
	if (strncmp(key, "auth_", 5) == 0)
		return parse_auth(key, value);

	for (set = settings; set->name != NULL; set++) {
		if (strcmp(set->name, key) == 0) {
			switch (set->type) {
			case SET_STR:
				i_strdup_replace((char **) set->ptr, value);
				break;
			case SET_INT:
				/* use %i so we can handle eg. 0600
				   as octal value with umasks */
				if (!sscanf(value, "%i", (int *) set->ptr))
					return t_strconcat("Invalid number: ",
							   value, NULL);
				break;
			case SET_BOOL:
				if (strcasecmp(value, "yes") == 0)
					*((int *) set->ptr) = TRUE;
				else if (strcasecmp(value, "no") == 0)
					*((int *) set->ptr) = FALSE;
				else
					return t_strconcat("Invalid boolean: ",
							   value, NULL);
				break;
			}
			return NULL;
		}
	}

	return t_strconcat("Unknown setting: ", key, NULL);
}

static void settings_free(void)
{
	while (auth_processes_config != NULL) {
		AuthConfig *auth = auth_processes_config;

		auth_processes_config = auth->next;
                auth_config_free(auth);
	}
}

#define IS_WHITE(c) ((c) == ' ' || (c) == '\t')

void settings_read(const char *path)
{
	IBuffer *inbuf;
	const char *errormsg;
	char *line, *key, *p;
	int fd, linenum;

	settings_free();

	fd = open(path, O_RDONLY);
	if (fd < 0)
		i_fatal("Can't open configuration file %s: %m", path);

	linenum = 0;
	inbuf = i_buffer_create_file(fd, default_pool, 2048, TRUE);
	for (;;) {
		line = i_buffer_next_line(inbuf);
		if (line == NULL) {
			if (i_buffer_read(inbuf) <= 0)
				break;
                        continue;
		}
		linenum++;

		/* skip whitespace */
		while (IS_WHITE(*line))
			line++;

		/* ignore comments or empty lines */
		if (*line == '#' || *line == '\0')
			continue;

		/* all lines must be in format "key = value" */
		key = line;
		while (!IS_WHITE(*line) && *line != '\0')
			line++;
		if (IS_WHITE(*line)) {
			*line++ = '\0';
			while (IS_WHITE(*line)) line++;
		}

		if (*line != '=') {
			errormsg = "Missing value";
		} else {
			/* skip whitespace after '=' */
			*line++ = '\0';
			while (IS_WHITE(*line)) line++;

			/* skip trailing whitespace */
			p = line + strlen(line);
			while (p > line && IS_WHITE(p[-1]))
				p--;
			*p = '\0';

			errormsg = parse_setting(key, line);
		}

		if (errormsg != NULL) {
			i_fatal("Error in configuration file %s line %d: %s",
				path, linenum, errormsg);
		}
	};

	i_buffer_unref(inbuf);

        settings_verify();
}

void settings_init(void)
{
	Setting *set;

	/* strdup() all default settings */
	for (set = settings; set->name != NULL; set++) {
		if (set->type == SET_STR) {
			char **str = set->ptr;
			*str = i_strdup(*str);
		}
	}
}
