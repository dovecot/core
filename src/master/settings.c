/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "iobuffer.h"
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

	{ "login_executable",	SET_STR, &set_login_executable },
	{ "login_user",		SET_STR, &set_login_user },
	{ "login_dir",		SET_STR, &set_login_dir },
	{ "login_chroot",	SET_BOOL,&set_login_chroot },
	{ "login_processes_count", SET_INT, &set_login_processes_count },

	{ "max_logging_users",	SET_INT, &set_max_logging_users },
	{ "imap_executable",	SET_STR, &set_imap_executable },
	{ "valid_chroot_dirs",	SET_STR, &set_valid_chroot_dirs },
	{ "max_imap_processes",	SET_INT, &set_max_imap_processes },
	{ "imap_listen",	SET_STR, &set_imap_listen },
	{ "imaps_listen",	SET_STR, &set_imaps_listen },
	{ "imap_port",		SET_INT, &set_imap_port },
	{ "imaps_port",		SET_INT, &set_imaps_port },
	{ "ssl_cert_file",	SET_STR, &set_ssl_cert_file },
	{ "ssl_key_file",	SET_STR, &set_ssl_key_file },
	{ "disable_plaintext_auth",
				SET_BOOL,&set_disable_plaintext_auth },
	{ "first_valid_uid",	SET_INT, &set_first_valid_uid },
	{ "last_valid_uid",	SET_INT, &set_last_valid_uid },
	{ "first_valid_gid",	SET_INT, &set_first_valid_gid },
	{ "last_valid_gid",	SET_INT, &set_last_valid_gid },
	{ "maildir_copy_with_hardlinks",
				SET_BOOL,&set_maildir_copy_with_hardlinks },
	{ "maildir_check_content_changes",
				SET_BOOL,&set_maildir_check_content_changes },
	{ "overwrite_incompatible_index",
				SET_BOOL,&set_overwrite_incompatible_index },
	{ "umask",		SET_INT, &set_umask },

	{ NULL, 0, NULL }
};

/* common */
char *set_log_path = NULL;
char *set_log_timestamp = DEFAULT_FAILURE_STAMP_FORMAT;

/* login */
char *set_login_executable = PKG_LIBDIR "/imap-login";
char *set_login_user = "imapd";
char *set_login_dir = PKG_RUNDIR;

int set_login_chroot = TRUE;
unsigned int set_login_processes_count = 1;
unsigned int set_max_logging_users = 256;

uid_t set_login_uid; /* generated from set_login_user */
gid_t set_login_gid; /* generated from set_login_user */

/* imap */
char *set_imap_executable = PKG_LIBDIR "/imap";
char *set_valid_chroot_dirs = NULL;
unsigned int set_max_imap_processes = 1024;

char *set_imap_listen = NULL;
char *set_imaps_listen = NULL;
unsigned int set_imap_port = 143;
unsigned int set_imaps_port = 993;

char *set_ssl_cert_file = NULL;
char *set_ssl_key_file = NULL;
int set_disable_plaintext_auth = FALSE;

unsigned int set_first_valid_uid = 500, set_last_valid_uid = 0;
unsigned int set_first_valid_gid = 1, set_last_valid_gid = 0;

int set_maildir_copy_with_hardlinks = FALSE;
int set_maildir_check_content_changes = FALSE;
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

static void settings_initialize(void)
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

static void settings_verify(void)
{
	get_login_uid();

	if (access(set_login_executable, X_OK) == -1) {
		i_fatal("Can't use login executable %s: %m",
			set_login_executable);
	}

	if (access(set_imap_executable, X_OK) == -1) {
		i_fatal("Can't use imap executable %s: %m",
			set_imap_executable);
	}

	/* since it's under /var/run by default, it may have been deleted */
	if (mkdir(set_login_dir, 0700) == 0)
		(void)chown(set_login_dir, set_login_uid, set_login_gid);
	if (access(set_login_dir, X_OK) == -1)
		i_fatal("Can't access login directory %s: %m", set_login_dir);

	if (set_login_processes_count < 1)
		i_fatal("login_processes_count must be at least 1");
	if (set_first_valid_uid < set_last_valid_uid)
		i_fatal("first_valid_uid can't be larger than last_valid_uid");
	if (set_first_valid_gid < set_last_valid_gid)
		i_fatal("first_valid_gid can't be larger than last_valid_gid");
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

static const char *parse_new_auth(const char *name)
{
	AuthConfig *auth;

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

#define IS_WHITE(c) ((c) == ' ' || (c) == '\t')

void settings_read(const char *path)
{
	IOBuffer *inbuf;
	const char *errormsg;
	char *line, *key, *p;
	int fd, linenum;

        settings_initialize();

	fd = open(path, O_RDONLY);
	if (fd == -1)
		i_fatal("Can't open configuration file %s: %m", path);

	linenum = 0;
	inbuf = io_buffer_create_file(fd, default_pool, 2048);
	for (;;) {
		line = io_buffer_next_line(inbuf);
		if (line == NULL) {
			if (io_buffer_read(inbuf) <= 0)
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

	io_buffer_destroy(inbuf);
	(void)close(fd);

        settings_verify();
}
