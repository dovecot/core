/* Copyright (c) 2002-2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "array.h"
#include "str.h"
#include "istream.h"
#include "env-util.h"
#include "fd-close-on-exec.h"
#include "safe-mkdir.h"
#include "mkdir-parents.h"
#include "unlink-directory.h"
#include "syslog-util.h"
#include "mail-process.h"
#include "master-login-interface.h"
#include "settings-parser.h"

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <pwd.h>
#include <grp.h>
#ifdef HAVE_SYS_RESOURCE_H
#  include <sys/resource.h>
#endif

extern struct setting_parser_info master_auth_setting_parser_info;
extern struct setting_parser_info master_setting_parser_info;
extern struct setting_parser_info master_auth_socket_setting_parser_info;

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct master_auth_socket_unix_settings, name), NULL }

static struct setting_define master_auth_socket_master_setting_defines[] = {
	DEF(SET_STR, path),

	SETTING_DEFINE_LIST_END
};

static struct master_auth_socket_unix_settings master_auth_socket_master_default_settings = {
	MEMBER(path) "auth-master"
};

struct setting_parser_info master_auth_socket_master_setting_parser_info = {
	MEMBER(defines) master_auth_socket_master_setting_defines,
	MEMBER(defaults) &master_auth_socket_master_default_settings,

	MEMBER(parent) &master_auth_socket_setting_parser_info,
	MEMBER(dynamic_parsers) NULL,

	MEMBER(parent_offset) (size_t)-1,
	MEMBER(type_offset) (size_t)-1,
	MEMBER(struct_size) sizeof(struct master_auth_socket_unix_settings)
};

#undef DEF
#undef DEFLIST
#define DEF(type, name) \
	{ type, #name, offsetof(struct master_auth_socket_settings, name), NULL }
#define DEFLIST(field, name, defines) \
	{ SET_DEFLIST, name, offsetof(struct master_auth_socket_settings, field), defines }
static struct setting_define master_auth_socket_setting_defines[] = {
	DEF(SET_STR, type),
	DEFLIST(masters, "master", &master_auth_socket_master_setting_parser_info),

	SETTING_DEFINE_LIST_END
};

struct setting_parser_info master_auth_socket_setting_parser_info = {
	MEMBER(defines) master_auth_socket_setting_defines,
	MEMBER(defaults) NULL,

	MEMBER(parent) &master_auth_setting_parser_info,
	MEMBER(dynamic_parsers) NULL,

	MEMBER(parent_offset) (size_t)-1,
	MEMBER(type_offset) offsetof(struct master_auth_socket_settings, type),
	MEMBER(struct_size) sizeof(struct master_auth_socket_settings)
};

#undef DEF
#undef DEFLIST
#define DEF(type, name) \
	{ type, #name, offsetof(struct master_auth_settings, name), NULL }
#define DEFLIST(field, name, defines) \
	{ SET_DEFLIST, name, offsetof(struct master_auth_settings, field), defines }

static struct setting_define master_auth_setting_defines[] = {
	DEF(SET_STR, name),
	DEF(SET_STR, executable),
	DEF(SET_STR, user),
	DEF(SET_STR, chroot),
	DEF(SET_UINT, count),
	DEF(SET_UINT, process_size),
	DEF(SET_STR, mechanisms),
	DEF(SET_BOOL, debug),
	DEFLIST(sockets, "socket", &master_auth_socket_setting_parser_info),

	SETTING_DEFINE_LIST_END
};

static struct master_auth_settings master_auth_default_settings = {
	MEMBER(name) "default",
	MEMBER(executable) PKG_LIBEXECDIR"/dovecot-auth",
	MEMBER(user) "root",
	MEMBER(chroot) "",
	MEMBER(count) 1,
	MEMBER(process_size) 256,
	MEMBER(mechanisms) "plain",
	MEMBER(debug) FALSE

	/* .. */
};

struct setting_parser_info master_auth_setting_parser_info = {
	MEMBER(defines) master_auth_setting_defines,
	MEMBER(defaults) &master_auth_default_settings,

	MEMBER(parent) &master_setting_parser_info,
	MEMBER(dynamic_parsers) NULL,

	MEMBER(parent_offset) (size_t)-1,
	MEMBER(type_offset) offsetof(struct master_auth_settings, name),
	MEMBER(struct_size) sizeof(struct master_auth_settings)
};

#undef DEF
#undef DEFLIST
#define DEF(type, name) \
	{ type, #name, offsetof(struct master_settings, name), NULL }
#define DEFLIST(field, name, defines) \
	{ SET_DEFLIST, name, offsetof(struct master_settings, field), defines }

static struct setting_define master_setting_defines[] = {
	/* common */
	DEF(SET_STR, base_dir),
	DEF(SET_STR, log_path),
	DEF(SET_STR, info_log_path),
	DEF(SET_STR, log_timestamp),
	DEF(SET_STR, syslog_facility),

	/* general */
	DEF(SET_STR, protocols),
	DEF(SET_STR, listen),
	DEF(SET_STR, ssl_listen),

	DEF(SET_STR, ssl),
	DEF(SET_STR, ssl_key_file),
	DEF(SET_UINT, ssl_parameters_regenerate),
	DEF(SET_BOOL, version_ignore),

	/* login */
	DEF(SET_STR, login_dir),
	DEF(SET_STR, login_executable),
	DEF(SET_STR, login_user),

	DEF(SET_BOOL, login_process_per_connection),
	DEF(SET_BOOL, login_chroot),
	DEF(SET_BOOL, disable_plaintext_auth),

	DEF(SET_UINT, login_process_size),
	DEF(SET_UINT, login_processes_count),
	DEF(SET_UINT, login_max_processes_count),

	/* mail */
	DEF(SET_STR, valid_chroot_dirs),
	DEF(SET_STR, mail_chroot),
	DEF(SET_UINT, max_mail_processes),
	DEF(SET_UINT, mail_max_userip_connections),
	DEF(SET_BOOL, verbose_proctitle),

	DEF(SET_UINT, first_valid_uid),
	DEF(SET_UINT, last_valid_uid),
	DEF(SET_UINT, first_valid_gid),
	DEF(SET_UINT, last_valid_gid),
	DEF(SET_STR, mail_access_groups),
	DEF(SET_STR, mail_privileged_group),
	DEF(SET_STR, mail_uid),
	DEF(SET_STR, mail_gid),

	DEF(SET_STR, mail_plugins),
	DEF(SET_STR, imap_capability),

	DEF(SET_STR_VARS, mail_location),
	DEF(SET_BOOL, mail_debug),
	DEF(SET_BOOL, mail_drop_priv_before_exec),

	DEF(SET_STR, mail_executable),
	DEF(SET_UINT, mail_process_size),
	DEF(SET_STR, mail_log_prefix),
	DEF(SET_UINT, mail_log_max_lines_per_sec),

	/* dict */
	DEF(SET_UINT, dict_process_count),
	DEFLIST(auths, "auth", &master_auth_setting_parser_info),

	SETTING_DEFINE_LIST_END
};

struct master_settings master_default_settings = {
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

	MEMBER(ssl) "yes",
	MEMBER(ssl_key_file) SSLDIR"/private/dovecot.pem",
	MEMBER(ssl_parameters_regenerate) 168,
	MEMBER(version_ignore) FALSE,

	/* login */
	MEMBER(login_dir) "login",
	MEMBER(login_executable) NULL,
	MEMBER(login_user) "dovecot",

	MEMBER(login_process_per_connection) TRUE,
	MEMBER(login_chroot) TRUE,
	MEMBER(disable_plaintext_auth) TRUE,

	MEMBER(login_process_size) 64,
	MEMBER(login_processes_count) 3,
	MEMBER(login_max_processes_count) 128,

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
	MEMBER(mail_access_groups) "",
	MEMBER(mail_privileged_group) "",
	MEMBER(mail_uid) "",
	MEMBER(mail_gid) "",
	MEMBER(mail_plugins) "",
	MEMBER(imap_capability) "",

	MEMBER(mail_location) "",
	MEMBER(mail_debug) FALSE,
	MEMBER(maildir_very_dirty_syncs) FALSE,
	MEMBER(dbox_purge_min_percentage) 0,
	MEMBER(mail_drop_priv_before_exec) FALSE,

	MEMBER(mail_executable) NULL,
	MEMBER(mail_process_size) 256,
	MEMBER(mail_log_prefix) "%Us(%u): ",
	MEMBER(mail_log_max_lines_per_sec) 10,

	/* dict */
	MEMBER(dict_process_count) 1

	/* .. */
};

struct setting_parser_info master_setting_parser_info = {
	MEMBER(defines) master_setting_defines,
	MEMBER(defaults) &master_default_settings,

	MEMBER(parent) NULL,
	MEMBER(dynamic_parsers) NULL,

	MEMBER(parent_offset) (size_t)-1,
	MEMBER(type_offset) (size_t)-1,
	MEMBER(struct_size) sizeof(struct master_settings)
};

static pool_t settings_pool, settings2_pool;
struct master_server_settings *master_set = NULL;

#ifdef HAVE_MODULES
static const char *
get_process_capability(enum process_type ptype, struct master_settings *set)
{
	/* FIXME: pretty ugly code just for getting the capability
	   automatically */
	static const char *args[] = {
		"uid=65534",
		"gid=65534",
		"home=/tmp",
		NULL
	};
	const char *pname = process_names[ptype];
	enum master_login_status login_status;
	struct mail_login_request request;
	char buf[4096];
	int fd[2], status;
	ssize_t ret;
	unsigned int pos;
	uid_t uid;
	pid_t pid;

	uid = geteuid();
	if (uid != 0) {
		/* use the current user */
		args[0] = t_strdup_printf("uid=%s", dec2str(uid));
		args[1] = t_strdup_printf("gid=%s", dec2str(getegid()));
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd) < 0) {
		i_error("socketpair() failed: %m");
		return NULL;
	}
	fd_close_on_exec(fd[0], TRUE);
	fd_close_on_exec(fd[1], TRUE);

	memset(&request, 0, sizeof(request));
	request.fd = fd[1];
	login_status = create_mail_process(ptype, set, &request,
					   "dump-capability", args, NULL, TRUE,
					   &pid);
	if (login_status != MASTER_LOGIN_STATUS_OK) {
		(void)close(fd[0]);
		(void)close(fd[1]);
		return NULL;
	}
	(void)close(fd[1]);

	alarm(5);
	if (wait(&status) == -1) {
		i_fatal("%s dump-capability process %d got stuck",
			pname, (int)pid);
	}
	alarm(0);

	if (status != 0) {
		(void)close(fd[0]);
		if (WIFSIGNALED(status)) {
			i_error("%s dump-capability process "
				"killed with signal %d",
				pname, WTERMSIG(status));
		} else {
			i_error("%s dump-capability process returned %d",
				pname, WIFEXITED(status) ? WEXITSTATUS(status) :
				status);
		}
		return NULL;
	}

	pos = 0;
	while ((ret = read(fd[0], buf + pos, sizeof(buf) - pos)) > 0)
		pos += ret;

	if (ret < 0) {
		i_error("read(%s dump-capability process) failed: %m", pname);
		(void)close(fd[0]);
		return NULL;
	}
	(void)close(fd[0]);

	if (pos == 0 || buf[pos-1] != '\n') {
		i_error("%s dump-capability: Couldn't read capability "
			"(got %u bytes)", pname, pos);
		return NULL;
	}
	buf[pos-1] = '\0';

	return i_strdup(buf);
}

static bool get_imap_capability(struct master_settings *set)
{
	static const char *generated_capability = NULL;

	if (generated_capability != NULL) {
		/* Reloading configuration. Don't try to execute the imap
		   process again. Too risky and the wait() call below will
		   break it anyway. Just use the previous capability list we
		   already had generated. */
		set->imap_generated_capability =
			p_strdup(settings_pool, generated_capability);
		return TRUE;
	}

	generated_capability = get_process_capability(PROCESS_TYPE_IMAP, set);
	if (generated_capability == NULL)
		return FALSE;

	set->imap_generated_capability =
		p_strdup(settings_pool, generated_capability);
	return TRUE;
}
#endif

static void fix_base_path(struct master_settings *set, const char **str)
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

static bool get_login_uid(struct master_settings *set)
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

static bool auth_settings_verify(struct master_settings *set,
				 struct master_auth_settings *auth)
{
	struct passwd *pw;
	struct master_auth_socket_settings *const *sockets;
	unsigned int i, count;

	if ((pw = getpwnam(auth->user)) == NULL) {
		i_error("Auth user doesn't exist: %s", auth->user);
		return FALSE;
	}

	if (set->login_uid == pw->pw_uid && master_uid != pw->pw_uid) {
		i_error("login_user %s (uid %s) must not be same as auth_user",
			auth->user, dec2str(pw->pw_uid));
		return FALSE;
	}
	auth->uid = pw->pw_uid;
	auth->gid = pw->pw_gid;

	if (access(t_strcut(auth->executable, ' '), X_OK) < 0) {
		i_error("auth_executable: Can't use %s: %m",
			t_strcut(auth->executable, ' '));
		return FALSE;
	}

	fix_base_path(set, &auth->chroot);
	if (*auth->chroot != '\0' && access(auth->chroot, X_OK) < 0) {
		i_error("Can't access auth chroot directory %s: %m",
			auth->chroot);
		return FALSE;
	}

	if (array_is_created(&auth->sockets))
		sockets = array_get(&auth->sockets, &count);
	else {
		sockets = NULL;
		count = 0;
	}
	for (i = 0; i < count; i++) {
		if (auth->count > 1 &&
		    strcmp(sockets[i]->type, "listen") == 0) {
			i_error("Currently auth process count must be 1 if "
				"you're using auth socket listeners.");
			return FALSE;
		}
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

static bool settings_is_active(struct master_settings *set)
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

static bool settings_have_connect_sockets(struct master_settings *set)
{
	struct master_auth_settings *const *auths;
	struct master_auth_socket_settings *const *sockets;
	unsigned int i, count, count2;

	auths = array_get(&set->auths, &count);
	for (i = 0; i < count; i++) {
		if (!array_is_created(&auths[i]->sockets))
			continue;
		sockets = array_get(&auths[i]->sockets, &count2);
		if (count2 > 0 && strcmp(sockets[0]->type, "connect") == 0)
			return TRUE;
	}

	return FALSE;
}

static bool settings_have_nonplaintext_auths(struct master_settings *set)
{
	struct master_auth_settings *const *auths;
	const char *const *tmp;
	unsigned int i, count;

	auths = array_get(&set->auths, &count);
	for (i = 0; i < count; i++) {
		tmp = t_strsplit_spaces(auths[i]->mechanisms, " ");
		for (; *tmp != NULL; tmp++) {
			if (strcasecmp(*tmp, "PLAIN") != 0 &&
			    strcasecmp(*tmp, "LOGIN") != 0)
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

static bool settings_verify(struct master_settings *set)
{
	const char *dir;
	int facility;

	if (!get_login_uid(set))
		return FALSE;

	set->mail_uid_t = (uid_t)-1;
	set->mail_gid_t = (gid_t)-1;
	set->mail_priv_gid_t = (gid_t)-1;

	if (*set->mail_uid != '\0') {
		if (!parse_uid(set->mail_uid, &set->mail_uid_t)) {
			i_error("Non-existing mail_uid: %s", set->mail_uid);
			return FALSE;
		}
	}
	if (*set->mail_gid != '\0') {
		if (!parse_gid(set->mail_gid, &set->mail_gid_t)) {
			i_error("Non-existing mail_gid: %s", set->mail_uid);
			return FALSE;
		}
	}
	if (*set->mail_privileged_group != '\0') {
		if (!parse_gid(set->mail_privileged_group,
			       &set->mail_priv_gid_t)) {
			i_error("Non-existing mail_privileged_group: %s",
				set->mail_privileged_group);
			return FALSE;
		}
	}

	if (set->protocol != MAIL_PROTOCOL_ANY &&
	    access(t_strcut(set->mail_executable, ' '), X_OK) < 0) {
		i_error("mail_executable: Can't use %s: %m",
			t_strcut(set->mail_executable, ' '));
		return FALSE;
	}

	if (*set->log_path != '\0' && access(set->log_path, W_OK) < 0) {
		dir = get_directory(set->log_path);
		if (access(dir, W_OK) < 0) {
			i_error("log_path: Can't write to directory %s: %m",
				dir);
			return FALSE;
		}
	}

	if (*set->info_log_path != '\0' &&
	    access(set->info_log_path, W_OK) < 0) {
		dir = get_directory(set->info_log_path);
		if (access(dir, W_OK) < 0) {
			i_error("info_log_path: Can't write to directory %s: %m",
				dir);
			return FALSE;
		}
	}

	if (!syslog_facility_find(set->syslog_facility, &facility)) {
		i_error("syslog_facility: Unknown value: %s",
			set->syslog_facility);
		return FALSE;
	}

#ifndef HAVE_SSL
	if (strcmp(set->ssl, "no") != 0) {
		i_error("SSL support not compiled in but ssl=%s", set->ssl);
		return FALSE;
	}
#endif
	if (strcmp(set->ssl, "no") == 0 && set->disable_plaintext_auth &&
	    strncmp(set->listen, "127.", 4) != 0 &&
	    strcmp(set->protocols, "none") != 0 &&
	    !settings_have_nonplaintext_auths(set)) {
		i_warning("There is no way to login to this server: "
			  "disable_plaintext_auth=yes, ssl=no, "
			  "no non-plaintext auth mechanisms.");
	}

	if (set->max_mail_processes < 1) {
		i_error("max_mail_processes must be at least 1");
		return FALSE;
	}
	if (strcmp(set->login_dir, set->base_dir) == 0) {
		i_error("login_dir can't be the same as base_dir");
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
		i_error("login_executable: Can't use %s: %m",
			t_strcut(set->login_executable, ' '));
		return FALSE;
	}

	if (set->login_processes_count < 1) {
		i_error("login_processes_count must be at least 1");
		return FALSE;
	}

#ifndef HAVE_MODULES
	if (*set->mail_plugins != '\0') {
		i_error("mail_plugins: Plugin support wasn't built into Dovecot, "
			"can't load plugins: %s", set->mail_plugins);
		return FALSE;
	}
#endif
	return TRUE;
}

static bool login_want_core_dumps(struct master_server_settings *set)
{
	const char *p;

	p = set->pop3 == NULL ? NULL :
		strstr(set->pop3->login_executable, " -D");
	if (p != NULL && p[3] == '\0')
		return TRUE;
	p = set->imap == NULL ? NULL :
		strstr(set->imap->login_executable, " -D");
	if (p != NULL && p[3] == '\0')
		return TRUE;
	return FALSE;
}

static bool settings_do_fixes(struct master_settings *set)
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

	/* remove auth worker sockets left by unclean exits */
	unlink_auth_sockets(set->base_dir, "auth-worker.");

	/* Make sure our permanent state directory exists */
	if (mkdir_parents(PKG_STATEDIR, 0750) < 0 && errno != EEXIST) {
		i_error("mkdir(%s) failed: %m", PKG_STATEDIR);
		return FALSE;
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

static bool
settings_fix(struct master_settings *set, bool nochecks, bool nofixes)
{
	/* fix relative paths */
	fix_base_path(set, &set->login_dir);

	if (nochecks)
		return TRUE;
	if (!settings_verify(set))
		return FALSE;
	return nofixes ? TRUE : settings_do_fixes(set);
}

static void
settings_warn_needed_fds(struct master_server_settings *server ATTR_UNUSED)
{
#ifdef HAVE_SETRLIMIT
	struct rlimit rlim;
	unsigned int fd_count = 0;

	if (getrlimit(RLIMIT_NOFILE, &rlim) < 0)
		return;

	/* count only log pipes needed for login and mail processes. we need
	   more, but they're the ones that can use up most of the fds */
	if (server->imap != NULL)
		fd_count += server->imap->login_max_processes_count;
	if (server->pop3 != NULL)
		fd_count += server->pop3->login_max_processes_count;
	fd_count += server->defaults->max_mail_processes;

	if (rlim.rlim_cur < fd_count) {
		i_warning("fd limit %d is lower than what Dovecot can use under "
			  "full load (more than %u). Either grow the limit or "
			  "change login_max_processes_count and "
			  "max_mail_processes master_settings",
			  (int)rlim.rlim_cur, fd_count);
	}
#endif
}

static void
config_split_all_settings(struct master_settings *set, const char *input)
{
	const char *p, *line;
	string_t *str;

	str = t_str_new(256);
	p_array_init(&set->all_settings, settings_pool, 256);
	for (p = input; *p != '\n'; p++) {
		str_truncate(str, 0);
		for (; *p != '='; p++) {
			i_assert(*p != '\n' && *p != '\0');
			str_append_c(str, i_toupper(*p));
		}
		for (; *p != '\n'; p++) {
			i_assert(*p != '\0');
			str_append_c(str, *p);
		}
		line = p_strdup(settings_pool, str_c(str));
		array_append(&set->all_settings, &line, 1);
	}
}

static int config_exec(const char *path, const char *service,
		       struct master_settings **set_r)
{
	struct setting_parser_context *parser;
	string_t *all_settings;
	int ret;

	env_put("LOG_TO_MASTER=1");

	all_settings = str_new(default_pool, 10240);
	parser = settings_parser_init(settings_pool,
				      &master_setting_parser_info,
				      SETTINGS_PARSER_FLAG_IGNORE_UNKNOWN_KEYS);
	settings_parse_save_input(parser, all_settings);
	if ((ret = settings_parse_exec(parser, DOVECOT_CONFIG_BIN_PATH,
				       path, service)) == 0) {
		*set_r = settings_parser_get(parser);
		config_split_all_settings(*set_r, str_c(all_settings));
	}
	settings_parser_deinit(&parser);
	str_free(&all_settings);
	return ret;
}

int master_settings_read(const char *path,
			 struct master_server_settings **set_r)
{
	struct master_server_settings *set;

	p_clear(settings_pool);
	set = p_new(settings_pool, struct master_server_settings, 1);

	master_default_settings.mail_executable = NULL;
	master_default_settings.login_executable = NULL;
	if (config_exec(path, "", &set->defaults) < 0)
		return -1;
	set->defaults->protocol = MAIL_PROTOCOL_ANY;
	set->defaults->server = set;

	master_default_settings.mail_executable = PKG_LIBEXECDIR"/imap";
	master_default_settings.login_executable = PKG_LIBEXECDIR"/imap-login";
	if (config_exec(path, "imap", &set->imap) < 0)
		return -1;
	set->imap->protocol = MAIL_PROTOCOL_IMAP;
	set->imap->server = set;

	master_default_settings.mail_executable = PKG_LIBEXECDIR"/pop3";
	master_default_settings.login_executable = PKG_LIBEXECDIR"/pop3-login";
	if (config_exec(path, "pop3", &set->pop3) < 0)
		return -1;
	set->pop3->protocol = MAIL_PROTOCOL_POP3;
	set->pop3->server = set;

	*set_r = set;
	return 0;
}

static void settings_verify_master(struct master_server_settings *set)
{
	if (!settings_have_connect_sockets(set->defaults)) {
		/* we are not using external authentication, so make sure the
		   login directory exists with correct permissions and it's
		   empty. with external auth we wouldn't want to delete
		   existing sockets or break the permissions required by the
		   auth server. */
		mode_t mode = login_want_core_dumps(set) ? 0770 : 0750;
		if (safe_mkdir(set->defaults->login_dir, mode,
			       master_uid, set->login_gid) == 0) {
			i_warning("Corrected permissions for login directory "
				  "%s", set->defaults->login_dir);
		}

		unlink_auth_sockets(set->defaults->login_dir, "");
	}
}

bool master_settings_check(struct master_server_settings *set,
			   bool nochecks, bool nofixes)
{
	struct master_auth_settings *const *auths;
	unsigned int i, count;
	pool_t temp;

	if ((*set->imap->protocols == '\0' ||
	     *set->pop3->protocols == '\0') && !nochecks) {
		i_error("protocols: No protocols given in configuration file");
		return FALSE;
	}
	/* --exec-mail is used if nochecks=TRUE. Allow it regardless
	   of what's in protocols setting. */
	if (!settings_is_active(set->imap) && !nochecks) {
		if (strcmp(set->imap->protocols, "none") == 0) {
			set->imap->protocol = MAIL_PROTOCOL_ANY;
			if (!settings_fix(set->imap, nochecks, nofixes))
				return FALSE;
		}
		set->imap = NULL;
	} else {
		if (!settings_fix(set->imap, nochecks, nofixes))
			return FALSE;
	}

	if (!settings_is_active(set->pop3) && !nochecks)
		set->pop3 = NULL;
	else {
		if (!settings_fix(set->pop3, nochecks, nofixes))
			return FALSE;
	}

	if (!settings_fix(set->defaults, nochecks, nofixes))
		return FALSE;

	if (!nofixes) {
		settings_verify_master(set);
		auths = array_get(&set->defaults->auths, &count);
		if (count == 0) {
			i_error("Missing auth section");
			return FALSE;
		}

		for (i = 0; i < count; i++) {
			if (!auth_settings_verify(set->defaults, auths[i]))
				return FALSE;
		}
	}

	if (!nochecks)
		settings_warn_needed_fds(set);

	/* settings ok, swap them */
	temp = settings_pool;
	settings_pool = settings2_pool;
	settings2_pool = temp;

	master_set = set;
	return TRUE;
}

void master_settings_export_to_env(const struct master_settings *set)
{
	const char *const *sets;
	unsigned int i, count;

	sets = array_get(&set->all_settings, &count);
	for (i = 0; i < count; i++)
		env_put(sets[i]);
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
