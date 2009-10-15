/* Copyright (c) 2005-2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "array.h"
#include "env-util.h"
#include "istream.h"
#include "str.h"
#include "mkdir-parents.h"
#include "safe-mkdir.h"
#include "settings-parser.h"
#include "master-settings.h"

#include <stddef.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

static bool master_settings_verify(void *_set, pool_t pool,
				   const char **error_r);

extern struct setting_parser_info service_setting_parser_info;

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct file_listener_settings, name), NULL }

static struct setting_define file_listener_setting_defines[] = {
	DEF(SET_STR, path),
	DEF(SET_UINT, mode),
	DEF(SET_STR, user),
	DEF(SET_STR, group),

	SETTING_DEFINE_LIST_END
};

static struct file_listener_settings file_listener_default_settings = {
	MEMBER(path) "",
	MEMBER(mode) 0600,
	MEMBER(user) "",
	MEMBER(group) "",
};

static struct setting_parser_info file_listener_setting_parser_info = {
	MEMBER(defines) file_listener_setting_defines,
	MEMBER(defaults) &file_listener_default_settings,

	MEMBER(parent) &service_setting_parser_info,
	MEMBER(parent_offset) (size_t)-1,
	MEMBER(type_offset) (size_t)-1,
	MEMBER(struct_size) sizeof(struct file_listener_settings)
};

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct inet_listener_settings, name), NULL }

static struct setting_define inet_listener_setting_defines[] = {
	DEF(SET_STR, address),
	DEF(SET_UINT, port),
	DEF(SET_BOOL, ssl),

	SETTING_DEFINE_LIST_END
};

static struct inet_listener_settings inet_listener_default_settings = {
	MEMBER(address) "",
	MEMBER(port) 0,
	MEMBER(ssl) FALSE
};

static struct setting_parser_info inet_listener_setting_parser_info = {
	MEMBER(defines) inet_listener_setting_defines,
	MEMBER(defaults) &inet_listener_default_settings,

	MEMBER(parent) &service_setting_parser_info,
	MEMBER(parent_offset) (size_t)-1,
	MEMBER(type_offset) (size_t)-1,
	MEMBER(struct_size) sizeof(struct inet_listener_settings)
};

#undef DEF
#undef DEFLIST
#define DEF(type, name) \
	{ type, #name, offsetof(struct service_settings, name), NULL }
#define DEFLIST(field, name, defines) \
	{ SET_DEFLIST, name, offsetof(struct service_settings, field), defines }

static struct setting_define service_setting_defines[] = {
	DEF(SET_STR, name),
	DEF(SET_STR, protocol),
	DEF(SET_STR, type),
	DEF(SET_STR, executable),
	DEF(SET_STR, user),
	DEF(SET_STR, group),
	DEF(SET_STR, privileged_group),
	DEF(SET_STR, extra_groups),
	DEF(SET_STR, chroot),
	DEF(SET_STR, auth_dest_service),

	DEF(SET_BOOL, drop_priv_before_exec),

	DEF(SET_UINT, process_min_avail),
	DEF(SET_UINT, process_limit),
	DEF(SET_UINT, client_limit),
	DEF(SET_UINT, service_count),
	DEF(SET_UINT, vsz_limit),

	DEFLIST(unix_listeners, "unix_listener",
		&file_listener_setting_parser_info),
	DEFLIST(fifo_listeners, "fifo_listener",
		&file_listener_setting_parser_info),
	DEFLIST(inet_listeners, "inet_listener",
		&inet_listener_setting_parser_info),

	SETTING_DEFINE_LIST_END
};

static struct service_settings service_default_settings = {
	MEMBER(master_set) NULL,

	MEMBER(name) "",
	MEMBER(protocol) "",
	MEMBER(type) "",
	MEMBER(executable) "",
	MEMBER(user) "",
	MEMBER(group) "",
	MEMBER(privileged_group) "",
	MEMBER(extra_groups) "",
	MEMBER(chroot) "",
	MEMBER(auth_dest_service) "",

	MEMBER(drop_priv_before_exec) FALSE,

	MEMBER(process_min_avail) 0,
	MEMBER(process_limit) (unsigned int)-1,
	MEMBER(client_limit) 0,
	MEMBER(service_count) 0,
	MEMBER(vsz_limit) 256,

	MEMBER(unix_listeners) ARRAY_INIT,
	MEMBER(fifo_listeners) ARRAY_INIT,
	MEMBER(inet_listeners) ARRAY_INIT
};

struct setting_parser_info service_setting_parser_info = {
	MEMBER(defines) service_setting_defines,
	MEMBER(defaults) &service_default_settings,

	MEMBER(parent) &master_setting_parser_info,
	MEMBER(dynamic_parsers) NULL,

	MEMBER(parent_offset) offsetof(struct service_settings, master_set),
	MEMBER(type_offset) offsetof(struct service_settings, name),
	MEMBER(struct_size) sizeof(struct service_settings)
};

#undef DEF
#undef DEFLIST
#define DEF(type, name) \
	{ type, #name, offsetof(struct master_settings, name), NULL }
#define DEFLIST(field, name, defines) \
	{ SET_DEFLIST, name, offsetof(struct master_settings, field), defines }

static struct setting_define master_setting_defines[] = {
	DEF(SET_STR, base_dir),
	DEF(SET_STR, libexec_dir),
	DEF(SET_STR, protocols),
	DEF(SET_STR, listen),
	DEF(SET_ENUM, ssl),
	DEF(SET_UINT, default_process_limit),
	DEF(SET_UINT, default_client_limit),
	DEF(SET_UINT, default_vsz_limit),

	DEF(SET_BOOL, version_ignore),
	DEF(SET_BOOL, mail_debug),
	DEF(SET_BOOL, auth_debug),
	DEF(SET_BOOL, verbose_proctitle),

	DEF(SET_UINT, first_valid_uid),
	DEF(SET_UINT, last_valid_uid),
	DEF(SET_UINT, first_valid_gid),
	DEF(SET_UINT, last_valid_gid),

	DEFLIST(services, "service", &service_setting_parser_info),

	SETTING_DEFINE_LIST_END
};

static struct master_settings master_default_settings = {
	MEMBER(base_dir) PKG_RUNDIR,
	MEMBER(libexec_dir) PKG_LIBEXECDIR,
	MEMBER(protocols) "imap pop3 lmtp",
	MEMBER(listen) "*, ::",
	MEMBER(ssl) "yes:no:required",
	MEMBER(default_process_limit) 100,
	MEMBER(default_client_limit) 1000,
	MEMBER(default_vsz_limit) 256,

	MEMBER(version_ignore) FALSE,
	MEMBER(mail_debug) FALSE,
	MEMBER(auth_debug) FALSE,
	MEMBER(verbose_proctitle) FALSE,

	MEMBER(first_valid_uid) 500,
	MEMBER(last_valid_uid) 0,
	MEMBER(first_valid_gid) 1,
	MEMBER(last_valid_gid) 0,

	MEMBER(services) ARRAY_INIT
};

struct setting_parser_info master_setting_parser_info = {
	MEMBER(defines) master_setting_defines,
	MEMBER(defaults) &master_default_settings,

	MEMBER(parent) NULL,
	MEMBER(parent_offset) (size_t)-1,
	MEMBER(type_offset) (size_t)-1,
	MEMBER(struct_size) sizeof(struct master_settings),
	MEMBER(check_func) master_settings_verify
};

/* <settings checks> */
static void fix_file_listener_paths(ARRAY_TYPE(file_listener_settings) *l,
				    pool_t pool, const char *base_dir)
{
	struct file_listener_settings *const *sets;
	unsigned int i, count;

	if (!array_is_created(l))
		return;

	sets = array_get(l, &count);
	for (i = 0; i < count; i++) {
		if (*sets[i]->path != '/') {
			sets[i]->path = p_strconcat(pool, base_dir, "/",
						    sets[i]->path, NULL);
		}
	}
}

static bool
master_settings_verify(void *_set, pool_t pool, const char **error_r)
{
	struct master_settings *set = _set;
	struct service_settings *const *services;
	unsigned int i, j, count;

	if (set->last_valid_uid != 0 &&
	    set->first_valid_uid > set->last_valid_uid) {
		*error_r = "first_valid_uid can't be larger than last_valid_uid";
		return FALSE;
	}
	if (set->last_valid_gid != 0 &&
	    set->first_valid_gid > set->last_valid_gid) {
		*error_r = "first_valid_gid can't be larger than last_valid_gid";
		return FALSE;
	}

	/* check that we have at least one service. the actual service
	   structure validity is checked later while creating them. */
	if (!array_is_created(&set->services) ||
	    array_count(&set->services) == 0) {
		*error_r = "No services defined";
		return FALSE;
	}
	services = array_get(&set->services, &count);
	for (i = 0; i < count; i++) {
		struct service_settings *service = services[i];

		if (*service->name == '\0') {
			*error_r = t_strdup_printf(
				"Service #%d is missing name", i);
			return FALSE;
		}
		if (*service->type != '\0' &&
		    strcmp(service->type, "log") != 0 &&
		    strcmp(service->type, "config") != 0 &&
		    strcmp(service->type, "anvil") != 0 &&
		    strcmp(service->type, "auth") != 0 &&
		    strcmp(service->type, "auth-source") != 0) {
			*error_r = t_strconcat("Unknown service type: ",
					       service->type, NULL);
			return FALSE;
		}
		for (j = 0; j < i; j++) {
			if (strcmp(service->name, services[j]->name) == 0) {
				*error_r = t_strdup_printf(
					"Duplicate service name: %s",
					service->name);
				return FALSE;
			}
		}
	}
	for (i = 0; i < count; i++) {
		struct service_settings *service = services[i];

		if (*service->executable != '/') {
			service->executable =
				p_strconcat(pool, set->libexec_dir, "/",
					    service->executable, NULL);
		}
		if (*service->chroot != '/' && *service->chroot != '\0') {
			service->chroot =
				p_strconcat(pool, set->base_dir, "/",
					    service->chroot, NULL);
		}
		if (service->drop_priv_before_exec &&
		    *service->chroot != '\0') {
			*error_r = t_strdup_printf("service(%s): "
				"drop_priv_before_exec=yes can't be "
				"used with chroot", service->name);
			return FALSE;
		}
		if (service->process_min_avail > service->process_limit) {
			*error_r = t_strdup_printf("service(%s): "
				"process_min_avail is higher than process_limit",
				service->name);
			return FALSE;
		}
		fix_file_listener_paths(&service->unix_listeners,
					pool, set->base_dir);
		fix_file_listener_paths(&service->fifo_listeners,
					pool, set->base_dir);
	}
	set->protocols_split = p_strsplit(pool, set->protocols, " ");
	return TRUE;
}
/* </settings checks> */

static bool
login_want_core_dumps(const struct master_settings *set, gid_t *gid_r)
{
	struct service_settings *const *services;
	unsigned int i, count;
	const char *error;
	bool cores = FALSE;
	uid_t uid;

	*gid_r = (gid_t)-1;

	services = array_get(&set->services, &count);
	for (i = 0; i < count; i++) {
		if (strcmp(services[i]->type, "auth-source") == 0 &&
		    strstr(services[i]->name, "-login") != NULL) {
			if (strstr(services[i]->executable, " -D") != NULL)
				cores = TRUE;
			(void)get_uidgid(services[i]->user, &uid, gid_r, &error);
			if (*services[i]->group != '\0')
				(void)get_gid(services[i]->group, gid_r, &error);
		}
	}
	return cores;
}

static bool
settings_have_auth_unix_listeners_in(const struct master_settings *set,
				     const char *dir)
{
	struct service_settings *const *services;
	struct file_listener_settings *const *u;
	unsigned int i, j, count, count2;

	services = array_get(&set->services, &count);
	for (i = 0; i < count; i++) {
		if (strcmp(services[i]->type, "auth") == 0 &&
		    array_is_created(&services[i]->unix_listeners)) {
			u = array_get(&services[i]->unix_listeners, &count2);
			for (j = 0; j < count2; j++) {
				if (strncmp(u[j]->path, dir, strlen(dir)) == 0)
					return TRUE;
			}
		}
	}
	return FALSE;
}

static void unlink_sockets(const char *path, const char *prefix)
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

bool master_settings_do_fixes(const struct master_settings *set)
{
	const char *login_dir, *empty_dir;
	struct stat st;
	gid_t gid;

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
	if (!S_ISDIR(st.st_mode)) {
		i_error("%s is not a directory", set->base_dir);
		return FALSE;
	}

	/* Make sure our permanent state directory exists */
	if (mkdir_parents(PKG_STATEDIR, 0750) < 0 && errno != EEXIST) {
		i_error("mkdir(%s) failed: %m", PKG_STATEDIR);
		return FALSE;
	}

	/* remove auth worker sockets left by unclean exits */
	unlink_sockets(set->base_dir, "auth-worker.");

	login_dir = t_strconcat(set->base_dir, "/login", NULL);
	if (settings_have_auth_unix_listeners_in(set, login_dir)) {
		/* we are not using external authentication, so make sure the
		   login directory exists with correct permissions and it's
		   empty. with external auth we wouldn't want to delete
		   existing sockets or break the permissions required by the
		   auth server. */
		mode_t mode = login_want_core_dumps(set, &gid) ? 0770 : 0750;
		if (gid != (gid_t)-1 &&
		    safe_mkdir(login_dir, mode, master_uid, gid) == 0) {
			i_warning("Corrected permissions for login directory "
				  "%s", login_dir);
		}

		unlink_sockets(login_dir, "");
	} else {
		/* still make sure that login directory exists */
		if (mkdir(login_dir, 0755) < 0 && errno != EEXIST) {
			i_error("mkdir(%s) failed: %m", login_dir);
			return FALSE;
		}
	}

	empty_dir = t_strconcat(set->base_dir, "/empty", NULL);
	if (safe_mkdir(empty_dir, 0755, master_uid, getegid()) == 0) {
		i_warning("Corrected permissions for empty directory "
			  "%s", empty_dir);
	}
	return TRUE;
}
