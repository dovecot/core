/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "array.h"
#include "env-util.h"
#include "istream.h"
#include "net.h"
#include "str.h"
#include "ipwd.h"
#include "mkdir-parents.h"
#include "safe-mkdir.h"
#include "restrict-process-size.h"
#include "settings-parser.h"
#include "master-settings.h"

#include <stddef.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

static bool master_settings_verify(void *_set, pool_t pool,
				   const char **error_r);

extern const struct setting_parser_info service_setting_parser_info;

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct file_listener_settings)

static const struct setting_define file_listener_setting_defines[] = {
	DEF(STR, path),
	DEF(STR, type),
	DEF(UINT_OCT, mode),
	DEF(STR, user),
	DEF(STR, group),

	SETTING_DEFINE_LIST_END
};

static const struct file_listener_settings file_listener_default_settings = {
	.path = "",
	.mode = 0600,
	.user = "",
	.group = "",
};

static const struct setting_parser_info file_listener_setting_parser_info = {
	.defines = file_listener_setting_defines,
	.defaults = &file_listener_default_settings,

	.type_offset = offsetof(struct file_listener_settings, path),
	.struct_size = sizeof(struct file_listener_settings),

	.parent_offset = SIZE_MAX,
	.parent = &service_setting_parser_info
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct inet_listener_settings)

static const struct setting_define inet_listener_setting_defines[] = {
	DEF(STR, name),
	DEF(STR, type),
	DEF(STR, address),
	DEF(IN_PORT, port),
	DEF(BOOL, ssl),
	DEF(BOOL, reuse_port),
	DEF(BOOL, haproxy),

	SETTING_DEFINE_LIST_END
};

static const struct inet_listener_settings inet_listener_default_settings = {
	.name = "",
	.address = "",
	.port = 0,
	.ssl = FALSE,
	.reuse_port = FALSE,
	.haproxy = FALSE
};

static const struct setting_parser_info inet_listener_setting_parser_info = {
	.defines = inet_listener_setting_defines,
	.defaults = &inet_listener_default_settings,

	.type_offset = offsetof(struct inet_listener_settings, name),
	.struct_size = sizeof(struct inet_listener_settings),

	.parent_offset = SIZE_MAX,
	.parent = &service_setting_parser_info
};

#undef DEF
#undef DEFLIST_UNIQUE
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct service_settings)
#define DEFLIST_UNIQUE(field, name, defines) \
	{ .type = SET_DEFLIST_UNIQUE, .key = name, \
	  .offset = offsetof(struct service_settings, field), \
	  .list_info = defines }

static const struct setting_define service_setting_defines[] = {
	DEF(STR, name),
	DEF(STR, protocol),
	DEF(STR, type),
	DEF(STR, executable),
	DEF(STR, user),
	DEF(STR, group),
	DEF(STR, privileged_group),
	DEF(STR, extra_groups),
	DEF(STR, chroot),

	DEF(BOOL, drop_priv_before_exec),

	DEF(UINT, process_min_avail),
	DEF(UINT, process_limit),
	DEF(UINT, client_limit),
	DEF(UINT, service_count),
	DEF(TIME, idle_kill),
	DEF(SIZE, vsz_limit),

	DEFLIST_UNIQUE(unix_listeners, "unix_listener",
		       &file_listener_setting_parser_info),
	DEFLIST_UNIQUE(fifo_listeners, "fifo_listener",
		       &file_listener_setting_parser_info),
	DEFLIST_UNIQUE(inet_listeners, "inet_listener",
		       &inet_listener_setting_parser_info),

	SETTING_DEFINE_LIST_END
};

static const struct service_settings service_default_settings = {
	.name = "",
	.protocol = "",
	.type = "",
	.executable = "",
	.user = "",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 0,
	.client_limit = 0,
	.service_count = 0,
	.idle_kill = 0,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};

const struct setting_parser_info service_setting_parser_info = {
	.defines = service_setting_defines,
	.defaults = &service_default_settings,

	.type_offset = offsetof(struct service_settings, name),
	.struct_size = sizeof(struct service_settings),

	.parent_offset = offsetof(struct service_settings, master_set),
	.parent = &master_setting_parser_info
};

#undef DEF
#undef DEFLIST_UNIQUE
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct master_settings)
#define DEFLIST_UNIQUE(field, name, defines) \
	{ .type = SET_DEFLIST_UNIQUE, .key = name, \
	  .offset = offsetof(struct master_settings, field), \
	  .list_info = defines }

static const struct setting_define master_setting_defines[] = {
	DEF(STR, base_dir),
	DEF(STR, state_dir),
	DEF(STR, libexec_dir),
	DEF(STR, instance_name),
	DEF(STR, protocols),
	DEF(STR, listen),
	DEF(ENUM, ssl),
	DEF(STR, default_internal_user),
	DEF(STR, default_internal_group),
	DEF(STR, default_login_user),
	DEF(UINT, default_process_limit),
	DEF(UINT, default_client_limit),
	DEF(TIME, default_idle_kill),
	DEF(SIZE, default_vsz_limit),

	DEF(BOOL, version_ignore),

	DEF(UINT, first_valid_uid),
	DEF(UINT, last_valid_uid),
	DEF(UINT, first_valid_gid),
	DEF(UINT, last_valid_gid),

	DEFLIST_UNIQUE(services, "service", &service_setting_parser_info),

	SETTING_DEFINE_LIST_END
};

static const struct master_settings master_default_settings = {
	.base_dir = PKG_RUNDIR,
	.state_dir = PKG_STATEDIR,
	.libexec_dir = PKG_LIBEXECDIR,
	.instance_name = PACKAGE,
	.protocols = "imap pop3 lmtp",
	.listen = "*, ::",
	.ssl = "yes:no:required",
	.default_internal_user = "dovecot",
	.default_internal_group = "dovecot",
	.default_login_user = "dovenull",
	.default_process_limit = 100,
	.default_client_limit = 1000,
	.default_idle_kill = 60,
	.default_vsz_limit = 256*1024*1024,

	.version_ignore = FALSE,

	.first_valid_uid = 500,
	.last_valid_uid = 0,
	.first_valid_gid = 1,
	.last_valid_gid = 0,

#ifndef CONFIG_BINARY
	.services = ARRAY_INIT
#else
	.services = { { &config_all_services_buf,
			     sizeof(struct service_settings *) } },
#endif
};

const struct setting_parser_info master_setting_parser_info = {
	.module_name = "master",
	.defines = master_setting_defines,
	.defaults = &master_default_settings,

	.type_offset = SIZE_MAX,
	.struct_size = sizeof(struct master_settings),

	.parent_offset = SIZE_MAX,

	.check_func = master_settings_verify
};

/* <settings checks> */
static void
expand_user(const char **user, enum service_user_default *default_r,
	    const struct master_settings *set)
{
	/* $variable expansion is typically done by doveconf, but these
	   variables can come from built-in settings, so we need to expand
	   them here */
	if (strcmp(*user, "$default_internal_user") == 0) {
		*user = set->default_internal_user;
		*default_r = SERVICE_USER_DEFAULT_INTERNAL;
	} else if (strcmp(*user, "$default_login_user") == 0) {
		*user = set->default_login_user;
		*default_r = SERVICE_USER_DEFAULT_LOGIN;
	} else {
		*default_r = SERVICE_USER_DEFAULT_NONE;
	}
}

static void
expand_group(const char **group, const struct master_settings *set)
{
	/* $variable expansion is typically done by doveconf, but these
	   variables can come from built-in settings, so we need to expand
	   them here */
	if (strcmp(*group, "$default_internal_group") == 0)
		*group = set->default_internal_group;
}

static bool
fix_file_listener_paths(ARRAY_TYPE(file_listener_settings) *l,
			pool_t pool, const struct master_settings *master_set,
			ARRAY_TYPE(const_string) *all_listeners,
			const char **error_r)
{
	struct file_listener_settings *set;
	size_t base_dir_len = strlen(master_set->base_dir);
	enum service_user_default user_default;

	if (!array_is_created(l))
		return TRUE;

	array_foreach_elem(l, set) {
		if (set->path[0] == '\0') {
			*error_r = "path must not be empty";
			return FALSE;
		}

		expand_user(&set->user, &user_default, master_set);
		expand_group(&set->group, master_set);
		if (*set->path != '/') {
			set->path = p_strconcat(pool, master_set->base_dir, "/",
						set->path, NULL);
		} else if (strncmp(set->path, master_set->base_dir,
				   base_dir_len) == 0 &&
			   set->path[base_dir_len] == '/') {
			i_warning("You should remove base_dir prefix from "
				  "unix_listener: %s", set->path);
		}
		if (set->mode != 0)
			array_push_back(all_listeners, &set->path);
	}
	return TRUE;
}

static void add_inet_listeners(ARRAY_TYPE(inet_listener_settings) *l,
			       ARRAY_TYPE(const_string) *all_listeners)
{
	struct inet_listener_settings *set;
	const char *str;

	if (!array_is_created(l))
		return;

	array_foreach_elem(l, set) {
		if (set->port != 0) {
			str = t_strdup_printf("%u:%s", set->port, set->address);
			array_push_back(all_listeners, &str);
		}
	}
}

static bool master_settings_parse_type(struct service_settings *set,
				       const char **error_r)
{
	if (*set->type == '\0')
		set->parsed_type = SERVICE_TYPE_UNKNOWN;
	else if (strcmp(set->type, "log") == 0)
		set->parsed_type = SERVICE_TYPE_LOG;
	else if (strcmp(set->type, "config") == 0)
		set->parsed_type = SERVICE_TYPE_CONFIG;
	else if (strcmp(set->type, "anvil") == 0)
		set->parsed_type = SERVICE_TYPE_ANVIL;
	else if (strcmp(set->type, "login") == 0)
		set->parsed_type = SERVICE_TYPE_LOGIN;
	else if (strcmp(set->type, "startup") == 0)
		set->parsed_type = SERVICE_TYPE_STARTUP;
	else if (strcmp(set->type, "worker") == 0)
		set->parsed_type = SERVICE_TYPE_WORKER;
	else {
		*error_r = t_strconcat("Unknown service type: ",
				       set->type, NULL);
		return FALSE;
	}
	return TRUE;
}

static void service_set_login_dump_core(struct service_settings *set)
{
	const char *p;

	if (set->parsed_type != SERVICE_TYPE_LOGIN)
		return;

	p = strstr(set->executable, " -D");
	if (p != NULL && (p[3] == '\0' || p[3] == ' '))
		set->login_dump_core = TRUE;
}

static bool
services_have_protocol(struct master_settings *set, const char *name)
{
	struct service_settings *service;

	array_foreach_elem(&set->services, service) {
		if (strcmp(service->protocol, name) == 0)
			return TRUE;
	}
	return FALSE;
}

#ifdef CONFIG_BINARY
static const struct service_settings *
master_default_settings_get_service(const char *name)
{
	extern struct master_settings master_default_settings;
	struct service_settings *set;

	array_foreach_elem(&master_default_settings.services, set) {
		if (strcmp(set->name, name) == 0)
			return set;
	}
	return NULL;
}
#endif

static unsigned int
service_get_client_limit(struct master_settings *set, const char *name)
{
	struct service_settings *service;

	array_foreach_elem(&set->services, service) {
		if (strcmp(service->name, name) == 0) {
			if (service->client_limit != 0)
				return service->client_limit;
			else
				return set->default_client_limit;
		}
	}
	return set->default_client_limit;
}

static bool service_is_enabled(const struct master_settings *set,
			       struct service_settings *service)
{
	return service->protocol[0] == '\0' ||
		str_array_find((const char **)set->protocols_split,
			       service->protocol);
}

static bool
master_settings_verify(void *_set, pool_t pool, const char **error_r)
{
	static bool warned_auth = FALSE, warned_anvil = FALSE;
	struct master_settings *set = _set;
	struct service_settings *const *services;
	const char *const *strings;
	ARRAY_TYPE(const_string) all_listeners;
	struct passwd pw;
	unsigned int i, j, count, client_limit, process_limit;
	unsigned int max_auth_client_processes, max_anvil_client_processes;
	string_t *max_auth_client_processes_reason = t_str_new(64);
	string_t *max_anvil_client_processes_reason = t_str_new(64);
	size_t len;
#ifdef CONFIG_BINARY
	const struct service_settings *default_service;
#else
	rlim_t fd_limit;
	const char *max_client_limit_source = "default_client_limit";
	unsigned int max_client_limit = set->default_client_limit;
#endif

	if (*set->listen == '\0') {
		*error_r = "listen can't be set empty";
		return FALSE;
	}

	len = strlen(set->base_dir);
	if (len > 0 && set->base_dir[len-1] == '/') {
		/* drop trailing '/' */
		set->base_dir = p_strndup(pool, set->base_dir, len - 1);
	}

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

	if (i_getpwnam(set->default_login_user, &pw) == 0) {
		*error_r = t_strdup_printf("default_login_user doesn't exist: %s",
					   set->default_login_user);
		return FALSE;
	}
	if (i_getpwnam(set->default_internal_user, &pw) == 0) {
		*error_r = t_strdup_printf("default_internal_user doesn't exist: %s",
					   set->default_internal_user);
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
		if (!master_settings_parse_type(service, error_r))
			return FALSE;
		for (j = 0; j < i; j++) {
			if (strcmp(service->name, services[j]->name) == 0) {
				*error_r = t_strdup_printf(
					"Duplicate service name: %s",
					service->name);
				return FALSE;
			}
		}
		expand_user(&service->user, &service->user_default, set);
		expand_group(&service->extra_groups, set);
		service_set_login_dump_core(service);
	}
	set->protocols_split = p_strsplit_spaces(pool, set->protocols, " ");
	if (set->protocols_split[0] != NULL &&
	    strcmp(set->protocols_split[0], "none") == 0 &&
	    set->protocols_split[1] == NULL)
		set->protocols_split[0] = NULL;

	for (i = 0; set->protocols_split[i] != NULL; i++) {
		if (!services_have_protocol(set, set->protocols_split[i])) {
			*error_r = t_strdup_printf("protocols: "
						   "Unknown protocol: %s",
						   set->protocols_split[i]);
			return FALSE;
		}
	}
	t_array_init(&all_listeners, 64);
	max_auth_client_processes = 0;
	max_anvil_client_processes = 2; /* blocking, nonblocking pipes */
	for (i = 0; i < count; i++) {
		struct service_settings *service = services[i];

		if (!service_is_enabled(set, service)) {
			/* protocol not enabled, ignore its settings */
			continue;
		}

		if (*service->executable != '/' &&
		    *service->executable != '\0') {
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
		process_limit = service->process_limit;
		if (process_limit == 0)
			process_limit = set->default_process_limit;
		if (service->process_min_avail > process_limit) {
			*error_r = t_strdup_printf("service(%s): "
				"process_min_avail is higher than process_limit",
				service->name);
			return FALSE;
		}
		if (service->vsz_limit < 1024*1024 && service->vsz_limit != 0) {
			*error_r = t_strdup_printf("service(%s): "
				"vsz_limit is too low", service->name);
			return FALSE;
		}

#ifdef CONFIG_BINARY
		default_service =
			master_default_settings_get_service(service->name);
		if (default_service != NULL &&
		    default_service->process_limit_1 && process_limit > 1) {
			*error_r = t_strdup_printf("service(%s): "
				"process_limit must be 1", service->name);
			return FALSE;
		}
#else
		if (max_client_limit < service->client_limit) {
			max_client_limit = service->client_limit;
			max_client_limit_source = t_strdup_printf(
				"service %s { client_limit }", service->name);
		}
#endif

		if (*service->protocol != '\0') {
			/* each imap/pop3/lmtp process can use up a connection,
			   although if service_count=1 it's only temporary.
			   imap-hibernate doesn't do any auth lookups. */
			if ((service->service_count != 1 ||
			     strcmp(service->type, "login") == 0) &&
			    strcmp(service->name, "imap-hibernate") != 0) {
				str_printfa(max_auth_client_processes_reason,
					    " + service %s { process_limit=%u }",
					    service->name, process_limit);
				max_auth_client_processes += process_limit;
			}
		}
		if (strcmp(service->type, "login") == 0 ||
		    strcmp(service->name, "auth") == 0) {
			max_anvil_client_processes += process_limit;
			str_printfa(max_anvil_client_processes_reason,
				    " + service %s { process_limit=%u }",
				    service->name, process_limit);
		}

		if (!fix_file_listener_paths(&service->unix_listeners, pool,
					     set, &all_listeners, error_r)) {
			*error_r = t_strdup_printf("service(%s): unix_listener: %s",
						   service->name, *error_r);
			return FALSE;
		}
		if (!fix_file_listener_paths(&service->fifo_listeners, pool,
					     set, &all_listeners, error_r)) {
			*error_r = t_strdup_printf("service(%s): fifo_listener: %s",
						   service->name, *error_r);
			return FALSE;
		}
		add_inet_listeners(&service->inet_listeners, &all_listeners);
	}

	client_limit = service_get_client_limit(set, "auth");
	if (client_limit < max_auth_client_processes && !warned_auth) {
		warned_auth = TRUE;
		str_delete(max_auth_client_processes_reason, 0, 3);
		i_warning("service auth { client_limit=%u } is lower than "
			  "required under max. load (%u). "
			  "Counted for protocol services with service_count != 1: %s",
			  client_limit, max_auth_client_processes,
			  str_c(max_auth_client_processes_reason));
	}

	client_limit = service_get_client_limit(set, "anvil");
	if (client_limit < max_anvil_client_processes && !warned_anvil) {
		warned_anvil = TRUE;
		str_delete(max_anvil_client_processes_reason, 0, 3);
		i_warning("service anvil { client_limit=%u } is lower than "
			  "required under max. load (%u). Counted with: %s",
			  client_limit, max_anvil_client_processes,
			  str_c(max_anvil_client_processes_reason));
	}
#ifndef CONFIG_BINARY
	if (restrict_get_fd_limit(&fd_limit) == 0 &&
	    fd_limit < (rlim_t)max_client_limit) {
		i_warning("fd limit (ulimit -n) is lower than required "
			  "under max. load (%u < %u), because of %s",
			  (unsigned int)fd_limit, max_client_limit,
			  max_client_limit_source);
	}
#endif

	/* check for duplicate listeners */
	array_sort(&all_listeners, i_strcmp_p);
	strings = array_get(&all_listeners, &count);
	for (i = 1; i < count; i++) {
		if (strcmp(strings[i-1], strings[i]) == 0) {
			*error_r = t_strdup_printf("duplicate listener: %s",
						   strings[i]);
			return FALSE;
		}
	}
	return TRUE;
}
/* </settings checks> */

static bool
login_want_core_dumps(const struct master_settings *set, gid_t *gid_r)
{
	struct service_settings *service;
	const char *error;
	bool cores = FALSE;
	uid_t uid;

	*gid_r = (gid_t)-1;

	array_foreach_elem(&set->services, service) {
		if (service->parsed_type == SERVICE_TYPE_LOGIN) {
			if (service->login_dump_core)
				cores = TRUE;
			(void)get_uidgid(service->user, &uid, gid_r, &error);
			if (*service->group != '\0')
				(void)get_gid(service->group, gid_r, &error);
		}
	}
	return cores;
}

static void unlink_sockets(const char *path, const char *prefix)
{
	DIR *dirp;
	struct dirent *dp;
	struct stat st;
	string_t *str;
	size_t prefix_len;

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
		   to die. */
		if (!startup_finished) {
			int fd = net_connect_unix(str_c(str));
			if (fd != -1 || errno != ECONNREFUSED) {
				i_fatal("Dovecot is already running? "
					"Socket already exists: %s",
					str_c(str));
			}
		}

		i_unlink_if_exists(str_c(str));
	}
	(void)closedir(dirp);
}

static void
mkdir_login_dir(const struct master_settings *set, const char *login_dir)
{
	mode_t mode;
	gid_t gid;

	/* Make sure the login directory exists with correct permissions and it's
	   empty. */
	mode = login_want_core_dumps(set, &gid) ? 0770 : 0750;
	if (safe_mkdir(login_dir, mode, master_uid, gid) == 0) {
		i_warning("Corrected permissions for login directory "
			  "%s", login_dir);
	}

	unlink_sockets(login_dir, "");
}

static void mkdir_listener(const struct file_listener_settings *set,
			   const char *dir, unsigned int mode)
{
	const char *error;
	uid_t uid;
	gid_t gid;

	/* Use the specified permissions for the parent directory, but only
	   if the directory doesn't already exist. It's likely not important
	   enough to change permissions for an existing directory and it might
	   cause problems if the permissions are intentionally different. */
	if (get_uidgid(set->user, &uid, &gid, &error) < 0 ||
	    get_gid(set->group, &gid, &error) < 0)
		i_fatal("%s (for creating directory %s)", error, dir);
	else if (mkdir(dir, mode) == 0) {
		if (chown(dir, uid, gid) < 0)
			i_fatal("chown(%s) failed: %m", dir);
	} else if (errno != EEXIST) {
		i_fatal("mkdir(%s) failed: %m", dir);
	}
}

static int
file_listener_settings_cmp_path(struct file_listener_settings *const *f1,
				struct file_listener_settings *const *f2)
{
	return strcmp((*f1)->path, (*f2)->path);
}

static void
subdir_add(ARRAY_TYPE(file_listener_settings) *subdir_listeners,
	   struct file_listener_settings *f, const char *base_prefix)
{
	if (!str_begins_with(f->path, base_prefix)) {
		/* not under base_dir */
		return;
	}

	const char *rel_path = f->path + strlen(base_prefix);
	if (strchr(rel_path, '/') == NULL) {
		/* not under a subdirectory */
		return;
	}

	if (str_begins_with(rel_path, "login/") ||
	    str_begins_with(rel_path, "token-login/")) {
		/* these are handled specially */
		return;
	}
	array_push_back(subdir_listeners, &f);
}

static void mkdir_listener_subdirs(const struct master_settings *set)
{
	struct service_settings *service;
	ARRAY_TYPE(file_listener_settings) subdir_listeners;
	struct file_listener_settings *f, *const *files;
	unsigned int i, count, files_mode, dir_mode;
	const char *p1, *p2, *last_group, *base_prefix;
	size_t dir1_len, dir2_len;

	/* First gather all unix/fifo listeners that have directories under
	   base_dir. */
	t_array_init(&subdir_listeners, 16);
	base_prefix = t_strconcat(set->base_dir, "/", NULL);
	array_foreach_elem(&set->services, service) {
		if (!service_is_enabled(set, service))
			continue;

		if (array_is_created(&service->unix_listeners)) {
			array_foreach_elem(&service->unix_listeners, f)
				subdir_add(&subdir_listeners, f, base_prefix);
		}
		if (array_is_created(&service->fifo_listeners)) {
			array_foreach_elem(&service->fifo_listeners, f)
				subdir_add(&subdir_listeners, f, base_prefix);
		}
	}
	/* Sort the listeners by path, so the listeners with same directories
	   are next to each others. */
	array_sort(&subdir_listeners, file_listener_settings_cmp_path);
	files = array_get(&subdir_listeners, &count);
	files_mode = 0; last_group = NULL;
	for (i = 0; i < count; i++) {
		p1 = strrchr(files[i]->path, '/');
		i_assert(p1 != NULL);
		dir1_len = p1 - files[i]->path;
		/* Create the directory permissions based on the union of its
		   file listeners permissions. */
		files_mode |= files[i]->mode;
		if ((files[i]->mode & 0070) != 0)
			last_group = files[i]->group;

		if (i+1 < count) {
			/* Delay creating the directory if the next listener
			   has the same directory. */
			p2 = strrchr(files[i+1]->path, '/');
			i_assert(p2 != NULL);
			dir2_len = p2 - files[i+1]->path;
			if (dir1_len == dir2_len &&
			    memcmp(files[i]->path, files[i+1]->path, dir1_len) == 0) {
				/* If the user or group differs, add more
				   permission bits to the mode. */
				if (strcmp(files[i]->user, files[i+1]->user) != 0)
					files_mode |= 0006;
				if (last_group != NULL &&
				    (files[i+1]->mode & 0070) != 0 &&
				    strcmp(files[i]->group, last_group) != 0)
					files_mode |= 0006;
				continue;
			}
		}
		/* keep the owner permissions +rwx, but group and other
		   permissions only as +rx. */
		dir_mode = 0700;
		if ((files_mode & 0070) != 0) dir_mode |= 0050;
		if ((files_mode & 0007) != 0) dir_mode |= 0005;
		mkdir_listener(files[i], t_strndup(files[i]->path, dir1_len),
			       dir_mode);
		files_mode = 0; last_group = NULL;
	}
}

void master_settings_do_fixes(const struct master_settings *set)
{
	const char *empty_dir;
	struct stat st;

	/* since base dir is under /var/run by default, it may have been
	   deleted. */
	if (mkdir_parents(set->base_dir, 0755) < 0 && errno != EEXIST)
		i_fatal("mkdir(%s) failed: %m", set->base_dir);
	/* allow base_dir to be a symlink, so don't use lstat() */
	if (stat(set->base_dir, &st) < 0)
		i_fatal("stat(%s) failed: %m", set->base_dir);
	if (!S_ISDIR(st.st_mode))
		i_fatal("%s is not a directory", set->base_dir);
	if ((st.st_mode & 0755) != 0755) {
		i_warning("Fixing permissions of %s to be world-readable",
			  set->base_dir);
		if (chmod(set->base_dir, 0755) < 0)
			i_error("chmod(%s) failed: %m", set->base_dir);
	}

	/* Make sure our permanent state directory exists */
	if (mkdir_parents(set->state_dir, 0755) < 0 && errno != EEXIST)
		i_fatal("mkdir(%s) failed: %m", set->state_dir);

	mkdir_login_dir(set, t_strconcat(set->base_dir, "/login", NULL));
	mkdir_login_dir(set, t_strconcat(set->base_dir, "/token-login", NULL));
	mkdir_listener_subdirs(set);

	empty_dir = t_strconcat(set->base_dir, "/empty", NULL);
	if (safe_mkdir(empty_dir, 0755, master_uid, getegid()) == 0) {
		i_warning("Corrected permissions for empty directory "
			  "%s", empty_dir);
	}
}
