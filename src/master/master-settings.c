/* Copyright (c) 2005-2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "array.h"
#include "env-util.h"
#include "istream.h"
#include "mkdir-parents.h"
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
	MEMBER(struct_size) sizeof(struct file_listener_settings)
};

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct inet_listener_settings, name), NULL }

static struct setting_define inet_listener_setting_defines[] = {
	DEF(SET_STR, address),
	DEF(SET_UINT, port),

	SETTING_DEFINE_LIST_END
};

static struct inet_listener_settings inet_listener_default_settings = {
	MEMBER(address) "*",
	MEMBER(port) 0
};

static struct setting_parser_info inet_listener_setting_parser_info = {
	MEMBER(defines) inet_listener_setting_defines,
	MEMBER(defaults) &inet_listener_default_settings,

	MEMBER(parent) &service_setting_parser_info,
	MEMBER(parent_offset) (size_t)-1,
	MEMBER(struct_size) sizeof(struct inet_listener_settings)
};

#undef DEF
#undef DEFLIST
#define DEF(type, name) \
	{ type, #name, offsetof(struct service_settings, name), NULL }
#define DEFLIST(field, name, defines) \
	{ SET_DEFLIST, name, offsetof(struct service_settings, field), defines }

static struct setting_define service_setting_defines[] = {
	DEF(SET_INTERNAL, master_set),
	DEF(SET_STR, name),
	DEF(SET_STR, type),
	DEF(SET_STR, executable),
	DEF(SET_STR, user),
	DEF(SET_STR, group),
	DEF(SET_STR, privileged_group),
	DEF(SET_STR, extra_groups),
	DEF(SET_STR, chroot),
	DEF(SET_STR, auth_dest_service),

	DEF(SET_BOOL, drop_priv_before_exec),

	DEF(SET_UINT, process_limit),
	DEF(SET_UINT, client_limit),
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
	MEMBER(type) "",
	MEMBER(executable) "",
	MEMBER(user) "",
	MEMBER(group) "",
	MEMBER(privileged_group) "",
	MEMBER(extra_groups) "",
	MEMBER(chroot) "",
	MEMBER(auth_dest_service) "",

	MEMBER(drop_priv_before_exec) FALSE,

	MEMBER(process_limit) (unsigned int)-1,
	MEMBER(client_limit) 0,
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
	DEF(SET_UINT, default_process_limit),
	DEF(SET_UINT, default_client_limit),

	DEF(SET_BOOL, version_ignore),

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
	MEMBER(default_process_limit) 100,
	MEMBER(default_client_limit) 1000,

	MEMBER(version_ignore) FALSE,

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
	const struct master_settings *set = _set;
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
	services = array_get(&set->services, &count);
	if (count == 0) {
		*error_r = "No services defined";
		return FALSE;
	}
	for (i = 0; i < count; i++) {
		if (*services[i]->name == '\0') {
			*error_r = t_strdup_printf(
				"Service #%d is missing name", i);
			return FALSE;
		}
		for (j = 0; j < i; j++) {
			if (strcmp(services[i]->name, services[j]->name) == 0) {
				*error_r = t_strdup_printf(
					"Duplicate service name: %s",
					services[i]->name);
				return FALSE;
			}
		}
	}
	for (i = 0; i < count; i++) {
		if (*services[i]->executable != '/') {
			services[i]->executable =
				p_strconcat(pool, set->libexec_dir, "/",
					    services[i]->executable, NULL);
		}
		if (*services[i]->chroot != '/' &&
		    *services[i]->chroot != '\0') {
			services[i]->chroot =
				p_strconcat(pool, set->base_dir, "/",
					    services[i]->chroot, NULL);
		}
		if (services[i]->drop_priv_before_exec &&
		    *services[i]->chroot != '\0') {
			*error_r = t_strdup_printf("service(%s): "
				"drop_priv_before_exec=yes can't be "
				"used with chroot", services[i]->name);
			return FALSE;
		}
		fix_file_listener_paths(&services[i]->unix_listeners,
					pool, set->base_dir);
		fix_file_listener_paths(&services[i]->fifo_listeners,
					pool, set->base_dir);
	}
	return TRUE;
}
/* </settings checks> */

bool master_settings_do_fixes(const struct master_settings *set)
{
	const char *login_dir;
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
	if (!S_ISDIR(st.st_mode)) {
		i_error("%s is not a directory", set->base_dir);
		return FALSE;
	}

	/* create login directory under base dir */
	login_dir = t_strconcat(set->base_dir, "/login", NULL);
	if (mkdir(login_dir, 0755) < 0 && errno != EEXIST) {
		i_error("mkdir(%s) failed: %m", login_dir);
		return FALSE;
	}

	/* Make sure our permanent state directory exists */
	if (mkdir_parents(PKG_STATEDIR, 0750) < 0 && errno != EEXIST) {
		i_error("mkdir(%s) failed: %m", PKG_STATEDIR);
		return FALSE;
	}
	return TRUE;
}
