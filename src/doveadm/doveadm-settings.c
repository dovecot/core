/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "service-settings.h"
#include "mail-storage-settings.h"
#include "doveadm-settings.h"

static bool doveadm_settings_check(void *_set, pool_t pool, const char **error_r);

/* <settings checks> */
static struct file_listener_settings doveadm_unix_listeners_array[] = {
	{ "doveadm-server", 0600, "", "" }
};
static struct file_listener_settings *doveadm_unix_listeners[] = {
	&doveadm_unix_listeners_array[0]
};
static buffer_t doveadm_unix_listeners_buf = {
	doveadm_unix_listeners, sizeof(doveadm_unix_listeners), { 0, }
};
/* </settings checks> */

struct service_settings doveadm_service_settings = {
	.name = "doveadm",
	.protocol = "",
	.type = "",
	.executable = "doveadm-server",
	.user = "",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 0,
	.client_limit = 1,
	.service_count = 1,
	.idle_kill = 0,
	.vsz_limit = (uoff_t)-1,

	.unix_listeners = { { &doveadm_unix_listeners_buf,
			      sizeof(doveadm_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct doveadm_settings, name), NULL }

static const struct setting_define doveadm_setting_defines[] = {
	DEF(SET_STR, base_dir),
	DEF(SET_STR, mail_plugins),
	DEF(SET_STR, mail_plugin_dir),
	DEF(SET_STR, doveadm_socket_path),
	DEF(SET_UINT, doveadm_worker_count),
	DEF(SET_UINT, doveadm_proxy_port),
	DEF(SET_STR, doveadm_password),
	DEF(SET_STR, doveadm_allowed_commands),

	{ SET_STRLIST, "plugin", offsetof(struct doveadm_settings, plugin_envs), NULL },

	SETTING_DEFINE_LIST_END
};

const struct doveadm_settings doveadm_default_settings = {
	.base_dir = PKG_RUNDIR,
	.mail_plugins = "",
	.mail_plugin_dir = MODULEDIR,
	.doveadm_socket_path = "doveadm-server",
	.doveadm_worker_count = 0,
	.doveadm_proxy_port = 0,
	.doveadm_password = "",
	.doveadm_allowed_commands = "",

	.plugin_envs = ARRAY_INIT
};

static const struct setting_parser_info *doveadm_setting_dependencies[] = {
	&mail_user_setting_parser_info,
	NULL
};

const struct setting_parser_info doveadm_setting_parser_info = {
	.module_name = "doveadm",
	.defines = doveadm_setting_defines,
	.defaults = &doveadm_default_settings,

	.type_offset = (size_t)-1,
	.struct_size = sizeof(struct doveadm_settings),

	.parent_offset = (size_t)-1,
	.check_func = doveadm_settings_check,
	.dependencies = doveadm_setting_dependencies
};

struct doveadm_settings *doveadm_settings;

static void
fix_base_path(struct doveadm_settings *set, pool_t pool, const char **str)
{
	if (*str != NULL && **str != '\0' && **str != '/')
		*str = p_strconcat(pool, set->base_dir, "/", *str, NULL);
}

/* <settings checks> */
static bool doveadm_settings_check(void *_set ATTR_UNUSED,
				   pool_t pool ATTR_UNUSED,
				   const char **error_r ATTR_UNUSED)
{
#ifndef CONFIG_BINARY
	struct doveadm_settings *set = _set;

	fix_base_path(set, pool, &set->doveadm_socket_path);
#endif
	return TRUE;
}
/* </settings checks> */
