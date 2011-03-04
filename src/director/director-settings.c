/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "service-settings.h"
#include "director-settings.h"

/* <settings checks> */
static struct file_listener_settings director_unix_listeners_array[] = {
	{ "login/director", 0, "", "" },
	{ "director-admin", 0600, "", "" }
};
static struct file_listener_settings *director_unix_listeners[] = {
	&director_unix_listeners_array[0],
	&director_unix_listeners_array[1]
};
static buffer_t director_unix_listeners_buf = {
	director_unix_listeners,
	sizeof(director_unix_listeners), { 0, }
};
static struct file_listener_settings director_fifo_listeners_array[] = {
	{ "login/proxy-notify", 0, "", "" }
};
static struct file_listener_settings *director_fifo_listeners[] = {
	&director_fifo_listeners_array[0]
};
static buffer_t director_fifo_listeners_buf = {
	director_fifo_listeners,
	sizeof(director_fifo_listeners), { 0, }
};
/* </settings checks> */

struct service_settings director_service_settings = {
	.name = "director",
	.protocol = "",
	.type = "",
	.executable = "director",
	.user = "$default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 1,
	.client_limit = 0,
	.service_count = 0,
	.idle_kill = -1U,
	.vsz_limit = (uoff_t)-1,

	.unix_listeners = { { &director_unix_listeners_buf,
			      sizeof(director_unix_listeners[0]) } },
	.fifo_listeners = { { &director_fifo_listeners_buf,
			      sizeof(director_fifo_listeners[0]) } },
	.inet_listeners = ARRAY_INIT,

	.process_limit_1 = TRUE
};
#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct director_settings, name), NULL }

static const struct setting_define director_setting_defines[] = {
	DEF(SET_STR, base_dir),
	DEF(SET_STR, master_user_separator),

	DEF(SET_STR, director_servers),
	DEF(SET_STR, director_mail_servers),
	DEF(SET_TIME, director_user_expire),
	DEF(SET_UINT, director_doveadm_port),

	SETTING_DEFINE_LIST_END
};

const struct director_settings director_default_settings = {
	.base_dir = PKG_RUNDIR,
	.master_user_separator = "",

	.director_servers = "",
	.director_mail_servers = "",
	.director_user_expire = 60*15,
	.director_doveadm_port = 0
};

const struct setting_parser_info director_setting_parser_info = {
	.module_name = "director",
	.defines = director_setting_defines,
	.defaults = &director_default_settings,

	.type_offset = (size_t)-1,
	.struct_size = sizeof(struct director_settings),

	.parent_offset = (size_t)-1
};
