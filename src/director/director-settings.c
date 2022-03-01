/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "service-settings.h"
#include "director-settings.h"

/* <settings checks> */
static bool director_settings_verify(void *_set, pool_t pool, const char **error_r);

static struct file_listener_settings director_unix_listeners_array[] = {
	{ "login/director", 0, "", "" },
	{ "director-admin", 0600, "", "" }
};
static struct file_listener_settings *director_unix_listeners[] = {
	&director_unix_listeners_array[0],
	&director_unix_listeners_array[1]
};
static buffer_t director_unix_listeners_buf = {
	{ { director_unix_listeners, sizeof(director_unix_listeners) } }
};
static struct file_listener_settings director_fifo_listeners_array[] = {
	{ "login/proxy-notify", 0, "", "" }
};
static struct file_listener_settings *director_fifo_listeners[] = {
	&director_fifo_listeners_array[0]
};
static buffer_t director_fifo_listeners_buf = {
	{ { director_fifo_listeners, sizeof(director_fifo_listeners) } }
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
	.chroot = ".",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 1,
	.client_limit = 0,
	.service_count = 0,
	.idle_kill = UINT_MAX,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = { { &director_unix_listeners_buf,
			      sizeof(director_unix_listeners[0]) } },
	.fifo_listeners = { { &director_fifo_listeners_buf,
			      sizeof(director_fifo_listeners[0]) } },
	.inet_listeners = ARRAY_INIT,

	.process_limit_1 = TRUE
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct director_settings)

static const struct setting_define director_setting_defines[] = {
	DEF(STR, master_user_separator),

	DEF(STR, director_servers),
	DEF(STR, director_mail_servers),
	DEF(STR, director_username_hash),
	DEF(STR, director_flush_socket),
	DEF(TIME, director_ping_idle_timeout),
	DEF(TIME, director_ping_max_timeout),
	DEF(TIME, director_user_expire),
	DEF(TIME, director_user_kick_delay),
	DEF(UINT, director_max_parallel_moves),
	DEF(UINT, director_max_parallel_kicks),
	DEF(SIZE, director_output_buffer_size),

	SETTING_DEFINE_LIST_END
};

const struct director_settings director_default_settings = {
	.master_user_separator = "",

	.director_servers = "",
	.director_mail_servers = "",
	.director_username_hash = "%Lu",
	.director_flush_socket = "",
	.director_ping_idle_timeout = 30,
	.director_ping_max_timeout = 60,
	.director_user_expire = 60*15,
	.director_user_kick_delay = 2,
	.director_max_parallel_moves = 100,
	.director_max_parallel_kicks = 100,
	.director_output_buffer_size = 10 * 1024 * 1024,
};

const struct setting_parser_info director_setting_parser_info = {
	.module_name = "director",
	.defines = director_setting_defines,
	.defaults = &director_default_settings,

	.type_offset = SIZE_MAX,
	.struct_size = sizeof(struct director_settings),

	.parent_offset = SIZE_MAX,

	.check_func = director_settings_verify
};

/* <settings checks> */
static bool
director_settings_verify(void *_set, pool_t pool ATTR_UNUSED, const char **error_r)
{
	struct director_settings *set = _set;

	if (set->director_user_expire < 10) {
		*error_r = "director_user_expire is too low";
		return FALSE;
	}
	return TRUE;
}
/* </settings checks> */
