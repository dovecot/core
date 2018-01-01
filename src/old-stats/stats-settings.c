/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "service-settings.h"
#include "stats-settings.h"

/* <settings checks> */
static struct file_listener_settings old_stats_unix_listeners_array[] = {
	{ "old-stats", 0600, "", "" }
};
static struct file_listener_settings *old_stats_unix_listeners[] = {
	&old_stats_unix_listeners_array[0]
};
static buffer_t old_stats_unix_listeners_buf = {
	old_stats_unix_listeners, sizeof(old_stats_unix_listeners), { NULL, }
};
static struct file_listener_settings old_stats_fifo_listeners_array[] = {
	{ "old-stats-mail", 0600, "", "" },
	{ "old-stats-user", 0600, "", "" }
};
static struct file_listener_settings *old_stats_fifo_listeners[] = {
	&old_stats_fifo_listeners_array[0],
	&old_stats_fifo_listeners_array[1]
};
static buffer_t old_stats_fifo_listeners_buf = {
	old_stats_fifo_listeners,
	sizeof(old_stats_fifo_listeners), { NULL, }
};
/* </settings checks> */

struct service_settings old_stats_service_settings = {
	.name = "old-stats",
	.protocol = "",
	.type = "",
	.executable = "old-stats",
	.user = "$default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "empty",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 1,
	.client_limit = 0,
	.service_count = 0,
	.idle_kill = UINT_MAX,
	.vsz_limit = (uoff_t)-1,

	.unix_listeners = { { &old_stats_unix_listeners_buf,
			      sizeof(old_stats_unix_listeners[0]) } },
	.fifo_listeners = { { &old_stats_fifo_listeners_buf,
			      sizeof(old_stats_fifo_listeners[0]) } },
	.inet_listeners = ARRAY_INIT,

	.process_limit_1 = TRUE
};

/* we're kind of kludging here to avoid "stats_" prefix in the struct fields */
#undef DEF
#define DEF(type, name) \
	{ type, "old_stats_"#name, offsetof(struct old_stats_settings, name), NULL }

static const struct setting_define old_stats_setting_defines[] = {
	DEF(SET_SIZE, memory_limit),
	DEF(SET_TIME, command_min_time),
	DEF(SET_TIME, session_min_time),
	DEF(SET_TIME, user_min_time),
	DEF(SET_TIME, domain_min_time),
	DEF(SET_TIME, ip_min_time),
	DEF(SET_STR, carbon_server),
	DEF(SET_TIME, carbon_interval),
	DEF(SET_STR, carbon_name),
	SETTING_DEFINE_LIST_END
};

const struct old_stats_settings old_stats_default_settings = {
	.memory_limit = 1024*1024*16,

	.command_min_time = 60,
	.session_min_time = 60*15,
	.user_min_time = 60*60,
	.domain_min_time = 60*60*12,
	.ip_min_time = 60*60*12,

	.carbon_interval = 30,
	.carbon_server = "",
	.carbon_name = ""
};

const struct setting_parser_info old_stats_setting_parser_info = {
	.module_name = "stats",
	.defines = old_stats_setting_defines,
	.defaults = &old_stats_default_settings,

	.type_offset = (size_t)-1,
	.struct_size = sizeof(struct old_stats_settings),

	.parent_offset = (size_t)-1
};

const struct old_stats_settings *stats_settings;
