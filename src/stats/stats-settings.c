/* Copyright (c) 2009-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "service-settings.h"
#include "stats-settings.h"

/* <settings checks> */
static struct file_listener_settings stats_unix_listeners_array[] = {
	{ "stats", 0600, "", "" }
};
static struct file_listener_settings *stats_unix_listeners[] = {
	&stats_unix_listeners_array[0]
};
static buffer_t stats_unix_listeners_buf = {
	stats_unix_listeners, sizeof(stats_unix_listeners), { 0, }
};
static struct file_listener_settings stats_fifo_listeners_array[] = {
	{ "stats-mail", 0600, "", "" }
};
static struct file_listener_settings *stats_fifo_listeners[] = {
	&stats_fifo_listeners_array[0]
};
static buffer_t stats_fifo_listeners_buf = {
	stats_fifo_listeners,
	sizeof(stats_fifo_listeners), { 0, }
};
/* </settings checks> */

struct service_settings stats_service_settings = {
	.name = "stats",
	.protocol = "",
	.type = "",
	.executable = "stats",
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

	.unix_listeners = { { &stats_unix_listeners_buf,
			      sizeof(stats_unix_listeners[0]) } },
	.fifo_listeners = { { &stats_fifo_listeners_buf,
			      sizeof(stats_fifo_listeners[0]) } },
	.inet_listeners = ARRAY_INIT
};

/* we're kind of kludging here to avoid "stats_" prefix in the struct fields */
#undef DEF
#define DEF(type, name) \
	{ type, "stats_"#name, offsetof(struct stats_settings, name), NULL }

static const struct setting_define stats_setting_defines[] = {
	DEF(SET_SIZE, memory_limit),
	DEF(SET_TIME, command_min_time),
	DEF(SET_TIME, session_min_time),
	DEF(SET_TIME, user_min_time),
	DEF(SET_TIME, domain_min_time),
	DEF(SET_TIME, ip_min_time),

	SETTING_DEFINE_LIST_END
};

const struct stats_settings stats_default_settings = {
	.memory_limit = 1024*1024*16,

	.command_min_time = 60,
	.session_min_time = 60*15,
	.user_min_time = 60*60,
	.domain_min_time = 60*60*12,
	.ip_min_time = 60*60*12
};

const struct setting_parser_info stats_setting_parser_info = {
	.module_name = "stats",
	.defines = stats_setting_defines,
	.defaults = &stats_default_settings,

	.type_offset = (size_t)-1,
	.struct_size = sizeof(struct stats_settings),

	.parent_offset = (size_t)-1
};

const struct stats_settings *stats_settings;
