/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "service-settings.h"
#include "aggregator-settings.h"

/* <settings checks> */
static struct file_listener_settings aggregator_unix_listeners_array[] = {
	{ "replication-notify", 0600, "", "" }
};
static struct file_listener_settings *aggregator_unix_listeners[] = {
	&aggregator_unix_listeners_array[0]
};
static buffer_t aggregator_unix_listeners_buf = {
	aggregator_unix_listeners, sizeof(aggregator_unix_listeners), { 0, }
};

static struct file_listener_settings aggregator_fifo_listeners_array[] = {
	{ "replication-notify-fifo", 0600, "", "" }
};
static struct file_listener_settings *aggregator_fifo_listeners[] = {
	&aggregator_fifo_listeners_array[0]
};
static buffer_t aggregator_fifo_listeners_buf = {
	aggregator_fifo_listeners, sizeof(aggregator_fifo_listeners), { 0, }
};
/* </settings checks> */

struct service_settings aggregator_service_settings = {
	.name = "aggregator",
	.protocol = "",
	.type = "",
	.executable = "aggregator",
	.user = "$default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = ".",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 0,
	.client_limit = 0,
	.service_count = 0,
	.idle_kill = 0,
	.vsz_limit = (uoff_t)-1,

	.unix_listeners = { { &aggregator_unix_listeners_buf,
			      sizeof(aggregator_unix_listeners[0]) } },
	.fifo_listeners = { { &aggregator_fifo_listeners_buf,
			      sizeof(aggregator_fifo_listeners[0]) } },
	.inet_listeners = ARRAY_INIT
};

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct aggregator_settings, name), NULL }

static const struct setting_define aggregator_setting_defines[] = {
	DEF(SET_STR, replicator_host),
	DEF(SET_UINT, replicator_port),

	SETTING_DEFINE_LIST_END
};

const struct aggregator_settings aggregator_default_settings = {
	.replicator_host = "replicator",
	.replicator_port = 0
};

const struct setting_parser_info aggregator_setting_parser_info = {
	.module_name = "aggregator",
	.defines = aggregator_setting_defines,
	.defaults = &aggregator_default_settings,

	.type_offset = (size_t)-1,
	.struct_size = sizeof(struct aggregator_settings),

	.parent_offset = (size_t)-1
};

const struct aggregator_settings *aggregator_settings;
