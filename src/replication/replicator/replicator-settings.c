/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "service-settings.h"
#include "replicator-settings.h"

struct event_category event_category_replication = {
	.name = "replication"
};

/* <settings checks> */
static struct file_listener_settings replicator_unix_listeners_array[] = {
	{
		.path = "replicator",
		.mode = 0600,
		.user = "$default_internal_user",
		.group = "",
	},
	{
		.path = "replicator-doveadm",
		.type = "doveadm",
		.mode = 0,
		.user = "$default_internal_user",
		.group = "",
	},
};
static struct file_listener_settings *replicator_unix_listeners[] = {
	&replicator_unix_listeners_array[0],
	&replicator_unix_listeners_array[1]
};
static buffer_t replicator_unix_listeners_buf = {
	{ { replicator_unix_listeners, sizeof(replicator_unix_listeners) } }
};
/* </settings checks> */

struct service_settings replicator_service_settings = {
	.name = "replicator",
	.protocol = "",
	.type = "",
	.executable = "replicator",
	.user = "",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 1,
	.client_limit = 0,
	.service_count = 0,
	.idle_kill = UINT_MAX,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = { { &replicator_unix_listeners_buf,
			      sizeof(replicator_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT,

	.process_limit_1 = TRUE
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct replicator_settings)

static const struct setting_define replicator_setting_defines[] = {
	DEF(STR, auth_socket_path),
	DEF(STR, doveadm_socket_path),
	DEF(STR, replication_dsync_parameters),

	DEF(TIME, replication_full_sync_interval),
	DEF(UINT, replication_max_conns),

	SETTING_DEFINE_LIST_END
};

const struct replicator_settings replicator_default_settings = {
	.auth_socket_path = "auth-userdb",
	.doveadm_socket_path = "doveadm-server",
	.replication_dsync_parameters = "-d -N -l 30 -U",

	.replication_full_sync_interval = 60*60*24,
	.replication_max_conns = 10
};

const struct setting_parser_info replicator_setting_parser_info = {
	.module_name = "replicator",
	.defines = replicator_setting_defines,
	.defaults = &replicator_default_settings,

	.type_offset = SIZE_MAX,
	.struct_size = sizeof(struct replicator_settings),

	.parent_offset = SIZE_MAX
};

const struct replicator_settings *replicator_settings;
