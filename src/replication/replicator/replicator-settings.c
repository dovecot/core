/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "service-settings.h"
#include "replicator-settings.h"

/* <settings checks> */
static struct file_listener_settings replicator_unix_listeners_array[] = {
	{ "replicator", 0600, "$default_internal_user", "" },
	{ "replicator-doveadm", 0, "$default_internal_user", "" }
};
static struct file_listener_settings *replicator_unix_listeners[] = {
	&replicator_unix_listeners_array[0],
	&replicator_unix_listeners_array[1]
};
static buffer_t replicator_unix_listeners_buf = {
	replicator_unix_listeners, sizeof(replicator_unix_listeners), { 0, }
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
	.vsz_limit = (uoff_t)-1,

	.unix_listeners = { { &replicator_unix_listeners_buf,
			      sizeof(replicator_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct replicator_settings, name), NULL }

static const struct setting_define replicator_setting_defines[] = {
	DEF(SET_STR, auth_socket_path),
	DEF(SET_STR, doveadm_socket_path),

	DEF(SET_TIME, replication_full_sync_interval),
	DEF(SET_UINT, replication_max_conns),

	SETTING_DEFINE_LIST_END
};

const struct replicator_settings replicator_default_settings = {
	.auth_socket_path = "auth-userdb",
	.doveadm_socket_path = "doveadm-server",

	.replication_full_sync_interval = 60*60*24,
	.replication_max_conns = 10
};

const struct setting_parser_info replicator_setting_parser_info = {
	.module_name = "replicator",
	.defines = replicator_setting_defines,
	.defaults = &replicator_default_settings,

	.type_offset = (size_t)-1,
	.struct_size = sizeof(struct replicator_settings),

	.parent_offset = (size_t)-1
};

const struct replicator_settings *replicator_settings;
