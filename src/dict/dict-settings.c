/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "service-settings.h"
#include "dict-settings.h"

struct service_settings dict_service_settings = {
	.name = "dict",
	.protocol = "",
	.type = "",
	.executable = "dict",
	.user = "$default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 0,
	.client_limit = 1,
	.service_count = 0,
	.idle_kill = 0,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};

const struct setting_keyvalue dict_service_settings_defaults[] = {
	{ "unix_listener", "dict" },

	{ "unix_listener/dict/path", "dict" },
	{ "unix_listener/dict/mode", "0660" },
	{ "unix_listener/dict/group", "$default_internal_group" },

	{ NULL, NULL }
};

struct service_settings dict_async_service_settings = {
	.name = "dict-async",
	.protocol = "",
	.type = "",
	.executable = "dict",
	.user = "$default_internal_user",
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

const struct setting_keyvalue dict_async_service_settings_defaults[] = {
	{ "unix_listener", "dict-async" },

	{ "unix_listener/dict-async/path", "dict-async" },
	{ "unix_listener/dict-async/mode", "0660" },
	{ "unix_listener/dict-async/group", "$default_internal_group" },

	{ NULL, NULL }
};

struct service_settings dict_expire_service_settings = {
	.name = "dict-expire",
	.protocol = "",
	.type = "",
	.executable = "dict-expire",
	.user = "$default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 1,
	.client_limit = 1,
	.service_count = 0,
	.idle_kill = 0,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct dict_server_settings)

static const struct setting_define dict_setting_defines[] = {
	DEF(STR, base_dir),
	DEF(BOOL, verbose_proctitle),
	{ .type = SET_STRLIST, .key = "dict",
	  .offset = offsetof(struct dict_server_settings, dicts) },

	SETTING_DEFINE_LIST_END
};

const struct dict_server_settings dict_default_settings = {
	.base_dir = PKG_RUNDIR,
	.verbose_proctitle = FALSE,
	.dicts = ARRAY_INIT
};

const struct setting_parser_info dict_server_setting_parser_info = {
	.name = "dict_server",

	.defines = dict_setting_defines,
	.defaults = &dict_default_settings,

	.struct_size = sizeof(struct dict_server_settings),
	.pool_offset1 = 1 + offsetof(struct dict_server_settings, pool),
};

const struct dict_server_settings *dict_settings;
