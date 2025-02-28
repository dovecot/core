/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "service-settings.h"
#include "master-service-settings.h"
#include "dict-settings.h"

struct service_settings dict_service_settings = {
	.name = "dict",
	.protocol = "",
	.type = "",
	.executable = "dict",
	.user = "$SET:default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = ARRAY_INIT,
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.client_limit = 1,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};

const struct setting_keyvalue dict_service_settings_defaults[] = {
	{ "unix_listener", "dict" },

	{ "unix_listener/dict/path", "dict" },
	{ "unix_listener/dict/mode", "0660" },
	{ "unix_listener/dict/group", "$SET:default_internal_group" },

	{ NULL, NULL }
};

struct service_settings dict_async_service_settings = {
	.name = "dict-async",
	.protocol = "",
	.type = "",
	.executable = "dict",
	.user = "$SET:default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = ARRAY_INIT,
	.chroot = "",

	.drop_priv_before_exec = FALSE,

#ifdef DOVECOT_PRO_EDITION
	/* Cassandra driver can use up a lot of VSZ */
	.vsz_limit = 2048ULL * 1024 * 1024,
#endif

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};

const struct setting_keyvalue dict_async_service_settings_defaults[] = {
	{ "unix_listener", "dict-async" },

	{ "unix_listener/dict-async/path", "dict-async" },
	{ "unix_listener/dict-async/mode", "0660" },
	{ "unix_listener/dict-async/group", "$SET:default_internal_group" },

	{ NULL, NULL }
};

struct service_settings dict_expire_service_settings = {
	.name = "dict-expire",
	.protocol = "",
	.type = "",
	.executable = "dict-expire",
	.user = "$SET:default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = ARRAY_INIT,
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_limit = 1,
	.client_limit = 1,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct dict_server_settings)

static const struct setting_define dict_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "dict_server" },

	DEF(STR_HIDDEN, base_dir),
	DEF(BOOL, verbose_proctitle),

	SETTING_DEFINE_LIST_END
};

const struct dict_server_settings dict_default_settings = {
	.base_dir = PKG_RUNDIR,
	.verbose_proctitle = VERBOSE_PROCTITLE_DEFAULT,
};

const struct setting_parser_info dict_server_setting_parser_info = {
	.name = "dict_server",

	.defines = dict_setting_defines,
	.defaults = &dict_default_settings,

	.struct_size = sizeof(struct dict_server_settings),
	.pool_offset1 = 1 + offsetof(struct dict_server_settings, pool),
};

const struct dict_server_settings *server_settings;
const struct dict_settings *dict_settings;

struct event_category dict_server_event_category = {
	.name = "dict-server",
};
