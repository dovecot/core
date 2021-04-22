/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "service-settings.h"
#include "dict-settings.h"

/* <settings checks> */
static struct file_listener_settings dict_unix_listeners_array[] = {
	{ "dict", 0660, "", "$default_internal_group" }
};
static struct file_listener_settings *dict_unix_listeners[] = {
	&dict_unix_listeners_array[0]
};
static buffer_t dict_unix_listeners_buf = {
	{ { dict_unix_listeners, sizeof(dict_unix_listeners) } }
};

static struct file_listener_settings dict_async_unix_listeners_array[] = {
	{ "dict-async", 0660, "", "$default_internal_group" }
};
static struct file_listener_settings *dict_async_unix_listeners[] = {
	&dict_async_unix_listeners_array[0]
};
static buffer_t dict_async_unix_listeners_buf = {
	{ { dict_async_unix_listeners, sizeof(dict_async_unix_listeners) } }
};
/* </settings checks> */

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

	.unix_listeners = { { &dict_unix_listeners_buf,
			      sizeof(dict_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
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

	.unix_listeners = { { &dict_async_unix_listeners_buf,
			      sizeof(dict_async_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct dict_server_settings)

static const struct setting_define dict_setting_defines[] = {
	DEF(STR, base_dir),
	DEF(BOOL, verbose_proctitle),

	DEF(STR, dict_db_config),
	{ .type = SET_STRLIST, .key = "dict",
	  .offset = offsetof(struct dict_server_settings, dicts) },

	SETTING_DEFINE_LIST_END
};

const struct dict_server_settings dict_default_settings = {
	.base_dir = PKG_RUNDIR,
	.verbose_proctitle = FALSE,

	.dict_db_config = "",
	.dicts = ARRAY_INIT
};

const struct setting_parser_info dict_setting_parser_info = {
	.module_name = "dict",
	.defines = dict_setting_defines,
	.defaults = &dict_default_settings,

	.type_offset = SIZE_MAX,
	.struct_size = sizeof(struct dict_server_settings),

	.parent_offset = SIZE_MAX
};

const struct dict_server_settings *dict_settings;
