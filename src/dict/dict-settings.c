/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "service-settings.h"
#include "dict-settings.h"

/* <settings checks> */
static struct file_listener_settings dict_unix_listeners_array[] = {
	{ "dict", 0600, "", "" }
};
static struct file_listener_settings *dict_unix_listeners[] = {
	&dict_unix_listeners_array[0]
};
static buffer_t dict_unix_listeners_buf = {
	dict_unix_listeners, sizeof(dict_unix_listeners), { 0, }
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
	.vsz_limit = (uoff_t)-1,

	.unix_listeners = { { &dict_unix_listeners_buf,
			      sizeof(dict_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct dict_settings, name), NULL }

static const struct setting_define dict_setting_defines[] = {
	DEF(SET_STR, base_dir),
	DEF(SET_STR, dict_db_config),
	{ SET_STRLIST, "dict", offsetof(struct dict_settings, dicts), NULL },

	SETTING_DEFINE_LIST_END
};

const struct dict_settings dict_default_settings = {
	.base_dir = PKG_RUNDIR,
	.dict_db_config = "",
	.dicts = ARRAY_INIT
};

const struct setting_parser_info dict_setting_parser_info = {
	.module_name = "dict",
	.defines = dict_setting_defines,
	.defaults = &dict_default_settings,

	.type_offset = (size_t)-1,
	.struct_size = sizeof(struct dict_settings),

	.parent_offset = (size_t)-1
};

const struct dict_settings *dict_settings;
