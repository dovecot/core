/* Copyright (c) 2009 Dovecot authors, see the included COPYING file */

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
	MEMBER(name) "dict",
	MEMBER(protocol) "",
	MEMBER(type) "",
	MEMBER(executable) "dict",
	MEMBER(user) "dovecot",
	MEMBER(group) "",
	MEMBER(privileged_group) "",
	MEMBER(extra_groups) "",
	MEMBER(chroot) "",

	MEMBER(drop_priv_before_exec) FALSE,

	MEMBER(process_min_avail) 0,
	MEMBER(process_limit) 0,
	MEMBER(client_limit) 0,
	MEMBER(service_count) 0,
	MEMBER(vsz_limit) -1U,

	MEMBER(unix_listeners) { { &dict_unix_listeners_buf,
				   sizeof(dict_unix_listeners[0]) } },
	MEMBER(fifo_listeners) ARRAY_INIT,
	MEMBER(inet_listeners) ARRAY_INIT
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
	MEMBER(base_dir) PKG_RUNDIR,
	MEMBER(dict_db_config) "",
	MEMBER(dicts) ARRAY_INIT
};

const struct setting_parser_info dict_setting_parser_info = {
	MEMBER(module_name) "dict",
	MEMBER(defines) dict_setting_defines,
	MEMBER(defaults) &dict_default_settings,

	MEMBER(type_offset) (size_t)-1,
	MEMBER(struct_size) sizeof(struct dict_settings),

	MEMBER(parent_offset) (size_t)-1
};

const struct dict_settings *dict_settings;
