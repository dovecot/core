/* Copyright (c) 2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "service-settings.h"
#include "master-service-settings.h"
#include "ssl-params-settings.h"

#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

/* <settings checks> */
static struct file_listener_settings ssl_params_unix_listeners_array[] = {
	{ "login/ssl-params", 0666, "", "" }
};
static struct file_listener_settings *ssl_params_unix_listeners[] = {
	&ssl_params_unix_listeners_array[0]
};
static buffer_t ssl_params_unix_listeners_buf = {
	ssl_params_unix_listeners, sizeof(ssl_params_unix_listeners), { 0, }
};
/* </settings checks> */

struct service_settings ssl_params_service_settings = {
	MEMBER(name) "ssl-params",
	MEMBER(protocol) "",
	MEMBER(type) "",
	MEMBER(executable) "ssl-params",
	MEMBER(user) "",
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

	MEMBER(unix_listeners) { { &ssl_params_unix_listeners_buf,
				   sizeof(ssl_params_unix_listeners[0]) } },
	MEMBER(fifo_listeners) ARRAY_INIT,
	MEMBER(inet_listeners) ARRAY_INIT
};

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct ssl_params_settings, name), NULL }

static const struct setting_define ssl_params_setting_defines[] = {
	DEF(SET_UINT, ssl_parameters_regenerate),

	SETTING_DEFINE_LIST_END
};

static const struct ssl_params_settings ssl_params_default_settings = {
	MEMBER(ssl_parameters_regenerate) 24*7
};

const struct setting_parser_info ssl_params_setting_parser_info = {
	MEMBER(module_name) "ssl-params",
	MEMBER(defines) ssl_params_setting_defines,
	MEMBER(defaults) &ssl_params_default_settings,

	MEMBER(type_offset) (size_t)-1,
	MEMBER(struct_size) sizeof(struct ssl_params_settings),

	MEMBER(parent_offset) (size_t)-1
};

struct ssl_params_settings *
ssl_params_settings_read(struct master_service *service)
{
	static const struct setting_parser_info *set_roots[] = {
		&ssl_params_setting_parser_info,
		NULL
	};
	const char *error;
	void **sets;

	if (master_service_settings_read_simple(service, set_roots, &error) < 0)
		i_fatal("Error reading configuration: %s", error);

	sets = master_service_settings_get_others(service);
	return sets[0];
}
