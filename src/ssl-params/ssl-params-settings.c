/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

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
	.name = "ssl-params",
	.protocol = "",
#ifdef HAVE_SSL
	.type = "startup",
#else
	.type = "",
#endif
	.executable = "ssl-params",
	.user = "",
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
	.vsz_limit = (uoff_t)-1,

	.unix_listeners = { { &ssl_params_unix_listeners_buf,
			      sizeof(ssl_params_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct ssl_params_settings, name), NULL }

static const struct setting_define ssl_params_setting_defines[] = {
	DEF(SET_UINT, ssl_parameters_regenerate),

	SETTING_DEFINE_LIST_END
};

static const struct ssl_params_settings ssl_params_default_settings = {
	.ssl_parameters_regenerate = 24*7
};

const struct setting_parser_info ssl_params_setting_parser_info = {
	.module_name = "ssl-params",
	.defines = ssl_params_setting_defines,
	.defaults = &ssl_params_default_settings,

	.type_offset = (size_t)-1,
	.struct_size = sizeof(struct ssl_params_settings),

	.parent_offset = (size_t)-1
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
