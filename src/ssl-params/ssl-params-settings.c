/* Copyright (c) 2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "master-service-settings.h"
#include "ssl-params-settings.h"

#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct ssl_params_settings, name), NULL }

static struct setting_define ssl_params_setting_defines[] = {
	DEF(SET_UINT, ssl_parameters_regenerate),

	SETTING_DEFINE_LIST_END
};

static struct ssl_params_settings ssl_params_default_settings = {
	MEMBER(ssl_parameters_regenerate) 24*7
};

struct setting_parser_info ssl_params_setting_parser_info = {
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
