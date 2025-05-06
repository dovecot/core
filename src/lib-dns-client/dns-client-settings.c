/* Copyright (c) 2005-2024 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "dns-lookup.h"
#include "strfuncs.h"

static bool dns_client_settings_check(void *_set, pool_t pool,
				      const char **error_r);

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct dns_client_settings)

#undef DEF_MSECS
#define DEF_MSECS(type, name) \
	SETTING_DEFINE_STRUCT_##type("dns_client_"#name, name##_msecs, struct dns_client_settings)

static const struct setting_define dns_client_setting_defines[] = {
	DEF(STR_HIDDEN, dns_client_socket_path),
	DEF(STR_HIDDEN, base_dir),
	DEF_MSECS(TIME_MSECS, timeout),

	SETTING_DEFINE_LIST_END
};

static const struct dns_client_settings dns_client_default_settings = {
	.dns_client_socket_path = "dns-client",
	.base_dir = PKG_RUNDIR,
	.timeout_msecs = 10 * 1000,
};

const struct setting_parser_info dns_client_setting_parser_info = {
    .name = "dns_client",

    .defines = dns_client_setting_defines,
    .defaults = &dns_client_default_settings,

    .pool_offset1 = 1 + offsetof(struct dns_client_settings, pool),
    .struct_size = sizeof(struct dns_client_settings),
    .check_func = dns_client_settings_check,
};

/* <settings checks> */
static bool
dns_client_settings_check(void *_set, pool_t pool, const char **error_r ATTR_UNUSED)
{
	struct dns_client_settings *set = _set;
	size_t len;
	len = strlen(set->base_dir);
	if (len > 0 &&
	    set->dns_client_socket_path[0] != '\0' &&
	    !str_begins_with(set->dns_client_socket_path, "./")) {
		if (set->base_dir[len - 1] == '/')
			set->base_dir = p_strndup(pool, set->base_dir, len);
		set->dns_client_socket_path = p_strconcat(pool, set->base_dir, "/",
							  set->dns_client_socket_path, NULL);
	}
	return TRUE;
}
/* </settings checks> */
