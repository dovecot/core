/* Copyright (c) Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings.h"
#include "settings-parser.h"

#include "dsasl-client-gssapi-settings.h"

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("client_auth_gssapi_"#name, name, \
				     struct dsasl_client_gssapi_settings)

static const struct setting_define dsasl_client_gssapi_setting_defines[] = {
	DEF(BOOL, channel_binding),

	SETTING_DEFINE_LIST_END
};

static const struct dsasl_client_gssapi_settings
dsasl_client_gssapi_default_settings = {
	.channel_binding = TRUE,
};

const struct setting_parser_info dsasl_client_gssapi_setting_parser_info = {
	.name = "dsasl_client_gssapi",

	.defines = dsasl_client_gssapi_setting_defines,
	.defaults = &dsasl_client_gssapi_default_settings,

	.pool_offset1 = 1 + offsetof(struct dsasl_client_gssapi_settings, pool),
	.struct_size = sizeof(struct dsasl_client_gssapi_settings),
};

int dsasl_client_gssapi_settings_equal(struct event *event1,
				       struct event *event2,
				       const char **error_r)
{
	const struct dsasl_client_gssapi_settings *set1, *set2;
	int ret;

	if (settings_get(event1, &dsasl_client_gssapi_setting_parser_info, 0,
			 &set1, error_r) < 0)
		return -1;
	if (settings_get(event2, &dsasl_client_gssapi_setting_parser_info, 0,
			 &set2, error_r) < 0) {
		settings_free(set1);
		return -1;
	}
	ret = settings_equal(&dsasl_client_gssapi_setting_parser_info,
			     set1, set2, NULL) ? 1 : 0;
	settings_free(set1);
	settings_free(set2);
	return ret;
}
