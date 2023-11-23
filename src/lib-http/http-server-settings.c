/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "http-request.h"
#include "http-server.h"

static bool
http_server_settings_check(void *_set, pool_t pool, const char **error_r);

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("http_server_"#name, name, struct http_server_settings)

#undef DEF_MSECS
#define DEF_MSECS(type, name) \
	SETTING_DEFINE_STRUCT_##type("http_server_"#name, name##_msecs, struct http_server_settings)

static const struct setting_define http_server_setting_defines[] = {
	SETTING_DEFINE_STRUCT_STR_HIDDEN("base_dir", base_dir,
					 struct http_server_settings),
	DEF(STR, rawlog_dir),
	DEF_MSECS(TIME_MSECS, max_client_idle_time),
	DEF(UINT, max_pipelined_requests),

	DEF(SIZE_HIDDEN, request_max_target_length),
	DEF(SIZE_HIDDEN, request_max_payload_size),

	DEF(SIZE_HIDDEN, request_hdr_max_size),
	DEF(SIZE_HIDDEN, request_hdr_max_field_size),
	DEF(UINT_HIDDEN, request_hdr_max_fields),

	DEF(STR_HIDDEN, default_host),
	DEF(SIZE_HIDDEN, socket_send_buffer_size),
	DEF(SIZE_HIDDEN, socket_recv_buffer_size),
	SETTING_DEFINE_LIST_END
};

static const struct http_server_settings http_server_default_settings = {
	.base_dir = PKG_RUNDIR,

	.rawlog_dir = "",
	.max_client_idle_time_msecs = 0,
	.max_pipelined_requests = 1,

	.request_max_target_length = 0,
	.request_max_payload_size = HTTP_SERVER_DEFAULT_MAX_PAYLOAD_SIZE,

	.request_hdr_max_size = 0,
	.request_hdr_max_field_size = 0,
	.request_hdr_max_fields = 0,

	.default_host = "",
	.socket_send_buffer_size = 0,
	.socket_recv_buffer_size = 0,
};

const struct setting_parser_info http_server_setting_parser_info = {
	.name = "http_server",

	.defines = http_server_setting_defines,
	.defaults = &http_server_default_settings,

	.pool_offset1 = 1 + offsetof(struct http_server_settings, pool),
	.struct_size = sizeof(struct http_server_settings),
	.check_func = http_server_settings_check,
};

/* <settings checks> */
static bool
http_server_settings_check(void *_set, pool_t pool ATTR_UNUSED,
			   const char **error_r)
{
	struct http_server_settings *set = _set;

	if (set->max_pipelined_requests == 0) {
		*error_r = "http_server_max_pipelined_requests must not be 0";
		return FALSE;
	}
	return TRUE;
}
/* </settings checks> */
