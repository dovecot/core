/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "http-request.h"
#include "http-client-private.h"

static bool
http_client_settings_check(void *_set, pool_t pool, const char **error_r);

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("http_client_"#name, name, struct http_client_settings)

#undef DEF_MSECS
#define DEF_MSECS(type, name) \
	SETTING_DEFINE_STRUCT_##type("http_client_"#name, name##_msecs, struct http_client_settings)

#undef DEF_SECS
#define DEF_SECS(type, name) \
	SETTING_DEFINE_STRUCT_##type("http_client_"#name, name##_secs, struct http_client_settings)

static const struct setting_define http_client_setting_defines[] = {
	SETTING_DEFINE_STRUCT_STR_HIDDEN("base_dir", base_dir,
					 struct http_client_settings),
	DEF(STR_HIDDEN, dns_client_socket_path),
	DEF_MSECS(TIME_MSECS_HIDDEN, dns_ttl),

	DEF(STR_HIDDEN, user_agent),

	DEF(STR, proxy_socket_path),
	DEF(STR, proxy_url),
	DEF(STR, proxy_username),
	DEF(STR, proxy_password),

	DEF(STR, rawlog_dir),

	DEF_MSECS(TIME_MSECS, max_idle_time),
	DEF(UINT, max_parallel_connections),
	DEF(UINT, max_pipelined_requests),

	DEF(BOOL_HIDDEN, auto_redirect),
	DEF(BOOL_HIDDEN, auto_retry),
	DEF(BOOL, proxy_ssl_tunnel),

	DEF(UINT, request_max_redirects),
	DEF(UINT, request_max_attempts),
	DEF(UINT, read_request_max_attempts),
	DEF(UINT, write_request_max_attempts),
	DEF(UINT, delete_request_max_attempts),
	DEF(UINT, max_connect_attempts),

	DEF_MSECS(TIME_MSECS_HIDDEN, connect_backoff_time),
	DEF_MSECS(TIME_MSECS_HIDDEN, connect_backoff_max_time),

	DEF(SIZE_HIDDEN, response_hdr_max_size),
	DEF(SIZE_HIDDEN, response_hdr_max_field_size),
	DEF(UINT_HIDDEN, response_hdr_max_fields),

	DEF_MSECS(TIME_MSECS, request_absolute_timeout),
	DEF_MSECS(TIME_MSECS, request_timeout),
	DEF_MSECS(TIME_MSECS, read_request_timeout),
	DEF_MSECS(TIME_MSECS, write_request_timeout),
	DEF_MSECS(TIME_MSECS, delete_request_timeout),
	DEF_MSECS(TIME_MSECS, connect_timeout),
	DEF_MSECS(TIME_MSECS_HIDDEN, soft_connect_timeout),
	DEF_SECS(TIME_HIDDEN, max_auto_retry_delay),

	DEF(SIZE_HIDDEN, socket_send_buffer_size),
	DEF(SIZE_HIDDEN, socket_recv_buffer_size),

	SETTING_DEFINE_LIST_END
};

static const struct http_client_settings http_client_default_settings = {
	.base_dir = PKG_RUNDIR,
	.dns_client_socket_path = "dns-client",
	.dns_ttl_msecs = HTTP_CLIENT_DEFAULT_DNS_TTL_MSECS,
	.user_agent = "",

	.proxy_socket_path = "",
	.proxy_url = "",
	.proxy_username = "",
	.proxy_password = "",

	.rawlog_dir = "",

	.max_idle_time_msecs = 0,
	.max_parallel_connections = 1,
	.max_pipelined_requests = 1,

	.auto_redirect = TRUE,
	.auto_retry = TRUE,
	.proxy_ssl_tunnel = TRUE,

	.request_max_redirects = 0,
	.request_max_attempts = 1,
	.read_request_max_attempts = 0,
	.write_request_max_attempts = 0,
	.delete_request_max_attempts = 0,
	.max_connect_attempts = 0,

	.connect_backoff_time_msecs = HTTP_CLIENT_DEFAULT_BACKOFF_TIME_MSECS,
	.connect_backoff_max_time_msecs = HTTP_CLIENT_DEFAULT_BACKOFF_MAX_TIME_MSECS,

	.response_hdr_max_size = HTTP_REQUEST_DEFAULT_MAX_HEADER_SIZE,
	.response_hdr_max_field_size = HTTP_REQUEST_DEFAULT_MAX_HEADER_FIELD_SIZE,
	.response_hdr_max_fields = HTTP_REQUEST_DEFAULT_MAX_HEADER_FIELDS,

	.request_absolute_timeout_msecs = 0,
	.request_timeout_msecs = HTTP_CLIENT_DEFAULT_REQUEST_TIMEOUT_MSECS,
	.read_request_timeout_msecs = 0,
	.write_request_timeout_msecs = 0,
	.delete_request_timeout_msecs = 0,
	.connect_timeout_msecs = 0,
	.soft_connect_timeout_msecs = 0,
	.max_auto_retry_delay_secs = 0,

	.socket_send_buffer_size = 0,
	.socket_recv_buffer_size = 0,
};

const struct setting_parser_info http_client_setting_parser_info = {
	.name = "http_client",

	.defines = http_client_setting_defines,
	.defaults = &http_client_default_settings,

	.pool_offset1 = 1 + offsetof(struct http_client_settings, pool),
	.struct_size = sizeof(struct http_client_settings),
	.check_func = http_client_settings_check,
};

/* <settings checks> */
static bool
http_client_settings_check(void *_set, pool_t pool, const char **error_r)
{
	struct http_client_settings *set = _set;
	const char *error;

	if (set->proxy_url[0] != '\0') {
		if (http_url_parse(set->proxy_url, NULL, 0, pool,
				   &set->parsed_proxy_url, &error) < 0) {
			*error_r = t_strdup_printf(
				"Invalid http_client_proxy_url: %s", error);
			return FALSE;
		}
	}
	if (set->request_max_attempts == 0) {
		*error_r = "request_max_attempts must not be 0";
		return FALSE;
	}
	if (set->max_pipelined_requests == 0) {
		*error_r = "http_client_max_pipelined_requests must not be 0";
		return FALSE;
	}
	if (set->max_parallel_connections == 0) {
		*error_r = "http_client_max_parallel_connections must not be 0";
		return FALSE;
	}
	if (set->connect_backoff_time_msecs == 0) {
		*error_r = "http_client_connect_backoff_time_msecs must not be 0";
		return FALSE;
	}
	if (set->connect_backoff_max_time_msecs < set->connect_backoff_time_msecs) {
		*error_r = t_strdup_printf(
			"http_client_connect_backoff_time_msecs (%u) "
			"must not be smaller than "
			"http_client_connect_backoff_max_time_msecs (%u)",
			set->connect_backoff_max_time_msecs,
			set->connect_backoff_time_msecs);
		return FALSE;
	}
	if (set->request_timeout_msecs == 0) {
		*error_r = "http_client_request_timeout_msecs must not be 0";
		return FALSE;
	}
	return TRUE;
}
/* </settings checks> */
