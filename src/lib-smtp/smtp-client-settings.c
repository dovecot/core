/* Copyright (c) 2026 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hostpid.h"
#include "settings-parser.h"

#include "smtp-client-settings.h"

static bool
smtp_client_settings_check(void *_set, pool_t pool, const char **error_r);
static bool
lmtp_client_settings_check(void *_set, pool_t pool, const char **error_r);

#undef DEF_BARE
#define DEF_BARE(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct smtp_client_settings)

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("smtp_client_"#name, name, struct smtp_client_settings)

#undef DEF_MSECS
#define DEF_MSECS(type, name) \
	SETTING_DEFINE_STRUCT_##type("smtp_client_"#name, name##_msecs, struct smtp_client_settings)

#undef DEF_SECS
#define DEF_SECS(type, name) \
	SETTING_DEFINE_STRUCT_##type("smtp_client_"#name, name##_secs, struct smtp_client_settings)

static const struct setting_define smtp_client_setting_defines[] = {
	DEF_BARE(STR, hostname),

	DEF(STR, source_ip),

	DEF(STR, host),
	DEF(IN_PORT, port),
	DEF(ENUM, ssl),

	DEF(PATH_DIR, rawlog_dir),

	DEF_MSECS(TIME_MSECS, command_timeout),
	DEF_MSECS(TIME_MSECS, connect_timeout),

	DEF(SIZE_HIDDEN, max_reply_size),
	DEF(SIZE_HIDDEN, max_data_chunk_size),
	DEF(UINT_HIDDEN, max_data_chunk_pipeline),

	DEF(SIZE_HIDDEN, socket_send_buffer_size),
	DEF(SIZE_HIDDEN, socket_recv_buffer_size),

	DEF(BOOL, peer_trusted),

	SETTING_DEFINE_LIST_END
};

static const struct smtp_client_settings smtp_client_default_settings = {
	.hostname = "",

	.source_ip = "",

	.host = "",
	.port = 25,
	.ssl = "no:smtps:submissions:starttls",

	.rawlog_dir = "",

	.command_timeout_msecs = SMTP_DEFAULT_COMMAND_TIMEOUT_MSECS,
	.connect_timeout_msecs = SMTP_DEFAULT_CONNECT_TIMEOUT_MSECS,

	.max_reply_size = SMTP_DEFAULT_MAX_REPLY_SIZE,
	.max_data_chunk_size = SMTP_DEFAULT_MAX_DATA_CHUNK_SIZE,
	.max_data_chunk_pipeline = SMTP_DEFAULT_MAX_DATA_CHUNK_PIPELINE,

	.socket_send_buffer_size = 0,
	.socket_recv_buffer_size = 0,

	.peer_trusted = FALSE,
};

const struct setting_parser_info smtp_client_setting_parser_info = {
	.name = "smtp_client",

	.defines = smtp_client_setting_defines,
	.defaults = &smtp_client_default_settings,

	.pool_offset1 = 1 + offsetof(struct smtp_client_settings, pool),
	.struct_size = sizeof(struct smtp_client_settings),
	.check_func = smtp_client_settings_check,
};

#undef DEF_BARE
#define DEF_BARE(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct smtp_client_settings)

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("lmtp_client_"#name, name, struct smtp_client_settings)

#undef DEF_MSECS
#define DEF_MSECS(type, name) \
	SETTING_DEFINE_STRUCT_##type("lmtp_client_"#name, name##_msecs, struct smtp_client_settings)

#undef DEF_SECS
#define DEF_SECS(type, name) \
	SETTING_DEFINE_STRUCT_##type("lmtp_client_"#name, name##_secs, struct smtp_client_settings)

static const struct setting_define lmtp_client_setting_defines[] = {
	DEF_BARE(STR, hostname),

	DEF(STR, source_ip),

	DEF(STR, host),
	DEF(IN_PORT, port),
	DEF(ENUM, ssl),

	DEF(PATH_DIR, rawlog_dir),

	DEF_MSECS(TIME_MSECS, command_timeout),
	DEF_MSECS(TIME_MSECS, connect_timeout),

	DEF(SIZE_HIDDEN, max_reply_size),
	DEF(SIZE_HIDDEN, max_data_chunk_size),
	DEF(UINT_HIDDEN, max_data_chunk_pipeline),

	DEF(SIZE_HIDDEN, socket_send_buffer_size),
	DEF(SIZE_HIDDEN, socket_recv_buffer_size),

	DEF(BOOL, peer_trusted),

	SETTING_DEFINE_LIST_END
};

static const struct smtp_client_settings lmtp_client_default_settings = {
	.hostname = "",

	.source_ip = "",

	.host = "",
	.port = 24,
	.ssl = "no:lmtps:starttls",

	.rawlog_dir = "",

	.command_timeout_msecs = SMTP_DEFAULT_COMMAND_TIMEOUT_MSECS,
	.connect_timeout_msecs = SMTP_DEFAULT_CONNECT_TIMEOUT_MSECS,

	.max_reply_size = SMTP_DEFAULT_MAX_REPLY_SIZE,
	.max_data_chunk_size = SMTP_DEFAULT_MAX_DATA_CHUNK_SIZE,
	.max_data_chunk_pipeline = SMTP_DEFAULT_MAX_DATA_CHUNK_PIPELINE,

	.socket_send_buffer_size = 0,
	.socket_recv_buffer_size = 0,

	.peer_trusted = FALSE,
};

const struct setting_parser_info lmtp_client_setting_parser_info = {
	.name = "lmtp_client",

	.defines = lmtp_client_setting_defines,
	.defaults = &lmtp_client_default_settings,

	.pool_offset1 = 1 + offsetof(struct smtp_client_settings, pool),
	.struct_size = sizeof(struct smtp_client_settings),
	.check_func = lmtp_client_settings_check,
};

/* <settings checks> */
static bool
smtp_client_settings_check_common(struct smtp_client_settings *set, pool_t pool,
				  const char *protocol, const char **error_r)
{
	int ret;

#ifndef CONFIG_BINARY
	if (*set->hostname == '\0')
		set->hostname = p_strdup(pool, my_hostdomain());
#endif
	if (set->max_data_chunk_size == 0) {
		*error_r = t_strdup_printf(
			"%s_client_max_data_chunk_size must not be 0",
			protocol);
		return FALSE;
	}
	if (set->max_data_chunk_pipeline == 0) {
		*error_r = t_strdup_printf(
			"%s_client_max_data_chunk_pipeline must not be 0",
			protocol);
		return FALSE;
	}
	if (set->command_timeout_msecs == 0) {
		*error_r = t_strdup_printf(
			"%s_client_command_timeout must not be 0", protocol);
		return FALSE;
	}
	if (set->connect_timeout_msecs == 0) {
		*error_r = t_strdup_printf(
			"%s_client_connect_timeout must not be 0", protocol);
		return FALSE;
	}

	ret = (*set->source_ip == '\0' ?
	       0 : net_addr2ip(set->source_ip, &set->parsed.source_ip));
	if (ret < 0) {
		*error_r = t_strdup_printf(
			"%s_client_source_ip: Invalid IP address: %s",
			protocol, set->source_ip);
		return FALSE;
	}
	return TRUE;
}

static bool
smtp_client_settings_check(void *_set, pool_t pool, const char **error_r)
{
	struct smtp_client_settings *set = _set;

	if (!smtp_client_settings_check_common(set, pool, "smtp", error_r))
		return FALSE;

	if (strcmp(set->ssl, "smtps") == 0 ||
	    strcmp(set->ssl, "submissions") == 0)
		set->parsed.ssl_mode = SMTP_CLIENT_SSL_MODE_IMMEDIATE;
	else if (strcmp(set->ssl, "starttls") == 0)
		set->parsed.ssl_mode = SMTP_CLIENT_SSL_MODE_STARTTLS;
	else
		set->parsed.ssl_mode = SMTP_CLIENT_SSL_MODE_NONE;
	return TRUE;
}

static bool
lmtp_client_settings_check(void *_set, pool_t pool, const char **error_r)
{
	struct smtp_client_settings *set = _set;

	if (!smtp_client_settings_check_common(set, pool, "lmtp", error_r))
		return FALSE;

	if (strcmp(set->ssl, "lmtps") == 0)
		set->parsed.ssl_mode = SMTP_CLIENT_SSL_MODE_IMMEDIATE;
	else if (strcmp(set->ssl, "starttls") == 0)
		set->parsed.ssl_mode = SMTP_CLIENT_SSL_MODE_STARTTLS;
	else
		set->parsed.ssl_mode = SMTP_CLIENT_SSL_MODE_NONE;
	return TRUE;
}
/* </settings checks> */

const struct smtp_client_settings *
smtp_client_settings_ref(pool_t pool, enum smtp_protocol protocol,
			 const struct smtp_client_settings *set)
{
	if (set->pool != NULL) {
		/* Proper persistent settings struct with a pool: just add
		   reference to the pool. */
		pool_ref(set->pool);
		return set;
	}

	/* Settings struct allocated temporarily (on stack and/or data stack):
	   Allocate a new struct on our pool, apply defaults and clone the
	   filled-in contents of the source. */

	struct smtp_client_settings *set_new;

	set_new = p_new(pool, struct smtp_client_settings, 1);
	switch (protocol) {
	case SMTP_PROTOCOL_SMTP:
		*set_new = smtp_client_default_settings;
		break;
	case SMTP_PROTOCOL_LMTP:
		*set_new = lmtp_client_default_settings;
		break;
	default:
		i_unreached();
	}
	set_new->pool = pool;
	pool_ref(pool);

	if (set->hostname != NULL && *set->hostname != '\0')
		set_new->hostname = p_strdup(pool, set->hostname);
	else
		set_new->hostname = p_strdup(pool, my_hostdomain());

	if (set->parsed.source_ip.family != 0)
		set_new->parsed.source_ip = set->parsed.source_ip;

	if (set->rawlog_dir != NULL && *set->rawlog_dir != '\0')
		set_new->rawlog_dir = p_strdup(pool, set->rawlog_dir);

	if (set->command_timeout_msecs != 0)
		set_new->command_timeout_msecs = set->command_timeout_msecs;
	if (set->connect_timeout_msecs != 0)
		set_new->connect_timeout_msecs = set->connect_timeout_msecs;

	if (set->max_reply_size != 0)
		set_new->max_reply_size = set->max_reply_size;
	if (set->max_data_chunk_size != 0)
		set_new->max_data_chunk_size = set->max_data_chunk_size;
	if (set->max_data_chunk_pipeline != 0)
		set_new->max_data_chunk_pipeline = set->max_data_chunk_pipeline;

	if (set->socket_send_buffer_size != 0)
		set_new->socket_send_buffer_size = set->socket_send_buffer_size;
	if (set->socket_recv_buffer_size != 0)
		set_new->socket_recv_buffer_size = set->socket_recv_buffer_size;

	set_new->peer_trusted = set->peer_trusted;

	return set_new;
}
