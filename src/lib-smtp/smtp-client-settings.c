/* Copyright (c) 2026 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hostpid.h"

#include "smtp-client-settings.h"

static const struct smtp_client_settings smtp_client_default_settings = {
	.my_hostname = "",

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

static const struct smtp_client_settings lmtp_client_default_settings = {
	.my_hostname = "",

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

	if (set->my_ip.family != 0)
		set_new->my_ip = set->my_ip;
	if (set->my_hostname != NULL && *set->my_hostname != '\0')
		set_new->my_hostname = p_strdup(pool, set->my_hostname);
	else
		set_new->my_hostname = p_strdup(pool, my_hostdomain());

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
