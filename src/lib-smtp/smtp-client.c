/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "net.h"
#include "str.h"
#include "hash.h"
#include "array.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "connection.h"
#include "dns-lookup.h"
#include "iostream-rawlog.h"
#include "iostream-ssl.h"

#include "smtp-client-private.h"

#define SMTP_DEFAULT_PORT 80
#define SSMTP_DEFAULT_PORT 465

/*
 * Client
 */

struct smtp_client *smtp_client_init(const struct smtp_client_settings *set)
{
	struct smtp_client *client;
	pool_t pool;

	pool = pool_alloconly_create("smtp client", 1024);
	client = p_new(pool, struct smtp_client, 1);
	client->pool = pool;

	client->set.my_ip = set->my_ip;
	client->set.my_hostname = p_strdup(pool, set->my_hostname);

	client->set.forced_capabilities = set->forced_capabilities;
	if (set->extra_capabilities != NULL) {
		client->set.extra_capabilities =
			p_strarray_dup(pool, set->extra_capabilities);
	}

	client->set.dns_client = set->dns_client;
	client->set.dns_client_socket_path =
		p_strdup(pool, set->dns_client_socket_path);
	client->set.rawlog_dir = p_strdup_empty(pool, set->rawlog_dir);

	if (set->ssl != NULL) {
		client->set.ssl =
			ssl_iostream_settings_dup(client->pool, set->ssl);
	}

	client->set.master_user = p_strdup_empty(pool, set->master_user);
	client->set.username = p_strdup_empty(pool, set->username);
	client->set.sasl_mech = set->sasl_mech;
	if (set->sasl_mech == NULL) {
		client->set.sasl_mechanisms =
			p_strdup(pool, set->sasl_mechanisms);
	}

	client->set.connect_timeout_msecs = set->connect_timeout_msecs != 0 ?
		set->connect_timeout_msecs :
		SMTP_DEFAULT_CONNECT_TIMEOUT_MSECS;
	client->set.command_timeout_msecs = set->command_timeout_msecs != 0 ?
		set->command_timeout_msecs :
		SMTP_DEFAULT_COMMAND_TIMEOUT_MSECS;
	client->set.max_reply_size = set->max_reply_size != 0 ?
		set->max_reply_size : SMTP_DEFAULT_MAX_REPLY_SIZE;
	client->set.max_data_chunk_size = set->max_data_chunk_size != 0 ?
		set->max_data_chunk_size : SMTP_DEFAULT_MAX_DATA_CHUNK_SIZE;
	client->set.max_data_chunk_pipeline = set->max_data_chunk_pipeline != 0 ?
		set->max_data_chunk_pipeline : SMTP_DEFAULT_MAX_DATA_CHUNK_PIPELINE;

	client->set.socket_send_buffer_size = set->socket_send_buffer_size;
	client->set.socket_recv_buffer_size = set->socket_recv_buffer_size;
	client->set.debug = set->debug;

	client->set.proxy_data.source_ip = set->proxy_data.source_ip;
	client->set.proxy_data.source_port = set->proxy_data.source_port;
	client->set.proxy_data.ttl_plus_1 = set->proxy_data.ttl_plus_1;
	client->set.proxy_data.timeout_secs = set->proxy_data.timeout_secs;
	client->set.proxy_data.helo = p_strdup_empty(pool, set->proxy_data.helo);
	client->set.proxy_data.login = p_strdup_empty(pool, set->proxy_data.login);

	client->conn_list = smtp_client_connection_list_init();

	return client;
}

void smtp_client_deinit(struct smtp_client **_client)
{
	struct smtp_client *client = *_client;

	connection_list_deinit(&client->conn_list);

	if (client->ssl_ctx != NULL)
		ssl_iostream_context_unref(&client->ssl_ctx);
	pool_unref(&client->pool);
	*_client = NULL;
}

void smtp_client_switch_ioloop(struct smtp_client *client)
{
	struct connection *_conn = client->conn_list->connections;

	/* move connections */
	for (; _conn != NULL; _conn = _conn->next) {
		struct smtp_client_connection *conn =
			(struct smtp_client_connection *)_conn;

		smtp_client_connection_switch_ioloop(conn);
	}
}

int smtp_client_init_ssl_ctx(struct smtp_client *client, const char **error_r)
{
	const char *error;

	if (client->ssl_ctx != NULL)
		return 0;

	if (client->set.ssl == NULL) {
		*error_r = "Requested SSL connection, but no SSL settings given";
		return -1;
	}
	if (ssl_iostream_client_context_cache_get(client->set.ssl,
		&client->ssl_ctx, &error) < 0) {
		*error_r = t_strdup_printf("Couldn't initialize SSL context: %s",
					   error);
		return -1;
	}
	return 0;
}

// FIXME: Implement smtp_client_run()
