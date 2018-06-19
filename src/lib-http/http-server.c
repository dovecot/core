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
#include "http-url.h"

#include "http-server-private.h"

/*
 * Server
 */

struct http_server *http_server_init(const struct http_server_settings *set)
{
	struct http_server *server;
	pool_t pool;
	size_t pool_size;

	pool_size = (set->ssl != NULL) ? 10240 : 1024; /* ca/cert/key will be >8K */
	pool = pool_alloconly_create("http server", pool_size);
	server = p_new(pool, struct http_server, 1);
	server->pool = pool;
	if (set->rawlog_dir != NULL && *set->rawlog_dir != '\0')
		server->set.rawlog_dir = p_strdup(pool, set->rawlog_dir);
	if (set->ssl != NULL) {
		server->set.ssl =
			ssl_iostream_settings_dup(server->pool, set->ssl);
	}
	server->set.max_client_idle_time_msecs = set->max_client_idle_time_msecs;
	server->set.max_pipelined_requests =
		(set->max_pipelined_requests > 0 ? set->max_pipelined_requests : 1);
	server->set.request_limits = set->request_limits;
	server->set.socket_send_buffer_size = set->socket_send_buffer_size;
	server->set.socket_recv_buffer_size = set->socket_recv_buffer_size;
	server->set.debug = set->debug;

	server->conn_list = http_server_connection_list_init();

	return server;
}

void http_server_deinit(struct http_server **_server)
{
	struct http_server *server = *_server;

	*_server = NULL;

	connection_list_deinit(&server->conn_list);

	if (server->ssl_ctx != NULL)
		ssl_iostream_context_unref(&server->ssl_ctx);
	pool_unref(&server->pool);
}

void http_server_switch_ioloop(struct http_server *server)
{
	struct connection *_conn = server->conn_list->connections;

	/* move connections */
	/* FIXME: we wouldn't necessarily need to switch all of them
	   immediately, only those that have requests now. but also connections
	   that get new requests before ioloop is switched again.. */
	for (; _conn != NULL; _conn = _conn->next) {
		struct http_server_connection *conn =
			(struct http_server_connection *)_conn;

		http_server_connection_switch_ioloop(conn);
	}
}

void http_server_shut_down(struct http_server *server)
{
	struct connection *_conn, *_next;

	server->shutting_down = TRUE;

	for (_conn = server->conn_list->connections;
		_conn != NULL; _conn = _next) {
		struct http_server_connection *conn =
			(struct http_server_connection *)_conn;

		_next = _conn->next;
		(void)http_server_connection_shut_down(conn);
	}
}

int http_server_init_ssl_ctx(struct http_server *server, const char **error_r)
{
	const char *error;

	if (server->set.ssl == NULL || server->ssl_ctx != NULL)
		return 0;

	if (ssl_iostream_server_context_cache_get(server->set.ssl,
		&server->ssl_ctx, &error) < 0) {
		*error_r = t_strdup_printf("Couldn't initialize SSL context: %s",
					   error);
		return -1;
	}
	return 0;
}
