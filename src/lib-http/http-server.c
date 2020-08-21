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
#include "settings.h"
#include "http-url.h"

#include "http-server-private.h"

static struct event_category event_category_http_server = {
	.name = "http-server"
};

/*
 * Server
 */

int http_server_init_auto(struct event *event_parent,
                          struct http_server **server_r, const char **error_r)
{
       const struct http_server_settings *set;
       if (settings_get(event_parent, &http_server_setting_parser_info,
                        0, &set, error_r) < 0)
               return -1;
       *server_r = http_server_init(set, event_parent);
       settings_free(set);
       return 0;
}

void http_server_settings_init(pool_t pool, struct http_server_settings *set_r)
{
	i_zero(set_r);
	set_r->pool = pool;
	set_r->base_dir = PKG_RUNDIR;
	set_r->default_host = "";
	set_r->max_pipelined_requests = 1;
	set_r->request_max_payload_size = HTTP_SERVER_DEFAULT_MAX_PAYLOAD_SIZE;
}

struct http_server *http_server_init(const struct http_server_settings *set,
				     struct event *event_parent)
{
	struct http_server *server;
	pool_t pool;

	pool = pool_alloconly_create("http server", 1024);
	server = p_new(pool, struct http_server, 1);
	server->pool = pool;

	server->set = set;
	pool_ref(set->pool);

	server->event = event_create(event_parent);
	event_add_category(server->event, &event_category_http_server);
	event_set_append_log_prefix(server->event, "http-server: ");

	server->conn_list = http_server_connection_list_init();

	settings_free(server->ssl_set);
	p_array_init(&server->resources, pool, 4);
	p_array_init(&server->locations, pool, 4);

	return server;
}

void http_server_deinit(struct http_server **_server)
{
	struct http_server *server = *_server;
	struct http_server_resource *res;

	*_server = NULL;

	connection_list_deinit(&server->conn_list);

	array_foreach_elem(&server->resources, res)
		http_server_resource_free(&res);
	i_assert(array_count(&server->locations) == 0);

	event_unref(&server->event);
	settings_free(server->set);
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
	struct connection *_conn;

	server->shutting_down = TRUE;

	_conn = server->conn_list->connections;
	while (_conn != NULL) {
		struct http_server_connection *conn =
			(struct http_server_connection *)_conn;
		struct connection *_next = _conn->next;

		(void)http_server_connection_shut_down(conn);
		_conn = _next;
	}
}

void http_server_set_ssl_settings(struct http_server *server,
				  const struct ssl_iostream_settings *ssl)
{
	settings_free(server->ssl_set);
	server->ssl_set = ssl;
	pool_ref(server->ssl_set->pool);
}
