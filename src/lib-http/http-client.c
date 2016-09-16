/* Copyright (c) 2013-2016 Dovecot authors, see the included COPYING file */

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

#include "http-client-private.h"

#define HTTP_DEFAULT_PORT 80
#define HTTPS_DEFAULT_PORT 443

/* Structure:

	 http-client:

	 Acts much like a browser; it is not dedicated to a single host. Client can
   accept requests to different hosts, which can be served at different IPs.
   Redirects are handled in the background by making a new connection.
   Connections to new hosts are created once needed for servicing a request.

	 http-client-request:

	 The request semantics are similar to imapc commands. Create a request, 
   optionally modify some aspects of it and finally submit it. Once finished,
   a callback is called with the returned response.

   http-client-host:

   We maintain a 'cache' of hosts for which we have looked up IPs. One host
   can have multiple IPs.

   http-client-queue:

   Requests are queued in a queue object. These queues are maintained for each
   host:port target and listed in the host object. The queue object is
   responsible for starting connection attempts to TCP port at the various IPs
   known for the host.

   http-client-peer:

   The peer object groups multiple connections to the same ip/port
   (== peer_addr).

   http-client-connection:

   This is an actual connection to a server. Once a connection is ready to
   handle requests, it claims a request from a queue object. One connection can
   service multiple hosts and one host can have multiple associated connections,
   possibly to different ips and ports.

 */

/*
 * Logging
 */

static inline void
http_client_debug(struct http_client *client,
	const char *format, ...) ATTR_FORMAT(2, 3);

static inline void
http_client_debug(struct http_client *client,
	const char *format, ...)
{
	va_list args;

	va_start(args, format);	
	if (client->set.debug)
		i_debug("http-client: %s", t_strdup_vprintf(format, args));
	va_end(args);
}

/*
 * Client
 */

struct http_client *http_client_init(const struct http_client_settings *set)
{
	struct http_client *client;
	pool_t pool;

	pool = pool_alloconly_create("http client", 1024);
	client = p_new(pool, struct http_client, 1);
	client->pool = pool;

	client->set.dns_client = set->dns_client;
	client->set.dns_client_socket_path =
		p_strdup_empty(pool, set->dns_client_socket_path);
	client->set.dns_ttl_msecs = (set->dns_ttl_msecs == 0 ?
		HTTP_CLIENT_DEFAULT_DNS_TTL_MSECS : set->dns_ttl_msecs);
	client->set.user_agent = p_strdup_empty(pool, set->user_agent);
	client->set.rawlog_dir = p_strdup_empty(pool, set->rawlog_dir);

	if (set->ssl != NULL)
		client->set.ssl = ssl_iostream_settings_dup(client->pool, set->ssl);

	if (set->proxy_socket_path != NULL && *set->proxy_socket_path != '\0') {
		client->set.proxy_socket_path = p_strdup(pool, set->proxy_socket_path);
	} else if (set->proxy_url != NULL) {
		client->set.proxy_url = http_url_clone(pool, set->proxy_url);
	}
	if (set->proxy_username != NULL && *set->proxy_username != '\0') {
		client->set.proxy_username = p_strdup_empty(pool, set->proxy_username);
		client->set.proxy_password = p_strdup(pool, set->proxy_password);
	} else if (set->proxy_url != NULL) {
		client->set.proxy_username =
			p_strdup_empty(pool, set->proxy_url->user);
		client->set.proxy_password =
			p_strdup(pool, set->proxy_url->password);
	}

	client->set.max_idle_time_msecs = set->max_idle_time_msecs;
	client->set.max_parallel_connections =
		(set->max_parallel_connections > 0 ? set->max_parallel_connections : 1);
	client->set.max_pipelined_requests =
		(set->max_pipelined_requests > 0 ? set->max_pipelined_requests : 1);
	client->set.max_attempts = set->max_attempts;
	client->set.max_connect_attempts = set->max_connect_attempts;
	client->set.connect_backoff_time_msecs =
		set->connect_backoff_time_msecs == 0 ?
			HTTP_CLIENT_DEFAULT_BACKOFF_TIME_MSECS :
			set->connect_backoff_time_msecs;
	client->set.connect_backoff_max_time_msecs =
		set->connect_backoff_max_time_msecs == 0 ?
			HTTP_CLIENT_DEFAULT_BACKOFF_MAX_TIME_MSECS :
			set->connect_backoff_max_time_msecs;
	client->set.no_auto_redirect = set->no_auto_redirect;
	client->set.no_auto_retry = set->no_auto_retry;
	client->set.no_ssl_tunnel = set->no_ssl_tunnel;
	client->set.max_redirects = set->max_redirects;
	client->set.response_hdr_limits = set->response_hdr_limits;
	client->set.request_absolute_timeout_msecs =
		set->request_absolute_timeout_msecs;
	client->set.request_timeout_msecs =
		set->request_timeout_msecs == 0 ?
			HTTP_CLIENT_DEFAULT_REQUEST_TIMEOUT_MSECS :
			set->request_timeout_msecs;
	client->set.connect_timeout_msecs = set->connect_timeout_msecs;
	client->set.soft_connect_timeout_msecs = set->soft_connect_timeout_msecs;
	client->set.max_auto_retry_delay = set->max_auto_retry_delay;
	client->set.socket_send_buffer_size = set->socket_send_buffer_size;
	client->set.socket_recv_buffer_size = set->socket_recv_buffer_size;
	client->set.debug = set->debug;

	i_array_init(&client->delayed_failing_requests, 1);

	client->conn_list = http_client_connection_list_init();

	hash_table_create(&client->hosts, default_pool, 0, str_hash, strcmp);
	hash_table_create(&client->peers, default_pool, 0,
		http_client_peer_addr_hash, http_client_peer_addr_cmp);

	return client;
}

void http_client_deinit(struct http_client **_client)
{
	struct http_client *client = *_client;
	struct http_client_request *req;
	struct http_client_host *host;
	struct http_client_peer *peer;

	*_client = NULL;

	/* destroy requests without calling callbacks */
	req = client->requests_list;
	while (req != NULL) {
		struct http_client_request *next_req = req->next;
		http_client_request_destroy(&req);
		req = next_req;
	}
	i_assert(client->requests_count == 0);

	/* free peers */
	while (client->peers_list != NULL) {
		peer = client->peers_list;
		http_client_peer_close(&peer);
	}
	hash_table_destroy(&client->peers);

	/* free hosts */
	while (client->hosts_list != NULL) {
		host = client->hosts_list;
		http_client_host_free(&host);
	}
	hash_table_destroy(&client->hosts);

	array_free(&client->delayed_failing_requests);
	if (client->to_failing_requests != NULL)
		timeout_remove(&client->to_failing_requests);

	connection_list_deinit(&client->conn_list);

	if (client->ssl_ctx != NULL)
		ssl_iostream_context_deinit(&client->ssl_ctx);
	pool_unref(&client->pool);
}

void http_client_switch_ioloop(struct http_client *client)
{
	struct connection *_conn = client->conn_list->connections;
	struct http_client_host *host;
	struct http_client_peer *peer;

	/* move connections */
	/* FIXME: we wouldn't necessarily need to switch all of them
	   immediately, only those that have requests now. but also connections
	   that get new requests before ioloop is switched again.. */
	for (; _conn != NULL; _conn = _conn->next) {
		struct http_client_connection *conn =
			(struct http_client_connection *)_conn;

		http_client_connection_switch_ioloop(conn);
	}

	/* move peers */
	for (peer = client->peers_list; peer != NULL; peer = peer->next)
		http_client_peer_switch_ioloop(peer);

	/* move dns lookups and delayed requests */
	for (host = client->hosts_list; host != NULL; host = host->next)
		http_client_host_switch_ioloop(host);

	/* move timeouts */
	if (client->to_failing_requests != NULL) {
		client->to_failing_requests =
			io_loop_move_timeout(&client->to_failing_requests);
	}
}

void http_client_wait(struct http_client *client)
{
	struct ioloop *prev_ioloop = current_ioloop;

	i_assert(client->ioloop == NULL);

	if (client->requests_count == 0)
		return;

	client->ioloop = io_loop_create();
	http_client_switch_ioloop(client);
	if (client->set.dns_client != NULL)
		dns_client_switch_ioloop(client->set.dns_client);
	/* either we're waiting for network I/O or we're getting out of a
	   callback using timeout_add_short(0) */
	i_assert(io_loop_have_ios(client->ioloop) ||
		 io_loop_have_immediate_timeouts(client->ioloop));

	do {
		http_client_debug(client,
			"Waiting for %d requests to finish", client->requests_count);
		io_loop_run(client->ioloop);
	} while (client->requests_count > 0);

	http_client_debug(client, "All requests finished");

	io_loop_set_current(prev_ioloop);
	http_client_switch_ioloop(client);
	if (client->set.dns_client != NULL)
		dns_client_switch_ioloop(client->set.dns_client);
	io_loop_set_current(client->ioloop);
	io_loop_destroy(&client->ioloop);
}

unsigned int http_client_get_pending_request_count(struct http_client *client)
{
	return client->requests_count;
}

int http_client_init_ssl_ctx(struct http_client *client, const char **error_r)
{
	const char *error;

	if (client->ssl_ctx != NULL)
		return 0;

	if (client->set.ssl == NULL) {
		*error_r = "Requested https connection, but no SSL settings given";
		return -1;
	}
	if (ssl_iostream_context_init_client(client->set.ssl, &client->ssl_ctx, &error) < 0) {
		*error_r = t_strdup_printf("Couldn't initialize SSL context: %s",
					   error);
		return -1;
	}
	return 0;
}

/*
 * Delayed request errors
 */

static void
http_client_handle_request_errors(struct http_client *client)
{		
	timeout_remove(&client->to_failing_requests);

	while (array_count(&client->delayed_failing_requests) > 0) {
		struct http_client_request *const *req_idx =
			array_idx(&client->delayed_failing_requests, 0);
		struct http_client_request *req = *req_idx;

		i_assert(req->refcount == 1);
		http_client_request_error_delayed(&req);
	}
	array_clear(&client->delayed_failing_requests);
}

void http_client_delay_request_error(struct http_client *client,
	struct http_client_request *req)
{
	if (client->to_failing_requests == NULL) {
		client->to_failing_requests = timeout_add_short(0,
			http_client_handle_request_errors, client);
	}
	array_append(&client->delayed_failing_requests, &req, 1);
}

void http_client_remove_request_error(struct http_client *client,
	struct http_client_request *req)
{
	struct http_client_request *const *reqs;
	unsigned int i, count;

	reqs = array_get(&client->delayed_failing_requests, &count);
	for (i = 0; i < count; i++) {
		if (reqs[i] == req) {
			array_delete(&client->delayed_failing_requests, i, 1);
			return;
		}
	}
}
