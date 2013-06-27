/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

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

/* FIXME: This implementation not yet finished. The essence works: it is
   possible to submit requests through the client. Responses are dumped to
   stdout

    Structure so far:
    Client - Acts much like a browser; it is not dedicated to a single host.
             Client can accept requests to different hosts, which can be served
             at different IPs. Redirects can be handled in the background by
             making a new connection. Connections to new hosts are created once
             needed for servicing a request.
    Requests - Semantics are similar to imapc commands. Create a request, 
               optionally modify some aspects of it and finally submit it.
    Hosts - We maintain a 'cache' of hosts for which we have looked up IPs.
            Requests are first queued in the host struct on a per-port basis.
    Peers - Group connections to the same ip/port (== peer_addr).
    Connections - Actual connections to a server. Once a connection is ready to
                  handle requests, it claims a request from a host object. One
                  connection hand service multiple hosts and one host can have
                  multiple associated connections, possibly to different ips and
                  ports.

  TODO: lots of cleanup, authentication, ssl, timeouts,	 rawlog etc.
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
	if (set->dns_client_socket_path != NULL && *set->dns_client_socket_path != '\0') {
		client->set.dns_client_socket_path =
			p_strdup(pool, set->dns_client_socket_path);
	}
	if (set->rawlog_dir != NULL && *set->rawlog_dir != '\0')
		client->set.rawlog_dir = p_strdup(pool, set->rawlog_dir);
	client->set.ssl_ca_dir = p_strdup(pool, set->ssl_ca_dir);
	client->set.ssl_ca_file = p_strdup(pool, set->ssl_ca_file);
	client->set.ssl_ca = p_strdup(pool, set->ssl_ca);
	client->set.ssl_crypto_device = p_strdup(pool, set->ssl_crypto_device);
	client->set.ssl_allow_invalid_cert = set->ssl_allow_invalid_cert;
	client->set.ssl_cert = p_strdup(pool, set->ssl_cert);
	client->set.ssl_key = p_strdup(pool, set->ssl_key);
	client->set.ssl_key_password = p_strdup(pool, set->ssl_key_password);
	client->set.max_idle_time_msecs = set->max_idle_time_msecs;
	client->set.max_parallel_connections =
		(set->max_parallel_connections > 0 ? set->max_parallel_connections : 1);
	client->set.max_pipelined_requests =
		(set->max_pipelined_requests > 0 ? set->max_pipelined_requests : 1);
	client->set.max_attempts = set->max_attempts;
	client->set.max_redirects = set->max_redirects;
	client->set.request_timeout_msecs = set->request_timeout_msecs;
	client->set.connect_timeout_msecs = set->connect_timeout_msecs;
	client->set.soft_connect_timeout_msecs = set->soft_connect_timeout_msecs;
	client->set.debug = set->debug;

	client->conn_list = http_client_connection_list_init();

	hash_table_create(&client->hosts, default_pool, 0, str_hash, strcmp);
	hash_table_create(&client->peers, default_pool, 0,
		http_client_peer_addr_hash, http_client_peer_addr_cmp);

	return client;
}

void http_client_deinit(struct http_client **_client)
{
	struct http_client *client = *_client;
	struct http_client_host *host;
	struct http_client_peer *peer;

	/* free peers */
	while (client->peers_list != NULL) {
		peer = client->peers_list;
		http_client_peer_free(&peer);
	}
	hash_table_destroy(&client->peers);

	/* free hosts */
	while (client->hosts_list != NULL) {
		host = client->hosts_list;
		http_client_host_free(&host);
	}
	hash_table_destroy(&client->hosts);

	connection_list_deinit(&client->conn_list);

	if (client->ssl_ctx != NULL)
		ssl_iostream_context_deinit(&client->ssl_ctx);
	pool_unref(&client->pool);
	*_client = NULL;
}

void http_client_switch_ioloop(struct http_client *client)
{
	struct connection *_conn = client->conn_list->connections;
	struct http_client_host *host;

	/* move connections */
	/* FIXME: we wouldn't necessarily need to switch all of them
	   immediately, only those that have requests now. but also connections
	   that get new requests before ioloop is switched again.. */
	for (; _conn != NULL; _conn = _conn->next) {
		struct http_client_connection *conn =
			(struct http_client_connection *)_conn;

		http_client_connection_switch_ioloop(conn);
	}

	/* move dns lookups and delayed requests */
	for (host = client->hosts_list; host != NULL; host = host->next)
		http_client_host_switch_ioloop(host);
}

void http_client_wait(struct http_client *client)
{
	struct ioloop *prev_ioloop = current_ioloop;

	i_assert(client->ioloop == NULL);

	if (client->pending_requests == 0)
		return;

	client->ioloop = io_loop_create();
	http_client_switch_ioloop(client);
	/* either we're waiting for network I/O or we're getting out of a
	   callback using timeout_add_short(0) */
	i_assert(io_loop_have_ios(client->ioloop) ||
		 io_loop_have_immediate_timeouts(client->ioloop));

	do {
		http_client_debug(client,
			"Waiting for %d requests to finish", client->pending_requests);
		io_loop_run(client->ioloop);
	} while (client->pending_requests > 0);

	http_client_debug(client, "All requests finished");

	current_ioloop = prev_ioloop;
	http_client_switch_ioloop(client);
	current_ioloop = client->ioloop;
	io_loop_destroy(&client->ioloop);
}

unsigned int http_client_get_pending_request_count(struct http_client *client)
{
	return client->pending_requests;
}

int http_client_init_ssl_ctx(struct http_client *client, const char **error_r)
{
	struct ssl_iostream_settings ssl_set;
	const char *error;

	if (client->ssl_ctx != NULL)
		return 0;

	memset(&ssl_set, 0, sizeof(ssl_set));
	ssl_set.ca_dir = client->set.ssl_ca_dir;
	ssl_set.ca_file = client->set.ssl_ca_file;
	ssl_set.ca = client->set.ssl_ca;
	ssl_set.verify_remote_cert = TRUE;
	ssl_set.crypto_device = client->set.ssl_crypto_device;
	ssl_set.cert = client->set.ssl_cert;
	ssl_set.key = client->set.ssl_key;
	ssl_set.key_password = client->set.ssl_key_password;
	ssl_set.verbose = client->set.debug;
	ssl_set.verbose_invalid_cert = client->set.debug;

	if (ssl_iostream_context_init_client(&ssl_set, &client->ssl_ctx, &error) < 0) {
		*error_r = t_strdup_printf("Couldn't initialize SSL context: %s",
					   error);
		return -1;
	}
	return 0;
}
