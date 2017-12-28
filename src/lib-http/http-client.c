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

#include "http-client-private.h"

#define HTTP_DEFAULT_PORT 80
#define HTTPS_DEFAULT_PORT 443

/* Structure:

   http_client_context:

   Shared context between multiple independent HTTP clients. This allows host
   name lookup data, peer status and idle connections to be shared between
   clients.

   http_client:

   Acts much like a browser; it is not dedicated to a single host. Client can
   accept requests to different hosts, which can be served at different IPs.
   Redirects are handled in the background by making a new connection.
   Connections to new hosts are created once needed for servicing a request.

   http_client_request:

   The request semantics are similar to imapc commands. Create a request,
   optionally modify some aspects of it, and finally submit it. Once finished,
   a callback is called with the returned response.

   http_client_host_shared:

   We maintain a 'cache' of hosts for which we have looked up IPs. This cache
   is maintained in client context, so multiple clients can share it. One host
   can have multiple IPs.

   http_client_host:

   A host object maintains client-specific information for a host. The queues
   that the client has for this host are listed here. For one host, there is a
   separate queue for each used server port.

   http_client_queue:

   Requests are queued in a queue object. These queues are maintained for each
   host:port target and listed in the host object. The queue object is
   responsible for starting connection attempts to TCP port at the various IPs
   known for the host.

   http_client_peer_pool:

   A peer pool lists all unused and pending connections to a peer, grouped by
   a compatible configuration, e.g. in terms of SSL and rawlog. Once needed,
   peers can claim/request an existing/new connection from the pool.

   http_client_peer_shared:

   The shared peer object records state information about a peer, which is a
   service access point (ip:port or unix socket path). The peer object also
   maintains lists of idle and pending connections to this service, which are
   grouped in pools with compatible client configuration. Each client has a
   separate (non-shared) peer object for client-specific state information.

   http_client_peer:

   A peer object maintains client-specific information for a peer. Claimed
   connections are dedicated to one peer (and therefore one client).

   http-client-connection:

   This is an actual connection to a server. Once a connection is ready to
   handle requests, it claims a request from a queue object. One connection can
   service multiple hosts and one host can have multiple associated connections,
   possibly to different ips and ports.

 */

static struct http_client_context *http_client_global_context = NULL;

/*
 * Client
 */

struct http_client *
http_client_init_shared(struct http_client_context *cctx,
	const struct http_client_settings *set)
{
	static unsigned int id = 0;
	struct http_client *client;
	const char *log_prefix;
	pool_t pool;

	pool = pool_alloconly_create("http client", 1024);
	client = p_new(pool, struct http_client, 1);
	client->pool = pool;

	/* create private context if none is provided */
	id++;
	if (cctx != NULL) {
		client->cctx = cctx;
		http_client_context_ref(cctx);
		log_prefix = t_strdup_printf("http-client[%u]: ", id);
	} else {
		client->cctx = cctx = http_client_context_create(set);
		log_prefix = "http-client: ";
	}

	struct event *parent_event;
	if (set != NULL && set->event != NULL)
		parent_event = set->event;
	else if (cctx->event == NULL)
		parent_event = NULL;
	else {
		/* FIXME: we could use cctx->event, but it already has a log
		   prefix that we don't want.. should we update event API to
		   support replacing parent's log prefix? */
		parent_event = event_get_parent(cctx->event);
	}
	client->event = event_create(parent_event);
	if ((set != NULL && set->debug) || (cctx != NULL && cctx->set.debug))
		event_set_forced_debug(client->event, TRUE);
	event_set_append_log_prefix(client->event, log_prefix);

	/* merge provided settings with context defaults */
	client->set = cctx->set;
	if (set != NULL) {
		if (set->user_agent != NULL && *set->user_agent != '\0')
			client->set.user_agent = p_strdup_empty(pool, set->user_agent);
		if (set->rawlog_dir != NULL && *set->rawlog_dir != '\0')
			client->set.rawlog_dir = p_strdup_empty(pool, set->rawlog_dir);

		if (set->ssl != NULL)
			client->set.ssl = ssl_iostream_settings_dup(pool, set->ssl);

		if (set->proxy_socket_path != NULL && *set->proxy_socket_path != '\0') {
			client->set.proxy_socket_path = p_strdup(pool, set->proxy_socket_path);
			client->set.proxy_url = NULL;
		} else if (set->proxy_url != NULL) {
			client->set.proxy_url = http_url_clone(pool, set->proxy_url);
			client->set.proxy_socket_path = NULL;
		}
		if (set->proxy_username != NULL && *set->proxy_username != '\0') {
			client->set.proxy_username = p_strdup_empty(pool, set->proxy_username);
			client->set.proxy_password = p_strdup(pool, set->proxy_password);
		} else if (set->proxy_url != NULL && set->proxy_url->user != NULL &&
			*set->proxy_url->user != '\0') {
			client->set.proxy_username =
				p_strdup_empty(pool, set->proxy_url->user);
			client->set.proxy_password =
				p_strdup(pool, set->proxy_url->password);
		}

		if (set->max_idle_time_msecs > 0)
			client->set.max_idle_time_msecs = set->max_idle_time_msecs;
		if (set->max_parallel_connections > 0)
			client->set.max_parallel_connections = set->max_parallel_connections;
		if (set->max_pipelined_requests > 0)
			client->set.max_pipelined_requests = set->max_pipelined_requests;
		if (set->max_attempts > 0)
			client->set.max_attempts = set->max_attempts;
		if (set->max_connect_attempts > 0)
			client->set.max_connect_attempts = set->max_connect_attempts;
		if (set->connect_backoff_time_msecs > 0) {
			client->set.connect_backoff_time_msecs =
				set->connect_backoff_time_msecs;
		}
		if (set->connect_backoff_max_time_msecs > 0) {
			client->set.connect_backoff_max_time_msecs =
				set->connect_backoff_max_time_msecs;
		}
		client->set.no_auto_redirect =
			client->set.no_auto_redirect || set->no_auto_redirect;
		client->set.no_auto_retry =
			client->set.no_auto_retry || set->no_auto_retry;
		client->set.no_ssl_tunnel =
			client->set.no_ssl_tunnel || set->no_ssl_tunnel;
		if (set->max_redirects > 0)
			client->set.max_redirects = set->max_redirects;
		if (set->request_absolute_timeout_msecs > 0) {
			client->set.request_absolute_timeout_msecs =
				set->request_absolute_timeout_msecs;
		}
		if (set->request_timeout_msecs > 0)
			client->set.request_timeout_msecs = set->request_timeout_msecs;
		if (set->connect_timeout_msecs > 0)
			client->set.connect_timeout_msecs = set->connect_timeout_msecs;
		if (set->soft_connect_timeout_msecs > 0)
			client->set.soft_connect_timeout_msecs = set->soft_connect_timeout_msecs;
		if (set->socket_send_buffer_size > 0)
			client->set.socket_send_buffer_size = set->socket_send_buffer_size;
		if (set->socket_recv_buffer_size > 0)
			client->set.socket_recv_buffer_size = set->socket_recv_buffer_size;
		if (set->max_auto_retry_delay > 0)
			client->set.max_auto_retry_delay = set->max_auto_retry_delay;
		client->set.debug = client->set.debug || set->debug;
	}

	i_array_init(&client->delayed_failing_requests, 1);

	return client;
}

struct http_client *
http_client_init(const struct http_client_settings *set)
{
	return http_client_init_shared(http_client_get_global_context(), set);
}

struct http_client *
http_client_init_private(const struct http_client_settings *set)
{
	return http_client_init_shared(NULL, set);
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

	/* free hosts */
	while (client->hosts_list != NULL) {
		host = client->hosts_list;
		http_client_host_free(&host);
	}

	array_free(&client->delayed_failing_requests);
	timeout_remove(&client->to_failing_requests);

	if (client->ssl_ctx != NULL)
		ssl_iostream_context_unref(&client->ssl_ctx);
	http_client_context_unref(&client->cctx);
	event_unref(&client->event);
	pool_unref(&client->pool);
}

struct ioloop *http_client_switch_ioloop(struct http_client *client)
{
	struct ioloop *prev_ioloop = client->ioloop;
	struct http_client_peer *peer;
	struct http_client_host *host;

	/* move peers */
	for (peer = client->peers_list; peer != NULL;
		peer = peer->client_next)
		http_client_peer_switch_ioloop(peer);

	/* move hosts/queues */
	for (host = client->hosts_list; host != NULL;
		host = host->client_next)
		http_client_host_switch_ioloop(host);

	/* move timeouts */
	if (client->to_failing_requests != NULL) {
		client->to_failing_requests =
			io_loop_move_timeout(&client->to_failing_requests);
	}

	http_client_context_switch_ioloop(client->cctx);

	client->ioloop = current_ioloop;
	return prev_ioloop;
}

void http_client_wait(struct http_client *client)
{
	struct ioloop *prev_ioloop, *client_ioloop, *prev_client_ioloop;

	if (client->requests_count == 0)
		return;

	prev_ioloop = current_ioloop;
	client_ioloop = io_loop_create();
	prev_client_ioloop = http_client_switch_ioloop(client);
	if (client->set.dns_client != NULL)
		dns_client_switch_ioloop(client->set.dns_client);
	/* either we're waiting for network I/O or we're getting out of a
	   callback using timeout_add_short(0) */
	i_assert(io_loop_have_ios(client_ioloop) ||
		 io_loop_have_immediate_timeouts(client_ioloop));

	client->waiting = TRUE;
	do {
		e_debug(client->event,
			"Waiting for %d requests to finish", client->requests_count);
		io_loop_run(client_ioloop);
	} while (client->requests_count > 0);
	client->waiting = FALSE;

	e_debug(client->event, "All requests finished");

	if (prev_client_ioloop != NULL)
		io_loop_set_current(prev_client_ioloop);
	else
		io_loop_set_current(prev_ioloop);
	(void)http_client_switch_ioloop(client);
	if (client->set.dns_client != NULL)
		dns_client_switch_ioloop(client->set.dns_client);
	io_loop_set_current(client_ioloop);
	io_loop_destroy(&client_ioloop);
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
	if (ssl_iostream_client_context_cache_get(client->set.ssl, &client->ssl_ctx, &error) < 0) {
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
	struct http_client_request *const *req_idx;

	timeout_remove(&client->to_failing_requests);

	array_foreach(&client->delayed_failing_requests, req_idx) {
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

/*
 * Client shared context
 */

struct http_client_context *
http_client_context_create(const struct http_client_settings *set)
{
	struct http_client_context *cctx;
	pool_t pool;

	pool = pool_alloconly_create("http client context", 1024);
	cctx = p_new(pool, struct http_client_context, 1);
	cctx->pool = pool;
	cctx->refcount = 1;

	cctx->event = event_create(set->event);
	if (set->debug)
		event_set_forced_debug(cctx->event, TRUE);
	event_set_append_log_prefix(cctx->event, "http-client: ");

	cctx->set.dns_client = set->dns_client;
	cctx->set.dns_client_socket_path =
		p_strdup_empty(pool, set->dns_client_socket_path);
	cctx->set.dns_ttl_msecs = (set->dns_ttl_msecs == 0 ?
			HTTP_CLIENT_DEFAULT_DNS_TTL_MSECS : set->dns_ttl_msecs);
	cctx->set.user_agent = p_strdup_empty(pool, set->user_agent);
	cctx->set.rawlog_dir = p_strdup_empty(pool, set->rawlog_dir);

	if (set->ssl != NULL)
		cctx->set.ssl = ssl_iostream_settings_dup(pool, set->ssl);

	if (set->proxy_socket_path != NULL && *set->proxy_socket_path != '\0') {
		cctx->set.proxy_socket_path = p_strdup(pool, set->proxy_socket_path);
	} else if (set->proxy_url != NULL) {
		cctx->set.proxy_url = http_url_clone(pool, set->proxy_url);
	}
	if (set->proxy_username != NULL && *set->proxy_username != '\0') {
		cctx->set.proxy_username = p_strdup_empty(pool, set->proxy_username);
		cctx->set.proxy_password = p_strdup(pool, set->proxy_password);
	} else if (set->proxy_url != NULL) {
		cctx->set.proxy_username =
			p_strdup_empty(pool, set->proxy_url->user);
		cctx->set.proxy_password =
			p_strdup(pool, set->proxy_url->password);
	}

	cctx->set.max_idle_time_msecs = set->max_idle_time_msecs;
	cctx->set.max_pipelined_requests =
		(set->max_pipelined_requests > 0 ? set->max_pipelined_requests : 1);
	cctx->set.max_parallel_connections =
		(set->max_parallel_connections > 0 ? set->max_parallel_connections : 1);
	cctx->set.max_attempts = set->max_attempts;
	cctx->set.max_connect_attempts = set->max_connect_attempts;
	cctx->set.connect_backoff_time_msecs =
		set->connect_backoff_time_msecs == 0 ?
			HTTP_CLIENT_DEFAULT_BACKOFF_TIME_MSECS :
			set->connect_backoff_time_msecs;
	cctx->set.connect_backoff_max_time_msecs =
		set->connect_backoff_max_time_msecs == 0 ?
			HTTP_CLIENT_DEFAULT_BACKOFF_MAX_TIME_MSECS :
			set->connect_backoff_max_time_msecs;
	cctx->set.no_auto_redirect = set->no_auto_redirect;
	cctx->set.no_auto_retry = set->no_auto_retry;
	cctx->set.no_ssl_tunnel = set->no_ssl_tunnel;
	cctx->set.max_redirects = set->max_redirects;
	cctx->set.response_hdr_limits = set->response_hdr_limits;
	cctx->set.request_absolute_timeout_msecs =
		set->request_absolute_timeout_msecs;
	cctx->set.request_timeout_msecs =
		set->request_timeout_msecs == 0 ?
			HTTP_CLIENT_DEFAULT_REQUEST_TIMEOUT_MSECS :
			set->request_timeout_msecs;
	cctx->set.connect_timeout_msecs = set->connect_timeout_msecs;
	cctx->set.soft_connect_timeout_msecs = set->soft_connect_timeout_msecs;
	cctx->set.max_auto_retry_delay = set->max_auto_retry_delay;
	cctx->set.socket_send_buffer_size = set->socket_send_buffer_size;
	cctx->set.socket_recv_buffer_size = set->socket_recv_buffer_size;
	cctx->set.debug = set->debug;

	cctx->conn_list = http_client_connection_list_init();

	hash_table_create(&cctx->hosts, default_pool, 0, str_hash, strcmp);

	hash_table_create(&cctx->peers, default_pool, 0,
		http_client_peer_addr_hash, http_client_peer_addr_cmp);

	return cctx;
}

void http_client_context_ref(struct http_client_context *cctx)
{
	cctx->refcount++;
}

void http_client_context_unref(struct http_client_context **_cctx)
{
	struct http_client_context *cctx = *_cctx;
	struct http_client_peer_shared *peer;
	struct http_client_host_shared *hshared;

	*_cctx = NULL;

	i_assert(cctx->refcount > 0);
	if (--cctx->refcount > 0)
		return;

	/* free hosts */
	while (cctx->hosts_list != NULL) {
		hshared = cctx->hosts_list;
		http_client_host_shared_free(&hshared);
	}
	hash_table_destroy(&cctx->hosts);

	/* close all idle connections */
	while (cctx->peers_list != NULL) {
		peer = cctx->peers_list;
		http_client_peer_shared_close(&peer);
		i_assert(peer == NULL);
	}
	hash_table_destroy(&cctx->peers);

	connection_list_deinit(&cctx->conn_list);

	event_unref(&cctx->event);
	pool_unref(&cctx->pool);
}

void http_client_context_switch_ioloop(struct http_client_context *cctx)
{
	struct connection *_conn = cctx->conn_list->connections;
	struct http_client_host_shared *hshared;

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
	for (hshared = cctx->hosts_list; hshared != NULL;
		hshared = hshared->next)
		http_client_host_shared_switch_ioloop(hshared);
}

static void http_client_global_context_free(void)
{
	http_client_context_unref(&http_client_global_context);
}

struct http_client_context *http_client_get_global_context(void)
{
	if (http_client_global_context != NULL)
		return http_client_global_context;

	struct http_client_settings set;
	i_zero(&set);
	http_client_global_context = http_client_context_create(&set);
	/* keep this a bit higher than lib-ssl-iostream */
	lib_atexit_priority(http_client_global_context_free, LIB_ATEXIT_PRIORITY_LOW-1);
	return http_client_global_context;
}
