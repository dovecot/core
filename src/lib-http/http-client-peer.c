/* Copyright (c) 2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "net.h"
#include "str.h"
#include "hash.h"
#include "array.h"
#include "istream.h"
#include "ostream.h"
#include "iostream-ssl.h"
#include "http-response-parser.h"

#include "http-client-private.h"

/*
 * Logging
 */

static inline void
http_client_peer_debug(struct http_client_peer *peer,
	const char *format, ...) ATTR_FORMAT(2, 3);

static inline void
http_client_peer_debug(struct http_client_peer *peer,
	const char *format, ...)
{
	va_list args;

	if (peer->client->set.debug) {
		va_start(args, format);	
		i_debug("http-client: peer %s:%u: %s", 
			net_ip2addr(&peer->addr.ip), peer->addr.port,
			t_strdup_vprintf(format, args));
		va_end(args);
	}
}

static inline void ATTR_FORMAT(2, 3)
http_client_peer_error(struct http_client_peer *peer,
	const char *format, ...)
{
	va_list args;
	va_start(args, format);	
	i_error("http-client: peer %s:%u: %s", 
		net_ip2addr(&peer->addr.ip), peer->addr.port,
		t_strdup_vprintf(format, args));
	va_end(args);
}

/*
 * Peer address
 */

unsigned int http_client_peer_addr_hash
(const struct http_client_peer_addr *peer)
{
	return net_ip_hash(&peer->ip) + peer->port + peer->ssl;
}

int http_client_peer_addr_cmp
(const struct http_client_peer_addr *peer1,
	const struct http_client_peer_addr *peer2)
{
	int ret;

	if ((ret=net_ip_cmp(&peer1->ip, &peer2->ip)) != 0)
		return ret;
	if (peer1->port != peer2->port)
		return (peer1->port > peer2->port ? 1 : -1);
	if (peer1->ssl != peer2->ssl)
		return (peer1->ssl > peer2->ssl ? 1 : -1);
	return 0;
}

/*
 * Peer
 */

const char *
http_client_peer_get_hostname(struct http_client_peer *peer)
{
	struct http_client_host *const *host;

	if (array_count(&peer->hosts) == 0)
		return NULL;

	/* just return name of initial host */
	host = array_idx(&peer->hosts, 1);
	return (*host)->name;
}

static int
http_client_peer_connect(struct http_client_peer *peer)
{
	struct http_client_connection *conn;

	conn = http_client_connection_create(peer);
	if (conn == NULL) {
		http_client_peer_debug(peer, "Failed to make new connection");
		return -1;
	}

	return 0;
}

static bool
http_client_peer_requests_pending(struct http_client_peer *peer, bool urgent)
{
	struct http_client_host *const *host;

	array_foreach(&peer->hosts, host) {
		if (http_client_host_have_requests(*host, &peer->addr, urgent))
			return TRUE;
	}

	return FALSE;
}

static bool
http_client_peer_next_request(struct http_client_peer *peer,
	bool urgent)
{
	struct http_client_connection *const *conn_idx;
	struct http_client_connection *conn = NULL;
	unsigned int closing = 0, min_waiting = (unsigned int)-1;
	
	/* at this point we already know that a request for this peer is pending
	 */

	/* find the least busy connection */
	array_foreach(&peer->conns, conn_idx) {
		if (http_client_connection_is_ready(*conn_idx)) {
			unsigned int waiting = array_count(&(*conn_idx)->request_wait_list);
			if (waiting < min_waiting) {
				min_waiting = waiting;
				conn = *conn_idx;
				if (min_waiting == 0)
					break;
			}
		}
		/* count the number of closing connections */
		if ((*conn_idx)->closing)
			closing++;
	}

	/* do we have an idle connection? */
	if (conn != NULL && min_waiting == 0) {
		/* yes */
		return http_client_connection_next_request(conn);
	}

	/* no, but can we create a new connection? */		
	if (!urgent && (array_count(&peer->conns) - closing) >=
		peer->client->set.max_parallel_connections) {
		/* no */
		if (conn == NULL)
			return FALSE;
		/* pipeline it */
		return http_client_connection_next_request(conn);
	}

	/* yes */
	if (http_client_peer_connect(peer) < 0) {
		/* connection failed */
		if (conn == NULL)
			return FALSE;
		/* pipeline it on the least busy connection we found */
		return http_client_connection_next_request(conn);
	}

	/* now we wait until it is connected */
	return FALSE;
}

void http_client_peer_handle_requests(struct http_client_peer *peer)
{
	/* check urgent requests first */
	while (http_client_peer_requests_pending(peer, TRUE)) {
		if (!http_client_peer_next_request(peer, TRUE))
			break;
	}

	/* check normal requests once we're done */
	while (http_client_peer_requests_pending(peer, FALSE)) {
		if (!http_client_peer_next_request(peer, FALSE))
			break;
	}
}

static struct http_client_peer *
http_client_peer_create(struct http_client *client,
			      const struct http_client_peer_addr *addr)
{
	struct http_client_peer *peer;
#ifdef HTTP_BUILD_SSL
	struct ssl_iostream_settings ssl_set;
#endif

	peer = i_new(struct http_client_peer, 1);
	peer->client = client;
	peer->addr = *addr;
	i_array_init(&peer->hosts, 16);
	i_array_init(&peer->conns, 16);

	hash_table_insert
		(client->peers, (const struct http_client_peer_addr *)&peer->addr, peer);

	http_client_peer_debug(peer, "Peer created");

#ifdef HTTP_BUILD_SSL
	if (peer->addr.ssl && peer->ssl_ctx == NULL) {
		const char *source;
		memset(&ssl_set, 0, sizeof(ssl_set));
		ssl_set.ca_dir = peer->client->set.ssl_ca_dir;
		ssl_set.verify_remote_cert = TRUE;
		ssl_set.crypto_device = peer->client->set.ssl_crypto_device;

		source = t_strdup_printf("http-client: peer %s:%u",
			net_ip2addr(&peer->addr.ip), peer->addr.port);
		if (ssl_iostream_context_init_client
			(source, &ssl_set, &peer->ssl_ctx) < 0) {
			http_client_peer_error(peer, "Couldn't initialize SSL context");
			http_client_peer_free(&peer);
			return NULL;
		}
	}
#else
	if (peer->addr.ssl) {
		http_client_peer_error(peer, "HTTPS is not supported");
		http_client_peer_free(&peer);
		return NULL;
	}
#endif

	if (http_client_peer_connect(peer) < 0) {
		http_client_peer_free(&peer);
		return NULL;
	}

	return peer;
}

void http_client_peer_free(struct http_client_peer **_peer)
{
	struct http_client_peer *peer = *_peer;
	struct http_client_connection **conn;
	ARRAY_TYPE(http_client_connection) conns;

	if (peer->destroyed)
		return;
	peer->destroyed = TRUE;

	http_client_peer_debug(peer, "Peer destroy");

	/* make a copy of the connection array; freed connections modify it */
	t_array_init(&conns, array_count(&peer->conns));
	array_copy(&conns.arr, 0, &peer->conns.arr, 0, array_count(&peer->conns));

	array_foreach_modifiable(&conns, conn) {
		http_client_connection_unref(conn);
	}

	i_assert(array_count(&peer->conns) == 0);
	array_free(&peer->conns);
	array_free(&peer->hosts);

#ifdef HTTP_BUILD_SSL
	if (peer->ssl_ctx != NULL)
		ssl_iostream_context_deinit(&peer->ssl_ctx);
#endif

	hash_table_remove
		(peer->client->peers, (const struct http_client_peer_addr *)&peer->addr);

	i_free(peer);
	*_peer = NULL;
}

struct http_client_peer *
http_client_peer_get(struct http_client *client,
			   const struct http_client_peer_addr *addr)
{
	struct http_client_peer *peer;

	peer = hash_table_lookup(client->peers, addr);
	if (peer == NULL)
		peer = http_client_peer_create(client, addr);

	return peer;
}

void http_client_peer_add_host(struct http_client_peer *peer,
			   struct http_client_host *host)
{
	struct http_client_host *const *host_idx;
	bool exists = FALSE;

	array_foreach(&peer->hosts, host_idx) {
		if (*host_idx == host) {
			exists = TRUE;
			break;
		}
	}

	if (!exists)
		array_append(&peer->hosts, &host, 1);
	if (exists || array_count(&peer->hosts) > 1)
		(void)http_client_peer_next_request(peer, FALSE);
}

struct http_client_request *
http_client_peer_claim_request(struct http_client_peer *peer, bool no_urgent)
{
	struct http_client_host *const *host_idx;
	struct http_client_request *req;

	array_foreach(&peer->hosts, host_idx) {
		if ((req=http_client_host_claim_request
			(*host_idx, &peer->addr, no_urgent)) != NULL) {
			req->peer = peer;
			return req;
		}
	}

	return NULL;
}

void http_client_peer_connection_failure(struct http_client_peer *peer)
{
	struct http_client_host *const *host;

	http_client_peer_debug(peer, "Failed to make connection");

	if (array_count(&peer->conns) == 1) {
		array_foreach(&peer->hosts, host) {
			http_client_host_connection_failure(*host, &peer->addr);
		}
	}
}

void http_client_peer_connection_lost(struct http_client_peer *peer)
{
	if (peer->destroyed)
		return;

	http_client_peer_debug(peer, "Lost a connection (%d connections left)",
		array_count(&peer->conns));

	if (array_count(&peer->conns) == 0) {
		if (http_client_peer_requests_pending(peer, TRUE))
			(void)http_client_peer_next_request(peer, TRUE);
		else if (http_client_peer_requests_pending(peer, FALSE))
			(void)http_client_peer_next_request(peer, FALSE);
		else
			http_client_peer_free(&peer);
	}
}

unsigned int http_client_peer_idle_connections(struct http_client_peer *peer)
{
    struct http_client_connection *const *conn_idx;
    unsigned int idle = 0;

	/* find the least busy connection */
    array_foreach(&peer->conns, conn_idx) {
        if (http_client_connection_is_idle(*conn_idx))
			idle++;
    }

	return idle;
}

