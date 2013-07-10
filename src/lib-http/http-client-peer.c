/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "net.h"
#include "str.h"
#include "hash.h"
#include "array.h"
#include "llist.h"
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

/*
 * Peer address
 */

unsigned int http_client_peer_addr_hash
(const struct http_client_peer_addr *peer)
{
	return net_ip_hash(&peer->ip) + peer->port +
		(peer->https_name == NULL ? 0 : str_hash(peer->https_name));
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
	return null_strcmp(peer1->https_name, peer2->https_name);
}

/*
 * Peer
 */

static void
http_client_peer_connect(struct http_client_peer *peer, unsigned int count)
{
	unsigned int i;

	for (i = 0; i < count; i++) {
		http_client_peer_debug(peer, "Making new connection %u of %u", i+1, count);
		(void)http_client_connection_create(peer);
	}
}

static unsigned int
http_client_peer_requests_pending(struct http_client_peer *peer,
				  unsigned int *num_urgent_r)
{
	struct http_client_host *const *host;
	unsigned int num_requests = 0, num_urgent = 0, requests, urgent;

	array_foreach(&peer->hosts, host) {
		requests = http_client_host_requests_pending(*host, &peer->addr, &urgent);

		num_requests += requests;
		num_urgent += urgent;
	}
	*num_urgent_r = num_urgent;
	return num_requests;
}

static bool
http_client_peer_next_request(struct http_client_peer *peer,
			      bool *created_connections)
{
	struct http_client_connection *const *conn_idx;
	struct http_client_connection *conn = NULL;
	unsigned int connecting = 0, closing = 0, min_waiting = UINT_MAX;
	unsigned int num_urgent, new_connections, working_conn_count;

	if (http_client_peer_requests_pending(peer, &num_urgent) == 0)
		return FALSE;

	/* find the least busy connection */
	array_foreach(&peer->conns, conn_idx) {
		if (http_client_connection_is_ready(*conn_idx)) {
			unsigned int waiting = http_client_connection_count_pending(*conn_idx);

			if (waiting < min_waiting) {
				min_waiting = waiting;
				conn = *conn_idx;
				if (min_waiting == 0) {
					/* found idle connection, use it now */
					break;
				}
			}
		}
		/* count the number of connecting and closing connections */
		if ((*conn_idx)->closing)
			closing++;
		else if (!(*conn_idx)->connected)
			connecting++;
	}
	working_conn_count = array_count(&peer->conns) - closing;

	/* did we find an idle connection? */
	if (conn != NULL && min_waiting == 0) {
		/* yes, use it */
		return http_client_connection_next_request(conn);
	}

	/* no, but can we create a new connection? */		
	if (num_urgent == 0 &&
	    working_conn_count >= peer->client->set.max_parallel_connections) {
		/* no */
		if (conn == NULL) {
			http_client_peer_debug(peer,
				"Only non-urgent requests, and we already have "
				"%u pending connections", working_conn_count);
			return FALSE;
		}
		/* pipeline it */
		return http_client_connection_next_request(conn);
	}

	/* yes, determine how many connections to set up */
	if (peer->last_connect_failed && working_conn_count > 0 &&
	    working_conn_count == connecting) {
		/* don't create new connections until the existing ones have
		   finished connecting successfully. */
		new_connections = 0;
	} else if (num_urgent == 0) {
		new_connections = connecting == 0 ? 1 : 0;
	} else {
		new_connections = (num_urgent > connecting ? num_urgent - connecting : 0);
	}
	http_client_peer_debug(peer,
		"Creating %u new connections to handle requests "
		"(already %u usable, connecting to %u, closing %u)",
		new_connections, working_conn_count - connecting,
		connecting, closing);
	if (new_connections > 0) {
		*created_connections = TRUE;
		http_client_peer_connect(peer, new_connections);
	}

	/* now we wait until it is connected */
	return FALSE;
}

bool http_client_peer_handle_requests(struct http_client_peer *peer)
{
	bool created_connections = FALSE;

	while (http_client_peer_next_request(peer, &created_connections)) ;
	return created_connections;
}

static struct http_client_peer *
http_client_peer_create(struct http_client *client,
			      const struct http_client_peer_addr *addr)
{
	struct http_client_peer *peer;

	i_assert(addr->https_name == NULL || client->ssl_ctx != NULL);

	peer = i_new(struct http_client_peer, 1);
	peer->client = client;
	peer->addr = *addr;
	peer->addr.https_name = i_strdup(addr->https_name);
	i_array_init(&peer->hosts, 16);
	i_array_init(&peer->conns, 16);

	hash_table_insert
		(client->peers, (const struct http_client_peer_addr *)&peer->addr, peer);
	DLLIST_PREPEND(&client->peers_list, peer);

	http_client_peer_debug(peer, "Peer created");
	http_client_peer_connect(peer, 1);
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

	hash_table_remove
		(peer->client->peers, (const struct http_client_peer_addr *)&peer->addr);
	DLLIST_REMOVE(&peer->client->peers_list, peer);

	i_free(peer->addr.https_name);
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

bool http_client_peer_have_host(struct http_client_peer *peer,
				struct http_client_host *host)
{
	struct http_client_host *const *host_idx;

	array_foreach(&peer->hosts, host_idx) {
		if (*host_idx == host)
			return TRUE;
	}
	return FALSE;
}

void http_client_peer_add_host(struct http_client_peer *peer,
			       struct http_client_host *host)
{
	if (!http_client_peer_have_host(peer, host))
		array_append(&peer->hosts, &host, 1);
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

void http_client_peer_connection_success(struct http_client_peer *peer)
{
	struct http_client_host *const *host;

	peer->last_connect_failed = FALSE;

	array_foreach(&peer->hosts, host) {
		http_client_host_connection_success(*host, &peer->addr);
	}
}

void http_client_peer_connection_failure(struct http_client_peer *peer,
					 const char *reason)
{
	struct http_client_host *const *host;
	unsigned int num_urgent;

	i_assert(array_count(&peer->conns) > 0);

	http_client_peer_debug(peer, "Failed to make connection");

	peer->last_connect_failed = TRUE;
	if (array_count(&peer->conns) > 1) {
		/* if there are other connections attempting to connect, wait
		   for them before failing the requests. remember that we had
		   trouble with connecting so in future we don't try to create
		   more than one connection until connects work again. */
	} else {
		/* this was the only/last connection and connecting to it
		   failed. a second connect will probably also fail, so just
		   abort all requests. */
		array_foreach(&peer->hosts, host) {
			http_client_host_connection_failure(*host, &peer->addr, reason);
		}
	}
	if (array_count(&peer->conns) == 0 &&
	    http_client_peer_requests_pending(peer, &num_urgent) == 0)
		http_client_peer_free(&peer);
}

void http_client_peer_connection_lost(struct http_client_peer *peer)
{
	unsigned int num_urgent;

	/* we get here when an already connected connection fails. if the
	   connect itself fails, http_client_peer_connection_failure() is
	   called instead. */

	if (peer->destroyed)
		return;

	http_client_peer_debug(peer, "Lost a connection (%d connections left)",
		array_count(&peer->conns));

	/* if there are pending requests for this peer, create a new connection
	   for them. */
	http_client_peer_handle_requests(peer);

	if (array_count(&peer->conns) == 0 &&
	    http_client_peer_requests_pending(peer, &num_urgent) == 0)
		http_client_peer_free(&peer);
}

unsigned int http_client_peer_idle_connections(struct http_client_peer *peer)
{
    struct http_client_connection *const *conn_idx;
    unsigned int idle = 0;

	/* find idle connections */
    array_foreach(&peer->conns, conn_idx) {
        if (http_client_connection_is_idle(*conn_idx))
			idle++;
    }

	return idle;
}

