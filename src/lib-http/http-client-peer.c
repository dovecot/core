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
		i_debug("http-client: peer %s: %s", 
			http_client_peer_label(peer), t_strdup_vprintf(format, args));
		va_end(args);
	}
}

/*
 * Peer address
 */

unsigned int http_client_peer_addr_hash
(const struct http_client_peer_addr *peer)
{
	switch (peer->type) {
	case HTTP_CLIENT_PEER_ADDR_RAW:
		return net_ip_hash(&peer->ip) + peer->port + 1;
	case HTTP_CLIENT_PEER_ADDR_HTTP:
		return net_ip_hash(&peer->ip) + peer->port;
	case HTTP_CLIENT_PEER_ADDR_HTTPS:
	case HTTP_CLIENT_PEER_ADDR_HTTPS_TUNNEL:
		return net_ip_hash(&peer->ip) + peer->port +
			(peer->https_name == NULL ? 0 : str_hash(peer->https_name));
	}
	i_unreached();
	return 0;
}

int http_client_peer_addr_cmp
(const struct http_client_peer_addr *peer1,
	const struct http_client_peer_addr *peer2)
{
	int ret;

	if (peer1->type != peer2->type)
		return (peer1->type > peer2->type ? 1 : -1);
	if ((ret=net_ip_cmp(&peer1->ip, &peer2->ip)) != 0)
		return ret;
	if (peer1->port != peer2->port)
		return (peer1->port > peer2->port ? 1 : -1);
	if (peer1->type != HTTP_CLIENT_PEER_ADDR_HTTPS)
		return 0;
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
		http_client_peer_debug(peer,
			"Making new connection %u of %u", i+1, count);
		(void)http_client_connection_create(peer);
	}
}

bool http_client_peer_is_connected(struct http_client_peer *peer)
{
	struct http_client_connection *const *conn_idx;

	array_foreach(&peer->conns, conn_idx) {
		if ((*conn_idx)->connected)
			return TRUE;
	}

	return FALSE;
}

static void http_client_peer_check_idle(struct http_client_peer *peer)
{
	struct http_client_connection *const *conn_idx;

	array_foreach(&peer->conns, conn_idx) {
		http_client_connection_check_idle(*conn_idx);
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

static void
http_client_peer_handle_requests_real(struct http_client_peer *peer)
{
	struct _conn_available {
		struct http_client_connection *conn;
		unsigned int pending_requests;
	};
	struct http_client_connection *const *conn_idx;
	ARRAY(struct _conn_available) conns_avail;
	struct _conn_available *conn_avail_idx;
	unsigned int connecting, closing, idle;
	unsigned int num_pending, num_urgent, new_connections, 	working_conn_count;
	bool statistics_dirty = TRUE;

	/* FIXME: limit the number of requests handled in one run to prevent
	   I/O starvation. */

	/* don't do anything unless we have pending requests */
	num_pending = http_client_peer_requests_pending(peer, &num_urgent);
	if (num_pending == 0) {
		http_client_peer_check_idle(peer);
		return;
	}

	t_array_init(&conns_avail, array_count(&peer->conns));
	do {
		array_clear(&conns_avail);
		connecting = closing = idle = 0;

		/* gather connection statistics */
		array_foreach(&peer->conns, conn_idx) {
			if (http_client_connection_is_ready(*conn_idx)) {			
				struct _conn_available *conn_avail;
				unsigned int insert_idx, pending_requests;

				/* compile sorted availability list */
				pending_requests = http_client_connection_count_pending(*conn_idx);
				if (array_count(&conns_avail) == 0) {
					insert_idx = 0;
				} else {
					insert_idx = array_count(&conns_avail);
					array_foreach_modifiable(&conns_avail, conn_avail_idx) {
						if (conn_avail_idx->pending_requests > pending_requests) {
							insert_idx = array_foreach_idx(&conns_avail, conn_avail_idx);
							break;
						}
					}
				}
				conn_avail = array_insert_space(&conns_avail, insert_idx);
				conn_avail->conn = *conn_idx;
				conn_avail->pending_requests = pending_requests;
				if (pending_requests == 0)
					idle++;
			}
			/* count the number of connecting and closing connections */
			if ((*conn_idx)->closing)
				closing++;
			else if (!(*conn_idx)->connected)
				connecting++;
		}

		working_conn_count = array_count(&peer->conns) - closing;
		statistics_dirty = FALSE;

		/* use idle connections right away */
		if (idle > 0) {
			http_client_peer_debug(peer,
				"Using %u idle connections to handle %u requests "
				"(%u total connections ready)",
				idle, num_pending > idle ? idle : num_pending,
				array_count(&conns_avail));

			array_foreach_modifiable(&conns_avail, conn_avail_idx) {
				if (num_pending == 0 || conn_avail_idx->pending_requests > 0)
					break;
				idle--;
				if (http_client_connection_next_request(conn_avail_idx->conn) <= 0) {
					/* no longer available (probably connection error/closed) */
					statistics_dirty = TRUE;
					conn_avail_idx->conn = NULL;
				} else {
					/* update statistics */
					conn_avail_idx->pending_requests++;
					if (num_urgent > 0)
						num_urgent--;
					num_pending--;
				}
			}
		}
	
		/* don't continue unless we have more pending requests */
		num_pending = http_client_peer_requests_pending(peer, &num_urgent);
		if (num_pending == 0) {
			http_client_peer_check_idle(peer);
			return;
		}
	} while (statistics_dirty);

	i_assert(idle == 0);

	/* determine how many new connections we can set up */
	if (peer->last_connect_failed && working_conn_count > 0 &&
	    working_conn_count == connecting) {
		/* don't create new connections until the existing ones have
		   finished connecting successfully. */
		new_connections = 0;
	} else {
		if (working_conn_count - connecting + num_urgent >=
			peer->client->set.max_parallel_connections) {
			/* only create connections for urgent requests */
			new_connections = (num_urgent > connecting ? num_urgent - connecting : 0);
		} else if (num_pending <= connecting) {
			/* there are already enough connections being made */
			new_connections = 0;
		} else if (working_conn_count == connecting) {
			/* no connections succeeded so far, don't hammer the server with more
			   than one connection attempt unless its urgent */
			if (num_urgent > 0) {
				new_connections =
					(num_urgent > connecting ? num_urgent - connecting : 0);
			} else {
				new_connections = (connecting == 0 ? 1 : 0);
			}
		} else if (num_pending - connecting >
			peer->client->set.max_parallel_connections - working_conn_count) {
			/* create maximum allowed connections */
			new_connections =
				peer->client->set.max_parallel_connections - working_conn_count;
		} else {
			/* create as many connections as we need */
			new_connections = num_pending - connecting;
		}
	}

	/* create connections */
	if (new_connections > 0) {
		http_client_peer_debug(peer,
			"Creating %u new connections to handle requests "
			"(already %u usable, connecting to %u, closing %u)",
			new_connections, working_conn_count - connecting,
			connecting, closing);
		http_client_peer_connect(peer, new_connections);
		return;
	}

	/* cannot create new connections for normal request; attempt pipelining */
	if (working_conn_count - connecting >=
		peer->client->set.max_parallel_connections) {
		unsigned int pipeline_level = 0, total_handled = 0, handled;

		if (!peer->allows_pipelining) {
			http_client_peer_debug(peer,
				"Will not pipeline until peer has shown support");
			return;
		}

		/* fill pipelines */
		do {
			handled = 0;
			/* fill smallest pipelines first,
			   until all pipelines are filled to the same level */
			array_foreach_modifiable(&conns_avail, conn_avail_idx) {
				if (conn_avail_idx->conn == NULL)
					continue;
				if (pipeline_level == 0) {
					pipeline_level = conn_avail_idx->pending_requests;
				} else if (conn_avail_idx->pending_requests > pipeline_level) {
					pipeline_level = conn_avail_idx->pending_requests;
					break; /* restart from least busy connection */
				}
				/* pipeline it */
				if (http_client_connection_next_request(conn_avail_idx->conn) <= 0) {
					/* connection now unavailable */
					conn_avail_idx->conn = NULL;
				} else {
					/* successfully pipelined */
					conn_avail_idx->pending_requests++;
					num_pending--;
					handled++;
				}
			}
			
			total_handled += handled;
		} while (num_pending > num_urgent && handled > 0);

		http_client_peer_debug(peer,
			"Pipelined %u requests (filled pipelines up to %u requests)",
			total_handled, pipeline_level);
		return;
	}

	/* still waiting for connections to finish */
	http_client_peer_debug(peer,
		"No request handled; waiting for new connections");
	return;
}

static void http_client_peer_handle_requests(struct http_client_peer *peer)
{
	if (peer->to_req_handling != NULL)
		timeout_remove(&peer->to_req_handling);
	
	T_BEGIN {
		http_client_peer_handle_requests_real(peer);
	} T_END;
}

void http_client_peer_trigger_request_handler(struct http_client_peer *peer)
{
	/* trigger request handling through timeout */
	if (peer->to_req_handling == NULL) {
		peer->to_req_handling =
			timeout_add_short(0, http_client_peer_handle_requests, peer);
	}
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
	peer->https_name = i_strdup(addr->https_name);
	peer->addr.https_name = peer->https_name;
	i_array_init(&peer->hosts, 16);
	i_array_init(&peer->conns, 16);

	hash_table_insert
		(client->peers, (const struct http_client_peer_addr *)&peer->addr, peer);
	DLLIST_PREPEND(&client->peers_list, peer);

	http_client_peer_debug(peer, "Peer created");
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

	if (peer->to_req_handling != NULL)
		timeout_remove(&peer->to_req_handling);

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

	i_free(peer->https_name);
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

void http_client_peer_remove_host(struct http_client_peer *peer,
				struct http_client_host *host)
{
	struct http_client_host *const *host_idx;

	array_foreach(&peer->hosts, host_idx) {
		if (*host_idx == host) {
			array_delete(&peer->hosts, array_foreach_idx(&peer->hosts, host_idx), 1);
			if (array_count(&peer->hosts) == 0)
				http_client_peer_free(&peer);
			return;
		}
	}
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

	http_client_peer_trigger_request_handler(peer);
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
		   try another IP for the hosts(s) or abort all requests if this
		   was the only/last option. */
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
	http_client_peer_trigger_request_handler(peer);

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

void http_client_peer_switch_ioloop(struct http_client_peer *peer)
{
	if (peer->to_req_handling != NULL) {
		peer->to_req_handling =
			io_loop_move_timeout(&peer->to_req_handling);
	}
}

