/* Copyright (c) 2013-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "net.h"
#include "time-util.h"
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
	unsigned int hash = (unsigned int)peer->type;

	switch (peer->type) {
	case HTTP_CLIENT_PEER_ADDR_HTTPS:
	case HTTP_CLIENT_PEER_ADDR_HTTPS_TUNNEL:
		if (peer->a.tcp.https_name != NULL)
			hash += str_hash(peer->a.tcp.https_name);
		/* fall through */
	case HTTP_CLIENT_PEER_ADDR_RAW:
	case HTTP_CLIENT_PEER_ADDR_HTTP:
		if (peer->a.tcp.ip.family != 0)
			hash += net_ip_hash(&peer->a.tcp.ip);
		hash += peer->a.tcp.port;
		break;
	case HTTP_CLIENT_PEER_ADDR_UNIX:
		hash += str_hash(peer->a.un.path);
		break;
	}

	return hash;
}

int http_client_peer_addr_cmp
(const struct http_client_peer_addr *peer1,
	const struct http_client_peer_addr *peer2)
{
	int ret;

	if (peer1->type != peer2->type)
		return (peer1->type > peer2->type ? 1 : -1);
	switch (peer1->type) {
	case HTTP_CLIENT_PEER_ADDR_RAW:
	case HTTP_CLIENT_PEER_ADDR_HTTP:
	case HTTP_CLIENT_PEER_ADDR_HTTPS:
	case HTTP_CLIENT_PEER_ADDR_HTTPS_TUNNEL:
		/* Queues are created with peer addresses that have an uninitialized
		   IP value, because that is assigned later when the host lookup completes.
		   In all other other contexts, the IP is always initialized, so we do not
		   compare IPs when one of them is unassigned. */
		if (peer1->a.tcp.ip.family != 0 &&
			peer2->a.tcp.ip.family != 0 &&
			(ret=net_ip_cmp(&peer1->a.tcp.ip, &peer2->a.tcp.ip)) != 0)
			return ret;
		if (peer1->a.tcp.port != peer2->a.tcp.port)
			return (peer1->a.tcp.port > peer2->a.tcp.port ? 1 : -1);
		if (peer1->type != HTTP_CLIENT_PEER_ADDR_HTTPS &&
			peer1->type != HTTP_CLIENT_PEER_ADDR_HTTPS_TUNNEL)
			return 0;
		return null_strcmp
			(peer1->a.tcp.https_name, peer2->a.tcp.https_name);
	case HTTP_CLIENT_PEER_ADDR_UNIX:
		return null_strcmp(peer1->a.un.path, peer2->a.un.path);
	}
	i_unreached();
	return 0;
}

/*
 * Peer
 */

static void
http_client_peer_do_connect(struct http_client_peer *peer,
	unsigned int count)
{
	unsigned int i;

	for (i = 0; i < count; i++) {
		http_client_peer_debug(peer,
			"Making new connection %u of %u", i+1, count);
		(void)http_client_connection_create(peer);
	}
}

static void
http_client_peer_connect_backoff(struct http_client_peer *peer)
{
	i_assert(peer->to_backoff != NULL);

	http_client_peer_debug(peer,
		"Backoff timer expired");

	timeout_remove(&peer->to_backoff);

	if (array_count(&peer->queues) == 0) {
		http_client_peer_close(&peer);
		return;
	}

	http_client_peer_do_connect(peer, 1);
}

static bool
http_client_peer_start_backoff_timer(struct http_client_peer *peer)
{
	if (peer->to_backoff != NULL)
		return TRUE;

	if (peer->last_failure.tv_sec > 0) {
		int backoff_time_spent =
			timeval_diff_msecs(&ioloop_timeval, &peer->last_failure);

		if (backoff_time_spent < (int)peer->backoff_time_msecs) {
			http_client_peer_debug(peer,
				"Starting backoff timer for %d msecs",
				peer->backoff_time_msecs - backoff_time_spent);
			peer->to_backoff = timeout_add
				((unsigned int)(peer->backoff_time_msecs - backoff_time_spent),
					http_client_peer_connect_backoff, peer);
			return TRUE;
		}

		http_client_peer_debug(peer,
			"Backoff time already exceeded by %d msecs",
			backoff_time_spent - peer->backoff_time_msecs);
	}
	return FALSE;
}

static void
http_client_peer_connect(struct http_client_peer *peer, unsigned int count)
{
	if (http_client_peer_start_backoff_timer(peer))
		return;

	http_client_peer_do_connect(peer, count);
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

static void
http_client_peer_cancel(struct http_client_peer *peer)
{
	struct http_client_connection **conn;
	ARRAY_TYPE(http_client_connection) conns;

	http_client_peer_debug(peer, "Peer cancel");

	/* make a copy of the connection array; freed connections modify it */
	t_array_init(&conns, array_count(&peer->conns));
	array_copy(&conns.arr, 0, &peer->conns.arr, 0, array_count(&peer->conns));
	array_foreach_modifiable(&conns, conn) {
		if (!http_client_connection_is_active(*conn))
			http_client_connection_close(conn);
	}
}

static unsigned int
http_client_peer_requests_pending(struct http_client_peer *peer,
				  unsigned int *num_urgent_r)
{
	struct http_client_queue *const *queue;
	unsigned int num_requests = 0, num_urgent = 0, requests, urgent;

	array_foreach(&peer->queues, queue) {
		requests = http_client_queue_requests_pending(*queue, &urgent);

		num_requests += requests;
		num_urgent += urgent;
	}
	*num_urgent_r = num_urgent;
	return num_requests;
}

static void http_client_peer_check_idle(struct http_client_peer *peer)
{
	struct http_client_connection *const *conn_idx;
	unsigned int num_urgent = 0;

	if (array_count(&peer->conns) == 0 &&
		http_client_peer_requests_pending(peer, &num_urgent) == 0) {
		/* no connections or pending requests; die immediately */
		http_client_peer_close(&peer);
		return;
	}

	/* check all connections for idle status */
	array_foreach(&peer->conns, conn_idx) {
		http_client_connection_check_idle(*conn_idx);
	}
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
	struct http_client_peer *tmp_peer;
	bool statistics_dirty = TRUE;

	/* FIXME: limit the number of requests handled in one run to prevent
	   I/O starvation. */

	/* disconnect pending connections if we're not linked to any queue
	   anymore */
	if (array_count(&peer->queues) == 0) {
		http_client_peer_debug(peer,
			"Peer no longer used; will now cancel pending connections "
			"(%u connections exist)", array_count(&peer->conns));
		http_client_peer_cancel(peer);
		return;
	}

	/* don't do anything unless we have pending requests */
	num_pending = http_client_peer_requests_pending(peer, &num_urgent);
	if (num_pending == 0) {
		http_client_peer_debug(peer,
			"No requests to service for this peer "
			"(%u connections exist)", array_count(&peer->conns));
		http_client_peer_check_idle(peer);
		return;
	}

	http_client_peer_ref(peer);
	peer->handling_requests = TRUE;
	t_array_init(&conns_avail, array_count(&peer->conns));
	do {
		bool conn_lost = FALSE;

		array_clear(&conns_avail);
		connecting = closing = idle = 0;

		/* gather connection statistics */
		array_foreach(&peer->conns, conn_idx) {
			struct http_client_connection *conn = *conn_idx;
			int ret;

			if ((ret=http_client_connection_check_ready(conn)) < 0) {
				conn_lost = TRUE;
				break;
			} else if (ret > 0) {
				struct _conn_available *conn_avail;
				unsigned int insert_idx, pending_requests;

				/* compile sorted availability list */
				pending_requests = http_client_connection_count_pending(conn);
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
				conn_avail->conn = conn;
				conn_avail->pending_requests = pending_requests;
				if (pending_requests == 0)
					idle++;
			}
			/* count the number of connecting and closing connections */
			if (conn->closing)
				closing++;
			else if (!conn->connected)
				connecting++;
		}

		if (conn_lost) {
			/* connection array changed while iterating; retry */
			continue;
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
			http_client_peer_debug(peer,
				"No more requests to service for this peer "
				"(%u connections exist)", array_count(&peer->conns));
			http_client_peer_check_idle(peer);
			break;
		}
	} while (statistics_dirty);

	tmp_peer = peer;
	if (!http_client_peer_unref(&tmp_peer))
		return;
	peer->handling_requests = FALSE;

	if (num_pending == 0)
		return;

	i_assert(idle == 0);

	/* determine how many new connections we can set up */
	if (peer->last_failure.tv_sec > 0 && working_conn_count > 0 &&
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

	peer = i_new(struct http_client_peer, 1);
	peer->refcount = 1;
	peer->client = client;
	peer->addr = *addr;

	switch (addr->type) {
	case HTTP_CLIENT_PEER_ADDR_RAW:
	case HTTP_CLIENT_PEER_ADDR_HTTP:
		i_assert(peer->addr.a.tcp.ip.family != 0);
		break;
	case HTTP_CLIENT_PEER_ADDR_HTTPS:
	case HTTP_CLIENT_PEER_ADDR_HTTPS_TUNNEL:
		i_assert(peer->addr.a.tcp.ip.family != 0);
		i_assert(client->ssl_ctx != NULL);
		peer->addr_name = i_strdup(addr->a.tcp.https_name);
		peer->addr.a.tcp.https_name = peer->addr_name;
		break;
	case HTTP_CLIENT_PEER_ADDR_UNIX:
		peer->addr_name = i_strdup(addr->a.un.path);
		peer->addr.a.un.path = peer->addr_name;
		break;
	default:
		break;
	}

	i_array_init(&peer->queues, 16);
	i_array_init(&peer->conns, 16);

	hash_table_insert
		(client->peers, (const struct http_client_peer_addr *)&peer->addr, peer);
	DLLIST_PREPEND(&client->peers_list, peer);

	http_client_peer_debug(peer, "Peer created");
	return peer;
}

static void
http_client_peer_disconnect(struct http_client_peer *peer)
{
	struct http_client_connection **conn;
	ARRAY_TYPE(http_client_connection) conns;

	if (peer->disconnected)
		return;
	peer->disconnected = TRUE;

	http_client_peer_debug(peer, "Peer disconnect");

	/* make a copy of the connection array; freed connections modify it */
	t_array_init(&conns, array_count(&peer->conns));
	array_copy(&conns.arr, 0, &peer->conns.arr, 0, array_count(&peer->conns));
	array_foreach_modifiable(&conns, conn) {
		http_client_connection_peer_closed(conn);
	}
	i_assert(array_count(&peer->conns) == 0);

	if (peer->to_req_handling != NULL)
		timeout_remove(&peer->to_req_handling);
	if (peer->to_backoff != NULL)
		timeout_remove(&peer->to_backoff);

	hash_table_remove
		(peer->client->peers, (const struct http_client_peer_addr *)&peer->addr);
	DLLIST_REMOVE(&peer->client->peers_list, peer);
}

void http_client_peer_ref(struct http_client_peer *peer)
{
	peer->refcount++;
}

bool http_client_peer_unref(struct http_client_peer **_peer)
{
	struct http_client_peer *peer = *_peer;

	i_assert(peer->refcount > 0);

	*_peer = NULL;

	if (--peer->refcount > 0)
		return TRUE;

	http_client_peer_debug(peer, "Peer destroy");

	http_client_peer_disconnect(peer);

	array_free(&peer->conns);
	array_free(&peer->queues);
	i_free(peer->addr_name);
	i_free(peer);
	return FALSE;
}

void http_client_peer_close(struct http_client_peer **_peer)
{
	struct http_client_peer *peer = *_peer;

	http_client_peer_debug(peer, "Peer close");

	http_client_peer_disconnect(peer);

	(void)http_client_peer_unref(_peer);
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

bool http_client_peer_have_queue(struct http_client_peer *peer,
				struct http_client_queue *queue)
{
	struct http_client_queue *const *queue_idx;

	array_foreach(&peer->queues, queue_idx) {
		if (*queue_idx == queue)
			return TRUE;
	}
	return FALSE;
}

void http_client_peer_link_queue(struct http_client_peer *peer,
			       struct http_client_queue *queue)
{
	if (!http_client_peer_have_queue(peer, queue)) {
		array_append(&peer->queues, &queue, 1);

		http_client_peer_debug(peer,
			"Linked queue %s (%d queues linked)",
			queue->name, array_count(&peer->queues));
	}
}

void http_client_peer_unlink_queue(struct http_client_peer *peer,
				struct http_client_queue *queue)
{
	struct http_client_queue *const *queue_idx;

	array_foreach(&peer->queues, queue_idx) {
		if (*queue_idx == queue) {
			array_delete(&peer->queues,
				array_foreach_idx(&peer->queues, queue_idx), 1);

			http_client_peer_debug(peer,
				"Unlinked queue %s (%d queues linked)",
				queue->name, array_count(&peer->queues));

			if (array_count(&peer->queues) == 0) {
				if (http_client_peer_start_backoff_timer(peer)) {
					/* will disconnect any pending connections */
					http_client_peer_trigger_request_handler(peer);
				} else {
					/* drop peer immediately */
					http_client_peer_close(&peer);
				}
			}
			return;
		}
	}
}

struct http_client_request *
http_client_peer_claim_request(struct http_client_peer *peer, bool no_urgent)
{
	struct http_client_queue *const *queue_idx;
	struct http_client_request *req;

	array_foreach(&peer->queues, queue_idx) {
		if ((req=http_client_queue_claim_request
			(*queue_idx, &peer->addr, no_urgent)) != NULL) {
			req->peer = peer;
			return req;
		}
	}

	return NULL;
}

void http_client_peer_connection_success(struct http_client_peer *peer)
{
	struct http_client_queue *const *queue;

	http_client_peer_debug(peer,
		"Successfully connected (connections=%u)",
		array_count(&peer->conns));

	peer->last_failure.tv_sec = peer->last_failure.tv_usec = 0;
	peer->backoff_time_msecs = 0;

	if (peer->to_backoff != NULL)
		timeout_remove(&peer->to_backoff);

	array_foreach(&peer->queues, queue) {
		http_client_queue_connection_success(*queue, &peer->addr);
	}

	http_client_peer_trigger_request_handler(peer);
}

void http_client_peer_connection_failure(struct http_client_peer *peer,
					 const char *reason)
{
	const struct http_client_settings *set = &peer->client->set;
	struct http_client_queue *const *queue;
	unsigned int pending;

	peer->last_failure = ioloop_timeval;

	/* count number of pending connections */
	pending = http_client_peer_pending_connections(peer);
	i_assert(pending > 0);

	http_client_peer_debug(peer,
		"Failed to make connection "
		"(connections=%u, connecting=%u)",
		array_count(&peer->conns), pending);

	/* manage backoff timer only when this was the only attempt */
	if (pending == 1) {
		if (peer->backoff_time_msecs == 0)
			peer->backoff_time_msecs = set->connect_backoff_time_msecs;
		else
			peer->backoff_time_msecs *= 2;
		if (peer->backoff_time_msecs > set->connect_backoff_max_time_msecs)
			peer->backoff_time_msecs = set->connect_backoff_max_time_msecs;
	}

	if (pending > 1) {
		/* if there are other connections attempting to connect, wait
		   for them before failing the requests. remember that we had
		   trouble with connecting so in future we don't try to create
		   more than one connection until connects work again. */
	} else {
		/* this was the only/last connection and connecting to it
		   failed. a second connect will probably also fail, so just
		   try another IP for the hosts(s) or abort all requests if this
		   was the only/last option. */
		array_foreach(&peer->queues, queue) {
			http_client_queue_connection_failure(*queue, &peer->addr, reason);
		}
	}
}

void http_client_peer_connection_lost(struct http_client_peer *peer)
{
	unsigned int num_pending, num_urgent;

	/* we get here when an already connected connection fails. if the
	   connect itself fails, http_client_peer_connection_failure() is
	   called instead. */

	if (peer->disconnected)
		return;

	num_pending = http_client_peer_requests_pending(peer, &num_urgent);

	http_client_peer_debug(peer,
		"Lost a connection "
		"(%d connections left, %u requests pending, %u requests urgent)",
		array_count(&peer->conns), num_pending, num_urgent);

	if (peer->handling_requests) {
		/* we got here from the request handler loop */
		return;
	}

	/* if there are pending requests for this peer, create a new connection
	   for them. if not, this peer will wind itself down. */
	http_client_peer_trigger_request_handler(peer);
}

unsigned int
http_client_peer_idle_connections(struct http_client_peer *peer)
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

unsigned int
http_client_peer_active_connections(struct http_client_peer *peer)
{
	struct http_client_connection *const *conn_idx;
	unsigned int active = 0;

	/* find idle connections */
	array_foreach(&peer->conns, conn_idx) {
		if (http_client_connection_is_active(*conn_idx))
			active++;
	}

	return active;
}

unsigned int
http_client_peer_pending_connections(struct http_client_peer *peer)
{
	struct http_client_connection *const *conn_idx;
	unsigned int pending = 0;

	/* find idle connections */
	array_foreach(&peer->conns, conn_idx) {
		if (!(*conn_idx)->closing && !(*conn_idx)->connected)
			pending++;
	}

	return pending;
}

void http_client_peer_switch_ioloop(struct http_client_peer *peer)
{
	if (peer->to_req_handling != NULL) {
		peer->to_req_handling =
			io_loop_move_timeout(&peer->to_req_handling);
	}
	if (peer->to_backoff != NULL) {
		peer->to_backoff =
			io_loop_move_timeout(&peer->to_backoff);
	}
}

