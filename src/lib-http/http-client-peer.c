/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

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

static void
http_client_peer_connect_backoff(struct http_client_peer *peer);

static void
http_client_peer_shared_connection_success(
	struct http_client_peer_shared *pshared);
static void
http_client_peer_shared_connection_failure(
	struct http_client_peer_shared *pshared);
static void
http_client_peer_connection_succeeded_pool(struct http_client_peer *peer);
static void
http_client_peer_connection_failed_pool(struct http_client_peer *peer,
					const char *reason);

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
}

/*
 * Peer pool
 */

static struct http_client_peer_pool *
http_client_peer_pool_create(struct http_client_peer_shared *pshared,
	struct ssl_iostream_context *ssl_ctx, const char *rawlog_dir)
{
	struct http_client_peer_pool *ppool;

	ppool = i_new(struct http_client_peer_pool, 1);
	ppool->refcount = 1;
	ppool->peer = pshared;
	ppool->event = event_create(pshared->cctx->event);
	event_set_append_log_prefix(ppool->event, t_strdup_printf(
		"peer %s: ", http_client_peer_shared_label(pshared)));

	http_client_peer_shared_ref(pshared);

	i_array_init(&ppool->conns, 16);
	i_array_init(&ppool->pending_conns, 16);
	i_array_init(&ppool->idle_conns, 16);

	DLLIST_PREPEND(&pshared->pools_list, ppool);

	ppool->ssl_ctx = ssl_ctx;
	ppool->rawlog_dir = i_strdup(rawlog_dir);

	e_debug(ppool->event, "Peer pool created");

	return ppool;
}

void http_client_peer_pool_ref(struct http_client_peer_pool *ppool)
{
	if (ppool->destroyed)
		return;
	ppool->refcount++;
}

void http_client_peer_pool_close(struct http_client_peer_pool **_ppool)
{
	struct http_client_peer_pool *ppool = *_ppool;
	struct http_client_connection **conn;
	ARRAY_TYPE(http_client_connection) conns;

	http_client_peer_pool_ref(ppool);

	/* make a copy of the connection array; freed connections modify it */
	t_array_init(&conns, array_count(&ppool->conns));
	array_copy(&conns.arr, 0, &ppool->conns.arr, 0, array_count(&ppool->conns));
	array_foreach_modifiable(&conns, conn)
		http_client_connection_unref(conn);
	i_assert(array_count(&ppool->idle_conns) == 0);
	i_assert(array_count(&ppool->pending_conns) == 0);
	i_assert(array_count(&ppool->conns) == 0);

	http_client_peer_pool_unref(_ppool);
}

void http_client_peer_pool_unref(struct http_client_peer_pool **_ppool)
{
	struct http_client_peer_pool *ppool = *_ppool;
	struct http_client_peer_shared *pshared = ppool->peer;

	*_ppool = NULL;

	if (ppool->destroyed)
		return;

	i_assert(ppool->refcount > 0);
	if (--ppool->refcount > 0)
		return;

	e_debug(ppool->event, "Peer pool destroy");
	ppool->destroyed = TRUE;

	i_assert(array_count(&ppool->idle_conns) == 0);
	i_assert(array_count(&ppool->conns) == 0);
	array_free(&ppool->idle_conns);
	array_free(&ppool->pending_conns);
	array_free(&ppool->conns);

	DLLIST_REMOVE(&pshared->pools_list, ppool);

	event_unref(&ppool->event);
	i_free(ppool->rawlog_dir);
	i_free(ppool);
	http_client_peer_shared_unref(&pshared);
}

static struct http_client_peer_pool *
http_client_peer_pool_get(struct http_client_peer_shared *pshared,
	struct http_client *client)
{
	struct http_client_peer_pool *ppool;
	struct ssl_iostream_context *ssl_ctx = client->ssl_ctx;
	const char *rawlog_dir = client->set.rawlog_dir;

	i_assert(!http_client_peer_addr_is_https(&pshared->addr) ||
		ssl_ctx != NULL);

	ppool = pshared->pools_list;
	while (ppool != NULL) {
		if (ppool->ssl_ctx == ssl_ctx &&
			null_strcmp(ppool->rawlog_dir, rawlog_dir) == 0)
			break;
		ppool = ppool->next;
	}

	if (ppool == NULL) {
		ppool = http_client_peer_pool_create
			(pshared, ssl_ctx, rawlog_dir);
	} else {
		e_debug(ppool->event, "Peer pool reused");
		http_client_peer_pool_ref(ppool);
	}

	return ppool;
}

static void
http_client_peer_pool_connection_success(
	struct http_client_peer_pool *ppool)
{
	e_debug(ppool->event, "Successfully connected "
		"(%u connections exist, %u pending)",
		array_count(&ppool->conns), array_count(&ppool->pending_conns));

	http_client_peer_shared_connection_success(ppool->peer);

	if (array_count(&ppool->pending_conns) > 0) {
		/* if there are other connections attempting to connect, wait
		   for them before notifying other peer objects about the
		   success (which may be premature). */
	} else {
		struct http_client_peer *peer;

		/* this was the only/last connection and connecting to it
		   succeeded. notify all interested peers in this pool about the
		   success */
		peer = ppool->peer->peers_list;
		while (peer != NULL) {
			struct http_client_peer *peer_next = peer->shared_next;
			if (peer->ppool == ppool)
				http_client_peer_connection_succeeded_pool(peer);
			peer = peer_next;
		}
	}
}

static void
http_client_peer_pool_connection_failure(
	struct http_client_peer_pool *ppool, const char *reason)
{
	e_debug(ppool->event,
		"Failed to make connection "
		"(%u connections exist, %u pending)",
		array_count(&ppool->conns), array_count(&ppool->pending_conns));

	http_client_peer_shared_connection_failure(ppool->peer);

	if (array_count(&ppool->pending_conns) > 0) {
		/* if there are other connections attempting to connect, wait
		   for them before failing the requests. remember that we had
		   trouble with connecting so in future we don't try to create
		   more than one connection until connects work again. */
	} else {
		struct http_client_peer *peer;

		/* this was the only/last connection and connecting to it
		   failed. notify all interested peers in this pool about the
		   failure */
		peer = ppool->peer->peers_list;
		while (peer != NULL) {
			struct http_client_peer *peer_next = peer->shared_next;
			if (peer->ppool == ppool)
				http_client_peer_connection_failed_pool(peer, reason);
			peer = peer_next;
		}
	}
}

/*
 * Peer (shared)
 */

static struct http_client_peer_shared *
http_client_peer_shared_create(struct http_client_context *cctx,
			      const struct http_client_peer_addr *addr)
{
	struct http_client_peer_shared *pshared;

	pshared = i_new(struct http_client_peer_shared, 1);
	pshared->refcount = 1;
	pshared->cctx = cctx;

	pshared->addr = *addr;
	switch (addr->type) {
	case HTTP_CLIENT_PEER_ADDR_RAW:
	case HTTP_CLIENT_PEER_ADDR_HTTP:
		i_assert(pshared->addr.a.tcp.ip.family != 0);
		break;
	case HTTP_CLIENT_PEER_ADDR_HTTPS:
	case HTTP_CLIENT_PEER_ADDR_HTTPS_TUNNEL:
		i_assert(pshared->addr.a.tcp.ip.family != 0);
		pshared->addr_name = i_strdup(addr->a.tcp.https_name);
		pshared->addr.a.tcp.https_name = pshared->addr_name;
		break;
	case HTTP_CLIENT_PEER_ADDR_UNIX:
		pshared->addr_name = i_strdup(addr->a.un.path);
		pshared->addr.a.un.path = pshared->addr_name;
		break;
	default:
		break;
	}
	pshared->event = event_create(cctx->event);
	event_set_append_log_prefix(pshared->event, t_strdup_printf(
		"peer %s (shared): ", http_client_peer_shared_label(pshared)));

	hash_table_insert(cctx->peers,
		(const struct http_client_peer_addr *)&pshared->addr, pshared);
	DLLIST_PREPEND(&cctx->peers_list, pshared);

	pshared->backoff_initial_time_msecs =
		cctx->set.connect_backoff_time_msecs;
	pshared->backoff_max_time_msecs =
		cctx->set.connect_backoff_max_time_msecs;

	e_debug(pshared->event, "Peer created");
	return pshared;
}

void http_client_peer_shared_ref(struct http_client_peer_shared *pshared)
{
	pshared->refcount++;
}

void http_client_peer_shared_unref(struct http_client_peer_shared **_pshared)
{
	struct http_client_peer_shared *pshared = *_pshared;

	*_pshared = NULL;

	i_assert(pshared->refcount > 0);
	if (--pshared->refcount > 0)
		return;

	e_debug(pshared->event, "Peer destroy");

	i_assert(pshared->pools_list == NULL);

	/* unlist in client */
	hash_table_remove(pshared->cctx->peers,
		(const struct http_client_peer_addr *)&pshared->addr);
	DLLIST_REMOVE(&pshared->cctx->peers_list, pshared);

	timeout_remove(&pshared->to_backoff);

	event_unref(&pshared->event);
	i_free(pshared->addr_name);
	i_free(pshared->label);
	i_free(pshared);
}

static struct http_client_peer_shared *
http_client_peer_shared_get(struct http_client_context *cctx,
			   const struct http_client_peer_addr *addr)
{
	struct http_client_peer_shared *pshared;

	pshared = hash_table_lookup(cctx->peers, addr);
	if (pshared == NULL) {
		pshared = http_client_peer_shared_create(cctx, addr);
	} else {
		e_debug(pshared->event, "Peer reused");
		http_client_peer_shared_ref(pshared);
	}

	return pshared;
}

void http_client_peer_shared_close(struct http_client_peer_shared **_pshared)
{
	struct http_client_peer_shared *pshared = *_pshared;
	struct http_client_peer_pool *pool, *next;

	http_client_peer_shared_ref(pshared);
	pool = pshared->pools_list;
	while (pool != NULL) {
		next = pool->next;
		http_client_peer_pool_close(&pool);
		pool = next;
	}
	http_client_peer_shared_unref(_pshared);
}

const char *
http_client_peer_shared_label(struct http_client_peer_shared *pshared)
{
	if (pshared->label == NULL) {
		switch (pshared->addr.type) {
		case HTTP_CLIENT_PEER_ADDR_HTTPS_TUNNEL:
			pshared->label = i_strconcat
				(http_client_peer_addr2str(&pshared->addr), " (tunnel)", NULL);
			break;
		default:
			pshared->label = i_strdup
				(http_client_peer_addr2str(&pshared->addr));
		}
	}
	return pshared->label;
}

static void
http_client_peer_shared_connect_backoff(
	struct http_client_peer_shared *pshared)
{
	struct http_client_peer *peer;

	i_assert(pshared->to_backoff != NULL);

	e_debug(pshared->event, "Backoff timer expired");

	timeout_remove(&pshared->to_backoff);

	peer = pshared->peers_list;
	while (peer != NULL) {
		http_client_peer_connect_backoff(peer);
		peer = peer->shared_next;
	}
}

static bool
http_client_peer_shared_start_backoff_timer(
	struct http_client_peer_shared *pshared)
{
	if (pshared->to_backoff != NULL)
		return TRUE;

	if (pshared->last_failure.tv_sec > 0) {
		int backoff_time_spent =
			timeval_diff_msecs(&ioloop_timeval, &pshared->last_failure);

		if (backoff_time_spent < (int)pshared->backoff_current_time_msecs) {
			unsigned int new_time = (unsigned int)
				(pshared->backoff_current_time_msecs - backoff_time_spent);
			e_debug(pshared->event,
				"Starting backoff timer for %d msecs", new_time);
			pshared->to_backoff = timeout_add_to(
				pshared->cctx->ioloop, new_time,
				http_client_peer_shared_connect_backoff, pshared);
			return TRUE;
		}

		e_debug(pshared->event,
			"Backoff time already exceeded by %d msecs",
			backoff_time_spent - pshared->backoff_current_time_msecs);
	}
	return FALSE;
}

static void
http_client_peer_shared_increase_backoff_timer(
	struct http_client_peer_shared *pshared)
{
	if (pshared->backoff_current_time_msecs == 0)
		pshared->backoff_current_time_msecs = pshared->backoff_initial_time_msecs;
	else
		pshared->backoff_current_time_msecs *= 2;
	if (pshared->backoff_current_time_msecs >
		pshared->backoff_max_time_msecs) {
		pshared->backoff_current_time_msecs = pshared->backoff_max_time_msecs;
	}
}

static void
http_client_peer_shared_reset_backoff_timer(
	struct http_client_peer_shared *pshared)
{
	pshared->backoff_current_time_msecs = 0;

	timeout_remove(&pshared->to_backoff);
}

static void
http_client_peer_shared_connection_success(
	struct http_client_peer_shared *pshared)
{
	pshared->last_failure.tv_sec = pshared->last_failure.tv_usec = 0;
	http_client_peer_shared_reset_backoff_timer(pshared);
}

static void
http_client_peer_shared_connection_failure(
	struct http_client_peer_shared *pshared)
{
	struct http_client_peer_pool *ppool;
	unsigned int pending = 0;

	/* determine the number of connections still pending */
	ppool = pshared->pools_list;
	while (ppool != NULL) {
		pending += array_count(&ppool->pending_conns);
		ppool = ppool->next;
	}

	pshared->last_failure = ioloop_timeval;

	/* manage backoff timer only when this was the only attempt */
	if (pending == 0)
		http_client_peer_shared_increase_backoff_timer(pshared);
}

static void
http_client_peer_shared_connection_lost(
	struct http_client_peer_shared *pshared,
	bool premature)
{
	/* update backoff timer if the connection was lost prematurely.
	   this prevents reconnecting immediately to a server that is
	   misbehaving by disconnecting before sending a response.
	 */
	if (premature) {
		pshared->last_failure = ioloop_timeval;
		http_client_peer_shared_increase_backoff_timer(pshared);
	}
}

void http_client_peer_shared_switch_ioloop(
	struct http_client_peer_shared *pshared)
{
	if (pshared->to_backoff != NULL) {
		pshared->to_backoff =
			io_loop_move_timeout(&pshared->to_backoff);
	}
}

unsigned int
http_client_peer_shared_max_connections(
	struct http_client_peer_shared *pshared)
{
	struct http_client_peer *peer;
	unsigned int max_conns = 0;

	peer = pshared->peers_list;
	while (peer != NULL) {
		max_conns += peer->client->set.max_parallel_connections;
		peer = peer->shared_next;
	}

	return max_conns;
}

/*
 * Peer
 */

static void
http_client_peer_drop(struct http_client_peer **_peer);

static struct http_client_peer *
http_client_peer_create(struct http_client *client,
			      struct http_client_peer_shared *pshared)
{
	struct http_client_peer *peer;

	peer = i_new(struct http_client_peer, 1);
	peer->refcount = 1;
	peer->client = client;
	peer->shared = pshared;

	peer->event = event_create(client->event);
	event_set_append_log_prefix(peer->event, t_strdup_printf(
		"peer %s: ", http_client_peer_shared_label(pshared)));

	i_array_init(&peer->queues, 16);
	i_array_init(&peer->conns, 16);
	i_array_init(&peer->pending_conns, 16);

	DLLIST_PREPEND_FULL
		(&client->peers_list, peer, client_prev, client_next);
	DLLIST_PREPEND_FULL
		(&pshared->peers_list, peer, shared_prev, shared_next);
	pshared->peers_count++;

	http_client_peer_shared_ref(pshared);
	peer->ppool = http_client_peer_pool_get(pshared, client);

	/* choose backoff times */
	if (pshared->peers_list == NULL ||
		client->set.connect_backoff_time_msecs <
			pshared->backoff_initial_time_msecs) {
		pshared->backoff_initial_time_msecs =
			client->set.connect_backoff_time_msecs;
	}
	if (pshared->peers_list == NULL ||
		client->set.connect_backoff_max_time_msecs >
			pshared->backoff_max_time_msecs) {
		pshared->backoff_max_time_msecs =
			client->set.connect_backoff_max_time_msecs;
	}

	e_debug(peer->event, "Peer created");
	return peer;
}

void http_client_peer_ref(struct http_client_peer *peer)
{
	peer->refcount++;
}

static void
http_client_peer_disconnect(struct http_client_peer *peer)
{
	struct http_client_queue *const *queue;
	struct http_client *client = peer->client;
	struct http_client_peer_shared *pshared = peer->shared;
	struct http_client_connection **conn;
	ARRAY_TYPE(http_client_connection) conns;

	if (peer->disconnected)
		return;
	peer->disconnected = TRUE;

	e_debug(peer->event, "Peer disconnect");

	/* make a copy of the connection array; freed connections modify it */
	t_array_init(&conns, array_count(&peer->conns));
	array_copy(&conns.arr, 0, &peer->conns.arr,
		0, array_count(&peer->conns));
	array_foreach_modifiable(&conns, conn)
		http_client_connection_lost_peer(*conn);
	i_assert(array_count(&peer->conns) == 0);
	array_clear(&peer->pending_conns);

	timeout_remove(&peer->to_req_handling);

	/* unlist in client */
	DLLIST_REMOVE_FULL
		(&client->peers_list, peer, client_prev, client_next);
	/* unlist in peer */
	DLLIST_REMOVE_FULL
		(&pshared->peers_list, peer, shared_prev, shared_next);
	pshared->peers_count--;

	/* unlink all queues */
	array_foreach(&peer->queues, queue)
		http_client_queue_peer_disconnected(*queue, peer);
	array_clear(&peer->queues);
}

bool http_client_peer_unref(struct http_client_peer **_peer)
{
	struct http_client_peer *peer = *_peer;
	struct http_client_peer_pool *ppool = peer->ppool;
	struct http_client_peer_shared *pshared = peer->shared;

	*_peer = NULL;

	i_assert(peer->refcount > 0);
	if (--peer->refcount > 0)
		return TRUE;

	e_debug(peer->event, "Peer destroy");

	http_client_peer_disconnect(peer);

	i_assert(array_count(&peer->queues) == 0);

	event_unref(&peer->event);
	array_free(&peer->conns);
	array_free(&peer->pending_conns);
	array_free(&peer->queues);
	i_free(peer);

	/* choose new backoff times */
	peer = pshared->peers_list;
	while (peer != NULL) {
		struct http_client *client = peer->client;

		if (client->set.connect_backoff_time_msecs <
				pshared->backoff_initial_time_msecs) {
			pshared->backoff_initial_time_msecs =
				client->set.connect_backoff_time_msecs;
		}
		if (client->set.connect_backoff_max_time_msecs >
				pshared->backoff_max_time_msecs) {
			pshared->backoff_max_time_msecs =
				client->set.connect_backoff_max_time_msecs;
		}
		peer = peer->shared_next;
	}

	http_client_peer_pool_unref(&ppool);
	http_client_peer_shared_unref(&pshared);
	return FALSE;
}

void http_client_peer_close(struct http_client_peer **_peer)
{
	struct http_client_peer *peer = *_peer;

	e_debug(peer->event, "Peer close");

	http_client_peer_disconnect(peer);

	(void)http_client_peer_unref(_peer);
}

static void
http_client_peer_drop(struct http_client_peer **_peer)
{
	struct http_client_peer *peer = *_peer;
	struct http_client_peer_shared *pshared = peer->shared;
	unsigned int conns_active =
		http_client_peer_active_connections(peer);

	if (conns_active > 0) {
		e_debug(peer->event,
			"Not dropping peer (%d connections active)",
			conns_active);
		return;
	}

	if (pshared->to_backoff != NULL)
		return;

	if (http_client_peer_shared_start_backoff_timer(pshared)) {
		e_debug(peer->event,
			"Dropping peer (waiting for backof timeout)");

		/* will disconnect any pending connections */
		http_client_peer_trigger_request_handler(peer);
	} else {
		e_debug(peer->event, "Dropping peer now");
		/* drop peer immediately */
		http_client_peer_close(_peer);
	}
}

struct http_client_peer *
http_client_peer_get(struct http_client *client,
			   const struct http_client_peer_addr *addr)
{
	struct http_client_peer *peer;
	struct http_client_peer_shared *pshared;

	pshared = http_client_peer_shared_get(client->cctx, addr);

	peer = pshared->peers_list;
	while (peer != NULL) {
		if (peer->client == client)
			break;
		peer = peer->shared_next;
	}

	if (peer == NULL)
		peer = http_client_peer_create(client, pshared);

	http_client_peer_shared_unref(&pshared);
	return peer;
}

static void
http_client_peer_do_connect(struct http_client_peer *peer,
	unsigned int count)
{
	struct http_client_peer_pool *ppool = peer->ppool;
	struct http_client_connection *const *idle_conns;
	unsigned int i, idle_count;
	bool claimed_existing = FALSE;

	if (count == 0)
		return;

	idle_conns = array_get(&ppool->idle_conns, &idle_count);
	for (i = 0; i < count && i < idle_count; i++) {
		http_client_connection_claim_idle(idle_conns[i], peer);
		claimed_existing = TRUE;

		e_debug(peer->event,
			"Claimed idle connection "
			"(%u connections exist, %u pending)",
			array_count(&peer->conns),
			array_count(&peer->pending_conns));
	}

	for (; i < count; i++) {
		e_debug(peer->event,
			"Making new connection %u of %u "
			"(%u connections exist, %u pending)",
			i+1, count, array_count(&peer->conns),
			array_count(&peer->pending_conns));

		(void)http_client_connection_create(peer);
	}

	if (claimed_existing)
		http_client_peer_connection_success(peer);
}

static void
http_client_peer_connect_backoff(struct http_client_peer *peer)
{
	if (peer->connect_backoff &&
		array_count(&peer->queues) == 0) {
		http_client_peer_close(&peer);
		return;
	}

	http_client_peer_do_connect(peer, 1);
	peer->connect_backoff = FALSE;
}

static void
http_client_peer_connect(struct http_client_peer *peer, unsigned int count)
{
	if (http_client_peer_shared_start_backoff_timer(peer->shared)) {
		peer->connect_backoff = TRUE;
		return;
	}

	http_client_peer_do_connect(peer, count);
}

bool http_client_peer_is_connected(struct http_client_peer *peer)
{
	struct http_client_connection *const *conn_idx;

	if (array_count(&peer->ppool->idle_conns) > 0)
		return TRUE;

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

	e_debug(peer->event, "Peer cancel");

	/* make a copy of the connection array; freed connections modify it */
	t_array_init(&conns, array_count(&peer->conns));
	array_copy(&conns.arr, 0, &peer->conns.arr, 0, array_count(&peer->conns));
	array_foreach_modifiable(&conns, conn) {
		if (!http_client_connection_is_active(*conn))
			http_client_connection_close(conn);
	}
	i_assert(array_count(&peer->pending_conns) == 0);
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
		/* no connections or pending requests; disconnect immediately */
		http_client_peer_drop(&peer);
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
	struct http_client_peer_shared *pshared = peer->shared;
	unsigned int connecting, closing, idle;
	unsigned int num_pending, num_urgent, new_connections, 	working_conn_count;
	struct http_client_peer *tmp_peer;
	bool statistics_dirty = TRUE;

	/* FIXME: limit the number of requests handled in one run to prevent
	   I/O starvation. */

	/* disconnect pending connections if we're not linked to any queue
	   anymore */
	if (array_count(&peer->queues) == 0) {
		if (array_count(&peer->conns) == 0 && pshared->to_backoff == NULL) {
			/* peer is completely unused and inactive; drop it immediately */
			http_client_peer_drop(&peer);
			return;
		}
		e_debug(peer->event,
			"Peer no longer used; will now cancel pending connections "
			"(%u connections exist, %u pending)",
			array_count(&peer->conns),
			array_count(&peer->pending_conns));

		http_client_peer_cancel(peer);
		return;
	}

	/* don't do anything unless we have pending requests */
	num_pending = http_client_peer_requests_pending(peer, &num_urgent);
	if (num_pending == 0) {
		e_debug(peer->event,
			"No requests to service for this peer "
			"(%u connections exist, %u pending)",
			array_count(&peer->conns),
			array_count(&peer->pending_conns));
		http_client_peer_check_idle(peer);
		return;
	}

	http_client_peer_ref(peer);
	peer->handling_requests = TRUE;
	t_array_init(&conns_avail, array_count(&peer->conns));
	do {
		bool conn_lost = FALSE;

		array_clear(&conns_avail);
		closing = idle = 0;

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
		}

		if (conn_lost) {
			/* connection array changed while iterating; retry */
			continue;
		}

		working_conn_count = array_count(&peer->conns) - closing;
		statistics_dirty = FALSE;

		/* use idle connections right away */
		if (idle > 0) {
			e_debug(peer->event,
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
			e_debug(peer->event,
				"No more requests to service for this peer "
				"(%u connections exist, %u pending)",
				array_count(&peer->conns),
				array_count(&peer->pending_conns));
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
	connecting = array_count(&peer->pending_conns);

	/* determine how many new connections we can set up */
	if (pshared->last_failure.tv_sec > 0 && working_conn_count > 0 &&
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
		e_debug(peer->event,
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

		if (!pshared->allows_pipelining) {
			e_debug(peer->event,
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

		e_debug(peer->event,
			"Pipelined %u requests (filled pipelines up to %u requests)",
			total_handled, pipeline_level);
		return;
	}

	/* still waiting for connections to finish */
	e_debug(peer->event, "No request handled; "
		"waiting for pending connections "
		"(%u connections exist, %u pending)",
		array_count(&peer->conns), connecting);
	return;
}

static void http_client_peer_handle_requests(struct http_client_peer *peer)
{
	timeout_remove(&peer->to_req_handling);
	
	T_BEGIN {
		http_client_peer_handle_requests_real(peer);
	} T_END;
}

void http_client_peer_trigger_request_handler(struct http_client_peer *peer)
{
	/* trigger request handling through timeout */
	if (peer->to_req_handling == NULL) {
		peer->to_req_handling =	timeout_add_short_to(
			peer->client->ioloop, 0,
			http_client_peer_handle_requests, peer);
	}
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

		e_debug(peer->event, "Linked queue %s (%d queues linked)",
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

			e_debug(peer->event,
				"Unlinked queue %s (%d queues linked)",
				queue->name, array_count(&peer->queues));

			if (array_count(&peer->queues) == 0)
				http_client_peer_check_idle(peer);
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
			(*queue_idx, &peer->shared->addr, no_urgent)) != NULL) {
			req->peer = peer;
			return req;
		}
	}

	return NULL;
}

void http_client_peer_connection_success(struct http_client_peer *peer)
{
	struct http_client_peer_pool *ppool = peer->ppool;
	struct http_client_queue *const *queue;

	e_debug(peer->event, "Successfully connected "
		"(%u connections exist, %u pending)",
		array_count(&peer->conns), array_count(&peer->pending_conns));

	http_client_peer_pool_connection_success(ppool);

	array_foreach(&peer->queues, queue)
		http_client_queue_connection_success(*queue, peer);

	http_client_peer_trigger_request_handler(peer);
}

void http_client_peer_connection_failure(struct http_client_peer *peer,
					 const char *reason)
{
	struct http_client_peer_pool *ppool = peer->ppool;

	e_debug(peer->event, "Connection failed "
		"(%u connections exist, %u pending)",
		array_count(&peer->conns), array_count(&peer->pending_conns));

	http_client_peer_pool_connection_failure(ppool, reason);

	peer->connect_failed = TRUE;
}

static void
http_client_peer_connection_succeeded_pool(struct http_client_peer *peer)
{
	if (!peer->connect_failed)
		return;
	peer->connect_failed = FALSE;

	e_debug(peer->event,
		"A connection succeeded within our peer pool, "
		"so this peer can retry connecting as well if needed "
		"(%u connections exist, %u pending)",
		array_count(&peer->conns), array_count(&peer->pending_conns));

	/* if there are pending requests for this peer, try creating a new
	   connection for them. if not, this peer will wind itself down. */
	http_client_peer_trigger_request_handler(peer);
}

static void
http_client_peer_connection_failed_pool(struct http_client_peer *peer,
					const char *reason)
{
	struct http_client_queue *const *queue;

	e_debug(peer->event,
		"Failed to establish any connection within our peer pool: %s "
		"(%u connections exist, %u pending)", reason,
		array_count(&peer->conns), array_count(&peer->pending_conns));

	peer->connect_failed = TRUE;

	/* failed to make any connection. a second connect will probably also
	   fail, so just try another IP for the hosts(s) or abort all requests
	   if this was the only/last option. */
	array_foreach(&peer->queues, queue)
		http_client_queue_connection_failure(*queue, peer, reason);
}

void http_client_peer_connection_lost(struct http_client_peer *peer,
	bool premature)
{
	unsigned int num_pending, num_urgent;

	/* we get here when an already connected connection fails. if the
	   connect itself fails, http_client_peer_shared_connection_failure() is
	   called instead. */

	if (peer->disconnected)
		return;

	http_client_peer_shared_connection_lost(peer->shared, premature);

	num_pending = http_client_peer_requests_pending(peer, &num_urgent);

	e_debug(peer->event,
		"Lost a connection%s "
		"(%u queues linked, %u connections left, "
		 "%u connections pending, %u requests pending, "
		 "%u requests urgent)",
		(premature ? " prematurely" : ""),
		array_count(&peer->queues), array_count(&peer->conns),
		array_count(&peer->pending_conns), num_pending, num_urgent);

	if (peer->handling_requests) {
		/* we got here from the request handler loop */
		e_debug(peer->event,
			"Lost a connection while handling requests");
		return;
	}

	/* if there are pending requests for this peer, create a new connection
	   for them. if not, this peer will wind itself down. */
	http_client_peer_trigger_request_handler(peer);
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
	return array_count(&peer->pending_conns);
}

void http_client_peer_switch_ioloop(struct http_client_peer *peer)
{
	if (peer->to_req_handling != NULL) {
		peer->to_req_handling =
			io_loop_move_timeout(&peer->to_req_handling);
	}
}
