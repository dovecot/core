/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "net.h"
#include "str.h"
#include "hash.h"
#include "array.h"
#include "bsearch-insert-pos.h"
#include "llist.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "time-util.h"
#include "dns-lookup.h"
#include "http-response-parser.h"

#include "http-client-private.h"

/*
 * Logging
 */

static inline void
http_client_queue_debug(struct http_client_queue *queue,
	const char *format, ...) ATTR_FORMAT(2, 3);

static inline void
http_client_queue_debug(struct http_client_queue *queue,
	const char *format, ...)
{
	va_list args;

	if (queue->client->set.debug) {

		va_start(args, format);	
		i_debug("http-client: queue %s: %s", 
			queue->name, t_strdup_vprintf(format, args));
		va_end(args);
	}
}

/*
 * Queue
 */

static void
http_client_queue_set_delay_timer(struct http_client_queue *queue,
	struct timeval time);

static struct http_client_queue *
http_client_queue_find(struct http_client_host *host,
	const struct http_client_peer_addr *addr)
{
	struct http_client_queue *const *queue_idx;

	array_foreach_modifiable(&host->queues, queue_idx) {
		struct http_client_queue *queue = *queue_idx;

		if (queue->addr.type == addr->type && queue->addr.port == addr->port &&
		    null_strcmp(queue->addr.https_name, addr->https_name) == 0)
			return queue;
	}

	return NULL;
}

struct http_client_queue *
http_client_queue_create(struct http_client_host *host,
	const struct http_client_peer_addr *addr)
{
	struct http_client_queue *queue;

	queue = http_client_queue_find(host, addr);
	if (queue == NULL) {
		char *name;

		switch (addr->type) {
		case HTTP_CLIENT_PEER_ADDR_RAW:
			name = i_strdup_printf("raw://%s:%u", host->name, addr->port);
			break;
		case HTTP_CLIENT_PEER_ADDR_HTTPS_TUNNEL:
		case HTTP_CLIENT_PEER_ADDR_HTTPS:
			name = i_strdup_printf("https://%s:%u", host->name, addr->port);
			break;
		case HTTP_CLIENT_PEER_ADDR_HTTP:
			name = i_strdup_printf("http://%s:%u", host->name, addr->port);
			break;
		default:
			i_unreached();
		}

		queue = i_new(struct http_client_queue, 1);
		queue->client = host->client;
		queue->host = host;
		queue->addr = *addr;
		queue->https_name = i_strdup(addr->https_name);
		queue->addr.https_name = queue->https_name;
		queue->name = name;
		queue->ips_connect_idx = 0;
		i_array_init(&queue->request_queue, 16);
		i_array_init(&queue->delayed_request_queue, 4);
		array_append(&host->queues, &queue, 1);
	}

	return queue;
}

void http_client_queue_free(struct http_client_queue *queue)
{
	http_client_queue_fail
		(queue, HTTP_CLIENT_REQUEST_ERROR_ABORTED, "Aborted");
	i_free(queue->https_name);
	if (array_is_created(&queue->pending_peers))
		array_free(&queue->pending_peers);
	array_free(&queue->request_queue);
	array_free(&queue->delayed_request_queue);
	if (queue->to_connect != NULL)
		timeout_remove(&queue->to_connect);
	if (queue->to_delayed != NULL)
		timeout_remove(&queue->to_delayed);
	i_free(queue->name);
	i_free(queue);
}

void http_client_queue_fail(struct http_client_queue *queue,
	unsigned int status, const char *error)
{
	struct http_client_request **req;

	/* abort all pending requests */
	array_foreach_modifiable(&queue->request_queue, req) {
		http_client_request_error(*req, status, error);
	}
	array_clear(&queue->request_queue);

	/* abort all delayed requests */
	array_foreach_modifiable(&queue->delayed_request_queue, req) {
		http_client_request_error(*req, status, error);
	}
	array_clear(&queue->delayed_request_queue);
}

void
http_client_queue_drop_request(struct http_client_queue *queue,
	struct http_client_request *req)
{
	ARRAY_TYPE(http_client_request) *req_arr = &queue->request_queue;
	struct http_client_request **req_idx;

	array_foreach_modifiable(req_arr, req_idx) {
		if (*req_idx == req) {
			array_delete(req_arr, array_foreach_idx(req_arr, req_idx), 1);
			break;
		}
	}
}

static bool
http_client_queue_is_last_connect_ip(struct http_client_queue *queue)
{
	struct http_client_host *host = queue->host;

	i_assert(queue->ips_connect_idx < host->ips_count);
	i_assert(queue->ips_connect_start_idx < host->ips_count);

	/* we'll always go through all the IPs. we don't necessarily start
	   connecting from the first IP, so we'll need to treat the IPs as
	   a ring buffer where we automatically wrap back to the first IP
	   when necessary. */
	return (queue->ips_connect_idx + 1) % host->ips_count ==
		queue->ips_connect_start_idx;
}

static void
http_client_queue_soft_connect_timeout(struct http_client_queue *queue)
{
	struct http_client_host *host = queue->host;
	const struct http_client_peer_addr *addr = &queue->addr;

	if (queue->to_connect != NULL)
		timeout_remove(&queue->to_connect);

	if (http_client_queue_is_last_connect_ip(queue)) {
		/* no more IPs to try */
		return;
	}

	/* if our our previous connection attempt takes longer than the
	   soft_connect_timeout, we start a connection attempt to the next IP in
	   parallel */
	http_client_queue_debug(queue, "Connection to %s%s is taking a long time; "
		"starting parallel connection attempt to next IP",
		http_client_peer_addr2str(addr), addr->https_name == NULL ? "" :
			t_strdup_printf(" (SSL=%s)", addr->https_name)); 

	/* next IP */
	queue->ips_connect_idx = (queue->ips_connect_idx + 1) % host->ips_count;

	/* setup connection to new peer (can start new soft timeout) */
	http_client_queue_connection_setup(queue);
}

void http_client_queue_connection_setup(struct http_client_queue *queue)
{
	struct http_client_host *host = queue->host;
	struct http_client_peer *peer = NULL;
	const struct http_client_peer_addr *addr = &queue->addr;
	unsigned int num_requests = array_count(&queue->request_queue);

	if (num_requests == 0)
		return;

	/* update our peer address */
	i_assert(queue->ips_connect_idx < host->ips_count);
	queue->addr.ip = host->ips[queue->ips_connect_idx];

	http_client_queue_debug(queue, "Setting up connection to %s%s "
		"(%u requests pending)", http_client_peer_addr2str(addr),
		(addr->https_name == NULL ? "" :
			t_strdup_printf(" (SSL=%s)", addr->https_name)), num_requests);

	/* create/get peer */
	peer = http_client_peer_get(queue->client, addr);
	http_client_peer_link_queue(peer, queue);

	/* handle requests; creates new connections when needed/possible */
	http_client_peer_trigger_request_handler(peer);

	if (!http_client_peer_is_connected(peer)) {
		unsigned int msecs;

		/* not already connected, wait for connections */
		if (!array_is_created(&queue->pending_peers))
			i_array_init(&queue->pending_peers, 8);
		array_append(&queue->pending_peers, &peer, 1);			

		/* start soft connect time-out (but only if we have another IP left) */
		msecs = host->client->set.soft_connect_timeout_msecs;
		if (!http_client_queue_is_last_connect_ip(queue) && msecs > 0 &&
		   	queue->to_connect == NULL) {
			queue->to_connect =
				timeout_add(msecs, http_client_queue_soft_connect_timeout, queue);
		}
	}
}

void
http_client_queue_connection_success(struct http_client_queue *queue,
					 const struct http_client_peer_addr *addr)
{
	/* we achieved at least one connection the the addr->ip */
	queue->ips_connect_start_idx =
		http_client_host_get_ip_idx(queue->host, &addr->ip);

	/* stop soft connect time-out */
	if (queue->to_connect != NULL)
		timeout_remove(&queue->to_connect);

	/* drop all other attempts to the hport. note that we get here whenever
	   a connection is successfully created, so pending_peers array
	   may be empty. */
	if (array_is_created(&queue->pending_peers) &&
		array_count(&queue->pending_peers) > 0) {
		struct http_client_peer *const *peer_idx;

		array_foreach(&queue->pending_peers, peer_idx) {
			if (http_client_peer_addr_cmp(&(*peer_idx)->addr, addr) == 0) {
				/* don't drop any connections to the successfully
				   connected peer, even if some of the connections
				   are pending. they may be intended for urgent
				   requests. */
				continue;
			}
			/* unlink this queue from the peer; if this was the last/only queue, the
			   peer will be freed, closing all connections.
			 */
			http_client_peer_unlink_queue(*peer_idx, queue);
		}
		array_clear(&queue->pending_peers);
	}
}

bool
http_client_queue_connection_failure(struct http_client_queue *queue,
	const struct http_client_peer_addr *addr, const char *reason)
{
	struct http_client_host *host = queue->host;

	if (array_is_created(&queue->pending_peers) &&
		array_count(&queue->pending_peers) > 0) {
		struct http_client_peer *const *peer_idx;

		/* we're still doing the initial connections to this hport. if
		   we're also doing parallel connections with soft timeouts
		   (pending_peer_count>1), wait for them to finish
		   first. */
		array_foreach(&queue->pending_peers, peer_idx) {
			if (http_client_peer_addr_cmp(&(*peer_idx)->addr, addr) == 0) {
				array_delete(&queue->pending_peers,
					array_foreach_idx(&queue->pending_peers, peer_idx), 1);
				break;
			}
		}
		if (array_count(&queue->pending_peers) > 0)
			return TRUE;
	}

	/* one of the connections failed. if we're not using soft timeouts,
	   we need to try to connect to the next IP. if we are using soft
	   timeouts, we've already tried all of the IPs by now. */
	if (queue->to_connect != NULL)
		timeout_remove(&queue->to_connect);

	if (http_client_queue_is_last_connect_ip(queue)) {
		/* all IPs failed, but retry all of them again on the
		   next request. */
		queue->ips_connect_idx = queue->ips_connect_start_idx =
			(queue->ips_connect_idx + 1) % host->ips_count;
		http_client_queue_fail(queue,
			HTTP_CLIENT_REQUEST_ERROR_CONNECT_FAILED, reason);
		return FALSE;
	}
	queue->ips_connect_idx = (queue->ips_connect_idx + 1) % host->ips_count;
	http_client_queue_connection_setup(queue);
	return TRUE;
}

static void http_client_queue_submit_now(struct http_client_queue *queue,
	struct http_client_request *req)
{
	req->release_time.tv_sec = 0;
	req->release_time.tv_usec = 0;

	if (req->urgent)
		array_insert(&queue->request_queue, 0, &req, 1);
	else
		array_append(&queue->request_queue, &req, 1);
}

static void
http_client_queue_delay_timeout(struct http_client_queue *queue)
{
	struct http_client_request *const *reqs;
	unsigned int count, i, finished;

	io_loop_time_refresh();

	finished = 0;
	reqs = array_get(&queue->delayed_request_queue, &count);
	for (i = 0; i < count; i++) {
		if (timeval_cmp(&reqs[i]->release_time, &ioloop_timeval) > 0) {
			break;
		}

		http_client_queue_debug(queue,
			"Activated delayed request %s%s",
			http_client_request_label(reqs[i]),
			(reqs[i]->urgent ? " (urgent)" : ""));
		http_client_queue_submit_now(queue, reqs[i]);
		finished++;
	}
	if (i < count) {
		http_client_queue_set_delay_timer(queue, reqs[i]->release_time);
	}
	array_delete(&queue->delayed_request_queue, 0, finished);

	http_client_queue_connection_setup(queue);
}

static void
http_client_queue_set_delay_timer(struct http_client_queue *queue,
	struct timeval time)
{
	int usecs = timeval_diff_usecs(&time, &ioloop_timeval);
	int msecs;

	/* round up to nearest microsecond */
	msecs = (usecs + 999) / 1000;

	/* set timer */
	if (queue->to_delayed != NULL)
		timeout_remove(&queue->to_delayed);	
	queue->to_delayed = timeout_add
		(msecs, http_client_queue_delay_timeout, queue);
}

static int
http_client_queue_delayed_cmp(struct http_client_request *const *req1,
	struct http_client_request *const *req2)
{
	return timeval_cmp(&(*req1)->release_time, &(*req2)->release_time);
}

void http_client_queue_submit_request(struct http_client_queue *queue,
	struct http_client_request *req)
{
	unsigned int insert_idx;

	req->queue = queue;

	if (req->release_time.tv_sec > 0) {
		io_loop_time_refresh();

		if (timeval_cmp(&req->release_time, &ioloop_timeval) > 0) {
			(void)array_bsearch_insert_pos(&queue->delayed_request_queue,
					&req, http_client_queue_delayed_cmp, &insert_idx);
			array_insert(&queue->delayed_request_queue, insert_idx, &req, 1);
			if (insert_idx == 0)
				http_client_queue_set_delay_timer(queue, req->release_time);
			return;
		}
	}

	http_client_queue_submit_now(queue, req);
}

struct http_client_request *
http_client_queue_claim_request(struct http_client_queue *queue,
	const struct http_client_peer_addr *addr, bool no_urgent)
{
	struct http_client_request *const *requests;
	struct http_client_request *req;
	unsigned int i, count;

 	requests = array_get(&queue->request_queue, &count);
	if (count == 0)
		return NULL;
	i = 0;
	if (requests[0]->urgent && no_urgent) {
		for (; requests[i]->urgent; i++) {
			if (i == count)
				return NULL;
		}
	}
	req = requests[i];
	array_delete(&queue->request_queue, i, 1);

	http_client_queue_debug(queue,
		"Connection to peer %s claimed request %s %s",
		http_client_peer_addr2str(addr), http_client_request_label(req),
		(req->urgent ? "(urgent)" : ""));

	return req;
}

unsigned int
http_client_queue_requests_pending(struct http_client_queue *queue,
	unsigned int *num_urgent_r)
{
	struct http_client_request *const *requests;
	unsigned int count, i;

	*num_urgent_r = 0;

	requests = array_get(&queue->request_queue, &count);
	for (i = 0; i < count; i++) {
		if (requests[i]->urgent)
			(*num_urgent_r)++;
		else
			break;
	}
	return count;
}

void http_client_queue_switch_ioloop(struct http_client_queue *queue)
{
	if (queue->to_connect != NULL)
		queue->to_connect = io_loop_move_timeout(&queue->to_connect);
	if (queue->to_delayed != NULL)
		queue->to_delayed = io_loop_move_timeout(&queue->to_delayed);
}
