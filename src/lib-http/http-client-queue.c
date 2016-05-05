/* Copyright (c) 2013-2016 Dovecot authors, see the included COPYING file */

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

#define TIMEOUT_CMP_MARGIN_USECS 2000

static void
http_client_queue_set_delay_timer(struct http_client_queue *queue,
	struct timeval time);
static void
http_client_queue_set_request_timer(struct http_client_queue *queue,
	const struct timeval *time);


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
 * Queue object
 */

static struct http_client_queue *
http_client_queue_find(struct http_client_host *host,
	const struct http_client_peer_addr *addr)
{
	struct http_client_queue *const *queue_idx;

	array_foreach_modifiable(&host->queues, queue_idx) {
		struct http_client_queue *queue = *queue_idx;

		if (http_client_peer_addr_cmp(&queue->addr, addr) == 0)
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
		queue = i_new(struct http_client_queue, 1);
		queue->client = host->client;
		queue->host = host;
		queue->addr = *addr;

		switch (addr->type) {
		case HTTP_CLIENT_PEER_ADDR_RAW:
			queue->name =
				i_strdup_printf("raw://%s:%u", host->name, addr->a.tcp.port);
			queue->addr.a.tcp.https_name = NULL;
			break;
		case HTTP_CLIENT_PEER_ADDR_HTTPS_TUNNEL:
		case HTTP_CLIENT_PEER_ADDR_HTTPS:
			queue->name =
				i_strdup_printf("https://%s:%u", host->name, addr->a.tcp.port);
			queue->addr_name = i_strdup(addr->a.tcp.https_name);
			queue->addr.a.tcp.https_name = queue->addr_name;
			break;
		case HTTP_CLIENT_PEER_ADDR_HTTP:
			queue->name =
				i_strdup_printf("http://%s:%u", host->name, addr->a.tcp.port);
			queue->addr.a.tcp.https_name = NULL;
			break;
		case HTTP_CLIENT_PEER_ADDR_UNIX:
			queue->name = i_strdup_printf("unix:%s", addr->a.un.path);
			queue->addr_name = i_strdup(addr->a.un.path);
			queue->addr.a.un.path = queue->addr_name;
			break;
		default:
			i_unreached();
		}

		queue->ips_connect_idx = 0;
		i_array_init(&queue->requests, 16);
		i_array_init(&queue->queued_requests, 16);
		i_array_init(&queue->queued_urgent_requests, 16);
		i_array_init(&queue->delayed_requests, 4);
		array_append(&host->queues, &queue, 1);
	}

	return queue;
}

void http_client_queue_free(struct http_client_queue *queue)
{
	http_client_queue_fail
		(queue, HTTP_CLIENT_REQUEST_ERROR_ABORTED, "Aborted");
	if (array_is_created(&queue->pending_peers))
		array_free(&queue->pending_peers);
	array_free(&queue->requests);
	array_free(&queue->queued_requests);
	array_free(&queue->queued_urgent_requests);
	array_free(&queue->delayed_requests);
	if (queue->to_connect != NULL)
		timeout_remove(&queue->to_connect);
	if (queue->to_delayed != NULL)
		timeout_remove(&queue->to_delayed);
	i_free(queue->addr_name);
	i_free(queue->name);
	i_free(queue);
}

/*
 * Error handling
 */

void http_client_queue_fail(struct http_client_queue *queue,
	unsigned int status, const char *error)
{
	ARRAY_TYPE(http_client_request) *req_arr, treqs;
	struct http_client_request **req_idx;

	/* abort all pending requests */
	req_arr = &queue->requests;
	t_array_init(&treqs, array_count(req_arr));
	array_copy(&treqs.arr, 0, &req_arr->arr, 0, array_count(req_arr));
	array_foreach_modifiable(&treqs, req_idx) {
		http_client_request_error(*req_idx, status, error);
	}

	/* all queues should be empty now... unless new requests were submitted
	   from the callback. this invariant captures it all: */
	i_assert((array_count(&queue->delayed_requests) +
		array_count(&queue->queued_requests) +
		array_count(&queue->queued_urgent_requests)) ==
		array_count(&queue->requests));
}

/*
 * Connection management
 */

static bool
http_client_queue_is_last_connect_ip(struct http_client_queue *queue)
{
	const struct http_client_settings *set =
		&queue->client->set;
	struct http_client_host *host = queue->host;

	i_assert(queue->addr.type != HTTP_CLIENT_PEER_ADDR_UNIX);
	i_assert(queue->ips_connect_idx < host->ips_count);
	i_assert(queue->ips_connect_start_idx < host->ips_count);

	/* if a maximum connect attempts > 1 is set, enforce it directly */
	if (set->max_connect_attempts > 1 &&
		queue->connect_attempts >= set->max_connect_attempts)
		return TRUE;
		
	/* otherwise, we'll always go through all the IPs. we don't necessarily
	   start connecting from the first IP, so we'll need to treat the IPs as
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
	const char *https_name;

	i_assert(queue->addr.type != HTTP_CLIENT_PEER_ADDR_UNIX);

	if (queue->to_connect != NULL)
		timeout_remove(&queue->to_connect);

	if (http_client_queue_is_last_connect_ip(queue)) {
		/* no more IPs to try */
		return;
	}

	/* if our our previous connection attempt takes longer than the
	   soft_connect_timeout, we start a connection attempt to the next IP in
	   parallel */
	https_name = http_client_peer_addr_get_https_name(addr);
	http_client_queue_debug(queue, "Connection to %s%s is taking a long time; "
		"starting parallel connection attempt to next IP",
		http_client_peer_addr2str(addr), (https_name == NULL ? "" :
			t_strdup_printf(" (SSL=%s)", https_name)));

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
	unsigned int num_requests =
		array_count(&queue->queued_requests) +
		array_count(&queue->queued_urgent_requests);
	const char *ssl = "";

	if (num_requests == 0)
		return;

	/* update our peer address */
	if (queue->addr.type != HTTP_CLIENT_PEER_ADDR_UNIX) {
		i_assert(queue->ips_connect_idx < host->ips_count);
		queue->addr.a.tcp.ip = host->ips[queue->ips_connect_idx];
		ssl = http_client_peer_addr_get_https_name(addr);
		ssl = (ssl == NULL ? "" : t_strdup_printf(" (SSL=%s)", ssl));
	}

	http_client_queue_debug(queue, "Setting up connection to %s%s "
		"(%u requests pending)", http_client_peer_addr2str(addr), ssl,
		num_requests);


	/* create/get peer */
	peer = http_client_peer_get(queue->client, addr);
	http_client_peer_link_queue(peer, queue);

	/* handle requests; creates new connections when needed/possible */
	http_client_peer_trigger_request_handler(peer);

	if (!http_client_peer_is_connected(peer)) {
		unsigned int msecs;
		bool new_peer = TRUE;

		/* not already connected, wait for connections */
		if (!array_is_created(&queue->pending_peers))
			i_array_init(&queue->pending_peers, 8);
		else {
			struct http_client_peer *const *peer_idx;

			/* we may be waiting for this peer already */
			array_foreach(&queue->pending_peers, peer_idx) {
				if (http_client_peer_addr_cmp(&(*peer_idx)->addr, addr) == 0) {
					new_peer = FALSE;
					break;
				}
			}
		}
		if (new_peer) {
			http_client_queue_debug(queue, "Started new connection to %s%s",
				http_client_peer_addr2str(addr), ssl);

			array_append(&queue->pending_peers, &peer, 1);
			if (queue->connect_attempts++ == 0)
				queue->first_connect_time = ioloop_timeval;
		}

		/* start soft connect time-out (but only if we have another IP left) */
		if (queue->addr.type != HTTP_CLIENT_PEER_ADDR_UNIX) {
			msecs = host->client->set.soft_connect_timeout_msecs;
			if (!http_client_queue_is_last_connect_ip(queue) && msecs > 0 &&
			   	queue->to_connect == NULL) {
				queue->to_connect =
					timeout_add(msecs, http_client_queue_soft_connect_timeout, queue);
			}
		}
	}
}

void
http_client_queue_connection_success(struct http_client_queue *queue,
					 const struct http_client_peer_addr *addr)
{
	if (queue->addr.type != HTTP_CLIENT_PEER_ADDR_UNIX) {
		/* we achieved at least one connection the the addr->ip */
		queue->ips_connect_start_idx =
			http_client_host_get_ip_idx(queue->host, &addr->a.tcp.ip);
	}

	/* reset attempt counter */
	queue->connect_attempts = 0;

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

void
http_client_queue_connection_failure(struct http_client_queue *queue,
	const struct http_client_peer_addr *addr, const char *reason)
{
	const struct http_client_settings *set =
		&queue->client->set;
	const char *https_name = http_client_peer_addr_get_https_name(addr);
	struct http_client_host *host = queue->host;

	http_client_queue_debug(queue,
		"Failed to set up connection to %s%s: %s "
		"(%u peers pending, %u requests pending)",
		http_client_peer_addr2str(addr),
		(https_name == NULL ? "" :
			t_strdup_printf(" (SSL=%s)", https_name)),
		reason, (array_is_created(&queue->pending_peers) ?
		 	array_count(&queue->pending_peers): 0),
		array_count(&queue->requests));

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
		if (array_count(&queue->pending_peers) > 0) {
			http_client_queue_debug(queue,
				"Waiting for remaining pending peers.");
			return;
		}
	}

	/* one of the connections failed. if we're not using soft timeouts,
	   we need to try to connect to the next IP. if we are using soft
	   timeouts, we've already tried all of the IPs by now. */
	if (queue->to_connect != NULL)
		timeout_remove(&queue->to_connect);

	if (queue->addr.type == HTTP_CLIENT_PEER_ADDR_UNIX) {
		http_client_queue_fail(queue,
			HTTP_CLIENT_REQUEST_ERROR_CONNECT_FAILED, reason);
		return;
	}

	if (http_client_queue_is_last_connect_ip(queue)) {
		/* all IPs failed, but retry all of them again if we have more
		   connect attempts left or on the next request. */
		queue->ips_connect_idx = queue->ips_connect_start_idx =
			(queue->ips_connect_idx + 1) % host->ips_count;

		if (set->max_connect_attempts == 0 ||
			queue->connect_attempts >= set->max_connect_attempts) {
			http_client_queue_debug(queue,
				"Failed to set up any connection; failing all queued requests");
			if (queue->connect_attempts > 1) {
				unsigned int total_msecs =
					timeval_diff_msecs(&ioloop_timeval, &queue->first_connect_time);
				reason = t_strdup_printf("%s (%u attempts in %u.%03u secs)",
					reason, queue->connect_attempts,
					total_msecs/1000, total_msecs%1000);
			}
			queue->connect_attempts = 0;
			http_client_queue_fail(queue,
				HTTP_CLIENT_REQUEST_ERROR_CONNECT_FAILED, reason);
			return;
		}
	} else {
		queue->ips_connect_idx = (queue->ips_connect_idx + 1) % host->ips_count;
	}
	
	http_client_queue_connection_setup(queue);
	return;
}

/*
 * Main request queue
 */

void
http_client_queue_drop_request(struct http_client_queue *queue,
	struct http_client_request *req)
{
	struct http_client_request **reqs;
	unsigned int count, i;

	http_client_queue_debug(queue,
		"Dropping request %s", http_client_request_label(req));

	/* drop from queue */
	if (req->urgent) {
		reqs = array_get_modifiable(&queue->queued_urgent_requests, &count);
		for (i = 0; i < count; i++) {
			if (reqs[i] == req) {
				array_delete(&queue->queued_urgent_requests, i, 1);
				break;
			}
		}
	} else {
		reqs = array_get_modifiable(&queue->queued_requests, &count);
		for (i = 0; i < count; i++) {
			if (reqs[i] == req) {
				array_delete(&queue->queued_requests, i, 1);
				break;
			}
		}
	}

	/* drop from delay queue */
	if (req->release_time.tv_sec > 0) {
		reqs = array_get_modifiable(&queue->delayed_requests, &count);
		for (i = 0; i < count; i++) {
			if (reqs[i] == req)
				break;
		}
		if (i < count) {
			if (i == 0) {
				if (queue->to_delayed != NULL) {
					timeout_remove(&queue->to_delayed);
					if (count > 1) {
						i_assert(reqs[1]->release_time.tv_sec > 0);
						http_client_queue_set_request_timer(queue, &reqs[1]->release_time);
					}
				}
			}
			array_delete(&queue->delayed_requests, i, 1);
		}
	}

	/* drop from main request list */
	reqs = array_get_modifiable(&queue->requests, &count);
	for (i = 0; i < count; i++) {
		if (reqs[i] == req)
			break;
	}
	i_assert(i < count);

	if (i == 0) {
		if (queue->to_request != NULL) {
			timeout_remove(&queue->to_request);
			if (count > 1 && reqs[1]->timeout_time.tv_sec > 0)
				http_client_queue_set_request_timer(queue, &reqs[1]->timeout_time);
		}
	}
	req->queue = NULL;
	array_delete(&queue->requests, i, 1);
	return;
}

static void
http_client_queue_request_timeout(struct http_client_queue *queue)
{
	struct http_client_request *const *reqs;
	ARRAY_TYPE(http_client_request) failed_requests;
	struct timeval new_to = { 0, 0 };
	unsigned int count, i;

	http_client_queue_debug(queue, "Timeout (now: %s.%03lu)",
		t_strflocaltime("%Y-%m-%d %H:%M:%S", ioloop_timeval.tv_sec),
			((unsigned long)ioloop_timeval.tv_usec)/1000);

	if (queue->to_request != NULL)
		timeout_remove(&queue->to_request);

	/* collect failed requests */
	reqs = array_get(&queue->requests, &count);
	i_assert(count > 0);
	t_array_init(&failed_requests, count);
	for (i = 0; i < count; i++) {
		if (reqs[i]->timeout_time.tv_sec > 0 &&
			timeval_cmp_margin(&reqs[i]->timeout_time,
				&ioloop_timeval, TIMEOUT_CMP_MARGIN_USECS) > 0) {
			break;
		}
		array_append(&failed_requests, &reqs[i], 1);
	}

	/* update timout */
	if (i < count)
		new_to = reqs[i]->timeout_time;

	/* abort all failed request */
	reqs = array_get(&failed_requests, &count);
	i_assert(count > 0); /* at least one request timed out */
	for (i = 0; i < count; i++) {
		struct http_client_request *req = reqs[i];

		http_client_queue_debug(queue,
			"Request %s timed out",	http_client_request_label(req));
		http_client_request_error(req,
			HTTP_CLIENT_REQUEST_ERROR_TIMED_OUT,
			"Timed out");
	}

	if (new_to.tv_sec > 0) {
		http_client_queue_debug(queue, "New timeout");
		http_client_queue_set_request_timer(queue, &new_to);
	}
}

static void
http_client_queue_set_request_timer(struct http_client_queue *queue,
	const struct timeval *time)
{
	i_assert(time->tv_sec > 0);
	if (queue->to_request != NULL)
		timeout_remove(&queue->to_request);	

	if (queue->client->set.debug) {
		http_client_queue_debug(queue,
			"Set request timeout to %s.%03lu (now: %s.%03lu)",
			t_strflocaltime("%Y-%m-%d %H:%M:%S", time->tv_sec),
			((unsigned long)time->tv_usec)/1000,
			t_strflocaltime("%Y-%m-%d %H:%M:%S", ioloop_timeval.tv_sec),
			((unsigned long)ioloop_timeval.tv_usec)/1000);
	}

	/* set timer */
	queue->to_request = timeout_add_absolute
		(time, http_client_queue_request_timeout, queue);
}

static int
http_client_queue_request_timeout_cmp(struct http_client_request *const *req1,
	struct http_client_request *const *req2)
{
	int ret;

	/* 0 means no timeout */
	if ((*req1)->timeout_time.tv_sec == 0) {
		if ((*req2)->timeout_time.tv_sec == 0) {
			/* sort by age */
			if ((ret=timeval_cmp(&(*req1)->submit_time, &(*req2)->submit_time)) != 0)
				return ret;
				
		} else {
			return 1;
		}
	} else if ((*req2)->timeout_time.tv_sec == 0) {
		return -1;

	/* sort by timeout */
	} else if 
		((ret=timeval_cmp(&(*req1)->timeout_time, &(*req2)->timeout_time)) != 0) {
		return ret;
	}

	/* sort by minumum attempts for fairness */
	return ((*req2)->attempts - (*req1)->attempts);
}

static void http_client_queue_submit_now(struct http_client_queue *queue,
	struct http_client_request *req)
{
	ARRAY_TYPE(http_client_request) *req_queue;

	req->release_time.tv_sec = 0;
	req->release_time.tv_usec = 0;

	if (req->urgent)
		req_queue = &queue->queued_urgent_requests;
	else
		req_queue = &queue->queued_requests;

	/* enqueue */
	if (req->timeout_time.tv_sec == 0) {
		/* no timeout; enqueue at end */
		array_append(req_queue, &req, 1);

	} else if (timeval_diff_msecs(&req->timeout_time, &ioloop_timeval) <= 1) {
		/* pretty much already timed out; don't bother */
		
	} else {
		unsigned int insert_idx;

		/* keep transmission queue sorted earliest timeout first */
		(void)array_bsearch_insert_pos(req_queue,
			&req, http_client_queue_request_timeout_cmp, &insert_idx);
		array_insert(req_queue, insert_idx, &req, 1);
	}
}

/*
 * Delayed request queue
 */

static void
http_client_queue_delay_timeout(struct http_client_queue *queue)
{
	struct http_client_request *const *reqs;
	unsigned int count, i, finished;

	io_loop_time_refresh();

	finished = 0;
	reqs = array_get(&queue->delayed_requests, &count);
	for (i = 0; i < count; i++) {
		if (timeval_cmp_margin(&reqs[i]->release_time,
			&ioloop_timeval, TIMEOUT_CMP_MARGIN_USECS) > 0) {
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
	array_delete(&queue->delayed_requests, 0, finished);

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

/*
 * Request submission
 */

void http_client_queue_submit_request(struct http_client_queue *queue,
	struct http_client_request *req)
{
	unsigned int insert_idx;

	if (req->queue != NULL)
		http_client_queue_drop_request(req->queue, req);
	req->queue = queue;

	/* check delay vs timeout */
	if (req->release_time.tv_sec > 0 && req->timeout_time.tv_sec > 0 &&
		timeval_cmp_margin(&req->release_time,
			&req->timeout_time, TIMEOUT_CMP_MARGIN_USECS) >= 0) {
		/* release time is later than absolute timeout */
		req->release_time.tv_sec = 0;
		req->release_time.tv_usec = 0;

		/* timeout rightaway */
		req->timeout_time = ioloop_timeval;

		http_client_queue_debug(queue,
			"Delayed request %s%s already timed out",
			http_client_request_label(req),
			(req->urgent ? " (urgent)" : ""));
	}

	/* add to main request list */
	if (req->timeout_time.tv_sec == 0) {
		/* no timeout; just append */
		array_append(&queue->requests, &req, 1);

	} else {
		unsigned int insert_idx;

		/* keep main request list sorted earliest timeout first */
		(void)array_bsearch_insert_pos(&queue->requests,
			&req, http_client_queue_request_timeout_cmp, &insert_idx);
		array_insert(&queue->requests, insert_idx, &req, 1);

		/* now first in queue; update timer */
		if (insert_idx == 0)
			http_client_queue_set_request_timer(queue, &req->timeout_time);
	}

	/* handle delay */
	if (req->release_time.tv_sec > 0) {
		io_loop_time_refresh();

		if (timeval_cmp_margin(&req->release_time,
			&ioloop_timeval, TIMEOUT_CMP_MARGIN_USECS) > 0) {
			(void)array_bsearch_insert_pos(&queue->delayed_requests,
					&req, http_client_queue_delayed_cmp, &insert_idx);
			array_insert(&queue->delayed_requests, insert_idx, &req, 1);
			if (insert_idx == 0)
				http_client_queue_set_delay_timer(queue, req->release_time);
			return;
		}
	}

	http_client_queue_submit_now(queue, req);
}

/*
 * Request retrieval
 */

struct http_client_request *
http_client_queue_claim_request(struct http_client_queue *queue,
	const struct http_client_peer_addr *addr, bool no_urgent)
{
	struct http_client_request *const *requests;
	struct http_client_request *req;
	unsigned int i, count;

	count = 0;
	if (!no_urgent)
	 	requests = array_get(&queue->queued_urgent_requests, &count);

	if (count == 0)
	 	requests = array_get(&queue->queued_requests, &count);
	if (count == 0)
		return NULL;
	i = 0;
	req = requests[i];
	if (req->urgent)
		array_delete(&queue->queued_urgent_requests, i, 1);
	else
		array_delete(&queue->queued_requests, i, 1);

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
	unsigned int urg_count = array_count(&queue->queued_urgent_requests); 

	if (num_urgent_r != NULL)
		*num_urgent_r = urg_count;
	return array_count(&queue->queued_requests) + urg_count;
}

/*
 * ioloop
 */

void http_client_queue_switch_ioloop(struct http_client_queue *queue)
{
	if (queue->to_connect != NULL)
		queue->to_connect = io_loop_move_timeout(&queue->to_connect);
	if (queue->to_request != NULL)
		queue->to_request = io_loop_move_timeout(&queue->to_request);
	if (queue->to_delayed != NULL)
		queue->to_delayed = io_loop_move_timeout(&queue->to_delayed);
}
