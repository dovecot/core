/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "net.h"
#include "str.h"
#include "hash.h"
#include "array.h"
#include "llist.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "time-util.h"
#include "dns-lookup.h"
#include "http-response-parser.h"
#include "settings.h"

#include "http-client-private.h"

#define HTTP_CLIENT_HOST_MINIMUM_IDLE_TIMEOUT_MSECS 100

static void http_client_host_lookup_done(struct http_client_host *host);
static void
http_client_host_lookup_failure(struct http_client_host *host,
				const char *error);
static bool http_client_host_is_idle(struct http_client_host *host);
static void http_client_host_free_shared(struct http_client_host **_host);

/*
 * Host (shared)
 */

static void
http_client_host_shared_idle_timeout(struct http_client_host_shared *hshared)
{
	e_debug(hshared->event, "Idle host timed out");
	http_client_host_shared_free(&hshared);
}

static void
http_client_host_shared_check_idle(struct http_client_host_shared *hshared)
{
	struct http_client_host *host;
	long long timeout = 0;

	if (hshared->destroyed)
		return;
	if (hshared->to_idle != NULL)
		return;

	host = hshared->hosts_list;
	while (host != NULL) {
		if (!http_client_host_is_idle(host))
			return;
		host = host->shared_next;
	}

	if (!hshared->unix_local && !hshared->explicit_ip &&
	    hshared->ips_timeout.tv_sec > 0) {
		timeout = timeval_diff_msecs(&hshared->ips_timeout,
					     &ioloop_timeval);
	}

	if (timeout <= HTTP_CLIENT_HOST_MINIMUM_IDLE_TIMEOUT_MSECS)
		timeout = HTTP_CLIENT_HOST_MINIMUM_IDLE_TIMEOUT_MSECS;

	hshared->to_idle = timeout_add_to(hshared->cctx->ioloop, timeout,
					  http_client_host_shared_idle_timeout,
					  hshared);

	e_debug(hshared->event, "Host is idle (timeout = %lld msecs)", timeout);
}

static void
http_client_host_shared_lookup_failure(struct http_client_host_shared *hshared,
				       const char *error)
{
	struct http_client_host *host;

	e_debug(hshared->event, "DNS lookup failed: %s", error);

	error = t_strdup_printf("Failed to lookup host %s: %s",
				hshared->name, error);

	host = hshared->hosts_list;
	while (host != NULL) {
		http_client_host_lookup_failure(host, error);
		host = host->shared_next;
	}

	http_client_host_shared_check_idle(hshared);
}

static void
http_client_host_shared_lookup_success(struct http_client_host_shared *hshared,
				       const struct ip_addr *ips,
				       unsigned int ips_count)
{
	struct http_client_context *cctx = hshared->cctx;

	i_assert(ips_count > 0);

	e_debug(hshared->event,
		"DNS lookup successful; got %d IPs", ips_count);

	hshared->ips = i_realloc_type(hshared->ips, struct ip_addr,
				      hshared->ips_count, ips_count);
	hshared->ips_count = ips_count;
	memcpy(hshared->ips, ips, sizeof(struct ip_addr) * ips_count);

	hshared->ips_timeout = ioloop_timeval;
	i_assert(cctx->dns_ttl_msecs > 0);
	timeval_add_msecs(&hshared->ips_timeout, cctx->dns_ttl_msecs);
}

static void
http_client_host_shared_dns_callback(const struct dns_lookup_result *result,
				     struct http_client_host_shared *hshared)
{
	/* We ended up here because dns_lookup_abort() was used */
	if (result->ret == EAI_CANCELED)
		return;
	struct http_client_host *host;

	hshared->dns_lookup = NULL;

	if (result->ret != 0) {
		/* Lookup failed */
		http_client_host_shared_lookup_failure(hshared, result->error);
		return;
	}

	http_client_host_shared_lookup_success(hshared, result->ips,
					       result->ips_count);

	/* Notify all sessions */
	host = hshared->hosts_list;
	while (host != NULL) {
		http_client_host_lookup_done(host);
		host = host->shared_next;
	}
}

static void
http_client_host_shared_lookup(struct http_client_host *host)
{
	struct http_client_host_shared *hshared = host->shared;
	struct http_client_context *cctx = hshared->cctx;

	i_assert(!hshared->explicit_ip);
	i_assert(hshared->dns_lookup == NULL);

	if (cctx->dns_client != NULL) {
		e_debug(host->client->event, "Performing asynchronous DNS lookup");
		/* Note: dns_client_lookup() takes DNS settings from cctx->dns_client
		   and may differ from host->client DNS settings */
		(void)dns_client_lookup(cctx->dns_client, hshared->name,
					host->client->event,
					http_client_host_shared_dns_callback,
					hshared, &hshared->dns_lookup);
	} else {
		struct ioloop *prev_ioloop = current_ioloop;
		/* host->client->event is used in order to
		   get client-specific DNS settings. */
		e_debug(host->client->event, "Performing asynchronous DNS lookup");
		io_loop_set_current(cctx->ioloop);
		(void)dns_lookup(hshared->name, NULL, host->client->event,
				 http_client_host_shared_dns_callback,
				 hshared, &hshared->dns_lookup);
		io_loop_set_current(prev_ioloop);
	}
}

static int
http_client_host_shared_refresh(struct http_client_host *host)
{
	struct http_client_host_shared *hshared = host->shared;
	if (hshared->unix_local)
		return 0;
	if (hshared->explicit_ip)
		return 0;

	if (hshared->dns_lookup != NULL)
		return -1;

	if (hshared->ips_count == 0) {
		e_debug(hshared->event, "Need to perform DNS lookup");
	} else {
		if (timeval_cmp(&hshared->ips_timeout, &ioloop_timeval) > 0)
			return 0;

		e_debug(hshared->event, "IPs have expired; "
			"need to refresh DNS lookup");
	}

	http_client_host_shared_lookup(host);
	if (hshared->dns_lookup != NULL)
		return -1;
	return (hshared->ips_count > 0 ? 1 : -1);
}

static struct http_client_host_shared *
http_client_host_shared_create(struct http_client_context *cctx,
			       const char *name)
{
	struct http_client_host_shared *hshared;

	// FIXME: limit the maximum number of inactive cached hosts
	hshared = i_new(struct http_client_host_shared, 1);
	hshared->cctx = cctx;
	hshared->name = i_strdup(name);
	hshared->event = event_create(cctx->event);
	event_set_append_log_prefix(hshared->event,
				    t_strdup_printf("host %s: ", name));
	DLLIST_PREPEND(&cctx->hosts_list, hshared);

	return hshared;
}

static struct http_client_host_shared *
http_client_host_shared_get(struct http_client_context *cctx,
			    const struct http_url *host_url)
{
	struct http_client_host_shared *hshared;

	if (host_url == NULL) {
		hshared = cctx->unix_host;
		if (hshared == NULL) {
			hshared = http_client_host_shared_create(
				cctx, "[unix]");
			hshared->unix_local = TRUE;

			cctx->unix_host = hshared;

			e_debug(hshared->event, "Unix host created");
		}

	} else {
		const char *hostname = host_url->host.name;
		struct ip_addr ip = host_url->host.ip;

		hshared = hash_table_lookup(cctx->hosts, hostname);
		if (hshared == NULL) {
			hshared = http_client_host_shared_create(
				cctx, hostname);
			hostname = hshared->name;
			hash_table_insert(cctx->hosts, hostname, hshared);

			if (ip.family != 0 ||
			    net_addr2ip(hshared->name, &ip) == 0) {
				hshared->ips_count = 1;
				hshared->ips = i_new(struct ip_addr,
						     hshared->ips_count);
				hshared->ips[0] = ip;
				hshared->explicit_ip = TRUE;
			}

			e_debug(hshared->event, "Host created");
		}
	}
	return hshared;
}

void http_client_host_shared_free(struct http_client_host_shared **_hshared)
{
	struct http_client_host_shared *hshared = *_hshared;
	struct http_client_context *cctx = hshared->cctx;
	struct http_client_host *host;
	const char *hostname = hshared->name;

	if (hshared->destroyed)
		return;
	hshared->destroyed = TRUE;

	e_debug(hshared->event, "Host destroy");

	timeout_remove(&hshared->to_idle);

	DLLIST_REMOVE(&cctx->hosts_list, hshared);
	if (hshared == cctx->unix_host)
		cctx->unix_host = NULL;
	else
		hash_table_remove(cctx->hosts, hostname);

	if (hshared->dns_lookup != NULL)
		dns_lookup_abort(&hshared->dns_lookup);

	/* Drop client sessions */
	while (hshared->hosts_list != NULL) {
		host = hshared->hosts_list;
		http_client_host_free_shared(&host);
	}

	event_unref(&hshared->event);
	i_free(hshared->ips);
	i_free(hshared->name);
	i_free(hshared);

	*_hshared = NULL;
}

static void
http_client_host_shared_request_submitted(
	struct http_client_host_shared *hshared)
{
	/* Cancel host idle timeout */
	timeout_remove(&hshared->to_idle);
}

void http_client_host_shared_switch_ioloop(
	struct http_client_host_shared *hshared)
{
	struct http_client_context *cctx = hshared->cctx;

	if (hshared->dns_lookup != NULL && cctx->dns_client == NULL)
		dns_lookup_switch_ioloop(hshared->dns_lookup);
	if (hshared->to_idle != NULL)
		hshared->to_idle = io_loop_move_timeout(&hshared->to_idle);
}

/*
 * Host
 */

struct http_client_host *
http_client_host_get(struct http_client *client,
		     const struct http_url *host_url)
{
	struct http_client_host_shared *hshared;
	struct http_client_host *host;

	hshared = http_client_host_shared_get(client->cctx, host_url);

	host = hshared->hosts_list;
	while (host != NULL) {
		if (host->client == client)
			break;
		host = host->shared_next;
	}

	if (host == NULL) {
		host = i_new(struct http_client_host, 1);
		host->client = client;
		host->shared = hshared;
		i_array_init(&host->queues, 4);
		DLLIST_PREPEND_FULL(&hshared->hosts_list,
				    host, shared_prev, shared_next);
		DLLIST_PREPEND_FULL(&client->hosts_list, host,
				    client_prev, client_next);

		e_debug(hshared->event, "Host session created");
	}

	return host;
}

static void http_client_host_free_shared(struct http_client_host **_host)
{
	struct http_client_host *host = *_host;
	struct http_client *client = host->client;
	struct http_client_host_shared *hshared = host->shared;
	struct http_client_queue *queue;
	ARRAY_TYPE(http_client_queue) queues;

	*_host = NULL;

	e_debug(hshared->event, "Host session destroy");

	DLLIST_REMOVE_FULL(&hshared->hosts_list, host,
			   shared_prev, shared_next);
	DLLIST_REMOVE_FULL(&client->hosts_list, host,
			   client_prev, client_next);

	/* Drop request queues */
	t_array_init(&queues, array_count(&host->queues));
	array_copy(&queues.arr, 0, &host->queues.arr, 0,
		   array_count(&host->queues));
	array_clear(&host->queues);
	array_foreach_elem(&queues, queue)
		http_client_queue_free(queue);
	array_free(&host->queues);

	i_free(host);
}

void http_client_host_free(struct http_client_host **_host)
{
	struct http_client_host *host = *_host;
	struct http_client_host_shared *hshared = host->shared;

	http_client_host_free_shared(_host);

	http_client_host_shared_check_idle(hshared);
}

static void http_client_host_lookup_done(struct http_client_host *host)
{
	struct http_client *client = host->client;
	struct http_client_queue *queue;
	unsigned int requests = 0;

	/* Notify all queues */
	array_foreach_elem(&host->queues, queue)
		requests += http_client_queue_host_lookup_done(queue);

	if (requests == 0 && client->waiting)
		io_loop_stop(client->ioloop);
}

static void
http_client_host_lookup_failure(struct http_client_host *host,
				const char *error)
{
	struct http_client_queue *queue;

	array_foreach_elem(&host->queues, queue)
		http_client_queue_host_lookup_failure(queue, error);
}

void http_client_host_submit_request(struct http_client_host *host,
				     struct http_client_request *req)
{
	struct http_client *client = req->client;
	struct http_client_queue *queue;
	struct http_client_peer_addr addr;
	const char *error;

	req->host = host;

	http_client_request_get_peer_addr(req, &addr);
	if (http_client_peer_addr_is_https(&addr) &&
	    client->ssl_ctx == NULL) {
		if (http_client_init_ssl_ctx(client, &error) < 0) {
			http_client_request_error(
				&req, HTTP_CLIENT_REQUEST_ERROR_CONNECT_FAILED,
				error);
			return;
		}
	}

	/* Add request to queue */
	queue = http_client_queue_get(host, &addr);
	http_client_queue_submit_request(queue, req);

	/* Update shared host object (idle timeout) */
	http_client_host_shared_request_submitted(host->shared);

	/* Queue will trigger host lookup once the request is activated
	   (may be delayed) */
}

static bool http_client_host_is_idle(struct http_client_host *host)
{
	struct http_client_queue *queue;
	unsigned int requests = 0;

	array_foreach_elem(&host->queues, queue)
		requests += http_client_queue_requests_active(queue);

	return (requests == 0);
}

void http_client_host_check_idle(struct http_client_host *host)
{
	http_client_host_shared_check_idle(host->shared);
}

int http_client_host_refresh(struct http_client_host *host)
{
	return http_client_host_shared_refresh(host);
}

bool http_client_host_get_ip_idx(struct http_client_host *host,
				 const struct ip_addr *ip, unsigned int *idx_r)
{
	struct http_client_host_shared *hshared = host->shared;
	unsigned int i;

	for (i = 0; i < hshared->ips_count; i++) {
		if (net_ip_compare(&hshared->ips[i], ip)) {
			*idx_r = i;
			return TRUE;
		}
	}
	return FALSE;
}

void http_client_host_switch_ioloop(struct http_client_host *host)
{
	struct http_client_queue *queue;

	array_foreach_elem(&host->queues, queue)
		http_client_queue_switch_ioloop(queue);
}
