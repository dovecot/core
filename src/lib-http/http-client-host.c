/* Copyright (c) 2013-2014 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "net.h"
#include "str.h"
#include "hash.h"
#include "array.h"
#include "llist.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "dns-lookup.h"
#include "http-response-parser.h"

#include "http-client-private.h"

/*
 * Logging
 */

static inline void
http_client_host_debug(struct http_client_host *host,
	const char *format, ...) ATTR_FORMAT(2, 3);

static inline void
http_client_host_debug(struct http_client_host *host,
	const char *format, ...)
{
	va_list args;

	if (host->client->set.debug) {

		va_start(args, format);	
		i_debug("http-client: host %s: %s", 
			host->name, t_strdup_vprintf(format, args));
		va_end(args);
	}
}

/*
 * Host
 */

static void
http_client_host_lookup_failure(struct http_client_host *host,
			      const char *error)
{
	struct http_client_queue *const *queue_idx;

	error = t_strdup_printf("Failed to lookup host %s: %s",
				host->name, error);
	array_foreach_modifiable(&host->queues, queue_idx) {
		http_client_queue_fail(*queue_idx,
			HTTP_CLIENT_REQUEST_ERROR_HOST_LOOKUP_FAILED, error);
	}
}

static void
http_client_host_dns_callback(const struct dns_lookup_result *result,
			      struct http_client_host *host)
{
	struct http_client_queue *const *queue_idx;
	unsigned int requests = 0;

	host->dns_lookup = NULL;

	if (result->ret != 0) {
		http_client_host_lookup_failure(host, result->error);
		return;
	}

	http_client_host_debug(host,
		"DNS lookup successful; got %d IPs", result->ips_count);

	i_assert(result->ips_count > 0);
	host->ips_count = result->ips_count;
	host->ips = i_new(struct ip_addr, host->ips_count);
	memcpy(host->ips, result->ips, sizeof(*host->ips) * host->ips_count);
	
	/* FIXME: make DNS result expire */

	/* make connections to requested ports */
	array_foreach_modifiable(&host->queues, queue_idx) {
		struct http_client_queue *queue = *queue_idx;
		unsigned int count = array_count(&queue->request_queue);
		queue->ips_connect_idx = queue->ips_connect_start_idx = 0;
		if (count > 0)
			http_client_queue_connection_setup(queue);
		requests += count;
	}

	if (requests == 0 && host->client->ioloop != NULL)
		io_loop_stop(host->client->ioloop);
}

static void http_client_host_lookup
(struct http_client_host *host)
{
	struct http_client *client = host->client;
	struct dns_lookup_settings dns_set;
	struct ip_addr ip, *ips;
	unsigned int ips_count;
	int ret;

	if (net_addr2ip(host->name, &ip) == 0) {
		host->ips_count = 1;
		host->ips = i_new(struct ip_addr, host->ips_count);
		host->ips[0] = ip;
	} else if (client->set.dns_client != NULL) {
		http_client_host_debug(host,
			"Performing asynchronous DNS lookup");
		(void)dns_client_lookup(client->set.dns_client, host->name,
			http_client_host_dns_callback, host, &host->dns_lookup);
	} else if (client->set.dns_client_socket_path != NULL) {
		http_client_host_debug(host,
			"Performing asynchronous DNS lookup");
		memset(&dns_set, 0, sizeof(dns_set));
		dns_set.dns_client_socket_path =
			client->set.dns_client_socket_path;
		dns_set.timeout_msecs = HTTP_CLIENT_DNS_LOOKUP_TIMEOUT_MSECS;
		(void)dns_lookup(host->name, &dns_set,
				 http_client_host_dns_callback, host, &host->dns_lookup);
	} else {
		ret = net_gethostbyname(host->name, &ips, &ips_count);
		if (ret != 0) {
			http_client_host_lookup_failure(host, net_gethosterror(ret));
			return;
		}

		http_client_host_debug(host,
			"DNS lookup successful; got %d IPs", ips_count);

		host->ips_count = ips_count;
		host->ips = i_new(struct ip_addr, ips_count);
		memcpy(host->ips, ips, ips_count * sizeof(*ips));
	}
}

struct http_client_host *http_client_host_get
(struct http_client *client, const struct http_url *host_url)
{
	struct http_client_host *host;
	const char *hostname = host_url->host_name;

	host = hash_table_lookup(client->hosts, hostname);
	if (host == NULL) {
		// FIXME: limit the maximum number of inactive cached hosts
		host = i_new(struct http_client_host, 1);
		host->client = client;
		host->name = i_strdup(hostname);
		i_array_init(&host->queues, 4);
		i_array_init(&host->delayed_failing_requests, 1);

		hostname = host->name;
		hash_table_insert(client->hosts, hostname, host);
		DLLIST_PREPEND(&client->hosts_list, host);

		if (host_url->have_host_ip) {
			host->ips_count = 1;
			host->ips = i_new(struct ip_addr, host->ips_count);
			host->ips[0] = host_url->host_ip;
		}

		http_client_host_debug(host, "Host created");
	}
	return host;
}

void http_client_host_submit_request(struct http_client_host *host,
	struct http_client_request *req)
{
	struct http_client_queue *queue;
	const struct http_url *host_url = req->host_url;
	struct http_client_peer_addr addr;
	const char *error;

	req->host = host;

	if (host_url->have_ssl && host->client->ssl_ctx == NULL) {
		if (http_client_init_ssl_ctx(host->client, &error) < 0) {
			http_client_request_error(req,
				HTTP_CLIENT_REQUEST_ERROR_CONNECT_FAILED, error);
			return;
		}
	}

	http_client_request_get_peer_addr(req, &addr);

	/* add request to queue (grouped by tcp port) */
	queue = http_client_queue_create(host, &addr);
	http_client_queue_submit_request(queue, req);

	/* start DNS lookup if necessary */
	if (host->ips_count == 0 && host->dns_lookup == NULL)	
		http_client_host_lookup(host);

	/* make a connection if we have an IP already */
	if (host->ips_count == 0)
		return;

	http_client_queue_connection_setup(queue);
}

void http_client_host_free(struct http_client_host **_host)
{
	struct http_client_host *host = *_host;
	struct http_client_queue *const *queue_idx;
	struct http_client_request *req, *const *req_idx;
	const char *hostname = host->name;

	http_client_host_debug(host, "Host destroy");

	DLLIST_REMOVE(&host->client->hosts_list, host);
	hash_table_remove(host->client->hosts, hostname);

	if (host->dns_lookup != NULL)
		dns_lookup_abort(&host->dns_lookup);

	/* drop request queues */
	array_foreach(&host->queues, queue_idx) {
		http_client_queue_free(*queue_idx);
	}
	array_free(&host->queues);

	while (array_count(&host->delayed_failing_requests) > 0) {
		req_idx = array_idx(&host->delayed_failing_requests, 0);
		req = *req_idx;

		i_assert(req->refcount == 1);
		http_client_request_error_delayed(&req);
	}
	array_free(&host->delayed_failing_requests);

	if (host->to_failing_requests != NULL)
		timeout_remove(&host->to_failing_requests);

	i_free(host->ips);
	i_free(host->name);
	i_free(host);
}

static void
http_client_host_handle_request_errors(struct http_client_host *host)
{		
	timeout_remove(&host->to_failing_requests);

	while (array_count(&host->delayed_failing_requests) > 0) {
		struct http_client_request *const *req_idx =
			array_idx(&host->delayed_failing_requests, 0);
		struct http_client_request *req = *req_idx;

		i_assert(req->refcount == 1);
		http_client_request_error_delayed(&req);
	}
	array_clear(&host->delayed_failing_requests);
}

void http_client_host_delay_request_error(struct http_client_host *host,
	struct http_client_request *req)
{
	if (host->to_failing_requests == NULL) {
		host->to_failing_requests = timeout_add_short(0,
			http_client_host_handle_request_errors, host);
	}
	array_append(&host->delayed_failing_requests, &req, 1);
}

void http_client_host_remove_request_error(struct http_client_host *host,
	struct http_client_request *req)
{
	struct http_client_request *const *reqs;
	unsigned int i, count;

	reqs = array_get(&host->delayed_failing_requests, &count);
	for (i = 0; i < count; i++) {
		if (reqs[i] == req) {
			array_delete(&host->delayed_failing_requests, i, 1);
			return;
		}
	}
}

void http_client_host_switch_ioloop(struct http_client_host *host)
{
	struct http_client_queue *const *queue_idx;

	if (host->dns_lookup != NULL)
		dns_lookup_switch_ioloop(host->dns_lookup);
	array_foreach(&host->queues, queue_idx)
		http_client_queue_switch_ioloop(*queue_idx);
	if (host->to_failing_requests != NULL) {
		host->to_failing_requests =
			io_loop_move_timeout(&host->to_failing_requests);
	}
}
