/* Copyright (c) 2013-2016 Dovecot authors, see the included COPYING file */

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
	struct http_client *client = host->client;
	struct http_client_queue *const *queue_idx;
	unsigned int requests = 0;

	host->dns_lookup = NULL;

	if (result->ret != 0) {
		/* lookup failed */
		http_client_host_lookup_failure(host, result->error);
		return;
	}

	http_client_host_debug(host,
		"DNS lookup successful; got %d IPs", result->ips_count);

	i_assert(result->ips_count > 0);
	host->ips_count = result->ips_count;
	host->ips = i_new(struct ip_addr, host->ips_count);
	memcpy(host->ips, result->ips, sizeof(*host->ips) * host->ips_count);

	host->ips_timeout = ioloop_timeval;
	timeval_add_msecs(&host->ips_timeout, client->set.dns_ttl_msecs);

	/* make connections to requested ports */
	array_foreach_modifiable(&host->queues, queue_idx) {
		requests += http_client_queue_host_lookup_done(*queue_idx);
	}

	if (requests == 0 && host->client->ioloop != NULL)
		io_loop_stop(host->client->ioloop);
}

static void http_client_host_lookup
(struct http_client_host *host)
{
	struct http_client *client = host->client;
	struct dns_lookup_settings dns_set;
	struct ip_addr *ips;
	int ret;

	i_assert(!host->explicit_ip);

	if (client->set.dns_client != NULL) {
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
		if (client->set.connect_timeout_msecs > 0)
			dns_set.timeout_msecs = client->set.connect_timeout_msecs;
		else if (client->set.request_timeout_msecs > 0)
			dns_set.timeout_msecs = client->set.request_timeout_msecs;
		else {
			dns_set.timeout_msecs =
				HTTP_CLIENT_DEFAULT_DNS_LOOKUP_TIMEOUT_MSECS;
		}
		(void)dns_lookup(host->name, &dns_set,
				 http_client_host_dns_callback, host, &host->dns_lookup);
	} else {
		unsigned int ips_count;

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

	if (host->ips_count > 0) {
		host->ips_timeout = ioloop_timeval;
		timeval_add_msecs(&host->ips_timeout, client->set.dns_ttl_msecs);
	}
}

int http_client_host_refresh(struct http_client_host *host)
{
	if (host->unix_local)
		return 0;
	if (host->explicit_ip)
		return 0;

	if (host->dns_lookup != NULL)
		return -1;

	if (host->ips_count > 0 &&
		timeval_cmp(&host->ips_timeout, &ioloop_timeval) > 0)
		return 0;

	http_client_host_debug(host,
		"IPs have expired; need to refresh DNS lookup");

	http_client_host_lookup(host);
	if (host->dns_lookup != NULL)
		return -1;
	return (host->ips_count > 0 ? 1 : -1);
}

static struct http_client_host *http_client_host_create
(struct http_client *client)
{
	struct http_client_host *host;

	// FIXME: limit the maximum number of inactive cached hosts
	host = i_new(struct http_client_host, 1);
	host->client = client;
	i_array_init(&host->queues, 4);
	DLLIST_PREPEND(&client->hosts_list, host);

	return host;
}

struct http_client_host *http_client_host_get
(struct http_client *client, const struct http_url *host_url)
{
	struct http_client_host *host;

	if (host_url == NULL) {
		host = client->unix_host;
		if (host == NULL) {
			host = http_client_host_create(client);
			host->name = i_strdup("[unix]");
			host->unix_local = TRUE;

			client->unix_host = host;

			http_client_host_debug(host, "Unix host created");
		}

	} else {
		const char *hostname = host_url->host.name;
		struct ip_addr ip = host_url->host.ip;

		host = hash_table_lookup(client->hosts, hostname);
		if (host == NULL) {
			host = http_client_host_create(client);
			host->name = i_strdup(hostname);
			hostname = host->name;
			hash_table_insert(client->hosts, hostname, host);

			if (ip.family != 0 || net_addr2ip(host->name, &ip) == 0) {
				host->ips_count = 1;
				host->ips = i_new(struct ip_addr, host->ips_count);
				host->ips[0] = ip;
				host->explicit_ip = TRUE;
			}

			http_client_host_debug(host, "Host created");
		}
	}
	return host;
}

void http_client_host_submit_request(struct http_client_host *host,
	struct http_client_request *req)
{
	struct http_client_queue *queue;
	struct http_client_peer_addr addr;
	const char *error;

	req->host = host;

	http_client_request_get_peer_addr(req, &addr);
	if (http_client_peer_addr_is_https(&addr) &&
		host->client->ssl_ctx == NULL) {
		if (http_client_init_ssl_ctx(host->client, &error) < 0) {
			http_client_request_error(&req,
				HTTP_CLIENT_REQUEST_ERROR_CONNECT_FAILED, error);
			return;
		}
	}

	/* add request to queue (grouped by tcp port) */
	queue = http_client_queue_create(host, &addr);
	http_client_queue_submit_request(queue, req);

	if (host->unix_local) {
		http_client_queue_connection_setup(queue);
		return;
	}

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
	const char *hostname = host->name;

	http_client_host_debug(host, "Host destroy");

	DLLIST_REMOVE(&host->client->hosts_list, host);
	if (host != host->client->unix_host)
		hash_table_remove(host->client->hosts, hostname);

	if (host->dns_lookup != NULL)
		dns_lookup_abort(&host->dns_lookup);

	/* drop request queues */
	array_foreach(&host->queues, queue_idx) {
		http_client_queue_free(*queue_idx);
	}
	array_free(&host->queues);

	i_free(host->ips);
	i_free(host->name);
	i_free(host);
}

void http_client_host_switch_ioloop(struct http_client_host *host)
{
	struct http_client_queue *const *queue_idx;

	if (host->dns_lookup != NULL && host->client->set.dns_client == NULL)
		dns_lookup_switch_ioloop(host->dns_lookup);
	array_foreach(&host->queues, queue_idx)
		http_client_queue_switch_ioloop(*queue_idx);
}
