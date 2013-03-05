/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

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
 * Host:port
 */

static struct http_client_host_port *
http_client_host_port_find(struct http_client_host *host,
	unsigned int port, bool ssl)
{
	struct http_client_host_port *hport;

	array_foreach_modifiable(&host->ports, hport) {
		if (hport->port == port && hport->ssl == ssl)
			return hport;
	}

	return NULL;
}

static struct http_client_host_port *
http_client_host_port_init(struct http_client_host *host,
	unsigned int port, bool ssl)
{
	struct http_client_host_port *hport;

	hport = http_client_host_port_find(host, port, ssl);
	if (hport == NULL) {
		hport = array_append_space(&host->ports);
		hport->port = port;
		hport->ssl = ssl;
		hport->ips_connect_idx = 0;
		i_array_init(&hport->request_queue, 16);
	}

	return hport;
}

static void http_client_host_port_error(struct http_client_host_port *hport,
	unsigned int status, const char *error)
{
	struct http_client_request **req;

	/* abort all pending requests */
	array_foreach_modifiable(&hport->request_queue, req) {
		http_client_request_error(*req, status, error);
	}
	array_clear(&hport->request_queue);
}

static void http_client_host_port_deinit(struct http_client_host_port *hport)
{
	http_client_host_port_error
		(hport, HTTP_CLIENT_REQUEST_ERROR_ABORTED, "Aborted");
	array_free(&hport->request_queue);
}

static void
http_client_host_port_drop_request(struct http_client_host_port *hport,
	struct http_client_request *req)
{
	struct http_client_request **req_idx;
	unsigned int idx;

	array_foreach_modifiable(&hport->request_queue, req_idx) {
		if (*req_idx == req) {
			idx = array_foreach_idx(&hport->request_queue, req_idx);
			array_delete(&hport->request_queue, idx, 1);
			break;
		}
	}
}

/*
 * Host
 */

static void
http_client_host_connection_setup(struct http_client_host *host,
	struct http_client_host_port *hport)
{
	struct http_client_peer *peer = NULL;
	struct http_client_peer_addr addr;

	while (hport->ips_connect_idx < host->ips_count) {
		addr.ip = host->ips[hport->ips_connect_idx];
		addr.port = hport->port;
		addr.ssl = hport->ssl;

		http_client_host_debug(host, "Setting up connection to %s:%u (ssl=%s)", 
			net_ip2addr(&addr.ip), addr.port, (addr.ssl ? "yes" : "no"));

		if ((peer=http_client_peer_get(host->client, &addr)) != NULL)
			break;

		hport->ips_connect_idx++;
	}

	if (peer == NULL) {
		/* all IPs failed, but retry all of them again on the
		   next request. */
		hport->ips_connect_idx = 0;
		http_client_host_port_error
			(hport, HTTP_CLIENT_REQUEST_ERROR_CONNECT_FAILED, "Connection failed");
		if (host->client->ioloop != NULL)
			io_loop_stop(host->client->ioloop);
		return;
	}

	http_client_peer_add_host(peer, host);
}

void http_client_host_connection_failure(struct http_client_host *host,
	const struct http_client_peer_addr *addr)
{
	struct http_client_host_port *hport;

	http_client_host_debug(host, "Failed to connect to %s:%u", 
		net_ip2addr(&addr->ip), addr->port);

	hport = http_client_host_port_find(host, addr->port, addr->ssl);
	if (hport == NULL)
		return;

	hport->ips_connect_idx++;
	http_client_host_connection_setup(host, hport);
}

static void
http_client_host_lookup_failure(struct http_client_host *host)
{
	struct http_client_host_port *hport;

	array_foreach_modifiable(&host->ports, hport) {
		http_client_host_port_error(hport,
			HTTP_CLIENT_REQUEST_ERROR_HOST_LOOKUP_FAILED, "Failed to lookup host");
	}
}

static void
http_client_host_dns_callback(const struct dns_lookup_result *result,
			      struct http_client_host *host)
{
	struct http_client_host_port *hport;
	unsigned int requests = 0;

	host->dns_lookup = NULL;

	if (result->ret != 0) {
		i_error("http-client: dns_lookup(%s) failed: %s",
			host->name, result->error);
		http_client_host_lookup_failure(host);
		return;
	}

	http_client_host_debug(host,
		"DNS lookup successful; got %d IPs", result->ips_count);

	i_assert(result->ips_count > 0);
	host->ips_count = result->ips_count;
	host->ips = i_new(struct ip_addr, host->ips_count);
	memcpy(host->ips, result->ips, sizeof(*host->ips) * host->ips_count);

	// FIXME: make DNS result expire 

	/* make connections to requested ports */
	array_foreach_modifiable(&host->ports, hport) {
		unsigned int count = array_count(&hport->request_queue);
		hport->ips_connect_idx = 0;
		if (count > 0)
			http_client_host_connection_setup(host, hport);
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

	memset(&dns_set, 0, sizeof(dns_set));
	dns_set.dns_client_socket_path =
		client->set.dns_client_socket_path;
	dns_set.timeout_msecs = HTTP_CLIENT_DNS_LOOKUP_TIMEOUT_MSECS;

	if (host->ips_count == 0 &&
	    net_addr2ip(host->name, &ip) == 0) { // FIXME: remove this?
		host->ips_count = 1;
		host->ips = i_new(struct ip_addr, host->ips_count);
		host->ips[0] = ip;
	} else if (dns_set.dns_client_socket_path == NULL) {
		ret = net_gethostbyname(host->name,	&ips, &ips_count);
		if (ret != 0) {
			i_error("http-client: net_gethostbyname(%s) failed: %s",
				host->name,	net_gethosterror(ret));
			http_client_host_lookup_failure(host);
			return;
		}

		http_client_host_debug(host,
			"DNS lookup successful; got %d IPs", ips_count);

		host->ips_count = ips_count;
		host->ips = i_new(struct ip_addr, ips_count);
		memcpy(host->ips, ips, ips_count * sizeof(*ips));
	}

	if (host->ips_count == 0) {
		http_client_host_debug(host,
			"Performing asynchronous DNS lookup");
		(void)dns_lookup(host->name, &dns_set,
				 http_client_host_dns_callback, host, &host->dns_lookup);
	}
}

struct http_client_host *http_client_host_get
(struct http_client *client, const char *hostname)
{
	struct http_client_host *host;

	host = hash_table_lookup(client->hosts, hostname);
	if (host == NULL) {
		// FIXME: limit the maximum number of inactive cached hosts
		host = i_new(struct http_client_host, 1);
		host->client = client;
		host->name = i_strdup(hostname);
		i_array_init(&host->ports, 4);

		hostname = host->name;
		hash_table_insert(client->hosts, hostname, host);
		DLLIST_PREPEND(&client->hosts_list, host);

		http_client_host_debug(host, "Host created");
	}
	return host;
}

void http_client_host_submit_request(struct http_client_host *host,
	struct http_client_request *req)
{
	struct http_client_host_port *hport;

	req->host = host;

	/* add request to host (grouped by tcp port) */
	hport = http_client_host_port_init(host, req->port, req->ssl);
	if (req->urgent)
		array_insert(&hport->request_queue, 0, &req, 1);
	else
		array_append(&hport->request_queue, &req, 1);

	/* start DNS lookup if necessary */
	if (host->ips_count == 0 && host->dns_lookup == NULL)	
		http_client_host_lookup(host);

	/* make a connection if we have an IP already */
	if (host->ips_count == 0)
		return;
	http_client_host_connection_setup(host, hport);
}

struct http_client_request *
http_client_host_claim_request(struct http_client_host *host,
	const struct http_client_peer_addr *addr, bool no_urgent)
{
	struct http_client_host_port *hport;
	struct http_client_request *const *requests;
	struct http_client_request *req;
	unsigned int i, count;

	hport = http_client_host_port_find(host, addr->port, addr->ssl);
	if (hport == NULL)
		return NULL;

	requests = array_get(&hport->request_queue, &count);
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
	array_delete(&hport->request_queue, i, 1);

	http_client_host_debug(host,
		"Connection to peer %s:%u claimed request %s %s",
		net_ip2addr(&addr->ip), addr->port, http_client_request_label(req),
		(req->urgent ? "(urgent)" : ""));

	return req;
}

unsigned int http_client_host_requests_pending(struct http_client_host *host,
	const struct http_client_peer_addr *addr, unsigned int *num_urgent_r)
{
	struct http_client_host_port *hport;
	struct http_client_request *const *requests;
	unsigned int count, i;

	*num_urgent_r = 0;

	hport = http_client_host_port_find(host, addr->port, addr->ssl);
	if (hport == NULL)
		return 0;

	requests = array_get(&hport->request_queue, &count);
	for (i = 0; i < count && requests[i]->urgent; i++)
		(*num_urgent_r)++;
	return count;
}

void http_client_host_drop_request(struct http_client_host *host,
	struct http_client_request *req)
{
	struct http_client_host_port *hport;

	hport = http_client_host_port_find(host, req->port, req->ssl);
	if (hport == NULL)
		return;

	http_client_host_port_drop_request(hport, req);
}

void http_client_host_free(struct http_client_host **_host)
{
	struct http_client_host *host = *_host;
	struct http_client_host_port *hport;
	const char *hostname = host->name;

	http_client_host_debug(host, "Host destroy");

	DLLIST_REMOVE(&host->client->hosts_list, host);
	hash_table_remove(host->client->hosts, hostname);

	if (host->dns_lookup != NULL)
		dns_lookup_abort(&host->dns_lookup);

	/* drop request queues */
	array_foreach_modifiable(&host->ports, hport) {
		http_client_host_port_deinit(hport);
	}
	array_free(&host->ports);

	i_free(host->ips);
	i_free(host->name);
	i_free(host);
}

void http_client_host_switch_ioloop(struct http_client_host *host)
{
	if (host->dns_lookup != NULL)
		dns_lookup_switch_ioloop(host->dns_lookup);
}
