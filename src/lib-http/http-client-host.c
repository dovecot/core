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

static void
http_client_host_port_connection_setup(struct http_client_host_port *hport);

static struct http_client_host_port *
http_client_host_port_find(struct http_client_host *host,
	unsigned int port, const char *https_name)
{
	struct http_client_host_port *hport;

	array_foreach_modifiable(&host->ports, hport) {
		if (hport->port == port &&
		    null_strcmp(hport->https_name, https_name) == 0)
			return hport;
	}

	return NULL;
}

static struct http_client_host_port *
http_client_host_port_init(struct http_client_host *host,
	unsigned int port, const char *https_name)
{
	struct http_client_host_port *hport;

	hport = http_client_host_port_find(host, port, https_name);
	if (hport == NULL) {
		hport = array_append_space(&host->ports);
		hport->host = host;
		hport->port = port;
		hport->https_name = i_strdup(https_name);
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
	i_free(hport->https_name);
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

static bool
http_client_hport_is_last_connect_ip(struct http_client_host_port *hport)
{
	i_assert(hport->ips_connect_idx < hport->host->ips_count);
	i_assert(hport->ips_connect_start_idx < hport->host->ips_count);

	/* we'll always go through all the IPs. we don't necessarily start
	   connecting from the first IP, so we'll need to treat the IPs as
	   a ring buffer where we automatically wrap back to the first IP
	   when necessary. */
	return (hport->ips_connect_idx + 1) % hport->host->ips_count ==
		hport->ips_connect_start_idx;
}

static void
http_client_host_port_soft_connect_timeout(struct http_client_host_port *hport)
{
	struct http_client_host *host = hport->host;

	if (hport->to_connect != NULL)
		timeout_remove(&hport->to_connect);

	if (http_client_hport_is_last_connect_ip(hport))
		return;

	/* if our our previous connection attempt takes longer than the
	   soft_connect_timeout we start a connection attempt to the next IP in
	   parallel */

	http_client_host_debug(host, "Connection to %s:%u%s is taking a long time; "
		"starting parallel connection attempt to next IP",
		net_ip2addr(&host->ips[hport->ips_connect_idx]), hport->port,
		hport->https_name == NULL ? "" :
			t_strdup_printf(" (SSL=%s)", hport->https_name));

	hport->ips_connect_idx = (hport->ips_connect_idx + 1) % host->ips_count;
	http_client_host_port_connection_setup(hport);
}

static void
http_client_host_port_connection_setup(struct http_client_host_port *hport)
{
	struct http_client_host *host = hport->host;
	struct http_client_peer *peer = NULL;
	struct http_client_peer_addr addr;
	unsigned int msecs;

	addr.ip = host->ips[hport->ips_connect_idx];
	addr.port = hport->port;
	addr.https_name = hport->https_name;

	http_client_host_debug(host, "Setting up connection to %s:%u%s",
		net_ip2addr(&addr.ip), addr.port, addr.https_name == NULL ? "" :
		t_strdup_printf(" (SSL=%s)", addr.https_name));

	peer = http_client_peer_get(host->client, &addr);
	http_client_peer_add_host(peer, host);
	if (http_client_peer_handle_requests(peer))
		hport->pending_connection_count++;

	/* start soft connect time-out (but only if we have another IP left) */
	msecs = host->client->set.soft_connect_timeout_msecs;
	if (!http_client_hport_is_last_connect_ip(hport) && msecs > 0 &&
	    hport->to_connect == NULL) {
		hport->to_connect =
			timeout_add(msecs, http_client_host_port_soft_connect_timeout, hport);
	}
}

static void
http_client_host_drop_pending_connections(struct http_client_host_port *hport,
					  const struct http_client_peer_addr *addr)
{
	struct http_client_peer *peer;
	struct http_client_connection *const *conns, *conn;
	unsigned int i, count;

	for (peer = hport->host->client->peers_list; peer != NULL; peer = peer->next) {
		if (http_client_peer_addr_cmp(&peer->addr, addr) == 0) {
			/* don't drop any connections to the successfully
			   connected peer, even if some of the connections
			   are pending. they may be intended for urgent
			   requests. */
			continue;
		}
		if (!http_client_peer_have_host(peer, hport->host))
			continue;

		conns = array_get(&peer->conns, &count);
		for (i = count; i > 0; i--) {
			conn = conns[i-1];
			if (!conn->connected) {
				i_assert(conn->refcount == 1);
				/* avoid recreating the connection */
				peer->last_connect_failed = TRUE;
				http_client_connection_unref(&conn);
			}
		}
	}
}

static unsigned int
http_client_host_get_ip_idx(struct http_client_host *host,
			    const struct ip_addr *ip)
{
	unsigned int i;

	for (i = 0; i < host->ips_count; i++) {
		if (net_ip_compare(&host->ips[i], ip))
			return i;
	}
	i_unreached();
}

static void
http_client_host_port_connection_success(struct http_client_host_port *hport,
					 const struct http_client_peer_addr *addr)
{
	/* we achieved at least one connection the the addr->ip */
	hport->ips_connect_start_idx =
		http_client_host_get_ip_idx(hport->host, &addr->ip);

	/* stop soft connect time-out */
	if (hport->to_connect != NULL)
		timeout_remove(&hport->to_connect);

	/* drop all other attempts to the hport. note that we get here whenever
	   a connection is successfully created, so pending_connection_count
	   may be 0. */
	if (hport->pending_connection_count > 1)
		http_client_host_drop_pending_connections(hport, addr);
	/* since this hport is now successfully connected, we won't be
	   getting any connection failures to it anymore. so we need
	   to reset the pending_connection_count count here. */
	hport->pending_connection_count = 0;
}

static bool
http_client_host_port_connection_failure(struct http_client_host_port *hport,
	const char *reason)
{
	struct http_client_host *host = hport->host;

	if (hport->pending_connection_count > 0) {
		/* we're still doing the initial connections to this hport. if
		   we're also doing parallel connections with soft timeouts
		   (pending_connection_count>1), wait for them to finish
		   first. */
		if (--hport->pending_connection_count > 0)
			return TRUE;
	}

	/* one of the connections failed. if we're not using soft timeouts,
	   we need to try to connect to the next IP. if we are using soft
	   timeouts, we've already tried all of the IPs by now. */
	if (hport->to_connect != NULL)
		timeout_remove(&hport->to_connect);

	if (http_client_hport_is_last_connect_ip(hport)) {
		/* all IPs failed, but retry all of them again on the
		   next request. */
		hport->ips_connect_idx = hport->ips_connect_start_idx =
			(hport->ips_connect_idx + 1) % host->ips_count;
		http_client_host_port_error(hport,
			HTTP_CLIENT_REQUEST_ERROR_CONNECT_FAILED, reason);
		return FALSE;
	}
	hport->ips_connect_idx = (hport->ips_connect_idx + 1) % host->ips_count;

	http_client_host_port_connection_setup(hport);
	return TRUE;
}

/*
 * Host
 */

void http_client_host_connection_success(struct http_client_host *host,
	const struct http_client_peer_addr *addr)
{
	struct http_client_host_port *hport;

	http_client_host_debug(host, "Successfully connected to %s:%u",
		net_ip2addr(&addr->ip), addr->port);

	hport = http_client_host_port_find(host, addr->port, addr->https_name);
	if (hport == NULL)
		return;

	http_client_host_port_connection_success(hport, addr);
}

void http_client_host_connection_failure(struct http_client_host *host,
	const struct http_client_peer_addr *addr, const char *reason)
{
	struct http_client_host_port *hport;

	http_client_host_debug(host, "Failed to connect to %s:%u: %s",
		net_ip2addr(&addr->ip), addr->port, reason);

	hport = http_client_host_port_find(host, addr->port, addr->https_name);
	if (hport == NULL)
		return;

	if (!http_client_host_port_connection_failure(hport, reason)) {
		/* failed definitively for currently queued requests */
		if (host->client->ioloop != NULL)
			io_loop_stop(host->client->ioloop);
	}
}

static void
http_client_host_lookup_failure(struct http_client_host *host, const char *error)
{
	struct http_client_host_port *hport;

	error = t_strdup_printf("Failed to lookup host %s: %s",
				host->name, error);
	array_foreach_modifiable(&host->ports, hport) {
		http_client_host_port_error(hport,
			HTTP_CLIENT_REQUEST_ERROR_HOST_LOOKUP_FAILED, error);
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
		http_client_host_lookup_failure(host, result->error);
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
		hport->ips_connect_idx = hport->ips_connect_start_idx = 0;
		if (count > 0)
			http_client_host_port_connection_setup(hport);
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
			http_client_host_lookup_failure(host, net_gethosterror(ret));
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
		i_array_init(&host->delayed_failing_requests, 1);

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
	const char *https_name = req->ssl ? req->hostname : NULL;
	const char *error;

	req->host = host;

	if (req->ssl && host->client->ssl_ctx == NULL) {
		if (http_client_init_ssl_ctx(host->client, &error) < 0) {
			http_client_request_error(req,
				HTTP_CLIENT_REQUEST_ERROR_CONNECT_FAILED, error);
			return;
		}
	}

	/* add request to host (grouped by tcp port) */
	hport = http_client_host_port_init(host, req->port, https_name);
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
	i_assert(hport->ips_connect_idx < host->ips_count);
	http_client_host_port_connection_setup(hport);
}

struct http_client_request *
http_client_host_claim_request(struct http_client_host *host,
	const struct http_client_peer_addr *addr, bool no_urgent)
{
	struct http_client_host_port *hport;
	struct http_client_request *const *requests;
	struct http_client_request *req;
	unsigned int i, count;

	hport = http_client_host_port_find(host, addr->port, addr->https_name);
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

	hport = http_client_host_port_find(host, addr->port, addr->https_name);
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
	const char *https_name = req->ssl ? req->hostname : NULL;

	hport = http_client_host_port_find(host, req->port, https_name);
	if (hport == NULL)
		return;

	http_client_host_port_drop_request(hport, req);
}

void http_client_host_free(struct http_client_host **_host)
{
	struct http_client_host *host = *_host;
	struct http_client_host_port *hport;
	struct http_client_request *req, *const *reqp;
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

	while (array_count(&host->delayed_failing_requests) > 0) {
		reqp = array_idx(&host->delayed_failing_requests, 0);
		req = *reqp;

		i_assert(req->refcount == 1);
		http_client_request_unref(&req);
	}
	array_free(&host->delayed_failing_requests);

	i_free(host->ips);
	i_free(host->name);
	i_free(host);
}

void http_client_host_switch_ioloop(struct http_client_host *host)
{
	struct http_client_request **req;

	if (host->dns_lookup != NULL)
		dns_lookup_switch_ioloop(host->dns_lookup);
	array_foreach_modifiable(&host->delayed_failing_requests, req) {
		(*req)->to_delayed_error =
			io_loop_move_timeout(&(*req)->to_delayed_error);
	}

}
