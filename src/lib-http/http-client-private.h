#ifndef HTTP_CLIENT_PRIVATE_H
#define HTTP_CLIENT_PRIVATE_H

#include "connection.h"

#include "http-client.h"

#define HTTP_DEFAULT_PORT 80
#define HTTPS_DEFAULT_PORT 443

#define HTTP_CLIENT_DNS_LOOKUP_TIMEOUT_MSECS (1000*30)
#define HTTP_CLIENT_CONNECT_TIMEOUT_MSECS (1000*30)
#define HTTP_CLIENT_DEFAULT_REQUEST_TIMEOUT_MSECS (1000*60*5)
#define HTTP_CLIENT_CONTINUE_TIMEOUT_MSECS (1000*2)

struct http_client_host;
struct http_client_host_port;
struct http_client_peer;
struct http_client_connection;

ARRAY_DEFINE_TYPE(http_client_host, struct http_client_host *);
ARRAY_DEFINE_TYPE(http_client_host_port, struct http_client_host_port);
ARRAY_DEFINE_TYPE(http_client_connection, struct http_client_connection *);
ARRAY_DEFINE_TYPE(http_client_request, struct http_client_request *);

HASH_TABLE_DEFINE_TYPE(http_client_host, const char *,
	struct http_client_host *);
HASH_TABLE_DEFINE_TYPE(http_client_peer, const struct http_client_peer_addr *,
	struct http_client_peer *);

struct http_client_request {
	pool_t pool;
	unsigned int refcount;

	struct http_client_request *prev, *next;

	const char *method, *hostname, *target;
	unsigned int port;

	struct http_client *client;
	struct http_client_host *host;
	struct http_client_peer *peer;
	struct http_client_connection *conn;

	string_t *headers;
	struct istream *payload_input;
	uoff_t payload_size, payload_offset;
	struct ostream *payload_output;

	unsigned int attempts;
	unsigned int redirects;

	unsigned int delayed_error_status;
	const char *delayed_error;
	struct timeout *to_delayed_error;

	http_client_request_callback_t *callback;
	void *context;

	void (*destroy_callback)(void *);
	void *destroy_context;

	enum http_request_state state;

	unsigned int payload_sync:1;
	unsigned int payload_chunked:1;
	unsigned int payload_wait:1;
	unsigned int ssl:1;
	unsigned int urgent:1;
	unsigned int submitted:1;
};

struct http_client_host_port {
	struct http_client_host *host;

	unsigned int port;
	char *https_name;

	/* current index in host->ips */
	unsigned int ips_connect_idx;
	/* the first IP that started the current round of connection attempts.
	   initially 0, and later set to the ip index of the last successful
	   connected IP */
	unsigned int ips_connect_start_idx;
	/* number of connections trying to connect for this host+port */
	unsigned int pending_connection_count;

	/* requests pending in queue to be picked up by connections */
	ARRAY_TYPE(http_client_request) request_queue;

	struct timeout *to_connect;
};

struct http_client_host {
	struct http_client_host *prev, *next;

	struct http_client *client;
	char *name;

	/* the ip addresses DNS returned for this host */
	unsigned int ips_count;
	struct ip_addr *ips;

	/* list of requests in this host that are waiting for ioloop */
	ARRAY(struct http_client_request *) delayed_failing_requests;

	/* requests are managed on a per-port basis */
	ARRAY_TYPE(http_client_host_port) ports;

	/* active DNS lookup */
	struct dns_lookup *dns_lookup;
};

struct http_client_peer_addr {
	char *https_name; /* TLS SNI */
	struct ip_addr ip;
	unsigned int port;
};

struct http_client_peer {
	struct http_client_peer_addr addr;
	struct http_client *client;
	struct http_client_peer *prev, *next;

	/* hosts served through this peer */
	ARRAY_TYPE(http_client_host) hosts;

	/* active connections to this peer */
	ARRAY_TYPE(http_client_connection) conns;

	unsigned int destroyed:1;        /* peer is being destroyed */
	unsigned int no_payload_sync:1;  /* expect: 100-continue failed before */
	unsigned int seen_100_response:1;/* expect: 100-continue succeeded before */
	unsigned int last_connect_failed:1;
};

struct http_client_connection {
	struct connection conn;
	struct http_client_peer *peer;
	struct http_client *client;
	unsigned int refcount;

	const char *label;

	unsigned int id; // DEBUG: identify parallel connections
	int connect_errno;
	struct timeval connect_start_timestamp;
	struct timeval connected_timestamp;

	struct ssl_iostream *ssl_iostream;
	struct http_response_parser *http_parser;
	struct timeout *to_connect, *to_input, *to_idle, *to_response;
	struct timeout *to_requests;

	struct http_client_request *pending_request;
	struct istream *incoming_payload;

	/* requests that have been sent, waiting for response */
	ARRAY_TYPE(http_client_request) request_wait_list;

	unsigned int connected:1;           /* connection is connected */
	unsigned int connect_succeeded:1;
	unsigned int closing:1;
	unsigned int close_indicated:1;
	unsigned int output_locked:1;       /* output is locked; no pipelining */
	unsigned int payload_continue:1;    /* received 100-continue for current
	                                        request */
};

struct http_client {
	pool_t pool;

	struct http_client_settings set;

	struct ioloop *ioloop;
	struct ssl_iostream_context *ssl_ctx;

	struct connection_list *conn_list;

	HASH_TABLE_TYPE(http_client_host) hosts;
	struct http_client_host *hosts_list;
	HASH_TABLE_TYPE(http_client_peer) peers;
	struct http_client_peer *peers_list;
	unsigned int pending_requests;
};

static inline const char *
http_client_request_label(struct http_client_request *req)
{
	return t_strdup_printf("[%s http%s://%s:%d%s]",
		req->method, req->ssl ? "s" : "", req->hostname, req->port, req->target);
}

static inline const char *
http_client_connection_label(struct http_client_connection *conn)
{
	return t_strdup_printf("%s:%u [%d]",
		net_ip2addr(&conn->conn.ip), conn->conn.port, conn->id);
}

int http_client_init_ssl_ctx(struct http_client *client, const char **error_r);

void http_client_request_ref(struct http_client_request *req);
void http_client_request_unref(struct http_client_request **_req);
int http_client_request_send(struct http_client_request *req,
			     const char **error_r);
int http_client_request_send_more(struct http_client_request *req,
				  const char **error_r);
bool http_client_request_callback(struct http_client_request *req,
	struct http_response *response);
void http_client_request_resubmit(struct http_client_request *req);
void http_client_request_retry(struct http_client_request *req,
	unsigned int status, const char *error);
void http_client_request_error(struct http_client_request *req,
	unsigned int status, const char *error);
void http_client_request_redirect(struct http_client_request *req,
	unsigned int status, const char *location);
void http_client_request_finish(struct http_client_request **_req);

struct connection_list *http_client_connection_list_init(void);

struct http_client_connection *
	http_client_connection_create(struct http_client_peer *peer);
void http_client_connection_ref(struct http_client_connection *conn);
void http_client_connection_unref(struct http_client_connection **_conn);
unsigned int
http_client_connection_count_pending(struct http_client_connection *conn);
bool http_client_connection_is_ready(struct http_client_connection *conn);
bool http_client_connection_is_idle(struct http_client_connection *conn);
bool http_client_connection_next_request(struct http_client_connection *conn);
void http_client_connection_switch_ioloop(struct http_client_connection *conn);

unsigned int http_client_peer_addr_hash
	(const struct http_client_peer_addr *peer) ATTR_PURE;
int http_client_peer_addr_cmp
	(const struct http_client_peer_addr *peer1,
		const struct http_client_peer_addr *peer2) ATTR_PURE;

struct http_client_peer *
	http_client_peer_get(struct http_client *client,
		const struct http_client_peer_addr *addr);
void http_client_peer_free(struct http_client_peer **_peer);
bool http_client_peer_have_host(struct http_client_peer *peer,
				struct http_client_host *host);
void http_client_peer_add_host(struct http_client_peer *peer,
	struct http_client_host *host);
struct http_client_request *
	http_client_peer_claim_request(struct http_client_peer *peer,
		bool no_urgent);
bool http_client_peer_handle_requests(struct http_client_peer *peer);
void http_client_peer_connection_success(struct http_client_peer *peer);
void http_client_peer_connection_failure(struct http_client_peer *peer,
					 const char *reason);
void http_client_peer_connection_lost(struct http_client_peer *peer);
unsigned int http_client_peer_idle_connections(struct http_client_peer *peer);

struct http_client_host *
	http_client_host_get(struct http_client *client, const char *hostname);
void http_client_host_free(struct http_client_host **_host);
void http_client_host_submit_request(struct http_client_host *host,
	struct http_client_request *req);
struct http_client_request *
http_client_host_claim_request(struct http_client_host *host,
	const struct http_client_peer_addr *addr, bool no_urgent);
void http_client_host_connection_success(struct http_client_host *host,
	const struct http_client_peer_addr *addr);
void http_client_host_connection_failure(struct http_client_host *host,
	const struct http_client_peer_addr *addr, const char *reason);
unsigned int http_client_host_requests_pending(struct http_client_host *host,
	const struct http_client_peer_addr *addr, unsigned int *num_urgent_r);
void http_client_host_drop_request(struct http_client_host *host,
	struct http_client_request *req);
void http_client_host_switch_ioloop(struct http_client_host *host);

#endif
