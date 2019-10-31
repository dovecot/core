#ifndef HTTP_CLIENT_PRIVATE_H
#define HTTP_CLIENT_PRIVATE_H

#include "connection.h"

#include "http-url.h"
#include "http-client.h"

/*
 * Defaults
 */

#define HTTP_CLIENT_CONTINUE_TIMEOUT_MSECS (1000*2)
#define HTTP_CLIENT_DEFAULT_REQUEST_TIMEOUT_MSECS (1000*60*1)
#define HTTP_CLIENT_DEFAULT_DNS_LOOKUP_TIMEOUT_MSECS (1000*10)
#define HTTP_CLIENT_DEFAULT_BACKOFF_TIME_MSECS (100)
#define HTTP_CLIENT_DEFAULT_BACKOFF_MAX_TIME_MSECS (1000*60)
#define HTTP_CLIENT_DEFAULT_DNS_TTL_MSECS (1000*60*30)

/*
 * Types
 */

struct http_client_connection;
struct http_client_peer_pool;
struct http_client_peer_shared;
struct http_client_peer;
struct http_client_queue;
struct http_client_host_shared;
struct http_client_host;

ARRAY_DEFINE_TYPE(http_client_request,
	struct http_client_request *);
ARRAY_DEFINE_TYPE(http_client_connection,
	struct http_client_connection *);
ARRAY_DEFINE_TYPE(http_client_peer,
	struct http_client_peer *);
ARRAY_DEFINE_TYPE(http_client_peer_shared,
	struct http_client_peer_shared *);
ARRAY_DEFINE_TYPE(http_client_peer_pool,
	struct http_client_peer_pool *);
ARRAY_DEFINE_TYPE(http_client_queue,
	struct http_client_queue *);
ARRAY_DEFINE_TYPE(http_client_host,
	struct http_client_host_shared *);

HASH_TABLE_DEFINE_TYPE(http_client_peer_shared,
	const struct http_client_peer_addr *,
	struct http_client_peer_shared *);
HASH_TABLE_DEFINE_TYPE(http_client_host_shared,
	const char *, struct http_client_host_shared *);

enum http_client_peer_addr_type {
	HTTP_CLIENT_PEER_ADDR_HTTP = 0,
	HTTP_CLIENT_PEER_ADDR_HTTPS,
	HTTP_CLIENT_PEER_ADDR_HTTPS_TUNNEL,
	HTTP_CLIENT_PEER_ADDR_RAW,
	HTTP_CLIENT_PEER_ADDR_UNIX,
};

struct http_client_peer_addr {
	enum http_client_peer_addr_type type;
	union {
		struct {
			const char *https_name; /* TLS SNI */
			struct ip_addr ip;
			in_port_t port;
		} tcp;
		struct {
			const char *path;
		} un;
	} a;
};

/*
 * Objects
 */

struct http_client_request {
	pool_t pool;
	unsigned int refcount;
	const char *label;
	unsigned int id;

	struct http_client_request *prev, *next;

	const char *method, *target;
	struct http_url origin_url;
	const char *username, *password;

	const char *host_socket;
	const struct http_url *host_url;
	const char *authority;

	struct http_client *client;
	struct http_client_host *host;
	struct http_client_queue *queue;
	struct http_client_peer *peer;
	struct http_client_connection *conn;

	struct event *event;
	unsigned int last_status;

	string_t *headers;
	time_t date;

	struct istream *payload_input;
	uoff_t payload_size, payload_offset;
	struct ostream *payload_output;

	/* Time when request can be sent the next time. This is set by
	   http_client_request_delay*(). Default is 0 = immediately. Retries
	   can update this. */
	struct timeval release_time;
	/* Time when http_client_request_submit() was called. */
	struct timeval submit_time;
	/* Time when the request was first sent to the server. The HTTP
	   connection already exists at this time. */
	struct timeval first_sent_time;
	/* Time when the request was last sent to the server (if it was
	   retried). */
	struct timeval sent_time;
	/* Time when the HTTP response header was last received. */
	struct timeval response_time;
	/* Time when the request will be aborted. Set by
	   http_client_request_set_timeout(). */
	struct timeval timeout_time;
	unsigned int timeout_msecs;
	unsigned int attempt_timeout_msecs;
	unsigned int max_attempts;

	uoff_t response_offset, request_offset;
	uoff_t bytes_in, bytes_out;

	unsigned int attempts, send_attempts;
	unsigned int redirects;
	uint64_t sent_global_ioloop_usecs;
	uint64_t sent_http_ioloop_usecs;
	uint64_t sent_lock_usecs;

	unsigned int delayed_error_status;
	const char *delayed_error;

	http_client_request_callback_t *callback;
	void *context;

	void (*destroy_callback)(void *);
	void *destroy_context;

	enum http_request_state state;

	bool have_hdr_authorization:1;
	bool have_hdr_body_spec:1;
	bool have_hdr_connection:1;
	bool have_hdr_date:1;
	bool have_hdr_expect:1;
	bool have_hdr_host:1;
	bool have_hdr_user_agent:1;

	bool payload_sync:1;
	bool payload_sync_continue:1;
	bool payload_chunked:1;
	bool payload_wait:1;
	bool payload_empty:1;
	bool urgent:1;
	bool submitted:1;
	bool listed:1;
	bool connect_tunnel:1;
	bool connect_direct:1;
	bool ssl_tunnel:1;
	bool preserve_exact_reason:1;
};

struct http_client_connection {
	struct connection conn;
	struct event *event;
	unsigned int refcount;

	struct http_client_peer_pool *ppool;
	struct http_client_peer *peer;

	int connect_errno;
	struct timeval connect_start_timestamp;
	struct timeval connected_timestamp;
	struct http_client_request *connect_request;

	struct ssl_iostream *ssl_iostream;
	struct http_response_parser *http_parser;
	struct timeout *to_connect, *to_input, *to_idle, *to_response;
	struct timeout *to_requests;

	struct http_client_request *pending_request;
	struct istream *incoming_payload;
	struct io *io_req_payload;
	struct ioloop *last_ioloop;
	struct io_wait_timer *io_wait_timer;

	/* requests that have been sent, waiting for response */
	ARRAY_TYPE(http_client_request) request_wait_list;

	bool connected:1;           /* connection is connected */
	bool tunneling:1;           /* last sent request turns this
	                               connection into tunnel */
	bool connect_succeeded:1;   /* connection succeeded including SSL */
	bool connect_failed:1;      /* connection failed */
	bool lost_prematurely:1;    /* lost connection before receiving any data */
	bool closing:1;
	bool disconnected:1;
	bool close_indicated:1;
	bool output_locked:1;       /* output is locked; no pipelining */
	bool output_broken:1;       /* output is broken; no more requests */
	bool in_req_callback:1;     /* performing request callback (busy) */
	bool debug:1;
};

struct http_client_peer_shared {
	unsigned int refcount;
	struct http_client_peer_addr addr;
	char *addr_name;
	struct event *event;

	char *label;

	struct http_client_context *cctx;
	struct http_client_peer_shared *prev, *next;

	struct http_client_peer_pool *pools_list;

	struct http_client_peer *peers_list;
	unsigned int peers_count;

	/* connection retry */
	struct timeval last_failure;
	struct timeout *to_backoff;
	unsigned int backoff_initial_time_msecs;
	unsigned int backoff_current_time_msecs;
	unsigned int backoff_max_time_msecs;

	bool no_payload_sync:1;  /* expect: 100-continue failed before */
	bool seen_100_response:1;/* expect: 100-continue succeeded before */
	bool allows_pipelining:1;/* peer is known to allow persistent
	                            connections */
};

struct http_client_peer_pool {
	unsigned int refcount;
	struct http_client_peer_shared *peer;
	struct http_client_peer_pool *prev, *next;
	struct event *event;

	/* all connections to this peer */
	ARRAY_TYPE(http_client_connection) conns;

	/* pending connections (not ready connecting) */
	ARRAY_TYPE(http_client_connection) pending_conns;

	/* available connections to this peer */
	ARRAY_TYPE(http_client_connection) idle_conns;

	/* distinguishing settings for these connections */
	struct ssl_iostream_context *ssl_ctx;
	char *rawlog_dir;
	struct pcap_output *pcap_output;

	bool destroyed:1;        /* peer pool is being destroyed */
};

struct http_client_peer {
	unsigned int refcount;
	struct http_client_peer_shared *shared;
	struct http_client_peer *shared_prev, *shared_next;

	struct http_client *client;
	struct http_client_peer *client_prev, *client_next;

	struct http_client_peer_pool *ppool;
	struct event *event;

	/* queues using this peer */
	ARRAY_TYPE(http_client_queue) queues;

	/* active connections to this peer */
	ARRAY_TYPE(http_client_connection) conns;
	/* pending connections (not ready connecting) */
	ARRAY_TYPE(http_client_connection) pending_conns;

	/* zero time-out for consolidating request handling */
	struct timeout *to_req_handling;

	bool connect_failed:1;   /* last connection attempt failed */
	bool connect_backoff:1;  /* peer is waiting for backoff timout*/
	bool disconnected:1;     /* peer is already disconnected */
	bool handling_requests:1;/* currently running request handler */
};

struct http_client_queue {
	struct http_client *client;
	struct http_client_queue *prev, *next;

	struct http_client_host *host;
	char *name;
	struct event *event;

	struct http_client_peer_addr addr;
	char *addr_name;

	/* current index in host->ips */
	unsigned int ips_connect_idx;
	/* the first IP that started the current round of connection attempts.
	   initially 0, and later set to the ip index of the last successful
	   connected IP */
	unsigned int ips_connect_start_idx;

	struct timeval first_connect_time;
	unsigned int connect_attempts;

	/* peers we are trying to connect to;
	   this can be more than one when soft connect timeouts are enabled */
	ARRAY_TYPE(http_client_peer) pending_peers;

	/* currently active peer */
	struct http_client_peer *cur_peer;

	/* all requests associated to this queue
	   (ordered by earliest timeout first) */
	ARRAY_TYPE(http_client_request) requests; 

	/* delayed requests waiting to be released after delay */
	ARRAY_TYPE(http_client_request) delayed_requests;

	/* requests pending in queue to be picked up by connections */
	ARRAY_TYPE(http_client_request) queued_requests, queued_urgent_requests;

	struct timeout *to_connect, *to_request, *to_delayed;
};

struct http_client_host_shared {
	struct http_client_host_shared *prev, *next;

	struct http_client_context *cctx;
	char *name;
	struct event *event;

	/* the ip addresses DNS returned for this host */
	unsigned int ips_count;
	struct ip_addr *ips;
	struct timeval ips_timeout;

	/* private instance for each client that uses this host */
	struct http_client_host *hosts_list;

	/* active DNS lookup */
	struct dns_lookup *dns_lookup;

	/* timeouts */
	struct timeout *to_idle;

	bool destroyed:1;	/* shared host object is being destroyed */
	bool unix_local:1;
	bool explicit_ip:1;
};

struct http_client_host {
	struct http_client_host_shared *shared;
	struct http_client_host *shared_prev, *shared_next;

	struct http_client *client;
	struct http_client_host *client_prev, *client_next;

	/* separate queue for each host port */
	ARRAY_TYPE(http_client_queue) queues;
};

struct http_client {
	pool_t pool;
	struct http_client_context *cctx;
	struct http_client_settings set;

	struct http_client *prev, *next;

	struct event *event;
	struct ioloop *ioloop;
	struct ssl_iostream_context *ssl_ctx;

	/* list of failed requests that are waiting for ioloop */
	ARRAY(struct http_client_request *) delayed_failing_requests;
	struct timeout *to_failing_requests;

	struct http_client_host *hosts_list;
	struct http_client_peer *peers_list;

	struct http_client_request *requests_list;
	unsigned int requests_count;

	bool waiting:1;
};

struct http_client_context {
	pool_t pool;
	unsigned int refcount;
	struct event *event;
	struct ioloop *ioloop;

	struct http_client_settings set;

	struct dns_client *dns_client;
	const char *dns_client_socket_path;
	unsigned int dns_ttl_msecs;
	unsigned int dns_lookup_timeout_msecs;

	struct http_client *clients_list;
	struct connection_list *conn_list;

	HASH_TABLE_TYPE(http_client_peer_shared) peers;
	struct http_client_peer_shared *peers_list;
	HASH_TABLE_TYPE(http_client_host_shared) hosts;
	struct http_client_host_shared *unix_host;
	struct http_client_host_shared *hosts_list;
};

/*
 * Peer address
 */

static inline bool
http_client_peer_addr_is_https(const struct http_client_peer_addr *addr)
{
	switch (addr->type) {
	case HTTP_CLIENT_PEER_ADDR_HTTPS:
	case HTTP_CLIENT_PEER_ADDR_HTTPS_TUNNEL:
		return TRUE;
	default:
		break;
	}
	return FALSE;
}

static inline const char *
http_client_peer_addr_get_https_name(const struct http_client_peer_addr *addr)
{
	switch (addr->type) {
	case HTTP_CLIENT_PEER_ADDR_HTTPS:
	case HTTP_CLIENT_PEER_ADDR_HTTPS_TUNNEL:
		return addr->a.tcp.https_name;
	default:
		break;
	}
	return NULL;
}

static inline const char *
http_client_peer_addr2str(const struct http_client_peer_addr *addr)
{
	switch (addr->type) {
	case HTTP_CLIENT_PEER_ADDR_HTTP:
	case HTTP_CLIENT_PEER_ADDR_HTTPS:
	case HTTP_CLIENT_PEER_ADDR_HTTPS_TUNNEL:
	case HTTP_CLIENT_PEER_ADDR_RAW:
		if (addr->a.tcp.ip.family == AF_INET6) {
			return t_strdup_printf("[%s]:%u",
				net_ip2addr(&addr->a.tcp.ip), addr->a.tcp.port);
		}
		return t_strdup_printf("%s:%u",
			net_ip2addr(&addr->a.tcp.ip), addr->a.tcp.port);
	case HTTP_CLIENT_PEER_ADDR_UNIX:
		return t_strdup_printf("unix:%s", addr->a.un.path);
	default:
		break;
	}
	i_unreached();
	return "";
}

/*
 * Request
 */

static inline bool
http_client_request_to_proxy(const struct http_client_request *req)
{
	return (req->host_url != &req->origin_url);
}

const char *
http_client_request_label(struct http_client_request *req);

void http_client_request_ref(struct http_client_request *req);
/* Returns FALSE if unrefing destroyed the request entirely */
bool http_client_request_unref(struct http_client_request **_req);
void http_client_request_destroy(struct http_client_request **_req);

void http_client_request_get_peer_addr(const struct http_client_request *req,
	struct http_client_peer_addr *addr);
enum http_response_payload_type
http_client_request_get_payload_type(struct http_client_request *req);
int http_client_request_send(struct http_client_request *req,
			    bool pipelined);
int http_client_request_send_more(struct http_client_request *req,
				  bool pipelined);
bool http_client_request_callback(struct http_client_request *req,
	struct http_response *response);
void http_client_request_connect_callback(struct http_client_request *req,
			     const struct http_client_tunnel *tunnel,
			     struct http_response *response);
void http_client_request_resubmit(struct http_client_request *req);
void http_client_request_retry(struct http_client_request *req,
	unsigned int status, const char *error);
void http_client_request_error_delayed(struct http_client_request **_req);
void http_client_request_error(struct http_client_request **req,
	unsigned int status, const char *error);
void http_client_request_redirect(struct http_client_request *req,
	unsigned int status, const char *location);
void http_client_request_finish(struct http_client_request *req);

/*
 * Connection
 */

struct connection_list *http_client_connection_list_init(void);

struct http_client_connection *
http_client_connection_create(struct http_client_peer *peer);
void http_client_connection_ref(struct http_client_connection *conn);
/* Returns FALSE if unrefing destroyed the connection entirely */
bool http_client_connection_unref(struct http_client_connection **_conn);
void http_client_connection_close(struct http_client_connection **_conn);

void http_client_connection_lost(struct http_client_connection **_conn,
				 const char *error) ATTR_NULL(2);

void http_client_connection_peer_closed(struct http_client_connection **_conn);
void http_client_connection_request_destroyed(
	struct http_client_connection *conn, struct http_client_request *req);

void http_client_connection_handle_output_error(
	struct http_client_connection *conn);
int http_client_connection_output(struct http_client_connection *conn);
void http_client_connection_start_request_timeout(
	struct http_client_connection *conn);
void http_client_connection_reset_request_timeout(
	struct http_client_connection *conn);
void http_client_connection_stop_request_timeout(
	struct http_client_connection *conn);
unsigned int
http_client_connection_count_pending(struct http_client_connection *conn);
int http_client_connection_check_ready(struct http_client_connection *conn);
bool http_client_connection_is_idle(struct http_client_connection *conn);
bool http_client_connection_is_active(struct http_client_connection *conn);
int http_client_connection_next_request(struct http_client_connection *conn);
void http_client_connection_check_idle(struct http_client_connection *conn);
void http_client_connection_switch_ioloop(struct http_client_connection *conn);
void http_client_connection_start_tunnel(struct http_client_connection **_conn,
	struct http_client_tunnel *tunnel);
void http_client_connection_lost_peer(struct http_client_connection *conn);
void http_client_connection_claim_idle(struct http_client_connection *conn,
	struct http_client_peer *peer);

/*
 * Peer
 */

/* address */

unsigned int http_client_peer_addr_hash
	(const struct http_client_peer_addr *peer) ATTR_PURE;
int http_client_peer_addr_cmp
	(const struct http_client_peer_addr *peer1,
		const struct http_client_peer_addr *peer2) ATTR_PURE;

/* connection pool */

void http_client_peer_pool_ref(struct http_client_peer_pool *ppool);
void http_client_peer_pool_unref(struct http_client_peer_pool **_ppool);

void http_client_peer_pool_close(struct http_client_peer_pool **_ppool);

/* peer (shared) */

const char *
http_client_peer_shared_label(struct http_client_peer_shared *pshared);

void http_client_peer_shared_ref(struct http_client_peer_shared *pshared);
void http_client_peer_shared_unref(struct http_client_peer_shared **_pshared);
void http_client_peer_shared_close(struct http_client_peer_shared **_pshared);

void http_client_peer_shared_switch_ioloop(struct http_client_peer_shared *pshared);

unsigned int
http_client_peer_shared_max_connections(struct http_client_peer_shared *pshared);

/* peer */

struct http_client_peer *
http_client_peer_get(struct http_client *client,
	const struct http_client_peer_addr *addr);
void http_client_peer_ref(struct http_client_peer *peer);
bool http_client_peer_unref(struct http_client_peer **_peer);
void http_client_peer_close(struct http_client_peer **_peer);

bool http_client_peer_have_queue(struct http_client_peer *peer,
				struct http_client_queue *queue);
void http_client_peer_link_queue(struct http_client_peer *peer,
	struct http_client_queue *queue);
void http_client_peer_unlink_queue(struct http_client_peer *peer,
				struct http_client_queue *queue);
struct http_client_request *
	http_client_peer_claim_request(struct http_client_peer *peer,
		bool no_urgent);
void http_client_peer_trigger_request_handler(struct http_client_peer *peer);
void http_client_peer_connection_success(struct http_client_peer *peer);
void http_client_peer_connection_failure(struct http_client_peer *peer,
					 const char *reason);
void http_client_peer_connection_lost(struct http_client_peer *peer,
	bool premature);
bool http_client_peer_is_connected(struct http_client_peer *peer);
unsigned int
http_client_peer_idle_connections(struct http_client_peer *peer);
unsigned int
http_client_peer_active_connections(struct http_client_peer *peer);
unsigned int
http_client_peer_pending_connections(struct http_client_peer *peer);
void http_client_peer_switch_ioloop(struct http_client_peer *peer);

/*
 * Queue
 */

struct http_client_queue *
http_client_queue_get(struct http_client_host *host,
	const struct http_client_peer_addr *addr);
void http_client_queue_free(struct http_client_queue *queue);
void http_client_queue_connection_setup(struct http_client_queue *queue);
unsigned int
http_client_queue_host_lookup_done(struct http_client_queue *queue);
void http_client_queue_host_lookup_failure(
	struct http_client_queue *queue, const char *error);
void http_client_queue_submit_request(struct http_client_queue *queue,
	struct http_client_request *req);
void http_client_queue_drop_request(struct http_client_queue *queue,
	struct http_client_request *req);
struct http_client_request *
http_client_queue_claim_request(struct http_client_queue *queue,
	const struct http_client_peer_addr *addr, bool no_urgent);
unsigned int
http_client_queue_requests_pending(struct http_client_queue *queue,
	unsigned int *num_urgent_r) ATTR_NULL(2);
unsigned int
http_client_queue_requests_active(struct http_client_queue *queue);
void http_client_queue_connection_success(struct http_client_queue *queue,
					 struct http_client_peer *peer);
void http_client_queue_connection_failure(struct http_client_queue *queue,
		struct http_client_peer *peer, const char *reason);
void http_client_queue_peer_disconnected(struct http_client_queue *queue,
	struct http_client_peer *peer);
void http_client_queue_switch_ioloop(struct http_client_queue *queue);

/*
 * Host
 */

/* host (shared) */

void http_client_host_shared_free(
	struct http_client_host_shared **_hshared);
void http_client_host_shared_switch_ioloop(
	struct http_client_host_shared *hshared);

/* host */

static inline unsigned int
http_client_host_get_ips_count(struct http_client_host *host)
{
	return host->shared->ips_count;
}

static inline const struct ip_addr *
http_client_host_get_ip(struct http_client_host *host,
	unsigned int idx)
{
	i_assert(idx < host->shared->ips_count);
	return &host->shared->ips[idx];
}

static inline bool
http_client_host_ready(struct http_client_host *host)
{
	return host->shared->dns_lookup == NULL;
}

struct http_client_host *
http_client_host_get(struct http_client *client,
	const struct http_url *host_url);
void http_client_host_free(struct http_client_host **_host);
void http_client_host_submit_request(struct http_client_host *host,
	struct http_client_request *req);
void http_client_host_switch_ioloop(struct http_client_host *host);
void http_client_host_check_idle(struct http_client_host *host);
int http_client_host_refresh(struct http_client_host *host);
bool http_client_host_get_ip_idx(struct http_client_host *host,
	const struct ip_addr *ip, unsigned int *idx_r);

/*
 * Client
 */

int http_client_init_ssl_ctx(struct http_client *client,
	const char **error_r);

void http_client_delay_request_error(struct http_client *client,
	struct http_client_request *req);
void http_client_remove_request_error(struct http_client *client,
	struct http_client_request *req);

/*
 * Client shared context
 */

void http_client_context_switch_ioloop(struct http_client_context *cctx);

#endif
