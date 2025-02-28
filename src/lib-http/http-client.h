#ifndef HTTP_CLIENT_H
#define HTTP_CLIENT_H

#include "net.h"

#include "http-common.h"
#include "http-response.h"

struct timeval;
struct http_response;

struct http_client_request;
struct http_client;
struct http_client_context;

struct dns_client;
struct ssl_iostream_settings;

/*
 * Client settings
 */

struct http_client_settings {
	pool_t pool;
	/* a) If http_client_set_dns_client() is used, all lookups are done
	   via it.
	   b) If dns_client_socket_path is set, each DNS lookup does its own
	   dns-lookup UNIX socket connection.
	   c) Otherwise, blocking gethostbyname() lookups are used. */
	const char *dns_client_socket_path;
	/* A copy of base_dir setting. FIXME: this should not be here. */
	const char *base_dir;
	/* How long to cache DNS records internally
	   (default = HTTP_CLIENT_DEFAULT_DNS_TTL_MSECS) */
	unsigned int dns_ttl_msecs;

	/* User-Agent: header (default: none) */
	const char *user_agent;

	/* Proxy on unix socket */
	const char *proxy_socket_path;
	/* URL for normal proxy (ignored if proxy_socket_path is set) */
	const char *proxy_url;
	/* Credentials for proxy */
	const char *proxy_username;
	const char *proxy_password;

	/* Directory for writing raw log data for debugging purposes */
	const char *rawlog_dir;

	/* Maximum time a connection will idle. if parallel connections are
	   idle, the duplicates will end earlier based on how many idle
	   connections exist to that same service. */
	unsigned int max_idle_time_msecs;

	/* Maximum number of parallel connections per peer (default = 1) */
	unsigned int max_parallel_connections;

	/* Maximum number of pipelined requests per connection (default = 1) */
	unsigned int max_pipelined_requests;

	/* FALSE = Don't automatically act upon redirect responses. The
	   redirects are returned as a regular response. TRUE = Handle
	   redirects as long as request_max_redirects isn't reached. */
	bool auto_redirect;

	/* FALSE = Never automatically retry requests. Explicit
	   http_client_request_try_retry() calls can still retry requests
	   as long as request_max_attempts isn't reached. */
	bool auto_retry;

	/* FALSE = If we use a proxy, delegate SSL negotiation to proxy, rather
	   than creating a CONNECT tunnel through the proxy for the SSL link */
	bool proxy_ssl_tunnel;

	/* Maximum number of redirects for a request
	   (default = 0; redirects result in
	   HTTP_CLIENT_REQUEST_ERROR_INVALID_REDIRECT)
	 */
	unsigned int request_max_redirects;

	/* Maximum number of attempts for a request. 0 means the same as 1. */
	unsigned int request_max_attempts;
	/* If non-zero, override max_attempts for GET/HEAD requests. */
	unsigned int read_request_max_attempts;
	/* If non-zero, override max_attempts for PUT/POST requests. */
	unsigned int write_request_max_attempts;
	/* If non-zero, override max_attempts for DELETE requests. */
	unsigned int delete_request_max_attempts;

	/* Maximum number of connection attempts to a host before all associated
	   requests fail.

	   if > 0, the maximum will be enforced across all IPs for that host,
	   meaning that IPs may be tried more than once eventually if the number
	   of IPs is smaller than the specified maximum attempts. If the number
	   of IPs is higher than the maximum attempts, not all IPs are tried.
	   If 0, all IPs are tried at most once.
	 */
	unsigned int max_connect_attempts;

	/* Initial backoff time; doubled at each connection failure
	   (default = HTTP_CLIENT_DEFAULT_BACKOFF_TIME_MSECS) */
	unsigned int connect_backoff_time_msecs;
	/* Maximum backoff time
	   (default = HTTP_CLIENT_DEFAULT_BACKOFF_MAX_TIME_MSECS) */
	unsigned int connect_backoff_max_time_msecs;

	/* Response header limits */
	uoff_t response_hdr_max_size;
	uoff_t response_hdr_max_field_size;
	unsigned int response_hdr_max_fields;

	/* Max total time to wait for HTTP request to finish this can be
	   overridden/reset for individual requests using
	   http_client_request_set_timeout() and friends.
	   (default is no timeout)
	 */
	unsigned int request_absolute_timeout_msecs;
	/* Max time to wait for HTTP request to finish before retrying.
	   (default = HTTP_CLIENT_DEFAULT_REQUEST_TIMEOUT_MSECS) */
	unsigned int request_timeout_msecs;
	/* If non-zero, override request_timeout for GET/HEAD requests. */
	unsigned int read_request_timeout_msecs;
	/* If non-zero, override request_timeout for PUT/POST requests. */
	unsigned int write_request_timeout_msecs;
	/* If non-zero, override request_timeout for DELETE requests. */
	unsigned int delete_request_timeout_msecs;
	/* Max time to wait for connect() (and SSL handshake) to finish before
	   retrying. (default = request_timeout_msecs) */
	unsigned int connect_timeout_msecs;
	/* Time to wait for connect() (and SSL handshake) to finish for the
	   first connection before trying the next IP in parallel.
	   (default = 0; wait until current connection attempt finishes) */
	unsigned int soft_connect_timeout_msecs;

	/* Maximum acceptable delay in seconds for automatically
	   retrying/redirecting requests. If a server sends a response with a
	   Retry-After header that causes a delay longer than this, the request
	   is not automatically retried and the response is returned */
	unsigned int max_auto_retry_delay_secs;

	/* The kernel send/receive buffer sizes used for the connection sockets.
	   Configuring this is mainly useful for the test suite. The kernel
	   defaults are used when these settings are 0. */
	uoff_t socket_send_buffer_size;
	uoff_t socket_recv_buffer_size;

	/* generated: */
	struct http_url *parsed_proxy_url;
};

extern const struct setting_parser_info http_client_setting_parser_info;

/*
 * Request
 */

enum http_client_request_error {
	/* The request was aborted. */
	HTTP_CLIENT_REQUEST_ERROR_ABORTED = HTTP_RESPONSE_STATUS_INTERNAL,
	/* Failed to parse HTTP target url. */
	HTTP_CLIENT_REQUEST_ERROR_INVALID_URL,
	/* Failed to perform DNS lookup for the host. */
	HTTP_CLIENT_REQUEST_ERROR_HOST_LOOKUP_FAILED,
	/* Failed to setup any connection for the host and client settings
	   allowed no more attempts. */
	HTTP_CLIENT_REQUEST_ERROR_CONNECT_FAILED,
	/* Service returned an invalid redirect response for this request */
	HTTP_CLIENT_REQUEST_ERROR_INVALID_REDIRECT,
	/* The connection was lost unexpectedly while handling the request and
	   client settings allowed no more attempts */
	HTTP_CLIENT_REQUEST_ERROR_CONNECTION_LOST,
	/* The input stream passed to the request using
	   http_client_request_set_payload() returned an error while sending the
	   request. */
	HTTP_CLIENT_REQUEST_ERROR_BROKEN_PAYLOAD,
	/* The service returned a bad response. */
	HTTP_CLIENT_REQUEST_ERROR_BAD_RESPONSE,
	/* The request timed out (either this was the last attempt or the
	   absolute timeout was hit) */
	HTTP_CLIENT_REQUEST_ERROR_TIMED_OUT,
};

enum http_request_state {
	/* New request; not yet submitted */
	HTTP_REQUEST_STATE_NEW = 0,
	/* Request is queued; waiting for a connection */
	HTTP_REQUEST_STATE_QUEUED,
	/* Request header is sent; still sending request payload to server */
	HTTP_REQUEST_STATE_PAYLOAD_OUT,
	/* Request is fully sent; waiting for response */
	HTTP_REQUEST_STATE_WAITING,
	/* Response header is received for the request */
	HTTP_REQUEST_STATE_GOT_RESPONSE,
	/* Reading response payload; response handler still needs to read more
	   payload. */
	HTTP_REQUEST_STATE_PAYLOAD_IN,
	/* Request is finished; still lingering due to references */
	HTTP_REQUEST_STATE_FINISHED,
	/* Request is aborted; still lingering due to references */
	HTTP_REQUEST_STATE_ABORTED
};
extern const char *http_request_state_names[];

struct http_client_tunnel {
	int fd_in, fd_out;
	struct istream *input;
	struct ostream *output;
};

struct http_client_request_stats {
	/* Total elapsed time since message was submitted */
	unsigned int total_msecs;
	/* Elapsed time since message was first sent */
	unsigned int first_sent_msecs;
	/* Elapsed time since message was last sent */
	unsigned int last_sent_msecs;

	/* Time spent in other ioloops */
	unsigned int other_ioloop_msecs;
	/* Time spent in the http-client's own ioloop */
	unsigned int http_ioloop_msecs;
	/* Total time spent on waiting for file locks */
	unsigned int lock_msecs;

	/* Number of times this request was retried */
	unsigned int attempts;
	/* Number of times the client attempted to actually send the request
	   to a server */
	unsigned int send_attempts;
};

typedef void
http_client_request_callback_t(const struct http_response *response,
			       void *context);

/* Create new HTTP request */
struct http_client_request *
http_client_request(struct http_client *client,
		    const char *method, const char *host, const char *target,
		    http_client_request_callback_t *callback, void *context);
#define http_client_request(client, method, host, target, callback, context) \
	http_client_request(client, method, host, target - \
		CALLBACK_TYPECHECK(callback, void (*)( \
			const struct http_response *response, \
			typeof(context))), \
		(http_client_request_callback_t *)callback, context)

/* Create new HTTP request using provided URL. This implicitly sets port, ssl,
   and username:password if provided. */
struct http_client_request *
http_client_request_url(struct http_client *client, const char *method,
			const struct http_url *target_url,
			http_client_request_callback_t *callback,
			void *context);
#define http_client_request_url(client, method, target_url, callback, context) \
	http_client_request_url(client, method, target_url - \
		CALLBACK_TYPECHECK(callback, void (*)( \
			const struct http_response *response, \
			typeof(context))), \
		(http_client_request_callback_t *)callback, context)
struct http_client_request *
http_client_request_url_str(struct http_client *client, const char *method,
			    const char *url_str,
			    http_client_request_callback_t *callback,
			    void *context);
#define http_client_request_url_str(client, method, url_str, \
				    callback, context) \
	http_client_request_url_str(client, method, url_str - \
		CALLBACK_TYPECHECK(callback, void (*)( \
			const struct http_response *response, \
			typeof(context))), \
		(http_client_request_callback_t *)callback, context)

/* Create new HTTP CONNECT request. If this HTTP is configured to use a proxy,
   a CONNECT request will be submitted at that proxy, otherwise the connection
   is created directly. Call http_client_request_start_tunnel() to
   to take over the connection.
 */
struct http_client_request *
http_client_request_connect(struct http_client *client,
			    const char *host, in_port_t port,
			    http_client_request_callback_t *callback,
			    void *context);
#define http_client_request_connect(client, host, port, callback, context) \
	http_client_request_connect(client, host, port - \
		CALLBACK_TYPECHECK(callback, void (*)( \
			const struct http_response *response, \
			typeof(context))), \
		(http_client_request_callback_t *)callback, context)

/* Same as http_client_request_connect, but uses an IP rather than a host
   name. */
struct http_client_request *
http_client_request_connect_ip(struct http_client *client,
			       const struct ip_addr *ip, in_port_t port,
			       http_client_request_callback_t *callback,
			       void *context);
#define http_client_request_connect_ip(client, ip, port, callback, context) \
	http_client_request_connect_ip(client, ip, port - \
		CALLBACK_TYPECHECK(callback, void (*)( \
			const struct http_response *response, \
			typeof(context))), \
		(http_client_request_callback_t *)callback, context)

void http_client_request_set_event(struct http_client_request *req,
				   struct event *event);
/* set the port for the service the request is directed at */
void http_client_request_set_port(struct http_client_request *req,
				  in_port_t port);
/* Indicate whether service the request is directed at uses ssl */
void http_client_request_set_ssl(struct http_client_request *req, bool ssl);
/* Set the urgent flag: this means that this request will get priority over
   non-urgent request. Also, if no idle connection is available, a new
   connection is created. Urgent requests are never pipelined. */
void http_client_request_set_urgent(struct http_client_request *req);
void http_client_request_set_preserve_exact_reason(
	struct http_client_request *req);

/* Add a custom header to the request. This can override headers that are
   otherwise created implicitly. If the same header key was already added, the
   value is replaced. */
void http_client_request_add_header(struct http_client_request *req,
				    const char *key, const char *value);
/* Add a custom header to the request. Do nothing if it was already added. */
void http_client_request_add_missing_header(struct http_client_request *req,
					    const char *key, const char *value);
/* Remove a header added earlier. This has no influence on implicitly created
   headers. */
void http_client_request_remove_header(struct http_client_request *req,
				       const char *key);
/* Lookup the value for a header added earlier. Returns NULL if not found. */
const char *http_client_request_lookup_header(struct http_client_request *req,
					      const char *key);

/* Retrieve the full header string of a request. */
const char *http_client_request_retrieve_headers(struct http_client_request *req);

/* Set the value of the "Date" header for the request using a time_t value.
   Use this instead of setting it directly using
   http_client_request_add_header() */
void http_client_request_set_date(struct http_client_request *req, time_t date);

/* Assign an input stream for the outgoing payload of this request. The input
   stream is read asynchronously while the request is sent to the server.

   when sync=TRUE a "100 Continue" response is requested from the service. The
   client will then postpone sending the payload until a provisional response
   with code 100 is received. This way, an error response can be sent by the
   service before any potentially big payload is transmitted. Use this only for
   payload that can be large. */
void http_client_request_set_payload(struct http_client_request *req,
				     struct istream *input, bool sync);
/* Assign payload data to the request. The data is copied to the request pool.
   If your data is already durably allocated during the existence of the
   request, you should consider using http_client_request_set_payload() with
   a data input stream instead. This will avoid copying the data unnecessarily.
 */
void http_client_request_set_payload_data(struct http_client_request *req,
					  const unsigned char *data,
					  size_t size);
/* Send an empty payload for this request. This means that a Content-Length
   header is generated with zero size. Calling this function is not necessary
   for the standard POST and PUT methods, for which this is done implicitly if
   there is no payload set. */
void http_client_request_set_payload_empty(struct http_client_request *req);

/* Set an absolute timeout for this request specifically, overriding the
   default client-wide absolute request timeout */
void http_client_request_set_timeout_msecs(struct http_client_request *req,
					   unsigned int msecs);
void http_client_request_set_timeout(struct http_client_request *req,
				     const struct timeval *time);

/* Override http_client_settings.request_timeout_msecs */
void http_client_request_set_attempt_timeout_msecs(
	struct http_client_request *req, unsigned int msecs);
/* Override http_client_settings.max_attempts */
void http_client_request_set_max_attempts(struct http_client_request *req,
					  unsigned int max_attempts);

/* Include the specified HTTP response headers in the http_request_finished
   event parameters with "http_hdr_" prefix. */
void http_client_request_set_event_headers(struct http_client_request *req,
					   const char *const *headers);

/* Set the username:password credentials for this request for simple
   authentication. This function is meant for simple schemes that use a
   password. More complex schemes will need to be handled manually.

   This currently only supports the "basic" authentication scheme. */
void http_client_request_set_auth_simple(struct http_client_request *req,
					 const char *username,
					 const char *password);

/* Assign a proxy to use for this particular request. This overrides any
   proxy defined in the client settings. */
void http_client_request_set_proxy_url(struct http_client_request *req,
				       const struct http_url *proxy_url);
/* Like http_client_request_set_proxy_url(), but the proxy is behind a unix
   socket. */
void http_client_request_set_proxy_socket(struct http_client_request *req,
					  const char *proxy_socket);

/* Delay handling of this request to a later time. This way, a request can be
   submitted that is held for some time until a certain time period has passed.
 */
void http_client_request_delay_until(struct http_client_request *req,
				     time_t time);
void http_client_request_delay(struct http_client_request *req, time_t seconds);
void http_client_request_delay_msecs(struct http_client_request *req,
				     unsigned int msecs);

/* Try to set request delay based on the Retry-After header. Returns 1 if
   successful, 0 if it doesn't exist or is already expired, -1 if the delay
   would be too long. */
int http_client_request_delay_from_response(
	struct http_client_request *req, const struct http_response *response);

/* Return the HTTP method for the request */
const char *
http_client_request_get_method(const struct http_client_request *req) ATTR_PURE;
/* Return the HTTP target for the request */
const char *
http_client_request_get_target(const struct http_client_request *req) ATTR_PURE;
/* Return the request state */
enum http_request_state
http_client_request_get_state(const struct http_client_request *req) ATTR_PURE;
/* Return number of retry attempts */
unsigned int
http_client_request_get_attempts(const struct http_client_request *req)
				 ATTR_PURE;
/* Return origin_url */
const struct http_url *
http_client_request_get_origin_url(const struct http_client_request *req)
				   ATTR_PURE;

/* Get statistics for the request */
void http_client_request_get_stats(struct http_client_request *req,
				   struct http_client_request_stats *stats);
/* Append text with request statistics to provided string buffer */
void http_client_request_append_stats_text(struct http_client_request *req,
					   string_t *str);

/* Submit the request. It is queued for transmission to the service */
void http_client_request_submit(struct http_client_request *req);

/* Attempt to retry the request. This function is called within the request
   callback. It returns false if the request cannot be retried */
bool http_client_request_try_retry(struct http_client_request *req);

/* Fail the request. This can also be used instead of submitting the request to
   cause the request callback to be called later on with the specified error. */
void http_client_request_error(struct http_client_request **req,
			       unsigned int status, const char *error);
/* Abort the request immediately. It may still linger for a while when it is
   already sent to the service, but the callback will not be called anymore. */
void http_client_request_abort(struct http_client_request **req);

/* Call the specified callback when HTTP request is destroyed. */
void http_client_request_set_destroy_callback(struct http_client_request *req,
					      void (*callback)(void *),
					      void *context);
#define http_client_request_set_destroy_callback(req, callback, context) \
        http_client_request_set_destroy_callback(req, \
		(void(*)(void*))callback, \
			TRUE ? context : \
			CALLBACK_TYPECHECK(callback, void (*)(typeof(context))))

/* Submits request and blocks until the provided payload is sent. Multiple
   calls are allowed; payload transmission is ended with
   http_client_request_finish_payload(). If the sending fails, returns -1
   and sets req=NULL to indicate that the request was freed, otherwise
   returns 0 and req is unchanged. */
int http_client_request_send_payload(struct http_client_request **req,
				     const unsigned char *data, size_t size);
/* Finish sending the payload. Always frees req and sets it to NULL.
   Returns 0 on success, -1 on error. */
int http_client_request_finish_payload(struct http_client_request **req);

/* Take over the connection this request was sent over for use as a HTTP
   CONNECT tunnel. This only applies to requests that were created using
   http_client_request_connect() or http_client_request_connect_ip(). */
void http_client_request_start_tunnel(struct http_client_request *req,
				      struct http_client_tunnel *tunnel);

/*
 * Client
 */

/* Initialize settings with defaults. Must be used if settings struct is
   filled manually. */
void http_client_settings_init(pool_t pool, struct http_client_settings *set_r);
/* Create a client using the global shared client context. The parent event can
   be overridden for specific requests with http_client_request_set_event(). */
struct http_client *http_client_init(const struct http_client_settings *set,
				     struct event *event_parent);
/* Same as http_client_init(), but pull settings automatically. */
int http_client_init_auto(struct event *event_parent,
			  struct http_client **client_r, const char **error_r);
/* Create a client without a shared context. */
struct http_client *
http_client_init_private(const struct http_client_settings *set,
			 struct event *event_parent);
/* Same as http_client_init_private(), but pull settings automatically. */
int http_client_init_private_auto(struct event *event_parent,
				  struct http_client **client_r,
				  const char **error_r);
struct http_client *
http_client_init_shared(struct http_client_context *cctx,
			const struct http_client_settings *set,
			struct event *event_parent) ATTR_NULL(1);
void http_client_deinit(struct http_client **_client);

/* Switch this client to the current ioloop */
struct ioloop *http_client_switch_ioloop(struct http_client *client);

/* Blocks until all currently submitted requests are handled */
void http_client_wait(struct http_client *client);

/* Specify the SSL settings. By default lib-ssl-iostream automatically looks
   them up from settings. */
void http_client_set_ssl_settings(struct http_client *client,
				  const struct ssl_iostream_settings *ssl);
/* Do all lookups using the specified DNS client. */
void http_client_set_dns_client(struct http_client *client,
				struct dns_client *dns_client);
/* Returns the total number of pending HTTP requests. */
unsigned int http_client_get_pending_request_count(struct http_client *client);

/*
 * Client shared context
 */

struct http_client_context *http_client_context_create(void);
void http_client_context_ref(struct http_client_context *cctx);
void http_client_context_unref(struct http_client_context **_cctx);

/* Return the default global shared client context, creating it if necessary.
   The context is freed automatically at exit. Don't unreference the
   returned context. */
struct http_client_context *http_client_get_global_context(void);

/* Explicitly free the global context. This function is only useful for testing:
   the global context is cleaned up implicitly. */
void http_client_global_context_free(void);

#endif
