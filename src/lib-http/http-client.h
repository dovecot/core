#ifndef HTTP_CLIENT_H
#define HTTP_CLIENT_H

#include "net.h"

#include "http-response.h"

struct timeval;
struct http_response;

struct http_client;
struct http_client_request;

enum http_client_request_error {
	HTTP_CLIENT_REQUEST_ERROR_ABORTED = 9000,
	HTTP_CLIENT_REQUEST_ERROR_HOST_LOOKUP_FAILED,
	HTTP_CLIENT_REQUEST_ERROR_CONNECT_FAILED,
	HTTP_CLIENT_REQUEST_ERROR_INVALID_REDIRECT,
	HTTP_CLIENT_REQUEST_ERROR_CONNECTION_LOST,
	HTTP_CLIENT_REQUEST_ERROR_BROKEN_PAYLOAD,
	HTTP_CLIENT_REQUEST_ERROR_BAD_RESPONSE,
	HTTP_CLIENT_REQUEST_ERROR_TIMED_OUT,
};

enum http_request_state {
	HTTP_REQUEST_STATE_NEW = 0,
	HTTP_REQUEST_STATE_QUEUED,
	HTTP_REQUEST_STATE_PAYLOAD_OUT,
	HTTP_REQUEST_STATE_WAITING,
	HTTP_REQUEST_STATE_GOT_RESPONSE,
	HTTP_REQUEST_STATE_PAYLOAD_IN,
	HTTP_REQUEST_STATE_FINISHED,
	HTTP_REQUEST_STATE_ABORTED
};
extern const char *http_request_state_names[];

struct http_client_settings {
	/* a) If dns_client is set, all lookups are done via it.
	   b) If dns_client_socket_path is set, each DNS lookup does its own
	   dns-lookup UNIX socket connection.
	   c) Otherwise, blocking gethostbyname() lookups are used. */
	struct dns_client *dns_client;
	const char *dns_client_socket_path;

	const char *ssl_ca_dir, *ssl_ca_file, *ssl_ca;
	const char *ssl_crypto_device;
	bool ssl_allow_invalid_cert;
	/* user cert */
	const char *ssl_cert, *ssl_key, *ssl_key_password;

	/* User-Agent: header (default: none) */
	const char *user_agent;

	/* proxy on unix socket */
	const char *proxy_socket_path;
	/* URL for normal proxy (ignored if proxy_socket_path is set) */   
	const struct http_url *proxy_url;
	/* credentials for proxy */
	const char *proxy_username;
	const char *proxy_password;

	const char *rawlog_dir;

	unsigned int max_idle_time_msecs;

	/* maximum number of parallel connections per peer (default = 1) */
	unsigned int max_parallel_connections;

	/* maximum number of pipelined requests per connection (default = 1) */
	unsigned int max_pipelined_requests;

	/* don't automatically act upon redirect responses */
	bool no_auto_redirect;

	/* if we use a proxy, delegate SSL negotiation to proxy, rather than
	   creating a CONNECT tunnel through the proxy for the SSL link */
	bool no_ssl_tunnel;

	/* maximum number of redirects for a request
	   (default = 0; redirects refused) 
   */
	unsigned int max_redirects;

	/* maximum number of attempts for a request */
	unsigned int max_attempts;

	/* maximum number of connection attempts to a host before all associated
	   requests fail.

     if > 1, the maximum will be enforced across all IPs for that host,
	   meaning that IPs may be tried more than once eventually if the number
	   of IPs is smaller than the specified maximum attempts. If the number of IPs
	   is higher than the maximum attempts, not all IPs are tried. If <= 1, all
	   IPs are tried at most once.
	 */
	unsigned int max_connect_attempts;

	/* Initial backoff time; doubled at each connection failure */
	unsigned int connect_backoff_time_msecs;
	/* Maximum backoff time */
	unsigned int connect_backoff_max_time_msecs;

	/* response header limits */
	struct http_header_limits response_hdr_limits;

	/* max total time to wait for HTTP request to finish
	   this can be overridden/reset for individual requests using
	   http_client_request_set_timeout() and friends.
	   (default is no timeout)
	 */
	unsigned int request_absolute_timeout_msecs;
	/* max time to wait for HTTP request to finish before retrying
	   (default = unlimited) */
	unsigned int request_timeout_msecs;
	/* max time to wait for connect() (and SSL handshake) to finish before
	   retrying (default = request_timeout_msecs) */
	unsigned int connect_timeout_msecs;
	/* time to wait for connect() (and SSL handshake) to finish for the first
	   connection before trying the next IP in parallel
	   (default = 0; wait until current connection attempt finishes) */
	unsigned int soft_connect_timeout_msecs;

	/* maximum acceptable delay in seconds for automatically
	   retrying/redirecting requests. if a server sends a response with a
	   Retry-After header that causes a delay longer than this, the request
	   is not automatically retried and the response is returned */
	unsigned int max_auto_retry_delay;

	bool debug;
};

struct http_client_tunnel {
	int fd_in, fd_out;
	struct istream *input;
	struct ostream *output;
};

typedef void
http_client_request_callback_t(const struct http_response *response,
			       void *context);

struct http_client *http_client_init(const struct http_client_settings *set);
void http_client_deinit(struct http_client **_client);

/* create new HTTP request */
struct http_client_request *
http_client_request(struct http_client *client,
		    const char *method, const char *host, const char *target,
		    http_client_request_callback_t *callback, void *context);
#define http_client_request(client, method, host, target, callback, context) \
	http_client_request(client, method, host, target + \
		CALLBACK_TYPECHECK(callback, void (*)( \
			const struct http_response *response, typeof(context))), \
		(http_client_request_callback_t *)callback, context)

struct http_client_request *
http_client_request_url(struct http_client *client,
		    const char *method, const struct http_url *target_url,
		    http_client_request_callback_t *callback, void *context);
#define http_client_request_url(client, method, target_url, callback, context) \
	http_client_request_url(client, method, target_url + \
		CALLBACK_TYPECHECK(callback, void (*)( \
			const struct http_response *response, typeof(context))), \
		(http_client_request_callback_t *)callback, context)

/* create new HTTP CONNECT request. If this HTTP is configured to use a proxy,
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
	http_client_request_connect(client, host, port + \
		CALLBACK_TYPECHECK(callback, void (*)( \
			const struct http_response *response, typeof(context))), \
		(http_client_request_callback_t *)callback, context)
struct http_client_request *
http_client_request_connect_ip(struct http_client *client,
		    const struct ip_addr *ip, in_port_t port,
		    http_client_request_callback_t *callback,
		    void *context);
#define http_client_request_connect_ip(client, ip, port, callback, context) \
	http_client_request_connect_ip(client, ip, port + \
		CALLBACK_TYPECHECK(callback, void (*)( \
			const struct http_response *response, typeof(context))), \
		(http_client_request_callback_t *)callback, context)

void http_client_request_set_port(struct http_client_request *req,
	in_port_t port);
void http_client_request_set_ssl(struct http_client_request *req,
	bool ssl);
void http_client_request_set_urgent(struct http_client_request *req);
void http_client_request_set_preserve_exact_reason(struct http_client_request *req);

void http_client_request_add_header(struct http_client_request *req,
				    const char *key, const char *value);
void http_client_request_remove_header(struct http_client_request *req,
				       const char *key);
void http_client_request_set_date(struct http_client_request *req,
				    time_t date);

void http_client_request_set_payload(struct http_client_request *req,
				     struct istream *input, bool sync);
void http_client_request_set_payload_data(struct http_client_request *req,
				     const unsigned char *data, size_t size);

void http_client_request_set_timeout_msecs(struct http_client_request *req,
	unsigned int msecs);
void http_client_request_set_timeout(struct http_client_request *req,
	const struct timeval *time);

void http_client_request_set_auth_simple(struct http_client_request *req,
	const char *username, const char *password);

void http_client_request_delay_until(struct http_client_request *req,
	time_t time);
void http_client_request_delay(struct http_client_request *req,
	time_t seconds);
void http_client_request_delay_msecs(struct http_client_request *req,
	unsigned int msecs);

const char *http_client_request_get_method(struct http_client_request *req);
const char *http_client_request_get_target(struct http_client_request *req);
enum http_request_state
http_client_request_get_state(struct http_client_request *req);
void http_client_request_submit(struct http_client_request *req);
bool http_client_request_try_retry(struct http_client_request *req);

void http_client_request_abort(struct http_client_request **req);

/* Call the specified callback when HTTP request is destroyed. */
void http_client_request_set_destroy_callback(struct http_client_request *req,
					      void (*callback)(void *),
					      void *context);

/* submits request and blocks until provided payload is sent. Multiple calls
   are allowed; payload transmission is ended with
   http_client_request_finish_payload(). If the sending fails, returns -1
   and sets req=NULL to indicate that the request was freed, otherwise
   returns 0 and req is unchanged. */
int http_client_request_send_payload(struct http_client_request **req,
	const unsigned char *data, size_t size);
/* Finish sending the payload. Always frees req and sets it to NULL.
   Returns 0 on success, -1 on error. */
int http_client_request_finish_payload(struct http_client_request **req);

void http_client_request_start_tunnel(struct http_client_request *req,
	struct http_client_tunnel *tunnel);

void http_client_switch_ioloop(struct http_client *client);

/* blocks until all currently submitted requests are handled */
void http_client_wait(struct http_client *client);
/* Returns number of pending HTTP requests. */
unsigned int http_client_get_pending_request_count(struct http_client *client);

#endif
