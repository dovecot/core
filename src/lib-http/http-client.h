#ifndef HTTP_CLIENT_H
#define HTTP_CLIENT_H

#include "http-response.h"

struct http_response;

struct http_client;
struct http_client_request;

enum http_client_request_error {
	HTTP_CLIENT_REQUEST_ERROR_ABORTED = 9000,
	HTTP_CLIENT_REQUEST_ERROR_HOST_LOOKUP_FAILED,
	HTTP_CLIENT_REQUEST_ERROR_CONNECT_FAILED,
	HTTP_CLIENT_REQUEST_ERROR_INVALID_REDIRECT,
	HTTP_CLIENT_REQUEST_ERROR_CONNECTION_LOST,
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
	const char *dns_client_socket_path;

	const char *ssl_ca_dir, *ssl_ca_file, *ssl_ca;
	const char *ssl_crypto_device;
	bool ssl_allow_invalid_cert;
	/* user cert */
	const char *ssl_cert, *ssl_key, *ssl_key_password;

	const char *rawlog_dir;

	unsigned int max_idle_time_msecs;

	/* maximum number of parallel connections per peer (default = 1) */
	unsigned int max_parallel_connections;

	/* maximum number of pipelined requests per connection (default = 1) */
	unsigned int max_pipelined_requests;

	/* maximum number of redirects for a request
	   (default = 0; redirects refused) 
   */
	unsigned int max_redirects;

	/* maximum number of attempts for a request */
	unsigned int max_attempts;

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

	bool debug;
};

typedef void
http_client_request_callback_t(const struct http_response *response,
			       void *context);

struct http_client *http_client_init(const struct http_client_settings *set);
void http_client_deinit(struct http_client **_client);

struct http_client_request *
http_client_request(struct http_client *client,
		    const char *method, const char *host, const char *target,
		    http_client_request_callback_t *callback, void *context);
#define http_client_request(client, method, host, target, callback, context) \
	http_client_request(client, method, host, target + \
		CALLBACK_TYPECHECK(callback, void (*)( \
			const struct http_response *response, typeof(context))), \
		(http_client_request_callback_t *)callback, context)

void http_client_request_set_port(struct http_client_request *req,
	unsigned int port);
void http_client_request_set_ssl(struct http_client_request *req,
	bool ssl);
void http_client_request_set_urgent(struct http_client_request *req);

void http_client_request_add_header(struct http_client_request *req,
				    const char *key, const char *value);
void http_client_request_set_payload(struct http_client_request *req,
				     struct istream *input, bool sync);

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
   http_client_request_finish_payload(). */
int http_client_request_send_payload(struct http_client_request **req,
	const unsigned char *data, size_t size);
int http_client_request_finish_payload(struct http_client_request **req);

void http_client_switch_ioloop(struct http_client *client);

/* blocks until all currently submitted requests are handled */
void http_client_wait(struct http_client *client);
/* Returns number of pending HTTP requests. */
unsigned int http_client_get_pending_request_count(struct http_client *client);

#endif
