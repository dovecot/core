#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#include "http-auth.h"
#include "http-request.h"

struct istream;
struct ostream;

struct http_request;

struct http_server;
struct http_server_request;
struct http_server_response;

struct http_server_settings {
	const char *rawlog_dir;

	unsigned int max_client_idle_time_msecs;

	/* maximum number of pipelined requests per connection (default = 1) */
	unsigned int max_pipelined_requests;

	/* request limits */
	struct http_request_limits request_limits;

	/* the kernel send/receive buffer sizes used for the connection sockets.
	   Configuring this is mainly useful for the test suite. The kernel
	   defaults are used when these settings are 0. */
	size_t socket_send_buffer_size;
	size_t socket_recv_buffer_size;

	bool debug;
};

struct http_server_stats {
	unsigned int request_count, response_count;
	uoff_t input, output;
};

struct http_server_tunnel {
	int fd_in, fd_out;
	struct istream *input;
	struct ostream *output;
};

struct http_server_callbacks {
	/* Handle the server request. All requests must be sent back a response.
	   The response is sent either with http_server_request_fail*() or
	   http_server_response_submit*(). For simple requests you can send the
	   response back immediately. If you can't do that, you'll need to
	   reference the request. Then the code flow usually goes like this:

	   - http_server_request_set_destroy_callback(destroy_callback)
	   - http_server_request_ref()
	   - <do whatever is needed to handle the request>
	   - http_server_response_create()
	   - http_server_response_set_payload() can be used especially with
	     istream-callback to create a large response without temp files.
	   - http_server_response_submit() triggers the destroy_callback
	     after it has finished sending the response and its payload.
	   - In destroy_callback: http_server_request_unref() and any other
	     necessary cleanup - the request handling is now fully finished.
	*/
	void (*handle_request)(void *context, struct http_server_request *req);
	void (*handle_connect_request)(void *context,
		struct http_server_request *req, struct http_url *target);

	void (*connection_destroy)(void *context, const char *reason);
};

typedef void (*http_server_tunnel_callback_t)(void *context,
	const struct http_server_tunnel *tunnel);

struct http_server *http_server_init(const struct http_server_settings *set);
void http_server_deinit(struct http_server **_server);
/* shut down the server; accept no new requests and drop connections once
   they become idle */
void http_server_shut_down(struct http_server *server);

struct http_server_connection *
http_server_connection_create(struct http_server *server,
	int fd_in, int fd_out, bool ssl,
	const struct http_server_callbacks *callbacks, void *context);
void http_server_connection_ref(struct http_server_connection *conn);
/* Returns FALSE if unrefing destroyed the connection entirely */
bool http_server_connection_unref(struct http_server_connection **_conn);
void http_server_connection_close(struct http_server_connection **_conn,
	const char *reason);
const struct http_server_stats *
http_server_connection_get_stats(struct http_server_connection *conn);

const struct http_request *
http_server_request_get(struct http_server_request *req);
pool_t http_server_request_get_pool(struct http_server_request *req);
/* Returns the response created for the request with
   http_server_response_create(), or NULL if none. */
struct http_server_response *
http_server_request_get_response(struct http_server_request *req);
/* Returns TRUE if request is finished either because a response was sent
   or because the request was aborted. */
bool http_server_request_is_finished(struct http_server_request *req);

/* Return input stream for the request's payload. Optionally, this stream
   can be made blocking. Do *NOT* meddle with the FD of the http_request
   payload to achieve the same, because protocol violations will result.
 */
struct istream *
http_server_request_get_payload_input(struct http_server_request *req,
	bool blocking);

/* Get the authentication credentials provided in this request. Returns 0 if
   the Authorization header is absent, returns -1 when that header cannot be
   parsed, and returns 1 otherwise */
int http_server_request_get_auth(struct http_server_request *req,
	struct http_auth_credentials *credentials);

/* Send a failure response to the request with given status/reason. */
void http_server_request_fail(struct http_server_request *req,
	unsigned int status, const char *reason);
/* Send a failure response to the request with given status/reason
   and close the connection. */
void http_server_request_fail_close(struct http_server_request *req,
	unsigned int status, const char *reason);
/* Send an authentication failure response to the request with given reason.
   The provided challenge is set in the WWW-Authenticate header of the
   response. */
void http_server_request_fail_auth(struct http_server_request *req,
	const char *reason, const struct http_auth_challenge *chlng)
	ATTR_NULL(2);
/* Send a authentication failure response to the request with given reason.
   The provided realm is used to construct an Basic challenge in the
   WWW-Authenticate header of the response. */
void http_server_request_fail_auth_basic(struct http_server_request *req,
	const char *reason, const char *realm)
	ATTR_NULL(2);

/* Call the specified callback when HTTP request is destroyed. This happens
   after one of the following:

   a) Response and its payload is fully sent
   b) Response was submitted, but it couldn't be sent due to disconnection.
   c) http_server_deinit() was called and the request was aborted

   Note client disconnection before response is submitted isn't visible to this.
   The request payload reading is the responsibility of the caller, which also
   must handle the read errors by submitting a failure response. */
void http_server_request_set_destroy_callback(struct http_server_request *req,
					      void (*callback)(void *),
					      void *context);

/* Reference a server request */
void http_server_request_ref(struct http_server_request *req);
/* Unreference a server request. Returns TRUE if there are still more
   references, FALSE if not. */
bool http_server_request_unref(struct http_server_request **_req);

/* Start creating the response for the request. This function can be called
   only once for each request. */
struct http_server_response *
http_server_response_create(struct http_server_request *req,
	unsigned int status, const char *reason);
void http_server_response_add_header(struct http_server_response *resp,
				    const char *key, const char *value);
/* Change the response code and text, cannot be used after submission */
void http_server_response_update_status(struct http_server_response *resp,
					unsigned int status, const char *reason);
void http_server_response_set_date(struct http_server_response *resp,
				    time_t date);
void http_server_response_set_payload(struct http_server_response *resp,
				     struct istream *input);
void http_server_response_set_payload_data(struct http_server_response *resp,
				     const unsigned char *data, size_t size);

struct ostream *
http_server_response_get_payload_output(struct http_server_response *resp,
	bool blocking);

/* get some information about response */
void http_server_response_get_status(struct http_server_response *resp,
	int *status_r, const char **reason_r);
uoff_t http_server_response_get_total_size(struct http_server_response *resp);
void http_server_response_add_auth(
	struct http_server_response *resp,
	const struct http_auth_challenge *chlng);
void http_server_response_add_auth_basic(
	struct http_server_response *resp, const char *realm);

void http_server_response_submit(struct http_server_response *resp);
/* Submit response and close the connection. */
void http_server_response_submit_close(struct http_server_response *resp);
void http_server_response_submit_tunnel(struct http_server_response *resp,
	http_server_tunnel_callback_t callback, void *context);

void http_server_switch_ioloop(struct http_server *server);

/* submits response and blocks until provided payload is sent. Multiple calls
   are allowed; payload transmission is finished with
   http_server_response_finish_payload(). If the sending fails, returns -1
   and sets resp=NULL to indicate that the response was freed, otherwise
   returns 0 and resp is unchanged. */
int http_server_response_send_payload(struct http_server_response **resp,
	const unsigned char *data, size_t size);
/* Finish sending the payload. Always frees resp and sets it to NULL.
   Returns 0 on success, -1 on error. */
int http_server_response_finish_payload(struct http_server_response **resp);
/* abort response payload transmission prematurely. this closes the associated
   connection */
void http_server_response_abort_payload(struct http_server_response **resp);

#endif
