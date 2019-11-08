#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#include "http-common.h"
#include "http-auth.h"
#include "http-request.h"

struct istream;
struct ostream;

struct http_request;

struct http_server;
struct http_server_resource;
struct http_server_request;
struct http_server_response;

/*
 * Server settings
 */

struct http_server_settings {
	const char *default_host;

	const char *rawlog_dir;

	/* SSL settings; if NULL, master_service_ssl_init() is used instead */
	const struct ssl_iostream_settings *ssl;

	/* The maximum time in milliseconds a client is allowed to be idle
	   before it is disconnected. */
	unsigned int max_client_idle_time_msecs;

	/* Maximum number of pipelined requests per connection (default = 1) */
	unsigned int max_pipelined_requests;

	/* Request limits */
	struct http_request_limits request_limits;

	/* The kernel send/receive buffer sizes used for the connection sockets.
	   Configuring this is mainly useful for the test suite. The kernel
	   defaults are used when these settings are 0. */
	size_t socket_send_buffer_size;
	size_t socket_recv_buffer_size;

	/* Event to use for the http server. */
	struct event *event;

	/* Enable logging debug messages */
	bool debug;
};

/*
 * Response
 */

/* Connection data for an established HTTP tunnel */
struct http_server_tunnel {
	int fd_in, fd_out;
	struct istream *input;
	struct ostream *output;
};

typedef void
(*http_server_tunnel_callback_t)(void *context,
				 const struct http_server_tunnel *tunnel);

/* Start creating the response for the request. This function can be called
   only once for each request. */
struct http_server_response *
http_server_response_create(struct http_server_request *req,
			    unsigned int status, const char *reason);

/* Add a custom header to the response. This can override headers that are
   otherwise created implicitly. */
void http_server_response_add_header(struct http_server_response *resp,
				     const char *key, const char *value);
/* Add a header permanently to the response. Even if another response is
   created for the request, this header is kept. */
void http_server_response_add_permanent_header(struct http_server_response *resp,
					       const char *key, const char *value);
/* Change the response code and text, cannot be used after submission */
void http_server_response_update_status(struct http_server_response *resp,
					unsigned int status, const char *reason);
/* Set the value of the "Date" header for the response using a time_t value.
   Use this instead of setting it directly using
   http_server_response_add_header() */
void http_server_response_set_date(struct http_server_response *resp,
				   time_t date);
/* Assign an input stream for the outgoing payload of this response. The input
   stream is read asynchronously while the response is sent to the client. */
void http_server_response_set_payload(struct http_server_response *resp,
				      struct istream *input);
/* Assign payload data to the response. The data is copied to the request pool.
   If your data is already durably allocated during the existence of the
   response, you should consider using http_server_response_set_payload() with
   a data input stream instead. This will avoid copying the data unnecessarily.
 */
void http_server_response_set_payload_data(struct http_server_response *resp,
					   const unsigned char *data,
					   size_t size);

/* Obtain an output stream for the response payload. This is an alternative to
   using http_server_response_set_payload(). Currently, this can only return a
   blocking output stream. The request is submitted implicitly once the output
   stream is written to. Closing the stream concludes the payload. Destroying
   the stream before that aborts the response and closes the connection.
 */
struct ostream *
http_server_response_get_payload_output(struct http_server_response *resp,
					bool blocking);

/* Get the status code and reason string currently set for this response. */
void http_server_response_get_status(struct http_server_response *resp,
				     int *status_r, const char **reason_r);
/* Get the total size of the response when sent over the connection. */
uoff_t http_server_response_get_total_size(struct http_server_response *resp);
/* Add authentication challenge to the response. */
void http_server_response_add_auth(struct http_server_response *resp,
				   const struct http_auth_challenge *chlng);
/* Add "Basic" authentication challenge to the response. */
void http_server_response_add_auth_basic(struct http_server_response *resp,
					 const char *realm);

/* Submit the response. It is queued for transmission to the client. */
void http_server_response_submit(struct http_server_response *resp);
/* Submit the response and close the connection once it is sent. */
void http_server_response_submit_close(struct http_server_response *resp);
/* Submit the response and turn the connection it is sent across into a tunnel
   once it is sent successfully. The callback is called once that happens. */
void http_server_response_submit_tunnel(struct http_server_response *resp,
					http_server_tunnel_callback_t callback,
					void *context);

/* Submits response and blocks until provided payload is sent. Multiple calls
   are allowed; payload is sent in chunks this way. Payload transmission is
   finished with http_server_response_finish_payload(). If the sending fails,
   returns -1 and sets resp=NULL to indicate that the response was freed,
   otherwise returns 0 and resp is unchanged.

   An often more convenient ostream wrapper API is available as
   http_server_response_get_payload_output() with blocking=TRUE.
 */
int http_server_response_send_payload(struct http_server_response **resp,
				      const unsigned char *data, size_t size);
/* Finish sending the payload. Always frees resp and sets it to NULL.
   Returns 0 on success, -1 on error. */
int http_server_response_finish_payload(struct http_server_response **resp);
/* Abort response payload transmission prematurely. This closes the associated
   connection */
void http_server_response_abort_payload(struct http_server_response **resp);

/*
 * Request
 */

/* Get the parsed HTTP request information for this request. */
const struct http_request *
http_server_request_get(struct http_server_request *req);

/* Reference a server request */
void http_server_request_ref(struct http_server_request *req);
/* Unreference a server request. Returns TRUE if there are still more
   references, FALSE if not. */
bool http_server_request_unref(struct http_server_request **_req);

/* Set flag that determines whether the connection is closed after the
   request is handled. */
void http_server_request_connection_close(struct http_server_request *req,
					  bool close);

/* Get the pool for this request. */
pool_t http_server_request_get_pool(struct http_server_request *req);
/* Returns the response created for the request with
   http_server_response_create(), or NULL if none. */
struct http_server_response *
http_server_request_get_response(struct http_server_request *req);
/* Returns TRUE if request is finished either because a response was sent
   or because the request was aborted. */
bool http_server_request_is_finished(struct http_server_request *req);

/* Add a header to any HTTP response created for the HTTP request. */
void http_server_request_add_response_header(struct http_server_request *req,
					     const char *key, const char *value);

/* Return input stream for the request's payload. Optionally, this stream
   can be made blocking. Do *NOT* meddle with the FD of the http_request
   payload to achieve the same, because protocol violations will result.
 */
struct istream *
http_server_request_get_payload_input(struct http_server_request *req,
				      bool blocking);

/* Forward the incoming request payload to the provided output stream in the
   background. Calls the provided callback once the payload was forwarded
   successfully. If forwarding fails, the client is presented with an
   appropriate error. If the payload size exceeds max_size, the client will
   get a 413 error. Before the callback finishes, the application must either
   have added a reference to the request or have submitted a response. */
void http_server_request_forward_payload(struct http_server_request *req,
					 struct ostream *output,
					 uoff_t max_size,
					 void (*callback)(void *),
					 void *context);
#define http_server_request_forward_payload(req, output, max_size, \
					    callback, context) \
	http_server_request_forward_payload(req, output, max_size, \
		(void(*)(void*))callback, TRUE ? context : \
		CALLBACK_TYPECHECK(callback, void (*)(typeof(context))))
/* Forward the incoming request payload to the provided buffer in the
   background. Behaves identical to http_server_request_forward_payload()
   otherwise. */
void http_server_request_buffer_payload(struct http_server_request *req,
					buffer_t *buffer, uoff_t max_size,
					void (*callback)(void *),
					void *context);
#define http_server_request_buffer_payload(req, buffer, max_size, \
					   callback, context) \
	http_server_request_buffer_payload(req, buffer, max_size, \
		(void(*)(void*))callback, TRUE ? context : \
		CALLBACK_TYPECHECK(callback, void (*)(typeof(context))))
/* Handle the incoming request payload by calling the callback each time
   more data is available. Payload reading automatically finishes when the
   request payload is fully read. Before the final callback finishes, the
   application must either have added a reference to the request or have
   submitted a response. */
void http_server_request_handle_payload(struct http_server_request *req,
					void (*callback)(void *context),
					void *context);
#define http_server_request_handle_payload(req, callback, context) \
	http_server_request_handle_payload(req,\
		(void(*)(void*))callback, TRUE ? context : \
		CALLBACK_TYPECHECK(callback, void (*)(typeof(context))))

/* Get the authentication credentials provided in this request. Returns 0 if
   the Authorization header is absent, returns -1 when that header cannot be
   parsed, and returns 1 otherwise */
int http_server_request_get_auth(struct http_server_request *req,
				 struct http_auth_credentials *credentials);

/* Send a failure response for the request with given status/reason. */
void http_server_request_fail(struct http_server_request *req,
			      unsigned int status, const char *reason);
/* Send a failure response for the request with given status/reason
   and close the connection. */
void http_server_request_fail_close(struct http_server_request *req,
				    unsigned int status, const char *reason);
/* Send a failure response for the request with given status/reason/text.
   The text is sent as the response payload, if appropriate. */
void http_server_request_fail_text(struct http_server_request *req,
				   unsigned int status, const char *reason,
				   const char *format, ...) ATTR_FORMAT(4, 5);
/* Send an authentication failure response for the request with given reason.
   The provided challenge is set in the WWW-Authenticate header of the
   response. */
void http_server_request_fail_auth(struct http_server_request *req,
				   const char *reason,
				   const struct http_auth_challenge *chlng)
				   ATTR_NULL(2);
/* Send a authentication failure response for the request with given reason.
   The provided realm is used to construct an Basic challenge in the
   WWW-Authenticate header of the response. */
void http_server_request_fail_auth_basic(struct http_server_request *req,
					 const char *reason, const char *realm)
					 ATTR_NULL(2);

/* Call the specified callback when HTTP request is destroyed. This happens
   after one of the following:

   a) Response and its payload is fully sent,
   b) Response was submitted, but it couldn't be sent due to disconnection or
      some other error,
   c) http_server_deinit() was called and the request was aborted

   Note client disconnection before response is submitted isn't visible to this.
   The request payload reading is the responsibility of the caller, which also
   must handle the read errors by submitting a failure response. */
void http_server_request_set_destroy_callback(struct http_server_request *req,
					      void (*callback)(void *),
					      void *context);
#define http_server_request_set_destroy_callback(req, callback, context) \
	http_server_request_set_destroy_callback( \
		req, (void(*)(void*))callback, \
		(TRUE ? context : \
		 CALLBACK_TYPECHECK(callback, void (*)(typeof(context)))))

/*
 * Connection
 */

/* Connection statistics */
struct http_server_stats {
	/* The number of requests received and responses sent */
	unsigned int request_count, response_count;
	/* Bytes sent and received accross the connection */
	uoff_t input, output;
};

/* Connection callbacks */
struct http_server_callbacks {
	/* Handle the server request. All requests must be sent back a response.
	   The response is sent either with http_server_request_fail*() or
	   http_server_response_submit*(). For simple requests you can send the
	   response back immediately. If you can't do that, you'll need to
	   reference the request (or the request payload input stream). Then the
	   code flow usually goes like this:

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
				       struct http_server_request *req,
				       struct http_url *target);

	/* Called once the connection is destroyed. */
	void (*connection_destroy)(void *context, const char *reason);
};

/* Create a HTTP server connection object for the provided fd pair. The
   callbacks structure is described above. */
struct http_server_connection *
http_server_connection_create(struct http_server *server,
			      int fd_in, int fd_out, bool ssl,
			      const struct http_server_callbacks *callbacks,
			      void *context);
/* Reference the connection */
void http_server_connection_ref(struct http_server_connection *conn);
/* Dereference the connection. Returns FALSE if unrefing destroyed the
   connection entirely */
bool http_server_connection_unref(struct http_server_connection **_conn);
/* Dereference and close the connection. The provided reason is passed to the
   connection_destroy() callback. */
void http_server_connection_close(struct http_server_connection **_conn,
				  const char *reason);
/* Get the current statistics for this connection */
const struct http_server_stats *
http_server_connection_get_stats(struct http_server_connection *conn);

/*
 * Resource
 */

typedef void
(http_server_resource_callback_t)(void *context,
				  struct http_server_request *req,
				  const char *sub_path);

struct http_server_resource *
http_server_resource_create(struct http_server *server, pool_t pool,
			    http_server_resource_callback_t *callback,
			    void *context);
#define http_server_resource_create(server, pool, callback, context) \
	http_server_resource_create(server, pool, \
		(http_server_resource_callback_t *)callback, \
		(TRUE ? context : \
		 CALLBACK_TYPECHECK(callback, void (*)( \
			typeof(context), struct http_server_request *req, \
			const char *sub_path))))
/* Resources are freed upon http_server_deinit(), so calling
   http_server_resource_free() is only necessary when the resource needs to
   disappear somewhere in the middle of the server lifetime. */
void http_server_resource_free(struct http_server_resource **_res);

pool_t http_server_resource_get_pool(struct http_server_resource *res)
				     ATTR_PURE;
const char *
http_server_resource_get_path(struct http_server_resource *res) ATTR_PURE;
struct event *
http_server_resource_get_event(struct http_server_resource *res) ATTR_PURE;

void http_server_resource_add_location(struct http_server_resource *res,
				       const char *path);

/* Call the specified callback when HTTP resource is destroyed. */
void http_server_resource_set_destroy_callback(struct http_server_resource *res,
					       void (*callback)(void *),
					       void *context);
#define http_server_resource_set_destroy_callback(req, callback, context) \
	http_server_resource_set_destroy_callback(req, \
		(void(*)(void*))callback, context - \
		CALLBACK_TYPECHECK(callback, void (*)(typeof(context))))

/*
 * Server
 */

struct http_server *http_server_init(const struct http_server_settings *set);
void http_server_deinit(struct http_server **_server);

/* Shut down the server; accept no new requests and drop connections once
   they become idle */
void http_server_shut_down(struct http_server *server);

/* Switch this server to the current ioloop */
void http_server_switch_ioloop(struct http_server *server);

#endif
