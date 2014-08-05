#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

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
	void (*handle_request)(void *context, struct http_server_request *req);
	void (*handle_connect_request)(void *context,
		struct http_server_request *req, struct http_url *target);

	void (*connection_destroy)(void *context, const char *reason);
};

typedef void (*http_server_tunnel_callback_t)(void *context,
	const struct http_server_tunnel *tunnel);

struct http_server *http_server_init(const struct http_server_settings *set);
void http_server_deinit(struct http_server **_server);

struct http_server_connection *
http_server_connection_create(struct http_server *server,
	int fd_in, int fd_out, bool ssl,
	const struct http_server_callbacks *callbacks, void *context);
void http_server_connection_ref(struct http_server_connection *conn);
void http_server_connection_unref(struct http_server_connection **_conn);
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
/* Send a failure response to the request with given status/reason. */
void http_server_request_fail(struct http_server_request *req,
	unsigned int status, const char *reason);
/* Send a failure response to the request with given status/reason
   and close the connection. */
void http_server_request_fail_close(struct http_server_request *req,
	unsigned int status, const char *reason);

/* Call the specified callback when HTTP request is destroyed. */
void http_server_request_set_destroy_callback(struct http_server_request *req,
					      void (*callback)(void *),
					      void *context);

/* Start creating the response for the request. This function can be called
   only once for each request. */
struct http_server_response *
http_server_response_create(struct http_server_request *req,
	unsigned int status, const char *reason);
void http_server_response_add_header(struct http_server_response *resp,
				    const char *key, const char *value);
void http_server_response_set_date(struct http_server_response *resp,
				    time_t date);
void http_server_response_set_payload(struct http_server_response *resp,
				     struct istream *input);
void http_server_response_set_payload_data(struct http_server_response *resp,
				     const unsigned char *data, size_t size);
void http_server_response_submit(struct http_server_response *resp);
/* Submit response and close the connection. */
void http_server_response_submit_close(struct http_server_response *resp);
void http_server_response_submit_tunnel(struct http_server_response *resp,
	http_server_tunnel_callback_t callback, void *context);

void http_server_switch_ioloop(struct http_server *server);

#endif
