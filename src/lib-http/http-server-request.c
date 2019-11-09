/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "ostream.h"
#include "istream-private.h"

#include "http-server-private.h"

/*
 * Logging
 */

static inline void
http_server_request_client_error(struct http_server_request *req,
				 const char *format, ...) ATTR_FORMAT(2, 3);

static inline void
http_server_request_client_error(struct http_server_request *req,
				 const char *format, ...)
{
	va_list args;

	va_start(args, format);
	e_info(req->event, "%s", t_strdup_vprintf(format, args));
	va_end(args);
}

/*
 * Request
 */

const char *http_server_request_label(struct http_server_request *req)
{
	if (req->req.target_raw == NULL) {
		if (req->req.method == NULL)
			return t_strdup_printf("[Req%u: <NEW>]", req->id);
		return t_strdup_printf("[Req%u: %s <INCOMPLETE>]",
			req->id, req->req.method);
	}
	return t_strdup_printf("[Req%u: %s %s]", req->id,
		req->req.method, req->req.target_raw);
}

void http_server_request_update_event(struct http_server_request *req)
{
	if (req->req.method != NULL)
		event_add_str(req->event, "method", req->req.method);
	if (req->req.target_raw != NULL)
		event_add_str(req->event, "target", req->req.target_raw);
	event_set_append_log_prefix(
		req->event, t_strdup_printf("request %s: ",
					    http_server_request_label(req)));
}

struct http_server_request *
http_server_request_new(struct http_server_connection *conn)
{
	static unsigned int id_counter = 0;
	pool_t pool;
	struct http_server_request *req;

	pool = pool_alloconly_create(
		MEMPOOL_GROWING"http_server_request", 4096);
	req = p_new(pool, struct http_server_request, 1);
	req->pool = pool;
	req->refcount = 1;
	req->conn = conn;
	req->server = conn->server;
	req->id = ++id_counter;
	req->event = event_create(conn->event);
	http_server_request_update_event(req);

	http_server_connection_add_request(conn, req);
	return req;
}

void http_server_request_ref(struct http_server_request *req)
{
	i_assert(req->refcount > 0);
	req->refcount++;
}

bool http_server_request_unref(struct http_server_request **_req)
{
	struct http_server_request *req = *_req;
	struct http_server_connection *conn = req->conn;

	i_assert(req->refcount > 0);

	*_req = NULL;
	if (--req->refcount > 0)
		return TRUE;

	e_debug(req->event, "Free");

	if (req->state < HTTP_SERVER_REQUEST_STATE_FINISHED) {
		req->state = HTTP_SERVER_REQUEST_STATE_ABORTED;
		http_server_connection_remove_request(conn, req);
	}

	if (req->destroy_callback != NULL) {
		req->destroy_callback(req->destroy_context);
		req->destroy_callback = NULL;
	}

	if (req->response != NULL)
		http_server_response_free(req->response);
	event_unref(&req->event);
	pool_unref(&req->pool);
	return FALSE;
}

void http_server_request_connection_close(struct http_server_request *req,
					  bool close)
{
	i_assert(req->state < HTTP_SERVER_REQUEST_STATE_SENT_RESPONSE);
	req->connection_close = close;
}

void http_server_request_destroy(struct http_server_request **_req)
{
	struct http_server_request *req = *_req;
	struct http_server *server = req->server;

	e_debug(req->event, "Destroy");

	/* Just make sure the request ends in a proper state */
	if (req->state < HTTP_SERVER_REQUEST_STATE_FINISHED)
		req->state = HTTP_SERVER_REQUEST_STATE_ABORTED;

	if (server->ioloop != NULL)
		io_loop_stop(server->ioloop);

	if (req->delay_destroy) {
		req->destroy_pending = TRUE;
	} else if (req->destroy_callback != NULL) {
		void (*callback)(void *) = req->destroy_callback;

		req->destroy_callback = NULL;
		callback(req->destroy_context);
	}
	http_server_request_unref(_req);
}

#undef http_server_request_set_destroy_callback
void http_server_request_set_destroy_callback(struct http_server_request *req,
					      void (*callback)(void *),
					      void *context)
{
	req->destroy_callback = callback;
	req->destroy_context = context;
}

void http_server_request_abort(struct http_server_request **_req,
			       const char *reason)
{
	struct http_server_request *req = *_req;
	struct http_server_connection *conn = req->conn;

	if (req->state >= HTTP_SERVER_REQUEST_STATE_FINISHED)
		return;

	e_debug(req->event, "Abort");

	req->conn = NULL;
	if (req->state < HTTP_SERVER_REQUEST_STATE_FINISHED) {
		if (conn != NULL) {
			http_server_connection_remove_request(conn, req);

			if (!conn->closed) {
				/* Send best-effort response if appropriate */
				if (!conn->output_locked &&
				    req->state >= HTTP_SERVER_REQUEST_STATE_PROCESSING &&
				    req->state < HTTP_SERVER_REQUEST_STATE_SENT_RESPONSE) {
					static const char *response =
						"HTTP/1.1 500 Internal Server Error\r\n"
						"Content-Length: 0\r\n"
						"\r\n";

					o_stream_nsend(conn->conn.output,
						       response, strlen(response));
					(void)o_stream_flush(conn->conn.output);
				}

				/* Close the connection */
				http_server_connection_close(&conn, reason);
			}
		}

		req->state = HTTP_SERVER_REQUEST_STATE_ABORTED;
	}

	if (req->response != NULL && !req->response->payload_blocking) {
		http_server_response_free(req->response);
		req->response = NULL;
	}

	http_server_request_destroy(_req);
}

const struct http_request *
http_server_request_get(struct http_server_request *req)
{
	return &req->req;
}

pool_t http_server_request_get_pool(struct http_server_request *req)
{
	return req->pool;
}

struct http_server_response *
http_server_request_get_response(struct http_server_request *req)
{
	return req->response;
}

int http_server_request_get_auth(struct http_server_request *req,
				 struct http_auth_credentials *credentials)
{
	const char *auth;

	auth = http_request_header_get(&req->req, "Authorization");
	if (auth == NULL)
		return 0;

	if (http_auth_parse_credentials((const unsigned char *)auth,
					strlen(auth), credentials) < 0)
		return -1;

	return 1;
}

bool http_server_request_is_finished(struct http_server_request *req)
{
	return (req->response != NULL ||
		req->state == HTTP_SERVER_REQUEST_STATE_ABORTED);
}

bool http_server_request_is_complete(struct http_server_request *req)
{
	return (req->failed || req->conn->input_broken ||
		(req->next != NULL && !http_server_request_is_new(req->next)) ||
		!http_server_connection_pending_payload(req->conn));
}

void http_server_request_halt_payload(struct http_server_request *req)
{
	i_assert(req->state <= HTTP_SERVER_REQUEST_STATE_QUEUED);
	req->payload_halted = TRUE;
}

void http_server_request_continue_payload(struct http_server_request *req)
{
	i_assert(req->state <= HTTP_SERVER_REQUEST_STATE_QUEUED);
	req->payload_halted = FALSE;
	if (req->req.expect_100_continue && !req->sent_100_continue)
		http_server_connection_output_trigger(req->conn);
}

static void
http_server_request_connect_callback(struct http_server_request *req)
{
	struct http_server_connection *conn = req->conn;

	if (conn->callbacks->handle_connect_request == NULL) {
		http_server_request_fail(req, 505, "Not Implemented");
		return;
	}

	if (req->req.target.format !=
	    HTTP_REQUEST_TARGET_FORMAT_AUTHORITY) {
		http_server_request_fail(req, 400, "Bad Request");
		return;
	}

	conn->callbacks->handle_connect_request(conn->context, req,
						req->req.target.url);
}

static void
http_server_request_default_handler(struct http_server_request *req)
{
	const struct http_request *hreq = &req->req;
	struct http_server_response *resp;

	if (strcmp(hreq->method, "OPTIONS") == 0 &&
	    hreq->target.format == HTTP_REQUEST_TARGET_FORMAT_ASTERISK) {
		resp = http_server_response_create(req, 200, "OK");
		http_server_response_submit(resp);
		return;
	}

	http_server_request_fail(req, 404, "Not Found");
	return;
}

void http_server_request_callback(struct http_server_request *req)
{
	struct http_server_connection *conn = req->conn;

	if (strcmp(req->req.method, "CONNECT") == 0) {
		/* CONNECT method */
		http_server_request_connect_callback(req);
		return;
	}

	if (http_server_resource_callback(req))
		return;

	if (array_count(&req->server->resources) > 0)
		e_debug(req->event, "No matching resource found");

	if (conn->callbacks->handle_request == NULL) {
		http_server_request_default_handler(req);
		return;
	}
	conn->callbacks->handle_request(conn->context, req);
}

void http_server_request_ready_to_respond(struct http_server_request *req)
{
	e_debug(req->event, "Ready to respond");

	req->state = HTTP_SERVER_REQUEST_STATE_READY_TO_RESPOND;
	http_server_connection_output_trigger(req->conn);
}

void http_server_request_submit_response(struct http_server_request *req)
{
	struct http_server_connection *conn = req->conn;

	i_assert(conn != NULL && req->response != NULL &&
		 req->response->submitted);

	http_server_request_ref(req);

	if (conn->payload_handler != NULL && conn->payload_handler->req == req)
		http_server_payload_handler_destroy(&conn->payload_handler);

	switch (req->state) {
	case HTTP_SERVER_REQUEST_STATE_NEW:
	case HTTP_SERVER_REQUEST_STATE_QUEUED:
	case HTTP_SERVER_REQUEST_STATE_PAYLOAD_IN:
	case HTTP_SERVER_REQUEST_STATE_PROCESSING:
	case HTTP_SERVER_REQUEST_STATE_SUBMITTED_RESPONSE:
		if (!http_server_request_is_complete(req)) {
			e_debug(req->event, "Not ready to respond");
			req->state = HTTP_SERVER_REQUEST_STATE_SUBMITTED_RESPONSE;
			break;
		}
		http_server_request_ready_to_respond(req);
		break;
	case HTTP_SERVER_REQUEST_STATE_READY_TO_RESPOND:
		http_server_connection_output_trigger(req->conn);
		break;
	case HTTP_SERVER_REQUEST_STATE_ABORTED:
		break;
	default:
		i_unreached();
	}

	http_server_request_unref(&req);
}

void http_server_request_finished(struct http_server_request *req)
{
	struct http_server_connection *conn = req->conn;
	struct http_server_response *resp = req->response;
	http_server_tunnel_callback_t tunnel_callback = resp->tunnel_callback;
	void *tunnel_context = resp->tunnel_context;

	e_debug(req->event, "Finished");

	i_assert(req->state < HTTP_SERVER_REQUEST_STATE_FINISHED);
	req->state = HTTP_SERVER_REQUEST_STATE_FINISHED;

	http_server_connection_remove_request(conn, req);
	conn->stats.response_count++;

	if (tunnel_callback == NULL) {
		if (req->connection_close) {
			http_server_connection_close(&conn,
				t_strdup_printf(
					"Server closed connection: %u %s",
					resp->status, resp->reason));
			http_server_request_destroy(&req);
			return;
		} else if (req->conn->input_broken) {
			http_server_connection_close(
				&conn, "Connection input is broken");
			http_server_request_destroy(&req);
			return;
		} else if (req->req.connection_close) {
			http_server_connection_close(
				&conn, "Client requested connection close");
			http_server_request_destroy(&req);
			return;
		}
	}

	http_server_request_destroy(&req);
	if (tunnel_callback != NULL) {
		http_server_connection_tunnel(&conn, tunnel_callback,
					      tunnel_context);
		return;
	}

	http_server_connection_output_trigger(conn);
}

static struct http_server_response *
http_server_request_create_fail_response(struct http_server_request *req,
					 unsigned int status,
					 const char *reason, const char *text)
					 ATTR_NULL(4)
{
	struct http_server_response *resp;

	req->failed = TRUE;

	i_assert(status / 100 != 1 && status != 204 && status != 304);

	resp = http_server_response_create(req, status, reason);
	if (!http_request_method_is(&req->req, "HEAD")) {
		http_server_response_add_header(resp, "Content-Type",
						"text/plain; charset=utf-8");
		if (text == NULL)
			text = reason;
		text = t_strconcat(text, "\r\n", NULL);
		http_server_response_set_payload_data(
			resp, (const unsigned char *)text, strlen(text));
	}

	return resp;
}

static void
http_server_request_fail_full(struct http_server_request *req,
			      unsigned int status, const char *reason,
			      const char *text) ATTR_NULL(4)
{
	struct http_server_response *resp;

	req->failed = TRUE;
	resp = http_server_request_create_fail_response(req, status, reason,
							text);
	http_server_response_submit(resp);
	if (req->conn->input_broken)
		req->connection_close = TRUE;
}

void http_server_request_fail(struct http_server_request *req,
			      unsigned int status, const char *reason)
{
	http_server_request_fail_full(req, status, reason, NULL);
}

void http_server_request_fail_close(struct http_server_request *req,
				    unsigned int status, const char *reason)
{
	http_server_request_connection_close(req, TRUE);
	http_server_request_fail_full(req, status, reason, NULL);
}

void http_server_request_fail_text(struct http_server_request *req,
				   unsigned int status, const char *reason,
				   const char *format, ...)
{
	va_list args;

	va_start(args, format);
	http_server_request_fail_full(req, status, reason,
		t_strdup_vprintf(format, args));
	va_end(args);
}

void http_server_request_fail_auth(struct http_server_request *req,
				   const char *reason,
				   const struct http_auth_challenge *chlng)
{
	struct http_server_response *resp;

	req->failed = TRUE;

	if (reason == NULL)
		reason = "Unauthenticated";

	resp = http_server_request_create_fail_response(req, 401, reason,
							reason);
	http_server_response_add_auth(resp, chlng);
	http_server_response_submit(resp);
}

void http_server_request_fail_auth_basic(struct http_server_request *req,
					 const char *reason, const char *realm)
{
	struct http_auth_challenge chlng;

	http_auth_basic_challenge_init(&chlng, realm);
	http_server_request_fail_auth(req, reason, &chlng);
}

void http_server_request_fail_bad_method(struct http_server_request *req,
					 const char *allow)
{
	struct http_server_response *resp;
	const char *reason = "Method Not Allowed";

	req->failed = TRUE;

	resp = http_server_request_create_fail_response(req, 405, reason,
							reason);
	http_server_response_add_header(resp, "Allow", allow);
	http_server_response_submit(resp);
}

/*
 * Payload input stream
 */

struct http_server_istream {
	struct istream_private istream;

	struct http_server_request *req;

	ssize_t read_status;
};

static void
http_server_istream_switch_ioloop_to(struct istream_private *stream,
				     struct ioloop *ioloop)
{
	struct http_server_istream *hsristream =
		(struct http_server_istream *)stream;

	if (hsristream->istream.istream.blocking)
		return;

	i_assert(ioloop == current_ioloop);
	http_server_connection_switch_ioloop(hsristream->req->conn);
}

static void
http_server_istream_read_any(struct http_server_istream *hsristream)
{
	struct istream_private *stream = &hsristream->istream;
	struct http_server *server = hsristream->req->server;
	ssize_t ret;

	if ((ret = i_stream_read_copy_from_parent(&stream->istream)) != 0) {
		hsristream->read_status = ret;
		io_loop_stop(server->ioloop);
	}
}

static ssize_t
http_server_istream_read(struct istream_private *stream)
{
	struct http_server_istream *hsristream =
		(struct http_server_istream *)stream;
	struct http_server_request *req = hsristream->req;
	struct http_server *server;
	struct http_server_connection *conn;
	bool blocking = stream->istream.blocking;
	ssize_t ret;

	if (req == NULL) {
		/* Request already gone (we shouldn't get here) */
		stream->istream.stream_errno = EINVAL;
		return -1;
	}

	i_stream_seek(stream->parent, stream->parent_start_offset +
		      stream->istream.v_offset);

	server = hsristream->req->server;
	conn = hsristream->req->conn;

	ret = i_stream_read_copy_from_parent(&stream->istream);
	if (ret == 0 && blocking) {
		struct ioloop *prev_ioloop = current_ioloop;
		struct io *io;

		http_server_connection_ref(conn);
		http_server_request_ref(req);

		i_assert(server->ioloop == NULL);
		server->ioloop = io_loop_create();
		http_server_connection_switch_ioloop(conn);

		if (blocking && req->req.expect_100_continue &&
		    !req->sent_100_continue)
			http_server_connection_output_trigger(conn);

		hsristream->read_status = 0;
		io = io_add_istream(&stream->istream,
				    http_server_istream_read_any, hsristream);
		while (req->state < HTTP_SERVER_REQUEST_STATE_FINISHED &&
			hsristream->read_status == 0) {
			io_loop_run(server->ioloop);
		}
		io_remove(&io);

		io_loop_set_current(prev_ioloop);
		http_server_connection_switch_ioloop(conn);
		io_loop_set_current(server->ioloop);
		io_loop_destroy(&server->ioloop);

		ret = hsristream->read_status;

		if (!http_server_request_unref(&req))
			hsristream->req = NULL;
		http_server_connection_unref(&conn);
	}

	return ret;
}

static void
http_server_istream_destroy(struct iostream_private *stream)
{
	struct http_server_istream *hsristream =
		(struct http_server_istream *)stream;
	uoff_t v_offset;

	v_offset = hsristream->istream.parent_start_offset +
		hsristream->istream.istream.v_offset;
	if (hsristream->istream.parent->seekable ||
	    v_offset > hsristream->istream.parent->v_offset) {
		/* Get to same position in parent stream */
		i_stream_seek(hsristream->istream.parent, v_offset);
	}
}

struct istream *
http_server_request_get_payload_input(struct http_server_request *req,
				      bool blocking)
{
	struct http_server_istream *hsristream;
	struct istream *payload = req->req.payload;

	i_assert(req->payload_input == NULL);

	hsristream = i_new(struct http_server_istream, 1);
	hsristream->req = req;
	hsristream->istream.max_buffer_size =
		payload->real_stream->max_buffer_size;
	hsristream->istream.stream_size_passthrough = TRUE;

	hsristream->istream.read = http_server_istream_read;
	hsristream->istream.switch_ioloop_to =
		http_server_istream_switch_ioloop_to;
	hsristream->istream.iostream.destroy = http_server_istream_destroy;

	hsristream->istream.istream.readable_fd = FALSE;
	hsristream->istream.istream.blocking = blocking;
	hsristream->istream.istream.seekable = FALSE;

	req->payload_input = i_stream_create(&hsristream->istream, payload,
					     i_stream_get_fd(payload), 0);
	i_stream_unref(&req->req.payload);
	return req->payload_input;
}

/*
 * Payload handling
 */

static void
http_server_payload_handler_init(struct http_server_payload_handler *handler,
				 struct http_server_request *req)
{
	struct http_server_connection *conn = req->conn;

	i_assert(conn->payload_handler == NULL);
	i_assert(conn->in_req_callback);

	conn->payload_handler = handler;

	handler->req = req;
}

void http_server_payload_handler_destroy(
	struct http_server_payload_handler **_handler)
{
	struct http_server_payload_handler *handler = *_handler;
	struct http_server_connection *conn = handler->req->conn;

	if (handler->in_callback) {
		/* Don't destroy handler while in callback */
		return;
	}

	*_handler = NULL;
	i_assert(conn->payload_handler == NULL);

	if (handler->destroy != NULL)
		handler->destroy(handler);
}

void http_server_payload_handler_switch_ioloop(
	struct http_server_payload_handler *handler, struct ioloop *ioloop)
{
	if (handler->switch_ioloop != NULL)
		handler->switch_ioloop(handler, ioloop);
}

/* Pump-based */

struct http_server_payload_handler_pump {
	struct http_server_payload_handler handler;

	struct iostream_pump *pump;

	void (*callback)(void *);
	void *context;
};

static void
payload_handler_pump_destroy(struct http_server_payload_handler *handler)
{
	struct http_server_payload_handler_pump *phandler =
		(struct http_server_payload_handler_pump *)handler;

	iostream_pump_unref(&phandler->pump);
}

static void
payload_handler_pump_switch_ioloop(struct http_server_payload_handler *handler,
				   struct ioloop *ioloop)
{
	struct http_server_payload_handler_pump *phandler =
		(struct http_server_payload_handler_pump *)handler;

	iostream_pump_switch_ioloop_to(phandler->pump, ioloop);
}

static void
payload_handler_pump_callback(enum iostream_pump_status status,
			      struct http_server_payload_handler_pump *phandler)
{
	struct http_server_payload_handler *handler = &phandler->handler;
	struct http_server_request *req = handler->req;
	struct http_server_connection *conn = req->conn;
	struct istream *input = iostream_pump_get_input(phandler->pump);
	struct ostream *output = iostream_pump_get_output(phandler->pump);

	switch (status) {
	case IOSTREAM_PUMP_STATUS_INPUT_EOF:
		if (!i_stream_read_eof(conn->incoming_payload)) {
			http_server_request_fail_close(req, 413,
						       "Payload Too Large");
		} else {
			unsigned int old_refcount = req->refcount;

			handler->in_callback = TRUE;
			phandler->callback(phandler->context);
			req->callback_refcount += req->refcount - old_refcount;
			handler->in_callback = FALSE;

			i_assert(req->callback_refcount > 0 ||
				 (req->response != NULL &&
				  req->response->submitted));
		}
		break;
	case IOSTREAM_PUMP_STATUS_INPUT_ERROR:
		http_server_request_client_error(
			req, "iostream_pump: read(%s) failed: %s",
			i_stream_get_name(input), i_stream_get_error(input));
		http_server_request_fail_close(req, 400, "Bad Request");
		break;
	case IOSTREAM_PUMP_STATUS_OUTPUT_ERROR:
		if (output->stream_errno != 0) {
			e_error(req->event,
				"iostream_pump: write(%s) failed: %s",
				o_stream_get_name(output),
				o_stream_get_error(output));
		}
		http_server_request_fail_close(req, 500,
					       "Internal Server Error");
		break;
	}

	if (conn->payload_handler != NULL)
		http_server_payload_handler_destroy(&conn->payload_handler);
}

#undef http_server_request_forward_payload
void http_server_request_forward_payload(struct http_server_request *req,
					 struct ostream *output,
					 uoff_t max_size,
					 void (*callback)(void *),
					 void *context)
{
	struct http_server_connection *conn = req->conn;
	struct istream *input = conn->incoming_payload;
	struct http_server_payload_handler_pump *phandler;
	uoff_t payload_size;
	int ret;

	i_assert(req->req.payload != NULL);

	if (max_size == (uoff_t)-1) {
		i_stream_ref(input);
	} else {
		if ((ret = i_stream_get_size(input, TRUE,
					     &payload_size)) != 0) {
			if (ret < 0) {
				e_error(req->event,
					"i_stream_get_size(%s) failed: %s",
					i_stream_get_name(input),
					i_stream_get_error(input));
				http_server_request_fail_close(
					req, 500, "Internal Server Error");
				return;
			}
			if (payload_size > max_size) {
				http_server_request_fail_close(
					req, 413, "Payload Too Large");
				return;
			}
		}
		input = i_stream_create_limit(input, max_size);
	}

	phandler = p_new(req->pool, struct http_server_payload_handler_pump, 1);
	http_server_payload_handler_init(&phandler->handler, req);
	phandler->handler.switch_ioloop = payload_handler_pump_switch_ioloop;
	phandler->handler.destroy = payload_handler_pump_destroy;
	phandler->callback = callback;
	phandler->context = context;

	phandler->pump = iostream_pump_create(input, output);
	iostream_pump_set_completion_callback(phandler->pump,
					      payload_handler_pump_callback,
					      phandler);
	iostream_pump_start(phandler->pump);
	i_stream_unref(&input);
}

#undef http_server_request_buffer_payload
void http_server_request_buffer_payload(struct http_server_request *req,
					buffer_t *buffer, uoff_t max_size,
					void (*callback)(void *),
					void *context)
{
	struct ostream *output;

	output = o_stream_create_buffer(buffer);
	http_server_request_forward_payload(req,
		output, max_size, callback, context);
	o_stream_unref(&output);
}

/* Raw */

struct http_server_payload_handler_raw {
	struct http_server_payload_handler handler;

	struct io *io;

	void (*callback)(void *context);
	void *context;
};

static void
payload_handler_raw_destroy(struct http_server_payload_handler *handler)
{
	struct http_server_payload_handler_raw *rhandler =
		(struct http_server_payload_handler_raw *)handler;

	io_remove(&rhandler->io);
}

static void
payload_handler_raw_switch_ioloop(struct http_server_payload_handler *handler,
				  struct ioloop *ioloop)
{
	struct http_server_payload_handler_raw *rhandler =
		(struct http_server_payload_handler_raw *)handler;

	rhandler->io = io_loop_move_io_to(ioloop, &rhandler->io);
}

static void
payload_handler_raw_input(struct http_server_payload_handler_raw *rhandler)
{
	struct http_server_payload_handler *handler = &rhandler->handler;
	struct http_server_request *req = handler->req;
	struct http_server_connection *conn = req->conn;
	struct istream *input = conn->incoming_payload;
	unsigned int old_refcount = req->refcount;

	handler->in_callback = TRUE;
	rhandler->callback(rhandler->context);
	req->callback_refcount += req->refcount - old_refcount;
	handler->in_callback = FALSE;

	if (input != NULL && input->stream_errno != 0) {
		if (req->response == NULL) {
			http_server_request_client_error(
				req, "read(%s) failed: %s",
				i_stream_get_name(input),
				i_stream_get_error(input));
			http_server_request_fail_close(req, 400, "Bad Request");
		}
	} else if (input == NULL || !i_stream_have_bytes_left(input)) {
		i_assert(req->callback_refcount > 0 ||
			 (req->response != NULL && req->response->submitted));
	} else {
		return;
	}

	if (conn->payload_handler != NULL)
		http_server_payload_handler_destroy(&conn->payload_handler);

}

#undef http_server_request_handle_payload
void http_server_request_handle_payload(struct http_server_request *req,
					void (*callback)(void *context),
					void *context)
{
	struct http_server_payload_handler_raw *rhandler;
	struct http_server_connection *conn = req->conn;

	rhandler = p_new(req->pool, struct http_server_payload_handler_raw, 1);
	http_server_payload_handler_init(&rhandler->handler, req);
	rhandler->handler.switch_ioloop = payload_handler_raw_switch_ioloop;
	rhandler->handler.destroy = payload_handler_raw_destroy;
	rhandler->callback = callback;
	rhandler->context = context;

	rhandler->io = io_add_istream(conn->incoming_payload,
				      payload_handler_raw_input, rhandler);
	i_stream_set_input_pending(conn->incoming_payload, TRUE);
}

void http_server_request_add_response_header(struct http_server_request *req,
					     const char *key, const char *value)
{
	struct http_server_response *resp;

	resp = http_server_response_create(req, 0, "");
	http_server_response_add_permanent_header(resp, key, value);
}
