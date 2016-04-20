/* Copyright (c) 2013-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "ostream.h"
#include "istream-private.h"

#include "http-server-private.h"

/*
 * Logging
 */

static inline void
http_server_request_debug(struct http_server_request *req,
	const char *format, ...) ATTR_FORMAT(2, 3);

static inline void
http_server_request_debug(struct http_server_request *req,
	const char *format, ...)
{
	struct http_server *server = req->server;
	va_list args;

	if (server->set.debug) {
		va_start(args, format);
		i_debug("http-server: request %s: %s",
			http_server_request_label(req),
			t_strdup_vprintf(format, args));
		va_end(args);
	}
}

/*
 * Request
 */

struct http_server_request *
http_server_request_new(struct http_server_connection *conn)
{
	static unsigned int id_counter = 0;
	pool_t pool;
	struct http_server_request *req;

	pool = pool_alloconly_create(MEMPOOL_GROWING"http_server_request", 4096);
	req = p_new(pool, struct http_server_request, 1);
	req->pool = pool;
	req->refcount = 1;
	req->conn = conn;
	req->server = conn->server;
	req->id = ++id_counter;

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

	http_server_request_debug(req, "Free");

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
	pool_unref(&req->pool);
	return FALSE;
}

void http_server_request_destroy(struct http_server_request **_req)
{
	struct http_server_request *req = *_req;
	struct http_server *server = req->server;

	http_server_request_debug(req, "Destroy");

	/* just make sure the request ends in a proper state */
	if (req->state < HTTP_SERVER_REQUEST_STATE_FINISHED)
		req->state = HTTP_SERVER_REQUEST_STATE_ABORTED;

	if (server->ioloop)
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

	http_server_request_debug(req, "Abort");

	req->conn = NULL;
	if (req->state < HTTP_SERVER_REQUEST_STATE_FINISHED) {
		if (conn != NULL) {
			http_server_connection_remove_request(conn, req);

			if (!conn->closed) {
				/* send best-effort response if appropriate */
				if (!conn->output_locked &&
					req->state >= HTTP_SERVER_REQUEST_STATE_PROCESSING &&
					req->state < HTTP_SERVER_REQUEST_STATE_SENT_RESPONSE) {
					static const char *response =
						"HTTP/1.1 500 Internal Server Error\r\n"
						"Content-Length: 0\r\n"
						"\r\n";

					(void)o_stream_send(conn->conn.output,
						response, strlen(response));
				}

				/* close the connection */
				http_server_connection_close(&conn, reason);
			}
		}

		req->state = HTTP_SERVER_REQUEST_STATE_ABORTED;
	}
	
	if (req->response != NULL &&
		!req->response->payload_blocking) {
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

pool_t
http_server_request_get_pool(struct http_server_request *req)
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

	if (http_auth_parse_credentials
		((const unsigned char *)auth, strlen(auth), credentials) < 0)
		return -1;
	
	return 1;
}

bool http_server_request_is_finished(struct http_server_request *req)
{
	return req->response != NULL ||
		req->state == HTTP_SERVER_REQUEST_STATE_ABORTED;
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
		http_server_connection_trigger_responses(req->conn);
}

void http_server_request_ready_to_respond(struct http_server_request *req)
{
	http_server_request_debug(req, "Ready to respond");

	req->state = HTTP_SERVER_REQUEST_STATE_READY_TO_RESPOND;
	http_server_connection_trigger_responses(req->conn);
}

void http_server_request_submit_response(struct http_server_request *req)
{
	struct http_server_connection *conn = req->conn;

	i_assert(conn != NULL && req->response != NULL && req->response->submitted);

	switch (req->state) {
	case HTTP_SERVER_REQUEST_STATE_NEW:
	case HTTP_SERVER_REQUEST_STATE_QUEUED:
	case HTTP_SERVER_REQUEST_STATE_PAYLOAD_IN:
	case HTTP_SERVER_REQUEST_STATE_PROCESSING:
		if (!http_server_request_is_complete(req)) {
			http_server_request_debug(req, "Not ready to respond");
			req->state = HTTP_SERVER_REQUEST_STATE_SUBMITTED_RESPONSE;
			break;
		}
		http_server_request_ready_to_respond(req);
		break;
	case HTTP_SERVER_REQUEST_STATE_ABORTED:
		break;
	default:
		i_unreached();
	}
}

void http_server_request_finished(struct http_server_request *req)
{
	struct http_server_connection *conn = req->conn;
	struct http_server_response *resp = req->response;
	http_server_tunnel_callback_t tunnel_callback = resp->tunnel_callback;
	void *tunnel_context = resp->tunnel_context;

	http_server_request_debug(req, "Finished");

	i_assert(req->state < HTTP_SERVER_REQUEST_STATE_FINISHED);
	req->state = HTTP_SERVER_REQUEST_STATE_FINISHED;

	http_server_connection_remove_request(conn, req);
	conn->stats.response_count++;

	if (tunnel_callback == NULL && (req->req.connection_close || resp->close)) {
		if (resp->close) {
			http_server_connection_close(&conn,
				t_strdup_printf("Server closed connection: %u %s",
					resp->status, resp->reason));
			
		} else {
			http_server_connection_close(&conn,
				"Client requested connection close");
		}
		http_server_request_destroy(&req);
		return;
	}

	http_server_request_destroy(&req);
	if (tunnel_callback != NULL) {
		http_server_connection_tunnel(&conn, tunnel_callback, tunnel_context);
		return;
	}
	
	http_server_connection_trigger_responses(conn);
}

static 	struct http_server_response *
http_server_request_create_fail_response(struct http_server_request *req,
	unsigned int status, const char *reason)
{
	struct http_server_response *resp;

	req->failed = TRUE;

	resp = http_server_response_create(req, status, reason);
	http_server_response_add_header
		(resp, "Content-Type", "text/plain; charset=utf-8");
	reason = t_strconcat(reason, "\r\n", NULL);
	http_server_response_set_payload_data
		(resp, (const unsigned char *)reason, strlen(reason));

	return resp;
}

static void
http_server_request_fail_full(struct http_server_request *req,
	unsigned int status, const char *reason, bool close)
{
	struct http_server_response *resp;

	req->failed = TRUE;
	resp = http_server_request_create_fail_response(req, status, reason);
	if (close)
		http_server_response_submit_close(resp);
	else
		http_server_response_submit(resp);
}

void http_server_request_fail(struct http_server_request *req,
	unsigned int status, const char *reason)
{
	http_server_request_fail_full(req, status, reason,
				      req->conn->input_broken);
}

void http_server_request_fail_close(struct http_server_request *req,
	unsigned int status, const char *reason)
{
	http_server_request_fail_full(req, status, reason, TRUE);
}

void http_server_request_fail_auth(struct http_server_request *req,
	const char *reason, const struct http_auth_challenge *chlng)
{
	struct http_server_response *resp;

	req->failed = TRUE;

	if (reason == NULL)
		reason = "Unauthenticated";

	resp = http_server_request_create_fail_response(req, 401, reason);
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

/*
 * Payload input stream
 */

struct http_server_istream {
	struct istream_private istream;

	struct http_server_request *req;

	ssize_t read_status;
};

static void
http_server_istream_switch_ioloop(struct istream_private *stream)
{
	struct http_server_istream *hsristream =
		(struct http_server_istream *)stream;

	if (hsristream->istream.istream.blocking)
		return;

	http_server_connection_switch_ioloop(hsristream->req->conn);
}

static void
http_server_istream_read_any(struct http_server_istream *hsristream)
{
	struct istream_private *stream = &hsristream->istream;
	struct http_server *server = hsristream->req->server;
	ssize_t ret;

	if ((ret=i_stream_read_copy_from_parent
		(&stream->istream)) > 0) {
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
		/* request already gone (we shouldn't get here) */
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
			http_server_connection_trigger_responses(conn);

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
		/* get to same position in parent stream */
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
	hsristream->istream.switch_ioloop = http_server_istream_switch_ioloop;
	hsristream->istream.iostream.destroy = http_server_istream_destroy;

	hsristream->istream.istream.readable_fd = FALSE;
	hsristream->istream.istream.blocking = blocking;
	hsristream->istream.istream.seekable = FALSE;

	req->payload_input = i_stream_create
		(&hsristream->istream, payload, i_stream_get_fd(payload));
	i_stream_unref(&req->req.payload);
	return req->payload_input;
}
