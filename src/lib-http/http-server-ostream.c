/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "dns-lookup.h"
#include "ostream-wrapper.h"

#include "http-server-private.h"

/*
 * Payload output stream
 */

struct http_server_ostream {
	struct wrapper_ostream wostream;

	struct http_server_connection *conn;
	struct http_server_response *resp;

	bool response_destroyed:1;
};

static void http_server_ostream_output_error(struct wrapper_ostream *wostream)
{
	struct http_server_ostream *hsostream =
		(struct http_server_ostream *)wostream;
	struct http_server_connection *conn = hsostream->conn;

	if (hsostream->response_destroyed)
		return;

	i_assert(hsostream->resp != NULL);
	http_server_connection_handle_output_error(conn);
}

static void http_server_ostream_output_start(struct wrapper_ostream *wostream)
{
	struct http_server_ostream *hsostream =
		(struct http_server_ostream *)wostream;
	struct http_server_response *resp = hsostream->resp;

	i_assert(hsostream->response_destroyed || resp != NULL);

	if (!hsostream->response_destroyed &&
	    resp->request->state <= HTTP_SERVER_REQUEST_STATE_PROCESSING) {
		/* implicitly submit the request */
		http_server_response_submit(resp);
	}
}

void http_server_ostream_output_available(
	struct http_server_ostream *hsostream)
{
	struct http_server_response *resp = hsostream->resp;

	i_assert(resp != NULL);
	i_assert(!hsostream->response_destroyed);
	wrapper_ostream_output_available(&hsostream->wostream,
					 resp->payload_output);
}

static bool http_server_ostream_output_ready(struct wrapper_ostream *wostream)
{
	struct http_server_ostream *hsostream =
		(struct http_server_ostream *)wostream;
	struct http_server_response *resp = hsostream->resp;

	i_assert(resp != NULL);
	i_assert(!hsostream->response_destroyed);
	return (resp->request->state >= HTTP_SERVER_REQUEST_STATE_PAYLOAD_OUT);
}

static int http_server_ostream_output_finish(struct wrapper_ostream *wostream)
{
	struct http_server_ostream *hsostream =
		(struct http_server_ostream *)wostream;
	struct http_server_response *resp = hsostream->resp;

	i_assert(resp != NULL);
	i_assert(!hsostream->response_destroyed);

	e_debug(wostream->event, "Finished response payload stream");

	/* finished sending payload */
	return http_server_response_finish_payload_out(resp);
}

static void http_server_ostream_output_halt(struct wrapper_ostream *wostream)
{
	struct http_server_ostream *hsostream =
		(struct http_server_ostream *)wostream;
	struct http_server_connection *conn = hsostream->conn;
	struct http_server_response *resp = hsostream->resp;

	i_assert(hsostream->response_destroyed || resp != NULL);

	if (hsostream->response_destroyed ||
	    resp->request->state < HTTP_SERVER_REQUEST_STATE_PAYLOAD_OUT)
		return;

	http_server_connection_output_halt(conn);
}

static void http_server_ostream_output_resume(struct wrapper_ostream *wostream)
{
	struct http_server_ostream *hsostream =
		(struct http_server_ostream *)wostream;
	struct http_server_connection *conn = hsostream->conn;

	if (hsostream->response_destroyed)
		return;
	i_assert(hsostream->resp != NULL);

	http_server_connection_output_resume(conn);
}

static void
http_server_ostream_output_update_timeouts(struct wrapper_ostream *wostream,
					   bool sender_blocking)
{
	struct http_server_ostream *hsostream =
		(struct http_server_ostream *)wostream;
	struct http_server_connection *conn = hsostream->conn;

	if (hsostream->response_destroyed)
		return;
	i_assert(hsostream->resp != NULL);

	if (sender_blocking) {
		http_server_connection_stop_idle_timeout(conn);
		return;
	}

	http_server_connection_start_idle_timeout(conn);
}

static void http_server_ostream_close(struct wrapper_ostream *wostream)
{
	struct http_server_ostream *hsostream =
		(struct http_server_ostream *)wostream;
	struct http_server_response *resp = hsostream->resp;

	e_debug(wostream->event, "Response payload stream closed");

	if (hsostream->response_destroyed) {
		http_server_response_unref(&hsostream->resp);
		return;
	}
	hsostream->response_destroyed = TRUE;

	i_assert(resp != NULL);
	(void)http_server_response_finish_payload_out(resp);
	resp->payload_stream = NULL;
	http_server_response_unref(&hsostream->resp);
}

static void http_server_ostream_destroy(struct wrapper_ostream *wostream)
{
	struct http_server_ostream *hsostream =
		(struct http_server_ostream *)wostream;
	struct http_server_response *resp = hsostream->resp;
	struct http_server_request *req;

	e_debug(wostream->event, "Response payload stream destroyed");

	if (hsostream->response_destroyed) {
		http_server_response_unref(&hsostream->resp);
		return;
	}
	hsostream->response_destroyed = TRUE;
	i_assert(resp != NULL);

	req = resp->request;
	resp->payload_stream = NULL;
	http_server_request_abort(
		&req, "Response output stream destroyed prematurely");
}

static struct ioloop *
http_server_ostream_wait_begin(struct wrapper_ostream *wostream,
			       struct ioloop *ioloop)
{
	struct http_server_ostream *hsostream =
		(struct http_server_ostream *)wostream;
	struct http_server_connection *conn = hsostream->conn;
	struct ioloop *prev_ioloop;

	i_assert(hsostream->resp != NULL);
	i_assert(!hsostream->response_destroyed);

	http_server_connection_ref(conn);

	/* When the response payload output stream is written from inside the
	   request callback, the incoming payload stream is not destroyed yet,
	   even though it is read to the end. This could lead to problems, so we
	   make an effort to destroy it here.
	 */
	if (conn->incoming_payload != NULL) {
		struct http_server_request *req = hsostream->resp->request;
		struct istream *payload;

		if (!i_stream_read_eof(conn->incoming_payload))
			i_unreached();
		payload = req->req.payload;
		req->req.payload = NULL;
		i_stream_unref(&payload);

		i_assert(conn->incoming_payload == NULL);
	}

	prev_ioloop = http_server_connection_switch_ioloop_to(conn, ioloop);
	return prev_ioloop;
}

static void
http_server_ostream_wait_end(struct wrapper_ostream *wostream,
			     struct ioloop *prev_ioloop)
{
	struct http_server_ostream *hsostream =
		(struct http_server_ostream *)wostream;
	struct http_server_connection *conn = hsostream->conn;

	(void)http_server_connection_switch_ioloop_to(conn, prev_ioloop);
	http_server_connection_unref(&conn);
}

void http_server_ostream_continue(struct http_server_ostream *hsostream)
{
	struct wrapper_ostream *wostream = &hsostream->wostream;
	struct http_server_response *resp = hsostream->resp;

	i_assert(hsostream->response_destroyed || resp != NULL);

	i_assert(hsostream->response_destroyed ||
		 resp->request->state >= HTTP_SERVER_REQUEST_STATE_PAYLOAD_OUT);

	wrapper_ostream_continue(wostream);
}

bool http_server_ostream_get_size(struct http_server_ostream *hsostream,
				  uoff_t *size_r)
{
	return wrapper_ostream_get_buffered_size(&hsostream->wostream, size_r);
}

static void
http_server_ostream_switch_ioloop_to(struct wrapper_ostream *wostream,
				     struct ioloop *ioloop)
{
	struct http_server_ostream *hsostream =
		(struct http_server_ostream *)wostream;
	struct http_server_connection *conn = hsostream->conn;

	if (hsostream->response_destroyed)
		return;
	i_assert(hsostream->resp != NULL);

	http_server_connection_switch_ioloop_to(conn, ioloop);
}

struct ostream *
http_server_ostream_create(struct http_server_response *resp,
			   size_t max_buffer_size, bool blocking)
{
	struct http_server_ostream *hsostream;

	i_assert(resp->payload_stream == NULL);

	hsostream = i_new(struct http_server_ostream, 1);

	resp->payload_stream = hsostream;
	http_server_response_ref(resp);
	hsostream->conn = resp->request->conn;
	hsostream->resp = resp;

	hsostream->wostream.output_start = http_server_ostream_output_start;
	hsostream->wostream.output_ready = http_server_ostream_output_ready;
	hsostream->wostream.output_error = http_server_ostream_output_error;
	hsostream->wostream.output_finish = http_server_ostream_output_finish;
	hsostream->wostream.output_halt = http_server_ostream_output_halt;
	hsostream->wostream.output_resume = http_server_ostream_output_resume;
	hsostream->wostream.output_update_timeouts =
		http_server_ostream_output_update_timeouts;

	hsostream->wostream.wait_begin = http_server_ostream_wait_begin;
	hsostream->wostream.wait_end = http_server_ostream_wait_end;

	hsostream->wostream.switch_ioloop_to =
		http_server_ostream_switch_ioloop_to;

	hsostream->wostream.close = http_server_ostream_close;
	hsostream->wostream.destroy = http_server_ostream_destroy;

	return wrapper_ostream_create(&hsostream->wostream, max_buffer_size,
				      blocking, resp->event);
}

void http_server_ostream_response_destroyed(
	struct http_server_ostream *hsostream)
{
	i_assert(hsostream->resp != NULL);
	hsostream->resp->payload_stream = NULL;

	e_debug(hsostream->wostream.event,
		"Response payload parent stream lost");

	hsostream->response_destroyed = TRUE;
	wrapper_ostream_output_destroyed(&hsostream->wostream);
	wrapper_ostream_notify_error(&hsostream->wostream);
}

struct ostream *
http_server_ostream_get_output(struct http_server_ostream *hsostream)
{
	return &hsostream->wostream.ostream.ostream;
}

void http_server_ostream_set_error(struct http_server_ostream *hsostream,
				   int stream_errno, const char *stream_error)
{
	wrapper_ostream_set_error(&hsostream->wostream, stream_errno,
				  stream_error);
}
