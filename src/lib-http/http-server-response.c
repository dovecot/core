/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "array.h"
#include "istream.h"
#include "ostream-private.h"
#include "http-date.h"
#include "http-transfer.h"
#include "http-server-private.h"

struct http_server_response_payload {
	struct http_server_response *resp;
	struct const_iovec *iov;
	unsigned int iov_count, iov_idx;
	size_t iov_pos;
};

/*
 * Response
 */

static void http_server_response_update_event(struct http_server_response *resp)
{
	event_add_int(resp->event, "status", resp->status);
	event_set_append_log_prefix(resp->event,
				    t_strdup_printf("%u response: ",
						    resp->status));
}

struct http_server_response *
http_server_response_create(struct http_server_request *req,
			    unsigned int status, const char *reason)
{
	struct http_server_response *resp;

	i_assert(req->state < HTTP_SERVER_REQUEST_STATE_SENT_RESPONSE);

	if (req->response == NULL) {
		resp = req->response = p_new(req->pool,
					     struct http_server_response, 1);
	} else {
		/* Was already composing a response, but decided to
		   start a new one (would usually be a failure response)
		 */
		resp = req->response;

		ARRAY_TYPE(string) perm_headers = resp->perm_headers;
		i_zero(&resp->perm_headers);

		http_server_response_request_free(resp);
		i_zero(resp);

		resp->perm_headers = perm_headers;
	}

	resp->request = req;
	resp->status = status;
	resp->reason = p_strdup(req->pool, reason);
	resp->headers = str_new(default_pool, 256);
	resp->date = (time_t)-1;
	resp->event = event_create(req->event);
	http_server_response_update_event(resp);

	if (array_is_created(&resp->perm_headers)) {
		unsigned int i, count;
		char *const *headers = array_get(&resp->perm_headers, &count);
		for (i = 0; i < count; i += 2)
			http_server_response_add_header(resp, headers[i],
							headers[i+1]);
	}
	return resp;
}

void http_server_response_request_free(struct http_server_response *resp)
{
	e_debug(resp->event, "Free");

	i_assert(!resp->payload_blocking);

	i_stream_unref(&resp->payload_input);
	o_stream_unref(&resp->payload_output);
	event_unref(&resp->event);
	str_free(&resp->headers);

	if (array_is_created(&resp->perm_headers)) {
		char **headers;

		array_foreach_modifiable(&resp->perm_headers, headers)
			i_free(*headers);
		array_free(&resp->perm_headers);
	}
}

void http_server_response_request_destroy(struct http_server_response *resp)
{
	e_debug(resp->event, "Destroy");
}

void http_server_response_ref(struct http_server_response *resp)
{
	http_server_request_ref(resp->request);
}

bool http_server_response_unref(struct http_server_response **_resp)
{
	struct http_server_response *resp = *_resp;
	struct http_server_request *req;

	*_resp = NULL;
	if (resp == NULL)
		return FALSE;

	req = resp->request;
	return http_server_request_unref(&req);
}

void http_server_response_add_header(struct http_server_response *resp,
				     const char *key, const char *value)
{
	i_assert(!resp->submitted);
	i_assert(strchr(key, '\r') == NULL && strchr(key, '\n') == NULL);
	i_assert(strchr(value, '\r') == NULL && strchr(value, '\n') == NULL);

	/* Mark presence of special headers */
	switch (key[0]) {
	case 'c': case 'C':
		if (strcasecmp(key, "Connection") == 0)
			resp->have_hdr_connection = TRUE;
		else 	if (strcasecmp(key, "Content-Length") == 0)
			resp->have_hdr_body_spec = TRUE;
		break;
	case 'd': case 'D':
		if (strcasecmp(key, "Date") == 0)
			resp->have_hdr_date = TRUE;
		break;
	case 't': case 'T':
		if (strcasecmp(key, "Transfer-Encoding") == 0)
			resp->have_hdr_body_spec = TRUE;
		break;
	}
	str_printfa(resp->headers, "%s: %s\r\n", key, value);
}

void http_server_response_update_status(struct http_server_response *resp,
					unsigned int status,
					const char *reason)
{
	i_assert(!resp->submitted);
	resp->status = status;
	/* Free not called because pool is alloconly */
	resp->reason = p_strdup(resp->request->pool, reason);
}

void http_server_response_set_date(struct http_server_response *resp,
				   time_t date)
{
	i_assert(!resp->submitted);

	resp->date = date;
}

void http_server_response_set_payload(struct http_server_response *resp,
				      struct istream *input)
{
	int ret;

	i_assert(!resp->submitted);
	i_assert(resp->blocking_output == NULL);
	i_assert(resp->payload_input == NULL);

	i_stream_ref(input);
	resp->payload_input = input;
	if ((ret = i_stream_get_size(input, TRUE, &resp->payload_size)) <= 0) {
		if (ret < 0) {
			e_error(resp->event, "i_stream_get_size(%s) failed: %s",
				i_stream_get_name(input),
				i_stream_get_error(input));
		}
		resp->payload_size = 0;
		resp->payload_chunked = TRUE;
	}
	resp->payload_offset = input->v_offset;
}

void http_server_response_set_payload_data(struct http_server_response *resp,
					   const unsigned char *data,
					   size_t size)
{
	struct istream *input;
	unsigned char *payload_data;

	if (size == 0)
		return;

	payload_data = p_malloc(resp->request->pool, size);
	memcpy(payload_data, data, size);
	input = i_stream_create_from_data(payload_data, size);

	http_server_response_set_payload(resp, input);
	i_stream_unref(&input);
}

void http_server_response_add_auth(struct http_server_response *resp,
				   const struct http_auth_challenge *chlng)
{
	struct http_auth_challenge *new;
	pool_t pool = resp->request->pool;

	if (!array_is_created(&resp->auth_challenges))
		p_array_init(&resp->auth_challenges, pool, 4);

	new = array_append_space(&resp->auth_challenges);
	http_auth_challenge_copy(pool, new, chlng);
}

void http_server_response_add_auth_basic(struct http_server_response *resp,
					 const char *realm)
{
	struct http_auth_challenge chlng;

	http_auth_basic_challenge_init(&chlng, realm);
	http_server_response_add_auth(resp, &chlng);
}

static void
http_server_response_do_submit(struct http_server_response *resp)
{
	i_assert(!resp->submitted);
	if (resp->date == (time_t)-1)
		resp->date = ioloop_time;
	resp->submitted = TRUE;
	http_server_request_submit_response(resp->request);
}

void http_server_response_submit(struct http_server_response *resp)
{
	e_debug(resp->event, "Submitted");

	http_server_response_do_submit(resp);
}

void http_server_response_submit_close(struct http_server_response *resp)
{
	http_server_request_connection_close(resp->request, TRUE);
	http_server_response_submit(resp);
}

void http_server_response_submit_tunnel(struct http_server_response *resp,
					http_server_tunnel_callback_t callback,
					void *context)
{
	e_debug(resp->event, "Started tunnelling");

	resp->tunnel_callback = callback;
	resp->tunnel_context = context;
	http_server_request_connection_close(resp->request, TRUE);
	http_server_response_do_submit(resp);
}

static int
http_server_response_flush_payload(struct http_server_response *resp)
{
	struct http_server_request *req = resp->request;
	struct http_server_connection *conn = req->conn;
	int ret;

	if (resp->payload_output != conn->conn.output &&
	    (ret = o_stream_finish(resp->payload_output)) <= 0) {
		if (ret < 0)
			http_server_connection_handle_output_error(conn);
		else
			http_server_connection_start_idle_timeout(conn);
		return ret;
	}

	return 1;
}

int http_server_response_finish_payload_out(struct http_server_response *resp)
{
	struct http_server_connection *conn = resp->request->conn;
	int ret;

	resp->payload_finished = TRUE;

	if (resp->payload_output != NULL) {
		ret = http_server_response_flush_payload(resp);
		if (ret < 0)
			return -1;
		if (ret == 0) {
			e_debug(resp->event,
				"Not quite finished sending payload");
			return 0;
		}
		o_stream_unref(&resp->payload_output);
		resp->payload_output = NULL;
	}

	e_debug(resp->event, "Finished sending payload");

	http_server_connection_ref(conn);
	conn->output_locked = FALSE;
	if (conn->conn.output != NULL && !conn->conn.output->closed) {
		if (resp->payload_corked &&
			o_stream_uncork_flush(conn->conn.output) < 0)
			http_server_connection_handle_output_error(conn);
		o_stream_set_flush_callback(conn->conn.output,
					    http_server_connection_output,
					    conn);
	}

	if (conn->request_queue_head == NULL ||
	    (conn->request_queue_head->state !=
	     HTTP_SERVER_REQUEST_STATE_PROCESSING))
		http_server_connection_start_idle_timeout(conn);

	http_server_request_finished(resp->request);
	http_server_connection_unref(&conn);
	return 1;
}

static int
http_server_response_output_direct(struct http_server_response_payload *rpay)
{
	struct http_server_response *resp = rpay->resp;
	struct http_server_connection *conn = resp->request->conn;
	struct http_server *server = resp->request->server;
	struct ostream *output = resp->payload_output;
	struct const_iovec *iov;
	unsigned int iov_count, i;
	size_t bytes_left, block_len;
	ssize_t ret;

	if (http_server_connection_flush(conn) < 0)
		return -1;

	iov = &rpay->iov[rpay->iov_idx];
	iov_count = rpay->iov_count - rpay->iov_idx;

	if ((ret = o_stream_sendv(output, iov, iov_count)) < 0) {
		http_server_connection_handle_output_error(conn);
		return -1;
	}
	if (ret > 0) {
		bytes_left = ret;
		for (i = 0; i < iov_count && bytes_left > 0; i++) {
			block_len = (iov[i].iov_len <= bytes_left ?
				     iov[i].iov_len : bytes_left);
			bytes_left -= block_len;
		}
		rpay->iov_idx += i;
		if (i < iov_count) {
			i_assert(iov[i].iov_len > bytes_left);
			iov[i].iov_base = PTR_OFFSET(
				iov[i].iov_base, iov[i].iov_len - bytes_left);
			iov[i].iov_len = bytes_left;
		} else {
			i_assert(rpay->iov_idx == rpay->iov_count);
			i_assert(server->ioloop != NULL);
			io_loop_stop(server->ioloop);
		}
	}
	return 1;
}

static int
http_server_response_output_payload(struct http_server_response **_resp,
				    const struct const_iovec *iov,
				    unsigned int iov_count)
{
	struct ioloop *prev_ioloop = current_ioloop;
	struct http_server_response *resp = *_resp;
	struct http_server_request *req = resp->request;
	struct http_server *server = req->server;
	struct http_server_connection *conn = req->conn;
	struct http_server_response_payload rpay;
	int ret;

	i_assert(req->state < HTTP_SERVER_REQUEST_STATE_SUBMITTED_RESPONSE ||
		 req->state == HTTP_SERVER_REQUEST_STATE_PAYLOAD_OUT);
	i_assert(resp->payload_input == NULL);

	/* Discard any remaining incoming payload */
	if (http_server_connection_discard_payload(conn) < 0)
		return -1;
	req->req.payload = NULL;

	http_server_connection_ref(conn);
	http_server_request_ref(req);
	resp->payload_blocking = TRUE;

	i_zero(&rpay);
	rpay.resp = resp;

	if (iov == NULL) {
		resp->payload_direct = FALSE;
		if (req->state == HTTP_SERVER_REQUEST_STATE_PAYLOAD_OUT)
			(void)http_server_response_finish_payload_out(resp);
	} else {
		resp->payload_direct = TRUE;
		rpay.iov = i_new(struct const_iovec, iov_count);
		memcpy(rpay.iov, iov, sizeof(*iov)*iov_count);
		rpay.iov_count = iov_count;
	}

	resp->payload_size = 0;
	resp->payload_chunked = TRUE;

	if (req->state < HTTP_SERVER_REQUEST_STATE_SUBMITTED_RESPONSE)
		http_server_response_submit(resp);

	if (req->state < HTTP_SERVER_REQUEST_STATE_FINISHED) {
		/* Wait for payload data to be written */

		i_assert(server->ioloop == NULL);
		server->ioloop = io_loop_create();
		http_server_connection_switch_ioloop(conn);

		do {
			if (req->state < HTTP_SERVER_REQUEST_STATE_PAYLOAD_OUT) {
				e_debug(resp->event,
					"Preparing to send blocking payload");
				http_server_connection_output_trigger(conn);
			} else if (resp->payload_output != NULL) {
				e_debug(resp->event,
					"Sending blocking payload");
				o_stream_unset_flush_callback(conn->conn.output);
				o_stream_set_flush_callback(
					resp->payload_output,
					http_server_response_output_direct,
					&rpay);
				o_stream_set_flush_pending(resp->payload_output,
							   TRUE);
			} else {
				http_server_response_finish_payload_out(resp);
				i_assert(req->state >=
					 HTTP_SERVER_REQUEST_STATE_FINISHED);
				break;
			}

			io_loop_run(server->ioloop);

			if (rpay.iov_count > 0 && rpay.iov_idx >= rpay.iov_count)
				break;
		} while (req->state < HTTP_SERVER_REQUEST_STATE_FINISHED);

		io_loop_set_current(prev_ioloop);
		http_server_connection_switch_ioloop(conn);
		io_loop_set_current(server->ioloop);
		io_loop_destroy(&server->ioloop);
	}

	switch (req->state) {
	case HTTP_SERVER_REQUEST_STATE_FINISHED:
		ret = 1;
		break;
	case HTTP_SERVER_REQUEST_STATE_ABORTED:
		e_debug(resp->event,
			"Request aborted while sending blocking payload");
		ret = -1;
		break;
	default:
		ret = 0;
		break;
	}

	resp->payload_blocking = FALSE;
	resp->payload_direct = FALSE;

	/* Callback may have messed with our pointer, so unref using local
	   variable */
	if (!http_server_request_unref(&req))
		*_resp = NULL;

	http_server_connection_unref(&conn);
	i_free(rpay.iov);

	/* Return status */
	return ret;
}

int http_server_response_send_payload(struct http_server_response **_resp,
				      const unsigned char *data, size_t size)
{
	struct http_server_response *resp = *_resp;
	struct const_iovec iov;
	int ret;

	i_assert(resp->blocking_output == NULL);

	resp->payload_corked = TRUE;

	i_assert(data != NULL);

	i_zero(&iov);
	iov.iov_base = data;
	iov.iov_len = size;
	ret = http_server_response_output_payload(&resp, &iov, 1);
	if (ret < 0)
		*_resp = NULL;
	else {
		i_assert(ret == 0);
		i_assert(resp != NULL);
	}
	return ret;
}

int http_server_response_finish_payload(struct http_server_response **_resp)
{
	struct http_server_response *resp = *_resp;
	int ret;

	i_assert(resp->blocking_output == NULL);

	*_resp = NULL;
	ret = http_server_response_output_payload(&resp, NULL, 0);
	i_assert(ret != 0);
	return ret < 0 ? -1 : 0;
}

void http_server_response_abort_payload(struct http_server_response **_resp)
{
	struct http_server_response *resp = *_resp;
	struct http_server_request *req = resp->request;

	*_resp = NULL;

	http_server_request_abort(&req, "Aborted sending response payload");
}

static void
http_server_response_payload_input(struct http_server_response *resp)
{
	struct http_server_connection *conn = resp->request->conn;

	io_remove(&conn->io_resp_payload);

	(void)http_server_connection_output(conn);
}

int http_server_response_send_more(struct http_server_response *resp)
{
	struct http_server_connection *conn = resp->request->conn;
	struct ostream *output = resp->payload_output;
	enum ostream_send_istream_result res;
	int ret = 0;

	i_assert(!resp->payload_blocking);
	i_assert(resp->payload_input != NULL);
	i_assert(resp->payload_output != NULL);

	if (resp->payload_finished)
		return http_server_response_finish_payload_out(resp);

	io_remove(&conn->io_resp_payload);

	/* Chunked ostream needs to write to the parent stream's buffer */
	o_stream_set_max_buffer_size(output, IO_BLOCK_SIZE);
	res = o_stream_send_istream(output, resp->payload_input);
	o_stream_set_max_buffer_size(output, (size_t)-1);

	switch (res) {
	case OSTREAM_SEND_ISTREAM_RESULT_FINISHED:
		/* Finished sending */
		if (!resp->payload_chunked &&
		    (resp->payload_input->v_offset - resp->payload_offset) !=
			resp->payload_size) {
			e_error(resp->event,
				"Payload stream %s size changed unexpectedly",
				i_stream_get_name(resp->payload_input));
			http_server_connection_close(
				&conn, "Payload read failure");
			ret = -1;
		} else {
			ret = 1;
		}
		break;
	case OSTREAM_SEND_ISTREAM_RESULT_WAIT_INPUT:
		/* Input is blocking (server needs to act; disable timeout) */
		conn->output_locked = TRUE;
		http_server_connection_stop_idle_timeout(conn);
		conn->io_resp_payload = io_add_istream(resp->payload_input,
			http_server_response_payload_input, resp);
		break;
	case OSTREAM_SEND_ISTREAM_RESULT_WAIT_OUTPUT:
		/* Output is blocking (client needs to act; enable timeout) */
		conn->output_locked = TRUE;
		http_server_connection_start_idle_timeout(conn);
		o_stream_set_flush_pending(output, TRUE);
		//e_debug(resp->event, "Partially sent payload");
		break;
	case OSTREAM_SEND_ISTREAM_RESULT_ERROR_INPUT:
		/* We're in the middle of sending a response, so the connection
		   will also have to be aborted */
		e_error(resp->event, "read(%s) failed: %s",
			i_stream_get_name(resp->payload_input),
			i_stream_get_error(resp->payload_input));
		http_server_connection_close(&conn,
			"Payload read failure");
		ret = -1;
		break;
	case OSTREAM_SEND_ISTREAM_RESULT_ERROR_OUTPUT:
		/* Failed to send response */
		http_server_connection_handle_output_error(conn);
		ret = -1;
		break;
	}

	if (ret != 0) {
		/* Finished sending payload (or error) */
		if (http_server_response_finish_payload_out(resp) < 0)
			return -1;
	}
	return ret < 0 ? -1 : 0;
}

static int http_server_response_send_real(struct http_server_response *resp)
{
	struct http_server_request *req = resp->request;
	struct http_server_connection *conn = req->conn;
	struct http_server *server = req->server;
	string_t *rtext = t_str_new(256);
	struct const_iovec iov[3];
	uoff_t content_length = 0;
	bool chunked = FALSE, send_content_length = FALSE, close = FALSE;
	bool is_head = http_request_method_is(&req->req, "HEAD");

	i_assert(!conn->output_locked);

	/* Determine response payload to send */
	if (resp->payload_input != NULL || resp->payload_direct) {
		i_assert(resp->tunnel_callback == NULL &&
			 resp->status / 100 != 1 &&
			 resp->status != 204 && resp->status != 304);
		if (resp->payload_chunked) {
			if (http_server_request_version_equals(req, 1, 0)) {
				/* Connection close marks end of payload
				 */
				close = TRUE;
			} else {
				/* Input stream with unknown size */
				chunked = TRUE;
			}
		} else {
			/* Send Content-Length if we have specified a payload,
			   even if it's 0 bytes. */
			content_length = resp->payload_size;
			send_content_length = TRUE;
		}
	} else if (resp->tunnel_callback == NULL && resp->status / 100 != 1 &&
		   resp->status != 204 && resp->status != 304 && !is_head) {
		/* RFC 7230, Section 3.3: Message Body

		   Responses to the HEAD request method (Section 4.3.2 of
		   [RFC7231]) never include a message body because the
		   associated response header fields (e.g., Transfer-Encoding,
		   Content-Length, etc.), if present, indicate only what their
		   values would have been if the request method had been GET
	           (Section 4.3.1 of [RFC7231]). 2xx (Successful) responses to a
		   CONNECT request method (Section 4.3.6 of [RFC7231]) switch to
		   tunnel mode instead of having a message body. All 1xx
		   (Informational), 204 (No Content), and 304 (Not Modified)
		   responses do not include a message body. All other responses
		   do include a message body, although the body might be of zero
		   length.

		   RFC 7230, Section 3.3.2: Content-Length

		   A server MUST NOT send a Content-Length header field in any
		   2xx (Successful) response to a CONNECT request (Section 4.3.6
		   of [RFC7231]).

		   -> Create empty body if it is missing.
		 */
		send_content_length = TRUE;
	}

	/* Initialize output payload stream if needed */
	if (is_head) {
		e_debug(resp->event, "A HEAD response has no payload");
	} else if (chunked) {
		i_assert(resp->payload_input != NULL || resp->payload_direct);

		e_debug(resp->event, "Will send payload in chunks");

		resp->payload_output =
			http_transfer_chunked_ostream_create(conn->conn.output);
	} else if (send_content_length) {
		i_assert(resp->payload_input != NULL || content_length == 0 ||
			 resp->payload_direct);

		e_debug(resp->event,
			"Will send payload with explicit size %"PRIuUOFF_T,
			content_length);

		if (content_length > 0) {
			resp->payload_output = conn->conn.output;
			o_stream_ref(conn->conn.output);
		}
	} else if (close) {
		i_assert(resp->payload_input != NULL || resp->payload_direct);

		e_debug(resp->event,
			"Will close connection after sending payload "
			"(HTTP/1.0)");

		resp->payload_output = conn->conn.output;
		o_stream_ref(conn->conn.output);
	} else {
		e_debug(resp->event, "Response has no payload");
	}

	/* Create status line */
	str_append(rtext, "HTTP/1.1 ");
	str_printfa(rtext, "%u", resp->status);
	str_append(rtext, " ");
	str_append(rtext, resp->reason);

	/* Create special headers implicitly if not set explicitly using
	   http_server_response_add_header() */
	if (!resp->have_hdr_date) {
		str_append(rtext, "\r\nDate: ");
		str_append(rtext, http_date_create(resp->date));
		str_append(rtext, "\r\n");
	}
	if (array_is_created(&resp->auth_challenges)) {
		str_append(rtext, "WWW-Authenticate: ");
		http_auth_create_challenges(rtext, &resp->auth_challenges);
		str_append(rtext, "\r\n");
	}
	if (chunked) {
		if (!resp->have_hdr_body_spec)
			str_append(rtext, "Transfer-Encoding: chunked\r\n");
	} else if (send_content_length) {
		if (!resp->have_hdr_body_spec) {
			str_printfa(rtext, "Content-Length: %"PRIuUOFF_T"\r\n",
				    content_length);
		}
	}
	if (!resp->have_hdr_connection) {
		close = (close || req->req.connection_close ||
			 req->connection_close || req->conn->input_broken);
		if (close && resp->tunnel_callback == NULL)
			str_append(rtext, "Connection: close\r\n");
		else if (http_server_request_version_equals(req, 1, 0))
			str_append(rtext, "Connection: Keep-Alive\r\n");
	}

	/* Status line + implicit headers */
	iov[0].iov_base = str_data(rtext);
	iov[0].iov_len = str_len(rtext);
	/* Explicit headers */
	iov[1].iov_base = str_data(resp->headers);
	iov[1].iov_len = str_len(resp->headers);
	/* End of header */
	iov[2].iov_base = "\r\n";
	iov[2].iov_len = 2;

	req->state = HTTP_SERVER_REQUEST_STATE_PAYLOAD_OUT;
	o_stream_cork(conn->conn.output);
	if (o_stream_sendv(conn->conn.output, iov, N_ELEMENTS(iov)) < 0) {
		http_server_connection_handle_output_error(conn);
		return -1;
	}

	e_debug(resp->event, "Sent header");

	if (resp->payload_blocking) {
		/* Blocking payload */
		conn->output_locked = TRUE;
		if (server->ioloop != NULL)
			io_loop_stop(server->ioloop);
	} else if (resp->payload_output != NULL) {
		/* Non-blocking payload */
		if (http_server_response_send_more(resp) < 0)
			return -1;
	} else {
		/* No payload to send */
		conn->output_locked = FALSE;
		http_server_response_finish_payload_out(resp);
	}

	if (conn->conn.output != NULL && !resp->payload_corked &&
	    o_stream_uncork_flush(conn->conn.output) < 0) {
		http_server_connection_handle_output_error(conn);
		return -1;
	}
	return 0;
}

int http_server_response_send(struct http_server_response *resp)
{
	int ret;

	T_BEGIN {
		ret = http_server_response_send_real(resp);
	} T_END;
	return ret;
}

/*
 * Payload output stream
 */

struct http_server_ostream {
	struct ostream_private ostream;

	struct http_server_response *resp;
};

static ssize_t
http_server_ostream_sendv(struct ostream_private *stream,
			  const struct const_iovec *iov, unsigned int iov_count)
{
	struct http_server_ostream *hsostream =
		(struct http_server_ostream *)stream;
	unsigned int i;
	ssize_t ret;

	if (http_server_response_output_payload(&hsostream->resp,
						iov, iov_count) < 0) {
		if (stream->parent->stream_errno != 0) {
			o_stream_copy_error_from_parent(stream);
		} else {
			io_stream_set_error(
				&stream->iostream,
				"HTTP connection broke while sending payload");
			stream->ostream.stream_errno = EIO;
		}
		return -1;
	}

	ret = 0;
	for (i = 0; i < iov_count; i++)
		ret += iov[i].iov_len;
	stream->ostream.offset += ret;
	return ret;
}

static void
http_server_ostream_close(struct iostream_private *stream,
			  bool close_parent ATTR_UNUSED)
{
	struct http_server_ostream *hsostream =
		(struct http_server_ostream *)stream;
	struct ostream_private *ostream = &hsostream->ostream;

	if (hsostream->resp == NULL)
		return;
	hsostream->resp->blocking_output = NULL;

	if (http_server_response_output_payload(
		&hsostream->resp, NULL, 0) < 0) {
		if (ostream->parent->stream_errno != 0) {
			o_stream_copy_error_from_parent(ostream);
		} else {
			io_stream_set_error(
				&ostream->iostream,
				"HTTP connection broke while sending payload");
			ostream->ostream.stream_errno = EIO;
		}
	}
	hsostream->resp = NULL;
}

static void http_server_ostream_destroy(struct iostream_private *stream)
{
	struct http_server_ostream *hsostream =
		(struct http_server_ostream *)stream;

	if (hsostream->resp != NULL) {
		hsostream->resp->blocking_output = NULL;
		http_server_response_abort_payload(&hsostream->resp);
	}
}

struct ostream *
http_server_response_get_payload_output(struct http_server_response *resp,
					bool blocking)
{
	struct http_server_connection *conn = resp->request->conn;
	struct http_server_ostream *hsostream;

	i_assert(resp->payload_input == NULL);
	i_assert(resp->blocking_output == NULL);

	i_assert(blocking == TRUE); // FIXME: support non-blocking

	hsostream = i_new(struct http_server_ostream, 1);
	hsostream->ostream.sendv = http_server_ostream_sendv;
	hsostream->ostream.iostream.close = http_server_ostream_close;
	hsostream->ostream.iostream.destroy = http_server_ostream_destroy;
	hsostream->resp = resp;

	resp->blocking_output = o_stream_create(&hsostream->ostream,
						conn->conn.output, -1);
	return resp->blocking_output;
}

void http_server_response_get_status(struct http_server_response *resp,
				     int *status_r, const char **reason_r)
{
	i_assert(resp != NULL);
	*status_r = resp->status;
	*reason_r = resp->reason;
}

uoff_t http_server_response_get_total_size(struct http_server_response *resp)
{
	i_assert(resp != NULL);
	return resp->payload_size + str_len(resp->headers);
}

void http_server_response_add_permanent_header(struct http_server_response *resp,
					       const char *key, const char *value)
{
	http_server_response_add_header(resp, key, value);

	if (!array_is_created(&resp->perm_headers))
		i_array_init(&resp->perm_headers, 4);
	char *key_dup = i_strdup(key);
	char *value_dup = i_strdup(value);
	array_push_back(&resp->perm_headers, &key_dup);
	array_push_back(&resp->perm_headers, &value_dup);
}
