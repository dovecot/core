/* Copyright (c) 2013-2017 Dovecot authors, see the included COPYING file */

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
 * Logging
 */

static inline void
http_server_response_debug(struct http_server_response *resp,
	const char *format, ...) ATTR_FORMAT(2, 3);

static inline void
http_server_response_debug(struct http_server_response *resp,
	const char *format, ...)
{
	va_list args;

	if (resp->request->server->set.debug) {
		va_start(args, format);	
		i_debug("http-server: request %s; %u response: %s",
			http_server_request_label(resp->request), resp->status,
			t_strdup_vprintf(format, args));
		va_end(args);
	}
}

/*
 * Response
 */

struct http_server_response *
http_server_response_create(struct http_server_request *req,
	unsigned int status, const char *reason)
{
	struct http_server_response *resp;

	if (req->response == NULL) {
		resp = req->response = p_new
			(req->pool, struct http_server_response, 1);
	} else {
		/* was already composing a response, but decided to
		   start a new one (would usually be a failure response)
		 */
		resp = req->response;
		i_assert(!resp->submitted);
		http_server_response_free(resp);
		i_zero(resp);
	}

	resp->request = req;
	resp->status = status;
	resp->reason = p_strdup(req->pool, reason);
	resp->headers = str_new(default_pool, 256);
	resp->date = (time_t)-1;

	return resp;
}

void http_server_response_free(struct http_server_response *resp)
{
	http_server_response_debug(resp, "Destroy");

	i_assert(!resp->payload_blocking);

	if (resp->payload_input != NULL)
		i_stream_unref(&resp->payload_input);
	if (resp->payload_output != NULL)
		o_stream_unref(&resp->payload_output);
	str_free(&resp->headers);
}

void http_server_response_add_header(struct http_server_response *resp,
				    const char *key, const char *value)
{
	i_assert(!resp->submitted);
	i_assert(strchr(key, '\r') == NULL && strchr(key, '\n') == NULL);
	i_assert(strchr(value, '\r') == NULL && strchr(value, '\n') == NULL);

	/* mark presence of special headers */
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
	/* free not called because pool is alloconly */
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
			i_error("i_stream_get_size(%s) failed: %s",
				i_stream_get_name(input), i_stream_get_error(input));
		}
		resp->payload_size = 0;
		resp->payload_chunked = TRUE;
	}
	resp->payload_offset = input->v_offset;
}

void http_server_response_set_payload_data(struct http_server_response *resp,
				     const unsigned char *data, size_t size)
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

void http_server_response_add_auth(
	struct http_server_response *resp,
	const struct http_auth_challenge *chlng)
{
	struct http_auth_challenge *new;
	pool_t pool = resp->request->pool;

	if (!array_is_created(&resp->auth_challenges))
		p_array_init(&resp->auth_challenges, pool, 4);

	new = array_append_space(&resp->auth_challenges);
	http_auth_challenge_copy(pool, new, chlng);
}

void http_server_response_add_auth_basic(
	struct http_server_response *resp, const char *realm)
{
	struct http_auth_challenge chlng;

	http_auth_basic_challenge_init(&chlng, realm);
	http_server_response_add_auth(resp, &chlng);
}

static void http_server_response_do_submit(struct http_server_response *resp,
	bool close)
{
	if (resp->date == (time_t)-1)
		resp->date = ioloop_time;
	resp->close = close;
	resp->submitted = TRUE;
	http_server_request_submit_response(resp->request);	
}

void http_server_response_submit(struct http_server_response *resp)
{
	i_assert(!resp->submitted);
	http_server_response_debug(resp, "Submitted");

	http_server_response_do_submit(resp, FALSE);
}

void http_server_response_submit_close(struct http_server_response *resp)
{
	i_assert(!resp->submitted);
	http_server_response_debug(resp, "Submitted");

	http_server_response_do_submit(resp, TRUE);
}

void http_server_response_submit_tunnel(struct http_server_response *resp,
	http_server_tunnel_callback_t callback, void *context)
{
	i_assert(!resp->submitted);
	http_server_response_debug(resp, "Started tunnelling");

	resp->tunnel_callback = callback;
	resp->tunnel_context = context;
	http_server_response_do_submit(resp, TRUE);
}

static void
http_server_response_finish_payload_out(struct http_server_response *resp)
{
	struct http_server_connection *conn = resp->request->conn;

	if (resp->payload_output != NULL) {
		o_stream_unref(&resp->payload_output);
		resp->payload_output = NULL;
	}

	http_server_response_debug(resp, "Finished sending payload");

	conn->output_locked = FALSE;
	if (resp->payload_corked)
		o_stream_uncork(conn->conn.output);
	o_stream_set_flush_callback(conn->conn.output,
		http_server_connection_output, conn);

	http_server_request_finished(resp->request);
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

	if ((ret=o_stream_sendv(output, iov, iov_count)) < 0) {
		const char *error = NULL;

		if (output->stream_errno != EPIPE &&
			output->stream_errno != ECONNRESET) {
			error = t_strdup_printf("write(%s) failed: %s",
				o_stream_get_name(output),
				o_stream_get_error(output));
		}
		http_server_connection_write_failed(conn, error);
		return -1;
	}
	if (ret > 0) {
		bytes_left = ret;
		for (i = 0; i < iov_count && bytes_left > 0; i++) {
			block_len = iov[i].iov_len <= bytes_left ?
				iov[i].iov_len : bytes_left;
			bytes_left -= block_len;
		}
		rpay->iov_idx += i;
		if (i < iov_count) {
			i_assert(iov[i].iov_len > bytes_left);
			iov[i].iov_base = PTR_OFFSET
				(iov[i].iov_base, iov[i].iov_len - bytes_left);
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
http_server_response_output_payload(
	struct http_server_response **_resp,
	const struct const_iovec *iov, unsigned int iov_count)
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
			http_server_response_finish_payload_out(resp);
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
				http_server_response_debug(resp,
					"Preparing to send blocking payload");
				http_server_connection_trigger_responses(conn);

			} else if (resp->payload_output != NULL) {
				http_server_response_debug(resp,
					"Sending blocking payload");
				o_stream_unset_flush_callback(conn->conn.output);
				o_stream_set_flush_callback(resp->payload_output,
				  http_server_response_output_direct, &rpay);
				o_stream_set_flush_pending(resp->payload_output, TRUE);

			} else {
				http_server_response_finish_payload_out(resp);
				i_assert(req->state >= HTTP_SERVER_REQUEST_STATE_FINISHED);
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
		http_server_response_debug(resp,
			"Request aborted while sending blocking payload");
		ret = -1;
		break;
	default:
		ret = 0;
		break;
	}

	resp->payload_blocking = FALSE;
	resp->payload_direct = FALSE;

	/* callback may have messed with our pointer,
	   so unref using local variable */
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

	http_server_request_abort(&req,
		"Aborted sending response payload");
}

static void
http_server_response_payload_input(struct http_server_response *resp)
{	
	struct http_server_connection *conn = resp->request->conn;

	if (conn->io_resp_payload != NULL)
		io_remove(&conn->io_resp_payload);

	(void)http_server_connection_output(conn);
}

int http_server_response_send_more(struct http_server_response *resp,
				  const char **error_r)
{
	struct http_server_connection *conn = resp->request->conn;
	struct ostream *output = resp->payload_output;
	off_t ret;

	*error_r = NULL;

	i_assert(!resp->payload_blocking);
	i_assert(resp->payload_input != NULL);
	i_assert(resp->payload_output != NULL);

	if (conn->io_resp_payload != NULL)
		io_remove(&conn->io_resp_payload);

	/* chunked ostream needs to write to the parent stream's buffer */
	o_stream_set_max_buffer_size(output, IO_BLOCK_SIZE);
	ret = o_stream_send_istream(output, resp->payload_input);
	o_stream_set_max_buffer_size(output, (size_t)-1);

	if (resp->payload_input->stream_errno != 0) {
		/* we're in the middle of sending a response, so the connection
		   will also have to be aborted */
		*error_r = t_strdup_printf("read(%s) failed: %s",
			i_stream_get_name(resp->payload_input),
			i_stream_get_error(resp->payload_input));
		ret = -1;
	} else if (output->stream_errno != 0) {
		/* failed to send response */
		if (output->stream_errno != EPIPE &&
		    output->stream_errno != ECONNRESET) {
			*error_r = t_strdup_printf("write(%s) failed: %s",
				o_stream_get_name(output), o_stream_get_error(output));
		}
		ret = -1;
	} else {
		i_assert(ret >= 0);
	}

	if (ret < 0 || i_stream_is_eof(resp->payload_input)) {
		/* finished sending */
		if (ret >= 0 && !resp->payload_chunked &&
			resp->payload_input->v_offset - resp->payload_offset !=
				resp->payload_size) {
			*error_r = t_strdup_printf(
				"Input stream %s size changed unexpectedly",
				i_stream_get_name(resp->payload_input));
			ret = -1;
		}
		/* finished sending payload */
		http_server_response_finish_payload_out(resp);
	} else if (i_stream_have_bytes_left(resp->payload_input)) {
		/* output is blocking */
		conn->output_locked = TRUE;
		o_stream_set_flush_pending(output, TRUE);
		//http_server_response_debug(resp, "Partially sent payload");
	} else {
		/* input is blocking */
		conn->output_locked = TRUE;	
		conn->io_resp_payload = io_add_istream(resp->payload_input,
			http_server_response_payload_input, resp);
	}
	return ret < 0 ? -1 : 0;
}

static int http_server_response_send_real(struct http_server_response *resp,
					 const char **error_r)
{
	struct http_server_request *req = resp->request;
	struct http_server_connection *conn = req->conn;
	struct http_server *server = req->server;
	struct ostream *output = conn->conn.output;
	string_t *rtext = t_str_new(256);
	struct const_iovec iov[3];
	int ret = 0;

	*error_r = NULL;

	i_assert(!conn->output_locked);

	/* create status line */
	str_append(rtext, "HTTP/1.1 ");
	str_printfa(rtext, "%u", resp->status);
	str_append(rtext, " ");
	str_append(rtext, resp->reason);

	/* create special headers implicitly if not set explicitly using
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
	if (resp->payload_input != NULL || resp->payload_direct) {
		if (resp->payload_chunked) {
			if (http_server_request_version_equals(req, 1, 0)) {
				/* cannot use Transfer-Encoding */
				resp->payload_output = output;
				o_stream_ref(output);
				/* connection close marks end of payload */
				resp->close = TRUE;
			} else {
				if (!resp->have_hdr_body_spec)
					str_append(rtext, "Transfer-Encoding: chunked\r\n");
				resp->payload_output =
					http_transfer_chunked_ostream_create(output);
			}
		} else {
			/* send Content-Length if we have specified a payload,
				 even if it's 0 bytes. */
			if (!resp->have_hdr_body_spec) {
				str_printfa(rtext, "Content-Length: %"PRIuUOFF_T"\r\n",
						  resp->payload_size);
			}
			resp->payload_output = output;
			o_stream_ref(output);
		}
	} else if (resp->tunnel_callback == NULL && resp->status / 100 != 1
		&& resp->status != 204 && resp->status != 304
		&& !http_request_method_is(&req->req, "HEAD")) {
		/* RFC 7230, Section 3.3: Message Body

		   Responses to the HEAD request method (Section 4.3.2 of [RFC7231])
		   never include a message body because the associated response header
		   fields (e.g., Transfer-Encoding, Content-Length, etc.), if present,
		   indicate only what their values would have been if the request method
		   had been GET (Section 4.3.1 of [RFC7231]). 2xx (Successful) responses
		   to a CONNECT request method (Section 4.3.6 of [RFC7231]) switch to
		   tunnel mode instead of having a message body. All 1xx (Informational),
		   204 (No Content), and 304 (Not Modified) responses do not include a
		   message body.  All other responses do include a message body, although
		   the body might be of zero length.

		   RFC 7230, Section 3.3.2: Content-Length

		   A server MUST NOT send a Content-Length header field in any 2xx
		   (Successful) response to a CONNECT request (Section 4.3.6 of [RFC7231]).

		   -> Create empty body if it is missing.
		 */
		if (!resp->have_hdr_body_spec)
			str_append(rtext, "Content-Length: 0\r\n");
	}
	if (!resp->have_hdr_connection) {
		if (resp->close && resp->tunnel_callback == NULL)
			str_append(rtext, "Connection: close\r\n");
		else if (http_server_request_version_equals(req, 1, 0))
			str_append(rtext, "Connection: Keep-Alive\r\n");
	}

	/* status line + implicit headers */
	iov[0].iov_base = str_data(rtext);
	iov[0].iov_len = str_len(rtext);
	/* explicit headers */
	iov[1].iov_base = str_data(resp->headers);
	iov[1].iov_len = str_len(resp->headers);
	/* end of header */
	iov[2].iov_base = "\r\n";
	iov[2].iov_len = 2;

	req->state = HTTP_SERVER_REQUEST_STATE_PAYLOAD_OUT;
	o_stream_ref(output);
	o_stream_cork(output);
	if (o_stream_sendv(output, iov, N_ELEMENTS(iov)) < 0) {
		if (output->stream_errno != EPIPE &&
		    output->stream_errno != ECONNRESET) {
			*error_r = t_strdup_printf("write(%s) failed: %s",
				o_stream_get_name(output), o_stream_get_error(output));
		}
		ret = -1;
	}

	if (ret >= 0) {
		http_server_response_debug(resp, "Sent header");

		if (resp->payload_blocking) {
			/* blocking payload */
			conn->output_locked = TRUE;
			if (server->ioloop != NULL)
				io_loop_stop(server->ioloop);
		} else if (resp->payload_output != NULL) {
			/* non-blocking payload */
			if (http_server_response_send_more(resp, error_r) < 0)
				ret = -1;
		} else {
			/* no payload to send */
			conn->output_locked = FALSE;
			http_server_response_finish_payload_out(resp);
		}
	}
	if (!resp->payload_corked)
		o_stream_uncork(output);
	o_stream_unref(&output);
	return ret;
}

int http_server_response_send(struct http_server_response *resp,
			     const char **error_r)
{
	char *errstr = NULL;
	int ret;

	T_BEGIN {
		ret = http_server_response_send_real(resp, error_r);
		if (ret < 0)
			errstr = i_strdup(*error_r);
	} T_END;
	*error_r = t_strdup(errstr);
	i_free(errstr);
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

	if (http_server_response_output_payload
		(&hsostream->resp, iov, iov_count) < 0) {
		if (stream->parent->stream_errno != 0) {
			o_stream_copy_error_from_parent(stream);
		} else {
			io_stream_set_error(&stream->iostream,
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

static void http_server_ostream_close(struct iostream_private *stream,
				  bool close_parent ATTR_UNUSED)
{
	struct http_server_ostream *hsostream =
		(struct http_server_ostream *)stream;
	struct ostream_private *ostream = &hsostream->ostream;

	if (hsostream->resp == NULL)
		return;
	hsostream->resp->blocking_output = NULL;

	if (http_server_response_output_payload
		(&hsostream->resp, NULL, 0) < 0) {
		if (ostream->parent->stream_errno != 0) {
			o_stream_copy_error_from_parent(ostream);
		} else {
			io_stream_set_error(&ostream->iostream,
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

	resp->blocking_output =
		o_stream_create(&hsostream->ostream, conn->conn.output, -1);
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
