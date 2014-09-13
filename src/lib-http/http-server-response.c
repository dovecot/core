/* Copyright (c) 2013-2014 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "array.h"
#include "istream.h"
#include "ostream.h"
#include "http-date.h"
#include "http-transfer.h"
#include "http-server-private.h"

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

	i_assert(req->response == NULL);

	resp = req->response = p_new(req->pool, struct http_server_response, 1);
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
	i_assert(resp->payload_input == NULL);

	i_stream_ref(input);
	resp->payload_input = input;
	if ((ret = i_stream_get_size(input, TRUE, &resp->payload_size)) <= 0) {
		if (ret < 0) {
			i_error("i_stream_get_size(%s) failed: %m",
				i_stream_get_name(input));
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
	if (resp->payload_output != NULL) {
		o_stream_unref(&resp->payload_output);
		resp->payload_output = NULL;
	}
	resp->request->conn->output_locked = FALSE;
	http_server_response_debug(resp, "Finished sending payload");

	http_server_request_finished(resp->request);
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

	i_assert(resp->payload_input != NULL);
	i_assert(resp->payload_output != NULL);

	if (conn->io_resp_payload != NULL)
		io_remove(&conn->io_resp_payload);

	/* chunked ostream needs to write to the parent stream's buffer */
	o_stream_set_max_buffer_size(output, IO_BLOCK_SIZE);
	ret = o_stream_send_istream(output, resp->payload_input);
	o_stream_set_max_buffer_size(output, (size_t)-1);

	if (resp->payload_input->stream_errno != 0) {
		errno = resp->payload_input->stream_errno;
		*error_r = t_strdup_printf("read(%s) failed: %m",
					   i_stream_get_name(resp->payload_input));
		ret = -1;
	} else if (output->stream_errno != 0) {
		errno = output->stream_errno;
		if (errno != EPIPE && errno != ECONNRESET) {
			*error_r = t_strdup_printf("write(%s) failed: %m",
					   o_stream_get_name(output));
		}
		ret = -1;
	} else {
		i_assert(ret >= 0);
	}

	if (ret < 0 || i_stream_is_eof(resp->payload_input)) {
		if (!resp->payload_chunked &&
			resp->payload_input->v_offset - resp->payload_offset != resp->payload_size) {
			i_error("stream input size changed"); //FIXME
			return -1;
		}

		http_server_response_finish_payload_out(resp);

	} else if (i_stream_get_data_size(resp->payload_input) > 0) {
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
	} else if (resp->payload_input != NULL) {
		/* send Content-Length if we have specified a payload,
		   even if it's 0 bytes. */
		if (!resp->have_hdr_body_spec) {
			str_printfa(rtext, "Content-Length: %"PRIuUOFF_T"\r\n",
				    resp->payload_size);
		}
		resp->payload_output = output;
		o_stream_ref(output);
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
		if (errno != EPIPE && errno != ECONNRESET) {
			*error_r = t_strdup_printf("write(%s) failed: %m",
					   o_stream_get_name(output));
		}
		ret = -1;
	}

	http_server_response_debug(resp, "Sent header");

	if (ret >= 0 && resp->payload_output != NULL) {
		if (http_server_response_send_more(resp, error_r) < 0)
			ret = -1;
	} else {
		conn->output_locked = FALSE;
		http_server_request_finished(resp->request);
	}
	o_stream_uncork(output);
	o_stream_unref(&output);
	return ret;
}

int http_server_response_send(struct http_server_response *resp,
			     const char **error_r)
{
	int ret;

	T_BEGIN {
		ret = http_server_response_send_real(resp, error_r);
	} T_END;
	return ret;
}
