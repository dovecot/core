/* Copyright (c) 2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "net.h"
#include "str.h"
#include "hash.h"
#include "array.h"
#include "istream.h"
#include "ostream.h"
#include "http-url.h"
#include "http-response-parser.h"

#include "http-client-private.h"

/*
 * Logging
 */

static inline void
http_client_request_debug(struct http_client_request *req,
	const char *format, ...) ATTR_FORMAT(2, 3);

static inline void
http_client_request_debug(struct http_client_request *req,
	const char *format, ...)
{
	va_list args;

	if (req->client->set.debug) {
		va_start(args, format);	
		i_debug("http-client: request %s: %s",
			http_client_request_label(req), t_strdup_vprintf(format, args));
		va_end(args);
	}
}

/*
 * Request
 */

#undef http_client_request
struct http_client_request *
http_client_request(struct http_client *client,
		    const char *method, const char *host, const char *target,
		    http_client_request_callback_t *callback, void *context)
{
	pool_t pool;
	struct http_client_request *req;

	pool = pool_alloconly_create("http client request", 2048);
	req = p_new(pool, struct http_client_request, 1);
	req->pool = pool;
	req->refcount = 1;
	req->client = client;
	req->method = p_strdup(pool, method);
	req->hostname = p_strdup(pool, host);
	req->port = HTTP_DEFAULT_PORT;
	req->target = p_strdup(pool, target);
	req->callback = callback;
	req->context = context;
	req->headers = str_new(default_pool, 256);

	req->state = HTTP_REQUEST_STATE_NEW;
	return req;
}

void http_client_request_ref(struct http_client_request *req)
{
	req->refcount++;
}

void http_client_request_unref(struct http_client_request **_req)
{
	struct http_client_request *req = *_req;
	struct http_client *client = req->client;

	i_assert(req->refcount > 0);

	if (--req->refcount > 0)
		return;

	/* only decrease pending request counter if this request was submitted */
	if (req->state > HTTP_REQUEST_STATE_NEW)
		req->client->pending_requests--;

	http_client_request_debug(req, "Destroy (requests left=%d)",
		client->pending_requests);

	if (req->input != NULL)
		i_stream_unref(&req->input);
	str_free(&req->headers);
	pool_unref(&req->pool);
	*_req = NULL;
}

void http_client_request_set_port(struct http_client_request *req,
	unsigned int port)
{
	i_assert(req->state == HTTP_REQUEST_STATE_NEW);
	req->port = port;
}

void http_client_request_set_ssl(struct http_client_request *req,
	bool ssl)
{
	i_assert(req->state == HTTP_REQUEST_STATE_NEW);
	if (ssl) {
		if (!req->ssl && req->port == HTTP_DEFAULT_PORT)
			req->port = HTTPS_DEFAULT_PORT;
	} else {
		if (req->ssl && req->port == HTTPS_DEFAULT_PORT)
			req->port = HTTP_DEFAULT_PORT;
	}
	req->ssl = ssl;
}

void http_client_request_set_urgent(struct http_client_request *req)
{
	i_assert(req->state == HTTP_REQUEST_STATE_NEW);
	req->urgent = TRUE;
}

void http_client_request_add_header(struct http_client_request *req,
				    const char *key, const char *value)
{
	i_assert(req->state == HTTP_REQUEST_STATE_NEW);
	str_printfa(req->headers, "%s: %s\r\n", key, value);
}

void http_client_request_set_payload(struct http_client_request *req,
				     struct istream *input, bool sync)
{
	i_assert(req->state == HTTP_REQUEST_STATE_NEW);
	i_assert(req->input == NULL);

	i_stream_ref(input);
	req->input = input;
	if (i_stream_get_size(input, TRUE, &req->input_size) <= 0)
		i_unreached(); //FIXME	
	req->input_offset = input->v_offset;

	/* prepare request payload sync using 100 Continue response from server */
	if (req->input_size > 0 && sync) {
		req->payload_sync = TRUE;
	}
}

void http_client_request_submit(struct http_client_request *req)
{
	struct http_client_host *host;

	i_assert(req->state == HTTP_REQUEST_STATE_NEW);
	http_client_request_debug(req, "Submitted");
	
	host = http_client_host_get(req->client, req->hostname);
	http_client_host_submit_request(host, req);
	req->state = HTTP_REQUEST_STATE_QUEUED;
	req->client->pending_requests++;
}

int http_client_request_send_more(struct http_client_request *req)
{
	struct http_client_connection *conn = req->conn;
	struct ostream *output = conn->conn.output;
	int ret = 0;

	i_assert(req->input != NULL);

	o_stream_set_max_buffer_size(output, 0);
	if (o_stream_send_istream(output, req->input) < 0)
		ret = -1;
	o_stream_set_max_buffer_size(output, (size_t)-1);

	if (!i_stream_have_bytes_left(req->input)) {
		if (req->input->v_offset != req->input_size) {
			i_error("stream input size changed"); //FIXME
			return -1;
		}
		req->state = HTTP_REQUEST_STATE_WAITING;
		conn->output_locked = FALSE;
		http_client_request_debug(req, "Sent all payload");

	} else {
		conn->output_locked = TRUE;
		o_stream_set_flush_pending(output, TRUE);
		http_client_request_debug(req, "Partially sent payload");
	}
	return ret;
}

int http_client_request_send(struct http_client_request *req)
{
	struct http_client_connection *conn = req->conn;
	struct ostream *output = conn->conn.output;
	string_t *rtext = t_str_new(256);
	struct const_iovec iov[3];
	int ret = 0;

	i_assert(!req->conn->output_locked);

	str_append(rtext, req->method);
	str_append(rtext, " ");
	str_append(rtext, req->target);
	str_append(rtext, " HTTP/1.1\r\n");
	str_append(rtext, "Host: ");
	str_append(rtext, req->hostname);
	if ((!req->ssl &&req->port != HTTP_DEFAULT_PORT) ||
		(req->ssl && req->port != HTTPS_DEFAULT_PORT)) {
		str_printfa(rtext, ":%u", req->port);
	}
	str_append(rtext, "\r\n");
	if (req->payload_sync) {
		str_append(rtext, "Expect: 100-continue\r\n");
	}
	if (req->input_size != 0) {
		str_printfa(rtext, "Content-Length: %"PRIuUOFF_T"\r\n",
			    req->input_size);
	}

	iov[0].iov_base = str_data(rtext);
	iov[0].iov_len = str_len(rtext);
	iov[1].iov_base = str_data(req->headers);
	iov[1].iov_len = str_len(req->headers);
	iov[2].iov_base = "\r\n";
	iov[2].iov_len = 2;

	req->state = HTTP_REQUEST_STATE_PAYLOAD_OUT;
	o_stream_cork(output);
	if (o_stream_sendv(output, iov, N_ELEMENTS(iov)) < 0)
		ret = -1;

	http_client_request_debug(req, "Sent");

	if (ret >= 0 && req->input_size != 0) {
		if (!req->payload_sync) {
			if (http_client_request_send_more(req) < 0)
				ret = -1;
		} else {
			http_client_request_debug(req, "Waiting for 100-continue");
		}
	} else {
		req->state = HTTP_REQUEST_STATE_WAITING;
		conn->output_locked = FALSE;
	}
	o_stream_uncork(output);
	return ret;
}

void http_client_request_callback(struct http_client_request *req,
			     struct http_response *response)
{
	http_client_request_callback_t *callback = req->callback;

	req->state = HTTP_REQUEST_STATE_GOT_RESPONSE;

	req->callback = NULL;
	if (callback != NULL)
		callback(response, req->context);
}

static void
http_client_request_send_error(struct http_client_request *req,
			       unsigned int status, const char *error)
{
	http_client_request_callback_t *callback;

	req->state = HTTP_REQUEST_STATE_ABORTED;

	callback = req->callback;
	req->callback = NULL;
	if (callback != NULL) {
		struct http_response response;

		memset(&response, 0, sizeof(response));
		response.status = status;
		response.reason = error;
		(void)callback(&response, req->context);
	}
}

void http_client_request_error(struct http_client_request *req,
	unsigned int status, const char *error)
{
	http_client_request_send_error(req, status, error);
	http_client_request_unref(&req);
}

void http_client_request_abort(struct http_client_request **_req)
{
	struct http_client_request *req = *_req;

	if (req->state >= HTTP_REQUEST_STATE_FINISHED)
		return;
	req->callback = NULL;
	req->state = HTTP_REQUEST_STATE_ABORTED;
	if (req->host != NULL)
		http_client_host_drop_request(req->host, req);
	http_client_request_unref(_req);
}

void http_client_request_finish(struct http_client_request **_req)
{
	struct http_client_request *req = *_req;

	if (req->state >= HTTP_REQUEST_STATE_FINISHED)
		return;

	http_client_request_debug(req, "Finished");

	req->callback = NULL;
	req->state = HTTP_REQUEST_STATE_FINISHED;
	http_client_request_unref(_req);
}

void http_client_request_redirect(struct http_client_request *req,
	unsigned int status, const char *location)
{
	struct http_url *url;
	const char *error;
	unsigned int newport;

	/* parse URL */
	if (http_url_parse(location, NULL, 0,
			   pool_datastack_create(), &url, &error) < 0) {
		http_client_request_error(req, HTTP_CLIENT_REQUEST_ERROR_INVALID_REDIRECT,
			t_strdup_printf("Invalid redirect location: %s", error));
		return;
	}

	if (++req->redirects > req->client->set.max_redirects) {
		if (req->client->set.max_redirects > 0) {
			http_client_request_error(req,
				HTTP_CLIENT_REQUEST_ERROR_INVALID_REDIRECT,
				t_strdup_printf("Redirected more than %d times",
					req->client->set.max_redirects));
		} else {
			http_client_request_error(req,
				HTTP_CLIENT_REQUEST_ERROR_INVALID_REDIRECT,
					"Redirect refused");
		}
		return;
	}

	/* rewind payload stream */
	if (req->input != NULL && req->input_size > 0 && status != 303) {
		if (req->input->v_offset != req->input_offset && !req->input->seekable) {
			http_client_request_error(req,
				HTTP_CLIENT_REQUEST_ERROR_ABORTED,
				"Redirect failed: Cannot resend payload; stream is not seekable");
			return;
		} else {
			i_stream_seek(req->input, req->input_offset);
		}
	}

	newport = (url->have_port ? url->port : (url->have_ssl ? 443 : 80));

	http_client_request_debug(req, "Redirecting to http://%s:%u%s",
		url->host_name, newport, url->path);

	// FIXME: handle literal IP specially (avoid duplicate parsing)
	req->host = NULL;
	req->conn = NULL;
	req->hostname = p_strdup(req->pool, url->host_name);
	req->port = newport;
	req->target = p_strdup(req->pool, url->path);
	req->ssl = url->have_ssl;

	/* https://tools.ietf.org/html/draft-ietf-httpbis-p2-semantics-21
	      Section-7.4.4
	
	   -> A 303 `See Other' redirect status response is handled a bit differently.
	   Basically, the response content is located elsewhere, but the original
	   (POST) request is handled already.
	 */
	if (status == 303 && strcasecmp(req->method, "HEAD") != 0 &&
		strcasecmp(req->method, "GET") != 0) {
		// FIXME: should we provide the means to skip this step? The original
		// request was already handled at this point.
		req->method = p_strdup(req->pool, "GET");

		/* drop payload */
		if (req->input != NULL)
			i_stream_unref(&req->input);
		req->input_size = 0;
		req->input_offset = 0;
	}

	/* resubmit */
	req->client->pending_requests--;
	req->state = HTTP_REQUEST_STATE_NEW;
	http_client_request_submit(req);
}

void http_client_request_resubmit(struct http_client_request *req)
{
	http_client_request_debug(req, "Resubmitting request");

	/* rewind payload stream */
	if (req->input != NULL && req->input_size > 0) {
		if (req->input->v_offset != req->input_offset && !req->input->seekable) {
			http_client_request_error(req,
				HTTP_CLIENT_REQUEST_ERROR_ABORTED,
				"Resubmission failed: Cannot resend payload; stream is not seekable");
			return;
		} else {
			i_stream_seek(req->input, req->input_offset);
		}
	}

	req->conn = NULL;
	req->peer = NULL;
	req->state = HTTP_REQUEST_STATE_QUEUED;
	http_client_host_submit_request(req->host, req);
}

void http_client_request_retry(struct http_client_request *req,
	unsigned int status, const char *error)
{
	/* limit the number of attempts for each request */
	if (++req->attempts >= req->client->set.max_attempts) {
		/* return error */
		http_client_request_error(req, status, error);
		return;
	}

	http_client_request_debug(req, "Retrying (attempts=%d)", req->attempts);

	/* resubmit */
	http_client_request_resubmit(req);
}
