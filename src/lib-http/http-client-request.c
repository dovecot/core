/* Copyright (c) 2013-2014 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "net.h"
#include "str.h"
#include "hash.h"
#include "array.h"
#include "istream.h"
#include "ostream.h"
#include "http-url.h"
#include "http-date.h"
#include "http-response-parser.h"
#include "http-transfer.h"

#include "http-client-private.h"

const char *http_request_state_names[] = {
	"new",
	"queued",
	"payload_out",
	"waiting",
	"got_response",
	"payload_in",
	"finished",
	"aborted"
};

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

static struct http_client_request *
http_client_request_new(struct http_client *client, const char *method, 
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
	req->callback = callback;
	req->context = context;
	req->date = (time_t)-1;

	req->state = HTTP_REQUEST_STATE_NEW;
	return req;
}

#undef http_client_request
struct http_client_request *
http_client_request(struct http_client *client,
		    const char *method, const char *host, const char *target,
		    http_client_request_callback_t *callback, void *context)
{
	struct http_client_request *req;

	req = http_client_request_new(client, method, callback, context);
	req->origin_url.host_name = p_strdup(req->pool, host);
	req->target = (target == NULL ? "/" : p_strdup(req->pool, target));
	return req;
}

#undef http_client_request_url
struct http_client_request *
http_client_request_url(struct http_client *client,
		    const char *method, const struct http_url *target_url,
		    http_client_request_callback_t *callback, void *context)
{
	struct http_client_request *req;

	req = http_client_request_new(client, method, callback, context);
	http_url_copy_authority(req->pool, &req->origin_url, target_url);
	req->target = p_strdup(req->pool, http_url_create_target(target_url));
	return req;
}

#undef http_client_request_connect
struct http_client_request *
http_client_request_connect(struct http_client *client,
		    const char *host, in_port_t port,
		    http_client_request_callback_t *callback,
				void *context)
{
	struct http_client_request *req;

	req = http_client_request_new(client, "CONNECT", callback, context);
	req->origin_url.host_name = p_strdup(req->pool, host);
	req->origin_url.port = port;
	req->origin_url.have_port = TRUE;
	req->connect_tunnel = TRUE;
	req->target = req->origin_url.host_name;
	return req;
}

#undef http_client_request_connect_ip
struct http_client_request *
http_client_request_connect_ip(struct http_client *client,
		    const struct ip_addr *ip, in_port_t port,
		    http_client_request_callback_t *callback,
				void *context)
{
	struct http_client_request *req;
	const char *hostname = net_ip2addr(ip);

	req = http_client_request_connect
		(client, hostname, port, callback, context);
	req->origin_url.host_ip = *ip;
	req->origin_url.have_host_ip = TRUE;
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

	if (req->destroy_callback != NULL) {
		req->destroy_callback(req->destroy_context);
		req->destroy_callback = NULL;
	}

	/* only decrease pending request counter if this request was submitted */
	if (req->state > HTTP_REQUEST_STATE_NEW)
		req->client->pending_requests--;

	http_client_request_debug(req, "Destroy (requests left=%d)",
		client->pending_requests);

	if (client->pending_requests == 0 && client->ioloop != NULL)
		io_loop_stop(client->ioloop);

	if (req->delayed_error != NULL)
		http_client_host_remove_request_error(req->host, req);
	if (req->payload_input != NULL)
		i_stream_unref(&req->payload_input);
	if (req->payload_output != NULL)
		o_stream_unref(&req->payload_output);
	if (req->headers != NULL)
		str_free(&req->headers);
	pool_unref(&req->pool);
	*_req = NULL;
}

void http_client_request_set_port(struct http_client_request *req,
	in_port_t port)
{
	i_assert(req->state == HTTP_REQUEST_STATE_NEW);
	req->origin_url.port = port;
	req->origin_url.have_port = TRUE;
}

void http_client_request_set_ssl(struct http_client_request *req,
	bool ssl)
{
	i_assert(req->state == HTTP_REQUEST_STATE_NEW);
	req->origin_url.have_ssl = ssl;
}

void http_client_request_set_urgent(struct http_client_request *req)
{
	i_assert(req->state == HTTP_REQUEST_STATE_NEW);
	req->urgent = TRUE;
}

void http_client_request_add_header(struct http_client_request *req,
				    const char *key, const char *value)
{
	i_assert(req->state == HTTP_REQUEST_STATE_NEW ||
		 /* allow calling for retries */
		 req->state == HTTP_REQUEST_STATE_GOT_RESPONSE ||
		 req->state == HTTP_REQUEST_STATE_ABORTED);

	/* mark presence of special headers */
	switch (key[0]) {
	case 'c': case 'C':
		if (strcasecmp(key, "Connection") == 0)
			req->have_hdr_connection = TRUE;
		else 	if (strcasecmp(key, "Content-Length") == 0)
			req->have_hdr_body_spec = TRUE;
		break;
	case 'd': case 'D':
		if (strcasecmp(key, "Date") == 0)
			req->have_hdr_date = TRUE;
		break;
	case 'e': case 'E':
		if (strcasecmp(key, "Expect") == 0)
			req->have_hdr_expect = TRUE;
		break;
	case 'h': case 'H':
		if (strcasecmp(key, "Host") == 0)
			req->have_hdr_host = TRUE;
		break;
	case 't': case 'T':
		if (strcasecmp(key, "Transfer-Encoding") == 0)
			req->have_hdr_body_spec = TRUE;
		break;
	case 'u': case 'U':
		if (strcasecmp(key, "User-Agent") == 0)
			req->have_hdr_user_agent = TRUE;
		break;
	}
	if (req->headers == NULL)
		req->headers = str_new(default_pool, 256);
	str_printfa(req->headers, "%s: %s\r\n", key, value);
}

void http_client_request_remove_header(struct http_client_request *req,
				       const char *key)
{
	const unsigned char *data, *p;
	size_t size, line_len, line_start_pos;
	unsigned int key_len = strlen(key);

	i_assert(req->state == HTTP_REQUEST_STATE_NEW ||
		 /* allow calling for retries */
		 req->state == HTTP_REQUEST_STATE_GOT_RESPONSE ||
		 req->state == HTTP_REQUEST_STATE_ABORTED);

	data = str_data(req->headers);
	size = str_len(req->headers);
	while ((p = memchr(data, '\n', size)) != NULL) {
		line_len = (p+1) - data;
		if (size > key_len && i_memcasecmp(data, key, key_len) == 0 &&
		    data[key_len] == ':' && data[key_len+1] == ' ') {
			/* key was found from header, replace its value */
			line_start_pos = str_len(req->headers) - size;
			str_delete(req->headers, line_start_pos, line_len);
			break;
		}
		size -= line_len;
		data += line_len;
	}
}

void http_client_request_set_date(struct http_client_request *req,
				    time_t date)
{
	i_assert(req->state == HTTP_REQUEST_STATE_NEW);
	req->date = date;
}

void http_client_request_set_payload(struct http_client_request *req,
				     struct istream *input, bool sync)
{
	int ret;

	i_assert(req->state == HTTP_REQUEST_STATE_NEW);
	i_assert(req->payload_input == NULL);

	i_stream_ref(input);
	req->payload_input = input;
	if ((ret = i_stream_get_size(input, TRUE, &req->payload_size)) <= 0) {
		if (ret < 0) {
			i_error("i_stream_get_size(%s) failed: %s",
				i_stream_get_name(input),
				i_stream_get_error(input));
		}
		req->payload_size = 0;
		req->payload_chunked = TRUE;
	}
	req->payload_offset = input->v_offset;

	/* prepare request payload sync using 100 Continue response from server */
	if ((req->payload_chunked || req->payload_size > 0) && sync)
		req->payload_sync = TRUE;
}

void http_client_request_delay_until(struct http_client_request *req,
	time_t time)
{
	req->release_time.tv_sec = time;
	req->release_time.tv_usec = 0;
}

void http_client_request_delay(struct http_client_request *req,
	time_t seconds)
{
	req->release_time = ioloop_timeval;
	req->release_time.tv_sec += seconds;
}

int http_client_request_delay_from_response(struct http_client_request *req,
	const struct http_response *response)
{
	time_t retry_after = response->retry_after;
	unsigned int max;

	if (retry_after == (time_t)-1)
		return 0;  /* no delay */
	if (retry_after < ioloop_time)
		return 0;  /* delay already expired */
	max = (req->client->set.max_auto_retry_delay == 0 ?
		req->client->set.request_timeout_msecs / 1000 :
		req->client->set.max_auto_retry_delay);
	if ((unsigned int)(retry_after - ioloop_time) > max)
		return -1; /* delay too long */
	req->release_time.tv_sec = retry_after;
	req->release_time.tv_usec = 0;
	return 1;    /* valid delay */
}

enum http_request_state
http_client_request_get_state(struct http_client_request *req)
{
	return req->state;
}

enum http_response_payload_type
http_client_request_get_payload_type(struct http_client_request *req)
{
	/* https://tools.ietf.org/html/draft-ietf-httpbis-p1-messaging-23
	     Section 3.3:

	   The presence of a message body in a response depends on both the
	   request method to which it is responding and the response status code.
	   Responses to the HEAD request method never include a message body
	   because the associated response header fields, if present, indicate only
	   what their values would have been if the request method had been GET
	   2xx (Successful) responses to CONNECT switch to tunnel mode instead of
	   having a message body (Section 4.3.6 of [Part2]).
	 */
	if (strcmp(req->method, "HEAD") == 0)
		return HTTP_RESPONSE_PAYLOAD_TYPE_NOT_PRESENT;
	if (strcmp(req->method, "CONNECT") == 0)
		return HTTP_RESPONSE_PAYLOAD_TYPE_ONLY_UNSUCCESSFUL;
	return HTTP_RESPONSE_PAYLOAD_TYPE_ALLOWED;
}

static void http_client_request_do_submit(struct http_client_request *req)
{
	struct http_client *client = req->client;
	struct http_client_host *host;
	const struct http_url *proxy_url = client->set.proxy_url;
	const char *authority, *target;

	i_assert(req->state == HTTP_REQUEST_STATE_NEW);

	authority = http_url_create_authority(&req->origin_url);
	if (req->connect_tunnel) {
		/* connect requests require authority form for request target */
		target = authority;
	} else {
		/* absolute target url */
		target = t_strconcat
			(http_url_create_host(&req->origin_url), req->target, NULL);
	}

	/* determine what host to contact to submit this request */
	if (proxy_url != NULL) {
		if (req->origin_url.have_ssl && !client->set.no_ssl_tunnel &&
			!req->connect_tunnel) {
			req->host_url = &req->origin_url;  /* tunnel to origin server */
			req->ssl_tunnel = TRUE;
		} else {
			req->host_url = proxy_url;         /* proxy server */
		}
	} else {
		req->host_url = &req->origin_url;    /* origin server */
	}

	/* use submission date if no date is set explicitly */
	if (req->date == (time_t)-1)
		req->date = ioloop_time;
	
	/* prepare value for Host header */
	req->authority = p_strdup(req->pool, authority);

	/* debug label */
	req->label = p_strdup_printf(req->pool, "[%s %s]", req->method, target);

	/* update request target */
	if (req->connect_tunnel || proxy_url != NULL)
		req->target = p_strdup(req->pool, target);

	if (proxy_url == NULL) {
		/* if we don't have a proxy, CONNECT requests are handled by creating
		   the requested connection directly */
		req->connect_direct = req->connect_tunnel;
		if (req->connect_direct)
			req->urgent = TRUE;
	}

	host = http_client_host_get(req->client, req->host_url);
	req->state = HTTP_REQUEST_STATE_QUEUED;

	http_client_host_submit_request(host, req);
}

void http_client_request_submit(struct http_client_request *req)
{
	req->client->pending_requests++;

	http_client_request_do_submit(req);
	http_client_request_debug(req, "Submitted");
	req->submitted = TRUE;
}

static void
http_client_request_finish_payload_out(struct http_client_request *req)
{
	i_assert(req->conn != NULL);

	if (req->payload_output != NULL) {
		o_stream_unref(&req->payload_output);
		req->payload_output = NULL;
	}
	req->state = HTTP_REQUEST_STATE_WAITING;
	req->conn->output_locked = FALSE;

	http_client_request_debug(req, "Finished sending payload");
}

static int
http_client_request_continue_payload(struct http_client_request **_req,
	const unsigned char *data, size_t size)
{
	struct ioloop *prev_ioloop = current_ioloop;
	struct http_client_request *req = *_req;
	struct http_client_connection *conn = req->conn;
	struct http_client *client = req->client;
	int ret;

	i_assert(req->state == HTTP_REQUEST_STATE_NEW ||
		req->state == HTTP_REQUEST_STATE_PAYLOAD_OUT);
	i_assert(req->payload_input == NULL);

	if (conn != NULL)
		http_client_connection_ref(conn);
	http_client_request_ref(req);
	req->payload_wait = TRUE;

	if (data == NULL) {
		req->payload_input = NULL;
		if (req->state == HTTP_REQUEST_STATE_PAYLOAD_OUT)
			http_client_request_finish_payload_out(req);
	} else { 
		req->payload_input = i_stream_create_from_data(data, size);
		i_stream_set_name(req->payload_input, "<HTTP request payload>");
	}
	req->payload_size = 0;
	req->payload_chunked = TRUE;

	if (req->state == HTTP_REQUEST_STATE_NEW)
		http_client_request_submit(req);

	/* Wait for payload data to be written */

	i_assert(client->ioloop == NULL);
	client->ioloop = io_loop_create();
	http_client_switch_ioloop(client);

	while (req->state < HTTP_REQUEST_STATE_FINISHED) {
		http_client_request_debug(req, "Waiting for request to finish");
		
		if (req->state == HTTP_REQUEST_STATE_PAYLOAD_OUT)
			o_stream_set_flush_pending(req->payload_output, TRUE);
		io_loop_run(client->ioloop);

		if (req->state == HTTP_REQUEST_STATE_PAYLOAD_OUT &&
			req->payload_input->eof) {
			i_stream_unref(&req->payload_input);
			req->payload_input = NULL;
			break;
		}
	}

	io_loop_set_current(prev_ioloop);
	http_client_switch_ioloop(client);
	io_loop_set_current(client->ioloop);
	io_loop_destroy(&client->ioloop);

	if (req->state == HTTP_REQUEST_STATE_FINISHED)
		ret = 1;
	else
		ret = (req->state == HTTP_REQUEST_STATE_ABORTED ? -1 : 0);

	req->payload_wait = FALSE;
	http_client_request_unref(_req);
	if (conn != NULL)
		http_client_connection_unref(&conn);

	/* Return status */
	return ret;
}

int http_client_request_send_payload(struct http_client_request **_req,
	const unsigned char *data, size_t size)
{
	i_assert(data != NULL);

	return http_client_request_continue_payload(_req, data, size);
}

int http_client_request_finish_payload(struct http_client_request **_req)
{
	return http_client_request_continue_payload(_req, NULL, 0);
}

static void http_client_request_payload_input(struct http_client_request *req)
{	
	struct http_client_connection *conn = req->conn;

	if (conn->io_req_payload != NULL)
		io_remove(&conn->io_req_payload);

	(void)http_client_connection_output(conn);
}

int http_client_request_send_more(struct http_client_request *req,
				  const char **error_r)
{
	struct http_client_connection *conn = req->conn;
	struct ostream *output = req->payload_output;
	off_t ret;
	int fd;

	i_assert(req->payload_input != NULL);
	i_assert(req->payload_output != NULL);

	if (conn->io_req_payload != NULL)
		io_remove(&conn->io_req_payload);

	/* chunked ostream needs to write to the parent stream's buffer */
	o_stream_set_max_buffer_size(output, IO_BLOCK_SIZE);
	ret = o_stream_send_istream(output, req->payload_input);
	o_stream_set_max_buffer_size(output, (size_t)-1);

	if (req->payload_input->stream_errno != 0) {
		/* the payload stream assigned to this request is broken,
		   fail this the request immediately */
		http_client_request_send_error(req,
			HTTP_CLIENT_REQUEST_ERROR_BROKEN_PAYLOAD,
			"Broken payload stream");

		/* we're in the middle of sending a request, so the connection
		   will also have to be aborted */
		errno = req->payload_input->stream_errno;
		*error_r = t_strdup_printf("read(%s) failed: %s",
					   i_stream_get_name(req->payload_input),
					   i_stream_get_error(req->payload_input));
		ret = -1;
	} else if (output->stream_errno != 0) {
		/* failed to send request */
		errno = output->stream_errno;
		*error_r = t_strdup_printf("write(%s) failed: %s",
					   o_stream_get_name(output),
					   o_stream_get_error(output));
		ret = -1;
	} else {
		i_assert(ret >= 0);
	}

	if (ret < 0 || i_stream_is_eof(req->payload_input)) {
		if (!req->payload_chunked &&
			req->payload_input->v_offset - req->payload_offset != req->payload_size) {
			*error_r = "stream input size changed [BUG]";
			i_error("stream input size changed"); //FIXME
			return -1;
		}

		if (req->payload_wait) {
			conn->output_locked = TRUE;
			if (req->client->ioloop != NULL)
				io_loop_stop(req->client->ioloop);
		} else {
			http_client_request_finish_payload_out(req);
		}
	} else if (i_stream_get_data_size(req->payload_input) > 0) {
		/* output is blocking */
		conn->output_locked = TRUE;
		o_stream_set_flush_pending(output, TRUE);
		http_client_request_debug(req, "Partially sent payload");
	} else {
		/* input is blocking */
		fd = i_stream_get_fd(req->payload_input);
		conn->output_locked = TRUE;	
		i_assert(fd >= 0);
		conn->io_req_payload = io_add
			(fd, IO_READ, http_client_request_payload_input, req);
	}
	return ret < 0 ? -1 : 0;
}

static int http_client_request_send_real(struct http_client_request *req,
					 const char **error_r)
{
	struct http_client_connection *conn = req->conn;
	struct ostream *output = conn->conn.output;
	string_t *rtext = t_str_new(256);
	struct const_iovec iov[3];
	int ret = 0;

	i_assert(!req->conn->output_locked);
	i_assert(req->payload_output == NULL);

	/* create request line */
	str_append(rtext, req->method);
	str_append(rtext, " ");
	str_append(rtext, req->target);
	str_append(rtext, " HTTP/1.1\r\n");

	/* create special headers implicitly if not set explicitly using
	   http_client_request_add_header() */
	if (!req->have_hdr_host) {
		str_append(rtext, "Host: ");
		str_append(rtext, req->authority);
		str_append(rtext, "\r\n");
	}
	if (!req->have_hdr_date) {
		str_append(rtext, "Date: ");
		str_append(rtext, http_date_create(req->date));
		str_append(rtext, "\r\n");
	}
	if (!req->have_hdr_user_agent && req->client->set.user_agent != NULL) {
		str_printfa(rtext, "User-Agent: %s\r\n",
			    req->client->set.user_agent);
	}
	if (!req->have_hdr_expect && req->payload_sync) {
		str_append(rtext, "Expect: 100-continue\r\n");
	}
	if (req->payload_input != NULL) {
		if (req->payload_chunked) {
			// FIXME: can't do this for a HTTP/1.0 server
			if (!req->have_hdr_body_spec)
				str_append(rtext, "Transfer-Encoding: chunked\r\n");
			req->payload_output =
				http_transfer_chunked_ostream_create(output);
		} else {
			/* send Content-Length if we have specified a payload,
				 even if it's 0 bytes. */
			if (!req->have_hdr_body_spec) {
				str_printfa(rtext, "Content-Length: %"PRIuUOFF_T"\r\n",
					req->payload_size);
			}
			req->payload_output = output;
			o_stream_ref(output);
		}
	}
	if (!req->have_hdr_connection && req->host_url == &req->origin_url) {
		/* https://tools.ietf.org/html/rfc2068
		     Section 19.7.1:

		   A client MUST NOT send the Keep-Alive connection token to a proxy
		   server as HTTP/1.0 proxy servers do not obey the rules of HTTP/1.1
		   for parsing the Connection header field.
		 */
		str_append(rtext, "Connection: Keep-Alive\r\n");
	}

	/* request line + implicit headers */
	iov[0].iov_base = str_data(rtext);
	iov[0].iov_len = str_len(rtext);	
	/* explicit headers */
	if (req->headers != NULL) {
		iov[1].iov_base = str_data(req->headers);
		iov[1].iov_len = str_len(req->headers);
	} else {
		iov[1].iov_base = "";
		iov[1].iov_len = 0;
	}
	/* end of header */
	iov[2].iov_base = "\r\n";
	iov[2].iov_len = 2;

	req->state = HTTP_REQUEST_STATE_PAYLOAD_OUT;
	o_stream_cork(output);
	if (o_stream_sendv(output, iov, N_ELEMENTS(iov)) < 0) {
		*error_r = t_strdup_printf("write(%s) failed: %s",
					   o_stream_get_name(output),
					   o_stream_get_error(output));
		ret = -1;
	}

	http_client_request_debug(req, "Sent header");

	if (ret >= 0 && req->payload_output != NULL) {
		if (!req->payload_sync) {
			if (http_client_request_send_more(req, error_r) < 0)
				ret = -1;
		} else {
			http_client_request_debug(req, "Waiting for 100-continue");
			conn->output_locked = TRUE;
		}
	} else {
		req->state = HTTP_REQUEST_STATE_WAITING;
		conn->output_locked = FALSE;
	}
	o_stream_uncork(output);
	return ret;
}

int http_client_request_send(struct http_client_request *req,
			     const char **error_r)
{
	int ret;

	T_BEGIN {
		ret = http_client_request_send_real(req, error_r);
	} T_END;
	return ret;
}

bool http_client_request_callback(struct http_client_request *req,
			     struct http_response *response)
{
	http_client_request_callback_t *callback = req->callback;
	unsigned int orig_attempts = req->attempts;

	req->state = HTTP_REQUEST_STATE_GOT_RESPONSE;

	req->callback = NULL;
	if (callback != NULL) {
		callback(response, req->context);
		if (req->attempts != orig_attempts) {
			/* retrying */
			req->callback = callback;
			http_client_request_resubmit(req);
			return FALSE;
		} else {
			/* release payload early (prevents server/client deadlock in proxy) */
			if (req->payload_input != NULL)
				i_stream_unref(&req->payload_input);
		}
	}
	return TRUE;
}

void
http_client_request_send_error(struct http_client_request *req,
			       unsigned int status, const char *error)
{
	http_client_request_callback_t *callback;

	if (req->state >= HTTP_REQUEST_STATE_FINISHED)
		return;
	req->state = HTTP_REQUEST_STATE_ABORTED;

	callback = req->callback;
	req->callback = NULL;
	if (callback != NULL) {
		struct http_response response;

		http_response_init(&response, status, error);
		(void)callback(&response, req->context);

		/* release payload early (prevents server/client in proxy) */
		if (req->payload_input != NULL)
			i_stream_unref(&req->payload_input);
	}
}

void http_client_request_error_delayed(struct http_client_request **_req)
{
	struct http_client_request *req = *_req;

	i_assert(req->delayed_error != NULL && req->delayed_error_status != 0);
	http_client_request_send_error(req, req->delayed_error_status,
				       req->delayed_error);
	http_client_request_unref(_req);
}

void http_client_request_error(struct http_client_request *req,
	unsigned int status, const char *error)
{
	if (!req->submitted && req->state < HTTP_REQUEST_STATE_FINISHED) {
		/* we're still in http_client_request_submit(). delay
		   reporting the error, so the caller doesn't have to handle
		   immediate callbacks. */
		i_assert(req->delayed_error == NULL);
		req->delayed_error = p_strdup(req->pool, error);
		req->delayed_error_status = status;
		http_client_host_delay_request_error(req->host, req);
	} else {
		http_client_request_send_error(req, status, error);
		http_client_request_unref(&req);
	}
}

void http_client_request_abort(struct http_client_request **_req)
{
	struct http_client_request *req = *_req;

	if (req->state >= HTTP_REQUEST_STATE_FINISHED)
		return;
	req->callback = NULL;
	req->state = HTTP_REQUEST_STATE_ABORTED;
	if (req->queue != NULL)
		http_client_queue_drop_request(req->queue, req);
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

	if (req->payload_wait && req->client->ioloop != NULL)
		io_loop_stop(req->client->ioloop);
	http_client_request_unref(_req);
}

void http_client_request_redirect(struct http_client_request *req,
	unsigned int status, const char *location)
{
	struct http_url *url;
	const char *error, *target, *origin_url;

	i_assert(!req->payload_wait);

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
	if (req->payload_input != NULL && req->payload_size > 0 && status != 303) {
		if (req->payload_input->v_offset != req->payload_offset &&
			!req->payload_input->seekable) {
			http_client_request_error(req,
				HTTP_CLIENT_REQUEST_ERROR_ABORTED,
				"Redirect failed: Cannot resend payload; stream is not seekable");
			return;
		} else {
			i_stream_seek(req->payload_input, req->payload_offset);
		}
	}

	/* drop payload output stream from previous attempt */
	if (req->payload_output != NULL)
		o_stream_unref(&req->payload_output);

	target = http_url_create_target(url);

	http_url_copy(req->pool, &req->origin_url, url);
	req->target = p_strdup(req->pool, target);
	if (req->host_url == &req->origin_url) {
		req->authority =
			p_strdup(req->pool, http_url_create_authority(req->host_url));
	}
	
	req->host = NULL;
	req->queue = NULL;
	req->conn = NULL;

	origin_url = http_url_create(&req->origin_url);

	http_client_request_debug(req, "Redirecting to %s%s",
		origin_url, target);

	req->label = p_strdup_printf(req->pool, "[%s %s%s]",
		req->method, origin_url, req->target);

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
		if (req->payload_input != NULL)
			i_stream_unref(&req->payload_input);
		req->payload_size = 0;
		req->payload_offset = 0;
	}

	/* resubmit */
	req->state = HTTP_REQUEST_STATE_NEW;
	http_client_request_do_submit(req);
}

void http_client_request_resubmit(struct http_client_request *req)
{
	i_assert(!req->payload_wait);

	http_client_request_debug(req, "Resubmitting request");

	/* rewind payload stream */
	if (req->payload_input != NULL && req->payload_size > 0) {
		if (req->payload_input->v_offset != req->payload_offset &&
			!req->payload_input->seekable) {
			http_client_request_error(req,
				HTTP_CLIENT_REQUEST_ERROR_ABORTED,
				"Resubmission failed: Cannot resend payload; stream is not seekable");
			return;
		} else {
			i_stream_seek(req->payload_input, req->payload_offset);
		}
	}

	/* rewind payload stream */
	if (req->payload_input != NULL && req->payload_size > 0) {
		if (req->payload_input->v_offset != req->payload_offset &&
			!req->payload_input->seekable) {
			http_client_request_error(req,
				HTTP_CLIENT_REQUEST_ERROR_ABORTED,
				"Resubmission failed: Cannot resend payload; stream is not seekable");
			return;
		} else {
			i_stream_seek(req->payload_input, req->payload_offset);
		}
	}

	/* drop payload output stream from previous attempt */
	if (req->payload_output != NULL)
		o_stream_unref(&req->payload_output);

	req->conn = NULL;
	req->peer = NULL;
	req->state = HTTP_REQUEST_STATE_QUEUED;
	http_client_host_submit_request(req->host, req);
}

void http_client_request_retry(struct http_client_request *req,
	unsigned int status, const char *error)
{
	if (!http_client_request_try_retry(req))
		http_client_request_error(req, status, error);
}

bool http_client_request_try_retry(struct http_client_request *req)
{
	/* limit the number of attempts for each request */
	if (req->attempts+1 >= req->client->set.max_attempts)
		return FALSE;
	req->attempts++;

	http_client_request_debug(req, "Retrying (attempts=%d)", req->attempts);
	if (req->callback != NULL)
		http_client_request_resubmit(req);
	return TRUE;
}

void http_client_request_set_destroy_callback(struct http_client_request *req,
					      void (*callback)(void *),
					      void *context)
{
	req->destroy_callback = callback;
	req->destroy_context = context;
}

void http_client_request_start_tunnel(struct http_client_request *req,
	struct http_client_tunnel *tunnel)
{
	i_assert(req->state == HTTP_REQUEST_STATE_GOT_RESPONSE);

	http_client_connection_start_tunnel(&req->conn, tunnel);
}
