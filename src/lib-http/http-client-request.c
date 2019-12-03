/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "net.h"
#include "str.h"
#include "hash.h"
#include "array.h"
#include "llist.h"
#include "time-util.h"
#include "istream.h"
#include "ostream.h"
#include "file-lock.h"
#include "dns-lookup.h"
#include "http-url.h"
#include "http-date.h"
#include "http-auth.h"
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
 * Request
 */

static bool
http_client_request_send_error(struct http_client_request *req,
			       unsigned int status, const char *error);

const char *
http_client_request_label(struct http_client_request *req)
{
	if (req->label == NULL) {
		req->label = p_strdup_printf(req->pool,
			"[Req%u: %s %s%s]", req->id, req->method,
			http_url_create_host(&req->origin_url), req->target);
	}
	return req->label;
}

static void
http_client_request_update_event(struct http_client_request *req)
{
	event_add_str(req->event, "method", req->method);
	event_add_str(req->event, "dest_host", req->origin_url.host.name);
	event_add_int(req->event, "dest_port", http_url_get_port(&req->origin_url));
	if (req->target != NULL)
		event_add_str(req->event, "target", req->target);
	event_set_append_log_prefix(req->event, t_strdup_printf(
		"request %s: ", http_client_request_label(req)));
}

static struct event_passthrough *
http_client_request_result_event(struct http_client_request *req)
{
	struct http_client_connection *conn = req->conn;

	if (conn != NULL) {
		if (req->state == HTTP_REQUEST_STATE_PAYLOAD_OUT) {
			/* got here prematurely; use bytes written so far */
			i_assert(req->request_offset <
				 conn->conn.output->offset);
			req->bytes_out = conn->conn.output->offset -
				req->request_offset;
		}
		if (conn->incoming_payload != NULL &&
			(req->state == HTTP_REQUEST_STATE_GOT_RESPONSE ||
			 req->state == HTTP_REQUEST_STATE_PAYLOAD_IN)) {
			/* got here prematurely; use bytes read so far */
			i_assert(conn->in_req_callback ||
				 conn->pending_request == req);
			i_assert(req->response_offset <
				 conn->conn.input->v_offset);
			req->bytes_in = conn->conn.input->v_offset -
				req->response_offset;
		}
	}

	struct event_passthrough *e = event_create_passthrough(req->event);
	if (req->queue != NULL &&
	    req->queue->addr.type != HTTP_CLIENT_PEER_ADDR_UNIX)
		e->add_str("dest_ip", net_ip2addr(&req->queue->addr.a.tcp.ip));

	return e->add_int("status_code", req->last_status)->
		add_int("attempts", req->attempts)->
		add_int("redirects", req->redirects)->
		add_int("bytes_in", req->bytes_in)->
		add_int("bytes_out", req->bytes_out);
}

static struct http_client_request *
http_client_request_new(struct http_client *client, const char *method, 
		    http_client_request_callback_t *callback, void *context)
{
	static unsigned int id_counter = 0;
	pool_t pool;
	struct http_client_request *req;

	pool = pool_alloconly_create("http client request", 2048);
	req = p_new(pool, struct http_client_request, 1);
	req->pool = pool;
	req->refcount = 1;
	req->client = client;
	req->id = ++id_counter;
	req->method = p_strdup(pool, method);
	req->callback = callback;
	req->context = context;
	req->date = (time_t)-1;
	req->event = event_create(client->event);

	/* default to client-wide settings: */
	req->max_attempts = client->set.max_attempts;
	req->attempt_timeout_msecs = client->set.request_timeout_msecs;

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
	req->origin_url.host.name = p_strdup(req->pool, host);
	req->target = (target == NULL ? "/" : p_strdup(req->pool, target));
	http_client_request_update_event(req);
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
	if (target_url->user != NULL && *target_url->user != '\0' &&
		target_url->password != NULL) {
		req->username = p_strdup(req->pool, target_url->user);
		req->password = p_strdup(req->pool, target_url->password);
	}
	http_client_request_update_event(req);
	return req;
}

#undef http_client_request_url_str
struct http_client_request *
http_client_request_url_str(struct http_client *client,
		    const char *method, const char *url_str,
		    http_client_request_callback_t *callback, void *context)
{
	struct http_client_request *req, *tmpreq;
	struct http_url *target_url;
	const char *error;

	req = tmpreq = http_client_request_new
		(client, method, callback, context);

	if (http_url_parse(url_str, NULL, HTTP_URL_ALLOW_USERINFO_PART,
		req->pool, &target_url, &error) < 0) {
		req->label = p_strdup_printf(req->pool,
			"[Req%u: %s %s]", req->id, req->method, url_str);
		http_client_request_error(&tmpreq,
			HTTP_CLIENT_REQUEST_ERROR_INVALID_URL,
			t_strdup_printf("Invalid HTTP URL: %s", error));
		http_client_request_update_event(req);
		return req;
	}

	req->origin_url = *target_url;
	req->target = p_strdup(req->pool, http_url_create_target(target_url));
	if (target_url->user != NULL && *target_url->user != '\0' &&
		target_url->password != NULL) {
		req->username = p_strdup(req->pool, target_url->user);
		req->password = p_strdup(req->pool, target_url->password);
	}
	http_client_request_update_event(req);
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
	req->origin_url.host.name = p_strdup(req->pool, host);
	req->origin_url.port = port;
	req->connect_tunnel = TRUE;
	req->target = req->origin_url.host.name;
	http_client_request_update_event(req);
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
	const char *hostname;

	i_assert(ip->family != 0);
	hostname = net_ip2addr(ip);

	req = http_client_request_connect
		(client, hostname, port, callback, context);
	req->origin_url.host.ip = *ip;
	return req;
}

void http_client_request_set_event(struct http_client_request *req,
				   struct event *event)
{
	event_unref(&req->event);
	req->event = event_create(event);
	event_set_forced_debug(req->event, req->client->set.debug);
	http_client_request_update_event(req);
}

static void
http_client_request_add(struct http_client_request *req)
{
	struct http_client *client = req->client;

	DLLIST_PREPEND(&client->requests_list, req);
	client->requests_count++;
	req->listed = TRUE;
}

static void
http_client_request_remove(struct http_client_request *req)
{
	struct http_client *client = req->client;

	if (client == NULL) {
		i_assert(!req->listed);
		return;
	}
	if (req->listed) {
		/* only decrease pending request counter if this request was submitted */
		DLLIST_REMOVE(&client->requests_list, req);
		client->requests_count--;
	}
	req->listed = FALSE;

	if (client->requests_count == 0 && client->waiting)
		io_loop_stop(client->ioloop);
}

void http_client_request_ref(struct http_client_request *req)
{
	i_assert(req->refcount > 0);
	req->refcount++;
}

bool http_client_request_unref(struct http_client_request **_req)
{
	struct http_client_request *req = *_req;
	struct http_client *client = req->client;

	i_assert(req->refcount > 0);

	*_req = NULL;

	if (--req->refcount > 0)
		return TRUE;

	if (client == NULL) {
		e_debug(req->event, "Free (client already destroyed)");
	} else {
		e_debug(req->event, "Free (requests left=%d)",
			client->requests_count);
	}

	/* cannot be destroyed while it is still pending */
	i_assert(req->conn == NULL);

	if (req->queue != NULL)
		http_client_queue_drop_request(req->queue, req);

	if (req->destroy_callback != NULL) {
		req->destroy_callback(req->destroy_context);
		req->destroy_callback = NULL;
	}

	http_client_request_remove(req);

	if (client != NULL) {
		if (client->requests_count == 0 && client->waiting)
			io_loop_stop(client->ioloop);
		if (req->delayed_error != NULL)
			http_client_remove_request_error(req->client, req);
	}
	i_stream_unref(&req->payload_input);
	o_stream_unref(&req->payload_output);
	str_free(&req->headers);
	event_unref(&req->event);
	pool_unref(&req->pool);
	return FALSE;
}

void http_client_request_destroy(struct http_client_request **_req)
{
	struct http_client_request *req = *_req, *tmp_req;
	struct http_client *client = req->client;

	*_req = NULL;

	if (client == NULL) {
		e_debug(req->event, "Destroy (client already destroyed)");
	} else {
		e_debug(req->event, "Destroy (requests left=%d)",
			client->requests_count);
	}


	if (req->state < HTTP_REQUEST_STATE_FINISHED)
		req->state = HTTP_REQUEST_STATE_ABORTED;
	req->callback = NULL;

	if (req->queue != NULL)
		http_client_queue_drop_request(req->queue, req);
		
	if (client != NULL && req->delayed_error != NULL)
		http_client_remove_request_error(req->client, req);
	req->delayed_error = NULL;

	if (req->destroy_callback != NULL) {
		void (*callback)(void *) = req->destroy_callback;

		req->destroy_callback = NULL;
		callback(req->destroy_context);
	}

	if (req->conn != NULL)
		http_client_connection_request_destroyed(req->conn, req);

	tmp_req = req;
	http_client_request_remove(req);
	if (http_client_request_unref(&tmp_req))
		req->client = NULL;
}

void http_client_request_set_port(struct http_client_request *req,
	in_port_t port)
{
	i_assert(req->state == HTTP_REQUEST_STATE_NEW);
	req->origin_url.port = port;
	event_add_int(req->event, "port", port);
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

void http_client_request_set_preserve_exact_reason(struct http_client_request *req)
{
	req->preserve_exact_reason = TRUE;
}

static bool
http_client_request_lookup_header_pos(struct http_client_request *req,
				      const char *key,
				      size_t *key_pos_r, size_t *value_pos_r,
				      size_t *next_pos_r)
{
	const unsigned char *data, *p;
	size_t size, line_len;
	size_t key_len = strlen(key);

	if (req->headers == NULL)
		return FALSE;

	data = str_data(req->headers);
	size = str_len(req->headers);
	while ((p = memchr(data, '\n', size)) != NULL) {
		line_len = (p+1) - data;
		if (size > key_len && i_memcasecmp(data, key, key_len) == 0 &&
		    data[key_len] == ':' && data[key_len+1] == ' ') {
			/* key was found from header, replace its value */
			*key_pos_r = str_len(req->headers) - size;
			*value_pos_r = *key_pos_r + key_len + 2;
			*next_pos_r = *key_pos_r + line_len;
			return TRUE;
		}
		size -= line_len;
		data += line_len;
	}
	return FALSE;
}

static void
http_client_request_add_header_full(struct http_client_request *req,
				    const char *key, const char *value,
				    bool replace_existing)
{
	size_t key_pos, value_pos, next_pos;

	i_assert(req->state == HTTP_REQUEST_STATE_NEW ||
		 /* allow calling for retries */
		 req->state == HTTP_REQUEST_STATE_GOT_RESPONSE ||
		 req->state == HTTP_REQUEST_STATE_ABORTED);
	/* make sure key or value can't break HTTP headers entirely */
	i_assert(strpbrk(key, ":\r\n") == NULL);
	i_assert(strpbrk(value, "\r\n") == NULL);

	/* mark presence of special headers */
	switch (key[0]) {
	case 'a': case 'A':
		if (strcasecmp(key, "Authorization") == 0)
			req->have_hdr_authorization = TRUE;
		break;
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
	case 'p': case 'P':
		i_assert(strcasecmp(key, "Proxy-Authorization") != 0);
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
	if (!http_client_request_lookup_header_pos(req, key, &key_pos,
						   &value_pos, &next_pos))
		str_printfa(req->headers, "%s: %s\r\n", key, value);
	else if (replace_existing) {
		/* don't delete CRLF */
		size_t old_value_len = next_pos - value_pos - 2;
		str_replace(req->headers, value_pos, old_value_len, value);
	}
}

void http_client_request_add_header(struct http_client_request *req,
				    const char *key, const char *value)
{
	http_client_request_add_header_full(req, key, value, TRUE);
}

void http_client_request_add_missing_header(struct http_client_request *req,
					    const char *key, const char *value)
{
	http_client_request_add_header_full(req, key, value, FALSE);
}

void http_client_request_remove_header(struct http_client_request *req,
				       const char *key)
{
	size_t key_pos, value_pos, next_pos;

	i_assert(req->state == HTTP_REQUEST_STATE_NEW ||
		 /* allow calling for retries */
		 req->state == HTTP_REQUEST_STATE_GOT_RESPONSE ||
		 req->state == HTTP_REQUEST_STATE_ABORTED);

	if (http_client_request_lookup_header_pos(req, key, &key_pos,
						  &value_pos, &next_pos))
		str_delete(req->headers, key_pos, next_pos - key_pos);
}

const char *http_client_request_lookup_header(struct http_client_request *req,
					      const char *key)
{
	size_t key_pos, value_pos, next_pos;

	if (!http_client_request_lookup_header_pos(req, key, &key_pos,
						   &value_pos, &next_pos))
		return NULL;

	/* don't return CRLF */
	return t_strndup(str_data(req->headers) + value_pos,
			 next_pos - value_pos - 2);
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

void http_client_request_set_payload_data(struct http_client_request *req,
				     const unsigned char *data, size_t size)
{
	struct istream *input;
	unsigned char *payload_data;

	if (size == 0)
		return;

	payload_data = p_malloc(req->pool, size);
	memcpy(payload_data, data, size);
	input = i_stream_create_from_data(payload_data, size);

	http_client_request_set_payload(req, input, FALSE);
	i_stream_unref(&input);
}

void http_client_request_set_payload_empty(struct http_client_request *req)
{
	req->payload_empty = TRUE;
}

void http_client_request_set_timeout_msecs(struct http_client_request *req,
	unsigned int msecs)
{
	i_assert(req->state == HTTP_REQUEST_STATE_NEW ||
		req->state == HTTP_REQUEST_STATE_GOT_RESPONSE);

	req->timeout_msecs = msecs;
}

void http_client_request_set_timeout(struct http_client_request *req,
	const struct timeval *time)
{
	i_assert(req->state == HTTP_REQUEST_STATE_NEW ||
		req->state == HTTP_REQUEST_STATE_GOT_RESPONSE);

	req->timeout_time = *time;
	req->timeout_msecs = 0;
}

void http_client_request_set_attempt_timeout_msecs(struct http_client_request *req,
	unsigned int msecs)
{
	i_assert(req->state == HTTP_REQUEST_STATE_NEW ||
		req->state == HTTP_REQUEST_STATE_GOT_RESPONSE);

	req->attempt_timeout_msecs = msecs;
}

void http_client_request_set_max_attempts(struct http_client_request *req,
	unsigned int max_attempts)
{
	i_assert(req->state == HTTP_REQUEST_STATE_NEW ||
		req->state == HTTP_REQUEST_STATE_GOT_RESPONSE);

	req->max_attempts = max_attempts;
}

void http_client_request_set_event_headers(struct http_client_request *req,
					   const char *const *headers)
{
	req->event_headers = p_strarray_dup(req->pool, headers);
}

void http_client_request_set_auth_simple(struct http_client_request *req,
	const char *username, const char *password)
{
	req->username = p_strdup(req->pool, username);
	req->password = p_strdup(req->pool, password);
}

void http_client_request_set_proxy_url(struct http_client_request *req,
	const struct http_url *proxy_url)
{
	i_assert(req->state == HTTP_REQUEST_STATE_NEW ||
		req->state == HTTP_REQUEST_STATE_GOT_RESPONSE);

	req->host_url = http_url_clone_authority(req->pool, proxy_url);
	req->host_socket = NULL;
}

void http_client_request_set_proxy_socket(struct http_client_request *req,
	const char *proxy_socket)
{
	i_assert(req->state == HTTP_REQUEST_STATE_NEW ||
		req->state == HTTP_REQUEST_STATE_GOT_RESPONSE);

	req->host_socket = p_strdup(req->pool, proxy_socket);
	req->host_url = NULL;
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

void http_client_request_delay_msecs(struct http_client_request *req,
	unsigned int msecs)
{
	req->release_time = ioloop_timeval;
	timeval_add_msecs(&req->release_time, msecs);
}

int http_client_request_delay_from_response(struct http_client_request *req,
	const struct http_response *response)
{
	time_t retry_after = response->retry_after;
	unsigned int max;

	i_assert(req->client != NULL);

	if (retry_after == (time_t)-1)
		return 0;  /* no delay */
	if (retry_after < ioloop_time)
		return 0;  /* delay already expired */
	max = (req->client->set.max_auto_retry_delay == 0 ?
		req->attempt_timeout_msecs / 1000 :
		req->client->set.max_auto_retry_delay);
	if ((unsigned int)(retry_after - ioloop_time) > max)
		return -1; /* delay too long */
	req->release_time.tv_sec = retry_after;
	req->release_time.tv_usec = 0;
	return 1;    /* valid delay */
}

const char *
http_client_request_get_method(const struct http_client_request *req)
{
	return req->method;
}

const char *
http_client_request_get_target(const struct http_client_request *req)
{
	return req->target;
}

const struct http_url *
http_client_request_get_origin_url(const struct http_client_request *req)
{
	return &req->origin_url;
}

enum http_request_state
http_client_request_get_state(const struct http_client_request *req)
{
	return req->state;
}

unsigned int
http_client_request_get_attempts(const struct http_client_request *req)
{
	return req->attempts;
}

void http_client_request_get_stats(struct http_client_request *req,
	struct http_client_request_stats *stats_r)
{
	struct http_client *client = req->client;
	int diff_msecs;
	uint64_t wait_usecs;

	i_zero(stats_r);
	if (!req->submitted)
		return;

	/* total elapsed time since message was submitted */
	diff_msecs = timeval_diff_msecs(&ioloop_timeval, &req->submit_time);
	stats_r->total_msecs = (unsigned int)I_MAX(diff_msecs, 0);

	/* elapsed time since message was first sent */
	if (req->first_sent_time.tv_sec > 0) {
		diff_msecs = timeval_diff_msecs(&ioloop_timeval, &req->first_sent_time);
		stats_r->first_sent_msecs = (unsigned int)I_MAX(diff_msecs, 0);
	}

	/* elapsed time since message was last sent */
	if (req->sent_time.tv_sec > 0) {
		diff_msecs = timeval_diff_msecs(&ioloop_timeval, &req->sent_time);
		stats_r->last_sent_msecs = (unsigned int)I_MAX(diff_msecs, 0);
	}

	if (req->conn != NULL) {
		/* time spent in other ioloops */
		i_assert(ioloop_global_wait_usecs >= req->sent_global_ioloop_usecs);
		stats_r->other_ioloop_msecs = (unsigned int)
			(ioloop_global_wait_usecs - req->sent_global_ioloop_usecs + 999) / 1000;

		/* time spent in the http-client's own ioloop */
		if (client != NULL && client->waiting) {
			wait_usecs = io_wait_timer_get_usecs(req->conn->io_wait_timer);
			i_assert(wait_usecs >= req->sent_http_ioloop_usecs);
			stats_r->http_ioloop_msecs = (unsigned int)
				(wait_usecs - req->sent_http_ioloop_usecs + 999) / 1000;

			i_assert(stats_r->other_ioloop_msecs >= stats_r->http_ioloop_msecs);
			stats_r->other_ioloop_msecs -= stats_r->http_ioloop_msecs;
		}
	}

	/* total time spent on waiting for file locks */
	wait_usecs = file_lock_wait_get_total_usecs();
	i_assert(wait_usecs >= req->sent_lock_usecs);
	stats_r->lock_msecs = (unsigned int)
		(wait_usecs - req->sent_lock_usecs + 999) / 1000;

	/* number of attempts for this request */
	stats_r->attempts = req->attempts;
	/* number of send attempts for this request */
	stats_r->send_attempts = req->send_attempts;
}

void http_client_request_append_stats_text(struct http_client_request *req,
	string_t *str)
{
	struct http_client_request_stats stats;

	if (!req->submitted) {
		str_append(str, "not yet submitted");
		return;
	}

	http_client_request_get_stats(req, &stats);

	str_printfa(str, "queued %u.%03u secs ago",
		    stats.total_msecs/1000, stats.total_msecs%1000);
	if (stats.attempts > 0)
		str_printfa(str, ", %u times retried", stats.attempts);

	if (stats.send_attempts == 0) {
		str_append(str, ", not yet sent");
	} else {
		str_printfa(str, ", %u send attempts in %u.%03u secs",
			    stats.send_attempts,
			    stats.first_sent_msecs/1000, stats.first_sent_msecs%1000);
		if (stats.send_attempts > 1) {
			str_printfa(str, ", %u.%03u in last attempt",
				    stats.last_sent_msecs/1000,
				    stats.last_sent_msecs%1000);
		}
	}

	if (stats.http_ioloop_msecs > 0) {
		str_printfa(str, ", %u.%03u in http ioloop",
			    stats.http_ioloop_msecs/1000,
			    stats.http_ioloop_msecs%1000);
	}
	str_printfa(str, ", %u.%03u in other ioloops",
		    stats.other_ioloop_msecs/1000, stats.other_ioloop_msecs%1000);

	if (stats.lock_msecs > 0) {
		str_printfa(str, ", %u.%03u in locks",
			    stats.lock_msecs/1000, stats.lock_msecs%1000);
	}
}

enum http_response_payload_type
http_client_request_get_payload_type(struct http_client_request *req)
{
	/* RFC 7230, Section 3.3:

		 The presence of a message body in a response depends on both the
		 request method to which it is responding and the response status code
		 (Section 3.1.2 of [RFC7230]). Responses to the HEAD request method
	   (Section 4.3.2 of [RFC7231]) never include a message body because the
	   associated response header fields (e.g., Transfer-Encoding,
	   Content-Length, etc.), if present, indicate only what their values
	   would have been if the request method had been GET (Section 4.3.1 of
	   [RFC7231]). 2xx (Successful) responses to a CONNECT request method
	   (Section 4.3.6 of [RFC7231]) switch to tunnel mode instead of having a
	   message body.
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
	const char *proxy_socket_path = client->set.proxy_socket_path;
	const struct http_url *proxy_url = client->set.proxy_url;
	bool have_proxy = (proxy_socket_path != NULL) || (proxy_url != NULL) ||
		(req->host_socket != NULL) || (req->host_url != NULL);
	const char *authority, *target;

	if (req->state == HTTP_REQUEST_STATE_ABORTED)
		return;
	i_assert(client != NULL);
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
	if (have_proxy) {
		if (req->host_socket != NULL) {               /* specific socket proxy */
			req->host_url = NULL;
		} else if (req->host_url != NULL) {           /* specific normal proxy */
			req->host_socket = NULL;
		} else if (req->origin_url.have_ssl &&
			!client->set.no_ssl_tunnel &&	!req->connect_tunnel) {
			req->host_url = &req->origin_url;           /* tunnel to origin server */
			req->ssl_tunnel = TRUE;
		} else if (proxy_socket_path != NULL) {
			req->host_socket = proxy_socket_path;       /* proxy on unix socket */
			req->host_url = NULL;
		} else {
			req->host_url = proxy_url;                  /* normal proxy server */
			req->host_socket = NULL;
		}
	} else {
		req->host_url = &req->origin_url;             /* origin server */
	}

	/* use submission date if no date is set explicitly */
	if (req->date == (time_t)-1)
		req->date = ioloop_time;
	
	/* prepare value for Host header */
	req->authority = p_strdup(req->pool, authority);

	/* debug label */
	req->label = p_strdup_printf(req->pool, "[Req%u: %s %s]", req->id, req->method, target);

	/* update request target */
	if (req->connect_tunnel || have_proxy)
		req->target = p_strdup(req->pool, target);

	if (!have_proxy) {
		/* if we don't have a proxy, CONNECT requests are handled by creating
		   the requested connection directly */
		req->connect_direct = req->connect_tunnel;
		if (req->connect_direct)
			req->urgent = TRUE;
	}

	if (req->timeout_time.tv_sec == 0) {
		if (req->timeout_msecs > 0) {
			req->timeout_time = ioloop_timeval;
			timeval_add_msecs(&req->timeout_time, req->timeout_msecs);
		} else if (	client->set.request_absolute_timeout_msecs > 0) {
			req->timeout_time = ioloop_timeval;
			timeval_add_msecs(&req->timeout_time, client->set.request_absolute_timeout_msecs);
		}
	}

	host = http_client_host_get(client, req->host_url);
	req->state = HTTP_REQUEST_STATE_QUEUED;
	req->last_status = 0;

	http_client_host_submit_request(host, req);
}

void http_client_request_submit(struct http_client_request *req)
{
	i_assert(req->client != NULL);

	req->submit_time = ioloop_timeval;

	http_client_request_do_submit(req);

	req->submitted = TRUE;
	http_client_request_add(req);

	e_debug(req->event, "Submitted (requests left=%d)",
		req->client->requests_count);
}

void
http_client_request_get_peer_addr(const struct http_client_request *req,
	struct http_client_peer_addr *addr)
{
	const char *host_socket = req->host_socket;
	const struct http_url *host_url = req->host_url;
	
	/* the IP address may be unassigned in the returned peer address, since
	   that is only available at this stage when the target URL has an
	   explicit IP address. */
	i_zero(addr);
	if (host_socket != NULL) {
		addr->type = HTTP_CLIENT_PEER_ADDR_UNIX;
		addr->a.un.path = host_socket;		
	} else if (req->connect_direct) {
		addr->type = HTTP_CLIENT_PEER_ADDR_RAW;
		addr->a.tcp.ip = host_url->host.ip;
		addr->a.tcp.port =
			http_url_get_port_default(host_url, HTTPS_DEFAULT_PORT);
	} else if (host_url->have_ssl) {
		if (req->ssl_tunnel)
			addr->type = HTTP_CLIENT_PEER_ADDR_HTTPS_TUNNEL;
		else
			addr->type = HTTP_CLIENT_PEER_ADDR_HTTPS;
		addr->a.tcp.ip = host_url->host.ip;
		addr->a.tcp.https_name = host_url->host.name;
		addr->a.tcp.port = http_url_get_port(host_url);
	} else {
		addr->type = HTTP_CLIENT_PEER_ADDR_HTTP;
		addr->a.tcp.ip = host_url->host.ip;
		addr->a.tcp.port = http_url_get_port(host_url);
	}
}

static void
http_client_request_finish_payload_out(struct http_client_request *req)
{
	struct http_client_connection *conn = req->conn;

	i_assert(conn != NULL);

	/* drop payload output stream */
	if (req->payload_output != NULL) {
		o_stream_unref(&req->payload_output);
		req->payload_output = NULL;
	}

	i_assert(req->request_offset < conn->conn.output->offset);
	req->bytes_out = conn->conn.output->offset - req->request_offset;

	/* advance state only when request didn't get aborted in the mean time */
	if (req->state != HTTP_REQUEST_STATE_ABORTED) {
		i_assert(req->state == HTTP_REQUEST_STATE_PAYLOAD_OUT);

		/* we're now waiting for a response from the server */
		req->state = HTTP_REQUEST_STATE_WAITING;
		http_client_connection_start_request_timeout(conn);
	}

	/* release connection */
	conn->output_locked = FALSE;

	e_debug(req->event, "Finished sending%s payload",
		(req->state == HTTP_REQUEST_STATE_ABORTED ? " aborted" : ""));
}

static int
http_client_request_continue_payload(struct http_client_request **_req,
	const unsigned char *data, size_t size)
{
	struct ioloop *prev_ioloop, *client_ioloop, *prev_client_ioloop;
	struct http_client_request *req = *_req;
	struct http_client_connection *conn = req->conn;
	struct http_client *client = req->client;
	int ret;

	i_assert(client != NULL);
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
	if (req->state == HTTP_REQUEST_STATE_ABORTED) {
		/* Request already failed */
		if (req->delayed_error != NULL) {
			struct http_client_request *tmpreq = req;

			/* Handle delayed error outside ioloop; the caller expects callbacks
			   occurring, so there is no need for delay. Also, it is very
			   important that any error triggers a callback before
			   http_client_request_send_payload() finishes, since its return
			   value is not always checked.
			 */
			http_client_remove_request_error(client, req);
			http_client_request_error_delayed(&tmpreq);
		}
	} else {
		/* Wait for payload data to be written */

		prev_ioloop = current_ioloop;
		client_ioloop = io_loop_create();
		prev_client_ioloop = http_client_switch_ioloop(client);
		if (client->set.dns_client != NULL)
			dns_client_switch_ioloop(client->set.dns_client);

		client->waiting = TRUE;
		while (req->state < HTTP_REQUEST_STATE_PAYLOAD_IN) {
			e_debug(req->event, "Waiting for request to finish");
		
			if (req->state == HTTP_REQUEST_STATE_PAYLOAD_OUT)
				o_stream_set_flush_pending(req->payload_output, TRUE);

			io_loop_run(client_ioloop);

			if (req->state == HTTP_REQUEST_STATE_PAYLOAD_OUT &&
				req->payload_input->eof) {
				i_stream_unref(&req->payload_input);
				req->payload_input = NULL;
				break;
			}
		}	
		client->waiting = FALSE;

		if (prev_client_ioloop != NULL)
			io_loop_set_current(prev_client_ioloop);
		else
			io_loop_set_current(prev_ioloop);
		(void)http_client_switch_ioloop(client);
		if (client->set.dns_client != NULL)
			dns_client_switch_ioloop(client->set.dns_client);
		io_loop_set_current(client_ioloop);
		io_loop_destroy(&client_ioloop);
	}

	switch (req->state) {
	case HTTP_REQUEST_STATE_PAYLOAD_IN:
	case HTTP_REQUEST_STATE_FINISHED:
		ret = 1;
		break;
	case HTTP_REQUEST_STATE_ABORTED:
		ret = -1;
		break;
	default:
		ret = 0;
		break;
	}

	req->payload_wait = FALSE;

	/* callback may have messed with our pointer,
	   so unref using local variable */	
	if (!http_client_request_unref(&req))
		*_req = NULL;

	if (conn != NULL)
		http_client_connection_unref(&conn);

	/* Return status */
	return ret;
}

int http_client_request_send_payload(struct http_client_request **_req,
	const unsigned char *data, size_t size)
{
	struct http_client_request *req = *_req;
	int ret;

	i_assert(data != NULL);

	ret = http_client_request_continue_payload(&req, data, size);
	if (ret < 0) {
		/* failed to send payload */
		*_req = NULL;
	} else if (ret > 0) {
		/* premature end of request;
		   server sent error before all payload could be sent */
		ret = -1;
		*_req = NULL;
	} else {
		/* not finished sending payload */
		i_assert(req != NULL);
	}
	return ret;
}

int http_client_request_finish_payload(struct http_client_request **_req)
{
	struct http_client_request *req = *_req;
	int ret;

	*_req = NULL;
	ret = http_client_request_continue_payload(&req, NULL, 0);
	i_assert(ret != 0);
	return ret < 0 ? -1 : 0;
}

static void http_client_request_payload_input(struct http_client_request *req)
{	
	struct http_client_connection *conn = req->conn;

	io_remove(&conn->io_req_payload);

	(void)http_client_connection_output(conn);
}

int http_client_request_send_more(struct http_client_request *req,
				  bool pipelined)
{
	struct http_client_connection *conn = req->conn;
	struct http_client_context *cctx = conn->ppool->peer->cctx;
	struct ostream *output = req->payload_output;
	enum ostream_send_istream_result res;
	const char *error;
	uoff_t offset;

	i_assert(req->payload_input != NULL);
	i_assert(req->payload_output != NULL);

	io_remove(&conn->io_req_payload);

	/* chunked ostream needs to write to the parent stream's buffer */
	offset = req->payload_input->v_offset;
	o_stream_set_max_buffer_size(output, IO_BLOCK_SIZE);
	res = o_stream_send_istream(output, req->payload_input);
	o_stream_set_max_buffer_size(output, (size_t)-1);

	i_assert(req->payload_input->v_offset >= offset);
	e_debug(req->event, "Send more (sent %"PRIuUOFF_T", buffered=%"PRIuSIZE_T")",
		(uoff_t)(req->payload_input->v_offset - offset),
		o_stream_get_buffer_used_size(output));

	switch (res) {
	case OSTREAM_SEND_ISTREAM_RESULT_FINISHED:
		/* finished sending */
		if (!req->payload_chunked &&
		    req->payload_input->v_offset - req->payload_offset != req->payload_size) {
			error = t_strdup_printf("BUG: stream '%s' input size changed: "
				"%"PRIuUOFF_T"-%"PRIuUOFF_T" != %"PRIuUOFF_T,
				i_stream_get_name(req->payload_input),
				req->payload_input->v_offset, req->payload_offset, req->payload_size);
			i_error("%s", error); //FIXME: remove?
			http_client_connection_lost(&conn, error);
			return -1;
		}

		if (req->payload_wait) {
			/* this chunk of input is finished
			   (client needs to act; disable timeout) */
			i_assert(!pipelined);
			conn->output_locked = TRUE;
			http_client_connection_stop_request_timeout(conn);
			if (req->client != NULL && req->client->waiting)
				io_loop_stop(req->client->ioloop);
		} else {
			/* finished sending payload */
			http_client_request_finish_payload_out(req);
		}
		return 0;
	case OSTREAM_SEND_ISTREAM_RESULT_WAIT_INPUT:
		/* input is blocking (client needs to act; disable timeout) */
		conn->output_locked = TRUE;	
		if (!pipelined)
			http_client_connection_stop_request_timeout(conn);
		conn->io_req_payload = io_add_istream_to(
			cctx->ioloop, req->payload_input,
			http_client_request_payload_input, req);
		return 0;
	case OSTREAM_SEND_ISTREAM_RESULT_WAIT_OUTPUT:
		/* output is blocking (server needs to act; enable timeout) */
		conn->output_locked = TRUE;
		if (!pipelined)
			http_client_connection_start_request_timeout(conn);
		e_debug(req->event, "Partially sent payload");
		return 0;
	case OSTREAM_SEND_ISTREAM_RESULT_ERROR_INPUT:
		/* we're in the middle of sending a request, so the connection
		   will also have to be aborted */
		error = t_strdup_printf("read(%s) failed: %s",
					i_stream_get_name(req->payload_input),
					i_stream_get_error(req->payload_input));

		/* the payload stream assigned to this request is broken,
		   fail this the request immediately */
		http_client_request_error(&req,
			HTTP_CLIENT_REQUEST_ERROR_BROKEN_PAYLOAD,
			"Broken payload stream");

		http_client_connection_lost(&conn, error);
		return -1;
	case OSTREAM_SEND_ISTREAM_RESULT_ERROR_OUTPUT:
		/* failed to send request */
		http_client_connection_handle_output_error(conn);
		return -1;
	}
	i_unreached();
}

static int http_client_request_send_real(struct http_client_request *req,
					 bool pipelined)
{
	const struct http_client_settings *set = &req->client->set;
	struct http_client_connection *conn = req->conn;
	string_t *rtext = t_str_new(256);
	struct const_iovec iov[3];

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
	if (!req->have_hdr_authorization &&
		req->username != NULL && req->password != NULL) {
		struct http_auth_credentials auth_creds;

		http_auth_basic_credentials_init(&auth_creds,
			req->username, req->password);

		str_append(rtext, "Authorization: ");
		http_auth_create_credentials(rtext, &auth_creds);
		str_append(rtext, "\r\n");
	}
	if (http_client_request_to_proxy(req) &&
		set->proxy_username != NULL && set->proxy_password != NULL) {
		struct http_auth_credentials auth_creds;

		http_auth_basic_credentials_init(&auth_creds,
			set->proxy_username, set->proxy_password);

		str_append(rtext, "Proxy-Authorization: ");
		http_auth_create_credentials(rtext, &auth_creds);
		str_append(rtext, "\r\n");
	}
	if (!req->have_hdr_user_agent && req->client->set.user_agent != NULL) {
		str_printfa(rtext, "User-Agent: %s\r\n",
			    req->client->set.user_agent);
	}
	if (!req->have_hdr_expect && req->payload_sync) {
		str_append(rtext, "Expect: 100-continue\r\n");
	}
	if (req->payload_input != NULL && req->payload_chunked) {
		// FIXME: can't do this for a HTTP/1.0 server
		if (!req->have_hdr_body_spec)
			str_append(rtext, "Transfer-Encoding: chunked\r\n");
		req->payload_output =
			http_transfer_chunked_ostream_create(conn->conn.output);
	} else if (req->payload_input != NULL ||
		req->payload_empty ||
		strcasecmp(req->method, "POST") == 0 ||
		strcasecmp(req->method, "PUT") == 0) {

		/* send Content-Length if we have specified a payload
		   or when one is normally expected, even if it's 0 bytes. */
		i_assert(req->payload_input != NULL || req->payload_size == 0);
		if (!req->have_hdr_body_spec) {
			str_printfa(rtext, "Content-Length: %"PRIuUOFF_T"\r\n",
				req->payload_size);
		}
		if (req->payload_input != NULL) {
			req->payload_output = conn->conn.output;
			o_stream_ref(conn->conn.output);
		}
	}
	if (!req->have_hdr_connection &&
		!http_client_request_to_proxy(req)) {
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
	req->send_attempts++;
	if (req->first_sent_time.tv_sec == 0)
		req->first_sent_time = ioloop_timeval;
	req->sent_time = ioloop_timeval;
	req->sent_lock_usecs = file_lock_wait_get_total_usecs();
	req->sent_global_ioloop_usecs = ioloop_global_wait_usecs;
	req->sent_http_ioloop_usecs =
		io_wait_timer_get_usecs(req->conn->io_wait_timer);
	o_stream_cork(conn->conn.output);
	req->request_offset = conn->conn.output->offset;
	if (o_stream_sendv(conn->conn.output, iov, N_ELEMENTS(iov)) < 0) {
		http_client_connection_handle_output_error(conn);
		return -1;
	}

	e_debug(req->event, "Sent header");

	if (req->payload_output != NULL) {
		if (!req->payload_sync) {
			if (http_client_request_send_more(req, pipelined) < 0)
				return -1;
		} else {
			e_debug(req->event, "Waiting for 100-continue");
			conn->output_locked = TRUE;
		}
	} else {
		req->state = HTTP_REQUEST_STATE_WAITING;
		if (!pipelined)
			http_client_connection_start_request_timeout(req->conn);
		conn->output_locked = FALSE;
	}
	if (conn->conn.output != NULL) {
		i_assert(req->request_offset < conn->conn.output->offset);
		req->bytes_out = conn->conn.output->offset - req->request_offset;
		if (o_stream_uncork_flush(conn->conn.output) < 0) {
			http_client_connection_handle_output_error(conn);
			return -1;
		}
	}
	return 0;
}

int http_client_request_send(struct http_client_request *req,
			     bool pipelined)
{
	int ret;

	T_BEGIN {
		ret = http_client_request_send_real(req, pipelined);
	} T_END;

	return ret;
}

bool http_client_request_callback(struct http_client_request *req,
			     struct http_response *response)
{
	http_client_request_callback_t *callback = req->callback;
	unsigned int orig_attempts = req->attempts;

	req->state = HTTP_REQUEST_STATE_GOT_RESPONSE;
	req->last_status = response->status;

	req->callback = NULL;
	if (callback != NULL) {
		struct http_response response_copy = *response;

		if (req->attempts > 0 && !req->preserve_exact_reason) {
			unsigned int total_msecs =
				timeval_diff_msecs(&ioloop_timeval, &req->submit_time);
			response_copy.reason = t_strdup_printf(
				"%s (%u retries in %u.%03u secs)",
				response_copy.reason, req->attempts,
				total_msecs/1000, total_msecs%1000);
		}

		callback(&response_copy, req->context);
		if (req->attempts != orig_attempts) {
			/* retrying */
			req->callback = callback;
			http_client_request_resubmit(req);
			return FALSE;
		} else {
			/* release payload early (prevents server/client deadlock in proxy) */
			i_stream_unref(&req->payload_input);
		}
	}
	return TRUE;
}

static bool
http_client_request_send_error(struct http_client_request *req,
			       unsigned int status, const char *error)
{
	http_client_request_callback_t *callback;
	bool sending = (req->state == HTTP_REQUEST_STATE_PAYLOAD_OUT);
	unsigned int orig_attempts = req->attempts;

	req->state = HTTP_REQUEST_STATE_ABORTED;

	callback = req->callback;
	req->callback = NULL;
	if (callback != NULL) {
		struct http_response response;

		http_response_init(&response, status, error);
		(void)callback(&response, req->context);

		if (req->attempts != orig_attempts) {
			/* retrying */
			req->callback = callback;
			http_client_request_resubmit(req);
			return FALSE;
		} else {
			/* release payload early (prevents server/client deadlock in proxy) */
			if (!sending && req->payload_input != NULL)
				i_stream_unref(&req->payload_input);
		}
	}
	if (req->payload_wait) {
		i_assert(req->client != NULL);
		io_loop_stop(req->client->ioloop);
	}
	return TRUE;
}

void http_client_request_error_delayed(struct http_client_request **_req)
{
	struct http_client_request *req = *_req;
	const char *error = req->delayed_error;
	unsigned int status = req->delayed_error_status;
	bool destroy;

	i_assert(req->state == HTTP_REQUEST_STATE_ABORTED);

	*_req = NULL;
	req->delayed_error = NULL;
	req->delayed_error_status = 0;

	i_assert(error != NULL && status != 0);
	destroy = http_client_request_send_error(req, status, error);
	if (req->queue != NULL)
		http_client_queue_drop_request(req->queue, req);
	if (destroy)
		http_client_request_destroy(&req);
}

void http_client_request_error(struct http_client_request **_req,
	unsigned int status, const char *error)
{
	struct http_client_request *req = *_req;

	*_req = NULL;

	i_assert(req->delayed_error_status == 0);
	i_assert(req->state < HTTP_REQUEST_STATE_FINISHED);

	req->state = HTTP_REQUEST_STATE_ABORTED;
	req->last_status = status;

	e_debug(http_client_request_result_event(req)->
		set_name("http_request_finished")->event(),
		"Error: %u %s", status, error);

	if (req->queue != NULL)
		http_client_queue_drop_request(req->queue, req);

	if (req->client != NULL && (!req->submitted ||
		req->state == HTTP_REQUEST_STATE_GOT_RESPONSE)) {
		/* we're still in http_client_request_submit() or in the callback
		   during a retry attempt. delay reporting the error, so the caller
		   doesn't have to handle immediate or nested callbacks. */
		req->delayed_error = p_strdup(req->pool, error);
		req->delayed_error_status = status;
		http_client_delay_request_error(req->client, req);
	} else {
		if (http_client_request_send_error(req, status, error))
			http_client_request_destroy(&req);
	}
}

void http_client_request_abort(struct http_client_request **_req)
{
	struct http_client_request *req = *_req;
	bool sending;

	if (req == NULL)
		return;

	sending = (req->state == HTTP_REQUEST_STATE_PAYLOAD_OUT);

	*_req = NULL;

	if (req->state >= HTTP_REQUEST_STATE_FINISHED &&
		req->delayed_error_status == 0)
		return;

	req->callback = NULL;
	req->state = HTTP_REQUEST_STATE_ABORTED;
	if (req->last_status == 0)
		req->last_status = HTTP_CLIENT_REQUEST_ERROR_ABORTED;

	if (req->state > HTTP_REQUEST_STATE_NEW &&
	    req->delayed_error_status == 0) {
		e_debug(http_client_request_result_event(req)->
			set_name("http_request_finished")->event(),
			"Aborted");
	}

	/* release payload early (prevents server/client deadlock in proxy) */
	if (!sending && req->payload_input != NULL)
		i_stream_unref(&req->payload_input);

	if (req->queue != NULL)
		http_client_queue_drop_request(req->queue, req);
	if (req->payload_wait) {
		i_assert(req->client != NULL);
		i_assert(req->client->ioloop != NULL);
		io_loop_stop(req->client->ioloop);
	}
	http_client_request_destroy(&req);
}

void http_client_request_finish(struct http_client_request *req)
{
	if (req->state >= HTTP_REQUEST_STATE_FINISHED)
		return;

	i_assert(req->refcount > 0);

	e_debug(http_client_request_result_event(req)->
		set_name("http_request_finished")->event(),
		"Finished");

	req->callback = NULL;
	req->state = HTTP_REQUEST_STATE_FINISHED;

	if (req->queue != NULL)
		http_client_queue_drop_request(req->queue, req);
	if (req->payload_wait) {
		i_assert(req->client != NULL);
		i_assert(req->client->ioloop != NULL);
		io_loop_stop(req->client->ioloop);
	}
	http_client_request_unref(&req);
}

void http_client_request_redirect(struct http_client_request *req,
	unsigned int status, const char *location)
{
	struct http_url *url;
	const char *error, *target, *origin_url;

	i_assert(req->client != NULL);
	i_assert(!req->payload_wait);

	req->last_status = status;

	/* parse URL */
	if (http_url_parse(location, NULL, 0,
			   pool_datastack_create(), &url, &error) < 0) {
		http_client_request_error(&req, HTTP_CLIENT_REQUEST_ERROR_INVALID_REDIRECT,
			t_strdup_printf("Invalid redirect location: %s", error));
		return;
	}

	i_assert(req->redirects <= req->client->set.max_redirects);
	if (++req->redirects > req->client->set.max_redirects) {
		if (req->client->set.max_redirects > 0) {
			http_client_request_error(&req,
				HTTP_CLIENT_REQUEST_ERROR_INVALID_REDIRECT,
				t_strdup_printf("Redirected more than %d times",
					req->client->set.max_redirects));
		} else {
			http_client_request_error(&req,
				HTTP_CLIENT_REQUEST_ERROR_INVALID_REDIRECT,
					"Redirect refused");
		}
		return;
	}

	/* rewind payload stream */
	if (req->payload_input != NULL && req->payload_size > 0 && status != 303) {
		if (req->payload_input->v_offset != req->payload_offset &&
			!req->payload_input->seekable) {
			http_client_request_error(&req,
				HTTP_CLIENT_REQUEST_ERROR_ABORTED,
				"Redirect failed: Cannot resend payload; stream is not seekable");
			return;
		} else {
			i_stream_seek(req->payload_input, req->payload_offset);
		}
	}

	/* drop payload output stream from previous attempt */
	o_stream_unref(&req->payload_output);

	target = http_url_create_target(url);

	http_url_copy(req->pool, &req->origin_url, url);
	req->target = p_strdup(req->pool, target);
	
	req->host = NULL;

	origin_url = http_url_create(&req->origin_url);

	e_debug(http_client_request_result_event(req)->
		set_name("http_request_redirected")->event(),
		"Redirecting to %s%s (redirects=%u)",
		origin_url, target, req->redirects);

	req->label = p_strdup_printf(req->pool, "[%s %s%s]",
		req->method, origin_url, req->target);

	/* RFC 7231, Section 6.4.4:
	
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

	e_debug(req->event, "Resubmitting request");

	/* rewind payload stream */
	if (req->payload_input != NULL && req->payload_size > 0) {
		if (req->payload_input->v_offset != req->payload_offset &&
			!req->payload_input->seekable) {
			http_client_request_error(&req,
				HTTP_CLIENT_REQUEST_ERROR_ABORTED,
				"Resubmission failed: Cannot resend payload; stream is not seekable");
			return;
		} else {
			i_stream_seek(req->payload_input, req->payload_offset);
		}
	}

	/* drop payload output stream from previous attempt */
	o_stream_unref(&req->payload_output);

	req->peer = NULL;
	req->state = HTTP_REQUEST_STATE_QUEUED;
	req->redirects = 0;
	req->last_status = 0;
	http_client_host_submit_request(req->host, req);
}

void http_client_request_retry(struct http_client_request *req,
	unsigned int status, const char *error)
{
	if (req->client == NULL || req->client->set.no_auto_retry ||
	    !http_client_request_try_retry(req))
		http_client_request_error(&req, status, error);
}

bool http_client_request_try_retry(struct http_client_request *req)
{
	/* don't ever retry if we're sending data in small blocks via
	   http_client_request_send_payload() and we're not waiting for a
	   100 continue (there's no way to rewind the payload for a retry)
	 */
	if (req->payload_wait &&
		(!req->payload_sync || req->payload_sync_continue))
		return FALSE;
	/* limit the number of attempts for each request */
	if (req->attempts+1 >= req->max_attempts)
		return FALSE;
	req->attempts++;

	e_debug(http_client_request_result_event(req)->
		set_name("http_request_retried")->event(),
		"Retrying (attempts=%d)", req->attempts);

	if (req->callback != NULL)
		http_client_request_resubmit(req);
	return TRUE;
}

#undef http_client_request_set_destroy_callback
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
	struct http_client_connection *conn = req->conn;

	i_assert(req->state == HTTP_REQUEST_STATE_GOT_RESPONSE);

	http_client_connection_start_tunnel(&conn, tunnel);
}
