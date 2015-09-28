/* Copyright (c) 2013-2015 Dovecot authors, see the included COPYING file */

#include "lib.h"

#include "http-server-private.h"

struct http_server_request *
http_server_request_new(struct http_server_connection *conn)
{
	pool_t pool;
	struct http_server_request *req;

	pool = pool_alloconly_create(MEMPOOL_GROWING"http_server_request", 4096);
	req = p_new(pool, struct http_server_request, 1);
	req->pool = pool;
	req->refcount = 1;
	req->conn = conn;
	req->server = conn->server;

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
	if (--req->refcount > 0)
		return TRUE;

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
	*_req = NULL;
	return FALSE;
}

void http_server_request_destroy(struct http_server_request **_req)
{
	struct http_server_request *req = *_req;

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

void http_server_request_abort(struct http_server_request **_req)
{
	struct http_server_request *req = *_req;
	struct http_server_connection *conn = req->conn;

	if (req->state < HTTP_SERVER_REQUEST_STATE_FINISHED) {
		req->state = HTTP_SERVER_REQUEST_STATE_ABORTED;
		http_server_connection_remove_request(conn, req);
	}
	
	if (req->response != NULL)
		http_server_response_free(req->response);
	req->response = NULL;
	req->conn = conn;

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

