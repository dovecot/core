/* Copyright (c) 2013-2014 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "llist.h"

#include "http-server-private.h"

struct http_server_request *
http_server_request_new(struct http_server_connection *conn)
{
	pool_t pool;
	struct http_server_request *req;

	pool = pool_alloconly_create("http_message", 4096);
	req = p_new(pool, struct http_server_request, 1);
	req->pool = pool;
	req->refcount = 1;
	req->conn = conn;
	req->server = conn->server;

	DLLIST2_APPEND(&conn->request_queue_head, &conn->request_queue_tail, req);
	conn->request_queue_count++;
	return req;
}

void http_server_request_ref(struct http_server_request *req)
{
	req->refcount++;
}

void http_server_request_unref(struct http_server_request **_req)
{
	struct http_server_request *req = *_req;
	struct http_server_connection *conn = req->conn;

	i_assert(req->refcount > 0);
	if (--req->refcount > 0)
		return;

	if (req->state < 	HTTP_SERVER_REQUEST_STATE_FINISHED) {
		req->state = HTTP_SERVER_REQUEST_STATE_ABORTED;
		DLLIST2_REMOVE(&conn->request_queue_head, &conn->request_queue_tail, req);
		conn->request_queue_count--;
	}

	if (req->destroy_callback != NULL) {
		req->destroy_callback(req->destroy_context);
		req->destroy_callback = NULL;
	}

	if (req->response != NULL)
		http_server_response_free(req->response);
	pool_unref(&req->pool);
	*_req = NULL;
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

	if (req->state < 	HTTP_SERVER_REQUEST_STATE_FINISHED) {
		req->state = HTTP_SERVER_REQUEST_STATE_ABORTED;
		DLLIST2_REMOVE(&conn->request_queue_head, &conn->request_queue_tail, req);
		conn->request_queue_count--;
	}
	
	if (req->response != NULL)
		http_server_response_free(req->response);
	req->response = NULL;
	req->conn = conn;

	http_server_request_unref(_req);
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
		http_server_connection_send_responses(req->conn);
}

void http_server_request_ready_to_respond(struct http_server_request *req)
{
	req->state = HTTP_SERVER_REQUEST_STATE_READY_TO_RESPOND;
	http_server_connection_send_responses(req->conn);
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

	DLLIST2_REMOVE(&conn->request_queue_head, &conn->request_queue_tail, req);
	conn->request_queue_count--;
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
		http_server_request_unref(&req);
		return;
	}

	http_server_request_unref(&req);
	if (tunnel_callback != NULL) {
		http_server_connection_tunnel(&conn, tunnel_callback, tunnel_context);
		return;
	}
	
	http_server_connection_send_responses(conn);
}

static void
http_server_request_fail_full(struct http_server_request *req,
	unsigned int status, const char *reason, bool close)
{
	struct http_server_response *resp;

	resp = http_server_response_create(req, status, reason);
	http_server_response_add_header
		(resp, "Content-Type", "text/plain; charset=utf-8");
	reason = t_strconcat(reason, "\r\n", NULL);
	http_server_response_set_payload_data
		(resp, (const unsigned char *)reason, strlen(reason));
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
