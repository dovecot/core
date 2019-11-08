/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "llist.h"
#include "array.h"
#include "str.h"
#include "hostpid.h"
#include "ioloop.h"
#include "istream.h"
#include "istream-timeout.h"
#include "ostream.h"
#include "connection.h"
#include "iostream-rawlog.h"
#include "iostream-ssl.h"
#include "master-service.h"
#include "master-service-ssl.h"
#include "http-date.h"
#include "http-url.h"
#include "http-request-parser.h"

#include "http-server-private.h"

static void
http_server_connection_disconnect(struct http_server_connection *conn,
				  const char *reason);

static bool
http_server_connection_unref_is_closed(struct http_server_connection *conn);

/*
 * Logging
 */

static inline void
http_server_connection_debug(struct http_server_connection *conn,
			     const char *format, ...) ATTR_FORMAT(2, 3);

static inline void
http_server_connection_debug(struct http_server_connection *conn,
			     const char *format, ...)
{
	va_list args;

	va_start(args, format);
	e_debug(conn->event, "%s", t_strdup_vprintf(format, args));
	va_end(args);
}

static inline void
http_server_connection_client_error(struct http_server_connection *conn,
				    const char *format, ...) ATTR_FORMAT(2, 3);

static inline void
http_server_connection_client_error(struct http_server_connection *conn,
				    const char *format, ...)
{
	va_list args;

	va_start(args, format);
	e_info(conn->event, "%s", t_strdup_vprintf(format, args));
	va_end(args);
}

/*
 * Connection
 */

static void http_server_connection_input(struct connection *_conn);

static void
http_server_connection_update_stats(struct http_server_connection *conn)
{
	if (conn->conn.input != NULL)
		conn->stats.input = conn->conn.input->v_offset;
	if (conn->conn.output != NULL)
		conn->stats.output = conn->conn.output->offset;
}

const struct http_server_stats *
http_server_connection_get_stats(struct http_server_connection *conn)
{
	http_server_connection_update_stats(conn);
	return &conn->stats;
}

static void
http_server_connection_input_halt(struct http_server_connection *conn)
{
	connection_input_halt(&conn->conn);
}

static void
http_server_connection_input_resume(struct http_server_connection *conn)
{
	if (!conn->closed && !conn->input_broken && !conn->close_indicated &&
	    !conn->in_req_callback && conn->incoming_payload == NULL) {
		connection_input_resume(&conn->conn);
	}
}

static void
http_server_connection_idle_timeout(struct http_server_connection *conn)
{
	http_server_connection_client_error(
		conn, "Disconnected for inactivity");
	http_server_connection_close(&conn, "Disconnected for inactivity");
}

static void
http_server_connection_timeout_stop(struct http_server_connection *conn)
{
	timeout_remove(&conn->to_idle);
}

static void
http_server_connection_timeout_start(struct http_server_connection *conn)
{
	if (conn->to_idle == NULL &&
	    conn->server->set.max_client_idle_time_msecs > 0) {
		conn->to_idle = timeout_add(
			conn->server->set.max_client_idle_time_msecs,
			http_server_connection_idle_timeout, conn);
	}
}

static void
http_server_connection_timeout_reset(struct http_server_connection *conn)
{
	if (conn->to_idle != NULL)
		timeout_reset(conn->to_idle);
}

bool http_server_connection_shut_down(struct http_server_connection *conn)
{
	if (conn->request_queue_head == NULL ||
	    conn->request_queue_head->state == HTTP_SERVER_REQUEST_STATE_NEW) {
		http_server_connection_close(&conn, "Server shutting down");
		return TRUE;
	}
	return FALSE;
}

static void http_server_connection_ready(struct http_server_connection *conn)
{
	const struct http_server_settings *set = &conn->server->set;
	struct http_url base_url;
	struct stat st;

	if (conn->server->set.rawlog_dir != NULL &&
	    stat(conn->server->set.rawlog_dir, &st) == 0) {
		iostream_rawlog_create(conn->server->set.rawlog_dir,
				       &conn->conn.input, &conn->conn.output);
	}

	i_zero(&base_url);
	if (set->default_host != NULL)
		base_url.host.name = set->default_host;
	else
		base_url.host.name = my_hostname;
	base_url.have_ssl = conn->ssl;

	conn->http_parser = http_request_parser_init(
		conn->conn.input, &base_url, &conn->server->set.request_limits,
		HTTP_REQUEST_PARSE_FLAG_STRICT);
	o_stream_set_flush_callback(conn->conn.output,
				    http_server_connection_output, conn);
}

static void http_server_connection_destroy(struct connection *_conn)
{
	struct http_server_connection *conn =
		(struct http_server_connection *)_conn;

	http_server_connection_disconnect(conn, NULL);
	http_server_connection_unref(&conn);
}

static void http_server_payload_finished(struct http_server_connection *conn)
{
	timeout_remove(&conn->to_input);
	http_server_connection_input_resume(conn);
}

static void
http_server_payload_destroyed_timeout(struct http_server_connection *conn)
{
	http_server_connection_input(&conn->conn);
}

static void http_server_payload_destroyed(struct http_server_request *req)
{
	struct http_server_connection *conn = req->conn;
	int stream_errno;

	i_assert(conn != NULL);
	i_assert(conn->request_queue_tail == req ||
		 req->state >= HTTP_SERVER_REQUEST_STATE_FINISHED);
	i_assert(conn->conn.io == NULL);

	http_server_connection_debug(conn, "Request payload stream destroyed");

	/* Caller is allowed to change the socket fd to blocking while reading
	   the payload. make sure here that it's switched back. */
	net_set_nonblock(conn->conn.fd_in, TRUE);

	stream_errno = conn->incoming_payload->stream_errno;
	conn->incoming_payload = NULL;

	if (conn->payload_handler != NULL)
		http_server_payload_handler_destroy(&conn->payload_handler);

	/* Handle errors in transfer stream */
	if (req->response == NULL && stream_errno != 0 &&
	    conn->conn.input->stream_errno == 0) {
		switch (stream_errno) {
		case EMSGSIZE:
			conn->input_broken = TRUE;
			http_server_connection_client_error(
				conn, "Client sent excessively large request");
			http_server_request_fail_close(req, 413,
						       "Payload Too Large");
			return;
		case EIO:
			conn->input_broken = TRUE;
			http_server_connection_client_error(
				conn, "Client sent invalid request payload");
			http_server_request_fail_close(req, 400,
						       "Bad Request");
			return;
		default:
			break;
		}
	}

	/* Resource stopped reading payload; update state */
	switch (req->state) {
	case HTTP_SERVER_REQUEST_STATE_QUEUED:
	case HTTP_SERVER_REQUEST_STATE_PAYLOAD_IN:
		/* Finished reading request */
		req->state = HTTP_SERVER_REQUEST_STATE_PROCESSING;
		http_server_connection_timeout_stop(conn);
		if (req->response != NULL && req->response->submitted)
			http_server_request_submit_response(req);
		break;
	case HTTP_SERVER_REQUEST_STATE_PROCESSING:
		/* No response submitted yet */
		break;
	case HTTP_SERVER_REQUEST_STATE_SUBMITTED_RESPONSE:
		/* Response submitted, but not all payload is necessarily read
		 */
		if (http_server_request_is_complete(req))
			http_server_request_ready_to_respond(req);
		break;
	case HTTP_SERVER_REQUEST_STATE_READY_TO_RESPOND:
	case HTTP_SERVER_REQUEST_STATE_FINISHED:
	case HTTP_SERVER_REQUEST_STATE_ABORTED:
		/* Nothing to do */
		break;
	default:
		i_unreached();
	}

	/* Input stream may have pending input. make sure input handler
	   gets called (but don't do it directly, since we get get here
	   somewhere from the API user's code, which we can't really know what
	   state it is in). this call also triggers sending the next response if
	   necessary. */
	if (!conn->input_broken && !conn->in_req_callback) {
		conn->to_input =
			timeout_add_short(0, http_server_payload_destroyed_timeout, conn);
	}
}

static void http_server_connection_request_callback(
	struct http_server_connection *conn, struct http_server_request *req)
{
	/* CONNECT method */
	if (strcmp(req->req.method, "CONNECT") == 0) {
		if (conn->callbacks->handle_connect_request == NULL) {
			http_server_request_fail(req, 505, "Not Implemented");
			return;
		}
		if (req->req.target.format !=
		    HTTP_REQUEST_TARGET_FORMAT_AUTHORITY) {
			http_server_request_fail(req, 400, "Bad Request");
			return;
		}
		conn->callbacks->handle_connect_request(conn->context, req,
							req->req.target.url);
	/* Other methods */
	} else {
		if (conn->callbacks->handle_request == NULL) {
			http_server_request_fail(req, 505, "Not Implemented");
			return;
		}
		conn->callbacks->handle_request(conn->context, req);
	}
}

static bool
http_server_connection_handle_request(struct http_server_connection *conn,
				      struct http_server_request *req)
{
	const struct http_server_settings *set = &conn->server->set;
	unsigned int old_refcount;
	struct istream *payload;
	bool payload_destroyed = FALSE;

	i_assert(!conn->in_req_callback);
	i_assert(conn->incoming_payload == NULL);

	if (req->req.version_major != 1) {
		http_server_request_fail(req, 505,
					 "HTTP Version Not Supported");
		return TRUE;
	}

	req->state = HTTP_SERVER_REQUEST_STATE_QUEUED;

	if (req->req.payload != NULL) {
		/* Wrap the stream to capture the destroy event without
		   destroying the actual payload stream. */
		conn->incoming_payload = req->req.payload =
			i_stream_create_timeout(
				req->req.payload,
				set->max_client_idle_time_msecs);
		/* We've received the request itself, and we can't reset the
		   timeout during the payload reading. */
		http_server_connection_timeout_stop(conn);
	} else {
		conn->incoming_payload = req->req.payload =
			i_stream_create_from_data("", 0);
	}
	i_stream_add_destroy_callback(req->req.payload,
				      http_server_payload_destroyed, req);
	/* The callback may add its own I/O, so we need to remove our one before
	   calling it. */
	http_server_connection_input_halt(conn);

	old_refcount = req->refcount;
	conn->in_req_callback = TRUE;
	http_server_connection_request_callback(conn, req);
	if (conn->closed) {
		/* The callback managed to get this connection destroyed/closed
		 */
		return FALSE;
	}
	conn->in_req_callback = FALSE;
	req->callback_refcount = req->refcount - old_refcount;

	if (req->req.payload != NULL) {
		/* Send 100 Continue when appropriate */
		if (req->req.expect_100_continue && !req->payload_halted &&
		    req->response == NULL) {
			http_server_connection_trigger_responses(conn);
		}

		/* Delegate payload handling to request handler */
		if (req->state < HTTP_SERVER_REQUEST_STATE_PAYLOAD_IN)
			req->state = HTTP_SERVER_REQUEST_STATE_PAYLOAD_IN;
		payload = req->req.payload;
		req->req.payload = NULL;
		i_stream_unref(&payload);
		if (conn->to_input != NULL) {
			/* Already finished reading the payload */
			http_server_payload_finished(conn);
			payload_destroyed = TRUE;
		}
	}

	if (req->state < HTTP_SERVER_REQUEST_STATE_PROCESSING &&
	    (conn->incoming_payload == NULL ||
	     !i_stream_have_bytes_left(conn->incoming_payload))) {
		/* Finished reading request */
		req->state = HTTP_SERVER_REQUEST_STATE_PROCESSING;
		if (req->response != NULL && req->response->submitted)
			http_server_request_submit_response(req);
	}

	i_assert(!payload_destroyed || req->callback_refcount > 0 ||
		 (req->response != NULL && req->response->submitted));

	if (conn->incoming_payload == NULL) {
		if (conn->conn.io == NULL && conn->to_input == NULL)
			http_server_connection_input_resume(conn);
		return TRUE;
	}

	/* Request payload is still being uploaded by the client */
	return FALSE;
}

static int
http_server_connection_ssl_init(struct http_server_connection *conn)
{
	struct http_server *server = conn->server;
	const char *error;
	int ret;

	if (http_server_init_ssl_ctx(server, &error) < 0) {
		e_error(conn->event, "Couldn't initialize SSL: %s", error);
		return -1;
	}

	http_server_connection_debug(conn, "Starting SSL handshake");

	http_server_connection_input_halt(conn);
	if (server->ssl_ctx == NULL) {
		ret = master_service_ssl_init(master_service,
					      &conn->conn.input,
					      &conn->conn.output,
					      &conn->ssl_iostream, &error);
	} else {
		ret = io_stream_create_ssl_server(server->ssl_ctx,
						  server->set.ssl,
						  &conn->conn.input,
						  &conn->conn.output,
						  &conn->ssl_iostream, &error);
	}
	if (ret < 0) {
		e_error(conn->event,
			"Couldn't initialize SSL server for %s: %s",
			conn->conn.name, error);
		return -1;
	}
	http_server_connection_input_resume(conn);

	if (ssl_iostream_handshake(conn->ssl_iostream) < 0) {
		e_error(conn->event, "SSL handshake failed: %s",
			ssl_iostream_get_last_error(conn->ssl_iostream));
		return -1;
	}

	http_server_connection_ready(conn);
	return 0;
}

static bool
http_server_connection_pipeline_is_full(struct http_server_connection *conn)
{
	return ((conn->request_queue_count >=
		 conn->server->set.max_pipelined_requests) ||
		conn->server->shutting_down);
}

static void
http_server_connection_pipeline_handle_full(struct http_server_connection *conn)
{
	if (conn->server->shutting_down) {
		http_server_connection_debug(
			conn, "Pipeline full "
			"(%u requests pending; server shutting down)",
			conn->request_queue_count);
	} else {
		http_server_connection_debug(
			conn, "Pipeline full "
			"(%u requests pending; %u maximum)",
			conn->request_queue_count,
			conn->server->set.max_pipelined_requests);
	}
	http_server_connection_input_halt(conn);
}

static bool
http_server_connection_check_input(struct http_server_connection *conn)
{
	struct istream *input = conn->conn.input;
	int stream_errno;

	if (input == NULL)
		return FALSE;
	stream_errno = input->stream_errno;

	if (input->eof || stream_errno != 0) {
		/* Connection input broken; output may still be intact */
		if (stream_errno != 0 && stream_errno != EPIPE &&
		    stream_errno != ECONNRESET) {
			http_server_connection_client_error(
				conn, "Connection lost: read(%s) failed: %s",
				i_stream_get_name(input),
				i_stream_get_error(input));
			http_server_connection_close(&conn, "Read failure");
		} else {
			http_server_connection_debug(
				conn, "Connection lost: Remote disconnected");

			if (conn->request_queue_head == NULL) {
				/* No pending requests; close */
				http_server_connection_close(
					&conn, "Remote closed connection");
			} else if (conn->request_queue_head->state <
				   HTTP_SERVER_REQUEST_STATE_SUBMITTED_RESPONSE) {
				/* Unfinished request; close */
				http_server_connection_close(&conn,
					"Remote closed connection unexpectedly");
			} else {
				/* A request is still processing; only drop
				   input io for now. The other end may only have
				   shutdown one direction */
				conn->input_broken = TRUE;
				http_server_connection_input_halt(conn);
			}
		}
		return FALSE;
	}
	return TRUE;
}

static bool
http_server_connection_finish_request(struct http_server_connection *conn)
{
	struct http_server_request *req;
	enum http_request_parse_error error_code;
	const char *error;
	int ret;

	req = conn->request_queue_tail;
	if (req != NULL &&
	    req->state == HTTP_SERVER_REQUEST_STATE_SUBMITTED_RESPONSE) {

		http_server_connection_debug(conn, "Finish receiving request");

		ret = http_request_parse_finish_payload(conn->http_parser,
							&error_code, &error);
		if (ret <= 0 && !http_server_connection_check_input(conn))
			return FALSE;
		if (ret < 0) {
			http_server_connection_ref(conn);

			http_server_connection_client_error(
				conn, "Client sent invalid request: %s", error);

			switch (error_code) {
			case HTTP_REQUEST_PARSE_ERROR_PAYLOAD_TOO_LARGE:
				conn->input_broken = TRUE;
				http_server_request_fail_close(
					req, 413, "Payload Too Large");
				break;
			case HTTP_REQUEST_PARSE_ERROR_BROKEN_REQUEST:
				conn->input_broken = TRUE;
				http_server_request_fail_close(
					req, 400, "Bad request");
				break;
			default:
				i_unreached();
			}

			if (http_server_connection_unref_is_closed(conn)) {
				/* Connection got closed */
				return FALSE;
			}

			if (conn->input_broken || conn->close_indicated)
				http_server_connection_input_halt(conn);
			return FALSE;
		}
		if (ret == 0)
			return FALSE;
		http_server_request_ready_to_respond(req);
	}

	return TRUE;
}

static void http_server_connection_input(struct connection *_conn)
{
	struct http_server_connection *conn =
		(struct http_server_connection *)_conn;
	struct http_server_request *req;
	enum http_request_parse_error error_code;
	const char *error;
	bool cont;
	int ret;

	if (conn->server->shutting_down) {
		if (!http_server_connection_shut_down(conn))
			http_server_connection_pipeline_handle_full(conn);
		return;
	}

	i_assert(!conn->in_req_callback);
	i_assert(!conn->input_broken && conn->incoming_payload == NULL);
	i_assert(!conn->close_indicated);

	http_server_connection_timeout_reset(conn);

	if (conn->ssl && conn->ssl_iostream == NULL) {
		if (http_server_connection_ssl_init(conn) < 0) {
			/* SSL failed */
			http_server_connection_close(
				&conn, "SSL Initialization failed");
			return;
		}
	}

	if (conn->to_input != NULL) {
		/* We came here from a timeout added by
		   http_server_payload_destroyed(). The IO couldn't be added
		   back immediately in there, because the HTTP API user may
		   still have had its own IO pointed to the same fd. It should
		   be removed by now, so we can add it back. */
		http_server_payload_finished(conn);
	}

	/* Finish up pending request */
	if (!http_server_connection_finish_request(conn))
		return;

	/* Create request object if none was created already */
	if (conn->request_queue_tail != NULL &&
	    conn->request_queue_tail->state == HTTP_SERVER_REQUEST_STATE_NEW) {
		if (conn->request_queue_count >
		    conn->server->set.max_pipelined_requests) {
			/* Pipeline full */
			http_server_connection_pipeline_handle_full(conn);
			return;
		}
		/* Continue last unfinished request */
		req = conn->request_queue_tail;
	} else {
		if (conn->request_queue_count >=
		    conn->server->set.max_pipelined_requests) {
			/* Pipeline full */
			http_server_connection_pipeline_handle_full(conn);
			return;
		}
		/* Start new request */
		req = http_server_request_new(conn);
	}

	/* Parse requests */
	ret = 1;
	while (!conn->close_indicated && ret != 0) {
		http_server_connection_ref(conn);
		while ((ret = http_request_parse_next(
			conn->http_parser, req->pool, &req->req,
			&error_code, &error)) > 0) {
			conn->stats.request_count++;
			http_server_request_update_event(req);
			http_server_connection_debug(
				conn, "Received new request %s "
				"(%u requests pending; %u maximum)",
				http_server_request_label(req),
				conn->request_queue_count,
				conn->server->set.max_pipelined_requests);

			http_server_request_ref(req);
			i_assert(!req->delay_destroy);
			req->delay_destroy = TRUE;
			T_BEGIN {
				cont = http_server_connection_handle_request(conn, req);
			} T_END;
			req->delay_destroy = FALSE;
			if (!cont) {
				/* Connection closed or request body not read
				   yet. The request may be destroyed now. */
				if (req->destroy_pending)
					http_server_request_destroy(&req);
				else
					http_server_request_unref(&req);
				http_server_connection_unref(&conn);
				return;
			}
			if (req->req.connection_close)
				conn->close_indicated = TRUE;
			if (req->destroy_pending)
				http_server_request_destroy(&req);
			else
				http_server_request_unref(&req);

			if (conn->closed) {
				/* Connection got closed in destroy callback */
				break;
			}

			if (conn->close_indicated) {
				/* Client indicated it will close after this
				   request; stop trying to read more. */
				break;
			}

			/* Finish up pending request if possible */
			if (!http_server_connection_finish_request(conn)) {
				http_server_connection_unref(&conn);
				return;
			}

			if (http_server_connection_pipeline_is_full(conn)) {
				/* Pipeline full */
				http_server_connection_pipeline_handle_full(conn);
				http_server_connection_unref(&conn);
				return;
			}

			/* Start new request */
			req = http_server_request_new(conn);
		}

		if (http_server_connection_unref_is_closed(conn)) {
			/* Connection got closed */
			return;
		}

		if (ret <= 0 && !http_server_connection_check_input(conn))
			return;

		if (ret < 0) {
			http_server_connection_ref(conn);

			http_server_connection_client_error(
				conn, "Client sent invalid request: %s", error);

			switch (error_code) {
			case HTTP_REQUEST_PARSE_ERROR_BROKEN_REQUEST:
				conn->input_broken = TRUE;
				/* fall through */
			case HTTP_REQUEST_PARSE_ERROR_BAD_REQUEST:
				http_server_request_fail(
					req, 400, "Bad Request");
				break;
			case HTTP_REQUEST_PARSE_ERROR_METHOD_TOO_LONG:
				conn->input_broken = TRUE;
				/* fall through */
			case HTTP_REQUEST_PARSE_ERROR_NOT_IMPLEMENTED:
				http_server_request_fail(
					req, 501, "Not Implemented");
				break;
			case HTTP_REQUEST_PARSE_ERROR_TARGET_TOO_LONG:
				conn->input_broken = TRUE;
				http_server_request_fail_close(
					req, 414, "URI Too Long");
				break;
			case HTTP_REQUEST_PARSE_ERROR_EXPECTATION_FAILED:
				http_server_request_fail(
					req, 417, "Expectation Failed");
				break;
			case HTTP_REQUEST_PARSE_ERROR_PAYLOAD_TOO_LARGE:
				conn->input_broken = TRUE;
				http_server_request_fail_close(
					req, 413, "Payload Too Large");
				break;
			default:
				i_unreached();
			}

			if (http_server_connection_unref_is_closed(conn)) {
				/* Connection got closed */
				return;
			}
		}

		if (conn->input_broken || conn->close_indicated) {
			http_server_connection_input_halt(conn);
			return;
		}
	}
}

static void
http_server_connection_discard_input(struct http_server_connection *conn)
{
	struct http_server *server = conn->server;
	enum http_request_parse_error error_code;
	const char *error;
	int ret = 0;

	i_assert(server->ioloop != NULL);

	ret = http_request_parse_finish_payload(conn->http_parser,
						&error_code, &error);

	if (ret <= 0 && !http_server_connection_check_input(conn)) {
		io_loop_stop(server->ioloop);
		return;
	}

	if (ret < 0) {
		http_server_connection_ref(conn);

		http_server_connection_client_error(
			conn, "Client sent invalid request: %s", error);

		switch (error_code) {
		case HTTP_REQUEST_PARSE_ERROR_PAYLOAD_TOO_LARGE:
			conn->input_broken = TRUE;
			http_server_request_fail_close(
				conn->request_queue_head,
				413, "Payload Too Large");
			break;
		default:
			i_unreached();
		}

		http_server_connection_unref(&conn);
		io_loop_stop(server->ioloop);
		return;
	}

	if (ret > 0)
		io_loop_stop(server->ioloop);
}

int http_server_connection_discard_payload(struct http_server_connection *conn)
{
	struct http_server *server = conn->server;
	struct ioloop *prev_ioloop = current_ioloop;

	i_assert(conn->conn.io == NULL);
	i_assert(server->ioloop == NULL);

	if (conn->payload_handler != NULL)
		http_server_payload_handler_destroy(&conn->payload_handler);

	/* Destroy payload wrapper early to advance state */
	if (conn->incoming_payload != NULL) {
		i_stream_unref(&conn->incoming_payload);
		conn->incoming_payload = NULL;
	}

	/* Finish reading payload from the parser */
	if (http_request_parser_pending_payload(conn->http_parser)) {
		http_server_connection_debug(
			conn, "Discarding remaining incoming payload");

		server->ioloop = io_loop_create();
		http_server_connection_switch_ioloop(conn);
		io_loop_set_running(server->ioloop);

		conn->conn.io = io_add_istream(
			conn->conn.input, http_server_connection_discard_input,
			conn);
		http_server_connection_discard_input(conn);
		if (io_loop_is_running(server->ioloop))
			io_loop_run(server->ioloop);
		io_remove(&conn->conn.io);

		io_loop_set_current(prev_ioloop);
		http_server_connection_switch_ioloop(conn);
		io_loop_set_current(server->ioloop);
		io_loop_destroy(&server->ioloop);
	} else {
		http_server_connection_debug(
			conn, "No remaining incoming payload");
	}

	/* Check whether connection is still viable */
	http_server_connection_ref(conn);
	(void)http_server_connection_check_input(conn);
	return http_server_connection_unref_is_closed(conn) ? -1 : 0;
}

void http_server_connection_handle_output_error(
	struct http_server_connection *conn)
{
	struct ostream *output = conn->conn.output;

	if (conn->closed)
		return;

	if (output->stream_errno != EPIPE &&
	    output->stream_errno != ECONNRESET) {
		e_error(conn->event, "Connection lost: write(%s) failed: %s",
			o_stream_get_name(output),
			o_stream_get_error(output));
		http_server_connection_close(
			&conn, "Write failure");
	} else {
		http_server_connection_debug(
			conn, "Connection lost: Remote disconnected");
		http_server_connection_close(
			&conn, "Remote closed connection unexpectedly");
	}
}

static bool
http_server_connection_next_response(struct http_server_connection *conn)
{
	struct http_server_request *req;
	int ret;

	if (conn->output_locked)
		return FALSE;

	req = conn->request_queue_head;
	if (req == NULL || req->state == HTTP_SERVER_REQUEST_STATE_NEW) {
		/* No requests pending */
		http_server_connection_debug(conn, "No more requests pending");
		http_server_connection_timeout_start(conn);
		return FALSE;
	}
	if (req->state < HTTP_SERVER_REQUEST_STATE_READY_TO_RESPOND) {
		if (req->state == HTTP_SERVER_REQUEST_STATE_PROCESSING) {
			/* Server is causing idle time */
			http_server_connection_debug(
				conn, "Not ready to respond: "
				"Server is processing");
			http_server_connection_timeout_stop(conn);
		} else {
			/* Client is causing idle time */
			http_server_connection_debug(
				conn, "Not ready to respond: "
				"Waiting for client");
			http_server_connection_timeout_start(conn);
		}

		/* send 100 Continue if appropriate */
		if (req->state >= HTTP_SERVER_REQUEST_STATE_QUEUED &&
		    conn->incoming_payload != NULL &&
		    req->response == NULL && req->req.version_minor >= 1 &&
		    req->req.expect_100_continue && !req->payload_halted &&
		    !req->sent_100_continue) {
			static const char *response =
				"HTTP/1.1 100 Continue\r\n\r\n";
			struct ostream *output = conn->conn.output;

			if (o_stream_send(output, response,
					  strlen(response)) < 0) {
				http_server_connection_handle_output_error(conn);
				return FALSE;
			}

			http_server_connection_debug(conn, "Sent 100 Continue");
			req->sent_100_continue = TRUE;
		}
		return FALSE;
	}

	i_assert(req->state == HTTP_SERVER_REQUEST_STATE_READY_TO_RESPOND &&
		 req->response != NULL);

	http_server_connection_debug(conn, "Sending response");
	http_server_connection_timeout_start(conn);

	http_server_request_ref(req);
	ret = http_server_response_send(req->response);
	http_server_request_unref(&req);

	if (ret < 0)
		return FALSE;

	http_server_connection_timeout_reset(conn);
	return TRUE;
}

static int
http_server_connection_send_responses(struct http_server_connection *conn)
{
	http_server_connection_ref(conn);

	/* Send more responses until no more responses remain, the output
	   blocks again, or the connection is closed */
	while (!conn->closed && http_server_connection_next_response(conn));

	if (http_server_connection_unref_is_closed(conn))
		return -1;

	/* Accept more requests if possible */
	if (conn->incoming_payload == NULL &&
	    (conn->request_queue_count <
	     conn->server->set.max_pipelined_requests) &&
	    !conn->server->shutting_down) {
		http_server_connection_input_resume(conn);
		return 1;
	}
	return 0;
}

int http_server_connection_flush(struct http_server_connection *conn)
{
	struct ostream *output = conn->conn.output;
	int ret;

	if ((ret = o_stream_flush(output)) <= 0) {
		if (ret < 0)
			http_server_connection_handle_output_error(conn);
		return -1;
	}

	http_server_connection_timeout_reset(conn);
	return 0;
}

int http_server_connection_output(struct http_server_connection *conn)
{
	bool pipeline_was_full =
		http_server_connection_pipeline_is_full(conn);
	int ret;

	if (http_server_connection_flush(conn) < 0)
		return -1;

	if (!conn->output_locked) {
		if (http_server_connection_send_responses(conn) < 0)
			return -1;
	} else if (conn->request_queue_head != NULL) {
		struct http_server_request *req = conn->request_queue_head;
		struct http_server_response *resp = req->response;

		http_server_connection_ref(conn);

		i_assert(resp != NULL);
		ret = http_server_response_send_more(resp);

		if (http_server_connection_unref_is_closed(conn) || ret < 0)
			return -1;

		if (!conn->output_locked) {
			/* Room for more responses */
			if (http_server_connection_send_responses(conn) < 0)
				return -1;
		} else if (conn->io_resp_payload != NULL) {
			/* Server is causing idle time */
			http_server_connection_debug(
				conn, "Not ready to continue response: "
				"Server is producing response");
			http_server_connection_timeout_stop(conn);
		} else {
			/* Client is causing idle time */
			http_server_connection_debug(
				conn, "Not ready to continue response: "
				"Waiting for client");
			http_server_connection_timeout_start(conn);
		}
	}

	if (conn->server->shutting_down &&
	    http_server_connection_shut_down(conn))
		return 1;

	if (!http_server_connection_pipeline_is_full(conn)) {
		http_server_connection_input_resume(conn);
		if (pipeline_was_full && conn->conn.io != NULL)
			i_stream_set_input_pending(conn->conn.input, TRUE);
	}

	return 1;
}

void http_server_connection_trigger_responses(
	struct http_server_connection *conn)
{
	o_stream_set_flush_pending(conn->conn.output, TRUE);
}

bool http_server_connection_pending_payload(
	struct http_server_connection *conn)
{
	return http_request_parser_pending_payload(conn->http_parser);
}

static struct connection_settings http_server_connection_set = {
	.input_max_size = (size_t)-1,
	.output_max_size = (size_t)-1,
	.client = FALSE,
	.log_connection_id = TRUE,
};

static const struct connection_vfuncs http_server_connection_vfuncs = {
	.destroy = http_server_connection_destroy,
	.input = http_server_connection_input
};

struct connection_list *http_server_connection_list_init(void)
{
	return connection_list_init(&http_server_connection_set,
				    &http_server_connection_vfuncs);
}

struct http_server_connection *
http_server_connection_create(struct http_server *server,
			      int fd_in, int fd_out, bool ssl,
			      const struct http_server_callbacks *callbacks,
			      void *context)
{
	const struct http_server_settings *set = &server->set;
	struct http_server_connection *conn;
	struct event *conn_event;

	i_assert(!server->shutting_down);

	conn = i_new(struct http_server_connection, 1);
	conn->refcount = 1;
	conn->server = server;
	conn->ssl = ssl;
	conn->callbacks = callbacks;
	conn->context = context;

	net_set_nonblock(fd_in, TRUE);
	if (fd_in != fd_out)
		net_set_nonblock(fd_out, TRUE);
	(void)net_set_tcp_nodelay(fd_out, TRUE);

	if (set->socket_send_buffer_size > 0 &&
	    net_set_send_buffer_size(fd_out,
				     set->socket_send_buffer_size) < 0) {
		e_error(conn->event,
			"net_set_send_buffer_size(%zu) failed: %m",
			set->socket_send_buffer_size);
	}
	if (set->socket_recv_buffer_size > 0 &&
	    net_set_recv_buffer_size(fd_in,
				     set->socket_recv_buffer_size) < 0) {
		e_error(conn->event,
			"net_set_recv_buffer_size(%zu) failed: %m",
			set->socket_recv_buffer_size);
	}

	conn_event = event_create(server->event);
	conn->conn.event_parent = conn_event;
	connection_init_server(server->conn_list, &conn->conn, NULL,
			       fd_in, fd_out);
	conn->event = conn->conn.event;
	event_unref(&conn_event);

	if (!ssl)
		http_server_connection_ready(conn);
	http_server_connection_timeout_start(conn);

	http_server_connection_debug(conn, "Connection created");
	return conn;
}

void http_server_connection_ref(struct http_server_connection *conn)
{
	i_assert(conn->refcount > 0);
	conn->refcount++;
}

static void
http_server_connection_disconnect(struct http_server_connection *conn,
	const char *reason)
{
	struct http_server_request *req, *req_next;

	if (conn->closed)
		return;

	if (reason == NULL)
		reason = "Connection closed";
	http_server_connection_debug(conn, "Disconnected: %s", reason);
	conn->disconnect_reason = i_strdup(reason);
	conn->closed = TRUE;

	/* Preserve statistics */
	http_server_connection_update_stats(conn);

	if (conn->incoming_payload != NULL) {
		/* The stream is still accessed by lib-http caller. */
		i_stream_remove_destroy_callback(conn->incoming_payload,
						 http_server_payload_destroyed);
		conn->incoming_payload = NULL;
	}
	if (conn->payload_handler != NULL)
		http_server_payload_handler_destroy(&conn->payload_handler);

	/* Drop all requests before connection is closed */
	req = conn->request_queue_head;
	while (req != NULL) {
		req_next = req->next;
		http_server_request_abort(&req, NULL);
		req = req_next;
	}

	timeout_remove(&conn->to_input);

	http_server_connection_timeout_stop(conn);
	io_remove(&conn->io_resp_payload);
	if (conn->conn.output != NULL)
		o_stream_uncork(conn->conn.output);

	if (conn->http_parser != NULL)
		http_request_parser_deinit(&conn->http_parser);
	connection_disconnect(&conn->conn);
}

bool http_server_connection_unref(struct http_server_connection **_conn)
{
	struct http_server_connection *conn = *_conn;

	i_assert(conn->refcount > 0);

	*_conn = NULL;
	if (--conn->refcount > 0)
		return TRUE;

	http_server_connection_disconnect(conn, NULL);

	http_server_connection_debug(conn, "Connection destroy");

	ssl_iostream_destroy(&conn->ssl_iostream);
	connection_deinit(&conn->conn);

	if (conn->callbacks != NULL &&
	    conn->callbacks->connection_destroy != NULL) T_BEGIN {
		conn->callbacks->connection_destroy(conn->context,
						    conn->disconnect_reason);
	} T_END;

	i_free(conn->disconnect_reason);
	i_free(conn);
	return FALSE;
}

static bool
http_server_connection_unref_is_closed(struct http_server_connection *conn)
{
	bool closed = conn->closed;

	if (!http_server_connection_unref(&conn))
		closed = TRUE;
	return closed;
}

void http_server_connection_close(struct http_server_connection **_conn,
				  const char *reason)
{
	struct http_server_connection *conn = *_conn;

	http_server_connection_disconnect(conn, reason);
	http_server_connection_unref(_conn);
}

void http_server_connection_tunnel(struct http_server_connection **_conn,
				   http_server_tunnel_callback_t callback,
				   void *context)
{
	struct http_server_connection *conn = *_conn;
	struct http_server_tunnel tunnel;

	/* Preserve statistics */
	http_server_connection_update_stats(conn);

	i_zero(&tunnel);
	tunnel.input = conn->conn.input;
	tunnel.output = conn->conn.output;
	tunnel.fd_in = conn->conn.fd_in;
	tunnel.fd_out = conn->conn.fd_out;

	conn->conn.input = NULL;
	conn->conn.output = NULL;
	conn->conn.fd_in = conn->conn.fd_out = -1;
	http_server_connection_close(_conn, "Tunnel initiated");

	callback(context, &tunnel);
}

void http_server_connection_switch_ioloop(struct http_server_connection *conn)
{
	if (conn->switching_ioloop)
		return;

	conn->switching_ioloop = TRUE;
	if (conn->to_input != NULL)
		conn->to_input = io_loop_move_timeout(&conn->to_input);
	if (conn->to_idle != NULL)
		conn->to_idle = io_loop_move_timeout(&conn->to_idle);
	if (conn->io_resp_payload != NULL)
		conn->io_resp_payload = io_loop_move_io(&conn->io_resp_payload);
	if (conn->payload_handler != NULL)
		http_server_payload_handler_switch_ioloop(conn->payload_handler);
	if (conn->incoming_payload != NULL)
		i_stream_switch_ioloop(conn->incoming_payload);
	connection_switch_ioloop(&conn->conn);
	conn->switching_ioloop = FALSE;
}
