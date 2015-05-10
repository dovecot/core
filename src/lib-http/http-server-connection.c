/* Copyright (c) 2013-2015 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "llist.h"
#include "array.h"
#include "str.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "connection.h"
#include "iostream-rawlog.h"
#include "iostream-ssl.h"
#include "master-service.h"
#include "master-service-ssl.h"
#include "http-date.h"
#include "http-request-parser.h"

#include "http-server-private.h"

static void
http_server_connection_disconnect(struct http_server_connection *conn,
	const char *reason);

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

	if (conn->server->set.debug) {

		va_start(args, format);	
		i_debug("http-server: conn %s: %s",
			http_server_connection_label(conn), t_strdup_vprintf(format, args));
		va_end(args);
	}
}

static inline void
http_server_connection_error(struct http_server_connection *conn,
	const char *format, ...) ATTR_FORMAT(2, 3);

static inline void
http_server_connection_error(struct http_server_connection *conn,
	const char *format, ...)
{
	va_list args;

	va_start(args, format);	
	i_error("http-server: conn %s: %s",
		http_server_connection_label(conn), t_strdup_vprintf(format, args));
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
	i_info("http-server: conn %s: %s",
		http_server_connection_label(conn), t_strdup_vprintf(format, args));
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
	if (conn->conn.io != NULL)
		io_remove(&conn->conn.io);
}

static void
http_server_connection_input_resume(struct http_server_connection *conn)
{
	if (conn->conn.io == NULL && !conn->closed &&
		!conn->input_broken && !conn->close_indicated) {
		conn->conn.io = io_add(conn->conn.fd_in, IO_READ,
       http_server_connection_input, &conn->conn);
	}
}

static void
http_server_connection_idle_timeout(struct http_server_connection *conn)
{
	http_server_connection_client_error(conn, "Disconnected for inactivity");
	http_server_connection_close(&conn, "Disconnected for inactivity");
}

static void
http_server_connection_timeout_stop(struct http_server_connection *conn)
{
	if (conn->to_idle != NULL)
		timeout_remove(&conn->to_idle);
}

static void
http_server_connection_timeout_start(struct http_server_connection *conn)
{
	if (conn->to_idle == NULL && conn->server->set.max_client_idle_time_msecs > 0) {
		conn->to_idle = timeout_add(conn->server->set.max_client_idle_time_msecs,
				      http_server_connection_idle_timeout, conn);
	}
}

static void
http_server_connection_timeout_reset(struct http_server_connection *conn)
{
	if (conn->to_idle != NULL)
		timeout_reset(conn->to_idle);
}

static void http_server_connection_ready(struct http_server_connection *conn)
{
	struct stat st;

	if (conn->server->set.rawlog_dir != NULL &&
		stat(conn->server->set.rawlog_dir, &st) == 0) {
		iostream_rawlog_create(conn->server->set.rawlog_dir,
				       &conn->conn.input, &conn->conn.output);
	}

	conn->http_parser = http_request_parser_init
		(conn->conn.input, &conn->server->set.request_limits);
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

	/* caller is allowed to change the socket fd to blocking while reading
	   the payload. make sure here that it's switched back. */
	net_set_nonblock(conn->conn.fd_in, TRUE);

	stream_errno = conn->incoming_payload->stream_errno;
	conn->incoming_payload = NULL;

	/* handle errors in transfer stream */
	if (req->response == NULL && stream_errno != 0 &&
		conn->conn.input->stream_errno == 0) {
		switch (stream_errno) {
		case EMSGSIZE:
			conn->input_broken = TRUE;
			http_server_connection_client_error(conn,
				"Client sent excessively large request");
			http_server_request_fail_close(req, 413, "Payload Too Large");
			return;
		case EIO:
			conn->input_broken = TRUE;
			http_server_connection_client_error(conn,
				"Client sent invalid request payload");
			http_server_request_fail_close(req, 400, "Bad Request");
			return;
		default:
			break;
		}
	}

	if (req->state < HTTP_SERVER_REQUEST_STATE_PROCESSING) {
		/* finished reading request */
		req->state = HTTP_SERVER_REQUEST_STATE_PROCESSING;
		if (req->response != NULL && req->response->submitted)
			http_server_request_submit_response(req);
	} else if (req->state == HTTP_SERVER_REQUEST_STATE_SUBMITTED_RESPONSE) {
		http_server_request_ready_to_respond(req);
	}

	/* input stream may have pending input. make sure input handler
	   gets called (but don't do it directly, since we get get here
	   somewhere from the API user's code, which we can't really know what
	   state it is in). this call also triggers sending the next response if
	   necessary. */
	if (!conn->input_broken) {
		conn->to_input =
			timeout_add_short(0, http_server_payload_destroyed_timeout, conn);
	}
}

static void http_server_connection_request_callback(
	struct http_server_connection *conn, struct http_server_request *req)
{
	unsigned int old_refcount = req->refcount;

	/* CONNECT method */
	if (strcmp(req->req.method, "CONNECT") == 0) {
		if (conn->callbacks->handle_connect_request == NULL) {
			http_server_request_fail(req, 505, "Not Implemented");
			return;
		}
		if (req->req.target.format != HTTP_REQUEST_TARGET_FORMAT_AUTHORITY) {
			http_server_request_fail(req, 400, "Bad Request");
			return;
		}
		conn->callbacks->handle_connect_request
			(conn->context, req, req->req.target.url);

	/* other methods */
	} else {
		if (conn->callbacks->handle_request == NULL) {
			http_server_request_fail(req, 505, "Not Implemented");
			return;
		}
		conn->callbacks->handle_request(conn->context, req);
	}

	i_assert((req->response != NULL &&
		  req->response->submitted) ||
		 req->refcount > old_refcount);
}

static bool
http_server_connection_handle_request(struct http_server_connection *conn,
	struct http_server_request *req)
{
	struct istream *payload;

	i_assert(conn->incoming_payload == NULL);

	if (req->req.version_major != 1) {
		http_server_request_fail(req, 505, "HTTP Version Not Supported");
		return TRUE;
	}

	req->state = HTTP_SERVER_REQUEST_STATE_QUEUED;

	if (req->req.payload != NULL) {
		/* wrap the stream to capture the destroy event without destroying the
		   actual payload stream. */
		conn->incoming_payload = req->req.payload =
			i_stream_create_limit(req->req.payload, (uoff_t)-1);
	} else {
		conn->incoming_payload = req->req.payload =
			i_stream_create_from_data("", 0);
	}
	i_stream_add_destroy_callback(req->req.payload,
				      http_server_payload_destroyed, req);
	/* the callback may add its own I/O, so we need to remove
	   our one before calling it */
	http_server_connection_input_halt(conn);

	http_server_connection_request_callback(conn, req);
	if (conn->closed) {
		/* the callback managed to get this connection destroyed/closed */
		return FALSE;
	}

	if (req->req.payload != NULL) {
		/* send 100 Continue when appropriate */
		if (req->req.expect_100_continue && !req->payload_halted
			&& req->response == NULL) {
			http_server_connection_trigger_responses(conn);
		}

		/* delegate payload handling to request handler */
		if (req->state < HTTP_SERVER_REQUEST_STATE_PAYLOAD_IN)
			req->state = HTTP_SERVER_REQUEST_STATE_PAYLOAD_IN;
		payload = req->req.payload;
		req->req.payload = NULL;
		i_stream_unref(&payload);
		if (conn->to_input != NULL) {
			/* already finished reading the payload */
			http_server_payload_finished(conn);
		}
	}

	if (req->state < HTTP_SERVER_REQUEST_STATE_PROCESSING &&
		(conn->incoming_payload == NULL ||
			!i_stream_have_bytes_left(conn->incoming_payload))) {
		/* finished reading request */
		req->state = HTTP_SERVER_REQUEST_STATE_PROCESSING;
		if (req->response != NULL && req->response->submitted)
			http_server_request_submit_response(req);
	}

	if (conn->incoming_payload == NULL) {
		i_assert(conn->conn.io != NULL);
		return TRUE;
	}

	/* Request payload is still being uploaded by the client */
	return FALSE;
}

static int 
http_server_connection_ssl_init(struct http_server_connection *conn)
{
	const char *error;

	if (conn->server->set.debug)
		http_server_connection_debug(conn, "Starting SSL handshake");

	if (master_service_ssl_init(master_service,
				&conn->conn.input, &conn->conn.output,
				&conn->ssl_iostream, &error) < 0) {
		http_server_connection_error(conn,
			"Couldn't initialize SSL server for %s: %s", conn->conn.name, error);
		return -1;
	}
	if (ssl_iostream_handshake(conn->ssl_iostream) < 0) {
		http_server_connection_error(conn,"SSL handshake failed: %s",
			ssl_iostream_get_last_error(conn->ssl_iostream));
		return -1;
	}

	http_server_connection_ready(conn);
	return 0;
}

static void http_server_connection_input(struct connection *_conn)
{
	struct http_server_connection *conn =
		(struct http_server_connection *)_conn;
	struct http_server_request *req, *pending_request;
	enum http_request_parse_error error_code;
	const char *error;
	bool cont;
	int ret;

	i_assert(!conn->input_broken && conn->incoming_payload == NULL);
	i_assert(!conn->close_indicated);

	http_server_connection_timeout_reset(conn);

	if (conn->ssl && conn->ssl_iostream == NULL) {
		if (http_server_connection_ssl_init(conn) < 0) {
			/* ssl failed */
			http_server_connection_close(&conn, "SSL Initialization failed");
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

	/* create request object if none was created already */
	if (conn->request_queue_tail != NULL &&
		conn->request_queue_tail->state == HTTP_SERVER_REQUEST_STATE_NEW) {
		if (conn->request_queue_count >
			conn->server->set.max_pipelined_requests) {
			/* pipeline full */
			http_server_connection_input_halt(conn);
			return;
		}
		/* continue last unfinished request*/
		req = conn->request_queue_tail;
	} else {
		if (conn->request_queue_count >=
			conn->server->set.max_pipelined_requests) {
			/* pipeline full */			
			http_server_connection_input_halt(conn);
			return;
		}
		/* start new request */
		req = http_server_request_new(conn);
	}

	pending_request = (req->prev != NULL &&
		req->prev->state == HTTP_SERVER_REQUEST_STATE_SUBMITTED_RESPONSE ?
		req->prev : NULL);

	/* parse requests */
	ret = 1;
	while (!conn->close_indicated && ret != 0) {
		http_server_connection_ref(conn);
		while ((ret = http_request_parse_next	(conn->http_parser,
			req->pool, &req->req, &error_code, &error)) > 0) {

			if (pending_request != NULL) {
				/* previous request is now fully read and ready to respond */
				http_server_request_ready_to_respond(pending_request);
			}

			http_server_connection_debug(conn,
				"Received new request %s", http_server_request_label(req));

			conn->stats.request_count++;

			http_server_request_ref(req);
			i_assert(!req->delay_destroy);
			req->delay_destroy = TRUE;
			T_BEGIN {
				cont = http_server_connection_handle_request(conn, req);
			} T_END;
			req->delay_destroy = FALSE;
			if (!cont) {
				/* connection closed or request body not read yet.
				   the request may be destroyed now. */
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
				/* connection got closed in destroy callback */
				break;
			}

			if (conn->close_indicated) {
				/* client indicated it will close after this request; stop trying
				   to read more. */
				break;
			}

			if (conn->request_queue_count >=
				conn->server->set.max_pipelined_requests) {
				/* pipeline full */
				http_server_connection_input_halt(conn);
				http_server_connection_unref(&conn);
				return;
			}

			/* start new request */
			req = http_server_request_new(conn);
		}

		http_server_connection_unref(&conn);
		if (conn == NULL || conn->closed) {
			/* connection got closed */
			return;
		}

		if (ret <= 0 &&
	    (conn->conn.input->eof || conn->conn.input->stream_errno != 0)) {
			int stream_errno = conn->conn.input->stream_errno;
		
			/* connection input broken; output may still be intact */
			if (stream_errno != 0 && stream_errno != EPIPE &&
				stream_errno != ECONNRESET) {
				http_server_connection_client_error(conn,
					"Connection lost: read(%s) failed: %s",
						i_stream_get_name(conn->conn.input), strerror(stream_errno));
				http_server_connection_close(&conn, "Read failure");
			} else {
				http_server_connection_debug(conn,
					"Connection lost: Remote disconnected");

				if (conn->request_queue_head == NULL) {
					/* no pending requests; close */
					http_server_connection_close(&conn, "Remote closed connection");
				} else if (conn->request_queue_head->state <
						HTTP_SERVER_REQUEST_STATE_SUBMITTED_RESPONSE) {
					/* unfinished request; close */
					http_server_connection_close(&conn,
						"Remote closed connection unexpectedly");
				} else {
					/* a request is still processing; only drop input io for now.
					   the other end may only have shutdown one direction */
					conn->input_broken = TRUE;
					http_server_connection_input_halt(conn);
				}
			}
			return;
		}

		if (ret < 0) {
			http_server_connection_ref(conn);

			http_server_connection_client_error(conn,
				"Client sent invalid request: %s", error);

			switch (error_code) {
			case HTTP_REQUEST_PARSE_ERROR_BROKEN_REQUEST:
				conn->input_broken = TRUE;
				/* fall through */
			case HTTP_REQUEST_PARSE_ERROR_BAD_REQUEST:
				http_server_request_fail(req, 400, "Bad Request");
				break;
			case HTTP_REQUEST_PARSE_ERROR_METHOD_TOO_LONG:
				conn->input_broken = TRUE;
				/* fall through */
			case HTTP_REQUEST_PARSE_ERROR_NOT_IMPLEMENTED:
				http_server_request_fail(req, 501, "Not Implemented");
				break;
			case HTTP_REQUEST_PARSE_ERROR_TARGET_TOO_LONG:
				conn->input_broken = TRUE;
				http_server_request_fail_close(req, 414, "URI Too Long");
				break;
			case HTTP_REQUEST_PARSE_ERROR_EXPECTATION_FAILED:
				http_server_request_fail(req, 417, "Expectation Failed");
				break;
			case HTTP_REQUEST_PARSE_ERROR_PAYLOAD_TOO_LARGE:
				conn->input_broken = TRUE;
				http_server_request_fail_close(req, 413, "Payload Too Large");
				break;
			default:
				i_unreached();
			}

			http_server_connection_unref(&conn);
			if (conn == NULL || conn->closed) {
				/* connection got closed */
				return;
			}
		}

		if (conn->input_broken || conn->close_indicated) {
			http_server_connection_input_halt(conn);
			return;
		}

		if (ret == 0 && pending_request != NULL &&
			!http_request_parser_pending_payload(conn->http_parser)) {
			/* previous request is now fully read and ready to respond */
			http_server_request_ready_to_respond(pending_request);
		}
	}
}

static bool
http_server_connection_next_response(struct http_server_connection *conn)
{
	struct http_server_request *req;
	const char *error = NULL;

	if (conn->output_locked)
		return FALSE;

	req = conn->request_queue_head;
	if (req == NULL) {
		/* no requests pending */
		http_server_connection_timeout_start(conn);
		return FALSE;
	}
	if (req->state < HTTP_SERVER_REQUEST_STATE_READY_TO_RESPOND) {
		if (req->state == HTTP_SERVER_REQUEST_STATE_PROCESSING) {
			/* server is causing idle time */
			http_server_connection_timeout_stop(conn);
		} else {
			/* client is causing idle time */
			http_server_connection_timeout_start(conn);
		}
		
		/* send 100 Continue if appropriate */
		if (req->state >= HTTP_SERVER_REQUEST_STATE_QUEUED
			&& conn->incoming_payload != NULL
			&& req->response == NULL && req->req.version_minor >= 1
			&& req->req.expect_100_continue	&& !req->payload_halted
			&& !req->sent_100_continue) {
			static const char *response = "HTTP/1.1 100 Continue\r\n\r\n";
			struct ostream *output = conn->conn.output;

			if (o_stream_send(output, response, strlen(response)) < 0) {
				if (errno != EPIPE && errno != ECONNRESET) {
					http_server_connection_error(conn,
						"Failed to send 100 response: write(%s) failed: %m",
						o_stream_get_name(output));
					http_server_connection_close(&conn,	"Write failure");
				} else {
					http_server_connection_debug(conn,
						"Failed to send 100 response: Remote disconnected");
					http_server_connection_close(&conn,
						"Remote closed connection");
				}
			}
			req->sent_100_continue = TRUE;
		}
		return FALSE;
	}

	i_assert(req->state == HTTP_SERVER_REQUEST_STATE_READY_TO_RESPOND &&
		req->response != NULL);

	http_server_connection_timeout_start(conn);

	if (http_server_response_send(req->response, &error) < 0) {
		if (error != NULL) {
			http_server_connection_error(conn,
				"Failed to send response: %s", error);
			http_server_connection_close(&conn, "Write failure");
		} else {
			http_server_connection_debug(conn,
				"Failed to send response: Remote disconnected");
			http_server_connection_close(&conn,
				"Remote closed connection");
		}
		return FALSE;
	}

	http_server_connection_timeout_reset(conn);
	return TRUE;
}

static int http_server_connection_send_responses(
	struct http_server_connection *conn)
{
	http_server_connection_ref(conn);
	
	/* send more responses until no more responses remain, the output
	   blocks again, or the connection is closed */
	while (!conn->closed && http_server_connection_next_response(conn));
	
	http_server_connection_unref(&conn);
	if (conn == NULL || conn->closed)
		return -1;

	/* accept more requests if possible */
	if (conn->incoming_payload == NULL &&
		conn->request_queue_count < conn->server->set.max_pipelined_requests) {
		http_server_connection_input_resume(conn);
		return 1;
	}
	return 0;
}

int http_server_connection_output(struct http_server_connection *conn)
{
	struct ostream *output = conn->conn.output;
	const char *error = NULL;
	int ret;

	if ((ret = o_stream_flush(output)) <= 0) {
		if (ret < 0) {
			if (errno != EPIPE && errno != ECONNRESET) {
				http_server_connection_error(conn,
					"Connection lost: write(%s) failed: %m",
						o_stream_get_name(output));
				http_server_connection_close(&conn, "Write failure");
			} else {
				http_server_connection_debug(conn,
					"Connection lost: Remote disconnected");
				http_server_connection_close(&conn,
					"Remote closed connection unexpectedly");
			}
		}
		return -1;
	}

	http_server_connection_timeout_reset(conn);

	if (!conn->output_locked) {
		if (http_server_connection_send_responses(conn) < 0)
			return -1;
	} else if (conn->request_queue_head != NULL) {
		struct http_server_request *req = conn->request_queue_head;
		struct http_server_response *resp = req->response;

		i_assert(resp != NULL);
		if (http_server_response_send_more(resp, &error) < 0) {
			if (error != NULL ) {
				http_server_connection_error(conn,
					"Connection lost: %s", error);
				http_server_connection_close(&conn, "Write failure");
			} else {
				http_server_connection_debug(conn,
					"Connection lost: Remote disconnected");
				http_server_connection_close(&conn,
					"Remote closed connection unexpectedly");
			}
			return -1;
		}

		if (!conn->output_locked) {
			/* room for more responses */
			if (http_server_connection_send_responses(conn) < 0)
				return -1;
		} else if (conn->io_resp_payload != NULL) {
			/* server is causing idle time */
			http_server_connection_timeout_stop(conn);
		} else {
			/* client is causing idle time */
			http_server_connection_timeout_start(conn);
		}
	}
	return 1;
}

void http_server_connection_trigger_responses(
	struct http_server_connection *conn)
{
	o_stream_set_flush_pending(conn->conn.output, TRUE);
}

bool
http_server_connection_pending_payload(struct http_server_connection *conn)
{
	return conn->incoming_payload != NULL;
}

static struct connection_settings http_server_connection_set = {
	.input_max_size = (size_t)-1,
	.output_max_size = (size_t)-1,
	.client = FALSE
};

static const struct connection_vfuncs http_server_connection_vfuncs = {
	.destroy = http_server_connection_destroy,
	.input = http_server_connection_input
};

struct connection_list *
http_server_connection_list_init(void)
{
	return connection_list_init
		(&http_server_connection_set, &http_server_connection_vfuncs);
}

struct http_server_connection *
http_server_connection_create(struct http_server *server,
	int fd_in, int fd_out, bool ssl,
	const struct http_server_callbacks *callbacks, void *context)
{
	struct http_server_connection *conn;
	static unsigned int id = 0;
	struct ip_addr addr;
	unsigned int port;
	const char *name;

	conn = i_new(struct http_server_connection, 1);
	conn->refcount = 1;
	conn->id = id++;
	conn->server = server;
	conn->ssl = ssl;
	conn->callbacks = callbacks;
	conn->context = context;

	/* get a name for this connection */
	if (fd_in != fd_out || net_getpeername(fd_in, &addr, &port) < 0) {
		name = t_strdup_printf("[%u]", id);
	} else {
		if (addr.family == 0) {
			struct net_unix_cred cred;

			if (net_getunixcred(fd_in, &cred) < 0) {
				name = t_strdup_printf("[%u]", id);
			} else if (cred.pid == (pid_t)-1) {
				name = t_strdup_printf("unix:uid=%u [%u]", cred.uid, id);
			} else {
				name = t_strdup_printf
					("unix:pid=%u,uid=%u [%u]", cred.pid, cred.uid, id);
			}
		} else if (addr.family == AF_INET6) {
			name = t_strdup_printf("[%s]:%u [%u]", net_ip2addr(&addr), port, id);
		} else {
			name = t_strdup_printf("%s:%u [%u]", net_ip2addr(&addr), port, id);
		}
	}

	connection_init_server
		(server->conn_list, &conn->conn, name, fd_in, fd_out);

	if (!ssl)
		http_server_connection_ready(conn);
	http_server_connection_timeout_start(conn);

	http_server_connection_debug(conn, "Connection created");
	return conn;
}

void http_server_connection_ref(struct http_server_connection *conn)
{
	conn->refcount++;
}

static void
http_server_connection_disconnect(struct http_server_connection *conn,
	const char *reason)
{
	if (conn->closed)
		return;

	if (reason == NULL)
		reason = "Connection closed";
	http_server_connection_debug(conn, "Disconnected: %s", reason);
	conn->disconnect_reason = i_strdup(reason);
	conn->closed = TRUE;

	/* preserve statistics */
	http_server_connection_update_stats(conn);

	if (conn->to_input != NULL)
		timeout_remove(&conn->to_input);

	http_server_connection_timeout_stop(conn);
	if (conn->io_resp_payload != NULL)
		io_remove(&conn->io_resp_payload);
	if (conn->conn.output != NULL) {
		o_stream_nflush(conn->conn.output);
		o_stream_uncork(conn->conn.output);
	}

	if (conn->incoming_payload != NULL) {
		/* the stream is still accessed by lib-http caller. */
		i_stream_remove_destroy_callback(conn->incoming_payload,
						 http_server_payload_destroyed);
		conn->incoming_payload = NULL;
	}

	if (conn->http_parser != NULL)
		http_request_parser_deinit(&conn->http_parser);
	connection_disconnect(&conn->conn);
}

void http_server_connection_unref(struct http_server_connection **_conn)
{
	struct http_server_connection *conn = *_conn;
	struct http_server_request *req, *req_next;

	i_assert(conn->refcount > 0);
	if (--conn->refcount > 0)
		return;

	http_server_connection_disconnect(conn, NULL);

	http_server_connection_debug(conn, "Connection destroy");

	req = conn->request_queue_head;
	while (req != NULL) {
		req_next = req->next;
		http_server_request_abort(&req);
		req = req_next;
	}

	if (conn->ssl_iostream != NULL)
		ssl_iostream_unref(&conn->ssl_iostream);
	connection_deinit(&conn->conn);

	if (conn->callbacks != NULL &&
		conn->callbacks->connection_destroy != NULL) T_BEGIN {
		conn->callbacks->connection_destroy
			(conn->context, conn->disconnect_reason);
	} T_END;

	i_free(conn->disconnect_reason);
	i_free(conn);
	*_conn = NULL;
}

void http_server_connection_close(struct http_server_connection **_conn,
	const char *reason)
{
	struct http_server_connection *conn = *_conn;

	http_server_connection_disconnect(conn, reason);
	http_server_connection_unref(_conn);
}

void http_server_connection_tunnel(struct http_server_connection **_conn,
	http_server_tunnel_callback_t callback, void *context)
{
	struct http_server_connection *conn = *_conn;
	struct http_server_tunnel tunnel;

	/* preserve statistics */
	http_server_connection_update_stats(conn);

	memset(&tunnel, 0, sizeof(tunnel));
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
	if (conn->to_input != NULL)
		conn->to_input = io_loop_move_timeout(&conn->to_input);
	if (conn->to_idle != NULL)
		conn->to_idle = io_loop_move_timeout(&conn->to_idle);
	if (conn->io_resp_payload != NULL)
		conn->io_resp_payload = io_loop_move_io(&conn->io_resp_payload);
	connection_switch_ioloop(&conn->conn);
}
