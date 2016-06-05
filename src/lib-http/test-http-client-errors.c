/* Copyright (c) 2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "hostpid.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "connection.h"
#include "test-common.h"
#include "http-url.h"
#include "http-request.h"
#include "http-client.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>

/*
 * Types
 */

struct server_connection {
	struct connection conn;

	pool_t pool;
};

typedef void (*test_server_init_t)(unsigned int index);
typedef void (*test_client_init_t)
	(const struct http_client_settings *client_set);

/*
 * State
 */

/* common */
static struct ip_addr bind_ip;
static in_port_t *bind_ports = 0;
static struct ioloop *ioloop;
static bool debug = FALSE;

/* server */
static struct io *io_listen;
static int fd_listen = -1;
static pid_t *server_pids = NULL;
static unsigned int server_pids_count = 0;
static struct connection_list *server_conn_list;
static size_t server_read_max = 0;
static unsigned int server_index;
static void (*test_server_input)(struct server_connection *conn);

/* client */
static struct http_client *http_client = NULL;

/*
 * Forward declarations
 */

/* server */
static void test_server_run(unsigned int index);
static void
server_connection_deinit(struct server_connection **_conn);

/* client */
static void
test_client_defaults(struct http_client_settings *http_set);
static void test_client_deinit(void);

/* test*/
static void test_run_client_server(
	const struct http_client_settings *client_set,
	test_client_init_t client_test,
	test_server_init_t server_test,
	unsigned int server_tests_count)
	ATTR_NULL(3);

/*
 * Host lookup failed
 */

/* client */

struct _host_lookup_failed {
	unsigned int count;
};

static void
test_client_host_lookup_failed_response(
	const struct http_response *resp,
	struct _host_lookup_failed *ctx)
{
	if (debug)
		i_debug("RESPONSE: %u %s", resp->status, resp->reason);

	test_assert(resp->status == HTTP_CLIENT_REQUEST_ERROR_HOST_LOOKUP_FAILED);
	test_assert(resp->reason != NULL && *resp->reason != '\0');

	if (--ctx->count == 0) {
		i_free(ctx);
		io_loop_stop(ioloop);
	}
}

static void
test_client_host_lookup_failed(const struct http_client_settings *client_set)
{
	struct http_client_request *hreq;
	struct _host_lookup_failed *ctx;

	ctx = i_new(struct _host_lookup_failed, 1);
	ctx->count = 2;

	http_client = http_client_init(client_set);

	hreq = http_client_request(http_client,
		"GET", "host.in-addr.arpa", "/host-lookup-failed.txt",
		test_client_host_lookup_failed_response, ctx);
	http_client_request_submit(hreq);

	hreq = http_client_request(http_client,
		"GET", "host.in-addr.arpa", "/host-lookup-failed2.txt",
		test_client_host_lookup_failed_response, ctx);
	http_client_request_submit(hreq);
}

/* test */

static void test_host_lookup_failed(void)
{
	struct http_client_settings http_client_set;

	test_client_defaults(&http_client_set);

	test_begin("host lookup failed");
	test_run_client_server(&http_client_set,
		test_client_host_lookup_failed,
		NULL, 0);
	test_end();
}

/*
 * Connection refused
 */

/* server */

static void
test_server_connection_refused(unsigned int index ATTR_UNUSED)
{
	i_close_fd(&fd_listen);
}

/* client */

struct _connection_refused {
	unsigned int count;
};

static void
test_client_connection_refused_response(
	const struct http_response *resp,
	struct _connection_refused *ctx)
{
	if (debug)
		i_debug("RESPONSE: %u %s", resp->status, resp->reason);

	test_assert(resp->status == HTTP_CLIENT_REQUEST_ERROR_CONNECT_FAILED);
	test_assert(resp->reason != NULL && *resp->reason != '\0');

	if (--ctx->count == 0) {
		i_free(ctx);
		io_loop_stop(ioloop);
	}
}

static void
test_client_connection_refused(const struct http_client_settings *client_set)
{
	struct http_client_request *hreq;
	struct _connection_refused *ctx;

	ctx = i_new(struct _connection_refused, 1);
	ctx->count = 2;

	http_client = http_client_init(client_set);

	hreq = http_client_request(http_client,
		"GET", net_ip2addr(&bind_ip), "/connection-refused.txt",
		test_client_connection_refused_response, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_submit(hreq);

	hreq = http_client_request(http_client,
		"GET", net_ip2addr(&bind_ip), "/connection-refused2.txt",
		test_client_connection_refused_response, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_submit(hreq);
}

/* test */

static void test_connection_refused(void)
{
	struct http_client_settings http_client_set;

	test_client_defaults(&http_client_set);

	test_begin("connection refused");
	test_run_client_server(&http_client_set,
		test_client_connection_refused,
		test_server_connection_refused, 1);
	test_end();
}

/*
 * Connection timed out
 */

/* client */

struct _connection_timed_out {
	unsigned int count;
};

static void
test_client_connection_timed_out_response(
	const struct http_response *resp,
	struct _connection_timed_out *ctx)
{
	if (debug)
		i_debug("RESPONSE: %u %s", resp->status, resp->reason);

	test_assert(resp->status == HTTP_CLIENT_REQUEST_ERROR_CONNECT_FAILED);
	test_assert(resp->reason != NULL && *resp->reason != '\0');

	if (--ctx->count == 0) {
		i_free(ctx);
		io_loop_stop(ioloop);
	}
}

static void
test_client_connection_timed_out(
	const struct http_client_settings *client_set)
{
	struct http_client_request *hreq;
	struct _connection_timed_out *ctx;

	ctx = i_new(struct _connection_timed_out, 1);
	ctx->count = 2;

	http_client = http_client_init(client_set);

	hreq = http_client_request(http_client,
		"GET", "192.168.0.0", "/connection-timed-out.txt",
		test_client_connection_timed_out_response, ctx);
	http_client_request_submit(hreq);

	hreq = http_client_request(http_client,
		"GET", "192.168.0.0", "/connection-timed-out2.txt",
		test_client_connection_timed_out_response, ctx);
	http_client_request_submit(hreq);
}

/* test */

static void test_connection_timed_out(void)
{
	struct http_client_settings http_client_set;

	test_client_defaults(&http_client_set);
	http_client_set.connect_timeout_msecs = 1000;
	http_client_set.max_attempts = 1;

	test_begin("connection timed out");
	test_run_client_server(&http_client_set,
		test_client_connection_timed_out,
		NULL, 0);
	test_end();
}

/*
 * Invalid redirect
 */

/* server */

/* -> not accepted */

static void
test_invalid_redirect_input1(struct server_connection *conn)
{
	static const char *resp =
		"HTTP/1.1 302 Redirect\r\n"
		"Location: http://localhost:4444\r\n"
		"\r\n";
	o_stream_nsend_str(conn->conn.output, resp);
	server_connection_deinit(&conn);
}

static void test_server_invalid_redirect1(unsigned int index)
{
	test_server_input = test_invalid_redirect_input1;
	test_server_run(index);
}

/* -> bad location */

static void
test_invalid_redirect_input2(struct server_connection *conn)
{
	static const char *resp =
		"HTTP/1.1 302 Redirect\r\n"
		"Location: unix:/var/run/dovecot/auth-master\r\n"
		"\r\n";
	o_stream_nsend_str(conn->conn.output, resp);
	server_connection_deinit(&conn);
}

static void test_server_invalid_redirect2(unsigned int index)
{
	test_server_input = test_invalid_redirect_input2;
	test_server_run(index);
}

/* -> too many */

static void
test_invalid_redirect_input3(struct server_connection *conn)
{
	string_t *resp;

	resp = t_str_new(512);
	str_printfa(resp, 
		"HTTP/1.1 302 Redirect\r\n"
		"Location: http://%s:%u/friep.txt\r\n"
		"\r\n",
		net_ip2addr(&bind_ip), bind_ports[server_index+1]);
	o_stream_nsend(conn->conn.output,
		str_data(resp), str_len(resp));
	server_connection_deinit(&conn);
}

static void test_server_invalid_redirect3(unsigned int index)
{
	test_server_input = test_invalid_redirect_input3;
	test_server_run(index);
}

/* client */

static void
test_client_invalid_redirect_response(
	const struct http_response *resp,
	void *context ATTR_UNUSED)
{
	if (debug)
		i_debug("RESPONSE: %u %s", resp->status, resp->reason);

	test_assert(resp->status == HTTP_CLIENT_REQUEST_ERROR_INVALID_REDIRECT);
	test_assert(resp->reason != NULL && *resp->reason != '\0');
	io_loop_stop(ioloop);
}

static void
test_client_invalid_redirect(const struct http_client_settings *client_set)
{
	struct http_client_request *hreq;

	http_client = http_client_init(client_set);

	hreq = http_client_request(http_client,
		"GET", net_ip2addr(&bind_ip), "/invalid-redirect.txt",
		test_client_invalid_redirect_response, NULL);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_submit(hreq);
}

/* test */

static void test_invalid_redirect(void)
{
	struct http_client_settings http_client_set;

	test_client_defaults(&http_client_set);

	test_begin("invalid redirect: not accepted");
	http_client_set.max_redirects = 0;
	test_run_client_server(&http_client_set,
		test_client_invalid_redirect,
		test_server_invalid_redirect1, 1);
	test_end();

	test_begin("invalid redirect: bad location");
	http_client_set.max_redirects = 1;
	test_run_client_server(&http_client_set,
		test_client_invalid_redirect,
		test_server_invalid_redirect2, 1);
	test_end();

	test_begin("invalid redirect: too many");
	http_client_set.max_redirects = 1;
	test_run_client_server(&http_client_set,
		test_client_invalid_redirect,
		test_server_invalid_redirect3, 3);
	test_end();
}

/* 
 * Unseekable redirect
 */

/* server */

static void
test_unseekable_redirect_input(struct server_connection *conn)
{
	string_t *resp;

	resp = t_str_new(512);
	str_printfa(resp, 
		"HTTP/1.1 302 Redirect\r\n"
		"Location: http://%s:%u/frml.txt\r\n"
		"\r\n",
		net_ip2addr(&bind_ip), bind_ports[server_index+1]);
	o_stream_nsend(conn->conn.output,
		str_data(resp), str_len(resp));
	server_connection_deinit(&conn);
}

static void test_server_unseekable_redirect(unsigned int index)
{
	test_server_input = test_unseekable_redirect_input;
	test_server_run(index);
}

/* client */

static void
test_client_unseekable_redirect_response(
	const struct http_response *resp,
	void *context ATTR_UNUSED)
{
	if (debug)
		i_debug("RESPONSE: %u %s", resp->status, resp->reason);

	test_assert(resp->status == HTTP_CLIENT_REQUEST_ERROR_ABORTED);
	test_assert(resp->reason != NULL && *resp->reason != '\0');
	io_loop_stop(ioloop);
}

static void
test_client_unseekable_redirect(const struct http_client_settings *client_set)
{
	struct http_client_request *hreq;
	struct istream *input;

	http_client = http_client_init(client_set);

	input = i_stream_create_from_data("FROP", 4);
	input->seekable = FALSE;

	hreq = http_client_request(http_client,
		"GET", net_ip2addr(&bind_ip), "/unseekable-redirect.txt",
		test_client_unseekable_redirect_response, NULL);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_set_payload(hreq, input, FALSE);
	http_client_request_submit(hreq);

	i_stream_unref(&input);	
}

/* test */

static void test_unseekable_redirect(void)
{
	struct http_client_settings http_client_set;

	test_client_defaults(&http_client_set);
	http_client_set.max_redirects = 1;

	test_begin("unseekable redirect");
	test_run_client_server(&http_client_set,
		test_client_unseekable_redirect,
		test_server_unseekable_redirect, 2);
	test_end();
}

/*
 * Unseekable retry
 */

/* server */

static void
test_unseekable_retry_input(struct server_connection *conn)
{
	server_connection_deinit(&conn);
}

static void test_server_unseekable_retry(unsigned int index)
{
	test_server_input = test_unseekable_retry_input;
	test_server_run(index);
}

/* client */

static void
test_client_unseekable_retry_response(
	const struct http_response *resp,
	void *context ATTR_UNUSED)
{
	if (debug)
		i_debug("RESPONSE: %u %s", resp->status, resp->reason);

	test_assert(resp->status == HTTP_CLIENT_REQUEST_ERROR_ABORTED);
	test_assert(resp->reason != NULL && *resp->reason != '\0');
	io_loop_stop(ioloop);
}

static void
test_client_unseekable_retry(const struct http_client_settings *client_set)
{
	struct http_client_request *hreq;
	struct istream *input;

	http_client = http_client_init(client_set);

	input = i_stream_create_from_data("FROP", 4);
	input->seekable = FALSE;

	hreq = http_client_request(http_client,
		"GET", net_ip2addr(&bind_ip), "/unseekable-retry.txt",
		test_client_unseekable_retry_response, NULL);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_set_payload(hreq, input, FALSE);
	http_client_request_submit(hreq);

	i_stream_unref(&input);	
}

/* test */

static void test_unseekable_retry(void)
{
	struct http_client_settings http_client_set;

	test_client_defaults(&http_client_set);
	http_client_set.max_attempts = 3;

	test_begin("unseekable retry");
	test_run_client_server(&http_client_set,
		test_client_unseekable_retry,
		test_server_unseekable_retry, 2);
	test_end();
}

/*
 * Broken payload
 */

/* server */

static void
test_broken_payload_input(struct server_connection *conn)
{
	static const char *resp =
		"HTTP/1.1 200 OK\r\n"
		"Content-Length: 18\r\n"
		"\r\n"
		"Everything is OK\r\n";
	o_stream_nsend_str(conn->conn.output, resp);
	server_connection_deinit(&conn);
}

static void test_server_broken_payload(unsigned int index)
{
	test_server_input = test_broken_payload_input;
	test_server_run(index);
}

/* client */

static void
test_client_broken_payload_response(
	const struct http_response *resp,
	void *context ATTR_UNUSED)
{
	if (debug)
		i_debug("RESPONSE: %u %s", resp->status, resp->reason);

	test_assert(resp->status == HTTP_CLIENT_REQUEST_ERROR_BROKEN_PAYLOAD);
	test_assert(resp->reason != NULL && *resp->reason != '\0');
	io_loop_stop(ioloop);
}

static void
test_client_broken_payload(const struct http_client_settings *client_set)
{
	struct http_client_request *hreq;
	struct istream *input;

	test_expect_errors(1);

	http_client = http_client_init(client_set);

	input = i_stream_create_error_str(EIO, "Moehahahaha!!");
	i_stream_set_name(input, "PURE EVIL");

	hreq = http_client_request(http_client,
		"GET", net_ip2addr(&bind_ip), "/broken-payload.txt",
		test_client_broken_payload_response, NULL);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_set_payload(hreq, input, FALSE);
	http_client_request_submit(hreq);

	i_stream_unref(&input);	
}

/* test */

static void test_broken_payload(void)
{
	struct http_client_settings http_client_set;

	test_client_defaults(&http_client_set);

	test_begin("broken payload");
	test_run_client_server(&http_client_set,
		test_client_broken_payload,
		test_server_broken_payload, 1);
	test_end();
}

/*
 * Connection lost
 */

/* server */

static void
test_connection_lost_input(struct server_connection *conn)
{
	ssize_t ret;

	if (server_read_max == 0) {
		server_connection_deinit(&conn);
		return;
	}

	i_stream_set_max_buffer_size(conn->conn.input, server_read_max);
	ret = i_stream_read(conn->conn.input);
	if (ret == -2) {
		server_connection_deinit(&conn);
		return;
	}
	if (ret < 0) {
		if (i_stream_is_eof(conn->conn.input))
			i_fatal("server: Client stream ended prematurely");
		else
			i_fatal("server: Streem error: %s",
				i_stream_get_error(conn->conn.input));
	}
}

static void test_server_connection_lost(unsigned int index)
{
	test_server_input = test_connection_lost_input;
	test_server_run(index);
}

/* client */

struct _connection_lost_ctx {
	unsigned int count;
};

static void
test_client_connection_lost_response(
	const struct http_response *resp,
	struct _connection_lost_ctx *ctx)
{
	if (debug)
		i_debug("RESPONSE: %u %s", resp->status, resp->reason);

	test_assert(resp->status == HTTP_CLIENT_REQUEST_ERROR_CONNECTION_LOST);
	test_assert(resp->reason != NULL && *resp->reason != '\0');

	if (--ctx->count == 0) {
		i_free(ctx);
		io_loop_stop(ioloop);
	}
}

static void
test_client_connection_lost(const struct http_client_settings *client_set)
{
	static const char payload[] =
		"This is a useless payload that only serves as a means to give the "
		"server the opportunity to close the connection before the payload "
		"is finished.";
	struct _connection_lost_ctx *ctx;
	struct http_client_request *hreq;
	struct istream *input;

	ctx = i_new(struct _connection_lost_ctx, 1);
	ctx->count = 2;

	http_client = http_client_init(client_set);

	input = i_stream_create_from_data(payload, sizeof(payload)-1);

	hreq = http_client_request(http_client,
		"GET", net_ip2addr(&bind_ip), "/connection-lost.txt",
		test_client_connection_lost_response, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_set_payload(hreq, input, FALSE);
	http_client_request_submit(hreq);

	hreq = http_client_request(http_client,
		"GET", net_ip2addr(&bind_ip), "/connection-lost2.txt",
		test_client_connection_lost_response, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_submit(hreq);

	i_stream_unref(&input);	
}

/* test */

static void test_connection_lost(void)
{
	struct http_client_settings http_client_set;

	test_client_defaults(&http_client_set);

	server_read_max = 0;

	test_begin("connection lost: one attempt");
	http_client_set.max_attempts = 1;
	test_run_client_server(&http_client_set,
		test_client_connection_lost,
		test_server_connection_lost, 1);
	test_end();

	test_begin("connection lost: two attempts");
	http_client_set.max_attempts = 2;
	test_run_client_server(&http_client_set,
		test_client_connection_lost,
		test_server_connection_lost, 1);
	test_end();

	test_begin("connection lost: three attempts");
	http_client_set.max_attempts = 3;
	test_run_client_server(&http_client_set,
		test_client_connection_lost,
		test_server_connection_lost, 1);
	test_end();
}

/*
 * Connection lost after 100-continue
 */

/* server */

static void
test_connection_lost_100_input(struct server_connection *conn)
{
	static const char *resp =
		"HTTP/1.1 100 Continue\r\n"
		"\r\n";
	o_stream_nsend_str(conn->conn.output, resp);
	server_connection_deinit(&conn);
}

static void test_server_connection_lost_100(unsigned int index)
{
	test_server_input = test_connection_lost_100_input;
	test_server_run(index);
}

/* client */

struct _connection_lost_100_ctx {
	unsigned int count;
};

static void
test_client_connection_lost_100_response(
	const struct http_response *resp,
	struct _connection_lost_100_ctx *ctx)
{
	if (debug)
		i_debug("RESPONSE: %u %s", resp->status, resp->reason);

	test_assert(resp->status == HTTP_CLIENT_REQUEST_ERROR_CONNECTION_LOST);
	test_assert(resp->reason != NULL && *resp->reason != '\0');

	if (--ctx->count == 0) {
		i_free(ctx);
		io_loop_stop(ioloop);
	}
}

static void
test_client_connection_lost_100(
	const struct http_client_settings *client_set)
{
	static const char payload[] =
		"This is a useless payload that only serves as a means to give the "
		"server the opportunity to close the connection before the payload "
		"is finished.";
	struct _connection_lost_100_ctx *ctx;
	struct http_client_request *hreq;
	struct istream *input;

	ctx = i_new(struct _connection_lost_100_ctx, 1);
	ctx->count = 2;

	http_client = http_client_init(client_set);

	input = i_stream_create_from_data(payload, sizeof(payload)-1);

	hreq = http_client_request(http_client,
		"GET", net_ip2addr(&bind_ip), "/connection-lost.txt",
		test_client_connection_lost_100_response, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_set_payload(hreq, input, TRUE);
	http_client_request_submit(hreq);

	hreq = http_client_request(http_client,
		"GET", net_ip2addr(&bind_ip), "/connection-lost2.txt",
		test_client_connection_lost_100_response, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_set_payload(hreq, input, TRUE);
	http_client_request_submit(hreq);

	i_stream_unref(&input);	
}

/* test */

static void test_connection_lost_100(void)
{
	struct http_client_settings http_client_set;

	test_client_defaults(&http_client_set);

	server_read_max = 0;

	test_begin("connection lost after 100-continue");
	http_client_set.max_attempts = 1;
	test_run_client_server(&http_client_set,
		test_client_connection_lost_100,
		test_server_connection_lost_100, 1);
	test_end();
}

/*
 * Connection lost in sub-ioloop
 */

/* server */

static void
test_connection_lost_sub_ioloop_input(struct server_connection *conn)
{
	static const char *resp =
		"HTTP/1.1 200 OK\r\n"
		"Content-Length: 0\r\n"
		"\r\n";
	o_stream_nsend_str(conn->conn.output, resp);
	server_connection_deinit(&conn);
}

static void test_server_connection_lost_sub_ioloop(unsigned int index)
{
	test_server_input = test_connection_lost_sub_ioloop_input;
	test_server_run(index);
}

/* client */

struct _connection_lost_sub_ioloop_ctx {
	unsigned int count;
};

static void
test_client_connection_lost_sub_ioloop_response2(
	const struct http_response *resp,
	struct ioloop *sub_ioloop)
{
	if (debug)
		i_debug("SUB-RESPONSE: %u %s", resp->status, resp->reason);
	io_loop_stop(sub_ioloop);
}

static void
test_client_connection_lost_sub_ioloop_response(
	const struct http_response *resp,
	struct _connection_lost_sub_ioloop_ctx *ctx)
{
	struct http_client_request *hreq;
	struct ioloop *sub_ioloop;

	if (debug)
		i_debug("RESPONSE: %u %s", resp->status, resp->reason);

	test_assert(resp->status == 200);
	test_assert(resp->reason != NULL && *resp->reason != '\0');

	sub_ioloop = io_loop_create();
	http_client_switch_ioloop(http_client);

	hreq = http_client_request(http_client,
		"GET", net_ip2addr(&bind_ip), "/connection-lost-sub-ioloop3.txt",
		test_client_connection_lost_sub_ioloop_response2, sub_ioloop);
	http_client_request_set_port(hreq, bind_ports[1]);
	http_client_request_submit(hreq);

	io_loop_run(sub_ioloop);
	io_loop_set_current(ioloop);
	http_client_switch_ioloop(http_client);
	io_loop_set_current(sub_ioloop);
	io_loop_destroy(&sub_ioloop);

	if (--ctx->count == 0) {
		i_free(ctx);
		io_loop_stop(ioloop);
	}
}

static void
test_client_connection_lost_sub_ioloop(
	const struct http_client_settings *client_set)
{
	static const char payload[] =
		"This is a useless payload that only serves as a means to give the "
		"server the opportunity to close the connection before the payload "
		"is finished.";
	struct _connection_lost_sub_ioloop_ctx *ctx;
	struct http_client_request *hreq;
	struct istream *input;

	ctx = i_new(struct _connection_lost_sub_ioloop_ctx, 1);
	ctx->count = 2;

	http_client = http_client_init(client_set);

	input = i_stream_create_from_data(payload, sizeof(payload)-1);

	hreq = http_client_request(http_client,
		"GET", net_ip2addr(&bind_ip), "/connection-lost-sub-ioloop.txt",
		test_client_connection_lost_sub_ioloop_response, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_set_payload(hreq, input, TRUE);
	http_client_request_submit(hreq);

	hreq = http_client_request(http_client,
		"GET", net_ip2addr(&bind_ip), "/connection-lost-sub-ioloop2.txt",
		test_client_connection_lost_sub_ioloop_response, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_set_payload(hreq, input, TRUE);
	http_client_request_submit(hreq);

	i_stream_unref(&input);	
}

/* test */

static void test_connection_lost_sub_ioloop(void)
{
	struct http_client_settings http_client_set;

	test_client_defaults(&http_client_set);

	server_read_max = 0;

	test_begin("connection lost while running sub-ioloop");
	http_client_set.max_attempts = 1;
	test_run_client_server(&http_client_set,
		test_client_connection_lost_sub_ioloop,
		test_server_connection_lost_sub_ioloop, 2);
	test_end();
}

/*
 * Early success
 */

/* server */

static void
test_early_success_input(struct server_connection *conn)
{
	static const char *resp =
		"HTTP/1.1 200 OK\r\n"
		"Content-Length: 18\r\n"
		"\r\n"
		"Everything is OK\r\n";
	
	usleep(200000);
	o_stream_nsend_str(conn->conn.output, resp);
	server_connection_deinit(&conn);
}

static void test_server_early_success(unsigned int index)
{
	test_server_input = test_early_success_input;
	test_server_run(index);
}

/* client */

struct _early_success_ctx {
	unsigned int count;
};

static void
test_client_early_success_response(
	const struct http_response *resp,
	struct _early_success_ctx *ctx)
{
	if (debug)
		i_debug("RESPONSE: %u %s", resp->status, resp->reason);

	if (ctx->count == 2)
		test_assert(resp->status == HTTP_CLIENT_REQUEST_ERROR_BAD_RESPONSE);
	else
		test_assert(resp->status == 200);
	test_assert(resp->reason != NULL && *resp->reason != '\0');
	if (--ctx->count == 0) {
		io_loop_stop(ioloop);
		i_free(ctx);
	}
}

static void
test_client_early_success(const struct http_client_settings *client_set)
{
	struct http_client_request *hreq;
	struct _early_success_ctx *ctx;
	string_t *payload;
	unsigned int i;

	ctx = i_new(struct _early_success_ctx, 1);
	ctx->count = 2;
	
	http_client = http_client_init(client_set);

	hreq = http_client_request(http_client,
		"GET", net_ip2addr(&bind_ip), "/early-success.txt",
		test_client_early_success_response, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);

	T_BEGIN {
		payload = t_str_new(204800);
		for (i = 0; i < 3200; i++) {
			str_append(payload,
				"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"
				"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
		}

		http_client_request_set_payload_data
			(hreq, str_data(payload), str_len(payload));
	} T_END;
	http_client_request_submit(hreq);

	hreq = http_client_request(http_client,
		"GET", net_ip2addr(&bind_ip), "/early-success2.txt",
		test_client_early_success_response, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_submit(hreq);
}

/* test */

static void test_early_success(void)
{
	struct http_client_settings http_client_set;

	test_client_defaults(&http_client_set);
	http_client_set.socket_send_buffer_size = 4096;

	test_begin("early succes");
	test_run_client_server(&http_client_set,
		test_client_early_success,
		test_server_early_success, 1);
	test_end();
}

/*
 * Bad response
 */

/* server */

static void
test_bad_response_input(struct server_connection *conn)
{
	static const char *resp =
		"HTTP/1.1 666 Really bad response\r\n"
		"\r\n";
	o_stream_nsend_str(conn->conn.output, resp);
	server_connection_deinit(&conn);
}

static void test_server_bad_response(unsigned int index)
{
	test_server_input = test_bad_response_input;
	test_server_run(index);
}

/* client */

struct _bad_response_ctx {
	unsigned int count;
};

static void
test_client_bad_response_response(
	const struct http_response *resp,
	struct _bad_response_ctx *ctx)
{
	if (debug)
		i_debug("RESPONSE: %u %s", resp->status, resp->reason);

	test_assert(resp->status == HTTP_CLIENT_REQUEST_ERROR_BAD_RESPONSE);
	test_assert(resp->reason != NULL && *resp->reason != '\0');

	if (--ctx->count == 0) {
		i_free(ctx);
		io_loop_stop(ioloop);
	}
}

static void
test_client_bad_response(const struct http_client_settings *client_set)
{
	struct http_client_request *hreq;
	struct _bad_response_ctx *ctx;

	ctx = i_new(struct _bad_response_ctx, 1);
	ctx->count = 2;

	http_client = http_client_init(client_set);

	hreq = http_client_request(http_client,
		"GET", net_ip2addr(&bind_ip), "/bad-response.txt",
		test_client_bad_response_response, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_submit(hreq);

	hreq = http_client_request(http_client,
		"GET", net_ip2addr(&bind_ip), "/bad-response2.txt",
		test_client_bad_response_response, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_submit(hreq);
}

/* test */

static void test_bad_response(void)
{
	struct http_client_settings http_client_set;

	test_client_defaults(&http_client_set);

	test_begin("bad response");
	test_run_client_server(&http_client_set,
		test_client_bad_response,
		test_server_bad_response, 1);
	test_end();
}

/*
 * Request timed out
 */

/* server */

static void
test_request_timed_out_input(struct server_connection *conn ATTR_UNUSED)
{
	/* do nothing */
}

static void test_server_request_timed_out(unsigned int index)
{
	test_server_input = test_request_timed_out_input;
	test_server_run(index);
}

/* client */

struct _request_timed_out_ctx {
	unsigned int count;
};

static void
test_client_request_timed_out_response(
	const struct http_response *resp,
	struct _request_timed_out_ctx *ctx)
{
	if (debug)
		i_debug("RESPONSE: %u %s", resp->status, resp->reason);

	test_assert(resp->status == HTTP_CLIENT_REQUEST_ERROR_TIMED_OUT);
	test_assert(resp->reason != NULL && *resp->reason != '\0');

	if (--ctx->count == 0) {
		i_free(ctx);
		io_loop_stop(ioloop);
	}
}

static void
test_client_request_timed_out(const struct http_client_settings *client_set)
{
	struct http_client_request *hreq;
	struct _request_timed_out_ctx *ctx;

	ctx = i_new(struct _request_timed_out_ctx, 1);
	ctx->count = 2;

	http_client = http_client_init(client_set);

	hreq = http_client_request(http_client,
		"GET", net_ip2addr(&bind_ip), "/request-timed-out.txt",
		test_client_request_timed_out_response, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_submit(hreq);

	hreq = http_client_request(http_client,
		"GET", net_ip2addr(&bind_ip), "/request-timed-out2.txt",
		test_client_request_timed_out_response, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_submit(hreq);
}

/* test */

static void test_request_timed_out(void)
{
	struct http_client_settings http_client_set;

	test_client_defaults(&http_client_set);

	test_begin("request timed out: one attempt");
	http_client_set.request_timeout_msecs = 1000;
	http_client_set.max_attempts = 1;
	test_run_client_server(&http_client_set,
		test_client_request_timed_out,
		test_server_request_timed_out, 1);
	test_end();

	test_begin("request timed out: two attempts");
	http_client_set.request_timeout_msecs = 1000;
	http_client_set.max_attempts = 1;
	test_run_client_server(&http_client_set,
		test_client_request_timed_out,
		test_server_request_timed_out, 1);
	test_end();

	test_begin("request absolutely timed out");
	http_client_set.request_timeout_msecs = 0;
	http_client_set.request_absolute_timeout_msecs = 2000;
	http_client_set.max_attempts = 3;
	test_run_client_server(&http_client_set,
		test_client_request_timed_out,
		test_server_request_timed_out, 1);
	test_end();

	test_begin("request double timed out");
	http_client_set.request_timeout_msecs = 500;
	http_client_set.request_absolute_timeout_msecs = 2000;
	http_client_set.max_attempts = 3;
	test_run_client_server(&http_client_set,
		test_client_request_timed_out,
		test_server_request_timed_out, 1);
	test_end();
}

/*
 * Request aborted early
 */

/* server */

static void
test_request_aborted_early_input(struct server_connection *conn ATTR_UNUSED)
{
	static const char *resp =
		"HTTP/1.1 404 Not Found\r\n"
		"\r\n";

	/* wait one second to respon */
	sleep(1);

	/* respond */
	o_stream_nsend_str(conn->conn.output, resp);
	server_connection_deinit(&conn);
}

static void test_server_request_aborted_early(unsigned int index)
{
	test_server_input = test_request_aborted_early_input;
	test_server_run(index);
}

/* client */

struct _request_aborted_early_ctx {
	struct http_client_request *req1, *req2;
	struct timeout *to;
};

static void
test_client_request_aborted_early_response(
	const struct http_response *resp,
	struct _request_aborted_early_ctx *ctx ATTR_UNUSED)
{
	if (debug)
		i_debug("RESPONSE: %u %s", resp->status, resp->reason);

	/* abort does not trigger callback */
	test_assert(FALSE); 
}

static void
test_client_request_aborted_early_timeout(
	struct _request_aborted_early_ctx *ctx)
{
	timeout_remove(&ctx->to);

	if (ctx->req1 != NULL) {
		/* abort early */
		http_client_request_abort(&ctx->req1); /* sent */
		http_client_request_abort(&ctx->req2); /* only queued */
	
		/* wait a little for server to actually respond to an
		   already aborted request */
		ctx->to = timeout_add_short(1000,
			test_client_request_aborted_early_timeout, ctx);
	} else {
		/* all done */
		i_free(ctx);
		io_loop_stop(ioloop);
	}
}

static void
test_client_request_aborted_early(
	const struct http_client_settings *client_set)
{
	struct http_client_request *hreq;
	struct _request_aborted_early_ctx *ctx;

	ctx = i_new(struct _request_aborted_early_ctx, 1);

	http_client = http_client_init(client_set);

	hreq = ctx->req1 = http_client_request(http_client,
		"GET", net_ip2addr(&bind_ip), "/request-aborted-early.txt",
		test_client_request_aborted_early_response, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_submit(hreq);

	hreq = ctx->req2 = http_client_request(http_client,
		"GET", net_ip2addr(&bind_ip), "/request-aborted-early2.txt",
		test_client_request_aborted_early_response, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_submit(hreq);

	ctx->to = timeout_add_short(500,
		test_client_request_aborted_early_timeout, ctx);
}

/* test */

static void test_request_aborted_early(void)
{
	struct http_client_settings http_client_set;

	test_client_defaults(&http_client_set);

	test_begin("request aborted early");
	test_run_client_server(&http_client_set,
		test_client_request_aborted_early,
		test_server_request_aborted_early, 1);
	test_end();
}

/*
 * Client deinit early
 */

/* server */

static void
test_client_deinit_early_input(struct server_connection *conn ATTR_UNUSED)
{
	static const char *resp =
		"HTTP/1.1 404 Not Found\r\n"
		"\r\n";

	/* wait one second to respon */
	sleep(1);

	/* respond */
	o_stream_nsend_str(conn->conn.output, resp);
	server_connection_deinit(&conn);
}

static void test_server_client_deinit_early(unsigned int index)
{
	test_server_input = test_client_deinit_early_input;
	test_server_run(index);
}

/* client */

struct _client_deinit_early_ctx {
	struct timeout *to;
};

static void
test_client_client_deinit_early_response(
	const struct http_response *resp,
	struct _client_deinit_early_ctx *ctx ATTR_UNUSED)
{
	if (debug)
		i_debug("RESPONSE: %u %s", resp->status, resp->reason);

	/* abort does not trigger callback */
	test_assert(FALSE); 
}

static void
test_client_client_deinit_early_timeout(
	struct _client_deinit_early_ctx *ctx)
{
	timeout_remove(&ctx->to);

	/* deinit early */
	http_client_deinit(&http_client);
	
	/* all done */
	i_free(ctx);
	io_loop_stop(ioloop);
}

static void
test_client_client_deinit_early(const struct http_client_settings *client_set)
{
	struct http_client_request *hreq;
	struct _client_deinit_early_ctx *ctx;

	ctx = i_new(struct _client_deinit_early_ctx, 1);

	http_client = http_client_init(client_set);

	hreq = http_client_request(http_client,
		"GET", net_ip2addr(&bind_ip), "/client-deinit-early.txt",
		test_client_client_deinit_early_response, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_submit(hreq);

	hreq =  http_client_request(http_client,
		"GET", net_ip2addr(&bind_ip), "/client-deinit-early2.txt",
		test_client_client_deinit_early_response, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_submit(hreq);

	ctx->to = timeout_add_short(500,
		test_client_client_deinit_early_timeout, ctx);
}

/* test */

static void test_client_deinit_early(void)
{
	struct http_client_settings http_client_set;

	test_client_defaults(&http_client_set);

	test_begin("client deinit early");
	test_run_client_server(&http_client_set,
		test_client_client_deinit_early,
		test_server_client_deinit_early, 1);
	test_end();
}

/*
 * All tests
 */

static void (*test_functions[])(void) = {
	test_host_lookup_failed,
	test_connection_refused,
	test_connection_timed_out,
	test_invalid_redirect,
	test_unseekable_redirect,
	test_unseekable_retry,
	test_broken_payload,
	test_connection_lost,
	test_connection_lost_100,
	test_connection_lost_sub_ioloop,
	test_early_success,
	test_bad_response,
	test_request_timed_out,
	test_request_aborted_early,
	test_client_deinit_early,
	NULL
};

/*
 * Test client
 */

static void
test_client_defaults(struct http_client_settings *http_set)
{
	/* client settings */
	memset(http_set, 0, sizeof(*http_set));
	http_set->max_idle_time_msecs = 5*1000;
	http_set->max_parallel_connections = 1;
	http_set->max_pipelined_requests = 1;
	http_set->max_redirects = 0;
	http_set->max_attempts = 1;
	http_set->debug = debug;
}

static void test_client_deinit(void)
{
	if (http_client != NULL)
		http_client_deinit(&http_client);
	http_client = NULL;
}

/*
 * Test server
 */

/* client connection */

static void
server_connection_input(struct connection *_conn)
{
	struct server_connection *conn = (struct server_connection *)_conn;
	
	test_server_input(conn);
}

static void
server_connection_init(int fd)
{
	struct server_connection *conn;
	pool_t pool;

	net_set_nonblock(fd, TRUE);

	pool = pool_alloconly_create("server connection", 256);
	conn = p_new(pool, struct server_connection, 1);
	conn->pool = pool;

	connection_init_server
		(server_conn_list, &conn->conn, "server connection", fd, fd);
}

static void
server_connection_deinit(struct server_connection **_conn)
{
	struct server_connection *conn = *_conn;

	*_conn = NULL;

	connection_deinit(&conn->conn);
	pool_unref(&conn->pool);
}

static void
server_connection_destroy(struct connection *_conn)
{
	struct server_connection *conn =
		(struct server_connection *)_conn;

	server_connection_deinit(&conn);
}

static void
server_connection_accept(void *context ATTR_UNUSED)
{
	int fd;

	/* accept new client */
	fd = net_accept(fd_listen, NULL, NULL);
	if (fd == -1)
		return;
	if (fd == -2) {
		i_fatal("test server: accept() failed: %m");
	}

	server_connection_init(fd);
}

/* */

static struct connection_settings server_connection_set = {
	.input_max_size = (size_t)-1,
	.output_max_size = (size_t)-1,
	.client = FALSE
};

static const struct connection_vfuncs server_connection_vfuncs = {
	.destroy = server_connection_destroy,
	.input = server_connection_input
};

static void test_server_run(unsigned int index)
{
	server_index = index;

	/* open server socket */
	io_listen = io_add(fd_listen,
		IO_READ, server_connection_accept, (void *)NULL);

	server_conn_list = connection_list_init
		(&server_connection_set, &server_connection_vfuncs);

	io_loop_run(ioloop);

	/* close server socket */
	io_remove(&io_listen);

	connection_list_deinit(&server_conn_list);
}

/*
 * Tests
 */

static int test_open_server_fd(in_port_t *bind_port)
{
	int fd = net_listen(&bind_ip, bind_port, 128);
	if (debug)
		i_debug("server listening on %u", *bind_port);
	if (fd == -1) {
		i_fatal("listen(%s:%u) failed: %m",
			net_ip2addr(&bind_ip), *bind_port);
	}
	return fd;
}

static void test_servers_kill_all(void)
{
	unsigned int i;

	if (server_pids_count > 0) {
		for (i = 0; i < server_pids_count; i++) {
			if (server_pids[i] != (pid_t)-1) {
				(void)kill(server_pids[i], SIGKILL);
				(void)waitpid(server_pids[i], NULL, 0);
				server_pids[i] = -1;
			}
		}
	}
	server_pids_count = 0;
}

static void test_run_client_server(
	const struct http_client_settings *client_set,
	test_client_init_t client_test,
	test_server_init_t server_test,
	unsigned int server_tests_count)
{
	unsigned int i;

	server_pids = NULL;
	server_pids_count = 0;

	if (server_tests_count > 0) {
		int fds[server_tests_count];

		bind_ports = i_new(in_port_t, server_tests_count);

		server_pids = i_new(pid_t, server_tests_count);
		for (i = 0; i < server_tests_count; i++)
			server_pids[i] = (pid_t)-1;
		server_pids_count = server_tests_count;

		for (i = 0; i < server_tests_count; i++)
			fds[i] = test_open_server_fd(&bind_ports[i]);

		for (i = 0; i < server_tests_count; i++) {
			fd_listen = fds[i];
			if ((server_pids[i] = fork()) == (pid_t)-1)
				i_fatal("fork() failed: %m");
			if (server_pids[i] == 0) {
				server_pids[i] = (pid_t)-1;
				server_pids_count = 0;
				hostpid_init();
				if (debug)
					i_debug("server[%d]: PID=%s", i+1, my_pid);
				/* child: server */
				ioloop = io_loop_create();
				server_test(i);
				io_loop_destroy(&ioloop);
				if (fd_listen != -1)
					i_close_fd(&fd_listen);
				i_free(bind_ports);
				i_free(server_pids);
				/* wait for it to be killed; this way, valgrind will not
				   object to this process going away inelegantly. */
				sleep(60);
				exit(1);
			}
			if (fd_listen != -1)
				i_close_fd(&fd_listen);
		}
		if (debug)
			i_debug("client: PID=%s", my_pid);
	}

	/* parent: client */

	usleep(100000); /* wait a little for server setup */

	ioloop = io_loop_create();
	client_test(client_set);
	io_loop_run(ioloop);
	test_client_deinit();
	io_loop_destroy(&ioloop);

	test_servers_kill_all();
	i_free(server_pids);
	i_free(bind_ports);
}

/*
 * Main
 */

volatile sig_atomic_t terminating = 0;

static void
test_signal_handler(int signo)
{
	if (terminating != 0)
		raise(signo);
	terminating = 1;

	/* make sure we don't leave any pesky children alive */
	test_servers_kill_all();

	(void)signal(signo, SIG_DFL);
	raise(signo);
}

static void test_atexit(void)
{
	test_servers_kill_all();
}

int main(int argc, char *argv[])
{
	int c;

	atexit(test_atexit);
	(void)signal(SIGCHLD, SIG_IGN);
	(void)signal(SIGTERM, test_signal_handler);
	(void)signal(SIGQUIT, test_signal_handler);
	(void)signal(SIGINT, test_signal_handler);
	(void)signal(SIGSEGV, test_signal_handler);
	(void)signal(SIGABRT, test_signal_handler);

  while ((c = getopt(argc, argv, "D")) > 0) {
		switch (c) {
		case 'D':
			debug = TRUE;
			break;
		default:
			i_fatal("Usage: %s [-D]", argv[0]);
		}
  }

	/* listen on localhost */
	memset(&bind_ip, 0, sizeof(bind_ip));
	bind_ip.family = AF_INET;
	bind_ip.u.ip4.s_addr = htonl(INADDR_LOOPBACK);	

	test_run(test_functions);
}
