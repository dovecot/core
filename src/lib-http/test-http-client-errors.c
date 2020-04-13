/* Copyright (c) 2016-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "lib-signals.h"
#include "str.h"
#include "str-sanitize.h"
#include "hostpid.h"
#include "ioloop.h"
#include "istream.h"
#include "istream-chain.h"
#include "ostream.h"
#include "time-util.h"
#include "sleep.h"
#include "connection.h"
#include "test-common.h"
#include "http-url.h"
#include "http-request.h"
#include "http-client.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>

#define CLIENT_PROGRESS_TIMEOUT     10

/*
 * Types
 */

struct server_connection {
	struct connection conn;
	void *context;

	pool_t pool;
	bool version_sent:1;
};

typedef void (*test_server_init_t)(unsigned int index);
typedef bool
(*test_client_init_t)(const struct http_client_settings *client_set);
typedef void (*test_dns_init_t)(void);

/*
 * State
 */

/* common */
static struct ip_addr bind_ip;
static in_port_t *bind_ports = 0;
static struct ioloop *ioloop;
static bool debug = FALSE;

/* dns */
static pid_t dns_pid = (pid_t)-1;

/* server */
static struct io *io_listen;
static int fd_listen = -1;
static pid_t *server_pids = NULL;
static unsigned int server_pids_count = 0;
static struct connection_list *server_conn_list;
static size_t server_read_max = 0;
static unsigned int server_index;
static int (*test_server_init)(struct server_connection *conn);
static void (*test_server_deinit)(struct server_connection *conn);
static void (*test_server_input)(struct server_connection *conn);

/* client */
static struct timeout *to_client_progress = NULL;
static struct http_client *http_client = NULL;

/*
 * Forward declarations
 */

/* server */
static void test_server_run(unsigned int index);
static void server_connection_deinit(struct server_connection **_conn);

/* client */
static void test_client_defaults(struct http_client_settings *http_set);
static void test_client_deinit(void);

/* test*/
static void
test_run_client_server(const struct http_client_settings *client_set,
		       test_client_init_t client_test,
		       test_server_init_t server_test,
		       unsigned int server_tests_count,
		       test_dns_init_t dns_test) ATTR_NULL(3);

/*
 * Utility
 */

static void
test_client_assert_response(const struct http_response *resp,
			    bool condition)
{
	const char *reason = (resp->reason != NULL ? resp->reason : "<NULL>");

	test_assert(resp->reason != NULL && *resp->reason != '\0');

	if (!condition)
		i_error("BAD RESPONSE: %u %s", resp->status, reason);
	else if (debug)
		i_debug("RESPONSE: %u %s", resp->status, resp->reason);
}

/*
 * Unconfigured SSL
 */

/* client */

struct _unconfigured_ssl {
	unsigned int count;
};

static void
test_client_unconfigured_ssl_response(const struct http_response *resp,
				      struct _unconfigured_ssl *ctx)
{
	test_client_assert_response(
		resp, resp->status == HTTP_CLIENT_REQUEST_ERROR_CONNECT_FAILED);

	if (--ctx->count == 0) {
		i_free(ctx);
		io_loop_stop(ioloop);
	}
}

static bool
test_client_unconfigured_ssl(const struct http_client_settings *client_set)
{
	struct http_client_request *hreq;
	struct _unconfigured_ssl *ctx;

	ctx = i_new(struct _unconfigured_ssl, 1);
	ctx->count = 2;

	http_client = http_client_init(client_set);

	hreq = http_client_request(
		http_client, "GET", "127.0.0.1", "/unconfigured-ssl.txt",
		test_client_unconfigured_ssl_response, ctx);
	http_client_request_set_ssl(hreq, TRUE);
	http_client_request_submit(hreq);

	hreq = http_client_request(
		http_client, "GET", "127.0.0.1", "/unconfigured-ssl2.txt",
		test_client_unconfigured_ssl_response, ctx);
	http_client_request_set_ssl(hreq, TRUE);
	http_client_request_submit(hreq);

	return TRUE;
}

/* test */

static void test_unconfigured_ssl(void)
{
	struct http_client_settings http_client_set;

	test_client_defaults(&http_client_set);

	test_begin("unconfigured ssl");
	test_run_client_server(&http_client_set,
			       test_client_unconfigured_ssl, NULL, 0, NULL);
	test_end();
}

/*
 * Unconfigured SSL abort
 */

/* client */

struct _unconfigured_ssl_abort {
	unsigned int count;
};

static void
test_client_unconfigured_ssl_abort_response1(
	const struct http_response *resp,
	struct _unconfigured_ssl_abort *ctx ATTR_UNUSED)
{
	if (debug)
		i_debug("RESPONSE: %u %s", resp->status, resp->reason);

	test_out_quiet("inappropriate callback", FALSE);
}

static void
test_client_unconfigured_ssl_abort_response2(
	const struct http_response *resp, struct _unconfigured_ssl_abort *ctx)
{
	test_client_assert_response(
		resp, resp->status == HTTP_CLIENT_REQUEST_ERROR_CONNECT_FAILED);

	i_free(ctx);
	io_loop_stop(ioloop);
}

static bool
test_client_unconfigured_ssl_abort(
	const struct http_client_settings *client_set)
{
	struct http_client_request *hreq;
	struct _unconfigured_ssl_abort *ctx;

	ctx = i_new(struct _unconfigured_ssl_abort, 1);
	ctx->count = 1;

	http_client = http_client_init(client_set);

	hreq = http_client_request(
		http_client, "GET", "127.0.0.1", "/unconfigured-ssl.txt",
		test_client_unconfigured_ssl_abort_response1, ctx);
	http_client_request_set_ssl(hreq, TRUE);
	http_client_request_submit(hreq);
	http_client_request_abort(&hreq);

	hreq = http_client_request(
		http_client, "GET", "127.0.0.1", "/unconfigured-ssl2.txt",
		test_client_unconfigured_ssl_abort_response2, ctx);
	http_client_request_set_ssl(hreq, TRUE);
	http_client_request_submit(hreq);

	return TRUE;
}

/* test */

static void test_unconfigured_ssl_abort(void)
{
	struct http_client_settings http_client_set;

	test_client_defaults(&http_client_set);

	test_begin("unconfigured ssl abort");
	test_run_client_server(&http_client_set,
			       test_client_unconfigured_ssl_abort,
			       NULL, 0, NULL);
	test_end();
}

/*
 * Invalid URL
 */

/* client */

struct _invalid_url {
	unsigned int count;
};

static void
test_client_invalid_url_response(const struct http_response *resp,
				 struct _invalid_url *ctx)
{
	test_client_assert_response(
		resp, resp->status == HTTP_CLIENT_REQUEST_ERROR_INVALID_URL);

	if (--ctx->count == 0) {
		i_free(ctx);
		io_loop_stop(ioloop);
	}
}

static bool
test_client_invalid_url(const struct http_client_settings *client_set)
{
	struct http_client_request *hreq;
	struct _invalid_url *ctx;

	ctx = i_new(struct _invalid_url, 1);
	ctx->count = 2;

	http_client = http_client_init(client_set);

	hreq = http_client_request_url_str(
		http_client, "GET", "imap://example.com/INBOX",
		test_client_invalid_url_response, ctx);
	http_client_request_submit(hreq);

	hreq = http_client_request_url_str(
		http_client, "GET", "http:/www.example.com",
		test_client_invalid_url_response, ctx);
	http_client_request_submit(hreq);

	return TRUE;
}

/* test */

static void test_invalid_url(void)
{
	struct http_client_settings http_client_set;

	test_client_defaults(&http_client_set);

	test_begin("invalid url");
	test_run_client_server(&http_client_set,
			       test_client_invalid_url, NULL, 0, NULL);
	test_end();
}

/*
 * Host lookup failed
 */

/* client */

struct _host_lookup_failed {
	unsigned int count;
};

static void
test_client_host_lookup_failed_response(const struct http_response *resp,
					struct _host_lookup_failed *ctx)
{
	test_client_assert_response(
		resp,
		resp->status == HTTP_CLIENT_REQUEST_ERROR_HOST_LOOKUP_FAILED);

	if (--ctx->count == 0) {
		i_free(ctx);
		io_loop_stop(ioloop);
	}
}

static bool
test_client_host_lookup_failed(const struct http_client_settings *client_set)
{
	struct http_client_request *hreq;
	struct _host_lookup_failed *ctx;

	ctx = i_new(struct _host_lookup_failed, 1);
	ctx->count = 2;

	http_client = http_client_init(client_set);

	hreq = http_client_request(
		http_client, "GET", "host.in-addr.arpa",
		"/host-lookup-failed.txt",
		test_client_host_lookup_failed_response, ctx);
	http_client_request_submit(hreq);

	hreq = http_client_request(
		http_client, "GET", "host.in-addr.arpa",
		"/host-lookup-failed2.txt",
		test_client_host_lookup_failed_response, ctx);
	http_client_request_submit(hreq);

	return TRUE;
}

/* test */

static void test_host_lookup_failed(void)
{
	struct http_client_settings http_client_set;

	test_client_defaults(&http_client_set);

	test_begin("host lookup failed");
	test_run_client_server(&http_client_set,
			       test_client_host_lookup_failed, NULL, 0, NULL);
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
	struct timeout *to;
};

static void
test_client_connection_refused_response(const struct http_response *resp,
					struct _connection_refused *ctx)
{
	test_assert(ctx->to == NULL);
	timeout_remove(&ctx->to);

	test_client_assert_response(
		resp, resp->status == HTTP_CLIENT_REQUEST_ERROR_CONNECT_FAILED);

	if (--ctx->count == 0) {
		i_free(ctx);
		io_loop_stop(ioloop);
	}
}

static void
test_client_connection_refused_timeout(struct _connection_refused *ctx)
{
	if (debug)
		i_debug("TIMEOUT (ok)");
	timeout_remove(&ctx->to);
}

static bool
test_client_connection_refused(const struct http_client_settings *client_set)
{
	struct http_client_request *hreq;
	struct _connection_refused *ctx;

	ctx = i_new(struct _connection_refused, 1);
	ctx->count = 2;

	if (client_set->max_connect_attempts > 0) {
		ctx->to = timeout_add_short(250,
			test_client_connection_refused_timeout, ctx);
	}

	http_client = http_client_init(client_set);

	hreq = http_client_request(
		http_client, "GET", net_ip2addr(&bind_ip),
		"/connection-refused.txt",
		test_client_connection_refused_response, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_submit(hreq);

	hreq = http_client_request(
		http_client, "GET", net_ip2addr(&bind_ip),
		"/connection-refused2.txt",
		test_client_connection_refused_response, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_submit(hreq);

	return TRUE;
}

/* test */

static void test_connection_refused(void)
{
	struct http_client_settings http_client_set;

	test_client_defaults(&http_client_set);

	test_begin("connection refused");
	test_run_client_server(&http_client_set,
			       test_client_connection_refused,
			       test_server_connection_refused, 1, NULL);
	test_end();

	http_client_set.max_connect_attempts = 3;

	test_begin("connection refused backoff");
	test_run_client_server(&http_client_set,
			       test_client_connection_refused,
			       test_server_connection_refused, 1, NULL);
	test_end();
}

/*
 * Connection lost prematurely
 */

/* server */

static void
test_server_connection_lost_prematurely_input(struct server_connection *conn)
{
	server_connection_deinit(&conn);
}

static void test_server_connection_lost_prematurely(unsigned int index)
{
	test_server_input = test_server_connection_lost_prematurely_input;
	test_server_run(index);
}

/* client */

struct _connection_lost_prematurely {
	unsigned int count;
	struct timeout *to;
};

static void
test_client_connection_lost_prematurely_response(
	const struct http_response *resp,
	struct _connection_lost_prematurely *ctx)
{
	test_assert(ctx->to == NULL);
	timeout_remove(&ctx->to);

	test_client_assert_response(
		resp,
		resp->status == HTTP_CLIENT_REQUEST_ERROR_CONNECTION_LOST);

	if (--ctx->count == 0) {
		i_free(ctx);
		io_loop_stop(ioloop);
	}
}

static void
test_client_connection_lost_prematurely_timeout(
	struct _connection_lost_prematurely *ctx)
{
	if (debug)
		i_debug("TIMEOUT (ok)");
	timeout_remove(&ctx->to);
}

static bool
test_client_connection_lost_prematurely(
	const struct http_client_settings *client_set)
{
	struct http_client_request *hreq;
	struct _connection_lost_prematurely *ctx;

	ctx = i_new(struct _connection_lost_prematurely, 1);
	ctx->count = 2;

	ctx->to = timeout_add_short(
		250, test_client_connection_lost_prematurely_timeout, ctx);

	http_client = http_client_init(client_set);

	hreq = http_client_request(
		http_client, "GET", net_ip2addr(&bind_ip),
		"/connection-refused-retry.txt",
		test_client_connection_lost_prematurely_response, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_submit(hreq);

	hreq = http_client_request(
		http_client, "GET", net_ip2addr(&bind_ip),
		"/connection-refused-retry2.txt",
		test_client_connection_lost_prematurely_response, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_submit(hreq);

	return TRUE;
}

/* test */

static void test_connection_lost_prematurely(void)
{
	struct http_client_settings http_client_set;

	test_client_defaults(&http_client_set);
	http_client_set.max_connect_attempts = 3;
	http_client_set.max_attempts = 3;

	test_begin("connection lost prematurely");
	test_run_client_server(&http_client_set,
			       test_client_connection_lost_prematurely,
			       test_server_connection_lost_prematurely, 1,
			       NULL);
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
test_client_connection_timed_out_response(const struct http_response *resp,
					  struct _connection_timed_out *ctx)
{
	test_client_assert_response(
		resp, resp->status == HTTP_CLIENT_REQUEST_ERROR_CONNECT_FAILED);

	if (--ctx->count == 0) {
		i_free(ctx);
		io_loop_stop(ioloop);
	}
}

static bool
test_client_connection_timed_out(const struct http_client_settings *client_set)
{
	struct http_client_request *hreq;
	struct _connection_timed_out *ctx;

	ctx = i_new(struct _connection_timed_out, 1);
	ctx->count = 2;

	http_client = http_client_init(client_set);

	hreq = http_client_request(
		http_client, "GET", "192.168.0.0", "/connection-timed-out.txt",
		test_client_connection_timed_out_response, ctx);
	http_client_request_submit(hreq);

	hreq = http_client_request(
		http_client, "GET", "192.168.0.0", "/connection-timed-out2.txt",
		test_client_connection_timed_out_response, ctx);
	http_client_request_submit(hreq);

	return TRUE;
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
			       test_client_connection_timed_out, NULL, 0, NULL);
	test_end();
}

/*
 * Invalid redirect
 */

/* server */

/* -> not accepted */

static void test_invalid_redirect_input1(struct server_connection *conn)
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

static void test_invalid_redirect_input2(struct server_connection *conn)
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

static void test_invalid_redirect_input3(struct server_connection *conn)
{
	string_t *resp;

	resp = t_str_new(512);
	str_printfa(resp, 
		    "HTTP/1.1 302 Redirect\r\n"
		    "Location: http://%s:%u/friep.txt\r\n"
		    "\r\n",
		    net_ip2addr(&bind_ip), bind_ports[server_index+1]);
	o_stream_nsend(conn->conn.output, str_data(resp), str_len(resp));
	server_connection_deinit(&conn);
}

static void test_server_invalid_redirect3(unsigned int index)
{
	test_server_input = test_invalid_redirect_input3;
	test_server_run(index);
}

/* client */

static void
test_client_invalid_redirect_response(const struct http_response *resp,
				      void *context ATTR_UNUSED)
{
	test_client_assert_response(
		resp,
		resp->status == HTTP_CLIENT_REQUEST_ERROR_INVALID_REDIRECT);

	io_loop_stop(ioloop);
}

static bool
test_client_invalid_redirect(const struct http_client_settings *client_set)
{
	struct http_client_request *hreq;

	http_client = http_client_init(client_set);

	hreq = http_client_request(
		http_client, "GET", net_ip2addr(&bind_ip),
		"/invalid-redirect.txt",
		test_client_invalid_redirect_response, NULL);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_submit(hreq);

	return TRUE;
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
			       test_server_invalid_redirect1, 1, NULL);
	test_end();

	test_begin("invalid redirect: bad location");
	http_client_set.max_redirects = 1;
	test_run_client_server(&http_client_set,
			       test_client_invalid_redirect,
			       test_server_invalid_redirect2, 1, NULL);
	test_end();

	test_begin("invalid redirect: too many");
	http_client_set.max_redirects = 1;
	test_run_client_server(&http_client_set,
			       test_client_invalid_redirect,
			       test_server_invalid_redirect3, 3, NULL);
	test_end();
}

/* 
 * Unseekable redirect
 */

/* server */

static void test_unseekable_redirect_input(struct server_connection *conn)
{
	string_t *resp;

	resp = t_str_new(512);
	str_printfa(resp, 
		    "HTTP/1.1 302 Redirect\r\n"
		    "Location: http://%s:%u/frml.txt\r\n"
		    "\r\n",
		    net_ip2addr(&bind_ip), bind_ports[server_index+1]);
	o_stream_nsend(conn->conn.output, str_data(resp), str_len(resp));
	server_connection_deinit(&conn);
}

static void test_server_unseekable_redirect(unsigned int index)
{
	test_server_input = test_unseekable_redirect_input;
	test_server_run(index);
}

/* client */

static void
test_client_unseekable_redirect_response(const struct http_response *resp,
					 void *context ATTR_UNUSED)
{
	test_client_assert_response(
		resp, resp->status == HTTP_CLIENT_REQUEST_ERROR_ABORTED);

	io_loop_stop(ioloop);
}

static bool
test_client_unseekable_redirect(const struct http_client_settings *client_set)
{
	struct http_client_request *hreq;
	struct istream *input;

	http_client = http_client_init(client_set);

	input = i_stream_create_from_data("FROP", 4);
	input->seekable = FALSE;

	hreq = http_client_request(
		http_client, "GET", net_ip2addr(&bind_ip),
		"/unseekable-redirect.txt",
		test_client_unseekable_redirect_response, NULL);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_set_payload(hreq, input, FALSE);
	http_client_request_submit(hreq);

	i_stream_unref(&input);
	return TRUE;
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
			       test_server_unseekable_redirect, 2, NULL);
	test_end();
}

/*
 * Unseekable retry
 */

/* server */

static void test_unseekable_retry_input(struct server_connection *conn)
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
test_client_unseekable_retry_response(const struct http_response *resp,
				      void *context ATTR_UNUSED)
{
	test_client_assert_response(
		resp, resp->status == HTTP_CLIENT_REQUEST_ERROR_ABORTED);

	io_loop_stop(ioloop);
}

static bool
test_client_unseekable_retry(const struct http_client_settings *client_set)
{
	struct http_client_request *hreq;
	struct istream *input;

	http_client = http_client_init(client_set);

	input = i_stream_create_from_data("FROP", 4);
	input->seekable = FALSE;

	hreq = http_client_request(
		http_client, "GET", net_ip2addr(&bind_ip),
		"/unseekable-retry.txt",
		test_client_unseekable_retry_response, NULL);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_set_payload(hreq, input, FALSE);
	http_client_request_submit(hreq);

	i_stream_unref(&input);
	return TRUE;
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
			       test_server_unseekable_retry, 2, NULL);
	test_end();
}

/*
 * Broken payload
 */

/* server */

static void test_broken_payload_input(struct server_connection *conn)
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
test_client_broken_payload_response(const struct http_response *resp,
				    void *context ATTR_UNUSED)
{
	test_client_assert_response(
		resp, resp->status == HTTP_CLIENT_REQUEST_ERROR_BROKEN_PAYLOAD);

	io_loop_stop(ioloop);
}

static bool
test_client_broken_payload(const struct http_client_settings *client_set)
{
	struct http_client_request *hreq;
	struct istream *input;

	test_expect_errors(1);

	http_client = http_client_init(client_set);

	input = i_stream_create_error_str(EIO, "Moehahahaha!!");
	i_stream_set_name(input, "PURE EVIL");

	hreq = http_client_request(
		http_client, "GET", net_ip2addr(&bind_ip),
		"/broken-payload.txt",
		test_client_broken_payload_response, NULL);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_set_payload(hreq, input, FALSE);
	http_client_request_submit(hreq);

	i_stream_unref(&input);
	return TRUE;	
}

/* test */

static void test_broken_payload(void)
{
	struct http_client_settings http_client_set;

	test_client_defaults(&http_client_set);

	test_begin("broken payload");
	test_run_client_server(&http_client_set,
			       test_client_broken_payload,
			       test_server_broken_payload, 1, NULL);
	test_end();
}

/*
 * Retry payload
 */

/* server */

struct _retry_payload_sctx {
	bool eoh;
};

static int test_retry_payload_init(struct server_connection *conn)
{
	struct _retry_payload_sctx *ctx;

	ctx = p_new(conn->pool, struct _retry_payload_sctx, 1);
	conn->context = ctx;
	return 0;
}

static void test_retry_payload_input(struct server_connection *conn)
{
	struct _retry_payload_sctx *ctx = conn->context;
	const char *line;

	while ((line = i_stream_read_next_line(conn->conn.input)) != NULL) {
		if (*line == '\0') {
			ctx->eoh = TRUE;
			continue;
		}
		if (ctx->eoh)
			break;
	}

	if (conn->conn.input->stream_errno != 0) {
		i_fatal("server: Stream error: %s",
			i_stream_get_error(conn->conn.input));
	}
	if (line == NULL) {
		if (conn->conn.input->eof)
			i_fatal("server: Client stream ended prematurely");
		return;
	}

	i_assert(ctx->eoh);

	if (strcmp(line, "This is the payload we expect.") == 0) {
		if (debug)
			i_debug("Expected payload received");
		o_stream_nsend_str(conn->conn.output,
				   "HTTP/1.1 500 Oh no!\r\n"
				   "Connection: close\r\n"
				   "Content-Length: 17\r\n"
				   "\r\n"
				   "Expected result\r\n");
	} else {
		i_error("Unexpected payload received: `%s'",
			str_sanitize(line, 128));
		o_stream_nsend_str(conn->conn.output,
				   "HTTP/1.1 501 Oh no!\r\n"
				   "Connection: close\r\n"
				   "Content-Length: 19\r\n"
				   "\r\n"
				   "Unexpected result\r\n");
	}
	server_connection_deinit(&conn);
}

static void test_server_retry_payload(unsigned int index)
{
	test_server_init = test_retry_payload_init;
	test_server_input = test_retry_payload_input;
	test_server_run(index);
}

/* client */

struct _retry_payload_ctx {
	unsigned int count;
};

struct _retry_payload_request_ctx {
	struct _retry_payload_ctx *ctx;
	struct http_client_request *req;
};

static void
test_client_retry_payload_response(const struct http_response *resp,
				   struct _retry_payload_request_ctx *rctx)
{
	struct _retry_payload_ctx *ctx = rctx->ctx;

	test_client_assert_response(resp, resp->status == 500);

	if (http_client_request_try_retry(rctx->req)) {
		if (debug)
			i_debug("retrying");
		return;
	}
	i_free(rctx);

	if (--ctx->count == 0) {
		i_free(ctx);
		io_loop_stop(ioloop);
	}
}

static bool
test_client_retry_payload(const struct http_client_settings *client_set)
{
	static const char payload[] = "This is the payload we expect.\r\n";
	struct _retry_payload_ctx *ctx;
	struct _retry_payload_request_ctx *rctx;
	struct http_client_request *hreq;
	struct istream *input;

	ctx = i_new(struct _retry_payload_ctx, 1);
	ctx->count = 1;

	http_client = http_client_init(client_set);

	input = i_stream_create_from_data(payload, sizeof(payload)-1);

	rctx = i_new(struct _retry_payload_request_ctx, 1);
	rctx->ctx = ctx;

	rctx->req = hreq = http_client_request(
		http_client, "GET", net_ip2addr(&bind_ip), "/retry-payload.txt",
		test_client_retry_payload_response, rctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_set_payload(hreq, input, FALSE);
	http_client_request_submit(hreq);

	i_stream_unref(&input);
	return TRUE;
}

/* test */

static void test_retry_payload(void)
{
	struct http_client_settings http_client_set;

	test_client_defaults(&http_client_set);
	http_client_set.max_attempts = 2;

	server_read_max = 0;

	test_begin("retry payload");
	test_run_client_server(&http_client_set,
			       test_client_retry_payload,
			       test_server_retry_payload, 1, NULL);
	test_end();
}

/*
 * Connection lost
 */

/* server */

static void test_connection_lost_input(struct server_connection *conn)
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
		i_assert(conn->conn.input->eof);
		if (conn->conn.input->stream_errno == 0)
			i_fatal("server: Client stream ended prematurely");
		else
			i_fatal("server: Stream error: %s",
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

struct _connection_lost_request_ctx {
	struct _connection_lost_ctx *ctx;
	struct http_client_request *req;
};

static void
test_client_connection_lost_response(const struct http_response *resp,
				     struct _connection_lost_request_ctx *rctx)
{
	struct _connection_lost_ctx *ctx = rctx->ctx;

	test_client_assert_response(
		resp,
		resp->status == HTTP_CLIENT_REQUEST_ERROR_CONNECTION_LOST);

	if (http_client_request_try_retry(rctx->req)) {
		if (debug)
			i_debug("retrying");
		return;
	}
	i_free(rctx);

	if (--ctx->count == 0) {
		i_free(ctx);
		io_loop_stop(ioloop);
	}
}

static bool
test_client_connection_lost(const struct http_client_settings *client_set)
{
	static const char payload[] =
		"This is a useless payload that only serves as a means to give "
		"the server the opportunity to close the connection before the "
		"payload is finished.";
	struct _connection_lost_ctx *ctx;
	struct _connection_lost_request_ctx *rctx;
	struct http_client_request *hreq;
	struct istream *input;

	ctx = i_new(struct _connection_lost_ctx, 1);
	ctx->count = 2;

	http_client = http_client_init(client_set);

	input = i_stream_create_from_data(payload, sizeof(payload)-1);

	rctx = i_new(struct _connection_lost_request_ctx, 1);
	rctx->ctx = ctx;

	rctx->req = hreq = http_client_request(
		http_client, "GET", net_ip2addr(&bind_ip),
		"/connection-lost.txt",
		test_client_connection_lost_response, rctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_set_payload(hreq, input, FALSE);
	http_client_request_submit(hreq);

	rctx = i_new(struct _connection_lost_request_ctx, 1);
	rctx->ctx = ctx;

	rctx->req = hreq = http_client_request(
		http_client, "GET", net_ip2addr(&bind_ip),
		"/connection-lost2.txt",
		test_client_connection_lost_response, rctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_submit(hreq);

	i_stream_unref(&input);
	return TRUE;
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
			       test_server_connection_lost, 1, NULL);
	test_end();

	test_begin("connection lost: two attempts");
	http_client_set.max_attempts = 2;
	test_run_client_server(&http_client_set,
			       test_client_connection_lost,
			       test_server_connection_lost, 1, NULL);
	test_end();

	test_begin("connection lost: three attempts");
	http_client_set.max_attempts = 3;
	test_run_client_server(&http_client_set,
			       test_client_connection_lost,
			       test_server_connection_lost, 1, NULL);
	test_end();

	test_begin("connection lost: manual retry");
	http_client_set.max_attempts = 3;
	http_client_set.no_auto_retry = TRUE;
	test_run_client_server(&http_client_set,
			       test_client_connection_lost,
			       test_server_connection_lost, 1, NULL);
	test_end();
}

/*
 * Connection lost after 100-continue
 */

/* server */

static void test_connection_lost_100_input(struct server_connection *conn)
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
test_client_connection_lost_100_response(const struct http_response *resp,
					 struct _connection_lost_100_ctx *ctx)
{
	test_client_assert_response(
		resp,
		resp->status == HTTP_CLIENT_REQUEST_ERROR_CONNECTION_LOST);

	if (--ctx->count == 0) {
		i_free(ctx);
		io_loop_stop(ioloop);
	}
}

static bool
test_client_connection_lost_100(
	const struct http_client_settings *client_set)
{
	static const char payload[] =
		"This is a useless payload that only serves as a means to give "
		"the server the opportunity to close the connection before the "
		"payload is finished.";
	struct _connection_lost_100_ctx *ctx;
	struct http_client_request *hreq;
	struct istream *input;

	ctx = i_new(struct _connection_lost_100_ctx, 1);
	ctx->count = 2;

	http_client = http_client_init(client_set);

	input = i_stream_create_from_data(payload, sizeof(payload)-1);

	hreq = http_client_request(
		http_client, "GET", net_ip2addr(&bind_ip),
		"/connection-lost.txt",
		test_client_connection_lost_100_response, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_set_payload(hreq, input, TRUE);
	http_client_request_submit(hreq);

	hreq = http_client_request(
		http_client, "GET", net_ip2addr(&bind_ip),
		"/connection-lost2.txt",
		test_client_connection_lost_100_response, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_set_payload(hreq, input, TRUE);
	http_client_request_submit(hreq);

	i_stream_unref(&input);
	return TRUE;
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
			       test_server_connection_lost_100, 1, NULL);
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
	const struct http_response *resp, struct ioloop *sub_ioloop)
{
	test_client_assert_response(
		resp,
		(resp->status == 200 ||
		 resp->status == HTTP_CLIENT_REQUEST_ERROR_CONNECTION_LOST));

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

	test_assert(resp->status == 200 ||
		    resp->status == HTTP_CLIENT_REQUEST_ERROR_CONNECTION_LOST);
	test_assert(resp->reason != NULL && *resp->reason != '\0');

	sub_ioloop = io_loop_create();
	http_client_switch_ioloop(http_client);

	hreq = http_client_request(
		http_client, "GET", net_ip2addr(&bind_ip),
		"/connection-lost-sub-ioloop3.txt",
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

static bool
test_client_connection_lost_sub_ioloop(
	const struct http_client_settings *client_set)
{
	static const char payload[] =
		"This is a useless payload that only serves as a means to give "
		"the server the opportunity to close the connection before the "
		"payload is finished.";
	struct _connection_lost_sub_ioloop_ctx *ctx;
	struct http_client_request *hreq;
	struct istream *input;

	ctx = i_new(struct _connection_lost_sub_ioloop_ctx, 1);
	ctx->count = 2;

	http_client = http_client_init(client_set);

	input = i_stream_create_from_data(payload, sizeof(payload)-1);

	hreq = http_client_request(
		http_client, "GET", net_ip2addr(&bind_ip),
		"/connection-lost-sub-ioloop.txt",
		test_client_connection_lost_sub_ioloop_response, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_set_payload(hreq, input, TRUE);
	http_client_request_submit(hreq);

	hreq = http_client_request(
		http_client, "GET", net_ip2addr(&bind_ip),
		"/connection-lost-sub-ioloop2.txt",
		test_client_connection_lost_sub_ioloop_response, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_set_payload(hreq, input, TRUE);
	http_client_request_submit(hreq);

	i_stream_unref(&input);
	return TRUE;
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
			       test_server_connection_lost_sub_ioloop, 2, NULL);
	test_end();
}

/*
 * Early success
 */

/* server */

static void test_early_success_input(struct server_connection *conn)
{
	static const char *resp =
		"HTTP/1.1 200 OK\r\n"
		"Content-Length: 18\r\n"
		"\r\n"
		"Everything is OK\r\n";

	i_sleep_msecs(200);
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
test_client_early_success_response(const struct http_response *resp,
				   struct _early_success_ctx *ctx)
{
	if (ctx->count == 2) {
		test_client_assert_response(
			resp,
			resp->status == HTTP_CLIENT_REQUEST_ERROR_BAD_RESPONSE);
	} else {
		test_client_assert_response(resp, resp->status == 200);
	}

	if (--ctx->count == 0) {
		io_loop_stop(ioloop);
		i_free(ctx);
	}
}

static bool
test_client_early_success(const struct http_client_settings *client_set)
{
	struct http_client_request *hreq;
	struct _early_success_ctx *ctx;
	string_t *payload;
	unsigned int i;

	ctx = i_new(struct _early_success_ctx, 1);
	ctx->count = 2;
	
	http_client = http_client_init(client_set);

	hreq = http_client_request(
		http_client, "GET", net_ip2addr(&bind_ip),
		"/early-success.txt",
		test_client_early_success_response, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);

	T_BEGIN {
		struct istream_chain *chain;
		struct istream *input, *chain_input;

		payload = t_str_new(64*3000);
		for (i = 0; i < 3000; i++) {
			str_append(payload,
				"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"
				"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
		}

		chain_input = i_stream_create_chain(&chain);

		input = i_stream_create_copy_from_data(str_data(payload),
						       str_len(payload));
		i_stream_chain_append(chain, input);
		i_stream_unref(&input);

		http_client_request_set_payload(hreq, chain_input, FALSE);
		i_stream_unref(&chain_input);
	} T_END;
	http_client_request_submit(hreq);

	hreq = http_client_request(
		http_client, "GET", net_ip2addr(&bind_ip),
		"/early-success2.txt",
		test_client_early_success_response, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_submit(hreq);

	return TRUE;
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
			       test_server_early_success, 1, NULL);
	test_end();
}

/*
 * Bad response
 */

/* server */

static void test_bad_response_input(struct server_connection *conn)
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
test_client_bad_response_response(const struct http_response *resp,
				  struct _bad_response_ctx *ctx)
{
	test_client_assert_response(
		resp, resp->status == HTTP_CLIENT_REQUEST_ERROR_BAD_RESPONSE);

	if (--ctx->count == 0) {
		i_free(ctx);
		io_loop_stop(ioloop);
	}
}

static bool
test_client_bad_response(const struct http_client_settings *client_set)
{
	struct http_client_request *hreq;
	struct _bad_response_ctx *ctx;

	ctx = i_new(struct _bad_response_ctx, 1);
	ctx->count = 2;

	http_client = http_client_init(client_set);

	hreq = http_client_request(
		http_client, "GET", net_ip2addr(&bind_ip),
		"/bad-response.txt",
		test_client_bad_response_response, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_submit(hreq);

	hreq = http_client_request(
		http_client, "GET", net_ip2addr(&bind_ip),
		"/bad-response2.txt",
		test_client_bad_response_response, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_submit(hreq);

	return TRUE;
}

/* test */

static void test_bad_response(void)
{
	struct http_client_settings http_client_set;

	test_client_defaults(&http_client_set);

	test_begin("bad response");
	test_run_client_server(&http_client_set,
			       test_client_bad_response,
			       test_server_bad_response, 1, NULL);
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

struct _request_timed_out1_ctx {
	unsigned int count;
};

static void
test_client_request_timed_out1_response(const struct http_response *resp,
					struct _request_timed_out1_ctx *ctx)
{
	test_client_assert_response(
		resp, resp->status == HTTP_CLIENT_REQUEST_ERROR_TIMED_OUT);

	if (--ctx->count == 0) {
		i_free(ctx);
		io_loop_stop(ioloop);
	}
}

static bool
test_client_request_timed_out1(const struct http_client_settings *client_set)
{
	struct http_client_request *hreq;
	struct _request_timed_out1_ctx *ctx;

	ctx = i_new(struct _request_timed_out1_ctx, 1);
	ctx->count = 2;

	http_client = http_client_init(client_set);

	hreq = http_client_request(
		http_client, "GET", net_ip2addr(&bind_ip),
		"/request-timed-out1-1.txt",
		test_client_request_timed_out1_response, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_submit(hreq);

	hreq = http_client_request(
		http_client, "GET", net_ip2addr(&bind_ip),
		"/request-timed-out1-2.txt",
		test_client_request_timed_out1_response, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_submit(hreq);

	return TRUE;
}

struct _request_timed_out2_ctx {
	struct timeout *to;
	unsigned int count;
	unsigned int max_parallel_connections;
};

static void
test_client_request_timed_out2_timeout(struct _request_timed_out2_ctx *ctx)
{
	timeout_remove(&ctx->to);
	i_debug("TIMEOUT");
}

static void
test_client_request_timed_out2_response(const struct http_response *resp,
					struct _request_timed_out2_ctx *ctx)
{
	test_client_assert_response(
		resp, resp->status == HTTP_CLIENT_REQUEST_ERROR_TIMED_OUT);
	test_assert(ctx->to != NULL);

	if (--ctx->count > 0) {
		if (ctx->to != NULL && ctx->max_parallel_connections <= 1)
			timeout_reset(ctx->to);
	} else {
		timeout_remove(&ctx->to);
		i_free(ctx);
		io_loop_stop(ioloop);
	}
}

static bool
test_client_request_timed_out2(const struct http_client_settings *client_set)
{
	struct http_client_request *hreq;
	struct _request_timed_out2_ctx *ctx;

	ctx = i_new(struct _request_timed_out2_ctx, 1);
	ctx->count = 2;
	ctx->max_parallel_connections =
		client_set->max_parallel_connections;

	ctx->to = timeout_add(2000,
		test_client_request_timed_out2_timeout, ctx);

	http_client = http_client_init(client_set);

	hreq = http_client_request(
		http_client, "GET", net_ip2addr(&bind_ip),
		"/request-timed-out2-1.txt",
		test_client_request_timed_out2_response, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_set_attempt_timeout_msecs(hreq, 1000);
	http_client_request_submit(hreq);

	hreq = http_client_request(
		http_client, "GET", net_ip2addr(&bind_ip),
		"/request-timed-out2-2.txt",
		test_client_request_timed_out2_response, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_set_attempt_timeout_msecs(hreq, 1000);
	http_client_request_submit(hreq);

	return TRUE;
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
			       test_client_request_timed_out1,
			       test_server_request_timed_out, 1, NULL);
	test_end();

	test_begin("request timed out: two attempts");
	http_client_set.request_timeout_msecs = 1000;
	http_client_set.max_attempts = 1;
	test_run_client_server(&http_client_set,
			       test_client_request_timed_out1,
			       test_server_request_timed_out, 1, NULL);
	test_end();

	test_begin("request absolutely timed out");
	http_client_set.request_timeout_msecs = 0;
	http_client_set.request_absolute_timeout_msecs = 2000;
	http_client_set.max_attempts = 3;
	test_run_client_server(&http_client_set,
			       test_client_request_timed_out1,
			       test_server_request_timed_out, 1, NULL);
	test_end();

	test_begin("request double timed out");
	http_client_set.request_timeout_msecs = 500;
	http_client_set.request_absolute_timeout_msecs = 2000;
	http_client_set.max_attempts = 3;
	test_run_client_server(&http_client_set,
			       test_client_request_timed_out1,
			       test_server_request_timed_out, 1, NULL);
	test_end();

	test_begin("request timed out: specific timeout");
	http_client_set.request_timeout_msecs = 3000;
	http_client_set.request_absolute_timeout_msecs = 0;
	http_client_set.max_attempts = 1;
	http_client_set.max_parallel_connections = 1;
	test_run_client_server(&http_client_set,
			       test_client_request_timed_out2,
			       test_server_request_timed_out, 1, NULL);
	test_end();

	test_begin("request timed out: specific timeout (parallel)");
	http_client_set.request_timeout_msecs = 3000;
	http_client_set.request_absolute_timeout_msecs = 0;
	http_client_set.max_attempts = 1;
	http_client_set.max_parallel_connections = 4;
	test_run_client_server(&http_client_set,
			       test_client_request_timed_out2,
			       test_server_request_timed_out, 1, NULL);
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

	/* wait one second to respond */
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
		ctx->to = timeout_add_short(
			1000, test_client_request_aborted_early_timeout, ctx);
	} else {
		/* all done */
		i_free(ctx);
		io_loop_stop(ioloop);
	}
}

static bool
test_client_request_aborted_early(const struct http_client_settings *client_set)
{
	struct http_client_request *hreq;
	struct _request_aborted_early_ctx *ctx;

	ctx = i_new(struct _request_aborted_early_ctx, 1);

	http_client = http_client_init(client_set);

	hreq = ctx->req1 = http_client_request(
		http_client, "GET", net_ip2addr(&bind_ip),
		"/request-aborted-early.txt",
		test_client_request_aborted_early_response, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_submit(hreq);

	hreq = ctx->req2 = http_client_request(
		http_client, "GET", net_ip2addr(&bind_ip),
		"/request-aborted-early2.txt",
		test_client_request_aborted_early_response, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_submit(hreq);

	ctx->to = timeout_add_short(
		500, test_client_request_aborted_early_timeout, ctx);
	return TRUE;
}

/* test */

static void test_request_aborted_early(void)
{
	struct http_client_settings http_client_set;

	test_client_defaults(&http_client_set);

	test_begin("request aborted early");
	test_run_client_server(&http_client_set,
			       test_client_request_aborted_early,
			       test_server_request_aborted_early, 1, NULL);
	test_end();
}

/*
 * Request failed blocking
 */

/* server */

static void
test_request_failed_blocking_input(struct server_connection *conn)
{
	static const char *resp =
		"HTTP/1.1 500 Internal Server Error\r\n"
		"\r\n";

	/* respond */
	o_stream_nsend_str(conn->conn.output, resp);
	sleep(10);
	server_connection_deinit(&conn);
}

static void test_server_request_failed_blocking(unsigned int index)
{
	test_server_input = test_request_failed_blocking_input;
	test_server_run(index);
}

/* client */

struct _request_failed_blocking_ctx {
	struct http_client_request *req;
};

static void
test_client_request_failed_blocking_response(
	const struct http_response *resp,
	struct _request_failed_blocking_ctx *ctx ATTR_UNUSED)
{
	test_client_assert_response(resp, resp->status == 500);
}

static bool
test_client_request_failed_blocking(
	const struct http_client_settings *client_set)
{
	static const char *payload = "This a test payload!";
	struct http_client_request *hreq;
	struct _request_failed_blocking_ctx *ctx;
	unsigned int n;
	string_t *data;

	data = str_new(default_pool, 1000000);
	for (n = 0; n < 50000; n++)
		str_append(data, payload);

	ctx = i_new(struct _request_failed_blocking_ctx, 1);

	http_client = http_client_init(client_set);

	hreq = ctx->req = http_client_request(
		http_client, "GET", net_ip2addr(&bind_ip),
		"/request-failed-blocking.txt",
		test_client_request_failed_blocking_response, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);

	test_assert(http_client_request_send_payload(&hreq,
		str_data(data), str_len(data)) < 0);
	i_assert(hreq == NULL);

	str_free(&data);
	i_free(ctx);
	return FALSE;
}

/* test */

static void test_request_failed_blocking(void)
{
	struct http_client_settings http_client_set;

	test_client_defaults(&http_client_set);
	http_client_set.socket_send_buffer_size = 4096;

	test_begin("request failed blocking");
	test_run_client_server(&http_client_set,
			       test_client_request_failed_blocking,
			       test_server_request_failed_blocking, 1, NULL);
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

	/* wait one second to respond */
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
test_client_client_deinit_early_timeout(struct _client_deinit_early_ctx *ctx)
{
	timeout_remove(&ctx->to);

	/* deinit early */
	http_client_deinit(&http_client);
	
	/* all done */
	i_free(ctx);
	io_loop_stop(ioloop);
}

static bool
test_client_client_deinit_early(const struct http_client_settings *client_set)
{
	struct http_client_request *hreq;
	struct _client_deinit_early_ctx *ctx;

	ctx = i_new(struct _client_deinit_early_ctx, 1);

	http_client = http_client_init(client_set);

	hreq = http_client_request(
		http_client, "GET", net_ip2addr(&bind_ip),
		"/client-deinit-early.txt",
		test_client_client_deinit_early_response, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_submit(hreq);

	hreq =  http_client_request(
		http_client, "GET", net_ip2addr(&bind_ip),
		"/client-deinit-early2.txt",
		test_client_client_deinit_early_response, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_submit(hreq);

	ctx->to = timeout_add_short(
		500, test_client_client_deinit_early_timeout, ctx);
	return TRUE;
}

/* test */

static void test_client_deinit_early(void)
{
	struct http_client_settings http_client_set;

	test_client_defaults(&http_client_set);

	test_begin("client deinit early");
	test_run_client_server(&http_client_set,
			       test_client_client_deinit_early,
			       test_server_client_deinit_early, 1, NULL);
	test_end();
}

/*
 * Retry with delay
 */

/* server */

static void test_retry_with_delay_input(struct server_connection *conn)
{
	string_t *resp;

	resp = t_str_new(512);
	str_printfa(resp,
		    "HTTP/1.1 500 Internal Server Error\r\n"
		    "\r\n");
	o_stream_nsend(conn->conn.output, str_data(resp), str_len(resp));
	server_connection_deinit(&conn);
}

static void test_server_retry_with_delay(unsigned int index)
{
	test_server_input = test_retry_with_delay_input;
	test_server_run(index);
}

/* client */

struct _client_retry_with_delay_ctx {
	struct http_client_request *req;
	unsigned int retries;
	struct timeval time;
};

static void
test_client_retry_with_delay_response(
	const struct http_response *resp,
	struct _client_retry_with_delay_ctx *ctx)
{
	int real_delay, exp_delay;

	test_client_assert_response(resp, resp->status == 500);

	if (ctx->retries > 0) {
		/* check delay */
		real_delay = timeval_diff_msecs(&ioloop_timeval, &ctx->time);
		exp_delay = (1 << (ctx->retries-1)) * 50;
		if (real_delay < exp_delay-2) {
			i_fatal("Retry delay is too short %d < %d",
				real_delay, exp_delay);
		}
	}

	http_client_request_delay_msecs(ctx->req, (1 << ctx->retries) * 50);
	ctx->time = ioloop_timeval;
	if (http_client_request_try_retry(ctx->req)) {
		ctx->retries++;
		if (debug)
			i_debug("retrying");
		return;
	}

	i_free(ctx);
	io_loop_stop(ioloop);
}

static bool
test_client_retry_with_delay(const struct http_client_settings *client_set)
{
	struct http_client_request *hreq;
	struct _client_retry_with_delay_ctx *ctx;

	ctx = i_new(struct _client_retry_with_delay_ctx, 1);
	ctx->time = ioloop_timeval;

	http_client = http_client_init(client_set);

	ctx->req = hreq = http_client_request(
		http_client, "GET", net_ip2addr(&bind_ip),
		"/retry-with-delay.txt",
		test_client_retry_with_delay_response, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_submit(hreq);

	return TRUE;
}

/* test */

static void test_retry_with_delay(void)
{
	struct http_client_settings http_client_set;

	test_client_defaults(&http_client_set);
	http_client_set.max_attempts = 3;

	test_begin("retry with delay");
	test_run_client_server(&http_client_set,
			       test_client_retry_with_delay,
			       test_server_retry_with_delay, 1, NULL);
	test_end();
}

/*
 * DNS service failure
 */

/* client */

struct _dns_service_failure {
	unsigned int count;
};

static void
test_client_dns_service_failure_response(
	const struct http_response *resp,
	struct _dns_service_failure *ctx)
{
	test_client_assert_response(
		resp,
		resp->status == HTTP_CLIENT_REQUEST_ERROR_HOST_LOOKUP_FAILED);

	if (--ctx->count == 0) {
		i_free(ctx);
		io_loop_stop(ioloop);
	}
}

static bool
test_client_dns_service_failure(const struct http_client_settings *client_set)
{
	struct http_client_request *hreq;
	struct _dns_service_failure *ctx;

	ctx = i_new(struct _dns_service_failure, 1);
	ctx->count = 2;

	http_client = http_client_init(client_set);

	hreq = http_client_request(
		http_client, "GET", "example.com", "/dns-service-failure.txt",
		test_client_dns_service_failure_response, ctx);
	http_client_request_set_port(hreq, 80);
	http_client_request_submit(hreq);

	hreq = http_client_request(
		http_client, "GET", "example.com", "/dns-service-failure2.txt",
		test_client_dns_service_failure_response, ctx);
	http_client_request_set_port(hreq, 80);
	http_client_request_submit(hreq);

	return TRUE;
}

/* test */

static void test_dns_service_failure(void)
{
	struct http_client_settings http_client_set;

	test_client_defaults(&http_client_set);
	http_client_set.dns_client_socket_path = "./frop";

	test_begin("dns service failure");
	test_run_client_server(&http_client_set,
			       test_client_dns_service_failure,
			       NULL, 0, NULL);
	test_end();
}

/*
 * DNS timeout
 */

/* dns */

static void test_dns_timeout_input(struct server_connection *conn ATTR_UNUSED)
{
	/* hang */
	sleep(100);
	server_connection_deinit(&conn);
}

static void test_dns_dns_timeout(void)
{
	test_server_input = test_dns_timeout_input;
	test_server_run(0);
}

/* client */

struct _dns_timeout {
	unsigned int count;
};

static void
test_client_dns_timeout_response(
	const struct http_response *resp,
	struct _dns_timeout *ctx)
{
	test_client_assert_response(
		resp,
		resp->status == HTTP_CLIENT_REQUEST_ERROR_HOST_LOOKUP_FAILED);

	if (--ctx->count == 0) {
		i_free(ctx);
		io_loop_stop(ioloop);
	}
}

static bool
test_client_dns_timeout(const struct http_client_settings *client_set)
{
	struct http_client_request *hreq;
	struct _dns_timeout *ctx;

	ctx = i_new(struct _dns_timeout, 1);
	ctx->count = 2;

	http_client = http_client_init(client_set);

	hreq = http_client_request(
		http_client, "GET", "example.com", "/dns-timeout.txt",
		test_client_dns_timeout_response, ctx);
	http_client_request_set_port(hreq, 80);
	http_client_request_submit(hreq);

	hreq = http_client_request(
		http_client, "GET", "example.com", "/dns-timeout2.txt",
		test_client_dns_timeout_response, ctx);
	http_client_request_set_port(hreq, 80);
	http_client_request_submit(hreq);

	return TRUE;
}

/* test */

static void test_dns_timeout(void)
{
	struct http_client_settings http_client_set;

	test_client_defaults(&http_client_set);
	http_client_set.request_timeout_msecs = 2000;
	http_client_set.connect_timeout_msecs = 2000;
	http_client_set.dns_client_socket_path = "./dns-test";

	test_begin("dns timeout");
	test_run_client_server(&http_client_set,
			       test_client_dns_timeout, NULL, 0,
			       test_dns_dns_timeout);
	test_end();
}

/*
 * DNS lookup failure
 */

/* dns */

static void
test_dns_lookup_failure_input(struct server_connection *conn)
{
	if (!conn->version_sent) {
	        conn->version_sent = TRUE;
	        o_stream_nsend_str(conn->conn.output, "VERSION\tdns\t1\t0\n");
	}

	o_stream_nsend_str(conn->conn.output,
			   t_strdup_printf("%d\tFAIL\n", EAI_FAIL));
	server_connection_deinit(&conn);
}

static void test_dns_dns_lookup_failure(void)
{
	test_server_input = test_dns_lookup_failure_input;
	test_server_run(0);
}

/* client */

struct _dns_lookup_failure {
	unsigned int count;
};

static void
test_client_dns_lookup_failure_response(const struct http_response *resp,
					struct _dns_lookup_failure *ctx)
{
	test_client_assert_response(
		resp,
		resp->status == HTTP_CLIENT_REQUEST_ERROR_HOST_LOOKUP_FAILED);

	if (--ctx->count == 0) {
		i_free(ctx);
		io_loop_stop(ioloop);
	}
}

static bool
test_client_dns_lookup_failure(const struct http_client_settings *client_set)
{
	struct http_client_request *hreq;
	struct _dns_lookup_failure *ctx;

	ctx = i_new(struct _dns_lookup_failure, 1);
	ctx->count = 2;

	http_client = http_client_init(client_set);

	hreq = http_client_request(
		http_client, "GET", "example.com", "/dns-lookup-failure.txt",
		test_client_dns_lookup_failure_response, ctx);
	http_client_request_set_port(hreq, 80);
	http_client_request_submit(hreq);

	hreq = http_client_request(
		http_client, "GET", "example.com", "/dns-lookup-failure2.txt",
		test_client_dns_lookup_failure_response, ctx);
	http_client_request_set_port(hreq, 80);
	http_client_request_submit(hreq);

	return TRUE;
}

/* test */

static void test_dns_lookup_failure(void)
{
	struct http_client_settings http_client_set;

	test_client_defaults(&http_client_set);
	http_client_set.dns_client_socket_path = "./dns-test";

	test_begin("dns lookup failure");
	test_run_client_server(&http_client_set,
			       test_client_dns_lookup_failure, NULL, 0,
			       test_dns_dns_lookup_failure);
	test_end();
}

/*
 * DNS lookup ttl
 */

/* dns */

static void
test_dns_lookup_ttl_input(struct server_connection *conn)
{
	static unsigned int count = 0;
	const char *line;

	if (!conn->version_sent) {
		conn->version_sent = TRUE;
		o_stream_nsend_str(conn->conn.output, "VERSION\tdns\t1\t0\n");
	}

	while ((line = i_stream_read_next_line(conn->conn.input)) != NULL) {
		if (str_begins(line, "VERSION"))
			continue;
		if (debug)
			i_debug("DNS REQUEST %u: %s", count, line);

		if (count == 0) {
			o_stream_nsend_str(conn->conn.output,
					   "0\t127.0.0.1\n");
		} else {
			o_stream_nsend_str(
				conn->conn.output,
				t_strdup_printf("%d\tFAIL\n", EAI_FAIL));
			if (count > 4) {
				server_connection_deinit(&conn);
				return;
			}
		}
		count++;
	}
}

static void test_dns_dns_lookup_ttl(void)
{
	test_server_input = test_dns_lookup_ttl_input;
	test_server_run(0);
}

/* server */

static void
test_server_dns_lookup_ttl_input(struct server_connection *conn)
{
	string_t *resp;

	resp = t_str_new(512);
	str_printfa(resp,
		    "HTTP/1.1 200 OK\r\n"
		    "Connection: close\r\n"
		    "\r\n");
	o_stream_nsend(conn->conn.output, str_data(resp), str_len(resp));
	server_connection_deinit(&conn);
}

static void test_server_dns_lookup_ttl(unsigned int index)
{
	test_server_input = test_server_dns_lookup_ttl_input;
	test_server_run(index);
}

/* client */

struct _dns_lookup_ttl {
	struct http_client *client;
	unsigned int count;
	struct timeout *to;
};

static void
test_client_dns_lookup_ttl_response_stage2(const struct http_response *resp,
					   struct _dns_lookup_ttl *ctx)
{
	test_client_assert_response(
		resp,
		resp->status == HTTP_CLIENT_REQUEST_ERROR_HOST_LOOKUP_FAILED);

	if (--ctx->count == 0) {
		i_free(ctx);
		io_loop_stop(ioloop);
	}
}

static void test_client_dns_lookup_ttl_stage2_start(struct _dns_lookup_ttl *ctx)
{
	struct http_client_request *hreq;

	timeout_remove(&ctx->to);

	ctx->count = 2;

	hreq = http_client_request(
		ctx->client, "GET", "example.com",
		"/dns-lookup-ttl-stage2.txt",
		test_client_dns_lookup_ttl_response_stage2, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_submit(hreq);

	hreq = http_client_request(
		ctx->client, "GET", "example.com",
		"/dns-lookup-ttl2-stage2.txt",
		test_client_dns_lookup_ttl_response_stage2, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_submit(hreq);
}

static void
test_client_dns_lookup_ttl_response_stage1(const struct http_response *resp,
					   struct _dns_lookup_ttl *ctx)
{
	test_client_assert_response(resp, resp->status == 200);

	if (--ctx->count == 0) {
		ctx->to = timeout_add(2000,
			test_client_dns_lookup_ttl_stage2_start, ctx);
	}
}

static bool
test_client_dns_lookup_ttl(const struct http_client_settings *client_set)
{
	struct http_client_request *hreq;
	struct _dns_lookup_ttl *ctx;

	ctx = i_new(struct _dns_lookup_ttl, 1);
	ctx->count = 2;

	ctx->client = http_client = http_client_init(client_set);

	hreq = http_client_request(
		ctx->client, "GET", "example.com",
		"/dns-lookup-ttl-stage1.txt",
		test_client_dns_lookup_ttl_response_stage1, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_submit(hreq);

	hreq = http_client_request(
		ctx->client, "GET", "example.com",
		"/dns-lookup-ttl2-stage1.txt",
		test_client_dns_lookup_ttl_response_stage1, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_submit(hreq);

	return TRUE;
}

/* test */

static void test_dns_lookup_ttl(void)
{
	struct http_client_settings http_client_set;

	test_client_defaults(&http_client_set);
	http_client_set.dns_client_socket_path = "./dns-test";
	http_client_set.dns_ttl_msecs = 1000;

	test_begin("dns lookup ttl");
	test_run_client_server(&http_client_set,
			       test_client_dns_lookup_ttl,
			       test_server_dns_lookup_ttl, 1,
			       test_dns_dns_lookup_ttl);
	test_end();
}

/*
 * Peer reuse failure
 */

/* server */

static void test_peer_reuse_failure_input(struct server_connection *conn)
{
	static unsigned int seq = 0;
	static const char *resp =
		"HTTP/1.1 200 OK\r\n"
		"\r\n";

	o_stream_nsend_str(conn->conn.output, resp);
	if (seq++ > 2) {
		server_connection_deinit(&conn);
		io_loop_stop(current_ioloop);
	}
}

static void test_server_peer_reuse_failure(unsigned int index)
{
	test_server_input = test_peer_reuse_failure_input;
	test_server_run(index);
}

/* client */

struct _peer_reuse_failure {
	struct timeout *to;
	bool first:1;
};

static void
test_client_peer_reuse_failure_response2(const struct http_response *resp,
					 struct _peer_reuse_failure *ctx)
{
	test_client_assert_response(
		resp, http_response_is_internal_error(resp));

	i_free(ctx);
	io_loop_stop(ioloop);
}

static void
test_client_peer_reuse_failure_next(struct _peer_reuse_failure *ctx)
{
	struct http_client_request *hreq;

	timeout_remove(&ctx->to);

	hreq = http_client_request(
		http_client, "GET", net_ip2addr(&bind_ip),
		"/peer-reuse-next.txt",
		test_client_peer_reuse_failure_response2, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_submit(hreq);
}

static void
test_client_peer_reuse_failure_response1(const struct http_response *resp,
					 struct _peer_reuse_failure *ctx)
{
	if (ctx->first) {
		test_client_assert_response(resp, resp->status == 200);

		ctx->first = FALSE;
		ctx->to = timeout_add_short(
			500, test_client_peer_reuse_failure_next, ctx);
	} else {
		test_client_assert_response(
			resp, http_response_is_internal_error(resp));
	}

	test_assert(resp->reason != NULL && *resp->reason != '\0');
}

static bool
test_client_peer_reuse_failure(const struct http_client_settings *client_set)
{
	struct http_client_request *hreq;
	struct _peer_reuse_failure *ctx;

	ctx = i_new(struct _peer_reuse_failure, 1);
	ctx->first = TRUE;

	http_client = http_client_init(client_set);

	hreq = http_client_request(
		http_client, "GET", net_ip2addr(&bind_ip), "/peer-reuse.txt",
		test_client_peer_reuse_failure_response1, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_submit(hreq);

	hreq = http_client_request(
		http_client, "GET", net_ip2addr(&bind_ip), "/peer-reuse.txt",
		test_client_peer_reuse_failure_response1, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_submit(hreq);

	hreq = http_client_request(
		http_client, "GET", net_ip2addr(&bind_ip), "/peer-reuse.txt",
		test_client_peer_reuse_failure_response1, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_submit(hreq);

	return TRUE;
}

/* test */

static void test_peer_reuse_failure(void)
{
	struct http_client_settings http_client_set;

	test_client_defaults(&http_client_set);
	http_client_set.max_connect_attempts = 1;
	http_client_set.max_idle_time_msecs = 500;

	test_begin("peer reuse failure");
	test_run_client_server(&http_client_set,
			       test_client_peer_reuse_failure,
			       test_server_peer_reuse_failure, 1, NULL);
	test_end();
}

/*
 * Reconnect failure
 */

/* dns */

static void test_dns_reconnect_failure_input(struct server_connection *conn)
{
	static unsigned int count = 0;
	const char *line;

	if (!conn->version_sent) {
	        conn->version_sent = TRUE;
	        o_stream_nsend_str(conn->conn.output, "VERSION\tdns\t1\t0\n");
	}

	while ((line = i_stream_read_next_line(conn->conn.input)) != NULL) {
		if (str_begins(line, "VERSION"))
			continue;
		if (debug)
			i_debug("DNS REQUEST %u: %s", count, line);

		if (count == 0) {
			o_stream_nsend_str(conn->conn.output,
					   "0\t127.0.0.1\n");
		} else {
			o_stream_nsend_str(
				conn->conn.output,
				t_strdup_printf("%d\tFAIL\n", EAI_FAIL));
			if (count > 4) {
				server_connection_deinit(&conn);
				return;
			}
		}
		count++;
	}
}

static void test_dns_reconnect_failure(void)
{
	test_server_input = test_dns_reconnect_failure_input;
	test_server_run(0);
}

/* server */

static void test_reconnect_failure_input(struct server_connection *conn)
{
	static const char *resp =
		"HTTP/1.1 200 OK\r\n"
		"Content-Length: 18\r\n"
		"\r\n"
		"Everything is OK\r\n";

	o_stream_nsend_str(conn->conn.output, resp);
	i_close_fd(&fd_listen);
	sleep(500);
}

static void test_server_reconnect_failure(unsigned int index)
{
	test_server_input = test_reconnect_failure_input;
	test_server_run(index);
}

/* client */

struct _reconnect_failure_ctx {
	struct timeout *to;
};

static void
test_client_reconnect_failure_response2(const struct http_response *resp,
					struct _reconnect_failure_ctx *ctx)
{
	test_client_assert_response(
		resp, resp->status == HTTP_CLIENT_REQUEST_ERROR_CONNECT_FAILED);

	io_loop_stop(ioloop);
	i_free(ctx);
}

static void
test_client_reconnect_failure_next(struct _reconnect_failure_ctx *ctx)
{
	struct http_client_request *hreq;

	if (debug)
		i_debug("NEXT REQUEST");

	timeout_remove(&ctx->to);

	hreq = http_client_request(
		http_client, "GET", "example.com", "/reconnect-failure-2.txt",
		test_client_reconnect_failure_response2, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_submit(hreq);
}

static void
test_client_reconnect_failure_response1(const struct http_response *resp,
					struct _reconnect_failure_ctx *ctx)
{
	test_client_assert_response(resp, resp->status == 200);

	ctx->to = timeout_add_short(
		5000, test_client_reconnect_failure_next, ctx);
}

static bool
test_client_reconnect_failure(const struct http_client_settings *client_set)
{
	struct http_client_request *hreq;
	struct _reconnect_failure_ctx *ctx;

	ctx = i_new(struct _reconnect_failure_ctx, 1);
	
	http_client = http_client_init(client_set);

	hreq = http_client_request(
		http_client, "GET", "example.com", "/reconnect-failure-1.txt",
		test_client_reconnect_failure_response1, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_submit(hreq);

	return TRUE;
}

/* test */

static void test_reconnect_failure(void)
{
	struct http_client_settings http_client_set;

	test_client_defaults(&http_client_set);
	http_client_set.dns_client_socket_path = "./dns-test";
	http_client_set.dns_ttl_msecs = 10000;
	http_client_set.max_idle_time_msecs = 1000;
	http_client_set.max_attempts = 1;
	http_client_set.request_timeout_msecs = 1000;

	test_begin("reconnect failure");
	test_run_client_server(&http_client_set,
			       test_client_reconnect_failure,
			       test_server_reconnect_failure, 1,
			       test_dns_reconnect_failure);
	test_end();
}

/*
 * Multi IP attempts
 */

/* dns */

static void test_multi_ip_attempts_input(struct server_connection *conn)
{
	unsigned int count = 0;
	const char *line;

	if (!conn->version_sent) {
		conn->version_sent = TRUE;
		o_stream_nsend_str(conn->conn.output, "VERSION\tdns\t1\t0\n");
	}

	while ((line = i_stream_read_next_line(conn->conn.input)) != NULL) {
		if (str_begins(line, "VERSION"))
			continue;
		if (debug)
			i_debug("DNS REQUEST %u: %s", count, line);

		if (strcmp(line, "IP\ttest1.local") == 0) {
			o_stream_nsend_str(conn->conn.output,
					   "0\t127.0.0.4\t127.0.0.3\t"
					   "127.0.0.2\t127.0.0.1\n");
			continue;
		}

		o_stream_nsend_str(conn->conn.output,
				   "0\t10.255.255.1\t192.168.0.0\t"
				   "192.168.255.255\t127.0.0.1\n");
	}
}

static void test_dns_multi_ip_attempts(void)
{
	test_server_input = test_multi_ip_attempts_input;
	test_server_run(0);
}

/* server */

static void test_server_multi_ip_attempts_input(struct server_connection *conn)
{
	string_t *resp;

	resp = t_str_new(512);
	str_printfa(resp,
		    "HTTP/1.1 200 OK\r\n"
		    "Connection: close\r\n"
		    "\r\n");
	o_stream_nsend(conn->conn.output, str_data(resp), str_len(resp));
	server_connection_deinit(&conn);
}

static void test_server_multi_ip_attempts(unsigned int index)
{
	test_server_input = test_server_multi_ip_attempts_input;
	test_server_run(index);
}

/* client */

struct _multi_ip_attempts {
	unsigned int count;
};

static void
test_client_multi_ip_attempts_response(const struct http_response *resp,
				       struct _multi_ip_attempts *ctx)
{
	test_client_assert_response(resp, resp->status == 200);

	if (--ctx->count == 0) {
		i_free(ctx);
		io_loop_stop(ioloop);
	}
}

static bool
test_client_multi_ip_attempts1(const struct http_client_settings *client_set)
{
	struct http_client_request *hreq;
	struct _multi_ip_attempts *ctx;

	ctx = i_new(struct _multi_ip_attempts, 1);
	ctx->count = 2;

	http_client = http_client_init(client_set);

	hreq = http_client_request(
		http_client, "GET", "test1.local", "/multi-ip-attempts.txt",
		test_client_multi_ip_attempts_response, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_submit(hreq);

	hreq = http_client_request(
		http_client, "GET", "test1.local", "/multi-ip-attempts2.txt",
		test_client_multi_ip_attempts_response, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_submit(hreq);

	return TRUE;
}

static bool
test_client_multi_ip_attempts2(const struct http_client_settings *client_set)
{
	struct http_client_request *hreq;
	struct _multi_ip_attempts *ctx;

	ctx = i_new(struct _multi_ip_attempts, 1);
	ctx->count = 2;

	http_client = http_client_init(client_set);

	hreq = http_client_request(
		http_client, "GET", "test2.local", "/multi-ip-attempts.txt",
		test_client_multi_ip_attempts_response, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_submit(hreq);

	hreq = http_client_request(
		http_client, "GET", "test2.local", "/multi-ip-attempts2.txt",
		test_client_multi_ip_attempts_response, ctx);
	http_client_request_set_port(hreq, bind_ports[0]);
	http_client_request_submit(hreq);

	return TRUE;
}

/* test */

static void test_multi_ip_attempts(void)
{
	struct http_client_settings http_client_set;

	test_client_defaults(&http_client_set);
	http_client_set.connect_timeout_msecs = 1000;
	http_client_set.request_timeout_msecs = 1000;
	http_client_set.dns_client_socket_path = "./dns-test";
	http_client_set.max_connect_attempts = 4;

	test_begin("multi IP attempts (connection refused)");
	test_run_client_server(&http_client_set,
			       test_client_multi_ip_attempts1,
			       test_server_multi_ip_attempts, 1,
			       test_dns_multi_ip_attempts);
	test_end();

	test_begin("multi IP attempts (connect timeout)");
	test_run_client_server(&http_client_set,
			       test_client_multi_ip_attempts2,
			       test_server_multi_ip_attempts, 1,
			       test_dns_multi_ip_attempts);
	test_end();

	http_client_set.soft_connect_timeout_msecs = 100;

	test_begin("multi IP attempts (soft connect timeout)");
	test_run_client_server(&http_client_set,
			       test_client_multi_ip_attempts2,
			       test_server_multi_ip_attempts, 1,
			       test_dns_multi_ip_attempts);
	test_end();
}

/*
 * All tests
 */

static void (*const test_functions[])(void) = {
	test_unconfigured_ssl,
	test_unconfigured_ssl_abort,
	test_invalid_url,
	test_host_lookup_failed,
	test_connection_refused,
	test_connection_lost_prematurely,
	test_connection_timed_out,
	test_invalid_redirect,
	test_unseekable_redirect,
	test_unseekable_retry,
	test_broken_payload,
	test_retry_payload,
	test_connection_lost,
	test_connection_lost_100,
	test_connection_lost_sub_ioloop,
	test_early_success,
	test_bad_response,
	test_request_timed_out,
	test_request_aborted_early,
	test_request_failed_blocking,
	test_client_deinit_early,
	test_retry_with_delay,
	test_dns_service_failure,
	test_dns_timeout,
	test_dns_lookup_failure,
	test_dns_lookup_ttl,
	test_peer_reuse_failure,
	test_reconnect_failure,
	test_multi_ip_attempts,
	NULL
};

/*
 * Test client
 */

static void test_client_defaults(struct http_client_settings *http_set)
{
	/* client settings */
	i_zero(http_set);
	http_set->max_idle_time_msecs = 5*1000;
	http_set->max_parallel_connections = 1;
	http_set->max_pipelined_requests = 1;
	http_set->max_redirects = 0;
	http_set->max_attempts = 1;
	http_set->debug = debug;
}

static void test_client_progress_timeout(void *context ATTR_UNUSED)
{
	/* Terminate test due to lack of progress */
	test_assert(FALSE);
	timeout_remove(&to_client_progress);
	io_loop_stop(current_ioloop);
}

static bool
test_client_init(test_client_init_t client_test,
		 const struct http_client_settings *client_set)
{
	i_assert(client_test != NULL);
	if (!client_test(client_set))
		return FALSE;

	to_client_progress = timeout_add(CLIENT_PROGRESS_TIMEOUT*1000,
					 test_client_progress_timeout, NULL);
	return TRUE;
}

static void test_client_deinit(void)
{
	timeout_remove(&to_client_progress);

	if (http_client != NULL)
		http_client_deinit(&http_client);
}

static void
test_client_run(test_client_init_t client_test,
		const struct http_client_settings *client_set)
{
	if (test_client_init(client_test, client_set))
		io_loop_run(ioloop);
	test_client_deinit();
}

/*
 * Test server
 */

/* client connection */

static void server_connection_input(struct connection *_conn)
{
	struct server_connection *conn = (struct server_connection *)_conn;
	
	test_server_input(conn);
}

static void server_connection_init(int fd)
{
	struct server_connection *conn;
	pool_t pool;

	net_set_nonblock(fd, TRUE);

	pool = pool_alloconly_create("server connection", 512);
	conn = p_new(pool, struct server_connection, 1);
	conn->pool = pool;

	connection_init_server(server_conn_list, &conn->conn,
			       "server connection", fd, fd);

	if (test_server_init != NULL) {
		if (test_server_init(conn) != 0)
			return;
	}
}

static void server_connection_deinit(struct server_connection **_conn)
{
	struct server_connection *conn = *_conn;

	*_conn = NULL;

	if (test_server_deinit != NULL)
		test_server_deinit(conn);

	connection_deinit(&conn->conn);
	pool_unref(&conn->pool);
}

static void server_connection_destroy(struct connection *_conn)
{
	struct server_connection *conn = (struct server_connection *)_conn;

	server_connection_deinit(&conn);
}

static void server_connection_accept(void *context ATTR_UNUSED)
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
	io_listen = io_add(fd_listen, IO_READ, server_connection_accept, NULL);

	server_conn_list = connection_list_init(&server_connection_set,
						&server_connection_vfuncs);

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

	if (dns_pid != (pid_t)-1) {
		(void)kill(dns_pid, SIGKILL);
		(void)waitpid(dns_pid, NULL, 0);
		dns_pid = (pid_t)-1;
	}
}

static void
test_run_client_server(const struct http_client_settings *client_set,
		       test_client_init_t client_test,
		       test_server_init_t server_test,
		       unsigned int server_tests_count,
		       test_dns_init_t dns_test)
{
	unsigned int i;

	server_pids = NULL;
	server_pids_count = 0;

	test_server_init = NULL;
	test_server_deinit = NULL;
	test_server_input = NULL;

	lib_signals_ioloop_detach();

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
				lib_signals_deinit();
				/* child: server */
				i_set_failure_prefix("SERVER[%u]: ", i + 1);
				if (debug)
					i_debug("PID=%s", my_pid);
				ioloop = io_loop_create();
				server_test(i);
				io_loop_destroy(&ioloop);
				i_close_fd(&fd_listen);
				i_free(bind_ports);
				i_free(server_pids);
				/* wait for it to be killed; this way, valgrind
				   will not object to this process going away
				   inelegantly. */
				sleep(60);
				exit(1);
			}
			i_close_fd(&fd_listen);
		}
	}

	if (dns_test != NULL) {
		int fd;

		i_unlink_if_exists("./dns-test");
		fd = net_listen_unix("./dns-test", 128);
		if (fd == -1) {
			i_fatal("listen(./dns-test) failed: %m");
		}

		fd_listen = fd;
		if ((dns_pid = fork()) == (pid_t)-1)
			i_fatal("fork() failed: %m");
		if (dns_pid == 0) {
			dns_pid = (pid_t)-1;
			hostpid_init();
			lib_signals_deinit();
			/* child: server */
			i_set_failure_prefix("DNS: ");
			if (debug)
				i_debug("PID=%s", my_pid);
			ioloop = io_loop_create();
			dns_test();
			io_loop_destroy(&ioloop);
			i_close_fd(&fd_listen);
			/* wait for it to be killed; this way, valgrind will not
			   object to this process going away inelegantly. */
			sleep(60);
			exit(1);
		}
		i_close_fd(&fd_listen);
	}

	lib_signals_ioloop_attach();

	/* parent: client */
	i_set_failure_prefix("CLIENT: ");
	if (debug)
		i_debug("PID=%s", my_pid);

	i_sleep_msecs(100); /* wait a little for server setup */

	ioloop = io_loop_create();
	test_client_run(client_test, client_set);
	io_loop_destroy(&ioloop);

	i_unset_failure_prefix();
	test_servers_kill_all();
	i_free(server_pids);
	i_free(bind_ports);

	i_unlink_if_exists("./dns-test");
}

/*
 * Main
 */

volatile sig_atomic_t terminating = 0;

static void test_signal_handler(const siginfo_t *si, void *context ATTR_UNUSED)
{
	int signo = si->si_signo;

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
	int ret;

	lib_init();
	lib_signals_init();

	atexit(test_atexit);
	lib_signals_ignore(SIGPIPE, TRUE);
	lib_signals_set_handler(SIGTERM, 0, test_signal_handler, NULL);
	lib_signals_set_handler(SIGQUIT, 0, test_signal_handler, NULL);
	lib_signals_set_handler(SIGINT, 0, test_signal_handler, NULL);
	lib_signals_set_handler(SIGSEGV, 0, test_signal_handler, NULL);
	lib_signals_set_handler(SIGABRT, 0, test_signal_handler, NULL);

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
	i_zero(&bind_ip);
	bind_ip.family = AF_INET;
	bind_ip.u.ip4.s_addr = htonl(INADDR_LOOPBACK);	

	ret = test_run(test_functions);

	lib_signals_deinit();
	lib_deinit();

	return ret;
}
