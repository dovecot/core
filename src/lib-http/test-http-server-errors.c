/* Copyright (c) 2016-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "hostpid.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "time-util.h"
#include "connection.h"
#include "test-common.h"
#include "http-url.h"
#include "http-request.h"
#include "http-server.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>

#define SERVER_MAX_TIMEOUT_MSECS 10*1000

/*
 * Types
 */

struct client_connection {
	struct connection conn;

	pool_t pool;
};

typedef void (*test_server_init_t)
	(const struct http_server_settings *server_set);
typedef void (*test_client_init_t)(unsigned int index);

/*
 * State
 */

/* common */
static struct ip_addr bind_ip;
static in_port_t bind_port = 0;
static struct ioloop *ioloop;
static bool debug = FALSE;

/* server */
static struct http_server *http_server = NULL;
static struct io *io_listen;
static int fd_listen = -1;
static void (*test_server_request)(struct http_server_request *req);

/* client */
static pid_t *client_pids = NULL;
static struct connection_list *client_conn_list;
static unsigned int client_pids_count = 0;
static unsigned int client_index;
static void (*test_client_connected)(struct client_connection *conn);
static void (*test_client_input)(struct client_connection *conn);

/*
 * Forward declarations
 */

/* server */
static void
test_server_defaults(struct http_server_settings *http_set);
static void
test_server_run(const struct http_server_settings *http_set);

/* client */
static void test_client_run(unsigned int index);

/* test*/
static void test_run_client_server(
	const struct http_server_settings *server_set,
	test_server_init_t server_test,
	test_client_init_t client_test,
	unsigned int client_tests_count)
	ATTR_NULL(3);

/*
 * Slow request
 */

/* client */

static void
test_slow_request_input(struct client_connection *conn ATTR_UNUSED)
{
	/* do nothing */
}

static void
test_slow_request_connected(struct client_connection *conn)
{
	o_stream_nsend_str(conn->conn.output,
		"GET / HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"\r\n");
}

static void test_client_slow_request(unsigned int index)
{
	test_client_input = test_slow_request_input;
	test_client_connected = test_slow_request_connected;
	test_client_run(index);
}

/* server */

struct _slow_request {
	struct http_server_request *req;
	struct timeout *to_delay;
	bool serviced:1;
};

static void
test_server_slow_request_destroyed(struct _slow_request *ctx)
{
	test_assert(ctx->serviced);
	timeout_remove(&ctx->to_delay);
	i_free(ctx);
	io_loop_stop(ioloop);
}

static void
test_server_slow_request_delayed(struct _slow_request *ctx)
{
	struct http_server_response *resp;
	struct http_server_request *req = ctx->req;

	resp = http_server_response_create(req, 200, "OK");
	http_server_response_submit(resp);
	ctx->serviced = TRUE;

	http_server_request_unref(&req);
}

static void
test_server_slow_request_request(
	struct http_server_request *req)
{
	const struct http_request *hreq =
		http_server_request_get(req);
	struct _slow_request *ctx;

	if (debug) {
		i_debug("REQUEST: %s %s HTTP/%u.%u",
			hreq->method, hreq->target_raw,
			hreq->version_major, hreq->version_minor);
	}

	ctx = i_new(struct _slow_request, 1);
	ctx->req = req;

	http_server_request_set_destroy_callback(req,
		test_server_slow_request_destroyed, ctx);

	http_server_request_ref(req);
	ctx->to_delay = timeout_add
		(4000, test_server_slow_request_delayed, ctx);
}

static void test_server_slow_request
(const struct http_server_settings *server_set)
{
	test_server_request = test_server_slow_request_request;
	test_server_run(server_set);
}

/* test */

static void test_slow_request(void)
{
	struct http_server_settings http_server_set;

	test_server_defaults(&http_server_set);
	http_server_set.max_client_idle_time_msecs = 1000;

	test_begin("slow request");
	test_run_client_server(&http_server_set,
		test_server_slow_request,
		test_client_slow_request, 1);
	test_end();
}

/*
 * Hanging request payload
 */

/* client */

static void
test_hanging_request_payload_connected(struct client_connection *conn)
{
	o_stream_nsend_str(conn->conn.output,
		"GET / HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"Content-Length: 1000\r\n"
		"\r\n"
		"To be continued... or not");
}

static void test_client_hanging_request_payload(unsigned int index)
{
	test_client_connected = test_hanging_request_payload_connected;
	test_client_run(index);
}

/* server */

struct _hanging_request_payload {
	struct http_server_request *req;
	struct istream *payload_input;
	struct io *io;
	bool serviced:1;
};

static void
test_server_hanging_request_payload_destroyed(struct _hanging_request_payload *ctx)
{
	test_assert(!ctx->serviced);
	io_remove(&ctx->io);
	i_free(ctx);
	io_loop_stop(ioloop);
}

static void
test_server_hanging_request_payload_input(struct _hanging_request_payload *ctx)
{
	struct http_server_response *resp;
	struct http_server_request *req = ctx->req;
	const unsigned char *data;
	size_t size;
	int ret;

	if (debug)
		i_debug("test server: got more payload");

	while ((ret=i_stream_read_data
		(ctx->payload_input, &data, &size, 0)) > 0) {
		i_stream_skip(ctx->payload_input, size);
	}

	if (ret == 0)
		return;
	if (ctx->payload_input->stream_errno != 0) {
		if (debug) {
			i_debug("test server: failed to read payload: %s",
				i_stream_get_error(ctx->payload_input));
		}
		i_stream_unref(&ctx->payload_input);
		io_remove(&ctx->io);
		http_server_request_fail_close(req,
			400, "Bad request");
		http_server_request_unref(&req);
		return;
	}

	i_assert(ctx->payload_input->eof);
		
	resp = http_server_response_create(req, 200, "OK");
	http_server_response_submit(resp);
	ctx->serviced = TRUE;

	i_stream_unref(&ctx->payload_input);
	http_server_request_unref(&req);
}

static void
test_server_hanging_request_payload_request(
	struct http_server_request *req)
{
	const struct http_request *hreq =
		http_server_request_get(req);
	struct _hanging_request_payload *ctx;

	if (debug) {
		i_debug("REQUEST: %s %s HTTP/%u.%u",
			hreq->method, hreq->target_raw,
			hreq->version_major, hreq->version_minor);
	}

	ctx = i_new(struct _hanging_request_payload, 1);
	ctx->req = req;

	http_server_request_set_destroy_callback(req,
		test_server_hanging_request_payload_destroyed, ctx);

	ctx->payload_input =
		http_server_request_get_payload_input(req, FALSE);

	http_server_request_ref(req);
	ctx->io = io_add_istream(ctx->payload_input,
		test_server_hanging_request_payload_input, ctx);
	test_server_hanging_request_payload_input(ctx);
}

static void test_server_hanging_request_payload
(const struct http_server_settings *server_set)
{
	test_server_request = test_server_hanging_request_payload_request;
	test_server_run(server_set);
}

/* test */

static void test_hanging_request_payload(void)
{
	struct http_server_settings http_server_set;

	test_server_defaults(&http_server_set);
	http_server_set.max_client_idle_time_msecs = 1000;

	test_begin("hanging request payload");
	test_run_client_server(&http_server_set,
		test_server_hanging_request_payload,
		test_client_hanging_request_payload, 1);
	test_end();
}

/*
 * Hanging response payload
 */

/* client */

static void
test_hanging_response_payload_connected(struct client_connection *conn)
{
	o_stream_nsend_str(conn->conn.output,
		"GET / HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"Content-Length: 18\r\n"
		"\r\n"
		"Complete payload\r\n");
}

static void test_client_hanging_response_payload(unsigned int index)
{
	test_client_connected = test_hanging_response_payload_connected;
	test_client_run(index);
}

/* server */

struct _hanging_response_payload {
	struct http_server_request *req;
	struct istream *payload_input;
	struct io *io;
	bool serviced:1;
};

static void
test_server_hanging_response_payload_destroyed(struct _hanging_response_payload *ctx)
{
	test_assert(!ctx->serviced);
	io_remove(&ctx->io);
	i_free(ctx);
	io_loop_stop(ioloop);
}

static void
test_server_hanging_response_payload_request(
	struct http_server_request *req)
{
	const struct http_request *hreq =
		http_server_request_get(req);
	struct http_server_response *resp;
	struct _hanging_response_payload *ctx;
	string_t *payload;
	unsigned int i;

	if (debug) {
		i_debug("REQUEST: %s %s HTTP/%u.%u",
			hreq->method, hreq->target_raw,
			hreq->version_major, hreq->version_minor);
	}

	ctx = i_new(struct _hanging_response_payload, 1);
	ctx->req = req;

	http_server_request_set_destroy_callback(req,
		test_server_hanging_response_payload_destroyed, ctx);

	resp = http_server_response_create(req, 200, "OK");
	T_BEGIN {
		payload = t_str_new(204800);
		for (i = 0; i < 3200; i++) {
			str_append(payload,
				"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"
				"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
		}

		http_server_response_set_payload_data
			(resp, str_data(payload), str_len(payload));
	} T_END;
	http_server_response_submit(resp);
}

static void test_server_hanging_response_payload
(const struct http_server_settings *server_set)
{
	test_server_request = test_server_hanging_response_payload_request;
	test_server_run(server_set);
}

/* test */

static void test_hanging_response_payload(void)
{
	struct http_server_settings http_server_set;

	test_server_defaults(&http_server_set);
	http_server_set.socket_send_buffer_size = 4096;
	http_server_set.max_client_idle_time_msecs = 1000;

	test_begin("hanging response payload");
	test_run_client_server(&http_server_set,
		test_server_hanging_response_payload,
		test_client_hanging_response_payload, 1);
	test_end();
}

/*
 * Excessive payload length
 */

/* client */

static void
test_excessive_payload_length_connected1(struct client_connection *conn)
{
	o_stream_nsend_str(conn->conn.output,
		"GET / HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"Content-Length: 150\r\n"
		"\r\n"
		"Too long\r\nToo long\r\nToo long\r\nToo long\r\nToo long\r\n"
		"Too long\r\nToo long\r\nToo long\r\nToo long\r\nToo long\r\n"
		"Too long\r\nToo long\r\nToo long\r\nToo long\r\nToo long\r\n");
}

static void
test_client_excessive_payload_length1(unsigned int index)
{
	test_client_connected = test_excessive_payload_length_connected1;
	test_client_run(index);
}

static void
test_excessive_payload_length_connected2(struct client_connection *conn)
{
	o_stream_nsend_str(conn->conn.output,
		"GET / HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"Transfer-Encoding: chunked\r\n"
		"\r\n"
		"32\r\n"
		"Too long\r\nToo long\r\nToo long\r\nToo long\r\nToo long\r\n"
		"\r\n"
		"32\r\n"
		"Too long\r\nToo long\r\nToo long\r\nToo long\r\nToo long\r\n"
		"\r\n"
		"32\r\n"
		"Too long\r\nToo long\r\nToo long\r\nToo long\r\nToo long\r\n"
		"\r\n"
		"0\r\n"
		"\r\n");
}

static void
test_client_excessive_payload_length2(unsigned int index)
{
	test_client_connected = test_excessive_payload_length_connected2;
	test_client_run(index);
}


/* server */

struct _excessive_payload_length {
	struct http_server_request *req;
	buffer_t *buffer;
	bool serviced:1;
};

static void
test_server_excessive_payload_length_destroyed(
	struct _excessive_payload_length *ctx)
{
	struct http_server_response *resp;
	const char *reason;
	int status;

	resp = http_server_request_get_response(ctx->req);
	test_assert(resp != NULL);
	if (resp != NULL) {
		http_server_response_get_status(resp, &status, &reason);
		test_assert(status == 413);
	}

	test_assert(!ctx->serviced);
	buffer_free(&ctx->buffer);
	i_free(ctx);
	io_loop_stop(ioloop);
}

static void
test_server_excessive_payload_length_finished(
	struct _excessive_payload_length *ctx)
{
	struct http_server_response *resp;

	resp = http_server_response_create(ctx->req, 200, "OK");
	http_server_response_submit(resp);
	ctx->serviced = TRUE;
}

static void
test_server_excessive_payload_length_request(
	struct http_server_request *req)
{
	const struct http_request *hreq =
		http_server_request_get(req);
	struct _excessive_payload_length *ctx;

	if (debug) {
		i_debug("REQUEST: %s %s HTTP/%u.%u",
			hreq->method, hreq->target_raw,
			hreq->version_major, hreq->version_minor);
	}

	ctx = i_new(struct _excessive_payload_length, 1);
	ctx->req = req;
	ctx->buffer = buffer_create_dynamic(default_pool, 128);

	http_server_request_set_destroy_callback(req,
		test_server_excessive_payload_length_destroyed, ctx);
	http_server_request_buffer_payload(req,	ctx->buffer, 128,
		test_server_excessive_payload_length_finished, ctx);
}

static void test_server_excessive_payload_length
(const struct http_server_settings *server_set)
{
	test_server_request = test_server_excessive_payload_length_request;
	test_server_run(server_set);
}

/* test */

static void test_excessive_payload_length(void)
{
	struct http_server_settings http_server_set;

	test_server_defaults(&http_server_set);
	http_server_set.max_client_idle_time_msecs = 1000;

	test_begin("excessive payload length (length)");
	test_run_client_server(&http_server_set,
		test_server_excessive_payload_length,
		test_client_excessive_payload_length1, 1);
	test_end();

	test_begin("excessive payload length (chunked)");
	test_run_client_server(&http_server_set,
		test_server_excessive_payload_length,
		test_client_excessive_payload_length2, 1);
	test_end();
}

/*
 * All tests
 */

static void (*const test_functions[])(void) = {
	test_slow_request,
	test_hanging_request_payload,
	test_hanging_response_payload,
	test_excessive_payload_length,
	NULL
};

/*
 * Test client
 */

/* client connection */

static void
client_connection_input(struct connection *_conn)
{
	struct client_connection *conn = (struct client_connection *)_conn;
	
	if (test_client_input != NULL)
		test_client_input(conn);
}

static void
client_connection_connected(struct connection *_conn, bool success)
{
	struct client_connection *conn = (struct client_connection *)_conn;

	if (success && test_client_connected != NULL)
		test_client_connected(conn);
}

static void
client_connection_init(const struct ip_addr *ip, in_port_t port)
{
	struct client_connection *conn;
	pool_t pool;

	pool = pool_alloconly_create("client connection", 256);
	conn = p_new(pool, struct client_connection, 1);
	conn->pool = pool;

	connection_init_client_ip(client_conn_list,
		&conn->conn, ip, port);
	(void)connection_client_connect(&conn->conn);
}

static void
server_connection_deinit(struct client_connection **_conn)
{
	struct client_connection *conn = *_conn;

	*_conn = NULL;

	connection_deinit(&conn->conn);
	pool_unref(&conn->pool);
}

static void
client_connection_destroy(struct connection *_conn)
{
	struct client_connection *conn =
		(struct client_connection *)_conn;

	server_connection_deinit(&conn);
}

/* */

static struct connection_settings client_connection_set = {
	.input_max_size = (size_t)-1,
	.output_max_size = (size_t)-1,
	.client = TRUE
};

static const struct connection_vfuncs client_connection_vfuncs = {
	.destroy = client_connection_destroy,
	.client_connected = client_connection_connected,
	.input = client_connection_input
};

static void test_client_run(unsigned int index)
{
	client_index = index;

	if (debug)
		i_debug("client connecting to %u", bind_port);

	client_conn_list = connection_list_init
		(&client_connection_set, &client_connection_vfuncs);

	client_connection_init(&bind_ip, bind_port);

	io_loop_run(ioloop);

	/* close server socket */
	io_remove(&io_listen);

	connection_list_deinit(&client_conn_list);
}

/*
 * Test server
 */

static void
test_server_defaults(struct http_server_settings *http_set)
{
	/* server settings */
	i_zero(http_set);
	http_set->max_client_idle_time_msecs = 5*1000;
	http_set->max_pipelined_requests = 1;
	http_set->debug = debug;
}

/* client connection */

static void
server_handle_request(void *context ATTR_UNUSED,
	struct http_server_request *req)
{
	test_server_request(req);
}

struct http_server_callbacks http_server_callbacks = {
	.handle_request = server_handle_request
};

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

	(void)http_server_connection_create(http_server, fd, fd, FALSE,
		&http_server_callbacks, NULL);
}

/* */

static void
test_server_timeout(void *context ATTR_UNUSED)
{
	i_fatal("Server timed out");
}

static void
test_server_run(const struct http_server_settings *http_set)
{
	struct timeout *to;

	to = timeout_add(SERVER_MAX_TIMEOUT_MSECS,
		test_server_timeout, NULL);

	/* open server socket */
	io_listen = io_add(fd_listen,
		IO_READ, server_connection_accept, NULL);

	http_server = http_server_init(http_set);

	io_loop_run(ioloop);

	/* close server socket */
	io_remove(&io_listen);
	timeout_remove(&to);

	http_server_deinit(&http_server);
}

/*
 * Tests
 */

static int test_open_server_fd(void)
{
	int fd = net_listen(&bind_ip, &bind_port, 128);
	if (debug)
		i_debug("server listening on %u", bind_port);
	if (fd == -1) {
		i_fatal("listen(%s:%u) failed: %m",
			net_ip2addr(&bind_ip), bind_port);
	}
	return fd;
}

static void test_clients_kill_all(void)
{
	unsigned int i;

	if (client_pids_count > 0) {
		for (i = 0; i < client_pids_count; i++) {
			if (client_pids[i] != (pid_t)-1) {
				(void)kill(client_pids[i], SIGKILL);
				(void)waitpid(client_pids[i], NULL, 0);
				client_pids[i] = -1;
			}
		}
	}
	client_pids_count = 0;
}

static void test_run_client_server(
	const struct http_server_settings *server_set,
	test_server_init_t server_test,
	test_client_init_t client_test,
	unsigned int client_tests_count)
{
	unsigned int i;

	client_pids = NULL;
	client_pids_count = 0;

	fd_listen = test_open_server_fd();

	if (client_tests_count > 0) {
		client_pids = i_new(pid_t, client_tests_count);
		for (i = 0; i < client_tests_count; i++)
			client_pids[i] = (pid_t)-1;
		client_pids_count = client_tests_count;

		for (i = 0; i < client_tests_count; i++) {
			if ((client_pids[i] = fork()) == (pid_t)-1)
				i_fatal("fork() failed: %m");
			if (client_pids[i] == 0) {
				client_pids[i] = (pid_t)-1;
				client_pids_count = 0;
				hostpid_init();
				if (debug)
					i_debug("client[%d]: PID=%s", i+1, my_pid);
				/* child: client */
				usleep(100000); /* wait a little for server setup */
				i_close_fd(&fd_listen);
				ioloop = io_loop_create();
				client_test(i);
				io_loop_destroy(&ioloop);
				i_free(client_pids);
				/* wait for it to be killed; this way, valgrind will not
				   object to this process going away inelegantly. */
				sleep(60);
				exit(1);
			}
		}
		if (debug)
			i_debug("server: PID=%s", my_pid);
	}

	/* parent: server */

	ioloop = io_loop_create();
	server_test(server_set);
	io_loop_destroy(&ioloop);

	i_close_fd(&fd_listen);

	test_clients_kill_all();
	i_free(client_pids);
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
	test_clients_kill_all();

	(void)signal(signo, SIG_DFL);
	raise(signo);
}

static void test_atexit(void)
{
	test_clients_kill_all();
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
	i_zero(&bind_ip);
	bind_ip.family = AF_INET;
	bind_ip.u.ip4.s_addr = htonl(INADDR_LOOPBACK);	

	test_run(test_functions);
}
