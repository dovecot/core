/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
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
#include "master-service.h"
#include "master-service-settings.h"
#include "iostream-ssl.h"
#include "iostream-ssl-test.h"
#include "iostream-openssl.h"
#include "http-client.h"
#include "test-common.h"
#include "test-subprocess.h"
#include "http-client.h"
#include "dlua-script-private.h"

#include <unistd.h>
#include <sys/signal.h>

#define CLIENT_PROGRESS_TIMEOUT     10
#define SERVER_KILL_TIMEOUT_SECS    20

static void main_deinit(void);

/*
 * Types
 */

struct server_connection {
	struct connection conn;
	void *context;

	struct ssl_iostream *ssl_iostream;
	struct istream *real_input;
	struct ostream *real_output;

	pool_t pool;
	bool version_sent:1;
};

typedef void (*test_server_init_t)(unsigned int index);
typedef bool (*test_client_init_t)(void);
typedef void (*test_dns_init_t)(void);

/*
 * State
 */

/* common */
static struct ip_addr bind_ip;
static in_port_t *bind_ports = 0;
static struct ioloop *ioloop;
static bool debug = FALSE;
static struct event *test_event;

/* server */
static struct io *io_listen;
static int fd_listen = -1;
static struct connection_list *server_conn_list;
static unsigned int server_index;
struct ssl_iostream_context *server_ssl_ctx = NULL;
bool test_server_ssl = FALSE;
static int (*test_server_init)(struct server_connection *conn);
static void (*test_server_deinit)(struct server_connection *conn);
static void (*test_server_input)(struct server_connection *conn);

/* client */
static struct timeout *to_client_progress = NULL;

/*
 * Forward declarations
 */

/* server */
static void test_server_run(unsigned int index);
static void server_connection_deinit(struct server_connection **_conn);

/* client */
static void test_client_deinit(void);

/* test*/
static void
test_run_client_server(test_client_init_t client_test,
		       test_server_init_t server_test,
		       unsigned int server_tests_count,
		       test_dns_init_t dns_test) ATTR_NULL(3);

/*
 * Simple post
 */

/* dns */

static void
test_dns_simple_post_input(struct server_connection *conn)
{
	const char *line;

	if (!conn->version_sent) {
		conn->version_sent = TRUE;
		o_stream_nsend_str(conn->conn.output, "VERSION\tdns\t1\t0\n");
	}

	while ((line = i_stream_read_next_line(conn->conn.input)) != NULL) {
		if (str_begins_with(line, "VERSION"))
			continue;
		e_debug(test_event, "DNS REQUEST: %s", line);

		if (strcmp(line, "IP\thosta") == 0) {
			o_stream_nsend_str(conn->conn.output,
					   "0\t127.0.0.1\n");
		} else {
			i_sleep_msecs(300);
			o_stream_nsend_str(
				conn->conn.output,
				t_strdup_printf("%d\tFAIL\n", EAI_FAIL));
		}
	}
}

static void test_dns_simple_post(void)
{
	test_server_input = test_dns_simple_post_input;
	test_server_run(0);
}

/* server */

struct _simple_post_sctx {
	struct timeout *to;
	bool serviced:1;
	bool eoh:1;
	bool agent_checked:1;
	bool post_checked:1;
};

static int test_server_simple_post_init(struct server_connection *conn)
{
	struct _simple_post_sctx *ctx;

	ctx = p_new(conn->pool, struct _simple_post_sctx, 1);
	conn->context = ctx;
	return 0;
}

static void
test_server_simple_post_disconnect(struct server_connection *conn)
{
	struct _simple_post_sctx *ctx = conn->context;

	timeout_remove(&ctx->to);
	server_connection_deinit(&conn);
}

static void test_server_simple_post_input(struct server_connection *conn)
{
	struct _simple_post_sctx *ctx = conn->context;
	const char *line;

	if (ctx->serviced) {
		/* Wait for disconnect or beginning of next request */
		ssize_t sret = i_stream_read(conn->conn.input);
		if (sret > 0 || conn->conn.input->eof)
			server_connection_deinit(&conn);
		return;
	}

	while ((line = i_stream_read_next_line(conn->conn.input)) != NULL) {
		const char *agent;
		if (*line == '\0') {
			ctx->eoh = TRUE;
			o_stream_nsend_str(conn->conn.output, "HTTP/1.1 100 OK\r\n\r\n");
			return;
		}
		if (!ctx->post_checked) {
			test_assert(str_begins_with(line, "POST /"));
			ctx->post_checked = TRUE;
		}
		if (!ctx->agent_checked && str_begins(line, "User-Agent: ", &agent)) {
			test_assert_strcmp(agent, "dovecot/unit-test");
			ctx->agent_checked = TRUE;
		}
		if (strcmp(line, "some+foolish+payload+for+funsies") == 0)
			break;
	}

	if (conn->conn.input->stream_errno != 0) {
		i_fatal("server: Stream error: %s",
			i_stream_get_error(conn->conn.input));
	}
	if (line == NULL) {
		if (conn->conn.input->eof)
			server_connection_deinit(&conn);
		return;
	}

	test_assert(ctx->post_checked);
	test_assert(ctx->agent_checked);
	i_assert(ctx->eoh);
	ctx->eoh = FALSE;

	static const char json_response[] =
	"{\n"
	"\"access_token\":\"MTQ0NjJkZmQ5OTM2NDE1ZTZjNGZmZjI3\",\n"
	"\"token_type\":\"Bearer\",\n"
	"\"expires_in\":3600,\n"
	"\"refresh_token\":\"IwOGYzYTlmM2YxOTQ5MGE3YmNmMDFkNTVk\",\n"
	"\"scope\":\"create\"\n"
	"}";

	string_t *resp = t_str_new(512);
	str_printfa(resp,
		    "HTTP/1.1 200 OK\r\n"
		    "Content-Length: %zu\r\n"
		    "\r\n"
		    "%s", sizeof(json_response) - 1, json_response);
	o_stream_nsend(conn->conn.output, str_data(resp), str_len(resp));
	if (o_stream_flush(conn->conn.output) < 0) {
		i_fatal("server: Flush error: %s",
			o_stream_get_error(conn->conn.output));
	}

	ctx->serviced = TRUE;
	ctx->to = timeout_add(
		5000, test_server_simple_post_disconnect, conn);
}

static void test_server_simple_post_deinit(struct server_connection *conn)
{
	struct _simple_post_sctx *ctx = conn->context;

	timeout_remove(&ctx->to);
}

static void test_server_simple_post(unsigned int index)
{
	test_server_init = test_server_simple_post_init;
	test_server_input = test_server_simple_post_input;
	test_server_deinit = test_server_simple_post_deinit;
	test_server_run(index);
}

/* client */

static void
test_client_simple_post_run_post(struct dlua_script *script, const char *url)
{
	const char *error;
	int ret;

	lua_pushstring(script->L, url);
	if (dlua_pcall(script->L, "http_request_post", 1, 1, &error) < 0)
		i_fatal("dlua_pcall() failed: %s", error);

	test_assert(lua_isinteger(script->L, -1));
	if (lua_isinteger(script->L, -1)) {
		ret = lua_tointeger(script->L, -1);
		/* not guaranteed to fail, but it will happen often */
		e_debug(test_event, "http_request_post() returned %d", ret);
		test_assert(ret == 0);
	}

	lua_pop(script->L, 1);
	i_assert(lua_gettop(script->L) == 0);
}

static bool test_client_simple_post(void)
{
	struct dlua_script *script;
	const char *error;

	if (event_want_debug(test_event))
		test_expect_errors(4);

	if (dlua_script_create_file(
		TEST_LUA_SCRIPT_DIR "/test-lua-http-client.lua",
		&script, test_event, &error) < 0)
		i_fatal("dlua_script_create_file() failed: %s", error);

	dlua_dovecot_register(script);
	if (dlua_script_init(script, &error) < 0)
		i_fatal("dlua_script_init() failed: %s", error);

	/* First POST */
	test_client_simple_post_run_post(
		script, t_strdup_printf("http%s://hosta:%u/first-post",
					test_server_ssl ? "s" : "",
					bind_ports[0]));

	/* Second POST */
	test_client_simple_post_run_post(
		script, t_strdup_printf("http%s://hosta:%u/second-post",
					test_server_ssl ? "s" : "",
					bind_ports[0]));

	dlua_script_unref(&script);

	return TRUE;
}

static bool test_client_second_post(void)
{
	struct dlua_script *script;
	const char *error;

	if (event_want_debug(test_event))
		test_expect_errors(4);

	if (dlua_script_create_file(
		TEST_LUA_SCRIPT_DIR "/test-lua-http-client.lua",
		&script, test_event, &error) < 0)
		i_fatal("dlua_script_create_file() failed: %s", error);

	dlua_dovecot_register(script);
	if (dlua_script_init(script, &error) < 0)
		i_fatal("dlua_script_init() failed: %s", error);

	/* First POST */
	test_client_simple_post_run_post(
		script, t_strdup_printf("http%s://hosta:%u/first-post",
					(test_server_ssl ? "s" : ""),
					bind_ports[0]));

	/* Second POST */
	test_client_simple_post_run_post(
		script, t_strdup_printf("http%s://hosta:%u/second-post",
					(test_server_ssl ? "s" : ""),
					bind_ports[0]));

	dlua_script_unref(&script);

	return TRUE;
}

/* test */

static void test_simple_post(void)
{
	test_begin("simple post");
	test_server_ssl = FALSE;
	test_run_client_server(test_client_simple_post,
			       test_server_simple_post, 1,
			       test_dns_simple_post);
	test_end();

	test_begin("simple post (ssl)");
	test_server_ssl = TRUE;
	test_run_client_server(test_client_simple_post,
			       test_server_simple_post, 1,
			       test_dns_simple_post);
	test_end();
}

static void test_second_post(void)
{
	test_begin("second post");
	test_server_ssl = FALSE;
	test_run_client_server(test_client_second_post,
			       test_server_simple_post, 1,
			       test_dns_simple_post);
	test_end();

	test_begin("second post (ssl)");
	test_server_ssl = TRUE;
	test_run_client_server(test_client_second_post,
			       test_server_simple_post, 1,
			       test_dns_simple_post);
	test_end();

}

static void test_bad_settings(void)
{
	struct dlua_script *script;
	const char *error;

	test_begin("bad settings");

	if (event_want_debug(test_event))
		test_expect_errors(4);

	if (dlua_script_create_file(
		TEST_LUA_SCRIPT_DIR "/test-lua-http-client.lua",
		&script, test_event, &error) < 0)
		i_fatal("dlua_script_create_file() failed: %s", error);

	dlua_dovecot_register(script);
	if (dlua_script_init(script, &error) < 0)
		i_fatal("dlua_script_init() failed: %s", error);

	int ret = dlua_pcall(script->L, "test_invalid_set_name", 0, 0, &error);
	test_assert(ret < 0);
	error = t_strcut(error, '\n');
	/* check the error is there */
	test_assert_strcmp(error, "lua_pcall(test_invalid_set_name, 0, 0) failed: "
				  "Invalid HTTP client setting: timeout is unknown setting");

	ret = dlua_pcall(script->L, "test_invalid_set_value_1", 0, 0, &error);
	test_assert(ret < 0);
	error = t_strcut(error, '\n');
	test_assert_strcmp(error, "lua_pcall(test_invalid_set_value_1, 0, 0) failed: "
				  "Invalid HTTP client setting: auto_retry=cow: Invalid boolean value: cow (use yes or no)");

	ret = dlua_pcall(script->L, "test_invalid_set_value_2", 0, 0, &error);
	test_assert(ret < 0);
	error = t_strcut(error, '\n');
	test_assert_strcmp(error, "lua_pcall(test_invalid_set_value_2, 0, 0) failed: "
				  "Invalid HTTP client setting: request_max_attempts=three: Invalid number three: Not a valid number");

	/* This needs a bit more roundabout way to check this as SSL settings
	   are lazily evaluated. */
	test_assert(dlua_pcall(script->L, "test_invalid_set_value_3", 0, 0, &error) == 0);
	lua_pushstring(script->L, "https://localhost");
	test_assert(dlua_pcall(script->L, "http_request_post", 1, 2, &error) == 2);
	error = lua_tostring(script->L, 2);
	test_assert_strcmp(error, "Couldn't initialize SSL client context: Can't set minimum protocol to 'cow' (ssl_min_protocol setting): Unknown value");

	dlua_script_unref(&script);

	test_end();
}

/*
 * All tests
 */

static void (*const test_functions[])(void) = {
	test_simple_post,
	test_second_post,
	test_bad_settings,
	NULL
};

/*
 * Test client
 */

static void test_client_progress_timeout(void *context ATTR_UNUSED)
{
	/* Terminate test due to lack of progress */
	test_assert(FALSE);
	timeout_remove(&to_client_progress);
	io_loop_stop(current_ioloop);
}

static bool
test_client_init(test_client_init_t client_test)
{
	i_assert(client_test != NULL);
	if (!client_test())
		return FALSE;

	to_client_progress = timeout_add(CLIENT_PROGRESS_TIMEOUT*1000,
					 test_client_progress_timeout, NULL);
	return TRUE;
}

static void test_client_deinit(void)
{
	timeout_remove(&to_client_progress);
	http_client_global_context_free();
}

static void test_client_run(test_client_init_t client_test)
{
	test_client_init(client_test);
	test_client_deinit();
}

/*
 * Test server
 */

/* client connection */

static int
server_connection_init_ssl(struct server_connection *conn)
{
	struct ssl_iostream_settings ssl_set;
	const char *error;

	if (!test_server_ssl)
		return 0;

	connection_input_halt(&conn->conn);

	ssl_iostream_test_settings_server(&ssl_set);

	if (server_ssl_ctx == NULL &&
	    ssl_iostream_context_init_server(&ssl_set, &server_ssl_ctx,
					     &error) < 0) {
		i_error("SSL context initialization failed: %s", error);
		return -1;
	}

	if (io_stream_create_ssl_server(server_ssl_ctx, conn->conn.event,
					&conn->conn.input, &conn->conn.output,
					&conn->ssl_iostream, &error) < 0) {
		i_error("SSL init failed: %s", error);
		return -1;
	}
	if (ssl_iostream_handshake(conn->ssl_iostream) < 0) {
		i_error("SSL handshake failed: %s",
			ssl_iostream_get_last_error(conn->ssl_iostream));
		return -1;
	}

	connection_input_resume(&conn->conn);
	return 0;
}

static void server_connection_input(struct connection *_conn)
{
	struct server_connection *conn =
		container_of(_conn, struct server_connection, conn);

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

	conn->real_input = conn->conn.input;
	conn->real_output = conn->conn.output;
	if (server_connection_init_ssl(conn) < 0) {
		server_connection_deinit(&conn);
		return;
	}

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

	ssl_iostream_destroy(&conn->ssl_iostream);
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
	if (fd == -2)
		i_fatal("test server: accept() failed: %m");

	server_connection_init(fd);
}

/* */

static struct connection_settings server_connection_set = {
	.input_max_size = SIZE_MAX,
	.output_max_size = SIZE_MAX,
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

	ssl_iostream_context_unref(&server_ssl_ctx);
}

/*
 * Tests
 */

struct test_server_data {
	unsigned int index;
	test_server_init_t server_test;
};

static int test_open_server_fd(in_port_t *bind_port)
{
	int fd = net_listen(&bind_ip, bind_port, 128);

	e_debug(test_event, "server listening on %u", *bind_port);
	if (fd == -1) {
		i_fatal("listen(%s:%u) failed: %m",
			net_ip2addr(&bind_ip), *bind_port);
	}
	return fd;
}

static int test_run_server(struct test_server_data *data)
{
	i_set_failure_prefix("SERVER[%u]: ", data->index + 1);

	e_debug(test_event, "PID=%s", my_pid);

	server_ssl_ctx = NULL;

	test_subprocess_notify_signal_send_parent(SIGHUP);
	ioloop = io_loop_create();
	data->server_test(data->index);
	io_loop_destroy(&ioloop);

	e_debug(test_event, "Terminated");

	i_close_fd(&fd_listen);
	i_free(bind_ports);
	event_unref(&test_event);
	main_deinit();
	master_service_deinit_forked(&master_service);
	return 0;
}

static int test_run_dns(test_dns_init_t dns_test)
{
	test_server_ssl = FALSE;

	i_set_failure_prefix("DNS: ");

	e_debug(test_event, "PID=%s", my_pid);

	test_subprocess_notify_signal_send_parent(SIGHUP);
	ioloop = io_loop_create();
	dns_test();
	io_loop_destroy(&ioloop);

	e_debug(test_event, "Terminated");

	i_close_fd(&fd_listen);
	i_free(bind_ports);
	event_unref(&test_event);
	main_deinit();
	master_service_deinit_forked(&master_service);
	return 0;
}

static void test_run_client(test_client_init_t client_test)
{
	i_set_failure_prefix("CLIENT: ");

	e_debug(test_event, "PID=%s", my_pid);

	ioloop = io_loop_create();
	test_client_run(client_test);
	io_loop_destroy(&ioloop);

	e_debug(test_event, "Terminated");
}

static void
test_run_client_server(test_client_init_t client_test,
		       test_server_init_t server_test,
		       unsigned int server_tests_count,
		       test_dns_init_t dns_test)
{
	unsigned int i;

	test_server_init = NULL;
	test_server_deinit = NULL;
	test_server_input = NULL;

	if (server_tests_count > 0) {
		int fds[server_tests_count];

		bind_ports = i_new(in_port_t, server_tests_count);
		for (i = 0; i < server_tests_count; i++)
			fds[i] = test_open_server_fd(&bind_ports[i]);

		for (i = 0; i < server_tests_count; i++) {
			struct test_server_data data;

			i_zero(&data);
			data.index = i;
			data.server_test = server_test;

			/* Fork server */
			fd_listen = fds[i];
			test_subprocess_notify_signal_reset(SIGHUP);
			test_subprocess_fork(test_run_server, &data, FALSE);
			test_subprocess_notify_signal_wait(
				SIGHUP, TEST_SIGNALS_DEFAULT_TIMEOUT_MS);
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

		/* Fork DNS service */
		fd_listen = fd;
		test_subprocess_notify_signal_reset(SIGHUP);
		test_subprocess_fork(test_run_dns, dns_test, FALSE);
		test_subprocess_notify_signal_wait(
			SIGHUP, TEST_SIGNALS_DEFAULT_TIMEOUT_MS);
		i_close_fd(&fd_listen);
	}

	/* Run client */
	test_run_client(client_test);

	i_unset_failure_prefix();
	test_subprocess_kill_all(SERVER_KILL_TIMEOUT_SECS);
	i_free(bind_ports);

	i_unlink_if_exists("./dns-test");
	http_client_global_context_free();
}

/*
 * Main
 */

static void main_init(void)
{
	ssl_iostream_openssl_init();
}

static void main_deinit(void)
{
	ssl_iostream_context_cache_free();
	ssl_iostream_openssl_deinit();
}

int main(int argc, char *argv[])
{
	const enum master_service_flags service_flags =
		MASTER_SERVICE_FLAG_NO_CONFIG_SETTINGS |
		MASTER_SERVICE_FLAG_STANDALONE |
		MASTER_SERVICE_FLAG_STD_CLIENT |
		MASTER_SERVICE_FLAG_DONT_SEND_STATS;
	const char *error;
	int c;
	int ret;

	while ((c = getopt(argc, argv, "D")) > 0) {
		switch (c) {
		case 'D':
			debug = TRUE;
			break;
		default:
			i_fatal("Usage: %s [-D]", argv[0]);
		}
	}

	master_service = master_service_init("test-lua-http-client",
					     service_flags, &argc, &argv, "");
	master_service_parse_option(
		master_service, 'o', "ssl_client_require_valid_cert=no");
	if (master_service_settings_read_simple(master_service, &error) < 0)
		i_fatal("Error reading configuration: %s", error);

	main_init();

	master_service_init_finish(master_service);

	test_subprocesses_init(debug);

	/* listen on localhost */
	i_zero(&bind_ip);
	bind_ip.family = AF_INET;
	bind_ip.u.ip4.s_addr = htonl(INADDR_LOOPBACK);

	test_event = event_create(NULL);
	event_set_forced_debug(test_event, debug);

	ret = test_run(test_functions);

	event_unref(&test_event);

	test_subprocesses_deinit();
	main_deinit();
	master_service_deinit(&master_service);

	return ret;
}
