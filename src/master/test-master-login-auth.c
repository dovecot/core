/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "lib-signals.h"
#include "str.h"
#include "strescape.h"
#include "hostpid.h"
#include "ioloop.h"
#include "istream.h"
#include "istream-chain.h"
#include "ostream.h"
#include "time-util.h"
#include "unlink-directory.h"
#include "write-full.h"
#include "randgen.h"
#include "connection.h"
#include "master-service.h"
#include "master-interface.h"
#include "test-common.h"

#include "master-auth.h"
#include "master-login-auth.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>

#define TEST_SOCKET "./master-login-auth-test"

/*
 * Types
 */

struct server_connection {
	struct connection conn;

	void *context;

	pool_t pool;
};

typedef void test_server_init_t(void);
typedef bool test_client_init_t(void);

/*
 * State
 */

/* common */
static struct ioloop *ioloop;
static bool debug = FALSE;

/* server */
static struct io *io_listen;
static int fd_listen = -1;
static pid_t server_pid;
static struct connection_list *server_conn_list;
static void (*test_server_input)(struct server_connection *conn);
static void (*test_server_init)(struct server_connection *conn);
static void (*test_server_deinit)(struct server_connection *conn);

/* client */

/*
 * Forward declarations
 */

/* server */
static void test_server_run(void);
static void server_connection_deinit(struct server_connection **_conn);

/* client */
static void test_client_deinit(void);

static int
test_client_request_parallel(pid_t client_pid, unsigned int concurrency,
			     bool retry, const char **error_r);
static int
test_client_request_simple(pid_t client_pid, bool retry, const char **error_r);

/* test*/
static void
test_run_client_server(test_client_init_t *client_test,
		       test_server_init_t *server_test) ATTR_NULL(2);

/*
 * Connection refused
 */

/* server */

static void test_server_connection_refused(void)
{
	i_close_fd(&fd_listen);
}

/* client */

static bool test_client_connection_refused(void)
{
	const char *error;
	int ret;

	ret = test_client_request_simple(2323, FALSE, &error);
	test_out("run (ret == -1)", ret == -1);
	test_assert(error != NULL &&
		    strstr(error, "Internal error occurred.") != NULL);

	return FALSE;
}

/* test */

static void test_connection_refused(void)
{
	test_begin("connection refused");
	test_expect_error_string_n_times("Connection refused", 2);
	test_run_client_server(test_client_connection_refused,
			       test_server_connection_refused);
	test_end();
}

/*
 * Connection timed out
 */

/* server */

static void test_connection_timed_out_input(struct server_connection *conn)
{
	sleep(5);
	server_connection_deinit(&conn);
}

static void test_server_connection_timed_out(void)
{
	test_server_input = test_connection_timed_out_input;
	test_server_run();
}

/* client */

static bool test_client_connection_timed_out(void)
{
	time_t time;
	const char *error;
	int ret;

	io_loop_time_refresh();
	time = ioloop_time;

	ret = test_client_request_simple(2323, FALSE, &error);
	test_out("run (ret == -1)", ret == -1);
	test_assert(error != NULL &&
		    strstr(error, "Internal error occurred.") != NULL);

	io_loop_time_refresh();
	test_out("timeout", (ioloop_time - time) < 5);
	return FALSE;
}

/* test */

static void test_connection_timed_out(void)
{
	test_begin("connection timed out");
	test_expect_error_string("Auth server request timed out");
	test_run_client_server(test_client_connection_timed_out,
			       test_server_connection_timed_out);
	test_end();
}

/*
 * Bad VERSION
 */

/* server */

static void test_bad_version_input(struct server_connection *conn)
{
	server_connection_deinit(&conn);
}

static void test_bad_version_init(struct server_connection *conn)
{
	o_stream_nsend_str(conn->conn.output, "VERSION\t666\t666\n");
	o_stream_nsend_str(conn->conn.output, "SPID\t23234\n");
}

static void test_server_bad_version(void)
{
	test_server_init = test_bad_version_init;
	test_server_input = test_bad_version_input;
	test_server_run();
}

/* client */

static bool test_client_bad_version(void)
{
	const char *error;
	int ret;

	ret = test_client_request_simple(2323, FALSE, &error);
	test_out("run (ret == -1)", ret == -1);
	test_assert(error != NULL &&
		    strstr(error, "Internal error occurred.") != NULL);

	return FALSE;
}

/* test */

static void test_bad_version(void)
{
	test_begin("bad version");
	test_expect_errors(2);
	test_run_client_server(test_client_bad_version,
			       test_server_bad_version);
	test_end();
}

/*
 * Disconnect VERSION
 */

/* server */

static void test_disconnect_version_input(struct server_connection *conn)
{
	const char *line;

	line = i_stream_read_next_line(conn->conn.input);
	if (line == NULL) {
		if (conn->conn.input->eof)
			server_connection_deinit(&conn);
		return;
	}
	server_connection_deinit(&conn);
}

static void test_disconnect_version_init(struct server_connection *conn)
{
	o_stream_nsend_str(conn->conn.output, "VERSION\t1\t0\n");
	o_stream_nsend_str(conn->conn.output, "SPID\t23234\n");
}

static void test_server_disconnect_version(void)
{
	test_server_init = test_disconnect_version_init;
	test_server_input = test_disconnect_version_input;
	test_server_run();
}

/* client */

static bool test_client_disconnect_version(void)
{
	const char *error;
	int ret;

	ret = test_client_request_simple(2323, FALSE, &error);
	test_out("run (ret == -1)", ret == -1);
	test_assert(error != NULL &&
		    strstr(error, "Internal error occurred.") != NULL);

	return FALSE;
}

/* test */

static void test_disconnect_version(void)
{
	test_begin("disconnect version");
	test_expect_error_string("Disconnected from auth server");
	test_run_client_server(test_client_disconnect_version,
			       test_server_disconnect_version);
	test_end();
}

/*
 * Changed SPID
 */

/* server */

static void test_changed_spid_input(struct server_connection *conn)
{
	const char *line;

	line = i_stream_read_next_line(conn->conn.input);
	if (line == NULL) {
		if (conn->conn.input->eof)
			server_connection_deinit(&conn);
		return;
	}
	server_connection_deinit(&conn);
}

static void test_changed_spid_init(struct server_connection *conn)
{
	o_stream_nsend_str(conn->conn.output, "VERSION\t1\t0\n");
	o_stream_nsend_str(conn->conn.output, "SPID\t35341\n");
}

static void test_server_changed_spid(void)
{
	test_server_init = test_changed_spid_init;
	test_server_input = test_changed_spid_input;
	test_server_run();
}

/* client */

static bool test_client_changed_spid(void)
{
	const char *error;
	int ret;

	ret = test_client_request_simple(2323, FALSE, &error);
	test_out("run (ret == -1)", ret == -1);
	test_assert(error != NULL &&
		    strstr(error, "Internal error occurred.") != NULL);

	return FALSE;
}

/* test */

static void test_changed_spid(void)
{
	test_begin("changed spid");
	test_expect_errors(2);
	test_run_client_server(test_client_changed_spid,
			       test_server_changed_spid);
	test_end();
}

/*
 * REQUEST FAIL
 */

/* server */

enum _request_fail_state {
	REQUEST_FAIL_STATE_VERSION = 0,
	REQUEST_FAIL_STATE_REQUEST
};

struct _request_fail_server {
	enum _request_fail_state state;

	bool not_found:1;
};

static void test_request_fail_input(struct server_connection *conn)
{
	struct _request_fail_server *ctx =
		(struct _request_fail_server *)conn->context;
	const char *const *args;
	unsigned int id;
	pid_t client_pid;
	const char *line;

	for (;;) {
		line = i_stream_read_next_line(conn->conn.input);
		if (line == NULL) {
			if (conn->conn.input->eof)
				server_connection_deinit(&conn);
			return;
		}

		switch (ctx->state) {
		case REQUEST_FAIL_STATE_VERSION:
			if (!str_begins(line, "VERSION\t")) {
				i_error("Bad VERSION");
				server_connection_deinit(&conn);
				return;
			}
			ctx->state = REQUEST_FAIL_STATE_REQUEST;
			continue;
		case REQUEST_FAIL_STATE_REQUEST:
			args = t_strsplit_tabescaped(line);
			if (strcmp(args[0], "REQUEST") != 0 ||
			    args[1] == NULL || str_to_uint(args[1], &id) < 0 ||
			    args[2] == NULL ||
			    str_to_pid(args[2], &client_pid) < 0) {
				i_error("Bad REQUEST");
				server_connection_deinit(&conn);
				return;
			}
			if (client_pid == 2324) {
				line = t_strdup_printf("NOTFOUND\t%u\n", id);
			} else if (client_pid == 2325) {
				sleep(5);
				server_connection_deinit(&conn);
				return;
			} else if (client_pid == 2326) {
				server_connection_deinit(&conn);
				return;
			} else {
				line = t_strdup_printf(
					"FAIL\t%u\t"
					"reason=REQUEST DENIED\n", id);
			}
			o_stream_nsend_str(conn->conn.output, line);
			server_connection_deinit(&conn);
			return;
		}
		i_unreached();
	}
}

static void test_request_fail_init(struct server_connection *conn)
{
	struct _request_fail_server *ctx;

	ctx = p_new(conn->pool, struct _request_fail_server, 1);
	conn->context = (void*)ctx;

	o_stream_nsend_str(conn->conn.output, "VERSION\t1\t0\n");
	o_stream_nsend_str(conn->conn.output, "SPID\t23234\n");
}

static void test_server_request_fail(void)
{
	test_server_init = test_request_fail_init;
	test_server_input = test_request_fail_input;
	test_server_run();
}

/* client */

static bool test_client_request_fail(void)
{
	const char *error;
	int ret;

	ret = test_client_request_simple(2323, FALSE, &error);
	test_out("run (ret == -1)", ret == -1);
	test_assert(error != NULL &&
		    strcmp(error, "REQUEST DENIED") == 0);

	return FALSE;
}

static bool test_client_request_notfound(void)
{
	const char *error;
	int ret;

	ret = test_client_request_simple(2324, FALSE, &error);
	test_out("run (ret == -1)", ret == -1);
	test_assert(error != NULL &&
		    strstr(error, "Internal error occurred.") != NULL);

	return FALSE;
}

static bool test_client_request_timeout(void)
{
	const char *error;
	int ret;

	ret = test_client_request_simple(2325, FALSE, &error);
	test_out("run (ret == -1)", ret == -1);
	test_assert(error != NULL &&
		    strstr(error, "Internal error occurred.") != NULL);

	return FALSE;
}

static bool test_client_request_disconnect(void)
{
	const char *error;
	int ret;

	ret = test_client_request_simple(2326, FALSE, &error);
	test_out("run (ret == -1)", ret == -1);
	test_assert(error != NULL &&
		    strstr(error, "Internal error occurred.") != NULL);

	return FALSE;
}

static bool test_client_request_reconnect(void)
{
	const char *error;
	int ret;

	ret = test_client_request_simple(2326, TRUE, &error);
	test_out("run (ret == -1)", ret == -1);
	test_assert(error != NULL &&
		    strstr(error, "Internal error occurred.") != NULL);

	return FALSE;
}

/* test */

static void test_request_fail(void)
{
	test_begin("request fail");
	test_expect_error_string("REQUEST DENIED");
	test_run_client_server(test_client_request_fail,
			       test_server_request_fail);
	test_end();

	test_begin("request notfound");
	test_expect_error_string("Authenticated user not found from userdb");
	test_run_client_server(test_client_request_notfound,
			       test_server_request_fail);
	test_end();

	test_begin("request timeout");
	test_expect_error_string("Auth server request timed out");
	test_run_client_server(test_client_request_timeout,
			       test_server_request_fail);
	test_end();

	test_begin("request disconnect");
	test_expect_error_string("Disconnected from auth server");
	test_run_client_server(test_client_request_disconnect,
			       test_server_request_fail);
	test_end();

	test_begin("request reconnect");
	test_expect_errors(2);
	test_run_client_server(test_client_request_reconnect,
			       test_server_request_fail);
	test_end();
}

/*
 * REQUEST
 */

/* server */

enum _request_login_state {
	REQUEST_LOGIN_STATE_VERSION = 0,
	REQUEST_LOGIN_STATE_REQUEST
};

struct _request_login_server {
	enum _request_login_state state;
};

static void test_request_login_input(struct server_connection *conn)
{
	struct _request_login_server *ctx =
		(struct _request_login_server *)conn->context;
	const char *const *args;
	unsigned int id;
	pid_t client_pid;
	const char *line;

	for (;;) {
		line = i_stream_read_next_line(conn->conn.input);
		if (line == NULL) {
			if (conn->conn.input->eof)
				server_connection_deinit(&conn);
			return;
		}
		switch (ctx->state) {
		case REQUEST_LOGIN_STATE_VERSION:
			if (!str_begins(line, "VERSION\t")) {
				i_error("Bad VERSION");
				server_connection_deinit(&conn);
				return;
			}
			ctx->state = REQUEST_LOGIN_STATE_REQUEST;
			continue;
		case REQUEST_LOGIN_STATE_REQUEST:
			args = t_strsplit_tabescaped(line);
			if (strcmp(args[0], "REQUEST") != 0 ||
			    args[1] == NULL || str_to_uint(args[1], &id) < 0 ||
			    args[2] == NULL ||
			    str_to_pid(args[2], &client_pid) < 0) {
				i_error("Bad PASS request");
				server_connection_deinit(&conn);
				return;
			}
			line = t_strdup_printf("USER\t%u\tfrop\n", id);
			o_stream_nsend_str(conn->conn.output, line);
			continue;
		}
		i_unreached();
	}
}

static void test_request_login_init(struct server_connection *conn)
{
	struct _request_login_server *ctx;

	ctx = p_new(conn->pool, struct _request_login_server, 1);
	conn->context = (void*)ctx;

	o_stream_nsend_str(conn->conn.output, "VERSION\t1\t0\n");
	o_stream_nsend_str(conn->conn.output, "SPID\t23234\n");
}

static void test_server_request_login(void)
{
	test_server_init = test_request_login_init;
	test_server_input = test_request_login_input;
	test_server_run();
}

/* client */

static bool test_client_request_login(void)
{
	const char *error;
	int ret;

	ret = test_client_request_simple(2323, FALSE, &error);
	test_out("run (ret == 0)", ret == 0);

	return FALSE;
}

static bool test_client_request_login_parallel(void)
{
	const char *error;
	int ret;

	ret = test_client_request_parallel(2323, 4, FALSE, &error);
	test_out("run (ret == 0)", ret == 0);

	return FALSE;
}

/* test */

static void test_request_login(void)
{
	test_begin("request login");
	test_run_client_server(test_client_request_login,
			       test_server_request_login);
	test_end();

	test_begin("request login parallel");
	test_run_client_server(test_client_request_login_parallel,
			       test_server_request_login);
	test_end();
}

/*
 * All tests
 */

static void (*const test_functions[])(void) = {
	test_connection_refused,
	test_connection_timed_out,
	test_bad_version,
	test_disconnect_version,
	test_changed_spid,
	test_request_fail,
	test_request_login,
	NULL
};

/*
 * Test client
 */

static void test_client_deinit(void)
{
}

struct login_test {
	char *error;
	int status;

	unsigned int pending_requests;

	struct ioloop *ioloop;
};

static void
test_client_request_callback(const char *const *auth_args ATTR_UNUSED,
			     const char *errormsg, void *context)
{
	struct login_test *login_test = context;

	if (errormsg != NULL) {
		login_test->error = i_strdup(errormsg);
		login_test->status = -1;
	}

	if (--login_test->pending_requests == 0)
		io_loop_stop(login_test->ioloop);
}

static int
test_client_request_run(struct master_login_auth *auth, struct ioloop *ioloop,
			struct master_auth_request *auth_req,
			unsigned int concurrency, const char **error_r)
{
	struct login_test login_test;
	unsigned int i;

	io_loop_set_running(ioloop);

	i_zero(&login_test);
	login_test.ioloop = ioloop;

	master_login_auth_set_timeout(auth, 1000);

	login_test.pending_requests = concurrency;
	for (i = 0; i < concurrency; i++) {
		master_login_auth_request(auth, auth_req,
					  test_client_request_callback,
					  &login_test);
	}

	if (io_loop_is_running(ioloop))
		io_loop_run(ioloop);

	*error_r = t_strdup(login_test.error);
	i_free(login_test.error);

	return login_test.status;
}

static int
test_client_request_parallel(pid_t client_pid, unsigned int concurrency,
			     bool retry, const char **error_r)
{
	struct master_login_auth *auth;
	struct master_auth_request auth_req;
	struct ioloop *ioloop;
	int ret;

	i_zero(&auth_req);
	auth_req.tag = 99033;
	auth_req.auth_pid = 23234;
	auth_req.auth_id = 45521;
	auth_req.client_pid = client_pid;
	random_fill(auth_req.cookie, sizeof(auth_req.cookie));
	(void)net_addr2ip("10.0.0.15", &auth_req.local_ip);
	auth_req.local_port = 143;
	(void)net_addr2ip("10.0.0.211", &auth_req.remote_ip);
	auth_req.remote_port = 45546;
	auth_req.flags = MAIL_AUTH_REQUEST_FLAG_CONN_SSL_SECURED;

	ioloop = io_loop_create();

	auth = master_login_auth_init(TEST_SOCKET, TRUE);
	ret = test_client_request_run(auth, ioloop, &auth_req, concurrency,
				      error_r);
	if (ret < 0 && retry) {
		ret = test_client_request_run(auth, ioloop, &auth_req,
					      concurrency, error_r);
	}
	master_login_auth_deinit(&auth);

	io_loop_destroy(&ioloop);

	return ret;
}

static int
test_client_request_simple(pid_t client_pid, bool retry, const char **error_r)
{
	return test_client_request_parallel(client_pid, 1, retry, error_r);
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

	pool = pool_alloconly_create("server connection", 256);
	conn = p_new(pool, struct server_connection, 1);
	conn->pool = pool;

	connection_init_server(server_conn_list, &conn->conn,
			       "server connection", fd, fd);

	if (test_server_init != NULL)
		test_server_init(conn);
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
	struct server_connection *conn =
		(struct server_connection *)_conn;

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

static void test_server_run(void)
{
	/* open server socket */
	io_listen = io_add(fd_listen,
		IO_READ, server_connection_accept, NULL);

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

static int test_open_server_fd(void)
{
	int fd;
	i_unlink_if_exists(TEST_SOCKET);
	fd = net_listen_unix(TEST_SOCKET, 128);
	if (debug)
		i_debug("server listening on "TEST_SOCKET);
	if (fd == -1)
		i_fatal("listen("TEST_SOCKET") failed: %m");
	return fd;
}

static void test_server_kill(void)
{
	if (server_pid != (pid_t)-1) {
		(void)kill(server_pid, SIGKILL);
		(void)waitpid(server_pid, NULL, 0);
		server_pid = -1;
	}
}

static void
test_run_client_server(test_client_init_t *client_test,
		       test_server_init_t *server_test)
{
	if (server_test != NULL) {
		lib_signals_ioloop_detach();

		server_pid = (pid_t)-1;

		fd_listen = test_open_server_fd();

		if ((server_pid = fork()) == (pid_t)-1)
			i_fatal("fork() failed: %m");
		if (server_pid == 0) {
			server_pid = (pid_t)-1;
			hostpid_init();
			while (current_ioloop != NULL) {
				ioloop = current_ioloop;
				io_loop_destroy(&ioloop);
			}
			lib_signals_deinit();
			/* child: server */
			i_set_failure_prefix("SERVER: ");
			if (debug)
				i_debug("PID=%s", my_pid);
			ioloop = io_loop_create();
			server_test();
			io_loop_destroy(&ioloop);
			if (fd_listen != -1)
				i_close_fd(&fd_listen);
			/* wait for it to be killed; this way, valgrind will not
			   object to this process going away inelegantly. */
			sleep(60);
			exit(1);
		}
		if (fd_listen != -1)
			i_close_fd(&fd_listen);

		lib_signals_ioloop_attach();
	}

	/* parent: client */
	i_set_failure_prefix("CLIENT: ");
	if (debug)
		i_debug("PID=%s", my_pid);

	usleep(100000); /* wait a little for server setup */

	ioloop = io_loop_create();
	if (client_test())
		io_loop_run(ioloop);
	test_client_deinit();
	io_loop_destroy(&ioloop);

	i_unset_failure_prefix();
	test_server_kill();
	i_unlink_if_exists(TEST_SOCKET);
}

/*
 * Main
 */

volatile sig_atomic_t terminating = 0;

static void test_signal_handler(int signo)
{
	if (terminating != 0)
		raise(signo);
	terminating = 1;

	/* make sure we don't leave any pesky children alive */
	test_server_kill();
	(void)unlink(TEST_SOCKET);

	(void)signal(signo, SIG_DFL);
	raise(signo);
}

static void test_atexit(void)
{
	test_server_kill();
	(void)unlink(TEST_SOCKET);
}

int main(int argc, char *argv[])
{
	const enum master_service_flags service_flags =
		MASTER_SERVICE_FLAG_STANDALONE |
		MASTER_SERVICE_FLAG_DONT_SEND_STATS |
		MASTER_SERVICE_FLAG_NO_SSL_INIT;
	int c;
	int ret;

	atexit(test_atexit);
	(void)signal(SIGPIPE, SIG_IGN);
	(void)signal(SIGTERM, test_signal_handler);
	(void)signal(SIGQUIT, test_signal_handler);
	(void)signal(SIGINT, test_signal_handler);
	(void)signal(SIGSEGV, test_signal_handler);
	(void)signal(SIGABRT, test_signal_handler);

	master_service = master_service_init("test-auth-master", service_flags,
					     &argc, &argv, "D");

	while ((c = master_getopt(master_service)) > 0) {
		switch (c) {
		case 'D':
			debug = TRUE;
			break;
		default:
			i_fatal("Usage: %s [-D]", argv[0]);
		}
	}

	master_service_init_finish(master_service);

	ret = test_run(test_functions);

	master_service_deinit(&master_service);

	return ret;
}
