/* Copyright (c) Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hostpid.h"
#include "net.h"
#include "istream.h"
#include "ostream.h"
#include "ioloop.h"
#include "unlink-directory.h"
#include "test-common.h"
#include "test-dir.h"
#include "test-subprocess.h"
#include "pop3c-client.h"
#include "settings.h"

#include <stdio.h>
#include <unistd.h>
#include <sys/signal.h>

#define SERVER_KILL_TIMEOUT_SECS    20

#define POP3C_COMMAND_STATE_INVALID (enum pop3c_command_state)-1

typedef void test_server_init_t(void);
typedef void test_client_init_t(void);

struct test_server {
	in_port_t port;
	pid_t pid;

	int fd_listen, fd;
	struct istream *input;
	struct ostream *output;
};

static struct event *common_event, *client_event, *server_event;
static struct ip_addr bind_ip;
static struct test_server server;
static struct pop3c_client *pop3c_client;
static enum pop3c_command_state pop3c_login_last_reply;

static struct settings_simple test_set;

static void main_deinit(void);

/*
 * Test client
 */

static void
test_add_setting(ARRAY_TYPE(const_string) *settings, const char *name,
		 const char *value)
{
	array_append(settings, &name, 1);
	array_append(settings, &value, 1);
}

static const char *const *
test_generate_settings(const char *port, const char *connection_timeout_interval)
{
	ARRAY_TYPE(const_string) settings;

	t_array_init(&settings, 16);
	test_add_setting(&settings, "pop3c_host", "127.0.0.1");
	if (port != NULL)
		test_add_setting(&settings, "pop3c_port", port);
	test_add_setting(&settings, "pop3c/client_auth_authid", "");
	test_add_setting(&settings, "pop3c/client_auth_authzid",
			 "testuser");
	test_add_setting(&settings, "pop3c/client_auth_password",
			 "testpass");
	if (connection_timeout_interval != NULL) {
		test_add_setting(&settings, "pop3c_cmd_timeout",
				 connection_timeout_interval);
		test_add_setting(&settings, "pop3c_connect_timeout",
				 connection_timeout_interval);
	} else {
		test_add_setting(&settings, "pop3c_cmd_timeout", "5s");
		test_add_setting(&settings, "pop3c_connect_timeout", "5s");
	}
	array_append_zero(&settings);

	return array_idx(&settings, 0);
}

static void
pop3c_login_callback(enum pop3c_command_state state, const char *reply,
		     void *context ATTR_UNUSED)
{
	e_debug(client_event, "Login reply: %s %s",
		pop3c_command_state_names[state], reply);
	pop3c_login_last_reply = state;
	io_loop_stop(current_ioloop);
}

/*
 * Test server
 */

static bool
test_pop3c_server_expect_full(struct test_server *server,
			      const char *expected_line)
{
	const char *line = i_stream_read_next_line(server->input);

	e_debug(server_event, "Received: %s", (line == NULL ? "<EOF>" : line));

	if (line == NULL) {
		printf("pop3c client disconnected unexpectedly: %s\n",
		       i_stream_get_error(server->input));
		return FALSE;
	} else if (strcmp(line, expected_line) != 0) {
		printf("pop3c client sent '%s' when expecting '%s'\n",
		       line, expected_line);
		return FALSE;
	} else {
		return TRUE;
	}
}

static bool test_pop3c_server_expect(const char *expected_line)
{
	return test_pop3c_server_expect_full(&server, expected_line);
}

static void
test_server_wait_connection_common(struct test_server *server)
{
	e_debug(server_event, "Waiting for connection");

	server->fd = net_accept(server->fd_listen, NULL, NULL);
	i_assert(server->fd >= 0);

	e_debug(server_event, "Client connected");

	fd_set_nonblock(server->fd, FALSE);
	server->input = i_stream_create_fd(server->fd, SIZE_MAX);
	server->output = o_stream_create_fd(server->fd, SIZE_MAX);
	o_stream_set_no_error_handling(server->output, TRUE);
}

static void
test_server_wait_connection(struct test_server *server, bool send_banner)
{
	test_server_wait_connection_common(server);
	if (send_banner) {
		o_stream_nsend_str(server->output,
			"+OK ready\r\n");
	}
}

static void test_server_disconnect(struct test_server *server)
{
	e_debug(server_event, "Disconnecting client");

	i_stream_unref(&server->input);
	o_stream_unref(&server->output);
	i_close_fd(&server->fd);
}

/*
 * Test processes
 */

static int test_open_server_fd(in_port_t *bind_port)
{
	int fd = net_listen(&bind_ip, bind_port, 128);
	e_debug(common_event, "server listening on %u", *bind_port);
	if (fd == -1) {
		i_fatal("listen(%s:%u) failed: %m",
			net_ip2addr(&bind_ip), *bind_port);
	}
	fd_set_nonblock(fd, FALSE);
	return fd;
}

static int test_run_server(test_server_init_t *server_test)
{
	struct ioloop *ioloop;

	i_set_failure_prefix("SERVER: ");

	e_debug(server_event, "PID=%s", my_pid);

	test_subprocess_notify_signal_send_parent(SIGHUP);
	ioloop = io_loop_create();
	if (server_test != NULL)
		server_test();
	test_server_disconnect(&server);
	io_loop_destroy(&ioloop);

	e_debug(server_event, "Terminated");

	i_close_fd(&server.fd_listen);
	main_deinit();

	/* Cleanup the test settings in the server process as well.
	   See test_run_client_server() for the appropriate cleanup call in the
	   main process. */
	settings_simple_deinit(&test_set);
	return 0;
}

static void
test_run_client(test_client_init_t *client_test, const char *temp_path_prefix)
{
	struct ioloop *ioloop;
	const char *error;

	i_set_failure_prefix("CLIENT: ");

	e_debug(client_event, "PID=%s", my_pid);

	struct pop3c_parameters pop3c_params = {
		.temp_path_prefix = temp_path_prefix,
	};

	ioloop = io_loop_create();
	if (pop3c_client_init(&pop3c_params, test_set.event,
			      &pop3c_client, &error) < 0)
		i_fatal("Failed to initialize POP3 client: %s", error);
	client_test();
	if (pop3c_client != NULL)
		pop3c_client_deinit(&pop3c_client);
	io_loop_destroy(&ioloop);

	e_debug(client_event, "Terminated");
}

static void
test_run_client_server(test_client_init_t *client_test,
		       test_server_init_t *server_test,
		       bool reduce_timeout)
{
	static unsigned int run_id = 0;
	const char *error;

	pop3c_login_last_reply = POP3C_COMMAND_STATE_INVALID;

	i_zero(&server);
	server.pid = (pid_t)-1;
	server.fd = -1;
	server.fd_listen = test_open_server_fd(&server.port);

	const char *const *settings =
		test_generate_settings(dec2str(server.port),
				       reduce_timeout ? "500ms" : "5s");
	settings_simple_init_with_event(&test_set, client_event, settings);

	const char *temp_path_prefix = t_strdup_printf(
		"%s/client-run-%u/", test_dir_get(), run_id++);
	if (mkdir(temp_path_prefix, 0700) < 0 && errno != EEXIST)
		i_fatal("mkdir(%s) failed: %m", temp_path_prefix);

	if (server_test != NULL) {
		/* Fork server */
		test_subprocess_notify_signal_reset(SIGHUP);
		test_subprocess_fork(test_run_server, server_test, TRUE);
		test_subprocess_notify_signal_wait(
			SIGHUP, TEST_SIGNALS_DEFAULT_TIMEOUT_MS);
	}
	i_close_fd(&server.fd_listen);

	/* Run client */
	test_run_client(client_test, temp_path_prefix);

	i_unset_failure_prefix();
	test_subprocess_kill_all(SERVER_KILL_TIMEOUT_SECS);
	if (unlink_directory(temp_path_prefix, UNLINK_DIRECTORY_FLAG_RMDIR,
			     &error) < 0)
		i_fatal("%s", error);

	/* Cleanup the test settings in the main process.
	   Note: This needs to be called as well in the server process,
	   otherwise it will leak it's event and the looked up settings
	   struct. See test_run_server() for the appropriate cleanup call in
	   the server process. */
	settings_simple_deinit(&test_set);
}

/*
 * pop3c connect failed
 */

static void test_pop3c_connect_failed_client(void)
{
	test_expect_errors(1);
	pop3c_client_login(pop3c_client, pop3c_login_callback, NULL);
	pop3c_client_wait_one(pop3c_client);
	test_expect_no_more_errors();
	test_assert(pop3c_login_last_reply == POP3C_COMMAND_STATE_DISCONNECTED);
}

static void test_pop3c_connect_failed(void)
{
	test_begin("pop3c connect failed");
	test_run_client_server(test_pop3c_connect_failed_client, NULL, FALSE);
	test_end();
}

/*
 * pop3c banner hang
 */

static void test_pop3c_banner_hangs_client(void)
{
	pop3c_client_login(pop3c_client, pop3c_login_callback, NULL);
	test_expect_errors(1);
	pop3c_client_wait_one(pop3c_client);
	test_expect_no_more_errors();
	test_assert(pop3c_login_last_reply == POP3C_COMMAND_STATE_DISCONNECTED);
}

static void test_pop3c_banner_hangs_server(void)
{
	test_server_wait_connection(&server, FALSE);
	test_assert(i_stream_read_next_line(server.input) == NULL);
	test_server_disconnect(&server);
}

static void test_pop3c_banner_hangs(void)
{
	test_begin("pop3c banner hangs");
	test_run_client_server(test_pop3c_banner_hangs_client,
			       test_pop3c_banner_hangs_server,
			       TRUE);
	test_end();
}

/*
 * pop3c user hangs
 */

static void test_pop3c_user_hangs_client(void)
{
	pop3c_client_login(pop3c_client, pop3c_login_callback, NULL);
	test_expect_error_string("Timed out in state USER");
	pop3c_client_wait_one(pop3c_client);
	test_expect_no_more_errors();
	test_assert(pop3c_login_last_reply == POP3C_COMMAND_STATE_DISCONNECTED);
}

static void test_pop3c_user_hangs_server(void)
{
	test_server_wait_connection(&server, TRUE);
	test_assert(test_pop3c_server_expect("CAPA"));
	o_stream_nsend_str(server.output,
		"+OK Capability list follows\r\nPIPELINING\r\n.\r\n");
	test_assert(test_pop3c_server_expect("USER testuser"));
	test_assert(i_stream_read_next_line(server.input) == NULL);
	test_server_disconnect(&server);
}

static void test_pop3c_user_hangs(void)
{
	test_begin("pop3c user hangs");
	test_run_client_server(test_pop3c_user_hangs_client,
			       test_pop3c_user_hangs_server,
			       TRUE);
	test_end();
}

/*
 * pop3c pass hangs
 */

static void test_pop3c_pass_hangs_client(void)
{
	pop3c_client_login(pop3c_client, pop3c_login_callback, NULL);
	test_expect_error_string("Timed out in state PASS");
	pop3c_client_wait_one(pop3c_client);
	test_expect_no_more_errors();
	test_assert(pop3c_login_last_reply == POP3C_COMMAND_STATE_DISCONNECTED);
}

static void test_pop3c_pass_hangs_server(void)
{
	test_server_wait_connection(&server, TRUE);
	test_assert(test_pop3c_server_expect("CAPA"));
	o_stream_nsend_str(server.output,
		"+OK Capability list follows\r\nPIPELINING\r\n.\r\n");
	test_assert(test_pop3c_server_expect("USER testuser"));
	o_stream_nsend_str(server.output, "+OK\r\n");
	test_assert(test_pop3c_server_expect("PASS testpass"));
	test_assert(i_stream_read_next_line(server.input) == NULL);
	test_server_disconnect(&server);
}

static void test_pop3c_pass_hangs(void)
{
	test_begin("pop3c pass hangs");
	test_run_client_server(test_pop3c_pass_hangs_client,
			       test_pop3c_pass_hangs_server,
			       TRUE);
	test_end();
}

/*
 * pop3c user fails
 */

static void test_pop3c_user_fails_client(void)
{
	pop3c_client_login(pop3c_client, pop3c_login_callback, NULL);
	test_expect_error_string("Test login failed");
	pop3c_client_wait_one(pop3c_client);
	test_expect_no_more_errors();
	test_assert(pop3c_login_last_reply == POP3C_COMMAND_STATE_DISCONNECTED);
}

static void test_pop3c_user_fails_server(void)
{
	test_server_wait_connection(&server, TRUE);
	test_assert(test_pop3c_server_expect("CAPA"));
	o_stream_nsend_str(server.output,
		"+OK Capability list follows\r\nPIPELINING\r\n.\r\n");
	test_assert(test_pop3c_server_expect("USER testuser"));
	o_stream_nsend_str(server.output, "-ERR Test login failed\r\n");
}

static void test_pop3c_user_fails(void)
{
	test_begin("pop3c user fails");
	test_run_client_server(test_pop3c_user_fails_client,
			       test_pop3c_user_fails_server,
			       FALSE);
	test_end();
}

/*
 * pop3c pass fails
 */

static void test_pop3c_pass_fails_client(void)
{
	pop3c_client_login(pop3c_client, pop3c_login_callback, NULL);
	pop3c_client_wait_one(pop3c_client);
	test_assert(pop3c_login_last_reply == POP3C_COMMAND_STATE_ERR);
}

static void test_pop3c_pass_fails_server(void)
{
	test_server_wait_connection(&server, TRUE);
	test_assert(test_pop3c_server_expect("CAPA"));
	o_stream_nsend_str(server.output,
		"+OK Capability list follows\r\nPIPELINING\r\n.\r\n");
	test_assert(test_pop3c_server_expect("USER testuser"));
	o_stream_nsend_str(server.output, "+OK\r\n");
	test_assert(test_pop3c_server_expect("PASS testpass"));
	o_stream_nsend_str(server.output, "-ERR Test login failed\r\n");
}

static void test_pop3c_pass_fails(void)
{
	test_begin("pop3c pass fails");
	test_run_client_server(test_pop3c_pass_fails_client,
			       test_pop3c_pass_fails_server,
			       FALSE);
	test_end();
}

/*
 * pop3c user+pass success
 */

static void test_pop3c_user_pass_success_client(void)
{
	pop3c_client_login(pop3c_client, pop3c_login_callback, NULL);
	pop3c_client_wait_one(pop3c_client);
	test_assert(pop3c_login_last_reply == POP3C_COMMAND_STATE_OK);

	const char *reply;
	test_assert(pop3c_client_cmd_line(pop3c_client, "NOOP\r\n", &reply) == 0);
	test_assert_strcmp(reply, "Doing nothing");
}

static void test_pop3c_user_pass_success_server(void)
{
	test_server_wait_connection(&server, TRUE);
	test_assert(test_pop3c_server_expect("CAPA"));
	o_stream_nsend_str(server.output,
		"+OK Capability list follows\r\nPIPELINING\r\n.\r\n");
	test_assert(test_pop3c_server_expect("USER testuser"));
	o_stream_nsend_str(server.output, "+OK\r\n");
	test_assert(test_pop3c_server_expect("PASS testpass"));
	o_stream_nsend_str(server.output, "+OK\r\n");
	test_assert(test_pop3c_server_expect("CAPA"));
	o_stream_nsend_str(server.output,
		"+OK Capability list follows\r\nPIPELINING\r\n.\r\n");
	test_assert(test_pop3c_server_expect("NOOP"));
	o_stream_nsend_str(server.output, "+OK Doing nothing\r\n");
}

static void test_pop3c_user_pass_success(void)
{
	test_begin("pop3c user+pass success");
	test_run_client_server(test_pop3c_user_pass_success_client,
			       test_pop3c_user_pass_success_server,
			       FALSE);
	test_end();
}

/*
 * pop3c capa failure, user+pass success
 */

static void test_pop3c_capa_failure_user_pass_success_client(void)
{
	pop3c_client_login(pop3c_client, pop3c_login_callback, NULL);
	pop3c_client_wait_one(pop3c_client);
	test_assert(pop3c_login_last_reply == POP3C_COMMAND_STATE_OK);

	const char *reply;
	test_assert(pop3c_client_cmd_line(pop3c_client, "NOOP\r\n", &reply) == 0);
	test_assert_strcmp(reply, "Doing nothing");
}

static void test_pop3c_capa_failure_user_pass_success_server(void)
{
	test_server_wait_connection(&server, TRUE);
	test_assert(test_pop3c_server_expect("CAPA"));
	o_stream_nsend_str(server.output, "-ERR Unknown command\r\n");
	test_assert(test_pop3c_server_expect("USER testuser"));
	o_stream_nsend_str(server.output, "+OK\r\n");
	test_assert(test_pop3c_server_expect("PASS testpass"));
	o_stream_nsend_str(server.output, "+OK\r\n");
	test_assert(test_pop3c_server_expect("NOOP"));
	o_stream_nsend_str(server.output, "+OK Doing nothing\r\n");
}

static void test_pop3c_capa_failure_user_pass_success(void)
{
	test_begin("pop3c capa failure, user+pass success");
	test_run_client_server(test_pop3c_capa_failure_user_pass_success_client,
			       test_pop3c_capa_failure_user_pass_success_server,
			       FALSE);
	test_end();
}

/*
 * Main
 */

static void main_init(void)
{
	common_event = test_event;
	client_event = event_create(common_event);
	event_set_append_log_prefix(client_event, "test client: ");
	server_event = event_create(common_event);
	event_set_append_log_prefix(server_event, "test server: ");
}

static void main_deinit(void)
{
	event_unref(&client_event);
	event_unref(&server_event);
	common_event = NULL;
}

int main(int argc ATTR_UNUSED, char *argv[])
{
	int c;
	bool debug = FALSE;
	int ret;

	static void (*const test_functions[])(void) = {
		test_pop3c_connect_failed,
		test_pop3c_banner_hangs,
		test_pop3c_user_hangs,
		test_pop3c_pass_hangs,
		test_pop3c_user_fails,
		test_pop3c_pass_fails,
		test_pop3c_user_pass_success,
		test_pop3c_capa_failure_user_pass_success,
		NULL
	};

	lib_init();

	while ((c = getopt(argc, argv, "D")) > 0) {
		switch (c) {
		case 'D':
			debug = TRUE;
			break;
		default:
			i_fatal("Usage: %s [-D]", argv[0]);
		}
	}

	test_init();
	event_set_forced_debug(test_event, debug);
	test_dir_init("test-pop3c-client");
	test_subprocesses_init();
	main_init();

	/* listen on localhost */
	i_zero(&bind_ip);
	bind_ip.family = AF_INET;
	bind_ip.u.ip4.s_addr = htonl(INADDR_LOOPBACK);

	ret = test_run(test_functions);

	main_deinit();
	lib_deinit();

	return ret;
}
