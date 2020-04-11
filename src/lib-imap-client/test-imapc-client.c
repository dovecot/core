/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hostpid.h"
#include "net.h"
#include "istream.h"
#include "ostream.h"
#include "ioloop.h"
#include "unlink-directory.h"
#include "sleep.h"
#include "test-common.h"
#include "test-subprocess.h"
#include "imapc-client-private.h"

#include <stdio.h>
#include <unistd.h>

#define SERVER_KILL_TIMEOUT_SECS    20

#define IMAPC_COMMAND_STATE_INVALID (enum imapc_command_state)-1

typedef void test_server_init_t(void);
typedef void test_client_init_t(void);

struct test_server {
	in_port_t port;
	pid_t pid;

	int fd_listen, fd;
	struct istream *input;
	struct ostream *output;
};

static struct ip_addr bind_ip;
static struct test_server server;
static struct imapc_client *imapc_client;
static enum imapc_command_state imapc_login_last_reply;
static ARRAY(enum imapc_command_state) imapc_cmd_last_replies;
static bool debug = FALSE;

static void main_deinit(void);

/*
 * Test client
 */

static struct imapc_client_settings test_imapc_default_settings = {
	.host = "127.0.0.1",
	.username = "testuser",
	.password = "testpass",

	.dns_client_socket_path = "",
	.temp_path_prefix = ".test-tmp/",
	.rawlog_dir = "",

	.connect_timeout_msecs = 500,
	.connect_retry_count = 3,
	.connect_retry_interval_msecs = 10,

	.max_idle_time = 10000,
};

static enum imapc_command_state test_imapc_cmd_last_reply_pop(void)
{
	const enum imapc_command_state *replies;
	enum imapc_command_state reply;
	unsigned int count;

	replies = array_get(&imapc_cmd_last_replies, &count);
	if (count == 0)
		return IMAPC_COMMAND_STATE_INVALID;
	reply = replies[0];
	array_pop_front(&imapc_cmd_last_replies);
	return reply;
}

static bool test_imapc_cmd_last_reply_expect(enum imapc_command_state state)
{
	if (array_count(&imapc_cmd_last_replies) == 0)
		imapc_client_run(imapc_client);
	return test_imapc_cmd_last_reply_pop() == state;
}

static void imapc_login_callback(const struct imapc_command_reply *reply,
				 void *context ATTR_UNUSED)
{
	if (debug) {
		i_debug("Login reply: %s %s",
			imapc_command_state_names[reply->state],
			reply->text_full);
	}
	imapc_login_last_reply = reply->state;
	imapc_client_stop(imapc_client);
}

static void imapc_command_callback(const struct imapc_command_reply *reply,
				   void *context ATTR_UNUSED)
{
	if (debug) {
		i_debug("Command reply: %s %s",
			imapc_command_state_names[reply->state],
			reply->text_full);
	}
	array_push_back(&imapc_cmd_last_replies, &reply->state);
	imapc_client_stop(imapc_client);
}

static void imapc_reopen_callback(void *context)
{
	struct imapc_client_mailbox *box = context;
	struct imapc_command *cmd;

	cmd = imapc_client_mailbox_cmd(box, imapc_command_callback, NULL);
	imapc_command_set_flags(cmd, IMAPC_COMMAND_FLAG_SELECT);
	imapc_command_send(cmd, "SELECT");
}

/*
 * Test server
 */

static bool
test_imapc_server_expect_full(struct test_server *server,
			      const char *expected_line)
{
	const char *line = i_stream_read_next_line(server->input);

	if (debug)
		i_debug("Received: %s", (line == NULL ? "<EOF>" : line));

	if (line == NULL) {
		printf("imapc client disconnected unexpectedly: %s\n",
		       i_stream_get_error(server->input));
		return FALSE;
	} else if (strcmp(line, expected_line) != 0) {
		printf("imapc client sent '%s' when expecting '%s'\n",
		       line, expected_line);
		return FALSE;
	} else {
		return TRUE;
	}
}

static bool test_imapc_server_expect(const char *expected_line)
{
	return test_imapc_server_expect_full(&server, expected_line);
}

static void
test_server_wait_connection(struct test_server *server, bool send_banner)
{
	if (debug)
		i_debug("Waiting for connection");

	server->fd = net_accept(server->fd_listen, NULL, NULL);
	i_assert(server->fd >= 0);

	if (debug)
		i_debug("Client connected");

	fd_set_nonblock(server->fd, FALSE);
	server->input = i_stream_create_fd(server->fd, (size_t)-1);
	server->output = o_stream_create_fd(server->fd, (size_t)-1);
	o_stream_set_no_error_handling(server->output, TRUE);

	if (send_banner) {
		o_stream_nsend_str(server->output,
			"* OK [CAPABILITY IMAP4rev1 UNSELECT QUOTA] ready\r\n");
	}
}

static void test_server_disconnect(struct test_server *server)
{
	if (debug)
		i_debug("Disconnecting client");

	i_stream_unref(&server->input);
	o_stream_unref(&server->output);
	i_close_fd(&server->fd);
}

static void test_server_disconnect_and_wait(bool send_banner)
{
	test_server_disconnect(&server);
	test_server_wait_connection(&server, send_banner);
}

/*
 * Test processes
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
	fd_set_nonblock(fd, FALSE);
	return fd;
}

static int test_run_server(test_server_init_t *server_test)
{
	struct ioloop *ioloop;

	i_set_failure_prefix("SERVER: ");

	if (debug)
		i_debug("PID=%s", my_pid);

	ioloop = io_loop_create();
	if (server_test != NULL)
		server_test();
	test_server_disconnect(&server);
	io_loop_destroy(&ioloop);

	if (debug)
		i_debug("Terminated");

	i_close_fd(&server.fd_listen);
	main_deinit();
	return 0;
}

static void
test_run_client(const struct imapc_client_settings *client_set,
		test_client_init_t *client_test)
{
	struct ioloop *ioloop;

	i_set_failure_prefix("CLIENT: ");

	if (debug)
		i_debug("PID=%s", my_pid);

	i_sleep_msecs(100); /* wait a little for server setup */

	ioloop = io_loop_create();
	imapc_client = imapc_client_init(client_set);
	client_test();
	imapc_client_logout(imapc_client);
	test_assert(array_count(&imapc_cmd_last_replies) == 0);
	if (imapc_client != NULL)
		imapc_client_deinit(&imapc_client);
	io_loop_destroy(&ioloop);

	if (debug)
		i_debug("Terminated");
}

static void
test_run_client_server(const struct imapc_client_settings *client_set,
		       test_client_init_t *client_test,
		       test_server_init_t *server_test)
{
	struct imapc_client_settings client_set_copy = *client_set;
	const char *error;

	imapc_client_cmd_tag_counter = 0;
	imapc_login_last_reply = IMAPC_COMMAND_STATE_INVALID;
	t_array_init(&imapc_cmd_last_replies, 4);

	i_zero(&server);
	server.pid = (pid_t)-1;
	server.fd = -1;
	server.fd_listen = test_open_server_fd(&server.port);
	client_set_copy.port = server.port;

	if (mkdir(client_set->temp_path_prefix, 0700) < 0 && errno != EEXIST)
		i_fatal("mkdir(%s) failed: %m", client_set->temp_path_prefix);

	if (server_test != NULL) {
		/* Fork server */
		test_subprocess_fork(test_run_server, server_test, TRUE);
	}
	i_close_fd(&server.fd_listen);

	/* Run client */
	test_run_client(&client_set_copy, client_test);

	i_unset_failure_prefix();
	test_subprocess_kill_all(SERVER_KILL_TIMEOUT_SECS);
	if (unlink_directory(client_set->temp_path_prefix,
			     UNLINK_DIRECTORY_FLAG_RMDIR, &error) < 0)
		i_fatal("%s", error);
}

/*
 * imapc connect failed
 */

static void test_imapc_connect_failed_client(void)
{
	imapc_client_set_login_callback(imapc_client,
					imapc_login_callback, NULL);
	imapc_client_login(imapc_client);
	/* connection refused & one reconnect */
	test_expect_errors(2);
	imapc_client_run(imapc_client);
	test_expect_no_more_errors();
	test_assert(imapc_login_last_reply == IMAPC_COMMAND_STATE_DISCONNECTED);
}

static void test_imapc_connect_failed(void)
{
	struct imapc_client_settings set = test_imapc_default_settings;

	test_begin("imapc connect failed");
	test_run_client_server(&set, test_imapc_connect_failed_client, NULL);
	test_end();
}

/*
 * imapc banner hang
 */

static void test_imapc_banner_hangs_client(void)
{
	imapc_client_set_login_callback(imapc_client,
					imapc_login_callback, NULL);
	imapc_client_login(imapc_client);
	test_expect_errors(2);
	imapc_client_run(imapc_client);
	test_expect_no_more_errors();
	test_assert(imapc_login_last_reply == IMAPC_COMMAND_STATE_DISCONNECTED);
}

static void test_imapc_banner_hangs_server(void)
{
	struct test_server server2 = { .fd_listen = server.fd_listen };

	test_server_wait_connection(&server, FALSE);
	test_server_wait_connection(&server2, FALSE);
	test_assert(i_stream_read_next_line(server2.input) == NULL);
	test_server_disconnect(&server2);
}

static void test_imapc_banner_hangs(void)
{
	struct imapc_client_settings set = test_imapc_default_settings;

	test_begin("imapc banner hangs");
	test_run_client_server(&set, test_imapc_banner_hangs_client,
			       test_imapc_banner_hangs_server);
	test_end();
}

/*
 * imapc login hangs
 */

static void test_imapc_login_hangs_client(void)
{
	imapc_client_set_login_callback(imapc_client,
					imapc_login_callback, NULL);
	imapc_client_login(imapc_client);
	/* run the first login */
	test_expect_error_string("Authentication timed out");
	imapc_client_run(imapc_client);
	test_expect_no_more_errors();
	/* imapc_login_callback() has stopped us. run the second reconnect
	   login. */
	test_expect_error_string("Authentication timed out");
	imapc_client_run(imapc_client);
	test_expect_no_more_errors();
	test_assert(imapc_login_last_reply == IMAPC_COMMAND_STATE_DISCONNECTED);
}

static void test_imapc_login_hangs_server(void)
{
	struct test_server server2 = { .fd_listen = server.fd_listen };

	test_server_wait_connection(&server, TRUE);
	test_assert(test_imapc_server_expect(
		"1 LOGIN \"testuser\" \"testpass\""));

	test_server_wait_connection(&server2, TRUE);
	test_assert(test_imapc_server_expect_full(
		&server2, "2 LOGIN \"testuser\" \"testpass\""));

	test_assert(i_stream_read_next_line(server2.input) == NULL);
	test_server_disconnect(&server2);
}

static void test_imapc_login_hangs(void)
{
	struct imapc_client_settings set = test_imapc_default_settings;

	test_begin("imapc login hangs");
	test_run_client_server(&set, test_imapc_login_hangs_client,
			       test_imapc_login_hangs_server);
	test_end();
}

/*
 * imapc login fails
 */

static void test_imapc_login_fails_client(void)
{
	imapc_client_set_login_callback(imapc_client,
					imapc_login_callback, NULL);
	imapc_client_login(imapc_client);
	test_expect_error_string("Authentication failed: Test login failed");
	imapc_client_run(imapc_client);
	test_expect_no_more_errors();
	test_assert(imapc_login_last_reply == IMAPC_COMMAND_STATE_AUTH_FAILED);
}

static void test_imapc_login_fails_server(void)
{
	test_server_wait_connection(&server, TRUE);
	test_assert(test_imapc_server_expect(
		"1 LOGIN \"testuser\" \"testpass\""));
	o_stream_nsend_str(server.output, "1 NO Test login failed\r\n");
}

static void test_imapc_login_fails(void)
{
	struct imapc_client_settings set = test_imapc_default_settings;

	test_begin("imapc login fails");
	test_run_client_server(&set, test_imapc_login_fails_client,
			       test_imapc_login_fails_server);
	test_end();
}

/*
 * imapc reconnect
 */

static void test_imapc_reconnect_client(void)
{
	struct imapc_command *cmd;

	/* login to server */
	imapc_client_set_login_callback(imapc_client,
					imapc_login_callback, NULL);
	imapc_client_login(imapc_client);
	imapc_client_run(imapc_client);
	test_assert(imapc_login_last_reply == IMAPC_COMMAND_STATE_OK);
	imapc_login_last_reply = IMAPC_COMMAND_STATE_INVALID;

	/* disconnect */
	cmd = imapc_client_cmd(imapc_client, imapc_command_callback, NULL);
	imapc_command_send(cmd, "DISCONNECT");
	test_expect_error_string("reconnecting");
	imapc_client_run(imapc_client);
	test_expect_no_more_errors();
	test_assert(test_imapc_cmd_last_reply_pop() ==
		    IMAPC_COMMAND_STATE_DISCONNECTED);

	/* we should be reconnected now. try a command. */
	cmd = imapc_client_cmd(imapc_client, imapc_command_callback, NULL);
	imapc_command_send(cmd, "NOOP");
	imapc_client_run(imapc_client);
	test_assert(imapc_login_last_reply == IMAPC_COMMAND_STATE_INVALID);
	test_assert(test_imapc_cmd_last_reply_pop() == IMAPC_COMMAND_STATE_OK);
}

static void test_imapc_reconnect_server(void)
{
	test_server_wait_connection(&server, TRUE);
	test_assert(test_imapc_server_expect(
		"1 LOGIN \"testuser\" \"testpass\""));
	o_stream_nsend_str(server.output, "1 OK \r\n");

	test_assert(test_imapc_server_expect("2 DISCONNECT"));
	test_server_disconnect_and_wait(TRUE);

	test_assert(test_imapc_server_expect(
		"4 LOGIN \"testuser\" \"testpass\""));
	o_stream_nsend_str(server.output, "4 OK \r\n");
	test_assert(test_imapc_server_expect("3 NOOP"));
	o_stream_nsend_str(server.output, "3 OK \r\n");

	test_assert(test_imapc_server_expect("5 LOGOUT"));
	o_stream_nsend_str(server.output, "5 OK \r\n");

	test_assert(i_stream_read_next_line(server.input) == NULL);
}

static void test_imapc_reconnect(void)
{
	struct imapc_client_settings set = test_imapc_default_settings;

	test_begin("imapc reconnect");
	test_run_client_server(&set, test_imapc_reconnect_client,
			       test_imapc_reconnect_server);
	test_end();
}

/*
 * imapc reconnect resend commands
 */

static void test_imapc_reconnect_resend_cmds_client(void)
{
	struct imapc_command *cmd;

	/* login to server */
	imapc_client_set_login_callback(imapc_client,
					imapc_login_callback, NULL);
	imapc_client_login(imapc_client);
	imapc_client_run(imapc_client);
	test_assert(imapc_login_last_reply == IMAPC_COMMAND_STATE_OK);
	imapc_login_last_reply = IMAPC_COMMAND_STATE_INVALID;

	/* send two commands */
	cmd = imapc_client_cmd(imapc_client, imapc_command_callback, NULL);
	imapc_command_set_flags(cmd, IMAPC_COMMAND_FLAG_RETRIABLE);
	imapc_command_send(cmd, "RETRY1");
	cmd = imapc_client_cmd(imapc_client, imapc_command_callback, NULL);
	imapc_command_set_flags(cmd, IMAPC_COMMAND_FLAG_RETRIABLE);
	imapc_command_send(cmd, "RETRY2");

	/* disconnect & reconnect automatically */
	cmd = imapc_client_cmd(imapc_client, imapc_command_callback, NULL);
	imapc_command_send(cmd, "DISCONNECT");
	test_expect_error_string("reconnecting");
	imapc_client_run(imapc_client);
	test_expect_no_more_errors();
	test_assert(test_imapc_cmd_last_reply_expect(
		IMAPC_COMMAND_STATE_DISCONNECTED));

	/* continue reconnection */
	test_assert(test_imapc_cmd_last_reply_expect(IMAPC_COMMAND_STATE_OK));
	test_assert(test_imapc_cmd_last_reply_expect(IMAPC_COMMAND_STATE_OK));
}

static void test_imapc_reconnect_resend_cmds_server(void)
{
	test_server_wait_connection(&server, TRUE);
	test_assert(test_imapc_server_expect(
		"1 LOGIN \"testuser\" \"testpass\""));
	o_stream_nsend_str(server.output, "1 OK \r\n");

	test_assert(test_imapc_server_expect("2 RETRY1"));
	test_assert(test_imapc_server_expect("3 RETRY2"));
	test_assert(test_imapc_server_expect("4 DISCONNECT"));
	test_server_disconnect_and_wait(TRUE);

	test_assert(test_imapc_server_expect(
		"5 LOGIN \"testuser\" \"testpass\""));
	o_stream_nsend_str(server.output, "5 OK \r\n");
	test_assert(test_imapc_server_expect("2 RETRY1"));
	o_stream_nsend_str(server.output, "2 OK \r\n");
	test_assert(test_imapc_server_expect("3 RETRY2"));
	o_stream_nsend_str(server.output, "3 OK \r\n");

	test_assert(test_imapc_server_expect("6 LOGOUT"));
	o_stream_nsend_str(server.output, "6 OK \r\n");

	test_assert(i_stream_read_next_line(server.input) == NULL);
}

static void test_imapc_reconnect_resend_commands(void)
{
	struct imapc_client_settings set = test_imapc_default_settings;

	test_begin("imapc reconnect resend commands");
	test_run_client_server(&set, test_imapc_reconnect_resend_cmds_client,
			       test_imapc_reconnect_resend_cmds_server);
	test_end();
}

/*
 * imapc reconnect resend commands failed
 */

static void test_imapc_reconnect_resend_cmds_failed_client(void)
{
	struct imapc_command *cmd;

	/* login to server */
	imapc_client_set_login_callback(imapc_client,
					imapc_login_callback, NULL);
	imapc_client_login(imapc_client);
	imapc_client_run(imapc_client);
	test_assert(imapc_login_last_reply == IMAPC_COMMAND_STATE_OK);
	imapc_login_last_reply = IMAPC_COMMAND_STATE_INVALID;

	/* send two commands */
	cmd = imapc_client_cmd(imapc_client, imapc_command_callback, NULL);
	imapc_command_set_flags(cmd, IMAPC_COMMAND_FLAG_RETRIABLE);
	imapc_command_send(cmd, "RETRY1");
	cmd = imapc_client_cmd(imapc_client, imapc_command_callback, NULL);
	imapc_command_set_flags(cmd, IMAPC_COMMAND_FLAG_RETRIABLE);
	imapc_command_send(cmd, "RETRY2");

	/* disconnect & try to reconnect automatically */
	cmd = imapc_client_cmd(imapc_client, imapc_command_callback, NULL);
	imapc_command_send(cmd, "DISCONNECT");
	test_expect_error_string("reconnecting");
	imapc_client_run(imapc_client);
	test_expect_no_more_errors();
	test_assert(test_imapc_cmd_last_reply_expect(
		IMAPC_COMMAND_STATE_DISCONNECTED));
	test_expect_error_string("timed out");
	test_assert(test_imapc_cmd_last_reply_expect(
		IMAPC_COMMAND_STATE_DISCONNECTED));
	test_expect_no_more_errors();
	test_assert(test_imapc_cmd_last_reply_expect(
		IMAPC_COMMAND_STATE_DISCONNECTED));
}

static void test_imapc_reconnect_resend_cmds_failed_server(void)
{
	test_server_wait_connection(&server, TRUE);
	test_assert(test_imapc_server_expect(
		"1 LOGIN \"testuser\" \"testpass\""));
	o_stream_nsend_str(server.output, "1 OK \r\n");

	test_assert(test_imapc_server_expect("2 RETRY1"));
	test_assert(test_imapc_server_expect("3 RETRY2"));
	test_assert(test_imapc_server_expect("4 DISCONNECT"));
	test_server_disconnect(&server);

	i_sleep_intr_secs(60);
}

static void test_imapc_reconnect_resend_commands_failed(void)
{
	struct imapc_client_settings set = test_imapc_default_settings;

	test_begin("imapc reconnect resend commands failed");
	test_run_client_server(&set,
			       test_imapc_reconnect_resend_cmds_failed_client,
			       test_imapc_reconnect_resend_cmds_failed_server);
	test_end();
}

/*
 * imapc reconnect mailbox
 */

static void test_imapc_reconnect_mailbox_client(void)
{
	struct imapc_command *cmd;
	struct imapc_client_mailbox *box;

	/* login to server */
	imapc_client_set_login_callback(imapc_client,
					imapc_login_callback, NULL);
	imapc_client_login(imapc_client);
	imapc_client_run(imapc_client);
	test_assert(imapc_login_last_reply == IMAPC_COMMAND_STATE_OK);
	imapc_login_last_reply = IMAPC_COMMAND_STATE_INVALID;

	/* select a mailbox */
	box = imapc_client_mailbox_open(imapc_client, NULL);
	imapc_client_mailbox_set_reopen_cb(box, imapc_reopen_callback, box);

	cmd = imapc_client_mailbox_cmd(box, imapc_command_callback, NULL);
	imapc_command_set_flags(cmd, IMAPC_COMMAND_FLAG_SELECT);
	imapc_command_send(cmd, "SELECT");
	imapc_client_run(imapc_client);
	test_assert(test_imapc_cmd_last_reply_expect(IMAPC_COMMAND_STATE_OK));

	/* send a command */
	cmd = imapc_client_mailbox_cmd(box, imapc_command_callback, NULL);
	imapc_command_set_flags(cmd, IMAPC_COMMAND_FLAG_RETRIABLE);
	imapc_command_send(cmd, "RETRY");

	/* disconnect & reconnect automatically */
	cmd = imapc_client_cmd(imapc_client, imapc_command_callback, NULL);
	imapc_command_send(cmd, "DISCONNECT");
	test_expect_error_string("reconnecting");
	imapc_client_run(imapc_client);
	test_expect_no_more_errors();
	test_assert(test_imapc_cmd_last_reply_expect(
		IMAPC_COMMAND_STATE_DISCONNECTED));

	/* continue reconnection */
	test_assert(test_imapc_cmd_last_reply_expect(IMAPC_COMMAND_STATE_OK));
	test_assert(test_imapc_cmd_last_reply_expect(IMAPC_COMMAND_STATE_OK));

	imapc_client_mailbox_close(&box);
}

static void test_imapc_reconnect_mailbox_server(void)
{
	test_server_wait_connection(&server, TRUE);
	test_assert(test_imapc_server_expect(
		"1 LOGIN \"testuser\" \"testpass\""));
	o_stream_nsend_str(server.output, "1 OK \r\n");

	test_assert(test_imapc_server_expect("2 SELECT"));
	o_stream_nsend_str(server.output, "2 OK \r\n");

	test_assert(test_imapc_server_expect("3 RETRY"));
	test_assert(test_imapc_server_expect("4 DISCONNECT"));
	test_server_disconnect_and_wait(TRUE);

	test_assert(test_imapc_server_expect(
		"5 LOGIN \"testuser\" \"testpass\""));
	o_stream_nsend_str(server.output, "5 OK \r\n");
	test_assert(test_imapc_server_expect("6 SELECT"));
	o_stream_nsend_str(server.output, "6 OK \r\n");
	test_assert(test_imapc_server_expect("3 RETRY"));
	o_stream_nsend_str(server.output, "3 OK \r\n");

	test_assert(test_imapc_server_expect("7 LOGOUT"));
	o_stream_nsend_str(server.output, "7 OK \r\n");

	test_assert(i_stream_read_next_line(server.input) == NULL);
}

static void test_imapc_reconnect_mailbox(void)
{
	struct imapc_client_settings set = test_imapc_default_settings;

	test_begin("imapc reconnect mailbox");
	test_run_client_server(&set, test_imapc_reconnect_mailbox_client,
			       test_imapc_reconnect_mailbox_server);
	test_end();
}

/*
 * imapc_client_get_capabilities()
 */

static void test_imapc_client_get_capabilities_client(void)
{
	enum imapc_capability capabilities;

	test_assert(imapc_client_get_capabilities(imapc_client, &capabilities) == 0);
	test_assert(capabilities == (IMAPC_CAPABILITY_IMAP4REV1 |
				     IMAPC_CAPABILITY_UNSELECT |
				     IMAPC_CAPABILITY_QUOTA));
}

static void test_imapc_client_get_capabilities_server(void)
{
	test_server_wait_connection(&server, TRUE);
	test_assert(test_imapc_server_expect(
		"1 LOGIN \"testuser\" \"testpass\""));
	o_stream_nsend_str(server.output, "1 OK \r\n");

	test_assert(test_imapc_server_expect("2 LOGOUT"));
	o_stream_nsend_str(server.output, "2 OK \r\n");

	test_assert(i_stream_read_next_line(server.input) == NULL);
}

static void test_imapc_client_get_capabilities(void)
{
	struct imapc_client_settings set = test_imapc_default_settings;

	test_begin("imapc_client_get_capabilities()");
	test_run_client_server(&set, test_imapc_client_get_capabilities_client,
			       test_imapc_client_get_capabilities_server);
	test_end();
}

/*
 * imapc_client_get_capabilities() reconnected
 */

static void test_imapc_client_get_capabilities_reconnected_client(void)
{
	enum imapc_capability capabilities;

	test_expect_error_string("Server disconnected unexpectedly");
	test_assert(imapc_client_get_capabilities(imapc_client,
						  &capabilities) == 0);
	test_assert(capabilities == (IMAPC_CAPABILITY_IMAP4REV1 |
				     IMAPC_CAPABILITY_UNSELECT |
				     IMAPC_CAPABILITY_QUOTA));
	test_expect_no_more_errors();
}

static void test_imapc_client_get_capabilities_reconnected_server(void)
{
	test_server_wait_connection(&server, TRUE);
	test_server_disconnect_and_wait(TRUE);

	test_assert(test_imapc_server_expect(
		"2 LOGIN \"testuser\" \"testpass\""));
	o_stream_nsend_str(server.output, "2 OK \r\n");

	test_assert(test_imapc_server_expect("3 LOGOUT"));
	o_stream_nsend_str(server.output, "3 OK \r\n");

	test_assert(i_stream_read_next_line(server.input) == NULL);
}

static void test_imapc_client_get_capabilities_reconnected(void)
{
	struct imapc_client_settings set = test_imapc_default_settings;

	test_begin("imapc_client_get_capabilities() reconnected");

	test_run_client_server(
		&set, test_imapc_client_get_capabilities_reconnected_client,
		test_imapc_client_get_capabilities_reconnected_server);
	test_end();
}

/*
 * imapc_client_get_capabilities() disconnected
 */

static void test_imapc_client_get_capabilities_disconnected_client(void)
{
	enum imapc_capability capabilities;

	test_expect_errors(2);
	test_assert(imapc_client_get_capabilities(imapc_client,
						  &capabilities) < 0);
	test_expect_no_more_errors();
}

static void test_imapc_client_get_capabilities_disconnected_server(void)
{
	test_server_wait_connection(&server, TRUE);
	test_server_disconnect_and_wait(TRUE);
}

static void test_imapc_client_get_capabilities_disconnected(void)
{
	struct imapc_client_settings set = test_imapc_default_settings;

	test_begin("imapc_client_get_capabilities() disconnected");

	test_run_client_server(
		&set, test_imapc_client_get_capabilities_disconnected_client,
		test_imapc_client_get_capabilities_disconnected_server);
	test_end();
}

/*
 * Main
 */

static void main_init(void)
{
	/* nothing yet */
}

static void main_deinit(void)
{
	/* nothing yet; also called from sub-processes */
}

int main(int argc ATTR_UNUSED, char *argv[])
{
	int c;
	int ret;

	static void (*const test_functions[])(void) = {
		test_imapc_connect_failed,
		test_imapc_banner_hangs,
		test_imapc_login_hangs,
		test_imapc_login_fails,
		test_imapc_reconnect,
		test_imapc_reconnect_resend_commands,
		test_imapc_reconnect_resend_commands_failed,
		test_imapc_reconnect_mailbox,
		test_imapc_client_get_capabilities,
		test_imapc_client_get_capabilities_reconnected,
		test_imapc_client_get_capabilities_disconnected,
		NULL
	};

	lib_init();
	main_init();

	while ((c = getopt(argc, argv, "D")) > 0) {
		switch (c) {
		case 'D':
			debug = TRUE;
			break;
		default:
			i_fatal("Usage: %s [-D]", argv[0]);
		}
	}

	test_subprocesses_init(debug);
	test_imapc_default_settings.debug = debug;

	/* listen on localhost */
	i_zero(&bind_ip);
	bind_ip.family = AF_INET;
	bind_ip.u.ip4.s_addr = htonl(INADDR_LOOPBACK);

	ret = test_run(test_functions);

	test_subprocesses_deinit();
	main_deinit();
	lib_deinit();

	return ret;
}
