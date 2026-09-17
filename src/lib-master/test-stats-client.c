/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "net.h"
#include "fd-util.h"
#include "lib-signals.h"
#include "stats-client.h"
#include "test-common.h"
#include "test-subprocess.h"

#include <unistd.h>
#include <signal.h>

#define TEST_SOCKET_PATH "./test-stats-client.socket"
#define TEST_TIMEOUT_SECS 20
#define TEST_EVENT_NAME "testev"
#define TEST_FILTER "(event=\""TEST_EVENT_NAME"\")"

static int fd_listen = -1;

static void test_info_callback(const struct failure_context *ctx ATTR_UNUSED,
			       const char *format ATTR_UNUSED,
			       va_list args ATTR_UNUSED)
{
	/* ignore the message - all we care about is what the stats client
	   sends out */
}

/*
 * Server - runs in a forked process, using blocking I/O.
 */

static int server_accept(struct istream **input_r, struct ostream **output_r)
{
	int fd = net_accept(fd_listen, NULL, NULL);

	if (fd < 0)
		return -1;
	net_set_nonblock(fd, FALSE);
	*input_r = i_stream_create_fd(fd, SIZE_MAX);
	*output_r = o_stream_create_fd_autoclose(&fd, SIZE_MAX);
	return 0;
}

/* Reads input until a line beginning with the given prefix is received.
   Returns -1 if the connection is closed before that. */
static int server_wait_line(struct istream *input, const char *prefix)
{
	const char *line;

	while ((line = i_stream_read_next_line(input)) != NULL) {
		if (str_begins_with(line, prefix))
			return 0;
	}
	return -1;
}

static void server_send_handshake(struct ostream *output)
{
	o_stream_nsend_str(output, "VERSION\tstats-server\t4\t1\n"
			   "FILTER\t"TEST_FILTER"\n");
	o_stream_nsend(output, "", 0);
	(void)o_stream_flush(output);
}

static int test_server(void *context ATTR_UNUSED)
{
	struct istream *input;
	struct ostream *output;
	int ret = 1;

	/* don't hang forever if the client doesn't do what it should */
	alarm(TEST_TIMEOUT_SECS);

	net_set_nonblock(fd_listen, FALSE);
	if (server_accept(&input, &output) < 0)
		i_fatal("net_accept() failed: %m");

	/* the first stats process: handshake, receive an event and then tell
	   the client to switch over to the stats process that replaces us */
	if (server_wait_line(input, "VERSION\t") == 0) {
		server_send_handshake(output);
		if (server_wait_line(input, "EVENT\t") == 0) {
			o_stream_nsend_str(output, "RECONNECT\n");
			(void)o_stream_flush(output);

			struct istream *input2;
			struct ostream *output2;

			/* the second stats process: the client connects to it
			   as soon as it's told to. Don't send the handshake
			   yet - the events in between have to keep using the
			   filter that the previous handshake set, or they are
			   lost. */
			if (server_accept(&input2, &output2) == 0) {
				if (server_wait_line(input2, "VERSION\t") == 0) {
					/* tell the test that the client has
					   reconnected, so it can send the
					   next event */
					test_subprocess_notify_signal_send_parent(SIGHUP);
					if (server_wait_line(input2, "EVENT\t") == 0) {
						ret = 0;
						test_subprocess_notify_signal_send_parent(SIGUSR1);
					}
				}
				i_stream_destroy(&input2);
				o_stream_destroy(&output2);
			}
		}
	}

	i_stream_destroy(&input);
	o_stream_destroy(&output);
	i_close_fd(&fd_listen);
	return ret;
}

/*
 * Client
 */

static void test_sig_notify(const siginfo_t *si ATTR_UNUSED, void *context)
{
	struct ioloop *ioloop = context;

	io_loop_stop(ioloop);
}

static void test_send_event(void)
{
	struct event *event = event_create(NULL);

	event_set_name(event, TEST_EVENT_NAME);
	e_info(event, "test event");
	event_unref(&event);
}

static void test_stats_client_reconnect(void)
{
	struct stats_client *client;
	struct ioloop *ioloop;
	struct timeout *to;

	test_begin("stats client reconnect");

	i_unlink_if_exists(TEST_SOCKET_PATH);
	fd_listen = net_listen_unix(TEST_SOCKET_PATH, 10);
	if (fd_listen == -1)
		i_fatal("net_listen_unix(%s) failed: %m", TEST_SOCKET_PATH);

	test_subprocess_fork(test_server, NULL, FALSE);

	ioloop = io_loop_create();
	/* SIGHUP: the server accepted the reconnection.
	   SIGUSR1: the server received the event that was sent after it. */
	lib_signals_set_handler(SIGHUP, LIBSIG_FLAGS_SAFE,
				test_sig_notify, ioloop);
	lib_signals_set_handler(SIGUSR1, LIBSIG_FLAGS_SAFE,
				test_sig_notify, ioloop);

	client = stats_client_init(TEST_SOCKET_PATH, FALSE);
	/* The first event goes to the stats process that is going away. It
	   replies with RECONNECT. */
	test_send_event();
	to = timeout_add(TEST_TIMEOUT_SECS * 1000, io_loop_stop, ioloop);
	io_loop_run(ioloop);
	timeout_remove(&to);

	/* The client is now connected to the new stats process, which hasn't
	   sent its handshake yet. The event has to be sent anyway. */
	test_send_event();
	to = timeout_add(TEST_TIMEOUT_SECS * 1000, io_loop_stop, ioloop);
	io_loop_run(ioloop);
	timeout_remove(&to);

	stats_client_deinit(&client);
	lib_signals_unset_handler(SIGHUP, test_sig_notify, ioloop);
	lib_signals_unset_handler(SIGUSR1, test_sig_notify, ioloop);
	io_loop_destroy(&ioloop);

	i_close_fd(&fd_listen);
	i_unlink(TEST_SOCKET_PATH);

	test_subprocess_wait_all(TEST_TIMEOUT_SECS);
	test_end();
}

int main(void)
{
	void (*const test_functions[])(void) = {
		test_stats_client_reconnect,
		NULL
	};
	int ret;

	lib_init();
	lib_signals_init();
	i_set_info_handler(test_info_callback);
	test_subprocesses_init();
	test_init_no_event();

	ret = test_run(test_functions);

	lib_signals_deinit();
	lib_deinit();
	return ret;
}
