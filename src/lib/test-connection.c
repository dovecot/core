/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "ioloop.h"
#include "connection.h"
#include "istream.h"
#include "ostream.h"
#include "strnum.h"
#include "strescape.h"

#include <unistd.h>

static const struct connection_settings client_set =
{
	.service_name_in = "TEST-S",
	.service_name_out = "TEST-C",
	.major_version = 1,
	.minor_version = 0,
	.client = TRUE,
	.input_max_size = (size_t)-1,
	.output_max_size = (size_t)-1,
};

static const struct connection_settings server_set =
{
	.service_name_in = "TEST-C",
	.service_name_out = "TEST-S",
	.major_version = 1,
	.minor_version = 0,
	.client = FALSE,
	.input_max_size = (size_t)-1,
	.output_max_size = (size_t)-1,
};

static bool received_quit = FALSE;
static bool was_resumed = FALSE;
static bool was_idle_killed = FALSE;
static int received_count = 0;

static void test_connection_run(const struct connection_settings *set_s,
				const struct connection_settings *set_c,
				const struct connection_vfuncs *v_s,
				const struct connection_vfuncs *v_c,
				unsigned int iter_count)
{
	int fds[2];

	struct ioloop *loop = io_loop_create();
	struct connection_list *clients = connection_list_init(set_c, v_c);
	struct connection_list *servers = connection_list_init(set_s, v_s);
	struct connection *conn_c = i_new(struct connection, 1);
	struct connection *conn_s = i_new(struct connection, 1);

	conn_s->ioloop = loop;
	conn_c->ioloop = loop;

	for(unsigned int iters = 0; iters < iter_count; iters++) {
		test_assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

		connection_init_server(servers, conn_s, "client", fds[1], fds[1]);
		connection_init_client_fd(clients, conn_c, "server", fds[0], fds[0]);

		io_loop_run(loop);

		connection_deinit(conn_c);
		connection_deinit(conn_s);
	}

	i_free(conn_c);
	i_free(conn_s);

	connection_list_deinit(&clients);
	connection_list_deinit(&servers);

	io_loop_destroy(&loop);
}

/* BEGIN SIMPLE TEST */

static void test_connection_simple_client_connected(struct connection *conn, bool success)
{
	if (conn->list->set.client)
		o_stream_nsend_str(conn->output, "QUIT\n");
	test_assert(success);
};

static int
test_connection_simple_input_args(struct connection *conn, const char *const *args)
{
	if (strcmp(args[0], "QUIT") == 0) {
		received_quit = TRUE;
		connection_disconnect(conn);
		return 0;
	}
	i_error("invalid input");
	return -1;
}

static void test_connection_simple_destroy(struct connection *conn)
{
	io_loop_stop(conn->ioloop);
	connection_disconnect(conn);
}

static const struct connection_vfuncs simple_v =
{
	.client_connected = test_connection_simple_client_connected,
	.input_args = test_connection_simple_input_args,
	.destroy = test_connection_simple_destroy,
};

static void test_connection_simple(void)
{
	test_begin("connection simple");

	test_connection_run(&server_set, &client_set, &simple_v, &simple_v, 10);

	test_assert(received_quit);
	received_quit = FALSE;

	test_end();
}

/* BEGIN NO INPUT TEST */

static const struct connection_settings no_input_client_set =
{
	.service_name_in = "TEST-S",
	.service_name_out = "TEST-C",
	.major_version = 1,
	.minor_version = 0,
	.client = TRUE,
	.input_max_size = 0,
	.output_max_size = (size_t)-1,
};

static const struct connection_settings no_input_server_set =
{
	.service_name_in = "TEST-C",
	.service_name_out = "TEST-S",
	.major_version = 1,
	.minor_version = 0,
	.client = FALSE,
	.input_max_size = 0,
	.output_max_size = (size_t)-1,
};

static void
test_connection_no_input_input(struct connection *conn)
{
	const char *input;
	struct istream *is = i_stream_create_fd(conn->fd_in, -1);
	i_stream_set_blocking(is, FALSE);
	while ((input = i_stream_read_next_line(is)) != NULL) {
		const char *const *args = t_strsplit_tabescaped(input);
		if (!conn->handshake_received) {
			if (connection_handshake_args_default(conn, args) > -1)
				conn->handshake_received = TRUE;
			continue;
		}
		if (strcmp(args[0], "QUIT") == 0) {
			received_quit = TRUE;
			io_loop_stop(conn->ioloop);
			break;
		}
	}
	i_stream_unref(&is);
}

static const struct connection_vfuncs no_input_v =
{
	.client_connected = test_connection_simple_client_connected,
	.input = test_connection_no_input_input,
	.destroy = test_connection_simple_destroy,
};

static void test_connection_no_input(void)
{
	test_begin("connection no input stream");

	test_connection_run(&no_input_server_set, &no_input_client_set,
			    &no_input_v, &no_input_v, 1);

	test_assert(received_quit);
	received_quit = FALSE;

	test_end();
}

/* BEGIN HANDSHAKE TEST */
static void test_connection_custom_handshake_client_connected(struct connection *conn, bool success)
{
	if (conn->list->set.client)
		o_stream_nsend_str(conn->output, "HANDSHAKE\tFRIEND\n");
	test_assert(success);
};

static int test_connection_custom_handshake_args(struct connection *conn,
						 const char *const *args)
{
	if (!conn->version_received) {
		if (connection_handshake_args_default(conn, args) < 0)
			return -1;
		return 0;
	}
	if (!conn->handshake_received) {
		if (strcmp(args[0], "HANDSHAKE") == 0 &&
		    strcmp(args[1], "FRIEND") == 0) {
			if (!conn->list->set.client)
				o_stream_nsend_str(conn->output, "HANDSHAKE\tFRIEND\n");
			else
				o_stream_nsend_str(conn->output, "QUIT\n");
			return 1;
		}
		return -1;
	}
	return 1;
}

static const struct connection_vfuncs custom_handshake_v =
{
	.client_connected = test_connection_custom_handshake_client_connected,
	.input_args = test_connection_simple_input_args,
	.handshake_args = test_connection_custom_handshake_args,
	.destroy = test_connection_simple_destroy,
};

static void test_connection_custom_handshake(void)
{
	test_begin("connection custom handshake");

	test_connection_run(&server_set, &client_set, &custom_handshake_v,
			    &custom_handshake_v, 10);

	test_assert(received_quit);
	received_quit = FALSE;

	test_end();
}

/* BEGIN PING PONG TEST */

static int test_connection_ping_pong_input_args(struct connection *conn, const char *const *args)
{
	unsigned int n;
	test_assert(args[0] != NULL && args[1] != NULL);
	if (args[0] == NULL || args[1] == NULL)
		return -1;
	if (str_to_uint(args[1], &n) < 0)
		return -1;
	if (n > 10)
		o_stream_nsend_str(conn->output, "QUIT\t0\n");
	else if (strcmp(args[0], "QUIT") == 0)
		connection_disconnect(conn);
	else if (strcmp(args[0], "PING") == 0) {
		received_count++;
		o_stream_nsend_str(conn->output, t_strdup_printf("PONG\t%u\n", n+1));
	} else if (strcmp(args[0], "PONG") == 0)
		o_stream_nsend_str(conn->output, t_strdup_printf("PING\t%u\n", n));
	else
		return -1;
	return 1;
}

static void test_connection_ping_pong_client_connected(struct connection *conn, bool success)
{
	o_stream_nsend_str(conn->output, "PING\t1\n");
	test_assert(success);
};

static const struct connection_vfuncs ping_pong_v =
{
	.client_connected = test_connection_ping_pong_client_connected,
	.input_args = test_connection_ping_pong_input_args,
	.destroy = test_connection_simple_destroy,
};

static void test_connection_ping_pong(void)
{
	test_begin("connection ping pong");

	test_connection_run(&server_set, &client_set, &ping_pong_v,
			    &ping_pong_v, 10);

	test_assert(received_count == 100);

	test_end();
}

/* BEGIN INPUT FULL TEST */

static const struct connection_settings input_full_client_set =
{
	.service_name_in = "TEST-S",
	.service_name_out = "TEST-C",
	.major_version = 1,
	.minor_version = 0,
	.client = TRUE,
	.input_max_size = 100,
	.output_max_size = (size_t)-1,
};

static int test_connection_input_full_input_args(struct connection *conn,
						 const char *const *args ATTR_UNUSED)
{
	/* send a long line */
	for (unsigned int i = 0; i < 200; i++)
		o_stream_nsend(conn->output, "c", 1);
	return 1;
}

static void test_connection_input_full_destroy(struct connection *conn)
{
	test_assert(conn->disconnect_reason == CONNECTION_DISCONNECT_BUFFER_FULL ||
		    conn->list->set.client == FALSE);
	test_connection_simple_destroy(conn);
}

static const struct connection_vfuncs input_full_v =
{
	.client_connected = test_connection_simple_client_connected,
	.input_args = test_connection_input_full_input_args,
	.destroy = test_connection_input_full_destroy,
};

static void test_connection_input_full(void)
{
	test_begin("connection input full");

	test_connection_run(&server_set, &input_full_client_set, &input_full_v,
			    &simple_v, 10);
	test_end();
}

/* BEGIN RESUME TEST */
static struct timeout *to_send_quit = NULL;
static struct timeout *to_resume = NULL;

static void test_connection_resume_client_connected(struct connection *conn, bool success)
{
	test_assert(success);
	o_stream_nsend_str(conn->output, "BEGIN\n");
}

static void test_connection_resume_continue(struct connection *conn)
{
	timeout_remove(&to_resume);
	/* ensure QUIT wasn't received early */
	was_resumed = !received_quit;
	connection_input_resume(conn);
}

static void test_connection_resume_send_quit(struct connection *conn)
{
	timeout_remove(&to_send_quit);
	o_stream_nsend_str(conn->output, "QUIT\n");
}

static int test_connection_resume_input_args(struct connection *conn,
					     const char *const *args)
{
	test_assert(args[0] != NULL);
	if (args[0] == NULL)
		return -1;

	if (strcmp(args[0], "BEGIN") == 0) {
		o_stream_nsend_str(conn->output, "HALT\n");
		to_send_quit = timeout_add_short(10, test_connection_resume_send_quit, conn);
	} else if (strcmp(args[0], "HALT") == 0) {
		connection_input_halt(conn);
		to_resume = timeout_add_short(100, test_connection_resume_continue, conn);
	} else if (strcmp(args[0], "QUIT") == 0) {
		received_quit = TRUE;
		connection_disconnect(conn);
	}

	return 1;
}

static const struct connection_vfuncs resume_v =
{
	.client_connected = test_connection_resume_client_connected,
	.input_args = test_connection_resume_input_args,
	.destroy = test_connection_simple_destroy,
};

static void test_connection_resume(void)
{
	test_begin("connection resume");

	was_resumed = received_quit = FALSE;
	test_connection_run(&server_set, &client_set, &resume_v, &resume_v, 1);

	test_assert(was_resumed);
	test_assert(received_quit);
	was_resumed = received_quit = FALSE;

	test_end();
}

/* BEGIN IDLE KILL TEST */

static void
test_connection_idle_kill_client_connected(struct connection *conn ATTR_UNUSED,
					   bool success)
{
	test_assert(success);
};

static const struct connection_settings idle_kill_server_set =
{
	.service_name_in = "TEST-C",
	.service_name_out = "TEST-S",
	.major_version = 1,
	.minor_version = 0,
	.client = FALSE,
	.input_max_size = (size_t)-1,
	.output_max_size = (size_t)-1,
	.input_idle_timeout_secs = 1,
};

static void test_connection_idle_kill_timeout(struct connection *conn)
{
	was_idle_killed = TRUE;
	o_stream_nsend_str(conn->output, "QUIT\n");
}

static const struct connection_vfuncs idle_kill_v =
{
	.client_connected = test_connection_idle_kill_client_connected,
	.input_args = test_connection_simple_input_args,
	.destroy = test_connection_simple_destroy,
	.idle_timeout = test_connection_idle_kill_timeout,
};

static void test_connection_idle_kill(void)
{
	test_begin("connection idle kill");

	was_idle_killed = received_quit = FALSE;
	test_connection_run(&idle_kill_server_set, &client_set, &idle_kill_v,
			    &idle_kill_v, 1);

	test_assert(received_quit);
	test_assert(was_idle_killed);
	was_idle_killed = received_quit = FALSE;

	test_end();
}

/* BEGIN HANDSHAKE FAILED TEST (version) */

static void test_connection_handshake_failed_destroy(struct connection *conn)
{
	test_assert(conn->disconnect_reason == CONNECTION_DISCONNECT_HANDSHAKE_FAILED);
	test_connection_simple_destroy(conn);
}

static const struct connection_vfuncs handshake_failed_version_v =
{
	.client_connected = test_connection_simple_client_connected,
	.input_args = test_connection_simple_input_args,
	.destroy = test_connection_handshake_failed_destroy,
};

static void test_connection_handshake_failed_version(void)
{
	static const struct connection_settings client_sets[] = {
	{
		.service_name_in = "TEST-S",
		.service_name_out = "TEST-S",
		.major_version = 1,
		.minor_version = 0,
		.client = TRUE,
		.input_max_size = (size_t)-1,
		.output_max_size = (size_t)-1,
	},
	{
		.service_name_in = "TEST-C",
		.service_name_out = "TEST-C",
		.major_version = 1,
		.minor_version = 0,
		.client = TRUE,
		.input_max_size = (size_t)-1,
		.output_max_size = (size_t)-1,
	},
	{
		.service_name_in = "TEST-S",
		.service_name_out = "TEST-C",
		.major_version = 2,
		.minor_version = 0,
		.client = TRUE,
		.input_max_size = (size_t)-1,
		.output_max_size = (size_t)-1,
	}
	};

	static const struct connection_settings client_set_minor = {
		.service_name_in = "TEST-S",
		.service_name_out = "TEST-C",
		.major_version = 1,
		.minor_version = 2,
		.client = TRUE,
		.input_max_size = (size_t)-1,
		.output_max_size = (size_t)-1,
	};

	test_begin("connection handshake failed (version)");

	test_expect_errors(N_ELEMENTS(client_sets));

	/* this should stay FALSE during the version mismatch sets */
	received_quit = FALSE;
	for (size_t i = 0; i < N_ELEMENTS(client_sets); i++) {
		test_connection_run(&server_set, &client_sets[i], &simple_v,
				    &handshake_failed_version_v, 1);
		test_assert(!received_quit);
	}

	received_quit = FALSE;
	test_connection_run(&server_set, &client_set_minor, &simple_v,
			    &simple_v, 1);
	test_assert(received_quit);
	received_quit = FALSE;

	test_end();
}

/* BEGIN HANDSHAKE FAILED TEST (args) */

static int test_connection_handshake_failed_1_args(struct connection *conn ATTR_UNUSED,
						   const char *const *args ATTR_UNUSED)
{
	/* just fail */
	return -1;
}

static const struct connection_vfuncs handshake_failed_1_v =
{
	.client_connected = test_connection_simple_client_connected,
	.input_args = test_connection_simple_input_args,
	.handshake_args = test_connection_handshake_failed_1_args,
	.destroy = test_connection_handshake_failed_destroy,
};

static void test_connection_handshake_failed_args(void)
{
	test_begin("connection handshake failed (handshake_args)");

	test_connection_run(&server_set, &client_set, &simple_v,
			    &handshake_failed_1_v, 10);

	test_end();
}

/* BEGIN HANDSHAKE FAILED TEST (handshake_line) */

static int test_connection_handshake_failed_2_line(struct connection *conn ATTR_UNUSED,
						   const char *line ATTR_UNUSED)
{
	return -1;
}

static const struct connection_vfuncs handshake_failed_2_v =
{
	.client_connected = test_connection_simple_client_connected,
	.input_args = test_connection_simple_input_args,
	.handshake_line = test_connection_handshake_failed_2_line,
	.destroy = test_connection_handshake_failed_destroy,
};

static void test_connection_handshake_failed_line(void)
{
	test_begin("connection handshake failed (handshake_line)");

	test_connection_run(&server_set, &client_set, &simple_v,
			    &handshake_failed_2_v, 10);

	test_end();
}

/* BEGIN HANDSHAKE FAILED TEST (handshake) */

static int test_connection_handshake_failed_3(struct connection *conn ATTR_UNUSED)
{
	return -1;
}

static const struct connection_vfuncs handshake_failed_3_v =
{
	.client_connected = test_connection_simple_client_connected,
	.input_args = test_connection_simple_input_args,
	.handshake = test_connection_handshake_failed_3,
	.destroy = test_connection_handshake_failed_destroy,
};

static void test_connection_handshake_failed_input(void)
{
	test_begin("connection handshake failed (handshake)");

	test_connection_run(&server_set, &client_set, &simple_v,
			    &handshake_failed_3_v, 10);

	test_end();
}

/* BEGIN CONNECTION ERRORED TEST (ensure correct error) */

static void test_connection_errored_client_connected(struct connection *conn,
						     bool success)
{
	test_assert(success);
	o_stream_nsend_str(conn->output, "HELLO\n");
}

static void test_connection_errored_destroy(struct connection *conn)
{
	test_assert(conn->disconnect_reason == CONNECTION_DISCONNECT_DEINIT);
	test_connection_simple_destroy(conn);
}

static int test_connection_errored_input_line(struct connection *conn ATTR_UNUSED,
					      const char *line)
{
	if (str_begins(line, "VERSION"))
		return 1;
	return -1;
}

static const struct connection_vfuncs test_connection_errored_1_v =
{
	.client_connected = test_connection_errored_client_connected,
	.input_line = test_connection_errored_input_line,
	.destroy = test_connection_errored_destroy,
};

static void test_connection_input_error_reason(void)
{
	test_begin("connection input error (correct disconnect reason)");

	test_connection_run(&server_set, &client_set, &test_connection_errored_1_v,
			    &test_connection_errored_1_v, 10);

	test_end();
}

/* END CONNECTION ERRORED TEST */

/* BEGIN NO VERSION TEST */

static const struct connection_settings no_version_client_set =
{
	.major_version = 0,
	.minor_version = 0,
	.client = TRUE,
	.input_max_size = (size_t)-1,
	.output_max_size = (size_t)-1,
	.dont_send_version = TRUE,
};

static const struct connection_settings no_version_server_set =
{
	.major_version = 0,
	.minor_version = 0,
	.input_max_size = (size_t)-1,
	.output_max_size = (size_t)-1,
	.dont_send_version = TRUE,
};

static void test_connection_no_version(void)
{
        test_begin("connection no version sent");

        test_connection_run(&no_version_server_set, &no_version_client_set,
			    &simple_v, &simple_v, 10);

        test_end();
}

/* END NO VERSION TEST */

void test_connection(void)
{
	test_connection_simple();
	test_connection_no_input();
	test_connection_custom_handshake();
	test_connection_ping_pong();
	test_connection_input_full();
	test_connection_resume();
	test_connection_idle_kill();
	test_connection_handshake_failed_version();
	test_connection_handshake_failed_args();
	test_connection_handshake_failed_line();
	test_connection_handshake_failed_input();
	test_connection_input_error_reason();
	test_connection_no_version();
}
