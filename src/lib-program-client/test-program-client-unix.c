/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "test-lib.h"
#include "mempool.h"
#include "buffer.h"
#include "str.h"
#include "array.h"
#include "istream.h"
#include "ostream.h"
#include "net.h"
#include "iostream-temp.h"
#include "program-client.h"

#include <unistd.h>

static const char *TEST_SOCKET = "program-client-test.sock";
static const char *pclient_test_io_string =
	"Lorem ipsum dolor sit amet, consectetur adipiscing elit.\n"
	"Praesent vehicula ac leo vel placerat. Nullam placerat \n"
	"volutpat leo, sed ultricies felis pulvinar quis. Nam \n"
	"tempus, augue ut tempor cursus, neque felis commodo lacus, \n"
	"sit amet tincidunt arcu justo vel augue. Proin dapibus \n"
	"vulputate maximus. Mauris congue lacus felis, sed varius \n"
	"leo finibus sagittis. Cum sociis natoque penatibus et magnis \n"
	"dis parturient montes, nascetur ridiculus mus. Aliquam \n"
	"laoreet arcu a hendrerit consequat. Duis vitae erat tellus.";

static struct program_client_parameters pc_params = {
	.client_connect_timeout_msecs = 1000,
	.input_idle_timeout_msecs = 5000,
};
static struct event *event;

static struct test_server {
	struct ioloop *ioloop;
	struct io *io;
	struct timeout *to;
	struct test_client *client;
	struct program_client *async_client;
	int listen_fd;
} test_globals;

struct test_client {
	pool_t pool;
	int fd;
	struct io *io;
	struct istream *in;
	struct ostream *out;
	struct ostream *os_body;
	struct istream *body;
	ARRAY_TYPE(const_string) args;
	enum {
		CLIENT_STATE_INIT,
		CLIENT_STATE_VERSION,
		CLIENT_STATE_ARGS,
		CLIENT_STATE_BODY
	} state;
};

static void test_program_client_destroy(struct test_client **_client)
{
	struct test_client *client = *_client;
	*_client = NULL;

	if (o_stream_finish(client->out) < 0)
		i_error("output error: %s", o_stream_get_error(client->out));

	io_remove(&client->io);
	o_stream_unref(&client->out);
	i_stream_unref(&client->in);
	o_stream_unref(&client->os_body);
	i_stream_unref(&client->body);
	i_close_fd(&client->fd);
	pool_unref(&client->pool);
	test_globals.client = NULL;
}

static int
test_program_input_handle(struct test_client *client, const char *line)
{
	int cmp = -1;
	const char *arg;

	switch(client->state) {
	case CLIENT_STATE_INIT:
		cmp = strncmp(line, "VERSION\tscript\t", 15);
		test_assert(cmp == 0);
		if (cmp == 0)
			client->state = CLIENT_STATE_VERSION;
		else
			return -1;
		break;
	case CLIENT_STATE_VERSION:
		if (strcmp(line, "noreply") == 0 ||
		    strcmp(line, "-") == 0)
			cmp = 0;
		test_assert(cmp == 0);
		if (cmp == 0)
			client->state = CLIENT_STATE_ARGS;
		else
			return -1;
		break;
	case CLIENT_STATE_ARGS:
		if (strcmp(line, "") == 0) {
			array_append_zero(&client->args);
			client->state = CLIENT_STATE_BODY;
			return 0;
		}
		arg = p_strdup(client->pool, line);
		array_push_back(&client->args, &arg);
		break;
	case CLIENT_STATE_BODY:
		if (client->os_body == NULL) {
			client->os_body = iostream_temp_create_named(
				".dovecot.test.", 0, "test_program_input body");
		}
		switch (o_stream_send_istream(client->os_body, client->in)) {
		case OSTREAM_SEND_ISTREAM_RESULT_ERROR_OUTPUT:
			i_panic("Cannot write to ostream-temp: %s",
				o_stream_get_error(client->os_body));
		case OSTREAM_SEND_ISTREAM_RESULT_ERROR_INPUT:
			i_warning("Client stream error: %s",
				  i_stream_get_error(client->in));
			return -1;
		case OSTREAM_SEND_ISTREAM_RESULT_WAIT_INPUT:
			i_debug("waiting for input");
			break;
		case OSTREAM_SEND_ISTREAM_RESULT_FINISHED:
			client->body = iostream_temp_finish(&client->os_body,
							    SIZE_MAX);
			return 1;
		case OSTREAM_SEND_ISTREAM_RESULT_WAIT_OUTPUT:
			i_panic("Cannot write to ostream-temp");
		}
		break;
	}
	return 0;
}

static void test_program_end(struct test_client *client)
{
	timeout_remove(&test_globals.to);
	test_program_client_destroy(&client);
}

static void test_program_run(struct test_client *client)
{
	const char *const *args;
	unsigned int count;

	timeout_remove(&test_globals.to);

	args = array_get(&client->args, &count);
	test_assert(count >= 2);
	if (strcmp(args[0], "test_program_success") == 0) {
		/* Return hello world */
		test_assert(count >= 3);
		o_stream_nsend_str(client->out, t_strdup_printf("%s %s\n+\n",
				   args[1], args[2]));
	} else if (strcmp(args[0], "test_program_io") == 0) {
		o_stream_nsend_istream(client->out, client->body);
		o_stream_nsend_str(client->out, "+\n");
	} else if (strcmp(args[0], "test_program_failure") == 0) {
		o_stream_nsend_str(client->out, "-\n");
	}
	if (count < 3 || strcmp(args[1], "slow_disconnect") != 0)
		test_program_client_destroy(&client);
	else {
		test_globals.to = timeout_add_short(
			500, test_program_end, client);
	}
}

static void test_program_input(struct test_client *client)
{
	const char *line = NULL;
	int ret = 0;

	while (ret >= 0) {
		if (client->state == CLIENT_STATE_BODY) {
			ret = test_program_input_handle(client, NULL);
			break;
		}
		while (client->state < CLIENT_STATE_BODY) {
			line = i_stream_read_next_line(client->in);
			if (line == NULL) {
				ret = 0;
				break;
			}
			ret = test_program_input_handle(client, line);
			if (ret < 0) {
				i_warning("Client sent invalid line: %s", line);
				break;
			}
		}
	}

	if (ret < 0 || client->in->stream_errno != 0) {
		test_program_client_destroy(&client);
		return;
	}
	if (!client->in->eof)
		return;

	if (client->state != CLIENT_STATE_BODY)
		i_warning("Client prematurely disconnected");

	io_remove(&client->io);
	/* Incur slight delay to check if the connection gets prematurely
	   closed. */
	test_globals.to = timeout_add_short(100, test_program_run, client);
}

static void test_program_connected(struct test_server *server)
{
	struct test_client *client;
	int fd;

	i_assert(server->client == NULL);
	fd = net_accept(server->listen_fd, NULL, NULL); /* makes no sense on unix */
	if (fd < 0)
		i_fatal("Failed to accept connection: %m");

	net_set_nonblock(fd, TRUE);

	pool_t pool = pool_alloconly_create("test_program client", 1024);
	client = p_new(pool, struct test_client, 1);
	client->pool = pool;
	client->fd = fd;
	client->in = i_stream_create_fd(fd, SIZE_MAX);
	client->out = o_stream_create_fd(fd, SIZE_MAX);
	client->io = io_add_istream(client->in, test_program_input, client);
	p_array_init(&client->args, client->pool, 2);
	server->client = client;
}

static void test_program_setup(void)
{
	test_begin("test_program_setup");

	test_globals.ioloop = io_loop_create();
	io_loop_set_current(test_globals.ioloop);

	/* Create listener */
	test_globals.listen_fd = net_listen_unix_unlink_stale(TEST_SOCKET, 100);
	if (test_globals.listen_fd < 0)
		i_fatal("Cannot create unix listener: %m");

	test_globals.io = io_add(test_globals.listen_fd, IO_READ,
				 test_program_connected, &test_globals);
	test_end();
}

static void test_program_teardown(void)
{
	test_begin("test_program_teardown");

	if (test_globals.client != NULL)
		test_program_client_destroy(&test_globals.client);

	if (test_globals.async_client != NULL) {
		program_client_wait(test_globals.async_client);
		program_client_destroy(&test_globals.async_client);
	}

	io_remove(&test_globals.io);
	i_close_fd(&test_globals.listen_fd);
	io_loop_destroy(&test_globals.ioloop);
	i_unlink(TEST_SOCKET);
	test_end();
}

static void test_program_async_callback(enum program_client_exit_status result,
					int *ret)
{
	*ret = (int)result;
	io_loop_stop(current_ioloop);
}

static void test_program_success(void)
{
	struct program_client *pc;
	int ret;

	const char *const args[] = {
		"test_program_success", "hello", "world", NULL
	};

	test_begin("test_program_success");

	pc_params.no_reply = FALSE;
	pc = program_client_unix_create(event, TEST_SOCKET, args, &pc_params);

	buffer_t *output = buffer_create_dynamic(default_pool, 16);
	struct ostream *os = test_ostream_create(output);
	program_client_set_output(pc, os);

	program_client_run_async(pc, test_program_async_callback, &ret);

	io_loop_run(current_ioloop);

	test_assert(ret == 1);
	test_assert(strcmp(str_c(output), "hello world\n") == 0);

	program_client_destroy(&pc);

	o_stream_unref(&os);
	buffer_free(&output);

	test_end();
}

static void test_program_io_common(const char *const *args)
{
	struct program_client *pc;
	int ret;

	pc_params.no_reply = FALSE;
	pc = program_client_unix_create(event, TEST_SOCKET, args, &pc_params);

	struct istream *is = test_istream_create(pclient_test_io_string);
	program_client_set_input(pc, is);

	buffer_t *output = buffer_create_dynamic(default_pool, 16);
	struct ostream *os = test_ostream_create(output);
	program_client_set_output(pc, os);

	program_client_run_async(pc, test_program_async_callback, &ret);

	io_loop_run(current_ioloop);

	test_assert(ret == 1);
	test_assert(strcmp(str_c(output), pclient_test_io_string) == 0);

	program_client_destroy(&pc);

	i_stream_unref(&is);
	o_stream_unref(&os);
	buffer_free(&output);
}

static void test_program_io(void)
{
	const char *args[3] = {
		"test_program_io", NULL, NULL
	};

	test_begin("test_program_io (async)");

	test_program_io_common(args);

	test_end();

	args[1] = "slow_disconnect";

	test_begin("test_program_io (async, slow disconnect)");

	test_program_io_common(args);

	test_end();
}

static void test_program_failure(void)
{
	struct program_client *pc;
	int ret;

	const char *const args[] = {
		"test_program_failure", NULL
	};

	test_begin("test_program_failure");

	pc_params.no_reply = FALSE;
	pc = program_client_unix_create(event, TEST_SOCKET, args, &pc_params);

	buffer_t *output = buffer_create_dynamic(default_pool, 16);
	struct ostream *os = test_ostream_create(output);
	program_client_set_output(pc, os);

	program_client_run_async(pc, test_program_async_callback, &ret);

	io_loop_run(current_ioloop);

	test_assert(ret == 0);

	program_client_destroy(&pc);

	o_stream_unref(&os);
	buffer_free(&output);

	test_end();
}

static void test_program_noreply(void)
{
	struct program_client *pc;
	int ret;

	const char *const args[] = {
		"test_program_success", "hello", "world", NULL
	};

	test_begin("test_program_noreply");

	pc_params.no_reply = TRUE;
	pc = program_client_unix_create(event, TEST_SOCKET, args, &pc_params);

	program_client_run_async(pc, test_program_async_callback, &ret);

	io_loop_run(current_ioloop);

	test_assert(ret == 1);

	program_client_destroy(&pc);

	test_end();
}

static void test_program_sync(void)
{
	struct program_client *pc;
	int ret;

	const char *const args[] = {
		"test_program_io", NULL, NULL
	};

	test_begin("test_program_sync");

	pc_params.no_reply = TRUE;
	pc = program_client_unix_create(event, TEST_SOCKET, args, &pc_params);
	ret = program_client_run(pc);
	test_assert(ret == 1);

	program_client_destroy(&pc);
	test_program_end(test_globals.client);

	test_end();
}

static void test_program_async_wait_finish(enum program_client_exit_status ret,
					   struct program_client *client ATTR_UNUSED)
{
	test_assert(ret == PROGRAM_CLIENT_EXIT_STATUS_SUCCESS);
	io_loop_stop(current_ioloop);
}

static void test_program_async_wait(void)
{
	const char *const args[] = {
		"test_program_io", NULL, NULL
	};

	test_begin("test_program_async_wait");

	pc_params.no_reply = TRUE;
	test_globals.async_client = program_client_unix_create(event, TEST_SOCKET,
			args, &pc_params);

	program_client_run_async(test_globals.async_client,
				 test_program_async_wait_finish,
				 test_globals.async_client);

	test_end();
}

int main(int argc, char *argv[])
{
	int ret, c;

	void (*tests[])(void) = {
		test_program_setup,
		test_program_success,
		test_program_io,
		test_program_failure,
		test_program_noreply,
		test_program_sync,
		test_program_async_wait,
		test_program_teardown,
		NULL
	};

	lib_init();

	event = event_create(NULL);
	while ((c = getopt(argc, argv, "D")) > 0) {
		switch (c) {
		case 'D':
			event_set_forced_debug(event, TRUE);
			break;
		default:
			i_fatal("Usage: %s [-D]", argv[0]);
		}
	}

	ret = test_run(tests);

	event_unref(&event);
	lib_deinit();
	return ret;
}
