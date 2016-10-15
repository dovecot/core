/* Copyright (c) 2002-2016 Dovecot authors, see the included COPYING file
 */

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

static const char *TEST_SOCKET = "/tmp/program-client-test.sock";
static const char *pclient_test_io_string = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.\n"
					    "Praesent vehicula ac leo vel placerat. Nullam placerat \n"
					    "volutpat leo, sed ultricies felis pulvinar quis. Nam \n"
					    "tempus, augue ut tempor cursus, neque felis commodo lacus, \n"
					    "sit amet tincidunt arcu justo vel augue. Proin dapibus \n"
					    "vulputate maximus. Mauris congue lacus felis, sed varius \n"
					    "leo finibus sagittis. Cum sociis natoque penatibus et magnis \n"
					    "dis parturient montes, nascetur ridiculus mus. Aliquam \n"
					    "laoreet arcu a hendrerit consequat. Duis vitae erat tellus.";

static
struct program_client_settings pc_set = {
	.client_connect_timeout_msecs = 1000,
	.input_idle_timeout_msecs = 5000,
	.debug = TRUE,
};

static
struct test_server {
	struct ioloop *ioloop;
	struct io *io;
	struct timeout *to;
	struct test_client *client;
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

static
void test_program_client_destroy(struct test_client **_client)
{
	struct test_client *client = *_client;
	*_client = NULL;

	if (o_stream_nfinish(client->out) != 0)
		i_error("output error: %s", o_stream_get_error(client->out));

	io_remove(&client->io);
	o_stream_unref(&client->out);
	i_stream_unref(&client->in);
	if (client->os_body != NULL)
		o_stream_unref(&client->os_body);
	if (client->body != NULL)
		i_stream_unref(&client->body);
	close(client->fd);
	pool_unref(&client->pool);
	test_globals.client = NULL;
}

static
int test_program_input_handle(struct test_client *client, const char *line)
{
	size_t siz;
	ssize_t ret;
	const unsigned char *data;
	int cmp;
	const char *arg;

	switch(client->state) {
	case CLIENT_STATE_INIT:
		test_assert((cmp = strcmp(line, "VERSION\tscript\t3\t0")) == 0);
		if (cmp == 0) {
			client->state = CLIENT_STATE_VERSION;
		} else
			return -1;
		break;
	case CLIENT_STATE_VERSION:
		test_assert((cmp = strcmp(line, "-")) == 0);
		if (cmp == 0)
			client->state = CLIENT_STATE_ARGS;
		else
			return -1;
		break;
	case CLIENT_STATE_ARGS:
		if  (strcmp(line, "") == 0) {
			array_append_zero(&client->args);
			client->state = CLIENT_STATE_BODY;
			return 0;
		}
		arg = p_strdup(client->pool, line);
		array_append(&client->args, &arg, 1);
		break;
	case CLIENT_STATE_BODY:
		client->os_body = iostream_temp_create_named("/tmp", 0, "test_program_input body");

		do {
			data = i_stream_get_data(client->in, &siz);
			o_stream_nsend(client->os_body, data, siz);
			i_stream_skip(client->in, siz);
		} while ((ret = i_stream_read(client->in))>0);

		if (ret == 0 && !client->in->eof) break;
		if (ret == -1 && !client->in->eof) return -1;

		if (o_stream_nfinish(client->os_body)<0) {
			i_fatal("Could not write response: %s",
				o_stream_get_error(client->os_body));
		}

		client->body = iostream_temp_finish(&client->os_body, -1);

		return 1;
	}
	return 0;
}

static
void test_program_run(struct test_client *client)
{
	const char *arg;
	size_t siz;
	int ret;
	const unsigned char *data;
	test_assert(array_count(&client->args) > 0);
	arg = *array_idx(&client->args, 0);
	if (strcmp(arg, "test_program_success")==0) {
		/* return hello world */
		o_stream_nsend_str(client->out, t_strdup_printf("%s %s\n+\n",
				   *array_idx(&client->args, 1),
				   *array_idx(&client->args, 2)));
	} else if (strcmp(arg, "test_program_io")==0) {
		do {
			data = i_stream_get_data(client->body, &siz);
			o_stream_nsend(client->out, data, siz);
			i_stream_skip(client->body, siz);
		} while((ret = i_stream_read(client->body))>0);
		o_stream_nsend_str(client->out, "+\n");
	} else if (strcmp(arg, "test_program_failure")==0) {
		o_stream_nsend_str(client->out, "-\n");
	}
}

static
void test_program_input(struct test_client *client)

{
	const char *line = "";

	if (client->state == CLIENT_STATE_BODY) {
		if (test_program_input_handle(client, NULL)==0 && !client->in->eof) return;
	} else {
		line = i_stream_read_next_line(client->in);
		if ((line == NULL && !client->in->eof) ||
		    (line != NULL && test_program_input_handle(client, line) == 0))
			return;
	}

	if (client->in->eof)
		test_program_run(client);

	if (client->state != CLIENT_STATE_BODY) {
		if (client->in->eof)
			i_warning("Client prematurely disconnected");
		else
			i_warning("Client sent invalid line: %s", line);
	}

	test_program_client_destroy(&client);
}

static
void test_program_connected(struct test_server *server)
{
	int fd;
	i_assert(server->client == NULL);
	fd = net_accept(server->listen_fd, NULL, NULL); /* makes no sense on unix */
	if (fd < 0)
		i_fatal("Failed to accept connection: %m");

	pool_t pool = pool_alloconly_create("test_program client", 1024);
	struct test_client *client = p_new(pool, struct test_client, 1);
	client->pool = pool;
	client->fd = fd;
	client->in = i_stream_create_fd(fd, -1, FALSE);
	client->out = o_stream_create_fd(fd, -1, FALSE);
	client->io = io_add_istream(client->in, test_program_input, client);
	p_array_init(&client->args, client->pool, 2);
	server->client = client;
}

static
void test_program_setup(void) {
	test_begin("test_program_setup");
	test_globals.ioloop = io_loop_create();
	io_loop_set_current(test_globals.ioloop);

	/* create listener */
	test_globals.listen_fd = net_listen_unix_unlink_stale(TEST_SOCKET, 100);
	if (test_globals.listen_fd < 0)
		i_fatal("Cannot create unix listener: %m");

	test_globals.io = io_add(test_globals.listen_fd, IO_READ, test_program_connected, &test_globals);
	test_end();
}

static
void test_program_teardown(void)
{
	test_begin("test_program_teardown");
	if (test_globals.client != NULL)
		test_program_client_destroy(&test_globals.client);
	io_remove(&test_globals.io);
	close(test_globals.listen_fd);
	io_loop_destroy(&test_globals.ioloop);
	test_end();
}

static
void test_program_async_callback(int result, int *ret)
{
	*ret = result;
	io_loop_stop(current_ioloop);
}

static
void test_program_success(void) {
	test_begin("test_program_success");
	int ret;

	const char *const args[] = {
		"test_program_success", "hello", "world", NULL
	};

	struct program_client *pc =
		program_client_remote_create(TEST_SOCKET, args, &pc_set, FALSE);

	buffer_t *output = buffer_create_dynamic(default_pool, 16);
	struct ostream *os = o_stream_create_buffer(output);
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

static
void test_program_io(void) {
	test_begin("test_program_io (async)");

	int ret;

	const char *const args[] = {
		"test_program_io", NULL
	};

	struct program_client *pc =
		program_client_remote_create(TEST_SOCKET, args, &pc_set, FALSE);

	struct istream *is = test_istream_create(pclient_test_io_string);
	program_client_set_input(pc, is);

	buffer_t *output = buffer_create_dynamic(default_pool, 16);
	struct ostream *os = o_stream_create_buffer(output);
	program_client_set_output(pc, os);

	program_client_run_async(pc, test_program_async_callback, &ret);

	io_loop_run(current_ioloop);

	test_assert(ret == 1);

	test_assert(strcmp(str_c(output), pclient_test_io_string) == 0);

	program_client_destroy(&pc);

	i_stream_unref(&is);
	o_stream_unref(&os);
	buffer_free(&output);

	test_end();
}

static
void test_program_failure(void) {
	test_begin("test_program_failure");

	int ret;

	const char *const args[] = {
		"test_program_failure", NULL
	};

	struct program_client *pc =
		program_client_remote_create(TEST_SOCKET, args, &pc_set, FALSE);

	buffer_t *output = buffer_create_dynamic(default_pool, 16);
	struct ostream *os = o_stream_create_buffer(output);
	program_client_set_output(pc, os);

	program_client_run_async(pc, test_program_async_callback, &ret);

	io_loop_run(current_ioloop);

	test_assert(ret == 0);

	program_client_destroy(&pc);

	o_stream_unref(&os);
	buffer_free(&output);

	test_end();
}

static
void test_program_noreply(void) {
	test_begin("test_program_noreply");

	int ret;

	const char *const args[] = {
		"test_program_success", "hello", "world", NULL
	};

	struct program_client *pc =
		program_client_remote_create(TEST_SOCKET, args, &pc_set, TRUE);

	program_client_run_async(pc, test_program_async_callback, &ret);

	io_loop_run(current_ioloop);

	test_assert(ret == 1);

	program_client_destroy(&pc);

	test_end();
}

int main(void)
{
	void (*tests[])(void) = {
		test_program_setup,
		test_program_success,
		test_program_io,
		test_program_failure,
		test_program_noreply,
		test_program_teardown,
		NULL
	};

	return test_run(tests);
}
