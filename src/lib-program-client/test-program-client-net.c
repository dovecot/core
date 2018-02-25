/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "test-lib.h"
#include "mempool.h"
#include "buffer.h"
#include "str.h"
#include "array.h"
#include "istream.h"
#include "ostream.h"
#include "istream-dot.h"
#include "ostream-dot.h"
#include "net.h"
#include "iostream-temp.h"
#include "program-client.h"

#include <unistd.h>

static const char *pclient_test_io_string =
	"Lorem ipsum dolor sit amet, consectetur adipiscing elit.\r\n"
	"Praesent vehicula ac leo vel placerat. Nullam placerat \r\n"
	"volutpat leo, sed ultricies felis pulvinar quis. Nam \r\n"
	"tempus, augue ut tempor cursus, neque felis commodo lacus, \r\n"
	"sit amet tincidunt arcu justo vel augue. Proin dapibus \r\n"
	"vulputate maximus. Mauris congue lacus felis, sed varius \r\n"
	"leo finibus sagittis. Cum sociis natoque penatibus et magnis \r\n"
	"dis parturient montes, nascetur ridiculus mus. Aliquam \r\n"
	"laoreet arcu a hendrerit consequat. Duis vitae erat tellus.";

static struct program_client_settings pc_set = {
	.client_connect_timeout_msecs = 5000,
	.input_idle_timeout_msecs = 10000,
	.debug = TRUE,
};

static struct test_server {
	struct ioloop *ioloop;
	struct io *io;
	struct timeout *to;
	struct test_client *client;
	int listen_fd;
	in_port_t port;
	unsigned int io_loop_ref;
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

static void test_program_io_loop_run(void)
{
	if (test_globals.io_loop_ref++ == 0)
		io_loop_run(current_ioloop);
}

static void test_program_io_loop_stop(void)
{
	if (--test_globals.io_loop_ref == 0)
		io_loop_stop(current_ioloop);
}

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
	test_program_io_loop_stop();
}

static int
test_program_input_handle(struct test_client *client, const char *line)
{
	int cmp = -1;
	const char *arg;
	struct istream *is;

	switch(client->state) {
	case CLIENT_STATE_INIT:
		test_assert((cmp=strncmp(line, "VERSION\tscript\t", 15)) == 0);
		if (cmp == 0) {
			client->state = CLIENT_STATE_VERSION;
		} else
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
		client->os_body = iostream_temp_create_named(
			".dovecot.test.", 0, "test_program_input body");
		is = client->in;
		client->in = i_stream_create_dot(is, FALSE);
		i_stream_unref(&is);

		switch(o_stream_send_istream(client->os_body, client->in)) {
		case OSTREAM_SEND_ISTREAM_RESULT_ERROR_OUTPUT:
		case OSTREAM_SEND_ISTREAM_RESULT_ERROR_INPUT:
			return -1;
		case OSTREAM_SEND_ISTREAM_RESULT_WAIT_INPUT:
			break;
		case OSTREAM_SEND_ISTREAM_RESULT_FINISHED:
			client->body =
				iostream_temp_finish(&client->os_body, -1);
			return 1;
		case OSTREAM_SEND_ISTREAM_RESULT_WAIT_OUTPUT:
			i_panic("Cannot write to ostream-temp");
		}
		break;
	}
	return 0;
}

static void test_program_run(struct test_client *client)
{
	const char *const *args;
	unsigned int count;

	struct ostream *os;

	timeout_remove(&test_globals.to);
	test_assert(array_is_created(&client->args));
	if (array_is_created(&client->args)) {
		args = array_get(&client->args, &count);
		test_assert(count > 0);
		if (count > 0) {
			if (strcmp(args[0], "test_program_success") == 0) {
				/* return hello world */
				i_assert(count >= 3);
				o_stream_nsend_str(client->out,
					t_strdup_printf("%s %s\r\n.\n+\n",
						   	args[1], args[2]));
			} else if (strcmp(args[0], "test_program_io") == 0) {
				os = o_stream_create_dot(client->out, FALSE);
				o_stream_nsend_istream(os, client->body);
				test_assert(o_stream_finish(os) > 0);
				o_stream_unref(&os);
				o_stream_nsend_str(client->out, "+\n");
			} else if (strcmp(args[0],
					  "test_program_failure") == 0) {
				o_stream_nsend_str(client->out, ".\n-\n");
			}
		} else
			o_stream_nsend_str(client->out, ".\n-\n");
	}
	test_program_client_destroy(&client);
}

static void test_program_input(struct test_client *client)
{
	const char *line = "";
	int ret = 0;

	if (client->state == CLIENT_STATE_BODY) {
		if (test_program_input_handle(client, NULL)==0 &&
		    !client->in->eof)
			return;
	} else {
		while((line = i_stream_read_next_line(client->in)) != NULL) {
			ret = test_program_input_handle(client, line);
			if (client->state == CLIENT_STATE_BODY)
				ret = test_program_input_handle(client, NULL);
			if (ret != 0) break;
		}

		if ((line == NULL && !client->in->eof) ||
		    (line != NULL && ret == 0))
			return;
	}

	/* incur short delay to make sure the client did not disconnect
	   prematurely */
	io_remove(&client->io);
	test_globals.to = timeout_add_short(100, test_program_run, client);

	if (client->state != CLIENT_STATE_BODY) {
		if (client->in->eof)
			i_warning("Client prematurely disconnected");
		else
			i_warning("Client sent invalid line: %s", line);
	}
}

static void test_program_connected(struct test_server *server)
{
	struct test_client *client;
	int fd;

	i_assert(server->client == NULL);
	fd = net_accept(server->listen_fd, NULL, NULL); /* makes no sense on net */
	if (fd < 0)
		i_fatal("Failed to accept connection: %m");

	pool_t pool = pool_alloconly_create("test_program client", 1024);
	client = p_new(pool, struct test_client, 1);
	client->pool = pool;
	client->fd = fd;
	client->in = i_stream_create_fd(fd, -1);
	client->out = o_stream_create_fd(fd, -1);
	client->io = io_add_istream(client->in, test_program_input, client);
	p_array_init(&client->args, client->pool, 2);
	server->client = client;

	test_program_io_loop_run();
}

static void test_program_setup(void)
{
	struct ip_addr ip;

	test_begin("test_program_setup");

	test_globals.ioloop = io_loop_create();
	io_loop_set_current(test_globals.ioloop);

	/* create listener */
	test_globals.port = 0;
	test_assert(net_addr2ip("127.0.0.1", &ip) == 0);

	test_globals.listen_fd = net_listen(&ip, &test_globals.port, 1);

	if (test_globals.listen_fd < 0)
		i_fatal("Cannot create TCP listener: %m");

	test_globals.io = io_add(test_globals.listen_fd, IO_READ,
				 test_program_connected, &test_globals);
	test_end();
}

static void test_program_teardown(void)
{
	test_begin("test_program_teardown");

	if (test_globals.client != NULL)
		test_program_client_destroy(&test_globals.client);
	io_remove(&test_globals.io);
	i_close_fd(&test_globals.listen_fd);
	io_loop_destroy(&test_globals.ioloop);
	test_end();
}

static void test_program_async_callback(int result, int *ret)
{
	*ret = result;
	test_program_io_loop_stop();
}

static void test_program_success(void)
{
	struct program_client *pc;
	int ret = -2;

	const char *const args[] = {
		"test_program_success", "hello", "world", NULL
	};

	test_begin("test_program_success");	

	pc = program_client_net_create("127.0.0.1", test_globals.port, args,
				       &pc_set, FALSE);

	buffer_t *output = buffer_create_dynamic(default_pool, 16);
	struct ostream *os = test_ostream_create(output);
	program_client_set_output(pc, os);

	program_client_run_async(pc, test_program_async_callback, &ret);

	if (ret == -2)
		test_program_io_loop_run();

	test_assert(ret == 1);
	test_assert(strcmp(str_c(output), "hello world") == 0);

	program_client_destroy(&pc);

	o_stream_unref(&os);
	buffer_free(&output);

	i_assert(test_globals.client == NULL);

	test_end();
}

static void test_program_io(void)
{
	struct program_client *pc;
	int ret = -2;

	const char *const args[] = {
		"test_program_io", NULL
	};

	test_begin("test_program_io (async)");

	pc = program_client_net_create("127.0.0.1", test_globals.port, args,
				       &pc_set, FALSE);

	struct istream *is = test_istream_create(pclient_test_io_string);
	program_client_set_input(pc, is);

	buffer_t *output = buffer_create_dynamic(default_pool, 16);
	struct ostream *os = test_ostream_create(output);
	program_client_set_output(pc, os);

	program_client_run_async(pc, test_program_async_callback, &ret);

	if (ret == -2)
		test_program_io_loop_run();

	test_assert(ret == 1);
	test_assert(strcmp(str_c(output), pclient_test_io_string) == 0);

	program_client_destroy(&pc);

	i_stream_unref(&is);
	o_stream_unref(&os);
	buffer_free(&output);

	i_assert(test_globals.client == NULL);

	test_end();
}

static void test_program_failure(void)
{
	struct program_client *pc;
	int ret = -2;

	const char *const args[] = {
		"test_program_failure", NULL
	};

	test_begin("test_program_failure");

	pc = program_client_net_create("127.0.0.1", test_globals.port, args,
				       &pc_set, FALSE);

	buffer_t *output = buffer_create_dynamic(default_pool, 16);
	struct ostream *os = test_ostream_create(output);
	program_client_set_output(pc, os);

	program_client_run_async(pc, test_program_async_callback, &ret);

	if (ret == -2)
		test_program_io_loop_run();

	test_assert(ret == 0);

	program_client_destroy(&pc);

	o_stream_unref(&os);
	buffer_free(&output);

	i_assert(test_globals.client == NULL);

	test_end();
}

static void test_program_noreply(void)
{
	struct program_client *pc;
	int ret = -2;

	const char *const args[] = {
		"test_program_success", "hello", "world", NULL
	};

	test_begin("test_program_noreply");

	pc = program_client_net_create("127.0.0.1", test_globals.port, args,
				       &pc_set, TRUE);

	program_client_run_async(pc, test_program_async_callback, &ret);

	if (ret == -2)
		test_program_io_loop_run();

	test_assert(ret == 1);

	program_client_destroy(&pc);

	i_assert(test_globals.client == NULL);

	test_end();
}

static void test_program_refused(void)
{
	struct program_client *pc;
	struct ip_addr ips[4];
	int ret = -2;

	const char *const args[] = {
		"test_program_success", "hello", "world", NULL
	};

	test_begin("test_program_refused");

	if (net_addr2ip("::1", &ips[0]) < 0 ||
	    net_addr2ip("127.0.0.3", &ips[1]) < 0 ||
	    net_addr2ip("127.0.0.2", &ips[2]) < 0 ||
	    net_addr2ip("127.0.0.1", &ips[3]) < 0) {
		i_fatal("Cannot convert addresses");
	}
	
	pc = program_client_net_create_ips(ips, N_ELEMENTS(ips),
					   test_globals.port, args,
					   &pc_set, TRUE);

	test_expect_errors(N_ELEMENTS(ips)-1);
	program_client_run_async(pc, test_program_async_callback, &ret);

	if (ret == -2)
		test_program_io_loop_run();

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
		test_program_refused,
		test_program_teardown,
		NULL
	};

	return test_run(tests);
}
