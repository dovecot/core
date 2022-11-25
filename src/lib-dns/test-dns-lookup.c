/* Copyright (c) 2021 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "test-common.h"
#include "strescape.h"
#include "strnum.h"
#include "strfuncs.h"
#include "unix-socket-create.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "connection.h"
#include "dns-lookup.h"
#include <unistd.h>

#define TEST_SOCKET_NAME ".test-dns-server"

static const struct {
	const char *name;
	const char *reply;
} replies[] = {
	{ "localhost", "0\t127.0.0.1\t::1\n" },
	{ "127.0.0.1", "0\tlocalhost\n" },
	{ "once-host", "0\t127.0.0.2\n" },
};

static struct test_server {
	struct ioloop *loop;
	struct io *io;
	struct timeout *to;
	int fd;
	unsigned int lookup_counter;
	bool once_host_seen;
} test_server;

struct test_expect_result {
	int ret;
	const char *result;
};

static void server_handle_timeout(struct connection *client)
{
	timeout_remove(&test_server.to);
	o_stream_nsend_str(client->output, "-1\tUnresolved\n");
	connection_input_resume(client);
}

static int
test_dns_client_input_args(struct connection *client, const char *const *args)
{
	const char *value;

	if (strcmp(args[0], "QUIT") == 0)
		return 0;
	if (strcmp(args[0], "IP") != 0 && strcmp(args[0], "NAME") != 0)
		return -1;
	test_server.lookup_counter++;
	/* never finish this query */
	if (str_begins(args[1], "waitfor", &value)) {
		unsigned int msecs;
		i_assert(test_server.to == NULL);
		if (str_to_uint(value, &msecs) < 0)
			i_unreached();
		connection_input_halt(client);
		test_server.to =
			timeout_add_short(msecs, server_handle_timeout, client);
		return 1;
	}
	if (strcmp(args[1], "once-host") == 0) {
		if (test_server.once_host_seen) {
			o_stream_nsend_str(client->output, "-1\tUnresolved\n");
			return 1;
		}
		test_server.once_host_seen = TRUE;
	}
	for (size_t i = 0; i < N_ELEMENTS(replies); i++) {
		if (strcmp(args[1], replies[i].name) == 0) {
			o_stream_nsend_str(client->output, replies[i].reply);
			return 1;
		}
	}
	o_stream_nsend_str(client->output, "-1\tUnresolved\n");
	return 1;
}

static void test_dns_client_destroy(struct connection *client)
{
	connection_deinit(client);
	i_free(client);
}

static const struct connection_vfuncs dns_client_vfuncs = {
	.input_args = test_dns_client_input_args,
	.destroy = test_dns_client_destroy
};

static const struct connection_settings dns_client_set = {
	.service_name_in = "dns-client",
	.service_name_out = "dns",
	.major_version = 1,
	.minor_version = 0,
	.input_max_size = SIZE_MAX,
	.output_max_size = SIZE_MAX
};

static struct connection_list *test_dns_clients = NULL;

static void test_dns_client_connected(struct test_server *server)
{
	int fd = accept(server->fd, NULL, NULL);
	i_assert(fd > -1);
	struct connection *conn = i_new(struct connection, 1);
	connection_init_server(test_dns_clients, conn, "test client", fd, fd);
}

static void create_dns_server(struct test_server *server_r)
{
	i_zero(server_r);
	server_r->loop = io_loop_create();
	test_dns_clients = connection_list_init(&dns_client_set,
						&dns_client_vfuncs);
	/* create unix socket for listening connections */
	server_r->fd = unix_socket_create(TEST_SOCKET_NAME, 0700, geteuid(),
					  getegid(), 1);
	server_r->io = io_add_to(server_r->loop, server_r->fd, IO_READ,
				 test_dns_client_connected, server_r);
}

static void destroy_dns_server(struct test_server *server)
{
	io_remove(&server->io);
	timeout_remove(&server->to);
	connection_list_deinit(&test_dns_clients);
	io_loop_destroy(&server->loop);
	i_close_fd(&server->fd);
	i_unlink_if_exists(TEST_SOCKET_NAME);
	i_zero(server);
}

static void test_callback_name(const struct dns_lookup_result *result,
			       struct test_expect_result *expected)
{
	io_loop_stop(current_ioloop);
	test_assert_cmp(result->ret, ==, expected->ret);
	if (result->ret != 0)
		return;
	test_assert_strcmp(result->name, expected->result);
}

static void test_callback_ips(const struct dns_lookup_result *result,
			      struct test_expect_result *expected)
{
	io_loop_stop(current_ioloop);
	test_assert_cmp(result->ret, ==, expected->ret);
	if (result->ret != 0)
		return;
	const char *const *addr = t_strsplit_tabescaped(expected->result);
	test_assert(result->ips_count == str_array_length(addr));
	if (result->ips_count == str_array_length(addr)) {
		for (unsigned int i = 0; i < result->ips_count; i++) {
			struct ip_addr ip;
			i_assert(net_addr2ip(addr[i], &ip) == 0);
			test_assert(net_ip_compare(&result->ips[i], &ip));
		}
	}
}

static void test_dns_expect_result_ips(const char *name, const char *result)
{
	const struct dns_lookup_settings set = {
		.dns_client_socket_path = TEST_SOCKET_NAME,
		.ioloop = test_server.loop,
		.timeout_msecs = 1000,
	};
	struct dns_lookup *lookup;
	struct test_expect_result ctx = {
		.ret = result == NULL ? -1 : 0,
		.result = result
	};
	test_assert(dns_lookup(name, &set, test_callback_ips, &ctx, &lookup) == 0);
	io_loop_run(test_server.loop);
}

static void test_dns_expect_result_name(const char *name, const char *result)
{
	const struct dns_lookup_settings set = {
		.dns_client_socket_path = TEST_SOCKET_NAME,
		.ioloop = test_server.loop,
		.timeout_msecs = 1000,
	};
	struct dns_lookup *lookup;
	struct test_expect_result ctx = {
		.ret = result == NULL ? -1 : 0,
		.result = result
	};
	struct ip_addr addr;
	i_assert(net_addr2ip(name, &addr) == 0);
	test_assert(dns_lookup_ptr(&addr, &set, test_callback_name, &ctx, &lookup) == 0);
	io_loop_run(test_server.loop);
}

static void test_dns_lookup(void)
{
	test_begin("dns lookup");
	create_dns_server(&test_server);

	test_dns_expect_result_ips("localhost", "127.0.0.1\t::1");
	test_dns_expect_result_name("127.0.0.1", "localhost");
	test_dns_expect_result_ips("nullhost", NULL);
	test_dns_expect_result_name("127.0.1.0", NULL);

	destroy_dns_server(&test_server);
	test_end();
}

static void test_dns_lookup_timeout(void)
{
	test_begin("dns lookup (timeout)");
	create_dns_server(&test_server);

	const struct dns_lookup_settings set = {
		.dns_client_socket_path = TEST_SOCKET_NAME,
		.ioloop = test_server.loop,
		.timeout_msecs = 1000,
	};
	struct dns_lookup *lookup;
	struct test_expect_result ctx = {
		.ret = -4,
		.result = NULL,
	};

	test_assert(dns_lookup("waitfor1500", &set, test_callback_ips, &ctx, &lookup) == 0);
	io_loop_run(current_ioloop);

	destroy_dns_server(&test_server);
	test_end();
}

static void test_dns_lookup_abort(void)
{
	test_begin("dns lookup (abort)");
	create_dns_server(&test_server);

	const struct dns_lookup_settings set = {
		.dns_client_socket_path = TEST_SOCKET_NAME,
		.ioloop = test_server.loop,
		.timeout_msecs = 1000,
	};
	struct dns_lookup *lookup;
	struct test_expect_result ctx = {
		.ret = -4,
		.result = NULL,
	};

	test_assert(dns_lookup("waitfor1500", &set, test_callback_ips, &ctx, &lookup) == 0);
	struct timeout *to = timeout_add_short(100, io_loop_stop, current_ioloop);
	io_loop_run(current_ioloop);
	timeout_remove(&to);
	dns_lookup_abort(&lookup);

	destroy_dns_server(&test_server);
	test_end();
}

static void test_dns_lookup_cached(void)
{
	struct test_expect_result ctx;
	struct dns_lookup *lookup;
	struct timeout *to;
	struct event *event = event_create(NULL);

	test_begin("dns lookup (cached)");
	create_dns_server(&test_server);
	const struct dns_lookup_settings set = {
		.dns_client_socket_path = TEST_SOCKET_NAME,
		.ioloop = test_server.loop,
		.timeout_msecs = 1000,
		.cache_ttl_secs = 4,
		.event_parent = event,
	};


	struct dns_client *client = dns_client_init(&set);

	/* lookup localhost */
	ctx.result = "127.0.0.1\t::1";
	ctx.ret = 0;

	/* should cause only one lookup */
	test_assert(dns_client_lookup(client, "localhost", event,
				      test_callback_ips, &ctx, &lookup) == 0);
	io_loop_run(current_ioloop);
	test_assert(dns_client_lookup(client, "localhost", event,
				      test_callback_ips, &ctx, &lookup) == 0);
	io_loop_run(current_ioloop);
	test_assert_cmp(test_server.lookup_counter, ==, 1);

	to = timeout_add(3*1000, io_loop_stop, test_server.loop);
	io_loop_run(current_ioloop);
	timeout_remove(&to);

	/* entry should get refreshed */
	test_assert(dns_client_lookup(client, "localhost", event,
				      test_callback_ips, &ctx, &lookup) == 0);
	io_loop_run(current_ioloop);
	while (dns_client_has_pending_queries(client)) {
		io_loop_handler_run(current_ioloop);
		io_loop_set_running(current_ioloop);
	}
	test_assert_cmp(test_server.lookup_counter, ==, 2);

	/* should get looked up again */
	to = timeout_add(5*1000, io_loop_stop, test_server.loop);
	io_loop_run(current_ioloop);
	timeout_remove(&to);

	test_assert(dns_client_lookup(client, "localhost", event,
				      test_callback_ips, &ctx, &lookup) == 0);
	io_loop_run(current_ioloop);

	test_assert_cmp(test_server.lookup_counter, ==, 3);

	/* Ensure failures do not get cached */
	ctx.result = NULL;
	ctx.ret = -1;
	test_assert(dns_client_lookup(client, "failhost", event,
				      test_callback_ips, &ctx, &lookup) == 0);
	io_loop_run(current_ioloop);
	test_assert_cmp(test_server.lookup_counter, ==, 4);

	test_assert(dns_client_lookup(client, "failhost", event,
				      test_callback_ips, &ctx, &lookup) == 0);
	io_loop_run(current_ioloop);
	test_assert_cmp(test_server.lookup_counter, ==, 5);

	/* Test that lookup failures do not crash client */
	ctx.result = "127.0.0.2";
	ctx.ret = 0;

	/* should cause only one lookup */
	test_assert(dns_client_lookup(client, "once-host", event,
				      test_callback_ips, &ctx, &lookup) == 0);
	io_loop_run(current_ioloop);
	test_assert(dns_client_lookup(client, "once-host", event,
				      test_callback_ips, &ctx, &lookup) == 0);
	io_loop_run(current_ioloop);
	test_assert_cmp(test_server.lookup_counter, ==, 6);

	to = timeout_add(3*1000, io_loop_stop, test_server.loop);
	io_loop_run(current_ioloop);
	timeout_remove(&to);

	/* Ensure failure does not crash anything (it will not be returned yet) */
	test_assert(dns_client_lookup(client, "once-host", event,
				      test_callback_ips, &ctx, &lookup) == 0);
	io_loop_run(current_ioloop);
	while (dns_client_has_pending_queries(client)) {
		io_loop_handler_run(current_ioloop);
		io_loop_set_running(current_ioloop);
	}
	test_assert_cmp(test_server.lookup_counter, ==, 7);

	to = timeout_add(3*1000, io_loop_stop, test_server.loop);
	io_loop_run(current_ioloop);
	timeout_remove(&to);

	ctx.result = NULL;
	ctx.ret = -1;
	/* Now it finally returns error */
	test_assert(dns_client_lookup(client, "once-host", event,
				      test_callback_ips, &ctx, &lookup) == 0);
	io_loop_run(current_ioloop);
	while (dns_client_has_pending_queries(client)) {
		io_loop_handler_run(current_ioloop);
		io_loop_set_running(current_ioloop);
	}
	test_assert_cmp(test_server.lookup_counter, ==, 8);

	dns_client_deinit(&client);
	destroy_dns_server(&test_server);
	event_unref(&event);

	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_dns_lookup,
		test_dns_lookup_timeout,
		test_dns_lookup_abort,
		test_dns_lookup_cached,
		NULL
	};

	return test_run(test_functions);
}
