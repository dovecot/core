/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "test-common.h"
#include "strescape.h"
#include "strnum.h"
#include "strfuncs.h"
#include "unix-socket-create.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "net.h"
#include "connection.h"
#include "lib-event-private.h"
#include "dns-lookup.h"
#include "settings.h"
#include <unistd.h>

#define TEST_SOCKET_NAME ".test-dns-server"

static struct settings_simple test_set;

static const char *const set_dns_test[] = {
	"dns_client_socket_path", TEST_SOCKET_NAME,
	"base_dir", "",
	"dns_client_timeout", "1s",
	NULL
};

static const struct {
	const char *name;
	const char *reply;
} replies[] = {
	{ "localhost", "0\t127.0.0.1\t::1\n" },
	{ "127.0.0.1", "0\tlocalhost\n" },
	{ "once-host", "0\t127.0.0.2\n" },
	/* Malformed reply: return code without the mandatory second field. */
	{ "badreply", "-1\n" },
};

static struct test_server {
	struct ioloop *loop;
	struct io *io;
	struct timeout *to;
	int fd;
	unsigned int lookup_counter;
	bool once_host_seen;
	bool quit_seen;
} test_server;

struct test_expect_result {
	int ret;
	const char *result;
	unsigned int calls;
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

	if (strcmp(args[0], "QUIT") == 0) {
		test_server.quit_seen = TRUE;
		return 0;
	}
	if (strcmp(args[0], "IP") != 0 && strcmp(args[0], "NAME") != 0)
		return -1;
	test_server.lookup_counter++;
	/* close the connection without replying */
	if (strcmp(args[1], "closeconn") == 0)
		return -1;
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
	/* Don't block on reading when the client keeps the connection open
	   after the delayed reply. */
	net_set_nonblock(fd, TRUE);
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
	expected->calls++;
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
	struct dns_lookup *lookup;
	struct test_expect_result ctx = {
		.ret = result == NULL ? -1 : 0,
		.result = result
	};
	dns_lookup(name, NULL, test_set.event, test_callback_ips, &ctx, &lookup);
	io_loop_run(test_server.loop);
}

static void test_dns_expect_result_name(const char *name, const char *result)
{
	struct dns_lookup *lookup;
	struct test_expect_result ctx = {
		.ret = result == NULL ? -1 : 0,
		.result = result
	};
	struct ip_addr addr;
	i_assert(net_addr2ip(name, &addr) == 0);
	dns_lookup_ptr(&addr, NULL, test_set.event, test_callback_name, &ctx, &lookup);
	io_loop_run(test_server.loop);
}

static void test_dns_lookup(void)
{
	test_begin("dns lookup");
	settings_simple_update(&test_set, set_dns_test);
	create_dns_server(&test_server);

	test_dns_expect_result_ips("localhost", "127.0.0.1\t::1");
	test_dns_expect_result_name("127.0.0.1", "localhost");
	test_dns_expect_result_ips("nullhost", NULL);
	test_dns_expect_result_name("127.0.1.0", NULL);

	destroy_dns_server(&test_server);
	test_end();
}

static void test_callback_empty(const struct dns_lookup_result *result,
				bool *called)
{
	io_loop_stop(current_ioloop);
	test_assert_cmp(result->ret, ==, EAI_FAIL);
	test_assert_strcmp(result->error, "Empty hostname");
	*called = TRUE;
}

static void test_dns_lookup_empty(void)
{
	struct dns_lookup *lookup;
	bool called = FALSE;

	test_begin("dns lookup (empty hostname)");
	settings_simple_update(&test_set, set_dns_test);
	create_dns_server(&test_server);

	/* The error is reported asynchronously via the callback. */
	dns_lookup("", NULL, test_set.event, test_callback_empty, &called, &lookup);
	test_assert(lookup != NULL);
	io_loop_run(test_server.loop);
	test_assert(called);

	destroy_dns_server(&test_server);
	test_end();
}

static void test_dns_lookup_ip(void)
{
	struct dns_lookup *lookup;

	test_begin("dns lookup (ip address)");
	settings_simple_update(&test_set, set_dns_test);
	create_dns_server(&test_server);

	struct test_expect_result ctx = {
		.ret = 0,
		.result = "127.0.0.1",
	};
	/* The IP shortcut resolves without contacting the dns server, but
	   must still set *lookup_r and call the callback asynchronously, so
	   that callers relying on it (e.g. doveadm_client_create()) don't
	   treat the lookup as not having started and connect a second time. */
	lookup = NULL;
	dns_lookup("127.0.0.1", NULL, test_set.event, test_callback_ips, &ctx, &lookup);
	test_assert(lookup != NULL);
	io_loop_run(test_server.loop);

	ctx.result = "::1";
	lookup = NULL;
	dns_lookup("::1", NULL, test_set.event, test_callback_ips, &ctx, &lookup);
	test_assert(lookup != NULL);
	io_loop_run(test_server.loop);

	test_assert_cmp(test_server.lookup_counter, ==, 0);

	destroy_dns_server(&test_server);
	test_end();
}

static void test_dns_lookup_timeout(void)
{
	test_begin("dns lookup (timeout)");
	create_dns_server(&test_server);

	struct dns_lookup *lookup;
	struct test_expect_result ctx = {
		.ret = EAI_FAIL,
		.result = NULL,
	};

	dns_lookup("waitfor1500", NULL, test_set.event, test_callback_ips, &ctx, &lookup);
	io_loop_run(current_ioloop);

	destroy_dns_server(&test_server);
	test_end();
}

static struct {
	unsigned int count;
	int error_code;
} finished_events;

static bool
test_finished_event_callback(struct event *event,
			     enum event_callback_type type,
			     struct failure_context *ctx ATTR_UNUSED,
			     const char *fmt ATTR_UNUSED,
			     va_list args ATTR_UNUSED)
{
	const struct event_field *field;

	if (type != EVENT_CALLBACK_TYPE_SEND || event->sending_name == NULL ||
	    strcmp(event->sending_name, "dns_request_finished") != 0)
		return TRUE;
	finished_events.count++;
	field = event_find_field_nonrecursive(event, "error_code");
	finished_events.error_code = field == NULL ? 0 :
		(int)field->value.intmax;
	/* don't log the event */
	return FALSE;
}

static void test_finished_events_start(void)
{
	i_zero(&finished_events);
	event_register_callback(test_finished_event_callback);
	event_set_forced_debug(test_set.event, TRUE);
}

static void test_finished_events_stop(void)
{
	event_set_forced_debug(test_set.event, FALSE);
	event_unregister_callback(test_finished_event_callback);
}

static void test_dns_lookup_abort(void)
{
	test_begin("dns lookup (abort)");
	create_dns_server(&test_server);
	test_finished_events_start();

	struct dns_lookup *lookup;
	struct test_expect_result ctx = {
		.ret = EAI_CANCELED,
		.result = NULL,
	};

	dns_lookup("waitfor1500", NULL, test_set.event, test_callback_ips, &ctx, &lookup);
	struct timeout *to = timeout_add_short(100, io_loop_stop, current_ioloop);
	io_loop_run(current_ioloop);
	timeout_remove(&to);
	dns_lookup_abort(&lookup);
	test_assert_ucmp(ctx.calls, ==, 1);
	test_assert_ucmp(finished_events.count, ==, 1);
	test_assert_cmp(finished_events.error_code, ==, EAI_CANCELED);

	test_finished_events_stop();
	destroy_dns_server(&test_server);
	test_end();
}

struct test_abort_ctx {
	unsigned int calls;
	int ret;
	/* Deinitialized by the callback, if non-NULL. */
	struct dns_client *client;
};

static void test_abort_callback(const struct dns_lookup_result *result,
				struct test_abort_ctx *ctx)
{
	ctx->calls++;
	ctx->ret = result->ret;
	if (ctx->client != NULL)
		dns_client_deinit(&ctx->client);
}

static void test_run_server_loop_for(unsigned int msecs)
{
	struct timeout *to = timeout_add_short(msecs, io_loop_stop,
					       current_ioloop);
	io_loop_run(current_ioloop);
	timeout_remove(&to);
}

static void test_dns_lookup_abort_shared(void)
{
	struct test_abort_ctx ctx = { .ret = -100 };
	struct dns_lookup *lookup;
	struct dns_client *client;
	const char *error;

	test_begin("dns lookup (shared client, abort in flight)");
	settings_simple_update(&test_set, set_dns_test);
	create_dns_server(&test_server);
	test_finished_events_start();
	test_assert_cmp(dns_client_init(NULL, test_set.event, &client,
					&error), ==, 0);

	dns_client_lookup(client, "waitfor300", test_set.event,
			  test_abort_callback, &ctx, &lookup);
	test_run_server_loop_for(100);
	dns_lookup_abort(&lookup);
	test_assert_ucmp(ctx.calls, ==, 1);
	test_assert_cmp(ctx.ret, ==, EAI_CANCELED);

	/* The server's late reply must not call the callback or send the
	   finished event again. */
	test_run_server_loop_for(500);
	test_assert_ucmp(ctx.calls, ==, 1);
	test_assert_ucmp(finished_events.count, ==, 1);
	test_assert_cmp(finished_events.error_code, ==, EAI_CANCELED);

	dns_client_deinit(&client);
	test_finished_events_stop();
	destroy_dns_server(&test_server);
	test_end();
}

static void test_dns_lookup_abort_deinit_client(void)
{
	struct test_abort_ctx ctx = { .ret = -100 };
	struct dns_lookup *lookup;
	const char *error;

	test_begin("dns lookup (shared client, deinit in abort callback)");
	settings_simple_update(&test_set, set_dns_test);
	create_dns_server(&test_server);
	test_assert_cmp(dns_client_init(NULL, test_set.event, &ctx.client,
					&error), ==, 0);

	dns_client_lookup(ctx.client, "waitfor300", test_set.event,
			  test_abort_callback, &ctx, &lookup);
	test_run_server_loop_for(100);
	dns_lookup_abort(&lookup);
	test_assert_ucmp(ctx.calls, ==, 1);
	test_assert_cmp(ctx.ret, ==, EAI_CANCELED);
	test_assert(ctx.client == NULL);

	destroy_dns_server(&test_server);
	test_end();
}

static void test_dns_lookup_malformed(void)
{
	test_begin("dns lookup (malformed reply)");
	create_dns_server(&test_server);

	struct dns_lookup *lookup;
	struct test_expect_result ctx = {
		.ret = EAI_FAIL,
		.result = NULL,
	};

	/* Server replies with only a return code and no second field, so
	   args[1] is NULL. This must be treated as a protocol error rather
	   than dereferencing the missing argument. */
	dns_lookup("badreply", NULL, test_set.event,
		   test_callback_ips, &ctx, &lookup);
	io_loop_run(test_server.loop);

	destroy_dns_server(&test_server);
	test_end();
}

static void test_dns_client_switch_ioloop_to_idle(void)
{
	struct dns_client *client;
	struct dns_lookup *lookup;
	struct test_expect_result ctx = {
		.ret = 0,
		.result = "127.0.0.1\t::1",
	};
	const struct dns_client_parameters params = {
		.idle_timeout_msecs = 300,
	};
	const char *error;

	test_begin("dns client (switch ioloop to non-current, idle timeout)");
	create_dns_server(&test_server);
	struct ioloop *server_ioloop = test_server.loop;

	test_assert_cmp(dns_client_init(&params, test_set.event, &client,
					&error), ==, 0);
	dns_client_lookup(client, "localhost", test_set.event,
			  test_callback_ips, &ctx, &lookup);
	io_loop_run(server_ioloop);

	/* The idle timeout must follow the requested ioloop, not the
	   current one. */
	struct ioloop *other_ioloop = io_loop_create();
	dns_client_switch_ioloop_to(client, server_ioloop);
	io_loop_destroy(&other_ioloop);
	io_loop_set_current(server_ioloop);

	struct timeout *to = timeout_add_short(1000, io_loop_stop,
					       server_ioloop);
	io_loop_run(server_ioloop);
	timeout_remove(&to);
	test_assert(test_server.quit_seen);

	dns_client_deinit(&client);
	destroy_dns_server(&test_server);
	test_end();
}

static void test_dns_lookup_cached(void)
{
	struct test_expect_result ctx;
	struct dns_lookup *lookup;
	struct timeout *to;
	struct event *event = event_create(NULL);
	struct dns_client *client;
	int init_res;
	const char *err;

	if (test_is_quick()) {
		/* waits over 10 seconds for the cache TTLs */
		return;
	}

	test_begin("dns lookup (cached)");
	create_dns_server(&test_server);
	const struct dns_client_parameters params = {
		.cache_ttl_secs = 4,
	};

	init_res = dns_client_init(&params, test_set.event, &client, &err);
	test_assert(init_res == 0);

	/* lookup localhost */
	ctx.result = "127.0.0.1\t::1";
	ctx.ret = 0;

	/* should cause only one lookup */
	dns_client_lookup(client, "localhost", event, test_callback_ips, &ctx, &lookup);
	io_loop_run(current_ioloop);
	dns_client_lookup(client, "localhost", event, test_callback_ips, &ctx, &lookup);
	io_loop_run(current_ioloop);
	test_assert_cmp(test_server.lookup_counter, ==, 1);

	/* The cache uses ioloop_time, so with a 4s TTL the entry is refreshed
	   when its age in whole seconds is 2..3 and expires at 4. Waiting
	   2.5s gives an age of 2 or 3 regardless of where within the second
	   the entry was added. Waiting 3s would randomly give 4. */
	to = timeout_add(2500, io_loop_stop, test_server.loop);
	io_loop_run(current_ioloop);
	timeout_remove(&to);

	/* entry should get refreshed */
	dns_client_lookup(client, "localhost", event, test_callback_ips, &ctx, &lookup);
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

	dns_client_lookup(client, "localhost", event, test_callback_ips, &ctx, &lookup);
	io_loop_run(current_ioloop);

	test_assert_cmp(test_server.lookup_counter, ==, 3);

	/* Ensure failures do not get cached */
	ctx.result = NULL;
	ctx.ret = -1;
	dns_client_lookup(client, "failhost", event, test_callback_ips, &ctx, &lookup);
	io_loop_run(current_ioloop);
	test_assert_cmp(test_server.lookup_counter, ==, 4);

	dns_client_lookup(client, "failhost", event, test_callback_ips, &ctx, &lookup);
	io_loop_run(current_ioloop);
	test_assert_cmp(test_server.lookup_counter, ==, 5);

	/* Test that lookup failures do not crash client */
	ctx.result = "127.0.0.2";
	ctx.ret = 0;

	/* should cause only one lookup */
	dns_client_lookup(client, "once-host", event, test_callback_ips, &ctx, &lookup);
	io_loop_run(current_ioloop);
	dns_client_lookup(client, "once-host", event, test_callback_ips, &ctx, &lookup);
	io_loop_run(current_ioloop);
	test_assert_cmp(test_server.lookup_counter, ==, 6);

	to = timeout_add(2500, io_loop_stop, test_server.loop);
	io_loop_run(current_ioloop);
	timeout_remove(&to);

	/* Ensure failure does not crash anything (it will not be returned yet) */
	dns_client_lookup(client, "once-host", event, test_callback_ips, &ctx, &lookup);
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
	dns_client_lookup(client, "once-host", event, test_callback_ips, &ctx, &lookup);
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

static void test_server_close_clients(void)
{
	while (test_dns_clients->connections != NULL)
		test_dns_client_destroy(test_dns_clients->connections);
}

static void test_dns_wait_msecs(unsigned int msecs)
{
	struct timeout *to = timeout_add_short(msecs, io_loop_stop,
					       current_ioloop);
	io_loop_run(current_ioloop);
	timeout_remove(&to);
}

static void test_dns_client_lookup_ips(struct dns_client *client,
				       const char *name, const char *result)
{
	struct dns_lookup *lookup;
	struct test_expect_result ctx = {
		.ret = result == NULL ? EAI_FAIL : 0,
		.result = result
	};

	dns_client_lookup(client, name, test_set.event, test_callback_ips,
			  &ctx, &lookup);
	io_loop_run(current_ioloop);
}

static void test_dns_lookup_reconnect(void)
{
	struct dns_client *client;
	const struct dns_client_parameters params = {
		.idle_timeout_msecs = 10000,
	};
	const char *error;

	test_begin("dns lookup (shared client, server closes idle connection)");
	settings_simple_update(&test_set, set_dns_test);
	create_dns_server(&test_server);
	test_assert(dns_client_init(&params, test_set.event, &client, &error) == 0);

	test_dns_client_lookup_ips(client, "localhost", "127.0.0.1\t::1");
	test_server_close_clients();
	test_dns_wait_msecs(100);
	test_dns_client_lookup_ips(client, "localhost", "127.0.0.1\t::1");

	dns_client_deinit(&client);
	destroy_dns_server(&test_server);
	test_end();
}

static void test_dns_lookup_reconnect_pending(void)
{
	struct dns_client *client;
	const struct dns_client_parameters params = {
		.idle_timeout_msecs = 10000,
	};
	const char *error;

	test_begin("dns lookup (shared client, server closes pending lookup)");
	settings_simple_update(&test_set, set_dns_test);
	create_dns_server(&test_server);
	test_assert(dns_client_init(&params, test_set.event, &client, &error) == 0);

	test_dns_client_lookup_ips(client, "closeconn", NULL);
	test_assert(!dns_client_has_pending_queries(client));
	test_dns_client_lookup_ips(client, "localhost", "127.0.0.1\t::1");

	dns_client_deinit(&client);
	destroy_dns_server(&test_server);
	test_end();
}

static void test_dns_lookup_closed_private(void)
{
	test_begin("dns lookup (server closes private client)");
	settings_simple_update(&test_set, set_dns_test);
	create_dns_server(&test_server);

	struct dns_lookup *lookup;
	struct test_expect_result ctx = {
		.ret = EAI_FAIL,
	};

	dns_lookup("closeconn", NULL, test_set.event, test_callback_ips,
		   &ctx, &lookup);
	io_loop_run(current_ioloop);
	test_dns_expect_result_ips("localhost", "127.0.0.1\t::1");

	destroy_dns_server(&test_server);
	test_end();
}

static const char *const set_invalid[] = {
	"dns_client_timeout", "invalid",
	"base_dir", "",
	NULL
};

struct test_deferred_ctx {
	unsigned int calls;
	int ret;
	struct ioloop *ioloop;
};

static void test_deferred_callback(const struct dns_lookup_result *result,
				   struct test_deferred_ctx *ctx)
{
	ctx->calls++;
	ctx->ret = result->ret;
	ctx->ioloop = current_ioloop;
	io_loop_stop(current_ioloop);
}

/* Run the ioloop for a short while, even if nothing stops it earlier. */
static void test_run_ioloop_briefly(struct ioloop *ioloop)
{
	struct timeout *to = timeout_add_short_to(ioloop, 200, io_loop_stop,
						  ioloop);
	io_loop_run(ioloop);
	timeout_remove(&to);
}

static void test_dns_lookup_init_failure_switch_ioloop(void)
{
	struct test_deferred_ctx ctx = { .ret = -100 };
	struct dns_lookup *lookup = NULL;
	struct ioloop *old_ioloop;

	test_begin("dns lookup (client init failure, switch ioloop)");
	old_ioloop = io_loop_create();
	settings_simple_update(&test_set, set_invalid);

	dns_lookup("localhost", NULL, test_set.event,
		   test_deferred_callback, &ctx, &lookup);
	test_assert(lookup != NULL);
	struct ioloop *new_ioloop = io_loop_create();
	dns_lookup_switch_ioloop(lookup);
	test_run_ioloop_briefly(new_ioloop);
	test_assert_ucmp(ctx.calls, ==, 1);
	test_assert(ctx.ioloop == new_ioloop);
	test_assert_cmp(ctx.ret, ==, EAI_FAIL);
	io_loop_destroy(&new_ioloop);

	test_run_ioloop_briefly(old_ioloop);
	test_assert_ucmp(ctx.calls, ==, 1);

	settings_simple_update(&test_set, set_dns_test);
	io_loop_destroy(&old_ioloop);
	test_end();
}

static void test_dns_lookup_deferred_switch_ioloop(void)
{
	static const char *const set_missing_socket[] = {
		"dns_client_socket_path", "/nonexistent/dns-client",
		"base_dir", "",
		NULL
	};
	struct test_deferred_ctx ctx = { .ret = -100 };
	struct dns_lookup *lookup = NULL;
	struct ioloop *old_ioloop;

	test_begin("dns lookup (deferred, switch ioloop)");
	old_ioloop = io_loop_create();
	settings_simple_update(&test_set, set_missing_socket);

	dns_lookup("localhost", NULL, test_set.event,
		   test_deferred_callback, &ctx, &lookup);
	test_assert(lookup != NULL);
	struct ioloop *new_ioloop = io_loop_create();
	dns_lookup_switch_ioloop(lookup);
	test_run_ioloop_briefly(new_ioloop);
	test_assert_ucmp(ctx.calls, ==, 1);
	test_assert(ctx.ioloop == new_ioloop);
	test_assert_cmp(ctx.ret, ==, EAI_FAIL);
	io_loop_destroy(&new_ioloop);

	/* Flush the lookup in case it stayed in the old ioloop. */
	test_run_ioloop_briefly(old_ioloop);
	test_assert_ucmp(ctx.calls, ==, 1);

	settings_simple_update(&test_set, set_dns_test);
	io_loop_destroy(&old_ioloop);
	test_end();
}

static void test_dns_lookup_deferred_switch_ioloop_shared(void)
{
	struct test_deferred_ctx ctx = { .ret = -100 };
	struct dns_lookup *lookup = NULL;
	struct dns_client *client;
	struct ioloop *old_ioloop;
	const char *error;

	test_begin("dns lookup (deferred, switch ioloop, shared client)");
	old_ioloop = io_loop_create();
	settings_simple_update(&test_set, set_dns_test);
	test_assert_cmp(dns_client_init(NULL, test_set.event, &client,
					&error), ==, 0);

	dns_client_lookup(client, "127.0.0.1", test_set.event,
			  test_deferred_callback, &ctx, &lookup);
	test_assert(lookup != NULL);
	struct ioloop *new_ioloop = io_loop_create();
	dns_client_switch_ioloop(client);
	test_run_ioloop_briefly(new_ioloop);
	test_assert_ucmp(ctx.calls, ==, 1);
	test_assert(ctx.ioloop == new_ioloop);
	test_assert_cmp(ctx.ret, ==, 0);
	io_loop_destroy(&new_ioloop);

	test_run_ioloop_briefly(old_ioloop);
	test_assert_ucmp(ctx.calls, ==, 1);

	dns_client_deinit(&client);
	io_loop_destroy(&old_ioloop);
	test_end();
}

static void test_dns_lookup_deferred_abort(void)
{
	struct test_deferred_ctx ctx = { .ret = -100 };
	struct dns_lookup *lookup = NULL;
	struct dns_client *client;
	struct ioloop *old_ioloop;
	const char *error;

	test_begin("dns lookup (deferred, abort)");
	old_ioloop = io_loop_create();
	settings_simple_update(&test_set, set_dns_test);

	/* private client */
	dns_lookup("127.0.0.1", NULL, test_set.event,
		   test_deferred_callback, &ctx, &lookup);
	test_assert(lookup != NULL);
	dns_lookup_abort(&lookup);
	test_run_ioloop_briefly(old_ioloop);
	test_assert_ucmp(ctx.calls, ==, 1);
	test_assert_cmp(ctx.ret, ==, EAI_CANCELED);

	ctx.calls = 0;
	ctx.ret = -100;

	/* shared client */
	test_assert_cmp(dns_client_init(NULL, test_set.event, &client,
					&error), ==, 0);
	dns_client_lookup(client, "127.0.0.1", test_set.event,
			  test_deferred_callback, &ctx, &lookup);
	test_assert(lookup != NULL);
	dns_lookup_abort(&lookup);
	test_run_ioloop_briefly(old_ioloop);
	test_assert_ucmp(ctx.calls, ==, 1);
	test_assert_cmp(ctx.ret, ==, EAI_CANCELED);
	dns_client_deinit(&client);

	ctx.calls = 0;
	ctx.ret = -100;

	/* client init failure */
	settings_simple_update(&test_set, set_invalid);
	dns_lookup("localhost", NULL, test_set.event,
		   test_deferred_callback, &ctx, &lookup);
	test_assert(lookup != NULL);
	dns_lookup_abort(&lookup);
	test_run_ioloop_briefly(old_ioloop);
	test_assert_ucmp(ctx.calls, ==, 1);
	test_assert_cmp(ctx.ret, ==, EAI_CANCELED);
	settings_simple_update(&test_set, set_dns_test);
	io_loop_destroy(&old_ioloop);
	test_end();
}

static void test_dns_lookup_deferred_abort_deinit_client(void)
{
	struct test_abort_ctx ctx = { .ret = -100 };
	struct dns_lookup *lookup = NULL;
	struct ioloop *old_ioloop;
	const char *error;

	test_begin("dns lookup (deferred, deinit client in abort callback)");
	old_ioloop = io_loop_create();
	settings_simple_update(&test_set, set_dns_test);
	test_assert_cmp(dns_client_init(NULL, test_set.event, &ctx.client,
					&error), ==, 0);

	dns_client_lookup(ctx.client, "127.0.0.1", test_set.event,
			  test_abort_callback, &ctx, &lookup);
	test_assert(lookup != NULL);
	dns_lookup_abort(&lookup);
	test_assert_ucmp(ctx.calls, ==, 1);
	test_assert_cmp(ctx.ret, ==, EAI_CANCELED);
	test_assert(ctx.client == NULL);
	test_run_ioloop_briefly(old_ioloop);
	test_assert_ucmp(ctx.calls, ==, 1);
	io_loop_destroy(&old_ioloop);
	test_end();
}

static void test_dns_lookup_deferred_client_deinit(void)
{
	struct test_deferred_ctx ctx = { .ret = -100 };
	struct dns_lookup *lookup = NULL;
	struct dns_client *client;
	struct ioloop *old_ioloop;
	const char *error;

	test_begin("dns lookup (deferred, client deinit)");
	old_ioloop = io_loop_create();
	settings_simple_update(&test_set, set_dns_test);
	test_assert_cmp(dns_client_init(NULL, test_set.event, &client,
					&error), ==, 0);

	dns_client_lookup(client, "127.0.0.1", test_set.event,
			  test_deferred_callback, &ctx, &lookup);
	test_assert(lookup != NULL);
	dns_client_deinit(&client);
	test_run_ioloop_briefly(old_ioloop);
	test_assert_ucmp(ctx.calls, ==, 1);
	test_assert_cmp(ctx.ret, ==, 0);

	/* A detached lookup can still be aborted. */
	ctx.calls = 0;
	ctx.ret = -100;
	test_assert_cmp(dns_client_init(NULL, test_set.event, &client,
					&error), ==, 0);
	dns_client_lookup(client, "127.0.0.1", test_set.event,
			  test_deferred_callback, &ctx, &lookup);
	test_assert(lookup != NULL);
	dns_client_deinit(&client);
	dns_lookup_abort(&lookup);
	test_run_ioloop_briefly(old_ioloop);
	test_assert_ucmp(ctx.calls, ==, 1);
	test_assert_cmp(ctx.ret, ==, EAI_CANCELED);
	io_loop_destroy(&old_ioloop);
	test_end();
}

static void test_dns_lookup_deferred_cache_refresh(void)
{
	struct test_deferred_ctx ctx = { .ret = -100 };
	struct dns_lookup *lookup = NULL;
	struct dns_client *client;
	const struct dns_client_parameters params = {
		.cache_ttl_secs = 4,
	};
	const char *error;

	test_begin("dns lookup (deferred, failed cache refresh, client deinit)");
	settings_simple_update(&test_set, set_dns_test);
	create_dns_server(&test_server);
	struct ioloop *ioloop = test_server.loop;

	test_assert_cmp(dns_client_init(&params, test_set.event, &client,
					&error), ==, 0);
	struct test_expect_result expected = {
		.ret = 0,
		.result = "127.0.0.1\t::1",
	};
	dns_client_lookup(client, "localhost", test_set.event,
			  test_callback_ips, &expected, &lookup);
	io_loop_run(ioloop);

	/* Wait until the cache entry is due for a refresh. The client also
	   disconnects from the dns server because it is idle. */
	struct timeout *to = timeout_add_short_to(ioloop, 2500, io_loop_stop,
						  ioloop);
	io_loop_run(ioloop);
	timeout_remove(&to);

	/* Make the dns server unreachable, so that the background refresh
	   fails immediately. */
	connection_list_deinit(&test_dns_clients);
	io_remove(&test_server.io);
	i_unlink(TEST_SOCKET_NAME);

	/* The cache hit starts the refresh, which fails asynchronously. */
	dns_client_lookup(client, "localhost", test_set.event,
			  test_deferred_callback, &ctx, &lookup);
	test_assert(lookup != NULL);
	dns_client_deinit(&client);
	test_run_ioloop_briefly(ioloop);
	test_assert_ucmp(ctx.calls, ==, 1);

	i_zero(&test_server.io);
	destroy_dns_server(&test_server);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_dns_lookup,
		test_dns_lookup_empty,
		test_dns_lookup_ip,
		test_dns_lookup_timeout,
		test_dns_lookup_abort,
		test_dns_lookup_abort_shared,
		test_dns_lookup_abort_deinit_client,
		test_dns_lookup_malformed,
		test_dns_client_switch_ioloop_to_idle,
		test_dns_lookup_cached,
		test_dns_lookup_reconnect,
		test_dns_lookup_reconnect_pending,
		test_dns_lookup_closed_private,
		test_dns_lookup_init_failure_switch_ioloop,
		test_dns_lookup_deferred_switch_ioloop,
		test_dns_lookup_deferred_switch_ioloop_shared,
		test_dns_lookup_deferred_abort,
		test_dns_lookup_deferred_abort_deinit_client,
		test_dns_lookup_deferred_client_deinit,
		test_dns_lookup_deferred_cache_refresh,
		NULL
	};

	lib_init();
	settings_simple_init(&test_set, set_dns_test);
	int ret = test_run(test_functions);
	settings_simple_deinit(&test_set);
	lib_deinit();
	return ret;
}
