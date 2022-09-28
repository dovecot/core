/* Copyright (c) 2022 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "net.h"
#include "istream.h"
#include "ioloop.h"
#include "write-full.h"
#include "dlua-script-private.h"
#include "dns-lookup.h"
#include "dns-lua.h"
#include "test-common.h"

#define TEST_DNS_SERVER_SOCKET_PATH ".test-dns-server"

static struct ioloop *ioloop;
static struct io *io_client = NULL;
static struct istream *input_client = NULL;

static void test_dns_finished(lua_State *L, struct ioloop *ioloop, int res)
{
	if (res < 0) {
		i_error("%s", lua_tostring(L, -1));
		lua_pop(L, 1);
	}
	io_loop_stop(ioloop);
}

static void test_dns_lua_init(void)
{
	ioloop = io_loop_create();
}

static void test_dns_lua_deinit(void)
{
	io_loop_destroy(&ioloop);
}

static void test_dns_lua_common(const char *luascript)
{
	const struct dns_lookup_settings set = {
		.dns_client_socket_path = TEST_DNS_SERVER_SOCKET_PATH,
		.timeout_msecs = 1000,
	};

	struct dns_client *client = dns_client_init(&set);

	struct dlua_script *script;
	const char *error;
	if (dlua_script_create_string(luascript, &script, NULL, &error) < 0)
		i_fatal("dlua_script_create_string() failed: %s", error);
	if (dlua_script_init(script, &error) < 0)
		i_fatal("dlua_script_init() failed: %s", error);

	lua_State *thread = dlua_script_new_thread(script);
	dlua_push_dns_client(thread, client);
	if (dlua_pcall_yieldable(thread, "test_dns", 1, test_dns_finished,
				 ioloop, &error) < 0)
		i_fatal("dlua_pcall() failed: %s", error);
	io_loop_run(ioloop);
	i_assert(lua_gettop(thread) == 0);
	dlua_script_close_thread(script, &thread);

	dlua_script_unref(&script);
	dns_client_deinit(&client);
}

static void test_dns_server_close(struct istream *input)
{
	i_assert(input == input_client);
	input_client = NULL;

	i_stream_unref(&input);
	io_remove(&io_client);
}

static int test_dns_server_input_line(struct istream *input)
{
	const char *line = i_stream_read_next_line(input);
	if (line == NULL) {
		if (input->eof)
			return -1;
		return 0;
	}
	const char *host, *reply;
	if (str_begins_with(line, "VERSION\t")) {
		/* ignore */
		return 1;
	} else if (str_begins(line, "IP\t", &host)) {
		if (strcmp(host, "localhost") == 0)
			reply = "0\t127.0.0.1\t127.0.0.2\n";
		else
			reply = "-4\tUnknown host\n";
		if (write_full(i_stream_get_fd(input), reply, strlen(reply)) < 0) {
			i_error("write(dns-client) failed: %m");
			return -1;
		}
		return 1;
	} else {
		i_error("unknown input: %s", line);
		return -1;
	}
}

static void test_dns_server_input(struct istream *input)
{
	int ret;

	while ((ret = test_dns_server_input_line(input)) > 0) ;
	if (ret < 0)
		test_dns_server_close(input);
}

static void test_dns_server_listen(int *fd_listenp)
{
	int fd_client = net_accept(*fd_listenp, NULL, NULL);
	if (fd_client < 0) {
		i_error("net_accept(dns-client) failed: %m");
		return;
	}
	net_set_nonblock(fd_client, TRUE);

	const char *handshake = "VERSION\tdns\t1\t0\n";
	if (write_full(fd_client, handshake, strlen(handshake)) < 0) {
		i_error("write(dns-client) failed: %m");
		i_close_fd(&fd_client);
		return;
	}

	i_assert(io_client == NULL);
	i_assert(input_client == NULL);
	input_client = i_stream_create_fd_autoclose(&fd_client, 1024);
	io_client = io_add_istream(input_client, test_dns_server_input,
				   input_client);
}

static void test_dns_lua(void)
{
	static const char *luascript =
"function test_dns(client)\n"
"  local arr, error, errno = client:lookup('localhost')\n"
"  assert(#arr == 2)\n"
"  assert(arr[1] == '127.0.0.1')\n"
"  assert(arr[2] == '127.0.0.2')\n"
"  local arr, error, errno = client:lookup('invalid..name')\n"
"  assert(arr == nil)\n"
"  assert(errno == -4)\n"
"  assert(error == \"Unknown host\")\n"
"end\n";
	test_begin("dns lua lookup");

	i_unlink_if_exists(TEST_DNS_SERVER_SOCKET_PATH);
	int fd_listen = net_listen_unix(TEST_DNS_SERVER_SOCKET_PATH, 1);
	if (fd_listen == -1) {
		i_fatal("net_listen_unix(%s) failed: %m",
			TEST_DNS_SERVER_SOCKET_PATH);
	}
	struct io *io = io_add(fd_listen, IO_READ,
			       test_dns_server_listen, &fd_listen);

	test_dns_lua_common(luascript);

	io_remove(&io);
	io_remove(&io_client);
	i_stream_destroy(&input_client);
	i_close_fd(&fd_listen);
	i_unlink(TEST_DNS_SERVER_SOCKET_PATH);
	test_end();
}

static void test_dns_lua_error(void)
{
	static const char *luascript =
"function test_dns(client)\n"
"  local arr, error, errno = client:lookup('localhost')\n"
"  assert(arr == nil)\n"
"  assert(error == 'Failed to connect to "TEST_DNS_SERVER_SOCKET_PATH": No such file or directory')\n"
"  assert(errno ~= 0)\n"
"end\n";
	test_begin("dns lua errors");
	i_unlink_if_exists(TEST_DNS_SERVER_SOCKET_PATH);
	test_dns_lua_common(luascript);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_dns_lua_init,
		test_dns_lua,
		test_dns_lua_error,
		test_dns_lua_deinit,
		NULL
	};
	return test_run(test_functions);
}
