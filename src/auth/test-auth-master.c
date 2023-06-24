/* Copyright (c) 2024 Dovecot authors, see the included COPYING file */

#include "test-auth.h"
#include "ioloop.h"
#include "net.h"
#include "master-service.h"
#include "auth-master.h"
#include "test-auth-master.h"

#include <sys/stat.h>

#define TEST_AUTH_MASTER_SOCKET "test-auth-master-socket"

static void auth_master_connected(int *server_fd)
{
	auth_master_server_connected(server_fd, TEST_AUTH_MASTER_SOCKET);
}

static void test_auth_master(void)
{
	test_begin("auth master");
	struct ioloop *loop = io_loop_create();
	test_auth_init();

	i_unlink_if_exists(TEST_AUTH_MASTER_SOCKET);
	int fd = net_listen_unix(TEST_AUTH_MASTER_SOCKET, 10);
	struct io *io = io_add(fd, IO_READ, auth_master_connected, &fd);

	struct auth_master_connection *client =
		auth_master_init(TEST_AUTH_MASTER_SOCKET,
				 AUTH_MASTER_FLAG_NO_IDLE_TIMEOUT |
				 AUTH_MASTER_FLAG_NO_INNER_IOLOOP);

	pool_t pool = pool_alloconly_create("test pool", 128);
	struct auth_user_info info = {
		.session_id = "1",
		.protocol = "default",
	};
	const char *const *fields;
	const char *username;

	int ret = auth_master_pass_lookup(client, "testuser", &info, pool, &fields);
	test_assert_cmp(ret, ==, 1);
	test_assert_strcmp(fields[0], "user=testuser");
	ret = auth_master_user_lookup(client, "testuser", &info, pool, &username, &fields);
	test_assert_cmp(ret, ==, 1);
	test_assert_strcmp(username, "testuser");

	pool_unref(&pool);
	auth_master_deinit(&client);
	io_remove(&io);
	auth_master_server_deinit();
	test_auth_deinit();
	io_loop_destroy(&loop);
	i_unlink_if_exists(TEST_AUTH_MASTER_SOCKET);
	test_end();
}

int main(int argc, char *argv[])
{
	static void (*const test_functions[])(void) = {
		test_auth_master,
		NULL
	};
	const enum master_service_flags service_flags =
		MASTER_SERVICE_FLAG_NO_CONFIG_SETTINGS |
		MASTER_SERVICE_FLAG_STANDALONE |
		MASTER_SERVICE_FLAG_STD_CLIENT |
		MASTER_SERVICE_FLAG_DONT_SEND_STATS;
	int ret;

	master_service = master_service_init("test-auth-master",
					     service_flags, &argc, &argv, "");

	master_service_init_finish(master_service);

	struct ioloop *ioloop = io_loop_create();
	io_loop_set_current(ioloop);
	ret = test_run(test_functions);
	io_loop_destroy(&ioloop);

	master_service_deinit(&master_service);
	return ret;
}
