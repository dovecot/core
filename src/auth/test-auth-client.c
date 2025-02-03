/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "test-auth.h"
#include "ioloop.h"
#include "net.h"
#include "master-service.h"
#include "auth-common.h"
#include "auth-client-connection.h"
#include "auth-client.h"

#define TEST_AUTH_CLIENT_SOCKET "test-auth-client-socket"

static void auth_client_connected(int *server_fd)
{
	struct auth *auth = auth_default_protocol();
	int fd = net_accept(*server_fd, NULL, NULL);
	auth_client_connection_create(auth, fd, TEST_AUTH_CLIENT_SOCKET, 0);
}

static void
test_callback(struct auth_client_request *req, enum auth_request_status status,
	      const char *b64, const char *const *args, void *context)
{
	struct auth_client *client ATTR_UNUSED = context;
	if (status == AUTH_REQUEST_STATUS_CONTINUE) {
		test_assert_strcmp(b64, "");
		/* continue with \0testuser\0testpass */
		auth_client_request_continue(req, "AHRlc3R1c2VyAHRlc3RwYXNz");
		return;
	}
	test_assert_strcmp(args[0], "user=testuser");
	test_assert_cmp(status, ==, AUTH_REQUEST_STATUS_OK);
	io_loop_stop(current_ioloop);
}

static void test_auth_client(void)
{
	test_begin("auth client");
	struct ioloop *loop = io_loop_create();
	test_auth_init();

	i_unlink_if_exists(TEST_AUTH_CLIENT_SOCKET);
	int fd = net_listen_unix(TEST_AUTH_CLIENT_SOCKET, 10);
	struct io *io = io_add(fd, IO_READ, auth_client_connected, &fd);

	struct auth_client *client =
		auth_client_init(TEST_AUTH_CLIENT_SOCKET, getpid(), FALSE);
	auth_client_connect(client);

	while (!auth_client_is_connected(client)) {
		io_loop_set_running(current_ioloop);
		io_loop_handler_run(current_ioloop);
	}

	struct auth_request_info reqinfo = {
		.mech = "plain",
		.client_id = "1",
		.protocol = "default",
		.session_id = "1",
	};
	(void)auth_client_request_new(client, &reqinfo, test_callback, client);

	io_loop_run(current_ioloop);

	auth_client_deinit(&client);
	io_remove(&io);
	auth_client_connections_destroy_all();
	test_auth_deinit();
	io_loop_destroy(&loop);
	i_unlink_if_exists(TEST_AUTH_CLIENT_SOCKET);
	test_end();
}

int main(int argc, char *argv[])
{
	static void (*const test_functions[])(void) = {
		test_auth_client,
		NULL
	};
	const enum master_service_flags service_flags =
		MASTER_SERVICE_FLAG_NO_CONFIG_SETTINGS |
		MASTER_SERVICE_FLAG_STANDALONE |
		MASTER_SERVICE_FLAG_STD_CLIENT |
		MASTER_SERVICE_FLAG_DONT_SEND_STATS;
	int ret;

	master_service = master_service_init("test-auth-client",
					     service_flags, &argc, &argv, "");

	master_service_init_finish(master_service);

	struct ioloop *ioloop = io_loop_create();
	io_loop_set_current(ioloop);
	ret = test_run(test_functions);
	io_loop_destroy(&ioloop);

	master_service_deinit(&master_service);
	return ret;
}
